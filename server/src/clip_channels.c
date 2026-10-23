/*
 * clip_channels.c — CLICOM Server-Side Channel & Membership Management
 */

#include "clip_channels.h"
#include "clip_crypto.h"
#include "clip_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t current_time_ms(void)
{
    return (uint64_t)time(NULL) * 1000ULL;
}

ClipError clip_channel_db_init_schema(sqlite3* db)
{
    if (!db) return CLIP_ERR_INVALID;

    const char* schema_sql =
        "CREATE TABLE IF NOT EXISTS channels ("
        "  channel_uuid BLOB PRIMARY KEY NOT NULL,"
        "  channel_uuid_str TEXT NOT NULL UNIQUE,"
        "  join_key TEXT NOT NULL UNIQUE,"
        "  name TEXT NOT NULL,"
        "  creator_node_uuid BLOB NOT NULL,"
        "  created_at INTEGER NOT NULL,"
        "  active INTEGER NOT NULL DEFAULT 1,"
        "  member_limit INTEGER NOT NULL DEFAULT 16,"
        "  key_revoked INTEGER NOT NULL DEFAULT 0,"
        "  FOREIGN KEY(creator_node_uuid) REFERENCES nodes(node_uuid)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_channels_join_key ON channels(join_key);"
        "CREATE INDEX IF NOT EXISTS idx_channels_uuid_str ON channels(channel_uuid_str);"
        ""
        "CREATE TABLE IF NOT EXISTS channel_members ("
        "  channel_uuid BLOB NOT NULL,"
        "  node_uuid BLOB NOT NULL,"
        "  joined_at INTEGER NOT NULL,"
        "  active INTEGER NOT NULL DEFAULT 1,"
        "  PRIMARY KEY (channel_uuid, node_uuid),"
        "  FOREIGN KEY(channel_uuid) REFERENCES channels(channel_uuid),"
        "  FOREIGN KEY(node_uuid) REFERENCES nodes(node_uuid)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_channel_members_node ON channel_members(node_uuid);";

    char* err_msg = NULL;
    int rc = sqlite3_exec(db, schema_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to create channels/members schema: %s", err_msg ? err_msg : "unknown error");
        if (err_msg) sqlite3_free(err_msg);
        return CLIP_ERR_STORAGE;
    }

    /* Auto-migrate existing database tables if columns are missing */
    sqlite3_exec(db, "ALTER TABLE channels ADD COLUMN member_limit INTEGER NOT NULL DEFAULT 16;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE channels ADD COLUMN key_revoked INTEGER NOT NULL DEFAULT 0;", NULL, NULL, NULL);

    return CLIP_OK;
}

/* Generates a collision-checked join key in "GC-XXXX" format */
static ClipError generate_unique_join_key(sqlite3* db, char* out_key, size_t key_buf_len)
{
    if (!db || !out_key || key_buf_len < 8) return CLIP_ERR_INVALID;

    const char charset[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; /* 32 unambiguous chars */
    const size_t charset_len = sizeof(charset) - 1;

    for (int attempt = 0; attempt < 50; attempt++) {
        uint8_t rand_bytes[4];
        if (clip_crypto_random_bytes(rand_bytes, sizeof(rand_bytes)) != CLIP_OK) {
            return CLIP_ERR_GENERIC;
        }

        char candidate[16];
        snprintf(candidate, sizeof(candidate), "GC-%c%c%c%c",
                 charset[rand_bytes[0] % charset_len],
                 charset[rand_bytes[1] % charset_len],
                 charset[rand_bytes[2] % charset_len],
                 charset[rand_bytes[3] % charset_len]);

        const char* check_sql = "SELECT 1 FROM channels WHERE join_key = ? LIMIT 1;";
        sqlite3_stmt* stmt = NULL;
        if (sqlite3_prepare_v2(db, check_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, candidate, -1, SQLITE_STATIC);
            int step_rc = sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            if (step_rc == SQLITE_DONE) {
                /* Not found, key is unique! */
                strncpy(out_key, candidate, key_buf_len - 1);
                out_key[key_buf_len - 1] = '\0';
                return CLIP_OK;
            }
        }
    }
    return CLIP_ERR_STORAGE;
}

ClipError clip_channel_create_with_limit(sqlite3*        db,
                                         const ClipUuid* creator_node_uuid,
                                         const char*     channel_name,
                                         uint16_t        member_limit,
                                         ClipUuid*       out_channel_uuid,
                                         char*           out_join_key,
                                         size_t          join_key_buf_len)
{
    if (!db || !creator_node_uuid || !out_channel_uuid || !out_join_key) {
        return CLIP_ERR_INVALID;
    }

    /* Clamp member limit: default 16, min 2, max 64 */
    uint16_t limit = (member_limit == 0) ? 16 : member_limit;
    if (limit < 2) limit = 2;
    if (limit > 64) limit = 64;

    const char* safe_name = (channel_name && channel_name[0] != '\0') ? channel_name : "GENERAL";

    ClipUuid chan_uuid;
    ClipError uuid_err = clip_crypto_uuid_generate(&chan_uuid);
    if (uuid_err != CLIP_OK) return uuid_err;

    char chan_uuid_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(&chan_uuid, chan_uuid_str, sizeof(chan_uuid_str));

    char join_key[CLIP_JOIN_KEY_MAX];
    ClipError key_err = generate_unique_join_key(db, join_key, sizeof(join_key));
    if (key_err != CLIP_OK) return key_err;

    uint64_t now = current_time_ms();

    /* Execute transaction */
    char* err_msg = NULL;
    int rc = sqlite3_exec(db, "BEGIN IMMEDIATE TRANSACTION;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        if (err_msg) sqlite3_free(err_msg);
        return CLIP_ERR_STORAGE;
    }

    const char* ins_chan_sql =
        "INSERT INTO channels (channel_uuid, channel_uuid_str, join_key, name, creator_node_uuid, created_at, active, member_limit, key_revoked) "
        "VALUES (?, ?, ?, ?, ?, ?, 1, ?, 0);";

    sqlite3_stmt* stmt = NULL;
    rc = sqlite3_prepare_v2(db, ins_chan_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return CLIP_ERR_STORAGE;
    }

    sqlite3_bind_blob(stmt, 1, chan_uuid.bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, chan_uuid_str, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, join_key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, safe_name, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, creator_node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now);
    sqlite3_bind_int(stmt, 7, (int)limit);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return CLIP_ERR_STORAGE;
    }

    /* Creator automatically becomes the first member (counts towards member_limit) */
    const char* ins_mem_sql =
        "INSERT INTO channel_members (channel_uuid, node_uuid, joined_at, active) "
        "VALUES (?, ?, ?, 1);";

    rc = sqlite3_prepare_v2(db, ins_mem_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return CLIP_ERR_STORAGE;
    }

    sqlite3_bind_blob(stmt, 1, chan_uuid.bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, creator_node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return CLIP_ERR_STORAGE;
    }

    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);

    memcpy(out_channel_uuid->bytes, chan_uuid.bytes, CLIP_UUID_BYTES);
    strncpy(out_join_key, join_key, join_key_buf_len - 1);
    out_join_key[join_key_buf_len - 1] = '\0';

    CLIP_LOGI("Channel created: UUID=%s, join_key='%s', name='%s', limit=%u",
              chan_uuid_str, join_key, safe_name, (unsigned)limit);

    return CLIP_OK;
}

ClipError clip_channel_create(sqlite3*        db,
                              const ClipUuid* creator_node_uuid,
                              const char*     channel_name,
                              ClipUuid*       out_channel_uuid,
                              char*           out_join_key,
                              size_t          join_key_buf_len)
{
    return clip_channel_create_with_limit(db,
                                          creator_node_uuid,
                                          channel_name,
                                          16,
                                          out_channel_uuid,
                                          out_join_key,
                                          join_key_buf_len);
}

ClipError clip_channel_join_by_key(sqlite3*        db,
                                   const ClipUuid* node_uuid,
                                   const char*     join_key,
                                   ClipUuid*       out_channel_uuid,
                                   char*           out_channel_name,
                                   size_t          name_buf_len)
{
    if (!db || !node_uuid || !join_key || !out_channel_uuid) {
        return CLIP_ERR_INVALID;
    }

    /* 1. Look up channel */
    const char* find_sql =
        "SELECT channel_uuid, name, active, member_limit, key_revoked FROM channels WHERE join_key = ? LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, find_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_text(stmt, 1, join_key, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOT_FOUND;
    }

    int active = sqlite3_column_int(stmt, 2);
    if (!active) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_DENIED;
    }

    int key_revoked = sqlite3_column_int(stmt, 4);
    if (key_revoked != 0) {
        sqlite3_finalize(stmt);
        CLIP_LOGW("Join rejected: invitation key '%s' has been revoked", join_key);
        return CLIP_ERR_REVOKED;
    }

    int member_limit = sqlite3_column_int(stmt, 3);
    if (member_limit < 2) member_limit = 16;

    const void* blob = sqlite3_column_blob(stmt, 0);
    int blob_len = sqlite3_column_bytes(stmt, 0);
    if (!blob || blob_len != CLIP_UUID_BYTES) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_STORAGE;
    }
    memcpy(out_channel_uuid->bytes, blob, CLIP_UUID_BYTES);

    const unsigned char* c_name = sqlite3_column_text(stmt, 1);
    if (out_channel_name && name_buf_len > 0) {
        if (c_name) {
            strncpy(out_channel_name, (const char*)c_name, name_buf_len - 1);
            out_channel_name[name_buf_len - 1] = '\0';
        } else {
            out_channel_name[0] = '\0';
        }
    }
    sqlite3_finalize(stmt);

    char chan_str[CLIP_UUID_STR_SIZE];
    char node_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(out_channel_uuid, chan_str, sizeof(chan_str));
    clip_uuid_to_string(node_uuid, node_str, sizeof(node_str));

    /* 2. Execute atomic capacity check and insertion */
    char* err_msg = NULL;
    rc = sqlite3_exec(db, "BEGIN IMMEDIATE TRANSACTION;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        if (err_msg) sqlite3_free(err_msg);
        return CLIP_ERR_STORAGE;
    }

    /* Check if node is already an active member (idempotent rejoin) */
    const char* check_member_sql =
        "SELECT 1 FROM channel_members WHERE channel_uuid = ? AND node_uuid = ? AND active = 1 LIMIT 1;";
    sqlite3_stmt* chk_stmt = NULL;
    bool already_member = false;
    if (sqlite3_prepare_v2(db, check_member_sql, -1, &chk_stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(chk_stmt, 1, out_channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
        sqlite3_bind_blob(chk_stmt, 2, node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
        if (sqlite3_step(chk_stmt) == SQLITE_ROW) {
            already_member = true;
        }
        sqlite3_finalize(chk_stmt);
    }

    if (!already_member) {
        /* Count current active members atomically */
        const char* count_sql =
            "SELECT COUNT(*) FROM channel_members WHERE channel_uuid = ? AND active = 1;";
        sqlite3_stmt* cnt_stmt = NULL;
        int current_members = 0;
        if (sqlite3_prepare_v2(db, count_sql, -1, &cnt_stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(cnt_stmt, 1, out_channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
            if (sqlite3_step(cnt_stmt) == SQLITE_ROW) {
                current_members = sqlite3_column_int(cnt_stmt, 0);
            }
            sqlite3_finalize(cnt_stmt);
        }

        if (current_members >= member_limit) {
            sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
            CLIP_LOGW("Channel %s at member limit (%d/%d): join rejected for node %s",
                      chan_str, current_members, member_limit, node_str);
            return CLIP_ERR_FULL;
        }

        /* Insert or reactivate member */
        uint64_t now = current_time_ms();
        const char* join_sql =
            "INSERT INTO channel_members (channel_uuid, node_uuid, joined_at, active) "
            "VALUES (?, ?, ?, 1) "
            "ON CONFLICT(channel_uuid, node_uuid) DO UPDATE SET active = 1;";

        sqlite3_stmt* ins_stmt = NULL;
        if (sqlite3_prepare_v2(db, join_sql, -1, &ins_stmt, NULL) != SQLITE_OK) {
            sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
            return CLIP_ERR_STORAGE;
        }

        sqlite3_bind_blob(ins_stmt, 1, out_channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
        sqlite3_bind_blob(ins_stmt, 2, node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
        sqlite3_bind_int64(ins_stmt, 3, (sqlite3_int64)now);

        rc = sqlite3_step(ins_stmt);
        sqlite3_finalize(ins_stmt);

        if (rc != SQLITE_DONE) {
            sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
            return CLIP_ERR_STORAGE;
        }
    }

    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);

    CLIP_LOGI("Node %s joined channel %s via key '%s'", node_str, chan_str, join_key);
    return CLIP_OK;
}

ClipError clip_channel_revoke_key(sqlite3*        db,
                                  const ClipUuid* channel_uuid,
                                  const ClipUuid* caller_node_uuid)
{
    if (!db || !channel_uuid || !caller_node_uuid) return CLIP_ERR_INVALID;

    ClipChannelRecord ch;
    ClipError err = clip_channel_get_by_uuid(db, channel_uuid, &ch);
    if (err != CLIP_OK) return err;

    /* Server-enforced owner permission: only channel creator can revoke join key */
    if (!clip_uuid_equal(&ch.creator_node_uuid, caller_node_uuid)) {
        CLIP_LOGW("Permission denied: non-owner attempted to revoke invitation key for channel %s", ch.channel_uuid_str);
        return CLIP_ERR_DENIED;
    }

    const char* sql = "UPDATE channels SET key_revoked = 1 WHERE channel_uuid = ?;";
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return CLIP_ERR_STORAGE;

    CLIP_LOGI("Invitation key for channel %s successfully revoked by owner", ch.channel_uuid_str);
    return CLIP_OK;
}

ClipError clip_channel_close(sqlite3*        db,
                             const ClipUuid* channel_uuid,
                             const ClipUuid* caller_node_uuid)
{
    if (!db || !channel_uuid || !caller_node_uuid) return CLIP_ERR_INVALID;

    ClipChannelRecord ch;
    ClipError err = clip_channel_get_by_uuid(db, channel_uuid, &ch);
    if (err != CLIP_OK) return err;

    /* Server-enforced owner permission: only channel creator can close room */
    if (!clip_uuid_equal(&ch.creator_node_uuid, caller_node_uuid)) {
        CLIP_LOGW("Permission denied: non-owner attempted to close channel %s", ch.channel_uuid_str);
        return CLIP_ERR_DENIED;
    }

    sqlite3_exec(db, "BEGIN IMMEDIATE TRANSACTION;", NULL, NULL, NULL);

    const char* sql1 = "UPDATE channels SET active = 0 WHERE channel_uuid = ?;";
    sqlite3_stmt* s1 = NULL;
    if (sqlite3_prepare_v2(db, sql1, -1, &s1, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(s1, 1, channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
        sqlite3_step(s1);
        sqlite3_finalize(s1);
    }

    const char* sql2 = "UPDATE channel_members SET active = 0 WHERE channel_uuid = ?;";
    sqlite3_stmt* s2 = NULL;
    if (sqlite3_prepare_v2(db, sql2, -1, &s2, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(s2, 1, channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
        sqlite3_step(s2);
        sqlite3_finalize(s2);
    }

    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
    CLIP_LOGI("Channel %s closed and deactivated by owner", ch.channel_uuid_str);
    return CLIP_OK;
}

ClipError clip_channel_leave(sqlite3*        db,
                             const ClipUuid* channel_uuid,
                             const ClipUuid* node_uuid)
{
    if (!db || !channel_uuid || !node_uuid) return CLIP_ERR_INVALID;

    const char* sql = "UPDATE channel_members SET active = 0 WHERE channel_uuid = ? AND node_uuid = ?;";
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? CLIP_OK : CLIP_ERR_STORAGE;
}

ClipError clip_channel_get_by_uuid(sqlite3*           db,
                                   const ClipUuid*    channel_uuid,
                                   ClipChannelRecord* out_channel)
{
    if (!db || !channel_uuid || !out_channel) return CLIP_ERR_INVALID;

    const char* sql =
        "SELECT channel_uuid, channel_uuid_str, join_key, name, creator_node_uuid, created_at, active, member_limit, key_revoked "
        "FROM channels WHERE channel_uuid = ? LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOT_FOUND;
    }

    memset(out_channel, 0, sizeof(ClipChannelRecord));
    memcpy(out_channel->channel_uuid.bytes, sqlite3_column_blob(stmt, 0), CLIP_UUID_BYTES);
    strncpy(out_channel->channel_uuid_str, (const char*)sqlite3_column_text(stmt, 1), sizeof(out_channel->channel_uuid_str) - 1);
    strncpy(out_channel->join_key, (const char*)sqlite3_column_text(stmt, 2), sizeof(out_channel->join_key) - 1);
    strncpy(out_channel->name, (const char*)sqlite3_column_text(stmt, 3), sizeof(out_channel->name) - 1);
    memcpy(out_channel->creator_node_uuid.bytes, sqlite3_column_blob(stmt, 4), CLIP_UUID_BYTES);
    out_channel->created_at_ms = (uint64_t)sqlite3_column_int64(stmt, 5);
    out_channel->active = (sqlite3_column_int(stmt, 6) != 0);
    out_channel->member_limit = (uint16_t)sqlite3_column_int(stmt, 7);
    out_channel->key_revoked = (sqlite3_column_int(stmt, 8) != 0);

    sqlite3_finalize(stmt);
    return CLIP_OK;
}

ClipError clip_channel_get_by_join_key(sqlite3*           db,
                                       const char*        join_key,
                                       ClipChannelRecord* out_channel)
{
    if (!db || !join_key || !out_channel) return CLIP_ERR_INVALID;

    const char* sql =
        "SELECT channel_uuid, channel_uuid_str, join_key, name, creator_node_uuid, created_at, active, member_limit, key_revoked "
        "FROM channels WHERE join_key = ? LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_text(stmt, 1, join_key, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOT_FOUND;
    }

    memset(out_channel, 0, sizeof(ClipChannelRecord));
    memcpy(out_channel->channel_uuid.bytes, sqlite3_column_blob(stmt, 0), CLIP_UUID_BYTES);
    strncpy(out_channel->channel_uuid_str, (const char*)sqlite3_column_text(stmt, 1), sizeof(out_channel->channel_uuid_str) - 1);
    strncpy(out_channel->join_key, (const char*)sqlite3_column_text(stmt, 2), sizeof(out_channel->join_key) - 1);
    strncpy(out_channel->name, (const char*)sqlite3_column_text(stmt, 3), sizeof(out_channel->name) - 1);
    memcpy(out_channel->creator_node_uuid.bytes, sqlite3_column_blob(stmt, 4), CLIP_UUID_BYTES);
    out_channel->created_at_ms = (uint64_t)sqlite3_column_int64(stmt, 5);
    out_channel->active = (sqlite3_column_int(stmt, 6) != 0);
    out_channel->member_limit = (uint16_t)sqlite3_column_int(stmt, 7);
    out_channel->key_revoked = (sqlite3_column_int(stmt, 8) != 0);

    sqlite3_finalize(stmt);
    return CLIP_OK;
}

ClipError clip_channel_is_member(sqlite3*        db,
                                 const ClipUuid* channel_uuid,
                                 const ClipUuid* node_uuid,
                                 bool*           out_is_member)
{
    if (!db || !channel_uuid || !node_uuid || !out_is_member) {
        return CLIP_ERR_INVALID;
    }

    *out_is_member = false;

    const char* sql =
        "SELECT 1 FROM channel_members WHERE channel_uuid = ? AND node_uuid = ? AND active = 1 LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_is_member = true;
    }
    sqlite3_finalize(stmt);
    return CLIP_OK;
}

ClipError clip_channel_get_members(sqlite3*            db,
                                   const ClipUuid*     channel_uuid,
                                   ClipChannelMember** out_members,
                                   size_t*             out_count)
{
    if (!db || !channel_uuid || !out_members || !out_count) {
        return CLIP_ERR_INVALID;
    }

    *out_members = NULL;
    *out_count = 0;

    const char* sql =
        "SELECT cm.node_uuid, n.display_name, cm.joined_at "
        "FROM channel_members cm "
        "LEFT JOIN nodes n ON cm.node_uuid = n.node_uuid "
        "WHERE cm.channel_uuid = ? AND cm.active = 1 "
        "ORDER BY cm.joined_at ASC;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    size_t cap = 16;
    size_t count = 0;
    ClipChannelMember* arr = (ClipChannelMember*)calloc(cap, sizeof(ClipChannelMember));
    if (!arr) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOMEM;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (count >= cap) {
            cap *= 2;
            ClipChannelMember* new_arr = (ClipChannelMember*)realloc(arr, cap * sizeof(ClipChannelMember));
            if (!new_arr) {
                free(arr);
                sqlite3_finalize(stmt);
                return CLIP_ERR_NOMEM;
            }
            arr = new_arr;
        }

        const void* n_blob = sqlite3_column_blob(stmt, 0);
        int n_len = sqlite3_column_bytes(stmt, 0);
        if (n_blob && n_len == CLIP_UUID_BYTES) {
            memcpy(arr[count].node_uuid.bytes, n_blob, CLIP_UUID_BYTES);
        }

        const unsigned char* d_name = sqlite3_column_text(stmt, 1);
        if (d_name) {
            strncpy(arr[count].display_name, (const char*)d_name, sizeof(arr[count].display_name) - 1);
        } else {
            strncpy(arr[count].display_name, "UNKNOWN", sizeof(arr[count].display_name) - 1);
        }

        arr[count].joined_at_ms = (uint64_t)sqlite3_column_int64(stmt, 2);
        arr[count].presence = CLIP_PRESENCE_OFFLINE; /* Default; caller resolves runtime presence */
        count++;
    }

    sqlite3_finalize(stmt);

    *out_members = arr;
    *out_count = count;
    return CLIP_OK;
}

void clip_channel_free_members(ClipChannelMember* members)
{
    if (members) free(members);
}

ClipError clip_channel_list_for_node(sqlite3*            db,
                                     const ClipUuid*     node_uuid,
                                     ClipChannelRecord** out_channels,
                                     size_t*             out_count)
{
    if (!db || !node_uuid || !out_channels || !out_count) {
        return CLIP_ERR_INVALID;
    }

    *out_channels = NULL;
    *out_count = 0;

    const char* sql =
        "SELECT c.channel_uuid, c.channel_uuid_str, c.join_key, c.name, c.creator_node_uuid, c.created_at, c.active, "
        "  (SELECT COUNT(*) FROM channel_members m WHERE m.channel_uuid = c.channel_uuid AND m.active = 1) AS mem_cnt "
        "FROM channel_members cm "
        "JOIN channels c ON cm.channel_uuid = c.channel_uuid "
        "WHERE cm.node_uuid = ? AND cm.active = 1 AND c.active = 1 "
        "ORDER BY c.created_at DESC;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    size_t cap = 16;
    size_t count = 0;
    ClipChannelRecord* arr = (ClipChannelRecord*)calloc(cap, sizeof(ClipChannelRecord));
    if (!arr) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOMEM;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (count >= cap) {
            cap *= 2;
            ClipChannelRecord* new_arr = (ClipChannelRecord*)realloc(arr, cap * sizeof(ClipChannelRecord));
            if (!new_arr) {
                free(arr);
                sqlite3_finalize(stmt);
                return CLIP_ERR_NOMEM;
            }
            arr = new_arr;
        }

        memset(&arr[count], 0, sizeof(ClipChannelRecord));
        memcpy(arr[count].channel_uuid.bytes, sqlite3_column_blob(stmt, 0), CLIP_UUID_BYTES);
        strncpy(arr[count].channel_uuid_str, (const char*)sqlite3_column_text(stmt, 1), sizeof(arr[count].channel_uuid_str) - 1);
        strncpy(arr[count].join_key, (const char*)sqlite3_column_text(stmt, 2), sizeof(arr[count].join_key) - 1);
        strncpy(arr[count].name, (const char*)sqlite3_column_text(stmt, 3), sizeof(arr[count].name) - 1);
        memcpy(arr[count].creator_node_uuid.bytes, sqlite3_column_blob(stmt, 4), CLIP_UUID_BYTES);
        arr[count].created_at_ms = (uint64_t)sqlite3_column_int64(stmt, 5);
        arr[count].active = (sqlite3_column_int(stmt, 6) != 0);
        arr[count].member_count = (size_t)sqlite3_column_int(stmt, 7);
        count++;
    }

    sqlite3_finalize(stmt);

    *out_channels = arr;
    *out_count = count;
    return CLIP_OK;
}

void clip_channel_free_list(ClipChannelRecord* channels)
{
    if (channels) free(channels);
}

/*
 * clip_connections.c — CLICOM Server-Side Connection Request & Tracking Management
 */

#include "clip_connections.h"
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

ClipError clip_connection_db_init_schema(sqlite3* db)
{
    if (!db) return CLIP_ERR_INVALID;

    const char* schema_sql =
        "CREATE TABLE IF NOT EXISTS connections ("
        "  connection_uuid BLOB PRIMARY KEY NOT NULL,"
        "  connection_uuid_str TEXT NOT NULL UNIQUE,"
        "  channel_uuid BLOB NOT NULL,"
        "  requester_node_uuid BLOB NOT NULL,"
        "  target_node_uuid BLOB NOT NULL,"
        "  state INTEGER NOT NULL DEFAULT 1,"
        "  created_at INTEGER NOT NULL,"
        "  updated_at INTEGER NOT NULL,"
        "  FOREIGN KEY(channel_uuid) REFERENCES channels(channel_uuid),"
        "  FOREIGN KEY(requester_node_uuid) REFERENCES nodes(node_uuid),"
        "  FOREIGN KEY(target_node_uuid) REFERENCES nodes(node_uuid)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_connections_lookup ON connections(channel_uuid, requester_node_uuid, target_node_uuid, state);"
        "CREATE INDEX IF NOT EXISTS idx_connections_target ON connections(target_node_uuid, state);"
        "CREATE INDEX IF NOT EXISTS idx_connections_uuid_str ON connections(connection_uuid_str);";

    char* err_msg = NULL;
    int rc = sqlite3_exec(db, schema_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to create connections schema: %s", err_msg ? err_msg : "unknown error");
        sqlite3_free(err_msg);
        return CLIP_ERR_STORAGE;
    }

    CLIP_LOGI("Connections SQLite schema initialized");
    return CLIP_OK;
}

ClipError clip_connection_find_active(sqlite3*              db,
                                      const ClipUuid*       channel_uuid,
                                      const ClipUuid*       node_a,
                                      const ClipUuid*       node_b,
                                      ClipConnectionRecord* out_conn,
                                      bool*                 out_found)
{
    if (!db || !channel_uuid || !node_a || !node_b || !out_found) {
        return CLIP_ERR_INVALID;
    }

    *out_found = false;

    /* Check for either direction where state is REQUESTED (1) or ACCEPTED (2) */
    const char* sql =
        "SELECT connection_uuid, channel_uuid, requester_node_uuid, target_node_uuid, state, created_at, updated_at "
        "FROM connections "
        "WHERE channel_uuid = ? "
        "  AND ((requester_node_uuid = ? AND target_node_uuid = ?) "
        "    OR (requester_node_uuid = ? AND target_node_uuid = ?)) "
        "  AND (state = 1 OR state = 2) "
        "ORDER BY created_at DESC LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, node_a->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, node_b->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, node_b->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, node_a->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_found = true;
        if (out_conn) {
            memset(out_conn, 0, sizeof(*out_conn));
            const void* c_blob = sqlite3_column_blob(stmt, 0);
            const void* ch_blob = sqlite3_column_blob(stmt, 1);
            const void* r_blob = sqlite3_column_blob(stmt, 2);
            const void* t_blob = sqlite3_column_blob(stmt, 3);
            if (c_blob) memcpy(out_conn->connection_uuid.bytes, c_blob, CLIP_UUID_BYTES);
            if (ch_blob) memcpy(out_conn->channel_uuid.bytes, ch_blob, CLIP_UUID_BYTES);
            if (r_blob) memcpy(out_conn->requester_node_uuid.bytes, r_blob, CLIP_UUID_BYTES);
            if (t_blob) memcpy(out_conn->target_node_uuid.bytes, t_blob, CLIP_UUID_BYTES);
            out_conn->state = (ClipConnectionState)sqlite3_column_int(stmt, 4);
            out_conn->created_at_ms = (uint64_t)sqlite3_column_int64(stmt, 5);
            out_conn->updated_at_ms = (uint64_t)sqlite3_column_int64(stmt, 6);
        }
    }

    sqlite3_finalize(stmt);
    return CLIP_OK;
}

ClipError clip_connection_create(sqlite3*              db,
                                 const ClipUuid*       channel_uuid,
                                 const ClipUuid*       requester_node_uuid,
                                 const ClipUuid*       target_node_uuid,
                                 ClipConnectionRecord* out_conn)
{
    if (!db || !channel_uuid || !requester_node_uuid || !target_node_uuid || !out_conn) {
        return CLIP_ERR_INVALID;
    }

    /* 1. Invariant: Cannot request connection to self */
    if (clip_uuid_equal(requester_node_uuid, target_node_uuid)) {
        CLIP_LOGW("Connection request rejected: cannot connect to self");
        return CLIP_ERR_INVALID;
    }

    /* 2. Check for active or pending duplicate connection */
    bool exists = false;
    ClipConnectionRecord existing_conn;
    ClipError check_err = clip_connection_find_active(db, channel_uuid, requester_node_uuid, target_node_uuid, &existing_conn, &exists);
    if (check_err != CLIP_OK) return check_err;
    if (exists) {
        CLIP_LOGW("Connection request rejected: connection already active/pending (state=%d)", (int)existing_conn.state);
        return CLIP_ERR_EXISTS;
    }

    /* 3. Generate unique connection_uuid (UUIDv4) */
    ClipUuid conn_uuid;
    ClipError u_err = clip_crypto_uuid_generate(&conn_uuid);
    if (u_err != CLIP_OK) return u_err;

    char conn_uuid_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(&conn_uuid, conn_uuid_str, sizeof(conn_uuid_str));

    uint64_t now = current_time_ms();

    const char* ins_sql =
        "INSERT INTO connections (connection_uuid, connection_uuid_str, channel_uuid, requester_node_uuid, target_node_uuid, state, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, ins_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, conn_uuid.bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, conn_uuid_str, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, requester_node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, target_node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, (int)CLIP_CONN_STATE_REQUESTED);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)now);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        CLIP_LOGE("Failed to insert connection record: sqlite rc=%d", rc);
        return CLIP_ERR_STORAGE;
    }

    out_conn->connection_uuid = conn_uuid;
    out_conn->channel_uuid = *channel_uuid;
    out_conn->requester_node_uuid = *requester_node_uuid;
    out_conn->target_node_uuid = *target_node_uuid;
    out_conn->state = CLIP_CONN_STATE_REQUESTED;
    out_conn->created_at_ms = now;
    out_conn->updated_at_ms = now;

    CLIP_LOGI("Connection created: UUID=%s (state=REQUESTED)", conn_uuid_str);
    return CLIP_OK;
}

ClipError clip_connection_get(sqlite3*              db,
                              const ClipUuid*       connection_uuid,
                              ClipConnectionRecord* out_conn)
{
    if (!db || !connection_uuid || !out_conn) {
        return CLIP_ERR_INVALID;
    }

    const char* sql =
        "SELECT connection_uuid, channel_uuid, requester_node_uuid, target_node_uuid, state, created_at, updated_at "
        "FROM connections WHERE connection_uuid = ? LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, connection_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOT_FOUND;
    }

    memset(out_conn, 0, sizeof(*out_conn));
    const void* c_blob = sqlite3_column_blob(stmt, 0);
    const void* ch_blob = sqlite3_column_blob(stmt, 1);
    const void* r_blob = sqlite3_column_blob(stmt, 2);
    const void* t_blob = sqlite3_column_blob(stmt, 3);
    if (c_blob) memcpy(out_conn->connection_uuid.bytes, c_blob, CLIP_UUID_BYTES);
    if (ch_blob) memcpy(out_conn->channel_uuid.bytes, ch_blob, CLIP_UUID_BYTES);
    if (r_blob) memcpy(out_conn->requester_node_uuid.bytes, r_blob, CLIP_UUID_BYTES);
    if (t_blob) memcpy(out_conn->target_node_uuid.bytes, t_blob, CLIP_UUID_BYTES);
    out_conn->state = (ClipConnectionState)sqlite3_column_int(stmt, 4);
    out_conn->created_at_ms = (uint64_t)sqlite3_column_int64(stmt, 5);
    out_conn->updated_at_ms = (uint64_t)sqlite3_column_int64(stmt, 6);

    sqlite3_finalize(stmt);
    return CLIP_OK;
}

ClipError clip_connection_set_state(sqlite3*            db,
                                    const ClipUuid*     connection_uuid,
                                    ClipConnectionState new_state)
{
    if (!db || !connection_uuid) {
        return CLIP_ERR_INVALID;
    }

    uint64_t now = current_time_ms();
    const char* sql =
        "UPDATE connections SET state = ?, updated_at = ? WHERE connection_uuid = ?;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_int(stmt, 1, (int)new_state);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
    sqlite3_bind_blob(stmt, 3, connection_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return CLIP_ERR_STORAGE;
    if (sqlite3_changes(db) == 0) return CLIP_ERR_NOT_FOUND;

    CLIP_LOGI("Connection state updated to %d", (int)new_state);
    return CLIP_OK;
}

ClipError clip_connection_list_for_node(sqlite3*               db,
                                        const ClipUuid*        node_uuid,
                                        ClipConnectionRecord** out_conns,
                                        size_t*                out_count)
{
    if (!db || !node_uuid || !out_conns || !out_count) {
        return CLIP_ERR_INVALID;
    }

    *out_conns = NULL;
    *out_count = 0;

    const char* sql =
        "SELECT connection_uuid, channel_uuid, requester_node_uuid, target_node_uuid, state, created_at, updated_at "
        "FROM connections "
        "WHERE requester_node_uuid = ? OR target_node_uuid = ? "
        "ORDER BY created_at DESC;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    size_t cap = 16;
    size_t count = 0;
    ClipConnectionRecord* arr = (ClipConnectionRecord*)calloc(cap, sizeof(ClipConnectionRecord));
    if (!arr) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOMEM;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (count >= cap) {
            cap *= 2;
            ClipConnectionRecord* new_arr = (ClipConnectionRecord*)realloc(arr, cap * sizeof(ClipConnectionRecord));
            if (!new_arr) {
                free(arr);
                sqlite3_finalize(stmt);
                return CLIP_ERR_NOMEM;
            }
            arr = new_arr;
        }

        const void* c_blob = sqlite3_column_blob(stmt, 0);
        const void* ch_blob = sqlite3_column_blob(stmt, 1);
        const void* r_blob = sqlite3_column_blob(stmt, 2);
        const void* t_blob = sqlite3_column_blob(stmt, 3);
        if (c_blob) memcpy(arr[count].connection_uuid.bytes, c_blob, CLIP_UUID_BYTES);
        if (ch_blob) memcpy(arr[count].channel_uuid.bytes, ch_blob, CLIP_UUID_BYTES);
        if (r_blob) memcpy(arr[count].requester_node_uuid.bytes, r_blob, CLIP_UUID_BYTES);
        if (t_blob) memcpy(arr[count].target_node_uuid.bytes, t_blob, CLIP_UUID_BYTES);
        arr[count].state = (ClipConnectionState)sqlite3_column_int(stmt, 4);
        arr[count].created_at_ms = (uint64_t)sqlite3_column_int64(stmt, 5);
        arr[count].updated_at_ms = (uint64_t)sqlite3_column_int64(stmt, 6);
        count++;
    }

    sqlite3_finalize(stmt);

    *out_conns = arr;
    *out_count = count;
    return CLIP_OK;
}

void clip_connection_free_list(ClipConnectionRecord* conns)
{
    if (conns) free(conns);
}

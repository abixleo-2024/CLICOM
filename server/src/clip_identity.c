/*
 * clip_identity.c — CLICOM Server-Side Persistent Identity Storage (SQLite)
 */

#include "clip_identity.h"
#include "clip_channels.h"
#include "clip_sessions.h"
#include "clip_connections.h"
#include "clip_notes.h"
#include "clip_security_db.h"
#include "clip_admin_db.h"
#include "clip_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

struct ClipIdentityDb {
    sqlite3* db;
    char     db_path[256];
};

static uint64_t current_time_ms(void)
{
    return (uint64_t)time(NULL) * 1000ULL;
}

ClipError clip_identity_db_open(ClipIdentityDb** out_db, const char* db_path)
{
    if (!out_db) return CLIP_ERR_INVALID;
    if (!db_path || db_path[0] == '\0') {
        db_path = CLIP_DEFAULT_IDENTITY_DB;
    }

    ClipIdentityDb* id_db = (ClipIdentityDb*)calloc(1, sizeof(ClipIdentityDb));
    if (!id_db) return CLIP_ERR_NOMEM;

    strncpy(id_db->db_path, db_path, sizeof(id_db->db_path) - 1);

    int rc = sqlite3_open(id_db->db_path, &id_db->db);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to open SQLite identity database '%s': %s",
                  id_db->db_path, sqlite3_errmsg(id_db->db));
        if (id_db->db) sqlite3_close(id_db->db);
        free(id_db);
        return CLIP_ERR_STORAGE;
    }

    /* Safety and performance pragmas */
    char* err_msg = NULL;
    rc = sqlite3_exec(id_db->db, "PRAGMA foreign_keys = ON;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to set PRAGMA foreign_keys = ON: %s", err_msg ? err_msg : "unknown error");
        if (err_msg) sqlite3_free(err_msg);
        sqlite3_close(id_db->db);
        free(id_db);
        return CLIP_ERR_STORAGE;
    }

    /* Configure 5000 ms busy timeout */
    sqlite3_busy_timeout(id_db->db, 5000);
    rc = sqlite3_exec(id_db->db, "PRAGMA busy_timeout = 5000;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to set PRAGMA busy_timeout: %s", err_msg ? err_msg : "unknown error");
        if (err_msg) sqlite3_free(err_msg);
        sqlite3_close(id_db->db);
        free(id_db);
        return CLIP_ERR_STORAGE;
    }

    /* Configure WAL journal mode and verify return value */
    sqlite3_stmt* wal_stmt = NULL;
    rc = sqlite3_prepare_v2(id_db->db, "PRAGMA journal_mode = WAL;", -1, &wal_stmt, NULL);
    if (rc == SQLITE_OK && sqlite3_step(wal_stmt) == SQLITE_ROW) {
        const char* jmode = (const char*)sqlite3_column_text(wal_stmt, 0);
        if (!jmode || (_stricmp(jmode, "wal") != 0 && strcmp(jmode, "memory") != 0)) {
            CLIP_LOGW("SQLite did not return WAL mode (returned: '%s')", jmode ? jmode : "null");
        } else {
            CLIP_LOGI("SQLite journal_mode verified: %s", jmode);
        }
    } else {
        CLIP_LOGE("Failed to execute PRAGMA journal_mode = WAL: %s", sqlite3_errmsg(id_db->db));
        if (wal_stmt) sqlite3_finalize(wal_stmt);
        sqlite3_close(id_db->db);
        free(id_db);
        return CLIP_ERR_STORAGE;
    }
    sqlite3_finalize(wal_stmt);

    rc = sqlite3_exec(id_db->db, "PRAGMA synchronous = NORMAL;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        CLIP_LOGW("Warning: PRAGMA synchronous = NORMAL returned error: %s", err_msg ? err_msg : "unknown");
        if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }
    }

    /* Create nodes table schema */
    const char* schema_sql =
        "CREATE TABLE IF NOT EXISTS nodes ("
        "  node_uuid BLOB PRIMARY KEY NOT NULL,"
        "  node_uuid_str TEXT NOT NULL UNIQUE,"
        "  credential_verifier BLOB NOT NULL,"
        "  display_name TEXT NOT NULL,"
        "  created_at INTEGER NOT NULL,"
        "  last_authenticated_at INTEGER NOT NULL,"
        "  revoked INTEGER NOT NULL DEFAULT 0,"
        "  active INTEGER NOT NULL DEFAULT 1"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_nodes_uuid_str ON nodes(node_uuid_str);";

    rc = sqlite3_exec(id_db->db, schema_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to initialize nodes schema in '%s': %s",
                  id_db->db_path, err_msg ? err_msg : "unknown error");
        if (err_msg) sqlite3_free(err_msg);
        sqlite3_close(id_db->db);
        free(id_db);
        return CLIP_ERR_STORAGE;
    }

    /* Initialize Phase 4, 5, 14 & 15 schemas */
    clip_channel_db_init_schema(id_db->db);
    clip_session_db_init_schema(id_db->db);
    clip_connection_db_init_schema(id_db->db);
    clip_notes_db_init_schema(id_db->db);
    clip_security_db_init_schema(id_db->db);
    clip_admin_db_init_schema(id_db->db);

    *out_db = id_db;
    CLIP_LOGI("SQLite identity database opened: %s", id_db->db_path);
    return CLIP_OK;
}

void clip_identity_db_close(ClipIdentityDb* db)
{
    if (!db) return;

    if (db->db) {
        sqlite3_close(db->db);
        db->db = NULL;
    }
    CLIP_LOGI("SQLite identity database closed: %s", db->db_path);
    free(db);
}

sqlite3* clip_identity_get_sqlite(ClipIdentityDb* db)
{
    return db ? db->db : NULL;
}

ClipError clip_identity_register(ClipIdentityDb* db,
                                 const char*     display_name,
                                 ClipUuid*       out_uuid,
                                 uint8_t         out_credential[CLIP_CREDENTIAL_BYTES])
{
    if (!db || !db->db || !out_uuid || !out_credential) {
        return CLIP_ERR_INVALID;
    }

    char safe_name[CLIP_DISPLAY_NAME_MAX];
    if (display_name && display_name[0] != '\0') {
        strncpy(safe_name, display_name, sizeof(safe_name) - 1);
        safe_name[sizeof(safe_name) - 1] = '\0';
    } else {
        strncpy(safe_name, "ANONYMOUS", sizeof(safe_name) - 1);
    }

    /* 1. Generate server-authoritative 16-byte UUIDv4 */
    ClipError err = clip_crypto_uuid_generate(out_uuid);
    if (err != CLIP_OK) return err;

    /* 2. Generate 32-byte cryptographically secure random credential */
    err = clip_crypto_random_bytes(out_credential, CLIP_CREDENTIAL_BYTES);
    if (err != CLIP_OK) return err;

    /* 3. Compute SHA-256 verifier (never store raw credential) */
    uint8_t verifier[CLIP_SHA256_BYTES];
    err = clip_crypto_sha256(out_credential, CLIP_CREDENTIAL_BYTES, verifier);
    if (err != CLIP_OK) {
#ifdef _WIN32
        SecureZeroMemory(out_credential, CLIP_CREDENTIAL_BYTES);
#else
        memset(out_credential, 0, CLIP_CREDENTIAL_BYTES);
#endif
        return err;
    }

    char uuid_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(out_uuid, uuid_str, sizeof(uuid_str));

    uint64_t now_ms = current_time_ms();

    /* 4. Atomic SQLite transaction */
    char* err_msg = NULL;
    sqlite3_exec(db->db, "BEGIN IMMEDIATE TRANSACTION;", NULL, NULL, &err_msg);
    if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }

    const char* insert_sql =
        "INSERT INTO nodes ("
        "  node_uuid, node_uuid_str, credential_verifier, display_name,"
        "  created_at, last_authenticated_at, revoked, active"
        ") VALUES (?, ?, ?, ?, ?, ?, 0, 1);";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db->db, insert_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to prepare registration statement: %s", sqlite3_errmsg(db->db));
        sqlite3_exec(db->db, "ROLLBACK;", NULL, NULL, NULL);
        return CLIP_ERR_STORAGE;
    }

    sqlite3_bind_blob(stmt, 1, out_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, uuid_str, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, verifier, CLIP_SHA256_BYTES, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, safe_name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)now_ms);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now_ms);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

#ifdef _WIN32
    SecureZeroMemory(verifier, sizeof(verifier));
#else
    memset(verifier, 0, sizeof(verifier));
#endif

    if (rc != SQLITE_DONE) {
        CLIP_LOGE("Failed to insert node record: %s", sqlite3_errmsg(db->db));
        sqlite3_exec(db->db, "ROLLBACK;", NULL, NULL, NULL);
        return CLIP_ERR_STORAGE;
    }

    sqlite3_exec(db->db, "COMMIT;", NULL, NULL, NULL);

    CLIP_LOGI("Registered new node: UUID=%s, display_name='%s'", uuid_str, safe_name);
    return CLIP_OK;
}

ClipError clip_identity_authenticate(ClipIdentityDb* db,
                                     const ClipUuid* uuid,
                                     const uint8_t   credential[CLIP_CREDENTIAL_BYTES],
                                     char*           out_display_name,
                                     size_t          name_buf_len,
                                     bool*           out_is_revoked)
{
    if (!db || !db->db || !uuid || !credential) return CLIP_ERR_INVALID;
    if (out_is_revoked) *out_is_revoked = false;

    const char* query_sql =
        "SELECT credential_verifier, display_name, revoked, active "
        "FROM nodes WHERE node_uuid = ?;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db->db, query_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return CLIP_ERR_STORAGE;
    }

    sqlite3_bind_blob(stmt, 1, uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        /* No such node UUID exists in database */
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOT_FOUND;
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_STORAGE;
    }

    const void* verifier_blob = sqlite3_column_blob(stmt, 0);
    int verifier_bytes = sqlite3_column_bytes(stmt, 0);
    const char* display_name_text = (const char*)sqlite3_column_text(stmt, 1);
    int revoked = sqlite3_column_int(stmt, 2);
    int active = sqlite3_column_int(stmt, 3);

    if (revoked != 0 || active == 0) {
        if (out_is_revoked) *out_is_revoked = true;
        sqlite3_finalize(stmt);
        return CLIP_ERR_DENIED;
    }

    if (!verifier_blob || verifier_bytes != CLIP_SHA256_BYTES) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_STORAGE;
    }

    /* Compute SHA-256 of supplied credential */
    uint8_t calc_verifier[CLIP_SHA256_BYTES];
    ClipError hash_err = clip_crypto_sha256(credential, CLIP_CREDENTIAL_BYTES, calc_verifier);
    if (hash_err != CLIP_OK) {
        sqlite3_finalize(stmt);
        return hash_err;
    }

    /* Constant-time verification to prevent timing attacks */
    bool match = clip_crypto_secure_equal(calc_verifier, (const uint8_t*)verifier_blob, CLIP_SHA256_BYTES);

#ifdef _WIN32
    SecureZeroMemory(calc_verifier, sizeof(calc_verifier));
#else
    memset(calc_verifier, 0, sizeof(calc_verifier));
#endif

    if (!match) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_AUTH;
    }

    if (out_display_name && name_buf_len > 0) {
        if (display_name_text) {
            strncpy(out_display_name, display_name_text, name_buf_len - 1);
            out_display_name[name_buf_len - 1] = '\0';
        } else {
            out_display_name[0] = '\0';
        }
    }

    sqlite3_finalize(stmt);

    /* Update last_authenticated_at */
    uint64_t now_ms = current_time_ms();
    const char* update_sql = "UPDATE nodes SET last_authenticated_at = ? WHERE node_uuid = ?;";
    if (sqlite3_prepare_v2(db->db, update_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now_ms);
        sqlite3_bind_blob(stmt, 2, uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    return CLIP_OK;
}

ClipError clip_identity_get(ClipIdentityDb* db,
                            const ClipUuid* uuid,
                            ClipNodeInfo*   out_info,
                            bool*           out_is_revoked)
{
    if (!db || !db->db || !uuid) return CLIP_ERR_INVALID;
    if (out_is_revoked) *out_is_revoked = false;

    const char* query_sql =
        "SELECT display_name, last_authenticated_at, revoked "
        "FROM nodes WHERE node_uuid = ?;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db->db, query_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOT_FOUND;
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_STORAGE;
    }

    const char* name = (const char*)sqlite3_column_text(stmt, 0);
    uint64_t last_seen = (uint64_t)sqlite3_column_int64(stmt, 1);
    int revoked = sqlite3_column_int(stmt, 2);

    if (out_is_revoked) {
        *out_is_revoked = (revoked != 0);
    }

    if (out_info) {
        memcpy(out_info->node_uuid, uuid->bytes, CLIP_UUID_BYTES);
        clip_uuid_to_string(uuid, out_info->node_uuid_str, sizeof(out_info->node_uuid_str));
        if (name) {
            strncpy(out_info->display_name, name, sizeof(out_info->display_name) - 1);
            out_info->display_name[sizeof(out_info->display_name) - 1] = '\0';
        }
        out_info->last_seen_ms = last_seen;
        out_info->presence = (revoked == 0) ? CLIP_PRESENCE_ONLINE : CLIP_PRESENCE_OFFLINE;
    }

    sqlite3_finalize(stmt);
    return CLIP_OK;
}

ClipError clip_identity_set_revoked(ClipIdentityDb* db,
                                    const ClipUuid* uuid,
                                    bool            revoked)
{
    if (!db || !db->db || !uuid) return CLIP_ERR_INVALID;

    const char* update_sql = "UPDATE nodes SET revoked = ? WHERE node_uuid = ?;";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db->db, update_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_int(stmt, 1, revoked ? 1 : 0);
    sqlite3_bind_blob(stmt, 2, uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return CLIP_ERR_STORAGE;
    return (sqlite3_changes(db->db) > 0) ? CLIP_OK : CLIP_ERR_NOT_FOUND;
}

ClipError clip_identity_update_display_name(ClipIdentityDb* db,
                                           const ClipUuid* uuid,
                                           const char*     new_display_name)
{
    if (!db || !db->db || !uuid || !new_display_name) return CLIP_ERR_INVALID;

    const char* update_sql = "UPDATE nodes SET display_name = ? WHERE node_uuid = ?;";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db->db, update_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_text(stmt, 1, new_display_name, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return CLIP_ERR_STORAGE;
    return (sqlite3_changes(db->db) > 0) ? CLIP_OK : CLIP_ERR_NOT_FOUND;
}

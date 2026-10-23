/*
 * clip_admin_db.c — CLICOM Server-Side Administrative Database Implementation
 */

#include "clip_admin_db.h"
#include "clip_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t current_time_ms(void)
{
    return (uint64_t)time(NULL) * 1000ULL;
}

ClipError clip_admin_db_init_schema(sqlite3* db)
{
    if (!db) return CLIP_ERR_INVALID;

    const char* schema_sql =
        "CREATE TABLE IF NOT EXISTS administrators ("
        "  admin_uuid BLOB PRIMARY KEY NOT NULL,"
        "  username TEXT NOT NULL UNIQUE,"
        "  role INTEGER NOT NULL,"
        "  salt BLOB NOT NULL,"
        "  verifier BLOB NOT NULL,"
        "  iterations INTEGER NOT NULL DEFAULT 100000,"
        "  created_at INTEGER NOT NULL,"
        "  updated_at INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_administrators_username ON administrators(username);"
        ""
        "CREATE TABLE IF NOT EXISTS node_sanctions ("
        "  node_uuid BLOB PRIMARY KEY NOT NULL,"
        "  status INTEGER NOT NULL,"
        "  reason TEXT NOT NULL,"
        "  admin_uuid BLOB NOT NULL,"
        "  updated_at INTEGER NOT NULL,"
        "  FOREIGN KEY(node_uuid) REFERENCES nodes(node_uuid),"
        "  FOREIGN KEY(admin_uuid) REFERENCES administrators(admin_uuid)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_node_sanctions_status ON node_sanctions(status);"
        ""
        "CREATE TABLE IF NOT EXISTS admin_audit_log ("
        "  audit_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  admin_uuid BLOB NOT NULL,"
        "  action_type INTEGER NOT NULL,"
        "  target_uuid BLOB,"
        "  reason TEXT NOT NULL,"
        "  related_event_id INTEGER,"
        "  related_session_uuid BLOB,"
        "  related_channel_uuid BLOB,"
        "  status INTEGER NOT NULL,"
        "  error_code INTEGER DEFAULT 0,"
        "  created_at INTEGER NOT NULL,"
        "  FOREIGN KEY(admin_uuid) REFERENCES administrators(admin_uuid)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_audit_admin ON admin_audit_log(admin_uuid);"
        "CREATE INDEX IF NOT EXISTS idx_audit_target ON admin_audit_log(target_uuid);"
        "CREATE INDEX IF NOT EXISTS idx_audit_event ON admin_audit_log(related_event_id);";

    char* err_msg = NULL;
    int rc = sqlite3_exec(db, schema_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to initialize admin schema: %s", err_msg ? err_msg : "unknown");
        if (err_msg) sqlite3_free(err_msg);
        return CLIP_ERR_STORAGE;
    }

    return CLIP_OK;
}

ClipError clip_admin_db_count_admins(sqlite3* db, size_t* out_count)
{
    if (!db || !out_count) return CLIP_ERR_INVALID;

    const char* sql = "SELECT COUNT(*) FROM administrators;";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_count = (size_t)sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);
        return CLIP_OK;
    }

    sqlite3_finalize(stmt);
    return CLIP_ERR_STORAGE;
}

ClipError clip_admin_db_create_admin(sqlite3* db, const ClipAdminUser* user)
{
    if (!db || !user) return CLIP_ERR_INVALID;

    const char* sql =
        "INSERT INTO administrators ("
        "  admin_uuid, username, role, salt, verifier, iterations, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, user->admin_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user->username, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, (int)user->role);
    sqlite3_bind_blob(stmt, 4, user->salt, CLIP_ADMIN_SALT_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, user->verifier, CLIP_ADMIN_VERIFIER_BYTES, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, (int)user->iterations);
    uint64_t now = user->created_at_ms ? user->created_at_ms : current_time_ms();
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)now);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_CONSTRAINT) return CLIP_ERR_EXISTS;
    return (rc == SQLITE_DONE) ? CLIP_OK : CLIP_ERR_STORAGE;
}

static void read_admin_row(sqlite3_stmt* stmt, ClipAdminUser* out_user)
{
    memset(out_user, 0, sizeof(ClipAdminUser));
    const void* u_blob = sqlite3_column_blob(stmt, 0);
    if (u_blob && sqlite3_column_bytes(stmt, 0) == CLIP_UUID_BYTES) {
        memcpy(out_user->admin_uuid, u_blob, CLIP_UUID_BYTES);
    }
    const unsigned char* un = sqlite3_column_text(stmt, 1);
    if (un) {
        strncpy(out_user->username, (const char*)un, sizeof(out_user->username) - 1);
    }
    out_user->role = (ClipAdminPermission)sqlite3_column_int(stmt, 2);
    const void* salt_blob = sqlite3_column_blob(stmt, 3);
    if (salt_blob && sqlite3_column_bytes(stmt, 3) == CLIP_ADMIN_SALT_BYTES) {
        memcpy(out_user->salt, salt_blob, CLIP_ADMIN_SALT_BYTES);
    }
    const void* verif_blob = sqlite3_column_blob(stmt, 4);
    if (verif_blob && sqlite3_column_bytes(stmt, 4) == CLIP_ADMIN_VERIFIER_BYTES) {
        memcpy(out_user->verifier, verif_blob, CLIP_ADMIN_VERIFIER_BYTES);
    }
    out_user->iterations = (uint32_t)sqlite3_column_int(stmt, 5);
    out_user->created_at_ms = (uint64_t)sqlite3_column_int64(stmt, 6);
    out_user->updated_at_ms = (uint64_t)sqlite3_column_int64(stmt, 7);
}

ClipError clip_admin_db_get_admin(sqlite3* db, const char* username, ClipAdminUser* out_user)
{
    if (!db || !username || !out_user) return CLIP_ERR_INVALID;

    const char* sql =
        "SELECT admin_uuid, username, role, salt, verifier, iterations, created_at, updated_at "
        "FROM administrators WHERE username = ? LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        read_admin_row(stmt, out_user);
        sqlite3_finalize(stmt);
        return CLIP_OK;
    }

    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? CLIP_ERR_NOT_FOUND : CLIP_ERR_STORAGE;
}

ClipError clip_admin_db_get_admin_by_uuid(sqlite3* db, const uint8_t admin_uuid[CLIP_UUID_BYTES], ClipAdminUser* out_user)
{
    if (!db || !admin_uuid || !out_user) return CLIP_ERR_INVALID;

    const char* sql =
        "SELECT admin_uuid, username, role, salt, verifier, iterations, created_at, updated_at "
        "FROM administrators WHERE admin_uuid = ? LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, admin_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        read_admin_row(stmt, out_user);
        sqlite3_finalize(stmt);
        return CLIP_OK;
    }

    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? CLIP_ERR_NOT_FOUND : CLIP_ERR_STORAGE;
}

ClipError clip_admin_db_get_sanction(sqlite3* db, const uint8_t node_uuid[CLIP_UUID_BYTES], ClipNodeSanction* out_sanction)
{
    if (!db || !node_uuid || !out_sanction) return CLIP_ERR_INVALID;

    const char* sql =
        "SELECT node_uuid, status, reason, admin_uuid, updated_at "
        "FROM node_sanctions WHERE node_uuid = ? LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, node_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        memset(out_sanction, 0, sizeof(ClipNodeSanction));
        memcpy(out_sanction->node_uuid, node_uuid, CLIP_UUID_BYTES);
        out_sanction->status = (ClipNodeSanctionState)sqlite3_column_int(stmt, 1);
        const unsigned char* r = sqlite3_column_text(stmt, 2);
        if (r) {
            strncpy(out_sanction->reason, (const char*)r, sizeof(out_sanction->reason) - 1);
        }
        const void* a_blob = sqlite3_column_blob(stmt, 3);
        if (a_blob && sqlite3_column_bytes(stmt, 3) == CLIP_UUID_BYTES) {
            memcpy(out_sanction->admin_uuid, a_blob, CLIP_UUID_BYTES);
        }
        out_sanction->updated_at_ms = (uint64_t)sqlite3_column_int64(stmt, 4);
        sqlite3_finalize(stmt);
        return CLIP_OK;
    }

    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? CLIP_ERR_NOT_FOUND : CLIP_ERR_STORAGE;
}

ClipError clip_admin_db_set_sanction(sqlite3* db, const ClipNodeSanction* sanction)
{
    if (!db || !sanction) return CLIP_ERR_INVALID;

    const char* sql =
        "INSERT INTO node_sanctions (node_uuid, status, reason, admin_uuid, updated_at) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(node_uuid) DO UPDATE SET "
        "  status = excluded.status, "
        "  reason = excluded.reason, "
        "  admin_uuid = excluded.admin_uuid, "
        "  updated_at = excluded.updated_at;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, sanction->node_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, (int)sanction->status);
    sqlite3_bind_text(stmt, 3, sanction->reason, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, sanction->admin_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    uint64_t now = sanction->updated_at_ms ? sanction->updated_at_ms : current_time_ms();
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? CLIP_OK : CLIP_ERR_STORAGE;
}

ClipError clip_admin_db_remove_sanction(sqlite3* db, const uint8_t node_uuid[CLIP_UUID_BYTES])
{
    if (!db || !node_uuid) return CLIP_ERR_INVALID;

    const char* sql = "DELETE FROM node_sanctions WHERE node_uuid = ?;";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, node_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? CLIP_OK : CLIP_ERR_STORAGE;
}

ClipError clip_admin_db_add_audit(sqlite3* db, const ClipAdminAuditRecord* record, uint32_t* out_audit_id)
{
    if (!db || !record) return CLIP_ERR_INVALID;

    const char* sql =
        "INSERT INTO admin_audit_log ("
        "  admin_uuid, action_type, target_uuid, reason, related_event_id, "
        "  related_session_uuid, related_channel_uuid, status, error_code, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, record->admin_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, (int)record->action_type);

    if (record->has_target_uuid) {
        sqlite3_bind_blob(stmt, 3, record->target_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 3);
    }

    sqlite3_bind_text(stmt, 4, record->reason, -1, SQLITE_STATIC);

    if (record->related_event_id > 0) {
        sqlite3_bind_int(stmt, 5, (int)record->related_event_id);
    } else {
        sqlite3_bind_null(stmt, 5);
    }

    if (record->has_related_session) {
        sqlite3_bind_blob(stmt, 6, record->related_session_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 6);
    }

    if (record->has_related_channel) {
        sqlite3_bind_blob(stmt, 7, record->related_channel_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 7);
    }

    sqlite3_bind_int(stmt, 8, (int)record->status);
    sqlite3_bind_int(stmt, 9, (int)record->error_code);
    uint64_t now = record->created_at_ms ? record->created_at_ms : current_time_ms();
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        if (out_audit_id) {
            *out_audit_id = (uint32_t)sqlite3_last_insert_rowid(db);
        }
        sqlite3_finalize(stmt);
        return CLIP_OK;
    }

    sqlite3_finalize(stmt);
    return CLIP_ERR_STORAGE;
}

ClipError clip_admin_db_query_events(sqlite3* db, int filter_status, ClipSecurityEvent* out_events, size_t max_events, size_t* out_count)
{
    if (!db || !out_events || !out_count || max_events == 0) return CLIP_ERR_INVALID;

    const char* sql = (filter_status < 0) ?
        "SELECT event_id, event_uuid, event_uuid_str, session_uuid, channel_uuid, node_uuid, "
        "       category, severity, matched_rule, matched_text, context_text, timestamp_ms, review_state "
        "FROM security_events ORDER BY timestamp_ms DESC LIMIT ?;" :
        "SELECT event_id, event_uuid, event_uuid_str, session_uuid, channel_uuid, node_uuid, "
        "       category, severity, matched_rule, matched_text, context_text, timestamp_ms, review_state "
        "FROM security_events WHERE review_state = ? ORDER BY timestamp_ms DESC LIMIT ?;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    if (filter_status < 0) {
        sqlite3_bind_int(stmt, 1, (int)max_events);
    } else {
        sqlite3_bind_int(stmt, 1, filter_status);
        sqlite3_bind_int(stmt, 2, (int)max_events);
    }

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_events) {
        ClipSecurityEvent* e = &out_events[count];
        memset(e, 0, sizeof(ClipSecurityEvent));

        e->event_id = (uint32_t)sqlite3_column_int(stmt, 0);
        const void* u_blob = sqlite3_column_blob(stmt, 1);
        if (u_blob && sqlite3_column_bytes(stmt, 1) == CLIP_UUID_BYTES) {
            memcpy(e->event_uuid, u_blob, CLIP_UUID_BYTES);
        }
        const unsigned char* u_str = sqlite3_column_text(stmt, 2);
        if (u_str) strncpy(e->event_uuid_str, (const char*)u_str, sizeof(e->event_uuid_str) - 1);

        const void* s_blob = sqlite3_column_blob(stmt, 3);
        if (s_blob && sqlite3_column_bytes(stmt, 3) == CLIP_UUID_BYTES) {
            memcpy(e->session_uuid, s_blob, CLIP_UUID_BYTES);
        }

        const void* c_blob = sqlite3_column_blob(stmt, 4);
        if (c_blob && sqlite3_column_bytes(stmt, 4) == CLIP_UUID_BYTES) {
            ClipUuid cu;
            memcpy(cu.bytes, c_blob, CLIP_UUID_BYTES);
            clip_uuid_to_string(&cu, e->channel_uuid_str, sizeof(e->channel_uuid_str));
        }

        const void* n_blob = sqlite3_column_blob(stmt, 5);
        if (n_blob && sqlite3_column_bytes(stmt, 5) == CLIP_UUID_BYTES) {
            ClipUuid nu;
            memcpy(nu.bytes, n_blob, CLIP_UUID_BYTES);
            clip_uuid_to_string(&nu, e->node_uuid_str, sizeof(e->node_uuid_str));
        }

        e->category = (ClipRuleCategory)sqlite3_column_int(stmt, 6);
        e->severity = (ClipSeverity)sqlite3_column_int(stmt, 7);

        const unsigned char* r_str = sqlite3_column_text(stmt, 8);
        if (r_str) strncpy(e->matched_rule, (const char*)r_str, sizeof(e->matched_rule) - 1);

        const unsigned char* t_str = sqlite3_column_text(stmt, 9);
        if (t_str) strncpy(e->matched_term, (const char*)t_str, sizeof(e->matched_term) - 1);

        const unsigned char* x_str = sqlite3_column_text(stmt, 10);
        if (x_str) strncpy(e->context_text, (const char*)x_str, sizeof(e->context_text) - 1);

        e->timestamp_ms = (uint64_t)sqlite3_column_int64(stmt, 11);
        e->status = (ClipEventStatus)sqlite3_column_int(stmt, 12);

        count++;
    }

    sqlite3_finalize(stmt);
    *out_count = count;
    return CLIP_OK;
}

ClipError clip_admin_db_update_event_status(sqlite3* db, uint32_t event_id, ClipEventStatus new_status)
{
    if (!db || event_id == 0) return CLIP_ERR_INVALID;

    /* 1. Query current review status */
    const char* check_sql = "SELECT review_state FROM security_events WHERE event_id = ? LIMIT 1;";
    sqlite3_stmt* check_stmt = NULL;
    int rc = sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_int(check_stmt, 1, (int)event_id);
    rc = sqlite3_step(check_stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(check_stmt);
        return CLIP_ERR_NOT_FOUND;
    }

    int current_state = sqlite3_column_int(check_stmt, 0);
    sqlite3_finalize(check_stmt);

    /* Enforce terminal lifecycle */
    if (current_state == (int)CLIP_EVENT_STATUS_REVIEWED) {
        if (new_status == CLIP_EVENT_STATUS_REVIEWED) {
            return CLIP_ERR_EXISTS; /* Already marked REVIEWED */
        }
        return CLIP_ERR_INVALID; /* Terminal state cannot be altered */
    }
    if (current_state == (int)CLIP_EVENT_STATUS_FALSE_POS) {
        if (new_status == CLIP_EVENT_STATUS_FALSE_POS) {
            return CLIP_ERR_EXISTS; /* Already marked FALSE_POS */
        }
        return CLIP_ERR_INVALID; /* Terminal state cannot be altered */
    }

    /* Current state is PENDING: allow transition to REVIEWED or FALSE_POS */
    const char* update_sql = "UPDATE security_events SET review_state = ? WHERE event_id = ?;";
    sqlite3_stmt* update_stmt = NULL;
    rc = sqlite3_prepare_v2(db, update_sql, -1, &update_stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_int(update_stmt, 1, (int)new_status);
    sqlite3_bind_int(update_stmt, 2, (int)event_id);

    rc = sqlite3_step(update_stmt);
    sqlite3_finalize(update_stmt);

    return (rc == SQLITE_DONE) ? CLIP_OK : CLIP_ERR_STORAGE;
}

ClipError clip_admin_db_query_audit(sqlite3* db, size_t limit, ClipAdminAuditRecord* out_records, size_t* out_count)
{
    if (!db || !out_records || !out_count || limit == 0) return CLIP_ERR_INVALID;

    const char* sql =
        "SELECT audit_id, admin_uuid, action_type, target_uuid, reason, "
        "       related_event_id, related_session_uuid, related_channel_uuid, "
        "       status, error_code, created_at "
        "FROM admin_audit_log ORDER BY audit_id DESC LIMIT ?;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_int(stmt, 1, (int)limit);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < limit) {
        ClipAdminAuditRecord* rec = &out_records[count];
        memset(rec, 0, sizeof(ClipAdminAuditRecord));

        rec->audit_id = (uint32_t)sqlite3_column_int(stmt, 0);
        const void* a_blob = sqlite3_column_blob(stmt, 1);
        if (a_blob && sqlite3_column_bytes(stmt, 1) == CLIP_UUID_BYTES) {
            memcpy(rec->admin_uuid, a_blob, CLIP_UUID_BYTES);
        }
        rec->action_type = (ClipAdminActionType)sqlite3_column_int(stmt, 2);

        const void* t_blob = sqlite3_column_blob(stmt, 3);
        if (t_blob && sqlite3_column_bytes(stmt, 3) == CLIP_UUID_BYTES) {
            memcpy(rec->target_uuid, t_blob, CLIP_UUID_BYTES);
            rec->has_target_uuid = true;
        }

        const unsigned char* r = sqlite3_column_text(stmt, 4);
        if (r) strncpy(rec->reason, (const char*)r, sizeof(rec->reason) - 1);

        if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) {
            rec->related_event_id = (uint32_t)sqlite3_column_int(stmt, 5);
        }

        const void* s_blob = sqlite3_column_blob(stmt, 6);
        if (s_blob && sqlite3_column_bytes(stmt, 6) == CLIP_UUID_BYTES) {
            memcpy(rec->related_session_uuid, s_blob, CLIP_UUID_BYTES);
            rec->has_related_session = true;
        }

        const void* c_blob = sqlite3_column_blob(stmt, 7);
        if (c_blob && sqlite3_column_bytes(stmt, 7) == CLIP_UUID_BYTES) {
            memcpy(rec->related_channel_uuid, c_blob, CLIP_UUID_BYTES);
            rec->has_related_channel = true;
        }

        rec->status = (ClipAuditStatus)sqlite3_column_int(stmt, 8);
        rec->error_code = (int16_t)sqlite3_column_int(stmt, 9);
        rec->created_at_ms = (uint64_t)sqlite3_column_int64(stmt, 10);

        count++;
    }

    sqlite3_finalize(stmt);
    *out_count = count;
    return CLIP_OK;
}

ClipError clip_admin_db_lock_channel(sqlite3* db, const uint8_t channel_uuid[CLIP_UUID_BYTES], bool lock)
{
    if (!db || !channel_uuid) return CLIP_ERR_INVALID;

    const char* sql = "UPDATE channels SET active = ? WHERE channel_uuid = ?;";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_int(stmt, 1, lock ? 0 : 1);
    sqlite3_bind_blob(stmt, 2, channel_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return CLIP_ERR_STORAGE;
    return (changes > 0) ? CLIP_OK : CLIP_ERR_NOT_FOUND;
}

ClipError clip_admin_db_event_exists(sqlite3* db, uint32_t event_id, bool* out_exists)
{
    if (!db || !out_exists) return CLIP_ERR_INVALID;
    *out_exists = false;
    if (event_id == 0) return CLIP_OK;

    const char* sql = "SELECT 1 FROM security_events WHERE event_id = ? LIMIT 1;";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_int(stmt, 1, (int)event_id);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_exists = true;
    }
    sqlite3_finalize(stmt);
    return CLIP_OK;
}

ClipError clip_admin_db_session_exists(sqlite3* db, const uint8_t session_uuid[CLIP_UUID_BYTES], bool* out_exists)
{
    if (!db || !session_uuid || !out_exists) return CLIP_ERR_INVALID;
    *out_exists = false;

    const char* sql = "SELECT 1 FROM sessions WHERE session_uuid = ? LIMIT 1;";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, session_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_exists = true;
    }
    sqlite3_finalize(stmt);
    return CLIP_OK;
}

ClipError clip_admin_db_channel_exists(sqlite3* db, const uint8_t channel_uuid[CLIP_UUID_BYTES], bool* out_exists)
{
    if (!db || !channel_uuid || !out_exists) return CLIP_ERR_INVALID;
    *out_exists = false;

    const char* sql = "SELECT 1 FROM channels WHERE channel_uuid = ? LIMIT 1;";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, channel_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_exists = true;
    }
    sqlite3_finalize(stmt);
    return CLIP_OK;
}

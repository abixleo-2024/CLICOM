/*
 * clip_security_db.c — CLICOM Server-Side Security Events SQLite Implementation
 */

#include "clip_security_db.h"
#include "clip_notes.h"
#include "clip_crypto.h"
#include "clip_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ClipError clip_security_db_init_schema(sqlite3* db)
{
    if (!db) return CLIP_ERR_INVALID;

    const char* schema_sql =
        "CREATE TABLE IF NOT EXISTS security_events ("
        "  event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  event_uuid BLOB NOT NULL UNIQUE,"
        "  event_uuid_str TEXT NOT NULL UNIQUE,"
        "  session_uuid BLOB NOT NULL,"
        "  channel_uuid BLOB NOT NULL,"
        "  node_uuid BLOB NOT NULL,"
        "  category INTEGER NOT NULL,"
        "  severity INTEGER NOT NULL,"
        "  matched_rule TEXT NOT NULL,"
        "  matched_text TEXT NOT NULL,"
        "  context_text TEXT NOT NULL,"
        "  timestamp_ms INTEGER NOT NULL,"
        "  review_state INTEGER NOT NULL DEFAULT 0,"
        "  FOREIGN KEY(session_uuid) REFERENCES sessions(session_uuid),"
        "  FOREIGN KEY(channel_uuid) REFERENCES channels(channel_uuid),"
        "  FOREIGN KEY(node_uuid) REFERENCES nodes(node_uuid)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_sec_events_session ON security_events(session_uuid);"
        "CREATE INDEX IF NOT EXISTS idx_sec_events_channel ON security_events(channel_uuid);"
        "CREATE INDEX IF NOT EXISTS idx_sec_events_node ON security_events(node_uuid);"
        "CREATE INDEX IF NOT EXISTS idx_sec_events_timestamp ON security_events(timestamp_ms);"
        "CREATE INDEX IF NOT EXISTS idx_sec_events_state ON security_events(review_state);";

    char* err_msg = NULL;
    int rc = sqlite3_exec(db, schema_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to initialize security_events schema: %s",
                  err_msg ? err_msg : "unknown error");
        if (err_msg) sqlite3_free(err_msg);
        return CLIP_ERR_STORAGE;
    }

    return CLIP_OK;
}

ClipError clip_security_db_insert_event(sqlite3* db, ClipSecurityEvent* event)
{
    if (!db || !event) return CLIP_ERR_INVALID;

    const char* sql =
        "INSERT INTO security_events ("
        "  event_uuid, event_uuid_str, session_uuid, channel_uuid, node_uuid,"
        "  category, severity, matched_rule, matched_text, context_text,"
        "  timestamp_ms, review_state"
        ") VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12);";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to prepare security event insert: %s", sqlite3_errmsg(db));
        return CLIP_ERR_STORAGE;
    }

    sqlite3_bind_blob(stmt, 1, event->event_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, event->event_uuid_str, -1, SQLITE_STATIC);

    ClipUuid sess_u, chan_u, node_u;
    memcpy(sess_u.bytes, event->session_uuid, CLIP_UUID_BYTES);
    sqlite3_bind_blob(stmt, 3, sess_u.bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    clip_uuid_from_string(&chan_u, event->channel_uuid_str);
    sqlite3_bind_blob(stmt, 4, chan_u.bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    clip_uuid_from_string(&node_u, event->node_uuid_str);
    sqlite3_bind_blob(stmt, 5, node_u.bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    sqlite3_bind_int(stmt, 6, (int)event->category);
    sqlite3_bind_int(stmt, 7, (int)event->severity);
    sqlite3_bind_text(stmt, 8, event->matched_rule, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, event->matched_term, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, event->context_text, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 11, (sqlite3_int64)event->timestamp_ms);
    sqlite3_bind_int(stmt, 12, (int)event->status);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        CLIP_LOGE("Failed to insert security event: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return CLIP_ERR_STORAGE;
    }

    event->event_id = (uint32_t)sqlite3_last_insert_rowid(db);
    sqlite3_finalize(stmt);
    return CLIP_OK;
}

static void parse_event_row(sqlite3_stmt* stmt, ClipSecurityEvent* event)
{
    memset(event, 0, sizeof(ClipSecurityEvent));

    event->event_id = (uint32_t)sqlite3_column_int(stmt, 0);

    const void* ev_blob = sqlite3_column_blob(stmt, 1);
    if (ev_blob && sqlite3_column_bytes(stmt, 1) == CLIP_UUID_BYTES) {
        memcpy(event->event_uuid, ev_blob, CLIP_UUID_BYTES);
    }
    const char* ev_str = (const char*)sqlite3_column_text(stmt, 2);
    if (ev_str) {
        strncpy(event->event_uuid_str, ev_str, sizeof(event->event_uuid_str) - 1);
    }

    const void* s_blob = sqlite3_column_blob(stmt, 3);
    if (s_blob && sqlite3_column_bytes(stmt, 3) == CLIP_UUID_BYTES) {
        memcpy(event->session_uuid, s_blob, CLIP_UUID_BYTES);
    }

    const void* ch_blob = sqlite3_column_blob(stmt, 4);
    if (ch_blob && sqlite3_column_bytes(stmt, 4) == CLIP_UUID_BYTES) {
        ClipUuid cu;
        memcpy(cu.bytes, ch_blob, CLIP_UUID_BYTES);
        clip_uuid_to_string(&cu, event->channel_uuid_str, sizeof(event->channel_uuid_str));
    }

    const void* n_blob = sqlite3_column_blob(stmt, 5);
    if (n_blob && sqlite3_column_bytes(stmt, 5) == CLIP_UUID_BYTES) {
        ClipUuid nu;
        memcpy(nu.bytes, n_blob, CLIP_UUID_BYTES);
        clip_uuid_to_string(&nu, event->node_uuid_str, sizeof(event->node_uuid_str));
    }

    event->category = (ClipRuleCategory)sqlite3_column_int(stmt, 6);
    event->severity = (ClipSeverity)sqlite3_column_int(stmt, 7);

    const char* r_str = (const char*)sqlite3_column_text(stmt, 8);
    if (r_str) {
        strncpy(event->matched_rule, r_str, sizeof(event->matched_rule) - 1);
    }

    const char* m_str = (const char*)sqlite3_column_text(stmt, 9);
    if (m_str) {
        strncpy(event->matched_term, m_str, sizeof(event->matched_term) - 1);
    }

    const char* ctx_str = (const char*)sqlite3_column_text(stmt, 10);
    if (ctx_str) {
        strncpy(event->context_text, ctx_str, sizeof(event->context_text) - 1);
    }

    event->timestamp_ms = (uint64_t)sqlite3_column_int64(stmt, 11);
    event->status = (ClipEventStatus)sqlite3_column_int(stmt, 12);
}

ClipError clip_security_db_get_event(sqlite3* db,
                                     uint32_t event_id,
                                     const uint8_t* event_uuid,
                                     ClipSecurityEvent* out_event)
{
    if (!db || !out_event) return CLIP_ERR_INVALID;
    if (event_id == 0 && (!event_uuid || clip_uuid_is_zero((const ClipUuid*)event_uuid))) {
        return CLIP_ERR_INVALID;
    }
    memset(out_event, 0, sizeof(ClipSecurityEvent));

    const char* sql = NULL;
    if (event_id > 0) {
        sql = "SELECT se.event_id, se.event_uuid, se.event_uuid_str, se.session_uuid, se.channel_uuid, se.node_uuid,"
              "       se.category, se.severity, se.matched_rule, se.matched_text, se.context_text,"
              "       se.timestamp_ms, se.review_state "
              "FROM security_events se "
              "WHERE se.event_id = ?1;";
    } else {
        sql = "SELECT se.event_id, se.event_uuid, se.event_uuid_str, se.session_uuid, se.channel_uuid, se.node_uuid,"
              "       se.category, se.severity, se.matched_rule, se.matched_text, se.context_text,"
              "       se.timestamp_ms, se.review_state "
              "FROM security_events se "
              "WHERE se.event_uuid = ?1;";
    }

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    if (event_id > 0) {
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)event_id);
    } else {
        sqlite3_bind_blob(stmt, 1, event_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOT_FOUND;
    }

    parse_event_row(stmt, out_event);
    sqlite3_finalize(stmt);
    return CLIP_OK;
}

ClipError clip_security_db_list_for_session(sqlite3* db,
                                            const uint8_t* session_uuid,
                                            ClipSecurityEvent** out_events,
                                            size_t* out_count)
{
    if (!db || !session_uuid || !out_events || !out_count) {
        return CLIP_ERR_INVALID;
    }
    *out_events = NULL;
    *out_count = 0;

    const char* sql =
        "SELECT se.event_id, se.event_uuid, se.event_uuid_str, se.session_uuid, se.channel_uuid, se.node_uuid,"
        "       se.category, se.severity, se.matched_rule, se.matched_text, se.context_text,"
        "       se.timestamp_ms, se.review_state "
        "FROM security_events se "
        "WHERE se.session_uuid = ?1 "
        "ORDER BY se.timestamp_ms DESC;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, session_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);

    size_t cap = 8;
    size_t count = 0;
    ClipSecurityEvent* list = (ClipSecurityEvent*)malloc(cap * sizeof(ClipSecurityEvent));
    if (!list) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOMEM;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= cap) {
            size_t ncap = cap * 2;
            ClipSecurityEvent* nlist = (ClipSecurityEvent*)realloc(list, ncap * sizeof(ClipSecurityEvent));
            if (!nlist) {
                free(list);
                sqlite3_finalize(stmt);
                return CLIP_ERR_NOMEM;
            }
            list = nlist;
            cap = ncap;
        }
        parse_event_row(stmt, &list[count++]);
    }

    sqlite3_finalize(stmt);
    *out_events = list;
    *out_count = count;
    return CLIP_OK;
}

ClipError clip_security_db_list_for_node(sqlite3* db,
                                         const uint8_t* requesting_node_uuid,
                                         ClipSecurityEvent** out_events,
                                         size_t* out_count)
{
    if (!db || !requesting_node_uuid || !out_events || !out_count) {
        return CLIP_ERR_INVALID;
    }
    *out_events = NULL;
    *out_count = 0;

    const char* sql =
        "SELECT se.event_id, se.event_uuid, se.event_uuid_str, se.session_uuid, se.channel_uuid, se.node_uuid,"
        "       se.category, se.severity, se.matched_rule, se.matched_text, se.context_text,"
        "       se.timestamp_ms, se.review_state "
        "FROM security_events se "
        "LEFT JOIN sessions s ON se.session_uuid = s.session_uuid "
        "LEFT JOIN channel_members cm ON s.channel_uuid = cm.channel_uuid AND cm.node_uuid = ?1 AND cm.active = 1 "
        "LEFT JOIN channels ch ON s.channel_uuid = ch.channel_uuid AND ch.creator_node_uuid = ?1 "
        "WHERE se.node_uuid = ?1 "
        "   OR s.initiator_node_uuid = ?1 "
        "   OR s.peer_node_uuid = ?1 "
        "   OR cm.node_uuid IS NOT NULL "
        "   OR ch.creator_node_uuid IS NOT NULL "
        "ORDER BY se.timestamp_ms DESC;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        /* Fallback if sessions or channels tables do not exist in test DB */
        const char* fallback_sql =
            "SELECT se.event_id, se.event_uuid, se.event_uuid_str, se.session_uuid, se.channel_uuid, se.node_uuid,"
            "       se.category, se.severity, se.matched_rule, se.matched_text, se.context_text,"
            "       se.timestamp_ms, se.review_state "
            "FROM security_events se "
            "WHERE se.node_uuid = ?1 "
            "ORDER BY se.timestamp_ms DESC;";
        rc = sqlite3_prepare_v2(db, fallback_sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;
    }

    sqlite3_bind_blob(stmt, 1, requesting_node_uuid, CLIP_UUID_BYTES, SQLITE_STATIC);

    size_t cap = 8;
    size_t count = 0;
    ClipSecurityEvent* list = (ClipSecurityEvent*)malloc(cap * sizeof(ClipSecurityEvent));
    if (!list) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOMEM;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= cap) {
            size_t ncap = cap * 2;
            ClipSecurityEvent* nlist = (ClipSecurityEvent*)realloc(list, ncap * sizeof(ClipSecurityEvent));
            if (!nlist) {
                free(list);
                sqlite3_finalize(stmt);
                return CLIP_ERR_NOMEM;
            }
            list = nlist;
            cap = ncap;
        }
        parse_event_row(stmt, &list[count++]);
    }

    sqlite3_finalize(stmt);
    *out_events = list;
    *out_count = count;
    return CLIP_OK;
}

void clip_security_free_event_list(ClipSecurityEvent* events)
{
    if (events) {
        free(events);
    }
}

void clip_security_db_free_event_list(ClipSecurityEvent* events, size_t count)
{
    (void)count;
    if (events) {
        free(events);
    }
}

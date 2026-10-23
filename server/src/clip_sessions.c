/*
 * clip_sessions.c — CLICOM Server-Side Communication Session Management
 */

#include "clip_sessions.h"
#include "clip_channels.h"
#include "clip_connections.h"
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

static void parse_session_row(sqlite3_stmt* stmt, ClipSessionRecord* out_session)
{
    memset(out_session, 0, sizeof(ClipSessionRecord));

    const void* s_blob = sqlite3_column_blob(stmt, 0);
    if (s_blob && sqlite3_column_bytes(stmt, 0) == CLIP_UUID_BYTES) {
        memcpy(out_session->session_uuid.bytes, s_blob, CLIP_UUID_BYTES);
    }

    const unsigned char* s_str = sqlite3_column_text(stmt, 1);
    if (s_str) {
        strncpy(out_session->session_uuid_str, (const char*)s_str, sizeof(out_session->session_uuid_str) - 1);
    }

    const void* cu_blob = sqlite3_column_blob(stmt, 2);
    if (cu_blob && sqlite3_column_bytes(stmt, 2) == CLIP_UUID_BYTES) {
        memcpy(out_session->connection_uuid.bytes, cu_blob, CLIP_UUID_BYTES);
    }

    const void* ch_blob = sqlite3_column_blob(stmt, 3);
    if (ch_blob && sqlite3_column_bytes(stmt, 3) == CLIP_UUID_BYTES) {
        memcpy(out_session->channel_uuid.bytes, ch_blob, CLIP_UUID_BYTES);
    }

    const void* init_blob = sqlite3_column_blob(stmt, 4);
    if (init_blob && sqlite3_column_bytes(stmt, 4) == CLIP_UUID_BYTES) {
        memcpy(out_session->initiator_node_uuid.bytes, init_blob, CLIP_UUID_BYTES);
    }

    const void* peer_blob = sqlite3_column_blob(stmt, 5);
    if (peer_blob && sqlite3_column_bytes(stmt, 5) == CLIP_UUID_BYTES) {
        memcpy(out_session->peer_node_uuid.bytes, peer_blob, CLIP_UUID_BYTES);
    }

    out_session->state = (ClipSessionState)sqlite3_column_int(stmt, 6);
    out_session->created_at_ms = (uint64_t)sqlite3_column_int64(stmt, 7);
    out_session->ended_at_ms = (uint64_t)sqlite3_column_int64(stmt, 8);
}

ClipError clip_session_db_init_schema(sqlite3* db)
{
    if (!db) return CLIP_ERR_INVALID;

    const char* schema_sql =
        "CREATE TABLE IF NOT EXISTS sessions ("
        "  session_uuid BLOB PRIMARY KEY NOT NULL,"
        "  session_uuid_str TEXT NOT NULL UNIQUE,"
        "  connection_uuid BLOB,"
        "  channel_uuid BLOB NOT NULL,"
        "  initiator_node_uuid BLOB NOT NULL,"
        "  peer_node_uuid BLOB,"
        "  state INTEGER NOT NULL DEFAULT 1,"
        "  created_at INTEGER NOT NULL,"
        "  ended_at INTEGER NOT NULL DEFAULT 0,"
        "  FOREIGN KEY(channel_uuid) REFERENCES channels(channel_uuid),"
        "  FOREIGN KEY(initiator_node_uuid) REFERENCES nodes(node_uuid)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_sessions_channel ON sessions(channel_uuid);"
        "CREATE INDEX IF NOT EXISTS idx_sessions_conn_active ON sessions(connection_uuid, state);";

    char* err_msg = NULL;
    int rc = sqlite3_exec(db, schema_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to create sessions schema: %s", err_msg ? err_msg : "unknown error");
        if (err_msg) sqlite3_free(err_msg);
        return CLIP_ERR_STORAGE;
    }

    /* Safe backward-compatible migration for pre-existing databases */
    sqlite3_exec(db, "ALTER TABLE sessions ADD COLUMN connection_uuid BLOB;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE sessions ADD COLUMN peer_node_uuid BLOB;", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_sessions_conn_active ON sessions(connection_uuid, state);", NULL, NULL, NULL);

    /*
     * Restart / crash sweep:
     * Inactive / unclosed sessions from previous server runs must transition to CLOSED
     * so active communication sessions never resume across restarts.
     * Historical records remain in SQLite intact.
     */
    uint64_t now = current_time_ms();
    const char* sweep_sql = "UPDATE sessions SET state = 3, ended_at = ? WHERE state = 1;";
    sqlite3_stmt* sw_stmt = NULL;
    if (sqlite3_prepare_v2(db, sweep_sql, -1, &sw_stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(sw_stmt, 1, (sqlite3_int64)now);
        sqlite3_step(sw_stmt);
        sqlite3_finalize(sw_stmt);
    }

    return CLIP_OK;
}

ClipError clip_session_create_for_connection(sqlite3*        db,
                                             const ClipUuid* conn_uuid,
                                             const ClipUuid* initiator_node_uuid,
                                             ClipUuid*       out_session_uuid)
{
    if (!db || !conn_uuid || !initiator_node_uuid || !out_session_uuid) {
        return CLIP_ERR_INVALID;
    }

    /* 1. Retrieve connection and verify it exists */
    ClipConnectionRecord conn;
    ClipError get_c_err = clip_connection_get(db, conn_uuid, &conn);
    if (get_c_err != CLIP_OK) {
        CLIP_LOGW("Session create rejected: connection not found");
        return get_c_err;
    }

    /* 2. Connection state MUST be ACCEPTED */
    if (conn.state != CLIP_CONN_STATE_ACCEPTED) {
        CLIP_LOGW("Session create rejected: connection state is %d (expected ACCEPTED)", (int)conn.state);
        return CLIP_ERR_DENIED;
    }

    /* 3. Initiator must be an endpoint of the connection */
    bool is_req = clip_uuid_equal(initiator_node_uuid, &conn.requester_node_uuid);
    bool is_tgt = clip_uuid_equal(initiator_node_uuid, &conn.target_node_uuid);
    if (!is_req && !is_tgt) {
        CLIP_LOGW("Session create rejected: initiator is not a party of the connection");
        return CLIP_ERR_DENIED;
    }

    const ClipUuid* peer_node_uuid = is_req ? &conn.target_node_uuid : &conn.requester_node_uuid;

    /* 4. Reject duplicate active session for this connection */
    ClipSessionRecord active_sess;
    if (clip_session_get_active_for_connection(db, conn_uuid, &active_sess) == CLIP_OK) {
        CLIP_LOGW("Session create rejected: an active session already exists for this connection");
        return CLIP_ERR_EXISTS;
    }

    /* 5. Generate fresh unique session_uuid */
    ClipUuid sess_uuid;
    ClipError uuid_err = clip_crypto_uuid_generate(&sess_uuid);
    if (uuid_err != CLIP_OK) return uuid_err;

    /* Strict identity separation: session_uuid != node_a != node_b != channel_uuid != connection_uuid */
    while (clip_uuid_equal(&sess_uuid, initiator_node_uuid) ||
           clip_uuid_equal(&sess_uuid, peer_node_uuid) ||
           clip_uuid_equal(&sess_uuid, &conn.channel_uuid) ||
           clip_uuid_equal(&sess_uuid, conn_uuid)) {
        clip_crypto_uuid_generate(&sess_uuid);
    }

    char sess_uuid_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(&sess_uuid, sess_uuid_str, sizeof(sess_uuid_str));

    uint64_t now = current_time_ms();

    const char* ins_sql =
        "INSERT INTO sessions (session_uuid, session_uuid_str, connection_uuid, channel_uuid, "
        "                      initiator_node_uuid, peer_node_uuid, state, created_at, ended_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0);";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, ins_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, sess_uuid.bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, sess_uuid_str, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, conn_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, conn.channel_uuid.bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, initiator_node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, peer_node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, (int)CLIP_SESSION_STATE_ACTIVE);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return CLIP_ERR_STORAGE;

    memcpy(out_session_uuid->bytes, sess_uuid.bytes, CLIP_UUID_BYTES);
    CLIP_LOGI("Communication session created: UUID=%s for connection", sess_uuid_str);

    return CLIP_OK;
}

ClipError clip_session_start(sqlite3*        db,
                             const ClipUuid* channel_uuid,
                             const ClipUuid* initiator_node_uuid,
                             ClipUuid*       out_session_uuid)
{
    if (!db || !channel_uuid || !initiator_node_uuid || !out_session_uuid) {
        return CLIP_ERR_INVALID;
    }

    /* 1. Verify channel membership */
    bool is_member = false;
    ClipError mem_err = clip_channel_is_member(db, channel_uuid, initiator_node_uuid, &is_member);
    if (mem_err != CLIP_OK) return mem_err;
    if (!is_member) {
        CLIP_LOGW("Session start rejected: initiator is not a member of the channel");
        return CLIP_ERR_DENIED;
    }

    /* 2. Verify channel is active */
    ClipChannelRecord chan;
    ClipError chan_err = clip_channel_get_by_uuid(db, channel_uuid, &chan);
    if (chan_err != CLIP_OK) return chan_err;
    if (!chan.active) {
        CLIP_LOGW("Session start rejected: channel is not active");
        return CLIP_ERR_DENIED;
    }

    /* Check if an active session already exists for this channel */
    ClipSessionRecord existing_sess;
    if (clip_session_get_active_for_channel(db, channel_uuid, &existing_sess) == CLIP_OK) {
        memcpy(out_session_uuid->bytes, existing_sess.session_uuid.bytes, CLIP_UUID_BYTES);
        return CLIP_OK;
    }

    /* 3. Generate unique session_uuid */
    ClipUuid sess_uuid;
    ClipError uuid_err = clip_crypto_uuid_generate(&sess_uuid);
    if (uuid_err != CLIP_OK) return uuid_err;

    /* Enforce invariant: session_uuid != node_uuid and session_uuid != channel_uuid */
    if (clip_uuid_equal(&sess_uuid, initiator_node_uuid) ||
        clip_uuid_equal(&sess_uuid, channel_uuid)) {
        clip_crypto_uuid_generate(&sess_uuid);
    }

    char sess_uuid_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(&sess_uuid, sess_uuid_str, sizeof(sess_uuid_str));

    uint64_t now = current_time_ms();

    const char* ins_sql =
        "INSERT INTO sessions (session_uuid, session_uuid_str, connection_uuid, channel_uuid, "
        "                      initiator_node_uuid, peer_node_uuid, state, created_at, ended_at) "
        "VALUES (?, ?, NULL, ?, ?, NULL, ?, ?, 0);";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, ins_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, sess_uuid.bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, sess_uuid_str, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, initiator_node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, (int)CLIP_SESSION_STATE_ACTIVE);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return CLIP_ERR_STORAGE;

    memcpy(out_session_uuid->bytes, sess_uuid.bytes, CLIP_UUID_BYTES);
    CLIP_LOGI("Session started: UUID=%s for channel %s", sess_uuid_str, chan.channel_uuid_str);

    return CLIP_OK;
}

ClipError clip_session_end(sqlite3*        db,
                           const ClipUuid* session_uuid,
                           const ClipUuid* requester_node_uuid)
{
    if (!db || !session_uuid || !requester_node_uuid) {
        return CLIP_ERR_INVALID;
    }

    ClipSessionRecord sess;
    ClipError get_err = clip_session_get(db, session_uuid, &sess);
    if (get_err != CLIP_OK) return get_err;

    if (sess.state != CLIP_SESSION_STATE_ACTIVE) {
        CLIP_LOGW("Session end rejected: session %s is not active (state=%d)",
                  sess.session_uuid_str, (int)sess.state);
        return CLIP_ERR_NO_SESSION;
    }

    /* Verify requester is an endpoint of the session or a member of the session's channel */
    bool is_authorized = false;
    if (clip_uuid_equal(requester_node_uuid, &sess.initiator_node_uuid) ||
        (!clip_uuid_is_zero(&sess.peer_node_uuid) && clip_uuid_equal(requester_node_uuid, &sess.peer_node_uuid))) {
        is_authorized = true;
    } else {
        clip_channel_is_member(db, &sess.channel_uuid, requester_node_uuid, &is_authorized);
    }

    if (!is_authorized) {
        CLIP_LOGW("Session end rejected: requester is not authorized for session %s", sess.session_uuid_str);
        return CLIP_ERR_DENIED;
    }

    uint64_t now = current_time_ms();
    const char* upd_sql =
        "UPDATE sessions SET state = ?, ended_at = ? WHERE session_uuid = ?;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, upd_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_int(stmt, 1, (int)CLIP_SESSION_STATE_CLOSED);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
    sqlite3_bind_blob(stmt, 3, session_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return CLIP_ERR_STORAGE;

    CLIP_LOGI("Session ended: UUID=%s", sess.session_uuid_str);
    return CLIP_OK;
}

ClipError clip_session_get(sqlite3*           db,
                           const ClipUuid*    session_uuid,
                           ClipSessionRecord* out_session)
{
    if (!db || !session_uuid || !out_session) return CLIP_ERR_INVALID;

    const char* sql =
        "SELECT session_uuid, session_uuid_str, connection_uuid, channel_uuid, "
        "       initiator_node_uuid, peer_node_uuid, state, created_at, ended_at "
        "FROM sessions WHERE session_uuid = ? LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, session_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOT_FOUND;
    }

    parse_session_row(stmt, out_session);
    sqlite3_finalize(stmt);
    return CLIP_OK;
}

ClipError clip_session_get_active_for_connection(sqlite3*           db,
                                                 const ClipUuid*    conn_uuid,
                                                 ClipSessionRecord* out_session)
{
    if (!db || !conn_uuid || !out_session) return CLIP_ERR_INVALID;

    const char* sql =
        "SELECT session_uuid, session_uuid_str, connection_uuid, channel_uuid, "
        "       initiator_node_uuid, peer_node_uuid, state, created_at, ended_at "
        "FROM sessions WHERE connection_uuid = ? AND state = 1 ORDER BY created_at DESC LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, conn_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOT_FOUND;
    }

    parse_session_row(stmt, out_session);
    sqlite3_finalize(stmt);
    return CLIP_OK;
}

ClipError clip_session_get_active_for_channel(sqlite3*           db,
                                              const ClipUuid*    channel_uuid,
                                              ClipSessionRecord* out_session)
{
    if (!db || !channel_uuid || !out_session) return CLIP_ERR_INVALID;

    const char* sql =
        "SELECT session_uuid, session_uuid_str, connection_uuid, channel_uuid, "
        "       initiator_node_uuid, peer_node_uuid, state, created_at, ended_at "
        "FROM sessions WHERE channel_uuid = ? AND state = 1 ORDER BY created_at DESC LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return CLIP_ERR_STORAGE;

    sqlite3_bind_blob(stmt, 1, channel_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CLIP_ERR_NOT_FOUND;
    }

    parse_session_row(stmt, out_session);
    sqlite3_finalize(stmt);
    return CLIP_OK;
}

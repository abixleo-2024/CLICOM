/*
 * clip_notes.c — CLICOM Server-Side Communication Notes & Session Logs
 */

#include "clip_notes.h"
#include "clip_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t current_time_ms(void)
{
    return (uint64_t)time(NULL) * 1000ULL;
}

bool clip_notes_db_init_schema(sqlite3* db)
{
    if (!db) return false;

    const char* schema_sql =
        "CREATE TABLE IF NOT EXISTS session_notes ("
        "  note_id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  session_uuid     BLOB NOT NULL,"
        "  author_node_uuid BLOB NOT NULL,"
        "  note_type        INTEGER NOT NULL DEFAULT 1,"
        "  created_at       INTEGER NOT NULL,"
        "  note_text        TEXT NOT NULL,"
        "  FOREIGN KEY(session_uuid) REFERENCES sessions(session_uuid),"
        "  FOREIGN KEY(author_node_uuid) REFERENCES nodes(node_uuid)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_notes_session ON session_notes(session_uuid, created_at);"
        "CREATE INDEX IF NOT EXISTS idx_notes_author ON session_notes(author_node_uuid);";

    char* err_msg = NULL;
    int rc = sqlite3_exec(db, schema_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to create session_notes schema: %s", err_msg ? err_msg : "unknown error");
        if (err_msg) sqlite3_free(err_msg);
        return false;
    }
    return true;
}

bool clip_session_is_authorized(sqlite3* db,
                                const ClipUuid* session_uuid,
                                const ClipUuid* node_uuid,
                                bool* out_authorized)
{
    if (!db || !session_uuid || !node_uuid || !out_authorized) {
        return false;
    }
    *out_authorized = false;

    const char* sql =
        "SELECT 1 FROM sessions s "
        "LEFT JOIN channel_members cm ON s.channel_uuid = cm.channel_uuid AND cm.node_uuid = ?2 AND cm.active = 1 "
        "LEFT JOIN channels ch ON s.channel_uuid = ch.channel_uuid AND ch.creator_node_uuid = ?2 "
        "WHERE s.session_uuid = ?1 "
        "  AND (s.initiator_node_uuid = ?2 OR s.peer_node_uuid = ?2 OR cm.node_uuid IS NOT NULL OR ch.creator_node_uuid IS NOT NULL) "
        "LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to prepare session authorization statement: %s", sqlite3_errmsg(db));
        return false;
    }

    sqlite3_bind_blob(stmt, 1, session_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    int step_rc = sqlite3_step(stmt);
    if (step_rc == SQLITE_ROW) {
        *out_authorized = true;
    }
    sqlite3_finalize(stmt);
    return true;
}

static void parse_session_log_row(sqlite3_stmt* stmt, ClipSessionLogEntry* entry)
{
    memset(entry, 0, sizeof(ClipSessionLogEntry));

    const void* s_blob = sqlite3_column_blob(stmt, 0);
    if (s_blob && sqlite3_column_bytes(stmt, 0) == CLIP_UUID_BYTES) {
        memcpy(entry->session_uuid.bytes, s_blob, CLIP_UUID_BYTES);
    }
    const void* ch_blob = sqlite3_column_blob(stmt, 1);
    if (ch_blob && sqlite3_column_bytes(stmt, 1) == CLIP_UUID_BYTES) {
        memcpy(entry->channel_uuid.bytes, ch_blob, CLIP_UUID_BYTES);
    }
    const void* cu_blob = sqlite3_column_blob(stmt, 2);
    if (cu_blob && sqlite3_column_bytes(stmt, 2) == CLIP_UUID_BYTES) {
        memcpy(entry->connection_uuid.bytes, cu_blob, CLIP_UUID_BYTES);
    }
    const void* init_blob = sqlite3_column_blob(stmt, 3);
    if (init_blob && sqlite3_column_bytes(stmt, 3) == CLIP_UUID_BYTES) {
        memcpy(entry->initiator_node_uuid.bytes, init_blob, CLIP_UUID_BYTES);
    }
    const void* peer_blob = sqlite3_column_blob(stmt, 4);
    if (peer_blob && sqlite3_column_bytes(stmt, 4) == CLIP_UUID_BYTES) {
        memcpy(entry->peer_node_uuid.bytes, peer_blob, CLIP_UUID_BYTES);
    }

    entry->state = (uint8_t)sqlite3_column_int(stmt, 5);
    entry->created_at = (uint64_t)sqlite3_column_int64(stmt, 6);
    entry->ended_at = (uint64_t)sqlite3_column_int64(stmt, 7);
    entry->note_count = (uint32_t)sqlite3_column_int(stmt, 8);

    uint64_t now_ms = current_time_ms();
    if (entry->ended_at > entry->created_at) {
        entry->duration_ms = entry->ended_at - entry->created_at;
    } else if (entry->ended_at == 0 && entry->state == 1 /* CLIP_SESSION_ACTIVE */) {
        entry->duration_ms = (now_ms > entry->created_at) ? (now_ms - entry->created_at) : 0;
    } else {
        entry->duration_ms = 0;
    }
}

bool clip_session_list_for_node(sqlite3* db,
                                const ClipUuid* node_uuid,
                                ClipSessionLogEntry** out_entries,
                                size_t* out_count)
{
    if (!db || !out_entries || !out_count) {
        return false;
    }
    *out_entries = NULL;
    *out_count = 0;

    const char* sql = NULL;
    if (node_uuid) {
        sql =
            "SELECT s.session_uuid, s.channel_uuid, s.connection_uuid, s.initiator_node_uuid, s.peer_node_uuid, "
            "       s.state, s.created_at, s.ended_at, "
            "       (SELECT COUNT(*) FROM session_notes sn WHERE sn.session_uuid = s.session_uuid) AS note_count "
            "FROM sessions s "
            "LEFT JOIN channel_members cm ON s.channel_uuid = cm.channel_uuid AND cm.node_uuid = ?1 AND cm.active = 1 "
            "LEFT JOIN channels ch ON s.channel_uuid = ch.channel_uuid AND ch.creator_node_uuid = ?1 "
            "WHERE s.initiator_node_uuid = ?1 OR s.peer_node_uuid = ?1 OR cm.node_uuid IS NOT NULL OR ch.creator_node_uuid IS NOT NULL "
            "ORDER BY s.created_at DESC;";
    } else {
        sql =
            "SELECT s.session_uuid, s.channel_uuid, s.connection_uuid, s.initiator_node_uuid, s.peer_node_uuid, "
            "       s.state, s.created_at, s.ended_at, "
            "       (SELECT COUNT(*) FROM session_notes sn WHERE sn.session_uuid = s.session_uuid) AS note_count "
            "FROM sessions s "
            "ORDER BY s.created_at DESC;";
    }

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to prepare session list query: %s", sqlite3_errmsg(db));
        return false;
    }

    if (node_uuid) {
        sqlite3_bind_blob(stmt, 1, node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    }

    size_t capacity = 16;
    size_t count = 0;
    ClipSessionLogEntry* list = (ClipSessionLogEntry*)malloc(capacity * sizeof(ClipSessionLogEntry));
    if (!list) {
        sqlite3_finalize(stmt);
        return false;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= capacity) {
            size_t new_cap = capacity * 2;
            ClipSessionLogEntry* new_list = (ClipSessionLogEntry*)realloc(list, new_cap * sizeof(ClipSessionLogEntry));
            if (!new_list) {
                free(list);
                sqlite3_finalize(stmt);
                return false;
            }
            list = new_list;
            capacity = new_cap;
        }

        parse_session_log_row(stmt, &list[count]);
        count++;
    }

    sqlite3_finalize(stmt);
    *out_entries = list;
    *out_count = count;
    return true;
}

bool clip_session_get_log(sqlite3* db,
                          const ClipUuid* session_uuid,
                          ClipSessionLogEntry* out_entry)
{
    if (!db || !session_uuid || !out_entry) {
        return false;
    }
    memset(out_entry, 0, sizeof(ClipSessionLogEntry));

    const char* sql =
        "SELECT s.session_uuid, s.channel_uuid, s.connection_uuid, s.initiator_node_uuid, s.peer_node_uuid, "
        "       s.state, s.created_at, s.ended_at, "
        "       (SELECT COUNT(*) FROM session_notes sn WHERE sn.session_uuid = s.session_uuid) AS note_count "
        "FROM sessions s "
        "WHERE s.session_uuid = ?1 "
        "LIMIT 1;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        CLIP_LOGE("Failed to prepare session get log statement: %s", sqlite3_errmsg(db));
        return false;
    }

    sqlite3_bind_blob(stmt, 1, session_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        parse_session_log_row(stmt, out_entry);
        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3_finalize(stmt);
    return false;
}

void clip_session_free_log_list(ClipSessionLogEntry* entries)
{
    if (entries) {
        free(entries);
    }
}

bool clip_notes_create(sqlite3* db,
                       const ClipUuid* session_uuid,
                       const ClipUuid* author_node_uuid,
                       ClipNoteType note_type,
                       const char* note_text,
                       uint32_t* out_note_id)
{
    if (!db || !session_uuid || !author_node_uuid || !note_text) {
        return false;
    }

    size_t len = strlen(note_text);
    if (len == 0 || len > CLIP_NOTE_TEXT_MAX_LEN) {
        CLIP_LOGE("Note text length %zu invalid (max %d, min 1)", len, CLIP_NOTE_TEXT_MAX_LEN);
        return false;
    }

    if (note_type != CLIP_NOTE_TYPE_MANUAL && note_type != CLIP_NOTE_TYPE_TRANSCRIPT) {
        CLIP_LOGE("Invalid note type %d", (int)note_type);
        return false;
    }

    /* Verify session exists */
    const char* check_sql = "SELECT 1 FROM sessions WHERE session_uuid = ?1 LIMIT 1;";
    sqlite3_stmt* check_stmt = NULL;
    if (sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, NULL) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_blob(check_stmt, 1, session_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    int step_rc = sqlite3_step(check_stmt);
    sqlite3_finalize(check_stmt);
    if (step_rc != SQLITE_ROW) {
        CLIP_LOGE("Cannot add note: session does not exist");
        return false;
    }

    const char* insert_sql =
        "INSERT INTO session_notes (session_uuid, author_node_uuid, note_type, created_at, note_text) "
        "VALUES (?1, ?2, ?3, ?4, ?5);";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL) != SQLITE_OK) {
        CLIP_LOGE("Failed to prepare note insert: %s", sqlite3_errmsg(db));
        return false;
    }

    uint64_t created_at = current_time_ms();
    sqlite3_bind_blob(stmt, 1, session_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, author_node_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, (int)note_type);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)created_at);
    sqlite3_bind_text(stmt, 5, note_text, (int)len, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        CLIP_LOGE("Failed to execute note insert: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    if (out_note_id) {
        *out_note_id = (uint32_t)sqlite3_last_insert_rowid(db);
    }
    return true;
}

static void parse_note_row(sqlite3_stmt* stmt, ClipSessionNoteEntry* note)
{
    memset(note, 0, sizeof(ClipSessionNoteEntry));

    note->note_id = (uint32_t)sqlite3_column_int(stmt, 0);

    const void* s_blob = sqlite3_column_blob(stmt, 1);
    if (s_blob && sqlite3_column_bytes(stmt, 1) == CLIP_UUID_BYTES) {
        memcpy(note->session_uuid.bytes, s_blob, CLIP_UUID_BYTES);
    }

    const void* a_blob = sqlite3_column_blob(stmt, 2);
    if (a_blob && sqlite3_column_bytes(stmt, 2) == CLIP_UUID_BYTES) {
        memcpy(note->author_node_uuid.bytes, a_blob, CLIP_UUID_BYTES);
    }

    note->note_type = (ClipNoteType)sqlite3_column_int(stmt, 3);
    note->created_at = (uint64_t)sqlite3_column_int64(stmt, 4);

    const unsigned char* text = sqlite3_column_text(stmt, 5);
    if (text) {
        strncpy(note->note_text, (const char*)text, CLIP_NOTE_TEXT_MAX_LEN);
        note->note_text[CLIP_NOTE_TEXT_MAX_LEN] = '\0';
    }
}

bool clip_notes_list_for_session(sqlite3* db,
                                const ClipUuid* session_uuid,
                                ClipSessionNoteEntry** out_notes,
                                size_t* out_count)
{
    if (!db || !session_uuid || !out_notes || !out_count) {
        return false;
    }
    *out_notes = NULL;
    *out_count = 0;

    const char* sql =
        "SELECT note_id, session_uuid, author_node_uuid, note_type, created_at, note_text "
        "FROM session_notes "
        "WHERE session_uuid = ?1 "
        "ORDER BY created_at ASC, note_id ASC;";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        CLIP_LOGE("Failed to prepare note list query: %s", sqlite3_errmsg(db));
        return false;
    }

    sqlite3_bind_blob(stmt, 1, session_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    size_t capacity = 16;
    size_t count = 0;
    ClipSessionNoteEntry* list = (ClipSessionNoteEntry*)malloc(capacity * sizeof(ClipSessionNoteEntry));
    if (!list) {
        sqlite3_finalize(stmt);
        return false;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= capacity) {
            size_t new_cap = capacity * 2;
            ClipSessionNoteEntry* new_list = (ClipSessionNoteEntry*)realloc(list, new_cap * sizeof(ClipSessionNoteEntry));
            if (!new_list) {
                free(list);
                sqlite3_finalize(stmt);
                return false;
            }
            list = new_list;
            capacity = new_cap;
        }

        parse_note_row(stmt, &list[count]);
        count++;
    }

    sqlite3_finalize(stmt);
    *out_notes = list;
    *out_count = count;
    return true;
}

bool clip_notes_search(sqlite3* db,
                       const ClipUuid* session_uuid,
                       const char* query,
                       ClipSessionNoteEntry** out_notes,
                       size_t* out_count)
{
    if (!db || !session_uuid || !query || !out_notes || !out_count) {
        return false;
    }
    *out_notes = NULL;
    *out_count = 0;

    const char* sql =
        "SELECT note_id, session_uuid, author_node_uuid, note_type, created_at, note_text "
        "FROM session_notes "
        "WHERE session_uuid = ?1 AND note_text LIKE ?2 "
        "ORDER BY created_at ASC, note_id ASC;";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        CLIP_LOGE("Failed to prepare note search query: %s", sqlite3_errmsg(db));
        return false;
    }

    char pattern[256];
    snprintf(pattern, sizeof(pattern), "%%%s%%", query);

    sqlite3_bind_blob(stmt, 1, session_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, pattern, -1, SQLITE_STATIC);

    size_t capacity = 16;
    size_t count = 0;
    ClipSessionNoteEntry* list = (ClipSessionNoteEntry*)malloc(capacity * sizeof(ClipSessionNoteEntry));
    if (!list) {
        sqlite3_finalize(stmt);
        return false;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= capacity) {
            size_t new_cap = capacity * 2;
            ClipSessionNoteEntry* new_list = (ClipSessionNoteEntry*)realloc(list, new_cap * sizeof(ClipSessionNoteEntry));
            if (!new_list) {
                free(list);
                sqlite3_finalize(stmt);
                return false;
            }
            list = new_list;
            capacity = new_cap;
        }

        parse_note_row(stmt, &list[count]);
        count++;
    }

    sqlite3_finalize(stmt);
    *out_notes = list;
    *out_count = count;
    return true;
}

bool clip_notes_count_for_session(sqlite3* db,
                                  const ClipUuid* session_uuid,
                                  uint32_t* out_count)
{
    if (!db || !session_uuid || !out_count) {
        return false;
    }
    *out_count = 0;

    const char* sql = "SELECT COUNT(*) FROM session_notes WHERE session_uuid = ?1;";
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_blob(stmt, 1, session_uuid->bytes, CLIP_UUID_BYTES, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *out_count = (uint32_t)sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3_finalize(stmt);
    return false;
}

void clip_notes_free_list(ClipSessionNoteEntry* notes)
{
    if (notes) {
        free(notes);
    }
}

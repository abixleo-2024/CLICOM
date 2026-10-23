/*
 * clip_notes.h — CLICOM Server-Side Communication Notes & Session Logs
 */

#ifndef CLIP_NOTES_H
#define CLIP_NOTES_H

#include <stdint.h>
#include <stdbool.h>
#include <sqlite3.h>
#include "clip_types.h"
#include "clip_protocol.h"

#define CLIP_NOTE_TEXT_MAX_LEN 1024

typedef struct {
    ClipUuid session_uuid;
    ClipUuid channel_uuid;
    ClipUuid connection_uuid;
    ClipUuid initiator_node_uuid;
    ClipUuid peer_node_uuid;
    uint8_t  state;
    uint64_t created_at;
    uint64_t ended_at;
    uint64_t duration_ms;
    uint32_t note_count;
} ClipSessionLogEntry;

typedef struct {
    uint32_t     note_id;
    ClipUuid     session_uuid;
    ClipUuid     author_node_uuid;
    ClipNoteType note_type;
    uint64_t     created_at;
    char         note_text[CLIP_NOTE_TEXT_MAX_LEN + 1];
} ClipSessionNoteEntry;

/* Database schema initialization & non-destructive migration */
bool clip_notes_db_init_schema(sqlite3* db);

/* Check if node is authorized for session (initiator, peer, or channel member) */
bool clip_session_is_authorized(sqlite3* db,
                                const ClipUuid* session_uuid,
                                const ClipUuid* node_uuid,
                                bool* out_authorized);

/* List session logs for an authorized node (or all if node_uuid is NULL) */
bool clip_session_list_for_node(sqlite3* db,
                                const ClipUuid* node_uuid,
                                ClipSessionLogEntry** out_entries,
                                size_t* out_count);

/* Get detailed log for a single session */
bool clip_session_get_log(sqlite3* db,
                          const ClipUuid* session_uuid,
                          ClipSessionLogEntry* out_entry);

/* Free session log list returned by clip_session_list_for_node */
void clip_session_free_log_list(ClipSessionLogEntry* entries);

/* Create a new note on a session (enforces author_node_uuid & server timestamp) */
bool clip_notes_create(sqlite3* db,
                       const ClipUuid* session_uuid,
                       const ClipUuid* author_node_uuid,
                       ClipNoteType note_type,
                       const char* note_text,
                       uint32_t* out_note_id);

/* List notes for a session (in chronological order) */
bool clip_notes_list_for_session(sqlite3* db,
                                const ClipUuid* session_uuid,
                                ClipSessionNoteEntry** out_notes,
                                size_t* out_count);

/* Search notes for a session by query substring */
bool clip_notes_search(sqlite3* db,
                       const ClipUuid* session_uuid,
                       const char* query,
                       ClipSessionNoteEntry** out_notes,
                       size_t* out_count);

/* Count notes for a session */
bool clip_notes_count_for_session(sqlite3* db,
                                  const ClipUuid* session_uuid,
                                  uint32_t* out_count);

/* Free note list returned by clip_notes_list_for_session or clip_notes_search */
void clip_notes_free_list(ClipSessionNoteEntry* notes);

#endif /* CLIP_NOTES_H */

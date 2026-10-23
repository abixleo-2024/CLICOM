/*
 * clip_notes_client.h — CLICOM Client-Side Notes & Session Logs Network API
 */

#ifndef CLICOM_CLIP_NOTES_CLIENT_H
#define CLICOM_CLIP_NOTES_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_types.h"
#include "clip_errors.h"
#include "clip_protocol.h"
#include "clip_notes.h"
#include "network.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Request list of session logs authorized for this node from server.
 * Returns array of ClipSessionLogEntry allocated with malloc, caller must free with clip_client_free_session_logs.
 */
ClipError clip_client_list_session_logs(ClipClientNet*        net,
                                        ClipSessionLogEntry** out_entries,
                                        size_t*               out_count);

/* Free session log array returned by clip_client_list_session_logs */
void clip_client_free_session_logs(ClipSessionLogEntry* entries);

/*
 * Request details for a single session log.
 */
ClipError clip_client_get_session_log(ClipClientNet*       net,
                                      const ClipUuid*      session_uuid,
                                      ClipSessionLogEntry* out_entry);

/*
 * Create a new note on a session.
 * Server assigns note_id, author_node_uuid, and authoritative timestamp.
 */
ClipError clip_client_create_note(ClipClientNet*   net,
                                  const ClipUuid*  session_uuid,
                                  ClipNoteType     note_type,
                                  const char*      note_text,
                                  uint32_t*        out_note_id);

/*
 * List notes for a session. If query is non-NULL and non-empty, searches notes matching query.
 * Returns array of ClipSessionNoteEntry allocated with malloc, caller must free with clip_client_free_notes.
 */
ClipError clip_client_list_notes(ClipClientNet*          net,
                                 const ClipUuid*         session_uuid,
                                 const char*             query,
                                 ClipSessionNoteEntry**  out_notes,
                                 size_t*                 out_count);

/* Free notes array returned by clip_client_list_notes */
void clip_client_free_notes(ClipSessionNoteEntry* notes);

#ifdef __cplusplus
}
#endif

#endif /* CLICOM_CLIP_NOTES_CLIENT_H */

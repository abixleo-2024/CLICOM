/*
 * clip_sessions.h — CLICOM Server-Side Communication Session Management
 *
 * Implements communication session lifecycle within channel contexts:
 * - Server-generated unique session_uuid (UUIDv4)
 * - Validation: initiator must be authenticated member of channel
 * - Invariant: session_uuid != node_uuid and session_uuid != channel_uuid
 * - SQLite session persistence and history preservation
 */

#ifndef CLIP_SESSIONS_H
#define CLIP_SESSIONS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sqlite3.h>
#include "clip_errors.h"
#include "clip_types.h"

typedef struct {
    ClipUuid         session_uuid;
    char             session_uuid_str[CLIP_UUID_STR_SIZE];
    ClipUuid         connection_uuid;
    ClipUuid         channel_uuid;
    ClipUuid         initiator_node_uuid;
    ClipUuid         peer_node_uuid;
    ClipSessionState state;
    uint64_t         created_at_ms;
    uint64_t         ended_at_ms;
} ClipSessionRecord;

/* Initialize session schema in SQLite database */
ClipError clip_session_db_init_schema(sqlite3* db);

/*
 * Start a new communication session bound to an ACCEPTED Phase 5 connection:
 * - Verifies connection exists and is in CLIP_CONN_STATE_ACCEPTED
 * - Verifies initiator_node_uuid is an endpoint of the connection
 * - Verifies no active session already exists for this connection
 * - Generates unique session_uuid (UUIDv4) enforcing all identity invariants
 * - Persists session in SQLite with state = CLIP_SESSION_STATE_ACTIVE
 */
ClipError clip_session_create_for_connection(sqlite3*        db,
                                             const ClipUuid* conn_uuid,
                                             const ClipUuid* initiator_node_uuid,
                                             ClipUuid*       out_session_uuid);

/*
 * Legacy/fallback: Start a new communication session within a channel:
 * - Verifies initiator_node_uuid is an active member of channel_uuid
 * - Generates unique session_uuid (UUIDv4)
 * - Persists session in SQLite with state = CLIP_SESSION_STATE_ACTIVE
 */
ClipError clip_session_start(sqlite3*        db,
                             const ClipUuid* channel_uuid,
                             const ClipUuid* initiator_node_uuid,
                             ClipUuid*       out_session_uuid);

/*
 * End an active communication session:
 * - Verifies session exists and is active
 * - Verifies requester_node_uuid is an authorized endpoint (initiator, peer, or channel member)
 * - Updates state = CLIP_SESSION_STATE_CLOSED and sets ended_at timestamp
 */
ClipError clip_session_end(sqlite3*        db,
                           const ClipUuid* session_uuid,
                           const ClipUuid* requester_node_uuid);

/* Retrieve session by session_uuid */
ClipError clip_session_get(sqlite3*           db,
                           const ClipUuid*    session_uuid,
                           ClipSessionRecord* out_session);

/* Retrieve current active session for a connection, if one exists */
ClipError clip_session_get_active_for_connection(sqlite3*           db,
                                                 const ClipUuid*    conn_uuid,
                                                 ClipSessionRecord* out_session);

/* Retrieve current active session for a channel, if one exists */
ClipError clip_session_get_active_for_channel(sqlite3*           db,
                                              const ClipUuid*    channel_uuid,
                                              ClipSessionRecord* out_session);

#endif /* CLIP_SESSIONS_H */

/*
 * clip_connections.h — CLICOM Connection Requests & Tracking (Phase 5)
 *
 * Implements server-authoritative connection request, accept, decline, and state
 * tracking between authenticated channel members.
 *
 * Persisted in SQLite (connections table).
 *
 * Invariant: connection_uuid != node_uuid != channel_uuid != session_uuid.
 * Header session_uuid is ALWAYS ZERO on all connection messages.
 */

#ifndef CLIP_CONNECTIONS_H
#define CLIP_CONNECTIONS_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "clip_types.h"
#include "clip_errors.h"

/* Initialize connections table and index in SQLite database */
ClipError clip_connection_db_init_schema(sqlite3* db);

/*
 * Create a new connection request:
 * - Validates requester != target
 * - Checks for duplicate pending or accepted connection
 * - Generates unique connection_uuid (UUIDv4)
 * - Persists record in SQLite with state = CLIP_CONN_STATE_REQUESTED
 */
ClipError clip_connection_create(sqlite3*              db,
                                 const ClipUuid*       channel_uuid,
                                 const ClipUuid*       requester_node_uuid,
                                 const ClipUuid*       target_node_uuid,
                                 ClipConnectionRecord* out_conn);

/* Query connection by connection_uuid */
ClipError clip_connection_get(sqlite3*              db,
                              const ClipUuid*       connection_uuid,
                              ClipConnectionRecord* out_conn);

/* Update connection state (e.g. ACCEPTED, DECLINED, CLOSED) */
ClipError clip_connection_set_state(sqlite3*            db,
                                    const ClipUuid*     connection_uuid,
                                    ClipConnectionState new_state);

/* Check if an active or pending connection exists between two nodes in a channel */
ClipError clip_connection_find_active(sqlite3*              db,
                                      const ClipUuid*       channel_uuid,
                                      const ClipUuid*       node_a,
                                      const ClipUuid*       node_b,
                                      ClipConnectionRecord* out_conn,
                                      bool*                 out_found);

/* List all connections involving node_uuid (as requester or target) */
ClipError clip_connection_list_for_node(sqlite3*               db,
                                        const ClipUuid*        node_uuid,
                                        ClipConnectionRecord** out_conns,
                                        size_t*                out_count);

/* Free array returned by clip_connection_list_for_node() */
void clip_connection_free_list(ClipConnectionRecord* conns);

#endif /* CLIP_CONNECTIONS_H */

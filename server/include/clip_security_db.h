/*
 * clip_security_db.h — CLICOM Server-Side Security Events SQLite Storage
 *
 * Implements:
 * - Persistent storage for advisory SecurityEvents
 * - Server-authoritative autoincrement event_id and UUID assignment
 * - Participant authorization checks (initiator, peer, channel member)
 * - Safe, non-destructive schema migration
 */

#ifndef CLIP_SECURITY_DB_H
#define CLIP_SECURITY_DB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sqlite3.h>
#include "clip_types.h"
#include "clip_errors.h"
#include "security_analyzer.h"

/* Initialize security_events table and indexes in SQLite */
ClipError clip_security_db_init_schema(sqlite3* db);

/* Insert a new security event; populates event->event_id */
ClipError clip_security_db_insert_event(sqlite3* db, ClipSecurityEvent* event);

/* Query a single security event by event_id or event_uuid */
ClipError clip_security_db_get_event(sqlite3* db,
                                     uint32_t event_id,
                                     const uint8_t* event_uuid,
                                     ClipSecurityEvent* out_event);

/* Query security events for a session */
ClipError clip_security_db_list_for_session(sqlite3* db,
                                            const uint8_t* session_uuid,
                                            ClipSecurityEvent** out_events,
                                            size_t* out_count);

/* Query all security events for sessions authorized for the requesting node */
ClipError clip_security_db_list_for_node(sqlite3* db,
                                         const uint8_t* node_uuid,
                                         ClipSecurityEvent** out_events,
                                         size_t* out_count);

/* Free an event list allocated by list_for_session or list_for_node */
void clip_security_free_event_list(ClipSecurityEvent* events);
void clip_security_db_free_event_list(ClipSecurityEvent* events, size_t count);

#endif /* CLIP_SECURITY_DB_H */

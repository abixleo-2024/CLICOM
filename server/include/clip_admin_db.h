/*
 * clip_admin_db.h — CLICOM Server-Side Administrative Database Operations
 *
 * Implements SQLite storage for:
 * - Administrators table and credential verifiers
 * - Persistent node sanctions (ACTIVE, RESTRICTED, BANNED)
 * - Append-only administrative audit log (immutable; no update or delete operations)
 * - Security event queries and terminal status updates
 * - Channel lock/unlock management
 * - Referential integrity verification for audit links
 */

#ifndef CLICOM_SERVER_ADMIN_DB_H
#define CLICOM_SERVER_ADMIN_DB_H

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "clip_errors.h"
#include "clip_types.h"
#include "clip_admin.h"
#include "security_analyzer.h"

/* Initialize administrators, sanctions, and audit schemas */
ClipError clip_admin_db_init_schema(sqlite3* db);

/* Count total existing administrators */
ClipError clip_admin_db_count_admins(sqlite3* db, size_t* out_count);

/* Insert a new administrator account */
ClipError clip_admin_db_create_admin(sqlite3* db, const ClipAdminUser* user);

/* Retrieve an administrator by username */
ClipError clip_admin_db_get_admin(sqlite3* db, const char* username, ClipAdminUser* out_user);

/* Retrieve an administrator by admin_uuid */
ClipError clip_admin_db_get_admin_by_uuid(sqlite3* db, const uint8_t admin_uuid[CLIP_UUID_BYTES], ClipAdminUser* out_user);

/* Retrieve sanction record for a node (returns CLIP_ERR_NOT_FOUND if none) */
ClipError clip_admin_db_get_sanction(sqlite3* db, const uint8_t node_uuid[CLIP_UUID_BYTES], ClipNodeSanction* out_sanction);

/* Set or update a node sanction */
ClipError clip_admin_db_set_sanction(sqlite3* db, const ClipNodeSanction* sanction);

/* Remove a node sanction (unrestrict or unban) */
ClipError clip_admin_db_remove_sanction(sqlite3* db, const uint8_t node_uuid[CLIP_UUID_BYTES]);

/* Append an entry to the audit log (append-only; no update/delete exists) */
ClipError clip_admin_db_add_audit(sqlite3* db, const ClipAdminAuditRecord* record, uint32_t* out_audit_id);

/* Query security events (filter_status < 0 means all events) */
ClipError clip_admin_db_query_events(sqlite3* db, int filter_status, ClipSecurityEvent* out_events, size_t max_events, size_t* out_count);

/*
 * Update security event review status.
 * Enforces terminal state machine:
 * PENDING -> REVIEWED or FALSE_POS is allowed.
 * REVIEWED -> FALSE_POS or FALSE_POS -> REVIEWED returns CLIP_ERR_INVALID.
 * Duplicate reviews return CLIP_ERR_EXISTS.
 */
ClipError clip_admin_db_update_event_status(sqlite3* db, uint32_t event_id, ClipEventStatus new_status);

/* Query recent entries from the append-only audit trail */
ClipError clip_admin_db_query_audit(sqlite3* db, size_t limit, ClipAdminAuditRecord* out_records, size_t* out_count);

/* Lock (active=0) or unlock (active=1) a channel */
ClipError clip_admin_db_lock_channel(sqlite3* db, const uint8_t channel_uuid[CLIP_UUID_BYTES], bool lock);

/* Referential checks */
ClipError clip_admin_db_event_exists(sqlite3* db, uint32_t event_id, bool* out_exists);
ClipError clip_admin_db_session_exists(sqlite3* db, const uint8_t session_uuid[CLIP_UUID_BYTES], bool* out_exists);
ClipError clip_admin_db_channel_exists(sqlite3* db, const uint8_t channel_uuid[CLIP_UUID_BYTES], bool* out_exists);

#endif /* CLICOM_SERVER_ADMIN_DB_H */

/*
 * clip_admin_client.h — CLICOM Client-Side Administrative Network API
 */

#ifndef CLICOM_CLIP_ADMIN_CLIENT_H
#define CLICOM_CLIP_ADMIN_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_types.h"
#include "clip_errors.h"
#include "clip_protocol.h"
#include "clip_admin.h"
#include "security_analyzer.h"
#include "network.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Authenticate administrator session over TLS.
 *
 * Parameters:
 *   net: Connected client network handle
 *   username: Administrator username
 *   password: Administrator password (plaintext, transmitted over TLS 1.3)
 *   out_role: [out] Assigned administrative role
 *   out_admin_uuid: [out] Optional output buffer for admin UUID (16 bytes)
 */
ClipError clip_admin_client_login(ClipClientNet*      net,
                                  const char*         username,
                                  const char*         password,
                                  ClipAdminPermission* out_role,
                                  ClipUuid*           out_admin_uuid);

/*
 * Send an explicit administrative action to the server.
 *
 * Parameters:
 *   net: Authenticated admin client network handle
 *   action_type: CLIP_ADMIN_* action
 *   target_uuid: Target node or channel UUID (optional depending on action)
 *   reason: Human-provided reason string (mandatory)
 *   related_event_id: Related security event ID (0 if none)
 *   related_session_uuid: Related session UUID (optional, can be NULL)
 *   related_channel_uuid: Related channel UUID (optional, can be NULL)
 *   out_audit_id: [out] Server-generated audit ID for the operation
 */
ClipError clip_admin_client_send_action(ClipClientNet*           net,
                                        ClipAdminActionType      action_type,
                                        const ClipUuid*          target_uuid,
                                        const char*              reason,
                                        uint32_t                 related_event_id,
                                        const ClipUuid*          related_session_uuid,
                                        const ClipUuid*          related_channel_uuid,
                                        uint32_t*                out_audit_id);

/*
 * Query security advisory events with optional review status filter.
 *
 * Parameters:
 *   net: Authenticated admin client network handle
 *   status_filter: -1 for all, or CLIP_EVENT_STATUS_*
 *   out_events: [out] Pointer to dynamically allocated array of events
 *   out_count: [out] Number of events returned
 */
ClipError clip_admin_client_list_events(ClipClientNet*      net,
                                        int                 status_filter,
                                        ClipSecurityEvent** out_events,
                                        size_t*             out_count);

/* Free event array returned by clip_admin_client_list_events */
void clip_admin_client_free_events(ClipSecurityEvent* events, size_t count);

/*
 * Query append-only administrative audit log.
 *
 * Parameters:
 *   net: Authenticated admin client network handle
 *   limit: Max records to return (0 for server default)
 *   out_records: [out] Pointer to dynamically allocated array of audit records
 *   out_count: [out] Number of records returned
 */
ClipError clip_admin_client_list_audit(ClipClientNet*         net,
                                       uint32_t               limit,
                                       ClipAdminAuditRecord** out_records,
                                       size_t*                out_count);

/* Free audit array returned by clip_admin_client_list_audit */
void clip_admin_client_free_audit(ClipAdminAuditRecord* records, size_t count);

/*
 * Create a new administrator account (SUPER_ADMIN only).
 */
ClipError clip_admin_client_create_admin(ClipClientNet*      net,
                                         const char*         new_username,
                                         const char*         new_password,
                                         ClipAdminPermission role,
                                         const char*         reason,
                                         uint32_t*           out_audit_id);

#ifdef __cplusplus
}
#endif

#endif /* CLICOM_CLIP_ADMIN_CLIENT_H */

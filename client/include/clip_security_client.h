/*
 * clip_security_client.h — CLICOM Client-Side Security Analysis Network API
 */

#ifndef CLICOM_CLIP_SECURITY_CLIENT_H
#define CLICOM_CLIP_SECURITY_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_types.h"
#include "clip_errors.h"
#include "clip_protocol.h"
#include "security_analyzer.h"
#include "network.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Submit finalized transcript (is_final=true) to server for security analysis.
 * Uses CLIP_MSG_SECURITY_TRANSCRIPT (0x0086).
 */
ClipError clip_client_submit_security_transcript(ClipClientNet*  net,
                                                 const ClipUuid* session_uuid,
                                                 const ClipUuid* speaker_uuid,
                                                 const char*     transcript_text,
                                                 uint64_t        timestamp_ms);

/*
 * Request list of advisory security events from server.
 * If session_uuid is non-NULL, filters for that session; otherwise returns events for current node.
 * Returns array of ClipSecurityEvent allocated with malloc, caller must free with clip_client_free_security_events.
 */
ClipError clip_client_list_security_events(ClipClientNet*      net,
                                           const ClipUuid*     session_uuid,
                                           ClipSecurityEvent** out_events,
                                           size_t*             out_count);

/* Free security event array returned by clip_client_list_security_events */
void clip_client_free_security_events(ClipSecurityEvent* events, size_t count);

/*
 * Request details for a single security event by ID and/or UUID.
 */
ClipError clip_client_get_security_event(ClipClientNet*     net,
                                         uint32_t           event_id,
                                         const ClipUuid*    event_uuid,
                                         ClipSecurityEvent* out_event);

#ifdef __cplusplus
}
#endif

#endif /* CLICOM_CLIP_SECURITY_CLIENT_H */

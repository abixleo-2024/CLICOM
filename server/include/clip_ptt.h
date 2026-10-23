/*
 * clip_ptt.h — CLICOM Server-Authoritative Push-to-Talk (PTT) Floor Control
 *
 * Implements server-side half-duplex floor arbitration for active Phase 6 sessions:
 * - Single floor holder per session
 * - Server is sole authority; clients cannot self-grant
 * - Ephemeral runtime state (not persisted across restarts)
 * - Automatic lease timeout (default 5 seconds)
 * - Automatic floor release on client disconnect
 * - Automatic floor release on session termination
 */

#ifndef CLIP_PTT_H
#define CLIP_PTT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_types.h"
#include "clip_errors.h"

#define CLIP_PTT_DEFAULT_LEASE_MS  5000u  /* 5 seconds */

typedef struct {
    ClipUuid          session_uuid;
    ClipUuid          holder_node_uuid;
    ClipPttFloorState floor_state;
    uint64_t          acquired_at_ms;
    uint64_t          last_renewed_at_ms;
    uint32_t          lease_duration_ms;
    bool              active;
} ClipPttFloorEntry;

typedef struct {
    ClipPttFloorEntry* entries;
    size_t             capacity;
    size_t             count;
} ClipPttManager;

/* Lifecycle */
ClipError clip_ptt_manager_init(ClipPttManager* mgr, size_t initial_cap);
void      clip_ptt_manager_cleanup(ClipPttManager* mgr);

/*
 * Acquire or confirm floor for session:
 * - If floor is FREE: acquires floor for requester, sets state=HELD, returns CLIP_OK.
 * - If floor is already HELD by requester: returns CLIP_OK and sets *out_already_held = true
 *   (does not overwrite acquired_at_ms).
 * - If floor is HELD by another node: returns CLIP_ERR_PTT_BUSY, populates out_entry with current holder.
 */
ClipError clip_ptt_manager_acquire(ClipPttManager*    mgr,
                                   const ClipUuid*    session_uuid,
                                   const ClipUuid*    requester_node_uuid,
                                   uint32_t           lease_ms,
                                   uint64_t           now_ms,
                                   ClipPttFloorEntry* out_entry,
                                   bool*              out_already_held);

/*
 * Release floor for session:
 * - Only current floor holder may release floor.
 * - If requester is not current holder: returns CLIP_ERR_DENIED.
 * - If floor is already FREE: returns CLIP_OK, state remains FREE.
 * - If valid: transitions to FREE, clears holder.
 */
ClipError clip_ptt_manager_release(ClipPttManager*    mgr,
                                   const ClipUuid*    session_uuid,
                                   const ClipUuid*    requester_node_uuid,
                                   ClipPttFloorEntry* out_entry);

/*
 * Renew active lease:
 * - Requester must be current holder and floor must be HELD.
 * - Updates last_renewed_at_ms to now_ms.
 */
ClipError clip_ptt_manager_renew(ClipPttManager* mgr,
                                 const ClipUuid* session_uuid,
                                 const ClipUuid* requester_node_uuid,
                                 uint64_t        now_ms,
                                 uint32_t*       out_remaining_lease_ms);

/* Query current floor status */
ClipError clip_ptt_manager_get_status(ClipPttManager*    mgr,
                                      const ClipUuid*    session_uuid,
                                      uint64_t           now_ms,
                                      ClipPttFloorEntry* out_entry);

/* Force-release floor when session terminates */
ClipError clip_ptt_manager_release_session(ClipPttManager* mgr,
                                           const ClipUuid* session_uuid);

/*
 * Disconnect safety:
 * Releases all floors currently held by holder_uuid across any active session.
 * Populates out_affected_sessions so the caller can notify peers.
 */
ClipError clip_ptt_manager_release_by_holder(ClipPttManager* mgr,
                                             const ClipUuid* holder_uuid,
                                             ClipUuid*       out_affected_sessions,
                                             size_t          max_affected,
                                             size_t*         out_affected_count);

/*
 * Lease watchdog check:
 * Inspects all HELD floors. If (now_ms - last_renewed_at_ms) >= lease_duration_ms:
 * floor is released to FREE and session UUID is added to out_expired_sessions.
 */
ClipError clip_ptt_manager_check_timeouts(ClipPttManager* mgr,
                                          uint64_t        now_ms,
                                          ClipUuid*       out_expired_sessions,
                                          size_t          max_expired,
                                          size_t*         out_expired_count);

#endif /* CLIP_PTT_H */

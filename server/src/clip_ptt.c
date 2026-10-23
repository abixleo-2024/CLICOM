/*
 * clip_ptt.c — CLICOM Server-Authoritative Push-to-Talk (PTT) Floor Control Implementation
 */

#include "clip_ptt.h"
#include "clip_log.h"
#include <stdlib.h>
#include <string.h>

#define CLIP_PTT_DEFAULT_CAPACITY 64u

ClipError clip_ptt_manager_init(ClipPttManager* mgr, size_t initial_cap)
{
    if (!mgr) return CLIP_ERR_INVALID;

    size_t cap = (initial_cap > 0) ? initial_cap : CLIP_PTT_DEFAULT_CAPACITY;
    mgr->entries = (ClipPttFloorEntry*)calloc(cap, sizeof(ClipPttFloorEntry));
    if (!mgr->entries) {
        return CLIP_ERR_NOMEM;
    }

    mgr->capacity = cap;
    mgr->count = 0;
    return CLIP_OK;
}

void clip_ptt_manager_cleanup(ClipPttManager* mgr)
{
    if (!mgr) return;
    if (mgr->entries) {
        free(mgr->entries);
        mgr->entries = NULL;
    }
    mgr->capacity = 0;
    mgr->count = 0;
}

static ClipPttFloorEntry* find_entry(ClipPttManager* mgr, const ClipUuid* session_uuid)
{
    if (!mgr || !mgr->entries || !session_uuid) return NULL;

    for (size_t i = 0; i < mgr->capacity; i++) {
        if (mgr->entries[i].active && clip_uuid_equal(&mgr->entries[i].session_uuid, session_uuid)) {
            return &mgr->entries[i];
        }
    }
    return NULL;
}

static ClipPttFloorEntry* get_or_create_entry(ClipPttManager* mgr, const ClipUuid* session_uuid)
{
    if (!mgr || !session_uuid) return NULL;

    ClipPttFloorEntry* existing = find_entry(mgr, session_uuid);
    if (existing) return existing;

    /* Find an inactive slot */
    for (size_t i = 0; i < mgr->capacity; i++) {
        if (!mgr->entries[i].active) {
            ClipPttFloorEntry* e = &mgr->entries[i];
            memset(e, 0, sizeof(ClipPttFloorEntry));
            e->session_uuid = *session_uuid;
            clip_uuid_zero(&e->holder_node_uuid);
            e->floor_state = CLIP_PTT_FLOOR_FREE;
            e->lease_duration_ms = CLIP_PTT_DEFAULT_LEASE_MS;
            e->active = true;
            mgr->count++;
            return e;
        }
    }

    /* Expand capacity */
    size_t new_cap = mgr->capacity ? (mgr->capacity * 2) : CLIP_PTT_DEFAULT_CAPACITY;
    ClipPttFloorEntry* new_entries = (ClipPttFloorEntry*)realloc(mgr->entries, new_cap * sizeof(ClipPttFloorEntry));
    if (!new_entries) return NULL;

    for (size_t i = mgr->capacity; i < new_cap; i++) {
        memset(&new_entries[i], 0, sizeof(ClipPttFloorEntry));
        new_entries[i].active = false;
    }

    size_t new_slot = mgr->capacity;
    mgr->entries = new_entries;
    mgr->capacity = new_cap;

    ClipPttFloorEntry* e = &mgr->entries[new_slot];
    e->session_uuid = *session_uuid;
    clip_uuid_zero(&e->holder_node_uuid);
    e->floor_state = CLIP_PTT_FLOOR_FREE;
    e->lease_duration_ms = CLIP_PTT_DEFAULT_LEASE_MS;
    e->active = true;
    mgr->count++;
    return e;
}

ClipError clip_ptt_manager_acquire(ClipPttManager*    mgr,
                                   const ClipUuid*    session_uuid,
                                   const ClipUuid*    requester_node_uuid,
                                   uint32_t           lease_ms,
                                   uint64_t           now_ms,
                                   ClipPttFloorEntry* out_entry,
                                   bool*              out_already_held)
{
    if (!mgr || !session_uuid || !requester_node_uuid) {
        return CLIP_ERR_INVALID;
    }

    if (out_already_held) *out_already_held = false;

    ClipPttFloorEntry* entry = get_or_create_entry(mgr, session_uuid);
    if (!entry) {
        return CLIP_ERR_NOMEM;
    }

    /* Check if currently held */
    if (entry->floor_state == CLIP_PTT_FLOOR_HELD) {
        /* Check if lease has expired in place */
        if (entry->lease_duration_ms > 0 &&
            now_ms >= entry->last_renewed_at_ms + entry->lease_duration_ms) {
            /* Expired! Reset to FREE */
            CLIP_LOGI("Floor lease expired for session during acquire check");
            entry->floor_state = CLIP_PTT_FLOOR_FREE;
            clip_uuid_zero(&entry->holder_node_uuid);
        } else if (clip_uuid_equal(&entry->holder_node_uuid, requester_node_uuid)) {
            /* Same holder duplicate request: return confirmation, keep acquired_at */
            if (out_already_held) *out_already_held = true;
            if (out_entry) *out_entry = *entry;
            return CLIP_OK;
        } else {
            /* Held by another node */
            if (out_entry) *out_entry = *entry;
            return CLIP_ERR_PTT_BUSY;
        }
    }

    /* Floor is FREE: grant to requester */
    entry->holder_node_uuid = *requester_node_uuid;
    entry->floor_state = CLIP_PTT_FLOOR_HELD;
    entry->acquired_at_ms = now_ms;
    entry->last_renewed_at_ms = now_ms;
    entry->lease_duration_ms = (lease_ms > 0) ? lease_ms : CLIP_PTT_DEFAULT_LEASE_MS;

    if (out_entry) *out_entry = *entry;
    return CLIP_OK;
}

ClipError clip_ptt_manager_release(ClipPttManager*    mgr,
                                   const ClipUuid*    session_uuid,
                                   const ClipUuid*    requester_node_uuid,
                                   ClipPttFloorEntry* out_entry)
{
    if (!mgr || !session_uuid || !requester_node_uuid) {
        return CLIP_ERR_INVALID;
    }

    ClipPttFloorEntry* entry = find_entry(mgr, session_uuid);
    if (!entry || entry->floor_state == CLIP_PTT_FLOOR_FREE) {
        /* Floor is already FREE */
        if (out_entry) {
            memset(out_entry, 0, sizeof(ClipPttFloorEntry));
            out_entry->session_uuid = *session_uuid;
            out_entry->floor_state = CLIP_PTT_FLOOR_FREE;
        }
        return CLIP_OK;
    }

    /* Floor is HELD: only holder may release */
    if (!clip_uuid_equal(&entry->holder_node_uuid, requester_node_uuid)) {
        if (out_entry) *out_entry = *entry;
        return CLIP_ERR_DENIED;
    }

    entry->floor_state = CLIP_PTT_FLOOR_FREE;
    clip_uuid_zero(&entry->holder_node_uuid);
    entry->last_renewed_at_ms = 0;

    if (out_entry) *out_entry = *entry;
    return CLIP_OK;
}

ClipError clip_ptt_manager_renew(ClipPttManager* mgr,
                                 const ClipUuid* session_uuid,
                                 const ClipUuid* requester_node_uuid,
                                 uint64_t        now_ms,
                                 uint32_t*       out_remaining_lease_ms)
{
    if (!mgr || !session_uuid || !requester_node_uuid) {
        return CLIP_ERR_INVALID;
    }

    ClipPttFloorEntry* entry = find_entry(mgr, session_uuid);
    if (!entry || entry->floor_state != CLIP_PTT_FLOOR_HELD) {
        return CLIP_ERR_INVALID;
    }

    if (!clip_uuid_equal(&entry->holder_node_uuid, requester_node_uuid)) {
        return CLIP_ERR_DENIED;
    }

    entry->last_renewed_at_ms = now_ms;
    if (out_remaining_lease_ms) {
        *out_remaining_lease_ms = entry->lease_duration_ms;
    }
    return CLIP_OK;
}

ClipError clip_ptt_manager_get_status(ClipPttManager*    mgr,
                                      const ClipUuid*    session_uuid,
                                      uint64_t           now_ms,
                                      ClipPttFloorEntry* out_entry)
{
    if (!mgr || !session_uuid || !out_entry) {
        return CLIP_ERR_INVALID;
    }

    ClipPttFloorEntry* entry = find_entry(mgr, session_uuid);
    if (!entry) {
        memset(out_entry, 0, sizeof(ClipPttFloorEntry));
        out_entry->session_uuid = *session_uuid;
        out_entry->floor_state = CLIP_PTT_FLOOR_FREE;
        return CLIP_OK;
    }

    /* Check timeout */
    if (entry->floor_state == CLIP_PTT_FLOOR_HELD &&
        entry->lease_duration_ms > 0 &&
        now_ms >= entry->last_renewed_at_ms + entry->lease_duration_ms) {
        entry->floor_state = CLIP_PTT_FLOOR_FREE;
        clip_uuid_zero(&entry->holder_node_uuid);
    }

    *out_entry = *entry;
    return CLIP_OK;
}

ClipError clip_ptt_manager_release_session(ClipPttManager* mgr,
                                           const ClipUuid* session_uuid)
{
    if (!mgr || !session_uuid) return CLIP_ERR_INVALID;

    ClipPttFloorEntry* entry = find_entry(mgr, session_uuid);
    if (entry) {
        entry->floor_state = CLIP_PTT_FLOOR_FREE;
        clip_uuid_zero(&entry->holder_node_uuid);
        entry->active = false;
        if (mgr->count > 0) mgr->count--;
    }
    return CLIP_OK;
}

ClipError clip_ptt_manager_release_by_holder(ClipPttManager* mgr,
                                             const ClipUuid* holder_uuid,
                                             ClipUuid*       out_affected_sessions,
                                             size_t          max_affected,
                                             size_t*         out_affected_count)
{
    if (!mgr || !holder_uuid) return CLIP_ERR_INVALID;

    size_t affected = 0;
    for (size_t i = 0; i < mgr->capacity; i++) {
        ClipPttFloorEntry* e = &mgr->entries[i];
        if (e->active && e->floor_state == CLIP_PTT_FLOOR_HELD &&
            clip_uuid_equal(&e->holder_node_uuid, holder_uuid)) {
            e->floor_state = CLIP_PTT_FLOOR_FREE;
            clip_uuid_zero(&e->holder_node_uuid);

            if (out_affected_sessions && affected < max_affected) {
                out_affected_sessions[affected] = e->session_uuid;
                affected++;
            }
        }
    }

    if (out_affected_count) *out_affected_count = affected;
    return CLIP_OK;
}

ClipError clip_ptt_manager_check_timeouts(ClipPttManager* mgr,
                                          uint64_t        now_ms,
                                          ClipUuid*       out_expired_sessions,
                                          size_t          max_expired,
                                          size_t*         out_expired_count)
{
    if (!mgr) return CLIP_ERR_INVALID;

    size_t expired = 0;
    for (size_t i = 0; i < mgr->capacity; i++) {
        ClipPttFloorEntry* e = &mgr->entries[i];
        if (e->active && e->floor_state == CLIP_PTT_FLOOR_HELD &&
            e->lease_duration_ms > 0 &&
            now_ms >= e->last_renewed_at_ms + e->lease_duration_ms) {
            e->floor_state = CLIP_PTT_FLOOR_FREE;
            clip_uuid_zero(&e->holder_node_uuid);

            if (out_expired_sessions && expired < max_expired) {
                out_expired_sessions[expired] = e->session_uuid;
                expired++;
            }
        }
    }

    if (out_expired_count) *out_expired_count = expired;
    return CLIP_OK;
}

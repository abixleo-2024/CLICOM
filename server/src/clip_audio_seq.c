/*
 * clip_audio_seq.c — Per-Session / Per-Sender Audio Sequence Validation Implementation
 */

#include "clip_audio_seq.h"
#include <string.h>

void clip_audio_seq_tracker_init(ClipAudioSeqTracker* tracker)
{
    if (!tracker) return;
    memset(tracker, 0, sizeof(ClipAudioSeqTracker));
    InitializeCriticalSection(&tracker->cs);
    tracker->initialized = true;
}

void clip_audio_seq_tracker_cleanup(ClipAudioSeqTracker* tracker)
{
    if (!tracker || !tracker->initialized) return;
    EnterCriticalSection(&tracker->cs);
    tracker->count = 0;
    tracker->initialized = false;
    LeaveCriticalSection(&tracker->cs);
    DeleteCriticalSection(&tracker->cs);
}

ClipError clip_audio_seq_validate_and_update(ClipAudioSeqTracker* tracker,
                                             const ClipUuid*      session_uuid,
                                             const uint8_t*       sender_node_uuid,
                                             uint64_t             seq_num)
{
    if (!tracker || !tracker->initialized || !session_uuid || !sender_node_uuid) {
        return CLIP_ERR_INVALID;
    }

    EnterCriticalSection(&tracker->cs);

    /* Search for existing entry */
    ClipAudioSeqEntry* entry = NULL;
    ClipAudioSeqEntry* free_slot = NULL;

    for (size_t i = 0; i < CLIP_MAX_AUDIO_SEQ_TRACKERS; i++) {
        if (tracker->entries[i].active) {
            if (clip_uuid_equal(&tracker->entries[i].session_uuid, session_uuid) &&
                memcmp(tracker->entries[i].sender_node_uuid, sender_node_uuid, CLIP_UUID_BYTES) == 0) {
                entry = &tracker->entries[i];
                break;
            }
        } else if (!free_slot) {
            free_slot = &tracker->entries[i];
        }
    }

    if (!entry) {
        /* New tracking entry */
        if (!free_slot) {
            LeaveCriticalSection(&tracker->cs);
            return CLIP_ERR_FULL;
        }
        entry = free_slot;
        entry->session_uuid = *session_uuid;
        memcpy(entry->sender_node_uuid, sender_node_uuid, CLIP_UUID_BYTES);
        entry->last_seq_num = seq_num;
        entry->has_seq = true;
        entry->active = true;
        tracker->count++;
        LeaveCriticalSection(&tracker->cs);
        return CLIP_OK;
    }

    /* Existing entry: sequence must be strictly increasing */
    if (entry->has_seq && seq_num <= entry->last_seq_num) {
        LeaveCriticalSection(&tracker->cs);
        return CLIP_ERR_AUDIO_SEQUENCE;
    }

    entry->last_seq_num = seq_num;
    entry->has_seq = true;

    LeaveCriticalSection(&tracker->cs);
    return CLIP_OK;
}

void clip_audio_seq_reset_session(ClipAudioSeqTracker* tracker,
                                 const ClipUuid*      session_uuid)
{
    if (!tracker || !tracker->initialized || !session_uuid) return;

    EnterCriticalSection(&tracker->cs);
    for (size_t i = 0; i < CLIP_MAX_AUDIO_SEQ_TRACKERS; i++) {
        if (tracker->entries[i].active &&
            clip_uuid_equal(&tracker->entries[i].session_uuid, session_uuid)) {
            memset(&tracker->entries[i], 0, sizeof(ClipAudioSeqEntry));
            if (tracker->count > 0) {
                tracker->count--;
            }
        }
    }
    LeaveCriticalSection(&tracker->cs);
}

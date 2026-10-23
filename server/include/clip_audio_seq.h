/*
 * clip_audio_seq.h — Per-Session / Per-Sender Audio Sequence Validation (Phase 10)
 *
 * Enforces strictly increasing sequence numbers for audio frames within
 * active communication sessions:
 *  - Accepts strictly increasing sequence numbers (seq_num > last_seq_num)
 *  - Rejects duplicate, stale, or backward/out-of-order sequence numbers
 *  - Resets tracking state when sessions terminate
 */

#ifndef CLIP_AUDIO_SEQ_H
#define CLIP_AUDIO_SEQ_H

#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include "clip_types.h"
#include "clip_errors.h"

#define CLIP_MAX_AUDIO_SEQ_TRACKERS 128

typedef struct {
    ClipUuid session_uuid;
    uint8_t  sender_node_uuid[CLIP_UUID_BYTES];
    uint64_t last_seq_num;
    bool     has_seq;
    bool     active;
} ClipAudioSeqEntry;

typedef struct {
    ClipAudioSeqEntry entries[CLIP_MAX_AUDIO_SEQ_TRACKERS];
    size_t            count;
    CRITICAL_SECTION  cs;
    bool              initialized;
} ClipAudioSeqTracker;

void      clip_audio_seq_tracker_init(ClipAudioSeqTracker* tracker);
void      clip_audio_seq_tracker_cleanup(ClipAudioSeqTracker* tracker);

/*
 * Validates and records audio frame sequence number:
 * - Must be strictly increasing per (session_uuid, sender_node_uuid)
 * - Returns CLIP_OK if valid and updates last_seq_num
 * - Returns CLIP_ERR_AUDIO_SEQUENCE if seq_num <= last_seq_num
 */
ClipError clip_audio_seq_validate_and_update(ClipAudioSeqTracker* tracker,
                                             const ClipUuid*      session_uuid,
                                             const uint8_t*       sender_node_uuid,
                                             uint64_t             seq_num);

/* Reset/clear tracking entries when session ends */
void      clip_audio_seq_reset_session(ClipAudioSeqTracker* tracker,
                                       const ClipUuid*      session_uuid);

#endif /* CLIP_AUDIO_SEQ_H */

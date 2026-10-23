/*
 * speech_buffer.c — Implementation of sample accumulator for SpeechAnalyzer
 */

#include "speech_buffer.h"
#include <stdlib.h>
#include <string.h>

ClipError speech_buffer_init(SpeechBuffer* sb, size_t capacity_samples)
{
    if (!sb || capacity_samples == 0) {
        return CLIP_ERR_INVALID;
    }
    memset(sb, 0, sizeof(*sb));
    sb->samples = (int16_t*)malloc(capacity_samples * sizeof(int16_t));
    if (!sb->samples) {
        return CLIP_ERR_NOMEM;
    }
    sb->capacity_samples = capacity_samples;
    sb->count_samples = 0;
    sb->start_time_ms = 0;
    sb->last_frame_time_ms = 0;
    sb->has_speaker = false;
    memset(sb->session_uuid.bytes, 0, CLIP_UUID_BYTES);
    memset(sb->speaker_uuid.bytes, 0, CLIP_UUID_BYTES);
    return CLIP_OK;
}

void speech_buffer_destroy(SpeechBuffer* sb)
{
    if (!sb) return;
    if (sb->samples) {
        free(sb->samples);
        sb->samples = NULL;
    }
    sb->capacity_samples = 0;
    sb->count_samples = 0;
    sb->has_speaker = false;
}

void speech_buffer_reset(SpeechBuffer* sb)
{
    if (!sb) return;
    sb->count_samples = 0;
    sb->start_time_ms = 0;
    sb->last_frame_time_ms = 0;
    sb->has_speaker = false;
    memset(sb->session_uuid.bytes, 0, CLIP_UUID_BYTES);
    memset(sb->speaker_uuid.bytes, 0, CLIP_UUID_BYTES);
}

ClipError speech_buffer_append(SpeechBuffer*   sb,
                               const ClipUuid* session_uuid,
                               const ClipUuid* speaker_uuid,
                               uint64_t        timestamp_ms,
                               const int16_t*  pcm,
                               size_t          sample_count,
                               bool*           out_speaker_changed)
{
    if (!sb || !sb->samples || !session_uuid || !speaker_uuid || !pcm || sample_count == 0) {
        return CLIP_ERR_INVALID;
    }
    if (out_speaker_changed) *out_speaker_changed = false;

    /* Detect session or speaker change */
    if (sb->has_speaker) {
        if (memcmp(sb->session_uuid.bytes, session_uuid->bytes, CLIP_UUID_BYTES) != 0 ||
            memcmp(sb->speaker_uuid.bytes, speaker_uuid->bytes, CLIP_UUID_BYTES) != 0) {
            if (out_speaker_changed) *out_speaker_changed = true;
            return CLIP_OK; /* Caller should flush before appending new speaker audio */
        }
    } else {
        memcpy(sb->session_uuid.bytes, session_uuid->bytes, CLIP_UUID_BYTES);
        memcpy(sb->speaker_uuid.bytes, speaker_uuid->bytes, CLIP_UUID_BYTES);
        sb->start_time_ms = timestamp_ms;
        sb->has_speaker = true;
    }

    sb->last_frame_time_ms = timestamp_ms;

    /* Prevent overflow: clamp to remaining capacity */
    size_t avail = sb->capacity_samples - sb->count_samples;
    size_t to_copy = (sample_count < avail) ? sample_count : avail;
    if (to_copy > 0) {
        memcpy(&sb->samples[sb->count_samples], pcm, to_copy * sizeof(int16_t));
        sb->count_samples += to_copy;
    }

    if (to_copy < sample_count) {
        return CLIP_ERR_SPEECH_BUFFER; /* Overflow, clamped */
    }

    return CLIP_OK;
}

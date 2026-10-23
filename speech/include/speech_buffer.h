/*
 * speech_buffer.h — Audio chunk accumulator for speech recognition
 */

#ifndef CLICOM_SPEECH_BUFFER_H
#define CLICOM_SPEECH_BUFFER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_types.h"
#include "clip_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SpeechBuffer {
    int16_t*    samples;
    size_t      capacity_samples;
    size_t      count_samples;
    uint64_t    start_time_ms;
    uint64_t    last_frame_time_ms;
    ClipUuid    session_uuid;
    ClipUuid    speaker_uuid;
    bool        has_speaker;
} SpeechBuffer;

ClipError speech_buffer_init(SpeechBuffer* sb, size_t capacity_samples);
void      speech_buffer_destroy(SpeechBuffer* sb);
void      speech_buffer_reset(SpeechBuffer* sb);

ClipError speech_buffer_append(SpeechBuffer* sb,
                               const ClipUuid* session_uuid,
                               const ClipUuid* speaker_uuid,
                               uint64_t timestamp_ms,
                               const int16_t* pcm,
                               size_t sample_count,
                               bool* out_speaker_changed);

#ifdef __cplusplus
}
#endif

#endif /* CLICOM_SPEECH_BUFFER_H */

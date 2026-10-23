/*
 * speech_analyzer.h — CLICOM SpeechAnalyzer Interface
 *
 * Phase 12: Modular SpeechAnalyzer abstraction, PCM chunking,
 *           deterministic mock adapter, and null adapter.
 *
 * ── Privacy and Transparency ─────────────────────────────────────────────
 *
 * CLICOM operates in server-mediated speech analysis mode by default.
 * In this mode, the server discloses analysis via CLIP_TAG_SPEECH_ANALYSIS
 * in SESSION_START messages. All session members are informed of this
 * disclosure before transmission begins.
 *
 * SpeechAnalyzer receives ONLY decoded 16-bit linear PCM audio associated
 * with an authenticated session, valid session_uuid, and currently
 * authorized PTT floor holder. It never opens audio recording hardware,
 * soundcards, or unrelated system audio.
 */

#ifndef CLICOM_SPEECH_ANALYZER_H
#define CLICOM_SPEECH_ANALYZER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_types.h"
#include "clip_errors.h"
#include "clip_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SpeechAnalyzer SpeechAnalyzer;

/*
 * Speech transcript result emitted when an audio chunk is transcribed.
 */
typedef struct SpeechTranscriptResult {
    const char* text;                   /* NUL-terminated UTF-8 transcript string */
    size_t      text_len;               /* Length of transcript string in bytes */
    uint64_t    start_time_ms;          /* Audio start timestamp (epoch or session ms) */
    uint64_t    duration_ms;            /* Audio segment duration in milliseconds */
    float       confidence;             /* Normalized confidence score [0.0f, 1.0f] */
    ClipUuid    speaker_node_uuid;      /* UUID of the speaker node */
    char        speaker_node_id[CLIP_UUID_STR_SIZE]; /* Canonical UUID string */
    ClipUuid    session_uuid;           /* Associated communication session UUID */
    bool        is_final;               /* True if utterance completed (e.g. floor release) */
} SpeechTranscriptResult;

/*
 * Asynchronous transcript callback.
 * Invoked when a transcript segment is ready.
 */
typedef void (*SpeechTranscriptCallback)(const SpeechTranscriptResult* result, void* user_data);

/*
 * SpeechAnalyzer configuration parameters.
 */
typedef struct SpeechAnalyzerConfig {
    int         sample_rate;            /* PCM sample rate in Hz (default: 16000) */
    int         channels;               /* Audio channels (default: 1 for mono) */
    size_t      min_chunk_samples;      /* Minimum samples before partial transcript (default: 8000 = 500ms) */
    size_t      max_buffer_samples;     /* Maximum buffered samples before force-flush (default: 48000 = 3000ms) */
    float       min_confidence;         /* Minimum confidence threshold (default: 0.5f) */
    void*       backend_config;         /* Backend-specific custom configuration */
} SpeechAnalyzerConfig;

/* Initializes a SpeechAnalyzerConfig with safe default values. */
void speech_analyzer_config_default(SpeechAnalyzerConfig* config);

/*
 * Factory: Creates a SpeechAnalyzer instance using the requested adapter.
 *   adapter_name: "null" (no-op stub) or "mock" (deterministic testing provider).
 *   config: Optional configuration pointer (pass NULL for default configuration).
 */
SpeechAnalyzer* speech_analyzer_create(const char* adapter_name, const SpeechAnalyzerConfig* config);

/* Destroys a SpeechAnalyzer instance and frees all associated resources. */
void speech_analyzer_destroy(SpeechAnalyzer* sa);

/*
 * Resets the analyzer state: clears internal audio buffers, pending transcripts,
 * and current speaker association.
 */
ClipError speech_analyzer_reset(SpeechAnalyzer* sa);

/*
 * Flushes any accumulated audio in the chunking buffer, forcing immediate
 * transcription of remaining samples and marking the result as is_final = true.
 * Typically invoked upon PTT floor release.
 */
ClipError speech_analyzer_flush(SpeechAnalyzer* sa);

/*
 * Feeds a decoded 16-bit linear PCM frame into the analyzer.
 * MUST be validated 16 kHz 16-bit signed mono PCM from an authorized session frame.
 * Never feeds raw un-decoded network packets or unrelated system audio.
 *
 * Parameters:
 *   sa: SpeechAnalyzer instance.
 *   session_uuid: Non-zero UUID of the active session.
 *   speaker_uuid: UUID of the current floor holder.
 *   timestamp_ms: Monotonic or epoch timestamp of frame start.
 *   pcm: Validated 16-bit linear PCM samples.
 *   sample_count: Number of samples in pcm (e.g. 320 for 20ms @ 16kHz).
 */
ClipError speech_analyzer_feed_pcm(SpeechAnalyzer*  sa,
                                   const ClipUuid*  session_uuid,
                                   const ClipUuid*  speaker_uuid,
                                   uint64_t         timestamp_ms,
                                   const int16_t*   pcm,
                                   size_t           sample_count);

/*
 * Registers or updates the asynchronous transcript callback and user context.
 */
ClipError speech_analyzer_set_callback(SpeechAnalyzer*          sa,
                                       SpeechTranscriptCallback callback,
                                       void*                    user_data);

/* Returns the active adapter name (e.g., "null", "mock"). */
const char* speech_analyzer_adapter_name(const SpeechAnalyzer* sa);

#ifdef __cplusplus
}
#endif

#endif /* CLICOM_SPEECH_ANALYZER_H */

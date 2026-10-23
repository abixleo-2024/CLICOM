/*
 * clip_captions.h — CLICOM Live Captions Subsystem
 *
 * Phase 13: Bounded, thread-safe in-memory caption buffer and terminal UI.
 *
 * Architecture:
 * - Consumes SpeechTranscriptResult from Phase 12 SpeechAnalyzer.
 * - Thread-safe circular buffer synchronized via Win32 CRITICAL_SECTION.
 * - Supports interim (in-progress) and final transcript updates.
 * - Enforces session UUID scoping and CLIP_TAG_SPEECH_ANALYSIS disclosure.
 * - Formats timestamps, resolves speaker friendly names (with UUID fallback).
 * - Renders cleanly in standard terminal/CLI without curses or TUI frameworks.
 * - CLIP_MSG_CAPTION (0x0070) remains reserved; Phase 13 is local-only presentation.
 */

#ifndef CLICOM_CLIP_CAPTIONS_H
#define CLICOM_CLIP_CAPTIONS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <windows.h>

#include "clip_types.h"
#include "clip_errors.h"
#include "clip_protocol.h"
#include "speech_analyzer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLIP_CAPTION_TEXT_MAX            256
#define CLIP_CAPTION_SPEAKER_NAME_MAX     64
#define CLIP_CAPTION_HISTORY_DEFAULT      50
#define CLIP_CAPTION_RENDER_LINES_DEFAULT  8

/*
 * Single caption entry representing a transcribed utterance segment.
 */
typedef struct ClipCaptionEntry {
    uint64_t timestamp_ms;                               /* Audio start timestamp (epoch or session ms) */
    char     time_str[16];                               /* Formatted "[HH:MM:SS]" string */
    ClipUuid speaker_uuid;                               /* UUID of the speaker node */
    char     speaker_name[CLIP_CAPTION_SPEAKER_NAME_MAX]; /* Friendly display name or UUID string */
    char     text[CLIP_CAPTION_TEXT_MAX];                /* Transcribed text (NUL-terminated UTF-8) */
    size_t   text_len;                                   /* Length in bytes */
    float    confidence;                                 /* Normalized confidence score [0.0f, 1.0f] */
    bool     is_final;                                   /* True if utterance completed; false if interim */
    uint32_t sequence_id;                                /* Monotonically increasing entry sequence */
} ClipCaptionEntry;

/*
 * Speaker name resolver callback function pointer.
 * Translates a speaker UUID into a friendly node name.
 * If returns NULL or not provided, canonical UUID string is used as fallback.
 */
typedef const char* (*ClipSpeakerResolver)(const ClipUuid* speaker_uuid, void* user_data);

/*
 * Thread-safe bounded circular caption buffer.
 */
typedef struct ClipCaptionBuffer {
    ClipCaptionEntry*   entries;                         /* Dynamic array of caption entries */
    size_t              capacity;                        /* Maximum history capacity */
    size_t              head;                            /* Circular buffer write head */
    size_t              count;                           /* Number of active stored entries */
    uint32_t            next_sequence;                   /* Monotonic entry sequence counter */
    ClipUuid            active_session_uuid;             /* Scoped active session UUID */
    bool                session_active;                  /* Whether a session is active */
    ClipSpeechMode      speech_mode;                     /* Active session disclosure mode */
    bool                has_active_interim;              /* True if latest entry is an in-progress interim */
    ClipSpeakerResolver speaker_resolver;                /* Optional friendly name resolver */
    void*               resolver_user_data;              /* User context for speaker resolver */
    CRITICAL_SECTION    lock;                            /* Thread-safety critical section */
    bool                initialized;                     /* Initialization guard */
} ClipCaptionBuffer;

/*
 * Initializes the caption buffer with the specified capacity.
 * If max_history == 0, CLIP_CAPTION_HISTORY_DEFAULT (50) is used.
 */
ClipError clip_captions_init(ClipCaptionBuffer* buf, size_t max_history);

/*
 * Frees buffer resources and destroys the synchronization object.
 */
void clip_captions_cleanup(ClipCaptionBuffer* buf);

/*
 * Configures the active session and speech mode disclosure.
 * If session_uuid is NULL or zero, the session is marked inactive.
 * Clears caption history upon session configuration change.
 */
ClipError clip_captions_set_session(ClipCaptionBuffer* buf,
                                    const ClipUuid*    session_uuid,
                                    ClipSpeechMode     speech_mode);

/*
 * Clears all stored caption entries while retaining session configuration and lock.
 */
ClipError clip_captions_clear(ClipCaptionBuffer* buf);

/*
 * Registers an optional speaker name resolver callback.
 */
void clip_captions_set_speaker_resolver(ClipCaptionBuffer*  buf,
                                        ClipSpeakerResolver resolver,
                                        void*               user_data);

/*
 * Ingests a SpeechTranscriptResult into the caption buffer.
 * Thread-safe: can be called directly from SpeechTranscriptCallback on worker threads.
 *
 * Rules:
 * - Rejects if session is not active or session_uuid does not match active session.
 * - Rejects if speech_mode == CLIP_SPEECH_MODE_NONE.
 * - Replaces latest interim entry in-place if speaker matches.
 * - Converts interim to final when is_final == true.
 * - Starts a new entry on speaker change or when previous utterance was finalized.
 * - Evicts oldest entries when capacity is exceeded.
 */
ClipError clip_captions_push_transcript(ClipCaptionBuffer*            buf,
                                        const SpeechTranscriptResult* result);

/*
 * Bridge callback compatible with SpeechTranscriptCallback.
 * Pass as speech_analyzer_set_callback(sa, clip_captions_transcript_callback, buf);
 */
void clip_captions_transcript_callback(const SpeechTranscriptResult* result, void* user_data);

/*
 * Returns the current number of stored caption entries.
 * Thread-safe.
 */
size_t clip_captions_get_count(ClipCaptionBuffer* buf);

/*
 * Retrieves an entry by chronological index (0 = oldest, count - 1 = newest).
 * Thread-safe.
 */
ClipError clip_captions_get_entry(ClipCaptionBuffer* buf,
                                  size_t             index,
                                  ClipCaptionEntry*  out_entry);

/*
 * Renders the live captions box to the specified file stream (stdout if NULL).
 * Displays up to max_lines of recent history.
 * Thread-safe.
 */
void clip_captions_render(ClipCaptionBuffer* buf, FILE* out_stream, size_t max_lines);

/*
 * Exports stored final caption entries formatted as a concise text summary.
 * Format per entry: "[HH:MM:SS] SPEAKER: text\n"
 * Thread-safe: operates under buffer CRITICAL_SECTION.
 * Only exports entries where is_final is true.
 * If out_written is non-NULL, receives the number of bytes written (excluding NUL).
 */
ClipError clip_captions_export_summary(ClipCaptionBuffer* buf,
                                       char*              out_buf,
                                       size_t             out_buf_len,
                                       size_t*            out_written);

#ifdef __cplusplus
}
#endif

#endif /* CLICOM_CLIP_CAPTIONS_H */

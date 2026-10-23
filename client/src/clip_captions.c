/*
 * clip_captions.c — CLICOM Live Captions Subsystem Implementation
 *
 * Phase 13: Bounded, thread-safe in-memory caption buffer and terminal UI.
 */

#include "clip_captions.h"
#include "clip_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

ClipError clip_captions_init(ClipCaptionBuffer* buf, size_t max_history)
{
    if (!buf) return CLIP_ERR_INVALID;

    size_t cap = (max_history == 0) ? CLIP_CAPTION_HISTORY_DEFAULT : max_history;
    ClipCaptionEntry* entries = (ClipCaptionEntry*)calloc(cap, sizeof(ClipCaptionEntry));
    if (!entries) return CLIP_ERR_NOMEM;

    InitializeCriticalSection(&buf->lock);
    buf->entries = entries;
    buf->capacity = cap;
    buf->head = 0;
    buf->count = 0;
    buf->next_sequence = 1;
    clip_uuid_zero(&buf->active_session_uuid);
    buf->session_active = false;
    buf->speech_mode = CLIP_SPEECH_MODE_NONE;
    buf->has_active_interim = false;
    buf->speaker_resolver = NULL;
    buf->resolver_user_data = NULL;
    buf->initialized = true;

    return CLIP_OK;
}

void clip_captions_cleanup(ClipCaptionBuffer* buf)
{
    if (!buf || !buf->initialized) return;

    EnterCriticalSection(&buf->lock);
    if (buf->entries) {
        free(buf->entries);
        buf->entries = NULL;
    }
    buf->capacity = 0;
    buf->head = 0;
    buf->count = 0;
    buf->session_active = false;
    buf->initialized = false;
    LeaveCriticalSection(&buf->lock);

    DeleteCriticalSection(&buf->lock);
}

ClipError clip_captions_set_session(ClipCaptionBuffer* buf,
                                    const ClipUuid*    session_uuid,
                                    ClipSpeechMode     speech_mode)
{
    if (!buf || !buf->initialized) return CLIP_ERR_INVALID;

    EnterCriticalSection(&buf->lock);

    if (!session_uuid || clip_uuid_is_zero(session_uuid)) {
        buf->session_active = false;
        clip_uuid_zero(&buf->active_session_uuid);
        buf->speech_mode = CLIP_SPEECH_MODE_NONE;
    } else {
        buf->session_active = true;
        buf->active_session_uuid = *session_uuid;
        buf->speech_mode = speech_mode;
    }

    /* Reset caption history upon session configuration change */
    buf->count = 0;
    buf->head = 0;
    buf->has_active_interim = false;

    LeaveCriticalSection(&buf->lock);
    return CLIP_OK;
}

ClipError clip_captions_clear(ClipCaptionBuffer* buf)
{
    if (!buf || !buf->initialized) return CLIP_ERR_INVALID;

    EnterCriticalSection(&buf->lock);
    buf->count = 0;
    buf->head = 0;
    buf->has_active_interim = false;
    LeaveCriticalSection(&buf->lock);

    return CLIP_OK;
}

void clip_captions_set_speaker_resolver(ClipCaptionBuffer*  buf,
                                        ClipSpeakerResolver resolver,
                                        void*               user_data)
{
    if (!buf || !buf->initialized) return;

    EnterCriticalSection(&buf->lock);
    buf->speaker_resolver = resolver;
    buf->resolver_user_data = user_data;
    LeaveCriticalSection(&buf->lock);
}

static void format_timestamp(uint64_t timestamp_ms, char* out_str, size_t out_len)
{
    if (!out_str || out_len == 0) return;

    /*
     * If timestamp_ms > 100000000000ULL, treat as epoch ms (> ~year 1973).
     * Otherwise, treat as relative session milliseconds.
     */
    if (timestamp_ms > 100000000000ULL) {
        time_t sec = (time_t)(timestamp_ms / 1000);
        struct tm tm_buf;
#if defined(_WIN32)
        localtime_s(&tm_buf, &sec);
#else
        localtime_r(&sec, &tm_buf);
#endif
        snprintf(out_str, out_len, "[%02d:%02d:%02d]", tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
    } else {
        uint32_t tot_sec = (uint32_t)(timestamp_ms / 1000);
        uint32_t hr = (tot_sec / 3600) % 24;
        uint32_t min = (tot_sec % 3600) / 60;
        uint32_t sec = tot_sec % 60;
        snprintf(out_str, out_len, "[%02u:%02u:%02u]", (unsigned)hr, (unsigned)min, (unsigned)sec);
    }
}

ClipError clip_captions_push_transcript(ClipCaptionBuffer*            buf,
                                        const SpeechTranscriptResult* result)
{
    if (!buf || !buf->initialized || !result) return CLIP_ERR_INVALID;

    EnterCriticalSection(&buf->lock);

    /* 1. Session verification */
    if (!buf->session_active) {
        LeaveCriticalSection(&buf->lock);
        return CLIP_ERR_NO_SESSION;
    }

    if (buf->speech_mode == CLIP_SPEECH_MODE_NONE) {
        LeaveCriticalSection(&buf->lock);
        return CLIP_ERR_SPEECH_INACTIVE;
    }

    if (clip_uuid_compare(&result->session_uuid, &buf->active_session_uuid) != 0) {
        LeaveCriticalSection(&buf->lock);
        return CLIP_ERR_INVALID;
    }

    /* 2. Speaker display name resolution */
    char spk_name[CLIP_CAPTION_SPEAKER_NAME_MAX] = {0};
    if (buf->speaker_resolver) {
        const char* res_name = buf->speaker_resolver(&result->speaker_node_uuid, buf->resolver_user_data);
        if (res_name && res_name[0] != '\0') {
            strncpy(spk_name, res_name, sizeof(spk_name) - 1);
        }
    }

    if (spk_name[0] == '\0') {
        if (result->speaker_node_id[0] != '\0') {
            strncpy(spk_name, result->speaker_node_id, sizeof(spk_name) - 1);
        } else {
            clip_uuid_to_string(&result->speaker_node_uuid, spk_name, sizeof(spk_name));
        }
    }

    /* 3. Timestamp formatting */
    char t_str[16] = {0};
    format_timestamp(result->start_time_ms, t_str, sizeof(t_str));

    /* 4. Text boundary and truncation */
    char safe_text[CLIP_CAPTION_TEXT_MAX] = {0};
    if (result->text) {
        strncpy(safe_text, result->text, sizeof(safe_text) - 1);
    }
    size_t safe_len = strlen(safe_text);

    /* 5. Interim update check */
    if (buf->has_active_interim && buf->count > 0) {
        size_t last_idx = (buf->head + buf->capacity - 1) % buf->capacity;
        bool same_speaker = (clip_uuid_compare(&buf->entries[last_idx].speaker_uuid,
                                              &result->speaker_node_uuid) == 0);
        if (same_speaker) {
            /* Update existing in-progress entry in place */
            strncpy(buf->entries[last_idx].text, safe_text, sizeof(buf->entries[last_idx].text) - 1);
            buf->entries[last_idx].text_len = safe_len;
            buf->entries[last_idx].confidence = result->confidence;
            if (result->is_final) {
                buf->entries[last_idx].is_final = true;
                buf->has_active_interim = false;
            } else {
                buf->entries[last_idx].is_final = false;
                buf->has_active_interim = true;
            }
            LeaveCriticalSection(&buf->lock);
            return CLIP_OK;
        } else {
            /* Speaker changed: seal previous speaker's utterance and allocate new */
            buf->entries[last_idx].is_final = true;
            buf->has_active_interim = false;
        }
    }

    /* 6. Append new entry into circular buffer */
    ClipCaptionEntry* entry = &buf->entries[buf->head];
    entry->timestamp_ms = result->start_time_ms;
    strncpy(entry->time_str, t_str, sizeof(entry->time_str) - 1);
    entry->speaker_uuid = result->speaker_node_uuid;
    strncpy(entry->speaker_name, spk_name, sizeof(entry->speaker_name) - 1);
    strncpy(entry->text, safe_text, sizeof(entry->text) - 1);
    entry->text_len = safe_len;
    entry->confidence = result->confidence;
    entry->is_final = result->is_final;
    entry->sequence_id = buf->next_sequence++;

    buf->head = (buf->head + 1) % buf->capacity;
    if (buf->count < buf->capacity) {
        buf->count++;
    }
    buf->has_active_interim = !result->is_final;

    LeaveCriticalSection(&buf->lock);
    return CLIP_OK;
}

void clip_captions_transcript_callback(const SpeechTranscriptResult* result, void* user_data)
{
    if (!result || !user_data) return;
    clip_captions_push_transcript((ClipCaptionBuffer*)user_data, result);
}

size_t clip_captions_get_count(ClipCaptionBuffer* buf)
{
    if (!buf || !buf->initialized) return 0;

    EnterCriticalSection(&buf->lock);
    size_t cnt = buf->count;
    LeaveCriticalSection(&buf->lock);

    return cnt;
}

ClipError clip_captions_get_entry(ClipCaptionBuffer* buf,
                                  size_t             index,
                                  ClipCaptionEntry*  out_entry)
{
    if (!buf || !buf->initialized || !out_entry) return CLIP_ERR_INVALID;

    EnterCriticalSection(&buf->lock);
    if (index >= buf->count) {
        LeaveCriticalSection(&buf->lock);
        return CLIP_ERR_NOT_FOUND;
    }

    /* Logical index 0 is oldest, count - 1 is newest */
    size_t phys_idx = (buf->head + buf->capacity - buf->count + index) % buf->capacity;
    *out_entry = buf->entries[phys_idx];

    LeaveCriticalSection(&buf->lock);
    return CLIP_OK;
}

void clip_captions_render(ClipCaptionBuffer* buf, FILE* out_stream, size_t max_lines)
{
    if (!buf || !buf->initialized) return;
    if (!out_stream) out_stream = stdout;

    EnterCriticalSection(&buf->lock);

    fprintf(out_stream, "+------------------------------------------------------------------------+\n");
    fprintf(out_stream, "| LIVE CAPTIONS                                                          |\n");
    fprintf(out_stream, "+------------------------------------------------------------------------+\n");

    if (!buf->session_active) {
        fprintf(out_stream, "| [No active session]                                                    |\n");
    } else if (buf->speech_mode == CLIP_SPEECH_MODE_NONE) {
        fprintf(out_stream, "| [DISABLED: Speech analysis not disclosed for this session]             |\n");
    } else if (buf->count == 0) {
        fprintf(out_stream, "| [Listening...]                                                         |\n");
    } else {
        size_t limit = (max_lines == 0) ? CLIP_CAPTION_RENDER_LINES_DEFAULT : max_lines;
        size_t start_i = (buf->count > limit) ? (buf->count - limit) : 0;

        for (size_t i = start_i; i < buf->count; i++) {
            size_t phys_idx = (buf->head + buf->capacity - buf->count + i) % buf->capacity;
            const ClipCaptionEntry* e = &buf->entries[phys_idx];

            if (e->is_final) {
                fprintf(out_stream, "| %s %s: %s\n", e->time_str, e->speaker_name, e->text);
            } else {
                fprintf(out_stream, "| %s %s: [interim] %s\n", e->time_str, e->speaker_name, e->text);
            }
        }
    }

    fprintf(out_stream, "+------------------------------------------------------------------------+\n");
    fflush(out_stream);

    LeaveCriticalSection(&buf->lock);
}

ClipError clip_captions_export_summary(ClipCaptionBuffer* buf,
                                       char*              out_buf,
                                       size_t             out_buf_len,
                                       size_t*            out_written)
{
    if (!buf || !buf->initialized || !out_buf || out_buf_len == 0) {
        return CLIP_ERR_INVALID;
    }

    EnterCriticalSection(&buf->lock);

    out_buf[0] = '\0';
    size_t written = 0;

    for (size_t i = 0; i < buf->count; i++) {
        size_t phys_idx = (buf->head + buf->capacity - buf->count + i) % buf->capacity;
        const ClipCaptionEntry* e = &buf->entries[phys_idx];

        if (!e->is_final) {
            continue;
        }

        char line[CLIP_CAPTION_TEXT_MAX + CLIP_CAPTION_SPEAKER_NAME_MAX + 32];
        int line_len = snprintf(line, sizeof(line), "%s %s: %s\n",
                                e->time_str, e->speaker_name, e->text);
        if (line_len < 0) continue;

        if (written + (size_t)line_len >= out_buf_len) {
            /* Buffer full, stop and preserve valid string */
            break;
        }

        memcpy(out_buf + written, line, (size_t)line_len);
        written += (size_t)line_len;
        out_buf[written] = '\0';
    }

    if (out_written) {
        *out_written = written;
    }

    LeaveCriticalSection(&buf->lock);
    return CLIP_OK;
}

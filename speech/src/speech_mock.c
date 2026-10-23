/*
 * speech_mock.c — Deterministic Testing Adapter for SpeechAnalyzer
 *
 * NOTE: This is purely a deterministic testing provider. It generates
 * synthetic transcript results to verify chunking, timestamps, speaker
 * mapping, confidence bounds, and flush behavior. It is NOT real STT.
 */

#include "speech_internal.h"
#include "speech_buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct MockContext {
    SpeechBuffer buffer;
    uint32_t     chunk_sequence;
} MockContext;

static void emit_chunk(SpeechAnalyzer* sa, MockContext* ctx, bool is_final)
{
    if (ctx->buffer.count_samples == 0) {
        return;
    }

    ctx->chunk_sequence++;

    char speaker_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(&ctx->buffer.speaker_uuid, speaker_str, sizeof(speaker_str));

    uint64_t duration_ms = 0;
    if (sa->config.sample_rate > 0) {
        duration_ms = (uint64_t)((ctx->buffer.count_samples * 1000) / (size_t)sa->config.sample_rate);
    }

    char transcript_buf[256];
    int len = snprintf(transcript_buf, sizeof(transcript_buf),
                       "[MOCK_TRANSCRIPT: seq=%u, samples=%zu, dur=%ums, final=%s]",
                       ctx->chunk_sequence,
                       ctx->buffer.count_samples,
                       (unsigned int)duration_ms,
                       is_final ? "true" : "false");
    if (len < 0) len = 0;
    if ((size_t)len >= sizeof(transcript_buf)) len = sizeof(transcript_buf) - 1;

    SpeechTranscriptResult res;
    memset(&res, 0, sizeof(res));
    res.text = transcript_buf;
    res.text_len = (size_t)len;
    res.start_time_ms = ctx->buffer.start_time_ms;
    res.duration_ms = duration_ms;
    res.confidence = 0.95f; /* Deterministic synthetic test confidence */
    memcpy(res.speaker_node_uuid.bytes, ctx->buffer.speaker_uuid.bytes, CLIP_UUID_BYTES);
    memcpy(res.speaker_node_id, speaker_str, sizeof(res.speaker_node_id));
    memcpy(res.session_uuid.bytes, ctx->buffer.session_uuid.bytes, CLIP_UUID_BYTES);
    res.is_final = is_final;

    speech_analyzer_dispatch_result(sa, &res);

    /* Reset buffer for next chunk */
    speech_buffer_reset(&ctx->buffer);
}

static ClipError mock_init(SpeechAnalyzer* sa, const SpeechAnalyzerConfig* config)
{
    MockContext* ctx = (MockContext*)malloc(sizeof(MockContext));
    if (!ctx) return CLIP_ERR_NOMEM;
    memset(ctx, 0, sizeof(*ctx));

    size_t cap = config->max_buffer_samples ? config->max_buffer_samples : 48000;
    ClipError err = speech_buffer_init(&ctx->buffer, cap);
    if (err != CLIP_OK) {
        free(ctx);
        return err;
    }

    sa->adapter_ctx = ctx;
    return CLIP_OK;
}

static void mock_destroy(SpeechAnalyzer* sa)
{
    if (!sa || !sa->adapter_ctx) return;
    MockContext* ctx = (MockContext*)sa->adapter_ctx;
    speech_buffer_destroy(&ctx->buffer);
    free(ctx);
    sa->adapter_ctx = NULL;
}

static ClipError mock_reset(SpeechAnalyzer* sa)
{
    if (!sa || !sa->adapter_ctx) return CLIP_ERR_INVALID;
    MockContext* ctx = (MockContext*)sa->adapter_ctx;
    speech_buffer_reset(&ctx->buffer);
    ctx->chunk_sequence = 0;
    return CLIP_OK;
}

static ClipError mock_flush(SpeechAnalyzer* sa)
{
    if (!sa || !sa->adapter_ctx) return CLIP_ERR_INVALID;
    MockContext* ctx = (MockContext*)sa->adapter_ctx;
    if (ctx->buffer.count_samples > 0) {
        emit_chunk(sa, ctx, true);
    }
    return CLIP_OK;
}

static ClipError mock_feed_pcm(SpeechAnalyzer* sa,
                               const ClipUuid* session_uuid,
                               const ClipUuid* speaker_uuid,
                               uint64_t timestamp_ms,
                               const int16_t* pcm,
                               size_t sample_count)
{
    if (!sa || !sa->adapter_ctx) return CLIP_ERR_INVALID;
    MockContext* ctx = (MockContext*)sa->adapter_ctx;

    bool speaker_changed = false;
    ClipError append_err = speech_buffer_append(&ctx->buffer, session_uuid, speaker_uuid,
                                                timestamp_ms, pcm, sample_count, &speaker_changed);
    if (speaker_changed) {
        /* Flush previous speaker chunk first */
        emit_chunk(sa, ctx, true);
        /* Then append to fresh buffer for new speaker */
        append_err = speech_buffer_append(&ctx->buffer, session_uuid, speaker_uuid,
                                          timestamp_ms, pcm, sample_count, NULL);
    }

    /* Check if buffer has reached chunk threshold */
    if (ctx->buffer.count_samples >= sa->config.min_chunk_samples) {
        emit_chunk(sa, ctx, false);
    }

    return append_err;
}

static const SpeechAnalyzerOps s_mock_ops = {
    .init     = mock_init,
    .destroy  = mock_destroy,
    .reset    = mock_reset,
    .flush    = mock_flush,
    .feed_pcm = mock_feed_pcm,
};

const SpeechAnalyzerOps* speech_adapter_mock_get_ops(void)
{
    return &s_mock_ops;
}

/*
 * speech_null.c — No-op stub SpeechAnalyzer adapter
 */

#include "speech_internal.h"
#include <stdlib.h>

static ClipError null_init(SpeechAnalyzer* sa, const SpeechAnalyzerConfig* config)
{
    (void)sa;
    (void)config;
    return CLIP_OK;
}

static void null_destroy(SpeechAnalyzer* sa)
{
    (void)sa;
}

static ClipError null_reset(SpeechAnalyzer* sa)
{
    (void)sa;
    return CLIP_OK;
}

static ClipError null_flush(SpeechAnalyzer* sa)
{
    (void)sa;
    return CLIP_OK;
}

static ClipError null_feed_pcm(SpeechAnalyzer* sa,
                               const ClipUuid* session_uuid,
                               const ClipUuid* speaker_uuid,
                               uint64_t timestamp_ms,
                               const int16_t* pcm,
                               size_t sample_count)
{
    (void)sa;
    (void)session_uuid;
    (void)speaker_uuid;
    (void)timestamp_ms;
    (void)pcm;
    (void)sample_count;
    /* Consumes PCM and produces zero output */
    return CLIP_OK;
}

static const SpeechAnalyzerOps s_null_ops = {
    .init     = null_init,
    .destroy  = null_destroy,
    .reset    = null_reset,
    .flush    = null_flush,
    .feed_pcm = null_feed_pcm,
};

const SpeechAnalyzerOps* speech_adapter_null_get_ops(void)
{
    return &s_null_ops;
}

/*
 * speech_analyzer.c — Public API dispatch and lifecycle for SpeechAnalyzer
 */

#include "speech_analyzer.h"
#include "speech_internal.h"
#include <stdlib.h>
#include <string.h>

void speech_analyzer_config_default(SpeechAnalyzerConfig* config)
{
    if (!config) return;
    memset(config, 0, sizeof(*config));
    config->sample_rate = 16000;
    config->channels = 1;
    config->min_chunk_samples = 8000;  /* 500 ms @ 16 kHz */
    config->max_buffer_samples = 48000; /* 3000 ms @ 16 kHz */
    config->min_confidence = 0.5f;
    config->backend_config = NULL;
}

SpeechAnalyzer* speech_analyzer_create(const char* adapter_name, const SpeechAnalyzerConfig* config)
{
    if (!adapter_name) {
        return NULL;
    }

    SpeechAnalyzerConfig cfg;
    if (config) {
        cfg = *config;
    } else {
        speech_analyzer_config_default(&cfg);
    }

    /* Validate basic PCM configuration */
    if (cfg.sample_rate <= 0 || cfg.channels != 1 || cfg.min_chunk_samples == 0 || cfg.max_buffer_samples == 0) {
        return NULL;
    }

    const SpeechAnalyzerOps* ops = NULL;
    if (strcmp(adapter_name, "null") == 0) {
        ops = speech_adapter_null_get_ops();
    } else if (strcmp(adapter_name, "mock") == 0) {
        ops = speech_adapter_mock_get_ops();
    } else {
        return NULL; /* Unsupported adapter */
    }

    SpeechAnalyzer* sa = (SpeechAnalyzer*)malloc(sizeof(SpeechAnalyzer));
    if (!sa) return NULL;
    memset(sa, 0, sizeof(*sa));

    sa->adapter_name = adapter_name;
    sa->ops = ops;
    sa->config = cfg;
    InitializeCriticalSection(&sa->lock);

    if (ops->init) {
        ClipError err = ops->init(sa, &cfg);
        if (err != CLIP_OK) {
            DeleteCriticalSection(&sa->lock);
            free(sa);
            return NULL;
        }
    }

    sa->initialized = true;
    return sa;
}

void speech_analyzer_destroy(SpeechAnalyzer* sa)
{
    if (!sa) return;

    EnterCriticalSection(&sa->lock);
    if (sa->ops && sa->ops->destroy) {
        sa->ops->destroy(sa);
    }
    sa->initialized = false;
    LeaveCriticalSection(&sa->lock);

    DeleteCriticalSection(&sa->lock);
    free(sa);
}

ClipError speech_analyzer_reset(SpeechAnalyzer* sa)
{
    if (!sa || !sa->initialized) return CLIP_ERR_INVALID;

    EnterCriticalSection(&sa->lock);
    ClipError err = CLIP_OK;
    if (sa->ops && sa->ops->reset) {
        err = sa->ops->reset(sa);
    }
    LeaveCriticalSection(&sa->lock);
    return err;
}

ClipError speech_analyzer_flush(SpeechAnalyzer* sa)
{
    if (!sa || !sa->initialized) return CLIP_ERR_INVALID;

    EnterCriticalSection(&sa->lock);
    ClipError err = CLIP_OK;
    if (sa->ops && sa->ops->flush) {
        err = sa->ops->flush(sa);
    }
    LeaveCriticalSection(&sa->lock);
    return err;
}

ClipError speech_analyzer_feed_pcm(SpeechAnalyzer*  sa,
                                   const ClipUuid*  session_uuid,
                                   const ClipUuid*  speaker_uuid,
                                   uint64_t         timestamp_ms,
                                   const int16_t*   pcm,
                                   size_t           sample_count)
{
    if (!sa || !sa->initialized || !session_uuid || !speaker_uuid || !pcm) {
        return CLIP_ERR_INVALID;
    }
    if (sample_count == 0) {
        return CLIP_ERR_INVALID;
    }
    if (clip_uuid_is_zero(session_uuid) || clip_uuid_is_zero(speaker_uuid)) {
        return CLIP_ERR_NO_SESSION;
    }

    EnterCriticalSection(&sa->lock);
    ClipError err = CLIP_OK;
    if (sa->ops && sa->ops->feed_pcm) {
        err = sa->ops->feed_pcm(sa, session_uuid, speaker_uuid, timestamp_ms, pcm, sample_count);
    }
    LeaveCriticalSection(&sa->lock);
    return err;
}

ClipError speech_analyzer_set_callback(SpeechAnalyzer*          sa,
                                       SpeechTranscriptCallback callback,
                                       void*                    user_data)
{
    if (!sa || !sa->initialized) return CLIP_ERR_INVALID;

    EnterCriticalSection(&sa->lock);
    sa->callback = callback;
    sa->user_data = user_data;
    LeaveCriticalSection(&sa->lock);
    return CLIP_OK;
}

const char* speech_analyzer_adapter_name(const SpeechAnalyzer* sa)
{
    if (!sa) return NULL;
    return sa->adapter_name;
}

void speech_analyzer_dispatch_result(SpeechAnalyzer* sa, const SpeechTranscriptResult* result)
{
    if (!sa || !result) return;
    if (sa->callback) {
        sa->callback(result, sa->user_data);
    }
}

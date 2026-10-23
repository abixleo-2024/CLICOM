/*
 * speech_internal.h — Internal vtable and definitions for SpeechAnalyzer
 */

#ifndef CLICOM_SPEECH_INTERNAL_H
#define CLICOM_SPEECH_INTERNAL_H

#include "speech_analyzer.h"
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SpeechAnalyzerOps {
    ClipError (*init)(SpeechAnalyzer* sa, const SpeechAnalyzerConfig* config);
    void      (*destroy)(SpeechAnalyzer* sa);
    ClipError (*reset)(SpeechAnalyzer* sa);
    ClipError (*flush)(SpeechAnalyzer* sa);
    ClipError (*feed_pcm)(SpeechAnalyzer* sa,
                          const ClipUuid* session_uuid,
                          const ClipUuid* speaker_uuid,
                          uint64_t timestamp_ms,
                          const int16_t* pcm,
                          size_t sample_count);
} SpeechAnalyzerOps;

struct SpeechAnalyzer {
    const char*              adapter_name;
    const SpeechAnalyzerOps* ops;
    SpeechAnalyzerConfig     config;
    SpeechTranscriptCallback callback;
    void*                    user_data;
    void*                    adapter_ctx;
    CRITICAL_SECTION         lock;
    bool                     initialized;
};

/* Internal helper: dispatches transcript callback safely under lock */
void speech_analyzer_dispatch_result(SpeechAnalyzer* sa, const SpeechTranscriptResult* result);

/* Adapter factory declarations */
const SpeechAnalyzerOps* speech_adapter_null_get_ops(void);
const SpeechAnalyzerOps* speech_adapter_mock_get_ops(void);

#ifdef __cplusplus
}
#endif

#endif /* CLICOM_SPEECH_INTERNAL_H */

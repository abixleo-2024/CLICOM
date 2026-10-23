/*
 * audio.h — CLICOM Audio Engine Interface
 *
 * Phase 0: Interface declaration only. No implementation.
 * Phase 10: PortAudio capture/playback backend.
 * Phase 11: Audio transport and codec abstraction.
 *
 * Design:
 *   Audio capture, playback, transport, codec, PTT, and session management
 *   are separate concerns. This interface does not couple them.
 *   The codec is swappable via codec.h. Future codecs (Opus etc.) can be
 *   added without modifying the AudioEngine interface.
 *   Phases 0-9: audio may be simulated with stub/null frames.
 */

#ifndef CLICOM_AUDIO_H
#define CLICOM_AUDIO_H

#include <stdint.h>
#include <stddef.h>

typedef struct AudioEngine AudioEngine;

typedef struct {
    int sample_rate;    /* e.g. 16000, 48000 */
    int channels;       /* 1 = mono, 2 = stereo */
    int frame_size;     /* samples per frame */
} AudioConfig;

/* Callback: invoked with captured PCM frames */
typedef void (*AudioCaptureCallback)(const int16_t* pcm,
                                     size_t         sample_count,
                                     void*          user_data);

/* Lifecycle */
AudioEngine* audio_engine_create(const AudioConfig* cfg);
void         audio_engine_destroy(AudioEngine* engine);

/* Capture */
int  audio_capture_start(AudioEngine* engine, AudioCaptureCallback cb,
                         void* user_data);
void audio_capture_stop(AudioEngine* engine);

/* Playback */
int  audio_playback_start(AudioEngine* engine);
int  audio_playback_submit(AudioEngine* engine, const int16_t* pcm,
                           size_t sample_count);
void audio_playback_stop(AudioEngine* engine);

#endif /* CLICOM_AUDIO_H */

/*
 * clip_audio.h — High-Level Audio Engine & PTT Floor Invariant Manager
 *
 * Coordinates microphone capture, speaker playback, circular buffering,
 * and strict server-authoritative Push-to-Talk (PTT) floor-gated capture.
 */

#ifndef CLIP_AUDIO_H
#define CLIP_AUDIO_H

#include "clip_audio_types.h"
#include "clip_audio_device.h"
#include "clip_audio_ring_buffer.h"

typedef struct {
    ClipAudioConfig          config;
    ClipAudioDevice*         device;             /* Abstracted capture/playback device */
    ClipAudioRingBuffer      capture_rb;         /* Capture FIFO ring buffer           */
    ClipAudioRingBuffer      playback_rb;        /* Playback FIFO ring buffer          */
    bool                     floor_held;         /* CRITICAL: Server PTT floor gating  */
    bool                     initialized;
    ClipAudioCaptureCallback app_capture_cb;     /* App callback when frames ready     */
    void*                    app_user_data;
    CRITICAL_SECTION         cs;
    uint64_t                 total_captured_frames;
    uint64_t                 total_playback_frames;
} ClipAudioEngine;

/* ── Lifecycle ──────────────────────────────────────────────────────────── */
ClipError clip_audio_engine_init(ClipAudioEngine* engine, const ClipAudioConfig* config);
void      clip_audio_engine_cleanup(ClipAudioEngine* engine);

/* ── PTT Floor Control Integration (CRITICAL INVARIANT) ─────────────────── */
/*
 * Invariants:
 *  - Audio MUST NOT capture unless server granted PTT floor.
 *  - Calling clip_audio_on_floor_granted() starts local microphone capture.
 *  - Calling clip_audio_on_floor_released() immediately stops capture.
 *  - Low-level audio callbacks received when floor_held == false are strictly suppressed.
 */
ClipError clip_audio_on_floor_granted(ClipAudioEngine* engine);
ClipError clip_audio_on_floor_released(ClipAudioEngine* engine);
bool      clip_audio_is_floor_held(const ClipAudioEngine* engine);

/* ── Application Capture API ────────────────────────────────────────────── */
/* Registers user callback. Capture will only deliver frames when floor_held == true */
ClipError clip_audio_set_capture_callback(ClipAudioEngine*         engine,
                                          ClipAudioCaptureCallback cb,
                                          void*                    user_data);

/* Direct read of captured PCM samples from circular ring buffer */
size_t    clip_audio_read_captured_pcm(ClipAudioEngine* engine,
                                       int16_t*         out_pcm,
                                       size_t           max_samples);

bool      clip_audio_is_capturing(const ClipAudioEngine* engine);

/* ── Application Playback API ───────────────────────────────────────────── */
ClipError clip_audio_start_playback(ClipAudioEngine* engine);
ClipError clip_audio_stop_playback(ClipAudioEngine* engine);
ClipError clip_audio_play_frame(ClipAudioEngine* engine,
                                const int16_t*   pcm,
                                size_t           sample_count);
bool      clip_audio_is_playing(const ClipAudioEngine* engine);

#endif /* CLIP_AUDIO_H */

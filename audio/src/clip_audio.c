/*
 * clip_audio.c — High-Level Audio Engine Implementation
 */

#include "clip_audio.h"
#include <stdlib.h>
#include <string.h>

/* Internal callback from ClipAudioDevice */
static void internal_device_capture_callback(const int16_t* pcm,
                                             size_t         sample_count,
                                             uint64_t       timestamp_ms,
                                             void*          user_data)
{
    ClipAudioEngine* engine = (ClipAudioEngine*)user_data;
    if (!engine || !pcm || sample_count == 0) return;

    EnterCriticalSection(&engine->cs);

    /* Push into capture ring buffer */

    /* Push into capture ring buffer */
    clip_audio_ring_buffer_write(&engine->capture_rb, pcm, sample_count);
    engine->total_captured_frames++;

    ClipAudioCaptureCallback cb = engine->app_capture_cb;
    void* udata = engine->app_user_data;

    LeaveCriticalSection(&engine->cs);

    if (cb) {
        cb(pcm, sample_count, timestamp_ms, udata);
    }
}

ClipError clip_audio_engine_init(ClipAudioEngine* engine, const ClipAudioConfig* config)
{
    if (!engine) return CLIP_ERR_INVALID;

    memset(engine, 0, sizeof(ClipAudioEngine));

    ClipAudioConfig cfg;
    if (config) {
        cfg = *config;
    } else {
        clip_audio_config_init_default(&cfg);
    }

    ClipError val_err = clip_audio_config_validate(&cfg);
    if (val_err != CLIP_OK) return val_err;

    engine->config = cfg;
    InitializeCriticalSection(&engine->cs);

    /* Allocate ring buffer for 2 seconds of audio */
    size_t rb_capacity = (size_t)cfg.sample_rate * (size_t)cfg.channels * 2u;
    ClipError rb_err = clip_audio_ring_buffer_init(&engine->capture_rb, rb_capacity);
    if (rb_err != CLIP_OK) {
        DeleteCriticalSection(&engine->cs);
        return rb_err;
    }

    clip_audio_ring_buffer_init(&engine->playback_rb, rb_capacity);

    /* Create backend audio device */
    engine->device = clip_audio_device_create(cfg.backend, &cfg);
    if (!engine->device) {
        /* If WinMM failed to open hardware, fallback to mock if requested, or return error */
        clip_audio_ring_buffer_cleanup(&engine->capture_rb);
        clip_audio_ring_buffer_cleanup(&engine->playback_rb);
        DeleteCriticalSection(&engine->cs);
        return CLIP_ERR_AUDIO_DEVICE;
    }

    engine->floor_held = false;
    engine->initialized = true;
    return CLIP_OK;
}

void clip_audio_engine_cleanup(ClipAudioEngine* engine)
{
    if (!engine || !engine->initialized) return;

    EnterCriticalSection(&engine->cs);
    engine->floor_held = false;

    if (engine->device) {
        clip_audio_device_stop_capture(engine->device);
        clip_audio_device_stop_playback(engine->device);
        clip_audio_device_destroy(engine->device);
        engine->device = NULL;
    }

    clip_audio_ring_buffer_cleanup(&engine->capture_rb);
    clip_audio_ring_buffer_cleanup(&engine->playback_rb);
    engine->initialized = false;

    LeaveCriticalSection(&engine->cs);
    DeleteCriticalSection(&engine->cs);
}

ClipError clip_audio_on_floor_granted(ClipAudioEngine* engine)
{
    if (!engine || !engine->initialized) return CLIP_ERR_INVALID;

    EnterCriticalSection(&engine->cs);
    engine->floor_held = true;

    /* Start low-level device capture */
    ClipError cap_err = CLIP_OK;
    if (engine->device && engine->device->capture_state != CLIP_AUDIO_STATE_CAPTURING) {
        cap_err = clip_audio_device_start_capture(engine->device,
                                                  internal_device_capture_callback,
                                                  engine);
    }
    LeaveCriticalSection(&engine->cs);
    return cap_err;
}

ClipError clip_audio_on_floor_released(ClipAudioEngine* engine)
{
    if (!engine || !engine->initialized) return CLIP_ERR_INVALID;

    EnterCriticalSection(&engine->cs);
    engine->floor_held = false;

    /* Immediately stop low-level capture */
    if (engine->device && engine->device->capture_state == CLIP_AUDIO_STATE_CAPTURING) {
        clip_audio_device_stop_capture(engine->device);
    }

    /* Reset ring buffer so no stale microphone frames remain */
    clip_audio_ring_buffer_reset(&engine->capture_rb);
    LeaveCriticalSection(&engine->cs);
    return CLIP_OK;
}

bool clip_audio_is_floor_held(const ClipAudioEngine* engine)
{
    return (engine && engine->initialized) ? engine->floor_held : false;
}

ClipError clip_audio_set_capture_callback(ClipAudioEngine*         engine,
                                          ClipAudioCaptureCallback cb,
                                          void*                    user_data)
{
    if (!engine || !engine->initialized) return CLIP_ERR_INVALID;

    EnterCriticalSection(&engine->cs);
    engine->app_capture_cb = cb;
    engine->app_user_data = user_data;
    LeaveCriticalSection(&engine->cs);
    return CLIP_OK;
}

size_t clip_audio_read_captured_pcm(ClipAudioEngine* engine,
                                    int16_t*         out_pcm,
                                    size_t           max_samples)
{
    if (!engine || !engine->initialized || !out_pcm) return 0;
    return clip_audio_ring_buffer_read(&engine->capture_rb, out_pcm, max_samples);
}

bool clip_audio_is_capturing(const ClipAudioEngine* engine)
{
    if (!engine || !engine->initialized || !engine->device) return false;
    return (engine->device->capture_state == CLIP_AUDIO_STATE_CAPTURING);
}

ClipError clip_audio_start_playback(ClipAudioEngine* engine)
{
    if (!engine || !engine->initialized || !engine->device) return CLIP_ERR_INVALID;
    return clip_audio_device_start_playback(engine->device);
}

ClipError clip_audio_stop_playback(ClipAudioEngine* engine)
{
    if (!engine || !engine->initialized || !engine->device) return CLIP_ERR_INVALID;
    return clip_audio_device_stop_playback(engine->device);
}

ClipError clip_audio_play_frame(ClipAudioEngine* engine,
                                const int16_t*   pcm,
                                size_t           sample_count)
{
    if (!engine || !engine->initialized || !engine->device || !pcm || sample_count == 0) {
        return CLIP_ERR_INVALID;
    }

    /* Queue or write directly to device */
    ClipError res = clip_audio_device_write_playback(engine->device, pcm, sample_count);
    if (res == CLIP_OK) {
        EnterCriticalSection(&engine->cs);
        engine->total_playback_frames++;
        LeaveCriticalSection(&engine->cs);
    }
    return res;
}

bool clip_audio_is_playing(const ClipAudioEngine* engine)
{
    if (!engine || !engine->initialized || !engine->device) return false;
    return (engine->device->playback_state == CLIP_AUDIO_STATE_PLAYING);
}

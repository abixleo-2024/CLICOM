/*
 * clip_audio_device.h — Audio Hardware & Virtual Device Abstraction
 *
 * Provides a clean polymorphic interface for microphone capture and speaker
 * playback with both Windows WinMM and deterministic in-memory Mock backends.
 */

#ifndef CLIP_AUDIO_DEVICE_H
#define CLIP_AUDIO_DEVICE_H

#include "clip_audio_types.h"

typedef struct ClipAudioDevice ClipAudioDevice;
typedef struct ClipAudioDeviceOps ClipAudioDeviceOps;

/* Callback: invoked when a new frame of PCM samples has been captured */
typedef void (*ClipAudioCaptureCallback)(const int16_t* pcm,
                                         size_t         sample_count,
                                         uint64_t       timestamp_ms,
                                         void*          user_data);

struct ClipAudioDeviceOps {
    ClipError (*init)(ClipAudioDevice* dev, const ClipAudioConfig* config);
    ClipError (*start_capture)(ClipAudioDevice* dev, ClipAudioCaptureCallback cb, void* user_data);
    ClipError (*stop_capture)(ClipAudioDevice* dev);
    ClipError (*start_playback)(ClipAudioDevice* dev);
    ClipError (*write_playback)(ClipAudioDevice* dev, const int16_t* pcm, size_t sample_count);
    ClipError (*stop_playback)(ClipAudioDevice* dev);
    ClipError (*shutdown)(ClipAudioDevice* dev);
    ClipError (*probe_devices)(ClipAudioDeviceType type, uint32_t* out_count);
};

struct ClipAudioDevice {
    const ClipAudioDeviceOps* ops;
    ClipAudioConfig           config;
    ClipAudioDeviceState      capture_state;
    ClipAudioDeviceState      playback_state;
    ClipAudioCaptureCallback  capture_cb;
    void*                     capture_user_data;
    void*                     backend_ctx;
};

/* Factory Functions */
ClipAudioDevice* clip_audio_device_create(ClipAudioBackendType backend, const ClipAudioConfig* config);
ClipAudioDevice* clip_audio_device_create_mock(const ClipAudioConfig* config);
ClipAudioDevice* clip_audio_device_create_winmm(const ClipAudioConfig* config);
void             clip_audio_device_destroy(ClipAudioDevice* dev);

/* Universal Device Operations */
ClipError clip_audio_device_start_capture(ClipAudioDevice* dev, ClipAudioCaptureCallback cb, void* user_data);
ClipError clip_audio_device_stop_capture(ClipAudioDevice* dev);
ClipError clip_audio_device_start_playback(ClipAudioDevice* dev);
ClipError clip_audio_device_write_playback(ClipAudioDevice* dev, const int16_t* pcm, size_t sample_count);
ClipError clip_audio_device_stop_playback(ClipAudioDevice* dev);

/* Diagnostics / Mock Verification */
size_t    clip_audio_mock_get_playback_samples(ClipAudioDevice* dev, int16_t* out_buf, size_t max_samples);
void      clip_audio_mock_set_synthetic_frequency(ClipAudioDevice* dev, float freq_hz);

#endif /* CLIP_AUDIO_DEVICE_H */

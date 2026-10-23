/*
 * clip_audio_types.h — CLICOM Audio Types & PCM Configuration
 *
 * Defines audio format parameters, PCM buffer descriptors, device states,
 * and backend identifications for Phase 9 local audio capture and playback.
 */

#ifndef CLIP_AUDIO_TYPES_H
#define CLIP_AUDIO_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_errors.h"

/* ── Default Audio Configuration Constants ───────────────────────────────── */

#define CLIP_AUDIO_DEFAULT_SAMPLE_RATE      16000u /* 16 kHz voice standard  */
#define CLIP_AUDIO_DEFAULT_CHANNELS         1u     /* Mono                   */
#define CLIP_AUDIO_DEFAULT_BITS_PER_SAMPLE  16u    /* 16-bit signed PCM LE   */
#define CLIP_AUDIO_DEFAULT_FRAME_MS         20u    /* 20 ms frame duration   */

/* Maximum frame parameters for allocation bounding */
#define CLIP_AUDIO_MAX_SAMPLE_RATE          48000u
#define CLIP_AUDIO_MIN_SAMPLE_RATE          8000u
#define CLIP_AUDIO_MAX_CHANNELS             2u
#define CLIP_AUDIO_MIN_CHANNELS             1u
#define CLIP_AUDIO_MAX_FRAME_MS             100u
#define CLIP_AUDIO_MIN_FRAME_MS             5u

/* ── Audio Device Backend Identifier ────────────────────────────────────── */

typedef enum {
    CLIP_AUDIO_BACKEND_MOCK  = 0, /* In-memory deterministic mock for tests  */
    CLIP_AUDIO_BACKEND_WINMM = 1  /* Windows Multimedia (waveIn / waveOut)   */
} ClipAudioBackendType;

/* ── Device State ───────────────────────────────────────────────────────── */

typedef enum {
    CLIP_AUDIO_STATE_IDLE        = 0,
    CLIP_AUDIO_STATE_CAPTURING   = 1,
    CLIP_AUDIO_STATE_PLAYING     = 2,
    CLIP_AUDIO_STATE_FULL_DUPLEX = 3,
    CLIP_AUDIO_STATE_ERROR       = 4
} ClipAudioDeviceState;

/* ── Device Direction / Type ────────────────────────────────────────────── */

typedef enum {
    CLIP_AUDIO_DEVICE_INPUT  = 1, /* Microphone / Recording device           */
    CLIP_AUDIO_DEVICE_OUTPUT = 2  /* Speaker / Playback device               */
} ClipAudioDeviceType;

/* ── Audio Format Configuration ─────────────────────────────────────────── */

typedef struct {
    uint32_t             sample_rate;       /* e.g. 16000, 48000 Hz          */
    uint16_t             channels;          /* 1 = mono, 2 = stereo          */
    uint16_t             bits_per_sample;   /* must be 16                    */
    uint16_t             frame_duration_ms; /* e.g. 20 ms                    */
    ClipAudioBackendType backend;           /* MOCK or WINMM                 */
    uint32_t             device_id_in;      /* input device index (0=default)*/
    uint32_t             device_id_out;     /* output device index (0=default)*/
} ClipAudioConfig;

/* ── PCM Buffer Representation ──────────────────────────────────────────── */

typedef struct {
    int16_t* samples;           /* Borrowed or owned PCM samples             */
    size_t   sample_count;      /* Total individual samples in buffer        */
    size_t   capacity_samples;  /* Buffer capacity in samples                */
    uint32_t sample_rate;       /* Sampling rate in Hz                       */
    uint16_t channels;          /* Channel count                             */
    uint64_t timestamp_ms;      /* Capture or queue timestamp                */
} ClipPcmBuffer;

/* ── PCM Frame Calculation Helpers ──────────────────────────────────────── */

static inline void clip_audio_config_init_default(ClipAudioConfig* cfg)
{
    if (!cfg) return;
    cfg->sample_rate       = CLIP_AUDIO_DEFAULT_SAMPLE_RATE;
    cfg->channels          = CLIP_AUDIO_DEFAULT_CHANNELS;
    cfg->bits_per_sample   = CLIP_AUDIO_DEFAULT_BITS_PER_SAMPLE;
    cfg->frame_duration_ms = CLIP_AUDIO_DEFAULT_FRAME_MS;
    cfg->backend           = CLIP_AUDIO_BACKEND_WINMM;
    cfg->device_id_in      = 0;
    cfg->device_id_out     = 0;
}

static inline ClipError clip_audio_config_validate(const ClipAudioConfig* cfg)
{
    if (!cfg) return CLIP_ERR_INVALID;
    if (cfg->sample_rate < CLIP_AUDIO_MIN_SAMPLE_RATE ||
        cfg->sample_rate > CLIP_AUDIO_MAX_SAMPLE_RATE) {
        return CLIP_ERR_AUDIO_FORMAT;
    }
    if (cfg->channels < CLIP_AUDIO_MIN_CHANNELS ||
        cfg->channels > CLIP_AUDIO_MAX_CHANNELS) {
        return CLIP_ERR_AUDIO_FORMAT;
    }
    if (cfg->bits_per_sample != 16) {
        return CLIP_ERR_AUDIO_FORMAT;
    }
    if (cfg->frame_duration_ms < CLIP_AUDIO_MIN_FRAME_MS ||
        cfg->frame_duration_ms > CLIP_AUDIO_MAX_FRAME_MS) {
        return CLIP_ERR_AUDIO_FORMAT;
    }
    return CLIP_OK;
}

/* Samples per single-channel frame */
static inline size_t clip_audio_samples_per_frame_per_channel(const ClipAudioConfig* cfg)
{
    if (!cfg || cfg->frame_duration_ms == 0) return 0;
    return (size_t)((cfg->sample_rate * cfg->frame_duration_ms) / 1000u);
}

/* Total samples across all channels in one frame */
static inline size_t clip_audio_samples_per_frame(const ClipAudioConfig* cfg)
{
    if (!cfg) return 0;
    return clip_audio_samples_per_frame_per_channel(cfg) * (size_t)cfg->channels;
}

/* Total bytes in one frame */
static inline size_t clip_audio_bytes_per_frame(const ClipAudioConfig* cfg)
{
    if (!cfg) return 0;
    return clip_audio_samples_per_frame(cfg) * (size_t)(cfg->bits_per_sample / 8u);
}

#endif /* CLIP_AUDIO_TYPES_H */

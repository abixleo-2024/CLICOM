/*
 * codec.h — CLICOM Audio Codec Interface
 *
 * Phase 11: Modular audio codec architecture.
 * Concrete implementations:
 *   - CLIP_CODEC_NULL: No-op / test dummy codec
 *   - CLIP_CODEC_PCM : 16-bit linear PCM passthrough
 *   - CLIP_CODEC_OPUS: Opus interactive voice compression (RFC 6716)
 */

#ifndef CLICOM_CODEC_H
#define CLICOM_CODEC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_errors.h"
#include "clip_protocol.h"

typedef ClipAudioCodecType ClipCodecType;

typedef struct AudioCodec AudioCodec;

typedef struct {
    int  sample_rate;       /* 8000, 12000, 16000, 24000, 48000 Hz */
    int  channels;          /* 1 = mono, 2 = stereo */
    int  bitrate_bps;       /* bits per second (default: 24000 for VoIP speech) */
    int  complexity;        /* 0..10 (Opus complexity, default 5) */
    bool enable_fec;        /* Forward Error Correction */
} AudioCodecConfig;

/* Initialize default config for given codec type */
void codec_config_init_default(AudioCodecConfig* cfg, ClipCodecType type);

/* Factory */
AudioCodec*   codec_create(ClipCodecType type, int sample_rate, int channels);
AudioCodec*   codec_create_custom(ClipCodecType type, const AudioCodecConfig* cfg);
void          codec_destroy(AudioCodec* codec);
ClipCodecType codec_get_type(const AudioCodec* codec);

/* Reset encoder/decoder internal states (called at PTT floor transitions) */
int codec_reset(AudioCodec* codec);

/* Configure bitrate */
int codec_set_bitrate(AudioCodec* codec, int bitrate_bps);

/* Encode: PCM -> compressed. Returns bytes written, or negative ClipError. */
int codec_encode(AudioCodec* codec, const int16_t* pcm_in,
                 size_t pcm_samples, uint8_t* out_buf, size_t out_max);

/* Decode: compressed -> PCM. If in_buf == NULL or in_len == 0: executes PLC. Returns samples written, or negative ClipError. */
int codec_decode(AudioCodec* codec, const uint8_t* in_buf, size_t in_len,
                 int16_t* pcm_out, size_t pcm_max_samples);

#endif /* CLICOM_CODEC_H */

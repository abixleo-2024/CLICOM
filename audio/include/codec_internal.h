/*
 * codec_internal.h — Internal vtable and declarations for CLICOM Audio Codecs
 */

#ifndef CLICOM_CODEC_INTERNAL_H
#define CLICOM_CODEC_INTERNAL_H

#include "codec.h"

struct AudioCodecOps {
    void          (*destroy)(AudioCodec* codec);
    ClipCodecType (*get_type)(const AudioCodec* codec);
    int           (*reset)(AudioCodec* codec);
    int           (*set_bitrate)(AudioCodec* codec, int bitrate_bps);
    int           (*encode)(AudioCodec* codec, const int16_t* pcm_in, size_t pcm_samples, uint8_t* out_buf, size_t out_max);
    int           (*decode)(AudioCodec* codec, const uint8_t* in_buf, size_t in_len, int16_t* pcm_out, size_t pcm_max_samples);
};

struct AudioCodec {
    const struct AudioCodecOps* ops;
    ClipCodecType type;
    int sample_rate;
    int channels;
    void* impl;
};

AudioCodec* codec_create_null(const AudioCodecConfig* cfg);
AudioCodec* codec_create_pcm(const AudioCodecConfig* cfg);
AudioCodec* codec_create_opus(const AudioCodecConfig* cfg);

#endif /* CLICOM_CODEC_INTERNAL_H */

/*
 * codec.c — Audio Codec Factory and Dispatch Implementation
 */

#include <stdlib.h>
#include <string.h>
#include "codec_internal.h"
#include "clip_errors.h"

void codec_config_init_default(AudioCodecConfig* cfg, ClipCodecType type)
{
    if (!cfg) return;
    memset(cfg, 0, sizeof(AudioCodecConfig));
    cfg->sample_rate = 16000;
    cfg->channels    = 1;
    cfg->bitrate_bps = 24000;
    cfg->complexity  = 5;
    cfg->enable_fec  = true;
}

AudioCodec* codec_create_custom(ClipCodecType type, const AudioCodecConfig* cfg)
{
    if (!cfg) return NULL;

    switch (type) {
        case CLIP_CODEC_NULL:
            return codec_create_null(cfg);
        case CLIP_CODEC_PCM:
            return codec_create_pcm(cfg);
        case CLIP_CODEC_OPUS:
            return codec_create_opus(cfg);
        default:
            return NULL;
    }
}

AudioCodec* codec_create(ClipCodecType type, int sample_rate, int channels)
{
    AudioCodecConfig cfg;
    codec_config_init_default(&cfg, type);
    cfg.sample_rate = sample_rate;
    cfg.channels    = channels;
    return codec_create_custom(type, &cfg);
}

void codec_destroy(AudioCodec* codec)
{
    if (!codec) return;
    if (codec->ops && codec->ops->destroy) {
        codec->ops->destroy(codec);
    } else {
        free(codec);
    }
}

ClipCodecType codec_get_type(const AudioCodec* codec)
{
    if (!codec) return CLIP_CODEC_NULL;
    return codec->type;
}

int codec_reset(AudioCodec* codec)
{
    if (!codec || !codec->ops || !codec->ops->reset) return CLIP_ERR_INVALID;
    return codec->ops->reset(codec);
}

int codec_set_bitrate(AudioCodec* codec, int bitrate_bps)
{
    if (!codec || !codec->ops || !codec->ops->set_bitrate) return CLIP_ERR_INVALID;
    return codec->ops->set_bitrate(codec, bitrate_bps);
}

int codec_encode(AudioCodec* codec, const int16_t* pcm_in,
                 size_t pcm_samples, uint8_t* out_buf, size_t out_max)
{
    if (!codec || !codec->ops || !codec->ops->encode) return CLIP_ERR_INVALID;
    return codec->ops->encode(codec, pcm_in, pcm_samples, out_buf, out_max);
}

int codec_decode(AudioCodec* codec, const uint8_t* in_buf, size_t in_len,
                 int16_t* pcm_out, size_t pcm_max_samples)
{
    if (!codec || !codec->ops || !codec->ops->decode) return CLIP_ERR_INVALID;
    return codec->ops->decode(codec, in_buf, in_len, pcm_out, pcm_max_samples);
}

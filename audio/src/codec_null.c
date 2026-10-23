/*
 * codec_null.c — No-op / Test Dummy Codec
 */

#include <stdlib.h>
#include <string.h>
#include "codec_internal.h"
#include "clip_errors.h"

static void null_destroy(AudioCodec* codec)
{
    free(codec);
}

static ClipCodecType null_get_type(const AudioCodec* codec)
{
    (void)codec;
    return CLIP_CODEC_NULL;
}

static int null_reset(AudioCodec* codec)
{
    (void)codec;
    return 0;
}

static int null_set_bitrate(AudioCodec* codec, int bitrate_bps)
{
    (void)codec;
    (void)bitrate_bps;
    return 0;
}

static int null_encode(AudioCodec* codec, const int16_t* pcm_in, size_t pcm_samples, uint8_t* out_buf, size_t out_max)
{
    (void)codec;
    (void)pcm_in;
    if (!out_buf || out_max == 0) return CLIP_ERR_INVALID;
    size_t write_bytes = (pcm_samples < out_max) ? pcm_samples : out_max;
    memset(out_buf, 0x5A, write_bytes);
    return (int)write_bytes;
}

static int null_decode(AudioCodec* codec, const uint8_t* in_buf, size_t in_len, int16_t* pcm_out, size_t pcm_max_samples)
{
    (void)codec;
    (void)in_buf;
    if (!pcm_out || pcm_max_samples == 0) return CLIP_ERR_INVALID;
    size_t samples = (in_len < pcm_max_samples) ? in_len : pcm_max_samples;
    memset(pcm_out, 0, samples * sizeof(int16_t));
    return (int)samples;
}

static const struct AudioCodecOps s_null_ops = {
    .destroy     = null_destroy,
    .get_type    = null_get_type,
    .reset       = null_reset,
    .set_bitrate = null_set_bitrate,
    .encode      = null_encode,
    .decode      = null_decode
};

AudioCodec* codec_create_null(const AudioCodecConfig* cfg)
{
    AudioCodec* c = (AudioCodec*)calloc(1, sizeof(AudioCodec));
    if (!c) return NULL;
    c->ops = &s_null_ops;
    c->type = CLIP_CODEC_NULL;
    c->sample_rate = cfg ? cfg->sample_rate : 16000;
    c->channels = cfg ? cfg->channels : 1;
    return c;
}

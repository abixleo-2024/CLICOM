/*
 * codec_pcm.c — Linear 16-Bit Signed PCM Codec Implementation
 */

#include <stdlib.h>
#include <string.h>
#include "codec_internal.h"
#include "clip_errors.h"

static void pcm_destroy(AudioCodec* codec)
{
    free(codec);
}

static ClipCodecType pcm_get_type(const AudioCodec* codec)
{
    (void)codec;
    return CLIP_CODEC_PCM;
}

static int pcm_reset(AudioCodec* codec)
{
    (void)codec;
    return 0;
}

static int pcm_set_bitrate(AudioCodec* codec, int bitrate_bps)
{
    (void)codec;
    (void)bitrate_bps;
    return 0;
}

static int pcm_encode(AudioCodec* codec, const int16_t* pcm_in, size_t pcm_samples, uint8_t* out_buf, size_t out_max)
{
    if (!codec || !pcm_in || !out_buf) return CLIP_ERR_INVALID;
    size_t req_bytes = pcm_samples * sizeof(int16_t);
    if (req_bytes > out_max) return CLIP_ERR_NOMEM;
    memcpy(out_buf, pcm_in, req_bytes);
    return (int)req_bytes;
}

static int pcm_decode(AudioCodec* codec, const uint8_t* in_buf, size_t in_len, int16_t* pcm_out, size_t pcm_max_samples)
{
    if (!codec || !pcm_out) return CLIP_ERR_INVALID;
    if (!in_buf || in_len == 0) {
        /* PLC for PCM: comfort noise / zero fill 320 samples */
        size_t samples = (320 < pcm_max_samples) ? 320 : pcm_max_samples;
        memset(pcm_out, 0, samples * sizeof(int16_t));
        return (int)samples;
    }
    if ((in_len % sizeof(int16_t)) != 0) {
        return CLIP_ERR_CODEC_DECODE;
    }
    size_t samples = in_len / sizeof(int16_t);
    if (samples > pcm_max_samples) return CLIP_ERR_NOMEM;
    memcpy(pcm_out, in_buf, in_len);
    return (int)samples;
}

static const struct AudioCodecOps s_pcm_ops = {
    .destroy     = pcm_destroy,
    .get_type    = pcm_get_type,
    .reset       = pcm_reset,
    .set_bitrate = pcm_set_bitrate,
    .encode      = pcm_encode,
    .decode      = pcm_decode
};

AudioCodec* codec_create_pcm(const AudioCodecConfig* cfg)
{
    if (!cfg || cfg->channels <= 0 || cfg->sample_rate <= 0) return NULL;
    AudioCodec* c = (AudioCodec*)calloc(1, sizeof(AudioCodec));
    if (!c) return NULL;
    c->ops = &s_pcm_ops;
    c->type = CLIP_CODEC_PCM;
    c->sample_rate = cfg->sample_rate;
    c->channels = cfg->channels;
    return c;
}

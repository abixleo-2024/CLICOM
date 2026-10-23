/*
 * codec_opus.c — Opus Interactive Speech Codec Implementation (RFC 6716)
 */

#include <stdlib.h>
#include <string.h>
#include <opus/opus.h>
#include "codec_internal.h"
#include "clip_errors.h"

typedef struct {
    OpusEncoder* encoder;
    OpusDecoder* decoder;
    int          bitrate_bps;
    int          complexity;
    bool         enable_fec;
} OpusCodecImpl;

static void opus_impl_destroy(AudioCodec* codec)
{
    if (!codec) return;
    OpusCodecImpl* impl = (OpusCodecImpl*)codec->impl;
    if (impl) {
        if (impl->encoder) opus_encoder_destroy(impl->encoder);
        if (impl->decoder) opus_decoder_destroy(impl->decoder);
        free(impl);
    }
    free(codec);
}

static ClipCodecType opus_impl_get_type(const AudioCodec* codec)
{
    (void)codec;
    return CLIP_CODEC_OPUS;
}

static int opus_impl_reset(AudioCodec* codec)
{
    if (!codec || !codec->impl) return CLIP_ERR_INVALID;
    OpusCodecImpl* impl = (OpusCodecImpl*)codec->impl;
    if (impl->encoder) {
        opus_encoder_ctl(impl->encoder, OPUS_RESET_STATE);
    }
    if (impl->decoder) {
        opus_decoder_ctl(impl->decoder, OPUS_RESET_STATE);
    }
    return 0;
}

static int opus_impl_set_bitrate(AudioCodec* codec, int bitrate_bps)
{
    if (!codec || !codec->impl || bitrate_bps <= 0) return CLIP_ERR_INVALID;
    OpusCodecImpl* impl = (OpusCodecImpl*)codec->impl;
    if (!impl->encoder) return CLIP_ERR_INVALID;
    impl->bitrate_bps = bitrate_bps;
    int err = opus_encoder_ctl(impl->encoder, OPUS_SET_BITRATE(bitrate_bps));
    return (err == OPUS_OK) ? 0 : CLIP_ERR_CODEC_ENCODE;
}

static int opus_impl_encode(AudioCodec* codec, const int16_t* pcm_in, size_t pcm_samples, uint8_t* out_buf, size_t out_max)
{
    if (!codec || !codec->impl || !pcm_in || pcm_samples == 0 || !out_buf || out_max == 0) {
        return CLIP_ERR_INVALID;
    }
    OpusCodecImpl* impl = (OpusCodecImpl*)codec->impl;
    if (!impl->encoder) return CLIP_ERR_INVALID;

    int bytes = opus_encode(impl->encoder, pcm_in, (int)pcm_samples, out_buf, (opus_int32)out_max);
    if (bytes < 0) {
        return CLIP_ERR_CODEC_ENCODE;
    }
    return bytes;
}

static int opus_impl_decode(AudioCodec* codec, const uint8_t* in_buf, size_t in_len, int16_t* pcm_out, size_t pcm_max_samples)
{
    if (!codec || !codec->impl || !pcm_out || pcm_max_samples == 0) {
        return CLIP_ERR_INVALID;
    }
    OpusCodecImpl* impl = (OpusCodecImpl*)codec->impl;
    if (!impl->decoder) return CLIP_ERR_INVALID;

    /* Opus PLC (Packet Loss Concealment) when in_buf == NULL or in_len == 0 */
    if (!in_buf || in_len == 0) {
        int samples = opus_decode(impl->decoder, NULL, 0, pcm_out, (int)pcm_max_samples, 0);
        if (samples < 0) return CLIP_ERR_CODEC_DECODE;
        return samples;
    }

    /* Malformed robustness checks (RFC 6716 max Opus packet size is 1275 bytes) */
    if (in_len > 1275) {
        return CLIP_ERR_AUDIO_OVERSIZED;
    }

    int samples = opus_decode(impl->decoder, in_buf, (opus_int32)in_len, pcm_out, (int)pcm_max_samples, 0);
    if (samples < 0) {
        return CLIP_ERR_CODEC_DECODE;
    }
    return samples;
}

static const struct AudioCodecOps s_opus_ops = {
    .destroy     = opus_impl_destroy,
    .get_type    = opus_impl_get_type,
    .reset       = opus_impl_reset,
    .set_bitrate = opus_impl_set_bitrate,
    .encode      = opus_impl_encode,
    .decode      = opus_impl_decode
};

AudioCodec* codec_create_opus(const AudioCodecConfig* cfg)
{
    if (!cfg) return NULL;

    /* Opus supports only 8000, 12000, 16000, 24000, 48000 Hz */
    if (cfg->sample_rate != 8000 && cfg->sample_rate != 12000 &&
        cfg->sample_rate != 16000 && cfg->sample_rate != 24000 &&
        cfg->sample_rate != 48000) {
        return NULL;
    }
    if (cfg->channels != 1 && cfg->channels != 2) {
        return NULL;
    }

    int err = OPUS_OK;
    OpusEncoder* enc = opus_encoder_create(cfg->sample_rate, cfg->channels, OPUS_APPLICATION_VOIP, &err);
    if (err != OPUS_OK || !enc) return NULL;

    int bitrate = cfg->bitrate_bps > 0 ? cfg->bitrate_bps : 24000;
    int complexity = (cfg->complexity >= 0 && cfg->complexity <= 10) ? cfg->complexity : 5;

    opus_encoder_ctl(enc, OPUS_SET_BITRATE(bitrate));
    opus_encoder_ctl(enc, OPUS_SET_COMPLEXITY(complexity));
    opus_encoder_ctl(enc, OPUS_SET_INBAND_FEC(cfg->enable_fec ? 1 : 0));
    opus_encoder_ctl(enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));

    OpusDecoder* dec = opus_decoder_create(cfg->sample_rate, cfg->channels, &err);
    if (err != OPUS_OK || !dec) {
        opus_encoder_destroy(enc);
        return NULL;
    }

    OpusCodecImpl* impl = (OpusCodecImpl*)calloc(1, sizeof(OpusCodecImpl));
    if (!impl) {
        opus_encoder_destroy(enc);
        opus_decoder_destroy(dec);
        return NULL;
    }
    impl->encoder     = enc;
    impl->decoder     = dec;
    impl->bitrate_bps = bitrate;
    impl->complexity  = complexity;
    impl->enable_fec  = cfg->enable_fec;

    AudioCodec* c = (AudioCodec*)calloc(1, sizeof(AudioCodec));
    if (!c) {
        opus_encoder_destroy(enc);
        opus_decoder_destroy(dec);
        free(impl);
        return NULL;
    }
    c->ops = &s_opus_ops;
    c->type = CLIP_CODEC_OPUS;
    c->sample_rate = cfg->sample_rate;
    c->channels = cfg->channels;
    c->impl = impl;

    return c;
}

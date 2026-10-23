/*
 * test_live_loopback.c — Live loopback test: mic -> opus encode -> opus decode -> speaker
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <windows.h>
#include <mmsystem.h>

#include "codec.h"
#include "clip_audio_types.h"
#include "clip_audio_device.h"
#include "clip_audio.h"

#define SAMPLE_RATE 48000
#define CHANNELS 1
#define FRAME_MS 20
#define SAMPLES_PER_FRAME ((SAMPLE_RATE * FRAME_MS) / 1000) /* 960 */

static AudioCodec* g_enc = NULL;
static AudioCodec* g_dec = NULL;
static ClipAudioEngine* g_play_hw = NULL;
static int g_frames = 0;

static void loopback_callback(const int16_t* pcm, size_t sample_count, uint64_t timestamp_ms, void* user_data) {
    (void)timestamp_ms;
    (void)user_data;
    g_frames++;

    uint8_t opus_buf[1275];
    int enc_bytes = codec_encode(g_enc, pcm, sample_count, opus_buf, sizeof(opus_buf));
    if (enc_bytes <= 0) return;

    int16_t decoded_pcm[SAMPLES_PER_FRAME * 2];
    int dec_samples = codec_decode(g_dec, opus_buf, (size_t)enc_bytes, decoded_pcm, SAMPLES_PER_FRAME * 2);
    if (dec_samples <= 0) return;

    clip_audio_play_frame(g_play_hw, decoded_pcm, (size_t)dec_samples);
}

int main(void) {
    printf("=== Live Mic -> Opus -> Speaker Loopback Test ===\n");

    ClipAudioConfig cfg;
    clip_audio_config_init_default(&cfg);
    cfg.sample_rate = SAMPLE_RATE;
    cfg.channels = CHANNELS;
    cfg.frame_duration_ms = FRAME_MS;
    cfg.backend = CLIP_AUDIO_BACKEND_WINMM;

    ClipAudioEngine cap_hw;
    ClipAudioEngine play_hw;

    clip_audio_engine_init(&cap_hw, &cfg);
    clip_audio_engine_init(&play_hw, &cfg);

    g_play_hw = &play_hw;
    g_enc = codec_create(CLIP_CODEC_OPUS, SAMPLE_RATE, CHANNELS);
    g_dec = codec_create(CLIP_CODEC_OPUS, SAMPLE_RATE, CHANNELS);

    clip_audio_set_capture_callback(&cap_hw, loopback_callback, NULL);

    clip_audio_start_playback(&play_hw);
    printf("Starting live loopback for 3.0 seconds (talk into microphone)...\n");
    clip_audio_on_floor_granted(&cap_hw);

    Sleep(3000);

    clip_audio_on_floor_released(&cap_hw);
    clip_audio_stop_playback(&play_hw);

    clip_audio_engine_cleanup(&cap_hw);
    clip_audio_engine_cleanup(&play_hw);

    codec_destroy(g_enc);
    codec_destroy(g_dec);

    printf("Loopback processed %d frames.\n", g_frames);
    printf("=== Test Complete ===\n");
    return 0;
}

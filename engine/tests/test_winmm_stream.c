/*
 * test_winmm_stream.c — Tests streaming 1 second (50 frames) of 1kHz tone through WinMM waveOut
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
#include "clip_errors.h"

#define SAMPLE_RATE 48000
#define CHANNELS 1
#define FRAME_MS 20
#define SAMPLES_PER_FRAME ((SAMPLE_RATE * FRAME_MS) / 1000) /* 960 */
#define TOTAL_FRAMES 50 /* 1 second of audio */

static void generate_continuous_tone(int16_t* pcm, size_t n_samples, uint32_t sample_rate, float freq_hz, float amplitude, double* phase) {
    double phase_inc = (2.0 * 3.14159265358979323846 * freq_hz) / (double)sample_rate;
    for (size_t i = 0; i < n_samples; i++) {
        pcm[i] = (int16_t)(sin(*phase) * amplitude * 32767.0);
        *phase += phase_inc;
        if (*phase >= 2.0 * 3.14159265358979323846) {
            *phase -= 2.0 * 3.14159265358979323846;
        }
    }
}

int main(void) {
    printf("=== WinMM Playback Streaming Test ===\n");

    ClipAudioConfig cfg;
    clip_audio_config_init_default(&cfg);
    cfg.sample_rate = SAMPLE_RATE;
    cfg.channels = CHANNELS;
    cfg.frame_duration_ms = FRAME_MS;
    cfg.backend = CLIP_AUDIO_BACKEND_WINMM;

    ClipAudioEngine hw;
    ClipError err = clip_audio_engine_init(&hw, &cfg);
    if (err != CLIP_OK) {
        printf("ERROR: clip_audio_engine_init failed: %d\n", err);
        return 1;
    }

    err = clip_audio_start_playback(&hw);
    if (err != CLIP_OK) {
        printf("ERROR: clip_audio_start_playback failed: %d\n", err);
        return 1;
    }
    printf("Audio engine initialized and playback started.\n");

    AudioCodec* enc = codec_create(CLIP_CODEC_OPUS, SAMPLE_RATE, CHANNELS);
    AudioCodec* dec = codec_create(CLIP_CODEC_OPUS, SAMPLE_RATE, CHANNELS);
    if (!enc || !dec) {
        printf("ERROR: Codec creation failed\n");
        return 1;
    }

    printf("Streaming %d frames (1.0 second) of continuous 1000 Hz tone through Opus and WinMM...\n", TOTAL_FRAMES);
    double phase = 0.0;
    int16_t pcm_in[SAMPLES_PER_FRAME];
    uint8_t opus_buf[1275];
    int16_t pcm_out[SAMPLES_PER_FRAME * 2];

    DWORD start_t = GetTickCount();
    for (int f = 0; f < TOTAL_FRAMES; f++) {
        generate_continuous_tone(pcm_in, SAMPLES_PER_FRAME, SAMPLE_RATE, 1000.0f, 0.25f, &phase);

        int enc_bytes = codec_encode(enc, pcm_in, SAMPLES_PER_FRAME, opus_buf, sizeof(opus_buf));
        if (enc_bytes <= 0) {
            printf("Frame %d encode error: %d\n", f, enc_bytes);
            break;
        }

        int dec_samples = codec_decode(dec, opus_buf, (size_t)enc_bytes, pcm_out, SAMPLES_PER_FRAME * 2);
        if (dec_samples <= 0) {
            printf("Frame %d decode error: %d\n", f, dec_samples);
            break;
        }

        /* Play frame */
        ClipError p_err = clip_audio_play_frame(&hw, pcm_out, (size_t)dec_samples);
        if (p_err != CLIP_OK) {
            printf("Frame %d play error: %d\n", f, p_err);
        }

        /* Pace frames every 20ms as network would deliver */
        Sleep(20);
    }
    DWORD elapsed = GetTickCount() - start_t;
    printf("Finished feeding %d frames in %lu ms. Letting buffer drain for 500ms...\n", TOTAL_FRAMES, elapsed);
    Sleep(500);

    clip_audio_stop_playback(&hw);
    clip_audio_engine_cleanup(&hw);
    codec_destroy(enc);
    codec_destroy(dec);

    printf("=== Test Complete ===\n");
    return 0;
}

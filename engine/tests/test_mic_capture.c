/*
 * test_mic_capture.c — Test real microphone capture and analyze recorded PCM
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <windows.h>
#include <mmsystem.h>

#include "clip_audio_types.h"
#include "clip_audio_device.h"
#include "clip_audio.h"

#define SAMPLE_RATE 48000
#define CHANNELS 1
#define FRAME_MS 20
#define SAMPLES_PER_FRAME ((SAMPLE_RATE * FRAME_MS) / 1000) /* 960 */

static int g_frame_count = 0;
static int64_t g_sum_sq = 0;
static int32_t g_min_sample = 0;
static int32_t g_max_sample = 0;
static int64_t g_dc_sum = 0;
static size_t g_total_samples = 0;

static void capture_callback(const int16_t* pcm, size_t sample_count, uint64_t timestamp_ms, void* user_data) {
    (void)timestamp_ms;
    (void)user_data;
    g_frame_count++;
    for (size_t i = 0; i < sample_count; i++) {
        int16_t s = pcm[i];
        if (s < g_min_sample) g_min_sample = s;
        if (s > g_max_sample) g_max_sample = s;
        g_dc_sum += s;
        g_sum_sq += ((int64_t)s * (int64_t)s);
        g_total_samples++;
    }
}

int main(void) {
    printf("=== Real Microphone Capture Analysis ===\n");

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

    clip_audio_set_capture_callback(&hw, capture_callback, NULL);

    printf("Starting microphone capture for 2.0 seconds...\n");
    err = clip_audio_on_floor_granted(&hw);
    if (err != CLIP_OK) {
        printf("ERROR: clip_audio_on_floor_granted failed: %d\n", err);
        return 1;
    }

    Sleep(2000);

    clip_audio_on_floor_released(&hw);
    clip_audio_engine_cleanup(&hw);

    printf("Captured %d frames (%zu total samples)\n", g_frame_count, g_total_samples);
    if (g_total_samples > 0) {
        double dc_offset = (double)g_dc_sum / (double)g_total_samples;
        double rms = sqrt((double)g_sum_sq / (double)g_total_samples);
        printf("  Min sample: %d\n", g_min_sample);
        printf("  Max sample: %d\n", g_max_sample);
        printf("  DC offset:  %.2f\n", dc_offset);
        printf("  RMS energy: %.2f / 32768 (%.2f dBFS)\n",
               rms, (rms > 0 ? 20.0 * log10(rms / 32768.0) : -96.0));
    }

    if (g_frame_count == 0) {
        printf("ERROR: 0 frames recorded from microphone!\n");
        return 1;
    }

    printf("=== Test Complete ===\n");
    return 0;
}

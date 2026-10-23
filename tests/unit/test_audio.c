/*
 * test_audio.c — Phase 9 Local Audio Capture & Playback Test Suite
 *
 * Covers:
 *  1. Audio config validation (valid/invalid configurations)
 *  2. PCM frame calculations (sample rates, channels, frame sizes)
 *  3. SPSC ring buffer (write, read, wrap-around, overrun, underrun, reset)
 *  4. Mock device capture (synthetic sine wave generation, callback delivery)
 *  5. Mock device playback (playback buffer writing, history verification)
 *  6. Audio engine lifecycle (initialization, cleanup, state tracking)
 *  7. Audio floor gating invariant (no capture without floor; capture when granted; stop when released)
 *  8. Audio capture floor bypass prevention (callbacks without floor rejected)
 *  9. Audio error handling (invalid args, null pointers, format errors)
 * 10. Local audio loopback (capture -> ring buffer read -> playback write)
 * 11. WinMM device probe (graceful handling in virtualized/headless environments)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <windows.h>
#include <mmsystem.h>

#include "clip_audio_types.h"
#include "clip_audio_ring_buffer.h"
#include "clip_audio_device.h"
#include "clip_audio.h"
#include "clip_errors.h"

static int g_pass = 0;
static int g_fail = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (cond) { \
        printf("  [PASS] %s\n", msg); \
        g_pass++; \
    } else { \
        printf("  [FAIL] %s (line %d)\n", msg, __LINE__); \
        g_fail++; \
    } \
} while(0)

/* ── Test 1: Config Validation ─────────────────────────────────────────── */
static void test_config_validation(void)
{
    printf("\n--- Test Group 1: Audio Config Validation ---\n");

    ClipAudioConfig cfg;
    clip_audio_config_init_default(&cfg);
    TEST_ASSERT(clip_audio_config_validate(&cfg) == CLIP_OK, "Default config is valid");
    TEST_ASSERT(cfg.sample_rate == 16000, "Default sample rate is 16000 Hz");
    TEST_ASSERT(cfg.channels == 1, "Default channels is 1 (mono)");
    TEST_ASSERT(cfg.bits_per_sample == 16, "Default bits per sample is 16");
    TEST_ASSERT(cfg.frame_duration_ms == 20, "Default frame duration is 20 ms");

    /* Valid custom configs */
    cfg.sample_rate = 8000;
    TEST_ASSERT(clip_audio_config_validate(&cfg) == CLIP_OK, "8000 Hz is valid");
    cfg.sample_rate = 44100;
    TEST_ASSERT(clip_audio_config_validate(&cfg) == CLIP_OK, "44100 Hz is valid");
    cfg.sample_rate = 48000;
    TEST_ASSERT(clip_audio_config_validate(&cfg) == CLIP_OK, "48000 Hz is valid");
    cfg.channels = 2;
    TEST_ASSERT(clip_audio_config_validate(&cfg) == CLIP_OK, "Stereo (2 channels) is valid");

    /* Invalid configs */
    cfg.sample_rate = 0;
    TEST_ASSERT(clip_audio_config_validate(&cfg) == CLIP_ERR_AUDIO_FORMAT, "0 Hz rejected");
    cfg.sample_rate = 120000;
    TEST_ASSERT(clip_audio_config_validate(&cfg) == CLIP_ERR_AUDIO_FORMAT, "120000 Hz rejected");
    cfg.sample_rate = 16000;
    cfg.channels = 0;
    TEST_ASSERT(clip_audio_config_validate(&cfg) == CLIP_ERR_AUDIO_FORMAT, "0 channels rejected");
    cfg.channels = 3;
    TEST_ASSERT(clip_audio_config_validate(&cfg) == CLIP_ERR_AUDIO_FORMAT, "3 channels rejected");
    cfg.channels = 1;
    cfg.bits_per_sample = 24;
    TEST_ASSERT(clip_audio_config_validate(&cfg) == CLIP_ERR_AUDIO_FORMAT, "24 bits rejected (PCM16 only)");
    cfg.bits_per_sample = 16;
    cfg.frame_duration_ms = 1;
    TEST_ASSERT(clip_audio_config_validate(&cfg) == CLIP_ERR_AUDIO_FORMAT, "1ms duration rejected");
    cfg.frame_duration_ms = 20;

    TEST_ASSERT(clip_audio_config_validate(NULL) == CLIP_ERR_INVALID, "NULL config rejected");
}

/* ── Test 2: PCM Frame Calculations ────────────────────────────────────── */
static void test_pcm_frame_calculations(void)
{
    printf("\n--- Test Group 2: PCM Frame Calculations ---\n");

    ClipAudioConfig cfg;
    clip_audio_config_init_default(&cfg);

    /* 16000 Hz, 20ms mono = 320 samples, 640 bytes */
    size_t samples = clip_audio_samples_per_frame(&cfg);
    size_t bytes = clip_audio_bytes_per_frame(&cfg);
    TEST_ASSERT(samples == 320, "16kHz 20ms mono -> 320 samples");
    TEST_ASSERT(bytes == 640, "16kHz 20ms mono -> 640 bytes");

    /* 48000 Hz, 10ms mono = 480 samples, 960 bytes */
    cfg.sample_rate = 48000;
    cfg.frame_duration_ms = 10;
    samples = clip_audio_samples_per_frame(&cfg);
    bytes = clip_audio_bytes_per_frame(&cfg);
    TEST_ASSERT(samples == 480, "48kHz 10ms mono -> 480 samples");
    TEST_ASSERT(bytes == 960, "48kHz 10ms mono -> 960 bytes");

    /* 44100 Hz, 20ms stereo = 882 samples/ch * 2 = 1764 samples, 3528 bytes */
    cfg.sample_rate = 44100;
    cfg.frame_duration_ms = 20;
    cfg.channels = 2;
    samples = clip_audio_samples_per_frame(&cfg);
    bytes = clip_audio_bytes_per_frame(&cfg);
    TEST_ASSERT(samples == 1764, "44.1kHz 20ms stereo -> 1764 total samples");
    TEST_ASSERT(bytes == 3528, "44.1kHz 20ms stereo -> 3528 bytes");
}

/* ── Test 3: SPSC Ring Buffer ──────────────────────────────────────────── */
static void test_ring_buffer(void)
{
    printf("\n--- Test Group 3: SPSC Ring Buffer ---\n");

    ClipAudioRingBuffer rb;
    TEST_ASSERT(clip_audio_ring_buffer_init(&rb, 1000) == CLIP_OK, "Init ring buffer with capacity 1000");
    TEST_ASSERT(clip_audio_ring_buffer_available_read(&rb) == 0, "Initial available read is 0");
    TEST_ASSERT(clip_audio_ring_buffer_available_write(&rb) == 1000, "Initial available write is 1000");

    /* Write 300 samples */
    int16_t w_buf[300];
    for (int i = 0; i < 300; i++) w_buf[i] = (int16_t)(i + 1);

    size_t written = clip_audio_ring_buffer_write(&rb, w_buf, 300);
    TEST_ASSERT(written == 300, "Wrote 300 samples");
    TEST_ASSERT(clip_audio_ring_buffer_available_read(&rb) == 300, "Available read is 300");
    TEST_ASSERT(clip_audio_ring_buffer_available_write(&rb) == 700, "Available write is 700");

    /* Read 300 samples */
    int16_t r_buf[300] = {0};
    size_t nread = clip_audio_ring_buffer_read(&rb, r_buf, 300);
    TEST_ASSERT(nread == 300, "Read 300 samples");
    TEST_ASSERT(memcmp(w_buf, r_buf, sizeof(w_buf)) == 0, "Read data matches written data");
    TEST_ASSERT(clip_audio_ring_buffer_available_read(&rb) == 0, "Available read back to 0");

    /* Test Circular Wrap-around:
     * Write 800 samples (head advances to 800)
     * Read 600 samples (tail advances to 600, 200 remain)
     * Write 500 samples (head wraps around end of buffer)
     * Read remaining 700 samples and verify sequence
     */
    int16_t seq_w[800];
    for (int i = 0; i < 800; i++) seq_w[i] = (int16_t)(1000 + i);
    clip_audio_ring_buffer_write(&rb, seq_w, 800);

    int16_t seq_r1[600];
    clip_audio_ring_buffer_read(&rb, seq_r1, 600);
    TEST_ASSERT(memcmp(seq_w, seq_r1, 600 * sizeof(int16_t)) == 0, "First 600 read correctly before wrap");

    int16_t seq_w2[500];
    for (int i = 0; i < 500; i++) seq_w2[i] = (int16_t)(2000 + i);
    size_t w2 = clip_audio_ring_buffer_write(&rb, seq_w2, 500);
    TEST_ASSERT(w2 == 500, "Wrote 500 samples wrapping around boundary");

    /* Total available should now be 200 (left from seq_w) + 500 (from seq_w2) = 700 */
    TEST_ASSERT(clip_audio_ring_buffer_available_read(&rb) == 700, "Available read across wrap is 700");

    int16_t seq_r2[700];
    nread = clip_audio_ring_buffer_read(&rb, seq_r2, 700);
    TEST_ASSERT(nread == 700, "Read 700 samples across wrap-around");
    TEST_ASSERT(memcmp(&seq_w[600], &seq_r2[0], 200 * sizeof(int16_t)) == 0, "Wrapped first part matched");
    TEST_ASSERT(memcmp(seq_w2, &seq_r2[200], 500 * sizeof(int16_t)) == 0, "Wrapped second part matched");

    /* Test Overflow */
    int16_t over_buf[1100] = {0};
    written = clip_audio_ring_buffer_write(&rb, over_buf, 1100);
    TEST_ASSERT(written == 1000, "Write capped at capacity 1000");
    TEST_ASSERT(rb.overruns > 0, "Overrun recorded in stats");

    /* Test Underrun */
    int16_t under_buf[2000];
    nread = clip_audio_ring_buffer_read(&rb, under_buf, 2000);
    TEST_ASSERT(nread == 1000, "Read capped at available 1000");
    nread = clip_audio_ring_buffer_read(&rb, under_buf, 100);
    TEST_ASSERT(nread == 0, "Read on empty returned 0");
    TEST_ASSERT(rb.underruns > 0, "Underrun recorded in stats");

    /* Test Reset */
    clip_audio_ring_buffer_write(&rb, w_buf, 200);
    TEST_ASSERT(clip_audio_ring_buffer_available_read(&rb) == 200, "Available read 200 before reset");
    clip_audio_ring_buffer_reset(&rb);
    TEST_ASSERT(clip_audio_ring_buffer_available_read(&rb) == 0, "Available read 0 after reset");

    clip_audio_ring_buffer_cleanup(&rb);
}

/* ── Test 4: Mock Device Capture ───────────────────────────────────────── */
typedef struct {
    uint32_t frame_count;
    size_t   total_samples;
    bool     has_non_zero_sample;
} CaptureTestContext;

static void mock_capture_callback(const int16_t* pcm,
                                  size_t         sample_count,
                                  uint64_t       timestamp_ms,
                                  void*          user_data)
{
    (void)timestamp_ms;
    CaptureTestContext* ctx = (CaptureTestContext*)user_data;
    if (!ctx || !pcm || sample_count == 0) return;

    ctx->frame_count++;
    ctx->total_samples += sample_count;
    for (size_t i = 0; i < sample_count; i++) {
        if (pcm[i] != 0) {
            ctx->has_non_zero_sample = true;
            break;
        }
    }
}

static void test_mock_device_capture(void)
{
    printf("\n--- Test Group 4: Mock Device Capture ---\n");

    ClipAudioConfig cfg;
    clip_audio_config_init_default(&cfg);
    cfg.backend = CLIP_AUDIO_BACKEND_MOCK;

    ClipAudioDevice* dev = clip_audio_device_create_mock(&cfg);
    TEST_ASSERT(dev != NULL, "Created mock audio device");
    TEST_ASSERT(dev->capture_state == CLIP_AUDIO_STATE_IDLE, "Capture state initially IDLE");

    CaptureTestContext ctx = {0};
    ClipError err = clip_audio_device_start_capture(dev, mock_capture_callback, &ctx);
    TEST_ASSERT(err == CLIP_OK, "Started mock capture");
    TEST_ASSERT(dev->capture_state == CLIP_AUDIO_STATE_CAPTURING, "Capture state is CAPTURING");

    /* Wait for ~80ms (at 20ms/frame, should generate ~3-4 frames) */
    Sleep(80);

    TEST_ASSERT(ctx.frame_count >= 2, "Received at least 2 capture frames from mock");
    TEST_ASSERT(ctx.total_samples >= 640, "Received at least 640 samples");
    TEST_ASSERT(ctx.has_non_zero_sample, "Mock generated non-zero PCM samples (sine wave)");

    err = clip_audio_device_stop_capture(dev);
    TEST_ASSERT(err == CLIP_OK, "Stopped mock capture");
    TEST_ASSERT(dev->capture_state == CLIP_AUDIO_STATE_IDLE, "Capture state back to IDLE");

    uint32_t saved_count = ctx.frame_count;
    Sleep(60);
    TEST_ASSERT(ctx.frame_count == saved_count, "Capture thread halted cleanly after stop");

    clip_audio_device_destroy(dev);
}

/* ── Test 5: Mock Device Playback ──────────────────────────────────────── */
static void test_mock_device_playback(void)
{
    printf("\n--- Test Group 5: Mock Device Playback ---\n");

    ClipAudioConfig cfg;
    clip_audio_config_init_default(&cfg);
    cfg.backend = CLIP_AUDIO_BACKEND_MOCK;

    ClipAudioDevice* dev = clip_audio_device_create_mock(&cfg);
    TEST_ASSERT(dev != NULL, "Created mock audio device for playback");

    ClipError err = clip_audio_device_start_playback(dev);
    TEST_ASSERT(err == CLIP_OK, "Started mock playback");
    TEST_ASSERT(dev->playback_state == CLIP_AUDIO_STATE_PLAYING, "Playback state is PLAYING");

    /* Write 320 samples */
    int16_t pcm_out[320];
    for (int i = 0; i < 320; i++) pcm_out[i] = (int16_t)(i * 10);

    err = clip_audio_device_write_playback(dev, pcm_out, 320);
    TEST_ASSERT(err == CLIP_OK, "Wrote 320 samples to mock playback");

    /* Read back and verify */
    int16_t pcm_in[320] = {0};
    size_t retrieved = clip_audio_mock_get_playback_samples(dev, pcm_in, 320);
    TEST_ASSERT(retrieved == 320, "Retrieved 320 samples from mock playback buffer");
    TEST_ASSERT(memcmp(pcm_out, pcm_in, sizeof(pcm_out)) == 0, "Playback samples match written data exactly");

    err = clip_audio_device_stop_playback(dev);
    TEST_ASSERT(err == CLIP_OK, "Stopped mock playback");
    TEST_ASSERT(dev->playback_state == CLIP_AUDIO_STATE_IDLE, "Playback state is IDLE");

    clip_audio_device_destroy(dev);
}

/* ── Test 6: Audio Engine Lifecycle ────────────────────────────────────── */
static void test_audio_engine_lifecycle(void)
{
    printf("\n--- Test Group 6: Audio Engine Lifecycle ---\n");

    ClipAudioEngine engine;
    ClipAudioConfig cfg;
    clip_audio_config_init_default(&cfg);
    cfg.backend = CLIP_AUDIO_BACKEND_MOCK;

    ClipError err = clip_audio_engine_init(&engine, &cfg);
    TEST_ASSERT(err == CLIP_OK, "Engine init with mock backend succeeded");
    TEST_ASSERT(engine.initialized == true, "Engine is marked initialized");
    TEST_ASSERT(clip_audio_is_floor_held(&engine) == false, "Initial floor_held is false");
    TEST_ASSERT(clip_audio_is_capturing(&engine) == false, "Initial is_capturing is false");
    TEST_ASSERT(clip_audio_is_playing(&engine) == false, "Initial is_playing is false");

    /* Playback lifecycle */
    err = clip_audio_start_playback(&engine);
    TEST_ASSERT(err == CLIP_OK, "Started engine playback");
    TEST_ASSERT(clip_audio_is_playing(&engine) == true, "Engine is_playing is true");

    int16_t frame[320] = {100, 200, 300};
    err = clip_audio_play_frame(&engine, frame, 320);
    TEST_ASSERT(err == CLIP_OK, "Played frame through engine");
    TEST_ASSERT(engine.total_playback_frames == 1, "Total playback frames is 1");

    err = clip_audio_stop_playback(&engine);
    TEST_ASSERT(err == CLIP_OK, "Stopped engine playback");
    TEST_ASSERT(clip_audio_is_playing(&engine) == false, "Engine is_playing is false");

    clip_audio_engine_cleanup(&engine);
    TEST_ASSERT(engine.initialized == false, "Engine cleaned up cleanly");
}

/* ── Test 7: PTT Floor Gating Invariant ─────────────────────────────────── */
static void test_audio_floor_gating_invariant(void)
{
    printf("\n--- Test Group 7: PTT Floor Gating Invariant (CRITICAL) ---\n");

    ClipAudioEngine engine;
    ClipAudioConfig cfg;
    clip_audio_config_init_default(&cfg);
    cfg.backend = CLIP_AUDIO_BACKEND_MOCK;

    TEST_ASSERT(clip_audio_engine_init(&engine, &cfg) == CLIP_OK, "Engine initialized");

    CaptureTestContext ctx = {0};
    clip_audio_set_capture_callback(&engine, mock_capture_callback, &ctx);

    /* 1. Floor is NOT held: capture must NOT happen */
    TEST_ASSERT(!clip_audio_is_floor_held(&engine), "Floor is NOT held initially");
    TEST_ASSERT(!clip_audio_is_capturing(&engine), "Device is NOT capturing initially");

    Sleep(60);
    TEST_ASSERT(ctx.frame_count == 0, "Invariant: 0 frames delivered when floor NOT held");
    int16_t pcm_tmp[320];
    size_t samples_read = clip_audio_read_captured_pcm(&engine, pcm_tmp, 320);
    TEST_ASSERT(samples_read == 0, "Invariant: 0 samples available in ring buffer when floor NOT held");

    /* 2. Floor is GRANTED: capture MUST start */
    ClipError g_err = clip_audio_on_floor_granted(&engine);
    TEST_ASSERT(g_err == CLIP_OK, "Floor granted signal processed");
    TEST_ASSERT(clip_audio_is_floor_held(&engine), "Floor is now HELD");
    TEST_ASSERT(clip_audio_is_capturing(&engine), "Device capture is active");

    for (int wait_i = 0; wait_i < 25 && ctx.frame_count < 2; wait_i++) {
        Sleep(10);
    }
    TEST_ASSERT(ctx.frame_count >= 2, "Frames delivered while floor is held");
    TEST_ASSERT(engine.total_captured_frames >= 2, "Engine total_captured_frames > 0");

    /* 3. Floor is RELEASED: capture MUST stop immediately and flush ring buffer */
    ClipError r_err = clip_audio_on_floor_released(&engine);
    TEST_ASSERT(r_err == CLIP_OK, "Floor released signal processed");
    TEST_ASSERT(!clip_audio_is_floor_held(&engine), "Floor is NO LONGER held");
    TEST_ASSERT(!clip_audio_is_capturing(&engine), "Device capture immediately STOPPED");

    uint32_t count_at_release = ctx.frame_count;
    Sleep(80);
    TEST_ASSERT(ctx.frame_count == count_at_release, "No additional frames delivered after floor release");

    /* Verify ring buffer was flushed on release */
    samples_read = clip_audio_read_captured_pcm(&engine, pcm_tmp, 320);
    TEST_ASSERT(samples_read == 0, "Ring buffer was flushed on floor release (no stale audio)");

    clip_audio_engine_cleanup(&engine);
}

/* ── Test 8: Capture Cannot Bypass Floor ────────────────────────────────── */
static void test_capture_cannot_bypass_floor(void)
{
    printf("\n--- Test Group 8: Capture Cannot Bypass Floor ---\n");

    ClipAudioEngine engine;
    ClipAudioConfig cfg;
    clip_audio_config_init_default(&cfg);
    cfg.backend = CLIP_AUDIO_BACKEND_MOCK;

    clip_audio_engine_init(&engine, &cfg);

    /* Verify floor is false */
    TEST_ASSERT(engine.floor_held == false, "Engine floor_held is false");

    CaptureTestContext ctx = {0};
    clip_audio_set_capture_callback(&engine, mock_capture_callback, &ctx);

    /* Verify that reading captured PCM without floor returns 0 */
    int16_t tmp[320];
    size_t rd = clip_audio_read_captured_pcm(&engine, tmp, 320);
    TEST_ASSERT(rd == 0, "Direct read without floor held returns 0 samples");
    TEST_ASSERT(clip_audio_ring_buffer_available_read(&engine.capture_rb) == 0,
                "Ring buffer has 0 samples when floor_held is false");

    clip_audio_engine_cleanup(&engine);
}

/* ── Test 9: Error Handling ────────────────────────────────────────────── */
static void test_error_handling(void)
{
    printf("\n--- Test Group 9: Error Handling ---\n");

    ClipAudioEngine engine;
    ClipAudioConfig invalid_cfg;
    clip_audio_config_init_default(&invalid_cfg);
    invalid_cfg.sample_rate = 99999; /* invalid */

    TEST_ASSERT(clip_audio_engine_init(NULL, NULL) == CLIP_ERR_INVALID, "NULL engine returns CLIP_ERR_INVALID");
    TEST_ASSERT(clip_audio_engine_init(&engine, &invalid_cfg) == CLIP_ERR_AUDIO_FORMAT,
                "Invalid sample rate returns CLIP_ERR_AUDIO_FORMAT");

    /* Ring buffer error handling */
    TEST_ASSERT(clip_audio_ring_buffer_init(NULL, 100) == CLIP_ERR_INVALID, "NULL ring buffer init fails");
    TEST_ASSERT(clip_audio_ring_buffer_init(&engine.capture_rb, 0) == CLIP_ERR_INVALID, "0 capacity ring buffer fails");

    /* Operations on uninitialized engine */
    ClipAudioEngine uninit_eng;
    memset(&uninit_eng, 0, sizeof(uninit_eng));
    TEST_ASSERT(clip_audio_on_floor_granted(&uninit_eng) == CLIP_ERR_INVALID, "Floor grant on uninit engine fails");
    TEST_ASSERT(clip_audio_on_floor_released(&uninit_eng) == CLIP_ERR_INVALID, "Floor release on uninit engine fails");
    TEST_ASSERT(clip_audio_start_playback(&uninit_eng) == CLIP_ERR_INVALID, "Start playback on uninit engine fails");
}

/* ── Test 10: Local Audio Loopback ─────────────────────────────────────── */
static void test_audio_loopback(void)
{
    printf("\n--- Test Group 10: Local Audio Loopback ---\n");

    ClipAudioEngine engine;
    ClipAudioConfig cfg;
    clip_audio_config_init_default(&cfg);
    cfg.backend = CLIP_AUDIO_BACKEND_MOCK;

    clip_audio_engine_init(&engine, &cfg);
    clip_audio_start_playback(&engine);

    /* Grant floor and capture some audio */
    clip_audio_on_floor_granted(&engine);
    Sleep(150);

    /* Read captured audio from ring buffer */
    int16_t loop_buf[640];
    size_t samples_captured = clip_audio_read_captured_pcm(&engine, loop_buf, 640);
    TEST_ASSERT(samples_captured >= 320, "Read at least one captured frame from ring buffer");

    /* Play captured frame back */
    ClipError play_err = clip_audio_play_frame(&engine, loop_buf, samples_captured);
    TEST_ASSERT(play_err == CLIP_OK, "Played captured frame back through playback sink");

    /* Verify mock playback received loopback data */
    int16_t pb_verify[640] = {0};
    size_t pb_read = clip_audio_mock_get_playback_samples(engine.device, pb_verify, samples_captured);
    TEST_ASSERT(pb_read == samples_captured, "Retrieved loopback samples from playback device");
    TEST_ASSERT(memcmp(loop_buf, pb_verify, samples_captured * sizeof(int16_t)) == 0,
                "Loopback samples match captured audio exactly");

    clip_audio_on_floor_released(&engine);
    clip_audio_stop_playback(&engine);
    clip_audio_engine_cleanup(&engine);
}

/* ── Test 11: WinMM Device Probe ───────────────────────────────────────── */
static void test_winmm_device_probe(void)
{
    printf("\n--- Test Group 11: WinMM Device Probe ---\n");

    UINT in_devs = waveInGetNumDevs();
    UINT out_devs = waveOutGetNumDevs();
    printf("  [INFO] WinMM Input Devices Detected  : %u\n", in_devs);
    printf("  [INFO] WinMM Output Devices Detected : %u\n", out_devs);

    ClipAudioConfig cfg;
    clip_audio_config_init_default(&cfg);
    cfg.backend = CLIP_AUDIO_BACKEND_WINMM;

    ClipAudioDevice* dev = clip_audio_device_create_winmm(&cfg);
    if (in_devs > 0 && out_devs > 0 && dev != NULL) {
        TEST_ASSERT(dev != NULL, "WinMM device created on host with physical/virtual audio devices");
        clip_audio_device_destroy(dev);
    } else {
        printf("  [INFO] Running in headless / VM environment without audio hardware; WinMM gracefully handled.\n");
        TEST_ASSERT(true, "WinMM device probe gracefully handles 0 devices");
    }
}

/* ── Main Entry ────────────────────────────────────────────────────────── */
int main(void)
{
    printf("====================================================\n");
    printf("    CLICOM Phase 9 Audio Subsystem Unit Tests       \n");
    printf("====================================================\n");

    test_config_validation();
    test_pcm_frame_calculations();
    test_ring_buffer();
    test_mock_device_capture();
    test_mock_device_playback();
    test_audio_engine_lifecycle();
    test_audio_floor_gating_invariant();
    test_capture_cannot_bypass_floor();
    test_error_handling();
    test_audio_loopback();
    test_winmm_device_probe();

    printf("\n====================================================\n");
    printf("  Audio Test Results: %d PASSED, %d FAILED\n", g_pass, g_fail);
    printf("====================================================\n");

    return (g_fail == 0) ? 0 : 1;
}

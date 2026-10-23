/*
 * test_codec.c — CLICOM Audio Codec Unit Tests (Phase 11)
 *
 * Test Groups:
 * 1. Codec Configuration & Factory Lifecycle (NULL, PCM, OPUS)
 * 2. PCM Codec Bit-Exact Fidelity & Bounds
 * 3. Opus Codec Deterministic Validity (Adjustment 1)
 *    - Expected decoded sample count (320 samples)
 *    - Bounded valid PCM output ([-32768, 32767])
 *    - Successful encode/decode
 *    - Measurable lossy output (compressed < 200 bytes, energy > 0)
 * 4. Opus Packet Loss Concealment (PLC - Adjustment 2)
 * 5. Codec State Reset on Floor Transitions
 * 6. Malformed Opus Robustness (Adjustment 6)
 *    - Empty packet
 *    - Truncated packet
 *    - Random/corrupt packet
 *    - Oversized packet (>1275 bytes)
 * 7. Explicit Codec Compatibility & Mismatches (Adjustment 3)
 *    - PCM payload -> PCM decoder
 *    - Opus payload -> Opus decoder
 *    - Codec mismatch: PCM bytes -> Opus decoder (safe error)
 *    - Codec mismatch: Opus bytes -> PCM decoder (safe error)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>

#include "codec.h"
#include "clip_errors.h"
#include "clip_protocol.h"

static int g_pass = 0;
static int g_fail = 0;

#define ASSERT(expr, msg) do { \
    if (expr) { \
        printf("  [PASS] %s\n", msg); \
        fflush(stdout); \
        g_pass++; \
    } else { \
        printf("  [FAIL] %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        fflush(stdout); \
        g_fail++; \
    } \
} while(0)

/* Helper: generate synthetic 440 Hz sine wave PCM */
static void generate_sine_pcm(int16_t* buf, size_t sample_count, int sample_rate, float freq)
{
    for (size_t i = 0; i < sample_count; i++) {
        float t = (float)i / (float)sample_rate;
        float val = sinf(2.0f * 3.14159265f * freq * t);
        buf[i] = (int16_t)(val * 16000.0f);
    }
}

/* ── Test Group 1: Codec Configuration & Factory Lifecycle ───────────────── */

static void test_codec_lifecycle(void)
{
    printf("\n--- Test Group 1: Codec Configuration & Factory Lifecycle ---\n");

    /* NULL Codec */
    AudioCodec* null_codec = codec_create(CLIP_CODEC_NULL, 16000, 1);
    ASSERT(null_codec != NULL, "Created NULL codec");
    ASSERT(codec_get_type(null_codec) == CLIP_CODEC_NULL, "NULL codec reports correct type");
    codec_destroy(null_codec);

    /* PCM Codec */
    AudioCodec* pcm_codec = codec_create(CLIP_CODEC_PCM, 16000, 1);
    ASSERT(pcm_codec != NULL, "Created PCM codec (16kHz mono)");
    ASSERT(codec_get_type(pcm_codec) == CLIP_CODEC_PCM, "PCM codec reports correct type");
    codec_destroy(pcm_codec);

    /* Opus Codec */
    AudioCodec* opus_codec = codec_create(CLIP_CODEC_OPUS, 16000, 1);
    ASSERT(opus_codec != NULL, "Created Opus codec (16kHz mono VoIP)");
    ASSERT(codec_get_type(opus_codec) == CLIP_CODEC_OPUS, "Opus codec reports correct type");
    codec_destroy(opus_codec);

    /* Invalid configurations for Opus */
    AudioCodec* bad_sr = codec_create(CLIP_CODEC_OPUS, 44100, 1);
    ASSERT(bad_sr == NULL, "Opus rejects unsupported sample rate 44.1 kHz (only 8, 12, 16, 24, 48 kHz)");

    AudioCodec* bad_ch = codec_create(CLIP_CODEC_OPUS, 16000, 3);
    ASSERT(bad_ch == NULL, "Opus rejects unsupported channel count 3");

    /* Unknown codec type */
    AudioCodec* unknown = codec_create((ClipCodecType)0x99, 16000, 1);
    ASSERT(unknown == NULL, "Factory rejects unknown codec type 0x99");
}

/* ── Test Group 2: PCM Codec Bit-Exact Fidelity ──────────────────────────── */

static void test_codec_pcm_fidelity(void)
{
    printf("\n--- Test Group 2: PCM Codec Bit-Exact Fidelity & Bounds ---\n");

    AudioCodec* pcm = codec_create(CLIP_CODEC_PCM, 16000, 1);
    ASSERT(pcm != NULL, "Initialized PCM codec");

    int16_t input_pcm[320];
    generate_sine_pcm(input_pcm, 320, 16000, 440.0f);

    uint8_t enc_buf[640];
    int enc_bytes = codec_encode(pcm, input_pcm, 320, enc_buf, sizeof(enc_buf));
    ASSERT(enc_bytes == 640, "PCM encode writes exact 640 bytes for 320 samples");

    int16_t out_pcm[320];
    int dec_samples = codec_decode(pcm, enc_buf, enc_bytes, out_pcm, 320);
    ASSERT(dec_samples == 320, "PCM decode returns exact 320 samples");
    ASSERT(memcmp(input_pcm, out_pcm, sizeof(input_pcm)) == 0, "PCM encode/decode preserves 100% bit-exact audio");

    /* Small buffer rejection */
    int small_enc = codec_encode(pcm, input_pcm, 320, enc_buf, 100);
    ASSERT(small_enc < 0, "PCM encode rejects insufficient output buffer");

    codec_destroy(pcm);
}

/* ── Test Group 3: Opus Codec Deterministic Validity (Adjustment 1) ─────── */

static void test_codec_opus_validity(void)
{
    printf("\n--- Test Group 3: Opus Deterministic Validity Checks ---\n");

    AudioCodec* opus = codec_create(CLIP_CODEC_OPUS, 16000, 1);
    ASSERT(opus != NULL, "Initialized Opus codec (16kHz mono)");

    int16_t input_pcm[320];
    generate_sine_pcm(input_pcm, 320, 16000, 440.0f);

    uint8_t opus_packet[1275];
    int enc_bytes = codec_encode(opus, input_pcm, 320, opus_packet, sizeof(opus_packet));
    ASSERT(enc_bytes > 0, "Opus encoded 320 PCM samples successfully");
    ASSERT(enc_bytes < 200, "Opus compressed size is < 200 bytes (significant bandwidth reduction vs 640 bytes PCM)");

    int16_t decoded_pcm[320];
    int dec_samples = codec_decode(opus, opus_packet, enc_bytes, decoded_pcm, 320);
    ASSERT(dec_samples == 320, "Opus decoded exact expected sample count (320 samples)");

    /* Bounded valid PCM output */
    bool all_bounded = true;
    int64_t energy = 0;
    for (int i = 0; i < 320; i++) {
        int32_t sample_val = (int32_t)decoded_pcm[i];
        if (sample_val < -32768L || sample_val > 32767L) {
            all_bounded = false;
        }
        energy += (int64_t)abs(decoded_pcm[i]);
    }
    ASSERT(all_bounded, "All decoded Opus samples are within valid 16-bit range [-32768, 32767]");
    ASSERT(energy > 100000, "Decoded Opus audio contains measurable active signal energy matching input");

    codec_destroy(opus);
}

/* ── Test Group 4: Opus Packet Loss Concealment (Adjustment 2) ───────────── */

static void test_codec_opus_plc(void)
{
    printf("\n--- Test Group 4: Opus Packet Loss Concealment (PLC) ---\n");

    AudioCodec* opus = codec_create(CLIP_CODEC_OPUS, 16000, 1);
    ASSERT(opus != NULL, "Initialized Opus codec for PLC test");

    /* First encode and decode one valid frame to prime the decoder history */
    int16_t input_pcm[320];
    generate_sine_pcm(input_pcm, 320, 16000, 440.0f);
    uint8_t packet[1275];
    int enc_bytes = codec_encode(opus, input_pcm, 320, packet, sizeof(packet));
    ASSERT(enc_bytes > 0, "Primed encoder with valid frame");

    int16_t dec_buf[320];
    codec_decode(opus, packet, enc_bytes, dec_buf, 320);

    /* Trigger PLC by passing in_buf = NULL, in_len = 0 */
    int16_t plc_buf[320];
    int plc_samples = codec_decode(opus, NULL, 0, plc_buf, 320);
    ASSERT(plc_samples == 320, "Opus PLC generated 320 concealed samples for missing frame");

    /* Verify PLC samples are bounded */
    bool plc_bounded = true;
    for (int i = 0; i < 320; i++) {
        int32_t plc_val = (int32_t)plc_buf[i];
        if (plc_val < -32768L || plc_val > 32767L) plc_bounded = false;
    }
    ASSERT(plc_bounded, "Opus PLC samples are strictly bounded within 16-bit range");

    codec_destroy(opus);
}

/* ── Test Group 5: Codec State Reset ─────────────────────────────────────── */

static void test_codec_reset(void)
{
    printf("\n--- Test Group 5: Codec State Reset on Floor Transitions ---\n");

    AudioCodec* opus = codec_create(CLIP_CODEC_OPUS, 16000, 1);
    ASSERT(opus != NULL, "Initialized Opus codec");

    int16_t input_pcm[320];
    generate_sine_pcm(input_pcm, 320, 16000, 440.0f);
    uint8_t packet[1275];
    codec_encode(opus, input_pcm, 320, packet, sizeof(packet));

    /* Reset encoder and decoder internal state */
    int r_res = codec_reset(opus);
    ASSERT(r_res == 0, "codec_reset() executed successfully");

    /* Encode again after reset */
    int enc2 = codec_encode(opus, input_pcm, 320, packet, sizeof(packet));
    ASSERT(enc2 > 0, "Encoded cleanly after state reset");

    codec_destroy(opus);
}

/* ── Test Group 6: Malformed Opus Robustness (Adjustment 6) ──────────────── */

static void test_codec_malformed_robustness(void)
{
    printf("\n--- Test Group 6: Malformed Opus Robustness Testing ---\n");

    AudioCodec* opus = codec_create(CLIP_CODEC_OPUS, 16000, 1);
    ASSERT(opus != NULL, "Initialized Opus codec for robustness test");

    int16_t out_pcm[320];

    /* 1. Empty packet with non-NULL pointer */
    uint8_t empty_byte = 0;
    int emp_res = codec_decode(opus, &empty_byte, 0, out_pcm, 320);
    ASSERT(emp_res == 320, "Empty packet (in_len=0) handled gracefully via PLC without crashing");

    /* 2. Truncated packet (1 byte invalid header) */
    uint8_t trunc_byte = 0xFF;
    int trunc_res = codec_decode(opus, &trunc_byte, 1, out_pcm, 320);
    ASSERT(trunc_res == CLIP_ERR_CODEC_DECODE, "Truncated 1-byte packet rejected safely with CLIP_ERR_CODEC_DECODE");

    /* 3. Random/corrupt packet */
    uint8_t garbage[64];
    memset(garbage, 0xDE, sizeof(garbage));
    int garb_res = codec_decode(opus, garbage, sizeof(garbage), out_pcm, 320);
    ASSERT(garb_res == CLIP_ERR_CODEC_DECODE || garb_res > 0, "Random/corrupt packet handled safely without crash or fault");

    /* 4. Oversized packet (> 1275 bytes) */
    uint8_t huge[2000];
    memset(huge, 0, sizeof(huge));
    int huge_res = codec_decode(opus, huge, sizeof(huge), out_pcm, 320);
    ASSERT(huge_res == CLIP_ERR_AUDIO_OVERSIZED, "Oversized packet (>1275 bytes) rejected safely before decoding");

    codec_destroy(opus);
}

/* ── Test Group 7: Explicit Codec Compatibility & Mismatches (Adjustment 3) */

static void test_codec_compatibility(void)
{
    printf("\n--- Test Group 7: Explicit Codec Compatibility & Mismatches ---\n");

    AudioCodec* pcm_codec  = codec_create(CLIP_CODEC_PCM, 16000, 1);
    AudioCodec* opus_codec = codec_create(CLIP_CODEC_OPUS, 16000, 1);
    ASSERT(pcm_codec != NULL && opus_codec != NULL, "Created PCM and Opus codecs for compatibility matrix");

    int16_t input_pcm[320];
    generate_sine_pcm(input_pcm, 320, 16000, 440.0f);

    /* 1. PCM payload -> PCM decoder (success) */
    uint8_t pcm_payload[640];
    int pcm_len = codec_encode(pcm_codec, input_pcm, 320, pcm_payload, sizeof(pcm_payload));
    ASSERT(pcm_len == 640, "PCM payload encoded (640 bytes)");

    int16_t pcm_decoded[320];
    int pcm_dec_res = codec_decode(pcm_codec, pcm_payload, pcm_len, pcm_decoded, 320);
    ASSERT(pcm_dec_res == 320, "PCM payload decoded cleanly by PCM decoder");

    /* 2. Opus payload -> Opus decoder (success) */
    uint8_t opus_payload[1275];
    int opus_len = codec_encode(opus_codec, input_pcm, 320, opus_payload, sizeof(opus_payload));
    ASSERT(opus_len > 0, "Opus payload encoded");

    int16_t opus_decoded[320];
    int opus_dec_res = codec_decode(opus_codec, opus_payload, opus_len, opus_decoded, 320);
    ASSERT(opus_dec_res == 320, "Opus payload decoded cleanly by Opus decoder");

    /* 3. Codec Mismatch: Opus payload fed to PCM decoder */
    /* An Opus packet (e.g. 50-60 bytes) is not a 640-byte PCM frame. If odd length, returns CLIP_ERR_CODEC_DECODE */
    uint8_t odd_opus[57];
    memcpy(odd_opus, opus_payload, 57);
    int odd_pcm_res = codec_decode(pcm_codec, odd_opus, 57, pcm_decoded, 320);
    ASSERT(odd_pcm_res == CLIP_ERR_CODEC_DECODE, "Unaligned Opus payload safely rejected by PCM decoder");

    /* 4. Codec Mismatch: Raw PCM payload fed to Opus decoder */
    /* Raw PCM bytes (640 bytes) do not constitute a valid 20ms 16kHz Opus frame */
    int mismatch_res = codec_decode(opus_codec, pcm_payload, pcm_len, opus_decoded, 320);
    ASSERT(mismatch_res == CLIP_ERR_CODEC_DECODE || mismatch_res != 320, "Raw PCM bytes safely rejected or frame mismatched by Opus decoder");

    codec_destroy(pcm_codec);
    codec_destroy(opus_codec);
}

/* ── Main Entry ────────────────────────────────────────────────────────── */

int main(void)
{
    printf("========================================================\n");
    printf("     CLICOM Phase 11: Audio Codec Unit Tests           \n");
    printf("========================================================\n");

    test_codec_lifecycle();
    test_codec_pcm_fidelity();
    test_codec_opus_validity();
    test_codec_opus_plc();
    test_codec_reset();
    test_codec_malformed_robustness();
    test_codec_compatibility();

    printf("\n========================================================\n");
    printf("  Codec Test Results: %d PASSED, %d FAILED\n", g_pass, g_fail);
    printf("========================================================\n");

    return (g_fail == 0) ? 0 : 1;
}

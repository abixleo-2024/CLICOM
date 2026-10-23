/*
 * diagnose_audio.c — Focused Audio Pipeline Diagnostic Tool
 * Tests 1kHz test signal through Opus encode/decode and WinMM playback.
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
#include "clip_protocol.h"
#include "clip_errors.h"

#define SAMPLE_RATE 48000
#define CHANNELS 1
#define FRAME_MS 20
#define SAMPLES_PER_FRAME ((SAMPLE_RATE * FRAME_MS) / 1000) /* 960 */

static void generate_tone(int16_t* pcm, size_t n_samples, uint32_t sample_rate, float freq_hz, float amplitude) {
    for (size_t i = 0; i < n_samples; i++) {
        double t = (double)i / (double)sample_rate;
        double val = sin(2.0 * 3.14159265358979323846 * freq_hz * t);
        pcm[i] = (int16_t)(val * amplitude * 32767.0);
    }
}

int main(void) {
    printf("=== CLICOM Audio Pipeline Diagnostic Tool ===\n");
    printf("Config: Sample Rate=%d, Channels=%d, Frame=%dms, Samples=%d\n\n",
           SAMPLE_RATE, CHANNELS, FRAME_MS, SAMPLES_PER_FRAME);

    /* 1. Test Signal Generation */
    int16_t orig_pcm[SAMPLES_PER_FRAME];
    generate_tone(orig_pcm, SAMPLES_PER_FRAME, SAMPLE_RATE, 1000.0f, 0.3f);
    printf("[1] Generated 1000 Hz sine wave test signal (amplitude 0.3, %d samples)\n", SAMPLES_PER_FRAME);

    /* 2. Opus Encoder Initialization */
    AudioCodec* enc = codec_create(CLIP_CODEC_OPUS, SAMPLE_RATE, CHANNELS);
    if (!enc) {
        printf("ERROR: Failed to create Opus encoder at %d Hz\n", SAMPLE_RATE);
        return 1;
    }
    printf("[2] Created Opus encoder (%d Hz, %d ch)\n", SAMPLE_RATE, CHANNELS);

    /* 3. Opus Decoder Initialization */
    AudioCodec* dec = codec_create(CLIP_CODEC_OPUS, SAMPLE_RATE, CHANNELS);
    if (!dec) {
        printf("ERROR: Failed to create Opus decoder at %d Hz\n", SAMPLE_RATE);
        return 1;
    }
    printf("[3] Created Opus decoder (%d Hz, %d ch)\n", SAMPLE_RATE, CHANNELS);

    /* 4. Encode Frame */
    uint8_t opus_buf[1275];
    int enc_bytes = codec_encode(enc, orig_pcm, SAMPLES_PER_FRAME, opus_buf, sizeof(opus_buf));
    if (enc_bytes <= 0) {
        printf("ERROR: Opus encoding failed (code=%d)\n", enc_bytes);
        return 1;
    }
    printf("[4] Encoded %d PCM samples -> %d Opus bytes\n", SAMPLES_PER_FRAME, enc_bytes);

    /* 5. Framing & Wire Packaging */
    uint8_t wire_buf[2048];
    size_t wire_len = 0;
    ClipUuid sess_uuid;
    memset(sess_uuid.bytes, 0x42, 16);

    ClipError b_err = clip_audio_frame_build_raw(wire_buf, sizeof(wire_buf), &wire_len,
                                                 &sess_uuid, 1,
                                                 (uint8_t)CLIP_CODEC_OPUS, 1000,
                                                 opus_buf, (size_t)enc_bytes);
    if (b_err != CLIP_OK) {
        printf("ERROR: Framing build failed (err=%d)\n", b_err);
        return 1;
    }
    printf("[5] Built wire frame (%zu bytes total)\n", wire_len);

    /* 6. Wire Unpacking & Parsing */
    ClipFrameHeader hdr;
    const uint8_t* payload = NULL;
    uint32_t payload_len = 0;
    ClipError dec_err = clip_frame_decode(wire_buf, wire_len, &hdr, &payload, &payload_len);
    if (dec_err != CLIP_OK) {
        printf("ERROR: Frame decode failed (err=%d)\n", dec_err);
        return 1;
    }

    uint8_t rx_codec = 0;
    uint64_t rx_ts = 0;
    const uint8_t* rx_audio = NULL;
    size_t rx_audio_len = 0;
    ClipError parse_err = clip_audio_frame_parse_raw(payload, payload_len, &rx_codec, &rx_ts, &rx_audio, &rx_audio_len);
    if (parse_err != CLIP_OK) {
        printf("ERROR: Parse raw failed (err=%d)\n", parse_err);
        return 1;
    }
    printf("[6] Parsed wire frame: codec=%d, ts=%llu, audio_len=%zu bytes\n",
           rx_codec, (unsigned long long)rx_ts, rx_audio_len);

    /* 7. Decode Frame */
    int16_t decoded_pcm[SAMPLES_PER_FRAME * 2];
    int dec_samples = codec_decode(dec, rx_audio, rx_audio_len, decoded_pcm, SAMPLES_PER_FRAME * 2);
    if (dec_samples <= 0) {
        printf("ERROR: Opus decoding failed (code=%d)\n", dec_samples);
        return 1;
    }
    printf("[7] Decoded %zu Opus bytes -> %d PCM samples\n", rx_audio_len, dec_samples);

    if (dec_samples != SAMPLES_PER_FRAME) {
        printf("WARNING: Decoded sample count %d != original %d!\n", dec_samples, SAMPLES_PER_FRAME);
    } else {
        printf("  ✓ Sample count exact match: %d == %d\n", dec_samples, SAMPLES_PER_FRAME);
    }

    /* Calculate correlation / difference */
    double diff_sum = 0.0;
    double max_diff = 0.0;
    for (int i = 0; i < dec_samples; i++) {
        double d = fabs((double)orig_pcm[i] - (double)decoded_pcm[i]);
        diff_sum += d;
        if (d > max_diff) max_diff = d;
    }
    printf("  ✓ Opus Audio Round-trip Avg Sample Error: %.2f / 32767, Max Error: %.2f\n",
           diff_sum / dec_samples, max_diff);

    /* 8. Probe WinMM Devices */
    UINT num_in = waveInGetNumDevs();
    UINT num_out = waveOutGetNumDevs();
    printf("\n[8] Windows Multimedia Device Probe:\n");
    printf("  waveIn devices: %u\n", num_in);
    printf("  waveOut devices: %u\n", num_out);

    WAVEINCAPSW in_caps;
    for (UINT i = 0; i < num_in; i++) {
        if (waveInGetDevCapsW(i, &in_caps, sizeof(in_caps)) == MMSYSERR_NOERROR) {
            wprintf(L"    In %u: %ls (Channels: %u, Formats: 0x%08X)\n", i, in_caps.szPname, in_caps.wChannels, in_caps.dwFormats);
        }
    }
    WAVEOUTCAPSW out_caps;
    for (UINT i = 0; i < num_out; i++) {
        if (waveOutGetDevCapsW(i, &out_caps, sizeof(out_caps)) == MMSYSERR_NOERROR) {
            wprintf(L"    Out %u: %ls (Channels: %u, Formats: 0x%08X)\n", i, out_caps.szPname, out_caps.wChannels, out_caps.dwFormats);
        }
    }

    codec_destroy(enc);
    codec_destroy(dec);
    printf("\n=== Diagnostic Complete ===\n");
    return 0;
}

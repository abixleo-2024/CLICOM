/*
 * diagnose_two_clients.c — Two-client E2E voice transmission diagnostic
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>

#include "clip_types.h"
#include "clip_protocol.h"
#include "clip_errors.h"
#include "clip_log.h"
#include "clip_audio_types.h"
#include "clip_audio_device.h"
#include "clip_audio.h"
#include "codec.h"
#include "network.h"
#include "server.h"

#define TEST_PORT 17890
#define SAMPLE_RATE 48000
#define CHANNELS 1
#define FRAME_MS 20
#define SAMPLES_PER_FRAME ((SAMPLE_RATE * FRAME_MS) / 1000) /* 960 */
#define NUM_FRAMES 100 /* 2 seconds of audio */

typedef struct {
    ClipServer srv;
    HANDLE     hServerThread;
    uint16_t   port;
    char       db_path[64];
} TestServerContext;

static DWORD WINAPI test_server_thread_func(LPVOID arg) {
    TestServerContext* ctx = (TestServerContext*)arg;
    while (ctx->srv.is_running) {
        clip_server_poll(&ctx->srv, 10);
    }
    return 0;
}

static void start_test_server(TestServerContext* ctx, uint16_t port) {
    memset(ctx, 0, sizeof(TestServerContext));
    ctx->port = port;
    snprintf(ctx->db_path, sizeof(ctx->db_path), "diag_two_clients_%u.db", port);
    remove(ctx->db_path);

    ClipServerConfig cfg;
    clip_server_config_init_default(&cfg);
    cfg.port = port;
    strncpy(cfg.db_path, ctx->db_path, sizeof(cfg.db_path) - 1);
    cfg.use_tls = true;
    strncpy(cfg.cert_file, "certs/server.crt", sizeof(cfg.cert_file) - 1);
    strncpy(cfg.key_file, "certs/server.key", sizeof(cfg.key_file) - 1);

    clip_server_init(&ctx->srv, &cfg);
    clip_server_start(&ctx->srv);

    ctx->hServerThread = CreateThread(NULL, 0, test_server_thread_func, ctx, 0, NULL);
    Sleep(200);
}

static void stop_test_server(TestServerContext* ctx) {
    ctx->srv.is_running = false;
    if (ctx->hServerThread) {
        WaitForSingleObject(ctx->hServerThread, 3000);
        CloseHandle(ctx->hServerThread);
        ctx->hServerThread = NULL;
    }
    clip_server_stop(&ctx->srv);
    clip_server_cleanup(&ctx->srv);
    remove(ctx->db_path);
}

static int g_bob_frames_received = 0;
static uint64_t g_bob_last_seq = 0;
static uint64_t g_bob_last_recv_time = 0;
static int g_seq_gaps = 0;
static double g_bob_energy_sum = 0;

static void bob_audio_recv_callback(const ClipUuid* sess, uint64_t ts, const int16_t* pcm, size_t sample_count, void* udata) {
    (void)sess;
    (void)ts;
    (void)udata;
    uint64_t now = GetTickCount64();
    g_bob_frames_received++;

    double energy = 0.0;
    for (size_t i = 0; i < sample_count; i++) {
        energy += ((double)pcm[i] * (double)pcm[i]);
    }
    double rms = sqrt(energy / (double)sample_count);
    g_bob_energy_sum += rms;

    uint64_t delta = g_bob_last_recv_time ? (now - g_bob_last_recv_time) : 0;
    g_bob_last_recv_time = now;

    if (g_bob_frames_received <= 10 || g_bob_frames_received % 20 == 0) {
        printf("  [Bob Recv #%d] samples=%zu, RMS=%.1f, delta=%llums\n",
               g_bob_frames_received, sample_count, rms, (unsigned long long)delta);
    }
}

int main(void) {
    printf("=== Two-Client Live Audio Diagnostics ===\n");

    /* 1. Start Server */
    TestServerContext srv_ctx;
    start_test_server(&srv_ctx, TEST_PORT);

    /* 2. Connect Alice and Bob */
    ClipClientNet alice, bob;
    clip_client_net_init(&alice);
    clip_client_net_init(&bob);

    clip_tls_client_config_t client_tls = {
        .ca_file = "certs/ca.crt",
        .expected_host = "localhost"
    };
    clip_client_net_set_tls_config(&alice, &client_tls);
    clip_client_net_set_tls_config(&bob, &client_tls);

    clip_client_connect(&alice, "127.0.0.1", TEST_PORT);
    clip_client_connect(&bob, "127.0.0.1", TEST_PORT);

    ClipUuid alice_uuid, bob_uuid;
    uint8_t cred[32];
    clip_client_register(&alice, "Alice", &alice_uuid, cred);
    clip_client_register(&bob, "Bob", &bob_uuid, cred);

    /* Set codec to Opus 48kHz on both */
    clip_client_set_codec_params(&alice, CLIP_CODEC_OPUS, SAMPLE_RATE, CHANNELS);
    clip_client_set_codec_params(&bob, CLIP_CODEC_OPUS, SAMPLE_RATE, CHANNELS);

    clip_client_set_audio_recv_callback(&bob, bob_audio_recv_callback, NULL);

    /* 3. Create Channel & Join */
    ClipUuid chan_uuid;
    char join_key[64];
    clip_client_channel_create_with_limit(&alice, "TACTICAL", 4, &chan_uuid, join_key, sizeof(join_key));

    ClipUuid bob_chan_uuid;
    char bob_chan_name[64];
    ClipChannelMember* members = NULL;
    size_t member_count = 0;
    clip_client_channel_join(&bob, join_key, &bob_chan_uuid, bob_chan_name, sizeof(bob_chan_name), &members, &member_count);
    clip_client_free_members(members);

    /* 4. Start Session */
    ClipUuid sess_uuid;
    clip_client_session_start(&alice, &chan_uuid, &sess_uuid);
    Sleep(200);

    /* 5. Alice Acquires PTT Floor */
    ClipPttFloor floor;
    ClipError denial = CLIP_OK;
    clip_client_ptt_request(&alice, &sess_uuid, 10000, &floor, &denial);
    printf("Alice acquired floor: %s\n", floor.speaker_uuid_str);

    /* 6. Alice sends 100 frames (2 seconds) of 1000 Hz continuous tone */
    printf("\nAlice sending %d frames (2.0s of audio, 48kHz mono, 1kHz tone)...\n", NUM_FRAMES);

    double phase = 0.0;
    double phase_inc = (2.0 * 3.14159265358979323846 * 1000.0) / (double)SAMPLE_RATE;
    int16_t tone_pcm[SAMPLES_PER_FRAME];

    for (int f = 1; f <= NUM_FRAMES; f++) {
        for (int i = 0; i < SAMPLES_PER_FRAME; i++) {
            tone_pcm[i] = (int16_t)(sin(phase) * 0.3 * 32767.0);
            phase += phase_inc;
            if (phase >= 2.0 * 3.14159265358979323846) phase -= 2.0 * 3.14159265358979323846;
        }

        uint64_t ts = GetTickCount64();
        ClipError send_err = clip_client_send_audio_frame(&alice, &sess_uuid, ts, tone_pcm, SAMPLES_PER_FRAME);
        if (send_err != CLIP_OK) {
            printf("  Alice send error on frame %d: %d\n", f, send_err);
        }

        /* Bob pumps events with timeout 0 */
        clip_client_pump_events(&bob, 0);

        Sleep(20);
    }

    /* Drain remaining frames on Bob for 500ms */
    DWORD drain_end = GetTickCount() + 500;
    while (GetTickCount() < drain_end) {
        clip_client_pump_events(&bob, 10);
    }

    printf("\nResults:\n");
    printf("  Alice sent:          %d frames\n", NUM_FRAMES);
    printf("  Server relayed:      %llu frames\n", (unsigned long long)srv_ctx.srv.total_audio_frames_relayed);
    printf("  Server dropped:      %llu frames\n", (unsigned long long)srv_ctx.srv.dropped_audio_frames);
    printf("  Bob received:        %d frames\n", g_bob_frames_received);
    if (g_bob_frames_received > 0) {
        printf("  Bob avg RMS:         %.1f\n", g_bob_energy_sum / g_bob_frames_received);
    }

    /* Cleanup */
    clip_client_ptt_release(&alice, &sess_uuid);
    clip_client_session_end(&alice, &sess_uuid);
    clip_client_disconnect(&alice);
    clip_client_disconnect(&bob);
    clip_client_net_cleanup(&alice);
    clip_client_net_cleanup(&bob);

    stop_test_server(&srv_ctx);

    printf("=== Test Finished ===\n");
    return 0;
}

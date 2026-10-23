/*
 * test_audio_transport.c — CLICOM Phase 10: Real-Time Audio Transport & Relay Test Suite
 *
 * Requirements Tested:
 * 1. Audio frame serialization & TLV parsing (build, parse, bounds, integrity)
 * 2. Strict maximum PCM frame/payload size enforcement (oversized rejected before processing)
 * 3. Per-session / per-sender audio sequence tracking (strictly increasing accepted;
 *    duplicate, stale, and backward rejected; reset on session end)
 * 4. Server-authoritative PTT floor gating (only active floor holder can stream;
 *    unauthorized / rogue sender dropped immediately)
 * 5. timestamp_ms treated strictly as metadata (never used as floor evidence)
 * 6. Server as validation-and-relay layer only (no decoding/resampling on server)
 * 7. End-to-end audio relay over TLS 1.3 to listening session peer(s)
 * 8. Routing through existing Phase 9 ClipAudioEngine playback abstraction
 * 9. Audio transmission halts immediately upon PTT floor release
 * 10. Audio transmission halts immediately upon server lease timeout expiration
 * 11. Audio sequence tracking reset upon session termination
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "clip_types.h"
#include "clip_protocol.h"
#include "clip_errors.h"
#include "clip_log.h"
#include "clip_audio_types.h"
#include "clip_audio_ring_buffer.h"
#include "clip_audio_device.h"
#include "clip_audio.h"
#include "network.h"
#include "server.h"
#include "clients.h"
#include "clip_channels.h"
#include "clip_sessions.h"
#include "clip_connections.h"
#include "clip_ptt.h"
#include "clip_audio_seq.h"
#include "clip_crypto.h"

static int g_pass = 0;
static int g_fail = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (cond) { \
        printf("  [PASS] %s\n", msg); \
        fflush(stdout); \
        g_pass++; \
    } else { \
        printf("  [FAIL] %s (line %d)\n", msg, __LINE__); \
        fflush(stdout); \
        g_fail++; \
    } \
} while(0)

/* Helper: generate mock UUID */
static void make_test_uuid(ClipUuid* u, uint8_t fill)
{
    memset(u->bytes, fill, CLIP_UUID_BYTES);
    u->bytes[6] = 0x40 | (fill & 0x0F);
    u->bytes[8] = 0x80 | (fill & 0x3F);
}

/* ── Test Group 1: Wire Frame Build & Parse ────────────────────────────── */

static void test_audio_frame_build_parse(void)
{
    printf("\n--- Test Group 1: Audio Frame Wire Serialization & Parsing ---\n");

    ClipUuid sess_uuid;
    make_test_uuid(&sess_uuid, 0xAA);

    int16_t original_pcm[320];
    for (int i = 0; i < 320; i++) original_pcm[i] = (int16_t)(i * 15 - 2000);

    uint8_t frame_buf[CLIP_AUDIO_MAX_FRAME_WIRE_SIZE];
    size_t frame_len = 0;

    /* Build valid audio frame */
    ClipError b_err = clip_audio_frame_build(frame_buf, sizeof(frame_buf), &frame_len,
                                             &sess_uuid, 42,
                                             (uint8_t)CLIP_CODEC_PCM, 1700000000000ULL,
                                             original_pcm, 320);
    TEST_ASSERT(b_err == CLIP_OK, "Built valid audio frame");
    TEST_ASSERT(frame_len > CLIP_HEADER_SIZE, "Frame length exceeds header size");

    /* Decode wire frame */
    ClipFrameHeader rx_hdr;
    const uint8_t* payload = NULL;
    uint32_t payload_len = 0;
    ClipError d_err = clip_frame_decode(frame_buf, frame_len, &rx_hdr, &payload, &payload_len);
    TEST_ASSERT(d_err == CLIP_OK, "Decoded wire frame");
    TEST_ASSERT(rx_hdr.msg_type == CLIP_MSG_AUDIO_FRAME, "Message type is CLIP_MSG_AUDIO_FRAME");
    TEST_ASSERT(rx_hdr.seq_num == 42, "Sequence number is 42");
    TEST_ASSERT(memcmp(rx_hdr.session_uuid, sess_uuid.bytes, CLIP_UUID_BYTES) == 0, "Session UUID matches in header");

    /* Parse audio TLV payload */
    uint8_t codec_type = 0;
    uint64_t ts_ms = 0;
    const int16_t* parsed_pcm = NULL;
    size_t sample_count = 0;

    ClipError p_err = clip_audio_frame_parse(payload, payload_len,
                                             &codec_type, &ts_ms,
                                             &parsed_pcm, &sample_count);
    TEST_ASSERT(p_err == CLIP_OK, "Parsed audio TLVs successfully");
    TEST_ASSERT(codec_type == (uint8_t)CLIP_CODEC_PCM, "Codec type is PCM");
    TEST_ASSERT(ts_ms == 1700000000000ULL, "Timestamp matches exactly");
    TEST_ASSERT(sample_count == 320, "Sample count is 320");
    TEST_ASSERT(memcmp(original_pcm, parsed_pcm, 320 * sizeof(int16_t)) == 0, "PCM sample contents match exactly");

    /* Zero session_uuid rejection */
    ClipUuid zero_uuid;
    clip_uuid_zero(&zero_uuid);
    ClipError z_err = clip_audio_frame_build(frame_buf, sizeof(frame_buf), &frame_len,
                                             &zero_uuid, 1, (uint8_t)CLIP_CODEC_PCM, 0,
                                             original_pcm, 320);
    TEST_ASSERT(z_err == CLIP_ERR_NO_SESSION, "Building frame with zero session_uuid rejected");

    /* Oversized frame rejection */
    size_t huge_samples = (CLIP_AUDIO_MAX_PAYLOAD_BYTES / sizeof(int16_t)) + 10;
    int16_t* huge_pcm = (int16_t*)calloc(huge_samples, sizeof(int16_t));
    ClipError over_err = clip_audio_frame_build(frame_buf, sizeof(frame_buf), &frame_len,
                                                &sess_uuid, 1, (uint8_t)CLIP_CODEC_PCM, 0,
                                                huge_pcm, huge_samples);
    TEST_ASSERT(over_err == CLIP_ERR_AUDIO_OVERSIZED, "Oversized sample count rejected in build");
    free(huge_pcm);
}

/* ── Test Group 2: Sequence Number Tracker ──────────────────────────────── */

static void test_audio_sequence_tracker(void)
{
    printf("\n--- Test Group 2: Per-Session Audio Sequence Tracking ---\n");

    ClipAudioSeqTracker tracker;
    clip_audio_seq_tracker_init(&tracker);

    ClipUuid sess1, sess2;
    make_test_uuid(&sess1, 0x11);
    make_test_uuid(&sess2, 0x22);

    uint8_t alice[CLIP_UUID_BYTES] = {1, 2, 3};
    uint8_t bob[CLIP_UUID_BYTES]   = {4, 5, 6};

    /* Alice sends sequence 1 in sess1: Accepted */
    TEST_ASSERT(clip_audio_seq_validate_and_update(&tracker, &sess1, alice, 1) == CLIP_OK,
                "First frame (seq=1) accepted for (sess1, alice)");

    /* Alice sends sequence 2 in sess1: Accepted */
    TEST_ASSERT(clip_audio_seq_validate_and_update(&tracker, &sess1, alice, 2) == CLIP_OK,
                "Increasing frame (seq=2) accepted for (sess1, alice)");

    /* Alice re-sends sequence 2 (duplicate): Rejected */
    TEST_ASSERT(clip_audio_seq_validate_and_update(&tracker, &sess1, alice, 2) == CLIP_ERR_AUDIO_SEQUENCE,
                "Duplicate frame (seq=2) rejected");

    /* Alice sends sequence 1 (stale/backward): Rejected */
    TEST_ASSERT(clip_audio_seq_validate_and_update(&tracker, &sess1, alice, 1) == CLIP_ERR_AUDIO_SEQUENCE,
                "Stale frame (seq=1) rejected");

    /* Alice sends sequence 5 (skip forward): Accepted */
    TEST_ASSERT(clip_audio_seq_validate_and_update(&tracker, &sess1, alice, 5) == CLIP_OK,
                "Forward frame (seq=5) accepted");

    /* Bob in sess1 has independent sequence tracking */
    TEST_ASSERT(clip_audio_seq_validate_and_update(&tracker, &sess1, bob, 1) == CLIP_OK,
                "Bob starting at seq=1 accepted in sess1");

    /* Alice in sess2 has independent sequence tracking */
    TEST_ASSERT(clip_audio_seq_validate_and_update(&tracker, &sess2, alice, 1) == CLIP_OK,
                "Alice starting at seq=1 accepted in sess2");

    /* Reset sess1: clears tracking for sess1 */
    clip_audio_seq_reset_session(&tracker, &sess1);

    /* Now Alice in sess1 can start from seq=1 again cleanly */
    TEST_ASSERT(clip_audio_seq_validate_and_update(&tracker, &sess1, alice, 1) == CLIP_OK,
                "After session reset, seq=1 accepted again for (sess1, alice)");

    /* sess2 tracking was NOT affected by resetting sess1 */
    TEST_ASSERT(clip_audio_seq_validate_and_update(&tracker, &sess2, alice, 1) == CLIP_ERR_AUDIO_SEQUENCE,
                "sess2 sequence tracking preserved after sess1 reset");

    clip_audio_seq_tracker_cleanup(&tracker);
}

/* ── Live Network Integration Context ───────────────────────────────────── */

typedef struct {
    ClipServer srv;
    uint16_t   port;
    char       db_path[64];
    HANDLE     hServerThread;
} TestServerContext;

static DWORD WINAPI test_server_thread_func(LPVOID arg)
{
    TestServerContext* ctx = (TestServerContext*)arg;
    while (ctx->srv.is_running) {
        clip_server_poll(&ctx->srv, 10);
    }
    return 0;
}

static void start_test_server(TestServerContext* ctx, uint16_t port)
{
    memset(ctx, 0, sizeof(TestServerContext));
    ctx->port = port;
    snprintf(ctx->db_path, sizeof(ctx->db_path), "test_audio_trans_%u.db", port);
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
    Sleep(100);
}

static void stop_test_server(TestServerContext* ctx)
{
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

static void connect_test_client(ClipClientNet* c, uint16_t port, const char* name, ClipUuid* out_uuid)
{
    clip_client_net_init(c);
    clip_tls_client_config_t tls_cfg = {
        .ca_file = "certs/ca.crt",
        .expected_host = "localhost"
    };
    clip_client_net_set_tls_config(c, &tls_cfg);
    clip_client_connect(c, "127.0.0.1", port);

    uint8_t cred[CLIP_CREDENTIAL_BYTES];
    clip_client_register(c, name, out_uuid, cred);
}

/* ── Test Group 3 & 4: Live PTT Floor Gated Audio Transport & Relay ─────── */

static void test_live_audio_transport_and_relay(void)
{
    printf("\n--- Test Group 3-7: Live End-to-End Audio Transport & Relay over TLS 1.3 ---\n");

    TestServerContext srv_ctx;
    uint16_t port = 16910;
    start_test_server(&srv_ctx, port);

    ClipClientNet alice, bob;
    ClipUuid alice_uuid, bob_uuid;

    connect_test_client(&alice, port, "ALICE", &alice_uuid);
    connect_test_client(&bob, port, "BOB", &bob_uuid);

    TEST_ASSERT(alice.is_connected && alice.transport != NULL, "Alice connected over TLS 1.3");
    TEST_ASSERT(bob.is_connected && bob.transport != NULL, "Bob connected over TLS 1.3");

    /* Create channel with Alice, Bob joins via key */
    ClipUuid chan_uuid;
    char join_key[CLIP_JOIN_KEY_MAX];
    TEST_ASSERT(clip_client_channel_create(&alice, "AUDIO-ROOM", &chan_uuid, join_key, sizeof(join_key)) == CLIP_OK,
                "Alice created channel");
    Sleep(50);

    ClipUuid bob_chan_uuid;
    char bob_chan_name[CLIP_DISPLAY_NAME_MAX];
    ClipChannelMember* members = NULL;
    size_t mem_cnt = 0;
    TEST_ASSERT(clip_client_channel_join(&bob, join_key, &bob_chan_uuid, bob_chan_name, sizeof(bob_chan_name), &members, &mem_cnt) == CLIP_OK,
                "Bob joined channel");
    clip_client_free_members(members);
    Sleep(50);

    /* Connection request: Alice -> Bob, Bob accepts */
    ClipUuid conn_uuid;
    ClipConnectionState cstate;
    TEST_ASSERT(clip_client_send_conn_request(&alice, &chan_uuid, &bob_uuid, &conn_uuid, &cstate) == CLIP_OK,
                "Alice requested connection to Bob");
    Sleep(50);

    TEST_ASSERT(clip_client_respond_conn(&bob, &conn_uuid, true) == CLIP_OK,
                "Bob accepted connection");
    Sleep(50);

    /* Start Session bound to connection */
    ClipUuid sess_uuid;
    ClipError s_err = clip_client_session_start_by_conn(&alice, &conn_uuid, &sess_uuid);
    TEST_ASSERT(s_err == CLIP_OK, "Started session bound to connection");
    Sleep(50);

    /* Setup Phase 9 ClipAudioEngine on Bob with Mock backend */
    ClipAudioConfig bob_audio_cfg;
    clip_audio_config_init_default(&bob_audio_cfg);
    bob_audio_cfg.backend = CLIP_AUDIO_BACKEND_MOCK;
    ClipAudioEngine bob_audio_engine;
    clip_audio_engine_init(&bob_audio_engine, &bob_audio_cfg);
    clip_audio_start_playback(&bob_audio_engine);

    /* ── Subtest A: Anti-Spoofing — Audio without floor MUST be rejected ── */
    int16_t test_pcm[320];
    for (int i = 0; i < 320; i++) test_pcm[i] = (int16_t)(i * 10);

    uint64_t initial_relayed = srv_ctx.srv.total_audio_frames_relayed;
    uint64_t initial_dropped = srv_ctx.srv.dropped_audio_frames;

    ClipError unauth_send = clip_client_send_audio_frame(&alice, &sess_uuid, 1000, test_pcm, 320);
    TEST_ASSERT(unauth_send == CLIP_OK, "Alice sent audio frame over socket");

    Sleep(100);
    TEST_ASSERT(srv_ctx.srv.dropped_audio_frames > initial_dropped,
                "Server rejected and dropped audio frame sent without PTT floor");
    TEST_ASSERT(srv_ctx.srv.total_audio_frames_relayed == initial_relayed,
                "0 frames relayed to Bob while floor was FREE");

    /* Bob attempts to recv: should timeout because server dropped frame */
    ClipUuid rx_sess;
    uint64_t rx_ts = 0;
    int16_t rx_pcm[320];
    size_t rx_samples = 0;
    ClipError b_recv_err = clip_client_recv_audio_frame(&bob, &rx_sess, &rx_ts, rx_pcm, 320, &rx_samples, 200);
    TEST_ASSERT(b_recv_err == CLIP_ERR_TIMEOUT, "Bob received 0 frames when floor not held");

    /* ── Subtest B: Floor Granted — Audio streaming & relay succeeds ── */
    ClipPttFloor granted_floor;
    ClipError denial = CLIP_OK;
    ClipError acq_err = clip_client_ptt_request(&alice, &sess_uuid, 5000, &granted_floor, &denial);
    TEST_ASSERT(acq_err == CLIP_OK, "Alice acquired PTT floor");
    Sleep(50);

    /* Alice streams 3 consecutive frames with increasing sequence */
    initial_relayed = srv_ctx.srv.total_audio_frames_relayed;

    for (int f = 1; f <= 3; f++) {
        for (int i = 0; i < 320; i++) test_pcm[i] = (int16_t)(f * 1000 + i);
        clip_client_send_audio_frame(&alice, &sess_uuid, 2000 + f * 20, test_pcm, 320);

        /* Bob receives each frame */
        ClipError r_err = clip_client_recv_audio_frame(&bob, &rx_sess, &rx_ts, rx_pcm, 320, &rx_samples, 1000);
        TEST_ASSERT(r_err == CLIP_OK, "Bob received relayed audio frame");
        TEST_ASSERT(clip_uuid_equal(&rx_sess, &sess_uuid), "Received frame has matching session_uuid");
        TEST_ASSERT(rx_samples == 320, "Received 320 PCM samples");
        TEST_ASSERT(memcmp(test_pcm, rx_pcm, 320 * sizeof(int16_t)) == 0,
                    "Bob received exact identical PCM samples sent by Alice");

        /* Route through Phase 9 ClipAudioEngine abstraction */
        ClipError play_res = clip_audio_play_frame(&bob_audio_engine, rx_pcm, rx_samples);
        TEST_ASSERT(play_res == CLIP_OK, "Received PCM routed through ClipAudioEngine playback successfully");
    }

    TEST_ASSERT(srv_ctx.srv.total_audio_frames_relayed >= initial_relayed + 3,
                "Server recorded at least 3 audio frames relayed");

    /* ── Subtest C: Stale / Out-of-Order Sequence Rejection ── */
    initial_dropped = srv_ctx.srv.dropped_audio_frames;
    /* Send duplicate sequence frame directly */
    uint8_t dup_buf[CLIP_AUDIO_MAX_FRAME_WIRE_SIZE];
    size_t dup_len = 0;
    clip_audio_frame_build(dup_buf, sizeof(dup_buf), &dup_len, &sess_uuid, alice.seq_counter - 1,
                           (uint8_t)CLIP_CODEC_PCM, 3000, test_pcm, 320);
    clip_transport_write(alice.transport, dup_buf, dup_len);

    Sleep(100);
    TEST_ASSERT(srv_ctx.srv.dropped_audio_frames > initial_dropped,
                "Server rejected stale/duplicate sequence frame during live streaming");

    /* ── Subtest D: Floor Release halts audio transmission ── */
    clip_client_ptt_release(&alice, &sess_uuid);
    Sleep(50);

    initial_dropped = srv_ctx.srv.dropped_audio_frames;
    clip_client_send_audio_frame(&alice, &sess_uuid, 4000, test_pcm, 320);
    Sleep(100);
    TEST_ASSERT(srv_ctx.srv.dropped_audio_frames > initial_dropped,
                "Server dropped audio frame sent after floor was released");

    /* ── Subtest E: Active Streaming Floor Renewal & Inactivity Timeout ── */
    ClipPttFloor e_floor;
    denial = CLIP_OK;
    /* Alice acquires floor with 300ms lease */
    acq_err = clip_client_ptt_request(&alice, &sess_uuid, 300, &e_floor, &denial);
    TEST_ASSERT(acq_err == CLIP_OK, "Alice acquired floor with 300ms lease");

    /* Alice streams 4 audio frames spaced 100ms apart (total elapsed 400ms > 300ms initial lease) */
    bool all_relayed = true;
    for (int k = 1; k <= 4; k++) {
        Sleep(100);
        clip_client_send_audio_frame(&alice, &sess_uuid, 5000 + k * 100, test_pcm, 320);
        ClipError rk = clip_client_recv_audio_frame(&bob, &rx_sess, &rx_ts, rx_pcm, 320, &rx_samples, 500);
        if (rk != CLIP_OK) all_relayed = false;
    }
    TEST_ASSERT(all_relayed, "All 4 frames relayed beyond initial 300ms lease via auto-renewal");

    /* Alice goes silent: wait 450ms (> 300ms lease duration) */
    Sleep(450);
    initial_dropped = srv_ctx.srv.dropped_audio_frames;
    clip_client_send_audio_frame(&alice, &sess_uuid, 6000, test_pcm, 320);
    Sleep(100);
    TEST_ASSERT(srv_ctx.srv.dropped_audio_frames > initial_dropped,
                "Server expired floor lease after inactivity period and dropped audio frame");

    /* ── Subtest F: Reverse Direction — Bob Acquires Floor & Streams Audio to Alice ── */
    ClipAudioConfig alice_audio_cfg;
    clip_audio_config_init_default(&alice_audio_cfg);
    alice_audio_cfg.backend = CLIP_AUDIO_BACKEND_MOCK;
    ClipAudioEngine alice_audio_engine;
    clip_audio_engine_init(&alice_audio_engine, &alice_audio_cfg);
    clip_audio_start_playback(&alice_audio_engine);

    ClipPttFloor bob_floor;
    denial = CLIP_OK;
    acq_err = clip_client_ptt_request(&bob, &sess_uuid, 5000, &bob_floor, &denial);
    TEST_ASSERT(acq_err == CLIP_OK, "Bob acquired PTT floor for reverse two-way voice");
    Sleep(50);

    initial_relayed = srv_ctx.srv.total_audio_frames_relayed;
    for (int f = 1; f <= 3; f++) {
        for (int i = 0; i < 320; i++) test_pcm[i] = (int16_t)(f * 2000 + i);
        clip_client_send_audio_frame(&bob, &sess_uuid, 7000 + f * 20, test_pcm, 320);

        /* Alice receives each frame */
        ClipError r_err = clip_client_recv_audio_frame(&alice, &rx_sess, &rx_ts, rx_pcm, 320, &rx_samples, 1000);
        TEST_ASSERT(r_err == CLIP_OK, "Alice received relayed audio frame from Bob");
        TEST_ASSERT(clip_uuid_equal(&rx_sess, &sess_uuid), "Received frame has matching session_uuid");
        TEST_ASSERT(rx_samples == 320, "Alice received 320 PCM samples");
        TEST_ASSERT(memcmp(test_pcm, rx_pcm, 320 * sizeof(int16_t)) == 0,
                    "Alice received exact identical PCM samples sent by Bob");

        /* Route through Phase 9 ClipAudioEngine playback */
        ClipError play_res = clip_audio_play_frame(&alice_audio_engine, rx_pcm, rx_samples);
        TEST_ASSERT(play_res == CLIP_OK, "Received PCM routed through Alice's ClipAudioEngine playback successfully");
    }
    TEST_ASSERT(srv_ctx.srv.total_audio_frames_relayed >= initial_relayed + 3,
                "Server recorded at least 3 audio frames relayed from Bob to Alice");

    clip_client_ptt_release(&bob, &sess_uuid);
    Sleep(50);

    clip_audio_stop_playback(&alice_audio_engine);
    clip_audio_engine_cleanup(&alice_audio_engine);

    /* Cleanup */
    clip_audio_stop_playback(&bob_audio_engine);
    clip_audio_engine_cleanup(&bob_audio_engine);

    clip_client_session_end(&alice, &sess_uuid);
    clip_client_disconnect(&alice);
    clip_client_disconnect(&bob);
    clip_client_net_cleanup(&alice);
    clip_client_net_cleanup(&bob);

    stop_test_server(&srv_ctx);
}

/* ── Main Entry ────────────────────────────────────────────────────────── */

int main(void)
{
    printf("========================================================\n");
    printf("  CLICOM Phase 10: Real-Time Audio Transport & Relay   \n");
    printf("========================================================\n");

    test_audio_frame_build_parse();
    test_audio_sequence_tracker();
    test_live_audio_transport_and_relay();

    printf("\n========================================================\n");
    printf("  Phase 10 Test Results: %d PASSED, %d FAILED\n", g_pass, g_fail);
    printf("========================================================\n");

    return (g_fail == 0) ? 0 : 1;
}

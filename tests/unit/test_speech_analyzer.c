/*
 * test_speech_analyzer.c — Phase 12 SpeechAnalyzer & Audio Pipeline Tests
 *
 * Verifies:
 * 1. SpeechAnalyzer lifecycle (null, mock, invalid adapters).
 * 2. PCM input validation and error boundaries.
 * 3. Deterministic Mock STT chunking, timestamps, confidence scores, and flush.
 * 4. Speaker change auto-flush and session separation.
 * 5. End-to-end PCM -> server relay -> decode -> SpeechAnalyzer.
 * 6. End-to-end Opus -> server relay -> decode -> SpeechAnalyzer.
 * 7. Security invariant: un-granted / no-floor audio never reaches SpeechAnalyzer.
 * 8. Mandatory disclosure: CLIP_TAG_SPEECH_ANALYSIS in SESSION_START.
 */

#include "speech_analyzer.h"
#include "codec.h"
#include "network.h"
#include "server.h"
#include "clip_log.h"
#include "clip_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <windows.h>

static int g_pass_count = 0;
static int g_fail_count = 0;

#define TEST(name, cond) do { \
    if (cond) { \
        printf("  [PASS] %s\n", (name)); \
        fflush(stdout); \
        g_pass_count++; \
    } else { \
        printf("  [FAIL] %s (line %d)\n", (name), __LINE__); \
        fflush(stdout); \
        g_fail_count++; \
    } \
} while(0)

/* Callback capture context */
typedef struct TestTranscriptContext {
    int         call_count;
    char        last_text[256];
    uint64_t    last_start_ms;
    uint64_t    last_dur_ms;
    float       last_confidence;
    bool        last_is_final;
    ClipUuid    last_speaker;
    ClipUuid    last_session;
} TestTranscriptContext;

static void on_test_transcript(const SpeechTranscriptResult* result, void* user_data)
{
    TestTranscriptContext* ctx = (TestTranscriptContext*)user_data;
    if (!ctx || !result) return;
    ctx->call_count++;
    if (result->text) {
        strncpy(ctx->last_text, result->text, sizeof(ctx->last_text) - 1);
        ctx->last_text[sizeof(ctx->last_text) - 1] = '\0';
    }
    ctx->last_start_ms = result->start_time_ms;
    ctx->last_dur_ms = result->duration_ms;
    ctx->last_confidence = result->confidence;
    ctx->last_is_final = result->is_final;
    memcpy(ctx->last_speaker.bytes, result->speaker_node_uuid.bytes, CLIP_UUID_BYTES);
    memcpy(ctx->last_session.bytes, result->session_uuid.bytes, CLIP_UUID_BYTES);
}

/* Helper to generate 20ms of 16kHz sine wave PCM */
static void generate_pcm_frame(int16_t* pcm, size_t sample_count, float freq_hz, int sample_rate)
{
    for (size_t i = 0; i < sample_count; i++) {
        double t = (double)i / (double)sample_rate;
        double val = sin(2.0 * 3.141592653589793 * (double)freq_hz * t) * 16000.0;
        pcm[i] = (int16_t)val;
    }
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
    snprintf(ctx->db_path, sizeof(ctx->db_path), "test_speech_%u.db", port);
    remove(ctx->db_path);

    ClipServerConfig cfg;
    clip_server_config_init_default(&cfg);
    cfg.port = port;
    strncpy(cfg.db_path, ctx->db_path, sizeof(cfg.db_path) - 1);
    cfg.use_tls = true;
    cfg.speech_mode = CLIP_SPEECH_MODE_SERVER_MEDIATED;
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

int main(void)
{
    clip_log_init(CLIP_LOG_WARN, NULL);

    printf("====================================================\n");
    printf("    CLICOM Phase 12 SpeechAnalyzer Unit Tests       \n");
    printf("====================================================\n\n");

    /* ── Test Group 1: SpeechAnalyzer Lifecycle & Config Validation ── */
    printf("--- Test Group 1: SpeechAnalyzer Lifecycle & Config Validation ---\n");
    {
        SpeechAnalyzerConfig cfg;
        speech_analyzer_config_default(&cfg);
        TEST("Default sample rate is 16000 Hz", cfg.sample_rate == 16000);
        TEST("Default channels is 1 (mono)", cfg.channels == 1);
        TEST("Default min chunk is 8000 samples (500ms)", cfg.min_chunk_samples == 8000);
        TEST("Default max buffer is 48000 samples (3000ms)", cfg.max_buffer_samples == 48000);

        SpeechAnalyzer* sa_null = speech_analyzer_create("null", NULL);
        TEST("Created null adapter with default config", sa_null != NULL);
        TEST("Null adapter name matches", strcmp(speech_analyzer_adapter_name(sa_null), "null") == 0);
        speech_analyzer_destroy(sa_null);

        SpeechAnalyzer* sa_mock = speech_analyzer_create("mock", &cfg);
        TEST("Created mock adapter with config", sa_mock != NULL);
        TEST("Mock adapter name matches", strcmp(speech_analyzer_adapter_name(sa_mock), "mock") == 0);
        speech_analyzer_destroy(sa_mock);

        TEST("Unsupported adapter returns NULL", speech_analyzer_create("non_existent", NULL) == NULL);

        SpeechAnalyzerConfig bad_cfg = cfg;
        bad_cfg.sample_rate = 0;
        TEST("0 Hz sample rate rejected", speech_analyzer_create("mock", &bad_cfg) == NULL);

        bad_cfg = cfg;
        bad_cfg.channels = 2; /* Mono required */
        TEST("Stereo channels rejected", speech_analyzer_create("mock", &bad_cfg) == NULL);

        bad_cfg = cfg;
        bad_cfg.min_chunk_samples = 0;
        TEST("0 chunk samples rejected", speech_analyzer_create("mock", &bad_cfg) == NULL);
    }

    /* ── Test Group 2: PCM Input Validation & Boundaries ── */
    printf("\n--- Test Group 2: PCM Input Validation & Boundaries ---\n");
    {
        SpeechAnalyzer* sa = speech_analyzer_create("mock", NULL);
        TEST("Analyzer instance created", sa != NULL);

        int16_t pcm[320];
        generate_pcm_frame(pcm, 320, 440.0f, 16000);

        ClipUuid valid_sess, valid_speaker, zero_uuid;
        clip_crypto_uuid_generate(&valid_sess);
        clip_crypto_uuid_generate(&valid_speaker);
        memset(zero_uuid.bytes, 0, CLIP_UUID_BYTES);

        TEST("NULL analyzer feed rejected", speech_analyzer_feed_pcm(NULL, &valid_sess, &valid_speaker, 1000, pcm, 320) == CLIP_ERR_INVALID);
        TEST("NULL PCM buffer rejected", speech_analyzer_feed_pcm(sa, &valid_sess, &valid_speaker, 1000, NULL, 320) == CLIP_ERR_INVALID);
        TEST("0 sample count rejected", speech_analyzer_feed_pcm(sa, &valid_sess, &valid_speaker, 1000, pcm, 0) == CLIP_ERR_INVALID);
        TEST("Zero session UUID rejected", speech_analyzer_feed_pcm(sa, &zero_uuid, &valid_speaker, 1000, pcm, 320) == CLIP_ERR_NO_SESSION);
        TEST("Zero speaker UUID rejected", speech_analyzer_feed_pcm(sa, &valid_sess, &zero_uuid, 1000, pcm, 320) == CLIP_ERR_NO_SESSION);

        speech_analyzer_destroy(sa);
    }

    /* ── Test Group 3: Deterministic Mock STT Chunking, Timestamps & Flush ── */
    printf("\n--- Test Group 3: Deterministic Mock STT Chunking & Flush ---\n");
    {
        SpeechAnalyzerConfig cfg;
        speech_analyzer_config_default(&cfg);
        cfg.min_chunk_samples = 1600; /* 100ms threshold for fast testing (5 frames) */

        SpeechAnalyzer* sa = speech_analyzer_create("mock", &cfg);
        TestTranscriptContext ctx;
        memset(&ctx, 0, sizeof(ctx));
        speech_analyzer_set_callback(sa, on_test_transcript, &ctx);

        ClipUuid sess, speaker;
        clip_crypto_uuid_generate(&sess);
        clip_crypto_uuid_generate(&speaker);

        int16_t pcm[320];
        generate_pcm_frame(pcm, 320, 440.0f, 16000);

        /* Feed 4 frames (1280 samples) - below 1600 chunk threshold */
        for (int i = 0; i < 4; i++) {
            speech_analyzer_feed_pcm(sa, &sess, &speaker, 1000 + i * 20, pcm, 320);
        }
        TEST("No transcript emitted before chunk threshold", ctx.call_count == 0);

        /* Feed 5th frame (1600 samples total) - reaches threshold */
        speech_analyzer_feed_pcm(sa, &sess, &speaker, 1080, pcm, 320);
        TEST("Chunk transcript emitted at threshold", ctx.call_count == 1);
        TEST("Transcript is not final during streaming", ctx.last_is_final == false);
        TEST("Deterministic confidence is 0.95f", fabs(ctx.last_confidence - 0.95f) < 0.001f);
        TEST("Start timestamp matches first frame (1000ms)", ctx.last_start_ms == 1000);
        TEST("Duration is 100ms", ctx.last_dur_ms == 100);
        TEST("Speaker UUID matches", memcmp(ctx.last_speaker.bytes, speaker.bytes, CLIP_UUID_BYTES) == 0);
        TEST("Session UUID matches", memcmp(ctx.last_session.bytes, sess.bytes, CLIP_UUID_BYTES) == 0);

        /* Feed 2 more frames (640 samples) */
        speech_analyzer_feed_pcm(sa, &sess, &speaker, 1100, pcm, 320);
        speech_analyzer_feed_pcm(sa, &sess, &speaker, 1120, pcm, 320);
        TEST("No new transcript yet for uncompleted chunk", ctx.call_count == 1);

        /* Trigger explicit flush (e.g. on PTT floor release) */
        speech_analyzer_flush(sa);
        TEST("Flush emitted remaining samples", ctx.call_count == 2);
        TEST("Flushed transcript is marked final", ctx.last_is_final == true);
        TEST("Flushed duration is 40ms (640 samples)", ctx.last_dur_ms == 40);

        /* Reset clears internal buffers and sequence */
        speech_analyzer_reset(sa);
        speech_analyzer_flush(sa);
        TEST("Flush on empty buffer after reset emits nothing", ctx.call_count == 2);

        speech_analyzer_destroy(sa);
    }

    /* ── Test Group 4: Speaker Change Auto-Flush ── */
    printf("\n--- Test Group 4: Speaker Change Auto-Flush ---\n");
    {
        SpeechAnalyzerConfig cfg;
        speech_analyzer_config_default(&cfg);
        cfg.min_chunk_samples = 3200; /* 200ms */

        SpeechAnalyzer* sa = speech_analyzer_create("mock", &cfg);
        TestTranscriptContext ctx;
        memset(&ctx, 0, sizeof(ctx));
        speech_analyzer_set_callback(sa, on_test_transcript, &ctx);

        ClipUuid sess, speaker_a, speaker_b;
        clip_crypto_uuid_generate(&sess);
        clip_crypto_uuid_generate(&speaker_a);
        clip_crypto_uuid_generate(&speaker_b);

        int16_t pcm[320];
        generate_pcm_frame(pcm, 320, 440.0f, 16000);

        /* Feed 2 frames from Speaker A */
        speech_analyzer_feed_pcm(sa, &sess, &speaker_a, 2000, pcm, 320);
        speech_analyzer_feed_pcm(sa, &sess, &speaker_a, 2020, pcm, 320);
        TEST("No transcript before threshold for speaker A", ctx.call_count == 0);

        /* Now feed a frame from Speaker B -> triggers auto-flush for Speaker A */
        speech_analyzer_feed_pcm(sa, &sess, &speaker_b, 2040, pcm, 320);
        TEST("Speaker change auto-flushed speaker A audio", ctx.call_count == 1);
        TEST("Auto-flushed chunk marked final", ctx.last_is_final == true);
        TEST("Auto-flushed speaker was speaker A", memcmp(ctx.last_speaker.bytes, speaker_a.bytes, CLIP_UUID_BYTES) == 0);

        speech_analyzer_destroy(sa);
    }

    /* ── Test Group 5: Live End-to-End PCM -> Server Relay -> Bob Decodes -> SpeechAnalyzer ── */
    printf("\n--- Test Group 5: Live End-to-End PCM Transport & SpeechAnalyzer ---\n");
    {
        TestServerContext srv_ctx;
        uint16_t port = 16930;
        start_test_server(&srv_ctx, port);

        ClipClientNet alice, bob;
        ClipUuid alice_uuid, bob_uuid;
        connect_test_client(&alice, port, "ALICE_PCM", &alice_uuid);
        connect_test_client(&bob, port, "BOB_PCM", &bob_uuid);

        ClipUuid chan_uuid;
        char join_key[CLIP_JOIN_KEY_MAX];
        TEST("Alice created channel", clip_client_channel_create(&alice, "PCM-ROOM", &chan_uuid, join_key, sizeof(join_key)) == CLIP_OK);
        Sleep(50);

        ClipUuid bob_chan_uuid;
        char bob_chan_name[CLIP_DISPLAY_NAME_MAX];
        ClipChannelMember* members = NULL;
        size_t mem_cnt = 0;
        TEST("Bob joined channel", clip_client_channel_join(&bob, join_key, &bob_chan_uuid, bob_chan_name, sizeof(bob_chan_name), &members, &mem_cnt) == CLIP_OK);
        clip_client_free_members(members);
        Sleep(50);

        ClipUuid conn_uuid;
        ClipConnectionState cstate;
        TEST("Alice requested connection to Bob", clip_client_send_conn_request(&alice, &chan_uuid, &bob_uuid, &conn_uuid, &cstate) == CLIP_OK);
        Sleep(50);
        TEST("Bob accepted connection", clip_client_respond_conn(&bob, &conn_uuid, true) == CLIP_OK);
        Sleep(50);

        ClipUuid sess_uuid;
        TEST("Started session bound to connection", clip_client_session_start_by_conn(&alice, &conn_uuid, &sess_uuid) == CLIP_OK);
        Sleep(50);

        TEST("Alice received CLIP_TAG_SPEECH_ANALYSIS disclosure (SERVER_MEDIATED)",
             clip_client_get_speech_mode(&alice) == CLIP_SPEECH_MODE_SERVER_MEDIATED);

        /* Set up Bob's SpeechAnalyzer */
        SpeechAnalyzerConfig sa_cfg;
        speech_analyzer_config_default(&sa_cfg);
        sa_cfg.min_chunk_samples = 320; /* 1 frame chunk */

        SpeechAnalyzer* bob_sa = speech_analyzer_create("mock", &sa_cfg);
        TestTranscriptContext bob_ctx;
        memset(&bob_ctx, 0, sizeof(bob_ctx));
        speech_analyzer_set_callback(bob_sa, on_test_transcript, &bob_ctx);

        clip_client_set_speech_analyzer(&bob, bob_sa);
        bob.session_speech_mode = CLIP_SPEECH_MODE_SERVER_MEDIATED;

        /* Alice acquires floor */
        ClipPttFloor granted_floor;
        ClipError denial = CLIP_OK;
        TEST("Alice acquired PTT floor", clip_client_ptt_request(&alice, &sess_uuid, 5000, &granted_floor, &denial) == CLIP_OK);
        Sleep(50);

        /* Alice sends uncompressed PCM audio frame */
        int16_t pcm[320];
        generate_pcm_frame(pcm, 320, 500.0f, 16000);
        clip_client_send_audio_frame(&alice, &sess_uuid, 3000, pcm, 320);

        /* Bob receives relayed frame (zero transcoding on server) */
        ClipUuid rx_sess;
        uint64_t rx_ts = 0;
        int16_t bob_rx_pcm[320];
        size_t bob_rx_samples = 0;
        ClipError r_err = clip_client_recv_audio_frame(&bob, &rx_sess, &rx_ts, bob_rx_pcm, 320, &bob_rx_samples, 1000);

        TEST("Bob received relayed PCM audio frame", r_err == CLIP_OK);
        TEST("Bob decoded 320 samples", bob_rx_samples == 320);
        TEST("Bob SpeechAnalyzer processed PCM and invoked callback", bob_ctx.call_count == 1);
        TEST("Bob transcript contains synthetic mock text", strstr(bob_ctx.last_text, "MOCK_TRANSCRIPT") != NULL);

        clip_client_disconnect(&alice);
        clip_client_disconnect(&bob);
        speech_analyzer_destroy(bob_sa);
        stop_test_server(&srv_ctx);
    }

    /* ── Test Group 6: Live End-to-End Opus -> Server Relay -> Bob Decodes -> SpeechAnalyzer ── */
    printf("\n--- Test Group 6: Live End-to-End Opus Transport & SpeechAnalyzer ---\n");
    {
        TestServerContext srv_ctx;
        uint16_t port = 16931;
        start_test_server(&srv_ctx, port);

        ClipClientNet alice, bob;
        ClipUuid alice_uuid, bob_uuid;
        connect_test_client(&alice, port, "ALICE_OPUS", &alice_uuid);
        connect_test_client(&bob, port, "BOB_OPUS", &bob_uuid);

        /* Configure both Alice and Bob for OPUS compression */
        TEST("Alice switched to Opus codec", clip_client_set_codec(&alice, CLIP_CODEC_OPUS) == CLIP_OK);
        TEST("Bob switched to Opus codec", clip_client_set_codec(&bob, CLIP_CODEC_OPUS) == CLIP_OK);

        ClipUuid chan_uuid;
        char join_key[CLIP_JOIN_KEY_MAX];
        TEST("Alice created channel", clip_client_channel_create(&alice, "OPUS-ROOM", &chan_uuid, join_key, sizeof(join_key)) == CLIP_OK);
        Sleep(50);

        ClipUuid bob_chan_uuid;
        char bob_chan_name[CLIP_DISPLAY_NAME_MAX];
        ClipChannelMember* members = NULL;
        size_t mem_cnt = 0;
        TEST("Bob joined channel", clip_client_channel_join(&bob, join_key, &bob_chan_uuid, bob_chan_name, sizeof(bob_chan_name), &members, &mem_cnt) == CLIP_OK);
        clip_client_free_members(members);
        Sleep(50);

        ClipUuid conn_uuid;
        ClipConnectionState cstate;
        TEST("Alice requested connection to Bob", clip_client_send_conn_request(&alice, &chan_uuid, &bob_uuid, &conn_uuid, &cstate) == CLIP_OK);
        Sleep(50);
        TEST("Bob accepted connection", clip_client_respond_conn(&bob, &conn_uuid, true) == CLIP_OK);
        Sleep(50);

        ClipUuid sess_uuid;
        TEST("Started session bound to connection", clip_client_session_start_by_conn(&alice, &conn_uuid, &sess_uuid) == CLIP_OK);
        Sleep(50);

        /* Set up Bob's SpeechAnalyzer */
        SpeechAnalyzerConfig sa_cfg;
        speech_analyzer_config_default(&sa_cfg);
        sa_cfg.min_chunk_samples = 320; /* 1 frame chunk */

        SpeechAnalyzer* bob_sa = speech_analyzer_create("mock", &sa_cfg);
        TestTranscriptContext bob_ctx;
        memset(&bob_ctx, 0, sizeof(bob_ctx));
        speech_analyzer_set_callback(bob_sa, on_test_transcript, &bob_ctx);

        clip_client_set_speech_analyzer(&bob, bob_sa);
        bob.session_speech_mode = CLIP_SPEECH_MODE_SERVER_MEDIATED;

        /* Alice acquires floor */
        ClipPttFloor granted_floor;
        ClipError denial = CLIP_OK;
        TEST("Alice acquired PTT floor", clip_client_ptt_request(&alice, &sess_uuid, 5000, &granted_floor, &denial) == CLIP_OK);
        Sleep(50);

        /* Alice encodes & transmits Opus audio frame */
        int16_t pcm[320];
        generate_pcm_frame(pcm, 320, 880.0f, 16000);
        clip_client_send_audio_frame(&alice, &sess_uuid, 4000, pcm, 320);

        /* Bob receives relayed Opus frame, decodes to PCM via codec_decode, feeds to SpeechAnalyzer */
        ClipUuid rx_sess;
        uint64_t rx_ts = 0;
        int16_t bob_rx_pcm[320];
        size_t bob_rx_samples = 0;
        ClipError r_err = clip_client_recv_audio_frame(&bob, &rx_sess, &rx_ts, bob_rx_pcm, 320, &bob_rx_samples, 1000);

        TEST("Bob received relayed Opus audio frame", r_err == CLIP_OK);
        TEST("Bob decoded Opus into 320 PCM samples", bob_rx_samples == 320);
        TEST("Bob SpeechAnalyzer processed decoded PCM and invoked callback", bob_ctx.call_count == 1);
        TEST("Transcript generated successfully from decoded Opus audio", strstr(bob_ctx.last_text, "MOCK_TRANSCRIPT") != NULL);

        clip_client_disconnect(&alice);
        clip_client_disconnect(&bob);
        speech_analyzer_destroy(bob_sa);
        stop_test_server(&srv_ctx);
    }

    /* ── Test Group 7: Security Invariant: Unauthorized / No-Floor Audio Rejected ── */
    printf("\n--- Test Group 7: Security Invariants (No-Floor Audio Gate) ---\n");
    {
        TestServerContext srv_ctx;
        uint16_t port = 16932;
        start_test_server(&srv_ctx, port);

        ClipClientNet alice, bob;
        ClipUuid alice_uuid, bob_uuid;
        connect_test_client(&alice, port, "ALICE_SEC", &alice_uuid);
        connect_test_client(&bob, port, "BOB_SEC", &bob_uuid);

        ClipUuid chan_uuid;
        char join_key[CLIP_JOIN_KEY_MAX];
        clip_client_channel_create(&alice, "SEC_ROOM", &chan_uuid, join_key, sizeof(join_key));
        Sleep(50);

        ClipUuid bob_chan_uuid;
        char bob_chan_name[CLIP_DISPLAY_NAME_MAX];
        ClipChannelMember* members = NULL;
        size_t mem_cnt = 0;
        clip_client_channel_join(&bob, join_key, &bob_chan_uuid, bob_chan_name, sizeof(bob_chan_name), &members, &mem_cnt);
        clip_client_free_members(members);
        Sleep(50);

        ClipUuid conn_uuid;
        ClipConnectionState cstate;
        clip_client_send_conn_request(&alice, &chan_uuid, &bob_uuid, &conn_uuid, &cstate);
        Sleep(50);
        clip_client_respond_conn(&bob, &conn_uuid, true);
        Sleep(50);

        ClipUuid sess_uuid;
        clip_client_session_start_by_conn(&alice, &conn_uuid, &sess_uuid);
        Sleep(50);

        /* Set up Bob's SpeechAnalyzer */
        SpeechAnalyzerConfig sa_cfg;
        speech_analyzer_config_default(&sa_cfg);
        SpeechAnalyzer* bob_sa = speech_analyzer_create("mock", &sa_cfg);
        TestTranscriptContext bob_ctx;
        memset(&bob_ctx, 0, sizeof(bob_ctx));
        speech_analyzer_set_callback(bob_sa, on_test_transcript, &bob_ctx);

        clip_client_set_speech_analyzer(&bob, bob_sa);
        bob.session_speech_mode = CLIP_SPEECH_MODE_SERVER_MEDIATED;

        /* Alice DOES NOT acquire floor. Sends rogue audio frame directly */
        int16_t pcm[320];
        generate_pcm_frame(pcm, 320, 440.0f, 16000);
        clip_client_send_audio_frame(&alice, &sess_uuid, 5000, pcm, 320);

        /* Bob attempts to receive - server must have dropped it */
        ClipUuid rx_sess;
        uint64_t rx_ts = 0;
        int16_t bob_rx_pcm[320];
        size_t bob_rx_samples = 0;
        ClipError r_err = clip_client_recv_audio_frame(&bob, &rx_sess, &rx_ts, bob_rx_pcm, 320, &bob_rx_samples, 200);

        TEST("Server dropped audio frame sent without PTT floor", r_err == CLIP_ERR_TIMEOUT);
        TEST("Bob SpeechAnalyzer received ZERO audio when floor not held", bob_ctx.call_count == 0);

        clip_client_disconnect(&alice);
        clip_client_disconnect(&bob);
        speech_analyzer_destroy(bob_sa);
        stop_test_server(&srv_ctx);
    }

    printf("\n====================================================\n");
    printf("  SpeechAnalyzer Results: %d PASSED, %d FAILED\n", g_pass_count, g_fail_count);
    printf("====================================================\n");

    return (g_fail_count == 0) ? 0 : 1;
}

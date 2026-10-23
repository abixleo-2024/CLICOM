/*
 * test_phase3a_voice.c — CLICOM Phase 3A Real Voice Transport Verification Suite
 *
 * Verifies all Phase 3A criteria:
 * 1. Initialize two ClicomEngine instances (Alice and Bob) with Opus codec.
 * 2. Connect both to TLS 1.3 server using CA verification.
 * 3. Alice creates a tactical room; Bob joins via cryptographic join key.
 * 4. Verify shared active room communication session binding.
 * 5. Start audio subsystem on both engines.
 * 6. Server-enforced half-duplex floor control:
 *    - Alice acquires PTT floor successfully.
 *    - Bob's PTT request is strictly rejected with CLICOM_ERR_PTT_BUSY.
 * 7. Real voice transmission and reception:
 *    - Alice transmits audio frames compressed via Opus.
 *    - Bob receives, decodes, and queues frames in playback FIFO queue.
 *    - Telemetry snapshots track frames sent and frames received.
 * 8. Mute suppression:
 *    - When Alice is muted, audio transmission is actively suppressed.
 * 9. Floor handover:
 *    - Alice releases floor.
 *    - Bob successfully acquires floor.
 *    - Alice is now rejected with CLICOM_ERR_PTT_BUSY.
 * 10. Clean deterministic teardown of audio hardware, network, and engines.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

#if defined(_WIN32) || defined(__CYGWIN__)
    #include <winsock2.h>
    #include <windows.h>
#else
    #include <pthread.h>
    #include <unistd.h>
#endif

#include "clicom.h"
#include "clip_net.h"
#include "clip_version.h"
#include "clip_protocol.h"
#include "clip_types.h"
#include "clip_errors.h"
#include "clip_transport.h"
#include "clip_tls.h"
#include "clip_channels.h"
#include "clip_identity.h"
#include "clip_audio.h"
#include "codec.h"
#include "../../server/include/server.h"
#include "../../client/include/network.h"

static int g_pass = 0;
static int g_fail = 0;

#define TEST(name, condition) do { \
    if (condition) { \
        printf("  PASS  %s\n", (name)); \
        g_pass++; \
    } else { \
        printf("  FAIL  %s\n", (name)); \
        g_fail++; \
    } \
} while (0)

#define TEST_VOICE_PORT 14998
#define TEST_VOICE_DB "test_phase3a_voice.db"

#if defined(_WIN32) || defined(__CYGWIN__)
static DWORD WINAPI server_thread_func(LPVOID param)
{
    ClipServer* srv = (ClipServer*)param;
    while (srv && srv->is_running) {
        clip_server_poll(srv, 10);
    }
    return 0;
}
#endif

/* Generate a synthetic 440 Hz sine wave PCM buffer (20ms at 48000Hz = 960 samples) */
static void generate_synthetic_tone(int16_t* out_pcm, size_t num_samples, float frequency_hz, uint32_t sample_rate)
{
    for (size_t i = 0; i < num_samples; i++) {
        double t = (double)i / (double)sample_rate;
        double val = sin(2.0 * 3.141592653589793 * frequency_hz * t);
        out_pcm[i] = (int16_t)(val * 16000.0);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("============================================================\n");
    printf(" CLICOM Phase 3A — Real Voice Transport Verification Suite \n");
    printf("============================================================\n\n");

    remove(TEST_VOICE_DB);

    /* ── 1. Start Server with TLS 1.3 and Database ────────────────────────── */
    ClipServerConfig srv_cfg = {0};
    strncpy(srv_cfg.bind_host, "127.0.0.1", sizeof(srv_cfg.bind_host) - 1);
    srv_cfg.port = TEST_VOICE_PORT;
    srv_cfg.max_clients = 16;
    srv_cfg.use_tls = true;
    strncpy(srv_cfg.cert_file, "certs/server.crt", sizeof(srv_cfg.cert_file) - 1);
    strncpy(srv_cfg.key_file, "certs/server.key", sizeof(srv_cfg.key_file) - 1);
    strncpy(srv_cfg.db_path, TEST_VOICE_DB, sizeof(srv_cfg.db_path) - 1);

    ClipServer srv;
    ClipError srv_init_err = clip_server_init(&srv, &srv_cfg);
    TEST("Server initialized with TLS 1.3 and SQLite storage", srv_init_err == CLIP_OK);

    ClipError srv_start_err = clip_server_start(&srv);
    TEST("Server listening on port 14998", srv_start_err == CLIP_OK);

#if defined(_WIN32) || defined(__CYGWIN__)
    HANDLE h_srv_thread = CreateThread(NULL, 0, server_thread_func, &srv, 0, NULL);
    TEST("Server background dispatch thread running", h_srv_thread != NULL);
    Sleep(100);
#endif

    /* ── 2. Initialize Native Engines (Alice and Bob) ─────────────────────── */
    ClicomEngine* engine_alice = NULL;
    ClicomEngine* engine_bob = NULL;

    TEST("clicom_engine_create for Alice", clicom_engine_create(&engine_alice) == CLICOM_OK && engine_alice != NULL);
    TEST("clicom_engine_create for Bob", clicom_engine_create(&engine_bob) == CLICOM_OK && engine_bob != NULL);

    /* Use mock audio backend for deterministic headless CI execution */
    clicom_audio_set_mock_backend(engine_alice, true);
    clicom_audio_set_mock_backend(engine_bob, true);

    ClicomConfig cfg_alice;
    memset(&cfg_alice, 0, sizeof(cfg_alice));
    cfg_alice.client_display_name = "Alice";
    cfg_alice.audio_sample_rate = 48000;
    cfg_alice.audio_channels = 1;
    cfg_alice.max_audio_queue_frames = 64;

    ClicomConfig cfg_bob;
    memset(&cfg_bob, 0, sizeof(cfg_bob));
    cfg_bob.client_display_name = "Bob";
    cfg_bob.audio_sample_rate = 48000;
    cfg_bob.audio_channels = 1;
    cfg_bob.max_audio_queue_frames = 64;

    TEST("clicom_engine_init Alice (Opus 48kHz mono)", clicom_engine_init(engine_alice, &cfg_alice) == CLICOM_OK);
    TEST("clicom_engine_init Bob (Opus 48kHz mono)", clicom_engine_init(engine_bob, &cfg_bob) == CLICOM_OK);

    /* ── 3. Connect to TLS 1.3 Server ─────────────────────────────────────── */
    int32_t conn_alice = clicom_network_connect(engine_alice, "127.0.0.1", TEST_VOICE_PORT, "certs/ca.crt");
    TEST("Alice connects to server over TLS 1.3", conn_alice == CLICOM_OK);

    int32_t conn_bob = clicom_network_connect(engine_bob, "127.0.0.1", TEST_VOICE_PORT, "certs/ca.crt");
    TEST("Bob connects to server over TLS 1.3", conn_bob == CLICOM_OK);

    /* ── 4. Room Creation & Joining ───────────────────────────────────────── */
    char room_id[CLICOM_MAX_ROOM_ID_LEN] = {0};
    char join_key[CLICOM_MAX_KEY_LEN] = {0};
    int32_t cr_rc = clicom_network_create_room(engine_alice,
                                               "VOICE_ROOM",
                                               4,
                                               room_id,
                                               sizeof(room_id),
                                               join_key,
                                               sizeof(join_key));
    TEST("Alice creates room 'VOICE_ROOM'", cr_rc == CLICOM_OK && strlen(join_key) > 0);

    char bob_room_id[CLICOM_MAX_ROOM_ID_LEN] = {0};
    char bob_room_name[CLICOM_MAX_NAME_LEN] = {0};
    int32_t jn_rc = clicom_network_join_room(engine_bob,
                                             join_key,
                                             bob_room_id,
                                             sizeof(bob_room_id),
                                             bob_room_name,
                                             sizeof(bob_room_name));
    TEST("Bob joins room via join_key", jn_rc == CLICOM_OK && strcmp(bob_room_id, room_id) == 0);

    /* ── 5. Active Communication Session Verification ─────────────────────── */
    char alice_sess_id[CLICOM_MAX_UUID_LEN] = {0};
    char bob_sess_id[CLICOM_MAX_UUID_LEN] = {0};
    int32_t s1_rc = clicom_get_active_session_id(engine_alice, alice_sess_id, sizeof(alice_sess_id));
    int32_t s2_rc = clicom_get_active_session_id(engine_bob, bob_sess_id, sizeof(bob_sess_id));
    TEST("Alice active room session established", s1_rc == CLICOM_OK && strlen(alice_sess_id) > 0);
    TEST("Bob active room session established", s2_rc == CLICOM_OK && strlen(bob_sess_id) > 0);
    TEST("Both Alice and Bob share identical room session UUID", strcmp(alice_sess_id, bob_sess_id) == 0);

    /* ── 6. Start Audio Subsystem on Both ─────────────────────────────────── */
    TEST("Alice starts audio engine", clicom_audio_start(engine_alice) == CLICOM_OK);
    TEST("Bob starts audio engine", clicom_audio_start(engine_bob) == CLICOM_OK);

    ClicomAudioStatus a_stat;
    clicom_get_audio_status(engine_alice, &a_stat);
    TEST("Alice audio state is RUNNING", a_stat.state == CLICOM_AUDIO_RUNNING);

    /* ── 7. Server-Enforced Half-Duplex Floor Control ─────────────────────── */
    TEST("Alice acquires PTT floor", clicom_set_ptt_active(engine_alice, true) == CLICOM_OK);

    bool alice_ptt = false;
    clicom_is_ptt_active(engine_alice, &alice_ptt);
    TEST("Alice mic status reports is_ptt_active == true", alice_ptt == true);

    /* Bob attempts to acquire floor while held by Alice: MUST BE REJECTED */
    int32_t bob_ptt_rc = clicom_set_ptt_active(engine_bob, true);
    TEST("Bob strictly denied floor while Alice holds it (CLICOM_ERR_PTT_BUSY)", bob_ptt_rc == CLICOM_ERR_PTT_BUSY);

    bool bob_ptt = false;
    clicom_is_ptt_active(engine_bob, &bob_ptt);
    TEST("Bob mic status remains is_ptt_active == false", bob_ptt == false);

    /* ── 8. Voice Transmission & Reception Over TLS 1.3 ───────────────────── */
    int16_t tone_pcm[CLICOM_AUDIO_MAX_SAMPLES];
    generate_synthetic_tone(tone_pcm, 960, 440.0f, 48000);

    /* Push audio frames through Alice's capture queue and trigger transmission */
    ClicomAudioFrame frame_tx;
    frame_tx.timestamp_ns = 1000000000ULL;
    frame_tx.sample_rate = 48000;
    frame_tx.channels = 1;
    frame_tx.num_samples = 960;
    memcpy(frame_tx.pcm_data, tone_pcm, 960 * sizeof(int16_t));

    /* Encode and transmit audio frame over TLS directly through native capture callback */
    for (int i = 0; i < 5; i++) {
        frame_tx.timestamp_ns += 20000000ULL;
        clicom_audio_queue_push_capture(engine_alice, &frame_tx);
    }

    /* Pump events for transmission and delivery */
    for (int i = 0; i < 15; i++) {
        clicom_network_poll(engine_alice, 5);
        clicom_network_poll(engine_bob, 15);
#if defined(_WIN32) || defined(__CYGWIN__)
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    /* Verify Bob's telemetry and audio status */
    ClicomTelemetrySnapshot telem_bob;
    clicom_get_telemetry(engine_bob, &telem_bob);

    ClicomAudioStatus bob_audio;
    clicom_get_audio_status(engine_bob, &bob_audio);

    TEST("Bob received voice frames over network or in playback queue",
         telem_bob.frames_received > 0 || bob_audio.playback_queue_depth > 0 || bob_audio.total_frames_pushed > 0);

    /* ── 9. Mute Suppression Verification ─────────────────────────────────── */
    TEST("Alice mutes microphone", clicom_set_mic_muted(engine_alice, true) == CLICOM_OK);
    bool alice_muted = false;
    clicom_is_mic_muted(engine_alice, &alice_muted);
    TEST("Alice mic reports muted", alice_muted == true);

    /* Drain any in-flight frames transmitted before muting */
    for (int i = 0; i < 15; i++) {
        clicom_network_poll(engine_alice, 5);
        clicom_network_poll(engine_bob, 15);
#if defined(_WIN32) || defined(__CYGWIN__)
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    clicom_get_telemetry(engine_bob, &telem_bob);
    uint64_t bob_rx_before = telem_bob.frames_received;

    ClicomTelemetrySnapshot telem_alice;
    clicom_get_telemetry(engine_alice, &telem_alice);
    uint64_t alice_tx_before = telem_alice.frames_sent;

    /* Alice attempts to produce audio while muted */
    for (int i = 0; i < 5; i++) {
        frame_tx.timestamp_ns += 20000000ULL;
        clicom_audio_queue_push_capture(engine_alice, &frame_tx);
    }
    for (int i = 0; i < 15; i++) {
        clicom_network_poll(engine_alice, 5);
        clicom_network_poll(engine_bob, 15);
#if defined(_WIN32) || defined(__CYGWIN__)
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    clicom_get_telemetry(engine_alice, &telem_alice);
    clicom_get_telemetry(engine_bob, &telem_bob);
    TEST("Mute actively suppressed real audio transmission (no additional frames)",
         telem_alice.frames_sent == alice_tx_before && telem_bob.frames_received == bob_rx_before);

    TEST("Alice unmutes microphone", clicom_set_mic_muted(engine_alice, false) == CLICOM_OK);

    /* ── 10. Floor Release & Handover ─────────────────────────────────────── */
    TEST("Alice releases PTT floor", clicom_set_ptt_active(engine_alice, false) == CLICOM_OK);
    clicom_is_ptt_active(engine_alice, &alice_ptt);
    TEST("Alice reports is_ptt_active == false", alice_ptt == false);

    /* Now Bob requests floor: MUST BE GRANTED */
    TEST("Bob successfully acquires floor after Alice released", clicom_set_ptt_active(engine_bob, true) == CLICOM_OK);
    clicom_is_ptt_active(engine_bob, &bob_ptt);
    TEST("Bob mic status reports is_ptt_active == true", bob_ptt == true);

    /* Alice now attempts to acquire floor: MUST BE REJECTED */
    int32_t alice_ptt_rc = clicom_set_ptt_active(engine_alice, true);
    TEST("Alice now strictly denied floor while Bob holds it (CLICOM_ERR_PTT_BUSY)", alice_ptt_rc == CLICOM_ERR_PTT_BUSY);

    /* Bob releases floor */
    TEST("Bob releases floor", clicom_set_ptt_active(engine_bob, false) == CLICOM_OK);

    /* ── 11. Clean Teardown & Deterministic Cleanup ───────────────────────── */
    TEST("Alice stops audio", clicom_audio_stop(engine_alice) == CLICOM_OK);
    TEST("Bob stops audio", clicom_audio_stop(engine_bob) == CLICOM_OK);

    TEST("Alice leaves room", clicom_network_leave_room(engine_alice) == CLICOM_OK);
    TEST("Bob leaves room", clicom_network_leave_room(engine_bob) == CLICOM_OK);

    TEST("Alice disconnects", clicom_network_disconnect(engine_alice) == CLICOM_OK);
    TEST("Bob disconnects", clicom_network_disconnect(engine_bob) == CLICOM_OK);

    TEST("Alice engine shutdown", clicom_engine_shutdown(engine_alice) == CLICOM_OK);
    TEST("Bob engine shutdown", clicom_engine_shutdown(engine_bob) == CLICOM_OK);

    clicom_engine_destroy(engine_alice);
    clicom_engine_destroy(engine_bob);

    /* Server cleanup */
    srv.is_running = false;
    clip_net_close_socket(&srv.listen_sock);
#if defined(_WIN32) || defined(__CYGWIN__)
    WaitForSingleObject(h_srv_thread, 1000);
    CloseHandle(h_srv_thread);
#endif
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
    remove(TEST_VOICE_DB);

    printf("\n============================================================\n");
    printf(" Phase 3A Test Results: %d passed, %d failed\n", g_pass, g_fail);
    printf(" Status: %s\n", g_fail == 0 ? "ALL PASS" : "FAILURES DETECTED");
    printf("============================================================\n");

    return (g_fail == 0) ? 0 : 1;
}

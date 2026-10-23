/**
 * @file test_engine.c
 * @brief Unit tests for CLICOM Native Foundation
 */

#include "clicom.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if defined(_WIN32) || defined(__CYGWIN__)
    #include <windows.h>
    typedef HANDLE TestThread;
    typedef DWORD WINAPI (*TestThreadFunc)(LPVOID);
#else
    #include <pthread.h>
    typedef pthread_t TestThread;
    typedef void* (*TestThreadFunc)(void*);
#endif

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "  [FAIL] %s (%s:%d): %s\n", __func__, __FILE__, __LINE__, msg); \
        return 0; \
    } \
} while (0)

#define RUN_TEST(fn) do { \
    g_tests_run++; \
    printf("[RUN ] %s\n", #fn); \
    if (fn()) { \
        printf("[PASS] %s\n", #fn); \
        g_tests_passed++; \
    } else { \
        printf("[FAIL] %s\n", #fn); \
    } \
} while (0)

/* ── Test 1: Version & Error Strings ─────────────────────────────────────── */
static int test_version_and_errors(void) {
    uint32_t ver = clicom_get_version();
    TEST_ASSERT(ver != 0, "Version code should be non-zero");

    const char* ver_str = clicom_get_version_string();
    TEST_ASSERT(ver_str != NULL, "Version string should not be NULL");
    TEST_ASSERT(strcmp(ver_str, "2.0.0") == 0, "Version string must match 2.0.0");

    TEST_ASSERT(strcmp(clicom_error_string(CLICOM_OK), "Success") == 0, "OK string mismatch");
    TEST_ASSERT(strcmp(clicom_error_string(CLICOM_ERR_INVALID_ARG), "Invalid argument") == 0, "Error string mismatch");
    TEST_ASSERT(strcmp(clicom_error_string(CLICOM_ERR_QUEUE_FULL), "Queue full") == 0, "Queue full string mismatch");
    TEST_ASSERT(strcmp(clicom_error_string(9999), "Unknown error code") == 0, "Unknown error code string mismatch");

    return 1;
}

/* ── Test 2: Engine Initialization & Lifecycle ───────────────────────────── */
static int test_initialization_lifecycle(void) {
    ClicomEngine* engine = NULL;

    /* NULL output pointer */
    TEST_ASSERT(clicom_engine_create(NULL) == CLICOM_ERR_NULL_POINTER, "Should fail on NULL out_engine");

    /* Valid create */
    TEST_ASSERT(clicom_engine_create(&engine) == CLICOM_OK, "Create should succeed");
    TEST_ASSERT(engine != NULL, "Engine pointer should be non-null");

    ClicomEngineStatus status;
    TEST_ASSERT(clicom_engine_get_status(engine, &status) == CLICOM_OK, "Get status on created engine");
    TEST_ASSERT(status.state == CLICOM_ENGINE_UNINITIALIZED, "Initial state should be UNINITIALIZED");

    /* Init with defaults */
    TEST_ASSERT(clicom_engine_init(engine, NULL) == CLICOM_OK, "Init with defaults should succeed");
    TEST_ASSERT(clicom_engine_get_status(engine, &status) == CLICOM_OK, "Get status on initialized engine");
    TEST_ASSERT(status.state == CLICOM_ENGINE_RUNNING, "State should be RUNNING");

    /* Double init */
    TEST_ASSERT(clicom_engine_init(engine, NULL) == CLICOM_ERR_ALREADY_INITIALIZED, "Double init should fail");

    /* Shutdown */
    TEST_ASSERT(clicom_engine_shutdown(engine) == CLICOM_OK, "Shutdown should succeed");
    TEST_ASSERT(clicom_engine_get_status(engine, &status) == CLICOM_OK, "Get status on shutdown engine");
    TEST_ASSERT(status.state == CLICOM_ENGINE_SHUTDOWN, "State should be SHUTDOWN");

    /* Repeated shutdown must be safe and deterministic */
    TEST_ASSERT(clicom_engine_shutdown(engine) == CLICOM_OK, "Repeated shutdown must succeed");
    TEST_ASSERT(clicom_engine_shutdown(engine) == CLICOM_OK, "Triple shutdown must succeed");

    /* Destroy */
    clicom_engine_destroy(engine);
    clicom_engine_destroy(NULL); /* Safe with NULL */

    return 1;
}

/* ── Test 3: Invalid Inputs ──────────────────────────────────────────────── */
static int test_invalid_inputs(void) {
    ClicomEngine* engine = NULL;
    TEST_ASSERT(clicom_engine_create(&engine) == CLICOM_OK, "Create engine");
    TEST_ASSERT(clicom_engine_init(engine, NULL) == CLICOM_OK, "Init engine");

    /* NULL engine pointers */
    TEST_ASSERT(clicom_set_display_name(NULL, "Test") == CLICOM_ERR_NULL_POINTER, "NULL engine set display");
    TEST_ASSERT(clicom_get_display_name(NULL, NULL, 0) == CLICOM_ERR_NULL_POINTER, "NULL engine get display");
    TEST_ASSERT(clicom_set_mic_muted(NULL, true) == CLICOM_ERR_NULL_POINTER, "NULL engine set mute");
    TEST_ASSERT(clicom_room_join(NULL, "r1", "k1") == CLICOM_ERR_NULL_POINTER, "NULL engine room join");
    TEST_ASSERT(clicom_audio_start(NULL) == CLICOM_ERR_NULL_POINTER, "NULL engine audio start");

    /* Invalid display names */
    TEST_ASSERT(clicom_set_display_name(engine, NULL) == CLICOM_ERR_INVALID_ARG, "NULL display name");
    TEST_ASSERT(clicom_set_display_name(engine, "") == CLICOM_ERR_INVALID_ARG, "Empty display name");
    char long_name[128];
    memset(long_name, 'A', sizeof(long_name));
    long_name[127] = '\0';
    TEST_ASSERT(clicom_set_display_name(engine, long_name) == CLICOM_ERR_INVALID_ARG, "Too long display name");

    /* Invalid gain ranges */
    TEST_ASSERT(clicom_set_mic_gain(engine, -0.1f) == CLICOM_ERR_INVALID_ARG, "Negative mic gain");
    TEST_ASSERT(clicom_set_mic_gain(engine, 2.5f) == CLICOM_ERR_INVALID_ARG, "Excessive mic gain");

    /* Invalid connection states */
    TEST_ASSERT(clicom_set_connection_state(engine, (ClicomConnectionState)-1) == CLICOM_ERR_INVALID_ARG, "Invalid conn state");
    TEST_ASSERT(clicom_set_connection_state(engine, (ClicomConnectionState)99) == CLICOM_ERR_INVALID_ARG, "Invalid conn state 99");

    /* Invalid room parameters */
    TEST_ASSERT(clicom_room_join(engine, NULL, NULL) == CLICOM_ERR_INVALID_ARG, "NULL room id");
    TEST_ASSERT(clicom_room_join(engine, "", NULL) == CLICOM_ERR_INVALID_ARG, "Empty room id");

    /* Invalid participant parameters */
    TEST_ASSERT(clicom_participant_add(engine, NULL) == CLICOM_ERR_NULL_POINTER, "NULL participant");
    ClicomParticipant bad_p = {0};
    TEST_ASSERT(clicom_participant_add(engine, &bad_p) == CLICOM_ERR_INVALID_ARG, "Empty participant fields");

    /* Invalid audio frames */
    TEST_ASSERT(clicom_audio_queue_push_capture(engine, NULL) == CLICOM_ERR_NULL_POINTER, "NULL frame push");
    ClicomAudioFrame bad_frame = {0};
    bad_frame.num_samples = 0;
    TEST_ASSERT(clicom_audio_queue_push_capture(engine, &bad_frame) == CLICOM_ERR_INVALID_ARG, "Zero sample frame");
    bad_frame.num_samples = CLICOM_AUDIO_MAX_SAMPLES + 10;
    TEST_ASSERT(clicom_audio_queue_push_capture(engine, &bad_frame) == CLICOM_ERR_INVALID_ARG, "Excessive sample frame");

    clicom_engine_destroy(engine);
    return 1;
}

/* ── Test 4: Display Name and Buffer Limits ───────────────────────────────── */
static int test_display_name_and_buffer_limits(void) {
    ClicomEngine* engine = NULL;
    TEST_ASSERT(clicom_engine_create(&engine) == CLICOM_OK, "Create engine");
    TEST_ASSERT(clicom_engine_init(engine, NULL) == CLICOM_OK, "Init engine");

    TEST_ASSERT(clicom_set_display_name(engine, "Operator-Alpha") == CLICOM_OK, "Set display name");

    char small_buf[5];
    TEST_ASSERT(clicom_get_display_name(engine, small_buf, sizeof(small_buf)) == CLICOM_ERR_BUFFER_TOO_SMALL,
                "Buffer too small should return error");

    char exact_buf[15]; /* "Operator-Alpha" is 14 chars + 1 null = 15 */
    TEST_ASSERT(clicom_get_display_name(engine, exact_buf, sizeof(exact_buf)) == CLICOM_OK, "Exact buffer size");
    TEST_ASSERT(strcmp(exact_buf, "Operator-Alpha") == 0, "Display name mismatch");

    clicom_engine_destroy(engine);
    return 1;
}

/* ── Test 5: Local Microphone and PTT State ──────────────────────────────── */
static int test_microphone_and_ptt_state(void) {
    ClicomEngine* engine = NULL;
    TEST_ASSERT(clicom_engine_create(&engine) == CLICOM_OK, "Create engine");
    TEST_ASSERT(clicom_engine_init(engine, NULL) == CLICOM_OK, "Init engine");

    bool muted = false;
    TEST_ASSERT(clicom_is_mic_muted(engine, &muted) == CLICOM_OK, "Query initial mute");
    TEST_ASSERT(muted == false, "Default mute must be false");

    TEST_ASSERT(clicom_set_mic_muted(engine, true) == CLICOM_OK, "Set mute true");
    TEST_ASSERT(clicom_is_mic_muted(engine, &muted) == CLICOM_OK, "Query mute after set");
    TEST_ASSERT(muted == true, "Mute must be true");

    bool ptt = false;
    TEST_ASSERT(clicom_is_ptt_active(engine, &ptt) == CLICOM_OK, "Query initial ptt");
    TEST_ASSERT(ptt == false, "Default ptt must be false");

    TEST_ASSERT(clicom_set_ptt_active(engine, true) == CLICOM_OK, "Set ptt true");
    TEST_ASSERT(clicom_is_ptt_active(engine, &ptt) == CLICOM_OK, "Query ptt after set");
    TEST_ASSERT(ptt == true, "PTT must be true");

    float gain = 0.0f;
    TEST_ASSERT(clicom_set_mic_gain(engine, 1.75f) == CLICOM_OK, "Set gain 1.75");
    TEST_ASSERT(clicom_get_mic_gain(engine, &gain) == CLICOM_OK, "Get gain");
    TEST_ASSERT(gain > 1.74f && gain < 1.76f, "Gain value check");

    ClicomMicState state;
    TEST_ASSERT(clicom_get_mic_state(engine, &state) == CLICOM_OK, "Get full mic state");
    TEST_ASSERT(state.is_muted == true, "MicState muted");
    TEST_ASSERT(state.is_ptt_active == true, "MicState ptt");
    TEST_ASSERT(state.gain > 1.74f && state.gain < 1.76f, "MicState gain");

    clicom_engine_destroy(engine);
    return 1;
}

/* ── Test 6: Room State & Participant Metadata ───────────────────────────── */
static int test_room_and_participants(void) {
    ClicomEngine* engine = NULL;
    TEST_ASSERT(clicom_engine_create(&engine) == CLICOM_OK, "Create engine");
    TEST_ASSERT(clicom_engine_init(engine, NULL) == CLICOM_OK, "Init engine");

    /* Room Join */
    TEST_ASSERT(clicom_room_join(engine, "tactical-net-1", "SEC-900") == CLICOM_OK, "Join room");

    ClicomRoomState r_state;
    TEST_ASSERT(clicom_get_room_state(engine, &r_state) == CLICOM_OK, "Get room state");
    TEST_ASSERT(r_state.state == CLICOM_ROOM_JOINED, "Room state should be JOINED");
    TEST_ASSERT(strcmp(r_state.room_id, "tactical-net-1") == 0, "Room ID mismatch");
    TEST_ASSERT(strcmp(r_state.join_key, "SEC-900") == 0, "Join key mismatch");
    TEST_ASSERT(r_state.participant_count == 0, "Initial participant count 0");

    /* Add Participant 1 */
    ClicomParticipant p1;
    memset(&p1, 0, sizeof(p1));
    strcpy(p1.participant_id, "node-uuid-001");
    strcpy(p1.display_name, "Alpha-Lead");
    p1.is_speaking = false;
    p1.is_muted = false;
    TEST_ASSERT(clicom_participant_add(engine, &p1) == CLICOM_OK, "Add participant 1");

    /* Add Participant 2 (Speaking) */
    ClicomParticipant p2;
    memset(&p2, 0, sizeof(p2));
    strcpy(p2.participant_id, "node-uuid-002");
    strcpy(p2.display_name, "Bravo-Two");
    p2.is_speaking = true;
    p2.is_muted = false;
    TEST_ASSERT(clicom_participant_add(engine, &p2) == CLICOM_OK, "Add participant 2");

    uint32_t count = 0;
    TEST_ASSERT(clicom_get_participant_count(engine, &count) == CLICOM_OK, "Get participant count");
    TEST_ASSERT(count == 2, "Count should be 2");

    TEST_ASSERT(clicom_get_room_state(engine, &r_state) == CLICOM_OK, "Get room state");
    TEST_ASSERT(strcmp(r_state.active_speaker_id, "node-uuid-002") == 0, "Active speaker should be node-uuid-002");

    /* Lookup by ID */
    ClicomParticipant found;
    TEST_ASSERT(clicom_get_participant_by_id(engine, "node-uuid-001", &found) == CLICOM_OK, "Find p1");
    TEST_ASSERT(strcmp(found.display_name, "Alpha-Lead") == 0, "p1 name check");
    TEST_ASSERT(clicom_get_participant_by_id(engine, "non-existent", &found) == CLICOM_ERR_NOT_FOUND, "Non-existent lookup");

    /* Buffer limit test for participant enumeration */
    ClicomParticipant part_buf[1];
    uint32_t actual = 0;
    TEST_ASSERT(clicom_get_participants(engine, part_buf, 1, &actual) == CLICOM_ERR_BUFFER_TOO_SMALL, "Buffer too small for participants");
    TEST_ASSERT(actual == 1, "Should have copied 1 item");

    ClicomParticipant part_buf2[2];
    TEST_ASSERT(clicom_get_participants(engine, part_buf2, 2, &actual) == CLICOM_OK, "Full participant copy");
    TEST_ASSERT(actual == 2, "Actual count should be 2");

    /* Update participant 2: stop speaking */
    p2.is_speaking = false;
    TEST_ASSERT(clicom_participant_add(engine, &p2) == CLICOM_OK, "Update p2 speaking to false");
    TEST_ASSERT(clicom_get_room_state(engine, &r_state) == CLICOM_OK, "Get room state");
    TEST_ASSERT(strlen(r_state.active_speaker_id) == 0, "Active speaker should be empty now");

    /* Remove participant */
    TEST_ASSERT(clicom_participant_remove(engine, "node-uuid-001") == CLICOM_OK, "Remove p1");
    TEST_ASSERT(clicom_get_participant_count(engine, &count) == CLICOM_OK, "Get count after remove");
    TEST_ASSERT(count == 1, "Count should be 1");
    TEST_ASSERT(clicom_participant_remove(engine, "node-uuid-001") == CLICOM_ERR_NOT_FOUND, "Repeated remove not found");

    /* Room Leave */
    TEST_ASSERT(clicom_room_leave(engine) == CLICOM_OK, "Leave room");
    TEST_ASSERT(clicom_get_room_state(engine, &r_state) == CLICOM_OK, "Get room state after leave");
    TEST_ASSERT(r_state.state == CLICOM_ROOM_DISCONNECTED, "State should be DISCONNECTED");
    TEST_ASSERT(r_state.participant_count == 0, "Count should be 0");

    clicom_engine_destroy(engine);
    return 1;
}

/* ── Test 7: Participant Capacity Limits ─────────────────────────────────── */
static int test_participant_capacity_limits(void) {
    ClicomEngine* engine = NULL;
    ClicomConfig cfg = {0};
    cfg.max_participants = 3;

    TEST_ASSERT(clicom_engine_create(&engine) == CLICOM_OK, "Create engine");
    TEST_ASSERT(clicom_engine_init(engine, &cfg) == CLICOM_OK, "Init engine with max 3 participants");

    for (int i = 0; i < 3; ++i) {
        ClicomParticipant p;
        memset(&p, 0, sizeof(p));
        snprintf(p.participant_id, sizeof(p.participant_id), "uuid-%d", i);
        snprintf(p.display_name, sizeof(p.display_name), "User-%d", i);
        TEST_ASSERT(clicom_participant_add(engine, &p) == CLICOM_OK, "Add participant within limit");
    }

    /* 4th participant should hit capacity limit */
    ClicomParticipant overflow_p;
    memset(&overflow_p, 0, sizeof(overflow_p));
    strcpy(overflow_p.participant_id, "uuid-overflow");
    strcpy(overflow_p.display_name, "Overflow");
    TEST_ASSERT(clicom_participant_add(engine, &overflow_p) == CLICOM_ERR_LIMIT_REACHED,
                "Participant overflow should return CLICOM_ERR_LIMIT_REACHED");

    clicom_engine_destroy(engine);
    return 1;
}

/* ── Test 8: Connection State & Telemetry Snapshots ──────────────────────── */
static int test_connection_and_telemetry(void) {
    ClicomEngine* engine = NULL;
    TEST_ASSERT(clicom_engine_create(&engine) == CLICOM_OK, "Create engine");
    TEST_ASSERT(clicom_engine_init(engine, NULL) == CLICOM_OK, "Init engine");

    ClicomConnectionState c_state;
    TEST_ASSERT(clicom_get_connection_state(engine, &c_state) == CLICOM_OK, "Get initial conn state");
    TEST_ASSERT(c_state == CLICOM_CONN_DISCONNECTED, "Default conn state DISCONNECTED");

    /* State transitions */
    TEST_ASSERT(clicom_set_connection_state(engine, CLICOM_CONN_CONNECTING) == CLICOM_OK, "Transition to CONNECTING");
    TEST_ASSERT(clicom_set_connection_state(engine, CLICOM_CONN_CONNECTED) == CLICOM_OK, "Transition to CONNECTED");

    ClicomTelemetrySnapshot snap;
    memset(&snap, 0, sizeof(snap));
    snap.conn_state = CLICOM_CONN_CONNECTED;
    snap.rtt_ms = 42;
    snap.packet_loss_pct = 1.5f;
    snap.bytes_sent = 1048576;
    snap.bytes_received = 2097152;
    snap.frames_sent = 5000;
    snap.frames_received = 4950;
    snap.frames_dropped = 50;
    snap.jitter_ms = 3.2f;

    TEST_ASSERT(clicom_update_telemetry(engine, &snap) == CLICOM_OK, "Update telemetry");

    ClicomTelemetrySnapshot read_snap;
    TEST_ASSERT(clicom_get_telemetry(engine, &read_snap) == CLICOM_OK, "Get telemetry");
    TEST_ASSERT(read_snap.conn_state == CLICOM_CONN_CONNECTED, "Telemetry conn state");
    TEST_ASSERT(read_snap.rtt_ms == 42, "Telemetry RTT");
    TEST_ASSERT(read_snap.bytes_sent == 1048576, "Telemetry bytes sent");
    TEST_ASSERT(read_snap.jitter_ms > 3.1f && read_snap.jitter_ms < 3.3f, "Telemetry jitter");

    /* Invalid packet loss */
    snap.packet_loss_pct = 150.0f;
    TEST_ASSERT(clicom_update_telemetry(engine, &snap) == CLICOM_ERR_INVALID_ARG, "Invalid packet loss >100%");

    clicom_engine_destroy(engine);
    return 1;
}

/* ── Test 9: Audio Lifecycle & Bounded Frame Queues ──────────────────────── */
static int test_audio_lifecycle_and_bounded_queues(void) {
    ClicomEngine* engine = NULL;
    ClicomConfig cfg = {0};
    cfg.max_audio_queue_frames = 4; /* Small bounded queue for limit testing */

    TEST_ASSERT(clicom_engine_create(&engine) == CLICOM_OK, "Create engine");
    TEST_ASSERT(clicom_engine_init(engine, &cfg) == CLICOM_OK, "Init engine with queue capacity 4");

    ClicomAudioStatus a_status;
    TEST_ASSERT(clicom_get_audio_status(engine, &a_status) == CLICOM_OK, "Get initial audio status");
    TEST_ASSERT(a_status.state == CLICOM_AUDIO_STOPPED, "Default audio state STOPPED");
    TEST_ASSERT(a_status.capture_queue_capacity == 4, "Capture capacity check");

    /* Cannot push frames when audio is stopped */
    ClicomAudioFrame frame = {0};
    frame.timestamp_ns = 1000000;
    frame.sample_rate = 48000;
    frame.channels = 1;
    frame.num_samples = 480;
    frame.pcm_data[0] = 1234;

    TEST_ASSERT(clicom_audio_queue_push_capture(engine, &frame) == CLICOM_ERR_INVALID_STATE, "Push while stopped");

    /* Start audio */
    TEST_ASSERT(clicom_audio_start(engine) == CLICOM_OK, "Start audio");
    TEST_ASSERT(clicom_get_audio_status(engine, &a_status) == CLICOM_OK, "Get audio status");
    TEST_ASSERT(a_status.state == CLICOM_AUDIO_RUNNING, "Audio state RUNNING");

    /* Push 4 frames into capture queue (fills capacity) */
    for (int i = 0; i < 4; ++i) {
        frame.pcm_data[0] = (int16_t)(1000 + i);
        TEST_ASSERT(clicom_audio_queue_push_capture(engine, &frame) == CLICOM_OK, "Push frame to queue");
    }

    TEST_ASSERT(clicom_get_audio_status(engine, &a_status) == CLICOM_OK, "Check queue depth 4");
    TEST_ASSERT(a_status.capture_queue_depth == 4, "Queue depth should be 4");

    /* 5th push must hit CLICOM_ERR_QUEUE_FULL */
    TEST_ASSERT(clicom_audio_queue_push_capture(engine, &frame) == CLICOM_ERR_QUEUE_FULL, "Queue full on 5th frame");
    TEST_ASSERT(clicom_get_audio_status(engine, &a_status) == CLICOM_OK, "Status after queue full");
    TEST_ASSERT(a_status.total_frames_dropped == 1, "Dropped frames count should be 1");

    /* Pop all 4 frames in FIFO order */
    for (int i = 0; i < 4; ++i) {
        ClicomAudioFrame out_frame;
        TEST_ASSERT(clicom_audio_queue_pop_capture(engine, &out_frame) == CLICOM_OK, "Pop frame from queue");
        TEST_ASSERT(out_frame.pcm_data[0] == (int16_t)(1000 + i), "FIFO order validation");
    }

    /* 5th pop must hit CLICOM_ERR_QUEUE_EMPTY */
    ClicomAudioFrame empty_frame;
    TEST_ASSERT(clicom_audio_queue_pop_capture(engine, &empty_frame) == CLICOM_ERR_QUEUE_EMPTY, "Pop from empty queue");

    /* Playback queue testing & clear */
    TEST_ASSERT(clicom_audio_queue_push_playback(engine, &frame) == CLICOM_OK, "Push playback frame");
    TEST_ASSERT(clicom_get_audio_status(engine, &a_status) == CLICOM_OK, "Playback queue depth 1");
    TEST_ASSERT(a_status.playback_queue_depth == 1, "Playback queue depth should be 1");

    TEST_ASSERT(clicom_audio_queue_clear(engine) == CLICOM_OK, "Clear audio queues");
    TEST_ASSERT(clicom_get_audio_status(engine, &a_status) == CLICOM_OK, "Status after clear");
    TEST_ASSERT(a_status.playback_queue_depth == 0, "Playback queue should be cleared to 0");

    /* Stop audio drains and resets */
    TEST_ASSERT(clicom_audio_stop(engine) == CLICOM_OK, "Stop audio");
    TEST_ASSERT(clicom_get_audio_status(engine, &a_status) == CLICOM_OK, "Status after stop");
    TEST_ASSERT(a_status.state == CLICOM_AUDIO_STOPPED, "State should be STOPPED");

    clicom_engine_destroy(engine);
    return 1;
}

/* ── Test 10: Thread Safety / Concurrent Access ──────────────────────────── */
typedef struct WorkerArgs {
    ClicomEngine* engine;
    int worker_id;
    int iterations;
} WorkerArgs;

#if defined(_WIN32) || defined(__CYGWIN__)
static DWORD WINAPI worker_thread_func(LPVOID param) {
#else
static void* worker_thread_func(void* param) {
#endif
    WorkerArgs* args = (WorkerArgs*)param;
    ClicomEngine* engine = args->engine;

    for (int i = 0; i < args->iterations; ++i) {
        /* Set/get display name */
        char name[32];
        snprintf(name, sizeof(name), "Worker-%d-%d", args->worker_id, i);
        clicom_set_display_name(engine, name);

        char read_name[CLICOM_MAX_NAME_LEN];
        clicom_get_display_name(engine, read_name, sizeof(read_name));

        /* Toggle mic and gain */
        clicom_set_mic_muted(engine, (i % 2 == 0));
        clicom_set_mic_gain(engine, 0.5f + (float)(i % 10) * 0.1f);

        /* Audio frames push / pop */
        ClicomAudioFrame frame = {0};
        frame.num_samples = 240;
        frame.pcm_data[0] = (int16_t)i;
        if (clicom_audio_queue_push_capture(engine, &frame) == CLICOM_OK) {
            ClicomAudioFrame out;
            clicom_audio_queue_pop_capture(engine, &out);
        }

        /* Participant add/update */
        ClicomParticipant p = {0};
        snprintf(p.participant_id, sizeof(p.participant_id), "part-%d", args->worker_id);
        snprintf(p.display_name, sizeof(p.display_name), "Disp-%d", args->worker_id);
        clicom_participant_add(engine, &p);
    }

#if defined(_WIN32) || defined(__CYGWIN__)
    return 0;
#else
    return NULL;
#endif
}

static int test_thread_safety(void) {
    ClicomEngine* engine = NULL;
    ClicomConfig cfg = {0};
    cfg.max_audio_queue_frames = 32;
    cfg.max_participants = 16;

    TEST_ASSERT(clicom_engine_create(&engine) == CLICOM_OK, "Create engine");
    TEST_ASSERT(clicom_engine_init(engine, &cfg) == CLICOM_OK, "Init engine");
    TEST_ASSERT(clicom_audio_start(engine) == CLICOM_OK, "Start audio");

    const int NUM_THREADS = 4;
    TestThread threads[4];
    WorkerArgs args[4];

    for (int i = 0; i < NUM_THREADS; ++i) {
        args[i].engine = engine;
        args[i].worker_id = i;
        args[i].iterations = 100;

#if defined(_WIN32) || defined(__CYGWIN__)
        threads[i] = CreateThread(NULL, 0, worker_thread_func, &args[i], 0, NULL);
        TEST_ASSERT(threads[i] != NULL, "CreateThread failed");
#else
        int rc = pthread_create(&threads[i], NULL, worker_thread_func, &args[i]);
        TEST_ASSERT(rc == 0, "pthread_create failed");
#endif
    }

    /* Wait for all threads to complete */
    for (int i = 0; i < NUM_THREADS; ++i) {
#if defined(_WIN32) || defined(__CYGWIN__)
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
#else
        pthread_join(threads[i], NULL);
#endif
    }

    ClicomEngineStatus status;
    TEST_ASSERT(clicom_engine_get_status(engine, &status) == CLICOM_OK, "Get status after concurrent runs");
    TEST_ASSERT(status.state == CLICOM_ENGINE_RUNNING, "Engine should remain RUNNING");

    clicom_engine_destroy(engine);
    return 1;
}

/* ── Test Suite Runner ───────────────────────────────────────────────────── */
int main(void) {
    printf("====================================================\n");
    printf("  CLICOM Engine Unit Tests (Native Foundation)\n");
    printf("====================================================\n\n");

    RUN_TEST(test_version_and_errors);
    RUN_TEST(test_initialization_lifecycle);
    RUN_TEST(test_invalid_inputs);
    RUN_TEST(test_display_name_and_buffer_limits);
    RUN_TEST(test_microphone_and_ptt_state);
    RUN_TEST(test_room_and_participants);
    RUN_TEST(test_participant_capacity_limits);
    RUN_TEST(test_connection_and_telemetry);
    RUN_TEST(test_audio_lifecycle_and_bounded_queues);
    RUN_TEST(test_thread_safety);

    printf("\n====================================================\n");
    printf("  Results: %d / %d tests passed\n", g_tests_passed, g_tests_run);
    printf("====================================================\n");

    return (g_tests_passed == g_tests_run) ? 0 : 1;
}

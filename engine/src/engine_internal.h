/**
 * @file engine_internal.h
 * @brief Internal definitions and shared structures for CLICOM Engine
 */

#ifndef ENGINE_INTERNAL_H
#define ENGINE_INTERNAL_H

#include "clicom.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32) || defined(__CYGWIN__)
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    typedef CRITICAL_SECTION EngineLock;
#else
    #include <pthread.h>
    typedef pthread_mutex_t EngineLock;
#endif

struct ClipClientNet;

/* ── Bounded FIFO Audio Queue ────────────────────────────────────────────── */
typedef struct AudioQueue {
    ClicomAudioFrame* frames;
    uint32_t capacity;
    uint32_t head;
    uint32_t tail;
    uint32_t count;
} AudioQueue;

/* ── Engine Instance Structure ───────────────────────────────────────────── */
struct ClicomEngine {
    EngineLock lock;
    bool lock_initialized;

    ClicomEngineState state;
    uint64_t start_time_ms;

    /* Configuration */
    char display_name[CLICOM_MAX_NAME_LEN];

    /* Microphone State */
    ClicomMicState mic_state;

    /* Room and Session State (session.c) */
    ClicomRoomState room_state;
    ClicomParticipant* participants;
    uint32_t participant_count;
    uint32_t participant_capacity;

    /* Connection and Telemetry State */
    ClicomConnectionState conn_state;
    ClicomTelemetrySnapshot telemetry;

    /* Network Client (Phase 2A) */
    struct ClipClientNet* net;
    uint8_t room_session_uuid[16];
    bool room_session_active;

    /* Audio Hardware & Virtual Engine (Phase 3A) */
    void* audio_hw;                     /* Pointer to ClipAudioEngine */
    bool audio_hw_initialized;
    bool audio_mock_mode;               /* If true, forces mock virtual audio device */

    /* Audio Engine State (audio_state.c) */
    ClicomAudioEngineState audio_state;
    uint32_t audio_sample_rate;
    uint8_t audio_channels;
    AudioQueue capture_queue;
    AudioQueue playback_queue;
    uint64_t total_frames_pushed;
    uint64_t total_frames_popped;
    uint64_t total_frames_dropped;
};

/* ── Internal Synchronization & Timing Helpers ─────────────────────────── */
void engine_lock(ClicomEngine* engine);
void engine_unlock(ClicomEngine* engine);
uint64_t engine_get_time_ms(void);

/* ── Internal Audio Queue Helpers ────────────────────────────────────────── */
int32_t audio_queue_init(AudioQueue* q, uint32_t capacity);
void audio_queue_destroy(AudioQueue* q);
void audio_queue_clear_internal(AudioQueue* q);
int32_t audio_queue_push_internal(AudioQueue* q, const ClicomAudioFrame* frame);
int32_t audio_queue_pop_internal(AudioQueue* q, ClicomAudioFrame* out_frame);

/* ── Internal Session Helpers ────────────────────────────────────────────── */
void session_cleanup_internal(ClicomEngine* engine);
int32_t participant_add_internal(ClicomEngine* engine, const ClicomParticipant* participant);

/* ── Internal Network Helpers ────────────────────────────────────────────── */
void network_disconnect_internal(ClicomEngine* engine);

#endif /* ENGINE_INTERNAL_H */

/**
 * @file clicom.h
 * @brief CLICOM Native Foundation C API
 *
 * Software Version: 2.0.0
 *
 * This header defines the stable, versioned C interface for the CLICOM engine.
 * The API is designed for thread-safe access from both native C/C++ applications
 * and high-level language bindings such as Python ctypes.
 *
 * Memory Ownership Model:
 * - Engine instances are allocated by clicom_engine_create() and released by
 *   clicom_engine_destroy(). The engine owns its internal state and buffers.
 * - Out-parameters and buffer pointers passed to functions (e.g. char*, structs)
 *   must be allocated and owned by the caller. Buffer capacities are passed
 *   explicitly to prevent buffer overflows.
 * - String outputs are always null-terminated if sufficient buffer space is provided.
 *
 * Thread Safety:
 * - All engine API functions taking a valid ClicomEngine pointer are thread-safe,
 *   synchronized via internal locking primitives.
 * - Lifecycle functions (create/destroy) are deterministic.
 */

#ifndef CLICOM_H
#define CLICOM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Export / Import Macro ──────────────────────────────────────────────── */
#ifndef CLICOM_API
    #if defined(_WIN32) || defined(__CYGWIN__)
        #if defined(CLICOM_EXPORTS) || defined(CLICOM_BUILDING_DLL)
            #define CLICOM_API __declspec(dllexport)
        #elif defined(CLICOM_STATIC)
            #define CLICOM_API
        #else
            #define CLICOM_API __declspec(dllimport)
        #endif
    #elif defined(__GNUC__) && __GNUC__ >= 4
        #define CLICOM_API __attribute__((visibility("default")))
    #else
        #define CLICOM_API
    #endif
#endif

/* ── Version Definitions ─────────────────────────────────────────────────── */
#define CLICOM_VERSION_MAJOR 2
#define CLICOM_VERSION_MINOR 0
#define CLICOM_VERSION_PATCH 0
#define CLICOM_VERSION_STRING "2.0.0"

/* ── Buffer Size Limits ─────────────────────────────────────────────────── */
#define CLICOM_MAX_NAME_LEN           64u
#define CLICOM_MAX_ROOM_ID_LEN        64u
#define CLICOM_MAX_KEY_LEN            64u
#define CLICOM_MAX_UUID_LEN           40u
#define CLICOM_AUDIO_MAX_SAMPLES      960u  /* 20ms at 48kHz (mono or interleaved) */

/* ── Error Codes ────────────────────────────────────────────────────────── */
typedef enum ClicomError {
    CLICOM_OK                        =  0,  /**< Operation completed successfully */
    CLICOM_ERR_GENERIC               = -1,  /**< Unspecified internal error */
    CLICOM_ERR_INVALID_ARG           = -2,  /**< Invalid argument or parameter range */
    CLICOM_ERR_NULL_POINTER          = -3,  /**< Unexpected NULL pointer */
    CLICOM_ERR_NOT_INITIALIZED       = -4,  /**< Engine is not initialized */
    CLICOM_ERR_ALREADY_INITIALIZED   = -5,  /**< Engine is already initialized */
    CLICOM_ERR_BUFFER_TOO_SMALL      = -6,  /**< Provided buffer too small for output */
    CLICOM_ERR_INVALID_STATE         = -7,  /**< Operation invalid in current state */
    CLICOM_ERR_QUEUE_FULL            = -8,  /**< Bounded audio queue has reached capacity */
    CLICOM_ERR_QUEUE_EMPTY           = -9,  /**< Bounded audio queue is empty */
    CLICOM_ERR_NOT_FOUND             = -10, /**< Requested item or participant not found */
    CLICOM_ERR_OUT_OF_MEMORY         = -11, /**< Memory allocation failure */
    CLICOM_ERR_LIMIT_REACHED         = -12, /**< Maximum participant or resource limit reached */
    CLICOM_ERR_SHUTDOWN              = -13, /**< Engine is shutting down or has shut down */
    CLICOM_ERR_NETWORK_DISCONNECTED  = -14, /**< Not connected to server */
    CLICOM_ERR_CONNECTION_FAILED     = -15, /**< Failed to establish network connection */
    CLICOM_ERR_UNAUTHORIZED          = -16, /**< Unauthorized action or owner-only restriction */
    CLICOM_ERR_REVOKED               = -17, /**< Key or credential has been revoked */
    CLICOM_ERR_RATE_LIMITED          = -18, /**< Action rejected due to rate limiting */
    CLICOM_ERR_PTT_BUSY              = -19, /**< PTT floor is currently held by another member */
    CLICOM_ERR_AUDIO_DEVICE          = -20  /**< Failed to open audio hardware device */
} ClicomError;

/* ── Engine State Enums ─────────────────────────────────────────────────── */
typedef enum ClicomEngineState {
    CLICOM_ENGINE_UNINITIALIZED = 0,
    CLICOM_ENGINE_INITIALIZING  = 1,
    CLICOM_ENGINE_RUNNING       = 2,
    CLICOM_ENGINE_STOPPING      = 3,
    CLICOM_ENGINE_SHUTDOWN      = 4
} ClicomEngineState;

typedef enum ClicomRoomJoinState {
    CLICOM_ROOM_DISCONNECTED = 0,
    CLICOM_ROOM_JOINING      = 1,
    CLICOM_ROOM_JOINED       = 2,
    CLICOM_ROOM_LEAVING      = 3
} ClicomRoomJoinState;

typedef enum ClicomConnectionState {
    CLICOM_CONN_DISCONNECTED = 0,
    CLICOM_CONN_CONNECTING   = 1,
    CLICOM_CONN_CONNECTED    = 2,
    CLICOM_CONN_RECONNECTING = 3,
    CLICOM_CONN_FAILED       = 4
} ClicomConnectionState;

typedef enum ClicomAudioEngineState {
    CLICOM_AUDIO_STOPPED  = 0,
    CLICOM_AUDIO_STARTING = 1,
    CLICOM_AUDIO_RUNNING  = 2,
    CLICOM_AUDIO_PAUSED   = 3,
    CLICOM_AUDIO_ERROR    = 4
} ClicomAudioEngineState;

/* ── Configuration & Status Structs ──────────────────────────────────────── */

/** Configuration structure passed to clicom_engine_init() */
typedef struct ClicomConfig {
    const char* client_display_name;   /**< Initial display name (optional, can be NULL) */
    uint32_t max_audio_queue_frames;   /**< Capacity of bounded audio queues (0 = default 64) */
    uint32_t max_participants;         /**< Capacity of room participant table (0 = default 64) */
    uint32_t audio_sample_rate;        /**< Target audio sample rate, e.g. 48000 (0 = default 48000) */
    uint8_t  audio_channels;           /**< Target audio channels, e.g. 1 or 2 (0 = default 1) */
} ClicomConfig;

/** Snapshot of high-level engine status */
typedef struct ClicomEngineStatus {
    ClicomEngineState state;
    uint64_t uptime_ms;
    uint32_t active_participants;
    bool is_audio_running;
    bool is_mic_muted;
    bool is_ptt_active;
} ClicomEngineStatus;

/** Local microphone and input status */
typedef struct ClicomMicState {
    bool is_muted;
    bool is_ptt_active;
    float gain;                        /**< Gain multiplier: 0.0f (silence) to 2.0f (+6dB) */
} ClicomMicState;

/** Room and membership status */
typedef struct ClicomRoomState {
    ClicomRoomJoinState state;
    char room_id[CLICOM_MAX_ROOM_ID_LEN];
    char join_key[CLICOM_MAX_KEY_LEN];
    char active_speaker_id[CLICOM_MAX_UUID_LEN];
    uint32_t participant_count;
} ClicomRoomState;

/** Participant metadata */
typedef struct ClicomParticipant {
    char participant_id[CLICOM_MAX_UUID_LEN];
    char display_name[CLICOM_MAX_NAME_LEN];
    bool is_speaking;
    bool is_muted;
    uint64_t joined_at_ms;
} ClicomParticipant;

/** Telemetry snapshot */
typedef struct ClicomTelemetrySnapshot {
    ClicomConnectionState conn_state;
    uint32_t rtt_ms;
    float packet_loss_pct;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t frames_sent;
    uint64_t frames_received;
    uint64_t frames_dropped;
    float jitter_ms;
    uint64_t timestamp_ms;
} ClicomTelemetrySnapshot;

/** Audio frame representation */
typedef struct ClicomAudioFrame {
    uint64_t timestamp_ns;
    uint32_t sample_rate;
    uint8_t channels;
    uint16_t num_samples;
    int16_t pcm_data[CLICOM_AUDIO_MAX_SAMPLES];
} ClicomAudioFrame;

/** Audio engine status and queue metrics */
typedef struct ClicomAudioStatus {
    ClicomAudioEngineState state;
    uint32_t sample_rate;
    uint8_t channels;
    uint32_t capture_queue_depth;
    uint32_t capture_queue_capacity;
    uint32_t playback_queue_depth;
    uint32_t playback_queue_capacity;
    uint64_t total_frames_pushed;
    uint64_t total_frames_popped;
    uint64_t total_frames_dropped;
} ClicomAudioStatus;

/* ── Opaque Engine Handle ────────────────────────────────────────────────── */
typedef struct ClicomEngine ClicomEngine;

/* ── Version & Error Query API ───────────────────────────────────────────── */

/**
 * @brief Get the numeric 32-bit version code (MAJOR.MINOR.PATCH in hex/packed format: 0xMMmmPP00).
 */
CLICOM_API uint32_t clicom_get_version(void);

/**
 * @brief Get the semantic version string (e.g. "2.0.0").
 */
CLICOM_API const char* clicom_get_version_string(void);

/**
 * @brief Convert a ClicomError code into a human-readable English string.
 */
CLICOM_API const char* clicom_error_string(int32_t error_code);

/* ── Engine Lifecycle API ────────────────────────────────────────────────── */

/**
 * @brief Allocate a new, uninitialized engine handle.
 *
 * @param out_engine Output pointer to receive the created handle.
 * @return CLICOM_OK on success, or structured error code.
 */
CLICOM_API int32_t clicom_engine_create(ClicomEngine** out_engine);

/**
 * @brief Initialize engine components with configuration parameters.
 *
 * @param engine Valid pointer returned from clicom_engine_create.
 * @param config Optional configuration settings (may be NULL for defaults).
 * @return CLICOM_OK on success, or structured error code.
 */
CLICOM_API int32_t clicom_engine_init(ClicomEngine* engine, const ClicomConfig* config);

/**
 * @brief Transition engine to SHUTDOWN state and release active resources.
 * Safe to invoke multiple times deterministically.
 *
 * @param engine Pointer to engine instance.
 * @return CLICOM_OK on success.
 */
CLICOM_API int32_t clicom_engine_shutdown(ClicomEngine* engine);

/**
 * @brief Destroy the engine instance and deallocate all underlying memory.
 * Safely handles already shut-down or NULL engines.
 *
 * @param engine Pointer to engine instance.
 */
CLICOM_API void clicom_engine_destroy(ClicomEngine* engine);

/**
 * @brief Retrieve a snapshot of the engine status.
 *
 * @param engine Pointer to engine instance.
 * @param out_status Output buffer for engine status.
 * @return CLICOM_OK on success, or structured error code.
 */
CLICOM_API int32_t clicom_engine_get_status(ClicomEngine* engine, ClicomEngineStatus* out_status);

/* ── Display Name Configuration API ──────────────────────────────────────── */

/**
 * @brief Set the local client display name.
 *
 * Validates display name: must be non-empty, null-terminated, and between 1 and 63 bytes.
 *
 * @param engine Pointer to engine instance.
 * @param name Null-terminated display name string.
 * @return CLICOM_OK on success, or CLICOM_ERR_INVALID_ARG.
 */
CLICOM_API int32_t clicom_set_display_name(ClicomEngine* engine, const char* name);

/**
 * @brief Copy the current display name into a caller-provided buffer.
 *
 * @param engine Pointer to engine instance.
 * @param out_buf Caller buffer to receive null-terminated string.
 * @param buf_len Length of out_buf in bytes.
 * @return CLICOM_OK on success, or CLICOM_ERR_BUFFER_TOO_SMALL.
 */
CLICOM_API int32_t clicom_get_display_name(ClicomEngine* engine, char* out_buf, size_t buf_len);

/* ── Local Microphone State API ──────────────────────────────────────────── */

/**
 * @brief Set microphone mute state.
 */
CLICOM_API int32_t clicom_set_mic_muted(ClicomEngine* engine, bool muted);

/**
 * @brief Query microphone mute state.
 */
CLICOM_API int32_t clicom_is_mic_muted(ClicomEngine* engine, bool* out_muted);

/**
 * @brief Set push-to-talk (PTT) active floor state.
 */
CLICOM_API int32_t clicom_set_ptt_active(ClicomEngine* engine, bool active);

/**
 * @brief Query push-to-talk (PTT) active floor state.
 */
CLICOM_API int32_t clicom_is_ptt_active(ClicomEngine* engine, bool* out_active);

/**
 * @brief Set microphone software gain multiplier.
 *
 * @param gain Gain value between 0.0f and 2.0f.
 */
CLICOM_API int32_t clicom_set_mic_gain(ClicomEngine* engine, float gain);

/**
 * @brief Query microphone software gain multiplier.
 */
CLICOM_API int32_t clicom_get_mic_gain(ClicomEngine* engine, float* out_gain);

/**
 * @brief Get complete local microphone state snapshot.
 */
CLICOM_API int32_t clicom_get_mic_state(ClicomEngine* engine, ClicomMicState* out_state);

/* ── Room & Session Management API (session.c) ───────────────────────────── */

/**
 * @brief Set local room membership state to joined.
 *
 * In this foundation phase, updates local room state without active network transmission.
 */
CLICOM_API int32_t clicom_room_join(ClicomEngine* engine, const char* room_id, const char* join_key);

/**
 * @brief Leave the current room and reset participant metadata.
 */
CLICOM_API int32_t clicom_room_leave(ClicomEngine* engine);

/**
 * @brief Get the current room state snapshot.
 */
CLICOM_API int32_t clicom_get_room_state(ClicomEngine* engine, ClicomRoomState* out_state);

/**
 * @brief Add or update a participant in the local room table.
 */
CLICOM_API int32_t clicom_participant_add(ClicomEngine* engine, const ClicomParticipant* participant);

/**
 * @brief Remove a participant by ID from the local room table.
 */
CLICOM_API int32_t clicom_participant_remove(ClicomEngine* engine, const char* participant_id);

/**
 * @brief Get the number of active participants in the room.
 */
CLICOM_API int32_t clicom_get_participant_count(ClicomEngine* engine, uint32_t* out_count);

/**
 * @brief Copy participant array into caller-provided buffer.
 *
 * @param engine Pointer to engine instance.
 * @param out_participants Caller allocated array.
 * @param max_count Maximum items out_participants can hold.
 * @param out_actual_count Receives the number of items written.
 */
CLICOM_API int32_t clicom_get_participants(ClicomEngine* engine,
                                           ClicomParticipant* out_participants,
                                           uint32_t max_count,
                                           uint32_t* out_actual_count);

/**
 * @brief Find participant by ID.
 */
CLICOM_API int32_t clicom_get_participant_by_id(ClicomEngine* engine,
                                                const char* participant_id,
                                                ClicomParticipant* out_participant);

/* ── Connection & Telemetry API ─────────────────────────────────────────── */

/**
 * @brief Query current connection state.
 */
CLICOM_API int32_t clicom_get_connection_state(ClicomEngine* engine, ClicomConnectionState* out_state);

/**
 * @brief Set current connection state (local engine state transition).
 */
CLICOM_API int32_t clicom_set_connection_state(ClicomEngine* engine, ClicomConnectionState state);

/**
 * @brief Retrieve a snapshot of the current connection telemetry.
 */
CLICOM_API int32_t clicom_get_telemetry(ClicomEngine* engine, ClicomTelemetrySnapshot* out_snapshot);

/**
 * @brief Update the telemetry snapshot.
 */
CLICOM_API int32_t clicom_update_telemetry(ClicomEngine* engine, const ClicomTelemetrySnapshot* snapshot);

/* ── Audio Engine Lifecycle & Bounded Queue API (audio_state.c) ──────────── */

/**
 * @brief Start the local audio engine state.
 */
CLICOM_API int32_t clicom_audio_start(ClicomEngine* engine);

/**
 * @brief Stop the local audio engine state and drain queues.
 */
CLICOM_API int32_t clicom_audio_stop(ClicomEngine* engine);

/**
 * @brief Get current audio status and queue depths.
 */
CLICOM_API int32_t clicom_get_audio_status(ClicomEngine* engine, ClicomAudioStatus* out_status);

/**
 * @brief Push an audio frame into the bounded capture queue.
 *
 * If the queue is at capacity, returns CLICOM_ERR_QUEUE_FULL and records a dropped frame.
 */
CLICOM_API int32_t clicom_audio_queue_push_capture(ClicomEngine* engine, const ClicomAudioFrame* frame);

/**
 * @brief Pop an audio frame from the capture queue.
 *
 * Returns CLICOM_ERR_QUEUE_EMPTY if no frames are available.
 */
CLICOM_API int32_t clicom_audio_queue_pop_capture(ClicomEngine* engine, ClicomAudioFrame* out_frame);

/**
 * @brief Push an audio frame into the bounded playback queue.
 *
 * If the queue is at capacity, returns CLICOM_ERR_QUEUE_FULL and records a dropped frame.
 */
CLICOM_API int32_t clicom_audio_queue_push_playback(ClicomEngine* engine, const ClicomAudioFrame* frame);

/**
 * @brief Pop an audio frame from the playback queue.
 *
 * Returns CLICOM_ERR_QUEUE_EMPTY if no frames are available.
 */
CLICOM_API int32_t clicom_audio_queue_pop_playback(ClicomEngine* engine, ClicomAudioFrame* out_frame);

/**
 * @brief Clear both capture and playback queues.
 */
CLICOM_API int32_t clicom_audio_queue_clear(ClicomEngine* engine);

/**
 * @brief Configure audio engine backend (real WinMM hardware vs in-memory mock for automated tests).
 *
 * @param engine Pointer to engine instance.
 * @param use_mock If true, forces in-memory synthetic audio mock backend; if false, uses WinMM hardware.
 * @return CLICOM_OK on success.
 */
CLICOM_API int32_t clicom_audio_set_mock_backend(ClicomEngine* engine, bool use_mock);

/**
 * @brief Retrieve current active room session UUID string if established.
 *
 * @param engine Pointer to engine instance.
 * @param out_buf Buffer to receive null-terminated UUID string.
 * @param buf_len Length of out_buf.
 * @return CLICOM_OK on success, or CLICOM_ERR_NO_SESSION.
 */
CLICOM_API int32_t clicom_get_active_session_id(ClicomEngine* engine, char* out_buf, size_t buf_len);

/**
 * @brief Query current audio hardware backend configuration.
 *
 * @param engine Pointer to engine instance.
 * @param out_backend Receives backend type (0 = MOCK, 1 = WINMM).
 * @param out_is_mock Receives true if running mock backend, false if real hardware.
 * @return CLICOM_OK on success.
 */
CLICOM_API int32_t clicom_audio_get_backend(ClicomEngine* engine, int32_t* out_backend, bool* out_is_mock);

/**
 * @brief Query physical audio devices detected on the host system.
 *
 * @param engine Pointer to engine instance.
 * @param out_inputs Receives number of recording/microphone devices.
 * @param out_outputs Receives number of playback/speaker devices.
 * @return CLICOM_OK on success.
 */
CLICOM_API int32_t clicom_audio_get_device_counts(ClicomEngine* engine, uint32_t* out_inputs, uint32_t* out_outputs);

/**
 * @brief Query server-authoritative PTT floor arbitration status.
 *
 * @param engine Pointer to engine instance.
 * @param out_floor_held Receives true if floor is currently occupied.
 * @param out_held_by_me Receives true if floor is held by this local client.
 * @param out_holder_id Optional buffer to receive UUID string or display name of holder.
 * @param id_buf_len Length of out_holder_id buffer.
 * @return CLICOM_OK on success.
 */
CLICOM_API int32_t clicom_get_floor_status(ClicomEngine* engine,
                                           bool* out_floor_held,
                                           bool* out_held_by_me,
                                           char* out_holder_id,
                                           size_t id_buf_len);

/**
 * @brief Refresh room participants list from the server.
 *
 * @param engine Pointer to engine instance.
 * @return CLICOM_OK on success.
 */
CLICOM_API int32_t clicom_network_refresh_participants(ClicomEngine* engine);

/* ── Network Engine API (Phase 2A) ────────────────────────────────────────── */

/**
 * @brief Connect the engine to a CLICOM TLS 1.3 server.
 *
 * Performs TLS handshake and registers the client using the current display name.
 *
 * @param engine Pointer to engine instance.
 * @param host Server hostname or IP address.
 * @param port Server port (e.g. 8443).
 * @param ca_cert_path Path to CA certificate for TLS verification (or NULL for default "certs/ca.crt").
 * @return CLICOM_OK on success, or structured error code.
 */
CLICOM_API int32_t clicom_network_connect(ClicomEngine* engine,
                                          const char* host,
                                          uint16_t port,
                                          const char* ca_cert_path);

/**
 * @brief Disconnect the engine from the CLICOM server.
 *
 * Safely leaves any active room and terminates the TLS connection.
 */
CLICOM_API int32_t clicom_network_disconnect(ClicomEngine* engine);

/**
 * @brief Check if the engine is currently connected to a server.
 */
CLICOM_API int32_t clicom_is_network_connected(ClicomEngine* engine, bool* out_connected);

/**
 * @brief Poll network events and process incoming protocol frames / heartbeats.
 *
 * @param engine Pointer to engine instance.
 * @param timeout_ms Timeout in milliseconds.
 * @return CLICOM_OK on success, or structured error code.
 */
CLICOM_API int32_t clicom_network_poll(ClicomEngine* engine, int32_t timeout_ms);

/**
 * @brief Create a new room on the server with specified member limit.
 *
 * Room creation is server-authoritative. Creator is automatically joined as room owner.
 *
 * @param engine Pointer to engine instance.
 * @param room_name Desired room name (1-63 chars).
 * @param member_limit Maximum participants (2-64).
 * @param out_room_id Buffer to receive generated room UUID string (at least CLICOM_MAX_ROOM_ID_LEN).
 * @param room_id_buf_len Length of out_room_id buffer.
 * @param out_join_key Buffer to receive generated invitation key string (at least CLICOM_MAX_KEY_LEN).
 * @param key_buf_len Length of out_join_key buffer.
 * @return CLICOM_OK on success, or structured error code.
 */
CLICOM_API int32_t clicom_network_create_room(ClicomEngine* engine,
                                              const char* room_name,
                                              uint32_t member_limit,
                                              char* out_room_id,
                                              size_t room_id_buf_len,
                                              char* out_join_key,
                                              size_t key_buf_len);

/**
 * @brief Join a room on the server using an invitation key.
 *
 * Server validates key and capacity atomically before confirming join.
 *
 * @param engine Pointer to engine instance.
 * @param join_key Cryptographic room invitation key.
 * @param out_room_id Buffer to receive joined room UUID string.
 * @param room_id_buf_len Length of out_room_id buffer.
 * @param out_room_name Buffer to receive room name string.
 * @param room_name_buf_len Length of out_room_name buffer.
 * @return CLICOM_OK on success, or structured error code (e.g. CLICOM_ERR_LIMIT_REACHED, CLICOM_ERR_NOT_FOUND, CLICOM_ERR_REVOKED).
 */
CLICOM_API int32_t clicom_network_join_room(ClicomEngine* engine,
                                            const char* join_key,
                                            char* out_room_id,
                                            size_t room_id_buf_len,
                                            char* out_room_name,
                                            size_t room_name_buf_len);

/**
 * @brief Leave the current server-managed room.
 */
CLICOM_API int32_t clicom_network_leave_room(ClicomEngine* engine);

/**
 * @brief Revoke the invitation key for the current room (owner-only).
 */
CLICOM_API int32_t clicom_network_revoke_invitation(ClicomEngine* engine);

/**
 * @brief Close and destroy the current room on the server (owner-only).
 */
CLICOM_API int32_t clicom_network_close_room(ClicomEngine* engine);

#ifdef __cplusplus
}
#endif

#endif /* CLICOM_H */

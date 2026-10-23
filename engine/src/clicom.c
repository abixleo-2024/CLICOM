/**
 * @file clicom.c
 * @brief Core CLICOM Engine Implementation
 */

#include "engine_internal.h"
#include "clip_audio.h"
#include "network.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define DEFAULT_AUDIO_QUEUE_FRAMES 64u
#define DEFAULT_MAX_PARTICIPANTS   64u
#define DEFAULT_AUDIO_SAMPLE_RATE  48000u
#define DEFAULT_AUDIO_CHANNELS     1u
#define DEFAULT_DISPLAY_NAME       "CLICOM-Node"

/* ── Platform-specific Helpers ───────────────────────────────────────────── */

void engine_lock(ClicomEngine* engine) {
    if (engine == NULL || !engine->lock_initialized) {
        return;
    }
#if defined(_WIN32) || defined(__CYGWIN__)
    EnterCriticalSection(&engine->lock);
#else
    pthread_mutex_lock(&engine->lock);
#endif
}

void engine_unlock(ClicomEngine* engine) {
    if (engine == NULL || !engine->lock_initialized) {
        return;
    }
#if defined(_WIN32) || defined(__CYGWIN__)
    LeaveCriticalSection(&engine->lock);
#else
    pthread_mutex_unlock(&engine->lock);
#endif
}

uint64_t engine_get_time_ms(void) {
#if defined(_WIN32) || defined(__CYGWIN__)
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
    }
    return 0;
#endif
}

/* ── Version & Error Query API ───────────────────────────────────────────── */

uint32_t clicom_get_version(void) {
    return ((uint32_t)CLICOM_VERSION_MAJOR << 24) |
           ((uint32_t)CLICOM_VERSION_MINOR << 16) |
           ((uint32_t)CLICOM_VERSION_PATCH << 8);
}

const char* clicom_get_version_string(void) {
    return CLICOM_VERSION_STRING;
}

const char* clicom_error_string(int32_t error_code) {
    switch (error_code) {
        case CLICOM_OK:
            return "Success";
        case CLICOM_ERR_GENERIC:
            return "Generic internal error";
        case CLICOM_ERR_INVALID_ARG:
            return "Invalid argument";
        case CLICOM_ERR_NULL_POINTER:
            return "Null pointer";
        case CLICOM_ERR_NOT_INITIALIZED:
            return "Engine not initialized";
        case CLICOM_ERR_ALREADY_INITIALIZED:
            return "Engine already initialized";
        case CLICOM_ERR_BUFFER_TOO_SMALL:
            return "Buffer too small";
        case CLICOM_ERR_INVALID_STATE:
            return "Invalid state transition";
        case CLICOM_ERR_QUEUE_FULL:
            return "Queue full";
        case CLICOM_ERR_QUEUE_EMPTY:
            return "Queue empty";
        case CLICOM_ERR_NOT_FOUND:
            return "Item not found";
        case CLICOM_ERR_OUT_OF_MEMORY:
            return "Out of memory";
        case CLICOM_ERR_LIMIT_REACHED:
            return "Capacity limit reached";
        case CLICOM_ERR_SHUTDOWN:
            return "Engine has shut down";
        case CLICOM_ERR_NETWORK_DISCONNECTED:
            return "Network disconnected";
        case CLICOM_ERR_CONNECTION_FAILED:
            return "Connection failed";
        case CLICOM_ERR_UNAUTHORIZED:
            return "Unauthorized action (owner-only)";
        case CLICOM_ERR_REVOKED:
            return "Invitation key has been revoked";
        case CLICOM_ERR_RATE_LIMITED:
            return "Request rate limited";
        case CLICOM_ERR_PTT_BUSY:
            return "PTT floor is busy";
        case CLICOM_ERR_AUDIO_DEVICE:
            return "Audio device error";
        default:
            return "Unknown error code";
    }
}

/* ── Engine Lifecycle API ────────────────────────────────────────────────── */

int32_t clicom_engine_create(ClicomEngine** out_engine) {
    if (out_engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    ClicomEngine* engine = (ClicomEngine*)calloc(1, sizeof(ClicomEngine));
    if (engine == NULL) {
        return CLICOM_ERR_OUT_OF_MEMORY;
    }

#if defined(_WIN32) || defined(__CYGWIN__)
    InitializeCriticalSection(&engine->lock);
#else
    if (pthread_mutex_init(&engine->lock, NULL) != 0) {
        free(engine);
        return CLICOM_ERR_GENERIC;
    }
#endif
    engine->lock_initialized = true;
    engine->state = CLICOM_ENGINE_UNINITIALIZED;

    *out_engine = engine;
    return CLICOM_OK;
}

int32_t clicom_engine_init(ClicomEngine* engine, const ClicomConfig* config) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);

    if (engine->state == CLICOM_ENGINE_RUNNING) {
        engine_unlock(engine);
        return CLICOM_ERR_ALREADY_INITIALIZED;
    }

    uint32_t queue_capacity = DEFAULT_AUDIO_QUEUE_FRAMES;
    uint32_t part_capacity = DEFAULT_MAX_PARTICIPANTS;
    uint32_t sample_rate = DEFAULT_AUDIO_SAMPLE_RATE;
    uint8_t channels = (uint8_t)DEFAULT_AUDIO_CHANNELS;
    const char* disp_name = DEFAULT_DISPLAY_NAME;

    if (config != NULL) {
        if (config->max_audio_queue_frames > 0) {
            queue_capacity = config->max_audio_queue_frames;
        }
        if (config->max_participants > 0) {
            part_capacity = config->max_participants;
        }
        if (config->audio_sample_rate > 0) {
            sample_rate = config->audio_sample_rate;
        }
        if (config->audio_channels > 0) {
            channels = config->audio_channels;
        }
        if (config->client_display_name != NULL && config->client_display_name[0] != '\0') {
            size_t name_len = strlen(config->client_display_name);
            if (name_len >= CLICOM_MAX_NAME_LEN) {
                engine_unlock(engine);
                return CLICOM_ERR_INVALID_ARG;
            }
            disp_name = config->client_display_name;
        }
    }

    /* Set Display Name */
    strncpy(engine->display_name, disp_name, CLICOM_MAX_NAME_LEN - 1);
    engine->display_name[CLICOM_MAX_NAME_LEN - 1] = '\0';

    /* Initialize Microphone Defaults */
    engine->mic_state.is_muted = false;
    engine->mic_state.is_ptt_active = false;
    engine->mic_state.gain = 1.0f;

    /* Initialize Connection & Telemetry Defaults */
    engine->conn_state = CLICOM_CONN_DISCONNECTED;
    memset(&engine->telemetry, 0, sizeof(engine->telemetry));
    engine->telemetry.conn_state = CLICOM_CONN_DISCONNECTED;
    engine->telemetry.timestamp_ms = engine_get_time_ms();

    /* Initialize Room & Participant Capacity */
    memset(&engine->room_state, 0, sizeof(engine->room_state));
    engine->room_state.state = CLICOM_ROOM_DISCONNECTED;
    engine->participant_count = 0;
    engine->participant_capacity = part_capacity;
    engine->participants = (ClicomParticipant*)calloc(part_capacity, sizeof(ClicomParticipant));
    if (engine->participants == NULL) {
        engine_unlock(engine);
        return CLICOM_ERR_OUT_OF_MEMORY;
    }

    /* Initialize Audio Subsystem State */
    engine->audio_state = CLICOM_AUDIO_STOPPED;
    engine->audio_sample_rate = sample_rate;
    engine->audio_channels = channels;
    engine->total_frames_pushed = 0;
    engine->total_frames_popped = 0;
    engine->total_frames_dropped = 0;

    int32_t q_rc = audio_queue_init(&engine->capture_queue, queue_capacity);
    if (q_rc != CLICOM_OK) {
        free(engine->participants);
        engine->participants = NULL;
        engine_unlock(engine);
        return q_rc;
    }

    q_rc = audio_queue_init(&engine->playback_queue, queue_capacity);
    if (q_rc != CLICOM_OK) {
        audio_queue_destroy(&engine->capture_queue);
        free(engine->participants);
        engine->participants = NULL;
        engine_unlock(engine);
        return q_rc;
    }

    engine->start_time_ms = engine_get_time_ms();
    engine->state = CLICOM_ENGINE_RUNNING;

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_engine_shutdown(ClicomEngine* engine) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);

    if (engine->state == CLICOM_ENGINE_SHUTDOWN || engine->state == CLICOM_ENGINE_UNINITIALIZED) {
        engine_unlock(engine);
        return CLICOM_OK; /* Safe repeated shutdown */
    }

    engine->state = CLICOM_ENGINE_STOPPING;

    /* Stop audio engine, hardware, and clear queues */
    engine->audio_state = CLICOM_AUDIO_STOPPED;
    if (engine->audio_hw_initialized && engine->audio_hw != NULL) {
        ClipAudioEngine* hw = (ClipAudioEngine*)engine->audio_hw;
        clip_audio_on_floor_released(hw);
        clip_audio_stop_playback(hw);
        clip_audio_engine_cleanup(hw);
        free(hw);
        engine->audio_hw = NULL;
        engine->audio_hw_initialized = false;
    }
    audio_queue_destroy(&engine->capture_queue);
    audio_queue_destroy(&engine->playback_queue);

    /* Disconnect network and cleanup network resources */
    network_disconnect_internal(engine);

    /* Clean up room & participants */
    session_cleanup_internal(engine);

    /* Reset connection state */
    engine->conn_state = CLICOM_CONN_DISCONNECTED;
    engine->telemetry.conn_state = CLICOM_CONN_DISCONNECTED;

    engine->state = CLICOM_ENGINE_SHUTDOWN;
    engine_unlock(engine);

    return CLICOM_OK;
}

void clicom_engine_destroy(ClicomEngine* engine) {
    if (engine == NULL) {
        return;
    }

    if (engine->state != CLICOM_ENGINE_SHUTDOWN) {
        clicom_engine_shutdown(engine);
    }

    if (engine->lock_initialized) {
#if defined(_WIN32) || defined(__CYGWIN__)
        DeleteCriticalSection(&engine->lock);
#else
        pthread_mutex_destroy(&engine->lock);
#endif
        engine->lock_initialized = false;
    }

    free(engine);
}

int32_t clicom_engine_get_status(ClicomEngine* engine, ClicomEngineStatus* out_status) {
    if (engine == NULL || out_status == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);

    out_status->state = engine->state;
    if (engine->state == CLICOM_ENGINE_RUNNING) {
        uint64_t now = engine_get_time_ms();
        out_status->uptime_ms = (now >= engine->start_time_ms) ? (now - engine->start_time_ms) : 0;
    } else {
        out_status->uptime_ms = 0;
    }

    out_status->active_participants = engine->participant_count;
    out_status->is_audio_running = (engine->audio_state == CLICOM_AUDIO_RUNNING);
    out_status->is_mic_muted = engine->mic_state.is_muted;
    out_status->is_ptt_active = engine->mic_state.is_ptt_active;

    engine_unlock(engine);
    return CLICOM_OK;
}

/* ── Display Name Configuration API ──────────────────────────────────────── */

int32_t clicom_set_display_name(ClicomEngine* engine, const char* name) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if (name == NULL) {
        return CLICOM_ERR_INVALID_ARG;
    }

    size_t len = strlen(name);
    if (len == 0 || len >= CLICOM_MAX_NAME_LEN) {
        return CLICOM_ERR_INVALID_ARG;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    memcpy(engine->display_name, name, len);
    engine->display_name[len] = '\0';

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_get_display_name(ClicomEngine* engine, char* out_buf, size_t buf_len) {
    if (engine == NULL || out_buf == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if (buf_len == 0) {
        return CLICOM_ERR_BUFFER_TOO_SMALL;
    }

    engine_lock(engine);
    size_t len = strlen(engine->display_name);
    if (buf_len <= len) {
        engine_unlock(engine);
        return CLICOM_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out_buf, engine->display_name, len + 1);
    engine_unlock(engine);
    return CLICOM_OK;
}

/* ── Local Microphone State API ──────────────────────────────────────────── */

int32_t clicom_set_mic_muted(ClicomEngine* engine, bool muted) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    engine->mic_state.is_muted = muted;

    if (muted) {
        audio_queue_clear_internal(&engine->capture_queue);
    }

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_is_mic_muted(ClicomEngine* engine, bool* out_muted) {
    if (engine == NULL || out_muted == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    *out_muted = engine->mic_state.is_muted;
    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_set_ptt_active(ClicomEngine* engine, bool active) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    if (active) {
        if (engine->mic_state.is_ptt_active) {
            engine_unlock(engine);
            return CLICOM_OK;
        }

        /* If connected to a network room session, request floor from server */
        if (engine->room_session_active && engine->net != NULL && engine->net->is_connected) {
            ClipPttFloor floor;
            ClipError denial = CLIP_OK;
            ClipError err = clip_client_ptt_request(engine->net,
                                                    (const ClipUuid*)engine->room_session_uuid,
                                                    10000,
                                                    &floor,
                                                    &denial);
            if (err != CLIP_OK) {
                engine->mic_state.is_ptt_active = false;
                engine_unlock(engine);
                return CLICOM_ERR_PTT_BUSY;
            }
        }

        engine->mic_state.is_ptt_active = true;
        if (engine->audio_hw_initialized && engine->audio_hw != NULL) {
            clip_audio_on_floor_granted((ClipAudioEngine*)engine->audio_hw);
        }
    } else {
        if (!engine->mic_state.is_ptt_active) {
            engine_unlock(engine);
            return CLICOM_OK;
        }

        engine->mic_state.is_ptt_active = false;
        if (engine->audio_hw_initialized && engine->audio_hw != NULL) {
            clip_audio_on_floor_released((ClipAudioEngine*)engine->audio_hw);
        }

        /* If connected to a network room session, release floor on server */
        if (engine->room_session_active && engine->net != NULL && engine->net->is_connected) {
            clip_client_ptt_release(engine->net, (const ClipUuid*)engine->room_session_uuid);
        }
    }

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_is_ptt_active(ClicomEngine* engine, bool* out_active) {
    if (engine == NULL || out_active == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    *out_active = engine->mic_state.is_ptt_active;
    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_set_mic_gain(ClicomEngine* engine, float gain) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if (gain < 0.0f || gain > 2.0f) {
        return CLICOM_ERR_INVALID_ARG;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    engine->mic_state.gain = gain;
    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_get_mic_gain(ClicomEngine* engine, float* out_gain) {
    if (engine == NULL || out_gain == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    *out_gain = engine->mic_state.gain;
    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_get_mic_state(ClicomEngine* engine, ClicomMicState* out_state) {
    if (engine == NULL || out_state == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    *out_state = engine->mic_state;
    engine_unlock(engine);
    return CLICOM_OK;
}

/* ── Connection & Telemetry API ─────────────────────────────────────────── */

int32_t clicom_get_connection_state(ClicomEngine* engine, ClicomConnectionState* out_state) {
    if (engine == NULL || out_state == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    *out_state = engine->conn_state;
    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_set_connection_state(ClicomEngine* engine, ClicomConnectionState state) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if ((int)state < (int)CLICOM_CONN_DISCONNECTED || (int)state > (int)CLICOM_CONN_FAILED) {
        return CLICOM_ERR_INVALID_ARG;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    engine->conn_state = state;
    engine->telemetry.conn_state = state;
    engine->telemetry.timestamp_ms = engine_get_time_ms();

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_get_telemetry(ClicomEngine* engine, ClicomTelemetrySnapshot* out_snapshot) {
    if (engine == NULL || out_snapshot == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    *out_snapshot = engine->telemetry;
    out_snapshot->conn_state = engine->conn_state;
    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_update_telemetry(ClicomEngine* engine, const ClicomTelemetrySnapshot* snapshot) {
    if (engine == NULL || snapshot == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if (snapshot->packet_loss_pct < 0.0f || snapshot->packet_loss_pct > 100.0f) {
        return CLICOM_ERR_INVALID_ARG;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    engine->telemetry = *snapshot;
    engine->conn_state = snapshot->conn_state;
    if (engine->telemetry.timestamp_ms == 0) {
        engine->telemetry.timestamp_ms = engine_get_time_ms();
    }

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_get_floor_status(ClicomEngine* engine,
                                bool* out_floor_held,
                                bool* out_held_by_me,
                                char* out_holder_id,
                                size_t id_buf_len)
{
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    bool floor_held = false;
    bool held_by_me = engine->mic_state.is_ptt_active;
    char holder_str[CLICOM_MAX_UUID_LEN] = {0};

    if (engine->net != NULL && engine->net->is_connected && engine->room_session_active) {
        ClipUuid holder_uuid;
        memset(&holder_uuid, 0, sizeof(holder_uuid));
        clip_client_get_floor_status(engine->net, &floor_held, &held_by_me, &holder_uuid);
        if (engine->mic_state.is_ptt_active) {
            held_by_me = true;
            floor_held = true;
        }
        if (held_by_me) {
            strncpy(holder_str, engine->display_name, sizeof(holder_str) - 1);
        } else if (floor_held && !clip_uuid_is_zero(&holder_uuid)) {
            clip_uuid_to_string(&holder_uuid, holder_str, sizeof(holder_str));
            /* Check if holder matches any local participant name */
            for (size_t i = 0; i < engine->participant_count; ++i) {
                if (strncmp(engine->participants[i].participant_id, holder_str, sizeof(holder_str)) == 0) {
                    strncpy(holder_str, engine->participants[i].display_name, sizeof(holder_str) - 1);
                    break;
                }
            }
        }
    } else {
        floor_held = held_by_me;
        if (held_by_me) {
            strncpy(holder_str, engine->display_name, sizeof(holder_str) - 1);
        }
    }

    if (floor_held && holder_str[0] != '\0') {
        strncpy(engine->room_state.active_speaker_id, holder_str, CLICOM_MAX_UUID_LEN - 1);
    } else if (!floor_held) {
        engine->room_state.active_speaker_id[0] = '\0';
    }

    if (out_floor_held) *out_floor_held = floor_held;
    if (out_held_by_me) *out_held_by_me = held_by_me;
    if (out_holder_id && id_buf_len > 0) {
        strncpy(out_holder_id, holder_str, id_buf_len - 1);
        out_holder_id[id_buf_len - 1] = '\0';
    }

    engine_unlock(engine);
    return CLICOM_OK;
}

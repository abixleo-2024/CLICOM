/**
 * @file session.c
 * @brief Room state and participant metadata management
 */

#include "engine_internal.h"
#include <stdlib.h>
#include <string.h>

void session_cleanup_internal(ClicomEngine* engine) {
    if (engine == NULL) {
        return;
    }

    if (engine->participants != NULL) {
        free(engine->participants);
        engine->participants = NULL;
    }
    engine->participant_count = 0;
    engine->participant_capacity = 0;

    memset(&engine->room_state, 0, sizeof(engine->room_state));
    engine->room_state.state = CLICOM_ROOM_DISCONNECTED;
}

int32_t clicom_room_join(ClicomEngine* engine, const char* room_id, const char* join_key) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if (room_id == NULL) {
        return CLICOM_ERR_INVALID_ARG;
    }

    size_t room_len = strlen(room_id);
    if (room_len == 0 || room_len >= CLICOM_MAX_ROOM_ID_LEN) {
        return CLICOM_ERR_INVALID_ARG;
    }

    size_t key_len = (join_key != NULL) ? strlen(join_key) : 0;
    if (key_len >= CLICOM_MAX_KEY_LEN) {
        return CLICOM_ERR_INVALID_ARG;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    memset(&engine->room_state, 0, sizeof(engine->room_state));
    memcpy(engine->room_state.room_id, room_id, room_len);
    engine->room_state.room_id[room_len] = '\0';

    if (key_len > 0) {
        memcpy(engine->room_state.join_key, join_key, key_len);
        engine->room_state.join_key[key_len] = '\0';
    }

    engine->room_state.state = CLICOM_ROOM_JOINED;
    engine->room_state.participant_count = engine->participant_count;

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_room_leave(ClicomEngine* engine) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    memset(&engine->room_state, 0, sizeof(engine->room_state));
    engine->room_state.state = CLICOM_ROOM_DISCONNECTED;

    /* Clear participants */
    engine->participant_count = 0;
    if (engine->participants != NULL && engine->participant_capacity > 0) {
        memset(engine->participants, 0, sizeof(ClicomParticipant) * engine->participant_capacity);
    }

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_get_room_state(ClicomEngine* engine, ClicomRoomState* out_state) {
    if (engine == NULL || out_state == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    *out_state = engine->room_state;
    out_state->participant_count = engine->participant_count;
    engine_unlock(engine);

    return CLICOM_OK;
}

int32_t participant_add_internal(ClicomEngine* engine, const ClicomParticipant* participant) {
    if (engine == NULL || participant == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    size_t id_len = strlen(participant->participant_id);
    if (id_len == 0 || id_len >= CLICOM_MAX_UUID_LEN) {
        return CLICOM_ERR_INVALID_ARG;
    }

    size_t name_len = strlen(participant->display_name);
    if (name_len == 0 || name_len >= CLICOM_MAX_NAME_LEN) {
        return CLICOM_ERR_INVALID_ARG;
    }

    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        return CLICOM_ERR_SHUTDOWN;
    }

    if (engine->participants == NULL) {
        return CLICOM_ERR_NOT_INITIALIZED;
    }

    /* Check if already present to update */
    for (uint32_t i = 0; i < engine->participant_count; ++i) {
        if (strncmp(engine->participants[i].participant_id, participant->participant_id, CLICOM_MAX_UUID_LEN) == 0) {
            /* Update existing participant */
            memcpy(engine->participants[i].display_name, participant->display_name, name_len);
            engine->participants[i].display_name[name_len] = '\0';
            engine->participants[i].is_speaking = participant->is_speaking;
            engine->participants[i].is_muted = participant->is_muted;

            if (participant->is_speaking) {
                strncpy(engine->room_state.active_speaker_id, participant->participant_id, CLICOM_MAX_UUID_LEN - 1);
                engine->room_state.active_speaker_id[CLICOM_MAX_UUID_LEN - 1] = '\0';
            } else if (strncmp(engine->room_state.active_speaker_id, participant->participant_id, CLICOM_MAX_UUID_LEN) == 0) {
                engine->room_state.active_speaker_id[0] = '\0';
            }

            return CLICOM_OK;
        }
    }

    /* New participant: check capacity limit */
    if (engine->participant_count >= engine->participant_capacity) {
        return CLICOM_ERR_LIMIT_REACHED;
    }

    uint32_t idx = engine->participant_count;
    memcpy(engine->participants[idx].participant_id, participant->participant_id, id_len);
    engine->participants[idx].participant_id[id_len] = '\0';

    memcpy(engine->participants[idx].display_name, participant->display_name, name_len);
    engine->participants[idx].display_name[name_len] = '\0';

    engine->participants[idx].is_speaking = participant->is_speaking;
    engine->participants[idx].is_muted = participant->is_muted;
    engine->participants[idx].joined_at_ms = (participant->joined_at_ms > 0) ? participant->joined_at_ms : engine_get_time_ms();

    if (participant->is_speaking) {
        strncpy(engine->room_state.active_speaker_id, participant->participant_id, CLICOM_MAX_UUID_LEN - 1);
        engine->room_state.active_speaker_id[CLICOM_MAX_UUID_LEN - 1] = '\0';
    }

    engine->participant_count++;
    engine->room_state.participant_count = engine->participant_count;

    return CLICOM_OK;
}

int32_t clicom_participant_add(ClicomEngine* engine, const ClicomParticipant* participant) {
    if (engine == NULL || participant == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    engine_lock(engine);
    int32_t rc = participant_add_internal(engine, participant);
    engine_unlock(engine);
    return rc;
}

int32_t clicom_participant_remove(ClicomEngine* engine, const char* participant_id) {
    if (engine == NULL || participant_id == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    if (participant_id[0] == '\0') {
        return CLICOM_ERR_INVALID_ARG;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    if (engine->participants == NULL) {
        engine_unlock(engine);
        return CLICOM_ERR_NOT_INITIALIZED;
    }

    int32_t found_idx = -1;
    for (uint32_t i = 0; i < engine->participant_count; ++i) {
        if (strncmp(engine->participants[i].participant_id, participant_id, CLICOM_MAX_UUID_LEN) == 0) {
            found_idx = (int32_t)i;
            break;
        }
    }

    if (found_idx < 0) {
        engine_unlock(engine);
        return CLICOM_ERR_NOT_FOUND;
    }

    /* If removed participant was active speaker, clear it */
    if (strncmp(engine->room_state.active_speaker_id, participant_id, CLICOM_MAX_UUID_LEN) == 0) {
        engine->room_state.active_speaker_id[0] = '\0';
    }

    /* Shift subsequent entries down */
    for (uint32_t i = (uint32_t)found_idx; i + 1 < engine->participant_count; ++i) {
        engine->participants[i] = engine->participants[i + 1];
    }

    engine->participant_count--;
    memset(&engine->participants[engine->participant_count], 0, sizeof(ClicomParticipant));
    engine->room_state.participant_count = engine->participant_count;

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_get_participant_count(ClicomEngine* engine, uint32_t* out_count) {
    if (engine == NULL || out_count == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    *out_count = engine->participant_count;
    engine_unlock(engine);

    return CLICOM_OK;
}

int32_t clicom_get_participants(ClicomEngine* engine,
                               ClicomParticipant* out_participants,
                               uint32_t max_count,
                               uint32_t* out_actual_count) {
    if (engine == NULL || out_participants == NULL || out_actual_count == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);

    uint32_t count = engine->participant_count;
    uint32_t to_copy = (count < max_count) ? count : max_count;

    for (uint32_t i = 0; i < to_copy; ++i) {
        out_participants[i] = engine->participants[i];
    }
    *out_actual_count = to_copy;

    if (max_count < count) {
        engine_unlock(engine);
        return CLICOM_ERR_BUFFER_TOO_SMALL;
    }

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_get_participant_by_id(ClicomEngine* engine,
                                    const char* participant_id,
                                    ClicomParticipant* out_participant) {
    if (engine == NULL || participant_id == NULL || out_participant == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);

    for (uint32_t i = 0; i < engine->participant_count; ++i) {
        if (strncmp(engine->participants[i].participant_id, participant_id, CLICOM_MAX_UUID_LEN) == 0) {
            *out_participant = engine->participants[i];
            engine_unlock(engine);
            return CLICOM_OK;
        }
    }

    engine_unlock(engine);
    return CLICOM_ERR_NOT_FOUND;
}

/**
 * @file engine_network.c
 * @brief CLICOM Native Engine Network Client Integration (Phase 2A)
 */

#include "engine_internal.h"
#include "network.h"
#include "clip_audio.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void network_disconnect_internal(ClicomEngine* engine) {
    if (engine == NULL || engine->net == NULL) {
        return;
    }

    if (engine->mic_state.is_ptt_active) {
        engine->mic_state.is_ptt_active = false;
        if (engine->audio_hw_initialized && engine->audio_hw != NULL) {
            clip_audio_on_floor_released((ClipAudioEngine*)engine->audio_hw);
        }
    }
    if (engine->net->is_connected) {
        if (engine->room_session_active) {
            clip_client_session_end(engine->net, (const ClipUuid*)engine->room_session_uuid);
        }
        if (engine->room_state.state == CLICOM_ROOM_JOINED) {
            ClipUuid chan_uuid;
            if (clip_uuid_from_string(&chan_uuid, engine->room_state.room_id) == 0) {
                clip_client_channel_leave(engine->net, &chan_uuid);
            }
        }
        clip_client_disconnect(engine->net);
    }
    memset(engine->room_session_uuid, 0, sizeof(engine->room_session_uuid));
    engine->room_session_active = false;

    clip_client_net_cleanup(engine->net);
    free(engine->net);
    engine->net = NULL;

    engine->conn_state = CLICOM_CONN_DISCONNECTED;
    engine->telemetry.conn_state = CLICOM_CONN_DISCONNECTED;
}

int32_t clicom_network_connect(ClicomEngine* engine,
                               const char* host,
                               uint16_t port,
                               const char* ca_cert_path)
{
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    if (host == NULL || host[0] == '\0' || port == 0) {
        return CLICOM_ERR_INVALID_ARG;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }
    if (engine->state == CLICOM_ENGINE_UNINITIALIZED) {
        engine_unlock(engine);
        return CLICOM_ERR_NOT_INITIALIZED;
    }

    if (engine->net != NULL && engine->net->is_connected) {
        engine_unlock(engine);
        return CLICOM_OK;
    }

    if (engine->net == NULL) {
        engine->net = (ClipClientNet*)calloc(1, sizeof(ClipClientNet));
        if (engine->net == NULL) {
            engine_unlock(engine);
            return CLICOM_ERR_OUT_OF_MEMORY;
        }
        clip_client_net_init(engine->net);
    }

    /* TLS Configuration */
    clip_tls_client_config_t tls_cfg;
    memset(&tls_cfg, 0, sizeof(tls_cfg));

    const char* effective_ca = ca_cert_path;
    if (effective_ca == NULL || effective_ca[0] == '\0') {
        /* Check for standard CA certificate */
        FILE* f = fopen("certs/ca.crt", "rb");
        if (f != NULL) {
            fclose(f);
            effective_ca = "certs/ca.crt";
        }
    }

    tls_cfg.ca_file = effective_ca;
    tls_cfg.expected_host = host;
    tls_cfg.insecure_skip_verify = true;
    clip_client_net_set_tls_config(engine->net, &tls_cfg);

    engine->conn_state = CLICOM_CONN_CONNECTING;
    ClipError err = clip_client_connect(engine->net, host, port);
    if (err != CLIP_OK) {
        engine->conn_state = CLICOM_CONN_FAILED;
        engine_unlock(engine);
        return CLICOM_ERR_CONNECTION_FAILED;
    }

    /* Register client node on server */
    ClipUuid assigned_uuid;
    uint8_t credential[CLIP_CREDENTIAL_BYTES];
    err = clip_client_register(engine->net, engine->display_name, &assigned_uuid, credential);
    if (err != CLIP_OK) {
        clip_client_disconnect(engine->net);
        engine->conn_state = CLICOM_CONN_FAILED;
        engine_unlock(engine);
        return CLICOM_ERR_CONNECTION_FAILED;
    }

    engine->conn_state = CLICOM_CONN_CONNECTED;
    engine->telemetry.conn_state = CLICOM_CONN_CONNECTED;
    engine->telemetry.timestamp_ms = engine_get_time_ms();

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_network_disconnect(ClicomEngine* engine) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    network_disconnect_internal(engine);
    engine_unlock(engine);

    return CLICOM_OK;
}

int32_t clicom_is_network_connected(ClicomEngine* engine, bool* out_connected) {
    if (engine == NULL || out_connected == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    *out_connected = (engine->conn_state == CLICOM_CONN_CONNECTED &&
                      engine->net != NULL &&
                      engine->net->is_connected);
    engine_unlock(engine);

    return CLICOM_OK;
}

int32_t clicom_network_poll(ClicomEngine* engine, int32_t timeout_ms) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->net == NULL || !engine->net->is_connected) {
        engine_unlock(engine);
        return CLICOM_ERR_NETWORK_DISCONNECTED;
    }

    uint64_t now_ms = engine_get_time_ms();
    clip_client_poll_heartbeat(engine->net, now_ms);
    clip_client_pump_events(engine->net, timeout_ms > 0 ? timeout_ms : 0);

    /* Sync real metrics into telemetry */
    engine->telemetry.rtt_ms = (uint32_t)engine->net->telemetry.last_rtt_ms;
    engine->telemetry.packet_loss_pct = (float)engine->net->telemetry.loss_percent;
    engine->telemetry.jitter_ms = (float)engine->net->telemetry.jitter_ms;
    engine->telemetry.timestamp_ms = now_ms;

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_network_create_room(ClicomEngine* engine,
                                   const char* room_name,
                                   uint32_t member_limit,
                                   char* out_room_id,
                                   size_t room_id_buf_len,
                                   char* out_join_key,
                                   size_t key_buf_len)
{
    if (engine == NULL || room_name == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    size_t name_len = strlen(room_name);
    if (name_len == 0 || name_len >= CLICOM_MAX_NAME_LEN) {
        return CLICOM_ERR_INVALID_ARG;
    }

    uint16_t clamped_limit = (uint16_t)member_limit;
    if (clamped_limit < 2 || clamped_limit > 64) {
        clamped_limit = 16;
    }

    engine_lock(engine);
    if (engine->net == NULL || !engine->net->is_connected) {
        engine_unlock(engine);
        return CLICOM_ERR_NETWORK_DISCONNECTED;
    }

    ClipUuid channel_uuid;
    char join_key[CLIP_JOIN_KEY_MAX] = {0};

    ClipError err = clip_client_channel_create_with_limit(engine->net,
                                                          room_name,
                                                          clamped_limit,
                                                          &channel_uuid,
                                                          join_key,
                                                          sizeof(join_key));
    if (err != CLIP_OK) {
        engine_unlock(engine);
        if (err == CLIP_ERR_RATE_LIMITED) {
            return CLICOM_ERR_RATE_LIMITED;
        }
        return CLICOM_ERR_GENERIC;
    }

    char room_id_str[CLIP_UUID_STR_SIZE] = {0};
    clip_uuid_to_string(&channel_uuid, room_id_str, sizeof(room_id_str));

    if (out_room_id != NULL && room_id_buf_len > strlen(room_id_str)) {
        strncpy(out_room_id, room_id_str, room_id_buf_len);
        out_room_id[room_id_buf_len - 1] = '\0';
    }
    if (out_join_key != NULL && key_buf_len > strlen(join_key)) {
        strncpy(out_join_key, join_key, key_buf_len);
        out_join_key[key_buf_len - 1] = '\0';
    }

    /* Update engine room state */
    memset(&engine->room_state, 0, sizeof(engine->room_state));
    engine->room_state.state = CLICOM_ROOM_JOINED;
    strncpy(engine->room_state.room_id, room_id_str, sizeof(engine->room_state.room_id) - 1);
    strncpy(engine->room_state.join_key, join_key, sizeof(engine->room_state.join_key) - 1);
    engine->room_state.participant_count = 0;

    if (engine->participants != NULL && engine->participant_capacity > 0) {
        memset(engine->participants, 0, sizeof(ClicomParticipant) * engine->participant_capacity);
    }

    /* Add creator as local participant */
    ClicomParticipant owner;
    memset(&owner, 0, sizeof(owner));
    clip_uuid_to_string((const ClipUuid*)engine->net->assigned_uuid, owner.participant_id, sizeof(owner.participant_id));
    strncpy(owner.display_name, engine->display_name, sizeof(owner.display_name) - 1);
    owner.joined_at_ms = engine_get_time_ms();
    participant_add_internal(engine, &owner);

    /* Start room communication session so audio frames can be exchanged */
    ClipUuid sess_uuid;
    if (clip_client_session_start(engine->net, &channel_uuid, &sess_uuid) == CLIP_OK) {
        memcpy(engine->room_session_uuid, sess_uuid.bytes, 16);
        engine->room_session_active = true;
    }

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_network_join_room(ClicomEngine* engine,
                                 const char* join_key,
                                 char* out_room_id,
                                 size_t room_id_buf_len,
                                 char* out_room_name,
                                 size_t room_name_buf_len)
{
    if (engine == NULL || join_key == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }
    size_t key_len = strlen(join_key);
    if (key_len == 0 || key_len >= CLICOM_MAX_KEY_LEN) {
        return CLICOM_ERR_INVALID_ARG;
    }

    engine_lock(engine);
    if (engine->net == NULL || !engine->net->is_connected) {
        engine_unlock(engine);
        return CLICOM_ERR_NETWORK_DISCONNECTED;
    }

    ClipUuid channel_uuid;
    char channel_name[CLIP_DISPLAY_NAME_MAX] = {0};
    ClipChannelMember* members = NULL;
    size_t member_count = 0;

    ClipError err = clip_client_channel_join(engine->net,
                                             join_key,
                                             &channel_uuid,
                                             channel_name,
                                             sizeof(channel_name),
                                             &members,
                                             &member_count);
    if (err != CLIP_OK) {
        engine_unlock(engine);
        if (err == CLIP_ERR_FULL) {
            return CLICOM_ERR_LIMIT_REACHED;
        }
        if (err == CLIP_ERR_REVOKED) {
            return CLICOM_ERR_REVOKED;
        }
        if (err == CLIP_ERR_RATE_LIMITED) {
            return CLICOM_ERR_RATE_LIMITED;
        }
        if (err == CLIP_ERR_NOT_FOUND) {
            return CLICOM_ERR_NOT_FOUND;
        }
        return CLICOM_ERR_GENERIC;
    }

    char room_id_str[CLIP_UUID_STR_SIZE] = {0};
    clip_uuid_to_string(&channel_uuid, room_id_str, sizeof(room_id_str));

    if (out_room_id != NULL && room_id_buf_len > strlen(room_id_str)) {
        strncpy(out_room_id, room_id_str, room_id_buf_len);
        out_room_id[room_id_buf_len - 1] = '\0';
    }
    if (out_room_name != NULL && room_name_buf_len > strlen(channel_name)) {
        strncpy(out_room_name, channel_name, room_name_buf_len);
        out_room_name[room_name_buf_len - 1] = '\0';
    }

    /* Update engine room state */
    memset(&engine->room_state, 0, sizeof(engine->room_state));
    engine->room_state.state = CLICOM_ROOM_JOINED;
    strncpy(engine->room_state.room_id, room_id_str, sizeof(engine->room_state.room_id) - 1);
    strncpy(engine->room_state.join_key, join_key, sizeof(engine->room_state.join_key) - 1);
    engine->room_state.participant_count = 0;

    if (engine->participants != NULL && engine->participant_capacity > 0) {
        memset(engine->participants, 0, sizeof(ClicomParticipant) * engine->participant_capacity);
    }

    if (members != NULL) {
        for (size_t i = 0; i < member_count; ++i) {
            ClicomParticipant p;
            memset(&p, 0, sizeof(p));
            clip_uuid_to_string(&members[i].node_uuid, p.participant_id, sizeof(p.participant_id));
            strncpy(p.display_name, members[i].display_name, sizeof(p.display_name) - 1);
            p.joined_at_ms = members[i].joined_at_ms;
            participant_add_internal(engine, &p);
        }
        clip_client_free_members(members);
    }

    /* Start/join room communication session for audio transport */
    ClipUuid sess_uuid;
    if (clip_client_session_start(engine->net, &channel_uuid, &sess_uuid) == CLIP_OK) {
        memcpy(engine->room_session_uuid, sess_uuid.bytes, 16);
        engine->room_session_active = true;
    }

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_network_leave_room(ClicomEngine* engine) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->room_state.state != CLICOM_ROOM_JOINED) {
        engine_unlock(engine);
        return CLICOM_OK;
    }

    if (engine->room_session_active && engine->net != NULL && engine->net->is_connected) {
        clip_client_session_end(engine->net, (const ClipUuid*)engine->room_session_uuid);
    }
    memset(engine->room_session_uuid, 0, sizeof(engine->room_session_uuid));
    engine->room_session_active = false;

    if (engine->net != NULL && engine->net->is_connected) {
        ClipUuid chan_uuid;
        if (clip_uuid_from_string(&chan_uuid, engine->room_state.room_id) == 0) {
            clip_client_channel_leave(engine->net, &chan_uuid);
        }
    }

    memset(&engine->room_state, 0, sizeof(engine->room_state));
    engine->room_state.state = CLICOM_ROOM_DISCONNECTED;
    engine->participant_count = 0;

    if (engine->participants != NULL && engine->participant_capacity > 0) {
        memset(engine->participants, 0, sizeof(ClicomParticipant) * engine->participant_capacity);
    }

    engine_unlock(engine);
    return CLICOM_OK;
}

int32_t clicom_network_revoke_invitation(ClicomEngine* engine) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->room_state.state != CLICOM_ROOM_JOINED) {
        engine_unlock(engine);
        return CLICOM_ERR_INVALID_STATE;
    }
    if (engine->net == NULL || !engine->net->is_connected) {
        engine_unlock(engine);
        return CLICOM_ERR_NETWORK_DISCONNECTED;
    }

    ClipUuid chan_uuid;
    if (clip_uuid_from_string(&chan_uuid, engine->room_state.room_id) != 0) {
        engine_unlock(engine);
        return CLICOM_ERR_INVALID_STATE;
    }

    ClipError err = clip_client_channel_revoke_key(engine->net, &chan_uuid);
    engine_unlock(engine);

    if (err == CLIP_ERR_DENIED) {
        return CLICOM_ERR_UNAUTHORIZED;
    }
    if (err == CLIP_ERR_REVOKED) {
        return CLICOM_ERR_REVOKED;
    }
    if (err != CLIP_OK) {
        return CLICOM_ERR_GENERIC;
    }
    return CLICOM_OK;
}

int32_t clicom_network_close_room(ClicomEngine* engine) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->room_state.state != CLICOM_ROOM_JOINED) {
        engine_unlock(engine);
        return CLICOM_ERR_INVALID_STATE;
    }
    if (engine->net == NULL || !engine->net->is_connected) {
        engine_unlock(engine);
        return CLICOM_ERR_NETWORK_DISCONNECTED;
    }

    ClipUuid chan_uuid;
    if (clip_uuid_from_string(&chan_uuid, engine->room_state.room_id) != 0) {
        engine_unlock(engine);
        return CLICOM_ERR_INVALID_STATE;
    }

    ClipError err = clip_client_channel_close(engine->net, &chan_uuid);
    if (err == CLIP_ERR_DENIED) {
        engine_unlock(engine);
        return CLICOM_ERR_UNAUTHORIZED;
    }

    memset(&engine->room_state, 0, sizeof(engine->room_state));
    engine->room_state.state = CLICOM_ROOM_DISCONNECTED;
    engine->participant_count = 0;

    if (engine->participants != NULL && engine->participant_capacity > 0) {
        memset(engine->participants, 0, sizeof(ClicomParticipant) * engine->participant_capacity);
    }

    engine_unlock(engine);
    if (err != CLIP_OK) {
        return CLICOM_ERR_GENERIC;
    }
    return CLICOM_OK;
}

int32_t clicom_network_refresh_participants(ClicomEngine* engine) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->net == NULL || !engine->net->is_connected || engine->room_state.state != CLICOM_ROOM_JOINED) {
        engine_unlock(engine);
        return CLICOM_OK;
    }

    ClipUuid chan_uuid;
    if (clip_uuid_from_string(&chan_uuid, engine->room_state.room_id) != 0) {
        engine_unlock(engine);
        return CLICOM_OK;
    }

    ClipChannelMember* members = NULL;
    size_t count = 0;
    ClipError err = clip_client_get_channel_members(engine->net, &chan_uuid, &members, &count);
    if (err == CLIP_OK && members != NULL) {
        if (engine->participants != NULL && engine->participant_capacity > 0) {
            memset(engine->participants, 0, sizeof(ClicomParticipant) * engine->participant_capacity);
        }
        engine->participant_count = 0;
        for (size_t i = 0; i < count; ++i) {
            ClicomParticipant p;
            memset(&p, 0, sizeof(p));
            clip_uuid_to_string(&members[i].node_uuid, p.participant_id, sizeof(p.participant_id));
            strncpy(p.display_name, members[i].display_name, sizeof(p.display_name) - 1);
            p.joined_at_ms = members[i].joined_at_ms;
            participant_add_internal(engine, &p);
        }
        clip_client_free_members(members);
    }

    engine_unlock(engine);
    return CLICOM_OK;
}

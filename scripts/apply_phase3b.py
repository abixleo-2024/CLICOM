"""
apply_phase3b.py — Script to apply Phase 3B enhancements.
"""

from pathlib import Path

root = Path(__file__).resolve().parent.parent

# 1. Update client/include/network.h
net_h_path = root / "client" / "include" / "network.h"
net_h = net_h_path.read_text(encoding="utf-8")

old_ptt_field = "    bool          ptt_floor_held;         /* PTT floor is never automatically resumed */\n    bool          mic_capture_active;"
new_ptt_field = "    bool          ptt_floor_held;         /* PTT floor is never automatically resumed */\n    bool          ptt_remote_floor_held;  /* Floor held by any member on server */\n    uint8_t       ptt_holder_uuid[CLIP_UUID_BYTES];\n    bool          mic_capture_active;"

if old_ptt_field not in net_h:
    # Try CRLF
    old_ptt_field = old_ptt_field.replace("\n", "\r\n")
    new_ptt_field = new_ptt_field.replace("\n", "\r\n")

if old_ptt_field in net_h:
    net_h = net_h.replace(old_ptt_field, new_ptt_field, 1)

old_floor_decl = "/* Renew lease for held floor */"
new_floor_decl = "/* Query current floor status */\nClipError clip_client_get_floor_status(const ClipClientNet* net,\n                                       bool*                out_floor_held,\n                                       bool*                out_held_by_me,\n                                       ClipUuid*            out_holder_uuid);\n\n/* Renew lease for held floor */"
if old_floor_decl in net_h:
    if "\r\n" in net_h:
        new_floor_decl = new_floor_decl.replace("\n", "\r\n")
    net_h = net_h.replace(old_floor_decl, new_floor_decl, 1)

net_h_path.write_text(net_h, encoding="utf-8")
print("Updated client/include/network.h")

# 2. Update client/src/network.c
net_c_path = root / "client" / "src" / "network.c"
net_c = net_c_path.read_text(encoding="utf-8")

old_ptt_dispatch = """static void dispatch_pumped_ptt_notify(ClipClientNet* net, const uint8_t* payload, uint32_t payload_len)
{
    if (!net || !payload || payload_len == 0) return;
    const uint8_t* f_ptr = NULL;
    uint16_t f_len = 0;
    if (clip_tlv_find(payload, payload_len, CLIP_TAG_FLOOR_STATE, &f_ptr, &f_len) == CLIP_OK && f_len == 1) {
        if (f_ptr[0] == CLIP_PTT_FLOOR_FREE) {
            net->ptt_floor_held = false;
        } else if (f_ptr[0] == CLIP_PTT_FLOOR_HELD) {
            const uint8_t* h_ptr = NULL;
            uint16_t h_len = 0;
            if (clip_tlv_find(payload, payload_len, CLIP_TAG_HOLDER_NODE_UUID, &h_ptr, &h_len) == CLIP_OK && h_len == CLIP_UUID_BYTES) {
                net->ptt_floor_held = (memcmp(net->assigned_uuid, h_ptr, CLIP_UUID_BYTES) == 0);
            }
        }
    }
}"""

new_ptt_dispatch = """static void dispatch_pumped_ptt_notify(ClipClientNet* net, const uint8_t* payload, uint32_t payload_len)
{
    if (!net || !payload || payload_len == 0) return;
    const uint8_t* f_ptr = NULL;
    uint16_t f_len = 0;
    if (clip_tlv_find(payload, payload_len, CLIP_TAG_FLOOR_STATE, &f_ptr, &f_len) == CLIP_OK && f_len == 1) {
        if (f_ptr[0] == CLIP_PTT_FLOOR_FREE) {
            net->ptt_floor_held = false;
            net->ptt_remote_floor_held = false;
            memset(net->ptt_holder_uuid, 0, CLIP_UUID_BYTES);
        } else if (f_ptr[0] == CLIP_PTT_FLOOR_HELD) {
            net->ptt_remote_floor_held = true;
            const uint8_t* h_ptr = NULL;
            uint16_t h_len = 0;
            if (clip_tlv_find(payload, payload_len, CLIP_TAG_HOLDER_NODE_UUID, &h_ptr, &h_len) == CLIP_OK && h_len == CLIP_UUID_BYTES) {
                memcpy(net->ptt_holder_uuid, h_ptr, CLIP_UUID_BYTES);
                net->ptt_floor_held = (memcmp(net->assigned_uuid, h_ptr, CLIP_UUID_BYTES) == 0);
            }
        }
    }
}

ClipError clip_client_get_floor_status(const ClipClientNet* net,
                                       bool*                out_floor_held,
                                       bool*                out_held_by_me,
                                       ClipUuid*            out_holder_uuid)
{
    if (!net) return CLIP_ERR_INVALID;
    if (out_floor_held) *out_floor_held = net->ptt_remote_floor_held;
    if (out_held_by_me) *out_held_by_me = net->ptt_floor_held;
    if (out_holder_uuid) memcpy(out_holder_uuid->bytes, net->ptt_holder_uuid, CLIP_UUID_BYTES);
    return CLIP_OK;
}"""

if old_ptt_dispatch not in net_c:
    old_ptt_dispatch = old_ptt_dispatch.replace("\n", "\r\n")
    new_ptt_dispatch = new_ptt_dispatch.replace("\n", "\r\n")

if old_ptt_dispatch in net_c:
    net_c = net_c.replace(old_ptt_dispatch, new_ptt_dispatch, 1)

old_audio_hook = "} else if (hdr.msg_type == CLIP_MSG_AUDIO_FRAME) {\n            dispatch_pumped_audio_frame(net, payload_ptr, decoded_len, hdr.session_uuid);"
new_audio_hook = "} else if (hdr.msg_type == CLIP_MSG_AUDIO_FRAME) {\n            net->ptt_remote_floor_held = true;\n            memcpy(net->ptt_holder_uuid, hdr.node_uuid, CLIP_UUID_BYTES);\n            dispatch_pumped_audio_frame(net, payload_ptr, decoded_len, hdr.session_uuid);"

if old_audio_hook not in net_c:
    old_audio_hook = old_audio_hook.replace("\n", "\r\n")
    new_audio_hook = new_audio_hook.replace("\n", "\r\n")

if old_audio_hook in net_c:
    net_c = net_c.replace(old_audio_hook, new_audio_hook, 1)

net_c_path.write_text(net_c, encoding="utf-8")
print("Updated client/src/network.c")

# 3. Update engine/include/clicom.h
clicom_h_path = root / "engine" / "include" / "clicom.h"
clicom_h = clicom_h_path.read_text(encoding="utf-8")

old_clicom_decls = "CLICOM_API int32_t clicom_get_active_session_id(ClicomEngine* engine, char* out_buf, size_t buf_len);"
new_clicom_decls = """CLICOM_API int32_t clicom_get_active_session_id(ClicomEngine* engine, char* out_buf, size_t buf_len);

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
CLICOM_API int32_t clicom_network_refresh_participants(ClicomEngine* engine);"""

if old_clicom_decls not in clicom_h:
    old_clicom_decls = old_clicom_decls.replace("\n", "\r\n")
    new_clicom_decls = new_clicom_decls.replace("\n", "\r\n")

if old_clicom_decls in clicom_h:
    clicom_h = clicom_h.replace(old_clicom_decls, new_clicom_decls, 1)

clicom_h_path.write_text(clicom_h, encoding="utf-8")
print("Updated engine/include/clicom.h")

# 4. Update engine/src/audio_state.c
audio_c_path = root / "engine" / "src" / "audio_state.c"
audio_c = audio_c_path.read_text(encoding="utf-8")

old_audio_backend_end = """int32_t clicom_audio_set_mock_backend(ClicomEngine* engine, bool use_mock) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    engine->audio_mock_mode = use_mock;
    engine_unlock(engine);

    return CLICOM_OK;
}"""

new_audio_backend_end = """int32_t clicom_audio_set_mock_backend(ClicomEngine* engine, bool use_mock) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    engine->audio_mock_mode = use_mock;
    engine_unlock(engine);

    return CLICOM_OK;
}

int32_t clicom_audio_get_backend(ClicomEngine* engine, int32_t* out_backend, bool* out_is_mock) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    int32_t backend = engine->audio_mock_mode ? 0 : 1;
    bool is_mock = engine->audio_mock_mode;
    if (engine->audio_hw_initialized && engine->audio_hw != NULL) {
        ClipAudioEngine* hw = (ClipAudioEngine*)engine->audio_hw;
        backend = (int32_t)hw->config.backend;
        is_mock = (hw->config.backend == CLIP_AUDIO_BACKEND_MOCK);
    }
    if (out_backend != NULL) {
        *out_backend = backend;
    }
    if (out_is_mock != NULL) {
        *out_is_mock = is_mock;
    }
    engine_unlock(engine);

    return CLICOM_OK;
}

int32_t clicom_audio_get_device_counts(ClicomEngine* engine, uint32_t* out_inputs, uint32_t* out_outputs) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    uint32_t in_devs = 0;
    uint32_t out_devs = 0;
#if defined(_WIN32) || defined(__CYGWIN__)
    in_devs = (uint32_t)waveInGetNumDevs();
    out_devs = (uint32_t)waveOutGetNumDevs();
#else
    in_devs = 1;
    out_devs = 1;
#endif

    if (out_inputs) *out_inputs = in_devs;
    if (out_outputs) *out_outputs = out_devs;

    return CLICOM_OK;
}"""

if old_audio_backend_end not in audio_c:
    old_audio_backend_end = old_audio_backend_end.replace("\n", "\r\n")
    new_audio_backend_end = new_audio_backend_end.replace("\n", "\r\n")

if old_audio_backend_end in audio_c:
    audio_c = audio_c.replace(old_audio_backend_end, new_audio_backend_end, 1)

# Ensure mmsystem.h is included if on windows
if "#include <mmsystem.h>" not in audio_c:
    inc_marker = "#include \"engine_internal.h\""
    new_inc = "#include \"engine_internal.h\"\n#if defined(_WIN32) || defined(__CYGWIN__)\n#include <mmsystem.h>\n#endif"
    if inc_marker in audio_c:
        if "\r\n" in audio_c:
            new_inc = new_inc.replace("\n", "\r\n")
        audio_c = audio_c.replace(inc_marker, new_inc, 1)

audio_c_path.write_text(audio_c, encoding="utf-8")
print("Updated engine/src/audio_state.c")

# 5. Update engine/src/clicom.c
clicom_c_path = root / "engine" / "src" / "clicom.c"
clicom_c = clicom_c_path.read_text(encoding="utf-8")

old_mic_muted = """int32_t clicom_set_mic_muted(ClicomEngine* engine, bool muted) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    engine->mic_state.is_muted = muted;
    engine_unlock(engine);
    return CLICOM_OK;
}"""

new_mic_muted = """int32_t clicom_set_mic_muted(ClicomEngine* engine, bool muted) {
    if (engine == NULL) {
        return CLICOM_ERR_NULL_POINTER;
    }

    engine_lock(engine);
    if (engine->state == CLICOM_ENGINE_SHUTDOWN) {
        engine_unlock(engine);
        return CLICOM_ERR_SHUTDOWN;
    }

    engine->mic_state.is_muted = muted;

    /* When muted, clear capture queue and stop hardware capture device if capturing */
    if (muted) {
        audio_queue_clear_internal(&engine->capture_queue);
        if (engine->audio_hw_initialized && engine->audio_hw != NULL) {
            clip_audio_on_floor_released((ClipAudioEngine*)engine->audio_hw);
        }
    } else {
        /* If unmuted and floor is held, resume hardware capture */
        if (engine->mic_state.is_ptt_active && engine->audio_hw_initialized && engine->audio_hw != NULL) {
            clip_audio_on_floor_granted((ClipAudioEngine*)engine->audio_hw);
        }
    }

    engine_unlock(engine);
    return CLICOM_OK;
}"""

if old_mic_muted not in clicom_c:
    old_mic_muted = old_mic_muted.replace("\n", "\r\n")
    new_mic_muted = new_mic_muted.replace("\n", "\r\n")

if old_mic_muted in clicom_c:
    clicom_c = clicom_c.replace(old_mic_muted, new_mic_muted, 1)

# Add clicom_get_floor_status implementation at bottom of clicom.c
floor_status_impl = """
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

    if (floor_held && holder_str[0] != '\\0') {
        strncpy(engine->room_state.active_speaker_id, holder_str, CLICOM_MAX_UUID_LEN - 1);
    } else if (!floor_held) {
        engine->room_state.active_speaker_id[0] = '\\0';
    }

    if (out_floor_held) *out_floor_held = floor_held;
    if (out_held_by_me) *out_held_by_me = held_by_me;
    if (out_holder_id && id_buf_len > 0) {
        strncpy(out_holder_id, holder_str, id_buf_len - 1);
        out_holder_id[id_buf_len - 1] = '\\0';
    }

    engine_unlock(engine);
    return CLICOM_OK;
}
"""

if "clicom_get_floor_status" not in clicom_c:
    if "\r\n" in clicom_c:
        floor_status_impl = floor_status_impl.replace("\n", "\r\n")
    clicom_c += floor_status_impl

clicom_c_path.write_text(clicom_c, encoding="utf-8")
print("Updated engine/src/clicom.c")

# 6. Update engine/src/engine_network.c
eng_net_c_path = root / "engine" / "src" / "engine_network.c"
eng_net_c = eng_net_c_path.read_text(encoding="utf-8")

old_disconn_internal = """    if (engine->net->is_connected) {
        if (engine->room_session_active) {
            clip_client_session_end(engine->net, (const ClipUuid*)engine->room_session_uuid);
        }"""
new_disconn_internal = """    if (engine->mic_state.is_ptt_active) {
        engine->mic_state.is_ptt_active = false;
        if (engine->audio_hw_initialized && engine->audio_hw != NULL) {
            clip_audio_on_floor_released((ClipAudioEngine*)engine->audio_hw);
        }
    }
    if (engine->net->is_connected) {
        if (engine->room_session_active) {
            clip_client_session_end(engine->net, (const ClipUuid*)engine->room_session_uuid);
        }"""

if old_disconn_internal not in eng_net_c:
    old_disconn_internal = old_disconn_internal.replace("\n", "\r\n")
    new_disconn_internal = new_disconn_internal.replace("\n", "\r\n")

if old_disconn_internal in eng_net_c:
    eng_net_c = eng_net_c.replace(old_disconn_internal, new_disconn_internal, 1)

# Add clicom_network_refresh_participants at bottom of engine_network.c
refresh_parts_impl = """
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
"""

if "clicom_network_refresh_participants" not in eng_net_c:
    if "\r\n" in eng_net_c:
        refresh_parts_impl = refresh_parts_impl.replace("\n", "\r\n")
    eng_net_c += refresh_parts_impl

eng_net_c_path.write_text(eng_net_c, encoding="utf-8")
print("Updated engine/src/engine_network.c")

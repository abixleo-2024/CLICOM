/*
 * server.c — CLICOM TCP Server Implementation (Phase 2 Networking Layer)
 */

#include "server.h"
#include "clip_channels.h"
#include "clip_sessions.h"
#include "clip_connections.h"
#include "clip_ptt.h"
#include "clip_notes.h"
#include "clip_admin.h"
#include "clip_admin_db.h"
#include <openssl/crypto.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif
#include "clip_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static ClipServer* g_active_server = NULL;

static ClipError clip_server_send_client_data(ClipServer* srv, clip_socket_t sock, const uint8_t* data, size_t len)
{
    ClipServer* s = srv ? srv : g_active_server;
    if (s) {
        ClipClientConn* c = clip_client_table_find(&s->clients, sock);
        if (c && c->transport) {
            return clip_transport_write(c->transport, data, len);
        }
    }
    return clip_net_send_all(sock, data, len);
}

static void send_auth_fail(clip_socket_t sock, uint64_t seq_num, ClipError status_code)
{
    uint8_t fail_payload[32];
    size_t offset = 0;
    uint16_t abs_code = (uint16_t)(-((int)status_code));
    uint8_t code_be[2] = {
        (uint8_t)((abs_code >> 8) & 0xFF),
        (uint8_t)(abs_code & 0xFF)
    };
    clip_tlv_write(fail_payload, sizeof(fail_payload), &offset, CLIP_TAG_AUTH_STATUS, code_be, sizeof(code_be));

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_AUTH_FAIL, (uint32_t)offset, seq_num, NULL);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 64];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, fail_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(NULL, sock, frame_buf, frame_len);
    }
}

static void send_channel_fail(clip_socket_t sock, uint64_t seq_num, ClipError status_code)
{
    CLIP_LOGI("send_channel_fail entered: sock %lld, seq %llu, code %d", (long long)sock, (unsigned long long)seq_num, (int)status_code);
    uint8_t fail_payload[32];
    size_t offset = 0;
    uint16_t abs_code = (uint16_t)(-((int)status_code));
    uint8_t code_be[2] = {
        (uint8_t)((abs_code >> 8) & 0xFF),
        (uint8_t)(abs_code & 0xFF)
    };
    clip_tlv_write(fail_payload, sizeof(fail_payload), &offset, CLIP_TAG_ERROR_CODE, code_be, sizeof(code_be));

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_FAIL, (uint32_t)offset, seq_num, NULL);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 64];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, fail_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        ClipError serr = clip_server_send_client_data(NULL, sock, frame_buf, frame_len);
        CLIP_LOGI("send_channel_fail: sent result=%d", (int)serr);
    }
}

static void send_session_fail(clip_socket_t sock, uint64_t seq_num, ClipError status_code)
{
    uint8_t fail_payload[32];
    size_t offset = 0;
    uint16_t abs_code = (uint16_t)(-((int)status_code));
    uint8_t code_be[2] = {
        (uint8_t)((abs_code >> 8) & 0xFF),
        (uint8_t)(abs_code & 0xFF)
    };
    clip_tlv_write(fail_payload, sizeof(fail_payload), &offset, CLIP_TAG_ERROR_CODE, code_be, sizeof(code_be));

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_SESSION_FAIL, (uint32_t)offset, seq_num, NULL);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 64];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, fail_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(NULL, sock, frame_buf, frame_len);
    }
}

static void send_conn_fail(clip_socket_t sock, uint64_t seq_num, ClipError status_code)
{
    uint8_t fail_payload[32];
    size_t offset = 0;
    uint16_t abs_code = (uint16_t)(-((int)status_code));
    uint8_t code_be[2] = {
        (uint8_t)((abs_code >> 8) & 0xFF),
        (uint8_t)(abs_code & 0xFF)
    };
    clip_tlv_write(fail_payload, sizeof(fail_payload), &offset, CLIP_TAG_ERROR_CODE, code_be, sizeof(code_be));

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_CONN_FAIL, (uint32_t)offset, seq_num, NULL);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 64];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, fail_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(NULL, sock, frame_buf, frame_len);
    }
}

static void send_note_fail(clip_socket_t sock, uint64_t seq_num, ClipError status_code, const uint8_t session_uuid[CLIP_UUID_BYTES])
{
    uint8_t fail_payload[64];
    size_t offset = 0;
    if (session_uuid) {
        clip_tlv_write(fail_payload, sizeof(fail_payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid, CLIP_UUID_BYTES);
    }
    uint16_t abs_code = (uint16_t)(-((int)status_code));
    uint8_t code_be[2] = {
        (uint8_t)((abs_code >> 8) & 0xFF),
        (uint8_t)(abs_code & 0xFF)
    };
    clip_tlv_write(fail_payload, sizeof(fail_payload), &offset, CLIP_TAG_ERROR_CODE, code_be, sizeof(code_be));

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_NOTE_FAIL, (uint32_t)offset, seq_num, session_uuid);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 64];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, fail_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(NULL, sock, frame_buf, frame_len);
    }
}

static void send_security_fail(clip_socket_t sock, uint64_t seq_num, ClipError status_code, const uint8_t session_uuid[CLIP_UUID_BYTES])
{
    uint8_t fail_payload[64];
    size_t offset = 0;
    if (session_uuid) {
        clip_tlv_write(fail_payload, sizeof(fail_payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid, CLIP_UUID_BYTES);
    }
    uint16_t abs_code = (uint16_t)(-((int)status_code));
    uint8_t code_be[2] = {
        (uint8_t)((abs_code >> 8) & 0xFF),
        (uint8_t)(abs_code & 0xFF)
    };
    clip_tlv_write(fail_payload, sizeof(fail_payload), &offset, CLIP_TAG_ERROR_CODE, code_be, sizeof(code_be));

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_SECURITY_EVENT_FAIL, (uint32_t)offset, seq_num, session_uuid);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 64];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, fail_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(NULL, sock, frame_buf, frame_len);
    }
}

static void send_admin_auth_resp(ClipServer* srv,
                                 clip_socket_t sock,
                                 uint64_t seq_num,
                                 ClipError status_code,
                                 ClipAdminPermission role,
                                 const uint8_t* admin_uuid,
                                 const char* username)
{
    uint8_t payload[256];
    size_t offset = 0;
    uint16_t abs_code = (uint16_t)(-((int)status_code));
    uint8_t code_be[2] = {
        (uint8_t)((abs_code >> 8) & 0xFF),
        (uint8_t)(abs_code & 0xFF)
    };
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_AUTH_STATUS, code_be, sizeof(code_be));
    if (status_code == CLIP_OK) {
        uint8_t r_byte = (uint8_t)role;
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_PERMISSION_LEVEL, &r_byte, 1);
        if (admin_uuid) {
            clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_NODE_UUID, admin_uuid, CLIP_UUID_BYTES);
        }
        if (username && username[0] != '\0') {
            clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_ADMIN_USERNAME, username, (uint16_t)strlen(username));
        }
    }

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_ADMIN_AUTH_RESP, (uint32_t)offset, seq_num, NULL);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 256];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(srv, sock, frame_buf, frame_len);
    }
}

static void send_admin_fail(ClipServer* srv, clip_socket_t sock, uint64_t seq_num, ClipError status_code, const char* reason)
{
    uint8_t fail_payload[384];
    size_t offset = 0;
    uint16_t abs_code = (uint16_t)(-((int)status_code));
    uint8_t code_be[2] = {
        (uint8_t)((abs_code >> 8) & 0xFF),
        (uint8_t)(abs_code & 0xFF)
    };
    clip_tlv_write(fail_payload, sizeof(fail_payload), &offset, CLIP_TAG_ERROR_CODE, code_be, sizeof(code_be));
    if (reason && reason[0] != '\0') {
        clip_tlv_write(fail_payload, sizeof(fail_payload), &offset, CLIP_TAG_TEXT, reason, (uint16_t)strlen(reason));
        clip_tlv_write(fail_payload, sizeof(fail_payload), &offset, CLIP_TAG_ADMIN_REASON, reason, (uint16_t)strlen(reason));
    }

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_ADMIN_ACTION_FAIL, (uint32_t)offset, seq_num, NULL);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 512];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, fail_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(srv, sock, frame_buf, frame_len);
    }
}

static void send_admin_action_ok(ClipServer* srv, clip_socket_t sock, uint64_t seq_num, ClipAdminActionType action, uint32_t audit_id)
{
    uint8_t ok_payload[128];
    size_t offset = 0;
    uint8_t act_byte = (uint8_t)action;
    clip_tlv_write(ok_payload, sizeof(ok_payload), &offset, CLIP_TAG_ADMIN_ACTION, &act_byte, 1);
    uint8_t id_be[4] = {
        (uint8_t)((audit_id >> 24) & 0xFF),
        (uint8_t)((audit_id >> 16) & 0xFF),
        (uint8_t)((audit_id >> 8) & 0xFF),
        (uint8_t)(audit_id & 0xFF)
    };
    clip_tlv_write(ok_payload, sizeof(ok_payload), &offset, CLIP_TAG_ADMIN_AUDIT_ID, id_be, 4);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_ADMIN_ACTION_OK, (uint32_t)offset, seq_num, NULL);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 256];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, ok_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(srv, sock, frame_buf, frame_len);
    }
}

static void server_security_event_cb(const ClipSecurityEvent* event, void* user_data)
{
    ClipServer* srv = (ClipServer*)user_data;
    if (!srv || !event || !srv->identity_db) return;

    sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
    if (!db) return;

    ClipSecurityEvent mutable_ev = *event;
    ClipError db_err = clip_security_db_insert_event(db, &mutable_ev);
    if (db_err != CLIP_OK) {
        CLIP_LOGE("Failed to persist security event to database: %s", clip_error_string(db_err));
        return;
    }

    CLIP_LOGW("Security event #%u recorded for session %s (status=PENDING)",
              mutable_ev.event_id, mutable_ev.event_uuid_str);

    /* Construct CLIP_MSG_SECURITY_EVENT advisory notification payload */
    uint8_t payload[1024];
    size_t offset = 0;

    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_EVENT_UUID, mutable_ev.event_uuid, CLIP_UUID_BYTES);

    uint8_t id_be[4] = {
        (uint8_t)((mutable_ev.event_id >> 24) & 0xFF),
        (uint8_t)((mutable_ev.event_id >> 16) & 0xFF),
        (uint8_t)((mutable_ev.event_id >> 8) & 0xFF),
        (uint8_t)(mutable_ev.event_id & 0xFF)
    };
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_EVENT_ID, id_be, 4);

    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, mutable_ev.session_uuid, CLIP_UUID_BYTES);

    ClipUuid chan_u, node_u;
    if (clip_uuid_from_string(&chan_u, mutable_ev.channel_uuid_str) == 0) {
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_CHANNEL_UUID, chan_u.bytes, CLIP_UUID_BYTES);
    }
    if (clip_uuid_from_string(&node_u, mutable_ev.node_uuid_str) == 0) {
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_NODE_UUID, node_u.bytes, CLIP_UUID_BYTES);
    }

    uint8_t ts_be[8];
    for (int i = 0; i < 8; i++) {
        ts_be[i] = (uint8_t)((mutable_ev.timestamp_ms >> (56 - i * 8)) & 0xFF);
    }
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_TIMESTAMP_MS, ts_be, 8);

    uint8_t cat_b = (uint8_t)mutable_ev.category;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_CATEGORY, &cat_b, 1);

    uint8_t sev_b = (uint8_t)mutable_ev.severity;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SEVERITY, &sev_b, 1);

    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_MATCHED_RULE, mutable_ev.matched_rule, (uint16_t)strlen(mutable_ev.matched_rule));
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_MATCHED_TEXT, mutable_ev.matched_term, (uint16_t)strlen(mutable_ev.matched_term));
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_CONTEXT_TEXT, mutable_ev.context_text, (uint16_t)strlen(mutable_ev.context_text));

    uint8_t st_b = (uint8_t)mutable_ev.status;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_EVENT_STATUS, &st_b, 1);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_SECURITY_EVENT, (uint32_t)offset, 0, mutable_ev.session_uuid);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 1024];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        /* Broadcast advisory notification to authorized session participants currently connected */
        ClipUuid sess_u;
        memcpy(sess_u.bytes, mutable_ev.session_uuid, CLIP_UUID_BYTES);
        for (size_t i = 0; i < srv->clients.capacity; i++) {
            ClipClientConn* c = &srv->clients.clients[i];
            if (c->active && c->auth_state == CLIP_AUTH_STATE_AUTHENTICATED) {
                ClipUuid client_u;
                memcpy(client_u.bytes, c->node_uuid, CLIP_UUID_BYTES);
                bool is_auth = false;
                if (clip_session_is_authorized(db, &sess_u, &client_u, &is_auth) && is_auth) {
                    clip_server_send_client_data(srv, c->sock, frame_buf, frame_len);
                    srv->total_frames_sent++;
                }
            }
        }
    }
}


static uint64_t current_time_ms(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return (uint64_t)((uli.QuadPart - 116444736000000000ULL) / 10000ULL);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
#endif
}

static void send_ptt_deny(ClipServer* srv,
                          clip_socket_t sock,
                          uint64_t seq_num,
                          const uint8_t session_uuid[CLIP_UUID_BYTES],
                          const ClipUuid* holder_uuid,
                          ClipError reason)
{
    uint8_t payload[128];
    size_t offset = 0;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid, CLIP_UUID_BYTES);
    if (holder_uuid && !clip_uuid_is_zero(holder_uuid)) {
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_NODE_UUID, holder_uuid->bytes, CLIP_UUID_BYTES);
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_HOLDER_NODE_UUID, holder_uuid->bytes, CLIP_UUID_BYTES);
    }
    uint8_t f_state = CLIP_PTT_FLOOR_HELD;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_FLOOR_STATE, &f_state, 1);
    uint16_t abs_code = (uint16_t)(-((int)reason));
    uint8_t code_be[2] = { (uint8_t)((abs_code >> 8) & 0xFF), (uint8_t)(abs_code & 0xFF) };
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_ERROR_CODE, code_be, 2);
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_DENIAL_REASON, code_be, 2);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_PTT_DENY, (uint32_t)offset, seq_num, session_uuid);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 128];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(srv, sock, frame_buf, frame_len);
        if (srv) srv->total_frames_sent++;
    }
}

static void send_ptt_grant(ClipServer* srv,
                           clip_socket_t sock,
                           uint64_t seq_num,
                           const uint8_t session_uuid[CLIP_UUID_BYTES],
                           const ClipUuid* holder_uuid,
                           uint64_t acquired_at_ms,
                           uint32_t lease_ms)
{
    uint8_t payload[128];
    size_t offset = 0;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid, CLIP_UUID_BYTES);
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_NODE_UUID, holder_uuid->bytes, CLIP_UUID_BYTES);
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_HOLDER_NODE_UUID, holder_uuid->bytes, CLIP_UUID_BYTES);
    uint8_t f_state = CLIP_PTT_FLOOR_HELD;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_FLOOR_STATE, &f_state, 1);

    uint8_t ts_be[8];
    for (int i = 0; i < 8; i++) ts_be[i] = (uint8_t)((acquired_at_ms >> (56 - i * 8)) & 0xFF);
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_TIMESTAMP_MS, ts_be, 8);

    uint8_t lease_be[4] = {
        (uint8_t)((lease_ms >> 24) & 0xFF),
        (uint8_t)((lease_ms >> 16) & 0xFF),
        (uint8_t)((lease_ms >> 8) & 0xFF),
        (uint8_t)(lease_ms & 0xFF)
    };
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_LEASE_TIMEOUT_MS, lease_be, 4);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_PTT_GRANT, (uint32_t)offset, seq_num, session_uuid);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 128];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(srv, sock, frame_buf, frame_len);
        if (srv) srv->total_frames_sent++;
    }
}

static void send_ptt_notify(ClipServer* srv,
                            clip_socket_t sock,
                            const uint8_t session_uuid[CLIP_UUID_BYTES],
                            ClipPttFloorState state,
                            const ClipUuid* holder_uuid,
                            uint64_t acquired_at_ms)
{
    uint8_t payload[128];
    size_t offset = 0;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid, CLIP_UUID_BYTES);
    uint8_t f_state = (uint8_t)state;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_FLOOR_STATE, &f_state, 1);
    if (holder_uuid && !clip_uuid_is_zero(holder_uuid)) {
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_NODE_UUID, holder_uuid->bytes, CLIP_UUID_BYTES);
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_HOLDER_NODE_UUID, holder_uuid->bytes, CLIP_UUID_BYTES);
    }
    if (acquired_at_ms > 0) {
        uint8_t ts_be[8];
        for (int i = 0; i < 8; i++) ts_be[i] = (uint8_t)((acquired_at_ms >> (56 - i * 8)) & 0xFF);
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_TIMESTAMP_MS, ts_be, 8);
    }

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_PTT_NOTIFY, (uint32_t)offset, 1, session_uuid);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 128];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(srv, sock, frame_buf, frame_len);
        if (srv) srv->total_frames_sent++;
    }
}

static void send_ptt_released(ClipServer* srv,
                              clip_socket_t sock,
                              uint64_t seq_num,
                              const uint8_t session_uuid[CLIP_UUID_BYTES])
{
    uint8_t payload[64];
    size_t offset = 0;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid, CLIP_UUID_BYTES);
    uint8_t f_state = CLIP_PTT_FLOOR_FREE;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_FLOOR_STATE, &f_state, 1);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_PTT_FLOOR_RELEASED, (uint32_t)offset, seq_num, session_uuid);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 64];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(srv, sock, frame_buf, frame_len);
        if (srv) srv->total_frames_sent++;
    }
}

static void send_ptt_status_resp(ClipServer* srv,
                                 clip_socket_t sock,
                                 uint64_t seq_num,
                                 const uint8_t session_uuid[CLIP_UUID_BYTES],
                                 const ClipPttFloorEntry* entry,
                                 uint64_t now_ms)
{
    uint8_t payload[128];
    size_t offset = 0;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid, CLIP_UUID_BYTES);
    uint8_t f_state = (uint8_t)entry->floor_state;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_FLOOR_STATE, &f_state, 1);

    if (entry->floor_state == CLIP_PTT_FLOOR_HELD && !clip_uuid_is_zero(&entry->holder_node_uuid)) {
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_NODE_UUID, entry->holder_node_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_HOLDER_NODE_UUID, entry->holder_node_uuid.bytes, CLIP_UUID_BYTES);

        uint8_t ts_be[8];
        for (int i = 0; i < 8; i++) ts_be[i] = (uint8_t)((entry->acquired_at_ms >> (56 - i * 8)) & 0xFF);
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_TIMESTAMP_MS, ts_be, 8);

        uint32_t rem = 0;
        if (now_ms < entry->last_renewed_at_ms + entry->lease_duration_ms) {
            rem = (uint32_t)((entry->last_renewed_at_ms + entry->lease_duration_ms) - now_ms);
        }
        uint8_t rem_be[4] = {
            (uint8_t)((rem >> 24) & 0xFF),
            (uint8_t)((rem >> 16) & 0xFF),
            (uint8_t)((rem >> 8) & 0xFF),
            (uint8_t)(rem & 0xFF)
        };
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_LEASE_TIMEOUT_MS, rem_be, 4);
    }

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_PTT_FLOOR_STATUS_RESP, (uint32_t)offset, seq_num, session_uuid);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 128];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(srv, sock, frame_buf, frame_len);
        if (srv) srv->total_frames_sent++;
    }
}

static void send_ptt_renew_ack(ClipServer* srv,
                               clip_socket_t sock,
                               uint64_t seq_num,
                               const uint8_t session_uuid[CLIP_UUID_BYTES],
                               uint32_t remaining_lease_ms)
{
    uint8_t payload[64];
    size_t offset = 0;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid, CLIP_UUID_BYTES);
    uint8_t rem_be[4] = {
        (uint8_t)((remaining_lease_ms >> 24) & 0xFF),
        (uint8_t)((remaining_lease_ms >> 16) & 0xFF),
        (uint8_t)((remaining_lease_ms >> 8) & 0xFF),
        (uint8_t)(remaining_lease_ms & 0xFF)
    };
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_LEASE_TIMEOUT_MS, rem_be, 4);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_PTT_FLOOR_RENEW_ACK, (uint32_t)offset, seq_num, session_uuid);

    uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 64];
    size_t frame_len = 0;
    if (clip_frame_encode(&tx_hdr, payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
        clip_server_send_client_data(srv, sock, frame_buf, frame_len);
        if (srv) srv->total_frames_sent++;
    }
}

static void clip_server_handle_client_disconnect(ClipServer* srv, ClipClientConn* c)
{
    if (!srv || !c || !c->active) return;

    if (c->auth_state == CLIP_AUTH_STATE_AUTHENTICATED) {
        ClipUuid affected_sessions[16];
        size_t affected_count = 0;
        clip_ptt_manager_release_by_holder(&srv->ptt_mgr, (const ClipUuid*)c->node_uuid, affected_sessions, 16, &affected_count);
        for (size_t k = 0; k < affected_count; k++) {
            CLIP_LOGI("Disconnect safety: released floor for session %02x%02x...",
                      affected_sessions[k].bytes[0], affected_sessions[k].bytes[1]);
            sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
            ClipSessionRecord srec;
            if (clip_session_get(db, &affected_sessions[k], &srec) == CLIP_OK && srec.state == CLIP_SESSION_STATE_ACTIVE) {
                ClipUuid peer_uuid = clip_uuid_equal((const ClipUuid*)c->node_uuid, &srec.initiator_node_uuid) ?
                                     srec.peer_node_uuid : srec.initiator_node_uuid;
                if (!clip_uuid_is_zero(&peer_uuid)) {
                    ClipClientConn* peer_cc = clip_client_table_find_by_node_uuid(&srv->clients, &peer_uuid);
                    if (peer_cc) {
                        send_ptt_notify(srv, peer_cc->sock, affected_sessions[k].bytes, CLIP_PTT_FLOOR_FREE, NULL, 0);
                    }
                }
            }
        }
    }

    clip_client_table_remove(&srv->clients, c->sock);
}

static void handle_client_frame(ClipServer*            srv,
                                ClipClientConn*        client,
                                const ClipFrameHeader* rx_hdr,
                                const uint8_t*         rx_payload,
                                uint32_t               rx_payload_len)
{
    CLIP_LOGI("Frame received: type=%s (0x%04X), seq=%llu, payload_len=%u from %s:%u",
              clip_message_type_string((ClipMessageType)rx_hdr->msg_type),
              rx_hdr->msg_type,
              (unsigned long long)rx_hdr->seq_num,
              rx_payload_len,
              client->ip_str,
              client->port);

    /* Update activity timestamp on every validated incoming frame from client */
    uint64_t frame_now_ms = srv->mock_now_ms ? srv->mock_now_ms : current_time_ms();
    client->last_seen_ms = frame_now_ms;

    /*
     * Anti-Spoofing & Session Wire Authorization Check:
     * If an incoming frame carries a non-zero session_uuid in its wire header,
     * the caller MUST be authenticated, the session MUST exist and be ACTIVE,
     * and the caller MUST be an authorized participant of that session.
     */
    if (rx_hdr->msg_type != CLIP_MSG_REGISTER &&
        rx_hdr->msg_type != CLIP_MSG_AUTH &&
        rx_hdr->msg_type != CLIP_MSG_GOODBYE &&
        rx_hdr->msg_type != CLIP_MSG_HEARTBEAT &&
        rx_hdr->msg_type != CLIP_MSG_HEARTBEAT_ACK &&
        !clip_uuid_is_zero((const ClipUuid*)rx_hdr->session_uuid)) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            CLIP_LOGW("Anti-spoofing rejected: unauthenticated client sent frame with non-zero session_uuid");
            send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        ClipUuid hdr_sess;
        memcpy(hdr_sess.bytes, rx_hdr->session_uuid, CLIP_UUID_BYTES);
        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipSessionRecord sess_chk;
        ClipError s_chk_err = clip_session_get(db, &hdr_sess, &sess_chk);
        bool state_valid = (sess_chk.state == CLIP_SESSION_STATE_ACTIVE);
        if (rx_hdr->msg_type == CLIP_MSG_SESSION_LOG_LIST_REQ ||
            rx_hdr->msg_type == CLIP_MSG_SESSION_LOG_GET_REQ ||
            rx_hdr->msg_type == CLIP_MSG_NOTE_LIST_REQ ||
            rx_hdr->msg_type == CLIP_MSG_NOTE_CREATE ||
            rx_hdr->msg_type == CLIP_MSG_SECURITY_EVENT_LIST_REQ ||
            rx_hdr->msg_type == CLIP_MSG_SECURITY_EVENT_GET_REQ) {
            state_valid = (sess_chk.state == CLIP_SESSION_STATE_ACTIVE || sess_chk.state == CLIP_SESSION_STATE_CLOSED);
        }
        if (s_chk_err != CLIP_OK || !state_valid) {
            CLIP_LOGW("Anti-spoofing rejected: frame references non-existent or inactive session");
            if (rx_hdr->msg_type == CLIP_MSG_SECURITY_EVENT_LIST_REQ ||
                rx_hdr->msg_type == CLIP_MSG_SECURITY_EVENT_GET_REQ) {
                send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NO_SESSION, hdr_sess.bytes);
            } else if (rx_hdr->msg_type == CLIP_MSG_NOTE_LIST_REQ ||
                       rx_hdr->msg_type == CLIP_MSG_NOTE_CREATE) {
                send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NO_SESSION, hdr_sess.bytes);
            } else {
                send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NO_SESSION);
            }
            return;
        }

        bool is_endpoint = clip_uuid_equal((const ClipUuid*)client->node_uuid, &sess_chk.initiator_node_uuid) ||
                           (!clip_uuid_is_zero(&sess_chk.peer_node_uuid) && clip_uuid_equal((const ClipUuid*)client->node_uuid, &sess_chk.peer_node_uuid));
        if (!is_endpoint) {
            bool is_chan_mem = false;
            clip_channel_is_member(db, &sess_chk.channel_uuid, (const ClipUuid*)client->node_uuid, &is_chan_mem);
            if (!is_chan_mem) {
                CLIP_LOGW("Anti-spoofing rejected: client is not an authorized endpoint of session");
                if (rx_hdr->msg_type == CLIP_MSG_SECURITY_EVENT_LIST_REQ ||
                    rx_hdr->msg_type == CLIP_MSG_SECURITY_EVENT_GET_REQ) {
                    send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, hdr_sess.bytes);
                } else if (rx_hdr->msg_type == CLIP_MSG_NOTE_LIST_REQ ||
                           rx_hdr->msg_type == CLIP_MSG_NOTE_CREATE) {
                    send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, hdr_sess.bytes);
                } else {
                    send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
                }
                return;
            }
        }
    }

    if (rx_hdr->msg_type == CLIP_MSG_REGISTER) {
        /*
         * Phase 3 First-Time Registration Flow:
         * 1. Extract requested display name from TLV or fallback string
         * 2. Server generates immutable UUIDv4 + 256-bit secure credential
         * 3. Server computes SHA-256 verifier and persists in SQLite
         * 4. Server replies with REGISTER_ACK carrying UUID + credential + canonical name
         */
        client->auth_state = CLIP_AUTH_STATE_REGISTERING;

        char display_name[CLIP_DISPLAY_NAME_MAX] = "ANONYMOUS";
        const uint8_t* name_tlv = NULL;
        uint16_t name_tlv_len = 0;

        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_DISPLAY_NAME, &name_tlv, &name_tlv_len) == CLIP_OK) {
            size_t copy_len = (name_tlv_len < CLIP_DISPLAY_NAME_MAX - 1) ? name_tlv_len : (CLIP_DISPLAY_NAME_MAX - 1);
            memcpy(display_name, name_tlv, copy_len);
            display_name[copy_len] = '\0';
        } else if (rx_payload_len > 0 && rx_payload) {
            size_t copy_len = (rx_payload_len < CLIP_DISPLAY_NAME_MAX - 1) ? rx_payload_len : (CLIP_DISPLAY_NAME_MAX - 1);
            memcpy(display_name, rx_payload, copy_len);
            display_name[copy_len] = '\0';
        }

        ClipUuid assigned_uuid;
        uint8_t new_cred[CLIP_CREDENTIAL_BYTES];

        ClipError reg_err = clip_identity_register(srv->identity_db,
                                                   display_name,
                                                   &assigned_uuid,
                                                   new_cred);

        if (reg_err != CLIP_OK) {
            CLIP_LOGE("Failed to register node in identity database: %s", clip_error_string(reg_err));
            send_auth_fail(client->sock, rx_hdr->seq_num + 1, reg_err);
            client->auth_state = CLIP_AUTH_STATE_FAILED;
            return;
        }

        client->registered = true;
        client->auth_state = CLIP_AUTH_STATE_AUTHENTICATED;
        memcpy(client->node_uuid, assigned_uuid.bytes, CLIP_UUID_BYTES);
        strncpy(client->display_name, display_name, sizeof(client->display_name) - 1);

        char uuid_str[CLIP_UUID_STR_SIZE];
        clip_uuid_to_string(&assigned_uuid, uuid_str, sizeof(uuid_str));
        CLIP_LOGI("Node registered successfully: UUID=%s, display_name='%s'", uuid_str, client->display_name);

        /* Construct REGISTER_ACK with TLVs: NODE_UUID, CREDENTIAL, DISPLAY_NAME */
        uint8_t ack_payload[512];
        size_t ack_payload_len = 0;

        clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_payload_len,
                       CLIP_TAG_NODE_UUID, assigned_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_payload_len,
                       CLIP_TAG_CREDENTIAL, new_cred, CLIP_CREDENTIAL_BYTES);
        clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_payload_len,
                       CLIP_TAG_DISPLAY_NAME, client->display_name, (uint16_t)strlen(client->display_name));

#ifdef _WIN32
        SecureZeroMemory(new_cred, sizeof(new_cred));
#else
        memset(new_cred, 0, sizeof(new_cred));
#endif

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr,
                               CLIP_MSG_REGISTER_ACK,
                               (uint32_t)ack_payload_len,
                               rx_hdr->seq_num + 1,
                               NULL);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 512];
        size_t frame_len = 0;
        ClipError enc_err = clip_frame_encode(&tx_hdr, ack_payload, frame_buf, sizeof(frame_buf), &frame_len);

#ifdef _WIN32
        SecureZeroMemory(ack_payload, sizeof(ack_payload));
#else
        memset(ack_payload, 0, sizeof(ack_payload));
#endif

        if (enc_err == CLIP_OK) {
            ClipError send_err = clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            if (send_err == CLIP_OK) {
                srv->total_frames_sent++;
                CLIP_LOGI("REGISTER_ACK sent to %s:%u (authenticated)", client->ip_str, client->port);
            } else {
                CLIP_LOGW("Failed to send REGISTER_ACK to %s:%u", client->ip_str, client->port);
            }
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_AUTH) {
        /*
         * Phase 17 Stage 4: Server-Side Rate Limiting Check
         */
        uint64_t now_ms = srv->mock_now_ms ? srv->mock_now_ms : current_time_ms();
        if (clip_rate_limiter_check(&srv->rate_limiter, client->ip_str, now_ms) != CLIP_OK) {
            CLIP_LOGW("AUTH rejected for IP %s: rate limit active / saturated", client->ip_str);
            send_auth_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_AUTH);
            client->auth_state = CLIP_AUTH_STATE_FAILED;
            return;
        }

        /*
         * Phase 3 Authenticated Reconnect Flow:
         * 1. Extract NODE_UUID and CREDENTIAL TLVs
         * 2. Look up stored verifier in SQLite
         * 3. Perform constant-time verifier comparison
         * 4. Reply with AUTH_OK on success or AUTH_FAIL on failure
         */
        const uint8_t* uuid_ptr = NULL;
        uint16_t uuid_len = 0;
        const uint8_t* cred_ptr = NULL;
        uint16_t cred_len = 0;

        ClipError err_uuid = clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_NODE_UUID, &uuid_ptr, &uuid_len);
        ClipError err_cred = clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CREDENTIAL, &cred_ptr, &cred_len);

        if (err_uuid != CLIP_OK || err_cred != CLIP_OK ||
            uuid_len != CLIP_UUID_BYTES || cred_len != CLIP_CREDENTIAL_BYTES) {
            CLIP_LOGW("Malformed AUTH payload from %s:%u (missing/invalid TLVs)", client->ip_str, client->port);
            clip_rate_limiter_record_failure(&srv->rate_limiter, client->ip_str, now_ms);
            send_auth_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_PROTO);
            client->auth_state = CLIP_AUTH_STATE_FAILED;
            return;
        }

        ClipUuid req_uuid;
        memcpy(req_uuid.bytes, uuid_ptr, CLIP_UUID_BYTES);

        char out_name[CLIP_DISPLAY_NAME_MAX];
        bool is_revoked = false;

        ClipError auth_err = clip_identity_authenticate(srv->identity_db,
                                                        &req_uuid,
                                                        cred_ptr,
                                                        out_name,
                                                        sizeof(out_name),
                                                        &is_revoked);

        if (auth_err == CLIP_OK) {
            sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
            ClipNodeSanction sanc;
            if (clip_admin_db_get_sanction(db, req_uuid.bytes, &sanc) == CLIP_OK) {
                if (sanc.status == CLIP_SANCTION_BANNED) {
                    CLIP_LOGW("Banned node %s rejected on AUTH", client->ip_str);
                    clip_rate_limiter_record_failure(&srv->rate_limiter, client->ip_str, now_ms);
                    send_auth_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_BANNED);
                    client->auth_state = CLIP_AUTH_STATE_FAILED;
                    return;
                } else if (sanc.status == CLIP_SANCTION_RESTRICTED) {
                    client->is_restricted = true;
                    CLIP_LOGI("Node authenticated with RESTRICTED status");
                }
            }

            clip_rate_limiter_record_success(&srv->rate_limiter, client->ip_str, now_ms);

            client->registered = true;
            client->auth_state = CLIP_AUTH_STATE_AUTHENTICATED;
            memcpy(client->node_uuid, req_uuid.bytes, CLIP_UUID_BYTES);
            strncpy(client->display_name, out_name, sizeof(client->display_name) - 1);

            char uuid_str[CLIP_UUID_STR_SIZE];
            clip_uuid_to_string(&req_uuid, uuid_str, sizeof(uuid_str));
            CLIP_LOGI("Node authenticated successfully: UUID=%s, display_name='%s'", uuid_str, client->display_name);

            /* Construct AUTH_OK payload with NODE_UUID and DISPLAY_NAME */
            uint8_t ok_payload[256];
            size_t ok_payload_len = 0;
            clip_tlv_write(ok_payload, sizeof(ok_payload), &ok_payload_len,
                           CLIP_TAG_NODE_UUID, req_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(ok_payload, sizeof(ok_payload), &ok_payload_len,
                           CLIP_TAG_DISPLAY_NAME, client->display_name, (uint16_t)strlen(client->display_name));

            ClipFrameHeader tx_hdr;
            clip_frame_header_init(&tx_hdr,
                                   CLIP_MSG_AUTH_OK,
                                   (uint32_t)ok_payload_len,
                                   rx_hdr->seq_num + 1,
                                   NULL);

            uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 256];
            size_t frame_len = 0;
            if (clip_frame_encode(&tx_hdr, ok_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
                clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
                srv->total_frames_sent++;
                CLIP_LOGI("AUTH_OK sent to %s:%u", client->ip_str, client->port);
            }
        } else if (is_revoked || auth_err == CLIP_ERR_DENIED) {
            CLIP_LOGW("Authentication REJECTED for revoked node from %s:%u", client->ip_str, client->port);
            clip_rate_limiter_record_failure(&srv->rate_limiter, client->ip_str, now_ms);
            client->auth_state = CLIP_AUTH_STATE_REVOKED;
            send_auth_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
        } else {
            CLIP_LOGW("Authentication FAILED (%s) from %s:%u", clip_error_string(auth_err), client->ip_str, client->port);
            clip_rate_limiter_record_failure(&srv->rate_limiter, client->ip_str, now_ms);
            client->auth_state = CLIP_AUTH_STATE_FAILED;
            send_auth_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_AUTH);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_HEARTBEAT) {
        /*
         * Phase 17: Heartbeat ping from client.
         * Server acknowledges immediately with CLIP_MSG_HEARTBEAT_ACK.
         */
        client->missed_heartbeats = 0;
        uint64_t now_ms = srv->mock_now_ms ? srv->mock_now_ms : current_time_ms();
        client->last_seen_ms = now_ms;
        client->last_heartbeat_ack_ms = now_ms;

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_HEARTBEAT_ACK, 0, rx_hdr->seq_num + 1, NULL);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 64];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, NULL, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("HEARTBEAT_ACK sent to %s:%u", client->ip_str, client->port);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_HEARTBEAT_ACK) {
        /*
         * Phase 17: Heartbeat pong received from client.
         */
        uint64_t now_ms = srv->mock_now_ms ? srv->mock_now_ms : current_time_ms();
        client->last_seen_ms = now_ms;
        client->last_heartbeat_ack_ms = now_ms;
        client->missed_heartbeats = 0;
        client->heartbeat_in_flight = false;
        CLIP_LOGI("HEARTBEAT_ACK received from %s:%u", client->ip_str, client->port);
    } else if (rx_hdr->msg_type == CLIP_MSG_PTT_REQUEST) {
        /*
         * Phase 8: PTT Floor Request
         */
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            CLIP_LOGW("Unauthorized PTT_REQUEST from unauthenticated client %s:%u", client->ip_str, client->port);
            send_auth_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        if (client->is_restricted) {
            CLIP_LOGW("Restricted node %s:%u denied PTT floor request", client->ip_str, client->port);
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, rx_hdr->session_uuid, NULL, CLIP_ERR_RESTRICTED);
            return;
        }

        /* 1. Wire Header Invariant: Must contain genuine active session_uuid */
        if (clip_uuid_is_zero((const ClipUuid*)rx_hdr->session_uuid)) {
            CLIP_LOGW("PTT_REQUEST rejected: header.session_uuid is zero");
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, rx_hdr->session_uuid, NULL, CLIP_ERR_INVALID);
            return;
        }

        ClipUuid sess_uuid;
        memcpy(sess_uuid.bytes, rx_hdr->session_uuid, CLIP_UUID_BYTES);

        /* 2. Verify Session exists and is ACTIVE */
        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipSessionRecord sess_rec;
        ClipError s_err = clip_session_get(db, &sess_uuid, &sess_rec);
        if (s_err != CLIP_OK || sess_rec.state != CLIP_SESSION_STATE_ACTIVE) {
            CLIP_LOGW("PTT_REQUEST rejected: session is not active or not found");
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, sess_uuid.bytes, NULL, CLIP_ERR_NO_SESSION);
            return;
        }

        /* 3. Verify requester is authorized session endpoint or channel member */
        bool is_endpoint = clip_uuid_equal((const ClipUuid*)client->node_uuid, &sess_rec.initiator_node_uuid) ||
                           (!clip_uuid_is_zero(&sess_rec.peer_node_uuid) && clip_uuid_equal((const ClipUuid*)client->node_uuid, &sess_rec.peer_node_uuid));
        if (!is_endpoint && clip_uuid_is_zero(&sess_rec.peer_node_uuid) && !clip_uuid_is_zero(&sess_rec.channel_uuid)) {
            bool is_member = false;
            if (clip_channel_is_member(db, &sess_rec.channel_uuid, (const ClipUuid*)client->node_uuid, &is_member) == CLIP_OK && is_member) {
                is_endpoint = true;
            }
        }
        if (!is_endpoint) {
            CLIP_LOGW("PTT_REQUEST rejected: client is not an authorized endpoint of session");
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, sess_uuid.bytes, NULL, CLIP_ERR_DENIED);
            return;
        }

        uint32_t lease_ms = CLIP_PTT_DEFAULT_LEASE_MS;
        const uint8_t* lease_val = NULL;
        uint16_t lease_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_LEASE_TIMEOUT_MS, &lease_val, &lease_len) == CLIP_OK && lease_len == 4) {
            lease_ms = ((uint32_t)lease_val[0] << 24) | ((uint32_t)lease_val[1] << 16) | ((uint32_t)lease_val[2] << 8) | (uint32_t)lease_val[3];
        }

        uint64_t now_ms = srv->mock_now_ms ? srv->mock_now_ms : current_time_ms();
        ClipPttFloorEntry entry;
        bool already_held = false;
        ClipError acq_err = clip_ptt_manager_acquire(&srv->ptt_mgr, &sess_uuid, (const ClipUuid*)client->node_uuid, lease_ms, now_ms, &entry, &already_held);

        if (acq_err == CLIP_OK) {
            /* Floor granted */
            send_ptt_grant(srv, client->sock, rx_hdr->seq_num + 1, sess_uuid.bytes, &entry.holder_node_uuid, entry.acquired_at_ms, entry.lease_duration_ms);
            CLIP_LOGI("PTT FLOOR GRANTED to %s:%u for session", client->ip_str, client->port);

            /* If newly granted, notify peer(s) */
            if (!already_held) {
                if (!clip_uuid_is_zero(&sess_rec.peer_node_uuid)) {
                    ClipUuid peer_uuid = clip_uuid_equal((const ClipUuid*)client->node_uuid, &sess_rec.initiator_node_uuid) ?
                                         sess_rec.peer_node_uuid : sess_rec.initiator_node_uuid;
                    if (!clip_uuid_is_zero(&peer_uuid)) {
                        ClipClientConn* peer_cc = clip_client_table_find_by_node_uuid(&srv->clients, &peer_uuid);
                        if (peer_cc) {
                            send_ptt_notify(srv, peer_cc->sock, sess_uuid.bytes, CLIP_PTT_FLOOR_HELD, (const ClipUuid*)client->node_uuid, entry.acquired_at_ms);
                        }
                    }
                } else if (!clip_uuid_is_zero(&sess_rec.channel_uuid)) {
                    ClipChannelMember* ch_mems = NULL;
                    size_t ch_cnt = 0;
                    if (clip_channel_get_members(db, &sess_rec.channel_uuid, &ch_mems, &ch_cnt) == CLIP_OK) {
                        for (size_t m = 0; m < ch_cnt; m++) {
                            if (!clip_uuid_equal(&ch_mems[m].node_uuid, (const ClipUuid*)client->node_uuid)) {
                                ClipClientConn* peer_cc = clip_client_table_find_by_node_uuid(&srv->clients, &ch_mems[m].node_uuid);
                                if (peer_cc && peer_cc->active) {
                                    send_ptt_notify(srv, peer_cc->sock, sess_uuid.bytes, CLIP_PTT_FLOOR_HELD, (const ClipUuid*)client->node_uuid, entry.acquired_at_ms);
                                }
                            }
                        }
                        clip_channel_free_members(ch_mems);
                    }
                }
            }
        } else if (acq_err == CLIP_ERR_PTT_BUSY) {
            /* Floor busy */
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, sess_uuid.bytes, &entry.holder_node_uuid, CLIP_ERR_PTT_BUSY);
            CLIP_LOGI("PTT FLOOR DENIED (busy) to %s:%u for session", client->ip_str, client->port);
        } else {
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, sess_uuid.bytes, NULL, acq_err);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_PTT_RELEASE) {
        /*
         * Phase 8: PTT Floor Release
         */
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            CLIP_LOGW("Unauthorized PTT_RELEASE from unauthenticated client %s:%u", client->ip_str, client->port);
            send_auth_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        if (clip_uuid_is_zero((const ClipUuid*)rx_hdr->session_uuid)) {
            CLIP_LOGW("PTT_RELEASE rejected: header.session_uuid is zero");
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, rx_hdr->session_uuid, NULL, CLIP_ERR_INVALID);
            return;
        }

        ClipUuid sess_uuid;
        memcpy(sess_uuid.bytes, rx_hdr->session_uuid, CLIP_UUID_BYTES);

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipSessionRecord sess_rec;
        ClipError s_err = clip_session_get(db, &sess_uuid, &sess_rec);
        if (s_err != CLIP_OK || sess_rec.state != CLIP_SESSION_STATE_ACTIVE) {
            CLIP_LOGW("PTT_RELEASE rejected: session is not active or not found");
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, sess_uuid.bytes, NULL, CLIP_ERR_NO_SESSION);
            return;
        }

        ClipPttFloorEntry entry;
        ClipError rel_err = clip_ptt_manager_release(&srv->ptt_mgr, &sess_uuid, (const ClipUuid*)client->node_uuid, &entry);
        if (rel_err == CLIP_ERR_DENIED) {
            CLIP_LOGW("PTT_RELEASE rejected: caller is not current floor holder");
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, sess_uuid.bytes, &entry.holder_node_uuid, CLIP_ERR_DENIED);
            return;
        }

        /* Released successfully */
        send_ptt_released(srv, client->sock, rx_hdr->seq_num + 1, sess_uuid.bytes);
        CLIP_LOGI("PTT FLOOR RELEASED by %s:%u", client->ip_str, client->port);

        /* Notify peer(s) that floor is now FREE */
        if (!clip_uuid_is_zero(&sess_rec.peer_node_uuid)) {
            ClipUuid peer_uuid = clip_uuid_equal((const ClipUuid*)client->node_uuid, &sess_rec.initiator_node_uuid) ?
                                 sess_rec.peer_node_uuid : sess_rec.initiator_node_uuid;
            if (!clip_uuid_is_zero(&peer_uuid)) {
                ClipClientConn* peer_cc = clip_client_table_find_by_node_uuid(&srv->clients, &peer_uuid);
                if (peer_cc) {
                    send_ptt_notify(srv, peer_cc->sock, sess_uuid.bytes, CLIP_PTT_FLOOR_FREE, NULL, 0);
                }
            }
        } else if (!clip_uuid_is_zero(&sess_rec.channel_uuid)) {
            ClipChannelMember* ch_mems = NULL;
            size_t ch_cnt = 0;
            if (clip_channel_get_members(db, &sess_rec.channel_uuid, &ch_mems, &ch_cnt) == CLIP_OK) {
                for (size_t m = 0; m < ch_cnt; m++) {
                    if (!clip_uuid_equal(&ch_mems[m].node_uuid, (const ClipUuid*)client->node_uuid)) {
                        ClipClientConn* peer_cc = clip_client_table_find_by_node_uuid(&srv->clients, &ch_mems[m].node_uuid);
                        if (peer_cc && peer_cc->active) {
                            send_ptt_notify(srv, peer_cc->sock, sess_uuid.bytes, CLIP_PTT_FLOOR_FREE, NULL, 0);
                        }
                    }
                }
                clip_channel_free_members(ch_mems);
            }
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_PTT_FLOOR_STATUS_REQ) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_auth_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }
        if (clip_uuid_is_zero((const ClipUuid*)rx_hdr->session_uuid)) {
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, rx_hdr->session_uuid, NULL, CLIP_ERR_INVALID);
            return;
        }

        ClipUuid sess_uuid;
        memcpy(sess_uuid.bytes, rx_hdr->session_uuid, CLIP_UUID_BYTES);

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipSessionRecord sess_rec;
        ClipError s_err = clip_session_get(db, &sess_uuid, &sess_rec);
        if (s_err != CLIP_OK || sess_rec.state != CLIP_SESSION_STATE_ACTIVE) {
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, sess_uuid.bytes, NULL, CLIP_ERR_NO_SESSION);
            return;
        }

        uint64_t now_ms = srv->mock_now_ms ? srv->mock_now_ms : current_time_ms();
        ClipPttFloorEntry entry;
        clip_ptt_manager_get_status(&srv->ptt_mgr, &sess_uuid, now_ms, &entry);
        send_ptt_status_resp(srv, client->sock, rx_hdr->seq_num + 1, sess_uuid.bytes, &entry, now_ms);
    } else if (rx_hdr->msg_type == CLIP_MSG_PTT_FLOOR_RENEW) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_auth_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }
        if (clip_uuid_is_zero((const ClipUuid*)rx_hdr->session_uuid)) {
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, rx_hdr->session_uuid, NULL, CLIP_ERR_INVALID);
            return;
        }

        ClipUuid sess_uuid;
        memcpy(sess_uuid.bytes, rx_hdr->session_uuid, CLIP_UUID_BYTES);

        uint64_t now_ms = srv->mock_now_ms ? srv->mock_now_ms : current_time_ms();
        uint32_t remaining_ms = 0;
        ClipError ren_err = clip_ptt_manager_renew(&srv->ptt_mgr, &sess_uuid, (const ClipUuid*)client->node_uuid, now_ms, &remaining_ms);
        if (ren_err == CLIP_OK) {
            send_ptt_renew_ack(srv, client->sock, rx_hdr->seq_num + 1, sess_uuid.bytes, remaining_ms);
        } else {
            send_ptt_deny(srv, client->sock, rx_hdr->seq_num + 1, sess_uuid.bytes, NULL, ren_err);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_GOODBYE) {
        CLIP_LOGI("Client %s:%u requested GOODBYE disconnect", client->ip_str, client->port);
        clip_server_handle_client_disconnect(srv, client);
        return;
    } else if (rx_hdr->msg_type == CLIP_MSG_AUDIO_FRAME) {
        /*
         * Phase 10: Real-Time Audio Transport & Session Relay
         *
         * Critical Requirements:
         * 1. Per-session / per-sender audio sequence validation (strictly increasing)
         * 2. Strict maximum PCM audio payload/frame size enforcement
         * 3. timestamp_ms treated as metadata ONLY; never floor ownership proof
         * 4. Server is validation-and-relay ONLY; no decoding/resampling/playback on server
         */

        /* Requirement 2: Enforce strict maximum PCM payload size */
        if (rx_hdr->payload_len > CLIP_AUDIO_MAX_PAYLOAD_BYTES + 64u) {
            CLIP_LOGW("AUDIO_FRAME rejected: payload_len (%u) exceeds strict max (%u)",
                      rx_hdr->payload_len, (unsigned)(CLIP_AUDIO_MAX_PAYLOAD_BYTES + 64u));
            srv->dropped_audio_frames++;
            return;
        }

        /* Authentication Check */
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            CLIP_LOGW("AUDIO_FRAME rejected: unauthenticated client %s:%u", client->ip_str, client->port);
            srv->dropped_audio_frames++;
            return;
        }

        /* Session Header Invariant: Must contain genuine active session_uuid */
        if (clip_uuid_is_zero((const ClipUuid*)rx_hdr->session_uuid)) {
            CLIP_LOGW("AUDIO_FRAME rejected: header.session_uuid is zero");
            srv->dropped_audio_frames++;
            return;
        }

        ClipUuid sess_uuid;
        memcpy(sess_uuid.bytes, rx_hdr->session_uuid, CLIP_UUID_BYTES);

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipSessionRecord sess_rec;
        ClipError s_err = clip_session_get(db, &sess_uuid, &sess_rec);
        if (s_err != CLIP_OK || sess_rec.state != CLIP_SESSION_STATE_ACTIVE) {
            CLIP_LOGW("AUDIO_FRAME rejected: session is non-existent or inactive");
            srv->dropped_audio_frames++;
            return;
        }

        /* Half-duplex PTT floor authority verification */
        uint64_t now_ms = srv->mock_now_ms ? srv->mock_now_ms : current_time_ms();
        ClipPttFloorEntry entry;
        ClipError fl_err = clip_ptt_manager_get_status(&srv->ptt_mgr, &sess_uuid, now_ms, &entry);
        if (fl_err != CLIP_OK || entry.floor_state != CLIP_PTT_FLOOR_HELD) {
            CLIP_LOGW("AUDIO_FRAME rejected: floor is not currently HELD");
            srv->dropped_audio_frames++;
            return;
        }

        if (memcmp(entry.holder_node_uuid.bytes, client->node_uuid, CLIP_UUID_BYTES) != 0) {
            CLIP_LOGW("AUDIO_FRAME rejected: sender %s is NOT the current floor holder (anti-spoof)",
                      client->display_name);
            srv->dropped_audio_frames++;
            return;
        }

        /* Requirement 1: Per-session / per-sender sequence validation */
        ClipError seq_err = clip_audio_seq_validate_and_update(&srv->audio_seq_tracker,
                                                               &sess_uuid,
                                                               (const uint8_t*)client->node_uuid,
                                                               rx_hdr->seq_num);
        if (seq_err != CLIP_OK) {
            CLIP_LOGW("AUDIO_FRAME rejected: duplicate, stale, or out-of-order sequence %llu",
                      (unsigned long long)rx_hdr->seq_num);
            srv->dropped_audio_frames++;
            return;
        }

        /* Floor lease keepalive: renew floor lease on valid audio frame from floor holder */
        clip_ptt_manager_renew(&srv->ptt_mgr, &sess_uuid, (const ClipUuid*)client->node_uuid, now_ms, NULL);

        /* Validate TLV structure (codec type, bounds) */
        uint8_t codec_type = 0;
        uint64_t ts_ms = 0;
        const uint8_t* raw_audio = NULL;
        size_t raw_len = 0;
        ClipError parse_err = clip_audio_frame_parse_raw(rx_payload, rx_payload_len,
                                                         &codec_type, &ts_ms,
                                                         &raw_audio, &raw_len);
        if (parse_err != CLIP_OK) {
            CLIP_LOGW("AUDIO_FRAME rejected: malformed TLV structure (%s)", clip_error_string(parse_err));
            srv->dropped_audio_frames++;
            return;
        }

        /* Requirement 4: Server is validation-and-relay ONLY. Re-encode and relay raw frame */
        uint8_t relay_buf[CLIP_MAX_FRAME_SIZE];
        size_t relay_len = 0;
        if (clip_frame_encode(rx_hdr, rx_payload, relay_buf, sizeof(relay_buf), &relay_len) == CLIP_OK) {
            /* Identify session peer(s) */
            if (!clip_uuid_is_zero(&sess_rec.channel_uuid)) {
                ClipChannelMember* ch_mems = NULL;
                size_t ch_cnt = 0;
                if (clip_channel_get_members(db, &sess_rec.channel_uuid, &ch_mems, &ch_cnt) == CLIP_OK) {
                    for (size_t m = 0; m < ch_cnt; m++) {
                        if (!clip_uuid_equal(&ch_mems[m].node_uuid, (const ClipUuid*)client->node_uuid)) {
                            ClipClientConn* peer_cc = clip_client_table_find_by_node_uuid(&srv->clients, &ch_mems[m].node_uuid);
                            if (peer_cc && peer_cc->active) {
                                clip_server_send_client_data(srv, peer_cc->sock, relay_buf, relay_len);
                                srv->total_frames_sent++;
                                srv->total_audio_frames_relayed++;
                            }
                        }
                    }
                    clip_channel_free_members(ch_mems);
                }
            } else {
                /* 1:1 Instant Connection session */
                ClipUuid peer_uuid;
                if (clip_uuid_equal((const ClipUuid*)client->node_uuid, &sess_rec.initiator_node_uuid)) {
                    peer_uuid = sess_rec.peer_node_uuid;
                } else {
                    peer_uuid = sess_rec.initiator_node_uuid;
                }

                if (!clip_uuid_is_zero(&peer_uuid)) {
                    ClipClientConn* peer_cc = clip_client_table_find_by_node_uuid(&srv->clients, &peer_uuid);
                    if (peer_cc && peer_cc->active) {
                        clip_server_send_client_data(srv, peer_cc->sock, relay_buf, relay_len);
                        srv->total_frames_sent++;
                        srv->total_audio_frames_relayed++;
                    }
                }
            }
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_CHANNEL_CREATE) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            CLIP_LOGW("Unauthorized CHANNEL_CREATE from unauthenticated client %s:%u", client->ip_str, client->port);
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        char chan_name[CLIP_DISPLAY_NAME_MAX] = "GENERAL";
        const uint8_t* name_ptr = NULL;
        uint16_t name_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CHANNEL_NAME, &name_ptr, &name_len) == CLIP_OK && name_len > 0) {
            size_t copy_len = (name_len < sizeof(chan_name) - 1) ? name_len : (sizeof(chan_name) - 1);
            memcpy(chan_name, name_ptr, copy_len);
            chan_name[copy_len] = '\0';
        }

        uint16_t member_limit = 16;
        const uint8_t* lim_ptr = NULL;
        uint16_t lim_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_MEMBER_LIMIT, &lim_ptr, &lim_len) == CLIP_OK && lim_len == 2) {
            member_limit = ((uint16_t)lim_ptr[0] << 8) | (uint16_t)lim_ptr[1];
            if (member_limit < 2) member_limit = 2;
            if (member_limit > 64) member_limit = 64;
        }

        ClipUuid chan_uuid;
        char join_key[CLIP_JOIN_KEY_MAX];
        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipError err = clip_channel_create_with_limit(db, (const ClipUuid*)client->node_uuid, chan_name, member_limit, &chan_uuid, join_key, sizeof(join_key));
        if (err != CLIP_OK) {
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, err);
            return;
        }

        uint8_t ack_payload[512];
        size_t ack_len = 0;
        clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_CHANNEL_JOIN_KEY, join_key, (uint16_t)strlen(join_key));
        clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_CHANNEL_NAME, chan_name, (uint16_t)strlen(chan_name));

        uint8_t lim_buf[2] = { (uint8_t)((member_limit >> 8) & 0xFF), (uint8_t)(member_limit & 0xFF) };
        clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_MEMBER_LIMIT, lim_buf, 2);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_CREATE_OK, (uint32_t)ack_len, rx_hdr->seq_num + 1, NULL);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 512];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, ack_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("CHANNEL_CREATE_OK sent to %s:%u (key: %s, limit: %u)", client->ip_str, client->port, join_key, (unsigned)member_limit);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_CHANNEL_JOIN) {
        uint64_t now_ms = srv->mock_now_ms ? srv->mock_now_ms : current_time_ms();

        /* Rate limit check for invitation attempts */
        if (clip_rate_limiter_check(&srv->rate_limiter, client->ip_str, now_ms) != CLIP_OK) {
            CLIP_LOGW("CHANNEL_JOIN rejected for IP %s: rate limit active / blocked", client->ip_str);
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_RATE_LIMITED);
            return;
        }

        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            CLIP_LOGW("Unauthorized CHANNEL_JOIN from unauthenticated client %s:%u", client->ip_str, client->port);
            clip_rate_limiter_record_failure(&srv->rate_limiter, client->ip_str, now_ms);
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        const uint8_t* key_ptr = NULL;
        uint16_t key_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CHANNEL_JOIN_KEY, &key_ptr, &key_len) != CLIP_OK || key_len == 0) {
            clip_rate_limiter_record_failure(&srv->rate_limiter, client->ip_str, now_ms);
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
            return;
        }

        char join_key[CLIP_JOIN_KEY_MAX];
        size_t copy_len = (key_len < sizeof(join_key) - 1) ? key_len : (sizeof(join_key) - 1);
        memcpy(join_key, key_ptr, copy_len);
        join_key[copy_len] = '\0';

        ClipUuid chan_uuid;
        char chan_name[CLIP_DISPLAY_NAME_MAX];
        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipError err = clip_channel_join_by_key(db, (const ClipUuid*)client->node_uuid, join_key, &chan_uuid, chan_name, sizeof(chan_name));
        if (err != CLIP_OK) {
            if (err == CLIP_ERR_NOT_FOUND || err == CLIP_ERR_DENIED || err == CLIP_ERR_REVOKED) {
                clip_rate_limiter_record_failure(&srv->rate_limiter, client->ip_str, now_ms);
            }
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, err);
            return;
        }
        clip_rate_limiter_record_success(&srv->rate_limiter, client->ip_str, now_ms);

        /* Retrieve channel members and resolve presence */
        ClipChannelMember* members = NULL;
        size_t member_count = 0;
        clip_channel_get_members(db, &chan_uuid, &members, &member_count);

        uint8_t ack_payload[4096];
        size_t ack_len = 0;
        clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_CHANNEL_NAME, chan_name, (uint16_t)strlen(chan_name));
        clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_CHANNEL_JOIN_KEY, join_key, (uint16_t)strlen(join_key));

        uint16_t m_cnt = (uint16_t)member_count;
        uint8_t cnt_buf[2] = { (uint8_t)((m_cnt >> 8) & 0xFF), (uint8_t)(m_cnt & 0xFF) };
        clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_MEMBER_COUNT, cnt_buf, 2);

        for (size_t i = 0; i < member_count; i++) {
            ClipPresence pres = CLIP_PRESENCE_OFFLINE;
            for (size_t c_idx = 0; c_idx < srv->clients.capacity; c_idx++) {
                ClipClientConn* cc = &srv->clients.clients[c_idx];
                if (cc->active && cc->registered && clip_uuid_equal((const ClipUuid*)cc->node_uuid, &members[i].node_uuid)) {
                    pres = CLIP_PRESENCE_ONLINE;
                    break;
                }
            }
            uint8_t pres_byte = (uint8_t)pres;
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_NODE_UUID, members[i].node_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_DISPLAY_NAME, members[i].display_name, (uint16_t)strlen(members[i].display_name));
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_PRESENCE, &pres_byte, 1);
        }
        clip_channel_free_members(members);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_JOIN_OK, (uint32_t)ack_len, rx_hdr->seq_num + 1, NULL);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 4096];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, ack_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("CHANNEL_JOIN_OK sent to %s:%u (chan: %s)", client->ip_str, client->port, chan_name);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_CHANNEL_LIST) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipChannelRecord* channels = NULL;
        size_t chan_count = 0;
        clip_channel_list_for_node(db, (const ClipUuid*)client->node_uuid, &channels, &chan_count);

        uint8_t resp_payload[4096];
        size_t resp_len = 0;
        uint16_t c_cnt = (uint16_t)chan_count;
        uint8_t cnt_buf[2] = { (uint8_t)((c_cnt >> 8) & 0xFF), (uint8_t)(c_cnt & 0xFF) };
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_MEMBER_COUNT, cnt_buf, 2);

        for (size_t i = 0; i < chan_count; i++) {
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CHANNEL_UUID, channels[i].channel_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CHANNEL_NAME, channels[i].name, (uint16_t)strlen(channels[i].name));
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CHANNEL_JOIN_KEY, channels[i].join_key, (uint16_t)strlen(channels[i].join_key));
        }
        clip_channel_free_list(channels);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_LIST_RESP, (uint32_t)resp_len, rx_hdr->seq_num + 1, NULL);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 4096];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, resp_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_CHANNEL_LEAVE) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        const uint8_t* chan_ptr = NULL;
        uint16_t chan_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CHANNEL_UUID, &chan_ptr, &chan_len) == CLIP_OK && chan_len == CLIP_UUID_BYTES) {
            ClipUuid chan_uuid;
            memcpy(chan_uuid.bytes, chan_ptr, CLIP_UUID_BYTES);
            sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
            clip_channel_leave(db, &chan_uuid, (const ClipUuid*)client->node_uuid);
        }

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_MEMBER_UPD, 0, rx_hdr->seq_num + 1, NULL);
        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 32];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, NULL, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_CHANNEL_REVOKE_KEY) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        const uint8_t* chan_ptr = NULL;
        uint16_t chan_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CHANNEL_UUID, &chan_ptr, &chan_len) != CLIP_OK || chan_len != CLIP_UUID_BYTES) {
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
            return;
        }

        ClipUuid chan_uuid;
        memcpy(chan_uuid.bytes, chan_ptr, CLIP_UUID_BYTES);
        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipError err = clip_channel_revoke_key(db, &chan_uuid, (const ClipUuid*)client->node_uuid);
        if (err != CLIP_OK) {
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, err);
            return;
        }

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_REVOKE_KEY_OK, 0, rx_hdr->seq_num + 1, NULL);
        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 32];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, NULL, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("CHANNEL_REVOKE_KEY_OK sent to %s:%u", client->ip_str, client->port);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_CHANNEL_CLOSE) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        const uint8_t* chan_ptr = NULL;
        uint16_t chan_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CHANNEL_UUID, &chan_ptr, &chan_len) != CLIP_OK || chan_len != CLIP_UUID_BYTES) {
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
            return;
        }

        ClipUuid chan_uuid;
        memcpy(chan_uuid.bytes, chan_ptr, CLIP_UUID_BYTES);
        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipError err = clip_channel_close(db, &chan_uuid, (const ClipUuid*)client->node_uuid);
        if (err != CLIP_OK) {
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, err);
            return;
        }

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_CLOSE_OK, 0, rx_hdr->seq_num + 1, NULL);
        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 32];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, NULL, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("CHANNEL_CLOSE_OK sent to %s:%u", client->ip_str, client->port);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_SESSION_START) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            CLIP_LOGW("Unauthorized SESSION_START from unauthenticated client %s:%u", client->ip_str, client->port);
            send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        if (client->is_restricted) {
            CLIP_LOGW("Restricted node %s:%u denied SESSION_START", client->ip_str, client->port);
            send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_RESTRICTED);
            return;
        }

        const uint8_t* cu_ptr = NULL;
        uint16_t cu_len = 0;
        bool has_conn = (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CONNECTION_UUID, &cu_ptr, &cu_len) == CLIP_OK && cu_len == CLIP_UUID_BYTES);

        if (has_conn) {
            ClipUuid conn_uuid;
            memcpy(conn_uuid.bytes, cu_ptr, CLIP_UUID_BYTES);

            sqlite3* db = clip_identity_get_sqlite(srv->identity_db);

            /* 1. Retrieve connection and verify it exists */
            ClipConnectionRecord conn;
            ClipError c_err = clip_connection_get(db, &conn_uuid, &conn);
            if (c_err != CLIP_OK) {
                CLIP_LOGW("SESSION_START rejected: connection not found");
                send_session_fail(client->sock, rx_hdr->seq_num + 1, c_err);
                return;
            }

            /* 2. Connection state MUST be ACCEPTED */
            if (conn.state != CLIP_CONN_STATE_ACCEPTED) {
                CLIP_LOGW("SESSION_START rejected: connection state is %d (expected ACCEPTED)", (int)conn.state);
                send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
                return;
            }

            /* 3. Caller must be an endpoint of the connection */
            bool is_req = clip_uuid_equal((const ClipUuid*)client->node_uuid, &conn.requester_node_uuid);
            bool is_tgt = clip_uuid_equal((const ClipUuid*)client->node_uuid, &conn.target_node_uuid);
            if (!is_req && !is_tgt) {
                CLIP_LOGW("SESSION_START rejected: caller is not an endpoint of connection");
                send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
                return;
            }

            ClipUuid peer_uuid = is_req ? conn.target_node_uuid : conn.requester_node_uuid;

            /* 4. Peer presence: peer must be currently ONLINE */
            ClipClientConn* peer_client = clip_client_table_find_by_node_uuid(&srv->clients, &peer_uuid);
            if (!peer_client) {
                CLIP_LOGW("SESSION_START rejected: peer node is offline");
                send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NOT_FOUND);
                return;
            }

            /* 5. Reject duplicate active session for this connection */
            ClipSessionRecord act_sess;
            if (clip_session_get_active_for_connection(db, &conn_uuid, &act_sess) == CLIP_OK) {
                CLIP_LOGW("SESSION_START rejected: active session already exists for connection");
                send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_EXISTS);
                return;
            }

            /* 6. Create session bound to connection */
            ClipUuid sess_uuid;
            ClipError cr_err = clip_session_create_for_connection(db, &conn_uuid, (const ClipUuid*)client->node_uuid, &sess_uuid);
            if (cr_err != CLIP_OK) {
                send_session_fail(client->sock, rx_hdr->seq_num + 1, cr_err);
                return;
            }

            /* 7. Send SESSION_START_ACK to initiator with genuine session_uuid in header */
            uint8_t ack_payload[512];
            size_t ack_len = 0;
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_SESSION_UUID, sess_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_CONNECTION_UUID, conn_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_CHANNEL_UUID, conn.channel_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_NODE_UUID, client->node_uuid, CLIP_UUID_BYTES);
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_TARGET_NODE_UUID, peer_uuid.bytes, CLIP_UUID_BYTES);
            uint8_t sm = srv->config.speech_mode ? srv->config.speech_mode : (uint8_t)CLIP_SPEECH_MODE_SERVER_MEDIATED;
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_SPEECH_ANALYSIS, &sm, 1);

            ClipFrameHeader tx_hdr;
            clip_frame_header_init(&tx_hdr, CLIP_MSG_SESSION_START_ACK, (uint32_t)ack_len, rx_hdr->seq_num + 1, sess_uuid.bytes);

            uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 512];
            size_t frame_len = 0;
            if (clip_frame_encode(&tx_hdr, ack_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
                clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
                srv->total_frames_sent++;
                CLIP_LOGI("SESSION_START_ACK sent to initiator %s:%u", client->ip_str, client->port);
            }

            /* 8. Notify peer with SESSION_START (genuine session_uuid in header) */
            ClipFrameHeader notif_hdr;
            clip_frame_header_init(&notif_hdr, CLIP_MSG_SESSION_START, (uint32_t)ack_len, 1, sess_uuid.bytes);
            uint8_t notif_buf[CLIP_MIN_FRAME_SIZE + 512];
            size_t notif_len = 0;
            if (clip_frame_encode(&notif_hdr, ack_payload, notif_buf, sizeof(notif_buf), &notif_len) == CLIP_OK) {
                clip_server_send_client_data(srv, peer_client->sock, notif_buf, notif_len);
                srv->total_frames_sent++;
                CLIP_LOGI("SESSION_START notification sent to peer %s:%u", peer_client->ip_str, peer_client->port);
            }
        } else {
            /* Fallback/legacy: channel-level session start for Phase 4 compatibility */
            const uint8_t* chan_ptr = NULL;
            uint16_t chan_len = 0;
            if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CHANNEL_UUID, &chan_ptr, &chan_len) != CLIP_OK || chan_len != CLIP_UUID_BYTES) {
                send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
                return;
            }

            ClipUuid chan_uuid;
            memcpy(chan_uuid.bytes, chan_ptr, CLIP_UUID_BYTES);

            ClipUuid sess_uuid;
            sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
            ClipError err = clip_session_start(db, &chan_uuid, (const ClipUuid*)client->node_uuid, &sess_uuid);
            if (err != CLIP_OK) {
                send_session_fail(client->sock, rx_hdr->seq_num + 1, err);
                return;
            }

            uint8_t ack_payload[256];
            size_t ack_len = 0;
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_SESSION_UUID, sess_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_NODE_UUID, client->node_uuid, CLIP_UUID_BYTES);
            uint8_t sm = srv->config.speech_mode ? srv->config.speech_mode : (uint8_t)CLIP_SPEECH_MODE_SERVER_MEDIATED;
            clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_SPEECH_ANALYSIS, &sm, 1);

            ClipFrameHeader tx_hdr;
            clip_frame_header_init(&tx_hdr, CLIP_MSG_SESSION_START_ACK, (uint32_t)ack_len, rx_hdr->seq_num + 1, sess_uuid.bytes);

            uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 256];
            size_t frame_len = 0;
            if (clip_frame_encode(&tx_hdr, ack_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
                clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
                srv->total_frames_sent++;
                CLIP_LOGI("SESSION_START_ACK sent to %s:%u", client->ip_str, client->port);
            }
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_SESSION_END) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            CLIP_LOGW("Unauthorized SESSION_END from unauthenticated client %s:%u", client->ip_str, client->port);
            send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        ClipUuid sess_uuid;
        const uint8_t* sess_ptr = NULL;
        uint16_t sess_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_SESSION_UUID, &sess_ptr, &sess_len) == CLIP_OK && sess_len == CLIP_UUID_BYTES) {
            memcpy(sess_uuid.bytes, sess_ptr, CLIP_UUID_BYTES);
        } else if (!clip_uuid_is_zero((const ClipUuid*)rx_hdr->session_uuid)) {
            memcpy(sess_uuid.bytes, rx_hdr->session_uuid, CLIP_UUID_BYTES);
        } else {
            send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
            return;
        }

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipSessionRecord sess_rec;
        ClipError get_s_err = clip_session_get(db, &sess_uuid, &sess_rec);
        if (get_s_err != CLIP_OK) {
            send_session_fail(client->sock, rx_hdr->seq_num + 1, get_s_err);
            return;
        }

        /* Verify requester is authorized endpoint of the session or channel member */
        bool is_auth = false;
        if (clip_uuid_equal((const ClipUuid*)client->node_uuid, &sess_rec.initiator_node_uuid) ||
            (!clip_uuid_is_zero(&sess_rec.peer_node_uuid) && clip_uuid_equal((const ClipUuid*)client->node_uuid, &sess_rec.peer_node_uuid))) {
            is_auth = true;
        } else {
            clip_channel_is_member(db, &sess_rec.channel_uuid, (const ClipUuid*)client->node_uuid, &is_auth);
        }

        if (!is_auth) {
            CLIP_LOGW("SESSION_END rejected: caller not authorized for session");
            send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        if (sess_rec.state != CLIP_SESSION_STATE_ACTIVE) {
            CLIP_LOGW("SESSION_END rejected: session is not active");
            send_session_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NO_SESSION);
            return;
        }

        /* Release any active PTT floor for this session before ending it */
        clip_ptt_manager_release_session(&srv->ptt_mgr, &sess_uuid);
        clip_audio_seq_reset_session(&srv->audio_seq_tracker, &sess_uuid);

        ClipError err = clip_session_end(db, &sess_uuid, (const ClipUuid*)client->node_uuid);
        if (err != CLIP_OK) {
            send_session_fail(client->sock, rx_hdr->seq_num + 1, err);
            return;
        }

        uint8_t ack_payload[64];
        size_t ack_len = 0;
        clip_tlv_write(ack_payload, sizeof(ack_payload), &ack_len, CLIP_TAG_SESSION_UUID, sess_uuid.bytes, CLIP_UUID_BYTES);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_SESSION_END_ACK, (uint32_t)ack_len, rx_hdr->seq_num + 1, sess_uuid.bytes);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 64];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, ack_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("SESSION_END_ACK sent to %s:%u", client->ip_str, client->port);
        }

        /* Notify peer if online and distinct from caller */
        ClipUuid peer_uuid;
        clip_uuid_zero(&peer_uuid);
        if (clip_uuid_equal((const ClipUuid*)client->node_uuid, &sess_rec.initiator_node_uuid)) {
            peer_uuid = sess_rec.peer_node_uuid;
        } else {
            peer_uuid = sess_rec.initiator_node_uuid;
        }

        if (!clip_uuid_is_zero(&peer_uuid)) {
            ClipClientConn* peer_cc = clip_client_table_find_by_node_uuid(&srv->clients, &peer_uuid);
            if (peer_cc) {
                ClipFrameHeader peer_hdr;
                clip_frame_header_init(&peer_hdr, CLIP_MSG_SESSION_END_ACK, (uint32_t)ack_len, 1, sess_uuid.bytes);
                uint8_t peer_buf[CLIP_MIN_FRAME_SIZE + 64];
                size_t peer_len = 0;
                if (clip_frame_encode(&peer_hdr, ack_payload, peer_buf, sizeof(peer_buf), &peer_len) == CLIP_OK) {
                    clip_server_send_client_data(srv, peer_cc->sock, peer_buf, peer_len);
                    srv->total_frames_sent++;
                    CLIP_LOGI("SESSION_END_ACK notification sent to peer %s:%u", peer_cc->ip_str, peer_cc->port);
                }
            }
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_CHANNEL_MEMBERS_REQ) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            CLIP_LOGW("Unauthorized CHANNEL_MEMBERS_REQ from unauthenticated client %s:%u", client->ip_str, client->port);
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        const uint8_t* chan_ptr = NULL;
        uint16_t chan_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CHANNEL_UUID, &chan_ptr, &chan_len) != CLIP_OK || chan_len != CLIP_UUID_BYTES) {
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
            return;
        }

        ClipUuid chan_uuid;
        memcpy(chan_uuid.bytes, chan_ptr, CLIP_UUID_BYTES);

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        bool is_member = false;
        ClipError mem_chk = clip_channel_is_member(db, &chan_uuid, (const ClipUuid*)client->node_uuid, &is_member);
        if (mem_chk != CLIP_OK || !is_member) {
            CLIP_LOGW("CHANNEL_MEMBERS_REQ rejected: client is not a member of the channel");
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        ClipChannelMember* members = NULL;
        size_t member_count = 0;
        ClipError get_err = clip_channel_get_members(db, &chan_uuid, &members, &member_count);
        if (get_err != CLIP_OK) {
            send_channel_fail(client->sock, rx_hdr->seq_num + 1, get_err);
            return;
        }

        uint8_t resp_payload[4096];
        size_t resp_len = 0;
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
        uint16_t m_cnt = (uint16_t)member_count;
        uint8_t cnt_buf[2] = { (uint8_t)((m_cnt >> 8) & 0xFF), (uint8_t)(m_cnt & 0xFF) };
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_MEMBER_COUNT, cnt_buf, 2);

        for (size_t i = 0; i < member_count; i++) {
            ClipClientConn* online_cc = clip_client_table_find_by_node_uuid(&srv->clients, &members[i].node_uuid);
            uint8_t pres_byte = online_cc ? (uint8_t)CLIP_PRESENCE_ONLINE : (uint8_t)CLIP_PRESENCE_OFFLINE;

            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NODE_UUID, members[i].node_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_DISPLAY_NAME, members[i].display_name, (uint16_t)strlen(members[i].display_name));
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_PRESENCE, &pres_byte, 1);
        }
        clip_channel_free_members(members);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_MEMBERS_RESP, (uint32_t)resp_len, rx_hdr->seq_num + 1, NULL);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 4096];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, resp_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("CHANNEL_MEMBERS_RESP sent to %s:%u (members=%zu)", client->ip_str, client->port, member_count);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_CONN_REQUEST) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            CLIP_LOGW("Unauthorized CONN_REQUEST from unauthenticated client %s:%u", client->ip_str, client->port);
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        const uint8_t* chan_ptr = NULL;
        uint16_t chan_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CHANNEL_UUID, &chan_ptr, &chan_len) != CLIP_OK || chan_len != CLIP_UUID_BYTES) {
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
            return;
        }
        ClipUuid chan_uuid;
        memcpy(chan_uuid.bytes, chan_ptr, CLIP_UUID_BYTES);

        const uint8_t* tgt_ptr = NULL;
        uint16_t tgt_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_TARGET_NODE_UUID, &tgt_ptr, &tgt_len) != CLIP_OK) {
            clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_NODE_UUID, &tgt_ptr, &tgt_len);
        }
        if (!tgt_ptr || tgt_len != CLIP_UUID_BYTES) {
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
            return;
        }
        ClipUuid tgt_uuid;
        memcpy(tgt_uuid.bytes, tgt_ptr, CLIP_UUID_BYTES);

        /* 1. Invariant: Cannot request connection to self */
        if (clip_uuid_equal((const ClipUuid*)client->node_uuid, &tgt_uuid)) {
            CLIP_LOGW("CONN_REQUEST rejected: requester cannot connect to self");
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
            return;
        }

        /* 2. Membership validation: both requester and target must belong to channel */
        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        bool req_is_mem = false, tgt_is_mem = false;
        clip_channel_is_member(db, &chan_uuid, (const ClipUuid*)client->node_uuid, &req_is_mem);
        clip_channel_is_member(db, &chan_uuid, &tgt_uuid, &tgt_is_mem);
        if (!req_is_mem) {
            CLIP_LOGW("CONN_REQUEST rejected: requester not in channel");
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }
        if (!tgt_is_mem) {
            CLIP_LOGW("CONN_REQUEST rejected: target not in channel");
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NOT_FOUND);
            return;
        }

        /* 3. Presence validation: target must be currently ONLINE */
        ClipClientConn* tgt_client = clip_client_table_find_by_node_uuid(&srv->clients, &tgt_uuid);
        if (!tgt_client) {
            CLIP_LOGW("CONN_REQUEST rejected: target node is offline");
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NOT_FOUND);
            return;
        }

        /* Look up channel record for name */
        ClipChannelRecord chan_rec;
        clip_channel_get_by_uuid(db, &chan_uuid, &chan_rec);

        /* 4. Create connection record in SQLite (handles duplicate checks) */
        ClipConnectionRecord conn;
        ClipError cr_err = clip_connection_create(db, &chan_uuid, (const ClipUuid*)client->node_uuid, &tgt_uuid, &conn);
        if (cr_err != CLIP_OK) {
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, cr_err);
            return;
        }

        /* 5. Forward INCOMING CONNECTION request to target client */
        uint8_t fwd_payload[512];
        size_t fwd_len = 0;
        clip_tlv_write(fwd_payload, sizeof(fwd_payload), &fwd_len, CLIP_TAG_CONNECTION_UUID, conn.connection_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(fwd_payload, sizeof(fwd_payload), &fwd_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(fwd_payload, sizeof(fwd_payload), &fwd_len, CLIP_TAG_CHANNEL_NAME, chan_rec.name, (uint16_t)strlen(chan_rec.name));
        clip_tlv_write(fwd_payload, sizeof(fwd_payload), &fwd_len, CLIP_TAG_NODE_UUID, client->node_uuid, CLIP_UUID_BYTES);
        clip_tlv_write(fwd_payload, sizeof(fwd_payload), &fwd_len, CLIP_TAG_DISPLAY_NAME, client->display_name, (uint16_t)strlen(client->display_name));

        ClipFrameHeader fwd_hdr;
        clip_frame_header_init(&fwd_hdr, CLIP_MSG_CONN_REQUEST, (uint32_t)fwd_len, 1, NULL);

        uint8_t fwd_frame[CLIP_MIN_FRAME_SIZE + 512];
        size_t fwd_frame_len = 0;
        if (clip_frame_encode(&fwd_hdr, fwd_payload, fwd_frame, sizeof(fwd_frame), &fwd_frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, tgt_client->sock, fwd_frame, fwd_frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("Incoming CONN_REQUEST forwarded to target %s:%u", tgt_client->ip_str, tgt_client->port);
        }

        /* 6. Reply to requester with CONNECTION_RESPONSE (state: REQUESTED) */
        uint8_t ack_pay[256];
        size_t ack_len = 0;
        uint8_t state_byte = (uint8_t)CLIP_CONN_STATE_REQUESTED;
        clip_tlv_write(ack_pay, sizeof(ack_pay), &ack_len, CLIP_TAG_CONNECTION_UUID, conn.connection_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(ack_pay, sizeof(ack_pay), &ack_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(ack_pay, sizeof(ack_pay), &ack_len, CLIP_TAG_TARGET_NODE_UUID, tgt_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(ack_pay, sizeof(ack_pay), &ack_len, CLIP_TAG_CONNECTION_STATE, &state_byte, 1);

        ClipFrameHeader ack_hdr;
        clip_frame_header_init(&ack_hdr, CLIP_MSG_CONNECTION_RESPONSE, (uint32_t)ack_len, rx_hdr->seq_num + 1, NULL);

        uint8_t ack_frame[CLIP_MIN_FRAME_SIZE + 256];
        size_t ack_frame_len = 0;
        if (clip_frame_encode(&ack_hdr, ack_pay, ack_frame, sizeof(ack_frame), &ack_frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, ack_frame, ack_frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("CONNECTION_RESPONSE sent to requester %s:%u (state=REQUESTED)", client->ip_str, client->port);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_CONN_ACCEPT) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        const uint8_t* cu_ptr = NULL;
        uint16_t cu_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CONNECTION_UUID, &cu_ptr, &cu_len) != CLIP_OK || cu_len != CLIP_UUID_BYTES) {
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
            return;
        }
        ClipUuid conn_uuid;
        memcpy(conn_uuid.bytes, cu_ptr, CLIP_UUID_BYTES);

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipConnectionRecord conn;
        ClipError get_c_err = clip_connection_get(db, &conn_uuid, &conn);
        if (get_c_err != CLIP_OK) {
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, get_c_err);
            return;
        }

        /* Target authorization check: caller must be target_node_uuid */
        if (!clip_uuid_equal((const ClipUuid*)client->node_uuid, &conn.target_node_uuid)) {
            CLIP_LOGW("CONN_ACCEPT rejected: caller is not the target of the request");
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        if (conn.state != CLIP_CONN_STATE_REQUESTED) {
            CLIP_LOGW("CONN_ACCEPT rejected: connection is not in REQUESTED state (state=%d)", (int)conn.state);
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
            return;
        }

        /* Update state to ACCEPTED */
        clip_connection_set_state(db, &conn_uuid, CLIP_CONN_STATE_ACCEPTED);

        /* Reply to target */
        uint8_t resp_pay[128];
        size_t resp_len = 0;
        uint8_t st_acc = (uint8_t)CLIP_CONN_STATE_ACCEPTED;
        clip_tlv_write(resp_pay, sizeof(resp_pay), &resp_len, CLIP_TAG_CONNECTION_UUID, conn_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(resp_pay, sizeof(resp_pay), &resp_len, CLIP_TAG_CONNECTION_STATE, &st_acc, 1);

        ClipFrameHeader r_hdr;
        clip_frame_header_init(&r_hdr, CLIP_MSG_CONN_ACCEPT, (uint32_t)resp_len, rx_hdr->seq_num + 1, NULL);
        uint8_t r_frame[CLIP_MIN_FRAME_SIZE + 128];
        size_t r_frame_len = 0;
        if (clip_frame_encode(&r_hdr, resp_pay, r_frame, sizeof(r_frame), &r_frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, r_frame, r_frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("CONN_ACCEPT confirmed to target %s:%u", client->ip_str, client->port);
        }

        /* Notify requester if online */
        ClipClientConn* req_client = clip_client_table_find_by_node_uuid(&srv->clients, &conn.requester_node_uuid);
        if (req_client) {
            ClipFrameHeader n_hdr;
            clip_frame_header_init(&n_hdr, CLIP_MSG_CONN_ACCEPT, (uint32_t)resp_len, 1, NULL);
            uint8_t n_frame[CLIP_MIN_FRAME_SIZE + 128];
            size_t n_frame_len = 0;
            if (clip_frame_encode(&n_hdr, resp_pay, n_frame, sizeof(n_frame), &n_frame_len) == CLIP_OK) {
                clip_server_send_client_data(srv, req_client->sock, n_frame, n_frame_len);
                srv->total_frames_sent++;
                CLIP_LOGI("CONN_ACCEPT notification sent to requester %s:%u", req_client->ip_str, req_client->port);
            }
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_CONN_DECLINE) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        const uint8_t* cu_ptr = NULL;
        uint16_t cu_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CONNECTION_UUID, &cu_ptr, &cu_len) != CLIP_OK || cu_len != CLIP_UUID_BYTES) {
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
            return;
        }
        ClipUuid conn_uuid;
        memcpy(conn_uuid.bytes, cu_ptr, CLIP_UUID_BYTES);

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipConnectionRecord conn;
        ClipError get_c_err = clip_connection_get(db, &conn_uuid, &conn);
        if (get_c_err != CLIP_OK) {
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, get_c_err);
            return;
        }

        if (!clip_uuid_equal((const ClipUuid*)client->node_uuid, &conn.target_node_uuid)) {
            CLIP_LOGW("CONN_DECLINE rejected: caller is not the target of the request");
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        if (conn.state != CLIP_CONN_STATE_REQUESTED) {
            CLIP_LOGW("CONN_DECLINE rejected: connection is not in REQUESTED state (state=%d)", (int)conn.state);
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID);
            return;
        }

        /* Update state to DECLINED */
        clip_connection_set_state(db, &conn_uuid, CLIP_CONN_STATE_DECLINED);

        uint8_t resp_pay[128];
        size_t resp_len = 0;
        uint8_t st_dec = (uint8_t)CLIP_CONN_STATE_DECLINED;
        clip_tlv_write(resp_pay, sizeof(resp_pay), &resp_len, CLIP_TAG_CONNECTION_UUID, conn_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(resp_pay, sizeof(resp_pay), &resp_len, CLIP_TAG_CONNECTION_STATE, &st_dec, 1);

        ClipFrameHeader r_hdr;
        clip_frame_header_init(&r_hdr, CLIP_MSG_CONN_DECLINE, (uint32_t)resp_len, rx_hdr->seq_num + 1, NULL);
        uint8_t r_frame[CLIP_MIN_FRAME_SIZE + 128];
        size_t r_frame_len = 0;
        if (clip_frame_encode(&r_hdr, resp_pay, r_frame, sizeof(r_frame), &r_frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, r_frame, r_frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("CONN_DECLINE confirmed to target %s:%u", client->ip_str, client->port);
        }

        /* Notify requester if online */
        ClipClientConn* req_client = clip_client_table_find_by_node_uuid(&srv->clients, &conn.requester_node_uuid);
        if (req_client) {
            ClipFrameHeader n_hdr;
            clip_frame_header_init(&n_hdr, CLIP_MSG_CONN_DECLINE, (uint32_t)resp_len, 1, NULL);
            uint8_t n_frame[CLIP_MIN_FRAME_SIZE + 128];
            size_t n_frame_len = 0;
            if (clip_frame_encode(&n_hdr, resp_pay, n_frame, sizeof(n_frame), &n_frame_len) == CLIP_OK) {
                clip_server_send_client_data(srv, req_client->sock, n_frame, n_frame_len);
                srv->total_frames_sent++;
                CLIP_LOGI("CONN_DECLINE notification sent to requester %s:%u", req_client->ip_str, req_client->port);
            }
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_CONN_LIST_REQ) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_conn_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED);
            return;
        }

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipConnectionRecord* conns = NULL;
        size_t conn_count = 0;
        clip_connection_list_for_node(db, (const ClipUuid*)client->node_uuid, &conns, &conn_count);

        uint8_t resp_payload[4096];
        size_t resp_len = 0;
        uint16_t c_cnt = (uint16_t)conn_count;
        uint8_t cnt_buf[2] = { (uint8_t)((c_cnt >> 8) & 0xFF), (uint8_t)(c_cnt & 0xFF) };
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_MEMBER_COUNT, cnt_buf, 2);

        for (size_t i = 0; i < conn_count; i++) {
            uint8_t st_b = (uint8_t)conns[i].state;
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CONNECTION_UUID, conns[i].connection_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CHANNEL_UUID, conns[i].channel_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NODE_UUID, conns[i].requester_node_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_TARGET_NODE_UUID, conns[i].target_node_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CONNECTION_STATE, &st_b, 1);
        }
        clip_connection_free_list(conns);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_CONN_LIST_RESP, (uint32_t)resp_len, rx_hdr->seq_num + 1, NULL);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 4096];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, resp_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("CONN_LIST_RESP sent to %s:%u (conns=%zu)", client->ip_str, client->port, conn_count);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_SESSION_LOG_LIST_REQ) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, NULL);
            return;
        }

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipSessionLogEntry* entries = NULL;
        size_t count = 0;
        if (!clip_session_list_for_node(db, (const ClipUuid*)client->node_uuid, &entries, &count)) {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_STORAGE, NULL);
            return;
        }

        uint8_t resp_payload[8192];
        size_t resp_len = 0;
        uint16_t log_cnt = (uint16_t)count;
        uint8_t cnt_buf[2] = { (uint8_t)((log_cnt >> 8) & 0xFF), (uint8_t)(log_cnt & 0xFF) };
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_LOG_COUNT, cnt_buf, 2);

        for (size_t i = 0; i < count; i++) {
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SESSION_UUID, entries[i].session_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CHANNEL_UUID, entries[i].channel_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CONNECTION_UUID, entries[i].connection_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NODE_UUID, entries[i].initiator_node_uuid.bytes, CLIP_UUID_BYTES);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_TARGET_NODE_UUID, entries[i].peer_node_uuid.bytes, CLIP_UUID_BYTES);
            uint8_t st = entries[i].state;
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SESSION_STATE, &st, 1);

            uint8_t ts_buf[8];
            for (int b = 0; b < 8; b++) ts_buf[b] = (uint8_t)((entries[i].created_at >> (56 - b * 8)) & 0xFF);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_TIMESTAMP_MS, ts_buf, 8);

            uint8_t dur_buf[8];
            for (int b = 0; b < 8; b++) dur_buf[b] = (uint8_t)((entries[i].duration_ms >> (56 - b * 8)) & 0xFF);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_DURATION_MS, dur_buf, 8);

            uint16_t n_cnt = (uint16_t)entries[i].note_count;
            uint8_t nc_buf[2] = { (uint8_t)((n_cnt >> 8) & 0xFF), (uint8_t)(n_cnt & 0xFF) };
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NOTE_COUNT, nc_buf, 2);
        }
        clip_session_free_log_list(entries);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_SESSION_LOG_LIST_RESP, (uint32_t)resp_len, rx_hdr->seq_num + 1, NULL);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 8192];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, resp_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("SESSION_LOG_LIST_RESP sent to %s:%u (logs=%zu)", client->ip_str, client->port, count);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_SESSION_LOG_GET_REQ) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, NULL);
            return;
        }

        ClipUuid session_uuid;
        const uint8_t* su_ptr = NULL;
        uint16_t su_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_SESSION_UUID, &su_ptr, &su_len) == CLIP_OK && su_len == CLIP_UUID_BYTES) {
            memcpy(session_uuid.bytes, su_ptr, CLIP_UUID_BYTES);
        } else if (!clip_uuid_is_zero((const ClipUuid*)rx_hdr->session_uuid)) {
            memcpy(session_uuid.bytes, rx_hdr->session_uuid, CLIP_UUID_BYTES);
        } else {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID, NULL);
            return;
        }

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        bool is_auth = false;
        if (!clip_session_is_authorized(db, &session_uuid, (const ClipUuid*)client->node_uuid, &is_auth) || !is_auth) {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, session_uuid.bytes);
            return;
        }

        ClipSessionLogEntry entry;
        if (!clip_session_get_log(db, &session_uuid, &entry)) {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NO_SESSION, session_uuid.bytes);
            return;
        }

        uint8_t resp_payload[512];
        size_t resp_len = 0;
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SESSION_UUID, entry.session_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CHANNEL_UUID, entry.channel_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CONNECTION_UUID, entry.connection_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NODE_UUID, entry.initiator_node_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_TARGET_NODE_UUID, entry.peer_node_uuid.bytes, CLIP_UUID_BYTES);
        uint8_t st = entry.state;
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SESSION_STATE, &st, 1);

        uint8_t ts_buf[8];
        for (int b = 0; b < 8; b++) ts_buf[b] = (uint8_t)((entry.created_at >> (56 - b * 8)) & 0xFF);
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_TIMESTAMP_MS, ts_buf, 8);

        uint8_t dur_buf[8];
        for (int b = 0; b < 8; b++) dur_buf[b] = (uint8_t)((entry.duration_ms >> (56 - b * 8)) & 0xFF);
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_DURATION_MS, dur_buf, 8);

        uint16_t n_cnt = (uint16_t)entry.note_count;
        uint8_t nc_buf[2] = { (uint8_t)((n_cnt >> 8) & 0xFF), (uint8_t)(n_cnt & 0xFF) };
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NOTE_COUNT, nc_buf, 2);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_SESSION_LOG_GET_RESP, (uint32_t)resp_len, rx_hdr->seq_num + 1, session_uuid.bytes);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 512];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, resp_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_NOTE_CREATE) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, NULL);
            return;
        }

        if (client->is_restricted) {
            CLIP_LOGW("Restricted node %s:%u denied NOTE_CREATE", client->ip_str, client->port);
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_RESTRICTED, rx_hdr->session_uuid);
            return;
        }

        ClipUuid session_uuid;
        const uint8_t* su_ptr = NULL;
        uint16_t su_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_SESSION_UUID, &su_ptr, &su_len) == CLIP_OK && su_len == CLIP_UUID_BYTES) {
            memcpy(session_uuid.bytes, su_ptr, CLIP_UUID_BYTES);
        } else if (!clip_uuid_is_zero((const ClipUuid*)rx_hdr->session_uuid)) {
            memcpy(session_uuid.bytes, rx_hdr->session_uuid, CLIP_UUID_BYTES);
        } else {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID, NULL);
            return;
        }

        const uint8_t* txt_ptr = NULL;
        uint16_t txt_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_NOTE_TEXT, &txt_ptr, &txt_len) != CLIP_OK || txt_len == 0 || txt_len > CLIP_NOTE_TEXT_MAX_LEN) {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID, session_uuid.bytes);
            return;
        }

        char note_str[CLIP_NOTE_TEXT_MAX_LEN + 1];
        memcpy(note_str, txt_ptr, txt_len);
        note_str[txt_len] = '\0';

        ClipNoteType n_type = CLIP_NOTE_TYPE_MANUAL;
        const uint8_t* type_ptr = NULL;
        uint16_t type_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_NOTE_TYPE, &type_ptr, &type_len) == CLIP_OK && type_len == 1) {
            n_type = (ClipNoteType)(*type_ptr);
        }

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        bool is_auth = false;
        if (!clip_session_is_authorized(db, &session_uuid, (const ClipUuid*)client->node_uuid, &is_auth) || !is_auth) {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, session_uuid.bytes);
            return;
        }

        uint32_t note_id = 0;
        if (!clip_notes_create(db, &session_uuid, (const ClipUuid*)client->node_uuid, n_type, note_str, &note_id)) {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_STORAGE, session_uuid.bytes);
            return;
        }

        uint8_t resp_payload[128];
        size_t resp_len = 0;
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SESSION_UUID, session_uuid.bytes, CLIP_UUID_BYTES);
        uint8_t nid_buf[4] = {
            (uint8_t)((note_id >> 24) & 0xFF),
            (uint8_t)((note_id >> 16) & 0xFF),
            (uint8_t)((note_id >> 8) & 0xFF),
            (uint8_t)(note_id & 0xFF)
        };
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NOTE_ID, nid_buf, 4);
        uint8_t tb = (uint8_t)n_type;
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NOTE_TYPE, &tb, 1);

        uint64_t now_ms = current_time_ms();
        uint8_t ts_buf[8];
        for (int b = 0; b < 8; b++) ts_buf[b] = (uint8_t)((now_ms >> (56 - b * 8)) & 0xFF);
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_TIMESTAMP_MS, ts_buf, 8);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_NOTE_CREATE_OK, (uint32_t)resp_len, rx_hdr->seq_num + 1, session_uuid.bytes);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 128];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, resp_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("NOTE_CREATE_OK sent to %s:%u (note_id=%u)", client->ip_str, client->port, note_id);
        }

        /* Security Keyword Analysis on Note text (Phase 15) */
        if (srv->security_analyzer) {
            char sess_str[64] = {0};
            char node_str[64] = {0};
            char chan_str[64] = {0};
            clip_uuid_to_string(&session_uuid, sess_str, sizeof(sess_str));
            clip_uuid_to_string((const ClipUuid*)client->node_uuid, node_str, sizeof(node_str));
            ClipSessionRecord srec;
            if (clip_session_get(db, &session_uuid, &srec) == CLIP_OK) {
                clip_uuid_to_string(&srec.channel_uuid, chan_str, sizeof(chan_str));
            }
            security_analyzer_process(srv->security_analyzer,
                                      note_str,
                                      node_str,
                                      chan_str,
                                      session_uuid.bytes,
                                      now_ms);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_NOTE_LIST_REQ) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, NULL);
            return;
        }

        ClipUuid session_uuid;
        const uint8_t* su_ptr = NULL;
        uint16_t su_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_SESSION_UUID, &su_ptr, &su_len) == CLIP_OK && su_len == CLIP_UUID_BYTES) {
            memcpy(session_uuid.bytes, su_ptr, CLIP_UUID_BYTES);
        } else if (!clip_uuid_is_zero((const ClipUuid*)rx_hdr->session_uuid)) {
            memcpy(session_uuid.bytes, rx_hdr->session_uuid, CLIP_UUID_BYTES);
        } else {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID, NULL);
            return;
        }

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        bool is_auth = false;
        if (!clip_session_is_authorized(db, &session_uuid, (const ClipUuid*)client->node_uuid, &is_auth) || !is_auth) {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, session_uuid.bytes);
            return;
        }

        const uint8_t* q_ptr = NULL;
        uint16_t q_len = 0;
        char query_str[256] = {0};
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_NOTE_TEXT, &q_ptr, &q_len) == CLIP_OK && q_len > 0) {
            size_t cpy = (q_len < sizeof(query_str) - 1) ? q_len : (sizeof(query_str) - 1);
            memcpy(query_str, q_ptr, cpy);
            query_str[cpy] = '\0';
        }

        ClipSessionNoteEntry* notes = NULL;
        size_t count = 0;
        bool list_ok = false;
        if (query_str[0] != '\0') {
            list_ok = clip_notes_search(db, &session_uuid, query_str, &notes, &count);
        } else {
            list_ok = clip_notes_list_for_session(db, &session_uuid, &notes, &count);
        }

        if (!list_ok) {
            send_note_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_STORAGE, session_uuid.bytes);
            return;
        }

        uint8_t resp_payload[16384];
        size_t resp_len = 0;
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SESSION_UUID, session_uuid.bytes, CLIP_UUID_BYTES);

        uint16_t nc = (uint16_t)count;
        uint8_t nc_buf[2] = { (uint8_t)((nc >> 8) & 0xFF), (uint8_t)(nc & 0xFF) };
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NOTE_COUNT, nc_buf, 2);

        for (size_t i = 0; i < count; i++) {
            uint8_t nid_buf[4] = {
                (uint8_t)((notes[i].note_id >> 24) & 0xFF),
                (uint8_t)((notes[i].note_id >> 16) & 0xFF),
                (uint8_t)((notes[i].note_id >> 8) & 0xFF),
                (uint8_t)(notes[i].note_id & 0xFF)
            };
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NOTE_ID, nid_buf, 4);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NOTE_AUTHOR_UUID, notes[i].author_node_uuid.bytes, CLIP_UUID_BYTES);
            uint8_t tb = (uint8_t)notes[i].note_type;
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NOTE_TYPE, &tb, 1);

            uint8_t ts_buf[8];
            for (int b = 0; b < 8; b++) ts_buf[b] = (uint8_t)((notes[i].created_at >> (56 - b * 8)) & 0xFF);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_TIMESTAMP_MS, ts_buf, 8);

            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NOTE_TEXT, notes[i].note_text, (uint16_t)strlen(notes[i].note_text));
        }
        clip_notes_free_list(notes);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_NOTE_LIST_RESP, (uint32_t)resp_len, rx_hdr->seq_num + 1, session_uuid.bytes);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 16384];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, resp_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("NOTE_LIST_RESP sent to %s:%u (notes=%zu)", client->ip_str, client->port, count);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_SECURITY_TRANSCRIPT) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, NULL);
            return;
        }

        ClipUuid session_uuid;
        const uint8_t* su_ptr = NULL;
        uint16_t su_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_SESSION_UUID, &su_ptr, &su_len) == CLIP_OK && su_len == CLIP_UUID_BYTES) {
            memcpy(session_uuid.bytes, su_ptr, CLIP_UUID_BYTES);
        } else if (!clip_uuid_is_zero((const ClipUuid*)rx_hdr->session_uuid)) {
            memcpy(session_uuid.bytes, rx_hdr->session_uuid, CLIP_UUID_BYTES);
        } else {
            send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID, NULL);
            return;
        }

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        bool is_auth = false;
        if (!clip_session_is_authorized(db, &session_uuid, (const ClipUuid*)client->node_uuid, &is_auth) || !is_auth) {
            send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, session_uuid.bytes);
            return;
        }

        ClipSessionRecord srec;
        if (clip_session_get(db, &session_uuid, &srec) != CLIP_OK || srec.state != CLIP_SESSION_STATE_ACTIVE) {
            send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NO_SESSION, session_uuid.bytes);
            return;
        }

        /* Extract speaker node UUID, timestamp, and transcript text */
        ClipUuid speaker_uuid = *(const ClipUuid*)client->node_uuid;
        const uint8_t* spk_ptr = NULL;
        uint16_t spk_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_NODE_UUID, &spk_ptr, &spk_len) == CLIP_OK && spk_len == CLIP_UUID_BYTES) {
            memcpy(speaker_uuid.bytes, spk_ptr, CLIP_UUID_BYTES);
        }

        uint64_t ts_ms = current_time_ms();
        const uint8_t* ts_ptr = NULL;
        uint16_t ts_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_TIMESTAMP_MS, &ts_ptr, &ts_len) == CLIP_OK && ts_len == 8) {
            ts_ms = 0;
            for (int b = 0; b < 8; b++) ts_ms = (ts_ms << 8) | ts_ptr[b];
        }

        const uint8_t* txt_ptr = NULL;
        uint16_t txt_len = 0;
        char text_str[512] = {0};
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_TRANSCRIPT_TEXT, &txt_ptr, &txt_len) == CLIP_OK && txt_len > 0) {
            size_t cpy = (txt_len < sizeof(text_str) - 1) ? txt_len : (sizeof(text_str) - 1);
            memcpy(text_str, txt_ptr, cpy);
            text_str[cpy] = '\0';
        }

        if (text_str[0] != '\0' && srv->security_analyzer) {
            char sess_str[64] = {0};
            char node_str[64] = {0};
            char chan_str[64] = {0};
            clip_uuid_to_string(&session_uuid, sess_str, sizeof(sess_str));
            clip_uuid_to_string(&speaker_uuid, node_str, sizeof(node_str));
            clip_uuid_to_string(&srec.channel_uuid, chan_str, sizeof(chan_str));

            security_analyzer_process(srv->security_analyzer,
                                      text_str,
                                      node_str,
                                      chan_str,
                                      session_uuid.bytes,
                                      ts_ms);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_SECURITY_EVENT_LIST_REQ) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, NULL);
            return;
        }

        ClipUuid session_uuid;
        memset(&session_uuid, 0, sizeof(session_uuid));
        bool has_session = false;
        const uint8_t* su_ptr = NULL;
        uint16_t su_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_SESSION_UUID, &su_ptr, &su_len) == CLIP_OK && su_len == CLIP_UUID_BYTES) {
            memcpy(session_uuid.bytes, su_ptr, CLIP_UUID_BYTES);
            has_session = true;
        } else if (!clip_uuid_is_zero((const ClipUuid*)rx_hdr->session_uuid)) {
            memcpy(session_uuid.bytes, rx_hdr->session_uuid, CLIP_UUID_BYTES);
            has_session = true;
        }

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipSecurityEvent* events = NULL;
        size_t count = 0;

        if (has_session) {
            bool is_auth = false;
            if (!clip_session_is_authorized(db, &session_uuid, (const ClipUuid*)client->node_uuid, &is_auth) || !is_auth) {
                send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, session_uuid.bytes);
                return;
            }
            if (clip_security_db_list_for_session(db, session_uuid.bytes, &events, &count) != CLIP_OK) {
                send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_STORAGE, session_uuid.bytes);
                return;
            }
        } else {
            if (clip_security_db_list_for_node(db, client->node_uuid, &events, &count) != CLIP_OK) {
                send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_STORAGE, NULL);
                return;
            }
        }

        uint8_t resp_payload[16384];
        size_t resp_len = 0;
        if (has_session) {
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SESSION_UUID, session_uuid.bytes, CLIP_UUID_BYTES);
        }

        uint16_t ec = (uint16_t)count;
        uint8_t ec_buf[2] = { (uint8_t)((ec >> 8) & 0xFF), (uint8_t)(ec & 0xFF) };
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_EVENT_COUNT, ec_buf, 2);

        for (size_t i = 0; i < count; i++) {
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_EVENT_UUID, events[i].event_uuid, CLIP_UUID_BYTES);

            uint8_t eid_buf[4] = {
                (uint8_t)((events[i].event_id >> 24) & 0xFF),
                (uint8_t)((events[i].event_id >> 16) & 0xFF),
                (uint8_t)((events[i].event_id >> 8) & 0xFF),
                (uint8_t)(events[i].event_id & 0xFF)
            };
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_EVENT_ID, eid_buf, 4);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SESSION_UUID, events[i].session_uuid, CLIP_UUID_BYTES);

            ClipUuid chan_u, node_u;
            if (clip_uuid_from_string(&chan_u, events[i].channel_uuid_str) == 0) {
                clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CHANNEL_UUID, chan_u.bytes, CLIP_UUID_BYTES);
            }
            if (clip_uuid_from_string(&node_u, events[i].node_uuid_str) == 0) {
                clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NODE_UUID, node_u.bytes, CLIP_UUID_BYTES);
            }

            uint8_t ts_buf[8];
            for (int b = 0; b < 8; b++) ts_buf[b] = (uint8_t)((events[i].timestamp_ms >> (56 - b * 8)) & 0xFF);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_TIMESTAMP_MS, ts_buf, 8);

            uint8_t cat_b = (uint8_t)events[i].category;
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CATEGORY, &cat_b, 1);

            uint8_t sev_b = (uint8_t)events[i].severity;
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SEVERITY, &sev_b, 1);

            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_MATCHED_RULE, events[i].matched_rule, (uint16_t)strlen(events[i].matched_rule));
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_MATCHED_TEXT, events[i].matched_term, (uint16_t)strlen(events[i].matched_term));
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CONTEXT_TEXT, events[i].context_text, (uint16_t)strlen(events[i].context_text));

            uint8_t st_b = (uint8_t)events[i].status;
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_EVENT_STATUS, &st_b, 1);
        }
        clip_security_db_free_event_list(events, count);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_SECURITY_EVENT_LIST_RESP, (uint32_t)resp_len, rx_hdr->seq_num + 1, has_session ? session_uuid.bytes : NULL);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 16384];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, resp_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("SECURITY_EVENT_LIST_RESP sent to %s:%u (events=%zu)", client->ip_str, client->port, count);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_SECURITY_EVENT_GET_REQ) {
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, NULL);
            return;
        }

        uint32_t req_id = 0;
        const uint8_t* id_ptr = NULL;
        uint16_t id_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_EVENT_ID, &id_ptr, &id_len) == CLIP_OK && id_len == 4) {
            req_id = ((uint32_t)id_ptr[0] << 24) | ((uint32_t)id_ptr[1] << 16) | ((uint32_t)id_ptr[2] << 8) | (uint32_t)id_ptr[3];
        }

        const uint8_t* req_uuid = NULL;
        const uint8_t* u_ptr = NULL;
        uint16_t u_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_EVENT_UUID, &u_ptr, &u_len) == CLIP_OK && u_len == CLIP_UUID_BYTES) {
            req_uuid = u_ptr;
        }

        if (req_id == 0 && !req_uuid) {
            send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID, NULL);
            return;
        }

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipSecurityEvent ev;
        if (clip_security_db_get_event(db, req_id, req_uuid, &ev) != CLIP_OK) {
            send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NOT_FOUND, NULL);
            return;
        }

        /* Check authorization: must be speaker node or authorized session participant */
        ClipUuid ev_node;
        bool is_speaker = (clip_uuid_from_string(&ev_node, ev.node_uuid_str) == 0 &&
                           clip_uuid_equal((const ClipUuid*)client->node_uuid, &ev_node));
        ClipUuid ev_sess;
        memcpy(ev_sess.bytes, ev.session_uuid, CLIP_UUID_BYTES);
        bool is_auth = false;
        clip_session_is_authorized(db, &ev_sess, (const ClipUuid*)client->node_uuid, &is_auth);

        if (!is_speaker && !is_auth) {
            send_security_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, ev.session_uuid);
            return;
        }

        uint8_t resp_payload[1024];
        size_t resp_len = 0;
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_EVENT_UUID, ev.event_uuid, CLIP_UUID_BYTES);

        uint8_t eid_buf[4] = {
            (uint8_t)((ev.event_id >> 24) & 0xFF),
            (uint8_t)((ev.event_id >> 16) & 0xFF),
            (uint8_t)((ev.event_id >> 8) & 0xFF),
            (uint8_t)(ev.event_id & 0xFF)
        };
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_EVENT_ID, eid_buf, 4);
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SESSION_UUID, ev.session_uuid, CLIP_UUID_BYTES);

        ClipUuid chan_u, node_u;
        if (clip_uuid_from_string(&chan_u, ev.channel_uuid_str) == 0) {
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CHANNEL_UUID, chan_u.bytes, CLIP_UUID_BYTES);
        }
        if (clip_uuid_from_string(&node_u, ev.node_uuid_str) == 0) {
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NODE_UUID, node_u.bytes, CLIP_UUID_BYTES);
        }

        uint8_t ts_buf[8];
        for (int b = 0; b < 8; b++) ts_buf[b] = (uint8_t)((ev.timestamp_ms >> (56 - b * 8)) & 0xFF);
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_TIMESTAMP_MS, ts_buf, 8);

        uint8_t cat_b = (uint8_t)ev.category;
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CATEGORY, &cat_b, 1);

        uint8_t sev_b = (uint8_t)ev.severity;
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SEVERITY, &sev_b, 1);

        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_MATCHED_RULE, ev.matched_rule, (uint16_t)strlen(ev.matched_rule));
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_MATCHED_TEXT, ev.matched_term, (uint16_t)strlen(ev.matched_term));
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CONTEXT_TEXT, ev.context_text, (uint16_t)strlen(ev.context_text));

        uint8_t st_b = (uint8_t)ev.status;
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_EVENT_STATUS, &st_b, 1);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_SECURITY_EVENT_GET_RESP, (uint32_t)resp_len, rx_hdr->seq_num + 1, ev.session_uuid);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 1024];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, resp_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
            CLIP_LOGI("SECURITY_EVENT_GET_RESP sent to %s:%u (event_id=%u)", client->ip_str, client->port, ev.event_id);
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_ADMIN_AUTH_REQ) {
        /*
         * Phase 17 Stage 4: Server-Side Rate Limiting Check
         */
        uint64_t now_ms = srv->mock_now_ms ? srv->mock_now_ms : current_time_ms();
        if (clip_rate_limiter_check(&srv->rate_limiter, client->ip_str, now_ms) != CLIP_OK) {
            CLIP_LOGW("ADMIN_AUTH rejected for IP %s: rate limit active / saturated", client->ip_str);
            send_admin_auth_resp(srv, client->sock, rx_hdr->seq_num + 1, CLIP_ERR_AUTH, 0, NULL, NULL);
            return;
        }

        /*
         * Phase 16: Authenticated Administrator Login
         * Extracts username and password/credential
         * Uses PBKDF2-HMAC-SHA256 verifier with constant-time comparison
         * Authoritatively assigns admin_role from SQLite
         */
        const uint8_t* u_ptr = NULL;
        uint16_t u_len = 0;
        const uint8_t* p_ptr = NULL;
        uint16_t p_len = 0;

        clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_ADMIN_USERNAME, &u_ptr, &u_len);
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_TEXT, &p_ptr, &p_len) != CLIP_OK) {
            clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CREDENTIAL, &p_ptr, &p_len);
        }

        if (!u_ptr || u_len == 0 || !p_ptr || p_len == 0) {
            CLIP_LOGW("Malformed ADMIN_AUTH_REQ from %s:%u", client->ip_str, client->port);
            clip_rate_limiter_record_failure(&srv->rate_limiter, client->ip_str, now_ms);
            send_admin_auth_resp(srv, client->sock, rx_hdr->seq_num + 1, CLIP_ERR_PROTO, 0, NULL, NULL);
            return;
        }

        char username[CLIP_ADMIN_USERNAME_MAX_LEN] = {0};
        size_t cp_u = (u_len < sizeof(username) - 1) ? u_len : sizeof(username) - 1;
        memcpy(username, u_ptr, cp_u);

        char password[128] = {0};
        size_t cp_p = (p_len < sizeof(password) - 1) ? p_len : sizeof(password) - 1;
        memcpy(password, p_ptr, cp_p);

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipAdminUser user;
        ClipError g_err = clip_admin_db_get_admin(db, username, &user);

        bool auth_ok = false;
        if (g_err == CLIP_OK) {
            auth_ok = clip_admin_verify_password(password, user.salt, user.iterations, user.verifier);
        }
        OPENSSL_cleanse(password, sizeof(password));

        if (!auth_ok) {
            CLIP_LOGW("Admin authentication FAILED for '%s' from %s:%u", username, client->ip_str, client->port);
            clip_rate_limiter_record_failure(&srv->rate_limiter, client->ip_str, now_ms);
            ClipAdminAuditRecord audit;
            memset(&audit, 0, sizeof(audit));
            if (g_err == CLIP_OK) {
                memcpy(audit.admin_uuid, user.admin_uuid, CLIP_UUID_BYTES);
            }
            audit.action_type = 0;
            snprintf(audit.reason, sizeof(audit.reason), "Admin auth failed for username: %s", username);
            audit.status = CLIP_AUDIT_STATUS_DENIED;
            audit.error_code = CLIP_ERR_AUTH;
            clip_admin_db_add_audit(db, &audit, NULL);

            send_admin_auth_resp(srv, client->sock, rx_hdr->seq_num + 1, CLIP_ERR_AUTH, 0, NULL, NULL);
            return;
        }

        clip_rate_limiter_record_success(&srv->rate_limiter, client->ip_str, now_ms);

        client->is_admin_authenticated = true;
        client->admin_role = user.role;
        memcpy(client->admin_uuid, user.admin_uuid, CLIP_UUID_BYTES);
        strncpy(client->admin_username, user.username, sizeof(client->admin_username) - 1);

        ClipAdminAuditRecord audit;
        memset(&audit, 0, sizeof(audit));
        memcpy(audit.admin_uuid, user.admin_uuid, CLIP_UUID_BYTES);
        audit.action_type = 0;
        snprintf(audit.reason, sizeof(audit.reason), "Admin login successful for %s (%s)",
                 user.username, clip_admin_role_name(user.role));
        audit.status = CLIP_AUDIT_STATUS_SUCCESS;
        audit.error_code = CLIP_OK;
        clip_admin_db_add_audit(db, &audit, NULL);

        CLIP_LOGI("Admin '%s' authenticated with role %s", user.username, clip_admin_role_name(user.role));
        send_admin_auth_resp(srv, client->sock, rx_hdr->seq_num + 1, CLIP_OK, user.role, user.admin_uuid, user.username);
    } else if (rx_hdr->msg_type == CLIP_MSG_ADMIN_ACTION) {
        /*
         * Phase 16: Explicit Administrative Action Execution
         * Enforces role authorization, mandatory reason, referential integrity,
         * state machine invariants, and append-only audit trail logging.
         */
        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);

        if (!client->is_admin_authenticated) {
            CLIP_LOGW("Unauthenticated client %s:%u attempted ADMIN_ACTION", client->ip_str, client->port);
            send_admin_fail(srv, client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, "Unauthenticated administrator connection");
            return;
        }

        const uint8_t* act_ptr = NULL;
        uint16_t act_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_ADMIN_ACTION, &act_ptr, &act_len) != CLIP_OK || act_len < 1) {
            send_admin_fail(srv, client->sock, rx_hdr->seq_num + 1, CLIP_ERR_PROTO, "Missing action type TLV");
            return;
        }
        ClipAdminActionType action = (ClipAdminActionType)act_ptr[0];

        const uint8_t* r_ptr = NULL;
        uint16_t r_len = 0;
        clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_ADMIN_REASON, &r_ptr, &r_len);
        if (!r_ptr || r_len == 0) {
            clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_TEXT, &r_ptr, &r_len);
        }
        if (!r_ptr || r_len == 0) {
            send_admin_fail(srv, client->sock, rx_hdr->seq_num + 1, CLIP_ERR_INVALID, "Reason string is required for audit trail");
            return;
        }
        char reason[CLIP_ADMIN_REASON_MAX_LEN] = {0};
        size_t cp_r = (r_len < sizeof(reason) - 1) ? r_len : sizeof(reason) - 1;
        memcpy(reason, r_ptr, cp_r);

        /* Optional target and related TLVs */
        const uint8_t* tgt_ptr = NULL;
        uint16_t tgt_len = 0;
        bool has_target = (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_ADMIN_TARGET_UUID, &tgt_ptr, &tgt_len) == CLIP_OK && tgt_len == CLIP_UUID_BYTES);
        if (!has_target) {
            has_target = (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_NODE_UUID, &tgt_ptr, &tgt_len) == CLIP_OK && tgt_len == CLIP_UUID_BYTES);
        }
        uint8_t target_uuid[CLIP_UUID_BYTES] = {0};
        if (has_target) memcpy(target_uuid, tgt_ptr, CLIP_UUID_BYTES);

        const uint8_t* eid_ptr = NULL;
        uint16_t eid_len = 0;
        uint32_t related_event_id = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_RELATED_EVENT_ID, &eid_ptr, &eid_len) == CLIP_OK && eid_len == 4) {
            related_event_id = ((uint32_t)eid_ptr[0] << 24) | ((uint32_t)eid_ptr[1] << 16) | ((uint32_t)eid_ptr[2] << 8) | (uint32_t)eid_ptr[3];
        } else if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_EVENT_ID, &eid_ptr, &eid_len) == CLIP_OK && eid_len == 4) {
            related_event_id = ((uint32_t)eid_ptr[0] << 24) | ((uint32_t)eid_ptr[1] << 16) | ((uint32_t)eid_ptr[2] << 8) | (uint32_t)eid_ptr[3];
        }

        const uint8_t* su_ptr = NULL;
        uint16_t su_len = 0;
        bool has_session = (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_RELATED_SESSION_UUID, &su_ptr, &su_len) == CLIP_OK && su_len == CLIP_UUID_BYTES);
        if (!has_session) {
            has_session = (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_SESSION_UUID, &su_ptr, &su_len) == CLIP_OK && su_len == CLIP_UUID_BYTES);
        }
        uint8_t session_uuid[CLIP_UUID_BYTES] = {0};
        if (has_session) memcpy(session_uuid, su_ptr, CLIP_UUID_BYTES);

        const uint8_t* chu_ptr = NULL;
        uint16_t chu_len = 0;
        bool has_channel = (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_RELATED_CHANNEL_UUID, &chu_ptr, &chu_len) == CLIP_OK && chu_len == CLIP_UUID_BYTES);
        if (!has_channel) {
            has_channel = (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_CHANNEL_UUID, &chu_ptr, &chu_len) == CLIP_OK && chu_len == CLIP_UUID_BYTES);
        }
        uint8_t channel_uuid[CLIP_UUID_BYTES] = {0};
        if (has_channel) memcpy(channel_uuid, chu_ptr, CLIP_UUID_BYTES);

        /* Setup base audit record */
        ClipAdminAuditRecord audit;
        memset(&audit, 0, sizeof(audit));
        memcpy(audit.admin_uuid, client->admin_uuid, CLIP_UUID_BYTES);
        audit.action_type = action;
        if (has_target) {
            memcpy(audit.target_uuid, target_uuid, CLIP_UUID_BYTES);
            audit.has_target_uuid = true;
        }
        strncpy(audit.reason, reason, sizeof(audit.reason) - 1);
        audit.related_event_id = related_event_id;
        if (has_session) {
            memcpy(audit.related_session_uuid, session_uuid, CLIP_UUID_BYTES);
            audit.has_related_session = true;
        }
        if (has_channel) {
            memcpy(audit.related_channel_uuid, channel_uuid, CLIP_UUID_BYTES);
            audit.has_related_channel = true;
        }

        /* 1. Permission check */
        if (!clip_admin_can_perform(client->admin_role, action)) {
            CLIP_LOGW("Admin '%s' (%s) denied action %s",
                      client->admin_username, clip_admin_role_name(client->admin_role), clip_admin_action_name(action));
            audit.status = CLIP_AUDIT_STATUS_DENIED;
            audit.error_code = CLIP_ERR_PERMISSION_DENIED;
            clip_admin_db_add_audit(db, &audit, NULL);
            send_admin_fail(srv, client->sock, rx_hdr->seq_num + 1, CLIP_ERR_PERMISSION_DENIED, "Administrative permission denied");
            return;
        }

        /* 2. Referential integrity validation */
        if (related_event_id > 0) {
            bool ev_exists = false;
            clip_admin_db_event_exists(db, related_event_id, &ev_exists);
            if (!ev_exists) {
                audit.status = CLIP_AUDIT_STATUS_FAILED;
                audit.error_code = CLIP_ERR_NOT_FOUND;
                clip_admin_db_add_audit(db, &audit, NULL);
                send_admin_fail(srv, client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NOT_FOUND, "Referenced security event does not exist");
                return;
            }
        }
        if (has_session) {
            bool s_exists = false;
            clip_admin_db_session_exists(db, session_uuid, &s_exists);
            if (!s_exists) {
                audit.status = CLIP_AUDIT_STATUS_FAILED;
                audit.error_code = CLIP_ERR_NOT_FOUND;
                clip_admin_db_add_audit(db, &audit, NULL);
                send_admin_fail(srv, client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NOT_FOUND, "Referenced session does not exist");
                return;
            }
        }
        if (has_channel) {
            bool c_exists = false;
            clip_admin_db_channel_exists(db, channel_uuid, &c_exists);
            if (!c_exists) {
                audit.status = CLIP_AUDIT_STATUS_FAILED;
                audit.error_code = CLIP_ERR_NOT_FOUND;
                clip_admin_db_add_audit(db, &audit, NULL);
                send_admin_fail(srv, client->sock, rx_hdr->seq_num + 1, CLIP_ERR_NOT_FOUND, "Referenced channel does not exist");
                return;
            }
        }

        /* 3. Execute action */
        ClipError act_err = CLIP_OK;
        const char* err_desc = NULL;

        switch (action) {
        case CLIP_ADMIN_DISCONNECT_NODE: {
            if (!has_target) {
                act_err = CLIP_ERR_INVALID;
                err_desc = "Target node UUID required for disconnect";
                break;
            }
            ClipClientConn* tgt = clip_client_table_find_by_node_uuid(&srv->clients, (const ClipUuid*)target_uuid);
            if (tgt) {
                clip_net_close_socket(&tgt->sock);
                tgt->active = false;
            }
            break;
        }

        case CLIP_ADMIN_RESTRICT_NODE: {
            if (!has_target) {
                act_err = CLIP_ERR_INVALID;
                err_desc = "Target node UUID required for restriction";
                break;
            }
            ClipNodeSanction sanc;
            if (clip_admin_db_get_sanction(db, target_uuid, &sanc) == CLIP_OK) {
                if (sanc.status == CLIP_SANCTION_RESTRICTED) {
                    act_err = CLIP_ERR_EXISTS;
                    err_desc = "Node is already restricted";
                    break;
                }
                if (sanc.status == CLIP_SANCTION_BANNED) {
                    act_err = CLIP_ERR_INVALID;
                    err_desc = "Cannot restrict a banned node";
                    break;
                }
            }
            memset(&sanc, 0, sizeof(sanc));
            memcpy(sanc.node_uuid, target_uuid, CLIP_UUID_BYTES);
            sanc.status = CLIP_SANCTION_RESTRICTED;
            strncpy(sanc.reason, reason, sizeof(sanc.reason) - 1);
            memcpy(sanc.admin_uuid, client->admin_uuid, CLIP_UUID_BYTES);
            act_err = clip_admin_db_set_sanction(db, &sanc);
            if (act_err == CLIP_OK) {
                ClipClientConn* tgt = clip_client_table_find_by_node_uuid(&srv->clients, (const ClipUuid*)target_uuid);
                if (tgt) tgt->is_restricted = true;
            }
            break;
        }

        case CLIP_ADMIN_UNRESTRICT_NODE: {
            if (!has_target) {
                act_err = CLIP_ERR_INVALID;
                err_desc = "Target node UUID required for unrestrict";
                break;
            }
            ClipNodeSanction sanc;
            ClipError g_s = clip_admin_db_get_sanction(db, target_uuid, &sanc);
            if (g_s != CLIP_OK || sanc.status != CLIP_SANCTION_RESTRICTED) {
                if (g_s == CLIP_OK && sanc.status == CLIP_SANCTION_BANNED) {
                    act_err = CLIP_ERR_INVALID;
                    err_desc = "Cannot unrestrict a banned node; must unban";
                } else {
                    act_err = CLIP_ERR_INVALID;
                    err_desc = "Node is not restricted";
                }
                break;
            }
            act_err = clip_admin_db_remove_sanction(db, target_uuid);
            if (act_err == CLIP_OK) {
                ClipClientConn* tgt = clip_client_table_find_by_node_uuid(&srv->clients, (const ClipUuid*)target_uuid);
                if (tgt) tgt->is_restricted = false;
            }
            break;
        }

        case CLIP_ADMIN_BAN_NODE: {
            if (!has_target) {
                act_err = CLIP_ERR_INVALID;
                err_desc = "Target node UUID required for ban";
                break;
            }
            ClipNodeSanction sanc;
            if (clip_admin_db_get_sanction(db, target_uuid, &sanc) == CLIP_OK && sanc.status == CLIP_SANCTION_BANNED) {
                act_err = CLIP_ERR_EXISTS;
                err_desc = "Node is already banned";
                break;
            }
            memset(&sanc, 0, sizeof(sanc));
            memcpy(sanc.node_uuid, target_uuid, CLIP_UUID_BYTES);
            sanc.status = CLIP_SANCTION_BANNED;
            strncpy(sanc.reason, reason, sizeof(sanc.reason) - 1);
            memcpy(sanc.admin_uuid, client->admin_uuid, CLIP_UUID_BYTES);
            act_err = clip_admin_db_set_sanction(db, &sanc);
            if (act_err == CLIP_OK) {
                ClipClientConn* tgt = clip_client_table_find_by_node_uuid(&srv->clients, (const ClipUuid*)target_uuid);
                if (tgt) {
                    clip_net_close_socket(&tgt->sock);
                    tgt->active = false;
                }
            }
            break;
        }

        case CLIP_ADMIN_UNBAN_NODE: {
            if (!has_target) {
                act_err = CLIP_ERR_INVALID;
                err_desc = "Target node UUID required for unban";
                break;
            }
            ClipNodeSanction sanc;
            ClipError g_s = clip_admin_db_get_sanction(db, target_uuid, &sanc);
            if (g_s != CLIP_OK || sanc.status != CLIP_SANCTION_BANNED) {
                act_err = CLIP_ERR_INVALID;
                err_desc = "Node is not banned";
                break;
            }
            act_err = clip_admin_db_remove_sanction(db, target_uuid);
            break;
        }

        case CLIP_ADMIN_LOCK_CHANNEL: {
            if (!has_target && !has_channel) {
                act_err = CLIP_ERR_INVALID;
                err_desc = "Target channel UUID required for lock";
                break;
            }
            const uint8_t* ch_id = has_channel ? channel_uuid : target_uuid;
            act_err = clip_admin_db_lock_channel(db, ch_id, true);
            if (act_err != CLIP_OK) err_desc = "Channel not found";
            break;
        }

        case CLIP_ADMIN_UNLOCK_CHANNEL: {
            if (!has_target && !has_channel) {
                act_err = CLIP_ERR_INVALID;
                err_desc = "Target channel UUID required for unlock";
                break;
            }
            const uint8_t* ch_id = has_channel ? channel_uuid : target_uuid;
            act_err = clip_admin_db_lock_channel(db, ch_id, false);
            if (act_err != CLIP_OK) err_desc = "Channel not found";
            break;
        }

        case CLIP_ADMIN_REVIEW_EVENT: {
            if (related_event_id == 0) {
                act_err = CLIP_ERR_INVALID;
                err_desc = "Related event ID required for REVIEW_EVENT";
                break;
            }
            act_err = clip_admin_db_update_event_status(db, related_event_id, CLIP_EVENT_STATUS_REVIEWED);
            if (act_err == CLIP_ERR_EXISTS) err_desc = "Event is already marked REVIEWED";
            else if (act_err == CLIP_ERR_INVALID) err_desc = "Event has already reached terminal review status";
            else if (act_err != CLIP_OK) err_desc = "Failed to update review status";
            break;
        }

        case CLIP_ADMIN_MARK_FALSE_POS: {
            if (related_event_id == 0) {
                act_err = CLIP_ERR_INVALID;
                err_desc = "Related event ID required for MARK_FALSE_POS";
                break;
            }
            act_err = clip_admin_db_update_event_status(db, related_event_id, CLIP_EVENT_STATUS_FALSE_POS);
            if (act_err == CLIP_ERR_EXISTS) err_desc = "Event is already marked FALSE_POS";
            else if (act_err == CLIP_ERR_INVALID) err_desc = "Event has already reached terminal review status";
            else if (act_err != CLIP_OK) err_desc = "Failed to update review status";
            break;
        }

        case CLIP_ADMIN_CREATE_ADMIN: {
            const uint8_t* new_u_ptr = NULL;
            uint16_t new_u_len = 0;
            const uint8_t* new_p_ptr = NULL;
            uint16_t new_p_len = 0;
            const uint8_t* new_r_ptr = NULL;
            uint16_t new_r_len = 0;

            clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_ADMIN_USERNAME, &new_u_ptr, &new_u_len);
            clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_TEXT, &new_p_ptr, &new_p_len);
            clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_PERMISSION_LEVEL, &new_r_ptr, &new_r_len);

            if (!new_u_ptr || new_u_len == 0 || !new_p_ptr || new_p_len < CLIP_ADMIN_PASSWORD_MIN_LEN || !new_r_ptr || new_r_len == 0) {
                act_err = CLIP_ERR_INVALID;
                err_desc = "Invalid username, role, or password (min 10 chars)";
                break;
            }

            char new_user[CLIP_ADMIN_USERNAME_MAX_LEN] = {0};
            size_t c_nu = (new_u_len < sizeof(new_user) - 1) ? new_u_len : sizeof(new_user) - 1;
            memcpy(new_user, new_u_ptr, c_nu);

            char new_pass[128] = {0};
            size_t c_np = (new_p_len < sizeof(new_pass) - 1) ? new_p_len : sizeof(new_pass) - 1;
            memcpy(new_pass, new_p_ptr, c_np);

            ClipAdminUser u_entry;
            memset(&u_entry, 0, sizeof(u_entry));
            clip_crypto_uuid_generate((ClipUuid*)u_entry.admin_uuid);
            strncpy(u_entry.username, new_user, sizeof(u_entry.username) - 1);
            u_entry.role = (ClipAdminPermission)new_r_ptr[0];
            u_entry.iterations = CLIP_ADMIN_DEFAULT_ITERATIONS;
            clip_crypto_random_bytes(u_entry.salt, CLIP_ADMIN_SALT_BYTES);

            act_err = clip_admin_hash_password(new_pass, u_entry.salt, u_entry.iterations, u_entry.verifier);
            OPENSSL_cleanse(new_pass, sizeof(new_pass));

            if (act_err == CLIP_OK) {
                act_err = clip_admin_db_create_admin(db, &u_entry);
            }
            if (act_err != CLIP_OK) err_desc = "Failed to create administrator account";
            break;
        }

        default:
            act_err = CLIP_ERR_INVALID;
            err_desc = "Unsupported administrative action";
            break;
        }

        if (act_err != CLIP_OK) {
            audit.status = CLIP_AUDIT_STATUS_FAILED;
            audit.error_code = act_err;
            clip_admin_db_add_audit(db, &audit, NULL);
            send_admin_fail(srv, client->sock, rx_hdr->seq_num + 1, act_err, err_desc ? err_desc : "Action failed");
            return;
        }

        audit.status = CLIP_AUDIT_STATUS_SUCCESS;
        audit.error_code = CLIP_OK;
        uint32_t audit_id = 0;
        clip_admin_db_add_audit(db, &audit, &audit_id);

        CLIP_LOGI("Admin action %s executed successfully by '%s' (audit_id=%u)",
                  clip_admin_action_name(action), client->admin_username, audit_id);
        send_admin_action_ok(srv, client->sock, rx_hdr->seq_num + 1, action, audit_id);
    } else if (rx_hdr->msg_type == CLIP_MSG_ADMIN_EVENTS_REQ) {
        if (!client->is_admin_authenticated) {
            send_admin_fail(srv, client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, "Unauthenticated administrator connection");
            return;
        }

        int filter_status = -1;
        const uint8_t* st_ptr = NULL;
        uint16_t st_len = 0;
        if (clip_tlv_find(rx_payload, rx_payload_len, CLIP_TAG_EVENT_STATUS, &st_ptr, &st_len) == CLIP_OK && st_len >= 1) {
            filter_status = (int)st_ptr[0];
        }

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipSecurityEvent events[64];
        size_t count = 0;
        clip_admin_db_query_events(db, filter_status, events, 64, &count);

        uint8_t resp_payload[16384];
        size_t resp_len = 0;

        uint16_t ec = (uint16_t)count;
        uint8_t ec_buf[2] = { (uint8_t)((ec >> 8) & 0xFF), (uint8_t)(ec & 0xFF) };
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_EVENT_COUNT, ec_buf, 2);

        for (size_t i = 0; i < count; i++) {
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_EVENT_UUID, events[i].event_uuid, CLIP_UUID_BYTES);
            uint8_t eid_buf[4] = {
                (uint8_t)((events[i].event_id >> 24) & 0xFF),
                (uint8_t)((events[i].event_id >> 16) & 0xFF),
                (uint8_t)((events[i].event_id >> 8) & 0xFF),
                (uint8_t)(events[i].event_id & 0xFF)
            };
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_EVENT_ID, eid_buf, 4);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SESSION_UUID, events[i].session_uuid, CLIP_UUID_BYTES);

            ClipUuid chan_u, node_u;
            if (clip_uuid_from_string(&chan_u, events[i].channel_uuid_str) == 0) {
                clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CHANNEL_UUID, chan_u.bytes, CLIP_UUID_BYTES);
            }
            if (clip_uuid_from_string(&node_u, events[i].node_uuid_str) == 0) {
                clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NODE_UUID, node_u.bytes, CLIP_UUID_BYTES);
            }

            uint8_t ts_buf[8];
            for (int b = 0; b < 8; b++) ts_buf[b] = (uint8_t)((events[i].timestamp_ms >> (56 - b * 8)) & 0xFF);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_TIMESTAMP_MS, ts_buf, 8);

            uint8_t cat_b = (uint8_t)events[i].category;
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CATEGORY, &cat_b, 1);

            uint8_t sev_b = (uint8_t)events[i].severity;
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_SEVERITY, &sev_b, 1);

            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_MATCHED_RULE, events[i].matched_rule, (uint16_t)strlen(events[i].matched_rule));
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_MATCHED_TEXT, events[i].matched_term, (uint16_t)strlen(events[i].matched_term));
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_CONTEXT_TEXT, events[i].context_text, (uint16_t)strlen(events[i].context_text));

            uint8_t st_b = (uint8_t)events[i].status;
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_EVENT_STATUS, &st_b, 1);
        }

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_ADMIN_EVENTS_RESP, (uint32_t)resp_len, rx_hdr->seq_num + 1, NULL);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 16384];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, resp_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
        }
    } else if (rx_hdr->msg_type == CLIP_MSG_ADMIN_AUDIT_REQ) {
        if (!client->is_admin_authenticated) {
            send_admin_fail(srv, client->sock, rx_hdr->seq_num + 1, CLIP_ERR_DENIED, "Unauthenticated administrator connection");
            return;
        }

        sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
        ClipAdminAuditRecord records[64];
        size_t count = 0;
        clip_admin_db_query_audit(db, 64, records, &count);

        uint8_t resp_payload[16384];
        size_t resp_len = 0;

        uint16_t ac = (uint16_t)count;
        uint8_t ac_buf[2] = { (uint8_t)((ac >> 8) & 0xFF), (uint8_t)(ac & 0xFF) };
        clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_ADMIN_AUDIT_COUNT, ac_buf, 2);

        for (size_t i = 0; i < count; i++) {
            uint8_t aid_buf[4] = {
                (uint8_t)((records[i].audit_id >> 24) & 0xFF),
                (uint8_t)((records[i].audit_id >> 16) & 0xFF),
                (uint8_t)((records[i].audit_id >> 8) & 0xFF),
                (uint8_t)(records[i].audit_id & 0xFF)
            };
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_ADMIN_AUDIT_ID, aid_buf, 4);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_NODE_UUID, records[i].admin_uuid, CLIP_UUID_BYTES);

            uint8_t act_b = (uint8_t)records[i].action_type;
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_ADMIN_ACTION, &act_b, 1);

            if (records[i].has_target_uuid) {
                clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_ADMIN_TARGET_UUID, records[i].target_uuid, CLIP_UUID_BYTES);
            }
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_ADMIN_REASON, records[i].reason, (uint16_t)strlen(records[i].reason));

            if (records[i].related_event_id > 0) {
                uint8_t reid_buf[4] = {
                    (uint8_t)((records[i].related_event_id >> 24) & 0xFF),
                    (uint8_t)((records[i].related_event_id >> 16) & 0xFF),
                    (uint8_t)((records[i].related_event_id >> 8) & 0xFF),
                    (uint8_t)(records[i].related_event_id & 0xFF)
                };
                clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_RELATED_EVENT_ID, reid_buf, 4);
            }
            if (records[i].has_related_session) {
                clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_RELATED_SESSION_UUID, records[i].related_session_uuid, CLIP_UUID_BYTES);
            }
            if (records[i].has_related_channel) {
                clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_RELATED_CHANNEL_UUID, records[i].related_channel_uuid, CLIP_UUID_BYTES);
            }

            uint8_t st_b = (uint8_t)records[i].status;
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_AUTH_STATUS, &st_b, 1);

            uint16_t err_c = (uint16_t)(-((int)records[i].error_code));
            uint8_t err_buf[2] = { (uint8_t)((err_c >> 8) & 0xFF), (uint8_t)(err_c & 0xFF) };
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_ERROR_CODE, err_buf, 2);

            uint8_t ts_buf[8];
            for (int b = 0; b < 8; b++) ts_buf[b] = (uint8_t)((records[i].created_at_ms >> (56 - b * 8)) & 0xFF);
            clip_tlv_write(resp_payload, sizeof(resp_payload), &resp_len, CLIP_TAG_TIMESTAMP_MS, ts_buf, 8);
        }

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_ADMIN_AUDIT_RESP, (uint32_t)resp_len, rx_hdr->seq_num + 1, NULL);

        uint8_t frame_buf[CLIP_MIN_FRAME_SIZE + 16384];
        size_t frame_len = 0;
        if (clip_frame_encode(&tx_hdr, resp_payload, frame_buf, sizeof(frame_buf), &frame_len) == CLIP_OK) {
            clip_server_send_client_data(srv, client->sock, frame_buf, frame_len);
            srv->total_frames_sent++;
        }
    } else {
        /* Enforce server authentication boundary: unauthenticated clients cannot proceed */
        if (client->auth_state != CLIP_AUTH_STATE_AUTHENTICATED) {
            CLIP_LOGW("Rejected unauthorized message type 0x%04X from unauthenticated client %s:%u",
                      rx_hdr->msg_type, client->ip_str, client->port);
            send_auth_fail(client->sock, rx_hdr->seq_num + 1, CLIP_ERR_AUTH);
        }
    }
}

void clip_server_config_init_default(ClipServerConfig* cfg)
{
    if (!cfg) return;
    memset(cfg, 0, sizeof(ClipServerConfig));
    strncpy(cfg->bind_host, CLIP_DEFAULT_HOST, sizeof(cfg->bind_host) - 1);
    cfg->port = CLIP_DEFAULT_PORT;
    cfg->max_clients = CLIP_MAX_CLIENTS_DEFAULT;
    strncpy(cfg->db_path, CLIP_DEFAULT_IDENTITY_DB, sizeof(cfg->db_path) - 1);
    cfg->use_tls = true;
    strncpy(cfg->cert_file, "certs/server.crt", sizeof(cfg->cert_file) - 1);
    strncpy(cfg->key_file, "certs/server.key", sizeof(cfg->key_file) - 1);
    cfg->speech_mode = CLIP_SPEECH_MODE_SERVER_MEDIATED;
    strncpy(cfg->rules_file, "config/security_rules.conf", sizeof(cfg->rules_file) - 1);
}

ClipError clip_server_init(ClipServer* srv, const ClipServerConfig* config)
{
    if (!srv) return CLIP_ERR_INVALID;

    memset(srv, 0, sizeof(ClipServer));
    srv->listen_sock = CLIP_INVALID_SOCKET;
    srv->is_running = false;
    srv->identity_db = NULL;

    if (config) {
        srv->config = *config;
    } else {
        clip_server_config_init_default(&srv->config);
    }

    if (srv->config.bind_host[0] == '\0') {
        strncpy(srv->config.bind_host, CLIP_DEFAULT_HOST, sizeof(srv->config.bind_host) - 1);
    }
    if (srv->config.port == 0) {
        srv->config.port = CLIP_DEFAULT_PORT;
    }
    if (srv->config.max_clients == 0) {
        srv->config.max_clients = CLIP_MAX_CLIENTS_DEFAULT;
    }
    if (srv->config.db_path[0] == '\0') {
        strncpy(srv->config.db_path, CLIP_DEFAULT_IDENTITY_DB, sizeof(srv->config.db_path) - 1);
    }

    clip_ptt_manager_init(&srv->ptt_mgr, 64);
    clip_audio_seq_tracker_init(&srv->audio_seq_tracker);
    clip_rate_limiter_init(&srv->rate_limiter);

    /* Load security rules and initialize SecurityAnalyzer (Phase 15) */
    const char* rpath = (srv->config.rules_file[0] != '\0') ? srv->config.rules_file : "config/security_rules.conf";
    srv->security_rules = security_rules_load(rpath);
    srv->security_analyzer = security_analyzer_create(srv->security_rules, server_security_event_cb, srv);

    return clip_client_table_init(&srv->clients, srv->config.max_clients);
}

ClipError clip_server_start(ClipServer* srv)
{
    if (!srv) return CLIP_ERR_INVALID;

    ClipError net_err = clip_net_init();
    if (net_err != CLIP_OK) {
        CLIP_LOGE("WSAStartup failed: %s", clip_error_string(net_err));
        return net_err;
    }

    /* Open SQLite persistent identity store */
    if (!srv->identity_db) {
        ClipError db_err = clip_identity_db_open(&srv->identity_db, srv->config.db_path);
        if (db_err != CLIP_OK) {
            CLIP_LOGE("Failed to open identity database: %s", clip_error_string(db_err));
            return db_err;
        }
    }

    /* Initialize TLS 1.3 server transport if enabled */
    if (srv->config.use_tls) {
        clip_tls_server_config_t tls_cfg = {0};
        tls_cfg.cert_file = (srv->config.cert_file[0] != '\0') ? srv->config.cert_file : "certs/server.crt";
        tls_cfg.key_file  = (srv->config.key_file[0] != '\0')  ? srv->config.key_file  : "certs/server.key";
        if (srv->config.ca_file[0] != '\0') {
            tls_cfg.ca_file = srv->config.ca_file;
        }

        ClipError tls_err = clip_transport_create_server(&tls_cfg, &srv->server_trans);
        if (tls_err != CLIP_OK) {
            CLIP_LOGE("Failed to initialize TLS 1.3 server transport: %s", clip_error_string(tls_err));
            return tls_err;
        }
        CLIP_LOGI("TLS 1.3 Secure Transport enabled (cert=%s)", tls_cfg.cert_file);
    }

    srv->listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv->listen_sock == CLIP_INVALID_SOCKET) {
        int err = clip_net_get_last_error();
        CLIP_LOGE("Failed to create server socket: %s", clip_net_strerror(err));
        return CLIP_ERR_IO;
    }

    /* Allow address reuse */
    int opt = 1;
#ifdef _WIN32
    setsockopt(srv->listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(srv->listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    /* Configure bind address */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(srv->config.port);

    if (strcmp(srv->config.bind_host, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        addr.sin_addr.s_addr = inet_addr(srv->config.bind_host);
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        }
    }

    if (bind(srv->listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == CLIP_SOCKET_ERROR) {
        int err = clip_net_get_last_error();
        CLIP_LOGE("Failed to bind to %s:%u: %s",
                  srv->config.bind_host, srv->config.port, clip_net_strerror(err));
        clip_net_close_socket(&srv->listen_sock);
        return CLIP_ERR_IO;
    }

    if (listen(srv->listen_sock, SOMAXCONN) == CLIP_SOCKET_ERROR) {
        int err = clip_net_get_last_error();
        CLIP_LOGE("Failed to listen on %s:%u: %s",
                  srv->config.bind_host, srv->config.port, clip_net_strerror(err));
        clip_net_close_socket(&srv->listen_sock);
        return CLIP_ERR_IO;
    }

    /* Set listening socket non-blocking for clean polling */
    clip_net_set_nonblocking(srv->listen_sock, true);

    srv->is_running = true;
    CLIP_LOGI("SERVER STARTED");
    CLIP_LOGI("LISTENING ON %s:%u", srv->config.bind_host, srv->config.port);

    return CLIP_OK;
}

ClipError clip_server_poll(ClipServer* srv, int timeout_ms)
{
    g_active_server = srv;
    if (!srv || !srv->is_running || srv->listen_sock == CLIP_INVALID_SOCKET) {
        return CLIP_ERR_INVALID;
    }

    /* Phase 17 Stage 4: Sync mock clock to rate limiter */
    clip_rate_limiter_set_mock_clock(&srv->rate_limiter, srv->mock_now_ms);

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(srv->listen_sock, &read_fds);

    clip_socket_t max_fd = srv->listen_sock;
    bool any_pending = false;

    for (size_t i = 0; i < srv->clients.capacity; i++) {
        ClipClientConn* c = &srv->clients.clients[i];
        if (c->active && c->sock != CLIP_INVALID_SOCKET) {
            FD_SET(c->sock, &read_fds);
            if (c->sock > max_fd) {
                max_fd = c->sock;
            }
            if (c->transport && clip_transport_has_pending(c->transport)) {
                any_pending = true;
            }
        }
    }

    struct timeval tv;
    if (any_pending) {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
    } else {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
    }

    int sel_res = select((int)(max_fd + 1), &read_fds, NULL, NULL, &tv);
    if (sel_res < 0) {
        int err = clip_net_get_last_error();
        if (err == WSAEINTR) return CLIP_OK;
        return CLIP_ERR_IO;
    }

    /* 1. Check for incoming client connections */
    if (sel_res > 0 && FD_ISSET(srv->listen_sock, &read_fds)) {
        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);

        clip_socket_t client_sock = accept(srv->listen_sock,
                                           (struct sockaddr*)&client_addr,
                                           &addr_len);

        if (client_sock != CLIP_INVALID_SOCKET) {
            clip_net_set_nodelay(client_sock, true);
            clip_net_set_keepalive(client_sock, true);

            char ip_str[64];
            const char* ip = inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
            uint16_t port = ntohs(client_addr.sin_port);

            clip_transport_t *client_trans = NULL;
            if (srv->server_trans) {
                ClipError acc_err = clip_transport_accept(srv->server_trans, client_sock, &client_trans);
                if (acc_err != CLIP_OK) {
                    CLIP_LOGW("TLS 1.3 Handshake failed from %s:%u (%s) - closing",
                              ip ? ip : "unknown", port, clip_error_string(acc_err));
                    clip_net_close_socket(&client_sock);
                    client_sock = CLIP_INVALID_SOCKET;
                }
            }

            if (client_sock != CLIP_INVALID_SOCKET) {
                ClipClientConn* new_conn = clip_client_table_add(&srv->clients,
                                                                 client_sock,
                                                                 ip ? ip : "unknown",
                                                                 port);

                if (new_conn) {
                    new_conn->transport = client_trans;
                    new_conn->tls_established = (client_trans != NULL);
                    uint64_t conn_now_ms = srv->mock_now_ms ? srv->mock_now_ms : current_time_ms();
                    new_conn->connected_at_ms = conn_now_ms;
                    new_conn->last_seen_ms = conn_now_ms;
                    CLIP_LOGI("CLIENT CONNECTED from %s:%u (%s)",
                              new_conn->ip_str, new_conn->port,
                              new_conn->tls_established ? "TLS 1.3 Encrypted" : "Plaintext");
                } else {
                    CLIP_LOGW("Rejected connection from %s:%u: server client table is full",
                              ip_str, port);
                    if (client_trans) clip_transport_free(client_trans);
                    else clip_net_close_socket(&client_sock);
                }
            }
        }
    }

    /* 2. Check for incoming data on connected client sockets */
    for (size_t i = 0; i < srv->clients.capacity; i++) {
        ClipClientConn* c = &srv->clients.clients[i];
        if (!c->active || c->sock == CLIP_INVALID_SOCKET) {
            continue;
        }

        bool socket_ready = (sel_res > 0 && FD_ISSET(c->sock, &read_fds));
        bool has_pending = (c->transport && clip_transport_has_pending(c->transport));

        if (socket_ready || has_pending) {
            size_t space_left = sizeof(c->rx_buf) - c->rx_len;
            if (space_left == 0) {
                /* Buffer is saturated without valid frame boundary: close malformed client */
                CLIP_LOGW("Client %s:%u receive buffer overflowed: closing", c->ip_str, c->port);
                clip_client_table_remove(&srv->clients, c->sock);
                continue;
            }

            int n = 0;
            if (c->transport) {
                size_t rbytes = 0;
                ClipError rerr = clip_transport_read(c->transport, c->rx_buf + c->rx_len, space_left, &rbytes);
                if (rerr == CLIP_OK) {
                    n = (int)rbytes;
                } else if (rerr == CLIP_ERR_SHUTDOWN) {
                    n = 0;
                } else {
                    n = -1;
                }
            } else {
                n = recv(c->sock, (char*)(c->rx_buf + c->rx_len), (int)space_left, 0);
            }

            if (n > 0) {
                c->rx_len += (size_t)n;

                /*
                 * Frame accumulation loop:
                 * Correctly processes:
                 * - partial headers
                 * - partial payloads
                 * - partial CRC trailers
                 * - multiple coalesced frames in a single recv()
                 */
                while (c->rx_len >= CLIP_MIN_FRAME_SIZE) {
                    /* Inspect header magic */
                    uint32_t magic = ((uint32_t)c->rx_buf[0] << 24) |
                                     ((uint32_t)c->rx_buf[1] << 16) |
                                     ((uint32_t)c->rx_buf[2] << 8)  |
                                      (uint32_t)c->rx_buf[3];

                    if (magic != CLIP_PROTOCOL_MAGIC) {
                        CLIP_LOGW("PROTOCOL ERROR: Invalid magic 0x%08X from %s:%u - closing",
                                  magic, c->ip_str, c->port);
                        clip_client_table_remove(&srv->clients, c->sock);
                        break;
                    }

                    /* Inspect payload length */
                    uint32_t payload_len = ((uint32_t)c->rx_buf[8]  << 24) |
                                           ((uint32_t)c->rx_buf[9]  << 16) |
                                           ((uint32_t)c->rx_buf[10] << 8)  |
                                            (uint32_t)c->rx_buf[11];

                    if (payload_len > CLIP_MAX_PAYLOAD_SIZE) {
                        CLIP_LOGW("PROTOCOL ERROR: Oversized payload %u from %s:%u - closing",
                                  payload_len, c->ip_str, c->port);
                        clip_client_table_remove(&srv->clients, c->sock);
                        break;
                    }

                    size_t expected_frame_size = (size_t)CLIP_HEADER_SIZE +
                                                 (size_t)payload_len +
                                                 (size_t)CLIP_CRC32_SIZE;

                    if (c->rx_len < expected_frame_size) {
                        /* Incomplete frame: wait for more bytes in subsequent recv() */
                        break;
                    }

                    /* Complete frame arrived: decode and validate using Phase 1 decoder */
                    ClipFrameHeader rx_hdr;
                    const uint8_t* rx_payload = NULL;
                    uint32_t decoded_payload_len = 0;

                    ClipError dec_err = clip_frame_decode(c->rx_buf,
                                                          expected_frame_size,
                                                          &rx_hdr,
                                                          &rx_payload,
                                                          &decoded_payload_len);

                    if (dec_err != CLIP_OK) {
                        CLIP_LOGW("PROTOCOL ERROR: Frame decode failed (%s) from %s:%u - closing",
                                  clip_error_string(dec_err), c->ip_str, c->port);
                        clip_client_table_remove(&srv->clients, c->sock);
                        break;
                    }

                    srv->total_frames_received++;

                    /* Dispatch validated frame */
                    handle_client_frame(srv, c, &rx_hdr, rx_payload, decoded_payload_len);

                    /* If client was closed during handling, exit loop */
                    if (!c->active) {
                        break;
                    }

                    /* Shift remaining bytes in receive buffer */
                    size_t remaining = c->rx_len - expected_frame_size;
                    if (remaining > 0) {
                        memmove(c->rx_buf, c->rx_buf + expected_frame_size, remaining);
                    }
                    c->rx_len = remaining;
                }
            } else if (n == 0) {
                /* Graceful client disconnect */
                CLIP_LOGI("CLIENT DISCONNECTED (%s:%u)", c->ip_str, c->port);
                clip_server_handle_client_disconnect(srv, c);
            } else {
                int err = clip_net_get_last_error();
                if (err != WSAEWOULDBLOCK && err != WSAEINTR) {
                    CLIP_LOGI("CLIENT DISCONNECTED (socket error %d) (%s:%u)",
                              err, c->ip_str, c->port);
                    clip_server_handle_client_disconnect(srv, c);
                }
            }
        }
    }

    /* 3. PTT Floor Lease Watchdog */
    if (srv->is_running) {
        uint64_t now_ms = srv->mock_now_ms ? srv->mock_now_ms : current_time_ms();
        ClipUuid expired_sessions[16];
        size_t expired_count = 0;
        clip_ptt_manager_check_timeouts(&srv->ptt_mgr, now_ms, expired_sessions, 16, &expired_count);
        for (size_t k = 0; k < expired_count; k++) {
            CLIP_LOGI("PTT Watchdog: Floor lease expired for session %02x%02x...",
                      expired_sessions[k].bytes[0], expired_sessions[k].bytes[1]);
            sqlite3* db = clip_identity_get_sqlite(srv->identity_db);
            ClipSessionRecord srec;
            if (clip_session_get(db, &expired_sessions[k], &srec) == CLIP_OK && srec.state == CLIP_SESSION_STATE_ACTIVE) {
                ClipClientConn* init_cc = clip_client_table_find_by_node_uuid(&srv->clients, &srec.initiator_node_uuid);
                if (init_cc) {
                    send_ptt_notify(srv, init_cc->sock, expired_sessions[k].bytes, CLIP_PTT_FLOOR_FREE, NULL, 0);
                }
                if (!clip_uuid_is_zero(&srec.peer_node_uuid)) {
                    ClipClientConn* peer_cc = clip_client_table_find_by_node_uuid(&srv->clients, &srec.peer_node_uuid);
                    if (peer_cc) {
                        send_ptt_notify(srv, peer_cc->sock, expired_sessions[k].bytes, CLIP_PTT_FLOOR_FREE, NULL, 0);
                    }
                }
            }
        }

        /* 4. Phase 17: Heartbeat & Inactivity Watchdog */
        for (size_t i = 0; i < srv->clients.capacity; i++) {
            ClipClientConn* c = &srv->clients.clients[i];
            if (!c->active || c->sock == CLIP_INVALID_SOCKET) continue;

            uint64_t last_activity = c->last_seen_ms ? c->last_seen_ms : c->connected_at_ms;

            /* Check if an in-flight server heartbeat ACK has timed out (> 5000 ms) */
            if (c->heartbeat_in_flight) {
                if (now_ms >= c->last_heartbeat_sent_ms + 5000ULL) {
                    c->missed_heartbeats++;
                    c->heartbeat_in_flight = false;
                    CLIP_LOGW("Server heartbeat ACK deadline expired for client %s:%u (missed=%u)",
                              c->ip_str, c->port, c->missed_heartbeats);

                    if (c->missed_heartbeats >= 2) {
                        CLIP_LOGW("Two consecutive missed heartbeat deadlines for client %s:%u - disconnecting",
                                  c->ip_str, c->port);
                        clip_server_handle_client_disconnect(srv, c);
                        continue;
                    }
                }
            }

            /* Fallback silence timeout for dead connections (40000 ms silence or 2 misses) */
            if (now_ms > last_activity + 40000ULL || c->missed_heartbeats >= 2) {
                CLIP_LOGW("Heartbeat timeout for client %s:%u (missed=%u, silence=%llu ms) - disconnecting",
                          c->ip_str, c->port, c->missed_heartbeats,
                          (unsigned long long)(now_ms - last_activity));
                clip_server_handle_client_disconnect(srv, c);
                continue;
            }

            /* Server-initiated keepalive ping if client quiet for > 15000 ms and no heartbeat in flight */
            if (!c->heartbeat_in_flight) {
                uint64_t last_quiet_check = (c->last_heartbeat_sent_ms > last_activity) ?
                                             c->last_heartbeat_sent_ms : last_activity;
                if (now_ms >= last_quiet_check + 15000ULL) {
                    ClipFrameHeader ping_hdr;
                    clip_frame_header_init(&ping_hdr, CLIP_MSG_HEARTBEAT, 0, 1, NULL);
                    uint8_t fbuf[CLIP_MIN_FRAME_SIZE + 32];
                    size_t flen = 0;
                    if (clip_frame_encode(&ping_hdr, NULL, fbuf, sizeof(fbuf), &flen) == CLIP_OK) {
                        clip_server_send_client_data(srv, c->sock, fbuf, flen);
                        srv->total_frames_sent++;
                        c->last_heartbeat_sent_ms = now_ms;
                        c->heartbeat_in_flight = true;
                        CLIP_LOGI("Server keepalive ping sent to %s:%u (started 5000ms deadline)",
                                  c->ip_str, c->port);
                    }
                }
            }
        }
    }

    return CLIP_OK;
}

void clip_server_stop(ClipServer* srv)
{
    if (!srv) return;

    if (srv->is_running) {
        CLIP_LOGI("Stopping server...");
        srv->is_running = false;
        if (srv->server_trans) {
            clip_transport_free(srv->server_trans);
            srv->server_trans = NULL;
        }
        clip_net_close_socket(&srv->listen_sock);
        clip_client_table_cleanup(&srv->clients);
        clip_ptt_manager_cleanup(&srv->ptt_mgr);
        clip_audio_seq_tracker_cleanup(&srv->audio_seq_tracker);
        clip_rate_limiter_cleanup(&srv->rate_limiter);

        if (srv->security_analyzer) {
            security_analyzer_destroy(srv->security_analyzer);
            srv->security_analyzer = NULL;
        }
        if (srv->security_rules) {
            security_rules_free(srv->security_rules);
            srv->security_rules = NULL;
        }
    }

    if (srv->identity_db) {
        clip_identity_db_close(srv->identity_db);
        srv->identity_db = NULL;
    }
}

void clip_server_cleanup(ClipServer* srv)
{
    if (!srv) return;
    clip_server_stop(srv);
    clip_net_cleanup();
}

ClipError clip_server_run(ClipServer* srv, const volatile bool* stop_flag)
{
    if (!srv) return CLIP_ERR_INVALID;

    while (srv->is_running && (!stop_flag || !(*stop_flag))) {
        ClipError err = clip_server_poll(srv, 100);
        if (err != CLIP_OK && err != CLIP_ERR_TIMEOUT) {
            return err;
        }
    }

    return CLIP_OK;
}

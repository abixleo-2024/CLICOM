/*
 * network.c — CLICOM Client TCP Networking Implementation (Phase 2)
 */

#include "network.h"
#include "speech_analyzer.h"
#include "clip_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static CRITICAL_SECTION g_client_send_cs;
static bool g_client_send_cs_init = false;
static void client_send_lock(void) {
    if (!g_client_send_cs_init) {
        InitializeCriticalSection(&g_client_send_cs);
        g_client_send_cs_init = true;
    }
    EnterCriticalSection(&g_client_send_cs);
}
static void client_send_unlock(void) {
    LeaveCriticalSection(&g_client_send_cs);
}
#else
#include <pthread.h>
static pthread_mutex_t g_client_send_mutex = PTHREAD_MUTEX_INITIALIZER;
static void client_send_lock(void) { pthread_mutex_lock(&g_client_send_mutex); }
static void client_send_unlock(void) { pthread_mutex_unlock(&g_client_send_mutex); }
#endif

ClipError clip_client_net_init(ClipClientNet* net)
{
    if (!net) return CLIP_ERR_INVALID;

    memset(net, 0, sizeof(ClipClientNet));
    net->sock = CLIP_INVALID_SOCKET;
    net->transport = NULL;
    net->use_tls = true;  /* Production default is TLS 1.3 */
    net->tls_cfg.ca_file = "certs/ca.crt";
    net->tls_cfg.expected_host = "localhost";
    net->is_connected = false;
    net->is_registered = false;
    net->seq_counter = 0;
    clip_telemetry_init(&net->telemetry);

    return clip_net_init();
}

void clip_client_net_set_tls_config(ClipClientNet* net, const clip_tls_client_config_t* cfg)
{
    if (!net) return;
    if (cfg) {
        net->tls_cfg = *cfg;
        net->use_tls = true;
    } else {
        net->use_tls = false;
    }
}

void clip_client_net_set_insecure_plaintext(ClipClientNet* net)
{
    if (!net) return;
    net->use_tls = false;
    if (net->transport) {
        clip_transport_free(net->transport);
        net->transport = NULL;
    }
}

ClipError clip_client_connect(ClipClientNet* net, const char* host, uint16_t port)
{
    if (!net) return CLIP_ERR_INVALID;

    const char* target_host = (host && host[0] != '\0') ? host : CLIP_DEFAULT_HOST;
    uint16_t target_port = (port > 0) ? port : CLIP_DEFAULT_PORT;

    strncpy(net->host, target_host, sizeof(net->host) - 1);
    net->port = target_port;
    net->rx_len = 0;

    if (net->use_tls) {
        if (!net->tls_cfg.ca_file || net->tls_cfg.ca_file[0] == '\0') {
            net->tls_cfg.ca_file = "certs/ca.crt";
        }
        if (!net->tls_cfg.expected_host || net->tls_cfg.expected_host[0] == '\0') {
            net->tls_cfg.expected_host = (strcmp(target_host, "127.0.0.1") == 0) ? "localhost" : target_host;
        }

        ClipError cr_err = clip_transport_create_client(&net->tls_cfg, &net->transport);
        if (cr_err != CLIP_OK) {
            CLIP_LOGE("Failed to create TLS client transport: %s", clip_error_string(cr_err));
            return cr_err;
        }

        ClipError conn_err = clip_transport_connect(net->transport, target_host, target_port);
        if (conn_err != CLIP_OK) {
            CLIP_LOGE("TLS connection to %s:%u failed: %s", target_host, target_port, clip_error_string(conn_err));
            clip_transport_free(net->transport);
            net->transport = NULL;
            return conn_err;
        }

        net->sock = clip_transport_get_socket(net->transport);
        net->is_connected = true;
        net->conn_epoch++;
        CLIP_LOGI("Connected to %s:%u via TLS 1.3 (%s, %s)",
                  target_host, target_port,
                  clip_transport_get_tls_version(net->transport),
                  clip_transport_get_cipher_name(net->transport));
        return CLIP_OK;
    }

    net->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (net->sock == CLIP_INVALID_SOCKET) {
        int err = clip_net_get_last_error();
        CLIP_LOGE("Failed to create client socket: %s", clip_net_strerror(err));
        return CLIP_ERR_IO;
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(target_port);

    srv_addr.sin_addr.s_addr = inet_addr(target_host);
    if (srv_addr.sin_addr.s_addr == INADDR_NONE) {
        struct hostent* he = gethostbyname(target_host);
        if (!he || !he->h_addr_list[0]) {
            int err = clip_net_get_last_error();
            CLIP_LOGE("Failed to resolve host '%s': %s", target_host, clip_net_strerror(err));
            clip_net_close_socket(&net->sock);
            return CLIP_ERR_NOT_FOUND;
        }
        memcpy(&srv_addr.sin_addr, he->h_addr_list[0], sizeof(srv_addr.sin_addr));
    }

    if (connect(net->sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) == CLIP_SOCKET_ERROR) {
        int err = clip_net_get_last_error();
        CLIP_LOGE("Connection to %s:%u failed: %s", target_host, target_port, clip_net_strerror(err));
        clip_net_close_socket(&net->sock);
        return CLIP_ERR_CONN_REFUSED;
    }

    clip_net_set_nodelay(net->sock, true);
    clip_net_set_keepalive(net->sock, true);

    net->is_connected = true;
    net->conn_epoch++;
    net->rx_len = 0;
    CLIP_LOGI("Connected to %s:%u (plaintext dev mode)", target_host, target_port);

    return CLIP_OK;
}

ClipError clip_client_send_frame(ClipClientNet*         net,
                                 const ClipFrameHeader* hdr,
                                 const uint8_t*         payload)
{
    if (!net || !net->is_connected || net->sock == CLIP_INVALID_SOCKET || !hdr) {
        return CLIP_ERR_INVALID;
    }

    size_t alloc_size = (size_t)CLIP_HEADER_SIZE + (size_t)hdr->payload_len + (size_t)CLIP_CRC32_SIZE;
    uint8_t* frame_buf = (uint8_t*)malloc(alloc_size);
    if (!frame_buf) {
        return CLIP_ERR_NOMEM;
    }

    size_t out_frame_len = 0;
    ClipError enc_err = clip_frame_encode(hdr, payload, frame_buf, alloc_size, &out_frame_len);
    if (enc_err != CLIP_OK) {
        free(frame_buf);
        return enc_err;
    }

    ClipError send_err = CLIP_OK;
    client_send_lock();
    if (net->transport) {
        send_err = clip_transport_write(net->transport, frame_buf, out_frame_len);
    } else {
        send_err = clip_net_send_all(net->sock, frame_buf, out_frame_len);
    }
    client_send_unlock();
    free(frame_buf);

    if (send_err == CLIP_OK) {
        uint64_t now_ms = net->mock_now_ms ? net->mock_now_ms : 0;
        if (!now_ms) {
#ifdef _WIN32
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            ULARGE_INTEGER uli;
            uli.LowPart = ft.dwLowDateTime;
            uli.HighPart = ft.dwHighDateTime;
            now_ms = (uint64_t)((uli.QuadPart - 116444736000000000ULL) / 10000ULL);
#else
            struct timeval tv;
            gettimeofday(&tv, NULL);
            now_ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
#endif
        }
        net->last_traffic_sent_ms = now_ms;
    }

    return send_err;
}

ClipError clip_client_recv_frame(ClipClientNet*   net,
                                 ClipFrameHeader* out_hdr,
                                 uint8_t*         out_payload_buf,
                                 size_t           out_payload_max,
                                 uint32_t*        out_payload_len,
                                 int              timeout_ms)
{
    if (!net || !net->is_connected || net->sock == CLIP_INVALID_SOCKET || !out_hdr) {
        return CLIP_ERR_INVALID;
    }

    uint64_t start_time_ms = 0; /* In future, use high-resolution timer if needed */
    (void)start_time_ms;

    while (true) {
        /* Check if a complete frame is already buffered */
        if (net->rx_len >= CLIP_MIN_FRAME_SIZE) {
            uint32_t magic = ((uint32_t)net->rx_buf[0] << 24) |
                             ((uint32_t)net->rx_buf[1] << 16) |
                             ((uint32_t)net->rx_buf[2] << 8)  |
                              (uint32_t)net->rx_buf[3];

            if (magic != CLIP_PROTOCOL_MAGIC) {
                return CLIP_ERR_BAD_MAGIC;
            }

            uint32_t payload_len = ((uint32_t)net->rx_buf[8]  << 24) |
                                   ((uint32_t)net->rx_buf[9]  << 16) |
                                   ((uint32_t)net->rx_buf[10] << 8)  |
                                    (uint32_t)net->rx_buf[11];

            if (payload_len > CLIP_MAX_PAYLOAD_SIZE) {
                return CLIP_ERR_PAYLOAD_SIZE;
            }

            size_t expected_size = (size_t)CLIP_HEADER_SIZE + (size_t)payload_len + (size_t)CLIP_CRC32_SIZE;
            if (net->rx_len >= expected_size) {
                /* Complete frame ready for decoding */
                const uint8_t* payload_ptr = NULL;
                uint32_t decoded_len = 0;

                ClipError dec_err = clip_frame_decode(net->rx_buf, expected_size,
                                                      out_hdr, &payload_ptr, &decoded_len);

                if (dec_err != CLIP_OK) {
                    return dec_err;
                }

                if (out_payload_len) {
                    *out_payload_len = decoded_len;
                }

                if (decoded_len > 0 && out_payload_buf) {
                    size_t copy_len = (decoded_len < out_payload_max) ? decoded_len : out_payload_max;
                    memcpy(out_payload_buf, payload_ptr, copy_len);
                }

                /* Shift remaining bytes in receive buffer */
                size_t remaining = net->rx_len - expected_size;
                if (remaining > 0) {
                    memmove(net->rx_buf, net->rx_buf + expected_size, remaining);
                }
                net->rx_len = remaining;

                /* Handle Heartbeat protocol messages */
                if (out_hdr->msg_type == CLIP_MSG_HEARTBEAT_ACK) {
                    uint64_t now_ms = net->mock_now_ms ? net->mock_now_ms : 0;
                    if (!now_ms) {
#ifdef _WIN32
                        FILETIME ft;
                        GetSystemTimeAsFileTime(&ft);
                        ULARGE_INTEGER uli;
                        uli.LowPart = ft.dwLowDateTime;
                        uli.HighPart = ft.dwHighDateTime;
                        now_ms = (uint64_t)((uli.QuadPart - 116444736000000000ULL) / 10000ULL);
#else
                        struct timeval tv;
                        gettimeofday(&tv, NULL);
                        now_ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
#endif
                    }
                    net->last_heartbeat_ack_ms = now_ms;
                    net->heartbeat_in_flight = false;
                    net->missed_heartbeats = 0;
                    uint64_t telem_now_us = net->mock_now_ms ? (net->mock_now_ms * 1000ULL) : 0;
                    clip_telemetry_on_probe_ack(&net->telemetry, out_hdr->seq_num, telem_now_us, NULL);
                } else if (out_hdr->msg_type == CLIP_MSG_HEARTBEAT) {
                    /* Reply to server ping */
                    ClipFrameHeader ack_hdr;
                    clip_frame_header_init(&ack_hdr, CLIP_MSG_HEARTBEAT_ACK, 0, ++net->seq_counter, net->assigned_uuid);
                    clip_client_send_frame(net, &ack_hdr, NULL);
                }

                return CLIP_OK;
            }
        }

        /* Wait for more data using select() unless TLS already has pending data */
        bool has_pending = (net->transport && clip_transport_has_pending(net->transport));
        if (!has_pending) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(net->sock, &read_fds);

            struct timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;

            int sel = select((int)(net->sock + 1), &read_fds, NULL, NULL, &tv);
            if (sel <= 0) {
                return (sel == 0) ? CLIP_ERR_TIMEOUT : CLIP_ERR_IO;
            }
        }

        size_t space = sizeof(net->rx_buf) - net->rx_len;
        if (space == 0) {
            return CLIP_ERR_NOMEM;
        }

        int n = 0;
        if (net->transport) {
            size_t rbytes = 0;
            ClipError rerr = clip_transport_read(net->transport, net->rx_buf + net->rx_len, space, &rbytes);
            if (rerr == CLIP_OK) {
                n = (int)rbytes;
            } else if (rerr == CLIP_ERR_SHUTDOWN) {
                n = 0;
            } else {
                n = -1;
            }
        } else {
            n = recv(net->sock, (char*)(net->rx_buf + net->rx_len), (int)space, 0);
        }

        if (n > 0) {
            net->rx_len += (size_t)n;
        } else if (n == 0) {
            net->is_connected = false;
            return CLIP_ERR_CONN_REFUSED;
        } else {
            int err = clip_net_get_last_error();
            if (err == WSAEINTR) continue;
            return CLIP_ERR_IO;
        }
    }
}

ClipError clip_client_register(ClipClientNet* net,
                               const char*    display_name,
                               ClipUuid*      out_uuid,
                               uint8_t        out_credential[CLIP_CREDENTIAL_BYTES])
{
    if (!net || !net->is_connected) {
        return CLIP_ERR_INVALID;
    }

    const char* name = (display_name && display_name[0] != '\0') ? display_name : "NODE-A";
    strncpy(net->display_name, name, sizeof(net->display_name) - 1);

    /* Construct payload with DISPLAY_NAME TLV */
    uint8_t reg_payload[128];
    size_t payload_len = 0;
    clip_tlv_write(reg_payload, sizeof(reg_payload), &payload_len,
                   CLIP_TAG_DISPLAY_NAME, net->display_name, (uint16_t)strlen(net->display_name));

    ClipFrameHeader reg_hdr;
    clip_frame_header_init(&reg_hdr,
                           CLIP_MSG_REGISTER,
                           (uint32_t)payload_len,
                           ++net->seq_counter,
                           NULL);

    CLIP_LOGI("Sending REGISTER (display_name='%s')...", net->display_name);
    ClipError send_err = clip_client_send_frame(net, &reg_hdr, reg_payload);
    if (send_err != CLIP_OK) {
        CLIP_LOGE("Failed to send REGISTER frame: %s", clip_error_string(send_err));
        return send_err;
    }

    /* Wait for REGISTER_ACK from server */
    ClipFrameHeader ack_hdr;
    uint8_t ack_payload[512];
    uint32_t ack_len = 0;
    ClipError recv_err = clip_client_recv_frame(net, &ack_hdr, ack_payload, sizeof(ack_payload), &ack_len, 5000);
    if (recv_err != CLIP_OK) {
        CLIP_LOGE("Failed to receive REGISTER_ACK: %s", clip_error_string(recv_err));
        return recv_err;
    }

    if (ack_hdr.msg_type != CLIP_MSG_REGISTER_ACK) {
        CLIP_LOGE("Unexpected response message type 0x%04X (expected REGISTER_ACK 0x%04X)",
                  ack_hdr.msg_type, CLIP_MSG_REGISTER_ACK);
        return CLIP_ERR_PROTO;
    }

    /* Extract UUID and CREDENTIAL from ACK payload */
    const uint8_t* uuid_ptr = NULL;
    uint16_t uuid_len = 0;
    const uint8_t* cred_ptr = NULL;
    uint16_t cred_len = 0;

    clip_tlv_find(ack_payload, ack_len, CLIP_TAG_NODE_UUID, &uuid_ptr, &uuid_len);
    clip_tlv_find(ack_payload, ack_len, CLIP_TAG_CREDENTIAL, &cred_ptr, &cred_len);

    if (uuid_ptr && uuid_len == CLIP_UUID_BYTES) {
        memcpy(net->assigned_uuid, uuid_ptr, CLIP_UUID_BYTES);
    } else {
        CLIP_LOGE("REGISTER_ACK missing valid NODE_UUID TLV");
        return CLIP_ERR_PROTO;
    }

    if (out_uuid) {
        memcpy(out_uuid->bytes, net->assigned_uuid, CLIP_UUID_BYTES);
    }

    if (cred_ptr && cred_len == CLIP_CREDENTIAL_BYTES && out_credential) {
        memcpy(out_credential, cred_ptr, CLIP_CREDENTIAL_BYTES);
    }

    net->is_registered = true;

    char uuid_str[CLIP_UUID_STR_SIZE];
    ClipUuid temp_uuid;
    memcpy(temp_uuid.bytes, net->assigned_uuid, CLIP_UUID_BYTES);
    clip_uuid_to_string(&temp_uuid, uuid_str, sizeof(uuid_str));

    CLIP_LOGI("REGISTER_ACK received from server! Assigned node UUID: %s", uuid_str);
    return CLIP_OK;
}

ClipError clip_client_authenticate(ClipClientNet*   net,
                                   const ClipUuid*  uuid,
                                   const uint8_t    credential[CLIP_CREDENTIAL_BYTES],
                                   char*            out_display_name,
                                   size_t           name_buf_len)
{
    if (!net || !net->is_connected || !uuid || !credential) {
        return CLIP_ERR_INVALID;
    }

    /* Construct AUTH payload with NODE_UUID and CREDENTIAL TLVs */
    uint8_t auth_payload[256];
    size_t payload_len = 0;
    clip_tlv_write(auth_payload, sizeof(auth_payload), &payload_len,
                   CLIP_TAG_NODE_UUID, uuid->bytes, CLIP_UUID_BYTES);
    clip_tlv_write(auth_payload, sizeof(auth_payload), &payload_len,
                   CLIP_TAG_CREDENTIAL, credential, CLIP_CREDENTIAL_BYTES);

    ClipFrameHeader auth_hdr;
    clip_frame_header_init(&auth_hdr,
                           CLIP_MSG_AUTH,
                           (uint32_t)payload_len,
                           ++net->seq_counter,
                           uuid->bytes);

    CLIP_LOGI("Sending AUTH...");
    ClipError send_err = clip_client_send_frame(net, &auth_hdr, auth_payload);

#ifdef _WIN32
    SecureZeroMemory(auth_payload, sizeof(auth_payload));
#else
    memset(auth_payload, 0, sizeof(auth_payload));
#endif

    if (send_err != CLIP_OK) {
        CLIP_LOGE("Failed to send AUTH frame: %s", clip_error_string(send_err));
        return send_err;
    }

    /* Wait for response from server */
    ClipFrameHeader resp_hdr;
    uint8_t resp_payload[256];
    uint32_t resp_len = 0;
    ClipError recv_err = clip_client_recv_frame(net, &resp_hdr, resp_payload, sizeof(resp_payload), &resp_len, 5000);
    if (recv_err != CLIP_OK) {
        CLIP_LOGE("Failed to receive AUTH response: %s", clip_error_string(recv_err));
        return recv_err;
    }

    if (resp_hdr.msg_type == CLIP_MSG_AUTH_OK) {
        memcpy(net->assigned_uuid, uuid->bytes, CLIP_UUID_BYTES);
        net->is_registered = true;

        const uint8_t* name_ptr = NULL;
        uint16_t name_len = 0;
        if (clip_tlv_find(resp_payload, resp_len, CLIP_TAG_DISPLAY_NAME, &name_ptr, &name_len) == CLIP_OK) {
            size_t copy_len = (name_len < sizeof(net->display_name) - 1) ? name_len : (sizeof(net->display_name) - 1);
            memcpy(net->display_name, name_ptr, copy_len);
            net->display_name[copy_len] = '\0';
            if (out_display_name && name_buf_len > 0) {
                size_t out_len = (name_len < name_buf_len - 1) ? name_len : (name_buf_len - 1);
                memcpy(out_display_name, name_ptr, out_len);
                out_display_name[out_len] = '\0';
            }
        }
        CLIP_LOGI("AUTH_OK received from server!");
        return CLIP_OK;
    }

    if (resp_hdr.msg_type == CLIP_MSG_AUTH_FAIL) {
        const uint8_t* status_ptr = NULL;
        uint16_t status_len = 0;
        if (clip_tlv_find(resp_payload, resp_len, CLIP_TAG_AUTH_STATUS, &status_ptr, &status_len) == CLIP_OK && status_len == 2) {
            uint16_t code = ((uint16_t)status_ptr[0] << 8) | (uint16_t)status_ptr[1];
            if (code == (uint16_t)(-((int)CLIP_ERR_DENIED))) {
                return CLIP_ERR_DENIED;
            }
            if (code == (uint16_t)(-((int)CLIP_ERR_BANNED))) {
                return CLIP_ERR_BANNED;
            }
        }
        return CLIP_ERR_AUTH;
    }

    return CLIP_ERR_PROTO;
}

void clip_client_disconnect(ClipClientNet* net)
{
    if (!net || !net->is_connected) {
        return;
    }

    /* Send graceful disconnect notification if possible */
    ClipFrameHeader bye_hdr;
    clip_frame_header_init(&bye_hdr, CLIP_MSG_GOODBYE, 0, ++net->seq_counter, net->assigned_uuid);
    clip_client_send_frame(net, &bye_hdr, NULL);

    if (net->transport) {
        clip_transport_free(net->transport);
        net->transport = NULL;
    }

    clip_net_close_socket(&net->sock);
    net->sock = CLIP_INVALID_SOCKET;
    net->is_connected = false;
    net->is_registered = false;
    net->heartbeat_in_flight = false;
    net->rx_len = 0;
    clip_telemetry_reset(&net->telemetry);

    /* Phase 17 Stage 5: Invalidate previous session and ensure PTT floor & mic capture are stopped */
    clip_uuid_zero(&net->current_session_uuid);
    net->session_valid = false;
    net->ptt_floor_held = false;
    net->mic_capture_active = false;
    net->conn_epoch++;

    CLIP_LOGI("Disconnected cleanly.");

    if (net->disconnect_cb) {
        net->disconnect_cb(net, net->disconnect_user_data);
    }
}

void clip_client_net_cleanup(ClipClientNet* net)
{
    if (!net) return;
    net->shutdown_requested = true;
    net->reconnect_enabled = false;
    clip_client_disconnect(net);
    clip_net_cleanup();
}

/* Phase 17 Heartbeat APIs */

void clip_client_set_disconnect_callback(ClipClientNet* net,
                                         void (*cb)(ClipClientNet* net, void* user_data),
                                         void* user_data)
{
    if (!net) return;
    net->disconnect_cb = cb;
    net->disconnect_user_data = user_data;
}

ClipError clip_client_send_heartbeat(ClipClientNet* net)
{
    if (!net || !net->is_connected) return CLIP_ERR_INVALID;

    uint64_t now_ms = net->mock_now_ms ? net->mock_now_ms : 0;
    if (!now_ms) {
#ifdef _WIN32
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        now_ms = (uint64_t)((uli.QuadPart - 116444736000000000ULL) / 10000ULL);
#else
        struct timeval tv;
        gettimeofday(&tv, NULL);
        now_ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
#endif
    }

    ClipFrameHeader ping_hdr;
    clip_frame_header_init(&ping_hdr, CLIP_MSG_HEARTBEAT, 0, ++net->seq_counter, net->assigned_uuid);
    ClipError err = clip_client_send_frame(net, &ping_hdr, NULL);
    if (err == CLIP_OK) {
        net->last_heartbeat_sent_ms = now_ms;
        net->heartbeat_in_flight = true;
        uint64_t telem_now_us = net->mock_now_ms ? (net->mock_now_ms * 1000ULL) : 0;
        clip_telemetry_on_probe_sent(&net->telemetry, ping_hdr.seq_num, telem_now_us);
    } else {
        /* Immediate transport failure triggers disconnect */
        clip_client_disconnect(net);
    }
    return err;
}

ClipError clip_client_poll_heartbeat(ClipClientNet* net, uint64_t now_ms)
{
    if (!net || !net->is_connected) return CLIP_ERR_INVALID;

    if (!now_ms) {
        now_ms = net->mock_now_ms ? net->mock_now_ms : 0;
        if (!now_ms) {
#ifdef _WIN32
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            ULARGE_INTEGER uli;
            uli.LowPart = ft.dwLowDateTime;
            uli.HighPart = ft.dwHighDateTime;
            now_ms = (uint64_t)((uli.QuadPart - 116444736000000000ULL) / 10000ULL);
#else
            struct timeval tv;
            gettimeofday(&tv, NULL);
            now_ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
#endif
        }
    }

    uint64_t telem_now_us = net->mock_now_ms ? (net->mock_now_ms * 1000ULL) : 0;
    clip_telemetry_check_timeouts(&net->telemetry, telem_now_us);

    /* 1. Check if an in-flight heartbeat timed out (> 5000 ms) */
    if (net->heartbeat_in_flight) {
        if (now_ms >= net->last_heartbeat_sent_ms + 5000ULL) {
            net->missed_heartbeats++;
            net->heartbeat_in_flight = false;
            CLIP_LOGW("Heartbeat ACK timed out (missed=%u)", net->missed_heartbeats);

            /* Two consecutive missed ACKs -> disconnect */
            if (net->missed_heartbeats >= 2) {
                CLIP_LOGW("Two consecutive missed heartbeats -> disconnecting");
                clip_client_disconnect(net);
                return CLIP_ERR_TIMEOUT;
            }
        }
    }

    /* 2. Check if a heartbeat should be sent (every 15000 ms of no traffic) */
    if (!net->heartbeat_in_flight) {
        uint64_t last_traffic = (net->last_traffic_sent_ms > net->last_heartbeat_sent_ms) ?
                                 net->last_traffic_sent_ms : net->last_heartbeat_sent_ms;
        if (now_ms >= last_traffic + 15000ULL) {
            if (net->mock_now_ms != 0 && now_ms != 0) {
                net->mock_now_ms = now_ms;
            }
            return clip_client_send_heartbeat(net);
        }
    }

    return CLIP_OK;
}

static void dispatch_pumped_audio_frame(ClipClientNet* net, const uint8_t* payload, uint32_t payload_len, const uint8_t* session_uuid)
{
    if (!net || !net->audio_recv_cb || !payload || payload_len == 0) return;

    uint8_t codec = 0;
    uint64_t ts = 0;
    const uint8_t* raw_audio = NULL;
    size_t raw_len = 0;
    if (clip_audio_frame_parse_raw(payload, payload_len, &codec, &ts, &raw_audio, &raw_len) != CLIP_OK) {
        return;
    }

    int16_t pcm_buf[5760];
    size_t max_buf_samples = sizeof(pcm_buf) / sizeof(pcm_buf[0]);
    size_t decoded_samples = 0;
    if (codec == CLIP_CODEC_PCM) {
        if ((raw_len % sizeof(int16_t)) != 0) return;
        size_t samples = raw_len / sizeof(int16_t);
        size_t copy_samples = (samples < max_buf_samples) ? samples : max_buf_samples;
        memcpy(pcm_buf, raw_audio, copy_samples * sizeof(int16_t));
        decoded_samples = copy_samples;
    } else if (codec == CLIP_CODEC_OPUS) {
        if (!net->codec_decoder) {
            uint32_t sr = net->codec_sample_rate ? net->codec_sample_rate : 16000;
            uint8_t ch = net->codec_channels ? net->codec_channels : 1;
            net->codec_decoder = codec_create(CLIP_CODEC_OPUS, sr, ch);
        }
        if (net->codec_decoder) {
            int dec = codec_decode(net->codec_decoder, raw_audio, raw_len, pcm_buf, max_buf_samples);
            if (dec > 0) decoded_samples = (size_t)dec;
        }
    }

    if (decoded_samples > 0) {
        ClipUuid sess;
        if (session_uuid) {
            memcpy(sess.bytes, session_uuid, CLIP_UUID_BYTES);
        } else {
            clip_uuid_zero(&sess);
        }
        net->audio_recv_cb(&sess, ts, pcm_buf, decoded_samples, net->audio_recv_user_data);

        if (net->speech_analyzer && net->session_speech_mode != CLIP_SPEECH_MODE_NONE) {
            speech_analyzer_feed_pcm(net->speech_analyzer, &sess, &sess, ts, pcm_buf, decoded_samples);
        }
    }
}

static void dispatch_pumped_ptt_notify(ClipClientNet* net, const uint8_t* payload, uint32_t payload_len)
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
            const uint8_t* h_ptr = NULL;
            uint16_t h_len = 0;
            if (clip_tlv_find(payload, payload_len, CLIP_TAG_HOLDER_NODE_UUID, &h_ptr, &h_len) == CLIP_OK && h_len == CLIP_UUID_BYTES) {
                memcpy(net->ptt_holder_uuid, h_ptr, CLIP_UUID_BYTES);
                if (memcmp(net->assigned_uuid, h_ptr, CLIP_UUID_BYTES) == 0) {
                    net->ptt_floor_held = true;
                    net->ptt_remote_floor_held = false;
                } else {
                    net->ptt_floor_held = false;
                    net->ptt_remote_floor_held = true;
                }
            } else {
                net->ptt_remote_floor_held = true;
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
    if (out_floor_held) *out_floor_held = (net->ptt_floor_held || net->ptt_remote_floor_held);
    if (out_held_by_me) *out_held_by_me = net->ptt_floor_held;
    if (out_holder_uuid) memcpy(out_holder_uuid->bytes, net->ptt_holder_uuid, CLIP_UUID_BYTES);
    return CLIP_OK;
}

static ClipError process_buffered_frames(ClipClientNet* net)
{
    size_t offset = 0;
    while (offset + CLIP_MIN_FRAME_SIZE <= net->rx_len) {
        uint32_t magic = ((uint32_t)net->rx_buf[offset]     << 24) |
                         ((uint32_t)net->rx_buf[offset + 1] << 16) |
                         ((uint32_t)net->rx_buf[offset + 2] << 8)  |
                          (uint32_t)net->rx_buf[offset + 3];

        if (magic != CLIP_PROTOCOL_MAGIC) {
            clip_client_disconnect(net);
            return CLIP_ERR_BAD_MAGIC;
        }

        uint16_t msg_type = ((uint16_t)net->rx_buf[offset + 6] << 8) |
                             (uint16_t)net->rx_buf[offset + 7];

        uint32_t payload_len = ((uint32_t)net->rx_buf[offset + 8]  << 24) |
                               ((uint32_t)net->rx_buf[offset + 9]  << 16) |
                               ((uint32_t)net->rx_buf[offset + 10] << 8)  |
                                (uint32_t)net->rx_buf[offset + 11];

        if (payload_len > CLIP_MAX_PAYLOAD_SIZE) {
            clip_client_disconnect(net);
            return CLIP_ERR_PAYLOAD_SIZE;
        }

        size_t expected_size = (size_t)CLIP_HEADER_SIZE + (size_t)payload_len + (size_t)CLIP_CRC32_SIZE;
        if (offset + expected_size > net->rx_len) {
            /* Partial frame at the tail: stop scanning buffered frames */
            break;
        }

        bool is_heartbeat = (msg_type == CLIP_MSG_HEARTBEAT || msg_type == CLIP_MSG_HEARTBEAT_ACK);
        bool is_audio = (msg_type == CLIP_MSG_AUDIO_FRAME && net->audio_recv_cb != NULL);
        bool is_ptt_notify = (msg_type == CLIP_MSG_PTT_NOTIFY);

        if (!is_heartbeat && !is_audio && !is_ptt_notify) {
            /* Non-handled application frame: skip past it and inspect the next frame */
            offset += expected_size;
            continue;
        }

        ClipFrameHeader hdr;
        const uint8_t* payload_ptr = NULL;
        uint32_t decoded_len = 0;
        ClipError dec_err = clip_frame_decode(net->rx_buf + offset, expected_size,
                                              &hdr, &payload_ptr, &decoded_len);
        if (dec_err != CLIP_OK) {
            clip_client_disconnect(net);
            return dec_err;
        }

        /* Splice out the handled frame from rx_buf */
        size_t remaining = net->rx_len - (offset + expected_size);
        if (remaining > 0) {
            memmove(net->rx_buf + offset, net->rx_buf + offset + expected_size, remaining);
        }
        net->rx_len -= expected_size;

        if (hdr.msg_type == CLIP_MSG_HEARTBEAT) {
            ClipFrameHeader ack_hdr;
            clip_frame_header_init(&ack_hdr, CLIP_MSG_HEARTBEAT_ACK, 0, ++net->seq_counter, net->assigned_uuid);
            ClipError send_err = clip_client_send_frame(net, &ack_hdr, NULL);
            if (send_err != CLIP_OK) {
                return send_err;
            }
        } else if (hdr.msg_type == CLIP_MSG_HEARTBEAT_ACK) {
            uint64_t now_ms = net->mock_now_ms ? net->mock_now_ms : 0;
            if (!now_ms) {
#ifdef _WIN32
                FILETIME ft;
                GetSystemTimeAsFileTime(&ft);
                ULARGE_INTEGER uli;
                uli.LowPart = ft.dwLowDateTime;
                uli.HighPart = ft.dwHighDateTime;
                now_ms = (uint64_t)((uli.QuadPart - 116444736000000000ULL) / 10000ULL);
#else
                struct timeval tv;
                gettimeofday(&tv, NULL);
                now_ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
#endif
            }
            net->last_heartbeat_ack_ms = now_ms;
            net->heartbeat_in_flight = false;
            net->missed_heartbeats = 0;
            uint64_t telem_now_us = net->mock_now_ms ? (net->mock_now_ms * 1000ULL) : 0;
            clip_telemetry_on_probe_ack(&net->telemetry, hdr.seq_num, telem_now_us, NULL);
        } else if (hdr.msg_type == CLIP_MSG_AUDIO_FRAME) {
            dispatch_pumped_audio_frame(net, payload_ptr, decoded_len, hdr.session_uuid);
        } else if (hdr.msg_type == CLIP_MSG_PTT_NOTIFY) {
            dispatch_pumped_ptt_notify(net, payload_ptr, decoded_len);
        }
    }
    return CLIP_OK;
}

ClipError clip_client_pump_events(ClipClientNet* net, int timeout_ms)
{
    if (!net || !net->is_connected || net->sock == CLIP_INVALID_SOCKET) {
        return CLIP_ERR_INVALID;
    }

    if (timeout_ms < 0) {
        timeout_ms = 0;
    }

    /* 1. First, process any complete frames already buffered in rx_buf */
    ClipError proc_err = process_buffered_frames(net);
    if (proc_err != CLIP_OK) return proc_err;

    /* 2. Poll socket or TLS for inbound data with timeout_ms */
    bool has_pending = (net->transport && clip_transport_has_pending(net->transport));
    if (!has_pending) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(net->sock, &read_fds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel = select((int)(net->sock + 1), &read_fds, NULL, NULL, &tv);
        if (sel <= 0) {
            /* Also service outbound heartbeat checks (e.g. 15s idle ping, 5s timeout) */
            uint64_t now_ms = net->mock_now_ms ? net->mock_now_ms : 0;
            clip_client_poll_heartbeat(net, now_ms);
            return (sel == 0) ? CLIP_OK : CLIP_ERR_IO;
        }
    }

    /* Drain available incoming bytes and process frames (bounded to 16 to keep UI thread non-blocking) */
    int drain_loops = 0;
    while (drain_loops < 16) {
        size_t space = sizeof(net->rx_buf) - net->rx_len;
        if (space == 0) {
            break;
        }

        int n = 0;
        if (net->transport) {
            size_t rbytes = 0;
            ClipError rerr = clip_transport_read(net->transport, net->rx_buf + net->rx_len, space, &rbytes);
            if (rerr == CLIP_OK) {
                n = (int)rbytes;
            } else if (rerr == CLIP_ERR_SHUTDOWN) {
                n = 0;
            } else {
                n = -1;
            }
        } else {
            n = recv(net->sock, (char*)(net->rx_buf + net->rx_len), (int)space, 0);
        }

        if (n > 0) {
            net->rx_len += (size_t)n;
            proc_err = process_buffered_frames(net);
            if (proc_err != CLIP_OK) return proc_err;
            drain_loops++;

            /* Check if more decrypted data is already pending inside OpenSSL */
            if (net->transport && clip_transport_has_pending(net->transport)) {
                continue;
            }

            /* Check if more data/records are waiting on the socket without blocking */
            fd_set chk_fds;
            FD_ZERO(&chk_fds);
            FD_SET(net->sock, &chk_fds);
            struct timeval tv_zero = {0, 0};
            int sel_more = select((int)(net->sock + 1), &chk_fds, NULL, NULL, &tv_zero);
            if (sel_more > 0) {
                continue;
            }
            break;
        } else if (n == 0) {
            net->is_connected = false;
            return CLIP_ERR_CONN_REFUSED;
        } else {
            int err = clip_net_get_last_error();
            if (err != WSAEINTR && err != EAGAIN && err != EWOULDBLOCK) {
                return CLIP_ERR_IO;
            }
            break;
        }
    }

    /* 3. Re-scan buffer for complete frames received in this read */
    proc_err = process_buffered_frames(net);
    if (proc_err != CLIP_OK) return proc_err;

    /* 4. Service outbound heartbeat timer / timeouts */
    uint64_t now_ms = net->mock_now_ms ? net->mock_now_ms : 0;
    clip_client_poll_heartbeat(net, now_ms);

    return CLIP_OK;
}

/* ── Phase 17 Stage 5: Safe Reconnection & Backoff Implementation ────────── */

uint32_t clip_client_reconnect_get_next_backoff_sec(uint32_t attempt_index)
{
    /*
     * Exponential backoff starting at 1 second:
     * attempt 0 -> 1s
     * attempt 1 -> 2s
     * attempt 2 -> 4s
     * attempt 3 -> 8s
     * attempt 4 -> 16s
     * attempt 5+ -> capped at 30s
     */
    if (attempt_index == 0) return 1;
    if (attempt_index == 1) return 2;
    if (attempt_index == 2) return 4;
    if (attempt_index == 3) return 8;
    if (attempt_index == 4) return 16;
    return 30;
}

void clip_client_reconnect_enable(ClipClientNet* net, bool enable)
{
    if (!net) return;
    net->reconnect_enabled = enable;
    if (!enable) {
        net->reconnect_attempts = 0;
        net->next_reconnect_time_ms = 0;
        net->reconnect_in_progress = false;
    }
}

void clip_client_reconnect_set_credentials(ClipClientNet* net,
                                           const ClipUuid* uuid,
                                           const uint8_t credential[CLIP_CREDENTIAL_BYTES])
{
    if (!net) return;
    if (uuid && credential) {
        memcpy(net->saved_node_uuid.bytes, uuid->bytes, CLIP_UUID_BYTES);
        memcpy(net->saved_credential, credential, CLIP_CREDENTIAL_BYTES);
        net->has_saved_credentials = true;
    } else {
        net->has_saved_credentials = false;
    }
}

void clip_client_reconnect_reset_backoff(ClipClientNet* net)
{
    if (!net) return;
    net->reconnect_attempts = 0;
    net->backoff_delay_sec = 1;
    net->next_reconnect_time_ms = 0;
    net->reconnect_in_progress = false;
}

void clip_client_request_shutdown(ClipClientNet* net)
{
    if (!net) return;
    net->shutdown_requested = true;
    net->reconnect_enabled = false;
    net->reconnect_in_progress = false;
    clip_client_disconnect(net);
}

void clip_client_reconnect_set_sync_callback(ClipClientNet* net,
                                                  ClipError (*cb)(ClipClientNet* net, void* user_data),
                                                  void* user_data)
{
    if (!net) return;
    net->sync_cb = cb;
    net->sync_user_data = user_data;
}

ClipError clip_client_reconnect_synchronize(ClipClientNet* net)
{
    if (!net || !net->is_connected || !net->is_registered) {
        return CLIP_ERR_INVALID;
    }

    if (net->sync_cb) {
        return net->sync_cb(net, net->sync_user_data);
    }

    /* Default authoritative synchronization: query node's channel list */
    ClipChannelInfo* chans = NULL;
    size_t chan_cnt = 0;
    ClipError ch_err = clip_client_channel_list(net, &chans, &chan_cnt);
    if (ch_err != CLIP_OK) {
        return ch_err;
    }

    /* If node has joined channels, synchronize membership and presence for each */
    for (size_t i = 0; i < chan_cnt; i++) {
        ClipChannelMember* members = NULL;
        size_t mem_cnt = 0;
        ClipUuid chan_u;
        memcpy(chan_u.bytes, chans[i].channel_uuid, CLIP_UUID_BYTES);
        ClipError mem_err = clip_client_get_channel_members(net, &chan_u, &members, &mem_cnt);
        if (members) {
            clip_client_free_members(members);
        }
        if (mem_err != CLIP_OK) {
            clip_client_free_channels(chans);
            return mem_err;
        }
    }
    clip_client_free_channels(chans);

    /* Authoritative synchronization of connections involving this node */
    ClipConnectionRecord* conns = NULL;
    size_t conn_cnt = 0;
    ClipError co_err = clip_client_list_connections(net, &conns, &conn_cnt);
    if (conns) {
        clip_client_free_connections(conns);
    }
    if (co_err != CLIP_OK) {
        return co_err;
    }

    return CLIP_OK;
}

ClipError clip_client_reconnect_trigger(ClipClientNet* net, uint64_t now_ms)
{
    if (!net) return CLIP_ERR_INVALID;
    if (net->shutdown_requested) {
        CLIP_LOGI("Reconnect suppressed: shutdown requested");
        return CLIP_ERR_INVALID;
    }
    if (!net->reconnect_enabled) {
        CLIP_LOGI("Reconnect suppressed: reconnect disabled");
        return CLIP_ERR_INVALID;
    }
    if (net->is_connected) {
        /* Already connected */
        return CLIP_OK;
    }
    if (net->reconnect_in_progress) {
        /* Guard against parallel reconnect attempts */
        CLIP_LOGW("Reconnect attempt already in progress - suppressing duplicate trigger");
        return CLIP_ERR_EXISTS;
    }

    if (!now_ms) {
        now_ms = net->mock_now_ms ? net->mock_now_ms : 0;
        if (!now_ms) {
#ifdef _WIN32
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            ULARGE_INTEGER uli;
            uli.LowPart = ft.dwLowDateTime;
            uli.HighPart = ft.dwHighDateTime;
            now_ms = (uint64_t)((uli.QuadPart - 116444736000000000ULL) / 10000ULL);
#else
            struct timeval tv;
            gettimeofday(&tv, NULL);
            now_ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
#endif
        }
    }

    net->reconnect_in_progress = true;

    /* Disconnect any lingering socket or state before attempting new connection */
    if (net->sock != CLIP_INVALID_SOCKET || net->transport != NULL) {
        clip_client_disconnect(net);
    }

    /* Preserve saved credentials, target host and port */
    const char* target_host = (net->host[0] != '\0') ? net->host : CLIP_DEFAULT_HOST;
    uint16_t target_port = (net->port > 0) ? net->port : CLIP_DEFAULT_PORT;

    CLIP_LOGI("Executing reconnect attempt %u to %s:%u (epoch=%u)",
              net->reconnect_attempts + 1, target_host, target_port, net->conn_epoch + 1);

    /* 1. Establish fresh transport connection (preserving TLS 1.3 requirement) */
    ClipError conn_err = clip_client_connect(net, target_host, target_port);
    if (conn_err != CLIP_OK) {
        CLIP_LOGW("Reconnect transport connection failed: %s", clip_error_string(conn_err));
        net->reconnect_in_progress = false;

        uint32_t delay_sec = clip_client_reconnect_get_next_backoff_sec(net->reconnect_attempts);
        net->backoff_delay_sec = delay_sec;
        net->next_reconnect_time_ms = now_ms + ((uint64_t)delay_sec * 1000ULL);
        net->reconnect_attempts++;
        CLIP_LOGI("Scheduled next reconnect attempt in %u seconds (attempt %u)", delay_sec, net->reconnect_attempts);
        return conn_err;
    }

    /* 2. Authenticate if saved credentials exist */
    if (net->has_saved_credentials) {
        char srv_name[CLIP_DISPLAY_NAME_MAX];
        ClipError auth_err = clip_client_authenticate(net,
                                                      &net->saved_node_uuid,
                                                      net->saved_credential,
                                                      srv_name,
                                                      sizeof(srv_name));
        if (auth_err != CLIP_OK) {
            CLIP_LOGW("Reconnect authentication failed: %s", clip_error_string(auth_err));
            clip_client_disconnect(net);
            net->reconnect_in_progress = false;

            uint32_t delay_sec = clip_client_reconnect_get_next_backoff_sec(net->reconnect_attempts);
            net->backoff_delay_sec = delay_sec;
            net->next_reconnect_time_ms = now_ms + ((uint64_t)delay_sec * 1000ULL);
            net->reconnect_attempts++;
            return auth_err;
        }
        CLIP_LOGI("Reconnect authentication successful for node %s", srv_name);
    }

    /* 3. Authoritative Initial Synchronization (Requirement 1) */
    ClipError sync_err = clip_client_reconnect_synchronize(net);
    if (sync_err != CLIP_OK) {
        CLIP_LOGW("Reconnect initial synchronization failed: %s", clip_error_string(sync_err));
        clip_client_disconnect(net);
        net->reconnect_in_progress = false;

        uint32_t delay_sec = clip_client_reconnect_get_next_backoff_sec(net->reconnect_attempts);
        net->backoff_delay_sec = delay_sec;
        net->next_reconnect_time_ms = now_ms + ((uint64_t)delay_sec * 1000ULL);
        net->reconnect_attempts++;
        return sync_err;
    }
    CLIP_LOGI("Reconnect initial synchronization successful");

    /* 4. Successful connection, authentication & initial synchronization: reset backoff policy */
    clip_client_reconnect_reset_backoff(net);
    net->reconnect_in_progress = false;

    /* Invariant: Prior session expired; PTT floor and mic capture remain stopped */
    clip_uuid_zero(&net->current_session_uuid);
    net->session_valid = false;
    net->ptt_floor_held = false;
    net->mic_capture_active = false;

    CLIP_LOGI("Reconnect complete and backoff reset.");
    return CLIP_OK;
}

ClipError clip_client_reconnect_poll(ClipClientNet* net, uint64_t now_ms)
{
    if (!net) return CLIP_ERR_INVALID;
    if (net->shutdown_requested || !net->reconnect_enabled || net->is_connected) {
        return CLIP_OK;
    }

    if (!now_ms) {
        now_ms = net->mock_now_ms ? net->mock_now_ms : 0;
        if (!now_ms) {
#ifdef _WIN32
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            ULARGE_INTEGER uli;
            uli.LowPart = ft.dwLowDateTime;
            uli.HighPart = ft.dwHighDateTime;
            now_ms = (uint64_t)((uli.QuadPart - 116444736000000000ULL) / 10000ULL);
#else
            struct timeval tv;
            gettimeofday(&tv, NULL);
            now_ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
#endif
        }
    }

    /* If schedule deadline reached, execute trigger */
    if (net->next_reconnect_time_ms > 0 && now_ms >= net->next_reconnect_time_ms) {
        return clip_client_reconnect_trigger(net, now_ms);
    }

    return CLIP_OK;
}

/* ── Phase 4 Channel & Session Implementations ─────────────────────────── */

ClipError clip_client_channel_create_with_limit(ClipClientNet* net,
                                                const char*    channel_name,
                                                uint16_t       member_limit,
                                                ClipUuid*      out_channel_uuid,
                                                char*          out_join_key,
                                                size_t         join_key_buf_len)
{
    if (!net || !net->is_connected || !net->is_registered || !out_channel_uuid || !out_join_key) {
        return CLIP_ERR_INVALID;
    }

    const char* safe_name = channel_name ? channel_name : "GENERAL";
    uint8_t payload[256];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len,
                   CLIP_TAG_CHANNEL_NAME, safe_name, (uint16_t)strlen(safe_name));

    uint16_t lim = (member_limit == 0) ? 16 : member_limit;
    uint8_t lim_buf[2] = { (uint8_t)((lim >> 8) & 0xFF), (uint8_t)(lim & 0xFF) };
    clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_MEMBER_LIMIT, lim_buf, 2);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_CREATE, (uint32_t)payload_len, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[512];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_CHANNEL_CREATE_OK ||
            rx_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_ERROR) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL) {
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_CHANNEL_CREATE_OK) {
        return CLIP_ERR_PROTO;
    }

    const uint8_t* u_ptr = NULL;
    uint16_t u_len = 0;
    const uint8_t* k_ptr = NULL;
    uint16_t k_len = 0;

    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_CHANNEL_UUID, &u_ptr, &u_len);
    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_CHANNEL_JOIN_KEY, &k_ptr, &k_len);

    if (!u_ptr || u_len != CLIP_UUID_BYTES || !k_ptr || k_len == 0) {
        return CLIP_ERR_PROTO;
    }

    memcpy(out_channel_uuid->bytes, u_ptr, CLIP_UUID_BYTES);
    size_t copy_k = (k_len < join_key_buf_len - 1) ? k_len : (join_key_buf_len - 1);
    memcpy(out_join_key, k_ptr, copy_k);
    out_join_key[copy_k] = '\0';

    return CLIP_OK;
}

ClipError clip_client_channel_create(ClipClientNet* net,
                                     const char*    channel_name,
                                     ClipUuid*      out_channel_uuid,
                                     char*          out_join_key,
                                     size_t         join_key_buf_len)
{
    return clip_client_channel_create_with_limit(net, channel_name, 16, out_channel_uuid, out_join_key, join_key_buf_len);
}

ClipError clip_client_channel_leave(ClipClientNet*  net,
                                    const ClipUuid* channel_uuid)
{
    if (!net || !net->is_connected || !channel_uuid) return CLIP_ERR_INVALID;

    uint8_t payload[64];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_CHANNEL_UUID, channel_uuid->bytes, CLIP_UUID_BYTES);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_LEAVE, (uint32_t)payload_len, ++net->seq_counter, NULL);
    return clip_client_send_frame(net, &tx_hdr, payload);
}

ClipError clip_client_channel_revoke_key(ClipClientNet*  net,
                                         const ClipUuid* channel_uuid)
{
    if (!net || !net->is_connected || !channel_uuid) return CLIP_ERR_INVALID;

    uint8_t payload[64];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_CHANNEL_UUID, channel_uuid->bytes, CLIP_UUID_BYTES);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_REVOKE_KEY, (uint32_t)payload_len, ++net->seq_counter, NULL);
    ClipError err = clip_client_send_frame(net, &tx_hdr, payload);
    if (err != CLIP_OK) return err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[128];
    uint32_t rx_len = 0;
    while (1) {
        err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (err != CLIP_OK) return err;
        if (rx_hdr.msg_type == CLIP_MSG_CHANNEL_REVOKE_KEY_OK ||
            rx_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_ERROR) break;
    }
    if (rx_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL) return CLIP_ERR_DENIED;
    return (rx_hdr.msg_type == CLIP_MSG_CHANNEL_REVOKE_KEY_OK) ? CLIP_OK : CLIP_ERR_PROTO;
}

ClipError clip_client_channel_close(ClipClientNet*  net,
                                    const ClipUuid* channel_uuid)
{
    if (!net || !net->is_connected || !channel_uuid) return CLIP_ERR_INVALID;

    uint8_t payload[64];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_CHANNEL_UUID, channel_uuid->bytes, CLIP_UUID_BYTES);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_CLOSE, (uint32_t)payload_len, ++net->seq_counter, NULL);
    ClipError err = clip_client_send_frame(net, &tx_hdr, payload);
    if (err != CLIP_OK) return err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[128];
    uint32_t rx_len = 0;
    while (1) {
        err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (err != CLIP_OK) return err;
        if (rx_hdr.msg_type == CLIP_MSG_CHANNEL_CLOSE_OK ||
            rx_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_ERROR) break;
    }
    if (rx_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL) return CLIP_ERR_DENIED;
    return (rx_hdr.msg_type == CLIP_MSG_CHANNEL_CLOSE_OK) ? CLIP_OK : CLIP_ERR_PROTO;
}

ClipError clip_client_channel_join(ClipClientNet*      net,
                                   const char*         join_key,
                                   ClipUuid*           out_channel_uuid,
                                   char*               out_channel_name,
                                   size_t              name_buf_len,
                                   ClipChannelMember** out_members,
                                   size_t*             out_member_count)
{
    if (!net || !net->is_connected || !net->is_registered || !join_key || !out_channel_uuid) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[128];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len,
                   CLIP_TAG_CHANNEL_JOIN_KEY, join_key, (uint16_t)strlen(join_key));

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_JOIN, (uint32_t)payload_len, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[4096];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_CHANNEL_JOIN_OK ||
            rx_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_ERROR) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_CHANNEL_JOIN_OK) {
        return CLIP_ERR_PROTO;
    }

    const uint8_t* u_ptr = NULL;
    uint16_t u_len = 0;
    const uint8_t* n_ptr = NULL;
    uint16_t n_len = 0;

    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_CHANNEL_UUID, &u_ptr, &u_len);
    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_CHANNEL_NAME, &n_ptr, &n_len);

    if (!u_ptr || u_len != CLIP_UUID_BYTES) {
        return CLIP_ERR_PROTO;
    }

    memcpy(out_channel_uuid->bytes, u_ptr, CLIP_UUID_BYTES);
    if (out_channel_name && name_buf_len > 0) {
        if (n_ptr && n_len > 0) {
            size_t copy_n = (n_len < name_buf_len - 1) ? n_len : (name_buf_len - 1);
            memcpy(out_channel_name, n_ptr, copy_n);
            out_channel_name[copy_n] = '\0';
        } else {
            out_channel_name[0] = '\0';
        }
    }

    /* Parse members if caller requested */
    if (out_members && out_member_count) {
        *out_members = NULL;
        *out_member_count = 0;

        const uint8_t* cnt_ptr = NULL;
        uint16_t cnt_len = 0;
        clip_tlv_find(rx_payload, rx_len, CLIP_TAG_MEMBER_COUNT, &cnt_ptr, &cnt_len);

        size_t expected_count = (cnt_ptr && cnt_len == 2) ? (((size_t)cnt_ptr[0] << 8) | cnt_ptr[1]) : 0;
        if (expected_count > 0) {
            ClipChannelMember* mems = (ClipChannelMember*)calloc(expected_count, sizeof(ClipChannelMember));
            if (mems) {
                size_t offset = 0;
                size_t parsed = 0;
                while (offset + 4 <= rx_len && parsed < expected_count) {
                    uint16_t tag = ((uint16_t)rx_payload[offset] << 8) | rx_payload[offset + 1];
                    uint16_t len = ((uint16_t)rx_payload[offset + 2] << 8) | rx_payload[offset + 3];
                    offset += 4;
                    if (offset + len > rx_len) break;

                    if (tag == CLIP_TAG_NODE_UUID && len == CLIP_UUID_BYTES) {
                        memcpy(mems[parsed].node_uuid.bytes, &rx_payload[offset], CLIP_UUID_BYTES);
                    } else if (tag == CLIP_TAG_DISPLAY_NAME) {
                        size_t copy_d = (len < sizeof(mems[parsed].display_name) - 1) ? len : (sizeof(mems[parsed].display_name) - 1);
                        memcpy(mems[parsed].display_name, &rx_payload[offset], copy_d);
                        mems[parsed].display_name[copy_d] = '\0';
                    } else if (tag == CLIP_TAG_PRESENCE && len >= 1) {
                        mems[parsed].presence = (ClipPresence)rx_payload[offset];
                        parsed++;
                    }
                    offset += len;
                }
                *out_members = mems;
                *out_member_count = parsed;
            }
        }
    }

    return CLIP_OK;
}

void clip_client_free_members(ClipChannelMember* members)
{
    if (members) free(members);
}

ClipError clip_client_channel_list(ClipClientNet*    net,
                                   ClipChannelInfo** out_channels,
                                   size_t*           out_channel_count)
{
    if (!net || !net->is_connected || !net->is_registered || !out_channels || !out_channel_count) {
        return CLIP_ERR_INVALID;
    }

    *out_channels = NULL;
    *out_channel_count = 0;

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_LIST, 0, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, NULL);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[4096];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_CHANNEL_LIST_RESP ||
            rx_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_ERROR) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL) {
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_CHANNEL_LIST_RESP) {
        return CLIP_ERR_PROTO;
    }

    const uint8_t* cnt_ptr = NULL;
    uint16_t cnt_len = 0;
    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_MEMBER_COUNT, &cnt_ptr, &cnt_len);

    size_t count = (cnt_ptr && cnt_len == 2) ? (((size_t)cnt_ptr[0] << 8) | cnt_ptr[1]) : 0;
    if (count == 0) return CLIP_OK;

    ClipChannelInfo* list = (ClipChannelInfo*)calloc(count, sizeof(ClipChannelInfo));
    if (!list) return CLIP_ERR_NOMEM;

    size_t offset = 0;
    size_t parsed = 0;
    while (offset + 4 <= rx_len && parsed < count) {
        uint16_t tag = ((uint16_t)rx_payload[offset] << 8) | rx_payload[offset + 1];
        uint16_t len = ((uint16_t)rx_payload[offset + 2] << 8) | rx_payload[offset + 3];
        offset += 4;
        if (offset + len > rx_len) break;

        if (tag == CLIP_TAG_CHANNEL_UUID && len == CLIP_UUID_BYTES) {
            memcpy(list[parsed].channel_uuid, &rx_payload[offset], CLIP_UUID_BYTES);
            clip_uuid_to_string((const ClipUuid*)list[parsed].channel_uuid, list[parsed].channel_uuid_str, sizeof(list[parsed].channel_uuid_str));
        } else if (tag == CLIP_TAG_CHANNEL_NAME) {
            size_t copy_n = (len < sizeof(list[parsed].name) - 1) ? len : (sizeof(list[parsed].name) - 1);
            memcpy(list[parsed].name, &rx_payload[offset], copy_n);
            list[parsed].name[copy_n] = '\0';
        } else if (tag == CLIP_TAG_CHANNEL_JOIN_KEY) {
            size_t copy_k = (len < sizeof(list[parsed].join_key) - 1) ? len : (sizeof(list[parsed].join_key) - 1);
            memcpy(list[parsed].join_key, &rx_payload[offset], copy_k);
            list[parsed].join_key[copy_k] = '\0';
            parsed++;
        }
        offset += len;
    }

    *out_channels = list;
    *out_channel_count = parsed;
    return CLIP_OK;
}

void clip_client_free_channels(ClipChannelInfo* channels)
{
    if (channels) free(channels);
}

ClipError clip_client_session_start(ClipClientNet*  net,
                                    const ClipUuid* channel_uuid,
                                    ClipUuid*       out_session_uuid)
{
    if (!net || !net->is_connected || !net->is_registered || !channel_uuid || !out_session_uuid) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[64];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len,
                   CLIP_TAG_CHANNEL_UUID, channel_uuid->bytes, CLIP_UUID_BYTES);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_SESSION_START, (uint32_t)payload_len, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[256];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_SESSION_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_SESSION_START_ACK ||
            rx_hdr.msg_type == CLIP_MSG_SESSION_START_OK) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_SESSION_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_SESSION_START_ACK && rx_hdr.msg_type != CLIP_MSG_SESSION_START_OK) {
        return CLIP_ERR_PROTO;
    }

    /* Extract session UUID from payload or header */
    const uint8_t* s_ptr = NULL;
    uint16_t s_len = 0;
    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_SESSION_UUID, &s_ptr, &s_len);

    if (s_ptr && s_len == CLIP_UUID_BYTES) {
        memcpy(out_session_uuid->bytes, s_ptr, CLIP_UUID_BYTES);
    } else {
        memcpy(out_session_uuid->bytes, rx_hdr.session_uuid, CLIP_UUID_BYTES);
    }

    const uint8_t* sm_ptr = NULL;
    uint16_t sm_len = 0;
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_SPEECH_ANALYSIS, &sm_ptr, &sm_len) == CLIP_OK && sm_len == 1) {
        net->session_speech_mode = (ClipSpeechMode)*sm_ptr;
    } else {
        net->session_speech_mode = CLIP_SPEECH_MODE_NONE;
    }

    return CLIP_OK;
}

ClipError clip_client_session_start_by_conn(ClipClientNet*  net,
                                            const ClipUuid* conn_uuid,
                                            ClipUuid*       out_session_uuid)
{
    if (!net || !net->is_connected || !net->is_registered || !conn_uuid || !out_session_uuid) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[64];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len,
                   CLIP_TAG_CONNECTION_UUID, conn_uuid->bytes, CLIP_UUID_BYTES);

    ClipFrameHeader tx_hdr;
    /* WIRE INVARIANT: session_uuid in header is strictly ZERO prior to session establishment */
    clip_frame_header_init(&tx_hdr, CLIP_MSG_SESSION_START, (uint32_t)payload_len, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[512];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_SESSION_START_ACK ||
            rx_hdr.msg_type == CLIP_MSG_SESSION_START_OK ||
            rx_hdr.msg_type == CLIP_MSG_SESSION_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_SESSION_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_SESSION_START_ACK && rx_hdr.msg_type != CLIP_MSG_SESSION_START_OK) {
        return CLIP_ERR_PROTO;
    }

    /* Extract session UUID from payload or wire header */
    const uint8_t* s_ptr = NULL;
    uint16_t s_len = 0;
    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_SESSION_UUID, &s_ptr, &s_len);

    if (s_ptr && s_len == CLIP_UUID_BYTES) {
        memcpy(out_session_uuid->bytes, s_ptr, CLIP_UUID_BYTES);
    } else {
        memcpy(out_session_uuid->bytes, rx_hdr.session_uuid, CLIP_UUID_BYTES);
    }

    const uint8_t* sm_ptr = NULL;
    uint16_t sm_len = 0;
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_SPEECH_ANALYSIS, &sm_ptr, &sm_len) == CLIP_OK && sm_len == 1) {
        net->session_speech_mode = (ClipSpeechMode)*sm_ptr;
    } else {
        net->session_speech_mode = CLIP_SPEECH_MODE_NONE;
    }

    return CLIP_OK;
}

ClipError clip_client_session_end(ClipClientNet*  net,
                                  const ClipUuid* session_uuid)
{
    if (!net || !net->is_connected || !net->is_registered || !session_uuid) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[64];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len,
                   CLIP_TAG_SESSION_UUID, session_uuid->bytes, CLIP_UUID_BYTES);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_SESSION_END, (uint32_t)payload_len, ++net->seq_counter, session_uuid->bytes);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[64];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_SESSION_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_SESSION_END_ACK ||
            rx_hdr.msg_type == CLIP_MSG_SESSION_END_OK) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_SESSION_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_SESSION_END_ACK && rx_hdr.msg_type != CLIP_MSG_SESSION_END_OK) {
        return CLIP_ERR_PROTO;
    }

    return CLIP_OK;
}

/* ── Phase 5 Client APIs ────────────────────────────────────────────────── */

ClipError clip_client_get_channel_members(ClipClientNet*      net,
                                          const ClipUuid*     channel_uuid,
                                          ClipChannelMember** out_members,
                                          size_t*             out_member_count)
{
    if (!net || !net->is_connected || !net->is_registered || !channel_uuid || !out_members || !out_member_count) {
        return CLIP_ERR_INVALID;
    }

    *out_members = NULL;
    *out_member_count = 0;

    uint8_t payload[64];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len,
                   CLIP_TAG_CHANNEL_UUID, channel_uuid->bytes, CLIP_UUID_BYTES);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_CHANNEL_MEMBERS_REQ, (uint32_t)payload_len, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[4096];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 500);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_CHANNEL_MEMBERS_RESP ||
            rx_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_ERROR) {
            break;
        } else if (rx_hdr.msg_type == CLIP_MSG_AUDIO_FRAME) {
            dispatch_pumped_audio_frame(net, rx_payload, rx_len, rx_hdr.session_uuid);
        } else if (rx_hdr.msg_type == CLIP_MSG_PTT_NOTIFY) {
            dispatch_pumped_ptt_notify(net, rx_payload, rx_len);
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_CHANNEL_MEMBERS_RESP) {
        return CLIP_ERR_PROTO;
    }

    /* Extract member count */
    const uint8_t* m_cnt_ptr = NULL;
    uint16_t m_cnt_len = 0;
    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_MEMBER_COUNT, &m_cnt_ptr, &m_cnt_len);
    size_t count = 0;
    if (m_cnt_ptr && m_cnt_len == 2) {
        count = ((size_t)m_cnt_ptr[0] << 8) | (size_t)m_cnt_ptr[1];
    }

    if (count == 0) {
        return CLIP_OK;
    }

    ClipChannelMember* members = (ClipChannelMember*)calloc(count, sizeof(ClipChannelMember));
    if (!members) return CLIP_ERR_NOMEM;

    size_t offset = 0;
    size_t parsed = 0;
    while (offset + CLIP_TLV_HEADER_SIZE <= rx_len && parsed < count) {
        uint16_t tag = ((uint16_t)rx_payload[offset] << 8) | (uint16_t)rx_payload[offset + 1];
        uint16_t val_len = ((uint16_t)rx_payload[offset + 2] << 8) | (uint16_t)rx_payload[offset + 3];
        offset += CLIP_TLV_HEADER_SIZE;
        if (offset + val_len > rx_len) break;
        const uint8_t* val_ptr = rx_payload + offset;

        if (tag == CLIP_TAG_NODE_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(members[parsed].node_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
            members[parsed].presence = CLIP_PRESENCE_OFFLINE;
        } else if (tag == CLIP_TAG_DISPLAY_NAME && val_len > 0) {
            size_t copy_n = (val_len < sizeof(members[parsed].display_name) - 1) ? val_len : (sizeof(members[parsed].display_name) - 1);
            memcpy(members[parsed].display_name, val_ptr, copy_n);
            members[parsed].display_name[copy_n] = '\0';
        } else if (tag == CLIP_TAG_PRESENCE && val_len == 1) {
            members[parsed].presence = (ClipPresence)val_ptr[0];
            parsed++;
        }

        offset += val_len;
    }

    *out_members = members;
    *out_member_count = parsed;
    return CLIP_OK;
}

ClipError clip_client_send_conn_request(ClipClientNet*       net,
                                        const ClipUuid*      channel_uuid,
                                        const ClipUuid*      target_node_uuid,
                                        ClipUuid*            out_connection_uuid,
                                        ClipConnectionState* out_state)
{
    if (!net || !net->is_connected || !net->is_registered || !channel_uuid || !target_node_uuid) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[128];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len,
                   CLIP_TAG_CHANNEL_UUID, channel_uuid->bytes, CLIP_UUID_BYTES);
    clip_tlv_write(payload, sizeof(payload), &payload_len,
                   CLIP_TAG_TARGET_NODE_UUID, target_node_uuid->bytes, CLIP_UUID_BYTES);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_CONN_REQUEST, (uint32_t)payload_len, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[512];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_CONNECTION_RESPONSE ||
            rx_hdr.msg_type == CLIP_MSG_CONN_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_ERROR) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_CONN_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_CONNECTION_RESPONSE) {
        return CLIP_ERR_PROTO;
    }

    const uint8_t* c_ptr = NULL;
    uint16_t c_len = 0;
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_CONNECTION_UUID, &c_ptr, &c_len) == CLIP_OK && c_len == CLIP_UUID_BYTES) {
        if (out_connection_uuid) memcpy(out_connection_uuid->bytes, c_ptr, CLIP_UUID_BYTES);
    }

    const uint8_t* s_ptr = NULL;
    uint16_t s_len = 0;
    if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_CONNECTION_STATE, &s_ptr, &s_len) == CLIP_OK && s_len == 1) {
        if (out_state) *out_state = (ClipConnectionState)s_ptr[0];
    } else {
        if (out_state) *out_state = CLIP_CONN_STATE_REQUESTED;
    }

    return CLIP_OK;
}

ClipError clip_client_respond_conn(ClipClientNet*  net,
                                   const ClipUuid* connection_uuid,
                                   bool            accept)
{
    if (!net || !net->is_connected || !net->is_registered || !connection_uuid) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[64];
    size_t payload_len = 0;
    clip_tlv_write(payload, sizeof(payload), &payload_len,
                   CLIP_TAG_CONNECTION_UUID, connection_uuid->bytes, CLIP_UUID_BYTES);

    ClipMessageType mtype = accept ? CLIP_MSG_CONN_ACCEPT : CLIP_MSG_CONN_DECLINE;
    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, mtype, (uint32_t)payload_len, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[256];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_CONN_FAIL ||
            rx_hdr.msg_type == mtype ||
            rx_hdr.msg_type == CLIP_MSG_CONNECTION_RESPONSE) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_CONN_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != mtype && rx_hdr.msg_type != CLIP_MSG_CONNECTION_RESPONSE) {
        return CLIP_ERR_PROTO;
    }

    return CLIP_OK;
}

ClipError clip_client_list_connections(ClipClientNet*         net,
                                       ClipConnectionRecord** out_conns,
                                       size_t*                out_count)
{
    if (!net || !net->is_connected || !net->is_registered || !out_conns || !out_count) {
        return CLIP_ERR_INVALID;
    }

    *out_conns = NULL;
    *out_count = 0;

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_CONN_LIST_REQ, 0, ++net->seq_counter, NULL);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, NULL);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[4096];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_CONN_LIST_RESP ||
            rx_hdr.msg_type == CLIP_MSG_CONN_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_ERROR) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_CONN_FAIL) {
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | (uint16_t)err_ptr[1];
            return (ClipError)(-((int)code));
        }
        return CLIP_ERR_DENIED;
    }

    if (rx_hdr.msg_type != CLIP_MSG_CONN_LIST_RESP) {
        return CLIP_ERR_PROTO;
    }

    const uint8_t* cnt_ptr = NULL;
    uint16_t cnt_len = 0;
    clip_tlv_find(rx_payload, rx_len, CLIP_TAG_MEMBER_COUNT, &cnt_ptr, &cnt_len);
    size_t count = 0;
    if (cnt_ptr && cnt_len == 2) {
        count = ((size_t)cnt_ptr[0] << 8) | (size_t)cnt_ptr[1];
    }

    if (count == 0) return CLIP_OK;

    ClipConnectionRecord* arr = (ClipConnectionRecord*)calloc(count, sizeof(ClipConnectionRecord));
    if (!arr) return CLIP_ERR_NOMEM;

    size_t offset = 0;
    size_t parsed = 0;
    while (offset + CLIP_TLV_HEADER_SIZE <= rx_len && parsed < count) {
        uint16_t tag = ((uint16_t)rx_payload[offset] << 8) | (uint16_t)rx_payload[offset + 1];
        uint16_t val_len = ((uint16_t)rx_payload[offset + 2] << 8) | (uint16_t)rx_payload[offset + 3];
        offset += CLIP_TLV_HEADER_SIZE;
        if (offset + val_len > rx_len) break;
        const uint8_t* val_ptr = rx_payload + offset;

        if (tag == CLIP_TAG_CONNECTION_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(arr[parsed].connection_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
        } else if (tag == CLIP_TAG_CHANNEL_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(arr[parsed].channel_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
        } else if (tag == CLIP_TAG_NODE_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(arr[parsed].requester_node_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
        } else if (tag == CLIP_TAG_TARGET_NODE_UUID && val_len == CLIP_UUID_BYTES) {
            memcpy(arr[parsed].target_node_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
        } else if (tag == CLIP_TAG_CONNECTION_STATE && val_len == 1) {
            arr[parsed].state = (ClipConnectionState)val_ptr[0];
            parsed++;
        }

        offset += val_len;
    }

    *out_conns = arr;
    *out_count = parsed;
    return CLIP_OK;
}

void clip_client_free_connections(ClipConnectionRecord* conns)
{
    if (conns) free(conns);
}

/*
 * Phase 8 PTT / Floor Control Client APIs
 */

ClipError clip_client_ptt_request(ClipClientNet*   net,
                                  const ClipUuid*  session_uuid,
                                  uint32_t         lease_ms,
                                  ClipPttFloor*    out_floor,
                                  ClipError*       out_denial_reason)
{
    if (!net || !net->is_connected || !net->is_registered || !session_uuid) {
        return CLIP_ERR_INVALID;
    }

    if (out_denial_reason) *out_denial_reason = CLIP_OK;
    if (out_floor) {
        memset(out_floor, 0, sizeof(ClipPttFloor));
        out_floor->session_uuid = *session_uuid;
        clip_uuid_to_string(session_uuid, out_floor->session_uuid_str, sizeof(out_floor->session_uuid_str));
    }

    uint8_t payload[128];
    size_t offset = 0;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid->bytes, CLIP_UUID_BYTES);
    if (lease_ms > 0) {
        uint8_t lease_be[4] = {
            (uint8_t)((lease_ms >> 24) & 0xFF),
            (uint8_t)((lease_ms >> 16) & 0xFF),
            (uint8_t)((lease_ms >> 8) & 0xFF),
            (uint8_t)(lease_ms & 0xFF)
        };
        clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_LEASE_TIMEOUT_MS, lease_be, 4);
    }

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_PTT_REQUEST, (uint32_t)offset, ++net->seq_counter, session_uuid->bytes);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[1024];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_PTT_GRANT ||
            rx_hdr.msg_type == CLIP_MSG_PTT_DENY ||
            rx_hdr.msg_type == CLIP_MSG_SESSION_FAIL ||
            rx_hdr.msg_type == CLIP_MSG_ERROR ||
            rx_hdr.msg_type == CLIP_MSG_AUTH_FAIL) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_PTT_GRANT) {
        net->ptt_floor_held = true;
        net->ptt_remote_floor_held = false;
        if (out_floor) {
            out_floor->floor_state = CLIP_PTT_FLOOR_HELD;
            const uint8_t* h_ptr = NULL;
            uint16_t h_len = 0;
            if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_HOLDER_NODE_UUID, &h_ptr, &h_len) == CLIP_OK && h_len == CLIP_UUID_BYTES) {
                memcpy(out_floor->holder_node_uuid.bytes, h_ptr, CLIP_UUID_BYTES);
                clip_uuid_to_string(&out_floor->holder_node_uuid, out_floor->speaker_uuid_str, sizeof(out_floor->speaker_uuid_str));
            } else if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_NODE_UUID, &h_ptr, &h_len) == CLIP_OK && h_len == CLIP_UUID_BYTES) {
                memcpy(out_floor->holder_node_uuid.bytes, h_ptr, CLIP_UUID_BYTES);
                clip_uuid_to_string(&out_floor->holder_node_uuid, out_floor->speaker_uuid_str, sizeof(out_floor->speaker_uuid_str));
            }
            const uint8_t* ts_ptr = NULL;
            uint16_t ts_len = 0;
            if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_TIMESTAMP_MS, &ts_ptr, &ts_len) == CLIP_OK && ts_len == 8) {
                out_floor->acquired_at_ms = 0;
                for (int i = 0; i < 8; i++) out_floor->acquired_at_ms = (out_floor->acquired_at_ms << 8) | ts_ptr[i];
            }
            const uint8_t* l_ptr = NULL;
            uint16_t l_len = 0;
            if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_LEASE_TIMEOUT_MS, &l_ptr, &l_len) == CLIP_OK && l_len == 4) {
                out_floor->lease_timeout_ms = ((uint32_t)l_ptr[0] << 24) | ((uint32_t)l_ptr[1] << 16) | ((uint32_t)l_ptr[2] << 8) | (uint32_t)l_ptr[3];
            }
        }
        return CLIP_OK;
    } else if (rx_hdr.msg_type == CLIP_MSG_PTT_DENY) {
        ClipError reason = CLIP_ERR_PTT_BUSY;
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | err_ptr[1];
            reason = (ClipError)(-(int)code);
        }
        if (out_denial_reason) *out_denial_reason = reason;
        if (out_floor) {
            out_floor->floor_state = CLIP_PTT_FLOOR_HELD;
            const uint8_t* h_ptr = NULL;
            uint16_t h_len = 0;
            if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_HOLDER_NODE_UUID, &h_ptr, &h_len) == CLIP_OK && h_len == CLIP_UUID_BYTES) {
                memcpy(out_floor->holder_node_uuid.bytes, h_ptr, CLIP_UUID_BYTES);
                clip_uuid_to_string(&out_floor->holder_node_uuid, out_floor->speaker_uuid_str, sizeof(out_floor->speaker_uuid_str));
            } else if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_NODE_UUID, &h_ptr, &h_len) == CLIP_OK && h_len == CLIP_UUID_BYTES) {
                memcpy(out_floor->holder_node_uuid.bytes, h_ptr, CLIP_UUID_BYTES);
                clip_uuid_to_string(&out_floor->holder_node_uuid, out_floor->speaker_uuid_str, sizeof(out_floor->speaker_uuid_str));
            }
        }
        return reason;
    } else if (rx_hdr.msg_type == CLIP_MSG_SESSION_FAIL) {
        ClipError reason = CLIP_ERR_NO_SESSION;
        const uint8_t* err_ptr = NULL;
        uint16_t err_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_ERROR_CODE, &err_ptr, &err_len) == CLIP_OK && err_len == 2) {
            uint16_t code = ((uint16_t)err_ptr[0] << 8) | err_ptr[1];
            reason = (ClipError)(-(int)code);
        }
        if (out_denial_reason) *out_denial_reason = reason;
        return reason;
    }

    return CLIP_ERR_PROTO;
}

ClipError clip_client_ptt_release(ClipClientNet* net, const ClipUuid* session_uuid)
{
    if (!net || !net->is_connected || !net->is_registered || !session_uuid) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[64];
    size_t offset = 0;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid->bytes, CLIP_UUID_BYTES);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_PTT_RELEASE, (uint32_t)offset, ++net->seq_counter, session_uuid->bytes);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[256];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_PTT_FLOOR_RELEASED ||
            rx_hdr.msg_type == CLIP_MSG_PTT_RELEASE ||
            rx_hdr.msg_type == CLIP_MSG_PTT_DENY ||
            rx_hdr.msg_type == CLIP_MSG_ERROR) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_PTT_FLOOR_RELEASED || rx_hdr.msg_type == CLIP_MSG_PTT_RELEASE) {
        net->ptt_floor_held = false;
        net->ptt_remote_floor_held = false;
        return CLIP_OK;
    } else if (rx_hdr.msg_type == CLIP_MSG_PTT_DENY) {
        return CLIP_ERR_DENIED;
    }

    return CLIP_ERR_PROTO;
}

ClipError clip_client_ptt_status(ClipClientNet* net, const ClipUuid* session_uuid, ClipPttFloor* out_floor)
{
    if (!net || !net->is_connected || !net->is_registered || !session_uuid || !out_floor) {
        return CLIP_ERR_INVALID;
    }

    memset(out_floor, 0, sizeof(ClipPttFloor));
    out_floor->session_uuid = *session_uuid;
    clip_uuid_to_string(session_uuid, out_floor->session_uuid_str, sizeof(out_floor->session_uuid_str));

    uint8_t payload[64];
    size_t offset = 0;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid->bytes, CLIP_UUID_BYTES);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_PTT_FLOOR_STATUS_REQ, (uint32_t)offset, ++net->seq_counter, session_uuid->bytes);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[1024];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_PTT_FLOOR_STATUS_RESP ||
            rx_hdr.msg_type == CLIP_MSG_ERROR) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_PTT_FLOOR_STATUS_RESP) {
        const uint8_t* st_ptr = NULL;
        uint16_t st_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_FLOOR_STATE, &st_ptr, &st_len) == CLIP_OK && st_len == 1) {
            out_floor->floor_state = (ClipPttFloorState)st_ptr[0];
        }
        const uint8_t* h_ptr = NULL;
        uint16_t h_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_HOLDER_NODE_UUID, &h_ptr, &h_len) == CLIP_OK && h_len == CLIP_UUID_BYTES) {
            memcpy(out_floor->holder_node_uuid.bytes, h_ptr, CLIP_UUID_BYTES);
            clip_uuid_to_string(&out_floor->holder_node_uuid, out_floor->speaker_uuid_str, sizeof(out_floor->speaker_uuid_str));
        } else if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_NODE_UUID, &h_ptr, &h_len) == CLIP_OK && h_len == CLIP_UUID_BYTES) {
            memcpy(out_floor->holder_node_uuid.bytes, h_ptr, CLIP_UUID_BYTES);
            clip_uuid_to_string(&out_floor->holder_node_uuid, out_floor->speaker_uuid_str, sizeof(out_floor->speaker_uuid_str));
        }
        const uint8_t* ts_ptr = NULL;
        uint16_t ts_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_TIMESTAMP_MS, &ts_ptr, &ts_len) == CLIP_OK && ts_len == 8) {
            out_floor->acquired_at_ms = 0;
            for (int i = 0; i < 8; i++) out_floor->acquired_at_ms = (out_floor->acquired_at_ms << 8) | ts_ptr[i];
        }
        const uint8_t* l_ptr = NULL;
        uint16_t l_len = 0;
        if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_LEASE_TIMEOUT_MS, &l_ptr, &l_len) == CLIP_OK && l_len == 4) {
            out_floor->lease_timeout_ms = ((uint32_t)l_ptr[0] << 24) | ((uint32_t)l_ptr[1] << 16) | ((uint32_t)l_ptr[2] << 8) | (uint32_t)l_ptr[3];
        }
        return CLIP_OK;
    }

    return CLIP_ERR_PROTO;
}

ClipError clip_client_ptt_renew(ClipClientNet* net, const ClipUuid* session_uuid, uint32_t* out_remaining_lease_ms)
{
    if (!net || !net->is_connected || !net->is_registered || !session_uuid) {
        return CLIP_ERR_INVALID;
    }

    uint8_t payload[64];
    size_t offset = 0;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_SESSION_UUID, session_uuid->bytes, CLIP_UUID_BYTES);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_PTT_FLOOR_RENEW, (uint32_t)offset, ++net->seq_counter, session_uuid->bytes);

    ClipError send_err = clip_client_send_frame(net, &tx_hdr, payload);
    if (send_err != CLIP_OK) return send_err;

    ClipFrameHeader rx_hdr;
    uint8_t rx_payload[256];
    uint32_t rx_len = 0;
    ClipError recv_err = CLIP_OK;
    while (1) {
        recv_err = clip_client_recv_frame(net, &rx_hdr, rx_payload, sizeof(rx_payload), &rx_len, 5000);
        if (recv_err != CLIP_OK) return recv_err;
        if (rx_hdr.msg_type == CLIP_MSG_PTT_FLOOR_RENEW_ACK ||
            rx_hdr.msg_type == CLIP_MSG_ERROR) {
            break;
        }
    }

    if (rx_hdr.msg_type == CLIP_MSG_PTT_FLOOR_RENEW_ACK) {
        if (out_remaining_lease_ms) {
            const uint8_t* l_ptr = NULL;
            uint16_t l_len = 0;
            if (clip_tlv_find(rx_payload, rx_len, CLIP_TAG_LEASE_TIMEOUT_MS, &l_ptr, &l_len) == CLIP_OK && l_len == 4) {
                *out_remaining_lease_ms = ((uint32_t)l_ptr[0] << 24) | ((uint32_t)l_ptr[1] << 16) | ((uint32_t)l_ptr[2] << 8) | (uint32_t)l_ptr[3];
            } else {
                *out_remaining_lease_ms = CLIP_PTT_DEFAULT_LEASE_MS;
            }
        }
        return CLIP_OK;
    }

    return CLIP_ERR_PROTO;
}

/*
 * Phase 10: Real-Time Audio Transport Client APIs
 */


ClipError clip_client_set_codec(ClipClientNet* net, ClipCodecType codec_type)
{
    if (!net) return CLIP_ERR_INVALID;
    return clip_client_set_codec_params(net, codec_type,
                                        net->codec_sample_rate ? net->codec_sample_rate : 16000,
                                        net->codec_channels ? net->codec_channels : 1);
}

ClipError clip_client_set_codec_params(ClipClientNet* net, ClipCodecType codec_type, uint32_t sample_rate, uint8_t channels)
{
    if (!net) return CLIP_ERR_INVALID;
    if (codec_type != CLIP_CODEC_PCM && codec_type != CLIP_CODEC_OPUS) {
        return CLIP_ERR_CODEC_UNSUPPORTED;
    }
    net->codec_sample_rate = sample_rate ? sample_rate : 16000;
    net->codec_channels = channels ? channels : 1;
    if (net->codec_encoder) {
        codec_destroy(net->codec_encoder);
        net->codec_encoder = NULL;
    }
    if (net->codec_decoder) {
        codec_destroy(net->codec_decoder);
        net->codec_decoder = NULL;
    }
    net->selected_codec = codec_type;
    net->codec_encoder = codec_create(codec_type, net->codec_sample_rate, net->codec_channels);
    net->codec_decoder = codec_create(codec_type, net->codec_sample_rate, net->codec_channels);
    if (!net->codec_encoder || !net->codec_decoder) {
        return CLIP_ERR_CODEC_INIT;
    }
    return CLIP_OK;
}

ClipError clip_client_send_audio_frame(ClipClientNet*  net,
                                       const ClipUuid* session_uuid,
                                       uint64_t        timestamp_ms,
                                       const int16_t*  pcm,
                                       size_t          sample_count)
{
    if (!net || !net->is_connected || !net->is_registered || !session_uuid || !pcm || sample_count == 0) {
        return CLIP_ERR_INVALID;
    }
    if (clip_uuid_is_zero(session_uuid)) {
        return CLIP_ERR_NO_SESSION;
    }
    if (sample_count * sizeof(int16_t) > CLIP_AUDIO_MAX_PAYLOAD_BYTES) {
        return CLIP_ERR_AUDIO_OVERSIZED;
    }

    uint8_t frame_buf[CLIP_AUDIO_MAX_FRAME_WIRE_SIZE];
    size_t frame_len = 0;
    ClipError b_err = CLIP_OK;

    if (net->selected_codec == CLIP_CODEC_OPUS) {
        if (!net->codec_encoder) {
            uint32_t sr = net->codec_sample_rate ? net->codec_sample_rate : 16000;
            uint8_t ch = net->codec_channels ? net->codec_channels : 1;
            net->codec_encoder = codec_create(CLIP_CODEC_OPUS, sr, ch);
            if (!net->codec_encoder) return CLIP_ERR_CODEC_INIT;
        }
        uint8_t opus_buf[1275];
        int enc_bytes = codec_encode(net->codec_encoder, pcm, sample_count, opus_buf, sizeof(opus_buf));
        if (enc_bytes < 0) return CLIP_ERR_CODEC_ENCODE;

        b_err = clip_audio_frame_build_raw(frame_buf, sizeof(frame_buf), &frame_len,
                                           session_uuid, ++net->seq_counter,
                                           (uint8_t)CLIP_CODEC_OPUS, timestamp_ms,
                                           opus_buf, (size_t)enc_bytes);
    } else {
        b_err = clip_audio_frame_build(frame_buf, sizeof(frame_buf), &frame_len,
                                       session_uuid, ++net->seq_counter,
                                       (uint8_t)CLIP_CODEC_PCM, timestamp_ms,
                                       pcm, sample_count);
    }
    if (b_err != CLIP_OK) return b_err;

    ClipError send_err = CLIP_OK;
    client_send_lock();
    if (net->transport) {
        send_err = clip_transport_write(net->transport, frame_buf, frame_len);
    } else {
        send_err = clip_net_send_all(net->sock, frame_buf, frame_len);
    }
    client_send_unlock();
    return send_err;
}

void clip_client_set_audio_recv_callback(ClipClientNet* net,
                                         void (*cb)(const ClipUuid* session_uuid,
                                                    uint64_t timestamp_ms,
                                                    const int16_t* pcm,
                                                    size_t sample_count,
                                                    void* user_data),
                                         void* user_data)
{
    if (!net) return;
    net->audio_recv_cb = cb;
    net->audio_recv_user_data = user_data;
}

ClipError clip_client_recv_audio_frame(ClipClientNet* net,
                                       ClipUuid*       out_session_uuid,
                                       uint64_t*       out_timestamp_ms,
                                       int16_t*        out_pcm,
                                       size_t          max_samples,
                                       size_t*         out_sample_count,
                                       int             timeout_ms)
{
    if (!net || !out_pcm || max_samples == 0 || !out_sample_count) {
        return CLIP_ERR_INVALID;
    }

    ClipFrameHeader rx_hdr;
    uint8_t payload[CLIP_MAX_FRAME_SIZE];
    uint32_t payload_len = 0;

    uint64_t start_tick = GetTickCount64();

    while (true) {
        int remaining_ms = timeout_ms;
        if (timeout_ms >= 0) {
            uint64_t elapsed = GetTickCount64() - start_tick;
            if (elapsed >= (uint64_t)timeout_ms) {
                return CLIP_ERR_TIMEOUT;
            }
            remaining_ms = timeout_ms - (int)elapsed;
        }

        ClipError err = clip_client_recv_frame(net, &rx_hdr, payload, sizeof(payload), &payload_len, remaining_ms);
        if (err != CLIP_OK) return err;

        if (rx_hdr.msg_type == CLIP_MSG_AUDIO_FRAME) {
            break;
        }
        /* Non-audio control frame (e.g. PTT_NOTIFY, SESSION notification); continue waiting */
    }

    if (out_session_uuid) {
        memcpy(out_session_uuid->bytes, rx_hdr.session_uuid, CLIP_UUID_BYTES);
    }

    uint8_t codec = 0;
    uint64_t ts = 0;
    const uint8_t* raw_audio = NULL;
    size_t raw_len = 0;
    ClipError parse_err = clip_audio_frame_parse_raw(payload, payload_len, &codec, &ts, &raw_audio, &raw_len);
    if (parse_err != CLIP_OK) return parse_err;

    if (out_timestamp_ms) *out_timestamp_ms = ts;

    size_t decoded_samples = 0;
    if (codec == CLIP_CODEC_PCM) {
        if ((raw_len % sizeof(int16_t)) != 0) {
            return CLIP_ERR_PROTO;
        }
        size_t samples = raw_len / sizeof(int16_t);
        size_t copy_samples = (samples < max_samples) ? samples : max_samples;
        memcpy(out_pcm, raw_audio, copy_samples * sizeof(int16_t));
        decoded_samples = copy_samples;
    } else if (codec == CLIP_CODEC_OPUS) {
        if (!net->codec_decoder) {
            uint32_t sr = net->codec_sample_rate ? net->codec_sample_rate : 16000;
            uint8_t ch = net->codec_channels ? net->codec_channels : 1;
            net->codec_decoder = codec_create(CLIP_CODEC_OPUS, sr, ch);
            if (!net->codec_decoder) return CLIP_ERR_CODEC_INIT;
        }
        int dec = codec_decode(net->codec_decoder, raw_audio, raw_len, out_pcm, max_samples);
        if (dec < 0) return CLIP_ERR_CODEC_DECODE;
        decoded_samples = (size_t)dec;
    } else {
        return CLIP_ERR_CODEC_UNSUPPORTED;
    }

    *out_sample_count = decoded_samples;

    if (net->audio_recv_cb) {
        ClipUuid sess;
        memcpy(sess.bytes, rx_hdr.session_uuid, CLIP_UUID_BYTES);
        net->audio_recv_cb(&sess, ts, out_pcm, decoded_samples, net->audio_recv_user_data);
    }

    if (net->speech_analyzer && net->session_speech_mode != CLIP_SPEECH_MODE_NONE && decoded_samples > 0) {
        ClipUuid sess;
        memcpy(sess.bytes, rx_hdr.session_uuid, CLIP_UUID_BYTES);
        speech_analyzer_feed_pcm(net->speech_analyzer, &sess, &sess, ts, out_pcm, decoded_samples);
    }

    return CLIP_OK;
}

void clip_client_set_speech_analyzer(ClipClientNet* net, struct SpeechAnalyzer* sa)
{
    if (!net) return;
    net->speech_analyzer = sa;
}

ClipSpeechMode clip_client_get_speech_mode(const ClipClientNet* net)
{
    if (!net) return CLIP_SPEECH_MODE_NONE;
    return net->session_speech_mode;
}


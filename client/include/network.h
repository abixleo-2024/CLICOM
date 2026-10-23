/*
 * network.h — CLICOM Client TCP Networking Layer (Phase 2)
 *
 * Implements TCP connection, frame transmission, and frame reception.
 */

#ifndef CLICOM_CLIENT_NETWORK_H
#define CLICOM_CLIENT_NETWORK_H

#include "codec.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_net.h"
#include "clip_types.h"
#include "clip_protocol.h"
#include "clip_crypto.h"
#include "clip_transport.h"
#include "clip_telemetry.h"

typedef struct ClipClientNet ClipClientNet;

struct ClipClientNet {
    clip_socket_t sock;
    clip_transport_t* transport;
    clip_tls_client_config_t tls_cfg;
    bool          use_tls;
    char          host[64];
    uint16_t      port;
    bool          is_connected;
    bool          is_registered;
    char          display_name[CLIP_DISPLAY_NAME_MAX];
    uint8_t       assigned_uuid[CLIP_UUID_BYTES];
    uint64_t      seq_counter;

    /* Receive buffer for incoming frame accumulation */
    uint8_t       rx_buf[CLIP_MAX_FRAME_SIZE];
    size_t        rx_len;

    /* Phase 17 Heartbeat & Disconnect Lifecycle */
    uint64_t      last_traffic_sent_ms;
    uint64_t      last_heartbeat_sent_ms;
    uint64_t      last_heartbeat_ack_ms;
    uint32_t      missed_heartbeats;
    bool          heartbeat_in_flight;
    uint64_t      mock_now_ms;            /* Mock clock for deterministic tests (0 = real time) */
    ClipTelemetryTracker telemetry;       /* Real validated telemetry tracker */

    /* Phase 17 Stage 5: Reconnection & Recovery State Machine */
    uint32_t      reconnect_attempts;
    uint32_t      backoff_delay_sec;      /* 1, 2, 4, 8, 16, capped at 30 */
    uint64_t      next_reconnect_time_ms;
    bool          reconnect_enabled;
    bool          reconnect_in_progress;
    bool          shutdown_requested;
    uint32_t      conn_epoch;             /* Increments on every new connection; rejects stale callbacks/frames */
    ClipUuid      saved_node_uuid;
    uint8_t       saved_credential[CLIP_CREDENTIAL_BYTES];
    bool          has_saved_credentials;
    ClipUuid      current_session_uuid;   /* Cleared on disconnect/reconnect; never resumed automatically */
    bool          session_valid;
    bool          ptt_floor_held;         /* PTT floor is never automatically resumed */
    bool          ptt_remote_floor_held;  /* Floor held by any member on server */
    uint8_t       ptt_holder_uuid[CLIP_UUID_BYTES];
    bool          mic_capture_active;     /* Microphone capture stopped until explicit user action */

    void (*disconnect_cb)(ClipClientNet* net, void* user_data);
    void*         disconnect_user_data;

    /* Reconnection Initial State Synchronization Callback (Phase 17 Stage 5) */
    ClipError (*sync_cb)(ClipClientNet* net, void* user_data);
    void*         sync_user_data;

    /* Audio receive callback (Phase 10) */
    void (*audio_recv_cb)(const ClipUuid* session_uuid,
                          uint64_t timestamp_ms,
                          const int16_t* pcm,
                          size_t sample_count,
                          void* user_data);
    void* audio_recv_user_data;

    /* Codec configuration (Phase 11) */
    ClipCodecType selected_codec;
    uint32_t      codec_sample_rate;
    uint8_t       codec_channels;
    AudioCodec*   codec_encoder;
    AudioCodec*   codec_decoder;

    /* Speech Analysis (Phase 12) */
    struct SpeechAnalyzer* speech_analyzer;
    ClipSpeechMode         session_speech_mode;
};

/* ── Client Network API ─────────────────────────────────────────────────── */

/* Initialize client network state */
ClipError clip_client_net_init(ClipClientNet* net);

/* Connect to remote CLICOM server */
ClipError clip_client_connect(ClipClientNet* net, const char* host, uint16_t port);

/* Encode and send a protocol frame using reliable send-all */
ClipError clip_client_send_frame(ClipClientNet*         net,
                                 const ClipFrameHeader* hdr,
                                 const uint8_t*         payload);

/*
 * Receive and decode a complete protocol frame:
 * - Accumulates bytes from TCP socket
 * - Waits up to timeout_ms
 * - Decodes and validates frame using Phase 1 decoder
 */
ClipError clip_client_recv_frame(ClipClientNet*   net,
                                 ClipFrameHeader* out_hdr,
                                 uint8_t*         out_payload_buf,
                                 size_t           out_payload_max,
                                 uint32_t*        out_payload_len,
                                 int              timeout_ms);

/*
 * High-level registration handshake (REGISTER -> REGISTER_ACK):
 * Transmits REGISTER frame with display_name, receives assigned UUID and credential.
 */
ClipError clip_client_register(ClipClientNet* net,
                               const char*    display_name,
                               ClipUuid*      out_uuid,
                               uint8_t        out_credential[CLIP_CREDENTIAL_BYTES]);

/*
 * High-level authentication handshake (AUTH -> AUTH_OK / AUTH_FAIL):
 * Transmits stored UUID and credential, verifies AUTH_OK response.
 */
ClipError clip_client_authenticate(ClipClientNet*   net,
                                   const ClipUuid*  uuid,
                                   const uint8_t    credential[CLIP_CREDENTIAL_BYTES],
                                   char*            out_display_name,
                                   size_t           name_buf_len);

/* Disconnect from server cleanly */
void clip_client_disconnect(ClipClientNet* net);

/* Clean up network resources */
void clip_client_net_cleanup(ClipClientNet* net);

/* Phase 17 Heartbeat & Disconnect APIs */
ClipError clip_client_send_heartbeat(ClipClientNet* net);
ClipError clip_client_poll_heartbeat(ClipClientNet* net, uint64_t now_ms);
ClipError clip_client_pump_events(ClipClientNet* net, int timeout_ms);
void clip_client_set_disconnect_callback(ClipClientNet* net,
                                              void (*cb)(ClipClientNet* net, void* user_data),
                                              void* user_data);

/* Phase 17 Stage 5: Safe Reconnection & Backoff APIs */
void      clip_client_reconnect_enable(ClipClientNet* net, bool enable);
void      clip_client_reconnect_set_credentials(ClipClientNet* net,
                                                const ClipUuid* uuid,
                                                const uint8_t credential[CLIP_CREDENTIAL_BYTES]);
uint32_t  clip_client_reconnect_get_next_backoff_sec(uint32_t attempt_index);
ClipError clip_client_reconnect_poll(ClipClientNet* net, uint64_t now_ms);
ClipError clip_client_reconnect_trigger(ClipClientNet* net, uint64_t now_ms);
void      clip_client_reconnect_reset_backoff(ClipClientNet* net);
void      clip_client_request_shutdown(ClipClientNet* net);
void      clip_client_reconnect_set_sync_callback(ClipClientNet* net,
                                                  ClipError (*cb)(ClipClientNet* net, void* user_data),
                                                  void* user_data);
ClipError clip_client_reconnect_synchronize(ClipClientNet* net);

/*
 * Phase 4 Channel & Session Client APIs
 */

/* Create a new channel on the server (default limit 16) */
ClipError clip_client_channel_create(ClipClientNet* net,
                                     const char*    channel_name,
                                     ClipUuid*      out_channel_uuid,
                                     char*          out_join_key,
                                     size_t         join_key_buf_len);

/* Create a new channel with explicit participant capacity limit */
ClipError clip_client_channel_create_with_limit(ClipClientNet* net,
                                                const char*    channel_name,
                                                uint16_t       member_limit,
                                                ClipUuid*      out_channel_uuid,
                                                char*          out_join_key,
                                                size_t         join_key_buf_len);

/* Leave an active channel */
ClipError clip_client_channel_leave(ClipClientNet*  net,
                                    const ClipUuid* channel_uuid);

/* Revoke the join key of a channel (owner-only) */
ClipError clip_client_channel_revoke_key(ClipClientNet*  net,
                                         const ClipUuid* channel_uuid);

/* Close/destroy a channel on the server (owner-only) */
ClipError clip_client_channel_close(ClipClientNet*  net,
                                    const ClipUuid* channel_uuid);

/* Join an existing channel using its join_key */
ClipError clip_client_channel_join(ClipClientNet*      net,
                                   const char*         join_key,
                                   ClipUuid*           out_channel_uuid,
                                   char*               out_channel_name,
                                   size_t              name_buf_len,
                                   ClipChannelMember** out_members,
                                   size_t*             out_member_count);

/* Free member list returned by clip_client_channel_join */
void clip_client_free_members(ClipChannelMember* members);

/* List channels for current node */
ClipError clip_client_channel_list(ClipClientNet*    net,
                                   ClipChannelInfo** out_channels,
                                   size_t*           out_channel_count);

/* Free channel list returned by clip_client_channel_list */
void clip_client_free_channels(ClipChannelInfo* channels);

/* Start a communication session within a channel (Phase 4 fallback) */
ClipError clip_client_session_start(ClipClientNet*  net,
                                    const ClipUuid* channel_uuid,
                                    ClipUuid*       out_session_uuid);

/*
 * Phase 6: Start a communication session bound to an ACCEPTED connection:
 * - Sends SESSION_START frame referencing connection_uuid (header.session_uuid == 0)
 * - Receives SESSION_START_ACK (header.session_uuid == genuine_session_uuid != 0)
 */
ClipError clip_client_session_start_by_conn(ClipClientNet*  net,
                                            const ClipUuid* conn_uuid,
                                            ClipUuid*       out_session_uuid);

/* End an active communication session */
ClipError clip_client_session_end(ClipClientNet*  net,
                                  const ClipUuid* session_uuid);

/*
 * Phase 5 Online Node Discovery & Connection Request Client APIs
 */

/* Query channel members and presence from server */
ClipError clip_client_get_channel_members(ClipClientNet*      net,
                                          const ClipUuid*     channel_uuid,
                                          ClipChannelMember** out_members,
                                          size_t*             out_member_count);

/* Send connection request to a channel member */
ClipError clip_client_send_conn_request(ClipClientNet*       net,
                                        const ClipUuid*      channel_uuid,
                                        const ClipUuid*      target_node_uuid,
                                        ClipUuid*            out_connection_uuid,
                                        ClipConnectionState* out_state);

/* Respond to an incoming connection request (accept or decline) */
ClipError clip_client_respond_conn(ClipClientNet*  net,
                                   const ClipUuid* connection_uuid,
                                   bool            accept);

/* List connections involving current node */
ClipError clip_client_list_connections(ClipClientNet*         net,
                                       ClipConnectionRecord** out_conns,
                                       size_t*                out_count);

/* Free connection list returned by clip_client_list_connections */
void clip_client_free_connections(ClipConnectionRecord* conns);

/* Set TLS configuration for client (pass NULL to disable TLS for legacy testing) */
void clip_client_net_set_tls_config(ClipClientNet* net, const clip_tls_client_config_t* cfg);

/* Explicit development/test opt-in for unencrypted plaintext mode */
void clip_client_net_set_insecure_plaintext(ClipClientNet* net);

/*
 * Phase 8 PTT / Floor Control Client APIs
 */

/* Request floor for an active communication session */
ClipError clip_client_ptt_request(ClipClientNet*   net,
                                  const ClipUuid*  session_uuid,
                                  uint32_t         lease_ms,
                                  ClipPttFloor*    out_floor,
                                  ClipError*       out_denial_reason);

/* Release floor for an active communication session */
ClipError clip_client_ptt_release(ClipClientNet*  net,
                                  const ClipUuid* session_uuid);

/* Query current floor status */
ClipError clip_client_ptt_status(ClipClientNet*  net,
                                 const ClipUuid* session_uuid,
                                 ClipPttFloor*   out_floor);

/* Query current floor status */
ClipError clip_client_get_floor_status(const ClipClientNet* net,
                                       bool*                out_floor_held,
                                       bool*                out_held_by_me,
                                       ClipUuid*            out_holder_uuid);

/* Renew lease for held floor */
ClipError clip_client_ptt_renew(ClipClientNet*  net,
                                const ClipUuid* session_uuid,
                                uint32_t*       out_remaining_lease_ms);

/*
 * Phase 10: Real-Time Audio Transport Client APIs
 */

/* Transmit audio frame over TLS 1.3 socket */
ClipError clip_client_send_audio_frame(ClipClientNet*  net,
                                       const ClipUuid* session_uuid,
                                       uint64_t        timestamp_ms,
                                       const int16_t*  pcm,
                                       size_t          sample_count);

/* Register audio frame receive callback */
void clip_client_set_audio_recv_callback(ClipClientNet* net,
                                         void (*cb)(const ClipUuid* session_uuid,
                                                    uint64_t timestamp_ms,
                                                    const int16_t* pcm,
                                                    size_t sample_count,
                                                    void* user_data),
                                         void* user_data);

/* Poll and receive audio frame with timeout (used in testing or blocking loop) */

/* Configure client audio codec (Phase 11) */
ClipError clip_client_set_codec(ClipClientNet* net, ClipCodecType codec_type);
ClipError clip_client_set_codec_params(ClipClientNet* net, ClipCodecType codec_type, uint32_t sample_rate, uint8_t channels);

ClipError clip_client_recv_audio_frame(ClipClientNet* net,
                                       ClipUuid*       out_session_uuid,
                                       uint64_t*       out_timestamp_ms,
                                       int16_t*        out_pcm,
                                       size_t          max_samples,
                                       size_t*         out_sample_count,
                                       int             timeout_ms);

/* Speech Analysis Client APIs (Phase 12) */
void           clip_client_set_speech_analyzer(ClipClientNet* net, struct SpeechAnalyzer* sa);
ClipSpeechMode clip_client_get_speech_mode(const ClipClientNet* net);

#endif /* CLICOM_CLIENT_NETWORK_H */

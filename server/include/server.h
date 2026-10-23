/*
 * server.h — CLICOM TCP Server (Phase 2 Networking Layer)
 *
 * Implements real non-blocking select()-multiplexed TCP server,
 * client connection handling, and frame accumulation.
 */

#ifndef CLICOM_SERVER_H
#define CLICOM_SERVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_net.h"
#include "clip_types.h"
#include "clip_protocol.h"
#include "clients.h"
#include "clip_identity.h"
#include "clip_transport.h"
#include "clip_ptt.h"
#include "clip_audio_seq.h"
#include "security_rules.h"
#include "security_analyzer.h"
#include "clip_security_db.h"

typedef struct {
    char     bind_host[64];
    uint16_t port;
    size_t   max_clients;
    char     db_path[256];
    bool     use_tls;
    char     cert_file[256];
    char     key_file[256];
    char     ca_file[256];
    uint8_t  speech_mode;
    char     rules_file[256];
} ClipServerConfig;

#include "clip_rate_limit.h"

typedef struct {
    ClipServerConfig config;
    clip_socket_t    listen_sock;
    clip_transport_t* server_trans;
    ClipClientTable  clients;
    ClipIdentityDb*  identity_db;
    ClipPttManager   ptt_mgr;
    ClipAudioSeqTracker audio_seq_tracker;
    SecurityRuleSet* security_rules;
    SecurityAnalyzer* security_analyzer;
    bool             is_running;
    uint64_t         total_frames_received;
    uint64_t         total_frames_sent;
    uint64_t         total_audio_frames_relayed;
    uint64_t         dropped_audio_frames;

    /* Phase 17 Stage 4: Authentication Rate Limiter */
    ClipRateLimiter  rate_limiter;

    /* Phase 17 Mock Clock (0 = use real system time) */
    uint64_t         mock_now_ms;
} ClipServer;

/* ── Server API ─────────────────────────────────────────────────────────── */

/* Initialize a server configuration structure with production defaults (TLS 1.3 enabled) */
void clip_server_config_init_default(ClipServerConfig* cfg);

/* Initialize server structure with configuration defaults or provided settings */
ClipError clip_server_init(ClipServer* srv, const ClipServerConfig* config);

/* Bind to configured address and start listening */
ClipError clip_server_start(ClipServer* srv);

/*
 * Poll one iteration using select():
 * - Accepts new incoming connections
 * - Receives bytes on connected client sockets
 * - Accumulates frames, validates with Phase 1 decoder
 * - Dispatches handshake responses (REGISTER -> REGISTER_ACK)
 * - Detects client disconnects
 *
 * timeout_ms: maximum time to wait for network activity (0 = immediate non-blocking)
 */
ClipError clip_server_poll(ClipServer* srv, int timeout_ms);

/* Stop listening and close all client connections */
void clip_server_stop(ClipServer* srv);

/* Clean up server and client resources */
void clip_server_cleanup(ClipServer* srv);

/* Run server event loop until *stop_flag becomes true */
ClipError clip_server_run(ClipServer* srv, const volatile bool* stop_flag);

#endif /* CLICOM_SERVER_H */

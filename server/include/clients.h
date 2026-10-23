/*
 * clients.h — CLICOM Server Client Connection Tracking (Phase 2 Transport)
 *
 * Tracks connected TCP sockets and maintains per-client frame accumulation buffers.
 * Bounded client table for Phase 2; designed to be extensible for Phase 3+.
 */

#ifndef CLICOM_SERVER_CLIENTS_H
#define CLICOM_SERVER_CLIENTS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_net.h"
#include "clip_types.h"
#include "clip_protocol.h"
#include "clip_transport.h"

#define CLIP_MAX_CLIENTS_DEFAULT 64

/* Authentication state machine per connection */
typedef enum {
    CLIP_AUTH_STATE_UNAUTHENTICATED = 0,
    CLIP_AUTH_STATE_REGISTERING     = 1,
    CLIP_AUTH_STATE_AUTHENTICATED   = 2,
    CLIP_AUTH_STATE_REVOKED         = 3,
    CLIP_AUTH_STATE_FAILED          = 4
} ClipAuthState;

/* Per-client connection context */
typedef struct {
    clip_socket_t   sock;
    clip_transport_t *transport;
    bool            tls_established;
    char            ip_str[64];
    uint16_t        port;
    bool            active;
    bool            registered;
    ClipAuthState   auth_state;
    char            display_name[CLIP_DISPLAY_NAME_MAX];
    uint8_t         node_uuid[CLIP_UUID_BYTES];
    uint64_t        connected_at_ms;
    uint64_t        last_seen_ms;

    /* Phase 17 Heartbeat Lifecycle */
    uint64_t        last_heartbeat_sent_ms;
    uint64_t        last_heartbeat_ack_ms;
    uint32_t        missed_heartbeats;
    bool            heartbeat_in_flight;

    /* Phase 16 Sanctions */
    bool            is_restricted;

    /* Phase 16 Admin Session Context (Strictly separate from node auth) */
    bool            is_admin_authenticated;
    uint8_t         admin_uuid[CLIP_UUID_BYTES];
    char            admin_username[64];
    ClipAdminPermission admin_role;

    /* Frame accumulation receive buffer */
    uint8_t         rx_buf[CLIP_MAX_FRAME_SIZE];
    size_t          rx_len;
} ClipClientConn;

/* Client table structure */
typedef struct {
    ClipClientConn* clients;
    size_t          capacity;
    size_t          count;
} ClipClientTable;

/* ── Lifecycle & Management ─────────────────────────────────────────────── */

ClipError clip_client_table_init(ClipClientTable* table, size_t max_clients);
void      clip_client_table_cleanup(ClipClientTable* table);

ClipClientConn* clip_client_table_add(ClipClientTable* table,
                                      clip_socket_t    sock,
                                      const char*      ip,
                                      uint16_t         port);

void            clip_client_table_remove(ClipClientTable* table,
                                         clip_socket_t    sock);

ClipClientConn* clip_client_table_find(ClipClientTable* table,
                                       clip_socket_t    sock);

ClipClientConn* clip_client_table_find_by_node_uuid(ClipClientTable* table,
                                                   const ClipUuid*  node_uuid);

size_t          clip_client_table_count(const ClipClientTable* table);

#endif /* CLICOM_SERVER_CLIENTS_H */

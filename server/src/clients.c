/*
 * clients.c — CLICOM Server Client Connection Tracking Implementation
 */

#include "clients.h"
#include "clip_log.h"
#include <stdlib.h>
#include <string.h>

ClipError clip_client_table_init(ClipClientTable* table, size_t max_clients)
{
    if (!table) return CLIP_ERR_INVALID;

    size_t cap = (max_clients > 0) ? max_clients : CLIP_MAX_CLIENTS_DEFAULT;
    table->clients = (ClipClientConn*)calloc(cap, sizeof(ClipClientConn));
    if (!table->clients) {
        return CLIP_ERR_NOMEM;
    }

    table->capacity = cap;
    table->count = 0;

    for (size_t i = 0; i < cap; i++) {
        table->clients[i].sock = CLIP_INVALID_SOCKET;
        table->clients[i].active = false;
        table->clients[i].rx_len = 0;
    }

    return CLIP_OK;
}

void clip_client_table_cleanup(ClipClientTable* table)
{
    if (!table || !table->clients) return;

    for (size_t i = 0; i < table->capacity; i++) {
        if (table->clients[i].active) {
            if (table->clients[i].transport) {
                clip_transport_free(table->clients[i].transport);
                table->clients[i].transport = NULL;
                table->clients[i].sock = CLIP_INVALID_SOCKET;
            } else {
                clip_net_close_socket(&table->clients[i].sock);
            }
            table->clients[i].active = false;
        }
    }

    free(table->clients);
    table->clients = NULL;
    table->capacity = 0;
    table->count = 0;
}

ClipClientConn* clip_client_table_add(ClipClientTable* table,
                                      clip_socket_t    sock,
                                      const char*      ip,
                                      uint16_t         port)
{
    if (!table || !table->clients || sock == CLIP_INVALID_SOCKET) {
        return NULL;
    }

    for (size_t i = 0; i < table->capacity; i++) {
        if (!table->clients[i].active) {
            ClipClientConn* c = &table->clients[i];
            memset(c, 0, sizeof(ClipClientConn));
            c->sock = sock;
            if (ip) {
                strncpy(c->ip_str, ip, sizeof(c->ip_str) - 1);
            }
            c->port = port;
            c->active = true;
            c->registered = false;
            c->auth_state = CLIP_AUTH_STATE_UNAUTHENTICATED;
            c->rx_len = 0;
            table->count++;
            return c;
        }
    }

    return NULL; /* Table is full */
}

void clip_client_table_remove(ClipClientTable* table, clip_socket_t sock)
{
    if (!table || !table->clients || sock == CLIP_INVALID_SOCKET) {
        return;
    }

    for (size_t i = 0; i < table->capacity; i++) {
        if (table->clients[i].active && table->clients[i].sock == sock) {
            if (table->clients[i].transport) {
                clip_transport_free(table->clients[i].transport);
                table->clients[i].transport = NULL;
                table->clients[i].sock = CLIP_INVALID_SOCKET;
            } else {
                clip_net_close_socket(&table->clients[i].sock);
            }
            table->clients[i].active = false;
            table->clients[i].rx_len = 0;
            if (table->count > 0) {
                table->count--;
            }
            return;
        }
    }
}

ClipClientConn* clip_client_table_find(ClipClientTable* table, clip_socket_t sock)
{
    if (!table || !table->clients || sock == CLIP_INVALID_SOCKET) {
        return NULL;
    }

    for (size_t i = 0; i < table->capacity; i++) {
        if (table->clients[i].active && table->clients[i].sock == sock) {
            return &table->clients[i];
        }
    }
    return NULL;
}

ClipClientConn* clip_client_table_find_by_node_uuid(ClipClientTable* table, const ClipUuid* node_uuid)
{
    if (!table || !table->clients || !node_uuid || clip_uuid_is_zero(node_uuid)) {
        return NULL;
    }

    for (size_t i = 0; i < table->capacity; i++) {
        if (table->clients[i].active &&
            table->clients[i].auth_state == CLIP_AUTH_STATE_AUTHENTICATED &&
            clip_uuid_equal((const ClipUuid*)table->clients[i].node_uuid, node_uuid)) {
            return &table->clients[i];
        }
    }
    return NULL;
}

size_t clip_client_table_count(const ClipClientTable* table)
{
    return table ? table->count : 0;
}

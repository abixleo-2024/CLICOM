/*
 * clip_transport.h — CLICOM Transport & TLS 1.3 Abstraction Layer
 *
 * Provides a clean abstraction separating transport confidentiality,
 * certificate verification, and framing from application protocol logic.
 */

#ifndef CLIP_TRANSPORT_H
#define CLIP_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_errors.h"
#include "clip_net.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct clip_transport clip_transport_t;

/* Server TLS Configuration */
typedef struct {
    const char *cert_file;      /* Server certificate file path (PEM) */
    const char *key_file;       /* Server private key file path (PEM) */
    const char *ca_file;        /* Optional client CA for mTLS (PEM) */
    bool require_client_cert;   /* If true, require client mTLS cert */
} clip_tls_server_config_t;

/* Client TLS Configuration */
typedef struct {
    const char *ca_file;        /* Trusted root CA certificate (PEM) */
    const char *expected_host;  /* Expected server hostname (SNI / SAN verification) */
    const char *client_cert;    /* Optional client certificate for mTLS */
    const char *client_key;     /* Optional client private key for mTLS */
    bool insecure_skip_verify;  /* Explicitly false; trust-all callbacks forbidden */
} clip_tls_client_config_t;

/* ── Transport Lifecycle ────────────────────────────────────────────────── */

/* Creates a TLS server listening context abstraction */
ClipError clip_transport_create_server(const clip_tls_server_config_t *config,
                                       clip_transport_t **out_trans);

/* Creates a TLS client endpoint abstraction */
ClipError clip_transport_create_client(const clip_tls_client_config_t *config,
                                       clip_transport_t **out_trans);

/* Establishes TCP connection, validates server certificate, and negotiates TLS 1.3 */
ClipError clip_transport_connect(clip_transport_t *trans, const char *host, uint16_t port);

/* Wraps accepted TCP client socket, performs TLS 1.3 server handshake */
ClipError clip_transport_accept(clip_transport_t *server_trans,
                                clip_socket_t client_sock,
                                clip_transport_t **out_client_trans);

/* ── Encrypted I/O ──────────────────────────────────────────────────────── */

/* Reads decrypted application data from TLS stream */
ClipError clip_transport_read(clip_transport_t *trans, void *buf, size_t count, size_t *out_read);

/* Reliably encrypts and sends all 'count' bytes over TLS stream */
ClipError clip_transport_write(clip_transport_t *trans, const void *buf, size_t count);

/* ── Teardown & Inspection ──────────────────────────────────────────────── */

/* Sends TLS close_notify and shuts down socket */
void clip_transport_shutdown(clip_transport_t *trans);

/* Frees transport resources */
void clip_transport_free(clip_transport_t *trans);

/* Inspect underlying socket descriptor */
clip_socket_t clip_transport_get_socket(const clip_transport_t *trans);

/* Checks if TLS 1.3 handshake completed successfully */
bool clip_transport_is_tls_established(const clip_transport_t *trans);

/* Returns negotiated TLS version string (e.g. "TLSv1.3") */
const char* clip_transport_get_tls_version(const clip_transport_t *trans);

/* Returns negotiated cipher suite string (e.g. "TLS_AES_256_GCM_SHA384") */
const char* clip_transport_get_cipher_name(const clip_transport_t *trans);

/* Formats peer certificate subject/issuer into buf */
int clip_transport_get_peer_cert_info(const clip_transport_t *trans, char *buf, size_t buf_len);

/* Checks if internal TLS buffers have pending decrypted data */
bool clip_transport_has_pending(const clip_transport_t *trans);

#ifdef __cplusplus
}
#endif

#endif /* CLIP_TRANSPORT_H */

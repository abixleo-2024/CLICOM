/*
 * clip_tls.h — CLICOM OpenSSL Helper Declarations
 */

#ifndef CLIP_TLS_H
#define CLIP_TLS_H

#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "clip_errors.h"
#include "clip_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Global OpenSSL library initialization */
ClipError clip_tls_init(void);

/* Global OpenSSL library cleanup */
void clip_tls_cleanup(void);

/* Enforces TLS 1.3 strictly on an SSL_CTX (rejecting TLS 1.2 or older) */
ClipError clip_tls_ctx_enforce_tls13(SSL_CTX *ctx);

/* Formats the most recent OpenSSL error string into buf */
void clip_tls_get_last_error(char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CLIP_TLS_H */

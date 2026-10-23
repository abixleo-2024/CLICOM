/*
 * clip_tls.c — CLICOM OpenSSL Helpers Implementation
 */

#include "clip_tls.h"
#include "clip_log.h"
#include <string.h>

static bool s_tls_initialized = false;

ClipError clip_tls_init(void)
{
    if (s_tls_initialized) {
        return CLIP_OK;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    s_tls_initialized = true;
    return CLIP_OK;
}

void clip_tls_cleanup(void)
{
    if (!s_tls_initialized) {
        return;
    }
    EVP_cleanup();
    ERR_free_strings();
    s_tls_initialized = false;
}

ClipError clip_tls_ctx_enforce_tls13(SSL_CTX *ctx)
{
    if (!ctx) {
        return CLIP_ERR_INVALID;
    }

    /* Strictly enforce TLS 1.3: min = TLS 1.3, max = TLS 1.3 */
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
        CLIP_LOGE("Failed to set minimum TLS protocol version to TLS 1.3");
        return CLIP_ERR_TLS_VERSION;
    }

    if (!SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
        CLIP_LOGE("Failed to set maximum TLS protocol version to TLS 1.3");
        return CLIP_ERR_TLS_VERSION;
    }

    /* Disable insecure options */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                             SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);

    return CLIP_OK;
}

void clip_tls_get_last_error(char *buf, size_t len)
{
    if (!buf || len == 0) return;
    unsigned long err = ERR_get_error();
    if (err == 0) {
        snprintf(buf, len, "No SSL error details");
        return;
    }
    ERR_error_string_n(err, buf, len);
}

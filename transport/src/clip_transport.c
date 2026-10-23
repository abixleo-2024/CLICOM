/*
 * clip_transport.c — CLICOM TLS 1.3 Transport Implementation
 */

#include "clip_transport.h"
#include "clip_tls.h"
#include "clip_log.h"
#include "clip_net.h"
#include <stdlib.h>
#include <string.h>

struct clip_transport {
    bool is_server;
    clip_socket_t sock;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    bool owns_ctx;
    bool tls_established;
    char expected_host[256];
    char tls_version[32];
    char cipher_name[64];
};

ClipError clip_transport_create_server(const clip_tls_server_config_t *config,
                                       clip_transport_t **out_trans)
{
    if (!config || !out_trans || !config->cert_file || !config->key_file) {
        return CLIP_ERR_INVALID;
    }

    clip_tls_init();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        CLIP_LOGE("Failed to create SSL_CTX for server");
        return CLIP_ERR_NOMEM;
    }

    ClipError err = clip_tls_ctx_enforce_tls13(ctx);
    if (err != CLIP_OK) {
        SSL_CTX_free(ctx);
        return err;
    }

    /* Load server certificate */
    if (SSL_CTX_use_certificate_chain_file(ctx, config->cert_file) <= 0) {
        char err_buf[256];
        clip_tls_get_last_error(err_buf, sizeof(err_buf));
        CLIP_LOGE("Failed to load server certificate '%s': %s", config->cert_file, err_buf);
        SSL_CTX_free(ctx);
        return CLIP_ERR_TLS_CERT_VERIFY;
    }

    /* Load server private key */
    if (SSL_CTX_use_PrivateKey_file(ctx, config->key_file, SSL_FILETYPE_PEM) <= 0) {
        char err_buf[256];
        clip_tls_get_last_error(err_buf, sizeof(err_buf));
        CLIP_LOGE("Failed to load server private key '%s': %s", config->key_file, err_buf);
        SSL_CTX_free(ctx);
        return CLIP_ERR_TLS_CERT_VERIFY;
    }

    /* Verify private key matches certificate */
    if (!SSL_CTX_check_private_key(ctx)) {
        CLIP_LOGE("Server private key does not match certificate public key");
        SSL_CTX_free(ctx);
        return CLIP_ERR_TLS_CERT_VERIFY;
    }

    /* Optional client cert verification (mTLS) */
    if (config->ca_file) {
        if (!SSL_CTX_load_verify_locations(ctx, config->ca_file, NULL)) {
            CLIP_LOGW("Failed to load client CA file '%s'", config->ca_file);
        } else if (config->require_client_cert) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        }
    }

    clip_transport_t *trans = calloc(1, sizeof(clip_transport_t));
    if (!trans) {
        SSL_CTX_free(ctx);
        return CLIP_ERR_NOMEM;
    }

    trans->is_server = true;
    trans->sock = CLIP_INVALID_SOCKET;
    trans->ssl_ctx = ctx;
    trans->ssl = NULL;
    trans->owns_ctx = true;
    trans->tls_established = false;

    *out_trans = trans;
    return CLIP_OK;
}

ClipError clip_transport_create_client(const clip_tls_client_config_t *config,
                                       clip_transport_t **out_trans)
{
    if (!config || !out_trans) {
        return CLIP_ERR_INVALID;
    }

    clip_tls_init();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        CLIP_LOGE("Failed to create SSL_CTX for client");
        return CLIP_ERR_NOMEM;
    }

    ClipError err = clip_tls_ctx_enforce_tls13(ctx);
    if (err != CLIP_OK) {
        SSL_CTX_free(ctx);
        return err;
    }

    /* Certificate verification root store */
    if (config->ca_file) {
        if (!SSL_CTX_load_verify_locations(ctx, config->ca_file, NULL)) {
            char err_buf[256];
            clip_tls_get_last_error(err_buf, sizeof(err_buf));
            CLIP_LOGE("Failed to load trusted CA '%s': %s", config->ca_file, err_buf);
            SSL_CTX_free(ctx);
            return CLIP_ERR_TLS_CERT_VERIFY;
        }
    } else {
        /* Use system default CA locations */
        SSL_CTX_set_default_verify_paths(ctx);
    }

    /* Set strict peer verification: verify server certificate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* Optional client mTLS cert */
    if (config->client_cert && config->client_key) {
        SSL_CTX_use_certificate_chain_file(ctx, config->client_cert);
        SSL_CTX_use_PrivateKey_file(ctx, config->client_key, SSL_FILETYPE_PEM);
    }

    clip_transport_t *trans = calloc(1, sizeof(clip_transport_t));
    if (!trans) {
        SSL_CTX_free(ctx);
        return CLIP_ERR_NOMEM;
    }

    trans->is_server = false;
    trans->sock = CLIP_INVALID_SOCKET;
    trans->ssl_ctx = ctx;
    trans->ssl = NULL;
    trans->owns_ctx = true;
    trans->tls_established = false;

    if (config->expected_host && config->expected_host[0]) {
        strncpy(trans->expected_host, config->expected_host, sizeof(trans->expected_host) - 1);
    } else {
        strncpy(trans->expected_host, "localhost", sizeof(trans->expected_host) - 1);
    }

    *out_trans = trans;
    return CLIP_OK;
}

ClipError clip_transport_connect(clip_transport_t *trans, const char *host, uint16_t port)
{
    if (!trans || !host || trans->is_server) {
        return CLIP_ERR_INVALID;
    }

    /* Initialize network subsystem */
    ClipError net_err = clip_net_init();
    if (net_err != CLIP_OK) {
        return net_err;
    }

    /* Establish TCP socket */
    clip_socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == CLIP_INVALID_SOCKET) {
        CLIP_LOGE("socket() failed: %s", clip_net_strerror(clip_net_get_last_error()));
        return CLIP_ERR_IO;
    }

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = inet_addr(host);

    if (saddr.sin_addr.s_addr == INADDR_NONE) {
        struct hostent *he = gethostbyname(host);
        if (!he || !he->h_addr_list[0]) {
            int dns_err = clip_net_get_last_error();
            CLIP_LOGE("DNS resolution failed for host '%s': %s", host, clip_net_strerror(dns_err));
            clip_net_close_socket(&sock);
            return CLIP_ERR_NOT_FOUND;
        }
        memcpy(&saddr.sin_addr, he->h_addr_list[0], sizeof(struct in_addr));
    }

    if (connect(sock, (struct sockaddr*)&saddr, sizeof(saddr)) == CLIP_SOCKET_ERROR) {
        int conn_err = clip_net_get_last_error();
        CLIP_LOGE("TCP connect to %s:%u failed: %s", host, port, clip_net_strerror(conn_err));
        clip_net_close_socket(&sock);
        return CLIP_ERR_CONN_REFUSED;
    }

    clip_net_set_nodelay(sock, true);
    clip_net_set_keepalive(sock, true);

    trans->sock = sock;

    /* Create SSL instance */
    trans->ssl = SSL_new(trans->ssl_ctx);
    if (!trans->ssl) {
        clip_net_close_socket(&trans->sock);
        return CLIP_ERR_NOMEM;
    }

    SSL_set_fd(trans->ssl, (int)trans->sock);

    /* RFC 6066: IP literals MUST NOT be sent in SNI (server_name) extension.
     * RFC 6125 / OpenSSL: Use SSL_set1_host for DNS names or SSL_set1_host for IP/hostname matching.
     */
    bool is_ip_literal = false;
    struct in_addr test_in4;
#ifdef _WIN32
    if (inet_addr(trans->expected_host) != INADDR_NONE || strcmp(trans->expected_host, "255.255.255.255") == 0) {
        is_ip_literal = true;
    }
#else
    if (inet_pton(AF_INET, trans->expected_host, &test_in4) == 1) {
        is_ip_literal = true;
    }
#endif

    if (is_ip_literal) {
        /* Do NOT set SNI for IP addresses (RFC 6066 Section 3).
         * Set target IP address for IP-SAN verification in peer certificate.
         */
        X509_VERIFY_PARAM *param = SSL_get0_param(trans->ssl);
        if (param) {
            X509_VERIFY_PARAM_set1_ip_asc(param, trans->expected_host);
        }
    } else {
        /* SNI (Server Name Indication) extension for FQDNs */
        SSL_set_tlsext_host_name(trans->ssl, trans->expected_host);

        /* Strict Hostname verification (RFC 6125 / SAN DNS / CN checking) */
        SSL_set1_host(trans->ssl, trans->expected_host);
    }

    /* Perform TLS Handshake */
    int ret = SSL_connect(trans->ssl);
    if (ret <= 0) {
        long verify_err = SSL_get_verify_result(trans->ssl);
        if (verify_err != X509_V_OK) {
            CLIP_LOGE("TLS Certificate verification failed: %s (error code %ld)",
                           X509_verify_cert_error_string(verify_err), verify_err);
            clip_transport_shutdown(trans);
            return CLIP_ERR_TLS_CERT_VERIFY;
        }

        char err_buf[256];
        clip_tls_get_last_error(err_buf, sizeof(err_buf));
        CLIP_LOGE("TLS 1.3 handshake failed: %s", err_buf);
        clip_transport_shutdown(trans);
        return CLIP_ERR_TLS_HANDSHAKE;
    }

    /* Enforce that negotiated protocol is TLS 1.3 */
    const char *ver = SSL_get_version(trans->ssl);
    if (!ver || strcmp(ver, "TLSv1.3") != 0) {
        CLIP_LOGE("TLS Version rejected: negotiated '%s', strictly require TLSv1.3", ver ? ver : "unknown");
        clip_transport_shutdown(trans);
        return CLIP_ERR_TLS_VERSION;
    }

    /* Verify that server provided a valid certificate */
    X509 *peer_cert = SSL_get_peer_certificate(trans->ssl);
    if (!peer_cert) {
        CLIP_LOGE("TLS Error: server did not provide a certificate");
        clip_transport_shutdown(trans);
        return CLIP_ERR_TLS_CERT_VERIFY;
    }
    X509_free(peer_cert);

    /* Record negotiated telemetry */
    strncpy(trans->tls_version, ver, sizeof(trans->tls_version) - 1);
    const char *cname = SSL_get_cipher_name(trans->ssl);
    if (cname) {
        strncpy(trans->cipher_name, cname, sizeof(trans->cipher_name) - 1);
    }

    trans->tls_established = true;
    CLIP_LOGI("TLS 1.3 Handshake completed successfully (%s, %s)",
                  trans->tls_version, trans->cipher_name);

    return CLIP_OK;
}

ClipError clip_transport_accept(clip_transport_t *server_trans,
                                clip_socket_t client_sock,
                                clip_transport_t **out_client_trans)
{
    if (!server_trans || !server_trans->is_server || client_sock == CLIP_INVALID_SOCKET || !out_client_trans) {
        return CLIP_ERR_INVALID;
    }

    clip_transport_t *trans = calloc(1, sizeof(clip_transport_t));
    if (!trans) {
        return CLIP_ERR_NOMEM;
    }

    trans->is_server = false;  /* endpoint transport for accepted client */
    trans->sock = client_sock;
    trans->ssl_ctx = server_trans->ssl_ctx;
    trans->owns_ctx = false;
    trans->tls_established = false;

    trans->ssl = SSL_new(server_trans->ssl_ctx);
    if (!trans->ssl) {
        free(trans);
        return CLIP_ERR_NOMEM;
    }

    SSL_set_fd(trans->ssl, (int)client_sock);

    /* Ensure socket is blocking with timeout for TLS handshake */
    clip_net_set_nonblocking(client_sock, false);
#ifdef _WIN32
    DWORD tv_ms = 2000;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_ms, sizeof(tv_ms));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv_ms, sizeof(tv_ms));
#endif

    /* Perform server-side TLS handshake */
    int ret = SSL_accept(trans->ssl);
    if (ret <= 0) {
        int ssl_err = SSL_get_error(trans->ssl, ret);
        char err_buf[256];
        clip_tls_get_last_error(err_buf, sizeof(err_buf));
        CLIP_LOGE("TLS Server accept failed on client socket %d (ssl_err=%d): %s",
                  (int)client_sock, ssl_err, err_buf);
        SSL_free(trans->ssl);
        free(trans);
        return CLIP_ERR_TLS_HANDSHAKE;
    }

    /* Restore non-blocking mode for select() multiplexing */
    clip_net_set_nonblocking(client_sock, true);

    /* Verify TLS 1.3 negotiated */
    const char *ver = SSL_get_version(trans->ssl);
    if (!ver || strcmp(ver, "TLSv1.3") != 0) {
        CLIP_LOGE("TLS Server rejected client: negotiated '%s', strictly require TLSv1.3",
                       ver ? ver : "unknown");
        SSL_free(trans->ssl);
        free(trans);
        return CLIP_ERR_TLS_VERSION;
    }

    strncpy(trans->tls_version, ver, sizeof(trans->tls_version) - 1);
    const char *cname = SSL_get_cipher_name(trans->ssl);
    if (cname) {
        strncpy(trans->cipher_name, cname, sizeof(trans->cipher_name) - 1);
    }

    trans->tls_established = true;
    CLIP_LOGI("TLS 1.3 Server accepted client (%s, %s)", trans->tls_version, trans->cipher_name);

    *out_client_trans = trans;
    return CLIP_OK;
}

ClipError clip_transport_read(clip_transport_t *trans, void *buf, size_t count, size_t *out_read)
{
    if (!trans || !trans->ssl || !trans->tls_established || !buf || count == 0 || !out_read) {
        return CLIP_ERR_INVALID;
    }

    *out_read = 0;
    int ret = SSL_read(trans->ssl, buf, (int)count);
    if (ret > 0) {
        *out_read = (size_t)ret;
        return CLIP_OK;
    }

    if (ret == 0) {
        return CLIP_ERR_SHUTDOWN;
    }

    int ssl_err = SSL_get_error(trans->ssl, ret);
    if (ssl_err == SSL_ERROR_ZERO_RETURN) {
        return CLIP_ERR_SHUTDOWN;
    }

    return CLIP_ERR_TLS_IO;
}

ClipError clip_transport_write(clip_transport_t *trans, const void *buf, size_t count)
{
    if (!trans || !trans->ssl || !trans->tls_established || !buf) {
        return CLIP_ERR_INVALID;
    }

    size_t total_sent = 0;
    while (total_sent < count) {
        int to_write = (int)(count - total_sent);
        int ret = SSL_write(trans->ssl, (const char*)buf + total_sent, to_write);
        if (ret <= 0) {
            int ssl_err = SSL_get_error(trans->ssl, ret);
            CLIP_LOGE("SSL_write failed (ssl_error=%d)", ssl_err);
            return CLIP_ERR_TLS_IO;
        }
        total_sent += (size_t)ret;
    }

    return CLIP_OK;
}

void clip_transport_shutdown(clip_transport_t *trans)
{
    if (!trans) return;

    if (trans->ssl && trans->tls_established) {
        SSL_shutdown(trans->ssl);
    }

    if (trans->sock != CLIP_INVALID_SOCKET) {
        clip_net_close_socket(&trans->sock);
    }

    trans->tls_established = false;
}

void clip_transport_free(clip_transport_t *trans)
{
    if (!trans) return;

    clip_transport_shutdown(trans);

    if (trans->ssl) {
        SSL_free(trans->ssl);
        trans->ssl = NULL;
    }

    if (trans->owns_ctx && trans->ssl_ctx) {
        SSL_CTX_free(trans->ssl_ctx);
        trans->ssl_ctx = NULL;
    }

    free(trans);
}

clip_socket_t clip_transport_get_socket(const clip_transport_t *trans)
{
    return trans ? trans->sock : CLIP_INVALID_SOCKET;
}

bool clip_transport_is_tls_established(const clip_transport_t *trans)
{
    return trans ? trans->tls_established : false;
}

const char* clip_transport_get_tls_version(const clip_transport_t *trans)
{
    return trans ? trans->tls_version : "";
}

const char* clip_transport_get_cipher_name(const clip_transport_t *trans)
{
    return trans ? trans->cipher_name : "";
}

int clip_transport_get_peer_cert_info(const clip_transport_t *trans, char *buf, size_t buf_len)
{
    if (!trans || !trans->ssl || !buf || buf_len == 0) return -1;
    X509 *cert = SSL_get_peer_certificate(trans->ssl);
    if (!cert) return -1;

    char sub[256] = {0};
    char iss[256] = {0};
    X509_NAME_oneline(X509_get_subject_name(cert), sub, sizeof(sub));
    X509_NAME_oneline(X509_get_issuer_name(cert), iss, sizeof(iss));
    snprintf(buf, buf_len, "Subject: %s | Issuer: %s", sub, iss);
    X509_free(cert);
    return 0;
}

bool clip_transport_has_pending(const clip_transport_t *trans)
{
    if (!trans || !trans->ssl || !trans->tls_established) return false;
    return SSL_pending(trans->ssl) > 0;
}

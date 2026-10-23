/*
 * tests/unit/test_tls.c — Phase 7 Unit & Integration Tests: TLS 1.3 Secure Transport
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "clip_net.h"
#include <windows.h>

#include "clip_version.h"
#include "clip_protocol.h"
#include "clip_types.h"
#include "clip_errors.h"
#include "clip_net.h"
#include "clip_transport.h"
#include "clip_tls.h"
#include "../../server/include/server.h"
#include "../../server/include/clip_sessions.h"
#include "../../server/include/clip_connections.h"
#include "../../client/include/network.h"

static int g_pass = 0;
static int g_fail = 0;

#define TEST(name, condition) do { \
    if (condition) { \
        printf("  PASS  %s\n", (name)); \
        g_pass++; \
    } else { \
        printf("  FAIL  %s\n", (name)); \
        g_fail++; \
    } \
} while (0)

#define TEST_TLS_PORT 14990

static DWORD WINAPI server_thread_func(LPVOID param)
{
    ClipServer* srv = (ClipServer*)param;
    while (srv && srv->is_running) {
        clip_server_poll(srv, 10);
    }
    return 0;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("============================================================\n");
    printf(" CLICOM Phase 7 — Unit & Integration Test: TLS 1.3 Transport \n");
    printf("============================================================\n\n");

    /* ── 1-3. TLS 1.3 Abstraction & Handshake Enforcement ─────────────────── */
    printf("[1-3. TLS 1.3 Configuration & Protocol Enforcement]\n");

    ClipError init_err = clip_tls_init();
    TEST("clip_tls_init succeeds", init_err == CLIP_OK);

    const SSL_METHOD *srv_m = TLS_server_method();
    SSL_CTX *test_ctx = SSL_CTX_new(srv_m);
    TEST("SSL_CTX created successfully", test_ctx != NULL);

    ClipError enf_err = clip_tls_ctx_enforce_tls13(test_ctx);
    TEST("TLS 1.3 strictly enforced (min=TLS1.3, max=TLS1.3)", enf_err == CLIP_OK);
    SSL_CTX_free(test_ctx);

    /* Test production defaults and explicit opt-in */
    ClipServerConfig def_srv_cfg;
    clip_server_config_init_default(&def_srv_cfg);
    TEST("production server defaults use_tls = true", def_srv_cfg.use_tls == true);
    TEST("production server default cert is certs/server.crt", strcmp(def_srv_cfg.cert_file, "certs/server.crt") == 0);
    TEST("production server default key is certs/server.key", strcmp(def_srv_cfg.key_file, "certs/server.key") == 0);

    ClipClientNet def_client;
    clip_client_net_init(&def_client);
    TEST("production client defaults use_tls = true", def_client.use_tls == true);
    TEST("production client default CA is certs/ca.crt", strcmp(def_client.tls_cfg.ca_file, "certs/ca.crt") == 0);
    TEST("production client default expected host is localhost", strcmp(def_client.tls_cfg.expected_host, "localhost") == 0);

    /* Test explicit opt-in for plaintext */
    clip_client_net_set_insecure_plaintext(&def_client);
    TEST("explicit opt-in disables TLS (use_tls = false)", def_client.use_tls == false);
    clip_client_net_cleanup(&def_client);

    /* ── Start Background Server for TLS Handshakes ──────────────────────── */
    remove("test_tls_srv.db");

    ClipServerConfig srv_config = {0};
    strncpy(srv_config.bind_host, "127.0.0.1", sizeof(srv_config.bind_host) - 1);
    srv_config.port = TEST_TLS_PORT;
    srv_config.max_clients = 16;
    srv_config.use_tls = true;
    strncpy(srv_config.cert_file, "certs/server.crt", sizeof(srv_config.cert_file) - 1);
    strncpy(srv_config.key_file, "certs/server.key", sizeof(srv_config.key_file) - 1);
    strncpy(srv_config.db_path, "test_tls_srv.db", sizeof(srv_config.db_path) - 1);

    ClipServer srv;
    clip_server_init(&srv, &srv_config);
    ClipError s_start = clip_server_start(&srv);
    TEST("TLS 1.3 Server started and listening on 127.0.0.1:14990", s_start == CLIP_OK);

    HANDLE hServerThread = CreateThread(NULL, 0, server_thread_func, &srv, 0, NULL);
    Sleep(50); /* give server thread time to enter poll loop */

    /* ── 4-6. Security Negative Tests: Certificate Verification ────────────── */
    printf("\n[4-6. Security Negative Tests: Certificate Verification & Hostname]\n");

    /* NEGATIVE TEST 1: Untrusted Root CA */
    clip_tls_client_config_t bad_ca_cfg = {
        .ca_file = "certs/untrusted_ca.crt",
        .expected_host = "localhost",
        .insecure_skip_verify = false
    };
    clip_transport_t *bad_client = NULL;
    clip_transport_create_client(&bad_ca_cfg, &bad_client);

    ClipError bad_conn_err = clip_transport_connect(bad_client, "127.0.0.1", TEST_TLS_PORT);
    TEST("NEGATIVE TEST: Untrusted CA connection rejected with CLIP_ERR_TLS_CERT_VERIFY",
         bad_conn_err == CLIP_ERR_TLS_CERT_VERIFY);
    clip_transport_free(bad_client);

    /* NEGATIVE TEST 2: Hostname Mismatch */
    clip_tls_client_config_t bad_host_cfg = {
        .ca_file = "certs/ca.crt",
        .expected_host = "invalid.domain.example.com",
        .insecure_skip_verify = false
    };
    clip_transport_t *bad_host_client = NULL;
    clip_transport_create_client(&bad_host_cfg, &bad_host_client);

    ClipError bad_host_err = clip_transport_connect(bad_host_client, "127.0.0.1", TEST_TLS_PORT);
    TEST("NEGATIVE TEST: Hostname mismatch rejected with CLIP_ERR_TLS_CERT_VERIFY",
         bad_host_err == CLIP_ERR_TLS_CERT_VERIFY);
    clip_transport_free(bad_host_client);

    /* NEGATIVE TEST 3: Downgrade Attempt (Client configured for TLS 1.2 max) */
    const SSL_METHOD *cmethod = TLS_client_method();
    SSL_CTX *c_downgrade_ctx = SSL_CTX_new(cmethod);
    SSL_CTX_set_max_proto_version(c_downgrade_ctx, TLS1_2_VERSION);
    clip_socket_t dg_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(TEST_TLS_PORT);
    saddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    connect(dg_sock, (struct sockaddr*)&saddr, sizeof(saddr));
    SSL *dg_ssl = SSL_new(c_downgrade_ctx);
    SSL_set_fd(dg_ssl, (int)dg_sock);
    int dg_ret = SSL_connect(dg_ssl);
    TEST("NEGATIVE TEST: TLS 1.2 downgrade attempt rejected by server", dg_ret <= 0);
    SSL_free(dg_ssl);
    SSL_CTX_free(c_downgrade_ctx);
    clip_net_close_socket(&dg_sock);

    /* NEGATIVE TEST 4: IP Address Mismatch against Certificate without IP SAN */
    clip_tls_client_config_t ip_san_cfg = {
        .ca_file = "certs/ca.crt",
        .expected_host = "192.0.2.1", /* IP address not in server certificate SAN */
        .insecure_skip_verify = false
    };
    clip_transport_t *ip_client = NULL;
    clip_transport_create_client(&ip_san_cfg, &ip_client);

    ClipError ip_conn_err = clip_transport_connect(ip_client, "127.0.0.1", TEST_TLS_PORT);
    TEST("NEGATIVE TEST: IP address not present in IP-SAN rejected with CLIP_ERR_TLS_CERT_VERIFY",
         ip_conn_err == CLIP_ERR_TLS_CERT_VERIFY);
    clip_transport_free(ip_client);

    /* ── 7-18. Full Stack Integration over TLS 1.3 ────────────────────────── */
    printf("\n[7-18. End-to-End Application Protocol over TLS 1.3]\n");

    /* Node 1 Connects via TLS 1.3 */
    ClipClientNet client1;
    clip_client_net_init(&client1);
    clip_tls_client_config_t c1_cfg = {
        .ca_file = "certs/ca.crt",
        .expected_host = "localhost"
    };
    clip_client_net_set_tls_config(&client1, &c1_cfg);

    ClipError c1_conn = clip_client_connect(&client1, "127.0.0.1", TEST_TLS_PORT);
    TEST("Node 1 connects over TLS 1.3 with certificate verification", c1_conn == CLIP_OK);

    TEST("TLS 1.3 protocol verified on connection",
         strcmp(clip_transport_get_tls_version(client1.transport), "TLSv1.3") == 0);
    TEST("TLS cipher suite negotiated",
         strlen(clip_transport_get_cipher_name(client1.transport)) > 0);

    /* Node 1 Registers */
    uint8_t n1_payload[64];
    size_t n1_off = 0;
    clip_tlv_write(n1_payload, sizeof(n1_payload), &n1_off, CLIP_TAG_DISPLAY_NAME, (const uint8_t*)"TLS-ALICE", 9);
    ClipFrameHeader n1_hdr;
    clip_frame_header_init(&n1_hdr, CLIP_MSG_REGISTER, (uint32_t)n1_off, 1, NULL);
    clip_client_send_frame(&client1, &n1_hdr, n1_payload);

    ClipFrameHeader ack1;
    uint8_t ack1_pay[512];
    uint32_t ack1_len = 0;
    ClipError r1 = clip_client_recv_frame(&client1, &ack1, ack1_pay, sizeof(ack1_pay), &ack1_len, 1000);
    TEST("Node 1 receives REGISTER_ACK over encrypted TLS", r1 == CLIP_OK && ack1.msg_type == CLIP_MSG_REGISTER_ACK);
    TEST("WIRE INVARIANT: REGISTER_ACK header session_uuid is strictly ZERO",
         clip_uuid_is_zero((const ClipUuid*)ack1.session_uuid));

    const uint8_t *n1_u = NULL;
    uint16_t n1_ulen = 0;
    clip_tlv_find(ack1_pay, ack1_len, CLIP_TAG_NODE_UUID, &n1_u, &n1_ulen);
    ClipUuid alice_uuid = {0};
    if (n1_u && n1_ulen == CLIP_UUID_BYTES) {
        memcpy(alice_uuid.bytes, n1_u, CLIP_UUID_BYTES);
    }

    /* Node 2 Connects via TLS 1.3 */
    ClipClientNet client2;
    clip_client_net_init(&client2);
    clip_tls_client_config_t c2_cfg = {
        .ca_file = "certs/ca.crt",
        .expected_host = "localhost"
    };
    clip_client_net_set_tls_config(&client2, &c2_cfg);

    ClipError c2_conn = clip_client_connect(&client2, "127.0.0.1", TEST_TLS_PORT);
    TEST("Node 2 connects over TLS 1.3", c2_conn == CLIP_OK);

    /* Node 2 Registers */
    uint8_t n2_payload[64];
    size_t n2_off = 0;
    clip_tlv_write(n2_payload, sizeof(n2_payload), &n2_off, CLIP_TAG_DISPLAY_NAME, (const uint8_t*)"TLS-BOB", 7);
    ClipFrameHeader n2_hdr;
    clip_frame_header_init(&n2_hdr, CLIP_MSG_REGISTER, (uint32_t)n2_off, 1, NULL);
    clip_client_send_frame(&client2, &n2_hdr, n2_payload);

    ClipFrameHeader ack2;
    uint8_t ack2_pay[512];
    uint32_t ack2_len = 0;
    clip_client_recv_frame(&client2, &ack2, ack2_pay, sizeof(ack2_pay), &ack2_len, 1000);
    const uint8_t *n2_u = NULL;
    uint16_t n2_ulen = 0;
    clip_tlv_find(ack2_pay, ack2_len, CLIP_TAG_NODE_UUID, &n2_u, &n2_ulen);
    ClipUuid bob_uuid = {0};
    if (n2_u && n2_ulen == CLIP_UUID_BYTES) {
        memcpy(bob_uuid.bytes, n2_u, CLIP_UUID_BYTES);
    }

    /* Node 1 Creates Channel over TLS */
    uint8_t c_pay[64];
    size_t c_off = 0;
    clip_tlv_write(c_pay, sizeof(c_pay), &c_off, CLIP_TAG_CHANNEL_NAME, (const uint8_t*)"SECURE-OPS", 10);
    ClipFrameHeader c_hdr;
    clip_frame_header_init(&c_hdr, CLIP_MSG_CHANNEL_CREATE, (uint32_t)c_off, 2, NULL);
    clip_client_send_frame(&client1, &c_hdr, c_pay);

    ClipFrameHeader c_ack;
    uint8_t c_ack_pay[512];
    uint32_t c_ack_len = 0;
    clip_client_recv_frame(&client1, &c_ack, c_ack_pay, sizeof(c_ack_pay), &c_ack_len, 1000);
    TEST("Channel created over TLS (CHANNEL_CREATE_OK)", c_ack.msg_type == CLIP_MSG_CHANNEL_CREATE_OK);

    const uint8_t *ch_u = NULL;
    uint16_t ch_ulen = 0;
    clip_tlv_find(c_ack_pay, c_ack_len, CLIP_TAG_CHANNEL_UUID, &ch_u, &ch_ulen);
    ClipUuid chan_uuid;
    memcpy(chan_uuid.bytes, ch_u, CLIP_UUID_BYTES);

    const uint8_t *jk_ptr = NULL;
    uint16_t jk_len = 0;
    clip_tlv_find(c_ack_pay, c_ack_len, CLIP_TAG_CHANNEL_JOIN_KEY, &jk_ptr, &jk_len);
    char join_key[16] = {0};
    memcpy(join_key, jk_ptr, jk_len);

    /* Node 2 Joins Channel via Join Key over TLS */
    uint8_t j_pay[64];
    size_t j_off = 0;
    clip_tlv_write(j_pay, sizeof(j_pay), &j_off, CLIP_TAG_CHANNEL_JOIN_KEY, (const uint8_t*)join_key, (uint16_t)strlen(join_key));
    ClipFrameHeader j_hdr;
    clip_frame_header_init(&j_hdr, CLIP_MSG_CHANNEL_JOIN, (uint32_t)j_off, 2, NULL);
    clip_client_send_frame(&client2, &j_hdr, j_pay);

    ClipFrameHeader j_ack;
    uint8_t j_ack_pay[512];
    uint32_t j_ack_len = 0;
    clip_client_recv_frame(&client2, &j_ack, j_ack_pay, sizeof(j_ack_pay), &j_ack_len, 1000);
    TEST("Node 2 joined channel over TLS (CHANNEL_JOIN_OK)", j_ack.msg_type == CLIP_MSG_CHANNEL_JOIN_OK);

    /* Phase 5 Connection Request over TLS */
    uint8_t req_pay[128];
    size_t req_off = 0;
    clip_tlv_write(req_pay, sizeof(req_pay), &req_off, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(req_pay, sizeof(req_pay), &req_off, CLIP_TAG_NODE_UUID, bob_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader req_hdr;
    clip_frame_header_init(&req_hdr, CLIP_MSG_CONN_REQUEST, (uint32_t)req_off, 3, NULL);
    clip_client_send_frame(&client1, &req_hdr, req_pay);

    /* Node 2 receives CONN_REQUEST notification over TLS */
    ClipFrameHeader fwd_hdr;
    uint8_t fwd_pay[512];
    uint32_t fwd_len = 0;
    clip_client_recv_frame(&client2, &fwd_hdr, fwd_pay, sizeof(fwd_pay), &fwd_len, 1000);
    TEST("Node 2 received CONN_REQUEST notification over TLS", fwd_hdr.msg_type == CLIP_MSG_CONN_REQUEST);
    TEST("WIRE INVARIANT: CONN_REQUEST header session_uuid is strictly ZERO",
         clip_uuid_is_zero((const ClipUuid*)fwd_hdr.session_uuid));

    const uint8_t *cn_u = NULL;
    uint16_t cn_ulen = 0;
    clip_tlv_find(fwd_pay, fwd_len, CLIP_TAG_CONNECTION_UUID, &cn_u, &cn_ulen);
    ClipUuid conn_uuid;
    memcpy(conn_uuid.bytes, cn_u, CLIP_UUID_BYTES);

    /* Node 1 receives confirmation */
    ClipFrameHeader req_resp;
    uint8_t req_resp_pay[512];
    uint32_t req_resp_len = 0;
    clip_client_recv_frame(&client1, &req_resp, req_resp_pay, sizeof(req_resp_pay), &req_resp_len, 1000);

    /* Node 2 Accepts Connection over TLS */
    uint8_t acc_pay[64];
    size_t acc_off = 0;
    clip_tlv_write(acc_pay, sizeof(acc_pay), &acc_off, CLIP_TAG_CONNECTION_UUID, conn_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader acc_hdr;
    clip_frame_header_init(&acc_hdr, CLIP_MSG_CONN_ACCEPT, (uint32_t)acc_off, 3, NULL);
    clip_client_send_frame(&client2, &acc_hdr, acc_pay);

    /* Node 2 receives ACCEPT_OK */
    ClipFrameHeader acc_ok;
    uint8_t acc_ok_pay[512];
    uint32_t acc_ok_len = 0;
    clip_client_recv_frame(&client2, &acc_ok, acc_ok_pay, sizeof(acc_ok_pay), &acc_ok_len, 1000);
    TEST("Connection accepted over TLS", acc_ok.msg_type == CLIP_MSG_CONN_ACCEPT);

    /* Node 1 receives ACCEPT notification */
    ClipFrameHeader n1_acc;
    uint8_t n1_acc_pay[512];
    uint32_t n1_acc_len = 0;
    clip_client_recv_frame(&client1, &n1_acc, n1_acc_pay, sizeof(n1_acc_pay), &n1_acc_len, 1000);

    /* Phase 6 Session Start on Accepted Connection over TLS */
    uint8_t sess_pay[64];
    size_t sess_off = 0;
    clip_tlv_write(sess_pay, sizeof(sess_pay), &sess_off, CLIP_TAG_CONNECTION_UUID, conn_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader sess_hdr;
    clip_frame_header_init(&sess_hdr, CLIP_MSG_SESSION_START, (uint32_t)sess_off, 4, NULL);
    clip_client_send_frame(&client1, &sess_hdr, sess_pay);

    /* Node 1 receives SESSION_START_ACK over TLS */
    ClipFrameHeader sess_ack;
    uint8_t sess_ack_pay[512];
    uint32_t sess_ack_len = 0;
    clip_client_recv_frame(&client1, &sess_ack, sess_ack_pay, sizeof(sess_ack_pay), &sess_ack_len, 1000);
    TEST("SESSION_START_ACK received over TLS", sess_ack.msg_type == CLIP_MSG_SESSION_START_ACK);
    TEST("WIRE INVARIANT: SESSION_START_ACK carries genuine NON-ZERO session_uuid",
         !clip_uuid_is_zero((const ClipUuid*)sess_ack.session_uuid));

    ClipUuid active_session_uuid;
    memcpy(active_session_uuid.bytes, sess_ack.session_uuid, CLIP_UUID_BYTES);

    /* Node 2 receives SESSION_START notification over TLS */
    ClipFrameHeader n2_s_notif;
    uint8_t n2_s_pay[512];
    uint32_t n2_s_len = 0;
    clip_client_recv_frame(&client2, &n2_s_notif, n2_s_pay, sizeof(n2_s_pay), &n2_s_len, 1000);
    TEST("Node 2 receives SESSION_START peer notification over TLS",
         n2_s_notif.msg_type == CLIP_MSG_SESSION_START);
    TEST("WIRE INVARIANT: Peer notification carries identical genuine session_uuid",
         clip_uuid_equal((const ClipUuid*)n2_s_notif.session_uuid, &active_session_uuid));

    /* Strict Identity Separation Verification */
    TEST("INVARIANT: session_uuid != alice_node_uuid", !clip_uuid_equal(&active_session_uuid, &alice_uuid));
    TEST("INVARIANT: session_uuid != bob_node_uuid", !clip_uuid_equal(&active_session_uuid, &bob_uuid));
    TEST("INVARIANT: session_uuid != channel_uuid", !clip_uuid_equal(&active_session_uuid, &chan_uuid));
    TEST("INVARIANT: session_uuid != connection_uuid", !clip_uuid_equal(&active_session_uuid, &conn_uuid));

    /* End Session over TLS */
    uint8_t end_pay[64];
    size_t end_off = 0;
    clip_tlv_write(end_pay, sizeof(end_pay), &end_off, CLIP_TAG_SESSION_UUID, active_session_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader end_hdr;
    clip_frame_header_init(&end_hdr, CLIP_MSG_SESSION_END, (uint32_t)end_off, 5, active_session_uuid.bytes);
    clip_client_send_frame(&client2, &end_hdr, end_pay);

    ClipFrameHeader end_ack;
    uint8_t end_ack_pay[512];
    uint32_t end_ack_len = 0;
    clip_client_recv_frame(&client2, &end_ack, end_ack_pay, sizeof(end_ack_pay), &end_ack_len, 1000);
    TEST("SESSION_END_ACK received over TLS", end_ack.msg_type == CLIP_MSG_SESSION_END_ACK);

    /* Disconnect clients cleanly */
    clip_client_disconnect(&client1);
    clip_client_disconnect(&client2);

    /* Stop server */
    srv.is_running = false;
    WaitForSingleObject(hServerThread, 1000);
    CloseHandle(hServerThread);
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);

    printf("\n============================================================\n");
    printf(" Total: %d passed, %d FAILED\n", g_pass, g_fail);
    printf(" Result: %s\n", (g_fail == 0) ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    printf("============================================================\n");

    return (g_fail == 0) ? 0 : 1;
}

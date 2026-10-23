/*
 * test_session_binding.c — CLICOM Phase 6 Unit & Integration Tests:
 * Secure Communication Session & Session Binding
 *
 * Tests:
 * 1. Database schema initialization (sessions table with connection_uuid and peer_node_uuid)
 * 2. Invariants: node_a != node_b != channel_uuid != connection_uuid != session_uuid
 * 3. Connection state validation: session creation fails if connection is REQUESTED, DECLINED, or CLOSED
 * 4. Endpoint validation: session creation fails if caller is not an endpoint of connection
 * 5. Successful session creation for ACCEPTED connection
 * 6. Duplicate prevention: second active session on same connection rejected with CLIP_ERR_EXISTS
 * 7. Active session lookup by connection and channel
 * 8. Session termination: only endpoint or channel member can end; updates state to CLOSED and sets ended_at
 * 9. Ending closed session returns CLIP_ERR_NO_SESSION
 * 10. Re-session start allowed after previous session ended (history preserved in SQLite)
 * 11. Startup/crash sweep: stale active sessions transitioned to CLOSED on startup; never auto-resumed
 * 12. Live loopback: unauthenticated session start rejected with CLIP_ERR_DENIED
 * 13. Live loopback: session start on REQUESTED connection rejected with CLIP_ERR_DENIED
 * 14. Live loopback: WIRE INVARIANT - non-session frames have header.session_uuid == 0
 * 15. Live loopback: successful session start over network on ACCEPTED connection
 * 16. Live loopback: WIRE INVARIANT - SESSION_START_ACK has header.session_uuid == genuine_session_uuid != 0
 * 17. Live loopback: peer notification routes SESSION_START with header.session_uuid == genuine_session_uuid != 0
 * 18. Live loopback: duplicate session start rejected over network with CLIP_ERR_EXISTS
 * 19. Live loopback: anti-spoofing rejection when non-participant sends frame claiming session_uuid
 * 20. Live loopback: session end acknowledged to initiator and notified to peer with genuine session_uuid
 * 21. Live loopback: peer offline rejection when peer is not connected
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "clip_types.h"
#include "clip_errors.h"
#include "clip_protocol.h"
#include "clip_crypto.h"
#include "clip_identity.h"
#include "clip_credentials.h"
#include "clip_channels.h"
#include "clip_sessions.h"
#include "clip_connections.h"
#include "../../server/include/server.h"
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

#define TEST_DB_PATH "test_session_binding.db"
#define TEST_PORT 14966

static inline ClipUuid hdr_session_uuid(const ClipFrameHeader* hdr)
{
    ClipUuid u;
    memcpy(u.bytes, hdr->session_uuid, CLIP_UUID_BYTES);
    return u;
}

/* ── Unit Tests: Database & Logic Layer ─────────────────────────────────── */

static void test_session_db_unit(void)
{
    printf("\n[1-11. Session SQLite Unit Logic, Invariants & Lifecycle]\n");

    remove(TEST_DB_PATH);

    ClipIdentityDb* id_db = NULL;
    ClipError open_err = clip_identity_db_open(&id_db, TEST_DB_PATH);
    TEST("Identity and Session DB opened cleanly", open_err == CLIP_OK && id_db != NULL);
    sqlite3* sql = clip_identity_get_sqlite(id_db);
    TEST("Direct SQLite handle retrieved", sql != NULL);

    /* Register test nodes */
    ClipUuid node_a, node_b, node_c;
    uint8_t cred_a[CLIP_CREDENTIAL_BYTES], cred_b[CLIP_CREDENTIAL_BYTES], cred_c[CLIP_CREDENTIAL_BYTES];
    clip_identity_register(id_db, "ALICE", &node_a, cred_a);
    clip_identity_register(id_db, "BOB", &node_b, cred_b);
    clip_identity_register(id_db, "CHARLIE", &node_c, cred_c);

    /* Create test channel by Alice */
    ClipUuid chan_uuid;
    char join_key[CLIP_JOIN_KEY_MAX];
    clip_channel_create(sql, &node_a, "OPS-ROOM", &chan_uuid, join_key, sizeof(join_key));
    /* Bob joins channel */
    clip_channel_join_by_key(sql, &node_b, join_key, NULL, NULL, 0);

    /* Create connection request (Alice -> Bob) */
    ClipConnectionRecord conn1;
    clip_connection_create(sql, &chan_uuid, &node_a, &node_b, &conn1);
    ClipUuid conn_uuid = conn1.connection_uuid;

    TEST("Connection created in REQUESTED state", conn1.state == CLIP_CONN_STATE_REQUESTED);

    /* 3. Session creation MUST fail on REQUESTED connection */
    ClipUuid bad_sess_uuid;
    ClipError err_req = clip_session_create_for_connection(sql, &conn_uuid, &node_a, &bad_sess_uuid);
    TEST("Session creation on REQUESTED connection rejected with CLIP_ERR_DENIED", err_req == CLIP_ERR_DENIED);

    /* 4. Non-existent connection */
    ClipUuid fake_conn;
    clip_crypto_uuid_generate(&fake_conn);
    ClipError err_fake = clip_session_create_for_connection(sql, &fake_conn, &node_a, &bad_sess_uuid);
    TEST("Session creation on non-existent connection rejected", err_fake == CLIP_ERR_NOT_FOUND);

    /* Accept connection */
    clip_connection_set_state(sql, &conn_uuid, CLIP_CONN_STATE_ACCEPTED);

    /* 4. Non-endpoint Charlie attempts to start session */
    ClipError err_charlie = clip_session_create_for_connection(sql, &conn_uuid, &node_c, &bad_sess_uuid);
    TEST("Non-endpoint Charlie rejected from creating session on Alice-Bob connection", err_charlie == CLIP_ERR_DENIED);

    /* 5. Successful session creation for ACCEPTED connection */
    ClipUuid sess1_uuid;
    ClipError start_err = clip_session_create_for_connection(sql, &conn_uuid, &node_a, &sess1_uuid);
    TEST("Alice creates session for ACCEPTED connection", start_err == CLIP_OK);
    TEST("Session UUID is non-zero", !clip_uuid_is_zero(&sess1_uuid));

    /* 2. Strict identity separation invariants */
    TEST("INVARIANT: session_uuid != node_a (initiator)", !clip_uuid_equal(&sess1_uuid, &node_a));
    TEST("INVARIANT: session_uuid != node_b (peer)", !clip_uuid_equal(&sess1_uuid, &node_b));
    TEST("INVARIANT: session_uuid != channel_uuid", !clip_uuid_equal(&sess1_uuid, &chan_uuid));
    TEST("INVARIANT: session_uuid != connection_uuid", !clip_uuid_equal(&sess1_uuid, &conn_uuid));

    /* 7. Verify session record */
    ClipSessionRecord sess1_rec;
    ClipError get_err = clip_session_get(sql, &sess1_uuid, &sess1_rec);
    TEST("Session record retrieved by UUID", get_err == CLIP_OK);
    TEST("Session state is ACTIVE", sess1_rec.state == CLIP_SESSION_STATE_ACTIVE);
    TEST("Session connection_uuid matches", clip_uuid_equal(&sess1_rec.connection_uuid, &conn_uuid));
    TEST("Session channel_uuid matches", clip_uuid_equal(&sess1_rec.channel_uuid, &chan_uuid));
    TEST("Session initiator matches Alice", clip_uuid_equal(&sess1_rec.initiator_node_uuid, &node_a));
    TEST("Session peer matches Bob", clip_uuid_equal(&sess1_rec.peer_node_uuid, &node_b));
    TEST("Session created_at timestamp set", sess1_rec.created_at_ms > 0);
    TEST("Session ended_at timestamp is zero while active", sess1_rec.ended_at_ms == 0);

    /* Active session lookup by connection */
    ClipSessionRecord active_by_conn;
    ClipError get_act_err = clip_session_get_active_for_connection(sql, &conn_uuid, &active_by_conn);
    TEST("Active session retrieved by connection_uuid", get_act_err == CLIP_OK &&
         clip_uuid_equal(&active_by_conn.session_uuid, &sess1_uuid));

    /* 6. Duplicate prevention: cannot start second session on same connection */
    ClipUuid dup_sess_uuid;
    ClipError dup_err = clip_session_create_for_connection(sql, &conn_uuid, &node_b, &dup_sess_uuid);
    TEST("Duplicate active session on same connection rejected with CLIP_ERR_EXISTS", dup_err == CLIP_ERR_EXISTS);

    /* 8. Unauthorized session termination */
    ClipError unauth_end = clip_session_end(sql, &sess1_uuid, &node_c);
    TEST("Non-party Charlie denied from ending Alice-Bob session", unauth_end == CLIP_ERR_DENIED);

    /* Bob (peer) ends session */
    ClipError end_err = clip_session_end(sql, &sess1_uuid, &node_b);
    TEST("Bob (peer endpoint) successfully ends session", end_err == CLIP_OK);

    /* Verify session state CLOSED and ended_at recorded */
    clip_session_get(sql, &sess1_uuid, &sess1_rec);
    TEST("Session state is now CLOSED", sess1_rec.state == CLIP_SESSION_STATE_CLOSED);
    TEST("Session ended_at is set", sess1_rec.ended_at_ms >= sess1_rec.created_at_ms);

    /* 9. Ending already closed session */
    ClipError re_end = clip_session_end(sql, &sess1_uuid, &node_a);
    TEST("Ending already closed session returns CLIP_ERR_NO_SESSION", re_end == CLIP_ERR_NO_SESSION);

    /* 10. Re-starting session on same connection after closing is permitted */
    ClipUuid sess2_uuid;
    ClipError start2_err = clip_session_create_for_connection(sql, &conn_uuid, &node_b, &sess2_uuid);
    TEST("Bob starts new session on same connection after closing", start2_err == CLIP_OK);
    TEST("New session UUID is distinct from previous session", !clip_uuid_equal(&sess2_uuid, &sess1_uuid));

    /* Historical record of first session is still in database */
    ClipSessionRecord hist_rec;
    TEST("Historical record of closed session 1 still exists in SQLite",
         clip_session_get(sql, &sess1_uuid, &hist_rec) == CLIP_OK && hist_rec.state == CLIP_SESSION_STATE_CLOSED);

    clip_session_end(sql, &sess2_uuid, &node_a);

    /* 11. Server restart / crash sweep test */
    /* Start session 3 and leave it ACTIVE */
    ClipUuid sess3_uuid;
    clip_session_create_for_connection(sql, &conn_uuid, &node_a, &sess3_uuid);
    ClipSessionRecord sess3_before;
    clip_session_get(sql, &sess3_uuid, &sess3_before);
    TEST("Session 3 active prior to database restart", sess3_before.state == CLIP_SESSION_STATE_ACTIVE);

    /* Close and reopen identity DB (simulating server restart) */
    clip_identity_db_close(id_db);
    id_db = NULL;

    ClipError reopen_err = clip_identity_db_open(&id_db, TEST_DB_PATH);
    TEST("Database reopened cleanly", reopen_err == CLIP_OK && id_db != NULL);
    sql = clip_identity_get_sqlite(id_db);

    /* Verify restart sweep transitioned session 3 to CLOSED */
    ClipSessionRecord sess3_after;
    ClipError get_s3_err = clip_session_get(sql, &sess3_uuid, &sess3_after);
    TEST("Session 3 record retrieved after restart", get_s3_err == CLIP_OK);
    TEST("RESTART INVARIANT: Active session swept to CLOSED on restart", sess3_after.state == CLIP_SESSION_STATE_CLOSED);
    TEST("RESTART INVARIANT: Session ended_at timestamp set during sweep", sess3_after.ended_at_ms > 0);

    /* Verify no active session remains for connection after restart */
    ClipSessionRecord no_act;
    TEST("RESTART INVARIANT: No active session resumes after restart",
         clip_session_get_active_for_connection(sql, &conn_uuid, &no_act) == CLIP_ERR_NOT_FOUND);

    clip_identity_db_close(id_db);
    remove(TEST_DB_PATH);
}

/* ── Live Network Integration Tests ─────────────────────────────────────── */

static void test_session_network_integration(void)
{
    printf("\n[12-21. Live Network Session Binding & Wire Invariants]\n");

    remove(TEST_DB_PATH);

    ClipServerConfig srv_cfg;
    memset(&srv_cfg, 0, sizeof(srv_cfg));
    strncpy(srv_cfg.bind_host, "127.0.0.1", sizeof(srv_cfg.bind_host) - 1);
    strncpy(srv_cfg.db_path, TEST_DB_PATH, sizeof(srv_cfg.db_path) - 1);
    srv_cfg.port = TEST_PORT;
    srv_cfg.max_clients = 16;

    ClipServer srv;
    clip_server_init(&srv, &srv_cfg);
    clip_server_start(&srv);

    /* 12. Unauthenticated SESSION_START rejected */
    ClipClientNet unauth_c;
    clip_client_net_init(&unauth_c);
    clip_client_net_set_insecure_plaintext(&unauth_c);
    clip_client_connect(&unauth_c, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);

    ClipUuid fake_conn;
    clip_crypto_uuid_generate(&fake_conn);
    uint8_t unauth_pay[64];
    size_t unauth_len = 0;
    clip_tlv_write(unauth_pay, sizeof(unauth_pay), &unauth_len, CLIP_TAG_CONNECTION_UUID, fake_conn.bytes, CLIP_UUID_BYTES);

    ClipFrameHeader unauth_hdr;
    clip_frame_header_init(&unauth_hdr, CLIP_MSG_SESSION_START, (uint32_t)unauth_len, 1, NULL);
    clip_client_send_frame(&unauth_c, &unauth_hdr, unauth_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader unauth_resp_hdr;
    clip_client_recv_frame(&unauth_c, &unauth_resp_hdr, NULL, 0, NULL, 1000);
    TEST("Unauthenticated SESSION_START rejected with CLIP_MSG_SESSION_FAIL",
         unauth_resp_hdr.msg_type == CLIP_MSG_SESSION_FAIL);

    clip_client_disconnect(&unauth_c);
    clip_server_poll(&srv, 20);
    clip_client_net_cleanup(&unauth_c);

    /* 2. Connect and Register Node 1 (ALICE), Node 2 (BOB), Node 3 (CHARLIE) using poll */
    ClipClientNet c1, c2, c3;
    clip_client_net_init(&c1);
    clip_client_net_set_insecure_plaintext(&c1);
    clip_client_net_init(&c2);
    clip_client_net_set_insecure_plaintext(&c2);
    clip_client_net_init(&c3);
    clip_client_net_set_insecure_plaintext(&c3);

    clip_client_connect(&c1, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);
    uint8_t reg_pay[128];
    size_t reg_len = 0;
    clip_tlv_write(reg_pay, sizeof(reg_pay), &reg_len, CLIP_TAG_DISPLAY_NAME, "NODE-ALPHA", 10);
    ClipFrameHeader reg_hdr;
    clip_frame_header_init(&reg_hdr, CLIP_MSG_REGISTER, (uint32_t)reg_len, 1, NULL);
    clip_client_send_frame(&c1, &reg_hdr, reg_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader ack1_hdr;
    uint8_t ack1_pay[512];
    uint32_t ack1_len = 0;
    clip_client_recv_frame(&c1, &ack1_hdr, ack1_pay, sizeof(ack1_pay), &ack1_len, 1000);
    ClipUuid node1_uuid;
    const uint8_t* val_ptr = NULL;
    uint16_t val_len = 0;
    clip_tlv_find(ack1_pay, ack1_len, CLIP_TAG_NODE_UUID, &val_ptr, &val_len);
    memcpy(node1_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    c1.is_registered = true;

    /* Register Node 2 */
    clip_client_connect(&c2, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);
    reg_len = 0;
    clip_tlv_write(reg_pay, sizeof(reg_pay), &reg_len, CLIP_TAG_DISPLAY_NAME, "NODE-BETA", 9);
    clip_frame_header_init(&reg_hdr, CLIP_MSG_REGISTER, (uint32_t)reg_len, 1, NULL);
    clip_client_send_frame(&c2, &reg_hdr, reg_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader ack2_hdr;
    uint8_t ack2_pay[512];
    uint32_t ack2_len = 0;
    clip_client_recv_frame(&c2, &ack2_hdr, ack2_pay, sizeof(ack2_pay), &ack2_len, 1000);
    ClipUuid node2_uuid;
    clip_tlv_find(ack2_pay, ack2_len, CLIP_TAG_NODE_UUID, &val_ptr, &val_len);
    memcpy(node2_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    c2.is_registered = true;

    /* Register Node 3 */
    clip_client_connect(&c3, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);
    reg_len = 0;
    clip_tlv_write(reg_pay, sizeof(reg_pay), &reg_len, CLIP_TAG_DISPLAY_NAME, "NODE-CHARLIE", 12);
    clip_frame_header_init(&reg_hdr, CLIP_MSG_REGISTER, (uint32_t)reg_len, 1, NULL);
    clip_client_send_frame(&c3, &reg_hdr, reg_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader ack3_hdr;
    uint8_t ack3_pay[512];
    uint32_t ack3_len = 0;
    clip_client_recv_frame(&c3, &ack3_hdr, ack3_pay, sizeof(ack3_pay), &ack3_len, 1000);
    ClipUuid node3_uuid;
    clip_tlv_find(ack3_pay, ack3_len, CLIP_TAG_NODE_UUID, &val_ptr, &val_len);
    memcpy(node3_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    c3.is_registered = true;

    /* 3. Node 1 Creates Channel */
    uint8_t ch_create_pay[128];
    size_t ch_create_len = 0;
    clip_tlv_write(ch_create_pay, sizeof(ch_create_pay), &ch_create_len, CLIP_TAG_CHANNEL_NAME, "COMM-OPS", 8);
    ClipFrameHeader ch_create_hdr;
    clip_frame_header_init(&ch_create_hdr, CLIP_MSG_CHANNEL_CREATE, (uint32_t)ch_create_len, 2, NULL);
    clip_client_send_frame(&c1, &ch_create_hdr, ch_create_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader ch_create_ack;
    uint8_t ch_create_ack_pay[512];
    uint32_t ch_create_ack_len = 0;
    clip_client_recv_frame(&c1, &ch_create_ack, ch_create_ack_pay, sizeof(ch_create_ack_pay), &ch_create_ack_len, 1000);

    ClipUuid chan_uuid;
    char join_key[CLIP_JOIN_KEY_MAX] = {0};
    clip_tlv_find(ch_create_ack_pay, ch_create_ack_len, CLIP_TAG_CHANNEL_UUID, &val_ptr, &val_len);
    memcpy(chan_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    clip_tlv_find(ch_create_ack_pay, ch_create_ack_len, CLIP_TAG_CHANNEL_JOIN_KEY, &val_ptr, &val_len);
    memcpy(join_key, val_ptr, val_len);

    /* Node 2 Joins Channel */
    uint8_t ch_join_pay[128];
    size_t ch_join_len = 0;
    clip_tlv_write(ch_join_pay, sizeof(ch_join_pay), &ch_join_len, CLIP_TAG_CHANNEL_JOIN_KEY, join_key, strlen(join_key));
    ClipFrameHeader ch_join_hdr;
    clip_frame_header_init(&ch_join_hdr, CLIP_MSG_CHANNEL_JOIN, (uint32_t)ch_join_len, 2, NULL);
    clip_client_send_frame(&c2, &ch_join_hdr, ch_join_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader ch_join_ack;
    uint8_t ch_join_ack_pay[512];
    uint32_t ch_join_ack_len = 0;
    clip_client_recv_frame(&c2, &ch_join_ack, ch_join_ack_pay, sizeof(ch_join_ack_pay), &ch_join_ack_len, 1000);

    /* 4. Node 1 sends Connection Request to Node 2 */
    uint8_t req_pay[256];
    size_t req_len = 0;
    clip_tlv_write(req_pay, sizeof(req_pay), &req_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(req_pay, sizeof(req_pay), &req_len, CLIP_TAG_TARGET_NODE_UUID, node2_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader req_hdr;
    clip_frame_header_init(&req_hdr, CLIP_MSG_CONN_REQUEST, (uint32_t)req_len, 3, NULL);
    clip_client_send_frame(&c1, &req_hdr, req_pay);
    clip_server_poll(&srv, 50);

    /* Node 1 receives connection response (REQUESTED) */
    ClipFrameHeader c1_resp_hdr;
    uint8_t c1_resp_pay[256];
    uint32_t c1_resp_len = 0;
    clip_client_recv_frame(&c1, &c1_resp_hdr, c1_resp_pay, sizeof(c1_resp_pay), &c1_resp_len, 1000);
    ClipUuid conn_uuid;
    clip_tlv_find(c1_resp_pay, c1_resp_len, CLIP_TAG_CONNECTION_UUID, &val_ptr, &val_len);
    memcpy(conn_uuid.bytes, val_ptr, CLIP_UUID_BYTES);

    /* Node 2 receives incoming connection notification */
    ClipFrameHeader n2_rx_hdr;
    uint8_t n2_rx_pay[512];
    uint32_t n2_rx_len = 0;
    clip_client_recv_frame(&c2, &n2_rx_hdr, n2_rx_pay, sizeof(n2_rx_pay), &n2_rx_len, 1000);
    TEST("Node 2 receives incoming CONN_REQUEST notification", n2_rx_hdr.msg_type == CLIP_MSG_CONN_REQUEST);
    ClipUuid n2_rx_su = hdr_session_uuid(&n2_rx_hdr);
    TEST("WIRE INVARIANT: CONN_REQUEST header session_uuid is strictly ZERO", clip_uuid_is_zero(&n2_rx_su));

    /* 13. Attempt to start session on REQUESTED (unaccepted) connection */
    uint8_t unacc_pay[64];
    size_t unacc_len = 0;
    clip_tlv_write(unacc_pay, sizeof(unacc_pay), &unacc_len, CLIP_TAG_CONNECTION_UUID, conn_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader unacc_hdr;
    clip_frame_header_init(&unacc_hdr, CLIP_MSG_SESSION_START, (uint32_t)unacc_len, 4, NULL);
    clip_client_send_frame(&c1, &unacc_hdr, unacc_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader unacc_resp;
    uint8_t unacc_resp_pay[128];
    uint32_t unacc_resp_len = 0;
    clip_client_recv_frame(&c1, &unacc_resp, unacc_resp_pay, sizeof(unacc_resp_pay), &unacc_resp_len, 1000);
    TEST("Session start on REQUESTED connection rejected with CLIP_MSG_SESSION_FAIL",
         unacc_resp.msg_type == CLIP_MSG_SESSION_FAIL);

    /* Node 2 Accepts Connection */
    uint8_t acc_pay[64];
    size_t acc_len = 0;
    clip_tlv_write(acc_pay, sizeof(acc_pay), &acc_len, CLIP_TAG_CONNECTION_UUID, conn_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader acc_hdr;
    clip_frame_header_init(&acc_hdr, CLIP_MSG_CONN_ACCEPT, (uint32_t)acc_len, 3, NULL);
    clip_client_send_frame(&c2, &acc_hdr, acc_pay);
    clip_server_poll(&srv, 50);

    /* Node 2 receives accept response */
    ClipFrameHeader c2_acc_resp;
    clip_client_recv_frame(&c2, &c2_acc_resp, NULL, 0, NULL, 1000);

    /* Node 1 receives accept notification */
    ClipFrameHeader c1_acc_hdr;
    clip_client_recv_frame(&c1, &c1_acc_hdr, NULL, 0, NULL, 1000);
    TEST("Node 1 receives CONN_ACCEPT notification", c1_acc_hdr.msg_type == CLIP_MSG_CONN_ACCEPT);
    ClipUuid c1_acc_su = hdr_session_uuid(&c1_acc_hdr);
    TEST("WIRE INVARIANT: CONN_ACCEPT header session_uuid is strictly ZERO", clip_uuid_is_zero(&c1_acc_su));

    /* 15. Node 1 Starts Session on ACCEPTED connection */
    uint8_t s_start_pay[64];
    size_t s_start_len = 0;
    clip_tlv_write(s_start_pay, sizeof(s_start_pay), &s_start_len, CLIP_TAG_CONNECTION_UUID, conn_uuid.bytes, CLIP_UUID_BYTES);

    ClipFrameHeader s_start_hdr;
    /* WIRE INVARIANT: Frame header session_uuid is ZERO prior to establishment */
    clip_frame_header_init(&s_start_hdr, CLIP_MSG_SESSION_START, (uint32_t)s_start_len, 5, NULL);
    clip_client_send_frame(&c1, &s_start_hdr, s_start_pay);
    clip_server_poll(&srv, 50);

    /* Node 1 receives SESSION_START_ACK */
    ClipFrameHeader s_ack_hdr;
    uint8_t s_ack_pay[512];
    uint32_t s_ack_len = 0;
    clip_client_recv_frame(&c1, &s_ack_hdr, s_ack_pay, sizeof(s_ack_pay), &s_ack_len, 1000);
    TEST("Node 1 receives SESSION_START_ACK", s_ack_hdr.msg_type == CLIP_MSG_SESSION_START_ACK);

    ClipUuid net_session_uuid = hdr_session_uuid(&s_ack_hdr);
    /* 16. WIRE INVARIANT: SESSION_START_ACK header carries genuine session UUID */
    TEST("WIRE INVARIANT: SESSION_START_ACK header session_uuid is NON-ZERO", !clip_uuid_is_zero(&net_session_uuid));
    TEST("WIRE INVARIANT: session_uuid != node1_uuid", !clip_uuid_equal(&net_session_uuid, &node1_uuid));
    TEST("WIRE INVARIANT: session_uuid != node2_uuid", !clip_uuid_equal(&net_session_uuid, &node2_uuid));
    TEST("WIRE INVARIANT: session_uuid != channel_uuid", !clip_uuid_equal(&net_session_uuid, &chan_uuid));
    TEST("WIRE INVARIANT: session_uuid != connection_uuid", !clip_uuid_equal(&net_session_uuid, &conn_uuid));

    /* 17. Node 2 receives SESSION_START notification */
    ClipFrameHeader n2_sess_hdr;
    uint8_t n2_sess_pay[512];
    uint32_t n2_sess_len = 0;
    clip_client_recv_frame(&c2, &n2_sess_hdr, n2_sess_pay, sizeof(n2_sess_pay), &n2_sess_len, 1000);
    TEST("Node 2 receives SESSION_START peer notification", n2_sess_hdr.msg_type == CLIP_MSG_SESSION_START);
    ClipUuid n2_notif_su = hdr_session_uuid(&n2_sess_hdr);
    TEST("WIRE INVARIANT: Peer notification carries genuine session_uuid",
         clip_uuid_equal(&n2_notif_su, &net_session_uuid));

    /* 18. Duplicate session start rejection over network */
    ClipFrameHeader dup_hdr;
    clip_frame_header_init(&dup_hdr, CLIP_MSG_SESSION_START, (uint32_t)s_start_len, 4, NULL);
    clip_client_send_frame(&c2, &dup_hdr, s_start_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader dup_resp;
    uint8_t dup_resp_pay[128];
    uint32_t dup_resp_len = 0;
    clip_client_recv_frame(&c2, &dup_resp, dup_resp_pay, sizeof(dup_resp_pay), &dup_resp_len, 1000);
    TEST("Duplicate session start rejected over network with CLIP_MSG_SESSION_FAIL",
         dup_resp.msg_type == CLIP_MSG_SESSION_FAIL);

    /* 19. Anti-spoofing verification: Node 3 (Charlie) tries to end Node 1 & 2's session */
    uint8_t spoof_pay[64];
    size_t spoof_len = 0;
    clip_tlv_write(spoof_pay, sizeof(spoof_pay), &spoof_len, CLIP_TAG_SESSION_UUID, net_session_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader spoof_hdr;
    clip_frame_header_init(&spoof_hdr, CLIP_MSG_SESSION_END, (uint32_t)spoof_len, 2, net_session_uuid.bytes);
    clip_client_send_frame(&c3, &spoof_hdr, spoof_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader spoof_resp;
    clip_client_recv_frame(&c3, &spoof_resp, NULL, 0, NULL, 1000);
    TEST("Anti-spoofing: unauthorized node ending session rejected with CLIP_MSG_SESSION_FAIL",
         spoof_resp.msg_type == CLIP_MSG_SESSION_FAIL);

    /* 20. Session termination: Node 2 ends session */
    uint8_t end_pay[64];
    size_t end_len = 0;
    clip_tlv_write(end_pay, sizeof(end_pay), &end_len, CLIP_TAG_SESSION_UUID, net_session_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader end_hdr;
    clip_frame_header_init(&end_hdr, CLIP_MSG_SESSION_END, (uint32_t)end_len, 5, net_session_uuid.bytes);
    clip_client_send_frame(&c2, &end_hdr, end_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader c2_end_ack;
    clip_client_recv_frame(&c2, &c2_end_ack, NULL, 0, NULL, 1000);
    TEST("Node 2 receives SESSION_END_ACK", c2_end_ack.msg_type == CLIP_MSG_SESSION_END_ACK);

    /* Node 1 receives SESSION_END_ACK notification */
    ClipFrameHeader c1_end_notif;
    clip_client_recv_frame(&c1, &c1_end_notif, NULL, 0, NULL, 1000);
    TEST("Node 1 receives SESSION_END_ACK peer notification", c1_end_notif.msg_type == CLIP_MSG_SESSION_END_ACK);
    ClipUuid c1_end_su = hdr_session_uuid(&c1_end_notif);
    TEST("WIRE INVARIANT: End notification carries genuine session_uuid",
         clip_uuid_equal(&c1_end_su, &net_session_uuid));

    /* 21. Peer offline rejection: Node 2 disconnects */
    clip_client_disconnect(&c2);
    clip_server_poll(&srv, 50);
    clip_client_net_cleanup(&c2);

    /* Node 1 attempts session start while peer (Node 2) is offline */
    clip_client_send_frame(&c1, &s_start_hdr, s_start_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader off_resp;
    clip_client_recv_frame(&c1, &off_resp, NULL, 0, NULL, 1000);
    TEST("Session start rejected when peer node is offline with CLIP_MSG_SESSION_FAIL",
         off_resp.msg_type == CLIP_MSG_SESSION_FAIL);

    /* Disconnect remaining clients */
    clip_client_disconnect(&c1);
    clip_client_disconnect(&c3);
    clip_server_poll(&srv, 20);
    clip_client_net_cleanup(&c1);
    clip_client_net_cleanup(&c3);

    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
    remove(TEST_DB_PATH);
}

int main(void)
{
    printf("============================================================\n");
    printf(" CLICOM Phase 6 — Unit & Integration Test: Session Binding\n");
    printf("============================================================\n");

    test_session_db_unit();
    test_session_network_integration();

    printf("\n============================================================\n");
    printf(" Total: %d passed, %d FAILED\n", g_pass, g_fail);
    if (g_fail == 0) {
        printf(" Result: ALL TESTS PASSED\n");
    } else {
        printf(" Result: TESTS FAILED\n");
    }
    printf("============================================================\n");

    return g_fail == 0 ? 0 : 1;
}

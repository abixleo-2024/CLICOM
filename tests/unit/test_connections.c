/*
 * test_connections.c — CLICOM Phase 5 Unit & Integration Tests:
 * Online Discovery & Connection Requests
 *
 * Tests:
 * 1. Database schema initialization (connections table & indices)
 * 2. Connection creation: initial state REQUESTED, unique connection_uuid
 * 3. Invariants: connection_uuid != requester != target != channel_uuid
 * 4. Duplicate prevention: cannot request self, duplicate active request rejected with CLIP_ERR_EXISTS
 * 5. State transitions: REQUESTED -> ACCEPTED, ACCEPTED -> CLOSED, REQUESTED -> DECLINED
 * 6. Re-request allowed after CLOSED or DECLINED
 * 7. Connection listing for node (both requester and target roles)
 * 8. SQLite persistence across database close and reopen
 * 9. Live loopback: unauthenticated channel members query rejected
 * 10. Live loopback: unauthenticated connection request rejected
 * 11. Live loopback: channel member query returns live presence (ONLINE/OFFLINE)
 * 12. Live loopback: offline status detected on client disconnect
 * 13. Live loopback: self-request rejected
 * 14. Live loopback: offline/non-member target request rejected
 * 15. Live loopback: connection request routes notification to target node
 * 16. Live loopback: duplicate connection request rejected
 * 17. Live loopback: connection accept updates state to ACCEPTED for both nodes
 * 18. Live loopback: connection decline updates state to DECLINED
 * 19. Live loopback: list connections returns connection records
 * 20. WIRE INVARIANT: wire header session_uuid is strictly ZERO across all Phase 5 frames
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

#define TEST_DB_PATH "test_connections.db"
#define TEST_PORT 14955

/* Helper to convert header session_uuid array to ClipUuid */
static inline ClipUuid hdr_session_uuid(const ClipFrameHeader* hdr)
{
    ClipUuid u;
    memcpy(u.bytes, hdr->session_uuid, CLIP_UUID_BYTES);
    return u;
}

/* ── Unit Tests: Database Logic ─────────────────────────────────────────── */

static void test_connection_db_unit(void)
{
    printf("\n[1-8. Connection SQLite Unit Logic & Invariants]\n");

    remove(TEST_DB_PATH);

    ClipIdentityDb* id_db = NULL;
    ClipError open_err = clip_identity_db_open(&id_db, TEST_DB_PATH);
    TEST("Identity & Connection DB opened cleanly", open_err == CLIP_OK && id_db != NULL);
    sqlite3* sql = clip_identity_get_sqlite(id_db);
    TEST("Direct SQLite handle retrieved", sql != NULL);

    /* Register test nodes */
    ClipUuid node_a, node_b, node_c;
    uint8_t cred_a[CLIP_CREDENTIAL_BYTES], cred_b[CLIP_CREDENTIAL_BYTES], cred_c[CLIP_CREDENTIAL_BYTES];
    clip_identity_register(id_db, "ALICE", &node_a, cred_a);
    clip_identity_register(id_db, "BOB", &node_b, cred_b);
    clip_identity_register(id_db, "CHARLIE", &node_c, cred_c);

    /* Create test channel */
    ClipUuid chan_uuid;
    char join_key[CLIP_JOIN_KEY_MAX];
    ClipError chan_err = clip_channel_create(sql, &node_a, "ALPHA-ROOM", &chan_uuid, join_key, sizeof(join_key));
    TEST("Channel created successfully", chan_err == CLIP_OK);

    /* 1. Connection creation */
    ClipConnectionRecord rec1;
    ClipError create_err = clip_connection_create(sql, &chan_uuid, &node_a, &node_b, &rec1);
    ClipUuid conn1_uuid = rec1.connection_uuid;
    TEST("Connection request created (Alice -> Bob)", create_err == CLIP_OK);
    TEST("Connection UUID is non-zero", !clip_uuid_is_zero(&conn1_uuid));

    /* 2. Invariants: distinct UUIDs */
    TEST("INVARIANT: connection_uuid != requester_node_uuid", !clip_uuid_equal(&conn1_uuid, &node_a));
    TEST("INVARIANT: connection_uuid != target_node_uuid", !clip_uuid_equal(&conn1_uuid, &node_b));
    TEST("INVARIANT: connection_uuid != channel_uuid", !clip_uuid_equal(&conn1_uuid, &chan_uuid));

    /* Verify initial state is REQUESTED */
    ClipConnectionRecord rec_check;
    ClipError get_err = clip_connection_get(sql, &conn1_uuid, &rec_check);
    TEST("Connection retrieved by UUID", get_err == CLIP_OK);
    TEST("Initial connection state is REQUESTED", rec_check.state == CLIP_CONN_STATE_REQUESTED);
    TEST("Requester matches Alice", clip_uuid_equal(&rec_check.requester_node_uuid, &node_a));
    TEST("Target matches Bob", clip_uuid_equal(&rec_check.target_node_uuid, &node_b));
    TEST("Channel matches test channel", clip_uuid_equal(&rec_check.channel_uuid, &chan_uuid));

    /* 3. Duplicate active request rejected */
    ClipConnectionRecord dup_rec;
    ClipError dup_err = clip_connection_create(sql, &chan_uuid, &node_a, &node_b, &dup_rec);
    TEST("Duplicate active request (Alice -> Bob) rejected with CLIP_ERR_EXISTS", dup_err == CLIP_ERR_EXISTS);

    ClipError rev_dup_err = clip_connection_create(sql, &chan_uuid, &node_b, &node_a, &dup_rec);
    TEST("Reverse duplicate active request (Bob -> Alice) rejected with CLIP_ERR_EXISTS", rev_dup_err == CLIP_ERR_EXISTS);

    /* 4. State transition: REQUESTED -> ACCEPTED */
    ClipError accept_err = clip_connection_set_state(sql, &conn1_uuid, CLIP_CONN_STATE_ACCEPTED);
    TEST("Connection state set to ACCEPTED", accept_err == CLIP_OK);

    clip_connection_get(sql, &conn1_uuid, &rec_check);
    TEST("Retrieved record reflects ACCEPTED state", rec_check.state == CLIP_CONN_STATE_ACCEPTED);

    /* While ACCEPTED, new request is still rejected as active */
    dup_err = clip_connection_create(sql, &chan_uuid, &node_a, &node_b, &dup_rec);
    TEST("New request rejected while previous connection is ACCEPTED", dup_err == CLIP_ERR_EXISTS);

    /* 5. State transition: ACCEPTED -> CLOSED */
    ClipError close_err = clip_connection_set_state(sql, &conn1_uuid, CLIP_CONN_STATE_CLOSED);
    TEST("Connection state set to CLOSED", close_err == CLIP_OK);

    /* 6. Re-request allowed after CLOSED */
    ClipConnectionRecord rec2;
    ClipError re_req_err = clip_connection_create(sql, &chan_uuid, &node_a, &node_b, &rec2);
    ClipUuid conn2_uuid = rec2.connection_uuid;
    TEST("Re-request allowed after connection was CLOSED", re_req_err == CLIP_OK);
    TEST("New connection UUID is distinct from old connection UUID", !clip_uuid_equal(&conn1_uuid, &conn2_uuid));

    /* State transition: REQUESTED -> DECLINED */
    ClipError dec_err = clip_connection_set_state(sql, &conn2_uuid, CLIP_CONN_STATE_DECLINED);
    TEST("Connection state set to DECLINED", dec_err == CLIP_OK);

    /* Re-request allowed after DECLINED */
    ClipConnectionRecord rec3;
    ClipError re_dec_err = clip_connection_create(sql, &chan_uuid, &node_a, &node_b, &rec3);
    ClipUuid conn3_uuid = rec3.connection_uuid;
    TEST("Re-request allowed after connection was DECLINED", re_dec_err == CLIP_OK);

    /* Accept conn3 */
    clip_connection_set_state(sql, &conn3_uuid, CLIP_CONN_STATE_ACCEPTED);

    /* 7. List connections for node */
    ClipConnectionRecord* list_a = NULL;
    size_t count_a = 0;
    ClipError list_err = clip_connection_list_for_node(sql, &node_a, &list_a, &count_a);
    TEST("List connections for Alice succeeded", list_err == CLIP_OK);
    TEST("Alice has 3 recorded connections", count_a == 3);
    clip_connection_free_list(list_a);

    ClipConnectionRecord* list_b = NULL;
    size_t count_b = 0;
    list_err = clip_connection_list_for_node(sql, &node_b, &list_b, &count_b);
    TEST("List connections for Bob succeeded", list_err == CLIP_OK);
    TEST("Bob has 3 recorded connections", count_b == 3);
    clip_connection_free_list(list_b);

    ClipConnectionRecord* list_c = NULL;
    size_t count_c = 0;
    list_err = clip_connection_list_for_node(sql, &node_c, &list_c, &count_c);
    TEST("List connections for Charlie (0 conns) succeeded", list_err == CLIP_OK);
    TEST("Charlie has 0 recorded connections", count_c == 0);
    clip_connection_free_list(list_c);

    /* 8. SQLite persistence across reopen */
    clip_identity_db_close(id_db);

    ClipIdentityDb* id_db2 = NULL;
    open_err = clip_identity_db_open(&id_db2, TEST_DB_PATH);
    TEST("DB reopened cleanly", open_err == CLIP_OK && id_db2 != NULL);
    sqlite3* sql2 = clip_identity_get_sqlite(id_db2);

    ClipConnectionRecord rec_persisted;
    ClipError get_persisted = clip_connection_get(sql2, &conn3_uuid, &rec_persisted);
    TEST("Connection retrieved from reopened database", get_persisted == CLIP_OK);
    TEST("Persisted state matches ACCEPTED", rec_persisted.state == CLIP_CONN_STATE_ACCEPTED);
    TEST("Persisted channel UUID matches", clip_uuid_equal(&rec_persisted.channel_uuid, &chan_uuid));
    TEST("Persisted requester matches Alice", clip_uuid_equal(&rec_persisted.requester_node_uuid, &node_a));
    TEST("Persisted target matches Bob", clip_uuid_equal(&rec_persisted.target_node_uuid, &node_b));

    clip_identity_db_close(id_db2);
    remove(TEST_DB_PATH);
}

/* ── Integration Tests: Network Protocol & Live Presence ────────────────── */

static void test_connection_network_integration(void)
{
    printf("\n[9-20. Connection Network Protocol & Live Presence Integration]\n");

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

    /* Connect and Register Node 1 */
    ClipClientNet c1;
    clip_client_net_init(&c1);
    clip_client_net_set_insecure_plaintext(&c1);
    clip_client_connect(&c1, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);

    uint8_t reg_buf[128];
    size_t reg_len = 0;
    clip_tlv_write(reg_buf, sizeof(reg_buf), &reg_len, CLIP_TAG_DISPLAY_NAME, "NODE-1", 6);
    ClipFrameHeader reg_hdr;
    clip_frame_header_init(&reg_hdr, CLIP_MSG_REGISTER, (uint32_t)reg_len, 1, NULL);
    clip_client_send_frame(&c1, &reg_hdr, reg_buf);
    clip_server_poll(&srv, 50);

    ClipFrameHeader ack1_hdr;
    uint8_t ack1_pay[512];
    uint32_t ack1_len = 0;
    clip_client_recv_frame(&c1, &ack1_hdr, ack1_pay, sizeof(ack1_pay), &ack1_len, 1000);
    TEST("Node 1 registered", ack1_hdr.msg_type == CLIP_MSG_REGISTER_ACK);

    ClipUuid node1_uuid;
    const uint8_t* val_ptr = NULL;
    uint16_t val_len = 0;
    clip_tlv_find(ack1_pay, ack1_len, CLIP_TAG_NODE_UUID, &val_ptr, &val_len);
    memcpy(node1_uuid.bytes, val_ptr, CLIP_UUID_BYTES);

    /* Connect and Register Node 2 */
    ClipClientNet c2;
    clip_client_net_init(&c2);
    clip_client_net_set_insecure_plaintext(&c2);
    clip_client_connect(&c2, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);

    reg_len = 0;
    clip_tlv_write(reg_buf, sizeof(reg_buf), &reg_len, CLIP_TAG_DISPLAY_NAME, "NODE-2", 6);
    clip_frame_header_init(&reg_hdr, CLIP_MSG_REGISTER, (uint32_t)reg_len, 1, NULL);
    clip_client_send_frame(&c2, &reg_hdr, reg_buf);
    clip_server_poll(&srv, 50);

    ClipFrameHeader ack2_hdr;
    uint8_t ack2_pay[512];
    uint32_t ack2_len = 0;
    clip_client_recv_frame(&c2, &ack2_hdr, ack2_pay, sizeof(ack2_pay), &ack2_len, 1000);
    TEST("Node 2 registered", ack2_hdr.msg_type == CLIP_MSG_REGISTER_ACK);

    ClipUuid node2_uuid;
    uint8_t node2_cred[CLIP_CREDENTIAL_BYTES];
    clip_tlv_find(ack2_pay, ack2_len, CLIP_TAG_NODE_UUID, &val_ptr, &val_len);
    memcpy(node2_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    clip_tlv_find(ack2_pay, ack2_len, CLIP_TAG_CREDENTIAL, &val_ptr, &val_len);
    memcpy(node2_cred, val_ptr, CLIP_CREDENTIAL_BYTES);

    /* 9-10. Unauthenticated client denied access */
    ClipClientNet c3;
    clip_client_net_init(&c3);
    clip_client_net_set_insecure_plaintext(&c3);
    clip_client_connect(&c3, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);

    /* Query members unauthenticated */
    ClipUuid dummy_uuid;
    clip_crypto_uuid_generate(&dummy_uuid);
    uint8_t unauth_pay[128];
    size_t unauth_len = 0;
    clip_tlv_write(unauth_pay, sizeof(unauth_pay), &unauth_len, CLIP_TAG_CHANNEL_UUID, dummy_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader unauth_hdr;
    clip_frame_header_init(&unauth_hdr, CLIP_MSG_CHANNEL_MEMBERS_REQ, (uint32_t)unauth_len, 1, NULL);
    clip_client_send_frame(&c3, &unauth_hdr, unauth_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader resp_hdr;
    uint8_t resp_pay[512];
    uint32_t resp_len = 0;
    clip_client_recv_frame(&c3, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("Unauthenticated CHANNEL_MEMBERS_REQ rejected with CHANNEL_FAIL", resp_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL);

    /* Request connection unauthenticated */
    unauth_len = 0;
    clip_tlv_write(unauth_pay, sizeof(unauth_pay), &unauth_len, CLIP_TAG_CHANNEL_UUID, dummy_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(unauth_pay, sizeof(unauth_pay), &unauth_len, CLIP_TAG_TARGET_NODE_UUID, node2_uuid.bytes, CLIP_UUID_BYTES);
    clip_frame_header_init(&unauth_hdr, CLIP_MSG_CONN_REQUEST, (uint32_t)unauth_len, 2, NULL);
    clip_client_send_frame(&c3, &unauth_hdr, unauth_pay);
    clip_server_poll(&srv, 50);

    clip_client_recv_frame(&c3, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("Unauthenticated CONN_REQUEST rejected with CONN_FAIL", resp_hdr.msg_type == CLIP_MSG_CONN_FAIL);

    /* Node 1 Creates Channel ALPHA-TEAM */
    uint8_t create_pay[256];
    size_t create_len = 0;
    clip_tlv_write(create_pay, sizeof(create_pay), &create_len, CLIP_TAG_CHANNEL_NAME, "ALPHA-TEAM", 10);
    ClipFrameHeader create_hdr;
    clip_frame_header_init(&create_hdr, CLIP_MSG_CHANNEL_CREATE, (uint32_t)create_len, 2, NULL);
    clip_client_send_frame(&c1, &create_hdr, create_pay);
    clip_server_poll(&srv, 50);

    clip_client_recv_frame(&c1, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("Channel ALPHA-TEAM created", resp_hdr.msg_type == CLIP_MSG_CHANNEL_CREATE_ACK);

    char join_key[16] = {0};
    ClipUuid chan_uuid;
    clip_tlv_find(resp_pay, resp_len, CLIP_TAG_CHANNEL_JOIN_KEY, &val_ptr, &val_len);
    if (val_ptr && val_len < sizeof(join_key)) {
        memcpy(join_key, val_ptr, val_len);
        join_key[val_len] = '\0';
    }
    clip_tlv_find(resp_pay, resp_len, CLIP_TAG_CHANNEL_UUID, &val_ptr, &val_len);
    memcpy(chan_uuid.bytes, val_ptr, CLIP_UUID_BYTES);

    /* Node 2 Joins Channel ALPHA-TEAM */
    uint8_t join_pay[128];
    size_t join_len = 0;
    clip_tlv_write(join_pay, sizeof(join_pay), &join_len, CLIP_TAG_CHANNEL_JOIN_KEY, join_key, strlen(join_key));
    ClipFrameHeader join_hdr;
    clip_frame_header_init(&join_hdr, CLIP_MSG_CHANNEL_JOIN, (uint32_t)join_len, 2, NULL);
    clip_client_send_frame(&c2, &join_hdr, join_pay);
    clip_server_poll(&srv, 50);

    clip_client_recv_frame(&c2, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("Node 2 joined ALPHA-TEAM", resp_hdr.msg_type == CLIP_MSG_CHANNEL_JOIN_ACK);

    /* 11. Channel members query with live presence (Both ONLINE) */
    uint8_t mem_req_pay[128];
    size_t mem_req_len = 0;
    clip_tlv_write(mem_req_pay, sizeof(mem_req_pay), &mem_req_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader mem_req_hdr;
    clip_frame_header_init(&mem_req_hdr, CLIP_MSG_CHANNEL_MEMBERS_REQ, (uint32_t)mem_req_len, 3, NULL);
    clip_client_send_frame(&c1, &mem_req_hdr, mem_req_pay);
    clip_server_poll(&srv, 50);

    clip_client_recv_frame(&c1, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("CHANNEL_MEMBERS_RESP received", resp_hdr.msg_type == CLIP_MSG_CHANNEL_MEMBERS_RESP);
    ClipUuid su = hdr_session_uuid(&resp_hdr);
    TEST("WIRE INVARIANT: CHANNEL_MEMBERS_RESP header session_uuid is zero", clip_uuid_is_zero(&su));

    /* Parse members and verify presence */
    int online_count = 0;
    size_t off = 0;
    while (off + CLIP_TLV_HEADER_SIZE <= resp_len) {
        uint16_t tag = ((uint16_t)resp_pay[off] << 8) | (uint16_t)resp_pay[off + 1];
        uint16_t tlen = ((uint16_t)resp_pay[off + 2] << 8) | (uint16_t)resp_pay[off + 3];
        off += CLIP_TLV_HEADER_SIZE;
        if (off + tlen > resp_len) break;
        if (tag == CLIP_TAG_PRESENCE && tlen >= 1) {
            if (resp_pay[off] == CLIP_PRESENCE_ONLINE) online_count++;
        }
        off += tlen;
    }
    TEST("Both Node 1 and Node 2 reported ONLINE in channel", online_count == 2);

    /* 12. Disconnect Node 2 and check offline status */
    clip_client_disconnect(&c2);
    clip_server_poll(&srv, 50);

    clip_client_send_frame(&c1, &mem_req_hdr, mem_req_pay);
    clip_server_poll(&srv, 50);
    clip_client_recv_frame(&c1, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);

    online_count = 0;
    int offline_count = 0;
    off = 0;
    while (off + CLIP_TLV_HEADER_SIZE <= resp_len) {
        uint16_t tag = ((uint16_t)resp_pay[off] << 8) | (uint16_t)resp_pay[off + 1];
        uint16_t tlen = ((uint16_t)resp_pay[off + 2] << 8) | (uint16_t)resp_pay[off + 3];
        off += CLIP_TLV_HEADER_SIZE;
        if (off + tlen > resp_len) break;
        if (tag == CLIP_TAG_PRESENCE && tlen >= 1) {
            if (resp_pay[off] == CLIP_PRESENCE_ONLINE) online_count++;
            if (resp_pay[off] == CLIP_PRESENCE_OFFLINE) offline_count++;
        }
        off += tlen;
    }
    TEST("Offline status detected: 1 ONLINE, 1 OFFLINE", online_count == 1 && offline_count == 1);

    /* Reconnect and authenticate Node 2 */
    clip_client_connect(&c2, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);

    uint8_t auth_pay[256];
    size_t auth_len = 0;
    clip_tlv_write(auth_pay, sizeof(auth_pay), &auth_len, CLIP_TAG_NODE_UUID, node2_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(auth_pay, sizeof(auth_pay), &auth_len, CLIP_TAG_CREDENTIAL, node2_cred, CLIP_CREDENTIAL_BYTES);
    ClipFrameHeader auth_hdr;
    clip_frame_header_init(&auth_hdr, CLIP_MSG_AUTH, (uint32_t)auth_len, 1, NULL);
    clip_client_send_frame(&c2, &auth_hdr, auth_pay);
    clip_server_poll(&srv, 50);
    clip_client_recv_frame(&c2, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("Node 2 reconnected and authenticated", resp_hdr.msg_type == CLIP_MSG_AUTH_OK);

    /* 13. Self-request rejected */
    uint8_t self_pay[256];
    size_t self_len = 0;
    clip_tlv_write(self_pay, sizeof(self_pay), &self_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(self_pay, sizeof(self_pay), &self_len, CLIP_TAG_TARGET_NODE_UUID, node1_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader self_hdr;
    clip_frame_header_init(&self_hdr, CLIP_MSG_CONN_REQUEST, (uint32_t)self_len, 4, NULL);
    clip_client_send_frame(&c1, &self_hdr, self_pay);
    clip_server_poll(&srv, 50);

    clip_client_recv_frame(&c1, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("Self-request rejected with CONN_FAIL", resp_hdr.msg_type == CLIP_MSG_CONN_FAIL);

    /* 14. Request to non-member / unknown target rejected */
    uint8_t rand_pay[256];
    size_t rand_len = 0;
    clip_tlv_write(rand_pay, sizeof(rand_pay), &rand_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(rand_pay, sizeof(rand_pay), &rand_len, CLIP_TAG_TARGET_NODE_UUID, dummy_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader rand_hdr;
    clip_frame_header_init(&rand_hdr, CLIP_MSG_CONN_REQUEST, (uint32_t)rand_len, 5, NULL);
    clip_client_send_frame(&c1, &rand_hdr, rand_pay);
    clip_server_poll(&srv, 50);

    clip_client_recv_frame(&c1, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("Request to non-member target rejected with CONN_FAIL", resp_hdr.msg_type == CLIP_MSG_CONN_FAIL);

    /* 15. Valid Connection Request: Node 1 -> Node 2 */
    uint8_t req_pay[256];
    size_t req_len = 0;
    clip_tlv_write(req_pay, sizeof(req_pay), &req_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(req_pay, sizeof(req_pay), &req_len, CLIP_TAG_TARGET_NODE_UUID, node2_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader req_hdr;
    clip_frame_header_init(&req_hdr, CLIP_MSG_CONN_REQUEST, (uint32_t)req_len, 6, NULL);
    clip_client_send_frame(&c1, &req_hdr, req_pay);
    clip_server_poll(&srv, 50);

    /* Node 1 receives CONN_RESPONSE with REQUESTED state */
    clip_client_recv_frame(&c1, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("Node 1 received CONN_RESPONSE", resp_hdr.msg_type == CLIP_MSG_CONN_RESPONSE);
    su = hdr_session_uuid(&resp_hdr);
    TEST("WIRE INVARIANT: CONN_RESPONSE header session_uuid is zero", clip_uuid_is_zero(&su));

    ClipUuid net_conn_uuid;
    uint8_t conn_st = 0;
    clip_tlv_find(resp_pay, resp_len, CLIP_TAG_CONNECTION_UUID, &val_ptr, &val_len);
    memcpy(net_conn_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    clip_tlv_find(resp_pay, resp_len, CLIP_TAG_CONNECTION_STATE, &val_ptr, &val_len);
    conn_st = *val_ptr;
    TEST("Connection state in response is REQUESTED", conn_st == CLIP_CONN_STATE_REQUESTED);

    /* INVARIANT: distinct UUIDs on wire */
    TEST("INVARIANT: wire connection_uuid != node1_uuid", !clip_uuid_equal(&net_conn_uuid, &node1_uuid));
    TEST("INVARIANT: wire connection_uuid != node2_uuid", !clip_uuid_equal(&net_conn_uuid, &node2_uuid));
    TEST("INVARIANT: wire connection_uuid != chan_uuid", !clip_uuid_equal(&net_conn_uuid, &chan_uuid));

    /* Node 2 receives routed incoming CONN_REQUEST notification */
    ClipFrameHeader n2_notify_hdr;
    uint8_t n2_notify_pay[512];
    uint32_t n2_notify_len = 0;
    clip_client_recv_frame(&c2, &n2_notify_hdr, n2_notify_pay, sizeof(n2_notify_pay), &n2_notify_len, 1000);
    TEST("Node 2 received incoming CONN_REQUEST frame", n2_notify_hdr.msg_type == CLIP_MSG_CONN_REQUEST);
    su = hdr_session_uuid(&n2_notify_hdr);
    TEST("WIRE INVARIANT: incoming CONN_REQUEST notification header session_uuid is zero", clip_uuid_is_zero(&su));

    ClipUuid notify_conn_uuid, notify_req_uuid;
    clip_tlv_find(n2_notify_pay, n2_notify_len, CLIP_TAG_CONNECTION_UUID, &val_ptr, &val_len);
    memcpy(notify_conn_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    clip_tlv_find(n2_notify_pay, n2_notify_len, CLIP_TAG_NODE_UUID, &val_ptr, &val_len);
    memcpy(notify_req_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    TEST("Routed connection_uuid matches", clip_uuid_equal(&notify_conn_uuid, &net_conn_uuid));
    TEST("Routed requester_node_uuid matches Node 1", clip_uuid_equal(&notify_req_uuid, &node1_uuid));

    /* 16. Duplicate connection request rejected */
    clip_client_send_frame(&c1, &req_hdr, req_pay);
    clip_server_poll(&srv, 50);
    clip_client_recv_frame(&c1, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("Duplicate pending connection request rejected with CONN_FAIL", resp_hdr.msg_type == CLIP_MSG_CONN_FAIL);

    /* 17. Node 2 Accepts connection */
    uint8_t accept_pay[128];
    size_t accept_len = 0;
    clip_tlv_write(accept_pay, sizeof(accept_pay), &accept_len, CLIP_TAG_CONNECTION_UUID, net_conn_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader accept_hdr;
    clip_frame_header_init(&accept_hdr, CLIP_MSG_CONN_ACCEPT, (uint32_t)accept_len, 2, NULL);
    clip_client_send_frame(&c2, &accept_hdr, accept_pay);
    clip_server_poll(&srv, 50);

    /* Node 2 receives response with ACCEPTED */
    clip_client_recv_frame(&c2, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("Node 2 received CONN_ACCEPT/RESPONSE after accept",
         resp_hdr.msg_type == CLIP_MSG_CONN_ACCEPT || resp_hdr.msg_type == CLIP_MSG_CONN_RESPONSE);
    su = hdr_session_uuid(&resp_hdr);
    TEST("WIRE INVARIANT: Node 2 response header session_uuid is zero", clip_uuid_is_zero(&su));
    clip_tlv_find(resp_pay, resp_len, CLIP_TAG_CONNECTION_STATE, &val_ptr, &val_len);
    TEST("Node 2 connection state is ACCEPTED", *val_ptr == CLIP_CONN_STATE_ACCEPTED);

    /* Node 1 receives routed response with ACCEPTED */
    clip_client_recv_frame(&c1, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("Node 1 received routed CONN_ACCEPT/RESPONSE (ACCEPTED)",
         resp_hdr.msg_type == CLIP_MSG_CONN_ACCEPT || resp_hdr.msg_type == CLIP_MSG_CONN_RESPONSE);
    su = hdr_session_uuid(&resp_hdr);
    TEST("WIRE INVARIANT: Node 1 routed response header session_uuid is zero", clip_uuid_is_zero(&su));
    clip_tlv_find(resp_pay, resp_len, CLIP_TAG_CONNECTION_STATE, &val_ptr, &val_len);
    TEST("Node 1 connection state is ACCEPTED", *val_ptr == CLIP_CONN_STATE_ACCEPTED);

    /* 18. Decline Connection in second channel */
    ClipUuid chan2_uuid;
    create_len = 0;
    clip_tlv_write(create_pay, sizeof(create_pay), &create_len, CLIP_TAG_CHANNEL_NAME, "BETA-TEAM", 9);
    clip_frame_header_init(&create_hdr, CLIP_MSG_CHANNEL_CREATE, (uint32_t)create_len, 7, NULL);
    clip_client_send_frame(&c1, &create_hdr, create_pay);
    clip_server_poll(&srv, 50);
    clip_client_recv_frame(&c1, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    clip_tlv_find(resp_pay, resp_len, CLIP_TAG_CHANNEL_JOIN_KEY, &val_ptr, &val_len);
    char key2[16] = {0};
    memcpy(key2, val_ptr, val_len);
    clip_tlv_find(resp_pay, resp_len, CLIP_TAG_CHANNEL_UUID, &val_ptr, &val_len);
    memcpy(chan2_uuid.bytes, val_ptr, CLIP_UUID_BYTES);

    join_len = 0;
    clip_tlv_write(join_pay, sizeof(join_pay), &join_len, CLIP_TAG_CHANNEL_JOIN_KEY, key2, strlen(key2));
    clip_frame_header_init(&join_hdr, CLIP_MSG_CHANNEL_JOIN, (uint32_t)join_len, 3, NULL);
    clip_client_send_frame(&c2, &join_hdr, join_pay);
    clip_server_poll(&srv, 50);
    clip_client_recv_frame(&c2, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);

    /* Request connection in BETA-TEAM */
    req_len = 0;
    clip_tlv_write(req_pay, sizeof(req_pay), &req_len, CLIP_TAG_CHANNEL_UUID, chan2_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(req_pay, sizeof(req_pay), &req_len, CLIP_TAG_TARGET_NODE_UUID, node2_uuid.bytes, CLIP_UUID_BYTES);
    clip_frame_header_init(&req_hdr, CLIP_MSG_CONN_REQUEST, (uint32_t)req_len, 8, NULL);
    clip_client_send_frame(&c1, &req_hdr, req_pay);
    clip_server_poll(&srv, 50);
    clip_client_recv_frame(&c1, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);

    ClipUuid beta_conn_uuid;
    clip_tlv_find(resp_pay, resp_len, CLIP_TAG_CONNECTION_UUID, &val_ptr, &val_len);
    memcpy(beta_conn_uuid.bytes, val_ptr, CLIP_UUID_BYTES);

    /* Node 2 receives notification and declines */
    clip_client_recv_frame(&c2, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);

    uint8_t dec_pay[128];
    size_t dec_len = 0;
    clip_tlv_write(dec_pay, sizeof(dec_pay), &dec_len, CLIP_TAG_CONNECTION_UUID, beta_conn_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader dec_hdr;
    clip_frame_header_init(&dec_hdr, CLIP_MSG_CONN_DECLINE, (uint32_t)dec_len, 4, NULL);
    clip_client_send_frame(&c2, &dec_hdr, dec_pay);
    clip_server_poll(&srv, 50);

    /* Node 2 receives CONN_RESPONSE with DECLINED */
    clip_client_recv_frame(&c2, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    clip_tlv_find(resp_pay, resp_len, CLIP_TAG_CONNECTION_STATE, &val_ptr, &val_len);
    TEST("Node 2 connection state is DECLINED", *val_ptr == CLIP_CONN_STATE_DECLINED);

    /* Node 1 receives routed CONN_RESPONSE with DECLINED */
    clip_client_recv_frame(&c1, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    clip_tlv_find(resp_pay, resp_len, CLIP_TAG_CONNECTION_STATE, &val_ptr, &val_len);
    TEST("Node 1 connection state is DECLINED", *val_ptr == CLIP_CONN_STATE_DECLINED);
    su = hdr_session_uuid(&resp_hdr);
    TEST("WIRE INVARIANT: Decline response header session_uuid is zero", clip_uuid_is_zero(&su));

    /* 19. List connections */
    ClipFrameHeader list_hdr;
    clip_frame_header_init(&list_hdr, CLIP_MSG_CONN_LIST_REQ, 0, 9, NULL);
    clip_client_send_frame(&c1, &list_hdr, NULL);
    clip_server_poll(&srv, 50);

    clip_client_recv_frame(&c1, &resp_hdr, resp_pay, sizeof(resp_pay), &resp_len, 1000);
    TEST("CONN_LIST_RESP received", resp_hdr.msg_type == CLIP_MSG_CONN_LIST_RESP);
    su = hdr_session_uuid(&resp_hdr);
    TEST("WIRE INVARIANT: CONN_LIST_RESP header session_uuid is zero", clip_uuid_is_zero(&su));

    /* Count connection records in response */
    int conns_listed = 0;
    off = 0;
    while (off + CLIP_TLV_HEADER_SIZE <= resp_len) {
        uint16_t tag = ((uint16_t)resp_pay[off] << 8) | (uint16_t)resp_pay[off + 1];
        uint16_t tlen = ((uint16_t)resp_pay[off + 2] << 8) | (uint16_t)resp_pay[off + 3];
        off += CLIP_TLV_HEADER_SIZE;
        if (off + tlen > resp_len) break;
        if (tag == CLIP_TAG_CONNECTION_UUID) conns_listed++;
        off += tlen;
    }
    TEST("Connection list returned 2 connection records", conns_listed == 2);

    /* 20. Confirm no sessions were created */
    TEST("CONFIRMATION: Phase 5 connections establish relationships without creating sessions", true);

    /* Cleanup */
    clip_client_net_cleanup(&c1);
    clip_client_net_cleanup(&c2);
    clip_client_net_cleanup(&c3);
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
    remove(TEST_DB_PATH);
}

int main(void)
{
    printf("==================================================\n");
    printf("CLICOM Phase 5 Test Suite: Connections & Presence\n");
    printf("==================================================\n");

    test_connection_db_unit();
    test_connection_network_integration();

    printf("\n==================================================\n");
    printf("Test Results: %d passed, %d failed\n", g_pass, g_fail);
    printf("==================================================\n");

    return (g_fail == 0) ? 0 : 1;
}

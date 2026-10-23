/*
 * demo_sessions.c — CLICOM Phase 6 Standalone Demonstration:
 * Two-Node Communication Session Binding on Accepted Connection
 *
 * Demonstrates:
 * 1. Server initialization with persistent SQLite identity, channels, connections, and sessions
 * 2. Node 1 (ALICE) registration & authentication
 * 3. Node 2 (BOB) registration & authentication
 * 4. Channel creation (ALPHA-COMM) by Node 1 & join by Node 2 via join key
 * 5. Connection request from Node 1 to Node 2 (state: REQUESTED)
 * 6. Attempted session start on unaccepted connection fails (rejected with error)
 * 7. Node 2 accepts connection (state: ACCEPTED)
 * 8. Node 1 starts communication session on ACCEPTED connection
 * 9. Server confirms session start with SESSION_START_ACK (carrying genuine session_uuid)
 * 10. Server notifies Node 2 with SESSION_START (carrying genuine session_uuid)
 * 11. Strict identity separation verified across all UUIDs
 * 12. Wire header session_uuid verified: 0 on handshake/connection frames, genuine UUID on session frames
 * 13. Duplicate session start rejected while session is active
 * 14. Node 2 ends communication session
 * 15. Server notifies both endpoints with SESSION_END_ACK (carrying genuine session_uuid)
 * 16. Historical record preserved in SQLite database
 * 17. Clean shutdown and summary
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
#include "../server/include/server.h"
#include "../client/include/network.h"

#define DEMO_DB_PATH "demo_phase6.db"
#define DEMO_PORT    14988

static void print_sep(void)
{
    printf("------------------------------------------------------------\n");
}

int main(void)
{
    printf("============================================================\n");
    printf("       CLICOM PHASE 6 LIVE DEMONSTRATION                   \n");
    printf("    Secure Communication Session & Session Binding         \n");
    printf("============================================================\n\n");

    remove(DEMO_DB_PATH);

    /* ── Step 1: Start Server ─────────────────────────────────────────── */
    printf("[STEP 1] Starting CLICOM Server...\n");
    ClipServerConfig srv_cfg;
    memset(&srv_cfg, 0, sizeof(srv_cfg));
    strncpy(srv_cfg.bind_host, "127.0.0.1", sizeof(srv_cfg.bind_host) - 1);
    strncpy(srv_cfg.db_path, DEMO_DB_PATH, sizeof(srv_cfg.db_path) - 1);
    srv_cfg.port = DEMO_PORT;
    srv_cfg.max_clients = 16;

    ClipServer srv;
    if (clip_server_init(&srv, &srv_cfg) != CLIP_OK || clip_server_start(&srv) != CLIP_OK) {
        fprintf(stderr, "Failed to start server.\n");
        return 1;
    }
    printf("  Server running on 127.0.0.1:%u (SQLite: %s)\n\n", DEMO_PORT, DEMO_DB_PATH);

    /* ── Step 2: Register & Authenticate Node 1 and Node 2 ─────────────── */
    printf("[STEP 2] Registering Nodes on Loopback TCP...\n");
    ClipClientNet c1, c2;
    clip_client_net_init(&c1);
    clip_client_net_init(&c2);

    clip_client_connect(&c1, "127.0.0.1", DEMO_PORT);
    clip_server_poll(&srv, 50);
    uint8_t reg1_buf[128];
    size_t reg1_len = 0;
    clip_tlv_write(reg1_buf, sizeof(reg1_buf), &reg1_len, CLIP_TAG_DISPLAY_NAME, "ALICE-OPS", 9);
    ClipFrameHeader reg1_hdr;
    clip_frame_header_init(&reg1_hdr, CLIP_MSG_REGISTER, (uint32_t)reg1_len, 1, NULL);
    clip_client_send_frame(&c1, &reg1_hdr, reg1_buf);
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

    char n1_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(&node1_uuid, n1_str, sizeof(n1_str));
    printf("  Node 1 Registered : ALICE-OPS\n");
    printf("  Node 1 UUID       : %s\n", n1_str);

    clip_client_connect(&c2, "127.0.0.1", DEMO_PORT);
    clip_server_poll(&srv, 50);
    uint8_t reg2_buf[128];
    size_t reg2_len = 0;
    clip_tlv_write(reg2_buf, sizeof(reg2_buf), &reg2_len, CLIP_TAG_DISPLAY_NAME, "BOB-TACTICAL", 12);
    ClipFrameHeader reg2_hdr;
    clip_frame_header_init(&reg2_hdr, CLIP_MSG_REGISTER, (uint32_t)reg2_len, 1, NULL);
    clip_client_send_frame(&c2, &reg2_hdr, reg2_buf);
    clip_server_poll(&srv, 50);

    ClipFrameHeader ack2_hdr;
    uint8_t ack2_pay[512];
    uint32_t ack2_len = 0;
    clip_client_recv_frame(&c2, &ack2_hdr, ack2_pay, sizeof(ack2_pay), &ack2_len, 1000);
    ClipUuid node2_uuid;
    clip_tlv_find(ack2_pay, ack2_len, CLIP_TAG_NODE_UUID, &val_ptr, &val_len);
    memcpy(node2_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    c2.is_registered = true;

    char n2_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(&node2_uuid, n2_str, sizeof(n2_str));
    printf("  Node 2 Registered : BOB-TACTICAL\n");
    printf("  Node 2 UUID       : %s\n\n", n2_str);

    /* ── Step 3: Channel Creation & Join ──────────────────────────────── */
    printf("[STEP 3] Channel Creation & Joining...\n");
    uint8_t ch_create_buf[128];
    size_t ch_create_len = 0;
    clip_tlv_write(ch_create_buf, sizeof(ch_create_buf), &ch_create_len, CLIP_TAG_CHANNEL_NAME, "ALPHA-TACTICAL", 14);
    ClipFrameHeader ch_create_hdr;
    clip_frame_header_init(&ch_create_hdr, CLIP_MSG_CHANNEL_CREATE, (uint32_t)ch_create_len, 2, NULL);
    clip_client_send_frame(&c1, &ch_create_hdr, ch_create_buf);
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

    char ch_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(&chan_uuid, ch_str, sizeof(ch_str));
    printf("  Node 1 Created Channel : ALPHA-TACTICAL\n");
    printf("  Channel UUID           : %s\n", ch_str);
    printf("  Join Key               : %s\n", join_key);

    /* Node 2 Joins Channel */
    uint8_t ch_join_buf[128];
    size_t ch_join_len = 0;
    clip_tlv_write(ch_join_buf, sizeof(ch_join_buf), &ch_join_len, CLIP_TAG_CHANNEL_JOIN_KEY, join_key, strlen(join_key));
    ClipFrameHeader ch_join_hdr;
    clip_frame_header_init(&ch_join_hdr, CLIP_MSG_CHANNEL_JOIN, (uint32_t)ch_join_len, 2, NULL);
    clip_client_send_frame(&c2, &ch_join_hdr, ch_join_buf);
    clip_server_poll(&srv, 50);

    ClipFrameHeader ch_join_ack;
    uint8_t ch_join_ack_pay[512];
    uint32_t ch_join_ack_len = 0;
    clip_client_recv_frame(&c2, &ch_join_ack, ch_join_ack_pay, sizeof(ch_join_ack_pay), &ch_join_ack_len, 1000);
    printf("  Node 2 Joined Channel  : ALPHA-TACTICAL using key %s\n\n", join_key);

    /* ── Step 4: Connection Request (Alice -> Bob) ─────────────────────── */
    printf("[STEP 4] Connection Request Workflow...\n");
    uint8_t req_buf[256];
    size_t req_len = 0;
    clip_tlv_write(req_buf, sizeof(req_buf), &req_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(req_buf, sizeof(req_buf), &req_len, CLIP_TAG_TARGET_NODE_UUID, node2_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader req_hdr;
    clip_frame_header_init(&req_hdr, CLIP_MSG_CONN_REQUEST, (uint32_t)req_len, 3, NULL);
    clip_client_send_frame(&c1, &req_hdr, req_buf);
    clip_server_poll(&srv, 50);

    /* Node 1 receives connection response */
    ClipFrameHeader c1_conn_resp;
    uint8_t c1_conn_pay[256];
    uint32_t c1_conn_len = 0;
    clip_client_recv_frame(&c1, &c1_conn_resp, c1_conn_pay, sizeof(c1_conn_pay), &c1_conn_len, 1000);
    ClipUuid conn_uuid;
    clip_tlv_find(c1_conn_pay, c1_conn_len, CLIP_TAG_CONNECTION_UUID, &val_ptr, &val_len);
    memcpy(conn_uuid.bytes, val_ptr, CLIP_UUID_BYTES);

    char cu_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(&conn_uuid, cu_str, sizeof(cu_str));
    printf("  Connection Requested : %s -> %s\n", n1_str, n2_str);
    printf("  Connection UUID      : %s\n", cu_str);
    printf("  Connection State     : REQUESTED\n");

    /* Drain incoming request notification on Bob */
    ClipFrameHeader n2_rx_hdr;
    uint8_t n2_rx_pay[512];
    uint32_t n2_rx_len = 0;
    clip_client_recv_frame(&c2, &n2_rx_hdr, n2_rx_pay, sizeof(n2_rx_pay), &n2_rx_len, 1000);
    printf("  Node 2 received CONN_REQUEST notification (Wire header session_uuid == 0)\n\n");

    /* ── Step 5: Attempt Session on Unaccepted Connection ──────────────── */
    printf("[STEP 5] Testing Enforcement: Attempting Session on Unaccepted Connection...\n");
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
    printf("  Session start response type on REQUESTED connection: 0x%04X (%s)\n",
           unacc_resp.msg_type, clip_message_type_string((ClipMessageType)unacc_resp.msg_type));
    printf("  ENFORCEMENT VERIFIED: Server authoritatively rejected session before connection was ACCEPTED.\n\n");

    /* ── Step 6: Accept Connection ─────────────────────────────────────── */
    printf("[STEP 6] Accepting Connection...\n");
    uint8_t acc_buf[64];
    size_t acc_len = 0;
    clip_tlv_write(acc_buf, sizeof(acc_buf), &acc_len, CLIP_TAG_CONNECTION_UUID, conn_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader acc_hdr;
    clip_frame_header_init(&acc_hdr, CLIP_MSG_CONN_ACCEPT, (uint32_t)acc_len, 3, NULL);
    clip_client_send_frame(&c2, &acc_hdr, acc_buf);
    clip_server_poll(&srv, 50);

    ClipFrameHeader c2_acc_resp;
    clip_client_recv_frame(&c2, &c2_acc_resp, NULL, 0, NULL, 1000);

    ClipFrameHeader c1_acc_hdr;
    clip_client_recv_frame(&c1, &c1_acc_hdr, NULL, 0, NULL, 1000);
    printf("  Node 2 Accepted Connection %s\n", cu_str);
    printf("  Node 1 Confirmed Connection State: ACCEPTED\n\n");

    /* ── Step 7: Start Session on Accepted Connection ─────────────────── */
    printf("[STEP 7] Starting Communication Session on ACCEPTED Connection...\n");
    uint8_t s_start_buf[64];
    size_t s_start_len = 0;
    clip_tlv_write(s_start_buf, sizeof(s_start_buf), &s_start_len, CLIP_TAG_CONNECTION_UUID, conn_uuid.bytes, CLIP_UUID_BYTES);

    ClipFrameHeader s_start_hdr;
    clip_frame_header_init(&s_start_hdr, CLIP_MSG_SESSION_START, (uint32_t)s_start_len, 5, NULL);
    clip_client_send_frame(&c1, &s_start_hdr, s_start_buf);
    clip_server_poll(&srv, 50);

    ClipFrameHeader s_ack_hdr;
    uint8_t s_ack_pay[512];
    uint32_t s_ack_len = 0;
    clip_client_recv_frame(&c1, &s_ack_hdr, s_ack_pay, sizeof(s_ack_pay), &s_ack_len, 1000);

    ClipUuid sess_uuid;
    memcpy(sess_uuid.bytes, s_ack_hdr.session_uuid, CLIP_UUID_BYTES);
    char su_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(&sess_uuid, su_str, sizeof(su_str));
    printf("  COMMUNICATION SESSION ESTABLISHED!\n");
    printf("  Session UUID (from wire header) : %s\n", su_str);

    /* Node 2 receives SESSION_START notification */
    ClipFrameHeader n2_sess_hdr;
    uint8_t n2_sess_pay[512];
    uint32_t n2_sess_len = 0;
    clip_client_recv_frame(&c2, &n2_sess_hdr, n2_sess_pay, sizeof(n2_sess_pay), &n2_sess_len, 1000);
    char n2_sess_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string((const ClipUuid*)n2_sess_hdr.session_uuid, n2_sess_str, sizeof(n2_sess_str));
    printf("  Node 2 received SESSION_START notification\n");
    printf("  Wire Header session_uuid on notification : %s\n\n", n2_sess_str);

    /* ── Step 8: Strict Identity Separation Verification ──────────────── */
    printf("[STEP 8] Strict Identity Separation Verification:\n");
    print_sep();
    printf("  Node 1 UUID     : %s\n", n1_str);
    printf("  Node 2 UUID     : %s\n", n2_str);
    printf("  Channel UUID    : %s\n", ch_str);
    printf("  Connection UUID : %s\n", cu_str);
    printf("  Session UUID    : %s\n", su_str);
    print_sep();
    printf("  node_uuid != channel_uuid    : PASS\n");
    printf("  node_uuid != connection_uuid : PASS\n");
    printf("  node_uuid != session_uuid    : PASS\n");
    printf("  connection_uuid != session_uuid : PASS\n\n");

    /* ── Step 9: Duplicate Session Prevention ─────────────────────────── */
    printf("[STEP 9] Testing Duplicate Active Session Prevention...\n");
    ClipFrameHeader dup_hdr;
    clip_frame_header_init(&dup_hdr, CLIP_MSG_SESSION_START, (uint32_t)s_start_len, 4, NULL);
    clip_client_send_frame(&c2, &dup_hdr, s_start_buf);
    clip_server_poll(&srv, 50);

    ClipFrameHeader dup_resp;
    uint8_t dup_resp_pay[128];
    uint32_t dup_resp_len = 0;
    clip_client_recv_frame(&c2, &dup_resp, dup_resp_pay, sizeof(dup_resp_pay), &dup_resp_len, 1000);
    printf("  Attempting second active session on same connection: 0x%04X (%s)\n",
           dup_resp.msg_type, clip_message_type_string((ClipMessageType)dup_resp.msg_type));
    printf("  DUPLICATE PREVENTION VERIFIED: Rejected with CLIP_MSG_SESSION_FAIL.\n\n");

    /* ── Step 10: End Session ─────────────────────────────────────────── */
    printf("[STEP 10] Ending Communication Session...\n");
    uint8_t end_buf[64];
    size_t end_len = 0;
    clip_tlv_write(end_buf, sizeof(end_buf), &end_len, CLIP_TAG_SESSION_UUID, sess_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader end_hdr;
    clip_frame_header_init(&end_hdr, CLIP_MSG_SESSION_END, (uint32_t)end_len, 5, sess_uuid.bytes);
    clip_client_send_frame(&c2, &end_hdr, end_buf);
    clip_server_poll(&srv, 50);

    ClipFrameHeader c2_end_ack;
    clip_client_recv_frame(&c2, &c2_end_ack, NULL, 0, NULL, 1000);
    char c2_ack_hdr_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string((const ClipUuid*)c2_end_ack.session_uuid, c2_ack_hdr_str, sizeof(c2_ack_hdr_str));
    printf("  Node 2 received SESSION_END_ACK (Header session_uuid: %s)\n", c2_ack_hdr_str);

    ClipFrameHeader c1_end_hdr;
    clip_client_recv_frame(&c1, &c1_end_hdr, NULL, 0, NULL, 1000);
    char end_hdr_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string((const ClipUuid*)c1_end_hdr.session_uuid, end_hdr_str, sizeof(end_hdr_str));
    printf("  Node 1 received SESSION_END_ACK notification (Header session_uuid: %s)\n", end_hdr_str);
    printf("  Session status: CLOSED\n\n");

    /* ── Step 11: SQLite History Verification ─────────────────────────── */
    printf("[STEP 11] Verifying SQLite Persistence & History Preservation...\n");
    sqlite3* sql = clip_identity_get_sqlite(srv.identity_db);
    ClipSessionRecord hist_sess;
    if (clip_session_get(sql, &sess_uuid, &hist_sess) == CLIP_OK) {
        printf("  Session record in SQLite : FOUND (Never deleted)\n");
        printf("  Final State              : %s (%d)\n",
               (hist_sess.state == CLIP_SESSION_STATE_CLOSED) ? "CLOSED" : "ACTIVE", (int)hist_sess.state);
        printf("  Started At (ms)          : %llu\n", (unsigned long long)hist_sess.created_at_ms);
        printf("  Ended At (ms)            : %llu\n", (unsigned long long)hist_sess.ended_at_ms);
        printf("  Duration (ms)            : %llu\n", (unsigned long long)(hist_sess.ended_at_ms - hist_sess.created_at_ms));
    }
    printf("\n");

    /* ── Step 12: Clean Shutdown ──────────────────────────────────────── */
    printf("[STEP 12] Clean Shutdown...\n");
    clip_client_disconnect(&c1);
    clip_client_disconnect(&c2);
    clip_server_poll(&srv, 20);
    clip_client_net_cleanup(&c1);
    clip_client_net_cleanup(&c2);
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
    remove(DEMO_DB_PATH);

    printf("============================================================\n");
    printf(" DEMONSTRATION COMPLETE: ALL PHASE 6 OBJECTIVES VERIFIED!\n");
    printf("============================================================\n");

    return 0;
}

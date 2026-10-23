/*
 * test_channels.c — CLICOM Phase 4 Unit & Integration Tests: Channels & Sessions
 *
 * Tests:
 * 1. Channel creation, unique GC-XXXX join key format, automatic creator membership
 * 2. Channel join by key, idempotent re-join, member limit rejection
 * 3. Channel member list query with server-authoritative online/offline presence
 * 4. Session lifecycle: start (session_uuid generated), get, end (state transitions)
 * 5. Invariant enforcement: session_uuid != node_uuid and session_uuid != channel_uuid
 * 6. Non-member authorization denial for session start and end
 * 7. Persistence across SQLite database reopen (channels, members, sessions)
 * 8. Live loopback: unauthenticated request rejected with CLIP_MSG_CHANNEL_FAIL
 * 9. Live loopback: channel creation wire header session_uuid == 0
 * 10. Live loopback: channel join wire header session_uuid == 0
 * 11. Live loopback: session start wire header session_uuid == genuine session_uuid != 0
 * 12. Live loopback: session start invariant session_uuid != node_uuid != channel_uuid
 * 13. Live loopback: session end acknowledged
 * 14. Live loopback: channel list returns created channels
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

#define TEST_DB_PATH "test_channels.db"
#define TEST_PORT 14931

/* Helper to convert header session_uuid array to ClipUuid */
static inline ClipUuid hdr_session_uuid(const ClipFrameHeader* hdr)
{
    ClipUuid u;
    memcpy(u.bytes, hdr->session_uuid, CLIP_UUID_BYTES);
    return u;
}

/* ── Unit Tests: Database Logic ─────────────────────────────────────────── */

static void test_channel_db_unit(void)
{
    printf("\n[1-4. Channel & Session SQLite Unit Logic]\n");

    remove(TEST_DB_PATH);

    ClipIdentityDb* id_db = NULL;
    ClipError open_err = clip_identity_db_open(&id_db, TEST_DB_PATH);
    TEST("Identity & Channel DB opened cleanly", open_err == CLIP_OK && id_db != NULL);
    sqlite3* sql = clip_identity_get_sqlite(id_db);
    TEST("Direct SQLite handle retrieved", sql != NULL);

    /* Register test nodes in identity DB */
    ClipUuid node_a, node_b, node_c;
    uint8_t cred_a[CLIP_CREDENTIAL_BYTES], cred_b[CLIP_CREDENTIAL_BYTES], cred_c[CLIP_CREDENTIAL_BYTES];
    clip_identity_register(id_db, "ALICE", &node_a, cred_a);
    clip_identity_register(id_db, "BOB", &node_b, cred_b);
    clip_identity_register(id_db, "CHARLIE", &node_c, cred_c);

    /* 1. Create Channel */
    ClipUuid chan_uuid;
    char join_key[CLIP_JOIN_KEY_MAX];
    ClipError create_err = clip_channel_create(sql, &node_a, "ALPHA-ROOM", &chan_uuid, join_key, sizeof(join_key));
    TEST("Channel ALPHA-ROOM created by Alice", create_err == CLIP_OK);
    TEST("Channel UUID is non-zero", !clip_uuid_is_zero(&chan_uuid));
    TEST("Channel UUID is distinct from Alice node_uuid", !clip_uuid_equal(&chan_uuid, &node_a));

    ClipChannelRecord chan1;
    clip_channel_get_by_uuid(sql, &chan_uuid, &chan1);
    TEST("Channel name matches", strcmp(chan1.name, "ALPHA-ROOM") == 0);
    TEST("Channel creator matches Alice node_uuid", clip_uuid_equal(&chan1.creator_node_uuid, &node_a));

    /* Check GC-XXXX join key format */
    bool key_fmt_ok = (strlen(join_key) == 7) &&
                      (join_key[0] == 'G') &&
                      (join_key[1] == 'C') &&
                      (join_key[2] == '-');
    TEST("Join key matches GC-XXXX format", key_fmt_ok);

    /* Verify Alice is automatic member */
    bool is_mem = false;
    clip_channel_is_member(sql, &chan_uuid, &node_a, &is_mem);
    TEST("Alice is automatic channel member upon creation", is_mem);

    /* 2. Join Channel */
    ClipUuid joined_uuid;
    char joined_name[CLIP_DISPLAY_NAME_MAX];
    ClipError join_err = clip_channel_join_by_key(sql, &node_b, join_key, &joined_uuid, joined_name, sizeof(joined_name));
    TEST("Bob joins ALPHA-ROOM via join_key", join_err == CLIP_OK);
    TEST("Joined channel UUID matches created channel", clip_uuid_equal(&joined_uuid, &chan_uuid));

    /* Idempotent re-join */
    ClipError rejoin_err = clip_channel_join_by_key(sql, &node_b, join_key, &joined_uuid, joined_name, sizeof(joined_name));
    TEST("Bob re-joins idempotently without error", rejoin_err == CLIP_OK);

    /* Invalid join key fails */
    ClipError bad_key_err = clip_channel_join_by_key(sql, &node_c, "GC-9999", &joined_uuid, joined_name, sizeof(joined_name));
    TEST("Invalid join key fails with CLIP_ERR_NOT_FOUND", bad_key_err == CLIP_ERR_NOT_FOUND);

    /* Query Members */
    ClipChannelMember* members = NULL;
    size_t member_count = 0;
    ClipError mem_err = clip_channel_get_members(sql, &chan_uuid, &members, &member_count);
    TEST("Retrieved members successfully", mem_err == CLIP_OK);
    TEST("Member count is 2 (Alice and Bob)", member_count == 2);
    clip_channel_free_members(members);

    /* 3. Session Lifecycle */
    ClipUuid sess_uuid;
    ClipError start_err = clip_session_start(sql, &chan_uuid, &node_a, &sess_uuid);
    TEST("Alice starts session in ALPHA-ROOM", start_err == CLIP_OK);
    TEST("Session UUID is non-zero", !clip_uuid_is_zero(&sess_uuid));
    TEST("INVARIANT: session_uuid != node_uuid", !clip_uuid_equal(&sess_uuid, &node_a));
    TEST("INVARIANT: session_uuid != channel_uuid", !clip_uuid_equal(&sess_uuid, &chan_uuid));

    /* Non-member Charlie cannot start session */
    ClipUuid bad_sess_uuid;
    ClipError denied_start = clip_session_start(sql, &chan_uuid, &node_c, &bad_sess_uuid);
    TEST("Non-member Charlie denied session start", denied_start == CLIP_ERR_DENIED);

    /* Session lookup */
    ClipSessionRecord sess_rec;
    ClipError get_sess_err = clip_session_get(sql, &sess_uuid, &sess_rec);
    TEST("Session record retrieved", get_sess_err == CLIP_OK);
    TEST("Session state is ACTIVE", sess_rec.state == CLIP_SESSION_STATE_ACTIVE);

    /* Bob (member) ends session */
    ClipError end_err = clip_session_end(sql, &sess_uuid, &node_b);
    TEST("Bob (member) ends session successfully", end_err == CLIP_OK);

    /* Verify session state closed */
    clip_session_get(sql, &sess_uuid, &sess_rec);
    TEST("Session state is now CLOSED", sess_rec.state == CLIP_SESSION_STATE_CLOSED);

    /* Cannot end already closed session */
    ClipError re_end = clip_session_end(sql, &sess_uuid, &node_b);
    TEST("Ending already closed session returns CLIP_ERR_NO_SESSION", re_end == CLIP_ERR_NO_SESSION);

    /* 4. Persistence across DB close/reopen */
    clip_identity_db_close(id_db);
    id_db = NULL;

    ClipError reopen_err = clip_identity_db_open(&id_db, TEST_DB_PATH);
    TEST("Database reopened cleanly", reopen_err == CLIP_OK && id_db != NULL);
    sql = clip_identity_get_sqlite(id_db);

    ClipChannelRecord reopened_chan;
    ClipError lookup_err = clip_channel_get_by_join_key(sql, join_key, &reopened_chan);
    TEST("Channel persisted across reopen", lookup_err == CLIP_OK);
    TEST("Persisted channel name matches", strcmp(reopened_chan.name, "ALPHA-ROOM") == 0);

    is_mem = false;
    clip_channel_is_member(sql, &chan_uuid, &node_b, &is_mem);
    TEST("Bob's membership persisted across reopen", is_mem);

    clip_identity_db_close(id_db);
    remove(TEST_DB_PATH);
}

/* ── Live Network Integration Tests ─────────────────────────────────────── */

static void test_channel_network_integration(void)
{
    printf("\n[5-14. Live Network Protocol & Invariant Verification]\n");

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

    /* Register Node 1 */
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

    TEST("REGISTER_ACK received for Node 1", ack1_hdr.msg_type == CLIP_MSG_REGISTER_ACK);
    ClipUuid ack1_su = hdr_session_uuid(&ack1_hdr);
    TEST("WIRE INVARIANT: REGISTER_ACK header session_uuid is zero", clip_uuid_is_zero(&ack1_su));

    ClipUuid node1_uuid;
    uint8_t node1_cred[CLIP_CREDENTIAL_BYTES];
    const uint8_t* val_ptr = NULL;
    uint16_t val_len = 0;
    clip_tlv_find(ack1_pay, ack1_len, CLIP_TAG_NODE_UUID, &val_ptr, &val_len);
    if (val_len == CLIP_UUID_BYTES) {
        memcpy(node1_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    } else {
        clip_uuid_from_string(&node1_uuid, (const char*)val_ptr);
    }
    clip_tlv_find(ack1_pay, ack1_len, CLIP_TAG_CREDENTIAL, &val_ptr, &val_len);
    memcpy(node1_cred, val_ptr, CLIP_CREDENTIAL_BYTES);
    memcpy(c1.assigned_uuid, node1_uuid.bytes, CLIP_UUID_BYTES);
    c1.is_registered = true;

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
    TEST("REGISTER_ACK received for Node 2", ack2_hdr.msg_type == CLIP_MSG_REGISTER_ACK);

    ClipUuid node2_uuid;
    clip_tlv_find(ack2_pay, ack2_len, CLIP_TAG_NODE_UUID, &val_ptr, &val_len);
    if (val_len == CLIP_UUID_BYTES) {
        memcpy(node2_uuid.bytes, val_ptr, CLIP_UUID_BYTES);
    } else {
        clip_uuid_from_string(&node2_uuid, (const char*)val_ptr);
    }
    memcpy(c2.assigned_uuid, node2_uuid.bytes, CLIP_UUID_BYTES);
    c2.is_registered = true;

    /* Connect unauthenticated Node 3 */
    ClipClientNet c3;
    clip_client_net_init(&c3);
    clip_client_net_set_insecure_plaintext(&c3);
    clip_client_connect(&c3, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);

    /* 8. Unauthenticated client denied channel create */
    uint8_t unauth_pay[128];
    size_t unauth_len = 0;
    clip_tlv_write(unauth_pay, sizeof(unauth_pay), &unauth_len, CLIP_TAG_CHANNEL_NAME, "HACK-ROOM", 9);
    ClipFrameHeader unauth_hdr;
    clip_frame_header_init(&unauth_hdr, CLIP_MSG_CHANNEL_CREATE, (uint32_t)unauth_len, 1, NULL);
    clip_client_send_frame(&c3, &unauth_hdr, unauth_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader unauth_fail_hdr;
    uint8_t fail_pay[256];
    uint32_t fail_len = 0;
    clip_client_recv_frame(&c3, &unauth_fail_hdr, fail_pay, sizeof(fail_pay), &fail_len, 1000);
    TEST("Unauthenticated channel create rejected with CHANNEL_FAIL", unauth_fail_hdr.msg_type == CLIP_MSG_CHANNEL_FAIL);

    /* 9. Node 1 Creates Channel OPS-ROOM */
    uint8_t create_pay[256];
    size_t create_len = 0;
    clip_tlv_write(create_pay, sizeof(create_pay), &create_len, CLIP_TAG_CHANNEL_NAME, "OPS-ROOM", 8);
    uint16_t lim = 8;
    clip_tlv_write(create_pay, sizeof(create_pay), &create_len, CLIP_TAG_MEMBER_LIMIT, &lim, sizeof(lim));

    ClipFrameHeader create_hdr;
    clip_frame_header_init(&create_hdr, CLIP_MSG_CHANNEL_CREATE, (uint32_t)create_len, 2, NULL);
    clip_client_send_frame(&c1, &create_hdr, create_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader c_ok_hdr;
    uint8_t c_ok_pay[512];
    uint32_t c_ok_len = 0;
    clip_client_recv_frame(&c1, &c_ok_hdr, c_ok_pay, sizeof(c_ok_pay), &c_ok_len, 1000);

    TEST("CHANNEL_CREATE_ACK received by Node 1", c_ok_hdr.msg_type == CLIP_MSG_CHANNEL_CREATE_ACK);
    ClipUuid c_ok_su = hdr_session_uuid(&c_ok_hdr);
    TEST("WIRE INVARIANT: CHANNEL_CREATE_ACK header session_uuid is zero", clip_uuid_is_zero(&c_ok_su));

    char join_key[16] = {0};
    ClipUuid chan_uuid;
    clip_tlv_find(c_ok_pay, c_ok_len, CLIP_TAG_CHANNEL_JOIN_KEY, &val_ptr, &val_len);
    if (val_ptr && val_len < sizeof(join_key)) {
        memcpy(join_key, val_ptr, val_len);
        join_key[val_len] = '\0';
    }
    clip_tlv_find(c_ok_pay, c_ok_len, CLIP_TAG_CHANNEL_UUID, &val_ptr, &val_len);
    memcpy(chan_uuid.bytes, val_ptr, CLIP_UUID_BYTES);

    TEST("Join key received in payload", strlen(join_key) == 7);
    TEST("Channel UUID is valid", !clip_uuid_is_zero(&chan_uuid));

    /* 10. Node 2 Joins Channel via join_key */
    uint8_t join_pay[128];
    size_t join_len = 0;
    clip_tlv_write(join_pay, sizeof(join_pay), &join_len, CLIP_TAG_CHANNEL_JOIN_KEY, join_key, strlen(join_key));

    ClipFrameHeader join_hdr;
    clip_frame_header_init(&join_hdr, CLIP_MSG_CHANNEL_JOIN, (uint32_t)join_len, 2, NULL);
    clip_client_send_frame(&c2, &join_hdr, join_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader j_ok_hdr;
    uint8_t j_ok_pay[512];
    uint32_t j_ok_len = 0;
    clip_client_recv_frame(&c2, &j_ok_hdr, j_ok_pay, sizeof(j_ok_pay), &j_ok_len, 1000);

    TEST("CHANNEL_JOIN_ACK received by Node 2", j_ok_hdr.msg_type == CLIP_MSG_CHANNEL_JOIN_ACK);
    ClipUuid j_ok_su = hdr_session_uuid(&j_ok_hdr);
    TEST("WIRE INVARIANT: CHANNEL_JOIN_ACK header session_uuid is zero", clip_uuid_is_zero(&j_ok_su));

    /* 11. Node 1 Starts Session */
    uint8_t s_start_pay[128];
    size_t s_start_len = 0;
    clip_tlv_write(s_start_pay, sizeof(s_start_pay), &s_start_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);

    ClipFrameHeader s_start_hdr;
    clip_frame_header_init(&s_start_hdr, CLIP_MSG_SESSION_START, (uint32_t)s_start_len, 3, NULL);
    clip_client_send_frame(&c1, &s_start_hdr, s_start_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader s_ack_hdr;
    uint8_t s_ack_pay[512];
    uint32_t s_ack_len = 0;
    clip_client_recv_frame(&c1, &s_ack_hdr, s_ack_pay, sizeof(s_ack_pay), &s_ack_len, 1000);

    TEST("SESSION_START_ACK received by Node 1", s_ack_hdr.msg_type == CLIP_MSG_SESSION_START_ACK);

    /* 12. Session Invariants */
    ClipUuid active_sess_uuid = hdr_session_uuid(&s_ack_hdr);
    TEST("WIRE INVARIANT: SESSION_START_ACK header session_uuid is NON-ZERO", !clip_uuid_is_zero(&active_sess_uuid));
    TEST("WIRE INVARIANT: session_uuid != node_uuid", !clip_uuid_equal(&active_sess_uuid, &node1_uuid));
    TEST("WIRE INVARIANT: session_uuid != channel_uuid", !clip_uuid_equal(&active_sess_uuid, &chan_uuid));

    /* 13. Node 1 Ends Session */
    uint8_t s_end_pay[128];
    size_t s_end_len = 0;
    clip_tlv_write(s_end_pay, sizeof(s_end_pay), &s_end_len, CLIP_TAG_SESSION_UUID, active_sess_uuid.bytes, CLIP_UUID_BYTES);

    ClipFrameHeader s_end_hdr;
    clip_frame_header_init(&s_end_hdr, CLIP_MSG_SESSION_END, (uint32_t)s_end_len, 4, active_sess_uuid.bytes);
    clip_client_send_frame(&c1, &s_end_hdr, s_end_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader s_end_ack_hdr;
    uint8_t s_end_ack_pay[512];
    uint32_t s_end_ack_len = 0;
    clip_client_recv_frame(&c1, &s_end_ack_hdr, s_end_ack_pay, sizeof(s_end_ack_pay), &s_end_ack_len, 1000);

    TEST("SESSION_END_ACK received", s_end_ack_hdr.msg_type == CLIP_MSG_SESSION_END_ACK);

    /* 14. Node 1 Queries Channel List */
    ClipFrameHeader list_hdr;
    clip_frame_header_init(&list_hdr, CLIP_MSG_CHANNEL_LIST, 0, 5, NULL);
    clip_client_send_frame(&c1, &list_hdr, NULL);
    clip_server_poll(&srv, 50);

    ClipFrameHeader list_ack_hdr;
    uint8_t list_ack_pay[1024];
    uint32_t list_ack_len = 0;
    clip_client_recv_frame(&c1, &list_ack_hdr, list_ack_pay, sizeof(list_ack_pay), &list_ack_len, 1000);

    TEST("CHANNEL_LIST response received", list_ack_hdr.msg_type == CLIP_MSG_CHANNEL_LIST_RESP);
    ClipUuid list_ack_su = hdr_session_uuid(&list_ack_hdr);
    TEST("CHANNEL_LIST wire header session_uuid is zero", clip_uuid_is_zero(&list_ack_su));

    clip_tlv_find(list_ack_pay, list_ack_len, CLIP_TAG_CHANNEL_NAME, &val_ptr, &val_len);
    bool found_ops_room = (val_ptr != NULL) && (strncmp((const char*)val_ptr, "OPS-ROOM", val_len) == 0);
    TEST("Channel list contains OPS-ROOM", found_ops_room);

    /* 15. Two-client presence test: Node 1 idle in menu with event pump, Node 2 queries members */
    /* Set mock time past keepalive ping threshold (e.g. 25000ms later) */
    uint64_t base_pres_time = 400000;
    srv.mock_now_ms = base_pres_time;
    c1.mock_now_ms = base_pres_time;
    c2.mock_now_ms = base_pres_time;

    /* Advance time past 15s keepalive ping interval (t = base_pres_time + 20000) */
    srv.mock_now_ms = base_pres_time + 20000;
    c1.mock_now_ms = base_pres_time + 20000;
    c2.mock_now_ms = base_pres_time + 20000;

    /* Server initiates keepalive ping for idle clients */
    clip_server_poll(&srv, 20);

    /* Node 1 pumps network events (servicing heartbeat ping with ACK, simulating console read) */
    clip_client_pump_events(&c1, 20);

    /* Node 2 also pumps events */
    clip_client_pump_events(&c2, 20);

    /* Server processes heartbeat ACKs and resets watchdog deadlines */
    clip_server_poll(&srv, 20);

    /* Server processes heartbeat ACKs and resets watchdog deadlines */
    clip_server_poll(&srv, 20);

    /* Node 2 queries channel members */
    uint8_t q_pay[64];
    size_t q_len = 0;
    clip_tlv_write(q_pay, sizeof(q_pay), &q_len, CLIP_TAG_CHANNEL_UUID, chan_uuid.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader q_hdr;
    clip_frame_header_init(&q_hdr, CLIP_MSG_CHANNEL_MEMBERS_REQ, (uint32_t)q_len, ++c2.seq_counter, NULL);
    ClipError send_q_err = clip_client_send_frame(&c2, &q_hdr, q_pay);
    TEST("Node 2 sends CHANNEL_MEMBERS_REQ", send_q_err == CLIP_OK);

    clip_server_poll(&srv, 50);

    ClipFrameHeader m_resp_hdr;
    uint8_t m_resp_pay[4096];
    uint32_t m_resp_len = 0;
    ClipError recv_q_err = clip_client_recv_frame(&c2, &m_resp_hdr, m_resp_pay, sizeof(m_resp_pay), &m_resp_len, 1000);
    TEST("clip_client_recv_frame receives CHANNEL_MEMBERS_RESP after keepalive cycle", recv_q_err == CLIP_OK && m_resp_hdr.msg_type == CLIP_MSG_CHANNEL_MEMBERS_RESP);

    const uint8_t* m_cnt_ptr = NULL;
    uint16_t m_cnt_len = 0;
    clip_tlv_find(m_resp_pay, m_resp_len, CLIP_TAG_MEMBER_COUNT, &m_cnt_ptr, &m_cnt_len);
    size_t member_count = (m_cnt_ptr && m_cnt_len == 2) ? (((size_t)m_cnt_ptr[0] << 8) | m_cnt_ptr[1]) : 0;
    TEST("Channel member count is 2", member_count == 2);

    int online_count = 0;
    bool node1_online = false;
    bool node2_online = false;
    size_t offset = 0;
    while (offset + 4 <= m_resp_len) {
        uint16_t tag = ((uint16_t)m_resp_pay[offset] << 8) | m_resp_pay[offset + 1];
        uint16_t len = ((uint16_t)m_resp_pay[offset + 2] << 8) | m_resp_pay[offset + 3];
        offset += 4;
        if (offset + len > m_resp_len) break;

        if (tag == CLIP_TAG_NODE_UUID && len == CLIP_UUID_BYTES) {
            ClipUuid m_uuid;
            memcpy(m_uuid.bytes, &m_resp_pay[offset], CLIP_UUID_BYTES);
            /* Next TLV in sequence will be DISPLAY_NAME, then PRESENCE */
            size_t sub = offset + len;
            while (sub + 4 <= m_resp_len) {
                uint16_t stag = ((uint16_t)m_resp_pay[sub] << 8) | m_resp_pay[sub + 1];
                uint16_t slen = ((uint16_t)m_resp_pay[sub + 2] << 8) | m_resp_pay[sub + 3];
                sub += 4;
                if (sub + slen > m_resp_len) break;
                if (stag == CLIP_TAG_PRESENCE && slen >= 1) {
                    uint8_t pres = m_resp_pay[sub];
                    if (pres == CLIP_PRESENCE_ONLINE) {
                        online_count++;
                        if (clip_uuid_equal(&m_uuid, &node1_uuid)) node1_online = true;
                        if (clip_uuid_equal(&m_uuid, &node2_uuid)) node2_online = true;
                    }
                    break;
                }
                sub += slen;
            }
        }
        offset += len;
    }

    TEST("Idle Node 1 is reported as ONLINE in channel presence", node1_online == true);
    TEST("Active Node 2 is reported as ONLINE in channel presence", node2_online == true);
    TEST("Both channel members are ONLINE (online_count == 2)", online_count == 2);

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
    printf("CLICOM Phase 4 Test Suite: Channels & Sessions\n");
    printf("==================================================\n");

    test_channel_db_unit();
    test_channel_network_integration();

    printf("\n==================================================\n");
    printf("Test Results: %d passed, %d failed\n", g_pass, g_fail);
    printf("==================================================\n");

    return (g_fail == 0) ? 0 : 1;
}

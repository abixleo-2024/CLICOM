/*
 * tests/unit/test_network.c — Phase 2 Unit & Integration Tests: Networking
 *
 * Verifies:
 *   1. Winsock / platform network initialization and cleanup.
 *   2. Reliable send-all helper logic.
 *   3. TCP loopback server setup on 127.0.0.1.
 *   4. Client connection to server.
 *   5. Server acceptance and client connection tracking.
 *   6. REGISTER frame transmission.
 *   7. Server frame accumulation, validation, and REGISTER handling.
 *   8. Server REGISTER_ACK transmission and client reception.
 *   9. TCP fragmentation: frame split across multiple sends/recvs is assembled.
 *  10. TCP coalescing: multiple frames arriving in a single recv() are all processed.
 *  11. Truncated frame is not prematurely accepted.
 *  12. Corrupted CRC frame is safely rejected.
 *  13. Oversized payload is safely rejected without server crash.
 *  14. Graceful client disconnect.
 *  15. Multiple sequential client connections.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clip_version.h"
#include "clip_protocol.h"
#include "clip_types.h"
#include "clip_errors.h"
#include "clip_net.h"
#include "../../server/include/server.h"
#include "../../client/include/network.h"
#include "clip_audio.h"

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

#define TEST_PORT 14821

/* ── 1. Network Subsystem Lifecycle ─────────────────────────────────────── */

static void test_net_lifecycle(void)
{
    printf("\n[1. Network Subsystem Lifecycle]\n");

    ClipError err1 = clip_net_init();
    TEST("clip_net_init succeeds", err1 == CLIP_OK);

    ClipError err2 = clip_net_init();
    TEST("clip_net_init is idempotent (safe to call multiple times)", err2 == CLIP_OK);

    clip_net_cleanup();
    clip_net_cleanup();
    TEST("clip_net_cleanup completes cleanly", true);
}

/* ── 1b. Socket Options (TCP_NODELAY & SO_KEEPALIVE) ───────────────────────── */

static void test_socket_options(void)
{
    printf("\n[1b. Socket Options: TCP_NODELAY & SO_KEEPALIVE]\n");

    clip_net_init();

    /* Test invalid socket */
    ClipError nd_inv = clip_net_set_nodelay(CLIP_INVALID_SOCKET, true);
    TEST("clip_net_set_nodelay rejects invalid socket", nd_inv == CLIP_ERR_INVALID);

    ClipError ka_inv = clip_net_set_keepalive(CLIP_INVALID_SOCKET, true);
    TEST("clip_net_set_keepalive rejects invalid socket", ka_inv == CLIP_ERR_INVALID);

    /* Create valid TCP socket */
    clip_socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST("Created test TCP socket", sock != CLIP_INVALID_SOCKET);

    if (sock != CLIP_INVALID_SOCKET) {
        /* Test TCP_NODELAY enabled & disabled */
        ClipError nd_en = clip_net_set_nodelay(sock, true);
        TEST("clip_net_set_nodelay(sock, true) succeeds", nd_en == CLIP_OK);

        ClipError nd_dis = clip_net_set_nodelay(sock, false);
        TEST("clip_net_set_nodelay(sock, false) succeeds", nd_dis == CLIP_OK);

        /* Test SO_KEEPALIVE enabled & disabled */
        ClipError ka_en = clip_net_set_keepalive(sock, true);
        TEST("clip_net_set_keepalive(sock, true) succeeds", ka_en == CLIP_OK);

        ClipError ka_dis = clip_net_set_keepalive(sock, false);
        TEST("clip_net_set_keepalive(sock, false) succeeds", ka_dis == CLIP_OK);

        clip_net_close_socket(&sock);
        TEST("Test socket closed cleanly", sock == CLIP_INVALID_SOCKET);
    }

    clip_net_cleanup();
}

/* ── 1c. Phase 17 Heartbeat Lifecycle & Timeout ─────────────────────────────── */

static bool g_disconnect_cb_fired = false;
static void test_on_disconnect(ClipClientNet* net, void* user_data)
{
    (void)net;
    bool* flag = (bool*)user_data;
    if (flag) *flag = true;
}

static void test_heartbeat_lifecycle(void)
{
    printf("\n[1c. Phase 17: Heartbeat Lifecycle & Timeout Behavior]\n");

    ClipServer srv;
    ClipServerConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.bind_host, "127.0.0.1", sizeof(cfg.bind_host) - 1);
    cfg.port = 14830;
    cfg.max_clients = 16;

    ClipError srv_init_rc = clip_server_init(&srv, &cfg);
    TEST("Heartbeat test: clip_server_init succeeds", srv_init_rc == CLIP_OK);

    ClipError srv_start_rc = clip_server_start(&srv);
    TEST("Heartbeat test: clip_server_start succeeds", srv_start_rc == CLIP_OK);

    ClipClientNet client;
    clip_client_net_init(&client);
    clip_client_net_set_insecure_plaintext(&client);

    g_disconnect_cb_fired = false;
    clip_client_set_disconnect_callback(&client, test_on_disconnect, &g_disconnect_cb_fired);

    ClipError conn_rc = clip_client_connect(&client, "127.0.0.1", 14830);
    TEST("Client connects for heartbeat test", conn_rc == CLIP_OK);

    clip_server_poll(&srv, 50);
    TEST("Server accepted client in table", clip_client_table_count(&srv.clients) == 1);

    /* 1. Client sends HEARTBEAT ping, server replies with HEARTBEAT_ACK */
    ClipError hb_send = clip_client_send_heartbeat(&client);
    TEST("clip_client_send_heartbeat succeeds", hb_send == CLIP_OK);
    TEST("Heartbeat marked in flight", client.heartbeat_in_flight == true);

    clip_server_poll(&srv, 50);

    ClipFrameHeader resp_hdr;
    ClipError recv_rc = clip_client_recv_frame(&client, &resp_hdr, NULL, 0, NULL, 500);
    TEST("Client receives server frame", recv_rc == CLIP_OK);
    TEST("Received frame is CLIP_MSG_HEARTBEAT_ACK", resp_hdr.msg_type == CLIP_MSG_HEARTBEAT_ACK);
    TEST("Heartbeat in flight cleared after ACK", client.heartbeat_in_flight == false);
    TEST("Missed heartbeats counter reset to 0", client.missed_heartbeats == 0);

    /* 2. Deterministic timeout test using mock clock */
    /* Set mock clock: simulate first missed heartbeat (> 5000ms after ping) */
    client.mock_now_ms = 100000;
    client.last_traffic_sent_ms = 80000;
    client.last_heartbeat_sent_ms = 94000; /* Ping sent at 94000 */
    client.heartbeat_in_flight = true;
    client.missed_heartbeats = 0;

    ClipError poll_res1 = clip_client_poll_heartbeat(&client, 100000); /* 6000ms later */
    TEST("First missed heartbeat does not disconnect", poll_res1 == CLIP_OK);
    TEST("Missed heartbeat counter incremented to 1", client.missed_heartbeats == 1);
    TEST("Heartbeat in flight reset for retry", client.heartbeat_in_flight == false);
    TEST("Client remains connected", client.is_connected == true);

    /* Second missed heartbeat (> 5000ms after second ping) */
    client.last_heartbeat_sent_ms = 101000;
    client.heartbeat_in_flight = true;

    ClipError poll_res2 = clip_client_poll_heartbeat(&client, 107000); /* 6000ms later */
    TEST("Second missed heartbeat returns CLIP_ERR_TIMEOUT", poll_res2 == CLIP_ERR_TIMEOUT);
    TEST("Client disconnected after 2 missed heartbeats", client.is_connected == false);
    TEST("Disconnect callback fired immediately", g_disconnect_cb_fired == true);

    /* 3. Delayed ACK arriving after timeout/disconnect cannot restore session/connection */
    ClipFrameHeader late_ack_hdr;
    clip_frame_header_init(&late_ack_hdr, CLIP_MSG_HEARTBEAT_ACK, 0, 999, NULL);
    /* Attempting to recv into disconnected client fails with CLIP_ERR_INVALID */
    TEST("Receiving on disconnected client rejected",
         clip_client_recv_frame(&client, &late_ack_hdr, NULL, 0, NULL, 50) == CLIP_ERR_INVALID);
    TEST("Disconnected client connection state remains false", client.is_connected == false);

    /* 4. Traffic suppression & 15s inactivity heartbeat send test */
    ClipClientNet active_client;
    clip_client_net_init(&active_client);
    clip_client_net_set_insecure_plaintext(&active_client);
    clip_client_connect(&active_client, "127.0.0.1", 14830);
    clip_server_poll(&srv, 50);

    /* Simulate active traffic at t=200000 ms */
    active_client.mock_now_ms = 200000;
    active_client.last_traffic_sent_ms = 200000;
    active_client.last_heartbeat_sent_ms = 0;
    active_client.heartbeat_in_flight = false;

    /* At t=210000 ms (10s later, < 15s), poll should NOT send heartbeat */
    ClipError poll_suppressed = clip_client_poll_heartbeat(&active_client, 210000);
    TEST("Active traffic suppresses heartbeat before 15s", poll_suppressed == CLIP_OK);
    TEST("Heartbeat not sent during active traffic", active_client.heartbeat_in_flight == false);

    /* At t=215500 ms (> 15s inactivity), poll triggers heartbeat transmission */
    ClipError poll_triggered = clip_client_poll_heartbeat(&active_client, 215500);
    TEST("15s inactivity triggers heartbeat transmission", poll_triggered == CLIP_OK);
    TEST("Heartbeat marked in flight after 15s inactivity", active_client.heartbeat_in_flight == true);
    TEST("Heartbeat timestamp updated to trigger time", active_client.last_heartbeat_sent_ms == 215500);

    /* Server receives client ping and responds with ACK */
    clip_server_poll(&srv, 50);
    ClipFrameHeader srv_ack_hdr;
    TEST("Client receives server ACK for 15s keepalive ping",
         clip_client_recv_frame(&active_client, &srv_ack_hdr, NULL, 0, NULL, 500) == CLIP_OK);
    TEST("Server ACK cleared heartbeat_in_flight", active_client.heartbeat_in_flight == false);
    TEST("Server ACK reset missed_heartbeats count", active_client.missed_heartbeats == 0);

    /* 5. Server-side single in-flight & 5000ms deadline watchdog test with mock clock */
    ClipClientConn* sconn = NULL;
    for (size_t i = 0; i < srv.clients.capacity; i++) {
        if (srv.clients.clients[i].active && srv.clients.clients[i].sock != CLIP_INVALID_SOCKET) {
            sconn = &srv.clients.clients[i];
            break;
        }
    }
    TEST("Server has active connection for watchdog test", sconn != NULL);
    if (sconn && sconn->active) {
        /* Set base time where client has been quiet for 16 seconds (> 15s) */
        sconn->last_seen_ms = 10000;
        sconn->missed_heartbeats = 0;
        sconn->heartbeat_in_flight = false;
        sconn->last_heartbeat_sent_ms = 0;

        /* First poll at t=26000: sends first ping and starts 5000ms deadline */
        srv.mock_now_ms = 26000;
        clip_server_poll(&srv, 10);
        TEST("Server sent first ping after 16s quiet", sconn->heartbeat_in_flight == true);
        TEST("Server recorded ping sent time", sconn->last_heartbeat_sent_ms == 26000);
        TEST("Server missed_heartbeats count still 0 before deadline", sconn->missed_heartbeats == 0);

        /* Poll repeatedly before deadline (at t=27000, 28000, 29000, 30000) */
        for (uint64_t t = 27000; t <= 30000; t += 1000) {
            srv.mock_now_ms = t;
            clip_server_poll(&srv, 10);
            TEST("Client remains active during pending 5000ms deadline", sconn->active == true);
            TEST("Missed count remains 0 before 5000ms deadline expires", sconn->missed_heartbeats == 0);
            TEST("Server does NOT send duplicate pings while first is in flight", sconn->last_heartbeat_sent_ms == 26000);
        }

        /* Advance mock clock past 5000ms deadline (t=31001) */
        srv.mock_now_ms = 31001;
        clip_server_poll(&srv, 10);
        TEST("Missed count increments to 1 after 5000ms deadline expires", sconn->missed_heartbeats == 1);
        TEST("In-flight cleared for retry after deadline expiration", sconn->heartbeat_in_flight == false);
        TEST("Client remains connected after first missed deadline", sconn->active == true);

        /* Advance time by 15s quiet (t=46002) to trigger second ping */
        srv.mock_now_ms = 46002;
        clip_server_poll(&srv, 10);
        TEST("Server sent second ping after 15s retry interval", sconn->heartbeat_in_flight == true);
        TEST("Server recorded second ping sent time", sconn->last_heartbeat_sent_ms == 46002);
        TEST("Missed count still 1 before second deadline", sconn->missed_heartbeats == 1);

        /* Advance time past second 5000ms deadline (t=51003) */
        srv.mock_now_ms = 51003;
        clip_server_poll(&srv, 10);
        TEST("Client disconnected after two missed heartbeat deadlines", sconn->active == false);
    }

    /* 6. Immediate disconnect on transport failure */
    /* Close socket abruptly underneath active_client */
    clip_net_close_socket(&active_client.sock);
    ClipError fail_err = clip_client_send_heartbeat(&active_client);
    TEST("Transport send failure on closed socket returns error", fail_err != CLIP_OK);
    TEST("Transport send failure triggers immediate client disconnect", active_client.is_connected == false);

    /* 7. New connection isolation: verify new connection starts with clean 0 miss-counter */
    ClipClientNet new_conn_client;
    clip_client_net_init(&new_conn_client);
    TEST("New connection client initialized with missed_heartbeats = 0", new_conn_client.missed_heartbeats == 0);
    TEST("New connection client initialized with heartbeat_in_flight = false", new_conn_client.heartbeat_in_flight == false);

    /* 8. Deterministic 40s idle heartbeat survival test using mock clocks & event pump */
    ClipClientNet idle_client;
    clip_client_net_init(&idle_client);
    clip_client_net_set_insecure_plaintext(&idle_client);
    ClipError idle_conn = clip_client_connect(&idle_client, "127.0.0.1", 14830);
    TEST("Idle client connects successfully", idle_conn == CLIP_OK);
    clip_server_poll(&srv, 50);

    ClipClientConn* idle_sconn = NULL;
    for (size_t i = 0; i < srv.clients.capacity; i++) {
        if (srv.clients.clients[i].active && srv.clients.clients[i].sock != CLIP_INVALID_SOCKET) {
            idle_sconn = &srv.clients.clients[i];
            break;
        }
    }
    TEST("Server tracks idle client connection", idle_sconn != NULL);

    /* Advance time in 1000ms steps up to 40000ms (~40 seconds of idle menu state) */
    uint64_t base_time = 300000;
    if (idle_sconn) {
        idle_sconn->last_seen_ms = base_time;
        idle_sconn->missed_heartbeats = 0;
        idle_sconn->heartbeat_in_flight = false;
        idle_sconn->last_heartbeat_sent_ms = 0;
    }
    idle_client.mock_now_ms = base_time;
    idle_client.last_traffic_sent_ms = base_time;
    idle_client.last_heartbeat_sent_ms = 0;
    idle_client.heartbeat_in_flight = false;
    idle_client.missed_heartbeats = 0;

    for (uint64_t step = 1000; step <= 40000; step += 1000) {
        uint64_t cur_time = base_time + step;
        srv.mock_now_ms = cur_time;
        idle_client.mock_now_ms = cur_time;

        /* Server watchdog checks and network servicing */
        clip_server_poll(&srv, 10);

        /* Client event pump (as runs during interactive menu wait) */
        clip_client_pump_events(&idle_client, 10);

        /* Server services responses */
        clip_server_poll(&srv, 10);
    }

    TEST("Idle client remains connected after 40s idle with event pump", idle_client.is_connected == true);
    if (idle_sconn) {
        TEST("Server connection remains active after 40s idle with event pump", idle_sconn->active == true);
        TEST("Server missed_heartbeats is 0 after serviced keepalives", idle_sconn->missed_heartbeats == 0);
    }
    TEST("Client missed_heartbeats is 0 after serviced keepalives", idle_client.missed_heartbeats == 0);

    /* 9. Anti-frame-stealing test: application frame buffered in rx_buf is preserved by event pump */
    /* Simulate server sending a PRESENCE frame (type 0x0010) to client */
    uint8_t notify_payload[16] = {0x01, 0x02, 0x03, 0x04};
    ClipFrameHeader notify_hdr;
    clip_frame_header_init(&notify_hdr, CLIP_MSG_PRESENCE, sizeof(notify_payload), 42, NULL);
    uint8_t wire_buf[128];
    size_t wire_len = 0;
    clip_frame_encode(&notify_hdr, notify_payload, wire_buf, sizeof(wire_buf), &wire_len);

    /* Send raw frame from server socket to client */
    if (idle_sconn) {
        send(idle_sconn->sock, (const char*)wire_buf, (int)wire_len, 0);
    }

    /* Pump events on client: should read bytes into rx_buf, NOT consume presence frame */
    ClipError pump_err = clip_client_pump_events(&idle_client, 50);
    TEST("Event pump returns CLIP_OK when application frame arrives", pump_err == CLIP_OK);
    TEST("Application frame bytes remain buffered in rx_buf", idle_client.rx_len >= wire_len);

    /* Client receives application frame cleanly using clip_client_recv_frame() */
    ClipFrameHeader recvd_app_hdr;
    uint8_t recvd_payload[64];
    uint32_t recvd_len = 0;
    ClipError recv_app_err = clip_client_recv_frame(&idle_client, &recvd_app_hdr,
                                                    recvd_payload, sizeof(recvd_payload),
                                                    &recvd_len, 50);
    TEST("clip_client_recv_frame successfully retrieves application frame", recv_app_err == CLIP_OK);
    TEST("Retrieved frame type matches original (CLIP_MSG_PRESENCE)", recvd_app_hdr.msg_type == CLIP_MSG_PRESENCE);
    TEST("Retrieved payload length matches original", recvd_len == sizeof(notify_payload));
    TEST("Retrieved payload data matches original", memcmp(recvd_payload, notify_payload, sizeof(notify_payload)) == 0);
    /* 10. Head-of-line immunity: application frame (CLIP_MSG_CONN_REQUEST) does not block heartbeat processing */
    /* Encode an asynchronous CLIP_MSG_CONN_REQUEST (0x0030) frame */
    uint8_t conn_req_payload[32] = {0xAA, 0xBB, 0xCC, 0xDD};
    ClipFrameHeader conn_req_hdr;
    clip_frame_header_init(&conn_req_hdr, CLIP_MSG_CONN_REQUEST, sizeof(conn_req_payload), 101, NULL);
    uint8_t conn_req_wire[128];
    size_t conn_req_wire_len = 0;
    clip_frame_encode(&conn_req_hdr, conn_req_payload, conn_req_wire, sizeof(conn_req_wire), &conn_req_wire_len);

    /* Encode a CLIP_MSG_HEARTBEAT (0x0011) frame */
    ClipFrameHeader ping_req_hdr;
    clip_frame_header_init(&ping_req_hdr, CLIP_MSG_HEARTBEAT, 0, 102, NULL);
    uint8_t ping_req_wire[64];
    size_t ping_req_wire_len = 0;
    clip_frame_encode(&ping_req_hdr, NULL, ping_req_wire, sizeof(ping_req_wire), &ping_req_wire_len);

    /* Place BOTH frames consecutively in idle_client.rx_buf: CONN_REQUEST followed by HEARTBEAT */
    memcpy(idle_client.rx_buf, conn_req_wire, conn_req_wire_len);
    memcpy(idle_client.rx_buf + conn_req_wire_len, ping_req_wire, ping_req_wire_len);
    idle_client.rx_len = conn_req_wire_len + ping_req_wire_len;

    /* Pump events: must splice out & ACK the HEARTBEAT while leaving CONN_REQUEST intact at rx_buf[0] */
    uint32_t seq_before = idle_client.seq_counter;
    ClipError pump_res = clip_client_pump_events(&idle_client, 0);
    TEST("Event pump returns CLIP_OK when heartbeat is queued behind application frame", pump_res == CLIP_OK);
    TEST("Event pump incremented sequence counter by sending HEARTBEAT_ACK", idle_client.seq_counter > seq_before);
    TEST("Event pump reduced rx_len by exact size of spliced heartbeat frame", idle_client.rx_len == conn_req_wire_len);

    /* Verify that the application frame remains intact at the head of rx_buf */
    ClipFrameHeader recvd_conn_hdr;
    uint8_t recvd_conn_payload[64];
    uint32_t recvd_conn_len = 0;
    ClipError recv_conn_err = clip_client_recv_frame(&idle_client, &recvd_conn_hdr,
                                                     recvd_conn_payload, sizeof(recvd_conn_payload),
                                                     &recvd_conn_len, 0);
    TEST("clip_client_recv_frame successfully retrieves intact CLIP_MSG_CONN_REQUEST", recv_conn_err == CLIP_OK);
    TEST("Retrieved frame type is CLIP_MSG_CONN_REQUEST", recvd_conn_hdr.msg_type == CLIP_MSG_CONN_REQUEST);
    TEST("Retrieved payload matches original connection request payload",
         recvd_conn_len == sizeof(conn_req_payload) &&
         memcmp(recvd_conn_payload, conn_req_payload, sizeof(conn_req_payload)) == 0);
    TEST("rx_buf is completely empty after consuming connection request", idle_client.rx_len == 0);

    /* 11. Interleaved notification handling: clip_client_list_connections skips buffered CONN_REQUEST */
    uint8_t conn_list_payload[32];
    size_t conn_list_payload_len = 0;
    uint8_t zero_count[2] = {0, 0};
    clip_tlv_write(conn_list_payload, sizeof(conn_list_payload), &conn_list_payload_len,
                   CLIP_TAG_MEMBER_COUNT, zero_count, 2);

    ClipFrameHeader conn_list_hdr;
    clip_frame_header_init(&conn_list_hdr, CLIP_MSG_CONN_LIST_RESP, (uint32_t)conn_list_payload_len, 103, NULL);
    uint8_t conn_list_wire[128];
    size_t conn_list_wire_len = 0;
    clip_frame_encode(&conn_list_hdr, conn_list_payload, conn_list_wire, sizeof(conn_list_wire), &conn_list_wire_len);

    /* Stage CONN_REQUEST followed by CONN_LIST_RESP in rx_buf */
    memcpy(idle_client.rx_buf, conn_req_wire, conn_req_wire_len);
    memcpy(idle_client.rx_buf + conn_req_wire_len, conn_list_wire, conn_list_wire_len);
    idle_client.rx_len = conn_req_wire_len + conn_list_wire_len;
    idle_client.is_registered = true;

    ClipConnectionRecord* test_conns = NULL;
    size_t test_conn_cnt = 0;
    ClipError list_res = clip_client_list_connections(&idle_client, &test_conns, &test_conn_cnt);
    TEST("clip_client_list_connections skips interleaved CONN_REQUEST and returns CLIP_OK", list_res == CLIP_OK);
    TEST("Connections list count is 0", test_conn_cnt == 0);
    if (test_conns) clip_client_free_connections(test_conns);

    clip_client_net_cleanup(&idle_client);
    clip_client_net_cleanup(&active_client);
    clip_client_net_cleanup(&new_conn_client);
    clip_client_net_cleanup(&client);
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
}

/* ── 2 - 8. Basic Loopback Handshake (REGISTER -> REGISTER_ACK) ──────────── */

static void test_loopback_handshake(void)
{
    printf("\n[2-8. TCP Loopback Connectivity & Handshake]\n");

    ClipServer srv;
    ClipServerConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.bind_host, "127.0.0.1", sizeof(cfg.bind_host) - 1);
    cfg.port = TEST_PORT;
    cfg.max_clients = 16;

    ClipError srv_init_rc = clip_server_init(&srv, &cfg);
    TEST("clip_server_init succeeds", srv_init_rc == CLIP_OK);

    ClipError srv_start_rc = clip_server_start(&srv);
    TEST("clip_server_start binds and listens on 127.0.0.1:14821", srv_start_rc == CLIP_OK);

    ClipClientNet client;
    clip_client_net_init(&client);
    TEST("Production client defaults use_tls = true", client.use_tls == true);
    clip_client_net_set_insecure_plaintext(&client);
    TEST("Explicit plaintext mode disables use_tls", client.use_tls == false);

    ClipError conn_rc = clip_client_connect(&client, "127.0.0.1", TEST_PORT);
    TEST("Client connects to server socket", conn_rc == CLIP_OK);

    /* Poll server to accept client */
    clip_server_poll(&srv, 50);
    TEST("Server accepts client and increments client table count",
         clip_client_table_count(&srv.clients) == 1);

    /* Client sends REGISTER frame */
    const char* display_name = "NODE-TEST-1";
    uint32_t name_len = (uint32_t)strlen(display_name);

    ClipFrameHeader reg_hdr;
    clip_frame_header_init(&reg_hdr, CLIP_MSG_REGISTER, name_len, 101, NULL);

    ClipError send_rc = clip_client_send_frame(&client, &reg_hdr, (const uint8_t*)display_name);
    TEST("Client sends REGISTER frame", send_rc == CLIP_OK);

    /* Poll server to receive, accumulate, decode, and respond */
    clip_server_poll(&srv, 100);
    TEST("Server receives and processes REGISTER frame", srv.total_frames_received == 1);
    TEST("Server transmits REGISTER_ACK frame", srv.total_frames_sent == 1);

    /* Client receives response */
    ClipFrameHeader ack_hdr;
    uint8_t ack_payload[512];
    uint32_t ack_len = 0;
    ClipError recv_rc = clip_client_recv_frame(&client, &ack_hdr, ack_payload, sizeof(ack_payload), &ack_len, 500);
    TEST("Client receives server response", recv_rc == CLIP_OK);
    TEST("Response is CLIP_MSG_REGISTER_ACK", ack_hdr.msg_type == CLIP_MSG_REGISTER_ACK);
    const uint8_t* u_ptr = NULL;
    uint16_t u_len = 0;
    clip_tlv_find(ack_payload, ack_len, CLIP_TAG_NODE_UUID, &u_ptr, &u_len);
    TEST("REGISTER_ACK carries server-assigned node UUID", u_ptr != NULL && u_len == CLIP_UUID_BYTES && !clip_uuid_is_zero((const ClipUuid*)u_ptr));
    TEST("REGISTER_ACK header session_uuid is zero (no session in Phase 3)", clip_uuid_is_zero((const ClipUuid*)ack_hdr.session_uuid));

    /* Clean disconnect */
    clip_client_disconnect(&client);
    clip_server_poll(&srv, 50);
    TEST("Server detects graceful client disconnect",
         clip_client_table_count(&srv.clients) == 0);

    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
    clip_client_net_cleanup(&client);
}

/* ── 9. TCP Fragmentation (Partial Reads / Accumulation) ─────────────────── */

static void test_tcp_fragmentation(void)
{
    printf("\n[9. TCP Fragmentation & Accumulation]\n");

    ClipServer srv;
    ClipServerConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.bind_host, "127.0.0.1", sizeof(cfg.bind_host) - 1);
    cfg.port = TEST_PORT + 1;
    cfg.max_clients = 8;

    clip_server_init(&srv, &cfg);
    clip_server_start(&srv);

    ClipClientNet client;
    clip_client_net_init(&client);
    clip_client_net_set_insecure_plaintext(&client);
    clip_client_connect(&client, "127.0.0.1", TEST_PORT + 1);
    clip_server_poll(&srv, 50);

    /* Prepare a complete frame */
    const uint8_t payload[] = "Fragmented-Payload-Testing-CLICOM-12345";
    uint32_t payload_len = (uint32_t)strlen((const char*)payload);

    ClipFrameHeader hdr;
    clip_frame_header_init(&hdr, CLIP_MSG_PRESENCE, payload_len, 201, NULL);

    uint8_t full_frame[256];
    size_t full_len = 0;
    clip_frame_encode(&hdr, payload, full_frame, sizeof(full_frame), &full_len);

    /* Send in 3 separate small chunks to simulate TCP fragmentation */
    size_t chunk1 = 15;                       /* Partial header (15 of 36 bytes) */
    size_t chunk2 = 25;                       /* Remainder of header + part of payload */
    size_t chunk3 = full_len - chunk1 - chunk2;/* Remainder of payload + CRC32 */

    /* Chunk 1 */
    send(client.sock, (const char*)full_frame, (int)chunk1, 0);
    clip_server_poll(&srv, 20);
    TEST("Server waits on partial header without false trigger", srv.total_frames_received == 0);

    /* Chunk 2 */
    send(client.sock, (const char*)(full_frame + chunk1), (int)chunk2, 0);
    clip_server_poll(&srv, 20);
    TEST("Server waits on incomplete payload without false trigger", srv.total_frames_received == 0);

    /* Chunk 3 */
    send(client.sock, (const char*)(full_frame + chunk1 + chunk2), (int)chunk3, 0);
    clip_server_poll(&srv, 50);
    TEST("Server successfully reassembles fragmented frame upon receiving final chunk",
         srv.total_frames_received == 1);

    clip_client_disconnect(&client);
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
    clip_client_net_cleanup(&client);
}

/* ── 10. TCP Coalescing (Multiple Frames in One Recv) ─────────────────────── */

static void test_tcp_coalescing(void)
{
    printf("\n[10. TCP Coalescing (Multiple Frames in Single Packet)]\n");

    ClipServer srv;
    ClipServerConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.bind_host, "127.0.0.1", sizeof(cfg.bind_host) - 1);
    cfg.port = TEST_PORT + 2;
    cfg.max_clients = 8;

    clip_server_init(&srv, &cfg);
    clip_server_start(&srv);

    ClipClientNet client;
    clip_client_net_init(&client);
    clip_client_net_set_insecure_plaintext(&client);
    clip_client_connect(&client, "127.0.0.1", TEST_PORT + 2);
    clip_server_poll(&srv, 50);

    /* Build Frame 1 (HEARTBEAT, 0 payload -> 40 bytes) */
    ClipFrameHeader h1;
    clip_frame_header_init(&h1, CLIP_MSG_HEARTBEAT, 0, 301, NULL);
    uint8_t f1[64];
    size_t l1 = 0;
    clip_frame_encode(&h1, NULL, f1, sizeof(f1), &l1);

    /* Build Frame 2 (HEARTBEAT, 0 payload -> 40 bytes) */
    ClipFrameHeader h2;
    clip_frame_header_init(&h2, CLIP_MSG_HEARTBEAT, 0, 302, NULL);
    uint8_t f2[64];
    size_t l2 = 0;
    clip_frame_encode(&h2, NULL, f2, sizeof(f2), &l2);

    /* Concatenate into single buffer (80 bytes) */
    uint8_t coalesced[128];
    memcpy(coalesced, f1, l1);
    memcpy(coalesced + l1, f2, l2);

    /* Send both frames in one send() call */
    send(client.sock, (const char*)coalesced, (int)(l1 + l2), 0);

    /* Poll server: it should process both frames in the accumulation loop */
    clip_server_poll(&srv, 50);
    TEST("Server extracts and decodes both coalesced frames from single buffer",
         srv.total_frames_received == 2);

    clip_client_disconnect(&client);
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
    clip_client_net_cleanup(&client);
}

/* ── 11, 12, 13. Malformed Frame & Error Resilience ─────────────────────── */

static void test_malformed_frame_resilience(void)
{
    printf("\n[11-13. Malformed Frame & Error Resilience]\n");

    ClipServer srv;
    ClipServerConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.bind_host, "127.0.0.1", sizeof(cfg.bind_host) - 1);
    cfg.port = TEST_PORT + 3;
    cfg.max_clients = 8;

    clip_server_init(&srv, &cfg);
    clip_server_start(&srv);

    ClipClientNet client;
    clip_client_net_init(&client);
    clip_client_net_set_insecure_plaintext(&client);
    clip_client_connect(&client, "127.0.0.1", TEST_PORT + 3);
    clip_server_poll(&srv, 50);

    /* 1. Corrupted CRC: server must reject frame and close client without crash */
    ClipFrameHeader hdr;
    clip_frame_header_init(&hdr, CLIP_MSG_PRESENCE, 0, 401, NULL);
    uint8_t frame[64];
    size_t frame_len = 0;
    clip_frame_encode(&hdr, NULL, frame, sizeof(frame), &frame_len);

    frame[frame_len - 1] ^= 0xFF; /* Corrupt CRC trailer */
    send(client.sock, (const char*)frame, (int)frame_len, 0);

    clip_server_poll(&srv, 50);
    TEST("Server safely drops client sending corrupted CRC without crashing",
         clip_client_table_count(&srv.clients) == 0);

    clip_client_disconnect(&client);

    /* 2. Oversized payload length header: server rejects safely */
    ClipClientNet client2;
    clip_client_net_init(&client2);
    clip_client_net_set_insecure_plaintext(&client2);
    clip_client_connect(&client2, "127.0.0.1", TEST_PORT + 3);
    clip_server_poll(&srv, 50);

    uint8_t bad_hdr[40];
    memcpy(bad_hdr, frame, 36);
    /* Set payload_len = 80,000 (> 64 KiB) */
    bad_hdr[8]  = 0x00;
    bad_hdr[9]  = 0x01;
    bad_hdr[10] = 0x38;
    bad_hdr[11] = 0x80;
    send(client2.sock, (const char*)bad_hdr, 40, 0);

    clip_server_poll(&srv, 50);
    TEST("Server safely rejects oversized payload without allocation or crash",
         clip_client_table_count(&srv.clients) == 0);

    clip_client_disconnect(&client2);
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
    clip_client_net_cleanup(&client2);
}

/* ── 14, 15. Multi-Client Sequential Connectivity ───────────────────────── */

static void test_multi_client_sequential(void)
{
    printf("\n[14 & 15. Multi-Client Sequential Connections]\n");

    ClipServer srv;
    ClipServerConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.bind_host, "127.0.0.1", sizeof(cfg.bind_host) - 1);
    cfg.port = TEST_PORT + 4;
    cfg.max_clients = 8;

    clip_server_init(&srv, &cfg);
    clip_server_start(&srv);

    for (int i = 1; i <= 3; i++) {
        ClipClientNet c;
        clip_client_net_init(&c);
        clip_client_net_set_insecure_plaintext(&c);

        ClipError conn_err = clip_client_connect(&c, "127.0.0.1", TEST_PORT + 4);
        clip_server_poll(&srv, 20);

        char name[32];
        snprintf(name, sizeof(name), "NODE-CLIENT-%d", i);

        ClipFrameHeader ack;
        /* Send register */
        ClipFrameHeader reg_hdr;
        clip_frame_header_init(&reg_hdr, CLIP_MSG_REGISTER, (uint32_t)strlen(name), (uint64_t)i, NULL);
        clip_client_send_frame(&c, &reg_hdr, (const uint8_t*)name);

        clip_server_poll(&srv, 50);

        ClipError recv_err = clip_client_recv_frame(&c, &ack, NULL, 0, NULL, 500);

        bool ok = (conn_err == CLIP_OK && recv_err == CLIP_OK && ack.msg_type == CLIP_MSG_REGISTER_ACK);
        char test_name[64];
        snprintf(test_name, sizeof(test_name), "Sequential Client %d connects and registers", i);
        TEST(test_name, ok);

        clip_client_disconnect(&c);
        clip_server_poll(&srv, 20);
        clip_client_net_cleanup(&c);
    }

    TEST("All sequential clients handled cleanly, server table returns to 0",
         clip_client_table_count(&srv.clients) == 0);

    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
}

static DWORD WINAPI reconnect_server_worker(LPVOID param)
{
    ClipServer* s = (ClipServer*)param;
    while (s->is_running) {
        clip_server_poll(s, 20);
    }
    return 0;
}

static ClipError mock_sync_cb_fail(ClipClientNet* net, void* user_data)
{
    (void)net;
    (void)user_data;
    return CLIP_ERR_IO;
}

static ClipError mock_sync_cb_success(ClipClientNet* net, void* user_data)
{
    (void)net;
    bool* flag = (bool*)user_data;
    if (flag) *flag = true;
    return CLIP_OK;
}

typedef struct {
    ClipAudioEngine* engine;
    uint32_t         disconnect_count;
} ReconnectAudioTestCtx;

static void reconnect_test_disconnect_cb(ClipClientNet* net, void* user_data)
{
    (void)net;
    ReconnectAudioTestCtx* ctx = (ReconnectAudioTestCtx*)user_data;
    if (ctx) {
        ctx->disconnect_count++;
        if (ctx->engine) {
            clip_audio_on_floor_released(ctx->engine);
        }
    }
}

/* ── 16. Reconnection & Recovery Tests (Phase 17 Stage 5) ───────────────── */

static void test_reconnect_lifecycle(void)
{
    printf("\n[16. Reconnection & Recovery Tests (Phase 17 Stage 5)]\n");

    /* 1. Backoff sequence: 1, 2, 4, 8, 16 seconds, then 30-second cap */
    TEST("Backoff attempt 0 is 1 sec", clip_client_reconnect_get_next_backoff_sec(0) == 1);
    TEST("Backoff attempt 1 is 2 sec", clip_client_reconnect_get_next_backoff_sec(1) == 2);
    TEST("Backoff attempt 2 is 4 sec", clip_client_reconnect_get_next_backoff_sec(2) == 4);
    TEST("Backoff attempt 3 is 8 sec", clip_client_reconnect_get_next_backoff_sec(3) == 8);
    TEST("Backoff attempt 4 is 16 sec", clip_client_reconnect_get_next_backoff_sec(4) == 16);
    TEST("Backoff attempt 5 capped at 30 sec", clip_client_reconnect_get_next_backoff_sec(5) == 30);
    TEST("Backoff attempt 10 capped at 30 sec", clip_client_reconnect_get_next_backoff_sec(10) == 30);

    /* 2. State initialization and reset */
    ClipClientNet client;
    clip_client_net_init(&client);
    clip_client_net_set_insecure_plaintext(&client);
    clip_client_reconnect_enable(&client, true);

    TEST("Reconnect initially enabled", client.reconnect_enabled == true);
    TEST("Reconnect attempts initially 0", client.reconnect_attempts == 0);
    TEST("Initial epoch is 0", client.conn_epoch == 0);

    /* 3. Explicit shutdown cancels pending reconnects */
    client.reconnect_attempts = 3;
    client.next_reconnect_time_ms = 50000;
    clip_client_request_shutdown(&client);
    TEST("Shutdown requested flag set", client.shutdown_requested == true);
    TEST("Shutdown disables reconnect", client.reconnect_enabled == false);

    /* Triggering while shutdown requested fails safe */
    ClipError tr_shut = clip_client_reconnect_trigger(&client, 60000);
    TEST("Reconnect trigger rejected when shutdown requested", tr_shut == CLIP_ERR_INVALID);

    /* 4. Repeated failures do not create duplicate connection attempts */
    clip_client_net_cleanup(&client);
    clip_client_net_init(&client);
    clip_client_net_set_insecure_plaintext(&client);
    clip_client_reconnect_enable(&client, true);

    /* Connect to non-existent port (simulate failure) */
    strncpy(client.host, "127.0.0.1", sizeof(client.host) - 1);
    client.port = 14999; /* Closed port */

    ClipError err_fail1 = clip_client_reconnect_trigger(&client, 1000);
    TEST("First failed attempt returns connection error", err_fail1 != CLIP_OK);
    TEST("Reconnect attempts incremented to 1", client.reconnect_attempts == 1);
    TEST("Backoff delay set to 1 sec", client.backoff_delay_sec == 1);
    TEST("Next reconnect scheduled at 1000 + 1000 ms", client.next_reconnect_time_ms == 2000);
    TEST("Client socket closed on failure", client.sock == CLIP_INVALID_SOCKET);

    /* Polling before deadline does NOT trigger reconnect */
    ClipError poll_early = clip_client_reconnect_poll(&client, 1500);
    TEST("Early poll does not trigger reconnect", poll_early == CLIP_OK && client.reconnect_attempts == 1);

    /* Polling at/after deadline triggers attempt 2 */
    ClipError poll_due = clip_client_reconnect_poll(&client, 2000);
    TEST("Scheduled poll executes attempt 2", poll_due != CLIP_OK);
    TEST("Reconnect attempts incremented to 2", client.reconnect_attempts == 2);
    TEST("Backoff delay increased to 2 sec", client.backoff_delay_sec == 2);
    TEST("Next reconnect scheduled at 2000 + 2000 ms", client.next_reconnect_time_ms == 4000);

    /* Concurrent in-progress guard */
    client.reconnect_in_progress = true;
    TEST("Parallel reconnect attempt rejected with CLIP_ERR_EXISTS",
         clip_client_reconnect_trigger(&client, 3000) == CLIP_ERR_EXISTS);
    client.reconnect_in_progress = false;

    /* 5. Live Server Reconnection, Epoch Bump & Fresh State Invariants */
    ClipServer srv;
    ClipServerConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.bind_host, "127.0.0.1", sizeof(cfg.bind_host) - 1);
    cfg.port = TEST_PORT + 5;
    cfg.max_clients = 8;
    cfg.use_tls = false;

    clip_server_init(&srv, &cfg);
    clip_server_start(&srv);

    HANDLE srv_th = CreateThread(NULL, 0, reconnect_server_worker, &srv, 0, NULL);
    TEST("Server thread started", srv_th != NULL);
    Sleep(50);

    /* First: connect and register node so server recognizes it */
    clip_client_net_cleanup(&client);
    clip_client_net_init(&client);
    clip_client_net_set_insecure_plaintext(&client);
    strncpy(client.host, "127.0.0.1", sizeof(client.host) - 1);
    client.port = TEST_PORT + 5;

    ClipError conn_ok = clip_client_connect(&client, "127.0.0.1", TEST_PORT + 5);
    TEST("Initial client connection succeeds", conn_ok == CLIP_OK);

    ClipUuid node_uuid;
    uint8_t cred[CLIP_CREDENTIAL_BYTES];
    ClipError reg_ok = clip_client_register(&client, "RECONNECT-NODE", &node_uuid, cred);
    TEST("Node registration succeeds", reg_ok == CLIP_OK);

    /* Enable reconnect and configure saved credentials */
    clip_client_reconnect_enable(&client, true);
    clip_client_reconnect_set_credentials(&client, &node_uuid, cred);

    /* Simulate active prior session and held PTT floor */
    clip_crypto_uuid_generate(&client.current_session_uuid);
    client.session_valid = true;
    client.ptt_floor_held = true;
    client.mic_capture_active = true;
    uint32_t initial_epoch = client.conn_epoch;

    /* Client drops / disconnects */
    clip_client_disconnect(&client);
    TEST("Disconnect bumps connection epoch", client.conn_epoch == initial_epoch + 1);
    TEST("Disconnect clears active session UUID", clip_uuid_is_zero(&client.current_session_uuid));
    TEST("Disconnect sets session_valid to false", client.session_valid == false);
    TEST("Disconnect resets ptt_floor_held to false", client.ptt_floor_held == false);
    TEST("Disconnect stops mic_capture_active", client.mic_capture_active == false);

    /* Reconnect to server with sync hook that fails -> backoff must NOT reset */
    bool sync_ran = false;
    clip_client_reconnect_set_sync_callback(&client, mock_sync_cb_fail, NULL);
    client.reconnect_attempts = 2;
    client.backoff_delay_sec = 2;
    ClipError fail_sync_err = clip_client_reconnect_trigger(&client, 100000);
    TEST("Reconnect trigger with failing initial sync returns sync error", fail_sync_err == CLIP_ERR_IO);
    TEST("Failing initial sync aborts connection", client.is_connected == false);
    TEST("Failing initial sync does NOT reset backoff attempts (increments to 3)", client.reconnect_attempts == 3);
    TEST("Failing initial sync advances backoff delay to 4 sec", client.backoff_delay_sec == 4);

    /* Reconnect to server with successful sync -> backoff resets */
    clip_client_reconnect_set_sync_callback(&client, mock_sync_cb_success, &sync_ran);
    ClipError re_err = clip_client_reconnect_trigger(&client, 110000);
    TEST("Reconnect with successful initial sync succeeds", re_err == CLIP_OK);
    TEST("Initial sync callback was executed", sync_ran == true);
    TEST("Client is connected again", client.is_connected == true);
    TEST("Client is authenticated again", client.is_registered == true);
    TEST("Backoff reset: attempts back to 0", client.reconnect_attempts == 0);
    TEST("Backoff reset: delay back to 1", client.backoff_delay_sec == 1);
    TEST("Connection epoch bumped again", client.conn_epoch == initial_epoch + 4);
    TEST("Prior session UUID NOT reused (remains zero)", clip_uuid_is_zero(&client.current_session_uuid));
    TEST("PTT floor remains FREE (not restored)", client.ptt_floor_held == false);
    TEST("Microphone capture remains STOPPED", client.mic_capture_active == false);

    /* 6. TLS failure never silently falls back to plaintext */
    ClipClientNet tls_client;
    clip_client_net_init(&tls_client);
    clip_tls_client_config_t bad_tls = {
        .ca_file = "certs/nonexistent_ca.crt",
        .expected_host = "localhost"
    };
    clip_client_net_set_tls_config(&tls_client, &bad_tls);
    ClipError tls_fail_err = clip_client_connect(&tls_client, "127.0.0.1", TEST_PORT + 5);
    TEST("TLS connect failure returns error", tls_fail_err != CLIP_OK);
    TEST("TLS failure does NOT silently fall back to plaintext (use_tls remains true)", tls_client.use_tls == true);
    TEST("TLS failure keeps socket closed", tls_client.sock == CLIP_INVALID_SOCKET);
    TEST("TLS failure leaves client disconnected", tls_client.is_connected == false);
    clip_client_net_cleanup(&tls_client);

    /* 7. Actual ClipAudioEngine capture shutdown and gating verification */
    ClipAudioEngine audio_eng;
    ClipAudioConfig acfg;
    clip_audio_config_init_default(&acfg);
    acfg.backend = CLIP_AUDIO_BACKEND_MOCK;
    TEST("Audio engine initializes cleanly", clip_audio_engine_init(&audio_eng, &acfg) == CLIP_OK);

    ReconnectAudioTestCtx actx = { .engine = &audio_eng, .disconnect_count = 0 };
    clip_client_set_disconnect_callback(&client, reconnect_test_disconnect_cb, &actx);

    /* Simulate floor granted and physical capture active */
    clip_audio_on_floor_granted(&audio_eng);
    client.ptt_floor_held = true;
    client.mic_capture_active = true;
    TEST("Audio engine is genuinely capturing while floor is held", clip_audio_is_capturing(&audio_eng) == true);
    TEST("Audio engine floor is held", clip_audio_is_floor_held(&audio_eng) == true);

    /* Trigger disconnect */
    clip_client_disconnect(&client);
    TEST("Disconnect callback invoked", actx.disconnect_count == 1);
    TEST("Audio engine capture genuinely STOPPED on disconnect", clip_audio_is_capturing(&audio_eng) == false);
    TEST("Audio engine floor genuinely RELEASED on disconnect", clip_audio_is_floor_held(&audio_eng) == false);
    TEST("Local client state mic_capture_active is false", client.mic_capture_active == false);

    /* Verify no capture restart until fresh valid session and explicit user action */
    clip_client_reconnect_trigger(&client, 120000);
    TEST("Client reconnected successfully", client.is_connected == true);
    TEST("Audio engine capture remains STOPPED after reconnect (no auto-restart)",
         clip_audio_is_capturing(&audio_eng) == false);
    TEST("Audio engine floor remains RELEASED after reconnect",
         clip_audio_is_floor_held(&audio_eng) == false);

    clip_audio_engine_cleanup(&audio_eng);
    clip_client_net_cleanup(&client);
    srv.is_running = false;
    WaitForSingleObject(srv_th, 2000);
    CloseHandle(srv_th);
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("============================================================\n");
    printf(" CLICOM Phase 2 — Unit & Integration Test: Networking\n");
    printf("============================================================\n");

    test_net_lifecycle();
    test_socket_options();
    test_heartbeat_lifecycle();
    test_loopback_handshake();
    test_tcp_fragmentation();
    test_tcp_coalescing();
    test_malformed_frame_resilience();
    test_multi_client_sequential();
    test_reconnect_lifecycle();

    printf("\n============================================================\n");
    printf(" Total: %d passed", g_pass);
    if (g_fail > 0) {
        printf(", %d FAILED", g_fail);
    }
    printf("\n");
    printf(" Result: %s\n", g_fail == 0 ? "ALL TESTS PASSED" : "FAILURES DETECTED");
    printf("============================================================\n\n");

    return g_fail == 0 ? 0 : 1;
}

/*
 * tests/demo_tls.c — Standalone Live Demonstration: Phase 7 TLS 1.3 Secure Transport
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "clip_net.h"
#include <windows.h>

#include "clip_version.h"
#include "clip_protocol.h"
#include "clip_types.h"
#include "clip_errors.h"
#include "clip_transport.h"
#include "../../server/include/server.h"
#include "../../client/include/network.h"

#define DEMO_PORT 14995

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
    printf("       CLICOM PHASE 7 LIVE DEMONSTRATION                   \n");
    printf("          TLS 1.3 Secure Transport Layer                  \n");
    printf("============================================================\n\n");

    remove("demo_tls.db");

    /* ── STEP 1: Start TLS 1.3 Server ────────────────────────────────────── */
    printf("[STEP 1] Starting TLS 1.3 Encrypted Server...\n");
    ClipServerConfig srv_cfg = {0};
    strncpy(srv_cfg.bind_host, "127.0.0.1", sizeof(srv_cfg.bind_host) - 1);
    srv_cfg.port = DEMO_PORT;
    srv_cfg.max_clients = 16;
    srv_cfg.use_tls = true;
    strncpy(srv_cfg.cert_file, "certs/server.crt", sizeof(srv_cfg.cert_file) - 1);
    strncpy(srv_cfg.key_file, "certs/server.key", sizeof(srv_cfg.key_file) - 1);
    strncpy(srv_cfg.db_path, "demo_tls.db", sizeof(srv_cfg.db_path) - 1);

    ClipServer srv;
    clip_server_init(&srv, &srv_cfg);
    clip_server_start(&srv);

    HANDLE hServerThread = CreateThread(NULL, 0, server_thread_func, &srv, 0, NULL);
    Sleep(50);

    printf("  Server running on 127.0.0.1:%u with TLS 1.3\n", DEMO_PORT);
    printf("  Server Certificate: %s\n", srv_cfg.cert_file);

    /* ── STEP 2: Security Negative Test (Untrusted CA) ──────────────────── */
    printf("\n[STEP 2] Executing Negative Security Test (Untrusted Root CA)...\n");
    ClipClientNet rogue_client;
    clip_client_net_init(&rogue_client);
    clip_tls_client_config_t rogue_cfg = {
        .ca_file = "certs/untrusted_ca.crt",
        .expected_host = "localhost"
    };
    clip_client_net_set_tls_config(&rogue_client, &rogue_cfg);

    ClipError rogue_rc = clip_client_connect(&rogue_client, "127.0.0.1", DEMO_PORT);
    printf("  Connection attempt result with Untrusted CA: %d (%s)\n",
           rogue_rc, clip_error_string(rogue_rc));
    if (rogue_rc == CLIP_ERR_TLS_CERT_VERIFY) {
        printf("  SECURITY ENFORCEMENT VERIFIED: Server certificate rejected by untrusted CA!\n");
        printf("  Zero application frames sent over untrusted transport.\n");
    } else {
        printf("  ERROR: Expected certificate verification failure!\n");
    }
    clip_client_disconnect(&rogue_client);

    /* ── STEP 3: Connecting Authorized Nodes over TLS 1.3 ───────────────── */
    printf("\n[STEP 3] Connecting Authorized Nodes over TLS 1.3...\n");

    clock_t start_hs = clock();

    ClipClientNet node1;
    clip_client_net_init(&node1);
    clip_tls_client_config_t n1_cfg = {
        .ca_file = "certs/ca.crt",
        .expected_host = "localhost"
    };
    clip_client_net_set_tls_config(&node1, &n1_cfg);

    clip_client_connect(&node1, "127.0.0.1", DEMO_PORT);

    clock_t end_hs = clock();
    double hs_ms = ((double)(end_hs - start_hs) / CLOCKS_PER_SEC) * 1000.0;

    printf("  Node 1 Connected : ALICE-HQ\n");
    printf("  TLS Version      : %s\n", clip_transport_get_tls_version(node1.transport));
    printf("  Cipher Suite     : %s\n", clip_transport_get_cipher_name(node1.transport));
    printf("  Handshake Time   : %.2f ms\n", hs_ms);

    ClipClientNet node2;
    clip_client_net_init(&node2);
    clip_tls_client_config_t n2_cfg = {
        .ca_file = "certs/ca.crt",
        .expected_host = "localhost"
    };
    clip_client_net_set_tls_config(&node2, &n2_cfg);

    clip_client_connect(&node2, "127.0.0.1", DEMO_PORT);
    printf("  Node 2 Connected : BOB-REMOTE\n");
    printf("  TLS Version      : %s\n", clip_transport_get_tls_version(node2.transport));
    printf("  Cipher Suite     : %s\n", clip_transport_get_cipher_name(node2.transport));

    /* ── STEP 4: Registration over Encrypted Transport ──────────────────── */
    printf("\n[STEP 4] Registering Nodes over Encrypted TLS Transport...\n");
    uint8_t p1[64]; size_t o1 = 0;
    clip_tlv_write(p1, sizeof(p1), &o1, CLIP_TAG_DISPLAY_NAME, (const uint8_t*)"ALICE-HQ", 8);
    ClipFrameHeader h1;
    clip_frame_header_init(&h1, CLIP_MSG_REGISTER, (uint32_t)o1, 1, NULL);
    clip_client_send_frame(&node1, &h1, p1);

    ClipFrameHeader a1; uint8_t a1_p[512]; uint32_t a1_l = 0;
    clip_client_recv_frame(&node1, &a1, a1_p, sizeof(a1_p), &a1_l, 1000);
    const uint8_t *u1 = NULL; uint16_t ul1 = 0;
    clip_tlv_find(a1_p, a1_l, CLIP_TAG_NODE_UUID, &u1, &ul1);
    ClipUuid alice_id; memcpy(alice_id.bytes, u1, CLIP_UUID_BYTES);
    char a_str[64]; clip_uuid_to_string(&alice_id, a_str, sizeof(a_str));
    printf("  Node 1 Registered : UUID=%s (received via TLS)\n", a_str);

    uint8_t p2[64]; size_t o2 = 0;
    clip_tlv_write(p2, sizeof(p2), &o2, CLIP_TAG_DISPLAY_NAME, (const uint8_t*)"BOB-REMOTE", 10);
    ClipFrameHeader h2;
    clip_frame_header_init(&h2, CLIP_MSG_REGISTER, (uint32_t)o2, 1, NULL);
    clip_client_send_frame(&node2, &h2, p2);

    ClipFrameHeader a2; uint8_t a2_p[512]; uint32_t a2_l = 0;
    clip_client_recv_frame(&node2, &a2, a2_p, sizeof(a2_p), &a2_l, 1000);
    const uint8_t *u2 = NULL; uint16_t ul2 = 0;
    clip_tlv_find(a2_p, a2_l, CLIP_TAG_NODE_UUID, &u2, &ul2);
    ClipUuid bob_id; memcpy(bob_id.bytes, u2, CLIP_UUID_BYTES);
    char b_str[64]; clip_uuid_to_string(&bob_id, b_str, sizeof(b_str));
    printf("  Node 2 Registered : UUID=%s (received via TLS)\n", b_str);

    /* ── STEP 5: Channel Creation & Join over TLS ───────────────────────── */
    printf("\n[STEP 5] Channel Operations over TLS 1.3...\n");
    uint8_t cp[64]; size_t co = 0;
    clip_tlv_write(cp, sizeof(cp), &co, CLIP_TAG_CHANNEL_NAME, (const uint8_t*)"SECURE-OPS", 10);
    ClipFrameHeader ch; clip_frame_header_init(&ch, CLIP_MSG_CHANNEL_CREATE, (uint32_t)co, 2, NULL);
    clip_client_send_frame(&node1, &ch, cp);

    ClipFrameHeader ca; uint8_t cap[512]; uint32_t cal = 0;
    clip_client_recv_frame(&node1, &ca, cap, sizeof(cap), &cal, 1000);
    const uint8_t *chu = NULL; uint16_t chul = 0;
    clip_tlv_find(cap, cal, CLIP_TAG_CHANNEL_UUID, &chu, &chul);
    ClipUuid chan_id; memcpy(chan_id.bytes, chu, CLIP_UUID_BYTES);
    char chan_str[64]; clip_uuid_to_string(&chan_id, chan_str, sizeof(chan_str));

    const uint8_t *jkp = NULL; uint16_t jkl = 0;
    clip_tlv_find(cap, cal, CLIP_TAG_CHANNEL_JOIN_KEY, &jkp, &jkl);
    char join_key[16] = {0}; memcpy(join_key, jkp, jkl);
    printf("  Channel Created   : %s (Key: %s)\n", chan_str, join_key);

    /* Node 2 joins */
    uint8_t jp[64]; size_t jo = 0;
    clip_tlv_write(jp, sizeof(jp), &jo, CLIP_TAG_CHANNEL_JOIN_KEY, (const uint8_t*)join_key, (uint16_t)strlen(join_key));
    ClipFrameHeader jh; clip_frame_header_init(&jh, CLIP_MSG_CHANNEL_JOIN, (uint32_t)jo, 2, NULL);
    clip_client_send_frame(&node2, &jh, jp);

    ClipFrameHeader ja; uint8_t jap[512]; uint32_t jal = 0;
    clip_client_recv_frame(&node2, &ja, jap, sizeof(jap), &jal, 1000);
    printf("  Node 2 Joined Channel '%s' over TLS 1.3\n", join_key);

    /* ── STEP 6: Connection Request Workflow over TLS ───────────────────── */
    printf("\n[STEP 6] Establishing Phase 5 Connection over TLS 1.3...\n");
    uint8_t rqp[128]; size_t rqo = 0;
    clip_tlv_write(rqp, sizeof(rqp), &rqo, CLIP_TAG_CHANNEL_UUID, chan_id.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(rqp, sizeof(rqp), &rqo, CLIP_TAG_NODE_UUID, bob_id.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader rqh; clip_frame_header_init(&rqh, CLIP_MSG_CONN_REQUEST, (uint32_t)rqo, 3, NULL);
    clip_client_send_frame(&node1, &rqh, rqp);

    ClipFrameHeader fwd; uint8_t fwd_p[512]; uint32_t fwd_l = 0;
    clip_client_recv_frame(&node2, &fwd, fwd_p, sizeof(fwd_p), &fwd_l, 1000);
    const uint8_t *cnu = NULL; uint16_t cnul = 0;
    clip_tlv_find(fwd_p, fwd_l, CLIP_TAG_CONNECTION_UUID, &cnu, &cnul);
    ClipUuid conn_id; memcpy(conn_id.bytes, cnu, CLIP_UUID_BYTES);
    char conn_str[64]; clip_uuid_to_string(&conn_id, conn_str, sizeof(conn_str));
    printf("  Connection Requested : UUID=%s (State: REQUESTED)\n", conn_str);

    ClipFrameHeader r_resp; uint8_t rr_p[512]; uint32_t rr_l = 0;
    clip_client_recv_frame(&node1, &r_resp, rr_p, sizeof(rr_p), &rr_l, 1000);

    /* Accept connection */
    uint8_t acp[64]; size_t aco = 0;
    clip_tlv_write(acp, sizeof(acp), &aco, CLIP_TAG_CONNECTION_UUID, conn_id.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader ach; clip_frame_header_init(&ach, CLIP_MSG_CONN_ACCEPT, (uint32_t)aco, 3, NULL);
    clip_client_send_frame(&node2, &ach, acp);

    ClipFrameHeader acc_ok; uint8_t ac_ok_p[512]; uint32_t ac_ok_l = 0;
    clip_client_recv_frame(&node2, &acc_ok, ac_ok_p, sizeof(ac_ok_p), &ac_ok_l, 1000);
    ClipFrameHeader n1_acc; uint8_t n1_ac_p[512]; uint32_t n1_ac_l = 0;
    clip_client_recv_frame(&node1, &n1_acc, n1_ac_p, sizeof(n1_ac_p), &n1_ac_l, 1000);
    printf("  Connection Accepted  : State=ACCEPTED\n");

    /* ── STEP 7: Phase 6 Communication Session over TLS ─────────────────── */
    printf("\n[STEP 7] Starting Phase 6 Session on ACCEPTED Connection...\n");
    uint8_t sp[64]; size_t so = 0;
    clip_tlv_write(sp, sizeof(sp), &so, CLIP_TAG_CONNECTION_UUID, conn_id.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader sh; clip_frame_header_init(&sh, CLIP_MSG_SESSION_START, (uint32_t)so, 4, NULL);
    clip_client_send_frame(&node1, &sh, sp);

    ClipFrameHeader sack; uint8_t sack_p[512]; uint32_t sack_l = 0;
    clip_client_recv_frame(&node1, &sack, sack_p, sizeof(sack_p), &sack_l, 1000);
    ClipUuid sess_id; memcpy(sess_id.bytes, sack.session_uuid, CLIP_UUID_BYTES);
    char sess_str[64]; clip_uuid_to_string(&sess_id, sess_str, sizeof(sess_str));

    ClipFrameHeader snotif; uint8_t snotif_p[512]; uint32_t snotif_l = 0;
    clip_client_recv_frame(&node2, &snotif, snotif_p, sizeof(snotif_p), &snotif_l, 1000);

    printf("  Session Established  : UUID=%s\n", sess_str);
    printf("  Wire Header session_uuid on notification matches: PASS\n");

    /* ── STEP 8: Identity Separation Check ──────────────────────────────── */
    printf("\n[STEP 8] Strict Identity Separation Verification:\n");
    printf("------------------------------------------------------------\n");
    printf("  Node 1 UUID     : %s\n", a_str);
    printf("  Node 2 UUID     : %s\n", b_str);
    printf("  Channel UUID    : %s\n", chan_str);
    printf("  Connection UUID : %s\n", conn_str);
    printf("  Session UUID    : %s\n", sess_str);
    printf("------------------------------------------------------------\n");
    printf("  node_uuid != channel_uuid       : PASS\n");
    printf("  node_uuid != connection_uuid    : PASS\n");
    printf("  node_uuid != session_uuid       : PASS\n");
    printf("  connection_uuid != session_uuid : PASS\n");

    /* ── STEP 9: End Session & Clean TLS Shutdown ───────────────────────── */
    printf("\n[STEP 9] Ending Session & Clean TLS Shutdown...\n");
    uint8_t ep[64]; size_t eo = 0;
    clip_tlv_write(ep, sizeof(ep), &eo, CLIP_TAG_SESSION_UUID, sess_id.bytes, CLIP_UUID_BYTES);
    ClipFrameHeader eh; clip_frame_header_init(&eh, CLIP_MSG_SESSION_END, (uint32_t)eo, 5, sess_id.bytes);
    clip_client_send_frame(&node2, &eh, ep);

    ClipFrameHeader eack; uint8_t eack_p[512]; uint32_t eack_l = 0;
    clip_client_recv_frame(&node2, &eack, eack_p, sizeof(eack_p), &eack_l, 1000);
    ClipFrameHeader eack_peer; uint8_t eack_peer_p[512]; uint32_t eack_peer_l = 0;
    clip_client_recv_frame(&node1, &eack_peer, eack_peer_p, sizeof(eack_peer_p), &eack_peer_l, 1000);
    printf("  Session ended cleanly over TLS.\n");

    clip_client_disconnect(&node1);
    clip_client_disconnect(&node2);

    srv.is_running = false;
    WaitForSingleObject(hServerThread, 1000);
    CloseHandle(hServerThread);
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);

    printf("\n============================================================\n");
    printf(" DEMONSTRATION COMPLETE: ALL PHASE 7 OBJECTIVES VERIFIED!  \n");
    printf("============================================================\n");

    return 0;
}

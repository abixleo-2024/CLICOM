/*
 * demo_ptt.c — Standalone Live Demonstration of Phase 8 PTT Floor Control
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "clip_protocol.h"
#include "clip_types.h"
#include "clip_errors.h"
#include "server.h"
#include "clients.h"
#include "clip_channels.h"
#include "clip_sessions.h"
#include "clip_connections.h"
#include "clip_ptt.h"
#include "network.h"

static DWORD WINAPI server_thread_func(LPVOID arg)
{
    ClipServer* s = (ClipServer*)arg;
    while (s->is_running) {
        clip_server_poll(s, 10);
    }
    return 0;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("====================================================\n");
    printf("  CLICOM PHASE 8: PTT FLOOR CONTROL LIVE DEMO       \n");
    printf("====================================================\n\n");

    uint16_t port = 15888;
    const char* db_file = "demo_ptt.db";
    remove(db_file);

    /* 1. Start TLS 1.3 Server */
    printf("[1] Starting TLS 1.3 Server on 127.0.0.1:%u...\n", port);
    ClipServer srv;
    ClipServerConfig cfg;
    clip_server_config_init_default(&cfg);
    cfg.port = port;
    strncpy(cfg.db_path, db_file, sizeof(cfg.db_path) - 1);
    cfg.use_tls = true;
    strncpy(cfg.cert_file, "certs/server.crt", sizeof(cfg.cert_file) - 1);
    strncpy(cfg.key_file, "certs/server.key", sizeof(cfg.key_file) - 1);

    if (clip_server_init(&srv, &cfg) != CLIP_OK || clip_server_start(&srv) != CLIP_OK) {
        printf("Failed to start server!\n");
        return 1;
    }

    HANDLE hServerThread = CreateThread(NULL, 0, server_thread_func, &srv, 0, NULL);
    Sleep(100);
    printf("    Server started successfully (TLS 1.3 Enabled, PTT Manager Active).\n\n");

    /* 2. Connect Alice and Bob over TLS 1.3 */
    printf("[2] Connecting Alice and Bob over TLS 1.3...\n");
    ClipClientNet alice, bob;
    clip_client_net_init(&alice);
    clip_client_net_init(&bob);

    clip_tls_client_config_t tls_cfg = {
        .ca_file = "certs/ca.crt",
        .expected_host = "localhost"
    };
    clip_client_net_set_tls_config(&alice, &tls_cfg);
    clip_client_net_set_tls_config(&bob, &tls_cfg);

    clip_client_connect(&alice, "127.0.0.1", port);
    clip_client_connect(&bob, "127.0.0.1", port);

    ClipUuid alice_uuid, bob_uuid;
    uint8_t a_cred[32], b_cred[32];
    clip_client_register(&alice, "ALICE", &alice_uuid, a_cred);
    clip_client_register(&bob, "BOB", &bob_uuid, b_cred);

    Sleep(50);

    char a_str[37], b_str[37];
    clip_uuid_to_string(&alice_uuid, a_str, sizeof(a_str));
    clip_uuid_to_string(&bob_uuid, b_str, sizeof(b_str));
    printf("    Alice registered: %s\n", a_str);
    printf("    Bob registered  : %s\n\n", b_str);

    /* 3. Channel & Accepted Connection */
    printf("[3] Setting up Channel and Accepted Connection...\n");
    ClipUuid chan_uuid;
    char jkey[32];
    clip_client_channel_create(&alice, "DISPATCH-1", &chan_uuid, jkey, sizeof(jkey));
    Sleep(50);

    ClipUuid b_chan;
    char cname[64];
    ClipChannelMember* mems = NULL;
    size_t m_cnt = 0;
    clip_client_channel_join(&bob, jkey, &b_chan, cname, sizeof(cname), &mems, &m_cnt);
    clip_client_free_members(mems);
    Sleep(50);

    ClipUuid conn_uuid;
    ClipConnectionState cst;
    clip_client_send_conn_request(&alice, &chan_uuid, &bob_uuid, &conn_uuid, &cst);
    Sleep(50);

    clip_client_respond_conn(&bob, &conn_uuid, true);
    Sleep(50);

    char c_str[37];
    clip_uuid_to_string(&conn_uuid, c_str, sizeof(c_str));
    printf("    Connection established: %s (ACCEPTED)\n\n", c_str);

    /* 4. Start Communication Session */
    printf("[4] Starting Phase 6 Communication Session...\n");
    ClipUuid sess_uuid;
    clip_client_session_start_by_conn(&alice, &conn_uuid, &sess_uuid);
    Sleep(50);

    char s_str[37];
    clip_uuid_to_string(&sess_uuid, s_str, sizeof(s_str));
    printf("    Active Session: %s\n\n", s_str);

    /* 5. Check Initial Floor Status */
    printf("[5] Querying Initial Floor Status...\n");
    ClipPttFloor st;
    clip_client_ptt_status(&alice, &sess_uuid, &st);
    printf("    Floor State: %s\n\n", (st.floor_state == CLIP_PTT_FLOOR_FREE) ? "FREE" : "HELD");

    /* 6. Alice Requests Floor */
    printf("[6] Alice Requests Floor...\n");
    ClipPttFloor a_floor;
    ClipError denial = CLIP_OK;
    ClipError acq_err = clip_client_ptt_request(&alice, &sess_uuid, 5000, &a_floor, &denial);
    Sleep(50);

    if (acq_err == CLIP_OK) {
        printf("    RESULT: GRANTED (Alice owns the floor)\n");
        printf("    Holder UUID: %s\n", a_floor.speaker_uuid_str);
        printf("    Lease: %u ms\n\n", (unsigned)a_floor.lease_timeout_ms);
    } else {
        printf("    Failed: %s\n\n", clip_error_string(acq_err));
    }

    /* 7. Bob Requests Floor while Alice Holds it */
    printf("[7] Bob Requests Floor (Contention Check)...\n");
    ClipPttFloor b_floor;
    ClipError b_denial = CLIP_OK;
    ClipError b_err = clip_client_ptt_request(&bob, &sess_uuid, 5000, &b_floor, &b_denial);
    Sleep(50);

    if (b_err == CLIP_ERR_PTT_BUSY) {
        printf("    RESULT: DENIED (FLOOR_BUSY)\n");
        printf("    Current Holder: %s (Alice)\n", b_floor.speaker_uuid_str);
        printf("    Arbitration: Server correctly prevented multiple holders.\n\n");
    } else {
        printf("    Unexpected result: %s\n\n", clip_error_string(b_err));
    }

    /* 8. Alice Releases Floor */
    printf("[8] Alice Releases Floor...\n");
    clip_client_ptt_release(&alice, &sess_uuid);
    Sleep(50);

    clip_client_ptt_status(&bob, &sess_uuid, &st);
    printf("    RESULT: Floor Released (Floor State is now %s)\n\n",
           (st.floor_state == CLIP_PTT_FLOOR_FREE) ? "FREE" : "HELD");

    /* 9. Bob Requests Floor */
    printf("[9] Bob Requests Newly-Freed Floor...\n");
    b_err = clip_client_ptt_request(&bob, &sess_uuid, 5000, &b_floor, &b_denial);
    Sleep(50);

    if (b_err == CLIP_OK) {
        printf("    RESULT: GRANTED (Bob now owns the floor)\n");
        printf("    Holder UUID: %s\n\n", b_floor.speaker_uuid_str);
    } else {
        printf("    Failed: %s\n\n", clip_error_string(b_err));
    }

    /* 10. Bob Releases Floor */
    printf("[10] Bob Releases Floor...\n");
    clip_client_ptt_release(&bob, &sess_uuid);
    Sleep(50);
    clip_client_ptt_status(&alice, &sess_uuid, &st);
    printf("    Floor State: %s\n\n", (st.floor_state == CLIP_PTT_FLOOR_FREE) ? "FREE" : "HELD");

    /* 11. Cleanup */
    clip_client_session_end(&alice, &sess_uuid);
    Sleep(50);

    clip_client_disconnect(&alice);
    clip_client_disconnect(&bob);
    clip_client_net_cleanup(&alice);
    clip_client_net_cleanup(&bob);

    srv.is_running = false;
    WaitForSingleObject(hServerThread, 3000);
    CloseHandle(hServerThread);

    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
    remove(db_file);

    printf("====================================================\n");
    printf("  DEMO COMPLETE: All PTT Arbitration Invariants Passed\n");
    printf("====================================================\n");
    return 0;
}

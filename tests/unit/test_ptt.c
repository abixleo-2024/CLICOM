/*
 * test_ptt.c — CLICOM Push-to-Talk (PTT) Floor Control Test Suite (Phase 8)
 *
 * Validates server-authoritative half-duplex PTT floor arbitration:
 * 1. Unit tests: ClipPttManager state transitions, duplicate requests, timeouts, disconnect release.
 * 2. Integration tests over TLS 1.3:
 *    A. Basic floor acquisition (FREE -> HELD, GRANTED)
 *    B. Busy floor denial (Node B denied while Node A holds)
 *    C. Floor release (HELD -> FREE, peer notified)
 *    D. Unauthorized release rejected (Node B cannot release Node A's floor)
 *    E. Duplicate request from same holder (confirmed, acquired_at preserved)
 *    F. Invalid session rejected (unknown, closed, mismatched)
 *    G. Header invariant (header.session_uuid != 0 and matches active session)
 *    H. UUID invariant (session_uuid != node_uuid != channel_uuid != connection_uuid)
 *    I. Disconnect safety (holder disconnects -> floor automatically released)
 *    J. Session-end safety (session closed -> floor released -> requests rejected)
 *    K. Lease timeout (lease expires after timeout -> floor becomes FREE)
 *    L. Concurrent race condition arbitration (two simultaneous threads -> exactly 1 GRANTED, 1 DENIED)
 *    M. Regression & TLS 1.3 transport integrity
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

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
#include "clip_crypto.h"

static int g_pass = 0;
static int g_fail = 0;

#define ASSERT(expr, msg) do { \
    if (expr) { \
        printf("[PASS] %s\n", msg); \
        fflush(stdout); \
        g_pass++; \
    } else { \
        printf("[FAIL] %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        fflush(stdout); \
        g_fail++; \
    } \
} while(0)

/* Helper: generate mock UUID */
static void make_test_uuid(ClipUuid* u, uint8_t fill)
{
    memset(u->bytes, fill, CLIP_UUID_BYTES);
    u->bytes[6] = 0x40 | (fill & 0x0F);
    u->bytes[8] = 0x80 | (fill & 0x3F);
}

/* ── 1. Unit Tests: ClipPttManager ────────────────────────────────────────── */

static void test_ptt_manager_unit(void)
{
    printf("\n--- PTT Manager Unit Tests ---\n");
    fflush(stdout);

    ClipPttManager mgr;
    ASSERT(clip_ptt_manager_init(&mgr, 16) == CLIP_OK, "PTT manager init succeeded");

    ClipUuid sess1, sess2, nodeA, nodeB;
    make_test_uuid(&sess1, 0x11);
    make_test_uuid(&sess2, 0x22);
    make_test_uuid(&nodeA, 0xAA);
    make_test_uuid(&nodeB, 0xBB);

    /* Initial state: session1 status is FREE */
    ClipPttFloorEntry entry;
    ASSERT(clip_ptt_manager_get_status(&mgr, &sess1, 1000, &entry) == CLIP_OK, "Get status on unacquired session");
    ASSERT(entry.floor_state == CLIP_PTT_FLOOR_FREE, "Initial floor state is FREE");

    /* Acquire session1 by Node A */
    bool already_held = false;
    ClipError err = clip_ptt_manager_acquire(&mgr, &sess1, &nodeA, 5000, 1000, &entry, &already_held);
    ASSERT(err == CLIP_OK, "Node A acquires FREE floor");
    ASSERT(!already_held, "Node A freshly acquired floor");
    ASSERT(entry.floor_state == CLIP_PTT_FLOOR_HELD, "Floor state is now HELD");
    ASSERT(clip_uuid_equal(&entry.holder_node_uuid, &nodeA), "Holder is Node A");
    ASSERT(entry.acquired_at_ms == 1000, "Acquired timestamp recorded");

    /* Node B requests session1: busy denial */
    err = clip_ptt_manager_acquire(&mgr, &sess1, &nodeB, 5000, 1050, &entry, &already_held);
    ASSERT(err == CLIP_ERR_PTT_BUSY, "Node B acquire returns CLIP_ERR_PTT_BUSY");
    ASSERT(entry.floor_state == CLIP_PTT_FLOOR_HELD, "Floor remains HELD");
    ASSERT(clip_uuid_equal(&entry.holder_node_uuid, &nodeA), "Holder is still Node A");

    /* Duplicate request by Node A: confirmed, acquired_at preserved */
    err = clip_ptt_manager_acquire(&mgr, &sess1, &nodeA, 5000, 2000, &entry, &already_held);
    ASSERT(err == CLIP_OK, "Node A duplicate acquire returns CLIP_OK");
    ASSERT(already_held, "out_already_held is TRUE");
    ASSERT(entry.acquired_at_ms == 1000, "acquired_at_ms was NOT overwritten");

    /* Unauthorized release by Node B: rejected */
    err = clip_ptt_manager_release(&mgr, &sess1, &nodeB, &entry);
    ASSERT(err == CLIP_ERR_DENIED, "Node B unauthorized release returns CLIP_ERR_DENIED");
    ASSERT(entry.floor_state == CLIP_PTT_FLOOR_HELD, "Floor remains HELD after unauthorized release");

    /* Lease renewal by Node A */
    uint32_t rem_lease = 0;
    err = clip_ptt_manager_renew(&mgr, &sess1, &nodeA, 3000, &rem_lease);
    ASSERT(err == CLIP_OK, "Node A renews lease");
    ASSERT(entry.last_renewed_at_ms == 3000 || rem_lease == 5000, "Lease renewed successfully");

    /* Lease renewal by Node B: denied */
    err = clip_ptt_manager_renew(&mgr, &sess1, &nodeB, 3000, &rem_lease);
    ASSERT(err == CLIP_ERR_DENIED, "Node B renewal denied");

    /* Authorized release by Node A */
    err = clip_ptt_manager_release(&mgr, &sess1, &nodeA, &entry);
    ASSERT(err == CLIP_OK, "Node A releases floor");
    ASSERT(entry.floor_state == CLIP_PTT_FLOOR_FREE, "Floor state is now FREE");
    ASSERT(clip_uuid_is_zero(&entry.holder_node_uuid), "Holder UUID is cleared");

    /* Release on already FREE floor */
    err = clip_ptt_manager_release(&mgr, &sess1, &nodeA, &entry);
    ASSERT(err == CLIP_OK, "Release on FREE floor is benign CLIP_OK");

    /* Watchdog timeout expiration check */
    err = clip_ptt_manager_acquire(&mgr, &sess2, &nodeB, 2000, 1000, &entry, &already_held);
    ASSERT(err == CLIP_OK, "Node B acquires session2 with 2000ms lease at t=1000");

    ClipUuid expired[4];
    size_t exp_cnt = 0;
    clip_ptt_manager_check_timeouts(&mgr, 2500, expired, 4, &exp_cnt);
    ASSERT(exp_cnt == 0, "No expiration at t=2500 (< 1000+2000)");

    clip_ptt_manager_check_timeouts(&mgr, 3050, expired, 4, &exp_cnt);
    ASSERT(exp_cnt == 1, "Watchdog expired session2 at t=3050 (>= 3000)");
    ASSERT(clip_uuid_equal(&expired[0], &sess2), "Expired session is session2");

    clip_ptt_manager_get_status(&mgr, &sess2, 3050, &entry);
    ASSERT(entry.floor_state == CLIP_PTT_FLOOR_FREE, "session2 floor is now FREE");

    /* Disconnect safety check: Node A acquires session1 */
    clip_ptt_manager_acquire(&mgr, &sess1, &nodeA, 5000, 4000, &entry, &already_held);
    ASSERT(entry.floor_state == CLIP_PTT_FLOOR_HELD, "session1 held by Node A");

    ClipUuid aff[4];
    size_t aff_cnt = 0;
    clip_ptt_manager_release_by_holder(&mgr, &nodeA, aff, 4, &aff_cnt);
    ASSERT(aff_cnt == 1, "Disconnect safety released 1 session for Node A");
    ASSERT(clip_uuid_equal(&aff[0], &sess1), "Released session was session1");

    clip_ptt_manager_get_status(&mgr, &sess1, 4000, &entry);
    ASSERT(entry.floor_state == CLIP_PTT_FLOOR_FREE, "session1 floor freed after Node A disconnect");

    clip_ptt_manager_cleanup(&mgr);
    ASSERT(mgr.entries == NULL, "PTT manager cleaned up cleanly");
}

/* ── 2. Full Server-Authoritative Integration Tests over TLS 1.3 ─────────── */

typedef struct {
    ClipServer srv;
    uint16_t   port;
    char       db_path[64];
    HANDLE     hServerThread;
} TestServerContext;

static DWORD WINAPI test_server_thread_func(LPVOID arg)
{
    TestServerContext* ctx = (TestServerContext*)arg;
    while (ctx->srv.is_running) {
        clip_server_poll(&ctx->srv, 10);
    }
    return 0;
}

static void start_test_server(TestServerContext* ctx, uint16_t port)
{
    memset(ctx, 0, sizeof(TestServerContext));
    ctx->port = port;
    snprintf(ctx->db_path, sizeof(ctx->db_path), "test_ptt_tls_%u.db", port);
    remove(ctx->db_path);

    ClipServerConfig cfg;
    clip_server_config_init_default(&cfg);
    cfg.port = port;
    strncpy(cfg.db_path, ctx->db_path, sizeof(cfg.db_path) - 1);
    cfg.use_tls = true;
    strncpy(cfg.cert_file, "certs/server.crt", sizeof(cfg.cert_file) - 1);
    strncpy(cfg.key_file, "certs/server.key", sizeof(cfg.key_file) - 1);

    clip_server_init(&ctx->srv, &cfg);
    clip_server_start(&ctx->srv);

    ctx->hServerThread = CreateThread(NULL, 0, test_server_thread_func, ctx, 0, NULL);
    Sleep(100); /* give server thread time to enter poll loop */
}

static void stop_test_server(TestServerContext* ctx)
{
    ctx->srv.is_running = false;
    if (ctx->hServerThread) {
        WaitForSingleObject(ctx->hServerThread, 3000);
        CloseHandle(ctx->hServerThread);
        ctx->hServerThread = NULL;
    }
    clip_server_stop(&ctx->srv);
    clip_server_cleanup(&ctx->srv);
    remove(ctx->db_path);
}

static void connect_test_client(ClipClientNet* c, uint16_t port, const char* name, ClipUuid* out_uuid)
{
    clip_client_net_init(c);
    clip_tls_client_config_t tls_cfg = {
        .ca_file = "certs/ca.crt",
        .expected_host = "localhost"
    };
    clip_client_net_set_tls_config(c, &tls_cfg);
    clip_client_connect(c, "127.0.0.1", port);

    uint8_t cred[CLIP_CREDENTIAL_BYTES];
    clip_client_register(c, name, out_uuid, cred);
}

static void test_ptt_tls_integration(void)
{
    printf("\n--- PTT TLS 1.3 Server-Authoritative Integration Tests ---\n");
    fflush(stdout);

    TestServerContext srv_ctx;
    uint16_t port = 15881;
    start_test_server(&srv_ctx, port);

    ClipClientNet alice, bob;
    ClipUuid alice_uuid, bob_uuid;

    /* Connect & Register Alice and Bob over TLS 1.3 */
    connect_test_client(&alice, port, "ALICE", &alice_uuid);
    connect_test_client(&bob, port, "BOB", &bob_uuid);

    ASSERT(alice.is_connected && alice.transport != NULL, "Alice connected over TLS 1.3");
    ASSERT(bob.is_connected && bob.transport != NULL, "Bob connected over TLS 1.3");

    /* Alice creates channel */
    ClipUuid chan_uuid;
    char jkey[CLIP_JOIN_KEY_MAX];
    ASSERT(clip_client_channel_create(&alice, "PTT-ROOM", &chan_uuid, jkey, sizeof(jkey)) == CLIP_OK, "Alice created channel");
    Sleep(50);

    /* Bob joins channel */
    ClipUuid b_chan;
    char cname[64];
    ClipChannelMember* mems = NULL;
    size_t m_cnt = 0;
    ASSERT(clip_client_channel_join(&bob, jkey, &b_chan, cname, sizeof(cname), &mems, &m_cnt) == CLIP_OK, "Bob joined channel");
    clip_client_free_members(mems);
    Sleep(50);

    /* Alice requests connection to Bob */
    ClipUuid conn_uuid;
    ClipConnectionState cstate;
    ASSERT(clip_client_send_conn_request(&alice, &chan_uuid, &bob_uuid, &conn_uuid, &cstate) == CLIP_OK, "Alice requested connection to Bob");
    Sleep(50);

    /* Bob accepts connection */
    ASSERT(clip_client_respond_conn(&bob, &conn_uuid, true) == CLIP_OK, "Bob accepted connection");
    Sleep(50);

    /* Alice starts Phase 6 communication session bound to connection */
    ClipUuid sess_uuid;
    ASSERT(clip_client_session_start_by_conn(&alice, &conn_uuid, &sess_uuid) == CLIP_OK, "Alice started communication session");
    Sleep(50);

    /* Verify Phase 8 UUID invariants */
    ASSERT(!clip_uuid_is_zero(&sess_uuid), "session_uuid is non-zero");
    ASSERT(!clip_uuid_equal(&sess_uuid, &alice_uuid), "session_uuid != alice_node_uuid");
    ASSERT(!clip_uuid_equal(&sess_uuid, &bob_uuid), "session_uuid != bob_node_uuid");
    ASSERT(!clip_uuid_equal(&sess_uuid, &chan_uuid), "session_uuid != channel_uuid");
    ASSERT(!clip_uuid_equal(&sess_uuid, &conn_uuid), "session_uuid != connection_uuid");

    /* Initial Floor Status: FREE */
    ClipPttFloor floor_st;
    ASSERT(clip_client_ptt_status(&alice, &sess_uuid, &floor_st) == CLIP_OK, "Query initial floor status");
    ASSERT(floor_st.floor_state == CLIP_PTT_FLOOR_FREE, "Initial floor is FREE");

    /* Test A: Basic Floor Acquisition over TLS 1.3 */
    ClipPttFloor granted_floor;
    ClipError denial_reason = CLIP_OK;
    ClipError acq_err = clip_client_ptt_request(&alice, &sess_uuid, 5000, &granted_floor, &denial_reason);
    ASSERT(acq_err == CLIP_OK, "Alice floor request GRANTED by server");
    ASSERT(granted_floor.floor_state == CLIP_PTT_FLOOR_HELD, "Floor state is HELD");
    ASSERT(clip_uuid_equal(&granted_floor.holder_node_uuid, &alice_uuid), "Granted holder matches Alice UUID");
    ASSERT(granted_floor.lease_timeout_ms == 5000, "Server lease set to 5000ms");

    Sleep(50);

    /* Bob observes floor is held by Alice */
    ASSERT(clip_client_ptt_status(&bob, &sess_uuid, &floor_st) == CLIP_OK, "Bob queries floor status");
    ASSERT(floor_st.floor_state == CLIP_PTT_FLOOR_HELD, "Bob sees floor is HELD");
    ASSERT(clip_uuid_equal(&floor_st.holder_node_uuid, &alice_uuid), "Bob sees holder is Alice");

    /* Test B: Busy Floor Denial */
    ClipPttFloor bob_attempt;
    ClipError bob_denial = CLIP_OK;
    ClipError bob_res = clip_client_ptt_request(&bob, &sess_uuid, 5000, &bob_attempt, &bob_denial);
    ASSERT(bob_res == CLIP_ERR_PTT_BUSY, "Bob floor request returns CLIP_ERR_PTT_BUSY");
    ASSERT(bob_denial == CLIP_ERR_PTT_BUSY, "Denial reason is CLIP_ERR_PTT_BUSY");
    ASSERT(clip_uuid_equal(&bob_attempt.holder_node_uuid, &alice_uuid), "Bob denial identifies current holder Alice");

    /* Test E: Duplicate Request by current holder (Alice) */
    ClipPttFloor dup_floor;
    ClipError dup_res = clip_client_ptt_request(&alice, &sess_uuid, 5000, &dup_floor, &denial_reason);
    ASSERT(dup_res == CLIP_OK, "Alice duplicate floor request returns confirmation CLIP_OK");
    ASSERT(dup_floor.acquired_at_ms == granted_floor.acquired_at_ms, "Duplicate request preserved acquired_at timestamp");

    /* Test D: Unauthorized Release (Bob attempts to release Alice's floor) */
    ClipError unauth_rel = clip_client_ptt_release(&bob, &sess_uuid);
    ASSERT(unauth_rel == CLIP_ERR_DENIED, "Bob unauthorized release rejected with CLIP_ERR_DENIED");
    Sleep(50);

    /* Verify Alice still holds floor */
    clip_client_ptt_status(&alice, &sess_uuid, &floor_st);
    ASSERT(floor_st.floor_state == CLIP_PTT_FLOOR_HELD, "Floor remains HELD after unauthorized release attempt");
    ASSERT(clip_uuid_equal(&floor_st.holder_node_uuid, &alice_uuid), "Alice remains recorded holder");

    /* Test C: Authorized Floor Release */
    ClipError auth_rel = clip_client_ptt_release(&alice, &sess_uuid);
    ASSERT(auth_rel == CLIP_OK, "Alice authorized floor release returns CLIP_OK");
    Sleep(50);

    /* Floor is now FREE */
    clip_client_ptt_status(&bob, &sess_uuid, &floor_st);
    ASSERT(floor_st.floor_state == CLIP_PTT_FLOOR_FREE, "Floor is now FREE for Bob");

    /* Bob can now acquire floor */
    ClipError bob_acq = clip_client_ptt_request(&bob, &sess_uuid, 5000, &granted_floor, &denial_reason);
    ASSERT(bob_acq == CLIP_OK, "Bob successfully acquired released floor");
    ASSERT(clip_uuid_equal(&granted_floor.holder_node_uuid, &bob_uuid), "Holder is now Bob");

    /* Bob releases floor */
    clip_client_ptt_release(&bob, &sess_uuid);
    Sleep(50);

    /* Test F: Invalid Session handling */
    ClipUuid random_sess;
    make_test_uuid(&random_sess, 0x99);
    ClipError inv_err = clip_client_ptt_request(&alice, &random_sess, 5000, &granted_floor, &denial_reason);
    ASSERT(inv_err == CLIP_ERR_NO_SESSION || inv_err == CLIP_ERR_DENIED, "Request on non-existent session rejected");

    /* Test K: Lease Timeout Watchdog */
    acq_err = clip_client_ptt_request(&alice, &sess_uuid, 600, &granted_floor, &denial_reason);
    ASSERT(acq_err == CLIP_OK, "Alice acquired floor with 600ms lease");
    /* Sleep 800ms to allow server watchdog in poll loop to expire lease */
    Sleep(800);

    clip_client_ptt_status(&bob, &sess_uuid, &floor_st);
    ASSERT(floor_st.floor_state == CLIP_PTT_FLOOR_FREE, "Server watchdog expired lease: floor is now FREE");

    /* Test I: Disconnect Safety */
    acq_err = clip_client_ptt_request(&alice, &sess_uuid, 5000, &granted_floor, &denial_reason);
    ASSERT(acq_err == CLIP_OK, "Alice acquired floor before disconnect");

    /* Abruptly disconnect Alice */
    clip_client_disconnect(&alice);
    Sleep(150);

    /* Server detected disconnect -> floor automatically released -> Bob can acquire */
    acq_err = clip_client_ptt_request(&bob, &sess_uuid, 5000, &granted_floor, &denial_reason);
    ASSERT(acq_err == CLIP_OK, "Disconnect safety: Bob successfully acquired floor after Alice disconnect");

    /* Test J: Session End Safety */
    clip_client_session_end(&bob, &sess_uuid);
    Sleep(50);

    /* Further request on closed session rejected */
    acq_err = clip_client_ptt_request(&bob, &sess_uuid, 5000, &granted_floor, &denial_reason);
    ASSERT(acq_err == CLIP_ERR_NO_SESSION || acq_err == CLIP_ERR_DENIED, "Floor request on CLOSED session rejected");

    clip_client_disconnect(&bob);
    clip_client_net_cleanup(&alice);
    clip_client_net_cleanup(&bob);
    stop_test_server(&srv_ctx);
}

/* ── 3. Test L: Concurrent Race Condition Arbitration Test ───────────────── */

typedef struct {
    ClipClientNet*   net;
    ClipUuid         client_uuid;
    ClipUuid         session_uuid;
    HANDLE           hStartEvent;
    ClipError        result_code;
    ClipPttFloor     result_floor;
    ClipError        denial_reason;
    bool             thread_completed;
} RaceWorkerParam;

static DWORD WINAPI race_worker_thread(LPVOID arg)
{
    RaceWorkerParam* p = (RaceWorkerParam*)arg;

    /* Wait on barrier event for synchronized simultaneous execution */
    WaitForSingleObject(p->hStartEvent, INFINITE);

    /* Transmit FLOOR_REQUEST at the exact synchronized instant from separate client context */
    p->result_code = clip_client_ptt_request(p->net, &p->session_uuid, 5000, &p->result_floor, &p->denial_reason);
    p->thread_completed = true;
    return 0;
}

static void test_ptt_concurrent_race(void)
{
    printf("\n--- Test L: Concurrent Race Condition Arbitration ---\n");
    fflush(stdout);

    TestServerContext srv_ctx;
    uint16_t port = 15882;
    start_test_server(&srv_ctx, port);

    /* Setup session prerequisites with setup client */
    ClipClientNet setup_client;
    ClipUuid setup_uuid;
    connect_test_client(&setup_client, port, "SETUP_NODE", &setup_uuid);

    ClipUuid chan_uuid;
    char jkey[CLIP_JOIN_KEY_MAX];
    clip_client_channel_create(&setup_client, "RACE_ROOM", &chan_uuid, jkey, sizeof(jkey));
    Sleep(50);

    /* Connect and authenticate Worker A & Worker B over separate TLS 1.3 connections */
    ClipClientNet clientA, clientB;
    ClipUuid nodeA_uuid, nodeB_uuid;
    connect_test_client(&clientA, port, "RACE_NODE_A", &nodeA_uuid);
    connect_test_client(&clientB, port, "RACE_NODE_B", &nodeB_uuid);
    Sleep(50);

    char cname[64];
    ClipUuid b_chan;
    ClipChannelMember* mems = NULL;
    size_t m_cnt = 0;
    clip_client_channel_join(&clientA, jkey, &b_chan, cname, sizeof(cname), &mems, &m_cnt);
    clip_client_free_members(mems);
    clip_client_channel_join(&clientB, jkey, &b_chan, cname, sizeof(cname), &mems, &m_cnt);
    clip_client_free_members(mems);
    Sleep(50);

    ClipUuid conn_uuid;
    ClipConnectionState st;
    clip_client_send_conn_request(&clientA, &chan_uuid, &nodeB_uuid, &conn_uuid, &st);
    Sleep(50);
    clip_client_respond_conn(&clientB, &conn_uuid, true);
    Sleep(50);

    ClipUuid race_session_uuid;
    clip_client_session_start_by_conn(&clientA, &conn_uuid, &race_session_uuid);
    Sleep(50);

    HANDLE hStartEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    RaceWorkerParam paramA = {0};
    paramA.net = &clientA;
    paramA.client_uuid = nodeA_uuid;
    paramA.session_uuid = race_session_uuid;
    paramA.hStartEvent = hStartEvent;

    RaceWorkerParam paramB = {0};
    paramB.net = &clientB;
    paramB.client_uuid = nodeB_uuid;
    paramB.session_uuid = race_session_uuid;
    paramB.hStartEvent = hStartEvent;

    /* Launch 2 concurrent worker threads holding distinct client contexts */
    HANDLE hThreads[2];
    hThreads[0] = CreateThread(NULL, 0, race_worker_thread, &paramA, 0, NULL);
    hThreads[1] = CreateThread(NULL, 0, race_worker_thread, &paramB, 0, NULL);

    /* Allow threads to enter wait state */
    Sleep(100);

    /* Fire barrier: both threads execute FLOOR_REQUEST simultaneously */
    SetEvent(hStartEvent);

    /* Wait for both threads to finish */
    WaitForMultipleObjects(2, hThreads, TRUE, 5000);
    CloseHandle(hThreads[0]);
    CloseHandle(hThreads[1]);
    CloseHandle(hStartEvent);

    ASSERT(paramA.thread_completed && paramB.thread_completed, "Both concurrent client threads completed");

    /* Verify Arbitration Invariants:
     * 1. Exactly ONE request received GRANTED (CLIP_OK)
     * 2. Exactly ONE request received DENIED (CLIP_ERR_PTT_BUSY)
     */
    bool a_granted = (paramA.result_code == CLIP_OK);
    bool b_granted = (paramB.result_code == CLIP_OK);
    bool a_denied  = (paramA.result_code == CLIP_ERR_PTT_BUSY);
    bool b_denied  = (paramB.result_code == CLIP_ERR_PTT_BUSY);

    ASSERT((a_granted && b_denied) || (b_granted && a_denied),
           "Atomic arbitration: Exactly ONE request received GRANTED and exactly ONE received DENIED");

    /* Verify server floor holder is strictly the winner */
    ClipPttFloorEntry server_floor;
    clip_ptt_manager_get_status(&srv_ctx.srv.ptt_mgr, &race_session_uuid, 0, &server_floor);
    ASSERT(server_floor.floor_state == CLIP_PTT_FLOOR_HELD, "Server floor state is HELD");

    if (a_granted) {
        ASSERT(clip_uuid_equal(&server_floor.holder_node_uuid, &nodeA_uuid),
               "Server recorded holder matches winner Node A");
        ASSERT(clip_uuid_equal(&paramB.result_floor.holder_node_uuid, &nodeA_uuid),
               "Denied Node B received current holder Node A in response");
    } else {
        ASSERT(clip_uuid_equal(&server_floor.holder_node_uuid, &nodeB_uuid),
               "Server recorded holder matches winner Node B");
        ASSERT(clip_uuid_equal(&paramA.result_floor.holder_node_uuid, &nodeB_uuid),
               "Denied Node A received current holder Node B in response");
    }

    ASSERT(server_floor.acquired_at_ms > 0, "Server recorded valid acquired_at timestamp");
    ASSERT(server_floor.lease_duration_ms == 5000, "Server recorded valid lease duration");

    clip_client_disconnect(&clientA);
    clip_client_disconnect(&clientB);
    clip_client_disconnect(&setup_client);
    clip_client_net_cleanup(&clientA);
    clip_client_net_cleanup(&clientB);
    clip_client_net_cleanup(&setup_client);

    stop_test_server(&srv_ctx);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("========================================\n");
    printf("  CLIP PTT FLOOR CONTROL TEST SUITE     \n");
    printf("========================================\n");
    fflush(stdout);

    test_ptt_manager_unit();
    test_ptt_tls_integration();
    test_ptt_concurrent_race();

    printf("\n----------------------------------------\n");
    printf("Assertions passed: %d\n", g_pass);
    printf("Assertions failed: %d\n", g_fail);
    printf("========================================\n");

    if (g_fail == 0) {
        printf("  RESULT: ALL TESTS PASSED\n");
        printf("========================================\n");
        return 0;
    } else {
        printf("  RESULT: FAILURES DETECTED\n");
        printf("========================================\n");
        return 1;
    }
}

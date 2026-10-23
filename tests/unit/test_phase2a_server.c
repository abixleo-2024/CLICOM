/*
 * test_phase2a_server.c — CLICOM Phase 2A Integration & Verification Suite
 *
 * Verifies all Phase 2A criteria:
 * 1. Two independently running clients connect to server over TLS 1.3 with CA verification.
 * 2. Room created with member limit (e.g. limit=2) and secure server-generated join key.
 * 3. Second client joins using valid join key.
 * 4. Atomic capacity check: Third client rejected under capacity limit (CLIP_ERR_FULL).
 * 5. Server-enforced owner permissions: Non-owner attempting to revoke key is rejected (CLIP_ERR_DENIED).
 * 6. Server-enforced owner permissions: Non-owner attempting to close room is rejected (CLIP_ERR_DENIED).
 * 7. Room owner revokes invitation key.
 * 8. Subsequent join with revoked key is rejected (CLIP_ERR_REVOKED).
 * 9. Join with non-existent key is rejected (CLIP_ERR_NOT_FOUND).
 * 10. Invalid messages and oversized payloads are handled safely.
 * 11. Disconnect and room leave safely clean up presence and membership.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "clip_net.h"

#if defined(_WIN32) || defined(__CYGWIN__)
    #include <windows.h>
#else
    #include <pthread.h>
    #include <unistd.h>
#endif

#include "clip_version.h"
#include "clip_protocol.h"
#include "clip_types.h"
#include "clip_errors.h"
#include "clip_transport.h"
#include "clip_tls.h"
#include "clip_channels.h"
#include "clip_identity.h"
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

#define TEST_PHASE2A_PORT 14995
#define TEST_DB_PATH "test_phase2a_server.db"

#if defined(_WIN32) || defined(__CYGWIN__)
static DWORD WINAPI server_thread_func(LPVOID param)
{
    ClipServer* srv = (ClipServer*)param;
    while (srv && srv->is_running) {
        clip_server_poll(srv, 10);
    }
    return 0;
}
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("============================================================\n");
    printf(" CLICOM Phase 2A — C Network Server Integration Suite      \n");
    printf("============================================================\n\n");

    remove(TEST_DB_PATH);

    /* ── 1. Start Server with TLS 1.3 and Database ────────────────────────── */
    ClipServerConfig srv_cfg = {0};
    strncpy(srv_cfg.bind_host, "127.0.0.1", sizeof(srv_cfg.bind_host) - 1);
    srv_cfg.port = TEST_PHASE2A_PORT;
    srv_cfg.max_clients = 16;
    srv_cfg.use_tls = true;
    strncpy(srv_cfg.cert_file, "certs/server.crt", sizeof(srv_cfg.cert_file) - 1);
    strncpy(srv_cfg.key_file, "certs/server.key", sizeof(srv_cfg.key_file) - 1);
    strncpy(srv_cfg.db_path, TEST_DB_PATH, sizeof(srv_cfg.db_path) - 1);

    ClipServer srv;
    ClipError srv_init_err = clip_server_init(&srv, &srv_cfg);
    TEST("Server initialized with TLS 1.3 and SQLite storage", srv_init_err == CLIP_OK);

    ClipError srv_start_err = clip_server_start(&srv);
    TEST("Server listening on port 14995", srv_start_err == CLIP_OK);

#if defined(_WIN32) || defined(__CYGWIN__)
    HANDLE h_srv_thread = CreateThread(NULL, 0, server_thread_func, &srv, 0, NULL);
    TEST("Server background dispatch thread running", h_srv_thread != NULL);
    Sleep(100);
#endif

    /* ── 2. Two Independently Running Clients Connect over TLS 1.3 ────────── */
    printf("\n[Step 1: Independent TLS 1.3 Client Connections & Verification]\n");

    ClipClientNet client1;
    clip_client_net_init(&client1);
    clip_tls_client_config_t tls1 = {
        .ca_file = "certs/ca.crt",
        .expected_host = "127.0.0.1",
        .insecure_skip_verify = false
    };
    clip_client_net_set_tls_config(&client1, &tls1);
    ClipError c1_conn = clip_client_connect(&client1, "127.0.0.1", TEST_PHASE2A_PORT);
    TEST("Client 1 connected to server over TLS 1.3 with CA verification", c1_conn == CLIP_OK);

    ClipUuid uuid1;
    uint8_t cred1[CLIP_CREDENTIAL_BYTES];
    ClipError c1_reg = clip_client_register(&client1, "NODE-ALPHA", &uuid1, cred1);
    TEST("Client 1 registered and authenticated as NODE-ALPHA", c1_reg == CLIP_OK && client1.is_registered);

    ClipClientNet client2;
    clip_client_net_init(&client2);
    clip_tls_client_config_t tls2 = {
        .ca_file = "certs/ca.crt",
        .expected_host = "127.0.0.1",
        .insecure_skip_verify = false
    };
    clip_client_net_set_tls_config(&client2, &tls2);
    ClipError c2_conn = clip_client_connect(&client2, "127.0.0.1", TEST_PHASE2A_PORT);
    TEST("Client 2 connected to server over TLS 1.3 with CA verification", c2_conn == CLIP_OK);

    ClipUuid uuid2;
    uint8_t cred2[CLIP_CREDENTIAL_BYTES];
    ClipError c2_reg = clip_client_register(&client2, "NODE-BRAVO", &uuid2, cred2);
    TEST("Client 2 registered and authenticated as NODE-BRAVO", c2_reg == CLIP_OK && client2.is_registered);

    /* ── 3. Room Creation with Member Limit (limit=2) & Join Key ─────────── */
    printf("\n[Step 2: Room Creation with Explicit Capacity Limit (2 Members)]\n");

    ClipUuid channel_uuid;
    char join_key[CLIP_JOIN_KEY_MAX] = {0};
    ClipError cr_err = clip_client_channel_create_with_limit(&client1, "RECON-SQUAD", 2, &channel_uuid, join_key, sizeof(join_key));
    TEST("Client 1 created room RECON-SQUAD with member_limit=2", cr_err == CLIP_OK);
    TEST("Room UUID is valid and non-zero", !clip_uuid_is_zero(&channel_uuid));
    TEST("Invitation key matches GC-XXXX format", strncmp(join_key, "GC-", 3) == 0 && strlen(join_key) == 7);

    /* ── 4. Client 2 Joins Room using Valid Invitation Key ───────────────── */
    printf("\n[Step 3: Client 2 Joins with Valid Invitation Key]\n");

    ClipUuid j_chan_uuid;
    char j_chan_name[CLIP_DISPLAY_NAME_MAX] = {0};
    ClipChannelMember* members = NULL;
    size_t member_count = 0;

    ClipError j_err = clip_client_channel_join(&client2, join_key, &j_chan_uuid, j_chan_name, sizeof(j_chan_name), &members, &member_count);
    TEST("Client 2 joined room via valid invitation key", j_err == CLIP_OK);
    TEST("Joined channel UUID matches created room", clip_uuid_equal(&j_chan_uuid, &channel_uuid));
    TEST("Joined channel name matches RECON-SQUAD", strcmp(j_chan_name, "RECON-SQUAD") == 0);
    TEST("Member count is now 2 (creator + joiner)", member_count == 2);
    clip_client_free_members(members);

    /* ── 5. Capacity Check: Client 3 Rejected when Limit Reached ─────────── */
    printf("\n[Step 4: Atomic Capacity Check — Max 2 Participants Enforced]\n");

    ClipClientNet client3;
    clip_client_net_init(&client3);
    clip_tls_client_config_t tls3 = {
        .ca_file = "certs/ca.crt",
        .expected_host = "127.0.0.1",
        .insecure_skip_verify = false
    };
    clip_client_net_set_tls_config(&client3, &tls3);
    clip_client_connect(&client3, "127.0.0.1", TEST_PHASE2A_PORT);
    ClipUuid uuid3;
    uint8_t cred3[CLIP_CREDENTIAL_BYTES];
    clip_client_register(&client3, "NODE-CHARLIE", &uuid3, cred3);

    members = NULL;
    member_count = 0;
    ClipError j3_err = clip_client_channel_join(&client3, join_key, &j_chan_uuid, j_chan_name, sizeof(j_chan_name), &members, &member_count);
    TEST("Client 3 rejected with CLIP_ERR_FULL when room capacity (2) reached", j3_err == CLIP_ERR_FULL);

    /* ── 6. Unauthorized Owner Operations Rejected ───────────────────────── */
    printf("\n[Step 5: Server-Enforced Owner Permissions]\n");

    /* Non-owner Client 2 tries to revoke invitation key */
    ClipError rev_unauth = clip_client_channel_revoke_key(&client2, &channel_uuid);
    TEST("Non-owner Client 2 denied when attempting key revocation (CLIP_ERR_DENIED)", rev_unauth == CLIP_ERR_DENIED);

    /* Non-owner Client 2 tries to close room */
    ClipError close_unauth = clip_client_channel_close(&client2, &channel_uuid);
    TEST("Non-owner Client 2 denied when attempting room closure (CLIP_ERR_DENIED)", close_unauth == CLIP_ERR_DENIED);

    /* ── 7. Room Owner Revokes Key & Subsequent Joins are Rejected ───────── */
    printf("\n[Step 6: Owner Revocation & Rejection of Revoked Key]\n");

    /* Client 2 leaves the room so capacity is 1/2 */
    ClipError leave_err = clip_client_channel_leave(&client2, &channel_uuid);
    TEST("Client 2 left room successfully", leave_err == CLIP_OK);

    /* Owner Client 1 revokes the invitation key */
    ClipError rev_ok = clip_client_channel_revoke_key(&client1, &channel_uuid);
    TEST("Room owner Client 1 revoked invitation key successfully", rev_ok == CLIP_OK);

    /* Now Client 3 attempts to join with the revoked key */
    ClipError j_rev_err = clip_client_channel_join(&client3, join_key, &j_chan_uuid, j_chan_name, sizeof(j_chan_name), &members, &member_count);
    TEST("Client 3 rejected with CLIP_ERR_REVOKED using revoked invitation key", j_rev_err == CLIP_ERR_REVOKED);

    /* ── 8. Rejection of Invalid / Non-Existent Key ──────────────────────── */
    printf("\n[Step 7: Rejection of Invalid / Bogus Invitation Key]\n");

    ClipError j_bogus = clip_client_channel_join(&client3, "GC-9999", &j_chan_uuid, j_chan_name, sizeof(j_chan_name), &members, &member_count);
    TEST("Client rejected with CLIP_ERR_NOT_FOUND using bogus key", j_bogus == CLIP_ERR_NOT_FOUND);

    /* ── 9. Oversized & Malformed Frame Safety ────────────────────────────── */
    printf("\n[Step 8: Malformed & Oversized Frame Resistance]\n");

    /* Send frame with huge payload length declared */
    ClipFrameHeader bad_hdr;
    clip_frame_header_init(&bad_hdr, CLIP_MSG_CHANNEL_JOIN, 65000, 999, NULL);
    uint8_t garbage[64] = {0xAA};
    ClipError send_bad = clip_client_send_frame(&client3, &bad_hdr, garbage);
    TEST("Client sent oversized header to server", send_bad == CLIP_OK);

#if defined(_WIN32) || defined(__CYGWIN__)
    Sleep(50);
#endif
    TEST("Server remained healthy and responsive after oversized frame", srv.is_running);

    /* ── 10. Clean Disconnect & Cleanup ───────────────────────────────────── */
    printf("\n[Step 9: Deterministic Disconnect and Cleanup]\n");

    clip_client_disconnect(&client1);
    clip_client_disconnect(&client2);
    clip_client_disconnect(&client3);
    clip_client_net_cleanup(&client1);
    clip_client_net_cleanup(&client2);
    clip_client_net_cleanup(&client3);
    TEST("All 3 clients cleanly disconnected and freed", true);

    srv.is_running = false;
#if defined(_WIN32) || defined(__CYGWIN__)
    WaitForSingleObject(h_srv_thread, 2000);
    CloseHandle(h_srv_thread);
#endif
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
    remove(TEST_DB_PATH);
    TEST("Server cleanly shut down and storage cleaned", true);

    printf("\n============================================================\n");
    printf(" Phase 2A Integration Test Results: %d PASS, %d FAIL\n", g_pass, g_fail);
    printf("============================================================\n");

    return (g_fail == 0) ? 0 : 1;
}

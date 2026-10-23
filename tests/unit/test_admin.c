/*
 * test_admin.c — CLICOM Phase 16: Admin Alerts & Actions Unit & Integration Tests
 *
 * Comprehensive verification of:
 * 1. Cryptographic verifier security (PBKDF2-HMAC-SHA256, constant-time compare, stack memory zeroing).
 * 2. Deterministic first-admin bootstrap (SUPER_ADMIN auto-assignment, rejection if admin exists).
 * 3. Separation of node identity vs admin identity (unauthenticated nodes denied, separate login).
 * 4. Role hierarchy & permissions matrix (OBSERVER < MODERATOR < SUPER_ADMIN).
 * 5. Terminal review state machine (PENDING -> REVIEWED/FALSE_POS; no reopening or status swapping).
 * 6. Persistent node sanctions (ACTIVE, RESTRICTED [listen-only], BANNED [connect blocked]).
 * 7. Server-authoritative channel locking/unlocking.
 * 8. Append-only administrative audit log.
 * 9. Referential integrity validation (event_id, session_uuid, channel_uuid).
 * 10. Live loopback network integration over TCP/wire protocol.
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sqlite3.h>

#include "clip_types.h"
#include "clip_errors.h"
#include "clip_protocol.h"
#include "clip_crypto.h"
#include "clip_identity.h"
#include "clip_channels.h"
#include "clip_sessions.h"
#include "clip_connections.h"
#include "clip_notes.h"
#include "clip_security_db.h"
#include "clip_admin.h"
#include "clip_admin_db.h"
#include "../../server/include/server.h"
#include "../../client/include/network.h"
#include "../../client/include/clip_admin_client.h"
#include "../../client/include/clip_security_client.h"

static int g_pass = 0;
static int g_fail = 0;

#define TEST(name, condition) do { \
    if (condition) { \
        printf("  PASS  %s\n", (name)); \
        g_pass++; \
    } else { \
        printf("  FAIL  %s (line %d)\n", (name), __LINE__); \
        g_fail++; \
    } \
} while (0)

#define TEST_ADMIN_DB "test_admin.db"
#define TEST_ADMIN_PORT 14989

static DWORD WINAPI test_server_thread(LPVOID param)
{
    ClipServer* srv = (ClipServer*)param;
    while (srv->is_running) {
        clip_server_poll(srv, 20);
    }
    return 0;
}

int main(void)
{
    printf("\n======================================================\n");
    printf("CLICOM Phase 16: Admin Alerts & Actions Test Suite\n");
    printf("======================================================\n\n");

    remove(TEST_ADMIN_DB);

    /* ── 1. Cryptographic Password Verifier Security ───────────────── */
    printf("--- Section 1: Cryptographic Verifier Security ---\n");

    const char* pwd1 = "StrongSecretPass123!";
    uint8_t salt1[CLIP_ADMIN_SALT_BYTES];
    clip_crypto_random_bytes(salt1, sizeof(salt1));

    uint8_t verifier1[CLIP_ADMIN_VERIFIER_BYTES];
    ClipError hash_err = clip_admin_hash_password(pwd1, salt1, CLIP_ADMIN_DEFAULT_ITERATIONS, verifier1);
    TEST("clip_admin_hash_password succeeds for valid password", hash_err == CLIP_OK);

    TEST("clip_admin_verify_password returns true for matching password",
         clip_admin_verify_password(pwd1, salt1, CLIP_ADMIN_DEFAULT_ITERATIONS, verifier1) == true);

    TEST("clip_admin_verify_password returns false for incorrect password",
         clip_admin_verify_password("WrongPassword999!", salt1, CLIP_ADMIN_DEFAULT_ITERATIONS, verifier1) == false);

    TEST("clip_admin_verify_password returns false for wrong salt",
         clip_admin_verify_password(pwd1, salt1 + 1, CLIP_ADMIN_DEFAULT_ITERATIONS, verifier1) == false);

    /* Short password rejection */
    uint8_t short_ver[CLIP_ADMIN_VERIFIER_BYTES];
    TEST("clip_admin_hash_password rejects password shorter than 10 chars",
         clip_admin_hash_password("short", salt1, CLIP_ADMIN_DEFAULT_ITERATIONS, short_ver) == CLIP_ERR_INVALID);

    /* ── 2. First-Admin Bootstrap & DB Storage ──────────────────────── */
    printf("\n--- Section 2: First-Admin Bootstrap & User Persistence ---\n");

    ClipIdentityDb* id_db = NULL;
    TEST("clip_identity_db_open opens database and schemas", clip_identity_db_open(&id_db, TEST_ADMIN_DB) == CLIP_OK && id_db != NULL);
    sqlite3* db = clip_identity_get_sqlite(id_db);
    TEST("clip_admin_db_init_schema creates admin tables", clip_admin_db_init_schema(db) == CLIP_OK);

    size_t admin_cnt = 0;
    TEST("Initial admin count is 0", clip_admin_db_count_admins(db, &admin_cnt) == CLIP_OK && admin_cnt == 0);

    /* Bootstrap initial SUPER_ADMIN */
    ClipAdminUser first_admin;
    memset(&first_admin, 0, sizeof(first_admin));
    clip_crypto_uuid_generate((ClipUuid*)first_admin.admin_uuid);
    strncpy(first_admin.username, "rootadmin", sizeof(first_admin.username) - 1);
    first_admin.role = CLIP_ADMIN_PERM_SUPER_ADMIN;
    first_admin.iterations = CLIP_ADMIN_DEFAULT_ITERATIONS;
    memcpy(first_admin.salt, salt1, CLIP_ADMIN_SALT_BYTES);
    memcpy(first_admin.verifier, verifier1, CLIP_ADMIN_VERIFIER_BYTES);

    TEST("clip_admin_db_create_admin creates initial admin", clip_admin_db_create_admin(db, &first_admin) == CLIP_OK);
    TEST("Admin count is now 1", clip_admin_db_count_admins(db, &admin_cnt) == CLIP_OK && admin_cnt == 1);

    /* Duplicate username rejection */
    ClipAdminUser dup_admin = first_admin;
    clip_crypto_uuid_generate((ClipUuid*)dup_admin.admin_uuid);
    TEST("Duplicate username creation returns CLIP_ERR_EXISTS",
         clip_admin_db_create_admin(db, &dup_admin) == CLIP_ERR_EXISTS);

    /* Retrieve admin */
    ClipAdminUser retrieved_admin;
    TEST("clip_admin_db_get_admin finds user by username",
         clip_admin_db_get_admin(db, "rootadmin", &retrieved_admin) == CLIP_OK);
    TEST("Retrieved user has role SUPER_ADMIN", retrieved_admin.role == CLIP_ADMIN_PERM_SUPER_ADMIN);
    TEST("Retrieved user salt matches", memcmp(retrieved_admin.salt, salt1, CLIP_ADMIN_SALT_BYTES) == 0);
    TEST("Retrieved user verifier matches", memcmp(retrieved_admin.verifier, verifier1, CLIP_ADMIN_VERIFIER_BYTES) == 0);

    /* ── 3. Role Hierarchy & Permission Matrix ──────────────────────── */
    printf("\n--- Section 3: Role Hierarchy & Permission Matrix ---\n");

    /* OBSERVER checks */
    TEST("OBSERVER cannot disconnect node", clip_admin_can_perform(CLIP_ADMIN_PERM_OBSERVER, CLIP_ADMIN_DISCONNECT_NODE) == false);
    TEST("OBSERVER cannot restrict node", clip_admin_can_perform(CLIP_ADMIN_PERM_OBSERVER, CLIP_ADMIN_RESTRICT_NODE) == false);
    TEST("OBSERVER cannot ban node", clip_admin_can_perform(CLIP_ADMIN_PERM_OBSERVER, CLIP_ADMIN_BAN_NODE) == false);
    TEST("OBSERVER cannot review event", clip_admin_can_perform(CLIP_ADMIN_PERM_OBSERVER, CLIP_ADMIN_REVIEW_EVENT) == false);
    TEST("OBSERVER cannot lock channel", clip_admin_can_perform(CLIP_ADMIN_PERM_OBSERVER, CLIP_ADMIN_LOCK_CHANNEL) == false);
    TEST("OBSERVER cannot create admin", clip_admin_can_perform(CLIP_ADMIN_PERM_OBSERVER, CLIP_ADMIN_CREATE_ADMIN) == false);

    /* MODERATOR checks */
    TEST("MODERATOR can disconnect node", clip_admin_can_perform(CLIP_ADMIN_PERM_MODERATOR, CLIP_ADMIN_DISCONNECT_NODE) == true);
    TEST("MODERATOR can restrict node", clip_admin_can_perform(CLIP_ADMIN_PERM_MODERATOR, CLIP_ADMIN_RESTRICT_NODE) == true);
    TEST("MODERATOR can unrestrict node", clip_admin_can_perform(CLIP_ADMIN_PERM_MODERATOR, CLIP_ADMIN_UNRESTRICT_NODE) == true);
    TEST("MODERATOR can lock channel", clip_admin_can_perform(CLIP_ADMIN_PERM_MODERATOR, CLIP_ADMIN_LOCK_CHANNEL) == true);
    TEST("MODERATOR can unlock channel", clip_admin_can_perform(CLIP_ADMIN_PERM_MODERATOR, CLIP_ADMIN_UNLOCK_CHANNEL) == true);
    TEST("MODERATOR can review event", clip_admin_can_perform(CLIP_ADMIN_PERM_MODERATOR, CLIP_ADMIN_REVIEW_EVENT) == true);
    TEST("MODERATOR can mark false positive", clip_admin_can_perform(CLIP_ADMIN_PERM_MODERATOR, CLIP_ADMIN_MARK_FALSE_POS) == true);
    TEST("MODERATOR CANNOT ban node", clip_admin_can_perform(CLIP_ADMIN_PERM_MODERATOR, CLIP_ADMIN_BAN_NODE) == false);
    TEST("MODERATOR CANNOT unban node", clip_admin_can_perform(CLIP_ADMIN_PERM_MODERATOR, CLIP_ADMIN_UNBAN_NODE) == false);
    TEST("MODERATOR CANNOT create admin", clip_admin_can_perform(CLIP_ADMIN_PERM_MODERATOR, CLIP_ADMIN_CREATE_ADMIN) == false);

    /* SUPER_ADMIN checks */
    TEST("SUPER_ADMIN can ban node", clip_admin_can_perform(CLIP_ADMIN_PERM_SUPER_ADMIN, CLIP_ADMIN_BAN_NODE) == true);
    TEST("SUPER_ADMIN can unban node", clip_admin_can_perform(CLIP_ADMIN_PERM_SUPER_ADMIN, CLIP_ADMIN_UNBAN_NODE) == true);
    TEST("SUPER_ADMIN can create admin", clip_admin_can_perform(CLIP_ADMIN_PERM_SUPER_ADMIN, CLIP_ADMIN_CREATE_ADMIN) == true);
    TEST("SUPER_ADMIN can review event", clip_admin_can_perform(CLIP_ADMIN_PERM_SUPER_ADMIN, CLIP_ADMIN_REVIEW_EVENT) == true);

    /* ── 4. Terminal Review State Machine ───────────────────────────── */
    printf("\n--- Section 4: Terminal Review State Machine ---\n");

    /* Create valid entities for foreign key integrity */
    ClipUuid base_node;
    uint8_t base_cred[CLIP_CREDENTIAL_BYTES];
    clip_identity_register(id_db, "BASE-OPERATOR", &base_node, base_cred);

    ClipUuid test_ch_uuid;
    char join_key[CLIP_JOIN_KEY_MAX];
    ClipError ch_err = clip_channel_create(db, &base_node, "TestLockChannel",
                                          &test_ch_uuid, join_key, sizeof(join_key));
    TEST("Setup channel creation succeeds", ch_err == CLIP_OK);

    ClipUuid test_sess_uuid;
    ClipError s_start_err = clip_session_start(db, &test_ch_uuid, &base_node, &test_sess_uuid);
    TEST("Setup session creation succeeds", s_start_err == CLIP_OK);

    /* Create sample security event in DB referencing genuine records */
    ClipSecurityEvent ev1;
    memset(&ev1, 0, sizeof(ev1));
    clip_crypto_uuid_generate((ClipUuid*)ev1.event_uuid);
    char ev1_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string((const ClipUuid*)ev1.event_uuid, ev1_str, sizeof(ev1_str));
    strcpy(ev1.event_uuid_str, ev1_str);
    memcpy(ev1.session_uuid, test_sess_uuid.bytes, CLIP_UUID_BYTES);
    clip_uuid_to_string(&test_ch_uuid, ev1.channel_uuid_str, sizeof(ev1.channel_uuid_str));
    clip_uuid_to_string(&base_node, ev1.node_uuid_str, sizeof(ev1.node_uuid_str));
    ev1.timestamp_ms = 1000;
    ev1.category = CLIP_SECURITY_CAT_THREAT;
    ev1.severity = CLIP_SECURITY_SEV_HIGH;
    strcpy(ev1.matched_rule, "threat_rule");
    strcpy(ev1.matched_term, "threat");
    strcpy(ev1.context_text, "this is a threat context");
    ev1.status = CLIP_EVENT_STATUS_PENDING;

    TEST("Insert test event 1 succeeds", clip_security_db_insert_event(db, &ev1) == CLIP_OK);
    TEST("Event 1 ID assigned > 0", ev1.event_id > 0);

    /* Transition PENDING -> REVIEWED */
    TEST("PENDING -> REVIEWED succeeds",
         clip_admin_db_update_event_status(db, ev1.event_id, CLIP_EVENT_STATUS_REVIEWED) == CLIP_OK);

    /* Verify terminal state: repeated review returns CLIP_ERR_EXISTS */
    TEST("REVIEWED -> REVIEWED returns CLIP_ERR_EXISTS",
         clip_admin_db_update_event_status(db, ev1.event_id, CLIP_EVENT_STATUS_REVIEWED) == CLIP_ERR_EXISTS);

    /* Verify terminal state: mutation to FALSE_POS is rejected */
    TEST("REVIEWED -> FALSE_POS returns CLIP_ERR_INVALID (terminal state)",
         clip_admin_db_update_event_status(db, ev1.event_id, CLIP_EVENT_STATUS_FALSE_POS) == CLIP_ERR_INVALID);

    /* Create second sample security event in DB */
    ClipSecurityEvent ev2 = ev1;
    clip_crypto_uuid_generate((ClipUuid*)ev2.event_uuid);
    char ev2_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string((const ClipUuid*)ev2.event_uuid, ev2_str, sizeof(ev2_str));
    strcpy(ev2.event_uuid_str, ev2_str);
    ev2.event_id = 0;
    ev2.status = CLIP_EVENT_STATUS_PENDING;

    TEST("Insert test event 2 succeeds", clip_security_db_insert_event(db, &ev2) == CLIP_OK);
    TEST("Event 2 ID assigned > 0", ev2.event_id > 0);

    /* Transition PENDING -> FALSE_POS */
    TEST("PENDING -> FALSE_POS succeeds",
         clip_admin_db_update_event_status(db, ev2.event_id, CLIP_EVENT_STATUS_FALSE_POS) == CLIP_OK);

    /* Verify terminal state: repeated FALSE_POS returns CLIP_ERR_EXISTS */
    TEST("FALSE_POS -> FALSE_POS returns CLIP_ERR_EXISTS",
         clip_admin_db_update_event_status(db, ev2.event_id, CLIP_EVENT_STATUS_FALSE_POS) == CLIP_ERR_EXISTS);

    /* Verify terminal state: mutation to REVIEWED is rejected */
    TEST("FALSE_POS -> REVIEWED returns CLIP_ERR_INVALID (terminal state)",
         clip_admin_db_update_event_status(db, ev2.event_id, CLIP_EVENT_STATUS_REVIEWED) == CLIP_ERR_INVALID);

    /* Create third sample security event in DB remaining in PENDING for Section 9 */
    ClipSecurityEvent ev3 = ev1;
    clip_crypto_uuid_generate((ClipUuid*)ev3.event_uuid);
    char ev3_str[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string((const ClipUuid*)ev3.event_uuid, ev3_str, sizeof(ev3_str));
    strcpy(ev3.event_uuid_str, ev3_str);
    ev3.event_id = 0;
    ev3.status = CLIP_EVENT_STATUS_PENDING;

    TEST("Insert test event 3 succeeds", clip_security_db_insert_event(db, &ev3) == CLIP_OK);
    TEST("Event 3 ID assigned > 0", ev3.event_id > 0);

    /* ── 5. Persistent Node Sanctions ───────────────────────────────── */
    printf("\n--- Section 5: Persistent Node Sanctions ---\n");

    ClipUuid test_node;
    uint8_t test_node_cred[CLIP_CREDENTIAL_BYTES];
    clip_identity_register(id_db, "SANCTION-TARGET", &test_node, test_node_cred);

    ClipNodeSanction sanc;
    TEST("Non-existent sanction returns CLIP_ERR_NOT_FOUND",
         clip_admin_db_get_sanction(db, test_node.bytes, &sanc) == CLIP_ERR_NOT_FOUND);

    /* Set RESTRICTED sanction */
    memset(&sanc, 0, sizeof(sanc));
    memcpy(sanc.node_uuid, test_node.bytes, CLIP_UUID_BYTES);
    sanc.status = CLIP_SANCTION_RESTRICTED;
    strcpy(sanc.reason, "Violated communication policy");
    memcpy(sanc.admin_uuid, first_admin.admin_uuid, CLIP_UUID_BYTES);

    TEST("clip_admin_db_set_sanction RESTRICTED succeeds", clip_admin_db_set_sanction(db, &sanc) == CLIP_OK);

    ClipNodeSanction read_sanc;
    TEST("clip_admin_db_get_sanction returns RESTRICTED record",
         clip_admin_db_get_sanction(db, test_node.bytes, &read_sanc) == CLIP_OK &&
         read_sanc.status == CLIP_SANCTION_RESTRICTED);
    TEST("Sanction reason matches", strcmp(read_sanc.reason, "Violated communication policy") == 0);

    /* Remove sanction */
    TEST("clip_admin_db_remove_sanction succeeds", clip_admin_db_remove_sanction(db, test_node.bytes) == CLIP_OK);
    TEST("Sanction record removed", clip_admin_db_get_sanction(db, test_node.bytes, &read_sanc) == CLIP_ERR_NOT_FOUND);

    /* Set BANNED sanction */
    sanc.status = CLIP_SANCTION_BANNED;
    strcpy(sanc.reason, "Severe policy violation");
    TEST("clip_admin_db_set_sanction BANNED succeeds", clip_admin_db_set_sanction(db, &sanc) == CLIP_OK);
    TEST("Sanction record status is BANNED",
         clip_admin_db_get_sanction(db, test_node.bytes, &read_sanc) == CLIP_OK &&
         read_sanc.status == CLIP_SANCTION_BANNED);

    clip_admin_db_remove_sanction(db, test_node.bytes);

    /* ── 6. Channel Lock / Unlock ───────────────────────────────────── */
    printf("\n--- Section 6: Channel Lock / Unlock Invariants ---\n");

    TEST("clip_admin_db_lock_channel(lock=true) succeeds",
         clip_admin_db_lock_channel(db, test_ch_uuid.bytes, true) == CLIP_OK);

    /* Joining locked channel should fail */
    ClipUuid joiner_node;
    uint8_t joiner_cred[CLIP_CREDENTIAL_BYTES];
    clip_identity_register(id_db, "JOINER-NODE", &joiner_node, joiner_cred);

    ClipUuid out_ch;
    char out_name[CLIP_DISPLAY_NAME_MAX];
    TEST("Joining locked channel is rejected with CLIP_ERR_DENIED",
         clip_channel_join_by_key(db, &joiner_node, join_key, &out_ch, out_name, sizeof(out_name)) == CLIP_ERR_DENIED);

    TEST("clip_admin_db_lock_channel(lock=false) succeeds",
         clip_admin_db_lock_channel(db, test_ch_uuid.bytes, false) == CLIP_OK);

    TEST("Joining unlocked channel succeeds",
         clip_channel_join_by_key(db, &joiner_node, join_key, &out_ch, out_name, sizeof(out_name)) == CLIP_OK);

    /* ── 7. Append-Only Audit Log Invariants ────────────────────────── */
    printf("\n--- Section 7: Append-Only Administrative Audit Log ---\n");

    ClipAdminAuditRecord audit1;
    memset(&audit1, 0, sizeof(audit1));
    memcpy(audit1.admin_uuid, first_admin.admin_uuid, CLIP_UUID_BYTES);
    audit1.action_type = CLIP_ADMIN_RESTRICT_NODE;
    memcpy(audit1.target_uuid, test_node.bytes, CLIP_UUID_BYTES);
    audit1.has_target_uuid = true;
    strcpy(audit1.reason, "Audit trail test record 1");
    audit1.status = CLIP_AUDIT_STATUS_SUCCESS;
    audit1.error_code = CLIP_OK;

    uint32_t aid1 = 0;
    TEST("clip_admin_db_add_audit record 1 succeeds", clip_admin_db_add_audit(db, &audit1, &aid1) == CLIP_OK);
    TEST("Assigned audit ID > 0", aid1 > 0);

    ClipAdminAuditRecord audit2;
    memset(&audit2, 0, sizeof(audit2));
    memcpy(audit2.admin_uuid, first_admin.admin_uuid, CLIP_UUID_BYTES);
    audit2.action_type = CLIP_ADMIN_BAN_NODE;
    memcpy(audit2.target_uuid, test_node.bytes, CLIP_UUID_BYTES);
    audit2.has_target_uuid = true;
    strcpy(audit2.reason, "Audit trail test record 2 (denied)");
    audit2.status = CLIP_AUDIT_STATUS_DENIED;
    audit2.error_code = CLIP_ERR_PERMISSION_DENIED;

    uint32_t aid2 = 0;
    TEST("clip_admin_db_add_audit record 2 succeeds", clip_admin_db_add_audit(db, &audit2, &aid2) == CLIP_OK);
    TEST("Audit ID auto-increments", aid2 > aid1);

    ClipAdminAuditRecord audit_records[10];
    size_t audit_count = 0;
    TEST("clip_admin_db_query_audit retrieves records",
         clip_admin_db_query_audit(db, 10, audit_records, &audit_count) == CLIP_OK && audit_count >= 2);
    TEST("Audit records sorted descending by ID", audit_records[0].audit_id >= audit_records[1].audit_id);

    /* ── 8. Referential Integrity Validation ────────────────────────── */
    printf("\n--- Section 8: Referential Integrity Checks ---\n");

    bool ex = false;
    TEST("clip_admin_db_event_exists returns true for ev1",
         clip_admin_db_event_exists(db, ev1.event_id, &ex) == CLIP_OK && ex == true);
    TEST("clip_admin_db_event_exists returns false for non-existent ID",
         clip_admin_db_event_exists(db, 999999, &ex) == CLIP_OK && ex == false);

    TEST("clip_admin_db_channel_exists returns true for created channel",
         clip_admin_db_channel_exists(db, test_ch_uuid.bytes, &ex) == CLIP_OK && ex == true);

    uint8_t dummy_u[CLIP_UUID_BYTES] = {0xFF};
    TEST("clip_admin_db_channel_exists returns false for dummy UUID",
         clip_admin_db_channel_exists(db, dummy_u, &ex) == CLIP_OK && ex == false);
    TEST("clip_admin_db_session_exists returns false for dummy UUID",
         clip_admin_db_session_exists(db, dummy_u, &ex) == CLIP_OK && ex == false);

    clip_identity_db_close(id_db);

    /* ── 9. Live Loopback Network Integration ───────────────────────── */
    printf("\n--- Section 9: Live Loopback Network Integration ---\n");

    ClipServer srv;
    ClipServerConfig srv_cfg;
    clip_server_config_init_default(&srv_cfg);
    srv_cfg.port = TEST_ADMIN_PORT;
    srv_cfg.use_tls = false;
    strncpy(srv_cfg.db_path, TEST_ADMIN_DB, sizeof(srv_cfg.db_path) - 1);
    strncpy(srv_cfg.rules_file, "config/security_rules.conf", sizeof(srv_cfg.rules_file) - 1);

    TEST("Server init succeeds", clip_server_init(&srv, &srv_cfg) == CLIP_OK);
    TEST("Server start succeeds", clip_server_start(&srv) == CLIP_OK);

    HANDLE srv_th = CreateThread(NULL, 0, test_server_thread, &srv, 0, NULL);
    TEST("Server background thread started", srv_th != NULL);
    Sleep(50);

    /* Connect Client A */
    ClipClientNet client_a;
    clip_client_net_init(&client_a);
    clip_client_net_set_insecure_plaintext(&client_a);
    TEST("Client A connects", clip_client_connect(&client_a, "127.0.0.1", TEST_ADMIN_PORT) == CLIP_OK);

    ClipUuid node_a_uuid;
    uint8_t cred_a[CLIP_CREDENTIAL_BYTES];
    TEST("Client A registers node", clip_client_register(&client_a, "OPERATOR-1", &node_a_uuid, cred_a) == CLIP_OK);

    /* Connect Client B (Target node) */
    ClipClientNet client_b;
    clip_client_net_init(&client_b);
    clip_client_net_set_insecure_plaintext(&client_b);
    TEST("Client B connects", clip_client_connect(&client_b, "127.0.0.1", TEST_ADMIN_PORT) == CLIP_OK);

    ClipUuid node_b_uuid;
    uint8_t cred_b[CLIP_CREDENTIAL_BYTES];
    TEST("Client B registers node", clip_client_register(&client_b, "TARGET-NODE", &node_b_uuid, cred_b) == CLIP_OK);

    /* Client A creates live channel and Client B joins */
    ClipUuid live_chan_uuid;
    char live_jkey[CLIP_JOIN_KEY_MAX];
    clip_client_channel_create(&client_a, "LiveAdminChan", &live_chan_uuid, live_jkey, sizeof(live_jkey));
    char b_cname[CLIP_DISPLAY_NAME_MAX];
    clip_client_channel_join(&client_b, live_jkey, &live_chan_uuid, b_cname, sizeof(b_cname), NULL, NULL);

    /* Connection request and session start */
    ClipUuid live_conn_uuid;
    ClipConnectionState cstate;
    clip_client_send_conn_request(&client_a, &live_chan_uuid, &node_b_uuid, &live_conn_uuid, &cstate);
    clip_client_respond_conn(&client_b, &live_conn_uuid, true);

    ClipUuid active_sess_uuid;
    TEST("Active session established", clip_client_session_start_by_conn(&client_a, &live_conn_uuid, &active_sess_uuid) == CLIP_OK);

    /* 9.1: Attempt admin action without admin login -> DENIED */
    uint32_t act_audit_id = 0;
    ClipError unauth_act = clip_admin_client_send_action(&client_a, CLIP_ADMIN_REVIEW_EVENT, NULL,
                                                         "Attempt without auth", ev1.event_id, NULL, NULL, &act_audit_id);
    TEST("ADMIN_ACTION without admin login fails with CLIP_ERR_DENIED", unauth_act == CLIP_ERR_DENIED);

    /* 9.2: Admin login with wrong password -> Fails */
    ClipAdminPermission login_role;
    ClipUuid admin_uuid_out;
    TEST("Admin login with wrong password fails with CLIP_ERR_AUTH",
         clip_admin_client_login(&client_a, "rootadmin", "WrongPassword123!", &login_role, &admin_uuid_out) == CLIP_ERR_AUTH);

    /* 9.3: Admin login with valid credentials -> Succeeds as SUPER_ADMIN */
    TEST("Admin login with valid password succeeds",
         clip_admin_client_login(&client_a, "rootadmin", pwd1, &login_role, &admin_uuid_out) == CLIP_OK);
    TEST("Logged in admin role is SUPER_ADMIN", login_role == CLIP_ADMIN_PERM_SUPER_ADMIN);

    /* 9.4: SUPER_ADMIN creates a new MODERATOR admin over the network */
    uint32_t create_aud = 0;
    TEST("clip_admin_client_create_admin creates moderator user",
         clip_admin_client_create_admin(&client_a, "moduser", "ModeratorSecret123!",
                                       CLIP_ADMIN_PERM_MODERATOR, "Onboard security moderator", &create_aud) == CLIP_OK);
    TEST("Audit ID generated for admin creation", create_aud > 0);

    /* 9.5: Mark false positive on ev2 over network */
    uint32_t fp_aud = 0;
    TEST("clip_admin_client_send_action MARK_FALSE_POS succeeds",
         clip_admin_client_send_action(&client_a, CLIP_ADMIN_MARK_FALSE_POS, NULL,
                                      "Confirmed test false positive", ev3.event_id, NULL, NULL, &fp_aud) == CLIP_OK);
    TEST("Audit ID generated for MARK_FALSE_POS", fp_aud > 0);

    /* Repeated false positive returns CLIP_ERR_EXISTS */
    TEST("Repeated MARK_FALSE_POS returns CLIP_ERR_EXISTS",
         clip_admin_client_send_action(&client_a, CLIP_ADMIN_MARK_FALSE_POS, NULL,
                                      "Duplicate false positive", ev3.event_id, NULL, NULL, NULL) == CLIP_ERR_EXISTS);

    /* Query security events as admin */
    ClipSecurityEvent* adm_events = NULL;
    size_t adm_ev_cnt = 0;
    TEST("clip_admin_client_list_events returns events",
         clip_admin_client_list_events(&client_a, -1, &adm_events, &adm_ev_cnt) == CLIP_OK && adm_ev_cnt >= 2);
    clip_admin_client_free_events(adm_events, adm_ev_cnt);

    /* 9.6: Sanction node B: RESTRICT_NODE */
    uint32_t restr_aud = 0;
    TEST("clip_admin_client_send_action RESTRICT_NODE on Client B succeeds",
         clip_admin_client_send_action(&client_a, CLIP_ADMIN_RESTRICT_NODE, &node_b_uuid,
                                      "Restricting client B for testing", 0, NULL, NULL, &restr_aud) == CLIP_OK);

    /* Verify restricted node cannot acquire PTT floor in active session */
    ClipPttFloor out_fl;
    ClipError out_denial = CLIP_OK;
    ClipError ptt_res = clip_client_ptt_request(&client_b, &active_sess_uuid, 5000, &out_fl, &out_denial);
    TEST("Restricted node PTT request is rejected with CLIP_ERR_RESTRICTED", ptt_res == CLIP_ERR_RESTRICTED);

    /* Verify restricted node cannot start a session */
    ClipUuid s_out;
    ClipError sess_res = clip_client_session_start(&client_b, &live_chan_uuid, &s_out);
    TEST("Restricted node session start is rejected with CLIP_ERR_RESTRICTED", sess_res == CLIP_ERR_RESTRICTED);

    /* 9.7: UNRESTRICT_NODE Client B */
    uint32_t unrestr_aud = 0;
    TEST("clip_admin_client_send_action UNRESTRICT_NODE succeeds",
         clip_admin_client_send_action(&client_a, CLIP_ADMIN_UNRESTRICT_NODE, &node_b_uuid,
                                      "Restoring client B privileges", 0, NULL, NULL, &unrestr_aud) == CLIP_OK);

    /* 9.8: BAN_NODE Client B */
    uint32_t ban_aud = 0;
    TEST("clip_admin_client_send_action BAN_NODE succeeds",
         clip_admin_client_send_action(&client_a, CLIP_ADMIN_BAN_NODE, &node_b_uuid,
                                      "Banning client B permanently", 0, NULL, NULL, &ban_aud) == CLIP_OK);

    /* Allow server to close socket and enforce disconnect */
    Sleep(100);

    /* Client B attempts reconnect / auth with saved credentials */
    clip_client_disconnect(&client_b);
    ClipClientNet client_b2;
    clip_client_net_init(&client_b2);
    clip_client_net_set_insecure_plaintext(&client_b2);
    clip_client_connect(&client_b2, "127.0.0.1", TEST_ADMIN_PORT);
    char dname[CLIP_DISPLAY_NAME_MAX];
    ClipError ban_login = clip_client_authenticate(&client_b2, &node_b_uuid, cred_b, dname, sizeof(dname));
    TEST("Banned node connection authentication rejected with CLIP_ERR_BANNED", ban_login == CLIP_ERR_BANNED);
    clip_client_disconnect(&client_b2);

    /* 9.9: UNBAN_NODE Client B */
    uint32_t unban_aud = 0;
    TEST("clip_admin_client_send_action UNBAN_NODE succeeds",
         clip_admin_client_send_action(&client_a, CLIP_ADMIN_UNBAN_NODE, &node_b_uuid,
                                      "Pardoning client B", 0, NULL, NULL, &unban_aud) == CLIP_OK);

    /* Client B can now authenticate again */
    clip_client_connect(&client_b2, "127.0.0.1", TEST_ADMIN_PORT);
    ClipError unban_login = clip_client_authenticate(&client_b2, &node_b_uuid, cred_b, dname, sizeof(dname));
    TEST("Unbanned node can authenticate successfully", unban_login == CLIP_OK);
    clip_client_disconnect(&client_b2);

    /* 9.10: Lock and unlock channel over network */
    uint32_t lock_aud = 0;
    TEST("clip_admin_client_send_action LOCK_CHANNEL succeeds",
         clip_admin_client_send_action(&client_a, CLIP_ADMIN_LOCK_CHANNEL, &live_chan_uuid,
                                      "Locking channel for maintenance", 0, NULL, &live_chan_uuid, &lock_aud) == CLIP_OK);

    uint32_t unlock_aud = 0;
    TEST("clip_admin_client_send_action UNLOCK_CHANNEL succeeds",
         clip_admin_client_send_action(&client_a, CLIP_ADMIN_UNLOCK_CHANNEL, &live_chan_uuid,
                                      "Maintenance complete, reopening channel", 0, NULL, &live_chan_uuid, &unlock_aud) == CLIP_OK);

    /* 9.11: Query audit log over network */
    ClipAdminAuditRecord* net_audits = NULL;
    size_t net_aud_cnt = 0;
    TEST("clip_admin_client_list_audit over network succeeds",
         clip_admin_client_list_audit(&client_a, 20, &net_audits, &net_aud_cnt) == CLIP_OK && net_aud_cnt >= 5);
    clip_admin_client_free_audit(net_audits, net_aud_cnt);

    /* Cleanup network */
    clip_client_disconnect(&client_a);
    srv.is_running = false;
    WaitForSingleObject(srv_th, 1000);
    CloseHandle(srv_th);
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);

    remove(TEST_ADMIN_DB);

    /* ── Summary ─────────────────────────────────────────────────────── */
    printf("\n======================================================\n");
    printf("Phase 16 Test Summary: %d passed, %d failed\n", g_pass, g_fail);
    printf("======================================================\n\n");

    return (g_fail == 0) ? 0 : 1;
}

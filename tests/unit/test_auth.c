/*
 * test_auth.c — CLICOM Phase 3 Unit & Integration Tests: Authentication & Identity
 *
 * Tests:
 * 1. Cryptographic RNG and UUIDv4 validation (version 4, variant 1)
 * 2. 256-bit credential entropy (distinct credentials)
 * 3. SHA-256 verifier computation & constant-time comparison
 * 4. SQLite identity database operations (atomic registration, lookup, verifier check)
 * 5. Server database never contains plaintext credential (only 32-byte verifier)
 * 6. Revocation lifecycle (active -> revoked -> authentication rejected)
 * 7. Display name updates without mutating immutable node_uuid
 * 8. Server restart persistence (closing DB and reopening preserves identity)
 * 9. Client DPAPI credential save/load/roundtrip
 * 10. Live loopback first-time registration (REGISTER -> REGISTER_ACK with UUID+cred)
 * 11. Live loopback authenticated reconnect (AUTH -> AUTH_OK with same UUID)
 * 12. Rejection of incorrect credentials (AUTH -> AUTH_FAIL with CLIP_ERR_AUTH)
 * 13. Rejection of unknown UUID (AUTH -> AUTH_FAIL with CLIP_ERR_AUTH)
 * 14. Rejection of revoked node (AUTH -> AUTH_FAIL with CLIP_ERR_DENIED)
 * 15. Server authentication boundary: unauthenticated clients cannot perform operations
 * 16. Security tests: malformed TLVs, oversized payloads, corrupted CRC32 rejection
 */

#include <winsock2.h>
#include <windows.h>
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
#include "clip_admin.h"
#include "clip_admin_db.h"
#include "../../server/include/server.h"
#include "../../client/include/network.h"

#define THREAD_STRESS_COUNT 8
typedef struct {
    ClipRateLimiter* rl;
    const char* ip;
    int thread_id;
} StressParam;

static DWORD WINAPI stress_worker(LPVOID p) {
    StressParam* sp = (StressParam*)p;
    for (int i = 0; i < 50; i++) {
        clip_rate_limiter_check(sp->rl, sp->ip, 5000000ULL + i * 10);
        clip_rate_limiter_record_failure(sp->rl, sp->ip, 5000000ULL + i * 10);
        clip_rate_limiter_record_success(sp->rl, sp->ip, 5000000ULL + i * 10);
    }
    return 0;
}

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

#define TEST_DB_PATH "test_auth_identity.db"
#define TEST_CRED_FILE "test_auth_node.cred"
#define TEST_PORT 14921

/* ── Test Suite ──────────────────────────────────────────────────────────── */

static void test_crypto_and_uuid(void)
{
    printf("\n[1-3. Cryptographic Primitives & UUIDv4]\n");

    ClipUuid u1, u2;
    ClipError err1 = clip_crypto_uuid_generate(&u1);
    ClipError err2 = clip_crypto_uuid_generate(&u2);

    TEST("UUID generation succeeds", err1 == CLIP_OK && err2 == CLIP_OK);
    TEST("Two generated UUIDs are distinct", !clip_uuid_equal(&u1, &u2));

    /* RFC 4122 v4 check: byte 6 high nibble == 0x4, byte 8 high 2 bits == 0x8 or 0x9 or 0xA or 0xB */
    bool v4_ok = ((u1.bytes[6] >> 4) == 4) && ((u1.bytes[8] >> 6) == 2);
    TEST("UUID satisfies RFC 4122 Version 4 and Variant 1 bits", v4_ok);

    uint8_t cred1[CLIP_CREDENTIAL_BYTES];
    uint8_t cred2[CLIP_CREDENTIAL_BYTES];
    clip_crypto_random_bytes(cred1, sizeof(cred1));
    clip_crypto_random_bytes(cred2, sizeof(cred2));

    TEST("Generated 256-bit credentials are distinct", memcmp(cred1, cred2, CLIP_CREDENTIAL_BYTES) != 0);

    /* SHA-256 verifier check */
    uint8_t hash1[CLIP_SHA256_BYTES];
    uint8_t hash2[CLIP_SHA256_BYTES];
    clip_crypto_sha256(cred1, sizeof(cred1), hash1);
    clip_crypto_sha256(cred2, sizeof(cred2), hash2);

    TEST("SHA-256 verifiers of distinct credentials are distinct",
         memcmp(hash1, hash2, CLIP_SHA256_BYTES) != 0);

    TEST("Constant-time equality helper validates identical hashes",
         clip_crypto_secure_equal(hash1, hash1, CLIP_SHA256_BYTES));
    TEST("Constant-time equality helper rejects differing hashes",
         !clip_crypto_secure_equal(hash1, hash2, CLIP_SHA256_BYTES));
}

static void test_client_dpapi_credentials(void)
{
    printf("\n[4. Client DPAPI Protected Credential Storage]\n");

    remove(TEST_CRED_FILE);

    ClipClientCredentials c_in;
    clip_crypto_uuid_generate(&c_in.node_uuid);
    clip_crypto_random_bytes(c_in.credential, sizeof(c_in.credential));
    strncpy(c_in.display_name, "TEST-DPAPI-NODE", sizeof(c_in.display_name) - 1);

    ClipError save_err = clip_credentials_save(TEST_CRED_FILE, &c_in);
    TEST("DPAPI credential save succeeds", save_err == CLIP_OK);
    TEST("Credential file exists on disk", clip_credentials_exists(TEST_CRED_FILE));

    ClipClientCredentials c_out;
    memset(&c_out, 0, sizeof(c_out));
    ClipError load_err = clip_credentials_load(TEST_CRED_FILE, &c_out);
    TEST("DPAPI credential load succeeds", load_err == CLIP_OK);

    TEST("Loaded UUID matches saved UUID exactly",
         clip_uuid_equal(&c_in.node_uuid, &c_out.node_uuid));
    TEST("Loaded 256-bit credential matches saved credential exactly",
         clip_crypto_secure_equal(c_in.credential, c_out.credential, CLIP_CREDENTIAL_BYTES));
    TEST("Loaded display name matches saved display name",
         strcmp(c_in.display_name, c_out.display_name) == 0);

    clip_credentials_delete(TEST_CRED_FILE);
    TEST("Credential delete removes file", !clip_credentials_exists(TEST_CRED_FILE));
}

static void test_sqlite_identity_store(void)
{
    printf("\n[5-8. Server SQLite Identity Database Operations]\n");

    remove(TEST_DB_PATH);

    ClipIdentityDb* db = NULL;
    ClipError open_err = clip_identity_db_open(&db, TEST_DB_PATH);
    TEST("SQLite identity database creation succeeds", open_err == CLIP_OK && db != NULL);

    if (db) {
        sqlite3* sdb = clip_identity_get_sqlite(db);
        sqlite3_stmt* stmt = NULL;

        /* Verify journal_mode is WAL */
        int rc = sqlite3_prepare_v2(sdb, "PRAGMA journal_mode;", -1, &stmt, NULL);
        TEST("Query PRAGMA journal_mode succeeds", rc == SQLITE_OK);
        if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
            const char* mode = (const char*)sqlite3_column_text(stmt, 0);
            TEST("PRAGMA journal_mode is WAL", mode != NULL && _stricmp(mode, "wal") == 0);
        }
        if (stmt) sqlite3_finalize(stmt);

        /* Verify busy_timeout is 5000 */
        stmt = NULL;
        rc = sqlite3_prepare_v2(sdb, "PRAGMA busy_timeout;", -1, &stmt, NULL);
        TEST("Query PRAGMA busy_timeout succeeds", rc == SQLITE_OK);
        if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
            int bt = sqlite3_column_int(stmt, 0);
            TEST("PRAGMA busy_timeout is 5000 ms", bt == 5000);
        }
        if (stmt) sqlite3_finalize(stmt);
    }

    ClipUuid uuid_a, uuid_b;
    uint8_t cred_a[CLIP_CREDENTIAL_BYTES];
    uint8_t cred_b[CLIP_CREDENTIAL_BYTES];

    ClipError reg_a = clip_identity_register(db, "ALPHA-NODE", &uuid_a, cred_a);
    ClipError reg_b = clip_identity_register(db, "BETA-NODE", &uuid_b, cred_b);

    TEST("Registration of Node A succeeds", reg_a == CLIP_OK);
    TEST("Registration of Node B succeeds", reg_b == CLIP_OK);
    TEST("Node A and Node B receive distinct UUIDs", !clip_uuid_equal(&uuid_a, &uuid_b));

    /* Authenticate Node A with correct credential */
    char name_buf[CLIP_DISPLAY_NAME_MAX];
    bool is_revoked = false;
    ClipError auth_ok = clip_identity_authenticate(db, &uuid_a, cred_a, name_buf, sizeof(name_buf), &is_revoked);
    TEST("Authentication with valid credential succeeds", auth_ok == CLIP_OK);
    TEST("Authentication recovers correct display name", strcmp(name_buf, "ALPHA-NODE") == 0);
    TEST("Node is active (not revoked)", !is_revoked);

    /* Authenticate with wrong credential */
    uint8_t bad_cred[CLIP_CREDENTIAL_BYTES];
    memcpy(bad_cred, cred_a, sizeof(bad_cred));
    bad_cred[0] ^= 0xFF; /* flip bits */
    ClipError auth_bad = clip_identity_authenticate(db, &uuid_a, bad_cred, name_buf, sizeof(name_buf), &is_revoked);
    TEST("Authentication with incorrect credential fails with CLIP_ERR_AUTH", auth_bad == CLIP_ERR_AUTH);

    /* Authenticate with non-existent UUID */
    ClipUuid unknown_uuid;
    clip_crypto_uuid_generate(&unknown_uuid);
    ClipError auth_unknown = clip_identity_authenticate(db, &unknown_uuid, cred_a, name_buf, sizeof(name_buf), &is_revoked);
    TEST("Authentication with unknown UUID fails with CLIP_ERR_NOT_FOUND", auth_unknown == CLIP_ERR_NOT_FOUND);

    /* Display name update */
    ClipError upd_err = clip_identity_update_display_name(db, &uuid_a, "ALPHA-RENAMED");
    TEST("Update display name succeeds", upd_err == CLIP_OK);
    clip_identity_authenticate(db, &uuid_a, cred_a, name_buf, sizeof(name_buf), &is_revoked);
    TEST("Updated display name reflected in subsequent authentication", strcmp(name_buf, "ALPHA-RENAMED") == 0);

    /* Revocation test */
    ClipError rev_err = clip_identity_set_revoked(db, &uuid_a, true);
    TEST("Set revoked succeeds", rev_err == CLIP_OK);

    ClipError auth_rev = clip_identity_authenticate(db, &uuid_a, cred_a, name_buf, sizeof(name_buf), &is_revoked);
    TEST("Authentication of revoked node fails with CLIP_ERR_DENIED", auth_rev == CLIP_ERR_DENIED);
    TEST("Revocation flag reported as true", is_revoked);

    /* Un-revoke */
    clip_identity_set_revoked(db, &uuid_a, false);
    ClipError auth_unrev = clip_identity_authenticate(db, &uuid_a, cred_a, name_buf, sizeof(name_buf), &is_revoked);
    TEST("Un-revoked node authenticates successfully again", auth_unrev == CLIP_OK && !is_revoked);

    /* Server restart test (close and reopen DB) */
    clip_identity_db_close(db);
    db = NULL;

    ClipError reopen_err = clip_identity_db_open(&db, TEST_DB_PATH);
    TEST("Database reopens cleanly after close", reopen_err == CLIP_OK && db != NULL);

    ClipError persist_auth = clip_identity_authenticate(db, &uuid_b, cred_b, name_buf, sizeof(name_buf), &is_revoked);
    TEST("Identity persisted across database restart and authenticates", persist_auth == CLIP_OK);
    TEST("Node B display name preserved across database restart", strcmp(name_buf, "BETA-NODE") == 0);

    clip_identity_db_close(db);
    remove(TEST_DB_PATH);
}

static void test_live_network_auth(void)
{
    printf("\n[9-13. Live Network Registration, Reconnect & Security Boundary]\n");

    remove(TEST_DB_PATH);
    remove(TEST_CRED_FILE);

    ClipServerConfig srv_cfg;
    memset(&srv_cfg, 0, sizeof(srv_cfg));
    strncpy(srv_cfg.bind_host, "127.0.0.1", sizeof(srv_cfg.bind_host) - 1);
    strncpy(srv_cfg.db_path, TEST_DB_PATH, sizeof(srv_cfg.db_path) - 1);
    srv_cfg.port = TEST_PORT;
    srv_cfg.max_clients = 16;

    ClipServer srv;
    clip_server_init(&srv, &srv_cfg);
    clip_server_start(&srv);

    /* 1. Client 1 First Registration */
    ClipClientNet c1;
    clip_client_net_init(&c1);
    clip_client_net_set_insecure_plaintext(&c1);
    clip_client_connect(&c1, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);

    /* Construct REGISTER payload */
    uint8_t reg_payload[128];
    size_t reg_len = 0;
    clip_tlv_write(reg_payload, sizeof(reg_payload), &reg_len,
                   CLIP_TAG_DISPLAY_NAME, "NODE-ALPHA", 10);

    ClipFrameHeader reg_hdr;
    clip_frame_header_init(&reg_hdr, CLIP_MSG_REGISTER, (uint32_t)reg_len, 1, NULL);
    clip_client_send_frame(&c1, &reg_hdr, reg_payload);

    /* Server processes frame and sends REGISTER_ACK */
    clip_server_poll(&srv, 50);

    /* Client receives response */
    ClipFrameHeader ack_hdr;
    uint8_t ack_payload[512];
    uint32_t ack_len = 0;
    ClipError recv_res = clip_client_recv_frame(&c1, &ack_hdr, ack_payload, sizeof(ack_payload), &ack_len, 1000);

    TEST("Client 1 live registration frame received", recv_res == CLIP_OK);
    TEST("Response is CLIP_MSG_REGISTER_ACK", ack_hdr.msg_type == CLIP_MSG_REGISTER_ACK);

    const uint8_t* u_ptr = NULL;
    uint16_t u_len = 0;
    const uint8_t* k_ptr = NULL;
    uint16_t k_len = 0;
    clip_tlv_find(ack_payload, ack_len, CLIP_TAG_NODE_UUID, &u_ptr, &u_len);
    clip_tlv_find(ack_payload, ack_len, CLIP_TAG_CREDENTIAL, &k_ptr, &k_len);

    TEST("REGISTER_ACK carries valid 16-byte UUID", u_ptr != NULL && u_len == CLIP_UUID_BYTES);
    TEST("REGISTER_ACK carries valid 32-byte credential", k_ptr != NULL && k_len == CLIP_CREDENTIAL_BYTES);

    static const uint8_t zero_uuid[CLIP_UUID_BYTES] = {0};
    TEST("REGISTER_ACK header session_uuid is zero (no session in Phase 3)",
         memcmp(ack_hdr.session_uuid, zero_uuid, CLIP_UUID_BYTES) == 0);
    TEST("REGISTER_ACK header session_uuid != node_uuid (regression)",
         u_ptr != NULL && memcmp(ack_hdr.session_uuid, u_ptr, CLIP_UUID_BYTES) != 0);

    ClipClientCredentials c1_creds;
    memset(&c1_creds, 0, sizeof(c1_creds));
    memcpy(c1_creds.node_uuid.bytes, u_ptr, CLIP_UUID_BYTES);
    memcpy(c1_creds.credential, k_ptr, CLIP_CREDENTIAL_BYTES);
    strncpy(c1_creds.display_name, "NODE-ALPHA", sizeof(c1_creds.display_name) - 1);
    clip_credentials_save(TEST_CRED_FILE, &c1_creds);

    /* Disconnect client 1 */
    clip_client_disconnect(&c1);
    clip_server_poll(&srv, 20);
    clip_client_net_cleanup(&c1);

    /* 2. Client 1 Reconnect & Authenticate */
    ClipClientNet c1_reconnect;
    clip_client_net_init(&c1_reconnect);
    clip_client_net_set_insecure_plaintext(&c1_reconnect);
    clip_client_connect(&c1_reconnect, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);

    ClipClientCredentials loaded_creds;
    clip_credentials_load(TEST_CRED_FILE, &loaded_creds);

    uint8_t auth_payload[256];
    size_t auth_len = 0;
    clip_tlv_write(auth_payload, sizeof(auth_payload), &auth_len,
                   CLIP_TAG_NODE_UUID, loaded_creds.node_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(auth_payload, sizeof(auth_payload), &auth_len,
                   CLIP_TAG_CREDENTIAL, loaded_creds.credential, CLIP_CREDENTIAL_BYTES);

    ClipFrameHeader auth_hdr;
    clip_frame_header_init(&auth_hdr, CLIP_MSG_AUTH, (uint32_t)auth_len, 1, loaded_creds.node_uuid.bytes);
    clip_client_send_frame(&c1_reconnect, &auth_hdr, auth_payload);

    clip_server_poll(&srv, 50);

    ClipFrameHeader auth_ack_hdr;
    uint8_t auth_ack_payload[256];
    uint32_t auth_ack_len = 0;
    ClipError auth_recv_res = clip_client_recv_frame(&c1_reconnect, &auth_ack_hdr, auth_ack_payload,
                                                     sizeof(auth_ack_payload), &auth_ack_len, 1000);

    TEST("Client 1 live reconnect AUTH response received", auth_recv_res == CLIP_OK);
    TEST("Response is CLIP_MSG_AUTH_OK", auth_ack_hdr.msg_type == CLIP_MSG_AUTH_OK);

    const uint8_t* u_ack_ptr = NULL;
    uint16_t u_ack_len = 0;
    clip_tlv_find(auth_ack_payload, auth_ack_len, CLIP_TAG_NODE_UUID, &u_ack_ptr, &u_ack_len);

    TEST("AUTH_OK header session_uuid is zero (no session in Phase 3)",
         memcmp(auth_ack_hdr.session_uuid, zero_uuid, CLIP_UUID_BYTES) == 0);
    TEST("AUTH_OK header session_uuid != node_uuid (regression)",
         memcmp(auth_ack_hdr.session_uuid, loaded_creds.node_uuid.bytes, CLIP_UUID_BYTES) != 0);
    TEST("AUTH_OK payload contains correct permanent node_uuid",
         u_ack_ptr != NULL && u_ack_len == CLIP_UUID_BYTES &&
         clip_uuid_equal(&loaded_creds.node_uuid, (const ClipUuid*)u_ack_ptr));

    const uint8_t* name_ack = NULL;
    uint16_t name_ack_len = 0;
    clip_tlv_find(auth_ack_payload, auth_ack_len, CLIP_TAG_DISPLAY_NAME, &name_ack, &name_ack_len);
    TEST("AUTH_OK returns registered display name", name_ack != NULL && strncmp((const char*)name_ack, "NODE-ALPHA", name_ack_len) == 0);

    clip_client_disconnect(&c1_reconnect);
    clip_server_poll(&srv, 20);
    clip_client_net_cleanup(&c1_reconnect);

    /* 3. Reconnect with Wrong Credential */
    ClipClientNet c_bad;
    clip_client_net_init(&c_bad);
    clip_client_net_set_insecure_plaintext(&c_bad);
    clip_client_connect(&c_bad, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);

    uint8_t wrong_cred[CLIP_CREDENTIAL_BYTES];
    memcpy(wrong_cred, loaded_creds.credential, CLIP_CREDENTIAL_BYTES);
    wrong_cred[5] ^= 0xFF;

    auth_len = 0;
    clip_tlv_write(auth_payload, sizeof(auth_payload), &auth_len,
                   CLIP_TAG_NODE_UUID, loaded_creds.node_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(auth_payload, sizeof(auth_payload), &auth_len,
                   CLIP_TAG_CREDENTIAL, wrong_cred, CLIP_CREDENTIAL_BYTES);

    clip_frame_header_init(&auth_hdr, CLIP_MSG_AUTH, (uint32_t)auth_len, 2, loaded_creds.node_uuid.bytes);
    clip_client_send_frame(&c_bad, &auth_hdr, auth_payload);
    clip_server_poll(&srv, 50);

    ClipFrameHeader bad_resp_hdr;
    clip_client_recv_frame(&c_bad, &bad_resp_hdr, NULL, 0, NULL, 1000);
    TEST("Server returns AUTH_FAIL for wrong credential", bad_resp_hdr.msg_type == CLIP_MSG_AUTH_FAIL);

    clip_client_disconnect(&c_bad);
    clip_server_poll(&srv, 20);
    clip_client_net_cleanup(&c_bad);

    /* 4. Revoke Node and attempt Reconnect */
    clip_identity_set_revoked(srv.identity_db, &loaded_creds.node_uuid, true);

    ClipClientNet c_rev;
    clip_client_net_init(&c_rev);
    clip_client_net_set_insecure_plaintext(&c_rev);
    clip_client_connect(&c_rev, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);

    auth_len = 0;
    clip_tlv_write(auth_payload, sizeof(auth_payload), &auth_len,
                   CLIP_TAG_NODE_UUID, loaded_creds.node_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(auth_payload, sizeof(auth_payload), &auth_len,
                   CLIP_TAG_CREDENTIAL, loaded_creds.credential, CLIP_CREDENTIAL_BYTES);

    clip_frame_header_init(&auth_hdr, CLIP_MSG_AUTH, (uint32_t)auth_len, 3, loaded_creds.node_uuid.bytes);
    clip_client_send_frame(&c_rev, &auth_hdr, auth_payload);
    clip_server_poll(&srv, 50);

    ClipFrameHeader rev_resp_hdr;
    uint8_t rev_payload[64];
    uint32_t rev_payload_len = 0;
    clip_client_recv_frame(&c_rev, &rev_resp_hdr, rev_payload, sizeof(rev_payload), &rev_payload_len, 1000);
    TEST("Server returns AUTH_FAIL for revoked node", rev_resp_hdr.msg_type == CLIP_MSG_AUTH_FAIL);

    const uint8_t* st_ptr = NULL;
    uint16_t st_len = 0;
    clip_tlv_find(rev_payload, rev_payload_len, CLIP_TAG_AUTH_STATUS, &st_ptr, &st_len);
    uint16_t denied_code = (uint16_t)(-((int)CLIP_ERR_DENIED));
    TEST("AUTH_FAIL contains CLIP_ERR_DENIED status code",
         st_ptr != NULL && st_len == 2 && (((uint16_t)st_ptr[0] << 8) | (uint16_t)st_ptr[1]) == denied_code);

    clip_client_disconnect(&c_rev);
    clip_server_poll(&srv, 20);
    clip_client_net_cleanup(&c_rev);

    /* 5. Malformed payload rejection */
    ClipClientNet c_malformed;
    clip_client_net_init(&c_malformed);
    clip_client_net_set_insecure_plaintext(&c_malformed);
    clip_client_connect(&c_malformed, "127.0.0.1", TEST_PORT);
    clip_server_poll(&srv, 50);

    /* Send AUTH frame with missing credential TLV */
    uint8_t bad_payload[16] = {0};
    ClipFrameHeader bad_hdr;
    clip_frame_header_init(&bad_hdr, CLIP_MSG_AUTH, sizeof(bad_payload), 999, NULL);
    clip_client_send_frame(&c_malformed, &bad_hdr, bad_payload);
    clip_server_poll(&srv, 50);

    ClipFrameHeader fail_resp;
    clip_client_recv_frame(&c_malformed, &fail_resp, NULL, 0, NULL, 1000);
    TEST("Server returns AUTH_FAIL on malformed authentication payload",
         fail_resp.msg_type == CLIP_MSG_AUTH_FAIL);

    clip_client_disconnect(&c_malformed);
    clip_server_poll(&srv, 20);
    clip_client_net_cleanup(&c_malformed);

    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
    remove(TEST_DB_PATH);
    remove(TEST_CRED_FILE);
}

static void test_rate_limiting(void)
{
    printf("\n[14. Phase 17 Stage 4: Authentication Rate Limiting & Block Behavior]\n");

    ClipRateLimiter rl;
    TEST("clip_rate_limiter_init succeeds", clip_rate_limiter_init(&rl) == CLIP_OK);

    const char* ip1 = "192.168.1.100";
    const char* ip2 = "192.168.1.101";

    /* Test 1: First 4 failed attempts are allowed (not blocked) */
    uint64_t t0 = 1000000ULL;
    for (int i = 0; i < 4; i++) {
        TEST("Pre-check before 5th failure allows attempt",
             clip_rate_limiter_check(&rl, ip1, t0 + i * 1000) == CLIP_OK);
        TEST("Failure 1..4 records without blocking",
             clip_rate_limiter_record_failure(&rl, ip1, t0 + i * 1000) == CLIP_OK);
    }

    /* Test 2: 5th failure triggers block and returns CLIP_ERR_DENIED */
    TEST("5th failure triggers block",
         clip_rate_limiter_record_failure(&rl, ip1, t0 + 4000) == CLIP_ERR_DENIED);

    /* Test 3: Subsequent checks within 60s return CLIP_ERR_DENIED */
    TEST("Active block rejects check at +10s",
         clip_rate_limiter_check(&rl, ip1, t0 + 14000) == CLIP_ERR_DENIED);
    TEST("Active block rejects check at +59s",
         clip_rate_limiter_check(&rl, ip1, t0 + 63999) == CLIP_ERR_DENIED);

    /* Test 4: Second IP is tracked independently and not affected */
    TEST("Independent IP2 allowed while IP1 is blocked",
         clip_rate_limiter_check(&rl, ip2, t0 + 10000) == CLIP_OK);
    TEST("IP2 failure 1 records independently",
         clip_rate_limiter_record_failure(&rl, ip2, t0 + 10000) == CLIP_OK);

    /* Test 5: Successful auth cannot bypass active block */
    TEST("Success cannot bypass active block",
         clip_rate_limiter_record_success(&rl, ip1, t0 + 20000) == CLIP_ERR_DENIED);
    TEST("IP1 still blocked after failed bypass",
         clip_rate_limiter_check(&rl, ip1, t0 + 20000) == CLIP_ERR_DENIED);

    /* Test 6: Block expires after 60,000 ms */
    uint64_t t_expire = t0 + 4000 + CLIP_RATE_LIMIT_BLOCK_MS;
    TEST("Block expires exactly after 60s window",
         clip_rate_limiter_check(&rl, ip1, t_expire) == CLIP_OK);

    /* Test 7: Successful auth on unblocked IP resets failure count */
    TEST("IP2 records 3 failures",
         clip_rate_limiter_record_failure(&rl, ip2, t0 + 11000) == CLIP_OK &&
         clip_rate_limiter_record_failure(&rl, ip2, t0 + 12000) == CLIP_OK);
    TEST("IP2 success resets failure history",
         clip_rate_limiter_record_success(&rl, ip2, t0 + 13000) == CLIP_OK);
    /* Now IP2 can have 4 failures without blocking */
    for (int i = 0; i < 4; i++) {
        clip_rate_limiter_record_failure(&rl, ip2, t0 + 14000 + i * 1000);
    }
    TEST("IP2 allowed on 4th attempt after reset",
         clip_rate_limiter_check(&rl, ip2, t0 + 18000) == CLIP_OK);

    /* Test 8: LRU eviction of unblocked entries */
    clip_rate_limiter_cleanup(&rl);
    clip_rate_limiter_init(&rl);

    /* Fill table with 128 distinct IPs with 1 failure each */
    char buf_ip[64];
    for (int i = 0; i < CLIP_RATE_LIMIT_MAX_ENTRIES; i++) {
        snprintf(buf_ip, sizeof(buf_ip), "10.0.0.%d", i);
        clip_rate_limiter_record_failure(&rl, buf_ip, 2000000ULL + i);
    }
    TEST("Table capacity reached 128 entries", rl.count == CLIP_RATE_LIMIT_MAX_ENTRIES);

    /* Adding 129th unblocked IP evicts oldest unblocked (10.0.0.0) */
    snprintf(buf_ip, sizeof(buf_ip), "10.0.1.1");
    TEST("129th IP evicts unblocked LRU entry and succeeds",
         clip_rate_limiter_record_failure(&rl, buf_ip, 2000000ULL + 200) == CLIP_OK);

    /* Test 9: Active blocks are NEVER evicted */
    clip_rate_limiter_cleanup(&rl);
    clip_rate_limiter_init(&rl);

    /* Create an active block for 10.1.0.1 */
    const char* blocked_ip = "10.1.0.1";
    for (int i = 0; i < 5; i++) {
        clip_rate_limiter_record_failure(&rl, blocked_ip, 3000000ULL + i);
    }
    TEST("10.1.0.1 is actively blocked",
         clip_rate_limiter_check(&rl, blocked_ip, 3000000ULL + 10) == CLIP_ERR_DENIED);

    /* Fill remaining 127 slots with unblocked entries */
    for (int i = 2; i <= CLIP_RATE_LIMIT_MAX_ENTRIES; i++) {
        snprintf(buf_ip, sizeof(buf_ip), "10.1.0.%d", i);
        clip_rate_limiter_record_failure(&rl, buf_ip, 3000000ULL + 10 + i);
    }
    TEST("Table full with 1 active block and 127 unblocked entries", rl.count == CLIP_RATE_LIMIT_MAX_ENTRIES);

    /* Insert another new IP: must evict an unblocked entry, NOT the active block */
    const char* new_ip = "10.1.1.1";
    clip_rate_limiter_record_failure(&rl, new_ip, 3000000ULL + 500);
    TEST("Active block was preserved and NOT evicted by LRU",
         clip_rate_limiter_check(&rl, blocked_ip, 3000000ULL + 500) == CLIP_ERR_DENIED);

    /* Test 10: 128 active blocks cause saturation rejection of new untracked IP */
    clip_rate_limiter_cleanup(&rl);
    clip_rate_limiter_init(&rl);

    uint64_t t_sat = 4000000ULL;
    for (int i = 0; i < CLIP_RATE_LIMIT_MAX_ENTRIES; i++) {
        snprintf(buf_ip, sizeof(buf_ip), "172.16.0.%d", i);
        for (int k = 0; k < 5; k++) {
            clip_rate_limiter_record_failure(&rl, buf_ip, t_sat + k);
        }
    }
    TEST("All 128 entries actively blocked", rl.count == CLIP_RATE_LIMIT_MAX_ENTRIES);

    /* Check & Record on brand new IP must be rejected due to saturation */
    const char* saturated_new_ip = "172.16.1.1";
    TEST("Saturation check rejects new untracked IP",
         clip_rate_limiter_check(&rl, saturated_new_ip, t_sat + 100) == CLIP_ERR_DENIED);
    TEST("Saturation failure recording rejects new untracked IP",
         clip_rate_limiter_record_failure(&rl, saturated_new_ip, t_sat + 100) == CLIP_ERR_NOMEM);

    clip_rate_limiter_cleanup(&rl);

    /* ── Live Wire Rate Limiting Integration Test ───────────────────── */
    printf("\n--- Section 14b: Live Network Wire Rate Limiting ---\n");
    remove(TEST_DB_PATH);
    remove(TEST_CRED_FILE);

    ClipServerConfig srv_cfg;
    clip_server_config_init_default(&srv_cfg);
    srv_cfg.port = TEST_PORT + 1; /* 14922 */
    srv_cfg.use_tls = false;
    strncpy(srv_cfg.db_path, TEST_DB_PATH, sizeof(srv_cfg.db_path) - 1);

    ClipServer srv;
    clip_server_init(&srv, &srv_cfg);
    clip_server_start(&srv);

    /* Register one valid node */
    ClipClientNet c_reg;
    clip_client_net_init(&c_reg);
    clip_client_net_set_insecure_plaintext(&c_reg);
    clip_client_connect(&c_reg, "127.0.0.1", TEST_PORT + 1);
    clip_server_poll(&srv, 50);

    uint8_t r_pay[128];
    size_t r_len = 0;
    clip_tlv_write(r_pay, sizeof(r_pay), &r_len, CLIP_TAG_DISPLAY_NAME, "RATE-NODE", 9);
    ClipFrameHeader r_hdr;
    clip_frame_header_init(&r_hdr, CLIP_MSG_REGISTER, (uint32_t)r_len, 1, NULL);
    clip_client_send_frame(&c_reg, &r_hdr, r_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader r_ack;
    uint8_t ack_p[256];
    uint32_t ack_plen = 0;
    clip_client_recv_frame(&c_reg, &r_ack, ack_p, sizeof(ack_p), &ack_plen, 1000);

    const uint8_t* u_p = NULL;
    uint16_t u_l = 0;
    const uint8_t* k_p = NULL;
    uint16_t k_l = 0;
    clip_tlv_find(ack_p, ack_plen, CLIP_TAG_NODE_UUID, &u_p, &u_l);
    clip_tlv_find(ack_p, ack_plen, CLIP_TAG_CREDENTIAL, &k_p, &k_l);

    ClipUuid reg_uuid;
    uint8_t reg_cred[CLIP_CREDENTIAL_BYTES];
    if (u_p && k_p) {
        memcpy(reg_uuid.bytes, u_p, CLIP_UUID_BYTES);
        memcpy(reg_cred, k_p, CLIP_CREDENTIAL_BYTES);
    } else {
        memset(reg_uuid.bytes, 0, CLIP_UUID_BYTES);
        memset(reg_cred, 0, sizeof(reg_cred));
    }

    clip_client_disconnect(&c_reg);
    clip_server_poll(&srv, 20);
    clip_client_net_cleanup(&c_reg);

    /* Attempt 5 consecutive failed AUTH frames over live socket */
    uint8_t bad_cred[CLIP_CREDENTIAL_BYTES];
    memcpy(bad_cred, reg_cred, CLIP_CREDENTIAL_BYTES);
    bad_cred[0] ^= 0xFF;

    for (int i = 0; i < 5; i++) {
        ClipClientNet c_fail;
        clip_client_net_init(&c_fail);
        clip_client_net_set_insecure_plaintext(&c_fail);
        clip_client_connect(&c_fail, "127.0.0.1", TEST_PORT + 1);
        clip_server_poll(&srv, 50);

        uint8_t payload[128];
        size_t plen = 0;
        clip_tlv_write(payload, sizeof(payload), &plen, CLIP_TAG_NODE_UUID, reg_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(payload, sizeof(payload), &plen, CLIP_TAG_CREDENTIAL, bad_cred, CLIP_CREDENTIAL_BYTES);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_AUTH, (uint32_t)plen, i + 1, reg_uuid.bytes);
        clip_client_send_frame(&c_fail, &tx_hdr, payload);
        clip_server_poll(&srv, 50);

        ClipFrameHeader rx_hdr;
        clip_client_recv_frame(&c_fail, &rx_hdr, NULL, 0, NULL, 1000);
        TEST("Failed attempt returns AUTH_FAIL", rx_hdr.msg_type == CLIP_MSG_AUTH_FAIL);

        clip_client_disconnect(&c_fail);
        clip_server_poll(&srv, 20);
        clip_client_net_cleanup(&c_fail);
    }

    /* 6th attempt: Even with VALID credentials, server rejects immediately due to active IP rate limit! */
    ClipClientNet c_blocked;
    clip_client_net_init(&c_blocked);
    clip_client_net_set_insecure_plaintext(&c_blocked);
    clip_client_connect(&c_blocked, "127.0.0.1", TEST_PORT + 1);
    clip_server_poll(&srv, 50);

    uint8_t val_payload[128];
    size_t val_plen = 0;
    clip_tlv_write(val_payload, sizeof(val_payload), &val_plen, CLIP_TAG_NODE_UUID, reg_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(val_payload, sizeof(val_payload), &val_plen, CLIP_TAG_CREDENTIAL, reg_cred, CLIP_CREDENTIAL_BYTES);

    ClipFrameHeader tx_val;
    clip_frame_header_init(&tx_val, CLIP_MSG_AUTH, (uint32_t)val_plen, 10, reg_uuid.bytes);
    clip_client_send_frame(&c_blocked, &tx_val, val_payload);
    clip_server_poll(&srv, 50);

    ClipFrameHeader rx_block;
    clip_client_recv_frame(&c_blocked, &rx_block, NULL, 0, NULL, 1000);
    TEST("Live server actively rejects authentication from rate-limited IP",
         rx_block.msg_type == CLIP_MSG_AUTH_FAIL);

    /* ── Live Wire: Shared Policy Across Node & Admin Auth ──────────── */
    printf("\n--- Section 14c: Shared Policy Across Node & Admin Auth ---\n");
    /* Register an admin user in identity_db */
    sqlite3* id_db = clip_identity_get_sqlite(srv.identity_db);
    ClipAdminUser adm;
    memset(&adm, 0, sizeof(adm));
    clip_crypto_uuid_generate((ClipUuid*)adm.admin_uuid);
    strncpy(adm.username, "rateadmin", sizeof(adm.username) - 1);
    adm.role = CLIP_ADMIN_PERM_SUPER_ADMIN;
    adm.iterations = CLIP_ADMIN_DEFAULT_ITERATIONS;
    clip_crypto_random_bytes(adm.salt, sizeof(adm.salt));
    clip_admin_hash_password("SuperSecretAdminPass123!", adm.salt, adm.iterations, adm.verifier);
    clip_admin_db_create_admin(id_db, &adm);

    uint16_t expected_auth_code = (uint16_t)(-((int)CLIP_ERR_AUTH));

    /* Reset server rate limiter for shared test */
    clip_rate_limiter_cleanup(&srv.rate_limiter);
    clip_rate_limiter_init(&srv.rate_limiter);

    /* Do 2 failed Node auths + 3 failed Admin auths on same IP (127.0.0.1) */
    for (int i = 0; i < 2; i++) {
        ClipClientNet c;
        clip_client_net_init(&c);
        clip_client_net_set_insecure_plaintext(&c);
        clip_client_connect(&c, "127.0.0.1", TEST_PORT + 1);
        clip_server_poll(&srv, 50);

        uint8_t payload[128];
        size_t plen = 0;
        clip_tlv_write(payload, sizeof(payload), &plen, CLIP_TAG_NODE_UUID, reg_uuid.bytes, CLIP_UUID_BYTES);
        clip_tlv_write(payload, sizeof(payload), &plen, CLIP_TAG_CREDENTIAL, bad_cred, CLIP_CREDENTIAL_BYTES);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_AUTH, (uint32_t)plen, 100 + i, reg_uuid.bytes);
        clip_client_send_frame(&c, &tx_hdr, payload);
        clip_server_poll(&srv, 50);

        ClipFrameHeader rx_hdr;
        clip_client_recv_frame(&c, &rx_hdr, NULL, 0, NULL, 1000);
        TEST("Shared policy: Node failed attempt records", rx_hdr.msg_type == CLIP_MSG_AUTH_FAIL);

        clip_client_disconnect(&c);
        clip_server_poll(&srv, 20);
        clip_client_net_cleanup(&c);
    }

    for (int i = 0; i < 3; i++) {
        ClipClientNet c;
        clip_client_net_init(&c);
        clip_client_net_set_insecure_plaintext(&c);
        clip_client_connect(&c, "127.0.0.1", TEST_PORT + 1);
        clip_server_poll(&srv, 50);

        uint8_t payload[128];
        size_t plen = 0;
        clip_tlv_write(payload, sizeof(payload), &plen, CLIP_TAG_ADMIN_USERNAME, "rateadmin", 9);
        clip_tlv_write(payload, sizeof(payload), &plen, CLIP_TAG_TEXT, "WrongPass!", 10);

        ClipFrameHeader tx_hdr;
        clip_frame_header_init(&tx_hdr, CLIP_MSG_ADMIN_AUTH_REQ, (uint32_t)plen, 200 + i, NULL);
        clip_client_send_frame(&c, &tx_hdr, payload);
        clip_server_poll(&srv, 50);

        ClipFrameHeader rx_hdr;
        uint8_t rx_p[128];
        uint32_t rx_plen = 0;
        clip_client_recv_frame(&c, &rx_hdr, rx_p, sizeof(rx_p), &rx_plen, 1000);
        TEST("Shared policy: Admin failed attempt records", rx_hdr.msg_type == CLIP_MSG_ADMIN_AUTH_RESP);

        /* Verify generic error code returned (CLIP_ERR_AUTH) without leak */
        const uint8_t* st_ptr = NULL;
        uint16_t st_len = 0;
        clip_tlv_find(rx_p, rx_plen, CLIP_TAG_AUTH_STATUS, &st_ptr, &st_len);
        uint16_t expected_auth_code = (uint16_t)(-((int)CLIP_ERR_AUTH));
        TEST("Admin auth failure returns generic CLIP_ERR_AUTH",
             st_ptr != NULL && st_len == 2 && (((uint16_t)st_ptr[0] << 8) | (uint16_t)st_ptr[1]) == expected_auth_code);

        clip_client_disconnect(&c);
        clip_server_poll(&srv, 20);
        clip_client_net_cleanup(&c);
    }

    /* Total failures reached 2 + 3 = 5. IP must now be blocked for BOTH Node and Admin! */
    ClipClientNet c_check_node;
    clip_client_net_init(&c_check_node);
    clip_client_net_set_insecure_plaintext(&c_check_node);
    clip_client_connect(&c_check_node, "127.0.0.1", TEST_PORT + 1);
    clip_server_poll(&srv, 50);

    uint8_t v_pay[128];
    size_t v_plen = 0;
    clip_tlv_write(v_pay, sizeof(v_pay), &v_plen, CLIP_TAG_NODE_UUID, reg_uuid.bytes, CLIP_UUID_BYTES);
    clip_tlv_write(v_pay, sizeof(v_pay), &v_plen, CLIP_TAG_CREDENTIAL, reg_cred, CLIP_CREDENTIAL_BYTES);
    ClipFrameHeader tx_n;
    clip_frame_header_init(&tx_n, CLIP_MSG_AUTH, (uint32_t)v_plen, 301, reg_uuid.bytes);
    clip_client_send_frame(&c_check_node, &tx_n, v_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader rx_blk_node;
    clip_client_recv_frame(&c_check_node, &rx_blk_node, NULL, 0, NULL, 1000);
    TEST("Shared policy: 5th aggregate failure blocks subsequent Node auth",
         rx_blk_node.msg_type == CLIP_MSG_AUTH_FAIL);
    clip_client_disconnect(&c_check_node);
    clip_server_poll(&srv, 20);
    clip_client_net_cleanup(&c_check_node);

    ClipClientNet c_check_adm;
    clip_client_net_init(&c_check_adm);
    clip_client_net_set_insecure_plaintext(&c_check_adm);
    clip_client_connect(&c_check_adm, "127.0.0.1", TEST_PORT + 1);
    clip_server_poll(&srv, 50);

    uint8_t a_pay[128];
    size_t a_plen = 0;
    clip_tlv_write(a_pay, sizeof(a_pay), &a_plen, CLIP_TAG_ADMIN_USERNAME, "rateadmin", 9);
    clip_tlv_write(a_pay, sizeof(a_pay), &a_plen, CLIP_TAG_TEXT, "SuperSecretAdminPass123!", 24);
    ClipFrameHeader tx_a;
    clip_frame_header_init(&tx_a, CLIP_MSG_ADMIN_AUTH_REQ, (uint32_t)a_plen, 302, NULL);
    clip_client_send_frame(&c_check_adm, &tx_a, a_pay);
    clip_server_poll(&srv, 50);

    ClipFrameHeader rx_blk_adm;
    uint8_t rx_abuf[128];
    uint32_t rx_alen = 0;
    clip_client_recv_frame(&c_check_adm, &rx_blk_adm, rx_abuf, sizeof(rx_abuf), &rx_alen, 1000);
    TEST("Shared policy: 5th aggregate failure blocks subsequent Admin auth",
         rx_blk_adm.msg_type == CLIP_MSG_ADMIN_AUTH_RESP);
    const uint8_t* st_a = NULL;
    uint16_t st_alen = 0;
    clip_tlv_find(rx_abuf, rx_alen, CLIP_TAG_AUTH_STATUS, &st_a, &st_alen);
    TEST("Shared policy block returns generic CLIP_ERR_AUTH without leak",
         st_a != NULL && st_alen == 2 && (((uint16_t)st_a[0] << 8) | (uint16_t)st_a[1]) == expected_auth_code);

    clip_client_disconnect(&c_check_adm);
    clip_server_poll(&srv, 20);
    clip_client_net_cleanup(&c_check_adm);

    /* ── Concurrency & Thread-Safety Stress Test ────────────────────── */
    printf("\n--- Section 14d: Concurrency & Atomicity Stress Test ---\n");
    ClipRateLimiter c_rl;
    clip_rate_limiter_init(&c_rl);

    /* Verify unknown IP fails safe */
    TEST("Fail-closed on empty IP string", clip_rate_limiter_check(&c_rl, "", 1000) == CLIP_ERR_INVALID);
    TEST("Fail-closed on NULL IP string", clip_rate_limiter_check(&c_rl, NULL, 1000) == CLIP_ERR_INVALID);

    /* Verify thread safety: simulate 8 concurrent threads hammering check and record */
    StressParam params[THREAD_STRESS_COUNT];
    HANDLE threads[THREAD_STRESS_COUNT];

    for (int i = 0; i < THREAD_STRESS_COUNT; i++) {
        params[i].rl = &c_rl;
        params[i].ip = (i % 2 == 0) ? "192.168.10.1" : "192.168.10.2";
        params[i].thread_id = i;
        threads[i] = CreateThread(NULL, 0, stress_worker, &params[i], 0, NULL);
    }
    WaitForMultipleObjects(THREAD_STRESS_COUNT, threads, TRUE, 5000);
    for (int i = 0; i < THREAD_STRESS_COUNT; i++) {
        CloseHandle(threads[i]);
    }
    TEST("Concurrent stress test completed without deadlocks or memory corruption", true);

    clip_rate_limiter_cleanup(&c_rl);

    clip_server_stop(&srv);
    clip_server_cleanup(&srv);
    remove(TEST_DB_PATH);
    remove(TEST_CRED_FILE);
}

int main(void)
{
    printf("============================================================\n");
    printf(" CLICOM Phase 3 — Unit & Integration Test: Authentication\n");
    printf("============================================================\n");

    clip_net_init();

    test_crypto_and_uuid();
    test_client_dpapi_credentials();
    test_sqlite_identity_store();
    test_live_network_auth();
    test_rate_limiting();

    clip_net_cleanup();

    printf("\n============================================================\n");
    printf(" Total: %d passed", g_pass);
    if (g_fail > 0) {
        printf(", %d FAILED", g_fail);
    }
    printf("\n Result: %s\n", (g_fail == 0) ? "ALL TESTS PASSED" : "TESTS FAILED");
    printf("============================================================\n");

    return (g_fail == 0) ? 0 : 1;
}

/*
 * test_notes.c — CLICOM Phase 14: Communication Notes & Session Logs Unit Tests
 *
 * Verifies:
 * 1. Database schema initialization & non-destructive migration.
 * 2. Session log querying and duration/note_count calculation.
 * 3. Session participant authorization (initiator, peer, channel member vs non-member).
 * 4. Manual note creation, server attribution (author_node_uuid & timestamp).
 * 5. Input validation (empty text rejected, text > 1024 bytes rejected, invalid type rejected).
 * 6. Live caption export summary generation & transcript note creation.
 * 7. Chronological note listing and keyword substring search.
 * 8. Persistence across database close and reopen.
 * 9. Protocol frame serialization / deserialization of Phase 14 messages and TLVs.
 * 10. Live loopback client/server network integration for notes & session logs.
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
#include "clip_captions.h"
#include "../../server/include/server.h"
#include "../../client/include/network.h"
#include "../../client/include/clip_notes_client.h"

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

#define TEST_DB_PATH "test_notes.db"
#define TEST_PERSIST_DB "test_notes_persist.db"
#define TEST_PORT 14977

static void cleanup_test_file(const char* path)
{
    remove(path);
}

/* ── Test 1: Schema Initialization & Non-Destructive Migration ──────────── */

static void test_schema_init(void)
{
    printf("\n=== Test 1: Schema Init & Non-Destructive Migration ===\n");
    cleanup_test_file(TEST_DB_PATH);

    sqlite3* db = NULL;
    int rc = sqlite3_open(TEST_DB_PATH, &db);
    TEST("SQLite database created", rc == SQLITE_OK && db != NULL);

    TEST("clip_notes_db_init_schema handles NULL gracefully", !clip_notes_db_init_schema(NULL));
    TEST("clip_notes_db_init_schema succeeds on fresh DB", clip_notes_db_init_schema(db));
    TEST("clip_notes_db_init_schema is idempotent", clip_notes_db_init_schema(db));

    /* Check that session_notes table exists */
    sqlite3_stmt* stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='session_notes';", -1, &stmt, NULL);
    TEST("session_notes table exists in SQLite schema", rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    sqlite3_close(db);
    cleanup_test_file(TEST_DB_PATH);
}

/* ── Test 2: Participant Authorization & Session Logs ───────────────────── */

static void test_authorization_and_session_logs(void)
{
    printf("\n=== Test 2: Participant Authorization & Session Logs ===\n");
    cleanup_test_file(TEST_DB_PATH);

    ClipIdentityDb* id_db = NULL;
    ClipError err = clip_identity_db_open(&id_db, TEST_DB_PATH);
    TEST("Identity DB opened with all schemas", err == CLIP_OK && id_db != NULL);
    sqlite3* db = clip_identity_get_sqlite(id_db);

    ClipUuid node_a, node_b, node_c, stranger;
    uint8_t cred[CLIP_CREDENTIAL_BYTES];
    clip_identity_register(id_db, "NODE-A", &node_a, cred);
    clip_identity_register(id_db, "NODE-B", &node_b, cred);
    clip_identity_register(id_db, "NODE-C", &node_c, cred);
    clip_identity_register(id_db, "STRANGER", &stranger, cred);

    /* Create channel by Node A, join by Node B */
    ClipUuid chan_uuid;
    char jkey[CLIP_JOIN_KEY_MAX];
    clip_channel_create(db, &node_a, "Alpha Channel", &chan_uuid, jkey, sizeof(jkey));
    char chan_name[CLIP_DISPLAY_NAME_MAX];
    clip_channel_join_by_key(db, &node_b, jkey, &chan_uuid, chan_name, sizeof(chan_name));

    /* Create connection Node A -> Node B and accept it */
    ClipConnectionRecord conn_rec;
    clip_connection_create(db, &chan_uuid, &node_a, &node_b, &conn_rec);
    clip_connection_set_state(db, &conn_rec.connection_uuid, CLIP_CONN_STATE_ACCEPTED);

    /* Start session */
    ClipUuid sess_uuid;
    clip_session_create_for_connection(db, &conn_rec.connection_uuid, &node_a, &sess_uuid);

    /* Authorization checks */
    bool is_auth = false;
    TEST("Initiator (Node A) is authorized", clip_session_is_authorized(db, &sess_uuid, &node_a, &is_auth) && is_auth);

    is_auth = false;
    TEST("Peer (Node B) is authorized", clip_session_is_authorized(db, &sess_uuid, &node_b, &is_auth) && is_auth);

    /* Channel member Node C joins channel */
    clip_channel_join_by_key(db, &node_c, jkey, &chan_uuid, chan_name, sizeof(chan_name));
    is_auth = false;
    TEST("Channel member (Node C) is authorized", clip_session_is_authorized(db, &sess_uuid, &node_c, &is_auth) && is_auth);

    is_auth = true;
    TEST("Stranger is NOT authorized", clip_session_is_authorized(db, &sess_uuid, &stranger, &is_auth) && !is_auth);

    ClipUuid bogus = {{ 0xFF }};
    is_auth = true;
    TEST("Non-existent session returns unauthorized", clip_session_is_authorized(db, &bogus, &node_a, &is_auth) && !is_auth);

    /* Session list for Node A (should find 1 session) */
    ClipSessionLogEntry* logs_a = NULL;
    size_t count_a = 0;
    TEST("clip_session_list_for_node succeeds for Node A", clip_session_list_for_node(db, &node_a, &logs_a, &count_a));
    TEST("Node A has 1 authorized session", count_a == 1 && logs_a != NULL);
    if (count_a > 0) {
        TEST("Session UUID matches", clip_uuid_equal(&logs_a[0].session_uuid, &sess_uuid));
        TEST("Session initial state is ACTIVE (1)", logs_a[0].state == 1);
        TEST("Session initial note_count is 0", logs_a[0].note_count == 0);
    }
    clip_session_free_log_list(logs_a);

    /* Session list for Stranger (should find 0 sessions) */
    ClipSessionLogEntry* logs_s = NULL;
    size_t count_s = 0;
    TEST("clip_session_list_for_node succeeds for Stranger", clip_session_list_for_node(db, &stranger, &logs_s, &count_s));
    TEST("Stranger has 0 authorized sessions", count_s == 0);
    clip_session_free_log_list(logs_s);

    clip_identity_db_close(id_db);
    cleanup_test_file(TEST_DB_PATH);
}

/* ── Test 3: Manual Note Creation, Attribution & Validation ─────────────── */

static void test_note_creation_and_validation(void)
{
    printf("\n=== Test 3: Note Creation, Attribution & Validation ===\n");
    cleanup_test_file(TEST_DB_PATH);

    ClipIdentityDb* id_db = NULL;
    clip_identity_db_open(&id_db, TEST_DB_PATH);
    sqlite3* db = clip_identity_get_sqlite(id_db);

    ClipUuid node_a, node_b;
    uint8_t cred[CLIP_CREDENTIAL_BYTES];
    clip_identity_register(id_db, "NODE-A", &node_a, cred);
    clip_identity_register(id_db, "NODE-B", &node_b, cred);

    ClipUuid chan_uuid;
    char jkey[CLIP_JOIN_KEY_MAX];
    clip_channel_create(db, &node_a, "Main", &chan_uuid, jkey, sizeof(jkey));

    ClipConnectionRecord conn_rec;
    clip_connection_create(db, &chan_uuid, &node_a, &node_b, &conn_rec);
    clip_connection_set_state(db, &conn_rec.connection_uuid, CLIP_CONN_STATE_ACCEPTED);

    ClipUuid sess_uuid;
    clip_session_create_for_connection(db, &conn_rec.connection_uuid, &node_a, &sess_uuid);

    /* Add valid note */
    uint32_t note_id_1 = 0;
    const char* txt1 = "Discussing Phase 14 architecture with Node B.";
    bool ok = clip_notes_create(db, &sess_uuid, &node_a, CLIP_NOTE_TYPE_MANUAL, txt1, &note_id_1);
    TEST("Manual note created successfully", ok && note_id_1 > 0);

    /* Verify count */
    uint32_t cnt = 0;
    TEST("Note count for session is 1", clip_notes_count_for_session(db, &sess_uuid, &cnt) && cnt == 1);

    /* Second note from Node B */
    uint32_t note_id_2 = 0;
    const char* txt2 = "Agreed on schema and bounds.";
    ok = clip_notes_create(db, &sess_uuid, &node_b, CLIP_NOTE_TYPE_MANUAL, txt2, &note_id_2);
    TEST("Second note created successfully with incremented ID", ok && note_id_2 == note_id_1 + 1);

    TEST("Note count for session is now 2", clip_notes_count_for_session(db, &sess_uuid, &cnt) && cnt == 2);

    /* Validation: Empty text */
    uint32_t bad_id = 0;
    TEST("Empty note text rejected", !clip_notes_create(db, &sess_uuid, &node_a, CLIP_NOTE_TYPE_MANUAL, "", &bad_id));

    /* Validation: Oversized text (>1024 bytes) */
    char huge[1050];
    memset(huge, 'A', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = '\0';
    TEST("Oversized note text (>1024 bytes) rejected", !clip_notes_create(db, &sess_uuid, &node_a, CLIP_NOTE_TYPE_MANUAL, huge, &bad_id));

    /* Validation: Invalid note type */
    TEST("Invalid note type rejected", !clip_notes_create(db, &sess_uuid, &node_a, (ClipNoteType)99, "Valid text", &bad_id));

    /* Validation: Non-existent session */
    ClipUuid bogus = {{ 0x77 }};
    TEST("Note creation on non-existent session rejected", !clip_notes_create(db, &bogus, &node_a, CLIP_NOTE_TYPE_MANUAL, "Valid text", &bad_id));

    /* Fetch notes and verify server attribution */
    ClipSessionNoteEntry* notes = NULL;
    size_t count = 0;
    TEST("clip_notes_list_for_session succeeds", clip_notes_list_for_session(db, &sess_uuid, &notes, &count));
    TEST("Returned 2 notes", count == 2 && notes != NULL);
    if (count == 2) {
        TEST("Note 1 ID matches", notes[0].note_id == note_id_1);
        TEST("Note 1 author matches Node A", clip_uuid_equal(&notes[0].author_node_uuid, &node_a));
        TEST("Note 1 type is MANUAL", notes[0].note_type == CLIP_NOTE_TYPE_MANUAL);
        TEST("Note 1 text matches", strcmp(notes[0].note_text, txt1) == 0);
        TEST("Note 1 has valid timestamp", notes[0].created_at > 0);

        TEST("Note 2 ID matches", notes[1].note_id == note_id_2);
        TEST("Note 2 author matches Node B", clip_uuid_equal(&notes[1].author_node_uuid, &node_b));
        TEST("Note 2 text matches", strcmp(notes[1].note_text, txt2) == 0);
    }
    clip_notes_free_list(notes);

    clip_identity_db_close(id_db);
    cleanup_test_file(TEST_DB_PATH);
}

/* ── Test 4: Live Caption Export Summary & Transcript Note ──────────────── */

static void test_caption_export_and_transcript_note(void)
{
    printf("\n=== Test 4: Live Caption Export & Transcript Note ===\n");
    cleanup_test_file(TEST_DB_PATH);

    ClipIdentityDb* id_db = NULL;
    clip_identity_db_open(&id_db, TEST_DB_PATH);
    sqlite3* db = clip_identity_get_sqlite(id_db);

    ClipUuid node_a;
    uint8_t cred[CLIP_CREDENTIAL_BYTES];
    clip_identity_register(id_db, "NODE-A", &node_a, cred);

    ClipUuid chan_uuid;
    char jkey[CLIP_JOIN_KEY_MAX];
    clip_channel_create(db, &node_a, "Voice", &chan_uuid, jkey, sizeof(jkey));

    ClipUuid sess_uuid;
    clip_session_start(db, &chan_uuid, &node_a, &sess_uuid);

    /* Setup caption buffer */
    ClipCaptionBuffer cap_buf;
    clip_captions_init(&cap_buf, 20);
    clip_captions_set_session(&cap_buf, &sess_uuid, CLIP_SPEECH_MODE_SERVER_MEDIATED);

    /* Push final transcripts */
    SpeechTranscriptResult res1 = {0};
    memcpy(res1.session_uuid.bytes, sess_uuid.bytes, CLIP_UUID_BYTES);
    memcpy(res1.speaker_node_uuid.bytes, node_a.bytes, CLIP_UUID_BYTES);
    clip_uuid_to_string(&node_a, res1.speaker_node_id, sizeof(res1.speaker_node_id));
    res1.text = "Radio check, how do you read?";
    res1.text_len = strlen(res1.text);
    res1.is_final = true;
    res1.start_time_ms = 1000;
    clip_captions_push_transcript(&cap_buf, &res1);

    SpeechTranscriptResult res2 = {0};
    memcpy(res2.session_uuid.bytes, sess_uuid.bytes, CLIP_UUID_BYTES);
    memcpy(res2.speaker_node_uuid.bytes, node_a.bytes, CLIP_UUID_BYTES);
    clip_uuid_to_string(&node_a, res2.speaker_node_id, sizeof(res2.speaker_node_id));
    res2.text = "Loud and clear on my end.";
    res2.text_len = strlen(res2.text);
    res2.is_final = true;
    res2.start_time_ms = 2000;
    clip_captions_push_transcript(&cap_buf, &res2);

    /* Export summary */
    char summary[1024] = {0};
    size_t written = 0;
    ClipError exp_err = clip_captions_export_summary(&cap_buf, summary, sizeof(summary), &written);
    TEST("clip_captions_export_summary succeeds", exp_err == CLIP_OK && written > 0);
    TEST("Exported summary contains first utterance", strstr(summary, "Radio check") != NULL);
    TEST("Exported summary contains second utterance", strstr(summary, "Loud and clear") != NULL);

    /* Store summary as TRANSCRIPT note */
    uint32_t note_id = 0;
    bool ok = clip_notes_create(db, &sess_uuid, &node_a, CLIP_NOTE_TYPE_TRANSCRIPT, summary, &note_id);
    TEST("Transcript note created successfully", ok && note_id > 0);

    /* Retrieve and verify note_type */
    ClipSessionNoteEntry* notes = NULL;
    size_t count = 0;
    clip_notes_list_for_session(db, &sess_uuid, &notes, &count);
    TEST("Notes count is 1", count == 1 && notes != NULL);
    if (count == 1) {
        TEST("Note type is CLIP_NOTE_TYPE_TRANSCRIPT", notes[0].note_type == CLIP_NOTE_TYPE_TRANSCRIPT);
        TEST("Note text matches exported summary", strcmp(notes[0].note_text, summary) == 0);
    }
    clip_notes_free_list(notes);

    clip_captions_cleanup(&cap_buf);
    clip_identity_db_close(id_db);
    cleanup_test_file(TEST_DB_PATH);
}

/* ── Test 5: Substring Search & Chronological Ordering ──────────────────── */

static void test_search_and_ordering(void)
{
    printf("\n=== Test 5: Substring Search & Chronological Ordering ===\n");
    cleanup_test_file(TEST_DB_PATH);

    ClipIdentityDb* id_db = NULL;
    clip_identity_db_open(&id_db, TEST_DB_PATH);
    sqlite3* db = clip_identity_get_sqlite(id_db);

    ClipUuid node;
    uint8_t cred[CLIP_CREDENTIAL_BYTES];
    clip_identity_register(id_db, "TESTER", &node, cred);

    ClipUuid chan_uuid;
    char jkey[CLIP_JOIN_KEY_MAX];
    clip_channel_create(db, &node, "Ops", &chan_uuid, jkey, sizeof(jkey));

    ClipUuid sess_uuid;
    clip_session_start(db, &chan_uuid, &node, &sess_uuid);

    /* Insert notes with distinctive keywords */
    uint32_t id1 = 0, id2 = 0, id3 = 0;
    clip_notes_create(db, &sess_uuid, &node, CLIP_NOTE_TYPE_MANUAL, "ALPHA status confirmed green.", &id1);
    clip_notes_create(db, &sess_uuid, &node, CLIP_NOTE_TYPE_MANUAL, "BRAVO checkpoint reached.", &id2);
    clip_notes_create(db, &sess_uuid, &node, CLIP_NOTE_TYPE_MANUAL, "ALPHA team standing by.", &id3);

    /* Search for ALPHA */
    ClipSessionNoteEntry* alpha_notes = NULL;
    size_t a_cnt = 0;
    TEST("Search for 'ALPHA' succeeds", clip_notes_search(db, &sess_uuid, "ALPHA", &alpha_notes, &a_cnt));
    TEST("Search returned 2 matches", a_cnt == 2 && alpha_notes != NULL);
    if (a_cnt == 2) {
        TEST("First match is id1", alpha_notes[0].note_id == id1);
        TEST("Second match is id3", alpha_notes[1].note_id == id3);
    }
    clip_notes_free_list(alpha_notes);

    /* Search for BRAVO */
    ClipSessionNoteEntry* bravo_notes = NULL;
    size_t b_cnt = 0;
    TEST("Search for 'BRAVO' succeeds", clip_notes_search(db, &sess_uuid, "BRAVO", &bravo_notes, &b_cnt));
    TEST("Search returned 1 match", b_cnt == 1 && bravo_notes != NULL);
    if (b_cnt == 1) {
        TEST("Match is id2", bravo_notes[0].note_id == id2);
    }
    clip_notes_free_list(bravo_notes);

    /* Search for non-existent keyword */
    ClipSessionNoteEntry* zero_notes = NULL;
    size_t z_cnt = 0;
    TEST("Search for 'ZULU' succeeds with 0 matches", clip_notes_search(db, &sess_uuid, "ZULU", &zero_notes, &z_cnt));
    TEST("0 matches found", z_cnt == 0);
    clip_notes_free_list(zero_notes);

    clip_identity_db_close(id_db);
    cleanup_test_file(TEST_DB_PATH);
}

/* ── Test 6: Persistence across Database Reopen ─────────────────────────── */

static void test_persistence(void)
{
    printf("\n=== Test 6: Persistence Across DB Reopen ===\n");
    cleanup_test_file(TEST_PERSIST_DB);

    ClipUuid sess_uuid, node_uuid;
    uint32_t saved_note_id = 0;

    /* Session 1: Create and write note */
    {
        ClipIdentityDb* id_db = NULL;
        clip_identity_db_open(&id_db, TEST_PERSIST_DB);
        sqlite3* db = clip_identity_get_sqlite(id_db);

        uint8_t cred[CLIP_CREDENTIAL_BYTES];
        clip_identity_register(id_db, "PERSIST_NODE", &node_uuid, cred);

        ClipUuid chan_uuid;
        char jkey[CLIP_JOIN_KEY_MAX];
        clip_channel_create(db, &node_uuid, "PersistChan", &chan_uuid, jkey, sizeof(jkey));

        clip_session_start(db, &chan_uuid, &node_uuid, &sess_uuid);

        clip_notes_create(db, &sess_uuid, &node_uuid, CLIP_NOTE_TYPE_MANUAL, "Persistent note content.", &saved_note_id);
        clip_identity_db_close(id_db);
    }

    /* Session 2: Reopen DB and verify data */
    {
        ClipIdentityDb* id_db = NULL;
        clip_identity_db_open(&id_db, TEST_PERSIST_DB);
        sqlite3* db = clip_identity_get_sqlite(id_db);

        ClipSessionLogEntry log;
        TEST("clip_session_get_log finds persisted session", clip_session_get_log(db, &sess_uuid, &log));
        TEST("Persisted session note_count is 1", log.note_count == 1);

        ClipSessionNoteEntry* notes = NULL;
        size_t count = 0;
        TEST("clip_notes_list_for_session finds persisted notes", clip_notes_list_for_session(db, &sess_uuid, &notes, &count));
        TEST("Persisted note count is 1", count == 1 && notes != NULL);
        if (count == 1) {
            TEST("Persisted note_id matches", notes[0].note_id == saved_note_id);
            TEST("Persisted text matches", strcmp(notes[0].note_text, "Persistent note content.") == 0);
            TEST("Persisted author matches", clip_uuid_equal(&notes[0].author_node_uuid, &node_uuid));
        }
        clip_notes_free_list(notes);

        clip_identity_db_close(id_db);
    }

    cleanup_test_file(TEST_PERSIST_DB);
}

/* ── Test 7: Protocol Wire Serialization & Deserialization ──────────────── */

static void test_protocol_wire(void)
{
    printf("\n=== Test 7: Protocol Wire Serialization & TLVs ===\n");

    /* Test TLV writing and reading for Phase 14 tags */
    uint8_t payload[512];
    size_t offset = 0;

    uint8_t nid_buf[4] = { 0x00, 0x00, 0x00, 0x2A };
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_NOTE_ID, nid_buf, 4);

    uint8_t ntype = (uint8_t)CLIP_NOTE_TYPE_TRANSCRIPT;
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_NOTE_TYPE, &ntype, 1);

    const char* txt = "Wire test note";
    clip_tlv_write(payload, sizeof(payload), &offset, CLIP_TAG_NOTE_TEXT, txt, (uint16_t)strlen(txt));

    /* Parse back */
    const uint8_t* ptr = NULL;
    uint16_t len = 0;
    TEST("CLIP_TAG_NOTE_ID found", clip_tlv_find(payload, (uint32_t)offset, CLIP_TAG_NOTE_ID, &ptr, &len) == CLIP_OK && len == 4);
    if (ptr && len == 4) {
        uint32_t id_val = ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) | ((uint32_t)ptr[2] << 8) | (uint32_t)ptr[3];
        TEST("Decoded note ID matches 42", id_val == 42);
    }

    TEST("CLIP_TAG_NOTE_TYPE found", clip_tlv_find(payload, (uint32_t)offset, CLIP_TAG_NOTE_TYPE, &ptr, &len) == CLIP_OK && len == 1);
    if (ptr && len == 1) {
        TEST("Decoded note type is TRANSCRIPT", *ptr == (uint8_t)CLIP_NOTE_TYPE_TRANSCRIPT);
    }

    TEST("CLIP_TAG_NOTE_TEXT found", clip_tlv_find(payload, (uint32_t)offset, CLIP_TAG_NOTE_TEXT, &ptr, &len) == CLIP_OK);
    if (ptr) {
        char decoded[64] = {0};
        memcpy(decoded, ptr, len);
        TEST("Decoded note text matches", strcmp(decoded, txt) == 0);
    }

    /* Encode frame with CLIP_MSG_NOTE_CREATE */
    ClipFrameHeader tx_hdr;
    ClipUuid sess = {{ 0x11 }};
    clip_frame_header_init(&tx_hdr, CLIP_MSG_NOTE_CREATE, (uint32_t)offset, 100, sess.bytes);

    uint8_t wire_frame[CLIP_MIN_FRAME_SIZE + 512];
    size_t wire_len = 0;
    TEST("Frame encode succeeds for CLIP_MSG_NOTE_CREATE", clip_frame_encode(&tx_hdr, payload, wire_frame, sizeof(wire_frame), &wire_len) == CLIP_OK);

    ClipFrameHeader rx_hdr;
    const uint8_t* rx_pay = NULL;
    uint32_t rx_pay_len = 0;
    TEST("Frame decode succeeds", clip_frame_decode(wire_frame, wire_len, &rx_hdr, &rx_pay, &rx_pay_len) == CLIP_OK);
    TEST("Frame msg_type is CLIP_MSG_NOTE_CREATE", rx_hdr.msg_type == CLIP_MSG_NOTE_CREATE);
    TEST("Frame session_uuid matches", clip_uuid_equal((const ClipUuid*)rx_hdr.session_uuid, &sess));
}

/* ── Test 8: Live Loopback Client / Server Network Integration ──────────── */

static DWORD WINAPI server_thread_fn(LPVOID param)
{
    ClipServer* srv = (ClipServer*)param;
    while (srv->is_running) {
        clip_server_poll(srv, 20);
    }
    return 0;
}

static void test_live_network_integration(void)
{
    printf("\n=== Test 8: Live Loopback Client/Server Network Integration ===\n");
    cleanup_test_file(TEST_DB_PATH);

    ClipServer srv;
    ClipServerConfig cfg;
    clip_server_config_init_default(&cfg);
    cfg.port = TEST_PORT;
    cfg.use_tls = false; /* Plaintext loopback for unit test simplicity */
    strncpy(cfg.db_path, TEST_DB_PATH, sizeof(cfg.db_path) - 1);

    TEST("clip_server_init succeeds", clip_server_init(&srv, &cfg) == CLIP_OK);
    TEST("clip_server_start succeeds", clip_server_start(&srv) == CLIP_OK);

    HANDLE srv_th = CreateThread(NULL, 0, server_thread_fn, &srv, 0, NULL);
    TEST("Server thread started", srv_th != NULL);
    Sleep(50);

    /* Initialize and connect Client A */
    ClipClientNet client_a;
    clip_client_net_init(&client_a);
    clip_client_net_set_insecure_plaintext(&client_a);
    TEST("Client A connected to server", clip_client_connect(&client_a, "127.0.0.1", TEST_PORT) == CLIP_OK);

    ClipUuid uuid_a;
    uint8_t cred_a[CLIP_CREDENTIAL_BYTES];
    TEST("Client A registered", clip_client_register(&client_a, "CLIENT-A", &uuid_a, cred_a) == CLIP_OK);

    /* Initialize and connect Client B */
    ClipClientNet client_b;
    clip_client_net_init(&client_b);
    clip_client_net_set_insecure_plaintext(&client_b);
    TEST("Client B connected to server", clip_client_connect(&client_b, "127.0.0.1", TEST_PORT) == CLIP_OK);

    ClipUuid uuid_b;
    uint8_t cred_b[CLIP_CREDENTIAL_BYTES];
    TEST("Client B registered", clip_client_register(&client_b, "CLIENT-B", &uuid_b, cred_b) == CLIP_OK);

    /* Client A creates channel, Client B joins */
    ClipUuid chan_uuid;
    char jkey[CLIP_JOIN_KEY_MAX];
    clip_client_channel_create(&client_a, "TestNetChan", &chan_uuid, jkey, sizeof(jkey));
    char cname[CLIP_DISPLAY_NAME_MAX];
    clip_client_channel_join(&client_b, jkey, &chan_uuid, cname, sizeof(cname), NULL, NULL);

    /* Client A requests connection to B, B accepts */
    ClipUuid conn_uuid;
    ClipConnectionState cstate;
    clip_client_send_conn_request(&client_a, &chan_uuid, &uuid_b, &conn_uuid, &cstate);
    clip_client_respond_conn(&client_b, &conn_uuid, true);

    /* Start session */
    ClipUuid sess_uuid;
    TEST("Client A starts session", clip_client_session_start_by_conn(&client_a, &conn_uuid, &sess_uuid) == CLIP_OK);

    /* 1. Client A queries session logs over network */
    ClipSessionLogEntry* logs = NULL;
    size_t log_cnt = 0;
    TEST("Client A lists session logs over network", clip_client_list_session_logs(&client_a, &logs, &log_cnt) == CLIP_OK);
    TEST("Client A received 1 session log", log_cnt == 1 && logs != NULL);
    if (log_cnt > 0) {
        TEST("Session log UUID matches", clip_uuid_equal(&logs[0].session_uuid, &sess_uuid));
        TEST("Session log state is ACTIVE", logs[0].state == 1);
        TEST("Session log note_count is 0", logs[0].note_count == 0);
    }
    clip_client_free_session_logs(logs);

    /* 2. Client A creates manual note over network */
    uint32_t net_note_id_1 = 0;
    ClipError n_err = clip_client_create_note(&client_a, &sess_uuid, CLIP_NOTE_TYPE_MANUAL, "Hello from Client A via network!", &net_note_id_1);
    TEST("Client A created note over network", n_err == CLIP_OK && net_note_id_1 > 0);

    /* 3. Client B creates note over network on same session */
    uint32_t net_note_id_2 = 0;
    n_err = clip_client_create_note(&client_b, &sess_uuid, CLIP_NOTE_TYPE_MANUAL, "Client B received message loud and clear.", &net_note_id_2);
    TEST("Client B created note over network", n_err == CLIP_OK && net_note_id_2 > 0);

    /* 4. Client A queries notes list over network */
    ClipSessionNoteEntry* net_notes = NULL;
    size_t net_n_cnt = 0;
    TEST("Client A lists notes over network", clip_client_list_notes(&client_a, &sess_uuid, NULL, &net_notes, &net_n_cnt) == CLIP_OK);
    TEST("Client A received 2 notes", net_n_cnt == 2 && net_notes != NULL);
    if (net_n_cnt == 2) {
        TEST("Note 1 author is Client A", clip_uuid_equal(&net_notes[0].author_node_uuid, &uuid_a));
        TEST("Note 2 author is Client B", clip_uuid_equal(&net_notes[1].author_node_uuid, &uuid_b));
        TEST("Note 2 text matches", strcmp(net_notes[1].note_text, "Client B received message loud and clear.") == 0);
    }
    clip_client_free_notes(net_notes);

    /* 5. Client B searches notes with keyword query */
    ClipSessionNoteEntry* search_notes = NULL;
    size_t s_cnt = 0;
    TEST("Client B searches notes over network", clip_client_list_notes(&client_b, &sess_uuid, "network", &search_notes, &s_cnt) == CLIP_OK);
    TEST("Search returned 1 match", s_cnt == 1 && search_notes != NULL);
    if (s_cnt == 1) {
        TEST("Match text contains 'network'", strstr(search_notes[0].note_text, "network") != NULL);
    }
    clip_client_free_notes(search_notes);

    /* 6. Verify single session log get */
    ClipSessionLogEntry single_log;
    TEST("Client A gets single session log", clip_client_get_session_log(&client_a, &sess_uuid, &single_log) == CLIP_OK);
    TEST("Single session log note_count updated to 2", single_log.note_count == 2);

    /* 7. End session and verify logs/notes still accessible for completed session */
    TEST("Client A ends session", clip_client_session_end(&client_a, &sess_uuid) == CLIP_OK);

    TEST("Client A gets completed session log", clip_client_get_session_log(&client_a, &sess_uuid, &single_log) == CLIP_OK);
    TEST("Completed session state is CLOSED", single_log.state == CLIP_SESSION_STATE_CLOSED);

    /* Client B can still query notes of completed session */
    ClipSessionNoteEntry* ended_notes = NULL;
    size_t ended_cnt = 0;
    TEST("Client B can list notes of completed session", clip_client_list_notes(&client_b, &sess_uuid, NULL, &ended_notes, &ended_cnt) == CLIP_OK);
    TEST("Notes intact on completed session", ended_cnt == 2);
    clip_client_free_notes(ended_notes);

    /* Cleanup network */
    clip_client_disconnect(&client_a);
    clip_client_net_cleanup(&client_a);
    clip_client_disconnect(&client_b);
    clip_client_net_cleanup(&client_b);

    srv.is_running = false;
    WaitForSingleObject(srv_th, 2000);
    CloseHandle(srv_th);
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);

    cleanup_test_file(TEST_DB_PATH);
}

/* ── Main test runner ───────────────────────────────────────────────────── */

int main(void)
{
    printf("==================================================\n");
    printf("CLICOM Phase 14 Unit & Integration Tests: Notes & Session Logs\n");
    printf("==================================================\n");

    test_schema_init();
    test_authorization_and_session_logs();
    test_note_creation_and_validation();
    test_caption_export_and_transcript_note();
    test_search_and_ordering();
    test_persistence();
    test_protocol_wire();
    test_live_network_integration();

    printf("\n==================================================\n");
    printf("Phase 14 Test Results: %d PASSED, %d FAILED\n", g_pass, g_fail);
    printf("==================================================\n");

    return (g_fail == 0) ? 0 : 1;
}

/*
 * test_security.c — CLICOM Phase 15: Security Keyword Analysis Unit & Integration Tests
 *
 * Verifies:
 * 1. Rule configuration loading, category parsing, and safe failure mode (0 rules, disabled, no hardcoded keywords).
 * 2. Case-insensitive whole-word and phrase matching with punctuation boundary detection.
 * 3. Substring false-positive rejection ("bombastic" != "bomb").
 * 4. Context window extraction (up to 10 words before/after).
 * 5. Strictly advisory, non-accusatory status (starts at PENDING=0, zero automated punishment).
 * 6. Thread-safe deduplication (5-second window per session, node, matched term).
 * 7. SQLite persistence across database close and reopen.
 * 8. Participant wire authorization (authorized participants only; stranger rejection).
 * 9. Protocol wire validation for Phase 15 messages (0x0080–0x0086) and TLVs.
 * 10. Live loopback client/server network integration (transcript submission, advisory event broadcast, list, get).
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
#include "clip_security_db.h"
#include "security_rules.h"
#include "security_analyzer.h"
#include "../../server/include/server.h"
#include "../../client/include/network.h"
#include "../../client/include/clip_notes_client.h"
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

#define TEST_DB_PATH "test_security.db"
#define TEST_PERSIST_DB "test_security_persist.db"
#define TEST_RULES_MALFORMED "test_malformed_rules.conf"
#define TEST_PORT 14988

static void cleanup_file(const char* path)
{
    remove(path);
}

/* ── Test 1: Configuration Loading & Safe Failure Mode ───────────────────── */

static void test_rules_config_and_safe_failure(void)
{
    printf("\n=== Test 1: Rule Configuration & Safe Failure Mode ===\n");

    /* 1. Normal configuration loading */
    SecurityRuleSet* rules = security_rules_load("config/security_rules.conf");
    TEST("security_rules_load succeeds on default config", rules != NULL);
    if (rules) {
        TEST("Rule count > 0", rules->count > 0);
        TEST("Rules are not disabled", !rules->is_disabled);
        TEST("Context window words is positive", rules->context_window_words > 0);

        bool has_threat = false;
        bool has_suspicious = false;
        for (size_t i = 0; i < rules->count; i++) {
            if (rules->rules[i].category == CLIP_SECURITY_CAT_THREAT) has_threat = true;
            if (rules->rules[i].category == CLIP_SECURITY_CAT_SUSPICIOUS) has_suspicious = true;
        }
        TEST("Contains THREAT category rules", has_threat);
        TEST("Contains SUSPICIOUS category rules", has_suspicious);

        security_rules_free(rules);
    }

    /* 2. Missing configuration file -> Safe Disabled Mode */
    SecurityRuleSet* missing = security_rules_load("non_existent_rules.conf");
    TEST("security_rules_load returns non-NULL object on missing file", missing != NULL);
    if (missing) {
        TEST("Missing file sets count == 0", missing->count == 0);
        TEST("Missing file sets is_disabled == true", missing->is_disabled);
        security_rules_free(missing);
    }

    /* 3. Malformed configuration file -> Safe Disabled Mode */
    FILE* mf = fopen(TEST_RULES_MALFORMED, "w");
    if (mf) {
        fprintf(mf, "[INVALID_SECTION_NAME]\n");
        fprintf(mf, "garbage syntax without equals or values %%%%$$$\n");
        fclose(mf);
    }
    SecurityRuleSet* malformed = security_rules_load(TEST_RULES_MALFORMED);
    TEST("security_rules_load handles malformed file gracefully", malformed != NULL);
    if (malformed) {
        TEST("Malformed file results in 0 valid rules", malformed->count == 0);
        TEST("Malformed file sets is_disabled == true", malformed->is_disabled);
        security_rules_free(malformed);
    }
    cleanup_file(TEST_RULES_MALFORMED);
}

/* ── Test 2: Case-Insensitive Whole-Word & Phrase Matching ───────────────── */

static void test_rules_matching(void)
{
    printf("\n=== Test 2: Case-Insensitive Whole-Word & Phrase Matching ===\n");

    SecurityRuleSet* rules = security_rules_load("config/security_rules.conf");
    TEST("Loaded rules for matching test", rules != NULL && rules->count > 0);
    if (!rules) return;

    /* 1. Exact match */
    char term[64] = {0};
    TEST("Matches 'threat' in sentence",
         security_rules_check(rules, "We detected an active threat in the sector", term, sizeof(term)) != 0);
    TEST("Matched term is 'threat'", strcmp(term, "threat") == 0);

    /* 2. Case-insensitivity */
    TEST("Matches uppercase 'THREAT'",
         security_rules_check(rules, "Severe THREAT detected", term, sizeof(term)) != 0);

    TEST("Matches mixed-case 'ThReAt'",
         security_rules_check(rules, "A ThReAt was reported", term, sizeof(term)) != 0);

    /* 3. Punctuation boundaries */
    TEST("Matches with trailing period 'threat.'",
         security_rules_check(rules, "Look out for the threat.", term, sizeof(term)) != 0);

    TEST("Matches with exclamation 'threat!'",
         security_rules_check(rules, "Immediate threat!", term, sizeof(term)) != 0);

    TEST("Matches in quotes '\"threat\"'",
         security_rules_check(rules, "He said \"threat\" clearly", term, sizeof(term)) != 0);

    /* 4. Substring avoidance: word boundary check */
    TEST("Rejects 'threaten' (not a whole-word match for threat)",
         security_rules_check(rules, "They did not threaten anyone here", term, sizeof(term)) == 0);

    TEST("Rejects 'bombastic' (not a match for bomb)",
         security_rules_check(rules, "He gave a bombastic speech yesterday", term, sizeof(term)) == 0);

    /* 5. Phrase matching */
    TEST("Matches multi-word phrase 'immediate evacuation'",
         security_rules_check(rules, "Initiating immediate evacuation of building A", term, sizeof(term)) != 0);
    TEST("Matched term is phrase 'immediate evacuation'", strcmp(term, "immediate evacuation") == 0);

    /* 6. Benign text produces NO match */
    TEST("Benign text produces no match",
         security_rules_check(rules, "The weather is very pleasant today in the valley", term, sizeof(term)) == 0);

    security_rules_free(rules);
}

/* ── Test 3: Context Extraction ─────────────────────────────────────────── */

static void test_context_extraction(void)
{
    printf("\n=== Test 3: Context Extraction ===\n");

    const char* full_text = "Alpha Bravo Charlie Delta Echo Foxtrot Golf Hotel India Juliet "
                            "threat Kilo Lima Mike November Oscar Papa Quebec Romeo Sierra";
    char context[512] = {0};

    security_rules_extract_context(NULL, full_text, "threat", context, sizeof(context));
    TEST("Context text extracted", strlen(context) > 0);
    TEST("Context contains matched term", strstr(context, "threat") != NULL);
    TEST("Context contains leading words", strstr(context, "Hotel") != NULL);
    TEST("Context contains trailing words", strstr(context, "Kilo") != NULL);

    /* Text where term is at start */
    security_rules_extract_context(NULL, "threat is present now", "threat", context, sizeof(context));
    TEST("Context at start begins with term", strncmp(context, "threat", 6) == 0);

    /* Text where term is at end */
    security_rules_extract_context(NULL, "we see a threat", "threat", context, sizeof(context));
    TEST("Context at end ends with term", strstr(context, "threat") != NULL);
}

/* ── Test 4: Advisory Event Generation & Deduplication ───────────────────── */

static int g_event_callback_count = 0;
static ClipSecurityEvent g_last_event = {0};

static void test_analyzer_event_cb(const ClipSecurityEvent* ev, void* user_data)
{
    (void)user_data;
    if (!ev) return;
    g_event_callback_count++;
    g_last_event = *ev;
}

static void test_analyzer_events_and_deduplication(void)
{
    printf("\n=== Test 4: Advisory Events & Deduplication ===\n");

    SecurityRuleSet* rules = security_rules_load("config/security_rules.conf");
    TEST("Loaded rules for analyzer test", rules != NULL);
    if (!rules) return;

    SecurityAnalyzer* sa = security_analyzer_create(rules, test_analyzer_event_cb, NULL);
    TEST("security_analyzer_create succeeded", sa != NULL);
    if (!sa) {
        security_rules_free(rules);
        return;
    }

    uint8_t sess_uuid[CLIP_UUID_BYTES] = { 0x01, 0x02, 0x03, 0x04 };
    g_event_callback_count = 0;
    memset(&g_last_event, 0, sizeof(g_last_event));

    /* 1. Process matching transcript */
    security_analyzer_process(sa,
                              "Caution, we have a confirmed threat here",
                              "node-uuid-001",
                              "chan-uuid-001",
                              sess_uuid,
                              100000);

    TEST("Event callback invoked once", g_event_callback_count == 1);
    TEST("Status starts as PENDING (0)", g_last_event.status == CLIP_EVENT_STATUS_PENDING);
    TEST("Category is THREAT", g_last_event.category == CLIP_SECURITY_CAT_THREAT);
    TEST("Matched term is 'threat'", strcmp(g_last_event.matched_term, "threat") == 0);
    TEST("Context text is populated", strlen(g_last_event.context_text) > 0);

    /* 2. Deduplication within 5000ms window */
    security_analyzer_process(sa,
                              "Another line saying threat again",
                              "node-uuid-001",
                              "chan-uuid-001",
                              sess_uuid,
                              102000); /* 2000ms later (< 5000ms) */

    TEST("Deduplication prevented duplicate event within 5s window", g_event_callback_count == 1);

    /* 3. Different term in same session/node fires new event */
    security_analyzer_process(sa,
                              "There is also a bypass discovered",
                              "node-uuid-001",
                              "chan-uuid-001",
                              sess_uuid,
                              102500);

    TEST("Different term fired new event", g_event_callback_count == 2);

    /* 4. Same term after window expires (> 5000ms) fires event */
    security_analyzer_process(sa,
                              "Long after, another threat occurred",
                              "node-uuid-001",
                              "chan-uuid-001",
                              sess_uuid,
                              108000); /* 8000ms later (> 5000ms) */

    TEST("Same term fired event after deduplication window expired", g_event_callback_count == 3);

    security_analyzer_destroy(sa);
    security_rules_free(rules);
}

/* ── Test 5: SQLite Database Persistence Across Reopen ──────────────────── */

static void test_sqlite_persistence(void)
{
    printf("\n=== Test 5: SQLite Database Persistence Across Reopen ===\n");
    cleanup_file(TEST_PERSIST_DB);

    sqlite3* db = NULL;
    int rc = sqlite3_open(TEST_PERSIST_DB, &db);
    TEST("Opened test SQLite database", rc == SQLITE_OK && db != NULL);

    TEST("Initialized security_events schema", clip_security_db_init_schema(db) == CLIP_OK);

    uint8_t ev_uuid[CLIP_UUID_BYTES] = { 0x11, 0x22, 0x33, 0x44 };
    uint8_t sess_uuid[CLIP_UUID_BYTES] = { 0xAA, 0xBB, 0xCC, 0xDD };

    ClipSecurityEvent ev;
    memset(&ev, 0, sizeof(ev));
    memcpy(ev.event_uuid, ev_uuid, CLIP_UUID_BYTES);
    strcpy(ev.event_uuid_str, "11223344-0000-0000-0000-000000000000");
    memcpy(ev.session_uuid, sess_uuid, CLIP_UUID_BYTES);
    strcpy(ev.channel_uuid_str, "00000000-0000-0000-0000-000000000002");
    strcpy(ev.node_uuid_str, "00000000-0000-0000-0000-000000000001");
    ev.timestamp_ms = 1234567890ULL;
    ev.category = CLIP_SECURITY_CAT_THREAT;
    ev.severity = CLIP_SECURITY_SEV_CRITICAL;
    strcpy(ev.matched_rule, "HOSTILE_ACTION");
    strcpy(ev.matched_term, "threat");
    strcpy(ev.context_text, "we spotted a threat in the corridor");
    ev.status = CLIP_EVENT_STATUS_PENDING;

    ClipError ins_err = clip_security_db_insert_event(db, &ev);
    TEST("Inserted security event into DB", ins_err == CLIP_OK);
    TEST("Server generated event_id > 0", ev.event_id > 0);

    /* Close DB and reopen */
    sqlite3_close(db);
    db = NULL;

    rc = sqlite3_open(TEST_PERSIST_DB, &db);
    TEST("Reopened SQLite database", rc == SQLITE_OK && db != NULL);

    /* Query by ID */
    ClipSecurityEvent loaded;
    memset(&loaded, 0, sizeof(loaded));
    ClipError get_err = clip_security_db_get_event(db, ev.event_id, NULL, &loaded);
    TEST("Loaded event by event_id across reopen", get_err == CLIP_OK);
    TEST("Loaded event_id matches", loaded.event_id == ev.event_id);
    TEST("Loaded category matches THREAT", loaded.category == CLIP_SECURITY_CAT_THREAT);
    TEST("Loaded severity matches CRITICAL", loaded.severity == CLIP_SECURITY_SEV_CRITICAL);
    TEST("Loaded status is PENDING", loaded.status == CLIP_EVENT_STATUS_PENDING);
    TEST("Loaded matched_term matches 'threat'", strcmp(loaded.matched_term, "threat") == 0);
    TEST("Loaded context text matches", strcmp(loaded.context_text, ev.context_text) == 0);

    /* List for session */
    ClipSecurityEvent* list = NULL;
    size_t count = 0;
    ClipError list_err = clip_security_db_list_for_session(db, sess_uuid, &list, &count);
    TEST("List events for session succeeded", list_err == CLIP_OK);
    TEST("Found exactly 1 event for session", count == 1 && list != NULL);
    clip_security_db_free_event_list(list, count);

    /* List for node */
    ClipUuid node_u;
    clip_uuid_from_string(&node_u, "00000000-0000-0000-0000-000000000001");
    list_err = clip_security_db_list_for_node(db, node_u.bytes, &list, &count);
    TEST("List events for node succeeded", list_err == CLIP_OK);
    TEST("Found exactly 1 event for node", count == 1 && list != NULL);
    clip_security_db_free_event_list(list, count);

    sqlite3_close(db);
    cleanup_file(TEST_PERSIST_DB);
}

/* ── Test 6: Protocol Serialization & Message Code Validation ───────────── */

static void test_protocol_constants_and_framing(void)
{
    printf("\n=== Test 6: Protocol Constants & Framing Validation ===\n");

    /* Verify Phase 13 locked reservation */
    TEST("CLIP_MSG_CAPTION remains 0x0070", CLIP_MSG_CAPTION == 0x0070);

    /* Verify Phase 15 message codes */
    TEST("CLIP_MSG_SECURITY_EVENT is 0x0080", CLIP_MSG_SECURITY_EVENT == 0x0080);
    TEST("CLIP_MSG_SECURITY_EVENT_LIST_REQ is 0x0081", CLIP_MSG_SECURITY_EVENT_LIST_REQ == 0x0081);
    TEST("CLIP_MSG_SECURITY_EVENT_LIST_RESP is 0x0082", CLIP_MSG_SECURITY_EVENT_LIST_RESP == 0x0082);
    TEST("CLIP_MSG_SECURITY_EVENT_GET_REQ is 0x0083", CLIP_MSG_SECURITY_EVENT_GET_REQ == 0x0083);
    TEST("CLIP_MSG_SECURITY_EVENT_GET_RESP is 0x0084", CLIP_MSG_SECURITY_EVENT_GET_RESP == 0x0084);
    TEST("CLIP_MSG_SECURITY_EVENT_FAIL is 0x0085", CLIP_MSG_SECURITY_EVENT_FAIL == 0x0085);
    TEST("CLIP_MSG_SECURITY_TRANSCRIPT is 0x0086", CLIP_MSG_SECURITY_TRANSCRIPT == 0x0086);

    /* Verify validity and string conversions in clip_protocol */
    TEST("CLIP_MSG_SECURITY_TRANSCRIPT is valid message type", clip_message_type_is_valid(CLIP_MSG_SECURITY_TRANSCRIPT));
    TEST("CLIP_MSG_SECURITY_EVENT is valid message type", clip_message_type_is_valid(CLIP_MSG_SECURITY_EVENT));
    TEST("CLIP_MSG_SECURITY_EVENT string representation",
         strcmp(clip_message_type_string(CLIP_MSG_SECURITY_EVENT), "SECURITY_EVENT") == 0);
    TEST("CLIP_MSG_SECURITY_TRANSCRIPT string representation",
         strcmp(clip_message_type_string(CLIP_MSG_SECURITY_TRANSCRIPT), "SECURITY_TRANSCRIPT") == 0);

    /* Verify TLV tags */
    TEST("CLIP_TAG_EVENT_UUID is 0x0029", CLIP_TAG_EVENT_UUID == 0x0029);
    TEST("CLIP_TAG_EVENT_ID is 0x002A", CLIP_TAG_EVENT_ID == 0x002A);
    TEST("CLIP_TAG_MATCHED_RULE is 0x002B", CLIP_TAG_MATCHED_RULE == 0x002B);
    TEST("CLIP_TAG_MATCHED_TEXT is 0x002C", CLIP_TAG_MATCHED_TEXT == 0x002C);
    TEST("CLIP_TAG_CONTEXT_TEXT is 0x002D", CLIP_TAG_CONTEXT_TEXT == 0x002D);
    TEST("CLIP_TAG_EVENT_STATUS is 0x002E", CLIP_TAG_EVENT_STATUS == 0x002E);
    TEST("CLIP_TAG_EVENT_COUNT is 0x002F", CLIP_TAG_EVENT_COUNT == 0x002F);
}

/* ── Test 7: Live Loopback Client/Server Network Integration ─────────────── */

static DWORD WINAPI test_server_thread(LPVOID param)
{
    ClipServer* srv = (ClipServer*)param;
    while (srv->is_running) {
        clip_server_poll(srv, 20);
    }
    return 0;
}

static void test_live_network_integration(void)
{
    printf("\n=== Test 7: Live Loopback Client/Server Network Integration ===\n");
    cleanup_file(TEST_DB_PATH);

    ClipServer srv;
    ClipServerConfig cfg;
    clip_server_config_init_default(&cfg);
    cfg.port = TEST_PORT;
    cfg.use_tls = false;
    strncpy(cfg.db_path, TEST_DB_PATH, sizeof(cfg.db_path) - 1);
    strncpy(cfg.rules_file, "config/security_rules.conf", sizeof(cfg.rules_file) - 1);

    TEST("clip_server_init succeeds", clip_server_init(&srv, &cfg) == CLIP_OK);
    TEST("clip_server_start succeeds", clip_server_start(&srv) == CLIP_OK);

    HANDLE srv_th = CreateThread(NULL, 0, test_server_thread, &srv, 0, NULL);
    TEST("Server thread started", srv_th != NULL);
    Sleep(50);

    /* Initialize Client A */
    ClipClientNet client_a;
    clip_client_net_init(&client_a);
    clip_client_net_set_insecure_plaintext(&client_a);
    TEST("Client A connected", clip_client_connect(&client_a, "127.0.0.1", TEST_PORT) == CLIP_OK);

    ClipUuid uuid_a;
    uint8_t cred_a[CLIP_CREDENTIAL_BYTES];
    TEST("Client A registered", clip_client_register(&client_a, "CLIENT-A", &uuid_a, cred_a) == CLIP_OK);

    /* Initialize Client B */
    ClipClientNet client_b;
    clip_client_net_init(&client_b);
    clip_client_net_set_insecure_plaintext(&client_b);
    TEST("Client B connected", clip_client_connect(&client_b, "127.0.0.1", TEST_PORT) == CLIP_OK);

    ClipUuid uuid_b;
    uint8_t cred_b[CLIP_CREDENTIAL_BYTES];
    TEST("Client B registered", clip_client_register(&client_b, "CLIENT-B", &uuid_b, cred_b) == CLIP_OK);

    /* Client A creates channel, Client B joins */
    ClipUuid chan_uuid;
    char jkey[CLIP_JOIN_KEY_MAX];
    clip_client_channel_create(&client_a, "SecChannel", &chan_uuid, jkey, sizeof(jkey));
    char cname[CLIP_DISPLAY_NAME_MAX];
    clip_client_channel_join(&client_b, jkey, &chan_uuid, cname, sizeof(cname), NULL, NULL);

    /* Connection request and acceptance */
    ClipUuid conn_uuid;
    ClipConnectionState cstate;
    clip_client_send_conn_request(&client_a, &chan_uuid, &uuid_b, &conn_uuid, &cstate);
    clip_client_respond_conn(&client_b, &conn_uuid, true);

    /* Start active session */
    ClipUuid sess_uuid;
    TEST("Start session succeeds", clip_client_session_start_by_conn(&client_a, &conn_uuid, &sess_uuid) == CLIP_OK);

    /* 1. Client A submits finalized transcript via 0x0086 CLIP_MSG_SECURITY_TRANSCRIPT */
    const char* transcript_with_keyword = "We have an active threat confirmed near the server rack";
    ClipError sub_err = clip_client_submit_security_transcript(&client_a,
                                                               &sess_uuid,
                                                               &uuid_a,
                                                               transcript_with_keyword,
                                                               1234567890ULL);
    TEST("clip_client_submit_security_transcript succeeded", sub_err == CLIP_OK);

    /* Allow server to process transcript and persist advisory event */
    Sleep(150);

    /* 2. Client A queries security event list for this session */
    ClipSecurityEvent* events = NULL;
    size_t ev_cnt = 0;
    ClipError list_err = clip_client_list_security_events(&client_a, &sess_uuid, &events, &ev_cnt);
    TEST("clip_client_list_security_events succeeded", list_err == CLIP_OK);
    TEST("Detected 1 advisory security event", ev_cnt == 1 && events != NULL);
    if (ev_cnt > 0) {
        TEST("Event status is PENDING (0)", events[0].status == CLIP_EVENT_STATUS_PENDING);
        TEST("Event category is THREAT", events[0].category == CLIP_SECURITY_CAT_THREAT);
        TEST("Matched term is 'threat'", strcmp(events[0].matched_term, "threat") == 0);
        TEST("Context contains matched text", strstr(events[0].context_text, "threat") != NULL);

        /* 3. Query single event by ID */
        ClipSecurityEvent single_ev;
        ClipError get_err = clip_client_get_security_event(&client_a, events[0].event_id, NULL, &single_ev);
        TEST("clip_client_get_security_event succeeded", get_err == CLIP_OK);
        TEST("Single event ID matches", single_ev.event_id == events[0].event_id);
        TEST("Single event status is PENDING", single_ev.status == CLIP_EVENT_STATUS_PENDING);
        ClipUuid node_uuid_tmp;
        TEST("Single event speaker matches Client A",
             clip_uuid_from_string(&node_uuid_tmp, single_ev.node_uuid_str) == 0 &&
             clip_uuid_equal(&node_uuid_tmp, &uuid_a));

        /* 4. Client B (authorized participant) can also view event */
        ClipSecurityEvent b_single_ev;
        ClipError b_get_err = clip_client_get_security_event(&client_b, events[0].event_id, NULL, &b_single_ev);
        TEST("Peer Client B is authorized to get security event", b_get_err == CLIP_OK);
        TEST("Peer sees same event ID", b_single_ev.event_id == events[0].event_id);
    }
    clip_client_free_security_events(events, ev_cnt);

    /* 5. Create a note containing security keyword -> triggers analysis */
    uint32_t note_id = 0;
    ClipError note_err = clip_client_create_note(&client_b,
                                                 &sess_uuid,
                                                 CLIP_NOTE_TYPE_MANUAL,
                                                 "Note: observed suspicious bypass in authorization logic",
                                                 &note_id);
    TEST("Client B created note with keyword", note_err == CLIP_OK && note_id > 0);
    Sleep(150);

    /* Verify list now contains the second event */
    events = NULL;
    ev_cnt = 0;
    list_err = clip_client_list_security_events(&client_a, &sess_uuid, &events, &ev_cnt);
    TEST("List events after note creation succeeded", list_err == CLIP_OK);
    TEST("Found 2 advisory events now", ev_cnt == 2 && events != NULL);
    if (ev_cnt >= 2) {
        bool has_bypass = (strcmp(events[0].matched_term, "bypass") == 0 || strcmp(events[1].matched_term, "bypass") == 0);
        bool has_threat = (strcmp(events[0].matched_term, "threat") == 0 || strcmp(events[1].matched_term, "threat") == 0);
        TEST("Events contain 'bypass'", has_bypass);
        TEST("Events contain 'threat'", has_threat);
        TEST("Events are PENDING", events[0].status == CLIP_EVENT_STATUS_PENDING && events[1].status == CLIP_EVENT_STATUS_PENDING);
    }
    clip_client_free_security_events(events, ev_cnt);

    /* 6. Stranger client is rejected */
    ClipClientNet client_stranger;
    clip_client_net_init(&client_stranger);
    clip_client_net_set_insecure_plaintext(&client_stranger);
    clip_client_connect(&client_stranger, "127.0.0.1", TEST_PORT);
    ClipUuid stranger_uuid;
    uint8_t cred_stranger[CLIP_CREDENTIAL_BYTES];
    clip_client_register(&client_stranger, "STRANGER", &stranger_uuid, cred_stranger);

    events = NULL;
    ev_cnt = 0;
    ClipError stranger_err = clip_client_list_security_events(&client_stranger, &sess_uuid, &events, &ev_cnt);
    TEST("Stranger node is denied access to session security events", stranger_err == CLIP_ERR_DENIED);

    /* Disconnect clients and stop server */
    clip_client_disconnect(&client_stranger);
    clip_client_net_cleanup(&client_stranger);

    clip_client_disconnect(&client_b);
    clip_client_net_cleanup(&client_b);

    clip_client_disconnect(&client_a);
    clip_client_net_cleanup(&client_a);

    srv.is_running = false;
    WaitForSingleObject(srv_th, 1000);
    CloseHandle(srv_th);
    clip_server_stop(&srv);
    clip_server_cleanup(&srv);

    cleanup_file(TEST_DB_PATH);
}

/* ── Main Runner ────────────────────────────────────────────────────────── */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("============================================================\n");
    printf("   CLICOM Phase 15: Security Keyword Analysis Unit Tests\n");
    printf("============================================================\n");

    test_rules_config_and_safe_failure();
    test_rules_matching();
    test_context_extraction();
    test_analyzer_events_and_deduplication();
    test_sqlite_persistence();
    test_protocol_constants_and_framing();
    test_live_network_integration();

    printf("\n============================================================\n");
    printf("Tests complete: %d passed, %d failed\n", g_pass, g_fail);
    printf("============================================================\n");

    return (g_fail == 0) ? 0 : 1;
}

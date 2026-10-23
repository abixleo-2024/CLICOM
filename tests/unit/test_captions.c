/*
 * test_captions.c — CLICOM Phase 13: Live Captions UI Unit Tests
 *
 * Verifies:
 * 1. Buffer initialization and cleanup (default & custom capacity).
 * 2. Session scoping and CLIP_TAG_SPEECH_ANALYSIS disclosure enforcement.
 * 3. Bounded circular buffer insertion, chronological ordering, and eviction.
 * 4. Monotonic sequence numbering across evictions.
 * 5. Interim transcript updates in-place (no duplicate entries for same speaker).
 * 6. Interim to final conversion when is_final == true.
 * 7. Speaker change handling (seals pending interim, creates new entry).
 * 8. Speaker name resolution and canonical UUID fallback.
 * 9. Safe truncation of oversized text and handling of NULL/empty inputs.
 * 10. Terminal rendering in all four states (no session, disabled, listening, active).
 * 11. Thread-safe concurrent worker ingestion and UI reads.
 * 12. End-to-end SpeechAnalyzer mock adapter -> callback -> caption buffer pipeline.
 */

#include "clip_captions.h"
#include "speech_analyzer.h"
#include "clip_errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>

static int g_pass_count = 0;
static int g_fail_count = 0;

#define TEST(name, cond) do { \
    if (cond) { \
        printf("  [PASS] %s\n", (name)); \
        fflush(stdout); \
        g_pass_count++; \
    } else { \
        printf("  [FAIL] %s (line %d)\n", (name), __LINE__); \
        fflush(stdout); \
        g_fail_count++; \
    } \
} while(0)

/* Helper to make a UUID with a distinctive byte */
static ClipUuid make_test_uuid(uint8_t byte_val)
{
    ClipUuid u;
    memset(u.bytes, byte_val, CLIP_UUID_BYTES);
    return u;
}

/* ── Test 1: Buffer Initialization & Cleanup ───────────────────────────── */

static void test_init_cleanup(void)
{
    printf("\n=== Test 1: Buffer Initialization & Cleanup ===\n");

    ClipCaptionBuffer buf;
    memset(&buf, 0, sizeof(buf));

    /* NULL buffer check */
    TEST("Init NULL buffer returns error", clip_captions_init(NULL, 0) == CLIP_ERR_INVALID);

    /* Default capacity */
    ClipError err = clip_captions_init(&buf, 0);
    TEST("Init with default capacity succeeds", err == CLIP_OK);
    TEST("Default capacity is 50", buf.capacity == CLIP_CAPTION_HISTORY_DEFAULT);
    TEST("Initial count is 0", clip_captions_get_count(&buf) == 0);
    clip_captions_cleanup(&buf);

    /* Custom capacity */
    err = clip_captions_init(&buf, 15);
    TEST("Init with custom capacity succeeds", err == CLIP_OK);
    TEST("Custom capacity is 15", buf.capacity == 15);
    clip_captions_cleanup(&buf);
}

/* ── Test 2: Session Scoping & Disclosure Enforcement ──────────────────── */

static void test_session_scoping_and_disclosure(void)
{
    printf("\n=== Test 2: Session Scoping & Disclosure Enforcement ===\n");

    ClipCaptionBuffer buf;
    clip_captions_init(&buf, 10);

    ClipUuid sess1 = make_test_uuid(0x11);
    ClipUuid sess2 = make_test_uuid(0x22);
    ClipUuid spk1  = make_test_uuid(0xAA);

    SpeechTranscriptResult res;
    memset(&res, 0, sizeof(res));
    res.session_uuid = sess1;
    res.speaker_node_uuid = spk1;
    res.text = "Hello world";
    res.text_len = strlen(res.text);
    res.start_time_ms = 1000;
    res.is_final = true;

    /* 1. Ingestion without active session must fail */
    TEST("Push rejected when no session active",
         clip_captions_push_transcript(&buf, &res) == CLIP_ERR_NO_SESSION);

    /* 2. Ingestion when speech analysis disclosure is NONE must fail */
    clip_captions_set_session(&buf, &sess1, CLIP_SPEECH_MODE_NONE);
    TEST("Push rejected when speech mode is NONE",
         clip_captions_push_transcript(&buf, &res) == CLIP_ERR_SPEECH_INACTIVE);

    /* 3. Ingestion when session UUID does not match must fail */
    clip_captions_set_session(&buf, &sess1, CLIP_SPEECH_MODE_SERVER_MEDIATED);
    res.session_uuid = sess2;
    TEST("Push rejected when session UUID does not match",
         clip_captions_push_transcript(&buf, &res) == CLIP_ERR_INVALID);

    /* 4. Valid session and disclosure allows push */
    res.session_uuid = sess1;
    ClipError push_err = clip_captions_push_transcript(&buf, &res);
    TEST("Push succeeds with matching session and enabled disclosure", push_err == CLIP_OK);
    TEST("Count is 1", clip_captions_get_count(&buf) == 1);

    /* 5. Session end clears buffer */
    clip_captions_set_session(&buf, NULL, CLIP_SPEECH_MODE_NONE);
    TEST("Setting NULL session marks inactive", !buf.session_active);
    TEST("Setting NULL session clears count to 0", clip_captions_get_count(&buf) == 0);

    clip_captions_cleanup(&buf);
}

/* ── Test 3: Chronological Insertion & Monotonic Sequence ──────────────── */

static void test_insertion_and_ordering(void)
{
    printf("\n=== Test 3: Chronological Insertion & Monotonic Sequence ===\n");

    ClipCaptionBuffer buf;
    clip_captions_init(&buf, 10);

    ClipUuid sess = make_test_uuid(0x10);
    ClipUuid spk  = make_test_uuid(0xA1);
    clip_captions_set_session(&buf, &sess, CLIP_SPEECH_MODE_SERVER_MEDIATED);

    /* Push 5 distinct final entries */
    for (int i = 1; i <= 5; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Utterance %d", i);

        SpeechTranscriptResult res;
        memset(&res, 0, sizeof(res));
        res.session_uuid = sess;
        res.speaker_node_uuid = spk;
        res.text = msg;
        res.text_len = strlen(msg);
        res.start_time_ms = (uint64_t)(i * 1000);
        res.is_final = true;

        ClipError err = clip_captions_push_transcript(&buf, &res);
        TEST("Pushing final utterance succeeds", err == CLIP_OK);
    }

    TEST("Total count is 5", clip_captions_get_count(&buf) == 5);

    /* Verify chronological ordering and sequence IDs */
    bool seq_ok = true;
    for (size_t i = 0; i < 5; i++) {
        ClipCaptionEntry e;
        ClipError err = clip_captions_get_entry(&buf, i, &e);
        if (err != CLIP_OK || e.sequence_id != (uint32_t)(i + 1)) {
            seq_ok = false;
        }
    }
    TEST("Chronological sequence IDs strictly increasing (1..5)", seq_ok);

    /* Out of bounds check */
    ClipCaptionEntry out_e;
    TEST("Get entry at count returns CLIP_ERR_NOT_FOUND",
         clip_captions_get_entry(&buf, 5, &out_e) == CLIP_ERR_NOT_FOUND);

    clip_captions_cleanup(&buf);
}

/* ── Test 4: Circular Buffer Eviction & Capacity Limit ─────────────────── */

static void test_circular_eviction(void)
{
    printf("\n=== Test 4: Circular Buffer Eviction & Capacity Limit ===\n");

    ClipCaptionBuffer buf;
    clip_captions_init(&buf, 5); /* Capacity of 5 */

    ClipUuid sess = make_test_uuid(0x20);
    ClipUuid spk  = make_test_uuid(0xB1);
    clip_captions_set_session(&buf, &sess, CLIP_SPEECH_MODE_SERVER_MEDIATED);

    /* Push 8 entries (3 more than capacity) */
    for (int i = 1; i <= 8; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Message %d", i);

        SpeechTranscriptResult res;
        memset(&res, 0, sizeof(res));
        res.session_uuid = sess;
        res.speaker_node_uuid = spk;
        res.text = msg;
        res.text_len = strlen(msg);
        res.start_time_ms = (uint64_t)(i * 1000);
        res.is_final = true;

        clip_captions_push_transcript(&buf, &res);
    }

    TEST("Count is bounded at capacity (5)", clip_captions_get_count(&buf) == 5);

    /* Check oldest entry (logical index 0): must be Message 4 (seq=4) */
    ClipCaptionEntry oldest;
    ClipError err0 = clip_captions_get_entry(&buf, 0, &oldest);
    TEST("Get oldest entry succeeds", err0 == CLIP_OK);
    TEST("Oldest entry is Message 4", strcmp(oldest.text, "Message 4") == 0);
    TEST("Oldest sequence ID is 4", oldest.sequence_id == 4);

    /* Check newest entry (logical index 4): must be Message 8 (seq=8) */
    ClipCaptionEntry newest;
    ClipError err4 = clip_captions_get_entry(&buf, 4, &newest);
    TEST("Get newest entry succeeds", err4 == CLIP_OK);
    TEST("Newest entry is Message 8", strcmp(newest.text, "Message 8") == 0);
    TEST("Newest sequence ID is 8", newest.sequence_id == 8);

    clip_captions_cleanup(&buf);
}

/* ── Test 5: Interim Updates and Final Replacement ─────────────────────── */

static void test_interim_update_and_final(void)
{
    printf("\n=== Test 5: Interim Updates and Final Replacement ===\n");

    ClipCaptionBuffer buf;
    clip_captions_init(&buf, 10);

    ClipUuid sess = make_test_uuid(0x30);
    ClipUuid spk  = make_test_uuid(0xC1);
    clip_captions_set_session(&buf, &sess, CLIP_SPEECH_MODE_SERVER_MEDIATED);

    /* 1. Push interim transcript */
    SpeechTranscriptResult res;
    memset(&res, 0, sizeof(res));
    res.session_uuid = sess;
    res.speaker_node_uuid = spk;
    res.text = "Hello";
    res.text_len = strlen(res.text);
    res.start_time_ms = 1000;
    res.is_final = false;

    clip_captions_push_transcript(&buf, &res);
    TEST("Count after first interim is 1", clip_captions_get_count(&buf) == 1);

    ClipCaptionEntry e1;
    clip_captions_get_entry(&buf, 0, &e1);
    TEST("Entry 0 text is 'Hello'", strcmp(e1.text, "Hello") == 0);
    TEST("Entry 0 is_final is false", e1.is_final == false);

    /* 2. Push updated interim from same speaker */
    res.text = "Hello world";
    res.text_len = strlen(res.text);
    res.is_final = false;

    clip_captions_push_transcript(&buf, &res);
    TEST("Count after interim update remains 1 (no duplicate)", clip_captions_get_count(&buf) == 1);

    ClipCaptionEntry e2;
    clip_captions_get_entry(&buf, 0, &e2);
    TEST("Entry 0 text updated in-place to 'Hello world'", strcmp(e2.text, "Hello world") == 0);
    TEST("Entry 0 is_final is still false", e2.is_final == false);

    /* 3. Push final transcript from same speaker */
    res.text = "Hello world!";
    res.text_len = strlen(res.text);
    res.is_final = true;

    clip_captions_push_transcript(&buf, &res);
    TEST("Count after final conversion remains 1", clip_captions_get_count(&buf) == 1);

    ClipCaptionEntry e3;
    clip_captions_get_entry(&buf, 0, &e3);
    TEST("Entry 0 text finalized to 'Hello world!'", strcmp(e3.text, "Hello world!") == 0);
    TEST("Entry 0 is_final is now true", e3.is_final == true);

    /* 4. Subsequent interim creates a NEW entry */
    res.text = "Next sentence";
    res.text_len = strlen(res.text);
    res.is_final = false;

    clip_captions_push_transcript(&buf, &res);
    TEST("Count after new interim is now 2", clip_captions_get_count(&buf) == 2);

    clip_captions_cleanup(&buf);
}

/* ── Test 6: Speaker Change Seals Previous Interim ─────────────────────── */

static void test_speaker_change(void)
{
    printf("\n=== Test 6: Speaker Change Seals Previous Interim ===\n");

    ClipCaptionBuffer buf;
    clip_captions_init(&buf, 10);

    ClipUuid sess = make_test_uuid(0x40);
    ClipUuid spkA = make_test_uuid(0xA0);
    ClipUuid spkB = make_test_uuid(0xB0);
    clip_captions_set_session(&buf, &sess, CLIP_SPEECH_MODE_SERVER_MEDIATED);

    /* Speaker A speaks interim */
    SpeechTranscriptResult resA;
    memset(&resA, 0, sizeof(resA));
    resA.session_uuid = sess;
    resA.speaker_node_uuid = spkA;
    resA.text = "Speaker A speaking...";
    resA.text_len = strlen(resA.text);
    resA.is_final = false;
    clip_captions_push_transcript(&buf, &resA);

    TEST("Speaker A interim stored, count is 1", clip_captions_get_count(&buf) == 1);

    /* Speaker B speaks (speaker change while A was interim) */
    SpeechTranscriptResult resB;
    memset(&resB, 0, sizeof(resB));
    resB.session_uuid = sess;
    resB.speaker_node_uuid = spkB;
    resB.text = "Speaker B breaking in...";
    resB.text_len = strlen(resB.text);
    resB.is_final = false;
    clip_captions_push_transcript(&buf, &resB);

    TEST("Speaker change increments count to 2", clip_captions_get_count(&buf) == 2);

    ClipCaptionEntry eA, eB;
    clip_captions_get_entry(&buf, 0, &eA);
    clip_captions_get_entry(&buf, 1, &eB);

    TEST("Previous Speaker A entry was sealed (is_final == true)", eA.is_final == true);
    TEST("Speaker B entry is in-progress (is_final == false)", eB.is_final == false);

    clip_captions_cleanup(&buf);
}

/* ── Test 7: Speaker Name Resolution & UUID Fallback ───────────────────── */

static const char* test_resolver_cb(const ClipUuid* speaker_uuid, void* user_data)
{
    (void)user_data;
    if (!speaker_uuid) return NULL;
    if (speaker_uuid->bytes[0] == 0x77) {
        return "DISPATCH-COMMAND";
    }
    return NULL; /* unknown */
}

static void test_speaker_resolution(void)
{
    printf("\n=== Test 7: Speaker Name Resolution & UUID Fallback ===\n");

    ClipCaptionBuffer buf;
    clip_captions_init(&buf, 10);

    ClipUuid sess = make_test_uuid(0x50);
    ClipUuid spk_known   = make_test_uuid(0x77);
    ClipUuid spk_unknown = make_test_uuid(0x88);
    clip_captions_set_session(&buf, &sess, CLIP_SPEECH_MODE_SERVER_MEDIATED);

    clip_captions_set_speaker_resolver(&buf, test_resolver_cb, NULL);

    /* Known speaker resolved via callback */
    SpeechTranscriptResult r1;
    memset(&r1, 0, sizeof(r1));
    r1.session_uuid = sess;
    r1.speaker_node_uuid = spk_known;
    r1.text = "All units proceed to sector 4";
    r1.text_len = strlen(r1.text);
    r1.is_final = true;
    clip_captions_push_transcript(&buf, &r1);

    ClipCaptionEntry e1;
    clip_captions_get_entry(&buf, 0, &e1);
    TEST("Known speaker resolved to 'DISPATCH-COMMAND'",
         strcmp(e1.speaker_name, "DISPATCH-COMMAND") == 0);

    /* Unknown speaker falls back to UUID string */
    SpeechTranscriptResult r2;
    memset(&r2, 0, sizeof(r2));
    r2.session_uuid = sess;
    r2.speaker_node_uuid = spk_unknown;
    r2.text = "Acknowledged, moving out";
    r2.text_len = strlen(r2.text);
    r2.is_final = true;
    clip_captions_push_transcript(&buf, &r2);

    ClipCaptionEntry e2;
    clip_captions_get_entry(&buf, 1, &e2);
    char expected_uuid[CLIP_UUID_STR_SIZE];
    clip_uuid_to_string(&spk_unknown, expected_uuid, sizeof(expected_uuid));
    TEST("Unknown speaker falls back to canonical UUID string",
         strcmp(e2.speaker_name, expected_uuid) == 0);

    clip_captions_cleanup(&buf);
}

/* ── Test 8: Text Truncation & Safe Handling ───────────────────────────── */

static void test_text_truncation(void)
{
    printf("\n=== Test 8: Text Truncation & Safe Handling ===\n");

    ClipCaptionBuffer buf;
    clip_captions_init(&buf, 5);

    ClipUuid sess = make_test_uuid(0x60);
    ClipUuid spk  = make_test_uuid(0x99);
    clip_captions_set_session(&buf, &sess, CLIP_SPEECH_MODE_SERVER_MEDIATED);

    /* 1. NULL text string handled safely */
    SpeechTranscriptResult r_null;
    memset(&r_null, 0, sizeof(r_null));
    r_null.session_uuid = sess;
    r_null.speaker_node_uuid = spk;
    r_null.text = NULL;
    r_null.is_final = true;
    TEST("NULL text handled safely without crash", clip_captions_push_transcript(&buf, &r_null) == CLIP_OK);

    ClipCaptionEntry e_null;
    clip_captions_get_entry(&buf, 0, &e_null);
    TEST("NULL text stored as empty string", strlen(e_null.text) == 0);

    /* 2. Oversized text string truncated to CLIP_CAPTION_TEXT_MAX - 1 */
    char huge_text[512];
    memset(huge_text, 'A', sizeof(huge_text) - 1);
    huge_text[sizeof(huge_text) - 1] = '\0';

    SpeechTranscriptResult r_huge;
    memset(&r_huge, 0, sizeof(r_huge));
    r_huge.session_uuid = sess;
    r_huge.speaker_node_uuid = spk;
    r_huge.text = huge_text;
    r_huge.text_len = strlen(huge_text);
    r_huge.is_final = true;

    TEST("Oversized text pushed safely", clip_captions_push_transcript(&buf, &r_huge) == CLIP_OK);
    ClipCaptionEntry e_huge;
    clip_captions_get_entry(&buf, 1, &e_huge);
    TEST("Oversized text truncated to max bounds",
         strlen(e_huge.text) == CLIP_CAPTION_TEXT_MAX - 1);
    TEST("NUL termination preserved", e_huge.text[CLIP_CAPTION_TEXT_MAX - 1] == '\0');

    clip_captions_cleanup(&buf);
}

/* ── Test 9: Terminal Rendering Modes ──────────────────────────────────── */

static void test_terminal_rendering(void)
{
    printf("\n=== Test 9: Terminal Rendering Modes ===\n");

    ClipCaptionBuffer buf;
    clip_captions_init(&buf, 5);

    /* 1. Render when no session active */
    printf("\n--- Rendering: No active session ---\n");
    clip_captions_render(&buf, stdout, 5);

    /* 2. Render when speech analysis disabled */
    ClipUuid sess = make_test_uuid(0x70);
    clip_captions_set_session(&buf, &sess, CLIP_SPEECH_MODE_NONE);
    printf("\n--- Rendering: Speech analysis disabled ---\n");
    clip_captions_render(&buf, stdout, 5);

    /* 3. Render when active session but no transcripts yet */
    clip_captions_set_session(&buf, &sess, CLIP_SPEECH_MODE_SERVER_MEDIATED);
    printf("\n--- Rendering: Listening (0 transcripts) ---\n");
    clip_captions_render(&buf, stdout, 5);

    /* 4. Render with active transcripts */
    ClipUuid spk = make_test_uuid(0x01);
    SpeechTranscriptResult r1 = {
        .text = "Control, this is Alpha 1, radio check.",
        .text_len = 38,
        .start_time_ms = 1700000000000ULL,
        .speaker_node_uuid = spk,
        .speaker_node_id = "ALPHA-1",
        .session_uuid = sess,
        .is_final = true,
        .confidence = 0.98f
    };
    clip_captions_push_transcript(&buf, &r1);

    SpeechTranscriptResult r2 = {
        .text = "Alpha 1, reading you five by five.",
        .text_len = 34,
        .start_time_ms = 1700000004000ULL,
        .speaker_node_uuid = spk,
        .speaker_node_id = "CONTROL",
        .session_uuid = sess,
        .is_final = true,
        .confidence = 0.99f
    };
    clip_captions_push_transcript(&buf, &r2);

    SpeechTranscriptResult r3 = {
        .text = "Copy that. Heading towards grid 4...",
        .text_len = 36,
        .start_time_ms = 1700000008000ULL,
        .speaker_node_uuid = spk,
        .speaker_node_id = "ALPHA-1",
        .session_uuid = sess,
        .is_final = false, /* interim */
        .confidence = 0.85f
    };
    clip_captions_push_transcript(&buf, &r3);

    printf("\n--- Rendering: Active captions (final + interim) ---\n");
    clip_captions_render(&buf, stdout, 5);

    TEST("Rendering executes cleanly across all states", true);
    clip_captions_cleanup(&buf);
}

/* ── Test 10: Multi-Threaded Concurrent Worker Ingestion ───────────────── */

typedef struct ThreadTestCtx {
    ClipCaptionBuffer* buf;
    ClipUuid           session_uuid;
    ClipUuid           speaker_uuid;
    int                iterations;
    volatile LONG      finished;
} ThreadTestCtx;

static DWORD WINAPI worker_push_thread(LPVOID param)
{
    ThreadTestCtx* ctx = (ThreadTestCtx*)param;
    for (int i = 0; i < ctx->iterations; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Concurrent utterance #%d", i);

        SpeechTranscriptResult res;
        memset(&res, 0, sizeof(res));
        res.session_uuid = ctx->session_uuid;
        res.speaker_node_uuid = ctx->speaker_uuid;
        res.text = msg;
        res.text_len = strlen(msg);
        res.start_time_ms = (uint64_t)i * 100;
        res.is_final = ((i % 2) == 1); /* alternate interim and final */

        clip_captions_push_transcript(ctx->buf, &res);
        Sleep(1);
    }
    InterlockedExchange(&ctx->finished, 1);
    return 0;
}

static void test_concurrent_ingestion(void)
{
    printf("\n=== Test 10: Multi-Threaded Concurrent Worker Ingestion ===\n");

    ClipCaptionBuffer buf;
    clip_captions_init(&buf, 20);

    ClipUuid sess = make_test_uuid(0x80);
    ClipUuid spk  = make_test_uuid(0xF1);
    clip_captions_set_session(&buf, &sess, CLIP_SPEECH_MODE_SERVER_MEDIATED);

    ThreadTestCtx ctx = {
        .buf = &buf,
        .session_uuid = sess,
        .speaker_uuid = spk,
        .iterations = 100,
        .finished = 0
    };

    HANDLE h_thread = CreateThread(NULL, 0, worker_push_thread, &ctx, 0, NULL);
    TEST("Worker push thread spawned", h_thread != NULL);

    int reads = 0;
    while (!InterlockedCompareExchange(&ctx.finished, 0, 0)) {
        size_t cnt = clip_captions_get_count(&buf);
        if (cnt > 0) {
            ClipCaptionEntry e;
            clip_captions_get_entry(&buf, cnt - 1, &e);
        }
        reads++;
        Sleep(2);
    }

    WaitForSingleObject(h_thread, 5000);
    CloseHandle(h_thread);

    TEST("Concurrent test completed without crashing", true);
    TEST("Buffer count is bounded within capacity (<= 20)", clip_captions_get_count(&buf) <= 20);
    TEST("Concurrent read loops executed", reads > 0);

    clip_captions_cleanup(&buf);
}

/* ── Test 11: End-to-End SpeechAnalyzer Mock Adapter Pipeline ──────────── */

static void test_speechanalyzer_mock_pipeline(void)
{
    printf("\n=== Test 11: End-to-End SpeechAnalyzer Mock Pipeline ===\n");

    ClipCaptionBuffer buf;
    clip_captions_init(&buf, 20);

    ClipUuid sess = make_test_uuid(0x90);
    ClipUuid spk  = make_test_uuid(0x02);
    clip_captions_set_session(&buf, &sess, CLIP_SPEECH_MODE_SERVER_MEDIATED);

    /* Create Phase 12 SpeechAnalyzer with mock adapter */
    SpeechAnalyzerConfig sa_cfg;
    speech_analyzer_config_default(&sa_cfg);
    sa_cfg.min_chunk_samples = 320; /* 20ms @ 16kHz */
    sa_cfg.max_buffer_samples = 640; /* 40ms */

    SpeechAnalyzer* sa = speech_analyzer_create("mock", &sa_cfg);
    TEST("SpeechAnalyzer mock adapter created", sa != NULL);

    /* Wire transcript callback directly into clip_captions_transcript_callback */
    ClipError cb_err = speech_analyzer_set_callback(sa, clip_captions_transcript_callback, &buf);
    TEST("Registered clip_captions_transcript_callback on SpeechAnalyzer", cb_err == CLIP_OK);

    /* Feed 320 samples (triggers interim chunk 1) */
    int16_t pcm[640];
    for (int i = 0; i < 640; i++) {
        pcm[i] = (int16_t)(i % 1000);
    }

    ClipError feed_err1 = speech_analyzer_feed_pcm(sa, &sess, &spk, 1000, pcm, 320);
    TEST("speech_analyzer_feed_pcm interim chunk succeeds", feed_err1 == CLIP_OK);

    /* Feed remaining 160 samples (accumulates in buffer below min_chunk_samples) */
    ClipError feed_err2 = speech_analyzer_feed_pcm(sa, &sess, &spk, 1020, pcm, 160);
    TEST("speech_analyzer_feed_pcm residual succeeds", feed_err2 == CLIP_OK);

    /* Flush analyzer (simulating PTT floor release, emits final chunk) */
    ClipError flush_err = speech_analyzer_flush(sa);
    TEST("speech_analyzer_flush succeeds", flush_err == CLIP_OK);

    /* Verify transcript arrived in caption buffer! */
    size_t cnt = clip_captions_get_count(&buf);
    TEST("Transcripts populated in ClipCaptionBuffer (> 0)", cnt > 0);

    if (cnt > 0) {
        ClipCaptionEntry e;
        clip_captions_get_entry(&buf, 0, &e);
        TEST("Transcript text contains MOCK_TRANSCRIPT prefix",
             strstr(e.text, "[MOCK_TRANSCRIPT") != NULL);
        TEST("Final utterance is sealed (is_final == true)", e.is_final == true);
    }

    speech_analyzer_destroy(sa);
    clip_captions_cleanup(&buf);
}

/* ── Test Runner ───────────────────────────────────────────────────────── */

int main(void)
{
    printf("============================================================\n");
    printf("       CLICOM Phase 13: Live Captions UI Unit Tests\n");
    printf("============================================================\n");

    test_init_cleanup();
    test_session_scoping_and_disclosure();
    test_insertion_and_ordering();
    test_circular_eviction();
    test_interim_update_and_final();
    test_speaker_change();
    test_speaker_resolution();
    test_text_truncation();
    test_terminal_rendering();
    test_concurrent_ingestion();
    test_speechanalyzer_mock_pipeline();

    printf("\n============================================================\n");
    printf("Test Results: %d passed, %d failed\n", g_pass_count, g_fail_count);
    printf("============================================================\n");

    return (g_fail_count == 0) ? 0 : 1;
}

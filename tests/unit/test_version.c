/*
 * tests/unit/test_version.c — Phase 0 Unit Tests: Version Constants
 *
 * Verifies that CMake correctly injects software and protocol version
 * values, that they are distinct, and that key protocol constants are
 * set to the documented values.
 *
 * Run via:   ctest  (or directly: ./test_version)
 * Expected:  exit code 0, all tests PASS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clip_version.h"
#include "clip_protocol.h"
#include "clip_types.h"
#include "clip_errors.h"

/* ── Minimal test harness ───────────────────────────────────────────────── */

static int g_pass = 0;
static int g_fail = 0;

#define TEST(name, condition) do { \
    if (condition) { \
        printf("  PASS  " name "\n"); \
        g_pass++; \
    } else { \
        printf("  FAIL  " name "\n"); \
        g_fail++; \
    } \
} while (0)

/* ── Tests ──────────────────────────────────────────────────────────────── */

static void test_software_version(void)
{
    printf("\n[Software Version]\n");
    TEST("CLICOM_VERSION_MAJOR == 2",  CLICOM_VERSION_MAJOR  == 2);
    TEST("CLICOM_VERSION_MINOR == 0",  CLICOM_VERSION_MINOR  == 0);
    TEST("CLICOM_VERSION_PATCH == 0",  CLICOM_VERSION_PATCH  == 0);
    TEST("CLICOM_VERSION_STRING not empty",
         CLICOM_VERSION_STRING[0] != '\0');
    TEST("CLICOM_TARGET_PLATFORM not empty",
         CLICOM_TARGET_PLATFORM[0] != '\0');
    TEST("CLICOM_BUILD_TIMESTAMP not empty",
         CLICOM_BUILD_TIMESTAMP[0] != '\0');
}

static void test_protocol_version(void)
{
    printf("\n[Protocol Version — must be independent of software version]\n");
    TEST("CLIP_PROTOCOL_VERSION_MAJOR == 1",
         CLIP_PROTOCOL_VERSION_MAJOR == 1);
    TEST("CLIP_PROTOCOL_VERSION_MINOR == 0",
         CLIP_PROTOCOL_VERSION_MINOR == 0);
    TEST("CLIP_PROTOCOL_VERSION_STRING not empty",
         CLIP_PROTOCOL_VERSION_STRING[0] != '\0');

    /* Critical: the two version strings must be distinct */
    TEST("Software version string != protocol version string",
         strcmp(CLICOM_VERSION_STRING, CLIP_PROTOCOL_VERSION_STRING) != 0);
}

static void test_wire_constants(void)
{
    printf("\n[Wire Constants]\n");
    /* Magic: ASCII "CLIP" */
    TEST("CLIP_PROTOCOL_MAGIC == 0x434C4950",
         CLIP_PROTOCOL_MAGIC == 0x434C4950u);
    /* Header: 4+2+2+4+8+16 = 36 bytes */
    TEST("CLIP_HEADER_SIZE == 36",
         CLIP_HEADER_SIZE == 36u);
    TEST("CLIP_SESSION_UUID_SIZE == 16",
         CLIP_SESSION_UUID_SIZE == 16u);
    TEST("CLIP_MAX_PAYLOAD_SIZE == 65536",
         CLIP_MAX_PAYLOAD_SIZE == (64u * 1024u));
    TEST("CLIP_TLV_HEADER_SIZE == 4",
         CLIP_TLV_HEADER_SIZE == 4u);
}

static void test_uuid_sizes(void)
{
    printf("\n[UUID / String Buffer Sizes]\n");
    TEST("CLIP_UUID_BYTES == 16",          CLIP_UUID_BYTES == 16u);
    TEST("CLIP_UUID_STR_SIZE == 37",       CLIP_UUID_STR_SIZE == 37u);
    TEST("CLIP_DISPLAY_NAME_MAX == 64",    CLIP_DISPLAY_NAME_MAX == 64u);
    TEST("CLIP_JOIN_KEY_MAX == 32",        CLIP_JOIN_KEY_MAX == 32u);
}

static void test_error_strings(void)
{
    printf("\n[Error String Table]\n");
    TEST("CLIP_OK string not empty",
         clip_error_string(CLIP_OK) != NULL &&
         clip_error_string(CLIP_OK)[0] != '\0');
    TEST("CLIP_ERR_AUTH string not empty",
         clip_error_string(CLIP_ERR_AUTH) != NULL &&
         clip_error_string(CLIP_ERR_AUTH)[0] != '\0');
    TEST("CLIP_ERR_PTT_BUSY string not empty",
         clip_error_string(CLIP_ERR_PTT_BUSY) != NULL &&
         clip_error_string(CLIP_ERR_PTT_BUSY)[0] != '\0');
    TEST("CLIP_ERR_SHUTDOWN string not empty",
         clip_error_string(CLIP_ERR_SHUTDOWN) != NULL &&
         clip_error_string(CLIP_ERR_SHUTDOWN)[0] != '\0');
    /* Unknown code should return a non-NULL, non-empty fallback */
    TEST("Unknown error code returns fallback string",
         clip_error_string((ClipError)(-999)) != NULL &&
         clip_error_string((ClipError)(-999))[0] != '\0');
}

static void test_enum_values(void)
{
    printf("\n[Enum Sanity Checks]\n");
    TEST("CLIP_PRESENCE_OFFLINE == 0",  CLIP_PRESENCE_OFFLINE  == 0);
    TEST("CLIP_PRESENCE_ONLINE  == 1",  CLIP_PRESENCE_ONLINE   == 1);
    TEST("CLIP_SPEECH_MODE_NONE == 0",  CLIP_SPEECH_MODE_NONE  == 0x00);
    TEST("CLIP_SPEECH_MODE_SERVER_MEDIATED == 1",
         CLIP_SPEECH_MODE_SERVER_MEDIATED == 0x01);
    TEST("CLIP_SPEECH_MODE_E2E_PRIVATE == 2",
         CLIP_SPEECH_MODE_E2E_PRIVATE == 0x02);
    TEST("CLIP_PTT_FLOOR_FREE == 0",  CLIP_PTT_FLOOR_FREE == 0);
    TEST("CLIP_PTT_FLOOR_HELD == 1",  CLIP_PTT_FLOOR_HELD == 1);
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=========================================\n");
    printf(" CLICOM Phase 0 — Unit Test: Version\n");
    printf("=========================================\n");

    test_software_version();
    test_protocol_version();
    test_wire_constants();
    test_uuid_sizes();
    test_error_strings();
    test_enum_values();

    printf("\n=========================================\n");
    printf(" Total: %d passed", g_pass);
    if (g_fail > 0) {
        printf(", %d FAILED", g_fail);
    }
    printf("\n");
    printf(" Result: %s\n", g_fail == 0 ? "ALL TESTS PASSED" : "FAILURES DETECTED");
    printf("=========================================\n\n");

    return g_fail == 0 ? 0 : 1;
}

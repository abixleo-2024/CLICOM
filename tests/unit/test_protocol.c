/*
 * tests/unit/test_protocol.c — Phase 1 Unit Tests: Common Types & Protocol
 *
 * Verifies:
 *   1. UUID size is exactly 16 bytes.
 *   2. UUID string representation and parsing.
 *   3. Protocol magic equals 0x434C4950.
 *   4. Protocol version is CLIPv1.0.
 *   5. Software version remains 2.0.0.
 *   6. Protocol header size/layout is deterministic (36 bytes).
 *   7. Required message types have stable distinct values.
 *   8. CRC32 known vector: "123456789" -> 0xCBF43926.
 *   9. Valid frame encode -> decode round trip.
 *  10. Invalid magic is rejected (CLIP_ERR_BAD_MAGIC).
 *  11. Invalid protocol version is rejected (CLIP_ERR_VERSION).
 *  12. Truncated frame is rejected (CLIP_ERR_TRUNCATED).
 *  13. Payload length exceeding maximum is rejected (CLIP_ERR_PAYLOAD_SIZE).
 *  14. Corrupted CRC is rejected (CLIP_ERR_CRC).
 *  15. Unsupported message type is rejected (CLIP_ERR_BAD_MSG_TYPE).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clip_version.h"
#include "clip_protocol.h"
#include "clip_types.h"
#include "clip_errors.h"

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

/* ── 1 & 2. UUID Tests ──────────────────────────────────────────────────── */

static void test_uuid(void)
{
    printf("\n[1 & 2. UUID Representation & String Helpers]\n");

    TEST("sizeof(ClipUuid) == 16", sizeof(ClipUuid) == 16);
    TEST("CLIP_UUID_BYTES == 16", CLIP_UUID_BYTES == 16u);
    TEST("CLIP_UUID_STR_SIZE == 37", CLIP_UUID_STR_SIZE == 37u);

    ClipUuid zero_uuid;
    clip_uuid_zero(&zero_uuid);
    TEST("clip_uuid_zero produces all zeros", clip_uuid_is_zero(&zero_uuid));

    const char* valid_str = "c759ed2d-0269-4eeb-bb24-81efcb8bc9f3";
    ClipUuid parsed_uuid;
    clip_uuid_zero(&parsed_uuid);

    int parse_rc = clip_uuid_from_string(&parsed_uuid, valid_str);
    TEST("clip_uuid_from_string succeeds on valid format", parse_rc == CLIP_OK);
    TEST("parsed UUID is not zero", !clip_uuid_is_zero(&parsed_uuid));

    char formatted[CLIP_UUID_STR_SIZE];
    int fmt_rc = clip_uuid_to_string(&parsed_uuid, formatted, sizeof(formatted));
    TEST("clip_uuid_to_string succeeds", fmt_rc == CLIP_OK);
    TEST("formatted UUID string matches original exactly",
         strcmp(formatted, valid_str) == 0);

    ClipUuid copy_uuid;
    clip_uuid_copy(&copy_uuid, &parsed_uuid);
    TEST("clip_uuid_equal succeeds on identical UUIDs",
         clip_uuid_equal(&copy_uuid, &parsed_uuid));
    TEST("clip_uuid_compare returns 0 on identical UUIDs",
         clip_uuid_compare(&copy_uuid, &parsed_uuid) == 0);

    /* Mutate one byte and verify inequality */
    copy_uuid.bytes[0] ^= 0xFF;
    TEST("clip_uuid_equal returns false on modified byte",
         !clip_uuid_equal(&copy_uuid, &parsed_uuid));

    /* Malformed string checks */
    ClipUuid bad_uuid;
    TEST("clip_uuid_from_string rejects too short string",
         clip_uuid_from_string(&bad_uuid, "c759ed2d-0269-4eeb") == CLIP_ERR_INVALID);
    TEST("clip_uuid_from_string rejects missing hyphens",
         clip_uuid_from_string(&bad_uuid, "c759ed2d0026904eeb0bb24081efcb8bc9f3") == CLIP_ERR_INVALID);
    TEST("clip_uuid_from_string rejects invalid hex characters",
         clip_uuid_from_string(&bad_uuid, "z759ed2d-0269-4eeb-bb24-81efcb8bc9f3") == CLIP_ERR_INVALID);
}

/* ── 3, 4, 5, 6. Protocol Constants & Header Layout ──────────────────────── */

static void test_protocol_constants_and_header(void)
{
    printf("\n[3, 4, 5, 6. Protocol Constants & Header Layout]\n");

    TEST("Protocol magic == 0x434C4950", CLIP_PROTOCOL_MAGIC == 0x434C4950u);
    TEST("Protocol version major == 1", CLIP_PROTOCOL_VERSION_MAJOR == 1);
    TEST("Protocol version minor == 0", CLIP_PROTOCOL_VERSION_MINOR == 0);
    TEST("Software version major == 2", CLICOM_VERSION_MAJOR == 2);
    TEST("Software version minor == 0", CLICOM_VERSION_MINOR == 0);
    TEST("Software version patch == 0", CLICOM_VERSION_PATCH == 0);

    TEST("Wire header size == 36 bytes", CLIP_HEADER_SIZE == 36u);
    TEST("Session UUID field in header == 16 bytes", CLIP_SESSION_UUID_SIZE == 16u);
    TEST("CRC32 size == 4 bytes", CLIP_CRC32_SIZE == 4u);
    TEST("Minimum frame size == 40 bytes (36 + 4)", CLIP_MIN_FRAME_SIZE == 40u);
    TEST("Maximum payload size == 65536 bytes", CLIP_MAX_PAYLOAD_SIZE == (64u * 1024u));
}

/* ── 7. Message Types ───────────────────────────────────────────────────── */

static void test_message_types(void)
{
    printf("\n[7. Protocol Message Types]\n");

    TEST("CLIP_MSG_REGISTER == 0x0005", CLIP_MSG_REGISTER == 0x0005);
    TEST("CLIP_MSG_REGISTER_ACK == 0x0006", CLIP_MSG_REGISTER_ACK == 0x0006);
    TEST("CLIP_MSG_PRESENCE == 0x0010", CLIP_MSG_PRESENCE == 0x0010);
    TEST("CLIP_MSG_CHANNEL_CREATE == 0x0020", CLIP_MSG_CHANNEL_CREATE == 0x0020);
    TEST("CLIP_MSG_CHANNEL_JOIN == 0x0022", CLIP_MSG_CHANNEL_JOIN == 0x0022);
    TEST("CLIP_MSG_CHANNEL_JOIN_ACK == 0x0023", CLIP_MSG_CHANNEL_JOIN_ACK == 0x0023);
    TEST("CLIP_MSG_CONNECTION_REQUEST == 0x0030", CLIP_MSG_CONNECTION_REQUEST == 0x0030);
    TEST("CLIP_MSG_CONN_ACCEPT == 0x0031", CLIP_MSG_CONN_ACCEPT == 0x0031);
    TEST("CLIP_MSG_CONN_DECLINE == 0x0032", CLIP_MSG_CONN_DECLINE == 0x0032);
    TEST("CLIP_MSG_CONNECTION_RESPONSE == 0x0034", CLIP_MSG_CONNECTION_RESPONSE == 0x0034);
    TEST("CLIP_MSG_SESSION_START == 0x0040", CLIP_MSG_SESSION_START == 0x0040);
    TEST("CLIP_MSG_SESSION_END == 0x0041", CLIP_MSG_SESSION_END == 0x0041);
    TEST("CLIP_MSG_PTT_REQUEST == 0x0050", CLIP_MSG_PTT_REQUEST == 0x0050);
    TEST("CLIP_MSG_PTT_GRANT == 0x0051", CLIP_MSG_PTT_GRANT == 0x0051);
    TEST("CLIP_MSG_PTT_RELEASE == 0x0053", CLIP_MSG_PTT_RELEASE == 0x0053);
    TEST("CLIP_MSG_ERROR == 0x00F0", CLIP_MSG_ERROR == 0x00F0);

    TEST("clip_message_type_is_valid recognizes REGISTER",
         clip_message_type_is_valid(CLIP_MSG_REGISTER));
    TEST("clip_message_type_is_valid recognizes PTT_REQUEST",
         clip_message_type_is_valid(CLIP_MSG_PTT_REQUEST));
    TEST("clip_message_type_is_valid rejects unallocated code 0x9999",
         !clip_message_type_is_valid(0x9999));
    TEST("clip_message_type_string returns non-empty for REGISTER",
         strlen(clip_message_type_string(CLIP_MSG_REGISTER)) > 0);
}

/* ── 8. CRC32 Known Test Vector ─────────────────────────────────────────── */

static void test_crc32(void)
{
    printf("\n[8. CRC32 Standard Test Vector]\n");

    /* Standard IEEE 802.3 test vector: "123456789" -> 0xCBF43926 */
    const uint8_t vector[] = "123456789";
    uint32_t crc = clip_crc32(vector, 9);
    TEST("CRC32 of '123456789' == 0xCBF43926", crc == 0xCBF43926u);

    /* Empty buffer test */
    uint32_t crc_empty = clip_crc32(NULL, 0);
    TEST("CRC32 of empty buffer == 0x00000000", crc_empty == 0x00000000u);
}

/* ── 9. Valid Frame Encode -> Decode Round Trip ─────────────────────────── */

static void test_frame_roundtrip(void)
{
    printf("\n[9. Frame Encode -> Decode Round Trip]\n");

    const uint8_t test_session[CLIP_UUID_BYTES] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    const uint8_t payload[] = "NODE-A Registration Payload";
    uint32_t payload_len = (uint32_t)strlen((const char*)payload);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_REGISTER, payload_len, 42, test_session);

    uint8_t frame_buf[256];
    size_t frame_len = 0;
    ClipError enc_rc = clip_frame_encode(&tx_hdr, payload, frame_buf, sizeof(frame_buf), &frame_len);

    TEST("clip_frame_encode succeeds", enc_rc == CLIP_OK);
    TEST("Encoded frame length == 36 + payload_len + 4",
         frame_len == (36u + payload_len + 4u));

    ClipFrameHeader rx_hdr;
    const uint8_t* rx_payload = NULL;
    uint32_t rx_payload_len = 0;

    ClipError dec_rc = clip_frame_decode(frame_buf, frame_len, &rx_hdr, &rx_payload, &rx_payload_len);
    TEST("clip_frame_decode succeeds", dec_rc == CLIP_OK);
    TEST("Decoded magic matches CLIP_PROTOCOL_MAGIC", rx_hdr.magic == CLIP_PROTOCOL_MAGIC);
    TEST("Decoded version matches 0x0100", rx_hdr.version == 0x0100);
    TEST("Decoded msg_type matches CLIP_MSG_REGISTER", rx_hdr.msg_type == CLIP_MSG_REGISTER);
    TEST("Decoded seq_num matches 42", rx_hdr.seq_num == 42);
    TEST("Decoded payload_len matches original", rx_payload_len == payload_len);
    TEST("Decoded session_uuid matches original",
         memcmp(rx_hdr.session_uuid, test_session, CLIP_UUID_BYTES) == 0);
    TEST("Decoded payload data matches original bytes",
         rx_payload != NULL && memcmp(rx_payload, payload, payload_len) == 0);

    /* Zero-payload round trip (e.g. HEARTBEAT) */
    ClipFrameHeader hb_tx;
    clip_frame_header_init(&hb_tx, CLIP_MSG_HEARTBEAT, 0, 100, NULL);
    size_t hb_len = 0;
    ClipError hb_enc = clip_frame_encode(&hb_tx, NULL, frame_buf, sizeof(frame_buf), &hb_len);
    TEST("Zero-payload frame encodes to exactly 40 bytes", hb_enc == CLIP_OK && hb_len == 40u);

    ClipFrameHeader hb_rx;
    const uint8_t* hb_payload = NULL;
    uint32_t hb_payload_len = 99;
    ClipError hb_dec = clip_frame_decode(frame_buf, hb_len, &hb_rx, &hb_payload, &hb_payload_len);
    TEST("Zero-payload frame decodes successfully",
         hb_dec == CLIP_OK && hb_payload_len == 0 && hb_payload == NULL);
}

/* ── 10, 11, 12, 13, 14, 15. Malformed & Truncated Frame Rejections ─────── */

static void test_frame_rejections(void)
{
    printf("\n[10-15. Malformed, Truncated & Invalid Frame Rejections]\n");

    const uint8_t payload[] = "Safety Validation Payload";
    uint32_t payload_len = (uint32_t)strlen((const char*)payload);

    ClipFrameHeader tx_hdr;
    clip_frame_header_init(&tx_hdr, CLIP_MSG_PRESENCE, payload_len, 1, NULL);

    uint8_t frame_buf[256];
    size_t frame_len = 0;
    clip_frame_encode(&tx_hdr, payload, frame_buf, sizeof(frame_buf), &frame_len);

    ClipFrameHeader rx_hdr;
    const uint8_t* rx_payload = NULL;
    uint32_t rx_payload_len = 0;

    /* 10. Invalid magic rejected */
    uint8_t bad_magic_buf[256];
    memcpy(bad_magic_buf, frame_buf, frame_len);
    bad_magic_buf[0] = 'X'; /* corrupt magic 0x43 -> 'X' */
    ClipError err_magic = clip_frame_decode(bad_magic_buf, frame_len, &rx_hdr, &rx_payload, &rx_payload_len);
    TEST("Invalid magic rejected with CLIP_ERR_BAD_MAGIC", err_magic == CLIP_ERR_BAD_MAGIC);

    /* 11. Invalid protocol version rejected */
    uint8_t bad_ver_buf[256];
    memcpy(bad_ver_buf, frame_buf, frame_len);
    bad_ver_buf[4] = 0x09; /* major version 9 instead of 1 */
    /* Recalculate CRC so CRC doesn't fail first */
    uint32_t new_crc = clip_crc32(bad_ver_buf, frame_len - 4);
    bad_ver_buf[frame_len - 4] = (uint8_t)(new_crc >> 24);
    bad_ver_buf[frame_len - 3] = (uint8_t)(new_crc >> 16);
    bad_ver_buf[frame_len - 2] = (uint8_t)(new_crc >> 8);
    bad_ver_buf[frame_len - 1] = (uint8_t)(new_crc);
    ClipError err_ver = clip_frame_decode(bad_ver_buf, frame_len, &rx_hdr, &rx_payload, &rx_payload_len);
    TEST("Incompatible major version rejected with CLIP_ERR_VERSION", err_ver == CLIP_ERR_VERSION);

    /* 12. Truncated frame rejected */
    ClipError err_trunc = clip_frame_decode(frame_buf, 20, &rx_hdr, &rx_payload, &rx_payload_len);
    TEST("Buffer shorter than minimum frame rejected with CLIP_ERR_TRUNCATED",
         err_trunc == CLIP_ERR_TRUNCATED);

    ClipError err_trunc_payload = clip_frame_decode(frame_buf, frame_len - 5, &rx_hdr, &rx_payload, &rx_payload_len);
    TEST("Buffer missing payload/CRC bytes rejected with CLIP_ERR_TRUNCATED",
         err_trunc_payload == CLIP_ERR_TRUNCATED);

    /* 13. Invalid payload length rejected */
    uint8_t huge_len_buf[64];
    memcpy(huge_len_buf, frame_buf, 36);
    /* set payload_len = 70000 (> 64 KiB limit) */
    huge_len_buf[8]  = 0x00;
    huge_len_buf[9]  = 0x01;
    huge_len_buf[10] = 0x11;
    huge_len_buf[11] = 0x70;
    ClipError err_size = clip_frame_decode(huge_len_buf, sizeof(huge_len_buf), &rx_hdr, &rx_payload, &rx_payload_len);
    TEST("Payload length exceeding 64 KiB rejected with CLIP_ERR_PAYLOAD_SIZE",
         err_size == CLIP_ERR_PAYLOAD_SIZE);

    /* 14. Corrupted CRC rejected */
    uint8_t bad_crc_buf[256];
    memcpy(bad_crc_buf, frame_buf, frame_len);
    bad_crc_buf[frame_len - 1] ^= 0x01; /* flip lowest CRC bit */
    ClipError err_crc = clip_frame_decode(bad_crc_buf, frame_len, &rx_hdr, &rx_payload, &rx_payload_len);
    TEST("Corrupted CRC trailer rejected with CLIP_ERR_CRC", err_crc == CLIP_ERR_CRC);

    /* Corrupted payload rejected via CRC */
    uint8_t bad_payload_buf[256];
    memcpy(bad_payload_buf, frame_buf, frame_len);
    bad_payload_buf[36] ^= 0x55; /* corrupt first payload byte */
    ClipError err_corrupt = clip_frame_decode(bad_payload_buf, frame_len, &rx_hdr, &rx_payload, &rx_payload_len);
    TEST("Tampered payload detected and rejected with CLIP_ERR_CRC", err_corrupt == CLIP_ERR_CRC);

    /* 15. Unsupported message type rejected */
    uint8_t bad_type_buf[256];
    memcpy(bad_type_buf, frame_buf, frame_len);
    bad_type_buf[6] = 0x77;
    bad_type_buf[7] = 0x77;
    new_crc = clip_crc32(bad_type_buf, frame_len - 4);
    bad_type_buf[frame_len - 4] = (uint8_t)(new_crc >> 24);
    bad_type_buf[frame_len - 3] = (uint8_t)(new_crc >> 16);
    bad_type_buf[frame_len - 2] = (uint8_t)(new_crc >> 8);
    bad_type_buf[frame_len - 1] = (uint8_t)(new_crc);
    ClipError err_type = clip_frame_decode(bad_type_buf, frame_len, &rx_hdr, &rx_payload, &rx_payload_len);
    TEST("Unsupported message type rejected with CLIP_ERR_BAD_MSG_TYPE",
         err_type == CLIP_ERR_BAD_MSG_TYPE);
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("============================================================\n");
    printf(" CLICOM Phase 1 — Unit Test: Common Types & Protocol\n");
    printf("============================================================\n");

    test_uuid();
    test_protocol_constants_and_header();
    test_message_types();
    test_crc32();
    test_frame_roundtrip();
    test_frame_rejections();

    printf("\n============================================================\n");
    printf(" Total: %d passed", g_pass);
    if (g_fail > 0) {
        printf(", %d FAILED", g_fail);
    }
    printf("\n");
    printf(" Result: %s\n", g_fail == 0 ? "ALL TESTS PASSED" : "FAILURES DETECTED");
    printf("============================================================\n\n");

    return g_fail == 0 ? 0 : 1;
}

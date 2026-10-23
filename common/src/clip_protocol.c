/*
 * clip_protocol.c — CLICOM Protocol Implementation (CLIPv1.0)
 *
 * Implements:
 *   - Canonical UUID helpers (16-byte representation)
 *   - Standard IEEE 802.3 CRC32 framing integrity check
 *   - Wire frame / header serialization and deserialization
 *   - Frame validation (bounds, truncation, magic, version, CRC)
 *
 * NOTE ON INTEGRITY:
 *   CRC32 is strictly used for framing integrity (boundary detection,
 *   corruption detection, truncation detection). It is NOT a security
 *   mechanism and provides neither encryption nor authentication.
 *   TLS 1.3 provides cryptographic transport security in later phases.
 */

#include "clip_protocol.h"
#include <stdio.h>
#include <string.h>

/* ── UUID Helpers ────────────────────────────────────────────────────────── */

void clip_uuid_zero(ClipUuid* uuid)
{
    if (uuid) {
        memset(uuid->bytes, 0, CLIP_UUID_BYTES);
    }
}

bool clip_uuid_is_zero(const ClipUuid* uuid)
{
    if (!uuid) return true;
    for (size_t i = 0; i < CLIP_UUID_BYTES; i++) {
        if (uuid->bytes[i] != 0) return false;
    }
    return true;
}

int clip_uuid_compare(const ClipUuid* a, const ClipUuid* b)
{
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    return memcmp(a->bytes, b->bytes, CLIP_UUID_BYTES);
}

bool clip_uuid_equal(const ClipUuid* a, const ClipUuid* b)
{
    return clip_uuid_compare(a, b) == 0;
}

void clip_uuid_copy(ClipUuid* dst, const ClipUuid* src)
{
    if (dst && src) {
        memcpy(dst->bytes, src->bytes, CLIP_UUID_BYTES);
    }
}

int clip_uuid_to_string(const ClipUuid* uuid, char* out_str, size_t str_len)
{
    if (!uuid || !out_str || str_len < CLIP_UUID_STR_SIZE) {
        return CLIP_ERR_INVALID;
    }

    const uint8_t* b = uuid->bytes;
    int written = snprintf(out_str, str_len,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0], b[1], b[2], b[3],
        b[4], b[5],
        b[6], b[7],
        b[8], b[9],
        b[10], b[11], b[12], b[13], b[14], b[15]);

    return (written == 36) ? CLIP_OK : CLIP_ERR_INVALID;
}

static int hex_char_to_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int clip_uuid_from_string(ClipUuid* out_uuid, const char* str)
{
    if (!out_uuid || !str) return CLIP_ERR_INVALID;

    /* Expected canonical format: 8-4-4-4-12 hex characters (36 chars total) */
    if (strlen(str) != 36) return CLIP_ERR_INVALID;

    if (str[8] != '-' || str[13] != '-' || str[18] != '-' || str[23] != '-') {
        return CLIP_ERR_INVALID;
    }

    size_t byte_idx = 0;
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) continue;

        int hi = hex_char_to_val(str[i]);
        i++;
        int lo = hex_char_to_val(str[i]);

        if (hi < 0 || lo < 0) return CLIP_ERR_INVALID;

        if (byte_idx < CLIP_UUID_BYTES) {
            out_uuid->bytes[byte_idx++] = (uint8_t)((hi << 4) | lo);
        }
    }

    return (byte_idx == CLIP_UUID_BYTES) ? CLIP_OK : CLIP_ERR_INVALID;
}

/* ── CRC32 Implementation (IEEE 802.3 Standard) ─────────────────────────── */

/*
 * Static precomputed table for polynomial 0xEDB88320 (reversed / little-endian).
 * Thread-safe, deterministic, requires zero initialization or locks.
 */
static const uint32_t s_crc32_table[256] = {
    0x00000000u, 0x77073096u, 0xEE0E612Cu, 0x990951BAu, 0x076DC419u, 0x706AF48Fu, 0xE963A535u, 0x9E6495A3u,
    0x0EDB8832u, 0x79DCB8A4u, 0xE0D5E91Eu, 0x97D2D988u, 0x09B64C2Bu, 0x7EB17CBDu, 0xE7B82D07u, 0x90BF1D91u,
    0x1DB71064u, 0x6AB020F2u, 0xF3B97148u, 0x84BE41DEu, 0x1ADAD47Du, 0x6DDDE4EBu, 0xF4D4B551u, 0x83D385C7u,
    0x136C9856u, 0x646BA8C0u, 0xFD62F97Au, 0x8A65C9ECu, 0x14015C4Fu, 0x63066CD9u, 0xFA0F3D63u, 0x8D080DF5u,
    0x3B6E20C8u, 0x4C69105Eu, 0xD56041E4u, 0xA2677172u, 0x3C03E4D1u, 0x4B04D447u, 0xD20D85FDu, 0xA50AB56Bu,
    0x35B5A8FAu, 0x42B2986Cu, 0xDBBBC9D6u, 0xACBCF940u, 0x32D86CE3u, 0x45DF5C75u, 0xDCD60DCFu, 0xABD13D59u,
    0x26D930ACu, 0x51DE003Au, 0xC8D75180u, 0xBFD06116u, 0x21B4F4B5u, 0x56B3C423u, 0xCFBA9599u, 0xB8BDA50Fu,
    0x2802B89Eu, 0x5F058808u, 0xC60CD9B2u, 0xB10BE924u, 0x2F6F7C87u, 0x58684C11u, 0xC1611DABu, 0xB6662D3Du,
    0x76DC4190u, 0x01DB7106u, 0x98D220BCu, 0xEFD5102Au, 0x71B18589u, 0x06B6B51Fu, 0x9FBFE4A5u, 0xE8B8D433u,
    0x7807C9A2u, 0x0F00F934u, 0x9609A88Eu, 0xE10E9818u, 0x7F6A0DBBu, 0x086D3D2Du, 0x91646C97u, 0xE6635C01u,
    0x6B6B51F4u, 0x1C6C6162u, 0x856530D8u, 0xF262004Eu, 0x6C0695EDu, 0x1B01A57Bu, 0x8208F4C1u, 0xF50FC457u,
    0x65B0D9C6u, 0x12B7E950u, 0x8BBEB8EAu, 0xFCB9887Cu, 0x62DD1DDFu, 0x15DA2D49u, 0x8CD37CF3u, 0xFBD44C65u,
    0x4DB26158u, 0x3AB551CEu, 0xA3BC0074u, 0xD4BB30E2u, 0x4ADFA541u, 0x3DD895D7u, 0xA4D1C46Du, 0xD3D6F4FBu,
    0x4369E96Au, 0x346ED9FCu, 0xAD678846u, 0xDA60B8D0u, 0x44042D73u, 0x33031DE5u, 0xAA0A4C5Fu, 0xDD0D7CC9u,
    0x5005713Cu, 0x270241AAu, 0xBE0B1010u, 0xC90C2086u, 0x5768B525u, 0x206F85B3u, 0xB966D409u, 0xCE61E49Fu,
    0x5EDEF90Eu, 0x29D9C998u, 0xB0D09822u, 0xC7D7A8B4u, 0x59B33D17u, 0x2EB40D81u, 0xB7BD5C3Bu, 0xC0BA6CADu,
    0xEDB88320u, 0x9ABFB3B6u, 0x03B6E20Cu, 0x74B1D29Au, 0xEAD54739u, 0x9DD277AFu, 0x04DB2615u, 0x73DC1683u,
    0xE3630B12u, 0x94643B84u, 0x0D6D6A3Eu, 0x7A6A5AA8u, 0xE40ECF0Bu, 0x9309FF9Du, 0x0A00AE27u, 0x7D079EB1u,
    0xF00F9344u, 0x8708A3D2u, 0x1E01F268u, 0x6906C2FEu, 0xF762575Du, 0x806567CBu, 0x196C3671u, 0x6E6B06E7u,
    0xFED41B76u, 0x89D32BE0u, 0x10DA7A5Au, 0x67DD4ACCu, 0xF9B9DF6Fu, 0x8EBEEFF9u, 0x17B7BE43u, 0x60B08ED5u,
    0xD6D6A3E8u, 0xA1D1937Eu, 0x38D8C2C4u, 0x4FDFF252u, 0xD1BB67F1u, 0xA6BC5767u, 0x3FB506DDu, 0x48B2364Bu,
    0xD80D2BDAu, 0xAF0A1B4Cu, 0x36034AF6u, 0x41047A60u, 0xDF60EFC3u, 0xA867DF55u, 0x316E8EEFu, 0x4669BE79u,
    0xCB61B38Cu, 0xBC66831Au, 0x256FD2A0u, 0x5268E236u, 0xCC0C7795u, 0xBB0B4703u, 0x220216B9u, 0x5505262Fu,
    0xC5BA3BBEu, 0xB2BD0B28u, 0x2BB45A92u, 0x5CB36A04u, 0xC2D7FFA7u, 0xB5D0CF31u, 0x2CD99E8Bu, 0x5BDEAE1Du,
    0x9B64C2B0u, 0xEC63F226u, 0x756AA39Cu, 0x026D930Au, 0x9C0906A9u, 0xEB0E363Fu, 0x72076785u, 0x05005713u,
    0x95BF4A82u, 0xE2B87A14u, 0x7BB12BAEu, 0x0CB61B38u, 0x92D28E9Bu, 0xE5D5BE0Du, 0x7CDCEFB7u, 0x0BDBDF21u,
    0x86D3D2D4u, 0xF1D4E242u, 0x68DDB3F8u, 0x1FDA836Eu, 0x81BE16CDu, 0xF6B9265Bu, 0x6FB077E1u, 0x18B74777u,
    0x88085AE6u, 0xFF0F6A70u, 0x66063BCAu, 0x11010B5Cu, 0x8F659EFFu, 0xF862AE69u, 0x616BFFD3u, 0x166CCF45u,
    0xA00AE278u, 0xD70DD2EEu, 0x4E048354u, 0x3903B3C2u, 0xA7672661u, 0xD06016F7u, 0x4969474Du, 0x3E6E77DBu,
    0xAED16A4Au, 0xD9D65ADCu, 0x40DF0B66u, 0x37D83BF0u, 0xA9BCAE53u, 0xDEBB9EC5u, 0x47B2CF7Fu, 0x30B5FFE9u,
    0xBDBDF21Cu, 0xCABAC28Au, 0x53B39330u, 0x24B4A3A6u, 0xBAD03605u, 0xCDD70693u, 0x54DE5729u, 0x23D967BFu,
    0xB3667A2Eu, 0xC4614AB8u, 0x5D681B02u, 0x2A6F2B94u, 0xB40BBE37u, 0xC30C8EA1u, 0x5A05DF1Bu, 0x2D02EF8Du
};

uint32_t clip_crc32_update(uint32_t running_crc, const uint8_t* data, size_t length)
{
    if (!data || length == 0) return running_crc;

    uint32_t crc = running_crc;
    for (size_t i = 0; i < length; i++) {
        crc = s_crc32_table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc;
}

uint32_t clip_crc32(const uint8_t* data, size_t length)
{
    /* Initial value 0xFFFFFFFF, inverted at end */
    return clip_crc32_update(0xFFFFFFFFu, data, length) ^ 0xFFFFFFFFu;
}

/* ── Message Type Helpers ────────────────────────────────────────────────── */

bool clip_message_type_is_valid(uint16_t msg_type)
{
    switch ((ClipMessageType)msg_type) {
    case CLIP_MSG_HELLO:
    case CLIP_MSG_AUTH:
    case CLIP_MSG_AUTH_OK:
    case CLIP_MSG_AUTH_FAIL:
    case CLIP_MSG_REGISTER:
    case CLIP_MSG_REGISTER_OK:
    case CLIP_MSG_PRESENCE:
    case CLIP_MSG_HEARTBEAT:
    case CLIP_MSG_HEARTBEAT_ACK:
    case CLIP_MSG_CHANNEL_CREATE:
    case CLIP_MSG_CHANNEL_CREATE_OK:
    case CLIP_MSG_CHANNEL_JOIN:
    case CLIP_MSG_CHANNEL_JOIN_OK:
    case CLIP_MSG_CHANNEL_LEAVE:
    case CLIP_MSG_CHANNEL_REVOKE_KEY:
    case CLIP_MSG_CHANNEL_REVOKE_KEY_OK:
    case CLIP_MSG_CHANNEL_CLOSE:
    case CLIP_MSG_CHANNEL_CLOSE_OK:
    case CLIP_MSG_CHANNEL_LIST:
    case CLIP_MSG_CHANNEL_LIST_RESP:
    case CLIP_MSG_CHANNEL_MEMBER_UPD:
    case CLIP_MSG_CHANNEL_FAIL:
    case CLIP_MSG_CHANNEL_MEMBERS_REQ:
    case CLIP_MSG_CHANNEL_MEMBERS_RESP:
    case CLIP_MSG_CONN_REQUEST:
    case CLIP_MSG_CONN_ACCEPT:
    case CLIP_MSG_CONN_DECLINE:
    case CLIP_MSG_CONN_TIMEOUT:
    case CLIP_MSG_CONNECTION_RESPONSE:
    case CLIP_MSG_CONN_FAIL:
    case CLIP_MSG_CONN_LIST_REQ:
    case CLIP_MSG_CONN_LIST_RESP:
    case CLIP_MSG_SESSION_START:
    case CLIP_MSG_SESSION_END:
    case CLIP_MSG_SESSION_START_ACK:
    case CLIP_MSG_SESSION_END_ACK:
    case CLIP_MSG_SESSION_FAIL:
    case CLIP_MSG_PTT_REQUEST:
    case CLIP_MSG_PTT_GRANT:
    case CLIP_MSG_PTT_DENY:
    case CLIP_MSG_PTT_RELEASE:
    case CLIP_MSG_PTT_NOTIFY:
    case CLIP_MSG_PTT_FLOOR_RELEASED:
    case CLIP_MSG_PTT_FLOOR_STATUS_REQ:
    case CLIP_MSG_PTT_FLOOR_STATUS_RESP:
    case CLIP_MSG_PTT_FLOOR_RENEW:
    case CLIP_MSG_PTT_FLOOR_RENEW_ACK:
    case CLIP_MSG_AUDIO_FRAME:
    case CLIP_MSG_CAPTION:
    case CLIP_MSG_SESSION_LOG_LIST_REQ:
    case CLIP_MSG_SESSION_LOG_LIST_RESP:
    case CLIP_MSG_SESSION_LOG_GET_REQ:
    case CLIP_MSG_SESSION_LOG_GET_RESP:
    case CLIP_MSG_NOTE_CREATE:
    case CLIP_MSG_NOTE_CREATE_OK:
    case CLIP_MSG_NOTE_LIST_REQ:
    case CLIP_MSG_NOTE_LIST_RESP:
    case CLIP_MSG_NOTE_FAIL:
    case CLIP_MSG_SECURITY_EVENT:
    case CLIP_MSG_SECURITY_EVENT_LIST_REQ:
    case CLIP_MSG_SECURITY_EVENT_LIST_RESP:
    case CLIP_MSG_SECURITY_EVENT_GET_REQ:
    case CLIP_MSG_SECURITY_EVENT_GET_RESP:
    case CLIP_MSG_SECURITY_EVENT_FAIL:
    case CLIP_MSG_SECURITY_TRANSCRIPT:
    case CLIP_MSG_ADMIN_ACTION:
    case CLIP_MSG_ADMIN_ACTION_OK:
    case CLIP_MSG_ADMIN_ACTION_FAIL:
    case CLIP_MSG_ADMIN_AUTH_REQ:
    case CLIP_MSG_ADMIN_AUTH_RESP:
    case CLIP_MSG_ADMIN_EVENTS_REQ:
    case CLIP_MSG_ADMIN_EVENTS_RESP:
    case CLIP_MSG_ADMIN_AUDIT_REQ:
    case CLIP_MSG_ADMIN_AUDIT_RESP:
    case CLIP_MSG_ERROR:
    case CLIP_MSG_GOODBYE:
        return true;
    default:
        return false;
    }
}

const char* clip_message_type_string(ClipMessageType type)
{
    switch (type) {
    case CLIP_MSG_HELLO:              return "HELLO";
    case CLIP_MSG_AUTH:               return "AUTH";
    case CLIP_MSG_AUTH_OK:            return "AUTH_OK";
    case CLIP_MSG_AUTH_FAIL:          return "AUTH_FAIL";
    case CLIP_MSG_REGISTER:           return "REGISTER";
    case CLIP_MSG_REGISTER_OK:        return "REGISTER_ACK";
    case CLIP_MSG_PRESENCE:           return "PRESENCE";
    case CLIP_MSG_HEARTBEAT:          return "HEARTBEAT";
    case CLIP_MSG_HEARTBEAT_ACK:      return "HEARTBEAT_ACK";
    case CLIP_MSG_CHANNEL_CREATE:     return "CHANNEL_CREATE";
    case CLIP_MSG_CHANNEL_CREATE_OK:  return "CHANNEL_CREATE_OK";
    case CLIP_MSG_CHANNEL_JOIN:       return "CHANNEL_JOIN";
    case CLIP_MSG_CHANNEL_JOIN_OK:    return "CHANNEL_JOIN_ACK";
    case CLIP_MSG_CHANNEL_LEAVE:      return "CHANNEL_LEAVE";
    case CLIP_MSG_CHANNEL_REVOKE_KEY: return "CHANNEL_REVOKE_KEY";
    case CLIP_MSG_CHANNEL_REVOKE_KEY_OK: return "CHANNEL_REVOKE_KEY_OK";
    case CLIP_MSG_CHANNEL_CLOSE:      return "CHANNEL_CLOSE";
    case CLIP_MSG_CHANNEL_CLOSE_OK:   return "CHANNEL_CLOSE_OK";
    case CLIP_MSG_CHANNEL_LIST:       return "CHANNEL_LIST";
    case CLIP_MSG_CHANNEL_LIST_RESP:  return "CHANNEL_LIST_RESP";
    case CLIP_MSG_CHANNEL_MEMBER_UPD: return "CHANNEL_MEMBER_UPD";
    case CLIP_MSG_CHANNEL_FAIL:       return "CHANNEL_FAIL";
    case CLIP_MSG_CHANNEL_MEMBERS_REQ: return "CHANNEL_MEMBERS_REQ";
    case CLIP_MSG_CHANNEL_MEMBERS_RESP: return "CHANNEL_MEMBERS_RESP";
    case CLIP_MSG_CONN_REQUEST:       return "CONNECTION_REQUEST";
    case CLIP_MSG_CONN_ACCEPT:        return "CONNECTION_ACCEPT";
    case CLIP_MSG_CONN_DECLINE:       return "CONNECTION_DECLINE";
    case CLIP_MSG_CONN_TIMEOUT:       return "CONNECTION_TIMEOUT";
    case CLIP_MSG_CONNECTION_RESPONSE:return "CONNECTION_RESPONSE";
    case CLIP_MSG_CONN_FAIL:          return "CONNECTION_FAIL";
    case CLIP_MSG_CONN_LIST_REQ:      return "CONNECTION_LIST_REQ";
    case CLIP_MSG_CONN_LIST_RESP:     return "CONNECTION_LIST_RESP";
    case CLIP_MSG_SESSION_START:      return "SESSION_START";
    case CLIP_MSG_SESSION_END:        return "SESSION_END";
    case CLIP_MSG_SESSION_START_ACK:  return "SESSION_START_ACK";
    case CLIP_MSG_SESSION_END_ACK:    return "SESSION_END_ACK";
    case CLIP_MSG_SESSION_FAIL:       return "SESSION_FAIL";
    case CLIP_MSG_PTT_REQUEST:        return "PTT_REQUEST";
    case CLIP_MSG_PTT_GRANT:          return "PTT_GRANT";
    case CLIP_MSG_PTT_DENY:           return "PTT_DENY";
    case CLIP_MSG_PTT_RELEASE:        return "PTT_RELEASE";
    case CLIP_MSG_PTT_NOTIFY:         return "PTT_NOTIFY";
    case CLIP_MSG_PTT_FLOOR_RELEASED: return "PTT_FLOOR_RELEASED";
    case CLIP_MSG_PTT_FLOOR_STATUS_REQ: return "PTT_FLOOR_STATUS_REQ";
    case CLIP_MSG_PTT_FLOOR_STATUS_RESP: return "PTT_FLOOR_STATUS_RESP";
    case CLIP_MSG_PTT_FLOOR_RENEW:    return "PTT_FLOOR_RENEW";
    case CLIP_MSG_PTT_FLOOR_RENEW_ACK:return "PTT_FLOOR_RENEW_ACK";
    case CLIP_MSG_AUDIO_FRAME:        return "AUDIO_FRAME";
    case CLIP_MSG_CAPTION:            return "CAPTION";
    case CLIP_MSG_SESSION_LOG_LIST_REQ: return "SESSION_LOG_LIST_REQ";
    case CLIP_MSG_SESSION_LOG_LIST_RESP: return "SESSION_LOG_LIST_RESP";
    case CLIP_MSG_SESSION_LOG_GET_REQ:  return "SESSION_LOG_GET_REQ";
    case CLIP_MSG_SESSION_LOG_GET_RESP: return "SESSION_LOG_GET_RESP";
    case CLIP_MSG_NOTE_CREATE:          return "NOTE_CREATE";
    case CLIP_MSG_NOTE_CREATE_OK:       return "NOTE_CREATE_OK";
    case CLIP_MSG_NOTE_LIST_REQ:        return "NOTE_LIST_REQ";
    case CLIP_MSG_NOTE_LIST_RESP:       return "NOTE_LIST_RESP";
    case CLIP_MSG_NOTE_FAIL:            return "NOTE_FAIL";
    case CLIP_MSG_SECURITY_EVENT:           return "SECURITY_EVENT";
    case CLIP_MSG_SECURITY_EVENT_LIST_REQ:  return "SECURITY_EVENT_LIST_REQ";
    case CLIP_MSG_SECURITY_EVENT_LIST_RESP: return "SECURITY_EVENT_LIST_RESP";
    case CLIP_MSG_SECURITY_EVENT_GET_REQ:   return "SECURITY_EVENT_GET_REQ";
    case CLIP_MSG_SECURITY_EVENT_GET_RESP:  return "SECURITY_EVENT_GET_RESP";
    case CLIP_MSG_SECURITY_EVENT_FAIL:      return "SECURITY_EVENT_FAIL";
    case CLIP_MSG_SECURITY_TRANSCRIPT:      return "SECURITY_TRANSCRIPT";
    case CLIP_MSG_ADMIN_ACTION:       return "ADMIN_ACTION";
    case CLIP_MSG_ADMIN_ACTION_OK:    return "ADMIN_ACTION_OK";
    case CLIP_MSG_ADMIN_ACTION_FAIL:  return "ADMIN_ACTION_FAIL";
    case CLIP_MSG_ADMIN_AUTH_REQ:     return "ADMIN_AUTH_REQ";
    case CLIP_MSG_ADMIN_AUTH_RESP:    return "ADMIN_AUTH_RESP";
    case CLIP_MSG_ADMIN_EVENTS_REQ:   return "ADMIN_EVENTS_REQ";
    case CLIP_MSG_ADMIN_EVENTS_RESP:  return "ADMIN_EVENTS_RESP";
    case CLIP_MSG_ADMIN_AUDIT_REQ:    return "ADMIN_AUDIT_REQ";
    case CLIP_MSG_ADMIN_AUDIT_RESP:   return "ADMIN_AUDIT_RESP";
    case CLIP_MSG_ERROR:              return "ERROR";
    case CLIP_MSG_GOODBYE:            return "GOODBYE";
    default:                          return "UNKNOWN";
    }
}

/* ── Frame Header Initialization ────────────────────────────────────────── */

void clip_frame_header_init(ClipFrameHeader* hdr,
                            ClipMessageType  msg_type,
                            uint32_t         payload_len,
                            uint64_t         seq_num,
                            const uint8_t    session_uuid[CLIP_UUID_BYTES])
{
    if (!hdr) return;

    hdr->magic       = CLIP_PROTOCOL_MAGIC;
    hdr->version     = (uint16_t)((CLIP_PROTOCOL_VERSION_MAJOR << 8) | CLIP_PROTOCOL_VERSION_MINOR);
    hdr->msg_type    = (uint16_t)msg_type;
    hdr->flags       = CLIP_FRAME_FLAG_HAS_CRC;
    hdr->payload_len = payload_len;
    hdr->seq_num     = seq_num;

    if (session_uuid) {
        memcpy(hdr->session_uuid, session_uuid, CLIP_UUID_BYTES);
    } else {
        memset(hdr->session_uuid, 0, CLIP_UUID_BYTES);
    }
    hdr->crc32 = 0;
}

/* ── Serialization: Header ──────────────────────────────────────────────── */

ClipError clip_header_encode(const ClipFrameHeader* hdr,
                             uint8_t*               out_buf,
                             size_t                 out_buf_size)
{
    if (!hdr || !out_buf) {
        return CLIP_ERR_INVALID;
    }
    if (out_buf_size < CLIP_HEADER_SIZE) {
        return CLIP_ERR_TRUNCATED;
    }
    if (hdr->payload_len > CLIP_MAX_PAYLOAD_SIZE) {
        return CLIP_ERR_PAYLOAD_SIZE;
    }

    /* Big-endian explicit serialization (no raw struct memcpy / no padding risk) */
    /* [0..3]: magic (4 bytes) */
    out_buf[0] = (uint8_t)(hdr->magic >> 24);
    out_buf[1] = (uint8_t)(hdr->magic >> 16);
    out_buf[2] = (uint8_t)(hdr->magic >> 8);
    out_buf[3] = (uint8_t)(hdr->magic);

    /* [4..5]: proto_version (2 bytes) */
    out_buf[4] = (uint8_t)(hdr->version >> 8);
    out_buf[5] = (uint8_t)(hdr->version);

    /* [6..7]: msg_type (2 bytes) */
    out_buf[6] = (uint8_t)(hdr->msg_type >> 8);
    out_buf[7] = (uint8_t)(hdr->msg_type);

    /* [8..11]: payload_len (4 bytes) */
    out_buf[8]  = (uint8_t)(hdr->payload_len >> 24);
    out_buf[9]  = (uint8_t)(hdr->payload_len >> 16);
    out_buf[10] = (uint8_t)(hdr->payload_len >> 8);
    out_buf[11] = (uint8_t)(hdr->payload_len);

    /* [12..19]: seq_num (8 bytes) */
    out_buf[12] = (uint8_t)(hdr->seq_num >> 56);
    out_buf[13] = (uint8_t)(hdr->seq_num >> 48);
    out_buf[14] = (uint8_t)(hdr->seq_num >> 40);
    out_buf[15] = (uint8_t)(hdr->seq_num >> 32);
    out_buf[16] = (uint8_t)(hdr->seq_num >> 24);
    out_buf[17] = (uint8_t)(hdr->seq_num >> 16);
    out_buf[18] = (uint8_t)(hdr->seq_num >> 8);
    out_buf[19] = (uint8_t)(hdr->seq_num);

    /* [20..35]: session_uuid (16 raw bytes) */
    memcpy(&out_buf[20], hdr->session_uuid, CLIP_UUID_BYTES);

    return CLIP_OK;
}

/* ── Deserialization: Header ────────────────────────────────────────────── */

ClipError clip_header_decode(ClipFrameHeader* out_hdr,
                             const uint8_t*   in_buf,
                             size_t           in_buf_size)
{
    if (!out_hdr || !in_buf) {
        return CLIP_ERR_INVALID;
    }
    if (in_buf_size < CLIP_HEADER_SIZE) {
        return CLIP_ERR_TRUNCATED;
    }

    /* 1. Parse and validate magic */
    uint32_t magic = ((uint32_t)in_buf[0] << 24) |
                     ((uint32_t)in_buf[1] << 16) |
                     ((uint32_t)in_buf[2] << 8)  |
                      (uint32_t)in_buf[3];

    if (magic != CLIP_PROTOCOL_MAGIC) {
        return CLIP_ERR_BAD_MAGIC;
    }

    /* 2. Parse and validate protocol version */
    uint16_t version = ((uint16_t)in_buf[4] << 8) | (uint16_t)in_buf[5];
    uint8_t major = (uint8_t)(version >> 8);
    if (major != CLIP_PROTOCOL_VERSION_MAJOR) {
        return CLIP_ERR_VERSION;
    }

    /* 3. Parse and validate message type */
    uint16_t msg_type = ((uint16_t)in_buf[6] << 8) | (uint16_t)in_buf[7];
    if (!clip_message_type_is_valid(msg_type)) {
        return CLIP_ERR_BAD_MSG_TYPE;
    }

    /* 4. Parse and validate payload length */
    uint32_t payload_len = ((uint32_t)in_buf[8]  << 24) |
                           ((uint32_t)in_buf[9]  << 16) |
                           ((uint32_t)in_buf[10] << 8)  |
                            (uint32_t)in_buf[11];

    if (payload_len > CLIP_MAX_PAYLOAD_SIZE) {
        return CLIP_ERR_PAYLOAD_SIZE;
    }

    /* 5. Parse sequence number */
    uint64_t seq_num = ((uint64_t)in_buf[12] << 56) |
                       ((uint64_t)in_buf[13] << 48) |
                       ((uint64_t)in_buf[14] << 40) |
                       ((uint64_t)in_buf[15] << 32) |
                       ((uint64_t)in_buf[16] << 24) |
                       ((uint64_t)in_buf[17] << 16) |
                       ((uint64_t)in_buf[18] << 8)  |
                        (uint64_t)in_buf[19];

    out_hdr->magic       = magic;
    out_hdr->version     = version;
    out_hdr->msg_type    = msg_type;
    out_hdr->flags       = CLIP_FRAME_FLAG_HAS_CRC;
    out_hdr->payload_len = payload_len;
    out_hdr->seq_num     = seq_num;
    memcpy(out_hdr->session_uuid, &in_buf[20], CLIP_UUID_BYTES);
    out_hdr->crc32       = 0;

    return CLIP_OK;
}

/* ── Full Frame Encoding ─────────────────────────────────────────────────── */

ClipError clip_frame_encode(const ClipFrameHeader* hdr,
                            const uint8_t*         payload,
                            uint8_t*               out_buf,
                            size_t                 out_buf_size,
                            size_t*                out_frame_len)
{
    if (!hdr || !out_buf || !out_frame_len) {
        return CLIP_ERR_INVALID;
    }
    if (hdr->payload_len > 0 && !payload) {
        return CLIP_ERR_INVALID;
    }
    if (hdr->payload_len > CLIP_MAX_PAYLOAD_SIZE) {
        return CLIP_ERR_PAYLOAD_SIZE;
    }

    /* Total wire frame size: 36 (header) + payload_len + 4 (CRC32) */
    size_t total_len = (size_t)CLIP_HEADER_SIZE + (size_t)hdr->payload_len + (size_t)CLIP_CRC32_SIZE;
    if (out_buf_size < total_len) {
        return CLIP_ERR_NOMEM;
    }

    /* 1. Encode 36-byte header */
    ClipError err = clip_header_encode(hdr, out_buf, CLIP_HEADER_SIZE);
    if (err != CLIP_OK) {
        return err;
    }

    /* 2. Copy payload */
    if (hdr->payload_len > 0) {
        memcpy(&out_buf[CLIP_HEADER_SIZE], payload, hdr->payload_len);
    }

    /* 3. Compute CRC32 over [Header + Payload] */
    size_t data_len = (size_t)CLIP_HEADER_SIZE + (size_t)hdr->payload_len;
    uint32_t crc = clip_crc32(out_buf, data_len);

    /* 4. Append 4-byte CRC32 at end of frame (big-endian) */
    uint8_t* crc_ptr = &out_buf[data_len];
    crc_ptr[0] = (uint8_t)(crc >> 24);
    crc_ptr[1] = (uint8_t)(crc >> 16);
    crc_ptr[2] = (uint8_t)(crc >> 8);
    crc_ptr[3] = (uint8_t)(crc);

    *out_frame_len = total_len;
    return CLIP_OK;
}

/* ── Full Frame Decoding & Validation ────────────────────────────────────── */

ClipError clip_frame_decode(const uint8_t*    in_buf,
                            size_t            in_buf_size,
                            ClipFrameHeader*  out_hdr,
                            const uint8_t**   out_payload,
                            uint32_t*         out_payload_len)
{
    if (!in_buf || !out_hdr || !out_payload || !out_payload_len) {
        return CLIP_ERR_INVALID;
    }

    /* Check minimum frame size (36 header + 4 CRC32 = 40 bytes) */
    if (in_buf_size < CLIP_MIN_FRAME_SIZE) {
        return CLIP_ERR_TRUNCATED;
    }

    /* Decode and validate header fields */
    ClipError err = clip_header_decode(out_hdr, in_buf, in_buf_size);
    if (err != CLIP_OK) {
        return err;
    }

    /* Compute expected total frame size */
    size_t expected_total = (size_t)CLIP_HEADER_SIZE + (size_t)out_hdr->payload_len + (size_t)CLIP_CRC32_SIZE;
    if (in_buf_size < expected_total) {
        return CLIP_ERR_TRUNCATED;
    }

    /* Verify framing CRC32 */
    size_t data_len = (size_t)CLIP_HEADER_SIZE + (size_t)out_hdr->payload_len;
    const uint8_t* crc_ptr = &in_buf[data_len];
    uint32_t wire_crc = ((uint32_t)crc_ptr[0] << 24) |
                        ((uint32_t)crc_ptr[1] << 16) |
                        ((uint32_t)crc_ptr[2] << 8)  |
                         (uint32_t)crc_ptr[3];

    uint32_t calc_crc = clip_crc32(in_buf, data_len);
    if (wire_crc != calc_crc) {
        return CLIP_ERR_CRC;
    }

    out_hdr->crc32 = wire_crc;

    if (out_hdr->payload_len > 0) {
        *out_payload = &in_buf[CLIP_HEADER_SIZE];
    } else {
        *out_payload = NULL;
    }
    *out_payload_len = out_hdr->payload_len;

    return CLIP_OK;
}

/* ── TLV Helper Functions ───────────────────────────────────────────────── */

ClipError clip_tlv_write(uint8_t*    buf,
                         size_t      buf_len,
                         size_t*     offset,
                         uint16_t    tag,
                         const void* val,
                         uint16_t    val_len)
{
    if (!buf || !offset) return CLIP_ERR_INVALID;

    size_t needed = CLIP_TLV_HEADER_SIZE + (size_t)val_len;
    if (*offset + needed > buf_len) {
        return CLIP_ERR_PAYLOAD_SIZE;
    }

    uint8_t* p = &buf[*offset];
    /* Tag (big-endian) */
    p[0] = (uint8_t)((tag >> 8) & 0xFF);
    p[1] = (uint8_t)(tag & 0xFF);

    /* Length (big-endian) */
    p[2] = (uint8_t)((val_len >> 8) & 0xFF);
    p[3] = (uint8_t)(val_len & 0xFF);

    if (val_len > 0 && val) {
        memcpy(&p[CLIP_TLV_HEADER_SIZE], val, val_len);
    }

    *offset += needed;
    return CLIP_OK;
}

ClipError clip_tlv_find(const uint8_t*  payload,
                        uint32_t        payload_len,
                        uint16_t        tag,
                        const uint8_t** out_val,
                        uint16_t*       out_len)
{
    if (!payload && payload_len > 0) return CLIP_ERR_INVALID;
    if (!out_val || !out_len) return CLIP_ERR_INVALID;

    *out_val = NULL;
    *out_len = 0;

    size_t offset = 0;
    while (offset + CLIP_TLV_HEADER_SIZE <= (size_t)payload_len) {
        uint16_t cur_tag = ((uint16_t)payload[offset] << 8) | (uint16_t)payload[offset + 1];
        uint16_t cur_len = ((uint16_t)payload[offset + 2] << 8) | (uint16_t)payload[offset + 3];
        offset += CLIP_TLV_HEADER_SIZE;

        if (offset + (size_t)cur_len > (size_t)payload_len) {
            return CLIP_ERR_PROTO; /* Malformed TLV exceeding payload boundary */
        }

        if (cur_tag == tag) {
            *out_val = &payload[offset];
            *out_len = cur_len;
            return CLIP_OK;
        }

        offset += (size_t)cur_len;
    }

    return CLIP_ERR_NOT_FOUND;
}

/* ── Audio Frame Helpers (Phase 10) ─────────────────────────────────────── */

ClipError clip_audio_frame_build(uint8_t* out_buf, size_t out_max, size_t* out_len,
                                 const ClipUuid* session_uuid, uint64_t seq_num,
                                 uint8_t codec_type, uint64_t timestamp_ms,
                                 const int16_t* pcm, size_t sample_count)
{
    if (!out_buf || !out_len || !session_uuid || (!pcm && sample_count > 0)) {
        return CLIP_ERR_INVALID;
    }
    if (clip_uuid_is_zero(session_uuid)) {
        return CLIP_ERR_NO_SESSION;
    }
    size_t audio_bytes = sample_count * sizeof(int16_t);
    if (audio_bytes > CLIP_AUDIO_MAX_PAYLOAD_BYTES) {
        return CLIP_ERR_AUDIO_OVERSIZED;
    }

    uint8_t payload[CLIP_AUDIO_MAX_PAYLOAD_BYTES + 64];
    size_t payload_len = 0;

    /* 1. Codec Type (1 byte) */
    ClipError tlv_err = clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_CODEC_TYPE, &codec_type, 1);
    if (tlv_err != CLIP_OK) return tlv_err;

    /* 2. Timestamp (8 bytes big-endian) */
    uint8_t ts_buf[8];
    for (int i = 0; i < 8; i++) {
        ts_buf[i] = (uint8_t)((timestamp_ms >> (56 - 8 * i)) & 0xFF);
    }
    tlv_err = clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_TIMESTAMP_MS, ts_buf, 8);
    if (tlv_err != CLIP_OK) return tlv_err;

    /* 3. Audio Data */
    tlv_err = clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_AUDIO_DATA, (const uint8_t*)pcm, (uint16_t)audio_bytes);
    if (tlv_err != CLIP_OK) return tlv_err;

    /* 4. Encode Frame Header */
    ClipFrameHeader hdr;
    clip_frame_header_init(&hdr, CLIP_MSG_AUDIO_FRAME, (uint32_t)payload_len, seq_num, session_uuid->bytes);

    return clip_frame_encode(&hdr, payload, out_buf, out_max, out_len);
}

ClipError clip_audio_frame_parse(const uint8_t* payload, size_t payload_len,
                                 uint8_t* out_codec_type, uint64_t* out_timestamp_ms,
                                 const int16_t** out_pcm, size_t* out_sample_count)
{
    if (!payload && payload_len > 0) return CLIP_ERR_INVALID;
    if (payload_len > CLIP_AUDIO_MAX_PAYLOAD_BYTES + 64u) {
        return CLIP_ERR_AUDIO_OVERSIZED;
    }

    const uint8_t* codec_ptr = NULL;
    uint16_t codec_len = 0;
    if (clip_tlv_find(payload, (uint32_t)payload_len, CLIP_TAG_CODEC_TYPE, &codec_ptr, &codec_len) != CLIP_OK || codec_len != 1) {
        return CLIP_ERR_PROTO;
    }
    if (out_codec_type) *out_codec_type = *codec_ptr;

    const uint8_t* ts_ptr = NULL;
    uint16_t ts_len = 0;
    if (clip_tlv_find(payload, (uint32_t)payload_len, CLIP_TAG_TIMESTAMP_MS, &ts_ptr, &ts_len) == CLIP_OK && ts_len == 8) {
        uint64_t ts = 0;
        for (int i = 0; i < 8; i++) {
            ts = (ts << 8) | (uint64_t)ts_ptr[i];
        }
        if (out_timestamp_ms) *out_timestamp_ms = ts;
    } else {
        if (out_timestamp_ms) *out_timestamp_ms = 0;
    }

    const uint8_t* audio_ptr = NULL;
    uint16_t audio_len = 0;
    if (clip_tlv_find(payload, (uint32_t)payload_len, CLIP_TAG_AUDIO_DATA, &audio_ptr, &audio_len) != CLIP_OK) {
        return CLIP_ERR_PROTO;
    }
    if (out_codec_type && *out_codec_type == CLIP_CODEC_PCM && (audio_len % sizeof(int16_t)) != 0) {
        return CLIP_ERR_PROTO;
    }
    if (audio_len > CLIP_AUDIO_MAX_PAYLOAD_BYTES) {
        return CLIP_ERR_AUDIO_OVERSIZED;
    }

    if (out_pcm) *out_pcm = (const int16_t*)audio_ptr;
    if (out_sample_count) *out_sample_count = (size_t)audio_len / sizeof(int16_t);

    return CLIP_OK;
}

ClipError clip_audio_frame_build_raw(uint8_t* out_buf, size_t out_max, size_t* out_len,
                                     const ClipUuid* session_uuid, uint64_t seq_num,
                                     uint8_t codec_type, uint64_t timestamp_ms,
                                     const uint8_t* payload_data, size_t payload_bytes)
{
    if (!out_buf || !out_len || !session_uuid || !payload_data) {
        return CLIP_ERR_INVALID;
    }
    if (clip_uuid_is_zero(session_uuid)) {
        return CLIP_ERR_NO_SESSION;
    }
    if (payload_bytes > CLIP_AUDIO_MAX_PAYLOAD_BYTES) {
        return CLIP_ERR_AUDIO_OVERSIZED;
    }

    uint8_t payload[CLIP_AUDIO_MAX_PAYLOAD_BYTES + 64];
    size_t payload_len = 0;

    /* 1. Codec Type (1 byte) */
    ClipError tlv_err = clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_CODEC_TYPE, &codec_type, 1);
    if (tlv_err != CLIP_OK) return tlv_err;

    /* 2. Timestamp (8 bytes big-endian) */
    uint8_t ts_buf[8];
    for (int i = 0; i < 8; i++) {
        ts_buf[i] = (uint8_t)((timestamp_ms >> (56 - 8 * i)) & 0xFF);
    }
    tlv_err = clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_TIMESTAMP_MS, ts_buf, 8);
    if (tlv_err != CLIP_OK) return tlv_err;

    /* 3. Audio Data */
    tlv_err = clip_tlv_write(payload, sizeof(payload), &payload_len, CLIP_TAG_AUDIO_DATA, payload_data, (uint16_t)payload_bytes);
    if (tlv_err != CLIP_OK) return tlv_err;

    /* 4. Encode Frame Header */
    ClipFrameHeader hdr;
    clip_frame_header_init(&hdr, CLIP_MSG_AUDIO_FRAME, (uint32_t)payload_len, seq_num, session_uuid->bytes);

    return clip_frame_encode(&hdr, payload, out_buf, out_max, out_len);
}

ClipError clip_audio_frame_parse_raw(const uint8_t* payload, size_t payload_len,
                                     uint8_t* out_codec_type, uint64_t* out_timestamp_ms,
                                     const uint8_t** out_audio_data, size_t* out_audio_len)
{
    if (!payload && payload_len > 0) return CLIP_ERR_INVALID;
    if (payload_len > CLIP_AUDIO_MAX_PAYLOAD_BYTES + 64u) {
        return CLIP_ERR_AUDIO_OVERSIZED;
    }

    const uint8_t* codec_ptr = NULL;
    uint16_t codec_len = 0;
    if (clip_tlv_find(payload, (uint32_t)payload_len, CLIP_TAG_CODEC_TYPE, &codec_ptr, &codec_len) != CLIP_OK || codec_len != 1) {
        return CLIP_ERR_PROTO;
    }
    if (out_codec_type) *out_codec_type = *codec_ptr;

    const uint8_t* ts_ptr = NULL;
    uint16_t ts_len = 0;
    if (clip_tlv_find(payload, (uint32_t)payload_len, CLIP_TAG_TIMESTAMP_MS, &ts_ptr, &ts_len) == CLIP_OK && ts_len == 8) {
        uint64_t ts = 0;
        for (int i = 0; i < 8; i++) {
            ts = (ts << 8) | (uint64_t)ts_ptr[i];
        }
        if (out_timestamp_ms) *out_timestamp_ms = ts;
    } else {
        if (out_timestamp_ms) *out_timestamp_ms = 0;
    }

    const uint8_t* audio_ptr = NULL;
    uint16_t audio_len = 0;
    if (clip_tlv_find(payload, (uint32_t)payload_len, CLIP_TAG_AUDIO_DATA, &audio_ptr, &audio_len) != CLIP_OK) {
        return CLIP_ERR_PROTO;
    }
    if (audio_len > CLIP_AUDIO_MAX_PAYLOAD_BYTES) {
        return CLIP_ERR_AUDIO_OVERSIZED;
    }

    if (out_audio_data) *out_audio_data = audio_ptr;
    if (out_audio_len) *out_audio_len = (size_t)audio_len;

    return CLIP_OK;
}

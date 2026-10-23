/*
 * clip_protocol.h — CLICOM Line Interface Protocol v1.0 (CLIPv1)
 *
 * Protocol version  : 1.0   (independent of software version 2.0.0)
 * Wire magic        : 0x434C4950  (ASCII "CLIP")
 *
 * ── Wire Frame Layout (36-byte header, all fields big-endian) ────────────
 *
 *  Offset  Size  Field
 *  ──────  ────  ────────────────────────────────────────────────────
 *       0     4  magic          CLIP_PROTOCOL_MAGIC (0x434C4950)
 *       4     2  proto_version  (major << 8) | minor  → e.g. 0x0100
 *       6     2  msg_type       ClipMessageType
 *       8     4  payload_len    bytes, NOT including header
 *      12     8  seq_num        monotonic uint64, per-connection
 *      20    16  session_uuid   UUID v4 raw bytes; zero if no session
 *      36     ?  payload        payload_len bytes of TLV fields
 *
 * ── Transport Integrity ──────────────────────────────────────────────────
 *
 *  TLS 1.3 provides ALL transport confidentiality and cryptographic
 *  integrity. The header fields allow the receiver to locate message
 *  boundaries (framing). A CRC32 may optionally be appended AFTER the
 *  payload for pre-TLS frame boundary detection ONLY — it is NOT a
 *  security mechanism and must never be treated as one.
 *
 * ── Payload Encoding: TLV (Type-Length-Value) ────────────────────────────
 *
 *  Each field in the payload:
 *    [TAG: 2 bytes][LENGTH: 2 bytes][VALUE: LENGTH bytes]
 *  All multi-byte values are big-endian.
 *  Unknown tags MUST be silently skipped (forward compatibility).
 *  Parsing must never use struct layout / padding assumptions.
 *
 * ── Channel ID vs Join Key ────────────────────────────────────────────────
 *
 *  channel_uuid (CLIP_TAG_CHANNEL_UUID, 16 bytes): internal immutable key.
 *  join_key (CLIP_TAG_CHANNEL_JOIN_KEY, string): user-facing e.g. "GC-4821".
 *  Protocol messages reference channels by channel_uuid.
 *  CHANNEL_CREATE and CHANNEL_JOIN carry the join_key for server lookup.
 *
 * ── Speech Analysis Transparency ─────────────────────────────────────────
 *
 *  Every SESSION_START message MUST include CLIP_TAG_SPEECH_ANALYSIS.
 *  This discloses the active speech analysis mode to all session members.
 *  CLICOM v2.0 default: CLIP_SPEECH_MODE_SERVER_MEDIATED.
 *  The E2E private mode is reserved for future deployment without requiring
 *  a protocol version bump.
 */

#ifndef CLIP_PROTOCOL_H
#define CLIP_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_version.h"
#include "clip_types.h"
#include "clip_errors.h"

/* ── Frame Constants ────────────────────────────────────────────────────── */

#define CLIP_HEADER_SIZE          36u   /* 4+2+2+4+8+16 = 36 bytes wire header */
#define CLIP_SESSION_UUID_SIZE    16u   /* UUID v4, raw bytes                */
#define CLIP_MAX_PAYLOAD_SIZE     (64u * 1024u)   /* 64 KiB per message      */
#define CLIP_TLV_HEADER_SIZE      4u    /* 2-byte tag + 2-byte length        */
#define CLIP_CRC32_SIZE           4u    /* 4-byte CRC32 framing integrity    */
#define CLIP_MIN_FRAME_SIZE       (CLIP_HEADER_SIZE + CLIP_CRC32_SIZE) /* 40u */
#define CLIP_MAX_FRAME_SIZE       (CLIP_HEADER_SIZE + CLIP_MAX_PAYLOAD_SIZE + CLIP_CRC32_SIZE) /* 65576u */

/* ── Audio Frame Payload Bounds (Phase 10) ──────────────────────────────── */
#define CLIP_AUDIO_DEFAULT_FRAME_SAMPLES   320u  /* 20ms @ 16kHz mono */
#define CLIP_AUDIO_DEFAULT_PAYLOAD_BYTES   (CLIP_AUDIO_DEFAULT_FRAME_SAMPLES * sizeof(int16_t)) /* 640 bytes */
#define CLIP_AUDIO_MAX_PAYLOAD_BYTES       19200u /* Strict max PCM payload: 100ms @ 48kHz stereo */
#define CLIP_AUDIO_MAX_FRAME_WIRE_SIZE     (CLIP_HEADER_SIZE + CLIP_AUDIO_MAX_PAYLOAD_BYTES + 64u + CLIP_CRC32_SIZE)

/* ── Message Types ──────────────────────────────────────────────────────── */

typedef enum {
    /* Handshake */
    CLIP_MSG_HELLO              = 0x0001,  /* C→S greeting + protocol ver    */
    CLIP_MSG_AUTH               = 0x0002,  /* C→S authentication credential  */
    CLIP_MSG_AUTH_OK            = 0x0003,  /* S→C auth accepted              */
    CLIP_MSG_AUTH_FAIL          = 0x0004,  /* S→C auth rejected              */
    CLIP_MSG_REGISTER           = 0x0005,  /* C→S node identity registration */
    CLIP_MSG_REGISTER_OK        = 0x0006,  /* S→C registration accepted      */
    CLIP_MSG_REGISTER_ACK       = 0x0006,  /* Alias: registration acknowledged */

    /* Presence and keep-alive */
    CLIP_MSG_PRESENCE           = 0x0010,  /* S→C presence snapshot/update   */
    CLIP_MSG_HEARTBEAT          = 0x0011,  /* S↔C keep-alive ping            */
    CLIP_MSG_HEARTBEAT_ACK      = 0x0012,  /* S↔C keep-alive pong            */

    /* Channel management */
    CLIP_MSG_CHANNEL_CREATE     = 0x0020,  /* C→S create channel (join_key)  */
    CLIP_MSG_CHANNEL_CREATE_OK  = 0x0021,  /* S→C channel_uuid assigned      */
    CLIP_MSG_CHANNEL_CREATE_ACK = 0x0021,  /* Alias: channel create acknowledged */
    CLIP_MSG_CHANNEL_JOIN       = 0x0022,  /* C→S join by join_key           */
    CLIP_MSG_CHANNEL_JOIN_OK    = 0x0023,  /* S→C join accepted + members    */
    CLIP_MSG_CHANNEL_JOIN_ACK   = 0x0023,  /* Alias: channel join acknowledged*/
    CLIP_MSG_CHANNEL_LEAVE      = 0x0024,  /* C→S leave channel              */
    CLIP_MSG_CHANNEL_LIST       = 0x0025,  /* C→S request available channels */
    CLIP_MSG_CHANNEL_LIST_RESP  = 0x0026,  /* S→C channel list               */
    CLIP_MSG_CHANNEL_MEMBER_UPD = 0x0027,  /* S→C member joined/left event   */
    CLIP_MSG_CHANNEL_FAIL       = 0x0028,  /* S→C channel operation rejected */
    CLIP_MSG_CHANNEL_MEMBERS_REQ = 0x0029, /* C→S query channel members & presence */
    CLIP_MSG_CHANNEL_MEMBERS_RESP= 0x002A, /* S→C channel members + presence response */
    CLIP_MSG_CHANNEL_REVOKE_KEY  = 0x002B, /* C→S revoke channel invitation key */
    CLIP_MSG_CHANNEL_REVOKE_KEY_OK=0x002C, /* S→C revoke key acknowledged */
    CLIP_MSG_CHANNEL_CLOSE       = 0x002D, /* C→S close/destroy channel */
    CLIP_MSG_CHANNEL_CLOSE_OK    = 0x002E, /* S→C channel closed acknowledged */

    /* Connection request workflow (Channel → Connection → Session) */
    CLIP_MSG_CONN_REQUEST       = 0x0030,  /* C→S/S→C directed request       */
    CLIP_MSG_CONNECTION_REQUEST = 0x0030,  /* Alias: directed request        */
    CLIP_MSG_CONN_ACCEPT        = 0x0031,  /* C→S/S→C accept                 */
    CLIP_MSG_CONN_DECLINE       = 0x0032,  /* C→S/S→C decline               */
    CLIP_MSG_CONN_TIMEOUT       = 0x0033,  /* S→C request expired (30s)      */
    CLIP_MSG_CONNECTION_RESPONSE= 0x0034,  /* S↔C connection response status */
    CLIP_MSG_CONN_RESPONSE      = 0x0034,  /* Alias: connection response status */
    CLIP_MSG_CONN_FAIL          = 0x0035,  /* S→C connection request rejected */
    CLIP_MSG_CONN_LIST_REQ      = 0x0036,  /* C→S list connections           */
    CLIP_MSG_CONN_LIST_RESP     = 0x0037,  /* S→C connections list           */

    /* Session lifecycle */
    CLIP_MSG_SESSION_START      = 0x0040,  /* C→S request / S→C established  */
    CLIP_MSG_SESSION_END        = 0x0041,  /* C→S / S→C session terminated   */
    CLIP_MSG_SESSION_START_ACK  = 0x0042,  /* S→C session start acknowledged */
    CLIP_MSG_SESSION_START_OK   = 0x0042,  /* Alias                          */
    CLIP_MSG_SESSION_END_ACK    = 0x0043,  /* S→C session end acknowledged   */
    CLIP_MSG_SESSION_END_OK     = 0x0043,  /* Alias                          */
    CLIP_MSG_SESSION_FAIL       = 0x0044,  /* S→C session operation rejected */

    /* PTT floor arbitration (server-authoritative, channel/session-level) */
    CLIP_MSG_PTT_REQUEST        = 0x0050,  /* C→S request floor              */
    CLIP_MSG_PTT_FLOOR_REQUEST  = 0x0050,  /* Alias: floor request           */
    CLIP_MSG_PTT_GRANT          = 0x0051,  /* S→C floor granted              */
    CLIP_MSG_PTT_FLOOR_GRANTED  = 0x0051,  /* Alias: floor granted           */
    CLIP_MSG_PTT_DENY           = 0x0052,  /* S→C floor denied (busy)        */
    CLIP_MSG_PTT_FLOOR_DENIED   = 0x0052,  /* Alias: floor denied            */
    CLIP_MSG_PTT_RELEASE        = 0x0053,  /* C→S release floor              */
    CLIP_MSG_PTT_FLOOR_RELEASE  = 0x0053,  /* Alias: floor release           */
    CLIP_MSG_PTT_NOTIFY         = 0x0054,  /* S→C floor status broadcast     */
    CLIP_MSG_PTT_FLOOR_NOTIFY   = 0x0054,  /* Alias: floor status broadcast  */
    CLIP_MSG_PTT_FLOOR_RELEASED = 0x0055,  /* S→C floor release acknowledged */
    CLIP_MSG_PTT_RELEASE_ACK    = 0x0055,  /* Alias: floor release ack       */
    CLIP_MSG_PTT_FLOOR_STATUS_REQ  = 0x0056, /* C→S query floor status       */
    CLIP_MSG_PTT_FLOOR_STATUS_RESP = 0x0057, /* S→C floor status response     */
    CLIP_MSG_PTT_FLOOR_RENEW       = 0x0058, /* C→S lease renewal            */
    CLIP_MSG_PTT_FLOOR_RENEW_ACK   = 0x0059, /* S→C lease renewal ack        */

    /* Audio transport */
    CLIP_MSG_AUDIO_FRAME        = 0x0060,  /* C→S/S→C encoded audio data     */

    /* Captions (server-mediated STT; Phase 13 local-only, RESERVED / NO NETWORK TRANSMISSION) */
    CLIP_MSG_CAPTION            = 0x0070,  /* RESERVED — local caption concept only; no wire transmission */

    /* Notes & Session Logs (Phase 14) */
    CLIP_MSG_SESSION_LOG_LIST_REQ  = 0x0071,  /* C→S list authorized sessions    */
    CLIP_MSG_SESSION_LOG_LIST_RESP = 0x0072,  /* S→C authorized sessions list    */
    CLIP_MSG_SESSION_LOG_GET_REQ   = 0x0073,  /* C→S query session details       */
    CLIP_MSG_SESSION_LOG_GET_RESP  = 0x0074,  /* S→C session details response    */
    CLIP_MSG_NOTE_CREATE           = 0x0075,  /* C→S add note to session         */
    CLIP_MSG_NOTE_CREATE_OK        = 0x0076,  /* S→C note created ack            */
    CLIP_MSG_NOTE_LIST_REQ         = 0x0077,  /* C→S query notes for session     */
    CLIP_MSG_NOTE_LIST_RESP        = 0x0078,  /* S→C notes list response         */
    CLIP_MSG_NOTE_FAIL             = 0x0079,  /* S→C notes/log operation rejected*/

    /* Security events (Phase 15: advisory only — never triggers automatic action) */
    CLIP_MSG_SECURITY_EVENT           = 0x0080,  /* S→C advisory event notification */
    CLIP_MSG_SECURITY_EVENT_LIST_REQ  = 0x0081,  /* C→S query security events list  */
    CLIP_MSG_SECURITY_EVENT_LIST_RESP = 0x0082,  /* S→C security events list response*/
    CLIP_MSG_SECURITY_EVENT_GET_REQ   = 0x0083,  /* C→S query single security event */
    CLIP_MSG_SECURITY_EVENT_GET_RESP  = 0x0084,  /* S→C single security event response*/
    CLIP_MSG_SECURITY_EVENT_FAIL      = 0x0085,  /* S→C security event op rejected  */
    CLIP_MSG_SECURITY_TRANSCRIPT      = 0x0086,  /* C→S authenticated finalized transcript for security analysis */

    /* Admin actions (require authenticated admin identity; server-validated) */
    CLIP_MSG_ADMIN_ACTION       = 0x0090,  /* C→S admin command              */
    CLIP_MSG_ADMIN_ACTION_OK    = 0x0091,  /* S→C command acknowledged       */
    CLIP_MSG_ADMIN_ACTION_FAIL  = 0x0092,  /* S→C command rejected           */
    CLIP_MSG_ADMIN_AUTH_REQ     = 0x0093,  /* C→S admin auth request         */
    CLIP_MSG_ADMIN_AUTH_RESP    = 0x0094,  /* S→C admin auth response        */
    CLIP_MSG_ADMIN_EVENTS_REQ   = 0x0095,  /* C→S admin query security events*/
    CLIP_MSG_ADMIN_EVENTS_RESP  = 0x0096,  /* S→C admin security events resp */
    CLIP_MSG_ADMIN_AUDIT_REQ    = 0x0097,  /* C→S admin query audit log      */
    CLIP_MSG_ADMIN_AUDIT_RESP   = 0x0098,  /* S→C admin audit log response   */

    /* Teardown and errors */
    CLIP_MSG_ERROR              = 0x00F0,  /* S→C protocol error             */
    CLIP_MSG_GOODBYE            = 0x00FF   /* C→S graceful disconnect        */
} ClipMessageType;

/* ── TLV Tag Codes ──────────────────────────────────────────────────────── */

typedef enum {
    CLIP_TAG_NODE_UUID          = 0x0001,  /* 16-byte UUID raw               */
    CLIP_TAG_NODE_UUID_STR      = 0x0002,  /* UUID as ASCII string           */
    CLIP_TAG_DISPLAY_NAME       = 0x0003,  /* UTF-8 display name             */
    CLIP_TAG_CHANNEL_UUID       = 0x0004,  /* 16-byte channel UUID raw       */
    CLIP_TAG_CHANNEL_JOIN_KEY   = 0x0005,  /* user-facing join key string    */
    CLIP_TAG_SESSION_UUID       = 0x0006,  /* 16-byte session UUID raw       */
    CLIP_TAG_TIMESTAMP_MS       = 0x0007,  /* uint64 Unix timestamp (ms)     */
    CLIP_TAG_TEXT               = 0x0008,  /* UTF-8 text (captions, errors)  */
    CLIP_TAG_TRANSCRIPT_TEXT    = 0x0008,  /* Alias: transcript text payload */
    CLIP_TAG_PRESENCE           = 0x0009,  /* uint8 ClipPresence value       */
    CLIP_TAG_MEMBER_LIMIT       = 0x000A,  /* uint16 max members             */
    CLIP_TAG_MEMBER_COUNT       = 0x000B,  /* uint16 current members         */
    CLIP_TAG_CODEC_TYPE         = 0x000C,  /* uint8 audio codec ID           */
    CLIP_TAG_AUDIO_DATA         = 0x000D,  /* raw encoded audio bytes        */
    CLIP_TAG_CATEGORY           = 0x000E,  /* uint8 security event category  */
    CLIP_TAG_SEVERITY           = 0x000F,  /* uint8 severity level           */
    CLIP_TAG_ADMIN_ACTION       = 0x0010,  /* uint8 admin action type        */
    CLIP_TAG_PERMISSION_LEVEL   = 0x0011,  /* uint8 admin permission level   */
    CLIP_TAG_ERROR_CODE         = 0x0012,  /* uint16 error code              */
    CLIP_TAG_PROTO_VERSION      = 0x0013,  /* uint16 protocol version        */
    CLIP_TAG_FLAGS              = 0x0014,  /* uint32 message flags           */
    CLIP_TAG_SPEECH_ANALYSIS    = 0x0015,  /* uint8 ClipSpeechMode — MANDATORY
                                              in every SESSION_START message */
    CLIP_TAG_CURRENT_SPEAKER    = 0x0016,  /* UUID str of current PTT holder */
    CLIP_TAG_CREDENTIAL         = 0x0017,  /* 32-byte raw credential         */
    CLIP_TAG_AUTH_STATUS        = 0x0018,  /* uint16 auth status / error code */
    CLIP_TAG_CHANNEL_NAME       = 0x0019,  /* UTF-8 channel name             */
    CLIP_TAG_SESSION_STATE      = 0x001A,  /* uint8 ClipSessionState value   */
    CLIP_TAG_CONNECTION_UUID    = 0x001B,  /* 16-byte raw connection UUID    */
    CLIP_TAG_CONNECTION_STATE   = 0x001C,  /* uint8 ClipConnectionState value*/
    CLIP_TAG_TARGET_NODE_UUID   = 0x001D,  /* 16-byte raw target node UUID   */
    CLIP_TAG_FLOOR_STATE        = 0x001E,  /* uint8: 0=FREE, 1=HELD          */
    CLIP_TAG_LEASE_TIMEOUT_MS   = 0x001F,  /* uint32 lease ms                */
    CLIP_TAG_DENIAL_REASON      = 0x0020,  /* uint16 denial error code       */
    CLIP_TAG_HOLDER_NODE_UUID   = 0x0021,  /* 16-byte raw holder UUID        */
    /* Phase 14 Notes and Session Logs */
    CLIP_TAG_NOTE_ID            = 0x0022,  /* uint32 note id                 */
    CLIP_TAG_NOTE_AUTHOR_UUID   = 0x0023,  /* 16-byte raw author node UUID   */
    CLIP_TAG_NOTE_TEXT          = 0x0024,  /* UTF-8 string note text         */
    CLIP_TAG_NOTE_COUNT         = 0x0025,  /* uint16 note count              */
    CLIP_TAG_NOTE_TYPE          = 0x0026,  /* uint8 ClipNoteType value       */
    CLIP_TAG_DURATION_MS        = 0x0027,  /* uint64 duration ms             */
    CLIP_TAG_LOG_COUNT          = 0x0028,  /* uint16 session log count       */
    /* Phase 15 Security Keyword Analysis */
    CLIP_TAG_EVENT_UUID         = 0x0029,  /* 16-byte raw security event UUID */
    CLIP_TAG_EVENT_ID           = 0x002A,  /* uint32 security event id        */
    CLIP_TAG_MATCHED_RULE       = 0x002B,  /* UTF-8 string matched rule name  */
    CLIP_TAG_MATCHED_TEXT       = 0x002C,  /* UTF-8 string matched keyword/term */
    CLIP_TAG_CONTEXT_TEXT       = 0x002D,  /* UTF-8 string context window     */
    CLIP_TAG_EVENT_STATUS       = 0x002E,  /* uint8 ClipEventStatus (0=PENDING) */
    CLIP_TAG_EVENT_COUNT        = 0x002F,  /* uint16 security event count     */
    /* Phase 16 Admin Alerts & Actions */
    CLIP_TAG_ADMIN_USERNAME     = 0x0030,  /* UTF-8 string admin username     */
    CLIP_TAG_ADMIN_REASON       = 0x0031,  /* UTF-8 string admin action reason*/
    CLIP_TAG_ADMIN_TARGET_UUID  = 0x0032,  /* 16-byte raw target node/chan UUID*/
    CLIP_TAG_RELATED_EVENT_ID   = 0x0033,  /* uint32 referenced event_id      */
    CLIP_TAG_RELATED_SESSION_UUID = 0x0034,/* 16-byte raw session UUID        */
    CLIP_TAG_RELATED_CHANNEL_UUID = 0x0035,/* 16-byte raw channel UUID        */
    CLIP_TAG_ADMIN_AUDIT_ID     = 0x0036,  /* uint32 auto-increment audit ID  */
    CLIP_TAG_ADMIN_AUDIT_COUNT  = 0x0037   /* uint16 count of audit records   */
} ClipTlvTag;

/* ── Note Types (Phase 14) ──────────────────────────────────────────────── */

typedef enum {
    CLIP_NOTE_TYPE_MANUAL     = 1, /* User authored note                    */
    CLIP_NOTE_TYPE_TRANSCRIPT = 2  /* Exported caption / transcript summary */
} ClipNoteType;

/* ── Speech Analysis Mode ───────────────────────────────────────────────── */

/*
 * CLICOM v2.0 default: CLIP_SPEECH_MODE_SERVER_MEDIATED.
 *
 * This tag MUST be included in every SESSION_START message so all members
 * know what analysis is active. Transparency is mandatory.
 *
 * CLIP_SPEECH_MODE_E2E_PRIVATE is reserved for a future deployment mode
 * where the server forwards opaque encrypted frames and cannot perform STT.
 * Adding it later requires no protocol version bump.
 */
typedef enum {
    CLIP_SPEECH_MODE_NONE            = 0x00, /* STT disabled                */
    CLIP_SPEECH_MODE_SERVER_MEDIATED = 0x01, /* Server performs auth. STT   */
    CLIP_SPEECH_MODE_E2E_PRIVATE     = 0x02  /* Future: E2E encrypted audio */
} ClipSpeechMode;

/* ── Admin Permission Levels ────────────────────────────────────────────── */

typedef enum {
    CLIP_ADMIN_PERM_NONE        = 0x00,  /* no admin privileges             */
    CLIP_ADMIN_PERM_OBSERVER    = 0x01,  /* view-only                       */
    CLIP_ADMIN_PERM_MODERATOR   = 0x02,  /* disconnect, restrict, review    */
    CLIP_ADMIN_PERM_SUPER_ADMIN = 0x03   /* all actions                     */
} ClipAdminPermission;

/* ── Admin Action Types ─────────────────────────────────────────────────── */

typedef enum {
    CLIP_ADMIN_DISCONNECT_NODE  = 0x01,  /* disconnect a node               */
    CLIP_ADMIN_RESTRICT_NODE    = 0x02,  /* receive-only restriction        */
    CLIP_ADMIN_UNRESTRICT_NODE  = 0x03,
    CLIP_ADMIN_BAN_NODE         = 0x04,  /* ban node from server            */
    CLIP_ADMIN_UNBAN_NODE       = 0x05,
    CLIP_ADMIN_LOCK_CHANNEL     = 0x06,  /* lock channel (no new joins)     */
    CLIP_ADMIN_UNLOCK_CHANNEL   = 0x07,
    CLIP_ADMIN_MARK_FALSE_POS   = 0x08,  /* dismiss security event          */
    CLIP_ADMIN_REVIEW_EVENT     = 0x09,  /* acknowledge security event      */
    CLIP_ADMIN_CREATE_ADMIN     = 0x0A   /* create admin account (super only)*/
} ClipAdminActionType;

/* ── Frame Flags ────────────────────────────────────────────────────────── */

#define CLIP_FRAME_FLAG_NONE       0x00000000u
#define CLIP_FRAME_FLAG_HAS_CRC    0x00000001u
#define CLIP_FRAME_FLAG_ENCRYPTED  0x00000002u  /* reserved for future E2E mode */
#define CLIP_FRAME_FLAG_COMPRESSED 0x00000004u  /* reserved */

/* ── Frame Header Structure (In-Memory Representation) ──────────────────── */

/*
 * In-memory representation of protocol frame header.
 *
 * Wire encoding is strictly 36 bytes (CLIP_HEADER_SIZE):
 *   [0..3]   magic (0x434C4950, big-endian)
 *   [4..5]   version (0x0100, big-endian)
 *   [6..7]   msg_type (ClipMessageType, big-endian)
 *   [8..11]  payload_len (uint32_t, big-endian)
 *   [12..19] seq_num (uint64_t, big-endian)
 *   [20..35] session_uuid (16 raw bytes)
 *
 * A complete frame over the wire consists of:
 *   [Header: 36 bytes] + [Payload: payload_len bytes] + [CRC32: 4 bytes]
 */
typedef struct {
    uint32_t magic;         /* CLIP_PROTOCOL_MAGIC (0x434C4950) */
    uint16_t version;       /* (CLIP_PROTOCOL_VERSION_MAJOR << 8) | MINOR */
    uint16_t msg_type;      /* ClipMessageType enum */
    uint32_t flags;         /* Frame flags (CLIP_FRAME_FLAG_*) */
    uint32_t payload_len;   /* Length of payload in bytes */
    uint64_t seq_num;       /* Monotonic sequence number */
    uint8_t  session_uuid[CLIP_UUID_BYTES]; /* 16-byte session UUID, zero if none */
    uint32_t crc32;         /* 32-bit CRC framing integrity */
} ClipFrameHeader;

typedef struct {
    ClipFrameHeader header;
    const uint8_t*  payload; /* Pointer to payload buffer (borrowed) */
} ClipFrame;

/* ── CRC32 Frame Integrity API ──────────────────────────────────────────── */

/*
 * Standard IEEE 802.3 CRC32 calculation.
 * Polynomial: 0xEDB88320 (reversed), initial 0xFFFFFFFF, final XOR 0xFFFFFFFF.
 *
 * NOTE: CRC32 is strictly for frame integrity, boundary location, and corruption/
 * truncation detection. It is NOT encryption, authentication, or cryptographic
 * security. TLS 1.3 will provide all transport confidentiality and authenticity.
 */
uint32_t clip_crc32(const uint8_t* data, size_t length);
uint32_t clip_crc32_update(uint32_t running_crc, const uint8_t* data, size_t length);

/* ── Frame Serialization & Deserialization API ──────────────────────────── */

/* Validates whether a message type is recognized by the protocol */
bool clip_message_type_is_valid(uint16_t msg_type);

/* Human-readable message type name */
const char* clip_message_type_string(ClipMessageType type);

/* Initialize a frame header with protocol defaults */
void clip_frame_header_init(ClipFrameHeader* hdr,
                            ClipMessageType  msg_type,
                            uint32_t         payload_len,
                            uint64_t         seq_num,
                            const uint8_t    session_uuid[CLIP_UUID_BYTES]);

/*
 * Serialize a 36-byte wire header into out_buf (big-endian).
 * out_buf_size must be at least CLIP_HEADER_SIZE (36).
 */
ClipError clip_header_encode(const ClipFrameHeader* hdr,
                             uint8_t*               out_buf,
                             size_t                 out_buf_size);

/*
 * Deserialize a 36-byte wire header from in_buf (big-endian).
 * Validates magic, protocol version, and payload_len limits.
 */
ClipError clip_header_decode(ClipFrameHeader* out_hdr,
                             const uint8_t*   in_buf,
                             size_t           in_buf_size);

/*
 * Encode a full protocol frame: [Header: 36][Payload: len][CRC32: 4]
 * Computes CRC32 over header + payload and appends to frame.
 * out_buf_size must be at least (CLIP_HEADER_SIZE + payload_len + CLIP_CRC32_SIZE).
 * out_frame_len receives the total bytes written.
 */
ClipError clip_frame_encode(const ClipFrameHeader* hdr,
                            const uint8_t*         payload,
                            uint8_t*               out_buf,
                            size_t                 out_buf_size,
                            size_t*                out_frame_len);

/*
 * Decode and validate a full protocol frame:
 * 1. Checks minimum buffer length (>= 40 bytes)
 * 2. Parses and validates magic, version, payload_len
 * 3. Checks payload_len bounds and buffer truncation
 * 4. Verifies CRC32 over [Header + Payload]
 * Returns CLIP_OK and sets out_hdr, out_payload, out_payload_len on success.
 * Returns appropriate ClipError code on validation failure.
 */
ClipError clip_frame_decode(const uint8_t*    in_buf,
                            size_t            in_buf_size,
                            ClipFrameHeader*  out_hdr,
                            const uint8_t**   out_payload,
                            uint32_t*         out_payload_len);

/* ── TLV Helper Functions ───────────────────────────────────────────────── */

/* Append a TLV field to a buffer */
ClipError clip_tlv_write(uint8_t*  buf,
                         size_t    buf_len,
                         size_t*   offset,
                         uint16_t  tag,
                         const void* val,
                         uint16_t  val_len);

/* Locate and extract a specific TLV field from a message payload */
ClipError clip_tlv_find(const uint8_t*  payload,
                        uint32_t        payload_len,
                        uint16_t        tag,
                        const uint8_t** out_val,
                        uint16_t*       out_len);

/* ── Audio Codec Types (Phase 10) ───────────────────────────────────────── */
typedef enum {
    CLIP_CODEC_NULL      = 0x00,  /* No-op / test dummy codec */
    CLIP_CODEC_PCM       = 0x01,  /* Linear 16-bit signed PCM (LE) */
    CLIP_CODEC_OPUS      = 0x02   /* Opus interactive speech (RFC 6716) */
} ClipAudioCodecType;

/* ── Audio Frame Helpers (Phase 10) ─────────────────────────────────────── */
ClipError clip_audio_frame_build(uint8_t* out_buf, size_t out_max, size_t* out_len,
                                 const ClipUuid* session_uuid, uint64_t seq_num,
                                 uint8_t codec_type, uint64_t timestamp_ms,
                                 const int16_t* pcm, size_t sample_count);

ClipError clip_audio_frame_parse(const uint8_t* payload, size_t payload_len,
                                 uint8_t* out_codec_type, uint64_t* out_timestamp_ms,
                                 const int16_t** out_pcm, size_t* out_sample_count);

ClipError clip_audio_frame_build_raw(uint8_t* out_buf, size_t out_max, size_t* out_len,
                                     const ClipUuid* session_uuid, uint64_t seq_num,
                                     uint8_t codec_type, uint64_t timestamp_ms,
                                     const uint8_t* payload_data, size_t payload_bytes);

ClipError clip_audio_frame_parse_raw(const uint8_t* payload, size_t payload_len,
                                     uint8_t* out_codec_type, uint64_t* out_timestamp_ms,
                                     const uint8_t** out_audio_data, size_t* out_audio_len);

#endif /* CLIP_PROTOCOL_H */

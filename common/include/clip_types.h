/*
 * clip_types.h — CLICOM Core Type Definitions
 *
 * CLICOM - CLI Communication System
 * Protocol: CLIPv1.0 (separate from software version)
 *
 * ── Node Identity Model ───────────────────────────────────────────────────
 *
 *   node_uuid     : Immutable, server-assigned UUID (16 bytes / 128-bit).
 *                   Generated once at first registration. Never changes.
 *                   Used in all protocol messages as the canonical node key.
 *
 *   display_name  : User-chosen mutable label (e.g. "NODE-A").
 *                   Shown in dashboards and captions. Not guaranteed unique.
 *                   Server validates length and safe characters.
 *
 * ── Channel Identity Model ────────────────────────────────────────────────
 *
 *   channel_uuid  : Immutable, server-assigned UUID (internal key).
 *                   Used in all protocol messages.
 *
 *   join_key      : User-facing alphanumeric string (e.g. "GC-4821").
 *                   Exchanged out-of-band. Server maps join_key → channel_uuid.
 *                   Join keys are checked for uniqueness at creation time.
 *
 * ── Conceptual Separation: Channel / Connection / Session ─────────────────
 *
 *   Channel    : A named, persistent grouping of authorized nodes.
 *                Persisted in SQLite. Survives server restarts.
 *
 *   Connection : A directed, accepted request for nodes to communicate.
 *                Triggers the accept/decline workflow. No audio flows until
 *                a connection is accepted and a Session begins.
 *
 *   Session    : An active communication period (audio + captions + logging)
 *                between connected nodes within a channel context.
 *                Sessions have a defined start and end.
 *                PTT floor arbitration operates at the channel level.
 *
 * ── Member Management ─────────────────────────────────────────────────────
 *
 *   Member lists are dynamically allocated (linked list / dynamic array).
 *   No hard-coded fixed-size member arrays in production code.
 *   Phase 3+ will provide full implementations.
 */

#ifndef CLIP_TYPES_H
#define CLIP_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ── Size Constants ─────────────────────────────────────────────────────── */

#define CLIP_UUID_BYTES           16u  /* 128-bit UUID, raw bytes            */
#define CLIP_UUID_STR_SIZE        37u  /* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\0" */
#define CLIP_DISPLAY_NAME_MAX     64u  /* max display name length incl. NUL  */
#define CLIP_JOIN_KEY_MAX         32u  /* max channel join key length incl. NUL */

/* ── UUID Representation ─────────────────────────────────────────────────── */

/*
 * Canonical 16-byte UUID representation.
 * Used consistently for node_uuid, channel_uuid, session_uuid, connection_uuid.
 */
typedef struct {
    uint8_t bytes[CLIP_UUID_BYTES];
} ClipUuid;

/* UUID helper prototypes */
void clip_uuid_zero(ClipUuid* uuid);
bool clip_uuid_is_zero(const ClipUuid* uuid);
int  clip_uuid_compare(const ClipUuid* a, const ClipUuid* b);
bool clip_uuid_equal(const ClipUuid* a, const ClipUuid* b);
void clip_uuid_copy(ClipUuid* dst, const ClipUuid* src);
int  clip_uuid_to_string(const ClipUuid* uuid, char* out_str, size_t str_len);
int  clip_uuid_from_string(ClipUuid* out_uuid, const char* str);

/* ── Node Presence ──────────────────────────────────────────────────────── */

/*
 * Presence state.
 * The server is authoritative; clients receive updates via PRESENCE messages.
 * Clients MUST NOT self-report or forge the presence of other nodes.
 */
typedef enum {
    CLIP_PRESENCE_OFFLINE  = 0,  /* not connected or timed out         */
    CLIP_PRESENCE_ONLINE   = 1,  /* connected and idle                 */
    CLIP_PRESENCE_BUSY     = 2,  /* in an active session               */
    CLIP_PRESENCE_AWAY     = 3   /* reserved for future use            */
} ClipPresence;

/* ── Node Info ──────────────────────────────────────────────────────────── */

/*
 * Minimal node descriptor used in Phase 0.
 * Phase 3+ adds credential material, session tokens, etc.
 */
typedef struct {
    uint8_t      node_uuid[CLIP_UUID_BYTES];       /* server-assigned immutable UUID */
    char         node_uuid_str[CLIP_UUID_STR_SIZE]; /* UUID as printable string      */
    char         display_name[CLIP_DISPLAY_NAME_MAX];
    ClipPresence presence;
    uint64_t     last_seen_ms;   /* Unix timestamp in milliseconds     */
} ClipNodeInfo;

/* ── Channel Info ───────────────────────────────────────────────────────── */

typedef enum {
    CLIP_CHANNEL_STATE_OPEN      = 1,  /* accepting members                */
    CLIP_CHANNEL_STATE_FULL      = 2,  /* at member_limit                  */
    CLIP_CHANNEL_STATE_LOCKED    = 3,  /* admin-locked, no new joins       */
    CLIP_CHANNEL_STATE_EMPTY     = 4,  /* all members gone; pending cleanup */
    CLIP_CHANNEL_STATE_DESTROYED = 5   /* permanently removed              */
} ClipChannelState;

/*
 * Channel descriptor.
 * channel_uuid  → internal, immutable, used in all protocol messages.
 * join_key      → user-facing, alphanumeric, exchanged out-of-band.
 *
 * member_limit  : Configurable (2, 3, 5, 10, ...). Dynamic allocation used
 *                 for member lists; this field is the declared maximum.
 * member_count  : Current number of members. Server is authoritative.
 */
typedef struct {
    uint8_t          channel_uuid[CLIP_UUID_BYTES];
    char             channel_uuid_str[CLIP_UUID_STR_SIZE];
    char             join_key[CLIP_JOIN_KEY_MAX];  /* user-facing key */
    char             name[CLIP_DISPLAY_NAME_MAX];  /* channel display name */
    ClipChannelState state;
    uint16_t         member_limit;
    uint16_t         member_count;   /* maintained by server */
    char             creator_uuid_str[CLIP_UUID_STR_SIZE];
    uint64_t         created_at_ms;
    uint64_t         last_activity_ms;
    bool             is_persistent;  /* always true in v2.0; SQLite persisted */
} ClipChannelInfo;

typedef struct {
    ClipUuid     node_uuid;
    char         display_name[CLIP_DISPLAY_NAME_MAX];
    ClipPresence presence;
    uint64_t     joined_at_ms;
} ClipChannelMember;

/* ── Connection Request & State ─────────────────────────────────────────── */

typedef enum {
    CLIP_CONN_STATE_NONE       = 0,
    CLIP_CONN_STATE_REQUESTED  = 1,
    CLIP_CONN_STATE_ACCEPTED   = 2,
    CLIP_CONN_STATE_DECLINED   = 3,
    CLIP_CONN_STATE_CLOSED     = 4,
    CLIP_CONN_STATE_EXPIRED    = 5
} ClipConnectionState;

typedef struct {
    ClipUuid            connection_uuid;
    ClipUuid            channel_uuid;
    ClipUuid            requester_node_uuid;
    ClipUuid            target_node_uuid;
    ClipConnectionState state;
    uint64_t            created_at_ms;
    uint64_t            updated_at_ms;
} ClipConnectionRecord;

/* ── Session Info ───────────────────────────────────────────────────────── */

typedef enum {
    CLIP_SESSION_STATE_INIT      = 0,
    CLIP_SESSION_STATE_ACTIVE    = 1,
    CLIP_SESSION_STATE_CLOSING   = 2,
    CLIP_SESSION_STATE_CLOSED    = 3
} ClipSessionState;

/*
 * Session descriptor (Phase 0 declaration; full implementation in Phase 8).
 * session_uuid is server-assigned.
 * A session lives within a channel context.
 * PTT floor arbitration is channel-level (not session-level).
 */
typedef struct {
    uint8_t          session_uuid[CLIP_UUID_BYTES];
    char             channel_uuid_str[CLIP_UUID_STR_SIZE];
    ClipSessionState state;
    uint64_t         started_at_ms;
    uint64_t         ended_at_ms;
    /* member list: dynamically allocated in Phase 8+ */
} ClipSessionInfo;

/* ── PTT Floor State ────────────────────────────────────────────────────── */

/*
 * PTT floor state (server-side, per channel).
 * Server is the sole authority for PTT floor grant/deny/release.
 * Clients MUST NOT self-grant the transmission floor.
 *
 * Crash protection: a watchdog reclaims the floor after lease_timeout_ms
 * if the speaker disconnects without sending PTT_RELEASE.
 */
#define CLIP_PTT_DEFAULT_LEASE_MS 5000u

typedef enum {
    CLIP_PTT_FLOOR_FREE = 0,
    CLIP_PTT_FLOOR_HELD = 1
} ClipPttFloorState;

typedef struct {
    ClipUuid          session_uuid;
    char              session_uuid_str[CLIP_UUID_STR_SIZE];
    ClipUuid          channel_uuid;
    char              channel_uuid_str[CLIP_UUID_STR_SIZE];
    ClipUuid          holder_node_uuid;
    char              speaker_uuid_str[CLIP_UUID_STR_SIZE]; /* empty if FREE */
    uint64_t          acquired_at_ms;
    uint64_t          last_renewed_at_ms;
    uint32_t          lease_timeout_ms;  /* default: 5000 */
    ClipPttFloorState floor_state;
} ClipPttFloor;

/*
 * Connection workflow state.
 * Connection: Directed request between two nodes that can be accepted or declined.
 * Distinct from Channel (persistent group) and Session (active communication).
 * (ClipConnectionState is defined above).
 */

typedef struct {
    uint8_t             connection_uuid[CLIP_UUID_BYTES];
    char                connection_uuid_str[CLIP_UUID_STR_SIZE];
    uint8_t             channel_uuid[CLIP_UUID_BYTES];
    char                channel_uuid_str[CLIP_UUID_STR_SIZE];
    uint8_t             source_node_uuid[CLIP_UUID_BYTES];
    char                source_node_uuid_str[CLIP_UUID_STR_SIZE];
    uint8_t             target_node_uuid[CLIP_UUID_BYTES];
    char                target_node_uuid_str[CLIP_UUID_STR_SIZE];
    ClipConnectionState state;
    uint64_t            requested_at_ms;
    uint64_t            responded_at_ms;
} ClipConnectionInfo;

/* ── Security Event Representation ──────────────────────────────────────── */

#ifndef CLIP_RULE_CATEGORY_DEFINED
#define CLIP_RULE_CATEGORY_DEFINED
typedef enum {
    CLIP_RULE_CAT_THREAT     = 1,
    CLIP_RULE_CAT_SUSPICIOUS = 2,
    CLIP_RULE_CAT_CUSTOM     = 3
} ClipRuleCategory;
#endif

#ifndef CLIP_SEVERITY_DEFINED
#define CLIP_SEVERITY_DEFINED
typedef enum {
    CLIP_SEVERITY_NONE       = 0,
    CLIP_SEVERITY_INFO       = 1,
    CLIP_SEVERITY_SUSPICIOUS = 2,
    CLIP_SEVERITY_THREAT     = 3
} ClipSeverity;
#endif

#ifndef CLIP_EVENT_STATUS_DEFINED
#define CLIP_EVENT_STATUS_DEFINED
typedef enum {
    CLIP_EVENT_STATUS_PENDING   = 0,  /* awaiting admin review    */
    CLIP_EVENT_STATUS_REVIEWED  = 1,  /* admin took action        */
    CLIP_EVENT_STATUS_FALSE_POS = 2   /* admin dismissed          */
} ClipEventStatus;
#endif

#endif /* CLIP_TYPES_H */

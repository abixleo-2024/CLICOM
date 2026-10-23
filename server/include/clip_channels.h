/*
 * clip_channels.h — CLICOM Server-Side Channel & Membership Management
 *
 * Implements persistent channel operations:
 * - Server-generated immutable channel_uuid (UUIDv4)
 * - Human-facing collision-free join_key (e.g. "GC-4821")
 * - SQLite persistent channel creation and join_by_key
 * - Persistent channel membership (channel_uuid + node_uuid)
 * - Authoritative presence resolution (runtime TCP connection state)
 */

#ifndef CLIP_CHANNELS_H
#define CLIP_CHANNELS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sqlite3.h>
#include "clip_errors.h"
#include "clip_types.h"


typedef struct {
    ClipUuid     channel_uuid;
    char         channel_uuid_str[CLIP_UUID_STR_SIZE];
    char         join_key[CLIP_JOIN_KEY_MAX];
    char         name[CLIP_DISPLAY_NAME_MAX];
    ClipUuid     creator_node_uuid;
    uint64_t     created_at_ms;
    bool         active;
    uint16_t     member_limit;
    bool         key_revoked;
    size_t       member_count;
} ClipChannelRecord;

/* Initialize channel and membership schemas in the existing SQLite database */
ClipError clip_channel_db_init_schema(sqlite3* db);

/*
 * Create a new channel (defaults to member_limit = 16):
 * - Generates unique UUIDv4 for channel_uuid
 * - Generates unique join_key in "GC-XXXX" format
 * - Atomically inserts channel and adds creator_node_uuid as initial member
 */
ClipError clip_channel_create(sqlite3*        db,
                              const ClipUuid* creator_node_uuid,
                              const char*     channel_name,
                              ClipUuid*       out_channel_uuid,
                              char*           out_join_key,
                              size_t          join_key_buf_len);

/*
 * Create a new channel with explicit participant capacity limit:
 * - Generates unique UUIDv4 for channel_uuid
 * - Generates unique join_key in "GC-XXXX" format
 * - member_limit: participant limit including creator (min 2, max 64)
 * - Atomically inserts channel and adds creator_node_uuid as initial member
 */
ClipError clip_channel_create_with_limit(sqlite3*        db,
                                         const ClipUuid* creator_node_uuid,
                                         const char*     channel_name,
                                         uint16_t        member_limit,
                                         ClipUuid*       out_channel_uuid,
                                         char*           out_join_key,
                                         size_t          join_key_buf_len);

/* Revoke the invitation join key for a channel (owner-only) */
ClipError clip_channel_revoke_key(sqlite3*        db,
                                  const ClipUuid* channel_uuid,
                                  const ClipUuid* caller_node_uuid);

/* Close/deactivate a channel and mark all memberships inactive (owner-only) */
ClipError clip_channel_close(sqlite3*        db,
                             const ClipUuid* channel_uuid,
                             const ClipUuid* caller_node_uuid);

/* Leave a channel: marks caller's membership as inactive */
ClipError clip_channel_leave(sqlite3*        db,
                             const ClipUuid* channel_uuid,
                             const ClipUuid* node_uuid);

/*
 * Join an existing channel using its join_key:
 * - Resolves active channel by join_key
 * - Verifies join_key is not revoked
 * - Atomically verifies capacity limit under concurrent joins
 * - Adds node_uuid as member if not already present (idempotent)
 * - Returns channel_uuid and channel name
 */
ClipError clip_channel_join_by_key(sqlite3*        db,
                                   const ClipUuid* node_uuid,
                                   const char*     join_key,
                                   ClipUuid*       out_channel_uuid,
                                   char*           out_channel_name,
                                   size_t          name_buf_len);

/* Query channel record by channel_uuid */
ClipError clip_channel_get_by_uuid(sqlite3*           db,
                                   const ClipUuid*    channel_uuid,
                                   ClipChannelRecord* out_channel);

/* Query channel record by join_key */
ClipError clip_channel_get_by_join_key(sqlite3*           db,
                                       const char*        join_key,
                                       ClipChannelRecord* out_channel);

/* Check if a node is an active member of a channel */
ClipError clip_channel_is_member(sqlite3*        db,
                                 const ClipUuid* channel_uuid,
                                 const ClipUuid* node_uuid,
                                 bool*           out_is_member);

/*
 * Retrieve all persistent members of a channel.
 * Caller must free *out_members using clip_channel_free_members().
 */
ClipError clip_channel_get_members(sqlite3*            db,
                                   const ClipUuid*     channel_uuid,
                                   ClipChannelMember** out_members,
                                   size_t*             out_count);

/* Free member array returned by clip_channel_get_members() */
void clip_channel_free_members(ClipChannelMember* members);

/* List all channels a node is a member of */
ClipError clip_channel_list_for_node(sqlite3*            db,
                                     const ClipUuid*     node_uuid,
                                     ClipChannelRecord** out_channels,
                                     size_t*             out_count);

/* Free channel array returned by clip_channel_list_for_node() */
void clip_channel_free_list(ClipChannelRecord* channels);

#endif /* CLIP_CHANNELS_H */

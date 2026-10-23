/*
 * clip_admin.h — CLICOM Administrative Types, Roles, and Cryptographic Security
 *
 * Implements:
 * - PBKDF2-HMAC-SHA256 password verifiers (100,000 iterations, 16-byte salt, 32-byte verifier)
 * - Constant-time verifier comparison with stack buffer zeroing
 * - Administrator roles: OBSERVER, MODERATOR, SUPER_ADMIN
 * - Hierarchical permission checks
 * - Node sanction states: ACTIVE, RESTRICTED, BANNED
 * - Append-only administrative audit record definitions
 */

#ifndef CLICOM_SECURITY_ADMIN_H
#define CLICOM_SECURITY_ADMIN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "clip_errors.h"
#include "clip_types.h"
#include "clip_protocol.h"

#define CLIP_ADMIN_SALT_BYTES         16u
#define CLIP_ADMIN_VERIFIER_BYTES     32u
#define CLIP_ADMIN_DEFAULT_ITERATIONS 100000u
#define CLIP_ADMIN_PASSWORD_MIN_LEN   10u
#define CLIP_ADMIN_USERNAME_MAX_LEN   64u
#define CLIP_ADMIN_REASON_MAX_LEN     256u

/* Audit record status outcomes */
typedef enum {
    CLIP_AUDIT_STATUS_SUCCESS = 1,
    CLIP_AUDIT_STATUS_DENIED  = 2,
    CLIP_AUDIT_STATUS_FAILED  = 3
} ClipAuditStatus;

/* Persistent Node Sanction States */
typedef enum {
    CLIP_SANCTION_ACTIVE     = 0,  /* Standard active participant */
    CLIP_SANCTION_RESTRICTED = 1,  /* Listen-only (PTT/session blocked) */
    CLIP_SANCTION_BANNED     = 2   /* Connection completely blocked */
} ClipNodeSanctionState;

/* Administrator User Profile */
typedef struct {
    uint8_t             admin_uuid[CLIP_UUID_BYTES];
    char                username[CLIP_ADMIN_USERNAME_MAX_LEN];
    ClipAdminPermission role;
    uint8_t             salt[CLIP_ADMIN_SALT_BYTES];
    uint8_t             verifier[CLIP_ADMIN_VERIFIER_BYTES];
    uint32_t            iterations;
    uint64_t            created_at_ms;
    uint64_t            updated_at_ms;
} ClipAdminUser;

/* Persistent Node Sanction Record */
typedef struct {
    uint8_t               node_uuid[CLIP_UUID_BYTES];
    ClipNodeSanctionState status;
    char                  reason[CLIP_ADMIN_REASON_MAX_LEN];
    uint8_t               admin_uuid[CLIP_UUID_BYTES];
    uint64_t              updated_at_ms;
} ClipNodeSanction;

/* Append-Only Administrative Audit Record */
typedef struct {
    uint32_t            audit_id;
    uint8_t             admin_uuid[CLIP_UUID_BYTES];
    ClipAdminActionType action_type;
    uint8_t             target_uuid[CLIP_UUID_BYTES];
    bool                has_target_uuid;
    char                reason[CLIP_ADMIN_REASON_MAX_LEN];
    uint32_t            related_event_id;     /* 0 if none */
    uint8_t             related_session_uuid[CLIP_UUID_BYTES];
    bool                has_related_session;
    uint8_t             related_channel_uuid[CLIP_UUID_BYTES];
    bool                has_related_channel;
    ClipAuditStatus     status;
    int16_t             error_code;
    uint64_t            created_at_ms;
} ClipAdminAuditRecord;

/*
 * Derives a PBKDF2-HMAC-SHA256 password verifier.
 *
 * Parameters:
 *   password: Plaintext password (min 10 characters)
 *   salt: 16 cryptographically random bytes
 *   iterations: Number of PBKDF2 rounds (min 1000, recommended 100000)
 *   out_verifier: Output buffer for 32-byte verifier
 */
ClipError clip_admin_hash_password(const char*    password,
                                   const uint8_t* salt,
                                   uint32_t       iterations,
                                   uint8_t        out_verifier[CLIP_ADMIN_VERIFIER_BYTES]);

/*
 * Verifies a candidate password against an existing verifier in constant time.
 * Wipes the temporary candidate verifier from stack memory before returning.
 */
bool clip_admin_verify_password(const char*    password,
                                const uint8_t* salt,
                                uint32_t       iterations,
                                const uint8_t  expected_verifier[CLIP_ADMIN_VERIFIER_BYTES]);

/*
 * Checks if the specified role is authorized to perform the requested action.
 * OBSERVER: Cannot perform any mutating actions.
 * MODERATOR: Can disconnect, restrict/unrestrict, lock/unlock channel, mark false positive, review event.
 * SUPER_ADMIN: Can perform all moderator actions plus ban/unban node and create admin.
 */
bool clip_admin_can_perform(ClipAdminPermission role, ClipAdminActionType action);

/* Returns human-readable string for admin action */
const char* clip_admin_action_name(ClipAdminActionType action);

/* Returns human-readable string for admin role */
const char* clip_admin_role_name(ClipAdminPermission role);

/* Returns human-readable string for sanction state */
const char* clip_admin_sanction_name(ClipNodeSanctionState state);

#endif /* CLICOM_SECURITY_ADMIN_H */

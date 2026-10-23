/*
 * clip_identity.h — CLICOM Server-Side Persistent Identity Storage (SQLite)
 *
 * Implements persistent identity management:
 * - Server-assigned immutable node_uuid (UUIDv4)
 * - 256-bit cryptographically secure credential generation
 * - SHA-256 credential verifier storage (raw credentials NEVER stored)
 * - Atomic database operations and schema management
 * - Authenticated reconnect and revocation enforcement
 */

#ifndef CLIP_IDENTITY_H
#define CLIP_IDENTITY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_errors.h"
#include "clip_types.h"
#include "clip_crypto.h"

#define CLIP_DEFAULT_IDENTITY_DB "clicom_identity.db"

typedef struct ClipIdentityDb ClipIdentityDb;

/* Open/initialize the SQLite identity database */
ClipError clip_identity_db_open(ClipIdentityDb** out_db, const char* db_path);

/* Close the SQLite identity database */
void clip_identity_db_close(ClipIdentityDb* db);

/* Get underlying sqlite3 handle */
struct sqlite3* clip_identity_get_sqlite(ClipIdentityDb* db);

/*
 * Register a new node identity:
 * - Generates cryptographically secure 16-byte UUIDv4
 * - Generates cryptographically secure 32-byte credential
 * - Computes SHA-256(credential) verifier
 * - Persists record atomically in SQLite
 * - Returns generated UUID and raw credential to caller (for REGISTER_ACK transmission)
 */
ClipError clip_identity_register(ClipIdentityDb* db,
                                 const char*     display_name,
                                 ClipUuid*       out_uuid,
                                 uint8_t         out_credential[CLIP_CREDENTIAL_BYTES]);

/*
 * Authenticate an existing node:
 * - Looks up node by UUID
 * - Checks active and revoked status (returns CLIP_ERR_DENIED if revoked)
 * - Computes SHA-256(credential)
 * - Constant-time comparison with stored verifier
 * - Updates last_authenticated_at timestamp on success
 * - Copies current display_name
 */
ClipError clip_identity_authenticate(ClipIdentityDb* db,
                                     const ClipUuid* uuid,
                                     const uint8_t   credential[CLIP_CREDENTIAL_BYTES],
                                     char*           out_display_name,
                                     size_t          name_buf_len,
                                     bool*           out_is_revoked);

/* Lookup identity by UUID without verifying credentials */
ClipError clip_identity_get(ClipIdentityDb* db,
                            const ClipUuid* uuid,
                            ClipNodeInfo*   out_info,
                            bool*           out_is_revoked);

/* Set revoked status for node */
ClipError clip_identity_set_revoked(ClipIdentityDb* db,
                                    const ClipUuid* uuid,
                                    bool            revoked);

/* Update display name */
ClipError clip_identity_update_display_name(ClipIdentityDb* db,
                                           const ClipUuid* uuid,
                                           const char*     new_display_name);

#endif /* CLIP_IDENTITY_H */

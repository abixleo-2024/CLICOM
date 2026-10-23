/*
 * clip_admin.c — CLICOM Administrative Security Implementation
 */

#include "clip_admin.h"
#include "clip_crypto.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

ClipError clip_admin_hash_password(const char*    password,
                                   const uint8_t* salt,
                                   uint32_t       iterations,
                                   uint8_t        out_verifier[CLIP_ADMIN_VERIFIER_BYTES])
{
    if (!password || !salt || !out_verifier) {
        return CLIP_ERR_INVALID;
    }
    size_t pass_len = strlen(password);
    if (pass_len < CLIP_ADMIN_PASSWORD_MIN_LEN) {
        return CLIP_ERR_INVALID;
    }
    if (iterations < 1000u) {
        return CLIP_ERR_INVALID;
    }

    int rc = PKCS5_PBKDF2_HMAC(password,
                               (int)pass_len,
                               salt,
                               (int)CLIP_ADMIN_SALT_BYTES,
                               (int)iterations,
                               EVP_sha256(),
                               (int)CLIP_ADMIN_VERIFIER_BYTES,
                               out_verifier);

    return (rc == 1) ? CLIP_OK : CLIP_ERR_GENERIC;
}

bool clip_admin_verify_password(const char*    password,
                                const uint8_t* salt,
                                uint32_t       iterations,
                                const uint8_t  expected_verifier[CLIP_ADMIN_VERIFIER_BYTES])
{
    if (!password || !salt || !expected_verifier) {
        return false;
    }

    uint8_t candidate[CLIP_ADMIN_VERIFIER_BYTES];
    memset(candidate, 0, sizeof(candidate));

    ClipError err = clip_admin_hash_password(password, salt, iterations, candidate);
    if (err != CLIP_OK) {
        OPENSSL_cleanse(candidate, sizeof(candidate));
        return false;
    }

    bool match = clip_crypto_secure_equal(candidate, expected_verifier, CLIP_ADMIN_VERIFIER_BYTES);
    OPENSSL_cleanse(candidate, sizeof(candidate));

    return match;
}

bool clip_admin_can_perform(ClipAdminPermission role, ClipAdminActionType action)
{
    switch (action) {
    case CLIP_ADMIN_DISCONNECT_NODE:
    case CLIP_ADMIN_RESTRICT_NODE:
    case CLIP_ADMIN_UNRESTRICT_NODE:
    case CLIP_ADMIN_LOCK_CHANNEL:
    case CLIP_ADMIN_UNLOCK_CHANNEL:
    case CLIP_ADMIN_MARK_FALSE_POS:
    case CLIP_ADMIN_REVIEW_EVENT:
        return (role >= CLIP_ADMIN_PERM_MODERATOR);

    case CLIP_ADMIN_BAN_NODE:
    case CLIP_ADMIN_UNBAN_NODE:
    case CLIP_ADMIN_CREATE_ADMIN:
        return (role >= CLIP_ADMIN_PERM_SUPER_ADMIN);

    default:
        return false;
    }
}

const char* clip_admin_action_name(ClipAdminActionType action)
{
    switch (action) {
    case CLIP_ADMIN_DISCONNECT_NODE: return "DISCONNECT_NODE";
    case CLIP_ADMIN_RESTRICT_NODE:   return "RESTRICT_NODE";
    case CLIP_ADMIN_UNRESTRICT_NODE: return "UNRESTRICT_NODE";
    case CLIP_ADMIN_BAN_NODE:        return "BAN_NODE";
    case CLIP_ADMIN_UNBAN_NODE:      return "UNBAN_NODE";
    case CLIP_ADMIN_LOCK_CHANNEL:    return "LOCK_CHANNEL";
    case CLIP_ADMIN_UNLOCK_CHANNEL:  return "UNLOCK_CHANNEL";
    case CLIP_ADMIN_MARK_FALSE_POS:  return "MARK_FALSE_POS";
    case CLIP_ADMIN_REVIEW_EVENT:    return "REVIEW_EVENT";
    case CLIP_ADMIN_CREATE_ADMIN:    return "CREATE_ADMIN";
    default:                         return "UNKNOWN_ACTION";
    }
}

const char* clip_admin_role_name(ClipAdminPermission role)
{
    switch (role) {
    case CLIP_ADMIN_PERM_OBSERVER:    return "OBSERVER";
    case CLIP_ADMIN_PERM_MODERATOR:   return "MODERATOR";
    case CLIP_ADMIN_PERM_SUPER_ADMIN: return "SUPER_ADMIN";
    default:                          return "UNKNOWN_ROLE";
    }
}

const char* clip_admin_sanction_name(ClipNodeSanctionState state)
{
    switch (state) {
    case CLIP_SANCTION_ACTIVE:     return "ACTIVE";
    case CLIP_SANCTION_RESTRICTED: return "RESTRICTED";
    case CLIP_SANCTION_BANNED:     return "BANNED";
    default:                       return "UNKNOWN_SANCTION";
    }
}

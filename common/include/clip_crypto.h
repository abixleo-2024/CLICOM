/*
 * clip_crypto.h — CLICOM Cryptographic Primitives
 *
 * Provides cryptographic operations:
 * - BCryptGenRandom for cryptographically secure random bytes
 * - Canonical UUIDv4 generation
 * - SHA-256 credential verifier computation
 * - Constant-time memory comparison
 */

#ifndef CLIP_CRYPTO_H
#define CLIP_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_errors.h"
#include "clip_types.h"

#define CLIP_CREDENTIAL_BYTES    32u  /* 256-bit credential */
#define CLIP_SHA256_BYTES        32u  /* 256-bit SHA-256 verifier */

/* Fills buffer with cryptographically secure random bytes via BCryptGenRandom */
ClipError clip_crypto_random_bytes(uint8_t* out, size_t len);

/* Generates a RFC 4122 compliant version 4 UUID with random bytes */
ClipError clip_crypto_uuid_generate(ClipUuid* out_uuid);

/* Computes SHA-256 hash of data (32 bytes output) */
ClipError clip_crypto_sha256(const uint8_t* data, size_t len, uint8_t out_hash[CLIP_SHA256_BYTES]);

/*
 * Constant-time byte comparison.
 * Returns true if both buffers are identical, false otherwise.
 * Prevents timing side channels when verifying credentials.
 */
bool clip_crypto_secure_equal(const uint8_t* a, const uint8_t* b, size_t len);

#endif /* CLIP_CRYPTO_H */

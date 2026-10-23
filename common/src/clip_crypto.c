/*
 * clip_crypto.c — CLICOM Cryptographic Primitives Implementation
 */

#include "clip_crypto.h"
#include <string.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <bcrypt.h>
#  ifndef NT_SUCCESS
#    define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#  endif
#endif

ClipError clip_crypto_random_bytes(uint8_t* out, size_t len)
{
    if (!out || len == 0) return CLIP_ERR_INVALID;

#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        return CLIP_ERR_GENERIC;
    }
    return CLIP_OK;
#else
    /* Fallback for POSIX platforms */
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return CLIP_ERR_IO;
    size_t read_bytes = fread(out, 1, len, f);
    fclose(f);
    return (read_bytes == len) ? CLIP_OK : CLIP_ERR_IO;
#endif
}

ClipError clip_crypto_uuid_generate(ClipUuid* out_uuid)
{
    if (!out_uuid) return CLIP_ERR_INVALID;

    ClipError err = clip_crypto_random_bytes(out_uuid->bytes, CLIP_UUID_BYTES);
    if (err != CLIP_OK) return err;

    /* RFC 4122 Section 4.4: Version 4 UUID
     * Set bits 4-7 of the 7th byte (index 6) to 0100 (0x40) */
    out_uuid->bytes[6] = (uint8_t)((out_uuid->bytes[6] & 0x0F) | 0x40);

    /* Set bits 6-7 of the 9th byte (index 8) to 10 (0x80) */
    out_uuid->bytes[8] = (uint8_t)((out_uuid->bytes[8] & 0x3F) | 0x80);

    return CLIP_OK;
}

ClipError clip_crypto_sha256(const uint8_t* data, size_t len, uint8_t out_hash[CLIP_SHA256_BYTES])
{
    if (!out_hash) return CLIP_ERR_INVALID;

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        return CLIP_ERR_GENERIC;
    }

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return CLIP_ERR_GENERIC;
    }

    if (len > 0 && data) {
        status = BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
        if (!NT_SUCCESS(status)) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return CLIP_ERR_GENERIC;
        }
    }

    status = BCryptFinishHash(hHash, out_hash, CLIP_SHA256_BYTES, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!NT_SUCCESS(status)) {
        return CLIP_ERR_GENERIC;
    }
    return CLIP_OK;
#else
    return CLIP_ERR_GENERIC;
#endif
}

bool clip_crypto_secure_equal(const uint8_t* a, const uint8_t* b, size_t len)
{
    if (!a || !b) return false;

    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return (diff == 0);
}

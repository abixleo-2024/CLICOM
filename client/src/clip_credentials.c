/*
 * clip_credentials.c — CLICOM Client Credential Storage (Windows DPAPI)
 */

#include "clip_credentials.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <wincrypt.h>
#endif

#define CLIP_CRED_MAGIC   0x43435244u /* "CCRD" */
#define CLIP_CRED_VERSION 1u

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint8_t  node_uuid[CLIP_UUID_BYTES];
    uint8_t  credential[CLIP_CREDENTIAL_BYTES];
    char     display_name[CLIP_DISPLAY_NAME_MAX];
} ClipCredDiskRecord;
#pragma pack(pop)

bool clip_credentials_exists(const char* filepath)
{
    if (!filepath) filepath = CLIP_DEFAULT_CREDENTIAL_FILE;

    FILE* f = fopen(filepath, "rb");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}

ClipError clip_credentials_save(const char* filepath, const ClipClientCredentials* creds)
{
    if (!creds) return CLIP_ERR_INVALID;
    if (!filepath) filepath = CLIP_DEFAULT_CREDENTIAL_FILE;

    ClipCredDiskRecord rec;
    memset(&rec, 0, sizeof(rec));
    rec.magic = CLIP_CRED_MAGIC;
    rec.version = CLIP_CRED_VERSION;
    memcpy(rec.node_uuid, creds->node_uuid.bytes, CLIP_UUID_BYTES);
    memcpy(rec.credential, creds->credential, CLIP_CREDENTIAL_BYTES);
    strncpy(rec.display_name, creds->display_name, sizeof(rec.display_name) - 1);

#ifdef _WIN32
    DATA_BLOB in_blob;
    DATA_BLOB out_blob;
    in_blob.pbData = (BYTE*)&rec;
    in_blob.cbData = sizeof(rec);

    /* Encrypt via DPAPI bound to the current logged-in user profile */
    if (!CryptProtectData(&in_blob,
                          L"CLICOM Node Credential",
                          NULL,
                          NULL,
                          NULL,
                          CRYPTPROTECT_UI_FORBIDDEN,
                          &out_blob)) {
        SecureZeroMemory(&rec, sizeof(rec));
        return CLIP_ERR_IO;
    }

    SecureZeroMemory(&rec, sizeof(rec));

    FILE* f = fopen(filepath, "wb");
    if (!f) {
        LocalFree(out_blob.pbData);
        return CLIP_ERR_IO;
    }

    size_t written = fwrite(out_blob.pbData, 1, out_blob.cbData, f);
    fflush(f);
    fclose(f);
    LocalFree(out_blob.pbData);

    return (written == out_blob.cbData) ? CLIP_OK : CLIP_ERR_IO;
#else
    FILE* f = fopen(filepath, "wb");
    if (!f) return CLIP_ERR_IO;
    size_t written = fwrite(&rec, 1, sizeof(rec), f);
    fflush(f);
    fclose(f);
    memset(&rec, 0, sizeof(rec));
    return (written == sizeof(rec)) ? CLIP_OK : CLIP_ERR_IO;
#endif
}

ClipError clip_credentials_load(const char* filepath, ClipClientCredentials* out_creds)
{
    if (!out_creds) return CLIP_ERR_INVALID;
    if (!filepath) filepath = CLIP_DEFAULT_CREDENTIAL_FILE;

    FILE* f = fopen(filepath, "rb");
    if (!f) return CLIP_ERR_NOT_FOUND;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 65536) {
        fclose(f);
        return CLIP_ERR_INVALID;
    }

    uint8_t* enc_buf = (uint8_t*)malloc((size_t)fsize);
    if (!enc_buf) {
        fclose(f);
        return CLIP_ERR_NOMEM;
    }

    size_t read_bytes = fread(enc_buf, 1, (size_t)fsize, f);
    fclose(f);

    if (read_bytes != (size_t)fsize) {
        free(enc_buf);
        return CLIP_ERR_IO;
    }

#ifdef _WIN32
    DATA_BLOB in_blob;
    DATA_BLOB out_blob;
    in_blob.pbData = enc_buf;
    in_blob.cbData = (DWORD)fsize;

    if (!CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob)) {
        free(enc_buf);
        return CLIP_ERR_AUTH;
    }

    free(enc_buf);

    if (out_blob.cbData != sizeof(ClipCredDiskRecord)) {
        LocalFree(out_blob.pbData);
        return CLIP_ERR_INVALID;
    }

    ClipCredDiskRecord rec;
    memcpy(&rec, out_blob.pbData, sizeof(rec));
    LocalFree(out_blob.pbData);
#else
    if (read_bytes != sizeof(ClipCredDiskRecord)) {
        free(enc_buf);
        return CLIP_ERR_INVALID;
    }
    ClipCredDiskRecord rec;
    memcpy(&rec, enc_buf, sizeof(rec));
    free(enc_buf);
#endif

    if (rec.magic != CLIP_CRED_MAGIC || rec.version != CLIP_CRED_VERSION) {
#ifdef _WIN32
        SecureZeroMemory(&rec, sizeof(rec));
#else
        memset(&rec, 0, sizeof(rec));
#endif
        return CLIP_ERR_INVALID;
    }

    memcpy(out_creds->node_uuid.bytes, rec.node_uuid, CLIP_UUID_BYTES);
    memcpy(out_creds->credential, rec.credential, CLIP_CREDENTIAL_BYTES);
    strncpy(out_creds->display_name, rec.display_name, sizeof(out_creds->display_name) - 1);
    out_creds->display_name[sizeof(out_creds->display_name) - 1] = '\0';

#ifdef _WIN32
    SecureZeroMemory(&rec, sizeof(rec));
#else
    memset(&rec, 0, sizeof(rec));
#endif
    return CLIP_OK;
}

ClipError clip_credentials_delete(const char* filepath)
{
    if (!filepath) filepath = CLIP_DEFAULT_CREDENTIAL_FILE;
    if (remove(filepath) == 0) {
        return CLIP_OK;
    }
    return CLIP_ERR_NOT_FOUND;
}

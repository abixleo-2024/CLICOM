/*
 * clip_credentials.h — CLICOM Client Credential Storage Abstraction
 *
 * Provides OS-protected credential storage (Windows DPAPI).
 * Protects 256-bit credentials and node UUID without exposing raw keys.
 */

#ifndef CLIP_CREDENTIALS_H
#define CLIP_CREDENTIALS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_errors.h"
#include "clip_types.h"
#include "clip_crypto.h"

#define CLIP_DEFAULT_CREDENTIAL_FILE "clicom_node.cred"

typedef struct {
    ClipUuid node_uuid;
    uint8_t  credential[CLIP_CREDENTIAL_BYTES];
    char     display_name[CLIP_DISPLAY_NAME_MAX];
} ClipClientCredentials;

/* Check if credential file exists */
bool clip_credentials_exists(const char* filepath);

/* Save credentials securely using Windows DPAPI */
ClipError clip_credentials_save(const char* filepath, const ClipClientCredentials* creds);

/* Load credentials and decrypt using Windows DPAPI */
ClipError clip_credentials_load(const char* filepath, ClipClientCredentials* out_creds);

/* Delete credential file */
ClipError clip_credentials_delete(const char* filepath);

#endif /* CLIP_CREDENTIALS_H */

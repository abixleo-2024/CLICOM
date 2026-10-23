/*
 * storage.h — CLICOM Storage Backend Interface
 *
 * Phase 0 : Interface declaration only.
 * Phase 17: SQLite backend implementation.
 * Future  : PostgreSQL, MySQL backends.
 *
 * ── Persistence Policy ───────────────────────────────────────────────────
 *
 *   Channel definitions, join keys, membership history, and configuration
 *   are PERSISTENT. A server restart does NOT destroy channel records.
 *
 *   Active runtime state (PTT floor hold, in-progress sessions) is RESET
 *   on restart and reconstructed from persisted state where appropriate.
 *
 * ── Backend Selection ────────────────────────────────────────────────────
 *
 *   storage_open("sqlite",     "path/to/clicom.db")
 *   storage_open("postgresql", "host=... dbname=clicom")  [future]
 */

#ifndef CLICOM_STORAGE_H
#define CLICOM_STORAGE_H

#include <stdint.h>
#include <stddef.h>
#include "clip_types.h"
#include "clip_errors.h"

typedef struct StorageBackend StorageBackend;

/* ── Lifecycle ──────────────────────────────────────────────────────────── */
StorageBackend* storage_open(const char* backend_name, const char* conn_str);
void            storage_close(StorageBackend* sb);

/* ── Node records ───────────────────────────────────────────────────────── */
ClipError storage_node_upsert(StorageBackend* sb, const ClipNodeInfo* node);
ClipError storage_node_get(StorageBackend* sb,
                            const uint8_t node_uuid[CLIP_UUID_BYTES],
                            ClipNodeInfo* out_node);

/* ── Channel records (persistent across restarts) ───────────────────────── */
ClipError storage_channel_create(StorageBackend* sb,
                                  const ClipChannelInfo* ch);
ClipError storage_channel_get_by_uuid(StorageBackend* sb,
                                       const uint8_t uuid[CLIP_UUID_BYTES],
                                       ClipChannelInfo* out_ch);
ClipError storage_channel_get_by_join_key(StorageBackend* sb,
                                           const char* join_key,
                                           ClipChannelInfo* out_ch);
ClipError storage_channel_update(StorageBackend* sb,
                                  const ClipChannelInfo* ch);

/* ── Session records (Phase 17+) ────────────────────────────────────────── */
/* Full schema TBD in Phase 8/17. */

/* ── Caption / transcript records (Phase 14+) ──────────────────────────── */
/* Full schema TBD in Phase 13/14. */

/* ── Security event records (Phase 15+) ────────────────────────────────── */
/* Full schema TBD in Phase 15. */

/* ── Admin audit log (Phase 16+) ───────────────────────────────────────── */
/* Full schema TBD in Phase 16. */

#endif /* CLICOM_STORAGE_H */

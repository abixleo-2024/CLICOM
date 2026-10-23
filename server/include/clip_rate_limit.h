/*
 * clip_rate_limit.h — CLICOM Server-Side Authentication Rate Limiting (Phase 17 Stage 4)
 *
 * Implements bounded IP-based rate limiting for node and admin authentication:
 * - 5 failed attempts per source IP within a rolling 60,000 ms window
 * - Block duration: 60,000 ms from the 5th failed attempt
 * - Capacity: exactly 128 IP entries
 * - Strict block protection: active blocks can NEVER be evicted
 * - Unblocked entries evicted using LRU
 * - Capacity saturation protection: if all 128 entries are actively blocked,
 *   new untracked IPs are rejected immediately rather than evicting an active block
 * - Thread-safe mutex protection across concurrent requests
 * - Injectable/monotonic clock support
 */

#ifndef CLICOM_CLIP_RATE_LIMIT_H
#define CLICOM_CLIP_RATE_LIMIT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_errors.h"

#define CLIP_RATE_LIMIT_MAX_ENTRIES 128
#define CLIP_RATE_LIMIT_MAX_ATTEMPTS 5
#define CLIP_RATE_LIMIT_WINDOW_MS    60000ULL
#define CLIP_RATE_LIMIT_BLOCK_MS     60000ULL

typedef struct {
    char     ip_str[64];
    uint32_t fail_count;
    uint64_t attempts[CLIP_RATE_LIMIT_MAX_ATTEMPTS];
    uint64_t blocked_until_ms;
    uint64_t last_accessed_ms;
    bool     is_used;
} ClipRateLimitEntry;

typedef struct ClipRateLimiter {
    ClipRateLimitEntry entries[CLIP_RATE_LIMIT_MAX_ENTRIES];
    size_t             count;
    uint64_t           mock_now_ms;  /* 0 = use system clock */
    void*              mutex;        /* CRITICAL_SECTION* on Win32, pthread_mutex_t* on POSIX */
} ClipRateLimiter;

/* Initialize rate limiter */
ClipError clip_rate_limiter_init(ClipRateLimiter* rl);

/* Clean up rate limiter resources */
void clip_rate_limiter_cleanup(ClipRateLimiter* rl);

/*
 * Check whether an IP is currently blocked or if all entries are saturated with blocks.
 * Returns:
 *   CLIP_OK           - IP is allowed to attempt authentication
 *   CLIP_ERR_DENIED   - IP is actively blocked OR table is saturated with active blocks
 *   CLIP_ERR_INVALID  - Invalid arguments
 */
ClipError clip_rate_limiter_check(ClipRateLimiter* rl, const char* ip_str, uint64_t now_ms);

/*
 * Record a failed authentication attempt for an IP.
 * If this failure reaches the 5-attempt limit within the 60s window, a 60s block begins.
 * Returns:
 *   CLIP_OK           - Failure recorded, IP is not yet blocked
 *   CLIP_ERR_DENIED   - 5th failure reached (or already blocked), IP is now blocked
 *   CLIP_ERR_NOMEM    - Table full with 128 active blocks; could not track new IP
 */
ClipError clip_rate_limiter_record_failure(ClipRateLimiter* rl, const char* ip_str, uint64_t now_ms);

/*
 * Record a successful authentication for an IP.
 * Note: If the IP is actively blocked, success is not allowed to bypass the block.
 * When an unblocked IP successfully authenticates, its rolling failure count is reset.
 */
ClipError clip_rate_limiter_record_success(ClipRateLimiter* rl, const char* ip_str, uint64_t now_ms);

/* Set mock clock (0 = use real time) */
void clip_rate_limiter_set_mock_clock(ClipRateLimiter* rl, uint64_t mock_now_ms);

#endif /* CLICOM_CLIP_RATE_LIMIT_H */

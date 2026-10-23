/*
 * clip_rate_limit.c — CLICOM Server-Side Authentication Rate Limiting Implementation
 */

#include "clip_rate_limit.h"
#include "clip_log.h"
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sys/time.h>
#endif

static uint64_t rl_current_time_ms(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return (uint64_t)((uli.QuadPart - 116444736000000000ULL) / 10000ULL);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
#endif
}

static void rl_lock(ClipRateLimiter* rl)
{
    if (!rl || !rl->mutex) return;
#ifdef _WIN32
    EnterCriticalSection((CRITICAL_SECTION*)rl->mutex);
#else
    pthread_mutex_lock((pthread_mutex_t*)rl->mutex);
#endif
}

static void rl_unlock(ClipRateLimiter* rl)
{
    if (!rl || !rl->mutex) return;
#ifdef _WIN32
    LeaveCriticalSection((CRITICAL_SECTION*)rl->mutex);
#else
    pthread_mutex_unlock((pthread_mutex_t*)rl->mutex);
#endif
}

ClipError clip_rate_limiter_init(ClipRateLimiter* rl)
{
    if (!rl) return CLIP_ERR_INVALID;
    memset(rl, 0, sizeof(ClipRateLimiter));

#ifdef _WIN32
    CRITICAL_SECTION* cs = (CRITICAL_SECTION*)malloc(sizeof(CRITICAL_SECTION));
    if (!cs) return CLIP_ERR_NOMEM;
    InitializeCriticalSection(cs);
    rl->mutex = cs;
#else
    pthread_mutex_t* m = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
    if (!m) return CLIP_ERR_NOMEM;
    pthread_mutex_init(m, NULL);
    rl->mutex = m;
#endif

    return CLIP_OK;
}

void clip_rate_limiter_cleanup(ClipRateLimiter* rl)
{
    if (!rl) return;
    rl_lock(rl);
    rl->count = 0;
    memset(rl->entries, 0, sizeof(rl->entries));
    rl_unlock(rl);

    if (rl->mutex) {
#ifdef _WIN32
        DeleteCriticalSection((CRITICAL_SECTION*)rl->mutex);
        free(rl->mutex);
#else
        pthread_mutex_destroy((pthread_mutex_t*)rl->mutex);
        free(rl->mutex);
#endif
        rl->mutex = NULL;
    }
}

void clip_rate_limiter_set_mock_clock(ClipRateLimiter* rl, uint64_t mock_now_ms)
{
    if (!rl) return;
    rl_lock(rl);
    rl->mock_now_ms = mock_now_ms;
    rl_unlock(rl);
}

static uint64_t rl_get_now(ClipRateLimiter* rl, uint64_t explicit_now_ms)
{
    if (explicit_now_ms > 0) return explicit_now_ms;
    if (rl->mock_now_ms > 0) return rl->mock_now_ms;
    return rl_current_time_ms();
}

/* Internal helper: find entry by IP. Must be called with lock held. */
static ClipRateLimitEntry* rl_find_entry_locked(ClipRateLimiter* rl, const char* ip_str)
{
    for (size_t i = 0; i < CLIP_RATE_LIMIT_MAX_ENTRIES; i++) {
        if (rl->entries[i].is_used && strncmp(rl->entries[i].ip_str, ip_str, sizeof(rl->entries[i].ip_str)) == 0) {
            return &rl->entries[i];
        }
    }
    return NULL;
}

/* Internal helper: clean expired timestamps and check if block expired. Must be called with lock held. */
static void rl_expire_entry_locked(ClipRateLimitEntry* entry, uint64_t now_ms)
{
    if (!entry || !entry->is_used) return;

    /* If blocked_until_ms has passed, clear the block */
    if (entry->blocked_until_ms > 0 && now_ms >= entry->blocked_until_ms) {
        entry->blocked_until_ms = 0;
        entry->fail_count = 0;
    }

    /* Prune attempts older than 60 seconds */
    if (entry->fail_count > 0 && entry->blocked_until_ms == 0) {
        uint32_t valid = 0;
        for (uint32_t i = 0; i < entry->fail_count; i++) {
            if (now_ms < entry->attempts[i] + CLIP_RATE_LIMIT_WINDOW_MS) {
                entry->attempts[valid++] = entry->attempts[i];
            }
        }
        entry->fail_count = valid;
    }
}

/*
 * Allocate or evict an entry for a new IP.
 * Rule:
 * 1. An unused slot is used first.
 * 2. If table is full, evict the unblocked entry with the oldest last_accessed_ms (LRU).
 * 3. Never evict an entry whose block is currently active (blocked_until_ms > now_ms).
 * 4. If ALL 128 entries are actively blocked, return NULL (rejection).
 */
static ClipRateLimitEntry* rl_allocate_entry_locked(ClipRateLimiter* rl, const char* ip_str, uint64_t now_ms)
{
    /* 1. Try unused slot */
    for (size_t i = 0; i < CLIP_RATE_LIMIT_MAX_ENTRIES; i++) {
        if (!rl->entries[i].is_used) {
            ClipRateLimitEntry* e = &rl->entries[i];
            memset(e, 0, sizeof(ClipRateLimitEntry));
            strncpy(e->ip_str, ip_str, sizeof(e->ip_str) - 1);
            e->is_used = true;
            e->last_accessed_ms = now_ms;
            rl->count++;
            return e;
        }
    }

    /* 2. Find oldest unblocked entry to evict (LRU) */
    ClipRateLimitEntry* lru_candidate = NULL;
    uint64_t oldest_time = UINT64_MAX;

    for (size_t i = 0; i < CLIP_RATE_LIMIT_MAX_ENTRIES; i++) {
        ClipRateLimitEntry* cur = &rl->entries[i];
        rl_expire_entry_locked(cur, now_ms);

        /* Never evict an active block */
        if (cur->blocked_until_ms > 0 && now_ms < cur->blocked_until_ms) {
            continue;
        }

        if (cur->last_accessed_ms < oldest_time) {
            oldest_time = cur->last_accessed_ms;
            lru_candidate = cur;
        }
    }

    if (lru_candidate) {
        /* Evict this unblocked entry */
        memset(lru_candidate, 0, sizeof(ClipRateLimitEntry));
        strncpy(lru_candidate->ip_str, ip_str, sizeof(lru_candidate->ip_str) - 1);
        lru_candidate->is_used = true;
        lru_candidate->last_accessed_ms = now_ms;
        return lru_candidate;
    }

    /* 3. All 128 entries are actively blocked -> saturation rejection */
    return NULL;
}

ClipError clip_rate_limiter_check(ClipRateLimiter* rl, const char* ip_str, uint64_t now_ms)
{
    if (!rl || !ip_str || ip_str[0] == '\0') return CLIP_ERR_INVALID;

    rl_lock(rl);
    uint64_t cur_now = rl_get_now(rl, now_ms);

    ClipRateLimitEntry* entry = rl_find_entry_locked(rl, ip_str);
    if (entry) {
        rl_expire_entry_locked(entry, cur_now);
        entry->last_accessed_ms = cur_now;

        if (entry->blocked_until_ms > 0 && cur_now < entry->blocked_until_ms) {
            rl_unlock(rl);
            CLIP_LOGW("Rate limiter: IP %s is actively BLOCKED (remaining %llu ms)",
                      ip_str, (unsigned long long)(entry->blocked_until_ms - cur_now));
            return CLIP_ERR_DENIED;
        }
    } else {
        /* New IP: check if table is full with 128 active blocks */
        if (rl->count >= CLIP_RATE_LIMIT_MAX_ENTRIES) {
            bool has_unblocked = false;
            for (size_t i = 0; i < CLIP_RATE_LIMIT_MAX_ENTRIES; i++) {
                rl_expire_entry_locked(&rl->entries[i], cur_now);
                if (rl->entries[i].blocked_until_ms == 0 || cur_now >= rl->entries[i].blocked_until_ms) {
                    has_unblocked = true;
                    break;
                }
            }
            if (!has_unblocked) {
                rl_unlock(rl);
                CLIP_LOGW("Rate limiter: Table SATURATED with 128 active blocks. Rejecting new IP %s", ip_str);
                return CLIP_ERR_DENIED;
            }
        }
    }

    rl_unlock(rl);
    return CLIP_OK;
}

ClipError clip_rate_limiter_record_failure(ClipRateLimiter* rl, const char* ip_str, uint64_t now_ms)
{
    if (!rl || !ip_str || ip_str[0] == '\0') return CLIP_ERR_INVALID;

    rl_lock(rl);
    uint64_t cur_now = rl_get_now(rl, now_ms);

    ClipRateLimitEntry* entry = rl_find_entry_locked(rl, ip_str);
    if (!entry) {
        entry = rl_allocate_entry_locked(rl, ip_str, cur_now);
        if (!entry) {
            rl_unlock(rl);
            CLIP_LOGW("Rate limiter: Cannot allocate entry for %s (all 128 entries actively blocked)", ip_str);
            return CLIP_ERR_NOMEM;
        }
    }

    rl_expire_entry_locked(entry, cur_now);
    entry->last_accessed_ms = cur_now;

    /* If already blocked, maintain block */
    if (entry->blocked_until_ms > 0 && cur_now < entry->blocked_until_ms) {
        rl_unlock(rl);
        return CLIP_ERR_DENIED;
    }

    /* Record new failed attempt */
    if (entry->fail_count < CLIP_RATE_LIMIT_MAX_ATTEMPTS) {
        entry->attempts[entry->fail_count++] = cur_now;
    } else {
        /* Shift and append */
        for (uint32_t i = 1; i < CLIP_RATE_LIMIT_MAX_ATTEMPTS; i++) {
            entry->attempts[i - 1] = entry->attempts[i];
        }
        entry->attempts[CLIP_RATE_LIMIT_MAX_ATTEMPTS - 1] = cur_now;
    }

    /* If reached 5 failures within 60s window, apply 60s block */
    if (entry->fail_count >= CLIP_RATE_LIMIT_MAX_ATTEMPTS) {
        entry->blocked_until_ms = cur_now + CLIP_RATE_LIMIT_BLOCK_MS;
        CLIP_LOGW("Rate limiter: IP %s exceeded %u failed attempts within %llums. BLOCKED until +%llums",
                  ip_str, CLIP_RATE_LIMIT_MAX_ATTEMPTS,
                  (unsigned long long)CLIP_RATE_LIMIT_WINDOW_MS,
                  (unsigned long long)CLIP_RATE_LIMIT_BLOCK_MS);
        rl_unlock(rl);
        return CLIP_ERR_DENIED;
    }

    rl_unlock(rl);
    return CLIP_OK;
}

ClipError clip_rate_limiter_record_success(ClipRateLimiter* rl, const char* ip_str, uint64_t now_ms)
{
    if (!rl || !ip_str || ip_str[0] == '\0') return CLIP_ERR_INVALID;

    rl_lock(rl);
    uint64_t cur_now = rl_get_now(rl, now_ms);

    ClipRateLimitEntry* entry = rl_find_entry_locked(rl, ip_str);
    if (entry) {
        rl_expire_entry_locked(entry, cur_now);
        entry->last_accessed_ms = cur_now;

        /* Do not clear if currently blocked */
        if (entry->blocked_until_ms > 0 && cur_now < entry->blocked_until_ms) {
            rl_unlock(rl);
            return CLIP_ERR_DENIED;
        }

        /* Unblocked IP reset failure count */
        entry->fail_count = 0;
    }

    rl_unlock(rl);
    return CLIP_OK;
}

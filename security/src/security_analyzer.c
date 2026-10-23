/*
 * security_analyzer.c — CLICOM Security Analyzer Engine
 *
 * Implements:
 * - Thread-safe transcript inspection against loaded SecurityRuleSet
 * - Deduplication window (suppresses duplicate events within 5 seconds)
 * - Strict non-accusatory event generation (always starts in status CLIP_EVENT_STATUS_PENDING)
 * - Surrounding context capture
 * - Zero automated punishment or state alterations
 */

#include "security_analyzer.h"
#include "security_rules.h"
#include "clip_crypto.h"
#include "clip_log.h"
#include "clip_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

#define DEDUP_HISTORY_CAPACITY 64
#define DEDUP_WINDOW_MS 5000ULL

typedef struct {
    uint8_t  session_uuid[CLIP_UUID_BYTES];
    char     node_uuid_str[CLIP_UUID_STR_SIZE];
    char     matched_term[128];
    uint64_t timestamp_ms;
} DedupEntry;

struct SecurityAnalyzer {
    const SecurityRuleSet* rules;
    SecurityEventCallback  event_cb;
    void*                  user_data;
    DedupEntry             dedup[DEDUP_HISTORY_CAPACITY];
    size_t                 dedup_count;
    size_t                 dedup_head;
#ifdef _WIN32
    CRITICAL_SECTION       lock;
#endif
};

SecurityAnalyzer* security_analyzer_create(const SecurityRuleSet* rules,
                                            SecurityEventCallback   event_cb,
                                            void*                  user_data)
{
    SecurityAnalyzer* sa = (SecurityAnalyzer*)calloc(1, sizeof(SecurityAnalyzer));
    if (!sa) return NULL;

    sa->rules = rules;
    sa->event_cb = event_cb;
    sa->user_data = user_data;

#ifdef _WIN32
    InitializeCriticalSection(&sa->lock);
#endif

    return sa;
}

void security_analyzer_destroy(SecurityAnalyzer* sa)
{
    if (!sa) return;

#ifdef _WIN32
    DeleteCriticalSection(&sa->lock);
#endif

    free(sa);
}

ClipError security_analyzer_process(SecurityAnalyzer* sa,
                                    const char*        transcript,
                                    const char*        node_uuid_str,
                                    const char*        channel_uuid_str,
                                    const uint8_t      session_uuid[CLIP_UUID_BYTES],
                                    uint64_t           timestamp_ms)
{
    if (!sa || !transcript || transcript[0] == '\0') {
        return CLIP_ERR_INVALID;
    }

    if (!sa->rules || security_rules_count(sa->rules) == 0) {
        /* Safe inert/disabled behavior when no rules are configured */
        return CLIP_OK;
    }

    char matched_term[128] = {0};
    ClipRuleCategory cat = security_rules_check(sa->rules, transcript, matched_term, sizeof(matched_term));
    if (cat == 0) {
        return CLIP_OK; /* No keyword matched */
    }

#ifdef _WIN32
    EnterCriticalSection(&sa->lock);
#endif

    /* Check deduplication: same session, node, matched term within DEDUP_WINDOW_MS */
    for (size_t i = 0; i < sa->dedup_count; i++) {
        const DedupEntry* d = &sa->dedup[i];
        if (memcmp(d->session_uuid, session_uuid, CLIP_UUID_BYTES) == 0 &&
            strcmp(d->node_uuid_str, node_uuid_str ? node_uuid_str : "") == 0 &&
            strcmp(d->matched_term, matched_term) == 0) {
            if (timestamp_ms >= d->timestamp_ms && (timestamp_ms - d->timestamp_ms) < DEDUP_WINDOW_MS) {
                /* Suppress duplicate event within deduplication window */
#ifdef _WIN32
                LeaveCriticalSection(&sa->lock);
#endif
                return CLIP_OK;
            }
        }
    }

    /* Record in circular dedup buffer */
    DedupEntry* slot = &sa->dedup[sa->dedup_head];
    memcpy(slot->session_uuid, session_uuid, CLIP_UUID_BYTES);
    strncpy(slot->node_uuid_str, node_uuid_str ? node_uuid_str : "", sizeof(slot->node_uuid_str) - 1);
    slot->node_uuid_str[sizeof(slot->node_uuid_str) - 1] = '\0';
    strncpy(slot->matched_term, matched_term, sizeof(slot->matched_term) - 1);
    slot->matched_term[sizeof(slot->matched_term) - 1] = '\0';
    slot->timestamp_ms = timestamp_ms;

    sa->dedup_head = (sa->dedup_head + 1) % DEDUP_HISTORY_CAPACITY;
    if (sa->dedup_count < DEDUP_HISTORY_CAPACITY) {
        sa->dedup_count++;
    }

#ifdef _WIN32
    LeaveCriticalSection(&sa->lock);
#endif

    /* Build ClipSecurityEvent */
    ClipSecurityEvent event;
    memset(&event, 0, sizeof(event));

    event.event_id = 0; /* Populated by server database on insertion */
    ClipUuid ev_uuid;
    clip_crypto_uuid_generate(&ev_uuid);
    memcpy(event.event_uuid, ev_uuid.bytes, CLIP_UUID_BYTES);
    clip_uuid_to_string(&ev_uuid, event.event_uuid_str, sizeof(event.event_uuid_str));

    if (node_uuid_str) {
        strncpy(event.node_uuid_str, node_uuid_str, sizeof(event.node_uuid_str) - 1);
    }
    if (channel_uuid_str) {
        strncpy(event.channel_uuid_str, channel_uuid_str, sizeof(event.channel_uuid_str) - 1);
    }
    if (session_uuid) {
        memcpy(event.session_uuid, session_uuid, CLIP_UUID_BYTES);
    }

    event.timestamp_ms = timestamp_ms;
    event.category = cat;

    if (cat == CLIP_RULE_CAT_THREAT) {
        event.severity = CLIP_SEVERITY_THREAT;
        strncpy(event.matched_rule, "THREAT", sizeof(event.matched_rule) - 1);
    } else if (cat == CLIP_RULE_CAT_SUSPICIOUS) {
        event.severity = CLIP_SEVERITY_SUSPICIOUS;
        strncpy(event.matched_rule, "SUSPICIOUS", sizeof(event.matched_rule) - 1);
    } else {
        event.severity = CLIP_SEVERITY_INFO;
        strncpy(event.matched_rule, "CUSTOM", sizeof(event.matched_rule) - 1);
    }

    strncpy(event.matched_term, matched_term, sizeof(event.matched_term) - 1);

    security_rules_extract_context(sa->rules, transcript, matched_term,
                                   event.context_text, sizeof(event.context_text));

    /* Strict invariant: every event starts as PENDING (Advisory — requires review) */
    event.status = CLIP_EVENT_STATUS_PENDING;

    CLIP_LOGW("SECURITY ADVISORY generated for node '%s': term='%s', category=%d, severity=%d",
              event.node_uuid_str, event.matched_term, (int)event.category, (int)event.severity);

    if (sa->event_cb) {
        sa->event_cb(&event, sa->user_data);
    }

    return CLIP_OK;
}

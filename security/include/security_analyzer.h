/*
 * security_analyzer.h — CLICOM Security Analyzer Interface
 *
 * Phase 0 : Interface declaration only.
 * Phase 15: Keyword matching and event generation.
 * Phase 16: Admin notification pipeline.
 *
 * ── Pipeline ─────────────────────────────────────────────────────────────
 *
 *   Audio → STT → Transcript → SecurityAnalyzer → ClipSecurityEvent
 *   → Storage → Admin Notification → Admin Review → Optional Admin Action
 *
 * ── Advisory-Only Policy ─────────────────────────────────────────────────
 *
 *   No automatic action is EVER taken based on analysis results alone.
 *   The system generates events; humans review them; admins act if needed.
 *   Admin actions are audit-logged with identity, action, and reason.
 */

#ifndef CLICOM_SECURITY_ANALYZER_H
#define CLICOM_SECURITY_ANALYZER_H

#include <stdint.h>
#include <stddef.h>
#include "clip_types.h"
#include "clip_errors.h"
#include "security_rules.h"

#ifndef CLIP_SEVERITY_DEFINED
#define CLIP_SEVERITY_DEFINED
typedef enum {
    CLIP_SEVERITY_NONE       = 0,
    CLIP_SEVERITY_INFO       = 1,
    CLIP_SEVERITY_SUSPICIOUS = 2,
    CLIP_SEVERITY_THREAT     = 3
} ClipSeverity;
#endif

#ifndef CLIP_EVENT_STATUS_DEFINED
#define CLIP_EVENT_STATUS_DEFINED
typedef enum {
    CLIP_EVENT_STATUS_PENDING   = 0,  /* awaiting admin review    */
    CLIP_EVENT_STATUS_REVIEWED  = 1,  /* admin took action        */
    CLIP_EVENT_STATUS_FALSE_POS = 2   /* admin dismissed          */
} ClipEventStatus;
#endif

typedef ClipRuleCategory ClipSecurityCategory;
typedef ClipSeverity     ClipSecuritySeverity;
typedef ClipEventStatus   ClipSecurityEventStatus;

typedef struct {
    uint32_t         event_id;
    uint8_t          event_uuid[CLIP_UUID_BYTES];
    char             event_uuid_str[CLIP_UUID_STR_SIZE];
    char             node_uuid_str[CLIP_UUID_STR_SIZE];
    char             channel_uuid_str[CLIP_UUID_STR_SIZE];
    uint8_t          session_uuid[CLIP_UUID_BYTES];
    uint64_t         timestamp_ms;
    ClipRuleCategory category;
    ClipSeverity     severity;
    char             matched_rule[128];
    char             matched_term[128];
    char             context_text[512];   /* surrounding words for human review */
    ClipEventStatus  status;
} ClipSecurityEvent;

typedef struct SecurityAnalyzer SecurityAnalyzer;

/* Callback: invoked when a security event is generated (advisory). */
typedef void (*SecurityEventCallback)(const ClipSecurityEvent* event,
                                      void*                     user_data);

SecurityAnalyzer* security_analyzer_create(const SecurityRuleSet* rules,
                                            SecurityEventCallback   event_cb,
                                            void*                  user_data);
void              security_analyzer_destroy(SecurityAnalyzer* sa);

/*
 * Analyze a transcript.
 * If a rule matches, generates a ClipSecurityEvent and fires event_cb.
 * NEVER performs automatic restriction or ban.
 */
ClipError security_analyzer_process(SecurityAnalyzer* sa,
                                    const char*        transcript,
                                    const char*        node_uuid_str,
                                    const char*        channel_uuid_str,
                                    const uint8_t      session_uuid[CLIP_UUID_BYTES],
                                    uint64_t           timestamp_ms);

#endif /* CLICOM_SECURITY_ANALYZER_H */

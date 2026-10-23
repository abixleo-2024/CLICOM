/*
 * security_rules.h — CLICOM Security Rules Interface
 *
 * Phase 0 : Interface declaration only.
 * Phase 15: Rule loading and keyword matching implementation.
 *
 * ── CRITICAL DESIGN RULE ─────────────────────────────────────────────────
 *
 *   Keyword matches are ADVISORY ONLY.
 *   A match generates a ClipSecurityEvent requiring admin review.
 *   The system NEVER automatically restricts, disconnects, or bans
 *   a node based solely on keyword detection.
 *   This rule cannot be changed without a full architectural review.
 *
 *   Context is always included:
 *     "The news reported a kidnapping yesterday."
 *   must be reviewed by a human before any conclusion is drawn.
 *
 * ── Rule Categories ──────────────────────────────────────────────────────
 *
 *   THREAT     : High-priority terms (e.g. "hijack", "bomb")
 *   SUSPICIOUS : Medium-priority terms (admin-defined)
 *   CUSTOM     : Organization-specific terms
 */

#ifndef CLICOM_SECURITY_RULES_H
#define CLICOM_SECURITY_RULES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "clip_errors.h"
#include "clip_types.h"

#define MAX_RULES 256
#define MAX_TERM_LEN 128
#define DEFAULT_CONTEXT_WINDOW_WORDS 10

#ifndef CLIP_RULE_CATEGORY_DEFINED
#define CLIP_RULE_CATEGORY_DEFINED
typedef enum {
    CLIP_RULE_CAT_THREAT     = 1,
    CLIP_RULE_CAT_SUSPICIOUS = 2,
    CLIP_RULE_CAT_CUSTOM     = 3
} ClipRuleCategory;
#endif

#ifndef CLIP_SEVERITY_DEFINED
#define CLIP_SEVERITY_DEFINED
typedef enum {
    CLIP_SEVERITY_NONE       = 0,
    CLIP_SEVERITY_INFO       = 1,
    CLIP_SEVERITY_SUSPICIOUS = 2,
    CLIP_SEVERITY_THREAT     = 3
} ClipSeverity;
#endif

#define CLIP_SECURITY_CAT_THREAT      CLIP_RULE_CAT_THREAT
#define CLIP_SECURITY_CAT_SUSPICIOUS  CLIP_RULE_CAT_SUSPICIOUS
#define CLIP_SECURITY_CAT_CUSTOM      CLIP_RULE_CAT_CUSTOM

#define CLIP_SECURITY_SEV_NONE        CLIP_SEVERITY_NONE
#define CLIP_SECURITY_SEV_INFO        CLIP_SEVERITY_INFO
#define CLIP_SECURITY_SEV_LOW         CLIP_SEVERITY_INFO
#define CLIP_SECURITY_SEV_MEDIUM      CLIP_SEVERITY_SUSPICIOUS
#define CLIP_SECURITY_SEV_SUSPICIOUS  CLIP_SEVERITY_SUSPICIOUS
#define CLIP_SECURITY_SEV_HIGH        CLIP_SEVERITY_THREAT
#define CLIP_SECURITY_SEV_THREAT      CLIP_SEVERITY_THREAT
#define CLIP_SECURITY_SEV_CRITICAL    CLIP_SEVERITY_THREAT

typedef struct {
    char             term[MAX_TERM_LEN];
    size_t           term_len;
    ClipRuleCategory category;
    ClipSeverity     severity;
} SecurityRule;

struct SecurityRuleSet {
    SecurityRule rules[MAX_RULES];
    size_t       count;
    int          context_window_words;
    ClipSeverity min_severity_for_alert;
    bool         is_disabled;
};

typedef struct SecurityRuleSet SecurityRuleSet;

/* Load rules from security_rules.conf. Returns NULL on failure. */
SecurityRuleSet* security_rules_load(const char* rules_file_path);
void             security_rules_free(SecurityRuleSet* rules);

/* Reload rules without restarting the server. */
ClipError security_rules_reload(SecurityRuleSet* rules,
                                 const char*      rules_file_path);

/* Return number of loaded active rules in the set */
size_t security_rules_count(const SecurityRuleSet* rules);

/*
 * Check a transcript against loaded rules.
 * Returns matched category (> 0) if a term is found, 0 if no match.
 * Fills out_matched_term (if non-NULL) with the matched word.
 */
ClipRuleCategory security_rules_check(const SecurityRuleSet* rules,
                                       const char*            transcript,
                                       char*                  out_matched_term,
                                       size_t                 out_term_max);

/*
 * Extract surrounding context words around the matched term.
 * out_context will contain up to context_window_words before and after the match.
 */
bool security_rules_extract_context(const SecurityRuleSet* rules,
                                    const char*            transcript,
                                    const char*            matched_term,
                                    char*                  out_context,
                                    size_t                 out_context_max);

#endif /* CLICOM_SECURITY_RULES_H */

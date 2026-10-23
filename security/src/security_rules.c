/*
 * security_rules.c — CLICOM Security Rules Loader & Matching Engine
 *
 * Implements:
 * - INI parser for security_rules.conf ([THREAT], [SUSPICIOUS], [CUSTOM], [SETTINGS])
 * - Safe failure: missing/malformed file safely disables security analysis (0 rules)
 * - Deterministic case-insensitive whole-word and phrase matching
 * - Punctuation-aware boundary detection (prevents substring false-positives)
 * - Surrounding contextual window extraction for human review
 */

#include "security_rules.h"
#include "security_analyzer.h"
#include "clip_log.h"
#include "clip_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

static void trim(char* s)
{
    if (!s) return;
    char* p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);

    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
}

static bool is_boundary_char(char c)
{
    if (c == '\0') return true;
    return !isalnum((unsigned char)c);
}

static int str_casecmp_n(const char* s1, const char* s2, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char c1 = (unsigned char)tolower((unsigned char)s1[i]);
        unsigned char c2 = (unsigned char)tolower((unsigned char)s2[i]);
        if (c1 != c2) return c1 - c2;
        if (c1 == '\0') break;
    }
    return 0;
}

SecurityRuleSet* security_rules_load(const char* rules_file_path)
{
    SecurityRuleSet* rs = (SecurityRuleSet*)calloc(1, sizeof(SecurityRuleSet));
    if (!rs) return NULL;

    rs->context_window_words = DEFAULT_CONTEXT_WINDOW_WORDS;
    rs->min_severity_for_alert = CLIP_SEVERITY_SUSPICIOUS;

    if (!rules_file_path || rules_file_path[0] == '\0') {
        rules_file_path = "config/security_rules.conf";
    }

    FILE* fp = fopen(rules_file_path, "r");
    if (!fp) {
        CLIP_LOGW("Security rules configuration unavailable or invalid ('%s') — security analysis DISABLED.",
                  rules_file_path);
        rs->is_disabled = true;
        rs->count = 0;
        return rs;
    }

    char line[512];
    ClipRuleCategory current_cat = (ClipRuleCategory)0;

    while (fgets(line, sizeof(line), fp)) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        if (line[0] == '[' && line[strlen(line) - 1] == ']') {
            if (strcmp(line, "[THREAT]") == 0) {
                current_cat = CLIP_RULE_CAT_THREAT;
            } else if (strcmp(line, "[SUSPICIOUS]") == 0) {
                current_cat = CLIP_RULE_CAT_SUSPICIOUS;
            } else if (strcmp(line, "[CUSTOM]") == 0) {
                current_cat = CLIP_RULE_CAT_CUSTOM;
            } else if (strcmp(line, "[SETTINGS]") == 0) {
                current_cat = (ClipRuleCategory)99; /* Settings section */
            } else {
                current_cat = (ClipRuleCategory)0;
            }
            continue;
        }

        if (current_cat == (ClipRuleCategory)99) {
            char* eq = strchr(line, '=');
            if (eq) {
                *eq = '\0';
                char* key = line;
                char* val = eq + 1;
                trim(key);
                trim(val);

                if (strcmp(key, "context_window_words") == 0) {
                    int w = atoi(val);
                    if (w >= 1 && w <= 25) {
                        rs->context_window_words = w;
                    }
                } else if (strcmp(key, "min_severity_for_alert") == 0) {
                    if (strcmp(val, "INFO") == 0) rs->min_severity_for_alert = CLIP_SEVERITY_INFO;
                    else if (strcmp(val, "SUSPICIOUS") == 0) rs->min_severity_for_alert = CLIP_SEVERITY_SUSPICIOUS;
                    else if (strcmp(val, "THREAT") == 0) rs->min_severity_for_alert = CLIP_SEVERITY_THREAT;
                } else if (strcmp(key, "auto_action") == 0) {
                    if (strcmp(val, "none") != 0) {
                        CLIP_LOGE("Invalid auto_action '%s' in security rules config — must be 'none'. Disabling rules.", val);
                        rs->is_disabled = true;
                        rs->count = 0;
                        fclose(fp);
                        return rs;
                    }
                }
            }
            continue;
        }

        if (current_cat >= CLIP_RULE_CAT_THREAT && current_cat <= CLIP_RULE_CAT_CUSTOM) {
            if (rs->count >= MAX_RULES) {
                CLIP_LOGW("Maximum security rules limit (%d) reached. Skipping remaining rules.", MAX_RULES);
                break;
            }

            SecurityRule* r = &rs->rules[rs->count];
            strncpy(r->term, line, sizeof(r->term) - 1);
            r->term[sizeof(r->term) - 1] = '\0';
            r->term_len = strlen(r->term);
            r->category = current_cat;

            if (current_cat == CLIP_RULE_CAT_THREAT) {
                r->severity = CLIP_SEVERITY_THREAT;
            } else if (current_cat == CLIP_RULE_CAT_SUSPICIOUS) {
                r->severity = CLIP_SEVERITY_SUSPICIOUS;
            } else {
                r->severity = CLIP_SEVERITY_INFO;
            }

            rs->count++;
        }
    }

    fclose(fp);
    if (rs->count == 0) {
        rs->is_disabled = true;
    }
    CLIP_LOGI("Loaded %zu security analysis rules from '%s'.", rs->count, rules_file_path);
    return rs;
}

void security_rules_free(SecurityRuleSet* rules)
{
    if (rules) {
        free(rules);
    }
}

ClipError security_rules_reload(SecurityRuleSet* rules, const char* rules_file_path)
{
    if (!rules) return CLIP_ERR_INVALID;
    SecurityRuleSet* fresh = security_rules_load(rules_file_path);
    if (!fresh) return CLIP_ERR_STORAGE;

    memcpy(rules, fresh, sizeof(SecurityRuleSet));
    free(fresh);
    return CLIP_OK;
}

size_t security_rules_count(const SecurityRuleSet* rules)
{
    if (!rules || rules->is_disabled) return 0;
    return rules->count;
}

ClipRuleCategory security_rules_check(const SecurityRuleSet* rules,
                                       const char*            transcript,
                                       char*                  out_matched_term,
                                       size_t                 out_term_max)
{
    if (out_matched_term && out_term_max > 0) {
        out_matched_term[0] = '\0';
    }

    if (!rules || rules->is_disabled || rules->count == 0 || !transcript || transcript[0] == '\0') {
        return (ClipRuleCategory)0;
    }

    size_t t_len = strlen(transcript);

    for (size_t r = 0; r < rules->count; r++) {
        const SecurityRule* rule = &rules->rules[r];
        if (rule->term_len == 0 || rule->term_len > t_len) continue;

        size_t r_len = rule->term_len;
        for (size_t i = 0; i + r_len <= t_len; i++) {
            /* Check boundary before */
            if (i > 0 && !is_boundary_char(transcript[i - 1])) {
                continue;
            }

            /* Check boundary after */
            if (i + r_len < t_len && !is_boundary_char(transcript[i + r_len])) {
                continue;
            }

            /* Check substring case-insensitively */
            if (str_casecmp_n(&transcript[i], rule->term, r_len) == 0) {
                if (out_matched_term && out_term_max > 0) {
                    strncpy(out_matched_term, rule->term, out_term_max - 1);
                    out_matched_term[out_term_max - 1] = '\0';
                }
                return rule->category;
            }
        }
    }

    return (ClipRuleCategory)0;
}

bool security_rules_extract_context(const SecurityRuleSet* rules,
                                    const char*            transcript,
                                    const char*            matched_term,
                                    char*                  out_context,
                                    size_t                 out_context_max)
{
    if (!out_context || out_context_max == 0) return false;
    out_context[0] = '\0';

    if (!transcript || !matched_term || matched_term[0] == '\0') return false;

    size_t t_len = strlen(transcript);
    size_t m_len = strlen(matched_term);

    /* Find match location */
    const char* match_ptr = NULL;
    for (size_t i = 0; i + m_len <= t_len; i++) {
        if ((i == 0 || is_boundary_char(transcript[i - 1])) &&
            (i + m_len >= t_len || is_boundary_char(transcript[i + m_len]))) {
            if (str_casecmp_n(&transcript[i], matched_term, m_len) == 0) {
                match_ptr = &transcript[i];
                break;
            }
        }
    }

    if (!match_ptr) {
        /* Fallback: copy bounded transcript */
        strncpy(out_context, transcript, out_context_max - 1);
        out_context[out_context_max - 1] = '\0';
        return true;
    }

    int window = (rules && rules->context_window_words > 0) ? rules->context_window_words : DEFAULT_CONTEXT_WINDOW_WORDS;

    /* Scan backwards for 'window' words */
    const char* start_ptr = match_ptr;
    int words_before = 0;
    while (start_ptr > transcript && words_before < window) {
        start_ptr--;
        if (isspace((unsigned char)*start_ptr) && start_ptr > transcript && !isspace((unsigned char)*(start_ptr - 1))) {
            words_before++;
        }
    }
    if (start_ptr > transcript && isspace((unsigned char)*start_ptr)) {
        start_ptr++;
    }

    /* Scan forwards for 'window' words */
    const char* end_ptr = match_ptr + m_len;
    int words_after = 0;
    while (*end_ptr != '\0' && words_after < window) {
        if (isspace((unsigned char)*end_ptr) && *(end_ptr + 1) != '\0' && !isspace((unsigned char)*(end_ptr + 1))) {
            words_after++;
        }
        end_ptr++;
    }

    size_t span = (size_t)(end_ptr - start_ptr);
    if (span >= out_context_max) {
        span = out_context_max - 1;
    }

    memcpy(out_context, start_ptr, span);
    out_context[span] = '\0';
    trim(out_context);

    return true;
}

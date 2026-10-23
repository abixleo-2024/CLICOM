/*
 * clip_telemetry.c — CLICOM Real Validated Telemetry Engine
 *
 * Implements truthful, operational network telemetry:
 * 1. Monotonic high-resolution timing (QueryPerformanceCounter / CLOCK_MONOTONIC).
 * 2. Uniquely matched ping/ack tracking with duplicate & late ACK safety.
 * 3. RFC 3550 exponential jitter filter.
 * 4. Rolling probe loss calculation.
 * 5. Composite connection quality evaluation.
 */

#include "clip_telemetry.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

static void update_loss_and_quality(ClipTelemetryTracker* tracker);

uint64_t clip_telemetry_now_us(const ClipTelemetryTracker* tracker)
{
    if (tracker && tracker->mock_now_us != 0) {
        return tracker->mock_now_us;
    }

#ifdef _WIN32
    static LARGE_INTEGER freq;
    static int freq_initialized = 0;
    if (!freq_initialized) {
        QueryPerformanceFrequency(&freq);
        freq_initialized = 1;
    }
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    if (freq.QuadPart == 0) return 0;
    return (uint64_t)((counter.QuadPart * 1000000ULL) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000);
#endif
}

void clip_telemetry_init(ClipTelemetryTracker* tracker)
{
    if (!tracker) return;
    memset(tracker, 0, sizeof(*tracker));
    tracker->last_rtt_ms = -1.0;
    tracker->min_rtt_ms = -1.0;
    tracker->max_rtt_ms = -1.0;
    tracker->jitter_ms = -1.0;
    tracker->loss_percent = -1.0;
    tracker->quality = CLIP_QUALITY_UNKNOWN;
}

void clip_telemetry_reset(ClipTelemetryTracker* tracker)
{
    if (!tracker) return;
    uint64_t mock_clock = tracker->mock_now_us;
    clip_telemetry_init(tracker);
    tracker->mock_now_us = mock_clock;
}

static void update_loss_and_quality(ClipTelemetryTracker* tracker)
{
    if (!tracker) return;

    size_t completed = 0;
    size_t lost = 0;

    for (size_t i = 0; i < CLIP_TELEMETRY_WINDOW_SIZE; i++) {
        if (tracker->probes[i].status == CLIP_PROBE_ACKED) {
            completed++;
        } else if (tracker->probes[i].status == CLIP_PROBE_TIMED_OUT) {
            completed++;
            lost++;
        }
    }

    tracker->window_completed_probes = completed;
    tracker->window_lost_probes = lost;

    if (completed < CLIP_TELEMETRY_MIN_LOSS_PROBES) {
        tracker->has_loss = false;
        tracker->loss_percent = 0.0;
    } else {
        tracker->has_loss = true;
        tracker->loss_percent = ((double)lost / (double)completed) * 100.0;
    }

    /* Connection Quality evaluation */
    if (!tracker->has_loss || !tracker->has_jitter || tracker->rtt_sample_count == 0) {
        tracker->quality = CLIP_QUALITY_UNKNOWN;
    } else {
        double rtt = tracker->last_rtt_ms;
        double jit = tracker->jitter_ms;
        double loss = tracker->loss_percent;

        if (rtt < 50.0 && jit < 15.0 && loss < 1.0) {
            tracker->quality = CLIP_QUALITY_EXCELLENT;
        } else if (rtt < 120.0 && jit < 35.0 && loss < 3.0) {
            tracker->quality = CLIP_QUALITY_GOOD;
        } else if (rtt < 250.0 && jit < 70.0 && loss < 8.0) {
            tracker->quality = CLIP_QUALITY_FAIR;
        } else {
            tracker->quality = CLIP_QUALITY_POOR;
        }
    }
}

void clip_telemetry_check_timeouts(ClipTelemetryTracker* tracker, uint64_t now_us)
{
    if (!tracker) return;
    if (now_us == 0) {
        now_us = clip_telemetry_now_us(tracker);
    }

    bool modified = false;
    for (size_t i = 0; i < CLIP_TELEMETRY_WINDOW_SIZE; i++) {
        if (tracker->probes[i].status == CLIP_PROBE_SENT) {
            if (now_us >= tracker->probes[i].sent_us + CLIP_TELEMETRY_TIMEOUT_US) {
                tracker->probes[i].status = CLIP_PROBE_TIMED_OUT;
                modified = true;
            }
        }
    }

    if (modified) {
        update_loss_and_quality(tracker);
    }
}

void clip_telemetry_on_probe_sent(ClipTelemetryTracker* tracker, uint64_t ping_seq, uint64_t now_us)
{
    if (!tracker) return;
    if (now_us == 0) {
        now_us = clip_telemetry_now_us(tracker);
    }

    /* Check timeouts of existing probes before recording new probe */
    clip_telemetry_check_timeouts(tracker, now_us);

    size_t idx = tracker->probe_head;
    tracker->probes[idx].ping_seq = ping_seq;
    tracker->probes[idx].expected_ack_seq = ping_seq + 1;
    tracker->probes[idx].sent_us = now_us;
    tracker->probes[idx].acked_us = 0;
    tracker->probes[idx].status = CLIP_PROBE_SENT;

    tracker->probe_head = (idx + 1) % CLIP_TELEMETRY_WINDOW_SIZE;
    tracker->total_probes_sent++;

    update_loss_and_quality(tracker);
}

bool clip_telemetry_on_probe_ack(ClipTelemetryTracker* tracker, uint64_t ack_seq, uint64_t now_us, double* out_rtt_ms)
{
    if (!tracker) return false;
    if (now_us == 0) {
        now_us = clip_telemetry_now_us(tracker);
    }

    /* First, service timeouts */
    clip_telemetry_check_timeouts(tracker, now_us);

    /* Search the rolling window for matching expected_ack_seq */
    ClipProbeRecord* matched = NULL;
    for (size_t i = 0; i < CLIP_TELEMETRY_WINDOW_SIZE; i++) {
        if (tracker->probes[i].status != CLIP_PROBE_FREE &&
            tracker->probes[i].expected_ack_seq == ack_seq) {
            matched = &tracker->probes[i];
            break;
        }
    }

    if (!matched) {
        /* Unrelated, duplicate, or stale response outside the window */
        return false;
    }

    if (matched->status == CLIP_PROBE_ACKED) {
        /* Duplicate response for an already-acknowledged probe */
        return false;
    }

    /*
     * Valid match!
     * If matched->status was CLIP_PROBE_TIMED_OUT, this is a late ACK.
     * By transitioning to CLIP_PROBE_ACKED, each probe is counted exactly once.
     */
    matched->status = CLIP_PROBE_ACKED;
    matched->acked_us = now_us;

    double rtt_ms = 0.0;
    if (now_us >= matched->sent_us) {
        rtt_ms = (double)(now_us - matched->sent_us) / 1000.0;
    }

    /* Update RTT statistics */
    tracker->last_rtt_ms = rtt_ms;
    tracker->sum_rtt_ms += rtt_ms;
    tracker->rtt_sample_count++;

    if (tracker->min_rtt_ms < 0.0 || rtt_ms < tracker->min_rtt_ms) {
        tracker->min_rtt_ms = rtt_ms;
    }
    if (tracker->max_rtt_ms < 0.0 || rtt_ms > tracker->max_rtt_ms) {
        tracker->max_rtt_ms = rtt_ms;
    }

    /* Update Jitter (RFC 3550 exponential filter) */
    if (tracker->rtt_sample_count == 1) {
        tracker->prev_rtt_ms = rtt_ms;
        tracker->has_jitter = false;
        tracker->jitter_ms = -1.0;
    } else if (tracker->rtt_sample_count == 2) {
        double delta = fabs(rtt_ms - tracker->prev_rtt_ms);
        tracker->jitter_ms = delta;
        tracker->prev_rtt_ms = rtt_ms;
        tracker->has_jitter = true;
    } else {
        double delta = fabs(rtt_ms - tracker->prev_rtt_ms);
        tracker->jitter_ms = tracker->jitter_ms + (delta - tracker->jitter_ms) / 16.0;
        tracker->prev_rtt_ms = rtt_ms;
        tracker->has_jitter = true;
    }

    update_loss_and_quality(tracker);

    if (out_rtt_ms) {
        *out_rtt_ms = rtt_ms;
    }

    return true;
}

const char* clip_telemetry_quality_name(ClipConnectionQuality quality)
{
    switch (quality) {
        case CLIP_QUALITY_EXCELLENT: return "EXCELLENT";
        case CLIP_QUALITY_GOOD:      return "GOOD";
        case CLIP_QUALITY_FAIR:      return "FAIR";
        case CLIP_QUALITY_POOR:      return "POOR";
        case CLIP_QUALITY_UNKNOWN:
        default:                     return "UNKNOWN";
    }
}

const char* clip_telemetry_quality_bars(ClipConnectionQuality quality)
{
    switch (quality) {
        case CLIP_QUALITY_EXCELLENT: return "[==========]";
        case CLIP_QUALITY_GOOD:      return "[========--]";
        case CLIP_QUALITY_FAIR:      return "[=====-----]";
        case CLIP_QUALITY_POOR:      return "[==--------]";
        case CLIP_QUALITY_UNKNOWN:
        default:                     return "[----------]";
    }
}

void clip_telemetry_format_compact(const ClipTelemetryTracker* tracker, char* out_buf, size_t buf_len)
{
    if (!out_buf || buf_len == 0) return;
    if (!tracker) {
        snprintf(out_buf, buf_len, "RTT: N/A | Jitter: N/A | Loss: N/A | Quality: UNKNOWN");
        return;
    }

    char rtt_str[32];
    if (tracker->rtt_sample_count > 0 && tracker->last_rtt_ms >= 0.0) {
        snprintf(rtt_str, sizeof(rtt_str), (tracker->last_rtt_ms < 1.0) ? "%.2f ms" : "%.1f ms", tracker->last_rtt_ms);
    } else {
        snprintf(rtt_str, sizeof(rtt_str), "N/A");
    }

    char jit_str[32];
    if (tracker->has_jitter && tracker->jitter_ms >= 0.0) {
        snprintf(jit_str, sizeof(jit_str), (tracker->jitter_ms < 1.0) ? "%.2f ms" : "%.1f ms", tracker->jitter_ms);
    } else {
        snprintf(jit_str, sizeof(jit_str), "N/A");
    }

    char loss_str[64];
    if (tracker->has_loss) {
        snprintf(loss_str, sizeof(loss_str), "%.1f%% (%zu/%zu)",
                 tracker->loss_percent,
                 tracker->window_lost_probes,
                 tracker->window_completed_probes);
    } else {
        snprintf(loss_str, sizeof(loss_str), "N/A (%zu/%d)",
                 tracker->window_completed_probes,
                 CLIP_TELEMETRY_MIN_LOSS_PROBES);
    }

    const char* q_name = clip_telemetry_quality_name(tracker->quality);
    const char* q_bars = clip_telemetry_quality_bars(tracker->quality);

    if (tracker->quality == CLIP_QUALITY_UNKNOWN) {
        snprintf(out_buf, buf_len, "RTT: %s | Jitter: %s | Loss: %s | Quality: %s %s (MEASURING...)",
                 rtt_str, jit_str, loss_str, q_bars, q_name);
    } else {
        snprintf(out_buf, buf_len, "RTT: %s | Jitter: %s | Loss: %s | Quality: %s %s",
                 rtt_str, jit_str, loss_str, q_bars, q_name);
    }
}

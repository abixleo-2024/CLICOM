/*
 * clip_telemetry.h — CLICOM Real Validated Telemetry Engine
 *
 * Implements truthful, operational network telemetry:
 * 1. RTT: Monotonic clock elapsed time for uniquely matched ping/ack probes.
 * 2. Jitter: RFC 3550 exponential interarrival/RTT variance filter.
 * 3. Rolling Loss: Accurate rolling probe window with late/duplicate ACK safety.
 * 4. Quality: Composite connection rating (EXCELLENT, GOOD, FAIR, POOR, UNKNOWN).
 *
 * Invariant: Never hardcode or default to EXCELLENT or 0.0.
 * Reports N/A and UNKNOWN when samples are insufficient.
 */

#ifndef CLICOM_CLIENT_TELEMETRY_H
#define CLICOM_CLIENT_TELEMETRY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CLIP_TELEMETRY_WINDOW_SIZE        20
#define CLIP_TELEMETRY_TIMEOUT_US         (5000ULL * 1000ULL) /* 5000 ms */
#define CLIP_TELEMETRY_MIN_LOSS_PROBES    5
#define CLIP_TELEMETRY_MIN_JITTER_SAMPLES 2

typedef enum {
    CLIP_PROBE_FREE = 0,
    CLIP_PROBE_SENT,
    CLIP_PROBE_ACKED,
    CLIP_PROBE_TIMED_OUT
} ClipProbeStatus;

typedef struct {
    uint64_t        ping_seq;         /* Sequence number in outgoing HEARTBEAT */
    uint64_t        expected_ack_seq; /* Expected sequence number in HEARTBEAT_ACK */
    uint64_t        sent_us;          /* Dispatch timestamp in microseconds */
    uint64_t        acked_us;         /* Acknowledgment timestamp in microseconds */
    ClipProbeStatus status;
} ClipProbeRecord;

typedef enum {
    CLIP_QUALITY_UNKNOWN = 0,
    CLIP_QUALITY_EXCELLENT,
    CLIP_QUALITY_GOOD,
    CLIP_QUALITY_FAIR,
    CLIP_QUALITY_POOR
} ClipConnectionQuality;

typedef struct {
    /* Rolling probe window */
    ClipProbeRecord       probes[CLIP_TELEMETRY_WINDOW_SIZE];
    size_t                probe_head;
    size_t                total_probes_sent;

    /* RTT tracking */
    double                last_rtt_ms;
    double                min_rtt_ms;
    double                max_rtt_ms;
    double                sum_rtt_ms;
    size_t                rtt_sample_count;

    /* Jitter tracking (RFC 3550) */
    double                jitter_ms;
    double                prev_rtt_ms;
    bool                  has_jitter;

    /* Rolling probe loss */
    double                loss_percent;
    bool                  has_loss;
    size_t                window_completed_probes;
    size_t                window_lost_probes;

    /* Derived connection quality */
    ClipConnectionQuality quality;

    /* Mock monotonic clock for deterministic unit testing (0 = use hardware clock) */
    uint64_t              mock_now_us;
} ClipTelemetryTracker;

/* Initialize or reset telemetry tracker */
void clip_telemetry_init(ClipTelemetryTracker* tracker);

/* Clear call/session statistics while retaining tracker configuration */
void clip_telemetry_reset(ClipTelemetryTracker* tracker);

/* Return monotonic time in microseconds (respects mock_now_us if set) */
uint64_t clip_telemetry_now_us(const ClipTelemetryTracker* tracker);

/* Record outgoing heartbeat probe */
void clip_telemetry_on_probe_sent(ClipTelemetryTracker* tracker, uint64_t ping_seq, uint64_t now_us);

/*
 * Record incoming heartbeat acknowledgment.
 * Returns true if ack matched an active/timed-out probe in the window.
 * Returns false if unmatched, duplicate, or stale.
 */
bool clip_telemetry_on_probe_ack(ClipTelemetryTracker* tracker, uint64_t ack_seq, uint64_t now_us, double* out_rtt_ms);

/* Scan in-flight probes and transition unacknowledged probes (> 5000ms) to TIMED_OUT */
void clip_telemetry_check_timeouts(ClipTelemetryTracker* tracker, uint64_t now_us);

/* String formatters */
const char* clip_telemetry_quality_name(ClipConnectionQuality quality);
const char* clip_telemetry_quality_bars(ClipConnectionQuality quality);

/* Format compact single-line telemetry status for CLI/TUI */
void clip_telemetry_format_compact(const ClipTelemetryTracker* tracker, char* out_buf, size_t buf_len);

#endif /* CLICOM_CLIENT_TELEMETRY_H */

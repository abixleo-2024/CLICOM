/*
 * test_telemetry.c — Unit tests for CLICOM Truthful Real Telemetry Engine
 *
 * Verifies:
 * 1. Cold start N/A values (no fabricated 0.0 or premature EXCELLENT).
 * 2. Monotonic RTT measurement and unique probe sequence matching.
 * 3. Rejection of unmatched and duplicate ACKs.
 * 4. RFC 3550 exponential jitter calculation (requires >= 2 samples).
 * 5. Rolling window probe loss (requires >= 5 completed probes).
 * 6. Timeout transitions after 5000ms.
 * 7. Late ACK handling (counted exactly once in loss calculation).
 * 8. Window rollover (bounded to 20 probes).
 * 9. Quality state transitions (EXCELLENT, GOOD, FAIR, POOR, UNKNOWN).
 */

#include "clip_telemetry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "ASSERTION FAILED: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))
#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
#define ASSERT_NEAR(a, b, eps) ASSERT_TRUE(fabs((a) - (b)) <= (eps))

static void test_cold_start(void)
{
    printf("[1] Testing cold start and insufficient samples...\n");
    ClipTelemetryTracker tracker;
    clip_telemetry_init(&tracker);

    ASSERT_EQ(tracker.rtt_sample_count, (size_t)0);
    ASSERT_TRUE(tracker.last_rtt_ms < 0.0);
    ASSERT_FALSE(tracker.has_jitter);
    ASSERT_FALSE(tracker.has_loss);
    ASSERT_EQ(tracker.quality, CLIP_QUALITY_UNKNOWN);

    char buf[256];
    clip_telemetry_format_compact(&tracker, buf, sizeof(buf));

    /* Must contain N/A and UNKNOWN/MEASURING, never EXCELLENT */
    ASSERT_TRUE(strstr(buf, "RTT: N/A") != NULL);
    ASSERT_TRUE(strstr(buf, "Jitter: N/A") != NULL);
    ASSERT_TRUE(strstr(buf, "Loss: N/A") != NULL);
    ASSERT_TRUE(strstr(buf, "UNKNOWN (MEASURING...)") != NULL);
    ASSERT_TRUE(strstr(buf, "EXCELLENT") == NULL);
    printf("    Passed cold start test.\n");
}

static void test_probe_matching_and_rtt(void)
{
    printf("[2] Testing probe matching and RTT calculation...\n");
    ClipTelemetryTracker tracker;
    clip_telemetry_init(&tracker);

    uint64_t t0 = 1000000000ULL; /* 1000 seconds in us */
    tracker.mock_now_us = t0;

    /* Send Probe 1 with sequence number 100 (expected ACK is 101) */
    clip_telemetry_on_probe_sent(&tracker, 100, t0);
    ASSERT_EQ(tracker.total_probes_sent, (size_t)1);
    ASSERT_EQ(tracker.rtt_sample_count, (size_t)0);

    /* Unrelated ACK arrives (seq 999) -> must be rejected */
    double rtt = 0.0;
    bool matched = clip_telemetry_on_probe_ack(&tracker, 999, t0 + 20000ULL, &rtt);
    ASSERT_FALSE(matched);
    ASSERT_EQ(tracker.rtt_sample_count, (size_t)0);

    /* Matching ACK arrives 45.5 ms later (45500 us) */
    uint64_t t1 = t0 + 45500ULL;
    tracker.mock_now_us = t1;
    matched = clip_telemetry_on_probe_ack(&tracker, 101, t1, &rtt);
    ASSERT_TRUE(matched);
    ASSERT_NEAR(rtt, 45.5, 0.001);
    ASSERT_NEAR(tracker.last_rtt_ms, 45.5, 0.001);
    ASSERT_EQ(tracker.rtt_sample_count, (size_t)1);

    /* Jitter and Loss must still be N/A due to insufficient samples */
    ASSERT_FALSE(tracker.has_jitter);
    ASSERT_FALSE(tracker.has_loss);
    ASSERT_EQ(tracker.quality, CLIP_QUALITY_UNKNOWN);

    char buf[256];
    clip_telemetry_format_compact(&tracker, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "RTT: 45.5 ms") != NULL);
    ASSERT_TRUE(strstr(buf, "Jitter: N/A") != NULL);
    ASSERT_TRUE(strstr(buf, "Loss: N/A (1/5") != NULL);

    /* Sub-millisecond probe test (e.g. loopback 420 us = 0.42 ms) */
    clip_telemetry_on_probe_sent(&tracker, 102, t1);
    matched = clip_telemetry_on_probe_ack(&tracker, 103, t1 + 420ULL, &rtt);
    ASSERT_TRUE(matched);
    ASSERT_NEAR(rtt, 0.42, 0.001);
    clip_telemetry_format_compact(&tracker, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "RTT: 0.42 ms") != NULL);

    printf("    Passed probe matching and RTT test.\n");
}

static void test_duplicate_ack_rejection(void)
{
    printf("[3] Testing rejection of duplicate ACKs...\n");
    ClipTelemetryTracker tracker;
    clip_telemetry_init(&tracker);

    uint64_t t0 = 1000000000ULL;
    clip_telemetry_on_probe_sent(&tracker, 200, t0);

    /* First ACK: accepted */
    double rtt = 0.0;
    bool matched = clip_telemetry_on_probe_ack(&tracker, 201, t0 + 30000ULL, &rtt);
    ASSERT_TRUE(matched);
    ASSERT_EQ(tracker.rtt_sample_count, (size_t)1);
    ASSERT_NEAR(tracker.last_rtt_ms, 30.0, 0.001);

    /* Duplicate ACK arrives 10ms later: must be rejected */
    matched = clip_telemetry_on_probe_ack(&tracker, 201, t0 + 40000ULL, &rtt);
    ASSERT_FALSE(matched);
    ASSERT_EQ(tracker.rtt_sample_count, (size_t)1);
    ASSERT_NEAR(tracker.last_rtt_ms, 30.0, 0.001);
    printf("    Passed duplicate ACK rejection test.\n");
}

static void test_rfc3550_jitter_filter(void)
{
    printf("[4] Testing RFC 3550 jitter calculation...\n");
    ClipTelemetryTracker tracker;
    clip_telemetry_init(&tracker);

    uint64_t t = 1000000000ULL;

    /* Probe 1: RTT = 40.0 ms */
    clip_telemetry_on_probe_sent(&tracker, 301, t);
    clip_telemetry_on_probe_ack(&tracker, 302, t + 40000ULL, NULL);
    ASSERT_FALSE(tracker.has_jitter);

    /* Probe 2: RTT = 48.0 ms. Delta = |48 - 40| = 8.0 ms. Jitter initialized to 8.0 ms */
    t += 1000000ULL;
    clip_telemetry_on_probe_sent(&tracker, 303, t);
    clip_telemetry_on_probe_ack(&tracker, 304, t + 48000ULL, NULL);
    ASSERT_TRUE(tracker.has_jitter);
    ASSERT_NEAR(tracker.jitter_ms, 8.0, 0.001);

    /* Probe 3: RTT = 32.0 ms. Delta = |32 - 48| = 16.0 ms.
     * Jitter = 8.0 + (16.0 - 8.0) / 16.0 = 8.0 + 0.5 = 8.5 ms */
    t += 1000000ULL;
    clip_telemetry_on_probe_sent(&tracker, 305, t);
    clip_telemetry_on_probe_ack(&tracker, 306, t + 32000ULL, NULL);
    ASSERT_TRUE(tracker.has_jitter);
    ASSERT_NEAR(tracker.jitter_ms, 8.5, 0.001);
    printf("    Passed RFC 3550 jitter filter test.\n");
}

static void test_timeouts_and_rolling_loss(void)
{
    printf("[5] Testing probe timeouts and rolling loss calculation...\n");
    ClipTelemetryTracker tracker;
    clip_telemetry_init(&tracker);

    uint64_t t = 1000000000ULL;

    /* Send 3 probes that succeed (RTT 20ms) */
    for (uint64_t seq = 1; seq <= 3; seq++) {
        clip_telemetry_on_probe_sent(&tracker, seq * 2, t);
        clip_telemetry_on_probe_ack(&tracker, seq * 2 + 1, t + 20000ULL, NULL);
        t += 1000000ULL;
    }

    /* Send 2 probes that time out (> 5000ms elapsed) */
    clip_telemetry_on_probe_sent(&tracker, 10, t);
    t += 1000000ULL;
    clip_telemetry_on_probe_sent(&tracker, 20, t);

    /* Advance time by 6000ms past probe 20 */
    t += 6000000ULL;
    tracker.mock_now_us = t;
    clip_telemetry_check_timeouts(&tracker, t);

    /* Now we have 5 completed probes: 3 acked, 2 timed out.
     * Completed = 5 >= 5 -> has_loss = true.
     * Loss = 2 / 5 = 40.0% */
    ASSERT_TRUE(tracker.has_loss);
    ASSERT_EQ(tracker.window_completed_probes, (size_t)5);
    ASSERT_EQ(tracker.window_lost_probes, (size_t)2);
    ASSERT_NEAR(tracker.loss_percent, 40.0, 0.001);

    /* Since loss is 40.0% (>= 8.0%), quality must be POOR */
    ASSERT_EQ(tracker.quality, CLIP_QUALITY_POOR);
    printf("    Passed probe timeouts and rolling loss test.\n");
}

static void test_late_ack_handling(void)
{
    printf("[6] Testing late ACK handling (single count guarantee)...\n");
    ClipTelemetryTracker tracker;
    clip_telemetry_init(&tracker);

    uint64_t t = 1000000000ULL;

    /* Send 5 probes: first 4 succeed */
    for (uint64_t seq = 1; seq <= 4; seq++) {
        clip_telemetry_on_probe_sent(&tracker, seq * 10, t);
        clip_telemetry_on_probe_ack(&tracker, seq * 10 + 1, t + 25000ULL, NULL);
        t += 1000000ULL;
    }

    /* Probe 5 sent at t */
    clip_telemetry_on_probe_sent(&tracker, 50, t);

    /* Advance time 5200ms -> probe 5 times out */
    uint64_t t_timeout = t + 5200000ULL;
    tracker.mock_now_us = t_timeout;
    clip_telemetry_check_timeouts(&tracker, t_timeout);

    ASSERT_EQ(tracker.window_completed_probes, (size_t)5);
    ASSERT_EQ(tracker.window_lost_probes, (size_t)1);
    ASSERT_NEAR(tracker.loss_percent, 20.0, 0.001);

    /* Now late ACK for probe 5 arrives at t + 5300ms */
    uint64_t t_late = t + 5300000ULL;
    tracker.mock_now_us = t_late;
    double late_rtt = 0.0;
    bool matched = clip_telemetry_on_probe_ack(&tracker, 51, t_late, &late_rtt);

    ASSERT_TRUE(matched);
    ASSERT_NEAR(late_rtt, 5300.0, 0.1);

    /* Probe 5 transitioned from TIMED_OUT to ACKED:
     * Window completed is still 5, lost probes becomes 0!
     * Each probe counted exactly once! */
    ASSERT_EQ(tracker.window_completed_probes, (size_t)5);
    ASSERT_EQ(tracker.window_lost_probes, (size_t)0);
    ASSERT_NEAR(tracker.loss_percent, 0.0, 0.001);
    printf("    Passed late ACK handling test.\n");
}

static void test_window_rollover(void)
{
    printf("[7] Testing rolling window rollover (20-probe capacity)...\n");
    ClipTelemetryTracker tracker;
    clip_telemetry_init(&tracker);

    uint64_t t = 1000000000ULL;

    /* Send 30 consecutive probes (more than 20 window size) */
    for (uint64_t seq = 1; seq <= 30; seq++) {
        clip_telemetry_on_probe_sent(&tracker, seq, t);
        /* Alternate: every 5th probe times out */
        if (seq % 5 != 0) {
            clip_telemetry_on_probe_ack(&tracker, seq + 1, t + 20000ULL, NULL);
        }
        t += 1000000ULL;
    }

    /* Advance clock to time out any pending probes */
    t += 10000000ULL;
    clip_telemetry_check_timeouts(&tracker, t);

    /* Window capacity is 20: completed probes must be exactly 20 */
    ASSERT_EQ(tracker.window_completed_probes, (size_t)CLIP_TELEMETRY_WINDOW_SIZE);

    /* In the last 20 probes (probes 11 to 30), probes 15, 20, 25, 30 timed out (4 probes) */
    ASSERT_EQ(tracker.window_lost_probes, (size_t)4);
    ASSERT_NEAR(tracker.loss_percent, (4.0 / 20.0) * 100.0, 0.001); /* 20.0% */
    printf("    Passed rolling window rollover test.\n");
}

static void test_quality_state_transitions(void)
{
    printf("[8] Testing quality rating state transitions...\n");
    ClipTelemetryTracker tracker;

    /* Helper lambda/closure simulation: configure tracker directly */
    clip_telemetry_init(&tracker);
    uint64_t t = 1000000000ULL;

    /* Case A: EXCELLENT (RTT=30ms, Jitter=5ms, Loss=0%) */
    for (uint64_t i = 1; i <= 6; i++) {
        clip_telemetry_on_probe_sent(&tracker, i, t);
        clip_telemetry_on_probe_ack(&tracker, i + 1, t + 30000ULL, NULL);
        t += 1000000ULL;
    }
    ASSERT_EQ(tracker.quality, CLIP_QUALITY_EXCELLENT);
    ASSERT_EQ(strcmp(clip_telemetry_quality_name(tracker.quality), "EXCELLENT"), 0);

    /* Case B: GOOD (RTT=80ms, Jitter=25ms, Loss=0%) */
    clip_telemetry_init(&tracker);
    t = 1000000000ULL;
    for (uint64_t i = 1; i <= 6; i++) {
        clip_telemetry_on_probe_sent(&tracker, i, t);
        /* Alternate RTT: 70ms then 90ms -> Jitter around 20ms, RTT around 80ms */
        uint64_t delay = (i % 2 == 0) ? 90000ULL : 70000ULL;
        clip_telemetry_on_probe_ack(&tracker, i + 1, t + delay, NULL);
        t += 1000000ULL;
    }
    ASSERT_EQ(tracker.quality, CLIP_QUALITY_GOOD);
    ASSERT_EQ(strcmp(clip_telemetry_quality_name(tracker.quality), "GOOD"), 0);

    /* Case C: FAIR (RTT=180ms, Jitter=40ms, Loss=0%) */
    clip_telemetry_init(&tracker);
    t = 1000000000ULL;
    for (uint64_t i = 1; i <= 6; i++) {
        clip_telemetry_on_probe_sent(&tracker, i, t);
        uint64_t delay = (i % 2 == 0) ? 200000ULL : 160000ULL;
        clip_telemetry_on_probe_ack(&tracker, i + 1, t + delay, NULL);
        t += 1000000ULL;
    }
    ASSERT_EQ(tracker.quality, CLIP_QUALITY_FAIR);
    ASSERT_EQ(strcmp(clip_telemetry_quality_name(tracker.quality), "FAIR"), 0);

    /* Case D: POOR due to High RTT (350ms) */
    clip_telemetry_init(&tracker);
    t = 1000000000ULL;
    for (uint64_t i = 1; i <= 6; i++) {
        clip_telemetry_on_probe_sent(&tracker, i, t);
        clip_telemetry_on_probe_ack(&tracker, i + 1, t + 350000ULL, NULL);
        t += 1000000ULL;
    }
    ASSERT_EQ(tracker.quality, CLIP_QUALITY_POOR);
    ASSERT_EQ(strcmp(clip_telemetry_quality_name(tracker.quality), "POOR"), 0);
    printf("    Passed quality state transitions test.\n");
}

int main(void)
{
    printf("=== CLICOM Telemetry Engine Unit Tests ===\n");
    test_cold_start();
    test_probe_matching_and_rtt();
    test_duplicate_ack_rejection();
    test_rfc3550_jitter_filter();
    test_timeouts_and_rolling_loss();
    test_late_ack_handling();
    test_window_rollover();
    test_quality_state_transitions();
    printf("All telemetry unit tests passed successfully!\n");
    return 0;
}

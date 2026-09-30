/*
 * detect_timing.c — Timing side-channel analysis
 *
 * Measures the latency of reading /proc/self/maps through both
 * libc and direct syscall paths.  If a filtering/interception layer
 * is present, the libc path should show measurably higher latency.
 */
#include "detect_timing.h"
#include "detect_syscall.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>

#define ITERATIONS   100
#define BUF_SIZE     (256 * 1024)  /* 256 KB buffer for maps */

static double get_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* Measure time to open + read + close /proc/self/maps via libc */
static double measure_libc_maps(char *buf)
{
    double start = get_ns();

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return -1.0;

    ssize_t total = 0;
    ssize_t n;
    while ((n = read(fd, buf + total, BUF_SIZE - (size_t)total)) > 0)
        total += n;

    close(fd);
    return get_ns() - start;
}

/* Measure time via direct syscall — bypasses any libc hooks */
static double measure_direct_maps(char *buf)
{
    double start = get_ns();

    long fd = direct_openat(-100, "/proc/self/maps", 0, 0);
    if (fd < 0) return -1.0;

    long total = 0;
    long n;
    while ((n = direct_read((int)fd, buf + total,
                            BUF_SIZE - (size_t)total)) > 0)
        total += n;

    direct_close((int)fd);
    return get_ns() - start;
}

void detect_timing_run(detect_score_t *score, int verbose)
{
    LOG_HEADER("TIMING SIDE-CHANNEL ANALYSIS");

    char *buf = malloc(BUF_SIZE);
    if (!buf) {
        LOG_FAIL("Cannot allocate buffer");
        score_fail(score);
        return;
    }

    double libc_times[ITERATIONS];
    double direct_times[ITERATIONS];
    int libc_ok = 0, direct_ok = 0;

    /* Warmup (5 iterations, discarded) */
    for (int i = 0; i < 5; i++) {
        measure_libc_maps(buf);
        measure_direct_maps(buf);
    }

    /* Measure libc path */
    for (int i = 0; i < ITERATIONS; i++) {
        double t = measure_libc_maps(buf);
        if (t > 0) {
            libc_times[libc_ok++] = t;
        }
    }

    /* Measure direct syscall path */
    for (int i = 0; i < ITERATIONS; i++) {
        double t = measure_direct_maps(buf);
        if (t > 0) {
            direct_times[direct_ok++] = t;
        }
    }

    free(buf);

    if (libc_ok < 10 || direct_ok < 10) {
        LOG_WARN("Insufficient timing samples (libc=%d, direct=%d)", libc_ok, direct_ok);
        score_warn(score);
        return;
    }

    /* Calculate statistics */
    double libc_sum = 0, direct_sum = 0;
    for (int i = 0; i < libc_ok; i++)   libc_sum   += libc_times[i];
    for (int i = 0; i < direct_ok; i++) direct_sum += direct_times[i];

    double libc_mean   = libc_sum / libc_ok;
    double direct_mean = direct_sum / direct_ok;

    double libc_var = 0, direct_var = 0;
    for (int i = 0; i < libc_ok; i++) {
        double d = libc_times[i] - libc_mean;
        libc_var += d * d;
    }
    for (int i = 0; i < direct_ok; i++) {
        double d = direct_times[i] - direct_mean;
        direct_var += d * d;
    }
    libc_var   /= libc_ok;
    direct_var /= direct_ok;

    double libc_stddev   = sqrt(libc_var);
    double direct_stddev = sqrt(direct_var);

    LOG_INFO("libc   path: mean=%.1f µs, stddev=%.1f µs (%d samples)",
             libc_mean / 1000.0, libc_stddev / 1000.0, libc_ok);
    LOG_INFO("direct path: mean=%.1f µs, stddev=%.1f µs (%d samples)",
             direct_mean / 1000.0, direct_stddev / 1000.0, direct_ok);

    double ratio = libc_mean / direct_mean;
    double diff_us = (libc_mean - direct_mean) / 1000.0;

    LOG_INFO("Ratio: libc/direct = %.2fx (diff = %.1f µs)", ratio, diff_us);

    /*
     * Threshold: if libc path is >3x slower or >100µs more than direct,
     * there's likely an interception layer (seccomp supervisor, maps filter).
     * Normal variance on SM8550 is ~1.0-1.3x.
     */
    if (ratio > 3.0 || diff_us > 100.0) {
        LOG_FAIL("Significant timing discrepancy detected (ratio=%.2fx) — "
                 "interception likely", ratio);
        score_fail(score);
    } else if (ratio > 1.5 || diff_us > 50.0) {
        LOG_WARN("Moderate timing difference (ratio=%.2fx) — possible interception",
                 ratio);
        score_warn(score);
    } else {
        LOG_PASS("Timing consistent between libc and direct syscall (ratio=%.2fx)",
                 ratio);
        score_pass(score);
    }
}

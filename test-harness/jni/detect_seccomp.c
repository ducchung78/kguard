/*
 * detect_seccomp.c — Detect active seccomp-bpf filters
 *
 * Uses both libc prctl() and direct syscall to detect filters.
 * If libc returns 0 but direct returns 2, the filter is hiding itself.
 */
#include "detect_seccomp.h"
#include "detect_syscall.h"

#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <errno.h>

void detect_seccomp_run(detect_score_t *score, int verbose)
{
    LOG_HEADER("SECCOMP FILTER DETECTION");

    /* Method 1: prctl via libc */
    int libc_seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    int libc_nnp     = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);

    /* Method 2: prctl via direct syscall */
    long direct_seccomp = direct_prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    long direct_nnp     = direct_prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);

    if (verbose) {
        LOG_INFO("libc   prctl(PR_GET_SECCOMP)      = %d", libc_seccomp);
        LOG_INFO("direct prctl(PR_GET_SECCOMP)       = %ld", direct_seccomp);
        LOG_INFO("libc   prctl(PR_GET_NO_NEW_PRIVS)  = %d", libc_nnp);
        LOG_INFO("direct prctl(PR_GET_NO_NEW_PRIVS)   = %ld", direct_nnp);
    }

    /* Check for discrepancy: filter hiding itself */
    if (libc_seccomp != (int)direct_seccomp) {
        LOG_FAIL("Seccomp status mismatch: libc=%d, direct=%ld (filter hiding!)",
                 libc_seccomp, direct_seccomp);
        score_fail(score);
    } else if (direct_seccomp == 2) {
        /* Filter mode active and NOT hiding */
        LOG_WARN("Seccomp filter active (mode=2), not hiding but present");
        score_warn(score);
    } else if (direct_seccomp == 0) {
        LOG_PASS("No seccomp filter active");
        score_pass(score);
    } else {
        LOG_INFO("Seccomp mode: %ld", direct_seccomp);
        score_pass(score);
    }

    /* Method 3: Read /proc/self/status for Seccomp field */
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp) {
        char line[256];
        int proc_seccomp = -1;

        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Seccomp:", 8) == 0) {
                sscanf(line + 8, "%d", &proc_seccomp);
                break;
            }
        }
        fclose(fp);

        if (proc_seccomp >= 0) {
            if (verbose)
                LOG_INFO("/proc/self/status Seccomp: %d", proc_seccomp);

            if (proc_seccomp != (int)direct_seccomp) {
                LOG_FAIL("Seccomp in /proc/self/status (%d) != direct prctl (%ld)",
                         proc_seccomp, direct_seccomp);
                score_fail(score);
            } else {
                LOG_PASS("/proc/self/status consistent with prctl");
                score_pass(score);
            }
        }
    }

    /* NNP check */
    if (libc_nnp != (int)direct_nnp) {
        LOG_FAIL("NO_NEW_PRIVS mismatch: libc=%d, direct=%ld",
                 libc_nnp, direct_nnp);
        score_fail(score);
    } else {
        LOG_PASS("NO_NEW_PRIVS consistent (value=%d)", libc_nnp);
        score_pass(score);
    }
}

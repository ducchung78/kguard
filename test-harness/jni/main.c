/*
 * main.c — KGuard Detection Test Harness
 *
 * Entry point that runs all detection modules and produces a
 * consolidated report with PASS/FAIL scores.
 *
 * Usage: kguard-detect [--verbose] [--json]
 */
#include "log.h"
#include "detect_maps.h"
#include "detect_integrity.h"
#include "detect_got.h"
#include "detect_syscall.h"
#include "detect_linker.h"
#include "detect_seccomp.h"
#include "detect_namespace.h"
#include "detect_tee.h"
#include "detect_props.h"
#include "detect_timing.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

static void print_banner(void)
{
    printf(CLR_BOLD
           "\n"
           "╔═══════════════════════════════════════════╗\n"
           "║   KGuard Detection Test Harness v1.0      ║\n"
           "║   Target: RedMagic 8 Pro (SM8550)         ║\n"
           "║   Kernel: 5.15.167 (ARM64)                ║\n"
           "╚═══════════════════════════════════════════╝\n"
           CLR_RESET "\n");
}

static void print_device_info(void)
{
    struct utsname u;
    if (uname(&u) == 0) {
        printf(CLR_CYAN " System:  " CLR_RESET "%s %s\n", u.sysname, u.release);
        printf(CLR_CYAN " Machine: " CLR_RESET "%s\n", u.machine);
        printf(CLR_CYAN " Node:    " CLR_RESET "%s\n", u.nodename);
    }
    printf(CLR_CYAN " PID:     " CLR_RESET "%d\n", getpid());
    printf(CLR_CYAN " UID:     " CLR_RESET "%d\n", getuid());
}

int main(int argc, char *argv[])
{
    int verbose = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [--verbose|-v]\n", argv[0]);
            printf("  --verbose  Show detailed output for each check\n");
            return 0;
        }
    }

    print_banner();
    print_device_info();

    detect_score_t score;
    score_init(&score);

    /* Run all detection modules */
    detect_maps_run(&score, verbose);
    detect_integrity_run(&score, verbose);
    detect_got_run(&score, verbose);
    detect_linker_run(&score, verbose);
    detect_seccomp_run(&score, verbose);
    detect_namespace_run(&score, verbose);
    detect_tee_run(&score, verbose);
    detect_props_run(&score, verbose);
    detect_timing_run(&score, verbose);

    /* Final summary */
    score_print(&score);

    return (score.failed > 0) ? 1 : 0;
}

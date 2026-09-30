/*
 * detect_tee.c — Detect TEE Simulator and Keybox module artifacts
 *
 * Checks for module files using both libc and direct syscall.
 * A discrepancy (libc=ENOENT but direct=found) reveals file hiding.
 */
#include "detect_tee.h"
#include "detect_syscall.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* Paths to probe for TEE Simulator / Keybox / root framework modules */
static const char *PROBE_PATHS[] = {
    /* TEE Simulator module */
    "/data/adb/modules/triquestokeymint",
    "/data/adb/modules/triquestokeymint/module.prop",
    /* PlayIntegrityFix */
    "/data/adb/modules/playintegrityfix",
    "/data/adb/modules/playintegrityfix/module.prop",
    "/data/adb/modules/playcurl",
    /* Shamiko */
    "/data/adb/modules/shamiko",
    "/data/adb/modules/zygisksu",
    /* Generic root indicators */
    "/data/adb/modules",
    "/data/adb/magisk",
    "/data/adb/ksu",
    "/data/adb/ap",
    /* Keybox locations */
    "/data/adb/keybox.xml",
    "/data/local/tmp/keybox.xml",
    "/sdcard/keybox.xml",
    "/data/adb/triquestokeymint/keybox.xml",
    /* HAL override indicators */
    "/system/etc/init/android.hardware.security.keymint.rc",
    /* su binaries */
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/data/adb/magisk/busybox",
    NULL
};

void detect_tee_run(detect_score_t *score, int verbose)
{
    LOG_HEADER("TEE SIMULATOR / KEYBOX / ROOT MODULE DETECTION");

    int libc_found = 0;
    int direct_found = 0;
    int hiding_detected = 0;

    for (int i = 0; PROBE_PATHS[i]; i++) {
        /* Method 1: libc faccessat (can be hooked) */
        int libc_result = faccessat(AT_FDCWD, PROBE_PATHS[i], F_OK, 0);
        int libc_exists = (libc_result == 0);

        /* Method 2: direct syscall (bypasses hooks) */
        long direct_result = direct_faccessat(-100 /* AT_FDCWD */,
                                               PROBE_PATHS[i], 0 /* F_OK */, 0);
        int direct_exists = (direct_result == 0);

        if (libc_exists)   libc_found++;
        if (direct_exists) direct_found++;

        /* Discrepancy detection */
        if (!libc_exists && direct_exists) {
            /* File exists but libc says no → file hiding active! */
            hiding_detected++;
            LOG_FAIL("FILE HIDING: %s (libc=ENOENT, direct=EXISTS)", PROBE_PATHS[i]);
        } else if (libc_exists && direct_exists) {
            LOG_FAIL("Module artifact found: %s", PROBE_PATHS[i]);
        } else if (libc_exists && !direct_exists) {
            /* Unusual: libc says exists but direct says no */
            LOG_WARN("Inconsistent: %s (libc=EXISTS, direct=ENOENT)", PROBE_PATHS[i]);
        } else {
            /* Neither found — clean */
            if (verbose)
                LOG_DETAIL("Clean: %s", PROBE_PATHS[i]);
        }
    }

    /* Summary */
    if (hiding_detected > 0) {
        LOG_FAIL("File hiding mechanism detected: %d files hidden from libc "
                 "but visible via direct syscall", hiding_detected);
        score_fail(score);
    } else if (direct_found > 0) {
        LOG_FAIL("Root/TEE module files detected: %d (via direct syscall)",
                 direct_found);
        score_fail(score);
    } else {
        LOG_PASS("No TEE Simulator, Keybox, or root module files detected");
        score_pass(score);
    }

    if (libc_found != direct_found) {
        LOG_FAIL("Syscall consistency: libc found %d, direct found %d (mismatch!)",
                 libc_found, direct_found);
        score_fail(score);
    } else {
        LOG_PASS("Syscall consistency: libc and direct agree (%d files)", libc_found);
        score_pass(score);
    }
}

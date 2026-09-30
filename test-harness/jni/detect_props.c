/*
 * detect_props.c — Check system properties for root/unlock indicators
 *
 * Reads properties via __system_property_get() and checks for values
 * indicating unlocked bootloader, debug build, or modified system.
 */
#include "detect_props.h"

#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>

typedef struct {
    const char *name;
    const char *safe_value;   /* Expected value on a locked, stock device */
    const char *description;
} prop_check_t;

static const prop_check_t PROP_CHECKS[] = {
    { "ro.boot.vbmeta.device_state", "locked",
      "Bootloader lock state" },
    { "ro.boot.verifiedbootstate",   "green",
      "Verified boot state" },
    { "ro.boot.flash.locked",        "1",
      "Flash lock status" },
    { "ro.debuggable",               "0",
      "Debug build flag" },
    { "ro.secure",                   "1",
      "Secure mode flag" },
    { "ro.build.tags",               "release-keys",
      "Build signing keys" },
    { "ro.build.type",               "user",
      "Build type" },
    { "init.svc.adbd",               "stopped",
      "ADB daemon status" },
    { "ro.build.selinux",            "1",
      "SELinux enabled" },
    { NULL, NULL, NULL }
};

void detect_props_run(detect_score_t *score, int verbose)
{
    LOG_HEADER("SYSTEM PROPERTY ANALYSIS");

    int suspicious = 0;

    for (int i = 0; PROP_CHECKS[i].name; i++) {
        char value[PROP_VALUE_MAX] = {0};
        int len = __system_property_get(PROP_CHECKS[i].name, value);

        if (len <= 0) {
            if (verbose)
                LOG_DETAIL("%-40s = (not set)", PROP_CHECKS[i].name);
            continue;
        }

        int matches = (strcmp(value, PROP_CHECKS[i].safe_value) == 0);

        if (!matches) {
            LOG_FAIL("%-40s = \"%s\" (expected \"%s\") — %s",
                     PROP_CHECKS[i].name, value,
                     PROP_CHECKS[i].safe_value,
                     PROP_CHECKS[i].description);
            suspicious++;
        } else {
            if (verbose)
                LOG_DETAIL("%-40s = \"%s\" ✓", PROP_CHECKS[i].name, value);
        }
    }

    if (suspicious > 0) {
        LOG_FAIL("%d suspicious system properties detected", suspicious);
        score_fail(score);
    } else {
        LOG_PASS("All system properties match stock/locked values");
        score_pass(score);
    }

    /* Additional: check for su-related properties */
    const char *su_props[] = {
        "ro.modversion",
        "ro.lineageversion",
        "ro.twrp.boot",
        NULL
    };

    int su_found = 0;
    for (int i = 0; su_props[i]; i++) {
        char val[PROP_VALUE_MAX] = {0};
        if (__system_property_get(su_props[i], val) > 0) {
            su_found++;
            if (verbose)
                LOG_DETAIL("Custom ROM property: %s = %s", su_props[i], val);
        }
    }

    if (su_found > 0) {
        LOG_WARN("Custom ROM properties found: %d", su_found);
        score_warn(score);
    } else {
        LOG_PASS("No custom ROM properties detected");
        score_pass(score);
    }
}

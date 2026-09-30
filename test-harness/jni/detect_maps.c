/*
 * detect_maps.c — Scan /proc/self/maps for injection artifacts
 *
 * Implements heuristics H1-H5 to detect injected libraries, hook
 * frameworks, TEE Simulator modules, and anonymous executable pages.
 */
#include "detect_maps.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

/* Whitelisted path prefixes — normal system library locations */
static const char *PATH_WHITELIST[] = {
    "/system/",  "/vendor/",  "/apex/",    "/data/app/",
    "/data/dalvik-cache/", "/dev/ashmem/", "/dev/mali",
    "/dev/kgsl",  "/dev/dma_heap/", "/dev/ion",
    "[vdso]", "[vvar]", "[stack", "[heap]", "[anon:",
    NULL
};

/* Known hook framework / module keywords in pathnames */
static const char *HOOK_KEYWORDS[] = {
    "frida",      "substrate",   "xposed",     "lsposed",
    "edxposed",   "riru",        "zygisk",     "magisk",
    "dobby",      "libgadget",   "linjector",  "xhook",
    "sandhook",   "whale",       "pine",
    "keymint_soft", "triquestokeymint", "playintegrityfix",
    "playcurl",   "keybox",      "shamiko",
    NULL
};

/* Track basenames for duplicate detection (H5) */
typedef struct {
    char   name[256];
    uint64_t base;
} lib_entry_t;

static int is_path_whitelisted(const char *path)
{
    if (!path || path[0] == '\0')
        return 1; /* empty path = anonymous, handled by H2 */

    for (int i = 0; PATH_WHITELIST[i]; i++) {
        if (strncmp(path, PATH_WHITELIST[i], strlen(PATH_WHITELIST[i])) == 0)
            return 1;
    }
    return 0;
}

static const char *match_hook_keyword(const char *path)
{
    if (!path) return NULL;
    /* Case-insensitive search through the path string */
    char lower[512];
    size_t len = strlen(path);
    if (len >= sizeof(lower)) len = sizeof(lower) - 1;

    for (size_t i = 0; i < len; i++)
        lower[i] = (path[i] >= 'A' && path[i] <= 'Z')
                   ? (char)(path[i] + 32) : path[i];
    lower[len] = '\0';

    for (int i = 0; HOOK_KEYWORDS[i]; i++) {
        if (strstr(lower, HOOK_KEYWORDS[i]))
            return HOOK_KEYWORDS[i];
    }
    return NULL;
}

void detect_maps_run(detect_score_t *score, int verbose)
{
    LOG_HEADER("MEMORY MAP INSPECTION (/proc/self/maps)");

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOG_FAIL("Cannot open /proc/self/maps: %s", strerror(errno));
        score_fail(score);
        return;
    }

    char line[1024];
    int suspicious_path = 0;
    int anonymous_exec = 0;
    int deleted_libs = 0;
    int abnormal_size = 0;
    int hook_found = 0;

    /* For duplicate detection */
    lib_entry_t libs[512];
    int lib_count = 0;
    int duplicates = 0;

    while (fgets(line, sizeof(line), fp)) {
        uint64_t start, end;
        char perms[5] = {0};
        uint64_t offset;
        unsigned int dev_major, dev_minor;
        unsigned long inode;
        char path[512] = {0};

        int n = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %511[^\n]",
                        &start, &end, perms, &offset,
                        &dev_major, &dev_minor, &inode, path);

        /* Trim leading whitespace from path */
        char *trimmed = path;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;

        int is_exec = (perms[0] == 'r' && perms[2] == 'x');
        uint64_t size = end - start;

        /* H1: Path anomaly — not in whitelist */
        if (n >= 8 && trimmed[0] != '\0' && is_exec) {
            if (!is_path_whitelisted(trimmed)) {
                suspicious_path++;
                if (verbose)
                    LOG_DETAIL("H1 suspicious path: %s [%lx-%lx]",
                               trimmed, start, end);
            }
        }

        /* H2: Anonymous executable page (r-xp, inode=0, dev=00:00) */
        if (is_exec && inode == 0 && dev_major == 0 && dev_minor == 0) {
            /* Exclude known benign: [vdso], [vectors], JIT pages */
            if (strstr(trimmed, "[vdso]") == NULL &&
                strstr(trimmed, "[vectors]") == NULL) {
                anonymous_exec++;
                if (verbose)
                    LOG_DETAIL("H2 anonymous exec: %s [%lx-%lx] (%lu KB)",
                               trimmed[0] ? trimmed : "(unnamed)",
                               start, end, (unsigned long)(size / 1024));
            }
        }

        /* H3: Deleted indicator */
        if (is_exec && strstr(trimmed, "(deleted)") != NULL) {
            deleted_libs++;
            if (verbose)
                LOG_DETAIL("H3 deleted lib: %s", trimmed);
        }

        /* H4: Abnormal r-xp size */
        if (is_exec && inode != 0 && size < 4096) {
            abnormal_size++;
            if (verbose)
                LOG_DETAIL("H4 tiny exec VMA: %lu bytes at %lx", (unsigned long)size, start);
        }

        /* Hook framework keyword scan */
        const char *kw = match_hook_keyword(trimmed);
        if (kw && is_exec) {
            hook_found++;
            if (verbose)
                LOG_DETAIL("Hook keyword '%s' in: %s", kw, trimmed);
        }

        /* H5: Track libraries for duplicate detection */
        if (n >= 8 && trimmed[0] == '/' && is_exec) {
            const char *bn = strrchr(trimmed, '/');
            bn = bn ? bn + 1 : trimmed;

            /* Check for duplicate basename with different base */
            for (int i = 0; i < lib_count; i++) {
                if (strcmp(libs[i].name, bn) == 0 && libs[i].base != start) {
                    duplicates++;
                    if (verbose)
                        LOG_DETAIL("H5 duplicate: %s at %lx and %lx",
                                   bn, libs[i].base, start);
                    break;
                }
            }
            if (lib_count < 512) {
                strncpy(libs[lib_count].name, bn, 255);
                libs[lib_count].name[255] = '\0';
                libs[lib_count].base = start;
                lib_count++;
            }
        }
    }
    fclose(fp);

    /* Report results */
    if (suspicious_path > 0) {
        LOG_FAIL("H1: %d suspicious library paths (outside whitelist)", suspicious_path);
        score_fail(score);
    } else {
        LOG_PASS("H1: No suspicious library paths");
        score_pass(score);
    }

    if (anonymous_exec > 0) {
        LOG_FAIL("H2: %d anonymous executable pages detected", anonymous_exec);
        score_fail(score);
    } else {
        LOG_PASS("H2: No anonymous executable pages");
        score_pass(score);
    }

    if (deleted_libs > 0) {
        LOG_FAIL("H3: %d deleted libraries still mapped", deleted_libs);
        score_fail(score);
    } else {
        LOG_PASS("H3: No deleted library mappings");
        score_pass(score);
    }

    if (abnormal_size > 0) {
        LOG_WARN("H4: %d abnormally small executable VMAs", abnormal_size);
        score_warn(score);
    } else {
        LOG_PASS("H4: All executable VMA sizes normal");
        score_pass(score);
    }

    if (duplicates > 0) {
        LOG_FAIL("H5: %d duplicate libraries with different bases", duplicates);
        score_fail(score);
    } else {
        LOG_PASS("H5: No duplicate library mappings");
        score_pass(score);
    }

    if (hook_found > 0) {
        LOG_FAIL("Hook frameworks detected: %d keyword matches", hook_found);
        score_fail(score);
    } else {
        LOG_PASS("No known hook framework signatures in maps");
        score_pass(score);
    }
}

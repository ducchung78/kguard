/*
 * detect_linker.c — Compare dl_iterate_phdr vs /proc/self/maps
 *
 * Cross-references the dynamic linker's view of loaded libraries
 * with the kernel's view via /proc/self/maps.  Discrepancies indicate
 * either hidden injection or filtered maps output.
 */
#include "detect_linker.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <link.h>
#include <dlfcn.h>

typedef struct {
    char     name[256];
    uint64_t addr;
} lib_record_t;

static lib_record_t g_phdr_libs[512];
static int          g_phdr_count = 0;

static lib_record_t g_maps_libs[512];
static int          g_maps_count = 0;

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    (void)data;

    if (!info->dlpi_name || info->dlpi_name[0] == '\0')
        return 0;

    if (g_phdr_count >= 512)
        return 0;

    const char *bn = strrchr(info->dlpi_name, '/');
    bn = bn ? bn + 1 : info->dlpi_name;

    strncpy(g_phdr_libs[g_phdr_count].name, bn, 255);
    g_phdr_libs[g_phdr_count].name[255] = '\0';
    g_phdr_libs[g_phdr_count].addr = info->dlpi_addr;
    g_phdr_count++;

    return 0;
}

static void load_maps_libs(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[1024];
    while (fgets(line, sizeof(line), fp) && g_maps_count < 512) {
        /* Only look at executable mappings with a file path */
        if (strstr(line, "r-xp") == NULL)
            continue;

        char path[256] = {0};
        uint64_t start;

        if (sscanf(line, "%lx-%*lx %*s %*s %*s %*s %255[^\n]", &start, path) < 2)
            continue;

        char *p = path;
        while (*p == ' ' || *p == '\t') p++;

        if (p[0] != '/')
            continue;
        if (strstr(p, ".so") == NULL)
            continue;

        const char *bn = strrchr(p, '/');
        bn = bn ? bn + 1 : p;

        /* Avoid duplicates (multiple VMAs for same lib) */
        int dup = 0;
        for (int i = 0; i < g_maps_count; i++) {
            if (strcmp(g_maps_libs[i].name, bn) == 0) {
                dup = 1;
                break;
            }
        }
        if (!dup) {
            strncpy(g_maps_libs[g_maps_count].name, bn, 255);
            g_maps_libs[g_maps_count].name[255] = '\0';
            g_maps_libs[g_maps_count].addr = start;
            g_maps_count++;
        }
    }
    fclose(fp);
}

void detect_linker_run(detect_score_t *score, int verbose)
{
    LOG_HEADER("LINKER / SOINFO CONSISTENCY CHECK");

    g_phdr_count = 0;
    g_maps_count = 0;

    dl_iterate_phdr(phdr_callback, NULL);
    load_maps_libs();

    if (verbose) {
        LOG_INFO("dl_iterate_phdr: %d libraries", g_phdr_count);
        LOG_INFO("/proc/self/maps: %d libraries", g_maps_count);
    }

    /* Check: libraries in maps but NOT in dl_iterate_phdr
     * → Could be manually dlopen'd or injected */
    int maps_only = 0;
    for (int i = 0; i < g_maps_count; i++) {
        int found = 0;
        for (int j = 0; j < g_phdr_count; j++) {
            if (strcmp(g_maps_libs[i].name, g_phdr_libs[j].name) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            /* Some system libs may not appear in dl_iterate_phdr (linker, vdso) */
            if (strstr(g_maps_libs[i].name, "linker") ||
                strstr(g_maps_libs[i].name, "vdso"))
                continue;

            maps_only++;
            if (verbose)
                LOG_DETAIL("In maps but not linker: %s @ %lx",
                           g_maps_libs[i].name, g_maps_libs[i].addr);
        }
    }

    /* Check: libraries in dl_iterate_phdr but NOT in maps
     * → Maps is being filtered/hidden */
    int phdr_only = 0;
    for (int i = 0; i < g_phdr_count; i++) {
        int found = 0;
        for (int j = 0; j < g_maps_count; j++) {
            if (strcmp(g_phdr_libs[i].name, g_maps_libs[j].name) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            phdr_only++;
            if (verbose)
                LOG_DETAIL("In linker but not maps: %s @ %lx (maps filtered?)",
                           g_phdr_libs[i].name, g_phdr_libs[i].addr);
        }
    }

    if (maps_only > 0) {
        LOG_FAIL("Found %d libraries in maps but not in linker (hidden from linker)",
                 maps_only);
        score_fail(score);
    } else {
        LOG_PASS("No libraries hidden from linker");
        score_pass(score);
    }

    if (phdr_only > 0) {
        LOG_FAIL("Found %d libraries in linker but not in maps (maps filtered!)",
                 phdr_only);
        score_fail(score);
    } else {
        LOG_PASS("Linker and maps are consistent");
        score_pass(score);
    }
}

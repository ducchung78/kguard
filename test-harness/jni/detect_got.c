/*
 * detect_got.c — GOT/PLT integrity verification
 *
 * Enumerates loaded libraries via dl_iterate_phdr, locates their
 * GOT sections, and verifies each entry points into a legitimate
 * dependency VMA rather than anonymous or unknown memory regions.
 */
#include "detect_got.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>

/* Parsed VMA entry from /proc/self/maps */
typedef struct {
    uint64_t start;
    uint64_t end;
    char     perms[5];
    char     path[256];
} vma_entry_t;

static vma_entry_t g_vmas[2048];
static int         g_vma_count = 0;

static void load_vma_table(void)
{
    if (g_vma_count > 0)
        return; /* Already loaded */

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[1024];
    while (fgets(line, sizeof(line), fp) && g_vma_count < 2048) {
        vma_entry_t *v = &g_vmas[g_vma_count];
        v->path[0] = '\0';

        unsigned long inode;
        unsigned int dmaj, dmin;
        uint64_t offset;

        int n = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %255[^\n]",
                        &v->start, &v->end, v->perms, &offset,
                        &dmaj, &dmin, &inode, v->path);
        if (n >= 7) {
            /* Trim leading whitespace from path */
            char *p = v->path;
            while (*p == ' ' || *p == '\t') p++;
            if (p != v->path)
                memmove(v->path, p, strlen(p) + 1);
            g_vma_count++;
        }
    }
    fclose(fp);
}

/* Find which library a given address belongs to */
static const char *find_vma_owner(uint64_t addr)
{
    for (int i = 0; i < g_vma_count; i++) {
        if (addr >= g_vmas[i].start && addr < g_vmas[i].end)
            return g_vmas[i].path[0] ? g_vmas[i].path : "[anonymous]";
    }
    return NULL;
}

/* Per-library check context */
typedef struct {
    int total_entries;
    int suspicious_entries;
    int verbose;
    detect_score_t *score;
} got_check_ctx_t;

/* Check GOT entries for a single shared object */
static int check_got_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    got_check_ctx_t *ctx = (got_check_ctx_t *)data;

    /* Skip entries with no name (main executable or vdso) */
    if (!info->dlpi_name || info->dlpi_name[0] == '\0')
        return 0;

    /* Skip linker itself and vdso */
    if (strstr(info->dlpi_name, "linker") || strstr(info->dlpi_name, "[vdso]"))
        return 0;

    /* Find DT_PLTGOT and DT_PLTRELSZ from .dynamic */
    uint64_t pltgot = 0;
    uint64_t jmprel = 0;
    uint64_t pltrelsz = 0;

    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type != PT_DYNAMIC)
            continue;

        const Elf64_Dyn *dyn = (const Elf64_Dyn *)
            (info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);

        for (; dyn->d_tag != DT_NULL; dyn++) {
            switch (dyn->d_tag) {
            case DT_PLTGOT:   pltgot   = dyn->d_un.d_ptr; break;
            case DT_JMPREL:   jmprel   = dyn->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz = dyn->d_un.d_val; break;
            }
        }
        break;
    }

    if (pltgot == 0 || jmprel == 0 || pltrelsz == 0)
        return 0;

    /* Calculate number of PLT/GOT entries from JMPREL relocation table */
    size_t num_entries = pltrelsz / sizeof(Elf64_Rela);

    /* Check if GOT is relocated (absolute address or relative) */
    const uint64_t *got = (const uint64_t *)(info->dlpi_addr + pltgot);

    /* The first 3 GOT entries are reserved (dynamic linker uses them) */
    /* PLT entries start after the reserved entries */
    if (num_entries < 4)
        return 0;

    /* Check each PLT/GOT entry (skip reserved 3) */
    for (size_t j = 3; j < num_entries + 3 && j < 256; j++) {
        uint64_t target = got[j];
        if (target == 0)
            continue;

        ctx->total_entries++;
        const char *owner = find_vma_owner(target);

        if (owner == NULL) {
            /* GOT entry points to unmapped memory */
            ctx->suspicious_entries++;
            if (ctx->verbose) {
                const char *bn = strrchr(info->dlpi_name, '/');
                bn = bn ? bn + 1 : info->dlpi_name;
                LOG_DETAIL("GOT[%zu] in %s → %lx (UNMAPPED)", j, bn, target);
            }
        } else if (strcmp(owner, "[anonymous]") == 0) {
            /* GOT entry points to anonymous executable page */
            ctx->suspicious_entries++;
            if (ctx->verbose) {
                const char *bn = strrchr(info->dlpi_name, '/');
                bn = bn ? bn + 1 : info->dlpi_name;
                LOG_DETAIL("GOT[%zu] in %s → %lx (ANONYMOUS)", j, bn, target);
            }
        }
    }

    return 0;
}

/* Also check specific known symbols via dlsym comparison */
static void check_dlsym_consistency(detect_score_t *score, int verbose)
{
    static const char *symbols[] = { "open", "read", "write", "mmap",
                                     "close", "fopen", "system", NULL };

    void *libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
    if (!libc) return;

    int mismatches = 0;

    for (int i = 0; symbols[i]; i++) {
        void *resolved = dlsym(libc, symbols[i]);
        if (!resolved) continue;

        const char *owner = find_vma_owner((uint64_t)resolved);
        if (owner && strstr(owner, "libc.so") == NULL) {
            mismatches++;
            if (verbose)
                LOG_DETAIL("dlsym(%s) → %p (owned by %s, NOT libc!)",
                           symbols[i], resolved, owner);
        }
    }

    dlclose(libc);

    if (mismatches > 0) {
        LOG_FAIL("dlsym consistency: %d symbols resolve outside libc", mismatches);
        score_fail(score);
    } else {
        LOG_PASS("dlsym consistency: all critical symbols resolve to libc");
        score_pass(score);
    }
}

void detect_got_run(detect_score_t *score, int verbose)
{
    LOG_HEADER("GOT/PLT INTEGRITY INSPECTION");

    load_vma_table();

    got_check_ctx_t ctx = {
        .total_entries = 0,
        .suspicious_entries = 0,
        .verbose = verbose,
        .score = score
    };

    dl_iterate_phdr(check_got_callback, &ctx);

    if (ctx.suspicious_entries > 0) {
        LOG_FAIL("GOT scan: %d/%d entries point to suspicious targets",
                 ctx.suspicious_entries, ctx.total_entries);
        score_fail(score);
    } else {
        LOG_PASS("GOT scan: all %d entries point to valid library VMAs",
                 ctx.total_entries);
        score_pass(score);
    }

    check_dlsym_consistency(score, verbose);
}

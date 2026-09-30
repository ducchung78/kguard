/*
 * detect_integrity.c — .text segment integrity verification
 *
 * 1) Compares SHA-256 of .text from disk file vs in-memory copy
 *    for critical system libraries (libc.so, libart.so).
 * 2) Scans for ARM64 trampoline/hook patterns in executable pages.
 */
#include "detect_integrity.h"
#include "utils/elf_parser.h"
#include "utils/sha256.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

/* ARM64 trampoline patterns to scan for */
typedef struct {
    const char *name;
    const uint8_t *pattern;
    const uint8_t *mask;  /* 0xFF = must match, 0x00 = wildcard */
    int length;
} trampoline_pattern_t;

/*
 * Pattern 1: LDR X16, #8; BR X16 (absolute jump trampoline)
 * 58000050 D61F0200
 */
static const uint8_t PAT_LDR_BR[] = { 0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1F, 0xD6 };
static const uint8_t MSK_LDR_BR[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/*
 * Pattern 2: MOVZ X16, #imm; MOVK X16, #imm, LSL#16; BR X16
 * D280xxxx F2A0xxxx D61F0200
 * (12 bytes: 4-byte MOVZ + 4-byte MOVK + 4-byte BR)
 */
static const uint8_t PAT_MOV_BR[] = { 0x00, 0x00, 0x80, 0xD2, 0x00, 0x00, 0xA0, 0xF2,
                                       0x00, 0x02, 0x1F, 0xD6 };
static const uint8_t MSK_MOV_BR[] = { 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF,
                                       0xFF, 0xFF, 0xFF, 0xFF };

/*
 * Pattern 3: STP X29, X30, [SP, #-16]!; ... ; BR X16
 * A9BF7BFD ... D61F0200
 * SubstrateHook frame-saving trampoline (check first 4 + last 4 bytes)
 */
static const uint8_t PAT_STP_BR_HEAD[] = { 0xFD, 0x7B, 0xBF, 0xA9 };
static const uint8_t MSK_STP_BR_HEAD[] = { 0xFF, 0xFF, 0xFF, 0xFF };

static const trampoline_pattern_t PATTERNS[] = {
    { "LDR X16 + BR X16 (Frida/Dobby)",  PAT_LDR_BR,  MSK_LDR_BR,  8 },
    { "MOVZ + MOVK + BR (Substrate)",     PAT_MOV_BR,  MSK_MOV_BR, 12 },
    { NULL, NULL, NULL, 0 }
};

static int scan_pattern(const uint8_t *code, size_t code_size,
                        const trampoline_pattern_t *pat)
{
    if ((size_t)pat->length > code_size)
        return 0;

    int count = 0;
    for (size_t i = 0; i <= code_size - (size_t)pat->length; i += 4) {
        int match = 1;
        for (int j = 0; j < pat->length; j++) {
            if ((code[i + j] & pat->mask[j]) != (pat->pattern[j] & pat->mask[j])) {
                match = 0;
                break;
            }
        }
        if (match)
            count++;
    }
    return count;
}

/*
 * Scan for far branch instructions (B #imm26) where the target
 * is outside the module's VMA range — indicates a hook redirect.
 */
static int scan_far_branches(const uint8_t *code, size_t code_size,
                             uint64_t base_addr, uint64_t module_start,
                             uint64_t module_end)
{
    int count = 0;
    for (size_t i = 0; i + 4 <= code_size; i += 4) {
        uint32_t insn = *(const uint32_t *)(code + i);

        /* B #imm26: opcode 000101 followed by 26-bit signed offset */
        if ((insn & 0xFC000000) == 0x14000000) {
            int32_t offset = (int32_t)(insn & 0x03FFFFFF);
            /* Sign-extend 26-bit to 32-bit */
            if (offset & 0x02000000)
                offset |= (int32_t)0xFC000000;
            /* Multiply by 4 to get byte offset */
            int64_t target = (int64_t)(base_addr + i) + (int64_t)offset * 4;

            if ((uint64_t)target < module_start || (uint64_t)target > module_end)
                count++;
        }
    }
    return count;
}

/* Libraries to check integrity */
static const char *CHECK_LIBS[] = {
    "/system/lib64/libc.so",
    "/system/lib64/libdl.so",
    "/system/lib64/libart.so",
    NULL
};

void detect_integrity_run(detect_score_t *score, int verbose)
{
    LOG_HEADER("IN-MEMORY INTEGRITY VERIFICATION");

    /* Part 1: Hash comparison for critical libraries */
    for (int i = 0; CHECK_LIBS[i]; i++) {
        char disk_hex[65] = {0};
        char mem_hex[65]  = {0};

        int result = elf_compare_text_integrity(CHECK_LIBS[i], disk_hex, mem_hex);

        const char *basename = strrchr(CHECK_LIBS[i], '/') + 1;

        if (result == 0) {
            LOG_PASS("%s .text integrity OK", basename);
            if (verbose)
                LOG_DETAIL("SHA-256: %s", disk_hex);
            score_pass(score);
        } else if (result == 1) {
            LOG_FAIL("%s .text MODIFIED (inline hook detected)", basename);
            if (verbose) {
                LOG_DETAIL("Disk:   %s", disk_hex);
                LOG_DETAIL("Memory: %s", mem_hex);
            }
            score_fail(score);
        } else {
            LOG_WARN("%s integrity check skipped (cannot open or parse)", basename);
            score_warn(score);
        }
    }

    /* Part 2: Trampoline pattern scan on libc.so .text */
    uint64_t libc_base = elf_find_base_in_maps("libc.so");
    if (libc_base == 0) {
        LOG_WARN("Cannot find libc.so base for trampoline scan");
        score_warn(score);
        return;
    }

    /* Get libc executable segment info */
    int fd = open("/system/lib64/libc.so", 0 /* O_RDONLY */);
    if (fd < 0) {
        LOG_WARN("Cannot open libc.so for trampoline scan");
        score_warn(score);
        return;
    }

    elf_exec_segment_t seg;
    if (elf_find_exec_segment(fd, &seg) < 0) {
        close(fd);
        LOG_WARN("Cannot parse libc.so ELF for trampoline scan");
        score_warn(score);
        return;
    }
    close(fd);

    const uint8_t *text_mem = (const uint8_t *)(libc_base + seg.vaddr);
    int total_hooks = 0;

    for (int p = 0; PATTERNS[p].name; p++) {
        int hits = scan_pattern(text_mem, seg.size, &PATTERNS[p]);
        if (hits > 0) {
            LOG_FAIL("Trampoline pattern '%s': %d hits in libc.so",
                     PATTERNS[p].name, hits);
            total_hooks += hits;
        }
    }

    /* Scan for far branches */
    /* Estimate module VMA range from maps */
    uint64_t mod_end = libc_base + seg.vaddr + seg.size;
    int far = scan_far_branches(text_mem, seg.size, libc_base + seg.vaddr,
                                libc_base, mod_end);
    if (far > 0) {
        LOG_FAIL("Far branch hooks: %d branches outside libc.so range", far);
        total_hooks += far;
    }

    if (total_hooks > 0) {
        score_fail(score);
    } else {
        LOG_PASS("No trampoline/hook patterns found in libc.so");
        score_pass(score);
    }
}

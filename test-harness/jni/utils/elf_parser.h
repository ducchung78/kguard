/*
 * elf_parser.h — Minimal ELF parser for ARM64 shared libraries
 */
#ifndef KGUARD_ELF_PARSER_H
#define KGUARD_ELF_PARSER_H

#include <elf.h>
#include <stdint.h>
#include <stdbool.h>

/* Information about a loaded ELF's executable segment */
typedef struct {
    uint64_t file_offset;   /* Offset of .text in the ELF file */
    uint64_t vaddr;         /* Virtual address (relative to load base) */
    uint64_t size;          /* Size of the executable segment */
    uint32_t flags;         /* Segment flags (PF_R | PF_X etc.) */
} elf_exec_segment_t;

/*
 * Parse an ELF file on disk and extract the first executable PT_LOAD segment.
 * Returns 0 on success, -1 on error.
 */
int elf_find_exec_segment(int fd, elf_exec_segment_t *out);

/*
 * Find the base address of a library in the current process maps.
 * Searches /proc/self/maps for the first r-xp mapping of `libname`.
 * Returns the base address, or 0 on failure.
 */
uint64_t elf_find_base_in_maps(const char *libname);

/*
 * Read the .text content of a library from both disk and memory,
 * computing SHA-256 of each.  Returns 0 if hashes match, 1 if
 * mismatch, -1 on error.
 */
int elf_compare_text_integrity(const char *lib_path,
                               char *disk_hash_hex,
                               char *mem_hash_hex);

#endif /* KGUARD_ELF_PARSER_H */

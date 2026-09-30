/*
 * elf_parser.c — Minimal ELF parser for ARM64
 *
 * Parses ELF64 headers to locate executable segments for integrity
 * verification.  Compares SHA-256 of .text on disk vs in memory.
 */
#include "elf_parser.h"
#include "sha256.h"
#include "../log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>

int elf_find_exec_segment(int fd, elf_exec_segment_t *out)
{
    Elf64_Ehdr ehdr;

    if (pread(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr))
        return -1;

    /* Validate ELF magic */
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
        return -1;

    /* Must be 64-bit ELF */
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64)
        return -1;

    /* Read program headers to find executable PT_LOAD */
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        off_t off = ehdr.e_phoff + (off_t)i * ehdr.e_phentsize;

        if (pread(fd, &phdr, sizeof(phdr), off) != sizeof(phdr))
            return -1;

        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            out->file_offset = phdr.p_offset;
            out->vaddr       = phdr.p_vaddr;
            out->size        = phdr.p_filesz;
            out->flags       = phdr.p_flags;
            return 0;
        }
    }
    return -1; /* No executable segment found */
}

uint64_t elf_find_base_in_maps(const char *libname)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp)
        return 0;

    char line[1024];
    uint64_t base = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* Look for r-xp (read-execute private) mapping of the library */
        if (strstr(line, "r-xp") == NULL)
            continue;
        if (strstr(line, libname) == NULL)
            continue;

        /* Parse base address (first hex number before '-') */
        char *dash = strchr(line, '-');
        if (dash) {
            *dash = '\0';
            base = strtoull(line, NULL, 16);
        }
        break;
    }

    fclose(fp);
    return base;
}

int elf_compare_text_integrity(const char *lib_path,
                               char *disk_hash_hex,
                               char *mem_hash_hex)
{
    int fd = open(lib_path, O_RDONLY);
    if (fd < 0)
        return -1;

    elf_exec_segment_t seg;
    if (elf_find_exec_segment(fd, &seg) < 0) {
        close(fd);
        return -1;
    }

    /* Limit segment size to avoid huge allocations */
    if (seg.size > 16 * 1024 * 1024) {
        close(fd);
        return -1;
    }

    /* Hash the .text from disk */
    uint8_t *disk_buf = malloc(seg.size);
    if (!disk_buf) {
        close(fd);
        return -1;
    }

    ssize_t rd = pread(fd, disk_buf, seg.size, seg.file_offset);
    close(fd);

    if (rd < 0 || (size_t)rd != seg.size) {
        free(disk_buf);
        return -1;
    }

    uint8_t disk_digest[SHA256_DIGEST_LENGTH];
    sha256_hash(disk_buf, seg.size, disk_digest);
    sha256_hex(disk_digest, disk_hash_hex);
    free(disk_buf);

    /* Hash the .text from memory */
    const char *basename = strrchr(lib_path, '/');
    basename = basename ? basename + 1 : lib_path;

    uint64_t base = elf_find_base_in_maps(basename);
    if (base == 0)
        return -1;

    const uint8_t *mem_text = (const uint8_t *)(base + seg.vaddr);

    uint8_t mem_digest[SHA256_DIGEST_LENGTH];
    sha256_hash(mem_text, seg.size, mem_digest);
    sha256_hex(mem_digest, mem_hash_hex);

    return memcmp(disk_digest, mem_digest, SHA256_DIGEST_LENGTH) == 0 ? 0 : 1;
}

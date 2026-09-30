#define _GNU_SOURCE
#include "supervisor_maps.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif

static const char *KEYWORDS[] = {
    "magisk", "zygisk", "zygisksu", "kguard", "riru", "edxposed", "lsposed", "xposed",
    "frida", "substrate", "dobby", "libgadget", "linjector",
    "keymint_soft", "triquestokeymint", "playintegrityfix", "keybox",
    "/data/adb",
    NULL
};

static int should_skip_line(const char *line) {
    if (!line) return 0;
    for (int i = 0; KEYWORDS[i]; i++) {
        if (strcasestr(line, KEYWORDS[i])) return 1;
    }
    return 0;
}

int create_filtered_maps_fd(pid_t target_pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", target_pid);

    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    int memfd = syscall(__NR_memfd_create, "maps", 0);
    if (memfd < 0) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (!should_skip_line(line)) {
            write(memfd, line, strlen(line));
        }
    }
    fclose(fp);

    lseek(memfd, 0, SEEK_SET);
    return memfd;
}

/*
 * detect_namespace.c — Mount namespace isolation detection
 *
 * Checks for overlay/tmpfs/bind mounts indicating root framework activity,
 * and compares this process's mount namespace inode with init's.
 */
#include "detect_namespace.h"
#include "detect_syscall.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

void detect_namespace_run(detect_score_t *score, int verbose)
{
    LOG_HEADER("MOUNT NAMESPACE ANALYSIS");

    /* 1. Compare mount namespace inode with init (PID 1) */
    struct stat self_ns, init_ns;
    int have_ns_info = 0;

    if (stat("/proc/self/ns/mnt", &self_ns) == 0 &&
        stat("/proc/1/ns/mnt", &init_ns) == 0) {
        have_ns_info = 1;

        if (self_ns.st_ino != init_ns.st_ino) {
            LOG_WARN("Process is in ISOLATED mount namespace (ino %lu != init %lu)",
                     (unsigned long)self_ns.st_ino, (unsigned long)init_ns.st_ino);
            score_warn(score);
        } else {
            LOG_PASS("Mount namespace matches init (not isolated)");
            score_pass(score);
        }
    } else {
        LOG_WARN("Cannot read namespace inodes (permission denied)");
        score_warn(score);
    }

    /* 2. Scan /proc/self/mountinfo for suspicious mounts */
    FILE *fp = fopen("/proc/self/mountinfo", "r");
    if (!fp) {
        /* Try direct syscall in case libc open is hooked */
        int fd = (int)direct_openat(-100, "/proc/self/mountinfo", 0, 0);
        if (fd < 0) {
            LOG_FAIL("Cannot open /proc/self/mountinfo via any method");
            score_fail(score);
            return;
        }

        /* Read content via direct syscall */
        char buf[65536];
        long total = 0;
        long n;
        while ((n = direct_read(fd, buf + total,
                                sizeof(buf) - (size_t)total - 1)) > 0)
            total += n;

        direct_close(fd);
        buf[total] = '\0';

        /* Parse from buffer instead */
        fp = fmemopen(buf, (size_t)total, "r");
        if (!fp) {
            LOG_FAIL("Cannot parse mountinfo");
            score_fail(score);
            return;
        }
    }

    char line[1024];
    int overlay_system = 0;
    int tmpfs_system = 0;
    int magisk_mounts = 0;
    int bind_suspicious = 0;

    while (fgets(line, sizeof(line), fp)) {
        /*
         * mountinfo format:
         * mount_id parent_id dev root mountpoint options ... - fstype source super_options
         */
        char mountpoint[256] = {0};
        char fstype[64] = {0};
        char source[256] = {0};

        /* Parse mountpoint (5th field) */
        int field = 0;
        char *tok = line;
        char *mp = NULL, *sep = NULL;

        /* Find fields by spaces */
        char *fields[20] = {0};
        int nf = 0;
        char *saveptr = NULL;
        char linecopy[1024];
        strncpy(linecopy, line, sizeof(linecopy) - 1);
        linecopy[sizeof(linecopy) - 1] = '\0';

        tok = strtok_r(linecopy, " ", &saveptr);
        while (tok && nf < 20) {
            fields[nf++] = tok;
            tok = strtok_r(NULL, " ", &saveptr);
        }

        /* Field 4 (0-indexed) = mountpoint */
        if (nf > 4)
            strncpy(mountpoint, fields[4], sizeof(mountpoint) - 1);

        /* Find separator '-' and then fstype, source */
        for (int i = 5; i < nf; i++) {
            if (strcmp(fields[i], "-") == 0 && i + 2 < nf) {
                strncpy(fstype, fields[i + 1], sizeof(fstype) - 1);
                strncpy(source, fields[i + 2], sizeof(source) - 1);
                break;
            }
        }

        /* Check for overlay on /system, /vendor, /product */
        if (strcmp(fstype, "overlay") == 0) {
            if (strncmp(mountpoint, "/system", 7) == 0 ||
                strncmp(mountpoint, "/vendor", 7) == 0 ||
                strncmp(mountpoint, "/product", 8) == 0) {
                overlay_system++;
                if (verbose)
                    LOG_DETAIL("Overlay on %s (source=%s)", mountpoint, source);
            }
        }

        /* Check for tmpfs on /system paths */
        if (strcmp(fstype, "tmpfs") == 0) {
            if (strncmp(mountpoint, "/system", 7) == 0) {
                tmpfs_system++;
                if (verbose)
                    LOG_DETAIL("tmpfs on %s", mountpoint);
            }
        }

        /* Check for magisk-related mounts */
        if (strstr(source, "magisk") || strstr(mountpoint, "magisk") ||
            strstr(mountpoint, ".magisk")) {
            magisk_mounts++;
            if (verbose)
                LOG_DETAIL("Magisk mount: %s → %s (%s)", source, mountpoint, fstype);
        }

        /* Check for bind mounts from /data/adb */
        if (strstr(source, "/data/adb") || strstr(line, "/data/adb")) {
            bind_suspicious++;
            if (verbose)
                LOG_DETAIL("Bind from /data/adb: %s → %s", source, mountpoint);
        }
    }
    fclose(fp);

    /* Report results */
    if (overlay_system > 0) {
        LOG_FAIL("Found %d overlay mount(s) on /system or /vendor", overlay_system);
        score_fail(score);
    } else {
        LOG_PASS("No overlay mounts on system partitions");
        score_pass(score);
    }

    if (tmpfs_system > 0) {
        LOG_FAIL("Found %d tmpfs mount(s) on /system paths", tmpfs_system);
        score_fail(score);
    } else {
        LOG_PASS("No tmpfs on system paths");
        score_pass(score);
    }

    if (magisk_mounts > 0) {
        LOG_FAIL("Found %d Magisk-related mount(s)", magisk_mounts);
        score_fail(score);
    } else {
        LOG_PASS("No Magisk mount artifacts");
        score_pass(score);
    }

    if (bind_suspicious > 0) {
        LOG_FAIL("Found %d suspicious bind mount(s) from /data/adb", bind_suspicious);
        score_fail(score);
    } else {
        LOG_PASS("No suspicious bind mounts");
        score_pass(score);
    }
}

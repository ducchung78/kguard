#include "namespace_cleanup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/mount.h>
#include <unistd.h>
#include <android/log.h>
#include <vector>
#include <string>

#define LOG_TAG "KGuard-NS"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static bool is_whitelisted(const char *mountpoint) {
    if (!mountpoint) return false;
    if (strstr(mountpoint, "/vendor/firmware")) return true;
    if (strstr(mountpoint, "/vendor/lib64")) return true;
    if (strstr(mountpoint, "/mnt/vendor/persist")) return true;
    if (strstr(mountpoint, "/dev/kgsl-3d0")) return true;
    return false;
}

int kguard_isolate_mount_namespace(uint32_t policy_flags) {
    // 1. Create a detached private mount namespace
    if (unshare(CLONE_NEWNS) != 0) {
        LOGE("unshare(CLONE_NEWNS) failed");
        return -1;
    }

    // 2. Prevent propagation from parent mount namespace
    if (mount("", "/", nullptr, MS_PRIVATE | MS_REC, nullptr) != 0) {
        LOGE("mount MS_PRIVATE / failed");
    }

    // 3. Scan /proc/self/mountinfo to detect injected mounts
    FILE *fp = fopen("/proc/self/mountinfo", "r");
    if (!fp) {
        LOGE("Failed to open /proc/self/mountinfo");
        return -1;
    }

    std::vector<std::string> to_unmount;
    char line[1024];

    while (fgets(line, sizeof(line), fp)) {
        char mountpoint[256] = {0};
        char fstype[64] = {0};
        char source[256] = {0};

        char *fields[24] = {nullptr};
        int nf = 0;
        char *saveptr = nullptr;
        char *tok = strtok_r(line, " ", &saveptr);
        while (tok && nf < 24) {
            fields[nf++] = tok;
            tok = strtok_r(nullptr, " ", &saveptr);
        }

        if (nf > 4) {
            strncpy(mountpoint, fields[4], sizeof(mountpoint) - 1);
        }

        // Find separator '-' to get fstype and source
        for (int i = 5; i < nf; i++) {
            if (fields[i] && strcmp(fields[i], "-") == 0 && i + 2 < nf) {
                strncpy(fstype, fields[i + 1], sizeof(fstype) - 1);
                strncpy(source, fields[i + 2], sizeof(source) - 1);
                break;
            }
        }

        if (is_whitelisted(mountpoint)) {
            continue;
        }

        bool should_unmount = false;

        // OverlayFS on system/vendor/product
        if (strcmp(fstype, "overlay") == 0) {
            if (strncmp(mountpoint, "/system", 7) == 0 ||
                strncmp(mountpoint, "/vendor", 7) == 0 ||
                strncmp(mountpoint, "/product", 8) == 0 ||
                strncmp(mountpoint, "/system_ext", 11) == 0) {
                should_unmount = true;
            }
        }

        // Tmpfs on system
        if (strcmp(fstype, "tmpfs") == 0) {
            if (strncmp(mountpoint, "/system", 7) == 0) {
                should_unmount = true;
            }
        }

        // Magisk / KernelSU / APatch mounts
        if (strstr(source, "magisk") || strstr(mountpoint, "magisk") ||
            strstr(mountpoint, ".magisk") || strstr(source, "/data/adb")) {
            should_unmount = true;
        }

        // TEE Simulator mounts (if policy flag enabled)
        if (policy_flags & (1 << 3)) { // HIDE_TEE
            if (strstr(mountpoint, "/system/bin/hw") ||
                strstr(mountpoint, "/system/etc/vintf") ||
                strstr(mountpoint, "/system/etc/init")) {
                should_unmount = true;
            }
        }

        if (should_unmount && mountpoint[0] != '\0') {
            to_unmount.push_back(mountpoint);
        }
    }
    fclose(fp);

    // 4. Perform unmounts in reverse order (leaf-first)
    int count = 0;
    for (auto it = to_unmount.rbegin(); it != to_unmount.rend(); ++it) {
        if (umount2(it->c_str(), MNT_DETACH) == 0) {
            count++;
            LOGD("Cleaned mount point: %s", it->c_str());
        }
    }

    LOGD("Mount namespace isolation complete: %d mounts detached", count);
    return count;
}

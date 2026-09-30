#define _GNU_SOURCE
#include "supervisor_handler.h"
#include "supervisor_maps.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/seccomp.h>
#include <android/log.h>

#define LOG_TAG "KGuard-SupvHandler"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

#ifndef SECCOMP_IOCTL_NOTIF_RECV
struct seccomp_notif {
    __u64 id;
    __u32 pid;
    __u32 flags;
    struct seccomp_data data;
};

struct seccomp_notif_resp {
    __u64 id;
    __s64 val;
    __s32 error;
    __u32 flags;
};

struct seccomp_notif_addfd {
    __u64 id;
    __u32 flags;
    __u32 srcfd;
    __u32 newfd;
    __u32 newfd_flags;
};

#define SECCOMP_IOC_MAGIC '!'
#define SECCOMP_IOCTL_NOTIF_RECV   _IOWR(SECCOMP_IOC_MAGIC, 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND   _IOWR(SECCOMP_IOC_MAGIC, 1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID _IOR(SECCOMP_IOC_MAGIC, 2, __u64)
#define SECCOMP_IOCTL_NOTIF_ADDFD  _IOW(SECCOMP_IOC_MAGIC, 3, struct seccomp_notif_addfd)
#endif

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

#define ARM64_NR_openat     56
#define ARM64_NR_faccessat  48
#define ARM64_NR_readlinkat 78
#define ARM64_NR_newfstatat 79
#define ARM64_NR_prctl      167
#define ARM64_NR_statx      291

static int read_target_path(pid_t pid, uint64_t addr, char *out, size_t max_len) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int fd = open(mem_path, O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n = pread(fd, out, max_len - 1, (off_t)addr);
    close(fd);
    if (n <= 0) return -1;

    out[max_len - 1] = '\0';
    return 0;
}

static int is_hidden_path(const char *path) {
    if (!path) return 0;
    if (strstr(path, "/data/adb/modules")) return 1;
    if (strstr(path, "/data/adb/magisk")) return 1;
    if (strstr(path, "/data/adb/ksu")) return 1;
    if (strstr(path, "keybox.xml")) return 1;
    if (strstr(path, "keybox.json")) return 1;
    if (strstr(path, "triquestokeymint")) return 1;
    if (strstr(path, "playintegrityfix")) return 1;
    return 0;
}

int handle_seccomp_notification(int notif_fd) {
    struct seccomp_notif req;
    memset(&req, 0, sizeof(req));

    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) != 0) {
        return (errno == ENOENT) ? 0 : -1;
    }

    struct seccomp_notif_resp resp;
    memset(&resp, 0, sizeof(resp));
    resp.id = req.id;

    switch (req.data.nr) {
        case ARM64_NR_openat: {
            char path[512] = {0};
            if (read_target_path(req.pid, req.data.args[1], path, sizeof(path)) == 0) {
                // If opening /proc/self/maps or /proc/[pid]/maps -> inject clean memfd
                if (strstr(path, "/proc/self/maps") || (strstr(path, "/proc/") && strstr(path, "/maps"))) {
                    int memfd = create_filtered_maps_fd(req.pid);
                    if (memfd >= 0) {
                        struct seccomp_notif_addfd addfd;
                        memset(&addfd, 0, sizeof(addfd));
                        addfd.id = req.id;
                        addfd.flags = 0;
                        addfd.srcfd = memfd;
                        addfd.newfd = 0;

                        int ret = ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
                        close(memfd);
                        if (ret >= 0) {
                            resp.val = ret;
                            resp.error = 0;
                            resp.flags = 0;
                            return ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
                        }
                    }
                }

                if (is_hidden_path(path)) {
                    resp.error = -ENOENT;
                    resp.val = 0;
                    resp.flags = 0;
                    return ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
                }
            }
            break;
        }

        case ARM64_NR_faccessat:
        case ARM64_NR_newfstatat:
        case ARM64_NR_statx: {
            char path[512] = {0};
            if (read_target_path(req.pid, req.data.args[1], path, sizeof(path)) == 0) {
                if (is_hidden_path(path)) {
                    resp.error = -ENOENT;
                    resp.val = 0;
                    resp.flags = 0;
                    return ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
                }
            }
            break;
        }

        case ARM64_NR_prctl: {
            // PR_GET_SECCOMP = 22, PR_GET_NO_NEW_PRIVS = 39
            if (req.data.args[0] == 22 || req.data.args[0] == 39) {
                resp.val = 0;
                resp.error = 0;
                resp.flags = 0;
                return ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
            }
            break;
        }

        default:
            break;
    }

    // Default: Continue syscall execution transparently
    resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    resp.error = 0;
    resp.val = 0;
    return ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
}

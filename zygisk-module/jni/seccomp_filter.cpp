#include "seccomp_filter.h"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/bpf_common.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <android/log.h>
#include <stddef.h>

#define LOG_TAG "KGuard-Seccomp"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define SUPERVISOR_SOCK "/data/adb/kguard/supervisor.sock"

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

#ifndef __NR_seccomp
#define __NR_seccomp 277
#endif

// ARM64 Syscall Numbers
#define ARM64_NR_openat         56
#define ARM64_NR_faccessat      48
#define ARM64_NR_readlinkat     78
#define ARM64_NR_newfstatat     79
#define ARM64_NR_prctl          167
#define ARM64_NR_statx          291
#define ARM64_NR_io_uring_setup 425
#define ARM64_NR_io_uring_enter 426

static int send_fd_to_supervisor(int fd_to_send) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SUPERVISOR_SOCK, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    struct msghdr msg = {0};
    char buf[CMSG_SPACE(sizeof(int))];
    memset(buf, 0, sizeof(buf));

    struct iovec io = { .iov_base = (void*)"FD", .iov_len = 2 };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *)CMSG_DATA(cmsg)) = fd_to_send;

    ssize_t res = sendmsg(sock, &msg, 0);
    close(sock);
    return (res > 0) ? 0 : -1;
}

int kguard_install_seccomp_filter(uint32_t policy_flags) {
    (void)policy_flags;

    struct sock_filter filter[] = {
        // Load syscall number: A = seccomp_data.nr
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

        // Block io_uring evasion (NR 425, 426) -> return -ENOSYS
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARM64_NR_io_uring_setup, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARM64_NR_io_uring_enter, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),

        // Syscalls requiring interception / sanitization -> SECCOMP_RET_USER_NOTIF
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARM64_NR_openat,     6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARM64_NR_faccessat,  5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARM64_NR_readlinkat, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARM64_NR_newfstatat, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARM64_NR_statx,      2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARM64_NR_prctl,      1, 0),

        // Default: Allow
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        // Action: User notification
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        LOGE("prctl(PR_SET_NO_NEW_PRIVS) failed");
        return -1;
    }

    int notif_fd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                           SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);

    if (notif_fd < 0) {
        LOGE("seccomp(SECCOMP_FILTER_FLAG_NEW_LISTENER) failed: %s", strerror(errno));
        return -1;
    }

    LOGD("Seccomp filter installed, listener fd = %d", notif_fd);

    // Transfer listener fd to background supervisor
    if (send_fd_to_supervisor(notif_fd) != 0) {
        LOGD("Supervisor daemon not reachable yet (fd kept in process)");
    }

    return notif_fd;
}

#define _GNU_SOURCE
#include "supervisor_handler.h"
#include "supervisor_watchdog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <signal.h>
#include <android/log.h>

#define LOG_TAG "KGuard-Supervisor"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define SUPERVISOR_SOCK "/data/adb/kguard/supervisor.sock"
#define MAX_EPOLL_EVENTS 64

static volatile int g_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static int recv_fd_from_client(int client_sock) {
    struct msghdr msg = {0};
    char m_buffer[32];
    struct iovec io = { .iov_base = m_buffer, .iov_len = sizeof(m_buffer) };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    char c_buffer[256];
    msg.msg_control = c_buffer;
    msg.msg_controllen = sizeof(c_buffer);

    ssize_t n = recvmsg(client_sock, &msg, 0);
    if (n <= 0) return -1;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;

    return *((int *)CMSG_DATA(cmsg));
}

int main(void) {
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    LOGI("KGuard Seccomp Supervisor Daemon starting...");

    unlink(SUPERVISOR_SOCK);

    int s_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s_fd < 0) {
        LOGE("socket() failed: %s", strerror(errno));
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SUPERVISOR_SOCK, sizeof(addr.sun_path) - 1);

    if (bind(s_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        LOGE("bind() failed: %s", strerror(errno));
        close(s_fd);
        return 1;
    }

    chmod(SUPERVISOR_SOCK, 0666);

    if (listen(s_fd, 16) != 0) {
        LOGE("listen() failed");
        close(s_fd);
        return 1;
    }

    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        LOGE("epoll_create1 failed");
        close(s_fd);
        return 1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = s_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s_fd, &ev);

    start_supervisor_watchdog();
    LOGI("Listening on %s with epoll engine", SUPERVISOR_SOCK);

    struct epoll_event events[MAX_EPOLL_EVENTS];

    while (g_running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, 1000);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == s_fd) {
                // New connection from Zygisk client
                int c_fd = accept(s_fd, NULL, NULL);
                if (c_fd >= 0) {
                    int notif_fd = recv_fd_from_client(c_fd);
                    close(c_fd);
                    if (notif_fd >= 0) {
                        LOGI("Acquired new seccomp listener fd: %d", notif_fd);
                        struct epoll_event nev;
                        nev.events = EPOLLIN;
                        nev.data.fd = notif_fd;
                        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, notif_fd, &nev);
                    }
                }
            } else {
                // Seccomp notification ready on notif_fd
                int notif_fd = events[i].data.fd;
                if (handle_seccomp_notification(notif_fd) != 0) {
                    // Closed or invalid target process
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, notif_fd, NULL);
                    close(notif_fd);
                }
            }
        }
    }

    close(s_fd);
    close(epoll_fd);
    unlink(SUPERVISOR_SOCK);
    LOGI("Supervisor shutdown complete");
    return 0;
}

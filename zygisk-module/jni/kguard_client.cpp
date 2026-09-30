#include "kguard_client.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>

#define KGUARD_DEVICE_PATH  "/dev/kguard"
#define KGUARD_IOC_MAGIC    'K'

struct kguard_pid_config {
    int32_t  pid;
    uint32_t policy_flags;
};

struct kguard_filter_rule {
    uint32_t type;
    char     keyword[256];
};

#define KGUARD_REGISTER_PID     _IOW(KGUARD_IOC_MAGIC,  1, struct kguard_pid_config)
#define KGUARD_UNREGISTER_PID   _IOW(KGUARD_IOC_MAGIC,  2, int32_t)
#define KGUARD_REGISTER_HAL_PID _IOW(KGUARD_IOC_MAGIC,  3, int32_t)
#define KGUARD_ADD_FILTER       _IOW(KGUARD_IOC_MAGIC, 10, struct kguard_filter_rule)
#define KGUARD_CLEAR_FILTERS    _IO(KGUARD_IOC_MAGIC,  12)

int kguard_client_open(void) {
    return open(KGUARD_DEVICE_PATH, O_RDWR | O_CLOEXEC);
}

void kguard_client_close(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

int kguard_client_register_pid(int fd, pid_t pid, uint32_t policy_flags) {
    if (fd < 0) return -EINVAL;
    struct kguard_pid_config cfg;
    cfg.pid = (int32_t)pid;
    cfg.policy_flags = policy_flags;
    return ioctl(fd, KGUARD_REGISTER_PID, &cfg);
}

int kguard_client_unregister_pid(int fd, pid_t pid) {
    if (fd < 0) return -EINVAL;
    int32_t p = (int32_t)pid;
    return ioctl(fd, KGUARD_UNREGISTER_PID, &p);
}

int kguard_client_register_hal_pid(int fd, pid_t pid) {
    if (fd < 0) return -EINVAL;
    int32_t p = (int32_t)pid;
    return ioctl(fd, KGUARD_REGISTER_HAL_PID, &p);
}

int kguard_client_add_filter(int fd, uint32_t type, const char *keyword) {
    if (fd < 0 || !keyword) return -EINVAL;
    struct kguard_filter_rule rule;
    rule.type = type;
    strncpy(rule.keyword, keyword, sizeof(rule.keyword) - 1);
    rule.keyword[sizeof(rule.keyword) - 1] = '\0';
    return ioctl(fd, KGUARD_ADD_FILTER, &rule);
}

int kguard_client_clear_filters(int fd) {
    if (fd < 0) return -EINVAL;
    return ioctl(fd, KGUARD_CLEAR_FILTERS);
}

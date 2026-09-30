#ifndef KGUARD_CLIENT_H
#define KGUARD_CLIENT_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int kguard_client_open(void);
void kguard_client_close(int fd);

int kguard_client_register_pid(int fd, pid_t pid, uint32_t policy_flags);
int kguard_client_unregister_pid(int fd, pid_t pid);
int kguard_client_register_hal_pid(int fd, pid_t pid);

int kguard_client_add_filter(int fd, uint32_t type, const char *keyword);
int kguard_client_clear_filters(int fd);

#ifdef __cplusplus
}
#endif

#endif // KGUARD_CLIENT_H

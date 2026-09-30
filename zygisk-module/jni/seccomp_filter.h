#ifndef KGUARD_SECCOMP_FILTER_H
#define KGUARD_SECCOMP_FILTER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Installs Seccomp-BPF filter for direct syscall trapping/notification,
// blocks io_uring evasion, and transfers notification listener to supervisor.
int kguard_install_seccomp_filter(uint32_t policy_flags);

#ifdef __cplusplus
}
#endif

#endif // KGUARD_SECCOMP_FILTER_H

#ifndef KGUARD_NAMESPACE_CLEANUP_H
#define KGUARD_NAMESPACE_CLEANUP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Performs unshare(CLONE_NEWNS), unmounts Magisk/overlayfs/tmpfs artifacts,
// and ensures private mount propagation.
int kguard_isolate_mount_namespace(uint32_t policy_flags);

#ifdef __cplusplus
}
#endif

#endif // KGUARD_NAMESPACE_CLEANUP_H

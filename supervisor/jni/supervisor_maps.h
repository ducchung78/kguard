#ifndef KGUARD_SUPERVISOR_MAPS_H
#define KGUARD_SUPERVISOR_MAPS_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Creates a sanitized in-memory memfd containing filtered /proc/[pid]/maps content
int create_filtered_maps_fd(pid_t target_pid);

#ifdef __cplusplus
}
#endif

#endif // KGUARD_SUPERVISOR_MAPS_H

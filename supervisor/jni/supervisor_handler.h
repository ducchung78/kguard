#ifndef KGUARD_SUPERVISOR_HANDLER_H
#define KGUARD_SUPERVISOR_HANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

// Handles an incoming seccomp notification on the given notification descriptor
int handle_seccomp_notification(int notif_fd);

#ifdef __cplusplus
}
#endif

#endif // KGUARD_SUPERVISOR_HANDLER_H

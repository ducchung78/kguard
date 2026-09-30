/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kguard_uapi.h — Userspace API for kguard kernel module
 *
 * Shared between kernel module and Zygisk/supervisor userland components.
 */
#ifndef KGUARD_UAPI_H
#define KGUARD_UAPI_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
typedef uint32_t __u32;
typedef int32_t  __s32;
typedef uint64_t __u64;
#endif

#define KGUARD_DEVICE_NAME  "kguard"
#define KGUARD_DEVICE_PATH  "/dev/kguard"
#define KGUARD_IOC_MAGIC    'K'

/* ── Policy flags (bitmask) ────────────────────────── */
#define KGUARD_POLICY_HIDE_MAPS       (1 << 0)
#define KGUARD_POLICY_HIDE_MOUNTS     (1 << 1)
#define KGUARD_POLICY_HIDE_FILES      (1 << 2)
#define KGUARD_POLICY_HIDE_TEE        (1 << 3)
#define KGUARD_POLICY_HIDE_KEYBOX     (1 << 4)
#define KGUARD_POLICY_SPOOF_PROPS     (1 << 5)
#define KGUARD_POLICY_SECCOMP         (1 << 6)
#define KGUARD_POLICY_HIDE_HAL        (1 << 7)

/* Combined presets */
#define KGUARD_POLICY_STRICT_ALL  (0xFF)  /* All flags on */
#define KGUARD_POLICY_STANDARD    (KGUARD_POLICY_HIDE_MAPS  | \
                                   KGUARD_POLICY_HIDE_MOUNTS | \
                                   KGUARD_POLICY_HIDE_FILES  | \
                                   KGUARD_POLICY_SECCOMP)

/* ── Filter types ──────────────────────────────────── */
#define KGUARD_FILTER_MAP   0  /* Filter for /proc/pid/maps lines */
#define KGUARD_FILTER_MNT   1  /* Filter for /proc/pid/mountinfo */
#define KGUARD_FILTER_PATH  2  /* Filter for file access hiding */

/* ── ioctl structures ──────────────────────────────── */

struct kguard_pid_config {
	__s32 pid;
	__u32 policy_flags;
};

struct kguard_filter_rule {
	__u32 type;           /* KGUARD_FILTER_MAP / MNT / PATH */
	char  keyword[256];   /* Keyword to match */
};

struct kguard_status {
	__u32 version;
	__u32 registered_pids;
	__u32 map_filters;
	__u32 mnt_filters;
	__u32 path_filters;
	__u32 hooks_active;
};

/* ── ioctl commands ────────────────────────────────── */

#define KGUARD_REGISTER_PID     _IOW(KGUARD_IOC_MAGIC,  1, struct kguard_pid_config)
#define KGUARD_UNREGISTER_PID   _IOW(KGUARD_IOC_MAGIC,  2, __s32)
#define KGUARD_REGISTER_HAL_PID _IOW(KGUARD_IOC_MAGIC,  3, __s32)

#define KGUARD_ADD_FILTER       _IOW(KGUARD_IOC_MAGIC, 10, struct kguard_filter_rule)
#define KGUARD_DEL_FILTER       _IOW(KGUARD_IOC_MAGIC, 11, struct kguard_filter_rule)
#define KGUARD_CLEAR_FILTERS    _IO(KGUARD_IOC_MAGIC,  12)

#define KGUARD_GET_STATUS       _IOR(KGUARD_IOC_MAGIC, 20, struct kguard_status)

#define KGUARD_VERSION          0x010000  /* 1.0.0 */

#endif /* KGUARD_UAPI_H */

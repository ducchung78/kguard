/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kguard.h — Internal header for kguard kernel module
 */
#ifndef KGUARD_H
#define KGUARD_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/rwlock.h>
#include <linux/rcupdate.h>

#include "kguard_uapi.h"

#define KGUARD_TAG       "kguard"
#define KGUARD_LOG_PREFIX KGUARD_TAG ": "

#define kg_info(fmt, ...)  pr_info(KGUARD_LOG_PREFIX fmt, ##__VA_ARGS__)
#define kg_err(fmt, ...)   pr_err(KGUARD_LOG_PREFIX fmt, ##__VA_ARGS__)
#define kg_warn(fmt, ...)  pr_warn(KGUARD_LOG_PREFIX fmt, ##__VA_ARGS__)
#define kg_dbg(fmt, ...)   pr_debug(KGUARD_LOG_PREFIX fmt, ##__VA_ARGS__)

/* ── PID management (kguard_pid.c) ────────────────── */

struct kguard_pid_entry {
	struct hlist_node  node;
	pid_t              pid;
	u32                policy_flags;
	ktime_t            registered_at;
	struct rcu_head    rcu;
};

int  kguard_pid_init(void);
void kguard_pid_exit(void);
int  kguard_pid_register(pid_t pid, u32 flags);
int  kguard_pid_unregister(pid_t pid);
struct kguard_pid_entry *kguard_pid_lookup(pid_t pid);
bool kguard_pid_has_flag(pid_t pid, u32 flag);
int  kguard_pid_count(void);
void kguard_pid_cleanup_dead(void);

/* ── Filter engine (kguard_filter.c) ──────────────── */

struct kguard_filter_rule_entry {
	struct list_head list;
	char             keyword[256];
	u32              type;
	struct rcu_head  rcu;
};

int  kguard_filter_init(void);
void kguard_filter_exit(void);
int  kguard_filter_add(u32 type, const char *keyword);
int  kguard_filter_remove(u32 type, const char *keyword);
void kguard_filter_clear(u32 type);
bool kguard_filter_match_maps(const char *path, const char *anon_name);
bool kguard_filter_match_mount(const char *source, const char *mountpoint,
			       const char *fstype);
bool kguard_filter_match_path(const char *path);
int  kguard_filter_count(u32 type);

/* ── ftrace hook framework (kguard_ftrace.c) ──────── */

struct kguard_hook {
	const char        *name;      /* Kernel symbol name */
	void              *function;  /* Replacement function */
	void              *original;  /* Saved original (filled by install) */
	unsigned long      address;   /* Resolved address */
	struct ftrace_ops  ops;
	bool               active;
};

int  kguard_ftrace_init(void);
void kguard_ftrace_exit(void);
int  kguard_hook_install(struct kguard_hook *hook);
void kguard_hook_remove(struct kguard_hook *hook);

/* ── procfs hooks (kguard_procfs_maps.c / _mounts.c) ─ */

int  kguard_procfs_maps_init(void);
void kguard_procfs_maps_exit(void);
int  kguard_procfs_mounts_init(void);
void kguard_procfs_mounts_exit(void);

/* ── File hiding (kguard_file_hide.c) ─────────────── */

int  kguard_file_hide_init(void);
void kguard_file_hide_exit(void);

/* ── Module parameters ────────────────────────────── */

extern int  kguard_max_pids;
extern bool kguard_debug;

#endif /* KGUARD_H */

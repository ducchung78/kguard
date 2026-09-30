// SPDX-License-Identifier: GPL-2.0
/*
 * kguard_file_hide.c — Hide file access for registered PIDs
 *
 * Hooks do_faccessat and do_sys_openat2 to return -ENOENT for
 * paths matching the path filter list (module dirs, keybox, etc).
 */
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/sched.h>

#include "kguard.h"

/* ── Original function pointers ────────────────────────────── */

static long (*orig_do_faccessat)(int dfd, const char __user *filename,
				 int mode, int flags);
static long (*orig_do_sys_openat2)(int dfd, const char __user *filename,
				   struct open_how *how);

/* ── Helper: copy and check path from userspace ────────────── */

static bool kguard_should_hide_user_path(const char __user *filename)
{
	char kpath[256];
	long len;

	len = strncpy_from_user(kpath, filename, sizeof(kpath));
	if (len <= 0)
		return false;

	kpath[sizeof(kpath) - 1] = '\0';
	return kguard_filter_match_path(kpath);
}

/* ── Replacement for do_faccessat ──────────────────────────── */

static long kguard_do_faccessat(int dfd, const char __user *filename,
				int mode, int flags)
{
	pid_t tgid = current->tgid;

	rcu_read_lock();
	if (kguard_pid_has_flag(tgid, KGUARD_POLICY_HIDE_FILES) ||
	    kguard_pid_has_flag(tgid, KGUARD_POLICY_HIDE_TEE)) {
		rcu_read_unlock();

		if (kguard_should_hide_user_path(filename))
			return -ENOENT;
	} else {
		rcu_read_unlock();
	}

	return orig_do_faccessat(dfd, filename, mode, flags);
}

/* ── Replacement for do_sys_openat2 ────────────────────────── */

static long kguard_do_sys_openat2(int dfd, const char __user *filename,
				  struct open_how *how)
{
	pid_t tgid = current->tgid;

	rcu_read_lock();
	if (kguard_pid_has_flag(tgid, KGUARD_POLICY_HIDE_FILES) ||
	    kguard_pid_has_flag(tgid, KGUARD_POLICY_HIDE_TEE)) {
		rcu_read_unlock();

		if (kguard_should_hide_user_path(filename))
			return -ENOENT;
	} else {
		rcu_read_unlock();
	}

	return orig_do_sys_openat2(dfd, filename, how);
}

/* ── Hook definitions ──────────────────────────────────────── */

static struct kguard_hook faccessat_hook = {
	.name     = "do_faccessat",
	.function = kguard_do_faccessat,
	.original = &orig_do_faccessat,
};

static struct kguard_hook openat2_hook = {
	.name     = "do_sys_openat2",
	.function = kguard_do_sys_openat2,
	.original = &orig_do_sys_openat2,
};

int kguard_file_hide_init(void)
{
	int ret;

	ret = kguard_hook_install(&faccessat_hook);
	if (ret)
		return ret;

	ret = kguard_hook_install(&openat2_hook);
	if (ret) {
		kguard_hook_remove(&faccessat_hook);
		return ret;
	}

	kg_info("file hide hooks active\n");
	return 0;
}

void kguard_file_hide_exit(void)
{
	kguard_hook_remove(&openat2_hook);
	kguard_hook_remove(&faccessat_hook);
	kg_info("file hide hooks removed\n");
}

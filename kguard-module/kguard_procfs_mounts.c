// SPDX-License-Identifier: GPL-2.0
/*
 * kguard_procfs_mounts.c — Hook mountinfo/mounts output filtering
 *
 * Filters mount entries (overlay, tmpfs, magisk) from /proc/pid/mounts
 * and /proc/pid/mountinfo for registered PIDs.
 */
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/mnt_namespace.h>
#include <linux/sched.h>
#include <linux/dcache.h>

#include "kguard.h"

/* ── Original function pointers ────────────────────────────── */

static int (*orig_show_vfsmnt)(struct seq_file *m, struct vfsmount *mnt);
static int (*orig_show_mountinfo)(struct seq_file *m, struct vfsmount *mnt);

/* ── Helper: extract mount info for filtering ──────────────── */

static bool should_hide_mount(struct vfsmount *mnt)
{
	struct super_block *sb;
	const char *fstype;
	char pathbuf[256];
	const char *devname;
	char mntpoint_buf[256];
	const char *mntpoint;
	struct path mnt_path;

	if (!mnt)
		return false;

	sb = mnt->mnt_sb;
	if (!sb || !sb->s_type)
		return false;

	fstype = sb->s_type->name;
	devname = mnt->mnt_sb->s_id;

	/* Get mountpoint path */
	mnt_path.mnt = mnt;
	mnt_path.dentry = mnt->mnt_root;
	mntpoint = d_path(&mnt_path, mntpoint_buf, sizeof(mntpoint_buf));
	if (IS_ERR(mntpoint))
		mntpoint = "";

	return kguard_filter_match_mount(devname, mntpoint, fstype);
}

/* ── Replacement for show_vfsmnt (/proc/pid/mounts) ────────── */

static int kguard_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt)
{
	pid_t tgid = current->tgid;

	rcu_read_lock();
	if (!kguard_pid_has_flag(tgid, KGUARD_POLICY_HIDE_MOUNTS)) {
		rcu_read_unlock();
		return orig_show_vfsmnt(m, mnt);
	}
	rcu_read_unlock();

	if (should_hide_mount(mnt))
		return 0; /* Skip this mount entry */

	return orig_show_vfsmnt(m, mnt);
}

/* ── Replacement for show_mountinfo (/proc/pid/mountinfo) ──── */

static int kguard_show_mountinfo(struct seq_file *m, struct vfsmount *mnt)
{
	pid_t tgid = current->tgid;

	rcu_read_lock();
	if (!kguard_pid_has_flag(tgid, KGUARD_POLICY_HIDE_MOUNTS)) {
		rcu_read_unlock();
		return orig_show_mountinfo(m, mnt);
	}
	rcu_read_unlock();

	if (should_hide_mount(mnt))
		return 0;

	return orig_show_mountinfo(m, mnt);
}

/* ── Hook definitions ──────────────────────────────────────── */

static struct kguard_hook mounts_hook = {
	.name     = "show_vfsmnt",
	.function = kguard_show_vfsmnt,
	.original = &orig_show_vfsmnt,
};

static struct kguard_hook mountinfo_hook = {
	.name     = "show_mountinfo",
	.function = kguard_show_mountinfo,
	.original = &orig_show_mountinfo,
};

int kguard_procfs_mounts_init(void)
{
	int ret;

	ret = kguard_hook_install(&mounts_hook);
	if (ret)
		return ret;

	ret = kguard_hook_install(&mountinfo_hook);
	if (ret) {
		kguard_hook_remove(&mounts_hook);
		return ret;
	}

	kg_info("procfs mounts hooks active\n");
	return 0;
}

void kguard_procfs_mounts_exit(void)
{
	kguard_hook_remove(&mountinfo_hook);
	kguard_hook_remove(&mounts_hook);
	kg_info("procfs mounts hooks removed\n");
}

// SPDX-License-Identifier: GPL-2.0
/*
 * kguard_procfs_maps.c — Hook show_map_vma to filter /proc/pid/maps
 *
 * When a registered PID reads /proc/self/maps or /proc/self/smaps,
 * we intercept the seq_file show callback and skip VMAs whose path
 * or anonymous name matches our filter keywords.
 */
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>

#include "kguard.h"

/* ── Original function pointers (filled by ftrace install) ── */

static int (*orig_show_map_vma)(struct seq_file *m,
				struct vm_area_struct *vma, int is_pid);
static int (*orig_show_smap)(struct seq_file *m, void *v);

/* ── Helper: extract file path from VMA ────────────────────── */

static const char *kguard_vma_path(struct vm_area_struct *vma,
				    char *buf, int bufsize)
{
	struct file *file = vma->vm_file;

	if (!file)
		return NULL;

	return d_path(&file->f_path, buf, bufsize);
}

/* ── Helper: get anonymous VMA name ────────────────────────── */

static const char *kguard_vma_anon_name(struct vm_area_struct *vma)
{
	/*
	 * On kernel 5.15 with CONFIG_ANON_VMA_NAME, the anon name is
	 * accessible via vma->anon_name or anon_vma_name(vma).
	 * If not configured, we return NULL.
	 */
#ifdef CONFIG_ANON_VMA_NAME
	struct anon_vma_name *name = vma->anon_name;

	if (name)
		return name->name;
#endif
	return NULL;
}

/* ── Replacement for show_map_vma ──────────────────────────── */

static int kguard_show_map_vma(struct seq_file *m,
			       struct vm_area_struct *vma, int is_pid)
{
	pid_t tgid;
	char pathbuf[256];
	const char *path;
	const char *anon_name;

	/* Only filter for registered PIDs */
	tgid = current->tgid;

	rcu_read_lock();
	if (!kguard_pid_lookup(tgid)) {
		rcu_read_unlock();
		return orig_show_map_vma(m, vma, is_pid);
	}

	if (!kguard_pid_has_flag(tgid, KGUARD_POLICY_HIDE_MAPS)) {
		rcu_read_unlock();
		return orig_show_map_vma(m, vma, is_pid);
	}
	rcu_read_unlock();

	/* Get path and anon_name for this VMA */
	path = kguard_vma_path(vma, pathbuf, sizeof(pathbuf));
	anon_name = kguard_vma_anon_name(vma);

	/* Check against filter rules */
	if (kguard_filter_match_maps(path, anon_name)) {
		/* Skip this VMA — output nothing */
		kg_dbg("hiding VMA %lx-%lx path=%s anon=%s pid=%d\n",
		       vma->vm_start, vma->vm_end,
		       path ? path : "(none)",
		       anon_name ? anon_name : "(none)",
		       tgid);
		return 0;
	}

	/* Not filtered — call original */
	return orig_show_map_vma(m, vma, is_pid);
}

/* ── Hook definitions ──────────────────────────────────────── */

static struct kguard_hook maps_hook = {
	.name     = "show_map_vma",
	.function = kguard_show_map_vma,
	.original = &orig_show_map_vma,
};

int kguard_procfs_maps_init(void)
{
	int ret;

	ret = kguard_hook_install(&maps_hook);
	if (ret)
		return ret;

	kg_info("procfs maps hook active\n");
	return 0;
}

void kguard_procfs_maps_exit(void)
{
	kguard_hook_remove(&maps_hook);
	kg_info("procfs maps hook removed\n");
}

// SPDX-License-Identifier: GPL-2.0
/*
 * kguard_filter.c — Filter rule engine
 *
 * Manages three lists of keyword-based filter rules for hiding
 * entries in /proc/pid/maps, /proc/pid/mountinfo, and file paths.
 */
#include <linux/slab.h>
#include <linux/string.h>

#include "kguard.h"

static LIST_HEAD(map_filter_list);
static LIST_HEAD(mnt_filter_list);
static LIST_HEAD(path_filter_list);
static DEFINE_RWLOCK(filter_lock);

/* Default filter keywords loaded at init */
static const char *default_map_filters[] = {
	"magisk", "zygisk", "riru", "edxposed", "lsposed", "xposed",
	"frida", "substrate", "dobby", "libgadget", "linjector",
	"xhook", "sandhook", "whale", "pine",
	"keymint_soft", "triquestokeymint", "playintegrityfix",
	"playcurl", "keybox", "shamiko",
	NULL
};

static const char *default_mnt_filters[] = {
	"magisk", "triquestokeymint", "playintegrityfix",
	"overlay", /* combined with mountpoint check */
	NULL
};

static const char *default_path_filters[] = {
	"/data/adb/modules",
	"/data/adb/magisk",
	"/data/adb/ksu",
	"/data/adb/ap",
	"keybox.xml",
	"keybox.json",
	"/sbin/su",
	"/system/bin/su",
	"/system/xbin/su",
	NULL
};

static struct list_head *get_list(u32 type)
{
	switch (type) {
	case KGUARD_FILTER_MAP:  return &map_filter_list;
	case KGUARD_FILTER_MNT:  return &mnt_filter_list;
	case KGUARD_FILTER_PATH: return &path_filter_list;
	default: return NULL;
	}
}

int kguard_filter_add(u32 type, const char *keyword)
{
	struct kguard_filter_rule_entry *entry;
	struct list_head *list = get_list(type);

	if (!list || !keyword || keyword[0] == '\0')
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	strscpy(entry->keyword, keyword, sizeof(entry->keyword));
	entry->type = type;

	write_lock(&filter_lock);
	list_add_tail_rcu(&entry->list, list);
	write_unlock(&filter_lock);

	kg_dbg("added filter type=%u keyword='%s'\n", type, keyword);
	return 0;
}

static void kguard_filter_rcu_free(struct rcu_head *head)
{
	struct kguard_filter_rule_entry *entry =
		container_of(head, struct kguard_filter_rule_entry, rcu);
	kfree(entry);
}

int kguard_filter_remove(u32 type, const char *keyword)
{
	struct kguard_filter_rule_entry *entry;
	struct list_head *list = get_list(type);

	if (!list)
		return -EINVAL;

	write_lock(&filter_lock);
	list_for_each_entry(entry, list, list) {
		if (entry->type == type &&
		    strcmp(entry->keyword, keyword) == 0) {
			list_del_rcu(&entry->list);
			write_unlock(&filter_lock);
			call_rcu(&entry->rcu, kguard_filter_rcu_free);
			return 0;
		}
	}
	write_unlock(&filter_lock);

	return -ENOENT;
}

void kguard_filter_clear(u32 type)
{
	struct kguard_filter_rule_entry *entry, *tmp;
	struct list_head *list = get_list(type);

	if (!list)
		return;

	write_lock(&filter_lock);
	list_for_each_entry_safe(entry, tmp, list, list) {
		list_del_rcu(&entry->list);
		call_rcu(&entry->rcu, kguard_filter_rcu_free);
	}
	write_unlock(&filter_lock);
}

/*
 * Case-insensitive substring search in haystack for needle.
 */
static bool kguard_strstri(const char *haystack, const char *needle)
{
	size_t hlen, nlen, i;

	if (!haystack || !needle)
		return false;

	hlen = strlen(haystack);
	nlen = strlen(needle);

	if (nlen > hlen)
		return false;

	for (i = 0; i <= hlen - nlen; i++) {
		if (strncasecmp(haystack + i, needle, nlen) == 0)
			return true;
	}
	return false;
}

bool kguard_filter_match_maps(const char *path, const char *anon_name)
{
	struct kguard_filter_rule_entry *entry;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &map_filter_list, list) {
		if (path && kguard_strstri(path, entry->keyword)) {
			rcu_read_unlock();
			return true;
		}
		if (anon_name && kguard_strstri(anon_name, entry->keyword)) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();

	return false;
}

bool kguard_filter_match_mount(const char *source, const char *mountpoint,
			       const char *fstype)
{
	struct kguard_filter_rule_entry *entry;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &mnt_filter_list, list) {
		if (source && kguard_strstri(source, entry->keyword)) {
			rcu_read_unlock();
			return true;
		}
		if (mountpoint && kguard_strstri(mountpoint, entry->keyword)) {
			rcu_read_unlock();
			return true;
		}
		/* Check for overlay/tmpfs on system partitions */
		if (fstype && strcmp(fstype, "overlay") == 0 &&
		    mountpoint &&
		    (strncmp(mountpoint, "/system", 7) == 0 ||
		     strncmp(mountpoint, "/vendor", 7) == 0 ||
		     strncmp(mountpoint, "/product", 8) == 0)) {
			rcu_read_unlock();
			return true;
		}
		if (fstype && strcmp(fstype, "tmpfs") == 0 &&
		    mountpoint &&
		    strncmp(mountpoint, "/system", 7) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();

	return false;
}

bool kguard_filter_match_path(const char *path)
{
	struct kguard_filter_rule_entry *entry;

	if (!path)
		return false;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &path_filter_list, list) {
		/* Check prefix match or substring match */
		if (strncmp(path, entry->keyword, strlen(entry->keyword)) == 0 ||
		    kguard_strstri(path, entry->keyword)) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();

	return false;
}

int kguard_filter_count(u32 type)
{
	struct kguard_filter_rule_entry *entry;
	struct list_head *list = get_list(type);
	int count = 0;

	if (!list)
		return 0;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, list, list)
		count++;
	rcu_read_unlock();

	return count;
}

int kguard_filter_init(void)
{
	int i;

	for (i = 0; default_map_filters[i]; i++)
		kguard_filter_add(KGUARD_FILTER_MAP, default_map_filters[i]);

	for (i = 0; default_mnt_filters[i]; i++)
		kguard_filter_add(KGUARD_FILTER_MNT, default_mnt_filters[i]);

	for (i = 0; default_path_filters[i]; i++)
		kguard_filter_add(KGUARD_FILTER_PATH, default_path_filters[i]);

	kg_info("filter engine ready: %d map, %d mnt, %d path rules\n",
		kguard_filter_count(KGUARD_FILTER_MAP),
		kguard_filter_count(KGUARD_FILTER_MNT),
		kguard_filter_count(KGUARD_FILTER_PATH));
	return 0;
}

void kguard_filter_exit(void)
{
	kguard_filter_clear(KGUARD_FILTER_MAP);
	kguard_filter_clear(KGUARD_FILTER_MNT);
	kguard_filter_clear(KGUARD_FILTER_PATH);
	synchronize_rcu();
	kg_info("filter engine cleaned up\n");
}

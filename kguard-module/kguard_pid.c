// SPDX-License-Identifier: GPL-2.0
/*
 * kguard_pid.c — PID registration hash table with RCU
 */
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/sched.h>

#include "kguard.h"

#define PID_HASH_BITS 8  /* 256 buckets */

static DEFINE_HASHTABLE(pid_table, PID_HASH_BITS);
static DEFINE_SPINLOCK(pid_lock);
static atomic_t pid_count = ATOMIC_INIT(0);

int kguard_pid_init(void)
{
	hash_init(pid_table);
	kg_info("pid manager ready (hash bits=%d)\n", PID_HASH_BITS);
	return 0;
}

static void kguard_pid_rcu_free(struct rcu_head *head)
{
	struct kguard_pid_entry *entry =
		container_of(head, struct kguard_pid_entry, rcu);
	kfree(entry);
}

int kguard_pid_register(pid_t pid, u32 flags)
{
	struct kguard_pid_entry *entry;

	if (atomic_read(&pid_count) >= kguard_max_pids)
		return -ENOSPC;

	/* Check if already registered */
	rcu_read_lock();
	hash_for_each_possible_rcu(pid_table, entry, node, pid) {
		if (entry->pid == pid) {
			/* Update flags */
			entry->policy_flags = flags;
			rcu_read_unlock();
			return 0;
		}
	}
	rcu_read_unlock();

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->pid = pid;
	entry->policy_flags = flags;
	entry->registered_at = ktime_get();

	spin_lock(&pid_lock);
	hash_add_rcu(pid_table, &entry->node, pid);
	spin_unlock(&pid_lock);

	atomic_inc(&pid_count);
	return 0;
}

int kguard_pid_unregister(pid_t pid)
{
	struct kguard_pid_entry *entry;

	spin_lock(&pid_lock);
	hash_for_each_possible_rcu(pid_table, entry, node, pid) {
		if (entry->pid == pid) {
			hash_del_rcu(&entry->node);
			spin_unlock(&pid_lock);
			call_rcu(&entry->rcu, kguard_pid_rcu_free);
			atomic_dec(&pid_count);
			return 0;
		}
	}
	spin_unlock(&pid_lock);

	return -ESRCH;
}

struct kguard_pid_entry *kguard_pid_lookup(pid_t pid)
{
	struct kguard_pid_entry *entry;

	/* Must be called under rcu_read_lock() */
	hash_for_each_possible_rcu(pid_table, entry, node, pid) {
		if (entry->pid == pid)
			return entry;
	}
	return NULL;
}

bool kguard_pid_has_flag(pid_t pid, u32 flag)
{
	struct kguard_pid_entry *entry;
	bool result = false;

	rcu_read_lock();
	entry = kguard_pid_lookup(pid);
	if (entry)
		result = (entry->policy_flags & flag) != 0;
	rcu_read_unlock();

	return result;
}

int kguard_pid_count(void)
{
	return atomic_read(&pid_count);
}

/* Remove entries for PIDs that no longer exist */
void kguard_pid_cleanup_dead(void)
{
	struct kguard_pid_entry *entry;
	struct hlist_node *tmp;
	int bkt, cleaned = 0;

	spin_lock(&pid_lock);
	hash_for_each_safe(pid_table, bkt, tmp, entry, node) {
		struct pid *kpid = find_get_pid(entry->pid);

		if (!kpid) {
			hash_del_rcu(&entry->node);
			call_rcu(&entry->rcu, kguard_pid_rcu_free);
			atomic_dec(&pid_count);
			cleaned++;
		} else {
			put_pid(kpid);
		}
	}
	spin_unlock(&pid_lock);

	if (cleaned > 0)
		kg_info("cleaned %d dead PIDs\n", cleaned);
}

void kguard_pid_exit(void)
{
	struct kguard_pid_entry *entry;
	struct hlist_node *tmp;
	int bkt;

	spin_lock(&pid_lock);
	hash_for_each_safe(pid_table, bkt, tmp, entry, node) {
		hash_del_rcu(&entry->node);
		call_rcu(&entry->rcu, kguard_pid_rcu_free);
	}
	spin_unlock(&pid_lock);

	synchronize_rcu();
	atomic_set(&pid_count, 0);
	kg_info("pid manager cleaned up\n");
}

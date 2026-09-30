// SPDX-License-Identifier: GPL-2.0
/*
 * kguard_ftrace.c — ftrace-based function hooking framework
 *
 * Uses ftrace to redirect kernel functions, which is safe under
 * CONFIG_CFI_CLANG=y (unlike direct function pointer patching).
 *
 * On kernel 5.15, kallsyms_lookup_name is not exported, so we use
 * the kprobe trick: register a kprobe on the target symbol to get
 * its address, then immediately unregister the kprobe.
 */
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/slab.h>

#include "kguard.h"

/* ── Symbol resolution via kprobe trick ────────────── */

static unsigned long kguard_lookup_name(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long addr;
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		kg_err("kprobe lookup failed for %s: %d\n", name, ret);
		return 0;
	}

	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);

	kg_dbg("resolved %s @ 0x%lx\n", name, addr);
	return addr;
}

/* ── ftrace callback ───────────────────────────────── */

/*
 * This callback fires when the hooked function is called.
 * We modify the instruction pointer (regs->pc on ARM64) to
 * redirect execution to our replacement function.
 */
static void notrace kguard_ftrace_callback(unsigned long ip,
					    unsigned long parent_ip,
					    struct ftrace_ops *ops,
					    struct ftrace_regs *fregs)
{
	struct kguard_hook *hook =
		container_of(ops, struct kguard_hook, ops);
	struct pt_regs *regs = ftrace_get_regs(fregs);

	if (!regs)
		return;

	/* Prevent recursion: if we're already inside our replacement,
	 * don't redirect again.  Check by comparing parent_ip. */
	if (!within_module(parent_ip, THIS_MODULE))
		regs->pc = (unsigned long)hook->function;
}

/* ── Public API ────────────────────────────────────── */

int kguard_hook_install(struct kguard_hook *hook)
{
	int ret;

	hook->address = kguard_lookup_name(hook->name);
	if (!hook->address) {
		kg_err("cannot resolve symbol: %s\n", hook->name);
		return -ENOENT;
	}

	/* Save original function pointer for calling from replacement */
	*((unsigned long *)hook->original) = hook->address;

	hook->ops.func = kguard_ftrace_callback;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS |
			  FTRACE_OPS_FL_RECURSION |
			  FTRACE_OPS_FL_IPMODIFY;

	ret = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (ret) {
		kg_err("ftrace_set_filter_ip failed for %s: %d\n",
		       hook->name, ret);
		return ret;
	}

	ret = register_ftrace_function(&hook->ops);
	if (ret) {
		kg_err("register_ftrace_function failed for %s: %d\n",
		       hook->name, ret);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return ret;
	}

	hook->active = true;
	kg_info("hooked %s @ 0x%lx\n", hook->name, hook->address);
	return 0;
}

void kguard_hook_remove(struct kguard_hook *hook)
{
	if (!hook->active)
		return;

	unregister_ftrace_function(&hook->ops);
	ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);

	hook->active = false;
	kg_info("unhooked %s\n", hook->name);
}

int kguard_ftrace_init(void)
{
	kg_info("ftrace subsystem ready\n");
	return 0;
}

void kguard_ftrace_exit(void)
{
	kg_info("ftrace subsystem cleaned up\n");
}

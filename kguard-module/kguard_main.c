// SPDX-License-Identifier: GPL-2.0
/*
 * kguard_main.c — Module entry point, char device, ioctl dispatcher
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include "kguard.h"

/* Module parameters */
int  kguard_max_pids = 256;
bool kguard_debug = false;

module_param(kguard_max_pids, int, 0644);
MODULE_PARM_DESC(kguard_max_pids, "Maximum number of registered PIDs");
module_param(kguard_debug, bool, 0644);
MODULE_PARM_DESC(kguard_debug, "Enable debug logging");

/* ── ioctl handler ─────────────────────────────────── */

static long kguard_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	switch (cmd) {
	case KGUARD_REGISTER_PID: {
		struct kguard_pid_config cfg;

		if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
			return -EFAULT;
		ret = kguard_pid_register(cfg.pid, cfg.policy_flags);
		if (ret == 0)
			kg_info("registered pid %d flags=0x%x\n",
				cfg.pid, cfg.policy_flags);
		break;
	}
	case KGUARD_UNREGISTER_PID: {
		__s32 pid;

		if (copy_from_user(&pid, (void __user *)arg, sizeof(pid)))
			return -EFAULT;
		ret = kguard_pid_unregister(pid);
		if (ret == 0)
			kg_info("unregistered pid %d\n", pid);
		break;
	}
	case KGUARD_REGISTER_HAL_PID: {
		__s32 pid;

		if (copy_from_user(&pid, (void __user *)arg, sizeof(pid)))
			return -EFAULT;
		/* HAL process gets full hiding policy */
		ret = kguard_pid_register(pid, KGUARD_POLICY_HIDE_MAPS |
					       KGUARD_POLICY_HIDE_HAL);
		if (ret == 0)
			kg_info("registered HAL pid %d\n", pid);
		break;
	}
	case KGUARD_ADD_FILTER: {
		struct kguard_filter_rule rule;

		if (copy_from_user(&rule, (void __user *)arg, sizeof(rule)))
			return -EFAULT;
		rule.keyword[sizeof(rule.keyword) - 1] = '\0';
		ret = kguard_filter_add(rule.type, rule.keyword);
		break;
	}
	case KGUARD_DEL_FILTER: {
		struct kguard_filter_rule rule;

		if (copy_from_user(&rule, (void __user *)arg, sizeof(rule)))
			return -EFAULT;
		rule.keyword[sizeof(rule.keyword) - 1] = '\0';
		ret = kguard_filter_remove(rule.type, rule.keyword);
		break;
	}
	case KGUARD_CLEAR_FILTERS:
		kguard_filter_clear(KGUARD_FILTER_MAP);
		kguard_filter_clear(KGUARD_FILTER_MNT);
		kguard_filter_clear(KGUARD_FILTER_PATH);
		break;
	case KGUARD_GET_STATUS: {
		struct kguard_status status = {
			.version        = KGUARD_VERSION,
			.registered_pids = kguard_pid_count(),
			.map_filters    = kguard_filter_count(KGUARD_FILTER_MAP),
			.mnt_filters    = kguard_filter_count(KGUARD_FILTER_MNT),
			.path_filters   = kguard_filter_count(KGUARD_FILTER_PATH),
			.hooks_active   = 1,
		};

		if (copy_to_user((void __user *)arg, &status, sizeof(status)))
			return -EFAULT;
		break;
	}
	default:
		ret = -ENOTTY;
	}

	return ret;
}

static int kguard_open(struct inode *inode, struct file *filp)
{
	/* Only root can interact with kguard */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

static const struct file_operations kguard_fops = {
	.owner          = THIS_MODULE,
	.open           = kguard_open,
	.unlocked_ioctl = kguard_ioctl,
	.compat_ioctl   = kguard_ioctl,
};

static struct miscdevice kguard_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = KGUARD_DEVICE_NAME,
	.fops  = &kguard_fops,
	.mode  = 0660,
};

/* ── Module init / exit ────────────────────────────── */

static int __init kguard_init(void)
{
	int ret;

	kg_info("initializing v%d.%d.%d (max_pids=%d)\n",
		(KGUARD_VERSION >> 16) & 0xFF,
		(KGUARD_VERSION >> 8) & 0xFF,
		KGUARD_VERSION & 0xFF,
		kguard_max_pids);

	ret = kguard_pid_init();
	if (ret) {
		kg_err("pid init failed: %d\n", ret);
		return ret;
	}

	ret = kguard_filter_init();
	if (ret) {
		kg_err("filter init failed: %d\n", ret);
		goto err_filter;
	}

	ret = kguard_ftrace_init();
	if (ret) {
		kg_err("ftrace init failed: %d\n", ret);
		goto err_ftrace;
	}

	ret = kguard_procfs_maps_init();
	if (ret) {
		kg_err("procfs maps hook failed: %d\n", ret);
		goto err_maps;
	}

	ret = kguard_procfs_mounts_init();
	if (ret) {
		kg_err("procfs mounts hook failed: %d\n", ret);
		goto err_mounts;
	}

	ret = kguard_file_hide_init();
	if (ret) {
		kg_err("file hide init failed: %d\n", ret);
		goto err_file;
	}

	ret = misc_register(&kguard_misc);
	if (ret) {
		kg_err("misc register failed: %d\n", ret);
		goto err_misc;
	}

	kg_info("initialized successfully, device at /dev/%s\n",
		KGUARD_DEVICE_NAME);
	return 0;

err_misc:
	kguard_file_hide_exit();
err_file:
	kguard_procfs_mounts_exit();
err_mounts:
	kguard_procfs_maps_exit();
err_maps:
	kguard_ftrace_exit();
err_ftrace:
	kguard_filter_exit();
err_filter:
	kguard_pid_exit();
	return ret;
}

static void __exit kguard_exit(void)
{
	misc_deregister(&kguard_misc);
	kguard_file_hide_exit();
	kguard_procfs_mounts_exit();
	kguard_procfs_maps_exit();
	kguard_ftrace_exit();
	kguard_filter_exit();
	kguard_pid_exit();
	kg_info("unloaded\n");
}

module_init(kguard_init);
module_exit(kguard_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kguard-project");
MODULE_DESCRIPTION("Process isolation and procfs virtualization for Android");
MODULE_VERSION("1.0.0");

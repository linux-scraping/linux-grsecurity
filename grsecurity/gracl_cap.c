#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/gracl.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

static const char *captab_log[] = {
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE",
	"CAP_NET_BROADCAST",
	"CAP_NET_ADMIN",
	"CAP_NET_RAW",
	"CAP_IPC_LOCK",
	"CAP_IPC_OWNER",
	"CAP_SYS_MODULE",
	"CAP_SYS_RAWIO",
	"CAP_SYS_CHROOT",
	"CAP_SYS_PTRACE",
	"CAP_SYS_PACCT",
	"CAP_SYS_ADMIN",
	"CAP_SYS_BOOT",
	"CAP_SYS_NICE",
	"CAP_SYS_RESOURCE",
	"CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG",
	"CAP_MKNOD",
	"CAP_LEASE",
	"CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL",
	"CAP_SETFCAP",
	"CAP_MAC_OVERRIDE",
	"CAP_MAC_ADMIN",
	"CAP_SYSLOG"
};

EXPORT_SYMBOL(gr_is_capable);
EXPORT_SYMBOL(gr_is_capable_nolog);

int
gr_is_capable(const int cap)
{
	struct task_struct *task = current;
	const struct cred *cred = current_cred();
	struct acl_subject_label *curracl;
	kernel_cap_t cap_drop = __cap_empty_set, cap_mask = __cap_empty_set;
	kernel_cap_t cap_audit = __cap_empty_set;

	if (!gr_acl_is_enabled())
		return 1;

	curracl = task->acl;

	cap_drop = curracl->cap_lower;
	cap_mask = curracl->cap_mask;
	cap_audit = curracl->cap_invert_audit;

	while ((curracl = curracl->parent_subject)) {
		/* if the cap isn't specified in the current computed mask but is specified in the
		   current level subject, and is lowered in the current level subject, then add
		   it to the set of dropped capabilities
		   otherwise, add the current level subject's mask to the current computed mask
		 */
		if (!cap_raised(cap_mask, cap) && cap_raised(curracl->cap_mask, cap)) {
			cap_raise(cap_mask, cap);
			if (cap_raised(curracl->cap_lower, cap))
				cap_raise(cap_drop, cap);
			if (cap_raised(curracl->cap_invert_audit, cap))
				cap_raise(cap_audit, cap);
		}
	}

	if (!cap_raised(cap_drop, cap)) {
		if (cap_raised(cap_audit, cap))
			gr_log_cap(GR_DO_AUDIT, GR_CAP_ACL_MSG2, task, captab_log[cap]);
		return 1;
	}

	curracl = task->acl;

	if ((curracl->mode & (GR_LEARN | GR_INHERITLEARN))
	    && cap_raised(cred->cap_effective, cap)) {
		security_learn(GR_LEARN_AUDIT_MSG, task->role->rolename,
			       task->role->roletype, cred->uid,
			       cred->gid, task->exec_file ?
			       gr_to_filename(task->exec_file->f_path.dentry,
			       task->exec_file->f_path.mnt) : curracl->filename,
			       curracl->filename, 0UL,
			       0UL, "", (unsigned long) cap, &task->signal->saved_ip);
		return 1;
	}

	if ((cap >= 0) && (cap < (sizeof(captab_log)/sizeof(captab_log[0]))) && cap_raised(cred->cap_effective, cap) && !cap_raised(cap_audit, cap))
		gr_log_cap(GR_DONT_AUDIT, GR_CAP_ACL_MSG, task, captab_log[cap]);
	return 0;
}

int
gr_is_capable_nolog(const int cap)
{
	struct acl_subject_label *curracl;
	kernel_cap_t cap_drop = __cap_empty_set, cap_mask = __cap_empty_set;

	if (!gr_acl_is_enabled())
		return 1;

	curracl = current->acl;

	cap_drop = curracl->cap_lower;
	cap_mask = curracl->cap_mask;

	while ((curracl = curracl->parent_subject)) {
		/* if the cap isn't specified in the current computed mask but is specified in the
		   current level subject, and is lowered in the current level subject, then add
		   it to the set of dropped capabilities
		   otherwise, add the current level subject's mask to the current computed mask
		 */
		if (!cap_raised(cap_mask, cap) && cap_raised(curracl->cap_mask, cap)) {
			cap_raise(cap_mask, cap);
			if (cap_raised(curracl->cap_lower, cap))
				cap_raise(cap_drop, cap);
		}
	}

	if (!cap_raised(cap_drop, cap))
		return 1;

	return 0;
}


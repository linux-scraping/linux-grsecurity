#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/gracl.h>
#include <linux/grinternal.h>

static const char *restab_log[] = {
	[RLIMIT_CPU] = "RLIMIT_CPU",
	[RLIMIT_FSIZE] = "RLIMIT_FSIZE",
	[RLIMIT_DATA] = "RLIMIT_DATA",
	[RLIMIT_STACK] = "RLIMIT_STACK",
	[RLIMIT_CORE] = "RLIMIT_CORE",
	[RLIMIT_RSS] = "RLIMIT_RSS",
	[RLIMIT_NPROC] = "RLIMIT_NPROC",
	[RLIMIT_NOFILE] = "RLIMIT_NOFILE",
	[RLIMIT_MEMLOCK] = "RLIMIT_MEMLOCK",
	[RLIMIT_AS] = "RLIMIT_AS",
	[RLIMIT_LOCKS] = "RLIMIT_LOCKS",
	[RLIMIT_SIGPENDING] = "RLIMIT_SIGPENDING",
	[RLIMIT_MSGQUEUE] = "RLIMIT_MSGQUEUE",
	[RLIMIT_NICE] = "RLIMIT_NICE",
	[RLIMIT_RTPRIO] = "RLIMIT_RTPRIO",
	[RLIMIT_RTTIME] = "RLIMIT_RTTIME",
	[GR_CRASH_RES] = "RLIMIT_CRASH"
};

void
gr_log_resource(const struct task_struct *task,
		const int res, const unsigned long wanted, const int gt)
{
	const struct cred *cred = __task_cred(task);

	if (res == RLIMIT_NPROC && 
	    (cap_raised(cred->cap_effective, CAP_SYS_ADMIN) || 
	     cap_raised(cred->cap_effective, CAP_SYS_RESOURCE)))
		return;
	else if (res == RLIMIT_MEMLOCK &&
		 cap_raised(cred->cap_effective, CAP_IPC_LOCK))
		return;
	else if (res == RLIMIT_NICE && cap_raised(cred->cap_effective, CAP_SYS_NICE))
		return;

	if (!gr_acl_is_enabled() && !grsec_resource_logging)
		return;

	// not yet supported resource
	if (!restab_log[res])
		return;

	preempt_disable();

	if (unlikely(((gt && wanted > task->signal->rlim[res].rlim_cur) ||
		      (!gt && wanted >= task->signal->rlim[res].rlim_cur)) &&
		     task->signal->rlim[res].rlim_cur != RLIM_INFINITY))
		gr_log_res_ulong2_str(GR_DONT_AUDIT, GR_RESOURCE_MSG, task, wanted, restab_log[res], task->signal->rlim[res].rlim_cur);
	preempt_enable_no_resched();

	return;
}

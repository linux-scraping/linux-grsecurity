#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/grinternal.h>
#include <linux/grsecurity.h>

void
gr_audit_ptrace(struct task_struct *task)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_PTRACE
	if (grsec_enable_audit_ptrace)
		gr_log_ptrace(GR_DO_AUDIT, GR_PTRACE_AUDIT_MSG, task);
#endif
	return;
}

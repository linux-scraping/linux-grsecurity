#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

void
gr_log_signal(const int sig, const struct task_struct *t)
{
#ifdef CONFIG_GRKERNSEC_SIGNAL
	if (grsec_enable_signal && ((sig == SIGSEGV) || (sig == SIGILL) ||
				    (sig == SIGABRT) || (sig == SIGBUS))) {
		if (t->pid == current->pid) {
			gr_log_int(GR_DONT_AUDIT_GOOD, GR_UNISIGLOG_MSG, sig);
		} else {
			gr_log_sig(GR_DONT_AUDIT_GOOD, GR_DUALSIGLOG_MSG, t, sig);
		}
	}
#endif
	return;
}

int
gr_handle_signal(const struct task_struct *p, const int sig)
{
#ifdef CONFIG_GRKERNSEC
	if (current->pid > 1 && gr_check_protected_task(p)) {
		gr_log_sig(GR_DONT_AUDIT, GR_SIG_ACL_MSG, p, sig);
		return -EPERM;
	} else if (gr_pid_is_chrooted((struct task_struct *)p)) {
		return -EPERM;
	}
#endif
	return 0;
}

void gr_handle_brute_attach(struct task_struct *p)
{
#ifdef CONFIG_GRKERNSEC_BRUTE
	read_lock(&tasklist_lock);
	read_lock(&grsec_exec_file_lock);
	if (p->parent && p->parent->exec_file == p->exec_file)
		p->parent->brute = 1;
	read_unlock(&grsec_exec_file_lock);
	read_unlock(&tasklist_lock);
#endif
	return;
}

void gr_handle_brute_check(void)
{
#ifdef CONFIG_GRKERNSEC_BRUTE
	if (current->brute)
		msleep(30 * 1000);
#endif
	return;
}


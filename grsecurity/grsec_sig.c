#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>
#include <linux/hardirq.h>

char *signames[] = {
	[SIGSEGV] = "Segmentation fault",
	[SIGILL] = "Illegal instruction",
	[SIGABRT] = "Abort",
	[SIGBUS] = "Invalid alignment/Bus error"
};

void
gr_log_signal(const int sig, const void *addr, const struct task_struct *t)
{
#ifdef CONFIG_GRKERNSEC_SIGNAL
	if (grsec_enable_signal && ((sig == SIGSEGV) || (sig == SIGILL) ||
				    (sig == SIGABRT) || (sig == SIGBUS))) {
		if (t->pid == current->pid) {
			gr_log_sig_addr(GR_DONT_AUDIT_GOOD, GR_UNISIGLOG_MSG, signames[sig], addr);
		} else {
			gr_log_sig_task(GR_DONT_AUDIT_GOOD, GR_DUALSIGLOG_MSG, t, sig);
		}
	}
#endif
	return;
}

int
gr_handle_signal(const struct task_struct *p, const int sig)
{
#ifdef CONFIG_GRKERNSEC
	/* ignore the 0 signal for protected task checks */
	if (current->pid > 1 && sig && gr_check_protected_task(p)) {
		gr_log_sig_task(GR_DONT_AUDIT, GR_SIG_ACL_MSG, p, sig);
		return -EPERM;
	} else if (gr_pid_is_chrooted((struct task_struct *)p)) {
		return -EPERM;
	}
#endif
	return 0;
}

#ifdef CONFIG_GRKERNSEC
extern int specific_send_sig_info(int sig, struct siginfo *info, struct task_struct *t);

int gr_fake_force_sig(int sig, struct task_struct *t)
{
	unsigned long int flags;
	int ret, blocked, ignored;
	struct k_sigaction *action;

	spin_lock_irqsave(&t->sighand->siglock, flags);
	action = &t->sighand->action[sig-1];
	ignored = action->sa.sa_handler == SIG_IGN;
	blocked = sigismember(&t->blocked, sig);
	if (blocked || ignored) {
		action->sa.sa_handler = SIG_DFL;
		if (blocked) {
			sigdelset(&t->blocked, sig);
			recalc_sigpending_and_wake(t);
		}
	}
	if (action->sa.sa_handler == SIG_DFL)
		t->signal->flags &= ~SIGNAL_UNKILLABLE;
	ret = specific_send_sig_info(sig, SEND_SIG_PRIV, t);

	spin_unlock_irqrestore(&t->sighand->siglock, flags);

	return ret;
}
#endif

#ifdef CONFIG_GRKERNSEC_BRUTE
#define GR_USER_BAN_TIME (15 * 60)

static int __get_dumpable(unsigned long mm_flags)
{
	int ret;

	ret = mm_flags & MMF_DUMPABLE_MASK;
	return (ret >= 2) ? 2 : ret;
}
#endif

void gr_handle_brute_attach(struct task_struct *p, unsigned long mm_flags)
{
#ifdef CONFIG_GRKERNSEC_BRUTE
	kuid_t uid = GLOBAL_ROOT_UID;

	if (!grsec_enable_brute)
		return;

	rcu_read_lock();
	read_lock(&tasklist_lock);
	read_lock(&grsec_exec_file_lock);
	if (p->real_parent && p->real_parent->exec_file == p->exec_file)
		p->real_parent->brute = 1;
	else {
		const struct cred *cred = __task_cred(p), *cred2;
		struct task_struct *tsk, *tsk2;

		if (!__get_dumpable(mm_flags) && !uid_eq(cred->uid, GLOBAL_ROOT_UID)) {
			struct user_struct *user;

			uid = cred->uid;

			/* this is put upon execution past expiration */
			user = find_user(uid);
			if (user == NULL)
				goto unlock;
			user->banned = 1;
			user->ban_expires = get_seconds() + GR_USER_BAN_TIME;
			if (user->ban_expires == ~0UL)
				user->ban_expires--;

			do_each_thread(tsk2, tsk) {
				cred2 = __task_cred(tsk);
				if (tsk != p && uid_eq(cred2->uid, uid))
					gr_fake_force_sig(SIGKILL, tsk);
			} while_each_thread(tsk2, tsk);
		}
	}
unlock:
	read_unlock(&grsec_exec_file_lock);
	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	if (!uid_eq(uid, GLOBAL_ROOT_UID))
		printk(KERN_ALERT "grsec: bruteforce prevention initiated against uid %u, banning for %d minutes\n",
			from_kuid_munged(&init_user_ns, uid), GR_USER_BAN_TIME / 60);

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

void gr_handle_kernel_exploit(void)
{
#ifdef CONFIG_GRKERNSEC_KERN_LOCKOUT
	const struct cred *cred;
	struct task_struct *tsk, *tsk2;
	struct user_struct *user;
	kuid_t uid;

	if (in_irq() || in_serving_softirq() || in_nmi())
		panic("grsec: halting the system due to suspicious kernel crash caused in interrupt context");

	uid = current_uid();

	if (uid_eq(uid, GLOBAL_ROOT_UID))
		panic("grsec: halting the system due to suspicious kernel crash caused by root");
	else {
		/* kill all the processes of this user, hold a reference
		   to their creds struct, and prevent them from creating
		   another process until system reset
		*/
		printk(KERN_ALERT "grsec: banning user with uid %u until system restart for suspicious kernel crash\n",
			from_kuid_munged(&init_user_ns, uid));
		/* we intentionally leak this ref */
		user = get_uid(current->cred->user);
		if (user) {
			user->banned = 1;
			user->ban_expires = ~0UL;
		}

		read_lock(&tasklist_lock);
		do_each_thread(tsk2, tsk) {
			cred = __task_cred(tsk);
			if (uid_eq(cred->uid, uid))
				gr_fake_force_sig(SIGKILL, tsk);
		} while_each_thread(tsk2, tsk);
		read_unlock(&tasklist_lock); 
	}
#endif
}

int __gr_process_user_ban(struct user_struct *user)
{
#if defined(CONFIG_GRKERNSEC_KERN_LOCKOUT) || defined(CONFIG_GRKERNSEC_BRUTE)
	if (unlikely(user->banned)) {
		if (user->ban_expires != ~0UL && time_after_eq(get_seconds(), user->ban_expires)) {
			user->banned = 0;
			user->ban_expires = 0;
			free_uid(user);
		} else
			return -EPERM;
	}
#endif
	return 0;
}

int gr_process_user_ban(void)
{
#if defined(CONFIG_GRKERNSEC_KERN_LOCKOUT) || defined(CONFIG_GRKERNSEC_BRUTE)
	return __gr_process_user_ban(current->cred->user);
#endif
	return 0;
}

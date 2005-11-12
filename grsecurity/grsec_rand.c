#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

extern int pid_max;

int
gr_random_pid(void)
{
#ifdef CONFIG_GRKERNSEC_RANDPID
	int pid;

	if (grsec_enable_randpid && current->fs->root) {
		/* return a pid in the range 1 ... pid_max - 1
		   optimize this so we don't have to do a real division
		*/
		pid = 1 + (get_random_long() % pid_max);
		if (pid == pid_max)
			pid = pid_max - 1;
		return pid;
	}
#endif
	return 0;
}

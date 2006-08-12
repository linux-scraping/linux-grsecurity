#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>
#include <linux/errno.h>

void
gr_log_forkfail(const int retval)
{
#ifdef CONFIG_GRKERNSEC_FORKFAIL
	if (grsec_enable_forkfail && retval != -ERESTARTNOINTR)
		gr_log_int(GR_DONT_AUDIT, GR_FAILFORK_MSG, retval);
#endif
	return;
}

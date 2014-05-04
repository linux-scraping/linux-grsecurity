#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

int gr_proc_is_restricted(void)
{
#if defined(CONFIG_GRKERNSEC_PROC_USER) || defined(CONFIG_GRKERNSEC_PROC_USERGROUP)
	const struct cred *cred = current_cred();
#endif

#ifdef CONFIG_GRKERNSEC_PROC_USER
	if (cred->fsuid)
		return -EACCES;
#elif defined(CONFIG_GRKERNSEC_PROC_USERGROUP)
	if (cred->fsuid && !in_group_p(grsec_proc_gid))
		return -EACCES;
#endif
	return 0;
}

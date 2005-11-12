#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

void
gr_log_remount(const char *devname, const int retval)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_MOUNT
	if (grsec_enable_mount && (retval >= 0))
		gr_log_str(GR_DO_AUDIT, GR_REMOUNT_AUDIT_MSG, devname ? devname : "none");
#endif
	return;
}

void
gr_log_unmount(const char *devname, const int retval)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_MOUNT
	if (grsec_enable_mount && (retval >= 0))
		gr_log_str(GR_DO_AUDIT, GR_UNMOUNT_AUDIT_MSG, devname ? devname : "none");
#endif
	return;
}

void
gr_log_mount(const char *from, const char *to, const int retval)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_MOUNT
	if (grsec_enable_mount && (retval >= 0))
		gr_log_str_str(GR_DO_AUDIT, GR_MOUNT_AUDIT_MSG, from, to);
#endif
	return;
}

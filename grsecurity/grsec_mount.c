#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mount.h>
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
		gr_log_str_str(GR_DO_AUDIT, GR_MOUNT_AUDIT_MSG, from ? from : "none", to);
#endif
	return;
}

int
gr_handle_rofs_mount(struct dentry *dentry, struct vfsmount *mnt, int mnt_flags)
{
#ifdef CONFIG_GRKERNSEC_ROFS
	if (grsec_enable_rofs && !(mnt_flags & MNT_READONLY)) {
		gr_log_fs_generic(GR_DO_AUDIT, GR_ROFS_MOUNT_MSG, dentry, mnt);
		return -EPERM;
	} else
		return 0;
#endif
	return 0;
}

int
gr_handle_rofs_blockwrite(struct dentry *dentry, struct vfsmount *mnt, int acc_mode)
{
#ifdef CONFIG_GRKERNSEC_ROFS
	if (grsec_enable_rofs && (acc_mode & MAY_WRITE) &&
	    dentry->d_inode && S_ISBLK(dentry->d_inode->i_mode)) {
		gr_log_fs_generic(GR_DO_AUDIT, GR_ROFS_BLOCKWRITE_MSG, dentry, mnt);
		return -EPERM;
	} else
		return 0;
#endif
	return 0;
}

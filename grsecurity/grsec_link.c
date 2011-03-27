#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/grinternal.h>

int
gr_handle_follow_link(const struct inode *parent,
		      const struct inode *inode,
		      const struct dentry *dentry, const struct vfsmount *mnt)
{
#ifdef CONFIG_GRKERNSEC_LINK
	const struct cred *cred = current_cred();

	if (grsec_enable_link && S_ISLNK(inode->i_mode) &&
	    (parent->i_mode & S_ISVTX) && (parent->i_uid != inode->i_uid) &&
	    (parent->i_mode & S_IWOTH) && (cred->fsuid != inode->i_uid)) {
		gr_log_fs_int2(GR_DONT_AUDIT, GR_SYMLINK_MSG, dentry, mnt, inode->i_uid, inode->i_gid);
		return -EACCES;
	}
#endif
	return 0;
}

int
gr_handle_hardlink(const struct dentry *dentry,
		   const struct vfsmount *mnt,
		   struct inode *inode, const int mode, const char *to)
{
#ifdef CONFIG_GRKERNSEC_LINK
	const struct cred *cred = current_cred();

	if (grsec_enable_link && cred->fsuid != inode->i_uid &&
	    (!S_ISREG(mode) || (mode & S_ISUID) ||
	     ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) ||
	     (inode_permission(inode, MAY_READ | MAY_WRITE))) &&
	    !capable(CAP_FOWNER) && cred->uid) {
		gr_log_fs_int2_str(GR_DONT_AUDIT, GR_HARDLINK_MSG, dentry, mnt, inode->i_uid, inode->i_gid, to);
		return -EPERM;
	}
#endif
	return 0;
}

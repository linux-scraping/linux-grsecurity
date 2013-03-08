#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/grinternal.h>

int gr_handle_symlink_owner(const struct path *link, const struct inode *target)
{
#ifdef CONFIG_GRKERNSEC_SYMLINKOWN
	const struct inode *link_inode = link->dentry->d_inode;

	if (grsec_enable_symlinkown && in_group_p(grsec_symlinkown_gid) &&
	   /* ignore root-owned links, e.g. /proc/self */
	    gr_is_global_nonroot(link_inode->i_uid) && target &&
	    !uid_eq(link_inode->i_uid, target->i_uid)) {
		gr_log_fs_int2(GR_DONT_AUDIT, GR_SYMLINKOWNER_MSG, link->dentry, link->mnt, link_inode->i_uid, target->i_uid);
		return 1;
	}
#endif
	return 0;
}

int
gr_handle_follow_link(const struct inode *parent,
		      const struct inode *inode,
		      const struct dentry *dentry, const struct vfsmount *mnt)
{
#ifdef CONFIG_GRKERNSEC_LINK
	const struct cred *cred = current_cred();

	if (grsec_enable_link && S_ISLNK(inode->i_mode) &&
	    (parent->i_mode & S_ISVTX) && !uid_eq(parent->i_uid, inode->i_uid) &&
	    (parent->i_mode & S_IWOTH) && !uid_eq(cred->fsuid, inode->i_uid)) {
		gr_log_fs_int2(GR_DONT_AUDIT, GR_SYMLINK_MSG, dentry, mnt, inode->i_uid, inode->i_gid);
		return -EACCES;
	}
#endif
	return 0;
}

int
gr_handle_hardlink(const struct dentry *dentry,
		   const struct vfsmount *mnt,
		   struct inode *inode, const int mode, const struct filename *to)
{
#ifdef CONFIG_GRKERNSEC_LINK
	const struct cred *cred = current_cred();

	if (grsec_enable_link && !uid_eq(cred->fsuid, inode->i_uid) &&
	    (!S_ISREG(mode) || is_privileged_binary(dentry) || 
	     (inode_permission(inode, MAY_READ | MAY_WRITE))) &&
	    !capable(CAP_FOWNER) && gr_is_global_nonroot(cred->uid)) {
		gr_log_fs_int2_str(GR_DONT_AUDIT, GR_HARDLINK_MSG, dentry, mnt, inode->i_uid, inode->i_gid, to->name);
		return -EPERM;
	}
#endif
	return 0;
}

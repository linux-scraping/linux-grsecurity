#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/grinternal.h>

extern int gr_acl_tpe_check(void);

int
gr_tpe_allow(const struct file *file)
{
#ifdef CONFIG_GRKERNSEC
	struct inode *inode = file->f_path.dentry->d_parent->d_inode;
	const struct cred *cred = current_cred();

	if (cred->uid && ((grsec_enable_tpe &&
#ifdef CONFIG_GRKERNSEC_TPE_INVERT
	    ((grsec_enable_tpe_invert && !in_group_p(grsec_tpe_gid)) ||
	     (!grsec_enable_tpe_invert && in_group_p(grsec_tpe_gid)))
#else
	    in_group_p(grsec_tpe_gid)
#endif
	    ) || gr_acl_tpe_check()) &&
	    (inode->i_uid || (!inode->i_uid && ((inode->i_mode & S_IWGRP) ||
						(inode->i_mode & S_IWOTH))))) {
		gr_log_fs_generic(GR_DONT_AUDIT, GR_EXEC_TPE_MSG, file->f_path.dentry, file->f_path.mnt);
		return 0;
	}
#ifdef CONFIG_GRKERNSEC_TPE_ALL
	if (cred->uid && grsec_enable_tpe && grsec_enable_tpe_all &&
	    ((inode->i_uid && (inode->i_uid != cred->uid)) ||
	     (inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))) {
		gr_log_fs_generic(GR_DONT_AUDIT, GR_EXEC_TPE_MSG, file->f_path.dentry, file->f_path.mnt);
		return 0;
	}
#endif
#endif
	return 1;
}

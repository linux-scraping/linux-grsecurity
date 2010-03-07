#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/types.h>
#include <linux/pid_namespace.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

int
gr_handle_chroot_unix(const pid_t pid)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_UNIX
	struct pid *spid = NULL;

	if (unlikely(!grsec_enable_chroot_unix))
		return 1;

	if (likely(!proc_is_chrooted(current)))
		return 1;

	read_lock(&tasklist_lock);

	spid = find_vpid(pid);
	if (spid) {
		struct task_struct *p;
		p = pid_task(spid, PIDTYPE_PID);
		gr_fs_read_lock(p);
		if (unlikely(!have_same_root(current, p))) {
			gr_fs_read_unlock(p);
			read_unlock(&tasklist_lock);
			gr_log_noargs(GR_DONT_AUDIT, GR_UNIX_CHROOT_MSG);
			return 0;
		}
		gr_fs_read_unlock(p);
	}
	read_unlock(&tasklist_lock);
#endif
	return 1;
}

int
gr_handle_chroot_nice(void)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_NICE
	if (grsec_enable_chroot_nice && proc_is_chrooted(current)) {
		gr_log_noargs(GR_DONT_AUDIT, GR_NICE_CHROOT_MSG);
		return -EPERM;
	}
#endif
	return 0;
}

int
gr_handle_chroot_setpriority(struct task_struct *p, const int niceval)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_NICE
	if (grsec_enable_chroot_nice && (niceval < task_nice(p))
			&& proc_is_chrooted(current)) {
		gr_log_str_int(GR_DONT_AUDIT, GR_PRIORITY_CHROOT_MSG, p->comm, p->pid);
		return -EACCES;
	}
#endif
	return 0;
}

int
gr_handle_chroot_rawio(const struct inode *inode)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	if (grsec_enable_chroot_caps && proc_is_chrooted(current) && 
	    inode && S_ISBLK(inode->i_mode) && !capable(CAP_SYS_RAWIO))
		return 1;
#endif
	return 0;
}

int
gr_pid_is_chrooted(struct task_struct *p)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_FINDTASK
	if (!grsec_enable_chroot_findtask || !proc_is_chrooted(current) || p == NULL)
		return 0;

	gr_fs_read_lock(p);
	if ((p->exit_state & (EXIT_ZOMBIE | EXIT_DEAD)) ||
	    !have_same_root(current, p)) {
		gr_fs_read_unlock(p);
		return 1;
	}
	gr_fs_read_unlock(p);
#endif
	return 0;
}

EXPORT_SYMBOL(gr_pid_is_chrooted);

#if defined(CONFIG_GRKERNSEC_CHROOT_DOUBLE) || defined(CONFIG_GRKERNSEC_CHROOT_FCHDIR)
int gr_is_outside_chroot(const struct dentry *u_dentry, const struct vfsmount *u_mnt)
{
	struct dentry *dentry = (struct dentry *)u_dentry;
	struct vfsmount *mnt = (struct vfsmount *)u_mnt;
	struct dentry *realroot;
	struct vfsmount *realrootmnt;
	struct dentry *currentroot;
	struct vfsmount *currentmnt;
	struct task_struct *reaper = &init_task;
	int ret = 1;

	read_lock(&reaper->fs->lock);
	realrootmnt = mntget(reaper->fs->root.mnt);
	realroot = dget(reaper->fs->root.dentry);
	read_unlock(&reaper->fs->lock);

	read_lock(&current->fs->lock);
	currentmnt = mntget(current->fs->root.mnt);
	currentroot = dget(current->fs->root.dentry);
	read_unlock(&current->fs->lock);

	spin_lock(&dcache_lock);
	for (;;) {
		if (unlikely((dentry == realroot && mnt == realrootmnt)
		     || (dentry == currentroot && mnt == currentmnt)))
			break;
		if (unlikely(dentry == mnt->mnt_root || IS_ROOT(dentry))) {
			if (mnt->mnt_parent == mnt)
				break;
			dentry = mnt->mnt_mountpoint;
			mnt = mnt->mnt_parent;
			continue;
		}
		dentry = dentry->d_parent;
	}
	spin_unlock(&dcache_lock);

	dput(currentroot);
	mntput(currentmnt);

	/* access is outside of chroot */
	if (dentry == realroot && mnt == realrootmnt)
		ret = 0;

	dput(realroot);
	mntput(realrootmnt);
	return ret;
}
#endif

int
gr_chroot_fchdir(struct dentry *u_dentry, struct vfsmount *u_mnt)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_FCHDIR
	if (!grsec_enable_chroot_fchdir)
		return 1;

	if (!proc_is_chrooted(current))
		return 1;
	else if (!gr_is_outside_chroot(u_dentry, u_mnt)) {
		gr_log_fs_generic(GR_DONT_AUDIT, GR_CHROOT_FCHDIR_MSG, u_dentry, u_mnt);
		return 0;
	}
#endif
	return 1;
}

int
gr_chroot_shmat(const pid_t shm_cprid, const pid_t shm_lapid,
		const time_t shm_createtime)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_SHMAT
	struct pid *pid = NULL;
	time_t starttime;

	if (unlikely(!grsec_enable_chroot_shmat))
		return 1;

	if (likely(!proc_is_chrooted(current)))
		return 1;

	read_lock(&tasklist_lock);

	pid = find_vpid(shm_cprid);
	if (pid) {
		struct task_struct *p;
		p = pid_task(pid, PIDTYPE_PID);
		gr_fs_read_lock(p);
		starttime = p->start_time.tv_sec;
		if (unlikely(!have_same_root(current, p) &&
			     time_before_eq((unsigned long)starttime, (unsigned long)shm_createtime))) {
			gr_fs_read_unlock(p);
			read_unlock(&tasklist_lock);
			gr_log_noargs(GR_DONT_AUDIT, GR_SHMAT_CHROOT_MSG);
			return 0;
		}
		gr_fs_read_unlock(p);
	} else {
		pid = find_vpid(shm_lapid);
		if (pid) {
			struct task_struct *p;
			p = pid_task(pid, PIDTYPE_PID);
			gr_fs_read_lock(p);
			if (unlikely(!have_same_root(current, p))) {
				gr_fs_read_unlock(p);
				read_unlock(&tasklist_lock);
				gr_log_noargs(GR_DONT_AUDIT, GR_SHMAT_CHROOT_MSG);
				return 0;
			}
			gr_fs_read_unlock(p);
		}
	}

	read_unlock(&tasklist_lock);
#endif
	return 1;
}

void
gr_log_chroot_exec(const struct dentry *dentry, const struct vfsmount *mnt)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_EXECLOG
	if (grsec_enable_chroot_execlog && proc_is_chrooted(current))
		gr_log_fs_generic(GR_DO_AUDIT, GR_EXEC_CHROOT_MSG, dentry, mnt);
#endif
	return;
}

int
gr_handle_chroot_mknod(const struct dentry *dentry,
		       const struct vfsmount *mnt, const int mode)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_MKNOD
	if (grsec_enable_chroot_mknod && !S_ISFIFO(mode) && !S_ISREG(mode) && 
	    proc_is_chrooted(current)) {
		gr_log_fs_generic(GR_DONT_AUDIT, GR_MKNOD_CHROOT_MSG, dentry, mnt);
		return -EPERM;
	}
#endif
	return 0;
}

int
gr_handle_chroot_mount(const struct dentry *dentry,
		       const struct vfsmount *mnt, const char *dev_name)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_MOUNT
	if (grsec_enable_chroot_mount && proc_is_chrooted(current)) {
		gr_log_str_fs(GR_DONT_AUDIT, GR_MOUNT_CHROOT_MSG, dev_name, dentry, mnt);
		return -EPERM;
	}
#endif
	return 0;
}

int
gr_handle_chroot_pivot(void)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_PIVOT
	if (grsec_enable_chroot_pivot && proc_is_chrooted(current)) {
		gr_log_noargs(GR_DONT_AUDIT, GR_PIVOT_CHROOT_MSG);
		return -EPERM;
	}
#endif
	return 0;
}

int
gr_handle_chroot_chroot(const struct dentry *dentry, const struct vfsmount *mnt)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_DOUBLE
	if (grsec_enable_chroot_double && proc_is_chrooted(current) &&
	    !gr_is_outside_chroot(dentry, mnt)) {
		gr_log_fs_generic(GR_DONT_AUDIT, GR_CHROOT_CHROOT_MSG, dentry, mnt);
		return -EPERM;
	}
#endif
	return 0;
}

int
gr_handle_chroot_caps(struct path *path)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	if (grsec_enable_chroot_caps && current->pid > 1 && current->fs != NULL &&
		(init_task.fs->root.dentry != path->dentry) &&
		(current->nsproxy->mnt_ns->root->mnt_root != path->dentry)) {

		kernel_cap_t chroot_caps = GR_CHROOT_CAPS;
		const struct cred *old = current_cred();
		struct cred *new = prepare_creds();
		if (new == NULL)
			return 1;

		new->cap_permitted = cap_drop(old->cap_permitted, 
					      chroot_caps);
		new->cap_inheritable = cap_drop(old->cap_inheritable, 
						chroot_caps);
		new->cap_effective = cap_drop(old->cap_effective,
					      chroot_caps);

		commit_creds(new);

		return 0;
	}
#endif
	return 0;
}

int
gr_handle_chroot_sysctl(const int op)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_SYSCTL
	if (grsec_enable_chroot_sysctl && (op & MAY_WRITE) &&
	    proc_is_chrooted(current))
		return -EACCES;
#endif
	return 0;
}

void
gr_handle_chroot_chdir(struct path *path)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_CHDIR
	if (grsec_enable_chroot_chdir)
		set_fs_pwd(current->fs, path);
#endif
	return;
}

int
gr_handle_chroot_chmod(const struct dentry *dentry,
		       const struct vfsmount *mnt, const int mode)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_CHMOD
	if (grsec_enable_chroot_chmod &&
	    ((mode & S_ISUID) || ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))) &&
	    proc_is_chrooted(current)) {
		gr_log_fs_generic(GR_DONT_AUDIT, GR_CHMOD_CHROOT_MSG, dentry, mnt);
		return -EPERM;
	}
#endif
	return 0;
}

#ifdef CONFIG_SECURITY
EXPORT_SYMBOL(gr_handle_chroot_caps);
#endif

#ifndef GR_SECURITY_H
#define GR_SECURITY_H
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/gracl.h>

extern void gr_handle_brute_attach(struct task_struct *p);
extern void gr_handle_brute_check(void);

extern char gr_roletype_to_char(void);

extern int gr_check_user_change(int real, int effective, int fs);
extern int gr_check_group_change(int real, int effective, int fs);

extern void gr_del_task_from_ip_table(struct task_struct *p);

extern int gr_pid_is_chrooted(struct task_struct *p);
extern int gr_handle_chroot_nice(void);
extern int gr_handle_chroot_sysctl(const int op);
extern int gr_handle_chroot_setpriority(struct task_struct *p,
					const int niceval);
extern int gr_chroot_fchdir(struct dentry *u_dentry, struct vfsmount *u_mnt);
extern int gr_handle_chroot_chroot(const struct dentry *dentry,
				   const struct vfsmount *mnt);
extern void gr_handle_chroot_caps(struct task_struct *task);
extern void gr_handle_chroot_chdir(struct dentry *dentry, struct vfsmount *mnt);
extern int gr_handle_chroot_chmod(const struct dentry *dentry,
				  const struct vfsmount *mnt, const int mode);
extern int gr_handle_chroot_mknod(const struct dentry *dentry,
				  const struct vfsmount *mnt, const int mode);
extern int gr_handle_chroot_mount(const struct dentry *dentry,
				  const struct vfsmount *mnt,
				  const char *dev_name);
extern int gr_handle_chroot_pivot(void);
extern int gr_handle_chroot_unix(const pid_t pid);

extern int gr_handle_rawio(const struct inode *inode);
extern int gr_handle_nproc(void);

extern void gr_handle_ioperm(void);
extern void gr_handle_iopl(void);

extern int gr_tpe_allow(const struct file *file);

extern int gr_random_pid(void);

extern void gr_log_forkfail(const int retval);
extern void gr_log_timechange(void);
extern void gr_log_signal(const int sig, const struct task_struct *t);
extern void gr_log_chdir(const struct dentry *dentry,
			 const struct vfsmount *mnt);
extern void gr_log_chroot_exec(const struct dentry *dentry,
			       const struct vfsmount *mnt);
extern void gr_handle_exec_args(struct linux_binprm *bprm, char **argv);
extern void gr_log_remount(const char *devname, const int retval);
extern void gr_log_unmount(const char *devname, const int retval);
extern void gr_log_mount(const char *from, const char *to, const int retval);
extern void gr_log_msgget(const int ret, const int msgflg);
extern void gr_log_msgrm(const uid_t uid, const uid_t cuid);
extern void gr_log_semget(const int err, const int semflg);
extern void gr_log_semrm(const uid_t uid, const uid_t cuid);
extern void gr_log_shmget(const int err, const int shmflg, const size_t size);
extern void gr_log_shmrm(const uid_t uid, const uid_t cuid);
extern void gr_log_textrel(struct vm_area_struct *vma);

extern int gr_handle_follow_link(const struct inode *parent,
				 const struct inode *inode,
				 const struct dentry *dentry,
				 const struct vfsmount *mnt);
extern int gr_handle_fifo(const struct dentry *dentry,
			  const struct vfsmount *mnt,
			  const struct dentry *dir, const int flag,
			  const int acc_mode);
extern int gr_handle_hardlink(const struct dentry *dentry,
			      const struct vfsmount *mnt,
			      struct inode *inode,
			      const int mode, const char *to);

extern int gr_task_is_capable(struct task_struct *task, const int cap);
extern int gr_is_capable_nolog(const int cap);
extern void gr_learn_resource(const struct task_struct *task, const int limit,
			      const unsigned long wanted, const int gt);
extern void gr_copy_label(struct task_struct *tsk);
extern void gr_handle_crash(struct task_struct *task, const int sig);
extern int gr_handle_signal(const struct task_struct *p, const int sig);
extern int gr_check_crash_uid(const uid_t uid);
extern int gr_check_protected_task(const struct task_struct *task);
extern int gr_acl_handle_mmap(const struct file *file,
			      const unsigned long prot);
extern int gr_acl_handle_mprotect(const struct file *file,
				  const unsigned long prot);
extern int gr_check_hidden_task(const struct task_struct *tsk);
extern __u32 gr_acl_handle_truncate(const struct dentry *dentry,
				    const struct vfsmount *mnt);
extern __u32 gr_acl_handle_utime(const struct dentry *dentry,
				 const struct vfsmount *mnt);
extern __u32 gr_acl_handle_access(const struct dentry *dentry,
				  const struct vfsmount *mnt, const int fmode);
extern __u32 gr_acl_handle_fchmod(const struct dentry *dentry,
				  const struct vfsmount *mnt, mode_t mode);
extern __u32 gr_acl_handle_chmod(const struct dentry *dentry,
				 const struct vfsmount *mnt, mode_t mode);
extern __u32 gr_acl_handle_chown(const struct dentry *dentry,
				 const struct vfsmount *mnt);
extern int gr_handle_ptrace(struct task_struct *task, const long request);
extern int gr_handle_proc_ptrace(struct task_struct *task);
extern __u32 gr_acl_handle_execve(const struct dentry *dentry,
				  const struct vfsmount *mnt);
extern int gr_check_crash_exec(const struct file *filp);
extern int gr_acl_is_enabled(void);
extern void gr_set_kernel_label(struct task_struct *task);
extern void gr_set_role_label(struct task_struct *task, const uid_t uid,
			      const gid_t gid);
extern int gr_set_proc_label(const struct dentry *dentry,
			      const struct vfsmount *mnt);
extern __u32 gr_acl_handle_hidden_file(const struct dentry *dentry,
				       const struct vfsmount *mnt);
extern __u32 gr_acl_handle_open(const struct dentry *dentry,
				const struct vfsmount *mnt, const int fmode);
extern __u32 gr_acl_handle_creat(const struct dentry *dentry,
				 const struct dentry *p_dentry,
				 const struct vfsmount *p_mnt, const int fmode,
				 const int imode);
extern void gr_handle_create(const struct dentry *dentry,
			     const struct vfsmount *mnt);
extern __u32 gr_acl_handle_mknod(const struct dentry *new_dentry,
				 const struct dentry *parent_dentry,
				 const struct vfsmount *parent_mnt,
				 const int mode);
extern __u32 gr_acl_handle_mkdir(const struct dentry *new_dentry,
				 const struct dentry *parent_dentry,
				 const struct vfsmount *parent_mnt);
extern __u32 gr_acl_handle_rmdir(const struct dentry *dentry,
				 const struct vfsmount *mnt);
extern void gr_handle_delete(const ino_t ino, const dev_t dev);
extern __u32 gr_acl_handle_unlink(const struct dentry *dentry,
				  const struct vfsmount *mnt);
extern __u32 gr_acl_handle_symlink(const struct dentry *new_dentry,
				   const struct dentry *parent_dentry,
				   const struct vfsmount *parent_mnt,
				   const char *from);
extern __u32 gr_acl_handle_link(const struct dentry *new_dentry,
				const struct dentry *parent_dentry,
				const struct vfsmount *parent_mnt,
				const struct dentry *old_dentry,
				const struct vfsmount *old_mnt, const char *to);
extern int gr_acl_handle_rename(struct dentry *new_dentry,
				struct dentry *parent_dentry,
				const struct vfsmount *parent_mnt,
				struct dentry *old_dentry,
				struct inode *old_parent_inode,
				struct vfsmount *old_mnt, const char *newname);
extern void gr_handle_rename(struct inode *old_dir, struct inode *new_dir,
				struct dentry *old_dentry,
				struct dentry *new_dentry,
				struct vfsmount *mnt, const __u8 replace);
extern __u32 gr_check_link(const struct dentry *new_dentry,
			   const struct dentry *parent_dentry,
			   const struct vfsmount *parent_mnt,
			   const struct dentry *old_dentry,
			   const struct vfsmount *old_mnt);
extern int gr_acl_handle_filldir(const struct file *file, const char *name,
				 const unsigned int namelen, const ino_t ino);

extern __u32 gr_acl_handle_unix(const struct dentry *dentry,
				const struct vfsmount *mnt);
extern void gr_acl_handle_exit(void);
extern void gr_acl_handle_psacct(struct task_struct *task, const long code);
extern int gr_acl_handle_procpidmem(const struct task_struct *task);
extern __u32 gr_cap_rtnetlink(void);

#ifdef CONFIG_SYSVIPC
extern void gr_shm_exit(struct task_struct *task);
#else
static inline void gr_shm_exit(struct task_struct *task)
{
	return;
}
#endif

#ifdef CONFIG_GRKERNSEC
extern void gr_handle_mem_write(void);
extern void gr_handle_kmem_write(void);
extern void gr_handle_open_port(void);
extern int gr_handle_mem_mmap(const unsigned long offset,
			      struct vm_area_struct *vma);

extern unsigned long pax_get_random_long(void);
#define get_random_long() pax_get_random_long()

extern int grsec_enable_dmesg;
extern int grsec_enable_randsrc;
extern int grsec_enable_shm;
#endif

#endif

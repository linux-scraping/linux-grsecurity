#ifndef GR_SECURITY_H
#define GR_SECURITY_H
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/binfmts.h>
#include <linux/gracl.h>

/* notify of brain-dead configs */
#if defined(CONFIG_PAX_NOEXEC) && !defined(CONFIG_PAX_PAGEEXEC) && !defined(CONFIG_PAX_SEGMEXEC) && !defined(CONFIG_PAX_KERNEXEC)
#error "CONFIG_PAX_NOEXEC enabled, but PAGEEXEC, SEGMEXEC, and KERNEXEC are disabled."
#endif
#if defined(CONFIG_PAX_NOEXEC) && !defined(CONFIG_PAX_EI_PAX) && !defined(CONFIG_PAX_PT_PAX_FLAGS)
#error "CONFIG_PAX_NOEXEC enabled, but neither CONFIG_PAX_EI_PAX nor CONFIG_PAX_PT_PAX_FLAGS are enabled."
#endif
#if defined(CONFIG_PAX_ASLR) && (defined(CONFIG_PAX_RANDMMAP) || defined(CONFIG_PAX_RANDUSTACK)) && !defined(CONFIG_PAX_EI_PAX) && !defined(CONFIG_PAX_PT_PAX_FLAGS)
#error "CONFIG_PAX_ASLR enabled, but neither CONFIG_PAX_EI_PAX nor CONFIG_PAX_PT_PAX_FLAGS are enabled."
#endif
#if defined(CONFIG_PAX_ASLR) && !defined(CONFIG_PAX_RANDKSTACK) && !defined(CONFIG_PAX_RANDUSTACK) && !defined(CONFIG_PAX_RANDMMAP)
#error "CONFIG_PAX_ASLR enabled, but RANDKSTACK, RANDUSTACK, and RANDMMAP are disabled."
#endif
#if defined(CONFIG_PAX) && !defined(CONFIG_PAX_NOEXEC) && !defined(CONFIG_PAX_ASLR)
#error "CONFIG_PAX enabled, but no PaX options are enabled."
#endif

void gr_handle_brute_attach(struct task_struct *p);
void gr_handle_brute_check(void);

char gr_roletype_to_char(void);

int gr_check_user_change(int real, int effective, int fs);
int gr_check_group_change(int real, int effective, int fs);

void gr_del_task_from_ip_table(struct task_struct *p);

int gr_pid_is_chrooted(struct task_struct *p);
int gr_handle_chroot_nice(void);
int gr_handle_chroot_sysctl(const int op);
int gr_handle_chroot_setpriority(struct task_struct *p,
					const int niceval);
int gr_chroot_fchdir(struct dentry *u_dentry, struct vfsmount *u_mnt);
int gr_handle_chroot_chroot(const struct dentry *dentry,
				   const struct vfsmount *mnt);
int gr_handle_chroot_caps(struct path *path);
void gr_handle_chroot_chdir(struct path *path);
int gr_handle_chroot_chmod(const struct dentry *dentry,
				  const struct vfsmount *mnt, const int mode);
int gr_handle_chroot_mknod(const struct dentry *dentry,
				  const struct vfsmount *mnt, const int mode);
int gr_handle_chroot_mount(const struct dentry *dentry,
				  const struct vfsmount *mnt,
				  const char *dev_name);
int gr_handle_chroot_pivot(void);
int gr_handle_chroot_unix(const pid_t pid);

int gr_handle_rawio(const struct inode *inode);
int gr_handle_nproc(void);

void gr_handle_ioperm(void);
void gr_handle_iopl(void);

int gr_tpe_allow(const struct file *file);

int gr_random_pid(void);

void gr_log_forkfail(const int retval);
void gr_log_timechange(void);
void gr_log_signal(const int sig, const void *addr, const struct task_struct *t);
void gr_log_chdir(const struct dentry *dentry,
			 const struct vfsmount *mnt);
void gr_log_chroot_exec(const struct dentry *dentry,
			       const struct vfsmount *mnt);
void gr_handle_exec_args(struct linux_binprm *bprm, char **argv);
void gr_log_remount(const char *devname, const int retval);
void gr_log_unmount(const char *devname, const int retval);
void gr_log_mount(const char *from, const char *to, const int retval);
void gr_log_textrel(struct vm_area_struct *vma);

int gr_handle_follow_link(const struct inode *parent,
				 const struct inode *inode,
				 const struct dentry *dentry,
				 const struct vfsmount *mnt);
int gr_handle_fifo(const struct dentry *dentry,
			  const struct vfsmount *mnt,
			  const struct dentry *dir, const int flag,
			  const int acc_mode);
int gr_handle_hardlink(const struct dentry *dentry,
			      const struct vfsmount *mnt,
			      struct inode *inode,
			      const int mode, const char *to);

int gr_is_capable(const int cap);
int gr_is_capable_nolog(const int cap);
void gr_learn_resource(const struct task_struct *task, const int limit,
			      const unsigned long wanted, const int gt);
void gr_copy_label(struct task_struct *tsk);
void gr_handle_crash(struct task_struct *task, const int sig);
int gr_handle_signal(const struct task_struct *p, const int sig);
int gr_check_crash_uid(const uid_t uid);
int gr_check_protected_task(const struct task_struct *task);
int gr_acl_handle_mmap(const struct file *file,
			      const unsigned long prot);
int gr_acl_handle_mprotect(const struct file *file,
				  const unsigned long prot);
int gr_check_hidden_task(const struct task_struct *tsk);
__u32 gr_acl_handle_truncate(const struct dentry *dentry,
				    const struct vfsmount *mnt);
__u32 gr_acl_handle_utime(const struct dentry *dentry,
				 const struct vfsmount *mnt);
__u32 gr_acl_handle_access(const struct dentry *dentry,
				  const struct vfsmount *mnt, const int fmode);
__u32 gr_acl_handle_fchmod(const struct dentry *dentry,
				  const struct vfsmount *mnt, mode_t mode);
__u32 gr_acl_handle_chmod(const struct dentry *dentry,
				 const struct vfsmount *mnt, mode_t mode);
__u32 gr_acl_handle_chown(const struct dentry *dentry,
				 const struct vfsmount *mnt);
int gr_handle_ptrace(struct task_struct *task, const long request);
int gr_handle_proc_ptrace(struct task_struct *task);
__u32 gr_acl_handle_execve(const struct dentry *dentry,
				  const struct vfsmount *mnt);
int gr_check_crash_exec(const struct file *filp);
int gr_acl_is_enabled(void);
void gr_set_kernel_label(struct task_struct *task);
void gr_set_role_label(struct task_struct *task, const uid_t uid,
			      const gid_t gid);
int gr_set_proc_label(const struct dentry *dentry,
			const struct vfsmount *mnt,
			const int unsafe_share);
__u32 gr_acl_handle_hidden_file(const struct dentry *dentry,
				const struct vfsmount *mnt);
__u32 gr_acl_handle_open(const struct dentry *dentry,
				const struct vfsmount *mnt, const int fmode);
__u32 gr_acl_handle_creat(const struct dentry *dentry,
				 const struct dentry *p_dentry,
				 const struct vfsmount *p_mnt, const int fmode,
				 const int imode);
void gr_handle_create(const struct dentry *dentry,
			     const struct vfsmount *mnt);
__u32 gr_acl_handle_mknod(const struct dentry *new_dentry,
				 const struct dentry *parent_dentry,
				 const struct vfsmount *parent_mnt,
				 const int mode);
__u32 gr_acl_handle_mkdir(const struct dentry *new_dentry,
				 const struct dentry *parent_dentry,
				 const struct vfsmount *parent_mnt);
__u32 gr_acl_handle_rmdir(const struct dentry *dentry,
				 const struct vfsmount *mnt);
void gr_handle_delete(const ino_t ino, const dev_t dev);
__u32 gr_acl_handle_unlink(const struct dentry *dentry,
				  const struct vfsmount *mnt);
__u32 gr_acl_handle_symlink(const struct dentry *new_dentry,
				   const struct dentry *parent_dentry,
				   const struct vfsmount *parent_mnt,
				   const char *from);
__u32 gr_acl_handle_link(const struct dentry *new_dentry,
				const struct dentry *parent_dentry,
				const struct vfsmount *parent_mnt,
				const struct dentry *old_dentry,
				const struct vfsmount *old_mnt, const char *to);
int gr_acl_handle_rename(struct dentry *new_dentry,
				struct dentry *parent_dentry,
				const struct vfsmount *parent_mnt,
				struct dentry *old_dentry,
				struct inode *old_parent_inode,
				struct vfsmount *old_mnt, const char *newname);
void gr_handle_rename(struct inode *old_dir, struct inode *new_dir,
				struct dentry *old_dentry,
				struct dentry *new_dentry,
				struct vfsmount *mnt, const __u8 replace);
__u32 gr_check_link(const struct dentry *new_dentry,
			   const struct dentry *parent_dentry,
			   const struct vfsmount *parent_mnt,
			   const struct dentry *old_dentry,
			   const struct vfsmount *old_mnt);
int gr_acl_handle_filldir(const struct file *file, const char *name,
				 const unsigned int namelen, const ino_t ino);

__u32 gr_acl_handle_unix(const struct dentry *dentry,
				const struct vfsmount *mnt);
void gr_acl_handle_exit(void);
void gr_acl_handle_psacct(struct task_struct *task, const long code);
int gr_acl_handle_procpidmem(const struct task_struct *task);
int gr_handle_rofs_mount(struct dentry *dentry, struct vfsmount *mnt, int mnt_flags);
int gr_handle_rofs_blockwrite(struct dentry *dentry, struct vfsmount *mnt, int acc_mode);
void gr_audit_ptrace(struct task_struct *task);

#ifdef CONFIG_GRKERNSEC
void gr_log_nonroot_mod_load(const char *modname);
void gr_handle_vm86(void);
void gr_handle_mem_write(void);
void gr_handle_kmem_write(void);
void gr_handle_open_port(void);
int gr_handle_mem_mmap(const unsigned long offset,
			      struct vm_area_struct *vma);

extern int grsec_enable_dmesg;
#endif

#endif

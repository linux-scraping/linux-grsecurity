#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/grdefs.h>
#include <linux/grinternal.h>
#include <linux/capability.h>
#include <linux/compat.h>

#include <asm/uaccess.h>

#ifdef CONFIG_GRKERNSEC_EXECLOG
static char gr_exec_arg_buf[132];
static DEFINE_MUTEX(gr_exec_arg_mutex);
#endif

int
gr_handle_nproc(void)
{
#ifdef CONFIG_GRKERNSEC_EXECVE
	const struct cred *cred = current_cred();
	if (grsec_enable_execve && cred->user &&
	    (atomic_read(&cred->user->processes) > rlimit(RLIMIT_NPROC)) &&
	    !capable(CAP_SYS_ADMIN) && !capable(CAP_SYS_RESOURCE)) {
		gr_log_noargs(GR_DONT_AUDIT, GR_NPROC_MSG);
		return -EAGAIN;
	}
#endif
	return 0;
}

void
gr_handle_exec_args(struct linux_binprm *bprm, const char __user *const __user *argv)
{
#ifdef CONFIG_GRKERNSEC_EXECLOG
	char *grarg = gr_exec_arg_buf;
	unsigned int i, x, execlen = 0;
	char c;

	if (!((grsec_enable_execlog && grsec_enable_group &&
	       in_group_p(grsec_audit_gid))
	      || (grsec_enable_execlog && !grsec_enable_group)))
		return;

	mutex_lock(&gr_exec_arg_mutex);
	memset(grarg, 0, sizeof(gr_exec_arg_buf));

	if (unlikely(argv == NULL))
		goto log;

	for (i = 0; i < bprm->argc && execlen < 128; i++) {
		const char __user *p;
		unsigned int len;

		if (copy_from_user(&p, argv + i, sizeof(p)))
			goto log;
		if (!p)
			goto log;
		len = strnlen_user(p, 128 - execlen);
		if (len > 128 - execlen)
			len = 128 - execlen;
		else if (len > 0)
			len--;
		if (copy_from_user(grarg + execlen, p, len))
			goto log;

		/* rewrite unprintable characters */
		for (x = 0; x < len; x++) {
			c = *(grarg + execlen + x);
			if (c < 32 || c > 126)
				*(grarg + execlen + x) = ' ';
		}

		execlen += len;
		*(grarg + execlen) = ' ';
		*(grarg + execlen + 1) = '\0';
		execlen++;
	}

      log:
	gr_log_fs_str(GR_DO_AUDIT, GR_EXEC_AUDIT_MSG, bprm->file->f_path.dentry,
			bprm->file->f_path.mnt, grarg);
	mutex_unlock(&gr_exec_arg_mutex);
#endif
	return;
}

#ifdef CONFIG_COMPAT
void
gr_handle_exec_args_compat(struct linux_binprm *bprm, compat_uptr_t __user *argv)
{
#ifdef CONFIG_GRKERNSEC_EXECLOG
	char *grarg = gr_exec_arg_buf;
	unsigned int i, x, execlen = 0;
	char c;

	if (!((grsec_enable_execlog && grsec_enable_group &&
	       in_group_p(grsec_audit_gid))
	      || (grsec_enable_execlog && !grsec_enable_group)))
		return;

	mutex_lock(&gr_exec_arg_mutex);
	memset(grarg, 0, sizeof(gr_exec_arg_buf));

	if (unlikely(argv == NULL))
		goto log;

	for (i = 0; i < bprm->argc && execlen < 128; i++) {
		compat_uptr_t p;
		unsigned int len;

		if (get_user(p, argv + i))
			goto log;
		len = strnlen_user(compat_ptr(p), 128 - execlen);
		if (len > 128 - execlen)
			len = 128 - execlen;
		else if (len > 0)
			len--;
		else
			goto log;
		if (copy_from_user(grarg + execlen, compat_ptr(p), len))
			goto log;

		/* rewrite unprintable characters */
		for (x = 0; x < len; x++) {
			c = *(grarg + execlen + x);
			if (c < 32 || c > 126)
				*(grarg + execlen + x) = ' ';
		}

		execlen += len;
		*(grarg + execlen) = ' ';
		*(grarg + execlen + 1) = '\0';
		execlen++;
	}

      log:
	gr_log_fs_str(GR_DO_AUDIT, GR_EXEC_AUDIT_MSG, bprm->file->f_path.dentry,
			bprm->file->f_path.mnt, grarg);
	mutex_unlock(&gr_exec_arg_mutex);
#endif
	return;
}
#endif

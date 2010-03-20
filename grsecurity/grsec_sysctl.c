#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sysctl.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

int
gr_handle_sysctl_mod(const char *dirname, const char *name, const int op)
{
#ifdef CONFIG_GRKERNSEC_SYSCTL
	if (!strcmp(dirname, "grsecurity") && grsec_lock && (op & MAY_WRITE)) {
		gr_log_str(GR_DONT_AUDIT, GR_SYSCTL_MSG, name);
		return -EACCES;
	}
#endif
	return 0;
}

#ifdef CONFIG_GRKERNSEC_ROFS
static int __maybe_unused one = 1;
#endif

#if defined(CONFIG_GRKERNSEC_SYSCTL) || defined(CONFIG_GRKERNSEC_ROFS)
ctl_table grsecurity_table[] = {
#ifdef CONFIG_GRKERNSEC_SYSCTL
#ifdef CONFIG_GRKERNSEC_LINK
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "linking_restrictions",
		.data		= &grsec_enable_link,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_FIFO
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "fifo_restrictions",
		.data		= &grsec_enable_fifo,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_EXECVE
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "execve_limiting",
		.data		= &grsec_enable_execve,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_BLACKHOLE
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "ip_blackhole",
		.data		= &grsec_enable_blackhole,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "lastack_retries",
		.data		= &grsec_lastack_retries,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_EXECLOG
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "exec_logging",
		.data		= &grsec_enable_execlog,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SIGNAL
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "signal_logging",
		.data		= &grsec_enable_signal,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_FORKFAIL
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "forkfail_logging",
		.data		= &grsec_enable_forkfail,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_TIME
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "timechange_logging",
		.data		= &grsec_enable_time,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_SHMAT
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_deny_shmat",
		.data		= &grsec_enable_chroot_shmat,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_UNIX
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_deny_unix",
		.data		= &grsec_enable_chroot_unix,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_MOUNT
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_deny_mount",
		.data		= &grsec_enable_chroot_mount,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_FCHDIR
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_deny_fchdir",
		.data		= &grsec_enable_chroot_fchdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_DOUBLE
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_deny_chroot",
		.data		= &grsec_enable_chroot_double,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_PIVOT
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_deny_pivot",
		.data		= &grsec_enable_chroot_pivot,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CHDIR
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_enforce_chdir",
		.data		= &grsec_enable_chroot_chdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CHMOD
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_deny_chmod",
		.data		= &grsec_enable_chroot_chmod,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_MKNOD
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_deny_mknod",
		.data		= &grsec_enable_chroot_mknod,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_NICE
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_restrict_nice",
		.data		= &grsec_enable_chroot_nice,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_EXECLOG
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_execlog",
		.data		= &grsec_enable_chroot_execlog,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_caps",
		.data		= &grsec_enable_chroot_caps,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_SYSCTL
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_deny_sysctl",
		.data		= &grsec_enable_chroot_sysctl,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_TPE
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "tpe",
		.data		= &grsec_enable_tpe,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "tpe_gid",
		.data		= &grsec_tpe_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_TPE_ALL
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "tpe_restrict_all",
		.data		= &grsec_enable_tpe_all,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SOCKET_ALL
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "socket_all",
		.data		= &grsec_enable_socket_all,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "socket_all_gid",
		.data		= &grsec_socket_all_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SOCKET_CLIENT
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "socket_client",
		.data		= &grsec_enable_socket_client,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "socket_client_gid",
		.data		= &grsec_socket_client_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SOCKET_SERVER
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "socket_server",
		.data		= &grsec_enable_socket_server,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "socket_server_gid",
		.data		= &grsec_socket_server_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_GROUP
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "audit_group",
		.data		= &grsec_enable_group,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "audit_gid",
		.data		= &grsec_audit_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_CHDIR
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "audit_chdir",
		.data		= &grsec_enable_chdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_MOUNT
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "audit_mount",
		.data		= &grsec_enable_mount,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_TEXTREL
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "audit_textrel",
		.data		= &grsec_enable_audit_textrel,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_DMESG
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "dmesg",
		.data		= &grsec_enable_dmesg,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_FINDTASK
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "chroot_findtask",
		.data		= &grsec_enable_chroot_findtask,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_RESLOG
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "resource_logging",
		.data		= &grsec_resource_logging,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_PTRACE
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "audit_ptrace",
		.data		= &grsec_enable_audit_ptrace,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_HARDEN_PTRACE
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "harden_ptrace",
		.data		= &grsec_enable_harden_ptrace,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "grsec_lock",
		.data		= &grsec_lock,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_ROFS
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "romount_protect",
		.data		= &grsec_enable_rofs,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &one,
	},
#endif
	{ .ctl_name = 0 }
};
#endif

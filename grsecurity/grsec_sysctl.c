#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sysctl.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

#ifdef CONFIG_GRKERNSEC_MODSTOP
int grsec_modstop;
#endif

int
gr_handle_sysctl_mod(const char *dirname, const char *name, const int op)
{
#ifdef CONFIG_GRKERNSEC_SYSCTL
	if (!strcmp(dirname, "grsecurity") && grsec_lock && (op & 002)) {
		gr_log_str(GR_DONT_AUDIT, GR_SYSCTL_MSG, name);
		return -EACCES;
	}
#endif
#ifdef CONFIG_GRKERNSEC_MODSTOP
	if (!strcmp(dirname, "grsecurity") && !strcmp(name, "disable_modules") &&
	    grsec_modstop && (op & 002)) {
		gr_log_str(GR_DONT_AUDIT, GR_SYSCTL_MSG, name);
		return -EACCES;
	}
#endif
	return 0;
}

#if defined(CONFIG_GRKERNSEC_SYSCTL) || defined(CONFIG_GRKERNSEC_MODSTOP)
enum {GS_LINK=1, GS_FIFO, GS_EXECVE, GS_EXECLOG, GS_SIGNAL,
GS_FORKFAIL, GS_TIME, GS_CHROOT_SHMAT, GS_CHROOT_UNIX, GS_CHROOT_MNT,
GS_CHROOT_FCHDIR, GS_CHROOT_DBL, GS_CHROOT_PVT, GS_CHROOT_CD, GS_CHROOT_CM,
GS_CHROOT_MK, GS_CHROOT_NI, GS_CHROOT_EXECLOG, GS_CHROOT_CAPS,
GS_CHROOT_SYSCTL, GS_TPE, GS_TPE_GID, GS_TPE_ALL, GS_SIDCAPS,
GS_RANDPID, GS_SOCKET_ALL, GS_SOCKET_ALL_GID, GS_SOCKET_CLIENT,
GS_SOCKET_CLIENT_GID, GS_SOCKET_SERVER, GS_SOCKET_SERVER_GID, 
GS_GROUP, GS_GID, GS_ACHDIR, GS_AMOUNT, GS_AIPC, GS_DMSG,
GS_TEXTREL, GS_FINDTASK, GS_SHM, GS_LOCK, GS_MODSTOP};


ctl_table grsecurity_table[] = {
#ifdef CONFIG_GRKERNSEC_SYSCTL
#ifdef CONFIG_GRKERNSEC_LINK
	{
		.ctl_name	= GS_LINK,
		.procname	= "linking_restrictions",
		.data		= &grsec_enable_link,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_FIFO
	{
		.ctl_name	= GS_FIFO,
		.procname	= "fifo_restrictions",
		.data		= &grsec_enable_fifo,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_EXECVE
	{
		.ctl_name	= GS_EXECVE,
		.procname	= "execve_limiting",
		.data		= &grsec_enable_execve,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_EXECLOG
	{
		.ctl_name	= GS_EXECLOG,
		.procname	= "exec_logging",
		.data		= &grsec_enable_execlog,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SIGNAL
	{
		.ctl_name	= GS_SIGNAL,
		.procname	= "signal_logging",
		.data		= &grsec_enable_signal,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_FORKFAIL
	{
		.ctl_name	= GS_FORKFAIL,
		.procname	= "forkfail_logging",
		.data		= &grsec_enable_forkfail,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_TIME
	{
		.ctl_name	= GS_TIME,
		.procname	= "timechange_logging",
		.data		= &grsec_enable_time,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_SHMAT
	{
		.ctl_name	= GS_CHROOT_SHMAT,
		.procname	= "chroot_deny_shmat",
		.data		= &grsec_enable_chroot_shmat,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_UNIX
	{
		.ctl_name	= GS_CHROOT_UNIX,
		.procname	= "chroot_deny_unix",
		.data		= &grsec_enable_chroot_unix,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_MOUNT
	{
		.ctl_name	= GS_CHROOT_MNT,
		.procname	= "chroot_deny_mount",
		.data		= &grsec_enable_chroot_mount,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_FCHDIR
	{
		.ctl_name	= GS_CHROOT_FCHDIR,
		.procname	= "chroot_deny_fchdir",
		.data		= &grsec_enable_chroot_fchdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_DOUBLE
	{
		.ctl_name	= GS_CHROOT_DBL,
		.procname	= "chroot_deny_chroot",
		.data		= &grsec_enable_chroot_double,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_PIVOT
	{
		.ctl_name	= GS_CHROOT_PVT,
		.procname	= "chroot_deny_pivot",
		.data		= &grsec_enable_chroot_pivot,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CHDIR
	{
		.ctl_name	= GS_CHROOT_CD,
		.procname	= "chroot_enforce_chdir",
		.data		= &grsec_enable_chroot_chdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CHMOD
	{
		.ctl_name	= GS_CHROOT_CM,
		.procname	= "chroot_deny_chmod",
		.data		= &grsec_enable_chroot_chmod,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_MKNOD
	{
		.ctl_name	= GS_CHROOT_MK,
		.procname	= "chroot_deny_mknod",
		.data		= &grsec_enable_chroot_mknod,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_NICE
	{
		.ctl_name	= GS_CHROOT_NI,
		.procname	= "chroot_restrict_nice",
		.data		= &grsec_enable_chroot_nice,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_EXECLOG
	{
		.ctl_name	= GS_CHROOT_EXECLOG,
		.procname	= "chroot_execlog",
		.data		= &grsec_enable_chroot_execlog,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	{
		.ctl_name	= GS_CHROOT_CAPS,
		.procname	= "chroot_caps",
		.data		= &grsec_enable_chroot_caps,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_SYSCTL
	{
		.ctl_name	= GS_CHROOT_SYSCTL,
		.procname	= "chroot_deny_sysctl",
		.data		= &grsec_enable_chroot_sysctl,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_TPE
	{
		.ctl_name	= GS_TPE,
		.procname	= "tpe",
		.data		= &grsec_enable_tpe,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= GS_TPE_GID,
		.procname	= "tpe_gid",
		.data		= &grsec_tpe_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_TPE_ALL
	{
		.ctl_name	= GS_TPE_ALL,
		.procname	= "tpe_restrict_all",
		.data		= &grsec_enable_tpe_all,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_RANDPID
	{
		.ctl_name	= GS_RANDPID,
		.procname	= "rand_pids",
		.data		= &grsec_enable_randpid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SOCKET_ALL
	{
		.ctl_name	= GS_SOCKET_ALL,
		.procname	= "socket_all",
		.data		= &grsec_enable_socket_all,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= GS_SOCKET_ALL_GID,
		.procname	= "socket_all_gid",
		.data		= &grsec_socket_all_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SOCKET_CLIENT
	{
		.ctl_name	= GS_SOCKET_CLIENT,
		.procname	= "socket_client",
		.data		= &grsec_enable_socket_client,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= GS_SOCKET_CLIENT_GID,
		.procname	= "socket_client_gid",
		.data		= &grsec_socket_client_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SOCKET_SERVER
	{
		.ctl_name	= GS_SOCKET_SERVER,
		.procname	= "socket_server",
		.data		= &grsec_enable_socket_server,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= GS_SOCKET_SERVER_GID,
		.procname	= "socket_server_gid",
		.data		= &grsec_socket_server_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_GROUP
	{
		.ctl_name	= GS_GROUP,
		.procname	= "audit_group",
		.data		= &grsec_enable_group,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= GS_GID,
		.procname	= "audit_gid",
		.data		= &grsec_audit_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_CHDIR
	{
		.ctl_name	= GS_ACHDIR,
		.procname	= "audit_chdir",
		.data		= &grsec_enable_chdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_MOUNT
	{
		.ctl_name	= GS_AMOUNT,
		.procname	= "audit_mount",
		.data		= &grsec_enable_mount,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_IPC
	{
		.ctl_name	= GS_AIPC,
		.procname	= "audit_ipc",
		.data		= &grsec_enable_audit_ipc,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_TEXTREL
	{
		.ctl_name	= GS_TEXTREL,
		.procname	= "audit_textrel",
		.data		= &grsec_enable_audit_textrel,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_DMESG
	{
		.ctl_name	= GS_DMSG,
		.procname	= "dmesg",
		.data		= &grsec_enable_dmesg,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_FINDTASK
	{
		.ctl_name	= GS_FINDTASK,
		.procname	= "chroot_findtask",
		.data		= &grsec_enable_chroot_findtask,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SHM
	{
		.ctl_name	= GS_SHM,
		.procname	= "destroy_unused_shm",
		.data		= &grsec_enable_shm,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{
		.ctl_name	= GS_LOCK,
		.procname	= "grsec_lock",
		.data		= &grsec_lock,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_GRKERNSEC_MODSTOP
	{
		.ctl_name	= GS_MODSTOP,
		.procname	= "disable_modules",
		.data		= &grsec_modstop,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{ .ctl_name = 0 }
};
#endif

int gr_check_modstop(void)
{
#ifdef CONFIG_GRKERNSEC_MODSTOP
	if (grsec_modstop == 1) {
		gr_log_noargs(GR_DONT_AUDIT, GR_STOPMOD_MSG);
		return 1;
	}
#endif
	return 0;
}

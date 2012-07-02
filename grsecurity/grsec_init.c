#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/gracl.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/percpu.h>
#include <linux/module.h>

int grsec_enable_ptrace_readexec;
int grsec_enable_setxid;
int grsec_enable_symlinkown;
int grsec_symlinkown_gid;
int grsec_enable_brute;
int grsec_enable_link;
int grsec_enable_dmesg;
int grsec_enable_harden_ptrace;
int grsec_enable_fifo;
int grsec_enable_execlog;
int grsec_enable_signal;
int grsec_enable_forkfail;
int grsec_enable_audit_ptrace;
int grsec_enable_time;
int grsec_enable_audit_textrel;
int grsec_enable_group;
int grsec_audit_gid;
int grsec_enable_chdir;
int grsec_enable_mount;
int grsec_enable_rofs;
int grsec_enable_chroot_findtask;
int grsec_enable_chroot_mount;
int grsec_enable_chroot_shmat;
int grsec_enable_chroot_fchdir;
int grsec_enable_chroot_double;
int grsec_enable_chroot_pivot;
int grsec_enable_chroot_chdir;
int grsec_enable_chroot_chmod;
int grsec_enable_chroot_mknod;
int grsec_enable_chroot_nice;
int grsec_enable_chroot_execlog;
int grsec_enable_chroot_caps;
int grsec_enable_chroot_sysctl;
int grsec_enable_chroot_unix;
int grsec_enable_tpe;
int grsec_tpe_gid;
int grsec_enable_blackhole;
#ifdef CONFIG_IPV6_MODULE
EXPORT_SYMBOL(grsec_enable_blackhole);
#endif
int grsec_lastack_retries;
int grsec_enable_tpe_all;
int grsec_enable_tpe_invert;
int grsec_enable_socket_all;
int grsec_socket_all_gid;
int grsec_enable_socket_client;
int grsec_socket_client_gid;
int grsec_enable_socket_server;
int grsec_socket_server_gid;
int grsec_resource_logging;
int grsec_disable_privio;
int grsec_enable_log_rwxmaps;
int grsec_lock;

DEFINE_SPINLOCK(grsec_alert_lock);
unsigned long grsec_alert_wtime = 0;
unsigned long grsec_alert_fyet = 0;

DEFINE_SPINLOCK(grsec_audit_lock);

DEFINE_RWLOCK(grsec_exec_file_lock);

char *gr_shared_page[4];

char *gr_alert_log_fmt;
char *gr_audit_log_fmt;
char *gr_alert_log_buf;
char *gr_audit_log_buf;

extern struct gr_arg *gr_usermode;
extern unsigned char *gr_system_salt;
extern unsigned char *gr_system_sum;

void __init
grsecurity_init(void)
{
	int j;
	/* create the per-cpu shared pages */

#ifdef CONFIG_X86
	memset((char *)(0x41a + PAGE_OFFSET), 0, 36);
#endif

	for (j = 0; j < 4; j++) {
		gr_shared_page[j] = (char *)__alloc_percpu(PAGE_SIZE, __alignof__(unsigned long long));
		if (gr_shared_page[j] == NULL) {
			panic("Unable to allocate grsecurity shared page");
			return;
		}
	}

	/* allocate log buffers */
	gr_alert_log_fmt = kmalloc(512, GFP_KERNEL);
	if (!gr_alert_log_fmt) {
		panic("Unable to allocate grsecurity alert log format buffer");
		return;
	}
	gr_audit_log_fmt = kmalloc(512, GFP_KERNEL);
	if (!gr_audit_log_fmt) {
		panic("Unable to allocate grsecurity audit log format buffer");
		return;
	}
	gr_alert_log_buf = (char *) get_zeroed_page(GFP_KERNEL);
	if (!gr_alert_log_buf) {
		panic("Unable to allocate grsecurity alert log buffer");
		return;
	}
	gr_audit_log_buf = (char *) get_zeroed_page(GFP_KERNEL);
	if (!gr_audit_log_buf) {
		panic("Unable to allocate grsecurity audit log buffer");
		return;
	}

	/* allocate memory for authentication structure */
	gr_usermode = kmalloc(sizeof(struct gr_arg), GFP_KERNEL);
	gr_system_salt = kmalloc(GR_SALT_LEN, GFP_KERNEL);
	gr_system_sum = kmalloc(GR_SHA_LEN, GFP_KERNEL);

	if (!gr_usermode || !gr_system_salt || !gr_system_sum) {
		panic("Unable to allocate grsecurity authentication structure");
		return;
	}


#ifdef CONFIG_GRKERNSEC_IO
#if !defined(CONFIG_GRKERNSEC_SYSCTL_DISTRO)
	grsec_disable_privio = 1;
#elif defined(CONFIG_GRKERNSEC_SYSCTL_ON)
	grsec_disable_privio = 1;
#else
	grsec_disable_privio = 0;
#endif
#endif

#ifdef CONFIG_GRKERNSEC_TPE_INVERT
	/* for backward compatibility, tpe_invert always defaults to on if
	   enabled in the kernel
	*/
	grsec_enable_tpe_invert = 1;
#endif

#if !defined(CONFIG_GRKERNSEC_SYSCTL) || defined(CONFIG_GRKERNSEC_SYSCTL_ON)
#ifndef CONFIG_GRKERNSEC_SYSCTL
	grsec_lock = 1;
#endif

#ifdef CONFIG_GRKERNSEC_AUDIT_TEXTREL
	grsec_enable_audit_textrel = 1;
#endif
#ifdef CONFIG_GRKERNSEC_RWXMAP_LOG
	grsec_enable_log_rwxmaps = 1;
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_GROUP
	grsec_enable_group = 1;
	grsec_audit_gid = CONFIG_GRKERNSEC_AUDIT_GID;
#endif
#ifdef CONFIG_GRKERNSEC_PTRACE_READEXEC
	grsec_enable_ptrace_readexec = 1;
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_CHDIR
	grsec_enable_chdir = 1;
#endif
#ifdef CONFIG_GRKERNSEC_HARDEN_PTRACE
	grsec_enable_harden_ptrace = 1;
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_MOUNT
	grsec_enable_mount = 1;
#endif
#ifdef CONFIG_GRKERNSEC_LINK
	grsec_enable_link = 1;
#endif
#ifdef CONFIG_GRKERNSEC_BRUTE
	grsec_enable_brute = 1;
#endif
#ifdef CONFIG_GRKERNSEC_DMESG
	grsec_enable_dmesg = 1;
#endif
#ifdef CONFIG_GRKERNSEC_BLACKHOLE
	grsec_enable_blackhole = 1;
	grsec_lastack_retries = 4;
#endif
#ifdef CONFIG_GRKERNSEC_FIFO
	grsec_enable_fifo = 1;
#endif
#ifdef CONFIG_GRKERNSEC_EXECLOG
	grsec_enable_execlog = 1;
#endif
#ifdef CONFIG_GRKERNSEC_SETXID
	grsec_enable_setxid = 1;
#endif
#ifdef CONFIG_GRKERNSEC_SIGNAL
	grsec_enable_signal = 1;
#endif
#ifdef CONFIG_GRKERNSEC_FORKFAIL
	grsec_enable_forkfail = 1;
#endif
#ifdef CONFIG_GRKERNSEC_TIME
	grsec_enable_time = 1;
#endif
#ifdef CONFIG_GRKERNSEC_RESLOG
	grsec_resource_logging = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_FINDTASK
	grsec_enable_chroot_findtask = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_UNIX
	grsec_enable_chroot_unix = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_MOUNT
	grsec_enable_chroot_mount = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_FCHDIR
	grsec_enable_chroot_fchdir = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_SHMAT
	grsec_enable_chroot_shmat = 1;
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_PTRACE
	grsec_enable_audit_ptrace = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_DOUBLE
	grsec_enable_chroot_double = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_PIVOT
	grsec_enable_chroot_pivot = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CHDIR
	grsec_enable_chroot_chdir = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CHMOD
	grsec_enable_chroot_chmod = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_MKNOD
	grsec_enable_chroot_mknod = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_NICE
	grsec_enable_chroot_nice = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_EXECLOG
	grsec_enable_chroot_execlog = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	grsec_enable_chroot_caps = 1;
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_SYSCTL
	grsec_enable_chroot_sysctl = 1;
#endif
#ifdef CONFIG_GRKERNSEC_SYMLINKOWN
	grsec_enable_symlinkown = 1;
	grsec_symlinkown_gid = CONFIG_GRKERNSEC_SYMLINKOWN_GID;
#endif
#ifdef CONFIG_GRKERNSEC_TPE
	grsec_enable_tpe = 1;
	grsec_tpe_gid = CONFIG_GRKERNSEC_TPE_GID;
#ifdef CONFIG_GRKERNSEC_TPE_ALL
	grsec_enable_tpe_all = 1;
#endif
#endif
#ifdef CONFIG_GRKERNSEC_SOCKET_ALL
	grsec_enable_socket_all = 1;
	grsec_socket_all_gid = CONFIG_GRKERNSEC_SOCKET_ALL_GID;
#endif
#ifdef CONFIG_GRKERNSEC_SOCKET_CLIENT
	grsec_enable_socket_client = 1;
	grsec_socket_client_gid = CONFIG_GRKERNSEC_SOCKET_CLIENT_GID;
#endif
#ifdef CONFIG_GRKERNSEC_SOCKET_SERVER
	grsec_enable_socket_server = 1;
	grsec_socket_server_gid = CONFIG_GRKERNSEC_SOCKET_SERVER_GID;
#endif
#endif

	return;
}

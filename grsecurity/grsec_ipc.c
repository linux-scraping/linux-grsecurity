#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

int
gr_ipc_permitted(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp, int requested_mode, int granted_mode)
{
#ifdef CONFIG_GRKERNSEC_HARDEN_IPC
	int write = (requested_mode & 00002);

	if (grsec_enable_harden_ipc && !(requested_mode & ~granted_mode & 0007) && !ns_capable_nolog(ns->user_ns, CAP_IPC_OWNER)) {
		gr_log_str2_int(GR_DONT_AUDIT, GR_IPC_DENIED_MSG, write ? "write" : "read", write ? "writ" : "read", GR_GLOBAL_UID(ipcp->cuid));
		return 0;
	}
#endif
	return 1;
}

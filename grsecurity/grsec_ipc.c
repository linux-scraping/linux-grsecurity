#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/ipc.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

void
gr_log_msgget(const int ret, const int msgflg)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_IPC
	if (((grsec_enable_group && in_group_p(grsec_audit_gid) &&
	      grsec_enable_audit_ipc) || (grsec_enable_audit_ipc &&
					  !grsec_enable_group)) && (ret >= 0)
	    && (msgflg & IPC_CREAT))
		gr_log_noargs(GR_DO_AUDIT, GR_MSGQ_AUDIT_MSG);
#endif
	return;
}

void
gr_log_msgrm(const uid_t uid, const uid_t cuid)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_IPC
	if ((grsec_enable_group && in_group_p(grsec_audit_gid) &&
	     grsec_enable_audit_ipc) ||
	    (grsec_enable_audit_ipc && !grsec_enable_group))
		gr_log_int_int(GR_DO_AUDIT, GR_MSGQR_AUDIT_MSG, uid, cuid);
#endif
	return;
}

void
gr_log_semget(const int err, const int semflg)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_IPC
	if (((grsec_enable_group && in_group_p(grsec_audit_gid) &&
	      grsec_enable_audit_ipc) || (grsec_enable_audit_ipc &&
					  !grsec_enable_group)) && (err >= 0)
	    && (semflg & IPC_CREAT))
		gr_log_noargs(GR_DO_AUDIT, GR_SEM_AUDIT_MSG);
#endif
	return;
}

void
gr_log_semrm(const uid_t uid, const uid_t cuid)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_IPC
	if ((grsec_enable_group && in_group_p(grsec_audit_gid) &&
	     grsec_enable_audit_ipc) ||
	    (grsec_enable_audit_ipc && !grsec_enable_group))
		gr_log_int_int(GR_DO_AUDIT, GR_SEMR_AUDIT_MSG, uid, cuid);
#endif
	return;
}

void
gr_log_shmget(const int err, const int shmflg, const size_t size)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_IPC
	if (((grsec_enable_group && in_group_p(grsec_audit_gid) &&
	      grsec_enable_audit_ipc) || (grsec_enable_audit_ipc &&
					  !grsec_enable_group)) && (err >= 0)
	    && (shmflg & IPC_CREAT))
		gr_log_int(GR_DO_AUDIT, GR_SHM_AUDIT_MSG, size);
#endif
	return;
}

void
gr_log_shmrm(const uid_t uid, const uid_t cuid)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_IPC
	if ((grsec_enable_group && in_group_p(grsec_audit_gid) &&
	     grsec_enable_audit_ipc) ||
	    (grsec_enable_audit_ipc && !grsec_enable_group))
		gr_log_int_int(GR_DO_AUDIT, GR_SHMR_AUDIT_MSG, uid, cuid);
#endif
	return;
}

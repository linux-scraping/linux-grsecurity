#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/grinternal.h>
#include <linux/grsecurity.h>

void
gr_log_textrel(struct vm_area_struct * vma)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_TEXTREL
	if (grsec_enable_audit_textrel)
		gr_log_textrel_ulong_ulong(GR_DO_AUDIT, GR_TEXTREL_AUDIT_MSG, vma->vm_file, vma->vm_start, vma->vm_pgoff);
#endif
	return;
}

void
gr_log_rwxmmap(struct file *file)
{
#ifdef CONFIG_GRKERNSEC_RWXMAP_LOG
	if (grsec_enable_log_rwxmaps)
		gr_log_rwxmap(GR_DONT_AUDIT, GR_RWXMMAP_MSG, file);
#endif
	return;
}

void
gr_log_rwxmprotect(struct file *file)
{
#ifdef CONFIG_GRKERNSEC_RWXMAP_LOG
	if (grsec_enable_log_rwxmaps)
		gr_log_rwxmap(GR_DONT_AUDIT, GR_RWXMPROTECT_MSG, file);
#endif
	return;
}

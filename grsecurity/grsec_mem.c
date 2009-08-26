#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/grinternal.h>

void
gr_handle_ioperm(void)
{
	gr_log_noargs(GR_DONT_AUDIT, GR_IOPERM_MSG);
	return;
}

void
gr_handle_iopl(void)
{
	gr_log_noargs(GR_DONT_AUDIT, GR_IOPL_MSG);
	return;
}

void
gr_handle_mem_write(void)
{
	gr_log_noargs(GR_DONT_AUDIT, GR_MEM_WRITE_MSG);
	return;
}

void
gr_handle_kmem_write(void)
{
	gr_log_noargs(GR_DONT_AUDIT, GR_KMEM_MSG);
	return;
}

void
gr_handle_open_port(void)
{
	gr_log_noargs(GR_DONT_AUDIT, GR_PORT_OPEN_MSG);
	return;
}

int
gr_handle_mem_mmap(const unsigned long offset, struct vm_area_struct *vma)
{
	unsigned long start, end;

	start = offset;
	end = start + vma->vm_end - vma->vm_start;

	if (start > end) {
		gr_log_noargs(GR_DONT_AUDIT, GR_MEM_MMAP_MSG);
		return -EPERM;
	}

	/* allowed ranges : ISA I/O BIOS */
	if ((start >= __pa(high_memory))
#ifdef CONFIG_X86
	    || (start >= 0x000a0000 && end <= 0x00100000)
	    || (start >= 0x00000000 && end <= 0x00001000)
#endif
	)
		return 0;

	if (vma->vm_flags & VM_WRITE) {
		gr_log_noargs(GR_DONT_AUDIT, GR_MEM_MMAP_MSG);
		return -EPERM;
	} else
		vma->vm_flags &= ~VM_MAYWRITE;

	return 0;
}

void
gr_log_nonroot_mod_load(const char *modname)
{
        gr_log_str(GR_DONT_AUDIT, GR_NONROOT_MODLOAD_MSG, modname);
        return;
}


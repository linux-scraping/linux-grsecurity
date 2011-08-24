/*
 * Set up the VMAs to tell the VM about the vDSO.
 * Copyright 2007 Andi Kleen, SUSE Labs.
 * Subject to the GPL, v.2
 */
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/elf.h>
#include <asm/vsyscall.h>
#include <asm/vgtod.h>
#include <asm/proto.h>
#include <asm/vdso.h>

extern char vdso_start[], vdso_end[];
extern unsigned short vdso_sync_cpuid;
extern char __vsyscall_0;

static struct page **vdso_pages;
static struct page *vsyscall_page;
static unsigned vdso_size;

static int __init init_vdso_vars(void)
{
	size_t nbytes = vdso_end - vdso_start;
	size_t npages = (nbytes + PAGE_SIZE - 1) / PAGE_SIZE;
	size_t i;

	vdso_size = npages << PAGE_SHIFT;
	vdso_pages = kmalloc(sizeof(struct page *) * npages, GFP_KERNEL);
	if (!vdso_pages)
		goto oom;
	for (i = 0; i < npages; i++) {
		struct page *p;
		p = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!p)
			goto oom;
		vdso_pages[i] = p;
		memcpy(page_address(p), vdso_start + i*PAGE_SIZE, nbytes > PAGE_SIZE ? PAGE_SIZE : nbytes);
		nbytes -= PAGE_SIZE;
	}
	vsyscall_page = pfn_to_page((__pa_symbol(&__vsyscall_0)) >> PAGE_SHIFT);

	return 0;

 oom:
	panic("Cannot allocate vdso\n");
}
subsys_initcall(init_vdso_vars);

struct linux_binprm;

/* Put the vdso above the (randomized) stack with another randomized offset.
   This way there is no hole in the middle of address space.
   To save memory make sure it is still in the same PTE as the stack top.
   This doesn't give that many random bits */
static unsigned long vdso_addr(unsigned long start, unsigned len)
{
	unsigned long addr, end;
	unsigned offset;
	end = (start + PMD_SIZE - 1) & PMD_MASK;
	if (end >= TASK_SIZE_MAX)
		end = TASK_SIZE_MAX;
	end -= len;
	/* This loses some more bits than a modulo, but is cheaper */
	offset = get_random_int() & (PTRS_PER_PTE - 1);
	addr = start + (offset << PAGE_SHIFT);
	if (addr >= end)
		addr = end;
	return addr;
}

/* Setup a VMA at program startup for the vsyscall page.
   Not called for compat tasks */
int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr;
	int ret;

	down_write(&mm->mmap_sem);
	addr = vdso_addr(mm->start_stack, vdso_size + PAGE_SIZE);
	addr = get_unmapped_area(NULL, addr, vdso_size + PAGE_SIZE, 0, 0);
	if (IS_ERR_VALUE(addr)) {
		ret = addr;
		goto up_fail;
	}

	mm->context.vdso = addr + PAGE_SIZE;

	ret = install_special_mapping(mm, addr, PAGE_SIZE,
				      VM_READ|VM_EXEC|
				      VM_MAYREAD|VM_MAYEXEC|
				      VM_ALWAYSDUMP,
				      &vsyscall_page);
	if (ret) {
		mm->context.vdso = 0;
		goto up_fail;
	}

	ret = install_special_mapping(mm, addr + PAGE_SIZE, vdso_size,
				      VM_READ|VM_EXEC|
				      VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC|
				      VM_ALWAYSDUMP,
				      vdso_pages);
	if (ret)
		mm->context.vdso = 0;

up_fail:
	up_write(&mm->mmap_sem);
	return ret;
}

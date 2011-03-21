/*
 * This file contains various random system calls that
 * have a non-standard calling sequence on the Linux/i386
 * platform.
 */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/smp.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/stat.h>
#include <linux/syscalls.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/utsname.h>
#include <linux/ipc.h>

#include <linux/uaccess.h>
#include <linux/unistd.h>

#include <asm/syscalls.h>

int i386_mmap_check(unsigned long addr, unsigned long len, unsigned long flags)
{
	unsigned long pax_task_size = TASK_SIZE;

#ifdef CONFIG_PAX_SEGMEXEC
	if (current->mm->pax_flags & MF_PAX_SEGMEXEC)
		pax_task_size = SEGMEXEC_TASK_SIZE;
#endif

	if (len > pax_task_size || addr > pax_task_size - len)
		return -EINVAL;

	return 0;
}

unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long start_addr, pax_task_size = TASK_SIZE;

#ifdef CONFIG_PAX_SEGMEXEC
	if (mm->pax_flags & MF_PAX_SEGMEXEC)
		pax_task_size = SEGMEXEC_TASK_SIZE;
#endif

	pax_task_size -= PAGE_SIZE;

	if (len > pax_task_size)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

#ifdef CONFIG_PAX_RANDMMAP
	if (!(mm->pax_flags & MF_PAX_RANDMMAP))
#endif

	if (addr) {
		addr = PAGE_ALIGN(addr);
		if (pax_task_size - len >= addr) {
			vma = find_vma(mm, addr);
			if (check_heap_stack_gap(vma, addr, len))
				return addr;
		}
	}
	if (len > mm->cached_hole_size) {
		start_addr = addr = mm->free_area_cache;
	} else {
		start_addr = addr = mm->mmap_base;
		mm->cached_hole_size = 0;
	}

#ifdef CONFIG_PAX_PAGEEXEC
	if (!(__supported_pte_mask & _PAGE_NX) && (mm->pax_flags & MF_PAX_PAGEEXEC) && (flags & MAP_EXECUTABLE) && start_addr >= mm->mmap_base) {
		start_addr = 0x00110000UL;

#ifdef CONFIG_PAX_RANDMMAP
		if (mm->pax_flags & MF_PAX_RANDMMAP)
			start_addr += mm->delta_mmap & 0x03FFF000UL;
#endif

		if (mm->start_brk <= start_addr && start_addr < mm->mmap_base)
			start_addr = addr = mm->mmap_base;
		else
			addr = start_addr;
	}
#endif

full_search:
	for (vma = find_vma(mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (pax_task_size - len < addr) {
			/*
			 * Start a new search - just in case we missed
			 * some holes.
			 */
			if (start_addr != mm->mmap_base) {
				start_addr = addr = mm->mmap_base;
				mm->cached_hole_size = 0;
				goto full_search;
			}
			return -ENOMEM;
		}
		if (check_heap_stack_gap(vma, addr, len))
			break;
		if (addr + mm->cached_hole_size < vma->vm_start)
			mm->cached_hole_size = vma->vm_start - addr;
		addr = vma->vm_end;
		if (mm->start_brk <= addr && addr < mm->mmap_base) {
			start_addr = addr = mm->mmap_base;
			mm->cached_hole_size = 0;
			goto full_search;
		}
	}

	/*
	 * Remember the place where we stopped the search:
	 */
	mm->free_area_cache = addr + len;
	return addr;
}

unsigned long
arch_get_unmapped_area_topdown(struct file *filp, const unsigned long addr0,
			  const unsigned long len, const unsigned long pgoff,
			  const unsigned long flags)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long base = mm->mmap_base, addr = addr0, pax_task_size = TASK_SIZE;

#ifdef CONFIG_PAX_SEGMEXEC
	if (mm->pax_flags & MF_PAX_SEGMEXEC)
		pax_task_size = SEGMEXEC_TASK_SIZE;
#endif

	pax_task_size -= PAGE_SIZE;

	/* requested length too big for entire address space */
	if (len > pax_task_size)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

#ifdef CONFIG_PAX_PAGEEXEC
	if (!(__supported_pte_mask & _PAGE_NX) && (mm->pax_flags & MF_PAX_PAGEEXEC) && (flags & MAP_EXECUTABLE))
		goto bottomup;
#endif

#ifdef CONFIG_PAX_RANDMMAP
	if (!(mm->pax_flags & MF_PAX_RANDMMAP))
#endif

	/* requesting a specific address */
	if (addr) {
		addr = PAGE_ALIGN(addr);
		if (pax_task_size - len >= addr) {
			vma = find_vma(mm, addr);
			if (check_heap_stack_gap(vma, addr, len))
				return addr;
		}
	}

	/* check if free_area_cache is useful for us */
	if (len <= mm->cached_hole_size) {
		mm->cached_hole_size = 0;
		mm->free_area_cache = mm->mmap_base;
	}

	/* either no address requested or can't fit in requested address hole */
	addr = mm->free_area_cache;

	/* make sure it can fit in the remaining address space */
	if (addr > len) {
		vma = find_vma(mm, addr-len);
		if (check_heap_stack_gap(vma, addr - len, len))
			/* remember the address as a hint for next time */
			return (mm->free_area_cache = addr-len);
	}

	if (mm->mmap_base < len)
		goto bottomup;

	addr = mm->mmap_base-len;

	do {
		/*
		 * Lookup failure means no vma is above this address,
		 * else if new region fits below vma->vm_start,
		 * return with success:
		 */
		vma = find_vma(mm, addr);
		if (check_heap_stack_gap(vma, addr, len))
			/* remember the address as a hint for next time */
			return (mm->free_area_cache = addr);

		/* remember the largest hole we saw so far */
		if (addr + mm->cached_hole_size < vma->vm_start)
			mm->cached_hole_size = vma->vm_start - addr;

		/* try just below the current vma->vm_start */
		addr = skip_heap_stack_gap(vma, len);
	} while (!IS_ERR_VALUE(addr));

bottomup:
	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */

#ifdef CONFIG_PAX_SEGMEXEC
	if (mm->pax_flags & MF_PAX_SEGMEXEC)
		mm->mmap_base = SEGMEXEC_TASK_UNMAPPED_BASE;
	else
#endif

	mm->mmap_base = TASK_UNMAPPED_BASE;

#ifdef CONFIG_PAX_RANDMMAP
	if (mm->pax_flags & MF_PAX_RANDMMAP)
		mm->mmap_base += mm->delta_mmap;
#endif

	mm->free_area_cache = mm->mmap_base;
	mm->cached_hole_size = ~0UL;
	addr = arch_get_unmapped_area(filp, addr0, len, pgoff, flags);
	/*
	 * Restore the topdown base:
	 */
	mm->mmap_base = base;
	mm->free_area_cache = base;
	mm->cached_hole_size = ~0UL;

	return addr;
}

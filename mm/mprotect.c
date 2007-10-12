/*
 *  mm/mprotect.c
 *
 *  (C) Copyright 1994 Linus Torvalds
 *  (C) Copyright 2002 Christoph Hellwig
 *
 *  Address space accounting code	<alan@redhat.com>
 *  (C) Copyright 2002 Red Hat Inc, All Rights Reserved
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/slab.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/security.h>
#include <linux/mempolicy.h>
#include <linux/personality.h>
#include <linux/syscalls.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/grsecurity.h>

#ifdef CONFIG_PAX_MPROTECT
#include <linux/elf.h>
#endif

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>

static void change_pte_range(struct mm_struct *mm, pmd_t *pmd,
		unsigned long addr, unsigned long end, pgprot_t newprot,
		int dirty_accountable)
{
	pte_t *pte, oldpte;
	spinlock_t *ptl;

	pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	arch_enter_lazy_mmu_mode();
	do {
		oldpte = *pte;
		if (pte_present(oldpte)) {
			pte_t ptent;

			/* Avoid an SMP race with hardware updated dirty/clean
			 * bits by wiping the pte and then setting the new pte
			 * into place.
			 */
			ptent = ptep_get_and_clear(mm, addr, pte);
			ptent = pte_modify(ptent, newprot);
			/*
			 * Avoid taking write faults for pages we know to be
			 * dirty.
			 */
			if (dirty_accountable && pte_dirty(ptent))
				ptent = pte_mkwrite(ptent);
			set_pte_at(mm, addr, pte, ptent);
			lazy_mmu_prot_update(ptent);
#ifdef CONFIG_MIGRATION
		} else if (!pte_file(oldpte)) {
			swp_entry_t entry = pte_to_swp_entry(oldpte);

			if (is_write_migration_entry(entry)) {
				/*
				 * A protection check is difficult so
				 * just be safe and disable write
				 */
				make_migration_entry_read(&entry);
				set_pte_at(mm, addr, pte,
					swp_entry_to_pte(entry));
			}
#endif
		}

	} while (pte++, addr += PAGE_SIZE, addr != end);
	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(pte - 1, ptl);
}

static inline void change_pmd_range(struct mm_struct *mm, pud_t *pud,
		unsigned long addr, unsigned long end, pgprot_t newprot,
		int dirty_accountable)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		change_pte_range(mm, pmd, addr, next, newprot, dirty_accountable);
	} while (pmd++, addr = next, addr != end);
}

static inline void change_pud_range(struct mm_struct *mm, pgd_t *pgd,
		unsigned long addr, unsigned long end, pgprot_t newprot,
		int dirty_accountable)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		change_pmd_range(mm, pud, addr, next, newprot, dirty_accountable);
	} while (pud++, addr = next, addr != end);
}

static void change_protection(struct vm_area_struct *vma,
		unsigned long addr, unsigned long end, pgprot_t newprot,
		int dirty_accountable)
{
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	unsigned long next;
	unsigned long start = addr;

	BUG_ON(addr >= end);
	pgd = pgd_offset(mm, addr);
	flush_cache_range(vma, addr, end);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		change_pud_range(mm, pgd, addr, next, newprot, dirty_accountable);
	} while (pgd++, addr = next, addr != end);
	flush_tlb_range(vma, start, end);
}

#ifdef CONFIG_ARCH_TRACK_EXEC_LIMIT
/* called while holding the mmap semaphor for writing */
static inline void establish_user_cs_limit(struct mm_struct *mm, unsigned long start, unsigned long end)
{
	struct vm_area_struct *vma = find_vma(mm, start);

	for (; vma && vma->vm_start < end; vma = vma->vm_next)
		change_protection(vma, vma->vm_start, vma->vm_end, vma->vm_page_prot, vma_wants_writenotify(vma));
}

void track_exec_limit(struct mm_struct *mm, unsigned long start, unsigned long end, unsigned long prot)
{
	unsigned long oldlimit, newlimit = 0UL;

	if (!(mm->pax_flags & MF_PAX_PAGEEXEC) || nx_enabled)
		return;

	spin_lock(&mm->page_table_lock);
	oldlimit = mm->context.user_cs_limit;
	if ((prot & VM_EXEC) && oldlimit < end)
		/* USER_CS limit moved up */
		newlimit = end;
	else if (!(prot & VM_EXEC) && start < oldlimit && oldlimit <= end)
		/* USER_CS limit moved down */
		newlimit = start;

	if (newlimit) {
		mm->context.user_cs_limit = newlimit;

#ifdef CONFIG_SMP
		wmb();
		cpus_clear(mm->context.cpu_user_cs_mask);
		cpu_set(smp_processor_id(), mm->context.cpu_user_cs_mask);
#endif

		set_user_cs(mm->context.user_cs_base, mm->context.user_cs_limit, smp_processor_id());
	}
	spin_unlock(&mm->page_table_lock);
	if (newlimit == end)
		establish_user_cs_limit(mm, oldlimit, end);
}
#endif

int
mprotect_fixup(struct vm_area_struct *vma, struct vm_area_struct **pprev,
	unsigned long start, unsigned long end, unsigned long newflags)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long oldflags = vma->vm_flags;
	long nrpages = (end - start) >> PAGE_SHIFT;
	unsigned long charged = 0;
	pgoff_t pgoff;
	int error;
	int dirty_accountable = 0;

#ifdef CONFIG_PAX_SEGMEXEC
	struct vm_area_struct *vma_m = NULL;
	unsigned long start_m, end_m;

	start_m = start + SEGMEXEC_TASK_SIZE;
	end_m = end + SEGMEXEC_TASK_SIZE;
#endif

	if (newflags == oldflags) {
		*pprev = vma;
		return 0;
	}

#ifdef CONFIG_PAX_SEGMEXEC
	if (pax_find_mirror_vma(vma) && !(newflags & VM_EXEC)) {
		if (start != vma->vm_start) {
			error = split_vma(mm, vma, start, 1);
			if (error)
				return -ENOMEM;
		}

		if (end != vma->vm_end) {
			error = split_vma(mm, vma, end, 0);
			if (error)
				return -ENOMEM;
		}

		error = __do_munmap(mm, start_m, end_m - start_m);
		if (error)
			return -ENOMEM;
	}
#endif

	/*
	 * If we make a private mapping writable we increase our commit;
	 * but (without finer accounting) cannot reduce our commit if we
	 * make it unwritable again.
	 *
	 * FIXME? We haven't defined a VM_NORESERVE flag, so mprotecting
	 * a MAP_NORESERVE private mapping to writable will now reserve.
	 */
	if (newflags & VM_WRITE) {
		if (!(oldflags & (VM_ACCOUNT|VM_WRITE|VM_SHARED))) {
			charged = nrpages;
			if (security_vm_enough_memory(charged))
				return -ENOMEM;
			newflags |= VM_ACCOUNT;
		}
	}

	/*
	 * First try to merge with previous and/or next vma.
	 */
	pgoff = vma->vm_pgoff + ((start - vma->vm_start) >> PAGE_SHIFT);
	*pprev = vma_merge(mm, *pprev, start, end, newflags,
			vma->anon_vma, vma->vm_file, pgoff, vma_policy(vma));
	if (*pprev) {
		vma = *pprev;
		goto success;
	}

	*pprev = vma;

	if (start != vma->vm_start) {
		error = split_vma(mm, vma, start, 1);
		if (error)
			goto fail;
	}

	if (end != vma->vm_end) {
		error = split_vma(mm, vma, end, 0);
		if (error)
			goto fail;
	}

#ifdef CONFIG_PAX_SEGMEXEC
	if ((mm->pax_flags & MF_PAX_SEGMEXEC) && !(oldflags & VM_EXEC) && (newflags & VM_EXEC)) {
		vma_m = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
		if (!vma_m) {
			error = -ENOMEM;
			goto fail;
		}
	}
#endif

success:
	/*
	 * vm_flags and vm_page_prot are protected by the mmap_sem
	 * held in write mode.
	 */
	vma->vm_flags = newflags;
	vma->vm_page_prot = vm_get_page_prot(newflags);
	if (vma_wants_writenotify(vma)) {
		vma->vm_page_prot = vm_get_page_prot(newflags & ~VM_SHARED);
		dirty_accountable = 1;
	}

	if (is_vm_hugetlb_page(vma))
		hugetlb_change_protection(vma, start, end, vma->vm_page_prot);
	else
		change_protection(vma, start, end, vma->vm_page_prot, dirty_accountable);

#ifdef CONFIG_PAX_SEGMEXEC
	if (vma_m)
		pax_mirror_vma(vma_m, vma);
#endif

	vm_stat_account(mm, oldflags, vma->vm_file, -nrpages);
	vm_stat_account(mm, newflags, vma->vm_file, nrpages);
	return 0;

fail:
	vm_unacct_memory(charged);
	return error;
}

#ifdef CONFIG_PAX_MPROTECT
/* PaX: non-PIC ELF libraries need relocations on their executable segments
 * therefore we'll grant them VM_MAYWRITE once during their life.
 *
 * The checks favour ld-linux.so behaviour which operates on a per ELF segment
 * basis because we want to allow the common case and not the special ones.
 */
static inline void pax_handle_maywrite(struct vm_area_struct *vma, unsigned long start)
{
	struct elfhdr elf_h;
	struct elf_phdr elf_p;
	elf_addr_t dyn_offset = 0UL;
	elf_dyn dyn;
	unsigned long i, j = 65536UL / sizeof(struct elf_phdr);

#ifndef CONFIG_PAX_NOELFRELOCS
	if ((vma->vm_start != start) ||
	    !vma->vm_file ||
	    !(vma->vm_flags & VM_MAYEXEC) ||
	    (vma->vm_flags & VM_MAYNOTWRITE))
#endif

		return;

	if (sizeof(elf_h) != kernel_read(vma->vm_file, 0UL, (char *)&elf_h, sizeof(elf_h)) ||
	    memcmp(elf_h.e_ident, ELFMAG, SELFMAG) ||

#ifdef CONFIG_PAX_ETEXECRELOCS
	    (elf_h.e_type != ET_DYN && elf_h.e_type != ET_EXEC) ||
#else
	    elf_h.e_type != ET_DYN ||
#endif

	    !elf_check_arch(&elf_h) ||
	    elf_h.e_phentsize != sizeof(struct elf_phdr) ||
	    elf_h.e_phnum > j)
		return;

	for (i = 0UL; i < elf_h.e_phnum; i++) {
		if (sizeof(elf_p) != kernel_read(vma->vm_file, elf_h.e_phoff + i*sizeof(elf_p), (char *)&elf_p, sizeof(elf_p)))
			return;
		if (elf_p.p_type == PT_DYNAMIC) {
			dyn_offset = elf_p.p_offset;
			j = i;
		}
	}
	if (elf_h.e_phnum <= j)
		return;

	i = 0UL;
	do {
		if (sizeof(dyn) != kernel_read(vma->vm_file, dyn_offset + i*sizeof(dyn), (char *)&dyn, sizeof(dyn)))
			return;
		if (dyn.d_tag == DT_TEXTREL || (dyn.d_tag == DT_FLAGS && (dyn.d_un.d_val & DF_TEXTREL))) {
			vma->vm_flags |= VM_MAYWRITE | VM_MAYNOTWRITE;
			gr_log_textrel(vma);
			return;
		}
		i++;
	} while (dyn.d_tag != DT_NULL);
	return;
}
#endif

asmlinkage long
sys_mprotect(unsigned long start, size_t len, unsigned long prot)
{
	unsigned long vm_flags, nstart, end, tmp, reqprot;
	struct vm_area_struct *vma, *prev;
	int error = -EINVAL;
	const int grows = prot & (PROT_GROWSDOWN|PROT_GROWSUP);
	prot &= ~(PROT_GROWSDOWN|PROT_GROWSUP);
	if (grows == (PROT_GROWSDOWN|PROT_GROWSUP)) /* can't be both */
		return -EINVAL;

	if (start & ~PAGE_MASK)
		return -EINVAL;
	if (!len)
		return 0;
	len = PAGE_ALIGN(len);
	end = start + len;
	if (end <= start)
		return -ENOMEM;

#ifdef CONFIG_PAX_SEGMEXEC
	if (current->mm->pax_flags & MF_PAX_SEGMEXEC) {
		if (end > SEGMEXEC_TASK_SIZE)
			return -EINVAL;
	} else
#endif

	if (end > TASK_SIZE)
		return -EINVAL;

	if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM))
		return -EINVAL;

	reqprot = prot;
	/*
	 * Does the application expect PROT_READ to imply PROT_EXEC:
	 */
	if ((prot & (PROT_READ | PROT_WRITE)) && (current->personality & READ_IMPLIES_EXEC))
		prot |= PROT_EXEC;

	vm_flags = calc_vm_prot_bits(prot);

	down_write(&current->mm->mmap_sem);

	vma = find_vma_prev(current->mm, start, &prev);
	error = -ENOMEM;
	if (!vma)
		goto out;
	if (unlikely(grows & PROT_GROWSDOWN)) {
		if (vma->vm_start >= end)
			goto out;
		start = vma->vm_start;
		error = -EINVAL;
		if (!(vma->vm_flags & VM_GROWSDOWN))
			goto out;
	}
	else {
		if (vma->vm_start > start)
			goto out;
		if (unlikely(grows & PROT_GROWSUP)) {
			end = vma->vm_end;
			error = -EINVAL;
			if (!(vma->vm_flags & VM_GROWSUP))
				goto out;
		}
	}
	if (start > vma->vm_start)
		prev = vma;

	if (!gr_acl_handle_mprotect(vma->vm_file, prot)) {
		error = -EACCES;
		goto out;
	}

#ifdef CONFIG_PAX_MPROTECT
	if ((vma->vm_mm->pax_flags & MF_PAX_MPROTECT) && (prot & PROT_WRITE))
		pax_handle_maywrite(vma, start);
#endif

	for (nstart = start ; ; ) {
		unsigned long newflags;

		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */

		newflags = vm_flags | (vma->vm_flags & ~(VM_READ | VM_WRITE | VM_EXEC));

		/* newflags >> 4 shift VM_MAY% in place of VM_% */
		if ((newflags & ~(newflags >> 4)) & (VM_READ | VM_WRITE | VM_EXEC)) {
			error = -EACCES;
			goto out;
		}

#ifdef CONFIG_PAX_MPROTECT
		/* PaX: disallow write access after relocs are done, hopefully noone else needs it... */
		if ((vma->vm_mm->pax_flags & MF_PAX_MPROTECT) && !(prot & PROT_WRITE) && (vma->vm_flags & VM_MAYNOTWRITE))
			newflags &= ~VM_MAYWRITE;
#endif

		error = security_file_mprotect(vma, reqprot, prot);
		if (error)
			goto out;

		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;
		error = mprotect_fixup(vma, &prev, nstart, tmp, newflags);
		if (error)
			goto out;

		track_exec_limit(current->mm, nstart, tmp, vm_flags);

		nstart = tmp;

		if (nstart < prev->vm_end)
			nstart = prev->vm_end;
		if (nstart >= end)
			goto out;

		vma = prev->vm_next;
		if (!vma || vma->vm_start != nstart) {
			error = -ENOMEM;
			goto out;
		}
	}
out:
	up_write(&current->mm->mmap_sem);
	return error;
}

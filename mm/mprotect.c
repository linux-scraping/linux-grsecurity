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
#include <linux/grsecurity.h>

#ifdef CONFIG_PAX_MPROTECT
#include <linux/elf.h>
#include <linux/fs.h>
#endif

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>

static void change_pte_range(struct mm_struct *mm, pmd_t *pmd,
		unsigned long addr, unsigned long end, pgprot_t newprot)
{
	pte_t *pte;
	spinlock_t *ptl;

	pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	do {
		if (pte_present(*pte)) {
			pte_t ptent;

			/* Avoid an SMP race with hardware updated dirty/clean
			 * bits by wiping the pte and then setting the new pte
			 * into place.
			 */
			ptent = pte_modify(ptep_get_and_clear(mm, addr, pte), newprot);
			set_pte_at(mm, addr, pte, ptent);
			lazy_mmu_prot_update(ptent);
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
	pte_unmap_unlock(pte - 1, ptl);
}

static inline void change_pmd_range(struct mm_struct *mm, pud_t *pud,
		unsigned long addr, unsigned long end, pgprot_t newprot)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		change_pte_range(mm, pmd, addr, next, newprot);
	} while (pmd++, addr = next, addr != end);
}

static inline void change_pud_range(struct mm_struct *mm, pgd_t *pgd,
		unsigned long addr, unsigned long end, pgprot_t newprot)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		change_pmd_range(mm, pud, addr, next, newprot);
	} while (pud++, addr = next, addr != end);
}

static void change_protection(struct vm_area_struct *vma,
		unsigned long addr, unsigned long end, pgprot_t newprot)
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
		change_pud_range(mm, pgd, addr, next, newprot);
	} while (pgd++, addr = next, addr != end);
	flush_tlb_range(vma, start, end);
}

#ifdef CONFIG_ARCH_TRACK_EXEC_LIMIT
/* called while holding the mmap semaphor for writing */
static inline void establish_user_cs_limit(struct mm_struct *mm, unsigned long start, unsigned long end)
{
	struct vm_area_struct *vma = find_vma(mm, start);

	for (; vma && vma->vm_start < end; vma = vma->vm_next)
		change_protection(vma, vma->vm_start, vma->vm_end, vma->vm_page_prot);

}

void track_exec_limit(struct mm_struct *mm, unsigned long start, unsigned long end, unsigned long prot)
{
	unsigned long oldlimit, newlimit = 0UL;

	if (!(mm->pax_flags & MF_PAX_PAGEEXEC))
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

		set_user_cs(mm, smp_processor_id());
	}
	spin_unlock(&mm->page_table_lock);
	if (newlimit == end)
		establish_user_cs_limit(mm, oldlimit, end);
}
#endif

#ifdef CONFIG_PAX_SEGMEXEC
static int __mprotect_fixup(struct vm_area_struct *vma, struct vm_area_struct **pprev,
	unsigned long start, unsigned long end, unsigned int newflags);

static int mprotect_fixup(struct vm_area_struct *vma, struct vm_area_struct **pprev,
	unsigned long start, unsigned long end, unsigned int newflags)
{
	if (vma->vm_flags & VM_MIRROR) {
		struct vm_area_struct * vma_m, * prev_m;
		unsigned long start_m, end_m;
		int error;

		start_m = vma->vm_start + vma->vm_mirror;
		vma_m = find_vma_prev(vma->vm_mm, start_m, &prev_m);
		if (vma_m && vma_m->vm_start == start_m && (vma_m->vm_flags & VM_MIRROR)) {
			start_m = start + vma->vm_mirror;
			end_m = end + vma->vm_mirror;

			if (vma_m->vm_start >= SEGMEXEC_TASK_SIZE && !(newflags & VM_EXEC))
				error = __mprotect_fixup(vma_m, &prev_m, start_m, end_m, vma_m->vm_flags & ~(VM_READ | VM_WRITE | VM_EXEC));
			else
				error = __mprotect_fixup(vma_m, &prev_m, start_m, end_m, newflags);
			if (error)
				return error;
		} else {
			printk("PAX: VMMIRROR: mprotect bug in %s, %08lx\n", current->comm, vma->vm_start);
			return -ENOMEM;
		}
	}

	return __mprotect_fixup(vma, pprev, start, end, newflags);
}

static int __mprotect_fixup(struct vm_area_struct *vma, struct vm_area_struct **pprev,
	unsigned long start, unsigned long end, unsigned int newflags)
{
	struct mm_struct * mm = vma->vm_mm;
	unsigned long oldflags = vma->vm_flags;
	long nrpages = (end - start) >> PAGE_SHIFT;
	unsigned long charged = 0;
	pgprot_t newprot;
	pgoff_t pgoff;
	int error;
#else
static int
mprotect_fixup(struct vm_area_struct *vma, struct vm_area_struct **pprev,
	unsigned long start, unsigned long end, unsigned long newflags)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long oldflags = vma->vm_flags;
	long nrpages = (end - start) >> PAGE_SHIFT;
	unsigned long charged = 0;
	pgprot_t newprot;
	pgoff_t pgoff;
	int error;

	if (newflags == oldflags) {
		*pprev = vma;
		return 0;
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
		if (!(oldflags & (VM_ACCOUNT|VM_WRITE|VM_SHARED|VM_HUGETLB))) {
			charged = nrpages;
			if (security_vm_enough_memory(charged))
				return -ENOMEM;
			newflags |= VM_ACCOUNT;
		}
	}

#ifdef CONFIG_PAX_PAGEEXEC
	if (!(mm->pax_flags & MF_PAX_PAGEEXEC) && (newflags & (VM_READ|VM_WRITE)))
		newprot = protection_map[(newflags | VM_EXEC) & 0xf];
	else
#endif

	newprot = protection_map[newflags & 0xf];

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

success:
	/*
	 * vm_flags and vm_page_prot are protected by the mmap_sem
	 * held in write mode.
	 */
	vma->vm_flags = newflags;
	vma->vm_page_prot = newprot;
	change_protection(vma, start, end, newprot);
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
static inline void pax_handle_maywrite(struct vm_area_struct * vma, unsigned long start)
{
	struct elfhdr elf_h;
	struct elf_phdr elf_p, p_dyn;
	elf_dyn dyn;
	unsigned long i, j = 65536UL / sizeof(struct elf_phdr);

#ifndef CONFIG_PAX_NOELFRELOCS
	if ((vma->vm_start != start) ||
	    !vma->vm_file ||
	    !(vma->vm_flags & VM_MAYEXEC) ||
	    (vma->vm_flags & VM_MAYNOTWRITE))
#endif

		return;

	if (sizeof(elf_h) != kernel_read(vma->vm_file, 0UL, (char*)&elf_h, sizeof(elf_h)) ||
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
		if (sizeof(elf_p) != kernel_read(vma->vm_file, elf_h.e_phoff + i*sizeof(elf_p), (char*)&elf_p, sizeof(elf_p)))
			return;
		if (elf_p.p_type == PT_DYNAMIC) {
			p_dyn = elf_p;
			j = i;
		}
	}
	if (elf_h.e_phnum <= j)
		return;

	i = 0UL;
	do {
		if (sizeof(dyn) != kernel_read(vma->vm_file, p_dyn.p_offset + i*sizeof(dyn), (char*)&dyn, sizeof(dyn)))
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
	if (unlikely((prot & PROT_READ) &&
			(current->personality & READ_IMPLIES_EXEC)))
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

#ifdef CONFIG_PAX_MPROTECT
	if ((vma->vm_mm->pax_flags & MF_PAX_MPROTECT) && (prot & PROT_WRITE))
		pax_handle_maywrite(vma, start);
#endif

	if (!gr_acl_handle_mprotect(vma->vm_file, prot)) {
		error = -EACCES;
		goto out;
	}

	for (nstart = start ; ; ) {
		unsigned long newflags;

		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */

		if (is_vm_hugetlb_page(vma)) {
			error = -EACCES;
			goto out;
		}

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

	track_exec_limit(current->mm, start, end, vm_flags);

out:
	up_write(&current->mm->mmap_sem);
	return error;
}

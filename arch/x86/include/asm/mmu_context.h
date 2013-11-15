#ifndef _ASM_X86_MMU_CONTEXT_H
#define _ASM_X86_MMU_CONTEXT_H

#include <asm/desc.h>
#include <linux/atomic.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/paravirt.h>
#ifndef CONFIG_PARAVIRT
#include <asm-generic/mm_hooks.h>

static inline void paravirt_activate_mm(struct mm_struct *prev,
					struct mm_struct *next)
{
}
#endif	/* !CONFIG_PARAVIRT */

/*
 * Used for LDT copy/destruction.
 */
int init_new_context(struct task_struct *tsk, struct mm_struct *mm);
void destroy_context(struct mm_struct *mm);


static inline void enter_lazy_tlb(struct mm_struct *mm, struct task_struct *tsk)
{

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
	if (!(static_cpu_has(X86_FEATURE_PCID))) {
		unsigned int i;
		pgd_t *pgd;

		pax_open_kernel();
		pgd = get_cpu_pgd(smp_processor_id(), kernel);
		for (i = USER_PGD_PTRS; i < 2 * USER_PGD_PTRS; ++i)
			set_pgd_batched(pgd+i, native_make_pgd(0));
		pax_close_kernel();
	}
#endif

#ifdef CONFIG_SMP
	if (this_cpu_read(cpu_tlbstate.state) == TLBSTATE_OK)
		this_cpu_write(cpu_tlbstate.state, TLBSTATE_LAZY);
#endif
}

static inline void switch_mm(struct mm_struct *prev, struct mm_struct *next,
			     struct task_struct *tsk)
{
	unsigned cpu = smp_processor_id();
#if defined(CONFIG_X86_32) && defined(CONFIG_SMP) && (defined(CONFIG_PAX_PAGEEXEC) || defined(CONFIG_PAX_SEGMEXEC))
	int tlbstate = TLBSTATE_OK;
#endif

	if (likely(prev != next)) {
#ifdef CONFIG_SMP
#if defined(CONFIG_X86_32) && (defined(CONFIG_PAX_PAGEEXEC) || defined(CONFIG_PAX_SEGMEXEC))
		tlbstate = this_cpu_read(cpu_tlbstate.state);
#endif
		this_cpu_write(cpu_tlbstate.state, TLBSTATE_OK);
		this_cpu_write(cpu_tlbstate.active_mm, next);
#endif
		cpumask_set_cpu(cpu, mm_cpumask(next));

		/* Re-load page tables */
#ifdef CONFIG_PAX_PER_CPU_PGD
		pax_open_kernel();

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
		if (static_cpu_has(X86_FEATURE_PCID))
			__clone_user_pgds(get_cpu_pgd(cpu, user), next->pgd);
		else
#endif

		__clone_user_pgds(get_cpu_pgd(cpu, kernel), next->pgd);
		__shadow_user_pgds(get_cpu_pgd(cpu, kernel) + USER_PGD_PTRS, next->pgd);
		pax_close_kernel();
		BUG_ON((__pa(get_cpu_pgd(cpu, kernel)) | PCID_KERNEL) != (read_cr3() & __PHYSICAL_MASK) && (__pa(get_cpu_pgd(cpu, user)) | PCID_USER) != (read_cr3() & __PHYSICAL_MASK));

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
		if (static_cpu_has(X86_FEATURE_PCID)) {
			if (static_cpu_has(X86_FEATURE_INVPCID)) {
				u64 descriptor[2];
				descriptor[0] = PCID_USER;
				asm volatile(__ASM_INVPCID : : "d"(&descriptor), "a"(INVPCID_SINGLE_CONTEXT) : "memory");
				if (!static_cpu_has(X86_FEATURE_STRONGUDEREF)) {
					descriptor[0] = PCID_KERNEL;
					asm volatile(__ASM_INVPCID : : "d"(&descriptor), "a"(INVPCID_SINGLE_CONTEXT) : "memory");
				}
			} else {
				write_cr3(__pa(get_cpu_pgd(cpu, user)) | PCID_USER);
				if (static_cpu_has(X86_FEATURE_STRONGUDEREF))
					write_cr3(__pa(get_cpu_pgd(cpu, kernel)) | PCID_KERNEL | PCID_NOFLUSH);
				else
					write_cr3(__pa(get_cpu_pgd(cpu, kernel)) | PCID_KERNEL);
			}
		} else
#endif

			load_cr3(get_cpu_pgd(cpu, kernel));
#else
		load_cr3(next->pgd);
#endif

		/* Stop flush ipis for the previous mm */
		cpumask_clear_cpu(cpu, mm_cpumask(prev));

		/* Load the LDT, if the LDT is different: */
		if (unlikely(prev->context.ldt != next->context.ldt))
			load_LDT_nolock(&next->context);

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_PAGEEXEC) && defined(CONFIG_SMP)
		if (!(__supported_pte_mask & _PAGE_NX)) {
			smp_mb__before_clear_bit();
			cpu_clear(cpu, prev->context.cpu_user_cs_mask);
			smp_mb__after_clear_bit();
			cpu_set(cpu, next->context.cpu_user_cs_mask);
		}
#endif

#if defined(CONFIG_X86_32) && (defined(CONFIG_PAX_PAGEEXEC) || defined(CONFIG_PAX_SEGMEXEC))
		if (unlikely(prev->context.user_cs_base != next->context.user_cs_base ||
			     prev->context.user_cs_limit != next->context.user_cs_limit))
			set_user_cs(next->context.user_cs_base, next->context.user_cs_limit, cpu);
#ifdef CONFIG_SMP
		else if (unlikely(tlbstate != TLBSTATE_OK))
			set_user_cs(next->context.user_cs_base, next->context.user_cs_limit, cpu);
#endif
#endif

	}
	else {

#ifdef CONFIG_PAX_PER_CPU_PGD
		pax_open_kernel();

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
		if (static_cpu_has(X86_FEATURE_PCID))
			__clone_user_pgds(get_cpu_pgd(cpu, user), next->pgd);
		else
#endif

		__clone_user_pgds(get_cpu_pgd(cpu, kernel), next->pgd);
		__shadow_user_pgds(get_cpu_pgd(cpu, kernel) + USER_PGD_PTRS, next->pgd);
		pax_close_kernel();
		BUG_ON((__pa(get_cpu_pgd(cpu, kernel)) | PCID_KERNEL) != (read_cr3() & __PHYSICAL_MASK) && (__pa(get_cpu_pgd(cpu, user)) | PCID_USER) != (read_cr3() & __PHYSICAL_MASK));

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
		if (static_cpu_has(X86_FEATURE_PCID)) {
			if (static_cpu_has(X86_FEATURE_INVPCID)) {
				u64 descriptor[2];
				descriptor[0] = PCID_USER;
				asm volatile(__ASM_INVPCID : : "d"(&descriptor), "a"(INVPCID_SINGLE_CONTEXT) : "memory");
				if (!static_cpu_has(X86_FEATURE_STRONGUDEREF)) {
					descriptor[0] = PCID_KERNEL;
					asm volatile(__ASM_INVPCID : : "d"(&descriptor), "a"(INVPCID_SINGLE_CONTEXT) : "memory");
				}
			} else {
				write_cr3(__pa(get_cpu_pgd(cpu, user)) | PCID_USER);
				if (static_cpu_has(X86_FEATURE_STRONGUDEREF))
					write_cr3(__pa(get_cpu_pgd(cpu, kernel)) | PCID_KERNEL | PCID_NOFLUSH);
				else
					write_cr3(__pa(get_cpu_pgd(cpu, kernel)) | PCID_KERNEL);
			}
		} else
#endif

			load_cr3(get_cpu_pgd(cpu, kernel));
#endif

#ifdef CONFIG_SMP
		this_cpu_write(cpu_tlbstate.state, TLBSTATE_OK);
		BUG_ON(this_cpu_read(cpu_tlbstate.active_mm) != next);

		if (!cpumask_test_cpu(cpu, mm_cpumask(next))) {
			/*
			 * On established mms, the mm_cpumask is only changed
			 * from irq context, from ptep_clear_flush() while in
			 * lazy tlb mode, and here. Irqs are blocked during
			 * schedule, protecting us from simultaneous changes.
			 */
			cpumask_set_cpu(cpu, mm_cpumask(next));
			/*
			 * We were in lazy tlb mode and leave_mm disabled
			 * tlb flush IPI delivery. We must reload CR3
			 * to make sure to use no freed page tables.
			 */

#ifndef CONFIG_PAX_PER_CPU_PGD
			load_cr3(next->pgd);
#endif

			load_LDT_nolock(&next->context);

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_PAGEEXEC)
			if (!(__supported_pte_mask & _PAGE_NX))
				cpu_set(cpu, next->context.cpu_user_cs_mask);
#endif

#if defined(CONFIG_X86_32) && (defined(CONFIG_PAX_PAGEEXEC) || defined(CONFIG_PAX_SEGMEXEC))
#ifdef CONFIG_PAX_PAGEEXEC
			if (!((next->pax_flags & MF_PAX_PAGEEXEC) && (__supported_pte_mask & _PAGE_NX)))
#endif
				set_user_cs(next->context.user_cs_base, next->context.user_cs_limit, cpu);
#endif

		}
#endif
	}
}

#define activate_mm(prev, next)			\
do {						\
	paravirt_activate_mm((prev), (next));	\
	switch_mm((prev), (next), NULL);	\
} while (0);

#ifdef CONFIG_X86_32
#define deactivate_mm(tsk, mm)			\
do {						\
	lazy_load_gs(0);			\
} while (0)
#else
#define deactivate_mm(tsk, mm)			\
do {						\
	load_gs_index(0);			\
	loadsegment(fs, 0);			\
} while (0)
#endif

#endif /* _ASM_X86_MMU_CONTEXT_H */

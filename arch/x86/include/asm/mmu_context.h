#ifndef _ASM_X86_MMU_CONTEXT_H
#define _ASM_X86_MMU_CONTEXT_H

#include <asm/desc.h>
#include <asm/atomic.h>
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
#ifdef CONFIG_SMP
	if (percpu_read(cpu_tlbstate.state) == TLBSTATE_OK)
		percpu_write(cpu_tlbstate.state, TLBSTATE_LAZY);
#endif
}

static inline void switch_mm(struct mm_struct *prev, struct mm_struct *next,
			     struct task_struct *tsk)
{
	unsigned cpu = smp_processor_id();
#if defined(CONFIG_X86_32) && defined(CONFIG_SMP)
	int tlbstate = TLBSTATE_OK;
#endif

	if (likely(prev != next)) {
		/* stop flush ipis for the previous mm */
		cpumask_clear_cpu(cpu, mm_cpumask(prev));
#ifdef CONFIG_SMP
#ifdef CONFIG_X86_32
		tlbstate = percpu_read(cpu_tlbstate.state);
#endif
		percpu_write(cpu_tlbstate.state, TLBSTATE_OK);
		percpu_write(cpu_tlbstate.active_mm, next);
#endif
		cpumask_set_cpu(cpu, mm_cpumask(next));

		/* Re-load page tables */
		load_cr3(next->pgd);

		/*
		 * load the LDT, if the LDT is different:
		 */
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
#ifdef CONFIG_SMP
	else {
		percpu_write(cpu_tlbstate.state, TLBSTATE_OK);
		BUG_ON(percpu_read(cpu_tlbstate.active_mm) != next);

		if (!cpumask_test_and_set_cpu(cpu, mm_cpumask(next))) {
			/* We were in lazy tlb mode and leave_mm disabled
			 * tlb flush IPI delivery. We must reload CR3
			 * to make sure to use no freed page tables.
			 */
			load_cr3(next->pgd);
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
	}
#endif
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

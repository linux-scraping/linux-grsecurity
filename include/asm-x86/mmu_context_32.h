#ifndef __I386_SCHED_H
#define __I386_SCHED_H

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
	unsigned cpu = smp_processor_id();
	if (per_cpu(cpu_tlbstate, cpu).state == TLBSTATE_OK)
		per_cpu(cpu_tlbstate, cpu).state = TLBSTATE_LAZY;
#endif
}

void leave_mm(unsigned long cpu);

static inline void switch_mm(struct mm_struct *prev,
			     struct mm_struct *next,
			     struct task_struct *tsk)
{
	int cpu = smp_processor_id();

	if (likely(prev != next)) {
		/* stop flush ipis for the previous mm */
		cpu_clear(cpu, prev->cpu_vm_mask);
#ifdef CONFIG_SMP
		per_cpu(cpu_tlbstate, cpu).state = TLBSTATE_OK;
		per_cpu(cpu_tlbstate, cpu).active_mm = next;
#endif
		cpu_set(cpu, next->cpu_vm_mask);

		/* Re-load page tables */
		load_cr3(next->pgd);

		/*
		 * load the LDT, if the LDT is different:
		 */
		if (unlikely(prev->context.ldt != next->context.ldt))
			load_LDT_nolock(&next->context);

#if defined(CONFIG_PAX_PAGEEXEC) && defined(CONFIG_SMP)
		if (!nx_enabled) {
			smp_mb__before_clear_bit();
			cpu_clear(cpu, prev->context.cpu_user_cs_mask);
			smp_mb__after_clear_bit();
			cpu_set(cpu, next->context.cpu_user_cs_mask);
		}
#endif

#if defined(CONFIG_PAX_PAGEEXEC) || defined(CONFIG_PAX_SEGMEXEC)
		if (unlikely(prev->context.user_cs_base != next->context.user_cs_base ||
			     prev->context.user_cs_limit != next->context.user_cs_limit))
			set_user_cs(next->context.user_cs_base, next->context.user_cs_limit, cpu);
#endif

	}
#ifdef CONFIG_SMP
	else {
		per_cpu(cpu_tlbstate, cpu).state = TLBSTATE_OK;
		BUG_ON(per_cpu(cpu_tlbstate, cpu).active_mm != next);

		if (!cpu_test_and_set(cpu, next->cpu_vm_mask)) {
			/* We were in lazy tlb mode and leave_mm disabled 
			 * tlb flush IPI delivery. We must reload %cr3.
			 */
			load_cr3(next->pgd);
			load_LDT_nolock(&next->context);

#ifdef CONFIG_PAX_PAGEEXEC
			if (!nx_enabled)
				cpu_set(cpu, next->context.cpu_user_cs_mask);
#endif

#if defined(CONFIG_PAX_PAGEEXEC) || defined(CONFIG_PAX_SEGMEXEC)
#ifdef CONFIG_PAX_PAGEEXEC
			if (!((next->pax_flags & MF_PAX_PAGEEXEC) && nx_enabled))
#endif
				set_user_cs(next->context.user_cs_base, next->context.user_cs_limit, cpu);
#endif

		}
	}
#endif
}

#define deactivate_mm(tsk, mm)			\
	asm("movl %0,%%gs": :"r" (0));

#define activate_mm(prev, next)				\
	do {						\
		paravirt_activate_mm(prev, next);	\
		switch_mm((prev),(next),NULL);		\
	} while(0);

#endif

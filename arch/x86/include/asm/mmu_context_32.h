#ifndef _ASM_X86_MMU_CONTEXT_32_H
#define _ASM_X86_MMU_CONTEXT_32_H

static inline void enter_lazy_tlb(struct mm_struct *mm, struct task_struct *tsk)
{
#ifdef CONFIG_SMP
	if (x86_read_percpu(cpu_tlbstate.state) == TLBSTATE_OK)
		x86_write_percpu(cpu_tlbstate.state, TLBSTATE_LAZY);
#endif
}

static inline void switch_mm(struct mm_struct *prev,
			     struct mm_struct *next,
			     struct task_struct *tsk)
{
	int cpu = smp_processor_id();
#ifdef CONFIG_SMP
	int tlbstate = TLBSTATE_OK;
#endif

	if (likely(prev != next)) {
		/* stop flush ipis for the previous mm */
		cpu_clear(cpu, prev->cpu_vm_mask);
#ifdef CONFIG_SMP
		tlbstate = x86_read_percpu(cpu_tlbstate.state);
		x86_write_percpu(cpu_tlbstate.state, TLBSTATE_OK);
		x86_write_percpu(cpu_tlbstate.active_mm, next);
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
			     prev->context.user_cs_limit != next->context.user_cs_limit
#ifdef CONFIG_SMP
			     || tlbstate != TLBSTATE_OK
#endif
			    ))
			set_user_cs(next->context.user_cs_base, next->context.user_cs_limit, cpu);
#endif

	}
#ifdef CONFIG_SMP
	else {
		x86_write_percpu(cpu_tlbstate.state, TLBSTATE_OK);
		BUG_ON(x86_read_percpu(cpu_tlbstate.active_mm) != next);

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

#endif /* _ASM_X86_MMU_CONTEXT_32_H */

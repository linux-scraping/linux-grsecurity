#include <linux/module.h>

#include <asm/checksum.h>
#include <asm/pgtable.h>
#include <asm/desc.h>
#include <asm/ftrace.h>

#ifdef CONFIG_FUNCTION_TRACER
/* mcount is defined in assembly */
EXPORT_SYMBOL(mcount);
#endif

/*
 * Note, this is a prototype to get at the symbol for
 * the export, but dont use it from C code, it is used
 * by assembly code and is not using C calling convention!
 */
#ifndef CONFIG_X86_CMPXCHG64
extern void cmpxchg8b_emu(void);
EXPORT_SYMBOL(cmpxchg8b_emu);
#endif

EXPORT_SYMBOL_GPL(cpu_gdt_table);

/* Networking helper routines. */
EXPORT_SYMBOL(csum_partial_copy_generic);
EXPORT_SYMBOL(csum_partial_copy_generic_to_user);
EXPORT_SYMBOL(csum_partial_copy_generic_from_user);

EXPORT_SYMBOL(__get_user_1);
EXPORT_SYMBOL(__get_user_2);
EXPORT_SYMBOL(__get_user_4);
EXPORT_SYMBOL(__get_user_8);

EXPORT_SYMBOL(__put_user_1);
EXPORT_SYMBOL(__put_user_2);
EXPORT_SYMBOL(__put_user_4);
EXPORT_SYMBOL(__put_user_8);

EXPORT_SYMBOL(strstr);

EXPORT_SYMBOL(csum_partial);
EXPORT_SYMBOL(empty_zero_page);

#ifdef CONFIG_PREEMPT
EXPORT_SYMBOL(___preempt_schedule);
#ifdef CONFIG_CONTEXT_TRACKING
EXPORT_SYMBOL(___preempt_schedule_context);
#endif
#endif

#ifdef CONFIG_PAX_KERNEXEC
EXPORT_SYMBOL(__LOAD_PHYSICAL_ADDR);
#endif

#ifdef CONFIG_PAX_PER_CPU_PGD
EXPORT_SYMBOL(cpu_pgd);
#endif

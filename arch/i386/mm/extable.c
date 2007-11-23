/*
 * linux/arch/i386/mm/extable.c
 */

#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/sort.h>
#include <asm/uaccess.h>

/*
 * The exception table needs to be sorted so that the binary
 * search that we use to find entries in it works properly.
 * This is used both for the kernel exception table and for
 * the exception tables of modules that get loaded.
 */
static int cmp_ex(const void *a, const void *b)
{
	const struct exception_table_entry *x = a, *y = b;

	/* avoid overflow */
	if (x->insn > y->insn)
		return 1;
	if (x->insn < y->insn)
		return -1;
	return 0;
}

static void swap_ex(void *a, void *b, int size)
{
	struct exception_table_entry t, *x = a, *y = b;

#ifdef CONFIG_PAX_KERNEXEC
	unsigned long cr0;
#endif

	t = *x;

#ifdef CONFIG_PAX_KERNEXEC
	pax_open_kernel(cr0);
#endif

	*x = *y;
	*y = t;

#ifdef CONFIG_PAX_KERNEXEC
	pax_close_kernel(cr0);
#endif

}

void sort_extable(struct exception_table_entry *start,
		  struct exception_table_entry *finish)
{
	sort(start, finish - start, sizeof(struct exception_table_entry),
	     cmp_ex, swap_ex);
}

int fixup_exception(struct pt_regs *regs)
{
	const struct exception_table_entry *fixup;

#ifdef CONFIG_PNPBIOS
	if (unlikely(!(regs->eflags & VM_MASK) && SEGMENT_IS_PNP_CODE(regs->xcs)))
	{
		extern u32 pnp_bios_fault_eip, pnp_bios_fault_esp;
		extern u32 pnp_bios_is_utter_crap;
		pnp_bios_is_utter_crap = 1;
		printk(KERN_CRIT "PNPBIOS fault.. attempting recovery.\n");
		__asm__ volatile(
			"movl %0, %%esp\n\t"
			"jmp *%1\n\t"
			: : "g" (pnp_bios_fault_esp), "g" (pnp_bios_fault_eip));
		panic("do_trap: can't hit this");
	}
#endif

	fixup = search_exception_tables(regs->eip);
	if (fixup) {
		regs->eip = fixup->fixup;
		return 1;
	}

	return 0;
}

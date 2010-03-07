#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/sort.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>

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

	t = *x;

	pax_open_kernel();
	*x = *y;
	*y = t;
	pax_close_kernel();
}

void sort_extable(struct exception_table_entry *start,
		  struct exception_table_entry *finish)
{
	sort(start, finish - start, sizeof(struct exception_table_entry),
	     cmp_ex, swap_ex);
}

#ifdef CONFIG_MODULES
/*
 * If the exception table is sorted, any referring to the module init
 * will be at the beginning or the end.
 */
void trim_init_extable(struct module *m)
{
	/*trim the beginning*/
	while (m->num_exentries && within_module_init(m->extable[0].insn, m)) {
		m->extable++;
		m->num_exentries--;
	}
	/*trim the end*/
	while (m->num_exentries &&
		within_module_init(m->extable[m->num_exentries-1].insn, m))
		m->num_exentries--;
}
#endif /* CONFIG_MODULES */

int fixup_exception(struct pt_regs *regs)
{
	const struct exception_table_entry *fixup;

#ifdef CONFIG_PNPBIOS
	if (unlikely(!v8086_mode(regs) && SEGMENT_IS_PNP_CODE(regs->cs))) {
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

	fixup = search_exception_tables(regs->ip);
	if (fixup) {
		/* If fixup is less than 16, it means uaccess error */
		if (fixup->fixup < 16) {
			current_thread_info()->uaccess_err = -EFAULT;
			regs->ip += fixup->fixup;
			return 1;
		}
		regs->ip = fixup->fixup;
		return 1;
	}

	return 0;
}

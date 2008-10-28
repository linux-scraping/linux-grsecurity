/*
 * SMP stuff which is common to all sub-architectures.
 */
#include <linux/module.h>
#include <asm/smp.h>
#include <asm/sections.h>

#ifdef CONFIG_X86_32
DEFINE_PER_CPU(unsigned long, this_cpu_off) = (unsigned long)__per_cpu_start;
EXPORT_PER_CPU_SYMBOL(this_cpu_off);

/*
 * Initialize the CPU's GDT.  This is either the boot CPU doing itself
 * (still using the master per-cpu area), or a CPU doing it for a
 * secondary which will soon come up.
 */
__cpuinit void init_gdt(int cpu)
{
	struct desc_struct d, *gdt = get_cpu_gdt_table(cpu);
	unsigned long base, limit;

	base = per_cpu_offset(cpu);
	limit = PERCPU_ENOUGH_ROOM - 1;
	if (limit < 64*1024)
		pack_descriptor(&d, base, limit, 0x80 | DESCTYPE_S | 0x3, 0x4);
	else
		pack_descriptor(&d, base, limit >> PAGE_SHIFT, 0x80 | DESCTYPE_S | 0x3, 0xC);

	write_gdt_entry(gdt, GDT_ENTRY_PERCPU, &d, DESCTYPE_S);

	per_cpu(this_cpu_off, cpu) = base;
	per_cpu(cpu_number, cpu) = cpu;
}
#endif

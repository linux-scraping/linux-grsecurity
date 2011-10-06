/*
 * Extensible Firmware Interface
 *
 * Based on Extensible Firmware Interface Specification version 1.0
 *
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999-2002 Hewlett-Packard Co.
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 *	Stephane Eranian <eranian@hpl.hp.com>
 *
 * All EFI Runtime Services are not implemented yet as EFI only
 * supports physical mode addressing on SoftSDV. This is to be fixed
 * in a future version.  --drummond 1999-07-20
 *
 * Implemented EFI runtime services and virtual mode calls.  --davidm
 *
 * Goutham Rao: <goutham.rao@intel.com>
 *	Skip non-WB memory and ignore empty memory ranges.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/ioport.h>
#include <linux/efi.h>

#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/efi.h>

/*
 * To make EFI call EFI runtime service in physical addressing mode we need
 * prelog/epilog before/after the invocation to disable interrupt, to
 * claim EFI runtime service handler exclusively and to duplicate a memory in
 * low memory space say 0 - 3G.
 */

static unsigned long efi_rt_eflags;
static pgd_t __initdata efi_bak_pg_dir_pointer[KERNEL_PGD_PTRS];

void __init efi_call_phys_prelog(void)
{
	struct desc_ptr gdt_descr;

#ifdef CONFIG_PAX_KERNEXEC
	struct desc_struct d;
#endif

	local_irq_save(efi_rt_eflags);

	clone_pgd_range(efi_bak_pg_dir_pointer, swapper_pg_dir, KERNEL_PGD_PTRS);
	clone_pgd_range(swapper_pg_dir, swapper_pg_dir + KERNEL_PGD_BOUNDARY,
			min_t(unsigned long, KERNEL_PGD_PTRS, KERNEL_PGD_BOUNDARY));

	/*
	 * After the lock is released, the original page table is restored.
	 */
	__flush_tlb_all();

#ifdef CONFIG_PAX_KERNEXEC
	pack_descriptor(&d, 0, 0xFFFFF, 0x9B, 0xC);
	write_gdt_entry(get_cpu_gdt_table(0), GDT_ENTRY_KERNEXEC_EFI_CS, &d, DESCTYPE_S);
	pack_descriptor(&d, 0, 0xFFFFF, 0x93, 0xC);
	write_gdt_entry(get_cpu_gdt_table(0), GDT_ENTRY_KERNEXEC_EFI_DS, &d, DESCTYPE_S);
#endif

	gdt_descr.address = __pa(get_cpu_gdt_table(0));
	gdt_descr.size = GDT_SIZE - 1;
	load_gdt(&gdt_descr);
}

void __init efi_call_phys_epilog(void)
{
	struct desc_ptr gdt_descr;

#ifdef CONFIG_PAX_KERNEXEC
	struct desc_struct d;

	memset(&d, 0, sizeof d);
	write_gdt_entry(get_cpu_gdt_table(0), GDT_ENTRY_KERNEXEC_EFI_CS, &d, DESCTYPE_S);
	write_gdt_entry(get_cpu_gdt_table(0), GDT_ENTRY_KERNEXEC_EFI_DS, &d, DESCTYPE_S);
#endif

	gdt_descr.address = (unsigned long)get_cpu_gdt_table(0);
	gdt_descr.size = GDT_SIZE - 1;
	load_gdt(&gdt_descr);

	clone_pgd_range(swapper_pg_dir, efi_bak_pg_dir_pointer, KERNEL_PGD_PTRS);

	/*
	 * After the lock is released, the original page table is restored.
	 */
	__flush_tlb_all();

	local_irq_restore(efi_rt_eflags);
}

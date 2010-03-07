/*
 * ld script for the x86 kernel
 *
 * Historic 32-bit version written by Martin Mares <mj@atrey.karlin.mff.cuni.cz>
 *
 * Modernisation, unification and other changes and fixes:
 *   Copyright (C) 2007-2009  Sam Ravnborg <sam@ravnborg.org>
 *
 *
 * Don't define absolute symbols until and unless you know that symbol
 * value is should remain constant even if kernel image is relocated
 * at run time. Absolute symbols are not relocated. If symbol value should
 * change if kernel is relocated, make the symbol section relative and
 * put it inside the section definition.
 */

#ifdef CONFIG_X86_32
#define LOAD_OFFSET __PAGE_OFFSET
#else
#define LOAD_OFFSET __START_KERNEL_map
#endif

#include <asm-generic/vmlinux.lds.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/page_types.h>
#include <asm/cache.h>
#include <asm/boot.h>
#include <asm/segment.h>

#undef PMD_SIZE
#undef PMD_SHIFT
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
#define PMD_SHIFT 21
#else
#define PMD_SHIFT 22
#endif
#define PMD_SIZE (1 << PMD_SHIFT)

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_KERNEXEC)
#define __KERNEL_TEXT_OFFSET	(LOAD_OFFSET + ____LOAD_PHYSICAL_ADDR)
#else
#define __KERNEL_TEXT_OFFSET	0
#endif

#undef i386     /* in case the preprocessor is a 32bit one */

OUTPUT_FORMAT(CONFIG_OUTPUT_FORMAT, CONFIG_OUTPUT_FORMAT, CONFIG_OUTPUT_FORMAT)

#ifdef CONFIG_X86_32
OUTPUT_ARCH(i386)
ENTRY(phys_startup_32)
#else
OUTPUT_ARCH(i386:x86-64)
ENTRY(phys_startup_64)
#endif

jiffies = jiffies_64;

#if defined(CONFIG_X86_64) && defined(CONFIG_DEBUG_RODATA)
/*
 * On 64-bit, align RODATA to 2MB so that even with CONFIG_DEBUG_RODATA
 * we retain large page mappings for boundaries spanning kernel text, rodata
 * and data sections.
 *
 * However, kernel identity mappings will have different RWX permissions
 * to the pages mapping to text and to the pages padding (which are freed) the
 * text section. Hence kernel identity mappings will be broken to smaller
 * pages. For 64-bit, kernel text and kernel identity mappings are different,
 * so we can enable protection checks that come with CONFIG_DEBUG_RODATA,
 * as well as retain 2MB large page mappings for kernel text.
 */
#define X64_ALIGN_DEBUG_RODATA_BEGIN	. = ALIGN(HPAGE_SIZE);

#define X64_ALIGN_DEBUG_RODATA_END				\
		. = ALIGN(HPAGE_SIZE);				\
		__end_rodata_hpage_align = .;

#else

#define X64_ALIGN_DEBUG_RODATA_BEGIN
#define X64_ALIGN_DEBUG_RODATA_END

#endif

PHDRS {
	text PT_LOAD FLAGS(5);          /* R_E */
#ifdef CONFIG_XEN
	rodata PT_LOAD FLAGS(5);        /* R_E */
#else
	rodata PT_LOAD FLAGS(4);        /* R__ */
#endif
#ifdef CONFIG_X86_32
	module PT_LOAD FLAGS(5);        /* R_E */
#endif
	data PT_LOAD FLAGS(6);          /* RW_ */
#ifdef CONFIG_X86_64
	user PT_LOAD FLAGS(5);          /* R_E */
#endif
	init.begin PT_LOAD FLAGS(6);    /* RW_ */
#ifdef CONFIG_SMP
	percpu PT_LOAD FLAGS(6);        /* RW_ */
#endif
	text.init PT_LOAD FLAGS(5);     /* R_E */
	text.exit PT_LOAD FLAGS(5);     /* R_E */
	init PT_LOAD FLAGS(7);          /* RWE */
	note PT_NOTE FLAGS(0);          /* ___ */
}

SECTIONS
{
#ifdef CONFIG_X86_32
	. = LOAD_OFFSET + ____LOAD_PHYSICAL_ADDR;
#else
	. = __START_KERNEL;
#endif

	/* Text and read-only data */
	.text (. - __KERNEL_TEXT_OFFSET): AT(ADDR(.text) - LOAD_OFFSET + __KERNEL_TEXT_OFFSET) {
		/* bootstrapping code */
#ifdef CONFIG_X86_32
		phys_startup_32 = startup_32 - LOAD_OFFSET + __KERNEL_TEXT_OFFSET;
#else
		phys_startup_64 = startup_64 - LOAD_OFFSET + __KERNEL_TEXT_OFFSET;
#endif
		__LOAD_PHYSICAL_ADDR = . - LOAD_OFFSET + __KERNEL_TEXT_OFFSET;
		_text = .;
		HEAD_TEXT
#ifdef CONFIG_X86_32
		. = ALIGN(PAGE_SIZE);
		*(.text.page_aligned)
#endif
		. = ALIGN(8);
		_stext = .;
		TEXT_TEXT
		SCHED_TEXT
		LOCK_TEXT
		KPROBES_TEXT
		IRQENTRY_TEXT
		*(.fixup)
		*(.gnu.warning)
	} :text = 0x9090

	. += __KERNEL_TEXT_OFFSET;

	. = ALIGN(PAGE_SIZE);
	NOTES :rodata :note

	EXCEPTION_TABLE(16) :rodata

	X64_ALIGN_DEBUG_RODATA_BEGIN
	RO_DATA(PAGE_SIZE)
	X64_ALIGN_DEBUG_RODATA_END

#ifdef CONFIG_X86_32
	. = ALIGN(PAGE_SIZE);
	.rodata.page_aligned : AT(ADDR(.rodata.page_aligned) - LOAD_OFFSET) {
		*(.idt)
		. = ALIGN(PAGE_SIZE);
		*(.empty_zero_page)
		*(.swapper_pg_pmd)
		*(.swapper_pg_dir)
	}

	. = ALIGN(PAGE_SIZE);
	.vmi.rom : AT(ADDR(.vmi.rom) - LOAD_OFFSET) {
		*(.vmi.rom)
	} :module

	. = ALIGN(PAGE_SIZE);
	.module.text : AT(ADDR(.module.text) - LOAD_OFFSET) {

#if defined(CONFIG_PAX_KERNEXEC) && defined(CONFIG_MODULES)
		MODULES_EXEC_VADDR = .;
		BYTE(0)
		. += (CONFIG_PAX_KERNEXEC_MODULE_TEXT * 1024 * 1024);
		. = ALIGN(PMD_SIZE);
		MODULES_EXEC_END = . - 1;
#endif

	} :module
#endif

	/* Data */
	.data : AT(ADDR(.data) - LOAD_OFFSET) {
		/* End of text section */
		_etext = . - __KERNEL_TEXT_OFFSET;

#ifdef CONFIG_PAX_KERNEXEC
	. = ALIGN(PMD_SIZE);
#else
	. = ALIGN(PAGE_SIZE);
#endif

		/* Start of data section */
		_sdata = .;

		/* init_task */
		INIT_TASK_DATA(THREAD_SIZE)

		NOSAVE_DATA

		PAGE_ALIGNED_DATA(PAGE_SIZE)

		CACHELINE_ALIGNED_DATA(L1_CACHE_BYTES)

		DATA_DATA
		CONSTRUCTORS

		/* rarely changed data like cpu maps */
		READ_MOSTLY_DATA(INTERNODE_CACHE_BYTES)

		/* End of data section */
		_edata = .;
	} :data

#ifdef CONFIG_X86_64

#define VSYSCALL_ADDR (-10*1024*1024)

#define VLOAD_OFFSET (VSYSCALL_ADDR - __vsyscall_0 + LOAD_OFFSET)
#define VLOAD(x) (ADDR(x) - VLOAD_OFFSET)

#define VVIRT_OFFSET (VSYSCALL_ADDR - __vsyscall_0)
#define VVIRT(x) (ADDR(x) - VVIRT_OFFSET)

	. = ALIGN(4096);
	__vsyscall_0 = .;

	. = VSYSCALL_ADDR;
	.vsyscall_0 : AT(VLOAD(.vsyscall_0)) {
		*(.vsyscall_0)
	} :user

	. = ALIGN(L1_CACHE_BYTES);
	.vsyscall_fn : AT(VLOAD(.vsyscall_fn)) {
		*(.vsyscall_fn)
	}

	. = ALIGN(L1_CACHE_BYTES);
	.vsyscall_gtod_data : AT(VLOAD(.vsyscall_gtod_data)) {
		*(.vsyscall_gtod_data)
	}

	vsyscall_gtod_data = VVIRT(.vsyscall_gtod_data);
	.vsyscall_clock : AT(VLOAD(.vsyscall_clock)) {
		*(.vsyscall_clock)
	}
	vsyscall_clock = VVIRT(.vsyscall_clock);


	.vsyscall_1 ADDR(.vsyscall_0) + 1024: AT(VLOAD(.vsyscall_1)) {
		*(.vsyscall_1)
	}
	.vsyscall_2 ADDR(.vsyscall_0) + 2048: AT(VLOAD(.vsyscall_2)) {
		*(.vsyscall_2)
	}

	.vgetcpu_mode : AT(VLOAD(.vgetcpu_mode)) {
		*(.vgetcpu_mode)
	}
	vgetcpu_mode = VVIRT(.vgetcpu_mode);

	.vsyscall_3 ADDR(.vsyscall_0) + 3072: AT(VLOAD(.vsyscall_3)) {
		*(.vsyscall_3)
	}

	. = __vsyscall_0 + PAGE_SIZE;

#undef VSYSCALL_ADDR
#undef VLOAD_OFFSET
#undef VLOAD
#undef VVIRT_OFFSET
#undef VVIRT

#endif /* CONFIG_X86_64 */

	/* Init code and data - will be freed after init */
	.init.begin : AT(ADDR(.init.begin) - LOAD_OFFSET) {
		BYTE(0)

#ifdef CONFIG_PAX_KERNEXEC
		. = ALIGN(PMD_SIZE);
#else
		. = ALIGN(PAGE_SIZE);
#endif

		__init_begin = .; /* paired with __init_end */
	} :init.begin

#ifdef CONFIG_SMP
	/*
	 * percpu offsets are zero-based on SMP.  PERCPU_VADDR() changes the
	 * output PHDR, so the next output section - .init.text - should
	 * start another segment - init.
	 */
	PERCPU_VADDR(0, :percpu)
#endif

	. = ALIGN(PAGE_SIZE);
	init_begin = .;
	.init.text (. - __KERNEL_TEXT_OFFSET): AT(init_begin - LOAD_OFFSET) {
		VMLINUX_SYMBOL(_sinittext) = .;
		INIT_TEXT
		VMLINUX_SYMBOL(_einittext) = .;
		. = ALIGN(PAGE_SIZE);
	} :text.init

	/*
	 * .exit.text is discard at runtime, not link time, to deal with
	 *  references from .altinstructions and .eh_frame
	 */
	.exit.text : AT(ADDR(.exit.text) - LOAD_OFFSET) {
		EXIT_TEXT
		. = ALIGN(16);
	} :text.exit
	. = init_begin + SIZEOF(.init.text) + SIZEOF(.exit.text);

	. = ALIGN(PAGE_SIZE);
	INIT_DATA_SECTION(16) :init

	.x86_cpu_dev.init : AT(ADDR(.x86_cpu_dev.init) - LOAD_OFFSET) {
		__x86_cpu_dev_start = .;
		*(.x86_cpu_dev.init)
		__x86_cpu_dev_end = .;
	}

	. = ALIGN(8);
	.parainstructions : AT(ADDR(.parainstructions) - LOAD_OFFSET) {
		__parainstructions = .;
		*(.parainstructions)
		__parainstructions_end = .;
	}

	. = ALIGN(8);
	.altinstructions : AT(ADDR(.altinstructions) - LOAD_OFFSET) {
		__alt_instructions = .;
		*(.altinstructions)
		__alt_instructions_end = .;
	}

	.altinstr_replacement : AT(ADDR(.altinstr_replacement) - LOAD_OFFSET) {
		*(.altinstr_replacement)
	}

	.exit.data : AT(ADDR(.exit.data) - LOAD_OFFSET) {
		EXIT_DATA
	}

#ifndef CONFIG_SMP
	PERCPU(PAGE_SIZE)
#endif

	. = ALIGN(PAGE_SIZE);

	/* freed after init ends here */
	.init.end : AT(ADDR(.init.end) - LOAD_OFFSET) {
		__init_end = .;
	}

	/*
	 * smp_locks might be freed after init
	 * start/end must be page aligned
	 */
	. = ALIGN(PAGE_SIZE);
	.smp_locks : AT(ADDR(.smp_locks) - LOAD_OFFSET) {
		__smp_locks = .;
		*(.smp_locks)
		__smp_locks_end = .;
		. = ALIGN(PAGE_SIZE);
	}

	/* BSS */
	. = ALIGN(PAGE_SIZE);
	.bss : AT(ADDR(.bss) - LOAD_OFFSET) {
		__bss_start = .;
		*(.bss.page_aligned)
		*(.bss)
		. = ALIGN(4);
		__bss_stop = .;
	}

	. = ALIGN(PAGE_SIZE);
	.brk : AT(ADDR(.brk) - LOAD_OFFSET) {
		__brk_base = .;
		. += 64 * 1024;		/* 64k alignment slop space */
		*(.brk_reservation)	/* areas brk users have reserved */
		. = ALIGN(PMD_SIZE);
		__brk_limit = .;
	}

	_end = .;

        STABS_DEBUG
        DWARF_DEBUG

	/* Sections to be discarded */
	DISCARDS
	/DISCARD/ : { *(.eh_frame) }
}


#ifdef CONFIG_X86_32
/*
 * The ASSERT() sink to . is intentional, for binutils 2.14 compatibility:
 */
. = ASSERT((_end - LOAD_OFFSET <= KERNEL_IMAGE_SIZE),
	   "kernel image bigger than KERNEL_IMAGE_SIZE");
#else
/*
 * Per-cpu symbols which need to be offset from __per_cpu_load
 * for the boot processor.
 */
#define INIT_PER_CPU(x) init_per_cpu__##x = per_cpu__##x + __per_cpu_load
INIT_PER_CPU(irq_stack_union);

/*
 * Build-time check on the image size:
 */
. = ASSERT((_end - _text - __KERNEL_TEXT_OFFSET <= KERNEL_IMAGE_SIZE),
	   "kernel image bigger than KERNEL_IMAGE_SIZE");

#ifdef CONFIG_SMP
. = ASSERT((per_cpu__irq_stack_union == 0),
           "irq_stack_union is not at start of per-cpu area");
#endif

#endif /* CONFIG_X86_32 */

#ifdef CONFIG_KEXEC
#include <asm/kexec.h>

. = ASSERT(kexec_control_code_size <= KEXEC_CONTROL_CODE_MAX_SIZE,
           "kexec control code size is too big");
#endif


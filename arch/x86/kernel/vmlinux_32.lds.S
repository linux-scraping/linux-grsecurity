/* ld script to make i386 Linux kernel
 * Written by Martin Mares <mj@atrey.karlin.mff.cuni.cz>;
 *
 * Don't define absolute symbols until and unless you know that symbol
 * value is should remain constant even if kernel image is relocated
 * at run time. Absolute symbols are not relocated. If symbol value should
 * change if kernel is relocated, make the symbol section relative and
 * put it inside the section definition.
 */

#define LOAD_OFFSET __PAGE_OFFSET

#include <asm-generic/vmlinux.lds.h>
#include <asm/thread_info.h>
#include <asm/page_types.h>
#include <asm/cache.h>
#include <asm/boot.h>
#include <asm/segment.h>

#ifdef CONFIG_X86_PAE
#define PMD_SHIFT 21
#else
#define PMD_SHIFT 22
#endif
#define PMD_SIZE (1 << PMD_SHIFT)

#ifdef CONFIG_PAX_KERNEXEC
#define __KERNEL_TEXT_OFFSET	(__PAGE_OFFSET + (((____LOAD_PHYSICAL_ADDR + 2*(PMD_SIZE - 1)) - 1) & ~(PMD_SIZE - 1)))
#else
#define __KERNEL_TEXT_OFFSET	0
#endif

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(phys_startup_32)
jiffies = jiffies_64;

PHDRS {
	initdata PT_LOAD FLAGS(6);	/* RW_ */
	percpu   PT_LOAD FLAGS(6);	/* RW_ */
	inittext PT_LOAD FLAGS(5);	/* R_E */
	text     PT_LOAD FLAGS(5);	/* R_E */
	rodata   PT_LOAD FLAGS(4);	/* R__ */
	data     PT_LOAD FLAGS(6);	/* RW_ */
	note     PT_NOTE FLAGS(0);	/* ___ */
}
SECTIONS
{
  . = LOAD_OFFSET + ____LOAD_PHYSICAL_ADDR;

  .text.startup : AT(ADDR(.text.startup) - LOAD_OFFSET) {
	__LOAD_PHYSICAL_ADDR = . - LOAD_OFFSET;
	phys_startup_32 = startup_32 - LOAD_OFFSET + __KERNEL_TEXT_OFFSET;
	*(.text.startup)
  } :initdata

  /* might get freed after init */
  . = ALIGN(PAGE_SIZE);
  .smp_locks : AT(ADDR(.smp_locks) - LOAD_OFFSET) {
  	__smp_locks = .;
	*(.smp_locks)
	__smp_locks_end = .;
  }
  /* will be freed after init
   * Following ALIGN() is required to make sure no other data falls on the
   * same page where __smp_alt_end is pointing as that page might be freed
   * after boot. Always make sure that ALIGN() directive is present after
   * the section which contains __smp_alt_end.
   */
  . = ALIGN(PAGE_SIZE);

  /* will be freed after init */
  .init.data : AT(ADDR(.init.data) - LOAD_OFFSET) {
	__init_begin = .;
	INIT_DATA
  }
  . = ALIGN(16);
  .init.setup : AT(ADDR(.init.setup) - LOAD_OFFSET) {
  	__setup_start = .;
	*(.init.setup)
  	__setup_end = .;
   }
  .initcall.init : AT(ADDR(.initcall.init) - LOAD_OFFSET) {
  	__initcall_start = .;
	INITCALLS
  	__initcall_end = .;
  }
  .con_initcall.init : AT(ADDR(.con_initcall.init) - LOAD_OFFSET) {
  	__con_initcall_start = .;
	*(.con_initcall.init)
  	__con_initcall_end = .;
  }
  .x86_cpu_dev.init : AT(ADDR(.x86_cpu_dev.init) - LOAD_OFFSET) {
	__x86_cpu_dev_start = .;
	*(.x86_cpu_dev.init)
	__x86_cpu_dev_end = .;
  }
  SECURITY_INIT
  . = ALIGN(4);
  .altinstructions : AT(ADDR(.altinstructions) - LOAD_OFFSET) {
  	__alt_instructions = .;
	*(.altinstructions)
	__alt_instructions_end = .;
  }
  .altinstr_replacement : AT(ADDR(.altinstr_replacement) - LOAD_OFFSET) {
	*(.altinstr_replacement)
  }
  . = ALIGN(4);
  .parainstructions : AT(ADDR(.parainstructions) - LOAD_OFFSET) {
  	__parainstructions = .;
	*(.parainstructions)
  	__parainstructions_end = .;
  }
  .exit.data : AT(ADDR(.exit.data) - LOAD_OFFSET) {
	EXIT_DATA
  }
#if defined(CONFIG_BLK_DEV_INITRD)
  . = ALIGN(PAGE_SIZE);
  .init.ramfs : AT(ADDR(.init.ramfs) - LOAD_OFFSET) {
	__initramfs_start = .;
	*(.init.ramfs)
	__initramfs_end = .;
  }
#endif
  . = ALIGN(PAGE_SIZE);
  PERCPU_VADDR(0, :percpu)
  . = ALIGN(PAGE_SIZE);
  /* freed after init ends here */

  . = ALIGN(PAGE_SIZE);		/* Init code and data */
  .init.text (. - __KERNEL_TEXT_OFFSET) : AT(ADDR(.init.text) - LOAD_OFFSET + __KERNEL_TEXT_OFFSET) {
	_sinittext = .;
	INIT_TEXT
	_einittext = .;
  } :inittext

  /* .exit.text is discard at runtime, not link time, to deal with references
     from .altinstructions and .eh_frame */
  .exit.text : AT(ADDR(.exit.text) - LOAD_OFFSET + __KERNEL_TEXT_OFFSET) {
	EXIT_TEXT
  }

  .filler : AT(ADDR(.filler) - LOAD_OFFSET + __KERNEL_TEXT_OFFSET) {
	BYTE(0)
	. = ALIGN(2*PMD_SIZE) - 1;
  }

  /* freed after init ends here */

  .text.head : AT(ADDR(.text.head) - LOAD_OFFSET + __KERNEL_TEXT_OFFSET) {
	__init_end = . + __KERNEL_TEXT_OFFSET;
	KERNEL_TEXT_OFFSET = . + __KERNEL_TEXT_OFFSET;
	_text = .;			/* Text and read-only data */
	*(.text.head)
  } :text = 0x9090

  /* read-only */
  .text : AT(ADDR(.text) - LOAD_OFFSET + __KERNEL_TEXT_OFFSET) {
	. = ALIGN(PAGE_SIZE); /* not really needed, already page aligned */
	*(.text.page_aligned)
	TEXT_TEXT
	SCHED_TEXT
	LOCK_TEXT
	KPROBES_TEXT
	IRQENTRY_TEXT
	*(.fixup)
	*(.gnu.warning)
  	_etext = .;			/* End of text section */
  } :text = 0x9090

  . += __KERNEL_TEXT_OFFSET;

  . = ALIGN(4096);
  NOTES :rodata :note

  . = ALIGN(16);		/* Exception table */
  __ex_table : AT(ADDR(__ex_table) - LOAD_OFFSET) {
  	__start___ex_table = .;
	 *(__ex_table)
  	__stop___ex_table = .;
  } :rodata

  RO_DATA(PAGE_SIZE)

  . = ALIGN(PAGE_SIZE);
  .rodata.page_aligned : AT(ADDR(.rodata.page_aligned) - LOAD_OFFSET) {
	*(.idt)
	. = ALIGN(PAGE_SIZE);
	*(.empty_zero_page)
	*(.swapper_pg_pmd)
	*(.swapper_pg_dir)

#if defined(CONFIG_PAX_KERNEXEC) && !defined(CONFIG_MODULES)
	. = ALIGN(PMD_SIZE);
#endif

	}

#if defined(CONFIG_PAX_KERNEXEC) && defined(CONFIG_MODULES)
  . = ALIGN(PAGE_SIZE);
  .module.text : AT(ADDR(.module.text) - LOAD_OFFSET) {
	MODULES_VADDR = .;
	BYTE(0)
	. += (8 * 1024 * 1024);
	. = ALIGN(PMD_SIZE);
	MODULES_END = . - 1;
  }
#endif

  /* writeable */
  . = ALIGN(PAGE_SIZE);
  .data : AT(ADDR(.data) - LOAD_OFFSET) {	/* Data */
	_data = .;
	DATA_DATA
	CONSTRUCTORS
	} :data

  . = ALIGN(PAGE_SIZE);
  .data_nosave : AT(ADDR(.data_nosave) - LOAD_OFFSET) {
  	__nosave_begin = .;
	*(.data.nosave)
  	. = ALIGN(PAGE_SIZE);
  	__nosave_end = .;
  }

  . = ALIGN(PAGE_SIZE);
  .data.page_aligned : AT(ADDR(.data.page_aligned) - LOAD_OFFSET) {
	*(.data.page_aligned)
  }

  . = ALIGN(32);
  .data.cacheline_aligned : AT(ADDR(.data.cacheline_aligned) - LOAD_OFFSET) {
	*(.data.cacheline_aligned)
  }

  /* rarely changed data like cpu maps */
  . = ALIGN(32);
  .data.read_mostly : AT(ADDR(.data.read_mostly) - LOAD_OFFSET) {
	*(.data.read_mostly)
	_edata = .;		/* End of data section */
  }

  . = ALIGN(THREAD_SIZE);	/* init_task */
  .data.init_task : AT(ADDR(.data.init_task) - LOAD_OFFSET) {
	*(.data.init_task)
  }

  .bss : AT(ADDR(.bss) - LOAD_OFFSET) {
	__bss_start = .;		/* BSS */
	*(.bss.page_aligned)
	*(.bss)
	. = ALIGN(4);
	__bss_stop = .;
  }

  .brk : AT(ADDR(.brk) - LOAD_OFFSET) {
	. = ALIGN(PAGE_SIZE);
	__brk_base = . ;
 	. += 64 * 1024 ;	/* 64k alignment slop space */
	*(.brk_reservation)	/* areas brk users have reserved */
	__brk_limit = . ;
  }

  .end : AT(ADDR(.end) - LOAD_OFFSET) {
	_end = . ;
  }

  /* Sections to be discarded */
  /DISCARD/ : {
	*(.exitcall.exit)
	*(.discard)
	}

  STABS_DEBUG

  DWARF_DEBUG
}

/*
 * Build-time check on the image size:
 */
ASSERT((_end - LOAD_OFFSET <= KERNEL_IMAGE_SIZE),
	"kernel image bigger than KERNEL_IMAGE_SIZE")

#ifdef CONFIG_KEXEC
/* Link time checks */
#include <asm/kexec.h>

ASSERT(kexec_control_code_size <= KEXEC_CONTROL_CODE_MAX_SIZE,
       "kexec control code size is too big")
#endif

/*
 *  PowerPC version
 *    Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *
 *  Derived from "arch/i386/mm/fault.c"
 *    Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Modified by Cort Dougan and Paul Mackerras.
 *
 *  Modified for PPC64 by Dave Engebretsen (engebret@ibm.com)
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */

#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kdebug.h>
#include <linux/perf_counter.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/compiler.h>
#include <linux/unistd.h>

#include <asm/firmware.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/mmu.h>
#include <asm/mmu_context.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/tlbflush.h>
#include <asm/siginfo.h>


#ifdef CONFIG_KPROBES
static inline int notify_page_fault(struct pt_regs *regs)
{
	int ret = 0;

	/* kprobe_running() needs smp_processor_id() */
	if (!user_mode(regs)) {
		preempt_disable();
		if (kprobe_running() && kprobe_fault_handler(regs, 11))
			ret = 1;
		preempt_enable();
	}

	return ret;
}
#else
static inline int notify_page_fault(struct pt_regs *regs)
{
	return 0;
}
#endif

#ifdef CONFIG_PAX_EMUSIGRT
void pax_syscall_close(struct vm_area_struct *vma)
{
	vma->vm_mm->call_syscall = 0UL;
}

static int pax_syscall_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	unsigned int *kaddr;

	vmf->page = alloc_page(GFP_HIGHUSER);
	if (!vmf->page)
		return VM_FAULT_OOM;

	kaddr = kmap(vmf->page);
	memset(kaddr, 0, PAGE_SIZE);
	kaddr[0] = 0x44000002U; /* sc */
	__flush_dcache_icache(kaddr);
	kunmap(vmf->page);
	return VM_FAULT_MAJOR;
}

static const struct vm_operations_struct pax_vm_ops = {
	.close = pax_syscall_close,
	.fault = pax_syscall_fault
};

static int pax_insert_vma(struct vm_area_struct *vma, unsigned long addr)
{
	int ret;

	vma->vm_mm = current->mm;
	vma->vm_start = addr;
	vma->vm_end = addr + PAGE_SIZE;
	vma->vm_flags = VM_READ | VM_EXEC | VM_MAYREAD | VM_MAYEXEC;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	vma->vm_ops = &pax_vm_ops;

	ret = insert_vm_struct(current->mm, vma);
	if (ret)
		return ret;

	++current->mm->total_vm;
	return 0;
}
#endif

#ifdef CONFIG_PAX_PAGEEXEC
/*
 * PaX: decide what to do with offenders (regs->nip = fault address)
 *
 * returns 1 when task should be killed
 *         2 when patched GOT trampoline was detected
 *         3 when patched PLT trampoline was detected
 *         4 when unpatched PLT trampoline was detected
 *         5 when sigreturn trampoline was detected
 *         6 when rt_sigreturn trampoline was detected
 */
static int pax_handle_fetch_fault(struct pt_regs *regs)
{

#if defined(CONFIG_PAX_EMUPLT) || defined(CONFIG_PAX_EMUSIGRT)
	int err;
#endif

#ifdef CONFIG_PAX_EMUPLT
	do { /* PaX: patched GOT emulation */
		unsigned int blrl;

		err = get_user(blrl, (unsigned int *)regs->nip);

		if (!err && blrl == 0x4E800021U) {
			unsigned long temp = regs->nip;

			regs->nip = regs->link & 0xFFFFFFFCUL;
			regs->link = temp + 4UL;
			return 2;
		}
	} while (0);

	do { /* PaX: patched PLT emulation #1 */
		unsigned int b;

		err = get_user(b, (unsigned int *)regs->nip);

		if (!err && (b & 0xFC000003U) == 0x48000000U) {
			regs->nip += (((b | 0xFC000000UL) ^ 0x02000000UL) + 0x02000000UL);
			return 3;
		}
	} while (0);

	do { /* PaX: unpatched PLT emulation #1 */
		unsigned int li, b;

		err = get_user(li, (unsigned int *)regs->nip);
		err |= get_user(b, (unsigned int *)(regs->nip+4));

		if (!err && (li & 0xFFFF0000U) == 0x39600000U && (b & 0xFC000003U) == 0x48000000U) {
			unsigned int rlwinm, add, li2, addis2, mtctr, li3, addis3, bctr;
			unsigned long addr = b | 0xFC000000UL;

			addr = regs->nip + 4 + ((addr ^ 0x02000000UL) + 0x02000000UL);
			err = get_user(rlwinm, (unsigned int *)addr);
			err |= get_user(add, (unsigned int *)(addr+4));
			err |= get_user(li2, (unsigned int *)(addr+8));
			err |= get_user(addis2, (unsigned int *)(addr+12));
			err |= get_user(mtctr, (unsigned int *)(addr+16));
			err |= get_user(li3, (unsigned int *)(addr+20));
			err |= get_user(addis3, (unsigned int *)(addr+24));
			err |= get_user(bctr, (unsigned int *)(addr+28));

			if (err)
				break;

			if (rlwinm == 0x556C083CU &&
			    add == 0x7D6C5A14U &&
			    (li2 & 0xFFFF0000U) == 0x39800000U &&
			    (addis2 & 0xFFFF0000U) == 0x3D8C0000U &&
			    mtctr == 0x7D8903A6U &&
			    (li3 & 0xFFFF0000U) == 0x39800000U &&
			    (addis3 & 0xFFFF0000U) == 0x3D8C0000U &&
			    bctr == 0x4E800420U)
			{
				regs->gpr[PT_R11] = 3 * (((li | 0xFFFF0000UL) ^ 0x00008000UL) + 0x00008000UL);
				regs->gpr[PT_R12] = (((li3 | 0xFFFF0000UL) ^ 0x00008000UL) + 0x00008000UL);
				regs->gpr[PT_R12] += (addis3 & 0xFFFFU) << 16;
				regs->ctr = (((li2 | 0xFFFF0000UL) ^ 0x00008000UL) + 0x00008000UL);
				regs->ctr += (addis2 & 0xFFFFU) << 16;
				regs->nip = regs->ctr;
				return 4;
			}
		}
	} while (0);

#if 0
	do { /* PaX: unpatched PLT emulation #2 */
		unsigned int lis, lwzu, b, bctr;

		err = get_user(lis, (unsigned int *)regs->nip);
		err |= get_user(lwzu, (unsigned int *)(regs->nip+4));
		err |= get_user(b, (unsigned int *)(regs->nip+8));
		err |= get_user(bctr, (unsigned int *)(regs->nip+12));

		if (err)
			break;

		if ((lis & 0xFFFF0000U) == 0x39600000U &&
		    (lwzu & 0xU) == 0xU &&
		    (b & 0xFC000003U) == 0x48000000U &&
		    bctr == 0x4E800420U)
		{
			unsigned int addis, addi, rlwinm, add, li2, addis2, mtctr, li3, addis3, bctr;
			unsigned long addr = b | 0xFC000000UL;

			addr = regs->nip + 12 + ((addr ^ 0x02000000UL) + 0x02000000UL);
			err = get_user(addis, (unsigned int *)addr);
			err |= get_user(addi, (unsigned int *)(addr+4));
			err |= get_user(rlwinm, (unsigned int *)(addr+8));
			err |= get_user(add, (unsigned int *)(addr+12));
			err |= get_user(li2, (unsigned int *)(addr+16));
			err |= get_user(addis2, (unsigned int *)(addr+20));
			err |= get_user(mtctr, (unsigned int *)(addr+24));
			err |= get_user(li3, (unsigned int *)(addr+28));
			err |= get_user(addis3, (unsigned int *)(addr+32));
			err |= get_user(bctr, (unsigned int *)(addr+36));

			if (err)
				break;

			if ((addis & 0xFFFF0000U) == 0x3D6B0000U &&
			    (addi & 0xFFFF0000U) == 0x396B0000U &&
			    rlwinm == 0x556C083CU &&
			    add == 0x7D6C5A14U &&
			    (li2 & 0xFFFF0000U) == 0x39800000U &&
			    (addis2 & 0xFFFF0000U) == 0x3D8C0000U &&
			    mtctr == 0x7D8903A6U &&
			    (li3 & 0xFFFF0000U) == 0x39800000U &&
			    (addis3 & 0xFFFF0000U) == 0x3D8C0000U &&
			    bctr == 0x4E800420U)
			{
				regs->gpr[PT_R11] = 3 * (((li | 0xFFFF0000UL) ^ 0x00008000UL) + 0x00008000UL);
				regs->gpr[PT_R12] = (((li3 | 0xFFFF0000UL) ^ 0x00008000UL) + 0x00008000UL);
				regs->gpr[PT_R12] += (addis3 & 0xFFFFU) << 16;
				regs->ctr = (((li2 | 0xFFFF0000UL) ^ 0x00008000UL) + 0x00008000UL);
				regs->ctr += (addis2 & 0xFFFFU) << 16;
				regs->nip = regs->ctr;
				return 4;
			}
		}
	} while (0);
#endif

	do { /* PaX: unpatched PLT emulation #3 */
		unsigned int li, b;

		err = get_user(li, (unsigned int *)regs->nip);
		err |= get_user(b, (unsigned int *)(regs->nip+4));

		if (!err && (li & 0xFFFF0000U) == 0x39600000U && (b & 0xFC000003U) == 0x48000000U) {
			unsigned int addis, lwz, mtctr, bctr;
			unsigned long addr = b | 0xFC000000UL;

			addr = regs->nip + 4 + ((addr ^ 0x02000000UL) + 0x02000000UL);
			err = get_user(addis, (unsigned int *)addr);
			err |= get_user(lwz, (unsigned int *)(addr+4));
			err |= get_user(mtctr, (unsigned int *)(addr+8));
			err |= get_user(bctr, (unsigned int *)(addr+12));

			if (err)
				break;

			if ((addis & 0xFFFF0000U) == 0x3D6B0000U &&
			    (lwz & 0xFFFF0000U) == 0x816B0000U &&
			    mtctr == 0x7D6903A6U &&
			    bctr == 0x4E800420U)
			{
				unsigned int r11;

				addr = (addis << 16) + (((li | 0xFFFF0000UL) ^ 0x00008000UL) + 0x00008000UL);
				addr += (((lwz | 0xFFFF0000UL) ^ 0x00008000UL) + 0x00008000UL);

				err = get_user(r11, (unsigned int *)addr);
				if (err)
					break;

				regs->gpr[PT_R11] = r11;
				regs->ctr = r11;
				regs->nip = r11;
				return 4;
			}
		}
	} while (0);
#endif

#ifdef CONFIG_PAX_EMUSIGRT
	do { /* PaX: sigreturn emulation */
		unsigned int li, sc;

		err = get_user(li, (unsigned int *)regs->nip);
		err |= get_user(sc, (unsigned int *)(regs->nip+4));

		if (!err && li == 0x38000000U + __NR_sigreturn && sc == 0x44000002U) {
			struct vm_area_struct *vma;
			unsigned long call_syscall;

			down_read(&current->mm->mmap_sem);
			call_syscall = current->mm->call_syscall;
			up_read(&current->mm->mmap_sem);
			if (likely(call_syscall))
				goto emulate;

			vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);

			down_write(&current->mm->mmap_sem);
			if (current->mm->call_syscall) {
				call_syscall = current->mm->call_syscall;
				up_write(&current->mm->mmap_sem);
				if (vma)
					kmem_cache_free(vm_area_cachep, vma);
				goto emulate;
			}

			call_syscall = get_unmapped_area(NULL, 0UL, PAGE_SIZE, 0UL, MAP_PRIVATE);
			if (!vma || (call_syscall & ~PAGE_MASK)) {
				up_write(&current->mm->mmap_sem);
				if (vma)
					kmem_cache_free(vm_area_cachep, vma);
				return 1;
			}

			if (pax_insert_vma(vma, call_syscall)) {
				up_write(&current->mm->mmap_sem);
				kmem_cache_free(vm_area_cachep, vma);
				return 1;
			}

			current->mm->call_syscall = call_syscall;
			up_write(&current->mm->mmap_sem);

emulate:
			regs->gpr[PT_R0] = __NR_sigreturn;
			regs->nip = call_syscall;
			return 5;
		}
	} while (0);

	do { /* PaX: rt_sigreturn emulation */
		unsigned int li, sc;

		err = get_user(li, (unsigned int *)regs->nip);
		err |= get_user(sc, (unsigned int *)(regs->nip+4));

		if (!err && li == 0x38000000U + __NR_rt_sigreturn && sc == 0x44000002U) {
			struct vm_area_struct *vma;
			unsigned int call_syscall;

			down_read(&current->mm->mmap_sem);
			call_syscall = current->mm->call_syscall;
			up_read(&current->mm->mmap_sem);
			if (likely(call_syscall))
				goto rt_emulate;

			vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);

			down_write(&current->mm->mmap_sem);
			if (current->mm->call_syscall) {
				call_syscall = current->mm->call_syscall;
				up_write(&current->mm->mmap_sem);
				if (vma)
					kmem_cache_free(vm_area_cachep, vma);
				goto rt_emulate;
			}

			call_syscall = get_unmapped_area(NULL, 0UL, PAGE_SIZE, 0UL, MAP_PRIVATE);
			if (!vma || (call_syscall & ~PAGE_MASK)) {
				up_write(&current->mm->mmap_sem);
				if (vma)
					kmem_cache_free(vm_area_cachep, vma);
				return 1;
			}

			if (pax_insert_vma(vma, call_syscall)) {
				up_write(&current->mm->mmap_sem);
				kmem_cache_free(vm_area_cachep, vma);
				return 1;
			}

			current->mm->call_syscall = call_syscall;
			up_write(&current->mm->mmap_sem);

rt_emulate:
			regs->gpr[PT_R0] = __NR_rt_sigreturn;
			regs->nip = call_syscall;
			return 6;
		}
	} while (0);
#endif

	return 1;
}

void pax_report_insns(void *pc, void *sp)
{
	unsigned long i;

	printk(KERN_ERR "PAX: bytes at PC: ");
	for (i = 0; i < 5; i++) {
		unsigned int c;
		if (get_user(c, (unsigned int *)pc+i))
			printk(KERN_CONT "???????? ");
		else
			printk(KERN_CONT "%08x ", c);
	}
	printk("\n");
}
#endif

/*
 * Check whether the instruction at regs->nip is a store using
 * an update addressing form which will update r1.
 */
static int store_updates_sp(struct pt_regs *regs)
{
	unsigned int inst;

	if (get_user(inst, (unsigned int __user *)regs->nip))
		return 0;
	/* check for 1 in the rA field */
	if (((inst >> 16) & 0x1f) != 1)
		return 0;
	/* check major opcode */
	switch (inst >> 26) {
	case 37:	/* stwu */
	case 39:	/* stbu */
	case 45:	/* sthu */
	case 53:	/* stfsu */
	case 55:	/* stfdu */
		return 1;
	case 62:	/* std or stdu */
		return (inst & 3) == 1;
	case 31:
		/* check minor opcode */
		switch ((inst >> 1) & 0x3ff) {
		case 181:	/* stdux */
		case 183:	/* stwux */
		case 247:	/* stbux */
		case 439:	/* sthux */
		case 695:	/* stfsux */
		case 759:	/* stfdux */
			return 1;
		}
	}
	return 0;
}

/*
 * For 600- and 800-family processors, the error_code parameter is DSISR
 * for a data fault, SRR1 for an instruction fault. For 400-family processors
 * the error_code parameter is ESR for a data fault, 0 for an instruction
 * fault.
 * For 64-bit processors, the error_code parameter is
 *  - DSISR for a non-SLB data access fault,
 *  - SRR1 & 0x08000000 for a non-SLB instruction access fault
 *  - 0 any SLB fault.
 *
 * The return value is 0 if the fault was handled, or the signal
 * number if this is a kernel fault that can't be handled here.
 */
int __kprobes do_page_fault(struct pt_regs *regs, unsigned long address,
			    unsigned long error_code)
{
	struct vm_area_struct * vma;
	struct mm_struct *mm = current->mm;
	siginfo_t info;
	int code = SEGV_MAPERR;
	int is_write = 0, ret;
	int trap = TRAP(regs);
 	int is_exec = trap == 0x400;

#if !(defined(CONFIG_4xx) || defined(CONFIG_BOOKE))
	/*
	 * Fortunately the bit assignments in SRR1 for an instruction
	 * fault and DSISR for a data fault are mostly the same for the
	 * bits we are interested in.  But there are some bits which
	 * indicate errors in DSISR but can validly be set in SRR1.
	 */
	if (trap == 0x400)
		error_code &= 0x58200000;
	else
		is_write = error_code & DSISR_ISSTORE;
#else
	is_write = error_code & ESR_DST;
#endif /* CONFIG_4xx || CONFIG_BOOKE */

	if (notify_page_fault(regs))
		return 0;

	if (unlikely(debugger_fault_handler(regs)))
		return 0;

	/* On a kernel SLB miss we can only check for a valid exception entry */
	if (!user_mode(regs) && (address >= TASK_SIZE))
		return SIGSEGV;

#if !(defined(CONFIG_4xx) || defined(CONFIG_BOOKE))
  	if (error_code & DSISR_DABRMATCH) {
		/* DABR match */
		do_dabr(regs, address, error_code);
		return 0;
	}
#endif /* !(CONFIG_4xx || CONFIG_BOOKE)*/

	if (in_atomic() || mm == NULL) {
		if (!user_mode(regs))
			return SIGSEGV;
		/* in_atomic() in user mode is really bad,
		   as is current->mm == NULL. */
		printk(KERN_EMERG "Page fault in user mode with "
		       "in_atomic() = %d mm = %p\n", in_atomic(), mm);
		printk(KERN_EMERG "NIP = %lx  MSR = %lx\n",
		       regs->nip, regs->msr);
		die("Weird page fault", regs, SIGSEGV);
	}

	perf_swcounter_event(PERF_COUNT_SW_PAGE_FAULTS, 1, 0, regs, address);

	/* When running in the kernel we expect faults to occur only to
	 * addresses in user space.  All other faults represent errors in the
	 * kernel and should generate an OOPS.  Unfortunately, in the case of an
	 * erroneous fault occurring in a code path which already holds mmap_sem
	 * we will deadlock attempting to validate the fault against the
	 * address space.  Luckily the kernel only validly references user
	 * space from well defined areas of code, which are listed in the
	 * exceptions table.
	 *
	 * As the vast majority of faults will be valid we will only perform
	 * the source reference check when there is a possibility of a deadlock.
	 * Attempt to lock the address space, if we cannot we then validate the
	 * source.  If this is invalid we can skip the address space check,
	 * thus avoiding the deadlock.
	 */
	if (!down_read_trylock(&mm->mmap_sem)) {
		if (!user_mode(regs) && !search_exception_tables(regs->nip))
			goto bad_area_nosemaphore;

		down_read(&mm->mmap_sem);
	}

	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;
	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;

	/*
	 * N.B. The POWER/Open ABI allows programs to access up to
	 * 288 bytes below the stack pointer.
	 * The kernel signal delivery code writes up to about 1.5kB
	 * below the stack pointer (r1) before decrementing it.
	 * The exec code can write slightly over 640kB to the stack
	 * before setting the user r1.  Thus we allow the stack to
	 * expand to 1MB without further checks.
	 */
	if (address + 0x100000 < vma->vm_end) {
		/* get user regs even if this fault is in kernel mode */
		struct pt_regs *uregs = current->thread.regs;
		if (uregs == NULL)
			goto bad_area;

		/*
		 * A user-mode access to an address a long way below
		 * the stack pointer is only valid if the instruction
		 * is one which would update the stack pointer to the
		 * address accessed if the instruction completed,
		 * i.e. either stwu rs,n(r1) or stwux rs,r1,rb
		 * (or the byte, halfword, float or double forms).
		 *
		 * If we don't check this then any write to the area
		 * between the last mapped region and the stack will
		 * expand the stack rather than segfaulting.
		 */
		if (address + 2048 < uregs->gpr[1]
		    && (!user_mode(regs) || !store_updates_sp(regs)))
			goto bad_area;
	}
	if (expand_stack(vma, address))
		goto bad_area;

good_area:
	code = SEGV_ACCERR;
#if defined(CONFIG_6xx)
	if (error_code & 0x95700000)
		/* an error such as lwarx to I/O controller space,
		   address matching DABR, eciwx, etc. */
		goto bad_area;
#endif /* CONFIG_6xx */
#if defined(CONFIG_8xx)
        /* The MPC8xx seems to always set 0x80000000, which is
         * "undefined".  Of those that can be set, this is the only
         * one which seems bad.
         */
	if (error_code & 0x10000000)
                /* Guarded storage error. */
		goto bad_area;
#endif /* CONFIG_8xx */

	if (is_exec) {
#ifdef CONFIG_PPC_STD_MMU
		/* Protection fault on exec go straight to failure on
		 * Hash based MMUs as they either don't support per-page
		 * execute permission, or if they do, it's handled already
		 * at the hash level. This test would probably have to
		 * be removed if we change the way this works to make hash
		 * processors use the same I/D cache coherency mechanism
		 * as embedded.
		 */
		if (error_code & DSISR_PROTFAULT)
			goto bad_area;
#endif /* CONFIG_PPC_STD_MMU */

		/*
		 * Allow execution from readable areas if the MMU does not
		 * provide separate controls over reading and executing.
		 *
		 * Note: That code used to not be enabled for 4xx/BookE.
		 * It is now as I/D cache coherency for these is done at
		 * set_pte_at() time and I see no reason why the test
		 * below wouldn't be valid on those processors. This -may-
		 * break programs compiled with a really old ABI though.
		 */
		if (!(vma->vm_flags & VM_EXEC) &&
		    (cpu_has_feature(CPU_FTR_NOEXECUTE) ||
		     !(vma->vm_flags & (VM_READ | VM_WRITE))))
			goto bad_area;
	/* a write */
	} else if (is_write) {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
	/* a read */
	} else {
		/* protection fault */
		if (error_code & 0x08000000)
			goto bad_area;
		if (!(vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE)))
			goto bad_area;
	}

	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
 survive:
	ret = handle_mm_fault(mm, vma, address, is_write ? FAULT_FLAG_WRITE : 0);
	if (unlikely(ret & VM_FAULT_ERROR)) {
		if (ret & VM_FAULT_OOM)
			goto out_of_memory;
		else if (ret & VM_FAULT_SIGBUS)
			goto do_sigbus;
		BUG();
	}
	if (ret & VM_FAULT_MAJOR) {
		current->maj_flt++;
		perf_swcounter_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1, 0,
				     regs, address);
#ifdef CONFIG_PPC_SMLPAR
		if (firmware_has_feature(FW_FEATURE_CMO)) {
			preempt_disable();
			get_lppaca()->page_ins += (1 << PAGE_FACTOR);
			preempt_enable();
		}
#endif
	} else {
		current->min_flt++;
		perf_swcounter_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1, 0,
				     regs, address);
	}
	up_read(&mm->mmap_sem);
	return 0;

bad_area:
	up_read(&mm->mmap_sem);

bad_area_nosemaphore:
	/* User mode accesses cause a SIGSEGV */
	if (user_mode(regs)) {

#ifdef CONFIG_PAX_PAGEEXEC
		if (mm->pax_flags & MF_PAX_PAGEEXEC) {
#ifdef CONFIG_PPC64
			if (is_exec && (error_code & DSISR_PROTFAULT)) {
#else
			if (is_exec && regs->nip == address) {
#endif
				switch (pax_handle_fetch_fault(regs)) {

#ifdef CONFIG_PAX_EMUPLT
				case 2:
				case 3:
				case 4:
					return 0;
#endif

#ifdef CONFIG_PAX_EMUSIGRT
				case 5:
				case 6:
					return 0;
#endif

				}

				pax_report_fault(regs, (void *)regs->nip, (void *)regs->gpr[PT_R1]);
				do_group_exit(SIGKILL);
			}
		}
#endif

		_exception(SIGSEGV, regs, code, address);
		return 0;
	}

	if (is_exec && (error_code & DSISR_PROTFAULT)
	    && printk_ratelimit())
		printk(KERN_CRIT "kernel tried to execute NX-protected"
		       " page (%lx) - exploit attempt? (uid: %d)\n",
		       address, current_uid());

	return SIGSEGV;

/*
 * We ran out of memory, or some other thing happened to us that made
 * us unable to handle the page fault gracefully.
 */
out_of_memory:
	up_read(&mm->mmap_sem);
	if (is_global_init(current)) {
		yield();
		down_read(&mm->mmap_sem);
		goto survive;
	}
	printk("VM: killing process %s\n", current->comm);
	if (user_mode(regs))
		do_group_exit(SIGKILL);
	return SIGKILL;

do_sigbus:
	up_read(&mm->mmap_sem);
	if (user_mode(regs)) {
		info.si_signo = SIGBUS;
		info.si_errno = 0;
		info.si_code = BUS_ADRERR;
		info.si_addr = (void __user *)address;
		force_sig_info(SIGBUS, &info, current);
		return 0;
	}
	return SIGBUS;
}

/*
 * bad_page_fault is called when we have a bad access from the kernel.
 * It is called from the DSI and ISI handlers in head.S and from some
 * of the procedures in traps.c.
 */
void bad_page_fault(struct pt_regs *regs, unsigned long address, int sig)
{
	const struct exception_table_entry *entry;

	/* Are we prepared to handle this fault?  */
	if ((entry = search_exception_tables(regs->nip)) != NULL) {
		regs->nip = entry->fixup;
		return;
	}

	/* kernel has accessed a bad area */

	switch (regs->trap) {
	case 0x300:
	case 0x380:
		printk(KERN_ALERT "Unable to handle kernel paging request for "
			"data at address 0x%08lx\n", regs->dar);
		break;
	case 0x400:
	case 0x480:
		printk(KERN_ALERT "Unable to handle kernel paging request for "
			"instruction fetch\n");
		break;
	default:
		printk(KERN_ALERT "Unable to handle kernel paging request for "
			"unknown fault\n");
		break;
	}
	printk(KERN_ALERT "Faulting instruction address: 0x%08lx\n",
		regs->nip);

	die("Kernel access of bad area", regs, sig);
}

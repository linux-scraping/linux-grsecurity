/*
 *  linux/arch/i386/mm/fault.c
 *
 *  Copyright (C) 1995  Linus Torvalds
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
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/vt_kern.h>		/* For unblank_screen() */
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/unistd.h>
#include <linux/compiler.h>
#include <linux/binfmts.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/desc.h>
#include <asm/kdebug.h>

extern void die(const char *,struct pt_regs *,long);

/*
 * Unlock any spinlocks which will prevent us from getting the
 * message out 
 */
void bust_spinlocks(int yes)
{
	int loglevel_save = console_loglevel;

	if (yes) {
		oops_in_progress = 1;
		return;
	}
#ifdef CONFIG_VT
	unblank_screen();
#endif
	oops_in_progress = 0;
	/*
	 * OK, the message is on the console.  Now we call printk()
	 * without oops_in_progress set so that printk will give klogd
	 * a poke.  Hold onto your hats...
	 */
	console_loglevel = 15;		/* NMI oopser may have shut the console up */
	printk(" ");
	console_loglevel = loglevel_save;
}

/*
 * Return EIP plus the CS segment base.  The segment limit is also
 * adjusted, clamped to the kernel/user address space (whichever is
 * appropriate), and returned in *eip_limit.
 *
 * The segment is checked, because it might have been changed by another
 * task between the original faulting instruction and here.
 *
 * If CS is no longer a valid code segment, or if EIP is beyond the
 * limit, or if it is a kernel address when CS is not a kernel segment,
 * then the returned value will be greater than *eip_limit.
 * 
 * This is slow, but is very rarely executed.
 */
static inline unsigned long get_segment_eip(struct pt_regs *regs,
					    unsigned long *eip_limit)
{
	unsigned long eip = regs->eip;
	unsigned seg = regs->xcs & 0xffff;
	u32 seg_ar, seg_limit, base, *desc;

	/* The standard kernel/user address space limit. */
	*eip_limit = (seg & 3) ? USER_DS.seg : KERNEL_DS.seg;

	/* Unlikely, but must come before segment checks. */
	if (unlikely((regs->eflags & VM_MASK) != 0))
		return (eip & 0xFFFF) + (seg << 4);
	
	/* By far the most common cases. */
	if (likely(seg == __USER_CS))
		return eip;
	if (likely(seg == __KERNEL_CS))
		return eip + __KERNEL_TEXT_OFFSET;

	/* Check the segment exists, is within the current LDT/GDT size,
	   that kernel/user (ring 0..3) has the appropriate privilege,
	   that it's a code segment, and get the limit. */
	__asm__ ("larl %3,%0; lsll %3,%1"
		 : "=&r" (seg_ar), "=r" (seg_limit) : "0" (0), "rm" (seg));
	if ((~seg_ar & 0x9800) || eip > seg_limit) {
		*eip_limit = 0;
		return 1;	 /* So that returned eip > *eip_limit. */
	}

	/* Get the GDT/LDT descriptor base. 
	   When you look for races in this code remember that
	   LDT and other horrors are only used in user space. */
	if (seg & (1<<2)) {
		/* Must lock the LDT while reading it. */
		down(&current->mm->context.sem);
		desc = current->mm->context.ldt;
		desc = (void *)desc + (seg & ~7);
	} else {
		/* Must disable preemption while reading the GDT. */
		desc = (u32 *)get_cpu_gdt_table(get_cpu());
		desc = (void *)desc + (seg & ~7);
	}

	/* Decode the code segment base from the descriptor */
	base = get_desc_base((unsigned long *)desc);

	if (seg & (1<<2)) { 
		up(&current->mm->context.sem);
	} else
		put_cpu();

	/* Adjust EIP and segment limit, and clamp at the kernel limit.
	   It's legitimate for segments to wrap at 0xffffffff. */
	seg_limit += base;
	if (seg_limit < *eip_limit && seg_limit >= base)
		*eip_limit = seg_limit;
	return eip + base;
}

/* 
 * Sometimes AMD Athlon/Opteron CPUs report invalid exceptions on prefetch.
 * Check that here and ignore it.
 */
static int __is_prefetch(struct pt_regs *regs, unsigned long addr)
{ 
	unsigned long limit;
	unsigned long instr = get_segment_eip (regs, &limit);
	int scan_more = 1;
	int prefetch = 0; 
	int i;

	for (i = 0; scan_more && i < 15; i++) { 
		unsigned char opcode;
		unsigned char instr_hi;
		unsigned char instr_lo;

		if (instr > limit)
			break;
		if (__get_user(opcode, (unsigned char __user *) instr))
			break; 

		instr_hi = opcode & 0xf0; 
		instr_lo = opcode & 0x0f; 
		instr++;

		switch (instr_hi) { 
		case 0x20:
		case 0x30:
			/* Values 0x26,0x2E,0x36,0x3E are valid x86 prefixes. */
			scan_more = ((instr_lo & 7) == 0x6);
			break;
			
		case 0x60:
			/* 0x64 thru 0x67 are valid prefixes in all modes. */
			scan_more = (instr_lo & 0xC) == 0x4;
			break;		
		case 0xF0:
			/* 0xF0, 0xF2, and 0xF3 are valid prefixes */
			scan_more = !instr_lo || (instr_lo>>1) == 1;
			break;			
		case 0x00:
			/* Prefetch instruction is 0x0F0D or 0x0F18 */
			scan_more = 0;
			if (instr > limit)
				break;
			if (__get_user(opcode, (unsigned char __user *) instr))
				break;
			prefetch = (instr_lo == 0xF) &&
				(opcode == 0x0D || opcode == 0x18);
			break;			
		default:
			scan_more = 0;
			break;
		} 
	}
	return prefetch;
}

static inline int is_prefetch(struct pt_regs *regs, unsigned long addr,
			      unsigned long error_code)
{
	if (unlikely(boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
		     boot_cpu_data.x86 >= 6)) {
		/* Catch an obscure case of prefetch inside an NX page. */
		if (nx_enabled && (error_code & 16))
			return 0;
		return __is_prefetch(regs, addr);
	}
	return 0;
} 

static noinline void force_sig_info_fault(int si_signo, int si_code,
	unsigned long address, struct task_struct *tsk)
{
	siginfo_t info;

	info.si_signo = si_signo;
	info.si_errno = 0;
	info.si_code = si_code;
	info.si_addr = (void __user *)address;
	force_sig_info(si_signo, &info, tsk);
}

fastcall void do_invalid_op(struct pt_regs *, unsigned long);

#if defined(CONFIG_PAX_PAGEEXEC) || defined(CONFIG_PAX_SEGMEXEC)
static int pax_handle_fetch_fault(struct pt_regs *regs);
#endif

#ifdef CONFIG_PAX_PAGEEXEC
static inline pmd_t * pax_get_pmd(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		return NULL;
	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return NULL;
	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return NULL;
	return pmd;
}
#endif

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 *
 * error_code:
 *	bit 0 == 0 means no page found, 1 means protection fault
 *	bit 1 == 0 means read, 1 means write
 *	bit 2 == 0 means kernel, 1 means user-mode
 */
fastcall void __kprobes do_page_fault(struct pt_regs *regs,
				      unsigned long error_code)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct * vma;
	unsigned long address;
	int write, si_code;

#ifdef CONFIG_PAX_PAGEEXEC
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	unsigned char pte_mask;
#endif

	/* get the address */
        address = read_cr2();

	if (notify_die(DIE_PAGE_FAULT, "page fault", regs, error_code, 14,
					SIGSEGV) == NOTIFY_STOP)
		return;
	/* It's safe to allow irq's after cr2 has been saved */
	if (regs->eflags & (X86_EFLAGS_IF|VM_MASK))
		local_irq_enable();

	tsk = current;
	mm = tsk->mm;

	si_code = SEGV_MAPERR;

	/*
	 * We fault-in kernel-space virtual memory on-demand. The
	 * 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 *
	 * This verifies that the fault happens in kernel space
	 * (error_code & 4) == 0, and that the fault was not a
	 * protection error (error_code & 1) == 0.
	 */
	if (unlikely(address >= TASK_SIZE)) { 
		if (!(error_code & 5))
			goto vmalloc_fault;
		/* 
		 * Don't take the mm semaphore here. If we fixup a prefetch
		 * fault we could otherwise deadlock.
		 */
		goto bad_area_nosemaphore;
	} 

	/*
	 * If we're in an interrupt, have no user context or are running in an
	 * atomic region then we must not take the fault..
	 */
	if (in_atomic() || !mm)
		goto bad_area_nopax;

	/* When running in the kernel we expect faults to occur only to
	 * addresses in user space.  All other faults represent errors in the
	 * kernel and should generate an OOPS.  Unfortunatly, in the case of an
	 * erroneous fault occuring in a code path which already holds mmap_sem
	 * we will deadlock attempting to validate the fault against the
	 * address space.  Luckily the kernel only validly references user
	 * space from well defined areas of code, which are listed in the
	 * exceptions table.
	 *
	 * As the vast majority of faults will be valid we will only perform
	 * the source reference check when there is a possibilty of a deadlock.
	 * Attempt to lock the address space, if we cannot we then validate the
	 * source.  If this is invalid we can skip the address space check,
	 * thus avoiding the deadlock.
	 */
	if (!down_read_trylock(&mm->mmap_sem)) {
		if ((error_code & 4) == 0 &&
		    !search_exception_tables(regs->eip))
			goto bad_area_nopax;
		down_read(&mm->mmap_sem);
	}

#ifdef CONFIG_PAX_PAGEEXEC
	if (unlikely((error_code & 5) != 5 ||
		     (regs->eflags & X86_EFLAGS_VM) ||
		     !(mm->pax_flags & MF_PAX_PAGEEXEC)))
		goto not_pax_fault;

	/* PaX: it's our fault, let's handle it if we can */

	/* PaX: take a look at read faults before acquiring any locks */
	if (unlikely(!(error_code & 2) && (regs->eip == address))) {
		/* instruction fetch attempt from a protected page in user mode */
		up_read(&mm->mmap_sem);
		switch (pax_handle_fetch_fault(regs)) {

#ifdef CONFIG_PAX_EMUTRAMP
		case 2:
			return;
#endif

		}
		pax_report_fault(regs, (void*)regs->eip, (void*)regs->esp);
		do_exit(SIGKILL);
	}

	pmd = pax_get_pmd(mm, address);
	if (unlikely(!pmd))
		goto not_pax_fault;

	pte = pte_offset_map_lock(mm, pmd, address, &ptl);
	if (unlikely(!(pte_val(*pte) & _PAGE_PRESENT) || pte_user(*pte))) {
		pte_unmap_unlock(pte, ptl);
		goto not_pax_fault;
	}

	if (unlikely((error_code & 2) && !pte_write(*pte))) {
		/* write attempt to a protected page in user mode */
		pte_unmap_unlock(pte, ptl);
		goto not_pax_fault;
	}

#ifdef CONFIG_SMP
	if (likely(address > get_limit(regs->xcs) && cpu_isset(smp_processor_id(), mm->context.cpu_user_cs_mask)))
#else
	if (likely(address > get_limit(regs->xcs)))
#endif
	{
		set_pte(pte, pte_mkread(*pte));
		__flush_tlb_one(address);
		pte_unmap_unlock(pte, ptl);
		up_read(&mm->mmap_sem);
		return;
	}

	pte_mask = _PAGE_ACCESSED | _PAGE_USER | ((error_code & 2) << (_PAGE_BIT_DIRTY-1));

	/*
	 * PaX: fill DTLB with user rights and retry
	 */
	__asm__ __volatile__ (
		"orb %2,%1\n"
#if defined(CONFIG_M586) || defined(CONFIG_M586TSC)
/*
 * PaX: let this uncommented 'invlpg' remind us on the behaviour of Intel's
 * (and AMD's) TLBs. namely, they do not cache PTEs that would raise *any*
 * page fault when examined during a TLB load attempt. this is true not only
 * for PTEs holding a non-present entry but also present entries that will
 * raise a page fault (such as those set up by PaX, or the copy-on-write
 * mechanism). in effect it means that we do *not* need to flush the TLBs
 * for our target pages since their PTEs are simply not in the TLBs at all.

 * the best thing in omitting it is that we gain around 15-20% speed in the
 * fast path of the page fault handler and can get rid of tracing since we
 * can no longer flush unintended entries.
 */
		"invlpg %0\n"
#endif
		"testb $0,%0\n"
		"xorb %3,%1\n"
		:
		: "m" (*(char*)address), "m" (*(char*)pte), "q" (pte_mask), "i" (_PAGE_USER)
		: "memory", "cc");
	pte_unmap_unlock(pte, ptl);
	up_read(&mm->mmap_sem);
	return;

not_pax_fault:
#endif

	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;
	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	if (error_code & 4) {
		/*
		 * accessing the stack below %esp is always a bug.
		 * The "+ 32" is there due to some instructions (like
		 * pusha) doing post-decrement on the stack and that
		 * doesn't show up until later..
		 */
		if (address + 32 < regs->esp)
			goto bad_area;
	}
	if (expand_stack(vma, address))
		goto bad_area;
/*
 * Ok, we have a good vm_area for this memory access, so
 * we can handle it..
 */
good_area:
	si_code = SEGV_ACCERR;
	write = 0;
	switch (error_code & 3) {
		default:	/* 3: write, present */
#ifdef TEST_VERIFY_AREA
			if (regs->cs == KERNEL_CS)
				printk("WP fault at %08lx\n", regs->eip);
#endif
			/* fall through */
		case 2:		/* write, not present */
			if (!(vma->vm_flags & VM_WRITE))
				goto bad_area;
			write++;
			break;
		case 1:		/* read, present */
			goto bad_area;
		case 0:		/* read, not present */
			if (!(vma->vm_flags & (VM_READ | VM_EXEC)))
				goto bad_area;
	}

 survive:
	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
	switch (handle_mm_fault(mm, vma, address, write)) {
		case VM_FAULT_MINOR:
			tsk->min_flt++;
			break;
		case VM_FAULT_MAJOR:
			tsk->maj_flt++;
			break;
		case VM_FAULT_SIGBUS:
			goto do_sigbus;
		case VM_FAULT_OOM:
			goto out_of_memory;
		default:
			BUG();
	}

	/*
	 * Did it hit the DOS screen memory VA from vm86 mode?
	 */
	if (regs->eflags & VM_MASK) {
		unsigned long bit = (address - 0xA0000) >> PAGE_SHIFT;
		if (bit < 32)
			tsk->thread.screen_bitmap |= 1 << bit;
	}
	up_read(&mm->mmap_sem);
	return;

/*
 * Something tried to access memory that isn't in our memory map..
 * Fix it, but check if it's kernel or user first..
 */
bad_area:
	up_read(&mm->mmap_sem);

bad_area_nosemaphore:

#if defined(CONFIG_PAX_PAGEEXEC) || defined(CONFIG_PAX_SEGMEXEC)
	if (mm && (error_code & 4) && !(regs->eflags & X86_EFLAGS_VM)) {

#ifdef CONFIG_PAX_PAGEEXEC
		if ((mm->pax_flags & MF_PAX_PAGEEXEC) && !(error_code & 3) && (regs->eip == address)) {
			pax_report_fault(regs, (void*)regs->eip, (void*)regs->esp);
			do_exit(SIGKILL);
		}
#endif

#ifdef CONFIG_PAX_SEGMEXEC
		if ((mm->pax_flags & MF_PAX_SEGMEXEC) && !(error_code & 3) && (regs->eip + SEGMEXEC_TASK_SIZE == address)) {

			switch (pax_handle_fetch_fault(regs)) {

#ifdef CONFIG_PAX_EMUTRAMP
			case 2:
				return;
#endif

			}
			pax_report_fault(regs, (void*)regs->eip, (void*)regs->esp);
			do_exit(SIGKILL);
		}
#endif

	}
#endif

bad_area_nopax:
	/* User mode accesses just cause a SIGSEGV */
	if (error_code & 4) {
		/* 
		 * Valid to do another page fault here because this one came 
		 * from user space.
		 */
		if (is_prefetch(regs, address, error_code))
			return;

		tsk->thread.cr2 = address;
		/* Kernel addresses are always protection faults */
		tsk->thread.error_code = error_code | (address >= TASK_SIZE);
		tsk->thread.trap_no = 14;
		force_sig_info_fault(SIGSEGV, si_code, address, tsk);
		return;
	}

#ifdef CONFIG_X86_F00F_BUG
	/*
	 * Pentium F0 0F C7 C8 bug workaround.
	 */
	if (boot_cpu_data.f00f_bug) {
		unsigned long nr;
		
		nr = (address - idt_descr.address) >> 3;

		if (nr == 6) {
			do_invalid_op(regs, 0);
			return;
		}
	}
#endif

no_context:
	/* Are we prepared to handle this kernel fault?  */
	if (fixup_exception(regs))
		return;

	/* 
	 * Valid to do another page fault here, because if this fault
	 * had been triggered by is_prefetch fixup_exception would have 
	 * handled it.
	 */
 	if (is_prefetch(regs, address, error_code))
 		return;

/*
 * Oops. The kernel tried to access some bad page. We'll have to
 * terminate things with extreme prejudice.
 */

	bust_spinlocks(1);

#ifdef CONFIG_X86_PAE
	if (error_code & 16) {
		pte_t *pte = lookup_address(address);

		if (pte && pte_present(*pte) && !pte_exec_kernel(*pte))
			printk(KERN_CRIT "kernel tried to execute NX-protected page - exploit attempt? (uid: %d)\n", current->uid);
	}
#endif
	if (address < PAGE_SIZE)
		printk(KERN_ALERT "Unable to handle kernel NULL pointer dereference");

#ifdef CONFIG_PAX_KERNEXEC
#ifdef CONFIG_MODULES
	else if (init_mm.start_code <= address && address < (unsigned long)MODULES_END)
#else
	else if (init_mm.start_code <= address && address < init_mm.end_code)
#endif
		if (tsk->signal->curr_ip)
			printk(KERN_ERR "PAX: From %u.%u.%u.%u: %s:%d, uid/euid: %u/%u, attempted to modify kernel code",
					 NIPQUAD(tsk->signal->curr_ip), tsk->comm, tsk->pid, tsk->uid, tsk->euid);
		else
			printk(KERN_ERR "PAX: %s:%d, uid/euid: %u/%u, attempted to modify kernel code",
					 tsk->comm, tsk->pid, tsk->uid, tsk->euid);
#endif

	else
		printk(KERN_ALERT "Unable to handle kernel paging request");
	printk(" at virtual address %08lx\n",address);
	printk(KERN_ALERT " printing eip:\n");
	printk("%08lx\n", regs->eip);
	{
		unsigned long index = pgd_index(address);
		pgd_t *pgd;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		pgd = index + (pgd_t *)__va(read_cr3());
		printk(KERN_ALERT "*pgd = %*llx\n", sizeof(*pgd), (unsigned long long)pgd_val(*pgd));
		if (pgd_present(*pgd)) {
			pud = pud_offset(pgd, address);
			pmd = pmd_offset(pud, address);
			printk(KERN_ALERT "*pmd = %*llx\n", sizeof(*pmd), (unsigned long long)pmd_val(*pmd));
			/*
			 * We must not directly access the pte in the highpte
			 * case, the page table might be allocated in highmem.
			 * And lets rather not kmap-atomic the pte, just in case
			 * it's allocated already.
			 */
#ifndef CONFIG_HIGHPTE
			if (pmd_present(*pmd) && !pmd_large(*pmd)) {
				pte = pte_offset_kernel(pmd, address);
				printk(KERN_ALERT "*pte = %*llx\n", sizeof(*pte), (unsigned long long)pte_val(*pte));
			}
#endif
		}
	}
	tsk->thread.cr2 = address;
	tsk->thread.trap_no = 14;
	tsk->thread.error_code = error_code;
	die("Oops", regs, error_code);
	bust_spinlocks(0);
	do_exit(SIGKILL);

/*
 * We ran out of memory, or some other thing happened to us that made
 * us unable to handle the page fault gracefully.
 */
out_of_memory:
	up_read(&mm->mmap_sem);
	if (tsk->pid == 1) {
		yield();
		down_read(&mm->mmap_sem);
		goto survive;
	}
	printk("VM: killing process %s\n", tsk->comm);
	if (error_code & 4)
		do_exit(SIGKILL);
	goto no_context;

do_sigbus:
	up_read(&mm->mmap_sem);

	/* Kernel mode? Handle exceptions or die */
	if (!(error_code & 4))
		goto no_context;

	/* User space => ok to do another page fault */
	if (is_prefetch(regs, address, error_code))
		return;

	tsk->thread.cr2 = address;
	tsk->thread.error_code = error_code;
	tsk->thread.trap_no = 14;
	force_sig_info_fault(SIGBUS, BUS_ADRERR, address, tsk);
	return;

vmalloc_fault:
	{
		/*
		 * Synchronize this task's top level page-table
		 * with the 'reference' page table.
		 *
		 * Do _not_ use "tsk" here. We might be inside
		 * an interrupt in the middle of a task switch..
		 */
		unsigned long index = pgd_index(address);
		unsigned long pgd_paddr;
		pgd_t *pgd, *pgd_k;
		pud_t *pud, *pud_k;
		pmd_t *pmd, *pmd_k;
		pte_t *pte_k;

		pgd_paddr = read_cr3();
		pgd = index + (pgd_t *)__va(pgd_paddr);
		pgd_k = init_mm.pgd + index;

		if (!pgd_present(*pgd_k))
			goto no_context;

		/*
		 * set_pgd(pgd, *pgd_k); here would be useless on PAE
		 * and redundant with the set_pmd() on non-PAE. As would
		 * set_pud.
		 */

		pud = pud_offset(pgd, address);
		pud_k = pud_offset(pgd_k, address);
		if (!pud_present(*pud_k))
			goto no_context;
		
		pmd = pmd_offset(pud, address);
		pmd_k = pmd_offset(pud_k, address);
		if (!pmd_present(*pmd_k))
			goto no_context;
		set_pmd(pmd, *pmd_k);

		pte_k = pte_offset_kernel(pmd_k, address);
		if (!pte_present(*pte_k))
			goto no_context;
		return;
	}
}

#if defined(CONFIG_PAX_PAGEEXEC) || defined(CONFIG_PAX_SEGMEXEC)
/*
 * PaX: decide what to do with offenders (regs->eip = fault address)
 *
 * returns 1 when task should be killed
 *         2 when gcc trampoline was detected
 */
static int pax_handle_fetch_fault(struct pt_regs *regs)
{

#ifdef CONFIG_PAX_EMUTRAMP
	static const unsigned char trans[8] = {6, 1, 2, 0, 13, 5, 3, 4};
	int err;
#endif

	if (regs->eflags & X86_EFLAGS_VM)
		return 1;

#ifdef CONFIG_PAX_EMUTRAMP
	if (!(current->mm->pax_flags & MF_PAX_EMUTRAMP))
		return 1;

	do { /* PaX: gcc trampoline emulation #1 */
		unsigned char mov1, mov2;
		unsigned short jmp;
		unsigned long addr1, addr2;

		err = get_user(mov1, (unsigned char __user *)regs->eip);
		err |= get_user(addr1, (unsigned long __user *)(regs->eip + 1));
		err |= get_user(mov2, (unsigned char __user *)(regs->eip + 5));
		err |= get_user(addr2, (unsigned long __user *)(regs->eip + 6));
		err |= get_user(jmp, (unsigned short __user *)(regs->eip + 10));

		if (err)
			break;

		if ((mov1 & 0xF8) == 0xB8 &&
		    (mov2 & 0xF8) == 0xB8 &&
		    (mov1 & 0x07) != (mov2 & 0x07) &&
		    (jmp & 0xF8FF) == 0xE0FF &&
		    (mov2 & 0x07) == ((jmp>>8) & 0x07))
		{
			((unsigned long *)regs)[trans[mov1 & 0x07]] = addr1;
			((unsigned long *)regs)[trans[mov2 & 0x07]] = addr2;
			regs->eip = addr2;
			return 2;
		}
	} while (0);

	do { /* PaX: gcc trampoline emulation #2 */
		unsigned char mov, jmp;
		unsigned long addr1, addr2;

		err = get_user(mov, (unsigned char __user *)regs->eip);
		err |= get_user(addr1, (unsigned long __user *)(regs->eip + 1));
		err |= get_user(jmp, (unsigned char __user *)(regs->eip + 5));
		err |= get_user(addr2, (unsigned long __user *)(regs->eip + 6));

		if (err)
			break;

		if ((mov & 0xF8) == 0xB8 &&
		    jmp == 0xE9)
		{
			((unsigned long *)regs)[trans[mov & 0x07]] = addr1;
			regs->eip += addr2 + 10;
			return 2;
		}
	} while (0);
#endif

	return 1; /* PaX in action */
}
#endif

#if defined(CONFIG_PAX_PAGEEXEC) || defined(CONFIG_PAX_SEGMEXEC)
void pax_report_insns(void *pc, void *sp)
{
	long i;

	printk(KERN_ERR "PAX: bytes at PC: ");
	for (i = 0; i < 20; i++) {
		unsigned char c;
		if (get_user(c, (unsigned char __user *)pc+i))
			printk("?? ");
		else
			printk("%02x ", c);
	}
	printk("\n");

	printk(KERN_ERR "PAX: bytes at SP-4: ");
	for (i = -1; i < 20; i++) {
		unsigned long c;
		if (get_user(c, (unsigned long __user *)sp+i))
			printk("???????? ");
		else
			printk("%08lx ", c);
	}
	printk("\n");
}
#endif

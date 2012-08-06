/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2000, 2001, 2002 Andi Kleen, SuSE Labs
 */
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/hardirq.h>
#include <linux/kdebug.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/kexec.h>
#include <linux/sysfs.h>
#include <linux/bug.h>
#include <linux/nmi.h>

#include <asm/stacktrace.h>


void dump_trace(struct task_struct *task, struct pt_regs *regs,
		unsigned long *stack, unsigned long bp,
		const struct stacktrace_ops *ops, void *data)
{
	int graph = 0;

	if (!task)
		task = current;

	if (!stack) {
		unsigned long dummy;

		stack = &dummy;
		if (task && task != current)
			stack = (unsigned long *)task->thread.sp;
	}

	if (!bp)
		bp = stack_frame(task, regs);

	for (;;) {
		void *stack_start = (void *)((unsigned long)stack & ~(THREAD_SIZE-1));

		bp = ops->walk_stack(task, stack_start, stack, bp, ops, data, NULL, &graph);

		if (stack_start == task_stack_page(task))
			break;
		stack = *(unsigned long **)stack_start;
		if (ops->stack(data, "IRQ") < 0)
			break;
		touch_nmi_watchdog();
	}
}
EXPORT_SYMBOL(dump_trace);

void
show_stack_log_lvl(struct task_struct *task, struct pt_regs *regs,
		   unsigned long *sp, unsigned long bp, char *log_lvl)
{
	unsigned long *stack;
	int i;

	if (sp == NULL) {
		if (task)
			sp = (unsigned long *)task->thread.sp;
		else
			sp = (unsigned long *)&sp;
	}

	stack = sp;
	for (i = 0; i < kstack_depth_to_print; i++) {
		if (kstack_end(stack))
			break;
		if (i && ((i % STACKSLOTS_PER_LINE) == 0))
			printk(KERN_CONT "\n");
		printk(KERN_CONT " %08lx", *stack++);
		touch_nmi_watchdog();
	}
	printk(KERN_CONT "\n");
	show_trace_log_lvl(task, regs, sp, bp, log_lvl);
}


void show_regs(struct pt_regs *regs)
{
	int i;

	print_modules();
	__show_regs(regs, !user_mode(regs));

	printk(KERN_EMERG "Process %.*s (pid: %d, ti=%p task=%p task.ti=%p)\n",
		TASK_COMM_LEN, current->comm, task_pid_nr(current),
		current_thread_info(), current, task_thread_info(current));
	/*
	 * When in-kernel, we also print out the stack and code at the
	 * time of the fault..
	 */
	if (!user_mode(regs)) {
		unsigned int code_prologue = code_bytes * 43 / 64;
		unsigned int code_len = code_bytes;
		unsigned char c;
		u8 *ip;
		unsigned long cs_base = get_desc_base(&get_cpu_gdt_table(smp_processor_id())[(0xffff & regs->cs) >> 3]);

		printk(KERN_EMERG "Stack:\n");
		show_stack_log_lvl(NULL, regs, &regs->sp, 0, KERN_EMERG);

		printk(KERN_EMERG "Code: ");

		ip = (u8 *)regs->ip - code_prologue + cs_base;
		if (ip < (u8 *)PAGE_OFFSET || probe_kernel_address(ip, c)) {
			/* try starting at IP */
			ip = (u8 *)regs->ip + cs_base;
			code_len = code_len - code_prologue + 1;
		}
		for (i = 0; i < code_len; i++, ip++) {
			if (ip < (u8 *)PAGE_OFFSET ||
					probe_kernel_address(ip, c)) {
				printk(KERN_CONT " Bad EIP value.");
				break;
			}
			if (ip == (u8 *)regs->ip + cs_base)
				printk(KERN_CONT "<%02x> ", c);
			else
				printk(KERN_CONT "%02x ", c);
		}
	}
	printk(KERN_CONT "\n");
}

int is_valid_bugaddr(unsigned long ip)
{
	unsigned short ud2;

	ip = ktla_ktva(ip);
	if (ip < PAGE_OFFSET)
		return 0;
	if (probe_kernel_address((unsigned short *)ip, ud2))
		return 0;

	return ud2 == 0x0b0f;
}

#ifdef CONFIG_PAX_MEMORY_STACKLEAK
void pax_check_alloca(unsigned long size)
{
	unsigned long sp = (unsigned long)&sp, stack_left;

	/* all kernel stacks are of the same size */
	stack_left = sp & (THREAD_SIZE - 1);
	BUG_ON(stack_left < 256 || size >= stack_left - 256);
}
EXPORT_SYMBOL(pax_check_alloca);
#endif

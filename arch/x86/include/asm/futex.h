#ifndef _ASM_X86_FUTEX_H
#define _ASM_X86_FUTEX_H

#ifdef __KERNEL__

#include <linux/futex.h>
#include <linux/uaccess.h>

#include <asm/asm.h>
#include <asm/errno.h>
#include <asm/processor.h>
#include <asm/system.h>

#ifdef CONFIG_X86_32
#define __futex_atomic_op1(insn, ret, oldval, uaddr, oparg)	\
	asm volatile(						\
		     "movw\t%w6, %%ds\n"			\
		     "1:\t" insn "\n"				\
		     "2:\tpushl\t%%ss\n"			\
		     "\tpopl\t%%ds\n"				\
		     "\t.section .fixup,\"ax\"\n"		\
		     "3:\tmov\t%3, %1\n"			\
		     "\tjmp\t2b\n"				\
		     "\t.previous\n"				\
		     _ASM_EXTABLE(1b, 3b)			\
		     : "=r" (oldval), "=r" (ret), "+m" (*uaddr)	\
		     : "i" (-EFAULT), "0" (oparg), "1" (0), "r" (__USER_DS))

#define __futex_atomic_op2(insn, ret, oldval, uaddr, oparg)	\
	asm volatile("movw\t%w7, %%es\n"			\
		     "1:\tmovl\t%%es:%2, %0\n"			\
		     "\tmovl\t%0, %3\n"				\
		     "\t" insn "\n"				\
		     "2:\tlock; cmpxchgl %3, %%es:%2\n"		\
		     "\tjnz\t1b\n"				\
		     "3:\tpushl\t%%ss\n"			\
		     "\tpopl\t%%es\n"				\
		     "\t.section .fixup,\"ax\"\n"		\
		     "4:\tmov\t%5, %1\n"			\
		     "\tjmp\t3b\n"				\
		     "\t.previous\n"				\
		     _ASM_EXTABLE(1b, 4b)			\
		     _ASM_EXTABLE(2b, 4b)			\
		     : "=&a" (oldval), "=&r" (ret),		\
		       "+m" (*uaddr), "=&r" (tem)		\
		     : "r" (oparg), "i" (-EFAULT), "1" (0), "r" (__USER_DS))
#else
#define __futex_atomic_op1(insn, ret, oldval, uaddr, oparg)	\
	asm volatile("1:\t" insn "\n"				\
		     "2:\t.section .fixup,\"ax\"\n"		\
		     "3:\tmov\t%3, %1\n"			\
		     "\tjmp\t2b\n"				\
		     "\t.previous\n"				\
		     _ASM_EXTABLE(1b, 3b)			\
		     : "=r" (oldval), "=r" (ret), "+m" (*uaddr)	\
		     : "i" (-EFAULT), "0" (oparg), "1" (0))

#define __futex_atomic_op2(insn, ret, oldval, uaddr, oparg)	\
	asm volatile("1:\tmovl	%2, %0\n"			\
		     "\tmovl\t%0, %3\n"				\
		     "\t" insn "\n"				\
		     "2:\t" LOCK_PREFIX "cmpxchgl %3, %2\n"	\
		     "\tjnz\t1b\n"				\
		     "3:\t.section .fixup,\"ax\"\n"		\
		     "4:\tmov\t%5, %1\n"			\
		     "\tjmp\t3b\n"				\
		     "\t.previous\n"				\
		     _ASM_EXTABLE(1b, 4b)			\
		     _ASM_EXTABLE(2b, 4b)			\
		     : "=&a" (oldval), "=&r" (ret),		\
		       "+m" (*uaddr), "=&r" (tem)		\
		     : "r" (oparg), "i" (-EFAULT), "1" (0))
#endif

static inline int futex_atomic_op_inuser(int encoded_op, u32 __user *uaddr)
{
	int op = (encoded_op >> 28) & 7;
	int cmp = (encoded_op >> 24) & 15;
	int oparg = (encoded_op << 8) >> 20;
	int cmparg = (encoded_op << 20) >> 20;
	int oldval = 0, ret, tem;

	if (encoded_op & (FUTEX_OP_OPARG_SHIFT << 28))
		oparg = 1 << oparg;

	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(int)))
		return -EFAULT;

#if defined(CONFIG_X86_32) && !defined(CONFIG_X86_BSWAP)
	/* Real i386 machines can only support FUTEX_OP_SET */
	if (op != FUTEX_OP_SET && boot_cpu_data.x86 == 3)
		return -ENOSYS;
#endif

	pagefault_disable();

	switch (op) {
	case FUTEX_OP_SET:
#ifdef CONFIG_X86_32
		__futex_atomic_op1("xchgl %0, %%ds:%2", ret, oldval, uaddr, oparg);
#else
		__futex_atomic_op1("xchgl %0, %2", ret, oldval, uaddr, oparg);
#endif
		break;
	case FUTEX_OP_ADD:
#ifdef CONFIG_X86_32
		__futex_atomic_op1(LOCK_PREFIX "xaddl %0, %%ds:%2", ret, oldval,
				   uaddr, oparg);
#else
		__futex_atomic_op1(LOCK_PREFIX "xaddl %0, %2", ret, oldval,
				   uaddr, oparg);
#endif
		break;
	case FUTEX_OP_OR:
		__futex_atomic_op2("orl %4, %3", ret, oldval, uaddr, oparg);
		break;
	case FUTEX_OP_ANDN:
		__futex_atomic_op2("andl %4, %3", ret, oldval, uaddr, ~oparg);
		break;
	case FUTEX_OP_XOR:
		__futex_atomic_op2("xorl %4, %3", ret, oldval, uaddr, oparg);
		break;
	default:
		ret = -ENOSYS;
	}

	pagefault_enable();

	if (!ret) {
		switch (cmp) {
		case FUTEX_OP_CMP_EQ:
			ret = (oldval == cmparg);
			break;
		case FUTEX_OP_CMP_NE:
			ret = (oldval != cmparg);
			break;
		case FUTEX_OP_CMP_LT:
			ret = (oldval < cmparg);
			break;
		case FUTEX_OP_CMP_GE:
			ret = (oldval >= cmparg);
			break;
		case FUTEX_OP_CMP_LE:
			ret = (oldval <= cmparg);
			break;
		case FUTEX_OP_CMP_GT:
			ret = (oldval > cmparg);
			break;
		default:
			ret = -ENOSYS;
		}
	}
	return ret;
}

static inline int futex_atomic_cmpxchg_inatomic(u32 __user *uaddr, int oldval,
						int newval)
{

#if defined(CONFIG_X86_32) && !defined(CONFIG_X86_BSWAP)
	/* Real i386 machines have no cmpxchg instruction */
	if (boot_cpu_data.x86 == 3)
		return -ENOSYS;
#endif

	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(int)))
		return -EFAULT;

	asm volatile(
#ifdef CONFIG_X86_32
		     "\tmovw %w5, %%ds\n"
		     "1:\tlock; cmpxchgl %3, %1\n"
		     "2:\tpushl   %%ss\n"
		     "\tpopl    %%ds\n"
		     "\t.section .fixup, \"ax\"\n"
#else
		     "1:\tlock; cmpxchgl %3, %1\n"
		     "2:\t.section .fixup, \"ax\"\n"
#endif
		     "3:\tmov     %2, %0\n"
		     "\tjmp     2b\n"
		     "\t.previous\n"
		     _ASM_EXTABLE(1b, 3b)
		     : "=a" (oldval), "+m" (*uaddr)
#ifdef CONFIG_X86_32
		     : "i" (-EFAULT), "r" (newval), "0" (oldval), "r" (__USER_DS)
#else
		     : "i" (-EFAULT), "r" (newval), "0" (oldval)
#endif
		     : "memory"
	);

	return oldval;
}

#endif
#endif /* _ASM_X86_FUTEX_H */

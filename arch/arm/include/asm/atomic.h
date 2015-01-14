/*
 *  arch/arm/include/asm/atomic.h
 *
 *  Copyright (C) 1996 Russell King.
 *  Copyright (C) 2002 Deep Blue Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __ASM_ARM_ATOMIC_H
#define __ASM_ARM_ATOMIC_H

#include <linux/compiler.h>
#include <linux/prefetch.h>
#include <linux/types.h>
#include <linux/irqflags.h>
#include <asm/barrier.h>
#include <asm/cmpxchg.h>

#ifdef CONFIG_GENERIC_ATOMIC64
#include <asm-generic/atomic64.h>
#endif

#define ATOMIC_INIT(i)	{ (i) }

#ifdef __KERNEL__

#ifdef CONFIG_THUMB2_KERNEL
#define REFCOUNT_TRAP_INSN "bkpt	0xf1"
#else
#define REFCOUNT_TRAP_INSN "bkpt	0xf103"
#endif

#define _ASM_EXTABLE(from, to)		\
"	.pushsection __ex_table,\"a\"\n"\
"	.align	3\n"			\
"	.long	" #from ", " #to"\n"	\
"	.popsection"

/*
 * On ARM, ordinary assignment (str instruction) doesn't clear the local
 * strex/ldrex monitor on some implementations. The reason we can use it for
 * atomic_set() is the clrex or dummy strex done on every exception return.
 */
#define atomic_read(v)	ACCESS_ONCE((v)->counter)
static inline int atomic_read_unchecked(const atomic_unchecked_t *v)
{
	return ACCESS_ONCE(v->counter);
}
#define atomic_set(v,i)	(((v)->counter) = (i))
static inline void atomic_set_unchecked(atomic_unchecked_t *v, int i)
{
	v->counter = i;
}

#if __LINUX_ARM_ARCH__ >= 6

/*
 * ARMv6 UP and SMP safe atomic ops.  We use load exclusive and
 * store exclusive to ensure that these are atomic.  We may loop
 * to ensure that the update happens.
 */

#ifdef CONFIG_PAX_REFCOUNT
#define __OVERFLOW_POST			\
	"	bvc	3f\n"		\
	"2:	" REFCOUNT_TRAP_INSN "\n"\
	"3:\n"
#define __OVERFLOW_POST_RETURN		\
	"	bvc	3f\n"		\
"	mov	%0, %1\n"		\
	"2:	" REFCOUNT_TRAP_INSN "\n"\
	"3:\n"
#define __OVERFLOW_EXTABLE		\
	"4:\n"				\
	_ASM_EXTABLE(2b, 4b)
#else
#define __OVERFLOW_POST
#define __OVERFLOW_POST_RETURN
#define __OVERFLOW_EXTABLE
#endif

#define __ATOMIC_OP(op, suffix, c_op, asm_op, post_op, extable)		\
static inline void atomic_##op##suffix(int i, atomic##suffix##_t *v)	\
{									\
	unsigned long tmp;						\
	int result;							\
									\
	prefetchw(&v->counter);						\
	__asm__ __volatile__("@ atomic_" #op #suffix "\n"		\
"1:	ldrex	%0, [%3]\n"						\
"	" #asm_op "	%0, %0, %4\n"					\
	post_op								\
"	strex	%1, %0, [%3]\n"						\
"	teq	%1, #0\n"						\
"	bne	1b\n"							\
	extable								\
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)		\
	: "r" (&v->counter), "Ir" (i)					\
	: "cc");							\
}									\

#define ATOMIC_OP(op, c_op, asm_op) __ATOMIC_OP(op, , c_op, asm_op, , )\
				    __ATOMIC_OP(op, _unchecked, c_op, asm_op##s, __OVERFLOW_POST, __OVERFLOW_EXTABLE)

#define __ATOMIC_OP_RETURN(op, suffix, c_op, asm_op, post_op, extable)	\
static inline int atomic_##op##_return##suffix(int i, atomic##suffix##_t *v)\
{									\
	unsigned long tmp;						\
	int result;							\
									\
	smp_mb();							\
	prefetchw(&v->counter);						\
									\
	__asm__ __volatile__("@ atomic_" #op "_return" #suffix "\n"	\
"1:	ldrex	%0, [%3]\n"						\
"	" #asm_op "	%0, %0, %4\n"					\
	post_op								\
"	strex	%1, %0, [%3]\n"						\
"	teq	%1, #0\n"						\
"	bne	1b\n"							\
	extable								\
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)		\
	: "r" (&v->counter), "Ir" (i)					\
	: "cc");							\
									\
	smp_mb();							\
									\
	return result;							\
}

#define ATOMIC_OP_RETURN(op, c_op, asm_op) __ATOMIC_OP_RETURN(op, , c_op, asm_op, , )\
					   __ATOMIC_OP_RETURN(op, _unchecked, c_op, asm_op##s, __OVERFLOW_POST_RETURN, __OVERFLOW_EXTABLE)

static inline int atomic_cmpxchg(atomic_t *ptr, int old, int new)
{
	int oldval;
	unsigned long res;

	smp_mb();
	prefetchw(&ptr->counter);

	do {
		__asm__ __volatile__("@ atomic_cmpxchg\n"
		"ldrex	%1, [%3]\n"
		"mov	%0, #0\n"
		"teq	%1, %4\n"
		"strexeq %0, %5, [%3]\n"
		    : "=&r" (res), "=&r" (oldval), "+Qo" (ptr->counter)
		    : "r" (&ptr->counter), "Ir" (old), "r" (new)
		    : "cc");
	} while (res);

	smp_mb();

	return oldval;
}

static inline int __atomic_add_unless(atomic_t *v, int a, int u)
{
	int oldval, newval;
	unsigned long tmp;

	smp_mb();
	prefetchw(&v->counter);

	__asm__ __volatile__ ("@ atomic_add_unless\n"
"1:	ldrex	%0, [%4]\n"
"	teq	%0, %5\n"
"	beq	4f\n"
"	adds	%1, %0, %6\n"

#ifdef CONFIG_PAX_REFCOUNT
"	bvc	3f\n"
"2:	" REFCOUNT_TRAP_INSN "\n"
"3:\n"
#endif

"	strex	%2, %1, [%4]\n"
"	teq	%2, #0\n"
"	bne	1b\n"
"4:"

#ifdef CONFIG_PAX_REFCOUNT
	_ASM_EXTABLE(2b, 4b)
#endif

	: "=&r" (oldval), "=&r" (newval), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter), "r" (u), "r" (a)
	: "cc");

	if (oldval != u)
		smp_mb();

	return oldval;
}

static inline int atomic_cmpxchg_unchecked(atomic_unchecked_t *ptr, int old, int new)
{
	unsigned long oldval, res;

	smp_mb();

	do {
		__asm__ __volatile__("@ atomic_cmpxchg_unchecked\n"
		"ldrex	%1, [%3]\n"
		"mov	%0, #0\n"
		"teq	%1, %4\n"
		"strexeq %0, %5, [%3]\n"
		    : "=&r" (res), "=&r" (oldval), "+Qo" (ptr->counter)
		    : "r" (&ptr->counter), "Ir" (old), "r" (new)
		    : "cc");
	} while (res);

	smp_mb();

	return oldval;
}

#else /* ARM_ARCH_6 */

#ifdef CONFIG_SMP
#error SMP not supported on pre-ARMv6 CPUs
#endif

#define __ATOMIC_OP(op, suffix, c_op, asm_op)				\
static inline void atomic_##op##suffix(int i, atomic##suffix##_t *v)	\
{									\
	unsigned long flags;						\
									\
	raw_local_irq_save(flags);					\
	v->counter c_op i;						\
	raw_local_irq_restore(flags);					\
}									\

#define ATOMIC_OP(op, c_op, asm_op) __ATOMIC_OP(op, , c_op, asm_op)	\
				    __ATOMIC_OP(op, _unchecked, c_op, asm_op)

#define __ATOMIC_OP_RETURN(op, suffix, c_op, asm_op)			\
static inline int atomic_##op##_return##suffix(int i, atomic##suffix##_t *v)\
{									\
	unsigned long flags;						\
	int val;							\
									\
	raw_local_irq_save(flags);					\
	v->counter c_op i;						\
	val = v->counter;						\
	raw_local_irq_restore(flags);					\
									\
	return val;							\
}

#define ATOMIC_OP_RETURN(op, c_op, asm_op) __ATOMIC_OP_RETURN(op, , c_op, asm_op)\
					   __ATOMIC_OP_RETURN(op, _unchecked, c_op, asm_op)

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	int ret;
	unsigned long flags;

	raw_local_irq_save(flags);
	ret = v->counter;
	if (likely(ret == old))
		v->counter = new;
	raw_local_irq_restore(flags);

	return ret;
}

static inline int atomic_cmpxchg_unchecked(atomic_unchecked_t *v, int old, int new)
{
	return atomic_cmpxchg((atomic_t *)v, old, new);
}

static inline int __atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old;

	c = atomic_read(v);
	while (c != u && (old = atomic_cmpxchg((v), c, c + a)) != c)
		c = old;
	return c;
}

#endif /* __LINUX_ARM_ARCH__ */

#define ATOMIC_OPS(op, c_op, asm_op)					\
	ATOMIC_OP(op, c_op, asm_op)					\
	ATOMIC_OP_RETURN(op, c_op, asm_op)

ATOMIC_OPS(add, +=, add)
ATOMIC_OPS(sub, -=, sub)

#undef ATOMIC_OPS
#undef ATOMIC_OP_RETURN
#undef __ATOMIC_OP_RETURN
#undef ATOMIC_OP
#undef __ATOMIC_OP

#define atomic_xchg(v, new) (xchg(&((v)->counter), new))
static inline int atomic_xchg_unchecked(atomic_unchecked_t *v, int new)
{
	return xchg(&v->counter, new);
}

#define atomic_inc(v)		atomic_add(1, v)
static inline void atomic_inc_unchecked(atomic_unchecked_t *v)
{
	atomic_add_unchecked(1, v);
}
#define atomic_dec(v)		atomic_sub(1, v)
static inline void atomic_dec_unchecked(atomic_unchecked_t *v)
{
	atomic_sub_unchecked(1, v);
}

#define atomic_inc_and_test(v)	(atomic_add_return(1, v) == 0)
static inline int atomic_inc_and_test_unchecked(atomic_unchecked_t *v)
{
	return atomic_add_return_unchecked(1, v) == 0;
}
#define atomic_dec_and_test(v)	(atomic_sub_return(1, v) == 0)
#define atomic_inc_return(v)    (atomic_add_return(1, v))
static inline int atomic_inc_return_unchecked(atomic_unchecked_t *v)
{
	return atomic_add_return_unchecked(1, v);
}
#define atomic_dec_return(v)    (atomic_sub_return(1, v))
#define atomic_sub_and_test(i, v) (atomic_sub_return(i, v) == 0)

#define atomic_add_negative(i,v) (atomic_add_return(i, v) < 0)

#ifndef CONFIG_GENERIC_ATOMIC64
typedef struct {
	long long counter;
} atomic64_t;

#ifdef CONFIG_PAX_REFCOUNT
typedef struct {
	long long counter;
} atomic64_unchecked_t;
#else
typedef atomic64_t atomic64_unchecked_t;
#endif

#define ATOMIC64_INIT(i) { (i) }

#ifdef CONFIG_ARM_LPAE
static inline long long atomic64_read(const atomic64_t *v)
{
	long long result;

	__asm__ __volatile__("@ atomic64_read\n"
"	ldrd	%0, %H0, [%1]"
	: "=&r" (result)
	: "r" (&v->counter), "Qo" (v->counter)
	);

	return result;
}

static inline long long atomic64_read_unchecked(const atomic64_unchecked_t *v)
{
	long long result;

	__asm__ __volatile__("@ atomic64_read_unchecked\n"
"	ldrd	%0, %H0, [%1]"
	: "=&r" (result)
	: "r" (&v->counter), "Qo" (v->counter)
	);

	return result;
}

static inline void atomic64_set(atomic64_t *v, long long i)
{
	__asm__ __volatile__("@ atomic64_set\n"
"	strd	%2, %H2, [%1]"
	: "=Qo" (v->counter)
	: "r" (&v->counter), "r" (i)
	);
}

static inline void atomic64_set_unchecked(atomic64_unchecked_t *v, long long i)
{
	__asm__ __volatile__("@ atomic64_set_unchecked\n"
"	strd	%2, %H2, [%1]"
	: "=Qo" (v->counter)
	: "r" (&v->counter), "r" (i)
	);
}
#else
static inline long long atomic64_read(const atomic64_t *v)
{
	long long result;

	__asm__ __volatile__("@ atomic64_read\n"
"	ldrexd	%0, %H0, [%1]"
	: "=&r" (result)
	: "r" (&v->counter), "Qo" (v->counter)
	);

	return result;
}

static inline long long atomic64_read_unchecked(const atomic64_unchecked_t *v)
{
	long long result;

	__asm__ __volatile__("@ atomic64_read_unchecked\n"
"	ldrexd	%0, %H0, [%1]"
	: "=&r" (result)
	: "r" (&v->counter), "Qo" (v->counter)
	);

	return result;
}

static inline void atomic64_set(atomic64_t *v, long long i)
{
	long long tmp;

	prefetchw(&v->counter);
	__asm__ __volatile__("@ atomic64_set\n"
"1:	ldrexd	%0, %H0, [%2]\n"
"	strexd	%0, %3, %H3, [%2]\n"
"	teq	%0, #0\n"
"	bne	1b"
	: "=&r" (tmp), "=Qo" (v->counter)
	: "r" (&v->counter), "r" (i)
	: "cc");
}

static inline void atomic64_set_unchecked(atomic64_unchecked_t *v, long long i)
{
	long long tmp;

	prefetchw(&v->counter);
	__asm__ __volatile__("@ atomic64_set_unchecked\n"
"1:	ldrexd	%0, %H0, [%2]\n"
"	strexd	%0, %3, %H3, [%2]\n"
"	teq	%0, #0\n"
"	bne	1b"
	: "=&r" (tmp), "=Qo" (v->counter)
	: "r" (&v->counter), "r" (i)
	: "cc");
}
#endif

#undef __OVERFLOW_POST_RETURN
#define __OVERFLOW_POST_RETURN		\
	"	bvc	3f\n"		\
"	mov	%0, %1\n"		\
"	mov	%H0, %H1\n"		\
	"2:	" REFCOUNT_TRAP_INSN "\n"\
	"3:\n"

#define __ATOMIC64_OP(op, suffix, op1, op2, post_op, extable)		\
static inline void atomic64_##op##suffix(long long i, atomic64##suffix##_t *v)\
{									\
	long long result;						\
	unsigned long tmp;						\
									\
	prefetchw(&v->counter);						\
	__asm__ __volatile__("@ atomic64_" #op #suffix "\n"		\
"1:	ldrexd	%0, %H0, [%3]\n"					\
"	" #op1 " %Q0, %Q0, %Q4\n"					\
"	" #op2 " %R0, %R0, %R4\n"					\
	post_op								\
"	strexd	%1, %0, %H0, [%3]\n"					\
"	teq	%1, #0\n"						\
"	bne	1b\n"							\
	extable								\
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)		\
	: "r" (&v->counter), "r" (i)					\
	: "cc");							\
}									\

#define ATOMIC64_OP(op, op1, op2) __ATOMIC64_OP(op, , op1, op2, , ) \
				  __ATOMIC64_OP(op, _unchecked, op1, op2##s, __OVERFLOW_POST, __OVERFLOW_EXTABLE)

#define __ATOMIC64_OP_RETURN(op, suffix, op1, op2, post_op, extable)	\
static inline long long atomic64_##op##_return##suffix(long long i, atomic64##suffix##_t *v) \
{									\
	long long result;						\
	unsigned long tmp;						\
									\
	smp_mb();							\
	prefetchw(&v->counter);						\
									\
	__asm__ __volatile__("@ atomic64_" #op "_return" #suffix "\n"	\
"1:	ldrexd	%0, %H0, [%3]\n"					\
"	" #op1 " %Q0, %Q0, %Q4\n"					\
"	" #op2 " %R0, %R0, %R4\n"					\
	post_op								\
"	strexd	%1, %0, %H0, [%3]\n"					\
"	teq	%1, #0\n"						\
"	bne	1b\n"							\
	extable								\
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)		\
	: "r" (&v->counter), "r" (i)					\
	: "cc");							\
									\
	smp_mb();							\
									\
	return result;							\
}

#define ATOMIC64_OP_RETURN(op, op1, op2) __ATOMIC64_OP_RETURN(op, , op1, op2, , ) \
					 __ATOMIC64_OP_RETURN(op, _unchecked, op1, op2##s, __OVERFLOW_POST_RETURN, __OVERFLOW_EXTABLE)

#define ATOMIC64_OPS(op, op1, op2)					\
	ATOMIC64_OP(op, op1, op2)					\
	ATOMIC64_OP_RETURN(op, op1, op2)

ATOMIC64_OPS(add, adds, adc)
ATOMIC64_OPS(sub, subs, sbc)

#undef ATOMIC64_OPS
#undef ATOMIC64_OP_RETURN
#undef __ATOMIC64_OP_RETURN
#undef ATOMIC64_OP
#undef __ATOMIC64_OP
#undef __OVERFLOW_EXTABLE
#undef __OVERFLOW_POST_RETURN
#undef __OVERFLOW_POST

static inline long long atomic64_cmpxchg(atomic64_t *ptr, long long old,
					long long new)
{
	long long oldval;
	unsigned long res;

	smp_mb();
	prefetchw(&ptr->counter);

	do {
		__asm__ __volatile__("@ atomic64_cmpxchg\n"
		"ldrexd		%1, %H1, [%3]\n"
		"mov		%0, #0\n"
		"teq		%1, %4\n"
		"teqeq		%H1, %H4\n"
		"strexdeq	%0, %5, %H5, [%3]"
		: "=&r" (res), "=&r" (oldval), "+Qo" (ptr->counter)
		: "r" (&ptr->counter), "r" (old), "r" (new)
		: "cc");
	} while (res);

	smp_mb();

	return oldval;
}

static inline long long atomic64_cmpxchg_unchecked(atomic64_unchecked_t *ptr, long long old,
					long long new)
{
	long long oldval;
	unsigned long res;

	smp_mb();

	do {
		__asm__ __volatile__("@ atomic64_cmpxchg_unchecked\n"
		"ldrexd		%1, %H1, [%3]\n"
		"mov		%0, #0\n"
		"teq		%1, %4\n"
		"teqeq		%H1, %H4\n"
		"strexdeq	%0, %5, %H5, [%3]"
		: "=&r" (res), "=&r" (oldval), "+Qo" (ptr->counter)
		: "r" (&ptr->counter), "r" (old), "r" (new)
		: "cc");
	} while (res);

	smp_mb();

	return oldval;
}

static inline long long atomic64_xchg(atomic64_t *ptr, long long new)
{
	long long result;
	unsigned long tmp;

	smp_mb();
	prefetchw(&ptr->counter);

	__asm__ __volatile__("@ atomic64_xchg\n"
"1:	ldrexd	%0, %H0, [%3]\n"
"	strexd	%1, %4, %H4, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b"
	: "=&r" (result), "=&r" (tmp), "+Qo" (ptr->counter)
	: "r" (&ptr->counter), "r" (new)
	: "cc");

	smp_mb();

	return result;
}

static inline long long atomic64_dec_if_positive(atomic64_t *v)
{
	long long result;
	u64 tmp;

	smp_mb();
	prefetchw(&v->counter);

	__asm__ __volatile__("@ atomic64_dec_if_positive\n"
"1:	ldrexd	%1, %H1, [%3]\n"
"	subs	%Q0, %Q1, #1\n"
"	sbcs	%R0, %R1, #0\n"

#ifdef CONFIG_PAX_REFCOUNT
"	bvc	3f\n"
"	mov	%Q0, %Q1\n"
"	mov	%R0, %R1\n"
"2:	" REFCOUNT_TRAP_INSN "\n"
"3:\n"
#endif

"	teq	%R0, #0\n"
"	bmi	4f\n"
"	strexd	%1, %0, %H0, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b\n"
"4:\n"

#ifdef CONFIG_PAX_REFCOUNT
	_ASM_EXTABLE(2b, 4b)
#endif

	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter)
	: "cc");

	smp_mb();

	return result;
}

static inline int atomic64_add_unless(atomic64_t *v, long long a, long long u)
{
	long long val;
	unsigned long tmp;
	int ret = 1;

	smp_mb();
	prefetchw(&v->counter);

	__asm__ __volatile__("@ atomic64_add_unless\n"
"1:	ldrexd	%0, %H0, [%4]\n"
"	teq	%0, %5\n"
"	teqeq	%H0, %H5\n"
"	moveq	%1, #0\n"
"	beq	4f\n"
"	adds	%Q0, %Q0, %Q6\n"
"	adcs	%R0, %R0, %R6\n"

#ifdef CONFIG_PAX_REFCOUNT
"	bvc	3f\n"
"2:	" REFCOUNT_TRAP_INSN "\n"
"3:\n"
#endif

"	strexd	%2, %0, %H0, [%4]\n"
"	teq	%2, #0\n"
"	bne	1b\n"
"4:\n"

#ifdef CONFIG_PAX_REFCOUNT
	_ASM_EXTABLE(2b, 4b)
#endif

	: "=&r" (val), "+r" (ret), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter), "r" (u), "r" (a)
	: "cc");

	if (ret)
		smp_mb();

	return ret;
}

#define atomic64_add_negative(a, v)	(atomic64_add_return((a), (v)) < 0)
#define atomic64_inc(v)			atomic64_add(1LL, (v))
#define atomic64_inc_unchecked(v)	atomic64_add_unchecked(1LL, (v))
#define atomic64_inc_return(v)		atomic64_add_return(1LL, (v))
#define atomic64_inc_return_unchecked(v)	atomic64_add_return_unchecked(1LL, (v))
#define atomic64_inc_and_test(v)	(atomic64_inc_return(v) == 0)
#define atomic64_sub_and_test(a, v)	(atomic64_sub_return((a), (v)) == 0)
#define atomic64_dec(v)			atomic64_sub(1LL, (v))
#define atomic64_dec_unchecked(v)	atomic64_sub_unchecked(1LL, (v))
#define atomic64_dec_return(v)		atomic64_sub_return(1LL, (v))
#define atomic64_dec_and_test(v)	(atomic64_dec_return((v)) == 0)
#define atomic64_inc_not_zero(v)	atomic64_add_unless((v), 1LL, 0LL)

#endif /* !CONFIG_GENERIC_ATOMIC64 */
#endif
#endif

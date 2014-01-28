/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 *
 * But use these as seldom as possible since they are much more slower
 * than regular operations.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1996, 97, 99, 2000, 03, 04, 06 by Ralf Baechle
 */
#ifndef _ASM_ATOMIC_H
#define _ASM_ATOMIC_H

#include <linux/irqflags.h>
#include <linux/types.h>
#include <asm/barrier.h>
#include <asm/cpu-features.h>
#include <asm/cmpxchg.h>
#include <asm/war.h>

#ifdef CONFIG_GENERIC_ATOMIC64
#include <asm-generic/atomic64.h>
#endif

#define ATOMIC_INIT(i)	  { (i) }

#ifdef CONFIG_64BIT
#define _ASM_EXTABLE(from, to)		\
"	.section __ex_table,\"a\"\n"	\
"	.dword	" #from ", " #to"\n"	\
"	.previous\n"
#else
#define _ASM_EXTABLE(from, to)		\
"	.section __ex_table,\"a\"\n"	\
"	.word	" #from ", " #to"\n"	\
"	.previous\n"
#endif

/*
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically reads the value of @v.
 */
static inline int atomic_read(const atomic_t *v)
{
	return (*(volatile const int *) &v->counter);
}

static inline int atomic_read_unchecked(const atomic_unchecked_t *v)
{
	return (*(volatile const int *) &v->counter);
}

/*
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
static inline void atomic_set(atomic_t *v, int i)
{
	v->counter = i;
}

static inline void atomic_set_unchecked(atomic_unchecked_t *v, int i)
{
	v->counter = i;
}

/*
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */
static __inline__ void atomic_add(int i, atomic_t *v)
{
	int temp;

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%0, %1		# atomic_add		\n"
#ifdef CONFIG_PAX_REFCOUNT
			/* Exception on overflow. */
		"2:	add	%0, %2					\n"
#else
		"	addu	%0, %2					\n"
#endif
		"	sc	%0, %1					\n"
		"	beqzl	%0, 1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"3:							\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%0, %1		# atomic_add		\n"
#ifdef CONFIG_PAX_REFCOUNT
		/* Exception on overflow. */
		"2:	add	%0, %2					\n"
#else
		"	addu	%0, %2					\n"
#endif
		"	sc	%0, %1					\n"
		"	beqz	%0, 1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"3:							\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		__asm__ __volatile__(
#ifdef CONFIG_PAX_REFCOUNT
			/* Exception on overflow. */
		"1:	add	%0, %1					\n"
		"2:							\n"
		_ASM_EXTABLE(1b, 2b)
#else
		"	addu	%0, %1					\n"
#endif
		: "+r" (v->counter) : "Ir" (i));
		raw_local_irq_restore(flags);
	}
}

static __inline__ void atomic_add_unchecked(int i, atomic_unchecked_t *v)
{
	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%0, %1		# atomic_add		\n"
		"	addu	%0, %2					\n"
		"	sc	%0, %1					\n"
		"	beqzl	%0, 1b					\n"
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		int temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	ll	%0, %1		# atomic_add	\n"
			"	addu	%0, %2				\n"
			"	sc	%0, %1				\n"
			"	.set	mips0				\n"
			: "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!temp));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		v->counter += i;
		raw_local_irq_restore(flags);
	}
}

/*
 * atomic_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.
 */
static __inline__ void atomic_sub(int i, atomic_t *v)
{
	int temp;

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%0, %1		# atomic64_sub		\n"
#ifdef CONFIG_PAX_REFCOUNT
		/* Exception on overflow. */
		"2:	sub	%0, %2					\n"
#else
		"	subu	%0, %2					\n"
#endif
		"	sc	%0, %1					\n"
		"	beqzl	%0, 1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"3:							\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%0, %1		# atomic64_sub		\n"
#ifdef CONFIG_PAX_REFCOUNT
		/* Exception on overflow. */
		"2:	sub	%0, %2					\n"
#else
		"	subu	%0, %2					\n"
#endif
		"	sc	%0, %1					\n"
		"	beqz	%0, 1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"3:							\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		__asm__ __volatile__(
#ifdef CONFIG_PAX_REFCOUNT
			/* Exception on overflow. */
		"1:	sub	%0, %1					\n"
		"2:							\n"
		_ASM_EXTABLE(1b, 2b)
#else
		"	subu	%0, %1					\n"
#endif
		: "+r" (v->counter) : "Ir" (i));
		raw_local_irq_restore(flags);
	}
}

static __inline__ void atomic_sub_unchecked(long i, atomic_unchecked_t *v)
{
	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%0, %1		# atomic_sub		\n"
		"	subu	%0, %2					\n"
		"	sc	%0, %1					\n"
		"	beqzl	%0, 1b					\n"
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		int temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	ll	%0, %1		# atomic_sub	\n"
			"	subu	%0, %2				\n"
			"	sc	%0, %1				\n"
			"	.set	mips0				\n"
			: "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!temp));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		v->counter -= i;
		raw_local_irq_restore(flags);
	}
}

/*
 * Same as above, but return the result value
 */
static __inline__ int atomic_add_return(int i, atomic_t *v)
{
	int result;
	int temp;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%1, %2		# atomic_add_return	\n"
#ifdef CONFIG_PAX_REFCOUNT
		"2:	add	%0, %1, %3				\n"
#else
		"	addu	%0, %1, %3				\n"
#endif
		"	sc	%0, %2					\n"
		"	beqzl	%0, 1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"	b	4f					\n"
		"	.set	noreorder				\n"
		"3:	b	5f					\n"
		"	move	%0, %1					\n"
		"	.set	reorder					\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"4:	addu	%0, %1, %3				\n"
#ifdef CONFIG_PAX_REFCOUNT
		"5:							\n"
#endif
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%1, %2	# atomic_add_return		\n"
#ifdef CONFIG_PAX_REFCOUNT
		"2:	add	%0, %1, %3				\n"
#else
		"	addu	%0, %1, %3				\n"
#endif
		"	sc	%0, %2					\n"
		"	bnez	%0, 4f					\n"
		"	b	1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"	.set	noreorder				\n"
		"3:	b	5f					\n"
		"	move	%0, %1					\n"
		"	.set	reorder					\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"4:	addu	%0, %1, %3				\n"
#ifdef CONFIG_PAX_REFCOUNT
		"5:							\n"
#endif
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		__asm__ __volatile__(
		"	lw	%0, %1					\n"
#ifdef CONFIG_PAX_REFCOUNT
			/* Exception on overflow. */
		"1:	add	%0, %2					\n"
#else
		"	addu	%0, %2					\n"
#endif
		"	sw	%0, %1					\n"
#ifdef CONFIG_PAX_REFCOUNT
		/* Note: Dest reg is not modified on overflow */
		"2:							\n"
		_ASM_EXTABLE(1b, 2b)
#endif
		: "=&r" (result), "+m" (v->counter) : "Ir" (i));
		raw_local_irq_restore(flags);
	}

	smp_llsc_mb();

	return result;
}

static __inline__ int atomic_add_return_unchecked(int i, atomic_unchecked_t *v)
{
	int result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%1, %2		# atomic_add_return	\n"
		"	addu	%0, %1, %3				\n"
		"	sc	%0, %2					\n"
		"	beqzl	%0, 1b					\n"
		"	addu	%0, %1, %3				\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		int temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	ll	%1, %2	# atomic_add_return	\n"
			"	addu	%0, %1, %3			\n"
			"	sc	%0, %2				\n"
			"	.set	mips0				\n"
			: "=&r" (result), "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!result));

		result = temp + i;
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result += i;
		v->counter = result;
		raw_local_irq_restore(flags);
	}

	smp_llsc_mb();

	return result;
}

static __inline__ int atomic_sub_return(int i, atomic_t *v)
{
	int result;
	int temp;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%1, %2		# atomic_sub_return	\n"
#ifdef CONFIG_PAX_REFCOUNT
		"2:	sub	%0, %1, %3				\n"
#else
		"	subu	%0, %1, %3				\n"
#endif
		"	sc	%0, %2					\n"
		"	beqzl	%0, 1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"	b	4f					\n"
		"	.set	noreorder				\n"
		"3:	b	5f					\n"
		"	move	%0, %1					\n"
		"	.set	reorder					\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"4:	subu	%0, %1, %3				\n"
#ifdef CONFIG_PAX_REFCOUNT
		"5:							\n"
#endif
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "=m" (v->counter)
		: "Ir" (i), "m" (v->counter)
		: "memory");
	} else if (kernel_uses_llsc) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%1, %2	# atomic_sub_return		\n"
#ifdef CONFIG_PAX_REFCOUNT
		"2:	sub	%0, %1, %3				\n"
#else
		"	subu	%0, %1, %3				\n"
#endif
		"	sc	%0, %2					\n"
		"	bnez	%0, 4f					\n"
		"	b	1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"	.set	noreorder				\n"
		"3:	b	5f					\n"
		"	move	%0, %1					\n"
		"	.set	reorder					\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"4:	subu	%0, %1, %3				\n"
#ifdef CONFIG_PAX_REFCOUNT
		"5:							\n"
#endif
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		__asm__ __volatile__(
		"	lw	%0, %1					\n"
#ifdef CONFIG_PAX_REFCOUNT
			/* Exception on overflow. */
		"1:	sub	%0, %2					\n"
#else
		"	subu	%0, %2					\n"
#endif
		"	sw	%0, %1					\n"
#ifdef CONFIG_PAX_REFCOUNT
		/* Note: Dest reg is not modified on overflow */
		"2:							\n"
		_ASM_EXTABLE(1b, 2b)
#endif
		: "=&r" (result), "+m" (v->counter) : "Ir" (i));
		raw_local_irq_restore(flags);
	}

	smp_llsc_mb();

	return result;
}
static __inline__ int atomic_sub_return_unchecked(int i, atomic_unchecked_t *v)
{
	int result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%1, %2		# atomic_sub_return	\n"
		"	subu	%0, %1, %3				\n"
		"	sc	%0, %2					\n"
		"	beqzl	%0, 1b					\n"
		"	subu	%0, %1, %3				\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "=m" (v->counter)
		: "Ir" (i), "m" (v->counter)
		: "memory");

		result = temp - i;
	} else if (kernel_uses_llsc) {
		int temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	ll	%1, %2	# atomic_sub_return	\n"
			"	subu	%0, %1, %3			\n"
			"	sc	%0, %2				\n"
			"	.set	mips0				\n"
			: "=&r" (result), "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!result));

		result = temp - i;
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result -= i;
		v->counter = result;
		raw_local_irq_restore(flags);
	}

	smp_llsc_mb();

	return result;
}

/*
 * atomic_sub_if_positive - conditionally subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically test @v and subtract @i if @v is greater or equal than @i.
 * The function returns the old value of @v minus @i.
 */
static __inline__ int atomic_sub_if_positive(int i, atomic_t *v)
{
	int result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%1, %2		# atomic_sub_if_positive\n"
		"	subu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	sc	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqzl	%0, 1b					\n"
		"	 subu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i), "m" (v->counter)
		: "memory");
	} else if (kernel_uses_llsc) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%1, %2		# atomic_sub_if_positive\n"
		"	subu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	sc	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqz	%0, 1b					\n"
		"	 subu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result -= i;
		if (result >= 0)
			v->counter = result;
		raw_local_irq_restore(flags);
	}

	smp_llsc_mb();

	return result;
}

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return cmpxchg(&v->counter, old, new);
}

static inline int atomic_cmpxchg_unchecked(atomic_unchecked_t *v, int old,
					   int new)
{
	return cmpxchg(&(v->counter), old, new);
}

static inline int atomic_xchg(atomic_t *v, int new)
{
	return xchg(&v->counter, new);
}

static inline int atomic_xchg_unchecked(atomic_unchecked_t *v, int new)
{
	return xchg(&(v->counter), new);
}

/**
 * __atomic_add_unless - add unless the number is a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns the old value of @v.
 */
static __inline__ int __atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old;
	c = atomic_read(v);
	for (;;) {
		if (unlikely(c == (u)))
			break;
		old = atomic_cmpxchg((v), c, c + (a));
		if (likely(old == c))
			break;
		c = old;
	}
	return c;
}

#define atomic_dec_return(v) atomic_sub_return(1, (v))
#define atomic_inc_return(v) atomic_add_return(1, (v))
static __inline__ int atomic_inc_return_unchecked(atomic_unchecked_t *v)
{
	return atomic_add_return_unchecked(1, v);
}

/*
 * atomic_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
#define atomic_sub_and_test(i, v) (atomic_sub_return((i), (v)) == 0)

/*
 * atomic_inc_and_test - increment and test
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
#define atomic_inc_and_test(v) (atomic_inc_return(v) == 0)
static __inline__ int atomic_inc_and_test_unchecked(atomic_unchecked_t *v)
{
	return atomic_add_return_unchecked(1, v) == 0;
}

/*
 * atomic_dec_and_test - decrement by 1 and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
#define atomic_dec_and_test(v) (atomic_sub_return(1, (v)) == 0)

/*
 * atomic_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic_t
 */
#define atomic_dec_if_positive(v)	atomic_sub_if_positive(1, v)

/*
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
#define atomic_inc(v) atomic_add(1, (v))
static __inline__ void atomic_inc_unchecked(atomic_unchecked_t *v)
{
	atomic_add_unchecked(1, v);
}

/*
 * atomic_dec - decrement and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
#define atomic_dec(v) atomic_sub(1, (v))
static __inline__ void atomic_dec_unchecked(atomic_unchecked_t *v)
{
	atomic_sub_unchecked(1, v);
}

/*
 * atomic_add_negative - add and test if negative
 * @v: pointer of type atomic_t
 * @i: integer value to add
 *
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
#define atomic_add_negative(i, v) (atomic_add_return(i, (v)) < 0)

#ifdef CONFIG_64BIT

#define ATOMIC64_INIT(i)    { (i) }

/*
 * atomic64_read - read atomic variable
 * @v: pointer of type atomic64_t
 *
 */
static inline long atomic64_read(const atomic64_t *v)
{
	return (*(volatile const long *) &v->counter);
}

static inline long atomic64_read_unchecked(const atomic64_unchecked_t *v)
{
	return (*(volatile const long *) &v->counter);
}

/*
 * atomic64_set - set atomic variable
 * @v: pointer of type atomic64_t
 * @i: required value
 */
static inline void atomic64_set(atomic64_t *v, long i)
{
	v->counter = i;
}

static inline void atomic64_set_unchecked(atomic64_unchecked_t *v, long i)
{
	v->counter = i;
}

/*
 * atomic64_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic64_t
 *
 * Atomically adds @i to @v.
 */
static __inline__ void atomic64_add(long i, atomic64_t *v)
{
	long temp;

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%0, %1		# atomic64_add		\n"
#ifdef CONFIG_PAX_REFCOUNT
			/* Exception on overflow. */
		"2:	dadd	%0, %2					\n"
#else
		"	daddu	%0, %2					\n"
#endif
		"	scd	%0, %1					\n"
		"	beqzl	%0, 1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"3:							\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%0, %1		# atomic64_add		\n"
#ifdef CONFIG_PAX_REFCOUNT
			/* Exception on overflow. */
		"2:	dadd	%0, %2					\n"
#else
		"	daddu	%0, %2					\n"
#endif
		"	scd	%0, %1					\n"
		"	beqz	%0, 1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"3:							\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		__asm__ __volatile__(
#ifdef CONFIG_PAX_REFCOUNT
			/* Exception on overflow. */
		"1:	dadd	%0, %1					\n"
		"2:							\n"
		_ASM_EXTABLE(1b, 2b)
#else
		"	daddu	%0, %1					\n"
#endif
		: "+r" (v->counter) : "Ir" (i));
		raw_local_irq_restore(flags);
	}
}
static __inline__ void atomic64_add_unchecked(long i, atomic64_unchecked_t *v)
{
	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%0, %1		# atomic64_add		\n"
		"	daddu	%0, %2					\n"
		"	scd	%0, %1					\n"
		"	beqzl	%0, 1b					\n"
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		long temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	lld	%0, %1		# atomic64_add	\n"
			"	daddu	%0, %2				\n"
			"	scd	%0, %1				\n"
			"	.set	mips0				\n"
			: "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!temp));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		v->counter += i;
		raw_local_irq_restore(flags);
	}
}

/*
 * atomic64_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic64_t
 *
 * Atomically subtracts @i from @v.
 */
static __inline__ void atomic64_sub(long i, atomic64_t *v)
{
	long temp;

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%0, %1		# atomic64_sub		\n"
#ifdef CONFIG_PAX_REFCOUNT
		/* Exception on overflow. */
		"2:	dsub	%0, %2					\n"
#else
		"	dsubu	%0, %2					\n"
#endif
		"	scd	%0, %1					\n"
		"	beqzl	%0, 1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"3:							\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%0, %1		# atomic64_sub		\n"
#ifdef CONFIG_PAX_REFCOUNT
		/* Exception on overflow. */
		"2:	dsub	%0, %2					\n"
#else
		"	dsubu	%0, %2					\n"
#endif
		"	scd	%0, %1					\n"
		"	beqz	%0, 1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"3:							\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		__asm__ __volatile__(
#ifdef CONFIG_PAX_REFCOUNT
			/* Exception on overflow. */
		"1:	dsub	%0, %1					\n"
		"2:							\n"
		_ASM_EXTABLE(1b, 2b)
#else
		"	dsubu	%0, %1					\n"
#endif
		: "+r" (v->counter) : "Ir" (i));
		raw_local_irq_restore(flags);
	}
}

static __inline__ void atomic64_sub_unchecked(long i, atomic64_unchecked_t *v)
{
	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%0, %1		# atomic64_sub		\n"
		"	dsubu	%0, %2					\n"
		"	scd	%0, %1					\n"
		"	beqzl	%0, 1b					\n"
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		long temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	lld	%0, %1		# atomic64_sub	\n"
			"	dsubu	%0, %2				\n"
			"	scd	%0, %1				\n"
			"	.set	mips0				\n"
			: "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!temp));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		v->counter -= i;
		raw_local_irq_restore(flags);
	}
}

/*
 * Same as above, but return the result value
 */
static __inline__ long atomic64_add_return(long i, atomic64_t *v)
{
	long result;
	long temp;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%1, %2		# atomic64_add_return	\n"
#ifdef CONFIG_PAX_REFCOUNT
		"2:	dadd	%0, %1, %3				\n"
#else
		"	daddu	%0, %1, %3				\n"
#endif
		"	scd	%0, %2					\n"
		"	beqzl	%0, 1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"	b	4f					\n"
		"	.set	noreorder				\n"
		"3:	b	5f					\n"
		"	move	%0, %1					\n"
		"	.set	reorder					\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"4:	daddu	%0, %1, %3				\n"
#ifdef CONFIG_PAX_REFCOUNT
		"5:							\n"
#endif
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%1, %2	# atomic64_add_return		\n"
#ifdef CONFIG_PAX_REFCOUNT
		"2:	dadd	%0, %1, %3				\n"
#else
		"	daddu	%0, %1, %3				\n"
#endif
		"	scd	%0, %2					\n"
		"	bnez	%0, 4f					\n"
		"	b	1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"	.set	noreorder				\n"
		"3:	b	5f					\n"
		"	move	%0, %1					\n"
		"	.set	reorder					\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"4:	daddu	%0, %1, %3				\n"
#ifdef CONFIG_PAX_REFCOUNT
		"5:							\n"
#endif
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "=m" (v->counter)
		: "Ir" (i), "m" (v->counter)
		: "memory");
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		__asm__ __volatile__(
		"	ld	%0, %1					\n"
#ifdef CONFIG_PAX_REFCOUNT
			/* Exception on overflow. */
		"1:	dadd	%0, %2					\n"
#else
		"	daddu	%0, %2					\n"
#endif
		"	sd	%0, %1					\n"
#ifdef CONFIG_PAX_REFCOUNT
		/* Note: Dest reg is not modified on overflow */
		"2:							\n"
		_ASM_EXTABLE(1b, 2b)
#endif
		: "=&r" (result), "+m" (v->counter) : "Ir" (i));
		raw_local_irq_restore(flags);
	}

	smp_llsc_mb();

	return result;
}
static __inline__ long atomic64_add_return_unchecked(long i, atomic64_unchecked_t *v)
{
	long result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%1, %2		# atomic64_add_return	\n"
		"	daddu	%0, %1, %3				\n"
		"	scd	%0, %2					\n"
		"	beqzl	%0, 1b					\n"
		"	daddu	%0, %1, %3				\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		long temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	lld	%1, %2	# atomic64_add_return	\n"
			"	daddu	%0, %1, %3			\n"
			"	scd	%0, %2				\n"
			"	.set	mips0				\n"
			: "=&r" (result), "=&r" (temp), "=m" (v->counter)
			: "Ir" (i), "m" (v->counter)
			: "memory");
		} while (unlikely(!result));

		result = temp + i;
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result += i;
		v->counter = result;
		raw_local_irq_restore(flags);
	}

	smp_llsc_mb();

	return result;
}

static __inline__ long atomic64_sub_return(long i, atomic64_t *v)
{
	long result;
	long temp;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%1, %2		# atomic64_sub_return	\n"
#ifdef CONFIG_PAX_REFCOUNT
		"2:	dsub	%0, %1, %3				\n"
#else
		"	dsubu	%0, %1, %3				\n"
#endif
		"	scd	%0, %2					\n"
		"	beqzl	%0, 1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"	b	4f					\n"
		"	.set	noreorder				\n"
		"3:	b	5f					\n"
		"	move	%0, %1					\n"
		"	.set	reorder					\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"4:	dsubu	%0, %1, %3				\n"
#ifdef CONFIG_PAX_REFCOUNT
		"5:							\n"
#endif
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "=m" (v->counter)
		: "Ir" (i), "m" (v->counter)
		: "memory");
	} else if (kernel_uses_llsc) {
		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%1, %2	# atomic64_sub_return		\n"
#ifdef CONFIG_PAX_REFCOUNT
		"2:	dsub	%0, %1, %3				\n"
#else
		"	dsubu	%0, %1, %3				\n"
#endif
		"	scd	%0, %2					\n"
		"	bnez	%0, 4f					\n"
		"	b	1b					\n"
#ifdef CONFIG_PAX_REFCOUNT
		"	.set	noreorder				\n"
		"3:	b	5f					\n"
		"	move	%0, %1					\n"
		"	.set	reorder					\n"
		_ASM_EXTABLE(2b, 3b)
#endif
		"4:	dsubu	%0, %1, %3				\n"
#ifdef CONFIG_PAX_REFCOUNT
		"5:							\n"
#endif
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "=m" (v->counter)
		: "Ir" (i), "m" (v->counter)
		: "memory");
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		__asm__ __volatile__(
		"	ld	%0, %1					\n"
#ifdef CONFIG_PAX_REFCOUNT
			/* Exception on overflow. */
		"1:	dsub	%0, %2					\n"
#else
		"	dsubu	%0, %2					\n"
#endif
		"	sd	%0, %1					\n"
#ifdef CONFIG_PAX_REFCOUNT
		/* Note: Dest reg is not modified on overflow */
		"2:							\n"
		_ASM_EXTABLE(1b, 2b)
#endif
		: "=&r" (result), "+m" (v->counter) : "Ir" (i));
		raw_local_irq_restore(flags);
	}

	smp_llsc_mb();

	return result;
}

static __inline__ long atomic64_sub_return_unchecked(long i, atomic64_unchecked_t *v)
{
	long result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%1, %2		# atomic64_sub_return	\n"
		"	dsubu	%0, %1, %3				\n"
		"	scd	%0, %2					\n"
		"	beqzl	%0, 1b					\n"
		"	dsubu	%0, %1, %3				\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "=m" (v->counter)
		: "Ir" (i), "m" (v->counter)
		: "memory");
	} else if (kernel_uses_llsc) {
		long temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	lld	%1, %2	# atomic64_sub_return	\n"
			"	dsubu	%0, %1, %3			\n"
			"	scd	%0, %2				\n"
			"	.set	mips0				\n"
			: "=&r" (result), "=&r" (temp), "=m" (v->counter)
			: "Ir" (i), "m" (v->counter)
			: "memory");
		} while (unlikely(!result));

		result = temp - i;
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result -= i;
		v->counter = result;
		raw_local_irq_restore(flags);
	}

	smp_llsc_mb();

	return result;
}

/*
 * atomic64_sub_if_positive - conditionally subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic64_t
 *
 * Atomically test @v and subtract @i if @v is greater or equal than @i.
 * The function returns the old value of @v minus @i.
 */
static __inline__ long atomic64_sub_if_positive(long i, atomic64_t *v)
{
	long result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%1, %2		# atomic64_sub_if_positive\n"
		"	dsubu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	scd	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqzl	%0, 1b					\n"
		"	 dsubu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "=m" (v->counter)
		: "Ir" (i), "m" (v->counter)
		: "memory");
	} else if (kernel_uses_llsc) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%1, %2		# atomic64_sub_if_positive\n"
		"	dsubu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	scd	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqz	%0, 1b					\n"
		"	 dsubu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result -= i;
		if (result >= 0)
			v->counter = result;
		raw_local_irq_restore(flags);
	}

	smp_llsc_mb();

	return result;
}

static inline long atomic64_cmpxchg(atomic64_t *v, long old, long new)
{
	return cmpxchg(&v->counter, old, new);
}

static inline long atomic64_cmpxchg_unchecked(atomic64_unchecked_t *v, long old,
					      long new)
{
	return cmpxchg(&(v->counter), old, new);
}

static inline long atomic64_xchg(atomic64_t *v, long new)
{
	return xchg(&v->counter, new);
}

static inline long atomic64_xchg_unchecked(atomic64_unchecked_t *v, long new)
{
	return xchg(&(v->counter), new);
}

/**
 * atomic64_add_unless - add unless the number is a given value
 * @v: pointer of type atomic64_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns the old value of @v.
 */
static __inline__ int atomic64_add_unless(atomic64_t *v, long a, long u)
{
	long c, old;
	c = atomic64_read(v);
	for (;;) {
		if (unlikely(c == (u)))
			break;
		old = atomic64_cmpxchg((v), c, c + (a));
		if (likely(old == c))
			break;
		c = old;
	}
	return c != (u);
}

#define atomic64_inc_not_zero(v) atomic64_add_unless((v), 1, 0)

#define atomic64_dec_return(v) atomic64_sub_return(1, (v))
#define atomic64_inc_return(v) atomic64_add_return(1, (v))
#define atomic64_inc_return_unchecked(v) atomic64_add_return_unchecked(1, (v))

/*
 * atomic64_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic64_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
#define atomic64_sub_and_test(i, v) (atomic64_sub_return((i), (v)) == 0)

/*
 * atomic64_inc_and_test - increment and test
 * @v: pointer of type atomic64_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
#define atomic64_inc_and_test(v) (atomic64_inc_return(v) == 0)
#define atomic64_inc_and_test_unchecked(v) atomic64_add_return_unchecked(1, (v)) == 0)

/*
 * atomic64_dec_and_test - decrement by 1 and test
 * @v: pointer of type atomic64_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
#define atomic64_dec_and_test(v) (atomic64_sub_return(1, (v)) == 0)

/*
 * atomic64_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic64_t
 */
#define atomic64_dec_if_positive(v)	atomic64_sub_if_positive(1, v)

/*
 * atomic64_inc - increment atomic variable
 * @v: pointer of type atomic64_t
 *
 * Atomically increments @v by 1.
 */
#define atomic64_inc(v) atomic64_add(1, (v))
#define atomic64_inc_unchecked(v) atomic64_add_unchecked(1, (v))

/*
 * atomic64_dec - decrement and test
 * @v: pointer of type atomic64_t
 *
 * Atomically decrements @v by 1.
 */
#define atomic64_dec(v) atomic64_sub(1, (v))
#define atomic64_dec_unchecked(v) atomic64_sub_unchecked(1, (v))

/*
 * atomic64_add_negative - add and test if negative
 * @v: pointer of type atomic64_t
 * @i: integer value to add
 *
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
#define atomic64_add_negative(i, v) (atomic64_add_return(i, (v)) < 0)

#endif /* CONFIG_64BIT */

/*
 * atomic*_return operations are serializing but not the non-*_return
 * versions.
 */
#define smp_mb__before_atomic_dec()	smp_mb__before_llsc()
#define smp_mb__after_atomic_dec()	smp_llsc_mb()
#define smp_mb__before_atomic_inc()	smp_mb__before_llsc()
#define smp_mb__after_atomic_inc()	smp_llsc_mb()

#endif /* _ASM_ATOMIC_H */

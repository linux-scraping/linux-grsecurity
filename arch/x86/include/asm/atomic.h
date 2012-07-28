#ifndef _ASM_X86_ATOMIC_H
#define _ASM_X86_ATOMIC_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <asm/processor.h>
#include <asm/alternative.h>
#include <asm/cmpxchg.h>

/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 */

#define ATOMIC_INIT(i)	{ (i) }

/**
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically reads the value of @v.
 */
static inline int atomic_read(const atomic_t *v)
{
	return (*(volatile const int *)&(v)->counter);
}

/**
 * atomic_read_unchecked - read atomic variable
 * @v: pointer of type atomic_unchecked_t
 *
 * Atomically reads the value of @v.
 */
static inline int atomic_read_unchecked(const atomic_unchecked_t *v)
{
	return (*(volatile const int *)&(v)->counter);
}

/**
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

/**
 * atomic_set_unchecked - set atomic variable
 * @v: pointer of type atomic_unchecked_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
static inline void atomic_set_unchecked(atomic_unchecked_t *v, int i)
{
	v->counter = i;
}

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */
static inline void atomic_add(int i, atomic_t *v)
{
	asm volatile(LOCK_PREFIX "addl %1,%0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     LOCK_PREFIX "subl %1,%0\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     : "+m" (v->counter)
		     : "ir" (i));
}

/**
 * atomic_add_unchecked - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_unchecked_t
 *
 * Atomically adds @i to @v.
 */
static inline void atomic_add_unchecked(int i, atomic_unchecked_t *v)
{
	asm volatile(LOCK_PREFIX "addl %1,%0\n"
		     : "+m" (v->counter)
		     : "ir" (i));
}

/**
 * atomic_sub - subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.
 */
static inline void atomic_sub(int i, atomic_t *v)
{
	asm volatile(LOCK_PREFIX "subl %1,%0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     LOCK_PREFIX "addl %1,%0\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     : "+m" (v->counter)
		     : "ir" (i));
}

/**
 * atomic_sub_unchecked - subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_unchecked_t
 *
 * Atomically subtracts @i from @v.
 */
static inline void atomic_sub_unchecked(int i, atomic_unchecked_t *v)
{
	asm volatile(LOCK_PREFIX "subl %1,%0\n"
		     : "+m" (v->counter)
		     : "ir" (i));
}

/**
 * atomic_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
static inline int atomic_sub_and_test(int i, atomic_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "subl %2,%0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     LOCK_PREFIX "addl %2,%0\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     "sete %1\n"
		     : "+m" (v->counter), "=qm" (c)
		     : "ir" (i) : "memory");
	return c;
}

/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
static inline void atomic_inc(atomic_t *v)
{
	asm volatile(LOCK_PREFIX "incl %0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     LOCK_PREFIX "decl %0\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     : "+m" (v->counter));
}

/**
 * atomic_inc_unchecked - increment atomic variable
 * @v: pointer of type atomic_unchecked_t
 *
 * Atomically increments @v by 1.
 */
static inline void atomic_inc_unchecked(atomic_unchecked_t *v)
{
	asm volatile(LOCK_PREFIX "incl %0\n"
		     : "+m" (v->counter));
}

/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
static inline void atomic_dec(atomic_t *v)
{
	asm volatile(LOCK_PREFIX "decl %0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     LOCK_PREFIX "incl %0\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     : "+m" (v->counter));
}

/**
 * atomic_dec_unchecked - decrement atomic variable
 * @v: pointer of type atomic_unchecked_t
 *
 * Atomically decrements @v by 1.
 */
static inline void atomic_dec_unchecked(atomic_unchecked_t *v)
{
	asm volatile(LOCK_PREFIX "decl %0\n"
		     : "+m" (v->counter));
}

/**
 * atomic_dec_and_test - decrement and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
static inline int atomic_dec_and_test(atomic_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "decl %0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     LOCK_PREFIX "incl %0\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     "sete %1\n"
		     : "+m" (v->counter), "=qm" (c)
		     : : "memory");
	return c != 0;
}

/**
 * atomic_inc_and_test - increment and test
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
static inline int atomic_inc_and_test(atomic_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "incl %0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     LOCK_PREFIX "decl %0\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     "sete %1\n"
		     : "+m" (v->counter), "=qm" (c)
		     : : "memory");
	return c != 0;
}

/**
 * atomic_inc_and_test_unchecked - increment and test
 * @v: pointer of type atomic_unchecked_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
static inline int atomic_inc_and_test_unchecked(atomic_unchecked_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "incl %0\n"
		     "sete %1\n"
		     : "+m" (v->counter), "=qm" (c)
		     : : "memory");
	return c != 0;
}

/**
 * atomic_add_negative - add and test if negative
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
static inline int atomic_add_negative(int i, atomic_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "addl %2,%0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     LOCK_PREFIX "subl %2,%0\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     "sets %1\n"
		     : "+m" (v->counter), "=qm" (c)
		     : "ir" (i) : "memory");
	return c;
}

/**
 * atomic_add_return - add integer and return
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v and returns @i + @v
 */
static inline int atomic_add_return(int i, atomic_t *v)
{
#ifdef CONFIG_M386
	int __i;
	unsigned long flags;
	if (unlikely(boot_cpu_data.x86 <= 3))
		goto no_xadd;
#endif
	/* Modern 486+ processor */
	return i + xadd_check_overflow(&v->counter, i);

#ifdef CONFIG_M386
no_xadd: /* Legacy 386 processor */
	raw_local_irq_save(flags);
	__i = atomic_read(v);
	atomic_set(v, i + __i);
	raw_local_irq_restore(flags);
	return i + __i;
#endif
}

/**
 * atomic_add_return_unchecked - add integer and return
 * @i: integer value to add
 * @v: pointer of type atomic_unchecked_t
 *
 * Atomically adds @i to @v and returns @i + @v
 */
static inline int atomic_add_return_unchecked(int i, atomic_unchecked_t *v)
{
#ifdef CONFIG_M386
	int __i;
	unsigned long flags;
	if (unlikely(boot_cpu_data.x86 <= 3))
		goto no_xadd;
#endif
	/* Modern 486+ processor */
	return i + xadd(&v->counter, i);

#ifdef CONFIG_M386
no_xadd: /* Legacy 386 processor */
	raw_local_irq_save(flags);
	__i = atomic_read_unchecked(v);
	atomic_set_unchecked(v, i + __i);
	raw_local_irq_restore(flags);
	return i + __i;
#endif
}

/**
 * atomic_sub_return - subtract integer and return
 * @v: pointer of type atomic_t
 * @i: integer value to subtract
 *
 * Atomically subtracts @i from @v and returns @v - @i
 */
static inline int atomic_sub_return(int i, atomic_t *v)
{
	return atomic_add_return(-i, v);
}

#define atomic_inc_return(v)  (atomic_add_return(1, v))
static inline int atomic_inc_return_unchecked(atomic_unchecked_t *v)
{
	return atomic_add_return_unchecked(1, v);
}
#define atomic_dec_return(v)  (atomic_sub_return(1, v))

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return cmpxchg(&v->counter, old, new);
}

static inline int atomic_cmpxchg_unchecked(atomic_unchecked_t *v, int old, int new)
{
	return cmpxchg(&v->counter, old, new);
}

static inline int atomic_xchg(atomic_t *v, int new)
{
	return xchg(&v->counter, new);
}

static inline int atomic_xchg_unchecked(atomic_unchecked_t *v, int new)
{
	return xchg(&v->counter, new);
}

/**
 * __atomic_add_unless - add unless the number is already a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as @v was not already @u.
 * Returns the old value of @v.
 */
static inline int __atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old, new;
	c = atomic_read(v);
	for (;;) {
		if (unlikely(c == u))
			break;

		asm volatile("addl %2,%0\n"

#ifdef CONFIG_PAX_REFCOUNT
			     "jno 0f\n"
			     "subl %2,%0\n"
			     "int $4\n0:\n"
			     _ASM_EXTABLE(0b, 0b)
#endif

			     : "=r" (new)
			     : "0" (c), "ir" (a));

		old = atomic_cmpxchg(v, c, new);
		if (likely(old == c))
			break;
		c = old;
	}
	return c;
}

/**
 * atomic_inc_not_zero_hint - increment if not null
 * @v: pointer of type atomic_t
 * @hint: probable value of the atomic before the increment
 *
 * This version of atomic_inc_not_zero() gives a hint of probable
 * value of the atomic. This helps processor to not read the memory
 * before doing the atomic read/modify/write cycle, lowering
 * number of bus transactions on some arches.
 *
 * Returns: 0 if increment was not done, 1 otherwise.
 */
#define atomic_inc_not_zero_hint atomic_inc_not_zero_hint
static inline int atomic_inc_not_zero_hint(atomic_t *v, int hint)
{
	int val, c = hint, new;

	/* sanity test, should be removed by compiler if hint is a constant */
	if (!hint)
		return __atomic_add_unless(v, 1, 0);

	do {
		asm volatile("incl %0\n"

#ifdef CONFIG_PAX_REFCOUNT
			     "jno 0f\n"
			     "decl %0\n"
			     "int $4\n0:\n"
			     _ASM_EXTABLE(0b, 0b)
#endif

			     : "=r" (new)
			     : "0" (c));

		val = atomic_cmpxchg(v, c, new);
		if (val == c)
			return 1;
		c = val;
	} while (c);

	return 0;
}

/*
 * atomic_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic_t
 *
 * The function returns the old value of *v minus 1, even if
 * the atomic variable, v, was not decremented.
 */
static inline int atomic_dec_if_positive(atomic_t *v)
{
	int c, old, dec;
	c = atomic_read(v);
	for (;;) {
		dec = c - 1;
		if (unlikely(dec < 0))
			break;
		old = atomic_cmpxchg((v), c, dec);
		if (likely(old == c))
			break;
		c = old;
	}
	return dec;
}

/**
 * atomic_inc_short - increment of a short integer
 * @v: pointer to type int
 *
 * Atomically adds 1 to @v
 * Returns the new value of @u
 */
static inline short int atomic_inc_short(short int *v)
{
	asm(LOCK_PREFIX "addw $1, %0" : "+m" (*v));
	return *v;
}

#ifdef CONFIG_X86_64
/**
 * atomic_or_long - OR of two long integers
 * @v1: pointer to type unsigned long
 * @v2: pointer to type unsigned long
 *
 * Atomically ORs @v1 and @v2
 * Returns the result of the OR
 */
static inline void atomic_or_long(unsigned long *v1, unsigned long v2)
{
	asm(LOCK_PREFIX "orq %1, %0" : "+m" (*v1) : "r" (v2));
}
#endif

/* These are x86-specific, used by some header files */
static inline void atomic_clear_mask(unsigned int mask, atomic_t *v)
{
	asm volatile(LOCK_PREFIX "andl %1,%0"
		     : "+m" (v->counter)
		     : "r" (~(mask))
		     : "memory");
}

static inline void atomic_clear_mask_unchecked(unsigned int mask, atomic_unchecked_t *v)
{
	asm volatile(LOCK_PREFIX "andl %1,%0"
		     : "+m" (v->counter)
		     : "r" (~(mask))
		     : "memory");
}

static inline void atomic_set_mask(unsigned int mask, atomic_t *v)
{
	asm volatile(LOCK_PREFIX "orl %1,%0"
		     : "+m" (v->counter)
		     : "r" (mask)
		     : "memory");
}

static inline void atomic_set_mask_unchecked(unsigned int mask, atomic_unchecked_t *v)
{
	asm volatile(LOCK_PREFIX "orl %1,%0"
		     : "+m" (v->counter)
		     : "r" (mask)
		     : "memory");
}

/* Atomic operations are already serializing on x86 */
#define smp_mb__before_atomic_dec()	barrier()
#define smp_mb__after_atomic_dec()	barrier()
#define smp_mb__before_atomic_inc()	barrier()
#define smp_mb__after_atomic_inc()	barrier()

#ifdef CONFIG_X86_32
# include "atomic64_32.h"
#else
# include "atomic64_64.h"
#endif

#endif /* _ASM_X86_ATOMIC_H */

#ifndef _ASM_X86_ATOMIC_64_H
#define _ASM_X86_ATOMIC_64_H

#include <linux/types.h>
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
	return v->counter;
}

/**
 * atomic_read_unchecked - read atomic variable
 * @v: pointer of type atomic_unchecked_t
 *
 * Atomically reads the value of @v.
 */
static inline int atomic_read_unchecked(const atomic_unchecked_t *v)
{
	return v->counter;
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

		     : "=m" (v->counter)
		     : "ir" (i), "m" (v->counter));
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
		     : "=m" (v->counter)
		     : "ir" (i), "m" (v->counter));
}

/**
 * atomic_sub - subtract the atomic variable
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

		     : "=m" (v->counter)
		     : "ir" (i), "m" (v->counter));
}

/**
 * atomic_sub_unchecked - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_unchecked_t
 *
 * Atomically subtracts @i from @v.
 */
static inline void atomic_sub_unchecked(int i, atomic_unchecked_t *v)
{
	asm volatile(LOCK_PREFIX "subl %1,%0\n"
		     : "=m" (v->counter)
		     : "ir" (i), "m" (v->counter));
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
		     : "=m" (v->counter), "=qm" (c)
		     : "ir" (i), "m" (v->counter) : "memory");
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
		     "int $4\n0:\n"
		     ".pushsection .fixup,\"ax\"\n"
		     "1:\n"
		     LOCK_PREFIX "decl %0\n"
		     "jmp 0b\n"
		     ".popsection\n"
		     _ASM_EXTABLE(0b, 1b)
#endif

		     : "=m" (v->counter)
		     : "m" (v->counter));
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
		     : "=m" (v->counter)
		     : "m" (v->counter));
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
		     "int $4\n0:\n"
		     ".pushsection .fixup,\"ax\"\n"
		     "1: \n"
		     LOCK_PREFIX "incl %0\n"
		     "jmp 0b\n"
		     ".popsection\n"
		     _ASM_EXTABLE(0b, 1b)
#endif

		     : "=m" (v->counter)
		     : "m" (v->counter));
}

/**
 * atomic_dec_unchecked - decrement atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
static inline void atomic_dec_unchecked(atomic_unchecked_t *v)
{
	asm volatile(LOCK_PREFIX "decl %0\n"
		     : "=m" (v->counter)
		     : "m" (v->counter));
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
		     "int $4\n0:\n"
		     ".pushsection .fixup,\"ax\"\n"
		     "1: \n"
		     LOCK_PREFIX "incl %0\n"
		     "jmp 0b\n"
		     ".popsection\n"
		     _ASM_EXTABLE(0b, 1b)
#endif

		     "sete %1\n"
		     : "=m" (v->counter), "=qm" (c)
		     : "m" (v->counter) : "memory");
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
		     "int $4\n0:\n"
		     ".pushsection .fixup,\"ax\"\n"
		     "1: \n"
		     LOCK_PREFIX "decl %0\n"
		     "jmp 0b\n"
		     ".popsection\n"
		     _ASM_EXTABLE(0b, 1b)
#endif

		     "sete %1\n"
		     : "=m" (v->counter), "=qm" (c)
		     : "m" (v->counter) : "memory");
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
		     : "=m" (v->counter), "=qm" (c)
		     : "ir" (i), "m" (v->counter) : "memory");
	return c;
}

/**
 * atomic_add_return - add and return
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v and returns @i + @v
 */
static inline int atomic_add_return(int i, atomic_t *v)
{
	int __i = i;
	asm volatile(LOCK_PREFIX "xaddl %0, %1\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     "movl %0, %1\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     : "+r" (i), "+m" (v->counter)
		     : : "memory");
	return i + __i;
}

/**
 * atomic_add_return_unchecked - add and return
 * @i: integer value to add
 * @v: pointer of type atomic_unchecked_t
 *
 * Atomically adds @i to @v and returns @i + @v
 */
static inline int atomic_add_return_unchecked(int i, atomic_unchecked_t *v)
{
	int __i = i;
	asm volatile(LOCK_PREFIX "xaddl %0, %1\n"
		     : "+r" (i), "+m" (v->counter)
		     : : "memory");
	return i + __i;
}

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

/* The 64-bit atomic type */

#define ATOMIC64_INIT(i)	{ (i) }

/**
 * atomic64_read - read atomic64 variable
 * @v: pointer of type atomic64_t
 *
 * Atomically reads the value of @v.
 * Doesn't imply a read memory barrier.
 */
static inline long atomic64_read(const atomic64_t *v)
{
	return v->counter;
}

/**
 * atomic64_read_unchecked - read atomic64 variable
 * @v: pointer of type atomic64_unchecked_t
 *
 * Atomically reads the value of @v.
 * Doesn't imply a read memory barrier.
 */
static inline long atomic64_read_unchecked(const atomic64_unchecked_t *v)
{
	return v->counter;
}

/**
 * atomic64_set - set atomic64 variable
 * @v: pointer to type atomic64_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
static inline void atomic64_set(atomic64_t *v, long i)
{
	v->counter = i;
}

/**
 * atomic64_set_unchecked - set atomic64 variable
 * @v: pointer to type atomic64_unchecked_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
static inline void atomic64_set_unchecked(atomic64_unchecked_t *v, long i)
{
	v->counter = i;
}

/**
 * atomic64_add - add integer to atomic64 variable
 * @i: integer value to add
 * @v: pointer to type atomic64_t
 *
 * Atomically adds @i to @v.
 */
static inline void atomic64_add(long i, atomic64_t *v)
{
	asm volatile(LOCK_PREFIX "addq %1,%0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     LOCK_PREFIX "subq %1,%0\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     : "=m" (v->counter)
		     : "er" (i), "m" (v->counter));
}

/**
 * atomic64_add_unchecked - add integer to atomic64 variable
 * @i: integer value to add
 * @v: pointer to type atomic64_unchecked_t
 *
 * Atomically adds @i to @v.
 */
static inline void atomic64_add_unchecked(long i, atomic64_unchecked_t *v)
{
	asm volatile(LOCK_PREFIX "addq %1,%0"
		     : "=m" (v->counter)
		     : "er" (i), "m" (v->counter));
}

/**
 * atomic64_sub - subtract the atomic64 variable
 * @i: integer value to subtract
 * @v: pointer to type atomic64_t
 *
 * Atomically subtracts @i from @v.
 */
static inline void atomic64_sub(long i, atomic64_t *v)
{
	asm volatile(LOCK_PREFIX "subq %1,%0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     LOCK_PREFIX "addq %1,%0\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     : "=m" (v->counter)
		     : "er" (i), "m" (v->counter));
}

/**
 * atomic64_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer to type atomic64_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
static inline int atomic64_sub_and_test(long i, atomic64_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "subq %2,%0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     LOCK_PREFIX "addq %2,%0\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     "sete %1\n"
		     : "=m" (v->counter), "=qm" (c)
		     : "er" (i), "m" (v->counter) : "memory");
	return c;
}

/**
 * atomic64_inc - increment atomic64 variable
 * @v: pointer to type atomic64_t
 *
 * Atomically increments @v by 1.
 */
static inline void atomic64_inc(atomic64_t *v)
{
	asm volatile(LOCK_PREFIX "incq %0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     "int $4\n0:\n"
		     ".pushsection .fixup,\"ax\"\n"
		     "1:\n"
		     LOCK_PREFIX "decq %0\n"
		     "jmp 0b\n"
		     ".popsection\n"
		     _ASM_EXTABLE(0b, 1b)
#endif

		     : "=m" (v->counter)
		     : "m" (v->counter));
}

/**
 * atomic64_inc_unchecked - increment atomic64 variable
 * @v: pointer to type atomic64_unchecked_t
 *
 * Atomically increments @v by 1.
 */
static inline void atomic64_inc_unchecked(atomic64_unchecked_t *v)
{
	asm volatile(LOCK_PREFIX "incq %0"
		     : "=m" (v->counter)
		     : "m" (v->counter));
}

/**
 * atomic64_dec - decrement atomic64 variable
 * @v: pointer to type atomic64_t
 *
 * Atomically decrements @v by 1.
 */
static inline void atomic64_dec(atomic64_t *v)
{
	asm volatile(LOCK_PREFIX "decq %0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     "int $4\n0:\n"
		     ".pushsection .fixup,\"ax\"\n"
		     "1: \n"
		     LOCK_PREFIX "incq %0\n"
		     "jmp 0b\n"
		     ".popsection\n"
		     _ASM_EXTABLE(0b, 1b)
#endif

		     : "=m" (v->counter)
		     : "m" (v->counter));
}

/**
 * atomic64_dec_unchecked - decrement atomic64 variable
 * @v: pointer to type atomic64_t
 *
 * Atomically decrements @v by 1.
 */
static inline void atomic64_dec_unchecked(atomic64_unchecked_t *v)
{
	asm volatile(LOCK_PREFIX "decq %0\n"
		     : "=m" (v->counter)
		     : "m" (v->counter));
}

/**
 * atomic64_dec_and_test - decrement and test
 * @v: pointer to type atomic64_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
static inline int atomic64_dec_and_test(atomic64_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "decq %0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     "int $4\n0:\n"
		     ".pushsection .fixup,\"ax\"\n"
		     "1: \n"
		     LOCK_PREFIX "incq %0\n"
		     "jmp 0b\n"
		     ".popsection\n"
		     _ASM_EXTABLE(0b, 1b)
#endif

		     "sete %1\n"
		     : "=m" (v->counter), "=qm" (c)
		     : "m" (v->counter) : "memory");
	return c != 0;
}

/**
 * atomic64_inc_and_test - increment and test
 * @v: pointer to type atomic64_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
static inline int atomic64_inc_and_test(atomic64_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "incq %0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     "int $4\n0:\n"
		     ".pushsection .fixup,\"ax\"\n"
		     "1: \n"
		     LOCK_PREFIX "decq %0\n"
		     "jmp 0b\n"
		     ".popsection\n"
		     _ASM_EXTABLE(0b, 1b)
#endif

		     "sete %1\n"
		     : "=m" (v->counter), "=qm" (c)
		     : "m" (v->counter) : "memory");
	return c != 0;
}

/**
 * atomic64_add_negative - add and test if negative
 * @i: integer value to add
 * @v: pointer to type atomic64_t
 *
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
static inline int atomic64_add_negative(long i, atomic64_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "addq %2,%0\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     LOCK_PREFIX "subq %2,%0\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     "sets %1\n"
		     : "=m" (v->counter), "=qm" (c)
		     : "er" (i), "m" (v->counter) : "memory");
	return c;
}

/**
 * atomic64_add_return - add and return
 * @i: integer value to add
 * @v: pointer to type atomic64_t
 *
 * Atomically adds @i to @v and returns @i + @v
 */
static inline long atomic64_add_return(long i, atomic64_t *v)
{
	long __i = i;
	asm volatile(LOCK_PREFIX "xaddq %0, %1\n"

#ifdef CONFIG_PAX_REFCOUNT
		     "jno 0f\n"
		     "movq %0, %1\n"
		     "int $4\n0:\n"
		     _ASM_EXTABLE(0b, 0b)
#endif

		     : "+r" (i), "+m" (v->counter)
		     : : "memory");
	return i + __i;
}

/**
 * atomic64_add_return_unchecked - add and return
 * @i: integer value to add
 * @v: pointer to type atomic64_unchecked_t
 *
 * Atomically adds @i to @v and returns @i + @v
 */
static inline long atomic64_add_return_unchecked(long i, atomic64_unchecked_t *v)
{
	long __i = i;
	asm volatile(LOCK_PREFIX "xaddq %0, %1"
		     : "+r" (i), "+m" (v->counter)
		     : : "memory");
	return i + __i;
}

static inline long atomic64_sub_return(long i, atomic64_t *v)
{
	return atomic64_add_return(-i, v);
}

#define atomic64_inc_return(v)  (atomic64_add_return(1, (v)))
static inline long atomic64_inc_return_unchecked(atomic64_unchecked_t *v)
{
	return atomic64_add_return_unchecked(1, v);
}
#define atomic64_dec_return(v)  (atomic64_sub_return(1, (v)))

static inline long atomic64_cmpxchg(atomic64_t *v, long old, long new)
{
	return cmpxchg(&v->counter, old, new);
}

static inline long atomic64_xchg(atomic64_t *v, long new)
{
	return xchg(&v->counter, new);
}

static inline long atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return cmpxchg(&v->counter, old, new);
}

static inline long atomic_xchg(atomic_t *v, int new)
{
	return xchg(&v->counter, new);
}

/**
 * atomic_add_unless - add unless the number is a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns non-zero if @v was not @u, and zero otherwise.
 */
static inline int atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old, new;
	c = atomic_read(v);
	for (;;) {
		if (unlikely(c == u))
			break;

		asm volatile("addl %2,%0\n"

#ifdef CONFIG_PAX_REFCOUNT
			     "jno 0f\n"
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
	return c != u;
}

#define atomic_inc_not_zero(v) atomic_add_unless((v), 1, 0)

/**
 * atomic64_add_unless - add unless the number is a given value
 * @v: pointer of type atomic64_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns non-zero if @v was not @u, and zero otherwise.
 */
static inline int atomic64_add_unless(atomic64_t *v, long a, long u)
{
	long c, old, new;
	c = atomic64_read(v);
	for (;;) {
		if (unlikely(c == u))
			break;

		asm volatile("addq %2,%0\n"

#ifdef CONFIG_PAX_REFCOUNT
			     "jno 0f\n"
			     "int $4\n0:\n"
			     _ASM_EXTABLE(0b, 0b)
#endif

			     : "=r" (new)
			     : "0" (c), "er" (a));

		old = atomic64_cmpxchg(v, c, new);
		if (likely(old == c))
			break;
		c = old;
	}
	return c != u;
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

#define atomic64_inc_not_zero(v) atomic64_add_unless((v), 1, 0)

/* These are x86-specific, used by some header files */
#define atomic_clear_mask(mask, addr)					\
	asm volatile(LOCK_PREFIX "andl %0,%1"				\
		     : : "r" (~(mask)), "m" (*(addr)) : "memory")

#define atomic_set_mask(mask, addr)					\
	asm volatile(LOCK_PREFIX "orl %0,%1"				\
		     : : "r" ((unsigned)(mask)), "m" (*(addr))		\
		     : "memory")

/* Atomic operations are already serializing on x86 */
#define smp_mb__before_atomic_dec()	barrier()
#define smp_mb__after_atomic_dec()	barrier()
#define smp_mb__before_atomic_inc()	barrier()
#define smp_mb__after_atomic_inc()	barrier()

#include <asm-generic/atomic-long.h>
#endif /* _ASM_X86_ATOMIC_64_H */

/* atomic.h: Thankfully the V9 is at least reasonable for this
 *           stuff.
 *
 * Copyright (C) 1996, 1997, 2000, 2012 David S. Miller (davem@redhat.com)
 */

#ifndef __ARCH_SPARC64_ATOMIC__
#define __ARCH_SPARC64_ATOMIC__

#include <linux/types.h>
#include <asm/cmpxchg.h>

#define ATOMIC_INIT(i)		{ (i) }
#define ATOMIC64_INIT(i)	{ (i) }

#define atomic_read(v)		(*(volatile int *)&(v)->counter)
static inline int atomic_read_unchecked(const atomic_unchecked_t *v)
{
	return *(const volatile int *)&v->counter;
}
#define atomic64_read(v)	(*(volatile long *)&(v)->counter)
static inline long atomic64_read_unchecked(const atomic64_unchecked_t *v)
{
	return *(const volatile long *)&v->counter;
}

#define atomic_set(v, i)	(((v)->counter) = i)
static inline void atomic_set_unchecked(atomic_unchecked_t *v, int i)
{
	v->counter = i;
}
#define atomic64_set(v, i)	(((v)->counter) = i)
static inline void atomic64_set_unchecked(atomic64_unchecked_t *v, long i)
{
	v->counter = i;
}

extern void atomic_add(int, atomic_t *);
extern void atomic_add_unchecked(int, atomic_unchecked_t *);
extern void atomic64_add(long, atomic64_t *);
extern void atomic64_add_unchecked(long, atomic64_unchecked_t *);
extern void atomic_sub(int, atomic_t *);
extern void atomic_sub_unchecked(int, atomic_unchecked_t *);
extern void atomic64_sub(long, atomic64_t *);
extern void atomic64_sub_unchecked(long, atomic64_unchecked_t *);

extern int atomic_add_ret(int, atomic_t *);
extern int atomic_add_ret_unchecked(int, atomic_unchecked_t *);
extern long atomic64_add_ret(long, atomic64_t *);
extern long atomic64_add_ret_unchecked(long, atomic64_unchecked_t *);
extern int atomic_sub_ret(int, atomic_t *);
extern long atomic64_sub_ret(long, atomic64_t *);

#define atomic_dec_return(v) atomic_sub_ret(1, v)
#define atomic64_dec_return(v) atomic64_sub_ret(1, v)

#define atomic_inc_return(v) atomic_add_ret(1, v)
static inline int atomic_inc_return_unchecked(atomic_unchecked_t *v)
{
	return atomic_add_ret_unchecked(1, v);
}
#define atomic64_inc_return(v) atomic64_add_ret(1, v)
static inline long atomic64_inc_return_unchecked(atomic64_unchecked_t *v)
{
	return atomic64_add_ret_unchecked(1, v);
}

#define atomic_sub_return(i, v) atomic_sub_ret(i, v)
#define atomic64_sub_return(i, v) atomic64_sub_ret(i, v)

#define atomic_add_return(i, v) atomic_add_ret(i, v)
static inline int atomic_add_return_unchecked(int i, atomic_unchecked_t *v)
{
	return atomic_add_ret_unchecked(i, v);
}
#define atomic64_add_return(i, v) atomic64_add_ret(i, v)
static inline long atomic64_add_return_unchecked(long i, atomic64_unchecked_t *v)
{
	return atomic64_add_ret_unchecked(i, v);
}

/*
 * atomic_inc_and_test - increment and test
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
#define atomic_inc_and_test(v) (atomic_inc_return(v) == 0)
static inline int atomic_inc_and_test_unchecked(atomic_unchecked_t *v)
{
	return atomic_inc_return_unchecked(v) == 0;
}
#define atomic64_inc_and_test(v) (atomic64_inc_return(v) == 0)

#define atomic_sub_and_test(i, v) (atomic_sub_ret(i, v) == 0)
#define atomic64_sub_and_test(i, v) (atomic64_sub_ret(i, v) == 0)

#define atomic_dec_and_test(v) (atomic_sub_ret(1, v) == 0)
#define atomic64_dec_and_test(v) (atomic64_sub_ret(1, v) == 0)

#define atomic_inc(v) atomic_add(1, v)
static inline void atomic_inc_unchecked(atomic_unchecked_t *v)
{
	atomic_add_unchecked(1, v);
}
#define atomic64_inc(v) atomic64_add(1, v)
static inline void atomic64_inc_unchecked(atomic64_unchecked_t *v)
{
	atomic64_add_unchecked(1, v);
}

#define atomic_dec(v) atomic_sub(1, v)
static inline void atomic_dec_unchecked(atomic_unchecked_t *v)
{
	atomic_sub_unchecked(1, v);
}
#define atomic64_dec(v) atomic64_sub(1, v)
static inline void atomic64_dec_unchecked(atomic64_unchecked_t *v)
{
	atomic64_sub_unchecked(1, v);
}

#define atomic_add_negative(i, v) (atomic_add_ret(i, v) < 0)
#define atomic64_add_negative(i, v) (atomic64_add_ret(i, v) < 0)

#define atomic_cmpxchg(v, o, n) (cmpxchg(&((v)->counter), (o), (n)))
static inline int atomic_cmpxchg_unchecked(atomic_unchecked_t *v, int old, int new)
{
	return cmpxchg(&v->counter, old, new);
}
#define atomic_xchg(v, new) (xchg(&((v)->counter), new))
static inline int atomic_xchg_unchecked(atomic_unchecked_t *v, int new)
{
	return xchg(&v->counter, new);
}

static inline int __atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old, new;
	c = atomic_read(v);
	for (;;) {
		if (unlikely(c == u))
			break;

		asm volatile("addcc %2, %0, %0\n"

#ifdef CONFIG_PAX_REFCOUNT
			     "tvs %%icc, 6\n"
#endif

			     : "=r" (new)
			     : "0" (c), "ir" (a)
			     : "cc");

		old = atomic_cmpxchg(v, c, new);
		if (likely(old == c))
			break;
		c = old;
	}
	return c;
}

#define atomic64_cmpxchg(v, o, n) \
	((__typeof__((v)->counter))cmpxchg(&((v)->counter), (o), (n)))
#define atomic64_xchg(v, new) (xchg(&((v)->counter), new))
static inline long atomic64_xchg_unchecked(atomic64_unchecked_t *v, long new)
{
	return xchg(&v->counter, new);
}

static inline long atomic64_add_unless(atomic64_t *v, long a, long u)
{
	long c, old, new;
	c = atomic64_read(v);
	for (;;) {
		if (unlikely(c == u))
			break;

		asm volatile("addcc %2, %0, %0\n"

#ifdef CONFIG_PAX_REFCOUNT
			     "tvs %%xcc, 6\n"
#endif

			     : "=r" (new)
			     : "0" (c), "ir" (a)
			     : "cc");

		old = atomic64_cmpxchg(v, c, new);
		if (likely(old == c))
			break;
		c = old;
	}
	return c != u;
}

#define atomic64_inc_not_zero(v) atomic64_add_unless((v), 1, 0)

extern long atomic64_dec_if_positive(atomic64_t *v);

/* Atomic operations are already serializing */
#define smp_mb__before_atomic_dec()	barrier()
#define smp_mb__after_atomic_dec()	barrier()
#define smp_mb__before_atomic_inc()	barrier()
#define smp_mb__after_atomic_inc()	barrier()

#endif /* !(__ARCH_SPARC64_ATOMIC__) */

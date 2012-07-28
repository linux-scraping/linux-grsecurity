#ifndef _ASM_GENERIC_ATOMIC_LONG_H
#define _ASM_GENERIC_ATOMIC_LONG_H
/*
 * Copyright (C) 2005 Silicon Graphics, Inc.
 *	Christoph Lameter
 *
 * Allows to provide arch independent atomic definitions without the need to
 * edit all arch specific atomic.h files.
 */

#include <asm/types.h>

/*
 * Suppport for atomic_long_t
 *
 * Casts for parameters are avoided for existing atomic functions in order to
 * avoid issues with cast-as-lval under gcc 4.x and other limitations that the
 * macros of a platform may have.
 */

#if BITS_PER_LONG == 64

typedef atomic64_t atomic_long_t;

#ifdef CONFIG_PAX_REFCOUNT
typedef atomic64_unchecked_t atomic_long_unchecked_t;
#else
typedef atomic64_t atomic_long_unchecked_t;
#endif

#define ATOMIC_LONG_INIT(i)	ATOMIC64_INIT(i)

static inline long atomic_long_read(atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	return (long)atomic64_read(v);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline long atomic_long_read_unchecked(atomic_long_unchecked_t *l)
{
	atomic64_unchecked_t *v = (atomic64_unchecked_t *)l;

	return (long)atomic64_read_unchecked(v);
}
#endif

static inline void atomic_long_set(atomic_long_t *l, long i)
{
	atomic64_t *v = (atomic64_t *)l;

	atomic64_set(v, i);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline void atomic_long_set_unchecked(atomic_long_unchecked_t *l, long i)
{
	atomic64_unchecked_t *v = (atomic64_unchecked_t *)l;

	atomic64_set_unchecked(v, i);
}
#endif

static inline void atomic_long_inc(atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	atomic64_inc(v);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline void atomic_long_inc_unchecked(atomic_long_unchecked_t *l)
{
	atomic64_unchecked_t *v = (atomic64_unchecked_t *)l;

	atomic64_inc_unchecked(v);
}
#endif

static inline void atomic_long_dec(atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	atomic64_dec(v);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline void atomic_long_dec_unchecked(atomic_long_unchecked_t *l)
{
	atomic64_unchecked_t *v = (atomic64_unchecked_t *)l;

	atomic64_dec_unchecked(v);
}
#endif

static inline void atomic_long_add(long i, atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	atomic64_add(i, v);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline void atomic_long_add_unchecked(long i, atomic_long_unchecked_t *l)
{
	atomic64_unchecked_t *v = (atomic64_unchecked_t *)l;

	atomic64_add_unchecked(i, v);
}
#endif

static inline void atomic_long_sub(long i, atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	atomic64_sub(i, v);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline void atomic_long_sub_unchecked(long i, atomic_long_unchecked_t *l)
{
	atomic64_unchecked_t *v = (atomic64_unchecked_t *)l;

	atomic64_sub_unchecked(i, v);
}
#endif

static inline int atomic_long_sub_and_test(long i, atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	return atomic64_sub_and_test(i, v);
}

static inline int atomic_long_dec_and_test(atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	return atomic64_dec_and_test(v);
}

static inline int atomic_long_inc_and_test(atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	return atomic64_inc_and_test(v);
}

static inline int atomic_long_add_negative(long i, atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	return atomic64_add_negative(i, v);
}

static inline long atomic_long_add_return(long i, atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	return (long)atomic64_add_return(i, v);
}

static inline long atomic_long_sub_return(long i, atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	return (long)atomic64_sub_return(i, v);
}

static inline long atomic_long_inc_return(atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	return (long)atomic64_inc_return(v);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline long atomic_long_inc_return_unchecked(atomic_long_unchecked_t *l)
{
	atomic64_unchecked_t *v = (atomic64_unchecked_t *)l;

	return (long)atomic64_inc_return_unchecked(v);
}
#endif

static inline long atomic_long_dec_return(atomic_long_t *l)
{
	atomic64_t *v = (atomic64_t *)l;

	return (long)atomic64_dec_return(v);
}

static inline long atomic_long_add_unless(atomic_long_t *l, long a, long u)
{
	atomic64_t *v = (atomic64_t *)l;

	return (long)atomic64_add_unless(v, a, u);
}

#define atomic_long_inc_not_zero(l) atomic64_inc_not_zero((atomic64_t *)(l))

#define atomic_long_cmpxchg(l, old, new) \
	(atomic64_cmpxchg((atomic64_t *)(l), (old), (new)))
#define atomic_long_xchg(v, new) \
	(atomic64_xchg((atomic64_t *)(v), (new)))

#else  /*  BITS_PER_LONG == 64  */

typedef atomic_t atomic_long_t;

#ifdef CONFIG_PAX_REFCOUNT
typedef atomic_unchecked_t atomic_long_unchecked_t;
#else
typedef atomic_t atomic_long_unchecked_t;
#endif

#define ATOMIC_LONG_INIT(i)	ATOMIC_INIT(i)
static inline long atomic_long_read(atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	return (long)atomic_read(v);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline long atomic_long_read_unchecked(atomic_long_unchecked_t *l)
{
	atomic_unchecked_t *v = (atomic_unchecked_t *)l;

	return (long)atomic_read_unchecked(v);
}
#endif

static inline void atomic_long_set(atomic_long_t *l, long i)
{
	atomic_t *v = (atomic_t *)l;

	atomic_set(v, i);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline void atomic_long_set_unchecked(atomic_long_unchecked_t *l, long i)
{
	atomic_unchecked_t *v = (atomic_unchecked_t *)l;

	atomic_set_unchecked(v, i);
}
#endif

static inline void atomic_long_inc(atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	atomic_inc(v);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline void atomic_long_inc_unchecked(atomic_long_unchecked_t *l)
{
	atomic_unchecked_t *v = (atomic_unchecked_t *)l;

	atomic_inc_unchecked(v);
}
#endif

static inline void atomic_long_dec(atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	atomic_dec(v);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline void atomic_long_dec_unchecked(atomic_long_unchecked_t *l)
{
	atomic_unchecked_t *v = (atomic_unchecked_t *)l;

	atomic_dec_unchecked(v);
}
#endif

static inline void atomic_long_add(long i, atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	atomic_add(i, v);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline void atomic_long_add_unchecked(long i, atomic_long_unchecked_t *l)
{
	atomic_unchecked_t *v = (atomic_unchecked_t *)l;

	atomic_add_unchecked(i, v);
}
#endif

static inline void atomic_long_sub(long i, atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	atomic_sub(i, v);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline void atomic_long_sub_unchecked(long i, atomic_long_unchecked_t *l)
{
	atomic_unchecked_t *v = (atomic_unchecked_t *)l;

	atomic_sub_unchecked(i, v);
}
#endif

static inline int atomic_long_sub_and_test(long i, atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	return atomic_sub_and_test(i, v);
}

static inline int atomic_long_dec_and_test(atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	return atomic_dec_and_test(v);
}

static inline int atomic_long_inc_and_test(atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	return atomic_inc_and_test(v);
}

static inline int atomic_long_add_negative(long i, atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	return atomic_add_negative(i, v);
}

static inline long atomic_long_add_return(long i, atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	return (long)atomic_add_return(i, v);
}

static inline long atomic_long_sub_return(long i, atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	return (long)atomic_sub_return(i, v);
}

static inline long atomic_long_inc_return(atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	return (long)atomic_inc_return(v);
}

#ifdef CONFIG_PAX_REFCOUNT
static inline long atomic_long_inc_return_unchecked(atomic_long_unchecked_t *l)
{
	atomic_unchecked_t *v = (atomic_unchecked_t *)l;

	return (long)atomic_inc_return_unchecked(v);
}
#endif

static inline long atomic_long_dec_return(atomic_long_t *l)
{
	atomic_t *v = (atomic_t *)l;

	return (long)atomic_dec_return(v);
}

static inline long atomic_long_add_unless(atomic_long_t *l, long a, long u)
{
	atomic_t *v = (atomic_t *)l;

	return (long)atomic_add_unless(v, a, u);
}

#define atomic_long_inc_not_zero(l) atomic_inc_not_zero((atomic_t *)(l))

#define atomic_long_cmpxchg(l, old, new) \
	(atomic_cmpxchg((atomic_t *)(l), (old), (new)))
#define atomic_long_xchg(v, new) \
	(atomic_xchg((atomic_t *)(v), (new)))

#endif  /*  BITS_PER_LONG == 64  */

#ifdef CONFIG_PAX_REFCOUNT
static inline void pax_refcount_needs_these_functions(void)
{
	atomic_read_unchecked((atomic_unchecked_t *)NULL);
	atomic_set_unchecked((atomic_unchecked_t *)NULL, 0);
	atomic_add_unchecked(0, (atomic_unchecked_t *)NULL);
	atomic_sub_unchecked(0, (atomic_unchecked_t *)NULL);
	atomic_inc_unchecked((atomic_unchecked_t *)NULL);
	(void)atomic_inc_and_test_unchecked((atomic_unchecked_t *)NULL);
	atomic_inc_return_unchecked((atomic_unchecked_t *)NULL);
	atomic_add_return_unchecked(0, (atomic_unchecked_t *)NULL);
	atomic_dec_unchecked((atomic_unchecked_t *)NULL);
	atomic_cmpxchg_unchecked((atomic_unchecked_t *)NULL, 0, 0);
	(void)atomic_xchg_unchecked((atomic_unchecked_t *)NULL, 0);
#ifdef CONFIG_X86
	atomic_clear_mask_unchecked(0, NULL);
	atomic_set_mask_unchecked(0, NULL);
#endif

	atomic_long_read_unchecked((atomic_long_unchecked_t *)NULL);
	atomic_long_set_unchecked((atomic_long_unchecked_t *)NULL, 0);
	atomic_long_add_unchecked(0, (atomic_long_unchecked_t *)NULL);
	atomic_long_sub_unchecked(0, (atomic_long_unchecked_t *)NULL);
	atomic_long_inc_unchecked((atomic_long_unchecked_t *)NULL);
	atomic_long_inc_return_unchecked((atomic_long_unchecked_t *)NULL);
	atomic_long_dec_unchecked((atomic_long_unchecked_t *)NULL);
}
#else
#define atomic_read_unchecked(v) atomic_read(v)
#define atomic_set_unchecked(v, i) atomic_set((v), (i))
#define atomic_add_unchecked(i, v) atomic_add((i), (v))
#define atomic_sub_unchecked(i, v) atomic_sub((i), (v))
#define atomic_inc_unchecked(v) atomic_inc(v)
#define atomic_inc_and_test_unchecked(v) atomic_inc_and_test(v)
#define atomic_inc_return_unchecked(v) atomic_inc_return(v)
#define atomic_add_return_unchecked(i, v) atomic_add_return((i), (v))
#define atomic_dec_unchecked(v) atomic_dec(v)
#define atomic_cmpxchg_unchecked(v, o, n) atomic_cmpxchg((v), (o), (n))
#define atomic_xchg_unchecked(v, i) atomic_xchg((v), (i))
#define atomic_clear_mask_unchecked(mask, v) atomic_clear_mask((mask), (v))
#define atomic_set_mask_unchecked(mask, v) atomic_set_mask((mask), (v))

#define atomic_long_read_unchecked(v) atomic_long_read(v)
#define atomic_long_set_unchecked(v, i) atomic_long_set((v), (i))
#define atomic_long_add_unchecked(i, v) atomic_long_add((i), (v))
#define atomic_long_sub_unchecked(i, v) atomic_long_sub((i), (v))
#define atomic_long_inc_unchecked(v) atomic_long_inc(v)
#define atomic_long_inc_return_unchecked(v) atomic_long_inc_return(v)
#define atomic_long_dec_unchecked(v) atomic_long_dec(v)
#endif

#endif  /*  _ASM_GENERIC_ATOMIC_LONG_H  */

#ifndef _ASM_POWERPC_ATOMIC_H_
#define _ASM_POWERPC_ATOMIC_H_

/*
 * PowerPC atomic operations
 */

#ifdef __KERNEL__
#include <linux/types.h>
#include <asm/cmpxchg.h>
#include <asm/barrier.h>

#define ATOMIC_INIT(i)		{ (i) }

#define _ASM_EXTABLE(from, to)			\
"	.section	__ex_table,\"a\"\n"	\
	PPC_LONG"	" #from ", " #to"\n"	\
"	.previous\n"

static __inline__ int atomic_read(const atomic_t *v)
{
	int t;

	__asm__ __volatile__("lwz%U1%X1 %0,%1" : "=r"(t) : "m"(v->counter));

	return t;
}

static __inline__ int atomic_read_unchecked(const atomic_unchecked_t *v)
{
	int t;

	__asm__ __volatile__("lwz%U1%X1 %0,%1" : "=r"(t) : "m"(v->counter));

	return t;
}

static __inline__ void atomic_set(atomic_t *v, int i)
{
	__asm__ __volatile__("stw%U0%X0 %1,%0" : "=m"(v->counter) : "r"(i));
}

static __inline__ void atomic_set_unchecked(atomic_unchecked_t *v, int i)
{
	__asm__ __volatile__("stw%U0%X0 %1,%0" : "=m"(v->counter) : "r"(i));
}

#ifdef CONFIG_PAX_REFCOUNT
#define __REFCOUNT_OP(op) op##o.
#define __OVERFLOW_PRE			\
	"	mcrxr	cr0\n"
#define __OVERFLOW_POST			\
	"	bf 4*cr0+so, 3f\n"	\
	"2:	.long 0x00c00b00\n"	\
	"3:\n"
#define __OVERFLOW_EXTABLE \
	"\n4:\n"
	_ASM_EXTABLE(2b, 4b)
#else
#define __REFCOUNT_OP(op) op
#define __OVERFLOW_PRE
#define __OVERFLOW_POST
#define __OVERFLOW_EXTABLE
#endif

#define __ATOMIC_OP(op, suffix, pre_op, asm_op, post_op, extable)	\
static inline void atomic_##op##suffix(int a, atomic##suffix##_t *v)	\
{									\
	int t;								\
									\
	__asm__ __volatile__(						\
"1:	lwarx	%0,0,%3		# atomic_" #op #suffix "\n"		\
	pre_op								\
	#asm_op " %0,%2,%0\n"						\
	post_op								\
	PPC405_ERR77(0,%3)						\
"	stwcx.	%0,0,%3 \n"						\
"	bne-	1b\n"							\
	extable								\
	: "=&r" (t), "+m" (v->counter)					\
	: "r" (a), "r" (&v->counter)					\
	: "cc");							\
}									\

#define ATOMIC_OP(op, asm_op) __ATOMIC_OP(op, , , asm_op, , )		\
			      __ATOMIC_OP(op, _unchecked, __OVERFLOW_PRE, __REFCOUNT_OP(asm_op), __OVERFLOW_POST, __OVERFLOW_EXTABLE)

#define __ATOMIC_OP_RETURN(op, suffix, pre_op, asm_op, post_op, extable)\
static inline int atomic_##op##_return##suffix(int a, atomic##suffix##_t *v)\
{									\
	int t;								\
									\
	__asm__ __volatile__(						\
	PPC_ATOMIC_ENTRY_BARRIER					\
"1:	lwarx	%0,0,%2		# atomic_" #op "_return" #suffix "\n"	\
	pre_op								\
	#asm_op " %0,%1,%0\n"						\
	post_op								\
	PPC405_ERR77(0,%2)						\
"	stwcx.	%0,0,%2 \n"						\
"	bne-	1b\n"							\
	extable								\
	PPC_ATOMIC_EXIT_BARRIER						\
	: "=&r" (t)							\
	: "r" (a), "r" (&v->counter)					\
	: "cc", "memory");						\
									\
	return t;							\
}

#define ATOMIC_OP_RETURN(op, asm_op) __ATOMIC_OP_RETURN(op, , , asm_op, , )\
				     __ATOMIC_OP_RETURN(op, _unchecked, __OVERFLOW_PRE, __REFCOUNT_OP(asm_op), __OVERFLOW_POST, __OVERFLOW_EXTABLE)

#define ATOMIC_OPS(op, asm_op) ATOMIC_OP(op, asm_op) ATOMIC_OP_RETURN(op, asm_op)

ATOMIC_OPS(add, add)
ATOMIC_OPS(sub, subf)

#undef ATOMIC_OPS
#undef ATOMIC_OP_RETURN
#undef __ATOMIC_OP_RETURN
#undef ATOMIC_OP
#undef __ATOMIC_OP

#define atomic_add_negative(a, v)	(atomic_add_return((a), (v)) < 0)

/*
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Automatically increments @v by 1
 */
#define atomic_inc(v) atomic_add(1, (v))
#define atomic_inc_return(v) atomic_add_return(1, (v))

static inline void atomic_inc_unchecked(atomic_unchecked_t *v)
{
	atomic_add_unchecked(1, v);
}

static inline int atomic_inc_return_unchecked(atomic_unchecked_t *v)
{
	return atomic_add_return_unchecked(1, v);
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

static __inline__ int atomic_inc_and_test_unchecked(atomic_unchecked_t *v)
{
	return atomic_add_return_unchecked(1, v) == 0;
}

/* 
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1
 */
#define atomic_dec(v) atomic_sub(1, (v))
#define atomic_dec_return(v) atomic_sub_return(1, (v))

static __inline__ void atomic_dec_unchecked(atomic_unchecked_t *v)
{
	atomic_sub_unchecked(1, v);
}

#define atomic_cmpxchg(v, o, n) (cmpxchg(&((v)->counter), (o), (n)))
#define atomic_xchg(v, new) (xchg(&((v)->counter), new))

static inline int atomic_cmpxchg_unchecked(atomic_unchecked_t *v, int old, int new)
{
	return cmpxchg(&(v->counter), old, new);
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
	int t;

	__asm__ __volatile__ (
	PPC_ATOMIC_ENTRY_BARRIER
"1:	lwarx	%0,0,%1		# __atomic_add_unless\n\
	cmpw	0,%0,%3 \n\
	beq-	2f \n"

#ifdef CONFIG_PAX_REFCOUNT
"	mcrxr	cr0\n"
"	addo.	%0,%2,%0\n"
"	bf 4*cr0+so, 4f\n"
"3:.long " "0x00c00b00""\n"
"4:\n"
#else
	"add	%0,%2,%0 \n"
#endif

	PPC405_ERR77(0,%2)
"	stwcx.	%0,0,%1 \n\
	bne-	1b \n"
"5:"

#ifdef CONFIG_PAX_REFCOUNT
	_ASM_EXTABLE(3b, 5b)
#endif

	PPC_ATOMIC_EXIT_BARRIER
"	subf	%0,%2,%0 \n\
2:"
	: "=&r" (t)
	: "r" (&v->counter), "r" (a), "r" (u)
	: "cc", "memory");

	return t;
}

/**
 * atomic_inc_not_zero - increment unless the number is zero
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1, so long as @v is non-zero.
 * Returns non-zero if @v was non-zero, and zero otherwise.
 */
static __inline__ int atomic_inc_not_zero(atomic_t *v)
{
	int t1, t2;

	__asm__ __volatile__ (
	PPC_ATOMIC_ENTRY_BARRIER
"1:	lwarx	%0,0,%2		# atomic_inc_not_zero\n\
	cmpwi	0,%0,0\n\
	beq-	2f\n\
	addic	%1,%0,1\n"
	PPC405_ERR77(0,%2)
"	stwcx.	%1,0,%2\n\
	bne-	1b\n"
	PPC_ATOMIC_EXIT_BARRIER
	"\n\
2:"
	: "=&r" (t1), "=&r" (t2)
	: "r" (&v->counter)
	: "cc", "xer", "memory");

	return t1;
}
#define atomic_inc_not_zero(v) atomic_inc_not_zero((v))

#define atomic_sub_and_test(a, v)	(atomic_sub_return((a), (v)) == 0)
#define atomic_dec_and_test(v)		(atomic_dec_return((v)) == 0)

/*
 * Atomically test *v and decrement if it is greater than 0.
 * The function returns the old value of *v minus 1, even if
 * the atomic variable, v, was not decremented.
 */
static __inline__ int atomic_dec_if_positive(atomic_t *v)
{
	int t;

	__asm__ __volatile__(
	PPC_ATOMIC_ENTRY_BARRIER
"1:	lwarx	%0,0,%1		# atomic_dec_if_positive\n\
	cmpwi	%0,1\n\
	addi	%0,%0,-1\n\
	blt-	2f\n"
	PPC405_ERR77(0,%1)
"	stwcx.	%0,0,%1\n\
	bne-	1b"
	PPC_ATOMIC_EXIT_BARRIER
	"\n\
2:"	: "=&b" (t)
	: "r" (&v->counter)
	: "cc", "memory");

	return t;
}
#define atomic_dec_if_positive atomic_dec_if_positive

#define smp_mb__before_atomic_dec()     smp_mb()
#define smp_mb__after_atomic_dec()      smp_mb()
#define smp_mb__before_atomic_inc()     smp_mb()
#define smp_mb__after_atomic_inc()      smp_mb()

#ifdef __powerpc64__

#define ATOMIC64_INIT(i)	{ (i) }

static __inline__ long atomic64_read(const atomic64_t *v)
{
	long t;

	__asm__ __volatile__("ld%U1%X1 %0,%1" : "=r"(t) : "m"(v->counter));

	return t;
}

static __inline__ long atomic64_read_unchecked(const atomic64_unchecked_t *v)
{
	long t;

	__asm__ __volatile__("ld%U1%X1 %0,%1" : "=r"(t) : "m"(v->counter));

	return t;
}

static __inline__ void atomic64_set(atomic64_t *v, long i)
{
	__asm__ __volatile__("std%U0%X0 %1,%0" : "=m"(v->counter) : "r"(i));
}

static __inline__ void atomic64_set_unchecked(atomic64_unchecked_t *v, long i)
{
	__asm__ __volatile__("std%U0%X0 %1,%0" : "=m"(v->counter) : "r"(i));
}

#define __ATOMIC64_OP(op, suffix, pre_op, asm_op, post_op, extable)	\
static inline void atomic64_##op##suffix(long a, atomic64##suffix##_t *v)\
{									\
	long t;								\
									\
	__asm__ __volatile__(						\
"1:	ldarx	%0,0,%3		# atomic64_" #op "\n"			\
	pre_op								\
	#asm_op " %0,%2,%0\n"						\
	post_op								\
"	stdcx.	%0,0,%3 \n"						\
"	bne-	1b\n"							\
	extable								\
	: "=&r" (t), "+m" (v->counter)					\
	: "r" (a), "r" (&v->counter)					\
	: "cc");							\
}

#define ATOMIC64_OP(op, asm_op) __ATOMIC64_OP(op, , , asm_op, , )		\
				__ATOMIC64_OP(op, _unchecked, __OVERFLOW_PRE, __REFCOUNT_OP(asm_op), __OVERFLOW_POST, __OVERFLOW_EXTABLE)

#define __ATOMIC64_OP_RETURN(op, suffix, pre_op, asm_op, post_op, extable)\
static inline long atomic64_##op##_return##suffix(long a, atomic64##suffix##_t *v)\
{									\
	long t;								\
									\
	__asm__ __volatile__(						\
	PPC_ATOMIC_ENTRY_BARRIER					\
"1:	ldarx	%0,0,%2		# atomic64_" #op "_return\n"		\
	pre_op								\
	#asm_op " %0,%1,%0\n"						\
	post_op								\
"	stdcx.	%0,0,%2 \n"						\
"	bne-	1b\n"							\
	extable								\
	PPC_ATOMIC_EXIT_BARRIER						\
	: "=&r" (t)							\
	: "r" (a), "r" (&v->counter)					\
	: "cc", "memory");						\
									\
	return t;							\
}

#define ATOMIC64_OP_RETURN(op, asm_op) __ATOMIC64_OP_RETURN(op, , , asm_op, , )\
				       __ATOMIC64_OP_RETURN(op, _unchecked, __OVERFLOW_PRE, __REFCOUNT_OP(asm_op), __OVERFLOW_POST, __OVERFLOW_EXTABLE)

#define ATOMIC64_OPS(op, asm_op) ATOMIC64_OP(op, asm_op) ATOMIC64_OP_RETURN(op, asm_op)

ATOMIC64_OPS(add, add)
ATOMIC64_OPS(sub, subf)

#undef ATOMIC64_OPS
#undef ATOMIC64_OP_RETURN
#undef __ATOMIC64_OP_RETURN
#undef ATOMIC64_OP
#undef __ATOMIC64_OP
#undef __OVERFLOW_EXTABLE
#undef __OVERFLOW_POST
#undef __OVERFLOW_PRE
#undef __REFCOUNT_OP

#define atomic64_add_negative(a, v)	(atomic64_add_return((a), (v)) < 0)

/*
 * atomic64_inc - increment atomic variable
 * @v: pointer of type atomic64_t
 *
 * Automatically increments @v by 1
 */
#define atomic64_inc(v) atomic64_add(1, (v))
#define atomic64_inc_return(v) atomic64_add_return(1, (v))

static inline void atomic64_inc_unchecked(atomic64_unchecked_t *v)
{
	atomic64_add_unchecked(1, v);
}

static inline long atomic64_inc_return_unchecked(atomic64_unchecked_t *v)
{
	return atomic64_add_return_unchecked(1, v);
}

/*
 * atomic64_inc_and_test - increment and test
 * @v: pointer of type atomic64_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
#define atomic64_inc_and_test(v) (atomic64_inc_return(v) == 0)

/* 
 * atomic64_dec - decrement atomic variable
 * @v: pointer of type atomic64_t
 * 
 * Atomically decrements @v by 1
 */
#define atomic64_dec(v) atomic64_sub(1, (v))
#define atomic64_dec_return(v) atomic64_sub_return(1, (v))

static __inline__ void atomic64_dec_unchecked(atomic64_unchecked_t *v)
{
	atomic64_sub_unchecked(1, v);
}

#define atomic64_sub_and_test(a, v)	(atomic64_sub_return((a), (v)) == 0)
#define atomic64_dec_and_test(v)	(atomic64_dec_return((v)) == 0)

/*
 * Atomically test *v and decrement if it is greater than 0.
 * The function returns the old value of *v minus 1.
 */
static __inline__ long atomic64_dec_if_positive(atomic64_t *v)
{
	long t;

	__asm__ __volatile__(
	PPC_ATOMIC_ENTRY_BARRIER
"1:	ldarx	%0,0,%1		# atomic64_dec_if_positive\n\
	addic.	%0,%0,-1\n\
	blt-	2f\n\
	stdcx.	%0,0,%1\n\
	bne-	1b"
	PPC_ATOMIC_EXIT_BARRIER
	"\n\
2:"	: "=&r" (t)
	: "r" (&v->counter)
	: "cc", "xer", "memory");

	return t;
}

#define atomic64_cmpxchg(v, o, n) (cmpxchg(&((v)->counter), (o), (n)))
#define atomic64_xchg(v, new) (xchg(&((v)->counter), new))

static inline long atomic64_cmpxchg_unchecked(atomic64_unchecked_t *v, long old, long new)
{
	return cmpxchg(&(v->counter), old, new);
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
	long t;

	__asm__ __volatile__ (
	PPC_ATOMIC_ENTRY_BARRIER
"1:	ldarx	%0,0,%1		# atomic64_add_unless\n\
	cmpd	0,%0,%3 \n\
	beq-	2f \n"

#ifdef CONFIG_PAX_REFCOUNT
"	mcrxr	cr0\n"
"	addo.	%0,%2,%0\n"
"	bf 4*cr0+so, 4f\n"
"3:.long " "0x00c00b00""\n"
"4:\n"
#else
	"add	%0,%2,%0 \n"
#endif

"	stdcx.	%0,0,%1 \n\
	bne-	1b \n"
	PPC_ATOMIC_EXIT_BARRIER
"5:"

#ifdef CONFIG_PAX_REFCOUNT
	_ASM_EXTABLE(3b, 5b)
#endif

"	subf	%0,%2,%0 \n\
2:"
	: "=&r" (t)
	: "r" (&v->counter), "r" (a), "r" (u)
	: "cc", "memory");

	return t != u;
}

/**
 * atomic_inc64_not_zero - increment unless the number is zero
 * @v: pointer of type atomic64_t
 *
 * Atomically increments @v by 1, so long as @v is non-zero.
 * Returns non-zero if @v was non-zero, and zero otherwise.
 */
static __inline__ long atomic64_inc_not_zero(atomic64_t *v)
{
	long t1, t2;

	__asm__ __volatile__ (
	PPC_ATOMIC_ENTRY_BARRIER
"1:	ldarx	%0,0,%2		# atomic64_inc_not_zero\n\
	cmpdi	0,%0,0\n\
	beq-	2f\n\
	addic	%1,%0,1\n\
	stdcx.	%1,0,%2\n\
	bne-	1b\n"
	PPC_ATOMIC_EXIT_BARRIER
	"\n\
2:"
	: "=&r" (t1), "=&r" (t2)
	: "r" (&v->counter)
	: "cc", "xer", "memory");

	return t1;
}

#endif /* __powerpc64__ */

#endif /* __KERNEL__ */
#endif /* _ASM_POWERPC_ATOMIC_H_ */

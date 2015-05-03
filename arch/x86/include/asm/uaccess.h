#ifndef _ASM_X86_UACCESS_H
#define _ASM_X86_UACCESS_H
/*
 * User space memory access functions
 */
#include <linux/errno.h>
#include <linux/compiler.h>
#include <linux/thread_info.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <asm/asm.h>
#include <asm/page.h>
#include <asm/smap.h>

#define VERIFY_READ 0
#define VERIFY_WRITE 1

/*
 * The fs value determines whether argument validity checking should be
 * performed or not.  If get_fs() == USER_DS, checking is performed, with
 * get_fs() == KERNEL_DS, checking is bypassed.
 *
 * For historical reasons, these macros are grossly misnamed.
 */

#define MAKE_MM_SEG(s)	((mm_segment_t) { (s) })

#define KERNEL_DS	MAKE_MM_SEG(-1UL)
#define USER_DS 	MAKE_MM_SEG(TASK_SIZE_MAX)

#define get_ds()	(KERNEL_DS)
#define get_fs()	(current_thread_info()->addr_limit)
#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_MEMORY_UDEREF)
void __set_fs(mm_segment_t x);
void set_fs(mm_segment_t x);
#else
#define set_fs(x)	(current_thread_info()->addr_limit = (x))
#endif

#define segment_eq(a, b)	((a).seg == (b).seg)

#define user_addr_max() (current_thread_info()->addr_limit.seg)
#define __addr_ok(addr) 	\
	((unsigned long __force)(addr) < user_addr_max())

/*
 * Test whether a block of memory is a valid user space address.
 * Returns 0 if the range is valid, nonzero otherwise.
 */
static inline bool __chk_range_not_ok(unsigned long addr, unsigned long size, unsigned long limit)
{
	/*
	 * If we have used "sizeof()" for the size,
	 * we know it won't overflow the limit (but
	 * it might overflow the 'addr', so it's
	 * important to subtract the size from the
	 * limit, not add it to the address).
	 */
	if (__builtin_constant_p(size))
		return addr > limit - size;

	/* Arbitrary sizes? Be careful about overflow */
	addr += size;
	if (addr < size)
		return true;
	return addr > limit;
}

#define __range_not_ok(addr, size, limit)				\
({									\
	__chk_user_ptr(addr);						\
	__chk_range_not_ok((unsigned long __force)(addr), size, limit); \
})

/**
 * access_ok: - Checks if a user space pointer is valid
 * @type: Type of access: %VERIFY_READ or %VERIFY_WRITE.  Note that
 *        %VERIFY_WRITE is a superset of %VERIFY_READ - if it is safe
 *        to write to a block, it is always safe to read from it.
 * @addr: User space pointer to start of block to check
 * @size: Size of block to check
 *
 * Context: User context only.  This function may sleep.
 *
 * Checks if a pointer to a block of memory in user space is valid.
 *
 * Returns true (nonzero) if the memory block may be valid, false (zero)
 * if it is definitely invalid.
 *
 * Note that, depending on architecture, this function probably just
 * checks that the pointer is in the user space range - after calling
 * this function, memory access functions may still return -EFAULT.
 */
extern int _cond_resched(void);
#define access_ok_noprefault(type, addr, size) (likely(!__range_not_ok(addr, size, user_addr_max())))
#define access_ok(type, addr, size)					\
({									\
	unsigned long __size = size;					\
	unsigned long __addr = (unsigned long)addr;			\
	bool __ret_ao = __range_not_ok(__addr, __size, user_addr_max()) == 0;\
	if (__ret_ao && __size) {					\
		unsigned long __addr_ao = __addr & PAGE_MASK;		\
		unsigned long __end_ao = __addr + __size - 1;		\
		if (unlikely((__end_ao ^ __addr_ao) & PAGE_MASK)) {	\
			while (__addr_ao <= __end_ao) {			\
				char __c_ao;				\
				__addr_ao += PAGE_SIZE;			\
				if (__size > PAGE_SIZE)			\
					_cond_resched();		\
				if (__get_user(__c_ao, (char __user *)__addr))	\
					break;				\
				if (type != VERIFY_WRITE) {		\
					__addr = __addr_ao;		\
					continue;			\
				}					\
				if (__put_user(__c_ao, (char __user *)__addr))	\
					break;				\
				__addr = __addr_ao;			\
			}						\
		}							\
	}								\
	__ret_ao;							\
})

/*
 * The exception table consists of pairs of addresses relative to the
 * exception table enty itself: the first is the address of an
 * instruction that is allowed to fault, and the second is the address
 * at which the program should continue.  No registers are modified,
 * so it is entirely up to the continuation code to figure out what to
 * do.
 *
 * All the routines below use bits of fixup code that are out of line
 * with the main instruction path.  This means when everything is well,
 * we don't even have to jump over them.  Further, they do not intrude
 * on our cache or tlb entries.
 */

struct exception_table_entry {
	int insn, fixup;
};
/* This is not the generic standard exception_table_entry format */
#define ARCH_HAS_SORT_EXTABLE
#define ARCH_HAS_SEARCH_EXTABLE

extern int fixup_exception(struct pt_regs *regs);
extern int early_fixup_exception(unsigned long *ip);

/*
 * These are the main single-value transfer routines.  They automatically
 * use the right size if we just have the right pointer type.
 *
 * This gets kind of ugly. We want to return _two_ values in "get_user()"
 * and yet we don't want to do any pointers, because that is too much
 * of a performance impact. Thus we have a few rather ugly macros here,
 * and hide all the ugliness from the user.
 *
 * The "__xxx" versions of the user access functions are versions that
 * do not verify the address space, that must have been done previously
 * with a separate "access_ok()" call (this is used when we do multiple
 * accesses to the same area of user memory).
 */

extern int __get_user_1(void);
extern int __get_user_2(void);
extern int __get_user_4(void);
extern int __get_user_8(void);
extern int __get_user_bad(void);

/*
 * This is a type: either (un)signed int, if the argument fits into
 * that type, or otherwise (un)signed long long.
 */
#define __inttype(x) \
__typeof__(__builtin_choose_expr(sizeof(x) > sizeof(0U),		\
	__builtin_choose_expr(__type_is_unsigned(__typeof__(x)), 0ULL, 0LL),\
	__builtin_choose_expr(__type_is_unsigned(__typeof__(x)), 0U, 0)))

/**
 * get_user: - Get a simple variable from user space.
 * @x:   Variable to store result.
 * @ptr: Source address, in user space.
 *
 * Context: User context only.  This function may sleep.
 *
 * This macro copies a single simple variable from user space to kernel
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and the result of
 * dereferencing @ptr must be assignable to @x without a cast.
 *
 * Returns zero on success, or -EFAULT on error.
 * On error, the variable @x is set to zero.
 */
/*
 * Careful: we have to cast the result to the type of the pointer
 * for sign reasons.
 *
 * The use of _ASM_DX as the register specifier is a bit of a
 * simplification, as gcc only cares about it as the starting point
 * and not size: for a 64-bit value it will use %ecx:%edx on 32 bits
 * (%ecx being the next register in gcc's x86 register sequence), and
 * %rdx on 64 bits.
 *
 * Clang/LLVM cares about the size of the register, but still wants
 * the base register for something that ends up being a pair.
 */
#define get_user(x, ptr)						\
({									\
	int __ret_gu;							\
	register __inttype(*(ptr)) __val_gu asm("%"_ASM_DX);		\
	__chk_user_ptr(ptr);						\
	might_fault();							\
	pax_open_userland();						\
	asm volatile("call __get_user_%P3"				\
		     : "=a" (__ret_gu), "=r" (__val_gu)			\
		     : "0" (ptr), "i" (sizeof(*(ptr))));		\
	(x) = (__force __typeof__(*(ptr))) __val_gu;			\
	pax_close_userland();						\
	__ret_gu;							\
})

#define __put_user_x(size, x, ptr, __ret_pu)			\
	asm volatile("call __put_user_" #size : "=a" (__ret_pu)	\
		     : "0" ((typeof(*(ptr)))(x)), "c" (ptr) : "ebx")

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_MEMORY_UDEREF)
#define __copyuser_seg "gs;"
#define __COPYUSER_SET_ES "pushl %%gs; popl %%es\n"
#define __COPYUSER_RESTORE_ES "pushl %%ss; popl %%es\n"
#else
#define __copyuser_seg
#define __COPYUSER_SET_ES
#define __COPYUSER_RESTORE_ES
#endif

#ifdef CONFIG_X86_32
#define __put_user_asm_u64(x, addr, err, errret)			\
	asm volatile(ASM_STAC "\n"					\
		     "1:	"__copyuser_seg"movl %%eax,0(%2)\n"	\
		     "2:	"__copyuser_seg"movl %%edx,4(%2)\n"	\
		     "3: " ASM_CLAC "\n"				\
		     ".section .fixup,\"ax\"\n"				\
		     "4:	movl %3,%0\n"				\
		     "	jmp 3b\n"					\
		     ".previous\n"					\
		     _ASM_EXTABLE(1b, 4b)				\
		     _ASM_EXTABLE(2b, 4b)				\
		     : "=r" (err)					\
		     : "A" (x), "r" (addr), "i" (errret), "0" (err))

#define __put_user_asm_ex_u64(x, addr)					\
	asm volatile(ASM_STAC "\n"					\
		     "1:	"__copyuser_seg"movl %%eax,0(%1)\n"	\
		     "2:	"__copyuser_seg"movl %%edx,4(%1)\n"	\
		     "3: " ASM_CLAC "\n"				\
		     _ASM_EXTABLE_EX(1b, 2b)				\
		     _ASM_EXTABLE_EX(2b, 3b)				\
		     : : "A" (x), "r" (addr))

#define __put_user_x8(x, ptr, __ret_pu)				\
	asm volatile("call __put_user_8" : "=a" (__ret_pu)	\
		     : "A" ((typeof(*(ptr)))(x)), "c" (ptr) : "ebx")
#else
#define __put_user_asm_u64(x, ptr, retval, errret) \
	__put_user_asm(x, ptr, retval, "q", "", "er", errret)
#define __put_user_asm_ex_u64(x, addr)	\
	__put_user_asm_ex(x, addr, "q", "", "er")
#define __put_user_x8(x, ptr, __ret_pu) __put_user_x(8, x, ptr, __ret_pu)
#endif

extern void __put_user_bad(void);

/*
 * Strange magic calling convention: pointer in %ecx,
 * value in %eax(:%edx), return value in %eax. clobbers %rbx
 */
extern void __put_user_1(void);
extern void __put_user_2(void);
extern void __put_user_4(void);
extern void __put_user_8(void);

/**
 * put_user: - Write a simple value into user space.
 * @x:   Value to copy to user space.
 * @ptr: Destination address, in user space.
 *
 * Context: User context only.  This function may sleep.
 *
 * This macro copies a single simple value from kernel space to user
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and @x must be assignable
 * to the result of dereferencing @ptr.
 *
 * Returns zero on success, or -EFAULT on error.
 */
#define put_user(x, ptr)					\
({								\
	int __ret_pu;						\
	__typeof__(*(ptr)) __pu_val;				\
	__chk_user_ptr(ptr);					\
	might_fault();						\
	__pu_val = (x);						\
	pax_open_userland();					\
	switch (sizeof(*(ptr))) {				\
	case 1:							\
		__put_user_x(1, __pu_val, ptr, __ret_pu);	\
		break;						\
	case 2:							\
		__put_user_x(2, __pu_val, ptr, __ret_pu);	\
		break;						\
	case 4:							\
		__put_user_x(4, __pu_val, ptr, __ret_pu);	\
		break;						\
	case 8:							\
		__put_user_x8(__pu_val, ptr, __ret_pu);		\
		break;						\
	default:						\
		__put_user_x(X, __pu_val, ptr, __ret_pu);	\
		break;						\
	}							\
	pax_close_userland();					\
	__ret_pu;						\
})

#define __put_user_size(x, ptr, size, retval, errret)			\
do {									\
	retval = 0;							\
	__chk_user_ptr(ptr);						\
	switch (size) {							\
	case 1:								\
		__put_user_asm(x, ptr, retval, "b", "b", "iq", errret);	\
		break;							\
	case 2:								\
		__put_user_asm(x, ptr, retval, "w", "w", "ir", errret);	\
		break;							\
	case 4:								\
		__put_user_asm(x, ptr, retval, "l", "k", "ir", errret);	\
		break;							\
	case 8:								\
		__put_user_asm_u64((__typeof__(*ptr))(x), ptr, retval,	\
				   errret);				\
		break;							\
	default:							\
		__put_user_bad();					\
	}								\
} while (0)

#define __put_user_size_ex(x, ptr, size)				\
do {									\
	__chk_user_ptr(ptr);						\
	switch (size) {							\
	case 1:								\
		__put_user_asm_ex(x, ptr, "b", "b", "iq");		\
		break;							\
	case 2:								\
		__put_user_asm_ex(x, ptr, "w", "w", "ir");		\
		break;							\
	case 4:								\
		__put_user_asm_ex(x, ptr, "l", "k", "ir");		\
		break;							\
	case 8:								\
		__put_user_asm_ex_u64((__typeof__(*ptr))(x), ptr);	\
		break;							\
	default:							\
		__put_user_bad();					\
	}								\
} while (0)

#ifdef CONFIG_X86_32
#define __get_user_asm_u64(x, ptr, retval, errret)	(x) = __get_user_bad()
#define __get_user_asm_ex_u64(x, ptr)			(x) = __get_user_bad()
#else
#define __get_user_asm_u64(x, ptr, retval, errret) \
	 __get_user_asm(x, ptr, retval, "q", "", "=r", errret)
#define __get_user_asm_ex_u64(x, ptr) \
	 __get_user_asm_ex(x, ptr, "q", "", "=r")
#endif

#define __get_user_size(x, ptr, size, retval, errret)			\
do {									\
	retval = 0;							\
	__chk_user_ptr(ptr);						\
	switch (size) {							\
	case 1:								\
		__get_user_asm(x, ptr, retval, "b", "b", "=q", errret);	\
		break;							\
	case 2:								\
		__get_user_asm(x, ptr, retval, "w", "w", "=r", errret);	\
		break;							\
	case 4:								\
		__get_user_asm(x, ptr, retval, "l", "k", "=r", errret);	\
		break;							\
	case 8:								\
		__get_user_asm_u64(x, ptr, retval, errret);		\
		break;							\
	default:							\
		(x) = __get_user_bad();					\
	}								\
} while (0)

#define __get_user_asm(x, addr, err, itype, rtype, ltype, errret)	\
do {									\
	pax_open_userland();						\
	asm volatile(ASM_STAC "\n"					\
		     "1:	"__copyuser_seg"mov"itype" %2,%"rtype"1\n"\
		     "2: " ASM_CLAC "\n"				\
		     ".section .fixup,\"ax\"\n"				\
		     "3:	mov %3,%0\n"				\
		     "	xor"itype" %"rtype"1,%"rtype"1\n"		\
		     "	jmp 2b\n"					\
		     ".previous\n"					\
		     _ASM_EXTABLE(1b, 3b)				\
		     : "=r" (err), ltype (x)				\
		     : "m" (__m(addr)), "i" (errret), "0" (err));	\
	pax_close_userland();						\
} while (0)

#define __get_user_size_ex(x, ptr, size)				\
do {									\
	__chk_user_ptr(ptr);						\
	switch (size) {							\
	case 1:								\
		__get_user_asm_ex(x, ptr, "b", "b", "=q");		\
		break;							\
	case 2:								\
		__get_user_asm_ex(x, ptr, "w", "w", "=r");		\
		break;							\
	case 4:								\
		__get_user_asm_ex(x, ptr, "l", "k", "=r");		\
		break;							\
	case 8:								\
		__get_user_asm_ex_u64(x, ptr);				\
		break;							\
	default:							\
		(x) = __get_user_bad();					\
	}								\
} while (0)

#define __get_user_asm_ex(x, addr, itype, rtype, ltype)			\
	asm volatile("1:	"__copyuser_seg"mov"itype" %1,%"rtype"0\n"\
		     "2:\n"						\
		     _ASM_EXTABLE_EX(1b, 2b)				\
		     : ltype(x) : "m" (__m(addr)))

#define __put_user_nocheck(x, ptr, size)			\
({								\
	int __pu_err;						\
	__put_user_size((x), (ptr), (size), __pu_err, -EFAULT);	\
	__pu_err;						\
})

#define __get_user_nocheck(x, ptr, size)				\
({									\
	int __gu_err;							\
	unsigned long __gu_val;						\
	__get_user_size(__gu_val, (ptr), (size), __gu_err, -EFAULT);	\
	(x) = (__typeof__(*(ptr)))__gu_val;				\
	__gu_err;							\
})

/* FIXME: this hack is definitely wrong -AK */
struct __large_struct { unsigned long buf[100]; };
#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
#define ____m(x)					\
({							\
	unsigned long ____x = (unsigned long)(x);	\
	if (____x < pax_user_shadow_base)		\
		____x += pax_user_shadow_base;		\
	(typeof(x))____x;				\
})
#else
#define ____m(x) (x)
#endif
#define __m(x) (*(struct __large_struct __user *)____m(x))

/*
 * Tell gcc we read from memory instead of writing: this is because
 * we do not write to any memory gcc knows about, so there are no
 * aliasing issues.
 */
#define __put_user_asm(x, addr, err, itype, rtype, ltype, errret)	\
do {									\
	pax_open_userland();						\
	asm volatile(ASM_STAC "\n"					\
		     "1:	"__copyuser_seg"mov"itype" %"rtype"1,%2\n"\
		     "2: " ASM_CLAC "\n"				\
		     ".section .fixup,\"ax\"\n"				\
		     "3:	mov %3,%0\n"				\
		     "	jmp 2b\n"					\
		     ".previous\n"					\
		     _ASM_EXTABLE(1b, 3b)				\
		     : "=r"(err)					\
		     : ltype (x), "m" (__m(addr)), "i" (errret), "0" (err));\
	pax_close_userland();						\
} while (0)

#define __put_user_asm_ex(x, addr, itype, rtype, ltype)			\
	asm volatile("1:	"__copyuser_seg"mov"itype" %"rtype"0,%1\n"\
		     "2:\n"						\
		     _ASM_EXTABLE_EX(1b, 2b)				\
		     : : ltype(x), "m" (__m(addr)))

/*
 * uaccess_try and catch
 */
#define uaccess_try	do {						\
	current_thread_info()->uaccess_err = 0;				\
	pax_open_userland();						\
	stac();								\
	barrier();

#define uaccess_catch(err)						\
	clac();								\
	pax_close_userland();						\
	(err) |= (current_thread_info()->uaccess_err ? -EFAULT : 0);	\
} while (0)

/**
 * __get_user: - Get a simple variable from user space, with less checking.
 * @x:   Variable to store result.
 * @ptr: Source address, in user space.
 *
 * Context: User context only.  This function may sleep.
 *
 * This macro copies a single simple variable from user space to kernel
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and the result of
 * dereferencing @ptr must be assignable to @x without a cast.
 *
 * Caller must check the pointer with access_ok() before calling this
 * function.
 *
 * Returns zero on success, or -EFAULT on error.
 * On error, the variable @x is set to zero.
 */

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
#define __get_user(x, ptr)	get_user((x), (ptr))
#else
#define __get_user(x, ptr)						\
	__get_user_nocheck((x), (ptr), sizeof(*(ptr)))
#endif

/**
 * __put_user: - Write a simple value into user space, with less checking.
 * @x:   Value to copy to user space.
 * @ptr: Destination address, in user space.
 *
 * Context: User context only.  This function may sleep.
 *
 * This macro copies a single simple value from kernel space to user
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and @x must be assignable
 * to the result of dereferencing @ptr.
 *
 * Caller must check the pointer with access_ok() before calling this
 * function.
 *
 * Returns zero on success, or -EFAULT on error.
 */

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
#define __put_user(x, ptr)	put_user((x), (ptr))
#else
#define __put_user(x, ptr)						\
	__put_user_nocheck((__typeof__(*(ptr)))(x), (ptr), sizeof(*(ptr)))
#endif

#define __get_user_unaligned __get_user
#define __put_user_unaligned __put_user

/*
 * {get|put}_user_try and catch
 *
 * get_user_try {
 *	get_user_ex(...);
 * } get_user_catch(err)
 */
#define get_user_try		uaccess_try
#define get_user_catch(err)	uaccess_catch(err)

#define get_user_ex(x, ptr)	do {					\
	unsigned long __gue_val;					\
	__get_user_size_ex((__gue_val), (ptr), (sizeof(*(ptr))));	\
	(x) = (__typeof__(*(ptr)))__gue_val;				\
} while (0)

#define put_user_try		uaccess_try
#define put_user_catch(err)	uaccess_catch(err)

#define put_user_ex(x, ptr)						\
	__put_user_size_ex((__typeof__(*(ptr)))(x), (ptr), sizeof(*(ptr)))

extern unsigned long
copy_from_user_nmi(void *to, const void __user *from, unsigned long n);
extern __must_check long
strncpy_from_user(char *dst, const char __user *src, long count);

extern __must_check long strlen_user(const char __user *str);
extern __must_check long strnlen_user(const char __user *str, long n);

unsigned long __must_check clear_user(void __user *mem, unsigned long len);
unsigned long __must_check __clear_user(void __user *mem, unsigned long len) __size_overflow(2);

extern void __cmpxchg_wrong_size(void)
	__compiletime_error("Bad argument size for cmpxchg");

#define __user_atomic_cmpxchg_inatomic(uval, ptr, old, new, size)	\
({									\
	int __ret = 0;							\
	__typeof__(ptr) __uval = (uval);				\
	__typeof__(*(ptr)) __old = (old);				\
	__typeof__(*(ptr)) __new = (new);				\
	pax_open_userland();						\
	switch (size) {							\
	case 1:								\
	{								\
		asm volatile("\t" ASM_STAC "\n"				\
			"1:\t" LOCK_PREFIX __copyuser_seg"cmpxchgb %4, %2\n"\
			"2:\t" ASM_CLAC "\n"				\
			"\t.section .fixup, \"ax\"\n"			\
			"3:\tmov     %3, %0\n"				\
			"\tjmp     2b\n"				\
			"\t.previous\n"					\
			_ASM_EXTABLE(1b, 3b)				\
			: "+r" (__ret), "=a" (__old), "+m" (*____m(ptr))\
			: "i" (-EFAULT), "q" (__new), "1" (__old)	\
			: "memory"					\
		);							\
		break;							\
	}								\
	case 2:								\
	{								\
		asm volatile("\t" ASM_STAC "\n"				\
			"1:\t" LOCK_PREFIX __copyuser_seg"cmpxchgw %4, %2\n"\
			"2:\t" ASM_CLAC "\n"				\
			"\t.section .fixup, \"ax\"\n"			\
			"3:\tmov     %3, %0\n"				\
			"\tjmp     2b\n"				\
			"\t.previous\n"					\
			_ASM_EXTABLE(1b, 3b)				\
			: "+r" (__ret), "=a" (__old), "+m" (*____m(ptr))\
			: "i" (-EFAULT), "r" (__new), "1" (__old)	\
			: "memory"					\
		);							\
		break;							\
	}								\
	case 4:								\
	{								\
		asm volatile("\t" ASM_STAC "\n"				\
			"1:\t" LOCK_PREFIX __copyuser_seg"cmpxchgl %4, %2\n"\
			"2:\t" ASM_CLAC "\n"				\
			"\t.section .fixup, \"ax\"\n"			\
			"3:\tmov     %3, %0\n"				\
			"\tjmp     2b\n"				\
			"\t.previous\n"					\
			_ASM_EXTABLE(1b, 3b)				\
			: "+r" (__ret), "=a" (__old), "+m" (*____m(ptr))\
			: "i" (-EFAULT), "r" (__new), "1" (__old)	\
			: "memory"					\
		);							\
		break;							\
	}								\
	case 8:								\
	{								\
		if (!IS_ENABLED(CONFIG_X86_64))				\
			__cmpxchg_wrong_size();				\
									\
		asm volatile("\t" ASM_STAC "\n"				\
			"1:\t" LOCK_PREFIX __copyuser_seg"cmpxchgq %4, %2\n"\
			"2:\t" ASM_CLAC "\n"				\
			"\t.section .fixup, \"ax\"\n"			\
			"3:\tmov     %3, %0\n"				\
			"\tjmp     2b\n"				\
			"\t.previous\n"					\
			_ASM_EXTABLE(1b, 3b)				\
			: "+r" (__ret), "=a" (__old), "+m" (*____m(ptr))\
			: "i" (-EFAULT), "r" (__new), "1" (__old)	\
			: "memory"					\
		);							\
		break;							\
	}								\
	default:							\
		__cmpxchg_wrong_size();					\
	}								\
	pax_close_userland();						\
	*__uval = __old;						\
	__ret;								\
})

#define user_atomic_cmpxchg_inatomic(uval, ptr, old, new)		\
({									\
	access_ok(VERIFY_WRITE, (ptr), sizeof(*(ptr))) ?		\
		__user_atomic_cmpxchg_inatomic((uval), (ptr),		\
				(old), (new), sizeof(*(ptr))) :		\
		-EFAULT;						\
})

/*
 * movsl can be slow when source and dest are not both 8-byte aligned
 */
#ifdef CONFIG_X86_INTEL_USERCOPY
extern struct movsl_mask {
	int mask;
} ____cacheline_aligned_in_smp movsl_mask;
#endif

#define ARCH_HAS_NOCACHE_UACCESS 1

#ifdef CONFIG_DEBUG_STRICT_USER_COPY_CHECKS
# define copy_user_diag __compiletime_error
#else
# define copy_user_diag __compiletime_warning
#endif

extern void copy_user_diag("copy_from_user() buffer size is too small")
copy_from_user_overflow(void);
extern void copy_user_diag("copy_to_user() buffer size is too small")
copy_to_user_overflow(void);

#undef copy_user_diag

#ifdef CONFIG_DEBUG_STRICT_USER_COPY_CHECKS

extern void
__compiletime_warning("copy_from_user() buffer size is not provably correct")
__copy_from_user_overflow(void) __asm__("copy_from_user_overflow");
#define __copy_from_user_overflow(size, count) __copy_from_user_overflow()

extern void
__compiletime_warning("copy_to_user() buffer size is not provably correct")
__copy_to_user_overflow(void) __asm__("copy_to_user_overflow");
#define __copy_to_user_overflow(size, count) __copy_to_user_overflow()

#else

static inline void
__copy_from_user_overflow(int size, unsigned long count)
{
	WARN(1, "Buffer overflow detected (%d < %lu)!\n", size, count);
}

#define __copy_to_user_overflow __copy_from_user_overflow

#endif

#ifdef CONFIG_X86_32
# include <asm/uaccess_32.h>
#else
# include <asm/uaccess_64.h>
#endif

static inline unsigned long __must_check
copy_from_user(void *to, const void __user *from, unsigned long n)
{
	size_t sz = __compiletime_object_size(to);

	might_fault();

	/*
	 * While we would like to have the compiler do the checking for us
	 * even in the non-constant size case, any false positives there are
	 * a problem (especially when DEBUG_STRICT_USER_COPY_CHECKS, but even
	 * without - the [hopefully] dangerous looking nature of the warning
	 * would make people go look at the respecitive call sites over and
	 * over again just to find that there's no problem).
	 *
	 * And there are cases where it's just not realistic for the compiler
	 * to prove the count to be in range. For example when multiple call
	 * sites of a helper function - perhaps in different source files -
	 * all doing proper range checking, yet the helper function not doing
	 * so again.
	 *
	 * Therefore limit the compile time checking to the constant size
	 * case, and do only runtime checking for non-constant sizes.
	 */

	if (likely(sz != (size_t)-1  && sz < n)) {
		 if(__builtin_constant_p(n))
			copy_from_user_overflow();
		else
			__copy_from_user_overflow(sz, n);
	} else if (access_ok(VERIFY_READ, from, n))
		n = __copy_from_user(to, from, n);
	else if ((long)n > 0)
		memset(to, 0, n);

	return n;
}

static inline unsigned long __must_check
copy_to_user(void __user *to, const void *from, unsigned long n)
{
	size_t sz = __compiletime_object_size(from);

	might_fault();

	/* See the comment in copy_from_user() above. */
	if (likely(sz != (size_t)-1  && sz < n)) {
		 if(__builtin_constant_p(n))
			copy_to_user_overflow();
		else
			__copy_to_user_overflow(sz, n);
	} else if (access_ok(VERIFY_WRITE, to, n))
		n = __copy_to_user(to, from, n);

	return n;
}

#undef __copy_from_user_overflow
#undef __copy_to_user_overflow

#endif /* _ASM_X86_UACCESS_H */


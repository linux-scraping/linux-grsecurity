#ifndef _ASM_X86_UACCESS_64_H
#define _ASM_X86_UACCESS_64_H

/*
 * User space memory access functions
 */
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/lockdep.h>
#include <asm/alternative.h>
#include <asm/cpufeature.h>
#include <asm/page.h>
#include <asm/pgtable.h>

#define set_fs(x)	(current_thread_info()->addr_limit = (x))

/*
 * Copy To/From Userspace
 */

/* Handles exceptions in both to and from, but doesn't do access_ok */
__must_check unsigned long
copy_user_enhanced_fast_string(void *to, const void *from, unsigned len);
__must_check unsigned long
copy_user_generic_string(void *to, const void *from, unsigned len);
__must_check unsigned long
copy_user_generic_unrolled(void *to, const void *from, unsigned len);

static __always_inline __must_check __size_overflow(3) unsigned long
copy_user_generic(void *to, const void *from, unsigned long len)
{
	unsigned ret;

	/*
	 * If CPU has ERMS feature, use copy_user_enhanced_fast_string.
	 * Otherwise, if CPU has rep_good feature, use copy_user_generic_string.
	 * Otherwise, use copy_user_generic_unrolled.
	 */
	alternative_call_2(copy_user_generic_unrolled,
			 copy_user_generic_string,
			 X86_FEATURE_REP_GOOD,
			 copy_user_enhanced_fast_string,
			 X86_FEATURE_ERMS,
			 ASM_OUTPUT2("=a" (ret), "=D" (to), "=S" (from),
				     "=d" (len)),
			 "1" (to), "2" (from), "3" (len)
			 : "memory", "rcx", "r8", "r9", "r10", "r11");
	return ret;
}

__must_check unsigned long
copy_in_user(void __user *to, const void __user *from, unsigned long len);

static __always_inline __must_check
unsigned long __copy_from_user_nocheck(void *dst, const void __user *src, unsigned long size)
{
	size_t sz = __compiletime_object_size(dst);
	unsigned ret = 0;

	if (size > INT_MAX)
		return size;

	check_object_size(dst, size, false);

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!access_ok_noprefault(VERIFY_READ, src, size))
		return size;
#endif

	if (unlikely(sz != (size_t)-1 && sz < size)) {
		 if(__builtin_constant_p(size))
			copy_from_user_overflow();
		else
			__copy_from_user_overflow(sz, size);
		return size;
	}

	if (!__builtin_constant_p(size))
		return copy_user_generic(dst, (__force_kernel const void *)____m(src), size);
	switch (size) {
	case 1:__get_user_asm(*(u8 *)dst, (const u8 __user *)src,
			      ret, "b", "b", "=q", 1);
		return ret;
	case 2:__get_user_asm(*(u16 *)dst, (const u16 __user *)src,
			      ret, "w", "w", "=r", 2);
		return ret;
	case 4:__get_user_asm(*(u32 *)dst, (const u32 __user *)src,
			      ret, "l", "k", "=r", 4);
		return ret;
	case 8:__get_user_asm(*(u64 *)dst, (const u64 __user *)src,
			      ret, "q", "", "=r", 8);
		return ret;
	case 10:
		__get_user_asm(*(u64 *)dst, (const u64 __user *)src,
			       ret, "q", "", "=r", 10);
		if (unlikely(ret))
			return ret;
		__get_user_asm(*(u16 *)(8 + (char *)dst),
			       (const u16 __user *)(8 + (const char __user *)src),
			       ret, "w", "w", "=r", 2);
		return ret;
	case 16:
		__get_user_asm(*(u64 *)dst, (const u64 __user *)src,
			       ret, "q", "", "=r", 16);
		if (unlikely(ret))
			return ret;
		__get_user_asm(*(u64 *)(8 + (char *)dst),
			       (const u64 __user *)(8 + (const char __user *)src),
			       ret, "q", "", "=r", 8);
		return ret;
	default:
		return copy_user_generic(dst, (__force_kernel const void *)____m(src), size);
	}
}

static __always_inline __must_check
unsigned long __copy_from_user(void *dst, const void __user *src, unsigned long size)
{
	might_fault();
	return __copy_from_user_nocheck(dst, src, size);
}

static __always_inline __must_check
unsigned long __copy_to_user_nocheck(void __user *dst, const void *src, unsigned long size)
{
	size_t sz = __compiletime_object_size(src);
	unsigned ret = 0;

	if (size > INT_MAX)
		return size;

	check_object_size(src, size, true);

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!access_ok_noprefault(VERIFY_WRITE, dst, size))
		return size;
#endif

	if (unlikely(sz != (size_t)-1 && sz < size)) {
		 if(__builtin_constant_p(size))
			copy_to_user_overflow();
		else
			__copy_to_user_overflow(sz, size);
		return size;
	}

	if (!__builtin_constant_p(size))
		return copy_user_generic((__force_kernel void *)____m(dst), src, size);
	switch (size) {
	case 1:__put_user_asm(*(const u8 *)src, (u8 __user *)dst,
			      ret, "b", "b", "iq", 1);
		return ret;
	case 2:__put_user_asm(*(const u16 *)src, (u16 __user *)dst,
			      ret, "w", "w", "ir", 2);
		return ret;
	case 4:__put_user_asm(*(const u32 *)src, (u32 __user *)dst,
			      ret, "l", "k", "ir", 4);
		return ret;
	case 8:__put_user_asm(*(const u64 *)src, (u64 __user *)dst,
			      ret, "q", "", "er", 8);
		return ret;
	case 10:
		__put_user_asm(*(const u64 *)src, (u64 __user *)dst,
			       ret, "q", "", "er", 10);
		if (unlikely(ret))
			return ret;
		asm("":::"memory");
		__put_user_asm(4[(const u16 *)src], 4 + (u16 __user *)dst,
			       ret, "w", "w", "ir", 2);
		return ret;
	case 16:
		__put_user_asm(*(const u64 *)src, (u64 __user *)dst,
			       ret, "q", "", "er", 16);
		if (unlikely(ret))
			return ret;
		asm("":::"memory");
		__put_user_asm(1[(const u64 *)src], 1 + (u64 __user *)dst,
			       ret, "q", "", "er", 8);
		return ret;
	default:
		return copy_user_generic((__force_kernel void *)____m(dst), src, size);
	}
}

static __always_inline __must_check
unsigned long __copy_to_user(void __user *dst, const void *src, unsigned long size)
{
	might_fault();
	return __copy_to_user_nocheck(dst, src, size);
}

static __always_inline __must_check
unsigned long __copy_in_user(void __user *dst, const void __user *src, unsigned size)
{
	unsigned ret = 0;

	might_fault();

	if (size > INT_MAX)
		return size;

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!access_ok_noprefault(VERIFY_READ, src, size))
		return size;
	if (!access_ok_noprefault(VERIFY_WRITE, dst, size))
		return size;
#endif

	if (!__builtin_constant_p(size))
		return copy_user_generic((__force_kernel void *)____m(dst),
					 (__force_kernel const void *)____m(src), size);
	switch (size) {
	case 1: {
		u8 tmp;
		__get_user_asm(tmp, (const u8 __user *)src,
			       ret, "b", "b", "=q", 1);
		if (likely(!ret))
			__put_user_asm(tmp, (u8 __user *)dst,
				       ret, "b", "b", "iq", 1);
		return ret;
	}
	case 2: {
		u16 tmp;
		__get_user_asm(tmp, (const u16 __user *)src,
			       ret, "w", "w", "=r", 2);
		if (likely(!ret))
			__put_user_asm(tmp, (u16 __user *)dst,
				       ret, "w", "w", "ir", 2);
		return ret;
	}

	case 4: {
		u32 tmp;
		__get_user_asm(tmp, (const u32 __user *)src,
			       ret, "l", "k", "=r", 4);
		if (likely(!ret))
			__put_user_asm(tmp, (u32 __user *)dst,
				       ret, "l", "k", "ir", 4);
		return ret;
	}
	case 8: {
		u64 tmp;
		__get_user_asm(tmp, (const u64 __user *)src,
			       ret, "q", "", "=r", 8);
		if (likely(!ret))
			__put_user_asm(tmp, (u64 __user *)dst,
				       ret, "q", "", "er", 8);
		return ret;
	}
	default:
		return copy_user_generic((__force_kernel void *)____m(dst),
					 (__force_kernel const void *)____m(src), size);
	}
}

static __must_check __always_inline unsigned long
__copy_from_user_inatomic(void *dst, const void __user *src, unsigned long size)
{
	return __copy_from_user_nocheck(dst, src, size);
}

static __must_check __always_inline unsigned long
__copy_to_user_inatomic(void __user *dst, const void *src, unsigned long size)
{
	return __copy_to_user_nocheck(dst, src, size);
}

extern unsigned long __copy_user_nocache(void *dst, const void __user *src,
				unsigned long size, int zerorest);

static inline unsigned long
__copy_from_user_nocache(void *dst, const void __user *src, unsigned long size)
{
	might_fault();

	if (size > INT_MAX)
		return size;

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!access_ok_noprefault(VERIFY_READ, src, size))
		return size;
#endif

	return __copy_user_nocache(dst, src, size, 1);
}

static inline unsigned long
__copy_from_user_inatomic_nocache(void *dst, const void __user *src,
				  unsigned long size)
{
	if (size > INT_MAX)
		return size;

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!access_ok_noprefault(VERIFY_READ, src, size))
		return size;
#endif

	return __copy_user_nocache(dst, src, size, 0);
}

unsigned long
copy_user_handle_tail(char __user *to, char __user *from, unsigned long len, unsigned zerorest) __size_overflow(3);

#endif /* _ASM_X86_UACCESS_64_H */

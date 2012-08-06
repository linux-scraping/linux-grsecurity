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
copy_user_generic_string(void *to, const void *from, unsigned long len) __size_overflow(3);
__must_check unsigned long
copy_user_generic_unrolled(void *to, const void *from, unsigned long len) __size_overflow(3);

static __always_inline __must_check unsigned long
copy_user_generic(void *to, const void *from, unsigned long len) __size_overflow(3);
static __always_inline __must_check unsigned long
copy_user_generic(void *to, const void *from, unsigned long len)
{
	unsigned ret;

	alternative_call(copy_user_generic_unrolled,
			 copy_user_generic_string,
			 X86_FEATURE_REP_GOOD,
			 ASM_OUTPUT2("=a" (ret), "=D" (to), "=S" (from),
				     "=d" (len)),
			 "1" (to), "2" (from), "3" (len)
			 : "memory", "rcx", "r8", "r9", "r11");
	return ret;
}

static __always_inline __must_check unsigned long
__copy_to_user(void __user *to, const void *from, unsigned long len) __size_overflow(3);
static __always_inline __must_check unsigned long
__copy_from_user(void *to, const void __user *from, unsigned long len) __size_overflow(3);
__must_check unsigned long
copy_in_user(void __user *to, const void __user *from, unsigned long len) __size_overflow(3);

extern void copy_to_user_overflow(void)
#ifdef CONFIG_DEBUG_STRICT_USER_COPY_CHECKS
	__compiletime_error("copy_to_user() buffer size is not provably correct")
#else
	__compiletime_warning("copy_to_user() buffer size is not provably correct")
#endif
;

extern void copy_from_user_overflow(void)
#ifdef CONFIG_DEBUG_STRICT_USER_COPY_CHECKS
	__compiletime_error("copy_from_user() buffer size is not provably correct")
#else
	__compiletime_warning("copy_from_user() buffer size is not provably correct")
#endif
;

static inline unsigned long __must_check copy_from_user(void *to,
					  const void __user *from,
					  unsigned long n)
{
	might_fault();

	if (access_ok(VERIFY_READ, from, n))
		n = __copy_from_user(to, from, n);
	else if (n < INT_MAX) {
		if (!__builtin_constant_p(n))
			check_object_size(to, n, false);
		memset(to, 0, n);
	}
	return n;
}

static __always_inline __must_check
int copy_to_user(void __user *dst, const void *src, unsigned long size)
{
	might_fault();

	if (access_ok(VERIFY_WRITE, dst, size))
		size = __copy_to_user(dst, src, size);
	return size;
}

static __always_inline __must_check
unsigned long __copy_from_user(void *dst, const void __user *src, unsigned long size)
{
	size_t sz = __compiletime_object_size(dst);
	unsigned ret = 0;

	might_fault();

	if (size > INT_MAX)
		return size;

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!__access_ok(VERIFY_READ, src, size))
		return size;
#endif

	if (unlikely(sz != (size_t)-1 && sz < size)) {
		copy_from_user_overflow();
		return size;
	}

	if (!__builtin_constant_p(size)) {
		check_object_size(dst, size, false);

#ifdef CONFIG_PAX_MEMORY_UDEREF
		if ((unsigned long)src < PAX_USER_SHADOW_BASE)
			src += PAX_USER_SHADOW_BASE;
#endif

		return copy_user_generic(dst, (__force_kernel const void *)src, size);
	}
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

#ifdef CONFIG_PAX_MEMORY_UDEREF
		if ((unsigned long)src < PAX_USER_SHADOW_BASE)
			src += PAX_USER_SHADOW_BASE;
#endif

		return copy_user_generic(dst, (__force_kernel const void *)src, size);
	}
}

static __always_inline __must_check
unsigned long __copy_to_user(void __user *dst, const void *src, unsigned long size)
{
	size_t sz = __compiletime_object_size(src);
	unsigned ret = 0;

	might_fault();

	if (size > INT_MAX)
		return size;

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!__access_ok(VERIFY_WRITE, dst, size))
		return size;
#endif

	if (unlikely(sz != (size_t)-1 && sz < size)) {
		copy_to_user_overflow();
		return size;
	}

	if (!__builtin_constant_p(size)) {
		check_object_size(src, size, true);

#ifdef CONFIG_PAX_MEMORY_UDEREF
		if ((unsigned long)dst < PAX_USER_SHADOW_BASE)
			dst += PAX_USER_SHADOW_BASE;
#endif

		return copy_user_generic((__force_kernel void *)dst, src, size);
	}
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

#ifdef CONFIG_PAX_MEMORY_UDEREF
		if ((unsigned long)dst < PAX_USER_SHADOW_BASE)
			dst += PAX_USER_SHADOW_BASE;
#endif

		return copy_user_generic((__force_kernel void *)dst, src, size);
	}
}

static __always_inline __must_check
unsigned long __copy_in_user(void __user *dst, const void __user *src, unsigned long size)
{
	unsigned ret = 0;

	might_fault();

	if (size > INT_MAX)
		return size;

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!__access_ok(VERIFY_READ, src, size))
		return size;
	if (!__access_ok(VERIFY_WRITE, dst, size))
		return size;
#endif

	if (!__builtin_constant_p(size)) {

#ifdef CONFIG_PAX_MEMORY_UDEREF
		if ((unsigned long)src < PAX_USER_SHADOW_BASE)
			src += PAX_USER_SHADOW_BASE;
		if ((unsigned long)dst < PAX_USER_SHADOW_BASE)
			dst += PAX_USER_SHADOW_BASE;
#endif

		return copy_user_generic((__force_kernel void *)dst,
					 (__force_kernel const void *)src, size);
	}
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

#ifdef CONFIG_PAX_MEMORY_UDEREF
		if ((unsigned long)src < PAX_USER_SHADOW_BASE)
			src += PAX_USER_SHADOW_BASE;
		if ((unsigned long)dst < PAX_USER_SHADOW_BASE)
			dst += PAX_USER_SHADOW_BASE;
#endif

		return copy_user_generic((__force_kernel void *)dst,
					 (__force_kernel const void *)src, size);
	}
}

__must_check unsigned long clear_user(void __user *mem, unsigned long len) __size_overflow(2);
__must_check unsigned long __clear_user(void __user *mem, unsigned long len) __size_overflow(2);

static __must_check __always_inline int
__copy_from_user_inatomic(void *dst, const void __user *src, unsigned long size)
{
	if (size > INT_MAX)
		return size;

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!__access_ok(VERIFY_READ, src, size))
		return size;

	if ((unsigned long)src < PAX_USER_SHADOW_BASE)
		src += PAX_USER_SHADOW_BASE;
#endif

	return copy_user_generic(dst, (__force_kernel const void *)src, size);
}

static __must_check __always_inline unsigned long
__copy_to_user_inatomic(void __user *dst, const void *src, unsigned long size)
{
	if (size > INT_MAX)
		return size;

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!__access_ok(VERIFY_WRITE, dst, size))
		return size;

	if ((unsigned long)dst < PAX_USER_SHADOW_BASE)
		dst += PAX_USER_SHADOW_BASE;
#endif

	return copy_user_generic((__force_kernel void *)dst, src, size);
}

extern unsigned long __copy_user_nocache(void *dst, const void __user *src,
				unsigned long size, int zerorest) __size_overflow(3);

static inline unsigned long __copy_from_user_nocache(void *dst, const void __user *src, unsigned long size)
{
	might_sleep();

	if (size > INT_MAX)
		return size;

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!__access_ok(VERIFY_READ, src, size))
		return size;
#endif

	return __copy_user_nocache(dst, src, size, 1);
}

static inline unsigned long __copy_from_user_inatomic_nocache(void *dst, const void __user *src,
				  unsigned long size)
{
	if (size > INT_MAX)
		return size;

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!__access_ok(VERIFY_READ, src, size))
		return size;
#endif

	return __copy_user_nocache(dst, src, size, 0);
}

extern unsigned long
copy_user_handle_tail(char __user *to, char __user *from, unsigned long len, unsigned zerorest) __size_overflow(3);

#endif /* _ASM_X86_UACCESS_64_H */

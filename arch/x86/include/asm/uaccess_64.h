#ifndef _ASM_X86_UACCESS_64_H
#define _ASM_X86_UACCESS_64_H

/*
 * User space memory access functions
 */
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/prefetch.h>
#include <linux/lockdep.h>
#include <asm/page.h>
#include <asm/pgtable.h>

#define set_fs(x)	(current_thread_info()->addr_limit = (x))

/*
 * Copy To/From Userspace
 */

/* Handles exceptions in both to and from, but doesn't do access_ok */
__must_check unsigned long
copy_user_generic(void *to, const void *from, unsigned long len) __size_overflow(3);

__must_check unsigned long
copy_in_user(void __user *to, const void __user *from, unsigned long len);

extern void copy_to_user_overflow(void) __compiletime_warning("copy_to_user() buffer size is not provably correct");
extern void copy_from_user_overflow(void) __compiletime_warning("copy_from_user() buffer size is not provably correct");

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
		return copy_user_generic(dst, (__force_kernel const void *)____m(src), size);
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
		return copy_user_generic(dst, (__force_kernel const void *)____m(src), size);
	}
}

static __always_inline __must_check
unsigned long __copy_to_user(void __user *dst, const void *src, unsigned long size)
{
	size_t sz = __compiletime_object_size(dst);
	unsigned ret = 0;

	might_fault();

	pax_track_stack();

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
		return copy_user_generic((__force_kernel void *)____m(dst), src, size);
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
		return copy_user_generic((__force_kernel void *)____m(dst), src, size);
	}
}

static __always_inline __must_check
unsigned long copy_to_user(void __user *to, const void *from, unsigned long len)
{
	if (access_ok(VERIFY_WRITE, to, len))
		len = __copy_to_user(to, from, len);
	return len;
}

static __always_inline __must_check
unsigned long copy_from_user(void *to, const void __user *from, unsigned long len)
{
	might_fault();

	if (access_ok(VERIFY_READ, from, len))
		len = __copy_from_user(to, from, len);
	else if (len < INT_MAX) {
		if (!__builtin_constant_p(len))
			check_object_size(to, len, false);
		memset(to, 0, len);
	}
	return len;
}

static __always_inline __must_check
unsigned long __copy_in_user(void __user *dst, const void __user *src, unsigned long size)
{
	unsigned ret = 0;

	might_fault();

	pax_track_stack();

	if (size > INT_MAX)
		return size;

#ifdef CONFIG_PAX_MEMORY_UDEREF
	if (!__access_ok(VERIFY_READ, src, size))
		return size;
	if (!__access_ok(VERIFY_WRITE, dst, size))
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

__must_check long
strncpy_from_user(char *dst, const char __user *src, long count);
__must_check long
__strncpy_from_user(char *dst, const char __user *src, long count);
__must_check long strnlen_user(const char __user *str, long n);
__must_check long __strnlen_user(const char __user *str, long n);
__must_check long strlen_user(const char __user *str);
__must_check unsigned long clear_user(void __user *mem, unsigned long len) __size_overflow(2);
__must_check unsigned long __clear_user(void __user *mem, unsigned long len) __size_overflow(2);

static __must_check __always_inline unsigned long
__copy_from_user_inatomic(void *dst, const void __user *src, unsigned long size)
{
	pax_track_stack();

	if (size > INT_MAX)
		return size;

	return copy_user_generic(dst, (__force_kernel const void *)____m(src), size);
}

static __must_check __always_inline unsigned long
__copy_to_user_inatomic(void __user *dst, const void *src, unsigned long size)
{
	if (size > INT_MAX)
		return size;

	return copy_user_generic((__force_kernel void *)____m(dst), src, size);
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

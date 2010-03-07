/*
 * User address space access functions.
 * The non inlined parts of asm-i386/uaccess.h are here.
 *
 * Copyright 1997 Andi Kleen <ak@muc.de>
 * Copyright 1997 Linus Torvalds
 */
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/interrupt.h>
#include <asm/uaccess.h>
#include <asm/mmx.h>

#ifdef CONFIG_X86_INTEL_USERCOPY
/*
 * Alignment at which movsl is preferred for bulk memory copies.
 */
struct movsl_mask movsl_mask __read_mostly;
#endif

static inline int __movsl_is_ok(unsigned long a1, unsigned long a2, unsigned long n)
{
#ifdef CONFIG_X86_INTEL_USERCOPY
	if (n >= 64 && ((a1 ^ a2) & movsl_mask.mask))
		return 0;
#endif
	return 1;
}
#define movsl_is_ok(a1, a2, n) \
	__movsl_is_ok((unsigned long)(a1), (unsigned long)(a2), (n))

/*
 * Copy a null terminated string from userspace.
 */

static long __do_strncpy_from_user(char *dst, const char __user *src, long count)
{
	int __d0, __d1, __d2;
	long res = -EFAULT;

	might_fault();
	__asm__ __volatile__(
		"	movw %w10,%%ds\n"
		"	testl %1,%1\n"
		"	jz 2f\n"
		"0:	lodsb\n"
		"	stosb\n"
		"	testb %%al,%%al\n"
		"	jz 1f\n"
		"	decl %1\n"
		"	jnz 0b\n"
		"1:	subl %1,%0\n"
		"2:\n"
		"	pushl %%ss\n"
		"	popl %%ds\n"
		".section .fixup,\"ax\"\n"
		"3:	movl %5,%0\n"
		"	jmp 2b\n"
		".previous\n"
		_ASM_EXTABLE(0b,3b)
		: "=&d"(res), "=&c"(count), "=&a" (__d0), "=&S" (__d1),
		  "=&D" (__d2)
		: "i"(-EFAULT), "0"(count), "1"(count), "3"(src), "4"(dst),
		  "r"(__USER_DS)
		: "memory");
	return res;
}

/**
 * __strncpy_from_user: - Copy a NUL terminated string from userspace, with less checking.
 * @dst:   Destination address, in kernel space.  This buffer must be at
 *         least @count bytes long.
 * @src:   Source address, in user space.
 * @count: Maximum number of bytes to copy, including the trailing NUL.
 *
 * Copies a NUL-terminated string from userspace to kernel space.
 * Caller must check the specified block with access_ok() before calling
 * this function.
 *
 * On success, returns the length of the string (not including the trailing
 * NUL).
 *
 * If access to userspace fails, returns -EFAULT (some data may have been
 * copied).
 *
 * If @count is smaller than the length of the string, copies @count bytes
 * and returns @count.
 */
long
__strncpy_from_user(char *dst, const char __user *src, long count)
{
	return __do_strncpy_from_user(dst, src, count);
}
EXPORT_SYMBOL(__strncpy_from_user);

/**
 * strncpy_from_user: - Copy a NUL terminated string from userspace.
 * @dst:   Destination address, in kernel space.  This buffer must be at
 *         least @count bytes long.
 * @src:   Source address, in user space.
 * @count: Maximum number of bytes to copy, including the trailing NUL.
 *
 * Copies a NUL-terminated string from userspace to kernel space.
 *
 * On success, returns the length of the string (not including the trailing
 * NUL).
 *
 * If access to userspace fails, returns -EFAULT (some data may have been
 * copied).
 *
 * If @count is smaller than the length of the string, copies @count bytes
 * and returns @count.
 */
long
strncpy_from_user(char *dst, const char __user *src, long count)
{
	long res = -EFAULT;
	if (access_ok(VERIFY_READ, src, 1))
		res = __do_strncpy_from_user(dst, src, count);
	return res;
}
EXPORT_SYMBOL(strncpy_from_user);

/*
 * Zero Userspace
 */

static unsigned long __do_clear_user(void __user *addr, unsigned long size)
{
	int __d0;

	might_fault();
	__asm__ __volatile__(
		"	movw %w6,%%es\n"
		"0:	rep; stosl\n"
		"	movl %2,%0\n"
		"1:	rep; stosb\n"
		"2:\n"
		"	pushl %%ss\n"
		"	popl %%es\n"
		".section .fixup,\"ax\"\n"
		"3:	lea 0(%2,%0,4),%0\n"
		"	jmp 2b\n"
		".previous\n"
		_ASM_EXTABLE(0b,3b)
		_ASM_EXTABLE(1b,2b)
		: "=&c"(size), "=&D" (__d0)
		: "r"(size & 3), "0"(size / 4), "1"(addr), "a"(0),
		  "r"(__USER_DS));
	return size;
}

/**
 * clear_user: - Zero a block of memory in user space.
 * @to:   Destination address, in user space.
 * @n:    Number of bytes to zero.
 *
 * Zero a block of memory in user space.
 *
 * Returns number of bytes that could not be cleared.
 * On success, this will be zero.
 */
unsigned long
clear_user(void __user *to, unsigned long n)
{
	might_fault();
	if (access_ok(VERIFY_WRITE, to, n))
		n = __do_clear_user(to, n);
	return n;
}
EXPORT_SYMBOL(clear_user);

/**
 * __clear_user: - Zero a block of memory in user space, with less checking.
 * @to:   Destination address, in user space.
 * @n:    Number of bytes to zero.
 *
 * Zero a block of memory in user space.  Caller must check
 * the specified block with access_ok() before calling this function.
 *
 * Returns number of bytes that could not be cleared.
 * On success, this will be zero.
 */
unsigned long
__clear_user(void __user *to, unsigned long n)
{
	return __do_clear_user(to, n);
}
EXPORT_SYMBOL(__clear_user);

/**
 * strnlen_user: - Get the size of a string in user space.
 * @s: The string to measure.
 * @n: The maximum valid length
 *
 * Get the size of a NUL-terminated string in user space.
 *
 * Returns the size of the string INCLUDING the terminating NUL.
 * On exception, returns 0.
 * If the string is too long, returns a value greater than @n.
 */
long strnlen_user(const char __user *s, long n)
{
	unsigned long mask = -__addr_ok(s);
	unsigned long res, tmp;

	might_fault();

	__asm__ __volatile__(
		"	movw %w8,%%es\n"
		"	testl %0, %0\n"
		"	jz 3f\n"
		"	movl %0,%%ecx\n"
		"0:	repne; scasb\n"
		"	setne %%al\n"
		"	subl %%ecx,%0\n"
		"	addl %0,%%eax\n"
		"1:\n"
		"	pushl %%ss\n"
		"	popl %%es\n"
		".section .fixup,\"ax\"\n"
		"2:	xorl %%eax,%%eax\n"
		"	jmp 1b\n"
		"3:	movb $1,%%al\n"
		"	jmp 1b\n"
		".previous\n"
		".section __ex_table,\"a\"\n"
		"	.align 4\n"
		"	.long 0b,2b\n"
		".previous"
		:"=&r" (n), "=&D" (s), "=&a" (res), "=&c" (tmp)
		:"0" (n), "1" (s), "2" (0), "3" (mask), "r" (__USER_DS)
		:"cc");
	return res & mask;
}
EXPORT_SYMBOL(strnlen_user);

#ifdef CONFIG_X86_INTEL_USERCOPY
static unsigned long
__generic_copy_to_user_intel(void __user *to, const void *from, unsigned long size)
{
	int d0, d1;
	__asm__ __volatile__(
		       "       movw %w6, %%es\n"
		       "       .align 2,0x90\n"
		       "1:     movl 32(%4), %%eax\n"
		       "       cmpl $67, %0\n"
		       "       jbe 3f\n"
		       "2:     movl 64(%4), %%eax\n"
		       "       .align 2,0x90\n"
		       "3:     movl 0(%4), %%eax\n"
		       "4:     movl 4(%4), %%edx\n"
		       "5:     movl %%eax, %%es:0(%3)\n"
		       "6:     movl %%edx, %%es:4(%3)\n"
		       "7:     movl 8(%4), %%eax\n"
		       "8:     movl 12(%4),%%edx\n"
		       "9:     movl %%eax, %%es:8(%3)\n"
		       "10:    movl %%edx, %%es:12(%3)\n"
		       "11:    movl 16(%4), %%eax\n"
		       "12:    movl 20(%4), %%edx\n"
		       "13:    movl %%eax, %%es:16(%3)\n"
		       "14:    movl %%edx, %%es:20(%3)\n"
		       "15:    movl 24(%4), %%eax\n"
		       "16:    movl 28(%4), %%edx\n"
		       "17:    movl %%eax, %%es:24(%3)\n"
		       "18:    movl %%edx, %%es:28(%3)\n"
		       "19:    movl 32(%4), %%eax\n"
		       "20:    movl 36(%4), %%edx\n"
		       "21:    movl %%eax, %%es:32(%3)\n"
		       "22:    movl %%edx, %%es:36(%3)\n"
		       "23:    movl 40(%4), %%eax\n"
		       "24:    movl 44(%4), %%edx\n"
		       "25:    movl %%eax, %%es:40(%3)\n"
		       "26:    movl %%edx, %%es:44(%3)\n"
		       "27:    movl 48(%4), %%eax\n"
		       "28:    movl 52(%4), %%edx\n"
		       "29:    movl %%eax, %%es:48(%3)\n"
		       "30:    movl %%edx, %%es:52(%3)\n"
		       "31:    movl 56(%4), %%eax\n"
		       "32:    movl 60(%4), %%edx\n"
		       "33:    movl %%eax, %%es:56(%3)\n"
		       "34:    movl %%edx, %%es:60(%3)\n"
		       "       addl $-64, %0\n"
		       "       addl $64, %4\n"
		       "       addl $64, %3\n"
		       "       cmpl $63, %0\n"
		       "       ja  1b\n"
		       "35:    movl  %0, %%eax\n"
		       "       shrl  $2, %0\n"
		       "       andl  $3, %%eax\n"
		       "       cld\n"
		       "99:    rep; movsl\n"
		       "36:    movl %%eax, %0\n"
		       "37:    rep; movsb\n"
		       "100:\n"
		       "       pushl %%ss\n"
		       "       popl %%es\n"
		       ".section .fixup,\"ax\"\n"
		       "101:   lea 0(%%eax,%0,4),%0\n"
		       "       jmp 100b\n"
		       ".previous\n"
		       ".section __ex_table,\"a\"\n"
		       "       .align 4\n"
		       "       .long 1b,100b\n"
		       "       .long 2b,100b\n"
		       "       .long 3b,100b\n"
		       "       .long 4b,100b\n"
		       "       .long 5b,100b\n"
		       "       .long 6b,100b\n"
		       "       .long 7b,100b\n"
		       "       .long 8b,100b\n"
		       "       .long 9b,100b\n"
		       "       .long 10b,100b\n"
		       "       .long 11b,100b\n"
		       "       .long 12b,100b\n"
		       "       .long 13b,100b\n"
		       "       .long 14b,100b\n"
		       "       .long 15b,100b\n"
		       "       .long 16b,100b\n"
		       "       .long 17b,100b\n"
		       "       .long 18b,100b\n"
		       "       .long 19b,100b\n"
		       "       .long 20b,100b\n"
		       "       .long 21b,100b\n"
		       "       .long 22b,100b\n"
		       "       .long 23b,100b\n"
		       "       .long 24b,100b\n"
		       "       .long 25b,100b\n"
		       "       .long 26b,100b\n"
		       "       .long 27b,100b\n"
		       "       .long 28b,100b\n"
		       "       .long 29b,100b\n"
		       "       .long 30b,100b\n"
		       "       .long 31b,100b\n"
		       "       .long 32b,100b\n"
		       "       .long 33b,100b\n"
		       "       .long 34b,100b\n"
		       "       .long 35b,100b\n"
		       "       .long 36b,100b\n"
		       "       .long 37b,100b\n"
		       "       .long 99b,101b\n"
		       ".previous"
		       : "=&c"(size), "=&D" (d0), "=&S" (d1)
		       :  "1"(to), "2"(from), "0"(size), "r"(__USER_DS)
		       : "eax", "edx", "memory");
	return size;
}

static unsigned long
__generic_copy_from_user_intel(void *to, const void __user *from, unsigned long size)
{
	int d0, d1;
	__asm__ __volatile__(
		       "       movw %w6, %%ds\n"
		       "       .align 2,0x90\n"
		       "1:     movl 32(%4), %%eax\n"
		       "       cmpl $67, %0\n"
		       "       jbe 3f\n"
		       "2:     movl 64(%4), %%eax\n"
		       "       .align 2,0x90\n"
		       "3:     movl 0(%4), %%eax\n"
		       "4:     movl 4(%4), %%edx\n"
		       "5:     movl %%eax, %%es:0(%3)\n"
		       "6:     movl %%edx, %%es:4(%3)\n"
		       "7:     movl 8(%4), %%eax\n"
		       "8:     movl 12(%4),%%edx\n"
		       "9:     movl %%eax, %%es:8(%3)\n"
		       "10:    movl %%edx, %%es:12(%3)\n"
		       "11:    movl 16(%4), %%eax\n"
		       "12:    movl 20(%4), %%edx\n"
		       "13:    movl %%eax, %%es:16(%3)\n"
		       "14:    movl %%edx, %%es:20(%3)\n"
		       "15:    movl 24(%4), %%eax\n"
		       "16:    movl 28(%4), %%edx\n"
		       "17:    movl %%eax, %%es:24(%3)\n"
		       "18:    movl %%edx, %%es:28(%3)\n"
		       "19:    movl 32(%4), %%eax\n"
		       "20:    movl 36(%4), %%edx\n"
		       "21:    movl %%eax, %%es:32(%3)\n"
		       "22:    movl %%edx, %%es:36(%3)\n"
		       "23:    movl 40(%4), %%eax\n"
		       "24:    movl 44(%4), %%edx\n"
		       "25:    movl %%eax, %%es:40(%3)\n"
		       "26:    movl %%edx, %%es:44(%3)\n"
		       "27:    movl 48(%4), %%eax\n"
		       "28:    movl 52(%4), %%edx\n"
		       "29:    movl %%eax, %%es:48(%3)\n"
		       "30:    movl %%edx, %%es:52(%3)\n"
		       "31:    movl 56(%4), %%eax\n"
		       "32:    movl 60(%4), %%edx\n"
		       "33:    movl %%eax, %%es:56(%3)\n"
		       "34:    movl %%edx, %%es:60(%3)\n"
		       "       addl $-64, %0\n"
		       "       addl $64, %4\n"
		       "       addl $64, %3\n"
		       "       cmpl $63, %0\n"
		       "       ja  1b\n"
		       "35:    movl  %0, %%eax\n"
		       "       shrl  $2, %0\n"
		       "       andl  $3, %%eax\n"
		       "       cld\n"
		       "99:    rep; movsl\n"
		       "36:    movl %%eax, %0\n"
		       "37:    rep; movsb\n"
		       "100:\n"
		       "       pushl %%ss\n"
		       "       popl %%ds\n"
		       ".section .fixup,\"ax\"\n"
		       "101:   lea 0(%%eax,%0,4),%0\n"
		       "       jmp 100b\n"
		       ".previous\n"
		       ".section __ex_table,\"a\"\n"
		       "       .align 4\n"
		       "       .long 1b,100b\n"
		       "       .long 2b,100b\n"
		       "       .long 3b,100b\n"
		       "       .long 4b,100b\n"
		       "       .long 5b,100b\n"
		       "       .long 6b,100b\n"
		       "       .long 7b,100b\n"
		       "       .long 8b,100b\n"
		       "       .long 9b,100b\n"
		       "       .long 10b,100b\n"
		       "       .long 11b,100b\n"
		       "       .long 12b,100b\n"
		       "       .long 13b,100b\n"
		       "       .long 14b,100b\n"
		       "       .long 15b,100b\n"
		       "       .long 16b,100b\n"
		       "       .long 17b,100b\n"
		       "       .long 18b,100b\n"
		       "       .long 19b,100b\n"
		       "       .long 20b,100b\n"
		       "       .long 21b,100b\n"
		       "       .long 22b,100b\n"
		       "       .long 23b,100b\n"
		       "       .long 24b,100b\n"
		       "       .long 25b,100b\n"
		       "       .long 26b,100b\n"
		       "       .long 27b,100b\n"
		       "       .long 28b,100b\n"
		       "       .long 29b,100b\n"
		       "       .long 30b,100b\n"
		       "       .long 31b,100b\n"
		       "       .long 32b,100b\n"
		       "       .long 33b,100b\n"
		       "       .long 34b,100b\n"
		       "       .long 35b,100b\n"
		       "       .long 36b,100b\n"
		       "       .long 37b,100b\n"
		       "       .long 99b,101b\n"
		       ".previous"
		       : "=&c"(size), "=&D" (d0), "=&S" (d1)
		       :  "1"(to), "2"(from), "0"(size), "r"(__USER_DS)
		       : "eax", "edx", "memory");
	return size;
}

static unsigned long
__copy_user_zeroing_intel(void *to, const void __user *from, unsigned long size)
{
	int d0, d1;
	__asm__ __volatile__(
		       "        movw %w6, %%ds\n"
		       "        .align 2,0x90\n"
		       "0:      movl 32(%4), %%eax\n"
		       "        cmpl $67, %0\n"
		       "        jbe 2f\n"
		       "1:      movl 64(%4), %%eax\n"
		       "        .align 2,0x90\n"
		       "2:      movl 0(%4), %%eax\n"
		       "21:     movl 4(%4), %%edx\n"
		       "        movl %%eax, %%es:0(%3)\n"
		       "        movl %%edx, %%es:4(%3)\n"
		       "3:      movl 8(%4), %%eax\n"
		       "31:     movl 12(%4),%%edx\n"
		       "        movl %%eax, %%es:8(%3)\n"
		       "        movl %%edx, %%es:12(%3)\n"
		       "4:      movl 16(%4), %%eax\n"
		       "41:     movl 20(%4), %%edx\n"
		       "        movl %%eax, %%es:16(%3)\n"
		       "        movl %%edx, %%es:20(%3)\n"
		       "10:     movl 24(%4), %%eax\n"
		       "51:     movl 28(%4), %%edx\n"
		       "        movl %%eax, %%es:24(%3)\n"
		       "        movl %%edx, %%es:28(%3)\n"
		       "11:     movl 32(%4), %%eax\n"
		       "61:     movl 36(%4), %%edx\n"
		       "        movl %%eax, %%es:32(%3)\n"
		       "        movl %%edx, %%es:36(%3)\n"
		       "12:     movl 40(%4), %%eax\n"
		       "71:     movl 44(%4), %%edx\n"
		       "        movl %%eax, %%es:40(%3)\n"
		       "        movl %%edx, %%es:44(%3)\n"
		       "13:     movl 48(%4), %%eax\n"
		       "81:     movl 52(%4), %%edx\n"
		       "        movl %%eax, %%es:48(%3)\n"
		       "        movl %%edx, %%es:52(%3)\n"
		       "14:     movl 56(%4), %%eax\n"
		       "91:     movl 60(%4), %%edx\n"
		       "        movl %%eax, %%es:56(%3)\n"
		       "        movl %%edx, %%es:60(%3)\n"
		       "        addl $-64, %0\n"
		       "        addl $64, %4\n"
		       "        addl $64, %3\n"
		       "        cmpl $63, %0\n"
		       "        ja  0b\n"
		       "5:      movl  %0, %%eax\n"
		       "        shrl  $2, %0\n"
		       "        andl $3, %%eax\n"
		       "        cld\n"
		       "6:      rep; movsl\n"
		       "        movl %%eax,%0\n"
		       "7:      rep; movsb\n"
		       "8:\n"
		       "        pushl %%ss\n"
		       "        popl %%ds\n"
		       ".section .fixup,\"ax\"\n"
		       "9:      lea 0(%%eax,%0,4),%0\n"
		       "16:     pushl %0\n"
		       "        pushl %%eax\n"
		       "        xorl %%eax,%%eax\n"
		       "        rep; stosb\n"
		       "        popl %%eax\n"
		       "        popl %0\n"
		       "        jmp 8b\n"
		       ".previous\n"
		       ".section __ex_table,\"a\"\n"
		       "	.align 4\n"
		       "	.long 0b,16b\n"
		       "	.long 1b,16b\n"
		       "	.long 2b,16b\n"
		       "	.long 21b,16b\n"
		       "	.long 3b,16b\n"
		       "	.long 31b,16b\n"
		       "	.long 4b,16b\n"
		       "	.long 41b,16b\n"
		       "	.long 10b,16b\n"
		       "	.long 51b,16b\n"
		       "	.long 11b,16b\n"
		       "	.long 61b,16b\n"
		       "	.long 12b,16b\n"
		       "	.long 71b,16b\n"
		       "	.long 13b,16b\n"
		       "	.long 81b,16b\n"
		       "	.long 14b,16b\n"
		       "	.long 91b,16b\n"
		       "	.long 6b,9b\n"
		       "        .long 7b,16b\n"
		       ".previous"
		       : "=&c"(size), "=&D" (d0), "=&S" (d1)
		       :  "1"(to), "2"(from), "0"(size), "r"(__USER_DS)
		       : "eax", "edx", "memory");
	return size;
}

/*
 * Non Temporal Hint version of __copy_user_zeroing_intel.  It is cache aware.
 * hyoshiok@miraclelinux.com
 */

static unsigned long __copy_user_zeroing_intel_nocache(void *to,
				const void __user *from, unsigned long size)
{
	int d0, d1;

	__asm__ __volatile__(
	       "        movw %w6, %%ds\n"
	       "        .align 2,0x90\n"
	       "0:      movl 32(%4), %%eax\n"
	       "        cmpl $67, %0\n"
	       "        jbe 2f\n"
	       "1:      movl 64(%4), %%eax\n"
	       "        .align 2,0x90\n"
	       "2:      movl 0(%4), %%eax\n"
	       "21:     movl 4(%4), %%edx\n"
	       "        movnti %%eax, %%es:0(%3)\n"
	       "        movnti %%edx, %%es:4(%3)\n"
	       "3:      movl 8(%4), %%eax\n"
	       "31:     movl 12(%4),%%edx\n"
	       "        movnti %%eax, %%es:8(%3)\n"
	       "        movnti %%edx, %%es:12(%3)\n"
	       "4:      movl 16(%4), %%eax\n"
	       "41:     movl 20(%4), %%edx\n"
	       "        movnti %%eax, %%es:16(%3)\n"
	       "        movnti %%edx, %%es:20(%3)\n"
	       "10:     movl 24(%4), %%eax\n"
	       "51:     movl 28(%4), %%edx\n"
	       "        movnti %%eax, %%es:24(%3)\n"
	       "        movnti %%edx, %%es:28(%3)\n"
	       "11:     movl 32(%4), %%eax\n"
	       "61:     movl 36(%4), %%edx\n"
	       "        movnti %%eax, %%es:32(%3)\n"
	       "        movnti %%edx, %%es:36(%3)\n"
	       "12:     movl 40(%4), %%eax\n"
	       "71:     movl 44(%4), %%edx\n"
	       "        movnti %%eax, %%es:40(%3)\n"
	       "        movnti %%edx, %%es:44(%3)\n"
	       "13:     movl 48(%4), %%eax\n"
	       "81:     movl 52(%4), %%edx\n"
	       "        movnti %%eax, %%es:48(%3)\n"
	       "        movnti %%edx, %%es:52(%3)\n"
	       "14:     movl 56(%4), %%eax\n"
	       "91:     movl 60(%4), %%edx\n"
	       "        movnti %%eax, %%es:56(%3)\n"
	       "        movnti %%edx, %%es:60(%3)\n"
	       "        addl $-64, %0\n"
	       "        addl $64, %4\n"
	       "        addl $64, %3\n"
	       "        cmpl $63, %0\n"
	       "        ja  0b\n"
	       "        sfence \n"
	       "5:      movl  %0, %%eax\n"
	       "        shrl  $2, %0\n"
	       "        andl $3, %%eax\n"
	       "        cld\n"
	       "6:      rep; movsl\n"
	       "        movl %%eax,%0\n"
	       "7:      rep; movsb\n"
	       "8:\n"
	       "        pushl %%ss\n"
	       "        popl %%ds\n"
	       ".section .fixup,\"ax\"\n"
	       "9:      lea 0(%%eax,%0,4),%0\n"
	       "16:     pushl %0\n"
	       "        pushl %%eax\n"
	       "        xorl %%eax,%%eax\n"
	       "        rep; stosb\n"
	       "        popl %%eax\n"
	       "        popl %0\n"
	       "        jmp 8b\n"
	       ".previous\n"
	       ".section __ex_table,\"a\"\n"
	       "	.align 4\n"
	       "	.long 0b,16b\n"
	       "	.long 1b,16b\n"
	       "	.long 2b,16b\n"
	       "	.long 21b,16b\n"
	       "	.long 3b,16b\n"
	       "	.long 31b,16b\n"
	       "	.long 4b,16b\n"
	       "	.long 41b,16b\n"
	       "	.long 10b,16b\n"
	       "	.long 51b,16b\n"
	       "	.long 11b,16b\n"
	       "	.long 61b,16b\n"
	       "	.long 12b,16b\n"
	       "	.long 71b,16b\n"
	       "	.long 13b,16b\n"
	       "	.long 81b,16b\n"
	       "	.long 14b,16b\n"
	       "	.long 91b,16b\n"
	       "	.long 6b,9b\n"
	       "        .long 7b,16b\n"
	       ".previous"
	       : "=&c"(size), "=&D" (d0), "=&S" (d1)
	       :  "1"(to), "2"(from), "0"(size), "r"(__USER_DS)
	       : "eax", "edx", "memory");
	return size;
}

static unsigned long __copy_user_intel_nocache(void *to,
				const void __user *from, unsigned long size)
{
	int d0, d1;

	__asm__ __volatile__(
	       "        movw %w6, %%ds\n"
	       "        .align 2,0x90\n"
	       "0:      movl 32(%4), %%eax\n"
	       "        cmpl $67, %0\n"
	       "        jbe 2f\n"
	       "1:      movl 64(%4), %%eax\n"
	       "        .align 2,0x90\n"
	       "2:      movl 0(%4), %%eax\n"
	       "21:     movl 4(%4), %%edx\n"
	       "        movnti %%eax, %%es:0(%3)\n"
	       "        movnti %%edx, %%es:4(%3)\n"
	       "3:      movl 8(%4), %%eax\n"
	       "31:     movl 12(%4),%%edx\n"
	       "        movnti %%eax, %%es:8(%3)\n"
	       "        movnti %%edx, %%es:12(%3)\n"
	       "4:      movl 16(%4), %%eax\n"
	       "41:     movl 20(%4), %%edx\n"
	       "        movnti %%eax, %%es:16(%3)\n"
	       "        movnti %%edx, %%es:20(%3)\n"
	       "10:     movl 24(%4), %%eax\n"
	       "51:     movl 28(%4), %%edx\n"
	       "        movnti %%eax, %%es:24(%3)\n"
	       "        movnti %%edx, %%es:28(%3)\n"
	       "11:     movl 32(%4), %%eax\n"
	       "61:     movl 36(%4), %%edx\n"
	       "        movnti %%eax, %%es:32(%3)\n"
	       "        movnti %%edx, %%es:36(%3)\n"
	       "12:     movl 40(%4), %%eax\n"
	       "71:     movl 44(%4), %%edx\n"
	       "        movnti %%eax, %%es:40(%3)\n"
	       "        movnti %%edx, %%es:44(%3)\n"
	       "13:     movl 48(%4), %%eax\n"
	       "81:     movl 52(%4), %%edx\n"
	       "        movnti %%eax, %%es:48(%3)\n"
	       "        movnti %%edx, %%es:52(%3)\n"
	       "14:     movl 56(%4), %%eax\n"
	       "91:     movl 60(%4), %%edx\n"
	       "        movnti %%eax, %%es:56(%3)\n"
	       "        movnti %%edx, %%es:60(%3)\n"
	       "        addl $-64, %0\n"
	       "        addl $64, %4\n"
	       "        addl $64, %3\n"
	       "        cmpl $63, %0\n"
	       "        ja  0b\n"
	       "        sfence \n"
	       "5:      movl  %0, %%eax\n"
	       "        shrl  $2, %0\n"
	       "        andl $3, %%eax\n"
	       "        cld\n"
	       "6:      rep; movsl\n"
	       "        movl %%eax,%0\n"
	       "7:      rep; movsb\n"
	       "8:\n"
	       "        pushl %%ss\n"
	       "        popl %%ds\n"
	       ".section .fixup,\"ax\"\n"
	       "9:      lea 0(%%eax,%0,4),%0\n"
	       "16:     jmp 8b\n"
	       ".previous\n"
	       ".section __ex_table,\"a\"\n"
	       "	.align 4\n"
	       "	.long 0b,16b\n"
	       "	.long 1b,16b\n"
	       "	.long 2b,16b\n"
	       "	.long 21b,16b\n"
	       "	.long 3b,16b\n"
	       "	.long 31b,16b\n"
	       "	.long 4b,16b\n"
	       "	.long 41b,16b\n"
	       "	.long 10b,16b\n"
	       "	.long 51b,16b\n"
	       "	.long 11b,16b\n"
	       "	.long 61b,16b\n"
	       "	.long 12b,16b\n"
	       "	.long 71b,16b\n"
	       "	.long 13b,16b\n"
	       "	.long 81b,16b\n"
	       "	.long 14b,16b\n"
	       "	.long 91b,16b\n"
	       "	.long 6b,9b\n"
	       "        .long 7b,16b\n"
	       ".previous"
	       : "=&c"(size), "=&D" (d0), "=&S" (d1)
	       :  "1"(to), "2"(from), "0"(size), "r"(__USER_DS)
	       : "eax", "edx", "memory");
	return size;
}

#else

/*
 * Leave these declared but undefined.  They should not be any references to
 * them
 */
unsigned long __copy_user_zeroing_intel(void *to, const void __user *from,
					unsigned long size);
unsigned long __generic_copy_to_user_intel(void __user *to, const void *from,
					unsigned long size);
unsigned long __generic_copy_from_user_intel(void *to, const void __user *from,
					unsigned long size);
unsigned long __copy_user_zeroing_intel_nocache(void *to,
				const void __user *from, unsigned long size);
#endif /* CONFIG_X86_INTEL_USERCOPY */

/* Generic arbitrary sized copy.  */
static unsigned long
__generic_copy_to_user(void __user *to, const void *from, unsigned long size)
{
	int __d0, __d1, __d2;

	__asm__ __volatile__(
		"	movw %w8,%%es\n"
		"	cmp  $7,%0\n"
		"	jbe  1f\n"
		"	movl %1,%0\n"
		"	negl %0\n"
		"	andl $7,%0\n"
		"	subl %0,%3\n"
		"4:	rep; movsb\n"
		"	movl %3,%0\n"
		"	shrl $2,%0\n"
		"	andl $3,%3\n"
		"	.align 2,0x90\n"
		"0:	rep; movsl\n"
		"	movl %3,%0\n"
		"1:	rep; movsb\n"
		"2:\n"
		"	pushl %%ss\n"
		"	popl %%es\n"
		".section .fixup,\"ax\"\n"
		"5:	addl %3,%0\n"
		"	jmp 2b\n"
		"3:	lea 0(%3,%0,4),%0\n"
		"	jmp 2b\n"
		".previous\n"
		".section __ex_table,\"a\"\n"
		"	.align 4\n"
		"	.long 4b,5b\n"
		"	.long 0b,3b\n"
		"	.long 1b,2b\n"
		".previous"
		: "=&c"(size), "=&D" (__d0), "=&S" (__d1), "=r"(__d2)
		: "3"(size), "0"(size), "1"(to), "2"(from), "r"(__USER_DS)
		: "memory");
	return size;
}

static unsigned long
__generic_copy_from_user(void *to, const void __user *from, unsigned long size)
{
	int __d0, __d1, __d2;

	__asm__ __volatile__(
		"	movw %w8,%%ds\n"
		"	cmp  $7,%0\n"
		"	jbe  1f\n"
		"	movl %1,%0\n"
		"	negl %0\n"
		"	andl $7,%0\n"
		"	subl %0,%3\n"
		"4:	rep; movsb\n"
		"	movl %3,%0\n"
		"	shrl $2,%0\n"
		"	andl $3,%3\n"
		"	.align 2,0x90\n"
		"0:	rep; movsl\n"
		"	movl %3,%0\n"
		"1:	rep; movsb\n"
		"2:\n"
		"	pushl %%ss\n"
		"	popl %%ds\n"
		".section .fixup,\"ax\"\n"
		"5:	addl %3,%0\n"
		"	jmp 2b\n"
		"3:	lea 0(%3,%0,4),%0\n"
		"	jmp 2b\n"
		".previous\n"
		".section __ex_table,\"a\"\n"
		"	.align 4\n"
		"	.long 4b,5b\n"
		"	.long 0b,3b\n"
		"	.long 1b,2b\n"
		".previous"
		: "=&c"(size), "=&D" (__d0), "=&S" (__d1), "=r"(__d2)
		: "3"(size), "0"(size), "1"(to), "2"(from), "r"(__USER_DS)
		: "memory");
	return size;
}

static unsigned long
__copy_user_zeroing(void *to, const void __user *from, unsigned long size)
{
	int __d0, __d1, __d2;

	__asm__ __volatile__(
		"	movw %w8,%%ds\n"
		"	cmp  $7,%0\n"
		"	jbe  1f\n"
		"	movl %1,%0\n"
		"	negl %0\n"
		"	andl $7,%0\n"
		"	subl %0,%3\n"
		"4:	rep; movsb\n"
		"	movl %3,%0\n"
		"	shrl $2,%0\n"
		"	andl $3,%3\n"
		"	.align 2,0x90\n"
		"0:	rep; movsl\n"
		"	movl %3,%0\n"
		"1:	rep; movsb\n"
		"2:\n"
		"	pushl %%ss\n"
		"	popl %%ds\n"
		".section .fixup,\"ax\"\n"
		"5:	addl %3,%0\n"
		"	jmp 6f\n"
		"3:	lea 0(%3,%0,4),%0\n"
		"6:	pushl %0\n"
		"	pushl %%eax\n"
		"	xorl %%eax,%%eax\n"
		"	rep; stosb\n"
		"	popl %%eax\n"
		"	popl %0\n"
		"	jmp 2b\n"
		".previous\n"
		".section __ex_table,\"a\"\n"
		"	.align 4\n"
		"	.long 4b,5b\n"
		"	.long 0b,3b\n"
		"	.long 1b,6b\n"
		".previous"
		: "=&c"(size), "=&D" (__d0), "=&S" (__d1), "=r"(__d2)
		: "3"(size), "0"(size), "1"(to), "2"(from), "r"(__USER_DS)
		: "memory");
	return size;
}

unsigned long __copy_to_user_ll(void __user *to, const void *from,
				unsigned long n)
{
#ifndef CONFIG_X86_WP_WORKS_OK
	if (unlikely(boot_cpu_data.wp_works_ok == 0) &&
			((unsigned long)to) < TASK_SIZE) {
		/*
		 * When we are in an atomic section (see
		 * mm/filemap.c:file_read_actor), return the full
		 * length to take the slow path.
		 */
		if (in_atomic())
			return n;

		/*
		 * CPU does not honor the WP bit when writing
		 * from supervisory mode, and due to preemption or SMP,
		 * the page tables can change at any time.
		 * Do it manually.	Manfred <manfred@colorfullife.com>
		 */
		while (n) {
			unsigned long offset = ((unsigned long)to)%PAGE_SIZE;
			unsigned long len = PAGE_SIZE - offset;
			int retval;
			struct page *pg;
			void *maddr;

			if (len > n)
				len = n;

survive:
			down_read(&current->mm->mmap_sem);
			retval = get_user_pages(current, current->mm,
					(unsigned long)to, 1, 1, 0, &pg, NULL);

			if (retval == -ENOMEM && is_global_init(current)) {
				up_read(&current->mm->mmap_sem);
				congestion_wait(BLK_RW_ASYNC, HZ/50);
				goto survive;
			}

			if (retval != 1) {
				up_read(&current->mm->mmap_sem);
				break;
			}

			maddr = kmap_atomic(pg, KM_USER0);
			memcpy(maddr + offset, from, len);
			kunmap_atomic(maddr, KM_USER0);
			set_page_dirty_lock(pg);
			put_page(pg);
			up_read(&current->mm->mmap_sem);

			from += len;
			to += len;
			n -= len;
		}
		return n;
	}
#endif
	if (movsl_is_ok(to, from, n))
		n = __generic_copy_to_user(to, from, n);
	else
		n = __generic_copy_to_user_intel(to, from, n);
	return n;
}
EXPORT_SYMBOL(__copy_to_user_ll);

unsigned long __copy_from_user_ll(void *to, const void __user *from,
					unsigned long n)
{
	if (movsl_is_ok(to, from, n))
		n = __copy_user_zeroing(to, from, n);
	else
		n = __copy_user_zeroing_intel(to, from, n);
	return n;
}
EXPORT_SYMBOL(__copy_from_user_ll);

unsigned long __copy_from_user_ll_nozero(void *to, const void __user *from,
					 unsigned long n)
{
	if (movsl_is_ok(to, from, n))
		n = __generic_copy_from_user(to, from, n);
	else
		n = __generic_copy_from_user_intel(to, from, n);
	return n;
}
EXPORT_SYMBOL(__copy_from_user_ll_nozero);

unsigned long __copy_from_user_ll_nocache(void *to, const void __user *from,
					unsigned long n)
{
#ifdef CONFIG_X86_INTEL_USERCOPY
	if (n > 64 && cpu_has_xmm2)
		n = __copy_user_zeroing_intel_nocache(to, from, n);
	else
		n = __copy_user_zeroing(to, from, n);
#else
	n = __copy_user_zeroing(to, from, n);
#endif
	return n;
}
EXPORT_SYMBOL(__copy_from_user_ll_nocache);

unsigned long __copy_from_user_ll_nocache_nozero(void *to, const void __user *from,
					unsigned long n)
{
#ifdef CONFIG_X86_INTEL_USERCOPY
	if (n > 64 && cpu_has_xmm2)
		n = __copy_user_intel_nocache(to, from, n);
	else
		n = __generic_copy_from_user(to, from, n);
#else
	n = __generic_copy_from_user(to, from, n);
#endif
	return n;
}
EXPORT_SYMBOL(__copy_from_user_ll_nocache_nozero);

void copy_from_user_overflow(void)
{
	WARN(1, "Buffer overflow detected!\n");
}
EXPORT_SYMBOL(copy_from_user_overflow);

void copy_to_user_overflow(void)
{
	WARN(1, "Buffer overflow detected!\n");
}
EXPORT_SYMBOL(copy_to_user_overflow);

#ifdef CONFIG_PAX_MEMORY_UDEREF
void __set_fs(mm_segment_t x, int cpu)
{
	unsigned long limit = x.seg;
	struct desc_struct d;

	current_thread_info()->addr_limit = x;
	if (unlikely(paravirt_enabled()))
		return;

	if (likely(limit))
		limit = (limit - 1UL) >> PAGE_SHIFT;
	pack_descriptor(&d, 0UL, limit, 0xF3, 0xC);
	write_gdt_entry(get_cpu_gdt_table(cpu), GDT_ENTRY_DEFAULT_USER_DS, &d, DESCTYPE_S);
}

void set_fs(mm_segment_t x)
{
	__set_fs(x, get_cpu());
	put_cpu();
}
EXPORT_SYMBOL(copy_from_user);
#else
void set_fs(mm_segment_t x)
{
	current_thread_info()->addr_limit = x;
}
#endif

EXPORT_SYMBOL(set_fs);

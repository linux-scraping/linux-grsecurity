/*
 * __put_user functions.
 *
 * (C) Copyright 2005 Linus Torvalds
 * (C) Copyright 2005 Andi Kleen
 * (C) Copyright 2008 Glauber Costa
 *
 * These functions have a non-standard call interface
 * to make them more efficient, especially as they
 * return an error value in addition to the "real"
 * return value.
 */
#include <linux/linkage.h>
#include <asm/dwarf2.h>
#include <asm/thread_info.h>
#include <asm/errno.h>
#include <asm/asm.h>
#include <asm/segment.h>


/*
 * __put_user_X
 *
 * Inputs:	%eax[:%edx] contains the data
 *		%ecx contains the address
 *
 * Outputs:	%eax is error code (0 or -EFAULT)
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */

#define ENTER	CFI_STARTPROC
#define EXIT	ret ; \
		CFI_ENDPROC

.text
ENTRY(__put_user_1)
	ENTER

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_MEMORY_UDEREF)
	pushl $(__USER_DS)
	popl %ds
#else
	GET_THREAD_INFO(%_ASM_BX)
	cmp TI_addr_limit(%_ASM_BX),%_ASM_CX
	jae bad_put_user
#endif

1:	movb %al,(%_ASM_CX)

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_MEMORY_UDEREF)
	pushl %ss
	popl %ds
#endif

	xor %eax,%eax
	EXIT
ENDPROC(__put_user_1)

ENTRY(__put_user_2)
	ENTER

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_MEMORY_UDEREF)
	pushl $(__USER_DS)
	popl %ds
#else
	GET_THREAD_INFO(%_ASM_BX)
	mov TI_addr_limit(%_ASM_BX),%_ASM_BX
	sub $1,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae bad_put_user
#endif

2:	movw %ax,(%_ASM_CX)

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_MEMORY_UDEREF)
	pushl %ss
	popl %ds
#endif

	xor %eax,%eax
	EXIT
ENDPROC(__put_user_2)

ENTRY(__put_user_4)
	ENTER

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_MEMORY_UDEREF)
	pushl $(__USER_DS)
	popl %ds
#else
	GET_THREAD_INFO(%_ASM_BX)
	mov TI_addr_limit(%_ASM_BX),%_ASM_BX
	sub $3,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae bad_put_user
#endif

3:	movl %eax,(%_ASM_CX)

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_MEMORY_UDEREF)
	pushl %ss
	popl %ds
#endif

	xor %eax,%eax
	EXIT
ENDPROC(__put_user_4)

ENTRY(__put_user_8)
	ENTER

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_MEMORY_UDEREF)
	pushl $(__USER_DS)
	popl %ds
#else
	GET_THREAD_INFO(%_ASM_BX)
	mov TI_addr_limit(%_ASM_BX),%_ASM_BX
	sub $7,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae bad_put_user
#endif

4:	mov %_ASM_AX,(%_ASM_CX)
#ifdef CONFIG_X86_32
5:	movl %edx,4(%_ASM_CX)
#endif

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_MEMORY_UDEREF)
	pushl %ss
	popl %ds
#endif

	xor %eax,%eax
	EXIT
ENDPROC(__put_user_8)

bad_put_user:
	CFI_STARTPROC

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_MEMORY_UDEREF)
	pushl %ss
	popl %ds
#endif

	movl $-EFAULT,%eax
	EXIT
END(bad_put_user)

.section __ex_table,"a"
	_ASM_PTR 1b,bad_put_user
	_ASM_PTR 2b,bad_put_user
	_ASM_PTR 3b,bad_put_user
	_ASM_PTR 4b,bad_put_user
#ifdef CONFIG_X86_32
	_ASM_PTR 5b,bad_put_user
#endif
.previous

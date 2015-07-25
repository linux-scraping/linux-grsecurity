/*

 x86 function call convention, 64-bit:
 -------------------------------------
  arguments           |  callee-saved      | extra caller-saved | return
 [callee-clobbered]   |                    | [callee-clobbered] |
 ---------------------------------------------------------------------------
 rdi rsi rdx rcx r8-9 | rbx rbp [*] r12-15 | r10-11             | rax, rdx [**]

 ( rsp is obviously invariant across normal function calls. (gcc can 'merge'
   functions when it sees tail-call optimization possibilities) rflags is
   clobbered. Leftover arguments are passed over the stack frame.)

 [*]  In the frame-pointers case rbp is fixed to the stack frame.

 [**] for struct return values wider than 64 bits the return convention is a
      bit more complex: up to 128 bits width we return small structures
      straight in rax, rdx. For structures larger than that (3 words or
      larger) the caller puts a pointer to an on-stack return struct
      [allocated in the caller's stack frame] into the first argument - i.e.
      into rdi. All other arguments shift up by one in this case.
      Fortunately this case is rare in the kernel.

For 32-bit we have the following conventions - kernel is built with
-mregparm=3 and -freg-struct-return:

 x86 function calling convention, 32-bit:
 ----------------------------------------
  arguments         | callee-saved        | extra caller-saved | return
 [callee-clobbered] |                     | [callee-clobbered] |
 -------------------------------------------------------------------------
 eax edx ecx        | ebx edi esi ebp [*] | <none>             | eax, edx [**]

 ( here too esp is obviously invariant across normal function calls. eflags
   is clobbered. Leftover arguments are passed over the stack frame. )

 [*]  In the frame-pointers case ebp is fixed to the stack frame.

 [**] We build with -freg-struct-return, which on 32-bit means similar
      semantics as on 64-bit: edx can be used for a second return value
      (i.e. covering integer and structure sizes up to 64 bits) - after that
      it gets more complex and more expensive: 3-word or larger struct returns
      get done in the caller's frame and the pointer to the return struct goes
      into regparm0, i.e. eax - the other arguments shift up and the
      function's register parameters degenerate to regparm=2 in essence.

*/

#include <asm/dwarf2.h>

#ifdef CONFIG_X86_64

/*
 * 64-bit system call stack frame layout defines and helpers,
 * for assembly code:
 */

/* The layout forms the "struct pt_regs" on the stack: */
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
#define R15		0*8
#define R14		1*8
#define R13		2*8
#define R12		3*8
#define RBP		4*8
#define RBX		5*8
/* These regs are callee-clobbered. Always saved on kernel entry. */
#define R11		6*8
#define R10		7*8
#define R9		8*8
#define R8		9*8
#define RAX		10*8
#define RCX		11*8
#define RDX		12*8
#define RSI		13*8
#define RDI		14*8
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
#define ORIG_RAX	15*8
/* Return frame for iretq */
#define RIP		16*8
#define CS		17*8
#define EFLAGS		18*8
#define RSP		19*8
#define SS		20*8

#define SIZEOF_PTREGS	21*8

	.macro ALLOC_PT_GPREGS_ON_STACK addskip=0
	subq	$15*8+\addskip, %rsp
	CFI_ADJUST_CFA_OFFSET 15*8+\addskip
	.endm

	.macro SAVE_C_REGS_HELPER offset=0 rax=1 rcx=1 r8910=1 r11=1
#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	movq_cfi r12, R12+\offset
#endif
	.if \r11
	movq_cfi r11, R11+\offset
	.endif
	.if \r8910
	movq_cfi r10, R10+\offset
	movq_cfi r9,  R9+\offset
	movq_cfi r8,  R8+\offset
	.endif
	.if \rax
	movq_cfi rax, RAX+\offset
	.endif
	.if \rcx
	movq_cfi rcx, RCX+\offset
	.endif
	movq_cfi rdx, RDX+\offset
	movq_cfi rsi, RSI+\offset
	movq_cfi rdi, RDI+\offset
	.endm
	.macro SAVE_C_REGS offset=0
	SAVE_C_REGS_HELPER \offset, 1, 1, 1, 1
	.endm
	.macro SAVE_C_REGS_EXCEPT_RAX_RCX offset=0
	SAVE_C_REGS_HELPER \offset, 0, 0, 1, 1
	.endm
	.macro SAVE_C_REGS_EXCEPT_R891011
	SAVE_C_REGS_HELPER 0, 1, 1, 0, 0
	.endm
	.macro SAVE_C_REGS_EXCEPT_RCX_R891011
	SAVE_C_REGS_HELPER 0, 1, 0, 0, 0
	.endm
	.macro SAVE_C_REGS_EXCEPT_RAX_RCX_R11
	SAVE_C_REGS_HELPER 0, 0, 0, 1, 0
	.endm

	.macro SAVE_EXTRA_REGS offset=0
	movq_cfi r15, R15+\offset
	movq_cfi r14, R14+\offset
	movq_cfi r13, R13+\offset
#ifndef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	movq_cfi r12, R12+\offset
#endif
	movq_cfi rbp, RBP+\offset
	movq_cfi rbx, RBX+\offset
	.endm
	.macro SAVE_EXTRA_REGS_RBP offset=0
	movq_cfi rbp, RBP+\offset
	.endm

	.macro RESTORE_EXTRA_REGS offset=0
	movq_cfi_restore R15+\offset, r15
	movq_cfi_restore R14+\offset, r14
	movq_cfi_restore R13+\offset, r13
#ifndef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	movq_cfi_restore R12+\offset, r12
#endif
	movq_cfi_restore RBP+\offset, rbp
	movq_cfi_restore RBX+\offset, rbx
	.endm

	.macro ZERO_EXTRA_REGS
	xorl	%r15d, %r15d
	xorl	%r14d, %r14d
	xorl	%r13d, %r13d
#ifndef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	xorl	%r12d, %r12d
#endif
	xorl	%ebp, %ebp
	xorl	%ebx, %ebx
	.endm

	.macro RESTORE_C_REGS_HELPER rstor_rax=1, rstor_rcx=1, rstor_r11=1, rstor_r8910=1, rstor_rdx=1, rstor_r12=1
#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	.if \rstor_r12
	movq_cfi_restore R12, r12
	.endif
#endif
	.if \rstor_r11
	movq_cfi_restore R11, r11
	.endif
	.if \rstor_r8910
	movq_cfi_restore R10, r10
	movq_cfi_restore R9, r9
	movq_cfi_restore R8, r8
	.endif
	.if \rstor_rax
	movq_cfi_restore RAX, rax
	.endif
	.if \rstor_rcx
	movq_cfi_restore RCX, rcx
	.endif
	.if \rstor_rdx
	movq_cfi_restore RDX, rdx
	.endif
	movq_cfi_restore RSI, rsi
	movq_cfi_restore RDI, rdi
	.endm
	.macro RESTORE_C_REGS
	RESTORE_C_REGS_HELPER 1,1,1,1,1,1
	.endm
	.macro RESTORE_C_REGS_EXCEPT_RAX
	RESTORE_C_REGS_HELPER 0,1,1,1,1,0
	.endm
	.macro RESTORE_C_REGS_EXCEPT_RCX
	RESTORE_C_REGS_HELPER 1,0,1,1,1,0
	.endm
	.macro RESTORE_C_REGS_EXCEPT_R11
	RESTORE_C_REGS_HELPER 1,1,0,1,1,1
	.endm
	.macro RESTORE_C_REGS_EXCEPT_RCX_R11
	RESTORE_C_REGS_HELPER 1,0,0,1,1,1
	.endm
	.macro RESTORE_RSI_RDI
	RESTORE_C_REGS_HELPER 0,0,0,0,0,1
	.endm
	.macro RESTORE_RSI_RDI_RDX
	RESTORE_C_REGS_HELPER 0,0,0,0,1,1
	.endm

	.macro REMOVE_PT_GPREGS_FROM_STACK addskip=0
	addq $15*8+\addskip, %rsp
	CFI_ADJUST_CFA_OFFSET -(15*8+\addskip)
	.endm

	.macro icebp
	.byte 0xf1
	.endm

#else /* CONFIG_X86_64 */

/*
 * For 32bit only simplified versions of SAVE_ALL/RESTORE_ALL. These
 * are different from the entry_32.S versions in not changing the segment
 * registers. So only suitable for in kernel use, not when transitioning
 * from or to user space. The resulting stack frame is not a standard
 * pt_regs frame. The main use case is calling C code from assembler
 * when all the registers need to be preserved.
 */

	.macro SAVE_ALL
	pushl_cfi_reg eax
	pushl_cfi_reg ebp
	pushl_cfi_reg edi
	pushl_cfi_reg esi
	pushl_cfi_reg edx
	pushl_cfi_reg ecx
	pushl_cfi_reg ebx
	.endm

	.macro RESTORE_ALL
	popl_cfi_reg ebx
	popl_cfi_reg ecx
	popl_cfi_reg edx
	popl_cfi_reg esi
	popl_cfi_reg edi
	popl_cfi_reg ebp
	popl_cfi_reg eax
	.endm

#endif /* CONFIG_X86_64 */


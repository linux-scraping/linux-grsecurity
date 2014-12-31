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

#define R15		  0
#define R14		  8
#define R13		 16
#define R12		 24
#define RBP		 32
#define RBX		 40

/* arguments: interrupts/non tracing syscalls only save up to here: */
#define R11		 48
#define R10		 56
#define R9		 64
#define R8		 72
#define RAX		 80
#define RCX		 88
#define RDX		 96
#define RSI		104
#define RDI		112
#define ORIG_RAX	120       /* + error_code */
/* end of arguments */

/* cpu exception frame or undefined in case of fast syscall: */
#define RIP		128
#define CS		136
#define EFLAGS		144
#define RSP		152
#define SS		160

#define ARGOFFSET	R15

	.macro SAVE_ARGS addskip=0, save_rcx=1, save_r891011=1, rax_enosys=0
	subq  $ORIG_RAX-ARGOFFSET+\addskip, %rsp
	CFI_ADJUST_CFA_OFFSET	ORIG_RAX-ARGOFFSET+\addskip
	movq_cfi rdi, RDI
	movq_cfi rsi, RSI
	movq_cfi rdx, RDX

	.if \save_rcx
	movq_cfi rcx, RCX
	.endif

	.if \rax_enosys
	movq $-ENOSYS, RAX(%rsp)
	.else
	movq_cfi rax, RAX
	.endif

	.if \save_r891011
	movq_cfi r8,  R8
	movq_cfi r9,  R9
	movq_cfi r10, R10
	movq_cfi r11, R11
	.endif

#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	movq_cfi r12, R12
#endif

	.endm

#define ARG_SKIP	ORIG_RAX

	.macro RESTORE_ARGS rstor_rax=1, addskip=0, rstor_rcx=1, rstor_r11=1, \
			    rstor_r8910=1, rstor_rdx=1

#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	movq_cfi_restore R12, r12
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

	.if ORIG_RAX+\addskip > 0
	addq $ORIG_RAX+\addskip, %rsp
	CFI_ADJUST_CFA_OFFSET	-(ORIG_RAX+\addskip)
	.endif
	.endm

	.macro LOAD_ARGS skiprax=0
	movq R11(%rsp),    %r11
	movq R10(%rsp),  %r10
	movq R9(%rsp), %r9
	movq R8(%rsp), %r8
	movq RCX(%rsp), %rcx
	movq RDX(%rsp), %rdx
	movq RSI(%rsp), %rsi
	movq RDI(%rsp), %rdi
	.if \skiprax
	.else
	movq ORIG_RAX(%rsp), %rax
	.endif
	.endm

	.macro SAVE_REST
	movq_cfi rbx, RBX
	movq_cfi rbp, RBP

#ifndef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	movq_cfi r12, R12
#endif

	movq_cfi r13, R13
	movq_cfi r14, R14
	movq_cfi r15, R15
	.endm

	.macro RESTORE_REST
	movq_cfi_restore R15, r15
	movq_cfi_restore R14, r14
	movq_cfi_restore R13, r13

#ifndef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	movq_cfi_restore R12, r12
#endif

	movq_cfi_restore RBP, rbp
	movq_cfi_restore RBX, rbx
	.endm

	.macro SAVE_ALL
	SAVE_ARGS
	SAVE_REST
	.endm

	.macro RESTORE_ALL addskip=0
	RESTORE_REST
	RESTORE_ARGS 1, \addskip
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
	pushl_cfi %eax
	CFI_REL_OFFSET eax, 0
	pushl_cfi %ebp
	CFI_REL_OFFSET ebp, 0
	pushl_cfi %edi
	CFI_REL_OFFSET edi, 0
	pushl_cfi %esi
	CFI_REL_OFFSET esi, 0
	pushl_cfi %edx
	CFI_REL_OFFSET edx, 0
	pushl_cfi %ecx
	CFI_REL_OFFSET ecx, 0
	pushl_cfi %ebx
	CFI_REL_OFFSET ebx, 0
	.endm

	.macro RESTORE_ALL
	popl_cfi %ebx
	CFI_RESTORE ebx
	popl_cfi %ecx
	CFI_RESTORE ecx
	popl_cfi %edx
	CFI_RESTORE edx
	popl_cfi %esi
	CFI_RESTORE esi
	popl_cfi %edi
	CFI_RESTORE edi
	popl_cfi %ebp
	CFI_RESTORE ebp
	popl_cfi %eax
	CFI_RESTORE eax
	.endm

#endif /* CONFIG_X86_64 */


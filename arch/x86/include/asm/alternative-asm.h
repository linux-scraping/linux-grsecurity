#ifndef _ASM_X86_ALTERNATIVE_ASM_H
#define _ASM_X86_ALTERNATIVE_ASM_H

#ifdef __ASSEMBLY__

#include <asm/asm.h>

#ifdef CONFIG_SMP
	.macro LOCK_PREFIX
672:	lock
	.pushsection .smp_locks,"a"
	.balign 4
	.long 672b - .
	.popsection
	.endm
#else
	.macro LOCK_PREFIX
	.endm
#endif

#ifdef KERNEXEC_PLUGIN
	.macro pax_force_retaddr_bts rip=0
	btsq $63,\rip(%rsp)
	.endm
#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_BTS
	.macro pax_force_retaddr rip=0, reload=0
	btsq $63,\rip(%rsp)
	.endm
	.macro pax_force_fptr ptr
	btsq $63,\ptr
	.endm
	.macro pax_set_fptr_mask
	.endm
#endif
#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	.macro pax_force_retaddr rip=0, reload=0
	.if \reload
	pax_set_fptr_mask
	.endif
	orq %r12,\rip(%rsp)
	.endm
	.macro pax_force_fptr ptr
	orq %r12,\ptr
	.endm
	.macro pax_set_fptr_mask
	movabs $0x8000000000000000,%r12
	.endm
#endif
#else
	.macro pax_force_retaddr rip=0, reload=0
	.endm
	.macro pax_force_fptr ptr
	.endm
	.macro pax_force_retaddr_bts rip=0
	.endm
	.macro pax_set_fptr_mask
	.endm
#endif

.macro altinstruction_entry orig alt feature orig_len alt_len
	.long \orig - .
	.long \alt - .
	.word \feature
	.byte \orig_len
	.byte \alt_len
.endm

#endif  /*  __ASSEMBLY__  */

#endif /* _ASM_X86_ALTERNATIVE_ASM_H */

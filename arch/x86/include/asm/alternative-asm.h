#ifdef __ASSEMBLY__

#include <asm/asm.h>

#ifdef CONFIG_SMP
	.macro LOCK_PREFIX
1:	lock
	.section .smp_locks,"a"
	.balign 4
	.long 1b - .
	.previous
	.endm
#else
	.macro LOCK_PREFIX
	.endm
#endif

#ifdef CONFIG_PAX_KERNEXEC_PLUGIN
	.macro pax_force_retaddr rip=0
	btsq $63,\rip(%rsp)
	.endm
	.macro pax_force_fptr ptr
	btsq $63,\ptr
	.endm
#else
	.macro pax_force_retaddr rip=0
	.endm
	.macro pax_force_fptr ptr
	.endm
#endif

.macro altinstruction_entry orig alt feature orig_len alt_len
	.align 8
	.quad \orig
	.quad \alt
	.word \feature
	.byte \orig_len
	.byte \alt_len
.endm

#endif  /*  __ASSEMBLY__  */

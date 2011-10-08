#ifdef __ASSEMBLY__

#ifdef CONFIG_X86_32
# define X86_ALIGN .long
#else
# define X86_ALIGN .quad
#endif

#ifdef CONFIG_SMP
	.macro LOCK_PREFIX
1:	lock
	.section .smp_locks,"a"
	.align 4
	X86_ALIGN 1b
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

#endif  /*  __ASSEMBLY__  */

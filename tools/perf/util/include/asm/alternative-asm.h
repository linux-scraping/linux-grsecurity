#ifndef _PERF_ASM_ALTERNATIVE_ASM_H
#define _PERF_ASM_ALTERNATIVE_ASM_H

/* Just disable it so we can build arch/x86/lib/memcpy_64.S for perf bench: */

#define altinstruction_entry #

	.macro pax_force_retaddr rip=0, reload=0
	.endm

#endif

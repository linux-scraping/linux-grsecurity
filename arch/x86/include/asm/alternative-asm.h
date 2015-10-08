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

/*
 * Issue one struct alt_instr descriptor entry (need to put it into
 * the section .altinstructions, see below). This entry contains
 * enough information for the alternatives patching code to patch an
 * instruction. See apply_alternatives().
 */
.macro altinstruction_entry orig alt feature orig_len alt_len pad_len
	.long \orig - .
	.long \alt - .
	.word \feature
	.byte \orig_len
	.byte \alt_len
	.byte \pad_len
.endm

/*
 * Define an alternative between two instructions. If @feature is
 * present, early code in apply_alternatives() replaces @oldinstr with
 * @newinstr. ".skip" directive takes care of proper instruction padding
 * in case @newinstr is longer than @oldinstr.
 */
.macro ALTERNATIVE oldinstr, newinstr, feature
140:
	\oldinstr
141:
	.skip -(((144f-143f)-(141b-140b)) > 0) * ((144f-143f)-(141b-140b)),0x90
142:

	.pushsection .altinstructions,"a"
	altinstruction_entry 140b,143f,\feature,142b-140b,144f-143f,142b-141b
	.popsection

	.pushsection .altinstr_replacement,"a"
143:
	\newinstr
144:
	.popsection
.endm

#define old_len			141b-140b
#define new_len1		144f-143f
#define new_len2		145f-144f

/*
 * max without conditionals. Idea adapted from:
 * http://graphics.stanford.edu/~seander/bithacks.html#IntegerMinOrMax
 */
#define alt_max_short(a, b)	((a) ^ (((a) ^ (b)) & -(-((a) < (b)))))


/*
 * Same as ALTERNATIVE macro above but for two alternatives. If CPU
 * has @feature1, it replaces @oldinstr with @newinstr1. If CPU has
 * @feature2, it replaces @oldinstr with @feature2.
 */
.macro ALTERNATIVE_2 oldinstr, newinstr1, feature1, newinstr2, feature2
140:
	\oldinstr
141:
	.skip -((alt_max_short(new_len1, new_len2) - (old_len)) > 0) * \
		(alt_max_short(new_len1, new_len2) - (old_len)),0x90
142:

	.pushsection .altinstructions,"a"
	altinstruction_entry 140b,143f,\feature1,142b-140b,144f-143f,142b-141b
	altinstruction_entry 140b,144f,\feature2,142b-140b,145f-144f,142b-141b
	.popsection

	.pushsection .altinstr_replacement,"a"
143:
	\newinstr1
144:
	\newinstr2
145:
	.popsection
.endm

#endif  /*  __ASSEMBLY__  */

#endif /* _ASM_X86_ALTERNATIVE_ASM_H */

#ifndef _ASM_X86_MMAN_H
#define _ASM_X86_MMAN_H

#define MAP_32BIT	0x40		/* only give out 32bit addresses */

#include <asm-generic/mman.h>

#ifdef __KERNEL__
#ifndef __ASSEMBLY__
#ifdef CONFIG_X86_32
#define arch_mmap_check	i386_mmap_check
int i386_mmap_check(unsigned long addr, unsigned long len,
		unsigned long flags);
#endif
#endif
#endif

#endif /* _ASM_X86_MMAN_H */

#ifndef _I386_BUG_H
#define _I386_BUG_H


/*
 * Tell the user there is some problem.
 * The offending file and line are encoded after the "officially
 * undefined" opcode for parsing in the trap handler.
 */

#ifdef CONFIG_BUG
#define HAVE_ARCH_BUG
#ifdef CONFIG_DEBUG_BUGVERBOSE
#define BUG()					\
 __asm__ __volatile__(	"ud2\n\t"		\
			"ljmp %0, %1\n\t"	\
			 : : "i" (__LINE__), "i" (__FILE__))
#else
#define BUG() __asm__ __volatile__("ud2\n")
#endif
#endif

#include <asm-generic/bug.h>
#endif

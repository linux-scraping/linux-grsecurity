#ifndef ___ASM_SPARC_UACCESS_H
#define ___ASM_SPARC_UACCESS_H

#ifdef __KERNEL__
#ifndef __ASSEMBLY__
#include <linux/types.h>
extern void check_object_size(const void *ptr, unsigned long n, bool to);
#endif
#endif

#if defined(__sparc__) && defined(__arch64__)
#include <asm/uaccess_64.h>
#else
#include <asm/uaccess_32.h>
#endif
#endif

#ifndef __ARCH_H8300_CACHE_H
#define __ARCH_H8300_CACHE_H

#include <linux/const.h>

/* bytes per L1 cache line */
#define        L1_CACHE_BYTES  _AC(4,UL)

/* m68k-elf-gcc  2.95.2 doesn't like these */

#define __cacheline_aligned
#define ____cacheline_aligned

#endif

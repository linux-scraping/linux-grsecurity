#ifndef __ASM_GENERIC_CACHE_H
#define __ASM_GENERIC_CACHE_H
/*
 * 32 bytes appears to be the most common cache line size,
 * so make that the default here. Architectures with larger
 * cache lines need to provide their own cache.h.
 */

#define L1_CACHE_SHIFT		5U
#define L1_CACHE_BYTES		(1U << L1_CACHE_SHIFT)

#endif /* __ASM_GENERIC_CACHE_H */

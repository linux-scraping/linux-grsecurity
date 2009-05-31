#ifndef _ASM_X86_VSYSCALL_H
#define _ASM_X86_VSYSCALL_H

enum vsyscall_num {
	__NR_vgettimeofday,
	__NR_vtime,
	__NR_vgetcpu,
};

#define VSYSCALL_START (-10UL << 20)
#define VSYSCALL_SIZE 1024
#define VSYSCALL_END (-2UL << 20)
#define VSYSCALL_MAPPED_PAGES 1
#define VSYSCALL_ADDR(vsyscall_nr) (VSYSCALL_START+VSYSCALL_SIZE*(vsyscall_nr))

#ifdef __KERNEL__
#include <linux/seqlock.h>
#include <linux/getcpu.h>
#include <linux/time.h>

#define __section_vgetcpu_mode __attribute__ ((unused, __section__ (".vgetcpu_mode"), aligned(16)))

/* Definitions for CONFIG_GENERIC_TIME definitions */
#define __section_vsyscall_gtod_data __attribute__ \
	((unused, __section__ (".vsyscall_gtod_data"),aligned(16)))
#define __section_vsyscall_clock __attribute__ \
	((unused, __section__ (".vsyscall_clock"),aligned(16)))
#define __vsyscall_fn \
	__attribute__ ((unused, __section__(".vsyscall_fn"))) notrace

#define VGETCPU_RDTSCP	1
#define VGETCPU_LSL	2

extern int __vgetcpu_mode;

/* kernel space (writeable) */
extern int vgetcpu_mode;
extern struct timezone sys_tz;

extern void map_vsyscall(void);

extern int vgettimeofday(struct timeval * tv, struct timezone * tz);
extern time_t vtime(time_t *t);
extern long vgetcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache);
#endif /* __KERNEL__ */

#endif /* _ASM_X86_VSYSCALL_H */

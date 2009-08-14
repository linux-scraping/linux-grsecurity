/*
 * Copyright 2006 Andi Kleen, SUSE Labs.
 * Subject to the GNU Public License, v.2
 *
 * Fast user context implementation of clock_gettime and gettimeofday.
 *
 * The code should have no internal unresolved relocations.
 * Check with readelf after changing.
 * Also alternative() doesn't work.
 */

/* Disable profiling for userspace code: */
#define DISABLE_BRANCH_PROFILING

#include <linux/kernel.h>
#include <linux/posix-timers.h>
#include <linux/time.h>
#include <linux/string.h>
#include <asm/vsyscall.h>
#include <asm/vgtod.h>
#include <asm/timex.h>
#include <asm/hpet.h>
#include <asm/unistd.h>
#include <asm/io.h>
#include <asm/fixmap.h>
#include "vextern.h"

#define gtod vdso_vsyscall_gtod_data

notrace noinline long __vdso_fallback_time(long *t)
{
	long secs;
	asm volatile("syscall"
		: "=a" (secs)
		: "0" (__NR_time),"D" (t) : "r11", "cx", "memory");
	return secs;
}

notrace static long vdso_fallback_gettime(long clock, struct timespec *ts)
{
	long ret;
	asm("syscall" : "=a" (ret) :
	    "0" (__NR_clock_gettime),"D" (clock), "S" (ts) : "r11", "cx", "memory");
	return ret;
}

notrace static inline cycle_t __vdso_vread_hpet(void)
{
	return readl((const void __iomem *)fix_to_virt(VSYSCALL_HPET) + 0xf0);
}

notrace static inline cycle_t __vdso_vread_tsc(void)
{
	cycle_t ret = (cycle_t)vget_cycles();

	return ret >= gtod->clock.cycle_last ? ret : gtod->clock.cycle_last;
}

notrace static inline long vgetns(void)
{
	long v;
	if (gtod->clock.name[0] == 't' && gtod->clock.name[1] == 's' && gtod->clock.name[2] == 'c' && !gtod->clock.name[3])
		v = __vdso_vread_tsc();
	else
		v = __vdso_vread_hpet();
	v = (v - gtod->clock.cycle_last) & gtod->clock.mask;
	return (v * gtod->clock.mult) >> gtod->clock.shift;
}

notrace static noinline int do_realtime(struct timespec *ts)
{
	unsigned long seq, ns;
	do {
		seq = read_seqbegin(&gtod->lock);
		ts->tv_sec = gtod->wall_time_sec;
		ts->tv_nsec = gtod->wall_time_nsec;
		ns = vgetns();
	} while (unlikely(read_seqretry(&gtod->lock, seq)));
	timespec_add_ns(ts, ns);
	return 0;
}

/* Copy of the version in kernel/time.c which we cannot directly access */
notrace static void
vset_normalized_timespec(struct timespec *ts, long sec, long nsec)
{
	while (nsec >= NSEC_PER_SEC) {
		nsec -= NSEC_PER_SEC;
		++sec;
	}
	while (nsec < 0) {
		nsec += NSEC_PER_SEC;
		--sec;
	}
	ts->tv_sec = sec;
	ts->tv_nsec = nsec;
}

notrace static noinline int do_monotonic(struct timespec *ts)
{
	unsigned long seq, ns, secs;
	do {
		seq = read_seqbegin(&gtod->lock);
		secs = gtod->wall_time_sec;
		ns = gtod->wall_time_nsec + vgetns();
		secs += gtod->wall_to_monotonic.tv_sec;
		ns += gtod->wall_to_monotonic.tv_nsec;
	} while (unlikely(read_seqretry(&gtod->lock, seq)));
	vset_normalized_timespec(ts, secs, ns);
	return 0;
}

notrace int __vdso_clock_gettime(clockid_t clock, struct timespec *ts)
{
	if (likely(gtod->sysctl_enabled &&
		   ((gtod->clock.name[0] == 'h' && gtod->clock.name[1] == 'p' && gtod->clock.name[2] == 'e' && gtod->clock.name[3] == 't' && !gtod->clock.name[4]) ||
		    (gtod->clock.name[0] == 't' && gtod->clock.name[1] == 's' && gtod->clock.name[2] == 'c' && !gtod->clock.name[3]))))
		switch (clock) {
		case CLOCK_REALTIME:
			return do_realtime(ts);
		case CLOCK_MONOTONIC:
			return do_monotonic(ts);
		}
	return vdso_fallback_gettime(clock, ts);
}
int clock_gettime(clockid_t, struct timespec *)
	__attribute__((weak, alias("__vdso_clock_gettime")));

notrace noinline int __vdso_fallback_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	long ret;
	asm("syscall" : "=a" (ret) :
	    "0" (__NR_gettimeofday), "D" (tv), "S" (tz) : "r11", "cx", "memory");
	return ret;
}

notrace int __vdso_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	if (likely(gtod->sysctl_enabled &&
		   ((gtod->clock.name[0] == 'h' && gtod->clock.name[1] == 'p' && gtod->clock.name[2] == 'e' && gtod->clock.name[3] == 't' && !gtod->clock.name[4]) ||
		    (gtod->clock.name[0] == 't' && gtod->clock.name[1] == 's' && gtod->clock.name[2] == 'c' && !gtod->clock.name[3]))))
	{
		BUILD_BUG_ON(offsetof(struct timeval, tv_usec) !=
			     offsetof(struct timespec, tv_nsec) ||
			     sizeof(*tv) != sizeof(struct timespec));
		do_realtime((struct timespec *)tv);
		tv->tv_usec /= 1000;
		if (unlikely(tz != NULL)) {
			/* Avoid memcpy. Some old compilers fail to inline it */
			tz->tz_minuteswest = gtod->sys_tz.tz_minuteswest;
			tz->tz_dsttime = gtod->sys_tz.tz_dsttime;
		}
		return 0;
	}
	return __vdso_fallback_gettimeofday(tv, tz);
}
int gettimeofday(struct timeval *, struct timezone *)
	__attribute__((weak, alias("__vdso_gettimeofday")));

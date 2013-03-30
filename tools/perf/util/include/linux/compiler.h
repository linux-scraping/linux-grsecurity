#ifndef _PERF_LINUX_COMPILER_H_
#define _PERF_LINUX_COMPILER_H_

#ifndef __always_inline
#define __always_inline	inline
#endif
#define __user
#ifndef __attribute_const__
#define __attribute_const__
#endif

#define __used		__attribute__((__unused__))

#ifndef __size_overflow
# define __size_overflow(...)
#endif

#ifndef __intentional_overflow
# define __intentional_overflow(...)
#endif

#endif

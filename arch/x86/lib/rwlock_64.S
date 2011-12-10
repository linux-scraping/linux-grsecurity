/* Slow paths of read/write spinlocks. */

#include <linux/linkage.h>
#include <asm/rwlock.h>
#include <asm/asm.h>
#include <asm/alternative-asm.h>
#include <asm/dwarf2.h>

/* rdi:	pointer to rwlock_t */
ENTRY(__write_lock_failed)
	CFI_STARTPROC
	LOCK_PREFIX
	addl $RW_LOCK_BIAS,(%rdi)

#ifdef CONFIG_PAX_REFCOUNT
	jno 1234f
	LOCK_PREFIX
	subl $RW_LOCK_BIAS,(%rdi)
	int $4
1234:
	_ASM_EXTABLE(1234b, 1234b)
#endif

1:	rep
	nop
	cmpl $RW_LOCK_BIAS,(%rdi)
	jne 1b
	LOCK_PREFIX
	subl $RW_LOCK_BIAS,(%rdi)

#ifdef CONFIG_PAX_REFCOUNT
	jno 1234f
	LOCK_PREFIX
	addl $RW_LOCK_BIAS,(%rdi)
	int $4
1234:
	_ASM_EXTABLE(1234b, 1234b)
#endif

	jnz  __write_lock_failed
	pax_force_retaddr
	ret
	CFI_ENDPROC
END(__write_lock_failed)

/* rdi:	pointer to rwlock_t */
ENTRY(__read_lock_failed)
	CFI_STARTPROC
	LOCK_PREFIX
	incl (%rdi)

#ifdef CONFIG_PAX_REFCOUNT
	jno 1234f
	LOCK_PREFIX
	decl (%rdi)
	int $4
1234:
	_ASM_EXTABLE(1234b, 1234b)
#endif

1:	rep
	nop
	cmpl $1,(%rdi)
	js 1b
	LOCK_PREFIX
	decl (%rdi)

#ifdef CONFIG_PAX_REFCOUNT
	jno 1234f
	LOCK_PREFIX
	incl (%rdi)
	int $4
1234:
	_ASM_EXTABLE(1234b, 1234b)
#endif

	js __read_lock_failed
	pax_force_retaddr
	ret
	CFI_ENDPROC
END(__read_lock_failed)

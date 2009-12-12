#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/init.h>

#include <asm/pgtable.h>

#if defined(CONFIG_X86_32) && defined(CONFIG_X86_PAE)
int nx_enabled;

#ifndef CONFIG_PAX_PAGEEXEC
/*
 * noexec = on|off
 *
 * Control non-executable mappings for processes.
 *
 * on      Enable
 * off     Disable
 */
static int __init noexec_setup(char *str)
{
	if (!str)
		return -EINVAL;
	if (!strncmp(str, "on", 2)) {
		nx_enabled = 1;
	} else if (!strncmp(str, "off", 3)) {
		nx_enabled = 0;
	}
	return 0;
}
early_param("noexec", noexec_setup);
#endif
#endif

#ifdef CONFIG_X86_PAE
void __init set_nx(void)
{
	if (!nx_enabled && cpu_has_nx) {
		unsigned l, h;

		__supported_pte_mask &= ~_PAGE_NX;
		rdmsr(MSR_EFER, l, h);
		l &= ~EFER_NX;
		wrmsr(MSR_EFER, l, h);
	}
}
#else
void set_nx(void)
{
}
#endif

#ifdef CONFIG_X86_64
void __cpuinit check_efer(void)
{
	unsigned long efer;

	rdmsrl(MSR_EFER, efer);
	if (!(efer & EFER_NX) || !nx_enabled)
		__supported_pte_mask &= ~_PAGE_NX;
}
#endif


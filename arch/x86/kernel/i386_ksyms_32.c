#include <linux/module.h>
#include <asm/semaphore.h>
#include <asm/checksum.h>
#include <asm/desc.h>
#include <asm/pgtable.h>

EXPORT_SYMBOL_GPL(cpu_gdt_table);

EXPORT_SYMBOL(__down_failed);
EXPORT_SYMBOL(__down_failed_interruptible);
EXPORT_SYMBOL(__down_failed_trylock);
EXPORT_SYMBOL(__up_wakeup);
/* Networking helper routines. */
EXPORT_SYMBOL(csum_partial_copy_generic);
EXPORT_SYMBOL(csum_partial_copy_generic_to_user);
EXPORT_SYMBOL(csum_partial_copy_generic_from_user);

EXPORT_SYMBOL(__get_user_1);
EXPORT_SYMBOL(__get_user_2);
EXPORT_SYMBOL(__get_user_4);

EXPORT_SYMBOL(__put_user_1);
EXPORT_SYMBOL(__put_user_2);
EXPORT_SYMBOL(__put_user_4);
EXPORT_SYMBOL(__put_user_8);

EXPORT_SYMBOL(strstr);

EXPORT_SYMBOL(csum_partial);
EXPORT_SYMBOL(empty_zero_page);

#ifdef CONFIG_PAX_KERNEXEC
EXPORT_SYMBOL(KERNEL_TEXT_OFFSET);
#endif

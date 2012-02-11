# grsecurity's ACL system was originally written in 2001 by Michael Dalton
# during 2001-2009 it has been completely redesigned by Brad Spengler
# into an RBAC system
#
# All code in this directory and various hooks inserted throughout the kernel
# are copyright Brad Spengler - Open Source Security, Inc., and released 
# under the GPL v2 or higher

KBUILD_CFLAGS += -Werror

obj-y = grsec_chdir.o grsec_chroot.o grsec_exec.o grsec_fifo.o grsec_fork.o \
	grsec_mount.o grsec_sig.o grsec_sysctl.o \
	grsec_time.o grsec_tpe.o grsec_link.o grsec_pax.o grsec_ptrace.o

obj-$(CONFIG_GRKERNSEC) += grsec_init.o grsum.o gracl.o gracl_segv.o \
	gracl_cap.o gracl_alloc.o gracl_shm.o grsec_mem.o gracl_fs.o \
	gracl_learn.o grsec_log.o
obj-$(CONFIG_GRKERNSEC_RESLOG) += gracl_res.o

ifdef CONFIG_NET
obj-y += grsec_sock.o
obj-$(CONFIG_GRKERNSEC) += gracl_ip.o
endif

ifndef CONFIG_GRKERNSEC
obj-y += grsec_disabled.o
endif

ifdef CONFIG_GRKERNSEC_HIDESYM
extra-y := grsec_hidesym.o
$(obj)/grsec_hidesym.o:
	@-chmod -f 500 /boot
	@-chmod -f 500 /lib/modules
	@-chmod -f 500 /lib64/modules
	@-chmod -f 500 /lib32/modules
	@-chmod -f 700 .
	@echo '  grsec: protected kernel image paths'
endif

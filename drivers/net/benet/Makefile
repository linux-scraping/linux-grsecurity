#
# Makefile to build the be2net network driver
#

EXTRA_CFLAGS += -DCONFIG_PALAU

obj-$(CONFIG_BE2NET) += be2net.o

be2net-y :=  be_main.o be_cmds.o be_ethtool.o be_compat.o be_misc.o

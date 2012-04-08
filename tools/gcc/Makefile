#CC := gcc
#PLUGIN_SOURCE_FILES := pax_plugin.c
#PLUGIN_OBJECT_FILES := $(patsubst %.c,%.o,$(PLUGIN_SOURCE_FILES))
GCCPLUGINS_DIR := $(shell $(CC) -print-file-name=plugin)
#CFLAGS += -I$(GCCPLUGINS_DIR)/include -fPIC -O2 -Wall -W -std=gnu99

HOST_EXTRACFLAGS += -I$(GCCPLUGINS_DIR)/include -I$(GCCPLUGINS_DIR)/include/c-family -std=gnu99 -ggdb
CFLAGS_size_overflow_plugin.o := -Wno-missing-initializer

hostlibs-y := constify_plugin.so
hostlibs-$(CONFIG_PAX_MEMORY_STACKLEAK) += stackleak_plugin.so
hostlibs-$(CONFIG_KALLOCSTAT_PLUGIN) += kallocstat_plugin.so
hostlibs-$(CONFIG_PAX_KERNEXEC_PLUGIN) += kernexec_plugin.so
hostlibs-$(CONFIG_CHECKER_PLUGIN) += checker_plugin.so
hostlibs-y += colorize_plugin.so
hostlibs-$(CONFIG_PAX_SIZE_OVERFLOW) += size_overflow_plugin.so

always := $(hostlibs-y)

constify_plugin-objs := constify_plugin.o
stackleak_plugin-objs := stackleak_plugin.o
kallocstat_plugin-objs := kallocstat_plugin.o
kernexec_plugin-objs := kernexec_plugin.o
checker_plugin-objs := checker_plugin.o
colorize_plugin-objs := colorize_plugin.o
size_overflow_plugin-objs := size_overflow_plugin.o

#CC := gcc
#PLUGIN_SOURCE_FILES := pax_plugin.c
#PLUGIN_OBJECT_FILES := $(patsubst %.c,%.o,$(PLUGIN_SOURCE_FILES))
GCCPLUGINS_DIR := $(shell $(HOSTCC) -print-file-name=plugin)
#CFLAGS += -I$(GCCPLUGINS_DIR)/include -fPIC -O2 -Wall -W

HOST_EXTRACFLAGS += -I$(GCCPLUGINS_DIR)/include

hostlibs-y := stackleak_plugin.so constify_plugin.so kallocstat_plugin.so kernexec_plugin.so
always := $(hostlibs-y)
stackleak_plugin-objs := stackleak_plugin.o
constify_plugin-objs := constify_plugin.o
kallocstat_plugin-objs := kallocstat_plugin.o
kernexec_plugin-objs := kernexec_plugin.o

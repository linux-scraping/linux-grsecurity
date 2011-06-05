#CC := gcc
#PLUGIN_SOURCE_FILES := pax_plugin.c
#PLUGIN_OBJECT_FILES := $(patsubst %.c,%.o,$(PLUGIN_SOURCE_FILES))
GCCPLUGINS_DIR := $(shell $(HOSTCC) -print-file-name=plugin)
#CFLAGS += -I$(GCCPLUGINS_DIR)/include -fPIC -O2 -Wall -W

HOST_EXTRACFLAGS += -I$(GCCPLUGINS_DIR)/include

hostlibs-y := pax_plugin.so
always := $(hostlibs-y)
pax_plugin-objs := pax_plugin.o

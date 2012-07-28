#CC := gcc
#PLUGIN_SOURCE_FILES := pax_plugin.c
#PLUGIN_OBJECT_FILES := $(patsubst %.c,%.o,$(PLUGIN_SOURCE_FILES))
GCCPLUGINS_DIR := $(shell $(CC) -print-file-name=plugin)
#CFLAGS += -I$(GCCPLUGINS_DIR)/include -fPIC -O2 -Wall -W -std=gnu99

ifeq ($(PLUGINCC),$(HOSTCC))
HOSTLIBS := hostlibs
HOST_EXTRACFLAGS += -I$(GCCPLUGINS_DIR)/include -I$(GCCPLUGINS_DIR)/include/c-family -std=gnu99 -ggdb
else
HOSTLIBS := hostcxxlibs
HOST_EXTRACXXFLAGS += -I$(GCCPLUGINS_DIR)/include -I$(GCCPLUGINS_DIR)/include/c-family -std=gnu++98 -ggdb -Wno-unused-parameter
endif

$(HOSTLIBS)-y := constify_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_MEMORY_STACKLEAK) += stackleak_plugin.so
$(HOSTLIBS)-$(CONFIG_KALLOCSTAT_PLUGIN) += kallocstat_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_KERNEXEC_PLUGIN) += kernexec_plugin.so
$(HOSTLIBS)-$(CONFIG_CHECKER_PLUGIN) += checker_plugin.so
$(HOSTLIBS)-y += colorize_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_SIZE_OVERFLOW) += size_overflow_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_LATENT_ENTROPY) += latent_entropy_plugin.so

always := $($(HOSTLIBS)-y)

constify_plugin-objs := constify_plugin.o
stackleak_plugin-objs := stackleak_plugin.o
kallocstat_plugin-objs := kallocstat_plugin.o
kernexec_plugin-objs := kernexec_plugin.o
checker_plugin-objs := checker_plugin.o
colorize_plugin-objs := colorize_plugin.o
size_overflow_plugin-objs := size_overflow_plugin.o
latent_entropy_plugin-objs := latent_entropy_plugin.o

$(obj)/size_overflow_plugin.o: $(objtree)/$(obj)/size_overflow_hash.h

quiet_cmd_build_size_overflow_hash = GENHASH  $@
      cmd_build_size_overflow_hash = \
	$(CONFIG_SHELL) $(srctree)/$(src)/generate_size_overflow_hash.sh -d $< -o $@
$(objtree)/$(obj)/size_overflow_hash.h: $(src)/size_overflow_hash.data FORCE
	$(call if_changed,build_size_overflow_hash)

targets += size_overflow_hash.h

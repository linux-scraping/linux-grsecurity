#CC := gcc
#PLUGIN_SOURCE_FILES := pax_plugin.c
#PLUGIN_OBJECT_FILES := $(patsubst %.c,%.o,$(PLUGIN_SOURCE_FILES))
GCCPLUGINS_DIR := $(shell $(CC) -print-file-name=plugin)
#CFLAGS += -I$(GCCPLUGINS_DIR)/include -fPIC -O2 -Wall -W -std=gnu99

ifeq ($(PLUGINCC),$(HOSTCC))
HOSTLIBS := hostlibs
HOST_EXTRACFLAGS += -I$(GCCPLUGINS_DIR)/include -I$(src) -std=gnu99 -ggdb
export HOST_EXTRACFLAGS
else
HOSTLIBS := hostcxxlibs
HOST_EXTRACXXFLAGS += -I$(GCCPLUGINS_DIR)/include -I$(src) -std=gnu++98 -fno-rtti -fno-exceptions -fasynchronous-unwind-tables -ggdb -Wno-unused-parameter -Wno-narrowing -Wno-unused-variable
export HOST_EXTRACXXFLAGS
endif

export GCCPLUGINS_DIR HOSTLIBS

$(HOSTLIBS)-$(CONFIG_PAX_CONSTIFY_PLUGIN) := constify_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_MEMORY_STACKLEAK) += stackleak_plugin.so
$(HOSTLIBS)-$(CONFIG_KALLOCSTAT_PLUGIN) += kallocstat_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_KERNEXEC_PLUGIN) += kernexec_plugin.so
$(HOSTLIBS)-$(CONFIG_CHECKER_PLUGIN) += checker_plugin.so
$(HOSTLIBS)-y += colorize_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_LATENT_ENTROPY) += latent_entropy_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_MEMORY_STRUCTLEAK) += structleak_plugin.so
$(HOSTLIBS)-y += initify_plugin.so
$(HOSTLIBS)-$(CONFIG_GRKERNSEC_RANDSTRUCT) += randomize_layout_plugin.so

subdir-$(CONFIG_PAX_SIZE_OVERFLOW) := size_overflow_plugin
subdir- += size_overflow_plugin

always := $($(HOSTLIBS)-y)

constify_plugin-objs := constify_plugin.o
stackleak_plugin-objs := stackleak_plugin.o
kallocstat_plugin-objs := kallocstat_plugin.o
kernexec_plugin-objs := kernexec_plugin.o
checker_plugin-objs := checker_plugin.o
colorize_plugin-objs := colorize_plugin.o
latent_entropy_plugin-objs := latent_entropy_plugin.o
structleak_plugin-objs := structleak_plugin.o
initify_plugin-objs := initify_plugin.o
randomize_layout_plugin-objs := randomize_layout_plugin.o

$(obj)/randomize_layout_plugin.o: $(objtree)/$(obj)/randomize_layout_seed.h

quiet_cmd_create_randomize_layout_seed = GENSEED  $@
      cmd_create_randomize_layout_seed = \
	$(CONFIG_SHELL) $(srctree)/$(src)/gen-random-seed.sh $@ $(objtree)/include/generated/randomize_layout_hash.h
$(objtree)/$(obj)/randomize_layout_seed.h: FORCE
	$(call if_changed,create_randomize_layout_seed)

targets += randomize_layout_seed.h randomize_layout_hash.h

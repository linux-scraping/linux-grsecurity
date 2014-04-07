#CC := gcc
#PLUGIN_SOURCE_FILES := pax_plugin.c
#PLUGIN_OBJECT_FILES := $(patsubst %.c,%.o,$(PLUGIN_SOURCE_FILES))
GCCPLUGINS_DIR := $(shell $(CC) -print-file-name=plugin)
#CFLAGS += -I$(GCCPLUGINS_DIR)/include -fPIC -O2 -Wall -W -std=gnu99

ifeq ($(PLUGINCC),$(HOSTCC))
HOSTLIBS := hostlibs
HOST_EXTRACFLAGS += -I$(GCCPLUGINS_DIR)/include -std=gnu99 -ggdb
else
HOSTLIBS := hostcxxlibs
HOST_EXTRACXXFLAGS += -I$(GCCPLUGINS_DIR)/include -std=gnu++98 -fno-rtti -ggdb -Wno-unused-parameter -Wno-narrowing
endif

$(HOSTLIBS)-$(CONFIG_PAX_CONSTIFY_PLUGIN) := constify_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_MEMORY_STACKLEAK) += stackleak_plugin.so
$(HOSTLIBS)-$(CONFIG_KALLOCSTAT_PLUGIN) += kallocstat_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_KERNEXEC_PLUGIN) += kernexec_plugin.so
$(HOSTLIBS)-$(CONFIG_CHECKER_PLUGIN) += checker_plugin.so
$(HOSTLIBS)-y += colorize_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_SIZE_OVERFLOW) += size_overflow_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_LATENT_ENTROPY) += latent_entropy_plugin.so
$(HOSTLIBS)-$(CONFIG_PAX_MEMORY_STRUCTLEAK) += structleak_plugin.so
$(HOSTLIBS)-$(CONFIG_GRKERNSEC_RANDSTRUCT) += randomize_layout_plugin.so

always := $($(HOSTLIBS)-y)

constify_plugin-objs := constify_plugin.o
stackleak_plugin-objs := stackleak_plugin.o
kallocstat_plugin-objs := kallocstat_plugin.o
kernexec_plugin-objs := kernexec_plugin.o
checker_plugin-objs := checker_plugin.o
colorize_plugin-objs := colorize_plugin.o
size_overflow_plugin-objs := size_overflow_plugin.o
latent_entropy_plugin-objs := latent_entropy_plugin.o
structleak_plugin-objs := structleak_plugin.o
randomize_layout_plugin-objs := randomize_layout_plugin.o

$(obj)/size_overflow_plugin.o: $(objtree)/$(obj)/size_overflow_hash.h $(objtree)/$(obj)/size_overflow_hash_aux.h
$(obj)/randomize_layout_plugin.o: $(objtree)/$(obj)/randomize_layout_seed.h

quiet_cmd_build_size_overflow_hash = GENHASH  $@
      cmd_build_size_overflow_hash = \
	$(CONFIG_SHELL) $(srctree)/$(src)/generate_size_overflow_hash.sh -s size_overflow_hash -d $< -o $@
$(objtree)/$(obj)/size_overflow_hash.h: $(src)/size_overflow_hash.data FORCE
	$(call if_changed,build_size_overflow_hash)

quiet_cmd_build_size_overflow_hash_aux = GENHASH  $@
      cmd_build_size_overflow_hash_aux = \
	$(CONFIG_SHELL) $(srctree)/$(src)/generate_size_overflow_hash.sh -s size_overflow_hash_aux -d $< -o $@
$(objtree)/$(obj)/size_overflow_hash_aux.h: $(src)/size_overflow_hash_aux.data FORCE
	$(call if_changed,build_size_overflow_hash_aux)

quiet_cmd_create_randomize_layout_seed = GENSEED  $@
      cmd_create_randomize_layout_seed = \
	$(CONFIG_SHELL) $(srctree)/$(src)/gen-random-seed.sh $@ $(objtree)/include/generated/randomize_layout_hash.h
$(objtree)/$(obj)/randomize_layout_seed.h: FORCE
	$(call if_changed,create_randomize_layout_seed)

targets += size_overflow_hash.h size_overflow_hash_aux.h randomize_layout_seed.h randomize_layout_hash.h

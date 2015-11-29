HOST_EXTRACXXFLAGS += $(call hostcc-option, -fno-ipa-icf)

$(HOSTLIBS)-$(CONFIG_PAX_SIZE_OVERFLOW) += size_overflow_plugin.so
always := $($(HOSTLIBS)-y)

size_overflow_plugin-objs := $(patsubst $(srctree)/$(src)/%.c,%.o,$(wildcard $(srctree)/$(src)/*.c))

$(patsubst $(srctree)/$(src)/%.c,$(obj)/%.o,$(wildcard $(srctree)/$(src)/*.c)): $(objtree)/$(obj)/size_overflow_hash.h $(objtree)/$(obj)/size_overflow_hash_aux.h $(objtree)/$(obj)/disable_size_overflow_hash.h

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

quiet_cmd_build_disable_size_overflow_hash = GENHASH  $@
      cmd_build_disable_size_overflow_hash = \
	$(CONFIG_SHELL) $(srctree)/$(src)/generate_size_overflow_hash.sh -s disable_size_overflow_hash -d $< -o $@
$(objtree)/$(obj)/disable_size_overflow_hash.h: $(src)/disable_size_overflow_hash.data FORCE
	$(call if_changed,build_disable_size_overflow_hash)

targets += size_overflow_hash.h size_overflow_hash_aux.h disable_size_overflow_hash.h

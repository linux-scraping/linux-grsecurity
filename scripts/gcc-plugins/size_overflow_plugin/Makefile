HOST_EXTRACXXFLAGS += $(call hostcc-option, -fno-ipa-icf)

$(HOSTLIBS)-$(CONFIG_PAX_SIZE_OVERFLOW) += size_overflow_plugin.so
always := $($(HOSTLIBS)-y)

targets +=	$(objtree)/$(obj)/e_fns.h \
		$(objtree)/$(obj)/e_fields.h \
		$(objtree)/$(obj)/e_fptrs.h \
		$(objtree)/$(obj)/e_vars.h \
		$(objtree)/$(obj)/e_aux.h \
		$(objtree)/$(obj)/disable.h

$(srctree)/$(src)/size_overflow_plugin_hash.c: $(objtree)/$(obj)/e_fns.h \
					       $(objtree)/$(obj)/e_fields.h \
					       $(objtree)/$(obj)/e_fptrs.h \
					       $(objtree)/$(obj)/e_vars.h \
					       $(objtree)/$(obj)/e_aux.h \
					       $(objtree)/$(obj)/disable.h

size_overflow_plugin-objs := $(patsubst $(srctree)/$(src)/%.c,%.o,$(wildcard $(srctree)/$(src)/*.c))

quiet_cmd_build_size_overflow_hash = GENHASH  $@
      cmd_build_size_overflow_hash = \
	$(CONFIG_SHELL) $(srctree)/$(src)/generate_size_overflow_hash.sh -s $(patsubst e_%,%,$(patsubst $(obj)/%.h,%,$@))_hash -d $< -o $@

$(objtree)/$(obj)/e_fns.h: $(srctree)/$(src)/e_fns.data
	$(call if_changed,build_size_overflow_hash)
$(objtree)/$(obj)/e_fields.h: $(srctree)/$(src)/e_fields.data
	$(call if_changed,build_size_overflow_hash)
$(objtree)/$(obj)/e_fptrs.h: $(srctree)/$(src)/e_fptrs.data
	$(call if_changed,build_size_overflow_hash)
$(objtree)/$(obj)/e_vars.h: $(srctree)/$(src)/e_vars.data
	$(call if_changed,build_size_overflow_hash)
$(objtree)/$(obj)/e_aux.h: $(srctree)/$(src)/e_aux.data
	$(call if_changed,build_size_overflow_hash)
$(objtree)/$(obj)/disable.h: $(srctree)/$(src)/disable.data
	$(call if_changed,build_size_overflow_hash)

clean-files += *.so

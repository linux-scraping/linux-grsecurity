/*
 * Copyright 2011 by the PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Note: the choice of the license means that the compilation process is
 *       NOT 'eligible' as defined by gcc's library exception to the GPL v3,
 *       but for the kernel it doesn't matter since it doesn't link against
 *       any of the gcc libraries
 *
 * gcc plugin to implement various sparse (source code checker) features
 *
 * TODO:
 * - define separate __iomem, __percpu and __rcu address spaces (lots of code to patch)
 *
 * BUGS:
 * - none known
 */
#include "gcc-plugin.h"
#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tree.h"
#include "tree-pass.h"
#include "flags.h"
#include "intl.h"
#include "toplev.h"
#include "plugin.h"
//#include "expr.h" where are you...
#include "diagnostic.h"
#include "plugin-version.h"
#include "tm.h"
#include "function.h"
#include "basic-block.h"
#include "gimple.h"
#include "rtl.h"
#include "emit-rtl.h"
#include "tree-flow.h"
#include "target.h"

extern void c_register_addr_space (const char *str, addr_space_t as);
extern enum machine_mode default_addr_space_pointer_mode (addr_space_t);
extern enum machine_mode default_addr_space_address_mode (addr_space_t);
extern bool default_addr_space_valid_pointer_mode(enum machine_mode mode, addr_space_t as);
extern bool default_addr_space_legitimate_address_p(enum machine_mode mode, rtx mem, bool strict, addr_space_t as);
extern rtx default_addr_space_legitimize_address(rtx x, rtx oldx, enum machine_mode mode, addr_space_t as);

extern void print_gimple_stmt(FILE *, gimple, int, int);
extern rtx emit_move_insn(rtx x, rtx y);

int plugin_is_GPL_compatible;

static struct plugin_info checker_plugin_info = {
	.version	= "201111150100",
};

#define ADDR_SPACE_KERNEL		0
#define ADDR_SPACE_FORCE_KERNEL		1
#define ADDR_SPACE_USER			2
#define ADDR_SPACE_FORCE_USER		3
#define ADDR_SPACE_IOMEM		0
#define ADDR_SPACE_FORCE_IOMEM		0
#define ADDR_SPACE_PERCPU		0
#define ADDR_SPACE_FORCE_PERCPU		0
#define ADDR_SPACE_RCU			0
#define ADDR_SPACE_FORCE_RCU		0

static enum machine_mode checker_addr_space_pointer_mode(addr_space_t addrspace)
{
	return default_addr_space_pointer_mode(ADDR_SPACE_GENERIC);
}

static enum machine_mode checker_addr_space_address_mode(addr_space_t addrspace)
{
	return default_addr_space_address_mode(ADDR_SPACE_GENERIC);
}

static bool checker_addr_space_valid_pointer_mode(enum machine_mode mode, addr_space_t as)
{
	return default_addr_space_valid_pointer_mode(mode, as);
}

static bool checker_addr_space_legitimate_address_p(enum machine_mode mode, rtx mem, bool strict, addr_space_t as)
{
	return default_addr_space_legitimate_address_p(mode, mem, strict, ADDR_SPACE_GENERIC);
}

static rtx checker_addr_space_legitimize_address(rtx x, rtx oldx, enum machine_mode mode, addr_space_t as)
{
	return default_addr_space_legitimize_address(x, oldx, mode, as);
}

static bool checker_addr_space_subset_p(addr_space_t subset, addr_space_t superset)
{
	if (subset == ADDR_SPACE_FORCE_KERNEL && superset == ADDR_SPACE_KERNEL)
		return true;

	if (subset == ADDR_SPACE_FORCE_USER && superset == ADDR_SPACE_USER)
		return true;

	if (subset == ADDR_SPACE_FORCE_IOMEM && superset == ADDR_SPACE_IOMEM)
		return true;

	if (subset == ADDR_SPACE_KERNEL && superset == ADDR_SPACE_FORCE_USER)
		return true;

	if (subset == ADDR_SPACE_KERNEL && superset == ADDR_SPACE_FORCE_IOMEM)
		return true;

	if (subset == ADDR_SPACE_USER && superset == ADDR_SPACE_FORCE_KERNEL)
		return true;

	if (subset == ADDR_SPACE_IOMEM && superset == ADDR_SPACE_FORCE_KERNEL)
		return true;

	return subset == superset;
}

static rtx checker_addr_space_convert(rtx op, tree from_type, tree to_type)
{
//	addr_space_t from_as = TYPE_ADDR_SPACE(TREE_TYPE(from_type));
//	addr_space_t to_as = TYPE_ADDR_SPACE(TREE_TYPE(to_type));

	return op;
}

static void register_checker_address_spaces(void *event_data, void *data)
{
	c_register_addr_space("__kernel", ADDR_SPACE_KERNEL);
	c_register_addr_space("__force_kernel", ADDR_SPACE_FORCE_KERNEL);
	c_register_addr_space("__user", ADDR_SPACE_USER);
	c_register_addr_space("__force_user", ADDR_SPACE_FORCE_USER);
//	c_register_addr_space("__iomem", ADDR_SPACE_IOMEM);
//	c_register_addr_space("__force_iomem", ADDR_SPACE_FORCE_IOMEM);
//	c_register_addr_space("__percpu", ADDR_SPACE_PERCPU);
//	c_register_addr_space("__force_percpu", ADDR_SPACE_FORCE_PERCPU);
//	c_register_addr_space("__rcu", ADDR_SPACE_RCU);
//	c_register_addr_space("__force_rcu", ADDR_SPACE_FORCE_RCU);

	targetm.addr_space.pointer_mode		= checker_addr_space_pointer_mode;
	targetm.addr_space.address_mode		= checker_addr_space_address_mode;
	targetm.addr_space.valid_pointer_mode	= checker_addr_space_valid_pointer_mode;
	targetm.addr_space.legitimate_address_p	= checker_addr_space_legitimate_address_p;
//	targetm.addr_space.legitimize_address	= checker_addr_space_legitimize_address;
	targetm.addr_space.subset_p		= checker_addr_space_subset_p;
	targetm.addr_space.convert		= checker_addr_space_convert;
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	int i;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &checker_plugin_info);

	for (i = 0; i < argc; ++i)
		error(G_("unkown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);

	if (TARGET_64BIT == 0)
		return 0;

	register_callback(plugin_name, PLUGIN_PRAGMAS, register_checker_address_spaces, NULL);

	return 0;
}

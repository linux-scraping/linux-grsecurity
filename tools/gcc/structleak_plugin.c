/*
 * Copyright 2013-2014 by PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Note: the choice of the license means that the compilation process is
 *       NOT 'eligible' as defined by gcc's library exception to the GPL v3,
 *       but for the kernel it doesn't matter since it doesn't link against
 *       any of the gcc libraries
 *
 * gcc plugin to forcibly initialize certain local variables that could
 * otherwise leak kernel stack to userland if they aren't properly initialized
 * by later code
 *
 * Homepage: http://pax.grsecurity.net/
 *
 * Usage:
 * $ # for 4.5/4.6/C based 4.7
 * $ gcc -I`gcc -print-file-name=plugin`/include -I`gcc -print-file-name=plugin`/include/c-family -fPIC -shared -O2 -o structleak_plugin.so structleak_plugin.c
 * $ # for C++ based 4.7/4.8+
 * $ g++ -I`g++ -print-file-name=plugin`/include -I`g++ -print-file-name=plugin`/include/c-family -fPIC -shared -O2 -o structleak_plugin.so structleak_plugin.c
 * $ gcc -fplugin=./structleak_plugin.so test.c -O2
 *
 * TODO: eliminate redundant initializers
 *       increase type coverage
 */

#include "gcc-common.h"

// unused C type flag in all versions 4.5-4.9
#define TYPE_USERSPACE(TYPE) TYPE_LANG_FLAG_3(TYPE)

int plugin_is_GPL_compatible;

static struct plugin_info structleak_plugin_info = {
	.version	= "201401260140",
	.help		= "disable\tdo not activate plugin\n",
};

static tree handle_user_attribute(tree *node, tree name, tree args, int flags, bool *no_add_attrs)
{
	*no_add_attrs = true;

	// check for types? for now accept everything linux has to offer
	if (TREE_CODE(*node) != FIELD_DECL)
		return NULL_TREE;

	*no_add_attrs = false;
	return NULL_TREE;
}

static struct attribute_spec user_attr = {
	.name			= "user",
	.min_length		= 0,
	.max_length		= 0,
	.decl_required		= false,
	.type_required		= false,
	.function_type_required	= false,
	.handler		= handle_user_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity	= true
#endif
};

static void register_attributes(void *event_data, void *data)
{
	register_attribute(&user_attr);
//	register_attribute(&force_attr);
}

static tree get_field_type(tree field)
{
	return strip_array_types(TREE_TYPE(field));
}

static bool is_userspace_type(tree type)
{
	tree field;

	for (field = TYPE_FIELDS(type); field; field = TREE_CHAIN(field)) {
		tree fieldtype = get_field_type(field);
		enum tree_code code = TREE_CODE(fieldtype);

		if (code == RECORD_TYPE || code == UNION_TYPE)
			if (is_userspace_type(fieldtype))
				return true;

		if (lookup_attribute("user", DECL_ATTRIBUTES(field)))
			return true;
	}
	return false;
}

static void finish_type(void *event_data, void *data)
{
	tree type = (tree)event_data;

	if (TYPE_USERSPACE(type))
		return;

	if (is_userspace_type(type))
		TYPE_USERSPACE(type) = 1;
}

static void initialize(tree var)
{
	basic_block bb;
	gimple_stmt_iterator gsi;
	tree initializer;
	gimple init_stmt;

	// this is the original entry bb before the forced split
	// TODO: check further BBs in case more splits occured before us
	bb = ENTRY_BLOCK_PTR_FOR_FN(cfun)->next_bb->next_bb;

	// first check if the variable is already initialized, warn otherwise
	for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
		gimple stmt = gsi_stmt(gsi);
		tree rhs1;

		// we're looking for an assignment of a single rhs...
		if (!gimple_assign_single_p(stmt))
			continue;
		rhs1 = gimple_assign_rhs1(stmt);
#if BUILDING_GCC_VERSION >= 4007
		// ... of a non-clobbering expression...
		if (TREE_CLOBBER_P(rhs1))
			continue;
#endif
		// ... to our variable...
		if (gimple_get_lhs(stmt) != var)
			continue;
		// if it's an initializer then we're good
		if (TREE_CODE(rhs1) == CONSTRUCTOR)
			return;
	}

	// these aren't the 0days you're looking for
//	inform(DECL_SOURCE_LOCATION(var), "userspace variable will be forcibly initialized");

	// build the initializer expression
	initializer = build_constructor(TREE_TYPE(var), NULL);

	// build the initializer stmt
	init_stmt = gimple_build_assign(var, initializer);
	gsi = gsi_start_bb(ENTRY_BLOCK_PTR_FOR_FN(cfun)->next_bb);
	gsi_insert_before(&gsi, init_stmt, GSI_NEW_STMT);
	update_stmt(init_stmt);
}

static unsigned int handle_function(void)
{
	basic_block bb;
	unsigned int ret = 0;
	tree var;
	unsigned int i;

	// split the first bb where we can put the forced initializers
	bb = split_block_after_labels(ENTRY_BLOCK_PTR_FOR_FN(cfun))->dest;
	if (dom_info_available_p(CDI_DOMINATORS))
		set_immediate_dominator(CDI_DOMINATORS, bb, ENTRY_BLOCK_PTR_FOR_FN(cfun));

	// enumarate all local variables and forcibly initialize our targets
	FOR_EACH_LOCAL_DECL(cfun, i, var) {
		tree type = TREE_TYPE(var);

		gcc_assert(DECL_P(var));
		if (!auto_var_in_fn_p(var, current_function_decl))
			continue;

		// only care about structure types
		if (TREE_CODE(type) != RECORD_TYPE && TREE_CODE(type) != UNION_TYPE)
			continue;

		// if the type is of interest, examine the variable
		if (TYPE_USERSPACE(type))
			initialize(var);
	}

	return ret;
}

#if BUILDING_GCC_VERSION >= 4009
static const struct pass_data structleak_pass_data = {
#else
static struct gimple_opt_pass structleak_pass = {
	.pass = {
#endif
		.type			= GIMPLE_PASS,
		.name			= "structleak",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 4009
		.has_gate		= false,
		.has_execute		= true,
#else
		.gate			= NULL,
		.execute		= handle_function,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
#endif
		.tv_id			= TV_NONE,
		.properties_required	= PROP_cfg,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_remove_unused_locals | TODO_update_ssa | TODO_ggc_collect | TODO_verify_flow
#if BUILDING_GCC_VERSION < 4009
	}
#endif
};

#if BUILDING_GCC_VERSION >= 4009
namespace {
class structleak_pass : public gimple_opt_pass {
public:
	structleak_pass() : gimple_opt_pass(structleak_pass_data, g) {}
	unsigned int execute() { return handle_function(); }
};
}

static opt_pass *make_structleak_pass(void)
{
	return new structleak_pass();
}
#else
static struct opt_pass *make_structleak_pass(void)
{
	return &structleak_pass.pass;
}
#endif

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	int i;
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	bool enable = true;
	struct register_pass_info structleak_pass_info;

	structleak_pass_info.pass			= make_structleak_pass();
	structleak_pass_info.reference_pass_name	= "ssa";
	structleak_pass_info.ref_pass_instance_number	= 1;
	structleak_pass_info.pos_op			= PASS_POS_INSERT_AFTER;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	if (strcmp(lang_hooks.name, "GNU C")) {
		inform(UNKNOWN_LOCATION, G_("%s supports C only"), plugin_name);
		enable = false;
	}

	for (i = 0; i < argc; ++i) {
		if (!strcmp(argv[i].key, "disable")) {
			enable = false;
			continue;
		}
		error(G_("unkown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &structleak_plugin_info);
	if (enable) {
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &structleak_pass_info);
		register_callback(plugin_name, PLUGIN_FINISH_TYPE, finish_type, NULL);
	}
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	return 0;
}

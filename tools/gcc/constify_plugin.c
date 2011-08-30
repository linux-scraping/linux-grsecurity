/*
 * Copyright 2011 by Emese Revfy <re.emese@gmail.com>
 * Copyright 2011 by PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2, or (at your option) v3
 *
 * This gcc plugin constifies all structures which contain only function pointers or are explicitly marked for constification.
 *
 * Homepage:
 * http://www.grsecurity.net/~ephox/const_plugin/
 *
 * Usage:
 * $ gcc -I`gcc -print-file-name=plugin`/include -fPIC -shared -O2 -o constify_plugin.so constify_plugin.c
 * $ gcc -fplugin=constify_plugin.so test.c -O2
 */

#include "gcc-plugin.h"
#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tree.h"
#include "tree-pass.h"
#include "intl.h"
#include "plugin-version.h"
#include "tm.h"
#include "toplev.h"
#include "function.h"
#include "tree-flow.h"
#include "plugin.h"
#include "diagnostic.h"
//#include "c-tree.h"

#define C_TYPE_FIELDS_READONLY(TYPE) TREE_LANG_FLAG_1(TYPE)

int plugin_is_GPL_compatible;

static struct plugin_info const_plugin_info = {
	.version	= "20110826",
	.help		= "no-constify\tturn off constification\n",
};

static void constify_type(tree type);
static bool walk_struct(tree node);

static tree deconstify_type(tree old_type)
{
	tree new_type, field;

	new_type = build_qualified_type(old_type, TYPE_QUALS(old_type) & ~TYPE_QUAL_CONST);
	TYPE_FIELDS(new_type) = copy_list(TYPE_FIELDS(new_type));
	for (field = TYPE_FIELDS(new_type); field; field = TREE_CHAIN(field))
		DECL_FIELD_CONTEXT(field) = new_type;
	TYPE_READONLY(new_type) = 0;
	C_TYPE_FIELDS_READONLY(new_type) = 0;
	return new_type;
}

static tree handle_no_const_attribute(tree *node, tree name, tree args, int flags, bool *no_add_attrs)
{
	tree type;

	*no_add_attrs = true;
	if (TREE_CODE(*node) == FUNCTION_DECL) {
		error("%qE attribute does not apply to functions", name);
		return NULL_TREE;
	}

	if (TREE_CODE(*node) == VAR_DECL) {
		error("%qE attribute does not apply to variables", name);
		return NULL_TREE;
	}

	if (TYPE_P(*node)) {
		if (TREE_CODE(*node) == RECORD_TYPE || TREE_CODE(*node) == UNION_TYPE)
			*no_add_attrs = false;
		else
			error("%qE attribute applies to struct and union types only", name);
		return NULL_TREE;
	}

	type = TREE_TYPE(*node);

	if (TREE_CODE(type) != RECORD_TYPE && TREE_CODE(type) != UNION_TYPE) {
		error("%qE attribute applies to struct and union types only", name);
		return NULL_TREE;
	}

	if (lookup_attribute(IDENTIFIER_POINTER(name), TYPE_ATTRIBUTES(type))) {
		error("%qE attribute is already applied to the type", name);
		return NULL_TREE;
	}

	if (TREE_CODE(*node) == TYPE_DECL && !TYPE_READONLY(type)) {
		error("%qE attribute used on type that is not constified", name);
		return NULL_TREE;
	}

	if (TREE_CODE(*node) == TYPE_DECL) {
		TREE_TYPE(*node) = deconstify_type(type);
		TREE_READONLY(*node) = 0;
		return NULL_TREE;
	}

	return NULL_TREE;
}

static tree handle_do_const_attribute(tree *node, tree name, tree args, int flags, bool *no_add_attrs)
{
	*no_add_attrs = true;
	if (!TYPE_P(*node)) {
		error("%qE attribute applies to types only", name);
		return NULL_TREE;
	}

	if (TREE_CODE(*node) != RECORD_TYPE && TREE_CODE(*node) != UNION_TYPE) {
		error("%qE attribute applies to struct and union types only", name);
		return NULL_TREE;
	}

	*no_add_attrs = false;
	constify_type(*node);
	return NULL_TREE;
}

static struct attribute_spec no_const_attr = {
	.name			= "no_const",
	.min_length		= 0,
	.max_length		= 0,
	.decl_required		= false,
	.type_required		= false,
	.function_type_required	= false,
	.handler		= handle_no_const_attribute
};

static struct attribute_spec do_const_attr = {
	.name			= "do_const",
	.min_length		= 0,
	.max_length		= 0,
	.decl_required		= false,
	.type_required		= false,
	.function_type_required	= false,
	.handler		= handle_do_const_attribute
};

static void register_attributes(void *event_data, void *data)
{
	register_attribute(&no_const_attr);
	register_attribute(&do_const_attr);
}

static void constify_type(tree type)
{
	TYPE_READONLY(type) = 1;
	C_TYPE_FIELDS_READONLY(type) = 1;
}

static bool is_fptr(tree field)
{
	tree ptr = TREE_TYPE(field);

	if (TREE_CODE(ptr) != POINTER_TYPE)
		return false;

	return TREE_CODE(TREE_TYPE(ptr)) == FUNCTION_TYPE;
}

static bool walk_struct(tree node)
{
	tree field;

	if (lookup_attribute("no_const", TYPE_ATTRIBUTES(node)))
		return false;

	if (TYPE_FIELDS(node) == NULL_TREE)
		return false;

	for (field = TYPE_FIELDS(node); field; field = TREE_CHAIN(field)) {
		tree type = TREE_TYPE(field);
		enum tree_code code = TREE_CODE(type);
		if (code == RECORD_TYPE || code == UNION_TYPE) {
			if (!(walk_struct(type)))
				return false;
		} else if (!is_fptr(field) && !TREE_READONLY(field))
			return false;
	}
	return true;
}

static void finish_type(void *event_data, void *data)
{
	tree type = (tree)event_data;

	if (type == NULL_TREE)
		return;

	if (TYPE_READONLY(type))
		return;

	if (walk_struct(type))
		constify_type(type);
}

static unsigned int check_local_variables(void);

struct gimple_opt_pass pass_local_variable = {
	{
		.type			= GIMPLE_PASS,
		.name			= "check_local_variables",
		.gate			= NULL,
		.execute		= check_local_variables,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
		.tv_id			= TV_NONE,
		.properties_required	= 0,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= 0
	}
};

static unsigned int check_local_variables(void)
{
	tree var;
	referenced_var_iterator rvi;

#if __GNUC__ == 4 && __GNUC_MINOR__ == 5
	FOR_EACH_REFERENCED_VAR(var, rvi) {
#else
	FOR_EACH_REFERENCED_VAR(cfun, var, rvi) {
#endif
		tree type = TREE_TYPE(var);

		if (!DECL_P(var) || TREE_STATIC(var) || DECL_EXTERNAL(var))
			continue;

		if (TREE_CODE(type) != RECORD_TYPE && TREE_CODE(type) != UNION_TYPE)
			continue;

		if (!TYPE_READONLY(type))
			continue;

//		if (lookup_attribute("no_const", DECL_ATTRIBUTES(var)))
//			continue;

//		if (lookup_attribute("no_const", TYPE_ATTRIBUTES(type)))
//			continue;

		if (walk_struct(type)) {
			error("constified variable %qE cannot be local", var);
			return 1;
		}
	}
	return 0;
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	int i;
	bool constify = true;

	struct register_pass_info local_variable_pass_info = {
		.pass				= &pass_local_variable.pass,
		.reference_pass_name		= "*referenced_vars",
		.ref_pass_instance_number	= 0,
		.pos_op				= PASS_POS_INSERT_AFTER
	};

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	for (i = 0; i < argc; ++i) {
		if (!(strcmp(argv[i].key, "no-constify"))) {
			constify = false;
			continue;
		}
		error(G_("unkown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &const_plugin_info);
	if (constify) {
		register_callback(plugin_name, PLUGIN_FINISH_TYPE, finish_type, NULL);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &local_variable_pass_info);
	}
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	return 0;
}

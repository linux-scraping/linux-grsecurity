/*
 * Copyright 2011 by Emese Revfy <re.emese@gmail.com>
 * Licensed under the GPL v2, or (at your option) v3
 *
 * This gcc plugin constifies all structures which contain only function pointers and const fields.
 *
 * Usage:
 * $ gcc -I`gcc -print-file-name=plugin`/include -fPIC -shared -O2 -o const_plugin.so const_plugin.c
 * $ gcc -fplugin=const_plugin.so test.c  -O2
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

int plugin_is_GPL_compatible;

static struct plugin_info const_plugin_info = {
	.version	= "20110706",
	.help		= "no-constify\tturn off constification\n",
};

static tree handle_no_const_attribute(tree *node, tree name, tree args, int flags, bool *no_add_attrs)
{
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

static void register_attributes(void *event_data, void *data)
{
	register_attribute(&no_const_attr);
}

/*
static void printnode(char *prefix, tree node)
{
	enum tree_code code;
	enum tree_code_class tclass;

	tclass = TREE_CODE_CLASS(TREE_CODE (node));

	code = TREE_CODE(node);
	fprintf(stderr, "\n%s node: %p, code: %d type: %s\n", prefix, node, code, tree_code_name[(int)code]);
	if (DECL_CONTEXT(node) != NULL_TREE && TYPE_NAME(DECL_CONTEXT(node)) != NULL_TREE)
		fprintf(stderr, "struct name: %s\n", IDENTIFIER_POINTER(TYPE_NAME(DECL_CONTEXT(node))));
	if (tclass == tcc_declaration && DECL_NAME(node) != NULL_TREE)
		fprintf(stderr, "field name: %s\n", IDENTIFIER_POINTER(DECL_NAME(node)));
}
*/

static void constify_node(tree node)
{
	TREE_READONLY(node) = 1;
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

	for (field = TYPE_FIELDS(node); field; field = TREE_CHAIN(field)) {
		enum tree_code code = TREE_CODE(TREE_TYPE(field));
		if (code == RECORD_TYPE) {
			if (!(walk_struct(TREE_TYPE(field))))
				return false;
		} else if (is_fptr(field) == false && !TREE_READONLY(field))
			return false;
	}
	return true;
}

static void finish_type(void *event_data, void *data)
{
	tree node = (tree)event_data;

	if (node == NULL_TREE)
		return;

	if (lookup_attribute("no_const", TYPE_ATTRIBUTES(node)))
		return;

	if (TREE_READONLY(node))
		return;

	if (TYPE_FIELDS(node) == NULL_TREE)
		return;

	if (walk_struct(node))
		constify_node(node);
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	int i;
	bool constify = true;

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
	if (constify)
		register_callback(plugin_name, PLUGIN_FINISH_TYPE, finish_type, NULL);
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	return 0;
}

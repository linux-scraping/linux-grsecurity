/*
 * Copyright 2012 by the PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Note: the choice of the license means that the compilation process is
 *       NOT 'eligible' as defined by gcc's library exception to the GPL v3,
 *       but for the kernel it doesn't matter since it doesn't link against
 *       any of the gcc libraries
 *
 * gcc plugin to help generate a little bit of entropy from program state,
 * used during boot in the kernel
 *
 * TODO:
 * - add ipa pass to identify not explicitly marked candidate functions
 * - mix in more program state (function arguments/return values, loop variables, etc)
 * - more instrumentation control via attribute parameters
 *
 * BUGS:
 * - LTO needs -flto-partition=none for now
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

int plugin_is_GPL_compatible;

static tree latent_entropy_decl;

static struct plugin_info latent_entropy_plugin_info = {
	.version	= "201207271820",
	.help		= NULL
};

static unsigned int execute_latent_entropy(void);
static bool gate_latent_entropy(void);

static struct gimple_opt_pass latent_entropy_pass = {
	.pass = {
		.type			= GIMPLE_PASS,
		.name			= "latent_entropy",
		.gate			= gate_latent_entropy,
		.execute		= execute_latent_entropy,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
		.tv_id			= TV_NONE,
		.properties_required	= PROP_gimple_leh | PROP_cfg,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0, //TODO_verify_ssa | TODO_verify_flow | TODO_verify_stmts,
		.todo_flags_finish	= TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_update_ssa
	}
};

static tree handle_latent_entropy_attribute(tree *node, tree name, tree args, int flags, bool *no_add_attrs)
{
	if (TREE_CODE(*node) != FUNCTION_DECL) {
		*no_add_attrs = true;
		error("%qE attribute only applies to functions", name);
	}
	return NULL_TREE;
}

static struct attribute_spec latent_entropy_attr = {
	.name				= "latent_entropy",
	.min_length			= 0,
	.max_length			= 0,
	.decl_required			= true,
	.type_required			= false,
	.function_type_required		= false,
	.handler			= handle_latent_entropy_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity		= false
#endif
};

static void register_attributes(void *event_data, void *data)
{
	register_attribute(&latent_entropy_attr);
}

static bool gate_latent_entropy(void)
{
	tree latent_entropy_attr;

	latent_entropy_attr = lookup_attribute("latent_entropy", DECL_ATTRIBUTES(current_function_decl));
	return latent_entropy_attr != NULL_TREE;
}

static unsigned HOST_WIDE_INT seed;
static unsigned HOST_WIDE_INT get_random_const(void)
{
	seed = (seed >> 1U) ^ (-(seed & 1ULL) & 0xD800000000000000ULL);
	return seed;
}

static enum tree_code get_op(tree *rhs)
{
	static enum tree_code op;
	unsigned HOST_WIDE_INT random_const;

	random_const = get_random_const();

	switch (op) {
	case BIT_XOR_EXPR:
		op = PLUS_EXPR;
		break;

	case PLUS_EXPR:
		if (rhs) {
			op = LROTATE_EXPR;
			random_const &= HOST_BITS_PER_WIDE_INT - 1;
			break;
		}

	case LROTATE_EXPR:
	default:
		op = BIT_XOR_EXPR;
		break;
	}
	if (rhs)
		*rhs = build_int_cstu(unsigned_intDI_type_node, random_const);
	return op;
}

static void perturb_local_entropy(basic_block bb, tree local_entropy)
{
	gimple_stmt_iterator gsi;
	gimple assign;
	tree addxorrol, rhs;
	enum tree_code op;

	op = get_op(&rhs);
	addxorrol = fold_build2_loc(UNKNOWN_LOCATION, op, unsigned_intDI_type_node, local_entropy, rhs);
	assign = gimple_build_assign(local_entropy, addxorrol);
	find_referenced_vars_in(assign);
//debug_bb(bb);
	gsi = gsi_after_labels(bb);
	gsi_insert_before(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
}

static void perturb_latent_entropy(basic_block bb, tree rhs)
{
	gimple_stmt_iterator gsi;
	gimple assign;
	tree addxorrol, temp;

	// 1. create temporary copy of latent_entropy
	temp = create_tmp_var(unsigned_intDI_type_node, "temp_latent_entropy");
	add_referenced_var(temp);
	mark_sym_for_renaming(temp);

	// 2. read...
	assign = gimple_build_assign(temp, latent_entropy_decl);
	find_referenced_vars_in(assign);
	gsi = gsi_after_labels(bb);
	gsi_insert_after(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);

	// 3. ...modify...
	addxorrol = fold_build2_loc(UNKNOWN_LOCATION, get_op(NULL), unsigned_intDI_type_node, temp, rhs);
	assign = gimple_build_assign(temp, addxorrol);
	find_referenced_vars_in(assign);
	gsi_insert_after(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);

	// 4. ...write latent_entropy
	assign = gimple_build_assign(latent_entropy_decl, temp);
	find_referenced_vars_in(assign);
	gsi_insert_after(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
}

static unsigned int execute_latent_entropy(void)
{
	basic_block bb;
	gimple assign;
	gimple_stmt_iterator gsi;
	tree local_entropy;

	if (!latent_entropy_decl) {
		struct varpool_node *node;

		for (node = varpool_nodes; node; node = node->next) {
			tree var = node->decl;
			if (strcmp(IDENTIFIER_POINTER(DECL_NAME(var)), "latent_entropy"))
				continue;
			latent_entropy_decl = var;
//			debug_tree(var);
			break;
		}
		if (!latent_entropy_decl) {
//			debug_tree(current_function_decl);
			return 0;
		}
	}

//fprintf(stderr, "latent_entropy: %s\n", IDENTIFIER_POINTER(DECL_NAME(current_function_decl)));

	// 1. create local entropy variable
	local_entropy = create_tmp_var(unsigned_intDI_type_node, "local_entropy");
	add_referenced_var(local_entropy);
	mark_sym_for_renaming(local_entropy);

	// 2. initialize local entropy variable
	bb = split_block_after_labels(ENTRY_BLOCK_PTR)->dest;
	if (dom_info_available_p(CDI_DOMINATORS))
		set_immediate_dominator(CDI_DOMINATORS, bb, ENTRY_BLOCK_PTR);
	gsi = gsi_start_bb(bb);

	assign = gimple_build_assign(local_entropy, build_int_cstu(unsigned_intDI_type_node, get_random_const()));
//	gimple_set_location(assign, loc);
	find_referenced_vars_in(assign);
	gsi_insert_after(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
	bb = bb->next_bb;

	// 3. instrument each BB with an operation on the local entropy variable
	while (bb != EXIT_BLOCK_PTR) {
		perturb_local_entropy(bb, local_entropy);
		bb = bb->next_bb;
	};

	// 4. mix local entropy into the global entropy variable
	perturb_latent_entropy(EXIT_BLOCK_PTR->prev_bb, local_entropy);
	return 0;
}

static void start_unit_callback(void *gcc_data, void *user_data)
{
#if BUILDING_GCC_VERSION >= 4007
	seed = get_random_seed(false);
#else
	sscanf(get_random_seed(false), "%" HOST_WIDE_INT_PRINT "x", &seed);
	seed *= seed;
#endif

	if (in_lto_p)
		return;

	// extern u64 latent_entropy
	latent_entropy_decl = build_decl(UNKNOWN_LOCATION, VAR_DECL, get_identifier("latent_entropy"), unsigned_intDI_type_node);

	TREE_STATIC(latent_entropy_decl) = 1;
	TREE_PUBLIC(latent_entropy_decl) = 1;
	TREE_USED(latent_entropy_decl) = 1;
	TREE_THIS_VOLATILE(latent_entropy_decl) = 1;
	DECL_EXTERNAL(latent_entropy_decl) = 1;
	DECL_ARTIFICIAL(latent_entropy_decl) = 0;
	DECL_INITIAL(latent_entropy_decl) = NULL;
//	DECL_ASSEMBLER_NAME(latent_entropy_decl);
//	varpool_finalize_decl(latent_entropy_decl);
//	varpool_mark_needed_node(latent_entropy_decl);
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	struct register_pass_info latent_entropy_pass_info = {
		.pass				= &latent_entropy_pass.pass,
		.reference_pass_name		= "optimized",
		.ref_pass_instance_number	= 1,
		.pos_op 			= PASS_POS_INSERT_BEFORE
	};

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &latent_entropy_plugin_info);
	register_callback ("start_unit", PLUGIN_START_UNIT, &start_unit_callback, NULL);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &latent_entropy_pass_info);
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	return 0;
}

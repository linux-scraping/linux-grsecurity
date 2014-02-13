/*
 * Copyright 2012-2014 by the PaX Team <pageexec@freemail.hu>
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

#include "gcc-common.h"

int plugin_is_GPL_compatible;

static tree latent_entropy_decl;

static struct plugin_info latent_entropy_plugin_info = {
	.version	= "201402131900",
	.help		= NULL
};

static unsigned HOST_WIDE_INT seed;
static unsigned HOST_WIDE_INT get_random_const(void)
{
	seed = (seed >> 1U) ^ (-(seed & 1ULL) & 0xD800000000000000ULL);
	return seed;
}

static tree handle_latent_entropy_attribute(tree *node, tree name, tree args, int flags, bool *no_add_attrs)
{
	switch (TREE_CODE(*node)) {
	default:
		*no_add_attrs = true;
		error("%qE attribute only applies to functions and variables", name);
		break;

	case VAR_DECL:
		if (DECL_INITIAL(*node)) {
			*no_add_attrs = true;
			error("variable %qD with %qE attribute must not be initialized", *node, name);
			break;
		}
		DECL_INITIAL(*node) = build_int_cstu(long_long_unsigned_type_node, get_random_const());
		break;

	case FUNCTION_DECL:
		break;
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
	gsi = gsi_after_labels(bb);
	gsi_insert_before(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
//debug_bb(bb);
}

static void perturb_latent_entropy(basic_block bb, tree rhs)
{
	gimple_stmt_iterator gsi;
	gimple assign;
	tree addxorrol, temp;

	// 1. create temporary copy of latent_entropy
	temp = create_tmp_var(unsigned_intDI_type_node, "temp_latent_entropy");
	add_referenced_var(temp);

	// 2. read...
	temp = make_ssa_name(temp, NULL);
	assign = gimple_build_assign(temp, latent_entropy_decl);
	SSA_NAME_DEF_STMT(temp) = assign;
	add_referenced_var(latent_entropy_decl);
	gsi = gsi_after_labels(bb);
	gsi_insert_after(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);

	// 3. ...modify...
	addxorrol = fold_build2_loc(UNKNOWN_LOCATION, get_op(NULL), unsigned_intDI_type_node, temp, rhs);
	temp = make_ssa_name(SSA_NAME_VAR(temp), NULL);
	assign = gimple_build_assign(temp, addxorrol);
	SSA_NAME_DEF_STMT(temp) = assign;
	gsi_insert_after(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);

	// 4. ...write latent_entropy
	assign = gimple_build_assign(latent_entropy_decl, temp);
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

		FOR_EACH_VARIABLE(node) {
			tree var = NODE_DECL(node);

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
	bb = split_block_after_labels(ENTRY_BLOCK_PTR_FOR_FN(cfun))->dest;
	if (dom_info_available_p(CDI_DOMINATORS))
		set_immediate_dominator(CDI_DOMINATORS, bb, ENTRY_BLOCK_PTR_FOR_FN(cfun));
	gsi = gsi_start_bb(bb);

	assign = gimple_build_assign(local_entropy, build_int_cstu(unsigned_intDI_type_node, get_random_const()));
//	gimple_set_location(assign, loc);
	gsi_insert_after(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
//debug_bb(bb);
	bb = bb->next_bb;

	// 3. instrument each BB with an operation on the local entropy variable
	while (bb != EXIT_BLOCK_PTR_FOR_FN(cfun)) {
		perturb_local_entropy(bb, local_entropy);
//debug_bb(bb);
		bb = bb->next_bb;
	};

	// 4. mix local entropy into the global entropy variable
	perturb_latent_entropy(EXIT_BLOCK_PTR_FOR_FN(cfun)->prev_bb, local_entropy);
//debug_bb(EXIT_BLOCK_PTR_FOR_FN(cfun)->prev_bb);
	return 0;
}

static void latent_entropy_start_unit(void *gcc_data, void *user_data)
{
	tree latent_entropy_type;

	seed = get_random_seed(false);

	if (in_lto_p)
		return;

	// extern volatile u64 latent_entropy
	gcc_assert(TYPE_PRECISION(long_long_unsigned_type_node) == 64);
	latent_entropy_type = build_qualified_type(long_long_unsigned_type_node, TYPE_QUALS(long_long_unsigned_type_node) | TYPE_QUAL_VOLATILE);
	latent_entropy_decl = build_decl(UNKNOWN_LOCATION, VAR_DECL, get_identifier("latent_entropy"), latent_entropy_type);

	TREE_STATIC(latent_entropy_decl) = 1;
	TREE_PUBLIC(latent_entropy_decl) = 1;
	TREE_USED(latent_entropy_decl) = 1;
	TREE_THIS_VOLATILE(latent_entropy_decl) = 1;
	DECL_EXTERNAL(latent_entropy_decl) = 1;
	DECL_ARTIFICIAL(latent_entropy_decl) = 1;
	lang_hooks.decls.pushdecl(latent_entropy_decl);
//	DECL_ASSEMBLER_NAME(latent_entropy_decl);
//	varpool_finalize_decl(latent_entropy_decl);
//	varpool_mark_needed_node(latent_entropy_decl);
}

#if BUILDING_GCC_VERSION >= 4009
static const struct pass_data latent_entropy_pass_data = {
#else
static struct gimple_opt_pass latent_entropy_pass = {
	.pass = {
#endif
		.type			= GIMPLE_PASS,
		.name			= "latent_entropy",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 4009
		.has_gate		= true,
		.has_execute		= true,
#else
		.gate			= gate_latent_entropy,
		.execute		= execute_latent_entropy,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
#endif
		.tv_id			= TV_NONE,
		.properties_required	= PROP_gimple_leh | PROP_cfg,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0, //TODO_verify_ssa | TODO_verify_flow | TODO_verify_stmts,
		.todo_flags_finish	= TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_update_ssa
#if BUILDING_GCC_VERSION < 4009
	}
#endif
};

#if BUILDING_GCC_VERSION >= 4009
namespace {
class latent_entropy_pass : public gimple_opt_pass {
public:
	latent_entropy_pass() : gimple_opt_pass(latent_entropy_pass_data, g) {}
	bool gate() { return gate_latent_entropy(); }
	unsigned int execute() { return execute_latent_entropy(); }
};
}
#endif

static struct opt_pass *make_latent_entropy_pass(void)
{
#if BUILDING_GCC_VERSION >= 4009
	return new latent_entropy_pass();
#else
	return &latent_entropy_pass.pass;
#endif
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	struct register_pass_info latent_entropy_pass_info;

	latent_entropy_pass_info.pass				= make_latent_entropy_pass();
	latent_entropy_pass_info.reference_pass_name		= "optimized";
	latent_entropy_pass_info.ref_pass_instance_number	= 1;
	latent_entropy_pass_info.pos_op 			= PASS_POS_INSERT_BEFORE;
	static const struct ggc_root_tab gt_ggc_r_gt_latent_entropy[] = {
		{
			.base = &latent_entropy_decl,
			.nelt = 1,
			.stride = sizeof(latent_entropy_decl),
			.cb = &gt_ggc_mx_tree_node,
			.pchw = &gt_pch_nx_tree_node
		},
		LAST_GGC_ROOT_TAB
	};

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &latent_entropy_plugin_info);
	register_callback(plugin_name, PLUGIN_START_UNIT, &latent_entropy_start_unit, NULL);
	if (!in_lto_p)
		register_callback(plugin_name, PLUGIN_REGISTER_GGC_ROOTS, NULL, (void *)&gt_ggc_r_gt_latent_entropy);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &latent_entropy_pass_info);
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	return 0;
}

/*
 * Copyright 2011-2015 by Emese Revfy <re.emese@gmail.com>
 * Licensed under the GPL v2, or (at your option) v3
 *
 * Homepage:
 * https://github.com/ephox-gcc-plugins/initify
 *
 * Move string constants (__func__ and function string arguments marked by the nocapture attribute)
 * only referenced in __init/__exit functions to __initconst/__exitconst sections.
 *
 * Usage:
 * $ make
 * $ make run
 */

#include "gcc-common.h"

int plugin_is_GPL_compatible;

static struct plugin_info initify_plugin_info = {
	.version	= "20151209",
	.help		= "initify_plugin\n",
};

/* nocapture attribute:
 *  * to mark nocapture function arguments. If used on a vararg argument it applies to all of them
 *    that have no other uses.
 *  * attribute value 0 is ignored to allow reusing print attribute arguments
 */
static tree handle_nocapture_attribute(tree *node, tree __unused name, tree args, int __unused flags, bool *no_add_attrs)
{
	tree orig_attr, arg;

	*no_add_attrs = true;
	switch (TREE_CODE(*node)) {
	case FUNCTION_DECL:
	case FUNCTION_TYPE:
	case METHOD_TYPE:
		break;
	case TYPE_DECL: {
		const_tree fntype = TREE_TYPE(*node);

		if (TREE_CODE(fntype) == POINTER_TYPE)
			fntype = TREE_TYPE(fntype);
		if (TREE_CODE(fntype) == FUNCTION_TYPE || TREE_CODE(fntype) == METHOD_TYPE)
			break;
		// FALLTHROUGH
	}
	default:
		debug_tree(*node);
		error("%s: %qE attribute only applies to functions", __func__, name);
		return NULL_TREE;
	}

	for (arg = args; arg; arg = TREE_CHAIN(arg)) {
		tree position = TREE_VALUE(arg);

		if (TREE_CODE(position) != INTEGER_CST) {
			error("%qE parameter of the %qE attribute isn't an integer (fn: %qE)", position, name, *node);
			return NULL_TREE;
		}

		if (tree_int_cst_lt(position, integer_minus_one_node)) {
			error("%qE parameter of the %qE attribute less than 0 (fn: %qE)", position, name, *node);
			return NULL_TREE;
		}
	}

	orig_attr = lookup_attribute("nocapture", DECL_ATTRIBUTES(*node));
	if (orig_attr)
		chainon(TREE_VALUE(orig_attr), args);
	else
		*no_add_attrs = false;

	return NULL_TREE;
}

static struct attribute_spec nocapture_attr = {
	.name				= "nocapture",
	.min_length			= 1,
	.max_length			= -1,
	.decl_required			= true,
	.type_required			= false,
	.function_type_required		= false,
	.handler			= handle_nocapture_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity		= false
#endif
};

static void register_attributes(void __unused *event_data, void __unused *data)
{
	register_attribute(&nocapture_attr);
}

static const char *get_init_exit_section(const_tree decl)
{
	const_tree section;
	tree attr_value;

	section = lookup_attribute("section", DECL_ATTRIBUTES(decl));
	if (!section)
		return NULL;

	gcc_assert(TREE_VALUE(section));
	for (attr_value = TREE_VALUE(section); attr_value; attr_value = TREE_CHAIN(attr_value)) {
		const char *str = TREE_STRING_POINTER(TREE_VALUE(attr_value));

		if (!strncmp(str, ".init.", 6))
			return str;
		if (!strncmp(str, ".exit.", 6))
			return str;
	}

	return NULL;
}

static tree get_string_cst(tree var)
{
	if (var == NULL_TREE)
		return NULL_TREE;

	if (TREE_CODE(var) == STRING_CST)
		return var;

	switch (TREE_CODE_CLASS(TREE_CODE(var))) {
	case tcc_expression:
	case tcc_reference: {
		int i;

		for (i = 0; i < TREE_OPERAND_LENGTH(var); i++) {
			tree ret = get_string_cst(TREE_OPERAND(var, i));
			if (ret != NULL_TREE)
				return ret;
		}
		break;
	}
	default:
		break;
	}
	return NULL_TREE;
}

static bool set_init_exit_section(tree decl, bool initexit)
{
	const char *str;

	gcc_assert(DECL_P(decl));

	str = get_init_exit_section(decl);
	if (str)
		return false;

	if (initexit)
		set_decl_section_name(decl, ".init.rodata.str");
	else
		set_decl_section_name(decl, ".exit.rodata.str");
	return true;
}

static bool is_syscall(const_tree fn)
{
	if (!strncmp(DECL_NAME_POINTER(fn), "sys_", 4))
		return true;

	if (!strncmp(DECL_NAME_POINTER(fn), "sys32_", 6))
		return true;

	if (!strncmp(DECL_NAME_POINTER(fn), "compat_sys_", 11))
		return true;

	return false;
}

static bool is_nocapture_param(const gcall *stmt, int fn_arg_count)
{
	const_tree attr, attr_val;
	int fntype_arg_len;
	const_tree fndecl = gimple_call_fndecl(stmt);

	gcc_assert(DECL_ABSTRACT_ORIGIN(fndecl) == NULL_TREE);

	if (is_syscall(fndecl))
		return true;

	fntype_arg_len = type_num_arguments(TREE_TYPE(fndecl));
	attr = lookup_attribute("nocapture", DECL_ATTRIBUTES(fndecl));
	if (attr == NULL_TREE)
		return false;

	for (attr_val = TREE_VALUE(attr); attr_val; attr_val = TREE_CHAIN(attr_val)) {
		int attr_arg_val = (int)tree_to_shwi(TREE_VALUE(attr_val));

		if (attr_arg_val == -1)
			return true;
		if (attr_arg_val == fn_arg_count)
			return true;
		if (attr_arg_val > fntype_arg_len && fn_arg_count >= attr_arg_val)
			return true;
	}

	return false;
}

static bool compare_vardecls(const_tree vardecl, tree op)
{
	tree decl, offset;
	HOST_WIDE_INT bitsize, bitpos;
	enum machine_mode mode;
	int unsignedp, reversep __unused, volatilep;
	enum tree_code code = TREE_CODE(op);

	if (TREE_CODE_CLASS(code) == tcc_exceptional && code != SSA_NAME)
		return false;

	if (code == ADDR_EXPR)
		op = TREE_OPERAND(op, 0);

	if (TREE_CODE(op) == COMPONENT_REF)
		return false;

	decl = get_inner_reference(op, &bitsize, &bitpos, &offset, &mode, &unsignedp, &reversep, &volatilep, true);

	switch (TREE_CODE_CLASS(TREE_CODE(decl))) {
	case tcc_constant:
	case tcc_statement:
		return false;
	default:
		break;
	}

	switch (TREE_CODE(decl)) {
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case TARGET_MEM_REF:
		decl = TREE_OPERAND(decl, 0);
		break;
	default:
		break;
	}

	if (TREE_CODE(decl) == ADDR_EXPR)
		decl = TREE_OPERAND(decl, 0);
	if (TREE_CODE(decl) == SSA_NAME)
		decl = SSA_NAME_VAR(decl);
	if (decl == NULL_TREE)
		return false;

	if (!DECL_P(decl)) {
		debug_tree(op);
		debug_tree(decl);
		gcc_unreachable();
	}

	if (!VAR_P(decl))
		return false;
	if (!DECL_NAME(decl))
		return false;

	if (decl != vardecl && strcmp(DECL_NAME_POINTER(decl), DECL_NAME_POINTER(vardecl)))
		return false;

	gcc_assert(TREE_CODE(op) != SSA_NAME);
	return true;
}

static bool search_capture_use(const_tree vardecl, gimple stmt)
{
	unsigned int i;

	for (i = 0; i < gimple_num_ops(stmt); i++) {
		unsigned int arg_count;
		const_tree fndecl;
		tree op = *(gimple_op_ptr(stmt, i));

		if (op == NULL_TREE)
			continue;
		if (is_gimple_constant(op))
			continue;

		if (!compare_vardecls(vardecl, op))
			continue;

		if (!is_gimple_call(stmt))
			return true;

		// return, fndecl
		gcc_assert(i >= 3);
		arg_count = i - 2;
		if (is_nocapture_param(as_a_const_gcall(stmt), (int)arg_count))
			continue;

		fndecl = gimple_call_fndecl(stmt);
		gcc_assert(fndecl != NULL_TREE);
//		inform(gimple_location(stmt), "nocapture attribute is missing (fn: %E, arg: %u)\n", fndecl, arg_count);
		return true;

	}
	return false;
}

static bool is_in_capture_init(const_tree vardecl)
{
	unsigned int i;
	tree var;

	FOR_EACH_LOCAL_DECL(cfun, i, var) {
		unsigned HOST_WIDE_INT cnt;
		tree index __unused, value;
		const_tree initial = DECL_INITIAL(var);

		if (initial == NULL_TREE)
			continue;
		if (TREE_CODE(initial) != CONSTRUCTOR)
			continue;

		FOR_EACH_CONSTRUCTOR_ELT(CONSTRUCTOR_ELTS(initial), cnt, index, value) {
			if (TREE_CODE(value) != ADDR_EXPR)
				continue;
			if (TREE_OPERAND(value, 0) == vardecl)
				return true;
		}
	}

	return false;
}

static bool has_capture_use_local_var(const_tree vardecl)
{
	basic_block bb;

	if (is_in_capture_init(vardecl))
		return true;

	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			if (search_capture_use(vardecl, gsi_stmt(gsi)))
				return true;
		}
	}

	return false;
}

static void search_local_strs(bool initexit)
{
	unsigned int i;
	tree var;

	FOR_EACH_LOCAL_DECL(cfun, i, var) {
		tree str, init_val = DECL_INITIAL(var);

		if (init_val == NULL_TREE || init_val == error_mark_node)
			continue;
		// !!! str local vars
		if (strcmp(DECL_NAME_POINTER(var), "__func__"))
			continue;

		if (has_capture_use_local_var(var))
			continue;

		str = get_string_cst(init_val);
		gcc_assert(str);

		if (set_init_exit_section(var, initexit)) {
//			inform(DECL_SOURCE_LOCATION(var), "initified local var: %s: %s", DECL_NAME_POINTER(current_function_decl), TREE_STRING_POINTER(str));
		}
	}
}

static tree create_tmp_assign(gcall *stmt, unsigned int num)
{
	tree str, type, decl, arg = gimple_call_arg(stmt, num);

	str = get_string_cst(arg);
	decl = build_decl(DECL_SOURCE_LOCATION(current_function_decl), VAR_DECL, create_tmp_var_name("cicus"), TREE_TYPE(str));

	type = TREE_TYPE(TREE_TYPE(decl));
	type = build_qualified_type(type, TYPE_QUALS(type) | TYPE_QUAL_CONST);
	TYPE_READONLY(type) = 1;
	TREE_PUBLIC(type) = 0;

	DECL_INITIAL(decl) = str;
	DECL_CONTEXT(decl) = current_function_decl;
	DECL_ARTIFICIAL(decl) = 1;

	TREE_STATIC(decl) = 1;
	TREE_READONLY(decl) = 1;
	TREE_ADDRESSABLE(decl) = 1;
	TREE_USED(decl) = 1;

	add_referenced_var(decl);
	add_local_decl(cfun, decl);

	varpool_add_new_variable(decl);
	varpool_mark_needed_node(varpool_node(decl));

	DECL_CHAIN(decl) = BLOCK_VARS(DECL_INITIAL(current_function_decl));
	BLOCK_VARS(DECL_INITIAL (current_function_decl)) = decl;

	decl = build_fold_addr_expr_loc(DECL_SOURCE_LOCATION(current_function_decl), decl);
	gimple_call_set_arg(stmt, num, decl);
	update_stmt(stmt);

	return TREE_OPERAND(decl, 0);
}

static void search_str_param(gcall *stmt, bool initexit)
{
	unsigned int num;

	for (num = 0; num < gimple_call_num_args(stmt); num++) {
		tree var, str, arg = gimple_call_arg(stmt, num);

		str = get_string_cst(arg);
		if (str == NULL_TREE)
			continue;

		if (!is_nocapture_param(stmt, num + 1))
			continue;

		var = create_tmp_assign(stmt, num);
		if (set_init_exit_section(var, initexit)) {
//			inform(gimple_location(stmt), "initified function arg: %E: [%E]", current_function_decl, str);
		}
	}
}

static bool has_nocapture_param(const gcall *stmt)
{
	const_tree attr, fndecl = gimple_call_fndecl(stmt);

	if (fndecl == NULL_TREE)
		return false;

	if (is_syscall(fndecl))
		return true;

	attr = lookup_attribute("nocapture", DECL_ATTRIBUTES(fndecl));
	return attr != NULL_TREE;
}

static void search_const_strs(bool initexit)
{
	basic_block bb;

	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gcall *call_stmt;
			gimple stmt = gsi_stmt(gsi);

			if (!is_gimple_call(stmt))
				continue;

			call_stmt = as_a_gcall(stmt);
			if (has_nocapture_param(call_stmt))
				search_str_param(call_stmt, initexit);
		}
	}
}

static unsigned int handle_function(void)
{
	bool initexit;
	const char *section = get_init_exit_section(current_function_decl);

	if (!section)
		return 0;

	initexit = !strncmp(section, ".init.", 6);
	search_local_strs(initexit);
	search_const_strs(initexit);

	return 0;
}

#if BUILDING_GCC_VERSION >= 4009
namespace {
static const struct pass_data initify_plugin_pass_data = {
#else
static struct gimple_opt_pass initify_plugin_pass = {
	.pass = {
#endif
		.type			= GIMPLE_PASS,
		.name			= "initify_plugin",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 5000
#elif BUILDING_GCC_VERSION >= 4009
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
		.properties_required	= 0,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= TODO_dump_func | TODO_verify_ssa | TODO_verify_stmts | TODO_remove_unused_locals | TODO_update_ssa_no_phi | TODO_cleanup_cfg | TODO_ggc_collect | TODO_verify_flow
#if BUILDING_GCC_VERSION < 4009
	}
#endif
};

#if BUILDING_GCC_VERSION >= 4009
class initify_plugin_pass : public gimple_opt_pass {
public:
	initify_plugin_pass() : gimple_opt_pass(initify_plugin_pass_data, g) {}
#if BUILDING_GCC_VERSION >= 5000
	virtual unsigned int execute(function *) { return handle_function(); }
#else
	unsigned int execute() { return handle_function(); }
#endif
};
}

static struct opt_pass *make_initify_plugin_pass(void)
{
	return new initify_plugin_pass();
}
#else
static struct opt_pass *make_initify_plugin_pass(void)
{
	return &initify_plugin_pass.pass;
}
#endif

static unsigned int (*old_section_type_flags)(tree decl, const char *name, int reloc);

static unsigned int initify_section_type_flags(tree decl, const char *name, int reloc)
{
	if (!strcmp(name, ".init.rodata.str") || !strcmp(name, ".exit.rodata.str")) {
		gcc_assert(TREE_CODE(decl) == VAR_DECL);
		gcc_assert(DECL_INITIAL(decl));
		gcc_assert(TREE_CODE(DECL_INITIAL(decl)) == STRING_CST);

		return 1 | SECTION_MERGE | SECTION_STRINGS;
	}

	return old_section_type_flags(decl, name, reloc);
}

static void initify_start_unit(void __unused *gcc_data, void __unused *user_data)
{
	old_section_type_flags = targetm.section_type_flags;
	targetm.section_type_flags = initify_section_type_flags;
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	struct register_pass_info initify_plugin_pass_info;

	initify_plugin_pass_info.pass				= make_initify_plugin_pass();
	initify_plugin_pass_info.reference_pass_name		= "nrv";
	initify_plugin_pass_info.ref_pass_instance_number	= 1;
	initify_plugin_pass_info.pos_op				= PASS_POS_INSERT_AFTER;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &initify_plugin_info);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &initify_plugin_pass_info);
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);
	register_callback(plugin_name, PLUGIN_START_UNIT, initify_start_unit, NULL);

	return 0;
}

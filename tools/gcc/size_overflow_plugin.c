/*
 * Copyright 2011-2014 by Emese Revfy <re.emese@gmail.com>
 * Licensed under the GPL v2, or (at your option) v3
 *
 * Homepage:
 * http://www.grsecurity.net/~ephox/overflow_plugin/
 *
 * Documentation:
 * http://forums.grsecurity.net/viewtopic.php?f=7&t=3043
 *
 * This plugin recomputes expressions of function arguments marked by a size_overflow attribute
 * with double integer precision (DImode/TImode for 32/64 bit integer types).
 * The recomputed argument is checked against TYPE_MAX and an event is logged on overflow and the triggering process is killed.
 *
 * Usage:
 * $ gcc -I`gcc -print-file-name=plugin`/include/c-family -I`gcc -print-file-name=plugin`/include -fPIC -shared -O2 -ggdb -Wall -W -o size_overflow_plugin.so size_overflow_plugin.c
 * $ gcc -fplugin=size_overflow_plugin.so test.c  -O2
 */

#include "gcc-common.h"

int plugin_is_GPL_compatible;

static struct plugin_info size_overflow_plugin_info = {
	.version	= "20140213",
	.help		= "no-size-overflow\tturn off size overflow checking\n",
};

#define BEFORE_STMT true
#define AFTER_STMT false
#define CREATE_NEW_VAR NULL_TREE
#define CODES_LIMIT 32
#define MAX_PARAM 31
#define VEC_LEN 128
#define MY_STMT GF_PLF_1
#define NO_CAST_CHECK GF_PLF_2
#define RET_CHECK NULL_TREE
#define CANNOT_FIND_ARG 32
#define WRONG_NODE 32
#define NOT_INTENTIONAL_ASM NULL
#define MIN_CHECK true
#define MAX_CHECK false

#define TURN_OFF_ASM_STR "# size_overflow MARK_TURN_OFF "
#define YES_ASM_STR "# size_overflow MARK_YES "
#define OK_ASM_STR "# size_overflow "

struct size_overflow_hash {
	const struct size_overflow_hash * const next;
	const char * const name;
	const unsigned int param;
};

#include "size_overflow_hash.h"

enum mark {
	MARK_NO, MARK_YES, MARK_NOT_INTENTIONAL, MARK_TURN_OFF
};

static unsigned int call_count;

struct visited {
	struct visited *next;
	const_tree fndecl;
	unsigned int num;
	const_tree rhs;
};

struct next_cgraph_node {
	struct next_cgraph_node *next;
	struct cgraph_node *current_function;
	tree callee_fndecl;
	unsigned int num;
};

struct interesting_node {
	struct interesting_node *next;
	gimple first_stmt;
	const_tree fndecl;
	tree node;
#if BUILDING_GCC_VERSION <= 4007
	VEC(tree, gc) *last_nodes;
#else
	vec<tree, va_gc> *last_nodes;
#endif
	unsigned int num;
	enum mark intentional_attr_decl;
	enum mark intentional_attr_cur_fndecl;
	gimple intentional_mark_from_gimple;
};

static tree report_size_overflow_decl;

static tree expand(struct pointer_set_t *visited, struct cgraph_node *caller_node, tree lhs);
static void set_conditions(struct pointer_set_t *visited, bool *interesting_conditions, const_tree lhs);
static void walk_use_def(struct pointer_set_t *visited, struct interesting_node *cur_node, tree lhs);
static enum mark search_intentional(struct pointer_set_t *visited, const_tree lhs);
static void search_size_overflow_attribute(struct pointer_set_t *visited, tree lhs);

static void check_size_overflow(struct cgraph_node *caller_node, gimple stmt, tree size_overflow_type, tree cast_rhs, tree rhs, bool before);
static tree get_size_overflow_type(gimple stmt, const_tree node);
static tree dup_assign(struct pointer_set_t *visited, gimple oldstmt, const_tree node, tree rhs1, tree rhs2, tree __unused rhs3);

static tree handle_size_overflow_attribute(tree *node, tree __unused name, tree args, int __unused flags, bool *no_add_attrs)
{
	unsigned int arg_count;
	enum tree_code code = TREE_CODE(*node);

	switch (code) {
	case FUNCTION_DECL:
		arg_count = type_num_arguments(TREE_TYPE(*node));
		break;
	case FUNCTION_TYPE:
	case METHOD_TYPE:
		arg_count = type_num_arguments(*node);
		break;
	default:
		*no_add_attrs = true;
		error("%s: %qE attribute only applies to functions", __func__, name);
		return NULL_TREE;
	}

	for (; args; args = TREE_CHAIN(args)) {
		tree position = TREE_VALUE(args);
		if (TREE_CODE(position) != INTEGER_CST || TREE_INT_CST_LOW(position) > arg_count ) {
			error("%s: parameter %u is outside range.", __func__, (unsigned int)TREE_INT_CST_LOW(position));
			*no_add_attrs = true;
		}
	}
	return NULL_TREE;
}

static tree handle_intentional_overflow_attribute(tree *node, tree __unused name, tree args, int __unused flags, bool *no_add_attrs)
{
	unsigned int arg_count;
	enum tree_code code = TREE_CODE(*node);

	switch (code) {
	case FUNCTION_DECL:
		arg_count = type_num_arguments(TREE_TYPE(*node));
		break;
	case FUNCTION_TYPE:
	case METHOD_TYPE:
		arg_count = type_num_arguments(*node);
		break;
	case FIELD_DECL:
		return NULL_TREE;
	default:
		*no_add_attrs = true;
		error("%qE attribute only applies to functions", name);
		return NULL_TREE;
	}

	if (TREE_INT_CST_HIGH(TREE_VALUE(args)) != 0)
		return NULL_TREE;

	for (; args; args = TREE_CHAIN(args)) {
		tree position = TREE_VALUE(args);
		if (TREE_CODE(position) != INTEGER_CST || TREE_INT_CST_LOW(position) > arg_count ) {
			error("%s: parameter %u is outside range.", __func__, (unsigned int)TREE_INT_CST_LOW(position));
			*no_add_attrs = true;
		}
	}
	return NULL_TREE;
}

static struct attribute_spec size_overflow_attr = {
	.name				= "size_overflow",
	.min_length			= 1,
	.max_length			= -1,
	.decl_required			= true,
	.type_required			= false,
	.function_type_required		= false,
	.handler			= handle_size_overflow_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity		= false
#endif
};

static struct attribute_spec intentional_overflow_attr = {
	.name				= "intentional_overflow",
	.min_length			= 1,
	.max_length			= -1,
	.decl_required			= true,
	.type_required			= false,
	.function_type_required		= false,
	.handler			= handle_intentional_overflow_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity		= false
#endif
};

static void register_attributes(void __unused *event_data, void __unused *data)
{
	register_attribute(&size_overflow_attr);
	register_attribute(&intentional_overflow_attr);
}

static bool is_bool(const_tree node)
{
	const_tree type;

	if (node == NULL_TREE)
		return false;

	type = TREE_TYPE(node);
	if (!INTEGRAL_TYPE_P(type))
		return false;
	if (TREE_CODE(type) == BOOLEAN_TYPE)
		return true;
	if (TYPE_PRECISION(type) == 1)
		return true;
	return false;
}

static bool skip_types(const_tree var)
{
	tree type;
	enum tree_code code;

	if (is_gimple_constant(var))
		return true;

	switch (TREE_CODE(var)) {
		case ADDR_EXPR:
#if BUILDING_GCC_VERSION >= 4006
		case MEM_REF:
#endif
		case ARRAY_REF:
		case BIT_FIELD_REF:
		case INDIRECT_REF:
		case TARGET_MEM_REF:
		case COMPONENT_REF:
		case VAR_DECL:
		case VIEW_CONVERT_EXPR:
			return true;
		default:
			break;
	}

	code = TREE_CODE(var);
	gcc_assert(code == SSA_NAME || code == PARM_DECL);

	type = TREE_TYPE(var);
	switch (TREE_CODE(type)) {
		case INTEGER_TYPE:
		case ENUMERAL_TYPE:
			return false;
		case BOOLEAN_TYPE:
			return is_bool(var);
		default:
			return true;
	}
}

static inline gimple get_def_stmt(const_tree node)
{
	gcc_assert(node != NULL_TREE);

	if (skip_types(node))
		return NULL;

	if (TREE_CODE(node) != SSA_NAME)
		return NULL;
	return SSA_NAME_DEF_STMT(node);
}

static unsigned char get_tree_code(const_tree type)
{
	switch (TREE_CODE(type)) {
	case ARRAY_TYPE:
		return 0;
	case BOOLEAN_TYPE:
		return 1;
	case ENUMERAL_TYPE:
		return 2;
	case FUNCTION_TYPE:
		return 3;
	case INTEGER_TYPE:
		return 4;
	case POINTER_TYPE:
		return 5;
	case RECORD_TYPE:
		return 6;
	case UNION_TYPE:
		return 7;
	case VOID_TYPE:
		return 8;
	case REAL_TYPE:
		return 9;
	case VECTOR_TYPE:
		return 10;
	case REFERENCE_TYPE:
		return 11;
	case OFFSET_TYPE:
		return 12;
	case COMPLEX_TYPE:
		return 13;
	default:
		debug_tree((tree)type);
		gcc_unreachable();
	}
}

struct function_hash {
	size_t tree_codes_len;
	unsigned char tree_codes[CODES_LIMIT];
	const_tree fndecl;
	unsigned int hash;
};

// http://www.team5150.com/~andrew/noncryptohashzoo2~/CrapWow.html
static unsigned int CrapWow(const char *key, unsigned int len, unsigned int seed)
{
#define cwfold( a, b, lo, hi ) { p = (unsigned int)(a) * (unsigned long long)(b); lo ^= (unsigned int)p; hi ^= (unsigned int)(p >> 32); }
#define cwmixa( in ) { cwfold( in, m, k, h ); }
#define cwmixb( in ) { cwfold( in, n, h, k ); }

	unsigned int m = 0x57559429;
	unsigned int n = 0x5052acdb;
	const unsigned int *key4 = (const unsigned int *)key;
	unsigned int h = len;
	unsigned int k = len + seed + n;
	unsigned long long p;

	while (len >= 8) {
		cwmixb(key4[0]) cwmixa(key4[1]) key4 += 2;
		len -= 8;
	}
	if (len >= 4) {
		cwmixb(key4[0]) key4 += 1;
		len -= 4;
	}
	if (len)
		cwmixa(key4[0] & ((1 << (len * 8)) - 1 ));
	cwmixb(h ^ (k + n));
	return k ^ h;

#undef cwfold
#undef cwmixa
#undef cwmixb
}

static void set_hash(const char *fn_name, struct function_hash *fn_hash_data)
{
	unsigned int fn, codes, seed = 0;

	fn = CrapWow(fn_name, strlen(fn_name), seed) & 0xffff;
	codes = CrapWow((const char*)fn_hash_data->tree_codes, fn_hash_data->tree_codes_len, seed) & 0xffff;

	fn_hash_data->hash = fn ^ codes;
}

static void set_node_codes(const_tree type, struct function_hash *fn_hash_data)
{
	gcc_assert(type != NULL_TREE);
	gcc_assert(TREE_CODE_CLASS(TREE_CODE(type)) == tcc_type);

	while (type && fn_hash_data->tree_codes_len < CODES_LIMIT) {
		fn_hash_data->tree_codes[fn_hash_data->tree_codes_len] = get_tree_code(type);
		fn_hash_data->tree_codes_len++;
		type = TREE_TYPE(type);
	}
}

static void set_result_codes(const_tree node, struct function_hash *fn_hash_data)
{
	const_tree result;

	gcc_assert(node != NULL_TREE);

	if (DECL_P(node)) {
		result = DECL_RESULT(node);
		if (result != NULL_TREE)
			return set_node_codes(TREE_TYPE(result), fn_hash_data);
		return set_result_codes(TREE_TYPE(node), fn_hash_data);
	}

	gcc_assert(TYPE_P(node));

	if (TREE_CODE(node) == FUNCTION_TYPE)
		return set_result_codes(TREE_TYPE(node), fn_hash_data);

	return set_node_codes(node, fn_hash_data);
}

static void set_function_codes(struct function_hash *fn_hash_data)
{
	const_tree arg, type = TREE_TYPE(fn_hash_data->fndecl);
	enum tree_code code = TREE_CODE(type);

	gcc_assert(code == FUNCTION_TYPE || code == METHOD_TYPE);

	set_result_codes(fn_hash_data->fndecl, fn_hash_data);

	for (arg = TYPE_ARG_TYPES(type); arg != NULL_TREE && fn_hash_data->tree_codes_len < CODES_LIMIT; arg = TREE_CHAIN(arg))
		set_node_codes(TREE_VALUE(arg), fn_hash_data);
}

static const struct size_overflow_hash *get_function_hash(const_tree fndecl)
{
	const struct size_overflow_hash *entry;
	struct function_hash fn_hash_data;
	const char *func_name;

	// skip builtins __builtin_constant_p
	if (DECL_BUILT_IN(fndecl))
		return NULL;

	fn_hash_data.fndecl = fndecl;
	fn_hash_data.tree_codes_len = 0;

	set_function_codes(&fn_hash_data);
	gcc_assert(fn_hash_data.tree_codes_len != 0);

	func_name = DECL_NAME_POINTER(fn_hash_data.fndecl);
	set_hash(func_name, &fn_hash_data);

	entry = size_overflow_hash[fn_hash_data.hash];

	while (entry) {
		if (!strcmp(entry->name, func_name))
			return entry;
		entry = entry->next;
	}
	return NULL;
}

static void print_missing_msg(const_tree func, unsigned int argnum)
{
	location_t loc;
	const char *curfunc;
	struct function_hash fn_hash_data;

	fn_hash_data.fndecl = DECL_ORIGIN(func);
	fn_hash_data.tree_codes_len = 0;

	loc = DECL_SOURCE_LOCATION(fn_hash_data.fndecl);
	curfunc = DECL_NAME_POINTER(fn_hash_data.fndecl);

	set_function_codes(&fn_hash_data);
	set_hash(curfunc, &fn_hash_data);

	inform(loc, "Function %s is missing from the size_overflow hash table +%s+%u+%u+", curfunc, curfunc, argnum, fn_hash_data.hash);
}

static unsigned int find_arg_number_tree(const_tree arg, const_tree func)
{
	tree var;
	unsigned int argnum = 1;

	if (TREE_CODE(arg) == SSA_NAME)
		arg = SSA_NAME_VAR(arg);

	for (var = DECL_ARGUMENTS(func); var; var = TREE_CHAIN(var), argnum++) {
		if (!operand_equal_p(arg, var, 0) && strcmp(DECL_NAME_POINTER(var), DECL_NAME_POINTER(arg)))
			continue;
		if (!skip_types(var))
			return argnum;
	}

	return CANNOT_FIND_ARG;
}

static tree create_new_var(tree type)
{
	tree new_var = create_tmp_var(type, "cicus");

	add_referenced_var(new_var);
	return new_var;
}

static gimple create_binary_assign(enum tree_code code, gimple stmt, tree rhs1, tree rhs2)
{
	gimple assign;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);
	tree type = TREE_TYPE(rhs1);
	tree lhs = create_new_var(type);

	gcc_assert(types_compatible_p(type, TREE_TYPE(rhs2)));
	assign = gimple_build_assign_with_ops(code, lhs, rhs1, rhs2);
	gimple_assign_set_lhs(assign, make_ssa_name(lhs, assign));

	gsi_insert_before(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
	gimple_set_plf(assign, MY_STMT, true);
	return assign;
}

static tree cast_a_tree(tree type, tree var)
{
	gcc_assert(type != NULL_TREE);
	gcc_assert(var != NULL_TREE);
	gcc_assert(fold_convertible_p(type, var));

	return fold_convert(type, var);
}

static tree get_lhs(const_gimple stmt)
{
	switch (gimple_code(stmt)) {
	case GIMPLE_ASSIGN:
	case GIMPLE_CALL:
		return gimple_get_lhs(stmt);
	case GIMPLE_PHI:
		return gimple_phi_result(stmt);
	default:
		return NULL_TREE;
	}
}

static bool skip_cast(tree dst_type, const_tree rhs, bool force)
{
	const_gimple def_stmt = get_def_stmt(rhs);

	if (force)
		return false;

	if (is_gimple_constant(rhs))
		return false;

	if (!def_stmt || gimple_code(def_stmt) == GIMPLE_NOP)
		return false;

	if (!types_compatible_p(dst_type, TREE_TYPE(rhs)))
		return false;

	// DI type can be on 32 bit (from create_assign) but overflow type stays DI
	if (LONG_TYPE_SIZE == GET_MODE_BITSIZE(SImode))
		return false;

	return true;
}

static gimple build_cast_stmt(tree dst_type, tree rhs, tree lhs, gimple_stmt_iterator *gsi, bool before, bool force)
{
	gimple assign, def_stmt;

	gcc_assert(dst_type != NULL_TREE && rhs != NULL_TREE);
	if (gsi_end_p(*gsi) && before == AFTER_STMT)
		gcc_unreachable();

	def_stmt = get_def_stmt(rhs);
	if (def_stmt && gimple_code(def_stmt) != GIMPLE_NOP && skip_cast(dst_type, rhs, force) && gimple_plf(def_stmt, MY_STMT))
		return def_stmt;

	if (lhs == CREATE_NEW_VAR)
		lhs = create_new_var(dst_type);

	assign = gimple_build_assign(lhs, cast_a_tree(dst_type, rhs));

	if (!gsi_end_p(*gsi)) {
		location_t loc = gimple_location(gsi_stmt(*gsi));
		gimple_set_location(assign, loc);
	}

	gimple_assign_set_lhs(assign, make_ssa_name(lhs, assign));

	if (before)
		gsi_insert_before(gsi, assign, GSI_NEW_STMT);
	else
		gsi_insert_after(gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
	return assign;
}

static tree cast_to_new_size_overflow_type(gimple stmt, tree rhs, tree size_overflow_type, bool before)
{
	gimple_stmt_iterator gsi;
	tree lhs;
	gimple new_stmt;

	if (rhs == NULL_TREE)
		return NULL_TREE;

	gsi = gsi_for_stmt(stmt);
	new_stmt = build_cast_stmt(size_overflow_type, rhs, CREATE_NEW_VAR, &gsi, before, false);
	gimple_set_plf(new_stmt, MY_STMT, true);

	lhs = get_lhs(new_stmt);
	gcc_assert(lhs != NULL_TREE);
	return lhs;
}

static tree cast_to_TI_type(gimple stmt, tree node)
{
	gimple_stmt_iterator gsi;
	gimple cast_stmt;
	tree type = TREE_TYPE(node);

	if (types_compatible_p(type, intTI_type_node))
		return node;

	gsi = gsi_for_stmt(stmt);
	cast_stmt = build_cast_stmt(intTI_type_node, node, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	gimple_set_plf(cast_stmt, MY_STMT, true);
	return gimple_assign_lhs(cast_stmt);
}

static tree create_assign(struct pointer_set_t *visited, gimple oldstmt, tree rhs1, bool before)
{
	tree lhs, new_lhs;
	gimple_stmt_iterator gsi;

	if (rhs1 == NULL_TREE) {
		debug_gimple_stmt(oldstmt);
		error("%s: rhs1 is NULL_TREE", __func__);
		gcc_unreachable();
	}

	switch (gimple_code(oldstmt)) {
	case GIMPLE_ASM:
		lhs = rhs1;
		break;
	case GIMPLE_CALL:
	case GIMPLE_ASSIGN:
		lhs = gimple_get_lhs(oldstmt);
		break;
	default:
		debug_gimple_stmt(oldstmt);
		gcc_unreachable();
	}

	gsi = gsi_for_stmt(oldstmt);
	pointer_set_insert(visited, oldstmt);
	if (lookup_stmt_eh_lp(oldstmt) != 0) {
		basic_block next_bb, cur_bb;
		const_edge e;

		gcc_assert(before == false);
		gcc_assert(stmt_can_throw_internal(oldstmt));
		gcc_assert(gimple_code(oldstmt) == GIMPLE_CALL);
		gcc_assert(!gsi_end_p(gsi));

		cur_bb = gimple_bb(oldstmt);
		next_bb = cur_bb->next_bb;
		e = find_edge(cur_bb, next_bb);
		gcc_assert(e != NULL);
		gcc_assert(e->flags & EDGE_FALLTHRU);

		gsi = gsi_after_labels(next_bb);
		gcc_assert(!gsi_end_p(gsi));

		before = true;
		oldstmt = gsi_stmt(gsi);
	}

	new_lhs = cast_to_new_size_overflow_type(oldstmt, rhs1, get_size_overflow_type(oldstmt, lhs), before);
	return new_lhs;
}

static tree dup_assign(struct pointer_set_t *visited, gimple oldstmt, const_tree node, tree rhs1, tree rhs2, tree __unused rhs3)
{
	gimple stmt;
	gimple_stmt_iterator gsi;
	tree size_overflow_type, new_var, lhs = gimple_assign_lhs(oldstmt);

	if (gimple_plf(oldstmt, MY_STMT))
		return lhs;

	if (gimple_num_ops(oldstmt) != 4 && rhs1 == NULL_TREE) {
		rhs1 = gimple_assign_rhs1(oldstmt);
		rhs1 = create_assign(visited, oldstmt, rhs1, BEFORE_STMT);
	}
	if (gimple_num_ops(oldstmt) == 3 && rhs2 == NULL_TREE) {
		rhs2 = gimple_assign_rhs2(oldstmt);
		rhs2 = create_assign(visited, oldstmt, rhs2, BEFORE_STMT);
	}

	stmt = gimple_copy(oldstmt);
	gimple_set_location(stmt, gimple_location(oldstmt));
	gimple_set_plf(stmt, MY_STMT, true);

	if (gimple_assign_rhs_code(oldstmt) == WIDEN_MULT_EXPR)
		gimple_assign_set_rhs_code(stmt, MULT_EXPR);

	size_overflow_type = get_size_overflow_type(oldstmt, node);

	new_var = create_new_var(size_overflow_type);
	new_var = make_ssa_name(new_var, stmt);
	gimple_assign_set_lhs(stmt, new_var);

	if (rhs1 != NULL_TREE)
		gimple_assign_set_rhs1(stmt, rhs1);

	if (rhs2 != NULL_TREE)
		gimple_assign_set_rhs2(stmt, rhs2);
#if BUILDING_GCC_VERSION >= 4006
	if (rhs3 != NULL_TREE)
		gimple_assign_set_rhs3(stmt, rhs3);
#endif
	gimple_set_vuse(stmt, gimple_vuse(oldstmt));
	gimple_set_vdef(stmt, gimple_vdef(oldstmt));

	gsi = gsi_for_stmt(oldstmt);
	gsi_insert_after(&gsi, stmt, GSI_SAME_STMT);
	update_stmt(stmt);
	pointer_set_insert(visited, oldstmt);
	return gimple_assign_lhs(stmt);
}

static tree cast_parm_decl(tree phi_ssa_name, tree arg, tree size_overflow_type, basic_block bb)
{
	gimple assign;
	gimple_stmt_iterator gsi;
	basic_block first_bb;

	gcc_assert(SSA_NAME_IS_DEFAULT_DEF(arg));

	if (bb->index == 0) {
		first_bb = split_block_after_labels(ENTRY_BLOCK_PTR_FOR_FN(cfun))->dest;
		gcc_assert(dom_info_available_p(CDI_DOMINATORS));
		set_immediate_dominator(CDI_DOMINATORS, first_bb, ENTRY_BLOCK_PTR_FOR_FN(cfun));
		bb = first_bb;
	}

	gsi = gsi_after_labels(bb);
	assign = build_cast_stmt(size_overflow_type, arg, phi_ssa_name, &gsi, BEFORE_STMT, false);
	gimple_set_plf(assign, MY_STMT, true);

	return gimple_assign_lhs(assign);
}

static tree use_phi_ssa_name(tree ssa_name_var, tree new_arg)
{
	gimple_stmt_iterator gsi;
	gimple assign, def_stmt = get_def_stmt(new_arg);

	if (gimple_code(def_stmt) == GIMPLE_PHI) {
		gsi = gsi_after_labels(gimple_bb(def_stmt));
		assign = build_cast_stmt(TREE_TYPE(new_arg), new_arg, ssa_name_var, &gsi, BEFORE_STMT, true);
	} else {
		gsi = gsi_for_stmt(def_stmt);
		assign = build_cast_stmt(TREE_TYPE(new_arg), new_arg, ssa_name_var, &gsi, AFTER_STMT, true);
	}

	gimple_set_plf(assign, MY_STMT, true);
	return gimple_assign_lhs(assign);
}

static tree cast_visited_phi_arg(tree ssa_name_var, tree arg, tree size_overflow_type)
{
	basic_block bb;
	gimple_stmt_iterator gsi;
	const_gimple def_stmt;
	gimple assign;

	def_stmt = get_def_stmt(arg);
	bb = gimple_bb(def_stmt);
	gcc_assert(bb->index != 0);
	gsi = gsi_after_labels(bb);

	assign = build_cast_stmt(size_overflow_type, arg, ssa_name_var, &gsi, BEFORE_STMT, false);
	gimple_set_plf(assign, MY_STMT, true);
	return gimple_assign_lhs(assign);
}

static tree create_new_phi_arg(tree ssa_name_var, tree new_arg, gimple oldstmt, unsigned int i)
{
	tree size_overflow_type;
	tree arg;
	const_gimple def_stmt;

	if (new_arg != NULL_TREE && is_gimple_constant(new_arg))
		return new_arg;

	arg = gimple_phi_arg_def(oldstmt, i);
	def_stmt = get_def_stmt(arg);
	gcc_assert(def_stmt != NULL);
	size_overflow_type = get_size_overflow_type(oldstmt, arg);

	switch (gimple_code(def_stmt)) {
	case GIMPLE_PHI:
		return cast_visited_phi_arg(ssa_name_var, arg, size_overflow_type);
	case GIMPLE_NOP: {
		basic_block bb;

		bb = gimple_phi_arg_edge(oldstmt, i)->src;
		return cast_parm_decl(ssa_name_var, arg, size_overflow_type, bb);
	}
	case GIMPLE_ASM: {
		gimple_stmt_iterator gsi;
		gimple assign, stmt = get_def_stmt(arg);

		gsi = gsi_for_stmt(stmt);
		assign = build_cast_stmt(size_overflow_type, arg, ssa_name_var, &gsi, AFTER_STMT, false);
		gimple_set_plf(assign, MY_STMT, true);
		return gimple_assign_lhs(assign);
	}
	default:
		gcc_assert(new_arg != NULL_TREE);
		gcc_assert(types_compatible_p(TREE_TYPE(new_arg), size_overflow_type));
		return use_phi_ssa_name(ssa_name_var, new_arg);
	}
}

static gimple overflow_create_phi_node(gimple oldstmt, tree result)
{
	basic_block bb;
	gimple phi;
	gimple_seq seq;
	gimple_stmt_iterator gsi = gsi_for_stmt(oldstmt);

	bb = gsi_bb(gsi);

	if (result == NULL_TREE) {
		tree old_result = gimple_phi_result(oldstmt);
		tree size_overflow_type = get_size_overflow_type(oldstmt, old_result);

		result = create_new_var(size_overflow_type);
	}

	phi = create_phi_node(result, bb);
	gimple_phi_set_result(phi, make_ssa_name(result, phi));
	seq = phi_nodes(bb);
	gsi = gsi_last(seq);
	gsi_remove(&gsi, false);

	gsi = gsi_for_stmt(oldstmt);
	gsi_insert_after(&gsi, phi, GSI_NEW_STMT);
	gimple_set_bb(phi, bb);
	gimple_set_plf(phi, MY_STMT, true);
	return phi;
}

#if BUILDING_GCC_VERSION <= 4007
static tree create_new_phi_node(VEC(tree, heap) **args, tree ssa_name_var, gimple oldstmt)
#else
static tree create_new_phi_node(vec<tree, va_heap, vl_embed> *&args, tree ssa_name_var, gimple oldstmt)
#endif
{
	gimple new_phi;
	unsigned int i;
	tree arg, result;
	location_t loc = gimple_location(oldstmt);

#if BUILDING_GCC_VERSION <= 4007
	gcc_assert(!VEC_empty(tree, *args));
#else
	gcc_assert(!args->is_empty());
#endif

	new_phi = overflow_create_phi_node(oldstmt, ssa_name_var);
	result = gimple_phi_result(new_phi);
	ssa_name_var = SSA_NAME_VAR(result);

#if BUILDING_GCC_VERSION <= 4007
	FOR_EACH_VEC_ELT(tree, *args, i, arg) {
#else
	FOR_EACH_VEC_SAFE_ELT(args, i, arg) {
#endif
		arg = create_new_phi_arg(ssa_name_var, arg, oldstmt, i);
		add_phi_arg(new_phi, arg, gimple_phi_arg_edge(oldstmt, i), loc);
	}

#if BUILDING_GCC_VERSION <= 4007
	VEC_free(tree, heap, *args);
#else
	vec_free(args);
#endif
	update_stmt(new_phi);
	return result;
}

static tree handle_phi(struct pointer_set_t *visited, struct cgraph_node *caller_node, tree orig_result)
{
	tree ssa_name_var = NULL_TREE;
#if BUILDING_GCC_VERSION <= 4007
	VEC(tree, heap) *args = NULL;
#else
	vec<tree, va_heap, vl_embed> *args = NULL;
#endif
	gimple oldstmt = get_def_stmt(orig_result);
	unsigned int i, len = gimple_phi_num_args(oldstmt);

	pointer_set_insert(visited, oldstmt);
	for (i = 0; i < len; i++) {
		tree arg, new_arg;

		arg = gimple_phi_arg_def(oldstmt, i);
		new_arg = expand(visited, caller_node, arg);

		if (ssa_name_var == NULL_TREE && new_arg != NULL_TREE)
			ssa_name_var = SSA_NAME_VAR(new_arg);

		if (is_gimple_constant(arg)) {
			tree size_overflow_type = get_size_overflow_type(oldstmt, arg);

			new_arg = cast_a_tree(size_overflow_type, arg);
		}

#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(tree, heap, args, new_arg);
#else
		vec_safe_push(args, new_arg);
#endif
	}

#if BUILDING_GCC_VERSION <= 4007
	return create_new_phi_node(&args, ssa_name_var, oldstmt);
#else
	return create_new_phi_node(args, ssa_name_var, oldstmt);
#endif
}

static tree change_assign_rhs(gimple stmt, const_tree orig_rhs, tree new_rhs)
{
	gimple assign;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);
	tree origtype = TREE_TYPE(orig_rhs);

	gcc_assert(is_gimple_assign(stmt));

	assign = build_cast_stmt(origtype, new_rhs, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	gimple_set_plf(assign, MY_STMT, true);
	return gimple_assign_lhs(assign);
}

static bool is_a_cast_and_const_overflow(const_tree no_const_rhs)
{
	const_tree rhs1, lhs, rhs1_type, lhs_type;
	enum machine_mode lhs_mode, rhs_mode;
	gimple def_stmt = get_def_stmt(no_const_rhs);

	if (!def_stmt || !gimple_assign_cast_p(def_stmt))
		return false;

	rhs1 = gimple_assign_rhs1(def_stmt);
	lhs = gimple_assign_lhs(def_stmt);
	rhs1_type = TREE_TYPE(rhs1);
	lhs_type = TREE_TYPE(lhs);
	rhs_mode = TYPE_MODE(rhs1_type);
	lhs_mode = TYPE_MODE(lhs_type);
	if (TYPE_UNSIGNED(lhs_type) == TYPE_UNSIGNED(rhs1_type) || lhs_mode != rhs_mode)
		return false;

	return true;
}

static tree create_cast_assign(struct pointer_set_t *visited, gimple stmt)
{
	tree rhs1 = gimple_assign_rhs1(stmt);
	tree lhs = gimple_assign_lhs(stmt);
	const_tree rhs1_type = TREE_TYPE(rhs1);
	const_tree lhs_type = TREE_TYPE(lhs);

	if (TYPE_UNSIGNED(rhs1_type) == TYPE_UNSIGNED(lhs_type))
		return create_assign(visited, stmt, lhs, AFTER_STMT);

	return create_assign(visited, stmt, rhs1, AFTER_STMT);
}

static bool no_uses(tree node)
{
	imm_use_iterator imm_iter;
	use_operand_p use_p;

	FOR_EACH_IMM_USE_FAST(use_p, imm_iter, node) {
		const_gimple use_stmt = USE_STMT(use_p);

		if (use_stmt == NULL)
			return true;
		if (is_gimple_debug(use_stmt))
			continue;
		return false;
	}
	return true;
}

// 3.8.5 mm/page-writeback.c __ilog2_u64(): ret, uint + uintmax; uint -> int; int max
static bool is_const_plus_unsigned_signed_truncation(const_tree lhs)
{
	tree rhs1, lhs_type, rhs_type, rhs2, not_const_rhs;
	gimple def_stmt = get_def_stmt(lhs);

	if (!def_stmt || !gimple_assign_cast_p(def_stmt))
		return false;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs_type = TREE_TYPE(rhs1);
	lhs_type = TREE_TYPE(lhs);
	if (TYPE_UNSIGNED(lhs_type) || !TYPE_UNSIGNED(rhs_type))
		return false;
	if (TYPE_MODE(lhs_type) != TYPE_MODE(rhs_type))
		return false;

	def_stmt = get_def_stmt(rhs1);
	if (!def_stmt || !is_gimple_assign(def_stmt) || gimple_num_ops(def_stmt) != 3)
		return false;

	if (gimple_assign_rhs_code(def_stmt) != PLUS_EXPR)
		return false;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);
	if (!is_gimple_constant(rhs1) && !is_gimple_constant(rhs2))
		return false;

	if (is_gimple_constant(rhs2))
		not_const_rhs = rhs1;
	else
		not_const_rhs = rhs2;

	return no_uses(not_const_rhs);
}

static bool skip_lhs_cast_check(const_gimple stmt)
{
	const_tree rhs = gimple_assign_rhs1(stmt);
	const_gimple def_stmt = get_def_stmt(rhs);

	// 3.8.2 kernel/futex_compat.c compat_exit_robust_list(): get_user() 64 ulong -> int (compat_long_t), int max
	if (gimple_code(def_stmt) == GIMPLE_ASM)
		return true;

	if (is_const_plus_unsigned_signed_truncation(rhs))
		return true;

	return false;
}

static tree create_cast_overflow_check(struct pointer_set_t *visited, struct cgraph_node *caller_node, tree new_rhs1, gimple stmt)
{
	bool cast_lhs, cast_rhs;
	tree lhs = gimple_assign_lhs(stmt);
	tree rhs = gimple_assign_rhs1(stmt);
	const_tree lhs_type = TREE_TYPE(lhs);
	const_tree rhs_type = TREE_TYPE(rhs);
	enum machine_mode lhs_mode = TYPE_MODE(lhs_type);
	enum machine_mode rhs_mode = TYPE_MODE(rhs_type);
	unsigned int lhs_size = GET_MODE_BITSIZE(lhs_mode);
	unsigned int rhs_size = GET_MODE_BITSIZE(rhs_mode);

	static bool check_lhs[3][4] = {
		// ss    su     us     uu
		{ false, true,  true,  false }, // lhs > rhs
		{ false, false, false, false }, // lhs = rhs
		{ true,  true,  true,  true  }, // lhs < rhs
	};

	static bool check_rhs[3][4] = {
		// ss    su     us     uu
		{ true,  false, true,  true  }, // lhs > rhs
		{ true,  false, true,  true  }, // lhs = rhs
		{ true,  false, true,  true  }, // lhs < rhs
	};

	// skip lhs check on signed SI -> HI cast or signed SI -> QI cast !!!!
	if (rhs_mode == SImode && !TYPE_UNSIGNED(rhs_type) && (lhs_mode == HImode || lhs_mode == QImode))
		return create_assign(visited, stmt, lhs, AFTER_STMT);

	if (lhs_size > rhs_size) {
		cast_lhs = check_lhs[0][TYPE_UNSIGNED(rhs_type) + 2 * TYPE_UNSIGNED(lhs_type)];
		cast_rhs = check_rhs[0][TYPE_UNSIGNED(rhs_type) + 2 * TYPE_UNSIGNED(lhs_type)];
	} else if (lhs_size == rhs_size) {
		cast_lhs = check_lhs[1][TYPE_UNSIGNED(rhs_type) + 2 * TYPE_UNSIGNED(lhs_type)];
		cast_rhs = check_rhs[1][TYPE_UNSIGNED(rhs_type) + 2 * TYPE_UNSIGNED(lhs_type)];
	} else {
		cast_lhs = check_lhs[2][TYPE_UNSIGNED(rhs_type) + 2 * TYPE_UNSIGNED(lhs_type)];
		cast_rhs = check_rhs[2][TYPE_UNSIGNED(rhs_type) + 2 * TYPE_UNSIGNED(lhs_type)];
	}

	if (!cast_lhs && !cast_rhs)
		return dup_assign(visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);

	if (cast_lhs && !skip_lhs_cast_check(stmt))
		check_size_overflow(caller_node, stmt, TREE_TYPE(new_rhs1), new_rhs1, lhs, BEFORE_STMT);

	if (cast_rhs)
		check_size_overflow(caller_node, stmt, TREE_TYPE(new_rhs1), new_rhs1, rhs, BEFORE_STMT);

	return dup_assign(visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);
}

static tree handle_unary_rhs(struct pointer_set_t *visited, struct cgraph_node *caller_node, gimple stmt)
{
	tree rhs1, new_rhs1, lhs = gimple_assign_lhs(stmt);

	if (gimple_plf(stmt, MY_STMT))
		return lhs;

	rhs1 = gimple_assign_rhs1(stmt);
	if (TREE_CODE(TREE_TYPE(rhs1)) == POINTER_TYPE)
		return create_assign(visited, stmt, lhs, AFTER_STMT);

	new_rhs1 = expand(visited, caller_node, rhs1);

	if (new_rhs1 == NULL_TREE)
		return create_cast_assign(visited, stmt);

	if (gimple_plf(stmt, NO_CAST_CHECK))
		return dup_assign(visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);

	if (gimple_assign_rhs_code(stmt) == BIT_NOT_EXPR) {
		tree size_overflow_type = get_size_overflow_type(stmt, rhs1);

		new_rhs1 = cast_to_new_size_overflow_type(stmt, new_rhs1, size_overflow_type, BEFORE_STMT);
		check_size_overflow(caller_node, stmt, size_overflow_type, new_rhs1, rhs1, BEFORE_STMT);
		return create_assign(visited, stmt, lhs, AFTER_STMT);
	}

	if (!gimple_assign_cast_p(stmt))
		return dup_assign(visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);

	return create_cast_overflow_check(visited, caller_node, new_rhs1, stmt);
}

static tree handle_unary_ops(struct pointer_set_t *visited, struct cgraph_node *caller_node, gimple stmt)
{
	tree rhs1, lhs = gimple_assign_lhs(stmt);
	gimple def_stmt = get_def_stmt(lhs);

	gcc_assert(gimple_code(def_stmt) != GIMPLE_NOP);
	rhs1 = gimple_assign_rhs1(def_stmt);

	if (is_gimple_constant(rhs1))
		return create_assign(visited, def_stmt, lhs, AFTER_STMT);

	switch (TREE_CODE(rhs1)) {
	case SSA_NAME:
		return handle_unary_rhs(visited, caller_node, def_stmt);
	case ARRAY_REF:
	case BIT_FIELD_REF:
	case ADDR_EXPR:
	case COMPONENT_REF:
	case INDIRECT_REF:
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case TARGET_MEM_REF:
	case VIEW_CONVERT_EXPR:
		return create_assign(visited, def_stmt, lhs, AFTER_STMT);
	case PARM_DECL:
	case VAR_DECL:
		return create_assign(visited, stmt, lhs, AFTER_STMT);

	default:
		debug_gimple_stmt(def_stmt);
		debug_tree(rhs1);
		gcc_unreachable();
	}
}

static void insert_cond(basic_block cond_bb, tree arg, enum tree_code cond_code, tree type_value)
{
	gimple cond_stmt;
	gimple_stmt_iterator gsi = gsi_last_bb(cond_bb);

	cond_stmt = gimple_build_cond(cond_code, arg, type_value, NULL_TREE, NULL_TREE);
	gsi_insert_after(&gsi, cond_stmt, GSI_CONTINUE_LINKING);
	update_stmt(cond_stmt);
}

static tree create_string_param(tree string)
{
	tree i_type, a_type;
	const int length = TREE_STRING_LENGTH(string);

	gcc_assert(length > 0);

	i_type = build_index_type(build_int_cst(NULL_TREE, length - 1));
	a_type = build_array_type(char_type_node, i_type);

	TREE_TYPE(string) = a_type;
	TREE_CONSTANT(string) = 1;
	TREE_READONLY(string) = 1;

	return build1(ADDR_EXPR, ptr_type_node, string);
}

static void insert_cond_result(struct cgraph_node *caller_node, basic_block bb_true, const_gimple stmt, const_tree arg, bool min)
{
	gimple func_stmt;
	const_gimple def_stmt;
	const_tree loc_line;
	tree loc_file, ssa_name, current_func;
	expanded_location xloc;
	char *ssa_name_buf;
	int len;
	struct cgraph_edge *edge;
	struct cgraph_node *callee_node;
	int frequency;
	gimple_stmt_iterator gsi = gsi_start_bb(bb_true);

	def_stmt = get_def_stmt(arg);
	xloc = expand_location(gimple_location(def_stmt));

	if (!gimple_has_location(def_stmt)) {
		xloc = expand_location(gimple_location(stmt));
		if (!gimple_has_location(stmt))
			xloc = expand_location(DECL_SOURCE_LOCATION(current_function_decl));
	}

	loc_line = build_int_cstu(unsigned_type_node, xloc.line);

	loc_file = build_string(strlen(xloc.file) + 1, xloc.file);
	loc_file = create_string_param(loc_file);

	current_func = build_string(DECL_NAME_LENGTH(current_function_decl) + 1, DECL_NAME_POINTER(current_function_decl));
	current_func = create_string_param(current_func);

	gcc_assert(DECL_NAME(SSA_NAME_VAR(arg)) != NULL);
	call_count++;
	len = asprintf(&ssa_name_buf, "%s_%u %s, count: %u\n", DECL_NAME_POINTER(SSA_NAME_VAR(arg)), SSA_NAME_VERSION(arg), min ? "min" : "max", call_count);
	gcc_assert(len > 0);
	ssa_name = build_string(len + 1, ssa_name_buf);
	free(ssa_name_buf);
	ssa_name = create_string_param(ssa_name);

	// void report_size_overflow(const char *file, unsigned int line, const char *func, const char *ssa_name)
	func_stmt = gimple_build_call(report_size_overflow_decl, 4, loc_file, loc_line, current_func, ssa_name);
	gsi_insert_after(&gsi, func_stmt, GSI_CONTINUE_LINKING);

	callee_node = cgraph_get_create_node(report_size_overflow_decl);
	frequency = compute_call_stmt_bb_frequency(current_function_decl, bb_true);

	edge = cgraph_create_edge(caller_node, callee_node, func_stmt, bb_true->count, frequency, bb_true->loop_depth);
	gcc_assert(edge != NULL);
}

static void __unused print_the_code_insertions(const_gimple stmt)
{
	location_t loc = gimple_location(stmt);

	inform(loc, "Integer size_overflow check applied here.");
}

static void insert_check_size_overflow(struct cgraph_node *caller_node, gimple stmt, enum tree_code cond_code, tree arg, tree type_value, bool before, bool min)
{
	basic_block cond_bb, join_bb, bb_true;
	edge e;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);

	cond_bb = gimple_bb(stmt);
	if (before)
		gsi_prev(&gsi);
	if (gsi_end_p(gsi))
		e = split_block_after_labels(cond_bb);
	else
		e = split_block(cond_bb, gsi_stmt(gsi));
	cond_bb = e->src;
	join_bb = e->dest;
	e->flags = EDGE_FALSE_VALUE;
	e->probability = REG_BR_PROB_BASE;

	bb_true = create_empty_bb(cond_bb);
	make_edge(cond_bb, bb_true, EDGE_TRUE_VALUE);
	make_edge(cond_bb, join_bb, EDGE_FALSE_VALUE);
	make_edge(bb_true, join_bb, EDGE_FALLTHRU);

	gcc_assert(dom_info_available_p(CDI_DOMINATORS));
	set_immediate_dominator(CDI_DOMINATORS, bb_true, cond_bb);
	set_immediate_dominator(CDI_DOMINATORS, join_bb, cond_bb);

	if (current_loops != NULL) {
		gcc_assert(cond_bb->loop_father == join_bb->loop_father);
		add_bb_to_loop(bb_true, cond_bb->loop_father);
	}

	insert_cond(cond_bb, arg, cond_code, type_value);
	insert_cond_result(caller_node, bb_true, stmt, arg, min);

//	print_the_code_insertions(stmt);
}

static void check_size_overflow(struct cgraph_node *caller_node, gimple stmt, tree size_overflow_type, tree cast_rhs, tree rhs, bool before)
{
	const_tree rhs_type = TREE_TYPE(rhs);
	tree cast_rhs_type, type_max_type, type_min_type, type_max, type_min;

	gcc_assert(rhs_type != NULL_TREE);
	if (TREE_CODE(rhs_type) == POINTER_TYPE)
		return;

	gcc_assert(TREE_CODE(rhs_type) == INTEGER_TYPE || TREE_CODE(rhs_type) == ENUMERAL_TYPE);

	if (is_const_plus_unsigned_signed_truncation(rhs))
		return;

	type_max = cast_a_tree(size_overflow_type, TYPE_MAX_VALUE(rhs_type));
	// typemax (-1) < typemin (0)
	if (TREE_OVERFLOW(type_max))
		return;

	type_min = cast_a_tree(size_overflow_type, TYPE_MIN_VALUE(rhs_type));

	cast_rhs_type = TREE_TYPE(cast_rhs);
	type_max_type = TREE_TYPE(type_max);
	gcc_assert(types_compatible_p(cast_rhs_type, type_max_type));

	insert_check_size_overflow(caller_node, stmt, GT_EXPR, cast_rhs, type_max, before, MAX_CHECK);

	// special case: get_size_overflow_type(), 32, u64->s
	if (LONG_TYPE_SIZE == GET_MODE_BITSIZE(SImode) && TYPE_UNSIGNED(size_overflow_type) && !TYPE_UNSIGNED(rhs_type))
		return;

	type_min_type = TREE_TYPE(type_min);
	gcc_assert(types_compatible_p(type_max_type, type_min_type));
	insert_check_size_overflow(caller_node, stmt, LT_EXPR, cast_rhs, type_min, before, MIN_CHECK);
}

static bool is_a_constant_overflow(const_gimple stmt, const_tree rhs)
{
	if (gimple_assign_rhs_code(stmt) == MIN_EXPR)
		return false;
	if (!is_gimple_constant(rhs))
		return false;
	return true;
}

static tree get_def_stmt_rhs(const_tree var)
{
	tree rhs1, def_stmt_rhs1;
	gimple rhs1_def_stmt, def_stmt_rhs1_def_stmt, def_stmt;

	def_stmt = get_def_stmt(var);
	if (!gimple_assign_cast_p(def_stmt))
		return NULL_TREE;
	gcc_assert(gimple_code(def_stmt) != GIMPLE_NOP && gimple_plf(def_stmt, MY_STMT) && gimple_assign_cast_p(def_stmt));

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs1_def_stmt = get_def_stmt(rhs1);
	if (!gimple_assign_cast_p(rhs1_def_stmt))
		return rhs1;

	def_stmt_rhs1 = gimple_assign_rhs1(rhs1_def_stmt);
	def_stmt_rhs1_def_stmt = get_def_stmt(def_stmt_rhs1);

	switch (gimple_code(def_stmt_rhs1_def_stmt)) {
	case GIMPLE_CALL:
	case GIMPLE_NOP:
	case GIMPLE_ASM:
	case GIMPLE_PHI:
		return def_stmt_rhs1;
	case GIMPLE_ASSIGN:
		return rhs1;
	default:
		debug_gimple_stmt(def_stmt_rhs1_def_stmt);
		gcc_unreachable();
	}
}

static tree handle_intentional_overflow(struct pointer_set_t *visited, struct cgraph_node *caller_node, bool check_overflow, gimple stmt, tree change_rhs, tree new_rhs2)
{
	tree new_rhs, orig_rhs;
	void (*gimple_assign_set_rhs)(gimple, tree);
	tree rhs1 = gimple_assign_rhs1(stmt);
	tree rhs2 = gimple_assign_rhs2(stmt);
	tree lhs = gimple_assign_lhs(stmt);

	if (!check_overflow)
		return create_assign(visited, stmt, lhs, AFTER_STMT);

	if (change_rhs == NULL_TREE)
		return create_assign(visited, stmt, lhs, AFTER_STMT);

	if (new_rhs2 == NULL_TREE) {
		orig_rhs = rhs1;
		gimple_assign_set_rhs = &gimple_assign_set_rhs1;
	} else {
		orig_rhs = rhs2;
		gimple_assign_set_rhs = &gimple_assign_set_rhs2;
	}

	check_size_overflow(caller_node, stmt, TREE_TYPE(change_rhs), change_rhs, orig_rhs, BEFORE_STMT);

	new_rhs = change_assign_rhs(stmt, orig_rhs, change_rhs);
	gimple_assign_set_rhs(stmt, new_rhs);
	update_stmt(stmt);

	return create_assign(visited, stmt, lhs, AFTER_STMT);
}

static bool is_subtraction_special(const_gimple stmt)
{
	gimple rhs1_def_stmt, rhs2_def_stmt;
	const_tree rhs1_def_stmt_rhs1, rhs2_def_stmt_rhs1, rhs1_def_stmt_lhs, rhs2_def_stmt_lhs;
	enum machine_mode rhs1_def_stmt_rhs1_mode, rhs2_def_stmt_rhs1_mode, rhs1_def_stmt_lhs_mode, rhs2_def_stmt_lhs_mode;
	const_tree rhs1 = gimple_assign_rhs1(stmt);
	const_tree rhs2 = gimple_assign_rhs2(stmt);

	if (is_gimple_constant(rhs1) || is_gimple_constant(rhs2))
		return false;

	gcc_assert(TREE_CODE(rhs1) == SSA_NAME && TREE_CODE(rhs2) == SSA_NAME);

	if (gimple_assign_rhs_code(stmt) != MINUS_EXPR)
		return false;

	rhs1_def_stmt = get_def_stmt(rhs1);
	rhs2_def_stmt = get_def_stmt(rhs2);
	if (!gimple_assign_cast_p(rhs1_def_stmt) || !gimple_assign_cast_p(rhs2_def_stmt))
		return false;

	rhs1_def_stmt_rhs1 = gimple_assign_rhs1(rhs1_def_stmt);
	rhs2_def_stmt_rhs1 = gimple_assign_rhs1(rhs2_def_stmt);
	rhs1_def_stmt_lhs = gimple_assign_lhs(rhs1_def_stmt);
	rhs2_def_stmt_lhs = gimple_assign_lhs(rhs2_def_stmt);
	rhs1_def_stmt_rhs1_mode = TYPE_MODE(TREE_TYPE(rhs1_def_stmt_rhs1));
	rhs2_def_stmt_rhs1_mode = TYPE_MODE(TREE_TYPE(rhs2_def_stmt_rhs1));
	rhs1_def_stmt_lhs_mode = TYPE_MODE(TREE_TYPE(rhs1_def_stmt_lhs));
	rhs2_def_stmt_lhs_mode = TYPE_MODE(TREE_TYPE(rhs2_def_stmt_lhs));
	if (GET_MODE_BITSIZE(rhs1_def_stmt_rhs1_mode) <= GET_MODE_BITSIZE(rhs1_def_stmt_lhs_mode))
		return false;
	if (GET_MODE_BITSIZE(rhs2_def_stmt_rhs1_mode) <= GET_MODE_BITSIZE(rhs2_def_stmt_lhs_mode))
		return false;

	gimple_set_plf(rhs1_def_stmt, NO_CAST_CHECK, true);
	gimple_set_plf(rhs2_def_stmt, NO_CAST_CHECK, true);
	return true;
}

static tree handle_integer_truncation(struct pointer_set_t *visited, struct cgraph_node *caller_node, const_tree lhs)
{
	tree new_rhs1, new_rhs2;
	tree new_rhs1_def_stmt_rhs1, new_rhs2_def_stmt_rhs1, new_lhs;
	gimple assign, stmt = get_def_stmt(lhs);
	tree rhs1 = gimple_assign_rhs1(stmt);
	tree rhs2 = gimple_assign_rhs2(stmt);

	if (!is_subtraction_special(stmt))
		return NULL_TREE;

	new_rhs1 = expand(visited, caller_node, rhs1);
	new_rhs2 = expand(visited, caller_node, rhs2);

	new_rhs1_def_stmt_rhs1 = get_def_stmt_rhs(new_rhs1);
	new_rhs2_def_stmt_rhs1 = get_def_stmt_rhs(new_rhs2);

	if (new_rhs1_def_stmt_rhs1 == NULL_TREE || new_rhs2_def_stmt_rhs1 == NULL_TREE)
		return NULL_TREE;

	if (!types_compatible_p(TREE_TYPE(new_rhs1_def_stmt_rhs1), TREE_TYPE(new_rhs2_def_stmt_rhs1))) {
		new_rhs1_def_stmt_rhs1 = cast_to_TI_type(stmt, new_rhs1_def_stmt_rhs1);
		new_rhs2_def_stmt_rhs1 = cast_to_TI_type(stmt, new_rhs2_def_stmt_rhs1);
	}

	assign = create_binary_assign(MINUS_EXPR, stmt, new_rhs1_def_stmt_rhs1, new_rhs2_def_stmt_rhs1);
	new_lhs = gimple_assign_lhs(assign);
	check_size_overflow(caller_node, assign, TREE_TYPE(new_lhs), new_lhs, rhs1, AFTER_STMT);

	return dup_assign(visited, stmt, lhs, new_rhs1, new_rhs2, NULL_TREE);
}

static bool is_a_neg_overflow(const_gimple stmt, const_tree rhs)
{
	const_gimple def_stmt;

	if (TREE_CODE(rhs) != SSA_NAME)
		return false;

	if (gimple_assign_rhs_code(stmt) != PLUS_EXPR)
		return false;

	def_stmt = get_def_stmt(rhs);
	if (!is_gimple_assign(def_stmt) || gimple_assign_rhs_code(def_stmt) != BIT_NOT_EXPR)
		return false;

	return true;
}

static tree handle_binary_ops(struct pointer_set_t *visited, struct cgraph_node *caller_node, tree lhs)
{
	tree rhs1, rhs2, new_lhs;
	gimple def_stmt = get_def_stmt(lhs);
	tree new_rhs1 = NULL_TREE;
	tree new_rhs2 = NULL_TREE;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);

	/* no DImode/TImode division in the 32/64 bit kernel */
	switch (gimple_assign_rhs_code(def_stmt)) {
	case RDIV_EXPR:
	case TRUNC_DIV_EXPR:
	case CEIL_DIV_EXPR:
	case FLOOR_DIV_EXPR:
	case ROUND_DIV_EXPR:
	case TRUNC_MOD_EXPR:
	case CEIL_MOD_EXPR:
	case FLOOR_MOD_EXPR:
	case ROUND_MOD_EXPR:
	case EXACT_DIV_EXPR:
	case POINTER_PLUS_EXPR:
	case BIT_AND_EXPR:
		return create_assign(visited, def_stmt, lhs, AFTER_STMT);
	default:
		break;
	}

	new_lhs = handle_integer_truncation(visited, caller_node, lhs);
	if (new_lhs != NULL_TREE)
		return new_lhs;

	if (TREE_CODE(rhs1) == SSA_NAME)
		new_rhs1 = expand(visited, caller_node, rhs1);
	if (TREE_CODE(rhs2) == SSA_NAME)
		new_rhs2 = expand(visited, caller_node, rhs2);

	if (is_a_neg_overflow(def_stmt, rhs2))
		return handle_intentional_overflow(visited, caller_node, true, def_stmt, new_rhs1, NULL_TREE);
	if (is_a_neg_overflow(def_stmt, rhs1))
		return handle_intentional_overflow(visited, caller_node, true, def_stmt, new_rhs2, new_rhs2);


	if (is_a_constant_overflow(def_stmt, rhs2))
		return handle_intentional_overflow(visited, caller_node, !is_a_cast_and_const_overflow(rhs1), def_stmt, new_rhs1, NULL_TREE);
	if (is_a_constant_overflow(def_stmt, rhs1))
		return handle_intentional_overflow(visited, caller_node, !is_a_cast_and_const_overflow(rhs2), def_stmt, new_rhs2, new_rhs2);

	return dup_assign(visited, def_stmt, lhs, new_rhs1, new_rhs2, NULL_TREE);
}

#if BUILDING_GCC_VERSION >= 4006
static tree get_new_rhs(struct pointer_set_t *visited, struct cgraph_node *caller_node, tree size_overflow_type, tree rhs)
{
	if (is_gimple_constant(rhs))
		return cast_a_tree(size_overflow_type, rhs);
	if (TREE_CODE(rhs) != SSA_NAME)
		return NULL_TREE;
	return expand(visited, caller_node, rhs);
}

static tree handle_ternary_ops(struct pointer_set_t *visited, struct cgraph_node *caller_node, tree lhs)
{
	tree rhs1, rhs2, rhs3, new_rhs1, new_rhs2, new_rhs3, size_overflow_type;
	gimple def_stmt = get_def_stmt(lhs);

	size_overflow_type = get_size_overflow_type(def_stmt, lhs);

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);
	rhs3 = gimple_assign_rhs3(def_stmt);
	new_rhs1 = get_new_rhs(visited, caller_node, size_overflow_type, rhs1);
	new_rhs2 = get_new_rhs(visited, caller_node, size_overflow_type, rhs2);
	new_rhs3 = get_new_rhs(visited, caller_node, size_overflow_type, rhs3);

	return dup_assign(visited, def_stmt, lhs, new_rhs1, new_rhs2, new_rhs3);
}
#endif

static tree get_size_overflow_type(gimple stmt, const_tree node)
{
	const_tree type;
	tree new_type;

	gcc_assert(node != NULL_TREE);

	type = TREE_TYPE(node);

	if (gimple_plf(stmt, MY_STMT))
		return TREE_TYPE(node);

	switch (TYPE_MODE(type)) {
	case QImode:
		new_type = intHI_type_node;
		break;
	case HImode:
		new_type = intSI_type_node;
		break;
	case SImode:
		new_type = intDI_type_node;
		break;
	case DImode:
		if (LONG_TYPE_SIZE == GET_MODE_BITSIZE(SImode))
			new_type = TYPE_UNSIGNED(type) ? unsigned_intDI_type_node : intDI_type_node;
		else
			new_type = intTI_type_node;
		break;
	case TImode:
		gcc_assert(!TYPE_UNSIGNED(type));
		new_type = intTI_type_node;
		break;
	default:
		debug_tree((tree)node);
		error("%s: unsupported gcc configuration (%qE).", __func__, current_function_decl);
		gcc_unreachable();
	}

	if (TYPE_QUALS(type) != 0)
		return build_qualified_type(new_type, TYPE_QUALS(type));
	return new_type;
}

static tree expand_visited(gimple def_stmt)
{
	const_gimple next_stmt;
	gimple_stmt_iterator gsi;
	enum gimple_code code = gimple_code(def_stmt);

	if (code == GIMPLE_ASM)
		return NULL_TREE;

	gsi = gsi_for_stmt(def_stmt);
	gsi_next(&gsi);

	if (gimple_code(def_stmt) == GIMPLE_PHI && gsi_end_p(gsi))
		return NULL_TREE;
	gcc_assert(!gsi_end_p(gsi));
	next_stmt = gsi_stmt(gsi);

	if (gimple_code(def_stmt) == GIMPLE_PHI && !gimple_plf((gimple)next_stmt, MY_STMT))
		return NULL_TREE;
	gcc_assert(gimple_plf((gimple)next_stmt, MY_STMT));

	return get_lhs(next_stmt);
}

static tree expand(struct pointer_set_t *visited, struct cgraph_node *caller_node, tree lhs)
{
	gimple def_stmt;

	def_stmt = get_def_stmt(lhs);

	if (!def_stmt || gimple_code(def_stmt) == GIMPLE_NOP)
		return NULL_TREE;

	if (gimple_plf(def_stmt, MY_STMT))
		return lhs;

	if (pointer_set_contains(visited, def_stmt))
		return expand_visited(def_stmt);

	switch (gimple_code(def_stmt)) {
	case GIMPLE_PHI:
		return handle_phi(visited, caller_node, lhs);
	case GIMPLE_CALL:
	case GIMPLE_ASM:
		return create_assign(visited, def_stmt, lhs, AFTER_STMT);
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			return handle_unary_ops(visited, caller_node, def_stmt);
		case 3:
			return handle_binary_ops(visited, caller_node, lhs);
#if BUILDING_GCC_VERSION >= 4006
		case 4:
			return handle_ternary_ops(visited, caller_node, lhs);
#endif
		}
	default:
		debug_gimple_stmt(def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
}

static tree cast_to_orig_type(gimple stmt, const_tree orig_node, tree new_node)
{
	const_gimple assign;
	tree orig_type = TREE_TYPE(orig_node);
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);

	assign = build_cast_stmt(orig_type, new_node, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	return gimple_assign_lhs(assign);
}

static void change_orig_node(struct interesting_node *cur_node, tree new_node)
{
	void (*set_rhs)(gimple, tree);
	gimple stmt = cur_node->first_stmt;
	const_tree orig_node = cur_node->node;

	switch (gimple_code(stmt)) {
	case GIMPLE_RETURN:
		gimple_return_set_retval(stmt, cast_to_orig_type(stmt, orig_node, new_node));
		break;
	case GIMPLE_CALL:
		gimple_call_set_arg(stmt, cur_node->num - 1, cast_to_orig_type(stmt, orig_node, new_node));
		break;
	case GIMPLE_ASSIGN:
		switch (cur_node->num) {
		case 1:
			set_rhs = &gimple_assign_set_rhs1;
			break;
		case 2:
			set_rhs = &gimple_assign_set_rhs2;
			break;
#if BUILDING_GCC_VERSION >= 4006
		case 3:
			set_rhs = &gimple_assign_set_rhs3;
			break;
#endif
		default:
			gcc_unreachable();
		}

		set_rhs(stmt, cast_to_orig_type(stmt, orig_node, new_node));
		break;
	default:
		debug_gimple_stmt(stmt);
		gcc_unreachable();
	}

	update_stmt(stmt);
}

static unsigned int get_correct_arg_count(unsigned int argnum, const_tree fndecl)
{
	const struct size_overflow_hash *hash;
	unsigned int new_argnum;
	tree arg;
	const_tree origarg;

	if (argnum == 0)
		return argnum;

	hash = get_function_hash(fndecl);
	if (hash && hash->param & (1U << argnum))
		return argnum;

	if (DECL_EXTERNAL(fndecl))
		return argnum;

	origarg = DECL_ARGUMENTS(DECL_ORIGIN(fndecl));
	argnum--;
	while (origarg && argnum) {
		origarg = TREE_CHAIN(origarg);
		argnum--;
	}
	gcc_assert(argnum == 0);
	gcc_assert(origarg != NULL_TREE);

	for (arg = DECL_ARGUMENTS(fndecl), new_argnum = 1; arg; arg = TREE_CHAIN(arg), new_argnum++)
		if (operand_equal_p(origarg, arg, 0) || !strcmp(DECL_NAME_POINTER(origarg), DECL_NAME_POINTER(arg)))
			return new_argnum;

	return CANNOT_FIND_ARG;
}

// Don't want to duplicate entries in next_cgraph_node
static bool is_in_next_cgraph_node(struct next_cgraph_node *head, struct cgraph_node *node, const_tree fndecl, unsigned int num)
{
	const_tree new_callee_fndecl;
	struct next_cgraph_node *cur_node;

	if (fndecl == RET_CHECK)
		new_callee_fndecl = NODE_DECL(node);
	else
		new_callee_fndecl = fndecl;

	for (cur_node = head; cur_node; cur_node = cur_node->next) {
		if (!operand_equal_p(NODE_DECL(cur_node->current_function), NODE_DECL(node), 0))
			continue;
		if (!operand_equal_p(cur_node->callee_fndecl, new_callee_fndecl, 0))
			continue;
		if (num == cur_node->num)
			return true;
	}
	return false;
}

/* Add a next_cgraph_node into the list for handle_function().
 * handle_function()  iterates over all the next cgraph nodes and
 * starts the overflow check insertion process.
 */
static struct next_cgraph_node *create_new_next_cgraph_node(struct next_cgraph_node *head, struct cgraph_node *node, tree fndecl, unsigned int num)
{
	struct next_cgraph_node *new_node;

	if (is_in_next_cgraph_node(head, node, fndecl, num))
		return head;

	new_node = (struct next_cgraph_node *)xmalloc(sizeof(*new_node));
	new_node->current_function = node;
	new_node->next = NULL;
	new_node->num = num;
	if (fndecl == RET_CHECK)
		new_node->callee_fndecl = NODE_DECL(node);
	else
		new_node->callee_fndecl = fndecl;

	if (!head)
		return new_node;

	new_node->next = head;
	return new_node;
}

static struct next_cgraph_node *create_new_next_cgraph_nodes(struct next_cgraph_node *head, struct cgraph_node *node, unsigned int num)
{
	struct cgraph_edge *e;

	if (num == 0)
		return create_new_next_cgraph_node(head, node, RET_CHECK, num);

	for (e = node->callers; e; e = e->next_caller) {
		tree fndecl = gimple_call_fndecl(e->call_stmt);

		gcc_assert(fndecl != NULL_TREE);
		head = create_new_next_cgraph_node(head, e->caller, fndecl, num);
	}

	return head;
}

static bool is_a_return_check(const_tree node)
{
	if (TREE_CODE(node) == FUNCTION_DECL)
		return true;

	gcc_assert(TREE_CODE(node) == PARM_DECL);
	return false;
}

static bool is_in_hash_table(const_tree fndecl, unsigned int num)
{
	const struct size_overflow_hash *hash;

	hash = get_function_hash(fndecl);
	if (hash && (hash->param & (1U << num)))
		return true;
	return false;
}

struct missing_functions {
	struct missing_functions *next;
	const_tree node;
	tree fndecl;
};

static struct missing_functions *create_new_missing_function(struct missing_functions *missing_fn_head, tree node)
{
	struct missing_functions *new_function;

	new_function = (struct missing_functions *)xmalloc(sizeof(*new_function));
	new_function->node = node;
	new_function->next = NULL;

	if (TREE_CODE(node) == FUNCTION_DECL)
		new_function->fndecl = node;
	else
		new_function->fndecl = current_function_decl;
	gcc_assert(new_function->fndecl);

	if (!missing_fn_head)
		return new_function;

	new_function->next = missing_fn_head;
	return new_function;
}

/* Check if the function has a size_overflow attribute or it is in the size_overflow hash table.
 * If the function is missing everywhere then print the missing message into stderr.
 */
static bool is_missing_function(const_tree orig_fndecl, unsigned int num)
{
	switch (DECL_FUNCTION_CODE(orig_fndecl)) {
#if BUILDING_GCC_VERSION >= 4008
	case BUILT_IN_BSWAP16:
#endif
	case BUILT_IN_BSWAP32:
	case BUILT_IN_BSWAP64:
	case BUILT_IN_EXPECT:
	case BUILT_IN_MEMCMP:
		return false;
	default:
		break;
	}

	// skip test.c
	if (strcmp(DECL_NAME_POINTER(current_function_decl), "coolmalloc")) {
		if (lookup_attribute("size_overflow", DECL_ATTRIBUTES(orig_fndecl)))
			warning(0, "unnecessary size_overflow attribute on: %s\n", DECL_NAME_POINTER(orig_fndecl));
	}

	if (is_in_hash_table(orig_fndecl, num))
		return false;

	print_missing_msg(orig_fndecl, num);
	return true;
}

// Get the argnum of a function decl, if node is a return then the argnum is 0
static unsigned int get_function_num(const_tree node, const_tree orig_fndecl)
{
	if (is_a_return_check(node))
		return 0;
	else
		return find_arg_number_tree(node, orig_fndecl);
}

/* If the function is missing from the hash table and it is a static function
 * then create a next_cgraph_node from it for handle_function()
 */
static struct next_cgraph_node *check_missing_overflow_attribute_and_create_next_node(struct next_cgraph_node *cnodes, struct missing_functions *missing_fn_head)
{
	unsigned int num;
	const_tree orig_fndecl;
	struct cgraph_node *next_node = NULL;

	orig_fndecl = DECL_ORIGIN(missing_fn_head->fndecl);

	num = get_function_num(missing_fn_head->node, orig_fndecl);
	if (num == CANNOT_FIND_ARG)
		return cnodes;

	if (!is_missing_function(orig_fndecl, num))
		return cnodes;

	next_node = cgraph_get_node(missing_fn_head->fndecl);
	if (next_node && next_node->local.local)
		cnodes = create_new_next_cgraph_nodes(cnodes, next_node, num);
	return cnodes;
}

/* Search for missing size_overflow attributes on the last nodes in ipa and collect them
 * into the next_cgraph_node list. They will be the next interesting returns or callees.
 */
static struct next_cgraph_node *search_overflow_attribute(struct next_cgraph_node *cnodes, struct interesting_node *cur_node)
{
	unsigned int i;
	tree node;
	struct missing_functions *cur, *missing_fn_head = NULL;

#if BUILDING_GCC_VERSION <= 4007
	FOR_EACH_VEC_ELT(tree, cur_node->last_nodes, i, node) {
#else
	FOR_EACH_VEC_ELT(*cur_node->last_nodes, i, node) {
#endif
		switch (TREE_CODE(node)) {
		case PARM_DECL:
			if (TREE_CODE(TREE_TYPE(node)) != INTEGER_TYPE)
				break;
		case FUNCTION_DECL:
			missing_fn_head = create_new_missing_function(missing_fn_head, node);
			break;
		default:
			break;
		}
	}

	while (missing_fn_head) {
		cnodes = check_missing_overflow_attribute_and_create_next_node(cnodes, missing_fn_head);

		cur = missing_fn_head->next;
		free(missing_fn_head);
		missing_fn_head = cur;
	}

	return cnodes;
}

static void walk_phi_set_conditions(struct pointer_set_t *visited, bool *interesting_conditions, const_tree result)
{
	gimple phi = get_def_stmt(result);
	unsigned int i, n = gimple_phi_num_args(phi);

	pointer_set_insert(visited, phi);
	for (i = 0; i < n; i++) {
		const_tree arg = gimple_phi_arg_def(phi, i);

		set_conditions(visited, interesting_conditions, arg);
	}
}

enum conditions {
	FROM_CONST, NOT_UNARY, CAST
};

// Search for constants, cast assignments and binary/ternary assignments
static void set_conditions(struct pointer_set_t *visited, bool *interesting_conditions, const_tree lhs)
{
	gimple def_stmt = get_def_stmt(lhs);

	if (is_gimple_constant(lhs)) {
		interesting_conditions[FROM_CONST] = true;
		return;
	}

	if (!def_stmt)
		return;

	if (pointer_set_contains(visited, def_stmt))
		return;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
	case GIMPLE_CALL:
	case GIMPLE_ASM:
		return;
	case GIMPLE_PHI:
		return walk_phi_set_conditions(visited, interesting_conditions, lhs);
	case GIMPLE_ASSIGN:
		if (gimple_num_ops(def_stmt) == 2) {
			const_tree rhs = gimple_assign_rhs1(def_stmt);

			if (gimple_assign_cast_p(def_stmt))
				interesting_conditions[CAST] = true;

			return set_conditions(visited, interesting_conditions, rhs);
		} else {
			interesting_conditions[NOT_UNARY] = true;
			return;
		}
	default:
		debug_gimple_stmt(def_stmt);
		gcc_unreachable();
	}
}

// determine whether duplication will be necessary or not.
static void search_interesting_conditions(struct interesting_node *cur_node, bool *interesting_conditions)
{
	struct pointer_set_t *visited;

	if (gimple_assign_cast_p(cur_node->first_stmt))
		interesting_conditions[CAST] = true;
	else if (is_gimple_assign(cur_node->first_stmt) && gimple_num_ops(cur_node->first_stmt) > 2)
		interesting_conditions[NOT_UNARY] = true;

	visited = pointer_set_create();
	set_conditions(visited, interesting_conditions, cur_node->node);
	pointer_set_destroy(visited);
}

// Remove the size_overflow asm stmt and create an assignment from the input and output of the asm
static void replace_size_overflow_asm_with_assign(gimple asm_stmt, tree lhs, tree rhs)
{
	gimple assign;
	gimple_stmt_iterator gsi;

	// already removed
	if (gimple_bb(asm_stmt) == NULL)
		return;
	gsi = gsi_for_stmt(asm_stmt);

	assign = gimple_build_assign(lhs, rhs);
	gsi_insert_before(&gsi, assign, GSI_SAME_STMT);
	SSA_NAME_DEF_STMT(lhs) = assign;

	gsi_remove(&gsi, true);
}

// Get the field decl of a component ref for intentional_overflow checking
static const_tree search_field_decl(const_tree comp_ref)
{
	const_tree field = NULL_TREE;
	unsigned int i, len = TREE_OPERAND_LENGTH(comp_ref);

	for (i = 0; i < len; i++) {
		field = TREE_OPERAND(comp_ref, i);
		if (TREE_CODE(field) == FIELD_DECL)
			break;
	}
	gcc_assert(TREE_CODE(field) == FIELD_DECL);
	return field;
}

/* Get the fndecl of an interesting stmt, the fndecl is the caller function if the interesting
 * stmt is a return otherwise it is the callee function.
 */
static const_tree get_interesting_orig_fndecl(const_gimple stmt, unsigned int argnum)
{
	const_tree fndecl;

	if (argnum == 0)
		fndecl = current_function_decl;
	else
		fndecl = gimple_call_fndecl(stmt);

	if (fndecl == NULL_TREE)
		return NULL_TREE;

	return DECL_ORIGIN(fndecl);
}

/* Get the param of the intentional_overflow attribute.
 *   * 0: MARK_NOT_INTENTIONAL
 *   * 1..MAX_PARAM: MARK_YES
 *   * -1: MARK_TURN_OFF
 */
static tree get_attribute_param(const_tree decl)
{
	const_tree attr;

	if (decl == NULL_TREE)
		return NULL_TREE;

	attr = lookup_attribute("intentional_overflow", DECL_ATTRIBUTES(decl));
	if (!attr || !TREE_VALUE(attr))
		return NULL_TREE;

	return TREE_VALUE(attr);
}

// MARK_TURN_OFF
static bool is_turn_off_intentional_attr(const_tree decl)
{
	const_tree param_head;

	param_head = get_attribute_param(decl);
	if (param_head == NULL_TREE)
		return false;

	if (TREE_INT_CST_HIGH(TREE_VALUE(param_head)) == -1)
		return true;
	return false;
}

// MARK_NOT_INTENTIONAL
static bool is_end_intentional_intentional_attr(const_tree decl, unsigned int argnum)
{
	const_tree param_head;

	if (argnum == 0)
		return false;

	param_head = get_attribute_param(decl);
	if (param_head == NULL_TREE)
		return false;

	if (!TREE_INT_CST_LOW(TREE_VALUE(param_head)))
		return true;
	return false;
}

// MARK_YES
static bool is_yes_intentional_attr(const_tree decl, unsigned int argnum)
{
	tree param, param_head;

	if (argnum == 0)
		return false;

	param_head = get_attribute_param(decl);
	for (param = param_head; param; param = TREE_CHAIN(param))
		if (argnum == TREE_INT_CST_LOW(TREE_VALUE(param)))
			return true;
	return false;
}

static const char *get_asm_string(const_gimple stmt)
{
	if (!stmt)
		return NULL;
	if (gimple_code(stmt) != GIMPLE_ASM)
		return NULL;

	return gimple_asm_string(stmt);
}

static bool is_size_overflow_intentional_asm_turn_off(const_gimple stmt)
{
	const char *str;

	str = get_asm_string(stmt);
	if (!str)
		return false;
	return !strncmp(str, TURN_OFF_ASM_STR, sizeof(TURN_OFF_ASM_STR) - 1);
}

static bool is_size_overflow_intentional_asm_yes(const_gimple stmt)
{
	const char *str;

	str = get_asm_string(stmt);
	if (!str)
		return false;
	return !strncmp(str, YES_ASM_STR, sizeof(YES_ASM_STR) - 1);
}

static bool is_size_overflow_asm(const_gimple stmt)
{
	const char *str;

	str = get_asm_string(stmt);
	if (!str)
		return false;
	return !strncmp(str, OK_ASM_STR, sizeof(OK_ASM_STR) - 1);
}

static void print_missing_intentional(enum mark callee_attr, enum mark caller_attr, const_tree decl, unsigned int argnum)
{
	location_t loc;

	if (caller_attr == MARK_NO || caller_attr == MARK_NOT_INTENTIONAL || caller_attr == MARK_TURN_OFF)
		return;

	if (callee_attr == MARK_NOT_INTENTIONAL || callee_attr == MARK_YES)
		return;

	loc = DECL_SOURCE_LOCATION(decl);
	inform(loc, "The intentional_overflow attribute is missing from +%s+%u+", DECL_NAME_POINTER(decl), argnum);
}

/* Get the type of the intentional_overflow attribute of a node
 *  * MARK_TURN_OFF
 *  * MARK_YES
 *  * MARK_NO
 *  * MARK_NOT_INTENTIONAL
 */
static enum mark get_intentional_attr_type(const_tree node)
{
	const_tree cur_decl;

	if (node == NULL_TREE)
		return MARK_NO;

	switch (TREE_CODE(node)) {
	case COMPONENT_REF:
		cur_decl = search_field_decl(node);
		if (is_turn_off_intentional_attr(cur_decl))
			return MARK_TURN_OFF;
		if (is_end_intentional_intentional_attr(cur_decl, 1))
			return MARK_YES;
		break;
	case PARM_DECL: {
		unsigned int argnum;

		cur_decl = DECL_ORIGIN(current_function_decl);
		argnum = find_arg_number_tree(node, cur_decl);
		if (argnum == CANNOT_FIND_ARG)
			return MARK_NO;
		if (is_yes_intentional_attr(cur_decl, argnum))
			return MARK_YES;
		if (is_end_intentional_intentional_attr(cur_decl, argnum))
			return MARK_NOT_INTENTIONAL;
		break;
	}
	case FUNCTION_DECL:
		if (is_turn_off_intentional_attr(DECL_ORIGIN(node)))
			return MARK_TURN_OFF;
		break;
	default:
		break;
	}
	return MARK_NO;
}

// Search for the intentional_overflow attribute on the last nodes
static enum mark search_last_nodes_intentional(struct interesting_node *cur_node)
{
	unsigned int i;
	tree last_node;
	enum mark mark = MARK_NO;

#if BUILDING_GCC_VERSION <= 4007
	FOR_EACH_VEC_ELT(tree, cur_node->last_nodes, i, last_node) {
#else
	FOR_EACH_VEC_ELT(*cur_node->last_nodes, i, last_node) {
#endif
		mark = get_intentional_attr_type(last_node);
		if (mark != MARK_NO)
			break;
	}
	return mark;
}

/* Check the intentional kind of size_overflow asm stmt (created by the gimple pass) and
 * set the appropriate intentional_overflow type. Delete the asm stmt in the end.
 */
static bool is_intentional_attribute_from_gimple(struct interesting_node *cur_node)
{
	if (!cur_node->intentional_mark_from_gimple)
		return false;

	if (is_size_overflow_intentional_asm_yes(cur_node->intentional_mark_from_gimple))
		cur_node->intentional_attr_cur_fndecl = MARK_YES;
	else
		cur_node->intentional_attr_cur_fndecl = MARK_TURN_OFF;

	// skip param decls
	if (gimple_asm_noutputs(cur_node->intentional_mark_from_gimple) == 0)
		return true;
	return true;
}

/* Search intentional_overflow attribute on caller and on callee too.
 * 0</MARK_YES: no dup, search size_overflow and intentional_overflow attributes
 * 0/MARK_NOT_INTENTIONAL: no dup, search size_overflow attribute (int)
 * -1/MARK_TURN_OFF: no dup, no search, current_function_decl -> no dup
*/
static void check_intentional_attribute_ipa(struct interesting_node *cur_node)
{
	const_tree fndecl;

	if (is_intentional_attribute_from_gimple(cur_node))
		return;

	if (is_turn_off_intentional_attr(DECL_ORIGIN(current_function_decl))) {
		cur_node->intentional_attr_cur_fndecl = MARK_TURN_OFF;
		return;
	}

	if (gimple_code(cur_node->first_stmt) == GIMPLE_ASM) {
		cur_node->intentional_attr_cur_fndecl = MARK_NOT_INTENTIONAL;
		return;
	}

	if (gimple_code(cur_node->first_stmt) == GIMPLE_ASSIGN)
		return;

	fndecl = get_interesting_orig_fndecl(cur_node->first_stmt, cur_node->num);
	if (is_turn_off_intentional_attr(fndecl)) {
		cur_node->intentional_attr_decl = MARK_TURN_OFF;
		return;
	}

	if (is_end_intentional_intentional_attr(fndecl, cur_node->num))
		cur_node->intentional_attr_decl = MARK_NOT_INTENTIONAL;
	else if (is_yes_intentional_attr(fndecl, cur_node->num))
		cur_node->intentional_attr_decl = MARK_YES;

	cur_node->intentional_attr_cur_fndecl = search_last_nodes_intentional(cur_node);
	print_missing_intentional(cur_node->intentional_attr_decl, cur_node->intentional_attr_cur_fndecl, cur_node->fndecl, cur_node->num);
}

// e.g., 3.8.2, 64, arch/x86/ia32/ia32_signal.c copy_siginfo_from_user32(): compat_ptr() u32 max
static bool skip_asm(const_tree arg)
{
	gimple def_stmt = get_def_stmt(arg);

	if (!def_stmt || !gimple_assign_cast_p(def_stmt))
		return false;

	def_stmt = get_def_stmt(gimple_assign_rhs1(def_stmt));
	return def_stmt && gimple_code(def_stmt) == GIMPLE_ASM;
}

static void walk_use_def_phi(struct pointer_set_t *visited, struct interesting_node *cur_node, tree result)
{
	gimple phi = get_def_stmt(result);
	unsigned int i, n = gimple_phi_num_args(phi);

	pointer_set_insert(visited, phi);
	for (i = 0; i < n; i++) {
		tree arg = gimple_phi_arg_def(phi, i);

		walk_use_def(visited, cur_node, arg);
	}
}

static void walk_use_def_binary(struct pointer_set_t *visited, struct interesting_node *cur_node, tree lhs)
{
	gimple def_stmt = get_def_stmt(lhs);
	tree rhs1, rhs2;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);

	walk_use_def(visited, cur_node, rhs1);
	walk_use_def(visited, cur_node, rhs2);
}

static void insert_last_node(struct interesting_node *cur_node, tree node)
{
	unsigned int i;
	tree element;
	enum tree_code code;

	gcc_assert(node != NULL_TREE);

	if (is_gimple_constant(node))
		return;

	code = TREE_CODE(node);
	if (code == VAR_DECL) {
		node = DECL_ORIGIN(node);
		code = TREE_CODE(node);
	}

	if (code != PARM_DECL && code != FUNCTION_DECL && code != COMPONENT_REF)
		return;

#if BUILDING_GCC_VERSION <= 4007
	FOR_EACH_VEC_ELT(tree, cur_node->last_nodes, i, element) {
#else
	FOR_EACH_VEC_ELT(*cur_node->last_nodes, i, element) {
#endif
		if (operand_equal_p(node, element, 0))
			return;
	}

#if BUILDING_GCC_VERSION <= 4007
	gcc_assert(VEC_length(tree, cur_node->last_nodes) < VEC_LEN);
	VEC_safe_push(tree, gc, cur_node->last_nodes, node);
#else
	gcc_assert(cur_node->last_nodes->length() < VEC_LEN);
	vec_safe_push(cur_node->last_nodes, node);
#endif
}

// a size_overflow asm stmt in the control flow doesn't stop the recursion
static void handle_asm_stmt(struct pointer_set_t *visited, struct interesting_node *cur_node, tree lhs, const_gimple stmt)
{
	if (!is_size_overflow_asm(stmt))
		walk_use_def(visited, cur_node, SSA_NAME_VAR(lhs));
}

/* collect the parm_decls and fndecls (for checking a missing size_overflow attribute (ret or arg) or intentional_overflow)
 * and component refs (for checking the intentional_overflow attribute).
 */
static void walk_use_def(struct pointer_set_t *visited, struct interesting_node *cur_node, tree lhs)
{
	const_gimple def_stmt;

	if (TREE_CODE(lhs) != SSA_NAME) {
		insert_last_node(cur_node, lhs);
		return;
	}

	def_stmt = get_def_stmt(lhs);
	if (!def_stmt)
		return;

	if (pointer_set_insert(visited, def_stmt))
		return;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
		return walk_use_def(visited, cur_node, SSA_NAME_VAR(lhs));
	case GIMPLE_ASM:
		return handle_asm_stmt(visited, cur_node, lhs, def_stmt);
	case GIMPLE_CALL: {
		tree fndecl = gimple_call_fndecl(def_stmt);

		if (fndecl == NULL_TREE)
			return;
		insert_last_node(cur_node, fndecl);
		return;
	}
	case GIMPLE_PHI:
		return walk_use_def_phi(visited, cur_node, lhs);
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			return walk_use_def(visited, cur_node, gimple_assign_rhs1(def_stmt));
		case 3:
			return walk_use_def_binary(visited, cur_node, lhs);
		}
	default:
		debug_gimple_stmt((gimple)def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
}

// Collect all the last nodes for checking the intentional_overflow and size_overflow attributes
static void set_last_nodes(struct interesting_node *cur_node)
{
	struct pointer_set_t *visited;

	visited = pointer_set_create();
	walk_use_def(visited, cur_node, cur_node->node);
	pointer_set_destroy(visited);
}

enum precond {
	NO_ATTRIBUTE_SEARCH, NO_CHECK_INSERT, NONE
};

/* If there is a mark_turn_off intentional attribute on the caller or the callee then there is no duplication and missing size_overflow attribute check anywhere.
 * There is only missing size_overflow attribute checking if the intentional_overflow attribute is the mark_no type.
 * Stmt duplication is unnecessary if there are no binary/ternary assignements or if the unary assignment isn't a cast.
 * It skips the possible error codes too. If the def_stmts trace back to a constant and there are no binary/ternary assigments then we assume that it is some kind of error code.
 */
static enum precond check_preconditions(struct interesting_node *cur_node)
{
	bool interesting_conditions[3] = {false, false, false};

	set_last_nodes(cur_node);

	check_intentional_attribute_ipa(cur_node);
	if (cur_node->intentional_attr_decl == MARK_TURN_OFF || cur_node->intentional_attr_cur_fndecl == MARK_TURN_OFF)
		return NO_ATTRIBUTE_SEARCH;

	search_interesting_conditions(cur_node, interesting_conditions);

	// error code
	if (interesting_conditions[CAST] && interesting_conditions[FROM_CONST] && !interesting_conditions[NOT_UNARY])
		return NO_ATTRIBUTE_SEARCH;

	// unnecessary overflow check
	if (!interesting_conditions[CAST] && !interesting_conditions[NOT_UNARY])
		return NO_CHECK_INSERT;

	if (cur_node->intentional_attr_cur_fndecl != MARK_NO)
		return NO_CHECK_INSERT;

	return NONE;
}

/* This function calls the main recursion function (expand) that duplicates the stmts. Before that it checks the intentional_overflow attribute and asm stmts,
 * it decides whether the duplication is necessary or not and it searches for missing size_overflow attributes. After expand() it changes the orig node to the duplicated node
 * in the original stmt (first stmt) and it inserts the overflow check for the arg of the callee or for the return value.
 */
static struct next_cgraph_node *handle_interesting_stmt(struct next_cgraph_node *cnodes, struct interesting_node *cur_node, struct cgraph_node *caller_node)
{
	enum precond ret;
	struct pointer_set_t *visited;
	tree new_node, orig_node = cur_node->node;

	ret = check_preconditions(cur_node);
	if (ret == NO_ATTRIBUTE_SEARCH)
		return cnodes;

	cnodes = search_overflow_attribute(cnodes, cur_node);

	if (ret == NO_CHECK_INSERT)
		return cnodes;

	visited = pointer_set_create();
	new_node = expand(visited, caller_node, orig_node);
	pointer_set_destroy(visited);

	if (new_node == NULL_TREE)
		return cnodes;

	change_orig_node(cur_node, new_node);
	check_size_overflow(caller_node, cur_node->first_stmt, TREE_TYPE(new_node), new_node, orig_node, BEFORE_STMT);

	return cnodes;
}

// Check visited interesting nodes.
static bool is_in_interesting_node(struct interesting_node *head, const_gimple first_stmt, const_tree node, unsigned int num)
{
	struct interesting_node *cur;

	for (cur = head; cur; cur = cur->next) {
		if (!operand_equal_p(node, cur->node, 0))
			continue;
		if (num != cur->num)
			continue;
		if (first_stmt == cur->first_stmt)
			return true;
	}
	return false;
}

/* Create an interesting node. The ipa pass starts to duplicate from these stmts.
   first_stmt: it is the call or assignment or ret stmt, change_orig_node() will change the original node (retval, or function arg) in this
   last_nodes: they are the last stmts in the recursion (they haven't a def_stmt). They are useful in the missing size_overflow attribute check and
               the intentional_overflow attribute check. They are collected by set_last_nodes().
   num: arg count of a call stmt or 0 when it is a ret
   node: the recursion starts from here, it is a call arg or a return value
   fndecl: the fndecl of the interesting node when the node is an arg. it is the fndecl of the callee function otherwise it is the fndecl of the caller (current_function_fndecl) function.
   intentional_attr_decl: intentional_overflow attribute of the callee function
   intentional_attr_cur_fndecl: intentional_overflow attribute of the caller function
   intentional_mark_from_gimple: the intentional overflow type of size_overflow asm stmt from gimple if it exists
 */
static struct interesting_node *create_new_interesting_node(struct interesting_node *head, gimple first_stmt, tree node, unsigned int num, gimple asm_stmt)
{
	struct interesting_node *new_node;
	tree fndecl;
	enum gimple_code code;

	gcc_assert(node != NULL_TREE);
	code = gimple_code(first_stmt);
	gcc_assert(code == GIMPLE_CALL || code == GIMPLE_ASM || code == GIMPLE_ASSIGN || code == GIMPLE_RETURN);

	if (num == CANNOT_FIND_ARG)
		return head;

	if (skip_types(node))
		return head;

	if (skip_asm(node))
		return head;

	if (is_gimple_call(first_stmt))
		fndecl = gimple_call_fndecl(first_stmt);
	else
		fndecl = current_function_decl;

	if (fndecl == NULL_TREE)
		return head;

	if (is_in_interesting_node(head, first_stmt, node, num))
		return head;

	new_node = (struct interesting_node *)xmalloc(sizeof(*new_node));

	new_node->next = NULL;
	new_node->first_stmt = first_stmt;
#if BUILDING_GCC_VERSION <= 4007
	new_node->last_nodes = VEC_alloc(tree, gc, VEC_LEN);
#else
	vec_alloc(new_node->last_nodes, VEC_LEN);
#endif
	new_node->num = num;
	new_node->node = node;
	new_node->fndecl = fndecl;
	new_node->intentional_attr_decl = MARK_NO;
	new_node->intentional_attr_cur_fndecl = MARK_NO;
	new_node->intentional_mark_from_gimple = asm_stmt;

	if (!head)
		return new_node;

	new_node->next = head;
	return new_node;
}

/* Check the ret stmts in the functions on the next cgraph node list (these functions will be in the hash table and they are reachable from ipa).
 * If the ret stmt is in the next cgraph node list then it's an interesting ret.
 */
static struct interesting_node *handle_stmt_by_cgraph_nodes_ret(struct interesting_node *head, gimple stmt, struct next_cgraph_node *next_node)
{
	struct next_cgraph_node *cur_node;
	tree ret = gimple_return_retval(stmt);

	if (ret == NULL_TREE)
		return head;

	for (cur_node = next_node; cur_node; cur_node = cur_node->next) {
		if (!operand_equal_p(cur_node->callee_fndecl, DECL_ORIGIN(current_function_decl), 0))
			continue;
		if (cur_node->num == 0)
			head = create_new_interesting_node(head, stmt, ret, 0, NOT_INTENTIONAL_ASM);
	}

	return head;
}

/* Check the call stmts in the functions on the next cgraph node list (these functions will be in the hash table and they are reachable from ipa).
 * If the call stmt is in the next cgraph node list then it's an interesting call.
 */
static struct interesting_node *handle_stmt_by_cgraph_nodes_call(struct interesting_node *head, gimple stmt, struct next_cgraph_node *next_node)
{
	unsigned int argnum;
	tree arg;
	const_tree fndecl;
	struct next_cgraph_node *cur_node;

	fndecl = gimple_call_fndecl(stmt);
	if (fndecl == NULL_TREE)
		return head;

	for (cur_node = next_node; cur_node; cur_node = cur_node->next) {
		if (!operand_equal_p(cur_node->callee_fndecl, fndecl, 0))
			continue;
		argnum = get_correct_arg_count(cur_node->num, fndecl);
		gcc_assert(argnum != CANNOT_FIND_ARG);
		if (argnum == 0)
			continue;

		arg = gimple_call_arg(stmt, argnum - 1);
		head = create_new_interesting_node(head, stmt, arg, argnum, NOT_INTENTIONAL_ASM);
	}

	return head;
}

static unsigned int check_ops(const_tree orig_node, const_tree node, unsigned int ret_count)
{
	if (!operand_equal_p(orig_node, node, 0))
		return WRONG_NODE;
	if (skip_types(node))
		return WRONG_NODE;
	return ret_count;
}

// Get the index of the rhs node in an assignment
static unsigned int get_assign_ops_count(const_gimple stmt, tree node)
{
	const_tree rhs1, rhs2;
	unsigned int ret;

	gcc_assert(stmt);
	gcc_assert(is_gimple_assign(stmt));

	rhs1 = gimple_assign_rhs1(stmt);
	gcc_assert(rhs1 != NULL_TREE);

	switch (gimple_num_ops(stmt)) {
	case 2:
		return check_ops(node, rhs1, 1);
	case 3:
		ret = check_ops(node, rhs1, 1);
		if (ret != WRONG_NODE)
			return ret;

		rhs2 = gimple_assign_rhs2(stmt);
		gcc_assert(rhs2 != NULL_TREE);
		return check_ops(node, rhs2, 2);
	default:
		gcc_unreachable();
	}
}

// Find the correct arg number of a call stmt. It is needed when the interesting function is a cloned function.
static unsigned int find_arg_number_gimple(const_tree arg, const_gimple stmt)
{
	unsigned int i;

	if (gimple_call_fndecl(stmt) == NULL_TREE)
		return CANNOT_FIND_ARG;

	for (i = 0; i < gimple_call_num_args(stmt); i++) {
		tree node;

		node = gimple_call_arg(stmt, i);
		if (!operand_equal_p(arg, node, 0))
			continue;
		if (!skip_types(node))
			return i + 1;
	}

	return CANNOT_FIND_ARG;
}

/* starting from the size_overflow asm stmt collect interesting stmts. They can be
 * any of return, call or assignment stmts (because of inlining).
 */
static struct interesting_node *get_interesting_ret_or_call(struct pointer_set_t *visited, struct interesting_node *head, tree node, gimple intentional_asm)
{
	use_operand_p use_p;
	imm_use_iterator imm_iter;
	unsigned int argnum;

	gcc_assert(TREE_CODE(node) == SSA_NAME);

	if (pointer_set_insert(visited, node))
		return head;

	FOR_EACH_IMM_USE_FAST(use_p, imm_iter, node) {
		gimple stmt = USE_STMT(use_p);

		if (stmt == NULL)
			return head;
		if (is_gimple_debug(stmt))
			continue;

		switch (gimple_code(stmt)) {
		case GIMPLE_CALL:
			argnum = find_arg_number_gimple(node, stmt);
			head = create_new_interesting_node(head, stmt, node, argnum, intentional_asm);
			break;
		case GIMPLE_RETURN:
			head = create_new_interesting_node(head, stmt, node, 0, intentional_asm);
			break;
		case GIMPLE_ASSIGN:
			argnum = get_assign_ops_count(stmt, node);
			head = create_new_interesting_node(head, stmt, node, argnum, intentional_asm);
			break;
		case GIMPLE_PHI: {
			tree result = gimple_phi_result(stmt);
			head = get_interesting_ret_or_call(visited, head, result, intentional_asm);
			break;
		}
		case GIMPLE_ASM:
			if (gimple_asm_noutputs(stmt) != 0)
				break;
			if (!is_size_overflow_asm(stmt))
				break;
			head = create_new_interesting_node(head, stmt, node, 1, intentional_asm);
			break;
		case GIMPLE_COND:
		case GIMPLE_SWITCH:
			break;
		default:
			debug_gimple_stmt(stmt);
			gcc_unreachable();
			break;
		}
	}
	return head;
}

static void remove_size_overflow_asm(gimple stmt)
{
	gimple_stmt_iterator gsi;
	tree input, output;

	if (!is_size_overflow_asm(stmt))
		return;

	if (gimple_asm_noutputs(stmt) == 0) {
		gsi = gsi_for_stmt(stmt);
		ipa_remove_stmt_references(cgraph_get_create_node(current_function_decl), stmt);
		gsi_remove(&gsi, true);
		return;
	}

	input = gimple_asm_input_op(stmt, 0);
	output = gimple_asm_output_op(stmt, 0);
	replace_size_overflow_asm_with_assign(stmt, TREE_VALUE(output), TREE_VALUE(input));
}

/* handle the size_overflow asm stmts from the gimple pass and collect the interesting stmts.
 * If the asm stmt is a parm_decl kind (noutputs == 0) then remove it.
 * If it is a simple asm stmt then replace it with an assignment from the asm input to the asm output.
 */
static struct interesting_node *handle_stmt_by_size_overflow_asm(gimple stmt, struct interesting_node *head)
{
	const_tree output;
	struct pointer_set_t *visited;
	gimple intentional_asm = NOT_INTENTIONAL_ASM;

	if (!is_size_overflow_asm(stmt))
		return head;

	if (is_size_overflow_intentional_asm_yes(stmt) || is_size_overflow_intentional_asm_turn_off(stmt))
		intentional_asm = stmt;

	gcc_assert(gimple_asm_ninputs(stmt) == 1);

	if (gimple_asm_noutputs(stmt) == 0 && is_size_overflow_intentional_asm_turn_off(stmt))
		return head;

	if (gimple_asm_noutputs(stmt) == 0) {
		const_tree input;

		if (!is_size_overflow_intentional_asm_turn_off(stmt))
			return head;

		input = gimple_asm_input_op(stmt, 0);
		remove_size_overflow_asm(stmt);
		if (is_gimple_constant(TREE_VALUE(input)))
			return head;
		visited = pointer_set_create();
		head = get_interesting_ret_or_call(visited, head, TREE_VALUE(input), intentional_asm);
		pointer_set_destroy(visited);
		return head;
	}

	if (!is_size_overflow_intentional_asm_yes(stmt) && !is_size_overflow_intentional_asm_turn_off(stmt))
		remove_size_overflow_asm(stmt);

	visited = pointer_set_create();
	output = gimple_asm_output_op(stmt, 0);
	head = get_interesting_ret_or_call(visited, head, TREE_VALUE(output), intentional_asm);
	pointer_set_destroy(visited);
	return head;
}

/* Iterate over all the stmts of a function and look for the size_overflow asm stmts (they were created in the gimple pass)
 * or a call stmt or a return stmt and store them in the interesting_node list
 */
static struct interesting_node *collect_interesting_stmts(struct next_cgraph_node *next_node)
{
	basic_block bb;
	struct interesting_node *head = NULL;

	FOR_ALL_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			enum gimple_code code;
			gimple stmt = gsi_stmt(gsi);

			code = gimple_code(stmt);

			if (code == GIMPLE_ASM)
				head = handle_stmt_by_size_overflow_asm(stmt, head);

			if (!next_node)
				continue;
			if (code == GIMPLE_CALL)
				head = handle_stmt_by_cgraph_nodes_call(head, stmt, next_node);
			if (code == GIMPLE_RETURN)
				head = handle_stmt_by_cgraph_nodes_ret(head, stmt, next_node);
		}
	}
	return head;
}

static void set_current_function_decl(tree fndecl)
{
	gcc_assert(fndecl != NULL_TREE);

	push_cfun(DECL_STRUCT_FUNCTION(fndecl));
	calculate_dominance_info(CDI_DOMINATORS);
	current_function_decl = fndecl;
}

static void unset_current_function_decl(void)
{
	free_dominance_info(CDI_DOMINATORS);
	pop_cfun();
	current_function_decl = NULL_TREE;
}

static void free_interesting_node(struct interesting_node *head)
{
	struct interesting_node *cur;

	while (head) {
		cur = head->next;
#if BUILDING_GCC_VERSION <= 4007
		VEC_free(tree, gc, head->last_nodes);
#else
		vec_free(head->last_nodes);
#endif
		free(head);
		head = cur;
	}
}

static struct visited *insert_visited_function(struct visited *head, struct interesting_node *cur_node)
{
	struct visited *new_visited;

	new_visited = (struct visited *)xmalloc(sizeof(*new_visited));
	new_visited->fndecl = cur_node->fndecl;
	new_visited->num = cur_node->num;
	new_visited->rhs = cur_node->node;
	new_visited->next = NULL;

	if (!head)
		return new_visited;

	new_visited->next = head;
	return new_visited;
}

/* Check whether the function was already visited. If the fndecl, the arg count of the fndecl and the first_stmt (call or return) are same then
 * it is a visited function.
 */
static bool is_visited_function(struct visited *head, struct interesting_node *cur_node)
{
	struct visited *cur;

	if (!head)
		return false;

	for (cur = head; cur; cur = cur->next) {
		if (!operand_equal_p(cur_node->fndecl, cur->fndecl, 0))
			continue;
		if (cur_node->num != cur->num)
			continue;
		if (cur_node->node == cur->rhs)
			return true;
	}
	return false;
}

static void free_next_cgraph_node(struct next_cgraph_node *head)
{
	struct next_cgraph_node *cur;

	while (head) {
		cur = head->next;
		free(head);
		head = cur;
	}
}

static void remove_all_size_overflow_asm(void)
{
	basic_block bb;

	FOR_ALL_BB_FN(bb, cfun) {
		gimple_stmt_iterator si;

		for (si = gsi_start_bb(bb); !gsi_end_p(si); gsi_next(&si))
			remove_size_overflow_asm(gsi_stmt(si));
	}
}

/* Main recursive walk of the ipa pass: iterate over the collected interesting stmts in a function
 * (they are interesting if they have an associated size_overflow asm stmt) and recursively walk
 * the newly collected interesting functions (they are interesting if there is control flow between
 * the interesting stmts and them).
 */
static struct visited *handle_function(struct cgraph_node *node, struct next_cgraph_node *next_node, struct visited *visited)
{
	struct interesting_node *head, *cur_node;
	struct next_cgraph_node *cur_cnodes, *cnodes_head = NULL;

	set_current_function_decl(NODE_DECL(node));
	call_count = 0;

	head = collect_interesting_stmts(next_node);
	for (cur_node = head; cur_node; cur_node = cur_node->next) {
		if (is_visited_function(visited, cur_node))
			continue;
		cnodes_head = handle_interesting_stmt(cnodes_head, cur_node, node);
		visited = insert_visited_function(visited, cur_node);
	}

	free_interesting_node(head);
	remove_all_size_overflow_asm();
	unset_current_function_decl();

	for (cur_cnodes = cnodes_head; cur_cnodes; cur_cnodes = cur_cnodes->next)
		visited = handle_function(cur_cnodes->current_function, cur_cnodes, visited);

	free_next_cgraph_node(cnodes_head);
	return visited;
}

static void free_visited(struct visited *head)
{
	struct visited *cur;

	while (head) {
		cur = head->next;
		free(head);
		head = cur;
	}
}

// erase the local flag
static void set_plf_false(void)
{
	basic_block bb;

	FOR_ALL_BB_FN(bb, cfun) {
		gimple_stmt_iterator si;

		for (si = gsi_start_bb(bb); !gsi_end_p(si); gsi_next(&si))
			gimple_set_plf(gsi_stmt(si), MY_STMT, false);
		for (si = gsi_start_phis(bb); !gsi_end_p(si); gsi_next(&si))
			gimple_set_plf(gsi_stmt(si), MY_STMT, false);
	}
}

// Main entry point of the ipa pass: erases the plf flag of all stmts and iterates over all the functions
static unsigned int search_function(void)
{
	struct cgraph_node *node;
	struct visited *visited = NULL;

	FOR_EACH_FUNCTION_WITH_GIMPLE_BODY(node) {
		set_current_function_decl(NODE_DECL(node));
		set_plf_false();
		unset_current_function_decl();
	}

	FOR_EACH_FUNCTION_WITH_GIMPLE_BODY(node) {
		gcc_assert(cgraph_function_flags_ready);
#if BUILDING_GCC_VERSION <= 4007
		gcc_assert(node->reachable);
#endif

		visited = handle_function(node, NULL, visited);
	}

	free_visited(visited);
	return 0;
}

#if BUILDING_GCC_VERSION >= 4009
static const struct pass_data ipa_pass_data = {
#else
static struct ipa_opt_pass_d ipa_pass = {
	.pass = {
#endif
		.type			= SIMPLE_IPA_PASS,
		.name			= "size_overflow",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 4009
		.has_gate		= false,
		.has_execute		= true,
#else
		.gate			= NULL,
		.execute		= search_function,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
#endif
		.tv_id			= TV_NONE,
		.properties_required	= 0,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= TODO_verify_ssa | TODO_verify_stmts | TODO_remove_unused_locals | TODO_ggc_collect | TODO_verify_flow | TODO_dump_cgraph | TODO_dump_func | TODO_update_ssa_no_phi,
#if BUILDING_GCC_VERSION < 4009
	},
	.generate_summary		= NULL,
	.write_summary			= NULL,
	.read_summary			= NULL,
#if BUILDING_GCC_VERSION >= 4006
	.write_optimization_summary	= NULL,
	.read_optimization_summary	= NULL,
#endif
	.stmt_fixup			= NULL,
	.function_transform_todo_flags_start		= 0,
	.function_transform		= NULL,
	.variable_transform		= NULL,
#endif
};

#if BUILDING_GCC_VERSION >= 4009
namespace {
class ipa_pass : public ipa_opt_pass_d {
public:
	ipa_pass() : ipa_opt_pass_d(ipa_pass_data, g, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL) {}
	unsigned int execute() { return search_function(); }
};
}
#endif

static struct opt_pass *make_ipa_pass(void)
{
#if BUILDING_GCC_VERSION >= 4009
	return new ipa_pass();
#else
	return &ipa_pass.pass;
#endif
}

// data for the size_overflow asm stmt
struct asm_data {
	gimple def_stmt;
	tree input;
	tree output;
};

#if BUILDING_GCC_VERSION <= 4007
static VEC(tree, gc) *create_asm_io_list(tree string, tree io)
#else
static vec<tree, va_gc> *create_asm_io_list(tree string, tree io)
#endif
{
	tree list;
#if BUILDING_GCC_VERSION <= 4007
	VEC(tree, gc) *vec_list = NULL;
#else
	vec<tree, va_gc> *vec_list = NULL;
#endif

	list = build_tree_list(NULL_TREE, string);
	list = chainon(NULL_TREE, build_tree_list(list, io));
#if BUILDING_GCC_VERSION <= 4007
	VEC_safe_push(tree, gc, vec_list, list);
#else
	vec_safe_push(vec_list, list);
#endif
	return vec_list;
}

static void create_asm_stmt(const char *str, tree str_input, tree str_output, struct asm_data *asm_data)
{
	gimple asm_stmt;
	gimple_stmt_iterator gsi;
#if BUILDING_GCC_VERSION <= 4007
	VEC(tree, gc) *input, *output = NULL;
#else
	vec<tree, va_gc> *input, *output = NULL;
#endif

	input = create_asm_io_list(str_input, asm_data->input);

	if (asm_data->output)
		output = create_asm_io_list(str_output, asm_data->output);

	asm_stmt = gimple_build_asm_vec(str, input, output, NULL, NULL);
	gsi = gsi_for_stmt(asm_data->def_stmt);
	gsi_insert_after(&gsi, asm_stmt, GSI_NEW_STMT);

	if (asm_data->output)
		SSA_NAME_DEF_STMT(asm_data->output) = asm_stmt;
}

static void replace_call_lhs(const struct asm_data *asm_data)
{
	gimple_set_lhs(asm_data->def_stmt, asm_data->input);
	update_stmt(asm_data->def_stmt);
	SSA_NAME_DEF_STMT(asm_data->input) = asm_data->def_stmt;
}

static enum mark search_intentional_phi(struct pointer_set_t *visited, const_tree result)
{
	enum mark cur_fndecl_attr;
	gimple phi = get_def_stmt(result);
	unsigned int i, n = gimple_phi_num_args(phi);

	pointer_set_insert(visited, phi);
	for (i = 0; i < n; i++) {
		tree arg = gimple_phi_arg_def(phi, i);

		cur_fndecl_attr = search_intentional(visited, arg);
		if (cur_fndecl_attr != MARK_NO)
			return cur_fndecl_attr;
	}
	return MARK_NO;
}

static enum mark search_intentional_binary(struct pointer_set_t *visited, const_tree lhs)
{
	enum mark cur_fndecl_attr;
	const_tree rhs1, rhs2;
	gimple def_stmt = get_def_stmt(lhs);

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);

	cur_fndecl_attr = search_intentional(visited, rhs1);
	if (cur_fndecl_attr != MARK_NO)
		return cur_fndecl_attr;
	return search_intentional(visited, rhs2);
}

// Look up the intentional_overflow attribute on the caller and the callee functions.
static enum mark search_intentional(struct pointer_set_t *visited, const_tree lhs)
{
	const_gimple def_stmt;

	if (TREE_CODE(lhs) != SSA_NAME)
		return get_intentional_attr_type(lhs);

	def_stmt = get_def_stmt(lhs);
	if (!def_stmt)
		return MARK_NO;

	if (pointer_set_contains(visited, def_stmt))
		return MARK_NO;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
		return search_intentional(visited, SSA_NAME_VAR(lhs));
	case GIMPLE_ASM:
		if (is_size_overflow_intentional_asm_turn_off(def_stmt))
			return MARK_TURN_OFF;
		return MARK_NO;
	case GIMPLE_CALL:
		return MARK_NO;
	case GIMPLE_PHI:
		return search_intentional_phi(visited, lhs);
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			return search_intentional(visited, gimple_assign_rhs1(def_stmt));
		case 3:
			return search_intentional_binary(visited, lhs);
		}
	case GIMPLE_RETURN:
		return MARK_NO;
	default:
		debug_gimple_stmt((gimple)def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
}

// Check the intentional_overflow attribute and create the asm comment string for the size_overflow asm stmt.
static enum mark check_intentional_attribute_gimple(const_tree arg, const_gimple stmt, unsigned int argnum)
{
	const_tree fndecl;
	struct pointer_set_t *visited;
	enum mark cur_fndecl_attr, decl_attr = MARK_NO;

	fndecl = get_interesting_orig_fndecl(stmt, argnum);
	if (is_end_intentional_intentional_attr(fndecl, argnum))
		decl_attr = MARK_NOT_INTENTIONAL;
	else if (is_yes_intentional_attr(fndecl, argnum))
		decl_attr = MARK_YES;
	else if (is_turn_off_intentional_attr(fndecl) || is_turn_off_intentional_attr(DECL_ORIGIN(current_function_decl))) {
		return MARK_TURN_OFF;
	}

	visited = pointer_set_create();
	cur_fndecl_attr = search_intentional(visited, arg);
	pointer_set_destroy(visited);

	switch (cur_fndecl_attr) {
	case MARK_NO:
	case MARK_TURN_OFF:
		return cur_fndecl_attr;
	default:
		print_missing_intentional(decl_attr, cur_fndecl_attr, fndecl, argnum);
		return MARK_YES;
	}
}

static void check_missing_size_overflow_attribute(tree var)
{
	tree orig_fndecl;
	unsigned int num;

	if (is_a_return_check(var))
		orig_fndecl = DECL_ORIGIN(var);
	else
		orig_fndecl = DECL_ORIGIN(current_function_decl);

	num = get_function_num(var, orig_fndecl);
	if (num == CANNOT_FIND_ARG)
		return;

	is_missing_function(orig_fndecl, num);
}

static void search_size_overflow_attribute_phi(struct pointer_set_t *visited, const_tree result)
{
	gimple phi = get_def_stmt(result);
	unsigned int i, n = gimple_phi_num_args(phi);

	pointer_set_insert(visited, phi);
	for (i = 0; i < n; i++) {
		tree arg = gimple_phi_arg_def(phi, i);

		search_size_overflow_attribute(visited, arg);
	}
}

static void search_size_overflow_attribute_binary(struct pointer_set_t *visited, const_tree lhs)
{
	const_gimple def_stmt = get_def_stmt(lhs);
	tree rhs1, rhs2;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);

	search_size_overflow_attribute(visited, rhs1);
	search_size_overflow_attribute(visited, rhs2);
}

static void search_size_overflow_attribute(struct pointer_set_t *visited, tree lhs)
{
	const_gimple def_stmt;

	if (TREE_CODE(lhs) == PARM_DECL) {
		check_missing_size_overflow_attribute(lhs);
		return;
	}

	def_stmt = get_def_stmt(lhs);
	if (!def_stmt)
		return;

	if (pointer_set_insert(visited, def_stmt))
		return;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
		return search_size_overflow_attribute(visited, SSA_NAME_VAR(lhs));
	case GIMPLE_ASM:
		return;
	case GIMPLE_CALL: {
		tree fndecl = gimple_call_fndecl(def_stmt);

		if (fndecl == NULL_TREE)
			return;
		check_missing_size_overflow_attribute(fndecl);
		return;
	}
	case GIMPLE_PHI:
		return search_size_overflow_attribute_phi(visited, lhs);
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			return search_size_overflow_attribute(visited, gimple_assign_rhs1(def_stmt));
		case 3:
			return search_size_overflow_attribute_binary(visited, lhs);
		}
	default:
		debug_gimple_stmt((gimple)def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
}

// Search missing entries in the hash table (invoked from the gimple pass)
static void search_missing_size_overflow_attribute_gimple(const_gimple stmt, unsigned int num)
{
	tree fndecl = NULL_TREE;
	tree lhs;
	struct pointer_set_t *visited;

	if (is_turn_off_intentional_attr(DECL_ORIGIN(current_function_decl)))
		return;

	if (num == 0) {
		gcc_assert(gimple_code(stmt) == GIMPLE_RETURN);
		lhs = gimple_return_retval(stmt);
	} else {
		gcc_assert(is_gimple_call(stmt));
		lhs = gimple_call_arg(stmt, num - 1);
		fndecl = gimple_call_fndecl(stmt);
	}

	if (fndecl != NULL_TREE && is_turn_off_intentional_attr(DECL_ORIGIN(fndecl)))
		return;

	visited = pointer_set_create();
	search_size_overflow_attribute(visited, lhs);
	pointer_set_destroy(visited);
}

static void create_output_from_phi(gimple stmt, unsigned int argnum, struct asm_data *asm_data)
{
	gimple_stmt_iterator gsi;
	gimple assign;

	assign = gimple_build_assign(asm_data->input, asm_data->output);
	gsi = gsi_for_stmt(stmt);
	gsi_insert_before(&gsi, assign, GSI_NEW_STMT);
	asm_data->def_stmt = assign;

	asm_data->output = create_new_var(TREE_TYPE(asm_data->output));
	asm_data->output = make_ssa_name(asm_data->output, stmt);
	if (gimple_code(stmt) == GIMPLE_RETURN)
		gimple_return_set_retval(stmt, asm_data->output);
	else
		gimple_call_set_arg(stmt, argnum - 1, asm_data->output);
	update_stmt(stmt);
}

static char *create_asm_comment(unsigned int argnum, const_gimple stmt , const char *mark_str)
{
	const char *fn_name;
	char *asm_comment;
	unsigned int len;

	if (argnum == 0)
		fn_name = DECL_NAME_POINTER(current_function_decl);
	else
		fn_name = DECL_NAME_POINTER(gimple_call_fndecl(stmt));

	len = asprintf(&asm_comment, "%s %s %u", mark_str, fn_name, argnum);
	gcc_assert(len > 0);

	return asm_comment;
}

static const char *convert_mark_to_str(enum mark mark)
{
	switch (mark) {
	case MARK_NO:
		return OK_ASM_STR;
	case MARK_YES:
	case MARK_NOT_INTENTIONAL:
		return YES_ASM_STR;
	case MARK_TURN_OFF:
		return TURN_OFF_ASM_STR;
	}

	gcc_unreachable();
}

/* Create the input of the size_overflow asm stmt.
 * When the arg of the callee function is a parm_decl it creates this kind of size_overflow asm stmt:
 *   __asm__("# size_overflow MARK_YES" :  : "rm" size_1(D));
 * The input field in asm_data will be empty if there is no need for further size_overflow asm stmt insertion.
 * otherwise create the input (for a phi stmt the output too) of the asm stmt.
 */
static void create_asm_input(gimple stmt, unsigned int argnum, struct asm_data *asm_data)
{
	if (!asm_data->def_stmt) {
		asm_data->input = NULL_TREE;
		return;
	}

	asm_data->input = create_new_var(TREE_TYPE(asm_data->output));
	asm_data->input = make_ssa_name(asm_data->input, asm_data->def_stmt);

	switch (gimple_code(asm_data->def_stmt)) {
	case GIMPLE_ASSIGN:
	case GIMPLE_CALL:
		replace_call_lhs(asm_data);
		break;
	case GIMPLE_PHI:
		create_output_from_phi(stmt, argnum, asm_data);
		break;
	case GIMPLE_NOP: {
		enum mark mark;
		const char *mark_str;
		char *asm_comment;

		mark = check_intentional_attribute_gimple(asm_data->output, stmt, argnum);

		asm_data->input = asm_data->output;
		asm_data->output = NULL;
		asm_data->def_stmt = stmt;

		mark_str = convert_mark_to_str(mark);
		asm_comment = create_asm_comment(argnum, stmt, mark_str);

		create_asm_stmt(asm_comment, build_string(2, "rm"), NULL, asm_data);
		free(asm_comment);
		asm_data->input = NULL_TREE;
		break;
	}
	case GIMPLE_ASM:
		if (is_size_overflow_asm(asm_data->def_stmt)) {
			asm_data->input = NULL_TREE;
			break;
		}
	default:
		debug_gimple_stmt(asm_data->def_stmt);
		gcc_unreachable();
	}
}

/* This is the gimple part of searching for a missing size_overflow attribute. If the intentional_overflow attribute type
 * is of the right kind create the appropriate size_overflow asm stmts:
 *   __asm__("# size_overflow" : =rm" D.3344_8 : "0" cicus.4_16);
 *   __asm__("# size_overflow MARK_YES" :  : "rm" size_1(D));
 */
static void create_size_overflow_asm(gimple stmt, tree output_node, unsigned int argnum)
{
	struct asm_data asm_data;
	const char *mark_str;
	char *asm_comment;
	enum mark mark;

	if (is_gimple_constant(output_node))
		return;

	asm_data.output = output_node;
	mark = check_intentional_attribute_gimple(asm_data.output, stmt, argnum);
	if (mark != MARK_TURN_OFF)
		search_missing_size_overflow_attribute_gimple(stmt, argnum);

	asm_data.def_stmt = get_def_stmt(asm_data.output);
	if (is_size_overflow_intentional_asm_turn_off(asm_data.def_stmt))
		return;

	create_asm_input(stmt, argnum, &asm_data);
	if (asm_data.input == NULL_TREE)
		return;

	mark_str = convert_mark_to_str(mark);
	asm_comment = create_asm_comment(argnum, stmt, mark_str);
	create_asm_stmt(asm_comment, build_string(1, "0"), build_string(3, "=rm"), &asm_data);
	free(asm_comment);
}

// Insert an asm stmt with "MARK_TURN_OFF", "MARK_YES" or "MARK_NOT_INTENTIONAL".
static bool create_mark_asm(gimple stmt, enum mark mark)
{
	struct asm_data asm_data;
	const char *asm_str;

	switch (mark) {
	case MARK_TURN_OFF:
		asm_str = TURN_OFF_ASM_STR;
		break;
	case MARK_NOT_INTENTIONAL:
	case MARK_YES:
		asm_str = YES_ASM_STR;
		break;
	default:
		gcc_unreachable();
	}

	asm_data.def_stmt = stmt;
	asm_data.output = gimple_call_lhs(stmt);

	if (asm_data.output == NULL_TREE) {
		asm_data.input = gimple_call_arg(stmt, 0);
		if (is_gimple_constant(asm_data.input))
			return false;
		asm_data.output = NULL;
		create_asm_stmt(asm_str, build_string(2, "rm"), NULL, &asm_data);
		return true;
	}

	create_asm_input(stmt, 0, &asm_data);
	gcc_assert(asm_data.input != NULL_TREE);

	create_asm_stmt(asm_str, build_string(1, "0"), build_string(3, "=rm"), &asm_data);
	return true;
}

static bool is_from_cast(const_tree node)
{
	gimple def_stmt = get_def_stmt(node);

	if (!def_stmt)
		return false;

	if (gimple_assign_cast_p(def_stmt))
		return true;

	return false;
}

// Skip duplication when there is a minus expr and the type of rhs1 or rhs2 is a pointer_type.
static bool skip_ptr_minus(gimple stmt)
{
	const_tree rhs1, rhs2, ptr1_rhs, ptr2_rhs;

	if (gimple_assign_rhs_code(stmt) != MINUS_EXPR)
		return false;

	rhs1 = gimple_assign_rhs1(stmt);
	if (!is_from_cast(rhs1))
		return false;

	rhs2 = gimple_assign_rhs2(stmt);
	if (!is_from_cast(rhs2))
		return false;

	ptr1_rhs = gimple_assign_rhs1(get_def_stmt(rhs1));
	ptr2_rhs = gimple_assign_rhs1(get_def_stmt(rhs2));

	if (TREE_CODE(TREE_TYPE(ptr1_rhs)) != POINTER_TYPE && TREE_CODE(TREE_TYPE(ptr2_rhs)) != POINTER_TYPE)
		return false;

	create_mark_asm(stmt, MARK_YES);
	return true;
}

static void walk_use_def_ptr(struct pointer_set_t *visited, const_tree lhs)
{
	gimple def_stmt;

	def_stmt = get_def_stmt(lhs);
	if (!def_stmt)
		return;

	if (pointer_set_insert(visited, def_stmt))
		return;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
	case GIMPLE_ASM:
	case GIMPLE_CALL:
		break;
	case GIMPLE_PHI: {
		unsigned int i, n = gimple_phi_num_args(def_stmt);

		pointer_set_insert(visited, def_stmt);

		for (i = 0; i < n; i++) {
			tree arg = gimple_phi_arg_def(def_stmt, i);

			walk_use_def_ptr(visited, arg);
		}
	}
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			walk_use_def_ptr(visited, gimple_assign_rhs1(def_stmt));
			return;
		case 3:
			if (skip_ptr_minus(def_stmt))
				return;

			walk_use_def_ptr(visited, gimple_assign_rhs1(def_stmt));
			walk_use_def_ptr(visited, gimple_assign_rhs2(def_stmt));
			return;
		default:
			return;
		}
	default:
		debug_gimple_stmt((gimple)def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
}

// Look for a ptr - ptr expression (e.g., cpuset_common_file_read() s - page)
static void insert_mark_not_intentional_asm_at_ptr(const_tree arg)
{
	struct pointer_set_t *visited;

	visited = pointer_set_create();
	walk_use_def_ptr(visited, arg);
	pointer_set_destroy(visited);
}

// Determine the return value and insert the asm stmt to mark the return stmt.
static void insert_asm_ret(gimple stmt)
{
	tree ret;

	ret = gimple_return_retval(stmt);
	create_size_overflow_asm(stmt, ret, 0);
}

// Determine the correct arg index and arg and insert the asm stmt to mark the stmt.
static void insert_asm_arg(gimple stmt, unsigned int orig_argnum)
{
	tree arg;
	unsigned int argnum;

	argnum = get_correct_arg_count(orig_argnum, gimple_call_fndecl(stmt));
	gcc_assert(argnum != 0);
	if (argnum == CANNOT_FIND_ARG)
		return;

	arg = gimple_call_arg(stmt, argnum - 1);
	gcc_assert(arg != NULL_TREE);

	// skip all ptr - ptr expressions
	insert_mark_not_intentional_asm_at_ptr(arg);

	create_size_overflow_asm(stmt, arg, argnum);
}

// If a function arg or the return value is marked by the size_overflow attribute then set its index in the array.
static void set_argnum_attribute(const_tree attr, bool *argnums)
{
	unsigned int argnum;
	tree attr_value;

	for (attr_value = TREE_VALUE(attr); attr_value; attr_value = TREE_CHAIN(attr_value)) {
		argnum = TREE_INT_CST_LOW(TREE_VALUE(attr_value));
		argnums[argnum] = true;
	}
}

// If a function arg or the return value is in the hash table then set its index in the array.
static void set_argnum_hash(tree fndecl, bool *argnums)
{
	unsigned int num;
	const struct size_overflow_hash *hash;

	hash = get_function_hash(DECL_ORIGIN(fndecl));
	if (!hash)
		return;

	for (num = 0; num <= MAX_PARAM; num++) {
		if (!(hash->param & (1U << num)))
			continue;

		argnums[num] = true;
	}
}

static bool is_all_the_argnums_empty(bool *argnums)
{
	unsigned int i;

	for (i = 0; i <= MAX_PARAM; i++)
		if (argnums[i])
			return false;
	return true;
}

// Check whether the arguments or the return value of the function are in the hash table or are marked by the size_overflow attribute.
static void search_interesting_args(tree fndecl, bool *argnums)
{
	const_tree attr;

	set_argnum_hash(fndecl, argnums);
	if (!is_all_the_argnums_empty(argnums))
		return;

	attr = lookup_attribute("size_overflow", DECL_ATTRIBUTES(fndecl));
	if (attr && TREE_VALUE(attr))
		set_argnum_attribute(attr, argnums);
}

/*
 * Look up the intentional_overflow attribute that turns off ipa based duplication
 * on the callee function.
 */
static bool is_mark_turn_off_attribute(gimple stmt)
{
	enum mark mark;
	const_tree fndecl = gimple_call_fndecl(stmt);

	mark = get_intentional_attr_type(DECL_ORIGIN(fndecl));
	if (mark == MARK_TURN_OFF)
		return true;
	return false;
}

// If the argument(s) of the callee function is/are in the hash table or are marked by an attribute then mark the call stmt with an asm stmt
static void handle_interesting_function(gimple stmt)
{
	unsigned int argnum;
	tree fndecl;
	bool orig_argnums[MAX_PARAM + 1] = {false};

	if (gimple_call_num_args(stmt) == 0)
		return;
	fndecl = gimple_call_fndecl(stmt);
	if (fndecl == NULL_TREE)
		return;
	fndecl = DECL_ORIGIN(fndecl);

	if (is_mark_turn_off_attribute(stmt)) {
		create_mark_asm(stmt, MARK_TURN_OFF);
		return;
	}

	search_interesting_args(fndecl, orig_argnums);

	for (argnum = 1; argnum < MAX_PARAM; argnum++)
		if (orig_argnums[argnum])
			insert_asm_arg(stmt, argnum);
}

// If the return value of the caller function is in hash table (its index is 0) then mark the return stmt with an asm stmt
static void handle_interesting_ret(gimple stmt)
{
	bool orig_argnums[MAX_PARAM + 1] = {false};

	search_interesting_args(current_function_decl, orig_argnums);

	if (orig_argnums[0])
		insert_asm_ret(stmt);
}

// Iterate over all the stmts and search for call and return stmts and mark them if they're in the hash table
static unsigned int search_interesting_functions(void)
{
	basic_block bb;

	FOR_ALL_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gimple stmt = gsi_stmt(gsi);

			if (is_size_overflow_asm(stmt))
				continue;

			if (is_gimple_call(stmt))
				handle_interesting_function(stmt);
			else if (gimple_code(stmt) == GIMPLE_RETURN)
				handle_interesting_ret(stmt);
		}
	}
	return 0;
}

/*
 * A lot of functions get inlined before the ipa passes so after the build_ssa gimple pass
 * this pass inserts asm stmts to mark the interesting args
 * that the ipa pass will detect and insert the size overflow checks for.
 */
#if BUILDING_GCC_VERSION >= 4009
static const struct pass_data insert_size_overflow_asm_pass_data = {
#else
static struct gimple_opt_pass insert_size_overflow_asm_pass = {
	.pass = {
#endif
		.type			= GIMPLE_PASS,
		.name			= "insert_size_overflow_asm",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 4009
		.has_gate		= false,
		.has_execute		= true,
#else
		.gate			= NULL,
		.execute		= search_interesting_functions,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
#endif
		.tv_id			= TV_NONE,
		.properties_required	= PROP_cfg,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= TODO_dump_func | TODO_verify_ssa | TODO_verify_stmts | TODO_remove_unused_locals | TODO_update_ssa_no_phi | TODO_cleanup_cfg | TODO_ggc_collect | TODO_verify_flow
#if BUILDING_GCC_VERSION < 4009
	}
#endif
};

#if BUILDING_GCC_VERSION >= 4009
namespace {
class insert_size_overflow_asm_pass : public gimple_opt_pass {
public:
	insert_size_overflow_asm_pass() : gimple_opt_pass(insert_size_overflow_asm_pass_data, g) {}
	unsigned int execute() { return search_interesting_functions(); }
};
}
#endif

static struct opt_pass *make_insert_size_overflow_asm_pass(void)
{
#if BUILDING_GCC_VERSION >= 4009
	return new insert_size_overflow_asm_pass();
#else
	return &insert_size_overflow_asm_pass.pass;
#endif
}

// Create the noreturn report_size_overflow() function decl.
static void size_overflow_start_unit(void __unused *gcc_data, void __unused *user_data)
{
	tree const_char_ptr_type_node;
	tree fntype;

	const_char_ptr_type_node = build_pointer_type(build_type_variant(char_type_node, 1, 0));

	// void report_size_overflow(const char *loc_file, unsigned int loc_line, const char *current_func, const char *ssa_var)
	fntype = build_function_type_list(void_type_node,
					  const_char_ptr_type_node,
					  unsigned_type_node,
					  const_char_ptr_type_node,
					  const_char_ptr_type_node,
					  NULL_TREE);
	report_size_overflow_decl = build_fn_decl("report_size_overflow", fntype);

	DECL_ASSEMBLER_NAME(report_size_overflow_decl);
	TREE_PUBLIC(report_size_overflow_decl) = 1;
	DECL_EXTERNAL(report_size_overflow_decl) = 1;
	DECL_ARTIFICIAL(report_size_overflow_decl) = 1;
	TREE_THIS_VOLATILE(report_size_overflow_decl) = 1;
}

static unsigned int dump_functions(void)
{
	struct cgraph_node *node;

	FOR_EACH_FUNCTION_WITH_GIMPLE_BODY(node) {
		basic_block bb;

		push_cfun(DECL_STRUCT_FUNCTION(NODE_DECL(node)));
		current_function_decl = NODE_DECL(node);

		fprintf(stderr, "-----------------------------------------\n%s\n-----------------------------------------\n", DECL_NAME_POINTER(current_function_decl));

		FOR_ALL_BB_FN(bb, cfun) {
			gimple_stmt_iterator si;

			fprintf(stderr, "<bb %u>:\n", bb->index);
			for (si = gsi_start_phis(bb); !gsi_end_p(si); gsi_next(&si))
				debug_gimple_stmt(gsi_stmt(si));
			for (si = gsi_start_bb(bb); !gsi_end_p(si); gsi_next(&si))
				debug_gimple_stmt(gsi_stmt(si));
			fprintf(stderr, "\n");
		}

		fprintf(stderr, "-------------------------------------------------------------------------\n");

		pop_cfun();
		current_function_decl = NULL_TREE;
	}

	fprintf(stderr, "###############################################################################\n");

	return 0;
}

#if BUILDING_GCC_VERSION >= 4009
static const struct pass_data dump_pass_data = {
#else
static struct ipa_opt_pass_d dump_pass = {
	.pass = {
#endif
		.type			= SIMPLE_IPA_PASS,
		.name			= "dump",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 4009
		.has_gate		= false,
		.has_execute		= true,
#else
		.gate			= NULL,
		.execute		= dump_functions,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
#endif
		.tv_id			= TV_NONE,
		.properties_required	= 0,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= 0,
#if BUILDING_GCC_VERSION < 4009
	},
	.generate_summary		= NULL,
	.write_summary			= NULL,
	.read_summary			= NULL,
#if BUILDING_GCC_VERSION >= 4006
	.write_optimization_summary	= NULL,
	.read_optimization_summary	= NULL,
#endif
	.stmt_fixup			= NULL,
	.function_transform_todo_flags_start		= 0,
	.function_transform		= NULL,
	.variable_transform		= NULL,
#endif
};

#if BUILDING_GCC_VERSION >= 4009
namespace {
class dump_pass : public ipa_opt_pass_d {
public:
	dump_pass() : ipa_opt_pass_d(dump_pass_data, g, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL) {}
	unsigned int execute() { return dump_functions(); }
};
}
#endif

static struct opt_pass *make_dump_pass(void)
{
#if BUILDING_GCC_VERSION >= 4009
	return new dump_pass();
#else
	return &dump_pass.pass;
#endif
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	int i;
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	bool enable = true;
	struct register_pass_info insert_size_overflow_asm_pass_info;
	struct register_pass_info __unused dump_before_pass_info;
	struct register_pass_info __unused dump_after_pass_info;
	struct register_pass_info ipa_pass_info;
	static const struct ggc_root_tab gt_ggc_r_gt_size_overflow[] = {
		{
			.base = &report_size_overflow_decl,
			.nelt = 1,
			.stride = sizeof(report_size_overflow_decl),
			.cb = &gt_ggc_mx_tree_node,
			.pchw = &gt_pch_nx_tree_node
		},
		LAST_GGC_ROOT_TAB
	};

	insert_size_overflow_asm_pass_info.pass				= make_insert_size_overflow_asm_pass();
	insert_size_overflow_asm_pass_info.reference_pass_name		= "ssa";
	insert_size_overflow_asm_pass_info.ref_pass_instance_number	= 1;
	insert_size_overflow_asm_pass_info.pos_op			= PASS_POS_INSERT_AFTER;

	dump_before_pass_info.pass			= make_dump_pass();
	dump_before_pass_info.reference_pass_name	= "increase_alignment";
	dump_before_pass_info.ref_pass_instance_number	= 1;
	dump_before_pass_info.pos_op			= PASS_POS_INSERT_BEFORE;

	ipa_pass_info.pass			= make_ipa_pass();
	ipa_pass_info.reference_pass_name	= "increase_alignment";
	ipa_pass_info.ref_pass_instance_number	= 1;
	ipa_pass_info.pos_op			= PASS_POS_INSERT_BEFORE;

	dump_after_pass_info.pass			= make_dump_pass();
	dump_after_pass_info.reference_pass_name	= "increase_alignment";
	dump_after_pass_info.ref_pass_instance_number	= 1;
	dump_after_pass_info.pos_op			= PASS_POS_INSERT_BEFORE;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	for (i = 0; i < argc; ++i) {
		if (!strcmp(argv[i].key, "no-size-overflow")) {
			enable = false;
			continue;
		}
		error(G_("unkown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &size_overflow_plugin_info);
	if (enable) {
		register_callback(plugin_name, PLUGIN_START_UNIT, &size_overflow_start_unit, NULL);
		register_callback(plugin_name, PLUGIN_REGISTER_GGC_ROOTS, NULL, (void *)&gt_ggc_r_gt_size_overflow);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &insert_size_overflow_asm_pass_info);
//		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &dump_before_pass_info);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &ipa_pass_info);
//		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &dump_after_pass_info);
	}
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	return 0;
}

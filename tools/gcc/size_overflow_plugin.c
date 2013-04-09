/*
 * Copyright 2011, 2012, 2013 by Emese Revfy <re.emese@gmail.com>
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
#include "gimple.h"
#include "diagnostic.h"
#include "cfgloop.h"

#if BUILDING_GCC_VERSION >= 4008
#define TODO_dump_func 0
#endif

struct size_overflow_hash {
	const struct size_overflow_hash * const next;
	const char * const name;
	const unsigned int param;
};

#include "size_overflow_hash.h"

enum mark {
	MARK_NO, MARK_YES, MARK_NOT_INTENTIONAL, MARK_TURN_OFF
};

enum err_code_conditions {
	CAST_ONLY, FROM_CONST
};

static unsigned int call_count = 0;

#define __unused __attribute__((__unused__))
#define NAME(node) IDENTIFIER_POINTER(DECL_NAME(node))
#define NAME_LEN(node) IDENTIFIER_LENGTH(DECL_NAME(node))
#define BEFORE_STMT true
#define AFTER_STMT false
#define CREATE_NEW_VAR NULL_TREE
#define CODES_LIMIT 32
#define MAX_PARAM 31
#define MY_STMT GF_PLF_1
#define NO_CAST_CHECK GF_PLF_2
#define FROM_ARG true
#define FROM_RET false

#if BUILDING_GCC_VERSION == 4005
#define DECL_CHAIN(NODE) (TREE_CHAIN(DECL_MINIMAL_CHECK(NODE)))
#endif

int plugin_is_GPL_compatible;
void debug_gimple_stmt(gimple gs);

static tree expand(struct pointer_set_t *visited, tree lhs);
static enum mark pre_expand(struct pointer_set_t *visited, bool *search_err_code, const_tree lhs);
static tree report_size_overflow_decl;
static const_tree const_char_ptr_type_node;
static unsigned int handle_function(void);
static void check_size_overflow(gimple stmt, tree size_overflow_type, tree cast_rhs, tree rhs, bool before);
static tree get_size_overflow_type(gimple stmt, const_tree node);
static tree dup_assign(struct pointer_set_t *visited, gimple oldstmt, const_tree node, tree rhs1, tree rhs2, tree __unused rhs3);
static void print_missing_msg(tree func, unsigned int argnum);

static struct plugin_info size_overflow_plugin_info = {
	.version	= "20130410beta",
	.help		= "no-size-overflow\tturn off size overflow checking\n",
};

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

static const char* get_asm_name(tree node)
{
	return IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(node));
}

static tree handle_intentional_overflow_attribute(tree *node, tree __unused name, tree args, int __unused flags, bool *no_add_attrs)
{
	unsigned int arg_count, arg_num;
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
		arg_num = TREE_INT_CST_LOW(TREE_VALUE(args));
		if (arg_num != 0) {
			*no_add_attrs = true;
			error("%s: %qE attribute parameter can only be 0 in structure fields", __func__, name);
		}
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

static inline unsigned int get_hash_num(const char *fndecl, const char *tree_codes, unsigned int len, unsigned int seed)
{
	unsigned int fn = CrapWow(fndecl, strlen(fndecl), seed) & 0xffff;
	unsigned int codes = CrapWow(tree_codes, len, seed) & 0xffff;
	return fn ^ codes;
}

static inline tree get_original_function_decl(tree fndecl)
{
	if (DECL_ABSTRACT_ORIGIN(fndecl))
		return DECL_ABSTRACT_ORIGIN(fndecl);
	return fndecl;
}

static inline gimple get_def_stmt(const_tree node)
{
	gcc_assert(node != NULL_TREE);
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

static size_t add_type_codes(const_tree type, unsigned char *tree_codes, size_t len)
{
	gcc_assert(type != NULL_TREE);

	while (type && len < CODES_LIMIT) {
		tree_codes[len] = get_tree_code(type);
		len++;
		type = TREE_TYPE(type);
	}
	return len;
}

static unsigned int get_function_decl(const_tree fndecl, unsigned char *tree_codes)
{
	const_tree arg, result, arg_field, type = TREE_TYPE(fndecl);
	enum tree_code code = TREE_CODE(type);
	size_t len = 0;

	gcc_assert(code == FUNCTION_TYPE || code == METHOD_TYPE);

	arg = TYPE_ARG_TYPES(type);
	// skip builtins __builtin_constant_p
	if (!arg && DECL_BUILT_IN(fndecl))
		return 0;

	if (TREE_CODE_CLASS(code) == tcc_type)
		result = type;
	else
		result = DECL_RESULT(fndecl);

	gcc_assert(result != NULL_TREE);
	len = add_type_codes(TREE_TYPE(result), tree_codes, len);

	if (arg == NULL_TREE) {
		gcc_assert(CODE_CONTAINS_STRUCT(TREE_CODE(fndecl), TS_DECL_NON_COMMON));
		arg_field = DECL_ARGUMENT_FLD(fndecl);
		if (arg_field == NULL_TREE)
			return 0;
		arg = TREE_TYPE(arg_field);
		len = add_type_codes(arg, tree_codes, len);
		gcc_assert(len != 0);
		return len;
	}

	gcc_assert(arg != NULL_TREE && TREE_CODE(arg) == TREE_LIST);
	while (arg && len < CODES_LIMIT) {
		len = add_type_codes(TREE_VALUE(arg), tree_codes, len);
		arg = TREE_CHAIN(arg);
	}

	gcc_assert(len != 0);
	return len;
}

static const struct size_overflow_hash *get_function_hash(tree fndecl)
{
	unsigned int hash;
	const struct size_overflow_hash *entry;
	unsigned char tree_codes[CODES_LIMIT];
	size_t len;
	const char *func_name;

	fndecl = get_original_function_decl(fndecl);
	len = get_function_decl(fndecl, tree_codes);
	if (len == 0)
		return NULL;

	func_name = get_asm_name(fndecl);
	hash = get_hash_num(func_name, (const char*) tree_codes, len, 0);

	entry = size_overflow_hash[hash];
	while (entry) {
		if (!strcmp(entry->name, func_name))
			return entry;
		entry = entry->next;
	}

	return NULL;
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
			return true;
		case PARM_DECL:
		case VAR_DECL:
		case COMPONENT_REF:
			return false;
		default:
			break;
	}

	gcc_assert(TREE_CODE(var) == SSA_NAME);

	type = TREE_TYPE(var);
	switch (TREE_CODE(type)) {
		case INTEGER_TYPE:
		case ENUMERAL_TYPE:
			return false;
		case BOOLEAN_TYPE:
			return is_bool(var);
		default:
			break;
	}

	gcc_assert(TREE_CODE(type) == POINTER_TYPE);

	type = TREE_TYPE(type);
	gcc_assert(type != NULL_TREE);
	switch (TREE_CODE(type)) {
		case RECORD_TYPE:
		case POINTER_TYPE:
		case ARRAY_TYPE:
			return true;
		case VOID_TYPE:
		case INTEGER_TYPE:
		case UNION_TYPE:
			return false;
		default:
			break;
	}

	debug_tree((tree)var);
	gcc_unreachable();
}

static unsigned int find_arg_number(const_tree arg, tree func)
{
	tree var;
	unsigned int argnum = 1;

	if (TREE_CODE(arg) == SSA_NAME)
		arg = SSA_NAME_VAR(arg);

	for (var = DECL_ARGUMENTS(func); var; var = TREE_CHAIN(var), argnum++) {
		if (!operand_equal_p(arg, var, 0) && strcmp(NAME(var), NAME(arg)))
			continue;
		if (!skip_types(var))
			return argnum;
	}

	return 0;
}

static tree create_new_var(tree type)
{
	tree new_var = create_tmp_var(type, "cicus");

#if BUILDING_GCC_VERSION <= 4007
	add_referenced_var(new_var);
	mark_sym_for_renaming(new_var);
#endif
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
	gimple_set_lhs(assign, make_ssa_name(lhs, assign));

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
		return gimple_get_lhs(stmt);
	case GIMPLE_PHI:
		return gimple_phi_result(stmt);
	case GIMPLE_CALL:
		return gimple_call_lhs(stmt);
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
	if (skip_cast(dst_type, rhs, force) && gimple_plf(def_stmt, MY_STMT))
		return def_stmt;

	if (lhs == CREATE_NEW_VAR)
		lhs = create_new_var(dst_type);

	assign = gimple_build_assign(lhs, cast_a_tree(dst_type, rhs));

	if (!gsi_end_p(*gsi)) {
		location_t loc = gimple_location(gsi_stmt(*gsi));
		gimple_set_location(assign, loc);
	}

	gimple_set_lhs(assign, make_ssa_name(lhs, assign));

	if (before)
		gsi_insert_before(gsi, assign, GSI_NEW_STMT);
	else
		gsi_insert_after(gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
	gimple_set_plf(assign, MY_STMT, true);

	return assign;
}

static tree cast_to_new_size_overflow_type(gimple stmt, tree rhs, tree size_overflow_type, bool before)
{
	gimple_stmt_iterator gsi;
	tree lhs;
	const_gimple new_stmt;

	if (rhs == NULL_TREE)
		return NULL_TREE;

	gsi = gsi_for_stmt(stmt);
	new_stmt = build_cast_stmt(size_overflow_type, rhs, CREATE_NEW_VAR, &gsi, before, false);

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
	return gimple_get_lhs(cast_stmt);
}

static void check_function_hash(const_gimple stmt)
{
	tree func;
	const struct size_overflow_hash *hash;

	if (gimple_code(stmt) != GIMPLE_CALL)
		return;

	func = gimple_call_fndecl(stmt);
	//fs/xattr.c D.34222_15 = D.34219_14 (dentry_3(D), name_7(D), 0B, 0);
	if (func == NULL_TREE)
		return;

	hash = get_function_hash(func);
	if (!hash)
		print_missing_msg(func, 0);
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
		lhs = gimple_call_lhs(oldstmt);
		break;
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
	tree size_overflow_type, new_var, lhs = gimple_get_lhs(oldstmt);

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
	gimple_set_lhs(stmt, new_var);

	if (rhs1 != NULL_TREE)
		gimple_assign_set_rhs1(stmt, rhs1);

	if (rhs2 != NULL_TREE)
		gimple_assign_set_rhs2(stmt, rhs2);
#if BUILDING_GCC_VERSION >= 4007
	if (rhs3 != NULL_TREE)
		gimple_assign_set_rhs3(stmt, rhs3);
#endif
	gimple_set_vuse(stmt, gimple_vuse(oldstmt));
	gimple_set_vdef(stmt, gimple_vdef(oldstmt));

	gsi = gsi_for_stmt(oldstmt);
	gsi_insert_after(&gsi, stmt, GSI_SAME_STMT);
	update_stmt(stmt);
	pointer_set_insert(visited, oldstmt);
	return gimple_get_lhs(stmt);
}

static tree cast_parm_decl(tree phi_ssa_name, tree arg, tree size_overflow_type)
{
	basic_block first_bb;
	gimple assign;
	gimple_stmt_iterator gsi;

	first_bb = split_block_after_labels(ENTRY_BLOCK_PTR)->dest;
	gcc_assert(dom_info_available_p(CDI_DOMINATORS));
	set_immediate_dominator(CDI_DOMINATORS, first_bb, ENTRY_BLOCK_PTR);

	gsi = gsi_start_bb(first_bb);
	assign = build_cast_stmt(size_overflow_type, arg, phi_ssa_name, &gsi, BEFORE_STMT, false);
	return gimple_get_lhs(assign);
}

static tree use_phi_ssa_name(tree phi_ssa_name, tree new_arg)
{
	gimple_stmt_iterator gsi;
	const_gimple assign;
	gimple def_stmt = get_def_stmt(new_arg);

	if (gimple_code(def_stmt) == GIMPLE_PHI) {
		gsi = gsi_after_labels(gimple_bb(def_stmt));
		assign = build_cast_stmt(TREE_TYPE(new_arg), new_arg, phi_ssa_name, &gsi, BEFORE_STMT, true);
	} else {
		gsi = gsi_for_stmt(def_stmt);
		assign = build_cast_stmt(TREE_TYPE(new_arg), new_arg, phi_ssa_name, &gsi, AFTER_STMT, true);
	}

	return gimple_get_lhs(assign);
}

static tree cast_visited_phi_arg(tree phi_ssa_name, tree arg, tree size_overflow_type)
{
	basic_block bb;
	gimple_stmt_iterator gsi;
	const_gimple assign, def_stmt;

	def_stmt = get_def_stmt(arg);
	bb = gimple_bb(def_stmt);
	gcc_assert(bb->index != 0);
	gsi = gsi_after_labels(bb);

	assign = build_cast_stmt(size_overflow_type, arg, phi_ssa_name, &gsi, BEFORE_STMT, false);
	return gimple_get_lhs(assign);
}

static tree create_new_phi_arg(tree phi_ssa_name, tree new_arg, tree arg, gimple oldstmt)
{
	tree size_overflow_type;
	const_gimple def_stmt = get_def_stmt(arg);

	if (phi_ssa_name != NULL_TREE)
		phi_ssa_name = SSA_NAME_VAR(phi_ssa_name);

	size_overflow_type = get_size_overflow_type(oldstmt, arg);

	if (new_arg != NULL_TREE) {
		gcc_assert(types_compatible_p(TREE_TYPE(new_arg), size_overflow_type));
		return use_phi_ssa_name(phi_ssa_name, new_arg);
	}

	switch(gimple_code(def_stmt)) {
	case GIMPLE_PHI:
		return cast_visited_phi_arg(phi_ssa_name, arg, size_overflow_type);
	case GIMPLE_NOP:
		return cast_parm_decl(phi_ssa_name, arg, size_overflow_type);
	default:
		debug_gimple_stmt((gimple)def_stmt);
		gcc_unreachable();
	}
}

static gimple overflow_create_phi_node(gimple oldstmt, tree result)
{
	basic_block bb;
	gimple phi;
	gimple_seq seq;
	gimple_stmt_iterator gsi = gsi_for_stmt(oldstmt);

	bb = gsi_bb(gsi);

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

static tree handle_phi(struct pointer_set_t *visited, tree orig_result)
{
	gimple new_phi = NULL;
	gimple oldstmt = get_def_stmt(orig_result);
	tree phi_ssa_name = NULL_TREE;
	unsigned int i;

	pointer_set_insert(visited, oldstmt);
	for (i = 0; i < gimple_phi_num_args(oldstmt); i++) {
		tree arg, new_arg;

		arg = gimple_phi_arg_def(oldstmt, i);

		new_arg = expand(visited, arg);
		new_arg = create_new_phi_arg(phi_ssa_name, new_arg, arg, oldstmt);
		if (i == 0) {
			phi_ssa_name = new_arg;
			new_phi = overflow_create_phi_node(oldstmt, SSA_NAME_VAR(phi_ssa_name));
		}

		gcc_assert(new_phi != NULL);
		add_phi_arg(new_phi, new_arg, gimple_phi_arg_edge(oldstmt, i), gimple_location(oldstmt));
	}

	gcc_assert(new_phi != NULL);
	update_stmt(new_phi);
	return gimple_phi_result(new_phi);
}

static tree change_assign_rhs(gimple stmt, const_tree orig_rhs, tree new_rhs)
{
	const_gimple assign;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);
	tree origtype = TREE_TYPE(orig_rhs);

	gcc_assert(gimple_code(stmt) == GIMPLE_ASSIGN);

	assign = build_cast_stmt(origtype, new_rhs, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	return gimple_get_lhs(assign);
}

static bool is_a_cast_and_const_overflow(const_tree no_const_rhs)
{
	const_tree rhs1, lhs, rhs1_type, lhs_type;
	enum machine_mode lhs_mode, rhs_mode;
	gimple def_stmt = get_def_stmt(no_const_rhs);

	if (!gimple_assign_cast_p(def_stmt))
		return false;

	rhs1 = gimple_assign_rhs1(def_stmt);
	lhs = gimple_get_lhs(def_stmt);
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
	tree lhs = gimple_get_lhs(stmt);
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
		if (!(gimple_bb(use_stmt)->flags & BB_REACHABLE))
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
	if (!def_stmt || gimple_code(def_stmt) != GIMPLE_ASSIGN || gimple_num_ops(def_stmt) != 3)
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

static tree create_cast_overflow_check(struct pointer_set_t *visited, tree new_rhs1, gimple stmt)
{
	bool cast_lhs, cast_rhs;
	tree lhs = gimple_get_lhs(stmt);
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
		check_size_overflow(stmt, TREE_TYPE(new_rhs1), new_rhs1, lhs, BEFORE_STMT);

	if (cast_rhs)
		check_size_overflow(stmt, TREE_TYPE(new_rhs1), new_rhs1, rhs, BEFORE_STMT);

	return dup_assign(visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);
}

static tree handle_unary_rhs(struct pointer_set_t *visited, gimple stmt)
{
	tree rhs1, new_rhs1, lhs = gimple_get_lhs(stmt);

	if (gimple_plf(stmt, MY_STMT))
		return lhs;

	rhs1 = gimple_assign_rhs1(stmt);
	if (TREE_CODE(TREE_TYPE(rhs1)) == POINTER_TYPE)
		return create_assign(visited, stmt, lhs, AFTER_STMT);

	new_rhs1 = expand(visited, rhs1);

	if (new_rhs1 == NULL_TREE)
		return create_cast_assign(visited, stmt);

	if (gimple_plf(stmt, NO_CAST_CHECK))
		return dup_assign(visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);

	if (gimple_assign_rhs_code(stmt) == BIT_NOT_EXPR) {
		tree size_overflow_type = get_size_overflow_type(stmt, rhs1);

		new_rhs1 = cast_to_new_size_overflow_type(stmt, new_rhs1, size_overflow_type, BEFORE_STMT);
		check_size_overflow(stmt, size_overflow_type, new_rhs1, rhs1, BEFORE_STMT);
		return create_assign(visited, stmt, lhs, AFTER_STMT);
	}

	if (!gimple_assign_cast_p(stmt))
		return dup_assign(visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);

	return create_cast_overflow_check(visited, new_rhs1, stmt);
}

static tree handle_unary_ops(struct pointer_set_t *visited, gimple stmt)
{
	tree rhs1, lhs = gimple_get_lhs(stmt);
	gimple def_stmt = get_def_stmt(lhs);

	gcc_assert(gimple_code(def_stmt) != GIMPLE_NOP);
	rhs1 = gimple_assign_rhs1(def_stmt);

	if (is_gimple_constant(rhs1))
		return create_assign(visited, def_stmt, lhs, AFTER_STMT);

	switch (TREE_CODE(rhs1)) {
	case SSA_NAME:
		return handle_unary_rhs(visited, def_stmt);
	case ARRAY_REF:
	case BIT_FIELD_REF:
	case ADDR_EXPR:
	case COMPONENT_REF:
	case INDIRECT_REF:
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case TARGET_MEM_REF:
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

static void insert_cond_result(basic_block bb_true, const_gimple stmt, const_tree arg, bool min)
{
	gimple func_stmt;
	const_gimple def_stmt;
	const_tree loc_line;
	tree loc_file, ssa_name, current_func;
	expanded_location xloc;
	char *ssa_name_buf;
	int len;
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

	current_func = build_string(NAME_LEN(current_function_decl) + 1, NAME(current_function_decl));
	current_func = create_string_param(current_func);

	gcc_assert(DECL_NAME(SSA_NAME_VAR(arg)) != NULL);
	call_count++;
	len = asprintf(&ssa_name_buf, "%s_%u %s, count: %u\n", NAME(SSA_NAME_VAR(arg)), SSA_NAME_VERSION(arg), min ? "min" : "max", call_count);
	gcc_assert(len > 0);
	ssa_name = build_string(len + 1, ssa_name_buf);
	free(ssa_name_buf);
	ssa_name = create_string_param(ssa_name);

	// void report_size_overflow(const char *file, unsigned int line, const char *func, const char *ssa_name)
	func_stmt = gimple_build_call(report_size_overflow_decl, 4, loc_file, loc_line, current_func, ssa_name);

	gsi_insert_after(&gsi, func_stmt, GSI_CONTINUE_LINKING);
}

static void __unused print_the_code_insertions(const_gimple stmt)
{
	location_t loc = gimple_location(stmt);

	inform(loc, "Integer size_overflow check applied here.");
}

static void insert_check_size_overflow(gimple stmt, enum tree_code cond_code, tree arg, tree type_value, bool before, bool min)
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
	insert_cond_result(bb_true, stmt, arg, min);

//	print_the_code_insertions(stmt);
}

static void check_size_overflow(gimple stmt, tree size_overflow_type, tree cast_rhs, tree rhs, bool before)
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
	type_min_type = TREE_TYPE(type_min);
	gcc_assert(types_compatible_p(cast_rhs_type, type_max_type));
	gcc_assert(types_compatible_p(type_max_type, type_min_type));

	insert_check_size_overflow(stmt, GT_EXPR, cast_rhs, type_max, before, false);
	insert_check_size_overflow(stmt, LT_EXPR, cast_rhs, type_min, before, true);
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

static tree handle_intentional_overflow(struct pointer_set_t *visited, bool check_overflow, gimple stmt, tree change_rhs, tree new_rhs2)
{
	tree new_rhs, orig_rhs;
	void (*gimple_assign_set_rhs)(gimple, tree);
	tree rhs1 = gimple_assign_rhs1(stmt);
	tree rhs2 = gimple_assign_rhs2(stmt);
	tree lhs = gimple_get_lhs(stmt);

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

	check_size_overflow(stmt, TREE_TYPE(change_rhs), change_rhs, orig_rhs, BEFORE_STMT);

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
	rhs1_def_stmt_lhs = gimple_get_lhs(rhs1_def_stmt);
	rhs2_def_stmt_lhs = gimple_get_lhs(rhs2_def_stmt);
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

static tree handle_integer_truncation(struct pointer_set_t *visited, const_tree lhs)
{
	tree new_rhs1, new_rhs2;
	tree new_rhs1_def_stmt_rhs1, new_rhs2_def_stmt_rhs1, new_lhs;
	gimple assign, stmt = get_def_stmt(lhs);
	tree rhs1 = gimple_assign_rhs1(stmt);
	tree rhs2 = gimple_assign_rhs2(stmt);

	if (!is_subtraction_special(stmt))
		return NULL_TREE;

	new_rhs1 = expand(visited, rhs1);
	new_rhs2 = expand(visited, rhs2);

	new_rhs1_def_stmt_rhs1 = get_def_stmt_rhs(new_rhs1);
	new_rhs2_def_stmt_rhs1 = get_def_stmt_rhs(new_rhs2);

	if (!types_compatible_p(TREE_TYPE(new_rhs1_def_stmt_rhs1), TREE_TYPE(new_rhs2_def_stmt_rhs1))) {
		new_rhs1_def_stmt_rhs1 = cast_to_TI_type(stmt, new_rhs1_def_stmt_rhs1);
		new_rhs2_def_stmt_rhs1 = cast_to_TI_type(stmt, new_rhs2_def_stmt_rhs1);
	}

	assign = create_binary_assign(MINUS_EXPR, stmt, new_rhs1_def_stmt_rhs1, new_rhs2_def_stmt_rhs1);
	new_lhs = gimple_get_lhs(assign);
	check_size_overflow(assign, TREE_TYPE(new_lhs), new_lhs, rhs1, AFTER_STMT);

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
	if (gimple_code(def_stmt) != GIMPLE_ASSIGN || gimple_assign_rhs_code(def_stmt) != BIT_NOT_EXPR)
		return false;

	return true;
}

static tree handle_binary_ops(struct pointer_set_t *visited, tree lhs)
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

	new_lhs = handle_integer_truncation(visited, lhs);
	if (new_lhs != NULL_TREE)
		return new_lhs;

	if (TREE_CODE(rhs1) == SSA_NAME)
		new_rhs1 = expand(visited, rhs1);
	if (TREE_CODE(rhs2) == SSA_NAME)
		new_rhs2 = expand(visited, rhs2);

	if (is_a_neg_overflow(def_stmt, rhs2))
		return handle_intentional_overflow(visited, true, def_stmt, new_rhs1, NULL_TREE);
	if (is_a_neg_overflow(def_stmt, rhs1))
		return handle_intentional_overflow(visited, true, def_stmt, new_rhs2, new_rhs2);


	if (is_a_constant_overflow(def_stmt, rhs2))
		return handle_intentional_overflow(visited, !is_a_cast_and_const_overflow(rhs1), def_stmt, new_rhs1, NULL_TREE);
	if (is_a_constant_overflow(def_stmt, rhs1))
		return handle_intentional_overflow(visited, !is_a_cast_and_const_overflow(rhs2), def_stmt, new_rhs2, new_rhs2);

	return dup_assign(visited, def_stmt, lhs, new_rhs1, new_rhs2, NULL_TREE);
}

#if BUILDING_GCC_VERSION >= 4007
static tree get_new_rhs(struct pointer_set_t *visited, tree size_overflow_type, tree rhs)
{
	if (is_gimple_constant(rhs))
		return cast_a_tree(size_overflow_type, rhs);
	if (TREE_CODE(rhs) != SSA_NAME)
		return NULL_TREE;
	return expand(visited, rhs);
}

static tree handle_ternary_ops(struct pointer_set_t *visited, tree lhs)
{
	tree rhs1, rhs2, rhs3, new_rhs1, new_rhs2, new_rhs3, size_overflow_type;
	gimple def_stmt = get_def_stmt(lhs);

	size_overflow_type = get_size_overflow_type(def_stmt, lhs);

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);
	rhs3 = gimple_assign_rhs3(def_stmt);
	new_rhs1 = get_new_rhs(visited, size_overflow_type, rhs1);
	new_rhs2 = get_new_rhs(visited, size_overflow_type, rhs2);
	new_rhs3 = get_new_rhs(visited, size_overflow_type, rhs3);

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
			new_type = intDI_type_node;
		else
			new_type = intTI_type_node;
		break;
	default:
		debug_tree((tree)node);
		error("%s: unsupported gcc configuration.", __func__);
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

static tree expand(struct pointer_set_t *visited, tree lhs)
{
	gimple def_stmt;

	if (skip_types(lhs))
		return NULL_TREE;

	def_stmt = get_def_stmt(lhs);

	if (!def_stmt || gimple_code(def_stmt) == GIMPLE_NOP)
		return NULL_TREE;

	if (gimple_plf(def_stmt, MY_STMT))
		return lhs;

	if (pointer_set_contains(visited, def_stmt))
		return expand_visited(def_stmt);

	switch (gimple_code(def_stmt)) {
	case GIMPLE_PHI:
		return handle_phi(visited, lhs);
	case GIMPLE_CALL:
	case GIMPLE_ASM:
		return create_assign(visited, def_stmt, lhs, AFTER_STMT);
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			return handle_unary_ops(visited, def_stmt);
		case 3:
			return handle_binary_ops(visited, lhs);
#if BUILDING_GCC_VERSION >= 4007
		case 4:
			return handle_ternary_ops(visited, lhs);
#endif
		}
	default:
		debug_gimple_stmt(def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
}

static tree get_new_tree(gimple stmt, const_tree orig_node, tree new_node)
{
	const_gimple assign;
	tree orig_type = TREE_TYPE(orig_node);
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);

	assign = build_cast_stmt(orig_type, new_node, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	return gimple_get_lhs(assign);
}

static void change_function_arg(gimple stmt, const_tree orig_arg, unsigned int argnum, tree new_arg)
{
	gimple_call_set_arg(stmt, argnum, get_new_tree(stmt, orig_arg, new_arg));
	update_stmt(stmt);
}

static void change_function_return(gimple stmt, const_tree orig_ret, tree new_ret)
{
	gimple_return_set_retval(stmt, get_new_tree(stmt, orig_ret, new_ret));
	update_stmt(stmt);
}

static bool get_function_arg(unsigned int* argnum, const_tree fndecl)
{
	tree arg;
	const_tree origarg;

	if (!DECL_ABSTRACT_ORIGIN(fndecl))
		return true;

	origarg = DECL_ARGUMENTS(DECL_ABSTRACT_ORIGIN(fndecl));
	while (origarg && *argnum) {
		(*argnum)--;
		origarg = TREE_CHAIN(origarg);
	}

	gcc_assert(*argnum == 0);

	gcc_assert(origarg != NULL_TREE);
	*argnum = 0;
	for (arg = DECL_ARGUMENTS(fndecl); arg; arg = TREE_CHAIN(arg), (*argnum)++)
		if (operand_equal_p(origarg, arg, 0) || !strcmp(NAME(origarg), NAME(arg)))
			return true;
	return false;
}

static enum mark walk_phi(struct pointer_set_t *visited, bool *search_err_code, const_tree result)
{
	gimple phi = get_def_stmt(result);
	unsigned int i, n = gimple_phi_num_args(phi);

	if (!phi)
		return MARK_NO;

	pointer_set_insert(visited, phi);
	for (i = 0; i < n; i++) {
		enum mark marked;
		const_tree arg = gimple_phi_arg_def(phi, i);
		marked = pre_expand(visited, search_err_code, arg);
		if (marked != MARK_NO)
			return marked;
	}
	return MARK_NO;
}

static enum mark walk_unary_ops(struct pointer_set_t *visited, bool *search_err_code, const_tree lhs)
{
	gimple def_stmt = get_def_stmt(lhs);
	const_tree rhs;

	if (!def_stmt)
		return MARK_NO;

	rhs = gimple_assign_rhs1(def_stmt);

	def_stmt = get_def_stmt(rhs);
	if (is_gimple_constant(rhs))
		search_err_code[FROM_CONST] = true;

	return pre_expand(visited, search_err_code, rhs);
}

static enum mark walk_binary_ops(struct pointer_set_t *visited, bool *search_err_code, const_tree lhs)
{
	gimple def_stmt = get_def_stmt(lhs);
	const_tree rhs1, rhs2;
	enum mark marked;

	if (!def_stmt)
		return MARK_NO;

	search_err_code[CAST_ONLY] = false;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);
	marked = pre_expand(visited, search_err_code, rhs1);
	if (marked != MARK_NO)
		return marked;
	return pre_expand(visited, search_err_code, rhs2);
}

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

static enum mark mark_status(const_tree fndecl, unsigned int argnum)
{
	const_tree attr, p;

	// mm/filemap.c D.35286_51 = D.35283_46 (file_10(D), mapping_11, pos_1, D.35273_50, D.35285_49, page.14_48, fsdata.15_47);
	if (fndecl == NULL_TREE)
		return MARK_NO;

	attr = lookup_attribute("intentional_overflow", DECL_ATTRIBUTES(fndecl));
	if (!attr || !TREE_VALUE(attr))
		return MARK_NO;

	p = TREE_VALUE(attr);
	if (TREE_INT_CST_HIGH(TREE_VALUE(p)) == -1)
		return MARK_TURN_OFF;
	if (!TREE_INT_CST_LOW(TREE_VALUE(p)))
		return MARK_NOT_INTENTIONAL;
	if (argnum == 0) {
		gcc_assert(current_function_decl == fndecl);
		return MARK_NO;
	}

	do {
		if (argnum == TREE_INT_CST_LOW(TREE_VALUE(p)))
			return MARK_YES;
		p = TREE_CHAIN(p);
	} while (p);

	return MARK_NO;
}

static void print_missing_msg(tree func, unsigned int argnum)
{
	unsigned int new_hash;
	size_t len;
	unsigned char tree_codes[CODES_LIMIT];
	location_t loc;
	const char *curfunc;

	func = get_original_function_decl(func);
	loc = DECL_SOURCE_LOCATION(func);
	curfunc = get_asm_name(func);

	len = get_function_decl(func, tree_codes);
	new_hash = get_hash_num(curfunc, (const char *) tree_codes, len, 0);
	inform(loc, "Function %s is missing from the size_overflow hash table +%s+%u+%u+", curfunc, curfunc, argnum, new_hash);
}

static unsigned int search_missing_attribute(const_tree arg)
{
	unsigned int argnum;
	const struct size_overflow_hash *hash;
	const_tree type = TREE_TYPE(arg);
	tree func = get_original_function_decl(current_function_decl);

	gcc_assert(TREE_CODE(arg) != COMPONENT_REF);

	if (TREE_CODE(type) == POINTER_TYPE)
		return 0;

	argnum = find_arg_number(arg, func);
	if (argnum == 0)
		return 0;

	if (lookup_attribute("size_overflow", DECL_ATTRIBUTES(func)))
		return argnum;

	hash = get_function_hash(func);
	if (!hash || !(hash->param & (1U << argnum))) {
		print_missing_msg(func, argnum);
		return 0;
	}
	return argnum;
}

static enum mark is_already_marked(const_tree lhs)
{
	unsigned int argnum;
	const_tree fndecl;

	argnum = search_missing_attribute(lhs);
	fndecl = get_original_function_decl(current_function_decl);
	if (argnum && mark_status(fndecl, argnum) == MARK_YES)
		return MARK_YES;
	return MARK_NO;
}

static enum mark pre_expand(struct pointer_set_t *visited, bool *search_err_code, const_tree lhs)
{
	const_gimple def_stmt;

	if (skip_types(lhs))
		return MARK_NO;

	if (TREE_CODE(lhs) == PARM_DECL)
		return is_already_marked(lhs);

	if (TREE_CODE(lhs) == COMPONENT_REF) {
		const_tree field, attr;

		field = search_field_decl(lhs);
		attr = lookup_attribute("intentional_overflow", DECL_ATTRIBUTES(field));
		if (!attr || !TREE_VALUE(attr))
			return MARK_NO;
		return MARK_YES;
	}

	def_stmt = get_def_stmt(lhs);

	if (!def_stmt)
		return MARK_NO;

	if (pointer_set_contains(visited, def_stmt))
		return MARK_NO;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
		if (TREE_CODE(SSA_NAME_VAR(lhs)) == PARM_DECL)
			return is_already_marked(lhs);
		return MARK_NO;
	case GIMPLE_PHI:
		return walk_phi(visited, search_err_code, lhs);
	case GIMPLE_CALL:
		if (mark_status((gimple_call_fndecl(def_stmt)), 0) == MARK_TURN_OFF)
			return MARK_TURN_OFF;
		check_function_hash(def_stmt);
		return MARK_NO;
	case GIMPLE_ASM:
		search_err_code[CAST_ONLY] = false;
		return MARK_NO;
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			return walk_unary_ops(visited, search_err_code, lhs);
		case 3:
			return walk_binary_ops(visited, search_err_code, lhs);
		}
	default:
		debug_gimple_stmt((gimple)def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
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

/*
0</MARK_YES: no dup, search attributes (so, int)
0/MARK_NOT_INTENTIONAL: no dup, search attribute (int)
-1/MARK_TURN_OFF: no dup, no search, current_function_decl -> no dup
*/

static bool search_attributes(tree fndecl, const_tree arg, unsigned int argnum, bool where)
{
	struct pointer_set_t *visited;
	enum mark is_marked, is_found;
	location_t loc;
	bool search_err_code[2] = {true, false};

	is_marked = mark_status(current_function_decl, 0);
	if (is_marked == MARK_TURN_OFF)
		return true;

	is_marked = mark_status(fndecl, argnum + 1);
	if (is_marked == MARK_TURN_OFF || is_marked == MARK_NOT_INTENTIONAL)
		return true;

	visited = pointer_set_create();
	is_found = pre_expand(visited, search_err_code, arg);
	pointer_set_destroy(visited);

	if (where == FROM_RET && search_err_code[CAST_ONLY] && search_err_code[FROM_CONST])
		return true;

	if (where == FROM_ARG && skip_asm(arg))
		return true;

	if (is_found == MARK_TURN_OFF)
		return true;

	if ((is_found == MARK_YES && is_marked == MARK_YES))
		return true;

	if (is_found == MARK_YES) {
		loc = DECL_SOURCE_LOCATION(fndecl);
		inform(loc, "The intentional_overflow attribute is missing from +%s+%u+", get_asm_name(fndecl), argnum + 1);
		return true;
	}
	return false;
}

static void handle_function_arg(gimple stmt, tree fndecl, unsigned int argnum)
{
	struct pointer_set_t *visited;
	tree arg, new_arg;
	bool match;

	if (argnum == 0)
		return;

	argnum--;

	match = get_function_arg(&argnum, fndecl);
	if (!match)
		return;
	gcc_assert(gimple_call_num_args(stmt) > argnum);
	arg = gimple_call_arg(stmt, argnum);
	if (arg == NULL_TREE)
		return;

	if (skip_types(arg))
		return;

	if (search_attributes(fndecl, arg, argnum, FROM_ARG))
		return;

	visited = pointer_set_create();
	new_arg = expand(visited, arg);
	pointer_set_destroy(visited);

	if (new_arg == NULL_TREE)
		return;

	change_function_arg(stmt, arg, argnum, new_arg);
	check_size_overflow(stmt, TREE_TYPE(new_arg), new_arg, arg, BEFORE_STMT);
}

static void handle_function_by_attribute(gimple stmt, const_tree attr, tree fndecl)
{
	tree p = TREE_VALUE(attr);
	do {
		handle_function_arg(stmt, fndecl, TREE_INT_CST_LOW(TREE_VALUE(p)));
		p = TREE_CHAIN(p);
	} while (p);
}

static void handle_function_by_hash(gimple stmt, tree fndecl)
{
	unsigned int num;
	const struct size_overflow_hash *hash;

	hash = get_function_hash(fndecl);
	if (!hash)
		return;

	for (num = 0; num <= MAX_PARAM; num++)
		if (hash->param & (1U << num))
			handle_function_arg(stmt, fndecl, num);
}

static bool check_return_value(void)
{
	const struct size_overflow_hash *hash;

	hash = get_function_hash(current_function_decl);
	if (!hash || !(hash->param & 1U << 0))
		return false;

	return true;
}

static void handle_return_value(gimple ret_stmt)
{
	struct pointer_set_t *visited;
	tree ret, new_ret;

	if (gimple_code(ret_stmt) != GIMPLE_RETURN)
		return;

	ret = gimple_return_retval(ret_stmt);

	if (skip_types(ret))
		return;

	if (search_attributes(current_function_decl, ret, 0, FROM_RET))
		return;

	visited = pointer_set_create();
	new_ret = expand(visited, ret);
	pointer_set_destroy(visited);

	change_function_return(ret_stmt, ret, new_ret);
	check_size_overflow(ret_stmt, TREE_TYPE(new_ret), new_ret, ret, BEFORE_STMT);
}

static void set_plf_false(void)
{
	basic_block bb;

	FOR_ALL_BB(bb) {
		gimple_stmt_iterator si;

		for (si = gsi_start_bb(bb); !gsi_end_p(si); gsi_next(&si))
			gimple_set_plf(gsi_stmt(si), MY_STMT, false);
		for (si = gsi_start_phis(bb); !gsi_end_p(si); gsi_next(&si))
			gimple_set_plf(gsi_stmt(si), MY_STMT, false);
	}
}

static unsigned int handle_function(void)
{
	basic_block next, bb = ENTRY_BLOCK_PTR->next_bb;
	bool check_ret;

	set_plf_false();

	check_ret = check_return_value();

	do {
		gimple_stmt_iterator gsi;
		next = bb->next_bb;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			tree fndecl, attr;
			gimple stmt = gsi_stmt(gsi);

			if (check_ret)
				handle_return_value(stmt);

			if (!(is_gimple_call(stmt)))
				continue;
			fndecl = gimple_call_fndecl(stmt);
			if (fndecl == NULL_TREE)
				continue;
			if (gimple_call_num_args(stmt) == 0)
				continue;
			attr = lookup_attribute("size_overflow", DECL_ATTRIBUTES(fndecl));
			if (!attr || !TREE_VALUE(attr))
				handle_function_by_hash(stmt, fndecl);
			else
				handle_function_by_attribute(stmt, attr, fndecl);
			gsi = gsi_for_stmt(stmt);
			next = gimple_bb(stmt)->next_bb;
		}
		bb = next;
	} while (bb);
	return 0;
}

static struct gimple_opt_pass size_overflow_pass = {
	.pass = {
		.type			= GIMPLE_PASS,
		.name			= "size_overflow",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
		.gate			= NULL,
		.execute		= handle_function,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
		.tv_id			= TV_NONE,
		.properties_required	= PROP_cfg,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= TODO_dump_func | TODO_verify_ssa | TODO_verify_stmts | TODO_remove_unused_locals | TODO_update_ssa_no_phi | TODO_cleanup_cfg | TODO_ggc_collect | TODO_verify_flow
	}
};

static void start_unit_callback(void __unused *gcc_data, void __unused *user_data)
{
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

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	int i;
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	bool enable = true;

	struct register_pass_info size_overflow_pass_info = {
		.pass				= &size_overflow_pass.pass,
		.reference_pass_name		= "ssa",
		.ref_pass_instance_number	= 1,
		.pos_op				= PASS_POS_INSERT_AFTER
	};

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
		register_callback("start_unit", PLUGIN_START_UNIT, &start_unit_callback, NULL);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &size_overflow_pass_info);
	}
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	return 0;
}

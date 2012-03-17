/*
 * Copyright 2011, 2012 by Emese Revfy <re.emese@gmail.com>
 * Licensed under the GPL v2, or (at your option) v3
 *
 * Homepage:
 * http://www.grsecurity.net/~ephox/overflow_plugin/
 *
 * This plugin recomputes expressions of function arguments marked by a size_overflow attribute
 * with double integer precision (DImode/TImode for 32/64 bit integer types).
 * The recomputed argument is checked against INT_MAX and an event is logged on overflow and the triggering process is killed.
 *
 * Usage:
 * $ gcc -I`gcc -print-file-name=plugin`/include -fPIC -shared -O2 -o size_overflow_plugin.so size_overflow_plugin.c
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
#include "c-common.h"
#include "diagnostic.h"

struct size_overflow_hash {
		const char *name;
		const char *file;
		unsigned short collision:1;
		unsigned short param1:1;
		unsigned short param2:1;
		unsigned short param3:1;
		unsigned short param4:1;
		unsigned short param5:1;
		unsigned short param6:1;
		unsigned short param7:1;
		unsigned short param8:1;
		unsigned short param9:1;
};

#include "size_overflow_hash1.h"
#include "size_overflow_hash2.h"

#define __unused __attribute__((__unused__))
#define NAME(node) IDENTIFIER_POINTER(DECL_NAME(node))
#define BEFORE_STMT true
#define AFTER_STMT false
#define CREATE_NEW_VAR NULL_TREE

int plugin_is_GPL_compatible;
void debug_gimple_stmt (gimple gs);

static tree expand(struct pointer_set_t *visited, tree var);
static tree signed_size_overflow_type;
static tree unsigned_size_overflow_type;
static tree report_size_overflow_decl;
static tree const_char_ptr_type_node;
static unsigned int handle_function(void);

static struct plugin_info size_overflow_plugin_info = {
	.version	= "20120311beta",
	.help		= "no-size_overflow\tturn off size overflow checking\n",
};

static tree handle_size_overflow_attribute(tree *node, tree __unused name, tree args, int __unused flags, bool *no_add_attrs)
{
	unsigned int arg_count = type_num_arguments(*node);

	for (; args; args = TREE_CHAIN(args)) {
		tree position = TREE_VALUE(args);
		if (TREE_CODE(position) != INTEGER_CST || TREE_INT_CST_HIGH(position) || TREE_INT_CST_LOW(position) < 1 || TREE_INT_CST_LOW(position) > arg_count ) {
			error("handle_size_overflow_attribute: overflow parameter outside range.");
			*no_add_attrs = true;
		}
	}
	return NULL_TREE;
}

static struct attribute_spec no_size_overflow_attr = {
	.name				= "size_overflow",
	.min_length			= 1,
	.max_length			= -1,
	.decl_required			= false,
	.type_required			= true,
	.function_type_required		= true,
	.handler			= handle_size_overflow_attribute
};

static void register_attributes(void __unused *event_data, void __unused *data)
{
	register_attribute(&no_size_overflow_attr);
}

// http://www.team5150.com/~andrew/noncryptohashzoo2~/CrapWow.html
static unsigned int CrapWow(const char *key, unsigned int len, unsigned int seed)
{
#define cwfold( a, b, lo, hi ) { p = (unsigned int)(a) * (unsigned long long)(b); lo ^= (unsigned int)p; hi ^= (unsigned int)(p >> 32); }
#define cwmixa( in ) { cwfold( in, m, k, h ); }
#define cwmixb( in ) { cwfold( in, n, h, k ); }

	const unsigned int m = 0x57559429;
	const unsigned int n = 0x5052acdb;
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

static inline unsigned int size_overflow_hash(const char *fndecl, unsigned int seed)
{
	return CrapWow(fndecl, strlen(fndecl), seed) & 0xffff;
}

static inline tree get_original_function_decl(tree fndecl)
{
	if (DECL_ABSTRACT_ORIGIN(fndecl))
		return DECL_ABSTRACT_ORIGIN(fndecl);
	return fndecl;
}

static inline gimple get_def_stmt(tree node)
{
	gcc_assert(TREE_CODE(node) == SSA_NAME);
	return SSA_NAME_DEF_STMT(node);
}

static struct size_overflow_hash *get_function_hash(tree fndecl)
{
	unsigned int hash;
	const char *func = NAME(fndecl);

	hash = size_overflow_hash(func, 0);

	if (size_overflow_hash1[hash].collision) {
		hash = size_overflow_hash(func, 23432);
		return &size_overflow_hash2[hash];
	}
	return &size_overflow_hash1[hash];
}

static void check_missing_attribute(tree arg)
{
	tree var, func = get_original_function_decl(current_function_decl);
	const char *curfunc = NAME(func);
	unsigned int new_hash, argnum = 1;
	struct size_overflow_hash *hash;
	location_t loc;
	expanded_location xloc;
	bool match = false;

	loc = DECL_SOURCE_LOCATION(func);
	xloc = expand_location(loc);

	if (lookup_attribute("size_overflow", TYPE_ATTRIBUTES(TREE_TYPE(func))))
		return;

	hash = get_function_hash(func);
	if (hash->name && !strcmp(hash->name, NAME(func)) && !strcmp(hash->file, xloc.file))
		return;

	gcc_assert(TREE_CODE(arg) != COMPONENT_REF);

	if (TREE_CODE(arg) == SSA_NAME)
		arg = SSA_NAME_VAR(arg);

	for (var = DECL_ARGUMENTS(func); var; var = TREE_CHAIN(var)) {
		if (strcmp(NAME(arg), NAME(var))) {
			argnum++;
			continue;
		}
		match = true;
		if (!TYPE_UNSIGNED(TREE_TYPE(var)))
			return;
		break;
	}
	if (!match) {
		warning(0, "check_missing_attribute: cannot find the %s argument in %s", NAME(arg), NAME(func));
		return;
	}

#define check_param(num)			\
	if (num == argnum && hash->param##num)	\
		return;
	check_param(1);
	check_param(2);
	check_param(3);
	check_param(4);
	check_param(5);
	check_param(6);
	check_param(7);
	check_param(8);
	check_param(9);
#undef check_param

	new_hash = size_overflow_hash(curfunc, 0);
	inform(loc, "Function %s is missing from the size_overflow hash table +%s+%d+%u+%s", curfunc, curfunc, argnum, new_hash, xloc.file);
}

static tree create_new_var(tree type)
{
	tree new_var = create_tmp_var(type, "cicus");

	add_referenced_var(new_var);
	mark_sym_for_renaming(new_var);
	return new_var;
}

static bool is_bool(tree node)
{
	tree type;

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

static gimple build_cast_stmt(tree type, tree var, tree new_var, location_t loc)
{
	gimple assign;

	if (new_var == CREATE_NEW_VAR)
		new_var = create_new_var(type);

	assign = gimple_build_assign(new_var, fold_convert(type, var));
	gimple_set_location(assign, loc);
	gimple_set_lhs(assign, make_ssa_name(new_var, assign));

	return assign;
}

static tree create_assign(struct pointer_set_t *visited, gimple oldstmt, tree rhs1, bool before)
{
	tree oldstmt_rhs1;
	enum tree_code code;
	gimple stmt;
	gimple_stmt_iterator gsi;

	if (is_bool(rhs1)) {
		pointer_set_insert(visited, oldstmt);
		return gimple_get_lhs(oldstmt);
	}

	if (rhs1 == NULL_TREE) {
		debug_gimple_stmt(oldstmt);
		error("create_assign: rhs1 is NULL_TREE");
		gcc_unreachable();
	}

	oldstmt_rhs1 = gimple_assign_rhs1(oldstmt);
	code = TREE_CODE(oldstmt_rhs1);
	if (code == PARM_DECL || (code == SSA_NAME && gimple_code(get_def_stmt(oldstmt_rhs1)) == GIMPLE_NOP))
		check_missing_attribute(oldstmt_rhs1);

	stmt = build_cast_stmt(signed_size_overflow_type, rhs1, CREATE_NEW_VAR, gimple_location(oldstmt));
	gsi = gsi_for_stmt(oldstmt);
	if (before)
		gsi_insert_before(&gsi, stmt, GSI_NEW_STMT);
	else
		gsi_insert_after(&gsi, stmt, GSI_NEW_STMT);
	update_stmt(stmt);
	pointer_set_insert(visited, oldstmt);
	return gimple_get_lhs(stmt);
}

static tree dup_assign(struct pointer_set_t *visited, gimple oldstmt, tree rhs1, tree rhs2, tree __unused rhs3)
{
	tree new_var, lhs = gimple_get_lhs(oldstmt);
	gimple stmt;
	gimple_stmt_iterator gsi;

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

	if (gimple_assign_rhs_code(oldstmt) == WIDEN_MULT_EXPR)
		gimple_assign_set_rhs_code(stmt, MULT_EXPR);

	if (is_bool(lhs))
		new_var = SSA_NAME_VAR(lhs);
	else
		new_var = create_new_var(signed_size_overflow_type);
	new_var = make_ssa_name(new_var, stmt);
	gimple_set_lhs(stmt, new_var);

	if (rhs1 != NULL_TREE) {
		if (!gimple_assign_cast_p(oldstmt))
			rhs1 = fold_convert(signed_size_overflow_type, rhs1);
		gimple_assign_set_rhs1(stmt, rhs1);
	}

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

static gimple overflow_create_phi_node(gimple oldstmt, tree var)
{
	basic_block bb;
	gimple phi;
	gimple_stmt_iterator gsi = gsi_for_stmt(oldstmt);

	bb = gsi_bb(gsi);
	phi = make_phi_node(var, EDGE_COUNT(bb->preds));

	gsi_insert_after(&gsi, phi, GSI_NEW_STMT);
	gimple_set_bb(phi, bb);
	return phi;
}

static tree signed_cast_constant(tree node)
{
	gcc_assert(is_gimple_constant(node));

	if (TYPE_PRECISION(signed_size_overflow_type) == TYPE_PRECISION(TREE_TYPE(node)))
		return build_int_cst_wide(signed_size_overflow_type, TREE_INT_CST_LOW(node), TREE_INT_CST_HIGH(node));
	else
		return build_int_cst(signed_size_overflow_type, int_cst_value(node));
}

static gimple cast_old_phi_arg(gimple oldstmt, tree arg, tree new_var)
{
	basic_block first_bb;
	gimple newstmt;
	gimple_stmt_iterator gsi;

	newstmt = build_cast_stmt(signed_size_overflow_type, arg, new_var, gimple_location(oldstmt));

	first_bb = split_block_after_labels(ENTRY_BLOCK_PTR)->dest;
	if (dom_info_available_p(CDI_DOMINATORS))
		set_immediate_dominator(CDI_DOMINATORS, first_bb, ENTRY_BLOCK_PTR);
	gsi = gsi_start_bb(first_bb);

	gsi_insert_before(&gsi, newstmt, GSI_NEW_STMT);
	return newstmt;
}

static gimple handle_new_phi_arg(tree arg, tree new_var, tree new_rhs)
{
	gimple newstmt;
	gimple_stmt_iterator gsi;
	void (*gsi_insert)(gimple_stmt_iterator *, gimple, enum gsi_iterator_update);
	gimple def_newstmt = get_def_stmt(new_rhs);

	gsi_insert = gsi_insert_after;
	gsi = gsi_for_stmt(def_newstmt);

	switch (gimple_code(get_def_stmt(arg))) {
	case GIMPLE_PHI:
		newstmt = gimple_build_assign(new_var, new_rhs);
		gsi = gsi_after_labels(gimple_bb(def_newstmt));
		gsi_insert = gsi_insert_before;
		break;
	case GIMPLE_ASM:
	case GIMPLE_CALL:
		newstmt = gimple_build_assign(new_var, new_rhs);
		break;
	case GIMPLE_ASSIGN:
		newstmt = gimple_copy(def_newstmt);
		break;
	default:
		/* unknown gimple_code (build_new_phi_arg) */
		gcc_unreachable();
	}

	gimple_set_lhs(newstmt, make_ssa_name(new_var, newstmt));
	gsi_insert(&gsi, newstmt, GSI_NEW_STMT);
	return newstmt;
}

static tree build_new_phi_arg(struct pointer_set_t *visited, gimple oldstmt, tree arg, tree new_var)
{
	gimple newstmt;
	tree new_rhs;

	if (is_gimple_constant(arg))
		return signed_cast_constant(arg);

	pointer_set_insert(visited, oldstmt);
	new_rhs = expand(visited, arg);
	if (new_rhs == NULL_TREE) {
		gcc_assert(TREE_CODE(TREE_TYPE(arg)) != VOID_TYPE);
		newstmt = cast_old_phi_arg(oldstmt, arg, new_var);
	} else
		newstmt = handle_new_phi_arg(arg, new_var, new_rhs);
	update_stmt(newstmt);
	return gimple_get_lhs(newstmt);
}

static tree build_new_phi(struct pointer_set_t *visited, gimple oldstmt)
{
	gimple phi;
	tree new_var = create_new_var(signed_size_overflow_type);
	unsigned int i, n = gimple_phi_num_args(oldstmt);

	phi = overflow_create_phi_node(oldstmt, new_var);

	for (i = 0; i < n; i++) {
		tree arg, lhs;

		arg = gimple_phi_arg_def(oldstmt, i);
		lhs = build_new_phi_arg(visited, oldstmt, arg, new_var);
		add_phi_arg(phi, lhs, gimple_phi_arg_edge(oldstmt, i), gimple_location(oldstmt));
	}
	update_stmt(phi);
	return gimple_phi_result(phi);
}

static tree handle_unary_ops(struct pointer_set_t *visited, tree var)
{
	gimple def_stmt = get_def_stmt(var);
	tree new_rhs1, rhs1 = gimple_assign_rhs1(def_stmt);

	if (is_gimple_constant(rhs1))
		return dup_assign(visited, def_stmt, signed_cast_constant(rhs1), NULL_TREE, NULL_TREE);

	switch (TREE_CODE(rhs1)) {
	case SSA_NAME:
		new_rhs1 = expand(visited, rhs1);
		break;
	case ARRAY_REF:
	case ADDR_EXPR:
	case COMPONENT_REF:
	case COND_EXPR:
	case INDIRECT_REF:
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case PARM_DECL:
	case TARGET_MEM_REF:
	case VAR_DECL:
		return create_assign(visited, def_stmt, var, AFTER_STMT);
	default:
		debug_gimple_stmt(def_stmt);
		debug_tree(rhs1);
		gcc_unreachable();
	}

	if (new_rhs1 == NULL_TREE)
		return create_assign(visited, def_stmt, rhs1, AFTER_STMT);
	return dup_assign(visited, def_stmt, new_rhs1, NULL_TREE, NULL_TREE);
}

static tree transform_mult_overflow(tree rhs, tree const_rhs, tree log2const_rhs, location_t loc)
{
	tree new_def_rhs;

	if (!is_gimple_constant(rhs))
		return NULL_TREE;

	new_def_rhs = fold_build2_loc(loc, MULT_EXPR, TREE_TYPE(const_rhs), rhs, const_rhs);
	new_def_rhs = signed_cast_constant(new_def_rhs);
	if (int_cst_value(new_def_rhs) >= 0)
		return NULL_TREE;
	return fold_build2_loc(loc, RSHIFT_EXPR, TREE_TYPE(new_def_rhs), new_def_rhs, log2const_rhs);
}

static tree handle_intentional_mult_overflow(struct pointer_set_t *visited, tree rhs, tree const_rhs)
{
	gimple new_def_stmt, def_stmt;
	tree def_rhs1, def_rhs2, new_def_rhs;
	location_t loc;
	tree log2const_rhs;
	int log2 = exact_log2(TREE_INT_CST_LOW(const_rhs));

	if (log2 == -1) {
//		warning(0, "Possibly unhandled intentional integer truncation");
		return NULL_TREE;
	}

	def_stmt = get_def_stmt(rhs);
	loc = gimple_location(def_stmt);
	def_rhs1 = gimple_assign_rhs1(def_stmt);
	def_rhs2 = gimple_assign_rhs2(def_stmt);
	new_def_stmt = get_def_stmt(expand(visited, rhs));
	log2const_rhs = build_int_cstu(TREE_TYPE(const_rhs), log2);

	new_def_rhs = transform_mult_overflow(def_rhs1, const_rhs, log2const_rhs, loc);
	if (new_def_rhs != NULL_TREE) {
		gimple_assign_set_rhs1(new_def_stmt, new_def_rhs);
	} else {
		new_def_rhs = transform_mult_overflow(def_rhs2, const_rhs, log2const_rhs, loc);
		if (new_def_rhs != NULL_TREE)
			gimple_assign_set_rhs2(new_def_stmt, new_def_rhs);
	}
	if (new_def_rhs == NULL_TREE)
		return NULL_TREE;

	update_stmt(new_def_stmt);
//	warning(0, "Handle integer truncation (gcc optimization)");
	return gimple_get_lhs(new_def_stmt);
}

static bool is_mult_overflow(gimple def_stmt, tree rhs1)
{
	gimple rhs1_def_stmt = get_def_stmt(rhs1);

	if (gimple_assign_rhs_code(def_stmt) != MULT_EXPR)
		return false;
	if (gimple_code(rhs1_def_stmt) != GIMPLE_ASSIGN)
		return false;
	if (gimple_assign_rhs_code(rhs1_def_stmt) != PLUS_EXPR)
		return false;
	return true;
}

static tree handle_intentional_overflow(struct pointer_set_t *visited, gimple def_stmt, tree rhs1, tree rhs2)
{
	if (is_mult_overflow(def_stmt, rhs1))
		return handle_intentional_mult_overflow(visited, rhs1, rhs2);
	return NULL_TREE;
}

static tree handle_binary_ops(struct pointer_set_t *visited, tree var)
{
	tree rhs1, rhs2;
	gimple def_stmt = get_def_stmt(var);
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
	/* logical AND cannot cause an overflow */
	case BIT_AND_EXPR:
		return create_assign(visited, def_stmt, var, AFTER_STMT);
	default:
		break;
	}

	if (is_gimple_constant(rhs2)) {
		new_rhs2 = signed_cast_constant(rhs2);
		new_rhs1 = handle_intentional_overflow(visited, def_stmt, rhs1, rhs2);
	}

	if (is_gimple_constant(rhs1)) {
		new_rhs1 = signed_cast_constant(rhs1);
		new_rhs2 = handle_intentional_overflow(visited, def_stmt, rhs2, rhs1);
	}

	if (new_rhs1 == NULL_TREE && TREE_CODE(rhs1) == SSA_NAME)
		new_rhs1 = expand(visited, rhs1);
	if (new_rhs2 == NULL_TREE && TREE_CODE(rhs2) == SSA_NAME)
		new_rhs2 = expand(visited, rhs2);

	return dup_assign(visited, def_stmt, new_rhs1, new_rhs2, NULL_TREE);
}

#if BUILDING_GCC_VERSION >= 4007
static tree get_new_rhs(struct pointer_set_t *visited, tree rhs)
{
	if (is_gimple_constant(rhs))
		return signed_cast_constant(rhs);
	if (TREE_CODE(rhs) != SSA_NAME)
		return NULL_TREE;
	return expand(visited, rhs);
}

static tree handle_ternary_ops(struct pointer_set_t *visited, tree var)
{
	tree rhs1, rhs2, rhs3, new_rhs1, new_rhs2, new_rhs3;
	gimple def_stmt = get_def_stmt(var);

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);
	rhs3 = gimple_assign_rhs3(def_stmt);
	new_rhs1 = get_new_rhs(visited, rhs1);
	new_rhs2 = get_new_rhs(visited, rhs2);
	new_rhs3 = get_new_rhs(visited, rhs3);

	if (new_rhs1 == NULL_TREE && new_rhs2 != NULL_TREE && new_rhs3 != NULL_TREE)
		return dup_assign(visited, def_stmt, new_rhs1, new_rhs2, new_rhs3);
	error("handle_ternary_ops: unknown rhs");
	gcc_unreachable();
}
#endif

static void set_size_overflow_type(tree node)
{
	switch (TYPE_MODE(TREE_TYPE(node))) {
	case SImode:
		signed_size_overflow_type = intDI_type_node;
		unsigned_size_overflow_type = unsigned_intDI_type_node;
		break;
	case DImode:
		if (LONG_TYPE_SIZE == GET_MODE_BITSIZE(SImode)) {
			signed_size_overflow_type = intDI_type_node;
			unsigned_size_overflow_type = unsigned_intDI_type_node;
		} else {
			signed_size_overflow_type = intTI_type_node;
			unsigned_size_overflow_type = unsigned_intTI_type_node;
		}
		break;
	default:
		error("set_size_overflow_type: unsupported gcc configuration.");
		gcc_unreachable();
	}
}

static tree expand_visited(gimple def_stmt)
{
	gimple tmp;
	gimple_stmt_iterator gsi = gsi_for_stmt(def_stmt);

	gsi_next(&gsi);
	tmp = gsi_stmt(gsi);
	switch (gimple_code(tmp)) {
	case GIMPLE_ASSIGN:
		return gimple_get_lhs(tmp);
	case GIMPLE_PHI:
		return gimple_phi_result(tmp);
	case GIMPLE_CALL:
		return gimple_call_lhs(tmp);
	default:
		return NULL_TREE;
	}
}

static tree expand(struct pointer_set_t *visited, tree var)
{
	gimple def_stmt;

	if (is_gimple_constant(var))
		return NULL_TREE;

	if (TREE_CODE(var) == ADDR_EXPR)
		return NULL_TREE;

	if (SSA_NAME_IS_DEFAULT_DEF(var))
		return NULL_TREE;

	def_stmt = get_def_stmt(var);

	if (!def_stmt)
		return NULL_TREE;

	if (pointer_set_contains(visited, def_stmt))
		return expand_visited(def_stmt);

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
		check_missing_attribute(var);
		return NULL_TREE;
	case GIMPLE_PHI:
		return build_new_phi(visited, def_stmt);
	case GIMPLE_CALL:
	case GIMPLE_ASM:
		gcc_assert(TREE_CODE(TREE_TYPE(var)) != VOID_TYPE);
		return create_assign(visited, def_stmt, var, AFTER_STMT);
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			return handle_unary_ops(visited, var);
		case 3:
			return handle_binary_ops(visited, var);
#if BUILDING_GCC_VERSION >= 4007
		case 4:
			return handle_ternary_ops(visited, var);
#endif
		}
	default:
		debug_gimple_stmt(def_stmt);
		error("expand: unknown gimple code");
		gcc_unreachable();
	}
}

static void change_function_arg(gimple func_stmt, tree origarg, unsigned int argnum, tree newarg)
{
	gimple assign, stmt;
	gimple_stmt_iterator gsi = gsi_for_stmt(func_stmt);
	tree origtype = TREE_TYPE(origarg);

	stmt = gsi_stmt(gsi);
	gcc_assert(gimple_code(stmt) == GIMPLE_CALL);

	assign = build_cast_stmt(origtype, newarg, CREATE_NEW_VAR, gimple_location(stmt));
	gsi_insert_before(&gsi, assign, GSI_SAME_STMT);
	update_stmt(assign);

	gimple_call_set_arg(stmt, argnum, gimple_get_lhs(assign));
	update_stmt(stmt);
}

static tree get_function_arg(unsigned int argnum, gimple stmt, tree fndecl)
{
	const char *origid;
	tree arg, origarg;

	if (!DECL_ABSTRACT_ORIGIN(fndecl)) {
		gcc_assert(gimple_call_num_args(stmt) > argnum);
		return gimple_call_arg(stmt, argnum);
	}

	origarg = DECL_ARGUMENTS(DECL_ABSTRACT_ORIGIN(fndecl));
	while (origarg && argnum) {
		argnum--;
		origarg = TREE_CHAIN(origarg);
	}

	gcc_assert(argnum == 0);

	gcc_assert(origarg != NULL_TREE);
	origid = NAME(origarg);
	for (arg = DECL_ARGUMENTS(fndecl); arg; arg = TREE_CHAIN(arg)) {
		if (!strcmp(origid, NAME(arg)))
			return arg;
	}
	return NULL_TREE;
}

static void insert_cond(tree arg, basic_block cond_bb)
{
	gimple cond_stmt;
	gimple_stmt_iterator gsi = gsi_last_bb(cond_bb);

	cond_stmt = gimple_build_cond(GT_EXPR, arg, build_int_cstu(signed_size_overflow_type, 0x7fffffff), NULL_TREE, NULL_TREE);
	gsi_insert_after(&gsi, cond_stmt, GSI_CONTINUE_LINKING);
	update_stmt(cond_stmt);
}

static tree create_string_param(tree string)
{
	tree array_ref = build4(ARRAY_REF, TREE_TYPE(string), string, integer_zero_node, NULL, NULL);

	return build1(ADDR_EXPR, ptr_type_node, array_ref);
}

static void insert_cond_result(basic_block bb_true, gimple stmt, tree arg)
{
	gimple func_stmt, def_stmt;
	tree current_func, loc_file, loc_line;
	expanded_location xloc;
	gimple_stmt_iterator gsi = gsi_start_bb(bb_true);

	def_stmt = get_def_stmt(arg);
	xloc = expand_location(gimple_location(def_stmt));

	if (!gimple_has_location(def_stmt)) {
		xloc = expand_location(gimple_location(stmt));
		gcc_assert(gimple_has_location(stmt));
	}

	loc_line = build_int_cstu(unsigned_type_node, xloc.line);

	loc_file = build_string(strlen(xloc.file), xloc.file);
	TREE_TYPE(loc_file) = char_array_type_node;
	loc_file = create_string_param(loc_file);

	current_func = build_string(IDENTIFIER_LENGTH(DECL_NAME(current_function_decl)), NAME(current_function_decl));
	TREE_TYPE(current_func) = char_array_type_node;
	current_func = create_string_param(current_func);

	// void report_size_overflow(const char *file, unsigned int line, const char *func)
	func_stmt = gimple_build_call(report_size_overflow_decl, 3, loc_file, loc_line, current_func);

	gsi_insert_after(&gsi, func_stmt, GSI_CONTINUE_LINKING);
}

static void insert_check_size_overflow(gimple stmt, tree arg)
{
	basic_block cond_bb, join_bb, bb_true;
	edge e;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);

	cond_bb = gimple_bb(stmt);
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

	if (dom_info_available_p(CDI_DOMINATORS)) {
		set_immediate_dominator(CDI_DOMINATORS, bb_true, cond_bb);
		set_immediate_dominator(CDI_DOMINATORS, join_bb, cond_bb);
	}

	insert_cond(arg, cond_bb);
	insert_cond_result(bb_true, stmt, arg);
}

static void handle_function_arg(gimple stmt, tree fndecl, unsigned int argnum)
{
	struct pointer_set_t *visited;
	tree arg, newarg;
	gimple ucast_stmt;
	gimple_stmt_iterator gsi;
	location_t loc = gimple_location(stmt);

	arg = get_function_arg(argnum, stmt, fndecl);
	if (arg == NULL_TREE)
		return;

	if (is_gimple_constant(arg))
		return;
	if (TREE_CODE(arg) != SSA_NAME)
		return;

	set_size_overflow_type(arg);
	visited = pointer_set_create();
	newarg = expand(visited, arg);
	pointer_set_destroy(visited);

	if (newarg == NULL_TREE)
		return;

	change_function_arg(stmt, arg, argnum, newarg);

	ucast_stmt = build_cast_stmt(unsigned_size_overflow_type, newarg, CREATE_NEW_VAR, loc);
	gsi = gsi_for_stmt(stmt);
	gsi_insert_before(&gsi, ucast_stmt, GSI_SAME_STMT);

	insert_check_size_overflow(stmt, gimple_get_lhs(ucast_stmt));
//	inform(loc, "Integer size_overflow check applied here.");
}

static void handle_function_by_attribute(gimple stmt, tree attr, tree fndecl)
{
	tree p = TREE_VALUE(attr);
	do {
		handle_function_arg(stmt, fndecl, TREE_INT_CST_LOW(TREE_VALUE(p))-1);
		p = TREE_CHAIN(p);
	} while (p);
}

static void handle_function_by_hash(gimple stmt, tree fndecl)
{
	struct size_overflow_hash *hash;
	expanded_location xloc;

	hash = get_function_hash(fndecl);
	xloc = expand_location(DECL_SOURCE_LOCATION(fndecl));

	fndecl = get_original_function_decl(fndecl);
	if (!hash->name || !hash->file)
		return;
	if (strcmp(hash->name, NAME(fndecl)) || strcmp(hash->file, xloc.file))
		return;

#define search_param(argnum)							\
	if (hash->param##argnum)						\
		handle_function_arg(stmt, fndecl, argnum - 1);

	search_param(1);
	search_param(2);
	search_param(3);
	search_param(4);
	search_param(5);
	search_param(6);
	search_param(7);
	search_param(8);
	search_param(9);
#undef search_param
}

static unsigned int handle_function(void)
{
	basic_block bb = ENTRY_BLOCK_PTR->next_bb;
	int saved_last_basic_block = last_basic_block;

	do {
		gimple_stmt_iterator gsi;
		basic_block next = bb->next_bb;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			tree fndecl, attr;
			gimple stmt = gsi_stmt(gsi);

			if (!(is_gimple_call(stmt)))
				continue;
			fndecl = gimple_call_fndecl(stmt);
			if (fndecl == NULL_TREE)
				continue;
			if (gimple_call_num_args(stmt) == 0)
				continue;
			attr = lookup_attribute("size_overflow", TYPE_ATTRIBUTES(TREE_TYPE(fndecl)));
			if (!attr || !TREE_VALUE(attr))
				handle_function_by_hash(stmt, fndecl);
			else
				handle_function_by_attribute(stmt, attr, fndecl);
			gsi = gsi_for_stmt(stmt);
		}
		bb = next;
	} while (bb && bb->index <= saved_last_basic_block);
	return 0;
}

static struct gimple_opt_pass size_overflow_pass = {
	.pass = {
		.type			= GIMPLE_PASS,
		.name			= "size_overflow",
		.gate			= NULL,
		.execute		= handle_function,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
		.tv_id			= TV_NONE,
		.properties_required	= PROP_cfg | PROP_referenced_vars,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_remove_unused_locals | TODO_update_ssa_no_phi | TODO_cleanup_cfg | TODO_ggc_collect | TODO_verify_flow
	}
};

static void start_unit_callback(void __unused *gcc_data, void __unused *user_data)
{
	tree fntype;

	const_char_ptr_type_node = build_pointer_type(build_type_variant(char_type_node, 1, 0));

	// void report_size_overflow(const char *loc_file, unsigned int loc_line, const char *current_func)
	fntype = build_function_type_list(void_type_node,
					  const_char_ptr_type_node,
					  unsigned_type_node,
					  const_char_ptr_type_node,
					  NULL_TREE);
	report_size_overflow_decl = build_fn_decl("report_size_overflow", fntype);

	TREE_PUBLIC(report_size_overflow_decl) = 1;
	DECL_EXTERNAL(report_size_overflow_decl) = 1;
	DECL_ARTIFICIAL(report_size_overflow_decl) = 1;
}

extern struct gimple_opt_pass pass_dce;

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	int i;
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	bool enable = true;

	struct register_pass_info size_overflow_pass_info = {
		.pass				= &size_overflow_pass.pass,
		.reference_pass_name		= "mudflap2",
		.ref_pass_instance_number	= 1,
		.pos_op				= PASS_POS_INSERT_BEFORE
	};

	struct register_pass_info dce_pass_info = {
		.pass				= &pass_dce.pass,
		.reference_pass_name		= "mudflap2",
		.ref_pass_instance_number	= 1,
		.pos_op				= PASS_POS_INSERT_BEFORE
	};

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	for (i = 0; i < argc; ++i) {
		if (!(strcmp(argv[i].key, "no-size_overflow"))) {
			enable = false;
			continue;
		}
		error(G_("unkown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &size_overflow_plugin_info);
	if (enable) {
		register_callback ("start_unit", PLUGIN_START_UNIT, &start_unit_callback, NULL);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &size_overflow_pass_info);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &dce_pass_info);
	}
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	return 0;
}

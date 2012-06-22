/*
 * Copyright 2011, 2012 by Emese Revfy <re.emese@gmail.com>
 * Licensed under the GPL v2, or (at your option) v3
 *
 * Homepage:
 * http://www.grsecurity.net/~ephox/overflow_plugin/
 *
 * This plugin recomputes expressions of function arguments marked by a size_overflow attribute
 * with double integer precision (DImode/TImode for 32/64 bit integer types).
 * The recomputed argument is checked against TYPE_MAX and an event is logged on overflow and the triggering process is killed.
 *
 * Usage:
 * $ gcc -I`gcc -print-file-name=plugin`/include/c-family -I`gcc -print-file-name=plugin`/include -fPIC -shared -O2 -ggdb -Wall -W -Wno-missing-field-initializers -o size_overflow_plugin.so size_overflow_plugin.c
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
#include "cfgloop.h"

struct size_overflow_hash {
		struct size_overflow_hash *next;
		const char *name;
		unsigned int param;
};

#include "size_overflow_hash.h"

#define __unused __attribute__((__unused__))
#define NAME(node) IDENTIFIER_POINTER(DECL_NAME(node))
#define NAME_LEN(node) IDENTIFIER_LENGTH(DECL_NAME(node))
#define BEFORE_STMT true
#define AFTER_STMT false
#define CREATE_NEW_VAR NULL_TREE
#define CODES_LIMIT 32
#define MAX_PARAM 10

#if BUILDING_GCC_VERSION == 4005
#define DECL_CHAIN(NODE) (TREE_CHAIN(DECL_MINIMAL_CHECK(NODE)))
#endif

int plugin_is_GPL_compatible;
void debug_gimple_stmt(gimple gs);

static tree expand(struct pointer_set_t *visited, bool *potentionally_overflowed, tree var);
static tree signed_size_overflow_type;
static tree unsigned_size_overflow_type;
static tree report_size_overflow_decl;
static tree const_char_ptr_type_node;
static unsigned int handle_function(void);

static struct plugin_info size_overflow_plugin_info = {
	.version	= "20120618beta",
	.help		= "no-size-overflow\tturn off size overflow checking\n",
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
	.handler			= handle_size_overflow_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity		= false
#endif
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

static inline gimple get_def_stmt(tree node)
{
	gcc_assert(TREE_CODE(node) == SSA_NAME);
	return SSA_NAME_DEF_STMT(node);
}

static unsigned char get_tree_code(tree type)
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
	default:
		debug_tree(type);
		gcc_unreachable();
	}
}

static size_t add_type_codes(tree type, unsigned char *tree_codes, size_t len)
{
	gcc_assert(type != NULL_TREE);

	while (type && len < CODES_LIMIT) {
		tree_codes[len] = get_tree_code(type);
		len++;
		type = TREE_TYPE(type);
	}
	return len;
}

static unsigned int get_function_decl(tree fndecl, unsigned char *tree_codes)
{
	tree arg, result, type = TREE_TYPE(fndecl);
	enum tree_code code = TREE_CODE(type);
	size_t len = 0;

	gcc_assert(code == FUNCTION_TYPE);

	arg = TYPE_ARG_TYPES(type);
	// skip builtins __builtin_constant_p
	if (!arg && DECL_BUILT_IN(fndecl))
		return 0;
	gcc_assert(arg != NULL_TREE);

	if (TREE_CODE_CLASS(code) == tcc_type)
		result = type;
	else
		result = DECL_RESULT(fndecl);

	gcc_assert(result != NULL_TREE);
	len = add_type_codes(TREE_TYPE(result), tree_codes, len);

	while (arg && len < CODES_LIMIT) {
		len = add_type_codes(TREE_VALUE(arg), tree_codes, len);
		arg = TREE_CHAIN(arg);
	}

	gcc_assert(len != 0);
	return len;
}

static struct size_overflow_hash *get_function_hash(tree fndecl)
{
	unsigned int hash;
	struct size_overflow_hash *entry;
	unsigned char tree_codes[CODES_LIMIT];
	size_t len;
	const char *func_name = NAME(fndecl);

	len = get_function_decl(fndecl, tree_codes);
	if (len == 0)
		return NULL;

	hash = get_hash_num(func_name, (const char*) tree_codes, len, 0);

	entry = size_overflow_hash[hash];
	while (entry) {
		if (!strcmp(entry->name, func_name))
			return entry;
		entry = entry->next;
	}

	return NULL;
}

static void check_arg_type(tree var)
{
	tree type = TREE_TYPE(var);
	enum tree_code code = TREE_CODE(type);

	gcc_assert(code == INTEGER_TYPE || code == ENUMERAL_TYPE ||
		  (code == POINTER_TYPE && TREE_CODE(TREE_TYPE(type)) == VOID_TYPE) ||
		  (code == POINTER_TYPE && TREE_CODE(TREE_TYPE(type)) == INTEGER_TYPE));
}

static int find_arg_number(tree arg, tree func)
{
	tree var;
	bool match = false;
	unsigned int argnum = 1;

	if (TREE_CODE(arg) == SSA_NAME)
		arg = SSA_NAME_VAR(arg);

	for (var = DECL_ARGUMENTS(func); var; var = TREE_CHAIN(var)) {
		if (strcmp(NAME(arg), NAME(var))) {
			argnum++;
			continue;
		}
		check_arg_type(var);

		match = true;
		break;
	}
	if (!match) {
		warning(0, "find_arg_number: cannot find the %s argument in %s", NAME(arg), NAME(func));
		return 0;
	}
	return argnum;
}

static void print_missing_msg(tree func, unsigned int argnum)
{
	unsigned int new_hash;
	size_t len;
	unsigned char tree_codes[CODES_LIMIT];
	location_t loc = DECL_SOURCE_LOCATION(func);
	const char *curfunc = NAME(func);

	len = get_function_decl(func, tree_codes);
	new_hash = get_hash_num(curfunc, (const char *) tree_codes, len, 0);
	inform(loc, "Function %s is missing from the size_overflow hash table +%s+%d+%u+", curfunc, curfunc, argnum, new_hash);
}

static void check_missing_attribute(tree arg)
{
	tree type, func = get_original_function_decl(current_function_decl);
	unsigned int argnum;
	struct size_overflow_hash *hash;

	gcc_assert(TREE_CODE(arg) != COMPONENT_REF);

	type = TREE_TYPE(arg);
	// skip function pointers
	if (TREE_CODE(type) == POINTER_TYPE && TREE_CODE(TREE_TYPE(type)) == FUNCTION_TYPE)
		return;

	if (lookup_attribute("size_overflow", TYPE_ATTRIBUTES(TREE_TYPE(func))))
		return;

	argnum = find_arg_number(arg, func);
	if (argnum == 0)
		return;

	hash = get_function_hash(func);
	if (!hash || !(hash->param & (1U << argnum)))
		print_missing_msg(func, argnum);
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

static tree cast_a_tree(tree type, tree var)
{
	gcc_assert(type != NULL_TREE && var != NULL_TREE);
	gcc_assert(fold_convertible_p(type, var));

	return fold_convert(type, var);
}

static tree signed_cast(tree var)
{
	return cast_a_tree(signed_size_overflow_type, var);
}

static gimple build_cast_stmt(tree type, tree var, tree new_var, location_t loc)
{
	gimple assign;

	if (new_var == CREATE_NEW_VAR)
		new_var = create_new_var(type);

	assign = gimple_build_assign(new_var, cast_a_tree(type, var));
	gimple_set_location(assign, loc);
	gimple_set_lhs(assign, make_ssa_name(new_var, assign));

	return assign;
}

static tree create_assign(struct pointer_set_t *visited, bool *potentionally_overflowed, gimple oldstmt, tree rhs1, bool before)
{
	tree oldstmt_rhs1;
	enum tree_code code;
	gimple stmt;
	gimple_stmt_iterator gsi;

	if (!*potentionally_overflowed)
		return NULL_TREE;

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
	if (lookup_stmt_eh_lp(oldstmt) != 0) {
		basic_block next_bb, cur_bb;
		edge e;

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
	}
	if (before)
		gsi_insert_before(&gsi, stmt, GSI_NEW_STMT);
	else
		gsi_insert_after(&gsi, stmt, GSI_NEW_STMT);
	update_stmt(stmt);
	pointer_set_insert(visited, oldstmt);
	return gimple_get_lhs(stmt);
}

static tree dup_assign(struct pointer_set_t *visited, bool *potentionally_overflowed, gimple oldstmt, tree rhs1, tree rhs2, tree __unused rhs3)
{
	tree new_var, lhs = gimple_get_lhs(oldstmt);
	gimple stmt;
	gimple_stmt_iterator gsi;

	if (!*potentionally_overflowed)
		return NULL_TREE;

	if (gimple_num_ops(oldstmt) != 4 && rhs1 == NULL_TREE) {
		rhs1 = gimple_assign_rhs1(oldstmt);
		rhs1 = create_assign(visited, potentionally_overflowed, oldstmt, rhs1, BEFORE_STMT);
	}
	if (gimple_num_ops(oldstmt) == 3 && rhs2 == NULL_TREE) {
		rhs2 = gimple_assign_rhs2(oldstmt);
		rhs2 = create_assign(visited, potentionally_overflowed, oldstmt, rhs2, BEFORE_STMT);
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
			rhs1 = signed_cast(rhs1);
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

	phi = create_phi_node(var, bb);
	gsi = gsi_last(phi_nodes(bb));
	gsi_remove(&gsi, false);

	gsi = gsi_for_stmt(oldstmt);
	gsi_insert_after(&gsi, phi, GSI_NEW_STMT);
	gimple_set_bb(phi, bb);
	return phi;
}

static basic_block create_a_first_bb(void)
{
	basic_block first_bb;

	first_bb = split_block_after_labels(ENTRY_BLOCK_PTR)->dest;
	if (dom_info_available_p(CDI_DOMINATORS))
		set_immediate_dominator(CDI_DOMINATORS, first_bb, ENTRY_BLOCK_PTR);
	return first_bb;
}

static gimple cast_old_phi_arg(gimple oldstmt, tree arg, tree new_var, unsigned int i)
{
	basic_block bb;
	gimple newstmt, def_stmt;
	gimple_stmt_iterator gsi;

	newstmt = build_cast_stmt(signed_size_overflow_type, arg, new_var, gimple_location(oldstmt));
	if (TREE_CODE(arg) == SSA_NAME) {
		def_stmt = get_def_stmt(arg);
		if (gimple_code(def_stmt) != GIMPLE_NOP) {
			gsi = gsi_for_stmt(def_stmt);
			gsi_insert_after(&gsi, newstmt, GSI_NEW_STMT);
			return newstmt;
		}
	}

	bb = gimple_phi_arg_edge(oldstmt, i)->src;
	if (bb->index == 0)
		bb = create_a_first_bb();
	gsi = gsi_after_labels(bb);
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
		newstmt = gimple_build_assign(new_var, gimple_get_lhs(def_newstmt));
		break;
	default:
		/* unknown gimple_code (handle_build_new_phi_arg) */
		gcc_unreachable();
	}

	gimple_set_lhs(newstmt, make_ssa_name(new_var, newstmt));
	gsi_insert(&gsi, newstmt, GSI_NEW_STMT);
	update_stmt(newstmt);
	return newstmt;
}

static tree build_new_phi_arg(struct pointer_set_t *visited, bool *potentionally_overflowed, tree arg, tree new_var)
{
	gimple newstmt;
	tree new_rhs;

	new_rhs = expand(visited, potentionally_overflowed, arg);

	if (new_rhs == NULL_TREE)
		return NULL_TREE;

	newstmt = handle_new_phi_arg(arg, new_var, new_rhs);
	return gimple_get_lhs(newstmt);
}

static tree build_new_phi(struct pointer_set_t *visited, bool *potentionally_overflowed, gimple oldstmt)
{
	gimple phi;
	tree new_var = create_new_var(signed_size_overflow_type);
	unsigned int i, n = gimple_phi_num_args(oldstmt);

	pointer_set_insert(visited, oldstmt);
	phi = overflow_create_phi_node(oldstmt, new_var);
	for (i = 0; i < n; i++) {
		tree arg, lhs;

		arg = gimple_phi_arg_def(oldstmt, i);
		if (is_gimple_constant(arg))
			arg = signed_cast(arg);
		lhs = build_new_phi_arg(visited, potentionally_overflowed, arg, new_var);
		if (lhs == NULL_TREE)
			lhs = gimple_get_lhs(cast_old_phi_arg(oldstmt, arg, new_var, i));
		add_phi_arg(phi, lhs, gimple_phi_arg_edge(oldstmt, i), gimple_location(oldstmt));
	}

	update_stmt(phi);
	return gimple_phi_result(phi);
}

static tree handle_unary_rhs(struct pointer_set_t *visited, bool *potentionally_overflowed, tree var)
{
	gimple def_stmt = get_def_stmt(var);
	tree new_rhs1, rhs1 = gimple_assign_rhs1(def_stmt);

	*potentionally_overflowed = true;
	new_rhs1 = expand(visited, potentionally_overflowed, rhs1);
	if (new_rhs1 == NULL_TREE) {
		if (TREE_CODE(TREE_TYPE(rhs1)) == POINTER_TYPE)
			return create_assign(visited, potentionally_overflowed, def_stmt, var, AFTER_STMT);
		else
			return create_assign(visited, potentionally_overflowed, def_stmt, rhs1, AFTER_STMT);
	}
	return dup_assign(visited, potentionally_overflowed, def_stmt, new_rhs1, NULL_TREE, NULL_TREE);
}

static tree handle_unary_ops(struct pointer_set_t *visited, bool *potentionally_overflowed, tree var)
{
	gimple def_stmt = get_def_stmt(var);
	tree rhs1 = gimple_assign_rhs1(def_stmt);

	if (is_gimple_constant(rhs1))
		return dup_assign(visited, potentionally_overflowed, def_stmt, signed_cast(rhs1), NULL_TREE, NULL_TREE);

	gcc_assert(TREE_CODE(rhs1) != COND_EXPR);
	switch (TREE_CODE(rhs1)) {
	case SSA_NAME:
		return handle_unary_rhs(visited, potentionally_overflowed, var);

	case ARRAY_REF:
	case BIT_FIELD_REF:
	case ADDR_EXPR:
	case COMPONENT_REF:
	case INDIRECT_REF:
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case PARM_DECL:
	case TARGET_MEM_REF:
	case VAR_DECL:
		return create_assign(visited, potentionally_overflowed, def_stmt, var, AFTER_STMT);

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
	int length = TREE_STRING_LENGTH(string);

	gcc_assert(length > 0);

	i_type = build_index_type(build_int_cst(NULL_TREE, length - 1));
	a_type = build_array_type(char_type_node, i_type);

	TREE_TYPE(string) = a_type;
	TREE_CONSTANT(string) = 1;
	TREE_READONLY(string) = 1;

	return build1(ADDR_EXPR, ptr_type_node, string);
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
		if (!gimple_has_location(stmt))
			xloc = expand_location(DECL_SOURCE_LOCATION(current_function_decl));
	}

	loc_line = build_int_cstu(unsigned_type_node, xloc.line);

	loc_file = build_string(strlen(xloc.file) + 1, xloc.file);
	loc_file = create_string_param(loc_file);

	current_func = build_string(NAME_LEN(current_function_decl) + 1, NAME(current_function_decl));
	current_func = create_string_param(current_func);

	// void report_size_overflow(const char *file, unsigned int line, const char *func)
	func_stmt = gimple_build_call(report_size_overflow_decl, 3, loc_file, loc_line, current_func);

	gsi_insert_after(&gsi, func_stmt, GSI_CONTINUE_LINKING);
}

static void __unused print_the_code_insertions(gimple stmt)
{
	location_t loc = gimple_location(stmt);

	inform(loc, "Integer size_overflow check applied here.");
}

static void insert_check_size_overflow(gimple stmt, enum tree_code cond_code, tree arg, tree type_value)
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
	make_edge(cond_bb, join_bb, EDGE_FALSE_VALUE);
	make_edge(bb_true, join_bb, EDGE_FALLTHRU);

	if (dom_info_available_p(CDI_DOMINATORS)) {
		set_immediate_dominator(CDI_DOMINATORS, bb_true, cond_bb);
		set_immediate_dominator(CDI_DOMINATORS, join_bb, cond_bb);
	}

	if (current_loops != NULL) {
		gcc_assert(cond_bb->loop_father == join_bb->loop_father);
		add_bb_to_loop(bb_true, cond_bb->loop_father);
	}

	insert_cond(cond_bb, arg, cond_code, type_value);
	insert_cond_result(bb_true, stmt, arg);

//	print_the_code_insertions(stmt);
}

static gimple cast_to_unsigned_size_overflow_type(gimple stmt, tree cast_rhs)
{
	gimple ucast_stmt;
	gimple_stmt_iterator gsi;
	location_t loc = gimple_location(stmt);

	ucast_stmt = build_cast_stmt(unsigned_size_overflow_type, cast_rhs, CREATE_NEW_VAR, loc);
	gsi = gsi_for_stmt(stmt);
	gsi_insert_before(&gsi, ucast_stmt, GSI_SAME_STMT);
	return ucast_stmt;
}

static void check_size_overflow(gimple stmt, tree cast_rhs, tree rhs, bool *potentionally_overflowed)
{
	tree type_max, type_min, rhs_type = TREE_TYPE(rhs);
	gimple ucast_stmt;

	if (!*potentionally_overflowed)
		return;

	if (TYPE_UNSIGNED(rhs_type)) {
		ucast_stmt = cast_to_unsigned_size_overflow_type(stmt, cast_rhs);
		type_max = cast_a_tree(unsigned_size_overflow_type, TYPE_MAX_VALUE(rhs_type));
		insert_check_size_overflow(stmt, GT_EXPR, gimple_get_lhs(ucast_stmt), type_max);
	} else {
		type_max = signed_cast(TYPE_MAX_VALUE(rhs_type));
		insert_check_size_overflow(stmt, GT_EXPR, cast_rhs, type_max);

		type_min = signed_cast(TYPE_MIN_VALUE(rhs_type));
		insert_check_size_overflow(stmt, LT_EXPR, cast_rhs, type_min);
	}
}

static tree change_assign_rhs(gimple stmt, tree orig_rhs, tree new_rhs)
{
	gimple assign;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);
	tree origtype = TREE_TYPE(orig_rhs);

	gcc_assert(gimple_code(stmt) == GIMPLE_ASSIGN);

	assign = build_cast_stmt(origtype, new_rhs, CREATE_NEW_VAR, gimple_location(stmt));
	gsi_insert_before(&gsi, assign, GSI_SAME_STMT);
	update_stmt(assign);
	return gimple_get_lhs(assign);
}

static tree handle_const_assign(struct pointer_set_t *visited, bool *potentionally_overflowed, gimple def_stmt, tree var, tree orig_rhs, tree var_rhs, tree new_rhs1, tree new_rhs2, void (*gimple_assign_set_rhs)(gimple, tree))
{
	tree new_rhs;

	if (gimple_assign_rhs_code(def_stmt) == MIN_EXPR)
		return dup_assign(visited, potentionally_overflowed, def_stmt, new_rhs1, new_rhs2, NULL_TREE);

	if (var_rhs == NULL_TREE)
		return create_assign(visited, potentionally_overflowed, def_stmt, var, AFTER_STMT);

	new_rhs = change_assign_rhs(def_stmt, orig_rhs, var_rhs);
	gimple_assign_set_rhs(def_stmt, new_rhs);
	update_stmt(def_stmt);

	check_size_overflow(def_stmt, var_rhs, orig_rhs, potentionally_overflowed);
	return create_assign(visited, potentionally_overflowed, def_stmt, var, AFTER_STMT);
}

static tree handle_binary_ops(struct pointer_set_t *visited, bool *potentionally_overflowed, tree var)
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
	case BIT_AND_EXPR:
		return create_assign(visited, potentionally_overflowed, def_stmt, var, AFTER_STMT);
	default:
		break;
	}

	*potentionally_overflowed = true;

	if (TREE_CODE(rhs1) == SSA_NAME)
		new_rhs1 = expand(visited, potentionally_overflowed, rhs1);
	if (TREE_CODE(rhs2) == SSA_NAME)
		new_rhs2 = expand(visited, potentionally_overflowed, rhs2);

	if (is_gimple_constant(rhs2))
		return handle_const_assign(visited, potentionally_overflowed, def_stmt, var, rhs1, new_rhs1, new_rhs1, signed_cast(rhs2), &gimple_assign_set_rhs1);

	if (is_gimple_constant(rhs1))
		return handle_const_assign(visited, potentionally_overflowed, def_stmt, var, rhs2, new_rhs2, signed_cast(rhs1), new_rhs2, &gimple_assign_set_rhs2);

	return dup_assign(visited, potentionally_overflowed, def_stmt, new_rhs1, new_rhs2, NULL_TREE);
}

#if BUILDING_GCC_VERSION >= 4007
static tree get_new_rhs(struct pointer_set_t *visited, bool *potentionally_overflowed, tree rhs)
{
	if (is_gimple_constant(rhs))
		return signed_cast(rhs);
	if (TREE_CODE(rhs) != SSA_NAME)
		return NULL_TREE;
	return expand(visited, potentionally_overflowed, rhs);
}

static tree handle_ternary_ops(struct pointer_set_t *visited, bool *potentionally_overflowed, tree var)
{
	tree rhs1, rhs2, rhs3, new_rhs1, new_rhs2, new_rhs3;
	gimple def_stmt = get_def_stmt(var);

	*potentionally_overflowed = true;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);
	rhs3 = gimple_assign_rhs3(def_stmt);
	new_rhs1 = get_new_rhs(visited, potentionally_overflowed, rhs1);
	new_rhs2 = get_new_rhs(visited, potentionally_overflowed, rhs2);
	new_rhs3 = get_new_rhs(visited, potentionally_overflowed, rhs3);

	if (new_rhs1 == NULL_TREE && new_rhs2 != NULL_TREE && new_rhs3 != NULL_TREE)
		return dup_assign(visited, potentionally_overflowed, def_stmt, new_rhs1, new_rhs2, new_rhs3);
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

static tree expand(struct pointer_set_t *visited, bool *potentionally_overflowed, tree var)
{
	gimple def_stmt;
	enum tree_code code = TREE_CODE(TREE_TYPE(var));

	if (is_gimple_constant(var))
		return NULL_TREE;

	if (TREE_CODE(var) == ADDR_EXPR)
		return NULL_TREE;

	gcc_assert(code == INTEGER_TYPE || code == POINTER_TYPE || code == BOOLEAN_TYPE || code == ENUMERAL_TYPE);
	if (code != INTEGER_TYPE)
		return NULL_TREE;

	if (SSA_NAME_IS_DEFAULT_DEF(var)) {
		check_missing_attribute(var);
		return NULL_TREE;
	}

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
		return build_new_phi(visited, potentionally_overflowed, def_stmt);
	case GIMPLE_CALL:
	case GIMPLE_ASM:
		return create_assign(visited, potentionally_overflowed, def_stmt, var, AFTER_STMT);
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			return handle_unary_ops(visited, potentionally_overflowed, var);
		case 3:
			return handle_binary_ops(visited, potentionally_overflowed, var);
#if BUILDING_GCC_VERSION >= 4007
		case 4:
			return handle_ternary_ops(visited, potentionally_overflowed, var);
#endif
		}
	default:
		debug_gimple_stmt(def_stmt);
		error("expand: unknown gimple code");
		gcc_unreachable();
	}
}

static void change_function_arg(gimple stmt, tree origarg, unsigned int argnum, tree newarg)
{
	gimple assign;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);
	tree origtype = TREE_TYPE(origarg);

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

static void handle_function_arg(gimple stmt, tree fndecl, unsigned int argnum)
{
	struct pointer_set_t *visited;
	tree arg, newarg;
	bool potentionally_overflowed;

	arg = get_function_arg(argnum, stmt, fndecl);
	if (arg == NULL_TREE)
		return;

	if (is_gimple_constant(arg))
		return;
	if (TREE_CODE(arg) != SSA_NAME)
		return;

	check_arg_type(arg);

	set_size_overflow_type(arg);

	visited = pointer_set_create();
	potentionally_overflowed = false;
	newarg = expand(visited, &potentionally_overflowed, arg);
	pointer_set_destroy(visited);

	if (newarg == NULL_TREE || !potentionally_overflowed)
		return;

	change_function_arg(stmt, arg, argnum, newarg);

	check_size_overflow(stmt, newarg, arg, &potentionally_overflowed);
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
	tree orig_fndecl;
	unsigned int num;
	struct size_overflow_hash *hash;

	orig_fndecl = get_original_function_decl(fndecl);
	hash = get_function_hash(orig_fndecl);
	if (!hash)
		return;

	for (num = 1; num <= MAX_PARAM; num++)
		if (hash->param & (1U << num))
			handle_function_arg(stmt, fndecl, num - 1);
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

	DECL_ASSEMBLER_NAME(report_size_overflow_decl);
	TREE_PUBLIC(report_size_overflow_decl) = 1;
	DECL_EXTERNAL(report_size_overflow_decl) = 1;
	DECL_ARTIFICIAL(report_size_overflow_decl) = 1;
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
		register_callback ("start_unit", PLUGIN_START_UNIT, &start_unit_callback, NULL);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &size_overflow_pass_info);
	}
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	return 0;
}

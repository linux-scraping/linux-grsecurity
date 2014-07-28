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
 * $ make
 * $ make run
 */

#include "gcc-common.h"
#include "size_overflow.h"

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
bool is_turn_off_intentional_attr(const_tree decl)
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
bool is_end_intentional_intentional_attr(const_tree decl, unsigned int argnum)
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
bool is_yes_intentional_attr(const_tree decl, unsigned int argnum)
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

void print_missing_intentional(enum mark callee_attr, enum mark caller_attr, const_tree decl, unsigned int argnum)
{
	location_t loc;

	if (caller_attr == MARK_NO || caller_attr == MARK_NOT_INTENTIONAL || caller_attr == MARK_TURN_OFF)
		return;

	if (callee_attr == MARK_NOT_INTENTIONAL || callee_attr == MARK_YES)
		return;

	loc = DECL_SOURCE_LOCATION(decl);
	inform(loc, "The intentional_overflow attribute is missing from +%s+%u+", DECL_NAME_POINTER(decl), argnum);
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

/* Get the type of the intentional_overflow attribute of a node
 *  * MARK_TURN_OFF
 *  * MARK_YES
 *  * MARK_NO
 *  * MARK_NOT_INTENTIONAL
 */
enum mark get_intentional_attr_type(const_tree node)
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
void check_intentional_attribute_ipa(struct interesting_node *cur_node)
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

bool is_a_cast_and_const_overflow(const_tree no_const_rhs)
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

static unsigned int uses_num(tree node)
{
	imm_use_iterator imm_iter;
	use_operand_p use_p;
	unsigned int num = 0;

	FOR_EACH_IMM_USE_FAST(use_p, imm_iter, node) {
		gimple use_stmt = USE_STMT(use_p);

		if (use_stmt == NULL)
			return num;
		if (is_gimple_debug(use_stmt))
			continue;
		if (gimple_assign_cast_p(use_stmt) && is_size_overflow_type(gimple_assign_lhs(use_stmt)))
			continue;
		num++;
	}
	return num;
}

static bool no_uses(tree node)
{
	return !uses_num(node);
}

// 3.8.5 mm/page-writeback.c __ilog2_u64(): ret, uint + uintmax; uint -> int; int max
bool is_const_plus_unsigned_signed_truncation(const_tree lhs)
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

static bool is_lt_signed_type_max(const_tree rhs)
{
	const_tree new_type, type_max, type = TREE_TYPE(rhs);

	if (!TYPE_UNSIGNED(type))
		return true;

	switch (TYPE_MODE(type)) {
	case QImode:
		new_type = intQI_type_node;
		break;
	case HImode:
		new_type = intHI_type_node;
		break;
	case SImode:
		new_type = intSI_type_node;
		break;
	case DImode:
		new_type = intDI_type_node;
		break;
	default:
		debug_tree((tree)type);
		gcc_unreachable();
	}

	type_max = TYPE_MAX_VALUE(new_type);
	if (!tree_int_cst_lt(type_max, rhs))
		return true;

	return false;
}

static bool is_gt_zero(const_tree rhs)
{
	const_tree type = TREE_TYPE(rhs);

	if (TYPE_UNSIGNED(type))
		return true;

	if (!tree_int_cst_lt(rhs, integer_zero_node))
		return true;

	return false;
}

bool is_a_constant_overflow(const_gimple stmt, const_tree rhs)
{
	if (gimple_assign_rhs_code(stmt) == MIN_EXPR)
		return false;
	if (!is_gimple_constant(rhs))
		return false;

	// If the const is between 0 and the max value of the signed type of the same bitsize then there is no intentional overflow
	if (is_lt_signed_type_max(rhs) && is_gt_zero(rhs))
		return false;

	return true;
}

static tree change_assign_rhs(struct visited *visited, gimple stmt, const_tree orig_rhs, tree new_rhs)
{
	gimple assign;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);
	tree origtype = TREE_TYPE(orig_rhs);

	gcc_assert(is_gimple_assign(stmt));

	assign = build_cast_stmt(visited, origtype, new_rhs, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	pointer_set_insert(visited->my_stmts, assign);
	return gimple_assign_lhs(assign);
}

tree handle_intentional_overflow(struct visited *visited, struct cgraph_node *caller_node, bool check_overflow, gimple stmt, tree change_rhs, tree new_rhs2)
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

	new_rhs = change_assign_rhs(visited, stmt, orig_rhs, change_rhs);
	gimple_assign_set_rhs(stmt, new_rhs);
	update_stmt(stmt);

	return create_assign(visited, stmt, lhs, AFTER_STMT);
}

static bool is_subtraction_special(struct visited *visited, const_gimple stmt)
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

	pointer_set_insert(visited->no_cast_check, rhs1_def_stmt);
	pointer_set_insert(visited->no_cast_check, rhs2_def_stmt);
	return true;
}

static gimple create_binary_assign(struct visited *visited, enum tree_code code, gimple stmt, tree rhs1, tree rhs2)
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
	pointer_set_insert(visited->my_stmts, assign);
	return assign;
}

static tree cast_to_TI_type(struct visited *visited, gimple stmt, tree node)
{
	gimple_stmt_iterator gsi;
	gimple cast_stmt;
	tree type = TREE_TYPE(node);

	if (types_compatible_p(type, intTI_type_node))
		return node;

	gsi = gsi_for_stmt(stmt);
	cast_stmt = build_cast_stmt(visited, intTI_type_node, node, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	pointer_set_insert(visited->my_stmts, cast_stmt);
	return gimple_assign_lhs(cast_stmt);
}

static tree get_def_stmt_rhs(struct visited *visited, const_tree var)
{
	tree rhs1, def_stmt_rhs1;
	gimple rhs1_def_stmt, def_stmt_rhs1_def_stmt, def_stmt;

	def_stmt = get_def_stmt(var);
	if (!gimple_assign_cast_p(def_stmt))
		return NULL_TREE;
	gcc_assert(gimple_code(def_stmt) != GIMPLE_NOP && pointer_set_contains(visited->my_stmts, def_stmt) && gimple_assign_cast_p(def_stmt));

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

tree handle_integer_truncation(struct visited *visited, struct cgraph_node *caller_node, const_tree lhs)
{
	tree new_rhs1, new_rhs2;
	tree new_rhs1_def_stmt_rhs1, new_rhs2_def_stmt_rhs1, new_lhs;
	gimple assign, stmt = get_def_stmt(lhs);
	tree rhs1 = gimple_assign_rhs1(stmt);
	tree rhs2 = gimple_assign_rhs2(stmt);

	if (!is_subtraction_special(visited, stmt))
		return NULL_TREE;

	new_rhs1 = expand(visited, caller_node, rhs1);
	new_rhs2 = expand(visited, caller_node, rhs2);

	new_rhs1_def_stmt_rhs1 = get_def_stmt_rhs(visited, new_rhs1);
	new_rhs2_def_stmt_rhs1 = get_def_stmt_rhs(visited, new_rhs2);

	if (new_rhs1_def_stmt_rhs1 == NULL_TREE || new_rhs2_def_stmt_rhs1 == NULL_TREE)
		return NULL_TREE;

	if (!types_compatible_p(TREE_TYPE(new_rhs1_def_stmt_rhs1), TREE_TYPE(new_rhs2_def_stmt_rhs1))) {
		new_rhs1_def_stmt_rhs1 = cast_to_TI_type(visited, stmt, new_rhs1_def_stmt_rhs1);
		new_rhs2_def_stmt_rhs1 = cast_to_TI_type(visited, stmt, new_rhs2_def_stmt_rhs1);
	}

	assign = create_binary_assign(visited, MINUS_EXPR, stmt, new_rhs1_def_stmt_rhs1, new_rhs2_def_stmt_rhs1);
	new_lhs = gimple_assign_lhs(assign);
	check_size_overflow(caller_node, assign, TREE_TYPE(new_lhs), new_lhs, rhs1, AFTER_STMT);

	return dup_assign(visited, stmt, lhs, new_rhs1, new_rhs2, NULL_TREE);
}

bool is_a_neg_overflow(const_gimple stmt, const_tree rhs)
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

/* e.g., drivers/acpi/acpica/utids.c acpi_ut_execute_CID()
 * ((count - 1) * sizeof(struct acpi_pnp_dee_id_list) -> (count + fffffff) * 16
 * fffffff * 16 > signed max -> truncate
 */
static bool look_for_mult_and_add(const_gimple stmt)
{
	const_tree res;
	tree rhs1, rhs2, def_rhs1, def_rhs2, const_rhs, def_const_rhs;
	const_gimple def_stmt;

	if (!stmt || gimple_code(stmt) == GIMPLE_NOP)
		return false;
	if (!is_gimple_assign(stmt))
		return false;
	if (gimple_assign_rhs_code(stmt) != MULT_EXPR)
		return false;

	rhs1 = gimple_assign_rhs1(stmt);
	rhs2 = gimple_assign_rhs2(stmt);
	if (is_gimple_constant(rhs1)) {
		const_rhs = rhs1;
		def_stmt = get_def_stmt(rhs2);
	} else if (is_gimple_constant(rhs2)) {
		const_rhs = rhs2;
		def_stmt = get_def_stmt(rhs1);
	} else
		return false;

	if (!is_gimple_assign(def_stmt))
		return false;

	if (gimple_assign_rhs_code(def_stmt) != PLUS_EXPR && gimple_assign_rhs_code(def_stmt) != MINUS_EXPR)
		return false;

	def_rhs1 = gimple_assign_rhs1(def_stmt);
	def_rhs2 = gimple_assign_rhs2(def_stmt);
	if (is_gimple_constant(def_rhs1))
		def_const_rhs = def_rhs1;
	else if (is_gimple_constant(def_rhs2))
		def_const_rhs = def_rhs2;
	else
		return false;

	res = fold_binary_loc(gimple_location(def_stmt), MULT_EXPR, TREE_TYPE(const_rhs), const_rhs, def_const_rhs);
	if (is_lt_signed_type_max(res) && is_gt_zero(res))
		return false;
	return true;
}

enum intentional_overflow_type add_mul_intentional_overflow(const_gimple stmt)
{
	const_gimple def_stmt_1, def_stmt_2;
	const_tree rhs1, rhs2;
	bool add_mul_rhs1, add_mul_rhs2;

	rhs1 = gimple_assign_rhs1(stmt);
	def_stmt_1 = get_def_stmt(rhs1);
	add_mul_rhs1 = look_for_mult_and_add(def_stmt_1);

	rhs2 = gimple_assign_rhs2(stmt);
	def_stmt_2 = get_def_stmt(rhs2);
	add_mul_rhs2 = look_for_mult_and_add(def_stmt_2);

	if (add_mul_rhs1)
		return RHS1_INTENTIONAL_OVERFLOW;
	if (add_mul_rhs2)
		return RHS2_INTENTIONAL_OVERFLOW;
	return NO_INTENTIONAL_OVERFLOW;
}

static gimple get_dup_stmt(struct visited *visited, gimple stmt)
{
	gimple my_stmt;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);

	gsi_next(&gsi);
	my_stmt = gsi_stmt(gsi);

	gcc_assert(pointer_set_contains(visited->my_stmts, my_stmt));
	gcc_assert(gimple_assign_rhs_code(stmt) == gimple_assign_rhs_code(my_stmt));

	return my_stmt;
}

/* unsigned type -> unary or binary assign (rhs1 or rhs2 is constant)
 * unsigned type cast to signed type, unsigned type: no more uses
 * e.g., lib/vsprintf.c:simple_strtol()
 * _10 = (unsigned long int) _9
 * _11 = -_10;
 * _12 = (long int) _11; (_11_ no more uses)
 */
static bool is_call_or_cast(gimple stmt)
{
	return gimple_assign_cast_p(stmt) || is_gimple_call(stmt);
}

static bool is_unsigned_cast_or_call_def_stmt(const_tree node)
{
	const_tree rhs;
	gimple def_stmt;

	if (node == NULL_TREE)
		return true;
	if (is_gimple_constant(node))
		return true;

	def_stmt = get_def_stmt(node);
	if (!def_stmt)
		return false;

	if (is_call_or_cast(def_stmt))
		return true;

	if (!is_gimple_assign(def_stmt) || gimple_num_ops(def_stmt) != 2)
		return false;
	rhs = gimple_assign_rhs1(def_stmt);
	def_stmt = get_def_stmt(rhs);
	if (!def_stmt)
		return false;
	return is_call_or_cast(def_stmt);
}

void unsigned_signed_cast_intentional_overflow(struct visited *visited, gimple stmt)
{
	unsigned int use_num;
	gimple so_stmt;
	const_gimple def_stmt;
	const_tree rhs1, rhs2;
	tree rhs = gimple_assign_rhs1(stmt);
	tree lhs_type = TREE_TYPE(gimple_assign_lhs(stmt));
	const_tree rhs_type = TREE_TYPE(rhs);

	if (!(TYPE_UNSIGNED(rhs_type) && !TYPE_UNSIGNED(lhs_type)))
		return;
	if (GET_MODE_BITSIZE(TYPE_MODE(rhs_type)) != GET_MODE_BITSIZE(TYPE_MODE(lhs_type)))
		return;
	use_num = uses_num(rhs);
	if (use_num != 1)
		return;

	def_stmt = get_def_stmt(rhs);
	if (!def_stmt)
		return;
	if (!is_gimple_assign(def_stmt))
		return;

	rhs1 = gimple_assign_rhs1(def_stmt);
	if (!is_unsigned_cast_or_call_def_stmt(rhs1))
		return;

	rhs2 = gimple_assign_rhs2(def_stmt);
	if (!is_unsigned_cast_or_call_def_stmt(rhs2))
		return;
	if (gimple_num_ops(def_stmt) == 3 && !is_gimple_constant(rhs1) && !is_gimple_constant(rhs2))
		return;

	so_stmt = get_dup_stmt(visited, stmt);
	create_up_and_down_cast(visited, so_stmt, lhs_type, gimple_assign_rhs1(so_stmt));
}


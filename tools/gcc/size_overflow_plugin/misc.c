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

void set_current_function_decl(tree fndecl)
{
	gcc_assert(fndecl != NULL_TREE);

	push_cfun(DECL_STRUCT_FUNCTION(fndecl));
	calculate_dominance_info(CDI_DOMINATORS);
	current_function_decl = fndecl;
}

void unset_current_function_decl(void)
{
	free_dominance_info(CDI_DOMINATORS);
	pop_cfun();
	current_function_decl = NULL_TREE;
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

bool skip_types(const_tree var)
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

gimple get_def_stmt(const_tree node)
{
	gcc_assert(node != NULL_TREE);

	if (skip_types(node))
		return NULL;

	if (TREE_CODE(node) != SSA_NAME)
		return NULL;
	return SSA_NAME_DEF_STMT(node);
}

tree create_new_var(tree type)
{
	tree new_var = create_tmp_var(type, "cicus");

	add_referenced_var(new_var);
	return new_var;
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

tree cast_a_tree(tree type, tree var)
{
	gcc_assert(type != NULL_TREE);
	gcc_assert(var != NULL_TREE);
	gcc_assert(fold_convertible_p(type, var));

	return fold_convert(type, var);
}

gimple build_cast_stmt(struct visited *visited, tree dst_type, tree rhs, tree lhs, gimple_stmt_iterator *gsi, bool before, bool force)
{
	gimple assign, def_stmt;

	gcc_assert(dst_type != NULL_TREE && rhs != NULL_TREE);
	gcc_assert(!is_gimple_constant(rhs));
	if (gsi_end_p(*gsi) && before == AFTER_STMT)
		gcc_unreachable();

	def_stmt = get_def_stmt(rhs);
	if (def_stmt && gimple_code(def_stmt) != GIMPLE_NOP && skip_cast(dst_type, rhs, force) && pointer_set_contains(visited->my_stmts, def_stmt))
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

bool is_size_overflow_type(const_tree var)
{
	const char *name;
	const_tree type_name, type;

	if (var == NULL_TREE)
		return false;

	type = TREE_TYPE(var);
	type_name = TYPE_NAME(type);
	if (type_name == NULL_TREE)
		return false;

	if (DECL_P(type_name))
		name = DECL_NAME_POINTER(type_name);
	else
		name = IDENTIFIER_POINTER(type_name);

	if (!strncmp(name, "size_overflow_type", 18))
		return true;
	return false;
}


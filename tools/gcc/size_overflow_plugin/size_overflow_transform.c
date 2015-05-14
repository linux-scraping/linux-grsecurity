/*
 * Copyright 2011-2015 by Emese Revfy <re.emese@gmail.com>
 * Licensed under the GPL v2, or (at your option) v3
 *
 * Homepage:
 * https://github.com/ephox-gcc-plugins/size_overflow
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

#include "size_overflow.h"

static tree cast_to_orig_type(struct visited *visited, gimple stmt, const_tree orig_node, tree new_node)
{
	const_gimple assign;
	tree orig_type = TREE_TYPE(orig_node);
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);

	assign = build_cast_stmt(visited, orig_type, new_node, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	return get_lhs(assign);
}

static void change_size_overflow_asm_input(gasm *stmt, tree new_input)
{
	tree list;

	gcc_assert(is_size_overflow_insert_check_asm(stmt));

	list = build_tree_list(NULL_TREE, build_string(3, "rm"));
	list = chainon(NULL_TREE, build_tree_list(list, new_input));
	gimple_asm_set_input_op(stmt, 0, list);
}

static void change_orig_node(struct visited *visited, gimple stmt, const_tree orig_node, tree new_node, unsigned int num)
{
	tree cast_lhs = cast_to_orig_type(visited, stmt, orig_node, new_node);

	switch (gimple_code(stmt)) {
	case GIMPLE_RETURN:
		gimple_return_set_retval(as_a_greturn(stmt), cast_lhs);
		break;
	case GIMPLE_CALL:
		gimple_call_set_arg(stmt, num - 1, cast_lhs);
		break;
	case GIMPLE_ASM:
		change_size_overflow_asm_input(as_a_gasm(stmt), cast_lhs);
		break;
	default:
		debug_gimple_stmt(stmt);
		gcc_unreachable();
	}

	update_stmt(stmt);
}

// e.g., 3.8.2, 64, arch/x86/ia32/ia32_signal.c copy_siginfo_from_user32(): compat_ptr() u32 max
static bool skip_asm_cast(const_tree arg)
{
	gimple def_stmt = get_def_stmt(arg);

	if (!def_stmt || !gimple_assign_cast_p(def_stmt))
		return false;

	def_stmt = get_def_stmt(gimple_assign_rhs1(def_stmt));
	if (is_size_overflow_asm(def_stmt))
		return false;
	return def_stmt && gimple_code(def_stmt) == GIMPLE_ASM;
}

struct interesting_stmts {
	struct interesting_stmts *next;
	gimple first_stmt;
	tree orig_node;
	unsigned int num;
};

static struct interesting_stmts *create_interesting_stmts(struct interesting_stmts *head, tree orig_node, gimple first_stmt, unsigned int num)
{
	struct interesting_stmts *new_node;

	new_node = (struct interesting_stmts *)xmalloc(sizeof(*new_node));
	new_node->first_stmt = first_stmt;
	new_node->num = num;
	new_node->orig_node = orig_node;
	new_node->next = head;
	return new_node;
}

static void free_interesting_stmts(struct interesting_stmts *head)
{
	while (head) {
		struct interesting_stmts *cur = head->next;
		free(head);
		head = cur;
	}
}

/* This function calls the main recursion function (expand) that duplicates the stmts. Before that it checks the intentional_overflow attribute,
 * it decides whether the duplication is necessary or not. After expand() it changes the orig node to the duplicated node
 * in the original stmt (first stmt) and it inserts the overflow check for the arg of the callee or for the return value.
 */
static struct interesting_stmts *search_interesting_stmt(struct interesting_stmts *head, gimple first_stmt, tree orig_node, unsigned int num)
{
	enum tree_code orig_code;

	gcc_assert(orig_node != NULL_TREE);

	if (is_gimple_constant(orig_node))
		return head;

	orig_code = TREE_CODE(orig_node);
	gcc_assert(orig_code != FIELD_DECL && orig_code != FUNCTION_DECL);
	gcc_assert(!skip_types(orig_node));

	if (check_intentional_asm(first_stmt, num) != MARK_NO)
		return head;

	if (SSA_NAME_IS_DEFAULT_DEF(orig_node))
		return head;

	if (skip_asm_cast(orig_node))
		return head;

	return create_interesting_stmts(head, orig_node, first_stmt, num);
}

static void handle_interesting_stmt(struct visited *visited, struct interesting_stmts *head)
{
	struct interesting_stmts *cur;

	for (cur = head; cur; cur = cur->next) {
		tree new_node;

		new_node = expand(visited, cur->orig_node);
		if (new_node == NULL_TREE)
			continue;

		change_orig_node(visited, cur->first_stmt, cur->orig_node, new_node, cur->num);
		check_size_overflow(cur->first_stmt, TREE_TYPE(new_node), new_node, cur->orig_node, BEFORE_STMT);
	}
}

static bool is_interesting_function(const_tree decl, unsigned int num)
{
	const struct size_overflow_hash *so_hash;

	if (get_global_next_interesting_function_entry_with_hash(decl, DECL_NAME_POINTER(decl), num, YES_SO_MARK))
		return true;

	if (made_by_compiler(decl))
		return false;

	so_hash = get_size_overflow_hash_entry_tree(decl, num);
	return so_hash != NULL;
}

tree handle_fnptr_assign(const_gimple stmt)
{
	tree field, rhs, op0;
	const_tree op0_type;
	enum tree_code rhs_code;

	// TODO skip binary assignments for now (fs/sync.c _591 = __bpf_call_base + _590;)
	if (gimple_num_ops(stmt) != 2)
		return NULL_TREE;

	gcc_assert(gimple_num_ops(stmt) == 2);
	// TODO skip asm_stmt for now
	if (gimple_code(stmt) == GIMPLE_ASM)
		return NULL_TREE;
	rhs = gimple_assign_rhs1(stmt);
	if (is_gimple_constant(rhs))
		return NULL_TREE;

	rhs_code = TREE_CODE(rhs);
	if (rhs_code == VAR_DECL)
		return rhs;

	switch (rhs_code) {
	case ADDR_EXPR:
		op0 = TREE_OPERAND(rhs, 0);
		gcc_assert(TREE_CODE(op0) == FUNCTION_DECL);
		return op0;
	case COMPONENT_REF:
		break;
	// TODO skip array_ref for now
	case ARRAY_REF:
		return NULL_TREE;
	// TODO skip ssa_name because it can lead to parm_decl
	case SSA_NAME:
		return NULL_TREE;
	// TODO skip mem_ref and indirect_ref for now
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case INDIRECT_REF:
		return NULL_TREE;
	default:
		debug_tree(rhs);
		debug_gimple_stmt((gimple)stmt);
		gcc_unreachable();
	}

	op0 = TREE_OPERAND(rhs, 0);
	switch (TREE_CODE(op0)) {
	// TODO skip array_ref and parm_decl for now
	case ARRAY_REF:
	case PARM_DECL:
		return NULL_TREE;
	case COMPONENT_REF:
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case INDIRECT_REF:
	case VAR_DECL:
		break;
	default:
		debug_tree(op0);
		gcc_unreachable();
	}

	op0_type = TREE_TYPE(op0);
	// TODO skip unions for now
	if (TREE_CODE(op0_type) == UNION_TYPE)
		return NULL_TREE;
	gcc_assert(TREE_CODE(op0_type) == RECORD_TYPE);

	field = TREE_OPERAND(rhs, 1);
	gcc_assert(TREE_CODE(field) == FIELD_DECL);
	return field;
}

static tree get_fn_or_fnptr_decl(const gcall *call_stmt)
{
	const_tree fnptr;
	const_gimple def_stmt;
	tree decl = gimple_call_fndecl(call_stmt);

	if (decl != NULL_TREE)
		return decl;

	fnptr = gimple_call_fn(call_stmt);
	// !!! assertot kell irni 0-ra, mert csak az lehet ott
	if (is_gimple_constant(fnptr))
		return NULL_TREE;
	def_stmt = get_fnptr_def_stmt(fnptr);
	return handle_fnptr_assign(def_stmt);
}

// Start stmt duplication on marked function parameters
static struct interesting_stmts *search_interesting_calls(struct interesting_stmts *head, gcall *call_stmt)
{
	tree decl;
	unsigned int i, len;

	len = gimple_call_num_args(call_stmt);
	if (len == 0)
		return head;

	decl = get_fn_or_fnptr_decl(call_stmt);
	if (decl == NULL_TREE)
		return head;

	for (i = 0; i < len; i++) {
		tree arg;

		arg = gimple_call_arg(call_stmt, i);
		if (is_gimple_constant(arg))
			continue;
		if (skip_types(arg))
			continue;
		if (is_interesting_function(decl, i + 1))
			head = search_interesting_stmt(head, call_stmt, arg, i + 1);
	}

	return head;
}

// Collect interesting stmts for duplication
static void search_interesting_stmts(struct visited *visited)
{
	basic_block bb;
	bool search_ret;
	struct interesting_stmts *head = NULL;

	search_ret = is_interesting_function(current_function_decl, 0);

	FOR_ALL_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			tree first_node;
			gimple stmt = gsi_stmt(gsi);

			switch (gimple_code(stmt)) {
			case GIMPLE_ASM:
				if (!is_size_overflow_insert_check_asm(as_a_gasm(stmt)))
					continue;
				first_node = get_size_overflow_asm_input(as_a_gasm(stmt));
				head = search_interesting_stmt(head, stmt, first_node, 0);
				break;
			case GIMPLE_RETURN:
				if (!search_ret)
					continue;
				first_node = gimple_return_retval(as_a_greturn(stmt));
				if (first_node == NULL_TREE)
					break;
				head = search_interesting_stmt(head, stmt, first_node, 0);
				break;
			case GIMPLE_CALL:
				head = search_interesting_calls(head, as_a_gcall(stmt));
				break;
			default:
				break;
			}
		}
	}

	handle_interesting_stmt(visited, head);
	free_interesting_stmts(head);
}

static struct visited *create_visited(void)
{
	struct visited *new_node;

	new_node = (struct visited *)xmalloc(sizeof(*new_node));
	new_node->stmts = pointer_set_create();
	new_node->my_stmts = pointer_set_create();
	new_node->skip_expr_casts = pointer_set_create();
	new_node->no_cast_check = pointer_set_create();
	return new_node;
}

static void free_visited(struct visited *visited)
{
	pointer_set_destroy(visited->stmts);
	pointer_set_destroy(visited->my_stmts);
	pointer_set_destroy(visited->skip_expr_casts);
	pointer_set_destroy(visited->no_cast_check);

	free(visited);
}

// Remove the size_overflow asm stmt and create an assignment from the input and output of the asm
static void replace_size_overflow_asm_with_assign(gasm *asm_stmt, tree lhs, tree rhs)
{
	gassign *assign;
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

// Replace our asm stmts with assignments (they are no longer needed and may interfere with later optimizations)
static void remove_size_overflow_asm(gimple stmt)
{
	gimple_stmt_iterator gsi;
	tree input, output;

	if (!is_size_overflow_asm(stmt))
		return;

	if (gimple_asm_noutputs(as_a_gasm(stmt)) == 0) {
		gsi = gsi_for_stmt(stmt);

		ipa_remove_stmt_references(cgraph_get_node(current_function_decl), stmt);
		gsi_remove(&gsi, true);
		return;
	}

	input = gimple_asm_input_op(as_a_gasm(stmt), 0);
	output = gimple_asm_output_op(as_a_gasm(stmt), 0);
	replace_size_overflow_asm_with_assign(as_a_gasm(stmt), TREE_VALUE(output), TREE_VALUE(input));
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

unsigned int size_overflow_transform(struct cgraph_node *node __unused)
{
	struct visited *visited;

#if BUILDING_GCC_VERSION >= 4008
	if (dump_file) {
		fprintf(dump_file, "BEFORE TRANSFORM -------------------------\n");
		size_overflow_dump_function(dump_file, node);
	}
#endif
	visited = create_visited();
	set_dominance_info();

	search_interesting_stmts(visited);

	remove_all_size_overflow_asm();

	unset_dominance_info();
	free_visited(visited);

#if BUILDING_GCC_VERSION >= 4008
	if (dump_file) {
		fprintf(dump_file, "AFTER TRANSFORM -------------------------\n");
		size_overflow_dump_function(dump_file, node);
	}
#endif
	return TODO_dump_func | TODO_verify_stmts | TODO_remove_unused_locals | TODO_update_ssa_no_phi | TODO_ggc_collect | TODO_verify_flow;
}

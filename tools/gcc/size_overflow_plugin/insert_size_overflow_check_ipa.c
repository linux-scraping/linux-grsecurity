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

#define VEC_LEN 128
#define RET_CHECK NULL_TREE
#define WRONG_NODE 32
#define NOT_INTENTIONAL_ASM NULL

unsigned int call_count;

static void set_conditions(struct pointer_set_t *visited, bool *interesting_conditions, const_tree lhs);
static void walk_use_def(struct pointer_set_t *visited, struct interesting_node *cur_node, tree lhs);

struct visited_fns {
	struct visited_fns *next;
	const_tree fndecl;
	unsigned int num;
	const_gimple first_stmt;
};

struct next_cgraph_node {
	struct next_cgraph_node *next;
	struct cgraph_node *current_function;
	tree callee_fndecl;
	unsigned int num;
};

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
	FROM_CONST, NOT_UNARY, CAST, RET, PHI
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
	case GIMPLE_CALL:
		if (lhs == gimple_call_lhs(def_stmt))
			interesting_conditions[RET] = true;
		return;
	case GIMPLE_NOP:
	case GIMPLE_ASM:
		return;
	case GIMPLE_PHI:
		interesting_conditions[PHI] = true;
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

/* Get the fndecl of an interesting stmt, the fndecl is the caller function if the interesting
 * stmt is a return otherwise it is the callee function.
 */
const_tree get_interesting_orig_fndecl(const_gimple stmt, unsigned int argnum)
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
 * It skips the possible error codes too.
 */
static enum precond check_preconditions(struct interesting_node *cur_node)
{
	bool interesting_conditions[5] = {false, false, false, false, false};

	set_last_nodes(cur_node);

	check_intentional_attribute_ipa(cur_node);
	if (cur_node->intentional_attr_decl == MARK_TURN_OFF || cur_node->intentional_attr_cur_fndecl == MARK_TURN_OFF)
		return NO_ATTRIBUTE_SEARCH;

	search_interesting_conditions(cur_node, interesting_conditions);

	// error code: a phi, unary assign (not cast) and returns only
	if (!interesting_conditions[NOT_UNARY] && interesting_conditions[PHI] && interesting_conditions[RET] && !interesting_conditions[CAST])
		return NO_ATTRIBUTE_SEARCH;

	// error code: def_stmts trace back to a constant and there are no binary/ternary assigments
	if (interesting_conditions[CAST] && interesting_conditions[FROM_CONST] && !interesting_conditions[NOT_UNARY])
		return NO_ATTRIBUTE_SEARCH;

	// unnecessary overflow check
	if (!interesting_conditions[CAST] && !interesting_conditions[NOT_UNARY])
		return NO_CHECK_INSERT;

	if (cur_node->intentional_attr_cur_fndecl != MARK_NO)
		return NO_CHECK_INSERT;

	return NONE;
}

static tree cast_to_orig_type(struct visited *visited, gimple stmt, const_tree orig_node, tree new_node)
{
	const_gimple assign;
	tree orig_type = TREE_TYPE(orig_node);
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);

	assign = build_cast_stmt(visited, orig_type, new_node, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	return gimple_assign_lhs(assign);
}

static void change_orig_node(struct visited *visited, struct interesting_node *cur_node, tree new_node)
{
	void (*set_rhs)(gimple, tree);
	gimple stmt = cur_node->first_stmt;
	const_tree orig_node = cur_node->node;

	switch (gimple_code(stmt)) {
	case GIMPLE_RETURN:
		gimple_return_set_retval(stmt, cast_to_orig_type(visited, stmt, orig_node, new_node));
		break;
	case GIMPLE_CALL:
		gimple_call_set_arg(stmt, cur_node->num - 1, cast_to_orig_type(visited, stmt, orig_node, new_node));
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

		set_rhs(stmt, cast_to_orig_type(visited, stmt, orig_node, new_node));
		break;
	default:
		debug_gimple_stmt(stmt);
		gcc_unreachable();
	}

	update_stmt(stmt);
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

/* This function calls the main recursion function (expand) that duplicates the stmts. Before that it checks the intentional_overflow attribute and asm stmts,
 * it decides whether the duplication is necessary or not and it searches for missing size_overflow attributes. After expand() it changes the orig node to the duplicated node
 * in the original stmt (first stmt) and it inserts the overflow check for the arg of the callee or for the return value.
 */
static struct next_cgraph_node *handle_interesting_stmt(struct visited *visited, struct next_cgraph_node *cnodes, struct interesting_node *cur_node, struct cgraph_node *caller_node)
{
	enum precond ret;
	tree new_node, orig_node = cur_node->node;

	ret = check_preconditions(cur_node);
	if (ret == NO_ATTRIBUTE_SEARCH)
		return cnodes;

	cnodes = search_overflow_attribute(cnodes, cur_node);

	if (ret == NO_CHECK_INSERT)
		return cnodes;

	new_node = expand(visited, caller_node, orig_node);
	if (new_node == NULL_TREE)
		return cnodes;

	change_orig_node(visited, cur_node, new_node);
	check_size_overflow(caller_node, cur_node->first_stmt, TREE_TYPE(new_node), new_node, orig_node, BEFORE_STMT);

	return cnodes;
}

// Check visited_fns interesting nodes.
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

static struct visited_fns *insert_visited_fns_function(struct visited_fns *head, struct interesting_node *cur_node)
{
	struct visited_fns *new_visited_fns;

	new_visited_fns = (struct visited_fns *)xmalloc(sizeof(*new_visited_fns));
	new_visited_fns->fndecl = cur_node->fndecl;
	new_visited_fns->num = cur_node->num;
	new_visited_fns->first_stmt = cur_node->first_stmt;
	new_visited_fns->next = NULL;

	if (!head)
		return new_visited_fns;

	new_visited_fns->next = head;
	return new_visited_fns;
}

/* Check whether the function was already visited_fns. If the fndecl, the arg count of the fndecl and the first_stmt (call or return) are same then
 * it is a visited_fns function.
 */
static bool is_visited_fns_function(struct visited_fns *head, struct interesting_node *cur_node)
{
	struct visited_fns *cur;

	if (!head)
		return false;

	for (cur = head; cur; cur = cur->next) {
		if (cur_node->first_stmt != cur->first_stmt)
			continue;
		if (!operand_equal_p(cur_node->fndecl, cur->fndecl, 0))
			continue;
		if (cur_node->num == cur->num)
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
static struct visited_fns *handle_function(struct cgraph_node *node, struct next_cgraph_node *next_node, struct visited_fns *visited_fns)
{
	struct visited *visited;
	struct interesting_node *head, *cur_node;
	struct next_cgraph_node *cur_cnodes, *cnodes_head = NULL;

	set_current_function_decl(NODE_DECL(node));
	call_count = 0;

	head = collect_interesting_stmts(next_node);

	visited = create_visited();
	for (cur_node = head; cur_node; cur_node = cur_node->next) {
		if (is_visited_fns_function(visited_fns, cur_node))
			continue;
		cnodes_head = handle_interesting_stmt(visited, cnodes_head, cur_node, node);
		visited_fns = insert_visited_fns_function(visited_fns, cur_node);
	}

	free_visited(visited);
	free_interesting_node(head);
	remove_all_size_overflow_asm();
	unset_current_function_decl();

	for (cur_cnodes = cnodes_head; cur_cnodes; cur_cnodes = cur_cnodes->next)
		visited_fns = handle_function(cur_cnodes->current_function, cur_cnodes, visited_fns);

	free_next_cgraph_node(cnodes_head);
	return visited_fns;
}

static void free_visited_fns(struct visited_fns *head)
{
	struct visited_fns *cur;

	while (head) {
		cur = head->next;
		free(head);
		head = cur;
	}
}

// Main entry point of the ipa pass: erases the plf flag of all stmts and iterates over all the functions
unsigned int search_function(void)
{
	struct cgraph_node *node;
	struct visited_fns *visited_fns = NULL;

	FOR_EACH_FUNCTION_WITH_GIMPLE_BODY(node) {
		gcc_assert(cgraph_function_flags_ready);
#if BUILDING_GCC_VERSION <= 4007
		gcc_assert(node->reachable);
#endif

		visited_fns = handle_function(node, NULL, visited_fns);
	}

	free_visited_fns(visited_fns);
	return 0;
}

#if BUILDING_GCC_VERSION >= 4009
static const struct pass_data insert_size_overflow_check_data = {
#else
static struct ipa_opt_pass_d insert_size_overflow_check = {
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
class insert_size_overflow_check : public ipa_opt_pass_d {
public:
	insert_size_overflow_check() : ipa_opt_pass_d(insert_size_overflow_check_data, g, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL) {}
	unsigned int execute() { return search_function(); }
};
}
#endif

struct opt_pass *make_insert_size_overflow_check(void)
{
#if BUILDING_GCC_VERSION >= 4009
	return new insert_size_overflow_check();
#else
	return &insert_size_overflow_check.pass;
#endif
}


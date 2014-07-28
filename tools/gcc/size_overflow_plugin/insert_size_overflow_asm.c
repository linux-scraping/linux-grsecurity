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

static void search_size_overflow_attribute(struct pointer_set_t *visited, tree lhs);
static enum mark search_intentional(struct pointer_set_t *visited, const_tree lhs);

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

		create_asm_stmt(asm_comment, build_string(3, "rm"), NULL, asm_data);
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
	create_asm_stmt(asm_comment, build_string(2, "0"), build_string(4, "=rm"), &asm_data);
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
		create_asm_stmt(asm_str, build_string(3, "rm"), NULL, &asm_data);
		return true;
	}

	create_asm_input(stmt, 0, &asm_data);
	gcc_assert(asm_data.input != NULL_TREE);

	create_asm_stmt(asm_str, build_string(2, "0"), build_string(4, "=rm"), &asm_data);
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

struct opt_pass *make_insert_size_overflow_asm_pass(void)
{
#if BUILDING_GCC_VERSION >= 4009
	return new insert_size_overflow_asm_pass();
#else
	return &insert_size_overflow_asm_pass.pass;
#endif
}

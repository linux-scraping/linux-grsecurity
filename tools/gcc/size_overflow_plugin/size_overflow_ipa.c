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

static next_interesting_function_t walk_use_def_next_functions(struct pointer_set_t *visited, next_interesting_function_t next_cnodes_head, const_tree lhs);

next_interesting_function_t global_next_interesting_function[GLOBAL_NIFN_LEN];

static struct cgraph_node_hook_list *function_insertion_hook_holder;
static struct cgraph_2node_hook_list *node_duplication_hook_holder;

struct cgraph_node *get_cnode(const_tree fndecl)
{
	gcc_assert(TREE_CODE(fndecl) == FUNCTION_DECL);
#if BUILDING_GCC_VERSION <= 4005
	return cgraph_get_node((tree)fndecl);
#else
	return cgraph_get_node(fndecl);
#endif
}

static bool compare_next_interesting_functions(next_interesting_function_t cur_node, const char *decl_name, const char *context, unsigned int num)
{
	if (cur_node->marked == ASM_STMT_SO_MARK)
		return false;
	if (num != CANNOT_FIND_ARG && cur_node->num != num)
		return false;
	if (strcmp(cur_node->context, context))
		return false;
	return !strcmp(cur_node->decl_name, decl_name);
}

// Return the type name for a function pointer (or "fielddecl" if the type has no name), otherwise either "vardecl" or "fndecl"
static const char* get_decl_context(const_tree decl)
{
	const char *context;

	if (TREE_CODE(decl) == VAR_DECL)
		return "vardecl";
	if (TREE_CODE(decl) == FUNCTION_DECL)
		return "fndecl";

	gcc_assert(TREE_CODE(decl) == FIELD_DECL);
	context = get_type_name_from_field(decl);

	if (!context)
		return "fielddecl";
	return context;
}

/* Find the function with the specified argument in the list
 *   * if marked is ASM_STMT_SO_MARK or YES_SO_MARK then filter accordingly
 *   * if num is CANNOT_FIND_ARG then ignore it
 */
next_interesting_function_t get_global_next_interesting_function_entry(const char *decl_name, const char *context, unsigned int hash, unsigned int num, enum size_overflow_mark marked)
{
	next_interesting_function_t cur_node, head;

	head = global_next_interesting_function[hash];
	for (cur_node = head; cur_node; cur_node = cur_node->next) {
		if ((marked == ASM_STMT_SO_MARK || marked == YES_SO_MARK) && cur_node->marked != marked)
			continue;
		if (compare_next_interesting_functions(cur_node, decl_name, context, num))
			return cur_node;
	}
	return NULL;
}

next_interesting_function_t get_global_next_interesting_function_entry_with_hash(const_tree decl, const char *decl_name, unsigned int num, enum size_overflow_mark marked)
{
	const char *context;
	unsigned int hash;

	hash = get_decl_hash(decl, decl_name);
	if (hash == NO_HASH)
		return NULL;

	context = get_decl_context(decl);
	return get_global_next_interesting_function_entry(decl_name, context, hash, num, marked);
}

static bool is_vararg(const_tree fn, unsigned int num)
{
	const_tree fn_type, last, type;
	tree arg_list;

	if (num == 0)
		return false;
	if (fn == NULL_TREE)
		return false;
	if (TREE_CODE(fn) != FUNCTION_DECL)
		return false;

	fn_type = TREE_TYPE(fn);
	if (fn_type == NULL_TREE)
		return false;

	arg_list = TYPE_ARG_TYPES(fn_type);
	if (arg_list == NULL_TREE)
		return false;
	last = TREE_VALUE(tree_last(arg_list));

	if (TREE_CODE_CLASS(TREE_CODE(last)) == tcc_type)
		type = last;
	else
		type = TREE_TYPE(last);

	gcc_assert(type != NULL_TREE);
	if (type == void_type_node)
		return false;

	return num >= (unsigned int)list_length(arg_list);
}

next_interesting_function_t create_new_next_interesting_entry(const char *decl_name, const char *context, unsigned int hash, unsigned int num, enum size_overflow_mark marked, next_interesting_function_t orig_next_node)
{
	next_interesting_function_t new_node;

	new_node = (next_interesting_function_t)xmalloc(sizeof(*new_node));
	new_node->decl_name = xstrdup(decl_name);
	gcc_assert(context);
	new_node->context = xstrdup(context);
	new_node->hash = hash;
	new_node->num = num;
	new_node->next = NULL;
	new_node->children = NULL;
	new_node->marked = marked;
	new_node->orig_next_node = orig_next_node;
	return new_node;
}

// Create the main data structure
next_interesting_function_t create_new_next_interesting_decl(tree decl, const char *decl_name, unsigned int num, enum size_overflow_mark marked, next_interesting_function_t orig_next_node)
{
	unsigned int hash;
	const char *context;
	enum tree_code decl_code = TREE_CODE(decl);

	gcc_assert(decl_code == FIELD_DECL || decl_code == FUNCTION_DECL || decl_code == VAR_DECL);

	if (is_vararg(decl, num))
		return NULL;

	hash = get_decl_hash(decl, decl_name);
	if (hash == NO_HASH)
		return NULL;

	gcc_assert(num <= MAX_PARAM);
	// Clones must have an orig_next_node
	gcc_assert(!made_by_compiler(decl) || orig_next_node);

	context = get_decl_context(decl);
	return create_new_next_interesting_entry(decl_name, context, hash, num, marked, orig_next_node);
}

void add_to_global_next_interesting_function(next_interesting_function_t new_entry)
{
	next_interesting_function_t cur_global_head, cur_global, cur_global_end = NULL;

	// new_entry is appended to the end of a list
	new_entry->next = NULL;

	cur_global_head = global_next_interesting_function[new_entry->hash];
	if (!cur_global_head) {
		global_next_interesting_function[new_entry->hash] = new_entry;
		return;
	}


	for (cur_global = cur_global_head; cur_global; cur_global = cur_global->next) {
		if (!cur_global->next)
			cur_global_end = cur_global;
		if (compare_next_interesting_functions(cur_global, new_entry->decl_name, new_entry->context, new_entry->num))
			return;
	}

	gcc_assert(cur_global_end);
	cur_global_end->next = new_entry;
}

/* If the interesting function is a clone then find or create its original next_interesting_function_t node
 * and add it to global_next_interesting_function
 */
static next_interesting_function_t create_orig_next_node_for_a_clone(const_tree clone_fndecl, unsigned int num, enum size_overflow_mark marked)
{
	next_interesting_function_t orig_next_node;
	tree decl;
	unsigned int orig_num;
	enum tree_code decl_code;
	const char *decl_name;

	decl = get_orig_fndecl(clone_fndecl);
	decl_code = TREE_CODE(decl);

	if (decl_code == FIELD_DECL || decl_code == VAR_DECL)
		orig_num = num;
	else
		orig_num = get_correct_argnum(clone_fndecl, decl, num);

	// Skip over ISRA.162 parm decls
	if (orig_num == CANNOT_FIND_ARG)
		return NULL;

	decl_name = get_orig_decl_name(decl);
	orig_next_node = get_global_next_interesting_function_entry_with_hash(decl, decl_name, orig_num, NO_SO_MARK);
	if (orig_next_node)
		return orig_next_node;

	orig_next_node = create_new_next_interesting_decl(decl, decl_name, orig_num, marked, NULL);
	gcc_assert(orig_next_node);

	add_to_global_next_interesting_function(orig_next_node);
	return orig_next_node;
}

// Find or create the next_interesting_function_t node for decl and num
next_interesting_function_t get_and_create_next_node_from_global_next_nodes(tree decl, unsigned int num, enum size_overflow_mark marked, next_interesting_function_t orig_next_node)
{
	next_interesting_function_t cur_next_cnode;
	const char *decl_name = DECL_NAME_POINTER(decl);

	cur_next_cnode = get_global_next_interesting_function_entry_with_hash(decl, decl_name, num, marked);
	if (cur_next_cnode)
		goto out;

	if (!orig_next_node && made_by_compiler(decl)) {
		orig_next_node = create_orig_next_node_for_a_clone(decl, num, marked);
		if (!orig_next_node)
			return NULL;
	}

	cur_next_cnode = create_new_next_interesting_decl(decl, decl_name, num, marked, orig_next_node);
	if (!cur_next_cnode)
		return NULL;

	add_to_global_next_interesting_function(cur_next_cnode);
out:
	if (cur_next_cnode->marked != marked && cur_next_cnode->marked == YES_SO_MARK)
		return cur_next_cnode;
	gcc_assert(cur_next_cnode->marked == marked);
	return cur_next_cnode;
}

static bool has_next_interesting_function_chain_node(next_interesting_function_t next_cnodes_head, const_tree decl, unsigned int num)
{
	next_interesting_function_t cur_node;
	const char *context, *decl_name;

	decl_name = DECL_NAME_POINTER(decl);
	context = get_decl_context(decl);
	for (cur_node = next_cnodes_head; cur_node; cur_node = cur_node->next) {
		if (compare_next_interesting_functions(cur_node, decl_name, context, num))
			return true;
	}
	return false;
}

static next_interesting_function_t handle_function(next_interesting_function_t next_cnodes_head, tree fndecl, const_tree arg)
{
	unsigned int num;
	next_interesting_function_t orig_next_node, new_node;

	gcc_assert(fndecl != NULL_TREE);

	// ignore builtins to not explode coverage (e.g., memcpy)
	if (DECL_BUILT_IN(fndecl))
		return next_cnodes_head;

	// convert arg into its position
	if (arg == NULL_TREE)
		num = 0;
	else
		num = find_arg_number_tree(arg, fndecl);
	if (num == CANNOT_FIND_ARG)
		return next_cnodes_head;

	if (has_next_interesting_function_chain_node(next_cnodes_head, fndecl, num))
		return next_cnodes_head;

	if (made_by_compiler(fndecl)) {
		orig_next_node = create_orig_next_node_for_a_clone(fndecl, num, NO_SO_MARK);
		if (!orig_next_node)
			return next_cnodes_head;
	} else
		orig_next_node = NULL;
	new_node = create_new_next_interesting_decl(fndecl, DECL_NAME_POINTER(fndecl), num, NO_SO_MARK, orig_next_node);
	if (!new_node)
		return next_cnodes_head;
	new_node->next = next_cnodes_head;
	return new_node;
}

static next_interesting_function_t walk_use_def_next_functions_phi(struct pointer_set_t *visited, next_interesting_function_t next_cnodes_head, const_tree result)
{
	gimple phi = get_def_stmt(result);
	unsigned int i, n = gimple_phi_num_args(phi);

	pointer_set_insert(visited, phi);
	for (i = 0; i < n; i++) {
		tree arg = gimple_phi_arg_def(phi, i);

		next_cnodes_head = walk_use_def_next_functions(visited, next_cnodes_head, arg);
	}

	return next_cnodes_head;
}

static next_interesting_function_t walk_use_def_next_functions_binary(struct pointer_set_t *visited, next_interesting_function_t next_cnodes_head, const_tree lhs)
{
	gimple def_stmt = get_def_stmt(lhs);
	tree rhs1, rhs2;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);

	next_cnodes_head = walk_use_def_next_functions(visited, next_cnodes_head, rhs1);
	return walk_use_def_next_functions(visited, next_cnodes_head, rhs2);
}

next_interesting_function_t __attribute__((weak)) handle_function_ptr_ret(struct pointer_set_t *visited __unused, next_interesting_function_t next_cnodes_head, const_tree fn_ptr __unused)
{
	return next_cnodes_head;
}

/* Find all functions that influence lhs
 *
 * Encountered functions are added to the children vector (next_interesting_function_t).
 */
static next_interesting_function_t walk_use_def_next_functions(struct pointer_set_t *visited, next_interesting_function_t next_cnodes_head, const_tree lhs)
{
	const_gimple def_stmt;

	if (skip_types(lhs))
		return next_cnodes_head;

	if (TREE_CODE(lhs) == PARM_DECL)
		return handle_function(next_cnodes_head, current_function_decl, lhs);

	if (TREE_CODE(lhs) != SSA_NAME)
		return next_cnodes_head;

	def_stmt = get_def_stmt(lhs);
	if (!def_stmt)
		return next_cnodes_head;

	if (pointer_set_insert(visited, def_stmt))
		return next_cnodes_head;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
		return walk_use_def_next_functions(visited, next_cnodes_head, SSA_NAME_VAR(lhs));
	case GIMPLE_ASM:
		if (is_size_overflow_asm(def_stmt))
			return walk_use_def_next_functions(visited, next_cnodes_head, get_size_overflow_asm_input(def_stmt));
		return next_cnodes_head;
	case GIMPLE_CALL: {
		tree fndecl = gimple_call_fndecl(def_stmt);

		if (fndecl != NULL_TREE)
			return handle_function(next_cnodes_head, fndecl, NULL_TREE);
		fndecl = gimple_call_fn(def_stmt);
		return handle_function_ptr_ret(visited, next_cnodes_head, fndecl);
	}
	case GIMPLE_PHI:
		return walk_use_def_next_functions_phi(visited, next_cnodes_head, lhs);
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			return walk_use_def_next_functions(visited, next_cnodes_head, gimple_assign_rhs1(def_stmt));
		case 3:
			return walk_use_def_next_functions_binary(visited, next_cnodes_head, lhs);
		}
	default:
		debug_gimple_stmt((gimple)def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
}

// Start the search for next_interesting_function_t children based on the (next_interesting_function_t) parent node
static next_interesting_function_t search_next_functions(const_tree node)
{
	struct pointer_set_t *visited;
	next_interesting_function_t next_cnodes_head;

	visited = pointer_set_create();
	next_cnodes_head = walk_use_def_next_functions(visited, NULL, node);
	pointer_set_destroy(visited);

	return next_cnodes_head;
}

// True if child already exists in the next_interesting_function_t children vector
bool has_next_interesting_function_vec(next_interesting_function_t target, next_interesting_function_t next_node)
{
	unsigned int i;
	next_interesting_function_t cur;

	gcc_assert(next_node);
	// handle recursion
	if (!strcmp(target->decl_name, next_node->decl_name) && target->num == next_node->num)
		return true;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, target->children))
		return false;
	FOR_EACH_VEC_ELT(next_interesting_function_t, target->children, i, cur) {
#else
	FOR_EACH_VEC_SAFE_ELT(target->children, i, cur) {
#endif
		if (compare_next_interesting_functions(cur, next_node->decl_name, next_node->context, next_node->num))
			return true;
	}
	return false;
}

void push_child(next_interesting_function_t parent, next_interesting_function_t child)
{
	if (!has_next_interesting_function_vec(parent, child)) {
#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(next_interesting_function_t, heap, parent->children, child);
#else
		vec_safe_push(parent->children, child);
#endif
	}
}

void __attribute__((weak)) check_local_variables(next_interesting_function_t next_node __unused) {}

// Add children to parent and global_next_interesting_function
static void collect_data_for_execute(next_interesting_function_t parent, next_interesting_function_t children)
{
	next_interesting_function_t cur = children;

	gcc_assert(parent);

	while (cur) {
		next_interesting_function_t next, child;

		next = cur->next;

		child = get_global_next_interesting_function_entry(cur->decl_name, cur->context, cur->hash, cur->num, NO_SO_MARK);
		if (!child) {
			add_to_global_next_interesting_function(cur);
			child = cur;
		}

		check_local_variables(child);

		push_child(parent, child);

		cur = next;
	}

	check_local_variables(parent);
}

next_interesting_function_t __attribute__((weak)) get_and_create_next_node_from_global_next_nodes_fnptr(const_tree fn_ptr __unused, unsigned int num __unused, enum size_overflow_mark marked __unused)
{
	return NULL;
}

static next_interesting_function_t create_parent_next_cnode(const_gimple stmt, unsigned int num)
{
	switch (gimple_code(stmt)) {
	case GIMPLE_ASM:
		return get_and_create_next_node_from_global_next_nodes(current_function_decl, num, ASM_STMT_SO_MARK, NULL);
	case GIMPLE_CALL: {
		tree decl = gimple_call_fndecl(stmt);

		if (decl != NULL_TREE)
			return get_and_create_next_node_from_global_next_nodes(decl, num, NO_SO_MARK, NULL);
		decl = gimple_call_fn(stmt);
		return get_and_create_next_node_from_global_next_nodes_fnptr(decl, num, NO_SO_MARK);
	}
	case GIMPLE_RETURN:
		return get_and_create_next_node_from_global_next_nodes(current_function_decl, num, NO_SO_MARK, NULL);
	default:
		debug_gimple_stmt((gimple)stmt);
		gcc_unreachable();
	}
}

// Handle potential next_interesting_function_t parent if its argument has an integer type
static void collect_all_possible_size_overflow_fns(const_gimple stmt, unsigned int num)
{
	const_tree start_var;
	next_interesting_function_t children_next_cnode, parent_next_cnode;

	switch (gimple_code(stmt)) {
	case GIMPLE_ASM:
		if (!is_size_overflow_insert_check_asm(stmt))
			return;
		start_var = get_size_overflow_asm_input(stmt);
		gcc_assert(start_var != NULL_TREE);
		break;
	case GIMPLE_CALL:
		start_var = gimple_call_arg(stmt, num - 1);
		break;
	case GIMPLE_RETURN:
		start_var = gimple_return_retval(stmt);
		if (start_var == NULL_TREE)
			return;
		break;
	default:
		debug_gimple_stmt((gimple)stmt);
		gcc_unreachable();
	}

	if (skip_types(start_var))
		return;

	// handle intentional MARK_TURN_OFF
	if (check_intentional_asm(stmt, num) == MARK_TURN_OFF)
		return;

	parent_next_cnode = create_parent_next_cnode(stmt, num);
	if (!parent_next_cnode)
		return;

	children_next_cnode = search_next_functions(start_var);
	collect_data_for_execute(parent_next_cnode, children_next_cnode);
}

// Find potential next_interesting_function_t parents
static void handle_cgraph_node(struct cgraph_node *node)
{
	basic_block bb;
	tree cur_fndecl = NODE_DECL(node);

	set_current_function_decl(cur_fndecl);

	FOR_ALL_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gimple stmt = gsi_stmt(gsi);

			switch (gimple_code(stmt)) {
			case GIMPLE_RETURN:
			case GIMPLE_ASM:
				collect_all_possible_size_overflow_fns(stmt, 0);
				break;
			case GIMPLE_CALL: {
				unsigned int i, len;
				tree fndecl = gimple_call_fndecl(stmt);

				if (fndecl != NULL_TREE && DECL_BUILT_IN(fndecl))
					break;

				len = gimple_call_num_args(stmt);
				for (i = 0; i < len; i++)
					collect_all_possible_size_overflow_fns(stmt, i + 1);
				break;
			}
			default:
				break;
			}
		}
	}

	unset_current_function_decl();
}

/* Collect all potentially interesting function parameters and return values of integer types
 * and store their data flow dependencies
 */
static void size_overflow_generate_summary(void)
{
	struct cgraph_node *node;

	size_overflow_register_hooks();

	FOR_EACH_FUNCTION(node) {
		if (is_valid_cgraph_node(node))
			handle_cgraph_node(node);
	}
}

static void size_overflow_function_insertion_hook(struct cgraph_node *node __unused, void *data __unused)
{
	debug_cgraph_node(node);
	gcc_unreachable();
}

/* Handle dst if src is in the global_next_interesting_function list.
 * If src is a clone then dst inherits the orig_next_node of src otherwise
 * src will become the orig_next_node of dst.
 */
static void size_overflow_node_duplication_hook(struct cgraph_node *src, struct cgraph_node *dst, void *data __unused)
{
	next_interesting_function_t head, cur;
	const_tree decl;
	const char *src_name, *src_context;

	decl = NODE_DECL(src);
	src_name = DECL_NAME_POINTER(decl);
	src_context = get_decl_context(decl);

	head = get_global_next_interesting_function_entry_with_hash(decl, src_name, NONE_ARGNUM, NO_SO_MARK);
	if (!head)
		return;

	for (cur = head; cur; cur = cur->next) {
		unsigned int new_argnum;
		next_interesting_function_t orig_next_node, next_node;
		bool dst_clone;

		if (!compare_next_interesting_functions(cur, src_name, src_context, CANNOT_FIND_ARG))
			continue;

		dst_clone = made_by_compiler(NODE_DECL(dst));
		if (!dst_clone)
			break;

		// For clones use the original node instead
		if (cur->orig_next_node)
			orig_next_node = cur->orig_next_node;
		else
			orig_next_node = cur;

		new_argnum = get_correct_argnum_fndecl(NODE_DECL(src), NODE_DECL(dst), cur->num);
		if (new_argnum == CANNOT_FIND_ARG)
			continue;

		next_node = create_new_next_interesting_decl(NODE_DECL(dst), cgraph_node_name(dst), new_argnum, cur->marked, orig_next_node);
		if (next_node)
			add_to_global_next_interesting_function(next_node);
	}
}

void size_overflow_register_hooks(void)
{
	static bool init_p = false;

	if (init_p)
		return;
	init_p = true;

	function_insertion_hook_holder = cgraph_add_function_insertion_hook(&size_overflow_function_insertion_hook, NULL);
	node_duplication_hook_holder = cgraph_add_node_duplication_hook(&size_overflow_node_duplication_hook, NULL);
}

static void set_yes_so_mark(next_interesting_function_t next_node)
{
	next_node->marked = YES_SO_MARK;
	// Mark the orig decl as well if it's a clone
	if (next_node->orig_next_node)
		next_node->orig_next_node->marked = YES_SO_MARK;
}

// Determine if the function is already in the hash table
static bool is_marked_fn(next_interesting_function_t next_node)
{
	const struct size_overflow_hash *entry;

	if (next_node->marked != NO_SO_MARK)
		return true;

	if (next_node->orig_next_node)
		entry = get_size_overflow_hash_entry(next_node->orig_next_node->hash, next_node->orig_next_node->decl_name, next_node->orig_next_node->num);
	else
		entry = get_size_overflow_hash_entry(next_node->hash, next_node->decl_name, next_node->num);
	if (!entry)
		return false;

	set_yes_so_mark(next_node);
	return true;
}

// Determine if any of the function pointer targets have data flow between the return value and one of the arguments
static next_interesting_function_t get_same_not_ret_child(next_interesting_function_t parent)
{
	unsigned int i;
	next_interesting_function_t child;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return NULL;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		if (child->num == 0)
			continue;
		if (strcmp(parent->decl_name, child->decl_name))
			continue;
		if (!strcmp(child->context, "fndecl"))
			return child;
	}
	return NULL;
}

/* Trace a return value of function pointer type back to an argument via a concrete function
   fnptr 0 && fn 0 && (fn 0 -> fn 2) => fnptr 2 */
static void search_missing_fptr_arg(next_interesting_function_t parent)
{
	next_interesting_function_t tracked_fn, cur_next_node, child;
	unsigned int i;
#if BUILDING_GCC_VERSION <= 4007
	VEC(next_interesting_function_t, heap) *new_children = NULL;
#else
	vec<next_interesting_function_t, va_heap, vl_embed> *new_children = NULL;
#endif

	if (parent->num != 0)
		return;
	if (!strcmp(parent->context, "fndecl"))
		return;
	if (!strcmp(parent->context, "vardecl"))
		return;

	// fnptr 0 && fn 0
#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		if (child->num != 0)
			continue;
		// (fn 0 -> fn 2)
		tracked_fn = get_same_not_ret_child(child);
		if (!tracked_fn)
			continue;

		// fn 2 => fnptr 2
		for (cur_next_node = global_next_interesting_function[parent->hash]; cur_next_node; cur_next_node = cur_next_node->next) {
			if (cur_next_node->num != tracked_fn->num)
				continue;
			if (strcmp(parent->decl_name, cur_next_node->decl_name))
				continue;
			if (!has_next_interesting_function_vec(parent, cur_next_node)) {
#if BUILDING_GCC_VERSION <= 4007
				VEC_safe_push(next_interesting_function_t, heap, new_children, cur_next_node);
#else
				vec_safe_push(new_children, cur_next_node);
#endif
			}
		}
	}

#if BUILDING_GCC_VERSION == 4005
	if (VEC_empty(next_interesting_function_t, new_children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, new_children, i, child)
		VEC_safe_push(next_interesting_function_t, heap, parent->children, child);
#elif BUILDING_GCC_VERSION <= 4007
	VEC_safe_splice(next_interesting_function_t, heap, parent->children, new_children);
#else
	vec_safe_splice(parent->children, new_children);
#endif
}

// Do a depth-first recursive dump of the next_interesting_function_t children vector
static void print_missing_functions(struct pointer_set_t *visited, next_interesting_function_t parent)
{
	unsigned int i;
	next_interesting_function_t child;

	gcc_assert(parent);
	check_global_variables(parent);
	search_missing_fptr_arg(parent);
	print_missing_function(parent);

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		// Since the parent is a marked function we will set YES_SO_MARK on the children to transform them as well
		child->marked = YES_SO_MARK;
		if (!pointer_set_insert(visited, child))
			print_missing_functions(visited, child);
	}
}

void __attribute__((weak)) check_global_variables(next_interesting_function_t cur_global __unused) {}

// Print all missing interesting functions
static unsigned int size_overflow_execute(void)
{
	unsigned int i;
	struct pointer_set_t *visited;
	next_interesting_function_t cur_global;

	visited = pointer_set_create();

	for (i = 0; i < GLOBAL_NIFN_LEN; i++) {
		for (cur_global = global_next_interesting_function[i]; cur_global; cur_global = cur_global->next) {
			if (is_marked_fn(cur_global))
				print_missing_functions(visited, cur_global);
		}
	}

	pointer_set_destroy(visited);

/*	if (in_lto_p) {
		fprintf(stderr, "%s: SIZE_OVERFLOW EXECUTE\n", __func__);
		print_global_next_interesting_functions();
	}*/

	return 0;
}

// Omit the IPA/LTO callbacks until https://gcc.gnu.org/bugzilla/show_bug.cgi?id=61311 gets fixed (license concerns)
#if BUILDING_GCC_VERSION >= 4008
void __attribute__((weak)) size_overflow_write_summary_lto(void) {}
#elif BUILDING_GCC_VERSION >= 4006
void __attribute__((weak)) size_overflow_write_summary_lto(cgraph_node_set set __unused, varpool_node_set vset __unused) {}
#else
void __attribute__((weak)) size_overflow_write_summary_lto(cgraph_node_set set __unused) {}
#endif

void __attribute__((weak)) size_overflow_read_summary_lto(void) {}

#if BUILDING_GCC_VERSION >= 4009
static const struct pass_data size_overflow_functions_pass_data = {
#else
static struct ipa_opt_pass_d size_overflow_functions_pass = {
	.pass = {
#endif
		.type			= IPA_PASS,
		.name			= "size_overflow_functions",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 4009
		.has_gate		= false,
		.has_execute		= true,
#else
		.gate			= NULL,
		.execute		= size_overflow_execute,
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
	.generate_summary		= size_overflow_generate_summary,
	.write_summary			= size_overflow_write_summary_lto,
	.read_summary			= size_overflow_read_summary_lto,
#if BUILDING_GCC_VERSION >= 4006
	.write_optimization_summary	= size_overflow_write_summary_lto,
	.read_optimization_summary	= size_overflow_read_summary_lto,
#endif
	.stmt_fixup			= NULL,
	.function_transform_todo_flags_start		= 0,
	.function_transform		= size_overflow_transform,
	.variable_transform		= NULL,
#endif
};

#if BUILDING_GCC_VERSION >= 4009
namespace {
class size_overflow_functions_pass : public ipa_opt_pass_d {
public:
	size_overflow_functions_pass() : ipa_opt_pass_d(size_overflow_functions_pass_data,
			 g,
			 size_overflow_generate_summary,
			 size_overflow_write_summary_lto,
			 size_overflow_read_summary_lto,
			 size_overflow_write_summary_lto,
			 size_overflow_read_summary_lto,
			 NULL,
			 0,
			 size_overflow_transform,
			 NULL) {}
	unsigned int execute() { return size_overflow_execute(); }
};
}

opt_pass *make_size_overflow_functions_pass(void)
{
	return new size_overflow_functions_pass();
}
#else
struct opt_pass *make_size_overflow_functions_pass(void)
{
	return &size_overflow_functions_pass.pass;
}
#endif

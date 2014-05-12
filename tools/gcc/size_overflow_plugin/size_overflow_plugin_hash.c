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

#include "size_overflow_hash.h"
#include "size_overflow_hash_aux.h"

#define CODES_LIMIT 32

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

static const struct size_overflow_hash *get_proper_hash_chain(const struct size_overflow_hash *entry, const char *func_name)
{
	while (entry) {
		if (!strcmp(entry->name, func_name))
			return entry;
		entry = entry->next;
	}
	return NULL;
}

const struct size_overflow_hash *get_function_hash(const_tree fndecl)
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
	entry = get_proper_hash_chain(entry, func_name);
	if (entry)
		return entry;
	entry = size_overflow_hash_aux[fn_hash_data.hash];
	return get_proper_hash_chain(entry, func_name);
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

unsigned int find_arg_number_tree(const_tree arg, const_tree func)
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

static const char *get_asm_string(const_gimple stmt)
{
	if (!stmt)
		return NULL;
	if (gimple_code(stmt) != GIMPLE_ASM)
		return NULL;

	return gimple_asm_string(stmt);
}

bool is_size_overflow_intentional_asm_turn_off(const_gimple stmt)
{
	const char *str;

	str = get_asm_string(stmt);
	if (!str)
		return false;
	return !strncmp(str, TURN_OFF_ASM_STR, sizeof(TURN_OFF_ASM_STR) - 1);
}

bool is_size_overflow_intentional_asm_yes(const_gimple stmt)
{
	const char *str;

	str = get_asm_string(stmt);
	if (!str)
		return false;
	return !strncmp(str, YES_ASM_STR, sizeof(YES_ASM_STR) - 1);
}

bool is_size_overflow_asm(const_gimple stmt)
{
	const char *str;

	str = get_asm_string(stmt);
	if (!str)
		return false;
	return !strncmp(str, OK_ASM_STR, sizeof(OK_ASM_STR) - 1);
}

bool is_a_return_check(const_tree node)
{
	if (TREE_CODE(node) == FUNCTION_DECL)
		return true;

	gcc_assert(TREE_CODE(node) == PARM_DECL);
	return false;
}

// Get the argnum of a function decl, if node is a return then the argnum is 0
unsigned int get_function_num(const_tree node, const_tree orig_fndecl)
{
	if (is_a_return_check(node))
		return 0;
	else
		return find_arg_number_tree(node, orig_fndecl);
}

unsigned int get_correct_arg_count(unsigned int argnum, const_tree fndecl)
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

static bool is_in_hash_table(const_tree fndecl, unsigned int num)
{
	const struct size_overflow_hash *hash;

	hash = get_function_hash(fndecl);
	if (hash && (hash->param & (1U << num)))
		return true;
	return false;
}

/* Check if the function has a size_overflow attribute or it is in the size_overflow hash table.
 * If the function is missing everywhere then print the missing message into stderr.
 */
bool is_missing_function(const_tree orig_fndecl, unsigned int num)
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


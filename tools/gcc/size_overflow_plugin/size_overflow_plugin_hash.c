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

#include "size_overflow_hash.h"
#include "size_overflow_hash_aux.h"

static const_tree get_function_type(const_tree decl)
{
	if (FUNCTION_PTR_P(decl))
		return TREE_TYPE(TREE_TYPE(decl));
	gcc_assert(TREE_CODE(decl) == FUNCTION_DECL);
	return TREE_TYPE(decl);
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

// For function pointer fields include the structure name in the hash
static unsigned int get_type_name_hash(const_tree decl)
{
	const char *type_str;
	unsigned int type_name_len;

	if (!FUNCTION_PTR_P(decl))
		return 0;
	if (TREE_CODE(decl) == VAR_DECL)
		return 0;

	gcc_assert(TREE_CODE(decl) == FIELD_DECL);
	type_str = get_type_name_from_field(decl);
	if (!type_str)
		return 0;
	type_name_len = strlen(type_str);
	return CrapWow(type_str, type_name_len, 0) & 0xffff;
}

static void set_hash(struct decl_hash *decl_hash_data)
{
	unsigned int fn, type, codes, seed = 0;

	fn = CrapWow(decl_hash_data->fn_name, strlen(decl_hash_data->fn_name), seed) & 0xffff;
	codes = CrapWow((const char*)decl_hash_data->tree_codes, decl_hash_data->tree_codes_len, seed) & 0xffff;
	type = get_type_name_hash(decl_hash_data->decl);
	decl_hash_data->hash = type ^ fn ^ codes;
}

static void set_decl_type_codes(const_tree type, struct decl_hash *decl_hash_data)
{
	gcc_assert(type != NULL_TREE);
	gcc_assert(TREE_CODE_CLASS(TREE_CODE(type)) == tcc_type);

	while (type && decl_hash_data->tree_codes_len < CODES_LIMIT) {
		decl_hash_data->tree_codes[decl_hash_data->tree_codes_len] = get_tree_code(type);
		decl_hash_data->tree_codes_len++;
		type = TREE_TYPE(type);
	}
}

static void set_result_codes(const_tree node, struct decl_hash *decl_hash_data)
{
	const_tree result;

	gcc_assert(node != NULL_TREE);

	if (DECL_P(node)) {
		result = DECL_RESULT(node);
		if (result != NULL_TREE)
			return set_decl_type_codes(TREE_TYPE(result), decl_hash_data);
		return set_result_codes(TREE_TYPE(node), decl_hash_data);
	}

	gcc_assert(TYPE_P(node));

	if (TREE_CODE(node) == FUNCTION_TYPE)
		return set_result_codes(TREE_TYPE(node), decl_hash_data);

	return set_decl_type_codes(node, decl_hash_data);
}

static void set_decl_codes(struct decl_hash *decl_hash_data)
{
	const_tree arg, type;
	enum tree_code code;

	if (TREE_CODE(decl_hash_data->decl) == VAR_DECL) {
		set_decl_type_codes(TREE_TYPE(decl_hash_data->decl), decl_hash_data);
		return;
	}

	type = get_function_type(decl_hash_data->decl);
	code = TREE_CODE(type);
	gcc_assert(code == FUNCTION_TYPE || code == METHOD_TYPE);

	if (FUNCTION_PTR_P(decl_hash_data->decl))
		set_result_codes(type, decl_hash_data);
	else
		set_result_codes(decl_hash_data->decl, decl_hash_data);

	for (arg = TYPE_ARG_TYPES(type); arg != NULL_TREE && decl_hash_data->tree_codes_len < CODES_LIMIT; arg = TREE_CHAIN(arg))
		set_decl_type_codes(TREE_VALUE(arg), decl_hash_data);
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

unsigned int get_decl_hash(const_tree decl, const char *decl_name)
{
	struct decl_hash decl_hash_data;
	enum tree_code code = TREE_CODE(decl);

	decl_hash_data.fn_name = decl_name;
	gcc_assert(code == FIELD_DECL || code == FUNCTION_DECL || code == VAR_DECL);

	// skip builtins __builtin_constant_p
	if (code == FUNCTION_DECL && DECL_BUILT_IN(decl))
		return NO_HASH;

	decl_hash_data.decl = decl;
	decl_hash_data.tree_codes_len = 0;

	set_decl_codes(&decl_hash_data);
	gcc_assert(decl_hash_data.tree_codes_len != 0);
	set_hash(&decl_hash_data);
	return decl_hash_data.hash;
}

const char *get_orig_decl_name(const_tree decl)
{
	const char *name;
	unsigned int len;
	const void *end;
	const_tree orig_decl = DECL_ORIGIN(decl);

	len = DECL_NAME_LENGTH(orig_decl);
	name = DECL_NAME_POINTER(orig_decl);

	/* Sometimes gcc loses the original cgraph node leaving only clones behind.
	 * In such cases we will extract the name from the clone and use it in the hash table
	 * without checking the parameter number on the original (unavailable) decl.
	 */

	if (made_by_compiler(orig_decl)) {
		end = memchr(name, '.', len);
		gcc_assert(end);
		len = (long)end - (long)name;
		gcc_assert(len > 0);
	}

	return xstrndup(name, len);
}

const struct size_overflow_hash *get_size_overflow_hash_entry(unsigned int hash, const char *decl_name, unsigned int argnum)
{
	const struct size_overflow_hash *entry, *entry_node;

	entry = size_overflow_hash[hash];
	entry_node = get_proper_hash_chain(entry, decl_name);
	if (entry_node && entry_node->param & (1U << argnum))
		return entry_node;

	entry = size_overflow_hash_aux[hash];
	entry_node = get_proper_hash_chain(entry, decl_name);
	if (entry_node && entry_node->param & (1U << argnum))
		return entry_node;

	return NULL;
}

const struct size_overflow_hash *get_size_overflow_hash_entry_tree(const_tree fndecl, unsigned int argnum)
{
	const struct size_overflow_hash *entry;
	const_tree orig_decl;
	unsigned int orig_argnum, hash;
	const char *decl_name;

	if (made_by_compiler(fndecl)) {
		orig_decl = get_orig_fndecl(fndecl);
		orig_argnum = get_correct_argnum(fndecl, orig_decl, argnum);
	} else {
		orig_decl = fndecl;
		orig_argnum = argnum;
	}

	if (orig_argnum == CANNOT_FIND_ARG)
		return NULL;

	decl_name = get_orig_decl_name(orig_decl);
	hash = get_decl_hash(orig_decl, decl_name);
	if (hash == NO_HASH)
		return NULL;

	entry = get_size_overflow_hash_entry(hash, decl_name, orig_argnum);
	return entry;
}

unsigned int find_arg_number_tree(const_tree arg, const_tree func)
{
	tree var;
	unsigned int argnum = 1;

	if (DECL_ARGUMENTS(func) == NULL_TREE)
		return CANNOT_FIND_ARG;

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

const_tree get_attribute(const char* attr_name, const_tree decl)
{
	const_tree attr = lookup_attribute(attr_name, DECL_ATTRIBUTES(decl));
	if (attr && TREE_VALUE(attr))
		return attr;
	return NULL_TREE;
}

/* Check if the function has a size_overflow attribute or it is in the size_overflow hash table.
 * If the function is missing everywhere then print the missing message into stderr.
 */
void print_missing_function(next_interesting_function_t node)
{
	unsigned int argnum, hash;
	const struct size_overflow_hash *entry;
	const char *decl_name;

	if (node->marked == ASM_STMT_SO_MARK)
		return;

	if (node->orig_next_node) {
		hash = node->orig_next_node->hash;
		decl_name = node->orig_next_node->decl_name;
		argnum = node->orig_next_node->num;
	} else {
		hash = node->hash;
		decl_name = node->decl_name;
		argnum = node->num;
	}

	entry = get_size_overflow_hash_entry(hash, decl_name, argnum);
	if (entry)
		return;

	// inform() would be too slow
	fprintf(stderr, "Function %s is missing from the size_overflow hash table +%s+%u+%u+\n", decl_name, decl_name, argnum, hash);
}


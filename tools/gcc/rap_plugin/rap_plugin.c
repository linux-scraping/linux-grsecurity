/*
 * Copyright 2012-2016 by PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Homepage: http://pax.grsecurity.net/
 *
 * Usage:
 * $ # for 4.5/4.6/C based 4.7
 * $ gcc -I`gcc -print-file-name=plugin`/include -I`gcc -print-file-name=plugin`/include/c-family -fPIC -shared -O2 -o rap_plugin.so rap_plugin.c
 * $ # for C++ based 4.7/4.8+
 * $ g++ -I`g++ -print-file-name=plugin`/include -I`g++ -print-file-name=plugin`/include/c-family -fPIC -shared -O2 -o rap_plugin.so rap_plugin.c
 * $ gcc -fplugin=./rap_plugin.so -fplugin-arg-rap_plugin-check=call test.c -O2
 */

#include "rap.h"

int plugin_is_GPL_compatible;

static struct plugin_info rap_plugin_info = {
	.version	= "201604272100",
	.help		= "check=call\tenable the corresponding features\n"
			  "hash=abs,abs-finish,const,volatile\n"
			  "report=func,fptr,abs\n"
};

rap_hash_flags_t imprecise_rap_hash_flags = {
	.qual_const	= 1,
	.qual_volatile	= 1,
};

tree rap_hash_type_node;

static bool report_func_hash, report_abs_hash;

// create the equivalent of
// asm volatile("" : : : "memory");
// or
// asm("" : "+rm"(var));
// or
// asm("" : : "rm"(var));
gimple barrier(tree var, bool full)
{
	gimple stmt;
	gasm *asm_stmt;
#if BUILDING_GCC_VERSION <= 4007
	VEC(tree, gc) *inputs = NULL;
	VEC(tree, gc) *outputs = NULL;
	VEC(tree, gc) *clobbers = NULL;
#else
	vec<tree, va_gc> *inputs = NULL;
	vec<tree, va_gc> *outputs = NULL;
	vec<tree, va_gc> *clobbers = NULL;
#endif

	if (!var && full) {
		tree clobber;

		clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(tree, gc, clobbers, clobber);
#else
		vec_safe_push(clobbers, clobber);
#endif
	} else if (full) {
		tree input, output;

		input = build_tree_list(NULL_TREE, build_string(2, "0"));
		input = chainon(NULL_TREE, build_tree_list(input, var));
#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(tree, gc, inputs, input);
#else
		vec_safe_push(inputs, input);
#endif

		output = build_tree_list(NULL_TREE, build_string(4, "=rm"));
		gcc_assert(SSA_NAME_VAR(var));
		var = make_ssa_name(SSA_NAME_VAR(var), NULL);
		output = chainon(NULL_TREE, build_tree_list(output, var));
#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(tree, gc, outputs, output);
#else
		vec_safe_push(outputs, output);
#endif
	} else {
		tree input;

		input = build_tree_list(NULL_TREE, build_string(3, "rm"));
		input = chainon(NULL_TREE, build_tree_list(input, var));
#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(tree, gc, inputs, input);
#else
		vec_safe_push(inputs, input);
#endif
	}

	stmt = gimple_build_asm_vec("", inputs, outputs, clobbers, NULL);
	asm_stmt = as_a_gasm(stmt);
	if (!var && full)
		gimple_asm_set_volatile(asm_stmt, true);
	else if (full)
		SSA_NAME_DEF_STMT(var) = stmt;
	return stmt;
}

static const struct gcc_debug_hooks *old_debug_hooks;
static struct gcc_debug_hooks rap_debug_hooks;

static bool __rap_cgraph_indirectly_callable(cgraph_node_ptr node, void *data)
{
#if BUILDING_GCC_VERSION >= 4008
	if (NODE_SYMBOL(node)->externally_visible)
#else
	if (node->local.externally_visible)
#endif
		return true;

	if (NODE_SYMBOL(node)->address_taken)
		return true;

	return false;
}

static bool rap_cgraph_indirectly_callable(cgraph_node_ptr node)
{
	return cgraph_for_node_and_aliases(node, __rap_cgraph_indirectly_callable, NULL, true);
}

static void rap_hash_align(tree decl)
{
	const unsigned HOST_WIDE_INT rap_hash_offset = TARGET_64BIT ? 2 * sizeof(rap_hash_t) : sizeof(rap_hash_t);
	unsigned HOST_WIDE_INT skip;

	skip = 1ULL << align_functions_log;
	if (DECL_USER_ALIGN(decl))
		return;

	if (!optimize_function_for_speed_p(cfun))
		return;

	if (skip <= rap_hash_offset)
		return;

#ifdef TARGET_386
	{
		char padding[skip - rap_hash_offset];

		// this byte sequence helps disassemblers not trip up on the following rap hash
		memset(padding, 0xcc, sizeof padding - 1);
		padding[sizeof padding - 1] = 0xb8;
		ASM_OUTPUT_ASCII(asm_out_file, padding, sizeof padding);
	}
#else
	ASM_OUTPUT_SKIP(asm_out_file, skip - rap_hash_offset);
#endif
}

static void rap_begin_function(tree decl)
{
	cgraph_node_ptr node;
	rap_hash_t imprecise_rap_hash;

	gcc_assert(debug_hooks == &rap_debug_hooks);

	// chain to previous callback
	if (old_debug_hooks && old_debug_hooks->begin_function)
		old_debug_hooks->begin_function(decl);

	// align the rap hash if necessary
	rap_hash_align(decl);

	// don't compute hash for functions called only directly
	node = cgraph_get_node(decl);
	gcc_assert(node);
	if (!rap_cgraph_indirectly_callable(node)) {
		imprecise_rap_hash.hash = 0;
	} else {
		imprecise_rap_hash = rap_hash_function_node_imprecise(node);
	}

	if (report_func_hash)
		inform(DECL_SOURCE_LOCATION(decl), "func rap_hash: %x %s", imprecise_rap_hash.hash, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(decl)));

	if (TARGET_64BIT)
		fprintf(asm_out_file, "\t.quad %#lx\t%s __rap_hash_%s\n", (long)imprecise_rap_hash.hash, ASM_COMMENT_START, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(decl)));
	else
		fprintf(asm_out_file, "\t.long %#x\t%s __rap_hash_%s\n", imprecise_rap_hash.hash, ASM_COMMENT_START, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(decl)));
}

static void rap_start_unit_common(void *gcc_data __unused, void *user_data __unused)
{
	rap_hash_type_node = long_integer_type_node;

	if (debug_hooks)
		rap_debug_hooks = *debug_hooks;
	rap_debug_hooks.begin_function = rap_begin_function;
	old_debug_hooks = debug_hooks;
	debug_hooks = &rap_debug_hooks;
}

/*
   emit an absolute symbol for each function that may be referenced through the plt
     - all externs
     - non-static functions
       - use visibility instead?

   .globl __rap_hash_func
   .offset 0xhash_for_func
   .type __rap_hash_func, @object
   __rap_hash_func:
   .previous
*/
static void rap_finish_unit(void *gcc_data __unused, void *user_data __unused)
{
	cgraph_node_ptr node;
	rap_hash_t hash;

	gcc_assert(debug_hooks == &rap_debug_hooks);

	hash.hash = 0;
	FOR_EACH_FUNCTION(node) {
		tree fndecl;
		const char *asmname;
		char *name = NULL;

		if (cgraph_function_body_availability(node) >= AVAIL_INTERPOSABLE) {
			if (node->thunk.thunk_p || node->alias)
				continue;
			if (!rap_cgraph_indirectly_callable(node))
				continue;
		}

#if BUILDING_GCC_VERSION >= 4007
		gcc_assert(cgraph_function_or_thunk_node(node, NULL) == node);
#endif

		fndecl = NODE_DECL(node);
		gcc_assert(fndecl);
		if (DECL_IS_BUILTIN(fndecl) && DECL_BUILT_IN_CLASS(fndecl) == BUILT_IN_NORMAL)
			continue;

		if (!TREE_PUBLIC(fndecl))
			continue;

		if (DECL_ARTIFICIAL(fndecl))
			continue;

		if (DECL_ABSTRACT_ORIGIN(fndecl) && DECL_ABSTRACT_ORIGIN(fndecl) != fndecl)
			continue;

		gcc_assert(DECL_ASSEMBLER_NAME(fndecl));
		asmname = IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(fndecl));
		if (strchr(asmname, '.'))
			continue;

		if (asmname[0] == '*')
			asmname++;

		gcc_assert(asmname[0]);
		gcc_assert(asprintf(&name, "__rap_hash_%s", asmname) != -1);

		hash = rap_hash_function_node_imprecise(node);
		if (report_abs_hash)
			inform(DECL_SOURCE_LOCATION(fndecl), "abs rap_hash: %x %s", hash.hash, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(fndecl)));

		fprintf(asm_out_file, GLOBAL_ASM_OP " %s\n", name);
		if (TARGET_64BIT)
			fprintf(asm_out_file, "\t.offset %#lx\n", (long)hash.hash);
		else
			fprintf(asm_out_file, "\t.offset %#x\n", hash.hash);
		ASM_OUTPUT_TYPE_DIRECTIVE(asm_out_file, name, "object");
		ASM_OUTPUT_LABEL(asm_out_file, name);
		free(name);
	}

	if (hash.hash)
		fprintf(asm_out_file, "\t.previous\n");
}

// emit the rap hash as an absolute symbol for all functions seen in the frontend
// this is necessary as later unreferenced nodes will be removed yet we'd like to emit as many hashes as possible
static void rap_finish_decl(void *event_data, void *data __unused)
{
	tree fndecl = (tree)event_data;
	rap_hash_t hash;
	const char *asmname;
	char *name = NULL;

	if (fndecl == error_mark_node)
		return;

	if (TREE_CODE(fndecl) != FUNCTION_DECL)
		return;

	if (!TREE_PUBLIC(fndecl))
		return;

	if (DECL_ARTIFICIAL(fndecl))
		return;

	if (DECL_ABSTRACT_ORIGIN(fndecl) && DECL_ABSTRACT_ORIGIN(fndecl) != fndecl)
		return;

	asmname = DECL_NAME_POINTER(fndecl);
	gcc_assert(asmname[0]);

	if (strchr(asmname, '.'))
		return;

	gcc_assert(asprintf(&name, "__rap_hash_%s", asmname) != -1);

	hash = rap_hash_function_decl(fndecl, imprecise_rap_hash_flags);

	if (report_abs_hash)
		inform(DECL_SOURCE_LOCATION(fndecl), "abs rap_hash: %x %s", hash.hash, asmname);

	fprintf(asm_out_file, GLOBAL_ASM_OP " %s\n", name);
	if (TARGET_64BIT)
		fprintf(asm_out_file, "\t.offset %#lx\n", (long)hash.hash);
	else
		fprintf(asm_out_file, "\t.offset %#x\n", hash.hash);
	ASM_OUTPUT_TYPE_DIRECTIVE(asm_out_file, name, "object");
	ASM_OUTPUT_LABEL(asm_out_file, name);
	free(name);

	fprintf(asm_out_file, "\t.previous\n");
}

static bool rap_unignore_gate(void)
{
	if (!DECL_IGNORED_P(current_function_decl))
		return false;

	inform(DECL_SOURCE_LOCATION(current_function_decl), "DECL_IGNORED fixed");

	DECL_IGNORED_P(current_function_decl) = 0;
	return false;
}

#define PASS_NAME rap_unignore
#define NO_EXECUTE
#define TODO_FLAGS_FINISH TODO_dump_func
#include "gcc-generate-rtl-pass.h"

static bool rap_version_check(struct plugin_gcc_version *gcc_version, struct plugin_gcc_version *plugin_version)
{
	if (!gcc_version || !plugin_version)
		return false;

#if BUILDING_GCC_VERSION >= 5000
	if (strncmp(gcc_version->basever, plugin_version->basever, 4))
#else
	if (strcmp(gcc_version->basever, plugin_version->basever))
#endif
		return false;
	if (strcmp(gcc_version->datestamp, plugin_version->datestamp))
		return false;
	if (strcmp(gcc_version->devphase, plugin_version->devphase))
		return false;
	if (strcmp(gcc_version->revision, plugin_version->revision))
		return false;
//	if (strcmp(gcc_version->configuration_arguments, plugin_version->configuration_arguments))
//		return false;
	return true;
}

EXPORTED_CONST struct ggc_root_tab gt_ggc_r_gt_rap[] = {
	{
		.base = &rap_hash_type_node,
		.nelt = 1,
		.stride = sizeof(rap_hash_type_node),
		.cb = &gt_ggc_mx_tree_node,
		.pchw = &gt_pch_nx_tree_node
	},
	LAST_GGC_ROOT_TAB
};

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	int i;
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	bool enable_call = false;
	bool enable_abs = false, enable_abs_finish = false;

	struct register_pass_info rap_fptr_pass_info;
	struct register_pass_info rap_unignore_pass_info;

	rap_fptr_pass_info.pass						= make_rap_fptr_pass();
	rap_fptr_pass_info.reference_pass_name				= "nrv";
	rap_fptr_pass_info.ref_pass_instance_number			= 1;
	rap_fptr_pass_info.pos_op 					= PASS_POS_INSERT_AFTER;

	rap_unignore_pass_info.pass					= make_rap_unignore_pass();
	rap_unignore_pass_info.reference_pass_name			= "final";
	rap_unignore_pass_info.ref_pass_instance_number			= 1;
	rap_unignore_pass_info.pos_op 					= PASS_POS_INSERT_BEFORE;

	if (!rap_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

#if BUILDING_GCC_VERSION >= 5000
	if (flag_ipa_icf_functions) {
//		warning_at(UNKNOWN_LOCATION, 0, G_("-fipa-icf is incompatible with %s, disabling..."), plugin_name);
//		inform(UNKNOWN_LOCATION, G_("-fipa-icf is incompatible with %s, disabling..."), plugin_name);
		flag_ipa_icf_functions = 0;
	}
#endif

	for (i = 0; i < argc; ++i) {
		if (!strcmp(argv[i].key, "disable"))
			continue;

		if (!strcmp(argv[i].key, "check")) {
			char *values, *value, *saveptr;

			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			values = xstrdup(argv[i].value);
			value = strtok_r(values, ",", &saveptr);
			while (value) {
				if (!strcmp(value, "call"))
					enable_call = true;
				else
					error(G_("unknown value supplied for option '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, value);
				value = strtok_r(NULL, ",", &saveptr);
			}
			free(values);
			continue;
		}

		if (!strcmp(argv[i].key, "hash")) {
			char *values, *value, *saveptr;

			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			values = xstrdup(argv[i].value);
			value = strtok_r(values, ",", &saveptr);
			while (value) {
				if (!strcmp(value, "abs"))
					enable_abs = enable_abs_finish = true;
				else if (!strcmp(value, "abs-finish"))
					enable_abs_finish = true;
//				else if (!strcmp(value, "const"))
//					imprecise_rap_hash_flags.qual_const = 1;
//				else if (!strcmp(value, "volatile"))
//					imprecise_rap_hash_flags.qual_volatile = 1;
				else
					error(G_("unknown value supplied for option '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, value);
				value = strtok_r(NULL, ",", &saveptr);
			}
			free(values);
			continue;
		}

		if (!strcmp(argv[i].key, "report")) {
			char *values, *value, *saveptr;

			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			values = xstrdup(argv[i].value);
			value = strtok_r(values, ",", &saveptr);
			while (value) {
				if (!strcmp(value, "func"))
					report_func_hash = true;
				else if (!strcmp(value, "fptr"))
					report_fptr_hash = true;
				else if (!strcmp(value, "abs"))
					report_abs_hash = true;
				else
					error(G_("unknown value supplied for option '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, value);
				value = strtok_r(NULL, ",", &saveptr);
			}
			free(values);
			continue;
		}

		error(G_("unkown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &rap_plugin_info);

	if (enable_call) {
#if BUILDING_GCC_VERSION >= 4007
		if (enable_abs)
			register_callback(plugin_name, PLUGIN_FINISH_DECL, rap_finish_decl, NULL);
#else
#warning TODO
#endif
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &rap_unignore_pass_info);
		register_callback(plugin_name, PLUGIN_START_UNIT, rap_start_unit_common, NULL);
		register_callback(plugin_name, PLUGIN_REGISTER_GGC_ROOTS, NULL, (void *)&gt_ggc_r_gt_rap);
		if (enable_abs_finish)
			register_callback(plugin_name, PLUGIN_FINISH_UNIT, rap_finish_unit, NULL);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &rap_fptr_pass_info);
		register_callback(plugin_name, PLUGIN_ALL_IPA_PASSES_START, rap_calculate_func_hashes, NULL);
	}

	return 0;
}

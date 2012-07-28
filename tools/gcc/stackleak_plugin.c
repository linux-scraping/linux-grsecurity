/*
 * Copyright 2011 by the PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Note: the choice of the license means that the compilation process is
 *       NOT 'eligible' as defined by gcc's library exception to the GPL v3,
 *       but for the kernel it doesn't matter since it doesn't link against
 *       any of the gcc libraries
 *
 * gcc plugin to help implement various PaX features
 *
 * - track lowest stack pointer
 *
 * TODO:
 * - initialize all local variables
 *
 * BUGS:
 * - none known
 */
#include "gcc-plugin.h"
#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tree.h"
#include "tree-pass.h"
#include "flags.h"
#include "intl.h"
#include "toplev.h"
#include "plugin.h"
//#include "expr.h" where are you...
#include "diagnostic.h"
#include "plugin-version.h"
#include "tm.h"
#include "function.h"
#include "basic-block.h"
#include "gimple.h"
#include "rtl.h"
#include "emit-rtl.h"

extern void print_gimple_stmt(FILE *, gimple, int, int);

int plugin_is_GPL_compatible;

static int track_frame_size = -1;
static const char track_function[] = "pax_track_stack";
static const char check_function[] = "pax_check_alloca";
static bool init_locals;

static struct plugin_info stackleak_plugin_info = {
	.version	= "201203140940",
	.help		= "track-lowest-sp=nn\ttrack sp in functions whose frame size is at least nn bytes\n"
//			  "initialize-locals\t\tforcibly initialize all stack frames\n"
};

static bool gate_stackleak_track_stack(void);
static unsigned int execute_stackleak_tree_instrument(void);
static unsigned int execute_stackleak_final(void);

static struct gimple_opt_pass stackleak_tree_instrument_pass = {
	.pass = {
		.type			= GIMPLE_PASS,
		.name			= "stackleak_tree_instrument",
		.gate			= gate_stackleak_track_stack,
		.execute		= execute_stackleak_tree_instrument,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
		.tv_id			= TV_NONE,
		.properties_required	= PROP_gimple_leh | PROP_cfg,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0, //TODO_verify_ssa | TODO_verify_flow | TODO_verify_stmts,
		.todo_flags_finish	= TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_update_ssa
	}
};

static struct rtl_opt_pass stackleak_final_rtl_opt_pass = {
	.pass = {
		.type			= RTL_PASS,
		.name			= "stackleak_final",
		.gate			= gate_stackleak_track_stack,
		.execute		= execute_stackleak_final,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
		.tv_id			= TV_NONE,
		.properties_required	= 0,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= TODO_dump_func
	}
};

static bool gate_stackleak_track_stack(void)
{
	return track_frame_size >= 0;
}

static void stackleak_check_alloca(gimple_stmt_iterator *gsi)
{
	gimple check_alloca;
	tree fntype, fndecl, alloca_size;

	fntype = build_function_type_list(void_type_node, long_unsigned_type_node, NULL_TREE);
	fndecl = build_fn_decl(check_function, fntype);
	DECL_ASSEMBLER_NAME(fndecl); // for LTO

	// insert call to void pax_check_alloca(unsigned long size)
	alloca_size = gimple_call_arg(gsi_stmt(*gsi), 0);
	check_alloca = gimple_build_call(fndecl, 1, alloca_size);
	gsi_insert_before(gsi, check_alloca, GSI_SAME_STMT);
}

static void stackleak_add_instrumentation(gimple_stmt_iterator *gsi)
{
	gimple track_stack;
	tree fntype, fndecl;

	fntype = build_function_type_list(void_type_node, NULL_TREE);
	fndecl = build_fn_decl(track_function, fntype);
	DECL_ASSEMBLER_NAME(fndecl); // for LTO

	// insert call to void pax_track_stack(void)
	track_stack = gimple_build_call(fndecl, 0);
	gsi_insert_after(gsi, track_stack, GSI_CONTINUE_LINKING);
}

#if BUILDING_GCC_VERSION == 4005
static bool gimple_call_builtin_p(gimple stmt, enum built_in_function code)
{
	tree fndecl;

	if (!is_gimple_call(stmt))
		return false;
	fndecl = gimple_call_fndecl(stmt);
	if (!fndecl)
		return false;
	if (DECL_BUILT_IN_CLASS(fndecl) != BUILT_IN_NORMAL)
		return false;
//	print_node(stderr, "pax", fndecl, 4);
	return DECL_FUNCTION_CODE(fndecl) == code;
}
#endif

static bool is_alloca(gimple stmt)
{
	if (gimple_call_builtin_p(stmt, BUILT_IN_ALLOCA))
		return true;

#if BUILDING_GCC_VERSION >= 4007
	if (gimple_call_builtin_p(stmt, BUILT_IN_ALLOCA_WITH_ALIGN))
		return true;
#endif

	return false;
}

static unsigned int execute_stackleak_tree_instrument(void)
{
	basic_block bb, entry_bb;
	bool prologue_instrumented = false, is_leaf = true;

	entry_bb = ENTRY_BLOCK_PTR_FOR_FUNCTION(cfun)->next_bb;

	// 1. loop through BBs and GIMPLE statements
	FOR_EACH_BB(bb) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gimple stmt;

			stmt = gsi_stmt(gsi);

			if (is_gimple_call(stmt))
				is_leaf = false;

			// gimple match: align 8 built-in BUILT_IN_NORMAL:BUILT_IN_ALLOCA attributes <tree_list 0xb7576450>
			if (!is_alloca(stmt))
				continue;

			// 2. insert stack overflow check before each __builtin_alloca call
			stackleak_check_alloca(&gsi);

			// 3. insert track call after each __builtin_alloca call
			stackleak_add_instrumentation(&gsi);
			if (bb == entry_bb)
				prologue_instrumented = true;
		}
	}

	// special cases for some bad linux code: taking the address of static inline functions will materialize them
	// but we mustn't instrument some of them as the resulting stack alignment required by the function call ABI
	// will break other assumptions regarding the expected (but not otherwise enforced) register clobbering  ABI.
	// case in point: native_save_fl on amd64 when optimized for size clobbers rdx if it were instrumented here.
	if (is_leaf && !TREE_PUBLIC(current_function_decl) && DECL_DECLARED_INLINE_P(current_function_decl))
		return 0;
	if (is_leaf && !strncmp(IDENTIFIER_POINTER(DECL_NAME(current_function_decl)), "_paravirt_", 10))
		return 0;

	// 4. insert track call at the beginning
	if (!prologue_instrumented) {
		gimple_stmt_iterator gsi;

		bb = split_block_after_labels(ENTRY_BLOCK_PTR)->dest;
		if (dom_info_available_p(CDI_DOMINATORS))
			set_immediate_dominator(CDI_DOMINATORS, bb, ENTRY_BLOCK_PTR);
		gsi = gsi_start_bb(bb);
		stackleak_add_instrumentation(&gsi);
	}

	return 0;
}

static unsigned int execute_stackleak_final(void)
{
	rtx insn;

	if (cfun->calls_alloca)
		return 0;

	// keep calls only if function frame is big enough
	if (get_frame_size() >= track_frame_size)
		return 0;

	// 1. find pax_track_stack calls
	for (insn = get_insns(); insn; insn = NEXT_INSN(insn)) {
		// rtl match: (call_insn 8 7 9 3 (call (mem (symbol_ref ("pax_track_stack") [flags 0x41] <function_decl 0xb7470e80 pax_track_stack>) [0 S1 A8]) (4)) -1 (nil) (nil))
		rtx body;

		if (!CALL_P(insn))
			continue;
		body = PATTERN(insn);
		if (GET_CODE(body) != CALL)
			continue;
		body = XEXP(body, 0);
		if (GET_CODE(body) != MEM)
			continue;
		body = XEXP(body, 0);
		if (GET_CODE(body) != SYMBOL_REF)
			continue;
		if (strcmp(XSTR(body, 0), track_function))
			continue;
//		warning(0, "track_frame_size: %d %ld %d", cfun->calls_alloca, get_frame_size(), track_frame_size);
		// 2. delete call
		insn = delete_insn_and_edges(insn);
#if BUILDING_GCC_VERSION >= 4007
		if (GET_CODE(insn) == NOTE && NOTE_KIND(insn) == NOTE_INSN_CALL_ARG_LOCATION)
			insn = delete_insn_and_edges(insn);
#endif
	}

//	print_simple_rtl(stderr, get_insns());
//	print_rtl(stderr, get_insns());
//	warning(0, "track_frame_size: %d %ld %d", cfun->calls_alloca, get_frame_size(), track_frame_size);

	return 0;
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	int i;
	struct register_pass_info stackleak_tree_instrument_pass_info = {
		.pass				= &stackleak_tree_instrument_pass.pass,
//		.reference_pass_name		= "tree_profile",
		.reference_pass_name		= "optimized",
		.ref_pass_instance_number	= 1,
		.pos_op 			= PASS_POS_INSERT_BEFORE
	};
	struct register_pass_info stackleak_final_pass_info = {
		.pass				= &stackleak_final_rtl_opt_pass.pass,
		.reference_pass_name		= "final",
		.ref_pass_instance_number	= 1,
		.pos_op 			= PASS_POS_INSERT_BEFORE
	};

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &stackleak_plugin_info);

	for (i = 0; i < argc; ++i) {
		if (!strcmp(argv[i].key, "track-lowest-sp")) {
			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}
			track_frame_size = atoi(argv[i].value);
			if (argv[i].value[0] < '0' || argv[i].value[0] > '9' || track_frame_size < 0)
				error(G_("invalid option argument '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, argv[i].value);
			continue;
		}
		if (!strcmp(argv[i].key, "initialize-locals")) {
			if (argv[i].value) {
				error(G_("invalid option argument '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, argv[i].value);
				continue;
			}
			init_locals = true;
			continue;
		}
		error(G_("unkown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &stackleak_tree_instrument_pass_info);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &stackleak_final_pass_info);

	return 0;
}

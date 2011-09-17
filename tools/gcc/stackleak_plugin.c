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
#include "intl.h"
#include "plugin-version.h"
#include "tm.h"
#include "toplev.h"
#include "basic-block.h"
#include "gimple.h"
//#include "expr.h" where are you...
#include "diagnostic.h"
#include "rtl.h"
#include "emit-rtl.h"
#include "function.h"

int plugin_is_GPL_compatible;

static int track_frame_size = -1;
static const char track_function[] = "pax_track_stack";
static bool init_locals;

static struct plugin_info stackleak_plugin_info = {
	.version	= "201109112100",
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
		.todo_flags_finish	= TODO_verify_stmts | TODO_dump_func
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

static void stackleak_add_instrumentation(gimple_stmt_iterator *gsi, bool before)
{
	gimple call;
	tree fndecl, type;

	// insert call to void pax_track_stack(void)
	type = build_function_type_list(void_type_node, NULL_TREE);
	fndecl = build_fn_decl(track_function, type);
	DECL_ASSEMBLER_NAME(fndecl); // for LTO
	call = gimple_build_call(fndecl, 0);
	if (before)
		gsi_insert_before(gsi, call, GSI_CONTINUE_LINKING);
	else
		gsi_insert_after(gsi, call, GSI_CONTINUE_LINKING);
}

static unsigned int execute_stackleak_tree_instrument(void)
{
	basic_block bb, entry_bb;
	gimple_stmt_iterator gsi;
	bool prologue_instrumented = false;

	entry_bb = ENTRY_BLOCK_PTR_FOR_FUNCTION(cfun)->next_bb;

	// 1. loop through BBs and GIMPLE statements
	FOR_EACH_BB(bb) {
		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			// gimple match: align 8 built-in BUILT_IN_NORMAL:BUILT_IN_ALLOCA attributes <tree_list 0xb7576450>
			tree fndecl;
			gimple stmt = gsi_stmt(gsi);

			if (!is_gimple_call(stmt))
				continue;
			fndecl = gimple_call_fndecl(stmt);
			if (!fndecl)
				continue;
			if (TREE_CODE(fndecl) != FUNCTION_DECL)
				continue;
			if (!DECL_BUILT_IN(fndecl))
				continue;
			if (DECL_BUILT_IN_CLASS(fndecl) != BUILT_IN_NORMAL)
				continue;
			if (DECL_FUNCTION_CODE(fndecl) != BUILT_IN_ALLOCA)
				continue;

			// 2. insert track call after each __builtin_alloca call
			stackleak_add_instrumentation(&gsi, false);
			if (bb == entry_bb)
				prologue_instrumented = true;
//			print_node(stderr, "pax", fndecl, 4);
		}
	}

	// 3. insert track call at the beginning
	if (!prologue_instrumented) {
		gsi = gsi_start_bb(entry_bb);
		stackleak_add_instrumentation(&gsi, true);
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
		delete_insn_and_edges(insn);
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
		.ref_pass_instance_number	= 0,
		.pos_op 			= PASS_POS_INSERT_AFTER
	};
	struct register_pass_info stackleak_final_pass_info = {
		.pass				= &stackleak_final_rtl_opt_pass.pass,
		.reference_pass_name		= "final",
		.ref_pass_instance_number	= 0,
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

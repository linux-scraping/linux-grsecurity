/*
 * Copyright 2011 by the PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Note: the choice of the license means that the compilation process is
 *       NOT 'eligible' as defined by gcc's library exception to the GPL v3,
 *       but for the kernel it doesn't matter since it doesn't link against
 *       any of the gcc libraries
 *
 * gcc plugin to make KERNEXEC/amd64 almost as good as it is on i386
 *
 * TODO:
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
#include "tree-flow.h"

extern void print_gimple_stmt(FILE *, gimple, int, int);
extern rtx emit_move_insn(rtx x, rtx y);

int plugin_is_GPL_compatible;

static struct plugin_info kernexec_plugin_info = {
	.version	= "201110032145",
};

static unsigned int execute_kernexec_fptr(void);
static unsigned int execute_kernexec_retaddr(void);
static bool kernexec_cmodel_check(void);

static struct gimple_opt_pass kernexec_fptr_pass = {
	.pass = {
		.type			= GIMPLE_PASS,
		.name			= "kernexec_fptr",
		.gate			= kernexec_cmodel_check,
		.execute		= execute_kernexec_fptr,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
		.tv_id			= TV_NONE,
		.properties_required	= 0,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_remove_unused_locals | TODO_update_ssa_no_phi
	}
};

static struct rtl_opt_pass kernexec_retaddr_pass = {
	.pass = {
		.type			= RTL_PASS,
		.name			= "kernexec_retaddr",
		.gate			= kernexec_cmodel_check,
		.execute		= execute_kernexec_retaddr,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
		.tv_id			= TV_NONE,
		.properties_required	= 0,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= TODO_dump_func | TODO_ggc_collect
	}
};

static bool kernexec_cmodel_check(void)
{
	tree section;

	if (ix86_cmodel != CM_KERNEL)
		return false;

	section = lookup_attribute("__section__", DECL_ATTRIBUTES(current_function_decl));
	if (!section || !TREE_VALUE(section))
		return true;

	section = TREE_VALUE(TREE_VALUE(section));
	if (strncmp(TREE_STRING_POINTER(section), ".vsyscall_", 10))
		return true;

	return false;
}

/*
 * add special KERNEXEC instrumentation: force MSB of fptr to 1, which will produce
 * a non-canonical address from a userland ptr and will just trigger a GPF on dereference
 */
static void kernexec_instrument_fptr(gimple_stmt_iterator gsi)
{
	gimple assign_intptr, assign_new_fptr, call_stmt;
	tree intptr, old_fptr, new_fptr, kernexec_mask;

	call_stmt = gsi_stmt(gsi);
	old_fptr = gimple_call_fn(call_stmt);

	// create temporary unsigned long variable used for bitops and cast fptr to it
	intptr = create_tmp_var(long_unsigned_type_node, NULL);
	add_referenced_var(intptr);
	mark_sym_for_renaming(intptr);
	assign_intptr = gimple_build_assign(intptr, fold_convert(long_unsigned_type_node, old_fptr));
	update_stmt(assign_intptr);
	gsi_insert_before(&gsi, assign_intptr, GSI_SAME_STMT);

	// apply logical or to temporary unsigned long and bitmask
	kernexec_mask = build_int_cstu(long_long_unsigned_type_node, 0x8000000000000000LL);
//	kernexec_mask = build_int_cstu(long_long_unsigned_type_node, 0xffffffff80000000LL);
	assign_intptr = gimple_build_assign(intptr, fold_build2(BIT_IOR_EXPR, long_long_unsigned_type_node, intptr, kernexec_mask));
	update_stmt(assign_intptr);
	gsi_insert_before(&gsi, assign_intptr, GSI_SAME_STMT);

	// cast temporary unsigned long back to a temporary fptr variable
	new_fptr = create_tmp_var(TREE_TYPE(old_fptr), NULL);
	add_referenced_var(new_fptr);
	mark_sym_for_renaming(new_fptr);
	assign_new_fptr = gimple_build_assign(new_fptr, fold_convert(TREE_TYPE(old_fptr), intptr));
	update_stmt(assign_new_fptr);
	gsi_insert_before(&gsi, assign_new_fptr, GSI_SAME_STMT);

	// replace call stmt fn with the new fptr
	gimple_call_set_fn(call_stmt, new_fptr);
	update_stmt(call_stmt);
}

/*
 * find all C level function pointer dereferences and forcibly set the highest bit of the pointer
 */
static unsigned int execute_kernexec_fptr(void)
{
	basic_block bb;
	gimple_stmt_iterator gsi;

	// 1. loop through BBs and GIMPLE statements
	FOR_EACH_BB(bb) {
		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			// gimple match: h_1 = get_fptr (); D.2709_3 = h_1 (x_2(D));
			tree fn;
			gimple call_stmt;

			// is it a call ...
			call_stmt = gsi_stmt(gsi);
			if (!is_gimple_call(call_stmt))
				continue;
			fn = gimple_call_fn(call_stmt);
			if (TREE_CODE(fn) == ADDR_EXPR)
				continue;
			if (TREE_CODE(fn) != SSA_NAME)
				gcc_unreachable();

			// ... through a function pointer
			fn = SSA_NAME_VAR(fn);
			if (TREE_CODE(fn) != VAR_DECL && TREE_CODE(fn) != PARM_DECL)
				continue;
			fn = TREE_TYPE(fn);
			if (TREE_CODE(fn) != POINTER_TYPE)
				continue;
			fn = TREE_TYPE(fn);
			if (TREE_CODE(fn) != FUNCTION_TYPE)
				continue;

			kernexec_instrument_fptr(gsi);

//debug_tree(gimple_call_fn(call_stmt));
//print_gimple_stmt(stderr, call_stmt, 0, TDF_LINENO);
		}
	}

	return 0;
}

// add special KERNEXEC instrumentation: btsq $63,(%rsp) just before retn
static void kernexec_instrument_retaddr(rtx insn)
{
	rtx btsq;
	rtvec argvec, constraintvec, labelvec;
	int line;

	// create asm volatile("btsq $63,(%%rsp)":::)
	argvec = rtvec_alloc(0);
	constraintvec = rtvec_alloc(0);
	labelvec = rtvec_alloc(0);
	line = expand_location(RTL_LOCATION(insn)).line;
	btsq = gen_rtx_ASM_OPERANDS(VOIDmode, "btsq $63,(%%rsp)", empty_string, 0, argvec, constraintvec, labelvec, line);
	MEM_VOLATILE_P(btsq) = 1;
	RTX_FRAME_RELATED_P(btsq) = 1;
	emit_insn_before(btsq, insn);
}

/*
 * find all asm level function returns and forcibly set the highest bit of the return address
 */
static unsigned int execute_kernexec_retaddr(void)
{
	rtx insn;

	// 1. find function returns
	for (insn = get_insns(); insn; insn = NEXT_INSN(insn)) {
		// rtl match: (jump_insn 41 40 42 2 (return) fptr.c:42 634 {return_internal} (nil))
		//            (jump_insn 12 9 11 2 (parallel [ (return) (unspec [ (0) ] UNSPEC_REP) ]) fptr.c:46 635 {return_internal_long} (nil))
		rtx body;

		// is it a retn
		if (!JUMP_P(insn))
			continue;
		body = PATTERN(insn);
		if (GET_CODE(body) == PARALLEL)
			body = XVECEXP(body, 0, 0);
		if (GET_CODE(body) != RETURN)
			continue;
		kernexec_instrument_retaddr(insn);
	}

//	print_simple_rtl(stderr, get_insns());
//	print_rtl(stderr, get_insns());

	return 0;
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	int i;
	struct register_pass_info kernexec_fptr_pass_info = {
		.pass				= &kernexec_fptr_pass.pass,
		.reference_pass_name		= "ssa",
		.ref_pass_instance_number	= 0,
		.pos_op 			= PASS_POS_INSERT_AFTER
	};
	struct register_pass_info kernexec_retaddr_pass_info = {
		.pass				= &kernexec_retaddr_pass.pass,
		.reference_pass_name		= "pro_and_epilogue",
		.ref_pass_instance_number	= 0,
		.pos_op 			= PASS_POS_INSERT_AFTER
	};

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &kernexec_plugin_info);

	for (i = 0; i < argc; ++i)
		error(G_("unkown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);

	if (TARGET_64BIT == 0)
		return 0;

	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &kernexec_fptr_pass_info);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &kernexec_retaddr_pass_info);

	return 0;
}

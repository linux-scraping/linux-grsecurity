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

static unsigned int dump_functions(void)
{
	struct cgraph_node *node;

	FOR_EACH_FUNCTION_WITH_GIMPLE_BODY(node) {
		basic_block bb;

		push_cfun(DECL_STRUCT_FUNCTION(NODE_DECL(node)));
		current_function_decl = NODE_DECL(node);

		fprintf(stderr, "-----------------------------------------\n%s\n-----------------------------------------\n", DECL_NAME_POINTER(current_function_decl));

		FOR_ALL_BB_FN(bb, cfun) {
			gimple_stmt_iterator si;

			fprintf(stderr, "<bb %u>:\n", bb->index);
			for (si = gsi_start_phis(bb); !gsi_end_p(si); gsi_next(&si))
				debug_gimple_stmt(gsi_stmt(si));
			for (si = gsi_start_bb(bb); !gsi_end_p(si); gsi_next(&si))
				debug_gimple_stmt(gsi_stmt(si));
			fprintf(stderr, "\n");
		}

		fprintf(stderr, "-------------------------------------------------------------------------\n");

		pop_cfun();
		current_function_decl = NULL_TREE;
	}

	fprintf(stderr, "###############################################################################\n");

	return 0;
}

#if BUILDING_GCC_VERSION >= 4009
static const struct pass_data dump_pass_data = {
#else
static struct ipa_opt_pass_d dump_pass = {
	.pass = {
#endif
		.type			= SIMPLE_IPA_PASS,
		.name			= "dump",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 4009
		.has_gate		= false,
		.has_execute		= true,
#else
		.gate			= NULL,
		.execute		= dump_functions,
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
class dump_pass : public ipa_opt_pass_d {
public:
	dump_pass() : ipa_opt_pass_d(dump_pass_data, g, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL) {}
	unsigned int execute() { return dump_functions(); }
};
}
#endif

struct opt_pass *make_dump_pass(void)
{
#if BUILDING_GCC_VERSION >= 4009
	return new dump_pass();
#else
	return &dump_pass.pass;
#endif
}

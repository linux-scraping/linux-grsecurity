#ifndef GCC_COMMON_H_INCLUDED
#define GCC_COMMON_H_INCLUDED

#include "plugin.h"
#include "bversion.h"
#include "plugin-version.h"
#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tm.h"
#include "line-map.h"
#include "input.h"
#include "tree.h"

#include "tree-inline.h"
#include "version.h"
#include "rtl.h"
#include "tm_p.h"
#include "flags.h"
//#include "insn-attr.h"
//#include "insn-config.h"
//#include "insn-flags.h"
#include "hard-reg-set.h"
//#include "recog.h"
#include "output.h"
#include "except.h"
#include "function.h"
#include "toplev.h"
//#include "expr.h"
#include "basic-block.h"
#include "intl.h"
#include "ggc.h"
//#include "regs.h"
#include "timevar.h"

#include "params.h"

#if BUILDING_GCC_VERSION <= 4009
#include "pointer-set.h"
#else
#include "hash-map.h"
#endif

#include "emit-rtl.h"
//#include "reload.h"
//#include "ira.h"
//#include "dwarf2asm.h"
#include "debug.h"
#include "target.h"
#include "langhooks.h"
#include "cfgloop.h"
//#include "hosthooks.h"
#include "cgraph.h"
#include "opts.h"
//#include "coverage.h"
//#include "value-prof.h"

#if BUILDING_GCC_VERSION == 4005
#include <sys/mman.h>
#endif

#if BUILDING_GCC_VERSION >= 4007
#include "tree-pretty-print.h"
#include "gimple-pretty-print.h"
#endif

#if BUILDING_GCC_VERSION >= 4006
//#include "c-tree.h"
//#include "cp/cp-tree.h"
#include "c-family/c-common.h"
#else
#include "c-common.h"
#endif

#if BUILDING_GCC_VERSION <= 4008
#include "tree-flow.h"
#else
#include "tree-cfgcleanup.h"
#endif

#include "diagnostic.h"
//#include "tree-diagnostic.h"
#include "tree-dump.h"
#include "tree-pass.h"
//#include "df.h"
#include "predict.h"
#include "ipa-utils.h"

#if BUILDING_GCC_VERSION >= 4009
#include "varasm.h"
#include "stor-layout.h"
#include "internal-fn.h"
#include "gimple-expr.h"
#include "gimple-fold.h"
//#include "diagnostic-color.h"
#include "context.h"
#include "tree-ssa-alias.h"
#include "stringpool.h"
#include "tree-ssanames.h"
#include "print-tree.h"
#include "tree-eh.h"
#include "stmt.h"
#endif

#include "gimple.h"

#if BUILDING_GCC_VERSION >= 4009
#include "tree-ssa-operands.h"
#include "tree-phinodes.h"
#include "tree-cfg.h"
#include "gimple-iterator.h"
#include "gimple-ssa.h"
#include "ssa-iterators.h"
#endif

//#include "lto/lto.h"
#if BUILDING_GCC_VERSION >= 4007
//#include "data-streamer.h"
#else
//#include "lto-streamer.h"
#endif
//#include "lto-compress.h"

//#include "expr.h" where are you...
extern rtx emit_move_insn(rtx x, rtx y);

// missing from basic_block.h...
extern void debug_dominance_info(enum cdi_direction dir);
extern void debug_dominance_tree(enum cdi_direction dir, basic_block root);

#ifdef __cplusplus
static inline void debug_tree(const_tree t)
{
	debug_tree(CONST_CAST_TREE(t));
}
#else
#define debug_tree(t) debug_tree(CONST_CAST_TREE(t))
#endif

#define __unused __attribute__((__unused__))

#define DECL_NAME_POINTER(node) IDENTIFIER_POINTER(DECL_NAME(node))
#define DECL_NAME_LENGTH(node) IDENTIFIER_LENGTH(DECL_NAME(node))
#define TYPE_NAME_POINTER(node) IDENTIFIER_POINTER(TYPE_NAME(node))
#define TYPE_NAME_LENGTH(node) IDENTIFIER_LENGTH(TYPE_NAME(node))

// should come from c-tree.h if only it were installed for gcc 4.5...
#define C_TYPE_FIELDS_READONLY(TYPE) TREE_LANG_FLAG_1(TYPE)

#if BUILDING_GCC_VERSION == 4005
#define FOR_EACH_VEC_ELT_REVERSE(T,V,I,P) for (I = VEC_length(T, (V)) - 1; VEC_iterate(T, (V), (I), (P)); (I)--)
#define FOR_EACH_LOCAL_DECL(FUN, I, D) FOR_EACH_VEC_ELT_REVERSE(tree, (FUN)->local_decls, I, D)
#define DECL_CHAIN(NODE) (TREE_CHAIN(DECL_MINIMAL_CHECK(NODE)))
#define FOR_EACH_VEC_ELT(T, V, I, P) for (I = 0; VEC_iterate(T, (V), (I), (P)); ++(I))
#define TODO_rebuild_cgraph_edges 0

#ifndef O_BINARY
#define O_BINARY 0
#endif

static inline bool gimple_call_builtin_p(gimple stmt, enum built_in_function code)
{
	tree fndecl;

	if (!is_gimple_call(stmt))
		return false;
	fndecl = gimple_call_fndecl(stmt);
	if (!fndecl || DECL_BUILT_IN_CLASS(fndecl) != BUILT_IN_NORMAL)
		return false;
//	print_node(stderr, "pax", fndecl, 4);
	return DECL_FUNCTION_CODE(fndecl) == code;
}

static inline bool is_simple_builtin(tree decl)
{
	if (decl && DECL_BUILT_IN_CLASS(decl) != BUILT_IN_NORMAL)
		return false;

	switch (DECL_FUNCTION_CODE(decl)) {
	/* Builtins that expand to constants. */
	case BUILT_IN_CONSTANT_P:
	case BUILT_IN_EXPECT:
	case BUILT_IN_OBJECT_SIZE:
	case BUILT_IN_UNREACHABLE:
	/* Simple register moves or loads from stack. */
	case BUILT_IN_RETURN_ADDRESS:
	case BUILT_IN_EXTRACT_RETURN_ADDR:
	case BUILT_IN_FROB_RETURN_ADDR:
	case BUILT_IN_RETURN:
	case BUILT_IN_AGGREGATE_INCOMING_ADDRESS:
	case BUILT_IN_FRAME_ADDRESS:
	case BUILT_IN_VA_END:
	case BUILT_IN_STACK_SAVE:
	case BUILT_IN_STACK_RESTORE:
	/* Exception state returns or moves registers around. */
	case BUILT_IN_EH_FILTER:
	case BUILT_IN_EH_POINTER:
	case BUILT_IN_EH_COPY_VALUES:
	return true;

	default:
	return false;
	}
}
#endif

#if BUILDING_GCC_VERSION <= 4006
#define ANY_RETURN_P(rtx) (GET_CODE(rtx) == RETURN)
#define C_DECL_REGISTER(EXP) DECL_LANG_FLAG_4(EXP)
#define EDGE_PRESERVE 0ULL
#define HOST_WIDE_INT_PRINT_HEX_PURE "%" HOST_WIDE_INT_PRINT "x"
#define flag_fat_lto_objects true

#define get_random_seed(noinit) ({						\
	unsigned HOST_WIDE_INT seed;						\
	sscanf(get_random_seed(noinit), "%" HOST_WIDE_INT_PRINT "x", &seed);	\
	seed * seed; })

#define int_const_binop(code, arg1, arg2) int_const_binop((code), (arg1), (arg2), 0)

static inline bool gimple_clobber_p(gimple s __unused)
{
	return false;
}

static inline bool gimple_asm_clobbers_memory_p(const_gimple stmt)
{
	unsigned i;

	for (i = 0; i < gimple_asm_nclobbers(stmt); i++) {
		tree op = gimple_asm_clobber_op(stmt, i);
		if (!strcmp(TREE_STRING_POINTER(TREE_VALUE(op)), "memory"))
			return true;
	}

	return false;
}

static inline tree builtin_decl_implicit(enum built_in_function fncode)
{
	return implicit_built_in_decls[fncode];
}

static inline int ipa_reverse_postorder(struct cgraph_node **order)
{
	return cgraph_postorder(order);
}

static inline struct cgraph_node *cgraph_get_create_node(tree decl)
{
	struct cgraph_node *node = cgraph_get_node(decl);

	return node ? node : cgraph_node(decl);
}

static inline bool cgraph_function_with_gimple_body_p(struct cgraph_node *node)
{
	return node->analyzed && !node->thunk.thunk_p && !node->alias;
}

static inline struct cgraph_node *cgraph_first_function_with_gimple_body(void)
{
	struct cgraph_node *node;

	for (node = cgraph_nodes; node; node = node->next)
		if (cgraph_function_with_gimple_body_p(node))
			return node;
	return NULL;
}

static inline struct cgraph_node *cgraph_next_function_with_gimple_body(struct cgraph_node *node)
{
	for (node = node->next; node; node = node->next)
		if (cgraph_function_with_gimple_body_p(node))
			return node;
	return NULL;
}

#define FOR_EACH_FUNCTION_WITH_GIMPLE_BODY(node) \
	for ((node) = cgraph_first_function_with_gimple_body(); (node); \
		(node) = cgraph_next_function_with_gimple_body(node))
#endif

#if BUILDING_GCC_VERSION == 4006
extern void debug_gimple_stmt(gimple);
extern void debug_gimple_seq(gimple_seq);
extern void print_gimple_seq(FILE *, gimple_seq, int, int);
extern void print_gimple_stmt(FILE *, gimple, int, int);
extern void print_gimple_expr(FILE *, gimple, int, int);
extern void dump_gimple_stmt(pretty_printer *, gimple, int, int);
#endif

#if BUILDING_GCC_VERSION <= 4007
#define FOR_EACH_FUNCTION(node) for (node = cgraph_nodes; node; node = node->next)
#define FOR_EACH_VARIABLE(node) for (node = varpool_nodes; node; node = node->next)
#define PROP_loops 0
#define NODE_SYMBOL(node) (node)
#define NODE_DECL(node) (node)->decl

static inline int bb_loop_depth(const_basic_block bb)
{
	return bb->loop_father ? loop_depth(bb->loop_father) : 0;
}

static inline bool gimple_store_p(gimple gs)
{
	tree lhs = gimple_get_lhs(gs);
	return lhs && !is_gimple_reg(lhs);
}
#endif

#if BUILDING_GCC_VERSION >= 4007
#define cgraph_create_edge(caller, callee, call_stmt, count, freq, nest) \
	cgraph_create_edge((caller), (callee), (call_stmt), (count), (freq))
#define cgraph_create_edge_including_clones(caller, callee, old_call_stmt, call_stmt, count, freq, nest, reason) \
	cgraph_create_edge_including_clones((caller), (callee), (old_call_stmt), (call_stmt), (count), (freq), (reason))
#endif

#if BUILDING_GCC_VERSION <= 4008
#define ENTRY_BLOCK_PTR_FOR_FN(FN)	ENTRY_BLOCK_PTR_FOR_FUNCTION(FN)
#define EXIT_BLOCK_PTR_FOR_FN(FN)	EXIT_BLOCK_PTR_FOR_FUNCTION(FN)
#define basic_block_info_for_fn(FN)	((FN)->cfg->x_basic_block_info)
#define n_basic_blocks_for_fn(FN)	((FN)->cfg->x_n_basic_blocks)
#define n_edges_for_fn(FN)		((FN)->cfg->x_n_edges)
#define last_basic_block_for_fn(FN)	((FN)->cfg->x_last_basic_block)
#define label_to_block_map_for_fn(FN)	((FN)->cfg->x_label_to_block_map)
#define profile_status_for_fn(FN)	((FN)->cfg->x_profile_status)
#define BASIC_BLOCK_FOR_FN(FN, N)	BASIC_BLOCK_FOR_FUNCTION((FN), (N))
#define NODE_IMPLICIT_ALIAS(node)	(node)->same_body_alias

static inline const char *get_tree_code_name(enum tree_code code)
{
	gcc_assert(code < MAX_TREE_CODES);
	return tree_code_name[code];
}

#define ipa_remove_stmt_references(cnode, stmt)
#endif

#if BUILDING_GCC_VERSION == 4008
#define NODE_SYMBOL(node) (&(node)->symbol)
#define NODE_DECL(node) (node)->symbol.decl
#endif

#if BUILDING_GCC_VERSION >= 4008
#define add_referenced_var(var)
#define mark_sym_for_renaming(var)
#define varpool_mark_needed_node(node)
#define TODO_dump_func 0
#define TODO_dump_cgraph 0
#endif

#if BUILDING_GCC_VERSION <= 4009
#define TODO_verify_il 0
#endif

#if BUILDING_GCC_VERSION >= 4009
#define TODO_ggc_collect 0
#define NODE_SYMBOL(node) (node)
#define NODE_DECL(node) (node)->decl
#define cgraph_node_name(node) (node)->name()
#define NODE_IMPLICIT_ALIAS(node) (node)->cpp_implicit_alias
#endif

#if BUILDING_GCC_VERSION >= 5000
#define TODO_verify_ssa TODO_verify_il
#define TODO_verify_flow TODO_verify_il
#define TODO_verify_stmts TODO_verify_il
#define TODO_verify_rtl_sharing TODO_verify_il

#define debug_cgraph_node(node) (node)->debug()
#define cgraph_get_node(decl) cgraph_node::get(decl)
#endif

#endif

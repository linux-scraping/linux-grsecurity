/*
 * Copyright 2012 by PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Note: the choice of the license means that the compilation process is
 *       NOT 'eligible' as defined by gcc's library exception to the GPL v3,
 *       but for the kernel it doesn't matter since it doesn't link against
 *       any of the gcc libraries
 *
 * gcc plugin to colorize diagnostic output
 *
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
#include "diagnostic.h"
#include "plugin-version.h"
#include "tm.h"

int plugin_is_GPL_compatible;

static struct plugin_info colorize_plugin_info = {
	.version	= "201203092200",
	.help		= NULL,
};

#define GREEN		"\033[32m\033[2m"
#define LIGHTGREEN	"\033[32m\033[1m"
#define YELLOW		"\033[33m\033[2m"
#define LIGHTYELLOW	"\033[33m\033[1m"
#define RED		"\033[31m\033[2m"
#define LIGHTRED	"\033[31m\033[1m"
#define BLUE		"\033[34m\033[2m"
#define LIGHTBLUE	"\033[34m\033[1m"
#define BRIGHT		"\033[m\033[1m"
#define NORMAL		"\033[m"

static diagnostic_starter_fn old_starter;
static diagnostic_finalizer_fn old_finalizer;

static void start_colorize(diagnostic_context *context, diagnostic_info *diagnostic)
{
	const char *color;
	char *newprefix;

	switch (diagnostic->kind) {
	case DK_NOTE:
		color = LIGHTBLUE;
		break;

	case DK_PEDWARN:
	case DK_WARNING:
		color = LIGHTYELLOW;
		break;

	case DK_ERROR:
	case DK_FATAL:
	case DK_ICE:
	case DK_PERMERROR:
	case DK_SORRY:
		color = LIGHTRED;
		break;

	default:
		color = NORMAL;
	}

	old_starter(context, diagnostic);
	if (-1 == asprintf(&newprefix, "%s%s" NORMAL, color, context->printer->prefix))
		return;
	pp_destroy_prefix(context->printer);
	pp_set_prefix(context->printer, newprefix);
}

static void finalize_colorize(diagnostic_context *context, diagnostic_info *diagnostic)
{
	old_finalizer(context, diagnostic);
}

static void colorize_arm(void)
{
	old_starter = diagnostic_starter(global_dc);
	old_finalizer = diagnostic_finalizer(global_dc);

	diagnostic_starter(global_dc) = start_colorize;
	diagnostic_finalizer(global_dc) = finalize_colorize;
}

static unsigned int execute_colorize_rearm(void)
{
	if (diagnostic_starter(global_dc) == start_colorize)
		return 0;

	colorize_arm();
	return 0;
}

struct simple_ipa_opt_pass pass_ipa_colorize_rearm = {
	.pass = {
		.type			= SIMPLE_IPA_PASS,
		.name			= "colorize_rearm",
		.gate			= NULL,
		.execute		= execute_colorize_rearm,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
		.tv_id			= TV_NONE,
		.properties_required	= 0,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= 0
	}
};

static void colorize_start_unit(void *gcc_data, void *user_data)
{
	colorize_arm();
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	struct register_pass_info colorize_rearm_pass_info = {
		.pass				= &pass_ipa_colorize_rearm.pass,
		.reference_pass_name		= "*free_lang_data",
		.ref_pass_instance_number	= 1,
		.pos_op 			= PASS_POS_INSERT_AFTER
	};

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &colorize_plugin_info);
	register_callback(plugin_name, PLUGIN_START_UNIT, &colorize_start_unit, NULL);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &colorize_rearm_pass_info);
	return 0;
}

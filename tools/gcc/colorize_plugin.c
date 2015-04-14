/*
 * Copyright 2012-2014 by PaX Team <pageexec@freemail.hu>
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

#include "gcc-common.h"

int plugin_is_GPL_compatible;

static struct plugin_info colorize_plugin_info = {
	.version	= "201404202350",
	.help		= "color=[never|always|auto]\tdetermine when to colorize\n",
};

#define GREEN		"\033[32m\033[K"
#define LIGHTGREEN	"\033[1;32m\033[K"
#define YELLOW		"\033[33m\033[K"
#define LIGHTYELLOW	"\033[1;33m\033[K"
#define RED		"\033[31m\033[K"
#define LIGHTRED	"\033[1;31m\033[K"
#define BLUE		"\033[34m\033[K"
#define LIGHTBLUE	"\033[1;34m\033[K"
#define BRIGHT		"\033[1;m\033[K"
#define NORMAL		"\033[m\033[K"

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

#if BUILDING_GCC_VERSION >= 4009
static const struct pass_data colorize_rearm_pass_data = {
#else
struct simple_ipa_opt_pass colorize_rearm_pass = {
	.pass = {
#endif
		.type			= SIMPLE_IPA_PASS,
		.name			= "colorize_rearm",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 5000
#elif BUILDING_GCC_VERSION == 4009
		.has_gate		= false,
		.has_execute		= true,
#else
		.gate			= NULL,
		.execute		= execute_colorize_rearm,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
#endif
		.tv_id			= TV_NONE,
		.properties_required	= 0,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= 0
#if BUILDING_GCC_VERSION < 4009
	}
#endif
};

#if BUILDING_GCC_VERSION >= 4009
namespace {
class colorize_rearm_pass : public simple_ipa_opt_pass {
public:
	colorize_rearm_pass() : simple_ipa_opt_pass(colorize_rearm_pass_data, g) {}
#if BUILDING_GCC_VERSION >= 5000
	virtual unsigned int execute(function *) { return execute_colorize_rearm(); }
#else
	unsigned int execute() { return execute_colorize_rearm(); }
#endif
};
}

static opt_pass *make_colorize_rearm_pass(void)
{
	return new colorize_rearm_pass();
}
#else
static struct opt_pass *make_colorize_rearm_pass(void)
{
	return &colorize_rearm_pass.pass;
}
#endif

static void colorize_start_unit(void *gcc_data, void *user_data)
{
	colorize_arm();
}

static bool should_colorize(void)
{
#if BUILDING_GCC_VERSION >= 4009
	return false;
#else
	char const *t = getenv("TERM");

	return t && strcmp(t, "dumb") && isatty(STDERR_FILENO);
#endif
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	int i;
	struct register_pass_info colorize_rearm_pass_info;
	bool colorize;

	colorize_rearm_pass_info.pass				= make_colorize_rearm_pass();
	colorize_rearm_pass_info.reference_pass_name		= "*free_lang_data";
	colorize_rearm_pass_info.ref_pass_instance_number	= 1;
	colorize_rearm_pass_info.pos_op 			= PASS_POS_INSERT_AFTER;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &colorize_plugin_info);

	colorize = getenv("GCC_COLORS") ? should_colorize() : false;

	for (i = 0; i < argc; ++i) {
		if (!strcmp(argv[i].key, "color")) {
			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}
			if (!strcmp(argv[i].value, "always"))
				colorize = true;
			else if (!strcmp(argv[i].value, "never"))
				colorize = false;
			else if (!strcmp(argv[i].value, "auto"))
				colorize = should_colorize();
			else
				error(G_("invalid option argument '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, argv[i].value);
			continue;
		}
		error(G_("unkown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	if (colorize) {
		// TODO: parse GCC_COLORS as used by gcc 4.9+
		register_callback(plugin_name, PLUGIN_START_UNIT, &colorize_start_unit, NULL);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &colorize_rearm_pass_info);
	}
	return 0;
}

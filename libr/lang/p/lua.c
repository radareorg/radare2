/* lua extension for libr (radare2) */

#include "r_lib.h"
#include "r_lang.h"

static int lua_run(void *user, const char *code, int len)
{
	printf("Evaluating '%s'\n", code);
	return R_TRUE;
}

static struct r_lang_handle_t r_lang_plugin_lua = {
	.name = "lua",
	.desc = "LUA language extension",
	.help = NULL,
	.run = &lua_run,
	.run_file = NULL,
	.set_argv = NULL,
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_lua,
};

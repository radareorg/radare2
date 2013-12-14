/* tcc extension for libr (radare2) - copyright pancake 2011-2013 */

#include "r_lib.h"
#include "r_lang.h"
#include <libtcc.h>

/* TODO: store the state globally or so.. */
static int r_lang_tcc_run(struct r_lang_t *lang, const char *code, int len) {
	TCCState *ts = tcc_new ();
	/* TODO: set defined vars as global */
	//list_for_each(lang->defs) {
	tcc_compile_string (ts, code);
	tcc_run (ts, 0, 0);//argc, argv);
	tcc_delete (ts);
	return R_TRUE;
}

static struct r_lang_plugin_t r_lang_plugin_tcc = {
	.name = "c99",
	.ext = "c",
	.desc = "C99 language extension (using libtcc)",
	.help = NULL,
	.run = &r_lang_tcc_run,
	.run_file = NULL,
	.set_argv = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_tcc,
};
#endif

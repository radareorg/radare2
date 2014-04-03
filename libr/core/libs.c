/* radare - LGPL - Copyright 2009-2014 - pancake */

#include "r_core.h"

#define CB(x,y) \
static int __lib_##x##_cb(RLibPlugin *pl, void *user, void *data) { \
	struct r_##x##_plugin_t *hand = (struct r_##x##_plugin_t *)data; \
	RCore *core = (RCore *)user; \
	r_##x##_add (core->y, hand); \
	return R_TRUE; \
}\
static int __lib_##x##_dt(RLibPlugin *pl, void *p, void *u) { return R_TRUE; }

// XXX api consistency issues
#define r_io_add r_io_plugin_add
CB (io, io)
#define r_core_add r_core_plugin_add
CB (core, rcmd)
#define r_debug_add r_debug_plugin_add
CB (debug, dbg)
#define r_bp_add r_bp_plugin_add
CB (bp, dbg->bp)
CB (lang, lang)
CB (anal, anal)
CB (asm, assembler)
CB (parse, parser)
CB (bin, bin)
CB (egg, egg)

R_API void r_core_loadlibs_init(RCore *core) {
#define DF(x,y,z) r_lib_add_handler(core->lib, R_LIB_TYPE_##x,y,&__lib_##z##_cb, &__lib_##z##_dt, core);
	core->lib = r_lib_new ("radare_plugin");
	DF (IO, "io plugins", io);
	DF (CORE, "core plugins", core);
	DF (DBG, "debugger plugins", debug);
	DF (BP, "debugger breakpoint plugins", bp);
	DF (LANG, "language plugins", lang);
	DF (ANAL, "analysis plugins", anal);
	DF (ASM, "(dis)assembler plugins", asm);
	DF (PARSE, "parsing plugins", parse);
	DF (BIN, "bin plugins", bin);
	DF (EGG, "egg plugins", egg);
}

R_API int r_core_loadlibs(RCore *core, int where, const char *path) {
	/* TODO: all those default plugin paths should be defined in r_lib */
	if (!where) where = -1;
	if (path) r_lib_opendir (core->lib, path);
	if (where & R_CORE_LOADLIBS_CONFIG)
		r_lib_opendir (core->lib, r_config_get (core->config, "dir.plugins"));
	if (where & R_CORE_LOADLIBS_ENV)
		r_lib_opendir (core->lib, getenv (R_LIB_ENV));
	if (where & R_CORE_LOADLIBS_HOME) {
		char *homeplugindir = r_str_home (R2_HOMEDIR"/plugins");
		r_lib_opendir (core->lib, homeplugindir);
		free (homeplugindir);
	}
	if (where & R_CORE_LOADLIBS_SYSTEM)
		r_lib_opendir (core->lib, R2_LIBDIR"/radare2/"R2_VERSION);
	return R_TRUE;
}

/* radare - LGPL - Copyright 2009-2017 - pancake */

#include "r_core.h"
#include "config.h"

#define CB(x, y)\
	static int __lib_ ## x ## _cb (RLibPlugin * pl, void *user, void *data) {\
		struct r_ ## x ## _plugin_t *hand = (struct r_ ## x ## _plugin_t *)data;\
		RCore *core = (RCore *) user;\
		r_ ## x ## _add (core->y, hand);\
		return true;\
	}\
	static int __lib_ ## x ## _dt (RLibPlugin * pl, void *p, void *u) { return true; }

#define CB_COPY(x, y)\
	static int __lib_ ## x ## _cb (RLibPlugin * pl, void *user, void *data) {\
		struct r_ ## x ## _plugin_t *hand = (struct r_ ## x ## _plugin_t *)data;\
		struct r_ ## x ## _plugin_t *instance;\
		RCore *core = (RCore *) user;\
		instance = R_NEW (struct r_ ## x ## _plugin_t);\
		memcpy (instance, hand, sizeof (struct r_ ## x ## _plugin_t));\
		r_ ## x ## _add (core->y, instance);\
		return true;\
	}\
	static int __lib_ ## x ## _dt (RLibPlugin * pl, void *p, void *u) { return true; }

// XXX api consistency issues
#define r_io_add r_io_plugin_add
CB_COPY (io, io)
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
CB (fs, fs)

R_API void r_core_loadlibs_init(RCore *core) {
	ut64 prev = r_sys_now ();
#define DF(x, y, z) r_lib_add_handler (core->lib, R_LIB_TYPE_ ## x, y, &__lib_ ## z ## _cb, &__lib_ ## z ## _dt, core);
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
	DF (FS, "fs plugins", fs);
	core->times->loadlibs_init_time = r_sys_now () - prev;
}

R_API int r_core_loadlibs(RCore *core, int where, const char *path) {
	char *p = NULL;
	ut64 prev = r_sys_now ();
#if R2_LOADLIBS
	/* TODO: all those default plugin paths should be defined in r_lib */
	if (!r_config_get_i (core->config, "cfg.plugins")) {
		core->times->loadlibs_time = 0;
		return false;
	}
	if (!where) {
		where = -1;
	}
	if (path) {
		r_lib_opendir (core->lib, path);
	}
	if (where & R_CORE_LOADLIBS_CONFIG) {
		r_lib_opendir (core->lib, r_config_get (core->config, "dir.plugins"));
	}
	if (where & R_CORE_LOADLIBS_ENV) {
		p = r_sys_getenv (R_LIB_ENV);
		if (p && *p) {
			r_lib_opendir (core->lib, p);
		}
		free (p);
	}
	if (where & R_CORE_LOADLIBS_HOME) {
		char *homeplugindir = r_str_home (R2_HOMEDIR "/plugins");
		// eprintf ("OPENDIR (%s)\n", homeplugindir);
		r_lib_opendir (core->lib, homeplugindir);
		free (homeplugindir);
	}
	if (where & R_CORE_LOADLIBS_SYSTEM) {
#if __WINDOWS__
		r_lib_opendir (core->lib, "plugins");
		r_lib_opendir (core->lib, "share/radare2/"R2_VERSION "/plugins");
#else
		r_lib_opendir (core->lib, R2_LIBDIR "/radare2/"R2_VERSION);
		r_lib_opendir (core->lib, R2_LIBDIR "/radare2-extras/"R2_VERSION);
		r_lib_opendir (core->lib, R2_LIBDIR "/radare2-bindings/"R2_VERSION);
#endif
	}
#endif
	// load script plugins
	char *homeplugindir = r_str_home (R2_HOMEDIR "/plugins");
        RList *files = r_sys_dir (homeplugindir);
	RListIter *iter;
	char *file;
	r_list_foreach (files, iter, file) {
		bool isScript = r_str_endswith (file, ".py") || r_str_endswith (file, ".js") || r_str_endswith (file, ".lua");
		if (isScript) {
			// eprintf ("-> %s\n", file);
			r_core_cmdf (core, ". %s/%s", homeplugindir, file);
		}
	}
	
	free (homeplugindir);
	core->times->loadlibs_time = r_sys_now () - prev;
	r_list_free (files);
	return true;
}

/* radare2 - LGPL - Copyright 2009-2023 - pancake */

#include "r_core.h"
#include "config.h"

#define CB(x, y)\
	static int __lib_ ## x ## _cb (RLibPlugin * pl, void *user, void *data) {\
		struct r_ ## x ## _plugin_t *hand = (struct r_ ## x ## _plugin_t *)data;\
		RCore *core = (RCore *) user;\
		pl->free = NULL; \
		r_ ## x ## _plugin_add (core->y, hand);\
		return true;\
	}\
	static int __lib_ ## x ## _dt (RLibPlugin * pl, void *user, void *data) { \
		struct r_ ## x ## _plugin_t *hand = (struct r_ ## x ## _plugin_t *)data; \
		RCore *core = (RCore *) user; \
		return r_ ## x ## _plugin_remove (core->y, hand); \
	}

// TODO: deprecate this
#define CB_COPY(x, y)\
	static int __lib_ ## x ## _cb (RLibPlugin * pl, void *user, void *data) {\
		struct r_ ## x ## _plugin_t *hand = (struct r_ ## x ## _plugin_t *)data;\
		struct r_ ## x ## _plugin_t *instance;\
		RCore *core = (RCore *) user;\
		instance = R_NEW (struct r_ ## x ## _plugin_t);\
		memcpy (instance, hand, sizeof (struct r_ ## x ## _plugin_t));\
		r_ ## x ## _plugin_add (core->y, instance);\
		return true;\
	}\
	static int __lib_ ## x ## _dt (RLibPlugin *pl, void *user, void *data) { \
		struct r_ ## x ## _plugin_t *hand = (struct r_ ## x ## _plugin_t *)data; \
		RCore *core = (RCore *) user; \
		return r_ ## x ## _plugin_remove (core->y, hand); \
	}

CB_COPY (io, io)
CB (core, rcmd)
CB (debug, dbg)
CB (bp, dbg->bp)
CB (lang, lang)
CB (anal, anal)
CB (esil, anal->esil)
CB (parse, parser)
CB (bin, bin)
CB (egg, egg)
CB (fs, fs)
CB (arch, anal->arch);

static void __openPluginsAt(RCore *core, const char *arg, const char *user_path) {
	if (arg && *arg) {
		if (user_path) {
			if (r_str_endswith (user_path, arg)) {
				return;
			}
		}
		char *pdir = r_str_r2_prefix (arg);
		if (pdir) {
			r_lib_opendir (core->lib, pdir);
			free (pdir);
		}
	}
}

static void __loadSystemPlugins(RCore *core, int where, const char *path) {
#if R2_LOADLIBS
	if (!where) {
		where = -1;
	}
	if (path) {
		r_lib_opendir (core->lib, path);
	}
	const char *dir_plugins = r_config_get (core->config, "dir.plugins");
	if (where & R_CORE_LOADLIBS_CONFIG) {
		r_lib_opendir (core->lib, dir_plugins);
	}
	if (where & R_CORE_LOADLIBS_ENV) {
		char *p = r_sys_getenv (R_LIB_ENV);
		if (p && *p) {
			r_lib_opendir (core->lib, p);
		}
		free (p);
	}
	if (where & R_CORE_LOADLIBS_HOME) {
		char *hpd = r_xdg_datadir ("plugins");
		if (hpd) {
			r_lib_opendir (core->lib, hpd);
			free (hpd);
		}
	}
	if (where & R_CORE_LOADLIBS_SYSTEM) {
		__openPluginsAt (core, R2_PLUGINS, dir_plugins);
		__openPluginsAt (core, R2_EXTRAS, dir_plugins);
		__openPluginsAt (core, R2_BINDINGS, dir_plugins);
	}
#endif
}

R_API void r_core_loadlibs_init(RCore *core) {
	ut64 prev = r_time_now_mono ();
#define DF(x, y, z) r_lib_add_handler (core->lib, R_LIB_TYPE_ ## x, y, &__lib_ ## z ## _cb, &__lib_ ## z ## _dt, core);
	core->lib = r_lib_new (NULL, NULL);
	DF (IO, "io plugins", io);
	DF (CORE, "core plugins", core);
	DF (DBG, "debugger plugins", debug);
	DF (BP, "debugger breakpoint plugins", bp);
	DF (LANG, "language plugins", lang);
	DF (ANAL, "analysis plugins", anal);
	DF (ESIL, "esil emulation plugins", esil);
	// DF (ASM, "(dis)assembler plugins", asm);
	DF (PARSE, "parsing plugins", parse);
	DF (BIN, "bin plugins", bin);
	DF (EGG, "egg plugins", egg);
	DF (FS, "fs plugins", fs);
	DF (ARCH, "arch plugins", arch);
	core->times->loadlibs_init_time = r_time_now_mono () - prev;
}

static bool __isScriptFilename(const char *name) {
	const char *ext = r_file_extension (name);
	if (ext) {
		if (0
		|| !strcmp (ext, "c")
		|| !strcmp (ext, "go")
		|| !strcmp (ext, "js")
		|| !strcmp (ext, "lua")
		|| !strcmp (ext, "pl")
		|| !strcmp (ext, "py")
		|| !strcmp (ext, "qjs")
		|| !strcmp (ext, "rs")
		|| !strcmp (ext, "v")
		|| !strcmp (ext, "vala")
		|| !strcmp (ext, "wren")) {
			return true;
		}
	}
	return false;
}

R_API bool r_core_loadlibs(RCore *core, int where, const char *path) {
	ut64 prev = r_time_now_mono ();
	__loadSystemPlugins (core, where, path);
	/* TODO: all those default plugin paths should be defined in r_lib */
	if (!r_config_get_b (core->config, "cfg.plugins")) {
		core->times->loadlibs_time = 0;
		return false;
	}
	// load script plugins
	char *homeplugindir = r_xdg_datadir ("plugins");
	RList *files = r_sys_dir (homeplugindir);
	RListIter *iter;
	char *file;
	r_list_foreach (files, iter, file) {
		if (__isScriptFilename (file)) {
			r_core_cmdf (core, "\"\". %s/%s", homeplugindir, file);
		}
	}
	r_list_free (files);
	free (homeplugindir);
	core->times->loadlibs_time = r_time_now_mono () - prev;
	return true;
}

/* radare2 - LGPL - Copyright 2009-2025 - pancake */

#include <r_core.h>
#include "config.h"

#define CB(x, y) \
	static bool __lib_ ## x ## _cb (RLibPlugin *pl, void *user, void *data) { \
		RCore *core = (RCore *)user; \
		RPluginMeta *meta = (RPluginMeta *)data; \
		pl->free = NULL; \
		pl->name = strdup (meta->name); \
		return r_libstore_add (core->y->libstore, data); \
	} \
	static bool __lib_ ## x ## _dt (RLibPlugin *pl, void *user, void *data) { \
		RCore *core = (RCore *)user; \
		free (pl->name); \
		return r_libstore_remove (core->y->libstore, data); \
	}

CB(io, io)
CB(core, rcmd)
CB(debug, dbg)
CB(bp, dbg->bp)
CB(lang, lang)
CB(anal, anal)
CB(esil, anal->esil)
CB(asm, rasm)
CB(bin, bin)
CB(egg, egg)
CB(fs, fs)
CB(arch, anal->arch);

static void core_load_internal_plugins(void *user) {
	RCore *core = (RCore *)user;
	r_libstore_load (core->libstore);
}

static bool core_plugins_load(RLibStore *store) {
	RCore *core = store->user;
	r_libstore_load (core->io->libstore);
	r_libstore_load (core->bin->libstore);
	r_libstore_load (core->anal->libstore);
	r_libstore_load (core->rasm->libstore);
	r_libstore_load (core->anal->arch->libstore);
	r_libstore_load (core->dbg->libstore);
	r_libstore_load (core->dbg->bp->libstore);
	r_libstore_load (core->anal->esil->libstore);
	r_libstore_load (core->egg->libstore);
	r_libstore_load (core->fs->libstore);
	r_libstore_load (core->lang->libstore);
	r_libstore_load (core->rcmd->libstore);
	r_libstore_load (core->muta->libstore);
	return true;
}

#if R2_LOADLIBS
static void load_plugins(RCore *core, int where, const char *path) {
	if (!where) {
		where = -1;
	}
	if (path) {
		r_lib_opendir (core->lib, path);
	}
	const char *dir_plugins = r_config_get (core->config, "dir.plugins");
	r_lib_load_paths (core->lib, (RLibLoadMask)where, dir_plugins);
}
#else
static void load_plugins(RCore *core, int where, const char *path){
	(void)
#warning built without the ability to load plugins dynamically
}
#endif

R_API void r_core_loadlibs_init(RCore *core) {
	R_RETURN_IF_FAIL (core);
	if (core->lib) {
		return;
	}
	ut64 prev = r_time_now_mono ();
#define DF(x, y, z) r_lib_add_handler(core->lib, R_LIB_TYPE_ ## x, y, &__lib_ ## z ## _cb, &__lib_ ## z ## _dt, core);
	core->lib = r_lib_new (NULL, NULL);
	r_libstore_new (&core->libstore, core, NULL, NULL, core_plugins_load, NULL, NULL);
	core->lib->cb_internal = core_load_internal_plugins;
	core->lib->cb_internal_user = core;
	DF (IO, "io plugins", io);
	DF (CORE, "core plugins", core);
	DF (DBG, "debugger plugins", debug);
	DF (BP, "debugger breakpoint plugins", bp);
	DF (LANG, "language plugins", lang);
	DF (ANAL, "analysis plugins", anal);
	DF (ESIL, "esil emulation plugins", esil);
	DF (ASM, "assembly plugins", asm);
	// DF (PARSE, "parsing plugins", parse);
	DF (BIN, "bin plugins", bin);
	DF (EGG, "egg plugins", egg);
	DF (FS, "fs plugins", fs);
	DF (ARCH, "arch plugins", arch);
	core->times->loadlibs_init_time = r_time_now_mono () - prev;
}

static bool is_script(const char *name) {
	const char *ext = r_file_extension (name);
	if (!ext) {
		return false;
	}
	static const char *exts[] = {
		"c", "go", "ts", "js", "qjs", "lua", "pl", "py",
		"rs", "v", "nim", "vala", "wren", NULL
	};
	const char **e;
	for (e = exts; *e; e++) {
		if (!strcmp (ext, *e)) {
			return true;
		}
	}
	return false;
}

static void load_scripts_at(RCore *core, const char *plugindir) {
	if (R_STR_ISEMPTY (plugindir) || !r_file_is_directory (plugindir)) {
		return;
	}
	RList *files = r_sys_dir (plugindir);
	RListIter *iter;
	char *file;
	r_list_foreach (files, iter, file) {
		if (is_script (file)) {
			char *script_file = r_str_newf ("%s/%s", plugindir, file);
			if (!r_core_run_script (core, script_file)) {
				R_LOG_ERROR ("Failed to run script '%s'", script_file);
			}
			free (script_file);
		}
	}
	r_list_free (files);
}

static void load_scripts(RCore *core) {
	char *homeplugindir = r_xdg_datadir ("plugins");
	load_scripts_at (core, homeplugindir);
	free (homeplugindir);

	const char *sysplugindir = r_config_get (core->config, "dir.plugins");
	load_scripts_at (core, sysplugindir);
}

R_API bool r_core_loadlibs(RCore *core, int where, const char *path) {
	if (!r_config_get_b (core->config, "cfg.plugins")) {
		core->times->loadlibs_time = 0;
		return false;
	}
	r_core_loadlibs_init (core);
	const ut64 prev = r_time_now_mono ();
	load_plugins (core, where, path);
	load_scripts (core);
	core->times->loadlibs_time = r_time_now_mono () - prev;
	return true;
}

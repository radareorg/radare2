/* radare - LPGL - Copyright 2017-2020 condret */

#include <r_lib.h>
#include <r_core.h>
#include <r_lang.h>

static bool lang_lib_init(RLang *user) {
	return true;
}

static bool lang_lib_file_run(RLang *user, const char *file) {
	char *libpath;
	void *lib;
	if (!(libpath = r_str_new (file))) {
		return false;
	}
	if (!r_str_startswith (libpath, "/") && !r_str_startswith (libpath, "./")) {
		libpath = r_str_prepend (libpath, "./");
	}
	if (!r_file_exists (libpath)) {
		if (!r_str_endswith (libpath, R_LIB_EXT)) {
			libpath = r_str_appendf (libpath, ".%s", R_LIB_EXT);
		}
	}
	if (!r_file_exists (libpath)) {
		free (libpath);
		return false;
	}	
	
	lib = r_lib_dl_open (libpath);
	if (lib) {
		void (*fcn)(RCore *);
		fcn = r_lib_dl_sym (lib, "entry");
		if (fcn) {
			fcn (user->user);
		} else {
			eprintf ("Cannot find 'entry' symbol in library\n");
		}
		r_lib_dl_close (lib);
	}
	free (libpath);
	return true;
}

static RLangPlugin r_lang_plugin_lib = {
	.name = "lib",
	.ext = R_LIB_EXT,
	.desc = "Load libs directly into r2",
	.license = "LGPL",
	.init = lang_lib_init,
	.run_file = lang_lib_file_run,
};

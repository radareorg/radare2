/* radare - LPGL - Copyright 2017-2022 condret */

#include <r_lang.h>

static bool lang_lib_file_run(RLangSession *user, const char *file) {
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
			fcn (user->user_data);
		} else {
			R_LOG_ERROR ("Cannot find 'entry' symbol in library");
		}
		r_lib_dl_close (lib);
	}
	free (libpath);
	return true;
}

static RLangPlugin r_lang_plugin_lib = {
	.meta = {
		.name = "lib",
		.author = "pancake",
		.desc = "Load libs directly into r2",
		.license = "LGPL",
	},
	.ext = R_LIB_EXT,
	.run_file = lang_lib_file_run,
};

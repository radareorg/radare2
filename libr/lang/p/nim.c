/* radare2 - LGPL - Copyright 2023 pancake */

#include <r_lang.h>

static bool lang_nim_file(RLangSession *s, const char *file) {
	if (!r_str_endswith (file, ".nim")) {
		R_LOG_WARN ("expecting .nim extension");
		return false;
	}
	if (!r_file_exists (file)) {
		R_LOG_WARN ("file does not exist");
		return false;
	}
	char *js_ofile = r_str_replace (strdup (file), ".nim", ".r2.js", 0);
	int rc = 0;
	/// check of ofile exists and its newer than file
	if (!r_file_is_newer (js_ofile, file)) {
		char *name = strdup (file);
		char *dot = strchr (name, '.');
		if (dot) {
			*dot = 0;
		}
		// TODO: compile to stdout and remove the need of another tmp file
		// eprintf ("nim c -d:release --backend=js -o:%s %s\n", js_ofile, file);
		rc = r_sys_cmdf ("nim c -d:release --backend=js -o:%s %s", js_ofile, file);
	} else {
		R_LOG_DEBUG ("no need to compile");
	}
	// TODO: use r_lang_run_string() and avoid the need of the intermediate qjs file
	if (rc == 0) {
		r_lang_use (s->lang, "qjs");
		rc = r_lang_run_file (s->lang, js_ofile)? 0: -1;
	} else {
		R_LOG_ERROR ("Cannot compile");
	}
	free (js_ofile);
	return rc;
}

static bool lang_nim_run(RLangSession *s, const char *code, int len) {
	char *ts_ofile = r_str_newf (".tmp.nim");
	bool rv = r_file_dump (ts_ofile, (const ut8 *)code, len, 0);
	if (rv) {
		rv = lang_nim_file (s, ts_ofile);
	}
	free (ts_ofile);
	return rv;
}

static bool lang_nim_init(RLangSession *s) {
	char *nim = r_file_path ("nim");
	bool found = (nim && *nim != 'n');
	free (nim);
	return found;
}

static RLangPlugin r_lang_plugin_nim = {
	.meta = {
		.name = "nim",
		.author = "pancake",
		.license = "MIT",
		.desc = "Use #!nim script.nim",
	},
	.ext = "nim",
	.init = lang_nim_init,
	.run = lang_nim_run,
	.run_file = (void*)lang_nim_file,
};

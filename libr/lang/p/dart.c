/* radare2 - LGPL - Copyright 2024 pancake */

#include <r_lang.h>

static bool lang_dart_file(RLangSession *s, const char *file) {
	if (!r_str_endswith (file, ".dart")) {
		R_LOG_WARN ("expecting .dart extension");
		return false;
	}
	if (!r_file_exists (file)) {
		R_LOG_WARN ("file does not exist");
		return false;
	}
	char *js_ofile = r_str_replace (strdup (file), ".dart", ".r2.js", 0);
	int rc = 0;
	/// check of ofile exists and its newer than file
	if (!r_file_is_newer (js_ofile, file)) {
		char *name = strdup (file);
		char *dot = strchr (name, '.');
		if (dot) {
			*dot = 0;
		}
		char *a = r_file_slurp (file, NULL);
		char *b = r_str_newf (
			"library r2pipe.js;\n\n"
			"import 'dart:convert';\n\n"
			"import 'dart:js' as js;\n\n"
			"String r2cmd(String cmd){return js.context.callMethod ('r2cmd', [cmd]);}\n"
			"dynamic r2cmdj(String cmd){return jsonDecode(r2cmd(cmd));}\n"
			"\n%s", a);
		free (a);
		char *file_dart = r_str_newf ("%s.dart", file);
		r_file_dump (file_dart, (const ut8*)b, strlen (b), false);
		free (b);
		rc = r_sys_cmdf ("dart compile js -o %s %s", js_ofile, file_dart);
		if (rc == 0) {
			char *a = r_file_slurp (js_ofile, NULL);
			char *b = r_str_newf ("var self = global;\n%s", a);
			free (a);
			r_file_dump (js_ofile, (const ut8*)b, strlen (b), false);
			free (b);
		}
		r_file_rm (file_dart);
		// rc = r_sys_cmdf ("dart c -d:release --backend=js -o:%s %s", js_ofile, file);
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

static bool lang_dart_run(RLangSession *s, const char *code, int len) {
	char *ts_ofile = r_str_newf (".tmp.dart");
	bool rv = r_file_dump (ts_ofile, (const ut8 *)code, len, 0);
	if (rv) {
		rv = lang_dart_file (s, ts_ofile);
	}
	free (ts_ofile);
	return rv;
}

static bool lang_dart_init(RLangSession *s) {
	char *dart = r_file_path ("dart");
	bool found = (dart && *dart != 'd');
	if (!found) {
		R_LOG_DEBUG ("Cannot find dart in PATH");
	}
	free (dart);
	return found;
}

static RLangPlugin r_lang_plugin_dart = {
	.meta = {
		.name = "dart",
		.author = "pancake",
		.license = "LGPL-3.0-only",
		.desc = "Use #!dart script.dart",
	},
	.ext = "dart",
	.init = lang_dart_init,
	.run = lang_dart_run,
	.run_file = (void*)lang_dart_file,
};

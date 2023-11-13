/* radare2 - LGPL - Copyright 2015-2023 pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

// #include "../js_require.c"

const char *const js_entrypoint_qjs = "Gmain(requirejs,global,{default:{open:()=>r2},r2,R,EsilParser,NativePointer,R2Papi,R2Pipe,Base64})";

static char *patch_entrypoint(char *input, const char *name) {
	char *needle = r_str_newf ("define(\"%s\"", name);
	char *found = strstr (input, needle);
	if (found) {
		const char *const key = ", function (";
		char *func = strstr (found, key);
		if (func) {
			*func = 0;
			char *rest = strdup (func + strlen (key));
			char *newstr = r_str_newf ("%s, Gmain=function (%s", input, rest);
			free (rest);
			free (input);
			input = newstr;
		}
		free (needle);
		return input;
	}
	free (needle);

	char *in = strdup (input);
	char *output = r_str_replace (input,
			", function (require, exports) {",
			", Gmain=function (require, exports) {", 1);
	if (input != output || strcmp (in, output)) {
		free (in);
		return output;
	}
	output = r_str_replace (input,
			"function (require, exports, r2papi_1) {",
			"Gmain=function (require, exports, r2papi_1) {", 1);
	if (input != output || strcmp (in, output)) {
		free (in);
		return output;
	}
	output = r_str_replace (input,
			", function (require, exports, index_1) {",
			", Gmain=function (require, exports, index_1) {", 1);
	if (input != output || strcmp (in, output)) {
		free (in);
		return output;
	}
	free (input);
	return NULL;
}

static bool lang_tsc_file(RLangSession *s, const char *file) {
	if (!r_str_endswith (file, ".ts")) {
		R_LOG_WARN ("expecting .ts extension");
		return false;
	}
	if (!r_file_exists (file)) {
		R_LOG_WARN ("file does not exist");
		return false;
	}
	char *js_ofile = r_str_replace (strdup (file), ".ts", ".js", 0);
	char *qjs_ofile = r_str_replace (strdup (file), ".ts", ".r2.js", 0);
	int rc = 0;
	/// check of ofile exists and its newer than file
	if (!r_file_is_newer (qjs_ofile, file)) {
		char *name = strdup (file);
		char *dot = strchr (name, '.');
		if (dot) {
			*dot = 0;
		}
		// TODO: compile to stdout and remove the need of another tmp file
		rc = r_sys_cmdf ("tsc --target es2020 --allowJs --outFile %s --lib es2020,dom --moduleResolution node --module amd %s", js_ofile, file);
		if (rc == 0) {
			char *js_ifile = r_file_slurp (js_ofile, NULL);
			RStrBuf *sb = r_strbuf_new ("");
			char *js_ifile_orig = strdup (js_ifile);
			// r_strbuf_append (sb, js_require_qjs);
			js_ifile = patch_entrypoint (js_ifile, name);
			if (js_ifile) {
				r_strbuf_append (sb, "var Gmain;");
				r_strbuf_append (sb, js_ifile);
				r_strbuf_append (sb, js_entrypoint_qjs);
			} else {
				R_LOG_DEBUG ("Cannot find Gmain entrypoint");
				r_strbuf_append (sb, js_ifile_orig);
			}
			char *s = r_strbuf_drain (sb);
			free (js_ifile_orig);
			r_file_dump (qjs_ofile, (const ut8*)s, -1, 0);
			free (s);
			r_file_rm (js_ofile);
		}
	} else {
		R_LOG_DEBUG ("no need to compile");
	}
	// TODO: use r_lang_run_string() and avoid the need of the intermediate qjs file
	if (rc == 0) {
		r_lang_use (s->lang, "qjs");
		rc = r_lang_run_file (s->lang, qjs_ofile)? 0: -1;
	}
	free (js_ofile);
	free (qjs_ofile);
	return rc;
}

static bool lang_tsc_run(RLangSession *s, const char *code, int len) {
	char *ts_ofile = r_str_newf (".tmp.ts");
	bool rv = r_file_dump (ts_ofile, (const ut8 *)code, len, 0);
	if (rv) {
		rv = lang_tsc_file (s, ts_ofile);
	}
	free (ts_ofile);
	return rv;
}

static bool lang_tsc_init(RLangSession *ls) {
	bool found = true;
	if (ls == NULL) {
		char *tsc = r_file_path ("tsc");
		free (tsc);
		found = (tsc != NULL);
	}
	return found;
}

static RLangPlugin r_lang_plugin_tsc = {
	// use RLibMeta for RLangPlugin too
	.meta = {
		.name = "tsc",
		.author = "pancake",
		.license = "LGPL",
		.desc = "Use #!tsc script.ts",
	},
	.ext = "ts",
	.init = lang_tsc_init,
	.run = lang_tsc_run,
	.run_file = (void*)lang_tsc_file,
};

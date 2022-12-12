/* radare2 - LGPL - Copyright 2015-2022 pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

static bool lang_tsc_file(RLangSession *s, const char *file) {
	char *ofile = r_str_newf ("%s.qjs", file);
	int rc = r_sys_cmdf ("tsc --outFile %s %s", ofile, file);
	if (rc == 0) {
		r_lang_use (s->lang, "qjs");
		rc = r_lang_run_file (s->lang, ofile)? 0: -1;
	}
	free (ofile);
	return rc == 0;
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

static RLangPlugin r_lang_plugin_tsc = {
	.name = "tsc",
	.ext = "ts",
	.author = "pancake",
	.license = "LGPL",
	.desc = "Use #!tsc script.ts",
	.run = lang_tsc_run,
	.run_file = (void*)lang_tsc_file,
};

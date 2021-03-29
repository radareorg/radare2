/* radare - LGPL - Copyright 2020 pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"
#define USE_R2 1

static RLang *Glang = NULL;
#include <spp.h>
#include "spp_r2.inc"

static bool lang_spp_init(RLang *l) {
	Glang = l;
	return true;
}

static bool lang_spp_run(RLang *lang, const char *code, int len) {
	Output out;
	out.fout = NULL;
	out.cout = r_strbuf_new (NULL);
	r_strbuf_init (out.cout);
	spp_proc_set (&spp_r2_proc, NULL, 0);
	char *c = strdup (code);
	spp_eval (c, &out);
	free (c);
	char *data = r_strbuf_drain (out.cout);
	r_cons_printf ("%s\n", data);
	free (data);
	return true;
}

static bool lang_spp_file(RLang *lang, const char *file) {
	size_t len;
	char *code = r_file_slurp (file, &len);
	if (code) {
		int res = lang_spp_run (lang, code, len);
		free (code);
		return res;
	}
	return 0;
}

#define r_lang_spp_example "Hello {{{r2 ?E Hello world}}}"

static RLangPlugin r_lang_plugin_spp = {
	.name = "spp",
	.ext = "spp",
	.license = "MIT",
	.desc = "SPP template programs",
	.example = r_lang_spp_example,
	.run = lang_spp_run,
	.init = (void*)lang_spp_init,
	.run_file = (void*)lang_spp_file,
};

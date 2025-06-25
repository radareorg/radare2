/* radare - LGPL - Copyright 2020-2024 pancake */

#include <r_core.h>
#define USE_R2 1

// XXX remove this global, but we need to improve spp to have context
static R_TH_LOCAL RLang *Glang = NULL;
#undef S_API
// #include "../../../shlr/spp/spp.c"
#include "../../../shlr/spp/spp.h"
#include "spp_r2.inc.c"

static bool lang_spp_run(RLangSession *s, const char *code, int len) {
	Glang = s->lang; // XXX
	Output out;
	out.fout = NULL;
	out.cout = r_strbuf_new (NULL);
	r_strbuf_init (out.cout);
	spp_proc_set (&spp_r2_proc, NULL, 0);
	char *c = strdup (code);
	spp_eval (c, &out);
	free (c);
	RCons *cons = s->lang->cons;
	char *data = r_strbuf_drain (out.cout);
	r_kons_printf (cons, "%s\n", data);
	free (data);
	return true;
}

static bool lang_spp_file(RLangSession *lang, const char *file) {
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
	.meta = {
		.name = "spp",
		.license = "MIT",
		.author = "pancake",
		.desc = "SPP template programs",
	},
	.ext = "spp",
	.example = r_lang_spp_example,
	.run = lang_spp_run,
	.run_file = (void*)lang_spp_file,
};

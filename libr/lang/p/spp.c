/* radare - LGPL - Copyright 2020-2024 pancake */

#include <r_core.h>
#define USE_R2 1
#include "../../../shlr/spp/spp.h"

static TAG_CALLBACK(spp_r2_cmd) {
	if (state->echo[state->ifl]) {
		RLang *lang = state->user;
		char *result = lang->cmd_str (lang->user, buf);
		if (result) {
			r_strbuf_append (out->cout, result);
			free (result);
		}
	}
	return 0;
}

static bool lang_spp_run(RLangSession *s, const char *code, int len) {
	const SppProc *base = spp_default_proc ();
	SppTag *base_tags = (SppTag *)base->tags;
	size_t n = 0;
	while (base_tags[n].name) {
		n++;
	}
	SppTag *tags = calloc (n + 3, sizeof (SppTag));
	if (!tags) {
		return false;
	}
	memcpy (tags, base_tags, n * sizeof (SppTag));
	tags[n] = (SppTag) { "r2", spp_r2_cmd };
	tags[n + 1] = base_tags[n];
	SppProc p = *base;
	p.tags = (SppTag **)tags;
	p.tag_pre = "{";
	p.tag_post = "}";
	p.state.user = s->lang;
	p.state.pipe_fd = NULL;
	p.state.switch_str = NULL;
	p.buf = (SppBuf) { 0 };
	(void)len;
	char *data = spp_eval_str (&p, code);
	free (p.buf.lbuf);
	free (tags);
	if (!data) {
		return false;
	}
	r_cons_printf (s->lang->cons, "%s\n", data);
	free (data);
	return true;
}

static bool lang_spp_file(RLangSession *s, const char *file) {
	char *code = r_file_slurp (file, NULL);
	if (!code) {
		return false;
	}
	bool res = lang_spp_run (s, code, strlen (code));
	free (code);
	return res;
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
	.run_file = (void *)lang_spp_file,
};

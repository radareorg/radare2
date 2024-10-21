/* radare - LPGL - Copyright 2023-2024 pancake */

#include <r_lang.h>

static bool lang_poke_file_run(RLangSession *s, const char *file) {
	R_RETURN_VAL_IF_FAIL (s && file, false);
	RCore *core = s->lang->user;
	if (core) {
		s->lang->cmdf (core, "'poke -f %s", file);
	} else {
		R_LOG_WARN ("RLang can't find the core instance");
	}
	return true;
}

static bool lang_poke_run(RLangSession *s, const char *code, int len) {
	R_RETURN_VAL_IF_FAIL (s, false);
	RCore *core = s->lang->user;
	if (core) {
		s->lang->cmdf (core, "'poke %s", code);
	} else {
		R_LOG_WARN ("RLang can't find the core instance");
	}
	return true;
}

static RLangPlugin r_lang_plugin_poke = {
	.meta = {
		.name = "poke",
		.author = "pancake",
		.desc = "Run GNU/Poke script file or oneliner",
		.license = "LGPL-3.0-only",
	},
	.ext = "pk",
	.run = lang_poke_run,
	.run_file = lang_poke_file_run,
};

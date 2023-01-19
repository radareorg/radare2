/* radare - LPGL - Copyright 2023 pancake */

#include <r_lang.h>

static bool lang_poke_file_run(RLangSession *session, const char *file) {
	RCore *core = session->user_data;
	session->lang->cmdf (core, "\"\"poke -f %s", file);
	return true;
}

static bool lang_poke_run(RLangSession *s, const char *code, int len) {
	RCore *core = s->user_data;
	s->lang->cmdf (core, "\"\"poke %s", code);
	return true;
}

static RLangPlugin r_lang_plugin_poke = {
	.name = "poke",
	.author = "pancake",
	.ext = "pk",
	.desc = "Run GNU/Poke script file or oneliner",
	.license = "LGPL",
	.run = lang_poke_run,
	.run_file = lang_poke_file_run,
};

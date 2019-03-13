/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <r_main.h>

#if EMSCRIPTEN
#include <emscripten.h>
static RCore *core = NULL;

void *r2_asmjs_new(const char *cmd) {
	return r_core_new ();
}

void r2_asmjs_free(void *core) {
	r_core_free (core);
}

char *r2_asmjs_cmd(void *kore, const char *cmd) {
	if (kore) {
		if (!cmd) {
			r_core_free (kore);
		}
	} else {
		if (core) {
			kore = core;
		} else {
			kore = core = r_core_new ();
		}
	}
	return r_core_cmd_str (kore, cmd);
}

static void wget_cb(const char *f) {
	r_core_cmdf (core, "o %s", f);
}

void r2_asmjs_openurl(void *kore, const char *url) {
	const char *file = r_str_lchr (url, '/');
	if (kore) {
		core = kore;
	}
	if (file) {
		emscripten_async_wget (url, file + 1, wget_cb, NULL);
	}
}
#else

int main(int argc, char **argv) {
	return r_main_radare2 (argc, argv);
}

#endif

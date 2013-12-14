/* radare - LGPL - Copyright 2011-2013 pancake */
/* vala extension for libr (radare2) */
// TODO: add cache directory (~/.r2/cache)

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

static int lang_c_file(RLang *lang, const char *file) {
	void *lib;
	char *p, name[512], buf[512];

	if (!strstr (file, ".c"))
		sprintf (name, "%s.c", file);
	else strcpy (name, file);
	if (!r_file_exists (name)) {
		eprintf ("file not found (%s)\n", name);
		return R_FALSE;
	}

	if (system (buf) != 0)
		return R_FALSE;
	p = strstr (name, ".c"); if (p) *p=0;
	// TODO: use CC environ if possible
	snprintf (buf, sizeof (buf), "gcc -fPIC -shared %s -o lib%s."R_LIB_EXT
		" $(pkg-config --cflags --libs r_core)", file, name);
	if (system (buf) != 0)
		return R_FALSE;

	snprintf (buf, sizeof (buf), "./lib%s."R_LIB_EXT, name);
	lib = r_lib_dl_open (buf);
	if (lib!= NULL) {
		void (*fcn)(RCore *);
		fcn = r_lib_dl_sym (lib, "entry");
		if (fcn) fcn (lang->user);
		else eprintf ("Cannot find 'entry' symbol in library\n");
		r_lib_dl_close (lib);
	} else eprintf ("Cannot open library\n");
	r_file_rm (buf); // remove lib
	return 0;
}

static int lang_c_init(void *user) {
	// TODO: check if "valac" is found in path
	return R_TRUE;
}

static int lang_c_run(RLang *lang, const char *code, int len) {
	FILE *fd = fopen (".tmp.c", "w");
	if (fd) {
		fputs ("#include <r_core.h>\n\nvoid entry(RCore *core) {\n", fd);
		fputs (code, fd);
		fputs (";\n}\n", fd);
		fclose (fd);
		lang_c_file (lang, ".tmp.c");
		r_file_rm (".tmp.c");
	} else eprintf ("Cannot open .tmp.c\n");
	return R_TRUE;
}

static struct r_lang_plugin_t r_lang_plugin_c = {
	.name = "C",
	.ext = "c",
	.desc = "C language extension",
	.help = NULL,
	.run = lang_c_run,
	.init = (void*)lang_c_init,
	.fini = NULL,
	.run_file = (void*)lang_c_file,
	.set_argv = NULL,
};

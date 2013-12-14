/* radare - LGPL - Copyright 2011-2013 pancake */
/* vala extension for libr (radare2) */
// TODO: add cache directory (~/.r2/cache)

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

static int lang_vala_file(RLang *lang, const char *file) {
	void *lib;
	char *p, name[512], buf[512];
	char *vapidir;

	if (!strstr (file, ".vala"))
		sprintf (name, "%s.vala", file);
	else strcpy (name, file);
	if (!r_file_exists (name)) {
		eprintf ("file not found (%s)\n", name);
		return R_FALSE;
	}

	vapidir = r_sys_getenv ("VAPIDIR");
	if (vapidir) {
		if (*vapidir) {
			snprintf (buf, sizeof (buf), "valac --vapidir=%s --pkg r_core -C %s",
				vapidir, name);
		}
		free (vapidir);
	} else sprintf (buf, "valac --pkg r_core -C %s", name);
	if (system (buf) != 0)
		return R_FALSE;
	p = strstr (name, ".vala"); if (p) *p=0;
	p = strstr (name, ".gs"); if (p) *p=0;
	// TODO: use CC environ if possible
	snprintf (buf, sizeof (buf), "gcc -fPIC -shared %s.c -o lib%s."R_LIB_EXT
		" $(pkg-config --cflags --libs r_core gobject-2.0)", name, name);
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
	sprintf (buf, "%s.c", name); // remove .c
	r_file_rm (buf);
	return 0;
}

static int lang_vala_init(void *user) {
	// TODO: check if "valac" is found in path
	return R_TRUE;
}

static int lang_vala_run(RLang *lang, const char *code, int len) {
	FILE *fd = fopen (".tmp.vala", "w");
	if (fd) {
		fputs ("using Radare;\n\npublic static void entry(RCore core) {\n", fd);
		fputs (code, fd);
		fputs (";\n}\n", fd);
		fclose (fd);
		lang_vala_file (lang, ".tmp.vala");
		r_file_rm (".tmp.vala");
	} else eprintf ("Cannot open .tmp.vala\n");
	return R_TRUE;
}

static struct r_lang_plugin_t r_lang_plugin_vala = {
	.name = "vala",
	.ext = "vala",
	.desc = "VALA language extension",
	.help = NULL,
	.run = lang_vala_run,
	.init = (void*)lang_vala_init,
	.fini = NULL,
	.run_file = (void*)lang_vala_file,
	.set_argv = NULL,
};

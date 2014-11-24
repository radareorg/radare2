/* radare - LGPL - Copyright 2011-2014 pancake */
/* vala extension for libr (radare2) */
// TODO: add cache directory (~/.r2/cache)

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

static int lang_c_file(RLang *lang, const char *file) {
	void *lib;
	char *cc, *p, name[512], buf[512];
	const char *libpath, *libname;

	if (strlen (file) > (sizeof(name)-10))
		return R_FALSE;
	if (!strstr (file, ".c"))
		sprintf (name, "%s.c", file);
	else strcpy (name, file);
	if (!r_file_exists (name)) {
		eprintf ("file not found (%s)\n", name);
		return R_FALSE;
	}

{
	char *a = (char*)r_str_lchr (name, '/');
	if (a) {
		*a = 0;
		libpath = name;
		libname = a+1;
	} else {
		libpath = ".";
		libname = name;
	}
}
	p = strstr (name, ".c"); if (p) *p=0;
	cc = r_sys_getenv ("CC");
	if (!cc || !*cc)
		cc = strdup ("gcc");
	snprintf (buf, sizeof (buf), "%s -fPIC -shared %s -o %s/lib%s."R_LIB_EXT
		" $(pkg-config --cflags --libs r_core)", cc, file, libpath, libname);
	free (cc);
	if (system (buf) != 0)
		return R_FALSE;

	snprintf (buf, sizeof (buf), "%s/lib%s."R_LIB_EXT, libpath, libname);
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
		fputs ("\n}\n", fd);
		fclose (fd);
		lang_c_file (lang, ".tmp.c");
		r_file_rm (".tmp.c");
	} else eprintf ("Cannot open .tmp.c\n");
	return R_TRUE;
}

static struct r_lang_plugin_t r_lang_plugin_c = {
	.name = "c",
	.ext = "c",
	.desc = "C language extension",
	.help = NULL,
	.run = lang_c_run,
	.init = (void*)lang_c_init,
	.fini = NULL,
	.run_file = (void*)lang_c_file,
	.set_argv = NULL,
};

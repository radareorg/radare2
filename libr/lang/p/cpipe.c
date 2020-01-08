/* radare - LGPL - Copyright 2011-2019 pancake */
/* vala extension for libr (radare2) */
// TODO: add cache directory (~/.r2/cache)

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

static int lang_cpipe_file(RLang *lang, const char *file) {
	char *a, *cc, *p, name[512];
	const char *libpath, *libname;

	if (strlen (file) > (sizeof (name)-10))
		return false;
	if (!strstr (file, ".c"))
		sprintf (name, "%s.c", file);
	else strcpy (name, file);
	if (!r_file_exists (name)) {
		eprintf ("file not found (%s)\n", name);
		return false;
	}

	a = (char*)r_str_lchr (name, '/');
	if (a) {
		*a = 0;
		libpath = name;
		libname = a + 1;
	} else {
		libpath = ".";
		libname = name;
	}
	r_sys_setenv ("PKG_CONFIG_PATH", R2_LIBDIR"/pkgconfig");
	p = strstr (name, ".c");
	if (p) *p = 0;
	cc = r_sys_getenv ("CC");
	if (!cc || !*cc) {
		free (cc);
		cc = strdup ("gcc");
	}
	char *buf = r_str_newf ("%s %s -o %s/bin%s"
		" $(pkg-config --cflags --libs r_socket)",
		cc, file, libpath, libname);
	free (cc);
	if (r_sandbox_system (buf, 1) == 0) {
		char *binfile = r_str_newf ("%s/bin%s", libpath, libname);
		lang_pipe_run (lang, binfile, -1);
		r_file_rm (binfile);
		free (binfile);
	}
	free (buf);
	return 0;
}

static int lang_cpipe_init(void *user) {
	// TODO: check if "valac" is found in path
	return true;
}

static int lang_cpipe_run(RLang *lang, const char *code, int len) {
	FILE *fd = r_sandbox_fopen (".tmp.c", "w");
	if (!fd) {
		eprintf ("Cannot open .tmp.c\n");
		return false;
	}
	fputs ("#include <r_socket.h>\n\n"
		"#define R2P(x,y...) r2pipe_cmdf(r2p,x,##y)\n"
		"int main() {\n"
		"  R2Pipe *r2p = r2pipe_open(NULL);", fd);
	fputs (code, fd);
	fputs ("\n}\n", fd);
	fclose (fd);
	lang_cpipe_file (lang, ".tmp.c");
	r_file_rm (".tmp.c");
	return true;
}

static RLangPlugin r_lang_plugin_cpipe = {
	.name = "cpipe",
	.ext = "c2",
	.desc = "r2pipe scripting in C",
	.license = "LGPL",
	.run = lang_cpipe_run,
	.init = (void*)lang_cpipe_init,
	.fini = NULL,
	.run_file = (void*)lang_cpipe_file,
};

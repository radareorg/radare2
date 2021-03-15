/* radare - LGPL - Copyright 2011-2019 pancake */
/* vala extension for libr (radare2) */
// TODO: add cache directory (~/.r2/cache)

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

#if __UNIX__
static int lang_cpipe_file(RLang *lang, const char *file) {
	char *a, *cc, *p, name[512];
	const char *libpath, *libname;

	if (strlen (file) > (sizeof (name)-10)) {
		return false;
	}
	if (!strstr (file, ".c")) {
		sprintf (name, "%s.c", file);
	} else {
		strcpy (name, file);
	}
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
	p = strstr (name, ".c");
	if (p) {
		*p = 0;
	}
	cc = r_sys_getenv ("CC");
	if (R_STR_ISEMPTY (cc)) {
		free (cc);
		cc = strdup ("gcc");
	}
	char *file_esc = r_str_escape_sh (file);
	char *libpath_esc = r_str_escape_sh (libpath);
	char *libname_esc = r_str_escape_sh (libname);
	char *buf = r_str_newf ("%s \"%s\" -o \"%s/bin%s\""
		" $(PKG_CONFIG_PATH=%s pkg-config --cflags --libs r_socket)",
		cc, file_esc, libpath_esc, libname_esc, R2_LIBDIR "/pkgconfig");
	free (libname_esc);
	free (libpath_esc);
	free (file_esc);
	free (cc);
	if (r_sandbox_system (buf, 1) == 0) {
		char *o_ld_path = r_sys_getenv ("LD_LIBRARY_PATH");
		r_sys_setenv ("LD_LIBRARY_PATH", R2_LIBDIR);
		char *binfile = r_str_newf ("%s/bin%s", libpath, libname);
		lang_pipe_run (lang, binfile, -1);
		r_file_rm (binfile);
		r_sys_setenv ("LD_LIBRARY_PATH", o_ld_path);
		free (o_ld_path);
		free (binfile);
	}
	free (buf);
	return 0;
}

static int lang_cpipe_init(void *user) {
	// TODO: check if "valac" is found in path
	return true;
}

static bool lang_cpipe_run(RLang *lang, const char *code, int len) {
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
#else
#ifdef _MSC_VER
#pragma message("Warning: cpipe RLangPlugin is not implemented on this platform")
#else
#warning cpipe RLangPlugin is not implemented on this platform
#endif
#endif

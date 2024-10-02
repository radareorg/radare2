/* radare - LGPL - Copyright 2011-2017 pancake */
/* vala extension for libr (radare2) */
// TODO: add cache directory (~/.r2/cache)

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

#if R2__UNIX__ && !__wasi__
static R_TH_LOCAL int ac = 0;
static R_TH_LOCAL const char **av = NULL;

static bool lang_c_set_argv(RLang *lang, int argc, const char **argv) {
	ac = argc;
	av = argv;
	return true;
}

static int lang_c_file(RLangSession *s, const char *file) {
	char *a, *cc, *p, name[512];
	const char *libpath, *libname;
	void *lib;

	if (strlen (file) > (sizeof (name) - 10)) {
		return false;
	}
	if (!strstr (file, ".c")) {
		snprintf (name, sizeof (name), "%s.c", file);
	} else {
		strcpy (name, file);
	}
	if (!r_file_exists (name)) {
		R_LOG_ERROR ("file not found (%s)", name);
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
		cc = strdup ("gcc");
	}
	char *file_esc = r_str_escape_sh (file);
	char *libpath_esc = r_str_escape_sh (libpath);
	char *libname_esc = r_str_escape_sh (libname);
#if 0
	char *buf = r_str_newf ("%s -fPIC -g -shared \"%s\" -o \"%s/lib%s." R_LIB_EXT "\""
		" $(PKG_CONFIG_PATH=%s pkg-config --cflags --libs r_core)",
		cc, file_esc, libpath_esc, libname_esc, R2_LIBDIR "/pkgconfig");
#else
	char *buf = r_str_newf ("%s -fPIC -shared \"%s\" -o \"%s/lib%s." R_LIB_EXT "\""
		" $(PKG_CONFIG_PATH=%s pkg-config --cflags --libs r_core)",
		cc, file_esc, libpath_esc, libname_esc, R2_LIBDIR "/pkgconfig");
#endif
	free (libname_esc);
	free (libpath_esc);
	free (file_esc);
	free (cc);
	if (r_sandbox_system (buf, 1) != 0) {
		free (buf);
		return false;
	}
	free (buf);
	buf = r_str_newf ("%s/lib%s."R_LIB_EXT, libpath, libname);
	lib = r_lib_dl_open (buf);
	if (lib) {
		void (*fcn)(RCore *, int argc, const char **argv);
		fcn = r_lib_dl_sym (lib, "entry");
		if (fcn) {
			fcn (s->lang->user, ac, av);
			ac = 0;
			av = NULL;
		} else {
			R_LOG_ERROR ("Cannot find 'entry' symbol in library");
		}
		r_lib_dl_close (lib);
	} else {
		R_LOG_ERROR ("Cannot open library");
	}
	r_file_rm (buf); // remove lib
	free (buf);
	return 0;
}

static int lang_c_init(void *user) {
	// TODO: check if "cc/gcc/clang/zig/tcc/cl" is found in path
	return true;
}

static bool lang_c_run(RLangSession *s, const char *code, int len) {
	FILE *fd = r_sandbox_fopen (".tmp.c", "w");
	if (!fd) {
		R_LOG_ERROR ("Cannot open .tmp.c");
		return false;
	}
	fputs ("#include <r_core.h>\n\nvoid entry(RCore *core, int argc, const char **argv) {\n", fd);
	fputs (code, fd);
	fputs ("\n}\n", fd);
	fclose (fd);
	lang_c_file (s, ".tmp.c");
	r_file_rm (".tmp.c");
	return true;
}

#define r_lang_c_example "" \
	"#include <r_core.h>\n"\
	"\nvoid entry(RCore *core, int argc, const char **argv) {\n"\
	"    char *s = r_core_cmd_str (core, \"?E hello world\");\n"\
	"    printf(\"%s\", s);\n"\
	"    free (s);\n"\
	"}\n"\
	""

static RLangPlugin r_lang_plugin_c = {
	.meta = {
		.name = "c",
		.desc = "C language extension",
		.author = "pancake",
		.license = "LGPL",
	},
	.ext = "c",
	.example = r_lang_c_example,
	.run = lang_c_run,
	.init = (void*)lang_c_init,
	.run_file = (void*)lang_c_file,
	.set_argv = (void*)lang_c_set_argv,
};
#else
#ifdef _MSC_VER
#pragma message("Warning: C RLangPlugin is not implemented on this platform")
#else
#warning C RLangPlugin is not implemented on this platform
#endif
#endif

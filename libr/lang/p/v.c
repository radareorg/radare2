/* radare - LGPL - Copyright 2019 pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

static int lang_v_file(RLang *lang, const char *file);

static const char *r2v = \
	"module r2\n"
	"\n"
	"#flag `pkg-config --cflags --libs r_core`\n"
	"\n"
	"#include <r_core.h>\n"
	"\n"
	"struct R2 {}\n"
	"\n"
	"pub fn (core &R2)cmd(s string) string {\n"
	"        o := C.r_core_cmd_str (core, s.str)\n"
	"        strs := string(byteptr(o))\n"
	"        free(o)\n"
	"        return strs\n"
	"}\n"
	"\n"
	"pub fn (core &R2)str() string {\n"
	"        return i64(core).str()\n"
	"}\n"
	"\n"
	"pub fn (core &R2)free() {\n"
	"        C.r_core_free (core)\n"
	"}\n"
	"\n"
	"pub fn new() &R2 {\n"
	"        return &R2(C.r_core_new ())\n"
	"}\n";
static const char *vsk = \
	"fn entry(core &R2) {\n";

static int __run(RLang *lang, const char *code, int len) {
	FILE *fd = r_sandbox_fopen (".tmp.v", "w");
	if (fd) {
		fputs (r2v, fd);
		if (len < 0) {
			fputs (code, fd);
		} else {
			fputs (vsk, fd);
			fputs (code, fd);
			fputs ("}", fd);
		}
		fclose (fd);
		lang_v_file (lang, ".tmp.v");
		r_file_rm (".tmp.v");
		return true;
	}
	eprintf ("Cannot open .tmp.v\n");
	return false;
}


static int lang_v_file(RLang *lang, const char *file) {
	if (!r_str_endswith (file, ".v")) {
		return false;
	}
	if (strcmp (file, ".tmp.v")) {
		char *code = r_file_slurp (file, NULL);
		int r = __run (lang, code, -1);
		free (code);
		return r;
	}
	if (!r_file_exists (file)) {
		eprintf ("file not found (%s)\n", file);
		return false;
	}
	char *name = strdup (file);
	char *a = (char*)r_str_lchr (name, '/');
	const char *libpath, *libname;
	if (a) {
		*a = 0;
		libpath = name;
		libname = a + 1;
	} else {
		libpath = ".";
		libname = name;
	}
	r_sys_setenv ("PKG_CONFIG_PATH", R2_LIBDIR"/pkgconfig");
	char *shl = r_str_newf ("%s/lib%s."R_LIB_EXT, libpath, libname);
	char *buf = r_str_newf ("v -cflags '-shared -fPIC' -o %s %s", shl, file);
	free (name);
	if (r_sandbox_system (buf, 1) != 0) {
		free (shl);
		free (buf);
		return false;
	}
	void *lib = r_lib_dl_open (shl);
	free (shl);
	if (lib) {
		void (*fcn)(RCore *, int argc, const char **argv);
		fcn = r_lib_dl_sym (lib, "r2__entry");
		if (fcn) {
			fcn (lang->user, ac, av);
			ac = 0;
			av = NULL;
		} else {
			eprintf ("Cannot find 'entry' symbol in library\n");
		}
		r_lib_dl_close (lib);
	} else {
		eprintf ("Cannot open library\n");
	}
	r_file_rm (buf); // remove lib
	free (buf);
	return 0;
}

static int lang_v_run(RLang *lang, const char *code, int len) {
	return __run (lang, code, len);
}

static RLangPlugin r_lang_plugin_v = {
	.name = "v",
	.ext = "v",
	.desc = "V language extension",
	.license = "LGPL",
	.run = lang_v_run,
	.run_file = (void*)lang_v_file,
};

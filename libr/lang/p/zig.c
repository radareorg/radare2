/* radare - LGPL - Copyright 2018 pancake */

#include <r_lib.h>
#include <r_core.h>
#include <r_lang.h>

static bool lang_zig_file(RLang *lang, const char *file) {
	void *lib;
	char *a, *cc, *p;
	const char *libpath, *libname;

	if (!r_file_exists (file)) {
		eprintf ("file not found (%s)\n", file);
		return false;
	}
	char *name = strdup (file);

	a = (char*)r_str_lchr (name, '/');
	if (a) {
		*a = 0;
		libpath = name;
		libname = a+1;
	} else {
		libpath = ".";
		libname = name;
	}
	p = strstr (name, ".zig");
	if (p) {
		*p = 0;
	}
	cc = r_sys_getenv ("ZIG");
	if (cc && !*cc) {
		R_FREE (cc);
	}
	if (!cc) {
		cc = strdup ("zig");
	}
	char *cmd = r_str_newf ("zig build-lib --output %s.%s --release-fast %s.zig --library r_core", name, R_LIB_EXT, name);
	if (r_sandbox_system (cmd, 1) != 0) {
		free (name);
		free (cmd);
		free (cc);
		return false;
	}
	free (cmd);

	char *path = r_str_newf ("%s/%s.%s", libpath, libname, R_LIB_EXT);
	lib = r_lib_dl_open (path);
	if (lib) {
		void (*fcn)(RCore *);
		fcn = r_lib_dl_sym (lib, "entry");
		if (fcn) {
			fcn (lang->user);
		} else {
			eprintf ("Cannot find 'entry' symbol in library\n");
		}
		r_lib_dl_close (lib);
	} else {
		eprintf ("Cannot open library\n");
		free (path);
		free (cc);
		return false;
	}
	r_file_rm (path); // remove lib
	free (path);
	free (cc);
	return true;
}

static bool lang_zig_init(void *user) {
	// TODO: check if "valac" is found in path
	return true;
}

static bool lang_zig_run(RLang *lang, const char *code, int len) {
	const char *file = "_tmp.zig";
	FILE *fd = r_sandbox_fopen (file, "w");
	if (fd) {
		const char *zig_header = \
"extern fn puts(&const u8) void;\n" \
"extern fn r_core_cmd_str(&u8, &const u8) &u8;\n" \
"extern fn r_core_new() &u8;\n" \
"extern fn r_core_free(&u8) void;\n" \
"\n" \
"export fn entry(core: &u8) void {\n";
		const char *zig_footer = \
"\n}\n" \
"pub fn r2cmd(core: &u8, cmd: u8) &u8 {\n" \
"  return r_core_cmd_str(core, cmd);\n" \
"}\n";
		fputs (zig_header, fd);
		fputs (code, fd);
		fputs (zig_footer, fd);
		fclose (fd);
		lang_zig_file (lang, file);
		r_file_rm (file);
	} else {
		eprintf ("Cannot open %s\n", file);
	}
	return true;
}

static RLangPlugin r_lang_plugin_zig = {
	.name = "zig",
	.ext = "zig",
	.license = "MIT",
	.desc = "Zig language extension",
	.run = lang_zig_run,
	.init = (void*)lang_zig_init,
	.run_file = (void*)lang_zig_file,
};

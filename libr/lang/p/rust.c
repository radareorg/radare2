/* radare - LGPL - Copyright 2016-2018 pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

static int lang_rust_file(RLang *lang, const char *file) {
	void *lib;
	char *a, *cc, *p, name[512];
	const char *libpath, *libname;

	if (strlen (file) > (sizeof (name) - 10)) {
		return false;
	}
	if (!strstr (file, ".rs")) {
		sprintf (name, "%s.rs", file);
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
		libname = a+1;
	} else {
		libpath = ".";
		libname = name;
	}
	r_sys_setenv ("PKG_CONFIG_PATH", R2_LIBDIR"/pkgconfig");
	p = strstr (name, ".rs"); if (p) *p=0;
	cc = r_sys_getenv ("RUSTC");
	if (cc && !*cc) {
		R_FREE (cc);
	}
	if (!cc) {
		cc = strdup ("rustc");
	}
	char *cmd = r_str_newf ("%s --crate-type dylib %s -o %s/lib%s."R_LIB_EXT" -L native=/usr/local/lib/ -l r_core",
		cc, file, libpath, libname);
	free (cc);
	if (r_sandbox_system (cmd, 1) != 0) {
		free (cmd);
		return false;
	}
	free (cmd);

	char *path = r_str_newf ("%s/lib%s."R_LIB_EXT, libpath, libname);
	lib = r_lib_dl_open (path);
	if (lib!= NULL) {
		void (*fcn)(RCore *);
		fcn = r_lib_dl_sym (lib, "entry");
		if (fcn) fcn (lang->user);
		else eprintf ("Cannot find 'entry' symbol in library\n");
		r_lib_dl_close (lib);
	} else {
		eprintf ("Cannot open library\n");
	}
	r_file_rm (path); // remove lib
	free (path);
	return 0;
}

static int lang_rust_init(void *user) {
	// TODO: check if "valac" is found in path
	return true;
}

static bool lang_rust_run(RLang *lang, const char *code, int len) {
	FILE *fd = r_sandbox_fopen ("_tmp.rs", "w");
	if (!fd) {
		eprintf ("Cannot open _tmp.rs\n");
		return false;
	}
	const char *rust_header = \
"use std::ffi::CStr;\n" \
"extern {\n" \
"        pub fn r_core_cmd_str(core: *const u8, s: *const u8) -> *const u8;\n" \
"        pub fn free (ptr: *const u8);\n" \
"}\n" \
"\n" \
"pub struct R2;\n" \
"\n" \
"#[allow(dead_code)]\n" \
"impl R2 {\n" \
"        fn cmdstr(&self, c: *const u8, str: &str) -> String {\n" \
"                unsafe {\n" \
"                        let ptr = r_core_cmd_str(c, str.as_ptr()) as *const i8;\n" \
"                        let c_str = CStr::from_ptr(ptr).to_string_lossy().into_owned();\n" \
"                        free (ptr as *const u8);\n" \
"                        String::from (c_str)\n" \
"                }\n" \
"        }\n" \
"}\n" \
"\n" \
"#[no_mangle]\n" \
"#[allow(unused_variables)]\n" \
"#[allow(unused_unsafe)]\n" \
"pub extern fn entry(core: *const u8) {\n" \
"        let r2 = R2;\n" \
"        unsafe { /* because core is external */\n";
		const char *rust_footer = \
"        }\n" \
"}\n";
	fputs (rust_header, fd);
	fputs (code, fd);
	fputs (rust_footer, fd);
	fclose (fd);
	lang_rust_file (lang, "_tmp.rs");
	r_file_rm ("_tmp.rs");
	return true;
}

static RLangPlugin r_lang_plugin_rust = {
	.name = "rust",
	.ext = "rs",
	.license = "MIT",
	.desc = "Rust language extension",
	.run = lang_rust_run,
	.init = (void*)lang_rust_init,
	.run_file = (void*)lang_rust_file,
};

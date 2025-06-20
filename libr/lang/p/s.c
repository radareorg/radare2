/* radare - LGPL - Copyright 2023 pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

#if R2__UNIX__ && !__wasi__

static int lang_s_file(RLangSession *s, const char *file) {
	char *a, *cc, *p;
	const char *libpath, *libname;
	void *lib;

	char *name = NULL;
	if (r_str_endswith (file, ".s")) {
		name = strdup (file);
	} else {
		name = r_str_newf ("%s.s", file);
	}
	if (!r_file_exists (name)) {
		R_LOG_ERROR ("file not found (%s)", name);
		free (name);
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
	// XXX check if ends with not just strstr
	p = strstr (name, ".s");
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
	char *buf = r_str_newf ("%s -fPIC -shared \"%s\" -o \"%s/lib%s." R_LIB_EXT "\""
		" $(PKG_CONFIG_PATH=%s pkg-config --cflags --libs r_core)",
		cc, file_esc, libpath_esc, libname_esc, R2_LIBDIR "/pkgconfig");
	free (libname_esc);
	free (libpath_esc);
	free (file_esc);
	free (cc);
	if (r_sandbox_system (buf, 1) != 0) {
		free (buf);
		free (name);
		return false;
	}
	free (buf);
	buf = r_str_newf ("%s/lib%s."R_LIB_EXT, libpath, libname);
	lib = r_lib_dl_open (buf, false);
	if (lib) {
		void (*fcn)(RCore *, int argc, const char **argv);
		fcn = r_lib_dl_sym (lib, "entry");
		if (!fcn) {
			fcn = r_lib_dl_sym (lib, "main");
			if (!fcn) {
				fcn = r_lib_dl_sym (lib, "_main");
			}
		}
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
	free (name);
	return 0;
}

static bool lang_s_run(RLangSession *s, const char *code, int len) {
	if (!r_file_dump (".tmp.s", (const ut8*)code, len, false)) {
		R_LOG_ERROR ("Cannot open .tmp.s");
		return false;
	}
	lang_s_file (s, ".tmp.s");
	r_file_rm (".tmp.s");
	return true;
}

#define r_lang_s_example "" \
	".extern _puts\n" \
	".global _main\n" \
	".extern _r_core_new\n" \
	".extern _r_cons_flush\n" \
	".extern _r_core_cmd_str\n" \
	".p2align    2\n" \
	"_main:\n" \
	"	// locals\n" \
	"	// [sp, 0] ptr(LR)\n" \
	"	// [sp, 8] RCore\n" \
	"\n" \
	"	// prelude\n" \
	"	sub sp, sp, 16 \n" \
	"	str lr, [sp, 0] // lr \n" \
	"\n" \
	"	// body\n" \
	"	bl getbase\n" \
	"	// mov x0, =text\n" \
	"	bl _puts\n" \
	"\n" \
	"	bl _r_core_new\n" \
	"	str x0, [sp, 8] // rcore is stored in sp+8\n" \
	"	bl getbase\n" \
	"	mov x1, x0\n" \
	"	ldr x0, [sp, 8]\n" \
	"	bl _r_core_cmd_str\n" \
	"	bl _puts\n" \
	"	// bl _r_cons_flush\n" \
	"\n" \
	"	// postlude\n" \
	"	ldr lr, [sp]\n" \
	"	add sp, sp, 16\n" \
	"	ret\n" \
	"\n" \
	"// .equ delta, (getbase - _main)\n" \
	".zerofill __DATA,__common,_core,4,2\n" \
	"\n" \
	".equ bdelta, 4 * 3 // (baseaddr-_me)\n" \
	"getbase:\n" \
	"	mov x12, lr\n" \
	"	bl _me\n" \
	"_me:\n" \
	"	add x0, lr, bdelta // 4 * 3 ;; 4*3 = text-_me\n" \
	"	mov lr, x12\n" \
	"	ret\n" \
	"baseaddr:\n" \
	"text:\n" \
	"	.string \"?e winrar\x00\"\n" \
	"core:\n" \
	"	.byte 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0\n" \
	""

static RLangPlugin r_lang_plugin_s = {
	.meta = {
		.name = "s",
		.desc = "GNU Assembler Source",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.ext = "s",
	.example = r_lang_s_example,
	.run = lang_s_run,
	.run_file = (void*)lang_s_file,
};
#else
#ifdef _MSC_VER
#pragma message("Warning: C RLangPlugin is not implemented on this platform")
#else
#warning C RLangPlugin is not implemented on this platform
#endif
#endif

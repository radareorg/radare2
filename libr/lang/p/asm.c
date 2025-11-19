/* radare - LGPL - Copyright 2022-2024 pancake */

#include <r_core.h>

#if R2__UNIX__ && !__wasi__
static bool lang_asm_run(RLangSession *s, const char *code, int len) {
	RCore *core = (RCore *)s->lang->user;
	RAsm *a = core->rasm; // r_asm_new ();
	RAsmCode *kode = r_asm_assemble (a, code);
	if (kode) {
		int i;
		eprintf ("CODE: %d\nBYTES: ", kode->len);
		for (i = 0; i < kode->len; i++) {
			eprintf ("%02x ", kode->bytes[i]);
		}
		eprintf ("\n");
		// TODO: resolve the externs
		// TODO: call _start symbol
		r_asm_code_free (kode);
	} else {
		R_LOG_ERROR ("Failed to assemble");
	}
	// r_asm_free (a);
	return true;
}

#define r_lang_asm_example "" \
	"extern r_core_cmd\n"\
	"_start:\n"\
	" mov x0, _cmd\n"\
	" call r_core_cmd\n"\
	" ret\n"\
	"_cmd:\n"\
	".string \"?E Hello Asm\"\n"

static RLangPlugin r_lang_plugin_asm = {
	.meta = {
		.name = "asm",
		.desc = "rasm2 assembly language extension",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.ext = "asm",
	.example = r_lang_asm_example,
	.run = lang_asm_run,
#if 0
	.run_file = (void*)lang_asm_file,
	.set_argv = (void*)lang_asm_set_argv,
#endif
};
#else

#pragma message("Warning: C RLangPlugin is not implemented on this platform")
static RLangPlugin r_lang_plugin_asm = { 0 };

#endif

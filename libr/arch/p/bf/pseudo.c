/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_asm.h>

/* Pseudo rules for brainfuck */
static const char *pseudo_rules[] = {
	/* pointer operations */
	"inc ptr/0/ptr++",
	"dec ptr/0/ptr--",
	"add ptr/1/ptr += $1",
	"sub ptr/1/ptr -= $1",

	/* cell operations */
	"inc [ptr]/0/(*ptr)++",
	"dec [ptr]/0/(*ptr)--",
	"add [ptr]/1/*ptr += $1",
	"sub [ptr]/1/*ptr -= $1",

	/* I/O operations */
	"in [ptr]/0/*ptr = getchar()",
	"out [ptr]/0/putchar(*ptr)",

	/* control flow */
	"while [ptr]/0/while (*ptr)",
	"loop/0/end while",

	/* traps and nops */
	"trap/0/trap",
	"nop/0/nop",

	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_bf = {
	.meta = {
		.name = "bf",
		.desc = "brainfuck pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_bf,
	.version = R2_VERSION
};
#endif
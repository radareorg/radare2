/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_asm.h>

static const char *pseudo_rules[] = {
	"mov/2/$1 = $2",
	"ldc/2/$1 = $2",
	"ldcu/2/$1 = $2",
	"ldg.e/2/$1 = $2",
	"stl/2/$1 = $2",
	"stg.e/2/$1 = $2",
	"iadd3/6/$1 = $4 + $5",
	"imad/4/$1 = $2 * $3 + $4",
	"imad.wide.u32/4/$1 = (ut64)$2 * $3 + $4",
	"ffma/4/$1 = $2 * $3 + $4",
	"hfma2/5/$1 = $2 * $3 + $4",
	"lop3.lut/6/$1 = lop3($2, $3, $4, $5)",
	"shf.l.u32/4/$1 = $2 << $3",
	"s2r/2/$1 = $2",
	"isetp.ne.u32.and/5/$1 = ($3 != $4)",
	"bra/1/goto $1",
	"call/1/call $1",
	"exit/0/exit",
	"nop/0/nop",
	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_ptx = {
	.meta = {
		.name = "ptx",
		.desc = "nvidia sass ptx pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ptx,
	.version = R2_VERSION
};
#endif

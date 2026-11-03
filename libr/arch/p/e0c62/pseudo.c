/* radare2 - LGPL-3.0-only - Copyright 2026 - pancake */

#include <r_asm.h>

#define NEXT_X "x = (x & 0xf00) | ((x + 1) & 0xff)"
#define NEXT_Y "y = (y & 0xf00) | ((y + 1) & 0xff)"

static const char *index_rules[] = {
	"ld/2/$1 = ($1 & 0xf00) | $2",
	"inc/1/$1 = ($1 & 0xf00) | (($1 + 1) & 0xff)",
	NULL
};

static const char *pseudo_rules[] = {
	"ld/2/$1 = $2",
	"ldpx/2/$1 = $2; " NEXT_X,
	"ldpy/2/$1 = $2; " NEXT_Y,
	"lbpx/2/$1 = $2 & 0xf; " NEXT_X "; [x] = $2 >> 4; " NEXT_X,
	"add/2/$1 += $2",
	"adc/2/$1 += $2 + C",
	"sub/2/$1 -= $2",
	"sbc/2/$1 -= $2 + C",
	"acpx/2/$1 += $2 + C; " NEXT_X,
	"acpy/2/$1 += $2 + C; " NEXT_Y,
	"scpx/2/$1 -= $2 + C; " NEXT_X,
	"scpy/2/$1 -= $2 + C; " NEXT_Y,
	"inc/1/$1++",
	"dec/1/$1--",
	"cp/2/compare ($1, $2)",
	"fan/2/Z = (($1 & $2) == 0)",
	"and/2/$1 &= $2",
	"or/2/$1 |= $2",
	"xor/2/$1 ^= $2",
	"not/1/$1 ^= 0xf",
	"rlc/1/$1 = rotate_left_carry ($1, 1)",
	"rrc/1/$1 = rotate_right_carry ($1, 1)",
	"pset/1/np = $1",
	"jp/1/goto ((np << 8) | $1) << 1",
	"jp/2/if ($1) goto ((np << 8) | $2) << 1",
	"jpba/0/goto ((np << 8) | (b << 4) | a) << 1",
	"call/1/call ((((pc >> 1) & 0x1000) | ((np & 0xf) << 8) | $1) << 1)",
	"calz/1/call ((((pc >> 1) & 0x1000) | $1) << 1)",
	"ret/0/return",
	"rets/0/return; skip_next ()",
	"retd/1/[x] = $1 & 0xf; " NEXT_X "; [x] = $1 >> 4; " NEXT_X "; return",
	"push/1/[--sp] = $1",
	"pop/1/$1 = [sp++]",
	"set/2/$1 |= $2",
	"rst/2/$1 &= $2",
	"scf/0/C = 1",
	"rcf/0/C = 0",
	"szf/0/Z = 1",
	"rzf/0/Z = 0",
	"sdf/0/D = 1",
	"rdf/0/D = 0",
	"ei/0/I = 1",
	"di/0/I = 0",
	"halt/0/halt ()",
	"slp/0/sleep ()",
	"nop5/0/nop ()",
	"nop7/0/nop ()",
	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	char *input = strdup (data);
	if (!input) {
		return NULL;
	}
	r_str_case (input, false);
	bool index_syntax = r_str_startswith (input, "ld x,") || r_str_startswith (input, "ld y,") || !strcmp (input, "inc x") || !strcmp (input, "inc y");
	char *text = r_str_pseudo_transform (index_syntax? index_rules: pseudo_rules, input);
	free (input);
	text = r_str_replace_all (text, "mx", "[x]");
	text = r_str_replace_all (text, "my", "[y]");
	text = r_str_replace_all (text, "if (c)", "if (C)");
	text = r_str_replace_all (text, "if (nc)", "if (!C)");
	text = r_str_replace_all (text, "if (z)", "if (Z)");
	return r_str_replace_all (text, "if (nz)", "if (!Z)");
}

RAsmPlugin r_asm_plugin_e0c62 = {
	.meta = {
		.name = "e0c62",
		.desc = "Epson E0C62 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_e0c62,
	.version = R2_VERSION,
};
#endif

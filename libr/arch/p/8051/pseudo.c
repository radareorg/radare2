/* radare - LGPL - Copyright 2024 - pancake */

#include <r_asm.h>

static const char *pseudo_rules[] = {
	"mov/2/$1 = $2",
	"movc/2/$1 = $2",
	"movx/2/$1 = $2",
	"add/2/$1 += $2",
	"addc/2/$1 += $2 + c",
	"anl/2/$1 &= $2",
	"orl/2/$1 |= $2",
	"xrl/2/$1 ^= $2",
	"subb/2/$1 -= $2",
	"inc/1/$1++",
	"dec/1/$1--",
	"div/1/$1 = a / b",
	"mul/1/$1 = a * b",
	"xch/2/swap($1, $2)",
	"clr/1/$1 = 0",
	"setb/1/$1 = 1",
	"cpl/1/$1 = ~$1",
	"rl/1/$1 = rotate_left($1, 1)",
	"rlc/1/$1 = rotate_left($1, 1) | (c << 7)",
	"rr/1/$1 = rotate_right($1, 1)",
	"rrc/1/$1 = rotate_right($1, 1) | (c << 7)",
	"swap/1/$1 = (($1 & 0xf0) >> 4) | (($1 & 0x0f) << 4)",
	"jmp/1/goto $1",
	"ljmp/1/goto $1",
	"sjmp/1/goto $1",
	"jb/2/if ($1) goto $2",
	"jnb/2/if (!$1) goto $2",
	"jc/1/if (c) goto $1",
	"jnc/1/if (!c) goto $1",
	"jz/1/if (!a) goto $1",
	"jnz/1/if (a) goto $1",
	"cjne/3/if ($1 != $2) goto $3",
	"djnz/2/$1--; if ($1) goto $2",
	"acall/1/call $1",
	"lcall/1/call $1",
	"ret/0/return",
	"reti/0/return",
	"push/1/stack[$sp++] = $1",
	"pop/1/$1 = stack[--$sp]",
	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_8051 = {
	.meta = {
		.name = "8051",
		.desc = "8051 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_8051,
	.version = R2_VERSION
};
#endif

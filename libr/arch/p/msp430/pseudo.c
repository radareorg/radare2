/* radare - LGPL - Copyright 2025 - pancake */

#include <r_asm.h>

static const char *pseudo_rules[] = {
	/* Two-operand core instructions (word and byte forms) */
	"mov/2/$2 = $1",
	"mov.b/2/$2 = $1",
	"mov.w/2/$2 = $1",
	"add/2/$2 += $1",
	"add.b/2/$2 += $1",
	"add.w/2/$2 += $1",
	"addc/2/$2 += $1 + c",
	"addc.b/2/$2 += $1 + c",
	"addc.w/2/$2 += $1 + c",
	"adc/2/$2 += $1 + c",
	"adc.b/2/$2 += $1 + c",
	"sub/2/$2 -= $1",
	"sub.b/2/$2 -= $1",
	"sub.w/2/$2 -= $1",
	"subc/2/$2 = $2 - $1 - c",
	"subc.b/2/$2 = $2 - $1 - c",
	"subc.w/2/$2 = $2 - $1 - c",
	"and/2/$2 &= $1",
	"and.b/2/$2 &= $1",
	"bis/2/$2 |= $1",
	"bis.b/2/$2 |= $1",
	"bic/2/$2 &= ~$1",
	"bic.b/2/$2 &= ~$1",
	"xor/2/$2 ^= $1",
	"xor.b/2/$2 ^= $1",
	"movc/2/$2 = $1",
	"cmp/2/if ($2, $1)",
	"cmp.b/2/if ($2, $1)",

	/* One-operand instructions */
	"inc/1/$2++",
	"incd/1/$2 += 2",
	"dec/1/$2--",
	"decd/1/$2 -= 2",
	"clr/1/$2 = 0",
	"clr.b/1/$2 = 0",
	"neg/1/$2 = -$2",
	"swpb/1/$2 = swap_bytes ($2)",
	"sxt/1/$2 = sign_extend ($2)",
	"rlc/1/$2 = rotate_left ($2, 1)",
	"rlc.b/1/$2 = rotate_left ($2, 1)",
	"rrc/1/$2 = rotate_right ($2, 1)",
	"rrc.b/1/$2 = rotate_right ($2, 1)",
	"rl/1/$2 = rotate_left ($2, 1)",
	"rr/1/$2 = rotate_right ($2, 1)",
	"rlc.w/1/$2 = rotate_left ($2, 1)",
	"rrc.w/1/$2 = rotate_right ($2, 1)",
	"tst/1/if ($2 == 0) goto _TST_FALSE_",
	"tst.b/1/if ($2 == 0) goto _TST_FALSE_",
	"nop/0/; nop",

	/* Stack and register operations */
	"push/1/stack[$sp++] = $2",
	"pop/1/$2 = stack[--$sp]",
	"push sr/1/stack[$sp++] = sr",
	"pop sr/1/sr = stack[--$sp]",

	/* Control flow */
	"jmp/1/goto $2",
	"br/1/goto $2",
	"br/2/goto $2",
	"br @/1/goto $2",
	"call/1/$2 ()",
	"ret/0/return",
	"reti/0/return",

	/* Conditional jumps and common mnemonics */
	"jz/1/if (z) goto $2",
	"jnz/1/if (!z) goto $2",
	"jeq/1/if (z) goto $2",
	"jne/1/if (!z) goto $2",
	"jc/1/if (c) goto $2",
	"jnc/1/if (!c) goto $2",
	"jl/1/if (n ^ v) goto $2",
	"jge/1/if (!(n ^ v)) goto $2",
	"jmi/1/if (n) goto $2",
	"jpl/1/if (!n) goto $2",
	"jlo/1/if (!c) goto $2",
	"jhs/1/if (c) goto $2",
	"jl/2/if (n ^ v) goto $2",

	/* Branch to register/indirect examples seen in disasm */
	"br/1/goto $2",
	"br/1/goto *$2",
	"br @r/1/goto *$2",

	/* Misc / helpers for odd cases */
	"adc/2/$2 += $1 + c",
	"adc.b/2/$2 += $1 + c",
	"subc/2/$2 = $2 - $1 - c",
	"subc.b/2/$2 = $2 - $1 - c",
	"addc/2/$2 += $1 + c",
	"addc.b/2/$2 += $1 + c",
	"invalid/0/; invalid instruction",
	"invalid/1/; invalid $2",

	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform(pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_msp430 = {
	.meta = {
		.name = "msp430",
		.desc = "msp430 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_msp430,
	.version = R2_VERSION
};
#endif

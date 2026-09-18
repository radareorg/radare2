/* radare - LGPL - Copyright 2026 - xXAbieGamingXx */

#include <r_asm.h>
#include <r_lib.h>

const char *pseudo_rules[] = {
	/* data transfer */
	"ld/2/$1 = $2",
	"ex/2/swap ($1, $2)",
	"push/1/[--sp] = $1",
	"push/2/[--sp] = $1; [--sp] = $2",
	"pop/1/$1 = [sp++]",
	"pop/2/$2 = [sp++]; $1 = [sp++]",

	/* arithmetic */
	"add/2/$1 += $2",
	"adc/2/$1 += $2 + c",
	"sub/2/$1 -= $2",
	"sbc/2/$1 -= $2 + c",
	"inc/1/$1++",
	"dec/1/$1--",
	"neg/1/$1 = -$1",
	"cpl/1/$1 = ~$1",
	/* mlt stores the 16 bit product in hl, div splits quotient and remainder */
	"mlt/2/hl = $1 * $2",
	"div/2/(l, h) = divmod ($1, $2)",
	"cp/2/if ($1 == $2)",

	/* logic */
	"and/2/$1 &= $2",
	"or/2/$1 |= $2",
	"xor/2/$1 ^= $2",
	"bit/2/if (($1 & $2) == 0)",

	/* shift and rotate, rl and rr go through c, rlc and rrc are circular */
	"rl/1/$1 = rotate_left_carry ($1, 1)",
	"rlc/1/$1 = rotate_left ($1, 1)",
	"rr/1/$1 = rotate_right_carry ($1, 1)",
	"rrc/1/$1 = rotate_right ($1, 1)",
	"sla/1/$1 <<= 1",
	"sll/1/$1 <<= 1",
	"sra/1/$1 >>= 1",
	"srl/1/$1 >>= 1",
	"swap/1/$1 = swap_nibbles ($1)",

	/* bcd packing */
	"pack/0/a = pack_bcd (a)",
	"upck/0/ba = unpack_bcd (a)",
	"sep/0/ba = sign_extend (a)",

	/* branches */
	"jp/1/goto $1",
	"jrs/1/goto $1",
	"jrs/2/if ($1) goto $2",
	"jrl/1/goto $1",
	"jrl/2/if ($1) goto $2",
	"djr/2/b--; if (b != 0) goto $2",

	/* calls */
	"call/1/$1 ()",
	"cars/1/$1 ()",
	"cars/2/if ($1) $2 ()",
	"carl/1/$1 ()",
	"carl/2/if ($1) $2 ()",
	"int/1/interrupt ($1)",

	/* returns */
	"ret/0/return",
	"rets/0/return; skip_next ()",
	"rete/0/return_from_interrupt",

	/* system */
	"halt/0/halt_until_interrupt ()",
	"slp/0/sleep ()",

	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_s1c88 = {
	.meta = {
		.name = "s1c88",
		.desc = "S1C88 pseudo syntax",
		.author = "xXAbieGamingXx",
		.license = "LGPL-3.0-only",
	},
	.parse = &parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_s1c88,
	.version = R2_VERSION,
};
#endif

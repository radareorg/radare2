/* radare - LGPL - Copyright 2015-2025 - pancake, jvoisin */

#include <r_lib.h>
#include <r_asm.h>
#include <r_util/r_str.h>

static const char *pseudo_rules[] = {
	/* Arithmetic operations */
	"adc/2/$1 = $1 + $2 + carry",
	"add/1/$1 += $2",
	"add/2/$1 = $1 + $2",
	"add/3/$1 = $2 + $3",
	"add_s/2/$1 = $1 + $2",
	"add1/3/$1 = $2 + ($3 << 1)",
	"add2/3/$1 = $2 + ($3 << 2)",
	"add3/3/$1 = $2 + ($3 << 3)",
	"sbc/2/$1 = $1 - $2 - carry",
	"sub/1/$1 -= $2",
	"sub/2/$1 = $1 - $2",
	"sub/3/$1 = $2 - $3",
	"sub_s/2/$1 = $1 - $2",
	"sub1/3/$1 = $2 - ($3 << 1)",
	"sub2/3/$1 = $2 - ($3 << 2)",
	"sub3/3/$1 = $2 - ($3 << 3)",
	"rsub/2/$1 = $2 - $1",
	"neg/1/$1 = -$1",
	"neg_s/1/$1 = -$1",

	/* Bit manipulation */
	"and/1/$1 &= $2",
	"and/2/$1 &= $2",
	"and/3/$1 = $2 & $3",
	"and_s/2/$1 &= $2",
	"or/1/$1 |= $2",
	"or/2/$1 |= $2",
	"or/3/$1 = $2 | $3",
	"or_s/2/$1 |= $2",
	"xor/1/$1 ^= $2",
	"xor/2/$1 ^= $2",
	"xor/3/$1 = $2 ^ $3",
	"xor_s/2/$1 ^= $2",
	"not/1/$1 = ~$1",
	"not_s/1/$1 = ~$1",
	"bic/2/$1 &= ~$2",
	"bic_s/2/$1 &= ~$2",
	"bxor/2/$1 ^= $2",

	/* Bit operations */
	"bset/2/$2 |= (1 << $1)",
	"bset_s/2/$2 |= (1 << $1)",
	"bclr/2/$2 &= ~(1 << $1)",
	"bclr_s/2/$2 &= ~(1 << $1)",
	"btst/2/if (($2 & (1 << $1)) != 0)",
	"btst_s/2/if (($2 & (1 << $1)) != 0)",
	"bmsk/2/$1 &= (1 << $2) - 1",
	"bmsk_s/2/$1 &= (1 << $2) - 1",

	/* Shift operations */
	"asl/2/$1 <<= $2",
	"asl_s/2/$1 <<= $2",
	"asls/2/$1 <<= $2 (saturate)",
	"asr/2/$1 >>= $2",
	"asr_s/2/$1 >>= $2",
	"asrs/2/$1 >>= $2 (saturate)",
	"lsr/2/$1 >>= $2",
	"lsr_s/2/$1 >>= $2",
	"ror/2/$1 = rotate_right($1, $2)",
	"rlc/2/$1 = rotate_left_through_carry($1, $2)",
	"rrc/2/$1 = rotate_right_through_carry($1, $2)",

	/* Load operations */
	"ld/2/$1 = [$2]",
	"ld/3/$1 = [$2 + $3]",
	"ld_s/2/$1 = [$2]",
	"ldb/2/$1 = byte[$2]",
	"ldh/2/$1 = halfword[$2]",
	"lr/2/$1 = aux[$2]",

	/* Store operations */
	"st/2/[$2] = $1",
	"st/3/[$2 + $3] = $1",
	"st_s/2/[$2] = $1",
	"stb/2/byte[$2] = $1",
	"sth/2/halfword[$2] = $1",
	"sr/2/aux[$2] = $1",

	/* Move operations */
	"mov/2/$1 = $2",
	"mov_s/2/$1 = $2",
	"ext/2/$1 = zero_extend($2)",
	"ext_s/2/$1 = zero_extend($2)",
	"sex/2/$1 = sign_extend($2)",
	"sex_s/2/$1 = sign_extend($2)",

	/* Stack operations */
	"push/1/stack[sp++] = $1",
	"push_s/1/stack[sp++] = $1",
	"pop/1/$1 = stack[--sp]",
	"pop_s/1/$1 = stack[--sp]",

	/* Compare operations */
	"cmp/2/if ($1 == $2)",
	"cmp/3/if ($2 == $3)",
	"cmp_s/2/if ($1 == $2)",
	"tst/2/if ($1 & $2)",
	"tst_s/2/if ($1 & $2)",
	"rcmp/2/if ($2 == $1)",

	/* Multiply operations */
	"mpy/3/$1 = $2 * $3",
	"mpyh/3/$1 = high($2 * $3)",
	"mpyhu/3/$1 = high(($2 * $3) unsigned)",
	"mpyu/3/$1 = ($2 * $3) unsigned",
	"mul64/3/$1 = $2 * $3",
	"mulu64/3/$1 = ($2 * $3) unsigned",

	/* Jump operations */
	"jmp/1/goto $1",
	"jcc/2/if ($1) goto $2",
	"jcc_s/2/if ($1) goto $2",
	"jl/1/$1()",
	"jl_s/1/$1()",
	"jlcc/2/if ($1) $2()",
	"bl_s/1/$1()",
	"blcc/2/if ($1) $2()",
	"call/1/$1()",
	"call/2/if ($1) $2()",

	/* Branch operations */
	"b/1/goto $1",
	"bbit0/2/if (($2 & (1 << $1)) == 0) goto next",
	"bbit1/2/if (($2 & (1 << $1)) != 0) goto next",
	"bcc/1/if (carry) goto $1",
	"bcc_s/1/if (carry) goto $1",
	"brcc/2/if ($1 < $2) goto next",
	"brcc_s/2/if ($1 < $2) goto next",

	/* Loop operations */
	"lpcc/1/loop $1",

	/* Status and control */
	"flag/1/status = $1",
	"sleep/0/sleep()",
	"sync/0/synchronize()",
	"swi/1/software_interrupt($1)",
	"trap/0/trap()",
	"trap0/0/trap(0)",
	"trap_s/1/trap($1)",
	"brk/0/break()",
	"brk_s/0/break()",
	"rtie/0/return_from_interrupt()",

	/* Utility operations */
	"nop/0/; nop",
	"nop_s/0/; nop",
	"ex/2/swap($1, $2)",
	"swap/2/swap_16bit($1, $2)",
	"norm/2/$1 = normalize($2)",
	"normw/2/$1 = normalize_16bit($2)",
	"divaw/2/$1 = divide_assist($2)",
	"max/3/$1 = max($2, $3)",
	"min/3/$1 = min($2, $3)",
	"abs/1/$1 = abs($1)",
	"abs_s/1/$1 = abs($1)",
	"rnd16/1/$1 = round_to_word($1)",
	"sat16/1/$1 = saturate_to_word($1)",
	"prefetch/1/prefetch($1)",
	"negs/1/$1 = negate_saturate($1)",
	"negsw/1/$1 = negate_saturate_word($1)",
	"adds/2/$1 = add_saturate($1, $2)",
	"subs/2/$1 = sub_saturate($1, $2)",
	"addsdw/3/$1 = add_saturate_dualword($2, $3)",
	"subsdw/3/$1 = sub_saturate_dualword($2, $3)",
	"abss/1/$1 = abs_saturate($1)",
	"abssw/1/$1 = abs_saturate_word($1)",
	"asls/2/$1 = asl_saturate($1, $2)",
	"asrs/2/$1 = asr_saturate($1, $2)",
	"negs/1/$1 = negate_saturate($1)",
	"ex/2/atomic_exchange($1, $2)",

	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_arc_pseudo = {
	.meta = {
		.name = "arc",
		.desc = "ARC pseudo syntax",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arc_pseudo,
	.version = R2_VERSION
};
#endif
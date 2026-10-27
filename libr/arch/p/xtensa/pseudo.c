/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_asm.h>

static const char *pseudo_rules[] = {
	/* loads and stores */
	"l32r/2/$1 = [$2]",
	"l32i/3/$1 = [$2 + $3]",
	"l32i.n/3/$1 = [$2 + $3]",
	"l32ai/3/$1 = [$2 + $3]",
	"l32e/3/$1 = [$2 + $3]",
	"l16ui/3/$1 = (ut16)[$2 + $3]",
	"l16si/3/$1 = (st16)[$2 + $3]",
	"l8ui/3/$1 = (ut8)[$2 + $3]",
	"s32i/3/[$2 + $3] = $1",
	"s32i.n/3/[$2 + $3] = $1",
	"s32ri/3/[$2 + $3] = $1",
	"s32e/3/[$2 + $3] = $1",
	"s16i/3/(ut16)[$2 + $3] = $1",
	"s8i/3/(ut8)[$2 + $3] = $1",
	"s32c1i/3/$1 = cas ([$2 + $3], scompare1, $1)",
	"lsi/3/$1 = [$2 + $3]",
	"lsiu/3/$2 += $3; $1 = [$2]",
	"lsx/3/$1 = [$2 + $3]",
	"lsxu/3/$2 += $3; $1 = [$2]",
	"ssi/3/[$2 + $3] = $1",
	"ssiu/3/$2 += $3; [$2] = $1",
	"ssx/3/[$2 + $3] = $1",
	"ssxu/3/$2 += $3; [$2] = $1",

	/* moves */
	"mov/2/$1 = $2",
	"mov.n/2/$1 = $2",
	"mov.s/2/$1 = $2",
	"movi/2/$1 = $2",
	"movi.n/2/$1 = $2",
	"movsp/2/$1 = $2",
	"rfr/2/$1 = $2",
	"wfr/2/$1 = $2",
	"moveqz/3/if ($3 == 0) $1 = $2",
	"movnez/3/if ($3 != 0) $1 = $2",
	"movltz/3/if ($3 < 0) $1 = $2",
	"movgez/3/if ($3 >= 0) $1 = $2",
	"movt/3/if ($3) $1 = $2",
	"movf/3/if (!$3) $1 = $2",
	"moveqz.s/3/if ($3 == 0) $1 = $2",
	"movnez.s/3/if ($3 != 0) $1 = $2",
	"movltz.s/3/if ($3 < 0) $1 = $2",
	"movgez.s/3/if ($3 >= 0) $1 = $2",
	"movt.s/3/if ($3) $1 = $2",
	"movf.s/3/if (!$3) $1 = $2",

	/* arithmetic and logic */
	"add/3/$1 = $2 + $3",
	"add.n/3/$1 = $2 + $3",
	"addi/3/$1 = $2 + $3",
	"addi.n/3/$1 = $2 + $3",
	"addmi/3/$1 = $2 + $3",
	"addx2/3/$1 = ($2 << 1) + $3",
	"addx4/3/$1 = ($2 << 2) + $3",
	"addx8/3/$1 = ($2 << 3) + $3",
	"sub/3/$1 = $2 - $3",
	"subx2/3/$1 = ($2 << 1) - $3",
	"subx4/3/$1 = ($2 << 2) - $3",
	"subx8/3/$1 = ($2 << 3) - $3",
	"neg/2/$1 = -$2",
	"abs/2/$1 = abs ($2)",
	"and/3/$1 = $2 & $3",
	"or/3/$1 = $2 | $3",
	"xor/3/$1 = $2 ^ $3",
	"mull/3/$1 = $2 * $3",
	"muluh/3/$1 = ((ut64)$2 * $3) >> 32",
	"mulsh/3/$1 = ((st64)$2 * $3) >> 32",
	"mul16u/3/$1 = (ut16)$2 * (ut16)$3",
	"mul16s/3/$1 = (st16)$2 * (st16)$3",
	"quou/3/$1 = $2 / $3",
	"quos/3/$1 = (st32)$2 / $3",
	"remu/3/$1 = $2 % $3",
	"rems/3/$1 = (st32)$2 % $3",
	"min/3/$1 = min ($2, $3)",
	"max/3/$1 = max ($2, $3)",
	"minu/3/$1 = minu ($2, $3)",
	"maxu/3/$1 = maxu ($2, $3)",
	"sext/3/$1 = sext ($2, $3)",
	"clamps/3/$1 = clamps ($2, $3)",
	"nsa/2/$1 = nsa ($2)",
	"nsau/2/$1 = nsau ($2)",

	/* shifts */
	"slli/3/$1 = $2 << $3",
	"srli/3/$1 = $2 >> $3",
	"srai/3/$1 = (st32)$2 >> $3",
	"ssl/1/sar = 32 - $1",
	"ssr/1/sar = $1",
	"ssai/1/sar = $1",
	"ssa8l/1/sar = $1 << 3",
	"ssa8b/1/sar = 32 - ($1 << 3)",
	"sll/2/$1 = $2 << (32 - sar)",
	"srl/2/$1 = $2 >> sar",
	"sra/2/$1 = (st32)$2 >> sar",
	"src/3/$1 = ($2:$3) >> sar",

	/* floating point */
	"add.s/3/$1 = $2 + $3",
	"sub.s/3/$1 = $2 - $3",
	"mul.s/3/$1 = $2 * $3",
	"madd.s/3/$1 += $2 * $3",
	"msub.s/3/$1 -= $2 * $3",
	"neg.s/2/$1 = -$2",
	"abs.s/2/$1 = abs ($2)",
	"float.s/3/$1 = (float)$2 / (1 << $3)",
	"ufloat.s/3/$1 = (float)(ut32)$2 / (1 << $3)",
	"trunc.s/3/$1 = (st32)($2 * (1 << $3))",
	"utrunc.s/3/$1 = (ut32)($2 * (1 << $3))",
	"round.s/3/$1 = round ($2 * (1 << $3))",
	"floor.s/3/$1 = floor ($2 * (1 << $3))",
	"ceil.s/3/$1 = ceil ($2 * (1 << $3))",
	"oeq.s/3/$1 = $2 == $3",
	"olt.s/3/$1 = $2 < $3",
	"ole.s/3/$1 = $2 <= $3",
	"ueq.s/3/$1 = $2 == $3",
	"ult.s/3/$1 = $2 < $3",
	"ule.s/3/$1 = $2 <= $3",
	"un.s/3/$1 = isnan ($2) || isnan ($3)",

	/* boolean registers */
	"andb/3/$1 = $2 & $3",
	"andbc/3/$1 = $2 & !$3",
	"orb/3/$1 = $2 | $3",
	"orbc/3/$1 = $2 | !$3",
	"xorb/3/$1 = $2 ^ $3",

	/* control flow */
	"j/1/goto $1",
	"jx/1/goto $1",
	"call0/1/$1 ()",
	"call4/1/$1 ()",
	"call8/1/$1 ()",
	"call12/1/$1 ()",
	"callx0/1/$1 ()",
	"callx4/1/$1 ()",
	"callx8/1/$1 ()",
	"callx12/1/$1 ()",
	"ret/0/return",
	"ret.n/0/return",
	"retw/0/return",
	"retw.n/0/return",
	"beqz/2/if ($1 == 0) goto $2",
	"beqz.n/2/if ($1 == 0) goto $2",
	"bnez/2/if ($1 != 0) goto $2",
	"bnez.n/2/if ($1 != 0) goto $2",
	"bltz/2/if ($1 < 0) goto $2",
	"bgez/2/if ($1 >= 0) goto $2",
	"beq/3/if ($1 == $2) goto $3",
	"bne/3/if ($1 != $2) goto $3",
	"blt/3/if ($1 < $2) goto $3",
	"bge/3/if ($1 >= $2) goto $3",
	"bltu/3/if ((ut32)$1 < $2) goto $3",
	"bgeu/3/if ((ut32)$1 >= $2) goto $3",
	"beqi/3/if ($1 == $2) goto $3",
	"bnei/3/if ($1 != $2) goto $3",
	"blti/3/if ($1 < $2) goto $3",
	"bgei/3/if ($1 >= $2) goto $3",
	"bltui/3/if ((ut32)$1 < $2) goto $3",
	"bgeui/3/if ((ut32)$1 >= $2) goto $3",
	"bany/3/if ($1 & $2) goto $3",
	"bnone/3/if (!($1 & $2)) goto $3",
	"ball/3/if (($1 & $2) == $2) goto $3",
	"bnall/3/if (($1 & $2) != $2) goto $3",
	"bbs/3/if ($1 & (1 << $2)) goto $3",
	"bbc/3/if (!($1 & (1 << $2))) goto $3",
	"bbsi/3/if ($1 & (1 << $2)) goto $3",
	"bbci/3/if (!($1 & (1 << $2))) goto $3",
	"bt/2/if ($1) goto $2",
	"bf/2/if (!$1) goto $2",
	"loop/2/loop $1 times until $2",
	"loopnez/2/if ($1) loop $1 times until $2",
	"loopgtz/2/if ($1 > 0) loop $1 times until $2",

	/* system */
	"rsil/2/$1 = ps; intlevel = $2",
	"nop/0/nop",
	"nop.n/0/nop",
	"ill/0/trap",
	"ill.n/0/trap",
	NULL
};

static char *special_register(const char *data) {
	const char *space = strchr (data, ' ');
	if (!space || space - data < 5 || data[3] != '.') {
		return NULL;
	}
	char *sr = r_str_ndup (data + 4, space - data - 4);
	const char *reg = r_str_trim_head_ro (space + 1);
	char *res = NULL;
	if (r_str_startswith (data, "rsr.") || r_str_startswith (data, "rur.")) {
		res = r_str_newf ("%s = %s", reg, sr);
	} else if (r_str_startswith (data, "wsr.") || r_str_startswith (data, "wur.")) {
		res = r_str_newf ("%s = %s", sr, reg);
	} else if (r_str_startswith (data, "xsr.")) {
		res = r_str_newf ("swap (%s, %s)", reg, sr);
	}
	free (sr);
	return res;
}

static char *extract_unsigned(const char *data) {
	char dst[32], src[32];
	int shift, bits;
	if (sscanf (data, "extui %31[^,], %31[^,], %d, %d", dst, src, &shift, &bits) != 4 || bits < 1 || bits > 32) {
		return NULL;
	}
	const ut32 mask = (bits == 32)? UT32_MAX: (1U << bits) - 1;
	if (!shift) {
		return r_str_newf ("%s = %s & 0x%x", dst, src, mask);
	}
	return r_str_newf ("%s = (%s >> %d) & 0x%x", dst, src, shift, mask);
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	char *res = special_register (data);
	if (!res && r_str_startswith (data, "extui ")) {
		res = extract_unsigned (data);
	}
	if (!res) {
		res = r_str_pseudo_transform (pseudo_rules, data);
	}
	return r_str_replace (res, " + 0]", "]", true);
}

RAsmPlugin r_asm_plugin_xtensa = {
	.meta = {
		.name = "xtensa",
		.desc = "Xtensa pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_xtensa,
	.version = R2_VERSION
};
#endif

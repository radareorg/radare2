/* radare - LGPL - Copyright 2025 - pancake */

#include <r_asm.h>

// Operand counts match actual disassembler output:
// - Bracketed memory operands like [r1 + 4] count as 1 operand
// - 16-bit *45 instructions: 2 ops (reg, reg/imm)
// - 16-bit *333 load/store: 2 ops (reg, [mem])
// - 16-bit *333 alu: 3 ops (reg, reg, reg/imm)
// - 32-bit load/store imm: 2 ops (reg, [mem])
// - 32-bit alu: 3 ops (reg, reg, reg/imm)
// - 32-bit *_slli/*_srli: 4 ops (reg, reg, reg, #imm)
// - 32-bit divr/divsr: 4 ops (reg, reg, reg, reg)
static const char *pseudo_rules[] = {
	// return / control flow
	"ret/0/return",
	"ret/1/return",
	"ret5/1/return",
	"iret/0/return",
	"ifret/0/ifret",
	"ifret16/0/ifret",

	// jumps
	"j/1/goto $1",
	"j8/1/goto $1",
	"jr/1/goto $1",
	"jr5/1/goto $1",
	"jal/1/$1 ()",
	"jral/2/$1 ()",
	"jral5/1/$1 ()",
	"ifcall/1/$1 ()",
	"bgezal/2/if ($1 >= 0) $2 ()",
	"bltzal/2/if ($1 < 0) $2 ()",

	// conditional branches
	"beq/3/if ($1 == $2) goto $3",
	"bne/3/if ($1 != $2) goto $3",
	"beqz/2/if (!$1) goto $2",
	"bnez/2/if ($1) goto $2",
	"beqz38/2/if (!$1) goto $2",
	"bnez38/2/if ($1) goto $2",
	"beqs38/2/if ($1 == r5) goto $2",
	"bnes38/2/if ($1 != r5) goto $2",
	"beqzs8/1/if (!r5) goto $1",
	"bnezs8/1/if (r5) goto $1",
	"beqc/3/if ($1 == $2) goto $3",
	"bnec/3/if ($1 != $2) goto $3",
	"bgtz/2/if ($1 > 0) goto $2",
	"bgez/2/if ($1 >= 0) goto $2",
	"bltz/2/if ($1 < 0) goto $2",
	"blez/2/if ($1 <= 0) goto $2",

	// moves
	"mov/2/$1 = $2",
	"mov55/2/$1 = $2",
	"movi/2/$1 = $2",
	"movi55/2/$1 = $2",
	"movpi45/2/$1 = $2",
	"movd44/2/$1 = $2",
	"sethi/2/$1 = ($2 << 16)",
	"mfsr/2/$1 = $2",
	"mtsr/2/$2 = $1",
	"mfusr/2/$1 = $2",
	"mtusr/2/$2 = $1",
	"cmovz/3/if (!$3) $1 = $2",
	"cmovn/3/if ($3) $1 = $2",

	// add
	"add/3/$1 = $2 + $3",
	"add45/2/$1 += $2",
	"add333/3/$1 = $2 + $3",
	"addi/3/$1 = $2 + $3",
	"addi45/2/$1 += $2",
	"addi333/3/$1 = $2 + $3",
	"addi10s/1/sp += $1",
	"addri36.sp/2/$1 = sp + $2",
	"addi.gp/2/$1 = gp + $2",
	"addri/3/$1 = $2 + $3",
	"add5.pc/1/$1 = pc + $1",
	"add_slli/4/$1 = $2 + ($3 << $4)",
	"add_srli/4/$1 = $2 + ($3 >> $4)",
	"maddr32/3/$1 += $2 * $3",

	// sub
	"sub/3/$1 = $2 - $3",
	"sub45/2/$1 -= $2",
	"sub333/3/$1 = $2 - $3",
	"subi/3/$1 = $2 - $3",
	"subi45/2/$1 -= $2",
	"subi333/3/$1 = $2 - $3",
	"subri/3/$1 = $2 - $3",
	"sub_slli/4/$1 = $2 - ($3 << $4)",
	"sub_srli/4/$1 = $2 - ($3 >> $4)",
	"msubr32/3/$1 -= $2 * $3",
	"neg33/2/$1 = -$2",

	// mul / div
	"mul/3/$1 = $2 * $3",
	"mul33/2/$1 *= $2",
	"mult/3/$1 = $2 * $3",
	"madd/3/$1 += $2 * $3",
	"msub/3/$1 -= $2 * $3",
	"divr/4/$1 = $3 / $4",
	"divsr/4/$1 = (signed)$3 / $4",
	"div/3/$1 = $2 / $3",
	"divs/3/$1 = (signed)$2 / $3",

	// bitwise
	"and/3/$1 = $2 & $3",
	"and33/2/$1 &= $2",
	"andi/3/$1 = $2 & $3",
	"and_slli/4/$1 = $2 & ($3 << $4)",
	"and_srli/4/$1 = $2 & ($3 >> $4)",
	"or/3/$1 = $2 | $3",
	"or33/2/$1 |= $2",
	"ori/3/$1 = $2 | $3",
	"or_slli/4/$1 = $2 | ($3 << $4)",
	"or_srli/4/$1 = $2 | ($3 >> $4)",
	"xor/3/$1 = $2 ^ $3",
	"xor33/2/$1 ^= $2",
	"xori/3/$1 = $2 ^ $3",
	"xor_slli/4/$1 = $2 ^ ($3 << $4)",
	"xor_srli/4/$1 = $2 ^ ($3 >> $4)",
	"nor/3/$1 = ~($2 | $3)",
	"not33/2/$1 = ~$2",
	"bitc/3/$1 = $2 & ~$3",
	"bitci/3/$1 = $2 & ~$3",

	// shifts
	"sll/3/$1 = $2 << $3",
	"slli/3/$1 = $2 << $3",
	"slli333/3/$1 = $2 << $3",
	"srl/3/$1 = $2 >> $3",
	"srli/3/$1 = $2 >> $3",
	"srli45/2/$1 >>= $2",
	"sra/3/$1 = (signed)$2 >> $3",
	"srai/3/$1 = (signed)$2 >> $3",
	"srai45/2/$1 = (signed)$1 >> $2",
	"rotr/3/$1 = ror($2, $3)",
	"rotri/3/$1 = ror($2, $3)",

	// compare / set
	"slt/3/$1 = ($2 < $3)",
	"slts/3/$1 = (signed)($2 < $3)",
	"slt45/2/$1 = ($1 < $2)",
	"slts45/2/$1 = (signed)($1 < $2)",
	"slti/3/$1 = ($2 < $3)",
	"sltsi/3/$1 = (signed)($2 < $3)",
	"slti45/2/$1 = ($1 < $2)",
	"sltsi45/2/$1 = (signed)($1 < $2)",

	// extend / extract
	"zeh/2/$1 = (uint16_t)$2",
	"zeh33/2/$1 = (uint16_t)$2",
	"zeb/2/$1 = (uint8_t)$2",
	"zeb33/2/$1 = (uint8_t)$2",
	"seh/2/$1 = (int16_t)$2",
	"seh33/2/$1 = (int16_t)$2",
	"seb/2/$1 = (int8_t)$2",
	"seb33/2/$1 = (int8_t)$2",
	"xlsb/2/$1 = $2 & 1",
	"xlsb33/2/$1 = $2 & 1",
	"abs/2/$1 = abs($2)",
	"fexti33/2/$1 &= (1 << $2) - 1",

	// 32-bit load (reg, [mem]) - bracket already in operand
	"lwi/2/$1 = $2",
	"lhi/2/$1 = (half)$2",
	"lbi/2/$1 = (byte)$2",
	"ldi/2/$1 = (dword)$2",
	"lbsi/2/$1 = (int8_t)$2",
	"lhsi/2/$1 = (int16_t)$2",
	"lwsi/2/$1 = (signed)$2",
	"llw/2/$1 = $2",

	// 32-bit store (reg, [mem])
	"swi/2/$2 = $1",
	"shi/2/$2 = (half)$1",
	"sbi/2/$2 = (byte)$1",
	"sdi/2/$2 = (dword)$1",
	"scw/2/$2 = $1",

	// 32-bit load/store with base update (reg, [base], imm/shift)
	"lwi.bi/3/$1 = $2; $2 += $3",
	"lhi.bi/3/$1 = $2; $2 += $3",
	"lbi.bi/3/$1 = $2; $2 += $3",
	"ldi.bi/3/$1 = $2; $2 += $3",
	"lbsi.bi/3/$1 = (int8_t)$2; $2 += $3",
	"lhsi.bi/3/$1 = (int16_t)$2; $2 += $3",
	"lwsi.bi/3/$1 = (signed)$2; $2 += $3",
	"swi.bi/3/$2 = $1; $2 += $3",
	"shi.bi/3/$2 = (half)$1; $2 += $3",
	"sbi.bi/3/$2 = (byte)$1; $2 += $3",
	"sdi.bi/3/$2 = (dword)$1; $2 += $3",

	// register-indexed load/store (reg, [mem]) - 2 ops
	"lw/2/$1 = $2",
	"lh/2/$1 = (half)$2",
	"lb/2/$1 = (byte)$2",
	"ld/2/$1 = (dword)$2",
	"lbs/2/$1 = (int8_t)$2",
	"lhs/2/$1 = (int16_t)$2",
	"lws/2/$1 = (signed)$2",
	"sw/2/$2 = $1",
	"sb/2/$2 = (byte)$1",
	"sd/2/$2 = (dword)$1",

	// 16-bit load/store (reg, [mem]) - bracket in operand
	"lwi333/2/$1 = $2",
	"swi333/2/$2 = $1",
	"lhi333/2/$1 = (half)$2",
	"shi333/2/$2 = (half)$1",
	"lbi333/2/$1 = (byte)$2",
	"sbi333/2/$2 = (byte)$1",
	"lwi450/2/$1 = $2",
	"swi450/2/$2 = $1",
	"lwi45/2/$1 = $2",
	"swi45/2/$2 = $1",
	"lwi37/2/$1 = $2",
	"swi37/2/$2 = $1",

	// GP-relative load/store (reg, [+ offset])
	"lwi.gp/2/$1 = [gp + $2]",
	"swi.gp/2/[gp + $2] = $1",
	"lbi.gp/2/$1 = (byte)[gp + $2]",
	"sbi.gp/2/[gp + $2] = (byte)$1",
	"lhi.gp/2/$1 = (half)[gp + $2]",
	"shi.gp/2/[gp + $2] = (half)$1",
	"lbsi.gp/2/$1 = (int8_t)[gp + $2]",
	"lhsi.gp/2/$1 = (int16_t)[gp + $2]",

	// FPU load/store
	"fls/2/$1 = (float)$2",
	"fld/2/$1 = (double)$2",
	"flsi/2/$1 = (float)$2",
	"fldi/2/$1 = (double)$2",
	"fss/2/$2 = (float)$1",
	"fsd/2/$2 = (double)$1",
	"fssi/2/$2 = (float)$1",
	"fsdi/2/$2 = (double)$1",

	// push/pop (reg, imm)
	"push25/2/push($1, $2)",
	"pop25/2/pop($1, $2)",

	// multi load/store
	"lmw.bi/4/load_multiple($1, $2, $3, $4)",
	"lmw.adm/4/load_multiple($1, $2, $3, $4)",
	"lmw.bim/4/load_multiple($1, $2, $3, $4)",
	"smw.bi/4/store_multiple($1, $2, $3, $4)",
	"smw.adm/4/store_multiple($1, $2, $3, $4)",
	"smw.bim/4/store_multiple($1, $2, $3, $4)",

	// traps / system
	"syscall/1/syscall($1)",
	"break/1/break($1)",
	"break16/1/break($1)",
	"trap/1/trap($1)",
	"teqz/2/if (!$1) trap($2)",
	"tnez/2/if ($1) trap($2)",
	"nop/0/nop",
	"dsb/0/dsb",
	"isb/0/isb",
	"msync/0/msync",
	"isync/0/isync",
	"standby/0/standby",
	"standby/1/standby($1)",
	"cctl/0/cctl",
	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

static char *patch(RAsmPluginSession *aps, RAnalOp *aop, const char *op) {
	const int size = aop->size;
	if (!strcmp (op, "nop")) {
		if (size == 2) {
			return strdup ("wx 0092"); // 16-bit nop (mov55 r0, r0)
		}
		if (size == 4) {
			return strdup ("wx 40000009"); // 32-bit nop (srli r0, r0, 0)
		}
		return NULL;
	}
	if (!strcmp (op, "ret")) {
		if (size >= 4) {
			return strdup ("wx 4a005c20"); // ret $lp
		}
		if (size >= 2) {
			return strdup ("wx dd64"); // ret5 $lp
		}
		return NULL;
	}
	if (!strcmp (op, "jinf")) {
		if (size >= 2) {
			return strdup ("wx d4fe"); // j8 self
		}
		return NULL;
	}
	return NULL;
}

RAsmPlugin r_asm_plugin_nds32 = {
	.meta = {
		.name = "nds32",
		.desc = "NDS32 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
	.patch = patch,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_nds32,
	.version = R2_VERSION
};
#endif

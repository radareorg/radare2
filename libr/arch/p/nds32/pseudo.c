/* radare - LGPL - Copyright 2025 - pancake */

#include <r_asm.h>

static const char *pseudo_rules[] = {
	"movi55/2/$1 = $2",
	"lwi333/3/$1 = [$2 + $3]",
	"swi333/3/[$2 + $3] = $1",
	"push25/1/stack[$sp++] = $1",
	"pop25/1/$1 = stack[--$sp]",
	"beqzs8/2/if (!$1) goto $2",
	"j8/1/goto $1",
	"bitci/3/$1 = $2 & ~(1 << $3)",
	"ori/3/$1 = $2 | $3",
	"addi45/3/$1 = $2 + $3",
	"subri45/3/$1 = $3 - $2",
	"andi45/3/$1 = $2 & $3",
	"ori45/3/$1 = $2 | $3",
	"xori45/3/$1 = $2 ^ $3",
	"slti45/3/$1 = ($2 < $3)",
	"sltsi45/3/$1 = ($2 < $3)",
	"beqz38/2/if (!$1) goto $2",
	"bnez38/2/if ($1) goto $2",
	"jr5/1/goto $1",
	"jal/1/$1 ()",
	"ret/0/return",
	"syscall/0/syscall",
	"break/0/break",
	"nop/0/nop",
	"sbi.gp/2/[$gp + $2] = $1",
	"lbi/2/$1 = [$2]",
	"sbi333/3/[$2 + $3] = $1",
	"mov55/2/$1 = $2",
	"lmw.bi/2/load_multiple($1, $2)",
	"addri36.sp/2/$1 = $sp + $2",
	"shi.bi/3/[$2] = $1; $2 += $3",
	"jral5/1/$1 ()",
	"lwi.gp/2/$1 = [$gp + $2]",
	"ret5/1/return $1",
	"bnec/3/if ($1 != $2) goto $3",
	"addi/3/$1 = $2 + $3",
	"addi.gp/2/$1 = $gp + $2",
	"beq/3/if ($1 == $2) goto $3",
	"mfsr/2/$1 = $2",
	"movi/2/$1 = $2",
	"swi/2/[$2] = $1",
	"lmw.bi/2/load_multiple($1, $2)",
	"sbi333/3/[$2 + $3] = $1",
	"swi450/3/[$2 + $3] = $1",
	"srai45/3/$1 = $2 >> $3",
	"beqc/3/if ($1 == $2) goto $3",
	"addi10s/2/$1 = $1 + $2",
	"movpi45/2/$1 = $2",
	"or_slli/4/$1 = $2 | ($3 << $4)",
	"maddr32/3/$1 = $1 + $2 * $3",
	"sethi/2/$1 = ($2 << 16)",
	"divr/3/$1 = $2 / $3",
	"or33/3/$1 = $2 | $3",
	"srli45/3/$1 = $2 >> $3",
	"lwi/2/$1 = [$2]",
	"zeh33/2/$1 = ($2 & 0xffff)",
	"movd44/2/$1 = $2",
	"xlsb33/2/$1 = ($2 & 1)",
	"andi/3/$1 = $2 & $3",
	"jr/1/goto $1",
	"subri/3/$1 = $3 - $2",
	"lwsi.bi/3/$1 = [$2]; $2 += $3",
	"slti45/3/$1 = ($2 < $3)",
	"smw.bi/2/store_multiple($1, $2)",
	"bnezs8/2/if ($1) goto $2",
	"slli/3/$1 = $2 << $3",
	"lbi333/3/$1 = [$2 + $3]",
	"swi45/3/[$2 + $3] = $1",
	"swi.gp/2/[$gp + $2] = $1",
	"sbi/2/[$2] = $1",
	"shi.gp/2/[$gp + $2] = $1",
	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_nds32 = {
	.meta = {
		.name = "nds32",
		.desc = "NDS32 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_nds32,
	.version = R2_VERSION
};
#endif

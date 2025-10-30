/* radare - LGPL - Copyright 2025 - pancake */

#include <r_asm.h>

static const char *pseudo_rules[] = {
	"ldw/3/$1 = [$3 + $2]",
	"stw/3/[$3 + $2] = $1",
	"ldwm/3/$1 = [$3 + $2]; $3 += 4",
	"stwm/3/[$3 + $2] = $1; $3 += 4",
	"ldb/3/$1 = .byte [$3 + $2]",
	"ldh/3/$1 = .word [$3 + $2]",
	"ldd/3/$1 = [$3 + $2]",
	"ldil/2/$2 = $1",
	"ldo/3/$1 = $3 + $2",
	"stby/3/[$3 + $2] = .byte $1",
	"fstw/3/[$3 + $2] = $1",
	"fldw/3/$1 = [$3 + $2]",
	"add/3/$3 = $1 + $2",
	"sub/3/$3 = $1 - $2",
	"and/3/$3 = $1 & $2",
	"or/3/$3 = $1 | $2",
	"xor/3/$3 = $1 ^ $2",
	"andcm/3/$3 = $1 & ~$2",
	"uaddcm/3/$3 = $1 + $2 + carry",
	"cmp/2/compare $1, $2",
	"cmpiclr/3/compare $2, $1",
	"cmpb/3/if ($1 ? $2) goto $3",
	"cmpib/3/if ($1 ? $2) goto $3",
	"be/1/if equal goto $1",
	"bne/1/if not_equal goto $1",
	"bl/2/call $1",
	"bv/2/$1 ($2)",
	"b/2/goto $1",
	"addb/3/if ($1 ? $2) goto $3",
	"movib/3/if ($2 == $1) goto $3",
	"nop/0/nop",
	"ret/0/return",
	"addi/3/$1 = $2 + $3",
	"subi/3/$1 = $2 - $3",
	"andi/3/$1 = $2 & $3",
	"ori/3/$1 = $2 | $3",
	"xori/3/$1 = $2 ^ $3",
	"addil/3/$3 = $2 + ($1 << 21)",
	"ldi/2/$1 = $2",
	"mov/2/$1 = $2",
	"shl/3/$3 = $1 << $2",
	"shr/3/$3 = $1 >> $2",
	"shrp/3/$3 = $1 >> $2",
	"shlp/3/$3 = $1 << $2",
	"extrw/4/$4 = ($1 >> $2) & ((1 << $3) - 1)",
	"extrd/4/$4 = ($1 >> $2) & ((1 << $3) - 1)",
	"depwi/4/$4 = ($4 & ~(((1 << $3) - 1) << $2)) | (($1 & ((1 << $3) - 1)) << $2)",
	"depdi/4/$4 = ($4 & ~(((1 << $3) - 1) << $2)) | (($1 & ((1 << $3) - 1)) << $2)",
	"depd/4/$4 = ($4 & ~(((1 << $3) - 1) << $2)) | (($1 & ((1 << $3) - 1)) << $2)",
	"hshladd/4/$4 = ($1 << $2) + $3",
	"jmp/1/goto $1",
	"call/1/$1 ()",
	"syscall/0/syscall",
	"break/2/break $1, $2",
	"diag/1/diag $1",
	"iitlbp/2/iitlbp $1, $2",
	"copr/3/copr $1, $2, $3",
	"cldw/3/$2 = [$1]",
	"cstd/4/if ($1) [$4 + $3] = $2",
	"spop3/4/spop3 $1, $2, $3, $4",
	"spop2/3/spop2 $1, $2, $3",
	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_hppa = {
	.meta = {
		.name = "hppa",
		.desc = "HPPA pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_hppa,
	.version = R2_VERSION
};
#endif
/* radare - LGPL - Copyright 2025 - pancake */

#include <r_lib.h>
#include <r_asm.h>

static const char *pseudo_rules[] = {
	/* basic moves and arithmetic */
	"movl/2/2 = 1",
	"movb/2/2 = 1",
	"movw/2/2 = 1",
	"movq/2/2 = 1",
	"movzbl/2/2 = (unsigned char) 1",
	"movab/2/2 = &1",
	"moval/2/2 = &1",

	"addl2/2/2 += 1",
	"addl3/3/3 = 2 + 1",
	"subl2/2/2 -= 1",
	"subl3/3/3 = 2 - 1",
	"incl/1/$1++",
	"decl/1/$1--",

	"cmpl/2/2 == 1",
	"cmpb/2/2 == 1",
	"tstl/1/1 == 0",
	"tstb/1/1 == 0",

	"beql/1/if (z) goto $1",
	"bneq/1/if (!z) goto $1",
	"bne/1/if (!z) goto $1",
	"brw/1/goto $1",
	"brb/1/goto $1",
	"brz/1/goto $1",

	"calls/2/call $2",
	"calls/1/call $1",
	"call/1/call $1",
	"pushl/1/push $1",
	"pushab/1/push $1",
	"pushal/1/push $1",
	"pushal/2/push $2",
	"ret/0/ret",
	"ret/1/ret",

	/* additional VAX instructions */
	"bpt/0/breakpoint",
	"caseb/2/switch ($1) { case $2: }",
	"xorb2/2/2 ^= 1",
	"halt/0/halt",
	"movc5/2/movc5 $1,$2",
	"blbs/1/if (l & 1) goto $1",
	"mulf3/2/2 *= (float)$1",
	"subp4/2/2 -= 1",
	"rei/0/rei",
	"clrf/1/$1 = 0",
	"xorb3/2/2 ^= 1",
	"blssu/1/goto $1",
	"bicl2/2/2 &= ~$1",
	"mcoml/1/1 = ~$1",
	"cmpf/2/2 == 1",
	"addf2/2/2 += 1",
	"breakpoint/0/breakpoint",
	"subb3/2/2 -= 1",
	"clrb/1/$1 = 0",
	"divw2/2/2 /= 1",
	"bisb2/2/2 |= 1",
	"bgtr/1/goto $1",
	"cvtfd/1/cvtfd $1",
	"bbsc/1/if (bit($1)) goto $1",
	"mull2/1/mull2 $1",
	"extv/2/extv $1,$2",
	NULL
};

static char *parse(RAsmPluginSession *s, const char *data) {
	if (!data) {
		return NULL;
	}
	if (r_str_startswith (data, "|| ")) {
		data += 3;
	}
	if (R_STR_ISEMPTY (data)) {
		return NULL;
	}
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_vax = {
	.meta = {
		.name = "vax",
		.desc = "VAX pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_vax,
	.version = R2_VERSION
};
#endif

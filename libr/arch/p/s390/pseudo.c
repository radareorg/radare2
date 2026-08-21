/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_asm.h>

static const char *pseudo_rules[] = {
	/* loads and stores */
	"la/2/$1 = $2",
	"lay/2/$1 = $2",
	"larl/2/$1 = $2",
	"l/2/$1 = $2",
	"ly/2/$1 = $2",
	"lg/2/$1 = $2",
	"lgf/2/$1 = $2",
	"lgh/2/$1 = $2",
	"lgb/2/$1 = $2",
	"llgf/2/$1 = $2",
	"llgh/2/$1 = $2",
	"llgc/2/$1 = $2",
	"lr/2/$1 = $2",
	"lgr/2/$1 = $2",
	"lgfr/2/$1 = $2",
	"lhi/2/$1 = $2",
	"lghi/2/$1 = $2",
	"st/2/$2 = $1",
	"sty/2/$2 = $1",
	"stg/2/$2 = $1",
	"sth/2/$2 = $1",
	"stc/2/$2 = $1",
	"stm/3/store_multiple ($1, $2, $3)",
	"stmg/3/store_multiple ($1, $2, $3)",

	/* arithmetic and logic */
	"a/2/$1 += $2",
	"ay/2/$1 += $2",
	"ag/2/$1 += $2",
	"agf/2/$1 += $2",
	"ah/2/$1 += $2",
	"ahi/2/$1 += $2",
	"aghi/2/$1 += $2",
	"ar/2/$1 += $2",
	"agr/2/$1 += $2",
	"afi/2/$1 += $2",
	"agfi/2/$1 += $2",
	"s/2/$1 -= $2",
	"sy/2/$1 -= $2",
	"sg/2/$1 -= $2",
	"sgf/2/$1 -= $2",
	"sh/2/$1 -= $2",
	"sr/2/$1 -= $2",
	"sgr/2/$1 -= $2",
	"n/2/$1 &= $2",
	"ny/2/$1 &= $2",
	"ng/2/$1 &= $2",
	"nr/2/$1 &= $2",
	"ngr/2/$1 &= $2",
	"ni/2/$1 &= $2",
	"o/2/$1 |= $2",
	"oy/2/$1 |= $2",
	"og/2/$1 |= $2",
	"or/2/$1 |= $2",
	"ogr/2/$1 |= $2",
	"oi/2/$1 |= $2",
	"x/2/$1 ^= $2",
	"xy/2/$1 ^= $2",
	"xg/2/$1 ^= $2",
	"xr/2/$1 ^= $2",
	"xgr/2/$1 ^= $2",
	"xi/2/$1 ^= $2",
	"xc/2/$1 ^= $2",

	/* comparisons */
	"c/2/compare ($1, $2)",
	"cy/2/compare ($1, $2)",
	"cg/2/compare ($1, $2)",
	"cr/2/compare ($1, $2)",
	"cgr/2/compare ($1, $2)",
	"chi/2/compare ($1, $2)",
	"cghi/2/compare ($1, $2)",
	"cfi/2/compare ($1, $2)",

	/* control flow */
	"b/1/goto $1",
	"br/1/goto $1",
	"j/1/goto $1",
	"jg/1/goto $1",
	"balr/2/$2 ()",
	"basr/2/$2 ()",
	"brasl/2/$2 ()",
	"je/1/if (cc == 0) goto $1",
	"jz/1/if (cc == 0) goto $1",
	"jne/1/if (cc != 0) goto $1",
	"jnz/1/if (cc != 0) goto $1",
	"jl/1/if (cc == 1) goto $1",
	"jh/1/if (cc == 2) goto $1",
	"jle/1/if (cc != 2) goto $1",
	"jhe/1/if (cc != 1) goto $1",
	"jo/1/if (cc == 3) goto $1",
	"jno/1/if (cc != 3) goto $1",
	"nop/0/nop",
	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_s390 = {
	.meta = {
		.name = "s390",
		.desc = "IBM System/390 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_s390,
	.version = R2_VERSION
};
#endif

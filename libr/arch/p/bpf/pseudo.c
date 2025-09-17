/* radare - LGPL - Copyright 2022-2025 - pancake */

#include <r_asm.h>

/* Pseudo rules for classic and extended BPF (eBPF/sBPF) */
static const char *pseudo_rules[] = {
    /* moves / immediates */
    "mov/2/$1 = $2",
    "mov64/2/$1 = $2",
    "lddw/2/$1 = $2",

    /* arithmetic */
    "add/2/$1 += $2",
    "add64/2/$1 += $2",
    "sub/2/$1 -= $2",
    "sub64/2/$1 -= $2",
    "mul/2/$1 *= $2",
    "mul64/2/$1 *= $2",
    "div/2/$1 /= $2",
    "div64/2/$1 /= $2",
    "mod/2/$1 %= $2",
    "mod64/2/$1 %= $2",
    "neg/1/$1 = -$1",
    "neg64/1/$1 = -$1",

    /* bitwise */
    "and/2/$1 &= $2",
    "and64/2/$1 &= $2",
    "or/2/$1 |= $2",
    "or64/2/$1 |= $2",
    "xor/2/$1 ^= $2",
    "xor64/2/$1 ^= $2",

    /* shifts */
    "lsh/2/$1 <<= $2",
    "lsh64/2/$1 <<= $2",
    "rsh/2/$1 >>= $2",
    "rsh64/2/$1 >>= $2",
    "arsh/2/$1 >>= $2",
    "arsh64/2/$1 >>= $2",

    /* byteswaps */
    "be16/1/$1 = bswap16($1)",
    "be32/1/$1 = bswap32($1)",
    "be64/1/$1 = bswap64($1)",
    "le16/1/$1 = (ut16)$1",
    "le32/1/$1 = (ut32)$1",
    "le64/1/$1 = (ut64)$1",

    /* classic BPF xfers */
    "tax/0/x = a",
    "txa/0/a = x",

    /* loads */
    "ldxw/2/$1 = $2",
    "ldxh/2/$1 = $2",
    "ldxb/2/$1 = $2",
    "ldxdw/2/$1 = $2",
    "ldw/2/$1 = $2",
    "ldh/2/$1 = $2",
    "ldb/2/$1 = $2",

    /* stores */
    "stxw/2/$1 = $2",
    "stxh/2/$1 = $2",
    "stxb/2/$1 = $2",
    "stxdw/2/$1 = $2",
    "stw/2/$1 = $2",
    "sth/2/$1 = $2",
    "stb/2/$1 = $2",

    /* atomics */
    "xaddw/2/$1 += $2",
    "xadddw/2/$1 += $2",

    /* control flow */
    "call/1/$1 ()",
    "exit/0/return",
    "ret/0/return",
    "ja/1/goto $1",
    "jmp/1/goto $1",
    "goto/1/goto $1",

    /* conditional branches */
    "jeq/3/if ($1 == $2) goto $3",
    "jne/3/if ($1 != $2) goto $3",
    "jgt/3/if ($1 > $2) goto $3",
    "jge/3/if ($1 >= $2) goto $3",
    "jlt/3/if ($1 < $2) goto $3",
    "jle/3/if ($1 <= $2) goto $3",
    "jset/3/if ($1 & $2) goto $3",
    /* signed variants */
    "jsgt/3/if ($1 > $2) goto $3",
    "jsge/3/if ($1 >= $2) goto $3",
    "jslt/3/if ($1 < $2) goto $3",
    "jsle/3/if ($1 <= $2) goto $3",

    NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
    return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_bpf = {
	.meta = {
		.name = "bpf",
		.desc = "bpf pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_bpf,
	.version = R2_VERSION
};
#endif

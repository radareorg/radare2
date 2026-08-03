/* radare - LGPL - Copyright 2026 - pancake */

#include <r_asm.h>

static const char *pseudo_rules[] = {
	/* data movement */
	"mov.b/2/$2 = $1",
	"mov.w/2/$2 = $1",
	"movfpe/2/$2 = $1",
	"movtpe/2/$2 = $1",
	"push/1/[--r7] = $1",
	"pop/1/$1 = [r7++]",
	"ldc/2/$2 = $1",
	"stc/2/$2 = $1",
	"eepmov/0/memcpy (r6, r5, r4l)",

	/* arithmetic */
	"add.b/2/$2 += $1",
	"add.w/2/$2 += $1",
	"adds/2/$2 += $1",
	"addx/2/$2 += $1 + C",
	"sub.b/2/$2 -= $1",
	"sub.w/2/$2 -= $1",
	"subs/2/$2 -= $1",
	"subx/2/$2 -= $1 + C",
	"inc/1/$1++",
	"dec/1/$1--",
	"mulxu/2/$2 = $2l * $1",
	"divxu/2/$2 /= $1",
	"neg/1/$1 = -$1",
	"daa/1/$1 = daa ($1)",
	"das/1/$1 = das ($1)",
	"cmp.b/2/if ($2 == $1)",
	"cmp.w/2/if ($2 == $1)",

	/* logical */
	"and/2/$2 &= $1",
	"andc/2/$2 &= $1",
	"or/2/$2 |= $1",
	"orc/2/$2 |= $1",
	"xor/2/$2 ^= $1",
	"xorc/2/$2 ^= $1",
	"not/1/$1 = ~$1",

	/* shifts and rotations */
	"shal/1/$1 <<= 1",
	"shar/1/$1 >>= 1",
	"shll/1/$1 <<= 1",
	"shlr/1/$1 >>= 1",
	"rotl/1/$1 = rotate_left ($1, 1)",
	"rotr/1/$1 = rotate_right ($1, 1)",
	"rotxl/1/$1 = rotate_left_carry ($1, 1)",
	"rotxr/1/$1 = rotate_right_carry ($1, 1)",

	/* bit manipulation */
	"bset/2/$2 |= 1 << $1",
	"bclr/2/$2 &= ~(1 << $1)",
	"bnot/2/$2 ^= 1 << $1",
	"btst/2/Z = !bit ($2, $1)",
	"bld/2/C = bit ($2, $1)",
	"bild/2/C = !bit ($2, $1)",
	"bst/2/bit ($2, $1) = C",
	"bist/2/bit ($2, $1) = !C",
	"band/2/C &= bit ($2, $1)",
	"biand/2/C &= !bit ($2, $1)",
	"bor/2/C |= bit ($2, $1)",
	"bior/2/C |= !bit ($2, $1)",
	"bxor/2/C ^= bit ($2, $1)",
	"bixor/2/C ^= !bit ($2, $1)",

	/* control flow */
	"jmp/1/goto $1",
	"jsr/1/$1 ()",
	"bsr/1/$1 ()",
	"rts/0/return",
	"rte/0/return",
	"bra/1/goto $1",
	"brn/1/if (0) goto $1",
	"bhi/1/if (!C && !Z) goto $1",
	"bls/1/if (C || Z) goto $1",
	"bcc/1/if (!C) goto $1",
	"bcs/1/if (C) goto $1",
	"bne/1/if (!Z) goto $1",
	"beq/1/if (Z) goto $1",
	"bvc/1/if (!V) goto $1",
	"bvs/1/if (V) goto $1",
	"bpl/1/if (!N) goto $1",
	"bmi/1/if (N) goto $1",
	"bge/1/if (N == V) goto $1",
	"blt/1/if (N != V) goto $1",
	"bgt/1/if (!Z && N == V) goto $1",
	"ble/1/if (Z || N != V) goto $1",
	NULL
};

/* jmp/jsr targets are direct (@rn, @aa:16) or vectored (@@aa:8), while the
 * conditional branches reuse the @@aa:8 notation for a relative displacement */
typedef enum {
	H8300_CTX_DATA,
	H8300_CTX_JUMP,
	H8300_CTX_BRANCH,
} H8300Ctx;

static bool is_operand_char(const char ch) {
	return ch && ch != ',' && ch != ':' && ch != '+' && ch != ')' && ch != ' ';
}

/* rewrite the h8300 operand sugar into C-like accessors, so the rules receive
 * uniform tokens: #imm:sz -> imm, @(d:16,rn) -> [rn + d], @rn+ -> [rn++],
 * @-rn -> [--rn], @rn -> [rn] and @aa:sz -> [aa] */
static char *h8300_normalize(const char *text, H8300Ctx ctx) {
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	const char *p = text;
	while (*p) {
		const char ch = *p;
		if (ch == '#') {
			p++;
			continue;
		}
		if (ch == ':' && isdigit ((ut8)p[1])) {
			const char *q = p + 1;
			while (isdigit ((ut8)*q)) {
				q++;
			}
			/* strip only the :8/:16/:3 size annotations, which always end
			 * an operand token, and not colons inside substituted flag names */
			if (!*q || *q == ',' || *q == ')' || *q == ' ') {
				p = q;
				continue;
			}
		}
		if (ch == '.' && ctx == H8300_CTX_BRANCH && isdigit ((ut8)p[1])) {
			/* make the sign of the bsr displacement explicit */
			r_strbuf_append (sb, ".+");
			p++;
			continue;
		}
		if (ch != '@') {
			r_strbuf_append_n (sb, p, 1);
			p++;
			continue;
		}
		if (p[1] == '@') {
			p += 2;
			if (ctx == H8300_CTX_BRANCH) {
				/* the branches print the raw pc-relative displacement
				 * byte, render it with the same .d notation as bsr */
				char *end = NULL;
				long disp = strtol (p, &end, 16);
				if (end && end != p) {
					r_strbuf_appendf (sb, ".%+d", (int)(st8)disp);
					p = end;
				}
				continue;
			}
			r_strbuf_append (sb, "[");
			while (is_operand_char (*p)) {
				r_strbuf_append_n (sb, p, 1);
				p++;
			}
			r_strbuf_append (sb, "]");
			continue;
		}
		if (ctx == H8300_CTX_JUMP) {
			/* direct target: @rn -> rn, @aa:16 -> aa */
			p++;
			continue;
		}
		if (p[1] == '(') {
			const char *comma = strchr (p, ',');
			const char *close = strchr (p, ')');
			if (comma && close && comma < close) {
				const char *disp = p + 2;
				const char *colon = memchr (disp, ':', comma - disp);
				r_strbuf_append (sb, "[");
				r_strbuf_append_n (sb, comma + 1, close - comma - 1);
				r_strbuf_append (sb, " + ");
				r_strbuf_append_n (sb, disp, (colon? colon: comma) - disp);
				r_strbuf_append (sb, "]");
				p = close + 1;
				continue;
			}
			r_strbuf_append_n (sb, p, 1);
			p++;
			continue;
		}
		if (p[1] == '-') {
			p += 2;
			r_strbuf_append (sb, "[--");
			while (is_operand_char (*p)) {
				r_strbuf_append_n (sb, p, 1);
				p++;
			}
			r_strbuf_append (sb, "]");
			continue;
		}
		p++;
		r_strbuf_append (sb, "[");
		while (is_operand_char (*p)) {
			r_strbuf_append_n (sb, p, 1);
			p++;
		}
		if (*p == '+') {
			r_strbuf_append (sb, "++");
			p++;
		}
		r_strbuf_append (sb, "]");
	}
	return r_strbuf_drain (sb);
}

static H8300Ctx opcode_ctx(const char *data) {
	const char *sp = strchr (data, ' ');
	if (!sp || sp - data != 3) {
		return H8300_CTX_DATA;
	}
	if (!r_str_ncasecmp (data, "jmp", 3) || !r_str_ncasecmp (data, "jsr", 3)) {
		return H8300_CTX_JUMP;
	}
	const char *branches[] = {
		"bra", "brn", "bhi", "bls", "bcc", "bcs", "bne", "beq",
		"bvc", "bvs", "bpl", "bmi", "bge", "blt", "bgt", "ble",
		"bsr", NULL
	};
	int i;
	for (i = 0; branches[i]; i++) {
		if (!r_str_ncasecmp (data, branches[i], 3)) {
			return H8300_CTX_BRANCH;
		}
	}
	return H8300_CTX_DATA;
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	char *str = h8300_normalize (data, opcode_ctx (data));
	if (!str) {
		return NULL;
	}
	char *res = r_str_pseudo_transform (pseudo_rules, str);
	free (str);
	return res;
}

RAsmPlugin r_asm_plugin_h8300 = {
	.meta = {
		.name = "h8300",
		.desc = "H8/300 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_h8300,
	.version = R2_VERSION
};
#endif

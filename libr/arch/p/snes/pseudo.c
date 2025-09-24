/*
/* radare - MIT - Copyright 2025 - pancake */

#include <r_asm.h>

/* SNES / 65C816 pseudo rules (based on 6502 plugin, extended for 65816) */
static const char *pseudo_rules[] = {
	"lda/1/a = $1",
	"ldx/1/x = $1",
	"ldy/1/y = $1",
	"sta/1/$1 = a",
	"stx/1/$1 = x",
	"sty/1/$1 = y",
	"dec/1/$1--",
	"inc/1/$1++",
	"inx/0/x++",
	"iny/0/y++",
	"tax/0/x = a",
	"tay/0/y = a",
	"txa/0/a = x",
	"tya/0/a = y",
	"tsx/0/x = s",
	"txs/0/s = x",
	"brk/0/break",
	"clc/0/clear_carry",
	"cld/0/clear_decimal",
	"cli/0/clear_interrupt",
	"clv/0/clear_overflow",
	"sec/0/set_carry",
	"sed/0/set_decimal",
	"sei/0/set_interrupt",
	"jsr/1/$1 ()",
	"jmp/1/goto $1",
	"bne/1/if (!z) goto $1",
	"beq/1/if (z) goto $1",
	"bcc/1/if (!c) goto $1",
	"bcs/1/if (c) goto $1",
	"bpl/1/if (!n) goto $1",
	"bmi/1/if (n) goto $1",
	"bvc/1/if (!v) goto $1",
	"bvs/1/if (v) goto $1",
	"pha/0/push a",
	"pla/0/a = pop()",
	"php/0/push p",
	"plp/0/p = pop()",
	"phb/0/push b",
	"plb/0/b = pop()",
	"phk/0/push bank",
	"plk/0/pull bank",
	"adc/1/a += $1",
	"sbc/1/a -= $1",
	"and/1/a &= $1",
	"eor/1/a ^= $1",
	"ora/1/a |= $1",
	"sep/1/flags |= $1",
	"rep/1/flags &= ~$1",
	"mvn/2/mvn $1,$2",
	"mvp/2/mvp $1,$2",
	NULL
};

static bool is_mem_access(const char *op) {
	const char *memops[] = {"lda","ldx","ldy","sta","stx","sty","adc","sbc","and","eor","ora","inc","dec","asl","lsr","rol","ror","stz", NULL};
	int i = 0;
	for (; memops[i]; i++) {
		if (r_str_casecmp (memops[i], op) == 0) {
			return true;
		}
	}
	return false;
}

static char *transform_operand(const char *op, const char *opcode) {
	if (!op) {
		return NULL;
	}
	char *s = r_str_trim_dup (op);
	if (R_STR_ISEMPTY (s)) {
		return NULL;
	}
	if (s[0] == '#') {
		char *ret = r_str_new (s + 1);
		free (s);
		return ret;
	}
	char *p = strchr (s, ')');
	if (strchr (s, '(') && p) {
		char *open = strchr (s, '(');
		char inside[128] = {0};
		int len = p - open - 1;
		if (len > 0 && len < (int)sizeof (inside)) {
			r_str_ncpy (inside, open + 1, len + 1);
		}
		char *comma = strchr (inside, ',');
		char idx = 0;
		if (comma) {
			idx = *(comma + 1);
			*comma = '\0';
		} else {
			char *after = (char *)r_str_trim_head_ro (p + 1);
			if (*after == ',') {
				after = (char *)r_str_trim_head_ro (after + 1);
				idx = *after;
			}
		}
		char buf[256];
		if (idx) {
			snprintf (buf, sizeof (buf), "[%s+%c]", inside, idx);
		} else {
			snprintf (buf, sizeof (buf), "[%s]", inside);
		}
		free (s);
		return r_str_new (buf);
	}
	char *comma = strchr (s, ',');
	if (comma) {
		char addr[128] = {0};
		char idx = '\0';
		r_str_ncpy (addr, s, sizeof (addr));
		char *c = strchr (addr, ',');
		if (c) {
			*c = '\0';
			c++;
			while (*c == ' ') {
				c++;
			}
			idx = *c;
		}
		char buf[256];
		if (idx) {
			snprintf (buf, sizeof (buf), "[%s+%c]", addr, idx);
		} else {
			snprintf (buf, sizeof (buf), "[%s]", addr);
		}
		free (s);
		return r_str_new (buf);
	}
	if (is_mem_access (opcode)) {
		char *buf = r_str_newf ("[%s]", s);
		free (s);
		return buf;
	}
	return s;
}

static char *parse(RAsmPluginSession *s, const char *data) {
	if (!data) {
		return NULL;
	}
	char *copy = r_str_new (data);
	if (R_STR_ISEMPTY (copy)) {
		return NULL;
	}
	r_str_trim (copy);
	char opcode[64] = {0};
	char *sp = strchr (copy, ' ');
	char *oper = NULL;
	if (!sp) {
		r_str_ncpy (opcode, copy, sizeof (opcode));
	} else {
		int olen = sp - copy;
		if (olen >= (int)sizeof (opcode)) {
			olen = sizeof (opcode) - 1;
		}
		r_str_ncpy (opcode, copy, olen + 1);
		oper = sp + 1;
	}
	if (R_STR_ISEMPTY (oper)) {
	    free (copy);
	    return r_str_pseudo_transform (pseudo_rules, opcode);
	}
	char *ops[4] = {0};
	int nops = 0;
	const char *p = oper;
	const char *start = p;
	bool in_paren = false;
	while (*p && nops < 4) {
		if (*p == '(') {
			in_paren = true;
		} else if (*p == ')') {
			in_paren = false;
		} else if (*p == ',' && !in_paren) {
			int len = p - start;
			char tmp[128] = {0};
			if (len > 0) {
				if (len >= (int)sizeof (tmp)) {
					len = sizeof (tmp) - 1;
				}
				r_str_ncpy (tmp, start, len + 1);
				ops[nops++] = r_str_trim_dup (tmp);
			}
			start = p + 1;
		}
		p++;
	}
	if (nops < 4 && *start) {
		ops[nops++] = r_str_trim_dup (start);
	}
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_append (sb, opcode);
	r_strbuf_append (sb, " ");
	int i;
	for (i = 0; i < nops; i++) {
		char *t = transform_operand (ops[i], opcode);
		if (t) {
			r_strbuf_append (sb, t);
			free (t);
		}
		if (i != nops - 1) {
			r_strbuf_append (sb, ",");
		}
	}
	char *canon = r_strbuf_drain (sb);
	free (copy);
	for (i = 0; i < nops; i++) {
		free (ops[i]);
	}
	char *out = r_str_pseudo_transform (pseudo_rules, canon);
	free (canon);
	return out;
}

RAsmPlugin r_asm_plugin_snes = {
	.meta = {
		.name = "snes",
		.desc = "SNES / 65C816 pseudo syntax",
		.author = "pancake",
		.license = "MIT",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_snes,
	.version = R2_VERSION
};
#endif

/* radare - LGPL - Copyright 2015-2025 - pancake, qnix */

#include <r_lib.h>
#include <r_asm.h>
#include <r_util.h>

typedef enum {
	IND_IDX = 0,
	IDX_IND = 1,
	NORM = 2,
} ADDR_TYPE;

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
	"adc/1/a += $1",
	"sbc/1/a -= $1",
	"and/1/a &= $1",
	"eor/1/a ^= $1",
	"ora/1/a |= $1",
	NULL
};

static bool is_mem_access(const char *op) {
	const char *memops[] = {"lda","ldx","ldy","sta","stx","sty","adc","sbc","and","eor","ora","inc","dec","asl","lsr","rol","ror", NULL};
	int i = 0;
	for (; memops[i]; i++) {
		if (r_str_casecmp (memops[i], op) == 0) {
			return true;
		}
	}
	return false;
}

// transform one operand: immediate (#value) -> value, indexed/indirect -> [expr]
static char *transform_operand(const char *op, const char *opcode) {
	if (!op) {
		return NULL;
	}
	char *s = r_str_trim_dup (op);
	if (!s) {
		return NULL;
	}
	// immediate
	if (s[0] == '#') {
		char *ret = strdup (s + 1);
		free (s);
		return ret;
	}
	// indirect indexed (addr),Y -> [addr+Y]
	char *p = strchr (s, ')');
	if (strchr (s, '(') && p) {
		// remove parentheses
		char *open = strchr (s, '(');
		char inside[128] = {0};
		int len = p - open - 1;
		if (len > 0 && len < (int)sizeof (inside)) {
			strncpy (inside, open + 1, len);
			inside[len] = '\0';
		}
		// check for comma separated index inside parentheses
		char *comma = strchr (inside, ',');
		char idx = 0;
		if (comma) {
			// e.g. (addr,X)
			idx = *(comma + 1);
			*comma = '\0';
		} else {
			// (addr) followed by ,X after )
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
		return strdup (buf);
	}
	// indexed without parentheses: addr,X -> [addr+X]
	char *comma = strchr (s, ',');
	if (comma) {
		char addr[128] = {0};
		char idx = '\0';
		strncpy (addr, s, sizeof (addr) - 1);
		// split
		char *c = strchr (addr, ',');
		if (c) {
			*c = '\0';
			// find index after comma in original string to preserve it
			char *ci = (char *)r_str_trim_head_ro (comma + 1);
			idx = *ci;
		}
		char buf[256];
		if (idx) {
			snprintf (buf, sizeof (buf), "[%s+%c]", addr, idx);
		} else {
			snprintf (buf, sizeof (buf), "[%s]", addr);
		}
		free (s);
		return strdup (buf);
	}
	// bare symbol/number: decide based on opcode
	if (is_mem_access (opcode)) {
		char *buf = r_str_newf ("[%s]", s);
		free (s);
		return buf;
	}
	// otherwise keep as-is (addresses for branches, jsr...)
	return s;
}

static char *parse(RAsmPluginSession *s, const char *data) {
	if (!data) {
		return NULL;
	}
	// copy and normalize
	char *copy = strdup (data);
	if (!copy) {
		return NULL;
	}
	r_str_trim (copy);
	// split opcode and operands
	char opcode[64] = {0};
	char *sp = strchr (copy, ' ');
	char *oper = NULL;
	if (!sp) {
		strncpy (opcode, copy, sizeof (opcode) - 1);
	} else {
		int olen = sp - copy;
		if (olen >= (int)sizeof (opcode)) {
			olen = sizeof (opcode) - 1;
		}
		strncpy (opcode, copy, olen);
		opcode[olen] = '\0';
		oper = sp + 1;
	}
	(void)opcode; // opcode comparisons are case-insensitive via r_str_casecmp

	// If there are no operands, delegate to str_pseudo
	if (!oper || !*oper) {
		free (copy);
		return r_str_pseudo_transform (pseudo_rules, opcode);
	}

	// Now split operands by commas but some addressing modes contain commas
	// We will manually parse operands and transform them into canonical form
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
			// split
			int len = p - start;
			char tmp[128] = {0};
			if (len > 0) {
				if (len >= (int)sizeof (tmp)) {
					len = sizeof (tmp) - 1;
				}
				strncpy (tmp, start, len);
				ops[nops++] = r_str_trim_dup (tmp);
			}
			start = p + 1;
		}
		p++;
	}
	// last operand
	if (nops < 4 && *start) {
		ops[nops++] = r_str_trim_dup (start);
	}

	// transform each operand depending on opcode
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

	// Use the general-purpose transform with canonical operands
	char *out = r_str_pseudo_transform (pseudo_rules, canon);
	free (canon);
	return out;
}

RAsmPlugin r_asm_plugin_6502 = {
	.meta = {
		.name = "6502",
		.desc = "6502 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_6502,
	.version = R2_VERSION};
#endif

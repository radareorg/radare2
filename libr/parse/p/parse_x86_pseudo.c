/* radare - LGPL - Copyright 2009-2020 - nibble, pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_util.h>
#include <r_anal.h>
#include <r_parse.h>
// 16 bit examples
//    0x0001f3a4      9a67620eca       call word 0xca0e:0x6267
//    0x0001f41c      eabe76de12       jmp word 0x12de:0x76be [2]
//    0x0001f56a      ea7ed73cd3       jmp word 0xd33c:0xd77e [6]
static int replace (int argc, char *argv[], char *newstr) {
#define MAXPSEUDOOPS 10
	int i, j, k, d;
	char ch;
	struct {
		char *op;
		char *str;
		int args[MAXPSEUDOOPS];  // XXX can't use flex arrays, all unused will be 0
	} ops[] = {
		{ "adc",  "# += #", {1, 2}},
		{ "add",  "# += #", {1, 2}},
		{ "and",  "# &= #", {1, 2}},
		{ "call", "# ()", {1}},
		{ "cmove", "if (!var) # = #", {1, 2}},
		{ "cmovl","if (var < 0) # = #", {1, 2}},
		{ "cmp", "var = # - #", {1, 2}},
		{ "cmpsq", "var = # - #", {1, 2}},
		{ "cmpsb", "while (CX != 0) { var = *(DS*16 + SI) - *(ES*16 + DI); SI++; DI++; CX--; if (!var) break; }", {0}},
		{ "cmpsw", "while (CX != 0) { var = *(DS*16 + SI) - *(ES*16 + DI); SI+=4; DI+=4; CX--; if (!var) break; }", {0}},
		{ "dec",  "#--", {1}},
		{ "div",  "# /= #", {1, 2}},
		{ "fabs",  "abs(#)", {1}},
		{ "fadd",  "# = # + #", {1, 1, 2}},
		{ "fcomp",  "var = # - #", {1, 2}},
		{ "fcos",  "# = cos(#)", {1, 1}},
		{ "fdiv",  "# = # / #", {1, 1, 2}},
		{ "fiadd",  "# = # / #", {1, 1, 2}},
		{ "ficom",  "var = # - #", {1, 2}},
		{ "fidiv",  "# = # / #", {1, 1, 2}},
		{ "fidiv",  "# = # * #", {1, 1, 2}},
		{ "fisub",  "# = # - #", {1, 1, 2}},
		{ "fnul",  "# = # * #", {1, 1, 2}},
		{ "fnop",  " ", {0}},
		{ "frndint",  "# = (int) #", {1, 1}},
		{ "fsin",  "# = sin(#)", {1, 1}},
		{ "fsqrt",  "# = sqrt(#)", {1, 1}},
		{ "fsub",  "# = # - #", {1, 1, 2}},
		{ "fxch",  "#,# = #,#", {1, 2, 2, 1}},
		{ "idiv",  "# /= #", {1, 2}},
		{ "imul",  "# = # * #", {1, 2, 3}},
		{ "in",   "# = io[#]", {1, 2}},
		{ "inc",  "#++", {1}},
		{ "ja", "if (((unsigned) var) > 0) goto #", {1}},
		{ "jb", "if (((unsigned) var) < 0) goto #", {1}},
		{ "jbe", "if (((unsigned) var) <= 0) goto #", {1}},
		{ "je", "if (!var) goto #", {1}},
		{ "jg", "if (var > 0) goto #", {1}},
		{ "jge", "if (var >= 0) goto #", {1}},
		{ "jle", "if (var <= 0) goto #", {1}},
		{ "jmp",  "goto #", {1}},
		{ "jne", "if (var) goto #", {1}},
		{ "lea",  "# = #", {1, 2}},
		{ "mov",  "# = #", {1, 2}},
		{ "movabs", "# = #", {1, 2}},
		{ "movq",  "# = #", {1, 2}},
		{ "movaps",  "# = #", {1, 2}},
		{ "movups",  "# = #", {1, 2}},
		{ "movsd",  "# = #", {1, 2}},
		{ "movsx","# = #", {1, 2}},
		{ "movsxd","# = #", {1, 2}},
		{ "movzx", "# = #", {1, 2}},
		{ "movntdq", "# = #", {1, 2}},
		{ "movnti", "# = #", {1, 2}},
		{ "movntpd", "# = #", {1, 2}},
		{ "pcmpeqb", "# == #", {1, 2}},

		{ "movdqu", "# = #", {1, 2}},
		{ "movdqa", "# = #", {1, 2}},
		{ "pextrb", "# = (byte) # [#]", {1, 2, 3}},
		{ "palignr", "# = # align #", {1, 2, 3}},
		{ "pxor", "# ^= #", {1, 2}},
		{ "xorps", "# ^= #", {1, 2}},
		{ "mul",  "# = # * #", {1, 2, 3}},
		{ "mulss",  "# = # * #", {1, 2, 3}},
		{ "neg",  "# ~= #", {1, 1}},
		{ "nop",  "", {0}},
		{ "not",  "# = !#", {1, 1}},
		{ "or",   "# |= #", {1, 2}},
		{ "out",  "io[#] = #", {1, 2}},
		{ "pop",  "pop #", {1}},
		{ "push", "push #", {1}},
		{ "ret",  "return", {0}},
		{ "sal",  "# <<= #", {1, 2}},
		{ "sar",  "# >>= #", {1, 2}},
		{ "sete",  "# = e", {1}},
		{ "setne",  "# = ne", {1}},
		{ "shl",  "# <<<= #", {1, 2}},
		{ "shld",  "# <<<= #", {1, 2}},
		{ "sbb",  "# = # - #", {1, 1, 2}},
		{ "shr",  "# >>>= #", {1, 2}},
		{ "shlr",  "# >>>= #", {1, 2}},
		//{ "strd",  "# = # - #", {1, 2, 3}},
		{ "sub",  "# -= #", {1, 2}},
		{ "swap", "var = #; # = #; # = var", {1, 1, 2, 2}},
		{ "test", "var = # & #", {1, 2}},
		{ "xchg",  "#,# = #,#", {1, 2, 2, 1}},
		{ "xadd",  "#,# = #,#+#", {1, 2, 2, 1, 2}},
		{ "xor",  "# ^= #", {1, 2}},
		{ NULL }
	};

	if (argc > 2 && !strcmp (argv[0], "xor")) {
		if (!strcmp (argv[1], argv[2])) {
			argv[0] = "mov";
			argv[2] = "0";
		}
	}
	for (i = 0; ops[i].op != NULL; i++) {
		if (!strcmp (ops[i].op, argv[0])) {
			if (newstr != NULL) {
				d = 0;
				j = 0;
				ch = ops[i].str[j];
				for (j = 0, k = 0; ch != '\0'; j++, k++) {
					ch = ops[i].str[j];
					if (ch == '#') {
						if (d >= MAXPSEUDOOPS) {
							// XXX Shouldn't ever happen...
							continue;
						}
						int idx = ops[i].args[d];
						d++;
						if (idx <= 0) {
							// XXX Shouldn't ever happen...
							continue;
						}
						const char *w = argv[idx];
						if (w != NULL) {
							strcpy (newstr + k, w);
							k += strlen (w) - 1;
						}
					} else {
						newstr[k] = ch;
					}
				}
				newstr[k] = '\0';
			}
			return true;
		}
	}

	/* TODO: this is slow */
	if (newstr) {
		newstr[0] = '\0';
		for (i = 0; i < argc; i++) {
			strcat (newstr, argv[i]);
			strcat (newstr, (i == 0 || i == argc - 1)? " ": ",");
		}
	}
	return false;
}

static int parse(RParse *p, const char *data, char *str) {
	char w0[256], w1[256], w2[256], w3[256];
	int i;
	size_t len = strlen (data);
	int sz = 32;
	char *buf, *ptr, *optr, *end;
	if (len >= sizeof (w0) || sz >= sizeof (w0)) {
		return false;
	}
	// strdup can be slow here :?
	if (!(buf = strdup (data))) {
		return false;
	}
	*w0 = *w1 = *w2 = *w3 = '\0';
	if (*buf) {
		end = buf + strlen (buf);
		ptr = strchr (buf, ' ');
		if (!ptr) {
			ptr = strchr (buf, '\t');
		}
		if (!ptr) {
			ptr = end;
		}
		*ptr = '\0';
		if (ptr != end) {
			for (++ptr; *ptr == ' '; ptr++) {
				;
			}
		}
		r_str_ncpy (w0, buf, sizeof (w0));
		r_str_ncpy (w1, ptr, sizeof (w1));
		optr = ptr;
		ptr = strchr (ptr, ',');
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr == ' '; ptr++) {
				;
			}
			r_str_ncpy (w1, optr, sizeof (w1));
			r_str_ncpy (w2, ptr, sizeof (w2));
			optr = ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr == ' '; ptr++) {
					;
				}
				r_str_ncpy (w2, optr, sizeof (w2));
				r_str_ncpy (w3, ptr, sizeof (w3));
			}
		}
	}
	char *wa[] = { w0, w1, w2, w3 };
	int nw = 0;
	for (i = 0; i < 4; i++) {
		if (wa[i][0] != '\0') {
			nw++;
		}
	}
	/* TODO: interpretation of memory location fails*/
	//ensure imul & mul interpretations works
	if (strstr (w0, "mul")) {
		if (nw == 2)
		{
			r_str_ncpy (wa[3], wa[1], sizeof (w3));

			switch (wa[3][0]) {
			case 'q':
			case 'r': //qword, r..
				r_str_ncpy (wa[1], "rax", sizeof (w1));
				r_str_ncpy (wa[2], "rax", sizeof (w2));
				break;
			case 'd':
			case 'e': //dword, e..
				if (strlen (wa[3]) > 2) {
					r_str_ncpy (wa[1], "eax", sizeof (w1));
					r_str_ncpy (wa[2], "eax", sizeof (w2));
					break;
				}
			default : // .x, .p, .i or word
				if (wa[3][1] == 'x' || wa[3][1] == 'p' || \
					wa[3][1] == 'i' || wa[3][0] == 'w') {
					r_str_ncpy (wa[1], "ax", sizeof (w1));
					r_str_ncpy (wa[2], "ax", sizeof (w2));
				} else { // byte and lowest 8 bit registers
					r_str_ncpy (wa[1], "al", sizeof (w1));
					r_str_ncpy (wa[2], "al", sizeof (w2));
				}
			}
		}
		else if (nw == 3)
		{
			r_str_ncpy (wa[3], wa[2], sizeof (w3));
			r_str_ncpy (wa[2], wa[1], sizeof (w2));
		}

		replace (nw, wa, str);

	} else if (strstr (w0, "lea")) {
		r_str_replace_char (w2, '[', 0);
		r_str_replace_char (w2, ']', 0);
		replace (nw, wa, str);
	} else if ((strstr (w1, "ax") || strstr (w1, "ah") || strstr (w1, "al")) && !p->retleave_asm) {
		if (!(p->retleave_asm = (char *) malloc (sz))) {
			return false;
		}
		r_snprintf (p->retleave_asm, sz, "return %s", w2);
		replace (nw, wa, str);
	} else if ((strstr (w0, "leave") && p->retleave_asm) || (strstr (w0, "pop") && strstr (w1, "bp"))) {
		r_str_ncpy (wa[0], " ", 2);
		r_str_ncpy (wa[1], " ", 2);
		replace (nw, wa, str);
	} else if (strstr (w0, "ret") && p->retleave_asm) {
		r_str_ncpy (str, p->retleave_asm, sz);
		R_FREE (p->retleave_asm);
	} else if (p->retleave_asm) {
		R_FREE (p->retleave_asm);
		replace (nw, wa, str);
	} else {
		replace (nw, wa, str);
	}
	free (buf);
	return true;
}

static void parse_localvar (RParse *p, char *newstr, size_t newstr_len, const char *var, const char *reg, char sign, char *ireg, bool att) {
	RStrBuf *sb = r_strbuf_new ("");
	if (att) {
		if (p->localvar_only) {
			if (ireg) {
				r_strbuf_setf (sb, "(%%%s)", ireg);
			}
			snprintf (newstr, newstr_len - 1, "%s%s", var, r_strbuf_get (sb));
		} else {
			if (ireg) {
				r_strbuf_setf (sb, ", %%%s", ireg);
			}
			snprintf (newstr, newstr_len - 1, "%s(%%%s%s)", var, reg, r_strbuf_get (sb));
		}
	} else {
		if (ireg) {
			r_strbuf_setf (sb, " + %s", ireg);
		}
		if (p->localvar_only) {
			snprintf (newstr, newstr_len - 1, "%s%s", var, r_strbuf_get (sb));
		} else {
			snprintf (newstr, newstr_len - 1, "%s%s %c %s", reg, r_strbuf_get (sb), sign, var);
		}
	}
	r_strbuf_free (sb);
}

static inline void mk_reg_str(const char *regname, int delta, bool sign, bool att, char *ireg, char *dest, int len) {
	RStrBuf *sb = r_strbuf_new ("");
	if (att) {
		if (ireg) {
			r_strbuf_setf (sb, ", %%%s", ireg);
		}
		if (delta == 0) {
			snprintf (dest, len - 1, "(%%%s%s)", regname, r_strbuf_get (sb));
		} else if (delta < 10) {
			snprintf (dest, len - 1, "%s%d(%%%s%s)", sign ? "" : "-", delta, regname, r_strbuf_get (sb));
		} else {
			snprintf (dest, len - 1, "%s0x%x(%%%s%s)", sign ? "" : "-", delta, regname, r_strbuf_get (sb));
		}
	} else {
		if (ireg) {
			r_strbuf_setf (sb, " + %s", ireg);
		}
		if (delta == 0) {
			snprintf (dest, len - 1, "%s%s", regname, r_strbuf_get (sb));
		} else if (delta < 10) {
			snprintf (dest, len - 1, "%s%s %c %d", regname, r_strbuf_get (sb), sign ? '+':'-', delta);
		} else {
			snprintf (dest, len - 1, "%s%s %c 0x%x", regname, r_strbuf_get (sb), sign ? '+':'-', delta);
		}
	}
	r_strbuf_free (sb);
}

static bool subvar(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	RList *bpargs, *spargs;
	RAnal *anal = p->analb.anal;
	RListIter *bpargiter, *spiter;
	char oldstr[64], newstr[64];
	char *tstr = strdup (data);
	if (!tstr) {
		return false;
	}

	bool att = strchr (data, '%');

	if (p->subrel) {
		if (att) {
			char *rip = (char *) r_str_casestr (tstr, "(%rip)");
			if (rip) {
				*rip = 0;
				char *pre = tstr;
				char *pos = rip + 6;
				char *word = rip;
				while (word > tstr && *word != ' ') {
					word--;
				}

				if (word > tstr) {
					*word++ = 0;
					*rip = 0;
					st64 n = r_num_math (NULL, word);
					ut64 repl_num = oplen + addr + n;
					char *tstr_new = r_str_newf ("%s 0x%08"PFMT64x"%s", pre, repl_num, pos);
					*rip = '(';
					free (tstr);
					tstr = tstr_new;
				}
			}
		} else {
			char *rip = (char *) r_str_casestr (tstr, "[rip");
			if (rip) {
				char *ripend = strchr (rip + 3, ']');
				const char *plus = strchr (rip, '+');
				const char *neg = strchr (rip, '-');
				char *tstr_new;
				ut64 repl_num = oplen + addr;

				if (!ripend) {
					ripend = "]";
				}
				if (plus) {
					repl_num += r_num_get (NULL, plus + 1);
				}
				if (neg) {
					repl_num -= r_num_get (NULL, neg + 1);
				}

				rip[1] = '\0';
				tstr_new = r_str_newf ("%s0x%08"PFMT64x"%s", tstr, repl_num, ripend);
				free (tstr);
				tstr = tstr_new;
			}
		}
	}

	if (!p->varlist) {
		free (tstr);
		return false;
	}
	bpargs = p->varlist (f, 'b');
	spargs = p->varlist (f, 's');
	/* Iterate over stack pointer arguments/variables */
	bool ucase = *tstr >= 'A' && *tstr <= 'Z';
	if (ucase && tstr[1]) {
		ucase = tstr[1] >= 'A' && tstr[1] <= 'Z';
	}
	char *ireg = NULL;
	if (p->get_op_ireg) {
		ireg = p->get_op_ireg(p->user, addr);
	}
	RAnalVarField *bparg, *sparg;
	r_list_foreach (spargs, spiter, sparg) {
		char sign = '+';
		st64 delta = p->get_ptr_at
			? p->get_ptr_at (f, sparg->delta, addr)
			: ST64_MAX;
		if (delta == ST64_MAX && sparg->field) {
			delta = sparg->delta;
		} else if (delta == ST64_MAX) {
			continue;
		}
		if (delta < 0) {
			sign = '-';
			delta = -delta;
		}
		const char *reg = NULL;
		if (p->get_reg_at) {
			reg = p->get_reg_at (f, sparg->delta, addr);
		}
		if (!reg) {
			reg = anal->reg->name[R_REG_NAME_SP];
		}
		mk_reg_str (reg, delta, sign == '+', att, ireg, oldstr, sizeof (oldstr));

		if (ucase) {
			r_str_case (oldstr, true);
		}
		parse_localvar (p, newstr, sizeof (newstr), sparg->name, reg, sign, ireg, att);
		char *ptr = strstr (tstr, oldstr);
		if (ptr && (!att || *(ptr - 1) == ' ')) {
			if (delta == 0) {
				char *end = ptr + strlen (oldstr);
				if (*end != ']' && *end != '\0') {
					continue;
				}
			}
			tstr = r_str_replace (tstr, oldstr, newstr, 1);
			break;
		} else {
			r_str_case (oldstr, false);
			ptr = strstr (tstr, oldstr);
			if (ptr && (!att || *(ptr - 1) == ' ')) {
				tstr = r_str_replace (tstr, oldstr, newstr, 1);
				break;
			}
		}
	}
	/* iterate over base pointer args/vars */
	r_list_foreach (bpargs, bpargiter, bparg) {
		char sign = '+';
		st64 delta = p->get_ptr_at
			? p->get_ptr_at (f, bparg->delta, addr)
			: ST64_MAX;
		if (delta == ST64_MAX && bparg->field) {
			delta = bparg->delta + f->bp_off;
		} else if (delta == ST64_MAX) {
			continue;
		}
		if (delta < 0) {
			sign = '-';
			delta = -delta;
		}
		const char *reg = NULL;
		if (p->get_reg_at) {
			reg = p->get_reg_at (f, bparg->delta, addr);
		}
		if (!reg) {
			reg = anal->reg->name[R_REG_NAME_BP];
		}
		mk_reg_str (reg, delta, sign == '+', att, ireg, oldstr, sizeof (oldstr));
		if (ucase) {
			r_str_case (oldstr, true);
		}
		parse_localvar (p, newstr, sizeof (newstr), bparg->name, reg, sign, ireg, att);
		char *ptr = strstr (tstr, oldstr);
		if (ptr && (!att || *(ptr - 1) == ' ')) {
			if (delta == 0) {
				char *end = ptr + strlen (oldstr);
				if (*end != ']' && *end != '\0') {
					continue;
				}
			}
			tstr = r_str_replace (tstr, oldstr, newstr, 1);
			break;
		} else {
			r_str_case (oldstr, false);
			ptr = strstr (tstr, oldstr);
			if (ptr && (!att || *(ptr - 1) == ' ')) {
				tstr = r_str_replace (tstr, oldstr, newstr, 1);
				break;
			}
		}
		// Try with no spaces
		snprintf (oldstr, sizeof (oldstr) - 1, "[%s%c0x%x]", reg, sign, (int)delta);
		if (strstr (tstr, oldstr) != NULL) {
			tstr = r_str_replace (tstr, oldstr, newstr, 1);
			break;
		}
	}

	char bp[32];
	if (anal->reg->name[R_REG_NAME_BP]) {
		strncpy (bp, anal->reg->name[R_REG_NAME_BP], sizeof (bp) - 1);
		if (isupper ((ut8)*str)) {
			r_str_case (bp, true);
		}
		bp[sizeof (bp) - 1] = 0;
	} else {
		bp[0] = 0;
	}

	bool ret = true;
	if (len > strlen (tstr)) {
		strcpy (str, tstr);
	} else {
		// TOO BIG STRING CANNOT REPLACE HERE
		ret = false;
	}
	free (tstr);
	free (ireg);
	r_list_free (spargs);
	r_list_free (bpargs);
	return ret;
}

RParsePlugin r_parse_plugin_x86_pseudo = {
	.name = "x86.pseudo",
	.desc = "X86 pseudo syntax",
	.parse = &parse,
	.subvar = &subvar,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_x86_pseudo,
	.version = R2_VERSION
};
#endif

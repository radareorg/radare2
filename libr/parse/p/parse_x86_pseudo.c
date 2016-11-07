/* radare - LGPL - Copyright 2009-2016 - nibble, pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_reg.h>
#include <r_parse.h>

// 16 bit examples
//    0x0001f3a4      9a67620eca       call word 0xca0e:0x6267
//    0x0001f41c      eabe76de12       jmp word 0x12de:0x76be [2]
//    0x0001f56a      ea7ed73cd3       jmp word 0xd33c:0xd77e [6]
static int replace(int argc, const char *argv[], char *newstr) {
	int i,j,k;
	struct {
		char *op;
		char *str;
	} ops[] = {
		{ "adc",  "1 += 2"},
		{ "add",  "1 += 2"},
		{ "and",  "1 &= 2"},
		{ "call", "1 ()"},
		{ "cmove", "1 = 2"},
		{ "cmovl","ifnot zf,1 = 2"},
		{ "cmp", "if (1 == 2"},
		{ "cmpsq", "if (1 == 2"},
		{ "cmsb", "if (1 == 2"},
		{ "cmsw", "if (1 == 2"},
		{ "dec",  "1--"},
		{ "div",  "1 /= 2"},
		{ "fabs",  "abs(1)"},
		{ "fadd",  "1 = 1 + 2"},
		{ "fcomp",  "if (1 == 2"},
		{ "fcos",  "1 = cos(1)"},
		{ "fdiv",  "1 = 1 / 2"},
		{ "fiadd",  "1 = 1 / 2"},
		{ "ficom",  "if (1 == 2"},
		{ "fidiv",  "1 = 1 / 2"},
		{ "fidiv",  "1 = 1 * 2"},
		{ "fisub",  "1 = 1 - 2"},
		{ "fnul",  "1 = 1 * 2"},
		{ "fnop",  " "},
		{ "frndint",  "1 = (int) 1"},
		{ "fsin",  "1 = sin(1)"},
		{ "fsqrt",  "1 = sqrt(1)"},
		{ "fsub",  "1 = 1 - 2"},
		{ "fxch",  "1,2 = 2,1"},
		{ "idiv",  "1 /= 2"},
		{ "imul",  "1 *= 2"},
		{ "in",   "1 = io[2]"},
		{ "inc",  "1++"},
		{ "ja", "isAbove 1)"},
		{ "jb", "isBelow 1)"},
		{ "jbe", "isBelowOrEqual 1)"},
		{ "je", "isZero 1)"},
		{ "jg", "isGreater 1)"},
		{ "jge", "isGreaterOrEqual 1)"},
		{ "jle", "isLessOrEqual 1)"},
		{ "jmp",  "goto 1"},
		{ "jne", "notZero 1)"},
		{ "lea",  "1 = 2"},
		{ "mov",  "1 = 2"},
		{ "movsd",  "1 = 2"},
		{ "movsx","1 = 2"},
		{ "movsxd","1 = 2"},
		{ "movzx", "1 = 2"},
		{ "movntdq", "1 = 2"},
		{ "movnti", "1 = 2"},
		{ "movntpd", "1 = 2"},
		{ "mul",  "1 *= 2"},
		{ "neg",  "1 ~= 1"},
		{ "nop",  ""},
		{ "not",  "1 = !1"},
		{ "or",   "1 |= 2"},
		{ "out",  "io[1] = 2"},
		{ "pop",  "pop 1"},
		{ "push", "push 1"},
		{ "sal",  "1 <<= 2"},
		{ "sar",  "1 >>= 2"},
		{ "sete",  "1 = e"},
		{ "setne",  "1 = ne"},
		{ "shl",  "1 <<<= 2"},
		{ "shld",  "1 <<<= 2"},
		{ "sbb",  "1 = 1 - 2"},
		{ "shr",  "1 >>>= 2"},
		{ "shlr",  "1 >>>= 2"},
		//{ "strd",  "1 = 2 - 3"},
		{ "sub",  "1 -= 2"},
		{ "swap", "swap 1, 2"},
		{ "test", "if (1 == 2"},
		{ "xchg",  "1,2 = 2,1"},
		{ "xadd",  "1,2 = 2,1+2"},
		{ "xor",  "1 ^= 2"},
		{ NULL }
	};

	if (argc>2 && !strcmp (argv[0], "xor")) {
		if (!strcmp (argv[1], argv[2])) {
			argv[0] = "mov";
			argv[2] = "0";
		}
	}
	for (i=0; ops[i].op != NULL; i++) {
		if (!strcmp (ops[i].op, argv[0])) {
			if (newstr != NULL) {
				for (j=k=0; ops[i].str[j]!='\0'; j++, k++) {
					if (ops[i].str[j]>='0' && ops[i].str[j]<='9') {
						const char *w = argv[ ops[i].str[j]-'0' ];
						if (w != NULL) {
							strcpy (newstr+k, w);
							k += strlen(w)-1;
						}
					} else newstr[k] = ops[i].str[j];
				}
				newstr[k]='\0';
			}
			return true;
		}
	}

	/* TODO: this is slow */
	if (newstr != NULL) {
		newstr[0] = '\0';
		for (i=0; i<argc; i++) {
			strcat (newstr, argv[i]);
			strcat (newstr, (i == 0 || i== argc - 1)?" ":",");
		}
	}
	return false;
}

static int parse(RParse *p, const char *data, char *str) {
	char w0[256], w1[256], w2[256], w3[256];
	int i, len = strlen (data);
	char *buf, *ptr, *optr;

	if (len>=sizeof (w0))
		return false;
	// malloc can be slow here :?
	if (!(buf = malloc (len+1)))
		return false;
	memcpy (buf, data, len+1);

	if (*buf) {
		*w0 = *w1 = *w2 = *w3 = '\0';
		ptr = strchr (buf, ' ');
		if (!ptr)
			ptr = strchr (buf, '\t');
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr==' '; ptr++);
			strncpy (w0, buf, sizeof (w0) - 1);
			strncpy (w1, ptr, sizeof (w1) - 1);

			optr = ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr==' '; ptr++);
				strncpy (w1, optr, sizeof (w1) - 1);
				strncpy (w2, ptr, sizeof (w2) - 1);
				optr = ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (++ptr; *ptr==' '; ptr++);
					strncpy (w2, optr, sizeof (w2) - 1);
					strncpy (w3, ptr, sizeof (w3) - 1);
				}
			}
		}
		{
			const char *wa[] = { w0, w1, w2, w3 };
			int nw = 0;
			for (i=0; i<4; i++) {
				if (wa[i][0] != '\0')
				nw++;
			}
			replace (nw, wa, str);
		}
	}
	free (buf);
	return true;
}

#if 0
static inline int ishexch (char c) {
	if (c>=0 && c<=9) return 1;
	if (c>='a' && c<='f') return 1;
	if (c>='A' && c<='F') return 1;
	return 0;
}

static inline int issegoff (const char *w) {
	if (!ishexch (w[0])) return 0;
	if (!ishexch (w[1])) return 0;
	if (!ishexch (w[2])) return 0;
	if (!ishexch (w[3])) return 0;
	// :
	if (!ishexch (w[5])) return 0;
	if (!ishexch (w[6])) return 0;
	if (!ishexch (w[7])) return 0;
	if (!ishexch (w[8])) return 0;
	return 1;
}
#endif

static bool varsub (RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	RAnalVar *reg, *bparg, *sparg;
	RListIter *regiter, *bpargiter, *spiter;
	char oldstr[64], newstr[64];
	char *tstr = strdup (data);
	if (!tstr) return false;
	RList *regs, *bpargs, *spargs;

	if (p->relsub) {
		char *rip = (char *)r_str_casestr (tstr, "[rip");
		if (rip) {
			char *ripend = strchr (rip + 3, ']');
			const char *plus = strchr (rip, '+');
			const char *neg = strchr (rip, '-');
			char *tstr_new;
			ut64 repl_num = oplen + addr;

			if (!ripend) ripend = "]";
			if (plus) repl_num += r_num_get (NULL, plus + 1);
			if (neg) repl_num -= r_num_get (NULL, neg + 1);

			rip[1] = '\0';
			tstr_new = r_str_newf ("%s0x%08"PFMT64x"%s", tstr, repl_num, ripend);
			free (tstr);
			tstr = tstr_new;
			if (!strncasecmp (tstr, "lea", 3)) {
				r_str_replace_char (tstr, '[', 0);
				r_str_replace_char (tstr, ']', 0);
			}
		}
	}

	if (!p->varlist) {
                free (tstr);
		return false;
        }
	regs = p->varlist (p->anal, f, 'r');
	bpargs = p->varlist (p->anal, f, 'b');
	spargs = p->varlist (p->anal, f, 's');
	/*iterate over stack pointer arguments/variables*/
	bool ucase = *tstr >= 'A' && *tstr <= 'Z';
	if (ucase && tstr[1]) {
		ucase = tstr[1] >= 'A' && tstr[1] <= 'Z';
	}
	r_list_foreach (spargs, spiter, sparg) {
		if (sparg->delta < 10) {
			snprintf (oldstr, sizeof (oldstr)-1, "[%s + %d]",
				p->anal->reg->name[R_REG_NAME_SP], sparg->delta);
		} else {
			snprintf (oldstr, sizeof (oldstr)-1, "[%s + 0x%x]",
				p->anal->reg->name[R_REG_NAME_SP], sparg->delta);
		}
		if (ucase) {
			r_str_case (oldstr, true);
		}
		snprintf (newstr, sizeof (newstr) - 1, "[%s + %s]",
			p->anal->reg->name[R_REG_NAME_SP],
			sparg->name);
		if (ucase) {
			char *plus = strchr (newstr, '+');
			if (plus) {
				*plus = 0;
				r_str_case (newstr, true);
				*plus = '+';
			} else {
				r_str_case (newstr, true);
			}
		}
		if (strstr (tstr, oldstr)) {
			tstr = r_str_replace (tstr, oldstr, newstr, 1);
			break;
		} else {
			r_str_case (oldstr, false);
			if (strstr (tstr, oldstr)) {
				tstr = r_str_replace (tstr, oldstr, newstr, 1);
				break;
			}
		}
	}
	/* iterate over base pointer args/vars */
	r_list_foreach (bpargs, bpargiter, bparg) {
		char sign = '+';
		if (bparg->delta < 0) {
			sign = '-';
			bparg->delta = -bparg->delta;
		}
		if (bparg->delta < 10) {
			snprintf (oldstr, sizeof (oldstr) - 1,
				"[%s %c %d]",
				p->anal->reg->name[R_REG_NAME_BP],
				sign, bparg->delta);
		} else {
			snprintf (oldstr, sizeof (oldstr) - 1,
				"[%s %c 0x%x]",
				p->anal->reg->name[R_REG_NAME_BP],
				sign, bparg->delta);
		}
		if (ucase) {
			r_str_case (oldstr, true);
		}
		snprintf (newstr, sizeof (newstr) - 1, "[%s %c %s]",
			p->anal->reg->name[R_REG_NAME_BP], sign,
			bparg->name);
		if (ucase) {
			char *plus = strchr (newstr, sign);
			if (plus) {
				*plus = 0;
				r_str_case (newstr, true);
				*plus = sign;
			} else {
				r_str_case (newstr, true);
			}
		}
		if (strstr (tstr, oldstr)) {
			tstr = r_str_replace (tstr, oldstr, newstr, 1);
			break;
		} else {
			r_str_case (oldstr, false);
			if (strstr (tstr, oldstr)) {
				tstr = r_str_replace (tstr, oldstr, newstr, 1);
				break;
			}
		}
		// Try with no spaces
		snprintf (oldstr, sizeof (oldstr)-1, "[%s%c0x%x]",
			p->anal->reg->name[R_REG_NAME_BP], sign,
			bparg->delta);
		if (strstr (tstr, oldstr) != NULL) {
			tstr = r_str_replace (tstr, oldstr, newstr, 1);
			break;
		}
	}

	char bp[32];
	if (p->anal->reg->name[R_REG_NAME_BP]) {
		strncpy (bp, p->anal->reg->name[R_REG_NAME_BP], sizeof (bp) -1);
		if (isupper (*str)) {
			r_str_case (bp, true);
		}
		bp[sizeof (bp) - 1] = 0;
	} else {
		bp[0] = 0;
	}

	r_list_foreach (regs, regiter, reg) {
		RRegItem *r = r_reg_index_get (p->anal->reg, reg->delta);
		if (r && r->name && strstr (tstr, r->name)){
			tstr = r_str_replace (tstr, r->name, reg->name, 1);
		}
	}

	bool ret = true;
	if (len > strlen (tstr)) {
		strncpy (str, tstr, strlen (tstr));
		str[strlen (tstr)] = 0;
	} else {
		// TOO BIG STRING CANNOT REPLACE HERE
		ret = false;
	}
	free (tstr);
	r_list_free (spargs);
	r_list_free (bpargs);
	r_list_free (regs);
	return ret;
}

RParsePlugin r_parse_plugin_x86_pseudo = {
	.name = "x86.pseudo",
	.desc = "X86 pseudo syntax",
	.parse = &parse,
	.varsub = &varsub,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_x86_pseudo,
	.version = R2_VERSION
};
#endif

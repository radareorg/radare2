/* radare - LGPL - Copyright 2024 - pancake */

#include <r_asm.h>

// XXX seems like '(#)' doesnt works.. so it needs to be '( # )'
// this is a bug somewhere else
static bool replace(int argc, char *argv[], char *newstr) {
#define MAXPSEUDOOPS 10
	int i, j, k, d;
	char ch;
	const char *op0 = argv[0];
	if (!strcmp (op0, "ret") || !strcmp (op0, "rfe")) {
		strcpy (newstr, "return");
		return false;
	}
	struct {
		const char *op;
		const char *str;
		int args[MAXPSEUDOOPS];  // XXX can't use flex arrays, all unused will be 0
	} ops[] = {
#if 0
		{ "ret",  "return;"},
		{ "rfe",  "return;"},
#endif
		{ "nop",  ""},
		{ "debug",  "breakpoint"},
		{ "invalid",  ""},
		{ "movh.a",  "# = #", {1, 2}},
		{ "mov.aa",  "# = #", {1, 2}},
		{ "mov.u",  "# = #", {1, 2}},
		{ "mov.d",  "# = #", {1, 2}},
		{ "mov.a",  "# = #", {1, 2}},
		{ "movh",  "# = #", {1, 2}},
		{ "mov",  "# = #", {1, 2}},
		{ "sha",  "# = #", {1, 2}},
		{ "lea",  "# = #", {1, 2}},
		{ "nop",  ";"},
		{ "jnz.t", "if (#) goto loc_#", {1, 2}},
		{ "jnz", "if (#) goto loc_#", {1, 2}},
		{ "jla", "if (la) goto loc_#", {1}},
		{ "jl.t", "if (la) goto loc_#", {1}},
		{ "jne", "if (# != #) goto loc_#", {1, 2, 3}},
		{ "jeq", "if (# == #) goto loc_#", {1, 2, 3}},
		{ "jgez", "if (# >= #) goto loc_#", {1, 2, 3}},
		{ "jz.t", "if (# == #) goto loc_#", {1, 2, 3}},
		{ "jge", "if (# >= #) goto loc_#", {1, 2, 3}},
		{ "jge.u", "if (# >= #) goto loc_#", {1, 2, 3}},
		{ "jge.u", "if (# >= #) goto loc_#", {1, 2, 3}},
		{ "jeq.a", "if (# == #) goto loc_#", {1, 2, 3}},
		{ "ji", "goto #", {1}},
		{ "jz.t", "if (!#) goto loc_#", {1, 2}},
		{ "jz.a", "if (!#) goto loc_#", {1, 2}},
		{ "jz", "if (!#) goto loc_#", {1, 2}},
		{ "jnz", "if (#) goto loc_#", {1, 2}},
		{ "calli", "call # ()", {1}},
		{ "sub", "# = # - #", {1, 2, 3}},
		{ "add.a", "# += #", {1, 2, 3}},
		{ "addsc.a", "# = # + #", {1, 2, 3}},
		{ "addih", "# = # + #", {1, 2, 3}},
		{ "add", "# = # + #", {1, 2, 3}},
		{ "and", "# &= #", {1, 2}},
		{ "or", "# = # | #", {1, 2, 3}},
		{ "isync", ""},
		{ "dsync", ""},
		{ "st.w", "# = #", {1, 2}},
		{ "st.h", "# = #", {1, 2}},
		{ "st.bu", "# = #", {1, 2}},
		{ "st.b", "# = #", {1, 2}},
		{ "st.a", "# = #", {1, 2}},
		{ "ld.bu", "# = #", {1, 2}},
		{ "ld.w", "# = #", {1, 2}},
		{ "ld.a", "# = #", {1, 2}},
		{ "ld.b", "# = #", {1, 2}},
		{ "ld.h", "# = #", {1, 2}},
		{ "ld.hu", "# = #", {1, 2}},
		{ "sha", "# = sha(#)", {1, 2}},
		{ "sh", "# = # >> #", {1, 2, 3}},
		{ NULL }
	};
	for (i = 0; ops[i].op; i++) {
		if (strcmp (ops[i].op, argv[0])) {
			continue;
		}
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
				int idx = ops[i].args[d++];
				if (idx <= 0) {
					// XXX Shouldn't ever happen...
					continue;
				}
				const char *w = argv[idx];
				if (w) {
					strcpy (newstr + k, w);
					k += strlen (w) - 1;
				}
			} else {
				newstr[k] = ch;
			}
		}
		newstr[k] = '\0';
		return true;
	}

	RStrBuf *sb = r_strbuf_new ("");
	for (i = 0; i < argc; i++) {
		r_strbuf_append (sb, argv[i]);
		r_strbuf_append (sb, (i == argc - 1)?"":" ");
	}
	char *sbs = r_strbuf_drain (sb);
	strcpy (newstr, sbs);
	free (sbs);
	return false;
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	char w0[256], w1[256], w2[256], w3[256];
	int i;
	size_t len = strlen (data);
	int sz = 32;
	char *ptr, *optr, *end;
	if (len >= sizeof (w0) || sz >= sizeof (w0)) {
		return NULL;
	}
	// strdup can be slow here :?
	char *buf = strdup (data);
	if (!buf) {
		return NULL;
	}
	*w0 = *w1 = *w2 = *w3 = '\0';
	if (*buf) {
		end = buf + strlen (buf);
		ptr = strchr (buf, '(');
		if (!ptr) {
			ptr = strchr (buf, ' ');
			if (!ptr) {
				ptr = strchr (buf, '\t');
				if (!ptr) {
					ptr = end;
				}
			}
		}
		bool par = (ptr != buf && *ptr == '(');
		for (; ptr < end; ptr++) {
			if (*ptr != ' ') {
				if (*ptr == ')') {
					ptr--;
				}
				break;
			}
		}
		if (par) ptr++;
		r_str_ncpy (w0, buf, R_MIN (ptr - buf, sizeof (w0)) + 1);
		r_str_trim (w0);
		if (par) ptr--;
		r_str_ncpy (w1, ptr, R_MIN (end-ptr+1, sizeof (w1)) + 1);
		r_str_trim (w1);
		optr = ptr;
		ptr = strchr (ptr, ',');
		if (ptr) {
			*ptr++ = '\0';
			for (ptr++; ptr < end ; ptr++) {
				if (*ptr != ')' && *ptr != ' ') {
					// ptr++;
					break;
				}
			}
			r_str_ncpy (w1, optr, sizeof (w1));
			r_str_ncpy (w2, ptr, sizeof (w2));
			optr = ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				ptr = (char *)r_str_trim_head_ro (ptr + 1);
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
#if 0
	str = r_str_fixspaces (str);
#endif
	char *str = malloc (strlen (data) + 128);
	strcpy (str, data);
	replace (nw, wa, str);
	free (buf);
	return str;
}

static void parse_localvar(RAsm *a, char *newstr, size_t newstr_len, const char *var, const char *reg, char sign, char *ireg, bool att) {
	RParse *p = a->parse;
	RStrBuf *sb = r_strbuf_new ("");
	if (att) {
		if (p->localvar_only) {
			if (ireg) {
				r_strbuf_setf (sb, "(%%%s)", ireg);
			}
			snprintf (newstr, newstr_len - 1, "%s%s", var, r_strbuf_tostring (sb));
		} else {
			if (ireg) {
				r_strbuf_setf (sb, ", %%%s", ireg);
			}
			snprintf (newstr, newstr_len - 1, "%s(%%%s%s)", var, reg, r_strbuf_tostring (sb));
		}
	} else {
		if (ireg) {
			r_strbuf_setf (sb, " + %s", ireg);
		}
		if (p->localvar_only) {
			snprintf (newstr, newstr_len - 1, "%s%s", var, r_strbuf_tostring (sb));
		} else {
			snprintf (newstr, newstr_len - 1, "%s%s %c %s", reg, r_strbuf_tostring (sb), sign, var);
		}
	}
	r_strbuf_free (sb);
}

static void mk_reg_str(const char *regname, int delta, bool sign, bool att, char *ireg, char *dest, int len) {
	RStrBuf *sb = r_strbuf_new ("");
	if (att) {
		if (ireg) {
			r_strbuf_setf (sb, ", %%%s", ireg);
		}
		if (delta == 0) {
			snprintf (dest, len - 1, "(%%%s%s)", regname, r_strbuf_tostring (sb));
		} else if (delta < 10) {
			snprintf (dest, len - 1, "%s%d(%%%s%s)", sign ? "" : "-", delta, regname, r_strbuf_tostring (sb));
		} else {
			snprintf (dest, len - 1, "%s0x%x(%%%s%s)", sign ? "" : "-", delta, regname, r_strbuf_tostring (sb));
		}
	} else {
		if (ireg) {
			r_strbuf_setf (sb, " + %s", ireg);
		}
		if (delta == 0) {
			snprintf (dest, len - 1, "%s%s", regname, r_strbuf_tostring (sb));
		} else if (delta < 10) {
			snprintf (dest, len - 1, "%s%s %c %d", regname, r_strbuf_tostring (sb), sign ? '+':'-', delta);
		} else {
			snprintf (dest, len - 1, "%s%s %c 0x%x", regname, r_strbuf_tostring (sb), sign ? '+':'-', delta);
		}
	}
	r_strbuf_free (sb);
}

static char *subvar(RAsmPluginSession *aps, RAnalFunction *f, ut64 addr, int oplen, const char *data) {
	RAsm *a = aps->rasm;
	RParse *p = a->parse;
	RAnal *anal = a->analb.anal;
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

	if (f && p->varlist) {
		RList *bpargs = p->varlist (f, 'b');
		RList *spargs = p->varlist (f, 's');
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
				R_FREE (ireg);
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
				reg = anal->reg->alias[R_REG_ALIAS_SP];
			}
			mk_reg_str (reg, delta, sign == '+', att, ireg, oldstr, sizeof (oldstr));

			if (ucase) {
				r_str_case (oldstr, true);
			}
			parse_localvar (a, newstr, sizeof (newstr), sparg->name, reg, sign, ireg, att);
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
				R_FREE (ireg);
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
				reg = anal->reg->alias[R_REG_ALIAS_BP];
			}
			mk_reg_str (reg, delta, sign == '+', att, ireg, oldstr, sizeof (oldstr));
			if (ucase) {
				r_str_case (oldstr, true);
			}
			parse_localvar (a, newstr, sizeof (newstr), bparg->name, reg, sign, ireg, att);
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
			if (strstr (tstr, oldstr)) {
				tstr = r_str_replace (tstr, oldstr, newstr, 1);
				break;
			}
		}
		R_FREE (ireg);
		r_list_free (spargs);
		r_list_free (bpargs);
	}
#if 0
	char bp[32];
	if (anal->reg->name[R_REG_ALIAS_BP]) {
		strncpy (bp, anal->reg->name[R_REG_ALIAS_BP], sizeof (bp) - 1);
		if (isupper ((ut8)tstr[0])) {
			r_str_case (bp, true);
		}
		bp[sizeof (bp) - 1] = 0;
	} else {
		bp[0] = 0;
	}
#endif
	return tstr;
}

static void fini(RAsmPluginSession *aps) {
	RParse *p = aps->rasm->parse;
	R_FREE (p->retleave_asm);
}

RAsmPlugin r_asm_plugin_tricore = {
	.meta = {
		.name = "tricore",
		.desc = "TriCore pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
	.subvar = subvar,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_tricore,
	.version = R2_VERSION
};
#endif

/* radare - LGPL - Copyright 2024 - pancake */

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

static int replace(int argc, const char *argv[], char *newstr) {
#define MAXPSEUDOOPS 10
	int i, j, k, d;
	char ch;
	struct {
		int narg;
		const char *op;
		const char *str;
		int args[MAXPSEUDOOPS];
	} ops[] = {
		// { 0, "ldw", "# = [#]", { 1, 2 } },
		{ 0, "ldf", "# = #", { 1, 2 } },
		{ 0, "ldw", "# = [#]", { 1, 2 } },
		{ 3, "ld", "# = [# + #]", { 3, 2, 1 } },
		{ 2, "ld", "# = #", { 2, 1 } },
		{ 0, "dec", "# --", { 1 } },
		// { 2, "dec", "# -= #", { 1, 2 } },
		{ 0, "inc", "# ++", { 1 } },
		{ 0, "subw", "# -= #", { 1, 2 } },
		{ 0, "addw", "# += #", { 1, 2 } },
		{ 0, "jrne", "if (!zero) goto #", { 1 } },
		{ 0, "jra", "goto #", { 1 } },
		{ 0, "clrw", "# = 0", { 1 } },
		{ 0, "sllw", "# <<= 1", { 1 } },
		{ 0, "slaw", "# <<= 1", { 1 } },
		{ 0, "srlw", "# >>= 1", { 1 } },
		{ 0, "sraw", "# >>= 1", { 1 } },
		{ 0, "add", "# += #", { 1, 2 } },
		{ 0, NULL }
	};
	if (!newstr) {
		return false;
	}

	for (i = 0; ops[i].op; i++) {
		if (ops[i].narg) {
			if (argc - 1 != ops[i].narg) {
				continue;
			}
		}
		if (!strcmp (ops[i].op, argv[0])) {
			if (newstr) {
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
						if (w) {
							strcpy (newstr + k, w);
							k += strlen (w) - 1;
						}
					} else {
						newstr[k] = ch;
					}
				}
				newstr[k] = '\0';
			}
			// r_str_replace_char (newstr, '{', '(');
			// r_str_replace_char (newstr, '}', ')');
			return true;
		}
	}

	/* TODO: this is slow */
	newstr[0] = '\0';
	for (i = 0; i < argc; i++) {
		strcat (newstr, argv[i]);
		strcat (newstr, (!i || i == argc - 1)? " " : ",");
	}
	return false;
}

static int parse(RParse *p, const char *data, char *str) {
	char w0[256], w1[256], w2[256], w3[256], w4[256];
	int i, len = strlen (data);
	char *buf, *ptr, *optr;

	if (len >= sizeof (w0)) {
		return false;
	}
	// malloc can be slow here :?
	if (!(buf = malloc (len + 1))) {
		return false;
	}
	memcpy (buf, data, len + 1);
#if 0
	buf = r_str_replace (buf, "(0", "0", true);
	buf = r_str_replace (buf, "p)", "p", true);
	buf = r_str_replace (buf, "x)", "x", true);
#endif
#if 0
	r_str_replace_char (buf, '(', '{');
	r_str_replace_char (buf, ')', '}');
#endif
	if (*buf) {
		*w0 = *w1 = *w2 = *w3 = *w4 = '\0';
		ptr = strchr (buf, ' ');
		if (!ptr) {
			ptr = strchr (buf, '\t');
		}
		if (ptr) {
			*ptr = '\0';
			ptr = (char *)r_str_trim_head_ro (ptr + 1);
			strncpy (w0, buf, sizeof (w0) - 1);
			strncpy (w1, ptr, sizeof (w1) - 1);
			optr = ptr;
			if (ptr && *ptr == '[') {
				ptr = strchr (ptr + 1, ']');
			}
			if (ptr && *ptr == '{') {
				ptr = strchr (ptr + 1, '}');
			}
			if (!ptr) {
				R_LOG_ERROR ("Unbalanced bracket");
				free (buf);
				return false;
			}
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				ptr = (char *)r_str_trim_head_ro (ptr + 1);
				strncpy (w1, optr, sizeof (w1) - 1);
				strncpy (w2, ptr, sizeof (w2) - 1);
				optr = ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					ptr = (char *)r_str_trim_head_ro (ptr + 1);
					strncpy (w2, optr, sizeof (w2) - 1);
					strncpy (w3, ptr, sizeof (w3) - 1);
					optr = ptr;
					ptr = strchr (ptr, ',');
					if (ptr) {
						*ptr = '\0';
						ptr = (char *)r_str_trim_head_ro (ptr + 1);
						strncpy (w3, optr, sizeof (w3) - 1);
						strncpy (w4, ptr, sizeof (w4) - 1);
					}
				}
			}
		}
		{
			const char *wa[] = { w0, w1, w2, w3, w4 };
			int nw = 0;
			for (i = 0; i < 5; i++) {
				if (wa[i][0]) {
					nw++;
				}
			}
			replace (nw, wa, str);
		}
	}
	char *s = strdup (str);
	if (s) {
		s = r_str_replace (s, "wzr", "0", 1);
		s = r_str_replace (s, " lsl ", " << ", 1);
		s = r_str_replace (s, " lsr ", " >> ", 1);
		s = r_str_replace (s, "+ -", "- ", 1);
		s = r_str_replace (s, "- -", "+ ", 1);
		strcpy (str, s);
		free (s);
	}
	free (buf);
	r_str_fixspaces (str);
	return true;
}

static char *subs_var_string(RParse *p, RAnalVarField *var, char *tstr, const char *oldstr, const char *reg, int delta) {
	char *newstr = p->localvar_only
		? r_str_newf ("%s", var->name)
		: r_str_newf ("%s %c %s", reg, delta > 0 ? '+' : '-', var->name);
	if (IS_UPPER (*tstr)) {
		char *space = strrchr (newstr, ' ');
		if (space) {
			*space = 0;
			r_str_case (newstr, true);
			*space = ' ';
		}
	}
	char *ret = r_str_replace (tstr, oldstr, newstr, 1);
	free (newstr);
	return ret;
}

static bool subvar(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	r_return_val_if_fail (p, false);
	RList *spargs = NULL;
	RList *bpargs = NULL;
	RListIter *iter;
	RAnal *anal = p->analb.anal;
	char *oldstr;
	bool newstack = anal->opt.var_newstack;
	char *tstr = strdup (data);
	if (!tstr) {
		return false;
	}

	if (p->subrel) {
		char *rip;
		if (p->pseudo) {
			rip = (char *)r_str_casestr (tstr, "[pc +");
			if (!rip) {
				rip = (char *)r_str_casestr (tstr, "[pc -");
			}
		} else {
			rip = (char *)r_str_casestr (tstr, "[pc, ");
		}

		if (rip && !strchr (rip + 4, ',')) {
			rip += 4;
			char *tstr_new, *ripend = strchr (rip, ']');
			const char *neg = strchr (rip, '-');
			ut64 off = (oplen == 2 || strstr (tstr, ".w") || strstr (tstr, ".W")) ? 4 : 8;
			ut64 repl_num = (addr + off) & ~3;
			if (!ripend) {
				ripend = "]";
			}
			if (neg) {
				repl_num -= r_num_get (NULL, neg + 1);
			} else {
				repl_num += r_num_get (NULL, rip);
			}
			rip -= 3;
			*rip = 0;
			tstr_new = r_str_newf ("%s0x%08"PFMT64x"%s", tstr, repl_num, ripend);
			free (tstr);
			tstr = tstr_new;
		}
	}
	if (len > strlen (tstr)) {
		strcpy  (str, tstr);
	} else {
		// TOO BIG STRING CANNOT REPLACE HERE
		free (tstr);
		return false;
	}
	free (tstr);
	return true;
}

RParsePlugin r_parse_plugin_stm8_pseudo = {
	.name = "stm8.pseudo",
	.desc = "STM8 pseudo syntax",
	.parse = parse,
//	.subvar = &subvar,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_stm8_pseudo,
	.version = R2_VERSION
};
#endif

/* radare - LGPL - Copyright 2025 - pancake */

#include <r_lib.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_asm.h>

static int can_replace(const char *str, int idx, int max_operands) {
	if (str[idx] > '9' || str[idx] < '1') {
		return false;
	}
	if (str[idx + 1] != '\x00' && str[idx + 1] <= '9' && str[idx + 1] >= '1') {
		return false;
	}
	if ((int)((int)str[idx] - 0x30) > max_operands) {
		return false;
	}
	return true;
}

static int replace(int argc, const char *argv[], char *newstr) {
	int i,j,k;
	struct {
		const char *op;
		const char *str;
		int max_operands;
	} ops[] = {
		{ "sethi", "2 = 1 << 16", 2},
		{ "mov", "2 = 1", 2},
		{ "add", "3 = 1 + 2", 3},
		{ "sub", "3 = 1 - 2", 3},
		{ "ld", "2 = 1", 2},
		{ "ldb", "2 = .byte 1", 2},
		{ "ldub", "2 = .byte 1", 2},
		{ "or", "3 = 1 | 2", 3},
		{ "sra", "3 = 1 >> 2", 3},
		{ "srl", "3 = 1 >> 2", 3},
		{ "stb", "2 = .byte 1", 2},
		{ "st", "2 = .byte 1", 2},
		{ "sla", "3 = 1 << 2", 3},
		{ "sll", "3 = 1 << 2", 3},
		{ "be", "if equal goto 1", 1},
		{ "bne", "if not_equal goto 1", 1},
		{ "cmp", "compare 1, 2", 2},
		{ "nop", ""},
		{ "ret", "return", 0},
#if 0
		{ "call", "1()", 1},
#endif
		{ NULL }
	};

	for (i = 0; ops[i].op; i++) {
		if (!strcmp (ops[i].op, argv[0])) {
			if (newstr) {
				for (j = k = 0; ops[i].str[j] != '\0'; j++, k++) {
					if (can_replace (ops[i].str, j, ops[i].max_operands)) {
						const char *w = argv[ ops[i].str[j]-'0' ];
						if (w) {
							strcpy (newstr + k, w);
							k += strlen (w) - 1;
						}
					} else {
						newstr[k] = ops[i].str[j];
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
			strcat (newstr, (i == 0 || i== argc - 1)?" ":", ");
		}
	}

	return false;
}

#define REPLACE(x,y) do { \
	int snprintf_len1_ = snprintf (a, 32, x, w1, w1); \
	int snprintf_len2_ = snprintf (b, 32, y, w1);	\
	if (snprintf_len1_ < 32 && snprintf_len2_ < 32) { \
		p = r_str_replace (p, a, b, 0); \
	} \
} while (0)
#define WSZ 64

static char *parse(RAsmPluginSession *aps, const char *data) {
	int i, len = strlen (data);
	char w0[WSZ];
	char w1[WSZ];
	char w2[WSZ];
	char w3[WSZ];
	char w4[WSZ];
	char *buf, *ptr, *optr;

#if 0
	if (!strcmp (data, "jr ra")) {
		return strdup ("ret");
	}
#endif

	// malloc can be slow here :?
	if (!(buf = malloc (len + 1))) {
		return NULL;
	}
	memcpy (buf, data, len + 1);

	r_str_replace_char (buf, '(', ',');
	r_str_replace_char (buf, ')', ' ');
	r_str_trim (buf);
	char *str = NULL;
	if (*buf) {
		w0[0]='\0';
		w1[0]='\0';
		w2[0]='\0';
		w3[0]='\0';
		w4[0]='\0';
		ptr = strchr (buf, ' ');
		if (!ptr) {
			ptr = strchr (buf, '\t');
		}
		if (ptr) {
			*ptr = '\0';
			for (ptr++; *ptr == ' '; ptr++) {
				;
			}
			strncpy (w0, buf, WSZ - 1);
			strncpy (w1, ptr, WSZ - 1);

			optr=ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (ptr++; *ptr == ' '; ptr++) {
					;
				}
				strncpy (w1, optr, WSZ - 1);
				strncpy (w2, ptr, WSZ - 1);
				optr = ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (ptr++; *ptr == ' '; ptr++) {
						;
					}
					strncpy (w2, optr, WSZ - 1);
					strncpy (w3, ptr, WSZ - 1);
					optr=ptr;
// bonus
					ptr = strchr (ptr, ',');
					if (ptr) {
						*ptr = '\0';
						for (ptr++; *ptr == ' '; ptr++) {
							;
						}
						strncpy (w3, optr, WSZ - 1);
						strncpy (w4, ptr, WSZ - 1);
					}
				}
			}
		} else {
			strncpy (w0, buf, WSZ - 1);
		}
		{
			const char *wa[] = { w0, w1, w2, w3, w4 };
			int nw = 0;
			for (i = 0; i < 4; i++) {
				if (wa[i][0] != '\0') {
					nw++;
				}
			}
			str = malloc (strlen (data) + 128);
			strcpy (str, data);
			replace (nw, wa, str);
			{
				char *p = strdup (str);
				p = r_str_replace (p, "+ -", "- ", 0);
				p = r_str_replace (p, " + ]", " + 0]", 0);

				p = r_str_replace (p, "zero", "0", 1);
				if (!strncmp (p, "0 = ", 4)) {
					*p = 0; // nop
				}
				if (!strcmp (w1, w2)) {
					char a[32], b[32];

					// TODO: optimize
					REPLACE ("%s = %s +", "%s +=");
					REPLACE ("%s = %s -", "%s -=");
					REPLACE ("%s = %s &", "%s &=");
					REPLACE ("%s = %s |", "%s |=");
					REPLACE ("%s = %s ^", "%s ^=");
					REPLACE ("%s = %s >>", "%s >>=");
					REPLACE ("%s = %s <<", "%s <<=");
				}
				p = r_str_replace (p, ":", "0000", 0);
				strcpy (str, p);
				free (p);
			}
		}
	}
	free (buf);
	return str;
}

static char *subvar(RAsmPluginSession *aps, RAnalFunction *f, ut64 addr, int oplen, const char *data) {
	RAsm *a = aps->rasm;
	RParse *p = a->parse;
	RListIter *iter;
	char *oldstr;
	char *tstr = strdup (data);
	RAnal *anal = a->analb.anal;

	if (f && p->varlist) {
		RList *bpargs = p->varlist (f, 'b');
		RList *spargs = p->varlist (f, 's');
		const bool ucase = isupper (*tstr);
		RAnalVarField *var;
		r_list_foreach (spargs, iter, var) {
			st64 delta = p->get_ptr_at
				? p->get_ptr_at (f, var->delta, addr)
				: ST64_MAX;
			if (delta == ST64_MAX && var->field) {
				delta = var->delta;
			} else if (delta == ST64_MAX) {
				continue;
			}
			const char *reg = NULL;
			if (p->get_reg_at) {
				reg = p->get_reg_at (f, var->delta, addr);
			}
			if (!reg) {
				reg = anal->reg->alias[R_REG_ALIAS_SP];
			}
			char *tmpf;
			//TODO: honor asm pseudo
			if (R_ABS (delta) < 10) {
				tmpf = "%d(%s)";
			} else if (delta > 0) {
				tmpf = "0x%x(%s)";
			} else {
				tmpf = "-0x%x(%s)";
			}
			oldstr = r_str_newf (tmpf, R_ABS (delta), reg);
			if (ucase) {
				char *comma = strchr (oldstr, ',');
				if (comma) {
					*comma = 0;
					r_str_case (oldstr, true);
					*comma = ',';
				}
			}
			if (strstr (tstr, oldstr)) {
				char *newstr = (p->localvar_only)
					? r_str_newf ("(%s)", var->name)
					: r_str_newf ("%s%s(%s)", delta > 0 ? "" : "-", var->name, reg);
				tstr = r_str_replace (tstr, oldstr, newstr, 1);
				free (newstr);
				free (oldstr);
				break;
			}
			free (oldstr);
		}
		r_list_foreach (bpargs, iter, var) {
			char *tmpf = NULL;
			st64 delta = p->get_ptr_at
				? p->get_ptr_at (f, var->delta, addr)
				: ST64_MAX;
			if (delta == ST64_MAX && var->field) {
				delta = var->delta + f->bp_off;
			} else if (delta == ST64_MAX) {
				continue;
			}
			const char *reg = NULL;
			if (p->get_reg_at) {
				reg = p->get_reg_at (f, var->delta, addr);
			}
			if (!reg) {
				reg = anal->reg->alias[R_REG_ALIAS_BP];
			}
			if (R_ABS (delta) < 10) {
				tmpf = "%d(%s)";
			} else if (delta > 0) {
				tmpf = "0x%x(%s)";
			} else {
				tmpf = "-0x%x(%s)";
			}
			oldstr = r_str_newf (tmpf, R_ABS (delta), reg);
			if (ucase) {
				char *comma = strchr (oldstr, ',');
				if (comma) {
					*comma = 0;
					r_str_case (oldstr, true);
					*comma = ',';
				}
			}
			if (strstr (tstr, oldstr)) {
				char *newstr = (p->localvar_only)
					? r_str_newf ("(%s)", var->name)
					: r_str_newf ("%s%s(%s)", delta > 0 ? "" : "-", var->name, reg);
				tstr = r_str_replace (tstr, oldstr, newstr, 1);
				free (newstr);
				free (oldstr);
				break;
			}
			free (oldstr);
		}
		r_list_free (bpargs);
		r_list_free (spargs);
	}
	return tstr;
}

RAsmPlugin r_asm_plugin_sparc = {
	.meta = {
		.name = "sparc",
		.desc = "SPARC pseudo",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
	.subvar = subvar,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_sparc,
	.version = R2_VERSION
};
#endif

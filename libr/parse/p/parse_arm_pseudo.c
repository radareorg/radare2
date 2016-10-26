/* radare - LGPL - Copyright 2015-2016 - pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

static int replace(int argc, const char *argv[], char *newstr) {
	int i,j,k;
	struct {
		int narg;
		char *op;
		char *str;
	} ops[] = {
		{ 0, "abs",  "1 = abs(1)"},
		{ 0, "adc",  "1 = 2 + 3"},
		{ 3, "add",  "1 = 2 + 3"},
		{ 2, "add",  "1 += 2"},
		{ 2, "adds",  "1 += 2"},
		{ 3, "adds",  "1 = 2 + 3"},
		{ 3, "addw",  "1 = 2 + 3"},
		{ 3, "add.w",  "1 = 2 + 3"},
		{ 0, "adf",  "1 = 2 + 3"},
		{ 0, "adrp",  "1 = 2"},
		{ 0, "and",  "1 = 2 & 3"},
		{ 0, "ands",  "1 &= 2"},
		{ 0, "asls",  "1 = 2 << 3"},
		{ 0, "asl",  "1 = 2 << 3"},
		{ 0, "asrs",  "1 = 2 >> 3"},
		{ 0, "asr",  "1 = 2 >> 3"},
		{ 0, "b",  "jmp 1"},
		{ 0, "cbz",  "if !1 jmp 2"},
		{ 0, "cbnz",  "if 1 jmp 2"},
		{ 0, "b.w",  "jmp 1"},
		{ 0, "b.gt",  "jmp ifgt 1"},
		{ 0, "b.le",  "jmp ifle 1"},
		{ 0, "beq lr",  "ifeq ret"},
		{ 0, "beq",  "je 1"},
		{ 0, "call",  "1()"},
		{ 0, "bl",  "1()"},
		{ 0, "blx",  "1()"},
		{ 0, "bx lr",  "ret"},
		{ 0, "bxeq",  "je 1"},
		{ 0, "cmf",  "if (1 == 2)"},
		{ 0, "cmp",  "if (1 == 2)"},
		{ 0, "tst",  "if (1 == 2)"},
		{ 0, "dvf",  "1 = 2 / 3"},
		{ 0, "eor",  "1 = 2 ^ 3"},
		{ 0, "fdv",  "1 = 2 / 3"},
		{ 0, "fml",  "1 = 2 * 3"},
		{ 2, "ldr",  "1 = 2"},
		{ 2, "ldrb",  "1 = (byte) 2"},
		{ 2, "ldrsb",  "1 = (byte) 2"},
		{ 2, "ldr.w",  "1 = 2"},
		{ 2, "ldrsw",  "1 = 2"},
		{ 3, "ldr",  "1 = 2 + 3"},
		{ 3, "ldrb",  "1 = (byte) 2 + 3"},
		{ 3, "ldrsb",  "1 = (byte) 2 + 3"},
		{ 3, "ldr.w",  "1 = 2 + 3"},
		{ 3, "ldrsw",  "1 = 2 + 3"},
		{ 0, "lsl",  "1 = 2 << 3"},
		{ 0, "lsr",  "1 = 2 >> 3"},
		{ 0, "mov",  "1 = 2"},
		{ 0, "mvn",  "1 = 2"},
		{ 0, "movz",  "1 = 2"},
		{ 0, "movk",  "1 = 2"},
		{ 0, "movn",  "1 = 2"},
		{ 0, "vmov.i32",  "1 = 2"},
		{ 0, "muf",  "1 = 2 * 3"},
		{ 0, "mul",  "1 = 2 * 3"},
		{ 0, "muls",  "1 = 2 * 3"},
		{ 0, "orr",  "1 = 2 | 3"},
		{ 0, "rmf",  "1 = 2 % 3"},
		{ 0, "bge",  "(>=) goto 1"},
		{ 0, "sbc",  "1 = 2 - 3"},
		{ 0, "sqt",  "1 = sqrt(2)"},
		{ 0, "lsrs",  "1 = 2 >> 3"},
		{ 0, "lsls",  "1 = 2 << 3"},
		{ 0, "lsr",  "1 = 2 >> 3"},
		{ 0, "lsl",  "1 = 2 << 3"},
		{ 2, "str",  "2 = 1"},
		{ 2, "strb",  "2 = (byte) 1"},
		{ 2, "strh",  "2 = (half) 1"},
		{ 2, "strh.w",  "2 = (half) 1"},
		{ 3, "str",  "2 + 3 = 1"},
		{ 3, "strb",  "2 + 3 = (byte) 1"},
		{ 3, "strh",  "2 + 3 = (half) 1"},
		{ 3, "strh.w",  "2 + 3 = (half) 1"},
		{ 3, "sub",  "1 = 2 - 3"},
		{ 3, "subs",  "1 = 2 - 3"},
		{ 2, "sub",  "1 -= 2"}, // THUMB
		{ 2, "subs",  "1 -= 2"}, // THUMB
		{ 0, "swp",  "swap(1, 2)"},
		/* arm thumb */
		{ 0, "movs",  "1 = 2"},
		{ 0, "movw",  "1 = 2"},
		{ 0, "movt",  "1 |= 2 << 16"},
		{ 0, "vmov",  "1 = (float) 2 . 3"},
		{ 0, "vdiv.f64", "1 = (float) 2 / 3" },
		{ 0, "addw",  "1 = 2 + 3"},
		{ 0, "sub.w",  "1 = 2 - 3"},
		{ 0, "tst.w", "if (1 == 2)"},
		{ 0, "lsr.w", "1 = 2 >> 3"},
		{ 0, "lsl.w", "1 = 2 << 3"},
		{ 0, "pop.w",  "pop 1"},
		{ 0, "vpop",  "pop 1"},
		{ 0, "vpush",  "push 1"},
		{ 0, "push.w",  "push 1"},
		{ 0, NULL }
	};
	if (!newstr) {
		return false;
	}

	for (i = 0; ops[i].op != NULL; i++) {
		if (ops[i].narg) {
			if (argc-1 != ops[i].narg) {
				continue;
			}
		}
		if (!strcmp (ops[i].op, argv[0])) {
			for (j = k = 0; ops[i].str[j] != '\0'; j++, k++) {
				if (ops[i].str[j] >= '0' && ops[i].str[j] <= '9') {
					int idx = ops[i].str[j]-'0';
					if (idx < argc) {
						const char *w = argv[idx];
						if (w) {
							strcpy (newstr + k, w);
							k += strlen (w) - 1;
						}
					}
				} else {
					newstr[k] = ops[i].str[j];
				}
			}
			newstr[k] = '\0';
			r_str_replace_char (newstr, '{', '(');
			r_str_replace_char (newstr, '}', ')');
			return true;
		}
	}

	/* TODO: this is slow */
	newstr[0] = '\0';
	for (i = 0; i < argc; i++) {
		strcat (newstr, argv[i]);
		strcat (newstr, (!i || i == argc - 1)? " " : ",");
	}
	r_str_replace_char (newstr, '{', '(');
	r_str_replace_char (newstr, '}', ')');
	return false;
}

static int parse(RParse *p, const char *data, char *str) {
	char w0[256], w1[256], w2[256], w3[256];
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
	if (*buf) {
		*w0 = *w1 = *w2 = *w3 = '\0';
		ptr = strchr (buf, ' ');
		if (!ptr) {
			ptr = strchr (buf, '\t');
		}
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr==' '; ptr++);
			strncpy (w0, buf, sizeof (w0) - 1);
			strncpy (w1, ptr, sizeof (w1) - 1);

			optr = ptr;
			if (*ptr == '(') { 
				ptr = strchr (ptr+1, ')'); 
			}
			if (ptr && *ptr == '[') {
				ptr = strchr (ptr+1, ']'); 
			}
			if (ptr && *ptr == '{') { 
				ptr = strchr (ptr+1, '}'); 
			}
			if (!ptr) {
				eprintf ("Unbalanced bracket\n");
				free(buf);
				return false;
			}
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
			for (i = 0; i < 4; i++) {
				if (wa[i][0]) {
					nw++;
				}
			}
			replace (nw, wa, str);
		}
	}
	{
		char *s = strdup (str);
		s = r_str_replace (s, "+ -", "- ", 1);
		s = r_str_replace (s, "- -", "+ ", 1);
		strcpy (str, s);
		free (s);
	}
	free (buf);
	return true;
}

static bool varsub(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	RAnalVar *var;
	RListIter *iter;
	char *oldstr, *newstr;
	char *tstr = strdup (data);
	if (!tstr) {
		return false;
	}
	RList *spargs, *bpargs, *regargs;

	if (!p->varlist) {
		free (tstr);
		return false;
	}
	if (p->relsub) {
		char *rip = (char *)r_str_casestr (tstr, "[pc, ");
		if (rip) {
			rip += 4;
			char *tstr_new, *ripend = strchr (rip, ']');
			const char *neg = strchr (rip, '-');
			ut64 repl_num = (2 * oplen) + addr;
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

	regargs = p->varlist (p->anal, f, 'r');
	bpargs = p->varlist (p->anal, f, 'b');
	spargs = p->varlist (p->anal, f, 's');
	bool ucase = IS_UPPER (*tstr);
	r_list_foreach (bpargs, iter, var) {
		if (var->delta > -10 && var->delta < 10) {
			oldstr = r_str_newf ("[%s, %d]",
				p->anal->reg->name[R_REG_NAME_BP],
				var->delta);
		} else if (var->delta > 0) {
			oldstr = r_str_newf ("[%s, 0x%x]",
			p->anal->reg->name[R_REG_NAME_BP],
				var->delta);
		} else {
			oldstr = r_str_newf ("[%s, -0x%x]",
				p->anal->reg->name[R_REG_NAME_BP],
				-var->delta);
		}
		if (ucase) {
			char *comma = strchr (oldstr, ',');
			if (comma) {
				*comma = 0;
				r_str_case (oldstr, true);
				*comma = ',';
			}
		}
		if (strstr (tstr, oldstr)) {
			newstr = r_str_newf ("[%s %c %s]",
				p->anal->reg->name[R_REG_NAME_BP],
				var->delta > 0 ? '+' : '-',
				var->name);
			if (ucase) {
				char *comma = strchr (newstr, ' ');
				if (comma) {
					*comma = 0;
					r_str_case (newstr, true);
					*comma = ' ';
				}
			}
			tstr = r_str_replace (tstr, oldstr, newstr, 1);
			free (newstr);
			free (oldstr);
			break;
		}
		free(oldstr);
	}
	r_list_foreach (spargs, iter, var) {
		if (var->delta > -10 && var->delta < 10) {
			oldstr = r_str_newf ("[sp, %d]", var->delta);
		} else if (var->delta > 0) {
			oldstr = r_str_newf ("[sp, 0x%x]", var->delta);
		} else {
			oldstr = r_str_newf ("[sp, -0x%x]", -var->delta);
		}
		if (strstr (tstr, oldstr)) {
			newstr = r_str_newf ("[sp %c %s]",
				var->delta > 0 ? '+' : '-',
				var->name);
			tstr = r_str_replace (tstr, oldstr, newstr, 1);
			free (newstr);
			free (oldstr);
			break;
		}
		free (oldstr);
		if (var->delta > -10 && var->delta < 10) {
			oldstr = r_str_newf ("[%s, %d]",
				p->anal->reg->name[R_REG_NAME_SP],
				var->delta);
		} else if (var->delta > 0) {
			oldstr = r_str_newf ("[%s, 0x%x]",
				p->anal->reg->name[R_REG_NAME_SP],
				var->delta);
		} else {
			oldstr = r_str_newf ("[%s, -0x%x]",
				p->anal->reg->name[R_REG_NAME_SP],
				-var->delta);
		}
		if (strstr (tstr, oldstr)) {
			newstr = r_str_newf ("[%s %c %s]",
				p->anal->reg->name[R_REG_NAME_BP],
				var->delta > 0 ? '+' : '-',
				var->name);
			tstr = r_str_replace (tstr, oldstr, newstr, 1);
			free (newstr);
			free (oldstr);
			break;
		}
		free (oldstr);
	}
	r_list_foreach (regargs, iter, var) {
		RRegItem *r = r_reg_index_get (p->anal->reg, var->delta);
		if (r && r->name && strstr (tstr, r->name)) {
			tstr = r_str_replace (tstr, r->name, var->name, 1);
		}
	}
	if (len > strlen (tstr)) {
		strncpy (str, tstr, strlen (tstr));
		str[strlen (tstr)] = 0;
	} else {
		// TOO BIG STRING CANNOT REPLACE HERE
		free (tstr);
		return false;
	}
	free (tstr);
	return true;
}

RParsePlugin r_parse_plugin_arm_pseudo = {
	.name = "arm.pseudo",
	.desc = "ARM/ARM64 pseudo syntax",
	.parse = parse,
	.varsub = &varsub,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_arm_pseudo,
	.version = R2_VERSION
};
#endif

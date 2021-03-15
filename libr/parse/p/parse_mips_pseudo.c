/* radare - LGPL - Copyright 2012-2017 - pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

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
		char *op;
		char *str;
		int max_operands;
	} ops[] = {
		{ "add", "1 = 2 + 3", 3},
		{ "addi",  "1 = 2 + 3", 3},
		{ "addiu",  "1 = 2 + 3", 3},
		{ "addu",  "1 = 2 + 3", 3},
		{ "and",  "1 = 2 & 3", 3},
		{ "andi",  "1 = 2 & 3", 3},
		{ "b",  "goto 1", 1},
		{ "bal",  "call 1", 1},
		{ "begzal", "if (1 >= 0) call 2", 2},
		{ "beq",  "if (1 == 2) goto 3", 3},
		{ "beqz",  "if (!1) goto 2", 2},
		{ "bgez", "if (1 >= 0) goto 2", 2},
		{ "bgtz", "if (1 > 0) goto 2", 2},
		{ "blez", "if (1 <= 0) goto 2", 2},
		{ "bltz", "if (1 < 0) goto 2", 2},
		{ "bltzal", "if (1 < 0) call 2", 2},
		{ "bne",  "if (1 != 2) goto 3", 3},
		{ "bnez",  "if (1) goto 2", 2},
		{ "j",   "goto 1", 1},
		{ "jal",   "call 1", 1},
		{ "jalr",  "call 1", 1},
		{ "jr",   "goto 1", 1},
		{ "lb",  "1 = byte [3 + 2]", 3},
		{ "lbu",  "1 = (unsigned) byte [3 + 2]", 3},
		{ "lh",  "1 = halfword [3 + 2]", 3},
		{ "lhu",  "1 = (unsigned) halfword [3 + 2]", 3},
		{ "li",   "1 = 2", 2},
		{ "lui",  "1 = 2 << 16", 2},
		{ "lw",  "1 = [3 + 2]", 3},
		{ "mfhi",  "1 = hi", 1},
		{ "mflo",  "1 = lo", 1},
		{ "move",  "1 = 2", 2},
		{ "movn",  "if (3) 1 = 2", 3},
		{ "movz",  "if (!3) 1 = 2", 3},
		{ "mult",  "(hi,lo) = 1 * 2", 2},
		{ "multu",  "unsigned (hi,lo) = 1 * 2", 2},
		{ "mul",  "1 = 2 * 3", 3},
		{ "mulu",  "1 = 2 * 3", 3},
		{ "negu",  "1 = ~2", 2},
		{ "nop",   "", 0},
		{ "nor",   "1 = ~(2 | 3)", 3},
		{ "or",   "1 = 2 | 3", 3},
		{ "ori",   "1 = 2 | 3", 3},
		{ "sb",  "byte [3 + 2] = 1", 3},
		{ "sh",  "halfword [3 + 2] = 1", 3},
		{ "sll",  "1 = 2 << 3", 3},
		{ "sllv",  "1 = 2 << 3", 3},
		{ "slr",  "1 = 2 >> 3", 3}, // logic
		{ "slt",  "1 = (2 < 3)", 3},
		{ "slti",  "1 = (2 < 3)", 3},
		{ "sltiu",  "1 = (unsigned) (2 < 3)", 3},
		{ "sltu",  "1 = (unsigned) (2 < 3)", 3},
		{ "sra",  "1 = (signed) 2 >> 3", 3}, // arithmetic
		{ "srl",  "1 = 2 >> 3", 3},
		{ "srlv",  "1 = 2 >> 3", 3},
		{ "subu",  "1 = 2 - 3", 3},
		{ "sub",  "1 = 2 - 3", 3},
		{ "sw",  "[3 + 2] = 1", 3},
		{ "syscall",  "syscall", 0},
		{ "xor",  "1 = 2 ^ 3", 3},
		{ "xori",  "1 = 2 ^ 3", 3},
		{ NULL }
	};

	for (i=0; ops[i].op != NULL; i++) {
		if (!strcmp (ops[i].op, argv[0])) {
			if (newstr != NULL) {
				for (j=k=0;ops[i].str[j]!='\0';j++,k++) {
					if (can_replace (ops[i].str, j, ops[i].max_operands)) {
						const char *w = argv[ ops[i].str[j]-'0' ];
						if (w != NULL) {
							strcpy (newstr+k, w);
							k += strlen (w) - 1;
						}
					} else {
						newstr[k] = ops[i].str[j];
					}
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
			strcat (newstr, (i == 0 || i== argc - 1)?" ":", ");
		}
	}

	return false;
}

#define WSZ 64
static int parse(RParse *p, const char *data, char *str) {
	int i, len = strlen (data);
	char w0[WSZ];
	char w1[WSZ];
	char w2[WSZ];
	char w3[WSZ];
	char w4[WSZ];
	char *buf, *ptr, *optr;

	if (!strcmp (data, "jr ra")) {
		strcpy (str, "ret");
		return true;
	}

	// malloc can be slow here :?
	if (!(buf = malloc (len + 1))) {
		return false;
	}
	memcpy (buf, data, len+1);

	r_str_replace_char (buf, '(', ',');
	r_str_replace_char (buf, ')', ' ');
	r_str_trim (buf);

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
			for (++ptr; *ptr == ' '; ptr++) {
				;
			}
			strncpy (w0, buf, WSZ - 1);
			strncpy (w1, ptr, WSZ - 1);

			optr=ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr == ' '; ptr++) {
					;
				}
				strncpy (w1, optr, WSZ - 1);
				strncpy (w2, ptr, WSZ - 1);
				optr=ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (++ptr; *ptr == ' '; ptr++) {
						;
					}
					strncpy (w2, optr, WSZ - 1);
					strncpy (w3, ptr, WSZ - 1);
					optr=ptr;
// bonus
					ptr = strchr (ptr, ',');
					if (ptr) {
						*ptr = '\0';
						for (++ptr; *ptr == ' '; ptr++) {
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
			for (i=0; i<4; i++) {
				if (wa[i][0] != '\0') {
					nw++;
				}
			}
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
#define REPLACE(x,y) do { \
		int snprintf_len1_ = snprintf (a, 32, x, w1, w1); \
		int snprintf_len2_ = snprintf (b, 32, y, w1);	\
		if (snprintf_len1_ < 32 && snprintf_len2_ < 32) { \
			p = r_str_replace (p, a, b, 0); \
		} \
	} while (0)

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
	return true;
}

static bool subvar(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	RListIter *iter;
	char *oldstr;
	char *tstr = strdup (data);
	RAnal *anal = p->analb.anal;

	if (!p->varlist) {
		free (tstr);
		return false;
	}
	RList *bpargs = p->varlist (f, 'b');
	RList *spargs = p->varlist (f, 's');
	const bool ucase = IS_UPPER (*tstr);
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
			reg = anal->reg->name[R_REG_NAME_SP];
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
			reg = anal->reg->name[R_REG_NAME_BP];
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
	bool ret = true;
	if (len > strlen (tstr)) {
		strcpy (str, tstr);
	} else {
		// TOO BIG STRING CANNOT REPLACE HERE
		ret = false;
	}
	free (tstr);
	r_list_free (bpargs);
	r_list_free (spargs);
	return ret;
}

RParsePlugin r_parse_plugin_mips_pseudo = {
	.name = "mips.pseudo",
	.desc = "MIPS pseudo syntax",
	.init = NULL,
	.fini = NULL,
	.parse = parse,
	.subvar = subvar,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_mips_pseudo,
	.version = R2_VERSION
};
#endif

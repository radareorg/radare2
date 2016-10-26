/* radare - LGPL - Copyright 2015 - pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

static int can_replace(const char *str, int idx, int max_operands) {
	int ret = true;
	if (str[idx] > '9' || str[idx] < '1') ret = false;
	if (str[idx + 1] != '\x00' && str[idx + 1] <= '9' && str[idx + 1] >= '1')
		ret = false;
	if ((int)((int)str[idx] - 0x30) > max_operands) ret = false;
	return ret;
}

static int replace(int argc, const char *argv[], char *newstr) {
	int i,j,k;
	struct {
		char *op;
		char *str;
		int max_operands;
	} ops[] = {
		{ "mr",   "1 = 2", 2},
		{ "li",   "1 = 2", 2},
		{ "lis",   "1 = 2", 2},
		{ "or",   "1 = 2 | 3", 3},
		{ "ori",   "1 = 2 | 3", 3},
		{ "stwu",   "[ 3 + 2 ] = 1", 3},
		{ "stw",   "[ 3 + 2 ] = 1", 3},

		{ "andi.",  "1 = 2 & 3", 3},
		{ "add",  "1 = 2 + 3", 3},
		{ "addf",  "1 = 2 + 3", 3},
		{ "subf",  "1 = 2 + 3", 3},
		{ "addi",  "1 = 2 + 3", 3},
		{ "addiu",  "1 = 2 + 3", 3},
		{ "addu",  "1 = 2 + 3", 3},
		{ "and",  "1 = 2 & 3", 3},
		{ "andi",  "1 = 2 & 3", 3},
		{ "b",  "goto 1", 1},
		{ "bal",  "call 1", 1},
		{ "begz", "if (1 >= 0) goto 2", 2},
		{ "begzal", "if (1 >= 0) call 2", 2},
		{ "beq",  "if (1 == 2) goto 3", 3},
		{ "beqz",  "if (!1) goto 2", 2},
		{ "bgtz", "if (1 > 0) goto 2", 2},
		{ "bltz", "if (1 < 0) goto 2", 2},
		{ "bltzal", "if (1 < 0) call 2", 2},
		{ "bne",  "if (1 != 2) goto 3", 3},
		{ "bnez",  "if (1) goto 2", 2},
		{ "j",   "call 1", 1},
		{ "jal",   "call 1", 1},
		{ "jalr",  "call 1", 1},
		{ "jr",   "ret 1", 1},
		{ "lb",  "1 = byte [3 + 2]", 3},
		{ "lbu",  "1 = byte [3 + 2]", 3},
		{ "lwz",  "1 = halfword [3 + 2]", 3},
		{ "lui",  "1 |= 2 << 16", 2},
		{ "lw",  "1 = [3 + 2]", 3},
		{ "move",  "1 = 2", 1},
		{ "mult",  "1 = 2 * 3", 3},
		{ "multu",  "1 = 2 * 3", 3},
		{ "negu",  "1 = !2", 2},
		{ "nop",   "", 0},
		{ "nor",   "1 = ~(2 | 3)", 3},
		{ "sb",  "byte [3 + 2] = 1", 3},
		{ "sh",  "halfword [3 + 2] = 1", 3},
		{ "sll",  "1 = 2 << 3", 3},
		{ "sllv",  "1 = 2 << 3", 3},
		{ "slr",  "1 = 2 >> 3", 3}, // logic
		{ "slt",  "1 = (2 < 3)", 3},
		{ "slti",  "1 = (2 < 3)", 3},
		{ "sltiu",  "1 = (2 < 3)", 3},
		{ "sltu",  "1 = unsigned (2 < 3)", 3},
		{ "sra",  "1 = 2 >> 3", 3}, // arithmetic
		{ "srl",  "1 = 2 >> 3", 3},
		{ "srlv",  "1 = 2 >> 3", 3},
		{ "subu",  "1 = 2 - 3", 3},
		{ "sub",  "1 = 2 - 3", 3},
		{ "sw",  "[3 + 2] = 1", 3},
		{ "xor",  "1 = 2 ^ 3", 3},
		{ "xori",  "1 = 2 ^ 3", 3},
		{ NULL }
	};

	for (i=0; ops[i].op != NULL; i++) {
		if (!strcmp (ops[i].op, argv[0])) {
			if (newstr != NULL) {
				for (j=k=0;ops[i].str[j]!='\0';j++,k++) {
					if (can_replace(ops[i].str, j, ops[i].max_operands)) {
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
	if (!(buf = malloc (len+1)))
		return false;
	memcpy (buf, data, len+1);

	r_str_replace_char (buf, '(', ',');
	r_str_replace_char (buf, ')', ' ');
	r_str_chop (buf);

	if (*buf) {
		w0[0]='\0';
		w1[0]='\0';
		w2[0]='\0';
		w3[0]='\0';
		w4[0]='\0';
		ptr = strchr (buf, ' ');
		if (!ptr)
			ptr = strchr (buf, '\t');
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr==' '; ptr++);
			strncpy (w0, buf, WSZ - 1);
			strncpy (w1, ptr, WSZ - 1);

			optr=ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr==' '; ptr++);
				strncpy (w1, optr, WSZ - 1);
				strncpy (w2, ptr, WSZ - 1);
				optr=ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (++ptr; *ptr==' '; ptr++);
					strncpy (w2, optr, WSZ - 1);
					strncpy (w3, ptr, WSZ - 1);
					optr=ptr;
// bonus
					ptr = strchr (ptr, ',');
					if (ptr) {
						*ptr = '\0';
						for (++ptr; *ptr==' '; ptr++);
						strncpy (w3, optr, WSZ - 1);
						strncpy (w4, ptr, WSZ - 1);
					}
				}
			}
		}
		{
			const char *wa[] = { w0, w1, w2, w3, w4 };
			int nw = 0;
			for (i=0; i<4; i++) {
				if (wa[i][0] != '\0')
				nw++;
			}
			replace (nw, wa, str);
{
	char *p = strdup (str);
	p = r_str_replace (p, "+ -", "- ", 0);
#if EXPERIMENTAL_ZERO
	p = r_str_replace (p, "zero", "0", 0);
	if (!memcmp (p, "0 = ", 4)) *p = 0; // nop
#endif
	if (!strcmp (w1, w2)) {
		char a[32], b[32];
#define REPLACE(x,y) \
		sprintf (a, x, w1, w1); \
		sprintf (b, y, w1); \
		p = r_str_replace (p, a, b, 0);

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

struct r_parse_plugin_t r_parse_plugin_ppc_pseudo = {
	.name = "ppc.pseudo",
	.desc = "PowerPC pseudo syntax",
	.parse = parse,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_ppc_pseudo,
	.version = R2_VERSION
};
#endif

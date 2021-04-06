/* radare - LGPL - Copyright 2016 - pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

static bool can_replace(const char *str, int idx, int max_operands) {
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
		{ "move",  "2 = 1", 2},
		{ "movea",  "2 = 1", 2},
		{ "moveq",  "2 = 1", 2},
		{ "movem",  "2 = 1", 2},
		{ "lea",  "2 = 1", 2},
		{ "bsr",  "1()", 1},
		{ "jsr",  "1()", 1},
		{ "beq",  "if (==) jmp 1", 1},
		{ "blt",  "if (<) jmp 1", 1},
		{ "ble",  "if (<=) jmp 1", 1},
		{ "bgt",  "if (>) jmp 1", 1},
		{ "bge",  "if (>=) jmp 1", 1},
		{ "bcs",  "if (cs) jmp 1", 1},
		{ "bcc",  "if (cc) jmp 1", 1},
		{ "bra",  "jmp 1", 1},
		{ "jmp",  "jmp 1", 1},
		{ "rts",  "ret", 2},
		{ "btst",  "1 == 2", 2},
		{ "cmp",  "1 == 2", 2},
		{ "cmpi",  "2 == 1", 2},
		{ "add",  "1 += 2", 2},
		{ "addi",  "1 += 2", 2},
		{ "adda",  "1 += 2", 2},
		{ "sub",  "1 += 2", 2},
		{ "subq",  "1 += 2", 2},
		{ "tst",  "1 == 2", 2},
		{ "ori",  "2 |= 1", 2},
		{ "or",  "2 |= 1", 2},
		{ "lsr",  "2 >>= 1", 2},
		{ "lsl",  "2 <<= 1", 2},
		{ "andi",  "2 &= 1", 2},
		{ "nop",  ""},
//
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

	r_str_replace_in (buf, len+1, ".l", "", 1);
	r_str_replace_in (buf, len+1, ".w", "", 1);
	r_str_replace_in (buf, len+1, ".d", "", 1);
	r_str_replace_in (buf, len+1, ".b", "", 1);
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
		}
		{
			const char *wa[] = { w0, w1, w2, w3, w4 };
			int nw = 0;
			for (i = 0; i < 5; i++) {
				if (wa[i][0] != '\0') {
					nw++;
				}
			}
			replace (nw, wa, str);
			{
				char *pluseq = strstr (str, "+ =");
				if (pluseq) {
					memcpy (pluseq, " +=", 3);
				}
			}
		}
	}
	free (buf);
	return true;
}

RParsePlugin r_parse_plugin_m68k_pseudo = {
	.name = "m68k.pseudo",
	.desc = "M68K pseudo syntax",
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_m68k_pseudo,
	.version = R2_VERSION
};
#endif

/* radare - LGPL - Copyright 2015 - pancake, qnix */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

typedef enum {
	IND_IDX = 0,
	IDX_IND = 1,
	NORM = 2,
} ADDR_TYPE;

static int replace(int argc, const char *argv[], char *newstr, ADDR_TYPE type) {
	int i, j, k;
	struct {
		int narg;
		const char *op;
		const char *str;
	} ops[] = {
		{1, "lda", "a = 1"},
		{2, "lda", "a = (1+2)"},
		{1, "ldx", "x = 1"},
		{2, "ldx", "x = (1+2)"},
		{1, "ldy", "y = 1"},
		{2, "ldy", "y = (1+2)"},
		{1, "sta", "[1] = a"},
		{2, "sta", "[1+2 ] = a"},
		{1, "stx", "[1] = x"},
		{2, "stx", "[1+2] = x"},
		{1, "sty", "[1] = y"},
		{2, "sty", "[1+2] = y"},
		{1, "dec", "1--"},
		{2, "dec", "(1+2)--"},
		{0, "dcx", "x--"},
		{0, "dcy", "y--"},
		{1, "inc", "1++"},
		{2, "inc", "(1+2)++"},
		{0, "inx", "x++"},
		{0, "iny", "y++"},
		{1, "adc", "a += 1"},
		{2, "adc", "a += (1+2)"},
		{1, "sbc", "a -= 1"},
		{2, "sbc", "a -= (1+2)"},
		{0, "pha", "push a"},
		{1, "and", "a &= 1"},
		{2, "and", "a &= (1+2)"},
		{1, "eor", "a ^= 1"},
		{2, "eor", "a ^= (1+2)"},
		{1, "ora", "a |= 1"},
		{2, "ora", "a |= (1+2)"},
		{0, "tax", "x = a"},
		{0, "tay", "y = a"},
		{0, "txa", "a = x"},
		{0, "tya", "a = y"},
		{0, "tsx", "x = s"},
		{0, "txs", "s = x"},
		{0, "brk", "break"},
		{0, "clc", "clear_carry"},
		{0, "cld", "clear_decimal"},
		{0, "cli", "clear_interrupt"},
		{0, "clv", "clear_overflow"},
		{0, "sec", "set_carry"},
		{0, "sed", "set_decimal"},
		{0, "sei", "set_interrupt"},
		{1, "jsr", "1()"},
		{0, NULL}};
	if (!newstr) {
		return false;
	}

	for (i = 0; ops[i].op != NULL; i++) {
		if (ops[i].narg) {
			if (argc - 1 != ops[i].narg) {
				continue;
			}
		}
		if (!strcmp(ops[i].op, argv[0])) {
			for (j = k = 0; ops[i].str[j] != '\0'; j++, k++) {
				if (IS_DIGIT(ops[i].str[j])) {
					const char *w = argv[ops[i].str[j] - '0'];
					if (w != NULL) {
						strcpy(newstr + k, w);
						k += strlen(w) - 1;
					}
				} else {
					newstr[k] = ops[i].str[j];
				}
			}
			newstr[k] = '\0';
			if (argc == 4 && argv[2][0] == '[') {
				strcat (newstr + k, "+");
				strcat (newstr + k + 3, argv[2]);
			}
			return true;
		}
	}

	/* TODO: this is slow */
	newstr[0] = '\0';
	for (i = 0; i < argc; i++) {
		strcat (newstr, argv[i]);
		strcat (newstr, (i == 0 || i == argc - 1) ? " " : ",");
	}
	return false;
}

static ADDR_TYPE addr_type(const char *str) {
	if (strchr(str, '(')) {
		char *e = strchr (str, ')');
		if (!e) {
			return NORM;
		}
		char *o = strchr (e, ',');
		return (o) ? IND_IDX : IDX_IND;
	}
	return NORM;
}

static int parse(RParse *p, const char *data, char *str) {
	char w0[256], w1[256], w2[256];
	int i, len = strlen (data);
	char *buf, *ptr, *optr;
	ADDR_TYPE atype;

	if (len >= sizeof (w0)) {
		return false;
	}
	// malloc can be slow here :?
	if (!(buf = malloc (len + 1))) {
		return false;
	}
	memcpy (buf, data, len + 1);

	if (*buf) {
		atype = addr_type (buf);
		r_str_replace_char (buf, '(', ' ');
		r_str_replace_char (buf, ')', ' ');
		*w0 = *w1 = *w2 = '\0';
		ptr = strchr (buf, ' ');
		if (!ptr) {
			ptr = strchr (buf, '\t');
		}
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr == ' '; ptr++) {
				;
			}
			strncpy (w0, buf, sizeof(w0) - 1);
			strncpy (w1, ptr, sizeof(w1) - 1);
			optr = ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr == ' '; ptr++) {
					;
				}
				strncpy (w1, optr, sizeof(w1) - 1);
				strncpy (w2, ptr, sizeof(w2) - 1);
			}
		} else {
			strncpy (w0, buf, sizeof(w0) - 1);
		}

		const char *wa[] = {w0, w1, w2};
		int nw = 0;
		for (i = 0; i < 3; i++) {
			if (wa[i][0]) {
				nw++;
			}
		}
		replace (nw, wa, str, atype);
	}

	free (buf);

	return true;
}

RParsePlugin r_parse_plugin_6502_pseudo = {
	.name = "6502.pseudo",
	.desc = "6502 pseudo syntax",
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_6502_pseudo,
	.version = R2_VERSION};
#endif

/* radare - LGPL - Copyright 2017-2019 - wargio */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

static bool replace(int argc, const char *argv[], char *newstr) {
	int i,j,k;
	struct {
		const char *op;
		const char *str;
	} ops[] = {
		{ "add",     "A += B"},
		{ "adc",     "A += B + carry"},
		{ "adiw",    "A+1:A += B"},
		{ "sub",     "A -= B"},
		{ "subi",    "A -= B"},
		{ "sbc",     "A -= (B + carry)"},
		{ "sbci",    "A -= (B + carry)"},
		{ "sbiw",    "A+1:A -= B"},
		{ "and",     "A &= B"},
		{ "andi",    "A &= B"},
		{ "or",      "A |= B"},
		{ "ori",     "A |= B"},
		{ "eor",     "A ^= B"},
		{ "com",     "A = 0xff - A"},
		{ "neg",     "A = -A"},
		{ "sbr",     "A |= B"},
		{ "cbr",     "A &= (0xff - B)"},
		{ "inc",     "A++"},
		{ "dec",     "A--"},
		{ "tst",     "A &= A"},
		{ "clr",     "A ^= A"},
		{ "ser",     "A = 0xff"},
		{ "mul",     "r1:r0 = A * B"},
		{ "rjmp",    "goto A"},
		{ "ijmp",    "goto z"},
		{ "jmp",     "goto A"},
		{ "rcall",   "goto A"},
		{ "icall",   "goto z"},
		{ "call",    "goto A"},
		{ "ret",     "return"},
		{ "iret",    "return_interrupt()"},
		{ "cp",      "var = A - B"},
		{ "cpc",     "var = A - B - carry"},
		{ "cpi",     "var = A - B"},
		{ "breq",    "if(!var) goto A"},
		{ "brne",    "if(var) goto A"},
		{ "brsh",    "if(var >= 0) goto A"},
		{ "brlo",    "if(var < 0) goto A"},
		{ "brmi",    "if(var < 0) goto A"},
		{ "brpl",    "if(var > 0) goto A"},
		{ "brge",    "if(var >= 0) goto A"},
		{ "brlt",    "if(var < 0) goto A"},
		{ "mov",     "A = B"},
		{ "movw",    "A+1:A = B+1:B"},
		{ "ldi",     "A = B"},
		{ "lds",     "A = *(B)"},
		{ "ld",      "A = *(B)"},
		{ "ldd",     "A = *(B)"},
		{ "lpm",     "r0 = z"},
		{ "in",      "A = B"},
		{ "out",     "A = B"},
		{ "push",    "push(A)"},
		{ "pop",     "A = pop()"},
		{ "lsl",     "A <<= 1"},
		{ "lsr",     "A >>= 1"},
		{ "rol",     "A = (A << 1) | (A >> 7)"},
		{ "ror",     "A = (A << 7) | (A >> 1)"},
		{ "asr",     "A >>= 1"},
		{ "swap",    "A = ((A & 0xf0) >> 4) | ((A & 0x0f) << 4)"},
		{ "sec",     "c = 1"},
		{ "clc",     "c = 0"},
		{ "sen",     "n = 1"},
		{ "cln",     "n = 0"},
		{ "sez",     "z = 1"},
		{ "clz",     "z = 0"},
		{ "sei",     "i = 1"},
		{ "cli",     "i = 0"},
		{ "ses",     "s = 1"},
		{ "cls",     "s = 0"},
		{ "sev",     "v = 1"},
		{ "clv",     "v = 0"},
		{ "set",     "t = 1"},
		{ "clt",     "t = 0"},
		{ "seh",     "h = 1"},
		{ "clh",     "h = 0"},
		{ "nop",     ""},
		{ "halt",    "_halt()"},
		{ "wdr",     "_watchdog_reset()"},
		{ "std",     "*(A) = B"},
		{ "st",      "*(A) = B"},
		{ "sts",     "*(A) = B"},
		{ NULL }
	};

	for (i = 0; ops[i].op != NULL; i++) {
		if (!strcmp (ops[i].op, argv[0])) {
			if (newstr != NULL) {
				for (j = k = 0; ops[i].str[j] != '\0'; j++, k++) {
					if (ops[i].str[j] >= 'A' && ops[i].str[j] <= 'J') {
						const char *w = argv[ops[i].str[j] - '@'];
						if (w != NULL) {
							strcpy (newstr + k, w);
							k += strlen(w) - 1;
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
	if (newstr != NULL) {
		newstr[0] = '\0';
		for (i = 0; i < argc; i++) {
			strcat (newstr, argv[i]);
			strcat (newstr, (i == 0 || i == argc - 1) ? " ":", ");
		}
	}

	return false;
}

#define WSZ 128
static int parse(RParse *p, const char *data, char *str) {
	int i, len = strlen (data);
	char w0[WSZ];
	char w1[WSZ];
	char w2[WSZ];
	char w3[WSZ];
	char w4[WSZ];
	char *buf, *ptr, *optr;

	// malloc can be slow here :?
	if (!(buf = malloc (len + 1))) {
		return false;
	}
	memcpy (buf, data, len + 1);

	r_str_trim (buf);
	if (*buf) {
		w0[0] = '\0';
		w1[0] = '\0';
		w2[0] = '\0';
		w3[0] = '\0';
		w4[0] = '\0';
		ptr = strchr (buf, ' ');
		if (!ptr) {
			ptr = strchr (buf, '\t');
		}
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr == ' '; ptr++) {
				//nothing to see here
			}
			strncpy (w0, buf, WSZ - 1);
			strncpy (w1, ptr, WSZ - 1);

			optr = ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr == ' '; ptr++) {
					//nothing to see here
				}
				strncpy (w1, optr, WSZ - 1);
				strncpy (w2, ptr, WSZ - 1);
				optr = ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (++ptr; *ptr == ' '; ptr++) {
						//nothing to see here
					}
					strncpy (w2, optr, WSZ - 1);
					strncpy (w3, ptr, WSZ - 1);
					optr = ptr;
					// bonus
					ptr = strchr (ptr, ',');
					if (ptr) {
						*ptr = '\0';
						for (++ptr; *ptr == ' '; ptr++) {
							//nothing to see here
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
			for (i = 0; i < 5; i++) {
				if (wa[i][0] != '\0') {
					nw++;
				}
			}
			(void)replace (nw, wa, str);
		}
	}
	free (buf);
	return true;
}

RParsePlugin r_parse_plugin_avr_pseudo = {
	.name = "avr.pseudo",
	.desc = "AVR pseudo syntax",
	.parse = parse
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_avr_pseudo,
	.version = R2_VERSION
};
#endif

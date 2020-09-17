/* radare - LGPL - Copyright 2020 - pancake */

#include <r_lib.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

// https://www.ti.com/lit/ug/spru732j/spru732j.pdf

static int replace(int argc, const char *argv[], char *newstr) {
	int i, j, k;
	struct {
		int narg;
		char *op;
		char *str;
	} ops[] = {
		{3, "add", "3 = 1 + 2"},    // add b12, b1, b9 -> b9 = b12 + b1
		{2, "addk", "2 += 1"},      // addk 123, b0 -> b0 += 123
		{3, "sadd", "3 = 1 + 2"},   // sadd b12, b1, b9 -> b9 = b12 + b1
		{3, "sadd2", "3 = 1 + 2"},  // sadd2 b12, b1, b9 -> b9 = b12 + b1
		{3, "sub", "3 = 1 - 2"},    // sub b12, b1, b9 -> b9 = b12 - b1
		{3, "subab", "3 = 1 - 2"},  // sub b12, b1, b9 -> b9 = b12 - b1
		{3, "ssub", "3 = 1 - 2"},   // ssub b12, b1, b9 -> b9 = b12 - b1
		{2, "mvk", "2 = 1"},        // mvk 1, a0 -> a0 = 1
		{2, "mvklh", "2 = (half) 1"},// mvk 1, a0 -> a0 = 1
		{3, "band", "3 = 1 & 2"},   //
		{4, "andn", "4 = 1 ~ 2 .. 3"}, //
		{3, "smpylh", "3 = 1 * 2"}, //
		{3, "smpyh", "3 = 1 * 2"}, //
		{3, "mpyu4", "3 = 1 * 2"}, //
		{3, "mpyh", "3 = 1 * 2"}, //
		{3, "mpyhl", "3 = 1 * 2"}, //
		{3, "mpyhlu", "3 = 1 * 2"}, //
		{3, "mpyhslu", "3 = 1 * 2"}, //
		{3, "mpyhi", "3 = 1 * 2"}, //
		{3, "mpyhu", "3 = 1 * 2"}, //
		{3, "mpyhus", "3 = 1 * 2"}, //
		{3, "mpyhul", "3 = 1 * 2"}, //
		{3, "mpyhuls", "3 = 1 * 2"}, //
		{3, "mpyhir", "3 = 1 * 2"}, //
		{3, "mpyli", "3 = 1 * 2"}, //
		{3, "mpylir", "3 = 1 * 2"}, //
		{4, "ext", "4 = 2 ext 1 .. 3"},  //
		{4, "extu", "4 = 2 ext 1 .. 3"},  //
		{0, "reti", "ret"},         // reti -> ret
		{2, "lddw", "2 = (word)1"}, // lddw
		{2, "ldhu", "2 = (half)1"}, // ldhu
		{2, "ldb", "2 = (byte)1"},  // ldb
		{2, "ldbu", "2 = (byte)1"}, // ldbu
		{2, "ldw", "2 = (word)1"},  // ldw
		{2, "ldh", "2 = (half)1"},  // ldw
		{2, "stb", "2 = (byte)1"},  // stb
		{2, "stw", "2 = (word)1"},  // stw
		{2, "sth", "2 = (half)1"},  // stw
		{2, "stdw", "2 = (half)1"}, // stw
		{3, "shl", "3 = (2 & 0xffffff) << 1"},
		{3, "shr", "3 = (2 & 0xffffff) << 1"},
		{4, "set", "4 = 2 .bitset 1 .. 2"}, // set a29,0x1a, 1, a19
		{4, "clr", "4 = 2 .bitclear 1 .. 2"}, // clr a29,0x1a, 1, a19
		{0, "invalid", "?"},
		{0, NULL}
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
			for (j = k = 0; ops[i].str[j]; j++, k++) {
				if (IS_DIGIT (ops[i].str[j])) {
					int index = ops[i].str[j] - '0';
					if (index >= 0 && index < argc) {
						const char *w = argv[index];
						if (!R_STR_ISEMPTY (w)) {
							r_str_cpy (newstr + k, w);
							k += strlen (w) - 1;
						}
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

static int parse(RParse *p, const char *data, char *str) {
	if (!strncmp (data, "|| ", 2)) {
		data += 3;
	}
	char w0[256], w1[256], w2[256], w3[256];
	size_t i, len = strlen (data);
	char *buf, *ptr, *optr;

	if (R_STR_ISEMPTY (data)) {
		*str = 0;
		return false;
	}

	if (len >= sizeof (w0)) {
		return false;
	}
	// malloc can be slow here :?
	if (!(buf = malloc (len + 1))) {
		return false;
	}
	memcpy (buf, data, len + 1);

	r_str_replace_char (buf, '(', ' ');
	r_str_replace_char (buf, ')', ' ');
	*w0 = *w1 = *w2 = *w3 = '\0';
	ptr = strchr (buf, ' ');
	if (!ptr) {
		ptr = strchr (buf, '\t');
	}
	if (ptr) {
		*ptr++ = '\0';
		ptr = (char*)r_str_trim_head_ro (ptr);
		r_str_ncpy (w0, buf, sizeof (w0));
		r_str_ncpy (w1, ptr, sizeof (w1) - 1);
		optr = ptr;
		ptr = strchr (ptr, ',');
		if (ptr) {
			*ptr++ = '\0';
			ptr = (char*)r_str_trim_head_ro (ptr);
			r_str_ncpy (w1, optr, sizeof (w1));
			char *ptr2 = strchr (ptr, ',');
			if (ptr2) {
				*ptr2 = '\0';
				ptr2 = (char*)r_str_trim_head_ro (ptr2);
				r_str_ncpy (w3, ptr2 + 1, sizeof (w3));
			}
			r_str_ncpy (w2, ptr, sizeof (w2));
		}
	} else {
		r_str_ncpy (w0, buf, sizeof (w0));
	}

	const char *wa[] = {w0, w1, w2, w3};
	int nw = 0;
	for (i = 0; i < 4; i++) {
		if (wa[i][0]) {
			nw++;
		}
	}
	replace (nw, wa, str);

	free (buf);

	return true;
}

RParsePlugin r_parse_plugin_tms320_pseudo = {
	.name = "tms320.pseudo",
	.desc = "tms320 pseudo syntax",
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_tms320_pseudo,
	.version = R2_VERSION};
#endif

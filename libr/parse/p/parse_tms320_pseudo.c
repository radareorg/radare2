/* radare - LGPL - Copyright 2020 - pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

static int replace(int argc, const char *argv[], char *newstr) {
	int i, j, k;
	struct {
		int narg;
		char *op;
		char *str;
	} ops[] = {
		{2, "mov", "1 = 2"},
		{3, "band", "1 = 2 & 3"},
		{0, "reti", "ret"},
		{2, "invalid", "?"},
		{0, NULL}};
	if (!newstr) {
		return false;
	}

	for (i = 0; ops[i].op; i++) {
		if (ops[i].narg) {
			if (argc - 1 != ops[i].narg) {
				continue;
			}
		}
		if (!strcmp(ops[i].op, argv[0])) {
			for (j = k = 0; ops[i].str[j]; j++, k++) {
				if (IS_DIGIT (ops[i].str[j])) {
					const char *w = argv[ops[i].str[j] - '0'];
					if (w) {
						strcpy (newstr + k, w);
						k += strlen (w) - 1;
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
	int i, len = strlen (data);
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
		ptr = r_str_trim_head_ro (ptr);
		r_str_ncpy (w0, buf, sizeof (w0) - 1);
		r_str_ncpy (w1, ptr, sizeof (w1) - 1);
		optr = ptr;
		ptr = strchr (ptr, ',');
		if (ptr) {
			*ptr++ = '\0';
			ptr = r_str_trim_head_ro (ptr);
			strncpy (w1, optr, sizeof (w1) - 1);
			char *ptr2 = strchr (ptr, ',');
			if (ptr2) {
				*ptr2 = 0;
				ptr2 = r_str_trim_head_ro (ptr2);
				r_str_ncpy (w3, ptr2 + 1, sizeof (w3) - 1);
			}
			r_str_ncpy (w2, ptr, sizeof (w2) - 1);
		}
	} else {
		r_str_ncpy (w0, buf, sizeof (w0) - 1);
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

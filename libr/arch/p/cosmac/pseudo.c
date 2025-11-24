/* radare - LGPL - Copyright 2024 - pancake */

#include <r_asm.h>

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
		{ 0, "ret", "return", { 0 } },
		{ 1, "bnz", "if (!zero) goto #", { 1 } },
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

static char *parse(RAsmPluginSession *aps, const char *data) {
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
	const char *op0 = buf;
	if (!strcmp (op0, "ret") || !strcmp (op0, "sret")) {
		free (buf);
		return strdup ("return r0");
	}
	char *str = malloc (strlen (data) + 128);
	strcpy (str, data);
	if (*buf) {
		*w0 = *w1 = *w2 = *w3 = *w4 = '\0';
		ptr = strchr (buf, ' ');
		if (ptr) {
			*ptr = '\0';
			ptr = (char *)r_str_trim_head_ro (ptr + 1);
			strncpy (w0, buf, sizeof (w0) - 1);
			strncpy (w1, ptr, sizeof (w1) - 1);
			optr = ptr;
			if (ptr && *ptr == '[') {
				ptr = strchr (ptr + 1, ']');
			}
			if (!ptr) {
				R_LOG_ERROR ("Unbalanced bracket");
				free (str);
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
	free (buf);
	return r_str_fixspaces (str);
}

RAsmPlugin r_asm_plugin_cosmac = {
	.meta = {
		.name = "cosmac",
		.desc = "pseudocode for cosmac cdp 1802",
		.author = "pancake",
		.license = "MIT",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_cosmac,
	.version = R2_VERSION
};
#endif

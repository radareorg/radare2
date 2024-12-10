/* radare - LGPL - Copyright 2015-2024 - pancake, qnix */

#include <r_lib.h>
#include <r_asm.h>

typedef enum {
	IND_IDX = 0,
	IDX_IND = 1,
	NORM = 2,
} ADDR_TYPE;

static char *replace(int argc, const char *argv[], ADDR_TYPE type) {
	int i, j;
	struct {
		int narg;
		const char *op;
		const char *str;
	} ops[] = {
		{1, "lda", "a = 1" },
		{2, "lda", "a = (1+2)" },
		{1, "ldx", "x = 1" },
		{2, "ldx", "x = (1+2)" },
		{1, "ldy", "y = 1" },
		{2, "ldy", "y = (1+2)" },
		{1, "sta", "[1] = a" },
		{2, "sta", "[1+2 ] = a" },
		{1, "stx", "[1] = x" },
		{2, "stx", "[1+2] = x" },
		{1, "sty", "[1] = y" },
		{2, "sty", "[1+2] = y" },
		{1, "dec", "1--" },
		{2, "dec", "(1+2)--" },
		{0, "dcx", "x--" },
		{0, "dcy", "y--" },
		{1, "inc", "1++" },
		{2, "inc", "(1+2)++" },
		{0, "inx", "x++" },
		{0, "iny", "y++" },
		{1, "adc", "a += 1" },
		{2, "adc", "a += (1+2)" },
		{1, "sbc", "a -= 1" },
		{2, "sbc", "a -= (1+2)" },
		{0, "pha", "push a" },
		{1, "and", "a &= 1" },
		{2, "and", "a &= (1+2)" },
		{1, "eor", "a ^= 1" },
		{2, "eor", "a ^= (1+2)" },
		{1, "ora", "a |= 1" },
		{2, "ora", "a |= (1+2)" },
		{0, "tax", "x = a" },
		{0, "tay", "y = a" },
		{0, "txa", "a = x" },
		{0, "tya", "a = y" },
		{0, "tsx", "x = s" },
		{0, "txs", "s = x" },
		{0, "brk", "break" },
		{0, "clc", "clear_carry" },
		{0, "cld", "clear_decimal" },
		{0, "cli", "clear_interrupt" },
		{0, "clv", "clear_overflow" },
		{0, "sec", "set_carry" },
		{0, "sed", "set_decimal" },
		{0, "sei", "set_interrupt" },
		{1, "jsr", "1()" },
		{0, NULL}};

	RStrBuf *sb = r_strbuf_new ("");
	for (i = 0; ops[i].op; i++) {
		if (ops[i].narg) {
			if (argc - 1 != ops[i].narg) {
				continue;
			}
		}
		if (!strcmp (ops[i].op, argv[0])) {
			for (j = 0; ops[i].str[j] != '\0'; j++) {
				if (isdigit(ops[i].str[j])) {
					const char *w = argv[ops[i].str[j] - '0'];
					if (w) {
						r_strbuf_append (sb, w);
					}
				} else {
					const char ch = ops[i].str[j];
					r_strbuf_append_n (sb, &ch, 1);
				}
			}
			if (argc == 4 && argv[2][0] == '[') {
				r_strbuf_append (sb, "+");
				r_strbuf_append (sb, argv[2]); // wtf+3?
				// strcat (newstr + k, "+");
				// strcat (newstr + k + 3, argv[2]);
			}
			return r_strbuf_drain (sb);
		}
	}

	for (i = 0; i < argc; i++) {
		r_strbuf_append (sb, argv[i]);
		r_strbuf_append (sb, (i == 0 || i == argc - 1) ? " " : ",");
	}
	return r_strbuf_drain (sb);
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

static char *parse(RAsmPluginSession *s, const char *data) {
	char w0[256], w1[256], w2[256];
	int i, len = strlen (data);
	char *ptr, *optr;
	ADDR_TYPE atype;
	char *str = NULL;

	if (len >= sizeof (w0)) {
		return NULL;
	}
	// malloc can be slow here :?
	char *buf = malloc (len + 1);
	if (!buf) {
		return NULL;
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
			for (ptr++; *ptr == ' '; ptr++) {
				;
			}
			strncpy (w0, buf, sizeof (w0) - 1);
			strncpy (w1, ptr, sizeof (w1) - 1);
			optr = ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (ptr++; *ptr == ' '; ptr++) {
					;
				}
				strncpy (w1, optr, sizeof (w1) - 1);
				strncpy (w2, ptr, sizeof (w2) - 1);
			}
		} else {
			strncpy (w0, buf, sizeof (w0) - 1);
		}

		const char *wa[] = {w0, w1, w2};
		int nw = 0;
		for (i = 0; i < 3; i++) {
			if (wa[i][0]) {
				nw++;
			}
		}
		str = replace (nw, wa, atype);
	}

	free (buf);

	return str;
}

RAsmPlugin r_asm_plugin_6502 = {
	.meta = {
		.name = "6502",
		.desc = "6502 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_6502,
	.version = R2_VERSION};
#endif

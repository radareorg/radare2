/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_util.h>

enum {
	BOLD,
	ITALIC,
	SCRIPT,
	DOUBLESTRUCK,
	UNDERLINE,
	STRIKE,
	FRAKTUR,
	BOLDITALIC,
	SANSSERIF,
	SANSSERIFITALIC,
	MONOSPACE,
	BOLDSCRIPT,
	BOLDFRAKTUR,
	SANSSERIBBOLD,
	SANSSERIFBOLDITALIC,
	OPENFACE,
	SMALLCAPS
};

static const char *styles[] = {
	"bold", "italic", "script", "doublestruck", "underline", "strikethrough", "fraktur", "bolditalic", "sansserif", "sansserifitalic", "monospace", "boldscript", "boldfraktur", "sansseribbold", "sansserifbolditalic", "openface", "smallcaps"
};

static int style_id(const char *s, size_t n) {
	int i;
	for (i = 0; i < (int) (sizeof (styles) / sizeof (*styles)); i++) {
		if (strlen (styles[i]) == n && !memcmp (styles[i], s, n)) {
			return i;
		}
	}
	if (n == 13 && !memcmp (s, "sansserifbold", n)) {
		return SANSSERIBBOLD;
	}
	return -1;
}

static int eqci(const char *a, const char *b, size_t n) {
	while (n--) {
		if (tolower ((unsigned char)*a++) != tolower ((unsigned char)*b++)) {
			return 0;
		}
	}
	return 1;
}

static bool putu(RStrBuf *sb, unsigned cp) {
	char buf[4];
	int len;
	if (cp < 0x80) {
		buf[0] = cp;
		len = 1;
	} else if (cp < 0x800) {
		buf[0] = 0xC0 | (cp >> 6);
		buf[1] = 0x80 | (cp & 0x3F);
		len = 2;
	} else if (cp < 0x10000) {
		buf[0] = 0xE0 | (cp >> 12);
		buf[1] = 0x80 | ((cp >> 6) & 0x3F);
		buf[2] = 0x80 | (cp & 0x3F);
		len = 3;
	} else {
		buf[0] = 0xF0 | (cp >> 18);
		buf[1] = 0x80 | ((cp >> 12) & 0x3F);
		buf[2] = 0x80 | ((cp >> 6) & 0x3F);
		buf[3] = 0x80 | (cp & 0x3F);
		len = 4;
	}
	return r_strbuf_append_n (sb, buf, len);
}

static unsigned ex(unsigned base, int i, const int *idx, const unsigned *val, int n) {
	int j;
	for (j = 0; j < n; j++) {
		if (idx[j] == i) {
			return val[j];
		}
	}
	return base + i;
}

static unsigned mapcp(char c, int st, unsigned *comb) {
	int i;
	*comb = 0;
	if (st == UNDERLINE || st == STRIKE) {
		if (isalnum ((unsigned char)c)) {
			*comb = st == UNDERLINE? 0x332: 0x335;
		}
		return (unsigned char)c;
	}
	if (c >= 'A' && c <= 'Z') {
		static const int se[] = { 1, 4, 5, 7, 8, 11, 12, 17 }, de[] = { 2, 7, 13, 15, 16, 17, 25 };
		static const int fe[] = { 2, 7, 8, 17, 25 };
		static const unsigned sv[] = { 0x212C, 0x2130, 0x2131, 0x210B, 0x2110, 0x2112, 0x2133, 0x211B };
		static const unsigned dv[] = { 0x2102, 0x210D, 0x2115, 0x2119, 0x211A, 0x211D, 0x2124 };
		static const unsigned fv[] = { 0x212D, 0x210C, 0x2111, 0x211C, 0x2128 };
		i = c - 'A';
		switch (st) {
		case BOLD: return 0x1D400 + i;
		case ITALIC: return 0x1D434 + i;
		case BOLDITALIC: return 0x1D468 + i;
		case SCRIPT: return ex (0x1D49C, i, se, sv, 8);
		case DOUBLESTRUCK:
		case OPENFACE: return ex (0x1D538, i, de, dv, 7);
		case FRAKTUR: return ex (0x1D504, i, fe, fv, 5);
		case SANSSERIF: return 0x1D5A0 + i;
		case SANSSERIBBOLD: return 0x1D5D4 + i;
		case SANSSERIFITALIC: return 0x1D608 + i;
		case MONOSPACE: return 0x1D670 + i;
		case BOLDSCRIPT: return 0x1D4D0 + i;
		case BOLDFRAKTUR: return 0x1D56C + i;
		case SANSSERIFBOLDITALIC: return 0x1D63C + i;
		case SMALLCAPS: return c;
		}
	}
	if (c >= 'a' && c <= 'z') {
		static const int il[] = { 7 };
		static const int sl[] = { 4, 6, 14 };
		static const unsigned iv[] = { 0x210E };
		static const unsigned sv[] = { 0x212F, 0x210A, 0x2134 };
		static const unsigned sc[] = {
			0x1D00, 0x299, 0x1D04, 0x1D05, 0x1D07, 0x493, 0x262, 0x29C, 0x26A, 0x1D0A, 0x1D0B, 0x29F, 0x1D0D, 0x274, 0x1D0F, 0x1D18, 0x1EB, 0x280, 0x73, 0x1D1B, 0x1D1C, 0x1D20, 0x1D21, 0x78, 0x28F, 0x1D22
		};
		i = c - 'a';
		switch (st) {
		case BOLD: return 0x1D41A + i;
		case ITALIC: return ex (0x1D44E, i, il, iv, 1);
		case BOLDITALIC: return 0x1D482 + i;
		case SCRIPT: return ex (0x1D4B6, i, sl, sv, 3);
		case DOUBLESTRUCK:
		case OPENFACE: return 0x1D552 + i;
		case FRAKTUR: return 0x1D51E + i;
		case SANSSERIF: return 0x1D5BA + i;
		case SANSSERIBBOLD: return 0x1D5EE + i;
		case SANSSERIFITALIC: return 0x1D622 + i;
		case MONOSPACE: return 0x1D68A + i;
		case BOLDSCRIPT: return 0x1D4EA + i;
		case BOLDFRAKTUR: return 0x1D586 + i;
		case SANSSERIFBOLDITALIC: return 0x1D656 + i;
		case SMALLCAPS: return sc[i];
		}
	}
	if (c >= '0' && c <= '9') {
		i = c - '0';
		switch (st) {
		case BOLD: return 0x1D7CE + i;
		case DOUBLESTRUCK: return 0x1D7D8 + i;
		case SANSSERIF: return 0x1D7E2 + i;
		case SANSSERIBBOLD: return 0x1D7EC + i;
		case MONOSPACE: return 0x1D7F6 + i;
		}
	}
	return (unsigned char)c;
}

static bool convert(const char *s, size_t n, int st, RStrBuf *sb) {
	while (n--) {
		unsigned comb, cp = mapcp (*s++, st, &comb);
		if (!putu (sb, cp)) {
			return false;
		}
		if (comb && !putu (sb, comb)) {
			return false;
		}
	}
	return true;
}

static const char *closing(const char *s, const char *tag, size_t n) {
	for (; *s; s++) {
		if (s[0] == '<' && s[1] == '/' && eqci (s + 2, tag, n) && s[n + 2] == '>') {
			return s;
		}
	}
	return NULL;
}

R_API char *r_str_font(const char *s) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	RStrBuf *sb = r_strbuf_new (NULL);
	while (*s) {
		if (*s == '<' && isalpha ((unsigned char)s[1])) {
			const char *q = s + 1;
			while (isalpha ((unsigned char)*q)) {
				q++;
			}
			if (*q == '>') {
				const char *body = q + 1;
				const char *end = closing (body, s + 1, (size_t) (q - s - 1));
				if (end) {
					int st = style_id (s + 1, (size_t) (q - s - 1));
					if (st < 0) {
						if (!r_strbuf_append_n (sb, body, (size_t) (end - body))) {
							goto err;
						}
					} else if (!convert (body, (size_t) (end - body), st, sb)) {
						goto err;
					}
					s = end + (q - s - 1) + 3;
					continue;
				}
			}
		}
		if (!r_strbuf_append_n (sb, s, 1)) {
			goto err;
		}
		s++;
	}
	return r_strbuf_drain (sb);
err:
	r_strbuf_free (sb);
	return NULL;
}

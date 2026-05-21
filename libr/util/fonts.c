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
	SANSSERIFBOLD,
	SANSSERIFBOLDITALIC,
	OPENFACE,
	SMALLCAPS
};

static const char *styles[] = {
	"bold", "italic", "script", "doublestruck", "underline", "strikethrough", "fraktur", "bolditalic", "sansserif", "sansserifitalic", "monospace", "boldscript", "boldfraktur", "sansserifbold", "sansserifbolditalic", "openface", "smallcaps"
};

R_API const char *r_font_name(int i) {
	if (i >= 0 && i < (int)R_ARRAY_SIZE (styles)) {
		return styles[i];
	}
	return NULL;
}
static int style_id(const char *s, size_t n) {
	int i;
	for (i = 0; i < (int)R_ARRAY_SIZE (styles); i++) {
		if (strlen (styles[i]) == n && !memcmp (styles[i], s, n)) {
			return i;
		}
	}
	if (n == 13 && !memcmp (s, "sansseribbold", n)) {
		return SANSSERIFBOLD;
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
	ut8 buf[4];
	const int len = r_utf8_encode (buf, cp);
	return len > 0 && r_strbuf_append_n (sb, (const char *)buf, len);
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

static const char *ansi_end(const char *s, const char *end) {
	if ((unsigned char)*s != 0x1b) {
		return NULL;
	}
	const char *p = s + 1;
	if (end && p >= end) {
		return end;
	}
	if (*p == '[') {
		p++;
		while ((!end || p < end) && *p) {
			unsigned char ch = (unsigned char)*p++;
			if (ch >= 0x40 && ch <= 0x7e) {
				return p;
			}
		}
		return p;
	}
	if ((!end || p < end) && *p) {
		p++;
	}
	return p;
}

static size_t utf8_len(const char *s, const char *end) {
	const unsigned char c = (unsigned char)*s;
	size_t len = 1;
	if (c >= 0xf0) {
		len = 4;
	} else if (c >= 0xe0) {
		len = 3;
	} else if (c >= 0xc0) {
		len = 2;
	}
	size_t left = end? (size_t)(end - s): strlen (s);
	return R_MIN (len, left);
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
		case SANSSERIFBOLD: return 0x1D5D4 + i;
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
		case SANSSERIFBOLD: return 0x1D5EE + i;
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
		case SANSSERIFBOLD: return 0x1D7EC + i;
		case MONOSPACE: return 0x1D7F6 + i;
		}
	}
	return (unsigned char)c;
}

static bool convert(const char *s, size_t n, int st, RStrBuf *sb) {
	const char *end = s + n;
	while (s < end) {
		const char *ansi = ansi_end (s, end);
		if (ansi) {
			if (!r_strbuf_append_n (sb, s, ansi - s)) {
				return false;
			}
			s = ansi;
			continue;
		}
		if ((unsigned char)*s >= 0x80) {
			size_t len = utf8_len (s, end);
			if (!r_strbuf_append_n (sb, s, len)) {
				return false;
			}
			s += len;
			continue;
		}
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

static bool append_text(RStrBuf *sb, const char *s, size_t n, int st) {
	return st < 0
		? r_strbuf_append_n (sb, s, n)
		: convert (s, n, st, sb);
}

static size_t tag_size(const char *s) {
	const char *p = s;
	if (*p++ != '<') {
		return 0;
	}
	if (*p == '/') {
		p++;
	}
	if (!isalpha ((unsigned char)*p)) {
		return 0;
	}
	while (isalpha ((unsigned char)*p)) {
		p++;
	}
	return *p == '>'? (size_t)(p - s + 1): 0;
}

static bool append_text_skipping_tags(RStrBuf *sb, const char *s, int st) {
	while (*s) {
		size_t n = tag_size (s);
		if (n) {
			s += n;
			continue;
		}
		const char *p = s + 1;
		while (*p && !tag_size (p)) {
			p++;
		}
		if (!append_text (sb, s, (size_t)(p - s), st)) {
			return false;
		}
		s = p;
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

R_API char *r_font_render(const char *s, const char *family) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	RStrBuf *sb = r_strbuf_new (NULL);
	int fst = family? style_id (family, strlen (family)): -1;
	if (family) {
		if (!append_text_skipping_tags (sb, s, fst)) {
			goto err;
		}
		return r_strbuf_drain (sb);
	}
	while (*s) {
		const char *ansi = ansi_end (s, NULL);
		if (ansi) {
			if (!r_strbuf_append_n (sb, s, ansi - s)) {
				goto err;
			}
			s = ansi;
			continue;
		}
		if ((unsigned char)*s >= 0x80) {
			size_t len = utf8_len (s, NULL);
			if (!r_strbuf_append_n (sb, s, len)) {
				goto err;
			}
			s += len;
			continue;
		}
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
						if (!append_text (sb, body, (size_t) (end - body), fst)) {
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
		if (!append_text (sb, s, 1, fst)) {
			goto err;
		}
		s++;
	}
	return r_strbuf_drain (sb);
err:
	r_strbuf_free (sb);
	return NULL;
}

R_API char *r_str_font(const char *s, const char *family) {
	return r_font_render (s, family);
}

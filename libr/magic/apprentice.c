/* $radare2: apprentice.c 2026/03/24 pancake Exp $ */
/* $OpenBSD: apprentice.c,v 1.29 2009/11/11 16:21:51 jsg Exp $ */
/* Copyright (c) Ian F. Darwin 1986-1995. */
/*
 * Software written by Ian F. Darwin and others;
 * maintained 1995-present by Christos Zoulas and others.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <r_userconf.h>

#if !USE_LIB_MAGIC

#include <r_util.h>
#include "file.h"
#include "patchlevel.h"

struct r_magic_entry {
	struct r_magic *mp;
	ut32 cont_count;
	ut32 max_count;
};

static const char usg_hdr[] = "cont\toffset\ttype\topcode\tmask\tvalue\tdesc";
static const char mime_marker[] = "!:mime";
static const size_t mime_marker_len = sizeof(mime_marker) - 1;

static size_t magic_cap_bytes(size_t bytes) {
	return R_MIN (bytes, (size_t)HOWMANY);
}

static inline const char *eatab(const char *l) {
	while (isascii ((ut8)*l) && isspace ((ut8)*l)) {
		l++;
	}
	return l;
}

static size_t magic_cap_sum(size_t base, size_t extra) {
	if (base >= (size_t)HOWMANY || extra >= (size_t)HOWMANY) {
		return HOWMANY;
	}
	return magic_cap_bytes (base + extra);
}

static size_t magic_min_bytes(const struct r_magic *m) {
	size_t need = file_magic_type_bytes (m, m->type);
	size_t offset = m->offset;

	if (m->flag & INDIR) {
		size_t indir_need = file_magic_type_bytes (m, m->in_type);
		need = R_MAX (need, indir_need);
		if ((m->in_op & FILE_OPINDIRECT) && m->in_offset > 0) {
			need = R_MAX (need, (size_t)m->in_offset + indir_need);
		}
	}
	return magic_cap_sum (offset, need);
}

static size_t magic_max_bytes(const struct r_magic *m) {
	size_t need;

	if (m->flag & (INDIR | OFFADD | INDIROFFADD)) {
		return HOWMANY;
	}
	switch (m->type) {
	case FILE_SEARCH:
		if (m->str_range == 0) {
			return HOWMANY;
		}
		need = m->vallen;
		if (need > 0) {
			need += (size_t)m->str_range - 1;
		}
		break;
	case FILE_REGEX:
		return HOWMANY;
	default:
		need = file_magic_type_bytes (m, m->type);
		break;
	}
	return magic_cap_sum (m->offset, need);
}

static bool magic_prepare_requirements(RMagic *ms, struct r_magic *magic, ut32 nmagic, size_t *bytes_max, ut32 **min_bytes) {
	ut32 i;
	size_t max_bytes = 0;
	ut32 *req;

	if (nmagic == 0) {
		*bytes_max = 0;
		*min_bytes = NULL;
		return true;
	}
	req = calloc (nmagic, sizeof (*req));
	if (!req) {
		__magic_file_oomem (ms, sizeof (*req) * nmagic);
		return false;
	}
	for (i = 0; i < nmagic; i++) {
		const size_t min_need = magic_min_bytes (&magic[i]);
		const size_t max_need = magic_max_bytes (&magic[i]);
		req[i] = (ut32)magic_cap_bytes (min_need);
		max_bytes = R_MAX (max_bytes, max_need);
	}
	*bytes_max = max_bytes;
	*min_bytes = req;
	return true;
}

static const struct type_tbl_s {
	const char name[16];
	const size_t len;
	const int type;
	const int format;
} type_tbl[] = {
#define TBLROW(s, t, f) { s, (sizeof (s) - 1), FILE_ ## t, FILE_FMT_ ## f }
	TBLROW ("byte", BYTE, NUM),
	TBLROW ("short", SHORT, NUM),
	TBLROW ("default", DEFAULT, STR),
	TBLROW ("long", LONG, NUM),
	TBLROW ("string", STRING, STR),
	TBLROW ("date", DATE, STR),
	TBLROW ("beshort", BESHORT, NUM),
	TBLROW ("belong", BELONG, NUM),
	TBLROW ("bedate", BEDATE, STR),
	TBLROW ("leshort", LESHORT, NUM),
	TBLROW ("lelong", LELONG, NUM),
	TBLROW ("ledate", LEDATE, STR),
	TBLROW ("pstring", PSTRING, STR),
	TBLROW ("ldate", LDATE, STR),
	TBLROW ("beldate", BELDATE, STR),
	TBLROW ("leldate", LELDATE, STR),
	TBLROW ("regex", REGEX, STR),
	TBLROW ("bestring16", BESTRING16, STR),
	TBLROW ("lestring16", LESTRING16, STR),
	TBLROW ("search", SEARCH, STR),
	TBLROW ("medate", MEDATE, STR),
	TBLROW ("meldate", MELDATE, STR),
	TBLROW ("melong", MELONG, NUM),
	TBLROW ("quad", QUAD, QUAD),
	TBLROW ("lequad", LEQUAD, QUAD),
	TBLROW ("bequad", BEQUAD, QUAD),
	TBLROW ("qdate", QDATE, STR),
	TBLROW ("leqdate", LEQDATE, STR),
	TBLROW ("beqdate", BEQDATE, STR),
	TBLROW ("qldate", QLDATE, STR),
	TBLROW ("leqldate", LEQLDATE, STR),
	TBLROW ("beqldate", BEQLDATE, STR),
	TBLROW ("float", FLOAT, FLOAT),
	TBLROW ("befloat", BEFLOAT, FLOAT),
	TBLROW ("lefloat", LEFLOAT, FLOAT),
	TBLROW ("double", DOUBLE, DOUBLE),
	TBLROW ("bedouble", BEDOUBLE, DOUBLE),
	TBLROW ("ledouble", LEDOUBLE, DOUBLE),
	{ { 0 }, 0, 0, 0 },
#undef XX
};

static int get_type(const char *l, const char **t) {
	const struct type_tbl_s *p;

	for (p = type_tbl; p->len; p++) {
		if (strncmp (l, p->name, p->len) == 0) {
			if (t) {
				*t = l + p->len;
			}
			break;
		}
	}
	return p->type;
}

void init_file_tables(RMagic *m) {
	const struct type_tbl_s *p;
	for (p = type_tbl; p->len; p++) {
		if (p->type >= FILE_NAMES_SIZE) {
			continue;
		}
		m->magic_file_names[p->type] = p->name;
		m->magic_file_formats[p->type] = p->format;
	}
}

void __magic_file_delmagic(struct r_magic *p, int type) {
	if (p) {
		switch (type) {
		case 1:
			p--;
			/*FALLTHROUGH*/
		case 0:
			R_FREE (p);
			break;
		default:
			abort (); // do not abort, ever XXX this is a lib, so it shouldn just report an error
		}
	}
}

/*
 * Get weight of this magic entry, for sorting purposes.
 */
static size_t apprentice_r_magic_strength(const struct r_magic *m) {
#define MULT 10
	size_t val = 2 * MULT; /* baseline strength */

	switch (m->type) {
	case FILE_DEFAULT: /* make sure this sorts last */
		return 0;
	case FILE_BYTE:
		val += 1 * MULT;
		break;
	case FILE_SHORT:
	case FILE_LESHORT:
	case FILE_BESHORT:
		val += 2 * MULT;
		break;
	case FILE_LONG:
	case FILE_LELONG:
	case FILE_BELONG:
	case FILE_MELONG:
		val += 4 * MULT;
		break;
	case FILE_PSTRING:
	case FILE_STRING:
		val += m->vallen * MULT;
		break;
	case FILE_BESTRING16:
	case FILE_LESTRING16:
		val += m->vallen * MULT / 2;
		break;
	case FILE_SEARCH:
	case FILE_REGEX:
		val += m->vallen * R_MAX (MULT / m->vallen, 1);
		break;
	case FILE_DATE:
	case FILE_LEDATE:
	case FILE_BEDATE:
	case FILE_MEDATE:
	case FILE_LDATE:
	case FILE_LELDATE:
	case FILE_BELDATE:
	case FILE_MELDATE:
	case FILE_FLOAT:
	case FILE_BEFLOAT:
	case FILE_LEFLOAT:
		val += 4 * MULT;
		break;
	case FILE_QUAD:
	case FILE_BEQUAD:
	case FILE_LEQUAD:
	case FILE_QDATE:
	case FILE_LEQDATE:
	case FILE_BEQDATE:
	case FILE_QLDATE:
	case FILE_LEQLDATE:
	case FILE_BEQLDATE:
	case FILE_DOUBLE:
	case FILE_BEDOUBLE:
	case FILE_LEDOUBLE:
		val += 8 * MULT;
		break;
	default:
		R_LOG_ERROR ("Bad type %d", m->type);
		abort ();
	}

	switch (m->reln) {
	case 'x': /* matches anything penalize */
	case '!': /* matches almost anything penalize */
		val = 0;
		break;
	case '=': /* Exact match, prefer */
		val += MULT;
		break;
	case '>':
	case '<': /* comparison match reduce strength */
		val -= 2 * MULT;
		break;
	case '^':
	case '&': /* masking bits, we could count them too */
		val -= MULT;
		break;
	default:
		R_LOG_ERROR ("Bad relation %c", m->reln);
		abort ();
	}
	return val? val: 1; /* ensure we only return 0 for FILE_DEFAULT */
}

/*
 * Sort callback for sorting entries by "strength" (basically length)
 */
static int apprentice_sort(const void *a, const void *b) {
	const struct r_magic_entry *ma = a;
	const struct r_magic_entry *mb = b;
	size_t sa = apprentice_r_magic_strength (ma->mp);
	size_t sb = apprentice_r_magic_strength (mb->mp);
	if (sa == sb) {
		return 0;
	}
	if (sa > sb) {
		return -1;
	}
	return 1;
}

static void set_test_type(struct r_magic *mstart, struct r_magic *m) {
	switch (m->type) {
	case FILE_BYTE:
	case FILE_SHORT:
	case FILE_LONG:
	case FILE_DATE:
	case FILE_BESHORT:
	case FILE_BELONG:
	case FILE_BEDATE:
	case FILE_LESHORT:
	case FILE_LELONG:
	case FILE_LEDATE:
	case FILE_LDATE:
	case FILE_BELDATE:
	case FILE_LELDATE:
	case FILE_MEDATE:
	case FILE_MELDATE:
	case FILE_MELONG:
	case FILE_QUAD:
	case FILE_LEQUAD:
	case FILE_BEQUAD:
	case FILE_QDATE:
	case FILE_LEQDATE:
	case FILE_BEQDATE:
	case FILE_QLDATE:
	case FILE_LEQLDATE:
	case FILE_BEQLDATE:
	case FILE_FLOAT:
	case FILE_BEFLOAT:
	case FILE_LEFLOAT:
	case FILE_DOUBLE:
	case FILE_BEDOUBLE:
	case FILE_LEDOUBLE:
	case FILE_STRING:
	case FILE_PSTRING:
	case FILE_BESTRING16:
	case FILE_LESTRING16:
		/* binary test, set flag */
		mstart->flag |= BINTEST;
		break;
	case FILE_REGEX:
	case FILE_SEARCH:
		/* binary test if pattern is not text */
		if (__magic_file_looks_utf8 ((const ut8 *)m->value.s, m->vallen, NULL, NULL) == 0) {
			mstart->flag |= BINTEST;
		}
		break;
	case FILE_DEFAULT:
		// Nothing to infer here at top level.
		break;
	case FILE_INVALID:
	default:
		/* invalid search type, but no need to complain here */
		break;
	}
}

static void debug_test_type(RMagic *ms, struct r_magic *m) {
	if ((ms->flags & R_MAGIC_DEBUG) == 0) {
		return;
	}
	(void)m;
}

/*
 * Load and parse from buffer.
 */
static bool bgets(char *line, size_t line_sz, const char **data) {
	const char *p = *data;
	if (R_STR_ISEMPTY (p)) {
		return false;
	}
	const char *nl = strchr (p, '\n');
	size_t adv = nl? (size_t) (nl - p) + 1: strlen (p);
	size_t len = R_MIN (adv, line_sz - 1);
	r_str_ncpy (line, p, len + 1);
	*data = p + adv;
	return true;
}

/*
 * extend the sign bit if the comparison is to be signed
 */
ut64 __magic_file_signextend(RMagic *ms, struct r_magic *m, ut64 v) {
	if (! (m->flag & UNSIGNED)) {
		switch (m->type) {
		// Keep these casts so values are sign-extended before comparison.
		case FILE_BYTE:
			v = (char)v;
			break;
		case FILE_SHORT:
		case FILE_BESHORT:
		case FILE_LESHORT:
			v = (short)v;
			break;
		case FILE_DATE:
		case FILE_BEDATE:
		case FILE_LEDATE:
		case FILE_MEDATE:
		case FILE_LDATE:
		case FILE_BELDATE:
		case FILE_LELDATE:
		case FILE_MELDATE:
		case FILE_LONG:
		case FILE_BELONG:
		case FILE_LELONG:
		case FILE_MELONG:
		case FILE_FLOAT:
		case FILE_BEFLOAT:
		case FILE_LEFLOAT:
			v = (int32_t)v;
			break;
		case FILE_QUAD:
		case FILE_BEQUAD:
		case FILE_LEQUAD:
		case FILE_QDATE:
		case FILE_QLDATE:
		case FILE_BEQDATE:
		case FILE_BEQLDATE:
		case FILE_LEQDATE:
		case FILE_LEQLDATE:
		case FILE_DOUBLE:
		case FILE_BEDOUBLE:
		case FILE_LEDOUBLE:
			v = (int64_t)v;
			break;
		case FILE_STRING:
		case FILE_PSTRING:
		case FILE_BESTRING16:
		case FILE_LESTRING16:
		case FILE_REGEX:
		case FILE_SEARCH:
		case FILE_DEFAULT:
			break;
		default:
			if (ms->flags & R_MAGIC_CHECK) {
				__magic_file_magwarn (ms, "cannot happen: m->type=%d\n", m->type);
			}
			return ~0U;
		}
	}
	return v;
}

static int string_modifier_check(RMagic *ms, struct r_magic *m) {
	if ((ms->flags & R_MAGIC_CHECK) == 0) {
		return 0;
	}

	switch (m->type) {
	case FILE_BESTRING16:
	case FILE_LESTRING16:
		if (m->str_flags != 0) {
			__magic_file_magwarn (ms,
				"no modifiers allowed for 16-bit strings\n");
			return -1;
		}
		break;
	case FILE_STRING:
	case FILE_PSTRING:
		if ((m->str_flags & REGEX_OFFSET_START) != 0) {
			__magic_file_magwarn (ms,
				"'/%c' only allowed on regex and search\n",
				CHAR_REGEX_OFFSET_START);
			return -1;
		}
		break;
	case FILE_SEARCH:
		if (m->str_range == 0) {
			__magic_file_magwarn (ms,
				"missing range; defaulting to %d\n",
				STRING_DEFAULT_RANGE);
			m->str_range = STRING_DEFAULT_RANGE;
			return -1;
		}
		break;
	case FILE_REGEX:
		if ((m->str_flags & STRING_COMPACT_BLANK) != 0) {
			__magic_file_magwarn (ms, "'/%c' not allowed on regex\n", CHAR_COMPACT_BLANK);
			return -1;
		}
		if ((m->str_flags & STRING_COMPACT_OPTIONAL_BLANK) != 0) {
			__magic_file_magwarn (ms, "'/%c' not allowed on regex\n", CHAR_COMPACT_OPTIONAL_BLANK);
			return -1;
		}
		break;
	default:
		__magic_file_magwarn (ms, "coding error: m->type=%d\n", m->type);
		return -1;
	}
	return 0;
}

static int get_op(char c) {
	switch (c) {
	case '&': return FILE_OPAND;
	case '|': return FILE_OPOR;
	case '^': return FILE_OPXOR;
	case '+': return FILE_OPADD;
	case '-': return FILE_OPMINUS;
	case '*': return FILE_OPMULTIPLY;
	case '/': return FILE_OPDIVIDE;
	case '%': return FILE_OPMODULO;
	default: return -1;
	}
}

static const struct cond_tbl_s {
	char name[8];
	size_t len;
	int cond;
} cond_tbl[] = {
	{ "if", 2, COND_IF },
	{ "elif", 4, COND_ELIF },
	{ "else", 4, COND_ELSE },
	{ "", 0, COND_NONE },
};

static int get_cond(const char *l, const char **t) {
	const struct cond_tbl_s *p;

	for (p = cond_tbl; p->len; p++) {
		if (strncmp (l, p->name, p->len) == 0 &&
			isspace ((ut8)l[p->len])) {
			if (t) {
				*t = l + p->len;
			}
			break;
		}
	}
	return p->cond;
}

static int check_cond(RMagic *ms, int cond, ut32 cont_level) {
	int last_cond = ms->c.li[cont_level].last_cond;

	switch (cond) {
	case COND_IF:
		if (last_cond != COND_NONE && last_cond != COND_ELIF) {
			if (ms->flags & R_MAGIC_CHECK) {
				__magic_file_magwarn (ms, "syntax error: `if'");
			}
			return -1;
		}
		last_cond = COND_IF;
		break;
	case COND_ELIF:
		if (last_cond != COND_IF && last_cond != COND_ELIF) {
			if (ms->flags & R_MAGIC_CHECK) {
				__magic_file_magwarn (ms, "syntax error: `elif'");
			}
			return -1;
		}
		last_cond = COND_ELIF;
		break;
	case COND_ELSE:
		if (last_cond != COND_IF && last_cond != COND_ELIF) {
			if (ms->flags & R_MAGIC_CHECK) {
				__magic_file_magwarn (ms, "syntax error: `else'");
			}
			return -1;
		}
		last_cond = COND_NONE;
		break;
	case COND_NONE:
		last_cond = COND_NONE;
		break;
	}

	ms->c.li[cont_level].last_cond = last_cond;
	return 0;
}

static int check_format_type(const char *ptr, int type) {
	int quad = 0;
	const char *const start = ptr;
	if (*ptr == '\0') {
		/* Missing format string; bad */
		return -1;
	}

	while (strchr ("#0- +", *ptr)) {
		ptr++;
	}
	if (*ptr == '*') {
		return -1;
	}
	while (isdigit ((ut8)*ptr)) {
		ptr++;
	}
	if (*ptr == '.') {
		ptr++;
		if (*ptr == '*') {
			return -1;
		}
		while (isdigit ((ut8)*ptr)) {
			ptr++;
		}
	}

	switch (type) {
	case FILE_FMT_QUAD:
		quad = 1;
		/*FALLTHROUGH*/
	case FILE_FMT_NUM:
		if (quad) {
			if (*ptr++ != 'l') {
				return -1;
			}
			if (*ptr++ != 'l') {
				return -1;
			}
		}
		switch (*ptr++) {
		case 'c':
		case 'd':
		case 'i':
		case 'o':
		case 'u':
		case 'x':
		case 'X':
			break;
		default:
			return -1;
		}
		break;
	case FILE_FMT_FLOAT:
		switch (*ptr++) {
		case 'e':
		case 'E':
		case 'f':
		case 'F':
		case 'g':
		case 'G':
			break;
		default:
			return -1;
		}
		break;
	case FILE_FMT_STR:
		if (*ptr++ != 's') {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return (int) (ptr - start);
}

/*
 * Check that the optional printf format in description matches
 * the type of the magic.
 */
static int check_format(RMagic *ms, struct r_magic *m) {
	char *ptr;
	int seen = 0;

	for (ptr = m->desc; *ptr; ptr++) {
		int fmtlen;

		if (*ptr != '%') {
			continue;
		}
		if (ptr[1] == '%') {
			ptr++;
			continue;
		}
		if (m->type >= FILE_NAMES_SIZE) {
			__magic_file_magwarn (ms, "Internal error inconsistency between "
				"m->type and format strings");
			return -1;
		}
		if (ms->magic_file_formats[m->type] == FILE_FMT_NONE) {
			__magic_file_magwarn (ms, "No format string for `%s' with description "
				"`%s'",
				m->desc,
				ms->magic_file_names[m->type]);
			return -1;
		}
		if (seen++) {
			__magic_file_magwarn (ms,
				"Too many format strings (should have at most one) "
				"for `%s' with description `%s'",
				ms->magic_file_names[m->type],
				m->desc);
			return -1;
		}
		fmtlen = check_format_type (ptr + 1, ms->magic_file_formats[m->type]);
		if (fmtlen == -1) {
			__magic_file_magwarn (ms, "Printf format `%c' is not valid for type "
				"`%s' in description `%s'",
				ptr[1]? ptr[1]: '?',
				ms->magic_file_names[m->type],
				m->desc);
			return -1;
		}
		ptr += fmtlen;
	}
	if (!seen) {
		/* No format string; ok */
		return 1;
	}
	return 0;
}

/* Single hex char to int; -1 if not a hex char. */
static int hextoint(int c) {
	if (!isascii ((ut8)c)) {
		return -1;
	}
	if (isdigit ((ut8)c)) {
		return c - '0';
	}
	if ((c >= 'a') && (c <= 'f')) {
		return c + 10 - 'a';
	}
	if ((c >= 'A') && (c <= 'F')) {
		return c + 10 - 'A';
	}
	return -1;
}

/*
 * Convert a string containing C character escapes.  Stop at an unescaped
 * space or tab.
 * Copy the converted version to "p", returning its length in *slen.
 * Return updated scan pointer as function result.
 */
static const char *getstr(RMagic *ms, const char *s, char *p, int plen, int *slen, int action) {
	const char *origs = s;
	char *origp = p;
	char *pmax = p + plen - 1;
	int c, val;

	while ((c = *s++) != '\0') {
		if (isspace ((ut8)c)) {
			break;
		}
		if (p >= pmax) {
			__magic_file_error (ms, 0, "string too long: `%s'", origs);
			return NULL;
		}
		if (c == '\\') {
			switch ((c = *s++)) {
			case '\0':
				if (action == FILE_COMPILE) {
					__magic_file_magwarn (ms, "incomplete escape");
				}
				goto out;
			case '\t':
				if (action == FILE_COMPILE) {
					__magic_file_magwarn (ms,
						"escaped tab found, use \\t instead");
					action++;
				}
				/*FALLTHROUGH*/
			default:
				if (action == FILE_COMPILE) {
					if (isprint ((ut8)c)) {
						__magic_file_magwarn (ms,
							"no need to escape `%c'",
							c);
					} else {
						__magic_file_magwarn (ms,
							"unknown escape sequence: \\%03o",
							c);
					}
				}
				/*FALLTHROUGH*/
			/* space, perhaps force people to use \040? */
			case ' ':
#if 0
			// Reject escapes that should stay literal.
			case '\'':
			case '"':
			case '?':
#endif
			/* Relations */
			case '>':
			case '<':
			case '&':
			case '^':
			case '=':
			case '!':
			/* and baskslash itself */
			case '\\':
				*p++ = (char)c;
				break;
			case 'a': *p++ = '\a'; break;
			case 'b': *p++ = '\b'; break;
			case 'f': *p++ = '\f'; break;
			case 'n': *p++ = '\n'; break;
			case 'r': *p++ = '\r'; break;
			case 't': *p++ = '\t'; break;
			case 'v': *p++ = '\v'; break;
			/* \ and up to 3 octal digits */
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
				val = c - '0';
				c = *s++; /* try for 2 */
				if (c >= '0' && c <= '7') {
					val = (val << 3) | (c - '0');
					c = *s++; /* try for 3 */
					if (c >= '0' && c <= '7') {
						val = (val << 3) | (c - '0');
					} else {
						--s;
					}
				} else {
					--s;
				}
				*p++ = (char)val;
				break;

			/* \x and up to 2 hex digits */
			case 'x':
				val = 'x'; /* Default if no digits */
				c = hextoint (*s++); /* Get next char */
				if (c >= 0) {
					val = c;
					c = hextoint (*s++);
					if (c >= 0) {
						val = (val << 4) + c;
					} else {
						--s;
					}
				} else {
					--s;
				}
				*p++ = (char)val;
				break;
			}
		} else {
			*p++ = (char)c;
		}
	}
out:
	*p = '\0';
	*slen = p - origp;
	return s;
}

/*
 * eatsize (): Eat the size spec from a number [eg. 10UL]
 */
static void eatsize(const char **p) {
	const char *l = *p;

	if (tolower (*l) == 'u') {
		l++;
	}

	switch (tolower (*l)) {
	case 'l': /* long */
	case 's': /* short */
	case 'h': /* short */
	case 'b': /* char/byte */
	case 'c': /* char/byte */
		l++;
		/*FALLTHROUGH*/
	default:
		break;
	}

	*p = l;
}

/*
 * Read a numeric value from a pointer, into the value union of a magic
 * pointer, according to the magic type.  Update the string pointer to point
 * just after the number read.  Return 0 for success, non-zero for failure.
 */
static int getvalue(RMagic *ms, struct r_magic *m, const char **p, int action) {
	int slen;

	if (file_magic_type_has_string_value (m->type)) {
		*p = getstr (ms, *p, m->value.s, sizeof (m->value.s), &slen, action);
		if (!*p) {
			if (ms->flags & R_MAGIC_CHECK) {
				__magic_file_magwarn (ms, "cannot get string from `%s'", m->value.s);
			}
			return -1;
		}
		m->vallen = slen;
		if (m->type == FILE_PSTRING) {
			m->vallen++;
		}
		return 0;
	}
	switch (m->type) {
	case FILE_FLOAT:
	case FILE_BEFLOAT:
	case FILE_LEFLOAT:
		if (m->reln != 'x') {
			char *ep;
#ifdef HAVE_STRTOF
			m->value.f = strtof (*p, &ep);
#else
			m->value.f = (float)strtod (*p, &ep);
#endif
			*p = ep;
		}
		return 0;
	case FILE_DOUBLE:
	case FILE_BEDOUBLE:
	case FILE_LEDOUBLE:
		if (m->reln != 'x') {
			char *ep;
			m->value.d = strtod (*p, &ep);
			*p = ep;
		}
		return 0;
	default:
		if (m->reln != 'x') {
			char *ep;
			m->value.q = __magic_file_signextend (ms, m, (ut64)strtoull (*p, &ep, 0));
			*p = ep;
			eatsize (p);
		}
		return 0;
	}
}

/*
 * parse one line from magic file, put into magic[index++] if valid
 */
static bool parse(RMagic *ms, struct r_magic_entry **mentryp, ut32 *nmentryp, const char *line, size_t lineno, int action) {
	size_t i;
	struct r_magic_entry *me;
	struct r_magic *m;
	const char *l = line;
	char *t;
	int op;
	ut32 cont_level = 0;

	for (; *l == '>'; l++, cont_level++) {
		;
	}
	if (cont_level == 0 || cont_level > ms->last_cont_level) {
		if (__magic_file_check_mem (ms, cont_level) == -1) {
			return false;
		}
	}
	ms->last_cont_level = cont_level;
#define ALLOC_CHUNK (size_t)10
#define ALLOC_INCR (size_t)200
	if (cont_level != 0) {
		if (*nmentryp == 0) {
			__magic_file_error (ms, 0, "No current entry for continuation");
			return false;
		}
		me = &(*mentryp)[*nmentryp - 1];
		if (me->cont_count == me->max_count) {
			struct r_magic *nm;
			size_t cnt = me->max_count + ALLOC_CHUNK;
			if (! (nm = realloc (me->mp, sizeof (*nm) * cnt))) {
				__magic_file_oomem (ms, sizeof (*nm) * cnt);
				return false;
			}
			me->mp = nm;
			me->max_count = cnt;
		}
		m = &me->mp[me->cont_count++];
		(void)memset (m, 0, sizeof (*m));
		m->cont_level = cont_level;
	} else {
		if (*nmentryp == ms->maxmagic) {
			struct r_magic_entry *mp;

			ms->maxmagic += ALLOC_INCR;
			if (! (mp = realloc (*mentryp, sizeof (*mp) * ms->maxmagic))) {
				__magic_file_oomem (ms, sizeof (*mp) * ms->maxmagic);
				return false;
			}
			(void)memset (&mp[*nmentryp], 0, sizeof (*mp) * ALLOC_INCR);
			*mentryp = mp;
		}
		me = &(*mentryp)[*nmentryp];
		if (!me->mp) {
			if (! (m = malloc (sizeof (*m) * ALLOC_CHUNK))) {
				__magic_file_oomem (ms, sizeof (*m) * ALLOC_CHUNK);
				return false;
			}
			me->mp = m;
			me->max_count = ALLOC_CHUNK;
		} else {
			m = me->mp;
		}
		(void)memset (m, 0, sizeof (*m));
		m->cont_level = 0;
		me->cont_count = 1;
	}
	m->lineno = lineno;

	if (*l == '&') { /* m->cont_level == 0 checked below. */
		l++; /* step over */
		m->flag |= OFFADD;
	}
	if (*l == '(') {
		l++; /* step over */
		m->flag |= INDIR;
		if (m->flag & OFFADD) {
			m->flag = (m->flag & ~OFFADD) | INDIROFFADD;
		}

		if (*l == '&') { /* m->cont_level == 0 checked below */
			l++; /* step over */
			m->flag |= OFFADD;
		}
	}
	/* Indirect offsets are not valid at level 0. */
	if (m->cont_level == 0 && (m->flag & (OFFADD | INDIROFFADD))) {
		if (ms->flags & R_MAGIC_CHECK) {
			__magic_file_magwarn (ms, "relative offset at level 0");
		}
	}

	/* get offset, then skip over it */
	m->offset = (ut32)strtoul (l, &t, 0);
	if ((l == t) && (ms->flags & R_MAGIC_CHECK)) {
		__magic_file_magwarn (ms, "offset `%s' invalid", l);
	}
	l = t;

	if (m->flag & INDIR) {
		m->in_type = FILE_LONG;
		m->in_offset = 0;
		// Parse the indirect offset suffix.
		if (*l == '.') {
			l++;
			switch (*l) {
			case 'l':
				m->in_type = FILE_LELONG;
				break;
			case 'L':
				m->in_type = FILE_BELONG;
				break;
			case 'm':
				m->in_type = FILE_MELONG;
				break;
			case 'h':
			case 's':
				m->in_type = FILE_LESHORT;
				break;
			case 'H':
			case 'S':
				m->in_type = FILE_BESHORT;
				break;
			case 'c':
			case 'b':
			case 'C':
			case 'B':
				m->in_type = FILE_BYTE;
				break;
			case 'e':
			case 'f':
			case 'g':
				m->in_type = FILE_LEDOUBLE;
				break;
			case 'E':
			case 'F':
			case 'G':
				m->in_type = FILE_BEDOUBLE;
				break;
			default:
				if (ms->flags & R_MAGIC_CHECK) {
					__magic_file_magwarn (ms,
						"indirect offset type `%c' invalid",
						*l);
				}
				break;
			}
			l++;
		}

		m->in_op = 0;
		if (*l == '~') {
			m->in_op |= FILE_OPINVERSE;
			l++;
		}
		if ((op = get_op (*l)) != -1) {
			m->in_op |= op;
			l++;
		}
		if (*l == '(') {
			m->in_op |= FILE_OPINDIRECT;
			l++;
		}
		if (isdigit ((ut8)*l) || *l == '-') {
			m->in_offset = (int32_t)strtol (l, &t, 0);
			if (l == t) {
				if (ms->flags & R_MAGIC_CHECK) {
					__magic_file_magwarn (ms,
						"in_offset `%s' invalid",
						l);
				}
			}
			l = t;
		}
		if (*l++ != ')' ||
			((m->in_op & FILE_OPINDIRECT) && *l++ != ')')) {
			if (ms->flags & R_MAGIC_CHECK) {
				__magic_file_magwarn (ms,
					"missing ')' in indirect offset");
			}
		}
	}
	l = eatab (l);

	m->cond = get_cond (l, &l);
	if (check_cond (ms, m->cond, cont_level) == -1) {
		return false;
	}
	l = eatab (l);

	if (*l == 'u') {
		l++;
		m->flag |= UNSIGNED;
	}

	m->type = get_type (l, &l);
	if (m->type == FILE_INVALID) {
		if (ms->flags & R_MAGIC_CHECK) {
			__magic_file_magwarn (ms, "type `%s' invalid", l);
		}
		return false;
	}

	/* New-style anding: "0 byte&0x80 =0x80 dynamically linked" */
	/* New and improved: ~ & | ^ + - * / % -- exciting, isn't it? */

	m->mask_op = 0;
	if (*l == '~') {
		if (!MAGIC_IS_STRING (m->type)) {
			m->mask_op |= FILE_OPINVERSE;
		} else if (ms->flags & R_MAGIC_CHECK) {
			__magic_file_magwarn (ms, "'~' invalid for string types");
		}
		l++;
	}
	m->str_range = 0;
	m->str_flags = 0;
	m->num_mask = 0;
	if ((op = get_op (*l)) != -1) {
		if (!MAGIC_IS_STRING (m->type)) {
			ut64 val;
			l++;
			m->mask_op |= op;
			val = (ut64)strtoull (l, &t, 0);
			l = t;
			m->num_mask = __magic_file_signextend (ms, m, val);
			eatsize (&l);
		} else if (op == FILE_OPDIVIDE) {
			int have_range = 0;
			for (l++; !isspace (*l); l++) {
				switch (*l) {
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					if (have_range &&
						(ms->flags & R_MAGIC_CHECK)) {
						__magic_file_magwarn (ms,
							"multiple ranges");
					}
					have_range = 1;
					m->str_range = strtoul (l, &t, 0);
					if (m->str_range == 0) {
						__magic_file_magwarn (ms,
							"zero range");
					}
					l = t - 1;
					break;
				case CHAR_COMPACT_BLANK:
					m->str_flags |= STRING_COMPACT_BLANK;
					break;
				case CHAR_COMPACT_OPTIONAL_BLANK:
					m->str_flags |=
						STRING_COMPACT_OPTIONAL_BLANK;
					break;
				case CHAR_IGNORE_LOWERCASE:
					m->str_flags |= STRING_IGNORE_LOWERCASE;
					break;
				case CHAR_IGNORE_UPPERCASE:
					m->str_flags |= STRING_IGNORE_UPPERCASE;
					break;
				case CHAR_REGEX_OFFSET_START:
					m->str_flags |= REGEX_OFFSET_START;
					break;
				default:
					if (ms->flags & R_MAGIC_CHECK) {
						__magic_file_magwarn (ms,
							"string extension `%c' invalid",
							*l);
					}
					return false;
				}
				/* allow multiple '/' for readability */
				if (l[1] == '/' && !isspace ((ut8)l[2])) {
					l++;
				}
			}
			if (string_modifier_check (ms, m) == -1) {
				return false;
			}
		} else {
			if (ms->flags & R_MAGIC_CHECK) {
				__magic_file_magwarn (ms, "invalid string op: %c", *t);
			}
			return false;
		}
	}
	l = eatab (l);

	switch (*l) {
	case '>':
	case '<':
	/* Old-style anding: "0 byte &0x80 dynamically linked" */
	case '&':
	case '^':
	case '=':
		m->reln = *l;
		l++;
		if (*l == '=') {
			/* HP compat: ignore &= etc. */
			l++;
		}
		break;
	case '!':
		m->reln = *l;
		l++;
		break;
	default:
		m->reln = '='; /* the default relation */
		if (*l == 'x' && ((isascii ((ut8)l[1]) && isspace ((ut8)l[1])) || !l[1])) {
			m->reln = *l;
			l++;
		}
		break;
	}
	// Parse the value unless the relation is 'x'.
	if (m->reln != 'x' && getvalue (ms, m, &l, action)) {
		return false;
	}

	// Parse the description.
	l = eatab (l);
	if (l[0] == '\b') {
		l++;
		m->flag |= NOSPACE;
	} else if ((l[0] == '\\') && (l[1] == 'b')) {
		l++;
		l++;
		m->flag |= NOSPACE;
	}
	for (i = 0; (m->desc[i++] = *l++) != '\0' && i < sizeof (m->desc);) {
	}
	if (i == sizeof (m->desc)) {
		m->desc[sizeof (m->desc) - 1] = '\0';
		if (ms->flags & R_MAGIC_CHECK) {
			__magic_file_magwarn (ms, "description `%s' truncated", m->desc);
		}
	}

	// Only validate formats in check mode.
	if (ms->flags & R_MAGIC_CHECK) {
		if (check_format (ms, m) == -1) {
			return false;
		}
	}
	if (action == FILE_CHECK) {
		__magic_file_mdump (ms, m);
	}
	m->mimetype[0] = '\0'; /* initialise MIME type to none */
	if (m->cont_level == 0) {
		++ (*nmentryp); /* make room for next */
	}
	return true;
}

/*
 * parse a MIME annotation line from magic file, put into magic[index - 1]
 * if valid
 */
static int parse_mime(RMagic *ms, struct r_magic_entry **mentryp, ut32 *nmentryp, const char *line) {
	size_t i;
	const char *l = line;
	struct r_magic *m;
	struct r_magic_entry *me;

	if (*nmentryp == 0) {
		__magic_file_error (ms, 0, "No current entry for MIME type");
		return -1;
	}

	me = &(*mentryp)[*nmentryp - 1];
	m = &me->mp[me->cont_count == 0? 0: me->cont_count - 1];

	if (m->mimetype[0] != '\0') {
		__magic_file_error (ms, 0, "Current entry already has a MIME type: %s\n"
			"Description: %s\nNew type: %s",
			m->mimetype,
			m->desc,
			l);
		return -1;
	}

	l = eatab (l);
	for (i = 0;
		*l && ((isascii ((ut8)*l) && isalnum ((ut8)*l)) || strchr ("-+/.", *l)) && i < sizeof (m->mimetype);
		m->mimetype[i++] = *l++) {
	}
	if (i == sizeof (m->mimetype)) {
		m->desc[sizeof (m->mimetype) - 1] = '\0';
		if (ms->flags & R_MAGIC_CHECK) {
			__magic_file_magwarn (ms, "MIME type `%s' truncated %zu", m->mimetype, i);
		}
	} else {
		m->mimetype[i] = '\0';
	}

	return (i > 0)? 0: -1;
}

static bool parse_line(RMagic *ms, int action, struct r_magic_entry **marray, ut32 *marraycount, char *line, size_t lineno) {
	// strip trailing whitespace so Windows CRLF magic files parse correctly
	r_str_trim_tail (line);
	if (R_STR_ISEMPTY (line) || *line == '#') {
		return true;
	}
	if (r_str_startswith (line, mime_marker)) {
		return parse_mime (ms, marray, marraycount, line + mime_marker_len) == 0;
	}
	return parse (ms, marray, marraycount, line, lineno, action);
}

static void load_b(RMagic *ms, int action, const char *data, int *errs, struct r_magic_entry **marray, ut32 *marraycount) {
	char line[BUFSIZ];
	for (ms->line = 1; bgets (line, sizeof (line), &data); ms->line++) {
		if (!parse_line (ms, action, marray, marraycount, line, ms->line)) {
			(*errs)++;
		}
	}
}

/*
 * Load and parse one file.
 */
static void load_1(RMagic *ms, int action, const char *file, int *errs, struct r_magic_entry **marray, ut32 *marraycount) {
	ms->file = file;
	char *data = r_file_slurp (file, NULL);
	if (!data) {
		__magic_file_error (ms, errno, "cannot read magic file `%s'", file);
		(*errs)++;
		return;
	}
	load_b (ms, action, data, errs, marray, marraycount);
	free (data);
}

static int apprentice_finish(RMagic *ms, struct r_magic **magicp, ut32 *nmagicp, struct r_magic_entry *marray, ut32 marraycount, int errs) {
	ut32 i;
	ut32 mentrycount = 0;
	ut32 starttest;

	if (!errs) {
		for (i = 0; i < marraycount;) {
			if (marray[i].mp->cont_level != 0) {
				i++;
				continue;
			}

			starttest = i;
			do {
				set_test_type (marray[starttest].mp, marray[i].mp);
				debug_test_type (ms, marray[i].mp);
			} while (++i < marraycount && marray[i].mp->cont_level != 0);
		}

		qsort (marray, marraycount, sizeof (*marray), apprentice_sort);

		for (i = 0; i < marraycount; i++) {
			if (marray[i].mp->cont_level == 0 &&
				marray[i].mp->type == FILE_DEFAULT) {
				while (++i < marraycount) {
					if (marray[i].mp->cont_level == 0) {
						break;
					}
				}
				if (i != marraycount) {
					ms->line = marray[i].mp->lineno;
					__magic_file_magwarn (ms, "level 0 \"default\" did not sort last");
				}
				break;
			}
		}

		for (i = 0; i < marraycount; i++) {
			mentrycount += marray[i].cont_count;
		}

		if (! (*magicp = malloc (1 + (sizeof (**magicp) * mentrycount)))) {
			__magic_file_oomem (ms, sizeof (**magicp) * mentrycount);
			errs++;
		} else {
			mentrycount = 0;
			for (i = 0; i < marraycount; i++) {
				(void)memcpy (*magicp + mentrycount, marray[i].mp, marray[i].cont_count * sizeof (**magicp));
				mentrycount += marray[i].cont_count;
			}
		}
	}
	for (i = 0; i < marraycount; i++) {
		free (marray[i].mp);
	}
	free (marray);
	if (errs) {
		*magicp = NULL;
		*nmagicp = 0;
		return errs;
	}
	*nmagicp = mentrycount;
	return 0;
}

/*
 * parse a file or directory of files
 * const char *fn: name of magic file or directory
 */
static int apprentice_load(RMagic *ms, struct r_magic **magicp, ut32 *nmagicp, const char *fn, int action) {
	ut32 marraycount = 0;
	RList *files;
	RListIter *iter;
	char *name;
	int errs = 0;
	ms->flags |= R_MAGIC_CHECK; /* Enable checks for parsed files */
	ms->maxmagic = MAXMAGIS;
	struct r_magic_entry *marray = calloc (ms->maxmagic, sizeof (*marray));
	if (!marray) {
		__magic_file_oomem (ms, ms->maxmagic * sizeof (*marray));
		return -1;
	}

	/* print silly verbose header for USG compat. */
	if (action == FILE_CHECK) {
		R_LOG_INFO ("%s", usg_hdr);
	}

	/* load directory or file */
	if (r_file_is_directory (fn)) {
		if (r_sandbox_enable (0) && !r_sandbox_check_path (fn)) {
			free (marray);
			return -1;
		}
		files = r_sys_dir (fn);
		if (files) {
			r_list_foreach (files, iter, name) {
				if (*name == '.') {
					continue;
				}
				char *subfn = r_file_new (fn, name, NULL);
				if (subfn && r_file_is_regular (subfn)) {
					load_1 (ms, action, subfn, &errs, &marray, &marraycount);
				}
				free (subfn);
			}
			r_list_free (files);
		} else {
			errs++;
		}
	} else {
		load_1 (ms, action, fn, &errs, &marray, &marraycount);
	}
	return apprentice_finish (ms, magicp, nmagicp, marray, marraycount, errs);
}

static int apprentice_load_buffer(RMagic *ms, struct r_magic **magicp, ut32 *nmagicp, const ut8 *buf, size_t buf_size, int action) {
	ut32 marraycount = 0;
	int errs = 0;

	ms->flags |= R_MAGIC_CHECK;
	ms->file = "(buffer)";
	ms->maxmagic = MAXMAGIS;
	struct r_magic_entry *marray = calloc (ms->maxmagic, sizeof (*marray));
	if (!marray) {
		__magic_file_oomem (ms, ms->maxmagic * sizeof (*marray));
		return -1;
	}
	if (action == FILE_CHECK) {
		R_LOG_INFO ("%s", usg_hdr);
	}
	char *data = r_str_ndup ((const char *)buf, buf_size);
	if (!data) {
		free (marray);
		__magic_file_oomem (ms, buf_size);
		return -1;
	}
	load_b (ms, action, data, &errs, &marray, &marraycount);
	free (data);
	return apprentice_finish (ms, magicp, nmagicp, marray, marraycount, errs);
}

static const char ext[] = ".mgc";
/*
 * make a dbname
 */
static char *mkdbname(const char *fn, int strip) {
	if (strip) {
		const char *p;
		if ((p = strrchr (fn, '/'))) {
			fn = p + 1;
		}
	}
	return r_str_newf ("%s%s", fn, ext);
}

static void decode_compiled_magic_entry(struct r_magic *m, bool be) {
	m->cont_level = r_read_ble16 (&m->cont_level, be);
	m->offset = r_read_ble32 (&m->offset, be);
	m->in_offset = r_read_ble32 (&m->in_offset, be);
	m->lineno = r_read_ble32 (&m->lineno, be);
	if (MAGIC_IS_STRING (m->type)) {
		m->str_range = r_read_ble32 (&m->str_range, be);
		m->str_flags = r_read_ble32 (&m->str_flags, be);
	} else {
		m->value.q = r_read_ble64 (&m->value.q, be);
		m->num_mask = r_read_ble64 (&m->num_mask, be);
	}
}

static void decode_compiled_magic(struct r_magic *magic, ut32 nmagic, bool be) {
	ut32 i;
	for (i = 0; i < nmagic; i++) {
		decode_compiled_magic_entry (&magic[i], be);
	}
}

static void encode_compiled_magic_entry(struct r_magic *dst, const struct r_magic *src) {
	memcpy (dst, src, sizeof (*dst));
	r_write_le16 (&dst->cont_level, src->cont_level);
	r_write_le32 (&dst->offset, src->offset);
	r_write_le32 (&dst->in_offset, src->in_offset);
	r_write_le32 (&dst->lineno, src->lineno);
	if (MAGIC_IS_STRING (src->type)) {
		r_write_le32 (&dst->str_range, src->str_range);
		r_write_le32 (&dst->str_flags, src->str_flags);
	} else {
		r_write_le64 (&dst->value.q, src->value.q);
		r_write_le64 (&dst->num_mask, src->num_mask);
	}
}

static void encode_compiled_magic(struct r_magic *dst, const struct r_magic *src, ut32 nmagic) {
	ut32 i;
	for (i = 0; i < nmagic; i++) {
		encode_compiled_magic_entry (&dst[i], &src[i]);
	}
}

static bool read_compiled_magic_header(const ut8 *buf, ut32 *version, bool *be) {
	ut32 magic = r_read_le32 (buf);
	if (magic == MAGICNO) {
		*version = r_read_at_le32 (buf, sizeof (ut32));
		*be = false;
		return true;
	}
	magic = r_read_be32 (buf);
	if (magic != MAGICNO) {
		return false;
	}
	*version = r_read_at_be32 (buf, sizeof (ut32));
	*be = true;
	return true;
}

/*
 * handle a compiled file.
 */
static int apprentice_map(RMagic *ms, struct r_magic **magicp, ut32 *nmagicp, const char *fn) {
	int fd = -1;
	struct stat st;
	ut32 version = 0;
	bool be = false;
	void *mm = NULL;

	char *dbname = mkdbname (fn, 0);
	if (!dbname) {
		goto error2;
	}

	if ((fd = r_sandbox_open (dbname, O_RDONLY | O_BINARY, 0)) == -1) {
		goto error2;
	}

	if (fstat (fd, &st) == -1) {
		__magic_file_error (ms, errno, "cannot stat `%s'", dbname);
		goto error1;
	}
	if (st.st_size < 8) {
		__magic_file_error (ms, 0, "file `%s' is too small", dbname);
		goto error1;
	}
	if (! (mm = malloc ((size_t)st.st_size))) {
		__magic_file_oomem (ms, (size_t)st.st_size);
		goto error1;
	}
	if (read (fd, mm, (size_t)st.st_size) != (size_t)st.st_size) {
		__magic_file_badread (ms);
		goto error1;
	}
	*magicp = mm;
	(void)close (fd);
	fd = -1;
	if (!read_compiled_magic_header ((const ut8 *)*magicp, &version, &be)) {
		// OPENBSDBUG __magic_file_error (ms, 0, "bad magic in `%s'");
		__magic_file_error (ms, 0, "bad magic in `%s'", dbname);
		goto error1;
	}
	if (version != VERSIONNO) {
		__magic_file_error (ms, 0, "File %d.%d supports only %d version magic "
			"files. `%s' is version %d",
			FILE_VERSION_MAJOR,
			patchlevel,
			VERSIONNO,
			dbname,
			version);
		goto error1;
	}
	*nmagicp = (ut32) (st.st_size / sizeof (struct r_magic));
	if (*nmagicp > 0) {
		(*nmagicp)--;
	}
	(*magicp)++;
	decode_compiled_magic (*magicp, *nmagicp, be);
	free (dbname);
	return 1;

error1:
	if (fd != -1) {
		(void)close (fd);
	}
	if (mm) {
		free (mm);
	} else {
		*magicp = NULL;
		*nmagicp = 0;
	}
error2:
	free (dbname);
	return -1;
}

static int apprentice_map_buffer(RMagic *ms, struct r_magic **magicp, ut32 *nmagicp, const ut8 *buf, size_t buf_size) {
	ut32 version = 0;
	bool be = false;
	void *mm = NULL;

	if (buf_size < sizeof (struct r_magic)) {
		__magic_file_error (ms, 0, "magic buffer is too small");
		return -1;
	}
	mm = malloc (buf_size);
	if (!mm) {
		__magic_file_oomem (ms, buf_size);
		return -1;
	}
	memcpy (mm, buf, buf_size);
	*magicp = mm;
	if (!read_compiled_magic_header ((const ut8 *)mm, &version, &be)) {
		__magic_file_error (ms, 0, "bad magic in buffer");
		free (mm);
		*magicp = NULL;
		*nmagicp = 0;
		return -1;
	}
	if (version != VERSIONNO) {
		__magic_file_error (ms, 0, "magic buffer version %d != %d", version, VERSIONNO);
		free (mm);
		*magicp = NULL;
		*nmagicp = 0;
		return -1;
	}
	*nmagicp = (ut32) (buf_size / sizeof (struct r_magic));
	if (*nmagicp > 0) {
		(*nmagicp)--;
	}
	(*magicp)++;
	decode_compiled_magic (*magicp, *nmagicp, be);
	return 1;
}

static void apprentice_log_error(RMagic *ms, int error, const char *fmt, const char *dbname) {
	if (!ms || ms->haderr) {
		return;
	}
	r_strbuf_setf (&ms->o.sb, fmt, dbname);
	if (error > 0) {
		r_strbuf_appendf (&ms->o.sb, " (%s)", strerror (error));
	}
	ms->haderr++;
	ms->error = error;
	R_LOG_ERROR ("%s", r_strbuf_get (&ms->o.sb));
}

/*
 * handle a compiled file.
 */
static int apprentice_compile(RMagic *ms, struct r_magic **magicp, ut32 *nmagicp, const char *fn) {
	int fd = -1;
	int rv = -1;
	size_t buf_size = 0;
	struct r_magic hdr = { 0 };
	struct r_magic *encoded = NULL;
	char *dbname = mkdbname (fn, 1);
	if (!dbname) {
		return -1;
	}
	if (r_mul_overflow ((size_t)*nmagicp, sizeof (struct r_magic), &buf_size)) {
		__magic_file_oomem (ms, SIZE_MAX);
		free (dbname);
		return -1;
	}
	if (buf_size > 0) {
		encoded = malloc (buf_size);
		if (!encoded) {
			__magic_file_oomem (ms, buf_size);
			free (dbname);
			return -1;
		}
		encode_compiled_magic (encoded, *magicp, *nmagicp);
	}
	r_write_le32 (&hdr, MAGICNO);
	r_write_at_le32 (&hdr, VERSIONNO, sizeof (ut32));

	do {
		fd = r_sandbox_open (dbname, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
		if (fd == -1) {
			apprentice_log_error (ms, errno, "cannot open `%s'", dbname);
			break;
		}
		if (write (fd, &hdr, sizeof (hdr)) != (int)sizeof (hdr)) {
			apprentice_log_error (ms, errno, "error writing `%s'", dbname);
			break;
		}
		if (buf_size > 0 && write (fd, encoded, buf_size) != (int)buf_size) {
			apprentice_log_error (ms, errno, "error writing `%s'", dbname);
			break;
		}
		rv = 0;
	} while (0);

	if (fd != -1) {
		(void)close (fd);
	}
	free (encoded);
	free (dbname);
	return rv;
}

/*
 * Handle one file or directory.
 */
static int apprentice_1(RMagic *ms, const char *fn, int action, RVecMagicMList *mlist) {
	struct r_magic *magic = NULL;
	ut32 *min_bytes = NULL;
	ut32 nmagic = 0;
	int rv = -1;
	size_t bytes_max = 0;

	if (!ms) {
		return -1;
	}
	ms->haderr = 0;
	if (sizeof (struct r_magic) != FILE_MAGICSIZE) {
		__magic_file_error (ms, 0, "magic element size %lu != %lu", (unsigned long) (size_t)sizeof (*magic), (unsigned long)FILE_MAGICSIZE);
		return -1;
	}

	ms->file = fn; // fix use of ms->file before being initialized
	if (action == FILE_COMPILE) {
		rv = apprentice_load (ms, &magic, &nmagic, fn, action);
		if (rv != 0) {
			return -1;
		}
		rv = apprentice_compile (ms, &magic, &nmagic, fn);
		free (magic);
		return rv;
	}

	if ((rv = apprentice_map (ms, &magic, &nmagic, fn)) == -1) {
		// if (ms->flags & R_MAGIC_CHECK)
		//	__magic_file_magwarn (ms, "using regular magic file `%s'", fn);
		rv = apprentice_load (ms, &magic, &nmagic, fn, action);
		if (rv != 0) {
			return -1;
		}
	}

	if (!magic) {
		__magic_file_delmagic (magic, rv);
		return -1;
	}
	if (!magic_prepare_requirements (ms, magic, nmagic, &bytes_max, &min_bytes)) {
		__magic_file_delmagic (magic, rv);
		return -1;
	}

	struct mlist *const ml = RVecMagicMList_emplace_back (mlist);
	if (!ml) {
		free (min_bytes);
		__magic_file_delmagic (magic, rv);
		__magic_file_oomem (ms, sizeof (*ml));
		return -1;
	}

	ml->magic = magic;
	ml->min_bytes = min_bytes;
	ml->nmagic = nmagic;
	ml->bytes_max = (ut32)bytes_max;
	ml->mapped = (ut8)rv;
	return 0;
}

/* const char *fn: list of magic files and directories */
bool __magic_file_apprentice(RMagic *ms, const char *fn, size_t fn_size, int action, RVecMagicMList *mlist) {
	char *p;
	int file_err, errs = -1;
	const char *it;
	size_t path_count = 1;

	if (!fn || !mlist) {
		return false;
	}

	char *mfn = r_str_ndup (fn, fn_size);
	if (!mfn) {
		__magic_file_oomem (ms, fn_size);
		return false;
	}
	fn = mfn;
	for (it = fn; (it = strstr (it, R_SYS_ENVSEP)); it += strlen (R_SYS_ENVSEP)) {
		path_count++;
	}
	if (!RVecMagicMList_reserve (mlist, path_count)) {
		free (mfn);
		__magic_file_oomem (ms, path_count * sizeof (struct mlist));
		return false;
	}

	while (fn) {
		p = strstr (fn, R_SYS_ENVSEP);
		if (p) {
			*p++ = '\0';
		}
		if (*fn == '\0') {
			break;
		}
		file_err = apprentice_1 (ms, fn, action, mlist);
		errs = R_MAX (errs, file_err);
		fn = p;
	}
	if (errs == -1) {
		free (mfn);
		__magic_file_error (ms, 0, "could not find any magic files!");
		return false;
	}
	free (mfn);
	return true;
}

static bool is_compiled_magic_buffer(const ut8 *buf, size_t buf_size) {
	ut32 version = 0;
	bool needsbyteswap = false;

	return buf_size >= sizeof (ut32) * 2 && read_compiled_magic_header (buf, &version, &needsbyteswap) && version == VERSIONNO;
}

bool __magic_file_apprentice_buffer(RMagic *ms, const ut8 *buf, size_t buf_size, int action, RVecMagicMList *mlist) {
	struct r_magic *magic = NULL;
	ut32 *min_bytes = NULL;
	ut32 nmagic = 0;
	int mapped = 0;
	size_t bytes_max = 0;

	if (!buf || !mlist) {
		return false;
	}
	if (action == FILE_COMPILE) {
		__magic_file_error (ms, 0, "magic buffer compilation is not supported");
		return false;
	}
	if (is_compiled_magic_buffer (buf, buf_size)) {
		mapped = apprentice_map_buffer (ms, &magic, &nmagic, buf, buf_size);
		if (mapped < 0) {
			return false;
		}
	} else {
		if (apprentice_load_buffer (ms, &magic, &nmagic, buf, buf_size, action) != 0) {
			return false;
		}
	}
	if (!magic_prepare_requirements (ms, magic, nmagic, &bytes_max, &min_bytes)) {
		__magic_file_delmagic (magic, mapped);
		return false;
	}
	if (!RVecMagicMList_reserve (mlist, RVecMagicMList_length (mlist) + 1)) {
		free (min_bytes);
		__magic_file_delmagic (magic, mapped);
		__magic_file_oomem (ms, sizeof (struct mlist));
		return false;
	}
	struct mlist *const ml = RVecMagicMList_emplace_back (mlist);
	if (!ml) {
		free (min_bytes);
		__magic_file_delmagic (magic, mapped);
		__magic_file_oomem (ms, sizeof (*ml));
		return false;
	}
	ml->magic = magic;
	ml->min_bytes = min_bytes;
	ml->nmagic = nmagic;
	ml->bytes_max = (ut32)bytes_max;
	ml->mapped = (ut8)mapped;
	return true;
}
#endif

/*	$OpenBSD: apprentice.c,v 1.29 2009/11/11 16:21:51 jsg Exp $ */
/*
 * Copyright (c) Ian F. Darwin 1986-1995.
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
/*
 * apprentice - make one pass through /etc/magic, learning its secrets.
 */
#include <r_userconf.h>

#if !USE_LIB_MAGIC

#include <r_util.h>
#include <sys/param.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#if __UNIX__
#define QUICK 1
#include <sys/mman.h>
#endif
#include "file.h"
#include "patchlevel.h"

#define	EATAB {while (isascii((ut8) *l) && isspace((ut8) *l))  ++l;}
#define LOWCASE(l) (isupper((ut8) (l)) ? tolower((ut8) (l)) : (l))

#ifdef __HAIKU__
#define MAP_FILE 0
#endif

struct r_magic_entry {
	struct r_magic *mp;
	ut32 cont_count;
	ut32 max_count;
};

int file_formats[FILE_NAMES_SIZE];
const size_t file_nformats = FILE_NAMES_SIZE;
const char *file_names[FILE_NAMES_SIZE];
const size_t file_nnames = FILE_NAMES_SIZE;

static int getvalue(RMagic *ms, struct r_magic *, const char **, int);
static int hextoint(int);
static const char *getstr(RMagic *, const char *, char *, int, int *, int);
static int parse(RMagic *, struct r_magic_entry **, ut32 *, const char *, size_t, int);
static int parse_mime(RMagic *, struct r_magic_entry **, ut32 *, const char *);
static void eatsize(const char **);
static int apprentice_1(RMagic *, const char *, int, struct mlist *);
static size_t apprentice_r_magic_strength(const struct r_magic *);
static int apprentice_sort(const void *, const void *);
static int apprentice_load(RMagic *, struct r_magic **, ut32 *, const char *, int);
static void byteswap(struct r_magic *, ut32);
static void bs1(struct r_magic *);
static ut16 swap2(ut16);
static ut32 swap4(ut32);
static ut64 swap8(ut64);
static char *mkdbname(const char *, int);
static int apprentice_map(RMagic *, struct r_magic **, ut32 *, const char *);
static int apprentice_compile(RMagic *, struct r_magic **, ut32 *, const char *);
static int check_format_type(const char *, int);
static int check_format(RMagic *, struct r_magic *);
static int get_op(char);

static size_t maxmagic = 0;
static size_t magicsize = sizeof(struct r_magic);

static const char usg_hdr[] = "cont\toffset\ttype\topcode\tmask\tvalue\tdesc";
static const char mime_marker[] = "!:mime";
static const size_t mime_marker_len = sizeof(mime_marker) - 1;

static const struct type_tbl_s {
	const char name[16];
	const size_t len;
	const int type;
	const int format;
} type_tbl[] = {
# define XX(s)		s, (sizeof(s) - 1)
# define XX_NULL	"", 0
	{ XX("byte"),		FILE_BYTE,		FILE_FMT_NUM },
	{ XX("short"),		FILE_SHORT,		FILE_FMT_NUM },
	{ XX("default"),	FILE_DEFAULT,		FILE_FMT_STR },
	{ XX("long"),		FILE_LONG,		FILE_FMT_NUM },
	{ XX("string"),		FILE_STRING,		FILE_FMT_STR },
	{ XX("date"),		FILE_DATE,		FILE_FMT_STR },
	{ XX("beshort"),	FILE_BESHORT,		FILE_FMT_NUM },
	{ XX("belong"),		FILE_BELONG,		FILE_FMT_NUM },
	{ XX("bedate"),		FILE_BEDATE,		FILE_FMT_STR },
	{ XX("leshort"),	FILE_LESHORT,		FILE_FMT_NUM },
	{ XX("lelong"),		FILE_LELONG,		FILE_FMT_NUM },
	{ XX("ledate"),		FILE_LEDATE,		FILE_FMT_STR },
	{ XX("pstring"),	FILE_PSTRING,		FILE_FMT_STR },
	{ XX("ldate"),		FILE_LDATE,		FILE_FMT_STR },
	{ XX("beldate"),	FILE_BELDATE,		FILE_FMT_STR },
	{ XX("leldate"),	FILE_LELDATE,		FILE_FMT_STR },
	{ XX("regex"),		FILE_REGEX,		FILE_FMT_STR },
	{ XX("bestring16"),	FILE_BESTRING16,	FILE_FMT_STR },
	{ XX("lestring16"),	FILE_LESTRING16,	FILE_FMT_STR },
	{ XX("search"),		FILE_SEARCH,		FILE_FMT_STR },
	{ XX("medate"),		FILE_MEDATE,		FILE_FMT_STR },
	{ XX("meldate"),	FILE_MELDATE,		FILE_FMT_STR },
	{ XX("melong"),		FILE_MELONG,		FILE_FMT_NUM },
	{ XX("quad"),		FILE_QUAD,		FILE_FMT_QUAD },
	{ XX("lequad"),		FILE_LEQUAD,		FILE_FMT_QUAD },
	{ XX("bequad"),		FILE_BEQUAD,		FILE_FMT_QUAD },
	{ XX("qdate"),		FILE_QDATE,		FILE_FMT_STR },
	{ XX("leqdate"),	FILE_LEQDATE,		FILE_FMT_STR },
	{ XX("beqdate"),	FILE_BEQDATE,		FILE_FMT_STR },
	{ XX("qldate"),		FILE_QLDATE,		FILE_FMT_STR },
	{ XX("leqldate"),	FILE_LEQLDATE,		FILE_FMT_STR },
	{ XX("beqldate"),	FILE_BEQLDATE,		FILE_FMT_STR },
	{ XX("float"),		FILE_FLOAT,		FILE_FMT_FLOAT },
	{ XX("befloat"),	FILE_BEFLOAT,		FILE_FMT_FLOAT },
	{ XX("lefloat"),	FILE_LEFLOAT,		FILE_FMT_FLOAT },
	{ XX("double"),		FILE_DOUBLE,		FILE_FMT_DOUBLE },
	{ XX("bedouble"),	FILE_BEDOUBLE,		FILE_FMT_DOUBLE },
	{ XX("ledouble"),	FILE_LEDOUBLE,		FILE_FMT_DOUBLE },
	{ XX_NULL,		FILE_INVALID,		FILE_FMT_NONE },
# undef XX
# undef XX_NULL
};

static int get_type(const char *l, const char **t) {
	const struct type_tbl_s *p;

	for (p = type_tbl; p->len; p++) {
		if (strncmp (l, p->name, p->len) == 0) {
			if (t) *t = l + p->len;
			break;
		}
	}
	return p->type;
}

static void init_file_tables(void) {
	static int done = 0;
	const struct type_tbl_s *p;
	if (done) return;
	done++;
	for (p = type_tbl; p->len; p++) {
		assert(p->type < FILE_NAMES_SIZE);
		file_names[p->type] = p->name;
		file_formats[p->type] = p->format;
	}
}

/*
 * Handle one file or directory.
 */
static int apprentice_1(RMagic *ms, const char *fn, int action, struct mlist *mlist) {
	struct r_magic *magic = NULL;
	ut32 nmagic = 0;
	struct mlist *ml;
	int rv = -1;
	int mapped;

	if (!ms) return -1;
	ms->haderr = 0;
	if (magicsize != FILE_MAGICSIZE) {
		file_error(ms, 0, "magic element size %lu != %lu",
		    (unsigned long)(size_t)sizeof (*magic),
		    (unsigned long)FILE_MAGICSIZE);
		return -1;
	}

	ms->file = fn; // fix use of ms->file before being initialized
	if (action == FILE_COMPILE) {
		rv = apprentice_load (ms, &magic, &nmagic, fn, action);
		if (rv != 0)
			return -1;
		rv = apprentice_compile (ms, &magic, &nmagic, fn);
		free (magic);
		return rv;
	}

	if ((rv = apprentice_map (ms, &magic, &nmagic, fn)) == -1) {
		//if (ms->flags & R_MAGIC_CHECK)
		//	file_magwarn(ms, "using regular magic file `%s'", fn);
		rv = apprentice_load (ms, &magic, &nmagic, fn, action);
		if (rv != 0)
			return -1;
	}

	mapped = rv;

	if (magic == NULL) {
		file_delmagic (magic, mapped, nmagic);
		return -1;
	}

	if ((ml = malloc (sizeof (*ml))) == NULL) {
		file_delmagic (magic, mapped, nmagic);
		file_oomem (ms, sizeof(*ml));
		free (magic);
		return -1;
	}

	ml->magic = magic;
	ml->nmagic = nmagic;
	ml->mapped = mapped;

	mlist->prev->next = ml;
	ml->prev = mlist->prev;
	ml->next = mlist;
	mlist->prev = ml;
	return 0;
}

void file_delmagic(struct r_magic *p, int type, size_t entries) {
	if (p)
	switch (type) {
#ifdef QUICK
	case 2:
		p--;
		(void)munmap ((void *)p, sizeof(*p) * (entries + 1));
		break;
#endif
	case 1:
		p--;
		/*FALLTHROUGH*/
	case 0:
		free (p);
		break;
	default:
		abort ();
	}
}

/* const char *fn: list of magic files and directories */
struct mlist * file_apprentice(RMagic *ms, const char *fn, int action) {
	char *p, *mfn;
	int file_err, errs = -1;
	struct mlist *mlist;

	init_file_tables ();

	if (!fn) fn = getenv ("MAGIC");
	if (!fn) fn = MAGICFILE;

	if ((mfn = strdup (fn)) == NULL) {
		file_oomem (ms, strlen (fn));
		return NULL;
	}
	fn = mfn;

	if ((mlist = malloc (sizeof (*mlist))) == NULL) {
		free (mfn);
		file_oomem (ms, sizeof (*mlist));
		return NULL;
	}
	mlist->next = mlist->prev = mlist;

	while (fn) {
		p = strchr (fn, PATHSEP);
		if (p) *p++ = '\0';
		if (*fn == '\0') break;
		file_err = apprentice_1 (ms, fn, action, mlist);
		errs = R_MAX (errs, file_err);
		fn = p;
	}
	if (errs == -1) {
		free (mfn);
		free (mlist);
		mlist = NULL;
		file_error (ms, 0, "could not find any magic files!");
		return NULL;
	}
	free (mfn);
	return mlist;
}

/*
 * Get weight of this magic entry, for sorting purposes.
 */
static size_t apprentice_r_magic_strength(const struct r_magic *m) {
#define MULT 10
	size_t val = 2 * MULT;	/* baseline strength */

	switch (m->type) {
	case FILE_DEFAULT:	/* make sure this sorts last */
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
		val = 0;
		eprintf ("Bad type %d\n", m->type);
		abort();
	}

	switch (m->reln) {
	case 'x':	/* matches anything penalize */
	case '!':       /* matches almost anything penalize */
		val = 0;
		break;
	case '=':	/* Exact match, prefer */
		val += MULT;
		break;
	case '>':
	case '<':	/* comparison match reduce strength */
		val -= 2 * MULT;
		break;
	case '^':
	case '&':	/* masking bits, we could count them too */
		val -= MULT;
		break;
	default:
		eprintf ("Bad relation %c\n", m->reln);
		abort();
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
	if (sa == sb) return 0;
	if (sa > sb) return -1;
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
		if (file_looks_utf8 ((const ut8 *)m->value.s, m->vallen, NULL, NULL) == 0)
			mstart->flag |= BINTEST;
		break;
	case FILE_DEFAULT:
		/* can't deduce anything; we shouldn't see this at the
		   top level anyway */
		break;
	case FILE_INVALID:
	default:
		/* invalid search type, but no need to complain here */
		break;
	}
}

/*
 * Load and parse one file.
 */
static void load_1(RMagic *ms, int action, const char *file, int *errs, struct r_magic_entry **marray, ut32 *marraycount) {
	char line[BUFSIZ];
	size_t lineno = 0;
	FILE *f = r_sandbox_fopen (ms->file = file, "r");
	if (f == NULL) {
		if (errno != ENOENT)
			file_error (ms, errno, "cannot read magic file `%s'", file);
		(*errs)++;
	} else {
		/* read and parse this file */
		for (ms->line = 1; fgets (line, sizeof (line), f) != NULL; ms->line++) {
			size_t len = strlen (line);
			if (len == 0) /* null line, garbage, etc */
				continue;
			if (line[len - 1] == '\n') {
				lineno++;
				line[len - 1] = '\0'; /* delete newline */
			}
			if (line[0] == '\0')	/* empty, do not parse */
				continue;
			if (line[0] == '#')	/* comment, do not parse */
				continue;
			if (len > mime_marker_len &&
			    memcmp (line, mime_marker, mime_marker_len) == 0) {
				/* MIME type */
				if (parse_mime (ms, marray, marraycount,
					       line + mime_marker_len) != 0)
					(*errs)++;
				continue;
			}
			if (parse (ms, marray, marraycount, line, lineno, action) != 0)
				(*errs)++;
		}
		fclose (f);
	}
}

/*
 * parse a file or directory of files
 * const char *fn: name of magic file or directory
 */
static int apprentice_load(RMagic *ms, struct r_magic **magicp, ut32 *nmagicp, const char *fn, int action) {
	ut32 marraycount, i, mentrycount = 0, starttest;
	struct r_magic_entry *marray;
	char subfn[MAXPATHLEN];
	struct dirent *d;
	struct stat st;
	int errs = 0;
	DIR *dir;

	ms->flags |= R_MAGIC_CHECK;	/* Enable checks for parsed files */

        maxmagic = MAXMAGIS;
	if ((marray = calloc (maxmagic, sizeof(*marray))) == NULL) {
		file_oomem (ms, maxmagic * sizeof(*marray));
		return -1;
	}
	marraycount = 0;

	/* print silly verbose header for USG compat. */
	if (action == FILE_CHECK)
		eprintf ("%s\n", usg_hdr);

	/* load directory or file */
	if (stat (fn, &st) == 0 && S_ISDIR (st.st_mode)) {
		if (r_sandbox_enable (0) && !r_sandbox_check_path (fn)) {
			free (marray);
			return  -1;
		}
		dir = opendir (fn);
		if (dir) {
			while ((d = readdir (dir))) {
				if (*d->d_name=='.') continue;
				snprintf (subfn, sizeof (subfn), "%s/%s", fn, d->d_name);
				if (stat (subfn, &st) == 0 && S_ISREG (st.st_mode))
					load_1 (ms, action, subfn, &errs, &marray, &marraycount);
				//else perror (subfn);
			}
			closedir (dir);
		} else errs++;
	} else load_1 (ms, action, fn, &errs, &marray, &marraycount);
	if (errs)
		goto out;

	/* Set types of tests */
	for (i = 0; i < marraycount; ) {
		if (marray[i].mp->cont_level != 0) {
			i++;
			continue;
		}

		starttest = i;
		do {
			set_test_type(marray[starttest].mp, marray[i].mp);
			if (ms->flags & R_MAGIC_DEBUG) {
				(void)fprintf(stderr, "%s%s%s: %s\n",
					marray[i].mp->mimetype,
					marray[i].mp->mimetype[0] == '\0' ? "" : "; ",
					marray[i].mp->desc[0] ? marray[i].mp->desc : "(no description)",
					marray[i].mp->flag & BINTEST ? "binary" : "text");
				if (marray[i].mp->flag & BINTEST) {
#define SYMBOL "text"
#define SYMLEN sizeof(SYMBOL)
					char *p = strstr(marray[i].mp->desc, "text");
					if (p && (p == marray[i].mp->desc || isspace((unsigned char)p[-1])) &&
					    (p + SYMLEN - marray[i].mp->desc == MAXstring ||
					     (p[SYMLEN] == '\0' || isspace((unsigned char)p[SYMLEN])))) {
						(void)fprintf(stderr,
							      "*** Possible binary test for text type\n");
					}
#undef SYMBOL
#undef SYMLEN
				}
			}
		} while (++i < marraycount && marray[i].mp->cont_level != 0);
	}

	qsort (marray, marraycount, sizeof(*marray), apprentice_sort);

	/*
	 * Make sure that any level 0 "default" line is last (if one exists).
	 */
	for (i = 0; i < marraycount; i++) {
		if (marray[i].mp->cont_level == 0 &&
		    marray[i].mp->type == FILE_DEFAULT) {
			while (++i < marraycount)
				if (marray[i].mp->cont_level == 0)
					break;
			if (i != marraycount) {
				ms->line = marray[i].mp->lineno; /* XXX - Ugh! */
				file_magwarn (ms, "level 0 \"default\" did not sort last");
			}
			break;
		}
	}

	for (i = 0; i < marraycount; i++)
		mentrycount += marray[i].cont_count;

	if ((*magicp = malloc (1+(sizeof(**magicp) * mentrycount))) == NULL) {
		file_oomem (ms, sizeof(**magicp) * mentrycount);
		errs++;
		goto out;
	}

	mentrycount = 0;
	for (i = 0; i < marraycount; i++) {
		(void)memcpy (*magicp + mentrycount, marray[i].mp,
		    marray[i].cont_count * sizeof (**magicp));
		mentrycount += marray[i].cont_count;
	}
out:
	for (i = 0; i < marraycount; i++)
		free(marray[i].mp);
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
 * extend the sign bit if the comparison is to be signed
 */
ut64 file_signextend(RMagic *ms, struct r_magic *m, ut64 v) {
	if (!(m->flag & UNSIGNED)) {
		switch (m->type) {
		/*
		 * Do not remove the casts below.  They are
		 * vital.  When later compared with the data,
		 * the sign extension must have happened.
		 */
		case FILE_BYTE:
			v = (char) v;
			break;
		case FILE_SHORT:
		case FILE_BESHORT:
		case FILE_LESHORT:
			v = (short) v;
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
			v = (int32_t) v;
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
			v = (int64_t) v;
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
			if (ms->flags & R_MAGIC_CHECK)
			    file_magwarn(ms, "cannot happen: m->type=%d\n",
				    m->type);
			return ~0U;
		}
	}
	return v;
}

static int string_modifier_check(RMagic *ms, struct r_magic *m) {
	if ((ms->flags & R_MAGIC_CHECK) == 0)
		return 0;

	switch (m->type) {
	case FILE_BESTRING16:
	case FILE_LESTRING16:
		if (m->str_flags != 0) {
			file_magwarn(ms,
			    "no modifiers allowed for 16-bit strings\n");
			return -1;
		}
		break;
	case FILE_STRING:
	case FILE_PSTRING:
		if ((m->str_flags & REGEX_OFFSET_START) != 0) {
			file_magwarn(ms,
			    "'/%c' only allowed on regex and search\n",
			    CHAR_REGEX_OFFSET_START);
			return -1;
		}
		break;
	case FILE_SEARCH:
		if (m->str_range == 0) {
			file_magwarn(ms,
			    "missing range; defaulting to %d\n",
                            STRING_DEFAULT_RANGE);
			m->str_range = STRING_DEFAULT_RANGE;
			return -1;
		}
		break;
	case FILE_REGEX:
		if ((m->str_flags & STRING_COMPACT_BLANK) != 0) {
			file_magwarn(ms, "'/%c' not allowed on regex\n",
			    CHAR_COMPACT_BLANK);
			return -1;
		}
		if ((m->str_flags & STRING_COMPACT_OPTIONAL_BLANK) != 0) {
			file_magwarn(ms, "'/%c' not allowed on regex\n",
			    CHAR_COMPACT_OPTIONAL_BLANK);
			return -1;
		}
		break;
	default:
		file_magwarn (ms, "coding error: m->type=%d\n",
		    m->type);
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
	default:  return -1;
	}
}

static int get_cond(const char *l, const char **t) {
	const struct cond_tbl_s *p;
	static const struct cond_tbl_s {
		char name[8];
		size_t len;
		int cond;
	} cond_tbl[] = {
		{ "if",		2,	COND_IF },
		{ "elif",	4,	COND_ELIF },
		{ "else",	4,	COND_ELSE },
		{ "",		0,	COND_NONE },
	};

	for (p = cond_tbl; p->len; p++) {
		if (strncmp (l, p->name, p->len) == 0 &&
				isspace ((ut8)l[p->len])) {
			if (t) *t = l + p->len;
			break;
		}
	}
	return p->cond;
}

static int check_cond(RMagic *ms, int cond, ut32 cont_level) {
	int last_cond;
	last_cond = ms->c.li[cont_level].last_cond;

	switch (cond) {
	case COND_IF:
		if (last_cond != COND_NONE && last_cond != COND_ELIF) {
			if (ms->flags & R_MAGIC_CHECK)
				file_magwarn(ms, "syntax error: `if'");
			return -1;
		}
		last_cond = COND_IF;
		break;
	case COND_ELIF:
		if (last_cond != COND_IF && last_cond != COND_ELIF) {
			if (ms->flags & R_MAGIC_CHECK)
				file_magwarn(ms, "syntax error: `elif'");
			return -1;
		}
		last_cond = COND_ELIF;
		break;
	case COND_ELSE:
		if (last_cond != COND_IF && last_cond != COND_ELIF) {
			if (ms->flags & R_MAGIC_CHECK)
				file_magwarn(ms, "syntax error: `else'");
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

/*
 * parse one line from magic file, put into magic[index++] if valid
 */
static int parse(RMagic *ms, struct r_magic_entry **mentryp, ut32 *nmentryp, const char *line, size_t lineno, int action) {
	static ut32 last_cont_level = 0;
	size_t i;
	struct r_magic_entry *me;
	struct r_magic *m;
	const char *l = line;
	char *t;
	int op;
	ut32 cont_level = 0;

	for (; *l == '>'; l++, cont_level++);
	if (cont_level == 0 || cont_level > last_cont_level)
		if (file_check_mem (ms, cont_level) == -1)
			return -1;
	last_cont_level = cont_level;
#define ALLOC_CHUNK	(size_t)10
#define ALLOC_INCR	(size_t)200
	if (cont_level != 0) {
		if (*nmentryp == 0) {
			file_error(ms, 0, "No current entry for continuation");
			return -1;
		}
		me = &(*mentryp)[*nmentryp - 1];
		if (me->cont_count == me->max_count) {
			struct r_magic *nm;
			size_t cnt = me->max_count + ALLOC_CHUNK;
			if ((nm = realloc(me->mp, sizeof(*nm) * cnt)) == NULL) {
				file_oomem(ms, sizeof(*nm) * cnt);
				return -1;
			}
			me->mp = m = nm;
			me->max_count = cnt;
		}
		m = &me->mp[me->cont_count++];
		(void)memset(m, 0, sizeof(*m));
		m->cont_level = cont_level;
	} else {
		if (*nmentryp == maxmagic) {
			struct r_magic_entry *mp;

			maxmagic += ALLOC_INCR;
			if (!(mp = realloc (*mentryp, sizeof(*mp) * maxmagic))) {
				file_oomem (ms, sizeof(*mp) * maxmagic);
				return -1;
			}
			(void)memset(&mp[*nmentryp], 0, sizeof(*mp) *
			    ALLOC_INCR);
			*mentryp = mp;
		}
		me = &(*mentryp)[*nmentryp];
		if (me->mp == NULL) {
			if ((m = malloc(sizeof(*m) * ALLOC_CHUNK)) == NULL) {
				file_oomem(ms, sizeof(*m) * ALLOC_CHUNK);
				return -1;
			}
			me->mp = m;
			me->max_count = ALLOC_CHUNK;
		} else
			m = me->mp;
		(void)memset(m, 0, sizeof(*m));
		m->cont_level = 0;
		me->cont_count = 1;
	}
	m->lineno = lineno;

	if (*l == '&') {  /* m->cont_level == 0 checked below. */
                ++l;            /* step over */
                m->flag |= OFFADD;
        }
	if (*l == '(') {
		++l;		/* step over */
		m->flag |= INDIR;
		if (m->flag & OFFADD)
			m->flag = (m->flag & ~OFFADD) | INDIROFFADD;

		if (*l == '&') {  /* m->cont_level == 0 checked below */
			++l;            /* step over */
			m->flag |= OFFADD;
		}
	}
	/* Indirect offsets are not valid at level 0. */
	if (m->cont_level == 0 && (m->flag & (OFFADD | INDIROFFADD)))
		if (ms->flags & R_MAGIC_CHECK)
			file_magwarn(ms, "relative offset at level 0");

	/* get offset, then skip over it */
	m->offset = (ut32)strtoul(l, &t, 0);
        if ((l == t) && (ms->flags & R_MAGIC_CHECK))
		file_magwarn(ms, "offset `%s' invalid", l);
        l = t;

	if (m->flag & INDIR) {
		m->in_type = FILE_LONG;
		m->in_offset = 0;
		/*
		 * read [.lbs][+-]nnnnn)
		 */
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
				if (ms->flags & R_MAGIC_CHECK)
					file_magwarn(ms,
					    "indirect offset type `%c' invalid",
					    *l);
				break;
			}
			l++;
		}

		m->in_op = 0;
		if (*l == '~') {
			m->in_op |= FILE_OPINVERSE;
			l++;
		}
		if ((op = get_op(*l)) != -1) {
			m->in_op |= op;
			l++;
		}
		if (*l == '(') {
			m->in_op |= FILE_OPINDIRECT;
			l++;
		}
		if (isdigit((ut8)*l) || *l == '-') {
			m->in_offset = (int32_t)strtol(l, &t, 0);
			if (l == t)
				if (ms->flags & R_MAGIC_CHECK)
					file_magwarn(ms,
					    "in_offset `%s' invalid", l);
			l = t;
		}
		if (*l++ != ')' ||
		    ((m->in_op & FILE_OPINDIRECT) && *l++ != ')'))
			if (ms->flags & R_MAGIC_CHECK)
				file_magwarn(ms,
				    "missing ')' in indirect offset");
	}
	EATAB;

	m->cond = get_cond(l, &l);
	if (check_cond(ms, m->cond, cont_level) == -1)
		return -1;
	EATAB;

	if (*l == 'u') {
		++l;
		m->flag |= UNSIGNED;
	}

	m->type = get_type(l, &l);
	if (m->type == FILE_INVALID) {
		if (ms->flags & R_MAGIC_CHECK)
			file_magwarn(ms, "type `%s' invalid", l);
		return -1;
	}

	/* New-style anding: "0 byte&0x80 =0x80 dynamically linked" */
	/* New and improved: ~ & | ^ + - * / % -- exciting, isn't it? */

	m->mask_op = 0;
	if (*l == '~') {
		if (!MAGIC_IS_STRING (m->type))
			m->mask_op |= FILE_OPINVERSE;
		else if (ms->flags & R_MAGIC_CHECK)
			file_magwarn (ms, "'~' invalid for string types");
		++l;
	}
	m->str_range = 0;
	m->str_flags = 0;
	m->num_mask = 0;
	if ((op = get_op (*l)) != -1) {
		if (!MAGIC_IS_STRING (m->type)) {
			ut64 val;
			++l;
			m->mask_op |= op;
			val = (ut64)strtoull (l, &t, 0);
			l = t;
			m->num_mask = file_signextend (ms, m, val);
			eatsize (&l);
		}
		else if (op == FILE_OPDIVIDE) {
			int have_range = 0;
			while (!isspace ((ut8)*++l)) {
				switch (*l) {
				case '0':  case '1':  case '2':
				case '3':  case '4':  case '5':
				case '6':  case '7':  case '8':
				case '9':
					if (have_range &&
					    (ms->flags & R_MAGIC_CHECK))
						file_magwarn(ms,
						    "multiple ranges");
					have_range = 1;
					m->str_range = strtoul(l, &t, 0);
					if (m->str_range == 0)
						file_magwarn(ms,
						    "zero range");
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
					if (ms->flags & R_MAGIC_CHECK)
						file_magwarn(ms,
						"string extension `%c' invalid",
						*l);
					return -1;
				}
				/* allow multiple '/' for readability */
				if (l[1] == '/' && !isspace ((ut8)l[2]))
					l++;
			}
			if (string_modifier_check(ms, m) == -1)
				return -1;
		} else {
			if (ms->flags & R_MAGIC_CHECK)
				file_magwarn(ms, "invalid string op: %c", *t);
			return -1;
		}
	}
	/*
	 * We used to set mask to all 1's here, instead let's just not do
	 * anything if mask = 0 (unless you have a better idea)
	 */
	EATAB;

	switch (*l) {
	case '>':
	case '<':
	/* Old-style anding: "0 byte &0x80 dynamically linked" */
	case '&':
	case '^':
	case '=':
  		m->reln = *l;
  		++l;
		if (*l == '=') {
		   /* HP compat: ignore &= etc. */
		   ++l;
		}
		break;
	case '!':
		m->reln = *l;
		++l;
		break;
	default:
  		m->reln = '=';	/* the default relation */
		if (*l == 'x' && ((isascii((ut8)l[1]) &&
				isspace ((ut8)l[1])) || !l[1])) {
			m->reln = *l;
			++l;
		}
		break;
	}
	/*
	 * Grab the value part, except for an 'x' reln.
	 */
	if (m->reln != 'x' && getvalue (ms, m, &l, action))
		return -1;

	/*
	 * TODO finish this macro and start using it!
	 * #define offsetcheck {if (offset > HOWMANY-1)
	 *	magwarn("offset too big"); }
	 */

	/*
	 * Now get last part - the description
	 */
	EATAB;
	if (l[0] == '\b') {
		++l;
		m->flag |= NOSPACE;
	} else if ((l[0] == '\\') && (l[1] == 'b')) {
		++l;
		++l;
		m->flag |= NOSPACE;
	}
	for (i = 0; (m->desc[i++] = *l++) != '\0' && i < sizeof(m->desc); )
		continue;
	if (i == sizeof(m->desc)) {
		m->desc[sizeof(m->desc) - 1] = '\0';
		if (ms->flags & R_MAGIC_CHECK)
			file_magwarn(ms, "description `%s' truncated", m->desc);
	}

        /*
	 * We only do this check while compiling, or if any of the magic
	 * files were not compiled.
         */
        if (ms->flags & R_MAGIC_CHECK)
		if (check_format (ms, m) == -1)
			return -1;
	if (action == FILE_CHECK)
		file_mdump (m);
	m->mimetype[0] = '\0';		/* initialise MIME type to none */
	if (m->cont_level == 0)
		++(*nmentryp);		/* make room for next */
	return 0;
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
		file_error(ms, 0, "No current entry for MIME type");
		return -1;
	}

	me = &(*mentryp)[*nmentryp - 1];
	m = &me->mp[me->cont_count == 0 ? 0 : me->cont_count - 1];

	if (m->mimetype[0] != '\0') {
		file_error(ms, 0, "Current entry already has a MIME type: %s\n"
		    "Description: %s\nNew type: %s", m->mimetype, m->desc, l);
		return -1;
	}

	EATAB;
	for (i = 0;
	     *l && ((isascii((ut8)*l) && isalnum((ut8)*l))
	     || strchr("-+/.", *l)) && i < sizeof(m->mimetype);
	     m->mimetype[i++] = *l++)
		continue;
	if (i == sizeof(m->mimetype)) {
		m->desc[sizeof(m->mimetype) - 1] = '\0';
		if (ms->flags & R_MAGIC_CHECK)
			file_magwarn(ms, "MIME type `%s' truncated %zu",
			    m->mimetype, i);
	} else m->mimetype[i] = '\0';

	return (i>0)? 0: -1;
}

static int check_format_type(const char *ptr, int type) {
	int quad = 0;
	if (*ptr == '\0') {
		/* Missing format string; bad */
		return -1;
	}

	switch (type) {
	case FILE_FMT_QUAD:
		quad = 1;
		/*FALLTHROUGH*/
	case FILE_FMT_NUM:
		if (*ptr == '-')
			ptr++;
		if (*ptr == '.')
			ptr++;
		while (isdigit((ut8)*ptr)) ptr++;
		if (*ptr == '.')
			ptr++;
		while (isdigit((ut8)*ptr)) ptr++;
		if (quad) {
			if (*ptr++ != 'l') return -1;
			if (*ptr++ != 'l') return -1;
		}
		switch (*ptr++) {
		case 'l':
			switch (*ptr++) {
			case 'i':
			case 'd':
			case 'u':
			case 'x':
			case 'X':
				return 0;
			default:
				return -1;
			}
		case 'h':
			switch (*ptr++) {
			case 'h':
				switch (*ptr++) {
				case 'i':
				case 'd':
				case 'u':
				case 'x':
				case 'X':
					return 0;
				default:
					return -1;
				}
			case 'd':
				return 0;
			default:
				return -1;
			}
		case 'i':
		case 'c':
		case 'd':
		case 'u':
		case 'x':
		case 'X':
			return 0;
		default:
			return -1;
		}
	case FILE_FMT_FLOAT:
	case FILE_FMT_DOUBLE:
		if (*ptr == '-')
			ptr++;
		if (*ptr == '.')
			ptr++;
		while (isdigit ((ut8)*ptr)) ptr++;
		if (*ptr == '.')
			ptr++;
		while (isdigit ((ut8)*ptr)) ptr++;

		switch (*ptr++) {
		case 'e':
		case 'E':
		case 'f':
		case 'F':
		case 'g':
		case 'G':
			return 0;

		default:
			return -1;
		}
	case FILE_FMT_STR:
		if (*ptr == '-')
			ptr++;
		while (isdigit ((ut8 )*ptr))
			ptr++;
		if (*ptr == '.') {
			ptr++;
			while (isdigit ((ut8 )*ptr))
				ptr++;
		}

		if (*ptr++=='s')
			return 0;
		return -1;
	default:
		/* internal error */
		abort ();
	}
	/*NOTREACHED*/
	return -1;
}

/*
 * Check that the optional printf format in description matches
 * the type of the magic.
 */
static int check_format(RMagic *ms, struct r_magic *m) {
	char *ptr;

	for (ptr = m->desc; *ptr; ptr++)
		if (*ptr == '%')
			break;
	if (*ptr == '\0') {
		/* No format string; ok */
		return 1;
	}

	assert(file_nformats == file_nnames);

	if (m->type >= file_nformats) {
		file_magwarn(ms, "Internal error inconsistency between "
		    "m->type and format strings");
		return -1;
	}
	if (file_formats[m->type] == FILE_FMT_NONE) {
		file_magwarn(ms, "No format string for `%s' with description "
		    "`%s'", m->desc, file_names[m->type]);
		return -1;
	}

	ptr++;
	if (check_format_type(ptr, file_formats[m->type]) == -1) {
		/*
		 * TODO: this error message is unhelpful if the format
		 * string is not one character long
		 */
		file_magwarn(ms, "Printf format `%c' is not valid for type "
		    "`%s' in description `%s'",
		    ptr && *ptr ? *ptr : '?',
		    file_names[m->type], m->desc);
		return -1;
	}

	for (; *ptr; ptr++) {
		if (*ptr == '%') {
			file_magwarn (ms,
			    "Too many format strings (should have at most one) "
			    "for `%s' with description `%s'",
			    file_names[m->type], m->desc);
			return -1;
		}
	}
	return 0;
}

/*
 * Read a numeric value from a pointer, into the value union of a magic
 * pointer, according to the magic type.  Update the string pointer to point
 * just after the number read.  Return 0 for success, non-zero for failure.
 */
static int getvalue(RMagic *ms, struct r_magic *m, const char **p, int action) {
	int slen;

	switch (m->type) {
	case FILE_BESTRING16:
	case FILE_LESTRING16:
	case FILE_STRING:
	case FILE_PSTRING:
	case FILE_REGEX:
	case FILE_SEARCH:
		*p = getstr(ms, *p, m->value.s, sizeof(m->value.s), &slen, action);
		if (*p == NULL) {
			if (ms->flags & R_MAGIC_CHECK)
				file_magwarn(ms, "cannot get string from `%s'",
				    m->value.s);
			return -1;
		}
		m->vallen = slen;
		if (m->type == FILE_PSTRING)
			m->vallen++;
		return 0;
	case FILE_FLOAT:
	case FILE_BEFLOAT:
	case FILE_LEFLOAT:
		if (m->reln != 'x') {
			char *ep;
#ifdef HAVE_STRTOF
			m->value.f = strtof(*p, &ep);
#else
			m->value.f = (float)strtod(*p, &ep);
#endif
			*p = ep;
		}
		return 0;
	case FILE_DOUBLE:
	case FILE_BEDOUBLE:
	case FILE_LEDOUBLE:
		if (m->reln != 'x') {
			char *ep;
			m->value.d = strtod(*p, &ep);
			*p = ep;
		}
		return 0;
	default:
		if (m->reln != 'x') {
			char *ep;
			m->value.q = file_signextend(ms, m,
			    (ut64)strtoull(*p, &ep, 0));
			*p = ep;
			eatsize(p);
		}
		return 0;
	}
}

/*
 * Convert a string containing C character escapes.  Stop at an unescaped
 * space or tab.
 * Copy the converted version to "p", returning its length in *slen.
 * Return updated scan pointer as function result.
 */
static const char * getstr(RMagic *ms, const char *s, char *p, int plen, int *slen, int action) {
	const char *origs = s;
	char *origp = p;
	char *pmax = p + plen - 1;
	int c, val;

	while ((c = *s++) != '\0') {
		if (isspace ((ut8) c))
			break;
		if (p >= pmax) {
			file_error(ms, 0, "string too long: `%s'", origs);
			return NULL;
		}
		if (c == '\\') {
			switch ((c = *s++)) {
			case '\0':
				if (action == FILE_COMPILE)
					file_magwarn(ms, "incomplete escape");
				goto out;
			case '\t':
				if (action == FILE_COMPILE) {
					file_magwarn(ms,
					    "escaped tab found, use \\t instead");
					action++;
				}
				/*FALLTHROUGH*/
			default:
				if (action == FILE_COMPILE) {
					if (isprint((ut8)c))
					    file_magwarn(ms,
						"no need to escape `%c'", c);
					else
					    file_magwarn(ms,
						"unknown escape sequence: \\%03o", c);
				}
				/*FALLTHROUGH*/
			/* space, perhaps force people to use \040? */
			case ' ':
#if 0
			/*
			 * Other things people escape, but shouldn't need to,
			 * so we disallow them
			 */
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
				*p++ = (char) c;
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
				c = *s++;  /* try for 2 */
				if (c >= '0' && c <= '7') {
					val = (val << 3) | (c - '0');
					c = *s++;  /* try for 3 */
					if (c >= '0' && c <= '7')
						val = (val << 3) | (c-'0');
					else --s;
				} else --s;
				*p++ = (char)val;
				break;

			/* \x and up to 2 hex digits */
			case 'x':
				val = 'x';	/* Default if no digits */
				c = hextoint(*s++);	/* Get next char */
				if (c >= 0) {
					val = c;
					c = hextoint(*s++);
					if (c >= 0)
						val = (val << 4) + c;
					else --s;
				} else --s;
				*p++ = (char)val;
				break;
			}
		} else *p++ = (char)c;
	}
out:
	*p = '\0';
	*slen = p - origp;
	return s;
}


/* Single hex char to int; -1 if not a hex char. */
static int hextoint(int c) {
	if (!isascii ((ut8) c))
		return -1;
	if (isdigit ((ut8) c))
		return c - '0';
	if ((c >= 'a') && (c <= 'f'))
		return c + 10 - 'a';
	if (( c>= 'A') && (c <= 'F'))
		return c + 10 - 'A';
	return -1;
}


/*
 * Print a string containing C character escapes.
 */
void file_showstr(FILE *fp, const char *s, size_t len) {
	for (;;) {
		char c = *s++;
		if (len == ~0U) {
			if (c == '\0')
				break;
		} else {
			if (len-- == 0)
				break;
		}
		if (c >= 040 && c <= 0176)	/* TODO isprint && !iscntrl */
			fputc (c, fp);
		else {
			fputc ('\\', fp);
			switch (c) {
			case '\a': fputc('a', fp); break;
			case '\b': fputc('b', fp); break;
			case '\f': fputc('f', fp); break;
			case '\n': fputc('n', fp); break;
			case '\r': fputc('r', fp); break;
			case '\t': fputc('t', fp); break;
			case '\v': fputc('v', fp); break;
			default:   fprintf(fp, "%.3o", c & 0377); break;
			}
		}
	}
}

/*
 * eatsize(): Eat the size spec from a number [eg. 10UL]
 */
static void eatsize(const char **p) {
	const char *l = *p;

	if (LOWCASE (*l) == 'u')
		l++;

	switch (LOWCASE (*l)) {
	case 'l':    /* long */
	case 's':    /* short */
	case 'h':    /* short */
	case 'b':    /* char/byte */
	case 'c':    /* char/byte */
		l++;
		/*FALLTHROUGH*/
	default:
		break;
	}

	*p = l;
}

/*
 * handle a compiled file.
 */
static int apprentice_map(RMagic *ms, struct r_magic **magicp, ut32 *nmagicp, const char *fn) {
	int fd;
	struct stat st;
	ut32 *ptr;
	ut32 version;
	int needsbyteswap;
	char *dbname = NULL;
	void *mm = NULL;

	dbname = mkdbname (fn, 0);
	if (dbname == NULL)
		goto error2;

	if ((fd = r_sandbox_open (dbname, O_RDONLY|O_BINARY, 0)) == -1)
		goto error2;

	if (fstat(fd, &st) == -1) {
		file_error (ms, errno, "cannot stat `%s'", dbname);
		goto error1;
	}
	if (st.st_size < 8) {
		file_error (ms, 0, "file `%s' is too small", dbname);
		goto error1;
	}

#ifdef QUICK
	if ((mm = mmap (0, (size_t)st.st_size, PROT_READ, //OPENBSDBUG  |PROT_WRITE,
	    MAP_PRIVATE|MAP_FILE, fd, (off_t)0)) == MAP_FAILED) {
		file_error (ms, errno, "cannot map `%s'"); //, dbname);
		goto error1;
	}
#define RET	2
#else
	if ((mm = malloc ((size_t)st.st_size)) == NULL) {
		file_oomem(ms, (size_t)st.st_size);
		goto error1;
	}
	if (read (fd, mm, (size_t)st.st_size) != (size_t)st.st_size) {
		file_badread(ms);
		goto error1;
	}
#define RET	1
#endif
	*magicp = mm;
	(void)close (fd);
	fd = -1;
	ptr = (ut32 *)(void *)*magicp;

	if (*ptr != MAGICNO) {
		if (swap4(*ptr) != MAGICNO) {
		//OPENBSDBUG file_error(ms, 0, "bad magic in `%s'");
			file_error(ms, 0, "bad magic in `%s'", dbname);
			goto error1;
		}
		needsbyteswap = 1;
	} else needsbyteswap = 0;

	version = needsbyteswap? swap4(ptr[1]): ptr[1];
	if (version != VERSIONNO) {
		file_error(ms, 0, "File %d.%d supports only %d version magic "
		    "files. `%s' is version %d", FILE_VERSION_MAJOR, patchlevel,
		    VERSIONNO, dbname, version);
		goto error1;
	}
	*nmagicp = (ut32)(st.st_size / sizeof(struct r_magic));
	if (*nmagicp > 0)
		(*nmagicp)--;
	(*magicp)++;
	if (needsbyteswap)
		byteswap (*magicp, *nmagicp);
	free (dbname);
	return RET;

error1:
	if (fd != -1)
		(void)close (fd);
	if (mm) {
#ifdef QUICK
		(void)munmap((void *)mm, (size_t)st.st_size);
#else
		free(mm);
#endif
	} else {
		*magicp = NULL;
		*nmagicp = 0;
	}
error2:
	free (dbname);
	return -1;
}

static const ut32 ar[] = {
    MAGICNO, VERSIONNO
};

/*
 * handle an mmaped file.
 */
static int apprentice_compile(RMagic *ms, struct r_magic **magicp, ut32 *nmagicp, const char *fn) {
	int fd;
	char *dbname;
	int rv = -1;

	dbname = mkdbname(fn, 1);

	if (dbname == NULL) 
		goto out;

	if ((fd = r_sandbox_open(dbname, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0644)) == -1) {
		file_error(ms, errno, "cannot open `%s'", dbname);
		goto out;
	}

	if (write(fd, ar, sizeof(ar)) != (ssize_t)sizeof(ar)) {
		file_error(ms, errno, "error writing `%s'", dbname);
		goto beach;
	}

	if (lseek(fd, (off_t)sizeof(struct r_magic), SEEK_SET)
	    != sizeof(struct r_magic)) {
		file_error(ms, errno, "error seeking `%s'", dbname);
		goto beach;
	}

	if (write(fd, *magicp, (sizeof(struct r_magic) * *nmagicp))
	    != (ssize_t)(sizeof(struct r_magic) * *nmagicp)) {
		file_error(ms, errno, "error writing `%s'", dbname);
		goto beach;
	}

	rv = 0;
beach:
	(void)close(fd);
out:
	free(dbname);
	return rv;
}

static const char ext[] = ".mgc";
/*
 * make a dbname
 */
static char *mkdbname(const char *fn, int strip) {
	char *buf = NULL;
	int fnlen, extlen;
	if (strip) {
		const char *p;
		if ((p = strrchr(fn, '/')) != NULL)
			fn = ++p;
	}
	fnlen = strlen (fn);
	extlen = strlen (ext);
	if (fnlen + extlen + 1 > MAXPATHLEN) {
		return NULL;
	}
	buf = malloc (fnlen + extlen + 1);
	if (buf) {
		memcpy (buf, fn, fnlen);
		memcpy (buf+fnlen, ext, extlen);
		buf[fnlen+extlen] = 0;
	}
	return buf;
}

/*
 * Byteswap an mmap'ed file if needed
 */
static void byteswap(struct r_magic *magic, ut32 nmagic) {
	ut32 i;
	for (i = 0; i < nmagic; i++)
		bs1 (&magic[i]);
}

/*
 * swap a short
 */
static ut16 swap2(ut16 sv) {
	ut16 rv;
	ut8 *s = (ut8 *)(void *)&sv;
	ut8 *d = (ut8 *)(void *)&rv;
	d[0] = s[1];
	d[1] = s[0];
	return rv;
}

/*
 * swap an int
 */
static ut32 swap4(ut32 sv) {
	ut32 rv;
	ut8 *s = (ut8 *)(void *)&sv;
	ut8 *d = (ut8 *)(void *)&rv;
	d[0] = s[3];
	d[1] = s[2];
	d[2] = s[1];
	d[3] = s[0];
	return rv;
}

/*
 * swap a quad
 */
static ut64 swap8(ut64 sv) {
	ut64 rv;
	ut8 *s = (ut8 *)(void *)&sv;
	ut8 *d = (ut8 *)(void *)&rv;
#if 0
	d[0] = s[3];
	d[1] = s[2];
	d[2] = s[1];
	d[3] = s[0];
	d[4] = s[7];
	d[5] = s[6];
	d[6] = s[5];
	d[7] = s[4];
#else
	d[0] = s[7];
	d[1] = s[6];
	d[2] = s[5];
	d[3] = s[4];
	d[4] = s[3];
	d[5] = s[2];
	d[6] = s[1];
	d[7] = s[0];
#endif
	return rv;
}

/*
 * byteswap a single magic entry
 */
static void bs1(struct r_magic *m) {
	m->cont_level = swap2(m->cont_level);
	m->offset = swap4((ut32)m->offset);
	m->in_offset = swap4((ut32)m->in_offset);
	m->lineno = swap4((ut32)m->lineno);
	if (MAGIC_IS_STRING (m->type)) {
		m->str_range = swap4(m->str_range);
		m->str_flags = swap4(m->str_flags);
	} else {
		m->value.q = swap8(m->value.q);
		m->num_mask = swap8(m->num_mask);
	}
}
#endif

/*
 *  TCC - Tiny C Compiler
 *
 *  Copyright (c) 2001-2004 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "tcc.h"
#include <math.h>
/********************************************************/
/* global variables */

/* use Tiny C extensions */
/* additional informations about token */
#define TOK_FLAG_BOL   0x0001	/* beginning of line before */
#define TOK_FLAG_BOF   0x0002	/* beginning of file before */
#define TOK_FLAG_ENDIF 0x0004	/* a endif was found matching starting #ifdef */
#define TOK_FLAG_EOF   0x0008	/* end of file */

#define PARSE_FLAG_PREPROCESS 0x0001	/* activate preprocessing */
#define PARSE_FLAG_TOK_NUM    0x0002	/* return numbers instead of TOK_PPNUM */
#define PARSE_FLAG_LINEFEED   0x0004	/* line feed is returned as a
					token. line feed is also
					returned at eof */
#define PARSE_FLAG_ASM_COMMENTS 0x0008	/* '#' can be used for line comment */
#define PARSE_FLAG_SPACES     0x0010	/* next() returns space tokens (for -E) */

/* ------------------------------------------------------------------------- */


static const char tcc_keywords[] =
#define DEF(id, str) str "\0"
#include "tcctok.h"
#undef DEF
;

/* WARNING: the content of this string encodes token numbers */
static const ut8 tok_two_chars[] =
	"<=\236>=\235!=\225&&\240||\241++\244--\242==\224<<\1>>\2+=\253"
	"-=\255*=\252/=\257%=\245&=\246^=\336|=\374->\313..\250##\266";

struct macro_level {
	struct macro_level *prev;
	const int *p;
};

static void next_nomacro_spc(TCCState *s1);

static void macro_subst(
	TCCState *s1,
	TokenString *tok_str,
	Sym **nested_list,
	const int *macro_str,
	struct macro_level **can_read_stream
);

ST_FUNC void skip(TCCState *s1, int c) {
	if (s1->tok != c) {
		tcc_error (s1, "'%c' expected (got \"%s\")", c, get_tok_str (s1, s1->tok, &s1->tokc));
	}
	next (s1);
}

ST_FUNC void expect(TCCState *s1, const char *msg) {
	tcc_error (s1, "%s expected", msg);
}

/* ------------------------------------------------------------------------- */
/* CString handling */
static void cstr_realloc(CString *cstr, int new_size) {
	int size = cstr->size_allocated;
	if (size == 0) {
		size = 8;	/* no need to allocate a too small first string */
	}
	while (size < new_size) {
		size = size * 2;
	}
	void *data = realloc (cstr->data_allocated, size);
	if (!data) {
		eprintf ("Assert\n");
		return;
	}
	cstr->data_allocated = data;
	cstr->size_allocated = size;
	cstr->data = data;
}

/* add a byte */
ST_FUNC void cstr_ccat(CString *cstr, int ch) {
	int size;
	size = cstr->size + 1;
	if (size > cstr->size_allocated) {
		cstr_realloc (cstr, size);
	}
	((ut8 *) cstr->data)[size - 1] = ch;
	cstr->size = size;
}

ST_FUNC void cstr_cat(CString *cstr, const char *str) {
	int c;
	for (;;) {
		c = *str;
		if (c == '\0') {
			break;
		}
		cstr_ccat (cstr, c);
		str++;
	}
}

/* add a wide char */
ST_FUNC void cstr_wccat(CString *cstr, int ch) {
	int size;
	size = cstr->size + sizeof (nwchar_t);
	if (size > cstr->size_allocated) {
		cstr_realloc (cstr, size);
	}
	*(nwchar_t *) (((ut8 *) cstr->data) + size - sizeof (nwchar_t)) = ch;
	cstr->size = size;
}

ST_FUNC void cstr_new(CString *cstr) {
	memset (cstr, 0, sizeof (CString));
}

/* free string and reset it to NULL */
ST_FUNC void cstr_free(CString *cstr)
{
	free (cstr->data_allocated);
	cstr_new (cstr);
}

/* reset string to empty */
ST_FUNC void cstr_reset(CString *cstr)
{
	cstr->size = 0;
}

/* XXX: unicode ? */
static void add_char(CString *cstr, int c)
{
	if (c == '\'' || c == '\"' || c == '\\') {
		/* XXX: could be more precise if char or string */
		cstr_ccat (cstr, '\\');
	}
	if (c >= 32 && c <= 126) {
		cstr_ccat (cstr, c);
	} else {
		cstr_ccat (cstr, '\\');
		if (c == '\n') {
			cstr_ccat (cstr, 'n');
		} else {
			cstr_ccat (cstr, '0' + ((c >> 6) & 7));
			cstr_ccat (cstr, '0' + ((c >> 3) & 7));
			cstr_ccat (cstr, '0' + (c & 7));
		}
	}
}

/* ------------------------------------------------------------------------- */
/* allocate a new token */
static TokenSym *tok_alloc_new(TCCState *s1, TokenSym **pts, const char *str, int len) {
	TokenSym *ts, **ptable;

	if (s1->tok_ident >= SYM_FIRST_ANOM) {
		tcc_error (s1, "memory full");
	}

	/* expand token table if needed */
	int i = s1->tok_ident - TOK_IDENT;
	if ((i % TOK_ALLOC_INCR) == 0) {
		ptable = realloc (s1->table_ident, (i + TOK_ALLOC_INCR) * sizeof (TokenSym *));
		s1->table_ident = ptable;
	}
	ts = malloc (sizeof (TokenSym) + len);
	s1->table_ident[i] = ts;
	ts->tok = s1->tok_ident++;
	ts->sym_define = NULL;
	ts->sym_label = NULL;
	ts->sym_struct = NULL;
	ts->sym_identifier = NULL;
	ts->len = len;
	ts->hash_next = NULL;
	memcpy (ts->str, str, len);
	ts->str[len] = '\0';
	*pts = ts;
	return ts;
}

#define TOK_HASH_INIT 1
#define TOK_HASH_FUNC(h, c) ((h) * 263 + (c))

/* find a token and add it if not found */
ST_FUNC TokenSym *tok_alloc(TCCState *s1, const char *str, int len) {
	TokenSym *ts, **pts;
	int i;
	unsigned int h;

	h = TOK_HASH_INIT;
	for (i = 0; i < len; i++) {
		h = TOK_HASH_FUNC (h, ((ut8 *) str)[i]);
	}
	h &= (TOK_HASH_SIZE - 1);

	pts = &s1->hash_ident[h];
	for (;;) {
		ts = *pts;
		if (!ts) {
			break;
		}
		if (ts->len == len && !memcmp (ts->str, str, len)) {
			return ts;
		}
		pts = &(ts->hash_next);
	}
	return tok_alloc_new (s1, pts, str, len);
}

/* XXX: buffer overflow */
/* XXX: float tokens */
ST_FUNC char *get_tok_str(TCCState *s1, int v, CValue *cv) {
	static char buf[STRING_MAX_SIZE + 1];
	static CString cstr_buf;
	CString *cstr;
	char *p;
	int i, len;

	/* NOTE: to go faster, we give a fixed buffer for small strings */
	cstr_reset (&cstr_buf);
	cstr_buf.data = buf;
	cstr_buf.size_allocated = sizeof (buf);
	p = buf;

	switch (v) {
	case TOK_CINT:
	case TOK_CUINT:
		/* XXX: not quite exact, but only useful for testing */
		if (cv) {
			sprintf (p, "%u", cv->ui);
		}
		break;
	case TOK_CLLONG:
	case TOK_CULLONG:
		/* XXX: not quite exact, but only useful for testing  */
		if (cv) {
			sprintf (p, "%"PFMT64u, (ut64)cv->ull);
		}
		break;
	case TOK_LCHAR:
		cstr_ccat (&cstr_buf, 'L');
	case TOK_CCHAR:
		cstr_ccat (&cstr_buf, '\'');
		if (cv) {
			add_char (&cstr_buf, cv->i);
		}
		cstr_ccat (&cstr_buf, '\'');
		cstr_ccat (&cstr_buf, '\0');
		break;
	case TOK_PPNUM:
		// last crash this is handled in "td enum { FOO=1, BAR };"
		if (cv) {
			cstr = cv->cstr;
			len = cstr->size - 1;
		} else {
			len = 0;
		}
		for (i = 0; i < len; i++) {
			add_char (&cstr_buf, ((ut8 *) cstr->data)[i]);
		}
		cstr_ccat (&cstr_buf, '\0');
		break;
	case TOK_LSTR:
		cstr_ccat (&cstr_buf, 'L');
	case TOK_STR:
		if (cv) {
			cstr = cv->cstr;
			cstr_ccat (&cstr_buf, '\"');
			if (v == TOK_STR) {
				len = cstr->size - 1;
				for (i = 0; i < len; i++) {
					add_char (&cstr_buf, ((ut8 *) cstr->data)[i]);
				}
			} else {
				len = (cstr->size / sizeof (nwchar_t)) - 1;
				for (i = 0; i < len; i++) {
					add_char (&cstr_buf, ((nwchar_t *) cstr->data)[i]);
				}
			}
			cstr_ccat (&cstr_buf, '\"');
			cstr_ccat (&cstr_buf, '\0');
		} else {
			eprintf ("cv = nil\n");
		}
		break;
	case TOK_LT:
		v = '<';
		goto addv;
	case TOK_GT:
		v = '>';
		goto addv;
	case TOK_DOTS:
		return strcpy (p, "...");
	case TOK_A_SHL:
		return strcpy (p, "<<=");
	case TOK_A_SAR:
		return strcpy (p, ">>=");
	default:
		if (v < TOK_IDENT) {
			/* search in two bytes table */
			const ut8 *q = tok_two_chars;
			while (*q) {
				if (q[2] == v) {
					*p++ = q[0];
					*p++ = q[1];
					*p = '\0';
					return buf;
				}
				q += 3;
			}
addv:
			*p++ = v;
			*p = '\0';
		} else if (v < s1->tok_ident) {
			return s1->table_ident[v - TOK_IDENT]->str;
		} else if (v >= SYM_FIRST_ANOM) {
			/* special name for anonymous symbol */
			sprintf (p, "%u", v - SYM_FIRST_ANOM);
		} else {
			/* should never happen */
			return NULL;
		}
		break;
	}
	return cstr_buf.data;
}

/* fill input buffer and peek next char */
static int tcc_peekc_slow(TCCState *s1, BufferedFile *bf) {
	int len;
	/* only tries to read if really end of buffer */
	if (bf->buf_ptr >= bf->buf_end) {
		if (bf->fd != -1) {
#if defined(PARSE_DEBUG)
			len = 8;
#else
			len = IO_BUF_SIZE;
#endif
			len = read (bf->fd, bf->buffer, len);
			if (len < 0) {
				len = 0;
			}
		} else {
			len = 0;
		}
		s1->total_bytes += len;
		bf->buf_ptr = bf->buffer;
		bf->buf_end = bf->buffer + len;
		*bf->buf_end = CH_EOB;
	}
	if (bf->buf_ptr < bf->buf_end) {
		return bf->buf_ptr[0];
	}
	bf->buf_ptr = bf->buf_end;
	return CH_EOF;
}

/* return the current character, handling end of block if necessary
   (but not stray) */
ST_FUNC int handle_eob(TCCState *s1) {
	return tcc_peekc_slow (s1, s1->file);
}

/* read next char from current input s1->file and handle end of input buffer */
ST_INLN void inp(TCCState *s1) {
	s1->ch = *(++(s1->file->buf_ptr));
	/* end of buffer/s1->file handling */
	if (s1->ch == CH_EOB) {
		s1->ch = handle_eob (s1);
	}
}

/* handle '\[\r]\n' */
static int handle_stray_noerror(TCCState *s1) {
	while (s1->ch == '\\') {
		inp (s1);
		if (s1->ch == '\n') {
			s1->file->line_num++;
			inp (s1);
		} else if (s1->ch == '\r') {
			inp (s1);
			if (s1->ch != '\n') {
				goto fail;
			}
			s1->file->line_num++;
			inp (s1);
		} else {
fail:
			return 1;
		}
	}
	return 0;
}

static void handle_stray(TCCState *s1) {
	if (handle_stray_noerror (s1)) {
		tcc_error (s1, "stray '\\' in program");
	}
}

/* skip the stray and handle the \\n case. Output an error if
   incorrect char after the stray */
static int handle_stray1(TCCState *s1, uint8_t *p) {
	int c;

	if (p >= s1->file->buf_end) {
		s1->file->buf_ptr = p;
		c = handle_eob (s1);
		p = s1->file->buf_ptr;
		if (c == '\\') {
			goto parse_stray;
		}
	} else {
parse_stray:
		s1->file->buf_ptr = p;
		s1->ch = *p;
		handle_stray (s1);
		p = s1->file->buf_ptr;
		c = *p;
	}
	return c;
}

/* input with '\[\r]\n' handling. Note that this function cannot
   handle other characters after '\', so you cannot call it inside
   strings or comments */
static void minp(TCCState *s1) {
	inp (s1);
	if (s1->ch == '\\') {
		handle_stray (s1);
	}
}

/* handle just the EOB case, but not stray */
#define PEEKC_EOB(s1, c, p)			\
	{				\
		p++;			\
		c = *p;			\
		if (c == '\\') {	\
			s1->file->buf_ptr = p;\
			c = handle_eob (s1);\
			p = s1->file->buf_ptr;\
		}			\
	}

/* handle the complicated stray case */
#define PEEKC(s1, c, p)			\
	{				\
		p++;			\
		c = *p;			\
		if (c == '\\') {	\
			c = handle_stray1 (s1, p);\
			p = s1->file->buf_ptr;\
		}			\
	}


/* single line C++ comments */
static uint8_t *parse_line_comment(TCCState *s1, uint8_t *p) {
	int c;

	p++;
	for (;;) {
		c = *p;
redo:
		if (c == '\n' || c == CH_EOF) {
			break;
		} else if (c == '\\') {
			s1->file->buf_ptr = p;
			c = handle_eob (s1);
			p = s1->file->buf_ptr;
			if (c == '\\') {
				PEEKC_EOB (s1, c, p);
				if (c == '\n') {
					s1->file->line_num++;
					PEEKC_EOB (s1, c, p);
				} else if (c == '\r') {
					PEEKC_EOB (s1, c, p);
					if (c == '\n') {
						s1->file->line_num++;
						PEEKC_EOB (s1, c, p);
					}
				}
			} else {
				goto redo;
			}
		} else {
			p++;
		}
	}
	return p;
}

/* C comments */
ST_FUNC uint8_t *parse_comment(TCCState *s1, uint8_t *p) {
	int c;

	p++;
	for (;;) {
		/* fast skip loop */
		for (;;) {
			c = *p;
			if (c == '\n' || c == '*' || c == '\\') {
				break;
			}
			p++;
			c = *p;
			if (c == '\n' || c == '*' || c == '\\') {
				break;
			}
			p++;
		}
		/* now we can handle all the cases */
		if (c == '\n') {
			s1->file->line_num++;
			p++;
		} else if (c == '*') {
			p++;
			for (;;) {
				c = *p;
				if (c == '*') {
					p++;
				} else if (c == '/') {
					goto end_of_comment;
				} else if (c == '\\') {
					s1->file->buf_ptr = p;
					c = handle_eob (s1);
					p = s1->file->buf_ptr;
					if (c == '\\') {
						/* skip '\[\r]\n', otherwise just skip the stray */
						while (c == '\\') {
							PEEKC_EOB (s1, c, p);
							if (c == '\n') {
								s1->file->line_num++;
								PEEKC_EOB (s1, c, p);
							} else if (c == '\r') {
								PEEKC_EOB (s1, c, p);
								if (c == '\n') {
									s1->file->line_num++;
									PEEKC_EOB (s1, c, p);
								}
							} else {
								goto after_star;
							}
						}
					}
				} else {
					break;
				}
			}
after_star:
			;
		} else {
			/* stray, eob or eof */
			s1->file->buf_ptr = p;
			c = handle_eob (s1);
			p = s1->file->buf_ptr;
			if (c == CH_EOF) {
				tcc_error (s1, "unexpected end of file in comment");
			} else if (c == '\\') {
				p++;
			}
		}
	}
end_of_comment:
	p++;
	return p;
}

static inline void skip_spaces(TCCState *s1) {
	while (is_space (s1->ch)) {
		minp (s1);
	}
}

static inline int check_space(int t, int *spc) {
	if (is_space (t)) {
		if (*spc) {
			return 1;
		}
		*spc = 1;
	} else {
		*spc = 0;
	}
	return 0;
}

/* parse a string without interpreting escapes */
static uint8_t *parse_pp_string(TCCState *s1, uint8_t *p, int sep, CString *str) {
	int c;
	p++;
	while (tcc_nerr (s1) == 0) {
		c = *p;
		if (c == sep) {
			break;
		} else if (c == '\\') {
			s1->file->buf_ptr = p;
			c = handle_eob (s1);
			p = s1->file->buf_ptr;
			if (c == CH_EOF) {
unterminated_string:
				/* XXX: indicate line number of start of string */
				tcc_error (s1, "missing terminating %c character", sep);
				return NULL;
			} else if (c == '\\') {
				/* escape : just skip \[\r]\n */
				PEEKC_EOB (s1, c, p);
				if (c == '\n') {
					s1->file->line_num++;
					p++;
				} else if (c == '\r') {
					PEEKC_EOB (s1, c, p);
					if (c != '\n') {
						expect (s1, "'\n' after '\r'");
						return NULL;
					}
					s1->file->line_num++;
					p++;
				} else if (c == CH_EOF) {
					goto unterminated_string;
				} else {
					if (str) {
						cstr_ccat (str, '\\');
						cstr_ccat (str, c);
					}
					p++;
				}
			}
		} else if (c == '\n') {
			s1->file->line_num++;
			goto add_char;
		} else if (c == '\r') {
			PEEKC_EOB (s1, c, p);
			if (c != '\n') {
				if (str) {
					cstr_ccat (str, '\r');
				}
			} else {
				s1->file->line_num++;
				goto add_char;
			}
		} else {
add_char:
			if (str) {
				cstr_ccat (str, c);
			}
			p++;
		}
	}
	p++;
	return p;
}

/* skip block of text until #else, #elif or #endif. skip also pairs of
   #if/#endif */
static void preprocess_skip(TCCState *s1) {
	int a, start_of_line, c, in_warn_or_error;
	uint8_t *p;

	p = s1->file->buf_ptr;
	a = 0;
redo_start:
	start_of_line = 1;
	in_warn_or_error = 0;
	while (tcc_nerr (s1) == 0) {
redo_no_start:
		c = *p;
		switch (c) {
		case ' ':
		case '\t':
		case '\f':
		case '\v':
		case '\r':
			p++;
			goto redo_no_start;
		case '\n':
			s1->file->line_num++;
			p++;
			goto redo_start;
		case '\\':
			s1->file->buf_ptr = p;
			c = handle_eob (s1);
			if (c == CH_EOF) {
				expect (s1, "#endif");
				return;
			} else if (c == '\\') {
				s1->ch = s1->file->buf_ptr[0];
				handle_stray_noerror (s1);
			}
			p = s1->file->buf_ptr;
			goto redo_no_start;
		/* skip strings */
		case '\"':
		case '\'':
			if (in_warn_or_error) {
				goto _default;
			}
			p = parse_pp_string (s1, p, c, NULL);
			if (p == NULL) {
				return;
			}
			break;
		/* skip comments */
		case '/':
			if (in_warn_or_error) {
				goto _default;
			}
			s1->file->buf_ptr = p;
			s1->ch = *p;
			minp (s1);
			p = s1->file->buf_ptr;
			if (s1->ch == '*') {
				p = parse_comment (s1, p);
			} else if (s1->ch == '/') {
				p = parse_line_comment (s1, p);
			}
			break;
		case '#':
			p++;
			if (start_of_line) {
				s1->file->buf_ptr = p;
				next_nomacro (s1);
				p = s1->file->buf_ptr;
				if (a == 0 &&
				    (s1->tok == TOK_ELSE || s1->tok == TOK_ELIF || s1->tok == TOK_ENDIF)) {
					goto the_end;
				}
				if (s1->tok == TOK_IF || s1->tok == TOK_IFDEF || s1->tok == TOK_IFNDEF) {
					a++;
				} else if (s1->tok == TOK_ENDIF) {
					a--;
				} else if (s1->tok == TOK_ERROR || s1->tok == TOK_WARNING) {
					in_warn_or_error = 1;
				} else if (s1->tok == TOK_LINEFEED) {
					goto redo_start;
				}
			}
			break;
_default:
		default:
			p++;
			break;
		}
		start_of_line = 0;
	}
the_end:
	;
	s1->file->buf_ptr = p;
}

/* ParseState handling */

/* XXX: currently, no include file info is stored. Thus, we cannot display
   accurate messages if the function or data definition spans multiple
   files */

/* save current parse state in 's' */
ST_FUNC void save_parse_state(TCCState *s1, ParseState *s) {
	s->line_num = s1->file->line_num;
	s->macro_ptr = s1->macro_ptr;
	s->tok = s1->tok;
	s->tokc = s1->tokc;
}

/* restore parse state from 's'
ST_FUNC void restore_parse_state(ParseState *s)
{
	file->line_num = s->line_num;
	macro_ptr = s->macro_ptr;
	tok = s->tok;
	tokc = s->tokc;
}
*/

/* return the number of additional 'ints' necessary to store the
   token */
static inline int tok_ext_size(TCCState *s1, int t) {
	switch (t) {
	/* 4 bytes */
	case TOK_CINT:
	case TOK_CUINT:
	case TOK_CCHAR:
	case TOK_LCHAR:
	case TOK_CFLOAT:
	case TOK_LINENUM:
		return 1;
	case TOK_STR:
	case TOK_LSTR:
	case TOK_PPNUM:
		tcc_error (s1, "unsupported token");
		return 1;
	case TOK_CDOUBLE:
	case TOK_CLLONG:
	case TOK_CULLONG:
		return 2;
	case TOK_CLDOUBLE:
		return LDOUBLE_SIZE / 4;
	default:
		return 0;
	}
}

/* token string handling */

ST_INLN void tok_str_new(TokenString *s)
{
	s->str = NULL;
	s->len = 0;
	s->allocated_len = 0;
	s->last_line_num = -1;
}

ST_FUNC void tok_str_free(int *str)
{
	free (str);
}

static int *tok_str_realloc(TokenString *s)
{
	int *str, len;

	if (s->allocated_len == 0) {
		len = 8;
	} else {
		len = s->allocated_len * 2;
	}
	str = realloc (s->str, len * sizeof (int));
	s->allocated_len = len;
	s->str = str;
	return str;
}

ST_FUNC void tok_str_add(TCCState *s1, TokenString *s, int t) {
	int len, *str;

	len = s->len;
	str = s->str;
	if (len >= s->allocated_len) {
		str = tok_str_realloc (s);
	}
	str[len++] = t;
	s->len = len;
}

static void tok_str_add2(TokenString *s, int t, CValue *cv) {
	int len, *str;

	len = s->len;
	str = s->str;

	/* allocate space for worst case */
	if (len + TOK_MAX_SIZE > s->allocated_len) {
		str = tok_str_realloc (s);
	}
	str[len++] = t;
	switch (t) {
	case TOK_CINT:
	case TOK_CUINT:
	case TOK_CCHAR:
	case TOK_LCHAR:
	case TOK_CFLOAT:
	case TOK_LINENUM:
		str[len++] = cv->tab[0];
		break;
	case TOK_PPNUM:
	case TOK_STR:
	case TOK_LSTR:
	{
		int nb_words;

		nb_words = (sizeof (CString) + cv->cstr->size + 3) >> 2;
		while ((len + nb_words) > s->allocated_len) {
			str = tok_str_realloc (s);
		}
		CString cstr = {0};
		cstr.data = NULL;
		cstr.size = cv->cstr->size;
		cstr.data_allocated = NULL;
		cstr.size_allocated = cstr.size;

		ut8 *p = (ut8*)(str + len);
		memcpy (p, &cstr, sizeof (CString));
		memcpy (p + sizeof (CString),
			cv->cstr->data, cstr.size);
		len += nb_words;
	}
	break;
	case TOK_CDOUBLE:
	case TOK_CLLONG:
	case TOK_CULLONG:
#if LDOUBLE_SIZE == 8
	case TOK_CLDOUBLE:
#endif
		str[len++] = cv->tab[0];
		str[len++] = cv->tab[1];
		break;
#if LDOUBLE_SIZE == 12
	case TOK_CLDOUBLE:
		str[len++] = cv->tab[0];
		str[len++] = cv->tab[1];
		str[len++] = cv->tab[2];
#elif LDOUBLE_SIZE == 16
	case TOK_CLDOUBLE:
		str[len++] = cv->tab[0];
		str[len++] = cv->tab[1];
		str[len++] = cv->tab[2];
		str[len++] = cv->tab[3];
#elif LDOUBLE_SIZE != 8
#error add long double size support
#endif
		break;
	default:
		break;
	}
	s->len = len;
}

/* add the current parse token in token string 's' */
ST_FUNC void tok_str_add_tok(TCCState *s1, TokenString *s) {
	CValue cval;

	/* save line number info */
	if (s1->file->line_num != s->last_line_num) {
		s->last_line_num = s1->file->line_num;
		cval.i = s->last_line_num;
		tok_str_add2 (s, TOK_LINENUM, &cval);
	}
	tok_str_add2 (s, s1->tok, &s1->tokc);
}

/* get a token from an integer array and increment pointer
   accordingly. we code it as a macro to avoid pointer aliasing. */
static inline void TOK_GET(int *t, const int **pp, CValue *cv) {
	const int *p = *pp;
	int n, *tab;

	tab = cv->tab;
	switch (*t = *p++) {
	case TOK_CINT:
	case TOK_CUINT:
	case TOK_CCHAR:
	case TOK_LCHAR:
	case TOK_CFLOAT:
	case TOK_LINENUM:
		tab[0] = *p++;
		break;
	case TOK_STR:
	case TOK_LSTR:
	case TOK_PPNUM:
		cv->cstr = (CString *) p;
		cv->cstr->data = (char *) p + sizeof (CString);
		p += (sizeof (CString) + cv->cstr->size + 3) >> 2;
		break;
	case TOK_CDOUBLE:
	case TOK_CLLONG:
	case TOK_CULLONG:
		n = 2;
		goto copy;
	case TOK_CLDOUBLE:
#if LDOUBLE_SIZE == 16
		n = 4;
#elif LDOUBLE_SIZE == 12
		n = 3;
#elif LDOUBLE_SIZE == 8
		n = 2;
#else
#error add long double size support
#endif
copy:
		do {
			*tab++ = *p++;
		} while (--n);
		break;
	default:
		break;
	}
	*pp = p;
}

static int macro_is_equal(TCCState *s1, const int *a, const int *b) {
	char buf[STRING_MAX_SIZE + 1];
	CValue cv;
	int t;
	while (*a && *b) {
		TOK_GET (&t, &a, &cv);
		r_str_ncpy (buf, get_tok_str (s1, t, &cv), sizeof (buf));
		TOK_GET (&t, &b, &cv);
		if (strcmp (buf, get_tok_str (s1, t, &cv))) {
			return 0;
		}
	}
	return !(*a || *b);
}

/* defines handling */
ST_INLN void define_push(TCCState *s1, int v, int macro_type, int *str, Sym *first_arg) {
	Sym *s = define_find (s1, v);
	if (s && !macro_is_equal (s1, s->d, str)) {
		tcc_warning (s1, "%s redefined", get_tok_str (s1, v, NULL));
	}

	s = sym_push2 (s1, &s1->define_stack, v, macro_type, 0);
	if (!s) {
		return;
	}
	s->d = str;
	s->next = first_arg;
	if (v >= TOK_IDENT) {
		s1->table_ident[v - TOK_IDENT]->sym_define = s;
	}
}

/* undefined a define symbol. Its name is just set to zero */
ST_FUNC void define_undef(TCCState *s1, Sym *s) {
	int v = s->v;
	if (v >= TOK_IDENT && v < s1->tok_ident) {
		s1->table_ident[v - TOK_IDENT]->sym_define = NULL;
	}
	s->v = 0;
}

ST_INLN Sym *define_find(TCCState *s1, int v) {
	v -= TOK_IDENT;
	if ((unsigned) v >= (unsigned) (s1->tok_ident - TOK_IDENT)) {
		return NULL;
	}
	return s1->table_ident[v]->sym_define;
}

/* free define stack until top reaches 'b' */
ST_FUNC void free_defines(TCCState *s1, Sym *b) {
	Sym *top, *top1;
	int v;

	top = s1->define_stack;
	while (top != b) {
		top1 = top->prev;
		/* do not free args or predefined defines */
		if (top->d) {
			tok_str_free (top->d);
		}
		v = top->v;
		if (v >= TOK_IDENT && v < s1->tok_ident) {
			s1->table_ident[v - TOK_IDENT]->sym_define = NULL;
		}
		sym_free (s1, top);
		top = top1;
	}
	s1->define_stack = b;
}


/* eval an expression for #if/#elif */
static int expr_preprocess(TCCState *s1)
{
	int c, t;
	TokenString str;

	tok_str_new (&str);
	while (s1->tok != TOK_LINEFEED && s1->tok != TOK_EOF) {
		next (s1);/* do macro subst */
		if (s1->tok == TOK_DEFINED) {
			next_nomacro (s1);
			t = s1->tok;
			if (t == '(') {
				next_nomacro (s1);
			}
			c = define_find (s1, s1->tok) != 0;
			if (t == '(') {
				next_nomacro (s1);
			}
			s1->tok = TOK_CINT;
			s1->tokc.i = c;
		} else if (s1->tok >= TOK_IDENT) {
			/* if undefined macro */
			s1->tok = TOK_CINT;
			s1->tokc.i = 0;
		}
		tok_str_add_tok (s1, &str);
	}
	tok_str_add (s1, &str, -1);	/* simulate end of file */
	tok_str_add (s1, &str, 0);
	/* now evaluate C constant expression */
	s1->macro_ptr = str.str;
	next (s1);
	c = expr_const (s1);
	s1->macro_ptr = NULL;
	tok_str_free (str.str);
	return c != 0;
}

#if defined(PARSE_DEBUG) || defined(PP_DEBUG)
static void tok_print(int *str) {
	int t;
	CValue cval;

	printf ("<");
	while (1) {
		TOK_GET (&t, &str, &cval);
		if (!t) {
			break;
		}
		printf ("%s", get_tok_str (s1, t, &cval));
	}
	printf (">\n");
}
#endif

/* parse after #define */
static void parse_define(TCCState *s1) {
	Sym *s, *first, **ps;
	int t, varg, is_vaargs, spc;
	TokenString str;

	int v = s1->tok;
	if (v < TOK_IDENT) {
		tcc_error (s1, "invalid macro name '%s'", get_tok_str (s1, s1->tok, &s1->tokc));
	}
	/* XXX: should check if same macro (ANSI) */
	first = NULL;
	t = MACRO_OBJ;
	/* '(' must be just after macro definition for MACRO_FUNC */
	next_nomacro_spc (s1);
	if (s1->tok == '(') {
		next_nomacro (s1);
		ps = &first;
		while (s1->tok != ')') {
			varg = s1->tok;
			next_nomacro (s1);
			is_vaargs = 0;
			if (varg == TOK_DOTS) {
				varg = TOK___VA_ARGS__;
				is_vaargs = 1;
			} else if (s1->tok == TOK_DOTS && gnu_ext) {
				is_vaargs = 1;
				next_nomacro (s1);
			}
			if (varg < TOK_IDENT) {
				tcc_error (s1, "badly punctuated parameter list");
			}
			s = sym_push2 (s1, &s1->define_stack, varg | SYM_FIELD, is_vaargs, 0);
			if (!s) {
				return;
			}
			*ps = s;
			ps = &s->next;
			if (s1->tok != ',') {
				break;
			}
			next_nomacro (s1);
		}
		if (s1->tok == ')') {
			next_nomacro_spc (s1);
		}
		t = MACRO_FUNC;
	}
	tok_str_new (&str);
	spc = 2;
	/* EOF testing necessary for '-D' handling */
	while (s1->tok != TOK_LINEFEED && s1->tok != TOK_EOF) {
		/* remove spaces around ## and after '#' */
		if (TOK_TWOSHARPS == s1->tok) {
			if (1 == spc) {
				--str.len;
			}
			spc = 2;
		} else if ('#' == s1->tok) {
			spc = 2;
		} else if (check_space (s1->tok, &spc)) {
			goto skip;
		}
		tok_str_add2 (&str, s1->tok, &s1->tokc);
skip:
		next_nomacro_spc (s1);
	}
	if (spc == 1) {
		--str.len;	/* remove trailing space */
	}
	tok_str_add (s1, &str, 0);
#ifdef PP_DEBUG
	printf ("define %s %d: ", get_tok_str (s1, v, NULL), t);
	tok_print (str.str);
#endif
	define_push (s1, v, t, str.str, first);
}

static inline int hash_cached_include(const char *filename) {
	unsigned int h = TOK_HASH_INIT;
	const ut8 *s = (const ut8 *) filename;
	while (*s) {
		h = TOK_HASH_FUNC (h, *s);
		s++;
	}
	h &= (CACHED_INCLUDES_HASH_SIZE - 1);
	return h;
}

static CachedInclude *search_cached_include(TCCState *s1, const char *filename) {
	CachedInclude *e;
	int i, h;
	h = hash_cached_include (filename);
	i = s1->cached_includes_hash[h];
	for (;;) {
		if (i == 0) {
			break;
		}
		e = s1->cached_includes[i - 1];
		if (0 == PATHCMP (e->filename, filename)) {
			return e;
		}
		i = e->hash_next;
	}
	return NULL;
}

static inline void add_cached_include(TCCState *s1, const char *filename, int ifndef_macro)
{
	CachedInclude *e;
	int h;

	if (search_cached_include (s1, filename)) {
		return;
	}
#ifdef INC_DEBUG
	printf ("adding cached '%s' %s\n", filename, get_tok_str (s1, ifndef_macro, NULL));
#endif
	e = malloc (sizeof (CachedInclude) + strlen (filename));
	strcpy (e->filename, filename);
	e->ifndef_macro = ifndef_macro;
	dynarray_add ((void ***) &s1->cached_includes, &s1->nb_cached_includes, e);
	/* add in hash table */
	h = hash_cached_include (filename);
	e->hash_next = s1->cached_includes_hash[h];
	s1->cached_includes_hash[h] = s1->nb_cached_includes;
}

static void pragma_parse(TCCState *s1) {
	int val;

	next (s1);
	if (s1->tok == TOK_pack) {
		/*
		  This may be:
		  #pragma pack(1) // set
		  #pragma pack() // reset to default
		  #pragma pack(push,1) // push & set
		  #pragma pack(pop) // restore previous
		*/
		next (s1);
		skip (s1, '(');
		if (s1->tok == TOK_ASM_pop) {
			next (s1);
			if (s1->pack_stack_ptr <= s1->pack_stack) {
stk_error:
				tcc_error (s1, "out of pack stack");
			}
			s1->pack_stack_ptr--;
		} else {
			val = 0;
			if (s1->tok != ')') {
				if (s1->tok == TOK_ASM_push) {
					next (s1);
					if (s1->pack_stack_ptr >= s1->pack_stack + PACK_STACK_SIZE - 1) {
						goto stk_error;
					}
					s1->pack_stack_ptr++;
					skip (s1, ',');
				}
				if (s1->tok != TOK_CINT) {
pack_error:
					tcc_error (s1, "invalid pack pragma");
				}
				val = s1->tokc.i;
				if (val < 1 || val > 16 || (val & (val - 1)) != 0) {
					goto pack_error;
				}
				next (s1);
			}
			*s1->pack_stack_ptr = val;
			skip (s1, ')');
		}
	}
}

/* is_bof is true if first non space token at beginning of file */
ST_FUNC void preprocess(TCCState *s1, bool is_bof) {
	int i, c, n, saved_parse_flags;
	char buf[1024], *q;
	Sym *s;

	saved_parse_flags = s1->parse_flags;
	s1->parse_flags = PARSE_FLAG_PREPROCESS | PARSE_FLAG_TOK_NUM |
		      PARSE_FLAG_LINEFEED;
	next_nomacro (s1);
redo:
	switch (s1->tok) {
	case TOK_DEFINE:
		next_nomacro (s1);
		parse_define (s1);
		break;
	case TOK_UNDEF:
		next_nomacro (s1);
		s = define_find (s1, s1->tok);
		/* undefine symbol by putting an invalid name */
		if (s) {
			define_undef (s1, s);
		}
		break;
	case TOK_INCLUDE:
	case TOK_INCLUDE_NEXT:
		s1->ch = s1->file->buf_ptr[0];
		/* XXX: incorrect if comments : use next_nomacro with a special mode */
		skip_spaces (s1);
		if (s1->ch == '<') {
			c = '>';
			goto read_name;
		} else if (s1->ch == '\"') {
			c = s1->ch;
read_name:
			inp (s1);
			q = buf;
			while (s1->ch != c && s1->ch != '\n' && s1->ch != CH_EOF) {
				if ((q - buf) < sizeof (buf) - 1) {
					*q++ = s1->ch;
				}
				if (s1->ch == '\\') {
					if (handle_stray_noerror (s1) == 0) {
						q--;
					}
				} else {
					inp (s1);
				}
			}
			*q = '\0';
			minp (s1);
#if 0
			/* eat all spaces and comments after include */
			/* XXX: slightly incorrect */
			while (ch1 != '\n' && ch1 != CH_EOF)
				inp ();
#endif
		} else {
			/* computed #include : either we have only strings or
			   we have anything enclosed in '<>' */
			next (s1);
			buf[0] = '\0';
			if (s1->tok == TOK_STR) {
				while (s1->tok != TOK_LINEFEED) {
					if (s1->tok != TOK_STR) {
include_syntax:
						tcc_error (s1, "'#include' expects \"FILENAME\" or <FILENAME>");
					}
					pstrcat (buf, sizeof (buf), (char *) s1->tokc.cstr->data);
					next (s1);
				}
				c = '\"';
			} else {
				int len;
				while (s1->tok != TOK_LINEFEED) {
					pstrcat (buf, sizeof (buf), get_tok_str (s1, s1->tok, &s1->tokc));
					next (s1);
				}
				len = strlen (buf);
				/* check syntax and remove '<>' */
				if (len < 2 || buf[0] != '<' || buf[len - 1] != '>') {
					goto include_syntax;
				}
				memmove (buf, buf + 1, len - 2);
				buf[len - 2] = '\0';
				c = '>';
			}
		}

		if (s1->include_stack_ptr >= s1->include_stack + INCLUDE_STACK_SIZE) {
			tcc_error (s1, "#include recursion too deep");
		}
		/* store current file in stack, but increment stack later below */
		*s1->include_stack_ptr = s1->file;

		n = s1->nb_include_paths + s1->nb_sysinclude_paths;
		for (i = -2; i < n; i++) {
			char buf1[sizeof s1->file->filename];
			CachedInclude *e;
			BufferedFile **f;
			const char *path;

			if (i == -2) {
				/* check absolute include path */
				if (!IS_ABSPATH (buf)) {
					continue;
				}
				buf1[0] = 0;
				i = n;	/* force end loop */

			} else if (i == -1) {
				/* search in current dir if "header.h" */
				if (c != '\"') {
					continue;
				}
				path = s1->file->filename;
				pstrncpy (buf1, path, tcc_basename (path) - path);

			} else {
				/* search in all the include paths */
				if (i < s1->nb_include_paths) {
					path = s1->include_paths[i];
				} else {
					path = s1->sysinclude_paths[i - s1->nb_include_paths];
				}
				r_str_ncpy (buf1, path, sizeof (buf1));
				pstrcat (buf1, sizeof (buf1), "/");
			}

			pstrcat (buf1, sizeof (buf1), buf);

			if (s1->tok == TOK_INCLUDE_NEXT) {
				for (f = s1->include_stack_ptr; f >= s1->include_stack; f--) {
					if (0 == PATHCMP ((*f)->filename, buf1)) {
#ifdef INC_DEBUG
						printf ("%s: #include_next skipping %s\n", s1->file->filename, buf1);
#endif
						goto include_trynext;
					}
				}
			}

			e = search_cached_include (s1, buf1);
			if (e && define_find (s1, e->ifndef_macro)) {
				/* no need to parse the include because the 'ifndef macro'
				   is defined */
#ifdef INC_DEBUG
				printf ("%s: skipping cached %s\n", s1->file->filename, buf1);
#endif
				goto include_done;
			}

			bool skip = false;
			if (strstr (buf1, "_overflow.h")) {
				skip = true;
			}
			if (!skip && tcc_open (s1, buf1) < 0) {
include_trynext:
				continue;
			}
			eprintf ("#include \"%s\"\n", buf1);

#ifdef INC_DEBUG
			eprintf ("%s: including %s\n", s1->file->prev->filename, s1->file->filename);
#endif
			/* update target deps */
			dynarray_add ((void ***) &s1->target_deps, &s1->nb_target_deps,
				strdup (buf1));
			/* push current file in stack */
			s1->include_stack_ptr++;
			s1->tok_flags |= TOK_FLAG_BOF | TOK_FLAG_BOL;
			s1->ch = s1->file->buf_ptr[0];
			goto the_end;
		}
		/* load include file from the same directory as the parent */
		{
			char filepath[1024];
			int filepath_len;
			char *e = s1->file->filename + strlen (s1->file->filename);
			while (e > s1->file->filename) {
				if (*e == R_SYS_DIR[0]) {
					break;
				}
				e--;
			}
			filepath_len = R_MIN ((size_t) (e - s1->file->filename) + 1, sizeof (filepath) - 1);
			memcpy (filepath, s1->file->filename, filepath_len);
			strcpy (filepath + filepath_len, buf);
			bool skip = false;
			if (strstr (s1->file->filename, "_overflow.h")) {
				skip = true;
			}
			if (!skip && tcc_open (s1, filepath) < 0) {
				if (!s1->dir_name) {
					s1->dir_name = ".";
				}
				int len = snprintf (filepath, sizeof (filepath), "%s/%s", s1->dir_name, buf);
				if (len >= sizeof (filepath) || tcc_open (s1, filepath) < 0) {
					eprintf ("include file '%s' not found\n", filepath);
					goto the_end;
				} else {
					eprintf ("#include \"%s\"\n", filepath);
					s1->include_stack_ptr++;
					s1->tok_flags |= TOK_FLAG_BOF | TOK_FLAG_BOL;
					s1->ch = s1->file->buf_ptr[0];
					goto the_end;
				}
			} else {
				eprintf ("#include \"%s\"\n", filepath);
				s1->include_stack_ptr++;
				s1->tok_flags |= TOK_FLAG_BOF | TOK_FLAG_BOL;
				s1->ch = s1->file->buf_ptr[0];
				goto the_end;
			}
		}
include_done:
		break;
	case TOK_IFNDEF:
		c = 1;
		goto do_ifdef;
	case TOK_IF:
		c = expr_preprocess (s1);
		goto do_if;
	case TOK_IFDEF:
		c = 0;
do_ifdef:
		next_nomacro (s1);
		if (s1->tok < TOK_IDENT) {
			tcc_error (s1, "invalid argument for '#if%sdef'", c? "n": "");
		}
		if (is_bof) {
			if (c) {
#ifdef INC_DEBUG
				printf ("#ifndef %s\n", get_tok_str (s1, s1->tok, NULL));
#endif
				s1->file->ifndef_macro = s1->tok;
			}
		}
		c = (define_find (s1, s1->tok) != 0) ^ c;
do_if:
		if (s1->ifdef_stack_ptr >= s1->ifdef_stack + IFDEF_STACK_SIZE) {
			tcc_error (s1, "memory full");
		}
		*s1->ifdef_stack_ptr++ = c;
		goto test_skip;
	case TOK_ELSE:
		if (s1->ifdef_stack_ptr == s1->ifdef_stack) {
			tcc_error (s1, "#else without matching #if");
		}
		if (s1->ifdef_stack_ptr[-1] & 2) {
			tcc_error (s1, "#else after #else");
		}
		c = (s1->ifdef_stack_ptr[-1] ^= 3);
		goto test_else;
	case TOK_ELIF:
		if (s1->ifdef_stack_ptr == s1->ifdef_stack) {
			tcc_error (s1, "#elif without matching #if");
		}
		c = s1->ifdef_stack_ptr[-1];
		if (c > 1) {
			tcc_error (s1, "#elif after #else");
		}
		/* last #if/#elif expression was true: we skip */
		if (c == 1) {
			goto skip;
		}
		c = expr_preprocess (s1);
		s1->ifdef_stack_ptr[-1] = c;
test_else:
		if (s1->ifdef_stack_ptr == s1->file->ifdef_stack_ptr + 1) {
			s1->file->ifndef_macro = 0;
		}
test_skip:
		if (!(c & 1)) {
skip:
			preprocess_skip (s1);
			is_bof = 0;
			goto redo;
		}
		break;
	case TOK_ENDIF:
		if (s1->ifdef_stack_ptr <= s1->file->ifdef_stack_ptr) {
			tcc_error (s1, "#endif without matching #if");
		}
		s1->ifdef_stack_ptr--;
		/* '#ifndef macro' was at the start of file. Now we check if
		   an '#endif' is exactly at the end of file */
		if (s1->file->ifndef_macro &&
		    s1->ifdef_stack_ptr == s1->file->ifdef_stack_ptr) {
			s1->file->ifndef_macro_saved = s1->file->ifndef_macro;
			/* need to set to zero to avoid false matches if another
			   #ifndef at middle of file */
			s1->file->ifndef_macro = 0;
			while (s1->tok != TOK_LINEFEED) {
				next_nomacro (s1);
			}
			s1->tok_flags |= TOK_FLAG_ENDIF;
			goto the_end;
		}
		break;
	case TOK_LINE:
		next (s1);
		if (s1->tok != TOK_CINT) {
			tcc_error (s1, "#line");
		}
		s1->file->line_num = s1->tokc.i - 1;	/* the line number will be incremented after */
		next (s1);
		if (s1->tok != TOK_LINEFEED) {
			if (s1->tok != TOK_STR) {
				tcc_error (s1, "#line");
			}
			r_str_ncpy (s1->file->filename, (char *) s1->tokc.cstr->data, sizeof (s1->file->filename));
		}
		break;
	case TOK_ERROR:
	case TOK_WARNING:
		c = s1->tok;
		s1->ch = s1->file->buf_ptr[0];
		skip_spaces (s1);
		q = buf;
		while (s1->ch != '\n' && s1->ch != CH_EOF) {
			if ((q - buf) < sizeof (buf) - 1) {
				*q++ = s1->ch;
			}
			if (s1->ch == '\\') {
				if (handle_stray_noerror (s1) == 0) {
					q--;
				}
			} else {
				inp (s1);
			}
		}
		*q = '\0';
		tcc_warning (s1, "#%s %s", c == TOK_ERROR? "error": "warning", buf);
		break;
	case TOK_PRAGMA:
		pragma_parse (s1);
		break;
	default:
		if (s1->tok == TOK_LINEFEED || s1->tok == '!' || s1->tok == TOK_PPNUM) {
			/* '!' is ignored to allow C scripts. numbers are ignored
			   to emulate cpp behaviour */
		} else {
			if (!(saved_parse_flags & PARSE_FLAG_ASM_COMMENTS)) {
				tcc_warning (s1, "Ignoring unknown preprocessing directive #%s", get_tok_str (s1, s1->tok, &s1->tokc));
			} else {
				/* this is a gas line comment in an 'S' file. */
				s1->file->buf_ptr = parse_line_comment (s1, s1->file->buf_ptr);
				goto the_end;
			}
		}
		break;
	}
	/* ignore other preprocess commands or #! for C scripts */
	while (s1->tok != TOK_LINEFEED) {
		next_nomacro (s1);
	}
the_end:
	s1->parse_flags = saved_parse_flags;
}

/* evaluate escape codes in a string. */
static void parse_escape_string(TCCState *s1, CString *outstr, const uint8_t *buf, int is_long) {
	int c, n;
	const uint8_t *p;

	p = buf;
	for (;;) {
		c = *p;
		if (c == '\0') {
			break;
		}
		if (c == '\\') {
			p++;
			/* escape */
			c = *p;
			switch (c) {
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
				/* at most three octal digits */
				n = c - '0';
				p++;
				c = *p;
				if (isoct (c)) {
					n = n * 8 + c - '0';
					p++;
					c = *p;
					if (isoct (c)) {
						n = n * 8 + c - '0';
						p++;
					}
				}
				c = n;
				goto add_char_nonext;
			case 'x':
			case 'u':
			case 'U':
				p++;
				n = 0;
				for (;;) {
					c = *p;
					if (c >= 'a' && c <= 'f') {
						c = c - 'a' + 10;
					} else if (c >= 'A' && c <= 'F') {
						c = c - 'A' + 10;
					} else if (isnum (c)) {
						c = c - '0';
					} else {
						break;
					}
					n = n * 16 + c;
					p++;
				}
				c = n;
				goto add_char_nonext;
			case 'a':
				c = '\a';
				break;
			case 'b':
				c = '\b';
				break;
			case 'f':
				c = '\f';
				break;
			case 'n':
				c = '\n';
				break;
			case 'r':
				c = '\r';
				break;
			case 't':
				c = '\t';
				break;
			case 'v':
				c = '\v';
				break;
			case 'e':
				if (!gnu_ext) {
					goto invalid_escape;
				}
				c = 27;
				break;
			case '\'':
			case '\"':
			case '\\':
			case '?':
				break;
			default:
invalid_escape:
				if (c >= '!' && c <= '~') {
					tcc_warning (s1, "unknown escape sequence: \'\\%c\'", c);
				} else {
					tcc_warning (s1, "unknown escape sequence: \'\\x%x\'", c);
				}
				break;
			}
		}
		p++;
add_char_nonext:
		if (!is_long) {
			cstr_ccat (outstr, c);
		} else {
			cstr_wccat (outstr, c);
		}
	}
	/* add a trailing '\0' */
	if (!is_long) {
		cstr_ccat (outstr, '\0');
	} else {
		cstr_wccat (outstr, '\0');
	}
}

/* we use 64 bit numbers */
#define BN_SIZE 2

/* bn = (bn << shift) | or_val */
static void bn_lshift(unsigned int *bn, int shift, int or_val)
{
	int i;
	unsigned int v;
	for (i = 0; i < BN_SIZE; i++) {
		v = bn[i];
		bn[i] = (v << shift) | or_val;
		or_val = v >> (32 - shift);
	}
}

static void bn_zero(unsigned int *bn)
{
	int i;
	for (i = 0; i < BN_SIZE; i++) {
		bn[i] = 0;
	}
}

/* parse number in null terminated string 'p' and return it in the
   current token */
static void parse_number(TCCState *s1, const char *p) {
	int b, t, shift, frac_bits, s, exp_val, ch;
	char *q;
	unsigned int bn[BN_SIZE];
	double d;

	/* number */
	q = s1->token_buf;
	ch = *p++;
	t = ch;
	ch = *p++;
	*q++ = t;
	b = 10;
	if (t == '.') {
		goto float_frac_parse;
	} else if (t == '0') {
		if (ch == 'x' || ch == 'X') {
			q--;
			ch = *p++;
			b = 16;
		} else if (tcc_ext && (ch == 'b' || ch == 'B')) {
			q--;
			ch = *p++;
			b = 2;
		}
	}
	/* parse all digits. cannot check octal numbers at this stage
	   because of floating point constants */
	while (1) {
		if (ch >= 'a' && ch <= 'f') {
			t = ch - 'a' + 10;
		} else if (ch >= 'A' && ch <= 'F') {
			t = ch - 'A' + 10;
		} else if (isnum (ch)) {
			t = ch - '0';
		} else {
			break;
		}
		if (t >= b) {
			break;
		}
		if (q >= s1->token_buf + STRING_MAX_SIZE) {
num_too_long:
			tcc_error (s1, "number too long");
		}
		*q++ = ch;
		ch = *p++;
	}
	if (ch == '.' ||
	    ((ch == 'e' || ch == 'E') && b == 10) ||
	    ((ch == 'p' || ch == 'P') && (b == 16 || b == 2))) {
		if (b != 10) {
			/* NOTE: strtox should support that for hexa numbers, but
			   non ISOC99 libcs do not support it, so we prefer to do
			   it by hand */
			/* hexadecimal or binary floats */
			/* XXX: handle overflows */
			*q = '\0';
			if (b == 16) {
				shift = 4;
			} else {
				shift = 2;
			}
			bn_zero (bn);
			q = s1->token_buf;
			while (1) {
				t = *q++;
				if (t == '\0') {
					break;
				} else if (t >= 'a') {
					t = t - 'a' + 10;
				} else if (t >= 'A') {
					t = t - 'A' + 10;
				} else {
					t = t - '0';
				}
				bn_lshift (bn, shift, t);
			}
			frac_bits = 0;
			if (ch == '.') {
				ch = *p++;
				while (1) {
					t = ch;
					if (t >= 'a' && t <= 'f') {
						t = t - 'a' + 10;
					} else if (t >= 'A' && t <= 'F') {
						t = t - 'A' + 10;
					} else if (t >= '0' && t <= '9') {
						t = t - '0';
					} else {
						break;
					}
					if (t >= b) {
						tcc_error (s1, "invalid digit");
					}
					bn_lshift (bn, shift, t);
					frac_bits += shift;
					ch = *p++;
				}
			}
			if (ch != 'p' && ch != 'P') {
				expect (s1, "exponent");
				return;
			}
			ch = *p++;
			s = 1;
			exp_val = 0;
			if (ch == '+') {
				ch = *p++;
			} else if (ch == '-') {
				s = -1;
				ch = *p++;
			}
			if (ch < '0' || ch > '9') {
				expect (s1, "exponent digits");
				return;
			}
			while (ch >= '0' && ch <= '9') {
				exp_val = exp_val * 10 + ch - '0';
				ch = *p++;
			}
			exp_val = exp_val * s;

			/* now we can generate the number */
			/* XXX: should patch directly float number */
			d = (double) bn[1] * 4294967296.0 + (double) bn[0];
			d = ldexp (d, exp_val - frac_bits);
			t = toup (ch);
			if (t == 'F') {
				ch = *p++;
				s1->tok = TOK_CFLOAT;
				/* float : should handle overflow */
				s1->tokc.f = (float) d;
			} else if (t == 'L') {
				ch = *p++;
#ifdef TCC_TARGET_PE
				s1->tok = TOK_CDOUBLE;
				s1->tokc.d = d;
#else
				s1->tok = TOK_CLDOUBLE;
				/* XXX: not large enough */
				s1->tokc.ld = (long double) d;
#endif
			} else {
				s1->tok = TOK_CDOUBLE;
				s1->tokc.d = d;
			}
		} else {
			/* decimal floats */
			if (ch == '.') {
				if (q >= s1->token_buf + STRING_MAX_SIZE) {
					goto num_too_long;
				}
				*q++ = ch;
				ch = *p++;
float_frac_parse:
				while (ch >= '0' && ch <= '9') {
					if (q >= s1->token_buf + STRING_MAX_SIZE) {
						goto num_too_long;
					}
					*q++ = ch;
					ch = *p++;
				}
			}
			if (ch == 'e' || ch == 'E') {
				if (q >= s1->token_buf + STRING_MAX_SIZE) {
					goto num_too_long;
				}
				*q++ = ch;
				ch = *p++;
				if (ch == '-' || ch == '+') {
					if (q >= s1->token_buf + STRING_MAX_SIZE) {
						goto num_too_long;
					}
					*q++ = ch;
					ch = *p++;
				}
				if (ch < '0' || ch > '9') {
					expect (s1, "exponent digits");
					return;
				}
				while (ch >= '0' && ch <= '9') {
					if (q >= s1->token_buf + STRING_MAX_SIZE) {
						goto num_too_long;
					}
					*q++ = ch;
					ch = *p++;
				}
			}
			*q = '\0';
			t = toup (ch);
			errno = 0;
			if (t == 'F') {
				ch = *p++;
				s1->tok = TOK_CFLOAT;
				s1->tokc.f = strtof (s1->token_buf, NULL);
			} else if (t == 'L') {
				ch = *p++;
				s1->tok = TOK_CDOUBLE;
				s1->tokc.d = strtod (s1->token_buf, NULL);
				// s1->tok = TOK_CLDOUBLE;
				// s1->tokc.ld = strtold (s1->token_buf, NULL);
			} else {
				s1->tok = TOK_CDOUBLE;
				s1->tokc.d = strtod (s1->token_buf, NULL);
			}
		}
	} else {
		ut64 n, n1;
		int lcount, ucount;

		/* integer number */
		*q = '\0';
		q = s1->token_buf;
		if (b == 10 && *q == '0') {
			b = 8;
			q++;
		}
		n = 0;
		while (1) {
			t = *q++;
			/* no need for checks except for base 10 / 8 errors */
			if (t == '\0') {
				break;
			} else if (t >= 'a') {
				t = t - 'a' + 10;
			} else if (t >= 'A') {
				t = t - 'A' + 10;
			} else {
				t = t - '0';
				if (t >= b) {
					tcc_error (s1, "invalid digit");
				}
			}
			n1 = n;
			n = n * b + t;
			/* detect overflow */
			/* XXX: this test is not reliable */
			if (n < n1) {
				tcc_error (s1, "integer constant overflow");
			}
		}

		/* XXX: not exactly ANSI compliant */
		if ((n & 0xffffffff00000000LL) != 0) {
			if ((n >> 63) != 0) {
				s1->tok = TOK_CULLONG;
			} else {
				s1->tok = TOK_CLLONG;
			}
		} else if (n > 0x7fffffff) {
			s1->tok = TOK_CUINT;
		} else {
			s1->tok = TOK_CINT;
		}
		lcount = 0;
		ucount = 0;
		for (;;) {
			t = toup (ch);
			if (t == 'L') {
				if (lcount >= 2) {
					tcc_error (s1, "three 'l's in integer constant");
				}
				lcount++;
				if (s1->tok == TOK_CINT) {
					s1->tok = TOK_CLLONG;
				} else if (s1->tok == TOK_CUINT) {
					s1->tok = TOK_CULLONG;
				}
				ch = *p++;
			} else if (t == 'U') {
				if (ucount >= 1) {
					tcc_error (s1, "two 'u's in integer constant");
				}
				ucount++;
				if (s1->tok == TOK_CINT) {
					s1->tok = TOK_CUINT;
				} else if (s1->tok == TOK_CLLONG) {
					s1->tok = TOK_CULLONG;
				}
				ch = *p++;
			} else {
				break;
			}
		}
		if (s1->tok == TOK_CINT || s1->tok == TOK_CUINT) {
			s1->tokc.ui = n;
		} else {
			s1->tokc.ull = n;
		}
	}
	if (ch) {
		tcc_error (s1, "invalid number\n");
	}
}

#define PARSE2(c1, tok1, c2, tok2)\
case c1:			\
	PEEKC (s1, c, p);		\
	if (c == c2) {		\
		p++;		\
		s1->tok = tok2;	\
	} else {		\
		s1->tok = tok1;	\
	}			\
	break;

/* return next token without macro substitution */
static inline void next_nomacro1(TCCState *s1) {
	int t, c, is_long;
	TokenSym *ts;
	uint8_t *p1;
	unsigned int h;

	uint8_t *p = s1->file->buf_ptr;
redo_no_start:
	c = *p;
	switch (c) {
	case ' ':
	case '\t':
		s1->tok = c;
		p++;
		goto keep_tok_flags;
	case '\f':
	case '\v':
	case '\r':
		p++;
		goto redo_no_start;
	case '\\':
		/* first look if it is in fact an end of buffer */
		if (p >= s1->file->buf_end) {
			s1->file->buf_ptr = p;
			handle_eob (s1);
			p = s1->file->buf_ptr;
			if (p >= s1->file->buf_end) {
				goto parse_eof;
			} else {
				goto redo_no_start;
			}
		} else {
			s1->file->buf_ptr = p;
			s1->ch = *p;
			handle_stray (s1);
			p = s1->file->buf_ptr;
			goto redo_no_start;
		}
parse_eof:
		{
			if ((s1->parse_flags & PARSE_FLAG_LINEFEED)
			    && !(s1->tok_flags & TOK_FLAG_EOF)) {
				s1->tok_flags |= TOK_FLAG_EOF;
				s1->tok = TOK_LINEFEED;
				goto keep_tok_flags;
			} else if (!(s1->parse_flags & PARSE_FLAG_PREPROCESS)) {
				s1->tok = TOK_EOF;
			} else if (s1->ifdef_stack_ptr != s1->file->ifdef_stack_ptr) {
				tcc_error (s1, "missing #endif");
			} else if (s1->include_stack_ptr == s1->include_stack) {
				/* no include left : end of file. */
				s1->tok = TOK_EOF;
			} else {
				s1->tok_flags &= ~TOK_FLAG_EOF;
				/* pop include file */

				/* test if previous '#endif' was after a #ifdef at
				   start of file */
				if (s1->tok_flags & TOK_FLAG_ENDIF) {
#ifdef INC_DEBUG
					printf ("#endif %s\n", get_tok_str (s1, s1->file->ifndef_macro_saved, NULL));
#endif
					add_cached_include (s1, s1->file->filename, s1->file->ifndef_macro_saved);
					s1->tok_flags &= ~TOK_FLAG_ENDIF;
				}

				/* pop include stack */
				tcc_close (s1);
				s1->include_stack_ptr--;
				p = s1->file->buf_ptr;
				goto redo_no_start;
			}
		}
		break;

	case '\n':
		s1->file->line_num++;
		s1->tok_flags |= TOK_FLAG_BOL;
		p++;
maybe_newline:
		if (0 == (s1->parse_flags & PARSE_FLAG_LINEFEED)) {
			goto redo_no_start;
		}
		s1->tok = TOK_LINEFEED;
		goto keep_tok_flags;

	case '#':
		/* XXX: simplify */
		PEEKC (s1, c, p);
		if ((s1->tok_flags & TOK_FLAG_BOL) &&
		    (s1->parse_flags & PARSE_FLAG_PREPROCESS)) {
			s1->file->buf_ptr = p;
			preprocess (s1, s1->tok_flags & TOK_FLAG_BOF);
			p = s1->file->buf_ptr;
			goto maybe_newline;
		} else {
			if (c == '#') {
				p++;
				s1->tok = TOK_TWOSHARPS;
			} else {
				if (s1->parse_flags & PARSE_FLAG_ASM_COMMENTS) {
					p = parse_line_comment (s1, p - 1);
					goto redo_no_start;
				}
				s1->tok = '#';
			}
		}
		break;

	case 'a': case 'b': case 'c': case 'd':
	case 'e': case 'f': case 'g': case 'h':
	case 'i': case 'j': case 'k': case 'l':
	case 'm': case 'n': case 'o': case 'p':
	case 'q': case 'r': case 's': case 't':
	case 'u': case 'v': case 'w': case 'x':
	case 'y': case 'z':
	case 'A': case 'B': case 'C': case 'D':
	case 'E': case 'F': case 'G': case 'H':
	case 'I': case 'J': case 'K':
	case 'M': case 'N': case 'O': case 'P':
	case 'Q': case 'R': case 'S': case 'T':
	case 'U': case 'V': case 'W': case 'X':
	case 'Y': case 'Z':
	case '_': case '.':
parse_ident_fast:
		p1 = p;
		h = TOK_HASH_INIT;
		h = TOK_HASH_FUNC (h, c);
		p++;
		for (;;) {
			c = *p;
			if (!s1->isidnum_table[*p - CH_EOF]) {
				break;
			}
			// dot handling here too
			if (isdot (c)) {
				PEEKC (s1, c, p);
				if (isnum (c)) {
					cstr_reset (&s1->tokcstr);
					cstr_ccat (&s1->tokcstr, '.');
					goto parse_num;
				} else if (isdot (c)) {
					goto parse_dots;
				}
			}
			h = TOK_HASH_FUNC (h, *p);
			p++;
		}
		if (c != '\\') {
			TokenSym **pts;
			int len;

			/* fast case : no stray found, so we have the full token
			   and we have already hashed it */
			len = p - p1;
			h &= (TOK_HASH_SIZE - 1);
			pts = &s1->hash_ident[h];
			for (;;) {
				ts = *pts;
				if (!ts) {
					break;
				}
				if (ts->len == len && !memcmp (ts->str, p1, len)) {
					goto token_found;
				}
				pts = &(ts->hash_next);
			}
			ts = tok_alloc_new (s1, pts, (const char *) p1, len);
token_found:
			;
		} else {
			/* slower case */
			cstr_reset (&s1->tokcstr);

			while (p1 < p) {
				cstr_ccat (&s1->tokcstr, *p1);
				p1++;
			}
			p--;
			PEEKC (s1, c, p);
parse_ident_slow:
			while (s1->isidnum_table[((c > 255)? 255: c) - CH_EOF]) {
				cstr_ccat (&s1->tokcstr, c);
				PEEKC (s1, c, p);
			}
			ts = tok_alloc (s1, s1->tokcstr.data, s1->tokcstr.size);
		}
		s1->tok = ts->tok;
		break;
	case 'L':
		t = p[1];
		if (t != '\\' && t != '\'' && t != '\"') {
			/* fast case */
			goto parse_ident_fast;
		} else {
			PEEKC (s1, c, p);
			if (c == '\'' || c == '\"') {
				is_long = 1;
				goto str_const;
			} else {
				cstr_reset (&s1->tokcstr);
				cstr_ccat (&s1->tokcstr, 'L');
				goto parse_ident_slow;
			}
		}
		break;
	case '0': case '1': case '2': case '3':
	case '4': case '5': case '6': case '7':
	case '8': case '9':

		cstr_reset (&s1->tokcstr);
		/* after the first digit, accept digits, alpha, '.' or sign if
		   prefixed by 'eEpP' */
parse_num:
		for (;;) {
			t = c;
			cstr_ccat (&s1->tokcstr, c);
			PEEKC (s1, c, p);
			if (!(isnum (c) || isid (c) || isdot (c) ||
			      ((c == '+' || c == '-') &&
			       (t == 'e' || t == 'E' || t == 'p' || t == 'P')))) {
				break;
			}
		}
		/* We add a trailing '\0' to ease parsing */
		cstr_ccat (&s1->tokcstr, '\0');
		s1->tokc.cstr = &s1->tokcstr;
		s1->tok = TOK_PPNUM;
		break;
		/* special dot handling because it can also start a number */
parse_dots:
		if (!isdot (c)) {
			expect (s1, "'.'");
			return;
		}
		PEEKC (s1, c, p);
		s1->tok = TOK_DOTS;
		break;
	case '\'':
	case '\"':
		is_long = 0;
str_const:
		{
			CString str;
			int sep;

			sep = c;

			/* parse the string */
			cstr_new (&str);
			p = parse_pp_string (s1, p, sep, &str);
			if (!p) {
				return;
			}
			cstr_ccat (&str, '\0');

			/* eval the escape (should be done as TOK_PPNUM) */
			cstr_reset (&s1->tokcstr);
			parse_escape_string (s1, &s1->tokcstr, str.data, is_long);
			cstr_free (&str);

			if (sep == '\'') {
				int char_size;
				/* XXX: make it portable */
				if (!is_long) {
					char_size = 1;
				} else {
					char_size = sizeof (nwchar_t);
				}
				if (s1->tokcstr.size <= char_size) {
					tcc_error (s1, "empty character constant");
				}
				if (s1->tokcstr.size > 2 * char_size) {
					tcc_warning (s1, "multi-character character constant");
				}
				if (!is_long) {
					s1->tokc.i = *(int8_t *) s1->tokcstr.data;
					s1->tok = TOK_CCHAR;
				} else {
					s1->tokc.i = *(nwchar_t *) s1->tokcstr.data;
					s1->tok = TOK_LCHAR;
				}
			} else {
				s1->tokc.cstr = &s1->tokcstr;
				if (!is_long) {
					s1->tok = TOK_STR;
				} else {
					s1->tok = TOK_LSTR;
				}
			}
		}
		break;

	case '<':
		PEEKC (s1, c, p);
		if (c == '=') {
			p++;
			s1->tok = TOK_LE;
		} else if (c == '<') {
			PEEKC (s1, c, p);
			if (c == '=') {
				p++;
				s1->tok = TOK_A_SHL;
			} else {
				s1->tok = TOK_SHL;
			}
		} else {
			s1->tok = TOK_LT;
		}
		break;

	case '>':
		PEEKC (s1, c, p);
		if (c == '=') {
			p++;
			s1->tok = TOK_GE;
		} else if (c == '>') {
			PEEKC (s1, c, p);
			if (c == '=') {
				p++;
				s1->tok = TOK_A_SAR;
			} else {
				s1->tok = TOK_SAR;
			}
		} else {
			s1->tok = TOK_GT;
		}
		break;

	case '&':
		PEEKC (s1, c, p);
		if (c == '&') {
			p++;
			s1->tok = TOK_LAND;
		} else if (c == '=') {
			p++;
			s1->tok = TOK_A_AND;
		} else {
			s1->tok = '&';
		}
		break;

	case '|':
		PEEKC (s1, c, p);
		if (c == '|') {
			p++;
			s1->tok = TOK_LOR;
		} else if (c == '=') {
			p++;
			s1->tok = TOK_A_OR;
		} else {
			s1->tok = '|';
		}
		break;

	case '+':
		PEEKC (s1, c, p);
		if (c == '+') {
			p++;
			s1->tok = TOK_INC;
		} else if (c == '=') {
			p++;
			s1->tok = TOK_A_ADD;
		} else {
			s1->tok = '+';
		}
		break;
	case '-':
		PEEKC (s1, c, p);
		if (c == '-') {
			p++;
			s1->tok = TOK_DEC;
		} else if (c == '=') {
			p++;
			s1->tok = TOK_A_SUB;
		} else if (c == '>') {
			p++;
			s1->tok = TOK_ARROW;
		} else {
			s1->tok = '-';
		}
		break;

		PARSE2 ('!', '!', '=', TOK_NE)
		PARSE2 ('=', '=', '=', TOK_EQ)
		PARSE2 ('*', '*', '=', TOK_A_MUL)
		PARSE2 ('%', '%', '=', TOK_A_MOD)
		PARSE2 ('^', '^', '=', TOK_A_XOR)

	/* comments or operator */
	case '/':
		PEEKC (s1, c, p);
		if (c == '*') {
			p = parse_comment (s1, p);
			/* comments replaced by a blank */
			s1->tok = ' ';
			goto keep_tok_flags;
		} else if (c == '/') {
			p = parse_line_comment (s1, p);
			s1->tok = ' ';
			goto keep_tok_flags;
		} else if (c == '=') {
			p++;
			s1->tok = TOK_A_DIV;
		} else {
			s1->tok = '/';
		}
		break;

	/* simple tokens */
	case '(':
	case ')':
	case '[':
	case ']':
	case '{':
	case '}':
	case ',':
	case ';':
	case ':':
	case '?':
	case '~':
	case '$':	/* only used in assembler */
	case '@':	/* dito */
		s1->tok = c;
		p++;
		break;
	default:
		tcc_error (s1, "unrecognized character \\x%02x", c);
		break;
	}
	s1->tok_flags = 0;
keep_tok_flags:
	s1->file->buf_ptr = p;
#if defined(PARSE_DEBUG)
	printf ("token = %s\n", get_tok_str (s1, s1->tok, &s1->tokc));
#endif
}

/* find a symbol and return its associated structure. 's' is the top
   of the symbol stack */
static Sym *sym_find2(Sym *s, int v) {
	while (s) {
		if (s->v == v) {
			return s;
		}
		s = s->prev;
	}
	return NULL;
}

/* return next token without macro substitution. Can read input from
   macro_ptr buffer */
static void next_nomacro_spc(TCCState *s1) {
	if (s1->macro_ptr) {
redo:
		s1->tok = *s1->macro_ptr;
		if (s1->tok) {
			TOK_GET (&s1->tok, &s1->macro_ptr, &s1->tokc);
			if (s1->tok == TOK_LINENUM) {
				s1->file->line_num = s1->tokc.i;
				goto redo;
			}
		}
	} else {
		next_nomacro1 (s1);
	}
}

ST_FUNC void next_nomacro(TCCState *s1) {
	do {
		next_nomacro_spc (s1);
	} while (tcc_nerr (s1) == 0 && is_space (s1->tok));
}

/* substitute args in macro_str and return allocated string */
static int *macro_arg_subst(TCCState *s1, Sym **nested_list, const int *macro_str, Sym *args) {
	int last_tok, t, spc;
	const int *st;
	Sym *s;
	CValue cval;
	TokenString str;
	CString cstr;

	tok_str_new (&str);
	last_tok = 0;
	while (tcc_nerr (s1) == 0) {
		TOK_GET (&t, &macro_str, &cval);
		if (!t) {
			break;
		}
		if (t == '#') {
			/* stringize */
			TOK_GET (&t, &macro_str, &cval);
			if (!t) {
				break;
			}
			s = sym_find2 (args, t);
			if (s) {
				cstr_new (&cstr);
				st = s->d;
				spc = 0;
				while (*st) {
					TOK_GET (&t, &st, &cval);
					if (!check_space (t, &spc)) {
						cstr_cat (&cstr, get_tok_str (s1, t, &cval));
					}
				}
				cstr.size -= spc;
				cstr_ccat (&cstr, '\0');
#ifdef PP_DEBUG
				printf ("stringize: %s\n", (char *) cstr.data);
#endif
				/* add string */
				cval.cstr = &cstr;
				tok_str_add2 (&str, TOK_STR, &cval);
				cstr_free (&cstr);
			} else {
				tok_str_add2 (&str, t, &cval);
			}
		} else if (t >= TOK_IDENT) {
			s = sym_find2 (args, t);
			if (s) {
				st = s->d;
				/* if '##' is present before or after, no arg substitution */
				if (*macro_str == TOK_TWOSHARPS || last_tok == TOK_TWOSHARPS) {
					/* special case for var arg macros : ## eats the
					   ',' if empty VA_ARGS variable. */
					/* XXX: test of the ',' is not 100%
					   reliable. should fix it to avoid security
					   problems */
					if (gnu_ext && s->type.t &&
					    last_tok == TOK_TWOSHARPS &&
					    str.len >= 2 && str.str[str.len - 2] == ',') {
						if (*st == 0) {
							/* suppress ',' '##' */
							str.len -= 2;
						} else {
							/* suppress '##' and add variable */
							str.len--;
							goto add_var;
						}
					} else {
						int t1;
add_var:
						for (;;) {
							TOK_GET (&t1, &st, &cval);
							if (!t1) {
								break;
							}
							tok_str_add2 (&str, t1, &cval);
						}
					}
				} else {
					/* NOTE: the stream cannot be read when macro
					   substituing an argument */
					macro_subst (s1, &str, nested_list, st, NULL);
				}
			} else {
				tok_str_add (s1, &str, t);
			}
		} else {
			tok_str_add2 (&str, t, &cval);
		}
		last_tok = t;
	}
	tok_str_add (s1, &str, 0);
	return str.str;
}

static char const ab_month_name[12][4] =
{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/* do macro substitution of current token with macro 's' and add
   result to (s1->tok_str,tok_len). 'nested_list' is the list of all
   macros we got inside to avoid recursing. Return non zero if no
   substitution needs to be done */
static int macro_subst_tok(TCCState *s1, TokenString *tok_str,
			   Sym **nested_list, Sym *s, struct macro_level **can_read_stream)
{
	Sym *args, *sa, *sa1;
	int mstr_allocated, parlevel, *mstr, t, t1, spc;
	const int *p;
	TokenString str;
	char *cstrval;
	CValue cval;
	CString cstr;
	char buf[32];

	/* if symbol is a macro, prepare substitution */
	/* special macros */
	if (s1->tok == TOK___LINE__) {
		snprintf (buf, sizeof (buf), "%d", s1->file->line_num);
		cstrval = buf;
		t1 = TOK_PPNUM;
		goto add_cstr1;
	} else if (s1->tok == TOK___FILE__) {
		cstrval = s1->file->filename;
		goto add_cstr;
	} else if (s1->tok == TOK___DATE__ || s1->tok == TOK___TIME__) {
		time_t ti;
		struct tm *tm;

		time (&ti);
		tm = localtime (&ti);
		if (s1->tok == TOK___DATE__) {
			snprintf (buf, sizeof (buf), "%s %2d %d",
				ab_month_name[tm->tm_mon], tm->tm_mday, tm->tm_year + 1900);
		} else {
			snprintf (buf, sizeof (buf), "%02d:%02d:%02d",
				tm->tm_hour, tm->tm_min, tm->tm_sec);
		}
		cstrval = buf;
add_cstr:
		t1 = TOK_STR;
add_cstr1:
		cstr_new (&cstr);
		cstr_cat (&cstr, cstrval);
		cstr_ccat (&cstr, '\0');
		cval.cstr = &cstr;
		tok_str_add2 (tok_str, t1, &cval);
		cstr_free (&cstr);
	} else {
		mstr = s->d;
		mstr_allocated = 0;
		if (s->type.t == MACRO_FUNC) {
			/* NOTE: we do not use next_nomacro to avoid eating the
			   next token. XXX: find better solution */
redo:
			if (s1->macro_ptr) {
				p = s1->macro_ptr;
				while (is_space (t = *p) || TOK_LINEFEED == t) {
					++p;
				}
				if (t == 0 && can_read_stream) {
					/* end of macro stream: we must look at the token
					   after in the file */
					struct macro_level *ml = *can_read_stream;
					s1->macro_ptr = NULL;
					if (ml) {
						s1->macro_ptr = ml->p;
						ml->p = NULL;
						*can_read_stream = ml->prev;
					}
					/* also, end of scope for nested defined symbol */
					(*nested_list)->v = -1;
					goto redo;
				}
			} else {
				s1->ch = s1->file->buf_ptr[0];
				while (is_space (s1->ch) || s1->ch == '\n' || s1->ch == '/') {
					if (s1->ch == '/') {
						int c;
						uint8_t *p = s1->file->buf_ptr;
						PEEKC (s1, c, p);
						if (c == '*') {
							p = parse_comment (s1, p);
							s1->file->buf_ptr = p - 1;
						} else if (c == '/') {
							p = parse_line_comment (s1, p);
							s1->file->buf_ptr = p - 1;
						} else {
							break;
						}
					}
					minp (s1);
				}
				t = s1->ch;
			}
			if (t != '(') {	/* no macro subst */
				return -1;
			}

			/* argument macro */
			next_nomacro (s1);
			next_nomacro (s1);
			args = NULL;
			sa = s->next;
			/* NOTE: empty args are allowed, except if no args */
			while (tcc_nerr (s1) == 0) {
				/* handle '()' case */
				if (!args && !sa && s1->tok == ')') {
					break;
				}
				if (!sa) {
					tcc_error (s1, "macro '%s' used with too many args", get_tok_str (s1, s->v, 0));
				}
				tok_str_new (&str);
				parlevel = spc = 0;
				/* NOTE: non zero sa->t indicates VA_ARGS */
				while ((parlevel > 0 ||
					(s1->tok != ')' &&
					 (s1->tok != ',' || (sa && sa->type.t)))) &&
				       s1->tok != -1) {
					if (s1->tok == '(') {
						parlevel++;
					} else if (s1->tok == ')') {
						parlevel--;
					}
					if (s1->tok == TOK_LINEFEED) {
						s1->tok = ' ';
					}
					if (!check_space (s1->tok, &spc)) {
						tok_str_add2 (&str, s1->tok, &s1->tokc);
					}
					next_nomacro_spc (s1);
				}
				str.len -= spc;
				tok_str_add (s1, &str, 0);
				sa1 = sa ? sym_push2 (s1, &args, sa->v & ~SYM_FIELD, sa->type.t, 0) : NULL;
				if (!sa1) {
					return -1;
				}
				sa1->d = str.str;
				sa = sa->next;
				if (s1->tok == ')') {
					/* special case for gcc var args: add an empty
					   var arg argument if it is omitted */
					if (sa && sa->type.t && gnu_ext) {
						continue;
					} else {
						break;
					}
				}
				if (s1->tok != ',') {
					expect (s1, ",");
					return 1;
				}
				next_nomacro (s1);
			}
			if (sa) {
				tcc_error (s1, "macro '%s' used with too few args", get_tok_str (s1, s->v, 0));
			}

			/* now subst each arg */
			mstr = macro_arg_subst (s1, nested_list, mstr, args);
			/* free memory */
			sa = args;
			while (sa) {
				sa1 = sa->prev;
				tok_str_free (sa->d);
				sym_free (s1, sa);
				sa = sa1;
			}
			mstr_allocated = 1;
		}
		if (sym_push2 (s1, nested_list, s->v, 0, 0) == 0) {
			return -1;
		}
		macro_subst (s1, tok_str, nested_list, mstr, can_read_stream);
		/* pop nested defined symbol */
		sa1 = *nested_list;
		*nested_list = sa1->prev;
		sym_free (s1, sa1);
		if (mstr_allocated) {
			tok_str_free (mstr);
		}
	}
	return 0;
}

/* handle the '##' operator. Return NULL if no '##' seen. Otherwise
   return the resulting string (which must be freed). */
static inline int *macro_twosharps(TCCState *s1, const int *macro_str) {
	const int *ptr;
	int t;
	TokenString macro_str1;
	CString cstr;
	int n, start_of_nosubsts;

	/* we search the first '##' */
	for (ptr = macro_str;;) {
		CValue cval;
		TOK_GET (&t, &ptr, &cval);
		if (t == TOK_TWOSHARPS) {
			break;
		}
		/* nothing more to do if end of string */
		if (t == 0) {
			return NULL;
		}
	}

	/* we saw '##', so we need more processing to handle it */
	start_of_nosubsts = -1;
	tok_str_new (&macro_str1);
	for (ptr = macro_str;;) {
		TOK_GET (&s1->tok, &ptr, &s1->tokc);
		if (s1->tok == 0) {
			break;
		}
		if (s1->tok == TOK_TWOSHARPS) {
			continue;
		}
		if (s1->tok == TOK_NOSUBST && start_of_nosubsts < 0) {
			start_of_nosubsts = macro_str1.len;
		}
		while (*ptr == TOK_TWOSHARPS) {
			/* given 'a##b', remove nosubsts preceding 'a' */
			if (start_of_nosubsts >= 0) {
				macro_str1.len = start_of_nosubsts;
			}
			/* given 'a##b', skip '##' */
			t = *++ptr;
			/* given 'a##b', remove nosubsts preceding 'b' */
			while (t == TOK_NOSUBST)
				t = *++ptr;
			if (t && t != TOK_TWOSHARPS) {
				CValue cval;
				TOK_GET (&t, &ptr, &cval);
				/* We concatenate the two tokens */
				cstr_new (&cstr);
				cstr_cat (&cstr, get_tok_str (s1, s1->tok, &s1->tokc));
				n = cstr.size;
				cstr_cat (&cstr, get_tok_str (s1, t, &cval));
				cstr_ccat (&cstr, '\0');

				tcc_open_bf (s1, ":paste:", cstr.size);
				memcpy (s1->file->buffer, cstr.data, cstr.size);
				while (tcc_nerr (s1) == 0) {
					next_nomacro1 (s1);
					if (0 == *s1->file->buf_ptr) {
						break;
					}
					tok_str_add2 (&macro_str1, s1->tok, &s1->tokc);
					tcc_warning (s1, "pasting \"%.*s\" and \"%s\" does not give a valid preprocessing token",
						n, (char *) cstr.data, (char *) cstr.data + n);
				}
				tcc_close (s1);
				cstr_free (&cstr);
			}
		}
		if (s1->tok != TOK_NOSUBST) {
			start_of_nosubsts = -1;
		}
		tok_str_add2 (&macro_str1, s1->tok, &s1->tokc);
	}
	tok_str_add (s1, &macro_str1, 0);
	return macro_str1.str;
}


/* do macro substitution of macro_str and add result to
   (tok_str,tok_len). 'nested_list' is the list of all macros we got
   inside to avoid recursing. */
static void macro_subst(TCCState *s1, TokenString *tok_str, Sym **nested_list,
			const int *macro_str, struct macro_level **can_read_stream)
{
	Sym *s;
	int *macro_str1;
	const int *ptr;
	int t, ret, spc;
	CValue cval;
	struct macro_level ml;
	int force_blank;

	/* first scan for '##' operator handling */
	ptr = macro_str;
	macro_str1 = macro_twosharps (s1, ptr);

	if (macro_str1) {
		ptr = macro_str1;
	}
	spc = 0;
	force_blank = 0;

	while (tcc_nerr (s1) == 0) {
		/* NOTE: ptr == NULL can only happen if tokens are read from
		   file stream due to a macro function call */
		if (ptr == NULL) {
			break;
		}
		TOK_GET (&t, &ptr, &cval);
		if (t == 0) {
			break;
		}
		if (t == TOK_NOSUBST) {
			/* following token has already been subst'd. just copy it on */
			tok_str_add2 (tok_str, TOK_NOSUBST, NULL);
			TOK_GET (&t, &ptr, &cval);
			goto no_subst;
		}
		s = define_find (s1, t);
		if (s) {
			/* if nested substitution, do nothing */
			if (sym_find2 (*nested_list, t)) {
				/* and mark it as TOK_NOSUBST, so it doesn't get subst'd again */
				tok_str_add2 (tok_str, TOK_NOSUBST, NULL);
				goto no_subst;
			}
			ml.p = s1->macro_ptr;
			if (can_read_stream) {
				ml.prev = *can_read_stream, *can_read_stream = &ml;
			}
			s1->macro_ptr = (int *) ptr;
			s1->tok = t;
			ret = macro_subst_tok (s1, tok_str, nested_list, s, can_read_stream);
			ptr = (int *) s1->macro_ptr;
			s1->macro_ptr = ml.p;
			if (can_read_stream && *can_read_stream == &ml) {
				*can_read_stream = ml.prev;
			}
			if (ret != 0) {
				goto no_subst;
			}
			if (s1->parse_flags & PARSE_FLAG_SPACES) {
				force_blank = 1;
			}
		} else {
no_subst:
			if (force_blank) {
				tok_str_add (s1, tok_str, ' ');
				spc = 1;
				force_blank = 0;
			}
			if (!check_space (t, &spc)) {
				tok_str_add2 (tok_str, t, &cval);
			}
		}
	}
	if (macro_str1) {
		tok_str_free (macro_str1);
	}
}

/* return next token with macro substitution */
ST_FUNC void next(TCCState *s1) {
	Sym *nested_list, *s;
	TokenString str;
	struct macro_level *ml;
redo:
	if (s1->parse_flags & PARSE_FLAG_SPACES) {
		next_nomacro_spc (s1);
	} else {
		next_nomacro (s1);
	}
	if (!s1->macro_ptr) {
		/* if not reading from macro substituted string, then try
		   to substitute macros */
		if (s1->tok >= TOK_IDENT &&
		    (s1->parse_flags & PARSE_FLAG_PREPROCESS)) {
			s = define_find (s1, s1->tok);
			if (s) {
				/* we have a macro: we try to substitute */
				tok_str_new (&str);
				nested_list = NULL;
				ml = NULL;
				if (macro_subst_tok (s1, &str, &nested_list, s, &ml) == 0) {
					/* substitution done, NOTE: maybe empty */
					tok_str_add (s1, &str, 0);
					s1->macro_ptr = str.str;
					s1->macro_ptr_allocated = str.str;
					goto redo;
				}
			}
		}
	} else {
		if (s1->tok == 0) {
			/* end of macro or end of unget buffer */
			if (s1->unget_buffer_enabled) {
				s1->macro_ptr = s1->unget_saved_macro_ptr;
				s1->unget_buffer_enabled = false;
			} else {
				/* end of macro string: free it */
				tok_str_free (s1->macro_ptr_allocated);
				s1->macro_ptr_allocated = NULL;
				s1->macro_ptr = NULL;
			}
			goto redo;
		} else if (s1->tok == TOK_NOSUBST) {
			/* discard preprocessor's nosubst markers */
			goto redo;
		}
	}

	/* convert preprocessor tokens into C tokens */
	if (s1->tok == TOK_PPNUM &&
	    (s1->parse_flags & PARSE_FLAG_TOK_NUM)) {
		parse_number (s1, (char *) s1->tokc.cstr->data);
	}
}

/* push back current token and set current token to 'last_tok'. Only
   identifier case handled for labels. */
ST_INLN void unget_tok(TCCState *s1, int last_tok) {
	int i, n;
	int *q;
	if (s1->unget_buffer_enabled) {
		/* assert(macro_ptr == unget_saved_buffer + 1);
		   assert(*macro_ptr == 0);  */
	} else {
		s1->unget_saved_macro_ptr = s1->macro_ptr;
		s1->unget_buffer_enabled = true;
	}
	q = s1->unget_saved_buffer;
	s1->macro_ptr = q;
	*q++ = s1->tok;
	n = tok_ext_size (s1, s1->tok) - 1;
	for (i = 0; i < n; i++) {
		*q++ = s1->tokc.tab[i];
	}
	*q = 0;	/* end of token string */
	s1->tok = last_tok;
}


/* better than nothing, but needs extension to handle '-E' option
   correctly too */
ST_FUNC void preprocess_init(TCCState *s1) {
	s1->include_stack_ptr = s1->include_stack;
	/* XXX: move that before to avoid having to initialize
	   file->ifdef_stack_ptr ? */
	s1->ifdef_stack_ptr = s1->ifdef_stack;
	s1->file->ifdef_stack_ptr = s1->ifdef_stack_ptr;

	s1->vtop = s1->vstack; //  - 1;
	s1->pack_stack[0] = 0;
	s1->pack_stack_ptr = s1->pack_stack;
}

ST_FUNC void preprocess_new(TCCState *s1) {
	int i, c;
	const char *p, *r;

	/* init isid table */
	for (i = CH_EOF; i < 256; i++) {
		s1->isidnum_table[i - CH_EOF] = isid (i) || isnum (i) || isdot (i);
	}

	/* add all tokens */
	s1->table_ident = NULL;
	memset (s1->hash_ident, 0, TOK_HASH_SIZE * sizeof (TokenSym *));

	s1->tok_ident = TOK_IDENT;
	p = tcc_keywords;
	while (*p) {
		r = p;
		for (;;) {
			c = *r++;
			if (c == '\0') {
				break;
			}
		}
		tok_alloc (s1, p, r - p - 1);
		p = r;
	}
}

/* Preprocess the current file */
ST_FUNC int tcc_preprocess(TCCState *s1) {
	BufferedFile *file_ref, **iptr, **iptr_new;
	int d;
	const char *s;

	preprocess_init (s1);
	Sym *define_start = s1->define_stack;
	s1->ch = s1->file->buf_ptr[0];
	s1->tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;
	s1->parse_flags = PARSE_FLAG_ASM_COMMENTS | PARSE_FLAG_PREPROCESS |
		      PARSE_FLAG_LINEFEED | PARSE_FLAG_SPACES;
	int token_seen = 0;
	int line_ref = 0;
	file_ref = NULL;
	iptr = s1->include_stack_ptr;

	while (tcc_nerr (s1) == 0) {
		next (s1);
		if (s1->tok == TOK_EOF) {
			break;
		} else if (s1->file != file_ref) {
			goto print_line;
		} else if (s1->tok == TOK_LINEFEED) {
			if (!token_seen) {
				continue;
			}
			++line_ref;
			token_seen = 0;
		} else if (!token_seen) {
			d = s1->file->line_num - line_ref;
			if (s1->file != file_ref || d < 0 || d >= 8) {
print_line:
				iptr_new = s1->include_stack_ptr;
				s = iptr_new > iptr? " 1"
				    : iptr_new < iptr? " 2"
				    : iptr_new > s1->include_stack? " 3"
				    : ""
				;
				iptr = iptr_new;
				fprintf (s1->ppfp, "# %d \"%s\"%s\n", s1->file->line_num, s1->file->filename, s);
			} else {
				while (d) {
					fputs ("\n", s1->ppfp), --d;
				}
			}
			line_ref = (file_ref = s1->file)->line_num;
			token_seen = s1->tok != TOK_LINEFEED;
			if (!token_seen) {
				continue;
			}
		}
		fputs (get_tok_str (s1, s1->tok, &s1->tokc), s1->ppfp);
	}
	free_defines (s1, define_start);
	return 0;
}

/* radare - LGPL - Copyright 2013-2025 - pancake */

#include <r_cons.h>
#include <r_util/r_assert.h>
#include <r_util.h>
#include <math.h>
#include "private.h"

#define PI 3.14159265359

#define W(y) r_cons_canvas_write(c, y)
#define G(x, y) r_cons_canvas_gotoxy(c, x, y)
#define ATTR_PAGE_BITS 12
#define ATTR_PAGE_CELLS (1 << ATTR_PAGE_BITS)

typedef struct {
	const char *str;
	ut32 len;
} CanvasStyle;

R_VEC_TYPE (RVecCanvasStyle, CanvasStyle);

struct r_cons_canvas_attrs_t {
	ut8 **pages; // lazily allocated style ids per cell, ut16 once wide
	size_t npages;
	bool wide;
	RVecCanvasStyle styles; // id -> interned attribute, id 0 means none
	HtUP *ids; // interned attribute -> id
	const char *last; // last looked up attribute, consecutive stamps repeat it
	ut32 last_id;
	ut32 maxlen;
	ut64 size; // total length of the stored attributes
};

static RConsCanvasAttrs *attrs_new(void) {
	RConsCanvasAttrs *a = R_NEW0 (RConsCanvasAttrs);
	a->ids = ht_up_new0 ();
	if (!a->ids || !RVecCanvasStyle_emplace_back (&a->styles)) {
		ht_up_free (a->ids);
		free (a);
		return NULL;
	}
	return a;
}

static void attrs_clear(RConsCanvasAttrs *a, bool release) {
	size_t i;
	for (i = 0; i < a->npages; i++) {
		if (release) {
			R_FREE (a->pages[i]);
		} else if (a->pages[i]) {
			memset (a->pages[i], 0, ATTR_PAGE_CELLS * (a->wide? sizeof (ut16): 1));
		}
	}
	if (release) {
		R_FREE (a->pages);
		a->npages = 0;
	}
	a->size = 0;
}

static void attrs_free(RConsCanvasAttrs *a) {
	if (a) {
		attrs_clear (a, true);
		RVecCanvasStyle_fini (&a->styles);
		ht_up_free (a->ids);
		free (a);
	}
}

static inline ut32 attrs_id_at(const RConsCanvasAttrs *a, ut64 loc) {
	const ut64 pagenum = loc >> ATTR_PAGE_BITS;
	if (pagenum >= a->npages || !a->pages[pagenum]) {
		return 0;
	}
	const size_t off = loc & (ATTR_PAGE_CELLS - 1);
	return a->wide? ((const ut16 *)a->pages[pagenum])[off]: a->pages[pagenum][off];
}

static inline const CanvasStyle *attrs_style(const RConsCanvasAttrs *a, ut32 id) {
	return a->styles._start + id;
}

static bool attrs_widen(RConsCanvasAttrs *a) {
	ut16 **pages = R_NEWS0 (ut16 *, a->npages + 1);
	if (!pages) {
		return false;
	}
	size_t i, j;
	for (i = 0; i < a->npages; i++) {
		if (!a->pages[i]) {
			continue;
		}
		if (!(pages[i] = malloc (ATTR_PAGE_CELLS * sizeof (ut16)))) {
			while (i > 0) {
				free (pages[--i]);
			}
			free (pages);
			return false;
		}
		for (j = 0; j < ATTR_PAGE_CELLS; j++) {
			pages[i][j] = a->pages[i][j];
		}
	}
	for (i = 0; i < a->npages; i++) {
		free (a->pages[i]);
	}
	free (a->pages);
	a->pages = (ut8 **)pages;
	a->wide = true;
	return true;
}

static ut32 attrs_style_id(RConsCanvasAttrs *a, const char *style) {
	if (style == a->last) {
		return a->last_id;
	}
	bool found = false;
	ut32 id = (ut32)(size_t)ht_up_find (a->ids, (ut64)(size_t)style, &found);
	if (!found) {
		id = RVecCanvasStyle_length (&a->styles);
		if (id > UT16_MAX || (id > UT8_MAX && !a->wide && !attrs_widen (a))) {
			return 0;
		}
		CanvasStyle *cs = RVecCanvasStyle_emplace_back (&a->styles);
		if (!cs) {
			return 0;
		}
		cs->str = style;
		cs->len = strlen (style);
		a->maxlen = R_MAX (a->maxlen, cs->len);
		ht_up_insert (a->ids, (ut64)(size_t)style, (void *)(size_t)id);
	}
	a->last = style;
	a->last_id = id;
	return id;
}

// style must be interned in the canvas constpool; NULL removes the cell attribute
R_IPI void canvas_attrs_set(RConsCanvasAttrs *a, ut64 loc, const char *style) {
	const ut64 pagenum = loc >> ATTR_PAGE_BITS;
	const ut32 id = style? attrs_style_id (a, style): 0;
	if (style && !id) {
		return;
	}
	if (pagenum >= a->npages || !a->pages[pagenum]) {
		if (!id || pagenum >= SIZE_MAX / sizeof (ut8 *) / 2) {
			return;
		}
		if (pagenum >= a->npages) {
			const size_t npages = R_MAX ((size_t)pagenum + 1, a->npages * 2);
			ut8 **pages = realloc (a->pages, npages * sizeof (ut8 *));
			if (!pages) {
				return;
			}
			memset (pages + a->npages, 0, (npages - a->npages) * sizeof (ut8 *));
			a->pages = pages;
			a->npages = npages;
		}
		if (!(a->pages[pagenum] = calloc (ATTR_PAGE_CELLS, a->wide? sizeof (ut16): 1))) {
			return;
		}
	}
	const size_t off = loc & (ATTR_PAGE_CELLS - 1);
	a->size -= attrs_style (a, attrs_id_at (a, loc))->len;
	a->size += attrs_style (a, id)->len;
	if (a->wide) {
		((ut16 *)a->pages[pagenum])[off] = id;
	} else {
		a->pages[pagenum][off] = id;
	}
}

static int rune_display_width(RRune ch) {
	if (ch < 0x80) {
		return 1;
	}
	// CJK and wide characters
	if ((ch >= 0x1100 && ch <= 0x115F) || // Hangul Jamo
		(ch >= 0x2E80 && ch <= 0x9FFF) || // CJK
		(ch >= 0xAC00 && ch <= 0xD7AF) || // Hangul Syllables
		(ch >= 0xF900 && ch <= 0xFAFF) || // CJK Compatibility Ideographs
		(ch >= 0xFE10 && ch <= 0xFE1F) || // Vertical Forms
		(ch >= 0xFE30 && ch <= 0xFE4F) || // CJK Compatibility Forms
		(ch >= 0x1F000 && ch <= 0x1FFFF) || // Emojis and symbols
		(ch >= 0x20000 && ch <= 0x2FFFF)) { // CJK Extension B, C, D, E, F
		return 2;
	}
	return 1;
}

static const char *r_cons_get_rune(const ut8 ch) {
	/* Fast lookup table for runes mapped by RUNECODE_* constants.
	 * The table is indexed by (ch - RUNECODE_MIN) and covers the
	 * continuous range [RUNECODE_MIN, RUNECODE_MAX).
	 */
	static const char *const rune_table[] = {
		/* 0xc8 */ RUNE_LINE_VERT,
		/* 0xc9 */ RUNE_LINE_CROSS,
		/* 0xca */ RUNE_CORNER_BR,
		/* 0xcb */ RUNE_CORNER_BL,
		/* 0xcc */ RUNE_ARROW_RIGHT,
		/* 0xcd */ RUNE_ARROW_LEFT,
		/* 0xce */ RUNE_LINE_HORIZ,
		/* 0xcf */ RUNE_CORNER_TL,
		/* 0xd0 */ RUNE_CORNER_TR,
		/* 0xd1 */ RUNE_LINE_UP,
		/* 0xd2 */ RUNE_CURVE_CORNER_TL,
		/* 0xd3 */ RUNE_CURVE_CORNER_TR,
		/* 0xd4 */ RUNE_CURVE_CORNER_BR,
		/* 0xd5 */ RUNE_CURVE_CORNER_BL,
	};

	if (ch < RUNECODE_MIN || ch >= RUNECODE_MAX) {
		return NULL;
	}
	return rune_table[ch - RUNECODE_MIN];
}

static inline bool __isAnsiSequence(const char *s) {
	return s && s[0] == 033 && s[1] == '[';
}

static int __getAnsiPiece(const char *p, char *chr) {
	const char *q = p;
	if (!p) {
		return 0;
	}
	while (p && *p && *p != '\n' && !__isAnsiSequence (p)) {
		p++;
	}
	if (chr) {
		*chr = *p;
	}
	return p - q;
}

static void __stampAttribute(RConsCanvas *c, ut64 loc, int length) {
	if (!c->color) {
		return;
	}
	int i;
	c->attr = r_str_constpool_get (&c->constpool, c->attr);
	canvas_attrs_set (c->attrs, loc, c->attr);
	for (i = 1; i < length; i++) {
		canvas_attrs_set (c->attrs, loc + i, NULL);
	}
}

/* check for ANSI sequences and use them as attr */
static const char *set_attr(RConsCanvas *c, const char *s) {
	if (!c || !s) {
		return NULL;
	}
	const char *p = s;

	while (__isAnsiSequence (p)) {
		p += 2;
		while (*p && *p != 'J' && *p != 'm' && *p != 'H') {
			p++;
		}
		p++;
	}

	const int slen = p - s;
	if (slen > 0) {
		char tmp[256];
		if (slen < (int)sizeof (tmp)) {
			memcpy (tmp, s, slen);
			tmp[slen] = '\0';
			c->attr = r_str_constpool_get (&c->constpool, tmp);
		} else {
			char *h = r_str_ndup (s, slen);
			if (h) {
				c->attr = r_str_constpool_get (&c->constpool, h);
				free (h);
			}
		}
	}
	return p;
}

static int __getUtf8Length(const char *s, int n) {
	int i = 0, len = 0;
	while (s[i] && n > 0) {
		const ut8 ch = s[i];
		if (ch < 0x80 || R_BETWEEN (RUNECODE_MIN, ch, RUNECODE_MAX - 1)) {
			len++;
			i++;
			n--;
		} else if ((ch & 0xc0) != 0x80) {
			RRune rune;
			int ulen = r_utf8_decode ((const ut8 *)s + i, n, &rune);
			if (ulen > 0) {
				len += rune_display_width (rune);
				i += ulen;
				n -= ulen;
			} else {
				len += 1;
				i++;
				n--;
			}
		} else {
			i++;
			n--;
		}
	}
	return len;
}

static int __getUtf8Length2(const char *s, int n, int left) {
	int i = 0, len = 0;
	while (i < left && s[i] && len < n) {
		const ut8 ch = s[i];
		if (ch < 0x80 || R_BETWEEN (RUNECODE_MIN, ch, RUNECODE_MAX - 1)) {
			len++;
			i++;
		} else if ((ch & 0xc0) != 0x80) {
			RRune rune;
			int ulen = r_utf8_decode ((const ut8 *)s + i, left - i, &rune);
			if (ulen > 0) {
				len += rune_display_width (rune);
				i += ulen;
			} else {
				len += 1;
				i++;
			}
		} else {
			i++;
		}
	}
	return i;
}

static bool __expandLine(RConsCanvas *c, int real_len, int utf8_len) {
	if (real_len == 0) {
		return true;
	}
	int buf_utf8_len = c->blen[c->y] == c->w
		? utf8_len
		: __getUtf8Length2 (c->b[c->y] + c->x, utf8_len, c->blen[c->y] - c->x);
	int goback = R_MAX (0, (buf_utf8_len - utf8_len));
	int padding = (real_len - utf8_len) - goback;

	if (padding) {
		if (padding > 0 && c->blen[c->y] + padding > c->bsize[c->y]) {
			int newsize = R_MAX ((int) (c->bsize[c->y] * 1.5), c->blen[c->y] + padding);
			char *newline = realloc (c->b[c->y], sizeof (*c->b[c->y]) *(newsize));
			if (!newline) {
				return false;
			}
			memset (newline + c->bsize[c->y], 0, newsize - c->bsize[c->y]);
			c->b[c->y] = newline;
			c->bsize[c->y] = newsize;
		}
		int size = R_MAX (c->blen[c->y] - c->x - goback, 0);
		char *start = c->b[c->y] + c->x + goback;
		if (padding < 0) {
			int lap = R_MAX (0, c->b[c->y] - (start + padding));
			memmove (start + padding + lap, start + lap, size - lap);
			c->blen[c->y] += padding;
			return true;
		}
		memmove (start + padding, start, size);
		c->blen[c->y] += padding;
	}
	return true;
}

static void canvas_free_buffers(RConsCanvas *c) {
	if (c->b) {
		int y;
		for (y = 0; y < c->h; y++) {
			free (c->b[y]);
		}
	}
	R_FREE (c->b);
	R_FREE (c->bsize);
	R_FREE (c->blen);
	c->w = c->h = 0;
	c->x = c->y = 0;
}

R_API void r_cons_canvas_free(RConsCanvas *c) {
	if (!c) {
		return;
	}
	canvas_free_buffers (c);
	free (c->bgcolor);
	attrs_free (c->attrs);
	r_str_constpool_fini (&c->constpool);
	free (c);
}

R_API void r_cons_canvas_clear(RConsCanvas *c, int flags) {
	R_RETURN_IF_FAIL (c && c->b);
	int y;
	for (y = 0; y < c->h; y++) {
		memset (c->b[y], '\n', c->bsize[y]);
		c->blen[y] = c->w;
	}
	c->x = c->y = 0;
	attrs_clear (c->attrs, false);
	if (flags != R_CONS_CANVAS_FLAG_DEFAULT) {
		c->flags = flags;
	}
}

R_API bool r_cons_canvas_gotoxy(RConsCanvas *c, int x, int y) {
	bool ret = true;
	if (!c) {
		return false;
	}
	y += c->sy;
	x += c->sx;

	if (y > c->h * 2) {
		return false;
	}
	if (y >= c->h) {
		y = c->h - 1;
		ret = false;
	}
	if (y < 0) {
		y = 0;
		ret = false;
	}
	if (x < 0) {
		// c->x = 0;
		ret = false;
	}
	if (x > c->blen[y] * 2) {
		return false;
	}
	if (x >= c->blen[y]) {
		c->x = c->blen[y];
		ret = false;
	}
	if (x < c->blen[y] && x >= 0) {
		c->x = x;
	}
	if (y < c->h) {
		c->y = y;
	}
	return ret;
}

static bool canvas_array_sizes(int w, int h, size_t *rows_size, size_t *lengths_size) {
	ut64 rows, lengths;
	if (w < 0 || w >= ST32_MAX || h <= 0
			|| r_mul_overflow_ut64 (h, sizeof (char *), &rows)
			|| r_mul_overflow_ut64 (h, sizeof (int), &lengths)
			|| rows > SIZE_MAX || lengths > SIZE_MAX) {
		return false;
	}
	*rows_size = (size_t)rows;
	*lengths_size = (size_t)lengths;
	return true;
}

R_API RConsCanvas *r_cons_canvas_new(RCons *cons, int w, int h, int flags) {
	size_t rows_size, lengths_size;
	if (w < 1 || !canvas_array_sizes (w, h, &rows_size, &lengths_size)) {
		return NULL;
	}
	RConsCanvas *c = R_NEW0 (RConsCanvas);
	c->cons = cons;
	c->bgcolor = strdup (Color_RESET);
	c->bsize = NULL;
	if (flags == R_CONS_CANVAS_FLAG_DEFAULT) {
		c->flags = 0;
	} else if (flags == R_CONS_CANVAS_FLAG_INHERIT) {
		c->flags = cons? r_cons_canvas_flags (cons): 0;
	} else {
		c->flags = flags;
	}
	c->blen = NULL;
	int i = 0;
	c->color = 0;
	c->sx = 0;
	c->sy = 0;
	c->b = malloc (rows_size);
	if (!c->b) {
		goto beach;
	}
	c->blen = malloc (lengths_size);
	if (!c->blen) {
		goto beach;
	}
	c->bsize = malloc (lengths_size);
	if (!c->bsize) {
		goto beach;
	}
	for (i = 0; i < h; i++) {
		c->b[i] = malloc (w + 1);
		c->blen[i] = w;
		c->bsize[i] = w + 1;
		if (!c->b[i]) {
			goto beach;
		}
	}
	c->w = w;
	c->h = h;
	c->x = c->y = 0;
	if (!r_str_constpool_init (&c->constpool)) {
		goto beach;
	}
	c->attrs = attrs_new ();
	if (!c->attrs) {
		goto beach;
	}
	c->attr = Color_RESET;
	r_cons_canvas_clear (c, -1);
	return c;
beach:
	r_str_constpool_fini (&c->constpool);
	int j;
	for (j = 0; j < i; j++) {
		free (c->b[j]);
	}
	free (c->bsize);
	free (c->blen);
	free (c->b);
	free (c);
	return NULL;
}

R_API void r_cons_canvas_write(RConsCanvas *c, const char *_s) {
	if (!c || !_s || !*_s || !R_BETWEEN (0, c->y, c->h - 1) || !R_BETWEEN (0, c->x, c->w - 1)) {
		return;
	}
	RCons *cons = c->cons;
	char *os = strstr (_s, Color_RESET)? r_str_ansi_resetbg (_s, c->bgcolor): NULL;
	const char *s = os? os: _s;
	char ch;
	int left, slen, attr_len, piece_len;
	int orig_x = c->x, attr_x = c->x;
	const bool check_break = strchr (s, '\n') || strchr (s, '\x1b');

	if (c->blen[c->y] != c->w) {
		c->x = __getUtf8Length2 (c->b[c->y], c->x, c->blen[c->y]);
	}

	/* split the string into pieces of non-ANSI chars and print them normally,
	 ** using the ANSI chars to set the attr of the canvas */
	if (check_break) {
		r_cons_break_push (cons, NULL, NULL);
	}
	do {
		const char *s_part = set_attr (c, s);
		ch = 0;
		piece_len = __getAnsiPiece (s_part, &ch);
		if (piece_len == 0 && ch == '\0' && s_part == s) {
			break;
		}
		left = c->blen[c->y] - c->x;
		slen = piece_len;

		if (piece_len > left) {
			int utf8_piece_len = __getUtf8Length (s_part, piece_len);
			if (utf8_piece_len > c->w - attr_x) {
				slen = left;
			}
		}

		int real_len = r_str_nlen (s_part, slen);
		int utf8_len = __getUtf8Length (s_part, slen);

		if (!__expandLine (c, real_len, utf8_len)) {
			break;
		}

		if (G (c->x - c->sx, c->y - c->sy)) {
			memcpy (c->b[c->y] + c->x, s_part, slen);
		}

		attr_len = slen <= 0 && s_part != s? 1: utf8_len;
		if (attr_len > 0 && attr_x < c->blen[c->y]) {
			__stampAttribute (c, (ut64)c->y * c->w + attr_x, attr_len);
		}
		s = s_part;
		if (ch == '\n') {
			c->attr = c->bgcolor;
			__stampAttribute (c, (ut64)c->y * c->w + attr_x, 0);
			c->y++;
			s++;
			if (*s == '\0' || c->y >= c->h) {
				break;
			}
			c->x = c->blen[c->y] == c->w
				? orig_x
				: __getUtf8Length2 (c->b[c->y], orig_x, c->blen[c->y]);
			attr_x = orig_x;
		} else {
			c->x += slen;
			attr_x += utf8_len;
		}
		s += piece_len;
	} while (*s && (!check_break || !r_cons_is_breaked (cons)));
	if (check_break) {
		r_cons_break_pop (cons);
	}
	c->x = orig_x;
	free (os);
}

R_API const char *r_cons_canvas_attribute_at(RConsCanvas *c, int x, int y) {
	R_RETURN_VAL_IF_FAIL (c, NULL);
	const ut32 id = (x < 0 || y < 0)? 0: attrs_id_at (c->attrs, (ut64)y * c->w + x);
	return id? attrs_style (c->attrs, id)->str: NULL;
}

R_API void r_cons_canvas_write_at(RConsCanvas *c, const char *s, int x, int y) {
	if (r_cons_canvas_gotoxy (c, x, y)) {
		r_cons_canvas_write (c, s);
	}
}

R_API void r_cons_canvas_background(RConsCanvas *c, const char *color) {
	if (color) {
		free (c->bgcolor);
		c->bgcolor = strdup (color);
	}
}

// renders one row without its trailing spaces and returns its length
static size_t canvas_render_row(RConsCanvas *c, int y, bool useutf, char *o) {
	size_t olen = 0;
	int x, attr_x = 0;
	for (x = 0; x < c->blen[y];) {
		const ut8 byte = c->b[y][x];
		if ((byte & 0xc0) != 0x80) {
			const ut32 id = c->color? attrs_id_at (c->attrs, (ut64)y * c->w + attr_x): 0;
			if (id) {
				const CanvasStyle *cs = attrs_style (c->attrs, id);
				memcpy (o + olen, cs->str, cs->len);
				olen += cs->len;
			}
			if (!byte || byte == '\n') {
				o[olen++] = ' ';
				attr_x++;
				x++;
				continue;
			}
			if (byte < 0x80) {
				o[olen++] = byte;
				attr_x++;
				x++;
				continue;
			}
			if (useutf) {
				RRune ch;
				int ulen = r_utf8_decode ((const ut8 *)c->b[y] + x, c->blen[y] - x, &ch);
				if (ulen > 1) {
					memcpy (o + olen, c->b[y] + x, ulen);
					olen += ulen;
					attr_x += rune_display_width (ch);
					x += ulen;
					continue;
				}
			}
			const char *rune = r_cons_get_rune (byte);
			if (rune) {
				size_t rune_len = strlen (rune);
				memcpy (o + olen, rune, rune_len + 1);
				olen += rune_len;
				attr_x++;
				x++;
			} else {
				RRune ch;
				int ulen = r_utf8_decode ((const ut8 *)c->b[y] + x, c->blen[y] - x, &ch);
				if (ulen > 0) {
					memcpy (o + olen, c->b[y] + x, ulen);
					olen += ulen;
					attr_x += rune_display_width (ch);
					x += ulen;
				} else {
					o[olen++] = c->b[y][x];
					attr_x++;
					x++;
				}
			}
		} else {
			x++;
		}
	}
	while (olen > 0 && o[olen - 1] == ' ') {
		olen--;
	}
	return olen;
}

R_API char *r_cons_canvas_tostring(RConsCanvas *c) {
	R_RETURN_VAL_IF_FAIL (c, NULL);

	int y;
	int max_line_length = 0;
	ut64 olen = 0;

	for (y = 0; y < c->h; y++) {
		if (c->blen[y] < 0 || r_add_overflow_ut64 (olen, c->blen[y], &olen)) {
			return NULL;
		}
		max_line_length = R_MAX (max_line_length, c->blen[y]);
	}
	ut64 output_size;
	// Runecode bytes expand to at most three UTF-8 bytes.
	if (r_mul_overflow_ut64 (olen, sizeof (RUNE_LINE_VERT) - 1, &output_size)
			|| r_add_overflow_ut64 (output_size, c->h, &output_size)) {
		return NULL;
	}
	if (c->color) {
		ut64 attributes_size = c->attrs->size;
		// Expanded UTF-8 rows can reach attribute locations from later rows.
		ut64 row_overlap = c->w > 0
			? (ut64)max_line_length / c->w + (max_line_length % c->w != 0)
			: 1;
		if (r_mul_overflow_ut64 (attributes_size, row_overlap, &attributes_size)
				|| r_add_overflow_ut64 (output_size, attributes_size, &output_size)) {
			return NULL;
		}
	}
	if (!output_size || output_size > SIZE_MAX) {
		return NULL;
	}
	char *o = malloc ((size_t)output_size);
	if (!o) {
		return NULL;
	}

	olen = 0;
	const bool useutf = c->flags & R_CONS_CANVAS_FLAG_UTF8;
	for (y = 0; y < c->h; y++) {
		if (y > 0) {
			o[olen++] = '\n';
		}
		olen += canvas_render_row (c, y, useutf, o + olen);
	}
	o[olen] = '\0';
	return o;
}

// writes the rows straight into the console buffer instead of building a full copy first
static void canvas_print_rows(RConsCanvas *c, bool trim) {
	int y, max_line_length = 0;
	for (y = 0; y < c->h; y++) {
		max_line_length = R_MAX (max_line_length, c->blen[y]);
	}
	const ut64 cell_size = sizeof (RUNE_LINE_VERT) - 1 + (c->color? c->attrs->maxlen: 0);
	ut64 row_size;
	if (r_mul_overflow_ut64 (max_line_length, cell_size, &row_size) || row_size >= SIZE_MAX) {
		return;
	}
	char *row = malloc ((size_t)row_size + 1);
	if (!row) {
		return;
	}
	// trailing whitespace is held back so the output matches r_str_trim_tail
	RStrBuf pending;
	r_strbuf_init (&pending);
	const bool useutf = c->flags & R_CONS_CANVAS_FLAG_UTF8;
	for (y = 0; y < c->h; y++) {
		if (y > 0) {
			if (trim) {
				r_strbuf_append_n (&pending, "\n", 1);
			} else {
				r_cons_write (c->cons, "\n", 1);
			}
		}
		size_t len = canvas_render_row (c, y, useutf, row);
		size_t visible = len;
		if (trim) {
			while (visible > 0 && IS_WHITECHAR (row[visible - 1])) {
				visible--;
			}
			if (!visible) {
				r_strbuf_append_n (&pending, row, len);
				continue;
			}
			if (r_strbuf_length (&pending) > 0) {
				r_cons_write (c->cons, r_strbuf_get (&pending), r_strbuf_length (&pending));
				r_strbuf_fini (&pending);
				r_strbuf_init (&pending);
			}
			r_strbuf_append_n (&pending, row + visible, len - visible);
		}
		if (visible > 0) {
			r_cons_write (c->cons, row, visible);
		}
	}
	r_strbuf_fini (&pending);
	free (row);
}

R_API void r_cons_canvas_print_region(RConsCanvas *c) {
	R_RETURN_IF_FAIL (c);
	canvas_print_rows (c, true);
}

R_API void r_cons_canvas_print(RConsCanvas *c) {
	R_RETURN_IF_FAIL (c);
	canvas_print_rows (c, false);
}

R_API int r_cons_canvas_resize(RConsCanvas *c, int w, int h) {
	size_t rows_size, lengths_size;
	if (!c || !canvas_array_sizes (w, h, &rows_size, &lengths_size)) {
		return false;
	}
	if (c->b && w == c->w && h == c->h) {
		r_cons_canvas_clear (c, R_CONS_CANVAS_FLAG_DEFAULT);
		return true;
	}
	const int old_h = c->h;
	int i;
	// shrink: free dropped lines before resizing the pointer array
	for (i = h; i < old_h; i++) {
		R_FREE (c->b[i]);
	}
	char **newb = realloc (c->b, rows_size);
	if (!newb) {
		goto beach;
	}
	c->b = newb;
	// NULL-init grown slots so failure cleanup never frees uninit pointers
	for (i = old_h; i < h; i++) {
		c->b[i] = NULL;
	}
	c->h = h;
	// blen/bsize are fully overwritten below; replace rather than realloc-preserve
	free (c->blen);
	free (c->bsize);
	c->blen = malloc (lengths_size);
	c->bsize = malloc (lengths_size);
	if (!c->blen || !c->bsize) {
		goto beach;
	}
	for (i = 0; i < h; i++) {
		char *line = c->b[i]
			? realloc (c->b[i], w + 1)
			: malloc (w + 1);
		if (!line) {
			goto beach;
		}
		c->b[i] = line;
		c->blen[i] = w;
		c->bsize[i] = w + 1;
	}
	c->w = w;
	attrs_clear (c->attrs, true);
	r_cons_canvas_clear (c, R_CONS_CANVAS_FLAG_DEFAULT);
	return true;
beach:
	canvas_free_buffers (c);
	attrs_clear (c->attrs, true);
	return false;
}

R_API void r_cons_canvas_circle(RConsCanvas *c, int x, int y, int w, int h, const char *color) {
	if (color) {
		c->attr = color;
	}
	double xfactor = 1; // (double)w / (double)h;
	double yfactor = (double)h / 24; // 0.8; // 24  10
	double size = w;
	double a = 0.0;
	double s = size / 2;
	while (a < (2 * PI)) {
		double sa = r_num_sin (a);
		double ca = r_num_cos (a);
		double cx = s * ca + (size / 2);
		double cy = s * sa + (size / 4);
		int X = x + (int) (xfactor * cx) - 2;
		int Y = y + (int) ((yfactor / 2) * cy);
		if (G (X, Y)) {
			W ("=");
		}
		a += 0.1;
	}
	if (color) {
		c->attr = Color_RESET;
	}
}

R_API void r_cons_canvas_box(RConsCanvas *c, int x, int y, int w, int h, const char *R_NULLABLE color) {
	// NOTE: As long as utf and curvy flags are tied to the canvas, we need to
	// regenerate the canvas to get such changes now. before the kons refactoring
	// this changed when cconfig settings were modified. not sure if its worth.
	const bool useutf = c->flags & R_CONS_CANVAS_FLAG_UTF8;
	const bool usecrv = c->flags & R_CONS_CANVAS_FLAG_CURVY;
	const char *hline = useutf? RUNECODESTR_LINE_HORIZ: "-";
	const char *vtmp = useutf? RUNECODESTR_LINE_VERT: "|";
	RStrBuf *vline = r_strbuf_new (NULL);
	if (color) {
		r_strbuf_appendf (vline, Color_RESET "%s%s", color, vtmp);
	} else {
		r_strbuf_appendf (vline, Color_RESET "%s", vtmp);
	}
	const char *tl_corner = useutf? (usecrv? RUNECODESTR_CURVE_CORNER_TL: RUNECODESTR_CORNER_TL): ".";
	const char *tr_corner = useutf? (usecrv? RUNECODESTR_CURVE_CORNER_TR: RUNECODESTR_CORNER_TR): ".";
	const char *bl_corner = useutf? (usecrv? RUNECODESTR_CURVE_CORNER_BL: RUNECODESTR_CORNER_BL): "`";
	const char *br_corner = useutf? (usecrv? RUNECODESTR_CURVE_CORNER_BR: RUNECODESTR_CORNER_BR): "'";
	int i, x_mod;
	int roundcorners = 0;
	char *row = NULL, *row_ptr;

	if (w < 1 || h < 1) {
		return;
	}
	if (color) {
		c->attr = color;
	}
	if (!c->color) {
		c->attr = Color_RESET;
	}
	row = malloc (w + 1);
	if (!row) {
		return;
	}
	row[0] = roundcorners? '.': tl_corner[0];
	if (w > 2) {
		memset (row + 1, hline[0], w - 2);
	}
	if (w > 1) {
		row[w - 1] = roundcorners? '.': tr_corner[0];
	}
	row[w] = 0;

	row_ptr = row;
	x_mod = x;
	if (x < -c->sx) {
		x_mod = R_MIN (-c->sx, x_mod + w);
		row_ptr += x_mod - x;
	}
	if (G (x_mod, y)) {
		W (row_ptr);
	}
	if (G (x_mod, y + h - 1)) {
		row[0] = roundcorners? '\'': bl_corner[0];
		row[w - 1] = roundcorners? '\'': br_corner[0];
		W (row_ptr);
	}
	for (i = 1; i < h - 1; i++) {
		if (G (x, y + i)) {
			W (r_strbuf_get (vline));
		}
		if (G (x + w - 1, y + i)) {
			W (r_strbuf_get (vline));
		}
	}
	free (row);
	r_strbuf_free (vline);
	if (color) {
		c->attr = Color_RESET;
		for (i = 0; i < h; i++) {
			if (G (x + w, y + i)) {
				W (Color_RESET);
			}
		}
	}
}

R_API void r_cons_canvas_fill(RConsCanvas *c, int x, int y, int w, int h, char ch) {
	int i;
	if (w < 0) {
		return;
	}
	char *row = malloc (w + 1);
	if (!row) {
		return;
	}
	memset (row, ch, w);
	row[w] = 0;
	for (i = 0; i < h; i++) {
		if (G (x, y + i)) {
			W (row);
		}
	}
	free (row);
}

R_API void r_cons_canvas_bgfill(RConsCanvas *c, int x, int y, int w, int h, const char *color) {
	// TODO: this is quite innefficient
	int i;
	char *bgcolor = strdup (color);
	char *col = strstr (bgcolor, "\x1b[3");
	if (col) {
		col[2] = '4';
	} else {
		free (bgcolor);
		bgcolor = strdup (Color_BGBLUE);
	}
	char *pad = r_str_pad (NULL, 0, ' ', w + 2);
	char *row = r_str_newf ("%s%s" Color_RESET, bgcolor, pad);
	free (pad);
	for (i = 0; i < h; i++) {
		if (G (x, y + i)) {
			W (row);
		}
	}
	free (row);
	free (bgcolor);
}

R_API void r_cons_canvas_line(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style) {
	if (c->linemode) {
		r_cons_canvas_line_square (c, x, y, x2, y2, style);
	} else {
		r_cons_canvas_line_diagonal (c, x, y, x2, y2, style);
	}
}

R_API int r_cons_canvas_flags(RCons *R_NONNULL cons) {
	R_RETURN_VAL_IF_FAIL (cons, 0);
	int flags = 0;
	if (cons->use_utf8) {
		flags |= R_CONS_CANVAS_FLAG_UTF8;
	}
	if (cons->use_utf8_curvy) {
		flags |= R_CONS_CANVAS_FLAG_CURVY;
	}
	return flags;
}

/* radare - LGPL - Copyright 2013-2019 - pancake */

#include <r_cons.h>
#include <r_util/r_assert.h>

#define useUtf8 (r_cons_singleton ()->use_utf8)
#define useUtf8Curvy (r_cons_singleton ()->use_utf8_curvy)

#define W(y) r_cons_canvas_write (c, y)
#define G(x, y) r_cons_canvas_gotoxy (c, x, y)

static inline bool __isAnsiSequence(const char *s) {
	return s && s[0] == 033 && s[1] == '[';
}

static int __getAnsiPiece(const char *p, char *chr) {
	const char *q = p;
	if (!p) {
		return 0;
	}
	while (p && *p && *p != '\n' && ! __isAnsiSequence (p)) {
		p++;
	}
	if (chr) {
		*chr = *p;
	}
	return p - q;
}

static void attribute_free_kv(HtUPKv *kv) {
	free (kv->value);
}

static const char *__attributeAt(RConsCanvas *c, int loc) {
	if (!c->color) {
		return NULL;
	}
	return ht_up_find (c->attrs, loc, NULL);
}

static void __stampAttribute(RConsCanvas *c, int loc, int length) {
	if (!c->color) {
		return;
	}
	int i;
	ht_up_update (c->attrs, loc, (void *)c->attr);
	for (i = 1; i < length; i++) {
		ht_up_delete (c->attrs, loc + i);
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
		RStrBuf tmp;
		r_strbuf_init (&tmp);
		r_strbuf_append_n (&tmp, s, slen);
		c->attr = r_str_constpool_get (&c->constpool, r_strbuf_get (&tmp));
		r_strbuf_fini (&tmp);
	}
	return p;
}

static int __getUtf8Length(const char *s, int n) {
	int i = 0, j = 0, fullwidths = 0;
	while (s[i] && n > 0) {
		if ((s[i] & 0xc0) != 0x80) {
			j++;
			if (r_str_char_fullwidth (s + i, n)) {
				fullwidths++;
			}
		}
		n--;
		i++;
	}
	return j + fullwidths;
}

static int __getUtf8Length2(const char *s, int n, int left) {
	int i = 0, fullwidths = 0;
	while (n > -1 && i < left && s[i]) {
		if (r_str_char_fullwidth (s + i, left - i)) {
			fullwidths++;
		}
		if ((s[i] & 0xc0) != 0x80) {
			n--;
		}
		i++;
	}
	i -= fullwidths;
	return n == -1 ? i - 1 : i;
}

static bool __expandLine(RConsCanvas *c, int real_len, int utf8_len) {
	if (real_len == 0) {
		return true;
	}
	int buf_utf8_len = __getUtf8Length2 (c->b[c->y] + c->x, utf8_len, c->blen[c->y] - c->x);
	int goback = R_MAX (0, (buf_utf8_len - utf8_len));
	int padding = (real_len - utf8_len) - goback;

	if (padding) {
		if (padding > 0 && c->blen[c->y] + padding > c->bsize[c->y]) {
			int newsize = R_MAX (c->bsize[c->y] * 1.5, c->blen[c->y] + padding);
			char * newline = realloc (c->b[c->y], sizeof (*c->b[c->y])*(newsize));
			if (!newline) {
				return false;
			}
			memset (newline + c->bsize[c->y], 0, newsize - c->bsize[c->y]);
			c->b[c->y] = newline;
			c->bsize[c->y] = newsize;
		}
		int size = R_MAX (c->blen[c->y] - c->x - goback, 0);
		char *start = c->b[c->y] + c->x + goback;
		char *tmp = malloc (size);
		if (!tmp) {
			return false;
		}
		memcpy (tmp, start, size);
		if (padding < 0) {
			int lap = R_MAX (0, c->b[c->y] - (start + padding));
			memcpy (start + padding + lap,  tmp + lap, size - lap);
			free (tmp);
			c->blen[c->y] += padding;
			return true;
		}
		memcpy (start + padding, tmp, size);
		free (tmp);
		c->blen[c->y] += padding;
	}
	return true;
}

R_API void r_cons_canvas_free(RConsCanvas *c) {
	if (!c) {
		return;
	}
	if (c->b) {
		int y;
		for (y = 0; y < c->h; y++) {
			free (c->b[y]);
		}
		free (c->b);
	}
	free (c->bsize);
	free (c->blen);
	ht_up_free (c->attrs);
	r_str_constpool_fini (&c->constpool);
	free (c);
}

static bool attribute_delete_cb(void *user, const ut64 key, const void *value) {
	HtUP *ht = (HtUP *)user;
	ht_up_delete (ht, key);
	return true;
}

R_API void r_cons_canvas_clear(RConsCanvas *c) {
	r_return_if_fail (c && c->b);
	int y;
	for (y = 0; y < c->h; y++) {
		memset (c->b[y], '\n', c->bsize[y]);
	}

	ht_up_foreach (c->attrs, attribute_delete_cb, c->attrs);
}

R_API bool r_cons_canvas_gotoxy(RConsCanvas *c, int x, int y) {
	bool ret = true;
	if (!c) {
		return 0;
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
		//c->x = 0;
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
	if (y < c->h && y >= 0) {
		c->y = y;
	}
	return ret;
}

R_API RConsCanvas *r_cons_canvas_new(int w, int h) {
	if (w < 1 || h < 1) {
		return NULL;
	}
	RConsCanvas *c = R_NEW0 (RConsCanvas);
	if (!c) {
		return NULL;
	}
	c->bsize = NULL;
	c->blen = NULL;
	int i = 0;
	c->color = 0;
	c->sx = 0;
	c->sy = 0;
	c->b = malloc (sizeof *c->b * h);
	if (!c->b) {
		goto beach;
	}
	c->blen = malloc (sizeof *c->blen * h);
	if (!c->blen) {
		goto beach;
	}
	c->bsize = malloc (sizeof *c->bsize * h);
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
	c->attrs = ht_up_new ((HtUPDupValue)strdup, attribute_free_kv, NULL);
	if (!c->attrs) {
		goto beach;
	}
	c->attr = Color_RESET;
	r_cons_canvas_clear (c);
	return c;
beach: {
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
}

R_API void r_cons_canvas_write(RConsCanvas *c, const char *s) {
	if (!c || !s || !*s || !R_BETWEEN (0, c->y, c->h - 1) || !R_BETWEEN (0, c->x, c->w - 1)) {
		return;
	}

	char ch;
	int left, slen, attr_len, piece_len;
	int orig_x = c->x, attr_x = c->x;

	c->x = __getUtf8Length2 (c->b[c->y], c->x, c->blen[c->y]);

	/* split the string into pieces of non-ANSI chars and print them normally,
	** using the ANSI chars to set the attr of the canvas */
	r_cons_break_push (NULL, NULL);
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
			__stampAttribute (c, c->y*c->w + attr_x, attr_len);
		}

		s = s_part;
		if (ch == '\n') {
			c->attr = Color_RESET;
			__stampAttribute (c, c->y*c->w + attr_x, 0);
			c->y++;
			s++;
			if (*s == '\0' || c->y  >= c->h) {
				break;
			}
			c->x = __getUtf8Length2 (c->b[c->y], orig_x, c->blen[c->y]);
			attr_x = orig_x;
		} else {
			c->x += slen;
			attr_x += utf8_len;
		}
		s += piece_len;
	} while (*s && !r_cons_is_breaked ());
	r_cons_break_pop ();
	c->x = orig_x;
}

R_API char *r_cons_canvas_to_string(RConsCanvas *c) {
	r_return_val_if_fail (c, NULL);

	int x, y, olen = 0, attr_x = 0;
	int is_first = true;

	for (y = 0; y < c->h; y++) {
		olen += c->blen[y] + 1;
	}
	char *o = calloc (1, olen * 4 * CONS_MAX_ATTR_SZ);
	if (!o) {
		return NULL;
	}
	if (!olen) {
		free (o);
		return NULL;
	}

	olen = 0;
	for (y = 0; y < c->h; y++) {
		if (!is_first) {
			o[olen++] = '\n';
		}
		is_first = false;
		attr_x = 0;
		for (x = 0; x < c->blen[y]; x++) {
			if ((c->b[y][x] & 0xc0) != 0x80) {
				const char *atr = __attributeAt (c, y * c->w + attr_x);
				if (atr) {
					int len = strlen (atr);
					memcpy (o + olen, atr, len);
					olen += len;
				}
				attr_x++;
				if (r_str_char_fullwidth (c->b[y] + x, c->blen[y] - x)) {
					attr_x++;
				}
			}
			if (!c->b[y][x] || c->b[y][x] == '\n') {
				o[olen++] = ' ';
				continue;
			}
			const char *rune = r_cons_get_rune ((const ut8)c->b[y][x]);
			if (rune) {
				strcpy (o + olen, rune);
				olen += strlen (rune);
			} else {
				o[olen++] = c->b[y][x];
			}
		}
		while (olen > 0 && o[olen - 1] == ' ') {
			o[--olen] = '\0';
		}
	}
	o[olen] = '\0';
	return o;
}

R_API void r_cons_canvas_print_region(RConsCanvas *c) {
	char *o = r_cons_canvas_to_string (c);
	if (o) {
		r_str_trim_tail (o);
		if (*o) {
			r_cons_strcat (o);
		}
		free (o);
	}
}

R_API void r_cons_canvas_print(RConsCanvas *c) {
	char *o = r_cons_canvas_to_string (c);
	if (o) {
		r_cons_strcat (o);
		free (o);
	}
}

R_API int r_cons_canvas_resize(RConsCanvas *c, int w, int h) {
	if (!c || w < 0 || h <= 0) {
		return false;
	}
	int *newblen = realloc (c->blen, sizeof *c->blen * h);
	if (!newblen) {
		r_cons_canvas_free (c);
		return false;
	}
	c->blen = newblen;
	int *newbsize = realloc (c->bsize, sizeof *c->bsize * h);
	if (!newbsize) {
		r_cons_canvas_free (c);
		return false;
	}
	c->bsize = newbsize;
	char **newb = realloc (c->b, sizeof *c->b * h);
	if (!newb) {
		r_cons_canvas_free (c);
		return false;
	}
	c->b = newb;
	int i;
	char *newline = NULL;
	for (i = 0; i < h; i++) {
		if (i < c->h) {
			newline = realloc (c->b[i], sizeof *c->b[i] * (w + 1));
		} else {
			newline = malloc ((w + 1));
		}
		c->blen[i] = w;
		c->bsize[i] = w + 1;
		if (!newline) {
			int j;
			for (j = 0; j <= i; j++) {
				free (c->b[i]);
			}
			ht_up_free (c->attrs);
			free (c->blen);
			free (c->bsize);
			free (c->b);
			free (c);
			return false;
		}
		c->b[i] = newline;
	}
	c->w = w;
	c->h = h;
	c->x = 0;
	c->y = 0;
	r_cons_canvas_clear (c);
	return true;
}

#include <math.h>
#define PI 3.1415
R_API void r_cons_canvas_circle(RConsCanvas *c, int x, int y, int w, int h, const char *color) {
	if (color) {
		c->attr = color;
	}
	double xfactor = 1; //(double)w / (double)h;
	double yfactor = (double)h / 24; // 0.8; // 24  10
	double size = w;
	float a = 0.0;
	double s = size / 2;
	while (a < (2 * PI)) {
		double sa = r_num_sin (a);
		double ca = r_num_cos (a);
		double cx = s * ca + (size / 2);
		double cy = s * sa + (size / 4);
		int X = x + (xfactor * cx) - 2;
		int Y = y + ((yfactor/2) * cy);
		if (G (X, Y)) {
			W ("=");
		}
		a += 0.1;
	}
	if (color) {
		c->attr = Color_RESET;
	}
}

R_API void r_cons_canvas_box(RConsCanvas *c, int x, int y, int w, int h, const char *color) {
	const char *hline = useUtf8? RUNECODESTR_LINE_HORIZ : "-";
	const char *vtmp = useUtf8? RUNECODESTR_LINE_VERT : "|";
	RStrBuf *vline = r_strbuf_new (NULL);
	r_strbuf_appendf (vline, Color_RESET"%s%s", color, vtmp);
	const char *tl_corner = useUtf8 ? (useUtf8Curvy ? RUNECODESTR_CURVE_CORNER_TL : RUNECODESTR_CORNER_TL) : ".";
	const char *tr_corner = useUtf8 ? (useUtf8Curvy ? RUNECODESTR_CURVE_CORNER_TR : RUNECODESTR_CORNER_TR) : ".";
	const char *bl_corner = useUtf8 ? (useUtf8Curvy ? RUNECODESTR_CURVE_CORNER_BL : RUNECODESTR_CORNER_BL) : "`";
	const char *br_corner = useUtf8 ? (useUtf8Curvy ? RUNECODESTR_CURVE_CORNER_BR : RUNECODESTR_CORNER_BR) : "'";
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

R_API void r_cons_canvas_line(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style) {
	if (c->linemode) {
		r_cons_canvas_line_square (c, x, y, x2, y2, style);
	} else {
		r_cons_canvas_line_diagonal (c, x, y, x2, y2, style);
	}
}

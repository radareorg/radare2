/* radare - LGPL - Copyright 2013-2017 - pancake */

#include <r_cons.h>

#define useUtf8 (r_cons_singleton()->use_utf8)
#define useUtf8Curvy (r_cons_singleton()->use_utf8_curvy)

#define W(y) r_cons_canvas_write (c, y)
#define G(x, y) r_cons_canvas_gotoxy (c, x, y)

R_API void r_cons_canvas_free(RConsCanvas *c) {
	free (c->b);
	free (c->attrs);
	free (c);
}

R_API void r_cons_canvas_clear(RConsCanvas *c) {
	int y;
	if (c && c->b) {
		memset (c->b, '\n', c->blen);
		c->b[c->blen] = 0;
		for (y = 0; y < c->h; y++) {
			c->b[y * c->w] = '\n';
		}
		if (c->attrs) {
			c->attrslen = 0;
			memset (c->attrs, 0, sizeof (*c->attrs) * c->blen);
		}
	}
}

R_API RConsCanvas *r_cons_canvas_new(int w, int h) {
	RConsCanvas *c;
	if (w < 1 || h < 1) {
		return NULL;
	}
	c = R_NEW0 (RConsCanvas);
	if (!c) return NULL;
	c->color = 0;
	c->sx = 0;
	c->sy = 0;
	c->blen = (w + 1) * h;
	c->b = malloc (c->blen + 1);
	if (!c->b) {
		free (c);
		return NULL;
	}
	c->attrslen = 0;
	c->attrs = calloc (sizeof (*c->attrs), c->blen + 1);
	if (!c->attrs) {
		free (c->b);
		free (c);
		return NULL;
	}
	c->attr = Color_RESET;
	c->w = w;
	c->h = h;
	c->x = c->y = 0;
	r_cons_canvas_clear (c);
	return c;
}

R_API bool r_cons_canvas_gotoxy(RConsCanvas *c, int x, int y) {
	bool ret = true;
	if (!c) {
		return 0;
	}
	x += c->sx;
	y += c->sy;
	if (x > c->w * 2) {
		return false;
	}
	if (y > c->h * 2) {
		return false;
	}
	if (x >= c->w) {
		c->x = c->w;
		ret = false;
	}
	if (y >= c->h) {
		c->y = c->h;
		ret = false;
	}
	if (x < 0) {
		//c->x = 0;
		ret = false;
	}
	if (y < 0) {
		c->y = 0;
		ret = false;
	}
	if (x < c->w && x >= 0) {
		c->x = x;
	}
	if (y < c->h && y >= 0) {
		c->y = y;
	}
	return ret;
}

static int is_ansi_seq(const char *s) {
#if 0
	/* check utf8 length */
	if (((*s & 0xc0) == 0x80)) {
		return false;
	}
#endif
	return s && *s == 0x1b && *(s + 1) == '[';
}

static int get_piece(const char *p, char *chr) {
	const char *q = p;
	if (!p) {
		return 0;
	}
	while (p && *p && *p != '\n' && !is_ansi_seq (p)) {
		p++;
	}
	if (chr) {
		*chr = *p;
	}
	return p - q;
}

static char *prefixline(RConsCanvas *c, int *left) {
	if (!c) {
		return NULL;
	}
	int x, len;
	char *p;
	int b_len = c->w * c->h;
	int yxw = c->y * c->w;
	if (b_len < yxw) {
		return NULL;
	}
	p = c->b + yxw;
	len = b_len - yxw - 1;
	for (x = 0; (p[x] && x < c->x) && x < len; x++) {
		if (p[x] == '\n') {
			p[x] = ' ';
		}
	}
	if (left) {
		*left = c->w - c->x;
	}
	return p + x;
}

static const char **attr_at(RConsCanvas *c, int loc) {
	int i, j, delta;
	if (!c->color || c->attrslen == 0) {
		return NULL;
	}
	j = c->attrslen / 2;
	delta = c->attrslen / 2;
	for (i = 0; i < (c->attrslen); i++) {
		delta /= 2;
		if (delta == 0) {
			delta = 1;
		}
		if (c->attrs[j].loc == loc) {
			return &c->attrs[j].a;
		}
		if (c->attrs[j].loc < loc) {
			j += delta;
			if (j >= c->attrslen) {
				break;
			}
			if (c->attrs[j].loc > loc && delta == 1) {
				break;
			}
		} else if (c->attrs[j].loc > loc) {
			j -= delta;
			if (j <= 0) {
				break;
			}
			if (c->attrs[j].loc < loc && delta == 1) {
				break;
			}
		}
	}
	return NULL;
}

static void sort_attrs(RConsCanvas *c) {
	int i, j;
	RConsCanvasAttr value;
	for (i = 1; i < c->attrslen; i++) {
		value = c->attrs[i];
		for (j = i - 1; j >= 0 && c->attrs[j].loc > value.loc; j--) {
			c->attrs[j + 1] = c->attrs[j];
		}
		c->attrs[j + 1] = value;
	}
}

static void stamp_attr(RConsCanvas *c, int length) {
	int i;
	const char **s;
	const int loc = c->x + (c->y * c->w);
	s = attr_at (c, loc);

	if (s) {
		//If theres already an attr there, just replace it.
		*s = c->attr;
	} else {
		c->attrs[c->attrslen].loc = loc;
		c->attrs[c->attrslen].a = c->attr;
		c->attrslen++;
		sort_attrs (c);
	}

	for (i = 0; i < length; i++) {
		s = attr_at (c, loc + i);
		if (s) {
			*s = c->attr;
		}
	}
}

/* check for ANSI sequences and use them as attr */
static const char *set_attr(RConsCanvas *c, const char *s) {
	const char *p = s;

	while (is_ansi_seq (p)) {
		p += 2;
		while (*p && *p != 'J' && *p != 'm' && *p != 'H') {
			p++;
		}
		p++;
	}

	if (p != s) {
		char tmp[256];
		const int slen = R_MIN (p - s, sizeof (tmp) - 1);
		if (slen > 0) {
			memcpy (tmp, s, slen);
			tmp[slen] = 0;
			// could be faster
			c->attr = r_str_const (tmp);
		}
	}
	return p;
}

R_API void r_cons_canvas_write(RConsCanvas *c, const char *s) {
	char *p, ch;
	int orig_x, x;
	int left, slen, attr_len, piece_len;

	if (!c || !s || !*s) {
		return;
	}
	/* split the string into pieces of non-ANSI chars and print them normally,
	** using the ANSI chars to set the attr of the canvas */
	orig_x = c->x;
	r_cons_break_push (NULL, NULL);
	do {
		const char *s_part = set_attr (c, s);
		ch = 0;
		piece_len = get_piece (s_part, &ch);
		if (piece_len == 0 && ch == '\0' && s_part == s) {
			break;
		}
		left = 0;
		p = prefixline (c, &left);
		slen = R_MIN (left, piece_len);
		attr_len = slen <= 0 && s_part != s? 1: slen;
		if (attr_len > 0) {
			stamp_attr (c, attr_len);
		}
		// XXX this is a bug if we scroll in the middle of \033
		x = c->x - c->sx;
		if (G (x, c->y - c->sy)) {
			memcpy (p, s_part, slen);
		}
		s = s_part;
		if (ch == '\n') {
			c->y++;
			c->x = orig_x;
			s++;
			if (*s == '\0') {
				break;
			}
		} else {
			c->x += slen;
		}
		s += piece_len;
	} while (*s && !r_cons_is_breaked ());
	r_cons_break_pop ();
	c->x = orig_x;
}

R_API char *r_cons_canvas_to_string(RConsCanvas *c) {
	int x, y, olen = 0;
	char *o;
	const char *b;
	const char **atr;
	int is_first = true;

	if (!c) {
		return NULL;
	}
	b = c->b;
	o = calloc (1, (c->w * (c->h + 1)) * (CONS_MAX_ATTR_SZ));
	if (!o) {
		return NULL;
	}
	for (y = 0; y < c->h; y++) {
		if (!is_first) {
			o[olen++] = '\n';
		}
		is_first = false;
		for (x = 0; x < c->w; x++) {
			const int p = x + (y * c->w);
			atr = attr_at (c, p);
			if (atr && *atr) {
				strcat (o, *atr);
				olen += strlen (*atr);
			}
			if (!b[p] || b[p] == '\n') {
				break;
			}
			const char *rune = r_cons_get_rune((const ut8)b[p]);
			if (rune) {
				strcpy (o + olen, rune);
				olen += strlen (rune);
			} else {
				o[olen++] = b[p];
			}
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
	void *newbuf = NULL;
	const int blen = (w + 1) * h;
	char *b = NULL;
	if (!c || w < 0) {
		return false;
	}
	b = realloc (c->b, blen + 1);
	if (!b) {
		return false;
	}
	c->b = b;
	newbuf = realloc (c->attrs, sizeof (*c->attrs) * blen + 1);
	if (!newbuf) {
		free (c->b);
		free (c->attrs);
		return false;
	}
	c->attrs = newbuf;
	c->blen = blen;
	c->b = b;
	c->w = w;
	c->h = h;
	c->x = 0;
	c->y = 0;
	r_cons_canvas_clear (c);
	return true;
}

R_API void r_cons_canvas_box(RConsCanvas *c, int x, int y, int w, int h, const char *color) {
	const char *hline = useUtf8? RUNECODESTR_LINE_HORIZ : "-";
	const char *vline = useUtf8? RUNECODESTR_LINE_VERT : "|";
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
	if (!c->color) c->attr = Color_RESET;
	row = malloc (w + 1);
	if (!row)
		return;
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
		if (G (x, y + i)) W (vline);
		if (G (x + w - 1, y + i)) W (vline);
	}
	free (row);
	if (color) c->attr = Color_RESET;
}

R_API void r_cons_canvas_fill(RConsCanvas *c, int x, int y, int w, int h, char ch, int replace) {
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

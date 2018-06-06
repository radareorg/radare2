/* radare - LGPL - Copyright 2013-2018 - pancake */

#include <r_cons.h>

#define useUtf8 (r_cons_singleton ()->use_utf8)
#define useUtf8Curvy (r_cons_singleton ()->use_utf8_curvy)

#define W(y) r_cons_canvas_write (c, y)
#define G(x, y) r_cons_canvas_gotoxy (c, x, y)

R_API void r_cons_canvas_free(RConsCanvas *c) {
	if (c) {
		if (c->b) {
			int y;
			for (y = 0; y < c->h; y++) {
				eprintf ("Freeing %d (%d)\n", y, c->bsize[y]);
				free (c->b[y]);
			}
			free (c->b);
		}
		free (c->bsize);
		free (c->blen);
		free (c->attrs);
		free (c);
	}
}

R_API void r_cons_canvas_clear(RConsCanvas *c) {
	if (c && c->b) {
		int y;
		for (y = 0; y < c->h; y++) {
			memset (c->b[y], '\n', c->bsize[y]);
		}

		/*//XXX tofix*/
		if (c->attrs) {
			c->attrslen = 0;
			eprintf ("clear %d\n", sizeof (*c->attrs) * (c->w + 1) * c->h);
			memset (c->attrs, 0, sizeof (*c->attrs) * (c->w + 1) * c->h);
		}
	}
}

static bool _is_ansi_seq(const char *s) {
	return s && s[0] == 033 && s[1] == '[';
}

static int _get_piece(const char *p, char *chr) {
	const char *q = p;
	if (!p) {
		return 0;
	}
	while (p && *p && *p != '\n' && ! _is_ansi_seq (p)) {
		p++;
	}
	if (chr) {
		*chr = *p;
	}
	return p - q;
}

static char * _prefixline(RConsCanvas *c, int *left) {

	if (!c) {
		return NULL;
	}
	if (left) {
		*left =  c->blen[c->y] - c->x;
	}

	return c->b[c->y] + c->x; //XXX check this

	//XXX probably wrong, check below

	/*if (!c) {*/
		/*return NULL;*/
	/*}*/
	/*int x, len;*/
	/*char *p;*/
	/*int b_len = c->w * c->h;*/
	/*int yxw = c->y * c->w;*/
	/*if (b_len < yxw) {*/
		/*return NULL;*/
	/*}*/
	/*p = c->b + yxw;*/
	/*len = b_len - yxw - 1;*/
	/*for (x = 0; (p[x] && x < c->x) && x < len; x++) {*/
		/*if (p[x] == '\n') {*/
			/*p[x] = ' ';*/
		/*}*/
	/*}*/
	/*if (left) {*/
		/**left = c->w - c->x;*/
	/*}*/
	/*return p + x;*/
}

//XXX todo
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

//XXX todo
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

//XXX todo
static void stamp_attr(RConsCanvas *c, int length) {
	int i;
	const char **s;
	int loc = c->x;
	for (int i = 0; i < c->y; i++) {
		loc += c->blen[i];
	}
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

//XXX todo
/* check for ANSI sequences and use them as attr */
static const char *set_attr(RConsCanvas *c, const char *s) {
	if (!c || !s) {
		return NULL;
	}
	const char *p = s;

	while (_is_ansi_seq (p)) {
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

R_API bool r_cons_canvas_gotoxy(RConsCanvas *c, int x, int y) {
	bool ret = true;
	if (!c) {
		return 0;
	}
	y += c->sy;
	x += c->sx;



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
	/*eprintf ("Went to pos (%d, %d)\n", c->x, c->y);*/
	return ret;
}


R_API RConsCanvas *r_cons_canvas_new(int w, int h) {
	eprintf ("Mi creano. (%d, %d)\n", w, h);
	if (w < 1 || h < 1) {
		return NULL;
	}
	RConsCanvas *c = R_NEW0 (RConsCanvas);
	if (!c) {
		return NULL;
	}
	c->color = 0;
	c->sx = 0;
	c->sy = 0;
	c->b = malloc (sizeof *c->b * h);
	if (!c->b) {
		free (c);
		return NULL;
	}
	c->blen = malloc (sizeof *c->blen * h);
	if (!c->blen) {
		free (c->b);
		free (c);
		return NULL;
	}
	c->bsize = malloc (sizeof *c->bsize * h);
	if (!c->bsize) {
		free (c->blen);
		free (c->b);
		free (c);
		return NULL;
	}
	int i;
	for (i = 0; i < h; i++) {
		c->b[i] = malloc (w + 1);
		c->blen[i] = w;
		c->bsize[i] = w + 1;
		if (!c->b[i]) {
			int j;
			for (j = 0; j < i; j++) {
				free (c->b[i]);
			}
			free (c->bsize);
			free (c->blen);
			free (c->b);
			free (c);
			return NULL;
		}
	}
	c->w = w;
	c->h = h;
	c->x = c->y = 0;
	c->attrslen = 0;
	c->attrs = calloc (sizeof (*c->attrs), (c->w + 1) * c->h + 1);
	eprintf ("start, %d\n", sizeof (*c->attrs) * (c->w + 1) * c->h + 1);
	if (!c->attrs) {
		free (c->b);
		free (c);
		return NULL;
	}
	c->attr = Color_RESET;
	r_cons_canvas_clear (c);
	return c;
}

static int utf8len (const char *s, int n) {
	int i = 0, j = 0;
	while (s[i] && n > 0) {
		if ((s[i] & 0xc0) != 0x80) {
			j++;
		}
		n--;
		i++;
		/*eprintf ("%d %d %d \n", i, j, n);*/
	}
	return j;
}

R_API void r_cons_canvas_write(RConsCanvas *c, const char *s) {
	char *p, ch;
	int orig_x, x, y;
	int left, slen, attr_len, piece_len;
	/*eprintf ("I'm writing: %s \n",s) ;*/

	if (!c || !s || !*s) {
		return;
	}

	int x_padding = utf8len (c->b[c->y], c->x);
	int real_x = c->x + (c->x - x_padding);
	orig_x = c->x;
	c->x = real_x;

	/* split the string into pieces of non-ANSI chars and print them normally,
	** using the ANSI chars to set the attr of the canvas */
	r_cons_break_push (NULL, NULL);
	do {
		const char *s_part = set_attr (c, s);
		ch = 0;
		piece_len = _get_piece (s_part, &ch);
		if (piece_len == 0 && ch == '\0' && s_part == s) {
			break;
		}
		left = 0;
		p = _prefixline (c, &left);
		slen = R_MIN (left, piece_len);
		attr_len = slen <= 0 && s_part != s? 1: slen;
		if (attr_len > 0) {
			stamp_attr (c, attr_len);
		}
		// XXX this is a bug if we scroll in the middle of \033
		x = c->x - c->sx;
		y = c->y - c->sy;



		/*int left;*/
		/*int pad = 0;*/
		/*int ax = c->x;*/
		/*char *k;*/
		/*if (x >= 67) {*/
			/*c->x = 0;*/
			/*k = prefixline (c, &left);*/
			/*pad = x - utf8len (k, x);*/
			/*eprintf ("[%d,%d] {%d} %.*s  ------ %d\n", c->sx, c->sy, pad, x, k, utf8len(k, x));*/
			/*[>x += pad;<]*/
			/*c->x = ax;*/
		/*}*/

		int real_len = r_str_nlen (s_part, slen);
		int utf8_len = utf8len (s_part, slen); //XXX error here, utf8len doesn't take slen
		int padding = real_len - utf8_len;

		if (c->y == 55) {
			eprintf ("real_len (%d), utf8_len(%d), padding(%d), writing: %s\n", real_len, utf8_len, padding, s_part);
		}

		if (padding > 0) {
			if (c->blen[c->y] + padding > c->bsize[c->y]) {
				int oldsize = c->bsize[c->y];
				char * newline = realloc (c->b[c->y], sizeof (*c->b[c->y])*(oldsize * 2)); //XXX should optimize by doubling
				c->bsize[c->y] = oldsize * 2;
				if (!newline) {
					r_cons_canvas_free (c);
				}
				c->b[c->y] = newline;
				eprintf ("Reallocing: %d %d\n", oldsize, c->bsize[c->y]);
			}
			char copy[1000];
			memcpy(copy, c->b[c->y] + c->x + 1, c->blen[c->y] - c->x - 1);
			memcpy(c->b[c->y] + c->x + 1 + padding, copy, c->blen[c->y] - c->x - 1);
			eprintf ("Moving padding (%d), copy: %s\n", padding, copy);
			c->blen[c->y] += padding;
		}

		if (G (x, y)) {
			memcpy (c->b[c->y] + c->x, s_part, slen);
		}
		s = s_part;
		if (ch == '\n') {
			c->y++;
			s++;
			if (*s == '\0' || c->y == c->h) {
				break;
			}
			x_padding = utf8len (c->b[c->y], orig_x);
			real_x = orig_x + (orig_x - x_padding);
			c->x = real_x;
		} else {
			c->x += slen;
		}
		s += piece_len;
	} while (*s && !r_cons_is_breaked ());
	r_cons_break_pop ();
	c->x = orig_x;
}

R_API char *r_cons_canvas_to_string(RConsCanvas *c) {
	int x, y, olen = 0, curlen = 0;
	char *o;
	const char **atr;
	int is_first = true;

	if (!c) {
		return NULL;
	}

	for (y = 0; y < c->h; y++) {
		olen += c->blen[y] + 1;
	}
	o = calloc (1, olen * (CONS_MAX_ATTR_SZ));
	if (!o) {
		return NULL;
	}

	olen = 0;
	for (y = 0; y < c->h; y++) {
		if (!is_first) {
			o[olen++] = '\n';
		}
		is_first = false;
		for (x = 0; x < c->blen[y]; x++) {
			atr = attr_at (c, x + curlen);
			if (atr && *atr) {
				strcat (o, *atr);
				olen += strlen (*atr);
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
				if (c->b[y][x] != '\0') {
					o[olen++] = c->b[y][x];
				} else {
					o[olen++] = ' ';
				}
			}
		}
		curlen += c->blen[y];
	}
	o[olen] = '\0';
	int i = 0;
	/*eprintf ("Yo olen%d beach this written: %s\n", olen, o);*/
	/*for  (i = 0; i < olen; i++) {*/
		/*if (o[i] == '\0') eprintf("A");*/
		/*else if (o[i] != '\n') eprintf ("%c", o[i]);*/
	/*}*/
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
	if (!c || w < 0) {
		return false;
	}
	void *newattrs = NULL;
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
		newline = realloc (c->b[i], sizeof *c->b[i] * (w + 1));
		c->blen[i] = w;
		c->bsize[i] = w + 1;
		if (!newline) {
			int j;
			for (j = 0; j <= i; j++) {
				free (c->b[i]);
			}
			free (c->bsize);
			free (c->blen);
			free (c->b);
			free (c);
			return false;
		}
		c->b[i] = newline;
	}
	newattrs = realloc (c->attrs, sizeof (*c->attrs) * (w + 1) * h + 1);
	if (!newattrs) {
		r_cons_canvas_free (c);
		return false;
	}
	c->attrs = newattrs;
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
			W (vline);
		}
		if (G (x + w - 1, y + i)) {
			W (vline);
		}
	}
	free (row);
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

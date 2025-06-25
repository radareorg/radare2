/* radare2 - LGPL - Copyright 2021-2022 - pancake */

#include <r_cons.h>
#include <r_util/r_print.h>

R_API RConsPixel *r_cons_pixel_new(int w, int h) {
	if (UT32_MUL_OVFCHK (w, h)) {
		return NULL;
	}
	RConsPixel *p = R_NEW (RConsPixel);
	if (!p) {
		return NULL;
	}
	p->w = w;
	p->h = h;
	p->buf_size = ((size_t)w) * h;
	p->buf = calloc (w, h);
	if (!p->buf) {
		free (p);
		return NULL;
	}
	return p;
}

R_API void r_cons_pixel_free(RConsPixel *p) {
	if (p) {
		free (p->buf);
		free (p);
	}
}

R_API ut8 r_cons_pixel_get(RConsPixel *p, int x, int y) {
	R_RETURN_VAL_IF_FAIL (p, 0);
	if (x < 0 || x >= p->w) {
		return 0;
	}
	if (y < 0 || y >= p->h) {
		return 0;
	}
	int pos = x + (y * p->w);
	if (pos > 0 && pos < p->buf_size) {
		return p->buf[pos];
	}
	return 0;
}
R_API void r_cons_pixel_set(RConsPixel *p, int x, int y, ut8 v) {
	R_RETURN_IF_FAIL (p);
	if (x < 0 || x >= p->w) {
		return;
	}
	if (y < 0 || y >= p->h) {
		return;
	}
	int pos = x + (y * p->w);
	if (pos > 0 && pos < p->buf_size) {
		p->buf [pos] = v;
	}
}

R_API void r_cons_pixel_sets(RConsPixel *p, int x, int y, const char *s) {
	R_RETURN_IF_FAIL (p && s);
	RRune ch;
	int cols = 0;
	int h = 0;
	const char *e = s + strlen (s);
	int ll = 0;
	while (*s) {
		if (*s == '\n') {
			h++;
			s++;
			if (ll >= cols) {
				cols = ll;
			}
			ll = 0;
			continue;
		}
		int chsz = r_utf8_decode ((const ut8*)s, e - s, &ch);
		if (chsz < 1) {
			chsz = 1;
		}
		if (*s != ' ' && *s != '\t') {
			r_cons_pixel_set (p, x + (ll / 2), y + (h ), 1);
		}
		s += chsz;
		ll++;
	}
}

R_API void r_cons_pixel_fill(RConsPixel *p, int _x, int _y, int w, int h, int v) {
	R_RETURN_IF_FAIL (p);
	int x, y;
	for (x = _x; x < _x+w; x++) {
		for (y = _y; y < _y+h; y++) {
			int pos = x + (y * p->w);
			if (pos > 0 && pos < p->buf_size) {
				p->buf [pos] = v;
			}
		}
	}
}

R_API char *r_cons_pixel_drain(RConsPixel *p) {
	R_RETURN_VAL_IF_FAIL (p, NULL);
	char *s = r_cons_pixel_tostring (p);
	r_cons_pixel_free (p);
	return s;
}

static int pixel_get(RConsPixel *p, int x, int y) {
	ut8 *X = p->buf + (x + (y * p->w));
	int u = 0;
	u |= (X[0]?_BR00:0);
	u |= (X[1]?_BR01:0);
	X = p->buf + (x + ((y + 1) * p->w));
	u |= (X[0]?_BR10:0);
	u |= (X[1]?_BR11:0);
	X = p->buf + (x + ((y + 2) * p->w));
	u |= (X[0]?_BR20:0);
	u |= (X[1]?_BR21:0);
	X = p->buf + (x + ((y + 3) * p->w));
	u |= (X[0]?_BR30:0);
	u |= (X[1]?_BR31:0);
	return u;
}

R_API char *r_cons_pixel_tostring(RConsPixel *p) {
	R_RETURN_VAL_IF_FAIL (p, NULL);
	RStrBuf *sb = r_strbuf_new (NULL);
	size_t x, y;
	for (y = 0; y < p->h; y += 4) {
		for (x = 0; x < p->w; x += 2) {
			size_t delta = x + ((y + 3) * p->w) + 1;
			if (delta >= p->buf_size) {
				continue;
			}
			int u = pixel_get (p, x, y);
			RBraile b = r_print_braile (u);
			r_strbuf_append (sb, b.str);
		}
		r_strbuf_append (sb, "\n");
	}
	return r_strbuf_drain (sb);
}

static inline void cons_pixel_paint(RCons *cons, RConsPixel *p, int sx, int sy, int x, int y, int cols, int rows) {
	int u = pixel_get (p, x, y);
	if (u) {
		RBraile b = r_print_braile (u);
		int px = sx + (x / 2);
		int py = sy + (y / 4);
		if (px >= 0 && px < cols) {
			if (py >= 0 && py < rows) {
				r_cons_gotoxy (sx + (x / 2), sy + (y / 4));
				// r_cons_print (Color_RESET);
				r_cons_print (b.str);
			}
		}
	}
}

R_API void r_cons_pixel_flush(RCons *cons, RConsPixel *p, int sx, int sy) {
	R_RETURN_IF_FAIL (p);
	int rows, cols = r_cons_get_size (cons, &rows);
	size_t x, y;
	for (y = 0; y + 4 < p->h; y += 4) {
		for (x = 0; x + 2 < p->w; x += 2) {
			cons_pixel_paint (cons, p, sx, sy, x, y, cols, rows);
		}
	}
}

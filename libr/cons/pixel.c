/* radare2 - LGPL - Copyright 2021 - pancake */

#include <r_cons.h>
#include <r_util/r_print.h>

R_API RConsPixel *r_cons_pixel_new(int w, int h) {
	RConsPixel *p = R_NEW (RConsPixel);
	p->w = w;
	p->h = h;
	p->buf_size = w * h;
	p->buf = calloc (w, h);
	return p;
}

R_API void r_cons_pixel_free(RConsPixel *p) {
	if (p) {
		free (p->buf);
		free (p);
	}
}

R_API void r_cons_pixel_set(RConsPixel *p, int x, int y, int v) {
	int pos = x + (y * p->w);
	if (pos > 0 && pos < p->buf_size) {
		p->buf [pos] = v;
	}
}

R_API void r_cons_pixel_fill(RConsPixel *p, int _x, int _y, int w, int h, int v) {
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
	char *s = r_cons_pixel_tostring (p);
	r_cons_pixel_free (p);
	return s;
}

R_API char *r_cons_pixel_tostring(RConsPixel *p) {
	RStrBuf *sb = r_strbuf_new (NULL);
	size_t x, y;
	for (y = 0; y < p->h; y += 4) {
		for (x = 0; x < p->w; x += 2) {
			ut8 *X = p->buf + (x + (y * p->w));
			int u = 0;
			u |= (X[0]?$00:0);
			u |= (X[1]?$01:0);
			X = p->buf + (x + ((y + 1) * p->w));
			u |= (X[0]?$10:0);
			u |= (X[1]?$11:0);
			X = p->buf + (x + ((y + 2) * p->w));
			u |= (X[0]?$20:0);
			u |= (X[1]?$21:0);
			X = p->buf + (x + ((y + 3) * p->w));
			u |= (X[0]?$30:0);
			u |= (X[1]?$31:0);
			RBraile b = r_print_braile (u);
			r_strbuf_append (sb, b.str);
		}
		r_strbuf_append (sb, "\n");
	}
	return r_strbuf_drain (sb);
}

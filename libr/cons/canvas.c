/* radare - LGPL - Copyright 2013 - pancake */

#include <r_cons.h>

R_API void r_cons_canvas_free (RConsCanvas *c) {
	free (c->b);
	free (c);
}

R_API void r_cons_canvas_clear (RConsCanvas *c) {
	int y;
	memset (c->b, '\n', c->blen);
	c->b[c->blen] = 0;
	for (y = 0; y<c->h; y++) 
		c->b[ y * c->w ] = '\n';
}

R_API RConsCanvas* r_cons_canvas_new (int w, int h) {
	RConsCanvas *c;
	if (w<1||h<1)
		return NULL;
	c = R_NEW0 (RConsCanvas);
	if (!c) return NULL;
	c->blen = (w+1)*h;
	c->b = malloc (c->blen+1);
	if (!c->b) {
		free (c);
		return NULL;
	}
	c->w = w;
	c->h = h;
	c->x = c->y = 0;
	r_cons_canvas_clear (c);
	return c;
}

R_API void r_cons_canvas_gotoxy(RConsCanvas *c, int x, int y) {
	if (x<c->w && x>=0)
		c->x = x;
	if (y<c->h && y>=0)
		c->y = y;
}

#if 0
static char *getptr(RConsCanvas *c, int *left) {
	if (left) *left = c->w - c->x;
	return c->b + (c->y * c->w) + c->x;
}
#endif

static char *getrow (char *p, char **n) {
	char *q = strchr (p, '\n');
	if (n) *n = NULL;
	if (q) {
		*q = 0;
		if (n) *n = q+1;
	}
	return p;
}

static char *prefixline(RConsCanvas *c, int *left) {
	int x;
	char *p = c->b + (c->y * c->w);
	for (x = 0; x<c->x; x++) {
		if (p[x] == '\n')
			p[x] = ' ';
	}
	if (left) *left = c->w - c->x;
	return p+x;
}

static void suffixline (char *p, int len) {
	int i;
	char *l = p;
	for (i=0; i<len; i++) {
		if (p[i] != ' ')
			l = p+1;
	}
	*l = '\n';
}

R_API void r_cons_canvas_write(RConsCanvas *c, const char *_s) {
	int left, slen;
	char *line, *n;
	char *p, *s, *str;
	str = s = strdup (_s);
	for (;;) {
		line = getrow (s, &n);
		p = prefixline (c, &left);
		//p = getptr (c, &left);
		slen = R_MIN (left, strlen (line));
		suffixline (p+slen, left);
		strncpy (p, line, slen); 
		if (!n) break;
		s = n;
		r_cons_canvas_gotoxy (c, c->x, c->y+1);
	}
	free (str);
}

R_API char *r_cons_canvas_to_string(RConsCanvas *c) {
	int x, y, olen = 0;
	char *o = malloc (c->blen+(c->h+1));
	char *b = c->b;
	for (y = 0; y<c->h; y++) {
		for (x = 0; x<c->w; x++) {
			int p = x + (y*c->w);
			if (!b[p] || b[p]=='\n')
				break;
			o[olen++] = b[p];
		}
		o[olen++] = '\n';
	}
	o[olen] = 0;
	return o;
}

R_API void r_cons_canvas_print(RConsCanvas *c) {
	char *o = r_cons_canvas_to_string (c);
	r_cons_strcat (o);
	free (o);
}

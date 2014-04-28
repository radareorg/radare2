/* radare - LGPL - Copyright 2013-2014 - pancake */

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
	// XXX may be problematic
	//	*l = '\n';
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
		memcpy (p, line, strlen (s));
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

R_API void r_cons_canvas_resize(RConsCanvas *c, int w, int h) {
	// 
}

R_API void r_cons_canvas_box(RConsCanvas *c, int x, int y, int w, int h) {
	int i;
	char *row = malloc (w+1);
	row[0] = '+';
	memset (row+1, '-', w-2);
	row[w-1] = '+';
	row[w] = 0;
	r_cons_canvas_gotoxy (c, x, y);
	r_cons_canvas_write (c, row);
	r_cons_canvas_gotoxy (c, x, y+h-1);
	r_cons_canvas_write (c, row);

	for (i=1;i<h-1;i++) {
		r_cons_canvas_gotoxy (c, x, y+i);
		r_cons_canvas_write (c, "|");
		r_cons_canvas_gotoxy (c, x+w-1, y+i);
		r_cons_canvas_write (c, "|");
	}
}

R_API void r_cons_canvas_fill(RConsCanvas *c, int x, int y, int w, int h, char ch, int replace) {
	int i;
	char *row = malloc (w+1);
	memset (row, '-', w-2);
	row[w-1] = '+';
	row[w] = 0;
	r_cons_canvas_gotoxy (c, x, y);
	r_cons_canvas_write (c, row);
	r_cons_canvas_gotoxy (c, x, y+h-1);
	r_cons_canvas_write (c, row);

	for (i=1;i<h-1;i++) {
		r_cons_canvas_gotoxy (c, x, y+i);
		r_cons_canvas_write (c, "|");
		r_cons_canvas_gotoxy (c, x+w-1, y+i);
		r_cons_canvas_write (c, "|");
	}
}

#define W(y) r_cons_canvas_write(c,y)
#define G(x,y) r_cons_canvas_gotoxy(c,x,y)

R_API void r_cons_canvas_line (RConsCanvas *c, int x, int y, int x2, int y2, int style) {
	switch (style) {
		// vertical arrow line
	case 0: //
		G (x, y);
		W ("v");
		G (x2, y2);
		W ("V");
		if (x==x2) {
			int i;
			int min = R_MIN (y,y2)+1;
			int max = R_MAX (y,y2);
			for (i=min;i<max;i++) {
				G (x,i);
				W ("|");
			}
		} else {
			// --
			// TODO: find if there's any collision in this line
			int hl = R_ABS(y-y2) / 2;
			int hl2 = R_ABS(y-y2)-hl;
			int i;
			hl--;
			if (y2 > (y+1)) {
				for (i=0;i<hl;i++) {
					G (x,y+i+1);
					W ("|");
				}
				for (i=0;i<hl2;i++) {
					G (x2, y+hl+i+1);
					W ("|");
				}
				int w = R_ABS (x-x2);
				char *row = malloc (w+2);
				if (x>x2) {
					w++;
					row[0] = '.';
					if (w>2)
						memset (row+1, '-', w-2);
					row[w-1] = '\'';
					row[w] = 0;
					G (x2,y+hl+1);
				} else {
					row[0] = '`';
					if (w>1)
						memset (row+1, '-', w-1);
					row[w] = '.';
					row[w+1] = 0;
					G (x,y+1+hl);
				}
				W (row);
			} else  {
				int minx = R_MIN (x, x2);
				//if (y >= y2) {
				int rl = R_ABS (x-x2)/2;
				int rl2 = R_ABS (x-x2)-rl+1;
				int vl = (R_ABS(y-y2))+1;
if (y+1==y2)
					vl--;

				for (i=0;i<vl; i++) {
					G (minx+rl,y2+i);
					W ("|");
				}

				int w = rl;
				char *row = malloc (w+1);
				if (x>x2) {
					row[0] = '.';
					if (w>2)
						memset (row+1, '-', w-2);
					row[w-1] = '.';
					row[w] = 0;
					G (x2,y2-1);
				} else {
					row[0] = '`';
					if (w>2)
						memset (row+1, '-', w-2);
					row[w-1] = '\'';
					row[w] = 0;
					G (x+1,y+1);
				}
				W (row);

				w = rl2;
				if (x>x2) {
					row[0] = '`';
					memset (row+1, '-', w-2);
					row[w-1] = '\'';
					row[w] = 0;
					G (x2+rl, y+1);
				} else {
					row[0] = '.';
					memset (row+1, '-', w-2);
					row[w-1] = '.';
					row[w] = 0;
					G (x+rl, y2-1);
				}
				W (row);
				free (row);
			}
			}
		break;
	}
}

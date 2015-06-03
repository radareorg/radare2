/* radare - LGPL - Copyright 2013-2015 - pancake */

#include <r_cons.h>

#define W(y) r_cons_canvas_write(c,y)
#define G(x,y) r_cons_canvas_gotoxy(c,x,y)

R_API void r_cons_canvas_free (RConsCanvas *c) {
	free (c->b);
	free (c->attrs);
	free (c);
}

R_API void r_cons_canvas_clear (RConsCanvas *c) {
	int y;
	if (c && c->b) {
		memset (c->b, '\n', c->blen);
		c->b[c->blen] = 0;
		for (y = 0; y<c->h; y++)
			c->b[ y * c->w ] = '\n';
		if(c->attrs){
			c->attrslen=0;
			memset (c->attrs, 0, sizeof (*c->attrs)*c->blen);
		}
	}
}

R_API RConsCanvas* r_cons_canvas_new (int w, int h) {
	RConsCanvas *c;
	if (w<1||h<1)
		return NULL;
	c = R_NEW0 (RConsCanvas);
	if (!c) return NULL;
	c->color = 0;
	c->sx = 0;
	c->sy = 0;
	c->blen = (w+1)*h;
	c->b = malloc (c->blen+1);
	if (!c->b) {
		free (c);
		return NULL;
	}
	c->attrslen = 0;
	c->attrs = calloc(sizeof(*c->attrs),c->blen+1);
	if (!c->attrs) {
		free (c->b);
		free (c);
		return NULL;
	}
	c->attr=Color_RESET;
	c->w = w;
	c->h = h;
	c->x = c->y = 0;
	r_cons_canvas_clear (c);
	return c;
}

R_API int r_cons_canvas_gotoxy(RConsCanvas *c, int x, int y) {
	int ret = R_TRUE;
	if (!c) return 0;
	x += c->sx;
	y += c->sy;
	if (x > c->w * 2) return 0;
	if (y > c->h * 2) return 0;
	if (x >= c->w) {
		c->x = c->w;
		ret = R_FALSE;
	}
	if (y >= c->h) {
		c->y = c->h;
		ret = R_FALSE;
	}
	if (x < 0) {
		//c->x = 0;
		ret = R_FALSE;
	}
	if (y < 0) {
		c->y = 0;
		ret = R_FALSE;
	}
	if (x < c->w && x >= 0) c->x = x;
	if (y < c->h && y >= 0) c->y = y;
	return ret;
}

#if 0
static char *getptr(RConsCanvas *c, int *left) {
	if (left) *left = c->w - c->x;
	return c->b + (c->y * c->w) + c->x;
}
#endif

static char *getrow (char *p, char **n) {
	char *q;
	if (!p) return NULL;
	q = strchr (p, '\n');
	if (n) *n = NULL;
	if (q) {
		*q = 0;
		if (n) *n = q+1;
	}
	return p;
}

static char *prefixline(RConsCanvas *c, int *left) {
	int x;
	char *p;
	if (!c) return NULL;
	p = c->b + (c->y * c->w);
	for (x = 0; p[x] && x<c->x; x++) {
		if (p[x] == '\n')
			p[x] = ' ';
	}
	if (left) *left = c->w - c->x;
	return p+x;
}

static const char ** attr_at(RConsCanvas *c,int loc){
	int i, j, delta;
	if (!c->color || c->attrslen==0)
		return NULL;
	j = c->attrslen / 2;
	delta = c->attrslen / 2;
	for (i=0; i<(c->attrslen); i++){
		delta/=2;
		if(delta == 0)
			delta=1;
		if (c->attrs[j].loc == loc)
			return &c->attrs[j].a;
		if(c->attrs[j].loc < loc) {
			j+=delta;
			if(j>=c->attrslen)
				break;
			if(c->attrs[j].loc > loc && delta==1)
				break;
		} else if(c->attrs[j].loc > loc) {
			j-=delta;
			if(j<=0)
				break;
			if(c->attrs[j].loc < loc && delta==1)
				break;
		}
	}
	return NULL;
}

static void sort_attrs(RConsCanvas *c) {
	int i,j;
	RConsCanvasAttr value;
	for (i = 1; i < c->attrslen; i++) {
		value = c->attrs[i];
		for (j = i-1; j>=0 && c->attrs[j].loc>value.loc; j--) {
			c->attrs[j+1] = c->attrs[j];
		}
		c->attrs[j+1] = value;
	}
}

static void stamp_attr(RConsCanvas *c,int length){
	int i;
	const char ** s;
	const int loc = c->x + (c->y * c->w);
	s = attr_at(c, loc);

	if (s) {
		//If theres already an attr there, just replace it.
		*s = c->attr;
	} else {
		c->attrs[c->attrslen].loc = loc;
		c->attrs[c->attrslen].a = c->attr;
		c->attrslen++;
		sort_attrs(c);
	}

	for(i=0;i<length;i++){
		s = attr_at(c,loc+i);
		if(s)
			*s = c->attr;
	}
}

R_API void r_cons_canvas_write(RConsCanvas *c, const char *_s) {
	int left, slen;
	char *p, *s, *str;
	char *line, *n;
	int x;

	if (!c || !_s || !*_s)
		return;
	str = n = strdup (_s);

	do {
		s = n;
		line = getrow (s, &n);
		if (!line)
			break;

		if (*line == '\0' && n)
			continue;

		p = prefixline (c, &left);
		slen = R_MIN (left, strlen (line));
		if (slen < 1)
			break;

		x = c->x - c->sx;
		if (!G (x, c->y - c->sy))
			continue;

		stamp_attr(c, slen);
		memcpy (p, line, slen);

		if (!n) break;
	} while (G (c->x - c->sx, c->y + 1 - c->sy));

	free (str);
}

R_API char *r_cons_canvas_to_string(RConsCanvas *c) {
	int x, y, olen = 0;
	char *o;
	const char* b;
	const char**atr;
	int is_first = R_TRUE;

	if (!c) return NULL;
	b = c->b;
	o = calloc (sizeof(char),
			  (c->w * (c->h + 1)) * (CONS_MAX_ATTR_SZ));
	if (!o) return NULL;
	for (y = 0; y < c->h; y++) {
		if (!is_first) {
			o[olen++] = '\n';
		}
		is_first = R_FALSE;

		for (x = 0; x<c->w; x++) {
			const int p = x + (y * c->w);
			atr = attr_at (c,p);
			if(atr) {
				strcat (o, *atr);
				olen += strlen (*atr);
			}
			if (!b[p] || b[p]=='\n')
				break;
			o[olen++] = b[p];
		}
	}
	o[olen] = '\0';
	return o;
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
	const int blen = (w+1) * h;
	char *b = NULL;
	if (!c || w < 0) return R_FALSE;
	b = realloc (c->b, blen+1);
	if (!b) return R_FALSE;
	c->b = b;
	newbuf = realloc (c->attrs, sizeof (*c->attrs)*blen+1);
	if (!newbuf) {
		free (c->b);
		free (c->attrs);
		return R_FALSE;
	}
	c->attrs = newbuf;
	c->blen = blen;
	c->b = b;
	c->w = w;
	c->h = h;
	c->x = 0;
	c->y = 0;
	r_cons_canvas_clear (c);
	return R_TRUE;
}

R_API void r_cons_canvas_box(RConsCanvas *c, int x, int y, int w, int h, const char *color) {
	int i, x_mod;
	int roundcorners = 0;
	char *row = NULL, *row_ptr;
	char corner = '=';

	if (w < 1 || h<1) return;
	//if (x > c->w*2) return;
	//if (y > c->h*2) return;

	if (color)
		c->attr = color;
	row = malloc (w+1);
	if (!row)
		return;
	row[0] = roundcorners?'.':corner;
	if (w>2)
		memset (row+1, '-', w-2);
	if (w>1)
		row[w-1] = roundcorners?'.':corner;
	row[w] = 0;

	row_ptr = row;
	x_mod = x;
	if (x < -c->sx) {
		x_mod = R_MIN(-c->sx, x_mod + w);
		row_ptr += x_mod - x;
	}
	if (G(x_mod, y)) {
		W(row_ptr);
	}
	if (G(x_mod, y+h-1)) {
		row[0] = roundcorners?'\'':corner;
		row[w-1] = roundcorners?'\'':corner;
		W(row_ptr);
	}

	for (i=1;i<h-1;i++) {
		if (G(x, y+i)) W("|");
		if (G(x+w-1, y+i)) W("|");
	}
	free (row);
	if (color)
		c->attr = Color_RESET;
}

R_API void r_cons_canvas_fill(RConsCanvas *c, int x, int y, int w, int h, char ch, int replace) {
	int i;
	char *row = NULL;

	if (w < 0) return;

	row = malloc (w+1);
	memset (row, ch, w);
	row[w] = 0;

	for (i=0;i<h;i++) {
		if (G(x, y+i))
			W(row);
	}
	free (row);
}

R_API void r_cons_canvas_line (RConsCanvas *c, int x, int y, int x2, int y2, int style) {
	if (c->linemode) {
		r_cons_canvas_line_square (c, x, y, x2, y2, style);
		return;
	} else {
		r_cons_canvas_line_diagonal (c, x, y, x2, y2, style);
	}
}

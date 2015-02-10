/* radare - LGPL - Copyright 2013-2015 - pancake */

#include <r_cons.h>

#define W(y) r_cons_canvas_write(c,y)
#define G(x,y) r_cons_canvas_gotoxy(c,x,y)
/*TODO GWC should be inline*/
#define GWC(x,y,s) do{\
	if(r_cons_canvas_gotoxy(c,x,y)){\
		if(color)\
			r_cons_canvas_attr(c,color);\
		r_cons_canvas_write(c,s);\
		if(color && r_cons_canvas_gotoxy(c,x+1,y))\
			r_cons_canvas_attr(c,Color_RESET);\
	}\
}while(0)

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
			memset (c->attrs, 0, sizeof(*c->attrs)*c->blen);
		}
	}
}

R_API RConsCanvas* r_cons_canvas_new (int w, int h) {
	RConsCanvas *c;
	if (w<1||h<1)
		return NULL;
	c = R_NEW0 (RConsCanvas);
	if (!c) return NULL;
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
		if (c->b)
			free (c->b);
		free (c);
		return NULL;
	}
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
	if (x >= c->w) {
		c->x = c->w;
		ret = R_FALSE;
	}
	if (y >= c->h) {
		c->y = c->h;
		ret = R_FALSE;
	}
	if (x <0) {
		//c->x = 0;
		ret = R_FALSE;
	}
	if (y <0) {
		c->y = 0;
		ret = R_FALSE;
	}
	if (x<c->w && x>=0) c->x = x;
	if (y<c->h && y>=0) c->y = y;
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
	if (!c)
		return NULL;
	p = c->b + (c->y * c->w);
	for (x = 0; x<c->x; x++) {
		if (p[x] == '\n')
			p[x] = ' ';
	}
	if (left) *left = c->w - c->x;
	return p+x;
}

R_API void r_cons_canvas_attr(RConsCanvas *c, const char * attr){
	int i;
	//check to make sure we don't have an attr in the same place
	for( i = 0; i<c->attrslen; i++){
		if( (c->attrs[c->attrslen].x == c->x) &&
		    (c->attrs[c->attrslen].y == c->y) ){
			c->attrs[i].x = c->x;
			c->attrs[i].y = c->y;
			c->attrs[i].a = (char *) attr;
		}
	}

	c->attrs[c->attrslen].x = c->x;
	c->attrs[c->attrslen].y = c->y;
	c->attrs[c->attrslen].a = (char *) attr;
	c->attrslen++;
}

R_API void r_cons_canvas_write(RConsCanvas *c, const char *_s) {
	int left, slen, i, linenum = 0;
	char *p, *s, *str;
	char *line, *n;
	int x, delta;

	if (!c || !_s || !*_s)
		return;
	str = s = strdup (_s);
	for (i=0; ; i++) {
		line = getrow (s, &n);
		if (!line)
			break;
		p = prefixline (c, &left);
		slen = R_MIN (left-1, strlen (line));
		if (slen<1) {
			break;
		}
		if (!G (c->x-c->sx+slen, c->y-c->sy)) {
			// TODO : chop slen
			slen = (c->w - (c->x-c->sx));
			if (slen<1)
				break;
			s = n;
			continue;
		}
		delta = 0;
		x = c->x - c->sx - slen;
		// if (x<0) x = 0;
		if (!G (x, c->y - c->sy))
			continue;
		memcpy (p, line+delta, slen-delta);
		if (!n) break;
		s = n;
		if (!G (c->x-c->sx, c->y+1-c->sy)) {
			break;
		}
		linenum ++;
	}
	free (str);
}

R_API char *r_cons_canvas_to_string(RConsCanvas *c) {
	int x, y, i = 0, olen = 0;
	char *o, *b;
	if (!c) return NULL;
	b = c->b;
	o = calloc (sizeof(char), (c->w*(c->h+1))+(c->attrslen*10));//TODO ew.
	if (!o) return NULL;
	for (y = 0; y<c->h; y++) {
		for (x = 0; x<c->w; x++) {
			int p = x + (y*c->w);
			if (x == c->attrs[i].x && y == c->attrs[i].y){
				if(i<c->attrslen && c->attrs[i].a){
					strcat(o,c->attrs[i].a);
					olen+=strlen(c->attrs[i].a);
					i++;
				}
			}
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
	if (o) {
		r_cons_strcat (o);
		free (o);
	}
}

R_API int r_cons_canvas_resize(RConsCanvas *c, int w, int h) {
	int blen = (w+1)*h;
	char *b = NULL;
	if (!c || w < 0) return R_FALSE;
	b = realloc (c->b, blen+1);
	if (!b) return R_FALSE;
	c->attrs = realloc(c->attrs,sizeof(*c->attrs)*blen+1);
	if (!c->attrs) return R_FALSE;
	c->blen = blen;
	c->b = b;
	c->w = w;
	c->h = h;
	c->x = 0;
	c->y = 0;
	r_cons_canvas_clear (c);
	return R_TRUE;
}

R_API void r_cons_canvas_box(RConsCanvas *c, int x, int y, int w, int h) {
	int i;
	int roundcorners = 0;
	char *row = NULL;
	char corner = '=';

	if (w < 0) return;

	row = malloc (w+1);
	row[0] = roundcorners?'.':corner;
	memset (row+1, '-', w-2);
	row[w-1] = roundcorners?'.':corner;
	row[w] = 0;
	if (G(x, y)) W(row);
	if (G(x, y+h-1)) {
		row[0] = roundcorners?'\'':corner;
		row[w-1] = roundcorners?'\'':corner;
		W(row);
	}

	for (i=1;i<h-1;i++) {
		if (G(x, y+i)) W("|");
		if (G(x+w-1, y+i)) W("|");
	}
	free (row);
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
	int i, onscreen;
	char *c1="v", *c2="V";
	char *color=NULL;
	switch (style) {
	case 0:
		color=Color_BLUE;
		c1="v";
		c2="V";
		break;
	case 1:
		color=Color_GREEN;
		c1="t";
		c2="\\";
		break;
	case 2:
		color=Color_RED;
		c1="f";
		c2="/";
		break;
	}
	GWC(x,y,c1);
	GWC(x2,y2,c2);
	if (x==x2) {
		int min = R_MIN (y,y2)+1;
		int max = R_MAX (y,y2);
		for (i=min; i<max; i++) {
			GWC(x,i,"|");
		}
	} else {
		// --
		// TODO: find if there's any collision in this line
		int hl = R_ABS (y-y2) / 2;
		int hl2 = R_ABS (y-y2)-hl;
		hl--;
		if (y2 > (y+1)) {
			for (i=0;i<hl;i++) {
				GWC(x,y+i+1,"|");
			}
			for (i=0;i<hl2;i++) {
				GWC(x2,y+hl+i+1,"|");
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
				onscreen = G (x2+w,y+hl+1);
				i = G (x2, y+hl+1);
				if (!onscreen)
					onscreen = i;
			} else {
				row[0] = '`';
				row[0] = '\'';//wtf?
				if (w>1)
					memset (row+1, '-', w-1);
				row[w] = '.';
				row[w+1] = 0;
				onscreen = G (x+w,y+1+hl);
				i = G (x,y+1+hl);
				if (!onscreen)
					onscreen = i;
			}
			if (onscreen){
				if(color)
					r_cons_canvas_attr(c,color);
				W (row);
				if(color && G(c->x+1,c->y))
					r_cons_canvas_attr(c,Color_RESET);
			}
			free (row);
		} else  {
			int minx = R_MIN (x, x2);
			//if (y >= y2) 
			int rl = R_ABS (x-x2)/2;
			int rl2 = R_ABS (x-x2)-rl+1;
			int vl = (R_ABS(y-y2))+1;
			if (y+1==y2)
				vl--;

			for (i=0;i<vl; i++) {
				GWC(minx+rl,y2+i,"|");
			}

			int w = rl;
			char *row = malloc (w+1);
			if (x>x2) {
				row[0] = '.';
				if (w>2)
					memset (row+1, '-', w-2);
				if (w>0)
					row[w-1] = '.';
				row[w] = 0;
				onscreen = G (x2,y2-1);
			} else {
				row[0] = '`';
				if (w>2)
					memset (row+1, '-', w-2);
				if (w>0)
					row[w-1] = '\'';
				row[w] = 0;
				onscreen = G (x+1,y+1);
			}
			if (onscreen){
				if(color)
					r_cons_canvas_attr(c,color);
				W (row);
				if(color && G(c->x+1,c->y))
					r_cons_canvas_attr(c,Color_RESET);
			}
			w = rl2;
			free (row);
			row = malloc (rl2+1);
			if (x>x2) {
				row[0] = '`';
				memset (row+1, '-', w-2);
				row[w-1] = '\'';
				row[w] = 0;
				onscreen = G (x2+rl, y+1);
			} else {
				row[0] = '.';
				memset (row+1, '-', w-2);
				row[w-1] = '.';
				row[w] = 0;
				onscreen = G (x+rl, y2-1);
			}
			if (onscreen){
				if(color)
					r_cons_canvas_attr(c,color);
				W (row);
				if(color && G(c->x+1,c->y))
					r_cons_canvas_attr(c,Color_RESET);
			}
			free (row);
		}
	}
}

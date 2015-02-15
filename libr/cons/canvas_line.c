/* radare - LGPL - Copyright 2013-2015 - pancake */

#include <r_cons.h>
#define W(y) r_cons_canvas_write(c,y)
#define G(x,y) r_cons_canvas_gotoxy(c,x,y)

R_API void r_cons_canvas_line_diagonal (RConsCanvas *c, int x, int y, int x2, int y2, int style) {
	const char *c1="v", *c2="V";
	switch (style) {
	case 0:
		c->attr=Color_BLUE;
		c1="v"; 
		c2="V";
		break;
	case 1:
		c->attr=Color_GREEN;
		c1="t";
		c2="\\";
		break;
	case 2:
		c->attr=Color_RED;
		c1="f";
		c2="/";
		break;
	}
	r_cons_canvas_goto_write (c,x,y,c1);
	r_cons_canvas_goto_write (c,x2,y2,c2);
	if(y2<y){
		int tmp = y2;
		y2=y;
		y=tmp;
		tmp=x2;
		x2=x;
		x=tmp;
	}
	char chizzle[2] = {0}; // = '.';//my nizzle
	int dx = abs(x2-x);
        int dy = abs(y2-y);
	int sx = x<x2 ? 1 : -1;
	int sy = y<y2 ? 1 : -1;
	int err = (dx>dy?dx:-dy)/2;
	int e2;
	// TODO: find if there's any collision in this line
loop:
	e2 = err;
	if(e2>-dx){
		*chizzle='_';
		err-=dy;
		x+=sx;
	}
	if(e2<dy){
		*chizzle='|';
		err+=dx;
		y+=sy;
	}
	if((e2<dy) && (e2>-dx)){
		if(sy>0){
			*chizzle=(sx>0)?'\\':'/';
		}else{
			*chizzle=(sx>0)?'/':'\\';
		}
	}
	if(!(x==x2&&y==y2)){
		int i = (*chizzle=='_'&&sy<0) ? 1 : 0;
		r_cons_canvas_goto_write(c,x,y-i,chizzle);
		goto loop;
	}
	c->attr=Color_RESET;
}

R_API void r_cons_canvas_line_square (RConsCanvas *c, int x, int y, int x2, int y2, int style) {
	int i, onscreen;
	switch (style) {
	case 0:
		c->attr=Color_BLUE;
		if (G (x, y))
			W ("v");
		if (G (x2, y2))
			W ("V");
		break;
	case 1:
		c->attr=Color_GREEN;
		if (G (x, y))
			W ("t"); //\\");
		if (G (x2, y2))
			W ("\\");
		break;
	case 2:
		c->attr=Color_RED;
		if (G (x, y))
			W ("f");
		if (G (x2, y2))
			W ("/");
		break;
	}
	if (x==x2) {
		int min = R_MIN (y,y2)+1;
		int max = R_MAX (y,y2);
		for (i=min; i<max; i++) {
			if (G (x,i))
				W ("|");
		}
	} else {
		// --
		// TODO: find if there's any collision in this line
		int hl = R_ABS (y-y2) / 2;
		int hl2 = R_ABS (y-y2)-hl;
		hl--;
		if (y2 > (y+1)) {
			for (i=0;i<hl;i++) {
				if (G (x,y+i+1))
					W ("|");
			}
			for (i=0;i<hl2;i++) {
				if (G (x2, y+hl+i+1))
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
				onscreen = G (x2+w,y+hl+1);
				i = G (x2, y+hl+1);
				if (!onscreen)
					onscreen = i;
			} else {
				row[0] = '`';
				row[0] = '\'';
				if (w>1)
					memset (row+1, '-', w-1);
				row[w] = '.';
				row[w+1] = 0;
				onscreen = G (x+w,y+1+hl);
				i = G (x,y+1+hl);
				if (!onscreen)
					onscreen = i;
			}
			if (onscreen)
				W (row);
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
				if (G (minx+rl,y2+i))
					W ("|");
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
			if (onscreen)
				W (row);
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
			if (onscreen)
				W (row);
			free (row);
		}
	}
	c->attr=Color_RESET;
}

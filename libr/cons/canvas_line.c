/* radare - LGPL - Copyright 2013-2015 - pancake */

#include <r_cons.h>
#define W(y) r_cons_canvas_write(c,y)
#define G(x,y) r_cons_canvas_gotoxy(c,x,y)

enum {
	APEX_DOT = 0,
	DOT_APEX,
	REV_APEX_APEX,
	DOT_DOT
};

static void apply_line_style(RConsCanvas *c, int x, int y, int x2, int y2, int style){
	switch (style) {
	case 0: // Unconditional jump
		c->attr=Color_BLUE;
		if (G (x, y))
			W ("v");
		if (G (x2, y2))
			W ("V");
		break;
	case 1: // Conditional jump, True branch
		c->attr=Color_GREEN;
		if (G (x, y))
			W ("t"); //\\");
		if (G (x2, y2))
			W ("\\");
		break;
	case 2: // Conditional jump, False branch
		c->attr=Color_RED;
		if (G (x, y))
			W ("f");
		if (G (x2, y2))
			W ("/");
		break;
	}
}

R_API void r_cons_canvas_line_diagonal (RConsCanvas *c, int x, int y, int x2, int y2, int style) {
	apply_line_style(c,x,y,x2,y2,style);
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
		if (sy>0){
			*chizzle=(sx>0)?'\\':'/';
		} else {
			*chizzle=(sx>0)?'/':'\\';
		}
	}
	if(!(x==x2&&y==y2)){
		int i = (*chizzle=='_'&&sy<0) ? 1 : 0;
		if(G(x,y-i))
			W(chizzle);
		goto loop;
	}
	c->attr=Color_RESET;
}

static void draw_horizontal_line (RConsCanvas *c,
								  int x, int y,
								  int width,
								  int style) {
	char *l_corner, *r_corner;
	int i;

	if (width <= 0) return;

	switch (style) {
	case APEX_DOT:
		l_corner = "'";
		r_corner = ".";
		break;
	case DOT_APEX:
		l_corner = ".";
		r_corner = "'";
		break;
	case REV_APEX_APEX:
		l_corner = "`";
		r_corner = "'";
		break;
	case DOT_DOT:
	default:
		l_corner = r_corner = ".";
		break;
	}

	if (G (x, y))
		W (l_corner);

	for (i = x + 1; i < x + width - 1; i++)
		if (G (i, y))
			W ("-");

	if (G (x + width - 1, y))
		W (r_corner);
}

static void draw_vertical_line (RConsCanvas *c, int x, int y, int height) {
	int i;
	for (i = y; i < y + height; i++)
		if (G (x, i))
			W ("|");
}

R_API void r_cons_canvas_line_square (RConsCanvas *c, int x, int y, int x2, int y2, int style) {
	int min_x = R_MIN (x, x2);
	int diff_x = R_ABS (x - x2);
	int diff_y = R_ABS (y - y2);

	apply_line_style (c, x, y, x2, y2, style);

	// --
	// TODO: find if there's any collision in this line
	if (y2 - y > 1) {
		int hl = diff_y / 2 - 1;
		int hl2 = diff_y - hl;
		int w = diff_x == 0 ? 0 : diff_x + 1;
		int style = min_x == x ? APEX_DOT : DOT_APEX;

		draw_vertical_line(c, x, y + 1, hl);
		draw_vertical_line(c, x2, y + hl + 1, hl2);
		draw_horizontal_line(c, min_x, y + hl + 1, w, style);
	} else  {
		int rl = diff_x / 2;
		int rl2 = diff_x - rl + 1;
		int vl = y2 - y == 1 ? 1 : diff_y + 1;
		int y_line, style;

		draw_vertical_line(c, min_x + rl, y2, vl);

		y_line = min_x == x ? y + 1 : y2 - 1;
		style = min_x == x ? REV_APEX_APEX : DOT_DOT;
		draw_horizontal_line(c, min_x, y_line, rl + 1, style);

		y_line = min_x == x ? y2 - 1 : y + 1;
		style = min_x == x ? DOT_DOT : REV_APEX_APEX;
		draw_horizontal_line(c, min_x + rl, y_line, rl2, style);
	}

	c->attr = Color_RESET;
}

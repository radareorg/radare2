/* radare - LGPL - Copyright 2013-2016 - pancake */

#include <r_cons.h>
#define W(y) r_cons_canvas_write(c,y)
#define G(x,y) r_cons_canvas_gotoxy(c,x,y)

#define useUtf8 (r_cons_singleton()->use_utf8)

enum {
	APEX_DOT = 0,
	DOT_APEX,
	REV_APEX_APEX,
	DOT_DOT
};

static void apply_line_style(RConsCanvas *c, int x, int y, int x2, int y2,
		RCanvasLineStyle *style){
	RCons *cons = r_cons_singleton ();
	switch (style->color) {
	case LINE_UNCJMP:
		c->attr = cons->pal.graph_trufae;
		break;
	case LINE_TRUE:
		c->attr = cons->pal.graph_true;
		break;
	case LINE_FALSE:
		c->attr = cons->pal.graph_false;
		break;
	case LINE_NONE:
	default:
		c->attr = cons->pal.graph_trufae;
		break;
	}
	if (!c->color) {
		c->attr = Color_RESET;
	}
	switch (style->symbol) {
	case LINE_UNCJMP:
		if (G (x, y)) {
			W ("v");
		}
		break;
	case LINE_TRUE:
		if (G (x, y)) {
			W ("t"); //\\");
		}
		break;
	case LINE_FALSE:
		if (G (x, y)) {
			W ("f");
		}
		break;
	case LINE_NONE:
	default:
		break;
	}
}

R_API void r_cons_canvas_line_diagonal (RConsCanvas *c, int x, int y, int x2, int y2,
		RCanvasLineStyle *style) {
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
	if (e2>-dx) {
		*chizzle='_';
		err-=dy;
		x+=sx;
	}
	if (e2<dy) {
		*chizzle='|';
		err+=dx;
		y+=sy;
	}
	if ((e2<dy) && (e2>-dx)) {
		if (sy > 0){
			*chizzle = (sx > 0)?'\\':'/';
		} else {
			*chizzle = (sx > 0)?'/':'\\';
		}
	}
	if (!(x == x2 && y == y2)) {
		int i = (*chizzle=='_'&&sy<0) ? 1 : 0;
		if(G(x,y-i)) {
			W(chizzle);
		}
		goto loop;
	}
	c->attr = Color_RESET;
}

static void draw_horizontal_line (RConsCanvas *c, int x, int y, int width, int style) {
	const char *l_corner = "?", *r_corner = "?";
	int i;

	if (width < 1) {
		return;
	}

	switch (style) {
	case APEX_DOT:
		if (useUtf8) {
			l_corner = RUNECODESTR_CORNER_BL;
			r_corner = RUNECODESTR_CORNER_TR;
		} else {
			l_corner = "'";
			r_corner = ".";
		}
		break;
	case DOT_APEX:
		if (useUtf8) {
			l_corner = RUNECODESTR_CORNER_TL;
			r_corner = RUNECODESTR_CORNER_BR;
		} else {
			l_corner = ".";
			r_corner = "'";
		}
		break;
	case REV_APEX_APEX:
		if (useUtf8) {
			l_corner = RUNECODESTR_CORNER_BL;
			r_corner = RUNECODESTR_CORNER_BR;
		} else {
			l_corner = "`";
			r_corner = "'";
		}
		break;
	case DOT_DOT:
	default:
		l_corner = r_corner = ".";
		break;
	}

	if (G (x, y)) {
		W (l_corner);
	}

	const char *hline = useUtf8? RUNECODESTR_LINE_HORIZ : "-";
	for (i = x + 1; i < x + width - 1; i++) {
		if (G (i, y)) {
			W (hline);
		}
	}

	if (G (x + width - 1, y)) {
		W (r_corner);
	}
}

static void draw_vertical_line (RConsCanvas *c, int x, int y, int height) {
	int i;
	const char *vline = useUtf8? RUNECODESTR_LINE_VERT : "|";
	for (i = y; i < y + height; i++) {
		if (G (x, i)) {
			W (vline);
		}
	}
}

R_API void r_cons_canvas_line_square (RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style) {
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
		draw_vertical_line (c, x, y + 1, hl);
		draw_vertical_line (c, x2, y + hl + 1, hl2);
		draw_horizontal_line (c, min_x, y + hl + 1, w, style);
	} else  {
		if (y2 == y) {
			draw_horizontal_line (c, min_x, y, diff_x + 1, DOT_DOT);
		} else {
			if (x != x2) {
				draw_horizontal_line (c, min_x, y, diff_x + 1, REV_APEX_APEX);
			}
			draw_vertical_line (c, x2, y2, diff_y);
		}
	}
	c->attr = Color_RESET;
}

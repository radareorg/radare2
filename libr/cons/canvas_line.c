/* radare - LGPL - Copyright 2013-2025 - pancake */

#include <r_cons.h>
#define W(y) r_cons_canvas_write(c,y)
#define G(x,y) r_cons_canvas_gotoxy(c,x,y)

#define DOTTED_LINE_HORIZ "┄"
#define DOTTED_LINE_VERT "┊"

#define DASHED_LINE_VERT "╵"
#define DASHED_LINE_HORIZ "╴"

enum {
	APEX_DOT = 0,
	DOT_APEX,
	REV_APEX_APEX,
	DOT_DOT,
	NRM_DOT,
	NRM_APEX,
	DOT_NRM,
	REV_APEX_NRM,
	NRM_NRM
};

static const char* utf8_line_vert(RCons *cons, int dot_style) {
	if (cons->dotted_lines) {
		switch (dot_style) {
		case DOT_STYLE_NORMAL:      return RUNECODESTR_LINE_VERT;
		case DOT_STYLE_CONDITIONAL: return DOTTED_LINE_VERT;
		case DOT_STYLE_BACKEDGE:    return DASHED_LINE_VERT;
		}
	}
	return RUNECODESTR_LINE_VERT;
}

static const char* utf8_line_horiz(RCons *cons, int dot_style) {
	if (cons->dotted_lines) {
		switch (dot_style) {
		case DOT_STYLE_NORMAL:      return RUNECODESTR_LINE_HORIZ;
		case DOT_STYLE_CONDITIONAL: return DOTTED_LINE_HORIZ;
		case DOT_STYLE_BACKEDGE:    return DASHED_LINE_HORIZ;
		}
	}
	return RUNECODESTR_LINE_HORIZ;
}

static void apply_line_style(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style, int isvert) {
	RCons *cons = c->cons;
	switch (style->color) {
	case LINE_UNCJMP:
		c->attr = cons->context->pal.graph_trufae;
		break;
	case LINE_TRUE:
		c->attr = cons->context->pal.graph_true;
		break;
	case LINE_FALSE:
		c->attr = cons->context->pal.graph_false;
		break;
	case LINE_NONE:
	default:
		c->attr = cons->context->pal.graph_trufae;
		break;
	}
	if (!c->color) {
		c->attr = Color_RESET;
	}
	if (style->ansicolor) {
		c->attr = style->ansicolor;
	}
	switch (style->symbol) {
	case LINE_UNCJMP:
		if (G (x, y)) {
			if (isvert) {
				W ("v");
			} else {
				W (">");
			}
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
	case LINE_NOSYM_VERT:
		if (G (x, y)) {
			W (cons->use_utf8? utf8_line_vert (cons, style->dot_style): "|");
		}
		break;
	case LINE_NOSYM_HORIZ:
		if (G (x, y)) {
			W (cons->use_utf8? utf8_line_horiz (cons, style->dot_style): "-");
		}
		break;
	case LINE_NONE:
	default:
		break;
	}
}

static void draw_horizontal_segment(RConsCanvas *c, int x, int y, int width, const char *unit) {
	const int from = R_MAX (x, -c->sx);
	const int to = R_MIN (x + width, c->w - c->sx);
	const int count = to - from;
	if (count < 1 || !G (from, y)) {
		return;
	}
	const size_t unit_len = strlen (unit);
	size_t len;
	if (r_mul_overflow_size_t (unit_len, count, &len) || len == SIZE_MAX) {
		return;
	}
	char *segment = malloc (len + 1);
	if (!segment) {
		return;
	}
	if (unit_len == 1) {
		memset (segment, *unit, len);
	} else {
		int i;
		for (i = 0; i < count; i++) {
			memcpy (segment + (i * unit_len), unit, unit_len);
		}
	}
	segment[len] = '\0';
	W (segment);
	if (c->color) {
		// Preserve the per-cell attributes of the former one-write-per-cell loop.
		const int loc = (c->y * c->w) + c->x;
		int i;
		for (i = 1; i < count; i++) {
			ht_up_update (c->attrs, loc + i, (void *)c->attr);
		}
	}
	free (segment);
}

static void draw_horizontal_line(RConsCanvas *c, int x, int y, int width, int style, int dot_style) {
	RCons *cons = c->cons;
	const char *l_corner = "?", *r_corner = "?";
	const bool use_utf8 = cons->use_utf8;
	const bool use_utf8_curvy = cons->use_utf8_curvy;

	if (width < 1) {
		return;
	}
	/* do not render offscreen horizontal lines */
	if (y + c->sy < 0) {
		return;
	}
	if (y + c->sy > c->h) {
		return;
	}

	switch (style) {
	case APEX_DOT:
		if (use_utf8) {
			if (use_utf8_curvy) {
				l_corner = RUNECODESTR_CURVE_CORNER_BL;
				r_corner = RUNECODESTR_CURVE_CORNER_TR;
			} else {
				l_corner = RUNECODESTR_CORNER_BL;
				r_corner = RUNECODESTR_CORNER_TR;
			}
		} else {
			l_corner = "'";
			r_corner = ".";
		}
		break;
	case DOT_APEX:
		if (use_utf8) {
			if (use_utf8_curvy) {
				l_corner = RUNECODESTR_CURVE_CORNER_TL;
				r_corner = RUNECODESTR_CURVE_CORNER_BR;
			} else {
				l_corner = RUNECODESTR_CORNER_TL;
				r_corner = RUNECODESTR_CORNER_BR;
			}
		} else {
			l_corner = ".";
			r_corner = "'";
		}
		break;
	case REV_APEX_APEX:
		if (use_utf8) {
			if (use_utf8_curvy) {
				l_corner = RUNECODESTR_CURVE_CORNER_BL;
				r_corner = RUNECODESTR_CURVE_CORNER_BR;
			} else {
				l_corner = RUNECODESTR_CORNER_BL;
				r_corner = RUNECODESTR_CORNER_BR;
			}
		} else {
			l_corner = "`";
			r_corner = "'";
		}
		break;
	case DOT_DOT:
		if (use_utf8) {
			if (use_utf8_curvy) {
				l_corner = RUNECODESTR_CURVE_CORNER_TL;
				r_corner = RUNECODESTR_CURVE_CORNER_TR;
			} else {
				l_corner = RUNECODESTR_CORNER_TL;
				r_corner = RUNECODESTR_CORNER_TR;
			}
		} else {
			l_corner = r_corner = ".";
		}
		break;
	case NRM_DOT:
		if (use_utf8) {
			l_corner = utf8_line_horiz (cons, dot_style);
			if (use_utf8_curvy) {
				r_corner = RUNECODESTR_CURVE_CORNER_TR;
			} else {
				r_corner = RUNECODESTR_CORNER_TR;
			}
		} else {
			l_corner = "-";
			r_corner = ".";
		}
		break;
	case NRM_APEX:
		if (use_utf8) {
			l_corner = utf8_line_horiz (cons, dot_style);
			if (use_utf8_curvy) {
				r_corner = RUNECODESTR_CURVE_CORNER_BR;
			} else {
				r_corner = RUNECODESTR_CORNER_BR;
			}
		} else {
			l_corner = "-";
			r_corner = "'";
		}
		break;
	case DOT_NRM:
		if (use_utf8) {
			if (use_utf8_curvy) {
				l_corner = RUNECODESTR_CURVE_CORNER_TL;
			} else {
				l_corner = RUNECODESTR_CORNER_TL;
			}
			r_corner = utf8_line_horiz (cons, dot_style);
		} else {
			l_corner = ".";
			r_corner = "-";
		}
		break;
	case REV_APEX_NRM:
		if (use_utf8) {
			if (use_utf8_curvy) {
				l_corner = RUNECODESTR_CURVE_CORNER_BL;
			} else {
				l_corner = RUNECODESTR_CORNER_BL;
			}
			r_corner = utf8_line_horiz (cons, dot_style);
		} else {
			l_corner = "`";
			r_corner = "-";
		}
		break;
	case NRM_NRM:
	default:
		if (use_utf8) {
			l_corner = r_corner = utf8_line_horiz (cons, dot_style);
		} else {
			l_corner = r_corner = "-";
		}
		break;
	}

	if (G (x, y)) {
		W (l_corner);
	}

	const char *hline = use_utf8? utf8_line_horiz (cons, dot_style): "-";
	draw_horizontal_segment (c, x + 1, y, width - 2, hline);

	if (G (x + width - 1, y)) {
		W (r_corner);
	}
}

static void draw_vertical_line(RConsCanvas *c, int x, int y, int height, int dot_style) {
	int i;
	RCons *cons = c->cons;
	/* do not render offscreen vertical lines */
	if (x + c->sx < 0) {
		return;
	}
	if (x + c->sx > c->w) {
		return;
	}
	const char *vline = cons->use_utf8? utf8_line_vert (cons, dot_style): "|";
	r_cons_break_push (c->cons, NULL, NULL);
	for (i = y; i < y + height; i++) {
		if (r_cons_is_breaked (c->cons)) {
			break;
		}
		if (G (x, i)) {
			W (vline);
		}
	}
	r_cons_break_pop (c->cons);
}

R_API void r_cons_canvas_line_diagonal(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style) {
	if (x == x2 || y == y2) {
		style->dot_style = DOT_STYLE_NORMAL;
		r_cons_canvas_line_square (c, x, y +1, x2, y2, style);
		return;
	}
	apply_line_style (c, x, y, x2, y2, style, 1);
	if (y2 < y) {
		int tmp = y2;
		y2 = y;
		y = tmp;
		tmp = x2;
		x2 = x;
		x = tmp;
	}
	char chizzle[2] = {0}; // = '.';//my nizzle
	// destination
	int dx = abs (x2-x);
	int dy = abs (y2-y);
	// source
	int sx = (x < x2) ? 1 : -1;
	int sy = (y < y2) ? 1 : -1;

	int err = (dx > (dy?dx:-dy)) / 2;
	int e2;

	// TODO: find if there's any collision in this line
loop:
	e2 = err;
	if (e2 > -dx) {
		*chizzle = '_';
		err -= dy;
		x+=sx;
	}
	if (e2 < dy) {
		*chizzle='|';
		err += dx;
		y += sy;
	}
	if ((e2 < dy) && (e2 > -dx)) {
		if (sy > 0) {
			*chizzle = (sx > 0)?'\\':'/';
		} else {
			*chizzle = (sx > 0)?'/':'\\';
		}
	}
	if (!(x == x2 && y == y2)) {
		int i = (*chizzle == '_' && sy < 0) ? 1 : 0;
		if (G(x, y - i)) {
			if (c->cons->use_utf8) {
				switch (*chizzle) {
				case '/':
					W("╯");
					break;
				case '\\':
					W("└");
					break;
				case '|':
					W("│");
					break;
				case '_':
					W("─");
					break;
				default:
					W("?");
					break;
				}
			} else {
				W(chizzle);
			}
		}
		goto loop;
	}
	if (dx) {
		if (dy && (dx / dy) < 1) {
			if (G(x, y)) {
				W("|");
			}
		}
		if (G(x, y + 1)) {
			W("|");
		}
	}
	c->attr = Color_RESET;
}

R_API void r_cons_canvas_line_square(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style) {
	int min_x = R_MIN (x, x2);
	int diff_x = R_ABS (x - x2);
	int diff_y = R_ABS (y - y2);

	apply_line_style (c, x, y, x2, y2, style, 1);

	// --
	// TODO: find if there's any collision in this line
	if (y2 - y > 1) {
		int hl = diff_y / 2 - 1;
		int hl2 = diff_y - hl;
		int w = diff_x == 0 ? 0 : diff_x + 1;
		int apex_style = min_x == x ? APEX_DOT : DOT_APEX;
		draw_vertical_line (c, x, y + 1, hl, style->dot_style);
		draw_vertical_line (c, x2, y + hl + 1, hl2, style->dot_style);
		draw_horizontal_line (c, min_x, y + hl + 1, w, apex_style, style->dot_style);
	} else  {
		if (y2 == y) {
			draw_horizontal_line (c, min_x, y, diff_x + 1, DOT_DOT, style->dot_style);
		} else {
			if (x != x2) {
				draw_horizontal_line (c, min_x, y, diff_x + 1, REV_APEX_APEX, style->dot_style);
			}
			draw_vertical_line (c, x2, y2, diff_y, style->dot_style);
		}
	}
	c->attr = Color_RESET;
}

R_API void r_cons_canvas_line_square_defined(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style, int bendpoint, int isvert) {
	if (!c->linemode) {
		r_cons_canvas_line (c, x, y, x2, y2, style);
		return;
	}
	int min_x = R_MIN (x, x2);
	int diff_x = R_ABS (x - x2);
	int diff_y = R_ABS (y - y2);
	int min_y = R_MIN (y, y2);

	apply_line_style (c, x, y, x2, y2, style, isvert);

	if (isvert) {
		if (x2 == x) {
			draw_vertical_line (c, x, y + 1, diff_y + 1, style->dot_style);
		} else if (y2 - y > 1) {
			int h1 = 1 + bendpoint;
			int h2 = diff_y - h1;
			int w = diff_x == 0 ? 0 : diff_x + 1;
			int apex_style = min_x == x ? APEX_DOT : DOT_APEX;
			draw_vertical_line (c, x, y + 1, h1, style->dot_style);
			draw_horizontal_line (c, min_x, y + bendpoint + 2, w, apex_style, style->dot_style);
			draw_vertical_line (c, x2, y + h1 + 1 + 1, h2, style->dot_style);
		} else {
			//TODO: currently copy-pasted
			if (y2 == y) {
				draw_horizontal_line (c, min_x, y, diff_x + 1, DOT_DOT, style->dot_style);
			} else {
				if (x != x2) {
					draw_horizontal_line (c, min_x, y, diff_x + 1, REV_APEX_APEX, style->dot_style);
				}
				draw_vertical_line (c, x2, y2, diff_y-2, style->dot_style);
			}
		}
	} else {
		if (y2 == y) {
			draw_horizontal_line (c, min_x + 1, y, diff_x, NRM_NRM, style->dot_style);
		} else if (x2 - x > 1) {
			int w1 = 1 + bendpoint;
			int w2 = diff_x - w1;
			//int h = diff_x;// == 0 ? 0 : diff_x + 1;
			//int style = min_x == x ? APEX_DOT : DOT_APEX;
			//draw_vertical_line (c, x, y + 1, h1);
			draw_horizontal_line (c, x + 1, y, w1 + 1, y2 > y ? NRM_DOT : NRM_APEX, style->dot_style);
			//draw_horizontal_line (c, min_x, y + bendpoint + 2, w, style);
			draw_vertical_line (c, x + 1 + w1, min_y + 1, diff_y - 1, style->dot_style);
			//draw_vertical_line (c, x2, y + h1 + 1 + 1, h2);
			draw_horizontal_line (c, x + 1 + w1, y2, w2, y2 < y ? DOT_NRM : REV_APEX_NRM, style->dot_style);
		}
	}
	c->attr = Color_RESET;
}

R_API void r_cons_canvas_line_back_edge(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style, int ybendpoint1, int xbendpoint, int ybendpoint2, int isvert) {
	if (!c->linemode) {
		r_cons_canvas_line (c, x, y, x2, y2, style);
		return;
	}
	int min_x1 = R_MIN (x, xbendpoint);
	int min_x2 = R_MIN (x2, xbendpoint);

	int diff_x1 = R_ABS (x - xbendpoint);
	int diff_x2 = R_ABS (x2 - xbendpoint);

	int diff_y = R_ABS ((y + ybendpoint1 + 1) - (y2 - ybendpoint2- 1));

	int w1 = diff_x1 == 0 ? 0 : diff_x1 + 1;
	int w2 = diff_x2 == 0 ? 0 : diff_x2 + 1;

	apply_line_style (c, x, y, x2, y2, style, isvert);

	if (isvert) {
		draw_vertical_line (c, x, y + 1, ybendpoint1 + 1, style->dot_style);
		draw_horizontal_line (c, min_x1, y + ybendpoint1 + 2, w1, REV_APEX_APEX, style->dot_style);
		draw_vertical_line (c, xbendpoint, y2 - ybendpoint2 + 1, diff_y - 1, style->dot_style);
		draw_horizontal_line (c, min_x2, y2 - ybendpoint2, w2, DOT_DOT, style->dot_style);
		draw_vertical_line (c, x2, y2 - ybendpoint2 + 1, ybendpoint2 + 1, style->dot_style);
	} else {
		int miny1 = R_MIN (y, xbendpoint);
		int miny2 = R_MIN (y2, xbendpoint);
		int diff_y1 = R_ABS (y - xbendpoint);
		int diff_y2 = R_ABS (y2 - xbendpoint);

		draw_horizontal_line (c, x + 1, y, 1 + ybendpoint1 + 1, xbendpoint > y ? NRM_DOT : NRM_APEX, style->dot_style);
		draw_vertical_line (c, x + 1 + ybendpoint1 + 1, miny1 + 1, diff_y1 - 1, style->dot_style);
		draw_horizontal_line (c, x2 - ybendpoint2, xbendpoint, (x + 1 + ybendpoint1 + 1) - (x2 - ybendpoint2) + 1, xbendpoint > y ? REV_APEX_APEX : DOT_DOT, style->dot_style);
		draw_vertical_line (c, x2 - ybendpoint2, miny2 + 1, diff_y2 - 1, style->dot_style);
		draw_horizontal_line (c, x2 - ybendpoint2, y2, ybendpoint2 + 1, xbendpoint > y ? DOT_NRM : REV_APEX_NRM, style->dot_style);
	}
}

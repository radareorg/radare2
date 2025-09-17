/* radare - LGPL - Copyright 2025 - pancake */

#include <r_core.h>

typedef struct {
	RCore *core;
	RConsCanvas *can;
	int cols;
	int rows;
	int box_h;
	int w;
	int h;
	int scroll_x;
	int scroll_y;
} RVMatrix;

static void draw_scrollbar(RVMatrix *rvm) {
	RConsCanvas *can = rvm->can;
	int i;
	int w = rvm->w - 3;
	int h = rvm->h - 2;
	int total_h = rvm->rows * rvm->box_h;
	int sbpos = rvm->scroll_y * rvm->h / total_h;
	for (i = 1; i < h; i++) {
		const char *box = (i == sbpos) ?"|#|": "|.|";
		r_cons_canvas_write_at (can, box, w, i);
	}
	r_cons_canvas_write_at (can, "[^]", w, 0);
	r_cons_canvas_write_at (can, Color_INVERT"[v]"Color_RESET, w, h - 1);
#if 0
	r_strf_var (xxx, 128, "(%d)", sbpos);
	r_cons_canvas_write_at (can, xxx, 5, 5);
#endif
}

static void vmatrix_refresh(RVMatrix *rvm) {
	RCons *cons = rvm->core->cons;
	int h, w = r_cons_get_size (cons, &h);
	rvm->h = h;
	rvm->w = w;
	RConsCanvas *can = r_cons_canvas_new (cons, w, h - 1, -2);
	rvm->can = can;
	RListIter *iter;
	w -= 6;
	int boxwidth = w / rvm->cols;
	int xpos = 0;
	int ypos = -rvm->scroll_y;
	RAnalFunction *f;
	int col = 0;
	RList *fcns = rvm->core->anal->fcns;
	rvm->rows = r_list_length (fcns) / rvm->cols;
	r_list_foreach (fcns, iter, f) {
		r_cons_canvas_box (can, xpos, ypos, boxwidth, rvm->box_h, ""); // Color_RED);
		char *fname = r_str_ndup (f->name, boxwidth - 4);
		r_cons_canvas_write_at (can, fname, xpos + 2, ypos + 1);
		xpos += boxwidth + 1;
		col++;
		if (col >= rvm->cols) {
			ypos += rvm->box_h;
			xpos = 0;
			col = 0;
		}
	}
	draw_scrollbar (rvm);

	char *s = r_cons_canvas_tostring (can);
	r_cons_clear00 (cons);
	r_cons_printf (cons, "[0x%08"PFMT64x"\n%s", rvm->core->addr, s);
	r_cons_visual_flush (cons);
}

R_API void r_core_visual_matrix(RCore *core) {
	RVMatrix rvm = {
		.core = core,
		.cols = 4,
		.box_h = 10,
	};
	r_cons_set_raw (core->cons, true);
	bool leave = false;
	while (!leave) {
		vmatrix_refresh (&rvm);
		char ch = r_cons_readchar (core->cons);
		ch = r_cons_arrow_to_hjkl (core->cons, ch);
		switch (ch) {
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			rvm.cols = ch - '0';
			break;
		case '+':
			rvm.box_h++;
			break;
		case '-':
			rvm.box_h--;
			if (rvm.box_h < 2) {
				rvm.box_h = 2;
			}
			break;
		case '_':
			// filter
			break;
		case 'j':
			rvm.scroll_y ++;
			break;
		case 'k':
			rvm.scroll_y --;
			if (rvm.scroll_y < 0) {
				rvm.scroll_y = 0;
			}
			break;
		case 'J':
			rvm.scroll_y += rvm.box_h;
			break;
		case 'K':
			rvm.scroll_y -= rvm.box_h;
			if (rvm.scroll_y < 0) {
				rvm.scroll_y = 0;
			}
			break;
		case 'g':
			rvm.scroll_y = 0;
			break;
		case 'G':
			rvm.scroll_y = rvm.rows*rvm.box_h - 1;
			break;
		case 'l':
		case 'h':
			break;
		case 'q':
			leave = true;
			break;
		}
	}
	r_cons_set_raw (core->cons, false);
}

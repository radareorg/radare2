/* radare2 - LGPL - Copyright 2021 - pancake */

#include <r_cons.h>

typedef struct r_cons_ui_attributes_t {
	int w;
	int h;
} RConsUIAttributes;

typedef struct r_cons_ui_element_t {
	int x;
	int y;
	int w;
	int h;
	bool center_x;
	bool center_y;
	bool focusable;
	bool scrollable;
	char *buf;
} RConsUIElement;

typedef struct r_cons_ui_t {
	RConsUIElement node;
	RList *children;
	RConsUIAttributes attr;
} RConsUI;

R_API RConsUI *r_cons_ui() {
	RConsUI *ui = R_NEW0 (RConsUI);
	ui->node.x = 0;
	ui->node.y = 0;
	ui->node.w = -1;
	ui->node.h = -1;
	ui->node.center_x = false;
	ui->node.center_y = false;
	return ui;
}

R_API r_cons_ui_render(RConsUI *ui, RConsUIElement *parent, RConsUIElement *node) {
	RConsUIElement e = *node;
	// restrict widet within parent boundaries
	r_cons_ui_element_render (&e);
}

R_API char *r_cons_ui_tostring(RConsUI *ui) {
	RListIter *iter;
	RConsUIElement *parent = &ui->node;
	RConsUIElement *e;
	r_list_foreach (ui->children, iter, e) {
		r_cons_ui_render (ui, parent, e);
	}
	return strdup (ui);
}

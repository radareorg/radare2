/* radare2 - LGPL - Copyright 2021 - pancake */

#include <r_cons.h>
#include <r_cons_ui.h>

R_API RConsUI *r_cons_ui_new() {
	RConsUI *ui = R_NEW0 (RConsUI);
	int h, w = r_cons_get_size (&h);
	ui->attr.w = w;
	ui->attr.h = h;
	ui->canvas = r_cons_canvas_new (w, h);
	ui->root.x = 0;
	ui->root.y = 0;
	ui->root.w = -1;
	ui->root.h = -1;
	ui->root.center_x = false;
	ui->root.center_y = false;
	return ui;
}

R_API int r_cons_ui_run(RConsUI *ui) {
	char ch;
	int ret = 0;
	bool notdone = true;
	while (notdone) {
		int h, w = r_cons_get_size (&h);
		if (w != ui->attr.w || h != ui->attr.h) {
			r_cons_canvas_resize (ui->canvas, w, h);
			ui->attr.w = w;
			ui->attr.h = h;
		}
		r_cons_canvas_print (ui->canvas);
		r_cons_flush ();
		r_cons_enable_mouse (true);
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch);
		switch (ch) {
		case 'q':
			notdone = false;
			break;
		}
	}
	return ret;
}


static void ui_layout(RConsUI *ui) {
	// measure the size of every element and adjust bounds
}

static const char *get(RConsUI *ui, const char *path, const char *k) {
	char *k = r_str_newf ("%s.%s.%s", ui->name, path, k);
	const char *s = sdb_const_get (ui->db, k);
	free (k);
	return s;
}

static int get_width(RConsUI *ui, const char *path) {
	const char *type = get (ui, path, "type");
	if (!strcmp (type, "button")) {
		const char *text = get (ui, path, "text");
		return text? strlen (text) + 4: 5;
	}
	if (!strcmp (type, "label")) {
		const char *text = get (ui, path, "text");
		return text? strlen (text) + 2: 2;
	}
	return 2;
}

static const char *get_height(RConsUI *ui, const char *path) {
	const char *type = get (ui, path, "type");
	if (!strcmp (type, "label")) {
		const char *text = get (ui, path, "text");
		return r_str_char_count (text, '\n') + 1;
	}
	if (!strcmp (type, "textarea")) {
		return 5;
	}
	return 1;
}

static void ui_render(RConsUI *ui, const char *path) {
	const char *type = get_type (ui, path);
	eprintf ("==> %s\n", type);
}

R_API char *r_cons_ui_tostring(RConsUI *ui) {
	RListIter *iter;
	ui_layout (ui);
	ui_render (ui, "");

	return r_cons_canvas_to_string (ui->canvas);
}

#if 0

int main() {
	RConsUI *ui = r_cons_ui_new ();
	RConsUIElement *w = r_cons_ui_window ("Demo");
	RConsUIElement *l = r_cons_ui_label ("Hello World"));
	RConsUIElement *b = r_cons_ui_button ("Accept"));
	// Add the window into the ui so it knows its boundaries
	// ui << w
	r_cons_ui_add (ui->root, w);
	// construct the Window contents
	// w << l
	r_cons_ui_add (w, l);
	r_cons_ui_add (w, b);
	r_cons_ui_run (ui);
	r_cons_ui_free (ui);
}


#endif

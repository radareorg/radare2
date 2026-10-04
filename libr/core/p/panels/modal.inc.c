/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

static bool r_panels_draw_modal(RCore *core, RModal *modal, int range_end, int start, const char *name) {
	if (start < modal->offset) {
		return true;
	}
	if (start >= range_end) {
		return false;
	}
	if (start == modal->idx) {
		r_strbuf_appendf (modal->data, ">  %s%s"Color_RESET, PANEL_HL_COLOR, name);
	} else {
		r_strbuf_appendf (modal->data, "   %s", name);
	}
	r_strbuf_append (modal->data, "          \n");
	return true;
}

static void r_panels_update_modal(RCore *core, RModal *modal, int delta) {
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	modal->data = r_strbuf_new (NULL);
	int count = n_modal_entries;
	const int list_h = R_MAX (modal->pos.h - 1, 1);
	if (modal->idx >= count) {
		modal->idx = 0;
		modal->offset = 0;
	} else if (modal->idx >= modal->offset + list_h) {
		if (modal->offset + list_h >= count) {
			modal->offset = 0;
			modal->idx = 0;
		} else {
			modal->offset += delta;
		}
	} else if (modal->idx < 0) {
		modal->offset = R_MAX (count - list_h, 0);
		modal->idx = count - 1;
	} else if (modal->idx < modal->offset) {
		modal->offset -= delta;
	}
	int i;
	int max_h = R_MIN (modal->offset + list_h, count);
	for (i = 0; i < n_modal_entries; i++) {
		if (!r_panels_draw_modal (core, modal, max_h, i, modal_entries[i].name)) {
			break;
		}
	}
	r_cons_gotoxy (core->cons, 0, 0);
	r_cons_canvas_fill (can, modal->pos.x, modal->pos.y, modal->pos.w + 2, modal->pos.h + 2, ' ');
	(void)r_cons_canvas_gotoxy (can, modal->pos.x + 2, modal->pos.y + 2);
	r_cons_canvas_write (can, r_strbuf_get (modal->data));
	r_strbuf_free (modal->data);

	r_cons_canvas_box (can, modal->pos.x, modal->pos.y, modal->pos.w + 2, modal->pos.h + 2, PANEL_HL_COLOR);
	(void)r_cons_canvas_gotoxy (can, modal->pos.x + 2, modal->pos.y + 1);
	r_cons_canvas_write (can, PANEL_HL_COLOR);
	r_cons_canvas_write (can, "[q]"Color_RESET" Select frame contents");

	print_notch (core);
	r_cons_canvas_print (can);
	r_cons_flush (core->cons);
	r_panels_show_cursor (core);
}

static void r_panels_exec_modal(RCore *core, RPanel *panel, RModal *modal, RPanelLayout dir) {
	if (modal->idx >= 0 && modal->idx < n_modal_entries) {
		RPanelAlmightyCallback cb = modal_entries[modal->idx].cb;
		if (cb) {
			cb (core, panel, dir, modal_entries[modal->idx].name);
		}
	}
	panel->view->sy = 0;
	panel->view->sx = 0;
}

static void r_panels_delete_modal(RCore *core, RModal *modal) {
	if (modal->idx >= 0 && modal->idx < n_modal_entries) {
		free (modal_entries[modal->idx].name);
		int i;
		for (i = modal->idx; i < n_modal_entries - 1; i++) {
			modal_entries[i] = modal_entries[i + 1];
		}
		n_modal_entries--;
	}
}

static RModal *r_panels_init_modal(void) {
	return R_NEW0 (RModal);
}

static void r_panels_free_modal(RModal **modal) {
	free (*modal);
	*modal = NULL;
}

static void r_panels_create_modal(RCore *core, RPanel *panel) {
	r_panels_set_cursor (core, false);
	const int w = 40;
	const int h = 20;
	const int x = (core->panels->can->w - w) / 2;
	const int y = (core->panels->can->h - h) / 2;
	RModal *modal = r_panels_init_modal ();
	r_panels_set_geometry (&modal->pos, x, y, w, h);
	int okey, key, cx, cy;
	char *word = NULL;
	RCons *cons = core->cons;
	r_panels_update_modal (core, modal, 1);
	while (modal) {
		r_cons_set_raw (cons, true);
		okey = r_cons_readchar (cons);
		key = r_cons_arrow_to_hjkl (cons, okey);
		word = NULL;
		if (cons->mouse_event && !cons->drag_event &&
				(key == 'h' || key == 'l')) {
			continue;
		}
		if (key == INT8_MAX - 1 ||
				(cons->mouse_event && !cons->drag_event && !key)) {
			if (r_cons_get_click (cons, &cx, &cy)) {
				cy -= r_config_get_i (core->config, "scr.notch");
				if ((cx < x || x + w < cx) || ((cy < y || y + h < cy))) {
					key = 'q';
				} else if (cy >= y + 1 && cy <= y + 2 &&
						cx >= x + 1 && cx <= x + 6) {
					key = 'q';
				} else {
					word = r_panels_get_word_from_canvas_for_menu (core, core->panels, cx, cy);
					if (word) {
						RPanelAlmightyCallback cb = NULL;
						int mi;
						for (mi = 0; mi < n_modal_entries; mi++) {
							if (!strcmp (modal_entries[mi].name, word)) {
								cb = modal_entries[mi].cb;
								break;
							}
						}
						if (cb) {
							cb (core, panel, PANEL_LAYOUT_NONE, word);
							r_panels_free_modal (&modal);
							free (word);
							break;
						}
						free (word);
					}
				}
			}
		}
		switch (key) {
		case 'E':
			r_core_visual_colors (core);
			break;
		case 'e':
			{
				r_panels_free_modal (&modal);
				char *cmd = r_panels_show_status_input (core, "New command: ");
				if (R_STR_ISNOTEMPTY (cmd)) {
					replace_cmd (core, cmd, cmd);
				}
				free (cmd);
			}
			break;
		case 'j':
			modal->idx++;
			r_panels_update_modal (core, modal, 1);
			break;
		case 'k':
			modal->idx--;
			r_panels_update_modal (core, modal, 1);
			break;
		case 'J':
			modal->idx += 5;
			r_panels_update_modal (core, modal, 5);
			break;
		case 'K':
			modal->idx -= 5;
			r_panels_update_modal (core, modal, 5);
			break;
		case 'v':
			r_panels_exec_modal (core, panel, modal, PANEL_LAYOUT_VERTICAL);
			r_panels_free_modal (&modal);
			break;
		case 'h':
			r_panels_exec_modal (core, panel, modal, PANEL_LAYOUT_HORIZONTAL);
			r_panels_free_modal (&modal);
			break;
		case ' ':
		case 0x0d:
			r_panels_exec_modal (core, panel, modal, PANEL_LAYOUT_NONE);
			r_panels_free_modal (&modal);
			break;
		case '-':
			r_panels_delete_modal (core, modal);
			r_panels_update_modal (core, modal, 1);
			break;
		case 'q':
		case '"':
			r_panels_free_modal (&modal);
			break;
		}
	}
}

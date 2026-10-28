/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

typedef struct {
	RCore *core;
	RConsCanvas *can;
	RPanelPos pos;
	ut8 keys[UT8_MAX + 1];
	char *lines[UT8_MAX + 1];
	int count;
	int selected;
	int offset;
	int rows;
	bool failed;
} RPanelsMarkModal;

static void r_panels_mark_write(RConsCanvas *can, int x, int y, int width, const char *text) {
	if (width < 1 || x < 0 || y < 0 || y >= can->h) {
		return;
	}
	char *cropped = r_str_ansi_crop (text, 0, 0, width, 1);
	if (cropped) {
		r_cons_canvas_write_at (can, cropped, x, y);
		free (cropped);
	}
}

static bool r_panels_modal_print(RCore *core, RConsCanvas *can, const RPanelPos *pos) {
	char *text = r_cons_canvas_tostring (can);
	if (!text) {
		return false;
	}
	char *line = text;
	int i, notch = r_config_get_i (core->config, "scr.notch");
	for (i = 0; line && i < pos->h; i++) {
		char *next = strchr (line, '\n');
		if (next) {
			*next++ = 0;
		}
		r_cons_gotoxy (core->cons, pos->x + 1, pos->y + notch + i + 1);
		r_cons_print (core->cons, line);
		line = next;
	}
	free (text);
	r_cons_flush (core->cons);
	return true;
}

typedef struct {
	RCore *core;
	RConsCanvas *can;
	RPanelPos pos;
	RPanelsModel model;
	RPanelView view;
	bool failed;
} RPanelsDefineModal;

static bool r_panels_define_draw(RPanelsDefineModal *modal) {
	RCore *core = modal->core;
	int height, width = r_panels_get_size (core, &height);
	RPanelPos *pos = &modal->pos;
	pos->w = R_MIN (modal->model.width + 4, width > 8? width - 4: width);
	pos->h = R_MIN (modal->model.height + 3, height > 8? height - 4: height);
	pos->x = (width - pos->w) / 2;
	pos->y = (height - pos->h) / 2;
	if (!modal->can) {
		modal->can = r_cons_canvas_new (core->cons, pos->w, pos->h, R_CONS_CANVAS_FLAG_INHERIT);
		if (!modal->can) {
			return false;
		}
	} else if (!r_cons_canvas_resize (modal->can, pos->w, pos->h)) {
		return false;
	}
	RConsCanvas *can = modal->can;
	can->color = core->panels->can->color;
	can->attr = Color_RESET;
	r_cons_canvas_background (can, Color_RESET);
	r_cons_canvas_fill (can, 0, 0, pos->w, pos->h, ' ');
	r_cons_canvas_box (can, 0, 0, pos->w, pos->h, PANEL_HL_COLOR);
	modal->view.pos = (RPanelPos) { .w = pos->w, .h = pos->h };
	if (pos->w >= 5 && pos->h >= 4) {
		RPanel panel = { .model = &modal->model.model, .view = &modal->view };
		RConsCanvas *previous = core->panels->can;
		core->panels->can = can;
		r_panels_panel_write_content (core, &panel, panel.model->readOnly, R_MAX (modal->view.sx, 0), false);
		core->panels->can = previous;
	}
	r_panels_mark_write (can, 2, 1, pos->w - 4, "Define [Arrows: pan, PgUp/PgDn, Esc/q: close]");
	return r_panels_modal_print (core, can, pos);
}

static void r_panels_define_resize(void *user) {
	RPanelsDefineModal *modal = user;
	r_panels_do_panels_resize (modal->core);
	modal->failed = !r_panels_define_draw (modal);
}

static int r_panels_define_readchar(RCore *core, const char **lines) {
	RPanelsDefineModal modal = { .core = core };
	RCons *cons = core->cons;
	RConsEvent resize = cons->event_resize;
	void *event_data = cons->event_data;
	bool mouse = cons->mouse;
	int ret = 'q', i;
	RStrBuf text;
	r_strbuf_init (&text);
	for (i = 0; lines[i]; i++) {
		if (!r_strbuf_appendf (&text, "%s\n", lines[i])) {
			r_strbuf_fini (&text);
			goto beach;
		}
	}
	modal.model.model.readOnly = r_strbuf_drain_nofree (&text);
	RPanel panel = { .model = &modal.model.model, .view = &modal.view };
	if (!r_panels_content_index (&panel, panel.model->readOnly)) {
		goto beach;
	}
	cons->event_resize = NULL;
	cons->event_data = &modal;
	cons->event_resize = r_panels_define_resize;
	r_cons_enable_mouse (cons, true);
	while (!modal.failed && r_panels_define_draw (&modal)) {
		int raw = r_cons_readchar (cons);
		if (raw == -1 || raw == 3) {
			break;
		}
		if (raw == 0x1b && !cons->input_state.readbuffer_length) {
			int next = r_cons_readchar_timeout (cons, 100);
			if (next == -1) {
				break;
			}
			char byte = next;
			if (!r_cons_readpush (cons, &byte, 1)) {
				break;
			}
		}
		bool navigation = raw == 0x1b || (ut8)raw == 0x9b;
#if R2__WINDOWS__
		navigation |= cons->is_arrow || cons->mouse_event;
#endif
		int key = navigation? r_cons_arrow_to_hjkl (cons, raw): raw;
		if (!navigation) {
			ret = key;
			break;
		}
		int step = cons->mouse_event? R_CLAMP (r_config_get_i (core->config, "scr.wheel.speed"), 1, UT8_MAX): 1;
		if (cons->mouse_event && (cons->drag_event || (key != 'j' && key != 'k' && key != 'h' && key != 'l'))) {
			int x, y;
			if (!r_cons_get_click (cons, &x, &y)) {
				continue;
			}
			x -= modal.pos.x + 1;
			y -= modal.pos.y + 1 + r_config_get_i (core->config, "scr.notch");
			if (x < 0 || x >= modal.pos.w || y < 0 || y >= modal.pos.h) {
				break;
			}
			int axis;
			for (axis = 0; axis < 2; axis++) {
				RPanelsScrollbar bar;
				if (r_panels_scrollbar_layout (&panel, &bar, axis)
						&& (axis? y == bar.y && x >= bar.x && x < bar.x + bar.length
						: x == bar.x && y >= bar.y && y < bar.y + bar.length)) {
					r_panels_scrollbar_seek (&panel, &bar, (axis? x - bar.x: y - bar.y) - bar.thumb_size / 2);
				}
			}
			continue;
		}
		switch (key) {
		case 'j': modal.view.sy += step; break;
		case 'k': modal.view.sy -= step; break;
		case 'h': modal.view.sx -= step; break;
		case 'l': modal.view.sx += step; break;
		case 'J': modal.view.sy += R_MAX (1, modal.pos.h - 4); break;
		case 'K': modal.view.sy -= R_MAX (1, modal.pos.h - 4); break;
		default: goto beach;
		}
	}
beach:
	cons->event_resize = NULL;
	cons->event_data = event_data;
	cons->event_resize = resize;
	if (cons->mouse != mouse) {
		r_cons_enable_mouse (cons, mouse);
	}
	r_cons_canvas_free (modal.can);
	RPanelsLines_fini (&modal.model.lines);
	free (modal.model.model.readOnly);
	r_panels_do_panels_refresh (core);
	return ret;
}

static bool r_panels_mark_draw(RPanelsMarkModal *modal) {
	RCore *core = modal->core;
	RCons *cons = core->cons;
	int height, width = r_panels_get_size (core, &height);
	RPanelPos *pos = &modal->pos;
	pos->w = R_MIN (80, width > 8? width - 4: width);
	pos->h = R_MIN (20, height > 8? height - 4: height);
	pos->x = (width - pos->w) / 2;
	pos->y = (height - pos->h) / 2;
	if (!modal->can) {
		modal->can = r_cons_canvas_new (cons, pos->w, pos->h, R_CONS_CANVAS_FLAG_INHERIT);
		if (!modal->can) {
			return false;
		}
	} else if (!r_cons_canvas_resize (modal->can, pos->w, pos->h)) {
		return false;
	}
	RConsCanvas *can = modal->can;
	can->color = core->panels->can->color;
	modal->rows = R_MAX (0, pos->h - 4);
	modal->selected = R_CLAMP (modal->selected, 0, R_MAX (0, modal->count - 1));
	if (modal->selected < modal->offset) {
		modal->offset = modal->selected;
	} else if (modal->selected >= modal->offset + modal->rows) {
		modal->offset = modal->selected - modal->rows + 1;
	}
	modal->offset = R_CLAMP (modal->offset, 0, R_MAX (0, modal->count - modal->rows));
	can->attr = Color_RESET;
	r_cons_canvas_background (can, Color_RESET);
	r_cons_canvas_fill (can, 0, 0, pos->w, pos->h, ' ');
	r_cons_canvas_box (can, 0, 0, pos->w, pos->h, PANEL_HL_COLOR);
	char title[64];
	snprintf (title, sizeof (title), "Visual marks [%d-%d/%d]", modal->count? modal->offset + 1: 0,
		R_MIN (modal->offset + modal->rows, modal->count), modal->count);
	r_panels_mark_write (can, 2, 1, pos->w - 10, title);
	r_panels_mark_write (can, pos->w - 7, 1, 5, "[Esc]");
	int i;
	for (i = 0; i < modal->rows && modal->offset + i < modal->count; i++) {
		int index = modal->offset + i;
		bool selected = index == modal->selected;
		can->attr = selected && can->color? cons->context->pal.widget_sel: Color_RESET;
		r_cons_canvas_background (can, can->attr);
		r_cons_canvas_fill (can, 1, i + 2, pos->w - 2, 1, ' ');
		r_panels_mark_write (can, 1, i + 2, 1, selected? ">": " ");
		r_panels_mark_write (can, 3, i + 2, pos->w - 10, modal->lines[index]);
		r_panels_mark_write (can, pos->w - 6, i + 2, 3, "[x]");
	}
	can->attr = Color_RESET;
	r_cons_canvas_background (can, Color_RESET);
	if (!modal->count) {
		r_panels_mark_write (can, 2, 2, pos->w - 4, "No visual marks. Use m<key> to set one.");
	}
	if (modal->rows > 0 && modal->count > modal->rows) {
		int thumb_size = R_MAX (1, modal->rows * modal->rows / modal->count);
		int thumb = modal->offset * (modal->rows - thumb_size) / (modal->count - modal->rows);
		bool utf8 = r_config_get_b (core->config, "scr.utf8");
		for (i = 0; i < modal->rows; i++) {
			bool active = i >= thumb && i < thumb + thumb_size;
			r_panels_mark_write (can, pos->w - 2, i + 2, 1,
				active? (utf8? "█": "#"): (utf8? "│": ":"));
		}
	}
	r_panels_mark_write (can, 2, pos->h - 2, pos->w - 4, "Enter: seek  BS/[x]: unset  Arrows/PgUp/PgDn/Wheel");
	return r_panels_modal_print (core, can, pos);
}

static void r_panels_mark_resize(void *user) {
	RPanelsMarkModal *modal = user;
	r_panels_do_panels_resize (modal->core);
	modal->failed = !r_panels_mark_draw (modal);
}

static void r_panels_mark_delete(RPanelsMarkModal *modal) {
	if (!modal->count) {
		return;
	}
	int i = modal->selected;
	r_core_vmark_del (modal->core, modal->keys[i]);
	free (modal->lines[i]);
	for (; i + 1 < modal->count; i++) {
		modal->keys[i] = modal->keys[i + 1];
		modal->lines[i] = modal->lines[i + 1];
	}
	modal->count--;
}

static int r_panels_vmark_modal(RCore *core) {
	RPanelsMarkModal modal = { .core = core };
	RCons *cons = core->cons;
	RConsEvent resize = cons->event_resize;
	void *event_data = cons->event_data;
	bool mouse = cons->mouse;
	int ret = -1, i;
	for (i = 0; i <= UT8_MAX; i++) {
		ut64 addr = r_core_vmark_get (core, i);
		if (addr == UT64_MAX) {
			continue;
		}
		char key[8];
		if (IS_PRINTABLE (i)) {
			snprintf (key, sizeof (key), "'%c", i);
		} else {
			snprintf (key, sizeof (key), "\\x%02x", i);
		}
		RFlagItem *flag = r_flag_get_at (core->flags, addr, false);
		const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
		char *line = r_str_newf ("[%s] 0x%08"PFMT64x"  %s%s%s", key, addr,
			flag? flag->name: "", R_STR_ISNOTEMPTY (comment)? " ; ": "", r_str_get (comment));
		if (!line) {
			goto beach;
		}
		r_str_replace_char (line, '\n', ' ');
		r_str_replace_char (line, '\r', ' ');
		r_str_replace_char (line, '\t', ' ');
		modal.keys[modal.count] = i;
		modal.lines[modal.count++] = line;
	}
	cons->event_resize = NULL;
	cons->event_data = &modal;
	cons->event_resize = r_panels_mark_resize;
	r_cons_enable_mouse (cons, true);
	while (!modal.failed && r_panels_mark_draw (&modal)) {
		int raw = r_cons_readchar (cons);
		if (raw == -1) {
			break;
		}
		if (raw == 0x1b && !cons->input_state.readbuffer_length) {
			int next = r_cons_readchar_timeout (cons, 100);
			if (next == -1) {
				break;
			}
			char byte = next;
			if (!r_cons_readpush (cons, &byte, 1)) {
				break;
			}
		}
		bool navigation = raw == 0x1b || (ut8)raw == 0x9b;
#if R2__WINDOWS__
		navigation |= cons->is_arrow || cons->mouse_event;
#endif
		int key = navigation? r_cons_arrow_to_hjkl (cons, raw): raw;
		bool mouse_event = navigation && cons->mouse_event;
		int step = mouse_event? R_CLAMP (r_config_get_i (core->config, "scr.wheel.speed"), 1, UT8_MAX): 1;
		if (mouse_event && (cons->drag_event || (key != 'j' && key != 'k'))) {
			int x, y;
			if (cons->drag_event || !r_cons_get_click (cons, &x, &y)) {
				continue;
			}
			x -= modal.pos.x + 1;
			y -= modal.pos.y + 1 + r_config_get_i (core->config, "scr.notch");
			if (x < 0 || x >= modal.pos.w || y < 0 || y >= modal.pos.h
					|| (y == 1 && x >= modal.pos.w - 7)) {
				break;
			}
			if (y < 2 || y >= 2 + modal.rows) {
				continue;
			}
			if (x == modal.pos.w - 2 && modal.count > modal.rows) {
				modal.offset = modal.rows > 1? (y - 2) * (modal.count - modal.rows) / (modal.rows - 1): 0;
				modal.selected = modal.offset;
				continue;
			}
			if (x < 1 || x >= modal.pos.w - 2 || modal.offset + y - 2 >= modal.count) {
				continue;
			}
			modal.selected = modal.offset + y - 2;
			if (x >= modal.pos.w - 6 && x < modal.pos.w - 3) {
				r_panels_mark_delete (&modal);
				continue;
			}
			ret = modal.keys[modal.selected];
			break;
		}
		if (navigation) {
			int delta;
			switch (key) {
			case 'j': delta = step; break;
			case 'k': delta = -step; break;
			case 'J': case 'l': delta = R_MAX (1, modal.rows); break;
			case 'K': case 'h': delta = -R_MAX (1, modal.rows); break;
			default: goto beach;
			}
			modal.selected = R_CLAMP (modal.selected + delta, 0, R_MAX (0, modal.count - 1));
			if (mouse_event || R_ABS (delta) > 1) {
				modal.offset = R_CLAMP (modal.offset + delta, 0, R_MAX (0, modal.count - modal.rows));
				modal.selected = R_MAX (modal.selected, modal.offset);
			}
		} else if (key == 127 || key == 8) {
			r_panels_mark_delete (&modal);
		} else if (key == '\r' || key == '\n') {
			if (modal.count) {
				ret = modal.keys[modal.selected];
				break;
			}
		} else if (key >= 0 && key <= UT8_MAX && r_core_vmark_get (core, key) != UT64_MAX) {
			ret = key;
			break;
		} else if (key == 'q' || key == '\'' || key == 3) {
			break;
		}
	}
beach:
	cons->event_resize = NULL;
	cons->event_data = event_data;
	cons->event_resize = resize;
	if (cons->mouse != mouse) {
		r_cons_enable_mouse (cons, mouse);
	}
	r_cons_canvas_free (modal.can);
	for (i = 0; i < modal.count; i++) {
		free (modal.lines[i]);
	}
	return ret;
}

static void r_panels_draw_modal(RCore *core, RModal *modal, int i, const char *name) {
	if (i == modal->idx) {
		r_strbuf_appendf (modal->data, ">  %s%s"Color_RESET, PANEL_HL_COLOR, name);
	} else {
		r_strbuf_appendf (modal->data, "   %s", name);
	}
	r_strbuf_append (modal->data, "          \n");
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
		modal->offset = R_MAX (modal->offset - delta, 0);
	}
	int i;
	int max_h = R_MIN (modal->offset + list_h, count);
	for (i = modal->offset; i < max_h; i++) {
		r_panels_draw_modal (core, modal, i, modal_entries[i].name);
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
	RCons *cons = core->cons;
	r_panels_update_modal (core, modal, 1);
	while (modal) {
		r_cons_set_raw (cons, true);
		okey = r_cons_readchar (cons);
		key = r_cons_arrow_to_hjkl (cons, okey);
		if (cons->mouse_event && !cons->drag_event &&
				(key == 'h' || key == 'l')) {
			continue;
		}
		if (key == INT8_MAX - 1 ||
				(cons->mouse_event && !cons->drag_event && !key)) {
			if (r_cons_get_click (cons, &cx, &cy)) {
				cx--;
				cy -= r_config_get_i (core->config, "scr.notch") + 1;
				const int title_x = R_MAX (x + 2, 0);
				const int title_y = R_MAX (y + 1, 0);
				const int list_y = R_MAX (y + 2, 0);
				if (cx < x || cx >= x + w + 2 || cy < y || cy >= y + h + 2) {
					key = 'q';
				} else if (cy == title_y) {
					if (cx >= title_x && cx < title_x + 3) {
						key = 'q';
					}
				} else if (cx > x && cx < x + w + 1 && cy >= list_y && cy < y + h + 1) {
					int index = modal->offset + cy - list_y;
					if (index >= 0 && index < n_modal_entries) {
						modal->idx = index;
						r_panels_exec_modal (core, panel, modal, PANEL_LAYOUT_NONE);
						r_panels_free_modal (&modal);
						break;
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

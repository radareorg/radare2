/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

static void print_notch(RCore *core) {
	const int notch = r_config_get_i (core->config, "scr.notch");
	int i;
	for (i = 0; i < notch; i++) {
		r_cons_printf (core->cons, R_CONS_CLEAR_LINE"\n");
	}
}

static void r_panels_bottom_panel_line(RCore *core) {
	RCons *cons = core->cons;
	const bool useUtf8 = core->cons->use_utf8;
	const bool useUtf8Curvy = core->cons->use_utf8_curvy;
	const char *hline = useUtf8? RUNE_LINE_HORIZ : "-";
	const char *bl_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_BL : RUNE_CORNER_BL) : "`";
	const char *br_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_BR : RUNE_CORNER_BR) : "'";
	int i, h, w = r_cons_get_size (cons, &h);
	r_cons_gotoxy (cons, 0, h - 1);
	r_cons_write (cons, bl_corner, strlen (bl_corner));
	for (i = 0; i < w - 2; i++) {
		r_cons_printf (cons, "%s", hline);
	}
	r_cons_write (cons, br_corner, strlen (br_corner));
	r_cons_gotoxy (cons, 0, h);
	r_cons_print (cons, Color_RESET R_CONS_CLEAR_LINE);
}

static void r_panels_canvas_write_bar(RConsCanvas *can, int y, int width, const char *text, char pad) {
	if (width < 1) {
		return;
	}
	char *cropped = r_str_ansi_crop (r_str_get (text), 0, 0, width, 1);
	const char *visible = cropped? cropped: r_str_get (text);
	char *padding = r_str_pad (NULL, 0, pad, R_MAX (width - r_str_ansi_len (visible), 0));
	char *line = r_str_newf ("%s%s"Color_RESET, visible, padding);
	(void)r_cons_canvas_gotoxy (can, -can->sx, y - can->sy);
	r_cons_canvas_write (can, line);
	free (line);
	free (padding);
	free (cropped);
}

static void r_panels_menu_panel_print(RConsCanvas *can, RPanel *panel, int x, int y, int w, int h) {
	(void) r_cons_canvas_gotoxy (can, panel->view->pos.x + 2, panel->view->pos.y + 1);
	char *text = r_str_ansi_crop (panel->model->title, x, y, w, h);
	if (text) {
		r_cons_canvas_write (can, text);
		free (text);
	} else {
		r_cons_canvas_write (can, panel->model->title);
	}
}

static const char *r_panels_rendered_content(RPanel *panel) {
	return panel->model->readOnly? panel->model->readOnly: panel->model->cmdStrCache;
}

static RPanelsModel *r_panels_content_index(RPanel *panel, const char *content) {
	RPanelsModel *model = (RPanelsModel *)panel->model;
	if (!content) {
		return NULL;
	}
	if (model->content == content) {
		return model;
	}
	model->content = NULL;
	model->width = model->height = 0;
	RPanelsLines_clear (&model->lines);
	const char *line = content;
	while (*line) {
		size_t *offset = RPanelsLines_emplace_back (&model->lines);
		if (!offset || model->height == INT_MAX) {
			return NULL;
		}
		*offset = line - content;
		const char *end = strchr (line, '\n');
		if (!end) {
			end = line + strlen (line);
		}
		int width = end == line? 0: R_MIN (r_str_ansi_nlen (line, end - line), INT_MAX);
		model->width = R_MAX (model->width, width);
		model->height++;
		line = *end? end + 1: end;
	}
	size_t *offset = RPanelsLines_emplace_back (&model->lines);
	if (!offset) {
		return NULL;
	}
	*offset = line - content;
	if (content == r_panels_rendered_content (panel)) {
		model->content = content;
	}
	return model;
}

static char *r_panels_crop_content(RPanel *panel, const char *content, int x, int y, int width, int height) {
	RPanelsModel *model = r_panels_content_index (panel, content);
	if (!model || width < 1 || height < 1 || y >= model->height) {
		return NULL;
	}
	const size_t start = *RPanelsLines_at (&model->lines, y);
	const size_t end = *RPanelsLines_at (&model->lines, y + R_MIN (height, model->height - y));
	if (end - start > INT_MAX) {
		return NULL;
	}
	char *rows = r_str_ndup (content + start, end - start);
	char *cropped = rows? r_str_ansi_crop (rows, x, 0, (ut32)x + width, height): NULL;
	free (rows);
	return cropped;
}

static bool r_panels_scrollbar_layout(RPanel *panel, RPanelsScrollbar *bar, bool horizontal) {
	RPanelPos *pos = &panel->view->pos;
	if (panel->model->type == PANEL_TYPE_MENU || (!panel->model->cache && !panel->model->readOnly)
			|| pos->w < 5 || pos->h < 4) {
		return false;
	}
	RPanelsModel *model = r_panels_content_index (panel, r_panels_rendered_content (panel));
	if (!model) {
		return false;
	}
	bool horizontal_scroll = model->width > pos->w - 3;
	bool vertical_scroll = model->height > pos->h - 3 - horizontal_scroll;
	horizontal_scroll |= model->width > pos->w - 3 - vertical_scroll;
	if (!(horizontal? horizontal_scroll: vertical_scroll)) {
		return false;
	}
	bar->horizontal = horizontal;
	bar->x = pos->x + (horizontal? 2: pos->w - 2);
	bar->y = pos->y + (horizontal? pos->h - 2: 2);
	bar->length = horizontal? pos->w - 3 - vertical_scroll: pos->h - 3 - horizontal_scroll;
	const int extent = horizontal? model->width: model->height;
	const int scroll = horizontal? panel->view->sx: panel->view->sy;
	bar->max_scroll = R_MAX (0, extent - bar->length);
	bar->thumb_size = extent > bar->length? R_MAX (1, (st64)bar->length * bar->length / extent): bar->length;
	bar->thumb = bar->max_scroll? (st64)R_MIN (R_MAX (scroll, 0), bar->max_scroll)
		* (bar->length - bar->thumb_size) / bar->max_scroll: 0;
	return bar->length > 0;
}

static void r_panels_panel_write_content(RCore *core, RPanel *panel, const char *content, int sx, bool r_panels_show_cursor) {
	RPanelsScrollbar bars[2];
	bool visible[2];
	const bool bounded = panel->model->type != PANEL_TYPE_MENU && (panel->model->cache || panel->model->readOnly);
	int axis;
	for (axis = 0; axis < 2; axis++) {
		visible[axis] = r_panels_scrollbar_layout (panel, &bars[axis], axis);
		if (bounded) {
			int *scroll = axis? &panel->view->sx: &panel->view->sy;
			*scroll = visible[axis]? R_MIN (R_MAX (*scroll, 0), bars[axis].max_scroll): 0;
		}
	}
	if (bounded && sx >= 0) {
		sx = panel->view->sx;
	}
	const int sy = R_MAX (panel->view->sy, 0);
	const int x = panel->view->pos.x;
	const int y = panel->view->pos.y;
	const int w = panel->view->pos.w - 3 - visible[0];
	const int h = panel->view->pos.h - 3 - visible[1];
	RConsCanvas *can = core->panels->can;
	if (x >= can->w || y >= can->h) {
		return;
	}
	(void) r_cons_canvas_gotoxy (can, x + 2, y + 2);
	char *text = r_panels_crop_content (panel, content, R_MAX (sx, 0), sy, w + R_MIN (sx, 0), h);
	if (sx < 0 && text) {
		char white[129];
		r_str_pad (white, sizeof (white), ' ', R_MIN (-sx, 128));
		char *prefixed = r_str_prefix_all (text, white);
		free (text);
		text = prefixed;
	}
	if (text) {
		r_cons_canvas_write (can, text);
		free (text);
	}
	if (r_panels_show_cursor) {
		int sub = panel->view->curpos - panel->view->sy;
		(void) r_cons_canvas_gotoxy (can, x + 2, y + 2 + sub);
		r_cons_canvas_write (can, "*");
	}
	const bool utf8 = r_config_get_b (core->config, "scr.utf8");
	for (axis = 0; axis < 2; axis++) {
		if (!visible[axis]) {
			continue;
		}
		RPanelsScrollbar *bar = &bars[axis];
		int i;
		for (i = 0; i < bar->length; i++) {
			const bool thumb = i >= bar->thumb && i < bar->thumb + bar->thumb_size;
			(void)r_cons_canvas_gotoxy (can, bar->x + (axis? i: 0), bar->y + (axis? 0: i));
			r_cons_canvas_write (can, thumb? (utf8? "█": "#"): (axis? (utf8? "─": "-"): (utf8? "│": "|")));
		}
	}
}

static void r_panels_update_help_contents(RCore *core, RPanel *panel) {
	r_panels_panel_write_content (core, panel, panel->model->readOnly, panel->view->sx, false);
}

static const char *r_panels_title_foreground(RCore *core) {
	RConsContext *ctx = core->cons->context;
	RColor color = ctx->cpal.widget_bg;
	int brightness = color.a == ALPHA_FGBG
		? 299 * color.r2 + 587 * color.g2 + 114 * color.b2
		: 299 * color.r + 587 * color.g + 114 * color.b;
	if (ctx->color_mode == COLOR_MODE_16) {
		// Use the emitted background because ANSI colors can approximate RGB poorly.
		const char *p = ctx->pal.widget_bg;
		int code = 0;
		for (; *p && *p != 'm'; p++) {
			if (*p == '[' || *p == ';') {
				code = atoi (p + 1);
			}
		}
		if (R_BETWEEN (40, code, 47) || R_BETWEEN (100, code, 107)) {
			int index = code >= 100? code - 100: code - 40;
			int intensity = code >= 100? 255: 128;
			brightness = intensity * (299 * !!(index & 1)
				+ 587 * !!(index & 2) + 114 * !!(index & 4));
			if (code == 47 || code == 100) {
				brightness = 192000;
			}
		}
	}
	return brightness < 128000? Color_WHITE: Color_BLACK;
}

static void r_panels_update_title(RCore *core, RPanel *panel) {
	RConsCanvas *can = core->panels->can;
	RPanelPos *pos = &panel->view->pos;
	int width = pos->w - 2;
	if (width < 1 || !r_cons_canvas_gotoxy (can, pos->x + 1, pos->y + 1)) {
		return;
	}
	bool selected = r_panels_check_if_cur_panel (core, panel);
	const char *name = r_str_get (panel->model->title);
	char *title = selected
		? r_str_newf (PANEL_FRAME_BUTTON" %s", name)
		: r_str_newf (" =  %s   ", name);
	char *cropped = r_str_ansi_crop (title, 0, 0, width, 1);
	free (title);
	if (!cropped) {
		return;
	}
	if (selected) {
		r_str_ansi_strip (cropped);
		char *padding = r_str_pad (NULL, 0, ' ', R_MAX (width - r_str_display_width (cropped), 0));
		if (padding) {
			char *line = r_str_newf (Color_RESET"%s%s%s%s"Color_RESET,
				core->cons->context->pal.widget_bg, r_panels_title_foreground (core), cropped, padding);
			r_cons_canvas_write (can, line);
			free (line);
			free (padding);
		}
	} else {
		r_cons_canvas_write (can, cropped);
	}
	free (cropped);
}

static void r_panels_update_panel_contents(RCore *core, RPanel *panel, const char *cmdstr) {
	bool b = core->print->cur_enabled && r_panels_is_abnormal_cursor_type (core, panel);
	int sx = b ? -2 : panel->view->sx;
	r_panels_panel_write_content (core, panel, cmdstr, sx, b);
}

static void r_panels_update_pdc_contents(RCore *core, RPanel *panel, const char *cmdstr) {
	r_panels_panel_write_content (core, panel, cmdstr, panel->view->sx, false);
}

static void r_panels_setup_help_panel(RCore *core, RPanel *p, const char *title, const char * const *msg) {
	const char *help = "Help";
	free (p->model->title);
	free (p->model->cmd);
	p->model->title = strdup (help);
	p->model->cmd = strdup (help);
	RStrBuf *rsb = r_strbuf_new (NULL);
	r_core_visual_append_help (core, rsb, title, msg);
	char *drained_string = r_strbuf_drain (rsb);
	r_panels_set_read_only (core, p, drained_string);
	free (drained_string);
}

static void r_panels_update_help(RCore *core, RPanels *ps) {
	const char *help = "Help";
	int i;
	for (i = 0; i < ps->n_panels; i++) {
		RPanel *p = r_panels_get_panel (ps, i);
		if (!p) {
			continue;
		}
		if (!strncmp (p->model->cmd, help, strlen (help))) {
			const char *title;
			const char * const * msg;
			switch (ps->mode) {
			case PANEL_MODE_WINDOW:
				title = "Panels Window Mode";
				msg = help_msg_panels_window;
				break;
			case PANEL_MODE_ZOOM:
				title = "Panels Zoom Mode";
				msg = help_msg_panels_zoom;
				break;
			default:
				title = "Panels Mode";
				msg = help_msg_panels;
				break;
			}
			r_panels_setup_help_panel(core, p, title, msg);
			p->view->refresh = true;
		}
	}
}

static int r_panels_navbar_window_width(RPanelsRoot *root, int first, int last) {
	int i, width = 2;
	for (i = first; i <= last; i++) {
		char number[16];
		const char *name = r_panels_navbar_tab_name (root, i, number, sizeof (number));
		width += r_str_ansi_len (name) + (i == root->cur_panels? 12: 8);
	}
	return width;
}

static int r_panels_navbar_x(RStrBuf *bar) {
	return r_str_ansi_len (r_strbuf_get (bar)) + 1;
}

static RStrBuf *r_panels_navbar(RCore *core, int width, RPanelsNavLayout *layout) {
	memset (layout, -1, sizeof (*layout));
	RStrBuf *bar = r_strbuf_new (" ");
	char *address = r_str_newf ("[0x%08"PFMT64x "]", core->addr);
	layout->address_x = r_panels_navbar_x (bar);
	layout->address_w = r_str_ansi_len (address);
	r_strbuf_appendf (bar, "%s ", address);
	free (address);
	layout->undo_x = r_panels_navbar_x (bar);
	r_strbuf_append (bar, "[<] ");
	layout->redo_x = r_panels_navbar_x (bar);
	r_strbuf_append (bar, "[>] ");
	RPanelsRoot *root = core->panels_root;
	int available = width - r_str_ansi_len (r_strbuf_get (bar)) - 3;
	if (!root || root->n_panels < 1) {
		r_strbuf_append (bar, "  ");
	} else if (available > 0) {
		int cur = R_MAX (0, R_MIN (root->cur_panels, root->n_panels - 1));
		int i, first = 0, last = cur;
		while (first < cur && r_panels_navbar_window_width (root, first, last) > available) {
			first++;
		}
		while (last + 1 < root->n_panels &&
				r_panels_navbar_window_width (root, first, last + 1) <= available) {
			last++;
		}
		if (first > 0) {
			layout->prev_tabs_x = r_panels_navbar_x (bar);
			layout->prev_tab = first - 1;
			r_strbuf_append (bar, "< ");
		} else {
			r_strbuf_append (bar, "  ");
		}
		for (i = first; i <= last; i++) {
			char number[16];
			const char *name = r_panels_navbar_tab_name (root, i, number, sizeof (number));
			int name_len = r_str_ansi_len (name);
			layout->tab_x[i] = r_panels_navbar_x (bar);
			if (i == cur) {
				layout->tab_w[i] = name_len + 10;
				layout->menu_x = layout->tab_x[i] + name_len + 4;
				if (core->panels->can->color) {
					r_strbuf_appendf (bar, "%s%s   %s [t]   "Color_RESET, core->cons->context->pal.widget_bg,
						r_panels_title_foreground (core), name);
				} else {
					r_strbuf_appendf (bar, "[  %s [t]  ]", name);
				}
			} else {
				layout->tab_w[i] = name_len + 6;
				r_strbuf_appendf (bar, "   %s   ", name);
			}
			if (i < last) {
				r_strbuf_append (bar, "  ");
			}
		}
		if (last + 1 < root->n_panels) {
			r_strbuf_append (bar, " ");
			layout->next_tabs_x = r_panels_navbar_x (bar);
			layout->next_tab = last + 1;
			r_strbuf_append (bar, ">");
		} else {
			r_strbuf_append (bar, "  ");
		}
	}
	return bar;
}

static void r_panels_do_panels_refresh(RCore *core) {
	if (core->panels) {
		r_panels_panel_all_clear (core, core->panels);
		r_panels_layout_refresh (core);
	}
}

static void r_panels_do_panels_refreshQueued(RCore *core) {
	r_panels_do_panels_resize (core);
}

static void r_panels_print_snow(RPanels *panels) {
	if (!panels->snows) {
		panels->snows = r_list_newf (free);
	}
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (!cur) {
		return;
	}
	int i, amount = r_num_rand (8);
	if (amount > 0) {
		for (i = 0; i < amount; i++) {
			RPanelsSnow *snow = R_NEW (RPanelsSnow);
			snow->x = r_num_rand (cur->view->pos.w) + cur->view->pos.x;
			snow->y = cur->view->pos.y;
			snow->stuck = false;
			r_list_append (panels->snows, snow);
		}
	}
	RListIter *iter, *iter2;
	RPanelsSnow *snow;
	r_list_foreach_safe (panels->snows, iter, iter2, snow) {
		if (r_num_rand (30) == 0) {
			r_list_delete (panels->snows, iter);
			continue;
		}
		if (snow->stuck) {
			goto print_this_snow;
		}
		int pos = r_num_rand (3) - 1;
		snow->x += pos;
		snow->y++;
		bool fall = false;
		{
			RListIter *it;
			RPanelsSnow *snw;
			bool collision = false;
			bool is_down_right = false;
			bool is_down_left = false;
			r_list_foreach (panels->snows, it, snw) {
				if (snw->stuck) {
					if (snw->x == snow->x && snw->y == snow->y) {
						collision = true;
						continue;
					}
					if (snw->x == snow->x + 1 && snw->y == snow->y) {
						is_down_right = true;
						continue;
					}
					if (snw->x == snow->x - 1 && snw->y == snow->y) {
						is_down_left = true;
					}
				}
			}
			if (collision) {
				if (is_down_right) {
					if (!is_down_left) {
						snow->x--;
						snow->y--;
						fall = true;
					}
				} else {
					if (is_down_left) {
						snow->x++;
						snow->y--;
						fall = true;
					}
				}
				if (!fall) {
					snow->stuck = true;
					snow->y--;
					goto print_this_snow;
				}
			}
		}
		if (fall) {
			snow->stuck = false;
	//		r_list_delete (panels->snows, iter);
		}
		if (snow->y + 1 >= panels->can->h) {
			snow->stuck = true;
			snow->y--;
			//r_list_delete (panels->snows, iter);
			goto print_this_snow;
		}
		if (snow->y >= cur->view->pos.h + cur->view->pos.y - 1) {
			snow->stuck = true;
			snow->y--;
			// r_list_delete (panels->snows, iter);
			// continue;
			goto print_this_snow;
		}
		if (snow->x < 0 || snow->x + 3 >= panels->can->w) {
			continue;
		}
print_this_snow:
		if (r_cons_canvas_gotoxy (panels->can, snow->x, snow->y)) {
			RConsCanvas *c = panels->can;
			char *line = c->b[c->y];
			if (line && c->x < c->w && line [c->x] != ' ') {
				continue;
			}
			if (line && c->x + 1 < c->w && line [c->x + 1] != ' ') {
				continue;
			}
			if (panels->fun == PANEL_FUN_SAKURA) {
				if (panels->can->color) {
					r_cons_canvas_write (panels->can, Color_MAGENTA",");
				} else {
					r_cons_canvas_write (panels->can, ",");
				}
			} else {
				r_cons_canvas_write (panels->can, "*");
			}
		}
	}
}

static void r_panels_default_panel_print(RCore *core, RPanel *panel) {
	bool o_cur = core->print->cur_enabled;
	core->print->cur_enabled = o_cur & (r_panels_get_cur_panel (core->panels) == panel);
	if (panel->model->readOnly) {
		r_panels_update_help_contents (core, panel);
		r_panels_update_title (core, panel);
	} else if (panel->model->cmd) {
		ut64 addr = core->addr;
		if (!r_panels_sync_seek (panel)) {
			r_core_seek (core, panel->model->addr, true);
		} else if (!r_panels_is_normal_cursor_type (panel)) {
			panel->model->addr = addr;
		}
		panel->model->print_cb (core, panel);
		r_panels_update_title (core, panel);
		if (!r_panels_sync_seek (panel)) {
			r_core_seek (core, addr, true);
		}
	}
	core->print->cur_enabled = o_cur;
}

static void r_panels_panel_print(RCore *core, RConsCanvas *can, RPanel *panel, bool color) {
	if (!can || !panel || !panel->view->refresh) {
		return;
	}
	RPanelPos *pos = &panel->view->pos;
	if (can->w <= pos->x || can->h <= pos->y) {
		return;
	}
	panel->view->refresh = panel->model->type == PANEL_TYPE_MENU;
	r_cons_canvas_background (can, panel->model->bgcolor);
	r_cons_canvas_fill (can, pos->x, pos->y, pos->w, pos->h, ' ');
	if (panel->model->type == PANEL_TYPE_MENU) {
		r_panels_menu_panel_print (can, panel, panel->view->sx, panel->view->sy, pos->w, pos->h);
	} else {
		r_panels_default_panel_print (core, panel);
	}
	int w = R_MIN (pos->w, can->w - pos->x);
	int h = R_MIN (pos->h, can->h - pos->y);
	r_cons_canvas_box (can, pos->x, pos->y, w, h,
		color ? PANEL_HL_COLOR : core->cons->context->pal.graph_box);
	r_cons_canvas_background (can, Color_RESET);
}

static void refresh_core_offset(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (r_panels_sync_seek (cur) && r_panels_check_panel_type (cur, "pd")) {
		core->addr = cur->model->addr;
	}
}

static void demo_begin(RCore *core, RConsCanvas *can) {
	char *s = r_cons_canvas_tostring (can);
	if (s) {
		// TODO drop utf8!!
		r_str_ansi_filter (s, NULL, NULL, -1);
		int i, h, w = r_panels_get_size (core, &h);
		for (i = 0; i < 40; i += (1 + (i / 30))) {
			int H = (int)(i * ((double)h / 40));
			char *r = r_str_scale (s, w, H);
			r_cons_clear00 (core->cons);
			r_cons_gotoxy (core->cons, 0, (h / 2) - (H / 2));
			r_cons_print (core->cons, r);
			r_cons_flush (core->cons);
			free (r);
			r_sys_usleep (5000);
		}
		free (s);
	}
}

// printed outside the canvas so the tint can reach the last column via clear-to-eol
static void r_panels_print_footer(RCore *core, int w, int footer_y, bool in_menu) {
	RCons *cons = core->cons;
	char *text;
	if (in_menu) {
		text = r_panels_menu_status_line (r_panels_get_selected_menu_item (core->panels));
	} else {
		RPanelsNavLayout nav_layout;
		text = r_strbuf_drain (r_panels_navbar (core, w, &nav_layout));
	}
	char *cropped = r_str_ansi_crop (r_str_get (text), 0, 0, R_MAX (w - 1, 1), 1);
	const int notch = r_config_get_i (core->config, "scr.notch");
	r_cons_gotoxy (cons, 0, notch + footer_y + 1);
	if (in_menu && core->panels->can->color) {
		r_cons_printf (cons, Color_RESET"%s%s%s\x1b[0K"Color_RESET, cons->context->pal.widget_bg,
			r_panels_title_foreground (core), r_str_get (cropped));
	} else if (core->panels->can->color) {
		r_cons_printf (cons, Color_RESET"%s\x1b[0K"Color_RESET, r_str_get (cropped));
	} else {
		r_cons_printf (cons, "%s\x1b[0K", r_str_get (cropped));
	}
	free (cropped);
	free (text);
}

static void r_panels_refresh(RCore *core) {
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	r_cons_gotoxy (core->cons, 0, 0);
	int i, h, w = r_panels_get_size (core, &h);
	if (!r_cons_canvas_resize (can, w, h)) {
		return;
	}
	RStrBuf *title = r_strbuf_new (" ");
	bool utf8 = r_config_get_b (core->config, "scr.utf8");
	if (core->visual.firstRun) {
		r_config_set_b (core->config, "scr.utf8", false);
	}

	refresh_core_offset (core);
	r_panels_set_refresh_all (core, false, false);

	const bool frame_menu = r_panels_frame_menu_is_open (panels);
	const bool menubar_open = panels->mode == PANEL_MODE_MENU && !frame_menu;
	const RPanelsMode mode = panels->mode == PANEL_MODE_MENU? panels->frame_mode: panels->mode;
	for (i = 0; i < panels->n_panels; i++) {
		if (mode == PANEL_MODE_ZOOM || i == panels->curnode) {
			continue;
		}
		r_panels_panel_print (core, can, r_panels_get_panel (panels, i), 0);
	}
	r_panels_panel_print (core, can, r_panels_get_cur_panel (panels), !menubar_open);
	if (mode == PANEL_MODE_WINDOW) {
		r_strbuf_appendf (title, "%s Window Mode | hjkl: move around the panels | q: quit the mode | Enter: Zoom mode"Color_RESET, PANEL_HL_COLOR);
	} else {
		RPanelsMenuItem *parent = panels->panels_menu->root;
		if (menubar_open) {
			r_strbuf_append (title, " > ");
		} else {
			if (panels->can->color) {
				r_strbuf_appendf (title, "%s[m]"Color_RESET, PANEL_HL_COLOR);
			} else {
				r_strbuf_append (title, "[m]");
			}
		}
		int menu_first, menu_last;
		r_panels_menu_bar_range (parent, parent->selectedIndex, w - 4, &menu_first, &menu_last);
		if (menu_first > 0) {
			r_strbuf_append (title, "< ");
		}
		for (i = menu_first; i <= menu_last && i < parent->n_sub; i++) {
			RPanelsMenuItem *item = parent->sub[i];
			if (menubar_open && i == parent->selectedIndex) {
				r_strbuf_appendf (title, "%s[%s]"Color_RESET, PANEL_HL_COLOR, item->name);
			} else {
				r_strbuf_appendf (title, " %s ", item->name);
			}
		}
		if (menu_last < parent->n_sub - 1) {
			r_strbuf_append (title, " >");
		}
	}
	const bool in_menu = panels->mode == PANEL_MODE_MENU;
	char *menubar = r_str_newf (Color_RESET"%s", r_strbuf_get (title));
	r_panels_canvas_write_bar (can, 0, w, menubar, ' ');
	free (menubar);
	for (i = 0; i < panels->panels_menu->n_refresh; i++) {
		r_panels_panel_print (core, can, panels->panels_menu->refreshPanels[i], 0);
	}
	r_strbuf_free (title);

	if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
		r_panels_print_snow (panels);
	}
	if (core->visual.firstRun) {
		if (core->panels_root->n_panels < 2) {
			if (r_config_get_b (core->config, "scr.demo")) {
				demo_begin (core, can);
			}
		}
		core->visual.firstRun = false;
		r_config_set_b (core->config, "scr.utf8", utf8);
		RPanel *cur = r_panels_get_cur_panel (core->panels);
		cur->view->refresh = true;
		r_panels_refresh (core);
	} else {
		print_notch (core);
		r_cons_printf (core->cons, Color_RESET R_CONS_CLEAR_LINE);
		r_cons_canvas_print (can);
		r_panels_print_footer (core, w, h - PANEL_FOOTER_H, in_menu && !r_panels_tab_menu_is_open (panels));
		if (core->scr_gadgets) {
			r_core_call (core, "pg");
		}
		r_panels_show_cursor (core);
		r_cons_flush (core->cons);
	}
}

static void demo_end(RCore *core, RConsCanvas *can) {
	bool utf8 = r_config_get_b (core->config, "scr.utf8");
	r_config_set_b (core->config, "scr.utf8", false);
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	cur->view->refresh = true;
	core->visual.firstRun = false;
	r_panels_refresh (core);
	core->visual.firstRun = true;
	r_config_set_b (core->config, "scr.utf8", utf8);
	char *s = r_cons_canvas_tostring (can);
	if (s) {
		// TODO drop utf8!!
		r_str_ansi_filter (s, NULL, NULL, -1);
		int i, h, w = r_panels_get_size (core, &h);
		for (i = h; i > 0; i--) {
			const int H = i;
			char *r = r_str_scale (s, w, H);
			r_cons_clear00 (core->cons);
			r_cons_gotoxy (core->cons, 0, (h / 2) - (H / 2)); // center
			r_cons_print (core->cons, r);
			r_cons_flush (core->cons);
			free (r);
			r_sys_usleep (3000);
		}
		r_sys_usleep (100000);
		free (s);
	}
}

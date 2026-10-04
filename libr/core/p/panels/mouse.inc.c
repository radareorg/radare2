/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

static void r_panels_release_edge(RPanels *panels) {
	panels->mouse_on_edge_x = false;
	panels->mouse_on_edge_y = false;
	panels->mouse_edge_grabbed = false;
	panels->mouse_orig_x = -1;
	panels->mouse_orig_y = -1;
}

static bool r_panels_drag_and_resize(RCore *core, int key) {
	RPanels *panels = core->panels;
	if (panels->mode == PANEL_MODE_ZOOM || panels->mode == PANEL_MODE_MENU) {
		r_panels_release_edge (panels);
		return false;
	}
	if (!panels->mouse_on_edge_x && !panels->mouse_on_edge_y) {
		return false;
	}
	RCons *cons = core->cons;
	if (cons->drag_event) {
		if (panels->mouse_on_edge_x) {
			if (key == 'h') {
				r_panels_update_edge_x (core, 1);
			} else if (key == 'l') {
				r_panels_update_edge_x (core, -1);
			}
		}
		if (panels->mouse_on_edge_y) {
			if (key == 'k') {
				r_panels_update_edge_y (core, 1);
			} else if (key == 'j') {
				r_panels_update_edge_y (core, -1);
			}
		}
		return true;
	}
	if (cons->dragging) {
		return true;
	}
	int x, y;
	const bool clicked = r_cons_get_click (cons, &x, &y);
	if (!cons->mouse_event) {
		r_panels_release_edge (panels);
		return false;
	}
	if (cons->drag_moved) {
		r_panels_release_edge (panels);
		return true;
	}
	if (!clicked) {
		return true;
	}
	// touch terminals like termux never report motion: tap the edge, then tap the target
	if (!panels->mouse_edge_grabbed) {
		panels->mouse_edge_grabbed = true;
		return true;
	}
	y -= r_config_get_i (core->config, "scr.notch");
	if (panels->mouse_on_edge_x) {
		r_panels_update_edge_x (core, x - 1 - panels->mouse_orig_x);
	}
	if (panels->mouse_on_edge_y) {
		r_panels_update_edge_y (core, y - 1 - panels->mouse_orig_y);
	}
	r_panels_release_edge (panels);
	return true;
}

static char *r_panels_get_word_from_canvas(RPanels *panels, int x, int y) {
	RStrBuf rsb;
	r_strbuf_init (&rsb);
	char *cs = r_cons_canvas_tostring (panels->can);
	r_strbuf_setf (&rsb, " %s", cs);
	char *R = r_str_ansi_crop (r_strbuf_get (&rsb), 0, y - 1, x + 1024, y);
	r_str_ansi_filter (R, NULL, NULL, -1);
	char *r = r_str_ansi_crop (r_strbuf_get (&rsb), x - 1, y - 1, x + 1024, y);
	r_str_ansi_filter (r, NULL, NULL, -1);
	if (R_STR_ISEMPTY (r) || *r == ' ' || *r == '\t') {
		free (r);
		free (R);
		free (cs);
		r_strbuf_fini (&rsb);
		return strdup ("");
	}
	char *pos = strstr (R, r);
	if (!pos) {
		pos = R;
	}
#define TOkENs ":=*+-/()[,] "
	const char *sp = r_str_rsep (R, pos, TOkENs);
	if (sp) {
		sp++;
	} else {
		sp = pos;
	}
	char *sp2 = (char *)r_str_sep (sp, TOkENs);
	if (sp2) {
		*sp2 = 0;
	}
	char *res = strdup (sp);
	free (r);
	free (R);
	free (cs);
	r_strbuf_fini (&rsb);
	return res;
}

static char *r_panels_get_word_from_canvas_for_menu(RCore *core, RPanels *panels, int x, int y) {
	char *cs = r_cons_canvas_tostring (panels->can);
	char *R = r_str_ansi_crop (cs, 0, y - 1, x + 1024, y);
	r_str_ansi_filter (R, NULL, NULL, -1);
	char *r = r_str_ansi_crop (cs, x - 1, y - 1, x + 1024, y);
	r_str_ansi_filter (r, NULL, NULL, -1);
	char *pos = strstr (R, r);
	char *tmp = pos;
	const char *padding = "  ";
	if (!pos) {
		pos = R;
	}
	int i = 0;
	while (pos > R && strncmp (padding, pos, strlen (padding))) {
		pos--;
		i++;
	}
	while (R_STR_ISNOTEMPTY (tmp) && strncmp (padding, tmp, strlen (padding))) {
		tmp++;
		i++;
	}
	char *ret = R_STR_NDUP (pos += strlen (padding), i - strlen (padding));
	if (!ret) {
		ret = strdup (pos);
	}
	free (r);
	free (R);
	free (cs);
	return ret;
}

static bool r_panels_handle_mouse_on_top(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	char *word = r_panels_get_word_from_canvas (panels, x, y);
	int i;
	for (i = 0; i < R_ARRAY_SIZE (menus); i++) {
		if (!strcmp (word, menus[i])) {
			RPanelsMenu *menu = panels->panels_menu;
			if (panels->mode == PANEL_MODE_MENU && menu->root->selectedIndex == i
					&& !r_panels_frame_menu_is_open (panels)) {
				r_panels_close_menu (core);
				free (word);
				return true;
			}
			r_panels_set_mode (core, PANEL_MODE_MENU);
			r_panels_clear_panels_menu (core);
			RPanelsMenuItem *parent = menu->history[menu->depth - 1];
			parent->selectedIndex = i;
			RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
			(void)(child->cb (core));
			free (word);
			return true;
		}
	}
	if (!strcmp (word, "Tab")) {
		r_panels_handle_tab_new (core);
		free (word);
		return true;
	}
	if (word[0] == '[' && word[1] && word[2] == ']') {
		free (word);
		return true;
	}
	if (atoi (word)) {
		r_panels_handle_tab_nth (core, word[0]);
		free (word);
		return true;
	}
	free (word);
	return false;
}

static bool r_panels_navbar_hit(int x, int start, int width) {
	return start > 0 && x >= start && x < start + width;
}

// returns the root when index is a valid tab, closing the menu first
static RPanelsRoot *r_panels_navbar_tab_root(RCore *core, int index) {
	RPanelsRoot *root = core->panels_root;
	if (!root || index < 0 || index >= root->n_panels) {
		return NULL;
	}
	if (core->panels->mode == PANEL_MODE_MENU) {
		r_panels_close_menu (core);
	}
	return root;
}

static void r_panels_navbar_select_tab(RCore *core, int index) {
	RPanelsRoot *root = r_panels_navbar_tab_root (core, index);
	if (root && index != root->cur_panels) {
		root->cur_panels = index;
		r_panels_set_root_state (core, ROTATE);
	}
}

static bool r_panels_handle_mouse_on_tabs(RCore *core, int x, RPanelsNavLayout *layout) {
	RPanelsRoot *root = core->panels_root;
	if (r_panels_navbar_hit (x, layout->menu_x, 3)) {
		r_panels_open_tab_menu (core);
		return true;
	}
	if (r_panels_navbar_hit (x, layout->prev_tabs_x, 1)) {
		r_panels_navbar_select_tab (core, layout->prev_tab);
		return true;
	}
	if (r_panels_navbar_hit (x, layout->next_tabs_x, 1)) {
		r_panels_navbar_select_tab (core, layout->next_tab);
		return true;
	}
	int i;
	for (i = 0; root && i < root->n_panels; i++) {
		if (r_panels_navbar_hit (x, layout->tab_x[i], layout->tab_w[i])) {
			r_panels_navbar_select_tab (core, i);
			return true;
		}
	}
	return true;
}

static bool r_panels_handle_mouse_on_navbar(RCore *core, int x, int *key) {
	RPanelsNavLayout layout;
	r_strbuf_free (r_panels_navbar (core, core->panels->can->w, &layout));
	int action = 0;
	if (r_panels_navbar_hit (x, layout.undo_x, 3)) {
		action = 'u';
	} else if (r_panels_navbar_hit (x, layout.redo_x, 3)) {
		action = 'U';
	} else if (r_panels_navbar_hit (x, layout.address_x, layout.address_w)) {
		action = 'g';
	}
	if (action) {
		if (core->panels->mode == PANEL_MODE_MENU) {
			r_panels_close_menu (core);
		}
		*key = action;
		return false;
	}
	return r_panels_handle_mouse_on_tabs (core, x, &layout);
}

static void r_panels_handle_mouse_on_menu(RCore *core, int x, int y) {
	RPanelsMenu *menu = core->panels->panels_menu;
	// mouse coordinates are 1-based terminal cells, menu positions are canvas cells
	x--;
	y--;
	while (menu->depth > 1) {
		RPanelsMenuItem *parent = menu->history[menu->depth - 1];
		const int idx = r_panels_menu_item_at (core, parent, x, y);
		if (idx == -2) {
			return;
		}
		if (idx >= 0) {
			parent->selectedIndex = idx;
			r_panels_update_menu_contents (core, menu, parent);
			(void)(parent->sub[idx]->cb (core));
			return;
		}
		r_panels_del_menu (core);
	}
	r_panels_close_menu (core);
}

static int r_panels_select_mouse_panel(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	const int idx = r_panels_get_panel_idx_in_pos (core, x, y);
	if (idx == -1 || idx == panels->curnode) {
		return idx;
	}
	RPanel *old = r_panels_get_cur_panel (panels);
	RPanel *cur = r_panels_get_panel (panels, idx);
	old->view->refresh = true;
	r_panels_set_cursor (core, false);
	r_panels_set_curnode (core, idx);
	cur->view->refresh = true;
	return idx;
}

static void r_panels_scrollbar_seek(RPanel *panel, const RPanelsScrollbar *bar, int row) {
	const int travel = bar->height - bar->thumb_size;
	panel->view->sy = travel? (st64)R_MIN (R_MAX (row, 0), travel) * bar->max_scroll / travel: 0;
	panel->view->curpos = panel->view->sy;
	panel->view->refresh = true;
}

static bool r_panels_scrollbar_click(RCore *core, int x, int y) {
	const int idx = r_panels_get_panel_idx_in_pos (core, x, y);
	if (idx < 0) {
		return false;
	}
	RPanels *panels = core->panels;
	RPanel *panel = r_panels_get_panel (panels, idx);
	RPanelsScrollbar bar;
	if (!r_panels_scrollbar_layout (panel, &bar) || x != bar.x + 1 || y <= bar.y || y > bar.y + bar.height) {
		return false;
	}
	r_panels_select_mouse_panel (core, x, y);
	r_panels_set_cursor (core, false);
	r_panels_release_edge (panels);
	const int row = y - bar.y - 1;
	panels->mouse_orig_x = x;
	// Preserve where the thumb was grabbed when dragging it.
	const bool on_thumb = row >= bar.thumb && row < bar.thumb + bar.thumb_size;
	panels->mouse_orig_y = on_thumb? row - bar.thumb: bar.thumb_size / 2;
	if (!on_thumb) {
		r_panels_scrollbar_seek (panel, &bar, row - panels->mouse_orig_y);
	}
	if (!core->cons->dragging) {
		r_panels_release_edge (panels);
	}
	return true;
}

static bool r_panels_scrollbar_drag(RCore *core) {
	RPanels *panels = core->panels;
	RCons *cons = core->cons;
	RPanelsScrollbar bar;
	RPanel *panel = r_panels_get_cur_panel (panels);
	if (!cons->mouse_event || panels->mode == PANEL_MODE_MENU || panels->mouse_on_edge_x || panels->mouse_on_edge_y
			|| panels->mouse_orig_x != panel->view->pos.x + panel->view->pos.w - 1
			|| !r_panels_scrollbar_layout (panel, &bar)) {
		return false;
	}
	if (cons->mouse_event && cons->drag_event) {
		const int y = cons->drag_y - r_config_get_i (core->config, "scr.notch");
		r_panels_scrollbar_seek (panel, &bar, y - bar.y - 1 - panels->mouse_orig_y);
		return true;
	}
	if (!cons->dragging) {
		int x, y;
		r_cons_get_click (cons, &x, &y);
		r_panels_release_edge (panels);
		return cons->mouse_event;
	}
	return false;
}

static bool r_panels_handle_mouse_on_title(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	const int idx = r_panels_get_panel_idx_in_pos (core, x, y);
	if (idx == -1) {
		return false;
	}
	RPanelPos *pos = &r_panels_get_panel (panels, idx)->view->pos;
	if (y != pos->y + 2) {
		return false;
	}
	(void)r_panels_select_mouse_panel (core, x, y);
	// the [=] button spans columns pos.x+1..pos.x+3 of the canvas, terminal columns are 1-based
	if (x > pos->x + 1 && x <= pos->x + 1 + strlen (PANEL_FRAME_BUTTON)) {
		r_panels_open_frame_menu (core);
	}
	return true;
}

static int r_panels_context_config_cb(void *user) {
	RCore *core = user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *item = parent->sub[parent->selectedIndex];
	RConfigNode *node = r_config_node_get (core->config, item->args);
	if (r_config_node_is_bool (node)) {
		r_config_toggle (core->config, item->args);
	} else {
		char *value = r_panels_show_status_input (core, "New value: ");
		if (R_STR_ISNOTEMPTY (value)) {
			r_config_set (core->config, item->args, value);
		}
		free (value);
	}
	free (item->name);
	item->name = r_str_newf ("%s: %s", item->args, r_config_get (core->config, item->args));
	r_panels_set_refresh_all (core, true, false);
	r_panels_update_menu_contents (core, menu, parent);
	return 0;
}

static int r_panels_clipboard_format_cb(void *user) {
	RCore *core = user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *item = parent->sub[parent->selectedIndex];
	replace_cmd (core, "Clipboard", item->args);
	r_panels_reset_scroll_pos (r_panels_get_cur_panel (core->panels));
	r_panels_close_menu (core);
	return 0;
}

static RPanelsMenuItem *r_panels_context_menu_new(RCore *core, RPanel *panel) {
	static const char *hex_settings[] = {
		"hex.cols", "hex.pairs", "hex.ascii", "hex.header", "hex.addr", "hex.comments", "hex.section"
	};
	static const char *disasm_settings[] = {
		"asm.bytes", "asm.addr", "asm.comments", "asm.cmt.right", "asm.pseudo", "asm.esil", "asm.emu"
	};
	static const char *other_settings[] = { "scr.color", "scr.utf8" };
	const char **settings = other_settings;
	size_t count = R_ARRAY_SIZE (other_settings);
	if (r_panels_check_panel_type (panel, "xc") || r_panels_check_panel_type (panel, "px")) {
		settings = hex_settings;
		count = R_ARRAY_SIZE (hex_settings);
	} else if (r_panels_check_panel_type (panel, "pd")) {
		settings = disasm_settings;
		count = R_ARRAY_SIZE (disasm_settings);
	}
	RPanelsMenuItem *context = r_panels_menu_item_new ("Panel settings", NULL, NULL, NULL);
	if (!strcmp (panel->model->cmd, "y") || !strcmp (panel->model->cmd, "yx") || !strcmp (panel->model->cmd, "ys")) {
		static const char *names[] = { "Summary", "Hexdump", "String" };
		static const char *commands[] = { "y", "yx", "ys" };
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (names); i++) {
			RPanelsMenuItem *item = r_panels_menu_item_new (names[i], "Change the clipboard display format",
				commands[i], r_panels_clipboard_format_cb);
			if (!r_panels_menu_item_append (context, item)) {
				r_panels_free_menu_item (item);
				break;
			}
		}
		return context;
	}
	size_t i;
	for (i = 0; i < count; i++) {
		RConfigNode *node = r_config_node_get (core->config, settings[i]);
		char *name = r_str_newf ("%s: %s", settings[i], node->value);
		RPanelsMenuItem *item = r_panels_menu_item_new (name, node->desc, settings[i], r_panels_context_config_cb);
		free (name);
		if (!r_panels_menu_item_append (context, item)) {
			r_panels_free_menu_item (item);
			break;
		}
	}
	return context;
}

static int r_panels_hexdump_byte_at(RCore *core, RPanel *panel, int x, int y) {
	RPanelPos *pos = &panel->view->pos;
	if (!r_panels_is_byte_hexdump (panel) || !panel->model->cmdStrCache
			|| x < pos->x + 3 || x >= pos->x + pos->w
			|| y < pos->y + 3 || y >= pos->y + pos->h) {
		return -1;
	}
	int row = y - pos->y - 3 + panel->view->sy;
	int column = x - pos->x - 3 + panel->view->sx;
	char *line = r_str_ansi_crop (panel->model->cmdStrCache, 0, row, INT_MAX, row + 1);
	if (!line) {
		return -1;
	}
	r_str_ansi_filter (line, NULL, NULL, -1);
	const int length = strlen (line);
	const int cols = R_MAX (core->print->cols, 2);
	int start = 0, result = -1;
	ut64 addr = panel->model->addr;
	if (core->print->flags & R_PRINT_FLAGS_OFFSET) {
		start = (core->print->flags & R_PRINT_FLAGS_SECTION)? 21: 0;
		if (start >= length || strncmp (line + start, "0x", 2)) {
			goto beach;
		}
		char *end;
		addr = strtoull (line + start, &end, 16);
		start = end - line;
	} else {
		int data_row = row - (core->print->cols >= 2 && (core->print->flags & R_PRINT_FLAGS_HEADER));
		if (data_row < 0) {
			goto beach;
		}
		addr += (ut64)data_row * (core->print->stride? core->print->stride: cols);
	}
	if (addr < panel->model->addr || addr - panel->model->addr > INT_MAX - cols) {
		goto beach;
	}
	while (start < length && (line[start] == ' ' || line[start] == '|')) {
		start++;
	}
	const int hex_start = start;
	int i;
	for (i = 0; i < cols; i++) {
		if (i && start < length && line[start] == ' ') {
			start++;
		}
		if (start + 1 >= length || !isxdigit ((ut8)line[start]) || !isxdigit ((ut8)line[start + 1])) {
			break;
		}
		if (column == start || column == start + 1) {
			result = addr - panel->model->addr + i;
			goto beach;
		}
		start += 2;
	}
	if (!(core->print->flags & R_PRINT_FLAGS_NONASCII)) {
		bool compact = core->print->flags & R_PRINT_FLAGS_COMPACT;
		int padding = compact? 0: (core->print->pairs? cols / 2: cols);
		int separator = compact && core->print->col == 1 && core->print->pairs && (cols & 1)? 0: 1;
		start = hex_start + cols * 2 + padding + separator;
		if (column >= start && column < start + i && column < length) {
			result = addr - panel->model->addr + column - start;
		}
	}
beach:
	free (line);
	return result;
}

static bool r_panels_select_byte(RCore *core, RPanel *panel, int x, int y, bool extend) {
	int offset = r_panels_hexdump_byte_at (core, panel, x, y);
	if (offset < 0) {
		return false;
	}
	if (panel->model->cache) {
		panel->model->cache = false;
		set_dcb (core, panel);
	}
	if (!extend) {
		core->print->ocur = offset;
	}
	core->print->cur_enabled = true;
	core->print->col = 1;
	core->print->cur = offset;
	panel->view->curpos = offset;
	panel->view->refresh = true;
	return true;
}

static void r_panels_seek_all(RCore *core, ut64 addr) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = r_panels_get_panel (panels, i);
		panel->model->addr = addr;
	}
}

static bool r_panels_handle_mouse_on_panel(RCore *core, int x, int y, int *key) {
	RPanels *panels = core->panels;
	const int idx = r_panels_select_mouse_panel (core, x, y);
	if (idx == -1) {
		return false;
	}
	RPanel *ppos = r_panels_get_panel (panels, idx);
	const RPanelPos *pos = &ppos->view->pos;
	if (r_panels_is_byte_hexdump (ppos)) {
		r_panels_select_byte (core, ppos, x, y, false);
		return true;
	}
	// click coordinates are 1-based, skip the frame borders
	if (y <= pos->y + 1 || y >= pos->y + pos->h || x <= pos->x + 1 || x >= pos->x + pos->w) {
		return true;
	}
	char *word = r_panels_get_word_from_canvas (panels, x, y);
	if (R_STR_ISEMPTY (word)) {
		free (word);
		return true;
	}
	if (R_STR_ISNOTEMPTY (word)) {
		const ut64 addr = r_num_math (core->num, word);
		if (r_panels_check_panel_type (ppos, "afl") &&
				r_panels_check_if_addr (word, strlen (word))) {
			r_core_seek (core, addr, true);
			set_addr_by_type (core, "pd", addr);
		}
	//	r_flag_set (core->flags, "panel.addr", addr, 1);
		r_config_set (core->config, "scr.highlight", word);
		if (addr != 0 && addr != UT64_MAX) {
			r_io_sundo_push (core->io, core->addr, 0);
			r_panels_seek_all (core, addr);
			if (r_panels_check_panel_type (ppos, "pd")) {
				r_panels_reset_scroll_pos (ppos);
				ppos->view->curpos = 0;
				if (ppos->model->cache) {
					r_panels_set_cmd_str_cache (core, ppos, NULL);
				}
			}
		}
	}
	free (word);
	if (x >= ppos->view->pos.x && x < ppos->view->pos.x + 4) {
		*key = 'c';
		return false;
	}
	return true;
}

static bool r_panels_handle_mouse_press(RCore *core) {
	RPanels *panels = core->panels;
	RCons *cons = core->cons;
	if (!cons->mouse_event || !cons->dragging || cons->drag_event ||
			panels->mode == PANEL_MODE_MENU) {
		return false;
	}
	const int x = cons->drag_x;
	const int y = cons->drag_y - r_config_get_i (core->config, "scr.notch");
	if (y <= PANEL_HEADER_H || y >= panels->can->h) {
		return false;
	}
	if (r_panels_scrollbar_click (core, x, y)) {
		return true;
	}
	r_panels_release_edge (panels);
	if (panels->mode != PANEL_MODE_ZOOM) {
		(void)r_panels_check_if_mouse_x_on_edge (core, x, y);
		(void)r_panels_check_if_mouse_y_on_edge (core, x, y);
	}
	if (panels->mouse_on_edge_x || panels->mouse_on_edge_y) {
		return true;
	}
	if (r_panels_select_mouse_panel (core, x, y) == -1) {
		return false;
	}
	RPanel *panel = r_panels_get_cur_panel (panels);
	core->print->ocur = -1;
	r_panels_select_byte (core, panel, x, y, false);
	return true;
}

static bool r_panels_handle_mouse(RCore *core, int *key) {
	RPanels *panels = core->panels;
	RCons *cons = core->cons;
	if (key && (*key == INT8_MAX || *key == -INT8_MAX)) {
		int x, y;
		r_cons_get_click (cons, &x, &y);
		if (*key == INT8_MAX && panels->mode != PANEL_MODE_MENU && cons->mouse_event) {
			y -= r_config_get_i (core->config, "scr.notch");
			if (y > PANEL_HEADER_H && y < panels->can->h
					&& r_panels_select_mouse_panel (core, x, y) != -1) {
				RPanel *panel = r_panels_get_cur_panel (panels);
				r_panels_release_edge (panels);
				r_panels_open_popup (core, r_panels_context_menu_new (core, panel), x - 1, y - 1);
			}
		}
		return true;
	}
	if (r_panels_scrollbar_drag (core) || r_panels_drag_and_resize (core, key? *key: 0)) {
		return true;
	}
	if (cons->drag_event && panels->mode != PANEL_MODE_MENU) {
		RPanel *panel = r_panels_get_cur_panel (panels);
		if (r_panels_is_byte_hexdump (panel)) {
			if (core->print->cur_enabled && core->print->ocur >= 0) {
				r_panels_select_byte (core, panel, cons->drag_x,
					cons->drag_y - r_config_get_i (core->config, "scr.notch"), true);
			}
			return true;
		}
	}
	if (r_panels_handle_mouse_press (core)) {
		return true;
	}
	if (key && !*key) {
		int x, y;
		if (!r_cons_get_click (core->cons, &x, &y)) {
			return false;
		}
		y -= r_config_get_i (core->config, "scr.notch");
		if (y == MENU_Y && r_panels_handle_mouse_on_top (core, x, y)) {
			return true;
		}
		if (y == panels->can->h && panels->mode != PANEL_MODE_MENU) {
			return r_panels_handle_mouse_on_navbar (core, x, key);
		}
		if (panels->mode == PANEL_MODE_MENU) {
			r_panels_handle_mouse_on_menu (core, x, y);
			return true;
		}
		if (y <= PANEL_HEADER_H) {
			return true;
		}
		if (r_panels_scrollbar_click (core, x, y)) {
			return true;
		}
		if (r_panels_handle_mouse_on_title (core, x, y)) {
			return true;
		}
		if (r_panels_check_if_mouse_x_illegal (core, x) || r_panels_check_if_mouse_y_illegal (core, y)) {
			panels->mouse_on_edge_x = false;
			panels->mouse_on_edge_y = false;
			return true;
		}
		if (r_panels_handle_mouse_on_panel (core, x, y, key)) {
			return true;
		}
		int h, w = r_cons_get_size (core->cons, &h);
		if (y == h) {
			RPanel *p = r_panels_get_cur_panel (panels);
			r_panels_split_panel (core, p, p->model->title, p->model->cmd, false);
		} else if (x == w) {
			RPanel *p = r_panels_get_cur_panel (panels);
			r_panels_split_panel (core, p, p->model->title, p->model->cmd, true);
		}
	}
	return false;
}

static int r_panels_content_width(const char *content) {
	int max_width = 0;
	const char *line = content;
	while (R_STR_ISNOTEMPTY (line)) {
		const char *end = strchr (line, '\n');
		size_t width = end
			? (end == line? 0: r_str_ansi_nlen (line, end - line))
			: r_str_ansi_len (line);
		if (width > INT_MAX) {
			return INT_MAX;
		}
		max_width = R_MAX (max_width, (int)width);
		if (!end) {
			break;
		}
		line = end + 1;
	}
	return max_width;
}

static bool r_panels_wheel_is_bounded(RCore *core, RPanel *panel, int direction) {
	RPanelDirectionCallback cb = panel->model->directionCb;
	const bool horizontal = direction == 'h' || direction == 'l';
	const bool view_scroll = cb == direction_default_cb || cb == direction_graph_cb;
	if (horizontal) {
		return view_scroll || cb == direction_hexdump_cb || !core->print->cur_enabled;
	}
	return view_scroll || (!core->print->cur_enabled && cb == direction_panels_cursor_cb);
}

static void r_panels_wheel_direction(RCore *core, RPanel *panel, int direction) {
	RPanelDirectionCallback cb = panel->model->directionCb;
	if (!cb || !r_panels_wheel_is_bounded (core, panel, direction)) {
		if (cb) {
			cb (core, direction);
		}
		return;
	}
	const char *content = r_panels_rendered_content (panel);
	if (R_STR_ISEMPTY (content)) {
		return;
	}
	const bool horizontal = direction == 'h' || direction == 'l';
	int viewport = horizontal? panel->view->pos.w - 3: panel->view->pos.h - 3;
	if (horizontal && (panel->model->cache || panel->model->readOnly)
			&& panel->view->pos.w >= 5 && panel->view->pos.h >= 4) {
		viewport--;
	}
	if (viewport < 1) {
		cb (core, direction);
		return;
	}
	const int extent = horizontal
		? r_panels_content_width (content)
		: r_panels_content_height (content);
	const int max_scroll = R_MAX (extent - viewport, 0);
	int *scroll = horizontal? &panel->view->sx: &panel->view->sy;
	const bool forward = direction == 'l' || direction == 'j';
	if ((forward && *scroll >= max_scroll) || (!forward && *scroll <= 0)) {
		return;
	}
	if (horizontal && cb == direction_hexdump_cb) {
		*scroll += forward? 1: -1;
		panel->view->refresh = true;
	} else {
		cb (core, direction);
	}
	*scroll = R_MAX (0, R_MIN (*scroll, max_scroll));
}

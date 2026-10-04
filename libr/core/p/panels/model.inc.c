/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

static RPanel *r_panels_get_panel(RPanels *panels, int i) {
	return (panels && i < PANEL_NUM_LIMIT)? panels->panel[i]: NULL;
}

static RPanel *r_panels_get_cur_panel(RPanels *panels) {
	return r_panels_get_panel (panels, panels->curnode);
}

static bool r_panels_frame_menu_is_open(RPanels *panels) {
	RPanelsMenu *menu = panels->panels_menu;
	return panels->mode == PANEL_MODE_MENU && menu && menu->frame
		&& menu->depth > 1 && menu->history[1] == menu->frame;
}

static bool r_panels_check_if_cur_panel(RCore *core, RPanel *panel) {
	RPanels *panels = core->panels;
	return (panels->mode != PANEL_MODE_MENU || r_panels_frame_menu_is_open (panels))
		&& r_panels_get_cur_panel (panels) == panel;
}

static bool r_panels_check_if_addr(const char *c, int len) {
	if (len < 2) {
		return false;
	}
	int i = 0;
	for (; i < len; i++) {
		if (R_STR_ISNOTEMPTY (c + i) && R_STR_ISNOTEMPTY (c+ i + 1) &&
				c[i] == '0' && c[i + 1] == 'x') {
			return true;
		}
	}
	return false;
}

static int r_panels_show_status(RCore *core, const char *msg) {
	RCons *cons = core->cons;
	r_cons_gotoxy (cons, 0, 0);
	r_cons_printf (cons, R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, PANEL_HL_COLOR, msg);
	r_cons_flush (cons);
	r_cons_set_raw (cons, true);
	return r_cons_readchar (cons);
}

static bool r_panels_show_status_yesno(RCore *core, int def, const char *msg) {
	RCons *cons = core->cons;
	r_cons_gotoxy (cons, 0, 0);
	r_cons_flush (cons);
	return r_cons_yesno (cons, def, R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, PANEL_HL_COLOR, msg);
}

static void r_panels_clamp_console_size(RCore *core, int *w, int *h) {
	int rows;
	int cols = r_cons_get_size (core->cons, &rows);
	if (cols < 1) {
		cols = 1;
	} else if (cols > 1024) {
		cols = 1024;
	}
	if (rows < 1) {
		rows = 1;
	} else if (rows > 1024) {
		rows = 1024;
	}
	core->cons->columns = cols;
	core->cons->rows = rows;
	if (w) {
		*w = cols;
	}
	if (h) {
		*h = rows;
	}
}

// get console size with scr.notch subtracted and clamped to >= 1
static int r_panels_get_size(RCore *core, int *ph) {
	int h, w = r_cons_get_size (core->cons, &h);
	h -= r_config_get_i (core->config, "scr.notch");
	if (ph) {
		*ph = R_MAX (h, 1);
	}
	return R_MAX (w, 1);
}

static char *r_panels_show_status_input(RCore *core, const char *msg) {
	char *n_msg = r_str_newf (R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, PANEL_HL_COLOR, msg);
	RCons *cons = core->cons;
	r_panels_clamp_console_size (core, NULL, NULL);
	r_cons_gotoxy (cons, 0, 0);
	r_cons_flush (cons);
	char *out = r_cons_input (cons, n_msg);
	r_cons_set_raw (cons, true);
	free (n_msg);
	return out;
}

static bool r_panels_check_panel_type(RPanel *panel, const char *type) {
	if (!panel || !panel->model->cmd || !type) {
		return false;
	}
	const char *cmd = panel->model->cmd;
	char *tmp = strdup (cmd);
	int n = r_str_split (tmp, ' ');
	if (!n || R_STR_ISEMPTY (r_str_word_get0 (tmp, 0))) {
		free (tmp);
		return false;
	}
	int len = strlen (type);
	bool res = false;
	if (!strcmp (type, "pd")) {
		res = !strncmp (tmp, type, len)
			&& strcmp (cmd, "pdc")
			&& strcmp (cmd, "pdco")
			&& strcmp (cmd, "pdsf");
	} else if (!strcmp (type, "px")) {
		res = !strcmp (tmp, "px");
	} else if (!strcmp (type, "xc")) {
		res = !strcmp (tmp, "pxc");
		int i;
		for (i = 0; i < R_ARRAY_SIZE (hexdump_rotate); i++) {
			if (!strcmp (tmp, hexdump_rotate[i])) {
				res = true;
				break;
			}
		}
	} else {
		res = !strncmp (cmd, type, len);
	}
	free (tmp);
	return res;
}

static bool r_panels_check_root_state(RCore *core, RPanelsRootState state) {
	return core->panels_root->root_state == state;
}

static bool r_panels_search_db_check_panel_type(RCore *core, RPanel *panel, const char *ch) {
	char *str = r_panels_search_db (core, ch);
	bool ret = str && r_panels_check_panel_type (panel, str);
	free (str);
	return ret;
}

static bool r_panels_is_abnormal_cursor_type(RCore *core, RPanel *panel) {
	if (r_panels_check_panel_type (panel, "isq") || r_panels_check_panel_type (panel, "is,")
			|| r_panels_check_panel_type (panel, "afl")) {
		return true;
	}
	static const char *types[] = {
		"Disassembly Summary", "Strings in data sections", "Strings in the whole bin",
		"Breakpoints", "Sections", "Segments",
		"Comments"
	};
	int i;
	for (i = 0; i < R_ARRAY_SIZE (types); i++) {
		if (r_panels_search_db_check_panel_type (core, panel, types[i])) {
			return true;
		}
	}
	return false;
}

static bool r_panels_is_normal_cursor_type(RPanel *panel) {
	return (r_panels_check_panel_type (panel, "px") ||
			r_panels_check_panel_type (panel, "dr fpu;drf") ||
			r_panels_check_panel_type (panel, "dr") ||
			r_panels_check_panel_type (panel, "pd") ||
			r_panels_check_panel_type (panel, "xc"));
}

static bool r_panels_is_byte_hexdump(RPanel *panel) {
	const char *cmd = panel->model->cmd;
	const size_t len = cmd? strcspn (cmd, " "): 0;
	return (len == 2 && (!strncmp (cmd, "xc", len) || !strncmp (cmd, "px", len)))
		|| (len == 3 && !strncmp (cmd, "pxc", len));
}

static void r_panels_set_cmd_str_cache(RCore *core, RPanel *p, char *s) {
	free (p->model->cmdStrCache);
	p->model->cmdStrCache = s? strdup (s): NULL;
	set_dcb (core, p);
	set_pcb (p);
}

static void r_panels_set_read_only(RCore *core, RPanel *p, const char * R_NULLABLE s) {
	free (p->model->readOnly);
	p->model->readOnly = s? strdup (s): NULL;
	set_dcb (core, p);
	set_pcb (p);
}

static void r_panels_set_panel_addr(RCore *core, RPanel *panel, ut64 addr) {
	panel->model->addr = addr;
}

static int r_panels_get_panel_idx_in_pos(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		if (panels->mode == PANEL_MODE_ZOOM && i != panels->curnode) {
			continue;
		}
		RPanel *p = r_panels_get_panel (panels, i);
		if (p && (x >= p->view->pos.x && x < p->view->pos.x + p->view->pos.w)) {
			if (y >= p->view->pos.y && y < p->view->pos.y + p->view->pos.h) {
				return i;
			}
		}
	}
	return -1;
}

static char *r_panels_apply_filter_cmd(RCore *core, RPanel *panel) {
	if (!panel->model->filter) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new (panel->model->cmd);
	int i;
	for (i = 0; i < panel->model->n_filter; i++) {
		const char *filter = panel->model->filter[i];
		r_strbuf_appendf (sb, "~%s", filter);
	}
	return r_strbuf_drain (sb);
}

static const char *r_panels_handle_cmd_str_cache(RCore *core, RPanel *panel, bool refresh) {
	if (!refresh && panel->model->cache && panel->model->cmdStrCache) {
		return panel->model->cmdStrCache;
	}
	char *cmd = r_panels_apply_filter_cmd (core, panel);
	if (!cmd) {
		return NULL;
	}
	bool b = core->print->cur_enabled && r_panels_get_cur_panel (core->panels) != panel;
	if (b) {
		core->print->cur_enabled = false;
	}
	bool o_interactive = r_cons_is_interactive (core->cons);
	r_cons_set_interactive (core->cons, false);
	char *out = (*cmd == '.')
		? r_core_cmd_str_pipe (core, cmd)
		: r_core_cmd_str (core, cmd);
	r_cons_set_interactive (core->cons, o_interactive);
	r_panels_set_cmd_str_cache (core, panel, out);
	free (out);
	free (cmd);
	if (b) {
		core->print->cur_enabled = true;
	}
	return panel->model->cmdStrCache;
}

static void r_panels_panel_all_clear(RCore *core, RPanels *panels) {
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p) {
			RPanelPos *pos = &p->view->pos;
			r_cons_canvas_fill (panels->can, pos->x, pos->y, pos->w, pos->h, ' ');
		}
	}
	print_notch (core);
	r_cons_canvas_print (panels->can);
	r_cons_flush (core->cons);
}

static void r_panels_set_cursor(RCore *core, bool cur) {
	RPanel *p = r_panels_get_cur_panel (core->panels);
	RPrint *print = core->print;
	print->cur_enabled = cur;
	print->ocur = -1;
	if (r_panels_is_abnormal_cursor_type (core, p)) {
		return;
	}
	if (cur) {
		print->cur = p->view->curpos;
	} else {
		p->view->curpos = print->cur;
	}
	print->col = print->cur_enabled ? 1: 0;
}

static void r_panels_set_mode(RCore *core, RPanelsMode mode) {
	RPanels *panels = core->panels;
	panels->mouse_orig_x = -1;
	if (mode == PANEL_MODE_MENU && panels->mode != PANEL_MODE_MENU) {
		panels->frame_mode = panels->mode;
	}
	r_panels_set_cursor (core, false);
	panels->mode = mode;
	r_panels_update_help (core, panels);
}

static void r_panels_set_curnode(RCore *core, int idx) {
	RPanels *panels = core->panels;
	if (idx >= panels->n_panels) {
		idx = 0;
	}
	if (idx < 0) {
		idx = panels->n_panels - 1;
	}
	panels->curnode = idx;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (cur) {
		cur->view->curpos = cur->view->sy;
	}
}

static bool r_panels_check_panel_num(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->n_panels + 1 > PANEL_NUM_LIMIT) {
		(void)r_panels_show_status (core, "panel limit exceeded");
		return false;
	}
	return true;
}

static void r_panels_init_panel_param(RCore *core, RPanel *p, const char *title, const char *cmd) {
	if (!p) {
		return;
	}
	RPanelModel *m = p->model;
	RPanelView *v = p->view;
	m->type = PANEL_TYPE_DEFAULT;
	m->rotate = 0;
	v->curpos = 0;
	r_panels_set_panel_addr (core, p, core->addr);
	m->rotateCb = NULL;
	r_panels_set_cmd_str_cache (core, p, NULL);
	r_panels_set_read_only (core, p, NULL);
	m->funcName = NULL;
	v->refresh = true;
	v->edge = 0;
	free (m->title);
	free (m->cmd);
	if (title) {
		m->title = strdup (title);
		if (cmd) {
			m->cmd = strdup (cmd);
		} else {
			m->cmd = strdup ("");
		}
	} else if (cmd) {
		m->title = strdup (cmd);
		m->cmd = strdup (cmd);
	} else {
		m->title = strdup ("");
		m->cmd = strdup ("");
	}
	m->cache = r_panels_default_cache (core, p);
	set_pcb (p);
	if (R_STR_ISNOTEMPTY (m->cmd)) {
		set_dcb (core, p);
		r_panels_set_rcb (core->panels, p);
		if (r_panels_check_panel_type (p, "px")) {
			const ut64 stackbase = r_reg_getv (core->anal->reg, "SP");
			m->baseAddr = stackbase;
			r_panels_set_panel_addr (core, p, stackbase - r_config_get_i (core->config, "stack.delta"));
		}
	}
	core->panels->n_panels++;
	return;
}

static void r_panels_insert_panel(RCore *core, int n, const char *name, const char *cmd) {
	RPanels *panels = core->panels;
	if (panels->n_panels + 1 > PANEL_NUM_LIMIT) {
		return;
	}
	RPanel **panel = panels->panel;
	int i;
	RPanel *last = panel[panels->n_panels];
	for (i = panels->n_panels - 1; i >= n; i--) {
		panel[i + 1] = panel[i];
	}
	panel[n] = last;
	r_panels_init_panel_param (core, panel[n], name, cmd);
}

static void r_panels_adjust_and_add_panel(RCore *core, const char *name, char *cmd) {
	int h;
	unsigned int available_space;
	(void)r_cons_get_size (core->cons, &h);
	RPanels *panels = core->panels;
	available_space = r_panels_adjust_side_panels (core);
	r_panels_insert_panel (core, 0, name, cmd);
	RPanel *p0 = r_panels_get_panel (panels, 0);
	r_panels_set_geometry (&p0->view->pos, 0, PANEL_HEADER_H, available_space + 1, h - PANEL_HEADER_H - PANEL_FOOTER_H);
	r_panels_set_curnode (core, 0);
}

static int r_panels_separator(void *user) {
	return 0;
}

static void r_panels_add_help_panel(RCore *core) {
	//TODO: all these things done below are very hacky and refactoring needed
	char *help = "Help";
	r_panels_adjust_and_add_panel (core, help, help);
}

static char *r_panels_load_cmdf(RCore *core, RPanel *p, char *input, char *str) {
	char *res = r_panels_show_status_input (core, input);
	if (!res) {
		return NULL;
	}
	p->model->cmd = r_str_newf (str, res);
	char *ret = r_core_cmd_str (core, p->model->cmd);
	free (res);
	return ret;
}

static void r_panels_show_cursor(RCore *core) {
	const bool keyCursor = r_config_get_b (core->config, "scr.cursor");
	if (keyCursor) {
		r_cons_gotoxy (core->cons, core->cons->cpos.x, core->cons->cpos.y);
		r_cons_show_cursor (core->cons, 1);
		r_cons_flush (core->cons);
	}
}

static void r_panels_set_refresh_all(RCore *core, bool clearCache, bool force_refresh) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = r_panels_get_panel (panels, i);
		if (!force_refresh && r_panels_check_panel_type (panel, "cat $console")) {
			continue;
		}
		panel->view->refresh = true;
		if (clearCache) {
			r_panels_set_cmd_str_cache (core, panel, NULL);
		}
	}
}

static void r_panels_check_stackbase(RCore *core) {
	RPanels *panels = core->panels;
	const ut64 stackbase = r_reg_getv (core->anal->reg, "SP");
	int i;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p && p->model->cmd && r_panels_check_panel_type (p, "px") && p->model->baseAddr != stackbase) {
			p->model->baseAddr = stackbase;
			r_panels_set_panel_addr (core, p, stackbase - r_config_get_i (core->config, "stack.delta") + core->print->cur);
		}
	}
}

static void r_panels_toggle_help(RCore *core) {
	RPanels *ps = core->panels;
	int i;
	for (i = 0; i < ps->n_panels; i++) {
		RPanel *p = r_panels_get_panel (ps, i);
		if (r_str_endswith (p->model->cmd, "Help")) {
			r_panels_dismantle_del_panel (core, p, i);
			if (ps->mode == PANEL_MODE_MENU) {
				r_panels_set_mode (core, PANEL_MODE_DEFAULT);
			}
			return;
		}
	}
	r_panels_add_help_panel (core);
	if (ps->mode == PANEL_MODE_MENU) {
		r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	}
	r_panels_update_help (core, ps);
}

static void r_panels_reset_snow(RPanels *panels) {
	RPanel *cur = r_panels_get_cur_panel (panels);
	r_list_free (panels->snows);
	panels->snows = NULL;
	cur->view->refresh = true;
}

static void r_panels_toggle_zoom_mode(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (panels->mode != PANEL_MODE_ZOOM) {
		panels->prevMode = panels->mode;
		r_panels_set_mode (core, PANEL_MODE_ZOOM);
		r_panels_save_panel_pos (cur);
		r_panels_maximize_panel_size (panels);
	} else {
		r_panels_set_mode (core, panels->prevMode);
		panels->prevMode = PANEL_MODE_DEFAULT;
		r_panels_restore_panel_pos (cur);
		if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
			r_panels_reset_snow (panels);
		}
	}
}

static void r_panels_set_root_state(RCore *core, RPanelsRootState state) {
	core->panels_root->root_state = state;
}

static RPanels *r_panels_get_panels(RPanelsRoot *panels_root, int i) {
	if (!panels_root || (i >= PANEL_NUM_LIMIT)) {
		return NULL;
	}
	return panels_root->panels[i];
}

static void r_panels_renew_filter(RPanel *panel, int n) {
	panel->model->n_filter = 0;
	char **filter = calloc (sizeof (char *), n);
	if (!filter) {
		panel->model->filter = NULL;
		return;
	}
	panel->model->filter = filter;
}

static void r_panels_reset_filter(RCore *core, RPanel *panel) {
	free (panel->model->filter);
	panel->model->filter = NULL;
	r_panels_renew_filter (panel, PANEL_NUM_LIMIT);
	r_panels_set_cmd_str_cache (core, panel, NULL);
	panel->view->refresh = true;
}

static RConsCanvas *r_panels_create_new_canvas(RCore *core, int w, int h) {
	if (w < 1) {
		w = 1;
	}
	if (h < 1) {
		h = 1;
	}
	RConsCanvas *can = r_cons_canvas_new (core->cons, w, h, -2);
	if (!can) {
		return false;
	}
	r_cons_canvas_fill (can, 0, 0, w, h, ' ');
	can->linemode = r_config_get_i (core->config, "graph.linemode");
	can->color = r_config_get_i (core->config, "scr.color");
	return can;
}

static bool r_panels_init(RCore *core, RPanels *panels, int w, int h) {
	panels->columnWidth = (w > 0 && w < 140)? w / 3: 80;
	if (r_config_get_b (core->config, "cfg.debug")) {
		panels->layout = PANEL_LAYOUT_DEFAULT_DYNAMIC;
	}
	panels->can = r_panels_create_new_canvas (core, w, h);
	panels->mht = ht_pp_new (NULL, (HtPPKvFreeFunc)r_panels_mht_free_kv, (HtPPCalcSizeV)strlen);
	panels->fun = PANEL_FUN_NOFUN;
	return true;
}

static RPanels *r_panels_new(RCore *core) {
	RPanels *panels = R_NEW0 (RPanels);
	int h, w;
	r_panels_clamp_console_size (core, &w, &h);
	core->visual.firstRun = true;
	if (!r_panels_init (core, panels, w, h)) {
		free (panels);
		return NULL;
	}
	return panels;
}

static bool r_panels_alloc(RCore *core, RPanels *panels) {
	panels->panel = calloc (sizeof (RPanel *), PANEL_NUM_LIMIT);
	if (!panels->panel) {
		return false;
	}
	int i;
	for (i = 0; i < PANEL_NUM_LIMIT; i++) {
		panels->panel[i] = R_NEW0 (RPanel);
		panels->panel[i]->model = R_NEW0 (RPanelModel);
		r_panels_renew_filter (panels->panel[i], PANEL_NUM_LIMIT);
		panels->panel[i]->view = R_NEW0 (RPanelView);
	}
	return true;
}

static void r_panels_clear_panels_menuRec(RPanelsMenuItem *pmi) {
	size_t i = 0;
	for (i = 0; i < pmi->n_sub; i++) {
		RPanelsMenuItem *sub = pmi->sub[i];
		if (sub) {
			sub->selectedIndex = 0;
			r_panels_clear_panels_menuRec (sub);
		}
	}
}

static void r_panels_clear_panels_menu(RCore *core) {
	RPanels *p = core->panels;
	RPanelsMenu *pm = p->panels_menu;
	r_panels_clear_panels_menuRec (pm->root);
	pm->root->selectedIndex = 0;
	pm->history[0] = pm->root;
	pm->depth = 1;
	pm->n_refresh = 0;
}

static void r_panels_del_menu(RCore *core) {
	RPanels *panels = core->panels;
	RPanelsMenu *menu = panels->panels_menu;
	int i;
	menu->depth--;
	for (i = 1; i < menu->depth; i++) {
		menu->history[i]->p->view->refresh = true;
		menu->refreshPanels[i - 1] = menu->history[i]->p;
	}
	menu->n_refresh = menu->depth - 1;
}

static void r_panels_close_menu(RCore *core) {
	RPanels *panels = core->panels;
	RPanelsMenu *menu = panels->panels_menu;
	while (menu->depth > 1) {
		r_panels_del_menu (core);
	}
	r_panels_clear_panels_menu (core);
	r_panels_set_mode (core, panels->frame_mode);
	panels->frame_mode = PANEL_MODE_DEFAULT;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (cur) {
		cur->view->refresh = true;
	}
}

static void r_panels_toggle_cache(RCore *core, RPanel *p) {
	p->model->cache = !p->model->cache;
	r_panels_set_cmd_str_cache (core, p, NULL);
	p->view->refresh = true;
}

static void r_panels_set_filter(RCore *core, RPanel *panel) {
	if (!panel->model->filter) {
		return;
	}
	char *input = r_panels_show_status_input (core, "filter word: ");
	if (input && *input) {
		panel->model->filter[panel->model->n_filter++] = input;
		r_panels_set_cmd_str_cache (core, panel, NULL);
		panel->view->refresh = true;
	}
}

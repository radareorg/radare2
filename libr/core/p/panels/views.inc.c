/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

static void r_panels_set_rcb(RPanels *ps, RPanel *p) {
	int i;
	for (i = 0; i < n_rotate_entries; i++) {
		if (r_panels_check_panel_type (p, rotate_entries[i].cmd)) {
			p->model->rotateCb = rotate_entries[i].cb;
			return;
		}
	}
}

static int add_cmdf_panel(RCore *core, char *input, char *str) {
	RPanels *panels = core->panels;
	if (!r_panels_check_panel_num (core)) {
		return 0;
	}
	int h;
	(void)r_cons_get_size (core->cons, &h);
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_panels_adjust_side_panels (core);
	r_panels_insert_panel (core, 0, child->name, "");
	RPanel *p0 = r_panels_get_panel (panels, 0);
	if (h > PANEL_HEADER_H + PANEL_FOOTER_H) {
		r_panels_set_geometry (&p0->view->pos, 0, PANEL_HEADER_H, PANEL_CONFIG_SIDEPANEL_W, h - PANEL_HEADER_H - PANEL_FOOTER_H);
	}
	char *cmdf = r_panels_load_cmdf (core, p0, input, str);
	r_panels_set_cmd_str_cache (core, p0, cmdf);
	free (cmdf);
	r_panels_set_curnode (core, 0);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	return 0;
}

static void handle_print_rotate(RCore *core) {
	if (r_config_get_i (core->config, "asm.pseudo")) {
		r_config_toggle (core->config, "asm.pseudo");
		r_config_toggle (core->config, "asm.esil");
	} else if (r_config_get_i (core->config, "asm.esil")) {
		r_config_toggle (core->config, "asm.esil");
	} else {
		r_config_toggle (core->config, "asm.pseudo");
	}
}

static void replace_cmd(RCore *core, const char *title, const char *cmd) {
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	r_panels_set_cursor (core, false);
	free (cur->model->cmd);
	free (cur->model->title);
	cur->model->cmd = strdup (cmd);
	cur->model->title = strdup (title);
	cur->model->cache = r_panels_default_cache (core, cur);
	r_panels_set_cmd_str_cache (core, cur, NULL);
	r_panels_reset_scroll_pos (cur);
	if (r_panels_sync_seek (cur)) {
		r_panels_set_panel_addr (core, cur, core->addr);
	}
	cur->model->type = PANEL_TYPE_DEFAULT;
	set_dcb (core, cur);
	set_pcb (cur);
	r_panels_set_rcb (panels, cur);
	r_panels_set_refresh_all (core, false, true);
}

static void create_panel(RCore *core, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title, const char *cmd) {
	if (!r_panels_check_panel_num (core)) {
		return;
	}
	if (!panel) {
		return;
	}
	switch (dir) {
	case PANEL_LAYOUT_VERTICAL:
		r_panels_split_panel (core, panel, title, cmd, true);
		break;
	case PANEL_LAYOUT_HORIZONTAL:
		r_panels_split_panel (core, panel, title, cmd, false);
		break;
	case PANEL_LAYOUT_NONE:
		replace_cmd (core, title, cmd);
		break;
	}
}

static void create_panel_db(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title) {
	RCore *core = (RCore *)user;
	char *cmd = r_panels_search_db (core, title);
	if (!cmd) {
		return;
	}
	create_panel (core, panel, dir, title, cmd);
	free (cmd);
}

static void create_panel_input(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title) {
	RCore *core = (RCore *)user;
	char *cmd = r_panels_show_status_input (core, "Command: ");
	if (cmd) {
		create_panel (core, panel, dir, cmd, cmd);
	}
}

static void replace_current_panel_input(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title) {
	RCore *core = (RCore *)user;
	char *cmd = r_panels_show_status_input (core, "New command: ");
	if (R_STR_ISNOTEMPTY (cmd)) {
		replace_cmd (core, cmd, cmd);
	}
	free (cmd);
}

static char *search_strings(RCore *core, bool whole) {
	const char *title = whole ? "Strings in the whole bin" : "Strings in data sections";
	const char *str = r_panels_show_status_input (core, "Search Strings: ");
	char *db_val = r_panels_search_db (core, title);
	char *ret = r_str_newf ("%s~%s", db_val, str);
	free (db_val);
	return ret;
}

static void search_strings_data_create(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title) {
	RCore *core = (RCore *)user;
	char *str = search_strings (core, false);
	create_panel (core, panel, dir, title, str);
	free (str);
}

static void search_strings_bin_create(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title) {
	RCore *core = (RCore *)user;
	char *str = search_strings (core, true);
	create_panel (core, panel, dir, title, str);
	free (str);
}

static void update_disassembly_or_open(RCore *core) {
	RPanels *panels = core->panels;
	int i;
	bool create_new = true;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (r_panels_check_panel_type (p, "pd")) {
			r_panels_set_panel_addr (core, p, core->addr);
			create_new = false;
		}
	}
	if (create_new) {
		r_panels_prepare_layout (core);
		RPanel *panel = r_panels_get_panel (panels, 0);
		int x0 = panel->view->pos.x;
		int y0 = panel->view->pos.y;
		int w0 = panel->view->pos.w;
		int h0 = panel->view->pos.h;
		int threshold_w = x0 + panel->view->pos.w;
		int x1 = x0 + w0 / 2 - 1;
		int w1 = threshold_w - x1;

		r_panels_insert_panel (core, 0, "Disassembly", "pd");
		RPanel *p0 = r_panels_get_panel (panels, 0);
		r_panels_set_geometry (&p0->view->pos, x0, y0, w0 / 2, h0);

		RPanel *p1 = r_panels_get_panel (panels, 1);
		r_panels_set_geometry (&p1->view->pos, x1, y0, w1, h0);

		r_panels_set_cursor (core, false);
		r_panels_set_curnode (core, 0);
	}
}

static bool r_panels_default_cache(RCore *core, RPanel *panel) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (modal_entries_db); i++) {
		const ModalEntryDef *entry = &modal_entries_db[i];
		if (entry->cache != PANEL_CACHE_AUTO && entry->cmd
				&& !strcmp (entry->name, panel->model->title) && !strcmp (entry->cmd, panel->model->cmd)) {
			return entry->cache == PANEL_CACHE_ON;
		}
	}
	for (i = 0; i < R_ARRAY_SIZE (cache_white_list_cmds); i++) {
		if (r_str_startswith (panel->model->cmd, cache_white_list_cmds[i])) {
			return true;
		}
	}
	return r_panels_is_abnormal_cursor_type (core, panel);
}

static char *r_panels_search_db(RCore *core, const char *title) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (modal_entries_db); i++) {
		const ModalEntryDef *entry = &modal_entries_db[i];
		if (entry->cmd && !strcmp (entry->name, title)) {
			return strdup (entry->cmd);
		}
	}
	return NULL;
}

static void init_modal_db(RCore *core) {
	free (modal_entries);
	modal_entries = R_NEWS0 (ModalEntry, R_ARRAY_SIZE (modal_entries_db));
	n_modal_entries = 0;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (modal_entries_db); i++) {
		const ModalEntryDef *entry = &modal_entries_db[i];
		modal_entries[n_modal_entries].name = strdup (entry->name);
		modal_entries[n_modal_entries].cb = entry->cb? entry->cb: create_panel_db;
		n_modal_entries++;
	}
}

static void rotate_panel_cmds(RCore *core, const char **cmds, const int cmdslen, const char *prefix, bool rev) {
	if (!cmdslen) {
		return;
	}
	RPanel *p = r_panels_get_cur_panel (core->panels);
	r_panels_reset_filter (core, p);
	if (rev) {
		if (!p->model->rotate) {
			p->model->rotate = cmdslen - 1;
		} else {
			p->model->rotate--;
		}
	} else {
		p->model->rotate++;
	}
	char tmp[64], *between;
	int i = p->model->rotate % cmdslen;
	snprintf (tmp, sizeof (tmp), "%s%s", prefix, cmds[i]);
	between = r_str_between (p->model->cmd, prefix, " ");
	if (between) {
		char replace[64];
		snprintf (replace, sizeof (replace), "%s%s", prefix, between);
		p->model->cmd = r_str_replace (p->model->cmd, replace, tmp, 1);
	} else {
		free (p->model->cmd);
		p->model->cmd = strdup (tmp);
	}
	r_panels_set_cmd_str_cache (core, p, NULL);
	p->view->refresh = true;
	free (between);
}

static void rotate_entropy_v_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	rotate_panel_cmds (core, entropy_rotate, R_ARRAY_SIZE (entropy_rotate), "p=", rev);
}

static void rotate_entropy_h_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	rotate_panel_cmds (core, entropy_rotate, R_ARRAY_SIZE (entropy_rotate), "p==", rev);
}

static void rotate_asmemu(RCore *core, RPanel *p) {
	const bool isEmuStr = r_config_get_b (core->config, "emu.str");
	const bool isEmu = r_config_get_b (core->config, "asm.emu");
	if (isEmu) {
		if (isEmuStr) {
			r_config_set_b (core->config, "emu.str", false);
		} else {
			r_config_set_b (core->config, "asm.emu", false);
		}
	} else {
		r_config_set_b (core->config, "emu.str", true);
	}
	p->view->refresh = true;
}

static void rotate_hexdump_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	RPanel *p = r_panels_get_cur_panel (core->panels);

	if (rev) {
		p->model->rotate--;
	} else {
		p->model->rotate++;
	}
	core->visual.hexMode = p->model->rotate;
	applyHexMode (core);
	rotate_asmemu (core, p);
}

static void rotate_register_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	rotate_panel_cmds (core, register_rotate, R_ARRAY_SIZE (register_rotate), "dr", rev);
}

static void rotate_function_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	rotate_panel_cmds (core, function_rotate, R_ARRAY_SIZE (function_rotate), "af", rev);
}

static void rotate_disasm_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	RPanel *p = r_panels_get_cur_panel (core->panels);

	//TODO: need to come up with a better solution but okay for now
	if (!strcmp (p->model->cmd, "pdc") ||
			!strcmp (p->model->cmd, "pdco")) {
		return;
	}

	if (rev) {
		if (p->model->rotate > 0) {
			p->model->rotate--;
		} else {
			p->model->rotate = 4;
		}
	} else {
		p->model->rotate++;
	}
	core->visual.disMode = p->model->rotate;
	applyDisMode (core);
	rotate_asmemu (core, p);
}

static void init_rotate_db(RCore *core) {
	n_rotate_entries = 0;
	rotate_entries[n_rotate_entries++] = (RotateEntry){ "pd", rotate_disasm_cb };
	rotate_entries[n_rotate_entries++] = (RotateEntry){ "p==", rotate_entropy_h_cb };
	rotate_entries[n_rotate_entries++] = (RotateEntry){ "p=", rotate_entropy_v_cb };
	rotate_entries[n_rotate_entries++] = (RotateEntry){ "px", rotate_hexdump_cb };
	rotate_entries[n_rotate_entries++] = (RotateEntry){ "dr", rotate_register_cb };
	rotate_entries[n_rotate_entries++] = (RotateEntry){ "af", rotate_function_cb };
	rotate_entries[n_rotate_entries++] = (RotateEntry){ "xc", rotate_hexdump_cb };
}

static void init_all_dbs(RCore *core) {
	init_modal_db (core);
	init_rotate_db (core);
}

static bool check_func_diff(RCore *core, RPanel *p) {
	RAnalFunction *func = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	if (!func) {
		if (R_STR_ISEMPTY (p->model->funcName)) {
			return false;
		}
		R_FREE (p->model->funcName);
		return true;
	}
	if (!p->model->funcName || strcmp (p->model->funcName, func->name)) {
		free (p->model->funcName);
		p->model->funcName = strdup (func->name);
		return true;
	}
	return false;
}

static void print_default_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	const char *cmdstr = r_panels_handle_cmd_str_cache (core, panel, false);
	r_panels_update_panel_contents (core, panel, cmdstr);
}

static void print_decompiler_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	RAnalFunction *func = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	if (!func) {
		char *msg = r_str_newf ("No function at 0x%08"PFMT64x, core->addr);
		r_panels_set_cmd_str_cache (core, panel, msg);
		r_panels_update_pdc_contents (core, panel, msg);
		free (msg);
		return;
	}
	const char *cmdstr = r_panels_handle_cmd_str_cache (core, panel, false);
	if (R_STR_ISNOTEMPTY (cmdstr)) {
		r_panels_update_pdc_contents (core, panel, cmdstr);
	}
}

static void print_disasmsummary_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && check_func_diff (core, panel);
	const char *cmdstr = r_panels_handle_cmd_str_cache (core, panel, update);
	if (update && panel->model->cache) {
		r_panels_reset_scroll_pos (panel);
	}
	r_panels_update_panel_contents (core, panel, cmdstr);
}

static void print_disassembly_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	core->print->screen_bounds = 1LL;
	char *ocmd = panel->model->cmd;
	if (panel->model->cmd && !strcmp (panel->model->cmd, "pd")) {
		panel->model->cmd = r_str_newf ("%s %d", panel->model->cmd, panel->view->pos.h - 3);
	} else {
		panel->model->cmd = strdup (panel->model->cmd);
	}
	ut64 o_offset = core->addr;
	core->addr = panel->model->addr;
	r_core_seek (core, panel->model->addr, true);
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_core_cmd (core, ".dr*", 0);
	}
	const char *cmdstr = r_panels_handle_cmd_str_cache (core, panel, false);
	core->addr = o_offset;
	free (panel->model->cmd);
	panel->model->cmd = ocmd;
	r_panels_update_panel_contents (core, panel, cmdstr);
}

static void r_panels_capture_graph(const RAGraph *graph, void *user) {
	RPanelsGraphNodes *nodes = user;
	RListIter *iter;
	RGraphNode *node;
	r_list_foreach (r_graph_get_nodes (graph->graph), iter, node) {
		RANode *anode = node->data;
		if (anode->is_dummy) {
			continue;
		}
		RPanelsGraphNode *position = RPanelsGraphNodes_emplace_back (nodes);
		if (!position) {
			break;
		}
		position->addr = r_num_get (NULL, anode->title);
		position->x = anode->x + graph->can->sx;
		position->y = anode->y + graph->can->sy + R_STR_ISNOTEMPTY (graph->title);
	}
}

static void r_panels_focus_graph(RCore *core, RPanel *panel) {
	RPanelsModel *model = (RPanelsModel *)panel->model;
	ut64 addr = r_anal_get_bbaddr (core->anal, core->addr);
	RPanelsGraphNode *node, *target = NULL;
	R_VEC_FOREACH (&model->graph_nodes, node) {
		if (node->addr == addr) {
			target = node;
			break;
		}
	}
	if (!target && !model->graph_focused && !RPanelsGraphNodes_empty (&model->graph_nodes)) {
		target = RPanelsGraphNodes_at (&model->graph_nodes, 0);
	}
	if (target) {
		panel->view->sx = R_MAX (0, target->x - 1);
		panel->view->sy = R_MAX (0, target->y - 1);
	}
	model->graph_addr = core->addr;
	model->graph_focused = true;
}

static void print_graph_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	RPanelsModel *model = (RPanelsModel *)panel->model;
	bool refresh = core->panels->autoUpdate || !panel->model->cache || !panel->model->cmdStrCache;
	bool update = refresh && check_func_diff (core, panel);
	if (refresh && !panel->model->funcName && r_panels_is_graph_panel (panel)) {
		if (update || !panel->model->cmdStrCache) {
			r_panels_reset_scroll_pos (panel);
		}
		char *msg = r_str_newf ("No function at 0x%08"PFMT64x"\nRight-click > Analyze function", core->addr);
		r_panels_set_cmd_str_cache (core, panel, msg);
		r_panels_update_panel_contents (core, panel, msg);
		free (msg);
		return;
	}
	bool geometry = r_panels_is_graph_panel (panel) && !panel->model->n_filter;
	bool capture = geometry && (update || !panel->model->cache || !panel->model->cmdStrCache);
	bool focus = update || !model->graph_focused || model->graph_addr != core->addr;
	RPanelsGraphNodes nodes;
	RPanelsGraphNodes_init (&nodes);
	RCoreGraphCapture context = { r_panels_capture_graph, &nodes };
	RCorePriv *priv = core->priv;
	RCoreGraphCapture *saved_capture = priv->graph_capture;
	if (capture) {
		priv->graph_capture = &context;
	}
	const char *cmdstr = r_panels_handle_cmd_str_cache (core, panel, update);
	priv->graph_capture = saved_capture;
	if (capture) {
		RPanelsGraphNodes_fini (&model->graph_nodes);
		model->graph_nodes = nodes;
	}
	if (geometry && focus) {
		r_panels_focus_graph (core, panel);
	}
	core->cons->event_resize = NULL;
	core->cons->event_data = core;
	core->cons->event_resize = (RConsEvent) r_panels_do_panels_refreshQueued;
	r_panels_update_panel_contents (core, panel, cmdstr);
}

static void print_stack_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	if (panel->model->cache && panel->model->cmdStrCache) {
		r_panels_update_panel_contents (core, panel, panel->model->cmdStrCache);
		return;
	}
	const int size = r_config_get_i (core->config, "stack.size");
	const int delta = r_panels_sync_seek (panel)? r_config_get_i (core->config, "stack.delta"): 0;
	const int bits = r_config_get_i (core->config, "asm.bits");
	const char sign = (delta < 0)? '+': '-';
	const int absdelta = R_ABS (delta);
	char *cmd = r_str_newf ("px%s %d", bits == 32? "w": "q", size);
	panel->model->cmd = cmd;
	ut64 sp_addr = r_panels_sync_seek (panel)? r_reg_getv (core->anal->reg, "SP"): panel->model->addr;
	char *k = r_str_newf ("%s @ 0x%08"PFMT64x"%c%d", cmd, sp_addr, sign, absdelta);
	char *cmdstr = r_core_cmd_str (core, k);
	free (k);
	if (R_STR_ISNOTEMPTY (cmdstr)) {
		r_panels_set_cmd_str_cache (core, panel, cmdstr);
	}
	r_panels_update_panel_contents (core, panel, cmdstr);
	free (cmdstr);
}

static void print_hexdump_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	ut64 saved_addr = core->addr;
	r_core_seek (core, panel->model->addr, true);
	const char *cmdstr = r_panels_handle_cmd_str_cache (core, panel, false);
	r_core_seek (core, saved_addr, true);
	r_panels_update_panel_contents (core, panel, cmdstr);
}

static void set_pcb(RPanel *p) {
	if (!p->model->cmd) {
		return;
	}
	if (r_panels_check_panel_type (p, "pd")) {
		p->model->print_cb = print_disassembly_cb;
		return;
	}
	if (r_panels_check_panel_type (p, "px")) {
		p->model->print_cb = print_stack_cb;
		return;
	}
	if (r_panels_check_panel_type (p, "xc")) {
		p->model->print_cb = print_hexdump_cb;
		return;
	}
	if (r_panels_check_panel_type (p, "pdc")) {
		p->model->print_cb = print_decompiler_cb;
		return;
	}
	if (r_panels_check_panel_type (p, "agf") || r_panels_check_panel_type (p, "agft")) {
		p->model->print_cb = print_graph_cb;
		return;
	}
	if (r_panels_check_panel_type (p, "pdsf")) {
		p->model->print_cb = print_disasmsummary_cb;
		return;
	}
	p->model->print_cb = print_default_cb;
}

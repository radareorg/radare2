/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

static char *r_panels_config_path(bool syspath) {
	if (syspath) {
		char *pfx = r_sys_prefix (NULL);
		char *res = r_file_new (pfx, R2_DATDIR_R2, "panels", NULL);
		free (pfx);
		return res;
	}
	return r_xdg_datadir ("r2panels");
}

static char *create_panels_config_path(const char *file) {
	char *dir = r_panels_config_path (false);
	r_sys_mkdirp (dir);
	char *path = r_file_new (dir, file, NULL);
	free (dir);
	return path;
}

static char *get_panels_config_file_from_dir(const char *file) {
	int i;
	for (i = 0; i < 2; i++) {
		char *dir = r_panels_config_path (i);
		char *path = r_file_new (dir, file, NULL);
		free (dir);
		if (r_file_exists (path)) {
			return path;
		}
		free (path);
	}
	return NULL;
}

static void panels_save(RCore *core, const char *oname) {
	if (!core->panels) {
		return;
	}
	char *input = NULL;
	const char *name = oname? r_str_trim_head_ro (oname): NULL;
	if (R_STR_ISEMPTY (name)) {
		name = input = r_panels_show_status_input (core, "Name for the layout: ");
	}
	if (R_STR_ISEMPTY (name)) {
		(void)r_panels_show_status (core, "Name can't be empty!");
		free (input);
		return;
	}
	char *path = create_panels_config_path (name);
	free (input);
	RPanels *panels = core->panels;
	const bool zoom = frame_maximize_state (core, r_panels_get_cur_panel (panels));
	PJ *pj = r_core_pj_new (core);
	pj_a (pj);
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = r_panels_get_panel (panels, i);
		bool maximized = zoom && i == panels->curnode;
		RPanelPos *pos = maximized? &panel->view->prevPos: &panel->view->pos;
		pj_o (pj);
		pj_ks (pj, "Title", panel->model->title);
		pj_ks (pj, "Cmd", panel->model->cmd);
		pj_kb (pj, "Cache", panel->model->cache);
		pj_kb (pj, "Sync", r_panels_sync_seek (panel));
		pj_kb (pj, "Maximize", maximized);
		pj_kn (pj, "Addr", panel->model->addr);
		pj_kn (pj, "x", pos->x);
		pj_kn (pj, "y", pos->y);
		pj_kn (pj, "w", pos->w);
		pj_kn (pj, "h", pos->h);
		pj_end (pj);
	}
	pj_end (pj);
	if (r_file_dump (path, (const ut8 *)pj_string (pj), -1, false)) {
		r_panels_update_menu (core, "Edit.Settings.Load Layout.Saved..", init_menu_saved_layout);
		(void)r_panels_show_status (core, "Panels layout saved!");
	}
	pj_free (pj);
	free (path);
}

static bool r_panels_config_bool(const RJson *item, const char *name, bool fallback) {
	const RJson *value = r_json_get (item, name);
	return value && value->type == R_JSON_BOOLEAN? value->num.u_value != 0: fallback;
}

static bool r_panels_config_position(const RJson *item, RPanelPos *pos) {
	if (item->type != R_JSON_OBJECT || !r_json_get_str (item, "Title") || !r_json_get_str (item, "Cmd")) {
		return false;
	}
	const char *keys[] = { "x", "y", "w", "h" };
	int values[4], i;
	for (i = 0; i < R_ARRAY_SIZE (keys); i++) {
		const RJson *value = r_json_get (item, keys[i]);
		if (!value || value->type != R_JSON_INTEGER || value->num.u_value > MAX_CANVAS_SIZE) {
			return false;
		}
		values[i] = value->num.u_value;
	}
	*pos = (RPanelPos){ values[0], values[1], values[2], values[3] };
	return pos->w >= PANEL_CONFIG_MIN_SIZE && pos->h >= PANEL_CONFIG_MIN_SIZE;
}

static bool panels_load(RCore *core, const char *name) {
	if (!core->panels) {
		return false;
	}
	char *path = get_panels_config_file_from_dir (name);
	char *text = path? r_file_slurp (path, NULL): NULL;
	free (path);
	if (!text) {
		R_LOG_ERROR ("Cannot read panel layout '%s'", name);
		return false;
	}
	char *wrapped = *r_str_trim_head_ro (text) == '['? NULL: r_str_newf ("[%s]", text);
	RJson *json = r_json_parsedup (wrapped? wrapped: text);
	free (wrapped);
	free (text);
	bool valid = json && json->type == R_JSON_ARRAY && json->children.count > 0 && json->children.count <= PANEL_NUM_LIMIT;
	RPanelPos positions[PANEL_NUM_LIMIT];
	const RJson *item;
	int i = 0;
	if (valid) {
		for (item = json->children.first; item; item = item->next) {
			if (!r_panels_config_position (item, &positions[i++])) {
				valid = false;
				break;
			}
		}
	}
	if (!valid) {
		r_json_free (json);
		R_LOG_ERROR ("Invalid panel layout '%s'", name);
		return false;
	}
	RPanels *panels = core->panels;
	r_panels_prepare_layout (core);
	r_panels_panel_all_clear (core, panels);
	panels->n_panels = 0;
	r_panels_set_curnode (core, 0);
	int maximized = -1;
	i = 0;
	for (item = json->children.first; item; item = item->next, i++) {
		RPanel *panel = r_panels_get_panel (panels, i);
		RPanelPos *pos = &positions[i];
		if (pos->y < PANEL_HEADER_H) {
			pos->h = R_MAX (pos->h - (PANEL_HEADER_H - pos->y), PANEL_CONFIG_MIN_SIZE);
			pos->y = PANEL_HEADER_H;
		}
		if (panels->can) {
			pos->h = R_MAX (R_MIN (pos->h, panels->can->h - PANEL_FOOTER_H - pos->y), PANEL_CONFIG_MIN_SIZE);
		}
		panel->view->pos = *pos;
		r_panels_init_panel_param (core, panel, r_json_get_str (item, "Title"), r_json_get_str (item, "Cmd"));
		panel->model->cache = r_panels_config_bool (item, "Cache", panel->model->cache);
		((RPanelsModel *)panel->model)->sync_seek = r_panels_config_bool (item, "Sync", true);
		const RJson *addr = r_json_get (item, "Addr");
		if (!r_panels_sync_seek (panel) && addr && addr->type == R_JSON_INTEGER) {
			panel->model->addr = addr->num.u_value;
		}
		set_dcb (core, panel);
		if (r_str_endswith (panel->model->cmd, "Help")) {
			r_panels_setup_help_panel (core, panel, "Panels Mode", help_msg_panels);
		}
		if (r_panels_config_bool (item, "Maximize", false)) {
			maximized = i;
		}
	}
	r_json_free (json);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	if (maximized >= 0) {
		r_panels_set_curnode (core, maximized);
		r_panels_toggle_zoom_mode (core);
	}
	r_panels_set_refresh_all (core, true, false);
	return true;
}

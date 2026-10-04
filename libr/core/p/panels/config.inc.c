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
	char *dir_path = r_panels_config_path (false);
	r_sys_mkdirp (dir_path);
	char *file_path = r_str_newf (R_JOIN_2_PATHS ("%s", "%s"), dir_path, file);
	R_FREE (dir_path);
	return file_path;
}

static char *get_panels_config_file_from_dir(const char *file) {
	char *dir_path = r_panels_config_path (false);
	RList *dir = r_sys_dir (dir_path);
	if (!dir_path || !dir) {
		free (dir_path);
		dir_path = r_panels_config_path (true);
		r_list_free (dir);
		dir = r_sys_dir (dir_path);
		if (!dir || !dir_path) {
			free (dir_path);
			r_list_free (dir);
			return NULL;
		}
	}
	char *tmp = NULL;
	RListIter *it;
	char *entry;
	r_list_foreach (dir, it, entry) {
		if (!strcmp (entry, file)) {
			tmp = entry;
			break;
		}
	}
	if (!tmp) {
		r_list_free (dir);
		free (dir_path);
		return NULL;
	}
	char *ret = r_str_newf (R_JOIN_2_PATHS ("%s", "%s"), dir_path, tmp);
	r_list_free (dir);
	free (dir_path);
	return ret;
}

static char *parse_panels_config(const char *cfg, int len) {
	if (R_STR_ISEMPTY (cfg) || len < 2) {
		return NULL;
	}
	char *tmp = R_STR_NDUP (cfg, len + 1);
	if (!tmp) {
		return NULL;
	}
	int i = 0;
	for (; tmp[i] && i < len; i++) {
		if (tmp[i] == '}') {
			if (i + 1 < len) {
				if (tmp[i + 1] == ',') {
					tmp[i + 1] = '\n';
				}
				continue;
			}
			tmp[i + 1] = '\n';
		}
	}
	return tmp;
}

static void panels_save(RCore *core, const char *oname) {
	int i;
	if (!core->panels) {
		return;
	}
	const char *name = oname? r_str_trim_head_ro (oname): NULL;
	if (R_STR_ISEMPTY (name)) {
		name = r_panels_show_status_input (core, "Name for the layout: ");
		if (R_STR_ISEMPTY (name)) {
			(void)r_panels_show_status (core, "Name can't be empty!");
			return;
		}
	}
	char *config_path = create_panels_config_path (name);
	RPanels *panels = core->panels;
	PJ *pj = r_core_pj_new (core);
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = r_panels_get_panel (panels, i);
		pj_o (pj);
		pj_ks (pj, "Title", panel->model->title);
		pj_ks (pj, "Cmd", panel->model->cmd);
		pj_kb (pj, "Cache", panel->model->cache);
		pj_kn (pj, "x", panel->view->pos.x);
		pj_kn (pj, "y", panel->view->pos.y);
		pj_kn (pj, "w", panel->view->pos.w);
		pj_kn (pj, "h", panel->view->pos.h);
		pj_end (pj);
	}
	FILE *fd = r_sandbox_fopen (config_path, "w");
	if (fd) {
		char *pjs = pj_drain (pj);
		fprintf (fd, "%s\n", pjs);
		free (pjs);
		fclose (fd);
		r_panels_update_menu (core, "Edit.Settings.Load Layout.Saved..", init_menu_saved_layout);
		(void)r_panels_show_status (core, "Panels layout saved!");
	} else {
		pj_free (pj);
	}
	free (config_path);
}

static bool panels_load(RCore *core, const char *_name) {
	if (!core->panels) {
		return false;
	}
	char *config_path = get_panels_config_file_from_dir (_name);
	if (!config_path) {
		char *tmp = r_str_newf ("No saved layout found for the name: %s", _name);
		(void)r_panels_show_status (core, tmp);
		free (tmp);
		return false;
	}
	char *panels_config = r_file_slurp (config_path, NULL);
	free (config_path);
	if (!panels_config) {
		char *tmp = r_str_newf ("Layout is empty: %s", _name);
		(void)r_panels_show_status (core, tmp);
		free (tmp);
		return false;
	}
	RPanels *panels = core->panels;
	r_panels_panel_all_clear (core, panels);
	panels->n_panels = 0;
	r_panels_set_curnode (core, 0);
	char *x, *y, *w, *h;
	char *p_cfg = panels_config;
	char *tmp_cfg = parse_panels_config (p_cfg, strlen (p_cfg));
	int tmp_count = r_str_split (tmp_cfg, '\n');
	int i;
	for (i = 0; i < tmp_count; i++) {
		if (R_STR_ISEMPTY (tmp_cfg)) {
			break;
		}
		char *title = sdb_json_get_str (tmp_cfg, "Title");
		char *cmd = sdb_json_get_str (tmp_cfg, "Cmd");
		(void)r_str_arg_unescape (cmd);
		x = sdb_json_get_str (tmp_cfg, "x");
		y = sdb_json_get_str (tmp_cfg, "y");
		w = sdb_json_get_str (tmp_cfg, "w");
		h = sdb_json_get_str (tmp_cfg, "h");
		RPanel *p = r_panels_get_panel (panels, panels->n_panels);
		int py = atoi (y);
		int ph = atoi (h);
		if (py < PANEL_HEADER_H) {
			ph = R_MAX (ph - (PANEL_HEADER_H - py), PANEL_CONFIG_MIN_SIZE);
			py = PANEL_HEADER_H;
		}
		if (panels->can && py + ph > panels->can->h - PANEL_FOOTER_H) {
			ph = R_MAX (panels->can->h - PANEL_FOOTER_H - py, PANEL_CONFIG_MIN_SIZE);
		}
		r_panels_set_geometry (&p->view->pos, atoi (x), py, atoi (w), ph);
		r_panels_init_panel_param (core, p, title, cmd);
		char *cache = sdb_json_get_str (tmp_cfg, "Cache");
		if (cache) {
			p->model->cache = !strcmp (cache, "true");
			free (cache);
		}
		if (r_str_endswith (cmd, "Help")) {
			r_panels_setup_help_panel(core, p, "Panels Mode", help_msg_panels);
		}
		tmp_cfg += strlen (tmp_cfg) + 1;
	}
	free (panels_config);
	if (!panels->n_panels) {
		free (tmp_cfg);
		return false;
	}
	r_panels_set_refresh_all (core, true, false);
	return true;
}

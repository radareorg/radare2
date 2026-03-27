/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

#include <r_core.h>

R_IPI void applyDisMode(RCore *core);
R_IPI void applyHexMode(RCore *core);

#define MENU_Y 1
#define PANEL_NUM_LIMIT 16
#define PANEL_HL_COLOR core->cons->context->pal.graph_box2
#define PANEL_CONFIG_SIDEPANEL_W 60
#define PANEL_CONFIG_MIN_SIZE    2
#define PANEL_CONFIG_RESIZE_W    4
#define PANEL_CONFIG_RESIZE_H    4
#define MAX_CANVAS_SIZE 0xffffff

#define PP(pos, off) (*(int *)((char *)&(pos) + (off)))

#define R_INCLUDE_BEGIN 1
#include "panels.inc.c"

R_API void r_core_panels_save(RCore *core, const char *oname) {
	int i;
	if (!core->panels) {
		return;
	}
	const char *name = r_str_trim_head_ro (oname); // leading whitespace skipped
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
		r_panels_update_menu (core, "Settings.Load Layout.Saved..", init_menu_saved_layout);
		(void)r_panels_show_status (core, "Panels layout saved!");
	} else {
		pj_free (pj);
	}
	free (config_path);
}

R_API bool r_core_panels_load(RCore *core, const char *_name) {
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
		r_panels_set_geometry (&p->view->pos, atoi (x), atoi (y), atoi (w),atoi (h));
		r_panels_init_panel_param (core, p, title, cmd);
		// TODO: fix code duplication with r_panels_update_help
		if (r_str_endswith (cmd, "Help")) {
			free (p->model->title);
			free (p->model->cmd);
			p->model->title = strdup ("Help");
			p->model->cmd = strdup ("Help");
			RStrBuf *rsb = r_strbuf_new (NULL);
			r_core_visual_append_help (core, rsb, "Panels Mode", help_msg_panels);
			if (!rsb) {
				return false;
			}
			char *drained_string = r_strbuf_drain (rsb);
			if (drained_string) {
				r_panels_set_read_only (core, p, drained_string);
				free (drained_string);
			}
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

R_API bool r_core_panels_root(RCore *core, RPanelsRoot *panels_root) {
	core->visual.fromVisual = core->vmode;
	if (!panels_root) {
		panels_root = R_NEW0 (RPanelsRoot);
		core->panels_root = panels_root;
		panels_root->panels = calloc (sizeof (RPanels *), PANEL_NUM_LIMIT);
		panels_root->n_panels = 0;
		panels_root->cur_panels = 0;
		panels_root->pdc_caches = sdb_new0 ();
		panels_root->cur_pdc_cache = NULL;
		r_panels_set_root_state (core, DEFAULT);
		init_new_panels_root (core);
	} else {
		if (!panels_root->n_panels) {
			panels_root->n_panels = 0;
			panels_root->cur_panels = 0;
			init_new_panels_root (core);
		}
		const char *pdc_now = r_config_get (core->config, "cmd.pdc");
		if (sdb_exists (panels_root->pdc_caches, pdc_now)) {
			panels_root->cur_pdc_cache = sdb_ptr_get (panels_root->pdc_caches, pdc_now, 0);
		} else {
			Sdb *sdb = sdb_new0();
			sdb_ptr_set (panels_root->pdc_caches, strdup (pdc_now), sdb, 0);
			panels_root->cur_pdc_cache = sdb;
		}
	}
	const char *layout = r_config_get (core->config, "scr.layout");
	if (!R_STR_ISEMPTY (layout)) {
		r_core_cmdf (core, "v %s", layout);
	}
	RPanels *panels = panels_root->panels[panels_root->cur_panels];
	if (panels) {
		size_t i = 0;
		for (; i < panels->n_panels; i++) {
			RPanel *cur = r_panels_get_panel (panels, i);
			if (cur) {
				cur->model->addr = core->addr;
			}
		}
	}
	int maxpage = r_config_get_i (core->config, "scr.maxpage");
	r_config_set_i (core->config, "scr.maxpage", 0);
	r_cons_set_raw (core->cons, true);
	while (panels_root->n_panels) {
		r_panels_set_root_state (core, DEFAULT);
		panels_process (core, panels_root->panels[panels_root->cur_panels]);
		if (r_panels_check_root_state (core, DEL)) {
			r_panels_del_panels (core);
		}
		if (r_panels_check_root_state (core, QUIT)) {
			break;
		}
	}
	r_config_set_i (core->config, "scr.maxpage", maxpage);
	if (core->visual.fromVisual) {
		r_core_visual (core, "");
	} else {
		r_cons_enable_mouse (core->cons, false);
	}
	return true;
}

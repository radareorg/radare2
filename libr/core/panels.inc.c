#if R_INCLUDE_BEGIN

// Forward declarations for functions defined in panels.c
static int __add_cmd_panel(void *user);
static int __config_toggle_cb(void *user);
static int __config_value_cb(void *user);
static void __create_panel_input(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title);
static void __cursor_del_breakpoints(RCore *core, RPanel *panel);
static void __handle_refs(RCore *core, RPanel *panel, ut64 tmp);
static void __handle_tab_new_with_cur_panel(RCore *core);
static void __init_new_panels_root(RCore *core);
static void __insert_value(RCore *core, int wat);
static void __jmp_to_cursor_addr(RCore *core, RPanel *panel);
static void __refresh_core_offset(RCore *core);
static void __replace_cmd(RCore *core, const char *title, const char *cmd);
static void __set_addr_by_type(RCore *core, const char *cmd, ut64 addr);
static void __set_breakpoints_on_cursor(RCore *core, RPanel *panel);
static void __set_dcb(RCore *core, RPanel *p);
static void __set_pcb(RPanel *p);
static void demo_begin(RCore *core, RConsCanvas *can);

// Forward declarations for API functions defined later in this file
static void r_panels_panels_refresh(RCore *core);
static RList *r_panels_sorted_list(RCore *core, const char *menu[], int count);
static void r_panels_show_cursor(RCore *core);

static void r_panels_print_notch(RCore *core) {
	int i, notch = r_config_get_i (core->config, "scr.notch");
	for (i = 0; i < notch; i++) {
		r_cons_printf (core->cons, R_CONS_CLEAR_LINE"\n");
	}
}

static RPanel *r_panels_get_panel(RPanels *panels, int i) {
	return (panels && i < PANEL_NUM_LIMIT)? panels->panel[i]: NULL;
}

static void r_panels_update_edge_x(RCore *core, int x) {
	RPanels *panels = core->panels;
	int i, j;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p0 = r_panels_get_panel (panels, i);
		if (!p0) {
			continue;
		}
		RPanelPos *pos = &p0->view->pos;
		if (pos->x - 2 <= panels->mouse_orig_x && panels->mouse_orig_x <= pos->x + 2) {
			int tmp = pos->x;
			pos->x += x;
			pos->w -= x;
			for (j = 0; j < panels->n_panels; j++) {
				RPanel *p1 = r_panels_get_panel (panels, j);
				if (p1 && p1->view->pos.x + p1->view->pos.w - 1 == tmp) {
					p1->view->pos.w += x;
				}
			}
		}
	}
}

static void r_panels_update_edge_y(RCore *core, int y) {
	RPanels *panels = core->panels;
	int i, j;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p0 = r_panels_get_panel (panels, i);
		if (!p0) {
			continue;
		}
		RPanelPos *pos = &p0->view->pos;
		if (pos->y - 2 <= panels->mouse_orig_y && panels->mouse_orig_y <= pos->y + 2) {
			int tmp = pos->y;
			pos->y += y;
			pos->h -= y;
			for (j = 0; j < panels->n_panels; j++) {
				RPanel *p1 = r_panels_get_panel (panels, j);
				if (p1 && p1->view->pos.y + p1->view->pos.h - 1 == tmp) {
					p1->view->pos.h += y;
				}
			}
		}
	}
}

static bool r_panels_check_if_mouse_x_illegal(RCore *core, int x) {
	int w = core->panels->can->w;
	return x <= 1 || w - 1 <= x;
}

static bool r_panels_check_if_mouse_y_illegal(RCore *core, int y) {
	return y <= 0 || core->panels->can->h <= y;
}

static bool r_panels_check_if_mouse_x_on_edge(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	const int e = r_config_get_i (core->config, "scr.panelborder") ? 3 : 1;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p && x > p->view->pos.x - (e - 1) && x <= p->view->pos.x + e) {
			panels->mouse_on_edge_x = true;
			panels->mouse_orig_x = x;
			return true;
		}
	}
	return false;
}

static bool r_panels_check_if_mouse_y_on_edge(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	const int e = r_config_get_i (core->config, "scr.panelborder") ? 3 : 1;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		RPanelPos *pos = &p->view->pos;
		if (x > pos->x && x <= pos->x + pos->w + e) {
			if (y > 2 && y >= pos->y && y <= pos->y + e) {
				panels->mouse_on_edge_y = true;
				panels->mouse_orig_y = y;
				return true;
			}
		}
	}
	return false;
}

static RPanel *r_panels_get_cur_panel(RPanels *panels) {
	return r_panels_get_panel (panels, panels->curnode);
}

static bool r_panels_check_if_cur_panel(RCore *core, RPanel *panel) {
	if (core->panels->mode == PANEL_MODE_MENU) {
		return false;
	}
	return r_panels_get_cur_panel (core->panels) == panel;
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

static void r_panels_check_edge(RCore *core) {
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		RPanelPos *pos = &p->view->pos;
		if (pos->x + pos->w == can->w) {
			p->view->edge |= (1 << PANEL_EDGE_RIGHT);
		} else {
			p->view->edge &= ~(1 << PANEL_EDGE_RIGHT);
		}
		if (pos->y + pos->h == can->h) {
			p->view->edge |= (1 << PANEL_EDGE_BOTTOM);
		} else {
			p->view->edge &= ~(1 << PANEL_EDGE_BOTTOM);
		}
	}
}

static void r_panels_shrink_panels_forward(RCore *core, int target) {
	RPanels *panels = core->panels;
	int i = target;
	for (; i < panels->n_panels - 1; i++) {
		panels->panel[i] = panels->panel[i + 1];
	}
}

static void r_panels_shrink_panels_backward(RCore *core, int target) {
	RPanels *panels = core->panels;
	int i = target;
	for (; i > 0; i--) {
		panels->panel[i] = panels->panel[i - 1];
	}
}

static void r_panels_cache_white_list(RCore *core, RPanel *panel) {
	int i;
	for (i = 0; i < COUNT (cache_white_list_cmds); i++) {
		if (!strcmp (panel->model->cmd, cache_white_list_cmds[i])) {
			panel->model->cache = true;
			return;
		}
	}
	panel->model->cache = false;
}

static char *r_panels_search_db(RCore *core, const char *title) {
	Sdb *db = core->panels->db;
	return db ? sdb_get (db, title, 0) : NULL;
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

static char *r_panels_show_status_input(RCore *core, const char *msg) {
	char *n_msg = r_str_newf (R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, PANEL_HL_COLOR, msg);
	RCons *cons = core->cons;
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
	if (!strcmp (type, PANEL_CMD_DISASSEMBLY)) {
		res = !strncmp (tmp, type, len)
			&& strcmp (cmd, PANEL_CMD_DECOMPILER)
			&& strcmp (cmd, PANEL_CMD_DECOMPILER_O)
			&& strcmp (cmd, PANEL_CMD_DISASMSUMMARY);
	} else if (!strcmp (type, PANEL_CMD_STACK)) {
		res = !strcmp (tmp, PANEL_CMD_STACK);
	} else if (!strcmp (type, PANEL_CMD_HEXDUMP)) {
		int i;
		for (i = 0; i < COUNT (hexdump_rotate); i++) {
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
	if (r_panels_check_panel_type (panel, PANEL_CMD_SYMBOLS) || r_panels_check_panel_type (panel, PANEL_CMD_FUNCTION)) {
		return true;
	}
	static const char *types[] = {
		PANEL_TITLE_DISASMSUMMARY, PANEL_TITLE_STRINGS_DATA, PANEL_TITLE_STRINGS_BIN,
		PANEL_TITLE_BREAKPOINTS, PANEL_TITLE_SECTIONS, PANEL_TITLE_SEGMENTS,
		PANEL_TITLE_COMMENTS, NULL
	};
	int i;
	for (i = 0; types[i]; i++) {
		if (r_panels_search_db_check_panel_type (core, panel, types[i])) {
			return true;
		}
	}
	return false;
}

static bool r_panels_is_normal_cursor_type(RPanel *panel) {
	return (r_panels_check_panel_type (panel, PANEL_CMD_STACK) ||
			r_panels_check_panel_type (panel, PANEL_CMD_FPU_REGISTERS) ||
			r_panels_check_panel_type (panel, PANEL_CMD_REGISTERS) ||
			r_panels_check_panel_type (panel, PANEL_CMD_DISASSEMBLY) ||
			r_panels_check_panel_type (panel, PANEL_CMD_HEXDUMP));
}

static void r_panels_set_cmd_str_cache(RCore *core, RPanel *p, char *s) {
	if (!s) {
		return;
	}
	free (p->model->cmdStrCache);
	p->model->cmdStrCache = strdup (s);
	__set_dcb (core, p);
	__set_pcb (p);
}

#if 0
static void r_panels_set_decompiler_cache(RCore *core, char *s) {
	RAnalFunction *func = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	if (func) {
		if (core->panels_root->cur_pdc_cache) {
			sdb_ptr_set (core->panels_root->cur_pdc_cache, r_num_as_string (NULL, func->addr, false), strdup (s), 0);
		} else {
			Sdb *sdb = sdb_new0 ();
			const char *pdc_now = r_config_get (core->config, "cmd.pdc");
			sdb_ptr_set (sdb, r_num_as_string (NULL, func->addr, false), strdup (s), 0);
			core->panels_root->cur_pdc_cache = sdb;
			if (!sdb_exists (core->panels_root->pdc_caches, pdc_now)) {
				sdb_ptr_set (core->panels_root->pdc_caches, strdup (pdc_now), sdb, 0);
			}
		}
	}
}
#endif

static void r_panels_set_read_only(RCore *core, RPanel *p, const char * R_NULLABLE s) {
	free (p->model->readOnly);
	p->model->readOnly = s? strdup (s): NULL;
	__set_dcb (core, p);
	__set_pcb (p);
}

static void r_panels_set_pos(RPanelPos *pos, int x, int y) {
	pos->x = x;
	pos->y = y;
}

static void r_panels_set_size(RPanelPos *pos, int w, int h) {
	pos->w = w;
	pos->h = h;
}

static void r_panels_set_geometry(RPanelPos *pos, int x, int y, int w, int h) {
	r_panels_set_pos (pos, x, y);
	r_panels_set_size (pos, w, h);
}

static void r_panels_set_panel_addr(RCore *core, RPanel *panel, ut64 addr) {
	panel->model->addr = addr;
}

static int r_panels_get_panel_idx_in_pos(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	int i = -1;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p && (x >= p->view->pos.x && x < p->view->pos.x + p->view->pos.w)) {
			if (y >= p->view->pos.y && y < p->view->pos.y + p->view->pos.h) {
				break;
			}
		}
	}
	return i;
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
}

static void r_panels_menu_panel_print(RConsCanvas *can, RPanel *panel, int x, int y, int w, int h) {
	(void) r_cons_canvas_gotoxy (can, panel->view->pos.x + 2, panel->view->pos.y + 2);
	char *text = r_str_ansi_crop (panel->model->title, x, y, w, h);
	if (text) {
		r_cons_canvas_write (can, text);
		free (text);
	} else {
		r_cons_canvas_write (can, panel->model->title);
	}
}

static void r_panels_panel_write_content(RCore *core, RPanel *panel, const char *content, int sx, int graph_pad, bool r_panels_show_cursor) {
	int sy = R_MAX (panel->view->sy, 0);
	int x = panel->view->pos.x;
	int y = panel->view->pos.y;
	int w = panel->view->pos.w;
	int h = panel->view->pos.h;
	RConsCanvas *can = core->panels->can;
	if (x >= can->w || y >= can->h) {
		return;
	}
	(void) r_cons_canvas_gotoxy (can, x + 2, y + 2);
	char *text = NULL;
	if (sx < 0) {
		int idx = R_MIN (-sx, 128);
		char white[129];
		r_str_pad (white, sizeof (white), ' ', idx);
		text = r_str_ansi_crop (content, 0, sy + graph_pad, w + sx - 3, h - 2 + sy);
		char *newText = r_str_prefix_all (text, white);
		if (newText) {
			free (text);
			text = newText;
		}
	} else {
		text = r_str_ansi_crop (content, sx, sy + graph_pad, w + sx - 3, h - 2 + sy);
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
}

static void r_panels_update_help_contents(RCore *core, RPanel *panel) {
	r_panels_panel_write_content (core, panel, panel->model->readOnly, panel->view->sx, 0, false);
}

static void r_panels_update_help_title(RCore *core, RPanel *panel) {
	RConsCanvas *can = core->panels->can;
	RPanelPos *pos = &panel->view->pos;
	RStrBuf *title = r_strbuf_new (NULL);
	RStrBuf *cache_title = r_strbuf_new (NULL);
	if (r_panels_check_if_cur_panel (core, panel)) {
		r_strbuf_setf (title, "%s[X] %s"Color_RESET, PANEL_HL_COLOR, panel->model->title);
		if (pos->w > 16) {
			r_strbuf_setf (cache_title, "%s[&%s]"Color_RESET, PANEL_HL_COLOR, panel->model->cache ? " cache" : "");
		}
	} else {
		r_strbuf_setf (title, " o    %s   ", panel->model->title);
		if (pos->w > 24) {
			r_strbuf_setf (cache_title, "%s[&%s]"Color_RESET, PANEL_HL_COLOR, panel->model->cache ? " cache" : "");
		}
	}
	if (pos->w > 16 && r_cons_canvas_gotoxy (can, pos->x + pos->w - r_str_ansi_len (r_strbuf_get (cache_title)) - 2, pos->y + 1)) {
		r_cons_canvas_write (can, r_strbuf_get (cache_title));
	}
	if (r_cons_canvas_gotoxy (can, pos->x + 1, pos->y + 1)) {
		char *s = r_str_ansi_crop (r_strbuf_get (title), 0, 0, pos->w - 1, 1);
		r_cons_canvas_write (can, s);
		free (s);
	}
	r_strbuf_free (cache_title);
	r_strbuf_free (title);
}

static void r_panels_update_panel_contents(RCore *core, RPanel *panel, const char *cmdstr) {
	bool b = r_panels_is_abnormal_cursor_type (core, panel) && core->print->cur_enabled;
	int sx = b ? -2 : panel->view->sx;
	int graph_pad = r_panels_check_panel_type (panel, PANEL_CMD_GRAPH) ? 1 : 0;
	r_panels_panel_write_content (core, panel, cmdstr, sx, graph_pad, b);
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

static void r_panels_update_panel_title(RCore *core, RPanel *panel) {
	RConsCanvas *can = core->panels->can;
	RPanelPos *pos = &panel->view->pos;
	RStrBuf *title = r_strbuf_new (NULL);
	RStrBuf *cache_title = r_strbuf_new (NULL);
	char *cmd_title = r_panels_apply_filter_cmd (core, panel);
	if (cmd_title) {
		char *tit = r_str_ansi_crop (panel->model->title, 0, 0, pos->w - 6, 1);
		if (!tit) {
			tit = strdup ("");
		}
		if (r_panels_check_if_cur_panel (core, panel)) {
			r_strbuf_setf (title, Color_INVERT"%s[X] ", PANEL_HL_COLOR);
			r_strbuf_appendf (title, (pos->w > 4) ? "%s" : "%s (%s)",
				r_str_get (tit), cmd_title);
			if (pos->w > 24) {
				r_strbuf_setf (cache_title, "%s[&%s]"Color_RESET, PANEL_HL_COLOR, panel->model->cache ? " cache" : "");
			}
		} else {
			if (!strcmp (panel->model->title, tit)) {
				r_strbuf_setf (title, " =  %s   ", tit);
			} else {
				r_strbuf_setf (title, " =  %s (%s)  ", panel->model->title, tit);
			}
			if (pos->w > 24) {
				r_strbuf_setf (cache_title, "%s[&%s]"Color_RESET, PANEL_HL_COLOR, panel->model->cache ? " cache" : "");
			}
		}
		free (tit);
	} else {
		r_strbuf_setf (cache_title, "%s[X] %s"Color_RESET, PANEL_HL_COLOR, "");
	}
	r_strbuf_slice (title, 0, pos->w);
	r_strbuf_slice (cache_title, 0, pos->w);
	if (r_cons_canvas_gotoxy (can, pos->x + pos->w - r_str_ansi_len (r_strbuf_get (cache_title)) - 2, pos->y + 1)) {
		r_cons_canvas_write (can, r_strbuf_get (cache_title));
	}
	if (r_cons_canvas_gotoxy (can, pos->x + 1, pos->y + 1)) {
		r_cons_canvas_write (can, r_strbuf_get (title));
	}
	r_strbuf_free (title);
	r_strbuf_free (cache_title);
	free (cmd_title);
}

static void r_panels_update_pdc_contents(RCore *core, RPanel *panel, char *cmdstr) {
	r_panels_panel_write_content (core, panel, cmdstr, panel->view->sx, 0, false);
}

static char *r_panels_handle_cmd_str_cache(RCore *core, RPanel *panel, bool force_cache) {
	// XXX force cache is always used as false!!
	if (panel->model->cache && panel->model->cmdStrCache) {
		return strdup (panel->model->cmdStrCache);
	}
	char *cmd = r_panels_apply_filter_cmd (core, panel);
	bool b = core->print->cur_enabled && r_panels_get_cur_panel (core->panels) != panel;
	char *out = NULL;
	if (cmd) {
		if (b) {
			core->print->cur_enabled = false;
		}
		bool o_interactive = r_cons_is_interactive (core->cons);
		r_cons_set_interactive (core->cons, false);
		out = (*cmd == '.')
			? r_core_cmd_str_pipe (core, cmd)
			: r_core_cmd_str (core, cmd);
		r_cons_set_interactive (core->cons, o_interactive);
		if (force_cache) {
			panel->model->cache = true;
		}
		if (R_STR_ISNOTEMPTY (out)) {
			r_panels_set_cmd_str_cache (core, panel, out);
		} else {
			R_FREE (out);
		}
		free (cmd);
	}
	if (b) {
		core->print->cur_enabled = true;
	}
	return out;
}

static char *r_panels_find_cmd_str_cache(RCore *core, RPanel* panel) {
	const char *cs = R_UNWRAP3 (panel, model, cmdStrCache);
	if (panel->model->cache && cs) {
		return strdup (cs);
	}
	return r_panels_handle_cmd_str_cache (core, panel, false);
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
	r_panels_print_notch (core);
	r_cons_canvas_print (panels->can);
	r_cons_flush (core->cons);
}

static void r_panels_layout_default(RCore *core, RPanels *panels) {
	RPanel *p0 = r_panels_get_panel (panels, 0);
	if (!p0) {
		R_LOG_ERROR ("_get_panel (...,0) return null");
		return;
	}
	int h, w = r_cons_get_size (core->cons, &h);
	if (panels->n_panels <= 1) {
		r_panels_set_geometry (&p0->view->pos, 0, 1, w, h - 1);
		return;
	}

	int ph = (h - 1) / (panels->n_panels - 1);
	int colpos = w - panels->columnWidth;
	r_panels_set_geometry (&p0->view->pos, 0, 1, colpos + 1, h - 1);

	int pos_x = p0->view->pos.x + p0->view->pos.w - 1;
	int i, total_h = 0;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		int tmp_w = R_MAX (w - colpos, 0);
		int tmp_h = 0;
		if (i + 1 == panels->n_panels) {
			tmp_h = h - total_h;
		} else {
			tmp_h = ph;
		}
		r_panels_set_geometry (&p->view->pos, pos_x, 2 + (ph * (i - 1)) - 1, tmp_w, tmp_h + 1);
		total_h += 2 + (ph * (i - 1)) - 1 + tmp_h + 1;
	}
}

static void r_panels_panels_layout(RCore *core, RPanels *panels) {
	panels->can->sx = 0;
	panels->can->sy = 0;
	r_panels_layout_default (core, panels);
}

static void r_panels_layout_equal_hor(RCore *core, RPanels *panels) {
	int h, w = r_cons_get_size (core->cons, &h);
	int pw = w / panels->n_panels;
	int i, cw = 0;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		r_panels_set_geometry (&p->view->pos, cw, 1, pw, h - 1);
		cw += pw - 1;
		if (i == panels->n_panels - 2) {
			pw = w - cw;
		}
	}
}

/* makes space for a side panel, returns the amount of space made*/
static unsigned int r_panels_adjust_side_panels(RCore *core) {
	RPanels *panels = core->panels;
	int i, h;
	unsigned int smallest = INT32_MAX;
	(void)r_cons_get_size (core->cons, &h);
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p && p->view->pos.x == 0 && smallest > p->view->pos.w) {
			smallest = p->view->pos.w;
		}
	}
	unsigned int space = (smallest > PANEL_CONFIG_SIDEPANEL_W + PANEL_CONFIG_MIN_SIZE)
		? PANEL_CONFIG_SIDEPANEL_W : smallest / 2;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p && p->view->pos.x == 0) {
			p->view->pos.x += space;
			p->view->pos.w -= space;
		}
	}
	return space;
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
			RStrBuf *rsb = r_strbuf_new (NULL);
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
			// panel's title does not change, keep it short and simple
			free (p->model->title);
			p->model->title = strdup (help);
			free (p->model->cmd);
			p->model->cmd = strdup (help);
			r_core_visual_append_help (core, rsb, title, msg);
			if (!rsb) {
				break;
			}
			char *drained = r_strbuf_drain (rsb);
			if (drained) {
				r_panels_set_read_only (core, p, drained);
				free (drained);
			}
			p->view->refresh = true;
		}
	}
}

static void r_panels_set_cursor(RCore *core, bool cur) {
	RPanel *p = r_panels_get_cur_panel (core->panels);
	RPrint *print = core->print;
	print->cur_enabled = cur;
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

static void r_panels_set_rcb(RPanels *ps, RPanel *p) {
	SdbKv *kv;
	SdbListIter *sdb_iter;
	SdbList *sdb_list = sdb_foreach_list (ps->rotate_db, false);
	ls_foreach (sdb_list, sdb_iter, kv) {
		char *key =  sdbkv_key (kv);
		if (!r_panels_check_panel_type (p, key)) {
			continue;
		}
		p->model->rotateCb = (RPanelRotateCallback)sdb_ptr_get (ps->rotate_db, key, 0);
		break;
	}
	ls_free (sdb_list);
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
	__set_pcb (p);
	if (R_STR_ISNOTEMPTY (m->cmd)) {
		__set_dcb (core, p);
		r_panels_set_rcb (core->panels, p);
		if (r_panels_check_panel_type (p, PANEL_CMD_STACK)) {
			const ut64 stackbase = r_reg_getv (core->anal->reg, "SP");
			m->baseAddr = stackbase;
			r_panels_set_panel_addr (core, p, stackbase - r_config_get_i (core->config, "stack.delta"));
		}
	}
	core->panels->n_panels++;
	r_panels_cache_white_list (core, p);
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
	r_panels_set_geometry (&p0->view->pos, 0, 1, available_space + 1, h - 1);
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
	char *ret = NULL;
	char *res = r_panels_show_status_input (core, input);
	if (res) {
		p->model->cmd = r_str_newf (str, res);
		ret = r_core_cmd_str (core, p->model->cmd);
		free (res);
	}
	return ret;
}

static void r_panels_fix_layout_axis(RCore *core, bool horizontal) {
	RPanels *panels = core->panels;
	size_t op = horizontal ? offsetof (RPanelPos, x) : offsetof (RPanelPos, y);
	size_t os = horizontal ? offsetof (RPanelPos, w) : offsetof (RPanelPos, h);
	int edges[PANEL_NUM_LIMIT];
	int n_edges = 0;
	int skip_pos = 0, skip_sz = 0;
	if (!horizontal) {
		int h;
		(void)r_cons_get_size (core->cons, &h);
		skip_pos = 1;
		skip_sz = h - 1;
	}
	int i;
	for (i = 0; i < panels->n_panels - 1 && n_edges < PANEL_NUM_LIMIT; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p) {
			edges[n_edges++] = PP (p->view->pos, op) + PP (p->view->pos, os);
		}
	}
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		int tpos = PP (p->view->pos, op);
		int tsz = PP (p->view->pos, os);
		if (horizontal ? (tpos == 0) : (tpos == skip_pos || tsz == skip_sz)) {
			continue;
		}
		int min = INT32_MAX;
		int target_num = INT32_MAX;
		bool found = false;
		int j;
		for (j = 0; j < n_edges; j++) {
			if (edges[j] - 1 == tpos) {
				found = true;
				break;
			}
			int sub = edges[j] - tpos;
			if (min > R_ABS (sub)) {
				min = R_ABS (sub);
				target_num = edges[j];
			}
		}
		if (!found) {
			int t = PP (p->view->pos, op) - target_num + 1;
			PP (p->view->pos, op) = target_num - 1;
			PP (p->view->pos, os) += t;
		}
	}
}

static void r_panels_fix_layout(RCore *core) {
	r_panels_fix_layout_axis (core, true);
	r_panels_fix_layout_axis (core, false);
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
		if (!force_refresh && r_panels_check_panel_type (panel, PANEL_CMD_CONSOLE)) {
			continue;
		}
		panel->view->refresh = true;
		if (clearCache) {
			r_panels_set_cmd_str_cache (core, panel, NULL);
		}
	}
}

static void r_panels_split_panel(RCore *core, RPanel *p, const char *name, const char *cmd, bool vertical) {
	RPanels *panels = core->panels;
	if (!r_panels_check_panel_num (core)) {
		return;
	}
	r_panels_insert_panel (core, panels->curnode + 1, name, cmd);
	RPanel *next = r_panels_get_panel (panels, panels->curnode + 1);
	RPanelPos *pos = &p->view->pos;
	if (vertical) {
		int ow = pos->w;
		pos->w = ow / 2 + 1;
		r_panels_set_geometry (&next->view->pos, pos->x + pos->w - 1, pos->y, ow - pos->w + 1, pos->h);
	} else {
		int oh = pos->h;
		p->view->curpos = 0;
		pos->h = oh / 2 + 1;
		r_panels_set_geometry (&next->view->pos, pos->x, pos->y + pos->h - 1, pos->w, oh - pos->h + 1);
	}
	r_panels_fix_layout (core);
	r_panels_set_refresh_all (core, false, true);
}

static void r_panels_panels_check_stackbase(RCore *core) {
	RPanels *panels = core->panels;
	const ut64 stackbase = r_reg_getv (core->anal->reg, "SP");
	int i;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p && p->model->cmd && r_panels_check_panel_type (p, PANEL_CMD_STACK) && p->model->baseAddr != stackbase) {
			p->model->baseAddr = stackbase;
			r_panels_set_panel_addr (core, p, stackbase - r_config_get_i (core->config, "stack.delta") + core->print->cur);
		}
	}
}

static void r_panels_del_panel(RCore *core, int pi) {
	int i;
	RPanels *panels = core->panels;
	RPanel *tmp = r_panels_get_panel (panels, pi);
	if (!tmp) {
		return;
	}
	for (i = pi; i < (panels->n_panels - 1); i++) {
		panels->panel[i] = panels->panel[i + 1];
	}
	panels->panel[panels->n_panels - 1] = tmp;
	panels->n_panels--;
	r_panels_set_curnode (core, panels->curnode);
}

static void r_panels_del_invalid_panels(RCore *core) {
	RPanels *panels = core->panels;
	bool found;
	do {
		found = false;
		int i;
		for (i = 1; i < panels->n_panels; i++) {
			RPanel *panel = r_panels_get_panel (panels, i);
			if (panel && (panel->view->pos.w < PANEL_CONFIG_MIN_SIZE
					|| panel->view->pos.h < PANEL_CONFIG_MIN_SIZE)) {
				r_panels_del_panel (core, i);
				found = true;
				break;
			}
		}
	} while (found);
}

static void r_panels_panels_layout_refresh(RCore *core) {
	r_panels_del_invalid_panels (core);
	r_panels_check_edge (core);
	r_panels_panels_check_stackbase (core);
	r_panels_panels_refresh (core);
}

static void r_panels_reset_scroll_pos(RPanel *p) {
	p->view->sx = 0;
	p->view->sy = 0;
}

static void r_panels_activate_cursor(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	bool normal = r_panels_is_normal_cursor_type (cur);
	bool abnormal = r_panels_is_abnormal_cursor_type (core, cur);
	if (normal || abnormal) {
		if (normal && cur->model->cache) {
			if (r_panels_show_status_yesno (core, 1, "You need to turn off cache to use cursor. Turn off now? (Y/n)")) {
				cur->model->cache = false;
				r_panels_set_cmd_str_cache (core, cur, NULL);
				(void)r_panels_show_status (core, "Cache is off and cursor is on");
				r_panels_set_cursor (core, !core->print->cur_enabled);
				cur->view->refresh = true;
				r_panels_reset_scroll_pos (cur);
			} else {
				(void)r_panels_show_status (core, "You can always toggle cache by \'&\' key");
			}
			return;
		}
		r_panels_set_cursor (core, !core->print->cur_enabled);
		cur->view->refresh = true;
	} else {
		(void)r_panels_show_status (core, "Cursor is not available for the current panel.");
	}
}

ut64 r_panels_parse_string_on_cursor(RCore *core, RPanel *panel, int idx) {
	if (!panel->model->cmdStrCache) {
		return UT64_MAX;
	}
	RStrBuf *buf = r_strbuf_new (NULL);
	char *s = panel->model->cmdStrCache;
	int l = 0;
	while (R_STR_ISNOTEMPTY (s) && l != idx) {
		if (*s == '\n') {
			l++;
		}
		s++;
	}
	while (R_STR_ISNOTEMPTY (s) && R_STR_ISNOTEMPTY (s + 1)) {
		if (*s == '0' && *(s + 1) == 'x') {
			r_strbuf_append_n (buf, s, 2);
			while (*s != ' ') {
				r_strbuf_append_n (buf, s, 1);
				s++;
			}
			ut64 ret = r_num_math (core->num, r_strbuf_get (buf));
			r_strbuf_free (buf);
			return ret;
		}
		s++;
	}
	r_strbuf_free (buf);
	return UT64_MAX;
}

static void r_panels_fix_cursor_up(RCore *core) {
	RPrint *print = core->print;
	if (print->cur >= 0) {
		return;
	}
	int sz = r_core_visual_prevopsz (core, core->addr + print->cur);
	if (sz < 1) {
		sz = 1;
	}
	r_core_seek_delta (core, -sz);
	print->cur += sz;
	if (print->ocur != -1) {
		print->ocur += sz;
	}
}

static void r_panels_cursor_left(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	RPrint *print = core->print;
	if (r_panels_check_panel_type (cur, PANEL_CMD_REGISTERS)
			|| r_panels_check_panel_type (cur, PANEL_CMD_STACK)) {
		if (print->cur > 0) {
			print->cur--;
			cur->model->addr--;
		}
	} else if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		print->cur--;
		r_panels_fix_cursor_up (core);
	} else {
		print->cur--;
	}
}

static void r_panels_fix_cursor_down(RCore *core) {
	RPrint *print = core->print;
	bool cur_is_visible = core->addr + print->cur + 32 < print->screen_bounds;
	if (!cur_is_visible) {
		int i;
		// XXX: ugly hack
		for (i = 0; i < 2; i++) {
			RAnalOp op;
			int sz = r_asm_disassemble (core->rasm, &op, core->block, 32);
			if (sz < 1) {
				sz = 1;
			}
			r_anal_op_fini (&op);
			r_core_seek_delta (core, sz);
			print->cur = R_MAX (print->cur - sz, 0);
			if (print->ocur != -1) {
				print->ocur = R_MAX (print->ocur - sz, 0);
			}
		}
	}
}

static void r_panels_cursor_right(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	RPrint *print = core->print;
	if (r_panels_check_panel_type (cur, PANEL_CMD_STACK) && print->cur >= 15) {
		return;
	}
	if (r_panels_check_panel_type (cur, PANEL_CMD_REGISTERS)
			|| r_panels_check_panel_type (cur, PANEL_CMD_STACK)) {
		print->cur++;
		cur->model->addr++;
	} else if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		print->cur++;
		r_panels_fix_cursor_down (core);
	} else {
		print->cur++;
	}
}

// copypasta from visual
static ut64 r_panels_insoff(RCore *core, int delta) {
	int minop = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	int maxop = r_anal_archinfo (core->anal, R_ARCH_INFO_MAXOP_SIZE);
	ut64 addr = core->addr + delta; // should be core->print->cur
	RAnalBlock *bb = r_anal_bb_from_offset (core->anal, addr - minop);
	if (bb) {
		ut64 res = r_anal_bb_opaddr_at (bb, addr - minop);
		if (res != UT64_MAX) {
			if (res < addr && addr - res <= maxop) {
				return res;
			}
		}
	}
	return addr;
}

static void r_panels_cursor_up(RCore *core) {
	RPrint *print = core->print;
	ut64 addr = 0;
	ut64 opaddr = r_panels_insoff (core, core->print->cur);
	if (r_core_prevop_addr (core, opaddr, 1, &addr)) {
		const int delta = opaddr - addr;
		print->cur -= delta;
	} else {
		print->cur -= 4;
	}
	r_panels_fix_cursor_up (core);
}

static void r_panels_cursor_down(RCore *core) {
	RPrint *print = core->print;
	RAnalOp *aop = r_core_anal_op (core, core->addr + print->cur, R_ARCH_OP_MASK_BASIC);
	if (aop) {
		print->cur += aop->size;
		r_anal_op_free (aop);
	} else {
		print->cur += 4;
	}
	// r_panels_fix_cursor_down (core);
}

static void r_panels_save_panel_pos(RPanel* panel) {
	if (!panel) {
		return;
	}
	r_panels_set_geometry (&panel->view->prevPos, panel->view->pos.x, panel->view->pos.y,
			panel->view->pos.w, panel->view->pos.h);
}

static void r_panels_restore_panel_pos(RPanel* panel) {
	if (!panel) {
		return;
	}
	r_panels_set_geometry (&panel->view->pos, panel->view->prevPos.x, panel->view->prevPos.y,
			panel->view->prevPos.w, panel->view->prevPos.h);
}

static void r_panels_maximize_panel_size(RPanels *panels) {
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (!cur) {
		return;
	}
	r_panels_set_geometry (&cur->view->pos, 0, 1, panels->can->w, panels->can->h - 1);
	cur->view->refresh = true;
}

static void r_panels_dismantle_panel(RPanels *ps, RPanel *p) {
	if (!p) {
		return;
	}
	RPanel *jL = NULL, *jR = NULL, *jU = NULL, *jD = NULL;
	bool lu = false, ld = false, ru = false, rd = false, ul = false, ur = false, dl = false, dr = false;
	int L[PANEL_NUM_LIMIT], R[PANEL_NUM_LIMIT], U[PANEL_NUM_LIMIT], D[PANEL_NUM_LIMIT];
	memset (L, -1, sizeof (L));
	memset (R, -1, sizeof (R));
	memset (U, -1, sizeof (U));
	memset (D, -1, sizeof (D));
	int i;
	int ox = p->view->pos.x, oy = p->view->pos.y;
	int ow = p->view->pos.w, oh = p->view->pos.h;
	for (i = 0; i < ps->n_panels; i++) {
		RPanel *t = r_panels_get_panel (ps, i);
		if (!t) {
			continue;
		}
		RPanelPos *tp = &t->view->pos;
		if (tp->x + tp->w - 1 == ox) {
			L[i] = 1;
			if (oy == tp->y) {
				lu = true;
				if (oh == tp->h) { jL = t; break; }
			}
			if (oy + oh == tp->y + tp->h) { ld = true; }
		}
		if (tp->x == ox + ow - 1) {
			R[i] = 1;
			if (oy == tp->y) {
				ru = true;
				if (oh == tp->h) { rd = true; jR = t; }
			}
			if (oy + oh == tp->y + tp->h) { rd = true; }
		}
		if (tp->y + tp->h - 1 == oy) {
			U[i] = 1;
			if (ox == tp->x) {
				ul = true;
				if (ow == tp->w) { ur = true; jU = t; }
			}
			if (ox + ow == tp->x + tp->w) { ur = true; }
		}
		if (tp->y == oy + oh - 1) {
			D[i] = 1;
			if (ox == tp->x) {
				dl = true;
				if (ow == tp->w) { dr = true; jD = t; }
			}
			if (ox + ow == tp->x + tp->w) { dr = true; }
		}
	}
	if (jL) {
		RPanelPos *jp = &jL->view->pos;
		jp->w += ox + ow - (jp->x + jp->w);
	} else if (jR) {
		RPanelPos *jp = &jR->view->pos;
		jp->w = jp->x + jp->w - ox;
		jp->x = ox;
	} else if (jU) {
		RPanelPos *jp = &jU->view->pos;
		jp->h += oy + oh - (jp->y + jp->h);
	} else if (jD) {
		RPanelPos *jp = &jD->view->pos;
		jp->h = oh + jp->y + jp->h - (oy + oh);
		jp->y = oy;
	} else if (lu && ld) {
		for (i = 0; i < ps->n_panels; i++) {
			if (L[i] != -1) {
				RPanelPos *tp = &r_panels_get_panel (ps, i)->view->pos;
				tp->w += ox + ow - (tp->x + tp->w);
			}
		}
	} else if (ru && rd) {
		for (i = 0; i < ps->n_panels; i++) {
			if (R[i] != -1) {
				RPanelPos *tp = &r_panels_get_panel (ps, i)->view->pos;
				tp->w = tp->x + tp->w - ox;
				tp->x = ox;
			}
		}
	} else if (ul && ur) {
		for (i = 0; i < ps->n_panels; i++) {
			if (U[i] != -1) {
				RPanelPos *tp = &r_panels_get_panel (ps, i)->view->pos;
				tp->h += oy + oh - (tp->y + tp->h);
			}
		}
	} else if (dl && dr) {
		for (i = 0; i < ps->n_panels; i++) {
			if (D[i] != -1) {
				RPanelPos *tp = &r_panels_get_panel (ps, i)->view->pos;
				tp->h = oh + tp->y + tp->h - (oy + oh);
				tp->y = oy;
			}
		}
	}
}

static void r_panels_dismantle_del_panel(RCore *core, RPanel *p, int pi) {
	RPanels *panels = core->panels;
	if (panels->n_panels <= 1) {
		return;
	}
	r_panels_dismantle_panel (panels, p);
	r_panels_del_panel (core, pi);
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

static void r_panels_handle_tab_next(RCore *core) {
	if (core->panels_root->n_panels > 1) {
		core->panels_root->cur_panels++;
		core->panels_root->cur_panels %= core->panels_root->n_panels;
		r_panels_set_root_state (core, ROTATE);
	}
}

static void r_panels_handle_tab_prev(RCore *core) {
	if (core->panels_root->n_panels > 1) {
		core->panels_root->cur_panels--;
		if (core->panels_root->cur_panels < 0) {
			core->panels_root->cur_panels = core->panels_root->n_panels - 1;
		}
		r_panels_set_root_state (core, ROTATE);
	}
}

static void r_panels_handle_tab_name(RCore *core) {
	free (core->panels->name);
	core->panels->name = r_panels_show_status_input (core, "tab name: ");
}

static void r_panels_handle_tab_new(RCore *core) {
	if (core->panels_root->n_panels >= PANEL_NUM_LIMIT) {
		return;
	}
	__init_new_panels_root (core);
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
	//r_panels_reset_scroll_pos (panel);
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

static void r_panels_free_menu_item(RPanelsMenuItem *item) {
	if (!item) {
		return;
	}
	size_t i;
	free (item->name);
	free (item->p->model);
	free (item->p->view);
	free (item->p);
	for (i = 0; i < item->n_sub; i++) {
		r_panels_free_menu_item (item->sub[i]);
	}
	free (item->sub);
	free (item);
}

static void r_panels_mht_free_kv(HtPPKv *kv) {
	free (kv->key);
	r_panels_free_menu_item ((RPanelsMenuItem *)kv->value);
}

static bool r_panels_init(RCore *core, RPanels *panels, int w, int h) {
	panels->panel = NULL;
	panels->n_panels = 0;
	panels->columnWidth = 80;
	if (r_config_get_b (core->config, "cfg.debug")) {
		panels->layout = PANEL_LAYOUT_DEFAULT_DYNAMIC;
	} else {
		panels->layout = PANEL_LAYOUT_DEFAULT_STATIC;
	}
	panels->autoUpdate = false;
	panels->mouse_on_edge_x = false;
	panels->mouse_on_edge_y = false;
	panels->mouse_orig_x = 0;
	panels->mouse_orig_y = 0;
	panels->can = r_panels_create_new_canvas (core, w, h);
	panels->db = sdb_new0 ();
	panels->rotate_db = sdb_new0 ();
	panels->modal_db = sdb_new0 ();
	panels->mht = ht_pp_new (NULL, (HtPPKvFreeFunc)r_panels_mht_free_kv, (HtPPCalcSizeV)strlen);
	panels->fun = PANEL_FUN_NOFUN;
	panels->prevMode = PANEL_MODE_DEFAULT;
	panels->name = NULL;

	if (w > 0 && w < 140) {
		panels->columnWidth = w / 3;
	}
	return true;
}

static RPanels *r_panels_panels_new(RCore *core) {
	RPanels *panels = R_NEW0 (RPanels);
	int h, w = r_cons_get_size (core->cons, &h);
	core->visual.firstRun = true;
	if (w < 1) {
		w = 1;
	}
	if (h < 1) {
		h = 1;
	}
	if (!r_panels_init (core, panels, w, h)) {
		free (panels);
		return NULL;
	}
	return panels;
}

static bool r_panels_init_panels(RCore *core, RPanels *panels) {
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
		if (!panels->panel[i]->model || !panels->panel[i]->view) {
			return false;
		}
	}
	return true;
}

static void r_panels_handle_tab_key(RCore *core, bool shift) {
	r_panels_set_cursor (core, false);
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	r_cons_switchbuf (core->cons, false);
	cur->view->refresh = true;
	if (!shift) {
		if (panels->mode == PANEL_MODE_MENU) {
			r_panels_set_curnode (core, 0);
			r_panels_set_mode (core, PANEL_MODE_DEFAULT);
		} else {
			r_panels_set_curnode (core, ++panels->curnode);
		}
	} else {
		if (panels->mode == PANEL_MODE_MENU) {
			r_panels_set_curnode (core, panels->n_panels - 1);
			r_panels_set_mode (core, PANEL_MODE_DEFAULT);
		} else {
			r_panels_set_curnode (core, --panels->curnode);
		}
	}
	cur = r_panels_get_cur_panel (panels);
	cur->view->refresh = true;
	if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
		r_panels_reset_snow (panels);
	}
}

static bool r_panels_handle_zoom_mode(RCore *core, const int key) {
	RPanels *panels = core->panels;
	r_cons_switchbuf (core->cons, false);
	switch (key) {
	case 'Q':
	case 'q':
	case 0x0d:
		r_panels_toggle_zoom_mode (core);
		break;
	case 'c':
	case 'C':
	case ';':
	case ' ':
	case '_':
	case '/':
	case '"':
	case 'A':
	case 'r':
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	case 'u':
	case 'U':
	case 'b':
	case 'd':
	case 'n':
	case 'N':
	case 'g':
	case 'h':
	case 'j':
	case 'k':
	case 'J':
	case 'K':
	case 'l':
	case '.':
	case 'R':
	case 'p':
	case 'P':
	case 's':
	case 'S':
	case 't':
	case 'T':
	case 'x':
	case 'X':
	case ':':
	case '[':
	case ']':
		return false;
	case 9:
		r_panels_restore_panel_pos (panels->panel[panels->curnode]);
		r_panels_handle_tab_key (core, false);
		r_panels_save_panel_pos (panels->panel[panels->curnode]);
		r_panels_maximize_panel_size (panels);
		break;
	case 'Z':
		r_panels_restore_panel_pos (panels->panel[panels->curnode]);
		r_panels_handle_tab_key (core, true);
		r_panels_save_panel_pos (panels->panel[panels->curnode]);
		r_panels_maximize_panel_size (panels);
		break;
	case '?':
		r_panels_toggle_zoom_mode (core);
		r_panels_toggle_help (core);
		r_panels_toggle_zoom_mode (core);
		break;
	}
	return true;
}

static void r_panels_set_refresh_by_type(RCore *core, const char *cmd, bool clearCache) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!r_panels_check_panel_type (p, cmd)) {
			continue;
		}
		p->view->refresh = true;
		if (clearCache) {
			r_panels_set_cmd_str_cache (core, p, NULL);
		}
	}
}

static char *r_panels_filter_arg(char *a) {
	r_str_filter (a, -1);
	char *r = r_str_escape (a);
	free (a);
	return r;
}

static bool r_panels_move_to_direction(RCore *core, Direction direction) {
	RPanels *panels = core->panels;
	RPanelPos *cp = &r_panels_get_cur_panel (panels)->view->pos;
	int cx0 = cp->x, cx1 = cp->x + cp->w - 1, cy0 = cp->y, cy1 = cp->y + cp->h - 1;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		RPanelPos *tp = &p->view->pos;
		int temp_x0 = tp->x, temp_x1 = tp->x + tp->w - 1;
		int temp_y0 = tp->y, temp_y1 = tp->y + tp->h - 1;
		switch (direction) {
		case 'h':
			if (temp_x1 == cx0 && !(temp_y1 <= cy0 || cy1 <= temp_y0)) {
				r_panels_set_curnode (core, i);
				return true;
			}
			break;
		case 'l':
			if (temp_x0 == cx1 && !(temp_y1 <= cy0 || cy1 <= temp_y0)) {
				r_panels_set_curnode (core, i);
				return true;
			}
			break;
		case 'k':
			if (temp_y1 == cy0 && !(temp_x1 <= cx0 || cx1 <= temp_x0)) {
				r_panels_set_curnode (core, i);
				return true;
			}
			break;
		case 'j':
			if (temp_y0 == cy1 && !(temp_x1 <= cx0 || cx1 <= temp_x0)) {
				r_panels_set_curnode (core, i);
				return true;
			}
			break;
		default:
			break;
		}
	}
	return false;
}

static void r_panels_toggle_window_mode(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->mode != PANEL_MODE_WINDOW) {
		panels->prevMode = panels->mode;
		r_panels_set_mode (core, PANEL_MODE_WINDOW);
	} else {
		r_panels_set_mode (core, panels->prevMode);
		panels->prevMode = PANEL_MODE_DEFAULT;
	}
}

static void r_panels_resize_panel(RPanels *panels, Direction dir) {
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (!cur) {
		return;
	}
	bool horiz = (dir == 'h' || dir == 'l');
	bool neg = (dir == 'h' || dir == 'k');
	int d = horiz ? PANEL_CONFIG_RESIZE_W : PANEL_CONFIG_RESIZE_H;
	int pmax = horiz ? panels->can->w : panels->can->h;
	// offsets into RPanelPos for primary axis (pos/size) and secondary axis
	size_t op = horiz ? offsetof (RPanelPos, x) : offsetof (RPanelPos, y);
	size_t os = horiz ? offsetof (RPanelPos, w) : offsetof (RPanelPos, h);
	size_t sp = horiz ? offsetof (RPanelPos, y) : offsetof (RPanelPos, x);
	size_t ss = horiz ? offsetof (RPanelPos, h) : offsetof (RPanelPos, w);
	// current panel bounds: primary axis [cp0,cp1], secondary [cs0,cs1]
	int cp0 = PP (cur->view->pos, op);
	int cp1 = cp0 + PP (cur->view->pos, os) - 1;
	int cs0 = PP (cur->view->pos, sp);
	int cs1 = cs0 + PP (cur->view->pos, ss) - 1;
	int n = panels->n_panels;
	size_t sz = sizeof (RPanel *) * n;
	RPanel **t1 = malloc (sz), **t2 = malloc (sz), **t3 = malloc (sz), **t4 = malloc (sz);
	if (!t1 || !t2 || !t3 || !t4) {
		goto beach;
	}
	int n1 = 0, n2 = 0, n3 = 0, n4 = 0, i;
	for (i = 0; i < n; i++) {
		if (i == panels->curnode) {
			continue;
		}
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		int tp0 = PP (p->view->pos, op);
		int tp1 = tp0 + PP (p->view->pos, os) - 1;
		int ts0 = PP (p->view->pos, sp);
		int ts1 = ts0 + PP (p->view->pos, ss) - 1;
		// fast path: exact neighbor on secondary axis, adjacent on primary
		if (ts0 == cs0 && ts1 == cs1) {
			if (neg && tp1 == cp0 && tp1 - d > tp0) {
				PP (p->view->pos, os) -= d;
				PP (cur->view->pos, op) -= d;
				PP (cur->view->pos, os) += d;
				p->view->refresh = true;
				cur->view->refresh = true;
				goto beach;
			}
			if (!neg && tp0 == cp1 && tp0 + d < tp1) {
				PP (p->view->pos, op) += d;
				PP (p->view->pos, os) -= d;
				PP (cur->view->pos, os) += d;
				p->view->refresh = true;
				cur->view->refresh = true;
				goto beach;
			}
		}
		bool sec_incl = (ts1 >= cs0 && cs1 >= ts1) || (ts0 >= cs0 && cs1 >= ts0);
		// t1: neighbors on leading edge
		if (tp1 == cp0 && sec_incl) {
			if (neg ? (tp1 - d > tp0) : (tp1 + d < cp1)) {
				t1[n1++] = p;
			}
		}
		// t3: neighbors on trailing edge
		if (tp0 == cp1 && sec_incl) {
			if (neg ? (tp0 - d > cp0) : (tp0 + d < tp1)) {
				t3[n3++] = p;
			}
		}
		// t2: same leading edge as cur
		if (tp0 == cp0) {
			if (neg ? (tp0 - d > 0) : (tp0 + d < tp1)) {
				t2[n2++] = p;
			}
		}
		// t4: same trailing edge as cur
		if (tp1 == cp1) {
			if (neg ? (tp1 + d < pmax) : (tp1 + d < pmax)) {
				t4[n4++] = p;
			}
		}
	}
	// for neg (h/k): try t1 first, fallback t3
	// for pos (l/j): try t3 first, fallback t1
	RPanel **ta, **tb, **tc, **td;
	int na, nb, nc, nd;
	if (neg) {
		ta = t1; na = n1; tb = t2; nb = n2;
		tc = t3; nc = n3; td = t4; nd = n4;
	} else {
		ta = t3; na = n3; tb = t4; nb = n4;
		tc = t1; nc = n1; td = t2; nd = n2;
	}
	if (na > 0) {
		for (i = 0; i < na; i++) {
			PP (ta[i]->view->pos, os) -= d;
			if (!neg) {
				PP (ta[i]->view->pos, op) += d;
			}
			ta[i]->view->refresh = true;
		}
		for (i = 0; i < nb; i++) {
			if (neg) {
				PP (tb[i]->view->pos, op) -= d;
			}
			PP (tb[i]->view->pos, os) += d;
			tb[i]->view->refresh = true;
		}
		PP (cur->view->pos, os) += d;
		if (neg) {
			PP (cur->view->pos, op) -= d;
		}
		cur->view->refresh = true;
	} else if (nc > 0) {
		for (i = 0; i < nc; i++) {
			PP (tc[i]->view->pos, os) += d;
			if (neg) {
				PP (tc[i]->view->pos, op) -= d;
			}
			tc[i]->view->refresh = true;
		}
		for (i = 0; i < nd; i++) {
			PP (td[i]->view->pos, os) -= d;
			if (!neg) {
				PP (td[i]->view->pos, op) += d;
			}
			td[i]->view->refresh = true;
		}
		PP (cur->view->pos, os) -= d;
		if (!neg) {
			PP (cur->view->pos, op) += d;
		}
		cur->view->refresh = true;
	}
beach:
	free (t1);
	free (t2);
	free (t3);
	free (t4);
}

static bool r_panels_handle_window_mode(RCore *core, const int key) {
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	r_cons_switchbuf (core->cons, false);
	switch (key) {
	case 'Q':
	case 'q':
	case 'w':
		r_panels_toggle_window_mode (core);
		break;
	case 0x0d:
		r_panels_toggle_zoom_mode (core);
		break;
	case 9: // tab
		r_panels_handle_tab_key (core, false);
		break;
	case 'Z': // shift-tab
		r_panels_handle_tab_key (core, true);
		break;
	case 'E':
		r_core_visual_colors (core);
		break;
	case 'e':
	{
		char *cmd = r_panels_show_status_input (core, "New command: ");
		if (R_STR_ISNOTEMPTY (cmd)) {
			__replace_cmd (core, cmd, cmd);
		}
		free (cmd);
	}
		break;
	case 'h':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.x--;
		} else {
			(void)r_panels_move_to_direction (core, 'h');
			if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
				r_panels_reset_snow (panels);
			}
		}
		break;
	case 'j':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y++;
		} else {
			(void)r_panels_move_to_direction (core, 'j');
			if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
				r_panels_reset_snow (panels);
			}
		}
		break;
	case 'k':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y--;
		} else {
			(void)r_panels_move_to_direction (core, 'k');
			if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
				r_panels_reset_snow (panels);
			}
		}
		break;
	case 'l':
		if (core->print->cur_enabled) {
			core->cons->cpos.x++;
		} else {
			(void)r_panels_move_to_direction (core, 'l');
			if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
				r_panels_reset_snow (panels);
			}
		}
		break;
	case 'H':
	case 'L':
	case 'J':
	case 'K':
		if (r_config_get_b (core->config, "scr.cursor")) {
			if (key == 'H' || key == 'L') {
				core->cons->cpos.x += 5;
			} else {
				core->cons->cpos.y += (key == 'J') ? 5 : -5;
			}
		} else {
			r_cons_switchbuf (core->cons, false);
			r_panels_resize_panel (panels, key | 0x20);
		}
		break;
	case 'n':
		__create_panel_input (core, cur, PANEL_LAYOUT_VERTICAL, NULL);
		break;
	case 'N':
		__create_panel_input (core, cur, PANEL_LAYOUT_HORIZONTAL, NULL);
		break;
	case 'X':
		r_panels_dismantle_del_panel (core, cur, panels->curnode);
		break;
	case '"':
	case ':':
	case ';':
	case '/':
	case 'd':
	case 'b':
	case 'p':
	case 'P':
	case 't':
	case 'T':
	case '?':
	case '|':
	case '-':
		return false;
	}
	return true;
}

static bool r_panels_handle_cursor_mode(RCore *core, const int key) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	RPrint *print = core->print;
	char *db_val;
	switch (key) {
	case ':':
	case ';':
	case 'd':
	case 'h':
	case 'j':
	case 'k':
	case 'J':
	case 'K':
	case 'l':
	case 'm':
	case 'Z':
	case '"':
	case 9:
		return false;
	case 'g':
		cur->view->curpos = 0;
		r_panels_reset_scroll_pos (cur);
		cur->view->refresh = true;
		break;
	case ']':
		if (r_panels_check_panel_type (cur, PANEL_CMD_HEXDUMP)) {
			const int cols = r_config_get_i (core->config, "hex.cols");
			r_config_set_i (core->config, "hex.cols", cols + 1);
		} else {
			const int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
			r_config_set_i (core->config, "asm.cmt.col", cmtcol + 2);
		}
		cur->view->refresh = true;
		break;
	case '[':
		if (r_panels_check_panel_type (cur, PANEL_CMD_HEXDUMP)) {
			const int cols = r_config_get_i (core->config, "hex.cols");
			r_config_set_i (core->config, "hex.cols", cols - 1);
 		} else {
			int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
			if (cmtcol > 2) {
				r_config_set_i (core->config, "asm.cmt.col", cmtcol - 2);
			}
		}
		cur->view->refresh = true;
		break;
	case 'Q':
	case 'q':
	case 'c':
		r_panels_set_cursor (core, !print->cur_enabled);
		cur->view->refresh = true;
		break;
	case 'w':
		r_panels_toggle_window_mode (core);
		r_panels_set_cursor (core, false);
		cur->view->refresh = true;
		break;
	case 'i':
		__insert_value (core, 'x');
		break;
	case 'I':
		__insert_value (core, 'a');
		break;
	case '*':
		if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
			r_core_cmdf (core, "dr PC=0x%08"PFMT64x, core->addr + print->cur);
			r_panels_set_panel_addr (core, cur, core->addr + print->cur);
		}
		break;
	case '-':
		db_val = r_panels_search_db (core, "Breakpoints");
		if (r_panels_check_panel_type (cur, db_val)) {
			__cursor_del_breakpoints(core, cur);
			free (db_val);
			break;
		}
		free (db_val);
		return false;
	case 'x':
		__handle_refs (core, cur, r_panels_parse_string_on_cursor (core, cur, cur->view->curpos));
		break;
	case 0x0d:
		__jmp_to_cursor_addr (core, cur);
		break;
	case 'b':
		__set_breakpoints_on_cursor (core, cur);
		break;
	case 'H':
		cur->view->curpos = cur->view->sy;
		cur->view->refresh = true;
		break;
	}
	return true;
}

static bool r_panels_drag_and_resize(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->mouse_on_edge_x || panels->mouse_on_edge_y) {
		int x, y;
		if (r_cons_get_click (core->cons, &x, &y)) {
			y -= r_config_get_i (core->config, "scr.notch");
			if (panels->mouse_on_edge_x) {
				r_panels_update_edge_x (core, x - panels->mouse_orig_x);
			}
			if (panels->mouse_on_edge_y) {
				r_panels_update_edge_y (core, y - panels->mouse_orig_y);
			}
		}
		panels->mouse_on_edge_x = false;
		panels->mouse_on_edge_y = false;
		return true;
	}
	return false;
}

static char *r_panels_get_word_from_canvas(RCore *core, RPanels *panels, int x, int y) {
	RStrBuf rsb;
	r_strbuf_init (&rsb);
	char *cs = r_cons_canvas_tostring (panels->can);
	r_strbuf_setf (&rsb, " %s", cs);
	char *R = r_str_ansi_crop (r_strbuf_get (&rsb), 0, y - 1, x + 1024, y);
	r_str_ansi_filter (R, NULL, NULL, -1);
	char *r = r_str_ansi_crop (r_strbuf_get (&rsb), x - 1, y - 1, x + 1024, y);
	r_str_ansi_filter (r, NULL, NULL, -1);
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

static void r_panels_handle_tab_nth(RCore *core, int ch) {
	ch -= '0' + 1;
	if (ch < 0) {
		return;
	}
	if (ch != core->panels_root->cur_panels && ch < core->panels_root->n_panels) {
		core->panels_root->cur_panels = ch;
		r_panels_set_root_state (core, ROTATE);
	}
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

static bool r_panels_handle_mouse_on_top(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	char *word = r_panels_get_word_from_canvas (core, panels, x, y);
	int i;
	for (i = 0; i < COUNT (menus); i++) {
		if (!strcmp (word, menus[i])) {
			r_panels_set_mode (core, PANEL_MODE_MENU);
			r_panels_clear_panels_menu (core);
			RPanelsMenu *menu = panels->panels_menu;
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
		return true;
	}
	if (atoi (word)) {
		r_panels_handle_tab_nth (core, word[0]);
		return true;
	}
	return false;
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

static void r_panels_menu_bar_range(RPanelsMenuItem *root, int sel, int bar_room, int *out_first, int *out_last) {
	int i, n = root->n_sub;
	*out_first = 0;
	*out_last = n - 1;
	int total = 0;
	for (i = 0; i < n; i++) {
		total += strlen (root->sub[i]->name) + 2;
	}
	if (total <= bar_room) {
		return;
	}
	int vis = 0;
	for (i = 0; i <= sel && i < n; i++) {
		vis += strlen (root->sub[i]->name) + 2;
	}
	while (*out_first < sel && vis > bar_room - 4) {
		vis -= strlen (root->sub[*out_first]->name) + 2;
		(*out_first)++;
	}
	int used = 0;
	int reserve = (*out_first > 0 ? 2 : 0) + 2;
	for (i = *out_first; i < n; i++) {
		int iw = strlen (root->sub[i]->name) + 2;
		if (used + iw > bar_room - reserve && i > sel) {
			break;
		}
		used += iw;
	}
	*out_last = i - 1;
}

static int r_panels_menu_bar_x(RPanelsMenu *menu, int index, int canw) {
	int first, last;
	r_panels_menu_bar_range (menu->root, index, canw - 16, &first, &last);
	int x = 4;
	if (first > 0) {
		x += 2;
	}
	int i;
	for (i = first; i < index && i < menu->root->n_sub; i++) {
		x += strlen (menu->root->sub[i]->name) + 2;
	}
	return x;
}

static RStrBuf *r_panels_draw_menu(RCore *core, RPanelsMenuItem *item, int max_items) {
	RStrBuf *buf = r_strbuf_new (NULL);
	if (!buf) {
		return NULL;
	}
	int i, n = item->n_sub;
	int sel = item->selectedIndex;
	int first = 0, last = n - 1;
	bool top_ell = false, bot_ell = false;
	if (max_items > 2 && n > max_items) {
		first = sel - max_items / 2;
		if (first < 0) {
			first = 0;
		}
		last = first + max_items - 1;
		if (last >= n) {
			last = n - 1;
			first = R_MAX (0, last - max_items + 1);
		}
		top_ell = first > 0;
		bot_ell = last < n - 1;
		if (top_ell) {
			first++;
		}
		if (bot_ell) {
			last--;
		}
	}
	if (top_ell) {
		r_strbuf_append (buf, "  (...)          \n");
	}
	for (i = first; i <= last; i++) {
		if (i == sel) {
			r_strbuf_appendf (buf, "%s> %s"Color_RESET, PANEL_HL_COLOR, item->sub[i]->name);
		} else {
			r_strbuf_appendf (buf, "  %s", item->sub[i]->name);
		}
		r_strbuf_append (buf, "          \n");
	}
	if (bot_ell) {
		r_strbuf_append (buf, "  (...)          \n");
	}
	return buf;
}

static void r_panels_update_menu_contents(RCore *core, RPanelsMenu *menu, RPanelsMenuItem *parent) {
	RPanel *p = parent->p;
	RConsCanvas *can = core->panels->can;
	int max_items = can->h - p->view->pos.y - 4;
	if (max_items < 3) {
		max_items = 3;
	}
	RStrBuf *buf = r_panels_draw_menu (core, parent, max_items);
	if (!buf) {
		return;
	}
	free (p->model->title);
	p->model->title = r_strbuf_drain (buf);
	p->view->pos.w = r_str_bounds (p->model->title, &p->view->pos.h);
	p->view->pos.h += 4;
	if (p->view->pos.y + p->view->pos.h > can->h) {
		p->view->pos.h = can->h - p->view->pos.y;
	}
	p->model->type = PANEL_TYPE_MENU;
	p->view->refresh = true;
	if (menu->n_refresh > 0) {
		menu->refreshPanels[menu->n_refresh - 1] = p;
	}
}

static void r_panels_handle_mouse_on_menu(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	char *word = r_panels_get_word_from_canvas_for_menu (core, panels, x, y);
	RPanelsMenu *menu = panels->panels_menu;
	int i, d = menu->depth - 1;
	while (d) {
		RPanelsMenuItem *parent = menu->history[d--];
		for (i = 0; i < parent->n_sub; i++) {
			if (!strcmp (word, parent->sub[i]->name)) {
				parent->selectedIndex = i;
				(void)(parent->sub[parent->selectedIndex]->cb (core));
				r_panels_update_menu_contents (core, menu, parent);
				free (word);
				return;
			}
		}
		r_panels_del_menu (core);
	}
	r_panels_clear_panels_menu (core);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	r_panels_get_cur_panel (panels)->view->refresh = true;
	free (word);
}

static void r_panels_toggle_cache(RCore *core, RPanel *p) {
	bool newcache = !p->model->cache;
	p->model->cache = newcache;
	r_panels_set_cmd_str_cache (core, p, NULL); // if cache is set ignore it!
	p->model->cache = newcache;
	p->view->refresh = true;
}

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

static void r_panels_update_modal(RCore *core, Sdb *menu_db, RModal *modal, int delta) {
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	modal->data = r_strbuf_new (NULL);
	int count = sdb_count (menu_db);
	if (modal->idx >= count) {
		modal->idx = 0;
		modal->offset = 0;
	} else if (modal->idx >= modal->offset + modal->pos.h) {
		if (modal->offset + modal->pos.h >= count) {
			modal->offset = 0;
			modal->idx = 0;
		} else {
			modal->offset += delta;
		}
	} else if (modal->idx < 0) {
		modal->offset = R_MAX (count - modal->pos.h, 0);
		modal->idx = count - 1;
	} else if (modal->idx < modal->offset) {
		modal->offset -= delta;
	}
	SdbList *l = sdb_foreach_list (menu_db, true);
	SdbKv *kv;
	SdbListIter *iter;
	int i = 0;
	int max_h = R_MIN (modal->offset + modal->pos.h, count);
	ls_foreach (l, iter, kv) {
		if (r_panels_draw_modal (core, modal, max_h, i, sdbkv_key (kv))) {
			i++;
		}
	}
	r_cons_gotoxy (core->cons, 0, 0);
	r_cons_canvas_fill (can, modal->pos.x, modal->pos.y, modal->pos.w + 2, modal->pos.h + 2, ' ');
	(void)r_cons_canvas_gotoxy (can, modal->pos.x + 2, modal->pos.y + 1);
	r_cons_canvas_write (can, r_strbuf_get (modal->data));
	r_strbuf_free (modal->data);

	r_cons_canvas_box (can, modal->pos.x, modal->pos.y, modal->pos.w + 2, modal->pos.h + 2, PANEL_HL_COLOR);

	r_panels_print_notch (core);
	r_cons_canvas_print (can);
	r_cons_flush (core->cons);
	r_panels_show_cursor (core);
}

static void r_panels_exec_modal(RCore *core, RPanel *panel, RModal *modal, Sdb *menu_db, RPanelLayout dir) {
	SdbList *l = sdb_foreach_list (menu_db, true);
	SdbKv *kv;
	SdbListIter *iter;
	int i = 0;
	ls_foreach (l, iter, kv) {
		if (i++ == modal->idx) {
			RPanelAlmightyCallback cb = sdb_ptr_get (menu_db, sdbkv_key (kv), 0);
			if (cb) {
				cb (core, panel, dir, sdbkv_key (kv));
			}
			break;
		}
	}
	panel->view->sy = 0;
	panel->view->sx = 0;
}

static void r_panels_delete_modal(RCore *core, RModal *modal, Sdb *menu_db) {
	SdbList *l = sdb_foreach_list (menu_db, true);
	SdbKv *kv;
	SdbListIter *iter;
	int i = 0;
	ls_foreach (l, iter, kv) {
		if (i++ == modal->idx) {
			sdb_remove (menu_db, sdbkv_key (kv), 0);
		}
	}
}

static RModal *r_panels_init_modal(void) {
	RModal *modal = R_NEW0 (RModal);
	r_panels_set_pos (&modal->pos, 0, 0);
	modal->idx = 0;
	modal->offset = 0;
	return modal;
}

static void r_panels_free_modal(RModal **modal) {
	free (*modal);
	*modal = NULL;
}

static void r_panels_create_modal(RCore *core, RPanel *panel, Sdb *menu_db) {
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
	r_panels_update_modal (core, menu_db, modal, 1);
	while (modal) {
		r_cons_set_raw (cons, true);
		okey = r_cons_readchar (cons);
		key = r_cons_arrow_to_hjkl (cons, okey);
		word = NULL;
		if (key == INT8_MAX - 1) {
			if (r_cons_get_click (cons, &cx, &cy)) {
				cy -= r_config_get_i (core->config, "scr.notch");
				if ((cx < x || x + w < cx) || ((cy < y || y + h < cy))) {
					key = 'q';
				} else {
					word = r_panels_get_word_from_canvas_for_menu (core, core->panels, cx, cy);
					if (word) {
						RPanelAlmightyCallback cb = sdb_ptr_get (menu_db, word, 0);
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
					__replace_cmd (core, cmd, cmd);
				}
				free (cmd);
			}
			break;
		case 'j':
			modal->idx++;
			r_panels_update_modal (core, menu_db, modal, 1);
			break;
		case 'k':
			modal->idx--;
			r_panels_update_modal (core, menu_db, modal, 1);
			break;
		case 'J':
			modal->idx += 5;
			r_panels_update_modal (core, menu_db, modal, 5);
			break;
		case 'K':
			modal->idx -= 5;
			r_panels_update_modal (core, menu_db, modal, 5);
			break;
		case 'v':
			r_panels_exec_modal (core, panel, modal, menu_db, PANEL_LAYOUT_VERTICAL);
			r_panels_free_modal (&modal);
			break;
		case 'h':
			r_panels_exec_modal (core, panel, modal, menu_db, PANEL_LAYOUT_HORIZONTAL);
			r_panels_free_modal (&modal);
			break;
		case ' ':
		case 0x0d:
			r_panels_exec_modal (core, panel, modal, menu_db, PANEL_LAYOUT_NONE);
			r_panels_free_modal (&modal);
			break;
		case '-':
			r_panels_delete_modal (core, modal, menu_db);
			r_panels_update_modal (core, menu_db, modal, 1);
			break;
		case 'q':
		case '"':
			r_panels_free_modal (&modal);
			break;
		}
	}
}

static bool r_panels_handle_mouse_on_X(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	const int idx = r_panels_get_panel_idx_in_pos (core, x, y);
	char *word = r_panels_get_word_from_canvas (core, panels, x, y);
	if (idx == -1) {
		return false;
	}
	RPanel *ppos = r_panels_get_panel(panels, idx);
	const int TITLE_Y = ppos->view->pos.y + 2;
	if (y == TITLE_Y && strcmp (word, " X ")) {
		int fx = ppos->view->pos.x;
		int fX = fx + ppos->view->pos.w;
		r_panels_set_curnode (core, idx);
		r_panels_set_refresh_all (core, true, true);
		if (x > (fX - 13) && x < fX) {
			r_panels_toggle_cache (core, r_panels_get_cur_panel (panels));
		} else if (x > fx && x < (fx + 5)) {
			r_panels_dismantle_del_panel (core, ppos, idx);
		} else {
			r_panels_create_modal (core, r_panels_get_panel (panels, 0), panels->modal_db);
			r_panels_set_mode (core, PANEL_MODE_DEFAULT);
		}
		free (word);
		return true;
	}
	free (word);
	return false;
}

static void r_panels_seek_all(RCore *core, ut64 addr) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = r_panels_get_panel (panels, i);
		panel->model->addr = addr;
	}
}

static bool r_panels_handle_mouse_on_panel(RCore *core, RPanel *panel, int x, int y, int *key) {
	RPanels *panels = core->panels;
	int h;
	(void)r_cons_get_size (core->cons, &h);
	const int idx = r_panels_get_panel_idx_in_pos (core, x, y);
	char *word = r_panels_get_word_from_canvas (core, panels, x, y);
	r_panels_set_curnode (core, idx);
	//r_panels_set_refresh_all (core, true, true);
	if (idx == -1 || R_STR_ISEMPTY (word)) {
		free (word);
		return false;
	}
	if (R_STR_ISNOTEMPTY (word)) {
		const ut64 addr = r_num_math (core->num, word);
		if (r_panels_check_panel_type (panel, PANEL_CMD_FUNCTION) &&
				r_panels_check_if_addr (word, strlen (word))) {
			r_core_seek (core, addr, true);
			__set_addr_by_type (core, PANEL_CMD_DISASSEMBLY, addr);
		}
	//	r_flag_set (core->flags, "panel.addr", addr, 1);
		r_config_set (core->config, "scr.highlight", word);
		if (addr != 0 && addr != UT64_MAX) {
			// TODO implement proper panel offset sync
			// r_panels_set_panel_addr (core, idx, addr);
			r_io_sundo_push (core->io, core->addr, 0);
			r_panels_seek_all (core, addr);
		}
	}
	free (word);
	RPanel *ppos = r_panels_get_panel (panels, idx);
	if (x >= ppos->view->pos.x && x < ppos->view->pos.x + 4) {
		*key = 'c';
		return false;
	}
	return true;
}

static bool r_panels_handle_mouse(RCore *core, RPanel *panel, int *key) {
	RPanels *panels = core->panels;
	if (r_panels_drag_and_resize (core)) {
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
		if (panels->mode == PANEL_MODE_MENU) {
			r_panels_handle_mouse_on_menu (core, x, y);
			return true;
		}
		if (r_panels_handle_mouse_on_X (core, x, y)) {
			return true;
		}
		if (r_panels_check_if_mouse_x_illegal (core, x) || r_panels_check_if_mouse_y_illegal (core, y)) {
			panels->mouse_on_edge_x = false;
			panels->mouse_on_edge_y = false;
			return true;
		}
		panels->mouse_on_edge_x = r_panels_check_if_mouse_x_on_edge (core, x, y);
		panels->mouse_on_edge_y = r_panels_check_if_mouse_y_on_edge (core, x, y);
		if (panels->mouse_on_edge_x || panels->mouse_on_edge_y) {
			return true;
		}
		if (r_panels_handle_mouse_on_panel (core, panel, x, y, key)) {
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
	if (key && *key == INT8_MAX) {
		*key = '"';
		return false;
	}
	return false;
}

static void r_panels_move_panel_to(RCore *core, RPanel *panel, int src, Direction dir) {
	RPanels *panels = core->panels;
	bool neg = (dir == 'h' || dir == 'k');
	bool horiz = (dir == 'h' || dir == 'l');
	if (neg) {
		r_panels_shrink_panels_backward (core, src);
		panels->panel[0] = panel;
	} else {
		r_panels_shrink_panels_forward (core, src);
		panels->panel[panels->n_panels - 1] = panel;
	}
	int h, w = r_cons_get_size (core->cons, &h);
	if (w < 1) {
		w = 1;
	}
	if (h < 1) {
		h = 1;
	}
	int start = neg ? 1 : 0;
	int end = neg ? panels->n_panels : panels->n_panels - 1;
	int i;
	if (horiz) {
		int p_w = (w - panels->columnWidth) / 2;
		int new_w = w - p_w;
		if (neg) {
			r_panels_set_geometry (&panel->view->pos, 0, 1, p_w + 1, h - 1);
		} else {
			r_panels_set_geometry (&panel->view->pos, w - p_w - 1, 1, p_w + 1, h - 1);
		}
		for (i = start; i < end; i++) {
			RPanel *tmp = r_panels_get_panel (panels, i);
			int t_x = (int)((double)tmp->view->pos.x / w * new_w + (neg ? p_w : 0));
			int t_w = (int)((double)tmp->view->pos.w / w * new_w + 1);
			r_panels_set_geometry (&tmp->view->pos, t_x, tmp->view->pos.y, t_w, tmp->view->pos.h);
		}
	} else {
		int p_h = h / 2;
		int new_h = h - p_h;
		if (neg) {
			r_panels_set_geometry (&panel->view->pos, 0, 1, w, p_h - 1);
		} else {
			r_panels_set_geometry (&panel->view->pos, 0, new_h, w, p_h);
		}
		for (i = start; i < end; i++) {
			RPanel *tmp = r_panels_get_panel (panels, i);
			int t_y, t_h;
			if (neg) {
				t_y = (int)((double)tmp->view->pos.y / h * new_h + p_h);
				t_h = (int)((double)tmp->view->pos.h / h * new_h + 1);
			} else {
				t_y = (int)(tmp->view->pos.y * new_h / h) + 1;
				t_h = (tmp->view->edge & (1 << PANEL_EDGE_BOTTOM))
					? new_h - t_y
					: (int)(tmp->view->pos.h * new_h / h);
			}
			r_panels_set_geometry (&tmp->view->pos, tmp->view->pos.x, t_y, tmp->view->pos.w, t_h);
		}
	}
	r_panels_fix_layout (core);
	r_panels_set_curnode (core, neg ? 0 : panels->n_panels - 1);
}

static void r_panels_move_panel_to_dir(RCore *core, RPanel *panel, int src) {
	r_panels_dismantle_panel (core->panels, panel);
	int key = r_panels_show_status (core, "Move the current panel to direction (h/j/k/l): ");
	key = r_cons_arrow_to_hjkl (core->cons, key);
	r_panels_set_refresh_all (core, false, true);
	if (key == 'h' || key == 'j' || key == 'k' || key == 'l') {
		r_panels_move_panel_to (core, panel, src, key);
	}
}

static void r_panels_swap_panels(RPanels *panels, int p0, int p1) {
	RPanel *panel0 = r_panels_get_panel (panels, p0);
	RPanel *panel1 = r_panels_get_panel (panels, p1);
	RPanelModel *tmp = panel0->model;

	panel0->model = panel1->model;
	panel1->model = tmp;
}

static bool r_panels_check_func(RCore *core) {
	RAnalFunction *fun = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	if (!fun) {
		r_cons_message (core->cons, "Not in a function. Type 'df' to define it here");
		return false;
	}
	if (r_list_empty (fun->bbs)) {
		r_cons_message (core->cons, "No basic blocks in this function. You may want to use 'afb+'.");
		return false;
	}
	return true;
}

static void r_panels_call_visual_graph(RCore *core) {
	if (r_panels_check_func (core)) {
		RPanels *panels = core->panels;

		r_cons_canvas_free (panels->can);
		panels->can = NULL;

		int ocolor = r_config_get_i (core->config, "scr.color");

		r_core_visual_graph (core, NULL, NULL, true);
		r_config_set_i (core->config, "scr.color", ocolor);

		int h, w = r_cons_get_size (core->cons, &h);
		if (h > 0) {
			const int notch = r_config_get_i (core->config, "scr.notch");
			if (h > notch) {
				h -= notch;
			}
		} else {
			h = 1;
		}
		if (w < 1) {
			w = 1;
		}
		panels->can = r_panels_create_new_canvas (core, w, h);
	}
}

static void r_panels_do_panels_refresh(RCore *core) {
	if (core->panels) {
		r_panels_panel_all_clear (core, core->panels);
		r_panels_panels_layout_refresh (core);
	}
}

static void r_panels_do_panels_resize(RCore *core) {
	RPanels *panels = core->panels;
	int i;
	int h, w = r_cons_get_size (core->cons, &h);
	if (h > 0) {
		const int notch = r_config_get_i (core->config, "scr.notch");
		if (h > notch) {
			h -= notch;
		}
	} else {
		h = 1;
	}
	if (w < 1) {
		w = 1;
	}
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		RPanelPos *pos = &p->view->pos;
		if ((p->view->edge & (1 << PANEL_EDGE_BOTTOM)) && pos->y + pos->h < h) {
			pos->h = h - pos->y;
		}
		if ((p->view->edge & (1 << PANEL_EDGE_RIGHT)) && pos->x + pos->w < w) {
			pos->w = w - pos->x;
		}
	}
	r_panels_do_panels_refresh (core);
}

static void r_panels_do_panels_refreshQueued(RCore *core) {
	r_panels_do_panels_resize (core);
}

static void r_panels_hudstuff(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	r_core_visual_hudstuff (core);

	if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		r_panels_set_panel_addr (core, cur, core->addr);
	} else {
		int i;
		for (i = 0; i < panels->n_panels; i++) {
			RPanel *panel = r_panels_get_panel (panels, i);
			if (r_panels_check_panel_type (panel, PANEL_CMD_DISASSEMBLY)) {
				r_panels_set_panel_addr (core, panel, core->addr);
				break;
			}
		}
	}
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
#if 0
		if (snow->x >= cur->view->pos.w + cur->view->pos.x || snow->x <= cur->view->pos.x + 1) {
			r_list_delete (panels->snows, iter);
			continue;
		}
#endif
		bool fall = false;
		{
			RListIter *it;
			RPanelsSnow *snw;
			r_list_foreach (panels->snows, it, snw) {
				if (snw->stuck) {
					if (snw->x == snow->x && snw->y == snow->y) {
						bool is_down_right = (snw->x == snow->x + 1 && snw->y == snow->y);
						bool is_down_left = (snw->x == snow->x - 1 && snw->y == snow->y);
						fall = false;
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
						}
						goto print_this_snow;
					}
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

static void r_panels_update_menu(RCore *core, const char *parent, R_NULLABLE RPanelMenuUpdateCallback cb) {
	RPanels *panels = core->panels;
	void *addr = ht_pp_find (panels->mht, parent, NULL);
	RPanelsMenuItem *p_item = (RPanelsMenuItem *)addr;
	int i;
	for (i = 0; i < p_item->n_sub; i++) {
		RPanelsMenuItem *sub = p_item->sub[i];
		r_strf_var (key, 128, "%s.%s", parent, sub->name);
		ht_pp_delete (core->panels->mht, key);
	}
	p_item->sub = NULL;
	p_item->n_sub = 0;
	if (cb) {
		cb (core, parent);
	}
	RPanelsMenu *menu = panels->panels_menu;
	r_panels_update_menu_contents (core, menu, p_item);
}

static char *r_panels_panels_config_path(bool syspath) {
	if (syspath) {
		char *pfx = r_sys_prefix (NULL);
		char *res = r_file_new (pfx, R2_DATDIR_R2, "panels", NULL);
		free (pfx);
		return res;
	}
	return r_xdg_datadir ("r2panels");
}

static void r_panels_add_menu(RCore *core, const char *parent, const char *name, RPanelsMenuCallback cb) {
	RPanels *panels = core->panels;
	RPanelsMenuItem *p_item;
	RPanelsMenuItem *item = R_NEW0 (RPanelsMenuItem);
	r_strf_buffer (128);
	if (parent) {
		void *addr = ht_pp_find (panels->mht, parent, NULL);
		p_item = (RPanelsMenuItem *)addr;
		ht_pp_insert (panels->mht, r_strf ("%s.%s", parent, name), item);
	} else {
		p_item = panels->panels_menu->root;
		ht_pp_insert (panels->mht, r_strf ("%s", name), item);
	}
	if (p_item == NULL) {
		R_LOG_WARN ("Cannot find panel %s", parent);
		r_sys_sleep (1);
	}
	item->n_sub = 0;
	item->selectedIndex = 0;
	item->name = strdup (name);
	item->sub = NULL;
	item->cb = cb;
	item->p = R_NEW0 (RPanel);
	if (item->p && p_item) {
		item->p->model = R_NEW0 (RPanelModel);
		item->p->view = R_NEW0 (RPanelView);
		if (item->p->model && item->p->view) {
			p_item->n_sub++;
			RPanelsMenuItem **sub = realloc (p_item->sub, sizeof (RPanelsMenuItem *) * p_item->n_sub);
			if (sub) {
				p_item->sub = sub;
				p_item->sub[p_item->n_sub - 1] = item;
				item = NULL;
			}
		}
	}
	r_panels_free_menu_item (item);
}

static void r_panels_init_menu_config(RCore *core, const char *parent,
		const char **items, int count, const char **value_items) {
	RList *list = r_panels_sorted_list (core, items, count);
	char *pos;
	RListIter *iter;
	RStrBuf *rsb = r_strbuf_new (NULL);
	r_list_foreach (list, iter, pos) {
		r_strbuf_setf (rsb, "%s: %s", pos, r_config_get (core->config, pos));
		bool is_value = false;
		int j;
		for (j = 0; value_items && value_items[j]; j++) {
			if (!strcmp (pos, value_items[j])) {
				is_value = true;
				break;
			}
		}
		r_panels_add_menu (core, parent, r_strbuf_get (rsb), is_value? __config_value_cb: __config_toggle_cb);
	}
	r_list_free (list);
	r_strbuf_free (rsb);
}

static int r_panels_cmpstr(const void *_a, const void *_b) {
	char *a = (char *)_a, *b = (char *)_b;
	return strcmp (a, b);
}

static RList *r_panels_sorted_list(RCore *core, const char *menu[], int count) {
	RList *list = r_list_newf (NULL);
	int i;
	for (i = 0; i < count; i++) {
		if (menu[i]) {
			(void)r_list_append (list, (void *)menu[i]);
		}
	}
	r_list_sort (list, r_panels_cmpstr);
	return list;
}

static RPanelsMenuCallback r_panels_find_menu_cb(const MenuItem *items, const char *name) {
	int i;
	for (i = 0; items && items[i].name; i++) {
		if (!strcmp (name, items[i].name)) {
			return items[i].cb;
		}
	}
	return NULL;
}

static void r_panels_add_menu_items(RCore *core, const char *parent,
		const MenuItem *items, const char **menu_list, RPanelsMenuCallback default_cb) {
	int i;
	for (i = 0; menu_list[i]; i++) {
		const char *name = menu_list[i];
		if (*name == '-') {
			r_panels_add_menu (core, parent, name, r_panels_separator);
			continue;
		}
		RPanelsMenuCallback cb = r_panels_find_menu_cb (items, name);
		r_panels_add_menu (core, parent, name, cb? cb: (default_cb? default_cb: __add_cmd_panel));
	}
}

static void r_panels_add_menu_items_sorted(RCore *core, const char *parent,
		const MenuItem *items, const char **menu_list, int count, RPanelsMenuCallback default_cb) {
	RList *list = r_panels_sorted_list (core, menu_list, count);
	char *pos;
	RListIter *iter;
	r_list_foreach (list, iter, pos) {
		RPanelsMenuCallback cb = r_panels_find_menu_cb (items, pos);
		r_panels_add_menu (core, parent, pos, cb? cb: (default_cb? default_cb: __add_cmd_panel));
	}
	r_list_free (list);
}

static void r_panels_default_panel_print(RCore *core, RPanel *panel) {
	bool o_cur = core->print->cur_enabled;
	core->print->cur_enabled = o_cur & (r_panels_get_cur_panel (core->panels) == panel);
	if (panel->model->readOnly) {
		r_panels_update_help_contents (core, panel);
		r_panels_update_help_title (core, panel);
	} else if (panel->model->cmd) {
		panel->model->print_cb (core, panel);
		r_panels_update_panel_title (core, panel);
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

static void r_panels_panels_refresh(RCore *core) {
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	r_cons_gotoxy (core->cons, 0, 0);
	int i, h, w = r_cons_get_size (core->cons, &h);
	h -= r_config_get_i (core->config, "scr.notch");
	if (!r_cons_canvas_resize (can, w, h)) {
		return;
	}
	RStrBuf *title = r_strbuf_new (" ");
	bool utf8 = r_config_get_b (core->config, "scr.utf8");
	if (core->visual.firstRun) {
		r_config_set_b (core->config, "scr.utf8", false);
	}

	__refresh_core_offset (core);
	r_panels_set_refresh_all (core, false, false);

	for (i = 0; i < panels->n_panels; i++) {
		if (panels->mode == PANEL_MODE_ZOOM) {
			if (i != panels->curnode) {
				continue;
			}
		}
		r_panels_panel_print (core, can, r_panels_get_panel (panels, i), 0);
	}
	r_panels_panel_print (core, can, r_panels_get_cur_panel (panels), panels->mode != PANEL_MODE_MENU);
	// draw menus
	for (i = 0; i < panels->panels_menu->n_refresh; i++) {
		r_panels_panel_print (core, can, panels->panels_menu->refreshPanels[i], 0);
	}
	(void) r_cons_canvas_gotoxy (can, -can->sx, -can->sy);
	r_cons_canvas_fill (can, -can->sx, -can->sy, w, 1, ' ');
	if (panels->mode == PANEL_MODE_ZOOM) {
		r_strbuf_appendf (title, "%s Zoom Mode | Press Enter or q to quit"Color_RESET, PANEL_HL_COLOR);
	} else if (panels->mode == PANEL_MODE_WINDOW) {
		r_strbuf_appendf (title, "%s Window Mode | hjkl: move around the panels | q: quit the mode | Enter: Zoom mode"Color_RESET, PANEL_HL_COLOR);
	} else {
		RPanelsMenuItem *parent = panels->panels_menu->root;
		if (panels->mode == PANEL_MODE_MENU) {
			r_strbuf_append (title, " > ");
		} else {
			if (panels->can->color) {
				r_strbuf_appendf (title, "%s[m]"Color_RESET, PANEL_HL_COLOR);
			} else {
				r_strbuf_append (title, "[m]");
			}
		}
		int menu_first, menu_last;
		r_panels_menu_bar_range (parent, parent->selectedIndex, w - 16, &menu_first, &menu_last);
		if (menu_first > 0) {
			r_strbuf_append (title, "< ");
		}
		for (i = menu_first; i <= menu_last && i < parent->n_sub; i++) {
			RPanelsMenuItem *item = parent->sub[i];
			if (panels->mode == PANEL_MODE_MENU && i == parent->selectedIndex) {
				r_strbuf_appendf (title, "%s[%s]"Color_RESET, PANEL_HL_COLOR, item->name);
			} else {
				r_strbuf_appendf (title, " %s ", item->name);
			}
		}
		if (menu_last < parent->n_sub - 1) {
			r_strbuf_append (title, " >");
		}
	}
	if (panels->mode == PANEL_MODE_MENU) {
		r_cons_canvas_write (can, Color_YELLOW);
		r_cons_canvas_write (can, r_strbuf_get (title));
		r_cons_canvas_write (can, Color_RESET);
	} else {
		r_cons_canvas_write (can, Color_RESET);
		r_cons_canvas_write (can, r_strbuf_get (title));
	}
	r_strbuf_setf (title, "[0x%08"PFMT64x "]", core->addr);
	i = -can->sx + w - r_strbuf_length (title);
	(void) r_cons_canvas_gotoxy (can, i, -can->sy);
	r_cons_canvas_write (can, r_strbuf_get (title));

	int tab_pos = i;
	for (i = core->panels_root->n_panels; i > 0; i--) {
		RPanels *panels = core->panels_root->panels[i - 1];
		const char *name = panels? panels->name: NULL;
		if (i - 1 == core->panels_root->cur_panels) {
			if (name) {
				r_strbuf_setf (title, "%s(%s) "Color_RESET, PANEL_HL_COLOR, name);
			} else {
				r_strbuf_setf (title, "%s(%d) "Color_RESET, PANEL_HL_COLOR, i);
			}
			tab_pos -= r_str_ansi_len (r_strbuf_get (title));
		} else {
			if (!name) {
				r_strbuf_setf (title, "%d ", i);
			} else {
				r_strbuf_setf (title, "%s ", name);
			}
			tab_pos -= r_strbuf_length (title);
		}
		(void) r_cons_canvas_gotoxy (can, tab_pos, -can->sy);
		r_cons_canvas_write (can, r_strbuf_get (title));
	}
	r_strbuf_setf (title, "%s[t]%sab ", PANEL_HL_COLOR, Color_RESET);
	tab_pos -= r_str_ansi_len (r_strbuf_get (title));
	(void) r_cons_canvas_gotoxy (can, tab_pos, -can->sy);
	r_cons_canvas_write (can, r_strbuf_get (title));
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
		r_panels_panels_refresh (core);
		return;
	}
	r_panels_print_notch (core);
	r_cons_canvas_print (can);
	if (core->scr_gadgets) {
		r_core_cmd_call (core, "pg");
	}
	r_panels_show_cursor (core);
	r_cons_flush (core->cons);
}

static void r_panels_rotate_panels(RCore *core, bool rev) {
	RPanels *panels = core->panels;
	RPanel *first = r_panels_get_panel (panels, 0);
	RPanel *last = r_panels_get_panel (panels, panels->n_panels - 1);
	int i;
	RPanelModel *tmp_model;
	if (!rev) {
		tmp_model = first->model;
		for (i = 0; i < panels->n_panels - 1; i++) {
			RPanel *p0 = r_panels_get_panel (panels, i);
			RPanel *p1 = r_panels_get_panel (panels, i + 1);
			p0->model = p1->model;
		}
		last->model = tmp_model;
	} else {
		tmp_model = last->model;
		for (i = panels->n_panels - 1; i > 0; i--) {
			RPanel *p0 = r_panels_get_panel (panels, i);
			RPanel *p1 = r_panels_get_panel (panels, i - 1);
			p0->model = p1->model;
		}
		first->model = tmp_model;
	}
	r_panels_set_refresh_all (core, false, true);
}

static void r_panels_undo_seek(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	if (!r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		return;
	}
	RIOUndos *undo = r_io_sundo (core->io, core->addr);
	if (undo) {
		r_core_visual_seek_animation (core, undo->off);
		r_panels_set_panel_addr (core, cur, core->addr);
	}
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
	//r_panels_reset_scroll_pos (panel);
}

static void r_panels_redo_seek(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	if (!r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		return;
	}
	RIOUndos *undo = r_io_sundo_redo (core->io);
	if (undo) {
		r_core_visual_seek_animation (core, undo->off);
		r_panels_set_panel_addr (core, cur, core->addr);
	}
}

static void r_panels_handle_tab(RCore *core) {
	r_cons_gotoxy (core->cons, 0, 0);
	if (core->panels_root->n_panels <= 1) {
		r_cons_printf (core->cons, R_CONS_CLEAR_LINE"%stab: q:quit t:new T:newWithCurPanel -:del =:setName"Color_RESET, PANEL_HL_COLOR);
	} else {
		const int min = 1;
		const int max = core->panels_root->n_panels;
		r_cons_printf (core->cons, R_CONS_CLEAR_LINE"%stab: q:quit [%d..%d]:select; p:prev; n:next; t:new T:newWithCurPanel -:del =:setName"Color_RESET,
				PANEL_HL_COLOR, min, max);
	}
	r_cons_flush (core->cons);
	r_cons_set_raw (core->cons, true);
	const int ch = r_cons_readchar (core->cons);

	if (isdigit (ch)) {
		r_panels_handle_tab_nth (core, ch);
	} else {
		switch (ch) {
		case 'n':
			r_panels_handle_tab_next (core);
			break;
		case 'p':
			r_panels_handle_tab_prev (core);
			break;
		case '-':
			r_panels_set_root_state (core, DEL);
			break;
		case '=':
			r_panels_handle_tab_name (core);
			break;
		case 't':
			r_panels_handle_tab_new (core);
			break;
		case 'T':
			__handle_tab_new_with_cur_panel (core);
			break;
		}
	}
}

static void r_panels_del_panels(RCore *core) {
	RPanelsRoot *panels_root = core->panels_root;
	if (panels_root->n_panels <= 1) {
		core->panels_root->root_state = QUIT;
		return;
	}
	int i;
	for (i = panels_root->cur_panels; i < panels_root->n_panels - 1; i++) {
		panels_root->panels[i] = panels_root->panels[i + 1];
	}
	panels_root->n_panels--;
	if (panels_root->cur_panels >= panels_root->n_panels) {
		panels_root->cur_panels = panels_root->n_panels - 1;
	}
}

#endif

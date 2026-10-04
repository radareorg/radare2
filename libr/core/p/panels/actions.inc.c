/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

static int help_manpage_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_core_cmdf (core, "man %s", child->name);
	return 0;
}

static int continue_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "dc", 0);
	r_cons_flush (core->cons);
	return 0;
}

static void panel_single_step_in(RCore *core) {
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_core_cmd (core, "ds", 0);
		r_core_cmd (core, ".dr*", 0);
	} else {
		r_core_cmd (core, "aes", 0);
		r_core_cmd (core, ".ar*", 0);
	}
}

static int step_cb(void *user) {
	RCore *core = (RCore *)user;
	panel_single_step_in (core);
	update_disassembly_or_open (core);
	return 0;
}

static void panel_single_step_over(RCore *core) {
	bool io_cache = r_config_get_i (core->config, "io.cache");
	r_config_set_b (core->config, "io.cache", false);
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_core_cmd (core, "dso", 0);
		r_core_cmd (core, ".dr*", 0);
	} else {
		r_core_cmd (core, "aeso", 0);
		r_core_cmd (core, ".ar*", 0);
	}
	r_config_set_b (core->config, "io.cache", io_cache);
}

static int step_over_cb(void *user) {
	RCore *core = (RCore *)user;
	panel_single_step_over (core);
	update_disassembly_or_open (core);
	return 0;
}

static int break_points_cb(void *user) {
	RCore *core = (RCore *)user;

	core->cons->line->prompt_type = R_LINE_PROMPT_OFFSET;
	r_line_set_hist_callback (core->cons->line,
		&r_line_hist_offset_up,
		&r_line_hist_offset_down);
	const char *buf = r_cons_visual_readln (core->cons, "addr: ", NULL);
	r_line_set_hist_callback (core->cons->line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	core->cons->line->prompt_type = R_LINE_PROMPT_DEFAULT;
	if (buf) {
		ut64 addr = r_num_math (core->num, buf);
		r_core_cmdf (core, "dbs 0x%08"PFMT64x, addr);
	}
	return 0;
}

static int show_all_decompiler_cb(void *user) {
	RCore *core = (RCore *)user;
	RAnalFunction *func = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	if (!func) {
		return 0;
	}
	RPanelsRoot *root = core->panels_root;
	const char *pdc_now = r_config_get (core->config, "cmd.pdc");
	char *opts = r_core_cmd_str (core, "e cmd.pdc=?");
	RList *optl = r_str_split_list (opts, "\n", 0);
	RListIter *iter;
	char *opt;
	int i = 0;
	r_panels_handle_tab_new (core);
	RPanels *panels = r_panels_get_panels (root, root->n_panels - 1);
	r_list_foreach (optl, iter, opt) {
		if (R_STR_ISEMPTY (opt)) {
			continue;
		}
		r_config_set (core->config, "cmd.pdc", opt);
		RPanel *panel = r_panels_get_panel (panels, i++);
		panels->n_panels = i;
		panel->model->title = strdup (opt);
		r_panels_set_read_only (core, panel, r_core_cmd_str (core, opt));
	}
	r_panels_layout_equal_hor (core, panels);
	r_list_free (optl);
	free (opts);
	r_config_set (core->config, "cmd.pdc", pdc_now);
	root->cur_panels = root->n_panels - 1;
	r_panels_set_root_state (core, ROTATE);
	return 0;
}

static void delegate_show_all_decompiler_cb(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title) {
	(void)show_all_decompiler_cb ((RCore *)user);
}

static int file_history_up(RLine *line) {
	RCore *core = line->user;
	RList *files = r_id_storage_list (&core->io->files);
	int num_files = r_list_length (files);
	if (line->file_hist_index >= num_files || line->file_hist_index < 0) {
		return false;
	}
	line->file_hist_index++;
	RIODesc *desc = r_list_get_n (files, num_files - line->file_hist_index);
	if (desc) {
		strncpy (line->state.buffer.data, desc->name, R_LINE_BUFSIZE - 1);
		line->state.buffer.index = line->state.buffer.length = strlen (line->state.buffer.data);
	}
	r_list_free (files);
	return true;
}

static int file_history_down(RLine *line) {
	RCore *core = line->user;
	RList *files = r_id_storage_list (&core->io->files);
	int num_files = r_list_length (files);
	if (line->file_hist_index <= 0 || line->file_hist_index > num_files) {
		return false;
	}
	line->file_hist_index--;
	if (line->file_hist_index <= 0) {
		line->state.buffer.data[0] = '\0';
		line->state.buffer.index = line->state.buffer.length = 0;
		return false;
	}
	RIODesc *desc = r_list_get_n (files, num_files - line->file_hist_index);
	if (desc) {
		strncpy (line->state.buffer.data, desc->name, R_LINE_BUFSIZE - 1);
		line->state.buffer.index = line->state.buffer.length = strlen (line->state.buffer.data);
	}
	r_list_free (files);
	return true;
}

static int open_file_cb(void *user) {
	RCore *core = (RCore *)user;
	core->cons->line->prompt_type = R_LINE_PROMPT_FILE;
	r_line_set_hist_callback (core->cons->line, &file_history_up, &file_history_down);
	add_cmdf_panel (core, "open file: ", "o %s");
	core->cons->line->prompt_type = R_LINE_PROMPT_DEFAULT;
	r_line_set_hist_callback (core->cons->line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	return 0;
}

static int rw_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "oo+", 0);
	return 0;
}

static int debugger_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "oo", 0);
	return 0;
}

static int settings_decompiler_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsRoot *root = core->panels_root;
	RPanelsMenu *menu = core->panels->panels_menu;
	menu->n_refresh = 0; // close the menubar
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	const char *pdc_next = child->name;
	const char *pdc_now = r_config_get (core->config, "cmd.pdc");
	if (!strcmp (pdc_next, pdc_now)) {
		return 0;
	}
	root->cur_pdc_cache = sdb_ptr_get (root->pdc_caches, pdc_next, 0);
	if (!root->cur_pdc_cache) {
		Sdb *sdb = sdb_new0 ();
		if (sdb) {
			sdb_ptr_set (root->pdc_caches, pdc_next, sdb, 0);
			root->cur_pdc_cache = sdb;
		}
	}
	r_config_set (core->config, "cmd.pdc", pdc_next);
	r_panels_set_refresh_all (core, true, false);
	r_panels_close_menu (core);
	return 0;
}

static void create_default_panels(RCore *core) {
	RPanels *panels = core->panels;
	panels->n_panels = 0;
	r_panels_set_curnode (core, 0);
	const char **panels_list = panels_static;
	int panels_count = R_ARRAY_SIZE (panels_static);
	if (panels->layout == PANEL_LAYOUT_DEFAULT_DYNAMIC) {
		panels_list = panels_dynamic;
		panels_count = R_ARRAY_SIZE (panels_dynamic);
	}

	int i;
	for (i = 0; i < panels_count; i++) {
		RPanel *p = r_panels_get_panel (panels, panels->n_panels);
		if (!p) {
			return;
		}
		const char *s = panels_list[i];
		char *db_val = r_panels_search_db (core, s);
		r_panels_init_panel_param (core, p, s, db_val);
		free (db_val);
	}
}

static int load_layout_saved_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_panels_prepare_layout (core);
	if (!r_core_panels_load (core, child->name)) {
		create_default_panels (core);
		r_panels_layout (core, core->panels);
	}
	r_panels_set_curnode (core, 0);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	r_panels_set_refresh_all (core, true, false);
	return 0;
}

static int load_layout_default_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_prepare_layout (core);
	r_panels_alloc (core, core->panels);
	create_default_panels (core);
	r_panels_layout (core, core->panels);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	r_panels_set_refresh_all (core, true, false);
	return 0;
}

static int close_file_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_call (core, "o-*");
	return 0;
}

static int project_open_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "Po `?i ProjectName`");
	return 0;
}

static int project_save_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_call (core, "Ps");
	return 0;
}

static int project_close_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_call (core, "Pc");
	return 0;
}

static int save_layout_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_prepare_layout (core);
	r_core_panels_save (core, NULL);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	r_panels_clear_panels_menu (core);
	r_panels_get_cur_panel (core->panels)->view->refresh = true;
	return 0;
}

static void init_menu_saved_layout(void *_core, const char *parent) {
	char *dir_path = r_panels_config_path (false);
	RList *dir = r_sys_dir (dir_path);
	RCore *core = (RCore *)_core;
	RListIter *it;
	char *entry, *entry2;
	if (dir) {
		r_list_foreach (dir, it, entry) {
			if (*entry != '.') {
				r_panels_add_menu (core, parent, entry, load_layout_saved_cb);
			}
		}
	}
	char *sysdir_path = r_panels_config_path (true);
	RList *sysdir = r_sys_dir (sysdir_path);
	if (sysdir) {
		bool found_in_home;
		// load entries from syspath
		r_list_foreach (sysdir, it, entry) {
			if (*entry != '.') {
				found_in_home = false;
				if (dir) {
					RListIter *it2;
					r_list_foreach (dir, it2, entry2) {
						if (!strcmp (entry, entry2)) {
							found_in_home = true;
							break;
						}
					}
				}
				if (!found_in_home) {
					r_panels_add_menu (core, parent, entry, load_layout_saved_cb);
				}
			}
		}
		r_list_free (sysdir);
		free (sysdir_path);
	}
	r_list_free (dir);
	free (dir_path);
}

static int clear_layout_cb(void *user) {
	RCore *core = (RCore *)user;
	if (!r_panels_show_status_yesno (core, 0, "Clear all the saved layouts? (y/n): ")) {
		return 0;
	}
	char *dir_path = r_panels_config_path (false);
	RList *dir = r_sys_dir ((const char *)dir_path);
	if (!dir) {
		free (dir_path);
		return 0;
	}
	RListIter *it;
	char *entry;
	r_list_foreach (dir, it, entry) {
		char *tmp = r_str_newf ("%s%s%s", dir_path, R_SYS_DIR, entry);
		r_file_rm (tmp);
		free (tmp);
	}
	r_file_rm (dir_path);
	r_list_free (dir);
	free (dir_path);

	r_panels_update_menu (core, "Edit.Settings.Load Layout.Saved..", init_menu_saved_layout);
	return 0;
}

static int copy_cb(void *user) {
	RCore *core = (RCore *)user;
	add_cmdf_panel (core, "How many bytes? ", "'y %s");
	return 0;
}

static int paste_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_call (core, "yy");
	return 0;
}

static int write_str_cb(void *user) {
	RCore *core = (RCore *)user;
	add_cmdf_panel (core, "insert string: ", "'w %s");
	return 0;
}

static int write_hex_cb(void *user) {
	RCore *core = (RCore *)user;
	add_cmdf_panel (core, "insert hexpairs: ", "'wx %s");
	return 0;
}

static int assemble_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_visual_asm (core, core->addr);
	return 0;
}

static int fill_cb(void *user) {
	RCore *core = (RCore *)user;
	add_cmdf_panel (core, "Fill with: ", "wow %s");
	return 0;
}

static int settings_colors_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_str_ansi_filter (child->name, NULL, NULL, -1);
	r_core_cmdf (core, "eco %s", child->name);
	int i;
	for (i = 1; i < menu->depth; i++) {
		RPanel *p = menu->history[i]->p;
		p->view->refresh = true;
		menu->refreshPanels[i - 1] = p;
	}
	r_panels_update_menu (core, "Edit.Settings.Color Themes...", init_menu_color_settings_layout);
	return 0;
}

static void config_refresh_menu(RCore *core, RPanelsMenu *menu, RPanelsMenuItem *parent) {
	free (parent->p->model->title);
	const int mi = r_panels_menu_max_items (core->panels->can, parent, parent->p->view->pos.y);
	parent->p->model->title = r_strbuf_drain (r_panels_draw_menu (core, parent, mi));
	size_t i;
	for (i = 1; i < menu->depth; i++) {
		RPanel *p = menu->history[i]->p;
		p->view->refresh = true;
		menu->refreshPanels[i - 1] = p;
	}
	if (!strcmp (parent->name, "asm")) {
		r_panels_update_menu (core, "Edit.Settings.Disassembly....asm", init_menu_disasm_asm_settings_layout);
	} else if (!strcmp (parent->name, "Screen")) {
		r_panels_update_menu (core, "Edit.Settings.Screen", init_menu_screen_settings_layout);
	}
}

static int config_value_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	RStrBuf *tmp = r_strbuf_new (child->name);
	(void)r_str_split (r_strbuf_get (tmp), ':');
	const char *v = r_panels_show_status_input (core, "New value: ");
	r_config_set (core->config, r_strbuf_get (tmp), v);
	r_strbuf_free (tmp);
	config_refresh_menu (core, menu, parent);
	return 0;
}

static int config_toggle_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	RStrBuf *tmp = r_strbuf_new (child->name);
	(void)r_str_split (r_strbuf_get (tmp), ':');
	r_config_toggle (core->config, r_strbuf_get (tmp));
	r_strbuf_free (tmp);
	config_refresh_menu (core, menu, parent);
	return 0;
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
		r_panels_add_menu (core, parent, r_strbuf_get (rsb), is_value? config_value_cb: config_toggle_cb);
	}
	r_list_free (list);
	r_strbuf_free (rsb);
}

static void init_menu_screen_settings_layout(void *_core, const char *parent) {
	r_panels_init_menu_config ((RCore *)_core, parent, menus_settings_screen, R_ARRAY_SIZE (menus_settings_screen), screen_value_items);
}

static int calculator_cb(void *user) {
	RCore *core = (RCore *)user;
	for (;;) {
		char *s = r_panels_show_status_input (core, "> ");
		if (R_STR_ISEMPTY (s)) {
			free (s);
			break;
		}
		r_cons_clear00 (core->cons);
		r_cons_printf (core->cons, "\n> %s\n", s);
		r_core_cmdf (core, "? %s", s);
		r_cons_flush (core->cons);
		free (s);
	}
	return 0;
}

static int r2_assembler_cb(void *user) {
	RCore *core = (RCore *)user;
	const int ocur = core->print->cur_enabled;
	r_core_visual_asm (core, core->addr);
	core->print->cur_enabled = ocur;
	return 0;
}

static int shell_r2_cb(void *user) {
	RCore *core = (RCore *)user;
	core->vmode = false;
	handlePrompt (core, core->panels);
	core->vmode = true;
	return 0;
}

static int shell_system_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_set_raw (core->cons, 0);
	r_cons_flush (core->cons);
	r_sys_cmd ("$SHELL");
	return 0;
}

static int shell_r2js_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_set_raw (core->cons, 0);
	r_cons_flush (core->cons);
	core->vmode = false;
	r_core_cmd0 (core, "-j");
	core->vmode = true;
	return 0;
}

static int shell_mmc_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_set_raw (core->cons, 0);
	r_cons_flush (core->cons);
	core->vmode = false;
	r_core_cmd0 (core, "mmc");
	core->vmode = true;
	return 0;
}

static int shell_fs_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_set_raw (core->cons, 0);
	r_cons_flush (core->cons);
	core->vmode = false;
	r_core_cmd0 (core, "ms");
	core->vmode = true;
	return 0;
}

static int string_whole_bin_cb(void *user) {
	RCore *core = (RCore *)user;
	add_cmdf_panel (core, "search strings in the whole binary: ", "izzq~%s");
	return 0;
}

static int string_data_sec_cb(void *user) {
	RCore *core = (RCore *)user;
	add_cmdf_panel (core, "search string in data sections: ", "izq~%s");
	return 0;
}

static int rop_cb(void *user) {
	RCore *core = (RCore *)user;
	add_cmdf_panel (core, "gadget grep: ", "'/g %s");
	return 0;
}

static int magic_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "/m");
	return 0;
}

static int code_cb(void *user) {
	RCore *core = (RCore *)user;
	add_cmdf_panel (core, "search code: ", "'/c %s");
	return 0;
}

static int hexpairs_cb(void *user) {
	RCore *core = (RCore *)user;
	add_cmdf_panel (core, "search hexpairs: ", "'/x %s");
	return 0;
}

static void esil_init(RCore *core) {
	r_core_cmd (core, "aeim", 0);
	r_core_cmd (core, "aeip", 0);
}

static void esil_step_to(RCore *core, ut64 end) {
	r_core_cmdf (core, "aesu 0x%08"PFMT64x, end);
}

static int esil_init_cb(void *user) {
	RCore *core = (RCore *)user;
	esil_init (core);
	return 0;
}

static int esil_step_to_cb(void *user) {
	RCore *core = (RCore *)user;
	char *end = r_panels_show_status_input (core, "target addr: ");
	esil_step_to (core, r_num_math (core->num, end));
	return 0;
}

static int esil_step_range_cb(void *user) {
	RStrBuf *rsb = r_strbuf_new (NULL);
	RCore *core = (RCore *)user;
	r_strbuf_append (rsb, "start addr: ");
	char *s = r_panels_show_status_input (core, r_strbuf_get (rsb));
	r_strbuf_append (rsb, s);
	r_strbuf_append (rsb, " end addr: ");
	char *d = r_panels_show_status_input (core, r_strbuf_get (rsb));
	r_strbuf_free (rsb);
	ut64 s_a = r_num_math (core->num, s);
	ut64 d_a = r_num_math (core->num, d);
	if (s_a >= d_a) {
		return 0;
	}
	ut64 tmp = core->addr;
	core->addr = s_a;
	esil_init (core);
	esil_step_to (core, d_a);
	core->addr = tmp;
	return 0;
}

static int io_cache_on_cb(void *user) {
	RCore *core = (RCore *)user;
	r_config_set_b (core->config, "io.cache", true);
	(void)r_panels_show_status (core, "io.cache is on");
	r_panels_close_menu (core);
	return 0;
}

static int io_cache_off_cb(void *user) {
	RCore *core = (RCore *)user;
	r_config_set_b (core->config, "io.cache", false);
	(void)r_panels_show_status (core, "io.cache is off");
	r_panels_close_menu (core);
	return 0;
}

static int reload_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_file_reopen_debug (core, "");
	update_disassembly_or_open (core);
	return 0;
}

static int function_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "af");
	return 0;
}

static int symbols_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aa");
	return 0;
}

static int program_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_del_menu (core);
	r_panels_refresh (core);
	r_cons_gotoxy (core->cons, 0, 3);
	r_cons_flush (core->cons);
	r_core_cmdf (core, "aaa");
	return 0;
}

static int aae_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aae");
	return 0;
}

static int aap_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aap");
	return 0;
}

static int basic_blocks_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aab");
	return 0;
}

static int calls_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aac");
	return 0;
}

static int watch_points_cb(void *user) {
	RCore *core = (RCore *)user;
	const char *addrstr = r_cons_visual_readln (core->cons, "addr: ", NULL);
	if (R_STR_ISNOTEMPTY (addrstr)) {
		ut64 addr = r_num_math (core->num, addrstr);
		const char *rw = r_cons_visual_readln (core->cons, "<r/w/rw>: ", NULL);
		if (R_STR_ISNOTEMPTY (rw)) {
			r_core_cmdf (core, "dbw 0x%08"PFMT64x" %s", addr, rw);
			return 1;
		}
	}
	// show error here or something?
	return 0;
}

static int references_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aar");
	return 0;
}

static int fortune_cb(void *user) {
	RCore *core = (RCore *)user;
	char *s = r_core_cmd_str (core, "fo");
	r_cons_message (core->cons, s);
	free (s);
	return 0;
}

static int game_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_2048 (core->cons, core->panels->can->color);
	return 0;
}

static int help_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_prepare_layout (core);
	r_panels_toggle_help (core);
	return 0;
}

static int license_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_message (core->cons, "Copyright 2006-2024 - pancake - LGPL");
	return 0;
}

static int version2_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_set_raw (core->cons, false);
	r_core_cmd0 (core, "!!r2 -Vj>$a");
	r_core_cmd0 (core, "$a~{}~..");
	r_core_cmd0 (core, "rm $a");
	r_cons_set_raw (core->cons, true);
	r_cons_flush (core->cons);
	return 0;
}

static int version_cb(void *user) {
	RCore *core = (RCore *)user;
	char *s = r_core_cmd_str (core, "?V");
	r_cons_message (core->cons, s);
	free (s);
	return 0;
}

static int r2rc_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_set_raw (core->cons, false);
	r_core_cmd0 (core, "edit");
	r_cons_set_raw (core->cons, true);
	r_cons_flush (core->cons);
	return 0;
}

static int writeValueCb(void *user) {
	RCore *core = (RCore *)user;
	char *res = r_panels_show_status_input (core, "insert number: ");
	if (res) {
		r_core_cmdf (core, "'wv %s", res);
		free (res);
	}
	return 0;
}

static int quit_cb(void *user) {
	r_panels_set_root_state ((RCore *)user, QUIT);
	return 0;
}

static int open_menu_cb(void *user) {
	RCore* core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RConsCanvas *can = core->panels->can;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	int x, y;
	if (menu->depth < 2) {
		x = r_panels_menu_bar_x (menu, menu->root->selectedIndex, can->w);
		y = MENU_Y;
	} else {
		RPanelPos *ppos = &parent->p->view->pos;
		x = ppos->x + ppos->w - 1;
		y = menu->depth == 2 ? ppos->y + parent->selectedIndex : ppos->y;
	}
	r_panels_menu_push (core, child, x, y);
	return 0;
}

static void init_menu_manpages(void *_core, const char *parent) {
	RCore *core = (RCore *)_core;
	int i;
	for (i = 0; i < R_ARRAY_SIZE (manpage_tools); i++) {
		r_panels_add_menu (core, parent, manpage_tools[i], help_manpage_cb);
	}
}

static void init_menu_color_settings_layout(void *_core, const char *parent) {
	RCore *core = (RCore *)_core;
	char *now = r_core_cmd_str (core, "eco.");
	r_str_split (now, '\n');
	parent = "Edit.Settings.Color Themes...";
	RList *list = r_panels_sorted_list (core, (const char **)core->visual.menus_Colors, R_ARRAY_SIZE (core->visual.menus_Colors));
	char *pos;
	RListIter* iter;
	RStrBuf *buf = r_strbuf_new (NULL);
	r_list_foreach (list, iter, pos) {
		if (pos && !strcmp (now, pos)) {
			r_strbuf_setf (buf, "%s%s", PANEL_HL_COLOR, pos);
			r_panels_add_menu (core, parent, r_strbuf_get (buf), settings_colors_cb);
			continue;
		}
		r_panels_add_menu (core, parent, pos, settings_colors_cb);
	}
	free (now);
	r_list_free (list);
	r_strbuf_free (buf);
}

static void init_menu_disasm_settings_layout(void *_core, const char *parent) {
	RCore *core = (RCore *)_core;
	RList *list = r_panels_sorted_list (core, menus_settings_disassembly, R_ARRAY_SIZE (menus_settings_disassembly));
	char *pos;
	RListIter* iter;
	RStrBuf *rsb = r_strbuf_new (NULL);
	r_list_foreach (list, iter, pos) {
		if (!strcmp (pos, "asm")) {
			r_panels_add_menu (core, parent, pos, open_menu_cb);
			init_menu_disasm_asm_settings_layout (core, "Edit.Settings.Disassembly....asm");
		} else {
			r_strbuf_set (rsb, pos);
			r_strbuf_append (rsb, ": ");
			r_strbuf_append (rsb, r_config_get (core->config, pos));
			r_panels_add_menu (core, parent, r_strbuf_get (rsb), config_toggle_cb);
		}
	}
	r_list_free (list);
	r_strbuf_free (rsb);
}

static void init_menu_disasm_asm_settings_layout(void *_core, const char *parent) {
	r_panels_init_menu_config ((RCore *)_core, parent, menus_settings_disassembly_asm, R_ARRAY_SIZE (menus_settings_disassembly_asm), asm_value_items);
}

static void load_config_menu(RCore *core) {
	RList *themes_list = r_core_list_themes (core);
	RListIter *th_iter;
	char *th;
	int i;
	for (i = 0; i < R_ARRAY_SIZE (core->visual.menus_Colors); i++) {
		free (core->visual.menus_Colors[i]);
		core->visual.menus_Colors[i] = NULL;
	}
	i = 0;
	r_list_foreach (themes_list, th_iter, th) {
		if (i >= R_ARRAY_SIZE (core->visual.menus_Colors)) {
			break;
		}
		core->visual.menus_Colors[i++] = strdup (th);
	}
	r_list_free (themes_list);
}

static bool init_panels_menu(RCore *core) {
	RPanels *panels = core->panels;
	RPanelsMenu *panels_menu = R_NEW0 (RPanelsMenu);
	RPanelsMenuItem *root = R_NEW0 (RPanelsMenuItem);
	panels->panels_menu = panels_menu;
	panels_menu->root = root;
	root->n_sub = 0;
	root->name = NULL;
	root->sub = NULL;

	load_config_menu (core);

	int i;
	for (i = 0; i < R_ARRAY_SIZE (menus); i++) {
		r_panels_add_menu_full (core, NULL, menus[i], menus_desc[i], NULL, open_menu_cb);
	}

	r_panels_add_menu_items (core, "File", file_items, menus_File, R_ARRAY_SIZE (menus_File), add_cmd_panel);
	r_panels_add_menu_items (core, "Edit", edit_items, menus_Edit, R_ARRAY_SIZE (menus_Edit), add_cmd_panel);
	r_panels_add_menu_items (core, "Edit.Settings", settings_items, menus_Settings, R_ARRAY_SIZE (menus_Settings), open_menu_cb);
	r_panels_add_menu_full (core, "View", "Code...", "Code and decompiler views", NULL, open_menu_cb);
	r_panels_add_menu_items (core, "View.Code...", view_items, menus_View_Code, R_ARRAY_SIZE (menus_View_Code), add_cmd_panel);
	r_panels_add_menu_full (core, "View", "Data...", "Raw data and string views", NULL, open_menu_cb);
	r_panels_add_menu_items (core, "View.Data...", view_items, menus_View_Data, R_ARRAY_SIZE (menus_View_Data), add_cmd_panel);
	r_panels_add_menu_full (core, "View", "Metadata...", "Comments, flags and types", NULL, open_menu_cb);
	r_panels_add_menu_items (core, "View.Metadata...", view_items, menus_View_Metadata, R_ARRAY_SIZE (menus_View_Metadata), add_cmd_panel);
	r_panels_add_menu_full (core, "View", "Binary...", "Binary structure, symbols and imports", NULL, open_menu_cb);
	r_panels_add_menu_items (core, "View.Binary...", view_items, menus_View_Binary, R_ARRAY_SIZE (menus_View_Binary), add_cmd_panel);
	r_panels_add_menu_full (core, "View", "Analysis...", "Functions, variables and cross references", NULL, open_menu_cb);
	r_panels_add_menu_items (core, "View.Analysis...", view_items, menus_View_Analysis, R_ARRAY_SIZE (menus_View_Analysis), add_cmd_panel);
	r_panels_add_menu_full (core, "View", "Debug...", "Registers, stack and debugger state", NULL, open_menu_cb);
	r_panels_add_menu_items (core, "View.Debug...", view_items, menus_View_Debug, R_ARRAY_SIZE (menus_View_Debug), add_cmd_panel);
	r_panels_add_menu_full (core, "View", "Other...", "Miscellaneous views", NULL, open_menu_cb);
	r_panels_add_menu_items (core, "View.Other...", view_items, menus_View_Other, R_ARRAY_SIZE (menus_View_Other), add_cmd_panel);
	r_panels_add_menu_items (core, "Tools", tools_items, menus_Tools, R_ARRAY_SIZE (menus_Tools), NULL);
	r_panels_add_menu_items (core, "Search", search_items, menus_Search, R_ARRAY_SIZE (menus_Search), NULL);
	r_panels_add_menu_full (core, "Debug", "Emulate...", "ESIL execution helpers", NULL, open_menu_cb);
	r_panels_add_menu_items_sorted (core, "Debug", debug_items, menus_Debug, R_ARRAY_SIZE (menus_Debug), add_cmd_panel);
	r_panels_add_menu_items (core, "Debug.Emulate...", emulate_items, menus_Emulate, R_ARRAY_SIZE (menus_Emulate), NULL);
	r_panels_add_menu_items (core, "Analyze", analyze_items, menus_Analyze, R_ARRAY_SIZE (menus_Analyze), NULL);
	r_panels_add_menu_items (core, "Help", help_items, menus_Help, R_ARRAY_SIZE (menus_Help), help_cb);
	r_panels_add_menu_items (core, "File.Reopen...", reopen_items, menus_ReOpen, R_ARRAY_SIZE (menus_ReOpen), NULL);
	r_panels_add_menu_items (core, "Edit.Settings.Load Layout", loadlayout_items, menus_loadLayout, R_ARRAY_SIZE (menus_loadLayout), NULL);

	init_menu_saved_layout (core, "Edit.Settings.Load Layout.Saved..");
	init_menu_color_settings_layout (core, "Edit.Settings.Color Themes...");
	init_menu_manpages (core, "Help.Manpages...");
	init_menu_anal_plugins (core, "Analyze.Plugins...");

	{
		const char *parent = "Edit.Settings.Decompiler...";
		char *opts = r_core_cmd_str (core, "e cmd.pdc=?");
		RList *optl = r_str_split_list (opts, "\n", 0);
		RListIter *iter;
		char *opt;
		r_list_foreach (optl, iter, opt) {
			r_panels_add_menu (core, parent, strdup (opt), settings_decompiler_cb);
		}
		r_list_free (optl);
		free (opts);
	}

	init_menu_disasm_settings_layout (core, "Edit.Settings.Disassembly...");
	init_menu_screen_settings_layout (core, "Edit.Settings.Screen...");
	r_panels_add_menu_items (core, "Edit.io.cache", iocache_items, menus_iocache, R_ARRAY_SIZE (menus_iocache), NULL);

	panels_menu->history = calloc (8, sizeof (RPanelsMenuItem *));
	r_panels_clear_panels_menu (core);
	panels_menu->refreshPanels = calloc (8, sizeof (RPanel *));
	return true;
}

/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

static bool r_panels_tab_menu_is_open(RPanels *panels) {
	return r_panels_frame_menu_is_open (panels) && !strcmp (panels->panels_menu->frame->name, "Tab");
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
	init_new_panels_root (core);
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

static const char *r_panels_navbar_tab_name(RPanelsRoot *root, int index, char *number, size_t number_size) {
	RPanels *panels = r_panels_get_panels (root, index);
	if (panels && R_STR_ISNOTEMPTY (panels->name)) {
		return panels->name;
	}
	snprintf (number, number_size, "Tab%d", index + 1);
	return number;
}

static void r_panels_handle_tab_nth(RCore *core, int ch) {
	ch -= '0' + 1;
	if (ch >= 0 && ch != core->panels_root->cur_panels && ch < core->panels_root->n_panels) {
		core->panels_root->cur_panels = ch;
		r_panels_set_root_state (core, ROTATE);
	}
}

static void r_panels_move_panel_to_tab(RCore *core, int dst) {
	RPanelsRoot *root = core->panels_root;
	RPanels *src = core->panels;
	RPanels *target = r_panels_get_panels (root, dst);
	if (!target || target == src || src->n_panels <= 1) {
		return;
	}
	RPanel *cur = r_panels_get_cur_panel (src);
	const int n_panels = target->n_panels;
	core->panels = target;
	r_panels_split_panel (core, r_panels_get_cur_panel (target), cur->model->title, cur->model->cmd, true);
	if (target->n_panels == n_panels) {
		core->panels = src;
		return;
	}
	r_panels_set_curnode (core, target->curnode + 1);
	r_panels_copy_panel_state (core, r_panels_get_cur_panel (target), cur);
	core->panels = src;
	r_panels_dismantle_del_panel (core, cur, src->curnode);
	root->cur_panels = dst;
	r_panels_set_root_state (core, ROTATE);
}

static void r_panels_del_panels(RCore *core) {
	RPanelsRoot *panels_root = core->panels_root;
	if (panels_root->n_panels <= 1) {
		core->panels_root->root_state = QUIT;
		return;
	}
	r_panels_free_partial (panels_root->panels[panels_root->cur_panels]);
	int i;
	for (i = panels_root->cur_panels; i < panels_root->n_panels - 1; i++) {
		panels_root->panels[i] = panels_root->panels[i + 1];
	}
	panels_root->panels[panels_root->n_panels - 1] = NULL;
	panels_root->n_panels--;
	if (panels_root->cur_panels >= panels_root->n_panels) {
		panels_root->cur_panels = panels_root->n_panels - 1;
	}
}

// appends an empty tab and leaves core->panels pointing to it, NULL and untouched on failure
static RPanels *r_panels_tab_append(RCore *core) {
	RPanelsRoot *root = core->panels_root;
	if (root->n_panels >= PANEL_NUM_LIMIT) {
		return NULL;
	}
	RPanels *panels = r_panels_new (core);
	if (!panels) {
		return NULL;
	}
	RPanels *prev = core->panels;
	core->panels = panels;
	root->panels[root->n_panels++] = panels;
	if (!init_panels_menu (core) || !r_panels_alloc (core, panels)) {
		root->panels[--root->n_panels] = NULL;
		r_panels_free_partial (panels);
		core->panels = prev;
		return NULL;
	}
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	init_all_dbs (core);
	return panels;
}

static void r_panels_tab_switch_last(RCore *core) {
	RPanelsRoot *root = core->panels_root;
	root->cur_panels = root->n_panels - 1;
	r_panels_set_root_state (core, ROTATE);
}

static void handle_tab_new_with_cur_panel(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->n_panels <= 1) {
		return;
	}
	RPanel *cur = r_panels_get_cur_panel (panels);
	RPanels *new_panels = r_panels_tab_append (core);
	if (!new_panels) {
		return;
	}
	RPanel *new_panel = r_panels_get_panel (new_panels, 0);
	r_panels_init_panel_param (core, new_panel, cur->model->title, cur->model->cmd);
	r_panels_copy_panel_state (core, new_panel, cur);
	r_panels_maximize_panel_size (new_panels);
	core->panels = panels;
	r_panels_dismantle_del_panel (core, cur, panels->curnode);
	r_panels_tab_switch_last (core);
}

static void r_panels_clone_tab(RCore *core) {
	RPanels *panels = core->panels;
	RPanels *clone = r_panels_tab_append (core);
	if (!clone) {
		return;
	}
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *src = r_panels_get_panel (panels, i);
		RPanel *dst = r_panels_get_panel (clone, i);
		r_panels_init_panel_param (core, dst, src->model->title, src->model->cmd);
		dst->view->pos = src->view->pos;
		dst->model->addr = src->model->addr;
		r_panels_copy_panel_state (core, dst, src);
	}
	clone->curnode = panels->curnode;
	core->panels = panels;
	r_panels_tab_switch_last (core);
}

static int tab_new_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_close_menu (core);
	const int n_tabs = core->panels_root->n_panels;
	r_panels_handle_tab_new (core);
	if (core->panels_root->n_panels > n_tabs) {
		r_panels_tab_switch_last (core);
	}
	return 0;
}

static int tab_clone_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_close_menu (core);
	if (core->panels->mode == PANEL_MODE_ZOOM) {
		r_panels_toggle_zoom_mode (core);
	}
	r_panels_clone_tab (core);
	return 0;
}

static int tab_rename_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_close_menu (core);
	r_panels_handle_tab_name (core);
	r_panels_set_refresh_all (core, false, false);
	return 0;
}

static int tab_close_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_close_menu (core);
	r_panels_set_root_state (core, DEL);
	return 0;
}

static int tab_next_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_close_menu (core);
	r_panels_handle_tab_next (core);
	return 0;
}

// entries are named "<n> <tab name>", n being the key that selects the tab
static int tab_goto_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	const int n = atoi (parent->sub[parent->selectedIndex]->name);
	r_panels_close_menu (core);
	r_panels_handle_tab_nth (core, '0' + n);
	return 0;
}

static int tab_prev_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_close_menu (core);
	r_panels_handle_tab_prev (core);
	return 0;
}

static void r_panels_tab_menu_add(RPanelsMenuItem *menu, const char *name, const char *desc, RPanelsMenuCallback cb) {
	RPanelsMenuItem *item = r_panels_menu_item_new (name, desc, NULL, cb);
	if (!r_panels_menu_item_append (menu, item)) {
		r_panels_free_menu_item (item);
	}
}

static void r_panels_open_tab_menu(RCore *core) {
	RPanelsRoot *root = core->panels_root;
	RConsCanvas *can = core->panels->can;
	RPanelsMenuItem *menu = r_panels_menu_item_new ("Tab", NULL, NULL, NULL);
	const bool many = root->n_panels > 1;
	if (root->n_panels < PANEL_NUM_LIMIT) {
		r_panels_tab_menu_add (menu, "New Tab", "Open a new tab with the default layout", tab_new_cb);
		r_panels_tab_menu_add (menu, "Clone", "Open a new tab with a copy of this one", tab_clone_cb);
	}
	r_panels_tab_menu_add (menu, "Rename", "Change the name of this tab", tab_rename_cb);
	if (many) {
		r_panels_tab_menu_add (menu, "Close", "Close this tab", tab_close_cb);
		r_panels_tab_menu_add (menu, "--", NULL, NULL);
		r_panels_tab_menu_add (menu, "Next", "Switch to the next tab", tab_next_cb);
		r_panels_tab_menu_add (menu, "Prev", "Switch to the previous tab", tab_prev_cb);
		r_panels_tab_menu_add (menu, "--", NULL, NULL);
		int i;
		for (i = 0; i < root->n_panels && i < 9; i++) {
			char number[16];
			const char *tab_name = r_panels_navbar_tab_name (root, i, number, sizeof (number));
			char *name = r_str_newf ("%d %s%s", i + 1, tab_name, i == root->cur_panels? " *": "");
			r_panels_tab_menu_add (menu, name, "Switch to this tab", tab_goto_cb);
			free (name);
		}
	}
	RPanelsNavLayout layout;
	r_strbuf_free (r_panels_navbar (core, can->w, &layout));
	// pop up above the selected tab, navbar columns are 1-based
	const int x = R_MAX (layout.tab_x[R_MAX (root->cur_panels, 0)] - 1, 0);
	const int y = can->h - PANEL_FOOTER_H - menu->n_sub - 2;
	r_panels_open_popup (core, menu, x, y);
}

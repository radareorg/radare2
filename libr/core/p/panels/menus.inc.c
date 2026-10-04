/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

static RPanelsMenuItem *r_panels_get_selected_menu_item(RPanels *panels) {
	RPanelsMenu *menu = panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	if (!parent || !parent->sub || parent->selectedIndex < 0 || parent->selectedIndex >= parent->n_sub) {
		return NULL;
	}
	return parent->sub[parent->selectedIndex];
}

static char *r_panels_menu_status_text(RPanelsMenuItem *item) {
	if (!item || !item->name) {
		return NULL;
	}
	if (R_STR_ISNOTEMPTY (item->args) && R_STR_ISNOTEMPTY (item->desc)) {
		return r_str_newf ("%s %s - %s", item->name, item->args, item->desc);
	}
	if (R_STR_ISNOTEMPTY (item->args)) {
		return r_str_newf ("%s %s", item->name, item->args);
	}
	if (R_STR_ISNOTEMPTY (item->desc)) {
		return r_str_newf ("%s: %s", item->name, item->desc);
	}
	return strdup (item->name);
}

static char *r_panels_menu_status_line(RPanelsMenuItem *item) {
	char *text = r_panels_menu_status_text (item);
	if (!text) {
		return NULL;
	}
	char *line = r_str_newf (" Menu: %s", text);
	free (text);
	return line;
}

static RPanelsMenuItem *r_panels_menu_item_new(const char *name, const char *desc, const char *args, RPanelsMenuCallback cb) {
	RPanelsMenuItem *item = R_NEW0 (RPanelsMenuItem);
	item->name = strdup (name);
	item->desc = R_STR_ISNOTEMPTY (desc)? strdup (desc): NULL;
	item->args = R_STR_ISNOTEMPTY (args)? strdup (args): NULL;
	item->cb = cb;
	item->p = R_NEW0 (RPanel);
	item->p->model = R_NEW0 (RPanelModel);
	item->p->view = R_NEW0 (RPanelView);
	return item;
}

static bool r_panels_menu_item_append(RPanelsMenuItem *parent, RPanelsMenuItem *item) {
	RPanelsMenuItem **sub = realloc (parent->sub, sizeof (RPanelsMenuItem *) * (parent->n_sub + 1));
	if (!sub) {
		return false;
	}
	parent->sub = sub;
	parent->sub[parent->n_sub++] = item;
	return true;
}

static void r_panels_mht_free_kv(HtPPKv *kv) {
	free (kv->key);
	// values are borrowed pointers owned by the menu tree - do not free
}

// recursively remove item and all descendants from the hashtable index
static void r_panels_mht_remove(HtPP *mht, const char *prefix, RPanelsMenuItem *item) {
	int i;
	for (i = 0; i < item->n_sub; i++) {
		RPanelsMenuItem *sub = item->sub[i];
		if (sub && sub->name && strcmp (sub->name, "--")) {
			r_strf_var (key, 256, "%s.%s", prefix, sub->name);
			r_panels_mht_remove (mht, key, sub);
			ht_pp_delete (mht, key);
		}
	}
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
	r_panels_menu_bar_range (menu->root, index, canw - 4, &first, &last);
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

static inline bool r_panels_menu_is_separator(const char *name) {
	return name && name[0] == '-';
}

// move selectedIndex by `dir` (+1/-1), skipping separators; clamps at both ends
static void r_panels_menu_move(RPanelsMenuItem *parent, int dir) {
	int next = parent->selectedIndex + dir;
	while (next >= 0 && next < parent->n_sub && r_panels_menu_is_separator (parent->sub[next]->name)) {
		next += dir;
	}
	if (next >= 0 && next < parent->n_sub) {
		parent->selectedIndex = next;
	}
}

// append a horizontal rule of `width` columns, box-drawing when scr.utf8 is set
static void r_panels_menu_hline(RCore *core, RStrBuf *buf, int width) {
	width = R_MAX (width, 1);
	if (!r_config_get_b (core->config, "scr.utf8")) {
		r_strbuf_pad (buf, '-', width);
		return;
	}
	int i;
	for (i = 0; i < width; i++) {
		r_strbuf_append (buf, RUNE_LINE_HORIZ);
	}
}

static int r_panels_menu_max_items(RConsCanvas *can, RPanelsMenuItem *item, int y) {
	return R_MAX (can->h - PANEL_FOOTER_H - y - 2, 3);
}

// entries first..last are shown, with a "(...)" row above or below when the list is scrolled
static void r_panels_menu_visible_range(RPanelsMenuItem *item, int max_items, int *first, int *last, bool *top_ell, bool *bot_ell) {
	const int n = item->n_sub;
	*first = 0;
	*last = n - 1;
	*top_ell = *bot_ell = false;
	if (max_items <= 2 || n <= max_items) {
		return;
	}
	*first = R_MAX (item->selectedIndex - max_items / 2, 0);
	*last = *first + max_items - 1;
	if (*last >= n) {
		*last = n - 1;
		*first = R_MAX (0, *last - max_items + 1);
	}
	*top_ell = *first > 0;
	*bot_ell = *last < n - 1;
	if (*top_ell) {
		(*first)++;
	}
	if (*bot_ell) {
		(*last)--;
	}
}

static RStrBuf *r_panels_draw_menu(RCore *core, RPanelsMenuItem *item, int max_items) {
	RStrBuf *buf = r_strbuf_new (NULL);
	if (!buf) {
		return NULL;
	}
	int i, first, last;
	bool top_ell, bot_ell;
	r_panels_menu_visible_range (item, max_items, &first, &last, &top_ell, &bot_ell);
	// widest visible line: "  " + name + "          "; ellipsis rows are 5 wide
	int content_w = top_ell || bot_ell? 5: 0;
	for (i = first; i <= last; i++) {
		const char *name = item->sub[i]->name;
		if (!r_panels_menu_is_separator (name)) {
			content_w = R_MAX (content_w, r_str_ansi_len (name));
		}
	}
	if (top_ell) {
		r_strbuf_append (buf, "  (...)          \n");
	}
	for (i = first; i <= last; i++) {
		const char *name = item->sub[i]->name;
		if (r_panels_menu_is_separator (name)) {
			r_strbuf_append (buf, Color_WHITE);
			r_panels_menu_hline (core, buf, content_w + 8);
			r_strbuf_append (buf, Color_RESET"\n");
			continue;
		}
		if (i == item->selectedIndex) {
			r_strbuf_appendf (buf, "%s> %s"Color_RESET, PANEL_HL_COLOR, name);
		} else {
			r_strbuf_appendf (buf, "  %s", name);
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
	const int max_items = r_panels_menu_max_items (can, parent, p->view->pos.y);
	RStrBuf *buf = r_panels_draw_menu (core, parent, max_items);
	if (!buf) {
		return;
	}
	free (p->model->title);
	p->model->title = r_strbuf_drain (buf);
	p->view->pos.w = r_str_bounds (p->model->title, &p->view->pos.h);
	p->view->pos.h += 2;
	if (p->view->pos.y + p->view->pos.h > can->h - PANEL_FOOTER_H) {
		p->view->pos.h = can->h - PANEL_FOOTER_H - p->view->pos.y;
	}
	p->model->type = PANEL_TYPE_MENU;
	p->view->refresh = true;
	if (menu->n_refresh > 0) {
		menu->refreshPanels[menu->n_refresh - 1] = p;
	}
}

// index of the entry drawn at canvas cell x,y; -1 outside the dropdown, -2 inside but not on an entry
static int r_panels_menu_item_at(RCore *core, RPanelsMenuItem *item, int x, int y) {
	const RPanelPos *pos = &item->p->view->pos;
	if (x < pos->x || x >= pos->x + pos->w || y < pos->y || y >= pos->y + pos->h) {
		return -1;
	}
	const int max_items = r_panels_menu_max_items (core->panels->can, item, pos->y);
	int first, last;
	bool top_ell, bot_ell;
	r_panels_menu_visible_range (item, max_items, &first, &last, &top_ell, &bot_ell);
	// entries are printed from the first row inside the box border
	const int idx = first + y - pos->y - 1 - (top_ell? 1: 0);
	const bool on_border = x == pos->x || x == pos->x + pos->w - 1;
	if (on_border || idx < first || idx > last || r_panels_menu_is_separator (item->sub[idx]->name)) {
		return -2;
	}
	return idx;
}

static void r_panels_menu_push(RCore *core, RPanelsMenuItem *item, int x, int y) {
	RPanelsMenu *menu = core->panels->panels_menu;
	RConsCanvas *can = core->panels->can;
	y = R_MAX (0, R_MIN (y, can->h - PANEL_FOOTER_H - 1));
	RStrBuf *buf = r_panels_draw_menu (core, item, r_panels_menu_max_items (can, item, y));
	if (!buf) {
		return;
	}
	RPanel *p = item->p;
	RPanelPos *pos = &p->view->pos;
	free (p->model->title);
	p->model->title = r_strbuf_drain (buf);
	pos->w = r_str_bounds (p->model->title, &pos->h);
	pos->h += 2;
	if (y + pos->h > can->h - PANEL_FOOTER_H) {
		pos->h = can->h - PANEL_FOOTER_H - y;
	}
	if (x + pos->w > can->w) {
		x = R_MAX (0, can->w - pos->w);
	}
	r_panels_set_pos (pos, x, y);
	p->model->type = PANEL_TYPE_MENU;
	p->view->refresh = true;
	menu->refreshPanels[menu->n_refresh++] = p;
	menu->history[menu->depth++] = item;
}

static int frame_maximize_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_close_menu (core);
	r_panels_toggle_zoom_mode (core);
	return 0;
}

static int frame_contents_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_close_menu (core);
	r_panels_set_refresh_all (core, false, false);
	r_panels_refresh (core);
	r_cons_switchbuf (core->cons, false);
	r_panels_create_modal (core, r_panels_get_cur_panel (core->panels));
	return 0;
}

static int frame_cache_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_toggle_cache (core, r_panels_get_cur_panel (core->panels));
	r_panels_frame_menu_update (core);
	return 0;
}

static void r_panels_frame_split(RCore *core, bool vertical) {
	RPanels *panels = core->panels;
	r_panels_close_menu (core);
	if (panels->mode == PANEL_MODE_ZOOM) {
		r_panels_toggle_zoom_mode (core);
	}
	RPanel *cur = r_panels_get_cur_panel (panels);
	r_panels_split_panel (core, cur, cur->model->title, cur->model->cmd, vertical);
}

static int frame_split_horizontal_cb(void *user) {
	r_panels_frame_split ((RCore *)user, false);
	return 0;
}

static int frame_split_vertical_cb(void *user) {
	r_panels_frame_split ((RCore *)user, true);
	return 0;
}

static int frame_close_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	r_panels_close_menu (core);
	if (panels->mode == PANEL_MODE_ZOOM) {
		r_panels_toggle_zoom_mode (core);
	}
	r_panels_dismantle_del_panel (core, r_panels_get_cur_panel (panels), panels->curnode);
	return 0;
}

static void r_panels_copy_panel_state(RCore *core, RPanel *dst, RPanel *src) {
	dst->model->cache = src->model->cache;
	free (dst->model->funcName);
	dst->model->funcName = src->model->funcName? strdup (src->model->funcName): NULL;
	r_panels_set_cmd_str_cache (core, dst, src->model->cmdStrCache);
}

static int frame_move_menu_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	if (parent->sub[parent->selectedIndex]->sub) {
		open_menu_cb (core);
	}
	return 0;
}

static int frame_move_tab_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanelsMenu *menu = panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	const char *args = parent->sub[parent->selectedIndex]->args;
	const int dst = args? atoi (args): -1;
	r_panels_close_menu (core);
	if (panels->mode == PANEL_MODE_ZOOM) {
		r_panels_toggle_zoom_mode (core);
	}
	if (dst < 0) {
		handle_tab_new_with_cur_panel (core);
	} else {
		r_panels_move_panel_to_tab (core, dst);
	}
	return 0;
}

// one entry per other tab plus a new tab, empty when the panel is the only one in this tab
static void r_panels_frame_move_menu_fill(RCore *core, RPanelsMenuItem *item) {
	RPanelsRoot *root = core->panels_root;
	if (core->panels->n_panels <= 1) {
		return;
	}
	int i;
	for (i = 0; i < root->n_panels; i++) {
		if (i == root->cur_panels) {
			continue;
		}
		char number[16];
		char *args = r_str_newf ("%d", i);
		const char *name = r_panels_navbar_tab_name (root, i, number, sizeof (number));
		RPanelsMenuItem *sub = r_panels_menu_item_new (name, "Move this panel into that tab", args, frame_move_tab_cb);
		free (args);
		if (!r_panels_menu_item_append (item, sub)) {
			r_panels_free_menu_item (sub);
			return;
		}
	}
	if (root->n_panels < PANEL_NUM_LIMIT) {
		RPanelsMenuItem *sub = r_panels_menu_item_new ("New tab", "Move this panel into a new tab", NULL, frame_move_tab_cb);
		if (!r_panels_menu_item_append (item, sub)) {
			r_panels_free_menu_item (sub);
		}
	}
}

static bool frame_maximize_state(RCore *core, RPanel *panel) {
	RPanels *panels = core->panels;
	return panels->mode == PANEL_MODE_ZOOM || (panels->mode == PANEL_MODE_MENU && panels->frame_mode == PANEL_MODE_ZOOM);
}

static bool frame_cache_state(RCore *core, RPanel *panel) {
	return panel->model->cache;
}

static char *r_panels_frame_action_name(RCore *core, RPanel *panel, const FrameMenuAction *action) {
	return action->state
		? r_str_newf ("%s (%s)", action->name, action->state (core, panel)? "on": "off")
		: strdup (action->name);
}

static RPanelsMenuItem *r_panels_frame_menu_new(RCore *core, RPanel *panel) {
	RPanelsMenuItem *frame = r_panels_menu_item_new ("Frame", NULL, NULL, NULL);
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (frame_menu_actions); i++) {
		const FrameMenuAction *action = &frame_menu_actions[i];
		char *name = r_panels_frame_action_name (core, panel, action);
		RPanelsMenuItem *item = r_panels_menu_item_new (name, action->desc, NULL, action->cb);
		free (name);
		if (action->cb == frame_move_menu_cb) {
			r_panels_frame_move_menu_fill (core, item);
		}
		if (!r_panels_menu_item_append (frame, item)) {
			r_panels_free_menu_item (item);
			break;
		}
	}
	return frame;
}

// refresh the (on)/(off) labels after an action that keeps the menu open
static void r_panels_frame_menu_update(RCore *core) {
	RPanels *panels = core->panels;
	RPanelsMenuItem *frame = panels->panels_menu->frame;
	RPanel *cur = r_panels_get_cur_panel (panels);
	int i;
	for (i = 0; i < frame->n_sub; i++) {
		free (frame->sub[i]->name);
		frame->sub[i]->name = r_panels_frame_action_name (core, cur, &frame_menu_actions[i]);
	}
	r_panels_update_menu_contents (core, panels->panels_menu, frame);
}

// contextual menus (panel frame, tab) share the frame slot of the menu
static void r_panels_open_popup(RCore *core, RPanelsMenuItem *item, int x, int y) {
	RPanels *panels = core->panels;
	RPanelsMenu *menu = panels->panels_menu;
	r_panels_set_mode (core, PANEL_MODE_MENU);
	r_panels_clear_panels_menu (core);
	r_panels_free_menu_item (menu->frame);
	menu->frame = item;
	r_panels_menu_push (core, item, x, y);
	r_panels_set_refresh_all (core, false, false);
}

static void r_panels_open_frame_menu(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (!cur) {
		return;
	}
	// drop down below the [=] button, which sits at the left of the title row
	r_panels_open_popup (core, r_panels_frame_menu_new (core, cur), cur->view->pos.x + 1, cur->view->pos.y + 2);
}

static void r_panels_update_menu(RCore *core, const char *parent, R_NULLABLE RPanelMenuUpdateCallback cb) {
	RPanels *panels = core->panels;
	void *addr = ht_pp_find (panels->mht, parent, NULL);
	RPanelsMenuItem *p_item = (RPanelsMenuItem *)addr;
	// remove all descendants from the hashtable index, then free the items
	r_panels_mht_remove (panels->mht, parent, p_item);
	int i;
	for (i = 0; i < p_item->n_sub; i++) {
		r_panels_free_menu_item (p_item->sub[i]);
	}
	free (p_item->sub);
	p_item->sub = NULL;
	p_item->n_sub = 0;
	if (cb) {
		cb (core, parent);
	}
	RPanelsMenu *menu = panels->panels_menu;
	r_panels_update_menu_contents (core, menu, p_item);
}

static void r_panels_set_menu_item_desc(RPanelsMenuItem *item, const char *desc) {
	if (!item) {
		return;
	}
	free (item->desc);
	item->desc = R_STR_ISNOTEMPTY (desc)? strdup (desc): NULL;
}

static void r_panels_set_menu_item_args(RPanelsMenuItem *item, const char *args) {
	if (!item) {
		return;
	}
	free (item->args);
	item->args = R_STR_ISNOTEMPTY (args)? strdup (args): NULL;
}

static void r_panels_add_menu_full(RCore *core, const char *parent, const char *name,
		const char *desc, const char *args, RPanelsMenuCallback cb) {
	RPanels *panels = core->panels;
	RPanelsMenuItem *p_item;
	char *key;
	const bool add_to_ht = strcmp (name, "--");
	if (parent) {
		void *addr = ht_pp_find (panels->mht, parent, NULL);
		p_item = (RPanelsMenuItem *)addr;
		key = add_to_ht? r_str_newf ("%s.%s", parent, name): NULL;
	} else {
		p_item = panels->panels_menu->root;
		key = add_to_ht? strdup (name): NULL;
	}
	if (add_to_ht && !key) {
		return;
	}
	if (!p_item) {
		R_LOG_WARN ("Cannot find panel %s", parent);
		free (key);
		return;
	}
	if (add_to_ht) {
		void *addr = ht_pp_find (panels->mht, key, NULL);
		if (addr) {
			RPanelsMenuItem *existing = (RPanelsMenuItem *)addr;
			r_panels_set_menu_item_desc (existing, desc);
			r_panels_set_menu_item_args (existing, args);
			if (cb) {
				existing->cb = cb;
			}
			free (key);
			return;
		}
	}
	RPanelsMenuItem *item = r_panels_menu_item_new (name, desc, args, cb);
	if (r_panels_menu_item_append (p_item, item)) {
		if (add_to_ht) {
			ht_pp_insert (panels->mht, key, item);
		}
		item = NULL;
		key = NULL;
	}
	free (key);
	r_panels_free_menu_item (item);
}

static void r_panels_add_menu(RCore *core, const char *parent, const char *name, RPanelsMenuCallback cb) {
	r_panels_add_menu_full (core, parent, name, NULL, NULL, cb);
}

static int r_panels_cmpstr(const void *_a, const void *_b) {
	char *a = (char *)_a, *b = (char *)_b;
	return strcmp (a, b);
}

static int r_panels_cmp_plugin_menu_entry(const void *_a, const void *_b) {
	const AnalPluginMenuEntry *a = _a;
	const AnalPluginMenuEntry *b = _b;
	return strcmp (a->name, b->name);
}

static void r_panels_free_plugin_menu_entry(void *p) {
	AnalPluginMenuEntry *entry = (AnalPluginMenuEntry *)p;
	if (!entry) {
		return;
	}
	free (entry->name);
	free (entry->desc);
	free (entry->args);
	free (entry);
}

static bool r_panels_is_blank_char(char ch) {
	return ch == ' ' || ch == '\t';
}

static bool r_panels_parse_anal_plugin_line(const char *line, char **out_name, char **out_desc, char **out_args) {
	*out_name = NULL;
	*out_desc = NULL;
	*out_args = NULL;
	if (R_STR_ISEMPTY (line)) {
		return false;
	}
	char *trimmed = r_str_trim_dup (line);
	if (R_STR_ISEMPTY (trimmed)) {
		free (trimmed);
		return false;
	}
	char *s = trimmed;
	if (*s == '|') {
		s = (char *)r_str_trim_head_ro (s + 1);
	} else if (r_str_startswith (s, "Usage:")) {
		s = (char *)r_str_trim_head_ro (s + strlen ("Usage:"));
	}
	if (*s != 'a') {
		free (trimmed);
		return false;
	}
	char *end = s;
	while (*end && !r_panels_is_blank_char (*end) && *end != '[' && *end != '<') {
		end++;
	}
	if (end == s) {
		free (trimmed);
		return false;
	}
	char saved = *end;
	*end = 0;
	*out_name = strdup (s);
	*end = saved;
	if (!*out_name) {
		free (trimmed);
		return false;
	}
	char *rest = (char *)r_str_trim_head_ro (end);
	RStrBuf *args = r_strbuf_new (NULL);
	if (!args) {
		free (*out_name);
		*out_name = NULL;
		free (trimmed);
		return false;
	}
	while (*rest == '[' || *rest == '<') {
		const char closech = *rest == '[' ? ']' : '>';
		char *close = strchr (rest, closech);
		if (!close) {
			break;
		}
		char *arg = R_STR_NDUP (rest, (int)(close - rest) + 1);
		if (R_STR_ISNOTEMPTY (arg)) {
			if (r_strbuf_length (args) > 0) {
				r_strbuf_append (args, " ");
			}
			r_strbuf_append (args, arg);
		}
		free (arg);
		rest = (char *)r_str_trim_head_ro (close + 1);
	}
	if (*rest == '-') {
		rest = (char *)r_str_trim_head_ro (rest + 1);
	}
	if (R_STR_ISNOTEMPTY (rest)) {
		*out_desc = strdup (rest);
	}
	char *argstr = r_strbuf_drain (args);
	if (R_STR_ISNOTEMPTY (argstr)) {
		*out_args = argstr;
	} else {
		free (argstr);
	}
	free (trimmed);
	return true;
}

static AnalPluginMenuEntry *r_panels_find_plugin_menu_entry(RList *list, const char *name) {
	RListIter *iter;
	AnalPluginMenuEntry *entry;
	r_list_foreach (list, iter, entry) {
		if (!strcmp (entry->name, name)) {
			return entry;
		}
	}
	return NULL;
}

static void r_panels_merge_plugin_menu_entry(AnalPluginMenuEntry *entry, const char *desc, const char *args) {
	if (!entry) {
		return;
	}
	if (R_STR_ISNOTEMPTY (args) && R_STR_ISEMPTY (entry->args)) {
		entry->args = strdup (args);
	}
	if (R_STR_ISEMPTY (desc)) {
		return;
	}
	if (R_STR_ISEMPTY (entry->desc)) {
		entry->desc = strdup (desc);
		return;
	}
	if (!strstr (entry->desc, desc)) {
		char *merged = r_str_newf ("%s; %s", entry->desc, desc);
		free (entry->desc);
		entry->desc = merged;
	}
}

static char *r_panels_menu_fallback_desc(RCore *core, const char *name, RPanelsMenuCallback cb, const char *desc) {
	if (R_STR_ISNOTEMPTY (desc)) {
		return strdup (desc);
	}
	if (cb == open_menu_cb) {
		return r_str_newf ("Open %s submenu", name);
	}
	return r_panels_search_db (core, name);
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

static const MenuItem *r_panels_find_menu_item(const MenuItem *items, const char *name) {
	int i;
	for (i = 0; items && items[i].name; i++) {
		if (!strcmp (name, items[i].name)) {
			return &items[i];
		}
	}
	return NULL;
}

static char *r_panels_prompt_menu_args(RCore *core, const RPanelsMenuItem *item) {
	if (!item || !item->name) {
		return NULL;
	}
	RStrBuf *buf = r_strbuf_new (item->name);
	if (!buf) {
		return NULL;
	}
	const char *args = item->args;
	while (R_STR_ISNOTEMPTY (args)) {
		const char *open = strchr (args, '[');
		if (!open) {
			break;
		}
		const char *close = strchr (open + 1, ']');
		if (!close) {
			break;
		}
		char *label = R_STR_NDUP (open + 1, (int)(close - open) - 1);
		if (!label) {
			break;
		}
		char *prompt = r_str_newf ("%s %s: ", item->name, label);
		char *value = r_panels_show_status_input (core, prompt);
		free (prompt);
		free (label);
		if (!value) {
			r_strbuf_free (buf);
			return NULL;
		}
		if (R_STR_ISEMPTY (value)) {
			free (value);
			break;
		}
		r_strbuf_append (buf, " ");
		r_strbuf_append (buf, value);
		free (value);
		args = close + 1;
	}
	return r_strbuf_drain (buf);
}

static int anal_plugins_cb(void *user) {
	RCore *core = (RCore *)user;
	if (!r_panels_check_panel_num (core)) {
		return 0;
	}
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	char *cmd = R_STR_ISNOTEMPTY (child->args)
		? r_panels_prompt_menu_args (core, child)
		: strdup (child->name);
	if (!cmd) {
		return 0;
	}
	r_panels_adjust_and_add_panel (core, child->name, cmd);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	free (cmd);
	menu->n_refresh = 0;
	return 0;
}

static void init_menu_anal_plugins(void *_core, const char *parent) {
	RCore *core = (RCore *)_core;
	RList *entries = r_list_newf (r_panels_free_plugin_menu_entry);
	if (!entries) {
		return;
	}
	RListIter *iter;
	RAnalPlugin *ap;
	r_list_foreach (core->anal->libstore->plugins, iter, ap) {
		if (!ap->cmd) {
			continue;
		}
		char *help = r_core_cmd_strf (core, "a:%s?", ap->meta.name);
		if (!help) {
			continue;
		}
		RList *lines = r_str_split_list (help, "\n", 0);
		if (!lines) {
			free (help);
			continue;
		}
		RListIter *line_iter;
		char *line;
		bool found = false;
		r_list_foreach (lines, line_iter, line) {
			char *name = NULL, *desc = NULL, *args = NULL;
			if (!r_panels_parse_anal_plugin_line (line, &name, &desc, &args)) {
				continue;
			}
			if (R_STR_ISEMPTY (desc) && R_STR_ISNOTEMPTY (ap->meta.desc)) {
				desc = strdup (ap->meta.desc);
			}
			AnalPluginMenuEntry *entry = r_panels_find_plugin_menu_entry (entries, name);
			if (!entry) {
				entry = R_NEW0 (AnalPluginMenuEntry);
				entry->name = name;
				entry->desc = desc;
				entry->args = args;
				r_list_append (entries, entry);
				name = desc = args = NULL;
			} else {
				r_panels_merge_plugin_menu_entry (entry, desc, args);
			}
			free (name);
			free (desc);
			free (args);
			found = true;
		}
		if (!found) {
			AnalPluginMenuEntry *entry = R_NEW0 (AnalPluginMenuEntry);
			entry->name = r_str_newf ("a:%s", ap->meta.name);
			entry->desc = R_STR_ISNOTEMPTY (ap->meta.desc)? strdup (ap->meta.desc): strdup ("analysis plugin command");
			r_list_append (entries, entry);
		}
		r_list_free (lines);
		free (help);
	}
	r_list_sort (entries, r_panels_cmp_plugin_menu_entry);
	AnalPluginMenuEntry *entry;
	r_list_foreach (entries, iter, entry) {
		r_panels_add_menu_full (core, parent, entry->name, entry->desc, entry->args, anal_plugins_cb);
	}
	r_list_free (entries);
}

static void r_panels_add_menu_items(RCore *core, const char *parent,
		const MenuItem *items, const char **menu_list, int count, RPanelsMenuCallback default_cb) {
	int i;
	for (i = 0; i < count; i++) {
		const char *name = menu_list[i];
		if (*name == '-') {
			r_panels_add_menu (core, parent, name, r_panels_separator);
			continue;
		}
		const MenuItem *item = r_panels_find_menu_item (items, name);
		RPanelsMenuCallback cb = item? item->cb: NULL;
		RPanelsMenuCallback final_cb = cb? cb: (default_cb? default_cb: add_cmd_panel);
		char *desc = r_panels_menu_fallback_desc (core, name, final_cb, item? item->desc: NULL);
		r_panels_add_menu_full (core, parent, name, desc, NULL, final_cb);
		free (desc);
	}
}

static void r_panels_add_menu_items_sorted(RCore *core, const char *parent,
		const MenuItem *items, const char **menu_list, int count, RPanelsMenuCallback default_cb) {
	RList *list = r_panels_sorted_list (core, menu_list, count);
	char *pos;
	RListIter *iter;
	r_list_foreach (list, iter, pos) {
		const MenuItem *item = r_panels_find_menu_item (items, pos);
		RPanelsMenuCallback cb = item? item->cb: NULL;
		RPanelsMenuCallback final_cb = cb? cb: (default_cb? default_cb: add_cmd_panel);
		char *desc = r_panels_menu_fallback_desc (core, pos, final_cb, item? item->desc: NULL);
		r_panels_add_menu_full (core, parent, pos, desc, NULL, final_cb);
		free (desc);
	}
	r_list_free (list);
}

static void handle_menu(RCore *core, const int key) {
	RPanels *panels = core->panels;
	RPanelsMenu *menu = panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	if (!parent || !parent->sub) {
		r_panels_close_menu (core);
		r_panels_set_refresh_all (core, true, false);
		return;
	}
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_cons_switchbuf (core->cons, false);
	if (r_panels_frame_menu_is_open (panels)) {
		switch (key) {
		case 'j':
		case 'k':
		case ' ':
		case '\r':
		case '\n':
			break;
		case 'l':
			if (child->sub) {
				(void)(child->cb (core));
			}
			return;
		case 'h':
		case 'q':
			if (menu->depth > 2) {
				r_panels_del_menu (core);
				return;
			}
			// fallthrough
		case 'm':
		case 'Q':
		case '=':
		case -1:
			r_panels_close_menu (core);
			return;
		default: // mouse presses arrive as key 0, keep the menu open for the release
			if (key >= '1' && key <= '9' && r_panels_tab_menu_is_open (panels)) {
				r_panels_close_menu (core);
				r_panels_handle_tab_nth (core, key);
			}
			return;
		}
	}
	switch (key) {
	case 'h':
		if (menu->depth <= 2) {
			menu->n_refresh = 0;
			if (menu->root->selectedIndex > 0) {
				menu->root->selectedIndex--;
			} else {
				menu->root->selectedIndex = menu->root->n_sub - 1;
			}
			if (menu->depth == 2) {
				menu->depth = 1;
				(void)(menu->root->sub[menu->root->selectedIndex]->cb (core));
			}
		} else {
			r_panels_del_menu (core);
		}
		break;
	case 'j':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y++;
		} else {
			if (menu->depth == 1) {
				(void)(child->cb (core));
			} else {
				r_panels_menu_move (parent, 1);
				r_panels_update_menu_contents (core, menu, parent);
			}
		}
		break;
	case 'k':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y--;
		} else {
			if (menu->depth < 2) {
				break;
			}
			RPanelsMenuItem *parent = menu->history[menu->depth - 1];
			int prev = parent->selectedIndex;
			r_panels_menu_move (parent, -1);
			if (parent->selectedIndex != prev) {
				r_panels_update_menu_contents (core, menu, parent);
			}
		}
		break;
	case 'l':
		if (menu->depth == 1) {
			menu->root->selectedIndex++;
			menu->root->selectedIndex %= menu->root->n_sub;
		} else if (parent->sub[parent->selectedIndex]->sub) {
			(void)(parent->sub[parent->selectedIndex]->cb (core));
		} else {
			menu->n_refresh = 0;
			menu->root->selectedIndex++;
			menu->root->selectedIndex %= menu->root->n_sub;
			menu->depth = 1;
			(void)(menu->root->sub[menu->root->selectedIndex]->cb (core));
		}
		break;
	case 'm':
	case 'q':
	case 'Q':
	case -1:
		if (panels->panels_menu->depth > 1) {
			r_panels_del_menu (core);
		} else {
			r_panels_close_menu (core);
		}
		break;
	case '$':
		r_core_call (core, "dr PC=$$");
		break;
	case ' ':
	case '\r':
	case '\n':
		(void)(child->cb (core));
		break;
	case 9:
	case 'Z':
		r_panels_close_menu (core);
		if (panels->mode == PANEL_MODE_ZOOM) {
			r_panels_handle_zoom_mode (core, key);
		} else {
			r_panels_handle_tab_key (core, key == 'Z');
		}
		break;
	case ':':
		menu->n_refresh = 0;
		handlePrompt (core, panels);
		break;
	case '?':
		r_panels_prepare_layout (core);
		r_panels_toggle_help (core);
		break;
	case '"':
		r_panels_prepare_layout (core);
		r_panels_create_modal (core, r_panels_get_panel (panels, 0));
		r_panels_set_mode (core, PANEL_MODE_DEFAULT);
		break;
	}
}

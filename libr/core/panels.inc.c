#if R_INCLUDE_BEGIN

static void set_dcb(RCore *core, RPanel *p);
static void set_pcb(RPanel *p);
static void r_panels_refresh(RCore *core);
static void init_new_panels_root(RCore *core);
static void replace_cmd(RCore *core, const char *title, const char *cmd);
static void create_panel_input(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title);
static void insert_value(RCore *core, int wat);
static void cursor_del_breakpoints(RCore *core, RPanel *panel);
static void handle_refs(RCore *core, RPanel *panel, ut64 tmp);
static void jmp_to_cursor_addr(RCore *core, RPanel *panel);
static void set_breakpoints_on_cursor(RCore *core, RPanel *panel);
static void set_addr_by_type(RCore *core, const char *cmd, ut64 addr);
static bool init_panels_menu(RCore *core);
static void init_menu_color_settings_layout(void *core, const char *parent);
static void init_menu_disasm_asm_settings_layout(void *_core, const char *parent);
static void init_menu_screen_settings_layout(void *_core, const char *parent);
static int open_menu_cb(void *user);
static int anal_plugins_cb(void *user);

typedef int Direction;

typedef struct {
	const char *name;
	const char *desc;
	RPanelsMenuCallback cb;
} MenuItem;

typedef struct {
	char *name;
	char *desc;
	char *args;
} AnalPluginMenuEntry;

// clang-format off

static const char *panels_dynamic[] = {
	"Disassembly", "Stack", "Registers"
};

static const char *panels_static[] = {
	"Disassembly", "Functions", "Symbols"
};

static const char *menus[] = {
	"File", "Settings", "Edit", "View", "Tools", "Search", "Emulate", "Debug", "Analyze", "Help"
};

static const char *menus_desc[] = {
	"File and project operations",
	"Configuration, themes and layouts",
	"Clipboard and write operations",
	"Open analysis and data views",
	"Tools, shells and file manager",
	"String, code and pattern searches",
	"ESIL execution helpers",
	"Debugger views and actions",
	"Core analysis actions and plugin commands",
	"Help, versions and manpages"
};

static const char *menus_File[] = {
	"New", "Open File", "Reopen...", "Close File", "--", "Open Project", "Save Project", "Close Project", "--", "Quit"
};

static const char *menus_Settings[] = {
	"Edit radare2rc", "--", "Color Themes...", "Decompiler...", "Disassembly...", "Screen...", "--",
	"Save Layout", "Load Layout", "Clear Saved Layouts"
};

static const char *menus_ReOpen[] = {
	"In Read+Write", "In Debugger"
};

static const char *menus_loadLayout[] = {
	"Saved..", "Default"
};

static const char *menus_Edit[] = {
	"Copy", "Paste", "Clipboard", "Write String", "Write Hex", "Write Value", "Assemble", "Fill", "io.cache"
};

static const char *menus_iocache[] = {
	"On", "Off"
};

static const char *menus_View[] = {
	"Console", "Hexdump", "Disassembly", "Disassemble Summary", "Decompiler", "Decompiler With Offsets",
	"Graph", "Tiny Graph",
	"Functions", "Function Calls", "Sections", "Segments", "Strings in data sections", "Strings in the whole bin",
	"Symbols", "Imports",
	"Info", "Database",  "Breakpoints", "Comments", "Classes", "Entropy", "Entropy Fire", "Xrefs Here", "Methods",
	"Var READ address", "Var WRITE address", "Summary", "Relocs", "Headers", "File Hashes", "Show All Decompiler Output"
};

static const char *menus_Tools[] = {
	"Calculator", "Assembler",
	"--",
	"R2 Shell", "System Shell", "FSMount Shell", "R2JS Shell",
	"--",
	"File Manager"
};

static const char *menus_Search[] = {
	"String (Whole Bin)", "String (Data Sections)", "Magic", "ROP", "Code", "Hexpairs"
};

static const char *menus_Emulate[] = {
	"Step From", "Step To", "Step Range"
};

static const char *menus_Debug[] = {
	"Registers", "Bit Registers", "FPU Registers", "XMM Registers", "YMM Registers", "RegisterRefs", "RegisterCols",
	"DRX", "Breakpoints", "Watchpoints",
	"Maps", "Modules", "Backtrace", "Locals", "Continue",
	"Stack", "Step", "Step Over", "Reload"
};

static const char *menus_Analyze[] = {
	"Function", "Symbols", "Program", "BasicBlocks", "Calls", "Preludes", "References", "Plugins..."
};

static const char *menus_settings_disassembly[] = {
	"asm", "hex.section", "io.cache", "hex.pairs", "emu.str"
};

static const char *menus_settings_disassembly_asm[] = {
	"asm.bytes", "asm.section", "asm.cmt.right", "asm.emu", "asm.var.summary",
	"asm.pseudo", "asm.flags.inbytes", "asm.arch", "asm.bits", "asm.cpu"
};

static const char *menus_settings_screen[] = {
	"scr.bgfill", "scr.color", "scr.utf8", "scr.utf8.curvy", "scr.wheel"
};

static const char *menus_Help[] = {
	"Toggle Help",
	"Manpages...",
	"--",
	"License", "Version", "Full Version",
	"--",
	"Fortune", "2048"
};

static const char *entropy_rotate[] = {
	"", "2", "b", "c", "d", "e", "F", "i", "j", "m", "p", "s", "z", "0"
};

static char *hexdump_rotate[] = {
	"xc", "pxa", "pxr", "prx", "pxb", "pxh", "pxw", "pxq", "pxd", "pxr"
};

static const char *register_rotate[] = {
	"", "=", "r", "??", "C", "i", "o"
};

static const char *function_rotate[] = {
	"l", "i", "x"
};

static const char *cache_white_list_cmds[] = {
	// "pdc", "pdco", "agf", "Help",
	"agf", "Help"
};

typedef struct {
	const char *title;
	const char *cmd;
} PanelDbEntry;

static const PanelDbEntry panels_db[] = {
	{ "Symbols", "isq" },
	{ "Stack", "pxr@r:SP" },
	{ "Locals", "afvd" },
	{ "Registers", "dr" },
	{ "Bit Registers", "dr 1" },
	{ "FPU Registers", "dr fpu;drf" },
	{ "XMM Registers", "drm" },
	{ "YMM Registers", "drmy" },
	{ "RegisterRefs", "drr" },
	{ "RegisterCols", "dr=" },
	{ "Disassembly", "pd" },
	{ "Disassemble Summary", "pdsf" },
	{ "Decompiler", "pdc" },
	{ "Decompiler With Offsets", "pdco" },
	{ "Graph", "agf" },
	{ "Tiny Graph", "agft" },
	{ "Info", "i" },
	{ "Database", "k ***" },
	{ "Console", "cat $console" },
	{ "Hexdump", "xc $r*16" },
	{ "Xrefs", "ax" },
	{ "Xrefs Here", "ax." },
	{ "Functions", "afl" },
	{ "Function Calls", "aflm" },
	{ "Comments", "CC" },
	{ "Entropy", "p=e 100" },
	{ "Entropy Fire", "p==e 100" },
	{ "DRX", "drx" },
	{ "Sections", "iSq" },
	{ "Segments", "iSSq" },
	{ "Strings in data sections", "izq" },
	{ "Strings in the whole bin", "izzq" },
	{ "Maps", "dm" },
	{ "Modules", "dmm" },
	{ "Backtrace", "dbt" },
	{ "Breakpoints", "db" },
	{ "Imports", "iiq" },
	{ "Clipboard", "yx" },
	{ "New", "o" },
	{ "Var READ address", "afvR" },
	{ "Var WRITE address", "afvW" },
	{ "Summary", "pdsf" },
	{ "Classes", "icq" },
	{ "Methods", "ic" },
	{ "Relocs", "ir" },
	{ "Headers", "iH" },
	{ "File Hashes", "it" }
};

typedef struct {
	const char *cmd;
	RPanelRotateCallback cb;
} RotateEntry;

typedef struct {
	char *name;
	RPanelAlmightyCallback cb;
} ModalEntry;

static RotateEntry rotate_entries[8];
static int n_rotate_entries;

static ModalEntry *modal_entries;
static int n_modal_entries;

static RCoreHelpMessage help_msg_panels = {
	"|",        "split current panel vertically",
	"-",        "split current panel horizontally",
	":",        "run r2 command in prompt",
	";",        "add/remove comment",
	"_",        "show hud",
	"\\",       "show user-friendly hud",
	"?",        "show this help",
	"!",        "swap into visual mode",
	".",        "seek to PC or entrypoint",
	"*",        "show decompiler in the current panel",
	"\"",       "create a panel from the list and replace the current one",
	"/",        "highlight the keyword",
	"(",        "toggle snow",
	"&",        "toggle cache",
	"[1-9]",    "follow jmp/call identified by shortcut (like ;[1])",
	"' '",      "(space) toggle graph / panels",
	"tab",      "go to the next panel",
	"Enter",    "maximize current panel in zoom mode",
	"a",        "toggle auto update for decompiler",
	"b",        "browse symbols, flags, configurations, classes, ...",
	"c",        "toggle cursor",
	"C",        "toggle color",
	"d",        "define in the current address. Same as Vd",
	"D",        "show disassembly in the current panel",
	"e",        "change title and command of current panel",
	"E",        "edit color theme",
	"f",        "set/add filter keywords",
	"F",        "remove all the filters",
	"g",        "go/seek to given offset",
	"G",        "go/seek to highlight",
	"i",        "insert hex",
	"I",        "insert assembly",
	"`",        "rotate between common disassembly / hexdump options",
	"hjkl",     "move around (left-down-up-right)",
	"HJKL",     "move around (left-down-up-right) by page",
	"m",        "select the menu panel",
	"M",        "open new custom frame",
	"n/N",      "seek next/prev function/flag/hit (scr.nkey)",
	"p/P",      "rotate panel layout",
	"q",        "quit, or close a tab",
	"Q",        "close all the tabs and quit",
	"r",        "toggle callhints/jmphints/leahints",
	"R",        "randomize color palette (ecr)",
	"s/S",      "step in / step over",
	"t/T",      "tab prompt / close a tab",
	"u/U",      "undo / redo seek",
	"w",        "shuffle panels around in window mode",
	"V",        "go to the graph mode",
	"x",        "show xrefs/refs of current function from/to data/code",
	"X",        "close current panel",
	"z",        "swap current panel with the first one",
	NULL
};

static RCoreHelpMessage help_msg_panels_window = {
	":",        "run r2 command in prompt",
	";",        "add/remove comment",
	"\"",       "create a panel from the list and replace the current one",
	"?",        "show this help",
	"|",        "split the current panel vertically",
	"-",        "split the current panel horizontally",
	"tab",      "go to the next panel",
	"Enter",    "maximize current panel in zoom mode",
	"d",        "define in the current address. Same as Vd",
	"b",        "browse symbols, flags, configurations, classes, ...",
	"hjkl",     "move around (left-down-up-right)",
	"HJKL",     "resize panels vertically/horizontally",
	"Q/q/w",    "quit window mode",
	"p/P",      "rotate panel layout",
	"t/T",      "rotate related commands in a panel",
	"X",        "close current panel",
	NULL
};

static RCoreHelpMessage help_msg_panels_zoom = {
	"?",        "show this help",
	":",        "run r2 command in prompt",
	";",        "add/remove comment",
	"\"",       "create a panel from the list and replace the current one",
	"' '",      "(space) toggle graph / panels",
	"tab",      "go to the next panel",
	"b",        "browse symbols, flags, configurations, classes, ...",
	"d",        "define in the current address. Same as Vd",
	"c",        "toggle cursor",
	"C",        "toggle color",
	"hjkl",     "move around (left-down-up-right)",
	"p/P",      "seek to next or previous scr.nkey",
	"s/S",      "step in / step over",
	"t/T",      "rotate related commands in a panel",
	"x",        "show xrefs/refs of current function from/to data/code",
	"X",        "close current panel",
	"q/Q/Enter","quit zoom mode",
	NULL
};

// clang-format off


static void print_notch(RCore *core) {
	const int notch = r_config_get_i (core->config, "scr.notch");
	int i;
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
	return core->panels->mode != PANEL_MODE_MENU
		&& r_panels_get_cur_panel (core->panels) == panel;
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
	for (i = 0; i < R_ARRAY_SIZE (cache_white_list_cmds); i++) {
		if (!strcmp (panel->model->cmd, cache_white_list_cmds[i])) {
			panel->model->cache = true;
			return;
		}
	}
	panel->model->cache = false;
}

static char *r_panels_search_db(RCore *core, const char *title) {
	int i;
	for (i = 0; i < R_ARRAY_SIZE (panels_db); i++) {
		if (!strcmp (panels_db[i].title, title)) {
			return strdup (panels_db[i].cmd);
		}
	}
	return NULL;
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
	if (r_panels_check_panel_type (panel, "isq") || r_panels_check_panel_type (panel, "afl")) {
		return true;
	}
	static const char *types[] = {
		"Disassemble Summary", "Strings in data sections", "Strings in the whole bin",
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

static void r_panels_set_cmd_str_cache(RCore *core, RPanel *p, char *s) {
	if (!s) {
		return;
	}
	free (p->model->cmdStrCache);
	p->model->cmdStrCache = strdup (s);
	set_dcb (core, p);
	set_pcb (p);
}

static void r_panels_set_read_only(RCore *core, RPanel *p, const char * R_NULLABLE s) {
	free (p->model->readOnly);
	p->model->readOnly = s? strdup (s): NULL;
	set_dcb (core, p);
	set_pcb (p);
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

static void r_panels_print_menu_status(RCore *core, const char *msg) {
	int rows;
	const int cols = r_cons_get_size (core->cons, &rows);
	if (rows < 1 || cols < 1) {
		return;
	}
	r_cons_gotoxy (core->cons, 0, rows - 1);
	if (R_STR_ISEMPTY (msg)) {
		r_cons_printf (core->cons, R_CONS_CLEAR_LINE);
		return;
	}
	char *cropped = r_str_ansi_crop (msg, 0, 0, R_MAX (1, cols - 1), 1);
	r_cons_printf (core->cons, R_CONS_CLEAR_LINE"%s%s"Color_RESET,
		PANEL_HL_COLOR, cropped? cropped: msg);
	free (cropped);
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
	int graph_pad = r_panels_check_panel_type (panel, "agf") ? 1 : 0;
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
	if (panel->model->cache && panel->model->cmdStrCache) {
		return strdup (panel->model->cmdStrCache);
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
	if (force_cache) {
		panel->model->cache = true;
	}
	if (R_STR_ISNOTEMPTY (out)) {
		r_panels_set_cmd_str_cache (core, panel, out);
	} else {
		R_FREE (out);
	}
	free (cmd);
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
	print_notch (core);
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

static void r_panels_layout(RCore *core, RPanels *panels) {
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

static void r_panels_setup_help_panel(RCore *core, RPanel *p, const char *title, const char * const *msg) {
	const char *help = "Help";
	free (p->model->title);
	free (p->model->cmd);
	p->model->title = strdup (help);
	p->model->cmd = strdup (help);
	RStrBuf *rsb = r_strbuf_new (NULL);
	r_core_visual_append_help (core, rsb, title, msg);
	char *drained_string = r_strbuf_drain (rsb);
	r_panels_set_read_only (core, p, drained_string);
	free (drained_string);
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
			r_panels_setup_help_panel(core, p, title, msg);
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
	int i;
	for (i = 0; i < n_rotate_entries; i++) {
		if (r_panels_check_panel_type (p, rotate_entries[i].cmd)) {
			p->model->rotateCb = rotate_entries[i].cb;
			return;
		}
	}
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
	char *res = r_panels_show_status_input (core, input);
	if (!res) {
		return NULL;
	}
	p->model->cmd = r_str_newf (str, res);
	char *ret = r_core_cmd_str (core, p->model->cmd);
	free (res);
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
		if (!force_refresh && r_panels_check_panel_type (panel, "cat $console")) {
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

static void r_panels_layout_refresh(RCore *core) {
	r_panels_del_invalid_panels (core);
	r_panels_check_edge (core);
	r_panels_check_stackbase (core);
	r_panels_refresh (core);
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
	if (r_panels_check_panel_type (cur, "dr")
			|| r_panels_check_panel_type (cur, "px")) {
		if (print->cur > 0) {
			print->cur--;
			cur->model->addr--;
		}
	} else if (r_panels_check_panel_type (cur, "pd")) {
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
	if (r_panels_check_panel_type (cur, "px") && print->cur >= 15) {
		return;
	}
	print->cur++;
	if (r_panels_check_panel_type (cur, "dr")
			|| r_panels_check_panel_type (cur, "px")) {
		cur->model->addr++;
	} else if (r_panels_check_panel_type (cur, "pd")) {
		r_panels_fix_cursor_down (core);
	}
}

// copypasta from visual
static ut64 r_panels_insoff(RCore *core, int delta) {
	int minop = r_arch_info (core->anal->arch, R_ARCH_INFO_MINOP_SIZE);
	int maxop = r_arch_info (core->anal->arch, R_ARCH_INFO_MAXOP_SIZE);
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

static void prevOpcode(RCore *core);
static void nextOpcode(RCore *core);

static void r_panels_cursor_up(RCore *core) {
	prevOpcode (core);
	r_panels_fix_cursor_up (core);
}

static void r_panels_cursor_down(RCore *core) {
	nextOpcode (core);
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
	init_new_panels_root (core);
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

static void r_panels_free_menu_item(RPanelsMenuItem *item) {
	if (!item) {
		return;
	}
	size_t i;
	free (item->name);
	free (item->desc);
	free (item->args);
	for (i = 0; i < item->n_sub; i++) {
		r_panels_free_menu_item (item->sub[i]);
	}
	free (item->sub);
	if (item->p) {
		if (item->p->model) {
			free (item->p->model->cmd);
			free (item->p->model->title);
			free (item->p->model->bgcolor);
			free (item->p->model->cmdStrCache);
			free (item->p->model->readOnly);
			free (item->p->model->funcName);
			if (item->p->model->filter) {
				for (i = 0; i < item->p->model->n_filter; i++) {
					free (item->p->model->filter[i]);
				}
				free (item->p->model->filter);
			}
			free (item->p->model);
		}
		free (item->p->view);
		free (item->p);
	}
	free (item);
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

static void r_panels_free_root_menu(RPanelsMenu *menu) {
	if (!menu) {
		return;
	}
	// items are freed here; mht must already be freed or cleared before this
	if (menu->root) {
		r_panels_free_menu_item (menu->root);
	}
	free (menu->history);
	free (menu->refreshPanels);
	free (menu);
}

static void r_panels_free_panel(RPanel *panel) {
	if (!panel) {
		return;
	}
	if (panel->model) {
		free (panel->model->cmd);
		free (panel->model->title);
		free (panel->model->bgcolor);
		free (panel->model->cmdStrCache);
		free (panel->model->readOnly);
		free (panel->model->funcName);
		if (panel->model->filter) {
			int i;
			for (i = 0; i < panel->model->n_filter; i++) {
				free (panel->model->filter[i]);
			}
			free (panel->model->filter);
		}
		free (panel->model);
	}
	free (panel->view);
	free (panel);
}

static void r_panels_free_partial(RPanels *panels) {
	if (!panels) {
		return;
	}
	if (panels->mht) {
		// free hashtable first: it only owns keys, values are borrowed from the menu tree
		ht_pp_free (panels->mht);
		panels->mht = NULL;
	}
	// then free the menu tree which owns all RPanelsMenuItem objects
	r_panels_free_root_menu (panels->panels_menu);
	if (panels->panel) {
		int i;
		for (i = 0; i < PANEL_NUM_LIMIT; i++) {
			r_panels_free_panel (panels->panel[i]);
		}
		free (panels->panel);
	}
	r_cons_canvas_free (panels->can);
	r_list_free (panels->snows);
	free (panels->name);
	free (panels);
}

R_API void r_panels_root_free(RPanelsRoot *panels_root) {
	if (!panels_root) {
		return;
	}
	if (panels_root->panels) {
		int i;
		for (i = 0; i < panels_root->n_panels; i++) {
			r_panels_free_partial (panels_root->panels[i]);
		}
		free (panels_root->panels);
	}
	sdb_free (panels_root->pdc_caches);
	free (panels_root);
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
			if (neg ? (tp1 - d > tp0) : (tp1 + d < pmax)) {
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
			replace_cmd (core, cmd, cmd);
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
		create_panel_input (core, cur, PANEL_LAYOUT_VERTICAL, NULL);
		break;
	case 'N':
		create_panel_input (core, cur, PANEL_LAYOUT_HORIZONTAL, NULL);
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
		if (r_panels_check_panel_type (cur, "xc")) {
			const int cols = r_config_get_i (core->config, "hex.cols");
			r_config_set_i (core->config, "hex.cols", cols + 1);
		} else {
			const int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
			r_config_set_i (core->config, "asm.cmt.col", cmtcol + 2);
		}
		cur->view->refresh = true;
		break;
	case '[':
		if (r_panels_check_panel_type (cur, "xc")) {
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
		insert_value (core, 'x');
		break;
	case 'I':
		insert_value (core, 'a');
		break;
	case '*':
		if (r_panels_check_panel_type (cur, "pd")) {
			r_core_cmdf (core, "dr PC=0x%08"PFMT64x, core->addr + print->cur);
			r_panels_set_panel_addr (core, cur, core->addr + print->cur);
		}
		break;
	case '-':
		db_val = r_panels_search_db (core, "Breakpoints");
		if (r_panels_check_panel_type (cur, db_val)) {
			cursor_del_breakpoints(core, cur);
			free (db_val);
			break;
		}
		free (db_val);
		return false;
	case 'x':
		handle_refs (core, cur, r_panels_parse_string_on_cursor (core, cur, cur->view->curpos));
		break;
	case 0x0d:
		jmp_to_cursor_addr (core, cur);
		break;
	case 'b':
		set_breakpoints_on_cursor (core, cur);
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
	if (ch >= 0 && ch != core->panels_root->cur_panels && ch < core->panels_root->n_panels) {
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
	for (i = 0; i < R_ARRAY_SIZE (menus); i++) {
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

static void r_panels_update_modal(RCore *core, RModal *modal, int delta) {
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	modal->data = r_strbuf_new (NULL);
	int count = n_modal_entries;
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
	int i;
	int max_h = R_MIN (modal->offset + modal->pos.h, count);
	for (i = 0; i < n_modal_entries; i++) {
		if (!r_panels_draw_modal (core, modal, max_h, i, modal_entries[i].name)) {
			break;
		}
	}
	r_cons_gotoxy (core->cons, 0, 0);
	r_cons_canvas_fill (can, modal->pos.x, modal->pos.y, modal->pos.w + 2, modal->pos.h + 2, ' ');
	(void)r_cons_canvas_gotoxy (can, modal->pos.x + 2, modal->pos.y + 1);
	r_cons_canvas_write (can, r_strbuf_get (modal->data));
	r_strbuf_free (modal->data);

	r_cons_canvas_box (can, modal->pos.x, modal->pos.y, modal->pos.w + 2, modal->pos.h + 2, PANEL_HL_COLOR);

	print_notch (core);
	r_cons_canvas_print (can);
	r_cons_flush (core->cons);
	r_panels_show_cursor (core);
}

static void r_panels_exec_modal(RCore *core, RPanel *panel, RModal *modal, RPanelLayout dir) {
	if (modal->idx >= 0 && modal->idx < n_modal_entries) {
		RPanelAlmightyCallback cb = modal_entries[modal->idx].cb;
		if (cb) {
			cb (core, panel, dir, modal_entries[modal->idx].name);
		}
	}
	panel->view->sy = 0;
	panel->view->sx = 0;
}

static void r_panels_delete_modal(RCore *core, RModal *modal) {
	if (modal->idx >= 0 && modal->idx < n_modal_entries) {
		free (modal_entries[modal->idx].name);
		int i;
		for (i = modal->idx; i < n_modal_entries - 1; i++) {
			modal_entries[i] = modal_entries[i + 1];
		}
		n_modal_entries--;
	}
}

static RModal *r_panels_init_modal(void) {
	return R_NEW0 (RModal);
}

static void r_panels_free_modal(RModal **modal) {
	free (*modal);
	*modal = NULL;
}

static void r_panels_create_modal(RCore *core, RPanel *panel) {
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
	r_panels_update_modal (core, modal, 1);
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
						RPanelAlmightyCallback cb = NULL;
						int mi;
						for (mi = 0; mi < n_modal_entries; mi++) {
							if (!strcmp (modal_entries[mi].name, word)) {
								cb = modal_entries[mi].cb;
								break;
							}
						}
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
					replace_cmd (core, cmd, cmd);
				}
				free (cmd);
			}
			break;
		case 'j':
			modal->idx++;
			r_panels_update_modal (core, modal, 1);
			break;
		case 'k':
			modal->idx--;
			r_panels_update_modal (core, modal, 1);
			break;
		case 'J':
			modal->idx += 5;
			r_panels_update_modal (core, modal, 5);
			break;
		case 'K':
			modal->idx -= 5;
			r_panels_update_modal (core, modal, 5);
			break;
		case 'v':
			r_panels_exec_modal (core, panel, modal, PANEL_LAYOUT_VERTICAL);
			r_panels_free_modal (&modal);
			break;
		case 'h':
			r_panels_exec_modal (core, panel, modal, PANEL_LAYOUT_HORIZONTAL);
			r_panels_free_modal (&modal);
			break;
		case ' ':
		case 0x0d:
			r_panels_exec_modal (core, panel, modal, PANEL_LAYOUT_NONE);
			r_panels_free_modal (&modal);
			break;
		case '-':
			r_panels_delete_modal (core, modal);
			r_panels_update_modal (core, modal, 1);
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
			r_panels_create_modal (core, r_panels_get_panel (panels, 0));
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
	if (idx == -1 || R_STR_ISEMPTY (word)) {
		free (word);
		return false;
	}
	if (R_STR_ISNOTEMPTY (word)) {
		const ut64 addr = r_num_math (core->num, word);
		if (r_panels_check_panel_type (panel, "afl") &&
				r_panels_check_if_addr (word, strlen (word))) {
			r_core_seek (core, addr, true);
			set_addr_by_type (core, "pd", addr);
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
	if (!r_panels_check_func (core)) {
		return;
	}
	RPanels *panels = core->panels;
	r_cons_canvas_free (panels->can);
	panels->can = NULL;
	int ocolor = r_config_get_i (core->config, "scr.color");
	r_core_visual_graph (core, NULL, NULL, true);
	r_config_set_i (core->config, "scr.color", ocolor);
	int h, w = r_panels_get_size (core, &h);
	panels->can = r_panels_create_new_canvas (core, w, h);
}

static void r_panels_do_panels_refresh(RCore *core) {
	if (core->panels) {
		r_panels_panel_all_clear (core, core->panels);
		r_panels_layout_refresh (core);
	}
}

static void r_panels_do_panels_resize(RCore *core) {
	RPanels *panels = core->panels;
	int i;
	int h, w = r_panels_get_size (core, &h);
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

	if (r_panels_check_panel_type (cur, "pd")) {
		r_panels_set_panel_addr (core, cur, core->addr);
	} else {
		int i;
		for (i = 0; i < panels->n_panels; i++) {
			RPanel *panel = r_panels_get_panel (panels, i);
			if (r_panels_check_panel_type (panel, "pd")) {
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
		bool fall = false;
		{
			RListIter *it;
			RPanelsSnow *snw;
			bool collision = false;
			bool is_down_right = false;
			bool is_down_left = false;
			r_list_foreach (panels->snows, it, snw) {
				if (snw->stuck) {
					if (snw->x == snow->x && snw->y == snow->y) {
						collision = true;
						continue;
					}
					if (snw->x == snow->x + 1 && snw->y == snow->y) {
						is_down_right = true;
						continue;
					}
					if (snw->x == snow->x - 1 && snw->y == snow->y) {
						is_down_left = true;
					}
				}
			}
			if (collision) {
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
					goto print_this_snow;
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

static char *r_panels_config_path(bool syspath) {
	if (syspath) {
		char *pfx = r_sys_prefix (NULL);
		char *res = r_file_new (pfx, R2_DATDIR_R2, "panels", NULL);
		free (pfx);
		return res;
	}
	return r_xdg_datadir ("r2panels");
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
	RPanelsMenuItem *item = R_NEW0 (RPanelsMenuItem);
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
		r_panels_free_menu_item (item);
		return;
	}
	if (!p_item) {
		R_LOG_WARN ("Cannot find panel %s", parent);
		free (key);
		r_panels_free_menu_item (item);
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
			r_panels_free_menu_item (item);
			return;
		}
	}
	item->n_sub = 0;
	item->selectedIndex = 0;
	item->name = strdup (name);
	item->desc = R_STR_ISNOTEMPTY (desc)? strdup (desc): NULL;
	item->args = R_STR_ISNOTEMPTY (args)? strdup (args): NULL;
	item->sub = NULL;
	item->cb = cb;
	item->p = R_NEW0 (RPanel);
	item->p->model = R_NEW0 (RPanelModel);
	item->p->view = R_NEW0 (RPanelView);
	p_item->n_sub++;
	RPanelsMenuItem **sub = realloc (p_item->sub, sizeof (RPanelsMenuItem *) * p_item->n_sub);
	if (sub) {
		if (add_to_ht) {
			ht_pp_insert (panels->mht, key, item);
		}
		p_item->sub = sub;
		p_item->sub[p_item->n_sub - 1] = item;
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

static void refresh_core_offset(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (r_panels_check_panel_type (cur, "pd")) {
		core->addr = cur->model->addr;
	}
}

static void demo_begin(RCore *core, RConsCanvas *can) {
	char *s = r_cons_canvas_tostring (can);
	if (s) {
		// TODO drop utf8!!
		r_str_ansi_filter (s, NULL, NULL, -1);
		int i, h, w = r_panels_get_size (core, &h);
		for (i = 0; i < 40; i += (1 + (i / 30))) {
			int H = (int)(i * ((double)h / 40));
			char *r = r_str_scale (s, w, H);
			r_cons_clear00 (core->cons);
			r_cons_gotoxy (core->cons, 0, (h / 2) - (H / 2));
			r_cons_print (core->cons, r);
			r_cons_flush (core->cons);
			free (r);
			r_sys_usleep (5000);
		}
		free (s);
	}
}

static void r_panels_refresh(RCore *core) {
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	r_cons_gotoxy (core->cons, 0, 0);
	int i, h, w = r_panels_get_size (core, &h);
	if (!r_cons_canvas_resize (can, w, h)) {
		return;
	}
	RStrBuf *title = r_strbuf_new (" ");
	bool utf8 = r_config_get_b (core->config, "scr.utf8");
	if (core->visual.firstRun) {
		r_config_set_b (core->config, "scr.utf8", false);
	}

	refresh_core_offset (core);
	r_panels_set_refresh_all (core, false, false);

	for (i = 0; i < panels->n_panels; i++) {
		if (panels->mode == PANEL_MODE_ZOOM && i != panels->curnode) {
			continue;
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
		r_panels_refresh (core);
	} else {
		print_notch (core);
		r_cons_canvas_print (can);
		if (core->scr_gadgets) {
			r_core_call (core, "pg");
		}
		if (panels->mode == PANEL_MODE_MENU) {
			RPanelsMenuItem *item = r_panels_get_selected_menu_item (panels);
			char *status = r_panels_menu_status_text (item);
			r_panels_print_menu_status (core, status);
			free (status);
		}
		r_panels_show_cursor (core);
		r_cons_flush (core->cons);
	}
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
	if (!r_panels_check_panel_type (cur, "pd")) {
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
}

static void r_panels_redo_seek(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	if (!r_panels_check_panel_type (cur, "pd")) {
		return;
	}
	RIOUndos *undo = r_io_sundo_redo (core->io);
	if (undo) {
		r_core_visual_seek_animation (core, undo->off);
		r_panels_set_panel_addr (core, cur, core->addr);
	}
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



static void handlePrompt(RCore *core, RPanels *panels) {
	r_panels_bottom_panel_line (core);
	r_core_visual_prompt_input (core);
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p && r_panels_check_panel_type (p, "pd")) {
			r_panels_set_panel_addr (core, p, core->addr);
			break;
		}
	}
}

static int add_cmd_panel(void *user) {
	RCore *core = (RCore *)user;
	if (!r_panels_check_panel_num (core)) {
		return 0;
	}
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	char *cmd = r_panels_search_db (core, child->name);
	if (!cmd) {
		return 0;
	}
	r_panels_adjust_and_add_panel (core, child->name, cmd);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	free (cmd);
	menu->n_refresh = 0; // close the menu bar
	return 0;
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
	if (h > 1) {
		r_panels_set_geometry (&p0->view->pos, 0, 1, PANEL_CONFIG_SIDEPANEL_W, h - 1);
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
	free (cur->model->cmd);
	free (cur->model->title);
	cur->model->cmd = strdup (cmd);
	cur->model->title = strdup (title);
	cur->model->cache = false;
	r_panels_set_cmd_str_cache (core, cur, NULL);
	cur->model->cache = false;
	r_panels_set_panel_addr (core, cur, core->addr);
	cur->model->type = PANEL_TYPE_DEFAULT;
	set_dcb (core, cur);
	set_pcb (cur);
	r_panels_set_rcb (panels, cur);
	r_panels_cache_white_list (core, cur);
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
	RPanel *p = r_panels_get_cur_panel (core->panels);
	r_panels_cache_white_list (core, p);
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

static void continue_modal_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED const char * R_NULLABLE title) {
	continue_cb (user);
	update_disassembly_or_open ((RCore *)user);
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

static void step_modal_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED const char * R_NULLABLE title) {
	step_cb (user);
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

static void put_breakpoints_cb(void *user, RPanel * R_UNUSED panel, R_UNUSED const RPanelLayout dir, R_UNUSED const char * R_NULLABLE title) {
	break_points_cb (user);
}

static void step_over_modal_cb(void *user, RPanel * R_UNUSED panel, R_UNUSED const RPanelLayout dir, R_UNUSED const char * R_NULLABLE title) {
	step_over_cb (user);
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

static void init_modal_db(RCore *core) {
	free (modal_entries);
	int cap = R_ARRAY_SIZE (panels_db) + 10;
	modal_entries = R_NEWS0 (ModalEntry, cap);
	n_modal_entries = 0;
	int i;
	for (i = 0; i < R_ARRAY_SIZE (panels_db); i++) {
		modal_entries[n_modal_entries].name = strdup (panels_db[i].title);
		modal_entries[n_modal_entries].cb = create_panel_db;
		n_modal_entries++;
	}
	modal_entries[n_modal_entries++] = (ModalEntry){ strdup ("Search strings in data sections"), search_strings_data_create };
	modal_entries[n_modal_entries++] = (ModalEntry){ strdup ("Search strings in the whole bin"), search_strings_bin_create };
	modal_entries[n_modal_entries++] = (ModalEntry){ strdup ("Create New"), create_panel_input };
	modal_entries[n_modal_entries++] = (ModalEntry){ strdup ("Change Command of Current Panel"), replace_current_panel_input };
	modal_entries[n_modal_entries++] = (ModalEntry){ strdup ("Show All Decompiler Output"), delegate_show_all_decompiler_cb };
	if (r_config_get_b (core->config, "cfg.debug")) {
		modal_entries[n_modal_entries++] = (ModalEntry){ strdup ("Put Breakpoints"), put_breakpoints_cb };
		modal_entries[n_modal_entries++] = (ModalEntry){ strdup ("Continue"), continue_modal_cb };
		modal_entries[n_modal_entries++] = (ModalEntry){ strdup ("Step"), step_modal_cb };
		modal_entries[n_modal_entries++] = (ModalEntry){ strdup ("Step Over"), step_over_modal_cb };
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

static void handle_tab_new_with_cur_panel(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->n_panels <= 1) {
		return;
	}

	RPanelsRoot *root = core->panels_root;
	if (root->n_panels + 1 >= PANEL_NUM_LIMIT) {
		return;
	}

	RPanel *cur = r_panels_get_cur_panel (panels);

	RPanels *new_panels = r_panels_new (core);
	if (!new_panels) {
		return;
	}
	root->panels[root->n_panels] = new_panels;

	RPanels *prev = core->panels;
	core->panels = new_panels;

	if (!init_panels_menu (core) || !r_panels_alloc (core, new_panels)) {
		core->panels = prev;
		return;
	}
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	init_all_dbs (core);

	RPanel *new_panel = r_panels_get_panel (new_panels, 0);
	r_panels_init_panel_param (core, new_panel, cur->model->title, cur->model->cmd);
	new_panel->model->cache = cur->model->cache;
	new_panel->model->funcName = strdup (cur->model->funcName);
	r_panels_set_cmd_str_cache (core, new_panel, cur->model->cmdStrCache);
	r_panels_maximize_panel_size (new_panels);

	core->panels = prev;
	r_panels_dismantle_del_panel (core, cur, panels->curnode);

	root->cur_panels = root->n_panels;
	root->n_panels++;
	r_panels_set_root_state (core, ROTATE);
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
			handle_tab_new_with_cur_panel (core);
			break;
		}
	}
}

static void handleComment(RCore *core) {
	RPanel *p = r_panels_get_cur_panel (core->panels);
	if (!r_panels_check_panel_type (p, "pd")) {
		return;
	}
	char buf[4095];
	char *cmd = NULL;
	r_line_set_prompt (core->cons->line, "[Comment]> ");
	if (r_cons_fgets (core->cons, buf, sizeof (buf), 0, NULL) > 0) {
		ut64 addr, orig;
		addr = orig = core->addr;
		if (core->print->cur_enabled) {
			addr += core->print->cur;
			r_core_seek (core, addr, false);
			r_core_cmdf (core, "s 0x%"PFMT64x, addr);
		}
		if (!strcmp (buf, "-")) {
			cmd = strdup ("CC-");
		} else {
			char *arg = r_panels_filter_arg (strdup (buf));
			switch (buf[0]) {
			case '-':
				cmd = r_str_newf ("'CC-%s", arg);
				break;
			case '!':
				cmd = strdup ("CC!");
				break;
			default:
				cmd = r_str_newf ("'CC %s", arg);
				break;
			}
			free (arg);
		}
		if (cmd) {
			r_core_cmd0 (core, cmd);
		}
		if (core->print->cur_enabled) {
			r_core_seek (core, orig, true);
		}
		free (cmd);
	}
	r_panels_set_refresh_by_type (core, p->model->cmd, true);
}

static void direction_default_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	cur->view->refresh = true;
	switch (direction) {
	case 'h':
		if (cur->view->sx > 0) {
			cur->view->sx--;
		}
		break;
	case 'l':
		if (cur->view->sx < MAX_CANVAS_SIZE) {
			cur->view->sx++;
		}
		break;
	case 'k':
		if (cur->view->sy > 0) {
			cur->view->sy--;
		}
		break;
	case 'j':
		if (cur->view->sy < MAX_CANVAS_SIZE) {
			cur->view->sy++;
		}
		break;
	}
}

static void direction_disassembly_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (cur->model->cache) {
		direction_default_cb (user, direction);
		return;
	}
	int cols = core->print->cols;
	cur->view->refresh = true;
	switch (direction) {
	case 'h':
		if (core->print->cur_enabled) {
			r_panels_cursor_left (core);
			r_core_block_read (core);
			r_panels_set_panel_addr (core, cur, core->addr);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			cur->model->addr--;
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
		}
		break;
	case 'l':
		if (core->print->cur_enabled) {
			r_panels_cursor_right (core);
			r_core_block_read (core);
			r_panels_set_panel_addr (core, cur, core->addr);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			cur->model->addr++;
		} else {
			cur->view->sx++;
		}
		break;
	case 'k':
		core->addr = cur->model->addr;
		if (core->print->cur_enabled) {
			r_panels_cursor_up (core);
			r_core_block_read (core);
			r_panels_set_panel_addr (core, cur, core->addr);
		} else {
			r_core_visual_disasm_up (core, &cols);
			r_core_seek_delta (core, -cols);
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case 'j':
		core->addr = cur->model->addr;
		if (core->print->cur_enabled) {
			r_panels_cursor_down (core);
			r_core_block_read (core);
			r_panels_set_panel_addr (core, cur, core->addr);
		} else {
			RAnalOp op;
			r_core_visual_disasm_down (core, &op, &cols);
			r_core_seek (core, core->addr + cols, true);
			r_panels_set_panel_addr (core, cur, core->addr);
			r_anal_op_fini (&op);
		}
		break;
	}
}

static void direction_graph_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (cur->model->cache) {
		direction_default_cb (user, direction);
		return;
	}
	cur->view->refresh = true;
	const int speed = r_config_get_i (core->config, "graph.scroll") * 2;
	switch (direction) {
	case 'h':
		if (cur->view->sx > 0) {
			cur->view->sx -= speed;
		}
		break;
	case 'l':
		cur->view->sx +=  speed;
		break;
	case 'k':
		if (cur->view->sy > 0) {
			cur->view->sy -= speed;
		}
		break;
	case 'j':
		cur->view->sy += speed;
		break;
	}
}

static void direction_register_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	int cols = core->dbg->regcols;
	cols = cols > 0 ? cols : 3;
	cur->view->refresh = true;
	switch (direction) {
	case 'h':
		if (core->print->cur_enabled) {
			r_panels_cursor_left (core);
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
			cur->view->refresh = true;
		}
		break;
	case 'l':
		if (core->print->cur_enabled) {
			r_panels_cursor_right (core);
		} else {
			cur->view->sx++;
			cur->view->refresh = true;
		}
		break;
	case 'k':
		if (core->print->cur_enabled) {
			int tmp = core->print->cur;
			tmp -= cols;
			if (tmp >= 0) {
				core->print->cur = tmp;
			}
		}
		break;
	case 'j':
		if (core->print->cur_enabled) {
			core->print->cur += cols;
		}
		break;
	}
}

static void direction_stack_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	int cols = r_config_get_i (core->config, "hex.cols");
	if (cols < 1) {
		cols = 16;
	}
	cur->view->refresh = true;
	switch (direction) {
	case 'h':
		if (core->print->cur_enabled) {
			r_panels_cursor_left (core);
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
			cur->view->refresh = true;
		}
		break;
	case 'l':
		if (core->print->cur_enabled) {
			r_panels_cursor_right (core);
		} else {
			cur->view->sx++;
			cur->view->refresh = true;
		}
		break;
	case 'k':
		{
			ut64 delta = r_config_get_i (core->config, "stack.delta");
			if (cur->model->addr >= (ut64)cols && delta <= UT64_MAX - (ut64)cols) {
				r_config_set_i (core->config, "stack.delta", delta + cols);
				cur->model->addr -= cols;
			}
		}
		break;
	case 'j':
		{
			ut64 delta = r_config_get_i (core->config, "stack.delta");
			if (delta >= (ut64)cols && cur->model->addr <= UT64_MAX - (ut64)cols) {
				r_config_set_i (core->config, "stack.delta", delta - cols);
				cur->model->addr += cols;
			}
		}
		break;
	}
}

static void direction_hexdump_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (!cur) {
		return;
	}
	if (cur->model->cache) {
		direction_default_cb (user, direction);
		return;
	}
	int cols = r_config_get_i (core->config, "hex.cols");
	if (cols < 1) {
		cols = 16;
	}
	cur->view->refresh = true;
	switch (direction) {
	case 'h':
		if (!core->print->cur) {
			cur->model->addr -= cols;
			core->print->cur += cols - 1;
		} else if (core->print->cur_enabled) {
			r_panels_cursor_left (core);
		} else {
			cur->model->addr--;
		}
		break;
	case 'l':
		if (core->print->cur / cols + 1 > cur->view->pos.h - 5
				&& core->print->cur % cols == cols - 1) {
			cur->model->addr += cols;
			core->print->cur -= cols - 1;
		} else if (core->print->cur_enabled) {
			r_panels_cursor_right (core);
		} else {
			cur->model->addr++;
		}
		break;
	case 'k':
		if (!cur->model->cache) {
			if (core->print->cur_enabled) {
				if (!(core->print->cur / cols)) {
					cur->model->addr -= cols;
				} else {
					core->print->cur -= cols;
				}
			} else {
				if (cur->model->addr <= cols) {
					r_panels_set_panel_addr (core, cur, 0);
				} else {
					cur->model->addr -= cols;
				}
			}
		} else if (cur->view->sy > 0) {
			cur->view->sy--;
		}
		break;
	case 'j':
		if (!cur->model->cache) {
			if (core->print->cur_enabled) {
				if (core->print->cur / cols + 1 > cur->view->pos.h - 5) {
					cur->model->addr += cols;
				} else {
					core->print->cur += cols;
				}
			} else {
				cur->model->addr += cols;
			}
		} else {
			cur->view->sy++;
		}
		break;
	}
}

static void direction_panels_cursor_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	cur->view->refresh = true;
	const int THRESHOLD = cur->view->pos.h / 3;
	int sub;
	switch (direction) {
	case 'h':
		if (core->print->cur_enabled) {
			break;
		}
		if (cur->view->sx > 0) {
			cur->view->sx -= r_config_get_i (core->config, "graph.scroll");
		}
		break;
	case 'l':
		if (core->print->cur_enabled) {
			break;
		}
		cur->view->sx += r_config_get_i (core->config, "graph.scroll");
		break;
	case 'k':
		if (core->print->cur_enabled) {
			if (cur->view->curpos > 0) {
				cur->view->curpos--;
			}
			if (cur->view->sy > 0) {
				sub = cur->view->curpos - cur->view->sy;
				if (sub < 0) {
					cur->view->sy--;
				}
			}
		} else {
			if (cur->view->sy > 0) {
				cur->view->curpos -= 1;
				cur->view->sy -= 1;
			}
		}
		break;
	case 'j':
		core->addr = cur->model->addr;
		if (core->print->cur_enabled) {
			cur->view->curpos++;
			sub = cur->view->curpos - cur->view->sy;
			if (sub > THRESHOLD) {
				cur->view->sy++;
			}
		} else {
			cur->view->curpos += 1;
			cur->view->sy += 1;
		}
		break;
	}
}

static void jmp_to_cursor_addr(RCore *core, RPanel *panel) {
	ut64 addr = r_panels_parse_string_on_cursor (core, panel, panel->view->curpos);
	if (addr == UT64_MAX) {
		return;
	}
	core->addr = addr;
	update_disassembly_or_open (core);
}

static void set_breakpoints_on_cursor(RCore *core, RPanel *panel) {
	if (!r_config_get_b (core->config, "cfg.debug")) {
		return;
	}
	if (r_panels_check_panel_type (panel, "pd")) {
		r_core_cmdf (core, "dbs 0x%08"PFMT64x, core->addr + core->print->cur);
		panel->view->refresh = true;
	}
}

static void insert_value(RCore *core, int wat) {
	if (!r_config_get_i (core->config, "io.cache")) {
		if (r_panels_show_status_yesno (core, 1, "Insert is not available because io.cache is off. Turn on now? (Y/n)")) {
			r_config_set_b (core->config, "io.cache", true);
			(void)r_panels_show_status (core, "io.cache is on and insert is available now.");
		} else {
			(void)r_panels_show_status (core, "Check Menu->Edit->io.cache to toggle that option.");
			return;
		}
	}
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	switch (wat) {
	case 'a': // asm
		r_core_visual_asm (core, cur->model->addr + core->print->cur);
		cur->view->refresh = true;
		return;
	case 'x': // hex
		{
		const char *buf = r_cons_visual_readln (core->cons, "insert hex: ", NULL);
		if (buf) {
			r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, cur->model->addr + core->print->cur);
			cur->view->refresh = true;
		}
		}
		return;
	}
	if (r_panels_check_panel_type (cur, "px")) {
		const char *buf = r_cons_visual_readln (core->cons, "insert hex: ", NULL);
		if (buf) {
			r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, cur->model->addr);
			cur->view->refresh = true;
		}
	} else if (r_panels_check_panel_type (cur, "dr")) {
		const char *creg = core->dbg->creg;
		if (creg) {
			const char *buf = r_cons_visual_readln (core->cons, "new-reg-value> ", NULL);
			if (buf) {
				r_core_callf (core, "dr %s = %s", creg, buf);
				cur->view->refresh = true;
			}
		}
	} else if (r_panels_check_panel_type (cur, "pd")) {
		const char *buf = r_cons_visual_readln (core->cons, "insert asm: ", NULL);
		if (buf) {
			r_core_visual_asm (core, cur->model->addr + core->print->cur);
			cur->view->refresh = true;
		}
	} else if (r_panels_check_panel_type (cur, "xc")) {
		const char *buf = r_cons_visual_readln (core->cons, "insert hex: ", NULL);
		if (buf) {
			r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, cur->model->addr + core->print->cur);
			cur->view->refresh = true;
		}
	}
}

static void cursor_del_breakpoints(RCore *core, RPanel *panel) {
	RListIter *iter;
	RBreakpointItem *b;
	int i = 0;
	r_list_foreach (core->dbg->bp->bps, iter, b) {
		if (panel->view->curpos == i++) {
			r_bp_del (core->dbg->bp, b->addr);
		}
	}
}

static void set_addr_by_type(RCore *core, const char *cmd, ut64 addr) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!r_panels_check_panel_type (p, cmd)) {
			continue;
		}
		r_panels_set_panel_addr (core, p, addr);
	}
}

static void handle_refs(RCore *core, RPanel *panel, ut64 tmp) {
	if (tmp != UT64_MAX) {
		core->addr = tmp;
	}
	int key = r_panels_show_status(core, "xrefs:x refs:X ");
	switch (key) {
	case 'x':
		(void)r_core_visual_refs (core, true, false);
		break;
	case 'X':
		(void)r_core_visual_refs (core, false, false);
		break;
	default:
		break;
	}
	if (r_panels_check_panel_type (panel, "pd")) {
		r_panels_set_panel_addr (core, panel, core->addr);
	} else {
		set_addr_by_type (core, "pd", core->addr);
	}
}

static void add_vmark(RCore *core) {
	char *msg = r_str_newf (R_CONS_CLEAR_LINE"Set shortcut key for 0x%"PFMT64x": ", core->addr);
	int ch = r_panels_show_status (core, msg);
	free (msg);
	r_core_vmark (core, ch);
}

static void handle_vmark(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	if (!r_panels_check_panel_type (cur, "pd")) {
		return;
	}
	RCons *cons = core->cons;
	int act = r_panels_show_status (core, "Visual Mark  s:set -:remove \':use: ");
	switch (act) {
	case 's':
		add_vmark (core);
		break;
	case '-':
		r_cons_gotoxy (core->cons, 0, 0);
		if (r_core_vmark_dump (core, 0)) {
			r_cons_printf (cons, R_CONS_CLEAR_LINE"Remove a shortcut key from the list\n");
			r_cons_flush (cons);
			r_cons_set_raw (cons, true);
			int ch = r_cons_readchar (cons);
			r_core_vmark_del (core, ch);
		}
		break;
	case '\'':
		r_cons_gotoxy (core->cons, 0, 0);
		if (r_core_vmark_dump (core, 0)) {
			r_cons_flush (cons);
			r_cons_set_raw (cons, true);
			int ch = r_cons_readchar (core->cons);
			r_core_vmark_seek (core, ch, NULL);
			r_panels_set_panel_addr (core, cur, core->addr);
		}
	}
}

static void set_dcb(RCore *core, RPanel *p) {
	if (r_panels_is_abnormal_cursor_type (core, p)) {
		p->model->cache = true;
		p->model->directionCb = direction_panels_cursor_cb;
		return;
	}
	if ((p->model->cache && p->model->cmdStrCache) || p->model->readOnly) {
		p->model->directionCb = direction_default_cb;
		return;
	}
	if (!p->model->cmd) {
		return;
	}
	if (r_panels_check_panel_type (p, "agf")) {
		p->model->directionCb = direction_graph_cb;
		return;
	}
	if (r_panels_check_panel_type (p, "px")) {
		p->model->directionCb = direction_stack_cb;
	} else if (r_panels_check_panel_type (p, "pd")) {
		p->model->directionCb = direction_disassembly_cb;
	} else if (r_panels_check_panel_type (p, "dr")
			|| r_panels_check_panel_type (p, "dr fpu;drf")
			|| r_panels_check_panel_type (p, "drm")
			|| r_panels_check_panel_type (p, "drmy")) {
		p->model->directionCb = direction_register_cb;
	} else if (r_panels_check_panel_type (p, "xc")) {
		p->model->directionCb = direction_hexdump_cb;
	} else {
		p->model->directionCb = direction_default_cb;
	}
}

static bool check_func_diff(RCore *core, RPanel *p) {
	RAnalFunction *func = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	if (!func) {
		if (R_STR_ISEMPTY (p->model->funcName)) {
			return false;
		}
		p->model->funcName = NULL;
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
	bool update = core->panels->autoUpdate && check_func_diff (core, panel);
	char *cmdstr = r_panels_find_cmd_str_cache (core, panel);
	if (update || !cmdstr) {
		free (cmdstr);
		cmdstr = r_panels_handle_cmd_str_cache (core, panel, false);
	}
	r_panels_update_panel_contents (core, panel, cmdstr);
	free (cmdstr);
}

static void print_decompiler_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	RAnalFunction *func = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	if (!func) {
		char *msg = r_str_newf ("No function at 0x%08"PFMT64x, core->addr);
		r_panels_update_pdc_contents (core, panel, msg);
		free (msg);
		return;
	}
	char *cmdstr = r_panels_find_cmd_str_cache (core, panel);
	if (R_STR_ISNOTEMPTY (cmdstr)) {
		r_panels_update_pdc_contents (core, panel, cmdstr);
	}
	free (cmdstr);
}

static void print_disasmsummary_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && check_func_diff (core, panel);
	char *cmdstr = r_panels_find_cmd_str_cache (core, panel);
	if (update || !cmdstr) {
		free (cmdstr);
		cmdstr = r_panels_handle_cmd_str_cache (core, panel, true);
		if (panel->model->cache && panel->model->cmdStrCache) {
			r_panels_reset_scroll_pos (panel);
		}
	}
	r_panels_update_panel_contents (core, panel, cmdstr);
	free (cmdstr);
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
	char *cmdstr = r_panels_handle_cmd_str_cache (core, panel, false);
	core->addr = o_offset;
	free (panel->model->cmd);
	panel->model->cmd = ocmd;
	r_panels_update_panel_contents (core, panel, cmdstr);
	free (cmdstr);
}

static void print_graph_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && check_func_diff (core, panel);
	char *cmdstr = r_panels_find_cmd_str_cache (core, panel);
	if (update || !cmdstr) {
		free (cmdstr);
		cmdstr = r_panels_handle_cmd_str_cache (core, panel, false);
	}
	core->cons->event_resize = NULL;
	core->cons->event_data = core;
	core->cons->event_resize = (RConsEvent) r_panels_do_panels_refreshQueued;
	r_panels_update_panel_contents (core, panel, cmdstr);
	free (cmdstr);
}

static void print_stack_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	const int size = r_config_get_i (core->config, "stack.size");
	const int delta = r_config_get_i (core->config, "stack.delta");
	const int bits = r_config_get_i (core->config, "asm.bits");
	const char sign = (delta < 0)? '+': '-';
	const int absdelta = R_ABS (delta);
	char *cmd = r_str_newf ("px%s %d", bits == 32? "w": "q", size);
	panel->model->cmd = cmd;
	ut64 sp_addr = r_reg_getv (core->anal->reg, "SP");
	char *k = r_str_newf ("%s @ 0x%08"PFMT64x"%c%d", cmd, sp_addr, sign, absdelta);
	char *cmdstr = r_core_cmd_str (core, k);
	free (k);
	r_panels_update_panel_contents (core, panel, cmdstr);
	free (cmdstr);
}

static void print_hexdump_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	char *cmdstr = r_panels_find_cmd_str_cache (core, panel);
	if (!cmdstr) {
		ut64 o_offset = core->addr;
		if (!panel->model->cache) {
			core->addr = panel->model->addr;
			r_core_seek (core, core->addr, true);
			r_core_block_read (core);
		}
		char *base = hexdump_rotate[R_ABS(panel->model->rotate) % R_ARRAY_SIZE (hexdump_rotate)];
		char *cmd = r_str_newf ("%s ", base);
		int n = r_str_split (panel->model->cmd, ' ');
		int i;
		for (i = 0; i < n; i++) {
			const char *s = r_str_word_get0 (panel->model->cmd, i);
			if (!i) {
				continue;
			}
			cmd = r_str_append (cmd, s);
		}
		panel->model->cmd = cmd;
		cmdstr = r_panels_handle_cmd_str_cache (core, panel, false);
		core->addr = o_offset;
	}
	r_panels_update_panel_contents (core, panel, cmdstr);
	free (cmdstr);
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
		strncpy (line->buffer.data, desc->name, R_LINE_BUFSIZE - 1);
		line->buffer.index = line->buffer.length = strlen (line->buffer.data);
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
		line->buffer.data[0] = '\0';
		line->buffer.index = line->buffer.length = 0;
		return false;
	}
	RIODesc *desc = r_list_get_n (files, num_files - line->file_hist_index);
	if (desc) {
		strncpy (line->buffer.data, desc->name, R_LINE_BUFSIZE - 1);
		line->buffer.index = line->buffer.length = strlen (line->buffer.data);
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
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
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
	if (!r_core_panels_load (core, child->name)) {
		create_default_panels (core);
		r_panels_layout (core, core->panels);
	}
	r_panels_set_curnode (core, 0);
	core->panels->panels_menu->depth = 1;
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	r_panels_del_menu (core);
	r_panels_del_menu (core);
	r_panels_set_refresh_all (core, true, false);
	return 0;
}

static int load_layout_default_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_alloc (core, core->panels);
	create_default_panels (core);
	r_panels_layout (core, core->panels);
	core->panels->panels_menu->depth = 1;
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	r_panels_del_menu (core);
	r_panels_del_menu (core);
	r_panels_del_menu (core);
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

	r_panels_update_menu (core, "Settings.Load Layout.Saved..", init_menu_saved_layout);
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
	r_panels_update_menu (core, "Settings.Color Themes...", init_menu_color_settings_layout);
	return 0;
}

static void config_refresh_menu(RCore *core, RPanelsMenu *menu, RPanelsMenuItem *parent) {
	free (parent->p->model->title);
	int mi = core->panels->can->h - parent->p->view->pos.y - 4;
	parent->p->model->title = r_strbuf_drain (r_panels_draw_menu (core, parent, R_MAX (mi, 3)));
	size_t i;
	for (i = 1; i < menu->depth; i++) {
		RPanel *p = menu->history[i]->p;
		p->view->refresh = true;
		menu->refreshPanels[i - 1] = p;
	}
	if (!strcmp (parent->name, "asm")) {
		r_panels_update_menu (core, "Settings.Disassembly....asm", init_menu_disasm_asm_settings_layout);
	} else if (!strcmp (parent->name, "Screen")) {
		r_panels_update_menu (core, "Settings.Screen", init_menu_screen_settings_layout);
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

static const char *screen_value_items[] = { "scr.color", NULL };

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
	r_core_visual_prompt_input (core);
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
	add_cmdf_panel (core, "rop grep: ", "'/R %s");
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
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	return 0;
}

static int io_cache_off_cb(void *user) {
	RCore *core = (RCore *)user;
	r_config_set_b (core->config, "io.cache", false);
	(void)r_panels_show_status (core, "io.cache is off");
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
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
		y = 1;
	} else {
		RPanelsMenuItem *p = menu->history[menu->depth - 2];
		RPanelsMenuItem *parent2 = p->sub[p->selectedIndex];
		x = parent2->p->view->pos.x + parent2->p->view->pos.w - 1;
		y = menu->depth == 2 ? parent2->p->view->pos.y + parent2->selectedIndex : parent2->p->view->pos.y;
	}
	if (y < 0) {
		y = 0;
	}
	if (y >= can->h) {
		y = can->h - 1;
	}
	int max_items = can->h - y - 4;
	if (max_items < 3) {
		max_items = 3;
	}
	RStrBuf *buf = r_panels_draw_menu (core, child, max_items);
	if (!buf) {
		return 0;
	}
	free (child->p->model->title);
	child->p->model->title = r_strbuf_drain (buf);
	child->p->view->pos.w = r_str_bounds (child->p->model->title, &child->p->view->pos.h);
	child->p->view->pos.h += 4;
	if (y + child->p->view->pos.h > can->h) {
		child->p->view->pos.h = can->h - y;
	}
	if (x + child->p->view->pos.w > can->w) {
		x = R_MAX (0, can->w - child->p->view->pos.w);
	}
	r_panels_set_pos (&child->p->view->pos, x, y);
	child->p->model->type = PANEL_TYPE_MENU;
	child->p->view->refresh = true;
	menu->refreshPanels[menu->n_refresh++] = child->p;
	menu->history[menu->depth++] = child;
	return 0;
}

static const char *manpage_tools[] = {
	"r2agent", "rabin2", "radare2", "rafind2", "ragg2",
	"rahash2", "rarun2", "rasign2", "rasm2", "ravc2", "rax2"
};

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
	parent = "Settings.Color Themes...";
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
			init_menu_disasm_asm_settings_layout (core, "Settings.Disassembly....asm");
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

static const char *asm_value_items[] = { "asm.var.summary", "asm.arch", "asm.bits", "asm.cpu", NULL };

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

static const MenuItem file_items[] = {
	{ "Open File", "Prompt for a file and open it", open_file_cb },
	{ "Reopen...", "Reopen the current file with a different mode", open_menu_cb },
	{ "Close File", "Close the current file descriptor", close_file_cb },
	{ "--", NULL, NULL },
	{ "Open Project", "Load a project into the current session", project_open_cb },
	{ "Save Project", "Save the current project state", project_save_cb },
	{ "Close Project", "Close the active project", project_close_cb },
	{ "--", NULL, NULL },
	{ "Quit", "Leave panels mode", quit_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem settings_items[] = {
	{ "Edit radare2rc", "Open the user radare2rc file", r2rc_cb },
	{ "Save Layout", "Save the current panels layout", save_layout_cb },
	{ "Load Layout", "Load a saved or default layout", open_menu_cb },
	{ "Clear Saved Layouts", "Delete every saved panels layout", clear_layout_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem edit_items[] = {
	{ "Copy", "Copy the current selection or line", copy_cb },
	{ "Paste", "Paste the clipboard at the current offset", paste_cb },
	{ "Write String", "Write an ASCII string", write_str_cb },
	{ "Write Hex", "Write raw hexpairs", write_hex_cb },
	{ "Write Value", "Write a numeric value", writeValueCb },
	{ "Assemble", "Assemble and write instructions", assemble_cb },
	{ "Fill", "Fill a block with a repeated value", fill_cb },
	{ "io.cache", "Toggle io.cache helpers", open_menu_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem view_items[] = {
	{ "Show All Decompiler Output", "Expand the full decompiler output", show_all_decompiler_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem tools_items[] = {
	{ "Calculator", "Open the expression calculator", calculator_cb },
	{ "Assembler", "Open the assembler helper", r2_assembler_cb },
	{ "R2 Shell", "Run commands inside an r2 shell", shell_r2_cb },
	{ "System Shell", "Open a system shell", shell_system_cb },
	{ "FSMount Shell", "Browse mounted filesystems", shell_fs_cb },
	{ "R2JS Shell", "Open an R2JS shell", shell_r2js_cb },
	{ "File Manager", "Open the file manager", shell_mmc_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem search_items[] = {
	{ "String (Whole Bin)", "Search strings in the whole binary", string_whole_bin_cb },
	{ "String (Data Sections)", "Search strings in data sections only", string_data_sec_cb },
	{ "ROP", "Search for ROP gadgets", rop_cb },
	{ "Magic", "Run magic signatures", magic_cb },
	{ "Code", "Search for code sequences", code_cb },
	{ "Hexpairs", "Search for raw hexpairs", hexpairs_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem emulate_items[] = {
	{ "Step From", "Emulate from the current address", esil_init_cb },
	{ "Step To", "Emulate until a target address", esil_step_to_cb },
	{ "Step Range", "Emulate a range of addresses", esil_step_range_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem debug_items[] = {
	{ "Breakpoints", "Open the breakpoints panel", break_points_cb },
	{ "Watchpoints", "Open the watchpoints panel", watch_points_cb },
	{ "Continue", "Resume execution", continue_cb },
	{ "Step", "Single-step into the next instruction", step_cb },
	{ "Step Over", "Single-step over the next instruction", step_over_cb },
	{ "Reload", "Reload the current debugging session", reload_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem analyze_items[] = {
	{ "Function", "Analyze the current function", function_cb },
	{ "Symbols", "Analyze symbols into functions and metadata", symbols_cb },
	{ "Program", "Run broad program analysis", program_cb },
	{ "BasicBlocks", "Analyze basic blocks", basic_blocks_cb },
	{ "Preludes", "Find function preludes", aap_cb },
	{ "Emulation", "Analyze through emulation", aae_cb },
	{ "Calls", "Analyze calls and callees", calls_cb },
	{ "References", "Analyze references", references_cb },
	{ "Plugins...", "Browse analysis plugin commands", open_menu_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem help_items[] = {
	{ "License", "Show the software license", license_cb },
	{ "Version", "Show the short version", version_cb },
	{ "Full Version", "Show the full version report", version2_cb },
	{ "Fortune", "Print a random fortune", fortune_cb },
	{ "2048", "Open the 2048 game", game_cb },
	{ "Manpages...", "Browse bundled manpages", open_menu_cb },
	{ "Toggle Help", "Toggle the panels help view", help_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem reopen_items[] = {
	{ "In Read+Write", "Reopen the file in read-write mode", rw_cb },
	{ "In Debugger", "Reopen the file in debugger mode", debugger_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem loadlayout_items[] = {
	{ "Saved..", "Choose one of the saved layouts", open_menu_cb },
	{ "Default", "Restore the default layout", load_layout_default_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem iocache_items[] = {
	{ "On", "Enable io.cache", io_cache_on_cb },
	{ "Off", "Disable io.cache", io_cache_off_cb },
	{ NULL, NULL, NULL }
};

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
	r_panels_add_menu_items (core, "Settings", settings_items, menus_Settings, R_ARRAY_SIZE (menus_Settings), open_menu_cb);
	r_panels_add_menu_items (core, "Edit", edit_items, menus_Edit, R_ARRAY_SIZE (menus_Edit), add_cmd_panel);
	r_panels_add_menu_items_sorted (core, "View", view_items, menus_View, R_ARRAY_SIZE (menus_View), add_cmd_panel);
	r_panels_add_menu_items (core, "Tools", tools_items, menus_Tools, R_ARRAY_SIZE (menus_Tools), NULL);
	r_panels_add_menu_items (core, "Search", search_items, menus_Search, R_ARRAY_SIZE (menus_Search), NULL);
	r_panels_add_menu_items (core, "Emulate", emulate_items, menus_Emulate, R_ARRAY_SIZE (menus_Emulate), NULL);
	r_panels_add_menu_items_sorted (core, "Debug", debug_items, menus_Debug, R_ARRAY_SIZE (menus_Debug), add_cmd_panel);
	r_panels_add_menu_items (core, "Analyze", analyze_items, menus_Analyze, R_ARRAY_SIZE (menus_Analyze), NULL);
	r_panels_add_menu_items (core, "Help", help_items, menus_Help, R_ARRAY_SIZE (menus_Help), help_cb);
	r_panels_add_menu_items (core, "File.Reopen...", reopen_items, menus_ReOpen, R_ARRAY_SIZE (menus_ReOpen), NULL);
	r_panels_add_menu_items (core, "Settings.Load Layout", loadlayout_items, menus_loadLayout, R_ARRAY_SIZE (menus_loadLayout), NULL);

	init_menu_saved_layout (core, "Settings.Load Layout.Saved..");
	init_menu_color_settings_layout (core, "Settings.Color Themes...");
	init_menu_manpages (core, "Help.Manpages...");
	init_menu_anal_plugins (core, "Analyze.Plugins...");

	{
		const char *parent = "Settings.Decompiler...";
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

	init_menu_disasm_settings_layout (core, "Settings.Disassembly...");
	init_menu_screen_settings_layout (core, "Settings.Screen...");
	r_panels_add_menu_items (core, "Edit.io.cache", iocache_items, menus_iocache, R_ARRAY_SIZE (menus_iocache), NULL);

	panels_menu->history = calloc (8, sizeof (RPanelsMenuItem *));
	r_panels_clear_panels_menu (core);
	panels_menu->refreshPanels = calloc (8, sizeof (RPanel *));
	return true;
}

static void demo_end(RCore *core, RConsCanvas *can) {
	bool utf8 = r_config_get_b (core->config, "scr.utf8");
	r_config_set_b (core->config, "scr.utf8", false);
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	cur->view->refresh = true;
	core->visual.firstRun = false;
	r_panels_refresh (core);
	core->visual.firstRun = true;
	r_config_set_b (core->config, "scr.utf8", utf8);
	char *s = r_cons_canvas_tostring (can);
	if (s) {
		// TODO drop utf8!!
		r_str_ansi_filter (s, NULL, NULL, -1);
		int i, h, w = r_panels_get_size (core, &h);
		for (i = h; i > 0; i--) {
			const int H = i;
			char *r = r_str_scale (s, w, H);
			r_cons_clear00 (core->cons);
			r_cons_gotoxy (core->cons, 0, (h / 2) - (H / 2)); // center
			r_cons_print (core->cons, r);
			r_cons_flush (core->cons);
			free (r);
			r_sys_usleep (3000);
		}
		r_sys_usleep (100000);
		free (s);
	}
}

static void panel_breakpoint(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	if (r_panels_check_panel_type (cur, "pd")) {
		r_core_cmd (core, "dbs $$", 0);
		cur->view->refresh = true;
	}
}

static void panel_continue(RCore *core) {
	r_core_cmd (core, "dc", 0);
}

static void handle_menu(RCore *core, const int key) {
	RPanels *panels = core->panels;
	RPanelsMenu *menu = panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	if (!parent || !parent->sub) {
		r_panels_del_menu (core);
		r_panels_del_menu (core);
		r_panels_del_menu (core);
		r_panels_del_menu (core);
		menu->n_refresh = 0;
		r_panels_set_mode (core, PANEL_MODE_DEFAULT);
		r_panels_get_cur_panel (panels)->view->refresh = true;
		r_panels_set_refresh_all (core, true, false);
		return;
	}
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_cons_switchbuf (core->cons, false);
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
				parent->selectedIndex = R_MIN (parent->n_sub - 1, parent->selectedIndex + 1);
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
			if (parent->selectedIndex > 0) {
				parent->selectedIndex--;
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
			menu->n_refresh = 0;
			r_panels_set_mode (core, PANEL_MODE_DEFAULT);
			r_panels_get_cur_panel (panels)->view->refresh = true;
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
		menu->n_refresh = 0;
		r_panels_handle_tab_key (core, false);
		break;
	case 'Z':
		menu->n_refresh = 0;
		r_panels_handle_tab_key (core, true);
		break;
	case ':':
		menu->n_refresh = 0;
		handlePrompt (core, panels);
		break;
	case '?':
		menu->n_refresh = 0;
		r_panels_toggle_help (core);
		break;
	case '"':
		menu->n_refresh = 0;
		r_panels_create_modal (core, r_panels_get_panel (panels, 0));
		r_panels_set_mode (core, PANEL_MODE_DEFAULT);
		break;
	}
}

static bool handle_console(RCore *core, RPanel *panel, const int key) {
	if (!r_panels_check_panel_type (panel, "cat $console")) {
		return false;
	}
	r_cons_switchbuf (core->cons, false);
	switch (key) {
	case 'i':
		{
			char *prompt = r_str_newf ("[0x%08"PFMT64x"]) ", core->addr);
			const char *cmd = r_cons_visual_readln (core->cons, prompt, NULL);
			if (R_STR_ISNOTEMPTY (cmd)) {
				if (!strcmp (cmd, "clear")) {
					r_core_cmd0 (core, ":>$console");
				} else {
					r_core_cmdf (core, "?e %s %s>>$console", prompt, cmd);
					r_core_cmdf (core, "%s >>$console", cmd);
				}
			}
			free (prompt);
			panel->view->refresh = true;
		}
		return true;
	case 'l':
		r_core_cmd0 (core, ":>$console");
		panel->view->refresh = true;
		return true;
	default:
		// add more things later
		break;
	}
	return false;
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

// copypasta from visual
static void prevOpcode(RCore *core) {
	RPrint *p = core->print;
	ut64 addr = 0;
	ut64 opaddr = r_panels_insoff (core, core->print->cur);
	if (r_core_prevop_addr (core, opaddr, 1, &addr)) {
		const int delta = opaddr - addr;
		p->cur -= delta;
	} else {
		p->cur -= 4;
	}
}

static void nextOpcode(RCore *core) {
	RAnalOp *aop = r_core_anal_op (core, core->addr + core->print->cur, R_ARCH_OP_MASK_BASIC);
	RPrint *p = core->print;
	if (aop) {
		p->cur += aop->size;
		r_anal_op_free (aop);
	} else {
		p->cur += 4;
	}
}

static void panels_process(RCore *core, RPanels *panels) {
	if (!panels) {
		return;
	}
	int i, okey, key;
	RPanelsRoot *panels_root = core->panels_root;
	RPanels *prev;
	prev = core->panels;
	core->panels = panels;
	panels->autoUpdate = true;
	int h, w = r_panels_get_size (core, &h);
	panels->can = r_panels_create_new_canvas (core, w, h);
	r_panels_set_refresh_all (core, false, true);

	r_cons_switchbuf (core->cons, false);

	int originCursor = core->print->cur;
	core->print->cur = 0;
	core->print->cur_enabled = false;
	core->print->col = 0;

	bool originVmode = core->vmode;
	core->vmode = true;

	bool o_interactive = r_cons_is_interactive (core->cons);
	r_cons_set_interactive (core->cons, true);
	r_core_visual_showcursor (core, false);
repeat:
	r_cons_enable_mouse (core->cons, r_config_get_i (core->config, "scr.wheel"));
	core->panels = panels;
	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = core;
	core->cons->event_resize = (RConsEvent) r_panels_do_panels_refreshQueued;
	r_panels_layout_refresh (core);
	RPanel *cur = r_panels_get_cur_panel (panels);
	r_cons_set_raw (core->cons, true);
	if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
		if (panels->mode == PANEL_MODE_MENU) {
			panels->fun = PANEL_FUN_NOFUN;
			r_panels_reset_snow (panels);
			goto repeat;
		}
		okey = r_cons_readchar_timeout (core->cons, 300);
		if (okey == -1) {
			cur->view->refresh = true;
			goto repeat;
		}
	} else {
		okey = r_cons_readchar (core->cons);
	}

	key = r_cons_arrow_to_hjkl (core->cons, okey);
virtualmouse:
	if (r_panels_handle_mouse (core, cur, &key)) {
		if (panels_root->root_state != DEFAULT) {
			goto exit;
		}
		goto repeat;
	}

	r_cons_switchbuf (core->cons, true);

	if (panels->mode == PANEL_MODE_MENU) {
		handle_menu (core, key);
		if (r_panels_check_root_state (core, QUIT) ||
				r_panels_check_root_state (core, ROTATE)) {
			goto exit;
		}
		goto repeat;
	}

	if (core->print->cur_enabled) {
		if (r_panels_handle_cursor_mode (core, key)) {
			goto repeat;
		}
	}

	if (panels->mode == PANEL_MODE_ZOOM) {
		if (r_panels_handle_zoom_mode (core, key)) {
			goto repeat;
		}
	}

	if (panels->mode == PANEL_MODE_WINDOW) {
		if (r_panels_handle_window_mode (core, key)) {
			goto repeat;
		}
	}

	if (r_panels_check_panel_type (cur, "pd") && '0' < key && key <= '9') {
		ut8 ch = key;
		r_core_visual_jump (core, ch);
		r_panels_set_panel_addr (core, cur, core->addr);
		goto repeat;
	}

	const char *cmd;
	RConsCanvas *can = panels->can;
	if (handle_console (core, cur, key)) {
		goto repeat;
	}
	switch (key) {
	case 'u':
		r_panels_undo_seek (core);
		break;
	case 'U':
		r_panels_redo_seek (core);
		break;
	case 'p':
		r_panels_rotate_panels (core, false);
		break;
	case 'P':
		r_panels_rotate_panels (core, true);
		break;
	case '.':
		if (r_panels_check_panel_type (cur, "pd")) {
			ut64 addr = r_debug_reg_get (core->dbg, "PC");
			if (addr && addr != UT64_MAX) {
				r_core_seek (core, addr, true);
			} else {
				addr = r_num_get (core->num, "entry0");
				if (addr && addr != UT64_MAX) {
					r_core_seek (core, addr, true);
				}
			}
			r_panels_set_panel_addr (core, cur, core->addr);
		} else if (!strcmp (cur->model->title, "Stack")) {
			r_config_set_i (core->config, "stack.delta", 0);
		}
		break;
	case '?':
		r_panels_toggle_help (core);
		break;
	case 'b':
		r_core_visual_browse (core, NULL);
		break;
	case ';':
		handleComment (core);
		break;
	case '$':
		if (core->print->cur_enabled) {
			r_core_cmdf (core, "dr PC=$$+%d", core->print->cur);
		} else {
			r_core_call (core, "dr PC=$$");
		}
		break;
	case 's':
		panel_single_step_in (core);
		if (r_panels_check_panel_type (cur, "pd")) {
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case 'S':
		panel_single_step_over (core);
		if (r_panels_check_panel_type (cur, "pd")) {
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case ' ':
		r_panels_call_visual_graph (core);
		break;
	case ':':
		handlePrompt(core, panels);
		r_panels_set_panel_addr (core, cur, core->addr);
		break;
	case 'c':
		r_panels_activate_cursor (core);
		break;
	case 'C':
		{
			int color = r_config_get_i (core->config, "scr.color");
			if (++color > 2) {
				color = 0;
			}
			r_config_set_i (core->config, "scr.color", color);
			can->color = color;
			r_panels_set_refresh_all (core, true, false);
		}
		break;
	case 'r':
		if (r_config_get_i (core->config, "asm.hint.call")) {
			r_config_toggle (core->config, "asm.hint.call");
			r_config_set_b (core->config, "asm.hint.jmp", true);
		} else if (r_config_get_i (core->config, "asm.hint.jmp")) {
			r_config_toggle (core->config, "asm.hint.jmp");
			r_config_set_b (core->config, "asm.hint.emu", true);
		} else if (r_config_get_i (core->config, "asm.hint.emu")) {
			r_config_toggle (core->config, "asm.hint.emu");
			r_config_set_b (core->config, "asm.hint.lea", true);
		} else if (r_config_get_i (core->config, "asm.hint.lea")) {
			r_config_toggle (core->config, "asm.hint.lea");
			r_config_set_b (core->config, "asm.hint.call", true);
		} else {
			r_config_set_b (core->config, "asm.hint.call", true);
		}
		break;
	case 'R':
		if (r_config_get_b (core->config, "scr.randpal")) {
			r_core_call (core, "ecr");
		} else {
			r_core_call (core, "ecn");
		}
		r_panels_do_panels_refresh (core);
		break;
	case 'a':
		panels->autoUpdate = r_panels_show_status_yesno (core, 1, "Auto update On? (Y/n)");
		break;
	case 'A':
		{
			const int ocur = core->print->cur_enabled;
			r_core_visual_asm (core, core->addr);
			core->print->cur_enabled = ocur;
		}
		break;
	case 'd':
		r_core_visual_define (core, "", 0);
		break;
	case 'D':
		replace_cmd (core, "Disassembly", "pd");
		break;
	case 'j':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y++;
			core->print->cur++;
		} else if (core->print->cur_enabled) {
			RPanel *cp = r_panels_get_cur_panel (core->panels);
			if (cp) {
				if (cur->model->directionCb) {
					cur->model->directionCb (core, 'j');
					break;
				} else {
					direction_panels_cursor_cb (core, 'j');
				}
			}
			nextOpcode (core);
		} else {
			if (cur->model->directionCb) {
				r_cons_switchbuf (core->cons, false);
				cur->model->directionCb (core, 'j');
			}
		}
		break;
	case 'k':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y--;
		} else if (core->print->cur_enabled) {
			RPanel *cp = r_panels_get_cur_panel (core->panels);
			if (cp) {
				if (strstr (cp->model->cmd, "pd")) {
					if (cur->model->directionCb) {
						cur->model->directionCb (core, 'k');
						break;
					}
					int op = cp->view->curpos;
					prevOpcode (core);
					if (op == cp->view->curpos) {
						cp->view->curpos--;
						prevOpcode (core);
					}
				} else {
					direction_panels_cursor_cb (core, 'k');
				}
			}
		} else if (cur->model->directionCb) {
			prevOpcode (core);
			r_cons_switchbuf (core->cons, false);
			cur->model->directionCb (core, 'k');
		}
		break;
	case 'K':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y -= 5;
		} else {
			r_cons_switchbuf (core->cons, false);
			if (cur->model->directionCb) {
				for (i = 0; i < r_panels_get_cur_panel (panels)->view->pos.h / 2 - 6; i++) {
					cur->model->directionCb (core, 'k');
				}
			} else {
				if (core->print->cur_enabled) {
					size_t i;
					for (i = 0; i < 4; i++) {
						prevOpcode (core);
					}
				}
			}
		}
		break;
	case 'J':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y += 5;
		} else {
			r_cons_switchbuf (core->cons, false);
			if (cur->model->directionCb) {
				for (i = 0; i < r_panels_get_cur_panel (panels)->view->pos.h / 2 - 6; i++) {
					cur->model->directionCb (core, 'j');
				}
			} else {
				if (core->print->cur_enabled) {
					size_t i;
					for (i = 0; i < 4; i++) {
						nextOpcode (core);
					}
				}
			}
		}
		break;
	case 'H':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.x -= 5;
		} else {
			r_cons_switchbuf (core->cons, false);
			if (cur->model->directionCb) {
				for (i = 0; i < r_panels_get_cur_panel (panels)->view->pos.w / 3; i++) {
					cur->model->directionCb (core, 'h');
				}
			}
		}
		break;
	case 'L':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.x += 5;
		} else {
			r_cons_switchbuf (core->cons, false);
			if (cur->model->directionCb) {
				for (i = 0; i < r_panels_get_cur_panel (panels)->view->pos.w / 3; i++) {
					cur->model->directionCb (core, 'l');
				}
			}
		}
		break;
	case 'f':
		r_panels_set_filter (core, cur);
		break;
	case 'F':
		r_panels_reset_filter (core, cur);
		break;
	case '_':
		r_panels_hudstuff (core);
		break;
	case '\\':
		r_core_visual_hud (core);
		break;
	case '"':
		r_cons_switchbuf (core->cons, false);
		r_panels_create_modal (core, cur);
		if (r_panels_check_root_state (core, ROTATE)) {
			goto exit;
		}
		// all panels containing decompiler data should be cached
		RPanel *p = r_panels_get_cur_panel (core->panels);
		r_panels_cache_white_list (core, p);
		break;
	case 'O':
		handle_print_rotate (core);
		break;
	case 'n':
		if (r_panels_check_panel_type (cur, "pd")) {
			r_core_seek_next (core, r_config_get (core->config, "scr.nkey"));
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case 'N':
		if (r_panels_check_panel_type (cur, "pd")) {
			r_core_seek_previous (core, r_config_get (core->config, "scr.nkey"));
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case 'x':
		handle_refs (core, cur, UT64_MAX);
		break;
	case 'X':
		r_panels_dismantle_del_panel (core, cur, panels->curnode);
		break;
	case 9: // TAB
		r_panels_handle_tab_key (core, false);
		break;
	case 'Z': // SHIFT-TAB
		r_panels_handle_tab_key (core, true);
		break;
	case 'M':
		handle_vmark (core);
		break;
	case 'E':
		r_core_visual_colors (core);
		break;
	case 'e':
	{
		char *cmd = r_panels_show_status_input (core, "New command: ");
		if (R_STR_ISNOTEMPTY (cmd)) {
			replace_cmd (core, cmd, cmd);
		}
		free (cmd);
	}
		break;
	case 'm':
		r_panels_set_mode (core, PANEL_MODE_MENU);
		r_panels_clear_panels_menu (core);
		r_panels_get_cur_panel (panels)->view->refresh = true;
		break;
	case 'g':
		r_core_visual_showcursor (core, true);
		r_core_visual_offset (core);
		r_core_visual_showcursor (core, false);
		r_panels_set_panel_addr (core, cur, core->addr);
		break;
	case 'G':
		{
			const char *hl = r_config_get (core->config, "scr.highlight");
			if (hl) {
				ut64 addr = r_num_math (core->num, hl);
				r_panels_set_panel_addr (core, cur, addr);
				// r_io_sundo_push (core->io, addr, false); // doesnt seems to work
			}
		}
		break;
	case 'h':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.x--;
			core->print->cur--;
		} else if (core->print->cur_enabled) {
			cur->model->directionCb (core, 'h');
			RPanel *cp = r_panels_get_cur_panel (core->panels);
			if (cp) {
				core->cons->cpos.x--;
				cp->view->curpos--;
			}
		} else if (cur->model->directionCb) {
			r_cons_switchbuf (core->cons, false);
			cur->model->directionCb (core, 'h');
		}
		break;
	case 'l':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.x++;
		} else if (cur->model->directionCb) {
			cur->model->directionCb (core, 'l');
			r_cons_switchbuf (core->cons, false);
		} else if (core->print->cur_enabled) {
			core->print->cur++;
		}
		break;
	case 'v':
		r_core_visual_anal (core, NULL);
		break;
	case 'V':
		r_panels_call_visual_graph (core);
		break;
	case ']':
		if (r_panels_check_panel_type (cur, "xc")) {
			r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") + 1);
		} else {
			int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
			r_config_set_i (core->config, "asm.cmt.col", cmtcol + 2);
		}
		cur->view->refresh = true;
		break;
	case '[':
		if (r_panels_check_panel_type (cur, "xc")) {
			r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") - 1);
		} else {
			int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
			if (cmtcol > 2) {
				r_config_set_i (core->config, "asm.cmt.col", cmtcol - 2);
			}
		}
		cur->view->refresh = true;
		break;
	case '/':
		r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
		break;
	case 'z':
		if (panels->curnode > 0) {
			r_panels_swap_panels (panels, 0, panels->curnode);
			r_panels_set_curnode (core, 0);
		}
		break;
	case '`':
		if (cur->model->rotateCb) {
			cur->model->rotateCb (core, false); // || true
			cur->view->refresh = true;
		}
		break;
	case 'i':
		insert_value (core, 'x');
		break;
	case 'I':
		insert_value (core, 'a');
		break;
	case 'o':
		{
			const char *s = "hexdump\n" \
				"esil\n" \
				"comments\n" \
				"analyze function\n" \
				"analyze program\n" \
				"bytes\n" \
				"address\n" \
				"disasm\n" \
				"entropy\n";
			char *format = r_cons_hud_line_string (core->cons, s);
			if (format) {
				if (!strcmp (format, "hexdump")) {
					replace_cmd (core, "px", "px");
				} else if (!strcmp (format, "analyze function")) {
					r_core_call (core, "af");
					r_core_call (core, "aaef");
				} else if (!strcmp (format, "analyze program")) {
					r_core_call (core, "aaa");
				} else if (!strcmp (format, "address")) {
					r_config_toggle (core->config, "asm.addr");
				} else if (!strcmp (format, "esil")) {
					r_config_toggle (core->config, "asm.esil");
				} else if (!strcmp (format, "bytes")) {
					r_config_toggle (core->config, "asm.bytes");
				} else if (!strcmp (format, "comments")) {
					r_config_toggle (core->config, "asm.comments");
				} else if (!strcmp (format, "disasm")) {
					replace_cmd (core, "pd", "pd");
				} else if (!strcmp (format, "entropy")) {
					replace_cmd (core, "p=e 100", "p=e 100");
				}
				free (format);
			}
		}
		return;
	case 't':
		r_panels_handle_tab (core);
		if (panels_root->root_state != DEFAULT) {
			goto exit;
		}
		break;
	case 'T':
		if (panels_root->n_panels > 1) {
			r_panels_set_root_state (core, DEL);
			goto exit;
		}
		break;
	case 'w':
		r_panels_toggle_window_mode (core);
		break;
	case 'W':
		r_panels_move_panel_to_dir (core, cur, panels->curnode);
		break;
	case 0x0d: // "\\n"
		if (r_config_get_b (core->config, "scr.cursor")) {
			key = 0;
			r_cons_set_click (core->cons, core->cons->cpos.x, core->cons->cpos.y);
			goto virtualmouse;
		} else {
			r_panels_toggle_zoom_mode (core);
		}
		break;
	case '|':
		{
			RPanel *p = r_panels_get_cur_panel (panels);
			r_panels_split_panel (core, p, p->model->title, p->model->cmd, true);
			break;
		}
	case '-':
		{
			RPanel *p = r_panels_get_cur_panel (panels);
			r_panels_split_panel (core, p, p->model->title, p->model->cmd, false);
			break;
		}
	case '*':
		if (r_panels_check_func (core)) {
			r_cons_canvas_free (can);
			panels->can = NULL;
			replace_cmd (core, "Decompiler", "pdc");
			int h, w = r_panels_get_size (core, &h);
			panels->can = r_panels_create_new_canvas (core, w, h);
		}
		break;
	case '(':
		if (panels->fun != PANEL_FUN_SNOW && panels->fun != PANEL_FUN_SAKURA) {
			//TODO: Refactoring the FUN if bored af
			panels->fun = PANEL_FUN_SNOW;
			// panels->fun = PANEL_FUN_SAKURA;
		} else {
			panels->fun = PANEL_FUN_NOFUN;
			r_panels_reset_snow (panels);
		}
		break;
	case ')':
		rotate_asmemu (core, r_panels_get_cur_panel (panels));
		break;
	case '&':
		r_panels_toggle_cache (core, r_panels_get_cur_panel (panels));
		break;
	case R_CONS_KEY_F1:
		cmd = r_config_get (core->config, "key.f1");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F2:
		cmd = r_config_get (core->config, "key.f2");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			panel_breakpoint (core);
		}
		break;
	case R_CONS_KEY_F3:
		cmd = r_config_get (core->config, "key.f3");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F4:
		cmd = r_config_get (core->config, "key.f4");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F5:
		cmd = r_config_get (core->config, "key.f5");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F6:
		cmd = r_config_get (core->config, "key.f6");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F7:
		cmd = r_config_get (core->config, "key.f7");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			panel_single_step_in (core);
			if (r_panels_check_panel_type (cur, "pd")) {
				r_panels_set_panel_addr (core, cur, core->addr);
			}
		}
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			panel_single_step_over (core);
			if (r_panels_check_panel_type (cur, "pd")) {
				r_panels_set_panel_addr (core, cur, core->addr);
			}
		}
		break;
	case R_CONS_KEY_F9:
		cmd = r_config_get (core->config, "key.f9");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			if (r_panels_check_panel_type (cur, "pd")) {
				panel_continue (core);
				r_panels_set_panel_addr (core, cur, core->addr);
			}
		}
		break;
	case R_CONS_KEY_F10:
		cmd = r_config_get (core->config, "key.f10");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F11:
		cmd = r_config_get (core->config, "key.f11");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F12:
		cmd = r_config_get (core->config, "key.f12");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case 'Q':
		r_panels_set_root_state (core, QUIT);
		goto exit;
	case '!':
		core->visual.fromVisual = true;
	case 'q':
	case -1: // EOF
		r_panels_set_root_state (core, DEL);
		if (core->panels_root->n_panels < 2) {
			if (r_config_get_i (core->config, "scr.demo")) {
				demo_end (core, can);
			}
		}
		goto exit;
	default:
		break;
	}
	goto repeat;
exit:
	if (!originVmode) {
		r_core_visual_showcursor (core, true);
	}
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	core->print->cur = originCursor;
	core->print->cur_enabled = false;
	core->print->col = 0;
	core->vmode = originVmode;
	core->panels = prev;
	r_cons_set_interactive (core->cons, o_interactive);
}

static void init_new_panels_root(RCore *core) {
	RPanelsRoot *panels_root = core->panels_root;
	RPanels *panels = r_panels_new (core);
	if (!panels) {
		return;
	}
	RPanels *prev = core->panels;
	core->panels = panels;
	panels_root->panels[panels_root->n_panels++] = panels;
	if (!init_panels_menu (core)) {
		panels_root->panels[--panels_root->n_panels] = NULL;
		r_panels_free_partial (panels);
		core->panels = prev;
		return;
	}
	if (!r_panels_alloc (core, panels)) {
		panels_root->panels[--panels_root->n_panels] = NULL;
		r_panels_free_partial (panels);
		core->panels = prev;
		return;
	}
	init_all_dbs (core);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	create_default_panels (core);
	r_panels_layout (core, panels);
	core->panels = prev;
}

#endif

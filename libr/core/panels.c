/* Copyright radare2 2014-2021 - Author: pancake, vane11ope */

#include <r_core.h>

/* few remaining static functions */
static bool __init_panels_menu(RCore *core);
static bool __init_panels(RCore *core, RPanels *panels);
static void __init_menu_screen_settings_layout(void *_core, const char *parent);
static void __init_new_panels_root(RCore *core);
static void __init_menu_color_settings_layout(void *core, const char *parent);
static void __init_menu_disasm_asm_settings_layout(void *_core, const char *parent);
static void __set_dcb(RCore *core, RPanel *p);
static void __set_pcb(RPanel *p);
static void __panels_refresh(RCore *core);

#define MENU_Y 1
#define PANEL_NUM_LIMIT 9

#define PANEL_TITLE_SYMBOLS          "Symbols"
#define PANEL_TITLE_STACK            "Stack"
#define PANEL_TITLE_XREFS_HERE       "Xrefs Here"
#define PANEL_TITLE_XREFS            "Xrefs"
#define PANEL_TITLE_REGISTERS        "Registers"
#define PANEL_TITLE_DISASSEMBLY      "Disassembly"
#define PANEL_TITLE_DISASMSUMMARY    "Disassemble Summary"
#define PANEL_TITLE_ALL_DECOMPILER   "Show All Decompiler Output"
#define PANEL_TITLE_DECOMPILER       "Decompiler"
#define PANEL_TITLE_DECOMPILER_O     "Decompiler With Offsets"
#define PANEL_TITLE_GRAPH            "Graph"
#define PANEL_TITLE_TINY_GRAPH       "Tiny Graph"
#define PANEL_TITLE_FUNCTIONS        "Functions"
#define PANEL_TITLE_FUNCTIONCALLS    "Function Calls"
#define PANEL_TITLE_BREAKPOINTS      "Breakpoints"
#define PANEL_TITLE_STRINGS_DATA     "Strings in data sections"
#define PANEL_TITLE_STRINGS_BIN      "Strings in the whole bin"
#define PANEL_TITLE_SECTIONS         "Sections"
#define PANEL_TITLE_SEGMENTS         "Segments"
#define PANEL_TITLE_COMMENTS         "Comments"

#define PANEL_CMD_SYMBOLS            "isq"
#define PANEL_CMD_XREFS_HERE         "ax."
#define PANEL_CMD_XREFS              "ax"
#define PANEL_CMD_STACK              "px"
#define PANEL_CMD_REGISTERS          "dr"
#define PANEL_CMD_DISASSEMBLY        "pd"
#define PANEL_CMD_DISASMSUMMARY      "pdsf"
#define PANEL_CMD_DECOMPILER         "pdc"
#define PANEL_CMD_DECOMPILER_O       "pddo"
#define PANEL_CMD_FUNCTION           "afl"
#define PANEL_CMD_GRAPH              "agf"
#define PANEL_CMD_TINYGRAPH          "agft"
#define PANEL_CMD_HEXDUMP            "xc"
#define PANEL_CMD_CONSOLE            "$console"

#define PANEL_CONFIG_MENU_MAX    64
#define PANEL_CONFIG_PAGE        10
#define PANEL_CONFIG_SIDEPANEL_W 60
#define PANEL_CONFIG_RESIZE_W    4
#define PANEL_CONFIG_RESIZE_H    4

#define COUNT(x) (sizeof((x)) / sizeof((*x)) - 1)

// TODO: kill mutable globals
static bool firstRun = true;
static bool fromVisual = false;
static char *menus_Colors[128];

typedef enum {
	LEFT,
	RIGHT,
	UP,
	DOWN
} Direction;

static const char *panels_dynamic [] = {
	"Disassembly", "Stack", "Registers",
	NULL
};

static const char *panels_static [] = {
	"Disassembly", "Functions", "Symbols",
	NULL
};

static const char *menus[] = {
	"File", "Settings", "Edit", "View", "Tools", "Search", "Emulate", "Debug", "Analyze", "Help",
	NULL
};

static const char *menus_File[] = {
	"New", "Open", "ReOpen", "Close", "Save Layout", "Load Layout", "Clear Saved Layouts", "Quit",
	NULL
};

static const char *menus_Settings[] = {
	"Colors", "Decompiler", "Disassembly", "Screen",
	NULL
};

static const char *menus_ReOpen[] = {
	"In RW", "In Debugger",
	NULL
};

static const char *menus_loadLayout[] = {
	"Saved", "Default",
	NULL
};

static const char *menus_Edit[] = {
	"Copy", "Paste", "Clipboard", "Write String", "Write Hex", "Write Value", "Assemble", "Fill", "io.cache",
	NULL
};

static const char *menus_iocache[] = {
	"On", "Off",
	NULL
};

static const char *menus_View[] = {
	"Console", "Hexdump", "Disassembly", "Disassemble Summary", "Decompiler", "Decompiler With Offsets", "Graph", "Tiny Graph",
	"Functions", "Function Calls", "Sections", "Segments", PANEL_TITLE_STRINGS_DATA, PANEL_TITLE_STRINGS_BIN, "Symbols", "Imports",
	"Info", "Database",  "Breakpoints", "Comments", "Classes", "Entropy", "Entropy Fire", "Stack", "Xrefs Here", "Methods",
	"Var READ address", "Var WRITE address", "Summary", "Relocs", "Headers", "File Hashes", PANEL_TITLE_ALL_DECOMPILER,
	NULL
};

static const char *menus_Tools[] = {
	"Calculator", "R2 Shell", "System Shell",
	NULL
};

static const char *menus_Search[] = {
	"String (Whole Bin)", "String (Data Sections)", "ROP", "Code", "Hexpairs",
	NULL
};

static const char *menus_Emulate[] = {
	"Step From", "Step To", "Step Range",
	NULL
};

static const char *menus_Debug[] = {
	"Registers", "RegisterRefs", "DRX", "Breakpoints", "Watchpoints",
	"Maps", "Modules", "Backtrace", "Locals", "Continue",
	"Step", "Step Over", "Reload",
	NULL
};

static const char *menus_Analyze[] = {
	"Function", "Symbols", "Program", "BasicBlocks", "Calls", "References",
	NULL
};

static const char *menus_settings_disassembly[] = {
	"asm", "hex.section", "io.cache", "hex.pairs", "emu.str",
	NULL
};

static const char *menus_settings_disassembly_asm[] = {
	"asm.bytes", "asm.section", "asm.cmt.right", "asm.emu", "asm.var.summary",
	"asm.pseudo", "asm.flags.inbytes", "asm.arch", "asm.bits", "asm.cpu",
	NULL
};

static const char *menus_settings_screen[] = {
	"scr.bgfill", "scr.color", "scr.utf8", "scr.utf8.curvy", "scr.wheel",
	NULL
};

static const char *menus_Help[] = {
	"Toggle Help",
	"License", "Version",
	"Fortune", "2048",
	NULL
};

static const char *entropy_rotate[] = {
	"", "2", "b", "c", "d", "e", "F", "i", "j", "m", "p", "s", "z", "0",
	NULL
};

static char *hexdump_rotate[] = {
	"xc", "pxa", "pxr", "prx", "pxb", "pxh", "pxw", "pxq", "pxd", "pxr",
	NULL
};

static const char *register_rotate[] = {
	"", "=", "r", "??", "C", "i", "o",
	NULL
};

static const char *function_rotate[] = {
	"l", "i", "x",
	NULL
};

static const char *cache_white_list_cmds[] = {
	"pdc", "pddo", "agf", "Help",
	NULL
};

static const char *help_msg_panels[] = {
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
	"f",        "set/add filter keywords",
	"F",        "remove all the filters",
	"g",        "go/seek to given offset",
	"G",        "go/seek to highlight",
	"i",        "insert hex",
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
	"xX",       "show xrefs/refs of current function from/to data/code",
	"z",        "swap current panel with the first one",
	NULL
};

static const char *help_msg_panels_window[] = {
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

static const char *help_msg_panels_zoom[] = {
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
	"xX",       "show xrefs/refs of current function from/to data/code",
	"q/Q/Enter","quit zoom mode",
	NULL
};

static RPanel *__get_panel(RPanels *panels, int i) {
	return (panels && i < PANEL_NUM_LIMIT)? panels->panel[i]: NULL;
}

static void __update_edge_x(RCore *core, int x) {
	RPanels *panels = core->panels;
	int i, j;
	int tmp_x = 0;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p0 = __get_panel (panels, i);
		if (p0 && (p0->view->pos.x - 2 <= panels->mouse_orig_x &&
				panels->mouse_orig_x <= p0->view->pos.x + 2)) {
			tmp_x = p0->view->pos.x;
			p0->view->pos.x += x;
			p0->view->pos.w -= x;
			for (j = 0; j < panels->n_panels; j++) {
				RPanel *p1 = __get_panel (panels, j);
				if (p1 && (p1->view->pos.x + p1->view->pos.w - 1 == tmp_x)) {
					p1->view->pos.w += x;
				}
			}
		}
	}
}

static void __update_edge_y(RCore *core, int y) {
	RPanels *panels = core->panels;
	size_t i, j;
	int tmp_y = 0;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p0 = __get_panel (panels, i);
		if (p0 && (p0->view->pos.y - 2 <= panels->mouse_orig_y &&
				panels->mouse_orig_y <= p0->view->pos.y + 2)) {
			tmp_y = p0->view->pos.y;
			p0->view->pos.y += y;
			p0->view->pos.h -= y;
			for (j = 0; j < panels->n_panels; j++) {
				RPanel *p1 = __get_panel (panels, j);
				if (p1 && (p1->view->pos.y + p1->view->pos.h - 1 == tmp_y)) {
					p1->view->pos.h += y;
				}
			}
		}
	}
}

static bool __check_if_mouse_x_illegal(RCore *core, int x) {
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	const int edge_x = 1;
	if (x <= edge_x || can->w - edge_x <= x) {
		return true;
	}
	return false;
}

static bool __check_if_mouse_y_illegal(RCore *core, int y) {
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	const int edge_y = 0;
	if (y <= edge_y || can->h - edge_y <= y) {
		return true;
	}
	return false;
}

static bool __check_if_mouse_x_on_edge(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	const int edge_x = r_config_get_i (core->config, "scr.panelborder")? 3: 1;
	int i = 0;
	for (; i < panels->n_panels; i++) {
		RPanel *panel = __get_panel (panels, i);
		if (panel && (x > panel->view->pos.x - (edge_x - 1) && x <= panel->view->pos.x + edge_x)) {
			panels->mouse_on_edge_x = true;
			panels->mouse_orig_x = x;
			return true;
		}
	}
	return false;
}

static bool __check_if_mouse_y_on_edge(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	const int edge_y = r_config_get_i (core->config, "scr.panelborder")? 3: 1;
	int i = 0;
	for (; i < panels->n_panels; i++) {
		RPanel *panel = __get_panel (panels, i);
		if (panel && (x > panel->view->pos.x && x <= panel->view->pos.x + panel->view->pos.w + edge_y)) {
			if (y > 2 && y >= panel->view->pos.y && y <= panel->view->pos.y + edge_y) {
				panels->mouse_on_edge_y = true;
				panels->mouse_orig_y = y;
				return true;
			}
		}
	}
	return false;
}

static RPanel *__get_cur_panel(RPanels *panels) {
	return __get_panel (panels, panels->curnode);
}

static bool __check_if_cur_panel(RCore *core, RPanel *panel) {
	return __get_cur_panel (core->panels) == panel;
}

static bool __check_if_addr(const char *c, int len) {
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

static void __check_edge(RCore *core) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = __get_panel (panels, i);
		if (!panel) {
			continue;
		}
		if (panel->view->pos.x + panel->view->pos.w == core->panels->can->w) {
			panel->view->edge |= (1 << PANEL_EDGE_RIGHT);
		} else {
			panel->view->edge &= (1 << PANEL_EDGE_BOTTOM);
		}
		if (panel->view->pos.y + panel->view->pos.h == core->panels->can->h) {
			panel->view->edge |= (1 << PANEL_EDGE_BOTTOM);
		} else {
			panel->view->edge &= (1 << PANEL_EDGE_RIGHT);
		}
	}
}

static void __shrink_panels_forward(RCore *core, int target) {
	RPanels *panels = core->panels;
	int i = target;
	for (; i < panels->n_panels - 1; i++) {
		panels->panel[i] = panels->panel[i + 1];
	}
}

static void __shrink_panels_backward(RCore *core, int target) {
	RPanels *panels = core->panels;
	int i = target;
	for (; i > 0; i--) {
		panels->panel[i] = panels->panel[i - 1];
	}
}

static void __cache_white_list(RCore *core, RPanel *panel) {
	int i = 0;
	for (; i < COUNT (cache_white_list_cmds); i++) {
		if (!strcmp (panel->model->cmd, cache_white_list_cmds[i])) {
			panel->model->cache = true;
			return;
		}
	}
	panel->model->cache = false;
}

static char *__search_db(RCore *core, const char *title) {
	RPanels *panels = core->panels;
	if (!panels->db) {
		return NULL;
	}
	char *out = sdb_get (panels->db, title, 0);
	if (out) {
		return out;
	}
	return NULL;
}

static int __show_status(RCore *core, const char *msg) {
	r_cons_gotoxy (0, 0);
	r_cons_printf (R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, core->cons->context->pal.graph_box2, msg);
	r_cons_flush ();
	return r_cons_readchar ();
}

static bool __show_status_yesno(RCore *core, int def, const char *msg) {
	r_cons_gotoxy (0, 0);
	r_cons_flush ();
	return r_cons_yesno (def, R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, core->cons->context->pal.graph_box2, msg);
}

static char *__show_status_input(RCore *core, const char *msg) {
	char *n_msg = r_str_newf (R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, core->cons->context->pal.graph_box2, msg);
	r_cons_gotoxy (0, 0);
	r_cons_flush ();
	char *out = r_cons_input (n_msg);
	free (n_msg);
	return out;
}

static bool __check_panel_type(RPanel *panel, const char *type) {
	if (!panel || !panel->model->cmd || !type) {
		return false;
	}
	char *tmp = r_str_new (panel->model->cmd);
	int n = r_str_split (tmp, ' ');
	if (!n) {
		free (tmp);
		return false;
	}
	const char *base = r_str_word_get0 (tmp, 0);
	if (R_STR_ISEMPTY (base)) {
		free (tmp);
		return false;
	}
	int len = strlen (type);
	if (!strcmp (type, PANEL_CMD_DISASSEMBLY)) {
		if (!strncmp (tmp, type, len) &&
				strcmp (panel->model->cmd, PANEL_CMD_DECOMPILER) &&
				strcmp (panel->model->cmd, PANEL_CMD_DECOMPILER_O) &&
				strcmp (panel->model->cmd, PANEL_CMD_DISASMSUMMARY)) {
			free (tmp);
			return true;
		}
		free (tmp);
		return false;
	}
	if (!strcmp (type, PANEL_CMD_STACK)) {
		if (!strcmp (tmp, PANEL_CMD_STACK)) {
			free (tmp);
			return true;
		}
		free (tmp);
		return false;
	}
	if (!strcmp (type, PANEL_CMD_HEXDUMP)) {
		int i = 0;
		for (; i < COUNT (hexdump_rotate); i++) {
			if (!strcmp (tmp, hexdump_rotate[i])) {
				free (tmp);
				return true;
			}
		}
		free (tmp);
		return false;
	}
	free (tmp);
	return !strncmp (panel->model->cmd, type, len);
}

static bool __check_root_state(RCore *core, RPanelsRootState state) {
	return core->panels_root->root_state == state;
}

static bool search_db_check_panel_type (RCore *core, RPanel *panel, const char *ch) {
	char *str = __search_db (core, ch);
	bool ret = str && __check_panel_type (panel, str);
	free (str);
	return ret;
}

//TODO: Refactroing
static bool __is_abnormal_cursor_type(RCore *core, RPanel *panel) {
	if (__check_panel_type (panel, PANEL_CMD_SYMBOLS) || __check_panel_type (panel, PANEL_CMD_FUNCTION)) {
		return true;
	}
	if (search_db_check_panel_type (core, panel, PANEL_TITLE_DISASMSUMMARY)) {
		return true;
	}
	if (search_db_check_panel_type (core, panel, PANEL_TITLE_STRINGS_DATA)) {
		return true;
	}
	if (search_db_check_panel_type (core, panel, PANEL_TITLE_STRINGS_BIN)) {
		return true;
	}
	if (search_db_check_panel_type (core, panel, PANEL_TITLE_BREAKPOINTS)) {
		return true;
	}
	if (search_db_check_panel_type (core, panel, PANEL_TITLE_SECTIONS)) {
		return true;
	}
	if (search_db_check_panel_type (core, panel, PANEL_TITLE_SEGMENTS)) {
		return true;
	}
	if (search_db_check_panel_type (core, panel, PANEL_TITLE_COMMENTS)) {
		return true;
	}
	return false;
}

static bool __is_normal_cursor_type(RPanel *panel) {
	return (__check_panel_type (panel, PANEL_CMD_STACK) ||
			__check_panel_type (panel, PANEL_CMD_REGISTERS) ||
			__check_panel_type (panel, PANEL_CMD_DISASSEMBLY) ||
			__check_panel_type (panel, PANEL_CMD_HEXDUMP));
}

static void __set_cmd_str_cache(RCore *core, RPanel *p, char *s) {
	free (p->model->cmdStrCache);
	p->model->cmdStrCache = s;
	__set_dcb (core, p);
	__set_pcb (p);
}

static void __set_decompiler_cache(RCore *core, char *s) {
	RAnalFunction *func = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	if (func) {
		if (core->panels_root->cur_pdc_cache) {
			sdb_ptr_set (core->panels_root->cur_pdc_cache, r_num_as_string (NULL, func->addr, false), r_str_new (s), 0);
		} else {
			Sdb *sdb = sdb_new0 ();
			const char *pdc_now = r_config_get (core->config, "cmd.pdc");
			sdb_ptr_set (sdb, r_num_as_string (NULL, func->addr, false), r_str_new (s), 0);
			core->panels_root->cur_pdc_cache = sdb;
			if (!sdb_exists (core->panels_root->pdc_caches, pdc_now)) {
				sdb_ptr_set (core->panels_root->pdc_caches, r_str_new (pdc_now), sdb, 0);
			}
		}
	}
}

static void __set_read_only(RCore *core, RPanel *p, char *s) {
	free (p->model->readOnly);
	p->model->readOnly = r_str_new (s);
	__set_dcb (core, p);
	__set_pcb (p);
}

static void __set_pos(RPanelPos *pos, int x, int y) {
	pos->x = x;
	pos->y = y;
}

static void __set_size(RPanelPos *pos, int w, int h) {
	pos->w = w;
	pos->h = h;
}

static void __set_geometry(RPanelPos *pos, int x, int y, int w, int h) {
	__set_pos (pos, x, y);
	__set_size (pos, w, h);
}

static void __set_panel_addr(RCore *core, RPanel *panel, ut64 addr) {
	panel->model->addr = addr;
}

static int __get_panel_idx_in_pos(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	int i = -1;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __get_panel (panels, i);
		if (p && (x >= p->view->pos.x && x < p->view->pos.x + p->view->pos.w)) {
			if (y >= p->view->pos.y && y < p->view->pos.y + p->view->pos.h) {
				break;
			}
		}
	}
	return i;
}

static void __handlePrompt(RCore *core, RPanels *panels) {
	r_core_visual_prompt_input (core);
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __get_panel (panels, i);
		if (p && __check_panel_type (p, PANEL_CMD_DISASSEMBLY)) {
			__set_panel_addr (core, p, core->offset);
			break;
		}
	}
}

static void __menu_panel_print(RConsCanvas *can, RPanel *panel, int x, int y, int w, int h) {
	(void) r_cons_canvas_gotoxy (can, panel->view->pos.x + 2, panel->view->pos.y + 2);
	char *text = r_str_ansi_crop (panel->model->title, x, y, w, h);
	if (text) {
		r_cons_canvas_write (can, text);
		free (text);
	} else {
		r_cons_canvas_write (can, panel->model->title);
	}
}

static void __update_help_contents(RCore *core, RPanel *panel) {
	char *read_only = panel->model->readOnly;
	char *text = NULL;
	int sx = panel->view->sx;
	int sy = R_MAX (panel->view->sy, 0);
	int x = panel->view->pos.x;
	int y = panel->view->pos.y;
	int w = panel->view->pos.w;
	int h = panel->view->pos.h;
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	(void) r_cons_canvas_gotoxy (can, x + 2, y + 2);
	if (sx < 0) {
		char *white = (char*)r_str_pad (' ', 128);
		int idx = R_MIN (-sx, strlen (white) - 1);
		white[idx] = 0;
		text = r_str_ansi_crop (read_only,
				0, sy, w + sx - 3, h - 2 + sy);
		char *newText = r_str_prefix_all (text, white);
		if (newText) {
			free (text);
			text = newText;
		}
	} else {
		text = r_str_ansi_crop (read_only,
				sx, sy, w + sx - 3, h - 2 + sy);
	}
	if (text) {
		r_cons_canvas_write (can, text);
		free (text);
	}
}

static void __update_help_title(RCore *core, RPanel *panel) {
	RConsCanvas *can = core->panels->can;
	RStrBuf *title = r_strbuf_new (NULL);
	RStrBuf *cache_title = r_strbuf_new (NULL);
	if (__check_if_cur_panel (core, panel)) {
		r_strbuf_setf (title, "%s[X] %s"Color_RESET,
				core->cons->context->pal.graph_box2, panel->model->title);
		r_strbuf_setf (cache_title, "%s[Cache] N/A"Color_RESET,
				core->cons->context->pal.graph_box2);
	} else {
		r_strbuf_setf (title, "[X]   %s   ", panel->model->title);
		r_strbuf_setf (cache_title, "[Cache] N/A");
	}
	if (r_cons_canvas_gotoxy (can, panel->view->pos.x + 1, panel->view->pos.y + 1)) {
		r_cons_canvas_write (can, r_strbuf_get (title));
	}
	if (r_cons_canvas_gotoxy (can, panel->view->pos.x + panel->view->pos.w
				- r_str_ansi_len (r_strbuf_get (cache_title)) - 2, panel->view->pos.y + 1)) {
		r_cons_canvas_write (can, r_strbuf_get (cache_title));
	}
	r_strbuf_free (cache_title);
	r_strbuf_free (title);
}

static void __update_panel_contents(RCore *core, RPanel *panel, const char *cmdstr) {
	bool b = __is_abnormal_cursor_type (core, panel) && core->print->cur_enabled;
	int sx = b ? -2 :panel->view->sx;
	int sy = R_MAX (panel->view->sy, 0);
	int x = panel->view->pos.x;
	int y = panel->view->pos.y;
	if (x >= core->panels->can->w) {
		return;
	}
	if (y >= core->panels->can->h) {
		return;
	}
	int w = panel->view->pos.w;
	int h = panel->view->pos.h;
	int graph_pad = __check_panel_type (panel, PANEL_CMD_GRAPH) ? 1 : 0;
	char *text = NULL;
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	(void) r_cons_canvas_gotoxy (can, x + 2, y + 2);
	if (sx < 0) {
		char *white = (char*)r_str_pad (' ', 128);
		int idx = R_MIN (-sx, strlen (white) - 1);
		white[idx] = 0;
		text = r_str_ansi_crop (cmdstr,
				0, sy + graph_pad, w + sx - 3, h - 2 + sy);
		char *newText = r_str_prefix_all (text, white);
		if (newText) {
			free (text);
			text = newText;
		}
	} else {
		text = r_str_ansi_crop (cmdstr, sx, sy + graph_pad, w + sx - 3, h - 2 + sy);
	}
	if (text) {
		r_cons_canvas_write (can, text);
		free (text);
	}
	if (b) {
		int sub = panel->view->curpos - panel->view->sy;
		(void) r_cons_canvas_gotoxy (can, panel->view->pos.x + 2, panel->view->pos.y + 2 + sub);
		r_cons_canvas_write (can, "*");
	}
}

static char *__apply_filter_cmd(RCore *core, RPanel *panel) {
	char *out = r_str_ndup (panel->model->cmd, strlen (panel->model->cmd) + 1024);
	if (!panel->model->filter) {
		return out;
	}
	int i;
	for (i = 0; i < panel->model->n_filter; i++) {
		char *filter = panel->model->filter[i];
		if (strlen (filter) > 1024) {
			(void)__show_status (core, "filter is too big.");
			return out;
		}
		strcat (out, "~");
		strcat (out, filter);
	}
	return out;
}

static void __update_panel_title(RCore *core, RPanel *panel) {
	RConsCanvas *can = core->panels->can;
	RStrBuf *title = r_strbuf_new (NULL);
	RStrBuf *cache_title = r_strbuf_new (NULL);
	char *cmd_title  = __apply_filter_cmd (core, panel);
	if (__check_if_cur_panel (core, panel)) {
		if (!strcmp (panel->model->title, cmd_title)) {
			r_strbuf_setf (title, "%s[X] %s"Color_RESET, core->cons->context->pal.graph_box2, panel->model->title);
		}  else {
			r_strbuf_setf (title, "%s[X] %s (%s)"Color_RESET, core->cons->context->pal.graph_box2, panel->model->title, cmd_title);
		}
		r_strbuf_setf (cache_title, "%s[Cache] %s"Color_RESET, core->cons->context->pal.graph_box2, panel->model->cache ? "On" : "Off");
	} else {
		if (!strcmp (panel->model->title, cmd_title)) {
			r_strbuf_setf (title, "[X]   %s   ", panel->model->title);
		} else {
			r_strbuf_setf (title, "[X]   %s (%s)  ", panel->model->title, cmd_title);
		}
		r_strbuf_setf (cache_title, "[Cache] %s", panel->model->cache ? "On" : "Off");
	}
	r_strbuf_slice (title, 0, panel->view->pos.w);
	r_strbuf_slice (cache_title, 0, panel->view->pos.w);
	if (r_cons_canvas_gotoxy (can, panel->view->pos.x + 1, panel->view->pos.y + 1)) {
		r_cons_canvas_write (can, r_strbuf_get (title));
	}
	if (r_cons_canvas_gotoxy (can, panel->view->pos.x + panel->view->pos.w - r_str_ansi_len (r_strbuf_get (cache_title)) - 2, panel->view->pos.y + 1)) {
		r_cons_canvas_write (can, r_strbuf_get (cache_title));
	}
	r_strbuf_free (title);
	r_strbuf_free (cache_title);
	free (cmd_title);
}

//TODO: make this a task
static void __update_pdc_contents(RCore *core, RPanel *panel, char *cmdstr) {
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	int sx = panel->view->sx;
	int sy = R_MAX (panel->view->sy, 0);
	int x = panel->view->pos.x;
	int y = panel->view->pos.y;
	int w = panel->view->pos.w;
	int h = panel->view->pos.h;
	char *text = NULL;

	(void) r_cons_canvas_gotoxy (can, x + 2, y + 2);

	if (sx < 0) {
		char *white = (char*)r_str_pad (' ', 128);
		int idx = R_MIN (-sx, strlen (white) - 1);
		white[idx] = 0;
		text = r_str_ansi_crop (cmdstr, 0, sy, w + sx - 3, h - 2 + sy);
		char *newText = r_str_prefix_all (text, white);
		if (newText) {
			free (text);
			text = newText;
		}
	} else {
		text = r_str_ansi_crop (cmdstr, sx, sy, w + sx - 3, h - 2 + sy);
	}
	if (text) {
		r_cons_canvas_write (can, text);
		free (text);
	}
}

static char *__find_cmd_str_cache(RCore *core, RPanel* panel) {
	if (panel->model->cache && panel->model->cmdStrCache) {
		return panel->model->cmdStrCache;
	}
	return NULL;
}

static char *__handle_cmd_str_cache(RCore *core, RPanel *panel, bool force_cache) {
	char *cmd = __apply_filter_cmd (core, panel);
	bool b = core->print->cur_enabled && __get_cur_panel (core->panels) != panel;
	if (b) {
		core->print->cur_enabled = false;
	}
	char *out = (*cmd == '.')
		? r_core_cmd_str_pipe (core, cmd)
		: r_core_cmd_str (core, cmd);
	if (force_cache) {
		panel->model->cache = true;
	}
	if (R_STR_ISNOTEMPTY (out)) {
		__set_cmd_str_cache (core, panel, out);
	} else {
		R_FREE (out);
	}
	free (cmd);
	if (b) {
		core->print->cur_enabled = true;
	}
	return out;
}

static void __panel_all_clear(RPanels *panels) {
	if (!panels) {
		return;
	}
	int i;
	RPanel *panel = NULL;
	for (i = 0; i < panels->n_panels; i++) {
		panel = __get_panel (panels, i);
		if (panel) {
			r_cons_canvas_fill (panels->can, panel->view->pos.x, panel->view->pos.y, panel->view->pos.w, panel->view->pos.h, ' ');
		}
	}
	r_cons_canvas_print (panels->can);
	r_cons_flush ();
}

static void __layout_default(RPanels *panels) {
	RPanel *p0 = __get_panel (panels, 0);
	if (!p0){
		eprintf("_get_panel (...,0) return null");
		return;
	}
	int h, w = r_cons_get_size (&h);
	if (panels->n_panels <= 1) {
		__set_geometry (&p0->view->pos, 0, 1, w, h - 1);
		return;
	}

	int ph = (h - 1) / (panels->n_panels - 1);
	int colpos = w - panels->columnWidth;
	__set_geometry (&p0->view->pos, 0, 1, colpos + 1, h - 1);

	int pos_x = p0->view->pos.x + p0->view->pos.w - 1;
	int i, total_h = 0;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *p = __get_panel (panels, i);
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
		__set_geometry (&p->view->pos, pos_x, 2 + (ph * (i - 1)) - 1, tmp_w, tmp_h + 1);
		total_h += 2 + (ph * (i - 1)) - 1 + tmp_h + 1;
	}
}

static void __panels_layout(RPanels *panels) {
	panels->can->sx = 0;
	panels->can->sy = 0;
	__layout_default (panels);
}

static void __layout_equal_hor(RPanels *panels) {
	int h, w = r_cons_get_size (&h);
	int pw = w / panels->n_panels;
	int i, cw = 0;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __get_panel (panels, i);
		if (!p) {
			continue;
		}
		__set_geometry(&p->view->pos, cw, 1, pw, h - 1);
		cw += pw - 1;
		if (i == panels->n_panels - 2) {
			pw = w - cw;
		}
	}
}

static void __adjust_side_panels(RCore *core) {
	int i, h;
	(void)r_cons_get_size (&h);
	RPanels *panels = core->panels;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __get_panel (panels, i);
		if (p && (p->view->pos.x == 0)) {
			if (p->view->pos.w >= PANEL_CONFIG_SIDEPANEL_W) {
				p->view->pos.x += PANEL_CONFIG_SIDEPANEL_W - 1;
				p->view->pos.w -= PANEL_CONFIG_SIDEPANEL_W - 1;
			}
		}
	}
}

static void __update_help(RCore *core, RPanels *ps) {
	const char *help = "Help";
	int i;
	for (i = 0; i < ps->n_panels; i++) {
		RPanel *p = __get_panel (ps, i);
		if (!p) {
			continue;
		}
		if (!strncmp (p->model->cmd, help, strlen (help))) {
			RStrBuf *rsb = r_strbuf_new (NULL);
			const char *title;
			const char **msg;
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
			p->model->title = r_str_dup (p->model->title, help);
			p->model->cmd = r_str_dup (p->model->cmd, help);
			r_core_visual_append_help (rsb, title, msg);
			if (!rsb) {
				break;
			}
			char *drained = r_strbuf_drain (rsb);
			__set_read_only (core, p, drained);
			free (drained);
			p->view->refresh = true;
		}
	}
}

static void __set_cursor(RCore *core, bool cur) {
	RPanel *p = __get_cur_panel (core->panels);
	RPrint *print = core->print;
	print->cur_enabled = cur;
	if (__is_abnormal_cursor_type (core, p)) {
		return;
	}
	if (cur) {
		print->cur = p->view->curpos;
	} else {
		p->view->curpos = print->cur;
	}
	print->col = print->cur_enabled ? 1: 0;
}

static void __set_mode(RCore *core, RPanelsMode mode) {
	RPanels *panels = core->panels;
	__set_cursor (core, false);
	panels->mode = mode;
	__update_help (core, panels);
}

static void __set_curnode(RCore *core, int idx) {
	RPanels *panels = core->panels;
	if (idx >= panels->n_panels) {
		idx = 0;
	}
	if (idx < 0) {
		idx = panels->n_panels - 1;
	}
	panels->curnode = idx;

	RPanel *cur = __get_cur_panel (panels);
	cur->view->curpos = cur->view->sy;
}

static bool __check_panel_num(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->n_panels + 1 > PANEL_NUM_LIMIT) {
		const char *msg = "panel limit exceeded.";
		(void)__show_status (core, msg);
		return false;
	}
	return true;
}

static void __set_rcb(RPanels *ps, RPanel *p) {
	SdbKv *kv;
	SdbListIter *sdb_iter;
	SdbList *sdb_list = sdb_foreach_list (ps->rotate_db, false);
	ls_foreach (sdb_list, sdb_iter, kv) {
		char *key =  sdbkv_key (kv);
		if (!__check_panel_type (p, key)) {
			continue;
		}
		p->model->rotateCb = (RPanelRotateCallback)sdb_ptr_get (ps->rotate_db, key, 0);
		break;
	}
	ls_free (sdb_list);
}

static void __init_panel_param(RCore *core, RPanel *p, const char *title, const char *cmd) {
	if (!p) {
		return;
	}
	RPanelModel *m = p->model;
	RPanelView *v = p->view;
	m->type = PANEL_TYPE_DEFAULT;
	m->rotate = 0;
	v->curpos = 0;
	__set_panel_addr (core, p, core->offset);
	m->rotateCb = NULL;
	__set_cmd_str_cache (core, p, NULL);
	__set_read_only (core, p, NULL);
	m->funcName = NULL;
	v->refresh = true;
	v->edge = 0;
	if (title) {
		m->title = r_str_dup (m->title, title);
		if (cmd) {
			m->cmd = r_str_dup (m->cmd, cmd);
		} else {
			m->cmd = r_str_dup (m->cmd, "");
		}
	} else if (cmd) {
		m->title = r_str_dup (m->title, cmd);
		m->cmd = r_str_dup (m->cmd, cmd);
	} else {
		m->title = r_str_dup (m->title, "");
		m->cmd = r_str_dup (m->cmd, "");
	}
	__set_pcb (p);
	if (R_STR_ISNOTEMPTY (m->cmd)) {
		__set_dcb (core, p);
		__set_rcb (core->panels, p);
		if (__check_panel_type (p, PANEL_CMD_STACK)) {
			const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
			const ut64 stackbase = r_reg_getv (core->anal->reg, sp);
			m->baseAddr = stackbase;
			__set_panel_addr (core, p, stackbase - r_config_get_i (core->config, "stack.delta"));
		}
	}
	core->panels->n_panels++;
	__cache_white_list (core, p);
	return;
}

static void __insert_panel(RCore *core, int n, const char *name, const char *cmd) {
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
	__init_panel_param (core, panel[n], name, cmd);
}

static int __add_cmd_panel(void *user) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	if (!__check_panel_num (core)) {
		return 0;
	}
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	char *cmd = __search_db (core, child->name);
	if (!cmd) {
		return 0;
	}
	int h;
	(void)r_cons_get_size (&h);
	__adjust_side_panels (core);
	__insert_panel (core, 0, child->name, cmd);
	RPanel *p0 = __get_panel (panels, 0);
	__set_geometry (&p0->view->pos, 0, 1, PANEL_CONFIG_SIDEPANEL_W, h - 1);
	__set_curnode (core, 0);
	__set_mode (core, PANEL_MODE_DEFAULT);
	free (cmd);
	return 0;
}

static void __add_help_panel(RCore *core) {
	//TODO: all these things done below are very hacky and refactoring needed
	RPanels *ps = core->panels;
	int h;
	const char *help = "Help";
	(void)r_cons_get_size (&h);
	__adjust_side_panels (core);
	__insert_panel (core, 0, help, help);
	RPanel *p0 = __get_panel (ps, 0);
	__set_geometry (&p0->view->pos, 0, 1, PANEL_CONFIG_SIDEPANEL_W, h - 1);
	__set_curnode (core, 0);
}

static char *__load_cmdf(RCore *core, RPanel *p, char *input, char *str) {
	char *ret = NULL;
	char *res = __show_status_input (core, input);
	if (res) {
		p->model->cmd = r_str_newf (str, res);
		ret = r_core_cmd_str (core, p->model->cmd);
		free (res);
	}
	return ret;
}

static int __add_cmdf_panel(RCore *core, char *input, char *str) {
	RPanels *panels = core->panels;
	if (!__check_panel_num (core)) {
		return 0;
	}
	int h;
	(void)r_cons_get_size (&h);
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	__adjust_side_panels (core);
	__insert_panel (core, 0, child->name, "");
	RPanel *p0 = __get_panel (panels, 0);
	__set_geometry (&p0->view->pos, 0, 1, PANEL_CONFIG_SIDEPANEL_W, h - 1);
	__set_cmd_str_cache (core, p0, __load_cmdf (core, p0, input, str));
	__set_curnode (core, 0);
	__set_mode (core, PANEL_MODE_DEFAULT);
	return 0;
}

static void __fix_layout_w(RCore *core) {
	RPanels *panels = core->panels;
	RList *list = r_list_new ();
	int i = 0;
	for (; i < panels->n_panels - 1; i++) {
		RPanel *p = __get_panel (panels, i);
		int32_t t = p->view->pos.x + p->view->pos.w;
		r_list_append (list, (void *)(size_t)(t));
	}
	RListIter *iter;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __get_panel (panels, i);
		int tx = p->view->pos.x;
		if (!tx) {
			continue;
		}
		int min = INT8_MAX;
		int target_num = INT8_MAX;
		bool found = false;
		void *numptr = NULL;
		r_list_foreach (list, iter, numptr) {
			st32 num = (st32)(size_t)(numptr);
			if (num - 1 == tx) {
				found = true;
				break;
			}
			int sub = num - tx;
			if (min > R_ABS (sub)) {
				min = R_ABS (sub);
				target_num = num;
			}
		}
		if (!found) {
			int t = p->view->pos.x - target_num + 1;
			p->view->pos.x = target_num - 1;
			p->view->pos.w += t;
		}
	}
}

static void __fix_layout_h(RCore *core) {
	RPanels *panels = core->panels;
	RList *list = r_list_new ();
	int h;
	(void)r_cons_get_size (&h);
	int i = 0;
	for (; i < panels->n_panels - 1; i++) {
		RPanel *p = __get_panel (panels, i);
		st32 t = p->view->pos.y + p->view->pos.h;
		r_list_append (list, (void *)(size_t)(t));
	}
	RListIter *iter;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __get_panel (panels, i);
		int ty = p->view->pos.y;
		int th = p->view->pos.h;
		if (ty == 1 || th == (h - 1)) {
			continue;
		}
		int min = INT8_MAX;
		int target_num = INT8_MAX;
		bool found = false;
		void *numptr = NULL;
		r_list_foreach (list, iter, numptr) {
			st32 num = (st32)(size_t)(numptr);
			if (num - 1 == ty) {
				found = true;
				break;
			}
			int sub = num - ty;
			if (min > R_ABS (sub)) {
				min = R_ABS (sub);
				target_num = num;
			}
		}
		if (!found) {
			int t = p->view->pos.y - target_num + 1;
			p->view->pos.y = target_num - 1;
			p->view->pos.h += t;
		}
	}
	r_list_free (list);
}

static void __fix_layout(RCore *core) {
	__fix_layout_w (core);
	__fix_layout_h (core);
}

static void show_cursor(RCore *core) {
	const bool keyCursor = r_config_get_i (core->config, "scr.cursor");
	if (keyCursor) {
		r_cons_gotoxy (core->cons->cpos.x, core->cons->cpos.y);
		r_cons_show_cursor (1);
		r_cons_flush ();
	}
}

static void __set_refresh_all(RCore *core, bool clearCache, bool force_refresh) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = __get_panel (panels, i);
		if (!force_refresh && __check_panel_type (panel, PANEL_CMD_CONSOLE)) {
			continue;
		}
		panel->view->refresh = true;
		if (clearCache) {
			__set_cmd_str_cache (core, panel, NULL);
		}
	}
}

static void __split_panel_vertical(RCore *core, RPanel *p, const char *name, const char *cmd) {
	RPanels *panels = core->panels;
	if (!__check_panel_num (core)) {
		return;
	}
	__insert_panel (core, panels->curnode + 1, name, cmd);
	RPanel *next = __get_panel (panels, panels->curnode + 1);
	int owidth = p->view->pos.w;
	p->view->pos.w = owidth / 2 + 1;
	__set_geometry (&next->view->pos, p->view->pos.x + p->view->pos.w - 1,
			p->view->pos.y, owidth - p->view->pos.w + 1, p->view->pos.h);
	__fix_layout (core);
	__set_refresh_all (core, false, true);
}

static void __split_panel_horizontal(RCore *core, RPanel *p, const char *name, const char *cmd) {
	RPanels *panels = core->panels;
	if (!__check_panel_num (core)) {
		return;
	}
	__insert_panel (core, panels->curnode + 1, name, cmd);
	RPanel *next = __get_panel (panels, panels->curnode + 1);
	int oheight = p->view->pos.h;
	p->view->curpos = 0;
	p->view->pos.h = oheight / 2 + 1;
	__set_geometry (&next->view->pos, p->view->pos.x, p->view->pos.y + p->view->pos.h - 1,
			p->view->pos.w, oheight - p->view->pos.h + 1);
	__fix_layout (core);
	__set_refresh_all (core, false, true);
}

static void __panels_check_stackbase(RCore *core) {
	if (!core || !core->panels) {
		return;
	}
	int i;
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	if (!sp) {
		return;
	}
	const ut64 stackbase = r_reg_getv (core->anal->reg, sp);
	RPanels *panels = core->panels;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *panel = __get_panel (panels, i);
		if (panel->model->cmd && __check_panel_type (panel, PANEL_CMD_STACK) && panel->model->baseAddr != stackbase) {
			panel->model->baseAddr = stackbase;
			__set_panel_addr (core, panel, stackbase - r_config_get_i (core->config, "stack.delta") + core->print->cur);
		}
	}
}

static void __del_panel(RCore *core, int pi) {
	int i;
	RPanels *panels = core->panels;
	RPanel *tmp = __get_panel (panels, pi);
	if (!tmp) {
		return;
	}
	for (i = pi; i < (panels->n_panels - 1); i++) {
		panels->panel[i] = panels->panel[i + 1];
	}
	panels->panel[panels->n_panels - 1] = tmp;
	panels->n_panels--;
	__set_curnode (core, panels->curnode);
}

static void __del_invalid_panels(RCore *core) {
	RPanels *panels = core->panels;
	int i;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *panel = __get_panel (panels, i);
		if (panel->view->pos.w < 2) {
			__del_panel (core, i);
			__del_invalid_panels (core);
			break;
		}
		if (panel->view->pos.h < 2) {
			__del_panel (core, i);
			__del_invalid_panels (core);
			break;
		}
	}
}

static void __panels_layout_refresh(RCore *core) {
	__del_invalid_panels (core);
	__check_edge (core);
	__panels_check_stackbase (core);
	__panels_refresh (core);
}

static void __reset_scroll_pos(RPanel *p) {
	p->view->sx = 0;
	p->view->sy = 0;
}

static void __activate_cursor(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	bool normal = __is_normal_cursor_type (cur);
	bool abnormal = __is_abnormal_cursor_type (core, cur);
	if (normal || abnormal) {
		if (normal && cur->model->cache) {
			if (__show_status_yesno (core, 1, "You need to turn off cache to use cursor. Turn off now?(Y/n)")) {
				cur->model->cache = false;
				__set_cmd_str_cache (core, cur, NULL);
				(void)__show_status (core, "Cache is off and cursor is on");
				__set_cursor (core, !core->print->cur_enabled);
				cur->view->refresh = true;
				__reset_scroll_pos (cur);
			} else {
				(void)__show_status (core, "You can always toggle cache by \'&\' key");
			}
			return;
		}
		__set_cursor (core, !core->print->cur_enabled);
		cur->view->refresh = true;
	} else {
		(void)__show_status (core, "Cursor is not available for the current panel.");
	}
}

ut64 __parse_string_on_cursor(RCore *core, RPanel *panel, int idx) {
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

static void __fix_cursor_up(RCore *core) {
	RPrint *print = core->print;
	if (print->cur >= 0) {
		return;
	}
	int sz = r_core_visual_prevopsz (core, core->offset + print->cur);
	if (sz < 1) {
		sz = 1;
	}
	r_core_seek_delta (core, -sz);
	print->cur += sz;
	if (print->ocur != -1) {
		print->ocur += sz;
	}
}

static void __cursor_left(RCore *core) {
	RPanel *cur = __get_cur_panel (core->panels);
	RPrint *print = core->print;
	if (__check_panel_type (cur, PANEL_CMD_REGISTERS)
			|| __check_panel_type (cur, PANEL_CMD_STACK)) {
		if (print->cur > 0) {
			print->cur--;
			cur->model->addr--;
		}
	} else if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		print->cur--;
		__fix_cursor_up (core);
	} else {
		print->cur--;
	}
}

static void __fix_cursor_down(RCore *core) {
	RPrint *print = core->print;
	bool cur_is_visible = core->offset + print->cur + 32 < print->screen_bounds;
	if (!cur_is_visible) {
		int i = 0;
		//XXX: ugly hack
		for (i = 0; i < 2; i++) {
			RAsmOp op;
			int sz = r_asm_disassemble (core->rasm,
					&op, core->block, 32);
			if (sz < 1) {
				sz = 1;
			}
			r_core_seek_delta (core, sz);
			print->cur = R_MAX (print->cur - sz, 0);
			if (print->ocur != -1) {
				print->ocur = R_MAX (print->ocur - sz, 0);
			}
		}
	}
}

static void __cursor_right(RCore *core) {
	RPanel *cur = __get_cur_panel (core->panels);
	RPrint *print = core->print;
	if (__check_panel_type (cur, PANEL_CMD_STACK) && print->cur >= 15) {
		return;
	}
	if (__check_panel_type (cur, PANEL_CMD_REGISTERS)
			|| __check_panel_type (cur, PANEL_CMD_STACK)) {
		print->cur++;
		cur->model->addr++;
	} else if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		print->cur++;
		__fix_cursor_down (core);
	} else {
		print->cur++;
	}
}

static void __cursor_up(RCore *core) {
	RPrint *print = core->print;
	ut64 addr, oaddr = core->offset + print->cur;
	if (r_core_prevop_addr (core, oaddr, 1, &addr)) {
		const int delta = oaddr - addr;
		print->cur -= delta;
	} else {
		print->cur -= 4;
	}
	__fix_cursor_up (core);
}

static void __cursor_down(RCore *core) {
	RPrint *print = core->print;
	RAnalOp *aop = r_core_anal_op (core, core->offset + print->cur, R_ANAL_OP_MASK_BASIC);
	if (aop) {
		print->cur += aop->size;
		r_anal_op_free (aop);
	} else {
		print->cur += 4;
	}
	__fix_cursor_down (core);
}

static void __save_panel_pos(RPanel* panel) {
	if (!panel) {
		return;
	}
	__set_geometry (&panel->view->prevPos, panel->view->pos.x, panel->view->pos.y,
			panel->view->pos.w, panel->view->pos.h);
}

static void __restore_panel_pos(RPanel* panel) {
	if(!panel){
		return;
	}
	__set_geometry (&panel->view->pos, panel->view->prevPos.x, panel->view->prevPos.y,
			panel->view->prevPos.w, panel->view->prevPos.h);
}

static void __maximize_panel_size(RPanels *panels) {
	RPanel *cur = __get_cur_panel (panels);
	if(!cur){
		return;
	}
	__set_geometry (&cur->view->pos, 0, 1, panels->can->w, panels->can->h - 1);
	cur->view->refresh = true;
}

static void __dismantle_panel(RPanels *ps, RPanel *p) {
	if (!p) {
		return;
	}
	RPanel *justLeftPanel = NULL, *justRightPanel = NULL, *justUpPanel = NULL, *justDownPanel = NULL;
	RPanel *tmpPanel = NULL;
	bool leftUpValid = false, leftDownValid = false, rightUpValid = false, rightDownValid = false,
		 upLeftValid = false, upRightValid = false, downLeftValid = false, downRightValid = false;
	int left[PANEL_NUM_LIMIT], right[PANEL_NUM_LIMIT], up[PANEL_NUM_LIMIT], down[PANEL_NUM_LIMIT];
	memset (left, -1, sizeof (left));
	memset (right, -1, sizeof (right));
	memset (up, -1, sizeof (up));
	memset (down, -1, sizeof (down));
	int i, ox, oy, ow, oh;
	ox = p->view->pos.x;
	oy = p->view->pos.y;
	ow = p->view->pos.w;
	oh = p->view->pos.h;
	for (i = 0; i < ps->n_panels; i++) {
		tmpPanel = __get_panel (ps, i);
		if (tmpPanel->view->pos.x + tmpPanel->view->pos.w - 1 == ox) {
			left[i] = 1;
			if (oy == tmpPanel->view->pos.y) {
				leftUpValid = true;
				if (oh == tmpPanel->view->pos.h) {
					justLeftPanel = tmpPanel;
					break;
				}
			}
			if (oy + oh == tmpPanel->view->pos.y + tmpPanel->view->pos.h) {
				leftDownValid = true;
			}
		}
		if (tmpPanel->view->pos.x == ox + ow - 1) {
			right[i] = 1;
			if (oy == tmpPanel->view->pos.y) {
				rightUpValid = true;
				if (oh == tmpPanel->view->pos.h) {
					rightDownValid = true;
					justRightPanel = tmpPanel;
				}
			}
			if (oy + oh == tmpPanel->view->pos.y + tmpPanel->view->pos.h) {
				rightDownValid = true;
			}
		}
		if (tmpPanel->view->pos.y + tmpPanel->view->pos.h - 1 == oy) {
			up[i] = 1;
			if (ox == tmpPanel->view->pos.x) {
				upLeftValid = true;
				if (ow == tmpPanel->view->pos.w) {
					upRightValid = true;
					justUpPanel = tmpPanel;
				}
			}
			if (ox + ow == tmpPanel->view->pos.x + tmpPanel->view->pos.w) {
				upRightValid = true;
			}
		}
		if (tmpPanel->view->pos.y == oy + oh - 1) {
			down[i] = 1;
			if (ox == tmpPanel->view->pos.x) {
				downLeftValid = true;
				if (ow == tmpPanel->view->pos.w) {
					downRightValid = true;
					justDownPanel = tmpPanel;
				}
			}
			if (ox + ow == tmpPanel->view->pos.x + tmpPanel->view->pos.w) {
				downRightValid = true;
			}
		}
	}
	if (justLeftPanel) {
		justLeftPanel->view->pos.w += ox + ow - (justLeftPanel->view->pos.x + justLeftPanel->view->pos.w);
	} else if (justRightPanel) {
		justRightPanel->view->pos.w = justRightPanel->view->pos.x + justRightPanel->view->pos.w - ox;
		justRightPanel->view->pos.x = ox;
	} else if (justUpPanel) {
		justUpPanel->view->pos.h += oy + oh - (justUpPanel->view->pos.y + justUpPanel->view->pos.h);
	} else if (justDownPanel) {
		justDownPanel->view->pos.h = oh + justDownPanel->view->pos.y + justDownPanel->view->pos.h - (oy + oh);
		justDownPanel->view->pos.y = oy;
	} else if (leftUpValid && leftDownValid) {
		for (i = 0; i < ps->n_panels; i++) {
			if (left[i] != -1) {
				tmpPanel = __get_panel (ps, i);
				tmpPanel->view->pos.w += ox + ow - (tmpPanel->view->pos.x + tmpPanel->view->pos.w);
			}
		}
	} else if (rightUpValid && rightDownValid) {
		for (i = 0; i < ps->n_panels; i++) {
			if (right[i] != -1) {
				tmpPanel = __get_panel (ps, i);
				tmpPanel->view->pos.w = tmpPanel->view->pos.x + tmpPanel->view->pos.w - ox;
				tmpPanel->view->pos.x = ox;
			}
		}
	} else if (upLeftValid && upRightValid) {
		for (i = 0; i < ps->n_panels; i++) {
			if (up[i] != -1) {
				tmpPanel = __get_panel (ps, i);
				tmpPanel->view->pos.h += oy + oh - (tmpPanel->view->pos.y + tmpPanel->view->pos.h);
			}
		}
	} else if (downLeftValid && downRightValid) {
		for (i = 0; i < ps->n_panels; i++) {
			if (down[i] != -1) {
				tmpPanel = __get_panel (ps, i);
				tmpPanel->view->pos.h = oh + tmpPanel->view->pos.y + tmpPanel->view->pos.h - (oy + oh);
				tmpPanel->view->pos.y = oy;
			}
		}
	}
}

static void __dismantle_del_panel(RCore *core, RPanel *p, int pi) {
	RPanels *panels = core->panels;
	if (panels->n_panels <= 1) {
		return;
	}
	__dismantle_panel (panels, p);
	__del_panel (core, pi);
}

static void __toggle_help(RCore *core) {
	RPanels *ps = core->panels;
	int i;
	for (i = 0; i < ps->n_panels; i++) {
		RPanel *p = __get_panel (ps, i);
		if (r_str_endswith (p->model->cmd, "Help")) {
			__dismantle_del_panel (core, p, i);
			if (ps->mode == PANEL_MODE_MENU) {
				__set_mode (core, PANEL_MODE_DEFAULT);
			}
			return;
		}
	}
	__add_help_panel (core);
	if (ps->mode == PANEL_MODE_MENU) {
		__set_mode (core, PANEL_MODE_DEFAULT);
	}
	__update_help (core, ps);
}

static void __reset_snow(RPanels *panels) {
	RPanel *cur = __get_cur_panel (panels);
	r_list_free (panels->snows);
	panels->snows = NULL;
	cur->view->refresh = true;
}

static void __toggle_zoom_mode(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	if (panels->mode != PANEL_MODE_ZOOM) {
		panels->prevMode = panels->mode;
		__set_mode (core, PANEL_MODE_ZOOM);
		__save_panel_pos (cur);
		__maximize_panel_size (panels);
	} else {
		__set_mode (core, panels->prevMode);
		panels->prevMode = PANEL_MODE_DEFAULT;
		__restore_panel_pos (cur);
		if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
			__reset_snow (panels);
		}
	}
}

static void __set_root_state(RCore *core, RPanelsRootState state) {
	core->panels_root->root_state = state;
}

static void __handle_tab_next(RCore *core) {
	if (core->panels_root->n_panels > 1) {
		core->panels_root->cur_panels++;
		core->panels_root->cur_panels %= core->panels_root->n_panels;
		__set_root_state (core, ROTATE);
	}
}

static void __handle_print_rotate(RCore *core) {
	if (r_config_get_i (core->config, "asm.pseudo")) {
		r_config_toggle (core->config, "asm.pseudo");
		r_config_toggle (core->config, "asm.esil");
	} else if (r_config_get_i (core->config, "asm.esil")) {
		r_config_toggle (core->config, "asm.esil");
	} else {
		r_config_toggle (core->config, "asm.pseudo");
	}
}

static void __handle_tab_prev(RCore *core) {
	if (core->panels_root->n_panels > 1) {
		core->panels_root->cur_panels--;
		if (core->panels_root->cur_panels < 0) {
			core->panels_root->cur_panels = core->panels_root->n_panels - 1;
		}
		__set_root_state (core, ROTATE);
	}
}

static void __handle_tab_name(RCore *core) {
	core->panels->name = __show_status_input (core, "tab name: ");
}

static void __handle_tab_new(RCore *core) {
	if (core->panels_root->n_panels >= PANEL_NUM_LIMIT) {
		return;
	}
	__init_new_panels_root (core);
}

static void __init_sdb(RCore *core) {
	Sdb *db = core->panels->db;
	sdb_set (db, "Symbols", "isq", 0);
	sdb_set (db, "Stack"  , "px 256@r:SP", 0);
	sdb_set (db, "Locals", "afvd", 0);
	sdb_set (db, "Registers", "dr", 0);
	sdb_set (db, "RegisterRefs", "drr", 0);
	sdb_set (db, "Disassembly", "pd", 0);
	sdb_set (db, "Disassemble Summary", "pdsf", 0);
	sdb_set (db, "Decompiler", "pdc", 0);
	sdb_set (db, "Decompiler With Offsets", "pdco", 0);
	sdb_set (db, "Graph", "agf", 0);
	sdb_set (db, "Tiny Graph", "agft", 0);
	sdb_set (db, "Info", "i", 0);
	sdb_set (db, "Database", "k ***", 0);
	sdb_set (db, "Console", "$console", 0);
	sdb_set (db, "Hexdump", "xc $r*16", 0);
	sdb_set (db, "Xrefs", "ax", 0);
	sdb_set (db, "Xrefs Here", "ax.", 0);
	sdb_set (db, "Functions", "afl", 0);
	sdb_set (db, "Function Calls", "aflm", 0);
	sdb_set (db, "Comments", "CC", 0);
	sdb_set (db, "Entropy", "p=e 100", 0);
	sdb_set (db, "Entropy Fire", "p==e 100", 0);
	sdb_set (db, "DRX", "drx", 0);
	sdb_set (db, "Sections", "iSq", 0);
	sdb_set (db, "Segments", "iSSq", 0);
	sdb_set (db, PANEL_TITLE_STRINGS_DATA, "izq", 0);
	sdb_set (db, PANEL_TITLE_STRINGS_BIN, "izzq", 0);
	sdb_set (db, "Maps", "dm", 0);
	sdb_set (db, "Modules", "dmm", 0);
	sdb_set (db, "Backtrace", "dbt", 0);
	sdb_set (db, "Breakpoints", "db", 0);
	sdb_set (db, "Imports", "iiq", 0);
	sdb_set (db, "Clipboard", "yx", 0);
	sdb_set (db, "New", "o", 0);
	sdb_set (db, "Var READ address", "afvR", 0);
	sdb_set (db, "Var WRITE address", "afvW", 0);
	sdb_set (db, "Summary", "pdsf", 0);
	sdb_set (db, "Classes", "icq", 0);
	sdb_set (db, "Methods", "ic", 0);
	sdb_set (db, "Relocs", "ir", 0);
	sdb_set (db, "Headers", "iH", 0);
	sdb_set (db, "File Hashes", "it", 0);
}

static void __free_panel_model(RPanel *panel) {
	if (!panel) {
		return;
	}
	free (panel->model->title);
	free (panel->model->cmd);
	free (panel->model->cmdStrCache);
	free (panel->model->readOnly);
	free (panel->model);
}

static void __replace_cmd(RCore *core, const char *title, const char *cmd) {
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	__free_panel_model (cur);
	cur->model = R_NEW0 (RPanelModel);
	cur->model->title = r_str_dup (cur->model->title, title);
	cur->model->cmd = r_str_dup (cur->model->cmd, cmd);
	__set_cmd_str_cache (core, cur, NULL);
	__set_panel_addr (core, cur, core->offset);
	cur->model->type = PANEL_TYPE_DEFAULT;
	__set_dcb (core, cur);
	__set_pcb (cur);
	__set_rcb (panels, cur);
	__cache_white_list (core, cur);
	__set_refresh_all (core, false, true);
}

static void __create_panel(RCore *core, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char* title, const char *cmd) {
	if (!__check_panel_num (core)) {
		return;
	}
	if (!panel) {
		return;
	}
	switch (dir) {
	case PANEL_LAYOUT_VERTICAL:
		__split_panel_vertical (core, panel, title, cmd);
		break;
	case PANEL_LAYOUT_HORIZONTAL:
		__split_panel_horizontal (core, panel, title, cmd);
		break;
	case PANEL_LAYOUT_NONE:
		__replace_cmd (core, title, cmd);
		break;
	}
}

static void __create_panel_db(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title) {
	RCore *core = (RCore *)user;
	char *cmd = sdb_get (core->panels->db, title, 0);
	if (!cmd) {
		return;
	}
	__create_panel (core, panel, dir, title, cmd);
}

static void __create_panel_input(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title) {
	RCore *core = (RCore *)user;
	char *cmd = __show_status_input (core, "Command: ");
	if (cmd) {
		__create_panel (core, panel, dir, cmd, cmd);
	}
}

static void __replace_current_panel_input(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title) {
	RCore *core = (RCore *)user;
	char *cmd = __show_status_input (core, "New command: ");
	if (R_STR_ISNOTEMPTY (cmd)) {
		__replace_cmd (core, cmd, cmd);
	}
	free (cmd);
}

static char *__search_strings(RCore *core, bool whole) {
	const char *title = whole ? PANEL_TITLE_STRINGS_BIN : PANEL_TITLE_STRINGS_DATA;
	const char *str = __show_status_input (core, "Search Strings: ");
	char *db_val = __search_db (core, title);
	char *ret = r_str_newf ("%s~%s", db_val, str);
	free (db_val);
	return ret;
}

static void __search_strings_data_create(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title) {
	RCore *core = (RCore *)user;
	__create_panel (core, panel, dir, title, __search_strings (core, false));
}

static void __search_strings_bin_create(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title) {
	RCore *core = (RCore *)user;
	__create_panel (core, panel, dir, title, __search_strings (core, true));
}

static RPanels *__get_panels(RPanelsRoot *panels_root, int i) {
	if (!panels_root || (i >= PANEL_NUM_LIMIT)) {
		return NULL;
	}
	return panels_root->panels[i];
}

static void __update_disassembly_or_open (RCore *core) {
	RPanels *panels = core->panels;
	int i;
	bool create_new = true;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __get_panel (panels, i);
		if (__check_panel_type (p, PANEL_CMD_DISASSEMBLY)) {
			__set_panel_addr (core, p, core->offset);
			create_new = false;
		}
	}
	if (create_new) {
		RPanel *panel = __get_panel (panels, 0);
		int x0 = panel->view->pos.x;
		int y0 = panel->view->pos.y;
		int w0 = panel->view->pos.w;
		int h0 = panel->view->pos.h;
		int threshold_w = x0 + panel->view->pos.w;
		int x1 = x0 + w0 / 2 - 1;
		int w1 = threshold_w - x1;

		__insert_panel (core, 0, PANEL_TITLE_DISASSEMBLY, PANEL_CMD_DISASSEMBLY);
		RPanel *p0 = __get_panel (panels, 0);
		__set_geometry (&p0->view->pos, x0, y0, w0 / 2, h0);

		RPanel *p1 = __get_panel (panels, 1);
		__set_geometry (&p1->view->pos, x1, y0, w1, h0);

		__set_cursor (core, false);
		__set_curnode (core, 0);
	}
}

static int __continue_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "dc", 0);
	r_cons_flush ();
	return 0;
}

static void __continue_modal_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED R_NULLABLE const char *title) {
	__continue_cb (user);
	__update_disassembly_or_open ((RCore *)user);
}

static void __panel_single_step_in(RCore *core) {
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_core_cmd (core, "ds", 0);
		r_core_cmd (core, ".dr*", 0);
	} else {
		r_core_cmd (core, "aes", 0);
		r_core_cmd (core, ".ar*", 0);
	}
}

static int __step_cb(void *user) {
	RCore *core = (RCore *)user;
	__panel_single_step_in (core);
	__update_disassembly_or_open (core);
	return 0;
}

static void __panel_single_step_over(RCore *core) {
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

static int __step_over_cb(void *user) {
	RCore *core = (RCore *)user;
	__panel_single_step_over (core);
	__update_disassembly_or_open (core);
	return 0;
}

static void __step_modal_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED R_NULLABLE const char *title) {
	__step_cb (user);
}

static void __panel_prompt(const char *prompt, char *buf, int len) {
	r_line_set_prompt (prompt);
	*buf = 0;
	r_cons_fgets (buf, len, 0, NULL);
}

static int __break_points_cb(void *user) {
	RCore *core = (RCore *)user;
	char buf[128];
	const char *prompt = "addr: ";

	core->cons->line->prompt_type = R_LINE_PROMPT_OFFSET;
	r_line_set_hist_callback (core->cons->line,
		&r_line_hist_offset_up,
		&r_line_hist_offset_down);
	__panel_prompt (prompt, buf, sizeof (buf));
	r_line_set_hist_callback (core->cons->line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	core->cons->line->prompt_type = R_LINE_PROMPT_DEFAULT;

	ut64 addr = r_num_math (core->num, buf);
	r_core_cmdf (core, "dbs 0x%08"PFMT64x, addr);
	return 0;
}

static void __put_breakpoints_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED R_NULLABLE const char *title) {
	__break_points_cb (user);
}

static void __step_over_modal_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED R_NULLABLE const char *title) {
	__step_over_cb (user);
}

static int __show_all_decompiler_cb(void *user) {
	RCore *core = (RCore *)user;
	RAnalFunction *func = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
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
	__handle_tab_new (core);
	RPanels *panels = __get_panels (root, root->n_panels - 1);
	r_list_foreach (optl, iter, opt) {
		if (R_STR_ISEMPTY (opt)) {
			continue;
		}
		r_config_set (core->config, "cmd.pdc", opt);
		RPanel *panel = __get_panel (panels, i++);
		panels->n_panels = i;
		panel->model->title = r_str_new (opt);
		__set_read_only (core, panel, r_core_cmd_str (core, opt));
	}
	__layout_equal_hor (panels);
	r_list_free (optl);
	free (opts);
	r_config_set (core->config, "cmd.pdc", pdc_now);
	root->cur_panels = root->n_panels - 1;
	__set_root_state (core, ROTATE);
	return 0;
}

static void __delegate_show_all_decompiler_cb(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title) {
	(void)__show_all_decompiler_cb ((RCore *)user);
}

static void __init_modal_db(RCore *core) {
	Sdb *db = core->panels->modal_db;
	SdbKv *kv;
	SdbListIter *sdb_iter;
	SdbList *sdb_list = sdb_foreach_list (core->panels->db, true);
	ls_foreach (sdb_list, sdb_iter, kv) {
		const char *key = sdbkv_key (kv);
		sdb_ptr_set (db, r_str_new (key), &__create_panel_db, 0);
	}
	sdb_ptr_set (db, "Search strings in data sections", &__search_strings_data_create, 0);
	sdb_ptr_set (db, "Search strings in the whole bin", &__search_strings_bin_create, 0);
	sdb_ptr_set (db, "Create New", &__create_panel_input, 0);
	sdb_ptr_set (db, "Change Command of Current Panel", &__replace_current_panel_input, 0);
	sdb_ptr_set (db, PANEL_TITLE_ALL_DECOMPILER, &__delegate_show_all_decompiler_cb, 0);
	if (r_config_get_b (core->config, "cfg.debug")) {
		sdb_ptr_set (db, "Put Breakpoints", &__put_breakpoints_cb, 0);
		sdb_ptr_set (db, "Continue", &__continue_modal_cb, 0);
		sdb_ptr_set (db, "Step", &__step_modal_cb, 0);
		sdb_ptr_set (db, "Step Over", &__step_over_modal_cb, 0);
	}
}

static void __renew_filter(RPanel *panel, int n) {
	panel->model->n_filter = 0;
	char **filter = calloc (sizeof (char *), n);
	if (!filter) {
		panel->model->filter = NULL;
		return;
	}
	panel->model->filter = filter;
}

static void __reset_filter(RCore *core, RPanel *panel) {
	free (panel->model->filter);
	panel->model->filter = NULL;
	__renew_filter (panel, PANEL_NUM_LIMIT);
	__set_cmd_str_cache (core, panel, NULL);
	panel->view->refresh = true;
	__reset_scroll_pos (panel);
}

static void __rotate_panel_cmds(RCore *core, const char **cmds, const int cmdslen, const char *prefix, bool rev) {
	if (!cmdslen) {
		return;
	}
	RPanel *p = __get_cur_panel (core->panels);
	__reset_filter (core, p);
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
		p->model->cmd = r_str_dup (p->model->cmd, tmp);
	}
	__set_cmd_str_cache (core, p, NULL);
	p->view->refresh = true;
}

static void __rotate_entropy_v_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	__rotate_panel_cmds (core, entropy_rotate, COUNT (entropy_rotate), "p=", rev);
}

static void __rotate_entropy_h_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	__rotate_panel_cmds (core, entropy_rotate, COUNT (entropy_rotate), "p==", rev);
}

static void __rotate_asmemu(RCore *core, RPanel *p) {
	const bool isEmuStr = r_config_get_i (core->config, "emu.str");
	const bool isEmu = r_config_get_i (core->config, "asm.emu");
	if (isEmu) {
		if (isEmuStr) {
			r_config_set (core->config, "emu.str", "false");
		} else {
			r_config_set (core->config, "asm.emu", "false");
		}
	} else {
		r_config_set (core->config, "emu.str", "true");
	}
	p->view->refresh = true;
}

static void __rotate_hexdump_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	RPanel *p = __get_cur_panel (core->panels);

	if (rev) {
		p->model->rotate--;
	} else {
		p->model->rotate++;
	}
	r_core_visual_applyHexMode (core, p->model->rotate);
	__rotate_asmemu (core, p);
}

static void __rotate_register_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	__rotate_panel_cmds (core, register_rotate, COUNT (register_rotate), "dr", rev);
}

static void __rotate_function_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	__rotate_panel_cmds (core, function_rotate, COUNT (function_rotate), "af", rev);
}

static void __rotate_disasm_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	RPanel *p = __get_cur_panel (core->panels);

	//TODO: need to come up with a better solution but okay for now
	if (!strcmp (p->model->cmd, PANEL_CMD_DECOMPILER) ||
			!strcmp (p->model->cmd, PANEL_CMD_DECOMPILER_O)) {
		return;
	}

	if (rev) {
		if (!p->model->rotate) {
			p->model->rotate = 4;
		} else {
			p->model->rotate--;
		}
	} else {
		p->model->rotate++;
	}
	r_core_visual_applyDisMode (core, p->model->rotate);
	__rotate_asmemu (core, p);
}

static void __init_rotate_db(RCore *core) {
	Sdb *db = core->panels->rotate_db;
	sdb_ptr_set (db, "pd", &__rotate_disasm_cb, 0);
	sdb_ptr_set (db, "p==", &__rotate_entropy_h_cb, 0);
	sdb_ptr_set (db, "p=", &__rotate_entropy_v_cb, 0);
	sdb_ptr_set (db, "px", &__rotate_hexdump_cb, 0);
	sdb_ptr_set (db, "dr", &__rotate_register_cb, 0);
	sdb_ptr_set (db, "af", &__rotate_function_cb, 0);
	sdb_ptr_set (db, PANEL_CMD_HEXDUMP, &__rotate_hexdump_cb, 0);
}

static void __init_all_dbs(RCore *core) {
	__init_sdb (core);
	__init_modal_db (core);
	__init_rotate_db (core);
}

static RConsCanvas *__create_new_canvas(RCore *core, int w, int h) {
	RConsCanvas *can = r_cons_canvas_new (w, h);
	if (!can) {
		eprintf ("Cannot create RCons.canvas context\n");
		return false;
	}
	r_cons_canvas_fill (can, 0, 0, w, h, ' ');
	can->linemode = r_config_get_i (core->config, "graph.linemode");
	can->color = r_config_get_i (core->config, "scr.color");
	return can;
}

static void __free_menu_item(RPanelsMenuItem *item) {
	if (!item) {
		return;
	}
	size_t i;
	free (item->name);
	free (item->p->model);
	free (item->p->view);
	free (item->p);
	for (i = 0; i < item->n_sub; i++) {
		__free_menu_item (item->sub[i]);
	}
	free (item->sub);
	free (item);
}

static void __mht_free_kv(HtPPKv *kv) {
	free (kv->key);
	__free_menu_item ((RPanelsMenuItem *)kv->value);
}

static bool __init(RCore *core, RPanels *panels, int w, int h) {
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
	panels->can = __create_new_canvas (core, w, h);
	panels->db = sdb_new0 ();
	panels->rotate_db = sdb_new0 ();
	panels->modal_db = sdb_new0 ();
	panels->mht = ht_pp_new (NULL, (HtPPKvFreeFunc)__mht_free_kv, (HtPPCalcSizeV)strlen);
	panels->fun = PANEL_FUN_NOFUN;
	panels->prevMode = PANEL_MODE_DEFAULT;
	panels->name = NULL;

	if (w < 140) {
		panels->columnWidth = w / 3;
	}
	return true;
}

static RPanels *__panels_new(RCore *core) {
	RPanels *panels = R_NEW0 (RPanels);
	if (!panels) {
		return NULL;
	}
	int h, w = r_cons_get_size (&h);
	firstRun = true;
	if (!__init (core, panels, w, h)) {
		free (panels);
		return NULL;
	}
	return panels;
}

static void __handle_tab_new_with_cur_panel (RCore *core) {
	RPanels *panels = core->panels;
	if (panels->n_panels <= 1) {
		return;
	}

	RPanelsRoot *root = core->panels_root;
	if (root->n_panels + 1 >= PANEL_NUM_LIMIT) {
		return;
	}

	RPanel *cur = __get_cur_panel (panels);

	RPanels *new_panels = __panels_new (core);
	if (!new_panels) {
		return;
	}
	root->panels[root->n_panels] = new_panels;

	RPanels *prev = core->panels;
	core->panels = new_panels;

	if (!__init_panels_menu (core) || !__init_panels (core, new_panels)) {
		core->panels = prev;
		return;
	}
	__set_mode (core, PANEL_MODE_DEFAULT);
	__init_all_dbs (core);

	RPanel *new_panel = __get_panel (new_panels, 0);
	__init_panel_param (core, new_panel, cur->model->title, cur->model->cmd);
	new_panel->model->cache = cur->model->cache;
	new_panel->model->funcName = r_str_new (cur->model->funcName);
	__set_cmd_str_cache (core, new_panel, r_str_new (cur->model->cmdStrCache));
	__maximize_panel_size (new_panels);

	core->panels = prev;
	__dismantle_del_panel (core, cur, panels->curnode);

	root->cur_panels = root->n_panels;
	root->n_panels++;
	__set_root_state (core, ROTATE);
}

static void __handle_tab_key(RCore *core, bool shift) {
	__set_cursor (core, false);
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	r_cons_switchbuf (false);
	cur->view->refresh = true;
	if (!shift) {
		if (panels->mode == PANEL_MODE_MENU) {
			__set_curnode (core, 0);
			__set_mode (core, PANEL_MODE_DEFAULT);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			__set_curnode (core, ++panels->curnode);
		} else {
			__set_curnode (core, ++panels->curnode);
		}
	} else {
		if (panels->mode == PANEL_MODE_MENU) {
			__set_curnode (core, panels->n_panels - 1);
			__set_mode (core, PANEL_MODE_DEFAULT);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			__set_curnode (core, --panels->curnode);
		} else {
			__set_curnode (core, --panels->curnode);
		}
	}
	cur = __get_cur_panel (panels);
	cur->view->refresh = true;
	if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
		__reset_snow (panels);
	}
}

static bool __handle_zoom_mode(RCore *core, const int key) {
	RPanels *panels = core->panels;
	r_cons_switchbuf (false);
	switch (key) {
	case 'Q':
	case 'q':
	case 0x0d:
		__toggle_zoom_mode (core);
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
		__restore_panel_pos (panels->panel[panels->curnode]);
		__handle_tab_key (core, false);
		__save_panel_pos (panels->panel[panels->curnode]);
		__maximize_panel_size (panels);
		break;
	case 'Z':
		__restore_panel_pos (panels->panel[panels->curnode]);
		__handle_tab_key (core, true);
		__save_panel_pos (panels->panel[panels->curnode]);
		__maximize_panel_size (panels);
		break;
	case '?':
		__toggle_zoom_mode (core);
		__toggle_help (core);
		__toggle_zoom_mode (core);
		break;
	}
	return true;
}

static void __set_refresh_by_type(RCore *core, const char *cmd, bool clearCache) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __get_panel (panels, i);
		if (!__check_panel_type (p, cmd)) {
			continue;
		}
		p->view->refresh = true;
		if (clearCache) {
			__set_cmd_str_cache (core, p, NULL);
		}
	}
}

static char *filter_arg(char *a) {
	r_name_filter_print (a);
	char *r = r_str_escape (a);
	free (a);
	return r;
}

static void __handleComment(RCore *core) {
	RPanel *p = __get_cur_panel (core->panels);
	if (!__check_panel_type (p, PANEL_CMD_DISASSEMBLY)) {
		return;
	}
	char buf[4095];
	char *cmd = NULL;
	r_line_set_prompt ("[Comment]> ");
	if (r_cons_fgets (buf, sizeof (buf), 0, NULL) > 0) {
		ut64 addr, orig;
		addr = orig = core->offset;
		if (core->print->cur_enabled) {
			addr += core->print->cur;
			r_core_seek (core, addr, false);
			r_core_cmdf (core, "s 0x%"PFMT64x, addr);
		}
		if (!strcmp (buf, "-")) {
			cmd = strdup ("CC-");
		} else {
			char *arg = filter_arg (strdup (buf));
			switch (buf[0]) {
			case '-':
				cmd = r_str_newf ("\"CC-%s\"", arg);
				break;
			case '!':
				strcpy (buf, "\"CC!");
				break;
			default:
				cmd = r_str_newf ("\"CC %s\"", arg);
				break;
			}
			free (arg);
		}
		if (cmd) {
			r_core_cmd (core, cmd, 1);
		}
		if (core->print->cur_enabled) {
			r_core_seek (core, orig, true);
		}
		free (cmd);
	}
	__set_refresh_by_type (core, p->model->cmd, true);
}

static bool __move_to_direction(RCore *core, Direction direction) {
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	int cur_x0 = cur->view->pos.x, cur_x1 = cur->view->pos.x + cur->view->pos.w - 1, cur_y0 = cur->view->pos.y, cur_y1 = cur->view->pos.y + cur->view->pos.h - 1;
	int temp_x0, temp_x1, temp_y0, temp_y1;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __get_panel (panels, i);
		temp_x0 = p->view->pos.x;
		temp_x1 = p->view->pos.x + p->view->pos.w - 1;
		temp_y0 = p->view->pos.y;
		temp_y1 = p->view->pos.y + p->view->pos.h - 1;
		switch (direction) {
		case LEFT:
			if (temp_x1 == cur_x0) {
				if (temp_y1 <= cur_y0 || cur_y1 <= temp_y0) {
					continue;
				}
				__set_curnode (core, i);
				return true;
			}
			break;
		case RIGHT:
			if (temp_x0 == cur_x1) {
				if (temp_y1 <= cur_y0 || cur_y1 <= temp_y0) {
					continue;
				}
				__set_curnode (core, i);
				return true;
			}
			break;
		case UP:
			if (temp_y1 == cur_y0) {
				if (temp_x1 <= cur_x0 || cur_x1 <= temp_x0) {
					continue;
				}
				__set_curnode (core, i);
				return true;
			}
			break;
		case DOWN:
			if (temp_y0 == cur_y1) {
				if (temp_x1 <= cur_x0 || cur_x1 <= temp_x0) {
					continue;
				}
				__set_curnode (core, i);
				return true;
			}
			break;
		default:
			break;
		}
	}
	return false;
}

static void __direction_default_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanel *cur = __get_cur_panel (core->panels);
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (cur->view->sx > 0) {
			cur->view->sx--;
		}
		break;
	case RIGHT:
		cur->view->sx++;
		break;
	case UP:
		if (cur->view->sy > 0) {
			cur->view->sy--;
		}
		break;
	case DOWN:
		cur->view->sy++;
		break;
	}
}

static void __direction_disassembly_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	int cols = core->print->cols;
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (core->print->cur_enabled) {
			__cursor_left (core);
			r_core_block_read (core);
			__set_panel_addr (core, cur, core->offset);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			cur->model->addr--;
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
		}
		break;
	case RIGHT:
		if (core->print->cur_enabled) {
			__cursor_right (core);
			r_core_block_read (core);
			__set_panel_addr (core, cur, core->offset);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			cur->model->addr++;
		} else {
			cur->view->sx++;
		}
		break;
	case UP:
		core->offset = cur->model->addr;
		if (core->print->cur_enabled) {
			__cursor_up (core);
			r_core_block_read (core);
			__set_panel_addr (core, cur, core->offset);
		} else {
			r_core_visual_disasm_up (core, &cols);
			r_core_seek_delta (core, -cols);
			__set_panel_addr (core, cur, core->offset);
		}
		break;
	case DOWN:
		core->offset = cur->model->addr;
		if (core->print->cur_enabled) {
			__cursor_down (core);
			r_core_block_read (core);
			__set_panel_addr (core, cur, core->offset);
		} else {
			RAsmOp op;
			r_core_visual_disasm_down (core, &op, &cols);
			r_core_seek (core, core->offset + cols, true);
			__set_panel_addr (core, cur, core->offset);
		}
		break;
	}
}

static void __direction_graph_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	cur->view->refresh = true;
	const int speed = r_config_get_i (core->config, "graph.scroll") * 2;
	switch ((Direction)direction) {
	case LEFT:
		if (cur->view->sx > 0) {
			cur->view->sx -= speed;
		}
		break;
	case RIGHT:
		cur->view->sx +=  speed;
		break;
	case UP:
		if (cur->view->sy > 0) {
			cur->view->sy -= speed;
		}
		break;
	case DOWN:
		cur->view->sy += speed;
		break;
	}
}

static void __direction_register_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	int cols = core->dbg->regcols;
	cols = cols > 0 ? cols : 3;
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (core->print->cur_enabled) {
			__cursor_left (core);
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
			cur->view->refresh = true;
		}
		break;
	case RIGHT:
		if (core->print->cur_enabled) {
			__cursor_right (core);
		} else {
			cur->view->sx++;
			cur->view->refresh = true;
		}
		break;
	case UP:
		if (core->print->cur_enabled) {
			int tmp = core->print->cur;
			tmp -= cols;
			if (tmp >= 0) {
				core->print->cur = tmp;
			}
		}
		break;
	case DOWN:
		if (core->print->cur_enabled) {
			core->print->cur += cols;
		}
		break;
	}
}

static void __direction_stack_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	int cols = r_config_get_i (core->config, "hex.cols");
	if (cols < 1) {
		cols = 16;
	}
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (core->print->cur_enabled) {
			__cursor_left (core);
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
			cur->view->refresh = true;
		}
		break;
	case RIGHT:
		if (core->print->cur_enabled) {
			__cursor_right (core);
		} else {
			cur->view->sx++;
			cur->view->refresh = true;
		}
		break;
	case UP:
		r_config_set_i (core->config, "stack.delta",
				r_config_get_i (core->config, "stack.delta") + cols);
		cur->model->addr -= cols;
		break;
	case DOWN:
		r_config_set_i (core->config, "stack.delta",
				r_config_get_i (core->config, "stack.delta") - cols);
		cur->model->addr += cols;
		break;
	}
}

static void __direction_hexdump_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	int cols = r_config_get_i (core->config, "hex.cols");
	if (cols < 1) {
		cols = 16;
	}
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (!core->print->cur) {
			cur->model->addr -= cols;
			core->print->cur += cols - 1;
		} else if (core->print->cur_enabled) {
			__cursor_left (core);
		} else {
			cur->model->addr--;
		}
		break;
	case RIGHT:
		if (core->print->cur / cols + 1 > cur->view->pos.h - 5
				&& core->print->cur % cols == cols - 1) {
			cur->model->addr += cols;
			core->print->cur -= cols - 1;
		} else if (core->print->cur_enabled) {
			__cursor_right (core);
		} else {
			cur->model->addr++;
		}
		break;
	case UP:
		if (!cur->model->cache) {
			if (core->print->cur_enabled) {
				if (!(core->print->cur / cols)) {
					cur->model->addr -= cols;
				} else {
					core->print->cur -= cols;
				}
			} else {
				if (cur->model->addr <= cols) {
					__set_panel_addr (core, cur, 0);
				} else {
					cur->model->addr -= cols;
				}
			}
		} else if (cur->view->sy > 0) {
			cur->view->sy--;
		}
		break;
	case DOWN:
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

static void __direction_panels_cursor_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	cur->view->refresh = true;
	const int THRESHOLD = cur->view->pos.h / 3;
	int sub;
	switch ((Direction)direction) {
	case LEFT:
		if (core->print->cur_enabled) {
			break;
		}
		if (cur->view->sx > 0) {
			cur->view->sx -= r_config_get_i (core->config, "graph.scroll");
		}
		break;
	case RIGHT:
		if (core->print->cur_enabled) {
			break;
		}
		cur->view->sx += r_config_get_i (core->config, "graph.scroll");
		break;
	case UP:
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
	case DOWN:
		core->offset = cur->model->addr;
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

static void __toggle_window_mode(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->mode != PANEL_MODE_WINDOW) {
		panels->prevMode = panels->mode;
		__set_mode (core, PANEL_MODE_WINDOW);
	} else {
		__set_mode (core, panels->prevMode);
		panels->prevMode = PANEL_MODE_DEFAULT;
	}
}

static void __resize_panel_left(RPanels *panels) {
	RPanel *cur = __get_cur_panel (panels);
	int i, cx0, cx1, cy0, cy1, tx0, tx1, ty0, ty1, cur1 = 0, cur2 = 0, cur3 = 0, cur4 = 0;
	cx0 = cur->view->pos.x;
	cx1 = cur->view->pos.x + cur->view->pos.w - 1;
	cy0 = cur->view->pos.y;
	cy1 = cur->view->pos.y + cur->view->pos.h - 1;
	RPanel **targets1 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets2 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets3 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets4 = malloc (sizeof (RPanel *) * panels->n_panels);
	if (!targets1 || !targets2 || !targets3 || !targets4) {
		goto beach;
	}
	for (i = 0; i < panels->n_panels; i++) {
		if (i == panels->curnode) {
			continue;
		}
		RPanel *p = __get_panel (panels, i);
		tx0 = p->view->pos.x;
		tx1 = p->view->pos.x + p->view->pos.w - 1;
		ty0 = p->view->pos.y;
		ty1 = p->view->pos.y + p->view->pos.h - 1;
		if (ty0 == cy0 && ty1 == cy1 && tx1 == cx0 && tx1 - PANEL_CONFIG_RESIZE_W > tx0) {
			p->view->pos.w -= PANEL_CONFIG_RESIZE_W;
			cur->view->pos.x -= PANEL_CONFIG_RESIZE_W;
			cur->view->pos.w += PANEL_CONFIG_RESIZE_W;
			p->view->refresh = true;
			cur->view->refresh = true;
			goto beach;
		}
		bool y_included =  (ty1 >= cy0 && cy1 >= ty1) || (ty0 >= cy0 && cy1 >= ty0);
		if (tx1 == cx0 && y_included) {
			if (tx1 - PANEL_CONFIG_RESIZE_W > tx0) {
				targets1[cur1++] = p;
			}
		}
		if (tx0 == cx1 && y_included) {
			if (tx0 - PANEL_CONFIG_RESIZE_W > cx0) {
				targets3[cur3++] = p;
			}
		}
		if (tx0 == cx0) {
			if (tx0 - PANEL_CONFIG_RESIZE_W > 0) {
				targets2[cur2++] = p;
			}
		}
		if (tx1 == cx1) {
			if (tx1 + PANEL_CONFIG_RESIZE_W < panels->can->w) {
				targets4[cur4++] = p;
			}
		}
	}
	if (cur1 > 0) {
		for (i = 0; i < cur1; i++) {
			targets1[i]->view->pos.w -= PANEL_CONFIG_RESIZE_W;
			targets1[i]->view->refresh = true;
		}
		for (i = 0; i < cur2; i++) {
			targets2[i]->view->pos.x -= PANEL_CONFIG_RESIZE_W;
			targets2[i]->view->pos.w += PANEL_CONFIG_RESIZE_W;
			targets2[i]->view->refresh = true;
		}
		cur->view->pos.x -= PANEL_CONFIG_RESIZE_W;
		cur->view->pos.w += PANEL_CONFIG_RESIZE_W;
		cur->view->refresh = true;
	} else if (cur3 > 0) {
		for (i = 0; i < cur3; i++) {
			targets3[i]->view->pos.w += PANEL_CONFIG_RESIZE_W;
			targets3[i]->view->pos.x -= PANEL_CONFIG_RESIZE_W;
			targets3[i]->view->refresh = true;
		}
		for (i = 0; i < cur4; i++) {
			targets4[i]->view->pos.w -= PANEL_CONFIG_RESIZE_W;
			targets4[i]->view->refresh = true;
		}
		cur->view->pos.w -= PANEL_CONFIG_RESIZE_W;
		cur->view->refresh = true;
	}
beach:
	free (targets1);
	free (targets2);
	free (targets3);
	free (targets4);
}

static void __resize_panel_right(RPanels *panels) {
	RPanel *cur = __get_cur_panel (panels);
	int i, tx0, tx1, ty0, ty1, cur1 = 0, cur2 = 0, cur3 = 0, cur4 = 0;
	int cx0 = cur->view->pos.x;
	int cx1 = cur->view->pos.x + cur->view->pos.w - 1;
	int cy0 = cur->view->pos.y;
	int cy1 = cur->view->pos.y + cur->view->pos.h - 1;
	RPanel **targets1 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets2 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets3 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets4 = malloc (sizeof (RPanel *) * panels->n_panels);
	if (!targets1 || !targets2 || !targets3 || !targets4) {
		goto beach;
	}
	for (i = 0; i < panels->n_panels; i++) {
		if (i == panels->curnode) {
			continue;
		}
		RPanel *p = __get_panel (panels, i);
		tx0 = p->view->pos.x;
		tx1 = p->view->pos.x + p->view->pos.w - 1;
		ty0 = p->view->pos.y;
		ty1 = p->view->pos.y + p->view->pos.h - 1;
		if (ty0 == cy0 && ty1 == cy1 && tx0 == cx1 && tx0 + PANEL_CONFIG_RESIZE_W < tx1) {
			p->view->pos.x += PANEL_CONFIG_RESIZE_W;
			p->view->pos.w -= PANEL_CONFIG_RESIZE_W;
			cur->view->pos.w += PANEL_CONFIG_RESIZE_W;
			p->view->refresh = true;
			cur->view->refresh = true;
			goto beach;
		}
		bool y_included =  (ty1 >= cy0 && cy1 >= ty1) || (ty0 >= cy0 && cy1 >= ty0);
		if (tx1 == cx0 && y_included) {
			if (tx1 + PANEL_CONFIG_RESIZE_W < cx1) {
				targets1[cur1++] = p;
			}
		}
		if (tx0 == cx1 && y_included) {
			if (tx0 + PANEL_CONFIG_RESIZE_W < tx1) {
				targets3[cur3++] = p;
			}
		}
		if (tx0 == cx0) {
			if (tx0 + PANEL_CONFIG_RESIZE_W < tx1) {
				targets2[cur2++] = p;
			}
		}
		if (tx1 == cx1) {
			if (tx1 + PANEL_CONFIG_RESIZE_W < panels->can->w) {
				targets4[cur4++] = p;
			}
		}
	}
	if (cur3 > 0) {
		for (i = 0; i < cur3; i++) {
			targets3[i]->view->pos.x += PANEL_CONFIG_RESIZE_W;
			targets3[i]->view->pos.w -= PANEL_CONFIG_RESIZE_W;
			targets3[i]->view->refresh = true;
		}
		for (i = 0; i < cur4; i++) {
			targets4[i]->view->pos.w += PANEL_CONFIG_RESIZE_W;
			targets4[i]->view->refresh = true;
		}
		cur->view->pos.w += PANEL_CONFIG_RESIZE_W;
		cur->view->refresh = true;
	} else if (cur1 > 0) {
		for (i = 0; i < cur1; i++) {
			targets1[i]->view->pos.w += PANEL_CONFIG_RESIZE_W;
			targets1[i]->view->refresh = true;
		}
		for (i = 0; i < cur2; i++) {
			targets2[i]->view->pos.x += PANEL_CONFIG_RESIZE_W;
			targets2[i]->view->pos.w -= PANEL_CONFIG_RESIZE_W;
			targets2[i]->view->refresh = true;
		}
		cur->view->pos.x += PANEL_CONFIG_RESIZE_W;
		cur->view->pos.w -= PANEL_CONFIG_RESIZE_W;
		cur->view->refresh = true;
	}
beach:
	free (targets1);
	free (targets2);
	free (targets3);
	free (targets4);
}

static void __resize_panel_up(RPanels *panels) {
	RPanel *cur = __get_cur_panel (panels);
	int i, tx0, tx1, ty0, ty1, cur1 = 0, cur2 = 0, cur3 = 0, cur4 = 0;
	int cx0 = cur->view->pos.x;
	int cx1 = cur->view->pos.x + cur->view->pos.w - 1;
	int cy0 = cur->view->pos.y;
	int cy1 = cur->view->pos.y + cur->view->pos.h - 1;
	RPanel **targets1 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets2 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets3 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets4 = malloc (sizeof (RPanel *) * panels->n_panels);
	if (!targets1 || !targets2 || !targets3 || !targets4) {
		goto beach;
	}
	for (i = 0; i < panels->n_panels; i++) {
		if (i == panels->curnode) {
			continue;
		}
		RPanel *p = __get_panel (panels, i);
		tx0 = p->view->pos.x;
		tx1 = p->view->pos.x + p->view->pos.w - 1;
		ty0 = p->view->pos.y;
		ty1 = p->view->pos.y + p->view->pos.h - 1;
		if (tx0 == cx0 && tx1 == cx1 && ty1 == cy0 && ty1 - PANEL_CONFIG_RESIZE_H > ty0) {
			p->view->pos.h -= PANEL_CONFIG_RESIZE_H;
			cur->view->pos.y -= PANEL_CONFIG_RESIZE_H;
			cur->view->pos.h += PANEL_CONFIG_RESIZE_H;
			p->view->refresh = true;
			cur->view->refresh = true;
			goto beach;
		}
		bool x_included =  (tx1 >= cx0 && cx1 >= tx1) || (tx0 >= cx0 && cx1 >= tx0);
		if (ty1 == cy0 && x_included) {
			if (ty1 - PANEL_CONFIG_RESIZE_H > ty0) {
				targets1[cur1++] = p;
			}
		}
		if (ty0 == cy1 && x_included) {
			if (ty0 - PANEL_CONFIG_RESIZE_H > cy0) {
				targets3[cur3++] = p;
			}
		}
		if (ty0 == cy0) {
			if (ty0 - PANEL_CONFIG_RESIZE_H > 0) {
				targets2[cur2++] = p;
			}
		}
		if (ty1 == cy1) {
			if (ty1 - PANEL_CONFIG_RESIZE_H > ty0) {
				targets4[cur4++] = p;
			}
		}
	}
	if (cur1 > 0) {
		for (i = 0; i < cur1; i++) {
			targets1[i]->view->pos.h -= PANEL_CONFIG_RESIZE_H;
			targets1[i]->view->refresh = true;
		}
		for (i = 0; i < cur2; i++) {
			targets2[i]->view->pos.y -= PANEL_CONFIG_RESIZE_H;
			targets2[i]->view->pos.h += PANEL_CONFIG_RESIZE_H;
			targets2[i]->view->refresh = true;
		}
		cur->view->pos.y -= PANEL_CONFIG_RESIZE_H;
		cur->view->pos.h += PANEL_CONFIG_RESIZE_H;
		cur->view->refresh = true;
	} else if (cur3 > 0) {
		for (i = 0; i < cur3; i++) {
			targets3[i]->view->pos.h += PANEL_CONFIG_RESIZE_H;
			targets3[i]->view->pos.y -= PANEL_CONFIG_RESIZE_H;
			targets3[i]->view->refresh = true;
		}
		for (i = 0; i < cur4; i++) {
			targets4[i]->view->pos.h -= PANEL_CONFIG_RESIZE_H;
			targets4[i]->view->refresh = true;
		}
		cur->view->pos.h -= PANEL_CONFIG_RESIZE_H;
		cur->view->refresh = true;
	}
beach:
	free (targets1);
	free (targets2);
	free (targets3);
	free (targets4);
}
static void __resize_panel_down(RPanels *panels) {
	RPanel *cur = __get_cur_panel (panels);
	int i, tx0, tx1, ty0, ty1, cur1 = 0, cur2 = 0, cur3 = 0, cur4 = 0;
	int cx0 = cur->view->pos.x;
	int cx1 = cur->view->pos.x + cur->view->pos.w - 1;
	int cy0 = cur->view->pos.y;
	int cy1 = cur->view->pos.y + cur->view->pos.h - 1;
	RPanel **targets1 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets2 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets3 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets4 = malloc (sizeof (RPanel *) * panels->n_panels);
	if (!targets1 || !targets2 || !targets3 || !targets4) {
		goto beach;
	}
	for (i = 0; i < panels->n_panels; i++) {
		if (i == panels->curnode) {
			continue;
		}
		RPanel *p = __get_panel (panels, i);
		tx0 = p->view->pos.x;
		tx1 = p->view->pos.x + p->view->pos.w - 1;
		ty0 = p->view->pos.y;
		ty1 = p->view->pos.y + p->view->pos.h - 1;
		if (tx0 == cx0 && tx1 == cx1 && ty0 == cy1 && ty0 + PANEL_CONFIG_RESIZE_H < ty1) {
			p->view->pos.y += PANEL_CONFIG_RESIZE_H;
			p->view->pos.h -= PANEL_CONFIG_RESIZE_H;
			cur->view->pos.h += PANEL_CONFIG_RESIZE_H;
			p->view->refresh = true;
			cur->view->refresh = true;
			goto beach;
		}
		bool x_included =  (tx1 >= cx0 && cx1 >= tx1) || (tx0 >= cx0 && cx1 >= tx0);
		if (ty1 == cy0 && x_included) {
			if (ty1 + PANEL_CONFIG_RESIZE_H < cy1) {
				targets1[cur1++] = p;
			}
		}
		if (ty0 == cy1 && x_included) {
			if (ty0 + PANEL_CONFIG_RESIZE_H < ty1) {
				targets3[cur3++] = p;
			}
		}
		if (ty0 == cy0) {
			if (ty0 + PANEL_CONFIG_RESIZE_H < ty1) {
				targets2[cur2++] = p;
			}
		}
		if (ty1 == cy1) {
			if (ty1 + PANEL_CONFIG_RESIZE_H < panels->can->h) {
				targets4[cur4++] = p;
			}
		}
	}
	if (cur3 > 0) {
		for (i = 0; i < cur3; i++) {
			targets3[i]->view->pos.h -= PANEL_CONFIG_RESIZE_H;
			targets3[i]->view->pos.y += PANEL_CONFIG_RESIZE_H;
			targets3[i]->view->refresh = true;
		}
		for (i = 0; i < cur4; i++) {
			targets4[i]->view->pos.h += PANEL_CONFIG_RESIZE_H;
			targets4[i]->view->refresh = true;
		}
		cur->view->pos.h += PANEL_CONFIG_RESIZE_H;
		cur->view->refresh = true;
	} else if (cur1 > 0) {
		for (i = 0; i < cur1; i++) {
			targets1[i]->view->pos.h += PANEL_CONFIG_RESIZE_H;
			targets1[i]->view->refresh = true;
		}
		for (i = 0; i < cur2; i++) {
			targets2[i]->view->pos.y += PANEL_CONFIG_RESIZE_H;
			targets2[i]->view->pos.h -= PANEL_CONFIG_RESIZE_H;
			targets2[i]->view->refresh = true;
		}
		cur->view->pos.y += PANEL_CONFIG_RESIZE_H;
		cur->view->pos.h -= PANEL_CONFIG_RESIZE_H;
		cur->view->refresh = true;
	}
beach:
	free (targets1);
	free (targets2);
	free (targets3);
	free (targets4);
}

static bool __handle_window_mode(RCore *core, const int key) {
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	r_cons_switchbuf (false);
	switch (key) {
	case 'Q':
	case 'q':
	case 'w':
		__toggle_window_mode (core);
		break;
	case 0x0d:
		__toggle_zoom_mode (core);
		break;
	case 9: // tab
		__handle_tab_key (core, false);
		break;
	case 'Z': // shift-tab
		__handle_tab_key (core, true);
		break;
	case 'e':
	{
		char *cmd = __show_status_input (core, "New command: ");
		if (R_STR_ISNOTEMPTY (cmd)) {
			__replace_cmd (core, cmd, cmd);
		}
		free (cmd);
	}
		break;
	case 'h':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.x--;
		} else {
			(void)__move_to_direction (core, LEFT);
			if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
				__reset_snow (panels);
			}
		}
		break;
	case 'j':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.y++;
		} else {
			(void)__move_to_direction (core, DOWN);
			if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
				__reset_snow (panels);
			}
		}
		break;
	case 'k':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.y--;
		} else {
			(void)__move_to_direction (core, UP);
			if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
				__reset_snow (panels);
			}
		}
		break;
	case 'l':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.x++;
		} else {
			(void)__move_to_direction (core, RIGHT);
			if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
				__reset_snow (panels);
			}
		}
		break;
	case 'H':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.x += 5;
		} else {
			r_cons_switchbuf (false);
			__resize_panel_left (panels);
		}
		break;
	case 'L':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.x += 5;
		} else {
			r_cons_switchbuf (false);
			__resize_panel_right (panels);
		}
		break;
	case 'J':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.y += 5;
		} else {
			r_cons_switchbuf (false);
			__resize_panel_down (panels);
		}
		break;
	case 'K':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.y -= 5;
		} else {
			r_cons_switchbuf (false);
			__resize_panel_up (panels);
		}
		break;
	case 'n':
		__create_panel_input (core, cur, PANEL_LAYOUT_VERTICAL, NULL);
		break;
	case 'N':
		__create_panel_input (core, cur, PANEL_LAYOUT_HORIZONTAL, NULL);
		break;
	case 'X':
		__dismantle_del_panel (core, cur, panels->curnode);
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

static void __jmp_to_cursor_addr(RCore *core, RPanel *panel) {
	ut64 addr = __parse_string_on_cursor (core, panel, panel->view->curpos);
	if (addr == UT64_MAX) {
		return;
	}
	core->offset = addr;
	__update_disassembly_or_open (core);
}

static void __set_breakpoints_on_cursor(RCore *core, RPanel *panel) {
	if (!r_config_get_b (core->config, "cfg.debug")) {
		return;
	}
	if (__check_panel_type (panel, PANEL_CMD_DISASSEMBLY)) {
		r_core_cmdf (core, "dbs 0x%08"PFMT64x, core->offset + core->print->cur);
		panel->view->refresh = true;
	}
}

static void __insert_value(RCore *core) {
	if (!r_config_get_i (core->config, "io.cache")) {
		if (__show_status_yesno (core, 1, "Insert is not available because io.cache is off. Turn on now?(Y/n)")) {
			r_config_set_b (core->config, "io.cache", true);
			(void)__show_status (core, "io.cache is on and insert is available now.");
		} else {
			(void)__show_status (core, "You can always turn on io.cache in Menu->Edit->io.cache");
			return;
		}
	}
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	char buf[128];
	if (__check_panel_type (cur, PANEL_CMD_STACK)) {
		const char *prompt = "insert hex: ";
		__panel_prompt (prompt, buf, sizeof (buf));
		r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, cur->model->addr);
		cur->view->refresh = true;
	} else if (__check_panel_type (cur, PANEL_CMD_REGISTERS)) {
		const char *creg = core->dbg->creg;
		if (creg) {
			const char *prompt = "new-reg-value> ";
			__panel_prompt (prompt, buf, sizeof (buf));
			r_core_cmdf (core, "dr %s = %s", creg, buf);
			cur->view->refresh = true;
		}
	} else if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		const char *prompt = "insert hex: ";
		__panel_prompt (prompt, buf, sizeof (buf));
		r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, core->offset + core->print->cur);
		cur->view->refresh = true;
	} else if (__check_panel_type (cur, PANEL_CMD_HEXDUMP)) {
		const char *prompt = "insert hex: ";
		__panel_prompt (prompt, buf, sizeof (buf));
		r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, cur->model->addr + core->print->cur);
		cur->view->refresh = true;
	}
}

static void __cursor_del_breakpoints(RCore *core, RPanel *panel) {
	RListIter *iter;
	RBreakpointItem *b;
	int i = 0;
	r_list_foreach (core->dbg->bp->bps, iter, b) {
		if (panel->view->curpos == i++) {
			r_bp_del (core->dbg->bp, b->addr);
		}
	}
}

static void __set_addr_by_type(RCore *core, const char *cmd, ut64 addr) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __get_panel (panels, i);
		if (!__check_panel_type (p, cmd)) {
			continue;
		}
		__set_panel_addr (core, p, addr);
	}
}

static void __handle_refs(RCore *core, RPanel *panel, ut64 tmp) {
	if (tmp != UT64_MAX) {
		core->offset = tmp;
	}
	int key = __show_status(core, "xrefs:x refs:X ");
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
	if (__check_panel_type (panel, PANEL_CMD_DISASSEMBLY)) {
		__set_panel_addr (core, panel, core->offset);
	} else {
		__set_addr_by_type (core, PANEL_CMD_DISASSEMBLY, core->offset);
	}
}

static bool __handle_cursor_mode(RCore *core, const int key) {
	RPanel *cur = __get_cur_panel (core->panels);
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
		__reset_scroll_pos (cur);
		cur->view->refresh = true;
		break;
	case ']':
		if (__check_panel_type (cur, PANEL_CMD_HEXDUMP)) {
			const int cols = r_config_get_i (core->config, "hex.cols");
			r_config_set_i (core->config, "hex.cols", cols + 1);
		} else {
			const int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
			r_config_set_i (core->config, "asm.cmt.col", cmtcol + 2);
		}
		cur->view->refresh = true;
		break;
	case '[':
		if (__check_panel_type (cur, PANEL_CMD_HEXDUMP)) {
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
		__set_cursor (core, !print->cur_enabled);
		cur->view->refresh = true;
		break;
	case 'w':
		__toggle_window_mode (core);
		__set_cursor (core, false);
		cur->view->refresh = true;
		break;
	case 'i':
		__insert_value (core);
		break;
	case '*':
		if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
			r_core_cmdf (core, "dr PC=0x%08"PFMT64x, core->offset + print->cur);
			__set_panel_addr (core, cur, core->offset + print->cur);
		}
		break;
	case '-':
		db_val = __search_db (core, "Breakpoints");
		if (__check_panel_type (cur, db_val)) {
			__cursor_del_breakpoints(core, cur);
			free (db_val);
			break;
		}
		free (db_val);
		return false;
	case 'x':
		__handle_refs (core, cur, __parse_string_on_cursor (core, cur, cur->view->curpos));
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

static bool __drag_and_resize(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->mouse_on_edge_x || panels->mouse_on_edge_y) {
		int x, y;
		if (r_cons_get_click (&x, &y)) {
			if (panels->mouse_on_edge_x) {
				__update_edge_x (core, x - panels->mouse_orig_x);
			}
			if (panels->mouse_on_edge_y) {
				__update_edge_y (core, y - panels->mouse_orig_y);
			}
		}
		panels->mouse_on_edge_x = false;
		panels->mouse_on_edge_y = false;
		return true;
	}
	return false;
}

static char *__get_word_from_canvas(RCore *core, RPanels *panels, int x, int y) {
	RStrBuf rsb;
	r_strbuf_init (&rsb);
	char *cs = r_cons_canvas_to_string (panels->can);
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

static char *__get_word_from_canvas_for_menu(RCore *core, RPanels *panels, int x, int y) {
	char *cs = r_cons_canvas_to_string (panels->can);
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
	char *ret = r_str_newlen (pos += strlen (padding), i - strlen (padding));
	if (!ret) {
		ret = strdup (pos);
	}
	free (r);
	free (R);
	free (cs);
	return ret;
}

static void __handle_tab_nth(RCore *core, int ch) {
	ch -= '0' + 1;
	if (ch < 0) {
		return;
	}
	if (ch != core->panels_root->cur_panels && ch < core->panels_root->n_panels) {
		core->panels_root->cur_panels = ch;
		__set_root_state (core, ROTATE);
	}
}

static void __clear_panels_menuRec(RPanelsMenuItem *pmi) {
	size_t i = 0;
	for (i = 0; i < pmi->n_sub; i++) {
		RPanelsMenuItem *sub = pmi->sub[i];
		if (sub) {
			sub->selectedIndex = 0;
			__clear_panels_menuRec (sub);
		}
	}
}

static void __clear_panels_menu(RCore *core) {
	RPanels *p = core->panels;
	RPanelsMenu *pm = p->panels_menu;
	__clear_panels_menuRec (pm->root);
	pm->root->selectedIndex = 0;
	pm->history[0] = pm->root;
	pm->depth = 1;
	pm->n_refresh = 0;
}

static bool __handle_mouse_on_top(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	char *word = __get_word_from_canvas (core, panels, x, y);
	int i;
	for (i = 0; i < COUNT (menus); i++) {
		if (!strcmp (word, menus[i])) {
			__set_mode (core, PANEL_MODE_MENU);
			__clear_panels_menu (core);
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
		__handle_tab_new (core);
		free (word);
		return true;
	}
	if (word[0] == '[' && word[1] && word[2] == ']') {
		return true;
	}
	if (atoi (word)) {
		__handle_tab_nth (core, word[0]);
		return true;
	}
	return false;
}

static void __del_menu(RCore *core) {
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

static RStrBuf *__draw_menu(RCore *core, RPanelsMenuItem *item) {
	RStrBuf *buf = r_strbuf_new (NULL);
	if (!buf) {
		return NULL;
	}
	size_t i;
	for (i = 0; i < item->n_sub; i++) {
		if (i == item->selectedIndex) {
			r_strbuf_appendf (buf, "%s> %s"Color_RESET,
					core->cons->context->pal.graph_box2, item->sub[i]->name);
		} else {
			r_strbuf_appendf (buf, "  %s", item->sub[i]->name);
		}
		r_strbuf_append (buf, "          \n");
	}
	return buf;
}

static void __update_menu_contents(RCore *core, RPanelsMenu *menu, RPanelsMenuItem *parent) {
	RPanel *p = parent->p;
	RStrBuf *buf = __draw_menu (core, parent);
	if (!buf) {
		return;
	}
	free (p->model->title);
	p->model->title = r_strbuf_drain (buf);
	int new_w = r_str_bounds (p->model->title, &p->view->pos.h);
	p->view->pos.w = new_w;
	p->view->pos.h += 4;
	p->model->type = PANEL_TYPE_MENU;
	p->view->refresh = true;
	menu->refreshPanels[menu->n_refresh - 1] = p;
}

static void __handle_mouse_on_menu(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	char *word = __get_word_from_canvas_for_menu (core, panels, x, y);
	RPanelsMenu *menu = panels->panels_menu;
	int i, d = menu->depth - 1;
	while (d) {
		RPanelsMenuItem *parent = menu->history[d--];
		for (i = 0; i < parent->n_sub; i++) {
			if (!strcmp (word, parent->sub[i]->name)) {
				parent->selectedIndex = i;
				(void)(parent->sub[parent->selectedIndex]->cb (core));
				__update_menu_contents (core, menu, parent);
				free (word);
				return;
			}
		}
		__del_menu (core);
	}
	__clear_panels_menu (core);
	__set_mode (core, PANEL_MODE_DEFAULT);
	__get_cur_panel (panels)->view->refresh = true;
	free (word);
}

static void __toggle_cache(RCore *core, RPanel *p) {
	p->model->cache = !p->model->cache;
	__set_cmd_str_cache (core, p, NULL);
	p->view->refresh = true;
}

static bool __draw_modal(RCore *core, RModal *modal, int range_end, int start, const char *name) {
	if (start < modal->offset) {
		return true;
	}
	if (start >= range_end) {
		return false;
	}
	if (start == modal->idx) {
		r_strbuf_appendf (modal->data, ">  %s%s"Color_RESET, core->cons->context->pal.graph_box2, name);
	} else {
		r_strbuf_appendf (modal->data, "   %s", name);
	}
	r_strbuf_append (modal->data, "          \n");
	return true;
}

static void __update_modal(RCore *core, Sdb *menu_db, RModal *modal) {
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
			modal->offset += 1;
		}
	} else if (modal->idx < 0) {
		modal->offset = R_MAX (count - modal->pos.h, 0);
		modal->idx = count - 1;
	} else if (modal->idx < modal->offset) {
		modal->offset -= 1;
	}
	SdbList *l = sdb_foreach_list (menu_db, true);
	SdbKv *kv;
	SdbListIter *iter;
	int i = 0;
	int max_h = R_MIN (modal->offset + modal->pos.h, count);
	ls_foreach (l, iter, kv) {
		if (__draw_modal (core, modal, max_h, i, sdbkv_key (kv))) {
			i++;
		}
	}
	r_cons_gotoxy (0, 0);
	r_cons_canvas_fill (can, modal->pos.x, modal->pos.y, modal->pos.w + 2, modal->pos.h + 2, ' ');
	(void)r_cons_canvas_gotoxy (can, modal->pos.x + 2, modal->pos.y + 1);
	r_cons_canvas_write (can, r_strbuf_get (modal->data));
	r_strbuf_free (modal->data);

	r_cons_canvas_box (can, modal->pos.x, modal->pos.y, modal->pos.w + 2, modal->pos.h + 2, core->cons->context->pal.graph_box2);

	r_cons_canvas_print (can);
	r_cons_flush ();
	show_cursor (core);
}

static void __exec_modal(RCore *core, RPanel *panel, RModal *modal, Sdb *menu_db, RPanelLayout dir) {
	SdbList *l = sdb_foreach_list (menu_db, true);
	SdbKv *kv;
	SdbListIter *iter;
	int i = 0;
	ls_foreach (l, iter, kv) {
		if (i++ == modal->idx) {
			RPanelAlmightyCallback cb = sdb_ptr_get (menu_db, sdbkv_key (kv), 0);
			cb (core, panel, dir, sdbkv_key (kv));
			break;
		}
	}
}

static void __delete_modal(RCore *core, RModal *modal, Sdb *menu_db) {
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

static RModal *__init_modal(void) {
	RModal *modal = R_NEW0 (RModal);
	if (modal) {
		__set_pos (&modal->pos, 0, 0);
		modal->idx = 0;
		modal->offset = 0;
	}
	return modal;
}

static void __free_modal(RModal **modal) {
	free (*modal);
	*modal = NULL;
}

static void __create_modal(RCore *core, RPanel *panel, Sdb *menu_db) {
	__set_cursor (core, false);
	const int w = 40;
	const int h = 20;
	const int x = (core->panels->can->w - w) / 2;
	const int y = (core->panels->can->h - h) / 2;
	RModal *modal = __init_modal ();
	__set_geometry (&modal->pos, x, y, w, h);
	int okey, key, cx, cy;
	char *word = NULL;
	__update_modal (core, menu_db, modal);
	while (modal) {
		okey = r_cons_readchar ();
		key = r_cons_arrow_to_hjkl (okey);
		word = NULL;
		if (key == INT8_MAX - 1) {
			if (r_cons_get_click (&cx, &cy)) {
				if ((cx < x || x + w < cx) || ((cy < y || y + h < cy))) {
					key = 'q';
				} else {
					word = __get_word_from_canvas_for_menu (core, core->panels, cx, cy);
					if (word) {
						void *cb = sdb_ptr_get (menu_db, word, 0);
						if (cb) {
							((RPanelAlmightyCallback)cb) (core, panel, PANEL_LAYOUT_NONE, word);
							__free_modal (&modal);
							free (word);
							break;
						}
						free (word);
					}
				}
			}
		}
		switch (key) {
		case 'e':
			{
				__free_modal (&modal);
				char *cmd = __show_status_input (core, "New command: ");
				if (R_STR_ISNOTEMPTY (cmd)) {
					__replace_cmd (core, cmd, cmd);
				}
				free (cmd);
			}
		break;
		case 'j':
			modal->idx++;
			__update_modal (core, menu_db, modal);
			break;
		case 'k':
			modal->idx--;
			__update_modal (core, menu_db, modal);
			break;
		case 'v':
			__exec_modal (core, panel, modal, menu_db, PANEL_LAYOUT_VERTICAL);
			__free_modal (&modal);
			break;
		case 'h':
			__exec_modal (core, panel, modal, menu_db, PANEL_LAYOUT_HORIZONTAL);
			__free_modal (&modal);
			break;
		case 0x0d:
			__exec_modal (core, panel, modal, menu_db, PANEL_LAYOUT_NONE);
			__free_modal (&modal);
			break;
		case '-':
			__delete_modal (core, modal, menu_db);
			__update_modal (core, menu_db, modal);
			break;
		case 'q':
		case '"':
			__free_modal (&modal);
			break;
		}
	}
}

static bool __handle_mouse_on_X(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	const int idx = __get_panel_idx_in_pos (core, x, y);
	char *word = __get_word_from_canvas (core, panels, x, y);
	if (idx == -1) {
		return false;
	}
	RPanel *ppos = __get_panel(panels, idx);
	const int TITLE_Y = ppos->view->pos.y + 2;
	if (y == TITLE_Y && strcmp (word, " X ")) {
		int fx = ppos->view->pos.x;
		int fX = fx + ppos->view->pos.w;
		__set_curnode (core, idx);
		__set_refresh_all (core, true, true);
		if (x > (fX - 13) && x < fX) {
			__toggle_cache (core, __get_cur_panel (panels));
		} else if (x > fx && x < (fx + 5)) {
			__dismantle_del_panel (core, ppos, idx);
		} else {
			__create_modal (core, __get_panel (panels, 0), panels->modal_db);
			__set_mode (core, PANEL_MODE_DEFAULT);
		}
		free (word);
		return true;
	}
	free (word);
	return false;
}

static void __seek_all(RCore *core, ut64 addr) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = __get_panel (panels, i);
		panel->model->addr = addr;
	}
}

static bool __handle_mouse_on_panel(RCore *core, RPanel *panel, int x, int y, int *key) {
	RPanels *panels = core->panels;
	int h;
	(void)r_cons_get_size (&h);
	const int idx = __get_panel_idx_in_pos (core, x, y);
	char *word = __get_word_from_canvas (core, panels, x, y);
	if (idx == -1) {
		return false;
	}
	__set_curnode (core, idx);
	__set_refresh_all (core, true, true);
	RPanel *ppos = __get_panel(panels, idx);
	if (word) {
		const ut64 addr = r_num_math (core->num, word);
		if (__check_panel_type (panel, PANEL_CMD_FUNCTION) &&
				__check_if_addr (word, strlen (word))) {
			r_core_seek (core, addr, true);
			__set_addr_by_type (core, PANEL_CMD_DISASSEMBLY, addr);
		}
		r_flag_set (core->flags, "panel.addr", addr, 1);
		r_config_set (core->config, "scr.highlight", word);
		{
			ut64 addr = r_num_math (core->num, word);
			if (addr > 0) {
				// TODO implement proper panel offset sync
				// __set_panel_addr (core, cur, addr);
				__seek_all (core, addr);
			}
		}
		free (word);
	}
	if (x >= ppos->view->pos.x && x < ppos->view->pos.x + 4) {
		*key = 'c';
		return false;
	}
	return true;
}

static bool __handle_mouse(RCore *core, RPanel *panel, int *key) {
	RPanels *panels = core->panels;
	if (__drag_and_resize (core)) {
		return true;
	}
	if (key && !*key) {
		int x, y;
		if (!r_cons_get_click (&x, &y)) {
			return false;
		}
		if (y == MENU_Y && __handle_mouse_on_top (core, x, y)) {
			return true;
		}
		if (panels->mode == PANEL_MODE_MENU) {
			__handle_mouse_on_menu (core, x, y);
			return true;
		}
		if (__handle_mouse_on_X (core, x, y)) {
			return true;
		}
		if (__check_if_mouse_x_illegal (core, x) || __check_if_mouse_y_illegal (core, y)) {
			panels->mouse_on_edge_x = false;
			panels->mouse_on_edge_y = false;
			return true;
		}
		panels->mouse_on_edge_x = __check_if_mouse_x_on_edge (core, x, y);
		panels->mouse_on_edge_y = __check_if_mouse_y_on_edge (core, x, y);
		if (panels->mouse_on_edge_x || panels->mouse_on_edge_y) {
			return true;
		}
		if (__handle_mouse_on_panel (core, panel, x, y, key)) {
			return true;
		}
		int h, w = r_cons_get_size (&h);
		if (y == h) {
			RPanel *p = __get_cur_panel (panels);
			__split_panel_horizontal (core, p, p->model->title, p->model->cmd);
		} else if (x == w) {
			RPanel *p = __get_cur_panel (panels);
			__split_panel_vertical (core, p, p->model->title, p->model->cmd);
		}
	}
	if (key && *key == INT8_MAX) {
		*key = '"';
		return false;
	}
	return false;
}

static void __add_visual_mark(RCore *core) {
	char *msg = r_str_newf (R_CONS_CLEAR_LINE"Set shortcut key for 0x%"PFMT64x": ", core->offset);
	int ch = __show_status (core, msg);
	free (msg);
	r_core_visual_mark (core, ch);
}

static void __handle_visual_mark(RCore *core) {
	RPanel *cur = __get_cur_panel (core->panels);
	if (!__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		return;
	}
	int act = __show_status (core, "Visual Mark  s:set -:remove \':use: ");
	switch (act) {
	case 's':
		__add_visual_mark (core);
		break;
	case '-':
		r_cons_gotoxy (0, 0);
		if (r_core_visual_mark_dump (core)) {
			r_cons_printf (R_CONS_CLEAR_LINE"Remove a shortcut key from the list\n");
			r_cons_flush ();
			int ch = r_cons_readchar ();
			r_core_visual_mark_del (core, ch);
		}
		break;
	case '\'':
		r_cons_gotoxy (0, 0);
		if (r_core_visual_mark_dump (core)) {
			r_cons_flush ();
			int ch = r_cons_readchar ();
			r_core_visual_mark_seek (core, ch);
			__set_panel_addr (core, cur, core->offset);
		}
	}
}

static void __move_panel_to_left(RCore *core, RPanel *panel, int src) {
	RPanels *panels = core->panels;
	__shrink_panels_backward (core, src);
	panels->panel[0] = panel;
	int h, w = r_cons_get_size (&h);
	int p_w = w - panels->columnWidth;
	p_w /= 2;
	int new_w = w - p_w;
	__set_geometry (&panel->view->pos, 0, 1, p_w + 1, h - 1);
	int i = 1;
	for (; i < panels->n_panels; i++) {
		RPanel *tmp = __get_panel (panels, i);
		int t_x = ((double)tmp->view->pos.x / (double)w) * (double)new_w + p_w;
		int t_w = ((double)tmp->view->pos.w / (double)w) * (double)new_w + 1;
		__set_geometry (&tmp->view->pos, t_x, tmp->view->pos.y, t_w, tmp->view->pos.h);
	}
	__fix_layout (core);
	__set_curnode (core, 0);
}

static void __move_panel_to_right(RCore *core, RPanel *panel, int src) {
	RPanels *panels = core->panels;
	__shrink_panels_forward (core, src);
	panels->panel[panels->n_panels - 1] = panel;
	int h, w = r_cons_get_size (&h);
	int p_w = w - panels->columnWidth;
	p_w /= 2;
	int p_x = w - p_w;
	__set_geometry (&panel->view->pos, p_x - 1, 1, p_w + 1, h - 1);
	int new_w = w - p_w;
	int i = 0;
	for (; i < panels->n_panels - 1; i++) {
		RPanel *tmp = __get_panel (panels, i);
		int t_x = ((double)tmp->view->pos.x / (double)w) * (double)new_w;
		int t_w = ((double)tmp->view->pos.w / (double)w) * (double)new_w + 1;
		__set_geometry (&tmp->view->pos, t_x, tmp->view->pos.y, t_w, tmp->view->pos.h);
	}
	__fix_layout (core);
	__set_curnode (core, panels->n_panels - 1);
}

static void __move_panel_to_up(RCore *core, RPanel *panel, int src) {
	RPanels *panels = core->panels;
	__shrink_panels_backward (core, src);
	panels->panel[0] = panel;
	int h, w = r_cons_get_size (&h);
	int p_h = h / 2;
	int new_h = h - p_h;
	__set_geometry (&panel->view->pos, 0, 1, w, p_h - 1);
	int i = 1;
	for (; i < panels->n_panels; i++) {
		RPanel *tmp = __get_panel (panels, i);
		int t_y = ((double)tmp->view->pos.y / (double)h) * (double)new_h + p_h;
		int t_h = ((double)tmp->view->pos.h / (double)h) * (double)new_h + 1;
		__set_geometry (&tmp->view->pos, tmp->view->pos.x, t_y, tmp->view->pos.w, t_h);
	}
	__fix_layout (core);
	__set_curnode (core, 0);
}

static void __move_panel_to_down(RCore *core, RPanel *panel, int src) {
	RPanels *panels = core->panels;
	__shrink_panels_forward (core, src);
	panels->panel[panels->n_panels - 1] = panel;
	int h, w = r_cons_get_size (&h);
	int p_h = h / 2;
	int new_h = h - p_h;
	__set_geometry (&panel->view->pos, 0, new_h, w, p_h);
	size_t i = 0;
	for (; i < panels->n_panels - 1; i++) {
		RPanel *tmp = __get_panel (panels, i);
		const size_t t_y = (tmp->view->pos.y * new_h / h)  + 1;
		const size_t t_h = (tmp->view->edge & (1 << PANEL_EDGE_BOTTOM)) ?  new_h - t_y : (tmp->view->pos.h * new_h / h) ;
		__set_geometry (&tmp->view->pos, tmp->view->pos.x, t_y, tmp->view->pos.w, t_h);
	}
	__fix_layout (core);
	__set_curnode (core, panels->n_panels - 1);
}

static void __move_panel_to_dir(RCore *core, RPanel *panel, int src) {
	RPanels *panels = core->panels;
	__dismantle_panel (panels, panel);
	int key = __show_status (core, "Move the current panel to direction (h/j/k/l): ");
	key = r_cons_arrow_to_hjkl (key);
	__set_refresh_all (core, false, true);
	switch (key) {
	case 'h':
		__move_panel_to_left (core, panel, src);
		break;
	case 'l':
		__move_panel_to_right (core, panel, src);
		break;
	case 'k':
		__move_panel_to_up (core, panel, src);
		break;
	case 'j':
		__move_panel_to_down (core, panel, src);
		break;
	default:
		break;
	}
}

static void __set_dcb(RCore *core, RPanel *p) {
	if (__is_abnormal_cursor_type (core, p)) {
		p->model->cache = true;
		p->model->directionCb = __direction_panels_cursor_cb;
		return;
	}
	if ((p->model->cache && p->model->cmdStrCache) || p->model->readOnly) {
		p->model->directionCb = __direction_default_cb;
		return;
	}
	if (!p->model->cmd) {
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_GRAPH)) {
		p->model->directionCb = __direction_graph_cb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_STACK)) {
		p->model->directionCb = __direction_stack_cb;
	} else if (__check_panel_type (p, PANEL_CMD_DISASSEMBLY)) {
		p->model->directionCb = __direction_disassembly_cb;
	} else if (__check_panel_type (p, PANEL_CMD_REGISTERS)) {
		p->model->directionCb = __direction_register_cb;
	} else if (__check_panel_type (p, PANEL_CMD_HEXDUMP)) {
		p->model->directionCb = __direction_hexdump_cb;
	} else {
		p->model->directionCb = __direction_default_cb;
	}
}

static void __swap_panels(RPanels *panels, int p0, int p1) {
	RPanel *panel0 = __get_panel (panels, p0);
	RPanel *panel1 = __get_panel (panels, p1);
	RPanelModel *tmp = panel0->model;

	panel0->model = panel1->model;
	panel1->model = tmp;
}

static bool __check_func(RCore *core) {
	RAnalFunction *fun = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	if (!fun) {
		r_cons_message ("Not in a function. Type 'df' to define it here");
		return false;
	}
	if (r_list_empty (fun->bbs)) {
		r_cons_message ("No basic blocks in this function. You may want to use 'afb+'.");
		return false;
	}
	return true;
}

static void __call_visual_graph(RCore *core) {
	if (__check_func (core)) {
		RPanels *panels = core->panels;

		r_cons_canvas_free (panels->can);
		panels->can = NULL;

		int ocolor = r_config_get_i (core->config, "scr.color");

		r_core_visual_graph (core, NULL, NULL, true);
		r_config_set_i (core->config, "scr.color", ocolor);

		int h, w = r_cons_get_size (&h);
		panels->can = __create_new_canvas (core, w, h);
	}
}

static bool __check_func_diff(RCore *core, RPanel *p) {
	RAnalFunction *func = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	if (!func) {
		if (R_STR_ISEMPTY (p->model->funcName)) {
			return false;
		}
		p->model->funcName = NULL;
		return true;
	}
	if (!p->model->funcName || strcmp (p->model->funcName, func->name)) {
		p->model->funcName = r_str_dup (p->model->funcName, func->name);
		return true;
	}
	return false;
}

static void __print_default_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && __check_func_diff (core, panel);
	char *cmdstr = __find_cmd_str_cache (core, panel);
	if (update || !cmdstr) {
		cmdstr = __handle_cmd_str_cache (core, panel, false);
		if (panel->model->cache && panel->model->cmdStrCache) {
			__reset_scroll_pos (panel);
		}
	}
	__update_panel_contents (core, panel, cmdstr);
}

static void __print_decompiler_cb(void *user, void *p) {
	//TODO: Refactoring
	//TODO: Also, __check_func_diff should use addr not name
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && __check_func_diff (core, panel);
	char *cmdstr = NULL;
	if (!update) {
		cmdstr = __find_cmd_str_cache (core, panel);
		if (cmdstr) {
			__update_pdc_contents (core, panel, cmdstr);
		}
		return;
	}
	RAnalFunction *func = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	if (func && core->panels_root->cur_pdc_cache) {
		cmdstr = r_str_new ((char *)sdb_ptr_get (core->panels_root->cur_pdc_cache,
					r_num_as_string (NULL, func->addr, false), 0));
		if (cmdstr) {
			__set_cmd_str_cache (core, panel, cmdstr);
			__reset_scroll_pos (panel);
			__update_pdc_contents (core, panel, cmdstr);
			return;
		}
	}
	cmdstr = __handle_cmd_str_cache (core, panel, false);
	if (cmdstr) {
		__reset_scroll_pos (panel);
		__set_decompiler_cache (core, cmdstr);
		__update_pdc_contents (core, panel, cmdstr);
	}
}

static void __print_disasmsummary_cb (void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && __check_func_diff (core, panel);
	char *cmdstr = __find_cmd_str_cache (core, panel);
	if (update || !cmdstr) {
		cmdstr = __handle_cmd_str_cache (core, panel, true);
		if (panel->model->cache && panel->model->cmdStrCache) {
			__reset_scroll_pos (panel);
		}
	}
	__update_panel_contents (core, panel, cmdstr);
}

static void __print_disassembly_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	core->print->screen_bounds = 1LL;
	char *cmdstr = __find_cmd_str_cache (core, panel);
	if (cmdstr) {
		__update_panel_contents (core, panel, cmdstr);
		return;
	}
	char *ocmd = panel->model->cmd;
	panel->model->cmd = r_str_newf ("%s %d", panel->model->cmd, panel->view->pos.h - 3);
	ut64 o_offset = core->offset;
	core->offset = panel->model->addr;
	r_core_seek (core, panel->model->addr, true);
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_core_cmd (core, ".dr*", 0);
	}
	cmdstr = __handle_cmd_str_cache (core, panel, false);
	core->offset = o_offset;
	free (panel->model->cmd);
	panel->model->cmd = ocmd;
	__update_panel_contents (core, panel, cmdstr);
}

static void __do_panels_refresh(RCore *core) {
	if (core->panels) {
		__panel_all_clear (core->panels);
		__panels_layout_refresh (core);
	}
}

static void __do_panels_resize(RCore *core) {
	RPanels *panels = core->panels;
	int i;
	int h, w = r_cons_get_size (&h);
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = __get_panel (panels, i);
		if ((panel->view->edge & (1 << PANEL_EDGE_BOTTOM))
				&& (panel->view->pos.y + panel->view->pos.h < h)) {
			panel->view->pos.h = h - panel->view->pos.y;
		}
		if ((panel->view->edge & (1 << PANEL_EDGE_RIGHT))
				&& (panel->view->pos.x + panel->view->pos.w < w)) {
			panel->view->pos.w = w - panel->view->pos.x;
		}
	}
	__do_panels_refresh (core);
}

static void __do_panels_refreshOneShot(RCore *core) {
	r_core_task_enqueue_oneshot (&core->tasks, (RCoreTaskOneShot) __do_panels_resize, core);
}

static void __print_graph_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && __check_func_diff (core, panel);
	char *cmdstr = __find_cmd_str_cache (core, panel);
	if (update || !cmdstr) {
		cmdstr = __handle_cmd_str_cache (core, panel, false);
	}
	core->cons->event_resize = NULL;
	core->cons->event_data = core;
	core->cons->event_resize = (RConsEvent) __do_panels_refreshOneShot;
	__update_panel_contents (core, panel, cmdstr);
}

static void __print_stack_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	const int delta = r_config_get_i (core->config, "stack.delta");
	const int bits = r_config_get_i (core->config, "asm.bits");
	const char sign = (delta < 0)? '+': '-';
	const int absdelta = R_ABS (delta);
	char *cmd = r_str_newf ("%s%s ", PANEL_CMD_STACK, bits == 32 ? "w" : "q");
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
	const char *cmdstr = r_core_cmd_str (core, r_str_newf ("%s%c%d", cmd, sign, absdelta));
	__update_panel_contents (core, panel, cmdstr);
}

static void __print_hexdump_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	char *cmdstr = __find_cmd_str_cache (core, panel);
	if (!cmdstr) {
		ut64 o_offset = core->offset;
		if (!panel->model->cache) {
			core->offset = panel->model->addr;
			r_core_seek (core, core->offset, true);
			r_core_block_read (core);
		}
		char *base = hexdump_rotate[R_ABS(panel->model->rotate) % COUNT (hexdump_rotate)];
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
		cmdstr = __handle_cmd_str_cache (core, panel, false);
		core->offset = o_offset;
	}
	__update_panel_contents (core, panel, cmdstr);
}

static void __hudstuff(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	r_core_visual_hudstuff (core);

	if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		__set_panel_addr (core, cur, core->offset);
	} else {
		int i;
		for (i = 0; i < panels->n_panels; i++) {
			RPanel *panel = __get_panel (panels, i);
			if (__check_panel_type (panel, PANEL_CMD_DISASSEMBLY)) {
				__set_panel_addr (core, panel, core->offset);
				break;
			}
		}
	}
}

static void __print_snow(RPanels *panels) {
	if (!panels->snows) {
		panels->snows = r_list_newf (free);
	}
	RPanel *cur = __get_cur_panel (panels);
	int i, amount = r_num_rand (4);
	if (amount > 0) {
		for (i = 0; i < amount; i++) {
			RPanelsSnow *snow = R_NEW (RPanelsSnow);
			snow->x = r_num_rand (cur->view->pos.w) + cur->view->pos.x;
			snow->y = cur->view->pos.y;
			r_list_append (panels->snows, snow);
		}
	}
	RListIter *iter, *iter2;
	RPanelsSnow *snow;
	r_list_foreach_safe (panels->snows, iter, iter2, snow) {
		int pos = r_num_rand (3) - 1;
		snow->x += pos;
		snow->y++;
		if (snow->x >= cur->view->pos.w + cur->view->pos.x || snow->x <= cur->view->pos.x + 1) {
			r_list_delete (panels->snows, iter);
			continue;
		}
		if (snow->y >= cur->view->pos.h + cur->view->pos.y - 1) {
			r_list_delete (panels->snows, iter);
			continue;
		}
		if (r_cons_canvas_gotoxy (panels->can, snow->x, snow->y)) {
			if (panels->fun == PANEL_FUN_SAKURA) {
				r_cons_canvas_write (panels->can, Color_BMAGENTA","Color_RESET);
			} else {
				r_cons_canvas_write (panels->can, "*");
			}
		}
	}
}

static void __set_pcb(RPanel *p) {
	if (!p->model->cmd) {
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_DISASSEMBLY)) {
		p->model->print_cb = __print_disassembly_cb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_STACK)) {
		p->model->print_cb = __print_stack_cb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_HEXDUMP)) {
		p->model->print_cb = __print_hexdump_cb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_DECOMPILER)) {
		p->model->print_cb = __print_decompiler_cb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_GRAPH)) {
		p->model->print_cb = __print_graph_cb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_TINYGRAPH)) {
		p->model->print_cb = __print_graph_cb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_DISASMSUMMARY)) {
		p->model->print_cb = __print_disasmsummary_cb;
		return;
	}
	p->model->print_cb = __print_default_cb;
}

static int __file_history_up(RLine *line) {
	RCore *core = line->user;
	RList *files = r_id_storage_list (core->io->files);
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

static int __file_history_down(RLine *line) {
	RCore *core = line->user;
	RList *files = r_id_storage_list (core->io->files);
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


static int __open_file_cb(void *user) {
	RCore *core = (RCore *)user;
	core->cons->line->prompt_type = R_LINE_PROMPT_FILE;
	r_line_set_hist_callback (core->cons->line, &__file_history_up, &__file_history_down);
	__add_cmdf_panel (core, "open file: ", "o %s");
	core->cons->line->prompt_type = R_LINE_PROMPT_DEFAULT;
	r_line_set_hist_callback (core->cons->line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	return 0;
}

static int __rw_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "oo+", 0);
	return 0;
}

static int __debugger_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "oo", 0);
	return 0;
}

static int __settings_decompiler_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsRoot *root = core->panels_root;
	RPanelsMenu *menu = core->panels->panels_menu;
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
	int j = 0;
	for (j = 0; j < core->panels->n_panels; j++) {
		RPanel *panel = __get_panel (core->panels, j);
		if (!strncmp (panel->model->cmd, "pdc", 3)) {
			char *cmdstr = r_core_cmd_strf (core, "pdc@0x%08"PFMT64x, panel->model->addr);
			__update_panel_contents (core, panel, cmdstr);
			__reset_scroll_pos (panel);
			free (cmdstr);
		}
	}
	__set_refresh_all (core, true, false);
	__set_mode (core, PANEL_MODE_DEFAULT);
	return 0;
}

static void __create_default_panels(RCore *core) {
	RPanels *panels = core->panels;
	panels->n_panels = 0;
	__set_curnode (core, 0);
	const char **panels_list = panels_static;
	if (panels->layout == PANEL_LAYOUT_DEFAULT_DYNAMIC) {
		panels_list = panels_dynamic;
	}

	int i = 0;
	while (panels_list[i]) {
		RPanel *p = __get_panel (panels, panels->n_panels);
		if (!p) {
			return;
		}
		const char *s = panels_list[i++];
		char *db_val = __search_db (core, s);
		__init_panel_param (core, p, s, db_val);
		free (db_val);
	}
}

static int __load_layout_saved_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	if (!r_core_panels_load (core, child->name)) {
		__create_default_panels (core);
		__panels_layout (core->panels);
	}
	__set_curnode (core, 0);
	core->panels->panels_menu->depth = 1;
	__set_mode (core, PANEL_MODE_DEFAULT);
	return 0;
}

static int __load_layout_default_cb(void *user) {
	RCore *core = (RCore *)user;
	__init_panels (core, core->panels);
	__create_default_panels (core);
	__panels_layout (core->panels);
	core->panels->panels_menu->depth = 1;
	__set_mode (core, PANEL_MODE_DEFAULT);
	return 0;
}

static int __close_file_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "o-*");
	return 0;
}

static int __save_layout_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_panels_save (core, NULL);
	__set_mode (core, PANEL_MODE_DEFAULT);
	__clear_panels_menu (core);
	__get_cur_panel (core->panels)->view->refresh = true;
	return 0;
}

static void __update_menu(RCore *core, const char *parent, R_NULLABLE RPanelMenuUpdateCallback cb) {
	RPanels *panels = core->panels;
	void *addr = ht_pp_find (panels->mht, parent, NULL);
	RPanelsMenuItem *p_item = (RPanelsMenuItem *)addr;
	int i;
	for (i = 0; i < p_item->n_sub; i++) {
		RPanelsMenuItem *sub = p_item->sub[i];
		ht_pp_delete (core->panels->mht, sdb_fmt ("%s.%s", parent, sub->name));
	}
	p_item->sub = NULL;
	p_item->n_sub = 0;
	if (cb) {
		cb (core, parent);
	}
	RPanelsMenu *menu = panels->panels_menu;
	__update_menu_contents (core, menu, p_item);
}

static char *__get_panels_config_dir_path(void) {
	return r_str_home (R_JOIN_2_PATHS (R2_HOME_DATADIR, ".r2panels"));
}

static void __add_menu(RCore *core, const char *parent, const char *name, RPanelsMenuCallback cb) {
	RPanels *panels = core->panels;
	RPanelsMenuItem *p_item, *item = R_NEW0 (RPanelsMenuItem);
	if (!item) {
		return;
	}
	if (parent) {
		void *addr = ht_pp_find (panels->mht, parent, NULL);
		p_item = (RPanelsMenuItem *)addr;
		ht_pp_insert (panels->mht, sdb_fmt ("%s.%s", parent, name), item);
	} else {
		p_item = panels->panels_menu->root;
		ht_pp_insert (panels->mht, sdb_fmt ("%s", name), item);
	}
	item->n_sub = 0;
	item->selectedIndex = 0;
	item->name = name ? r_str_new (name) : NULL;
	item->sub = NULL;
	item->cb = cb;
	item->p = R_NEW0 (RPanel);
	if (item->p) {
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
	__free_menu_item (item);
}

static void __init_menu_saved_layout (void *_core, const char *parent) {
	char *dir_path = __get_panels_config_dir_path ();
	RList *dir = r_sys_dir (dir_path);
	if (!dir) {
		free (dir_path);
		return;
	}
	RCore *core = (RCore *)_core;
	RListIter *it;
	char *entry;
	r_list_foreach (dir, it, entry) {
		if (strcmp (entry, ".") && strcmp (entry, "..")) {
			__add_menu (core, parent, entry, __load_layout_saved_cb);
		}
	}
	r_list_free (dir);
	free (dir_path);
}

static int __clear_layout_cb(void *user) {
	RCore *core = (RCore *)user;
	if (!__show_status_yesno (core, 0, "Clear all the saved layouts?(y/n): ")) {
		return 0;
	}
	char *dir_path = __get_panels_config_dir_path ();
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

	__update_menu (core, "File.Load Layout.Saved", __init_menu_saved_layout);
	return 0;
}

static int __copy_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "How many bytes? ", "\"y %s\"");
	return 0;
}

static int __paste_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "yy");
	return 0;
}

static int __write_str_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "insert string: ", "\"w %s\"");
	return 0;
}

static int __write_hex_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "insert hexpairs: ", "\"wx %s\"");
	return 0;
}

static int __assemble_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_visual_asm (core, core->offset);
	return 0;
}

static int __fill_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "Fill with: ", "wow %s");
	return 0;
}

static int __settings_colors_cb(void *user) {
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
	__update_menu(core, "Settings.Colors", __init_menu_color_settings_layout);
	return 0;
}

static int __config_value_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	RStrBuf *tmp = r_strbuf_new (child->name);
	(void)r_str_split (r_strbuf_get(tmp), ':');
	const char *v = __show_status_input (core, "New value: ");
	r_config_set (core->config, r_strbuf_get (tmp), v);
	r_strbuf_free (tmp);
	free (parent->p->model->title);
	parent->p->model->title = r_strbuf_drain (__draw_menu (core, parent));
	size_t i;
	for (i = 1; i < menu->depth; i++) {
		RPanel *p = menu->history[i]->p;
		p->view->refresh = true;
		menu->refreshPanels[i - 1] = p;
	}
	if (!strcmp (parent->name, "asm")) {
		__update_menu (core, "Settings.Disassembly.asm", __init_menu_disasm_asm_settings_layout);
	}
	if (!strcmp (parent->name, "Screen")) {
		__update_menu (core, "Settings.Screen", __init_menu_screen_settings_layout);
	}
	return 0;
}

static int __config_toggle_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	RStrBuf *tmp = r_strbuf_new (child->name);
	(void)r_str_split (r_strbuf_get (tmp), ':');
	r_config_toggle (core->config, r_strbuf_get (tmp));
	r_strbuf_free (tmp);
	free (parent->p->model->title);
	parent->p->model->title = r_strbuf_drain (__draw_menu (core, parent));
	size_t i;
	for (i = 1; i < menu->depth; i++) {
		RPanel *p = menu->history[i]->p;
		p->view->refresh = true;
		menu->refreshPanels[i - 1] = p;
	}
	if (!strcmp (parent->name, "asm")) {
		__update_menu (core, "Settings.Disassembly.asm", __init_menu_disasm_asm_settings_layout);
	}
	if (!strcmp (parent->name, "Screen")) {
		__update_menu (core, "Settings.Screen", __init_menu_screen_settings_layout);
	}
	return 0;
}

static void __init_menu_screen_settings_layout(void *_core, const char *parent) {
	RCore *core = (RCore *)_core;
	RStrBuf *rsb = r_strbuf_new (NULL);
	int i = 0;
	while (menus_settings_screen[i]) {
		const char *menu = menus_settings_screen[i];
		r_strbuf_set (rsb, menu);
		r_strbuf_append (rsb, ": ");
		r_strbuf_append (rsb, r_config_get (core->config, menu));
		if (!strcmp (menus_settings_screen[i], "scr.color")) {
			__add_menu (core, parent, r_strbuf_get (rsb), __config_value_cb);
		} else {
			__add_menu (core, parent, r_strbuf_get (rsb), __config_toggle_cb);
		}
		i++;
	}
	r_strbuf_free (rsb);
}

static int __calculator_cb(void *user) {
	RCore *core = (RCore *)user;
	for (;;) {
		char *s = __show_status_input (core, "> ");
		if (!s || !*s) {
			free (s);
			break;
		}
		r_core_cmdf (core, "? %s", s);
		r_cons_flush ();
		free (s);
	}
	return 0;
}

static int __r2_shell_cb(void *user) {
	RCore *core = (RCore *)user;
	core->vmode = false;
	r_core_visual_prompt_input (core);
	core->vmode = true;
	return 0;
}

static int __system_shell_cb(void *user) {
	r_cons_set_raw (0);
	r_cons_flush ();
	r_sys_cmd ("$SHELL");
	return 0;
}

static int __string_whole_bin_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "search strings in the whole binary: ", "izzq~%s");
	return 0;
}

static int __string_data_sec_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "search string in data sections: ", "izq~%s");
	return 0;
}

static int __rop_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "rop grep: ", "\"/R %s\"");
	return 0;
}

static int __code_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "search code: ", "\"/c %s\"");
	return 0;
}

static int __hexpairs_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "search hexpairs: ", "\"/x %s\"");
	return 0;
}

static void __esil_init(RCore *core) {
	r_core_cmd (core, "aeim", 0);
	r_core_cmd (core, "aeip", 0);
}

static void __esil_step_to(RCore *core, ut64 end) {
	r_core_cmdf (core, "aesu 0x%08"PFMT64x, end);
}


static int __esil_init_cb(void *user) {
	RCore *core = (RCore *)user;
	__esil_init (core);
	return 0;
}

static int __esil_step_to_cb(void *user) {
	RCore *core = (RCore *)user;
	char *end = __show_status_input (core, "target addr: ");
	__esil_step_to (core, r_num_math (core->num, end));
	return 0;
}

static int __esil_step_range_cb(void *user) {
	RStrBuf *rsb = r_strbuf_new (NULL);
	RCore *core = (RCore *)user;
	r_strbuf_append (rsb, "start addr: ");
	char *s = __show_status_input (core, r_strbuf_get (rsb));
	r_strbuf_append (rsb, s);
	r_strbuf_append (rsb, " end addr: ");
	char *d = __show_status_input (core, r_strbuf_get (rsb));
	r_strbuf_free (rsb);
	ut64 s_a = r_num_math (core->num, s);
	ut64 d_a = r_num_math (core->num, d);
	if (s_a >= d_a) {
		return 0;
	}
	ut64 tmp = core->offset;
	core->offset = s_a;
	__esil_init (core);
	__esil_step_to (core, d_a);
	core->offset = tmp;
	return 0;
}

static int __io_cache_on_cb(void *user) {
	RCore *core = (RCore *)user;
	r_config_set_b (core->config, "io.cache", true);
	(void)__show_status (core, "io.cache is on");
	__set_mode (core, PANEL_MODE_DEFAULT);
	return 0;
}

static int __io_cache_off_cb(void *user) {
	RCore *core = (RCore *)user;
	r_config_set_b (core->config, "io.cache", false);
	(void)__show_status (core, "io.cache is off");
	__set_mode (core, PANEL_MODE_DEFAULT);
	return 0;
}

static int __reload_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_file_reopen_debug (core, "");
	__update_disassembly_or_open (core);
	return 0;
}

static int __function_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "af");
	return 0;
}

static int __symbols_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aa");
	return 0;
}

static int __program_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aaa");
	return 0;
}

static int __basic_blocks_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aab");
	return 0;
}

static int __calls_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aac");
	return 0;
}

static int __watch_points_cb(void *user) {
	RCore *core = (RCore *)user;
	char addrBuf[128], rw[128];
	const char *addrPrompt = "addr: ", *rwPrompt = "<r/w/rw>: ";
	__panel_prompt (addrPrompt, addrBuf, sizeof (addrBuf));
	__panel_prompt (rwPrompt, rw, sizeof (rw));
	ut64 addr = r_num_math (core->num, addrBuf);
	r_core_cmdf (core, "dbw 0x%08"PFMT64x" %s", addr, rw);
	return 0;
}

static int __references_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aar");
	return 0;
}

static int __fortune_cb(void *user) {
	RCore *core = (RCore *)user;
	char *s = r_core_cmd_str (core, "fo");
	r_cons_message (s);
	free (s);
	return 0;
}

static int __game_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_2048 (core->panels->can->color);
	return 0;
}

static int __help_cb(void *user) {
	RCore *core = (RCore *)user;
	__toggle_help (core);
	return 0;
}

static int __license_cb(void *user) {
	r_cons_message ("Copyright 2006-2020 - pancake - LGPL");
	return 0;
}

static int __version_cb(void *user) {
	RCore *core = (RCore *)user;
	char *s = r_core_cmd_str (core, "?V");
	r_cons_message (s);
	free (s);
	return 0;
}

static int __writeValueCb(void *user) {
	RCore *core = (RCore *)user;
	char *res = __show_status_input (core, "insert number: ");
	if (res) {
		r_core_cmdf (core, "\"wv %s\"", res);
		free (res);
	}
	return 0;
}

static int __quit_cb(void *user) {
	__set_root_state ((RCore *)user, QUIT);
	return 0;
}

static int __open_menu_cb (void *user) {
	RCore* core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	if (menu->depth < 2) {
		__set_pos (&child->p->view->pos, menu->root->selectedIndex * 6, 1);
	} else {
		RPanelsMenuItem *p = menu->history[menu->depth - 2];
		RPanelsMenuItem *parent2 = p->sub[p->selectedIndex];
		__set_pos (&child->p->view->pos, parent2->p->view->pos.x + parent2->p->view->pos.w - 1,
				menu->depth == 2 ? parent2->p->view->pos.y + parent2->selectedIndex : parent2->p->view->pos.y);
	}
	RStrBuf *buf = __draw_menu (core, child);
	if (!buf) {
		return 0;
	}
	free (child->p->model->title);
	child->p->model->title = r_strbuf_drain (buf);
	child->p->view->pos.w = r_str_bounds (child->p->model->title, &child->p->view->pos.h);
	child->p->view->pos.h += 4;
	child->p->model->type = PANEL_TYPE_MENU;
	child->p->view->refresh = true;
	menu->refreshPanels[menu->n_refresh++] = child->p;
	menu->history[menu->depth++] = child;
	return 0;
}

static int cmpstr(const void *_a, const void *_b) {
	char *a = (char *)_a, *b = (char *)_b;
	return strcmp (a, b);
}

static RList *__sorted_list(RCore *core, const char *menu[], int count) {
	RList *list = r_list_newf (NULL);
	int i;
	for (i = 0; i < count; i++) {
		if (menu[i]) {
			(void)r_list_append (list, (void *)menu[i]);
		}
	}
	r_list_sort (list, cmpstr);
	return list;
}

static void __init_menu_color_settings_layout (void *_core, const char *parent) {
	RCore *core = (RCore *)_core;
	const char *color = core->cons->context->pal.graph_box2;
	char *now = r_core_cmd_str (core, "eco.");
	r_str_split (now, '\n');
	parent = "Settings.Colors";
	RList *list = __sorted_list (core, (const char **)menus_Colors, COUNT (menus_Colors));
	char *pos;
	RListIter* iter;
	RStrBuf *buf = r_strbuf_new (NULL);
	r_list_foreach (list, iter, pos) {
		if (pos && !strcmp (now, pos)) {
			r_strbuf_setf (buf, "%s%s", color, pos);
			__add_menu (core, parent, r_strbuf_get (buf), __settings_colors_cb);
			continue;
		}
		__add_menu (core, parent, pos, __settings_colors_cb);
	}
	free (now);
	r_list_free (list);
	r_strbuf_free (buf);
}

static void __init_menu_disasm_settings_layout (void *_core, const char *parent) {
	RCore *core = (RCore *)_core;
	int i = 0;
	RList *list = __sorted_list (core, menus_settings_disassembly, COUNT (menus_settings_disassembly));
	char *pos;
	RListIter* iter;
	RStrBuf *rsb = r_strbuf_new (NULL);
	r_list_foreach (list, iter, pos) {
		if (!strcmp (pos, "asm")) {
			__add_menu (core, parent, pos, __open_menu_cb);
			__init_menu_disasm_asm_settings_layout (core, "Settings.Disassembly.asm");
		} else {
			r_strbuf_set (rsb, pos);
			r_strbuf_append (rsb, ": ");
			r_strbuf_append (rsb, r_config_get (core->config, pos));
			__add_menu (core, parent, r_strbuf_get (rsb), __config_toggle_cb);
		}
		i++;
	}
	r_list_free (list);
	r_strbuf_free (rsb);
}

static void __init_menu_disasm_asm_settings_layout(void *_core, const char *parent) {
	RCore *core = (RCore *)_core;
	RList *list = __sorted_list (core, menus_settings_disassembly_asm, COUNT (menus_settings_disassembly_asm));
	char *pos;
	RListIter* iter;
	RStrBuf *rsb = r_strbuf_new (NULL);
	r_list_foreach (list, iter, pos) {
		r_strbuf_set (rsb, pos);
		r_strbuf_append (rsb, ": ");
		r_strbuf_append (rsb, r_config_get (core->config, pos));
		if (!strcmp (pos, "asm.var.summary") ||
				!strcmp (pos, "asm.arch") ||
				!strcmp (pos, "asm.bits") ||
				!strcmp (pos, "asm.cpu")) {
			__add_menu (core, parent, r_strbuf_get (rsb), __config_value_cb);
		} else {
			__add_menu (core, parent, r_strbuf_get (rsb), __config_toggle_cb);
		}
	}
	r_list_free (list);
	r_strbuf_free (rsb);
}

static void __load_config_menu(RCore *core) {
	RList *themes_list = r_core_list_themes (core);
	RListIter *th_iter;
	char *th;
	int i = 0;
	r_list_foreach (themes_list, th_iter, th) {
		menus_Colors[i++] = th;
	}
}

static bool __init_panels_menu(RCore *core) {
	RPanels *panels = core->panels;
	RPanelsMenu *panels_menu = R_NEW0 (RPanelsMenu);
	if (!panels_menu) {
		return false;
	}
	RPanelsMenuItem *root = R_NEW0 (RPanelsMenuItem);
	if (!root) {
		R_FREE (panels_menu);
		return false;
	}
	panels->panels_menu = panels_menu;
	panels_menu->root = root;
	root->n_sub = 0;
	root->name = NULL;
	root->sub = NULL;

	__load_config_menu (core);

	int i = 0;
	while (menus[i]) {
		__add_menu (core, NULL, menus[i], __open_menu_cb);
		i++;
	}
	char *parent = "File";
	i = 0;
	while (menus_File[i]) {
		if (!strcmp (menus_File[i], "Open")) {
			__add_menu (core, parent, menus_File[i], __open_file_cb);
		} else if (!strcmp (menus_File[i], "ReOpen")) {
			__add_menu (core, parent, menus_File[i], __open_menu_cb);
		} else if (!strcmp (menus_File[i], "Close")) {
			__add_menu (core, parent, menus_File[i], __close_file_cb);
		} else if (!strcmp (menus_File[i], "Save Layout")) {
			__add_menu (core, parent, menus_File[i], __save_layout_cb);
		} else if (!strcmp (menus_File[i], "Load Layout")) {
			__add_menu (core, parent, menus_File[i], __open_menu_cb);
		} else if (!strcmp (menus_File[i], "Clear Saved Layouts")) {
			__add_menu (core, parent, menus_File[i], __clear_layout_cb);
		} else if (!strcmp (menus_File[i], "Quit")) {
			__add_menu (core, parent, menus_File[i], __quit_cb);
		} else {
			__add_menu (core, parent, menus_File[i], __add_cmd_panel);
		}
		i++;
	}

	parent = "Settings";
	i = 0;
	while (menus_Settings[i]) {
		__add_menu (core, parent, menus_Settings[i++], __open_menu_cb);
	}

	parent = "Edit";
	i = 0;
	while (menus_Edit[i]) {
		if (!strcmp (menus_Edit[i], "Copy")) {
			__add_menu (core, parent, menus_Edit[i], __copy_cb);
		} else if (!strcmp (menus_Edit[i], "Paste")) {
			__add_menu (core, parent, menus_Edit[i], __paste_cb);
		} else if (!strcmp (menus_Edit[i], "Write String")) {
			__add_menu (core, parent, menus_Edit[i], __write_str_cb);
		} else if (!strcmp (menus_Edit[i], "Write Hex")) {
			__add_menu (core, parent, menus_Edit[i], __write_hex_cb);
		} else if (!strcmp (menus_Edit[i], "Write Value")) {
			__add_menu (core, parent, menus_Edit[i], __writeValueCb);
		} else if (!strcmp (menus_Edit[i], "Assemble")) {
			__add_menu (core, parent, menus_Edit[i], __assemble_cb);
		} else if (!strcmp (menus_Edit[i], "Fill")) {
			__add_menu (core, parent, menus_Edit[i], __fill_cb);
		} else if (!strcmp (menus_Edit[i], "io.cache")) {
			__add_menu (core, parent, menus_Edit[i], __open_menu_cb);
		} else {
			__add_menu (core, parent, menus_Edit[i], __add_cmd_panel);
		}
		i++;
	}

	{
		parent = "View";
		RList *list = __sorted_list (core, menus_View, COUNT (menus_View));
		char *pos;
		RListIter* iter;
		r_list_foreach (list, iter, pos) {
			if (!strcmp (pos, PANEL_TITLE_ALL_DECOMPILER)) {
				__add_menu (core, parent, pos, __show_all_decompiler_cb);
			} else {
				__add_menu (core, parent, pos, __add_cmd_panel);
			}
		}
	}

	parent = "Tools";
	i = 0;
	while (menus_Tools[i]) {
		if (!strcmp (menus_Tools[i], "Calculator")) {
			__add_menu (core, parent, menus_Tools[i], __calculator_cb);
		} else if (!strcmp (menus_Tools[i], "R2 Shell")) {
			__add_menu (core, parent, menus_Tools[i], __r2_shell_cb);
		} else if (!strcmp (menus_Tools[i], "System Shell")) {
			__add_menu (core, parent, menus_Tools[i], __system_shell_cb);
		}
		i++;
	}

	parent = "Search";
	i = 0;
	while (menus_Search[i]) {
		if (!strcmp (menus_Search[i], "String (Whole Bin)")) {
			__add_menu (core, parent, menus_Search[i], __string_whole_bin_cb);
		} else if (!strcmp (menus_Search[i], "String (Data Sections)")) {
			__add_menu (core, parent, menus_Search[i], __string_data_sec_cb);
		} else if (!strcmp (menus_Search[i], "ROP")) {
			__add_menu (core, parent, menus_Search[i], __rop_cb);
		} else if (!strcmp (menus_Search[i], "Code")) {
			__add_menu (core, parent, menus_Search[i], __code_cb);
		} else if (!strcmp (menus_Search[i], "Hexpairs")) {
			__add_menu (core, parent, menus_Search[i], __hexpairs_cb);
		}
		i++;
	}

	parent = "Emulate";
	i = 0;
	while (menus_Emulate[i]) {
		if (!strcmp (menus_Emulate[i], "Step From")) {
			__add_menu (core, parent, menus_Emulate[i], __esil_init_cb);
		} else if (!strcmp (menus_Emulate[i], "Step To")) {
			__add_menu (core, parent, menus_Emulate[i], __esil_step_to_cb);
		} else if (!strcmp (menus_Emulate[i], "Step Range")) {
			__add_menu (core, parent, menus_Emulate[i], __esil_step_range_cb);
		}
		i++;
	}

	{
		parent = "Debug";
		RList *list = __sorted_list (core, menus_Debug, COUNT (menus_Debug));
		char *pos;
		RListIter* iter;
		r_list_foreach (list, iter, pos) {
			if (!strcmp (pos, "Breakpoints")) {
				__add_menu (core, parent, pos, __break_points_cb);
			} else if (!strcmp (pos, "Watchpoints")) {
				__add_menu (core, parent, pos, __watch_points_cb);
			} else if (!strcmp (pos, "Continue")) {
				__add_menu (core, parent, pos, __continue_cb);
			} else if (!strcmp (pos, "Step")) {
				__add_menu (core, parent, pos, __step_cb);
			} else if (!strcmp (pos, "Step Over")) {
				__add_menu (core, parent, pos, __step_over_cb);
			} else if (!strcmp (pos, "Reload")) {
				__add_menu (core, parent, pos, __reload_cb);
			} else {
				__add_menu (core, parent, pos, __add_cmd_panel);
			}
		}
	}

	parent = "Analyze";
	i = 0;
	while (menus_Analyze[i]) {
		if (!strcmp (menus_Analyze[i], "Function")) {
			__add_menu (core, parent, menus_Analyze[i], __function_cb);
		} else if (!strcmp (menus_Analyze[i], "Symbols")) {
			__add_menu (core, parent, menus_Analyze[i], __symbols_cb);
		} else if (!strcmp (menus_Analyze[i], "Program")) {
			__add_menu (core, parent, menus_Analyze[i], __program_cb);
		} else if (!strcmp (menus_Analyze[i], "BasicBlocks")) {
			__add_menu (core, parent, menus_Analyze[i], __basic_blocks_cb);
		} else if (!strcmp (menus_Analyze[i], "Calls")) {
			__add_menu (core, parent, menus_Analyze[i], __calls_cb);
		} else if (!strcmp (menus_Analyze[i], "References")) {
			__add_menu (core, parent, menus_Analyze[i], __references_cb);
		}
		i++;
	}
	parent = "Help";
	i = 0;
	while (menus_Help[i]) {
		if (!strcmp (menus_Help[i], "License")) {
			__add_menu (core, parent, menus_Help[i], __license_cb);
		} else if (!strcmp (menus_Help[i], "Version")) {
			__add_menu (core, parent, menus_Help[i], __version_cb);
		} else if (!strcmp (menus_Help[i], "Fortune")) {
			__add_menu (core, parent, menus_Help[i], __fortune_cb);
		} else if (!strcmp (menus_Help[i], "2048")) {
			__add_menu (core, parent, menus_Help[i], __game_cb);
		} else {
			__add_menu (core, parent, menus_Help[i], __help_cb);
		}
		i++;
	}

	parent = "File.ReOpen";
	i = 0;
	while (menus_ReOpen[i]) {
		if (!strcmp (menus_ReOpen[i], "In RW")) {
			__add_menu (core, parent, menus_ReOpen[i], __rw_cb);
		} else if (!strcmp (menus_ReOpen[i], "In Debugger")) {
			__add_menu (core, parent, menus_ReOpen[i], __debugger_cb);
		}
		i++;
	}

	parent = "File.Load Layout";
	i = 0;
	while (menus_loadLayout[i]) {
		if (!strcmp (menus_loadLayout[i], "Saved")) {
			__add_menu (core, parent, menus_loadLayout[i], __open_menu_cb);
		} else if (!strcmp (menus_loadLayout[i], "Default")) {
			__add_menu (core, parent, menus_loadLayout[i], __load_layout_default_cb);
		}
		i++;
	}

	__init_menu_saved_layout (core, "File.Load Layout.Saved");

	__init_menu_color_settings_layout (core, "Settings.Colors");

	{
		parent = "Settings.Decompiler";
		char *opts = r_core_cmd_str (core, "e cmd.pdc=?");
		RList *optl = r_str_split_list (opts, "\n", 0);
		RListIter *iter;
		char *opt;
		r_list_foreach (optl, iter, opt) {
			__add_menu (core, parent, strdup (opt), __settings_decompiler_cb);
		}
		r_list_free (optl);
		free (opts);
	}

	__init_menu_disasm_settings_layout (core, "Settings.Disassembly");
	__init_menu_screen_settings_layout (core, "Settings.Screen");

	parent = "Edit.io.cache";
	i = 0;
	while (menus_iocache[i]) {
		if (!strcmp (menus_iocache[i], "On")) {
			__add_menu (core, parent, menus_iocache[i], __io_cache_on_cb);
		} else if (!strcmp (menus_iocache[i], "Off")) {
			__add_menu (core, parent, menus_iocache[i], __io_cache_off_cb);
		}
		i++;
	}

	panels_menu->history = calloc (8, sizeof (RPanelsMenuItem *));
	__clear_panels_menu (core);
	panels_menu->refreshPanels = calloc (8, sizeof (RPanel *));
	return true;
}

static bool __init_panels(RCore *core, RPanels *panels) {
	panels->panel = calloc (sizeof (RPanel *), PANEL_NUM_LIMIT);
	if (!panels->panel) {
		return false;
	}
	int i;
	for (i = 0; i < PANEL_NUM_LIMIT; i++) {
		panels->panel[i] = R_NEW0 (RPanel);
		panels->panel[i]->model = R_NEW0 (RPanelModel);
		__renew_filter (panels->panel[i], PANEL_NUM_LIMIT);
		panels->panel[i]->view = R_NEW0 (RPanelView);
		if (!panels->panel[i]->model || !panels->panel[i]->view) {
			return false;
		}
	}
	return true;
}

static void __refresh_core_offset (RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = __get_cur_panel (panels);
	if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		core->offset = cur->model->addr;
	}
}

static void demo_begin(RCore *core, RConsCanvas *can) {
	char *s = r_cons_canvas_to_string (can);
	if (s) {
		// TODO drop utf8!!
		r_str_ansi_filter (s, NULL, NULL, -1);
		int i, h, w = r_cons_get_size (&h);
		for (i = 0; i < 40; i+= (1 + (i/30))) {
			int H = i * ((double)h / 40);
			char *r = r_str_scale (s, w, H);
			r_cons_clear00 ();
			r_cons_gotoxy (0, (h / 2) - (H / 2));
			r_cons_strcat (r);
			r_cons_flush ();
			free (r);
			r_sys_usleep (3000);
		}
		free (s);
	}
}

static void demo_end(RCore *core, RConsCanvas *can) {
	bool utf8 = r_config_get_i (core->config, "scr.utf8");
	r_config_set_b (core->config, "scr.utf8", false);
	RPanel *cur = __get_cur_panel (core->panels);
	cur->view->refresh = true;
	firstRun= false;
	__panels_refresh (core);
	firstRun= true;
	r_config_set_b (core->config, "scr.utf8", utf8);
	char *s = r_cons_canvas_to_string (can);
	if (s) {
		// TODO drop utf8!!
		r_str_ansi_filter (s, NULL, NULL, -1);
		int i, h, w = r_cons_get_size (&h);
		for (i = h; i > 0; i--) {
			int H = i;
			char *r = r_str_scale (s, w, H);
			r_cons_clear00 ();
			r_cons_gotoxy (0, (h / 2) - (H / 2)); // center
			//r_cons_gotoxy (0, h-H); // bottom
			r_cons_strcat (r);
			r_cons_flush ();
			free (r);
			r_sys_usleep (3000);
		}
		r_sys_usleep (100000);
		free (s);
	}
}

static void __default_panel_print(RCore *core, RPanel *panel) {
	bool o_cur = core->print->cur_enabled;
	core->print->cur_enabled = o_cur & (__get_cur_panel (core->panels) == panel);
	if (panel->model->readOnly) {
		__update_help_contents (core, panel);
		__update_help_title (core, panel);
	} else if (panel->model->cmd) {
		panel->model->print_cb (core, panel);
		__update_panel_title (core, panel);
	}
	core->print->cur_enabled = o_cur;
}

static void __panel_print(RCore *core, RConsCanvas *can, RPanel *panel, int color) {
	if (!can || !panel|| !panel->view->refresh) {
		return;
	}
	if (can->w <= panel->view->pos.x || can->h <= panel->view->pos.y) {
		return;
	}
	panel->view->refresh = panel->model->type == PANEL_TYPE_MENU;
	r_cons_canvas_fill (can, panel->view->pos.x, panel->view->pos.y, panel->view->pos.w, panel->view->pos.h, ' ');
	if (panel->model->type == PANEL_TYPE_MENU) {
		__menu_panel_print (can, panel, panel->view->sx, panel->view->sy, panel->view->pos.w, panel->view->pos.h);
	} else {
		__default_panel_print (core, panel);
	}
	int w, h;
	w = R_MIN (panel->view->pos.w, can->w - panel->view->pos.x);
	h = R_MIN (panel->view->pos.h, can->h - panel->view->pos.y);
	if (color) {
		r_cons_canvas_box (can, panel->view->pos.x, panel->view->pos.y, w, h, core->cons->context->pal.graph_box2);
	} else {
		r_cons_canvas_box (can, panel->view->pos.x, panel->view->pos.y, w, h, core->cons->context->pal.graph_box);
	}
}

static void __panels_refresh(RCore *core) {
	RPanels *panels = core->panels;
	if (!panels) {
		return;
	}
	RConsCanvas *can = panels->can;
	if (!can) {
		return;
	}
	r_cons_gotoxy (0, 0);
	int i, h, w = r_cons_get_size (&h);
	if (!r_cons_canvas_resize (can, w, h)) {
		return;
	}
	RStrBuf *title = r_strbuf_new (" ");
	bool utf8 = r_config_get_i (core->config, "scr.utf8");
	if (firstRun) {
		r_config_set_b (core->config, "scr.utf8", false);
	}

	__refresh_core_offset (core);
	__set_refresh_all (core, false, false);

	//TODO use getPanel
	for (i = 0; i < panels->n_panels; i++) {
		if (i != panels->curnode) {
			__panel_print (core, can, __get_panel (panels, i), 0);
		}
	}
	if (panels->mode == PANEL_MODE_MENU) {
		__panel_print (core, can, __get_cur_panel (panels), 0);
	} else {
		__panel_print (core, can, __get_cur_panel (panels), 1);
	}
	for (i = 0; i < panels->panels_menu->n_refresh; i++) {
		__panel_print (core, can, panels->panels_menu->refreshPanels[i], 1);
	}
	(void) r_cons_canvas_gotoxy (can, -can->sx, -can->sy);
	r_cons_canvas_fill (can, -can->sx, -can->sy, w, 1, ' ');
	const char *color = core->cons->context->pal.graph_box2;
	if (panels->mode == PANEL_MODE_ZOOM) {
		r_strbuf_appendf (title, "%s Zoom Mode | Press Enter or q to quit"Color_RESET, color);
	} else if (panels->mode == PANEL_MODE_WINDOW) {
		r_strbuf_appendf (title, "%s Window Mode | hjkl: move around the panels | q: quit the mode | Enter: Zoom mode"Color_RESET, color);
	} else {
		RPanelsMenuItem *parent = panels->panels_menu->root;
		for (i = 0; i < parent->n_sub; i++) {
			RPanelsMenuItem *item = parent->sub[i];
			if (panels->mode == PANEL_MODE_MENU && i == parent->selectedIndex) {
				r_strbuf_appendf (title, "%s[%s]"Color_RESET, color, item->name);
			} else {
				r_strbuf_appendf (title, " %s ", item->name);
			}
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
	r_strbuf_setf (title, "[0x%08"PFMT64x "]", core->offset);
	i = -can->sx + w - r_strbuf_length (title);
	(void) r_cons_canvas_gotoxy (can, i, -can->sy);
	r_cons_canvas_write (can, r_strbuf_get (title));

	int tab_pos = i;
	for (i = core->panels_root->n_panels; i > 0; i--) {
		RPanels *panels = core->panels_root->panels[i - 1];
		char *name = NULL;
		if (panels) {
			name = panels->name;
		}
		if (i - 1 == core->panels_root->cur_panels) {
			if (!name) {
				r_strbuf_setf (title, "%s[%d] "Color_RESET, color, i);
			} else {
				r_strbuf_setf (title, "%s[%s] "Color_RESET, color, name);
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
	r_strbuf_set (title, "Tab ");
	tab_pos -= r_strbuf_length (title);
	(void) r_cons_canvas_gotoxy (can, tab_pos, -can->sy);
	r_cons_canvas_write (can, r_strbuf_get (title));
	r_strbuf_free (title);

	if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
		__print_snow (panels);
	}

	if (firstRun) {
		if (core->panels_root->n_panels < 2) {
			if (r_config_get_i (core->config, "scr.demo")) {
				demo_begin (core, can);
			}
		}
		firstRun = false;
		r_config_set_b (core->config, "scr.utf8", utf8);
		RPanel *cur = __get_cur_panel (core->panels);
		cur->view->refresh = true;
		__panels_refresh (core);
		return;
	}
	r_cons_canvas_print (can);
	if (core->scr_gadgets) {
		r_core_cmd0 (core, "pg");
	}
	show_cursor (core);
	r_cons_flush ();
	if (r_cons_singleton ()->fps) {
		r_cons_print_fps (40);
	}
}

static void __panel_breakpoint(RCore *core) {
	RPanel *cur = __get_cur_panel (core->panels);
	if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		r_core_cmd (core, "dbs $$", 0);
		cur->view->refresh = true;
	}
}

static void __panel_continue(RCore *core) {
	r_core_cmd (core, "dc", 0);
}

static void __handle_menu(RCore *core, const int key) {
	RPanels *panels = core->panels;
	RPanelsMenu *menu = panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_cons_switchbuf (false);
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
			__del_menu (core);
		}
		break;
	case 'j':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.y++;
		} else {
			if (menu->depth == 1) {
				(void)(child->cb (core));
			} else {
				parent->selectedIndex = R_MIN (parent->n_sub - 1, parent->selectedIndex + 1);
				__update_menu_contents (core, menu, parent);
			}
		}
		break;
	case 'k':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.y--;
		} else {
			if (menu->depth < 2) {
				break;
			}
			RPanelsMenuItem *parent = menu->history[menu->depth - 1];
			if (parent->selectedIndex > 0) {
				parent->selectedIndex--;
				__update_menu_contents (core, menu, parent);
			}
		}
		break;
	case 'l':
		{
			if (menu->depth == 1) {
				menu->root->selectedIndex++;
				menu->root->selectedIndex %= menu->root->n_sub;
				break;
			}
			if (parent->sub[parent->selectedIndex]->sub) {
				(void)(parent->sub[parent->selectedIndex]->cb (core));
			} else {
				menu->n_refresh = 0;
				menu->root->selectedIndex++;
				menu->root->selectedIndex %= menu->root->n_sub;
				menu->depth = 1;
				(void)(menu->root->sub[menu->root->selectedIndex]->cb (core));
			}
		}
		break;
	case 'm':
	case 'q':
	case 'Q':
	case -1:
		if (panels->panels_menu->depth > 1) {
			__del_menu (core);
		} else {
			menu->n_refresh = 0;
			__set_mode (core, PANEL_MODE_DEFAULT);
			__get_cur_panel (panels)->view->refresh = true;
		}
		break;
	case '$':
		r_core_cmd0 (core, "dr PC=$$");
		break;
	case ' ':
	case '\r':
	case '\n':
		(void)(child->cb (core));
		break;
	case 9:
		menu->n_refresh = 0;
		__handle_tab_key (core, false);
		break;
	case 'Z':
		menu->n_refresh = 0;
		__handle_tab_key (core, true);
		break;
	case ':':
		menu->n_refresh = 0;
		__handlePrompt (core, panels);
		break;
	case '?':
		menu->n_refresh = 0;
		__toggle_help (core);
		break;
	case '"':
		menu->n_refresh = 0;
		__create_modal (core, __get_panel (panels, 0), panels->modal_db);
		__set_mode (core, PANEL_MODE_DEFAULT);
		break;
	}
}

static bool __handle_console(RCore *core, RPanel *panel, const int key) {
	if (!__check_panel_type (panel, PANEL_CMD_CONSOLE)) {
		return false;
	}
	r_cons_switchbuf (false);
	switch (key) {
	case 'i':
		{
			char cmd[128] = {0};
			char *prompt = r_str_newf ("[0x%08"PFMT64x"]) ", core->offset);
			__panel_prompt (prompt, cmd, sizeof (cmd));
			if (*cmd) {
				if (!strcmp (cmd, "clear")) {
					r_core_cmd0 (core, ":>$console");
				} else {
					r_core_cmdf (core, "?e %s %s>>$console", prompt, cmd);
					r_core_cmdf (core, "%s >>$console", cmd);
				}
			}
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

static char *__create_panels_config_path(const char *file) {
	char *dir_path = __get_panels_config_dir_path ();
	r_sys_mkdirp (dir_path);
	char *file_path = r_str_newf (R_JOIN_2_PATHS ("%s", "%s"), dir_path, file);
	R_FREE (dir_path);
	return file_path;
}

static char *__get_panels_config_file_from_dir(const char *file) {
	char *dir_path = __get_panels_config_dir_path ();
	RList *dir = r_sys_dir (dir_path);
	if (!dir_path || !dir) {
		free (dir_path);
		return NULL;
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

R_API void r_core_panels_save(RCore *core, const char *oname) {
	int i;
	if (!core->panels) {
		return;
	}
	const char *name = oname;
	if (R_STR_ISEMPTY (name)) {
		name = __show_status_input (core, "Name for the layout: ");
		if (R_STR_ISEMPTY (name)) {
			(void)__show_status (core, "Name can't be empty!");
			return;
		}
	}
	char *config_path = __create_panels_config_path (name);
	RPanels *panels = core->panels;
	PJ *pj = pj_new ();
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = __get_panel (panels, i);
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
		__update_menu (core, "File.Load Layout.Saved", __init_menu_saved_layout);
		(void)__show_status (core, "Panels layout saved!");
	}
	free (config_path);
}

static char *__parse_panels_config(const char *cfg, int len) {
	if (R_STR_ISEMPTY (cfg) || len < 2) {
		return NULL;
	}
	char *tmp = r_str_newlen (cfg, len + 1);
	int i = 0;
	for (; i < len; i++) {
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

R_API bool r_core_panels_load(RCore *core, const char *_name) {
	if (!core->panels) {
		return false;
	}
	char *config_path = __get_panels_config_file_from_dir (_name);
	if (!config_path) {
		char *tmp = r_str_newf ("No saved layout found for the name: %s", _name);
		(void)__show_status (core, tmp);
		free (tmp);
		return false;
	}
	char *panels_config = r_file_slurp (config_path, NULL);
	free (config_path);
	if (!panels_config) {
		char *tmp = r_str_newf ("Layout is empty: %s", _name);
		(void)__show_status (core, tmp);
		free (tmp);
		return false;
	}
	RPanels *panels = core->panels;
	__panel_all_clear (panels);
	panels->n_panels = 0;
	__set_curnode (core, 0);
	char *title, *cmd, *x, *y, *w, *h, *p_cfg = panels_config, *tmp_cfg;
	int i, tmp_count;
	tmp_cfg = __parse_panels_config (p_cfg, strlen (p_cfg));
	tmp_count = r_str_split (tmp_cfg, '\n');
	for (i = 0; i < tmp_count; i++) {
		if (R_STR_ISEMPTY (tmp_cfg)) {
			break;
		}
		title = sdb_json_get_str (tmp_cfg, "Title");
		cmd = sdb_json_get_str (tmp_cfg, "Cmd");
		(void)r_str_arg_unescape (cmd);
		x = sdb_json_get_str (tmp_cfg, "x");
		y = sdb_json_get_str (tmp_cfg, "y");
		w = sdb_json_get_str (tmp_cfg, "w");
		h = sdb_json_get_str (tmp_cfg, "h");
		RPanel *p = __get_panel (panels, panels->n_panels);
		__set_geometry (&p->view->pos, atoi (x), atoi (y), atoi (w),atoi (h));
		__init_panel_param (core, p, title, cmd);
		// TODO: fix code duplication with __update_help
		if (r_str_endswith (cmd, "Help")) {
			p->model->title = r_str_dup (p->model->title, "Help");
			p->model->cmd = r_str_dup (p->model->cmd, "Help");
			RStrBuf *rsb = r_strbuf_new (NULL);
			r_core_visual_append_help (rsb, "Panels Mode", help_msg_panels);
			if (!rsb) {
				return false;
			}
			__set_read_only (core, p, r_strbuf_drain (rsb));
		}
		tmp_cfg += strlen (tmp_cfg) + 1;
	}
	free (panels_config);
	if (!panels->n_panels) {
		free (tmp_cfg);
		return false;
	}
	__set_refresh_all (core, true, false);
	return true;
}

static void __rotate_panels(RCore *core, bool rev) {
	RPanels *panels = core->panels;
	RPanel *first = __get_panel (panels, 0);
	RPanel *last = __get_panel (panels, panels->n_panels - 1);
	int i;
	RPanelModel *tmp_model;
	if (!rev) {
		tmp_model = first->model;
		for (i = 0; i < panels->n_panels - 1; i++) {
			RPanel *p0 = __get_panel (panels, i);
			RPanel *p1 = __get_panel (panels, i + 1);
			p0->model = p1->model;
		}
		last->model = tmp_model;
	} else {
		tmp_model = last->model;
		for (i = panels->n_panels - 1; i > 0; i--) {
			RPanel *p0 = __get_panel (panels, i);
			RPanel *p1 = __get_panel (panels, i - 1);
			p0->model = p1->model;
		}
		first->model = tmp_model;
	}
	__set_refresh_all (core, false, true);
}

static void __undo_seek(RCore *core) {
	RPanel *cur = __get_cur_panel (core->panels);
	if (!__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		return;
	}
	RIOUndos *undo = r_io_sundo (core->io, core->offset);
	if (undo) {
		r_core_visual_seek_animation (core, undo->off);
		__set_panel_addr (core, cur, core->offset);
	}
}

static void __set_filter(RCore *core, RPanel *panel) {
	if (!panel->model->filter) {
		return;
	}
	char *input = __show_status_input (core, "filter word: ");
	if (input) {
		panel->model->filter[panel->model->n_filter++] = input;
		__set_cmd_str_cache (core, panel, NULL);
		panel->view->refresh = true;
	}
	__reset_scroll_pos (panel);
}

static void __redo_seek(RCore *core) {
	RPanel *cur = __get_cur_panel (core->panels);
	if (!__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		return;
	}
	RIOUndos *undo = r_io_sundo_redo (core->io);
	if (undo) {
		r_core_visual_seek_animation (core, undo->off);
		__set_panel_addr (core, cur, core->offset);
	}
}

static void __handle_tab(RCore *core) {
	r_cons_gotoxy (0, 0);
	if (core->panels_root->n_panels <= 1) {
		r_cons_printf (R_CONS_CLEAR_LINE"%s[Tab] t:new T:new with current panel -:del =:name"Color_RESET, core->cons->context->pal.graph_box2);
	} else {
		const int min = 1;
		const int max = core->panels_root->n_panels;
		r_cons_printf (R_CONS_CLEAR_LINE"%s[Tab] [%d..%d]:select; p:prev; n:next; t:new T:new with current panel -:del =:name"Color_RESET,
			core->cons->context->pal.graph_box2, min, max);
	}
	r_cons_flush ();
	int ch = r_cons_readchar ();

	if (isdigit (ch)) {
		__handle_tab_nth (core, ch);
		return;
	}

	switch (ch) {
	case 'n':
		__handle_tab_next (core);
		return;
	case 'p':
		__handle_tab_prev (core);
		return;
	case '-':
		__set_root_state (core, DEL);
		return;
	case '=':
		__handle_tab_name (core);
		return;
	case 't':
		__handle_tab_new (core);
		return;
	case 'T':
		__handle_tab_new_with_cur_panel (core);
		return;
	}
}

// copypasta from visual
static void prevOpcode(RCore *core) {
	RPrint *p = core->print;
	ut64 addr, oaddr = core->offset + core->print->cur;
	if (r_core_prevop_addr (core, oaddr, 1, &addr)) {
		const int delta = oaddr - addr;
		p->cur -= delta;
	} else {
		p->cur -= 4;
	}
}

static void nextOpcode(RCore *core) {
	RAnalOp *aop = r_core_anal_op (core, core->offset + core->print->cur, R_ANAL_OP_MASK_BASIC);
	RPrint *p = core->print;
	if (aop) {
		p->cur += aop->size;
		r_anal_op_free (aop);
	} else {
		p->cur += 4;
	}
}

static void __panels_process(RCore *core, RPanels *panels) {
	if (!panels) {
		return;
	}
	int i, okey, key;
	RPanelsRoot *panels_root = core->panels_root;
	RPanels *prev;
	prev = core->panels;
	core->panels = panels;
	panels->autoUpdate = true;
	int h, w = r_cons_get_size (&h);
	panels->can = __create_new_canvas (core, w, h);
	__set_refresh_all (core, false, true);

	r_cons_switchbuf (false);

	int originCursor = core->print->cur;
	core->print->cur = 0;
	core->print->cur_enabled = false;
	core->print->col = 0;

	bool originVmode = core->vmode;
	core->vmode = true;
	{
		const char *layout = r_config_get (core->config, "scr.layout");
		if (R_STR_ISNOTEMPTY (layout)) {
			r_core_panels_load (core, layout);
		}
	}

	bool o_interactive = r_cons_is_interactive ();
	r_cons_set_interactive (true);
	r_core_visual_showcursor (core, false);

	r_cons_enable_mouse (false);
repeat:
	r_cons_enable_mouse (r_config_get_i (core->config, "scr.wheel"));
	core->panels = panels;
	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = core;
	core->cons->event_resize = (RConsEvent) __do_panels_refreshOneShot;
	__panels_layout_refresh (core);
	RPanel *cur = __get_cur_panel (panels);
	if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
		if (panels->mode == PANEL_MODE_MENU) {
			panels->fun = PANEL_FUN_NOFUN;
			__reset_snow (panels);
			goto repeat;
		}
		okey = r_cons_readchar_timeout (300);
		if (okey == -1) {
			cur->view->refresh = true;
			goto repeat;
		}
	} else {
		okey = r_cons_readchar ();
	}

	key = r_cons_arrow_to_hjkl (okey);
virtualmouse:
	if (__handle_mouse (core, cur, &key)) {
		if (panels_root->root_state != DEFAULT) {
			goto exit;
		}
		goto repeat;
	}

	r_cons_switchbuf (true);

	if (panels->mode == PANEL_MODE_MENU) {
		__handle_menu (core, key);
		if (__check_root_state (core, QUIT) ||
				__check_root_state (core, ROTATE)) {
			goto exit;
		}
		goto repeat;
	}

	if (core->print->cur_enabled) {
		if (__handle_cursor_mode (core, key)) {
			goto repeat;
		}
	}

	if (panels->mode == PANEL_MODE_ZOOM) {
		if (__handle_zoom_mode (core, key)) {
			goto repeat;
		}
	}

	if (panels->mode == PANEL_MODE_WINDOW) {
		if (__handle_window_mode (core, key)) {
			goto repeat;
		}
	}

	if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY) && '0' < key && key <= '9') {
		ut8 ch = key;
		r_core_visual_jump (core, ch);
		__set_panel_addr (core, cur, core->offset);
		goto repeat;
	}

	const char *cmd;
	RConsCanvas *can = panels->can;
	if (__handle_console (core, cur, key)) {
		goto repeat;
	}
	switch (key) {
	case 'u':
		__undo_seek (core);
		break;
	case 'U':
		__redo_seek (core);
		break;
	case 'p':
		__rotate_panels (core, false);
		break;
	case 'P':
		__rotate_panels (core, true);
		break;
	case '.':
		if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
			ut64 addr = r_debug_reg_get (core->dbg, "PC");
			if (addr && addr != UT64_MAX) {
				r_core_seek (core, addr, true);
			} else {
				addr = r_num_get (core->num, "entry0");
				if (addr && addr != UT64_MAX) {
					r_core_seek (core, addr, true);
				}
			}
			__set_panel_addr (core, cur, core->offset);
		}
		break;
	case '?':
		__toggle_help (core);
		break;
	case 'b':
		r_core_visual_browse (core, NULL);
		break;
	case ';':
		__handleComment (core);
		break;
	case '$':
		if (core->print->cur_enabled) {
			r_core_cmdf (core, "dr PC=$$+%d", core->print->cur);
		} else {
			r_core_cmd0 (core, "dr PC=$$");
		}
		break;
	case 's':
		__panel_single_step_in (core);
		if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
			__set_panel_addr (core, cur, core->offset);
		}
		break;
	case 'S':
		__panel_single_step_over (core);
		if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
			__set_panel_addr (core, cur, core->offset);
		}
		break;
	case ' ':
		if (r_config_get_i (core->config, "graph.web")) {
			r_core_cmd0 (core, "agv $$");
		} else {
			__call_visual_graph (core);
		}
		break;
	case ':':
		r_core_visual_prompt_input (core);
		__set_panel_addr (core, cur, core->offset);
		break;
	case 'c':
		__activate_cursor (core);
		break;
	case 'C':
		{
			int color = r_config_get_i (core->config, "scr.color");
			if (++color > 2) {
				color = 0;
			}
			r_config_set_i (core->config, "scr.color", color);
			can->color = color;
			__set_refresh_all (core, true, false);
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
		if (r_config_get_i (core->config, "scr.randpal")) {
			r_core_cmd0 (core, "ecr");
		} else {
			r_core_cmd0 (core, "ecn");
		}
		__do_panels_refresh (core);
		break;
	case 'a':
		panels->autoUpdate = __show_status_yesno (core, 1, "Auto update On? (Y/n)");
		break;
	case 'A':
		{
			const int ocur = core->print->cur_enabled;
			r_core_visual_asm (core, core->offset);
			core->print->cur_enabled = ocur;
		}
		break;
	case 'd':
		r_core_visual_define (core, "", 0);
		break;
	case 'D':
		__replace_cmd (core, PANEL_TITLE_DISASSEMBLY, PANEL_CMD_DISASSEMBLY);
		break;
	case 'j':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.y++;
		} else {
			if (core->print->cur_enabled) {
				nextOpcode (core);
			} else {
				r_cons_switchbuf (false);
				if (cur->model->directionCb) {
					cur->model->directionCb (core, (int)DOWN);
				}
			}
		}
		break;
	case 'k':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.y--;
		} else {
			if (core->print->cur_enabled) {
				prevOpcode (core);
			} else {
				r_cons_switchbuf (false);
				if (cur->model->directionCb) {
					cur->model->directionCb (core, (int)UP);
				}
			}
		}
		break;
	case 'K':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.y -= 5;
		} else {
			if (core->print->cur_enabled) {
				size_t i;
				for (i = 0; i < 4; i++) {
					prevOpcode (core);
				}
			} else {
				r_cons_switchbuf (false);
				if (cur->model->directionCb) {
					for (i = 0; i < __get_cur_panel (panels)->view->pos.h / 2 - 6; i++) {
						cur->model->directionCb (core, (int)UP);
					}
				}
			}
		}
		break;
	case 'J':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.y += 5;
		} else {
			if (core->print->cur_enabled) {
				size_t i;
				for (i = 0; i < 4; i++) {
					nextOpcode (core);
				}
			} else {
				r_cons_switchbuf (false);
				if (cur->model->directionCb) {
					for (i = 0; i < __get_cur_panel (panels)->view->pos.h / 2 - 6; i++) {
						cur->model->directionCb (core, (int)DOWN);
					}
				}
			}
		}
		break;
	case 'H':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.x -= 5;
		} else {
			r_cons_switchbuf (false);
			if (cur->model->directionCb) {
				for (i = 0; i < __get_cur_panel (panels)->view->pos.w / 3; i++) {
					cur->model->directionCb (core, (int)LEFT);
				}
			}
		}
		break;
	case 'L':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.x += 5;
		} else {
			r_cons_switchbuf (false);
			if (cur->model->directionCb) {
				for (i = 0; i < __get_cur_panel (panels)->view->pos.w / 3; i++) {
					cur->model->directionCb (core, (int)RIGHT);
				}
			}
		}
		break;
	case 'f':
		__set_filter (core, cur);
		break;
	case 'F':
		__reset_filter (core, cur);
		break;
	case '_':
		__hudstuff (core);
		break;
	case '\\':
		r_core_visual_hud (core);
		break;
	case '"':
		r_cons_switchbuf (false);
		__create_modal (core, cur, panels->modal_db);
		if (__check_root_state (core, ROTATE)) {
			goto exit;
		}
		// all panels containing decompiler data should be cached
		cur->model->cache = strstr (cur->model->title, "Decomp") != NULL;
		break;
	case 'O':
		__handle_print_rotate (core);
		break;
	case 'n':
		if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
			r_core_seek_next (core, r_config_get (core->config, "scr.nkey"));
			__set_panel_addr (core, cur, core->offset);
		}
		break;
	case 'N':
		if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
			r_core_seek_previous (core, r_config_get (core->config, "scr.nkey"));
			__set_panel_addr (core, cur, core->offset);
		}
		break;
	case 'x':
		__handle_refs (core, cur, UT64_MAX);
		break;
	case 'X':
#if 0
// already accessible via xX
		r_core_visual_refs (core, false, true);
		cur->model->addr = core->offset;
		set_refresh_all (panels, false);
#endif
		__dismantle_del_panel (core, cur, panels->curnode);
		break;
	case 9: // TAB
		__handle_tab_key (core, false);
		break;
	case 'Z': // SHIFT-TAB
		__handle_tab_key (core, true);
		break;
	case 'M':
		__handle_visual_mark (core);
		break;
	case 'e':
	{
		char *cmd = __show_status_input (core, "New command: ");
		if (R_STR_ISNOTEMPTY (cmd)) {
			__replace_cmd (core, cmd, cmd);
		}
		free (cmd);
	}
		break;
	case 'm':
		__set_mode (core, PANEL_MODE_MENU);
		__clear_panels_menu (core);
		__get_cur_panel (panels)->view->refresh = true;
		break;
	case 'g':
		r_core_visual_showcursor (core, true);
		r_core_visual_offset (core);
		r_core_visual_showcursor (core, false);
		__set_panel_addr (core, cur, core->offset);
		break;
	case 'G':
		{
			const char *hl = r_config_get (core->config, "scr.highlight");
			if (hl) {
				ut64 addr = r_num_math (core->num, hl);
				__set_panel_addr (core, cur, addr);
				// r_io_sundo_push (core->io, addr, false); // doesnt seems to work
			}
		}
		break;
	case 'h':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.x--;
		} else {
			if (core->print->cur_enabled) {
				core->print->cur--;
			} else {
				r_cons_switchbuf (false);
				if (cur->model->directionCb) {
					cur->model->directionCb (core, (int)LEFT);
				}
			}
		}
		break;
	case 'l':
		if (r_config_get_i (core->config, "scr.cursor")) {
			core->cons->cpos.x++;
		} else {
			if (core->print->cur_enabled) {
				core->print->cur++;
			} else {
				r_cons_switchbuf (false);
				if (cur->model->directionCb) {
					cur->model->directionCb (core, (int)RIGHT);
				}
			}
		}
		break;
	case 'V':
		if (r_config_get_i (core->config, "graph.web")) {
			r_core_cmd0 (core, "agv $$");
		} else {
			__call_visual_graph (core);
		}
		break;
	case ']':
		if (__check_panel_type (cur, PANEL_CMD_HEXDUMP)) {
			r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") + 1);
		} else {
			int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
			r_config_set_i (core->config, "asm.cmt.col", cmtcol + 2);
		}
		cur->view->refresh = true;
		break;
	case '[':
		if (__check_panel_type (cur, PANEL_CMD_HEXDUMP)) {
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
			__swap_panels (panels, 0, panels->curnode);
			__set_curnode (core, 0);
		}
		break;
	case 'i':
		if (cur->model->rotateCb) {
			cur->model->rotateCb (core, false);
			cur->view->refresh = true;
		}
		break;
	case 'I':
		if (cur->model->rotateCb) {
			cur->model->rotateCb (core, true);
			cur->view->refresh = true;
		}
		break;
	case 't':
		__handle_tab (core);
		if (panels_root->root_state != DEFAULT) {
			goto exit;
		}
		break;
	case 'T':
		if (panels_root->n_panels > 1) {
			__set_root_state (core, DEL);
			goto exit;
		}
		break;
	case 'w':
		__toggle_window_mode (core);
		break;
	case 'W':
		__move_panel_to_dir (core, cur, panels->curnode);
		break;
	case 0x0d: // "\\n"
		if (r_config_get_i (core->config, "scr.cursor")) {
			key = 0;
			r_cons_set_click (core->cons->cpos.x, core->cons->cpos.y);
			goto virtualmouse;
		} else {
			__toggle_zoom_mode (core);
		}
		break;
	case '|':
		{
			RPanel *p = __get_cur_panel (panels);
			__split_panel_vertical (core, p, p->model->title, p->model->cmd);
			break;
		}
	case '-':
		{
			RPanel *p = __get_cur_panel (panels);
			__split_panel_horizontal (core, p, p->model->title, p->model->cmd);
			break;
		}
	case '*':
		if (__check_func (core)) {
			r_cons_canvas_free (can);
			panels->can = NULL;

			__replace_cmd (core, PANEL_TITLE_DECOMPILER, PANEL_CMD_DECOMPILER);

			int h, w = r_cons_get_size (&h);
			panels->can = __create_new_canvas (core, w, h);
		}
		break;
	case '(':
		if (panels->fun != PANEL_FUN_SNOW && panels->fun != PANEL_FUN_SAKURA) {
			//TODO: Refactoring the FUN if bored af
			//panels->fun = PANEL_FUN_SNOW;
			panels->fun = PANEL_FUN_SAKURA;
		} else {
			panels->fun = PANEL_FUN_NOFUN;
			__reset_snow (panels);
		}
		break;
	case ')':
		__rotate_asmemu (core, __get_cur_panel (panels));
		break;
	case '&':
		__toggle_cache (core, __get_cur_panel (panels));
		break;
	case R_CONS_KEY_F1:
		cmd = r_config_get (core->config, "key.f1");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F2:
		cmd = r_config_get (core->config, "key.f2");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			__panel_breakpoint (core);
		}
		break;
	case R_CONS_KEY_F3:
		cmd = r_config_get (core->config, "key.f3");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F4:
		cmd = r_config_get (core->config, "key.f4");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F5:
		cmd = r_config_get (core->config, "key.f5");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F6:
		cmd = r_config_get (core->config, "key.f6");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F7:
		cmd = r_config_get (core->config, "key.f7");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			__panel_single_step_in (core);
			if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
				__set_panel_addr (core, cur, core->offset);
			}
		}
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			__panel_single_step_over (core);
			if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
				__set_panel_addr (core, cur, core->offset);
			}
		}
		break;
	case R_CONS_KEY_F9:
		cmd = r_config_get (core->config, "key.f9");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
				__panel_continue (core);
				__set_panel_addr (core, cur, core->offset);
			}
		}
		break;
	case R_CONS_KEY_F10:
		cmd = r_config_get (core->config, "key.f10");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F11:
		cmd = r_config_get (core->config, "key.f11");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F12:
		cmd = r_config_get (core->config, "key.f12");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case 'Q':
		__set_root_state (core, QUIT);
		goto exit;
	case '!':
		fromVisual = true;
	case 'q':
	case -1: // EOF
		__set_root_state (core, DEL);
		if (core->panels_root->n_panels < 2) {
			if (r_config_get_i (core->config, "scr.demo")) {
				demo_end (core, can);
			}
		}
		goto exit;
#if 0
	case 27: // ESC
		if (r_cons_readchar () == 91) {
			if (r_cons_readchar () == 90) {}
		}
		break;
#endif
	default:
		// eprintf ("Key %d\n", key);
		// sleep (1);
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
	r_cons_set_interactive (o_interactive);
}

static void __del_panels(RCore *core) {
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

R_API bool r_core_panels_root(RCore *core, RPanelsRoot *panels_root) {
	fromVisual = core->vmode;
	if (!panels_root) {
		panels_root = R_NEW0 (RPanelsRoot);
		if (!panels_root) {
			return false;
		}
		core->panels_root = panels_root;
		panels_root->panels = calloc (sizeof (RPanels *), PANEL_NUM_LIMIT);
		panels_root->n_panels = 0;
		panels_root->cur_panels = 0;
		panels_root->pdc_caches = sdb_new0 ();
		panels_root->cur_pdc_cache = NULL;
		__set_root_state (core, DEFAULT);
		__init_new_panels_root (core);
	} else {
		if (!panels_root->n_panels) {
			panels_root->n_panels = 0;
			panels_root->cur_panels = 0;
			__init_new_panels_root (core);
		}
		const char *pdc_now = r_config_get (core->config, "cmd.pdc");
		if (sdb_exists (panels_root->pdc_caches, pdc_now)) {
			panels_root->cur_pdc_cache = sdb_ptr_get (panels_root->pdc_caches, r_str_new (pdc_now), 0);
		} else {
			Sdb *sdb = sdb_new0();
			sdb_ptr_set (panels_root->pdc_caches, r_str_new (pdc_now), sdb, 0);
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
			RPanel *cur = __get_panel (panels, i);
			if (cur) {
				cur->model->addr = core->offset;
			}
		}
	}
	while (panels_root->n_panels) {
		__set_root_state (core, DEFAULT);
		__panels_process (core, panels_root->panels[panels_root->cur_panels]);
		if (__check_root_state (core, DEL)) {
			__del_panels (core);
		}
		if (__check_root_state (core, QUIT)) {
			break;
		}
	}
	if (fromVisual) {
		r_core_cmdf (core, "V");
	} else {
		r_cons_enable_mouse (false);
	}
	return true;
}

static void __init_new_panels_root(RCore *core) {
	RPanelsRoot *panels_root = core->panels_root;
	RPanels *panels = __panels_new (core);
	if (!panels) {
		return;
	}
	RPanels *prev = core->panels;
	core->panels = panels;
	panels_root->panels[panels_root->n_panels++] = panels;
	if (!__init_panels_menu (core)) {
		core->panels = prev;
		return;
	}
	if (!__init_panels (core, panels)) {
		core->panels = prev;
		return;
	}
	__init_all_dbs (core);
	__set_mode (core, PANEL_MODE_DEFAULT);
	__create_default_panels (core);
	__panels_layout (panels);
	core->panels = prev;
}

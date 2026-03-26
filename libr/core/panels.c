/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

#include <r_core.h>

// few remaining static functions
static bool __init_panels_menu(RCore *core);
static void __init_menu_screen_settings_layout(void *_core, const char *parent);
static void __init_new_panels_root(RCore *core);
static void __init_menu_color_settings_layout(void *core, const char *parent);
static void __init_menu_disasm_asm_settings_layout(void *_core, const char *parent);
static void __set_dcb(RCore *core, RPanel *p);
static void __set_pcb(RPanel *p);
R_IPI void applyDisMode(RCore *core);
R_IPI void applyHexMode(RCore *core);

#define MENU_Y 1
#define PANEL_NUM_LIMIT 16
#define PANEL_HL_COLOR core->cons->context->pal.graph_box2

#define PANEL_TITLE_DISASSEMBLY      "Disassembly"
#define PANEL_TITLE_DISASMSUMMARY    "Disassemble Summary"
#define PANEL_TITLE_ALL_DECOMPILER   "Show All Decompiler Output"
#define PANEL_TITLE_DECOMPILER       "Decompiler"
#define PANEL_TITLE_DECOMPILER_O     "Decompiler With Offsets"
#define PANEL_TITLE_GRAPH            "Graph"
#define PANEL_TITLE_TINY_GRAPH       "Tiny Graph"
#define PANEL_TITLE_BREAKPOINTS      "Breakpoints"
#define PANEL_TITLE_STRINGS_DATA     "Strings in data sections"
#define PANEL_TITLE_STRINGS_BIN      "Strings in the whole bin"
#define PANEL_TITLE_SECTIONS         "Sections"
#define PANEL_TITLE_SEGMENTS         "Segments"
#define PANEL_TITLE_COMMENTS         "Comments"

#define PANEL_CMD_SYMBOLS            "isq"
#define PANEL_CMD_STACK              "px"
#define PANEL_CMD_REGISTERS          "dr"
#define PANEL_CMD_FPU_REGISTERS      "dr fpu;drf"
#define PANEL_CMD_XMM_REGISTERS      "drm"
#define PANEL_CMD_YMM_REGISTERS      "drmy"
#define PANEL_CMD_DISASSEMBLY        "pd"
#define PANEL_CMD_DISASMSUMMARY      "pdsf"
#define PANEL_CMD_DECOMPILER         "pdc"
#define PANEL_CMD_DECOMPILER_O       "pdco"
#define PANEL_CMD_FUNCTION           "afl"
#define PANEL_CMD_GRAPH              "agf"
#define PANEL_CMD_TINYGRAPH          "agft"
#define PANEL_CMD_HEXDUMP            "xc"
#define PANEL_CMD_CONSOLE            "cat $console"

#define PANEL_CONFIG_SIDEPANEL_W 60
#define PANEL_CONFIG_MIN_SIZE    2
#define PANEL_CONFIG_RESIZE_W    4
#define PANEL_CONFIG_RESIZE_H    4

#define COUNT(x) (sizeof ((x)) / sizeof ((*x)) - 1)
#define PP(pos, off) (*(int *)((char *)&(pos) + (off)))

// Direction values use vi keys: h=left, j=down, k=up, l=right
typedef int Direction;

typedef struct {
	const char *name;
	RPanelsMenuCallback cb;
} MenuItem;

static const char *panels_dynamic[] = {
	"Disassembly", "Stack", "Registers",
	NULL
};

static const char *panels_static[] = {
	"Disassembly", "Functions", "Symbols",
	NULL
};

static const char *menus[] = {
	"File", "Settings", "Edit", "View", "Tools", "Search", "Emulate", "Debug", "Analyze", "Help",
	NULL
};

static const char *menus_File[] = {
	"New", "Open File", "ReOpen", "Close File", "--", "Open Project", "Save Project", "Close Project", "--", "Quit",
	NULL
};

static const char *menus_Settings[] = {
	"Edit radare2rc", "--", "Color Themes...", "Decompiler...", "Disassembly...", "Screen...", "--",
	"Save Layout", "Load Layout", "Clear Saved Layouts",
	NULL
};

static const char *menus_ReOpen[] = {
	"In Read+Write", "In Debugger",
	NULL
};

static const char *menus_loadLayout[] = {
	"Saved..", "Default",
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
	"Console", "Hexdump", "Disassembly", "Disassemble Summary", "Decompiler", "Decompiler With Offsets",
	"Graph", "Tiny Graph",
	"Functions", "Function Calls", "Sections", "Segments", PANEL_TITLE_STRINGS_DATA, PANEL_TITLE_STRINGS_BIN,
	"Symbols", "Imports",
	"Info", "Database",  "Breakpoints", "Comments", "Classes", "Entropy", "Entropy Fire", "Xrefs Here", "Methods",
	"Var READ address", "Var WRITE address", "Summary", "Relocs", "Headers", "File Hashes", PANEL_TITLE_ALL_DECOMPILER,
	NULL
};

static const char *menus_Tools[] = {
	"Calculator", "Assembler", "R2 Shell", "System Shell",
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
	"Registers", "Bit Registers", "FPU Registers", "XMM Registers", "YMM Registers", "RegisterRefs", "RegisterCols",
	"DRX", "Breakpoints", "Watchpoints",
	"Maps", "Modules", "Backtrace", "Locals", "Continue",
	"Stack", "Step", "Step Over", "Reload",
	NULL
};

static const char *menus_Analyze[] = {
	"Function", "Symbols", "Program", "BasicBlocks", "Calls", "Preludes", "References",
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
	"Manpages...",
	"--",
	"License", "Version", "Full Version",
	"--",
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
	// "pdc", "pdco", "agf", "Help",
	"agf", "Help",
	NULL
};

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


#define R_INCLUDE_BEGIN 1
#include "panels.inc.c"


static void __handlePrompt(RCore *core, RPanels *panels) {
	r_panels_bottom_panel_line (core);
	r_core_visual_prompt_input (core);
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p && r_panels_check_panel_type (p, PANEL_CMD_DISASSEMBLY)) {
			r_panels_set_panel_addr (core, p, core->addr);
			break;
		}
	}
}

static int __add_cmd_panel(void *user) {
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

static int __add_cmdf_panel(RCore *core, char *input, char *str) {
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

static void __init_sdb(RCore *core) {
	Sdb *db = core->panels->db;
	sdb_set (db, "Symbols", "isq", 0);
	sdb_set (db, "Stack", "pxr@r:SP", 0);
	sdb_set (db, "Locals", "afvd", 0);
	sdb_set (db, "Registers", "dr", 0);
	sdb_set (db, "Bit Registers", "dr 1", 0);
	sdb_set (db, "FPU Registers", PANEL_CMD_FPU_REGISTERS, 0);
	sdb_set (db, "XMM Registers", PANEL_CMD_XMM_REGISTERS, 0);
	sdb_set (db, "YMM Registers", PANEL_CMD_YMM_REGISTERS, 0);
	sdb_set (db, "RegisterRefs", "drr", 0);
	sdb_set (db, "RegisterCols", "dr=", 0);
	sdb_set (db, "Disassembly", "pd", 0);
	sdb_set (db, "Disassemble Summary", "pdsf", 0);
	sdb_set (db, "Decompiler", "pdc", 0);
	sdb_set (db, "Decompiler With Offsets", "pdco", 0);
	sdb_set (db, "Graph", "agf", 0);
	sdb_set (db, "Tiny Graph", "agft", 0);
	sdb_set (db, "Info", "i", 0);
	sdb_set (db, "Database", "k ***", 0);
	sdb_set (db, "Console", "cat $console", 0);
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

static void __replace_cmd(RCore *core, const char *title, const char *cmd) {
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
	__set_dcb (core, cur);
	__set_pcb (cur);
	r_panels_set_rcb (panels, cur);
	r_panels_cache_white_list (core, cur);
	r_panels_set_refresh_all (core, false, true);
}

static void __create_panel(RCore *core, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title, const char *cmd) {
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
		__replace_cmd (core, title, cmd);
		break;
	}
}

static void __create_panel_db(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title) {
	RCore *core = (RCore *)user;
	char *cmd = sdb_get (core->panels->db, title, 0);
	if (!cmd) {
		return;
	}
	__create_panel (core, panel, dir, title, cmd);
	RPanel *p = r_panels_get_cur_panel (core->panels);
	r_panels_cache_white_list (core, p);
}

static void __create_panel_input(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title) {
	RCore *core = (RCore *)user;
	char *cmd = r_panels_show_status_input (core, "Command: ");
	if (cmd) {
		__create_panel (core, panel, dir, cmd, cmd);
	}
}

static void __replace_current_panel_input(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title) {
	RCore *core = (RCore *)user;
	char *cmd = r_panels_show_status_input (core, "New command: ");
	if (R_STR_ISNOTEMPTY (cmd)) {
		__replace_cmd (core, cmd, cmd);
	}
	free (cmd);
}

static char *__search_strings(RCore *core, bool whole) {
	const char *title = whole ? PANEL_TITLE_STRINGS_BIN : PANEL_TITLE_STRINGS_DATA;
	const char *str = r_panels_show_status_input (core, "Search Strings: ");
	char *db_val = r_panels_search_db (core, title);
	char *ret = r_str_newf ("%s~%s", db_val, str);
	free (db_val);
	return ret;
}

static void __search_strings_data_create(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title) {
	RCore *core = (RCore *)user;
	char *str = __search_strings (core, false);
	__create_panel (core, panel, dir, title, str);
	free (str);
}

static void __search_strings_bin_create(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title) {
	RCore *core = (RCore *)user;
	char *str = __search_strings (core, true);
	__create_panel (core, panel, dir, title, str);
	free (str);
}

static void __update_disassembly_or_open(RCore *core) {
	RPanels *panels = core->panels;
	int i;
	bool create_new = true;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (r_panels_check_panel_type (p, PANEL_CMD_DISASSEMBLY)) {
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

		r_panels_insert_panel (core, 0, PANEL_TITLE_DISASSEMBLY, PANEL_CMD_DISASSEMBLY);
		RPanel *p0 = r_panels_get_panel (panels, 0);
		r_panels_set_geometry (&p0->view->pos, x0, y0, w0 / 2, h0);

		RPanel *p1 = r_panels_get_panel (panels, 1);
		r_panels_set_geometry (&p1->view->pos, x1, y0, w1, h0);

		r_panels_set_cursor (core, false);
		r_panels_set_curnode (core, 0);
	}
}

static int __help_manpage_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_core_cmdf (core, "man %s", child->name);
	return 0;
}

static int __continue_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "dc", 0);
	r_cons_flush (core->cons);
	return 0;
}

static void __continue_modal_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED const char * R_NULLABLE title) {
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

static void __step_modal_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED const char * R_NULLABLE title) {
	__step_cb (user);
}

static int __break_points_cb(void *user) {
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

static void __put_breakpoints_cb(void *user, RPanel * R_UNUSED panel, R_UNUSED const RPanelLayout dir, R_UNUSED const char * R_NULLABLE title) {
	__break_points_cb (user);
}

static void __step_over_modal_cb(void *user, RPanel * R_UNUSED panel, R_UNUSED const RPanelLayout dir, R_UNUSED const char * R_NULLABLE title) {
	__step_over_cb (user);
}

static int __show_all_decompiler_cb(void *user) {
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

static void __delegate_show_all_decompiler_cb(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title) {
	(void)__show_all_decompiler_cb ((RCore *)user);
}

static void __init_modal_db(RCore *core) {
	Sdb *db = core->panels->modal_db;
	SdbKv *kv;
	SdbListIter *sdb_iter;
	SdbList *sdb_list = sdb_foreach_list (core->panels->db, true);
	ls_foreach (sdb_list, sdb_iter, kv) {
		const char *key = sdbkv_key (kv);
		sdb_ptr_set (db, strdup (key), &__create_panel_db, 0);
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

static void __rotate_panel_cmds(RCore *core, const char **cmds, const int cmdslen, const char *prefix, bool rev) {
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

static void __rotate_entropy_v_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	__rotate_panel_cmds (core, entropy_rotate, COUNT (entropy_rotate), "p=", rev);
}

static void __rotate_entropy_h_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	__rotate_panel_cmds (core, entropy_rotate, COUNT (entropy_rotate), "p==", rev);
}

static void __rotate_asmemu(RCore *core, RPanel *p) {
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

static void __rotate_hexdump_cb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	RPanel *p = r_panels_get_cur_panel (core->panels);

	if (rev) {
		p->model->rotate--;
	} else {
		p->model->rotate++;
	}
	core->visual.hexMode = p->model->rotate;
	applyHexMode (core);
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
	RPanel *p = r_panels_get_cur_panel (core->panels);

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
	core->visual.disMode = p->model->rotate;
	applyDisMode (core);
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

static void __handle_tab_new_with_cur_panel(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->n_panels <= 1) {
		return;
	}

	RPanelsRoot *root = core->panels_root;
	if (root->n_panels + 1 >= PANEL_NUM_LIMIT) {
		return;
	}

	RPanel *cur = r_panels_get_cur_panel (panels);

	RPanels *new_panels = r_panels_panels_new (core);
	if (!new_panels) {
		return;
	}
	root->panels[root->n_panels] = new_panels;

	RPanels *prev = core->panels;
	core->panels = new_panels;

	if (!__init_panels_menu (core) || !r_panels_init_panels (core, new_panels)) {
		core->panels = prev;
		return;
	}
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	__init_all_dbs (core);

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

static void __handleComment(RCore *core) {
	RPanel *p = r_panels_get_cur_panel (core->panels);
	if (!r_panels_check_panel_type (p, PANEL_CMD_DISASSEMBLY)) {
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

static void __direction_default_cb(void *user, int direction) {
#define MAX_CANVAS_SIZE 0xffffff
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

static void __direction_disassembly_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (cur->model->cache) {
		__direction_default_cb (user, direction);
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

static void __direction_graph_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (cur->model->cache) {
		__direction_default_cb (user, direction);
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

static void __direction_register_cb(void *user, int direction) {
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

static void __direction_stack_cb(void *user, int direction) {
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
		r_config_set_i (core->config, "stack.delta",
				r_config_get_i (core->config, "stack.delta") + cols);
		cur->model->addr -= cols;
		break;
	case 'j':
		r_config_set_i (core->config, "stack.delta",
				r_config_get_i (core->config, "stack.delta") - cols);
		cur->model->addr += cols;
		break;
	}
}

static void __direction_hexdump_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (!cur) {
		return;
	}
	if (cur->model->cache) {
		__direction_default_cb (user, direction);
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

static void __direction_panels_cursor_cb(void *user, int direction) {
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

static void __jmp_to_cursor_addr(RCore *core, RPanel *panel) {
	ut64 addr = r_panels_parse_string_on_cursor (core, panel, panel->view->curpos);
	if (addr == UT64_MAX) {
		return;
	}
	core->addr = addr;
	__update_disassembly_or_open (core);
}

static void __set_breakpoints_on_cursor(RCore *core, RPanel *panel) {
	if (!r_config_get_b (core->config, "cfg.debug")) {
		return;
	}
	if (r_panels_check_panel_type (panel, PANEL_CMD_DISASSEMBLY)) {
		r_core_cmdf (core, "dbs 0x%08"PFMT64x, core->addr + core->print->cur);
		panel->view->refresh = true;
	}
}

static void __insert_value(RCore *core, int wat) {
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
	if (r_panels_check_panel_type (cur, PANEL_CMD_STACK)) {
		const char *buf = r_cons_visual_readln (core->cons, "insert hex: ", NULL);
		if (buf) {
			r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, cur->model->addr);
			cur->view->refresh = true;
		}
	} else if (r_panels_check_panel_type (cur, PANEL_CMD_REGISTERS)) {
		const char *creg = core->dbg->creg;
		if (creg) {
			const char *buf = r_cons_visual_readln (core->cons, "new-reg-value> ", NULL);
			if (buf) {
				r_core_cmdf (core, "dr %s = %s", creg, buf);
				cur->view->refresh = true;
			}
		}
	} else if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		const char *buf = r_cons_visual_readln (core->cons, "insert asm: ", NULL);
		if (buf) {
			r_core_visual_asm (core, cur->model->addr + core->print->cur);
			cur->view->refresh = true;
		}
	} else if (r_panels_check_panel_type (cur, PANEL_CMD_HEXDUMP)) {
		const char *buf = r_cons_visual_readln (core->cons, "insert hex: ", NULL);
		if (buf) {
			r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, cur->model->addr + core->print->cur);
			cur->view->refresh = true;
		}
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
		RPanel *p = r_panels_get_panel (panels, i);
		if (!r_panels_check_panel_type (p, cmd)) {
			continue;
		}
		r_panels_set_panel_addr (core, p, addr);
	}
}

static void __handle_refs(RCore *core, RPanel *panel, ut64 tmp) {
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
	if (r_panels_check_panel_type (panel, PANEL_CMD_DISASSEMBLY)) {
		r_panels_set_panel_addr (core, panel, core->addr);
	} else {
		__set_addr_by_type (core, PANEL_CMD_DISASSEMBLY, core->addr);
	}
}

static void __add_vmark(RCore *core) {
	char *msg = r_str_newf (R_CONS_CLEAR_LINE"Set shortcut key for 0x%"PFMT64x": ", core->addr);
	int ch = r_panels_show_status (core, msg);
	free (msg);
	r_core_vmark (core, ch);
}

static void __handle_vmark(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	if (!r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		return;
	}
	RCons *cons = core->cons;
	int act = r_panels_show_status (core, "Visual Mark  s:set -:remove \':use: ");
	switch (act) {
	case 's':
		__add_vmark (core);
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

static void __set_dcb(RCore *core, RPanel *p) {
	if (r_panels_is_abnormal_cursor_type (core, p)) {
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
	if (r_panels_check_panel_type (p, PANEL_CMD_GRAPH)) {
		p->model->directionCb = __direction_graph_cb;
		return;
	}
	if (r_panels_check_panel_type (p, PANEL_CMD_STACK)) {
		p->model->directionCb = __direction_stack_cb;
	} else if (r_panels_check_panel_type (p, PANEL_CMD_DISASSEMBLY)) {
		p->model->directionCb = __direction_disassembly_cb;
	} else if (r_panels_check_panel_type (p, PANEL_CMD_REGISTERS)) {
		p->model->directionCb = __direction_register_cb;
	} else if (r_panels_check_panel_type (p, PANEL_CMD_FPU_REGISTERS)) {
		p->model->directionCb = __direction_register_cb;
	} else if (r_panels_check_panel_type (p, PANEL_CMD_XMM_REGISTERS)) {
		p->model->directionCb = __direction_register_cb;
	} else if (r_panels_check_panel_type (p, PANEL_CMD_YMM_REGISTERS)) {
		p->model->directionCb = __direction_register_cb;
	} else if (r_panels_check_panel_type (p, PANEL_CMD_HEXDUMP)) {
		p->model->directionCb = __direction_hexdump_cb;
	} else {
		p->model->directionCb = __direction_default_cb;
	}
}

static bool __check_func_diff(RCore *core, RPanel *p) {
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

static void __print_default_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && __check_func_diff (core, panel);
	char *cmdstr = r_panels_find_cmd_str_cache (core, panel);
	if (update || !cmdstr) {
		free (cmdstr);
		cmdstr = r_panels_handle_cmd_str_cache (core, panel, false);
	}
	r_panels_update_panel_contents (core, panel, cmdstr);
	free (cmdstr);
}

static void __print_decompiler_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	char *cmdstr = NULL;
	RAnalFunction *func = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	if (!func) {
		char *msg = r_str_newf ("No function at 0x%08"PFMT64x, core->addr);
		r_panels_update_pdc_contents (core, panel, msg);
		free (msg);
		return;
	}
	if (panel->model->cache) {
		cmdstr = r_panels_find_cmd_str_cache (core, panel);
		if (cmdstr) {
			free (panel->model->cmdStrCache);
			panel->model->cmdStrCache = strdup (cmdstr);
			if (panel->model->cmdStrCache) {
				r_panels_update_pdc_contents (core, panel, cmdstr);
			}
			free (cmdstr);
		}
	} else {
		cmdstr = r_panels_find_cmd_str_cache (core, panel);
		if (cmdstr) {
			free (panel->model->cmdStrCache);
			panel->model->cmdStrCache = strdup (cmdstr);
			free (cmdstr);  // Free the original cmdstr to avoid use-after-free
			if (panel->model->cmdStrCache) {
				// Use a temporary variable to avoid accessing potentially freed memory
				char *cached_cmd = panel->model->cmdStrCache;
				cmdstr = strdup (cached_cmd);
				if (R_STR_ISNOTEMPTY (cmdstr)) {
					r_panels_update_pdc_contents (core, panel, cmdstr);
				}
				free (cmdstr);
			} else {
				// Handle allocation failure - cmdstrCache is NULL or invalid
				cmdstr = NULL;
			}
		}
	}
	return;
#if 0
	if (core->panels_root->cur_pdc_cache) {
		cmdstr = strdup ((char *)sdb_ptr_get (core->panels_root->cur_pdc_cache,
					r_num_as_string (NULL, func->addr, false), 0));
		if (R_STR_ISNOTEMPTY (cmdstr)) {
			r_panels_set_cmd_str_cache (core, panel, cmdstr);
			r_panels_reset_scroll_pos (panel);
			r_panels_update_pdc_contents (core, panel, cmdstr);
			return;
		}
	}
#endif
}

static void __print_disasmsummary_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && __check_func_diff (core, panel);
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

static void __print_disassembly_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	core->print->screen_bounds = 1LL;
	char *cmdstr = r_panels_find_cmd_str_cache (core, panel);
	if (cmdstr) {
	//	r_panels_update_panel_contents (core, panel, cmdstr);
		// return;
	}
	char *ocmd = panel->model->cmd;
	if (panel->model->cmd && !strcmp (panel->model->cmd, "pd")) {
		panel->model->cmd = r_str_newf ("%s %d", panel->model->cmd, panel->view->pos.h - 3);
	} else {
		panel->model->cmd = r_str_newf ("%s", panel->model->cmd);
	}
	ut64 o_offset = core->addr;
	core->addr = panel->model->addr;
	r_core_seek (core, panel->model->addr, true);
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_core_cmd (core, ".dr*", 0);
	}
	free (cmdstr);
	cmdstr = r_panels_handle_cmd_str_cache (core, panel, false);
	core->addr = o_offset;
	free (panel->model->cmd);
	panel->model->cmd = ocmd;
	r_panels_update_panel_contents (core, panel, cmdstr);
	free (cmdstr);
}

static void __print_graph_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && __check_func_diff (core, panel);
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

static void __print_stack_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	const int size = r_config_get_i (core->config, "stack.size");
	const int delta = r_config_get_i (core->config, "stack.delta");
	const int bits = r_config_get_i (core->config, "asm.bits");
	const char sign = (delta < 0)? '+': '-';
	const int absdelta = R_ABS (delta);
	char *cmd = r_str_newf ("%s%s %d", PANEL_CMD_STACK, bits == 32? "w": "q", size);
	panel->model->cmd = cmd;
	ut64 sp_addr = r_reg_getv (core->anal->reg, "SP");
	char *k = r_str_newf ("%s @ 0x%08"PFMT64x"%c%d", cmd, sp_addr, sign, absdelta);
	char *cmdstr = r_core_cmd_str (core, k);
	free (k);
	r_panels_update_panel_contents (core, panel, cmdstr);
	free (cmdstr);
}

static void __print_hexdump_cb(void *user, void *p) {
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
		cmdstr = r_panels_handle_cmd_str_cache (core, panel, false);
		core->addr = o_offset;
	}
	r_panels_update_panel_contents (core, panel, cmdstr);
	free (cmdstr);
}

static void __set_pcb(RPanel *p) {
	if (!p->model->cmd) {
		return;
	}
	if (r_panels_check_panel_type (p, PANEL_CMD_DISASSEMBLY)) {
		p->model->print_cb = __print_disassembly_cb;
		return;
	}
	if (r_panels_check_panel_type (p, PANEL_CMD_STACK)) {
		p->model->print_cb = __print_stack_cb;
		return;
	}
	if (r_panels_check_panel_type (p, PANEL_CMD_HEXDUMP)) {
		p->model->print_cb = __print_hexdump_cb;
		return;
	}
	if (r_panels_check_panel_type (p, PANEL_CMD_DECOMPILER)) {
		p->model->print_cb = __print_decompiler_cb;
		return;
	}
	if (r_panels_check_panel_type (p, PANEL_CMD_GRAPH) || r_panels_check_panel_type (p, PANEL_CMD_TINYGRAPH)) {
		p->model->print_cb = __print_graph_cb;
		return;
	}
	if (r_panels_check_panel_type (p, PANEL_CMD_DISASMSUMMARY)) {
		p->model->print_cb = __print_disasmsummary_cb;
		return;
	}
	p->model->print_cb = __print_default_cb;
}

static int __file_history_up(RLine *line) {
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

static int __file_history_down(RLine *line) {
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
#if 0
	// seems unnecessary to me
	int j = 0;
	for (j = 0; j < core->panels->n_panels; j++) {
		RPanel *panel = r_panels_get_panel (core->panels, j);
		if (r_str_startswith (panel->model->cmd, "pdc")) {
			char *cmdstr = r_core_cmd_strf (core, "pdc@0x%08"PFMT64x, panel->model->addr);
			if (R_STR_ISNOTEMPTY (cmdstr)) {
				r_panels_update_panel_contents (core, panel, cmdstr);
				r_panels_reset_scroll_pos (panel);
			}
			free (cmdstr);
		}
	}
#endif
	r_panels_set_refresh_all (core, true, false);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	return 0;
}

static void __create_default_panels(RCore *core) {
	RPanels *panels = core->panels;
	panels->n_panels = 0;
	r_panels_set_curnode (core, 0);
	const char **panels_list = panels_static;
	if (panels->layout == PANEL_LAYOUT_DEFAULT_DYNAMIC) {
		panels_list = panels_dynamic;
	}

	int i = 0;
	while (panels_list[i]) {
		RPanel *p = r_panels_get_panel (panels, panels->n_panels);
		if (!p) {
			return;
		}
		const char *s = panels_list[i++];
		char *db_val = r_panels_search_db (core, s);
		r_panels_init_panel_param (core, p, s, db_val);
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
		r_panels_panels_layout (core, core->panels);
	}
	r_panels_set_curnode (core, 0);
	core->panels->panels_menu->depth = 1;
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	r_panels_del_menu (core);
	r_panels_del_menu (core);
	r_panels_set_refresh_all (core, true, false);
	return 0;
}

static int __load_layout_default_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_init_panels (core, core->panels);
	__create_default_panels (core);
	r_panels_panels_layout (core, core->panels);
	core->panels->panels_menu->depth = 1;
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	r_panels_del_menu (core);
	r_panels_del_menu (core);
	r_panels_del_menu (core);
	r_panels_set_refresh_all (core, true, false);
	return 0;
}

static int __close_file_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd_call (core, "o-*");
	return 0;
}

static int __project_open_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "Po `?i ProjectName`");
	return 0;
}

static int __project_save_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd_call (core, "Ps");
	return 0;
}

static int __project_close_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd_call (core, "Pc");
	return 0;
}

static int __save_layout_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_panels_save (core, NULL);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	r_panels_clear_panels_menu (core);
	r_panels_get_cur_panel (core->panels)->view->refresh = true;
	return 0;
}

static void __init_menu_saved_layout(void *_core, const char *parent) {
	char *dir_path = r_panels_panels_config_path (false);
	RList *dir = r_sys_dir (dir_path);
	RCore *core = (RCore *)_core;
	RListIter *it;
	char *entry, *entry2;
	if (dir) {
		r_list_foreach (dir, it, entry) {
			if (*entry != '.') {
				r_panels_add_menu (core, parent, entry, __load_layout_saved_cb);
			}
		}
	}
	char *sysdir_path = r_panels_panels_config_path (true);
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
					r_panels_add_menu (core, parent, entry, __load_layout_saved_cb);
				}
			}
		}
		r_list_free (sysdir);
		free (sysdir_path);
	}
	r_list_free (dir);
	free (dir_path);
}

static int __clear_layout_cb(void *user) {
	RCore *core = (RCore *)user;
	if (!r_panels_show_status_yesno (core, 0, "Clear all the saved layouts? (y/n): ")) {
		return 0;
	}
	char *dir_path = r_panels_panels_config_path (false);
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

	r_panels_update_menu (core, "Settings.Load Layout.Saved..", __init_menu_saved_layout);
	return 0;
}

static int __copy_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "How many bytes? ", "'y %s");
	return 0;
}

static int __paste_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd_call (core, "yy");
	return 0;
}

static int __write_str_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "insert string: ", "'w %s");
	return 0;
}

static int __write_hex_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "insert hexpairs: ", "'wx %s");
	return 0;
}

static int __assemble_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_visual_asm (core, core->addr);
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
	r_panels_update_menu (core, "Settings.Color Themes...", __init_menu_color_settings_layout);
	return 0;
}

static int __config_value_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	RStrBuf *tmp = r_strbuf_new (child->name);
	(void)r_str_split (r_strbuf_get(tmp), ':');
	const char *v = r_panels_show_status_input (core, "New value: ");
	r_config_set (core->config, r_strbuf_get (tmp), v);
	r_strbuf_free (tmp);
	free (parent->p->model->title);
	int _mi = core->panels->can->h - parent->p->view->pos.y - 4;
	parent->p->model->title = r_strbuf_drain (r_panels_draw_menu (core, parent, R_MAX (_mi, 3)));
	size_t i;
	for (i = 1; i < menu->depth; i++) {
		RPanel *p = menu->history[i]->p;
		p->view->refresh = true;
		menu->refreshPanels[i - 1] = p;
	}
	if (!strcmp (parent->name, "asm")) {
		r_panels_update_menu (core, "Settings.Disassembly....asm", __init_menu_disasm_asm_settings_layout);
	}
	if (!strcmp (parent->name, "Screen")) {
		r_panels_update_menu (core, "Settings.Screen", __init_menu_screen_settings_layout);
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
	int _mi2 = core->panels->can->h - parent->p->view->pos.y - 4;
	parent->p->model->title = r_strbuf_drain (r_panels_draw_menu (core, parent, R_MAX (_mi2, 3)));
	size_t i;
	for (i = 1; i < menu->depth; i++) {
		RPanel *p = menu->history[i]->p;
		p->view->refresh = true;
		menu->refreshPanels[i - 1] = p;
	}
	if (!strcmp (parent->name, "asm")) {
		r_panels_update_menu (core, "Settings.Disassembly....asm", __init_menu_disasm_asm_settings_layout);
	} else if (!strcmp (parent->name, "Screen")) {
		r_panels_update_menu (core, "Settings.Screen", __init_menu_screen_settings_layout);
	}
	return 0;
}

static const char *screen_value_items[] = { "scr.color", NULL };

static void __init_menu_screen_settings_layout(void *_core, const char *parent) {
	r_panels_init_menu_config ((RCore *)_core, parent, menus_settings_screen, COUNT (menus_settings_screen), screen_value_items);
}

static int __calculator_cb(void *user) {
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

static int __r2_assembler_cb(void *user) {
	RCore *core = (RCore *)user;
	const int ocur = core->print->cur_enabled;
	r_core_visual_asm (core, core->addr);
	core->print->cur_enabled = ocur;
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
	RCore *core = (RCore *)user;
	r_cons_set_raw (core->cons, 0);
	r_cons_flush (core->cons);
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
	__add_cmdf_panel (core, "rop grep: ", "'/R %s");
	return 0;
}

static int __code_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "search code: ", "'/c %s");
	return 0;
}

static int __hexpairs_cb(void *user) {
	RCore *core = (RCore *)user;
	__add_cmdf_panel (core, "search hexpairs: ", "'/x %s");
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
	char *end = r_panels_show_status_input (core, "target addr: ");
	__esil_step_to (core, r_num_math (core->num, end));
	return 0;
}

static int __esil_step_range_cb(void *user) {
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
	__esil_init (core);
	__esil_step_to (core, d_a);
	core->addr = tmp;
	return 0;
}

static int __io_cache_on_cb(void *user) {
	RCore *core = (RCore *)user;
	r_config_set_b (core->config, "io.cache", true);
	(void)r_panels_show_status (core, "io.cache is on");
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	return 0;
}

static int __io_cache_off_cb(void *user) {
	RCore *core = (RCore *)user;
	r_config_set_b (core->config, "io.cache", false);
	(void)r_panels_show_status (core, "io.cache is off");
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
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
	r_panels_del_menu (core);
	r_panels_panels_refresh (core);
	r_cons_gotoxy (core->cons, 0, 3);
	r_cons_flush (core->cons);
	r_core_cmdf (core, "aaa");
	return 0;
}

static int __aae_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aae");
	return 0;
}

static int __aap_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aap");
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

static int __references_cb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aar");
	return 0;
}

static int __fortune_cb(void *user) {
	RCore *core = (RCore *)user;
	char *s = r_core_cmd_str (core, "fo");
	r_cons_message (core->cons, s);
	free (s);
	return 0;
}

static int __game_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_2048 (core->cons, core->panels->can->color);
	return 0;
}

static int __help_cb(void *user) {
	RCore *core = (RCore *)user;
	r_panels_toggle_help (core);
	return 0;
}

static int __license_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_message (core->cons, "Copyright 2006-2024 - pancake - LGPL");
	return 0;
}

static int __version2_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_set_raw (core->cons, false);
	r_core_cmd0 (core, "!!r2 -Vj>$a");
	r_core_cmd0 (core, "$a~{}~..");
	r_core_cmd0 (core, "rm $a");
	r_cons_set_raw (core->cons, true);
	r_cons_flush (core->cons);
	return 0;
}

static int __version_cb(void *user) {
	RCore *core = (RCore *)user;
	char *s = r_core_cmd_str (core, "?V");
	r_cons_message (core->cons, s);
	free (s);
	return 0;
}

static int __r2rc_cb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_set_raw (core->cons, false);
	r_core_cmd0 (core, "edit");
	r_cons_set_raw (core->cons, true);
	r_cons_flush (core->cons);
	return 0;
}

static int __writeValueCb(void *user) {
	RCore *core = (RCore *)user;
	char *res = r_panels_show_status_input (core, "insert number: ");
	if (res) {
		r_core_cmdf (core, "'wv %s", res);
		free (res);
	}
	return 0;
}

static int __quit_cb(void *user) {
	r_panels_set_root_state ((RCore *)user, QUIT);
	return 0;
}

static int __open_menu_cb(void *user) {
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
	"rahash2", "rarun2", "rasign2", "rasm2", "ravc2", "rax2", NULL
};

static void __init_menu_manpages(void *_core, const char *parent) {
	RCore *core = (RCore *)_core;
	int i;
	for (i = 0; manpage_tools[i]; i++) {
		r_panels_add_menu (core, parent, manpage_tools[i], __help_manpage_cb);
	}
}

static void __init_menu_color_settings_layout(void *_core, const char *parent) {
	RCore *core = (RCore *)_core;
	char *now = r_core_cmd_str (core, "eco.");
	r_str_split (now, '\n');
	parent = "Settings.Color Themes...";
	RList *list = r_panels_sorted_list (core, (const char **)core->visual.menus_Colors, COUNT (core->visual.menus_Colors));
	char *pos;
	RListIter* iter;
	RStrBuf *buf = r_strbuf_new (NULL);
	r_list_foreach (list, iter, pos) {
		if (pos && !strcmp (now, pos)) {
			r_strbuf_setf (buf, "%s%s", PANEL_HL_COLOR, pos);
			r_panels_add_menu (core, parent, r_strbuf_get (buf), __settings_colors_cb);
			continue;
		}
		r_panels_add_menu (core, parent, pos, __settings_colors_cb);
	}
	free (now);
	r_list_free (list);
	r_strbuf_free (buf);
}

static void __init_menu_disasm_settings_layout(void *_core, const char *parent) {
	RCore *core = (RCore *)_core;
	RList *list = r_panels_sorted_list (core, menus_settings_disassembly, COUNT (menus_settings_disassembly));
	char *pos;
	RListIter* iter;
	RStrBuf *rsb = r_strbuf_new (NULL);
	r_list_foreach (list, iter, pos) {
		if (!strcmp (pos, "asm")) {
			r_panels_add_menu (core, parent, pos, __open_menu_cb);
			__init_menu_disasm_asm_settings_layout (core, "Settings.Disassembly....asm");
		} else {
			r_strbuf_set (rsb, pos);
			r_strbuf_append (rsb, ": ");
			r_strbuf_append (rsb, r_config_get (core->config, pos));
			r_panels_add_menu (core, parent, r_strbuf_get (rsb), __config_toggle_cb);
		}
	}
	r_list_free (list);
	r_strbuf_free (rsb);
}

static const char *asm_value_items[] = { "asm.var.summary", "asm.arch", "asm.bits", "asm.cpu", NULL };

static void __init_menu_disasm_asm_settings_layout(void *_core, const char *parent) {
	r_panels_init_menu_config ((RCore *)_core, parent, menus_settings_disassembly_asm, COUNT (menus_settings_disassembly_asm), asm_value_items);
}

static void __load_config_menu(RCore *core) {
	RList *themes_list = r_core_list_themes (core);
	RListIter *th_iter;
	char *th;
	int i = 0;
	r_list_foreach (themes_list, th_iter, th) {
		core->visual.menus_Colors[i++] = th;
	}
}

static const MenuItem file_items[] = {
	{ "Open File", __open_file_cb },
	{ "ReOpen", __open_menu_cb },
	{ "Close File", __close_file_cb },
	{ "Open Project", __project_open_cb },
	{ "Save Project", __project_save_cb },
	{ "Close Project", __project_close_cb },
	{ "Quit", __quit_cb },
	{ NULL, NULL }
};

static const MenuItem settings_items[] = {
	{ "Edit radare2rc", __r2rc_cb },
	{ "Save Layout", __save_layout_cb },
	{ "Load Layout", __open_menu_cb },
	{ "Clear Saved Layouts", __clear_layout_cb },
	{ NULL, NULL }
};

static const MenuItem edit_items[] = {
	{ "Copy", __copy_cb },
	{ "Paste", __paste_cb },
	{ "Write String", __write_str_cb },
	{ "Write Hex", __write_hex_cb },
	{ "Write Value", __writeValueCb },
	{ "Assemble", __assemble_cb },
	{ "Fill", __fill_cb },
	{ "io.cache", __open_menu_cb },
	{ NULL, NULL }
};

static const MenuItem view_items[] = {
	{ PANEL_TITLE_ALL_DECOMPILER, __show_all_decompiler_cb },
	{ NULL, NULL }
};

static const MenuItem tools_items[] = {
	{ "Calculator", __calculator_cb },
	{ "Assembler", __r2_assembler_cb },
	{ "R2 Shell", __r2_shell_cb },
	{ "System Shell", __system_shell_cb },
	{ NULL, NULL }
};

static const MenuItem search_items[] = {
	{ "String (Whole Bin)", __string_whole_bin_cb },
	{ "String (Data Sections)", __string_data_sec_cb },
	{ "ROP", __rop_cb },
	{ "Code", __code_cb },
	{ "Hexpairs", __hexpairs_cb },
	{ NULL, NULL }
};

static const MenuItem emulate_items[] = {
	{ "Step From", __esil_init_cb },
	{ "Step To", __esil_step_to_cb },
	{ "Step Range", __esil_step_range_cb },
	{ NULL, NULL }
};

static const MenuItem debug_items[] = {
	{ "Breakpoints", __break_points_cb },
	{ "Watchpoints", __watch_points_cb },
	{ "Continue", __continue_cb },
	{ "Step", __step_cb },
	{ "Step Over", __step_over_cb },
	{ "Reload", __reload_cb },
	{ NULL, NULL }
};

static const MenuItem analyze_items[] = {
	{ "Function", __function_cb },
	{ "Symbols", __symbols_cb },
	{ "Program", __program_cb },
	{ "BasicBlocks", __basic_blocks_cb },
	{ "Preludes", __aap_cb },
	{ "Emulation", __aae_cb },
	{ "Calls", __calls_cb },
	{ "References", __references_cb },
	{ NULL, NULL }
};

static const MenuItem help_items[] = {
	{ "License", __license_cb },
	{ "Version", __version_cb },
	{ "Full Version", __version2_cb },
	{ "Fortune", __fortune_cb },
	{ "2048", __game_cb },
	{ "Manpages...", __open_menu_cb },
	{ "Toggle Help", __help_cb },
	{ NULL, NULL }
};

static const MenuItem reopen_items[] = {
	{ "In Read+Write", __rw_cb },
	{ "In Debugger", __debugger_cb },
	{ NULL, NULL }
};

static const MenuItem loadlayout_items[] = {
	{ "Saved..", __open_menu_cb },
	{ "Default", __load_layout_default_cb },
	{ NULL, NULL }
};

static const MenuItem iocache_items[] = {
	{ "On", __io_cache_on_cb },
	{ "Off", __io_cache_off_cb },
	{ NULL, NULL }
};

static bool __init_panels_menu(RCore *core) {
	RPanels *panels = core->panels;
	RPanelsMenu *panels_menu = R_NEW0 (RPanelsMenu);
	RPanelsMenuItem *root = R_NEW0 (RPanelsMenuItem);
	panels->panels_menu = panels_menu;
	panels_menu->root = root;
	root->n_sub = 0;
	root->name = NULL;
	root->sub = NULL;

	__load_config_menu (core);

	int i;
	for (i = 0; menus[i]; i++) {
		r_panels_add_menu (core, NULL, menus[i], __open_menu_cb);
	}

	r_panels_add_menu_items (core, "File", file_items, menus_File, __add_cmd_panel);
	r_panels_add_menu_items (core, "Settings", settings_items, menus_Settings, __open_menu_cb);
	r_panels_add_menu_items (core, "Edit", edit_items, menus_Edit, __add_cmd_panel);
	r_panels_add_menu_items_sorted (core, "View", view_items, menus_View, COUNT (menus_View), __add_cmd_panel);
	r_panels_add_menu_items (core, "Tools", tools_items, menus_Tools, NULL);
	r_panels_add_menu_items (core, "Search", search_items, menus_Search, NULL);
	r_panels_add_menu_items (core, "Emulate", emulate_items, menus_Emulate, NULL);
	r_panels_add_menu_items_sorted (core, "Debug", debug_items, menus_Debug, COUNT (menus_Debug), __add_cmd_panel);
	r_panels_add_menu_items (core, "Analyze", analyze_items, menus_Analyze, NULL);
	r_panels_add_menu_items (core, "Help", help_items, menus_Help, __help_cb);
	r_panels_add_menu_items (core, "File.ReOpen", reopen_items, menus_ReOpen, NULL);
	r_panels_add_menu_items (core, "Settings.Load Layout", loadlayout_items, menus_loadLayout, NULL);

	__init_menu_saved_layout (core, "Settings.Load Layout.Saved..");
	__init_menu_color_settings_layout (core, "Settings.Color Themes...");
	__init_menu_manpages (core, "Help.Manpages...");

	{
		const char *parent = "Settings.Decompiler...";
		char *opts = r_core_cmd_str (core, "e cmd.pdc=?");
		RList *optl = r_str_split_list (opts, "\n", 0);
		RListIter *iter;
		char *opt;
		r_list_foreach (optl, iter, opt) {
			r_panels_add_menu (core, parent, strdup (opt), __settings_decompiler_cb);
		}
		r_list_free (optl);
		free (opts);
	}

	__init_menu_disasm_settings_layout (core, "Settings.Disassembly...");
	__init_menu_screen_settings_layout (core, "Settings.Screen...");
	r_panels_add_menu_items (core, "Edit.io.cache", iocache_items, menus_iocache, NULL);

	panels_menu->history = calloc (8, sizeof (RPanelsMenuItem *));
	r_panels_clear_panels_menu (core);
	panels_menu->refreshPanels = calloc (8, sizeof (RPanel *));
	return true;
}

static void __refresh_core_offset(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
		core->addr = cur->model->addr;
	}
}

static void demo_begin(RCore *core, RConsCanvas *can) {
	char *s = r_cons_canvas_tostring (can);
	if (s) {
		// TODO drop utf8!!
		r_str_ansi_filter (s, NULL, NULL, -1);
		int i, h, w = r_cons_get_size (core->cons, &h);
		h -= r_config_get_i (core->config, "scr.notch");
		for (i = 0; i < 40; i+= (1 + (i/30))) {
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

static void demo_end(RCore *core, RConsCanvas *can) {
	bool utf8 = r_config_get_b (core->config, "scr.utf8");
	r_config_set_b (core->config, "scr.utf8", false);
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	cur->view->refresh = true;
	core->visual.firstRun = false;
	r_panels_panels_refresh (core);
	core->visual.firstRun = true;
	r_config_set_b (core->config, "scr.utf8", utf8);
	char *s = r_cons_canvas_tostring (can);
	if (s) {
		// TODO drop utf8!!
		r_str_ansi_filter (s, NULL, NULL, -1);
		int i, h, w = r_cons_get_size (core->cons, &h);
		h -= r_config_get_i (core->config, "scr.notch");
		for (i = h; i > 0; i--) {
			int H = i;
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

static void __panel_breakpoint(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
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
		r_core_cmd_call (core, "dr PC=$$");
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
		__handlePrompt (core, panels);
		break;
	case '?':
		menu->n_refresh = 0;
		r_panels_toggle_help (core);
		break;
	case '"':
		menu->n_refresh = 0;
		r_panels_create_modal (core, r_panels_get_panel (panels, 0), panels->modal_db);
		r_panels_set_mode (core, PANEL_MODE_DEFAULT);
		break;
	}
}

static bool __handle_console(RCore *core, RPanel *panel, const int key) {
	if (!r_panels_check_panel_type (panel, PANEL_CMD_CONSOLE)) {
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

static char *__create_panels_config_path(const char *file) {
	char *dir_path = r_panels_panels_config_path (false);
	r_sys_mkdirp (dir_path);
	char *file_path = r_str_newf (R_JOIN_2_PATHS ("%s", "%s"), dir_path, file);
	R_FREE (dir_path);
	return file_path;
}

static char *__get_panels_config_file_from_dir(const char *file) {
	char *dir_path = r_panels_panels_config_path (false);
	RList *dir = r_sys_dir (dir_path);
	if (!dir_path || !dir) {
		free (dir_path);
		dir_path = r_panels_panels_config_path (true);
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
	char *config_path = __create_panels_config_path (name);
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
		r_panels_update_menu (core, "Settings.Load Layout.Saved..", __init_menu_saved_layout);
		(void)r_panels_show_status (core, "Panels layout saved!");
	} else {
		pj_free (pj);
	}
	free (config_path);
}

static char *__parse_panels_config(const char *cfg, int len) {
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

R_API bool r_core_panels_load(RCore *core, const char *_name) {
	if (!core->panels) {
		return false;
	}
	char *config_path = __get_panels_config_file_from_dir (_name);
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
	char *tmp_cfg = __parse_panels_config (p_cfg, strlen (p_cfg));
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
	int h, w = r_cons_get_size (core->cons, &h);
	h -= r_config_get_i (core->config, "scr.notch");
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
	r_panels_panels_layout_refresh (core);
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
		__handle_menu (core, key);
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

	if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY) && '0' < key && key <= '9') {
		ut8 ch = key;
		r_core_visual_jump (core, ch);
		r_panels_set_panel_addr (core, cur, core->addr);
		goto repeat;
	}

	const char *cmd;
	RConsCanvas *can = panels->can;
	if (__handle_console (core, cur, key)) {
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
		if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
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
		__handleComment (core);
		break;
	case '$':
		if (core->print->cur_enabled) {
			r_core_cmdf (core, "dr PC=$$+%d", core->print->cur);
		} else {
			r_core_cmd_call (core, "dr PC=$$");
		}
		break;
	case 's':
		__panel_single_step_in (core);
		if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case 'S':
		__panel_single_step_over (core);
		if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case ' ':
		r_panels_call_visual_graph (core);
		break;
	case ':':
		__handlePrompt(core, panels);
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
			r_core_cmd_call (core, "ecr");
		} else {
			r_core_cmd_call (core, "ecn");
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
		__replace_cmd (core, PANEL_TITLE_DISASSEMBLY, PANEL_CMD_DISASSEMBLY);
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
					__direction_panels_cursor_cb (core, 'j');
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
					__direction_panels_cursor_cb (core, 'k');
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
		r_panels_create_modal (core, cur, panels->modal_db);
		if (r_panels_check_root_state (core, ROTATE)) {
			goto exit;
		}
		// all panels containing decompiler data should be cached
		RPanel *p = r_panels_get_cur_panel (core->panels);
		r_panels_cache_white_list (core, p);
#if 0
		if (strstr (cur->model->title, "Decomp")) {
			cur->model->cache = true;
		}
#endif
		break;
	case 'O':
		__handle_print_rotate (core);
		break;
	case 'n':
		if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
			r_core_seek_next (core, r_config_get (core->config, "scr.nkey"));
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case 'N':
		if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
			r_core_seek_previous (core, r_config_get (core->config, "scr.nkey"));
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case 'x':
		__handle_refs (core, cur, UT64_MAX);
		break;
	case 'X':
#if 0
// already accessible via xX
		r_core_visual_refs (core, false, true);
		cur->model->addr = core->addr;
		set_refresh_all (panels, false);
#endif
		r_panels_dismantle_del_panel (core, cur, panels->curnode);
		break;
	case 9: // TAB
		r_panels_handle_tab_key (core, false);
		break;
	case 'Z': // SHIFT-TAB
		r_panels_handle_tab_key (core, true);
		break;
	case 'M':
		__handle_vmark (core);
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
		if (r_panels_check_panel_type (cur, PANEL_CMD_HEXDUMP)) {
			r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") + 1);
		} else {
			int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
			r_config_set_i (core->config, "asm.cmt.col", cmtcol + 2);
		}
		cur->view->refresh = true;
		break;
	case '[':
		if (r_panels_check_panel_type (cur, PANEL_CMD_HEXDUMP)) {
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
		__insert_value (core, 'x');
		break;
	case 'I':
		__insert_value (core, 'a');
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
					__replace_cmd (core, "px", "px");
				} else if (!strcmp (format, "analyze function")) {
					r_core_cmd_call (core, "af");
					r_core_cmd_call (core, "aaef");
				} else if (!strcmp (format, "analyze program")) {
					r_core_cmd_call (core, "aaa");
				} else if (!strcmp (format, "address")) {
					r_config_toggle (core->config, "asm.addr");
				} else if (!strcmp (format, "esil")) {
					r_config_toggle (core->config, "asm.esil");
				} else if (!strcmp (format, "bytes")) {
					r_config_toggle (core->config, "asm.bytes");
				} else if (!strcmp (format, "comments")) {
					r_config_toggle (core->config, "asm.comments");
				} else if (!strcmp (format, "disasm")) {
					__replace_cmd (core, "pd", "pd");
				} else if (!strcmp (format, "entropy")) {
					__replace_cmd (core, "p=e 100", "p=e 100");
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

			__replace_cmd (core, PANEL_TITLE_DECOMPILER, PANEL_CMD_DECOMPILER);

			int h, w = r_cons_get_size (core->cons, &h);
			h -= r_config_get_i (core->config, "scr.notch");
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
		__rotate_asmemu (core, r_panels_get_cur_panel (panels));
		break;
	case '&':
		r_panels_toggle_cache (core, r_panels_get_cur_panel (panels));
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
			if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
				r_panels_set_panel_addr (core, cur, core->addr);
			}
		}
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			__panel_single_step_over (core);
			if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
				r_panels_set_panel_addr (core, cur, core->addr);
			}
		}
		break;
	case R_CONS_KEY_F9:
		cmd = r_config_get (core->config, "key.f9");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			if (r_panels_check_panel_type (cur, PANEL_CMD_DISASSEMBLY)) {
				__panel_continue (core);
				r_panels_set_panel_addr (core, cur, core->addr);
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
#if 0
	case 27: // ESC
		if (r_cons_readchar (core->cons) == 91) {
			if (r_cons_readchar (core->cons) == 90) {}
		}
		break;
#endif
	default:
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
	r_cons_set_interactive (core->cons, o_interactive);
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
		__init_new_panels_root (core);
	} else {
		if (!panels_root->n_panels) {
			panels_root->n_panels = 0;
			panels_root->cur_panels = 0;
			__init_new_panels_root (core);
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
		__panels_process (core, panels_root->panels[panels_root->cur_panels]);
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

static void __init_new_panels_root(RCore *core) {
	RPanelsRoot *panels_root = core->panels_root;
	RPanels *panels = r_panels_panels_new (core);
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
	if (!r_panels_init_panels (core, panels)) {
		core->panels = prev;
		return;
	}
	__init_all_dbs (core);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	__create_default_panels (core);
	r_panels_panels_layout (core, panels);
	core->panels = prev;
}

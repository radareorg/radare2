/* Copyright radare2 2014-2019 - Author: pancake, vane11ope */

// pls move the typedefs into roons and rename it -> RConsPanel

#include <r_core.h>

#define PANEL_NUM_LIMIT 64

#define PANEL_TITLE_SYMBOLS       "Symbols"
#define PANEL_TITLE_STACK         "Stack"
#define PANEL_TITLE_REGISTERS     "Registers"
#define PANEL_TITLE_DISASSEMBLY   "Disassembly"
#define PANEL_TITLE_DISASMSUMMARY "Disassemble Summary"
#define PANEL_TITLE_DECOMPILER    "Decompiler"
#define PANEL_TITLE_GRAPH         "Graph"
#define PANEL_TITLE_FUNCTIONS     "Functions"
#define PANEL_TITLE_BREAKPOINTS   "Breakpoints"
#define PANEL_TITLE_STRINGS_DATA  "Strings in data sections"
#define PANEL_TITLE_STRINGS_BIN   "Strings in the whole bin"
#define PANEL_TITLE_SECTIONS      "Sections"
#define PANEL_TITLE_SEGMENTS      "Segments"

#define PANEL_CMD_SYMBOLS         "isq"
#define PANEL_CMD_STACK           "px"
#define PANEL_CMD_REGISTERS       "dr"
#define PANEL_CMD_DISASSEMBLY     "pd"
#define PANEL_CMD_DISASMSUMMARY   "pdsf"
#define PANEL_CMD_DECOMPILER      "pdc"
#define PANEL_CMD_FUNCTION        "afl"
#define PANEL_CMD_GRAPH           "agf"
#define PANEL_CMD_HEXDUMP         "xc"
#define PANEL_CMD_CONSOLE         "$console"

#define PANEL_CONFIG_MENU_MAX    64
#define PANEL_CONFIG_PAGE        10
#define PANEL_CONFIG_SIDEPANEL_W 60
#define PANEL_CONFIG_RESIZE_W    4
#define PANEL_CONFIG_RESIZE_H    4

#define COUNT(x) (sizeof((x)) / sizeof((*x)) - 1)

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
	"File", "Settings", "Edit", "View", "Tools", "Search", "Emulate", "Debug", "Analyze", "Fun", "About", "Help",
	NULL
};

static const char *menus_File[] = {
	"New", "Open", "ReOpen", "Close", "Save Layout", "Load Layout", "Clear Saved Layouts", "Quit",
	NULL
};

static const char *menus_Settings[] = {
	"Colors", "Decompiler", "Disassembly",
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
	"Console", "Hexdump", "Disassembly", "Disassemble Summary", "Decompiler", "Graph", "Functions", "Sections", "Segments", PANEL_TITLE_STRINGS_DATA, PANEL_TITLE_STRINGS_BIN, "Symbols", "Imports", "Info", "Database",  "Breakpoints", "Comments", "Entropy", "Entropy Fire",
	"Stack", "Var READ address", "Var WRITE address", "Summary",
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

static const char *menus_Fun[] = {
	"Fortune", "2048",
	NULL
};

static const char *menus_About[] = {
	"License", "Version",
	NULL
};

static const char *menus_Colors[128];

static const char *menus_settings_disassembly[] = {
	"asm.bytes", "asm.section", "hex.section", "asm.cmt.right", "io.cache", "hex.pairs", "emu.str",
	"asm.emu", "asm.var.summary", "asm.pseudo", "asm.flags.inbytes",
	NULL
};

static const char *menus_Help[] = {
	"Toggle Help",
	NULL
};

static const char *entropy_rotate[] = {
	"", "2", "b", "c", "d", "e", "F", "i", "j", "m", "p", "s", "z", "0",
	NULL
};

static const char *hexdump_rotate[] = {
	"", "a", "r", "b", "h", "w", "q", "d", "r",
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

static const char *help_msg_panels[] = {
	"|",        "split the current panel vertically",
	"-",        "split the current panel horizontally",
	":",        "run r2 command in prompt",
	";",        "add/remove comment",
	"_",        "start the hud input mode",
	"\\",       "show the user-friendly hud",
	"?",        "show this help",
	"!",        "run r2048 game",
	".",        "seek to PC or entrypoint",
	"*",        "show decompiler in the current panel",
	"\"",       "create a panel from the list and replace the current one",
	"/",        "highlight the keyword",
	"(",        "toggle snow",
	"&",        "toggle cache",
	"[1-9]",    "follow jmp/call identified by shortcut (like ;[1])",
	"' '",      "(space) toggle graph / panels",
	"tab",      "go to the next panel",
	"Enter",    "start Zoom mode",
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
	"G",        "show graph in the current panel",
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
	"w",        "start Window mode",
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
	"Enter",    "start Zoom mode",
	"d",        "define in the current address. Same as Vd",
	"b",        "browse symbols, flags, configurations, classes, ...",
	"hjkl",     "move around (left-down-up-right)",
	"HJKL",     "resize panels vertically/horizontally",
	"Q/q/w",    "quit Window mode",
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
	"q/Q/Enter","quit Zoom mode",
	NULL
};

/* init */
static bool __init(RCore *core, RPanels *panels, int w, int h);
static void __initSdb(RCore *core);
static void __initRotatedb(RCore *core);
static void __init_almighty_db(RCore *core);
static bool __initPanelsMenu(RCore *core);
static bool __initPanels(RCore *core, RPanels *panels);
static void __init_all_dbs(RCore *core);
static void __init_panel_param(RCore *core, RPanel *p, const char *title, const char *cmd, bool cache);
static RPanels *__panels_new(RCore *core);
static void __init_new_panels_root(RCore *core);

/* create */
static void __createDefaultPanels(RCore *core);
static RConsCanvas *__createNewCanvas(RCore *core, int w, int h);

/* free */
static void __panels_free(RPanelsRoot *panels_root, int i, RPanels *panels);
static void __freePanelModel(RPanel *panel);
static void __freePanelView(RPanel *panel);
static void __freeSinglePanel(RPanel *panel);
static void __freeAllPanels(RPanels *panels);

/* get */
static RPanel *__getPanel(RPanels *panels, int i);
static RPanel *__getCurPanel(RPanels *panels);
static RPanels *__get_panels(RPanelsRoot *panels_root, int i);
static RPanels *__get_cur_panels(RPanelsRoot *panels_root);

/* set */
static void __set_curnode(RCore *core, int idx);
static void __setRefreshAll(RCore *core, bool clearCache, bool force_refresh);
static void __setAddrByType(RCore *core, const char *cmd, ut64 addr);
static void __setRefreshByType(RCore *core, const char *cmd, bool clearCache);
static void __setCursor(RCore *core, bool cur);
static void __setdcb(RCore *core, RPanel *p);
static void __setrcb(RPanels *ps, RPanel *p);
static void __setpcb(RPanel *p);
static void __setReadOnly(RPanel *p, char *s);
static void __set_pos(RPanelPos *pos, int x, int y);
static void __set_size(RPanelPos *pos, int w, int h);
static void __set_geometry(RPanelPos *pos, int x, int y, int w, int h);
static void __set_panel_addr(RCore *core, RPanel *panel, ut64 addr);
static void __set_root_state(RCore *core, RPanelsRootState state);

/* reset */
static void __resetScrollPos(RPanel *p);

/* update */
static void __update_disassembly_or_open(RCore *core);
static void __updateHelp(RPanels *ps);

/* check */
static bool __check_panel_type(RPanel *panel, const char *type, int len);
static void __panels_check_stackbase(RCore *core);
static bool __checkPanelNum(RCore *core);
static bool __checkFunc(RCore *core);
static bool __checkFuncDiff(RCore *core, RPanel *p);
static bool __check_root_state(RCore *core, RPanelsRootState state);

/* add */
static void __addHelpPanel(RCore *core);
static void __add_visual_mark(RCore *core);
static void __addMenu(RCore *core, const char *parent, const char *base_name, RPanelsMenuCallback cb, RPanelsMenuGetName get_name_cb);

/* user input */
static int __show_status(RCore *core, const char *msg);
static bool __show_status_yesno(RCore *core, int def, const char *msg);
static char *__show_status_input(RCore *core, const char *msg);
static void __panelPrompt(const char *prompt, char *buf, int len);

/* panel layout */
static void __panels_layout_refresh(RCore *core);
static void __panels_layout(RPanels *panels);
static void __layoutDefault(RPanels *panels);
static void __savePanelsLayout(RCore *core);
static int __loadSavedPanelsLayout(RCore *core, const char *name);
static void __splitPanelVertical(RCore *core, RPanel *p, const char *name, const char *cmd, bool cache);
static void __splitPanelHorizontal(RCore *core, RPanel *p, const char *name, const char *cmd, bool cache);
static void __panelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int color);
static void __menuPanelPrint(RConsCanvas *can, RPanel *panel, int x, int y, int w, int h);
static void __defaultPanelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int w, int h, int color);
static void __resizePanelLeft(RPanels *panels);
static void __resizePanelRight(RPanels *panels);
static void __resizePanelUp(RPanels *panels);
static void __resizePanelDown(RPanels *panels);
static void __adjustSidePanels(RCore *core);
static void __insertPanel(RCore *core, int n, const char *name, const char*cmd, bool cache);
static void __dismantleDelPanel(RCore *core, RPanel *p, int pi);
static void __dismantlePanel(RPanels *ps, RPanel *p);
static void __panels_refresh(RCore *core);
static void __doPanelsRefresh(RCore *core);
static void __doPanelsRefreshOneShot(RCore *core);
static void __panelAllClear(RPanels *panels);
static void __delPanel(RCore *core, int pi);
static void __delInvalidPanels(RCore *core);
static void __swapPanels(RPanels *panels, int p0, int p1);

/* cursor */
static bool __is_abnormal_cursor_type(RCore *core, RPanel *panel);
static bool __is_normal_cursor_type(RPanel *panel);
static void __activateCursor(RCore *core);
static ut64 __parse_string_on_cursor(RCore *core, RPanel *panel, int idx);
static void __cursorLeft(RCore *core);
static void __cursorRight(RCore *core);
static void __cursorDown(RCore *core);
static void __cursorUp(RCore *core);
static void __fix_cursor_up(RCore *core);
static void __fix_cursor_down(RCore *core);
static void __jmp_to_cursor_addr(RCore *core, RPanel *panel);
static void __cursor_del_breakpoints(RCore *core, RPanel *panel);
static void __insertValue(RCore *core);
static void __set_breakpoints_on_cursor(RCore *core, RPanel *panel);

/* filter */
static void __set_filter(RCore *core, RPanel *panel);
static void __reset_filter(RCore *core, RPanel *panel);
static void __renew_filter(RPanel *panel, int n);
static char *__apply_filter_cmd(RCore *core, RPanel *panel);

/* cmd */
static int __addCmdPanel(void *user);
static int __addCmdfPanel(RCore *core, char *input, char *str);
static void __setCmdStrCache(RCore *core, RPanel *p, char *s);
static char *__handleCmdStrCache(RCore *core, RPanel *panel, bool force_cache);
static char *__findCmdStrCache(RCore *core, RPanel *panel);
static char *__loadCmdf(RCore *core, RPanel *p, char *input, char *str);
static void __replaceCmd(RCore *core, const char *title, const char *cmd, const bool cache);

/* rotate */
static void __rotatePanels(RCore *core, bool rev);
static void __rotatePanelCmds(RCore *core, const char **cmds, const int cmdslen, const char *prefix, bool rev);
static void __rotateAsmemu(RCore *core, RPanel *p);

/* mode */
static void __setMode(RCore *core, RPanelsMode mode);
static bool __handleZoomMode(RCore *core, const int key);
static bool __handleWindowMode(RCore *core, const int key);
static bool __handleCursorMode(RCore *core, const int key);
static void __toggleZoomMode(RCore *core);
static void __toggleWindowMode(RCore *core);

/* modal */
static void __exec_almighty(RCore *core, RPanel *panel, RModal *modal, Sdb *menu_db, RPanelLayout dir);
static void __delete_almighty(RCore *core, RModal *modal, Sdb *menu_db);
static void __create_almighty(RCore *core, RPanel *panel, Sdb *menu_db);
static void __update_modal(RCore *core, Sdb *menu_db, RModal *modal);
static bool __draw_modal (RCore *core, RModal *modal, int range_end, int start, const char *name);
static RModal *__init_modal();
static void __free_modal(RModal **modal);

/* menu callback */
static int __openMenuCb(void *user);
static int __openFileCb(void *user);
static int __rwCb(void *user);
static int __debuggerCb(void *user);
static int __decompiler_cb(void *user);
static int __loadLayoutSavedCb(void *user);
static int __loadLayoutDefaultCb(void *user);
static int __closeFileCb(void *user);
static int __saveLayoutCb(void *user);
static int __clearLayoutsCb(void *user);
static int __copyCb(void *user);
static int __pasteCb(void *user);
static int __writeStrCb(void *user);
static int __writeHexCb(void *user);
static int __assembleCb(void *user);
static int __fillCb(void *user);
static int __colorsCb(void *user);
static int __config_toggle_cb(void *user);
static int __config_value_cb(void *user);
static int __calculatorCb(void *user);
static int __r2shellCb(void *user);
static int __systemShellCb(void *user);
static int __string_whole_bin_Cb(void *user);
static int __string_data_sec_Cb(void *user);
static int __ropCb(void *user);
static int __codeCb(void *user);
static int __hexpairsCb(void *user);
static int __continueCb(void *user);
static int __esil_init_cb(void *user);
static int __esil_step_to_cb(void *user);
static int __esil_step_range_cb(void *user);
static int __stepCb(void *user);
static int __stepoverCb(void *user);
static int __reloadCb(void *user);
static int __functionCb(void *user);
static int __symbolsCb(void *user);
static int __programCb(void *user);
static int __basicblocksCb(void *user);
static int __callsCb(void *user);
static int __breakpointsCb(void *user);
static int __watchpointsCb(void *user);
static int __referencesCb(void *user);
static int __helpCb(void *user);
static int __fortuneCb(void *user);
static int __gameCb(void *user);
static int __licenseCb(void *user);
static int __versionCb(void *user);
static int __quitCb(void *user);
static int __ioCacheOnCb(void *user);
static int __ioCacheOffCb(void *user);
static char *__get_name_cb (R_NULLABLE void *user, char *base_name);
static char *__get_config_name_cb (R_NULLABLE void *user, char *base_name);

/* direction callback */
static void __directionDefaultCb(void *user, int direction);
static void __directionDisassemblyCb(void *user, int direction);
static void __directionGraphCb(void *user, int direction);
static void __directionRegisterCb(void *user, int direction);
static void __directionStackCb(void *user, int direction);
static void __directionHexdumpCb(void *user, int direction);
static void __direction_panels_cursor_cb(void *user, int direction);

/* rotate callback */
static void __rotateDisasCb(void *user, bool rev);
static void __rotateEntropyVCb(void *user, bool rev);
static void __rotateEntropyHCb(void *user, bool rev);
static void __rotateHexdumpCb (void *user, bool rev);
static void __rotateRegisterCb (void *user, bool rev);
static void __rotateFunctionCb (void *user, bool rev);

/* print callback */
static char *__print_default_cb(void *user, void *p);
static char *__print_decompiler_cb(void *user, void *p);
static char *__print_disassembly_cb(void *user, void *p);
static char *__print_disasmsummary_cb (void *user, void *p);
static char *__print_graph_cb(void *user, void *p);
static char *__print_stack_cb(void *user, void *p);
static char *__print_hexdump_cb(void *user, void *p);

/* almighty callback */
static void __create_panel(RCore *core, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char* title, const char *cmd);
static void __create_panel_db(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title);
static void __create_panel_input(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title);
static void __search_strings_data_create(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title);
static void __search_strings_bin_create(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title);
static char *__search_strings (RCore *core, bool whole);
static void __put_breakpoints_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED R_NULLABLE const char *title);
static void __continue_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED R_NULLABLE const char *title);
static void __step_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED R_NULLABLE const char *title);
static void __step_over_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED R_NULLABLE const char *title);

/* menu */
static void __del_menu(RCore *core);
static void __clearPanelsMenu(RCore *core);
static void __clearPanelsMenuRec(RPanelsMenuItem *pmi);
static RStrBuf *__drawMenu(RCore *core, RPanelsMenuItem *item);
static void __moveMenuCursor(RCore *core, RPanelsMenu *menu, RPanelsMenuItem *parent);
static void __handleMenu(RCore *core, const int key);

/* config */
static char *__getPanelsConfigPath();
static void __load_config_menu(RCore *core);
static char *__parsePanelsConfig(const char *cfg, int len);

/* history */
static int __file_history_up(RLine *line);
static int __file_history_down(RLine *line);

/* hud */
static void __hudstuff(RCore *core);

/* esil */
static void __esil_init(RCore *core);
static void __esil_step_to(RCore *core, ut64 end);

/* debug */
static void __panelBreakpoint(RCore *core);
static void __panelSingleStepIn(RCore *core);
static void __panelSingleStepOver(RCore *core);
static void __panelContinue(RCore *core);

/* zoom mode */
static void __savePanelPos(RPanel* panel);
static void __restorePanelPos(RPanel* panel);
static void __maximizePanelSize(RPanels *panels);

/* tab */
static void __handle_tab(RCore *core);
static void __handle_tab_nth(RCore *core, int ch);
static void __handle_tab_next(RCore *core);
static void __handle_tab_prev(RCore *core);
static void __handle_tab_name(RCore *core);
static void __handle_tab_new(RCore *core);
static void __handle_tab_new_with_cur_panel(RCore *core);
static void __del_panels(RCore *core);

/* hobby */
static void __printSnow(RPanels *panels);
static void __resetSnow(RPanels *panels);

/* other */
static void __panels_process(RCore *core, RPanels *panels);
static bool __handle_console(RCore *core, RPanel *panel, const int key);
static void __toggleCache (RCore *core, RPanel *p);
static bool __moveToDirection(RCore *core, Direction direction);
static void __toggleHelp(RCore *core);
static void __checkEdge(RPanels *panels);
static void __callVisualGraph(RCore *core);
static void __refreshCoreOffset (RCore *core);
static char *__search_db(RCore *core, const char *title);
static void __handle_visual_mark(RCore *core);
static void __fitToCanvas(RPanels *panels);
static void __handleTabKey(RCore *core, bool shift);
static void __handle_refs(RCore *core, RPanel *panel, ut64 tmp);
static void __undoSeek(RCore *core);
static void __redoSeek(RCore *core);


char *__search_db(RCore *core, const char *title) {
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

int __show_status(RCore *core, const char *msg) {
	r_cons_gotoxy (0, 0);
	r_cons_printf (R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, core->cons->context->pal.graph_box2, msg);
	r_cons_flush ();
	return r_cons_readchar ();
}

bool __show_status_yesno(RCore *core, int def, const char *msg) {
	r_cons_gotoxy (0, 0);
	r_cons_flush ();
	return r_cons_yesno (def, R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, core->cons->context->pal.graph_box2, msg);
}

char *__show_status_input(RCore *core, const char *msg) {
	char *n_msg = r_str_newf (R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, core->cons->context->pal.graph_box2, msg);
	r_cons_gotoxy (0, 0);
	r_cons_flush ();
	char *out = r_cons_input (n_msg);
	free (n_msg);
	return out;
}

bool __check_panel_type(RPanel *panel, const char *type, int len) {
	if (!panel->model->cmd || !type) {
		return false;
	}
	if (!strcmp (type, PANEL_CMD_DISASSEMBLY)) {
		if (!strncmp (panel->model->cmd, type, len) &&
				strcmp (panel->model->cmd, PANEL_CMD_DECOMPILER) &&
				strcmp (panel->model->cmd, PANEL_CMD_DISASMSUMMARY)) {
			return true;
		}
		return false;
	}
	return !strncmp (panel->model->cmd, type, len);
}

bool __check_root_state(RCore *core, RPanelsRootState state) {
	return core->panels_root->root_state == state;
}

//TODO: Refactroing
bool __is_abnormal_cursor_type(RCore *core, RPanel *panel) {
	char *str;
	if (__check_panel_type (panel, PANEL_CMD_SYMBOLS, strlen (PANEL_CMD_SYMBOLS)) ||
			__check_panel_type (panel, PANEL_CMD_FUNCTION, strlen (PANEL_CMD_FUNCTION))) {
		return true;
	}
	str = __search_db (core, PANEL_TITLE_DISASMSUMMARY);
	if (str && __check_panel_type (panel, __search_db (core, PANEL_TITLE_DISASMSUMMARY), strlen (__search_db (core, PANEL_TITLE_DISASMSUMMARY)))) {
		return true;
	}
	str = __search_db (core, PANEL_TITLE_STRINGS_DATA);
	if (str && __check_panel_type (panel, __search_db (core, PANEL_TITLE_STRINGS_DATA), strlen (__search_db (core, PANEL_TITLE_STRINGS_DATA)))) {
		return true;
	}
	str = __search_db (core, PANEL_TITLE_STRINGS_BIN);
	if (str && __check_panel_type (panel, __search_db (core, PANEL_TITLE_STRINGS_BIN), strlen (__search_db (core, PANEL_TITLE_STRINGS_BIN)))) {
		return true;
	}
	str = __search_db (core, PANEL_TITLE_BREAKPOINTS);
	if (str && __check_panel_type (panel, __search_db (core, PANEL_TITLE_BREAKPOINTS), strlen (__search_db (core, PANEL_TITLE_BREAKPOINTS)))) {
		return true;
	}
	str = __search_db (core, PANEL_TITLE_SECTIONS);
	if (str && __check_panel_type (panel, __search_db (core, PANEL_TITLE_SECTIONS), strlen (__search_db (core, PANEL_TITLE_SECTIONS)))) {
		return true;
	}
	str = __search_db (core, PANEL_TITLE_SEGMENTS);
	if (str && __check_panel_type (panel, __search_db (core, PANEL_TITLE_SEGMENTS), strlen (__search_db (core, PANEL_TITLE_SEGMENTS)))) {
		return true;
	}
	return false;
}

bool __is_normal_cursor_type(RPanel *panel) {
	if (__check_panel_type (panel, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK)) ||
			__check_panel_type (panel, PANEL_CMD_REGISTERS, strlen (PANEL_CMD_REGISTERS)) ||
			__check_panel_type (panel, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY)) ||
			__check_panel_type (panel, PANEL_CMD_HEXDUMP, strlen (PANEL_CMD_HEXDUMP))) {
		return true;
	}
	return false;
}

void __setCmdStrCache(RCore *core, RPanel *p, char *s) {
	free (p->model->cmdStrCache);
	p->model->cmdStrCache = s;
	__setdcb (core, p);
	__setpcb (p);
}

void __setReadOnly(RPanel *p, char *s) {
	free (p->model->readOnly);
	p->model->readOnly = s;
}

void __set_pos(RPanelPos *pos, int x, int y) {
	pos->x = x;
	pos->y = y;
}

void __set_size(RPanelPos *pos, int w, int h) {
	pos->w = w;
	pos->h = h;
}

void __set_geometry(RPanelPos *pos, int x, int y, int w, int h) {
	__set_pos (pos, x, y);
	__set_size (pos, w, h);
}

void __set_panel_addr(RCore *core, RPanel *panel, ut64 addr) {
	panel->model->addr = addr;
	if (core->panels->autoUpdate) {
		__setRefreshAll (core, false, false);
		return;
	}
	panel->view->refresh = true;
}

RPanel *__getPanel(RPanels *panels, int i) {
	if (!panels || (i >= PANEL_NUM_LIMIT)) {
		return NULL;
	}
	return panels->panel[i];
}

RPanel *__getCurPanel(RPanels *panels) {
	return __getPanel (panels, panels->curnode);
}

void __handlePrompt(RCore *core, RPanels *panels) {
	r_core_visual_prompt_input (core);
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __getPanel (panels, i);
		if (__check_panel_type (p, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			__set_panel_addr (core, p, core->offset);
			break;
		}
	}
	__setRefreshAll (core, false, false);
}

void __panelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int color) {
	if (!can || !panel|| !panel->view->refresh) {
		return;
	}

	if (can->w <= panel->view->pos.x || can->h <= panel->view->pos.y) {
		return;
	}
	panel->view->refresh = false;
	r_cons_canvas_fill (can, panel->view->pos.x, panel->view->pos.y, panel->view->pos.w, panel->view->pos.h, ' ');
	if (panel->model->type == PANEL_TYPE_MENU) {
		__menuPanelPrint (can, panel, panel->view->sx, panel->view->sy, panel->view->pos.w, panel->view->pos.h);
	} else {
		__defaultPanelPrint (core, can, panel, panel->view->pos.w, panel->view->pos.h, color);
	}
	if (color) {
		r_cons_canvas_box (can, panel->view->pos.x, panel->view->pos.y, panel->view->pos.w, panel->view->pos.h, core->cons->context->pal.graph_box2);
	} else {
		r_cons_canvas_box (can, panel->view->pos.x, panel->view->pos.y, panel->view->pos.w, panel->view->pos.h, core->cons->context->pal.graph_box);
	}
}

void __menuPanelPrint(RConsCanvas *can, RPanel *panel, int x, int y, int w, int h) {
	(void) r_cons_canvas_gotoxy (can, panel->view->pos.x + 2, panel->view->pos.y + 2);
	char *text = r_str_ansi_crop (panel->model->title, x, y, w, h);
	if (text) {
		r_cons_canvas_write (can, text);
		free (text);
	} else {
		r_cons_canvas_write (can, panel->model->title);
	}
}

void __defaultPanelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int w, int h, int color) {
	char title[128], cache_title[128], *text, *cmdStr = NULL;
	char *readOnly = panel->model->readOnly;
	char *cmd_title  = __apply_filter_cmd (core, panel);
	int graph_pad = __check_panel_type (panel, PANEL_CMD_GRAPH, strlen (PANEL_CMD_GRAPH)) ? 1 : 0;
	bool o_cur = core->print->cur_enabled;
	core->print->cur_enabled = o_cur & (__getCurPanel (core->panels) == panel);
	(void) r_cons_canvas_gotoxy (can, panel->view->pos.x + 2, panel->view->pos.y + 2);
	if (readOnly) {
		cmdStr = readOnly;
	} else {
		if (panel->model->cmd) {
			cmdStr = panel->model->print_cb (core, panel);
		}
	}
	int x = panel->view->sx;
	int y = panel->view->sy;
	if (y < 0) {
		y = 0;
	}
	bool b = __is_abnormal_cursor_type (core, panel) && core->print->cur_enabled;
	if (b) {
		x = -2;
	}
	if (x < 0) {
		char *white = (char*)r_str_pad (' ', 128);
		int idx = R_MIN (-x, strlen (white) - 1);
		white[idx] = 0;
		text = r_str_ansi_crop (cmdStr,
				0, y + graph_pad, w + x - 3, h - 2 + y);
		char *newText = r_str_prefix_all (text, white);
		if (newText) {
			free (text);
			text = newText;
		}
	} else {
		text = r_str_ansi_crop (cmdStr,
				x, y + graph_pad, w + x - 3, h - 2 + y);
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
	if (!panel->model->cmdStrCache && !readOnly) {
		free (cmdStr);
	}
	if (color) {
		if (!strcmp (panel->model->title, cmd_title)) {
			snprintf (title, sizeof (title) - 1,
					"%s[X] %s"Color_RESET, core->cons->context->pal.graph_box2, panel->model->title);
		}  else {
			snprintf (title, sizeof (title) - 1,
					"%s[X] %s (%s)"Color_RESET, core->cons->context->pal.graph_box2, panel->model->title, cmd_title);
		}
		snprintf (cache_title, sizeof (cache_title) - 1,
				"%s[Cache] %s"Color_RESET, core->cons->context->pal.graph_box2, readOnly ? "N/A" : panel->model->cache ? "On" : "Off");
	} else {
		if (!strcmp (panel->model->title, cmd_title)) {
			snprintf (title, sizeof (title) - 1,
					"   %s   ", panel->model->title);
		} else {
			snprintf (title, sizeof (title) - 1,
					"   %s (%s)  ", panel->model->title, cmd_title);
		}
		snprintf (cache_title, sizeof (cache_title) - 1,
				"[Cache] %s", readOnly ? "N/A" : panel->model->cache ? "On" : "Off");
	}
	free (cmd_title);
	if (r_cons_canvas_gotoxy (can, panel->view->pos.x + 1, panel->view->pos.y + 1)) {
		r_cons_canvas_write (can, title);
	}
	if (r_cons_canvas_gotoxy (can, panel->view->pos.x + panel->view->pos.w - r_str_ansi_len (cache_title) - 2, panel->view->pos.y + 1)) {
		r_cons_canvas_write (can, cache_title);
	}
	core->print->cur_enabled = o_cur;
}

void __resetScrollPos(RPanel *p) {
	p->view->sx = 0;
	p->view->sy = 0;
}

char *__findCmdStrCache(RCore *core, RPanel* panel) {
	if (panel->model->cache && panel->model->cmdStrCache) {
		return panel->model->cmdStrCache;
	}
	return NULL;
}

char *__apply_filter_cmd(RCore *core, RPanel *panel) {
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

char *__handleCmdStrCache(RCore *core, RPanel *panel, bool force_cache) {
	char *out;
	char *cmd = __apply_filter_cmd (core, panel);
	bool b = core->print->cur_enabled && __getCurPanel (core->panels) != panel;
	if (b) {
		core->print->cur_enabled = false;
	}
	out = r_core_cmd_str (core, cmd);
	if (force_cache) {
		panel->model->cache = true;
	}
	if (R_STR_ISNOTEMPTY (out)) {
		__setCmdStrCache (core, panel, out);
	}
	free (cmd);
	if (b) {
		core->print->cur_enabled = true;
	}
	return out;
}

void __panelAllClear(RPanels *panels) {
	if (!panels) {
		return;
	}
	int i;
	RPanel *panel = NULL;
	for (i = 0; i < panels->n_panels; i++) {
		panel = __getPanel (panels, i);
		r_cons_canvas_fill (panels->can, panel->view->pos.x, panel->view->pos.y, panel->view->pos.w, panel->view->pos.h, ' ');
	}
	r_cons_canvas_print (panels->can);
	r_cons_flush ();
}

void __panels_layout (RPanels *panels) {
	panels->can->sx = 0;
	panels->can->sy = 0;
	__layoutDefault (panels);
}

void __layoutDefault(RPanels *panels) {
	int h, w = r_cons_get_size (&h);
	int ph = (h - 1) / (panels->n_panels - 1);
	int i;
	int colpos = w - panels->columnWidth;
	RPanel *p0 = __getPanel (panels, 0);
	if (panels->n_panels <= 1) {
		__set_geometry (&p0->view->pos, 0, 1, w, h - 1);
		return;
	}
	__set_geometry (&p0->view->pos, 0, 1, colpos + 1, h - 1);

	int pos_x = p0->view->pos.x + p0->view->pos.w - 1;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *p = __getPanel (panels, i);
		int tmp_w = R_MAX (w - colpos, 0);
		int tmp_h = (i + 1) == panels->n_panels ? h - p->view->pos.y : ph;
		__set_geometry(&p->view->pos, pos_x, 2 + (ph * (i - 1)) - 1, tmp_w, tmp_h + 1);
	}
}

void __adjustSidePanels(RCore *core) {
	int i, h;
	(void)r_cons_get_size (&h);
	RPanels *panels = core->panels;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __getPanel (panels, i);
		if (p->view->pos.x == 0) {
			if (p->view->pos.w >= PANEL_CONFIG_SIDEPANEL_W) {
				p->view->pos.x += PANEL_CONFIG_SIDEPANEL_W - 1;
				p->view->pos.w -= PANEL_CONFIG_SIDEPANEL_W - 1;
			}
		}
	}
}

int __addCmdPanel(void *user) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	if (!__checkPanelNum (core)) {
		return 0;
	}
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	const char *cmd = __search_db (core, child->get_name_cb (core, child->base_name));
	if (!cmd) {
		return 0;
	}
	int h;
	(void)r_cons_get_size (&h);
	bool cache = __show_status_yesno (core, 'y', "Cache the result? (Y/n) ");
	__adjustSidePanels (core);
	__insertPanel (core, 0, child->base_name, cmd, cache);
	RPanel *p0 = __getPanel (panels, 0);
	__set_geometry (&p0->view->pos, 0, 1, PANEL_CONFIG_SIDEPANEL_W, h - 1);
	__set_curnode (core, 0);
	__setRefreshAll (core, false, false);
	__setMode (core, PANEL_MODE_DEFAULT);
	return 0;
}

void __addHelpPanel(RCore *core) {
	//TODO: all these things done below are very hacky and refactoring needed
	RPanels *ps = core->panels;
	int h;
	const char *help = "Help";
	(void)r_cons_get_size (&h);
	__adjustSidePanels (core);
	__insertPanel (core, 0, help, help, true);
	RPanel *p0 = __getPanel (ps, 0);
	__set_geometry (&p0->view->pos, 0, 1, PANEL_CONFIG_SIDEPANEL_W, h - 1);
	__set_curnode (core, 0);
	__setRefreshAll (core, false, false);
}

char *__loadCmdf(RCore *core, RPanel *p, char *input, char *str) {
	char *ret = NULL;
	char *res = __show_status_input (core, input);
	if (res) {
		p->model->cmd = r_str_newf (str, res);
		ret = r_core_cmd_str (core, p->model->cmd);
		free (res);
	}
	return ret;
}

int __addCmdfPanel(RCore *core, char *input, char *str) {
	RPanels *panels = core->panels;
	if (!__checkPanelNum (core)) {
		return 0;
	}
	int h;
	(void)r_cons_get_size (&h);
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	__adjustSidePanels (core);
	__insertPanel (core, 0, child->get_name_cb (core, child->base_name), "", true);
	RPanel *p0 = __getPanel (panels, 0);
	__set_geometry (&p0->view->pos, 0, 1, PANEL_CONFIG_SIDEPANEL_W, h - 1);
	__setCmdStrCache (core, p0, __loadCmdf (core, p0, input, str));
	__set_curnode (core, 0);
	__setRefreshAll (core, false, false);
	__setMode (core, PANEL_MODE_DEFAULT);
	return 0;
}

void __splitPanelVertical(RCore *core, RPanel *p, const char *name, const char *cmd, bool cache) {
	RPanels *panels = core->panels;
	if (!__checkPanelNum (core)) {
		return;
	}
	__insertPanel (core, panels->curnode + 1, name, cmd, cache);
	RPanel *next = __getPanel (panels, panels->curnode + 1);
	int owidth = p->view->pos.w;
	p->view->pos.w = owidth / 2 + 1;
	__set_geometry (&next->view->pos, p->view->pos.x + p->view->pos.w - 1,
			p->view->pos.y, owidth - p->view->pos.w + 1, p->view->pos.h);
	__setRefreshAll (core, false, false);
}

void __splitPanelHorizontal(RCore *core, RPanel *p, const char *name, const char *cmd, bool cache) {
	RPanels *panels = core->panels;
	if (!__checkPanelNum (core)) {
		return;
	}
	__insertPanel (core, panels->curnode + 1, name, cmd, cache);
	RPanel *next = __getPanel (panels, panels->curnode + 1);
	int oheight = p->view->pos.h;
	p->view->curpos = 0;
	p->view->pos.h = oheight / 2 + 1;
	__set_geometry (&next->view->pos, p->view->pos.x, p->view->pos.y + p->view->pos.h - 1,
			p->view->pos.w, oheight - p->view->pos.h + 1);
	__setRefreshAll (core, false, false);
}

void __panels_layout_refresh(RCore *core) {
	__delInvalidPanels (core);
	__checkEdge (core->panels);
	__panels_check_stackbase (core);
	__panels_refresh (core);
}

void __insertPanel(RCore *core, int n, const char *name, const char *cmd, bool cache) {
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
	__init_panel_param (core, panel[n], name, cmd, cache);
}

void __setCursor(RCore *core, bool cur) {
	RPanel *p = __getCurPanel (core->panels);
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

void __activateCursor(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	if (__is_normal_cursor_type (cur) || __is_abnormal_cursor_type (core, cur)) {
		if (cur->model->cache) {
			if (__show_status_yesno (core, 'y', "You need to turn off cache to use cursor. Turn off now?(Y/n)")) {
				cur->model->cache = false;
				__setCmdStrCache (core, cur, NULL);
				(void)__show_status (core, "Cache is off and cursor is on");
				__setCursor (core, !core->print->cur_enabled);
				cur->view->refresh = true;
				__resetScrollPos (cur);
			} else {
				(void)__show_status (core, "You can always toggle cache by \'&\' key");
			}
			return;
		}
		__setCursor (core, !core->print->cur_enabled);
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
			return r_num_math (core->num, r_strbuf_drain (buf));
		}
		s++;
	}
	return UT64_MAX;
}

void __cursorLeft(RCore *core) {
	RPanel *cur = __getCurPanel (core->panels);
	RPrint *print = core->print;
	if (__check_panel_type (cur, PANEL_CMD_REGISTERS, strlen (PANEL_CMD_REGISTERS))
			|| __check_panel_type (cur, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK))) {
		if (print->cur > 0) {
			print->cur--;
			cur->model->addr--;
		}
	} else if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		print->cur--;
		__fix_cursor_up (core);
	} else {
		print->cur--;
	}
}

void __cursorRight(RCore *core) {
	RPanel *cur = __getCurPanel (core->panels);
	RPrint *print = core->print;
	if (__check_panel_type (cur, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK)) && print->cur >= 15) {
		return;
	}
	if (__check_panel_type (cur, PANEL_CMD_REGISTERS, strlen (PANEL_CMD_REGISTERS))
			|| __check_panel_type (cur, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK))) {
		print->cur++;
		cur->model->addr++;
	} else if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		print->cur++;
		__fix_cursor_down (core);
	} else {
		print->cur++;
	}
}


void __cursorUp(RCore *core) {
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

void __cursorDown(RCore *core) {
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

void __fix_cursor_up(RCore *core) {
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

void __fix_cursor_down(RCore *core) {
	RPrint *print = core->print;
	bool cur_is_visible = core->offset + print->cur + 32 < print->screen_bounds;
	if (!cur_is_visible) {
		int i = 0;
		//XXX: ugly hack
		for (i = 0; i < 2; i++) {
			RAsmOp op;
			int sz = r_asm_disassemble (core->assembler,
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

bool __handleZoomMode(RCore *core, const int key) {
	RPanels *panels = core->panels;
	r_cons_switchbuf (false);
	switch (key) {
	case 'Q':
	case 'q':
	case 0x0d:
		__toggleZoomMode (core);
		break;
	case 'c':
	case 'C':
	case ';':
	case ' ':
	case '"':
	case 'b':
	case 'd':
	case 'n':
	case 'N':
	case 'g':
	case 'h':
	case 'j':
	case 'k':
	case 'l':
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
		__restorePanelPos (panels->panel[panels->curnode]);
		__handleTabKey (core, false);
		__savePanelPos (panels->panel[panels->curnode]);
		__maximizePanelSize (panels);
		break;
	case 'Z':
		__restorePanelPos (panels->panel[panels->curnode]);
		__handleTabKey (core, true);
		__savePanelPos (panels->panel[panels->curnode]);
		__maximizePanelSize (panels);
		break;
	case '?':
		__toggleZoomMode (core);
		__toggleHelp (core);
		__toggleZoomMode (core);
		break;
	}
	return true;
}

void __handleComment(RCore *core) {
	RPanel *p = __getCurPanel (core->panels);
	if (!__check_panel_type (p, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		return;
	}
	char buf[4095];
	int i;
	r_line_set_prompt ("[Comment]> ");
	strcpy (buf, "\"CC ");
	i = strlen (buf);
	if (r_cons_fgets (buf + i, sizeof (buf) - i - 1, 0, NULL) > 0) {
		ut64 addr, orig;
		addr = orig = core->offset;
		if (core->print->cur_enabled) {
			addr += core->print->cur;
			r_core_seek (core, addr, 0);
			r_core_cmdf (core, "s 0x%"PFMT64x, addr);
		}
		if (!strcmp (buf + i, "-")) {
			strcpy (buf, "CC-");
		} else {
			switch (buf[i]) {
				case '-':
					memcpy (buf, "\"CC-\x00", 5);
					break;
				case '!':
					memcpy (buf, "\"CC!\x00", 5);
					break;
				default:
					memcpy (buf, "\"CC ", 4);
					break;
			}
			strcat (buf, "\"");
		}
		if (buf[3] == ' ') {
			int j, len = strlen (buf);
			char *duped = strdup (buf);
			for (i = 4, j = 4; i < len; ++i,++j) {
				char c = duped[i];
				if (c == '"' && i != (len - 1)) {
					buf[j] = '\\';
					j++;
					buf[j] = '"';
				} else {
					buf[j] = c;
				}
			}
			free (duped);
		}
		r_core_cmd (core, buf, 1);
		if (core->print->cur_enabled) {
			r_core_seek (core, orig, 1);
		}
	}
	__setRefreshByType (core, p->model->cmd, true);
}

bool __handleWindowMode(RCore *core, const int key) {
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	r_cons_switchbuf (false);
	switch (key) {
	case 'Q':
	case 'q':
	case 'w':
		__toggleWindowMode (core);
		break;
	case 0x0d:
		__toggleZoomMode (core);
		break;
	case 9: // tab
		__handleTabKey (core, false);
		break;
	case 'Z': // shift-tab
		__handleTabKey (core, true);
		break;
	case 'h':
		if (__moveToDirection (core, LEFT)) {
			__setRefreshAll (core, false, false);
		}
		if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
			__resetSnow (panels);
		}
		break;
	case 'j':
		if (__moveToDirection (core, DOWN)) {
			__setRefreshAll (core, false, false);
		}
		if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
			__resetSnow (panels);
		}
		break;
	case 'k':
		if (__moveToDirection (core, UP)) {
			__setRefreshAll (core, false, false);
		}
		if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
			__resetSnow (panels);
		}
		break;
	case 'l':
		if (__moveToDirection (core, RIGHT)) {
			__setRefreshAll (core, false, false);
		}
		if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
			__resetSnow (panels);
		}
		break;
	case 'H':
		r_cons_switchbuf (false);
		__resizePanelLeft (panels);
		break;
	case 'L':
		r_cons_switchbuf (false);
		__resizePanelRight (panels);
		break;
	case 'J':
		r_cons_switchbuf (false);
		__resizePanelDown (panels);
		break;
	case 'K':
		r_cons_switchbuf (false);
		__resizePanelUp (panels);
		break;
	case 'n':
		__create_panel_input (core, cur, VERTICAL, NULL);
		break;
	case 'N':
		__create_panel_input (core, cur, HORIZONTAL, NULL);
		break;
	case 'X':
		__dismantleDelPanel (core, cur, panels->curnode);
		__setRefreshAll (core, false, false);
		break;
	case '"':
	case ':':
	case ';':
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

bool __handleCursorMode(RCore *core, const int key) {
	RPanel *cur = __getCurPanel (core->panels);
	RPrint *print = core->print;
	switch (key) {
	case ':':
	case ';':
	case 'd':
	case 'h':
	case 'j':
	case 'k':
	case 'l':
	case 'm':
	case 'Z':
	case '"':
	case 9:
		return false;
	case 'Q':
	case 'q':
	case 'c':
		__setCursor (core, !print->cur_enabled);
		cur->view->refresh = true;
		break;
	case 'w':
		__toggleWindowMode (core);
		__setCursor (core, false);
		cur->view->refresh = true;
		break;
	case 'i':
		__insertValue (core);
		break;
	case '*':
		if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			r_core_cmdf (core, "dr PC=0x%08"PFMT64x, core->offset + print->cur);
			__set_panel_addr (core, cur, core->offset + print->cur);
		}
		break;
	case '-':
		if (__check_panel_type (cur, __search_db (core, "Breakpoints"), strlen (__search_db (core, "Breakpoints")))) {
			__cursor_del_breakpoints(core, cur);
			break;
		}
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
	}
	return true;
}

void __jmp_to_cursor_addr(RCore *core, RPanel *panel) {
	ut64 addr = __parse_string_on_cursor (core, panel, panel->view->curpos);
	if (addr == UT64_MAX) {
		return;
	}
	core->offset = addr;
	__update_disassembly_or_open (core);
}

void __cursor_del_breakpoints(RCore *core, RPanel *panel) {
	RListIter *iter;
	RBreakpointItem *b;
	int i = 0;
	r_list_foreach (core->dbg->bp->bps, iter, b) {
		if (panel->view->curpos == i++) {
			r_bp_del(core->dbg->bp, b->addr);
			__setRefreshAll (core, false, false);
		}
	}
}

void __handle_visual_mark(RCore *core) {
	RPanel *cur = __getCurPanel (core->panels);
	if (!__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
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
	return;
}

void __handle_refs(RCore *core, RPanel *panel, ut64 tmp) {
	if (tmp != UT64_MAX) {
		core->offset = tmp;
	}
	int key = __show_status(core, "xrefs:x refs:X ");
	switch (key) {
	case 'x':
		(void)r_core_visual_refs(core, true, false);
		break;
	case 'X':
		(void)r_core_visual_refs(core, false, false);
		break;
	default:
		break;
	}
	if (__check_panel_type (panel, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		__set_panel_addr (core, panel, core->offset);
		__setRefreshAll (core, false, false);
		return;
	}
	__setAddrByType (core, PANEL_CMD_DISASSEMBLY, core->offset);
}

void __add_visual_mark(RCore *core) {
	char *msg = r_str_newf (R_CONS_CLEAR_LINE"Set shortcut key for 0x%"PFMT64x": ", core->offset);
	int ch = __show_status (core, msg);
	free (msg);
	r_core_visual_mark (core, ch);
}

void __resizePanelLeft(RPanels *panels) {
	RPanel *cur = __getCurPanel (panels);
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
		RPanel *p = __getPanel (panels, i);
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

void __resizePanelRight(RPanels *panels) {
	RPanel *cur = __getCurPanel (panels);
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
		RPanel *p = __getPanel (panels, i);
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

void __resizePanelUp(RPanels *panels) {
	RPanel *cur = __getCurPanel (panels);
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
		RPanel *p = __getPanel (panels, i);
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

void __resizePanelDown(RPanels *panels) {
	RPanel *cur = __getCurPanel (panels);
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
		RPanel *p = __getPanel (panels, i);
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

void __checkEdge(RPanels *panels) {
	int i, tmpright, tmpbottom, maxright = 0, maxbottom = 0;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = __getPanel (panels, i);
		if (!panel) {
			continue;
		}
		tmpright = panel->view->pos.x + panel->view->pos.w;
		tmpbottom = panel->view->pos.y + panel->view->pos.h;
		if (tmpright > maxright) {
			maxright = tmpright;
		}
		if (tmpbottom > maxbottom) {
			maxbottom = tmpbottom;
		}
	}
	int f1, f2;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = __getPanel (panels, i);
		if (!panel) {
			continue;
		}
		f1 = f2 = 0;
		if (panel->view->pos.x + panel->view->pos.w == maxright) {
			f1 = (1 << PANEL_EDGE_RIGHT);
		}
		if (panel->view->pos.y + panel->view->pos.h == maxbottom) {
			f2 = (1 << PANEL_EDGE_BOTTOM);
		}
		panel->view->edgeflag = f1 | f2;
	}
}

void __fitToCanvas(RPanels *panels) {
	RConsCanvas *can = panels->can;
	int i, w, h;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = __getPanel (panels, i);
		if (!panel) {
			continue;
		}
		if (panel->view->edgeflag & 1 << PANEL_EDGE_RIGHT && panel->view->pos.x < can->w) {
			w = can->w - panel->view->pos.x;
			if (w != panel->view->pos.w) {
				panel->view->pos.w = w;
				panel->view->refresh = true;
			}
		}
		if (panel->view->edgeflag & 1 << PANEL_EDGE_BOTTOM && panel->view->pos.y < can->h) {
			h = can->h - panel->view->pos.y;
			if (h != panel->view->pos.h) {
				panel->view->pos.h = h;
				panel->view->refresh = true;
			}
		}
	}
}

void __delPanel(RCore *core, int pi) {
	int i;
	RPanels *panels = core->panels;
	RPanel *tmp = __getPanel (panels, pi);
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

void __dismantleDelPanel(RCore *core, RPanel *p, int pi) {
	RPanels *panels = core->panels;
	if (panels->n_panels <= 1) {
		return;
	}
	__dismantlePanel (panels, p);
	__delPanel (core, pi);
}

void __delInvalidPanels(RCore *core) {
	RPanels *panels = core->panels;
	int i;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *panel = __getPanel (panels, i);
		if (panel->view->pos.w < 2) {
			__delPanel (core, i);
			__delInvalidPanels (core);
			break;
		}
		if (panel->view->pos.h < 2) {
			__delPanel (core, i);
			__delInvalidPanels (core);
			break;
		}
	}
}

void __dismantlePanel(RPanels *ps, RPanel *p) {
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
		tmpPanel = __getPanel (ps, i);
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
				tmpPanel = __getPanel (ps, i);
				tmpPanel->view->pos.w += ox + ow - (tmpPanel->view->pos.x + tmpPanel->view->pos.w);
			}
		}
	} else if (rightUpValid && rightDownValid) {
		for (i = 0; i < ps->n_panels; i++) {
			if (right[i] != -1) {
				tmpPanel = __getPanel (ps, i);
				tmpPanel->view->pos.w = tmpPanel->view->pos.x + tmpPanel->view->pos.w - ox;
				tmpPanel->view->pos.x = ox;
			}
		}
	} else if (upLeftValid && upRightValid) {
		for (i = 0; i < ps->n_panels; i++) {
			if (up[i] != -1) {
				tmpPanel = __getPanel (ps, i);
				tmpPanel->view->pos.h += oy + oh - (tmpPanel->view->pos.y + tmpPanel->view->pos.h);
			}
		}
	} else if (downLeftValid && downRightValid) {
		for (i = 0; i < ps->n_panels; i++) {
			if (down[i] != -1) {
				tmpPanel = __getPanel (ps, i);
				tmpPanel->view->pos.h = oh + tmpPanel->view->pos.y + tmpPanel->view->pos.h - (oy + oh);
				tmpPanel->view->pos.y = oy;
			}
		}
	}
}

void __replaceCmd(RCore *core, const char *title, const char *cmd, const bool cache) {
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	__freePanelModel (cur);
	cur->model = R_NEW0 (RPanelModel);
	cur->model->title = r_str_dup (cur->model->title, title);
	cur->model->cmd = r_str_dup (cur->model->cmd, cmd);
	cur->model->cache = cache;
	__setCmdStrCache (core, cur, NULL);
	__set_panel_addr (core, cur, core->offset);
	cur->model->type = PANEL_TYPE_DEFAULT;
	__setdcb (core, cur);
	__setpcb (cur);
	__setrcb (panels, cur);
	__setRefreshAll (core, false, false);
}

void __swapPanels(RPanels *panels, int p0, int p1) {
	RPanel *panel0 = __getPanel (panels, p0);
	RPanel *panel1 = __getPanel (panels, p1);
	RPanelModel *tmp = panel0->model;

	panel0->model = panel1->model;
	panel1->model = tmp;
}

void __callVisualGraph(RCore *core) {
	if (__checkFunc (core)) {
		RPanels *panels = core->panels;

		r_cons_canvas_free (panels->can);
		panels->can = NULL;

		int ocolor = r_config_get_i (core->config, "scr.color");

		r_core_visual_graph (core, NULL, NULL, true);
		r_config_set_i (core->config, "scr.color", ocolor);

		int h, w = r_cons_get_size (&h);
		panels->can = __createNewCanvas (core, w, h);
		__setRefreshAll (core, false, false);
	}
}

bool __checkFunc(RCore *core) {
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

bool __checkFuncDiff(RCore *core, RPanel *p) {
	RAnalFunction *fun = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	if (!fun) {
		if (R_STR_ISEMPTY (p->model->funcName)) {
			return false;
		}
		p->model->funcName = r_str_dup (p->model->funcName, "");
		return true;
	}
	if (!p->model->funcName || strcmp (p->model->funcName, fun->name)) {
		p->model->funcName = r_str_dup (p->model->funcName, fun->name);
		return true;
	}
	return false;
}

void __setRefreshAll(RCore *core, bool clearCache, bool force_refresh) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = __getPanel (panels, i);
		if (!force_refresh && __check_panel_type (panel, PANEL_CMD_CONSOLE, strlen (PANEL_CMD_CONSOLE))) {
			continue;
		}
		panel->view->refresh = true;
		if (clearCache) {
			__setCmdStrCache (core, panel, NULL);
		}
	}
}

void __setRefreshByType(RCore *core, const char *cmd, bool clearCache) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __getPanel (panels, i);
		if (!__check_panel_type (p, cmd, strlen (cmd))) {
			continue;
		}
		p->view->refresh = true;
		if (clearCache) {
			__setCmdStrCache (core, p, NULL);
		}
	}
}

void __setAddrByType(RCore *core, const char *cmd, ut64 addr) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __getPanel (panels, i);
		if (!__check_panel_type (p, cmd, strlen (cmd))) {
			continue;
		}
		__set_panel_addr (core, p, addr);
	}
}

RConsCanvas *__createNewCanvas(RCore *core, int w, int h) {
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

bool __checkPanelNum(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->n_panels + 1 > PANEL_NUM_LIMIT) {
		const char *msg = "panel limit exceeded.";
		(void)__show_status (core, msg);
		return false;
	}
	return true;
}

void __init_panel_param(RCore *core, RPanel *p, const char *title, const char *cmd, bool cache) {
	RPanelModel *m = p->model;
	RPanelView *v = p->view;
	m->cache = cache;
	m->type = PANEL_TYPE_DEFAULT;
	m->rotate = 0;
	v->curpos = 0;
	__set_panel_addr (core, p, core->offset);
	m->rotateCb = NULL;
	__setCmdStrCache (core, p, NULL);
	__setReadOnly(p, NULL);
	m->funcName = NULL;
	v->refresh = true;
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
	__setpcb (p);
	if (R_STR_ISNOTEMPTY (m->cmd)) {
		__setdcb (core, p);
		__setrcb (core->panels, p);
		if (__check_panel_type (p, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK))) {
			const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
			const ut64 stackbase = r_reg_getv (core->anal->reg, sp);
			m->baseAddr = stackbase;
			__set_panel_addr (core, p, stackbase - r_config_get_i (core->config, "stack.delta"));
		}
	}
	core->panels->n_panels++;
	return;
}

void __setdcb(RCore *core, RPanel *p) {
	if (!p->model->cmd) {
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_GRAPH, strlen (PANEL_CMD_GRAPH))) {
		p->model->directionCb = __directionGraphCb;
		return;
	}
	if ((p->model->cache && p->model->cmdStrCache) || p->model->readOnly) {
		p->model->directionCb = __directionDefaultCb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK))) {
		p->model->directionCb = __directionStackCb;
	} else if (__check_panel_type (p, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		p->model->directionCb = __directionDisassemblyCb;
	} else if (__check_panel_type (p, PANEL_CMD_REGISTERS, strlen (PANEL_CMD_REGISTERS))) {
		p->model->directionCb = __directionRegisterCb;
	} else if (__check_panel_type (p, PANEL_CMD_HEXDUMP, strlen (PANEL_CMD_HEXDUMP))) {
		p->model->directionCb = __directionHexdumpCb;
	} else if (__is_abnormal_cursor_type (core, p)) {
		p->model->directionCb = __direction_panels_cursor_cb;
	} else {
		p->model->directionCb = __directionDefaultCb;
	}
}

void __setrcb(RPanels *ps, RPanel *p) {
	SdbKv *kv;
	SdbListIter *sdb_iter;
	SdbList *sdb_list = sdb_foreach_list (ps->rotate_db, false);
	ls_foreach (sdb_list, sdb_iter, kv) {
		char *key =  sdbkv_key (kv);
		if (!__check_panel_type (p, key, strlen (key))) {
			continue;
		}
		p->model->rotateCb = (RPanelRotateCallback)sdb_ptr_get (ps->rotate_db, key, 0);
		break;
	}
	ls_free (sdb_list);
}

void __setpcb(RPanel *p) {
	if (!p->model->cmd) {
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		p->model->print_cb = __print_disassembly_cb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK))) {
		p->model->print_cb = __print_stack_cb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_HEXDUMP, strlen (PANEL_CMD_HEXDUMP))) {
		p->model->print_cb = __print_hexdump_cb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_DECOMPILER, strlen (PANEL_CMD_DECOMPILER))) {
		p->model->print_cb = __print_decompiler_cb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_GRAPH, strlen (PANEL_CMD_GRAPH))) {
		p->model->print_cb = __print_graph_cb;
		return;
	}
	if (__check_panel_type (p, PANEL_CMD_DISASMSUMMARY, strlen (PANEL_CMD_DISASMSUMMARY))) {
		p->model->print_cb = __print_disasmsummary_cb;
		return;
	}
	p->model->print_cb = __print_default_cb;
}

int __openFileCb(void *user) {
	RCore *core = (RCore *)user;
	core->cons->line->prompt_type = R_LINE_PROMPT_FILE;
	r_line_set_hist_callback (core->cons->line, &__file_history_up, &__file_history_down);
	__addCmdfPanel (core, "open file: ", "o %s");
	core->cons->line->prompt_type = R_LINE_PROMPT_DEFAULT;
	r_line_set_hist_callback (core->cons->line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	return 0;
}

int __rwCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "oo+", 0);
	return 0;
}

int __debuggerCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "oo", 0);
	return 0;
}

int __decompiler_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_config_set (core->config, "cmd.pdc", child->get_name_cb (core, child->base_name));
	__setRefreshAll (core, false, false);
	__setMode (core, PANEL_MODE_DEFAULT);
	return 0;
}

int __loadLayoutSavedCb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	if (!__loadSavedPanelsLayout (core, child->get_name_cb (core, child->base_name))) {
		__createDefaultPanels (core);
		__panels_layout (core->panels);
	}
	__set_curnode (core, 0);
	core->panels->panelsMenu->depth = 1;
	__setMode (core, PANEL_MODE_DEFAULT);
	return 0;
}

int __loadLayoutDefaultCb(void *user) {
	RCore *core = (RCore *)user;
	__initPanels (core, core->panels);
	__createDefaultPanels (core);
	__panels_layout (core->panels);
	__setRefreshAll (core, false, false);
	core->panels->panelsMenu->depth = 1;
	__setMode (core, PANEL_MODE_DEFAULT);
	return 0;
}

int __closeFileCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "o-*");
	return 0;
}

int __saveLayoutCb(void *user) {
	RCore *core = (RCore *)user;
	__savePanelsLayout (core);
	(void)__show_status (core, "Panels layout saved!");
	return 0;
}

int __clearLayoutsCb(void *user) {
	__show_status_yesno ((RCore *)user, 'n', "Clear all the saved layouts?(y/n): ");
	r_file_rm (__getPanelsConfigPath ());
	return 0;
}

int __copyCb(void *user) {
	RCore *core = (RCore *)user;
	__addCmdfPanel (core, "How many bytes? ", "\"y %s\"");
	return 0;
}

int __pasteCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "yy");
	return 0;
}

int __writeStrCb(void *user) {
	RCore *core = (RCore *)user;
	__addCmdfPanel (core, "insert string: ", "\"w %s\"");
	return 0;
}

int __writeHexCb(void *user) {
	RCore *core = (RCore *)user;
	__addCmdfPanel (core, "insert hexpairs: ", "\"wx %s\"");
	return 0;
}

int __assembleCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_visual_asm (core, core->offset);
	return 0;
}

int __fillCb(void *user) {
	RCore *core = (RCore *)user;
	__addCmdfPanel (core, "Fill with: ", "wow %s");
	return 0;
}

int __colorsCb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_core_cmdf (core, "eco %s", child->get_name_cb (core, child->base_name));
	__setRefreshAll (core, false, false);
	int i;
	for (i = 1; i < menu->depth; i++) {
		RPanel *p = menu->history[i]->p;
		p->view->refresh = true;
		menu->refreshPanels[menu->n_refresh++] = p;
	}
	return 0;
}

int __config_toggle_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_config_toggle (core->config, child->base_name);
	__setRefreshAll (core, false, false);
	parent->p->model->title = r_strbuf_drain (__drawMenu (core, parent));
	int i;
	for (i = 1; i < menu->depth; i++) {
		RPanel *p = menu->history[i]->p;
		p->view->refresh = true;
		menu->refreshPanels[menu->n_refresh++] = p;
	}
	return 0;
}

int __config_value_cb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	const char *v = __show_status_input (core, "New value: ");
	r_config_set_i (core->config, child->base_name, r_num_math (core->num, v));
	__setRefreshAll (core, false, false);
	parent->p->model->title = r_strbuf_drain (__drawMenu (core, parent));
	int i;
	for (i = 1; i < menu->depth; i++) {
		RPanel *p = menu->history[i]->p;
		p->view->refresh = true;
		menu->refreshPanels[menu->n_refresh++] = p;
	}
	return 0;
}

int __calculatorCb(void *user) {
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

int __r2shellCb(void *user) {
	RCore *core = (RCore *)user;
	core->vmode = false;
	r_core_visual_prompt_input (core);
	core->vmode = true;
	return 0;
}

int __systemShellCb(void *user) {
	r_cons_set_raw (0);
	r_cons_flush ();
	r_sys_cmd ("$SHELL");
	return 0;
}

int __string_whole_bin_Cb(void *user) {
	RCore *core = (RCore *)user;
	__addCmdfPanel (core, "search strings in the whole binary: ", "izzq~%s");
	return 0;
}

int __string_data_sec_Cb(void *user) {
	RCore *core = (RCore *)user;
	__addCmdfPanel (core, "search string in data sections: ", "izq~%s");
	return 0;
}

int __ropCb(void *user) {
	RCore *core = (RCore *)user;
	__addCmdfPanel (core, "rop grep: ", "\"/R %s\"");
	return 0;
}

int __codeCb(void *user) {
	RCore *core = (RCore *)user;
	__addCmdfPanel (core, "search code: ", "\"/c %s\"");
	return 0;
}

int __hexpairsCb(void *user) {
	RCore *core = (RCore *)user;
	__addCmdfPanel (core, "search hexpairs: ", "\"/x %s\"");
	return 0;
}

int __continueCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "dc", 0);
	r_cons_flush ();
	return 0;
}

int __esil_init_cb(void *user) {
	RCore *core = (RCore *)user;
	__esil_init (core);
	__setRefreshAll (core, false, false);
	return 0;
}

int __esil_step_to_cb(void *user) {
	RCore *core = (RCore *)user;
	char *end = __show_status_input (core, "target addr: ");
	__esil_step_to (core, r_num_math (core->num, end));
	__setRefreshAll (core, false, false);
	return 0;
}

int __esil_step_range_cb(void *user) {
	RStrBuf *rsb = r_strbuf_new (NULL);
	RCore *core = (RCore *)user;
	r_strbuf_append (rsb, "start addr: ");
	char *s = __show_status_input (core, r_strbuf_get (rsb));
	r_strbuf_append (rsb, s);
	r_strbuf_append (rsb, " end addr: ");
	char *d = __show_status_input (core, r_strbuf_drain (rsb));
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
	__setRefreshAll ((RCore *)user, false, false);
	return 0;
}

int __stepCb(void *user) {
	RCore *core = (RCore *)user;
	__panelSingleStepIn (core);
	__update_disassembly_or_open (core);
	return 0;
}

int __stepoverCb(void *user) {
	RCore *core = (RCore *)user;
	__panelSingleStepOver (core);
	__update_disassembly_or_open (core);
	return 0;
}

int __ioCacheOnCb(void *user) {
	RCore *core = (RCore *)user;
	r_config_set_i (core->config, "io.cache", 1);
	(void)__show_status (core, "io.cache is on");
	__setMode (core, PANEL_MODE_DEFAULT);
	return 0;
}

int __ioCacheOffCb(void *user) {
	RCore *core = (RCore *)user;
	r_config_set_i (core->config, "io.cache", 0);
	(void)__show_status (core, "io.cache is off");
	__setMode (core, PANEL_MODE_DEFAULT);
	return 0;
}

char *__get_name_cb (R_NULLABLE void *user, char *base_name) {
	return base_name;
}

char *__get_config_name_cb (R_NULLABLE void *user, char *base_name) {
	RCore *core = (RCore *)user;
	RStrBuf *rsb = r_strbuf_new (NULL);
	r_strbuf_append (rsb, base_name);
	r_strbuf_append (rsb, ": ");
	r_strbuf_append (rsb, r_config_get (core->config, base_name));
	return r_strbuf_drain (rsb);
}

void __update_disassembly_or_open (RCore *core) {
	RPanels *panels = core->panels;
	int i;
	bool create_new = true;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __getPanel (panels, i);
		if (__check_panel_type (p, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			__set_panel_addr (core, p, core->offset);
			create_new = false;
		}
	}
	if (create_new) {
		RPanel *panel = __getPanel (panels, 0);
		int x0 = panel->view->pos.x;
		int y0 = panel->view->pos.y;
		int w0 = panel->view->pos.w;
		int h0 = panel->view->pos.h;
		int threshold_w = x0 + panel->view->pos.w;
		int x1 = x0 + w0 / 2 - 1;
		int w1 = threshold_w - x1;

		__insertPanel (core, 0, PANEL_TITLE_DISASSEMBLY, PANEL_CMD_DISASSEMBLY, false);
		RPanel *p0 = __getPanel (panels, 0);
		__set_geometry (&p0->view->pos, x0, y0, w0 / 2, h0);

		RPanel *p1 = __getPanel (panels, 1);
		__set_geometry (&p1->view->pos, x1, y0, w1, h0);

		__setCursor (core, false);
		__set_curnode (core, 0);
	}
	__setRefreshAll (core, false, false);
}

void __set_curnode(RCore *core, int idx) {
	RPanels *panels = core->panels;
	if (idx >= panels->n_panels) {
		idx = 0;
	}
	if (idx < 0) {
		idx = panels->n_panels - 1;
	}
	panels->curnode = idx;
}

void __setMode(RCore *core, RPanelsMode mode) {
	RPanels *panels = core->panels;
	__setCursor (core, false);
	panels->mode = mode;
	__updateHelp (panels);
}

void __updateHelp(RPanels *ps) {
	int i;
	for (i = 0; i < ps->n_panels; i++) {
		RPanel *p = __getPanel (ps, i);
		if (r_str_endswith (p->model->cmd, "Help")) {
			RStrBuf *rsb = r_strbuf_new (NULL);
			const char *title, *cmd;
			const char **msg;
			switch (ps->mode) {
				case PANEL_MODE_WINDOW:
					title = "Panels Window mode help";
					cmd = "Window Mode Help";
					msg = help_msg_panels_window;
					break;
				case PANEL_MODE_ZOOM:
					title = "Panels Zoom mode help";
					cmd = "Zoom Mode Help";
					msg = help_msg_panels_zoom;
					break;
				default:
					title = "Visual Ascii Art Panels";
					cmd = "Help";
					msg = help_msg_panels;
					break;
			}
			p->model->title = r_str_dup (p->model->title, cmd);
			p->model->cmd = r_str_dup (p->model->cmd, cmd);
			r_core_visual_append_help (rsb, title, msg);
			if (!rsb) {
				return;
			}
			__setReadOnly (p, r_strbuf_drain (rsb));
			p->view->refresh = true;
		}
	}
}

int __reloadCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_file_reopen_debug (core, "");
	__update_disassembly_or_open (core);
	__setRefreshAll (core, false, false);
	return 0;
}

int __functionCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "af");
	__setRefreshAll (core, false, false);
	return 0;
}

int __symbolsCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aa");
	__setRefreshAll (core, false, false);
	return 0;
}

int __programCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aaa");
	__setRefreshAll (core, false, false);
	return 0;
}

int __basicblocksCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aab");
	__setRefreshAll (core, false, false);
	return 0;
}

int __callsCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aac");
	__setRefreshAll (core, false, false);
	return 0;
}

int __breakpointsCb(void *user) {
	RCore *core = (RCore *)user;
	char buf[128];
	const char *prompt = "addr: ";

	core->cons->line->prompt_type = R_LINE_PROMPT_OFFSET;
	r_line_set_hist_callback (core->cons->line,
		&r_line_hist_offset_up,
		&r_line_hist_offset_down);
	__panelPrompt (prompt, buf, sizeof (buf));
	r_line_set_hist_callback (core->cons->line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	core->cons->line->prompt_type = R_LINE_PROMPT_DEFAULT;

	ut64 addr = r_num_math (core->num, buf);
	r_core_cmdf (core, "dbs 0x%08"PFMT64x, addr);
	__setRefreshAll (core, false, false);
	return 0;
}

int __watchpointsCb(void *user) {
	RCore *core = (RCore *)user;
	char addrBuf[128], rw[128];
	const char *addrPrompt = "addr: ", *rwPrompt = "<r/w/rw>: ";
	__panelPrompt (addrPrompt, addrBuf, sizeof (addrBuf));
	__panelPrompt (rwPrompt, rw, sizeof (rw));
	ut64 addr = r_num_math (core->num, addrBuf);
	r_core_cmdf (core, "dbw 0x%08"PFMT64x" %s", addr, rw);
	__setRefreshAll (core, false, false);
	return 0;
}

int __referencesCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aar");
	__setRefreshAll (core, false, false);
	return 0;
}

int __fortuneCb(void *user) {
	RCore *core = (RCore *)user;
	char *s = r_core_cmd_str (core, "fo");
	r_cons_message (s);
	free (s);
	return 0;
}

int __gameCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_2048 (core->panels->can->color);
	return 0;
}

int __helpCb(void *user) {
	RCore *core = (RCore *)user;
	__toggleHelp (core);
	return 0;
}

int __licenseCb(void *user) {
	r_cons_message ("Copyright 2006-2019 - pancake - LGPL");
	return 0;
}

int __versionCb(void *user) {
	RCore *core = (RCore *)user;
	char *s = r_core_cmd_str (core, "?V");
	r_cons_message (s);
	free (s);
	return 0;
}

int __writeValueCb(void *user) {
	RCore *core = (RCore *)user;
	char *res = __show_status_input (core, "insert number: ");
	if (res) {
		r_core_cmdf (core, "\"wv %s\"", res);
		free (res);
	}
	return 0;
}

int __quitCb(void *user) {
	__set_root_state ((RCore *)user, QUIT);
	return 0;
}

void __directionDefaultCb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanel *cur = __getCurPanel (core->panels);
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (cur->view->sx > 0) {
			cur->view->sx--;
		}
		return;
	case RIGHT:
		cur->view->sx++;
		return;
	case UP:
		if (cur->view->sy > 0) {
			cur->view->sy--;
		}
		return;
	case DOWN:
		cur->view->sy++;
		return;
	}
}

void __directionDisassemblyCb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	int cols = core->print->cols;
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (core->print->cur_enabled) {
			__cursorLeft (core);
			r_core_block_read (core);
			__set_panel_addr (core, cur, core->offset);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			cur->model->addr--;
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
		}
		return;
	case RIGHT:
		if (core->print->cur_enabled) {
			__cursorRight (core);
			r_core_block_read (core);
			__set_panel_addr (core, cur, core->offset);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			cur->model->addr++;
		} else {
			cur->view->sx++;
		}
		return;
	case UP:
		core->offset = cur->model->addr;
		if (core->print->cur_enabled) {
			__cursorUp (core);
			r_core_block_read (core);
			__set_panel_addr (core, cur, core->offset);
		} else {
			r_core_visual_disasm_up (core, &cols);
			r_core_seek_delta (core, -cols);
			__set_panel_addr (core, cur, core->offset);
		}
		return;
	case DOWN:
		core->offset = cur->model->addr;
		if (core->print->cur_enabled) {
			__cursorDown (core);
			r_core_block_read (core);
			__set_panel_addr (core, cur, core->offset);
		} else {
			RAsmOp op;
			r_core_visual_disasm_down (core, &op, &cols);
			r_core_seek (core, core->offset + cols, 1);
			__set_panel_addr (core, cur, core->offset);
		}
		return;
	}
}

void __directionGraphCb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	cur->view->refresh = true;
	const int speed = r_config_get_i (core->config, "graph.scroll") * 2;
	switch ((Direction)direction) {
	case LEFT:
		if (cur->view->sx > 0) {
			cur->view->sx -= speed;
		}
		return;
	case RIGHT:
		cur->view->sx +=  speed;
		return;
	case UP:
		if (cur->view->sy > 0) {
			cur->view->sy -= speed;
		}
		return;
	case DOWN:
		cur->view->sy += speed;
		return;
	}
}

void __directionRegisterCb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	int cols = core->dbg->regcols;
	cols = cols > 0 ? cols : 3;
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (core->print->cur_enabled) {
			__cursorLeft (core);
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
			cur->view->refresh = true;
		}
		return;
	case RIGHT:
		if (core->print->cur_enabled) {
			__cursorRight (core);
		} else {
			cur->view->sx++;
			cur->view->refresh = true;
		}
		return;
	case UP:
		if (core->print->cur_enabled) {
			int tmp = core->print->cur;
			tmp -= cols;
			if (tmp >= 0) {
				core->print->cur = tmp;
			}
		}
		return;
	case DOWN:
		if (core->print->cur_enabled) {
			core->print->cur += cols;
		}
		return;
	}
}

void __directionStackCb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	int cols = r_config_get_i (core->config, "hex.cols");
	if (cols < 1) {
		cols = 16;
	}
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (core->print->cur_enabled) {
			__cursorLeft (core);
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
			cur->view->refresh = true;
		}
		return;
	case RIGHT:
		if (core->print->cur_enabled) {
			__cursorRight (core);
		} else {
			cur->view->sx++;
			cur->view->refresh = true;
		}
		return;
	case UP:
		r_config_set_i (core->config, "stack.delta",
				r_config_get_i (core->config, "stack.delta") + cols);
		cur->model->addr -= cols;
		return;
	case DOWN:
		r_config_set_i (core->config, "stack.delta",
				r_config_get_i (core->config, "stack.delta") - cols);
		cur->model->addr += cols;
		return;
	}
}

void __directionHexdumpCb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
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
			__cursorLeft (core);
		} else {
			cur->model->addr--;
		}
		return;
	case RIGHT:
		if (core->print->cur / cols + 1 > cur->view->pos.h - 5
				&& core->print->cur % cols == cols - 1) {
			cur->model->addr += cols;
			core->print->cur -= cols - 1;
		} else if (core->print->cur_enabled) {
			__cursorRight (core);
		} else {
			cur->model->addr++;
		}
		return;
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
		return;
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
		return;
	}
}

void __direction_panels_cursor_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	cur->view->refresh = true;
	const int THRESHOLD = cur->view->pos.h / 3;
	int sub;
	switch ((Direction)direction) {
	case LEFT:
		if (core->print->cur_enabled) {
			return;
		}
		if (cur->view->sx > 0) {
			cur->view->sx -= r_config_get_i (core->config, "graph.scroll");
		}
		return;
	case RIGHT:
		if (core->print->cur_enabled) {
			return;
		}
		cur->view->sx += r_config_get_i (core->config, "graph.scroll");
		return;
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
		return;
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
		return;
	}
}

char *__print_default_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && __checkFuncDiff (core, panel);
	char *cmdstr = __findCmdStrCache (core, panel);
	if (update || !cmdstr) {
		cmdstr = __handleCmdStrCache (core, panel, false);
		if (panel->model->cache && panel->model->cmdStrCache) {
			__resetScrollPos (panel);
		}
	}
	return cmdstr;
}

char *__print_decompiler_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && __checkFuncDiff (core, panel);
	char *cmdstr = __findCmdStrCache (core, panel);
	if (update || !cmdstr) {
		cmdstr = __handleCmdStrCache (core, panel, true);
		if (panel->model->cmdStrCache) {
			__resetScrollPos (panel);
		}
	}
	return cmdstr;
}

char *__print_disasmsummary_cb (void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && __checkFuncDiff (core, panel);
	char *cmdstr = __findCmdStrCache (core, panel);
	if (update || !cmdstr) {
		cmdstr = __handleCmdStrCache (core, panel, true);
		if (panel->model->cache && panel->model->cmdStrCache) {
			__resetScrollPos (panel);
		}
	}
	return cmdstr;
}

char *__print_disassembly_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	core->print->screen_bounds = 1LL;
	char *cmdstr = __findCmdStrCache (core, panel);
	if (cmdstr) {
		return cmdstr;
	}
	char *ocmd = panel->model->cmd;
	panel->model->cmd = r_str_newf ("%s %d", panel->model->cmd, panel->view->pos.h - 3);
	ut64 o_offset = core->offset;
	core->offset = panel->model->addr;
	r_core_seek (core, panel->model->addr, 1);
	if (r_config_get_i (core->config, "cfg.debug")) {
		r_core_cmd (core, ".dr*", 0);
	}
	cmdstr = __handleCmdStrCache (core, panel, false);
	core->offset = o_offset;
	free (panel->model->cmd);
	panel->model->cmd = ocmd;
	return cmdstr;
}

char *__print_graph_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	bool update = core->panels->autoUpdate && __checkFuncDiff (core, panel);
	char *cmdstr = __findCmdStrCache (core, panel);
	if (update || !cmdstr) {
		cmdstr = __handleCmdStrCache (core, panel, true);
		if (panel->model->cmdStrCache) {
			__resetScrollPos (panel);
		}
	}
	core->cons->event_resize = NULL;
	core->cons->event_data = core;
	core->cons->event_resize = (RConsEvent) __doPanelsRefreshOneShot;
	return cmdstr;
}

char *__print_stack_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	const int delta = r_config_get_i (core->config, "stack.delta");
	const char sign = (delta < 0)? '+': '-';
	const int absdelta = R_ABS (delta);
	return r_core_cmd_strf (core, "%s%c%d", panel->model->cmd, sign, absdelta);
}

char *__print_hexdump_cb(void *user, void *p) {
	RCore *core = (RCore *)user;
	RPanel *panel = (RPanel *)p;
	char *cmdstr = __findCmdStrCache (core, panel);
	if (!cmdstr) {
		ut64 o_offset = core->offset;
		if (!panel->model->cache) {
			core->offset = panel->model->addr;
			r_core_seek (core, core->offset, 1);
			r_core_block_read (core);
		}
		cmdstr = __handleCmdStrCache (core, panel, false);
		core->offset = o_offset;
	}
	return cmdstr;
}

void __hudstuff(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	r_core_visual_hudstuff (core);

	if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		__set_panel_addr (core, cur, core->offset);
	} else {
		int i;
		for (i = 0; i < panels->n_panels; i++) {
			RPanel *panel = __getPanel (panels, i);
			if (__check_panel_type (panel, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
				__set_panel_addr (core, panel, core->offset);
				break;
			}
		}
	}
	__setRefreshAll (core, true, false);
}

void __esil_init(RCore *core) {
	r_core_cmd (core, "aeim", 0);
	r_core_cmd (core, "aeip", 0);
}

void __esil_step_to(RCore *core, ut64 end) {
	r_core_cmdf (core, "aesu 0x%08"PFMT64x, end);
}

void __printSnow(RPanels *panels) {
	if (!panels->snows) {
		panels->snows = r_list_newf (free);
	}
	RPanel *cur = __getCurPanel (panels);
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

void __resetSnow(RPanels *panels) {
	RPanel *cur = __getCurPanel (panels);
	r_list_free (panels->snows);
	panels->snows = NULL;
	cur->view->refresh = true;
}

int __openMenuCb (void *user) {
	RCore* core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panelsMenu;
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
	RStrBuf *buf = __drawMenu (core, child);
	if (!buf) {
		return 0;
	}
	child->p->model->title = r_strbuf_drain (buf);
	child->p->view->pos.w = r_str_bounds (child->p->model->title, &child->p->view->pos.h);
	child->p->view->pos.h += 4;
	child->p->model->type = PANEL_TYPE_MENU;
	child->p->view->refresh = true;
	menu->refreshPanels[menu->n_refresh++] = child->p;
	menu->history[menu->depth++] = child;
	return 0;
}

void __addMenu(RCore *core, const char *parent, const char *base_name, RPanelsMenuCallback cb, RPanelsMenuGetName get_name_cb) {
	RPanels *panels = core->panels;
	RPanelsMenuItem *p_item, *item = R_NEW0 (RPanelsMenuItem);
	if (!item) {
		return;
	}
	if (parent) {
		void *addr = ht_pp_find (panels->mht, parent, NULL);
		p_item = (RPanelsMenuItem *)addr;
		ht_pp_insert (panels->mht, sdb_fmt ("%s.%s", parent, base_name), item);
	} else {
		p_item = panels->panelsMenu->root;
		ht_pp_insert (panels->mht, sdb_fmt ("%s", base_name), item);
	}
	item->n_sub = 0;
	item->selectedIndex = 0;
	item->base_name = base_name ? r_str_new (base_name) : NULL;
	item->sub = NULL;
	item->cb = cb;
	item->get_name_cb = get_name_cb;
	item->p = R_NEW0 (RPanel);
	if (!item->p) {
		free (item);
		return;
	}
	item->p->model = R_NEW0 (RPanelModel);
	item->p->view = R_NEW0 (RPanelView);
	if (!item->p->model || !item->p->view) {
		return;
	}
	p_item->n_sub++;
	RPanelsMenuItem **sub = realloc (p_item->sub, sizeof (RPanelsMenuItem *) * p_item->n_sub);
	if (sub) {
		p_item->sub = sub;
		p_item->sub[p_item->n_sub - 1] = item;
	} else {
		free (item);
	}
}

void __del_menu(RCore *core) {
	RPanels *panels = core->panels;
	RPanelsMenu *menu = panels->panelsMenu;
	int i;
	menu->depth--;
	for (i = 1; i < menu->depth; i++) {
		menu->history[i]->p->view->refresh = true;
		menu->refreshPanels[i - 1] = menu->history[i]->p;
	}
	menu->n_refresh = menu->depth - 1;
	__setRefreshAll (core, false, false);
}

RStrBuf *__drawMenu(RCore *core, RPanelsMenuItem *item) {
	RStrBuf *buf = r_strbuf_new (NULL);
	if (!buf) {
		return NULL;
	}
	int i;
	for (i = 0; i < item->n_sub; i++) {
		if (i == item->selectedIndex) {
			r_strbuf_appendf (buf, "> %s %s"Color_RESET,
					core->cons->context->pal.graph_box2, item->sub[i]->get_name_cb (core, item->sub[i]->base_name));
		} else {
			r_strbuf_appendf (buf, "   %s", item->sub[i]->get_name_cb (core, item->sub[i]->base_name));
		}
		r_strbuf_append (buf, "          \n");
	}
	return buf;
}

void __moveMenuCursor(RCore *core, RPanelsMenu *menu, RPanelsMenuItem *parent) {
	RPanel *p = parent->p;
	RStrBuf *buf = __drawMenu (core, parent);
	if (!buf) {
		return;
	}
	p->model->title = r_strbuf_drain (buf);
	int new_w = r_str_bounds (p->model->title, &p->view->pos.h);
	if (new_w < p->view->pos.w) {
		__setRefreshAll (core, false, false);
	}
	p->view->pos.w = new_w;
	p->view->pos.h += 4;
	p->model->type = PANEL_TYPE_MENU;
	p->view->refresh = true;
	menu->refreshPanels[menu->n_refresh++] = p;
}

bool __initPanelsMenu(RCore *core) {
	RPanels *panels = core->panels;
	RPanelsMenu *panelsMenu = R_NEW0 (RPanelsMenu);
	if (!panelsMenu) {
		return false;
	}
	RPanelsMenuItem *root = R_NEW0 (RPanelsMenuItem);
	if (!root) {
		R_FREE (panelsMenu);
		return false;
	}
	panels->panelsMenu = panelsMenu;
	panelsMenu->root = root;
	root->n_sub = 0;
	root->base_name = NULL;
	root->sub = NULL;

	__load_config_menu (core);

	int i = 0;
	while (menus[i]) {
		__addMenu (core, NULL, menus[i], __openMenuCb, __get_name_cb);
		i++;
	}
	char *parent = "File";
	i = 0;
	while (menus_File[i]) {
		if (!strcmp (menus_File[i], "Open")) {
			__addMenu (core, parent, menus_File[i], __openFileCb, __get_name_cb);
		} else if (!strcmp (menus_File[i], "ReOpen")) {
			__addMenu (core, parent, menus_File[i], __openMenuCb, __get_name_cb);
		} else if (!strcmp (menus_File[i], "Close")) {
			__addMenu (core, parent, menus_File[i], __closeFileCb, __get_name_cb);
		} else if (!strcmp (menus_File[i], "Save Layout")) {
			__addMenu (core, parent, menus_File[i], __saveLayoutCb, __get_name_cb);
		} else if (!strcmp (menus_File[i], "Load Layout")) {
			__addMenu (core, parent, menus_File[i], __openMenuCb, __get_name_cb);
		} else if (!strcmp (menus_File[i], "Clear Saved Layouts")) {
			__addMenu (core, parent, menus_File[i], __clearLayoutsCb, __get_name_cb);
		} else if (!strcmp (menus_File[i], "Quit")) {
			__addMenu (core, parent, menus_File[i], __quitCb, __get_name_cb);
		} else {
			__addMenu (core, parent, menus_File[i], __addCmdPanel, __get_name_cb);
		}
		i++;
	}

	parent = "Settings";
	i = 0;
	while (menus_Settings[i]) {
		__addMenu (core, parent, menus_Settings[i++], __openMenuCb, __get_name_cb);
	}

	parent = "Edit";
	i = 0;
	while (menus_Edit[i]) {
		if (!strcmp (menus_Edit[i], "Copy")) {
			__addMenu (core, parent, menus_Edit[i], __copyCb, __get_name_cb);
		} else if (!strcmp (menus_Edit[i], "Paste")) {
			__addMenu (core, parent, menus_Edit[i], __pasteCb, __get_name_cb);
		} else if (!strcmp (menus_Edit[i], "Write String")) {
			__addMenu (core, parent, menus_Edit[i], __writeStrCb, __get_name_cb);
		} else if (!strcmp (menus_Edit[i], "Write Hex")) {
			__addMenu (core, parent, menus_Edit[i], __writeHexCb, __get_name_cb);
		} else if (!strcmp (menus_Edit[i], "Write Value")) {
			__addMenu (core, parent, menus_Edit[i], __writeValueCb, __get_name_cb);
		} else if (!strcmp (menus_Edit[i], "Assemble")) {
			__addMenu (core, parent, menus_Edit[i], __assembleCb, __get_name_cb);
		} else if (!strcmp (menus_Edit[i], "Fill")) {
			__addMenu (core, parent, menus_Edit[i], __fillCb, __get_name_cb);
		} else if (!strcmp (menus_Edit[i], "io.cache")) {
			__addMenu (core, parent, menus_Edit[i], __openMenuCb, __get_name_cb);
		} else {
			__addMenu (core, parent, menus_Edit[i], __addCmdPanel, __get_name_cb);
		}
		i++;
	}

	parent = "View";
	i = 0;
	while (menus_View[i]) {
		__addMenu (core, parent, menus_View[i++], __addCmdPanel, __get_name_cb);
	}

	parent = "Tools";
	i = 0;
	while (menus_Tools[i]) {
		if (!strcmp (menus_Tools[i], "Calculator")) {
			__addMenu (core, parent, menus_Tools[i], __calculatorCb, __get_name_cb);
		} else if (!strcmp (menus_Tools[i], "R2 Shell")) {
			__addMenu (core, parent, menus_Tools[i], __r2shellCb, __get_name_cb);
		} else if (!strcmp (menus_Tools[i], "System Shell")) {
			__addMenu (core, parent, menus_Tools[i], __systemShellCb, __get_name_cb);
		}
		i++;
	}

	parent = "Search";
	i = 0;
	while (menus_Search[i]) {
		if (!strcmp (menus_Search[i], "String (Whole Bin)")) {
			__addMenu (core, parent, menus_Search[i], __string_whole_bin_Cb, __get_name_cb);
		} else if (!strcmp (menus_Search[i], "String (Data Sections)")) {
			__addMenu (core, parent, menus_Search[i], __string_data_sec_Cb, __get_name_cb);
		} else if (!strcmp (menus_Search[i], "ROP")) {
			__addMenu (core, parent, menus_Search[i], __ropCb, __get_name_cb);
		} else if (!strcmp (menus_Search[i], "Code")) {
			__addMenu (core, parent, menus_Search[i], __codeCb, __get_name_cb);
		} else if (!strcmp (menus_Search[i], "Hexpairs")) {
			__addMenu (core, parent, menus_Search[i], __hexpairsCb, __get_name_cb);
		}
		i++;
	}

	parent = "Emulate";
	i = 0;
	while (menus_Emulate[i]) {
		if (!strcmp (menus_Emulate[i], "Step From")) {
			__addMenu (core, parent, menus_Emulate[i], __esil_init_cb, __get_name_cb);
		} else if (!strcmp (menus_Emulate[i], "Step To")) {
			__addMenu (core, parent, menus_Emulate[i], __esil_step_to_cb, __get_name_cb);
		} else if (!strcmp (menus_Emulate[i], "Step Range")) {
			__addMenu (core, parent, menus_Emulate[i], __esil_step_range_cb, __get_name_cb);
		}
		i++;
	}

	parent = "Debug";
	i = 0;
	while (menus_Debug[i]) {
		if (!strcmp (menus_Debug[i], "Breakpoints")) {
			__addMenu (core, parent, menus_Debug[i], __breakpointsCb, __get_name_cb);
		} else if (!strcmp (menus_Debug[i], "Watchpoints")) {
			__addMenu (core, parent, menus_Debug[i], __watchpointsCb, __get_name_cb);
		} else if (!strcmp (menus_Debug[i], "Continue")) {
			__addMenu (core, parent, menus_Debug[i], __continueCb, __get_name_cb);
		} else if (!strcmp (menus_Debug[i], "Step")) {
			__addMenu (core, parent, menus_Debug[i], __stepCb, __get_name_cb);
		} else if (!strcmp (menus_Debug[i], "Step Over")) {
			__addMenu (core, parent, menus_Debug[i], __stepoverCb, __get_name_cb);
		} else if (!strcmp (menus_Debug[i], "Reload")) {
			__addMenu (core, parent, menus_Debug[i], __reloadCb, __get_name_cb);
		} else {
			__addMenu (core, parent, menus_Debug[i], __addCmdPanel, __get_name_cb);
		}
		i++;
	}

	parent = "Analyze";
	i = 0;
	while (menus_Analyze[i]) {
		if (!strcmp (menus_Analyze[i], "Function")) {
			__addMenu (core, parent, menus_Analyze[i], __functionCb, __get_name_cb);
		} else if (!strcmp (menus_Analyze[i], "Symbols")) {
			__addMenu (core, parent, menus_Analyze[i], __symbolsCb, __get_name_cb);
		} else if (!strcmp (menus_Analyze[i], "Program")) {
			__addMenu (core, parent, menus_Analyze[i], __programCb, __get_name_cb);
		} else if (!strcmp (menus_Analyze[i], "BasicBlocks")) {
			__addMenu (core, parent, menus_Analyze[i], __basicblocksCb, __get_name_cb);
		} else if (!strcmp (menus_Analyze[i], "Calls")) {
			__addMenu (core, parent, menus_Analyze[i], __callsCb, __get_name_cb);
		} else if (!strcmp (menus_Analyze[i], "References")) {
			__addMenu (core, parent, menus_Analyze[i], __referencesCb, __get_name_cb);
		}
		i++;
	}

	parent = "Fun";
	i = 0;
	while (menus_Fun[i]) {
		if (!strcmp (menus_Fun[i], "Fortune")) {
			__addMenu (core, parent, menus_Fun[i], __fortuneCb, __get_name_cb);
		} else if (!strcmp (menus_Fun[i], "2048")) {
			__addMenu (core, parent, menus_Fun[i], __gameCb, __get_name_cb);
		}
		i++;
	}

	parent = "About";
	i = 0;
	while (menus_About[i]) {
		if (!strcmp (menus_About[i], "License")) {
			__addMenu (core, parent, menus_About[i], __licenseCb, __get_name_cb);
		} else if (!strcmp (menus_About[i], "Version")) {
			__addMenu (core, parent, menus_About[i], __versionCb, __get_name_cb);
		}
		i++;
	}

	parent = "Help";
	i = 0;
	while (menus_Help[i]) {
		__addMenu (core, parent, menus_Help[i], __helpCb, __get_name_cb);
		i++;
	}

	parent = "File.ReOpen";
	i = 0;
	while (menus_ReOpen[i]) {
		if (!strcmp (menus_ReOpen[i], "In RW")) {
			__addMenu (core, parent, menus_ReOpen[i], __rwCb, __get_name_cb);
		} else if (!strcmp (menus_ReOpen[i], "In Debugger")) {
			__addMenu (core, parent, menus_ReOpen[i], __debuggerCb, __get_name_cb);
		}
		i++;
	}

	parent = "File.Load Layout";
	i = 0;
	while (menus_loadLayout[i]) {
		if (!strcmp (menus_loadLayout[i], "Saved")) {
			__addMenu (core, parent, menus_loadLayout[i], __openMenuCb, __get_name_cb);
		} else if (!strcmp (menus_loadLayout[i], "Default")) {
			__addMenu (core, parent, menus_loadLayout[i], __loadLayoutDefaultCb, __get_name_cb);
		}
		i++;
	}

	parent = "File.Load Layout.Saved";
	int s;
	i = 0;
	char *config_path = __getPanelsConfigPath();
	char *panels_config = r_file_slurp (config_path, &s);
	if (panels_config) {
		char *tmp = panels_config;
		free (config_path);
		if (!panels_config) {
			return 0;
		}
		char *names = NULL;
		int len = 0;
		while (*(panels_config + 1) != '{') {
			len++;
			panels_config++;
		}
		names = r_str_newlen (tmp, len + 1);
		int count = r_str_split (names, ',');
		i = 0;
		for (; i < count - 1; i++) {
			__addMenu (core, parent, names, __loadLayoutSavedCb, __get_name_cb);
			names += strlen (names) + 1;
		}
	} else {
		__addMenu (core, parent, "Default", __loadLayoutDefaultCb, __get_name_cb);
	}

	parent = "Settings.Colors";
	i = 0;
	while (menus_Colors[i]) {
		__addMenu (core, parent, menus_Colors[i], __colorsCb, __get_name_cb);
		i++;
	}

	parent = "Settings.Decompiler";
	char *opts = r_core_cmd_str (core, "e cmd.pdc=?");
	RList *optl = r_str_split_list (opts, "\n");
	RListIter *iter;
	char *opt;
	r_list_foreach (optl, iter, opt) {
		__addMenu (core, parent, strdup (opt), __decompiler_cb, __get_name_cb);
	}
	r_list_free (optl);
	free (opts);

	parent = "Settings.Disassembly";
	i = 0;
	while (menus_settings_disassembly[i]) {
		if (!strcmp (menus_settings_disassembly[i], "asm.var.summary")) {
			__addMenu (core, parent, menus_settings_disassembly[i], __config_value_cb, __get_config_name_cb);
		} else {
			__addMenu (core, parent, menus_settings_disassembly[i], __config_toggle_cb, __get_config_name_cb);
		}
		i++;
	}

	parent = "Edit.io.cache";
	i = 0;
	while (menus_iocache[i]) {
		if (!strcmp (menus_iocache[i], "On")) {
			__addMenu (core, parent, menus_iocache[i], __ioCacheOnCb, __get_name_cb);
		} else if (!strcmp (menus_iocache[i], "Off")) {
			__addMenu (core, parent, menus_iocache[i], __ioCacheOffCb, __get_name_cb);
		}
		i++;
	}

	panelsMenu->history = calloc (8, sizeof (RPanelsMenuItem *));
	__clearPanelsMenu (core);
	panelsMenu->refreshPanels = calloc (8, sizeof (RPanel *));
	return true;
}

void __clearPanelsMenuRec(RPanelsMenuItem *pmi) {
	int i = 0;
	for(i = 0; i < pmi->n_sub; i++) {
		RPanelsMenuItem *sub = pmi->sub[i];
		if (sub) {
			sub->selectedIndex = 0;
			__clearPanelsMenuRec (sub);
		}
	}
}

void __clearPanelsMenu(RCore *core) {
	RPanels *p = core->panels;
	RPanelsMenu *pm = p->panelsMenu;
	__clearPanelsMenuRec (pm->root);
	pm->root->selectedIndex = 0;
	pm->history[0] = pm->root;
	pm->depth = 1;
	pm->n_refresh = 0;
}

bool __initPanels(RCore *core, RPanels *panels) {
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

RModal *__init_modal() {
	RModal *modal = R_NEW0 (RModal);
	if (!modal) {
		return NULL;
	}
	__set_pos (&modal->pos, 0, 0);
	modal->idx = 0;
	modal->offset = 0;
	return modal;
}

void __freePanelModel(RPanel *panel) {
	free (panel->model->title);
	free (panel->model->cmd);
	free (panel->model->cmdStrCache);
	free (panel->model->readOnly);
	free (panel->model);
}

void __free_modal(RModal **modal) {
	free (*modal);
	*modal = NULL;
}

void __freePanelView(RPanel *panel) {
	free (panel->view);
}

void __freeSinglePanel(RPanel *panel) {
	__freePanelModel (panel);
	__freePanelView (panel);
	free (panel);
}

void __freeAllPanels(RPanels *panels) {
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __getPanel (panels, i);
		__freeSinglePanel (p);
	}
	free (panels->panel);
}

void __refreshCoreOffset (RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		core->offset = cur->model->addr;
	}
}

void __panels_refresh(RCore *core) {
	RPanels *panels = core->panels;
	if (!panels) {
		return;
	}
	RConsCanvas *can = panels->can;
	if (!can) {
		return;
	}
	char title[1024];
	char str[1024];
	int i, h, w = r_cons_get_size (&h);
	__refreshCoreOffset (core);
	r_cons_gotoxy (0, 0);
	if (panels->isResizing || (can->w != w || can->h != h)) {
		panels->isResizing = false;
		if (!r_cons_canvas_resize (can, w, h)) {
			return;
		}
		__setRefreshAll (core, false, false);
	}
	__fitToCanvas (panels);
	//TODO use getPanel
	for (i = 0; i < panels->n_panels; i++) {
		if (i != panels->curnode) {
			__panelPrint (core, can, __getPanel (panels, i), 0);
		}
	}
	if (panels->mode == PANEL_MODE_MENU) {
		__panelPrint (core, can, __getCurPanel (panels), 0);
	} else {
		__panelPrint (core, can, __getCurPanel (panels), 1);
	}
	for (i = 0; i < panels->panelsMenu->n_refresh; i++) {
		__panelPrint (core, can, panels->panelsMenu->refreshPanels[i], 1);
	}
	panels->panelsMenu->n_refresh = 0;
	(void) r_cons_canvas_gotoxy (can, -can->sx, -can->sy);
	r_cons_canvas_fill (can, -can->sx, -can->sy, w, 1, ' ');
	title[0] = 0;
	if (panels->mode == PANEL_MODE_MENU) {
		strcpy (title, "> ");
	}
	const char *color = core->cons->context->pal.graph_box2;
	if (panels->mode == PANEL_MODE_ZOOM) {
		snprintf (str, sizeof (title) - 1, "%s Zoom Mode | Press Enter or q to quit"Color_RESET, color);
		strcat (title, str);
	} else if (panels->mode == PANEL_MODE_WINDOW) {
		snprintf (str, sizeof (title) - 1, "%s Window Mode | hjkl: move around the panels | q: quit the mode | Enter: Zoom mode"Color_RESET, color);
		strcat (title, str);
	} else {
		RPanelsMenuItem *parent = panels->panelsMenu->root;
		for (i = 0; i < parent->n_sub; i++) {
			RPanelsMenuItem *item = parent->sub[i];
			if (panels->mode == PANEL_MODE_MENU && i == parent->selectedIndex) {
				snprintf (str, sizeof (title) - 1, "%s[%s] "Color_RESET, color, item->get_name_cb (core, item->base_name));
			} else {
				snprintf (str, sizeof (title) - 1, "%s  ", item->get_name_cb (core, item->base_name));
			}
			strcat (title, str);
		}
	}
	if (panels->mode == PANEL_MODE_MENU) {
		r_cons_canvas_write (can, Color_BLUE);
		r_cons_canvas_write (can, title);
		r_cons_canvas_write (can, Color_RESET);
	} else {
		r_cons_canvas_write (can, Color_RESET);
		r_cons_canvas_write (can, title);
	}

	snprintf (title, sizeof (title) - 1,
		"[0x%08"PFMT64x "]", core->offset);
	i = -can->sx + w - strlen (title);
	(void) r_cons_canvas_gotoxy (can, i, -can->sy);
	r_cons_canvas_write (can, title);

	int tab_pos = i;
	for (i = core->panels_root->n_panels; i > 0; i--) {
		RPanels *panels = core->panels_root->panels[i - 1];
		char *name = NULL;
		if (panels) {
			name = panels->name;
		}
		if (i - 1 == core->panels_root->cur_panels) {
			if (!name) {
				snprintf (title, sizeof (title) - 1, "%s[%d] "Color_RESET, color, i);
			} else {
				snprintf (title, sizeof (title) - 1, "%s[%s] "Color_RESET, color, name);
			}
			tab_pos -= r_str_ansi_len (title);
		} else {
			if (!name) {
				snprintf (title, sizeof (title) - 1, "%d ", i);
			} else {
				snprintf (title, sizeof (title) - 1, "%s ", name);
			}
			tab_pos -= strlen (title);
		}
		(void) r_cons_canvas_gotoxy (can, tab_pos, -can->sy);
		r_cons_canvas_write (can, title);
	}
	snprintf (title, sizeof (title) - 1, "Tab ");
	tab_pos -= strlen (title);
	(void) r_cons_canvas_gotoxy (can, tab_pos, -can->sy);
	r_cons_canvas_write (can, title);

	if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
		__printSnow (panels);
	}

	r_cons_canvas_print (can);
	if (core->scr_gadgets) {
		r_core_cmd0 (core, "pg");
	}
	r_cons_flush ();
}

void __doPanelsRefresh(RCore *core) {
	if (!core->panels) {
		return;
	}
	core->panels->isResizing = true;
	__panelAllClear (core->panels);
	__panels_refresh (core);
}

void __doPanelsRefreshOneShot(RCore *core) {
	r_core_task_enqueue_oneshot (core, (RCoreTaskOneShot) __doPanelsRefresh, core);
}

void __panelSingleStepIn(RCore *core) {
	if (r_config_get_i (core->config, "cfg.debug")) {
		r_core_cmd (core, "ds", 0);
		r_core_cmd (core, ".dr*", 0);
	} else {
		r_core_cmd (core, "aes", 0);
		r_core_cmd (core, ".ar*", 0);
	}
}

void __panelSingleStepOver(RCore *core) {
	bool io_cache = r_config_get_i (core->config, "io.cache");
	r_config_set_i (core->config, "io.cache", false);
	if (r_config_get_i (core->config, "cfg.debug")) {
		r_core_cmd (core, "dso", 0);
		r_core_cmd (core, ".dr*", 0);
	} else {
		r_core_cmd (core, "aeso", 0);
		r_core_cmd (core, ".ar*", 0);
	}
	r_config_set_i (core->config, "io.cache", io_cache);
}

void __panelBreakpoint(RCore *core) {
	RPanel *cur = __getCurPanel (core->panels);
	if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		r_core_cmd (core, "dbs $$", 0);
		cur->view->refresh = true;
	}
}

void __panelContinue(RCore *core) {
	r_core_cmd (core, "dc", 0);
}

void __panels_check_stackbase(RCore *core) {
	if (!core || !core->panels) {
		return;
	}
	int i;
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	const ut64 stackbase = r_reg_getv (core->anal->reg, sp);
	RPanels *panels = core->panels;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *panel = __getPanel (panels, i);
		if (panel->model->cmd && __check_panel_type (panel, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK)) && panel->model->baseAddr != stackbase) {
			panel->model->baseAddr = stackbase;
			__set_panel_addr (core, panel, stackbase - r_config_get_i (core->config, "stack.delta") + core->print->cur);
		}
	}
}

void __initRotatedb(RCore *core) {
	RPanels *panels = core->panels;
	sdb_ptr_set (panels->rotate_db, "pd", &__rotateDisasCb, 0);
	sdb_ptr_set (panels->rotate_db, "p==", &__rotateEntropyHCb, 0);
	sdb_ptr_set (panels->rotate_db, "p=", &__rotateEntropyVCb, 0);
	sdb_ptr_set (panels->rotate_db, "px", &__rotateHexdumpCb, 0);
	sdb_ptr_set (panels->rotate_db, "dr", &__rotateRegisterCb, 0);
	sdb_ptr_set (panels->rotate_db, "af", &__rotateFunctionCb, 0);
}

void __initSdb(RCore *core) {
	RPanels *panels = core->panels;
	sdb_set (panels->db, "Symbols", "isq", 0);
	sdb_set (panels->db, "Stack"  , "px 256@r:SP", 0);
	sdb_set (panels->db, "Locals", "afvd", 0);
	sdb_set (panels->db, "Registers", "dr", 0);
	sdb_set (panels->db, "RegisterRefs", "drr", 0);
	sdb_set (panels->db, "Disassembly", "pd", 0);
	sdb_set (panels->db, "Disassemble Summary", "pdsf", 0);
	sdb_set (panels->db, "Decompiler", "pdc", 0);
	sdb_set (panels->db, "Graph", "agf", 0);
	sdb_set (panels->db, "Info", "i", 0);
	sdb_set (panels->db, "Database", "k ***", 0);
	sdb_set (panels->db, "Console", "$console", 0);
	sdb_set (panels->db, "Hexdump", "xc", 0);
	sdb_set (panels->db, "Functions", "afl", 0);
	sdb_set (panels->db, "Comments", "CC", 0);
	sdb_set (panels->db, "Entropy", "p=e 100", 0);
	sdb_set (panels->db, "Entropy Fire", "p==e 100", 0);
	sdb_set (panels->db, "DRX", "drx", 0);
	sdb_set (panels->db, "Sections", "iSq", 0);
	sdb_set (panels->db, "Segments", "iSSq", 0);
	sdb_set (panels->db, PANEL_TITLE_STRINGS_DATA, "izq", 0);
	sdb_set (panels->db, PANEL_TITLE_STRINGS_BIN, "izzq", 0);
	sdb_set (panels->db, "Maps", "dm", 0);
	sdb_set (panels->db, "Modules", "dmm", 0);
	sdb_set (panels->db, "Backtrace", "dbt", 0);
	sdb_set (panels->db, "Breakpoints", "db", 0);
	sdb_set (panels->db, "Imports", "iiq", 0);
	sdb_set (panels->db, "Clipboard", "yx", 0);
	sdb_set (panels->db, "New", "o", 0);
	sdb_set (panels->db, "Var READ address", "afvR", 0);
	sdb_set (panels->db, "Var WRITE address", "afvW", 0);
	sdb_set (panels->db, "Summary", "pdsf", 0);
}

void __init_almighty_db(RCore *core) {
	RPanels *panels = core->panels;
	SdbKv *kv;
	SdbListIter *sdb_iter;
	SdbList *sdb_list = sdb_foreach_list (panels->db, true);
	ls_foreach (sdb_list, sdb_iter, kv) {
		char *key =  sdbkv_key (kv);
		sdb_ptr_set (panels->almighty_db, r_str_new (key), &__create_panel_db, 0);
	}
	sdb_ptr_set (panels->almighty_db, "Search strings in data sections", &__search_strings_data_create, 0);
	sdb_ptr_set (panels->almighty_db, "Search strings in the whole bin", &__search_strings_bin_create, 0);
	sdb_ptr_set (panels->almighty_db, "Create New", &__create_panel_input, 0);
	if (r_config_get_i (core->config, "cfg.debug")) {
		sdb_ptr_set (panels->almighty_db, "Put Breakpoints", &__put_breakpoints_cb, 0);
		sdb_ptr_set (panels->almighty_db, "Continue", &__continue_cb, 0);
		sdb_ptr_set (panels->almighty_db, "Step", &__step_cb, 0);
		sdb_ptr_set (panels->almighty_db, "Step Over", &__step_over_cb, 0);
	}
}

void __init_all_dbs(RCore *core) {
	__initSdb (core);
	__init_almighty_db (core);
	__initRotatedb (core);
}

void __create_panel_db(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title) {
	RCore *core = (RCore *)user;
	char *cmd = sdb_get (core->panels->db, title, 0);
	if (!cmd) {
		return;
	}
	__create_panel (core, panel, dir, title, cmd);
}

void __create_panel_input(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title) {
	RCore *core = (RCore *)user;
	char *name = __show_status_input (core, "Name: ");
	char *cmd = __show_status_input (core, "Command: ");
	if (!cmd) {
		return;
	}
	__create_panel (core, panel, dir, name, cmd);
}

void __create_panel(RCore *core, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char* title, const char *cmd) {
	if (!__checkPanelNum (core)) {
		return;
	}
	bool cache = __show_status_yesno (core, 'y', "Cache the result? (Y/n) ");
	switch (dir) {
	case VERTICAL:
		__splitPanelVertical (core, panel, title, cmd, cache);
		break;
	case HORIZONTAL:
		__splitPanelHorizontal (core, panel, title, cmd, cache);
		break;
	case NONE:
		__replaceCmd (core, title, cmd, false);
		break;
	}
}

void __search_strings_data_create(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title) {
	RCore *core = (RCore *)user;
	__create_panel (core, panel, dir, title, __search_strings (core, false));
}

void __search_strings_bin_create(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title) {
	RCore *core = (RCore *)user;
	__create_panel (core, panel, dir, title, __search_strings (core, true));
}

char *__search_strings (RCore *core, bool whole) {
	const char *title = whole ? PANEL_TITLE_STRINGS_BIN : PANEL_TITLE_STRINGS_DATA;
	const char *str = __show_status_input (core, "Search Strings: ");
	return r_str_newf ("%s~%s", __search_db (core, title), str);
}

void __put_breakpoints_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED R_NULLABLE const char *title) {
	__breakpointsCb (user);
}

void __continue_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED R_NULLABLE const char *title) {
	__continueCb (user);
	__update_disassembly_or_open ((RCore *)user);
}

void __step_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED R_NULLABLE const char *title) {
	__stepCb (user);
}

void __step_over_cb(void *user, R_UNUSED RPanel *panel, R_UNUSED const RPanelLayout dir, R_UNUSED R_NULLABLE const char *title) {
	__stepoverCb (user);
}

void __mht_free_kv(HtPPKv *kv) {
	free (kv->key);
	free (kv->value);
}

bool __init(RCore *core, RPanels *panels, int w, int h) {
	panels->panel = NULL;
	panels->n_panels = 0;
	panels->columnWidth = 80;
	if (r_config_get_i (core->config, "cfg.debug")) {
		panels->layout = PANEL_LAYOUT_DEFAULT_DYNAMIC;
	} else {
		panels->layout = PANEL_LAYOUT_DEFAULT_STATIC;
	}
	panels->isResizing = false;
	panels->autoUpdate = false;
	panels->can = __createNewCanvas (core, w, h);
	panels->db = sdb_new0 ();
	panels->rotate_db = sdb_new0 ();
	panels->almighty_db = sdb_new0 ();
	panels->mht = ht_pp_new (NULL, (HtPPKvFreeFunc)__mht_free_kv, (HtPPCalcSizeV)strlen);
	panels->fun = PANEL_FUN_NOFUN;
	panels->prevMode = PANEL_MODE_DEFAULT;
	panels->name = NULL;

	if (w < 140) {
		panels->columnWidth = w / 3;
	}
	return true;
}

int __file_history_up(RLine *line) {
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

int __file_history_down(RLine *line) {
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

void __handleMenu(RCore *core, const int key) {
	RPanels *panels = core->panels;
	RPanelsMenu *menu = panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_cons_switchbuf (false);
	switch (key) {
	case 'h':
		if (menu->depth <= 2) {
			if (menu->root->selectedIndex > 0) {
				menu->root->selectedIndex--;
			} else {
				menu->root->selectedIndex = menu->root->n_sub - 1;
			}
			if (menu->depth == 2) {
				menu->depth = 1;
				__setRefreshAll (core, false, false);
				(void)(menu->root->sub[menu->root->selectedIndex]->cb (core));
			}
		} else {
			__del_menu (core);
		}
		break;
	case 'j':
		{
			if (menu->depth == 1) {
				(void)(child->cb (core));
			} else {
				parent->selectedIndex = R_MIN (parent->n_sub - 1, parent->selectedIndex + 1);
				__moveMenuCursor (core, menu, parent);
			}
		}
		break;
	case 'k':
		{
			if (menu->depth < 2) {
				break;
			}
			RPanelsMenuItem *parent = menu->history[menu->depth - 1];
			if (parent->selectedIndex > 0) {
				parent->selectedIndex--;
				__moveMenuCursor (core, menu, parent);
			} else if (menu->depth == 2) {
				menu->depth--;
				__setRefreshAll (core, false, false);
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
				menu->root->selectedIndex++;
				menu->root->selectedIndex %= menu->root->n_sub;
				menu->depth = 1;
				__setRefreshAll (core, false, false);
				(void)(menu->root->sub[menu->root->selectedIndex]->cb (core));
			}
		}
		break;
	case 'm':
	case 'q':
	case 'Q':
	case -1:
		if (panels->panelsMenu->depth > 1) {
			__del_menu (core);
		} else {
			__setMode (core, PANEL_MODE_DEFAULT);
			__getCurPanel (panels)->view->refresh = true;
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
		__handleTabKey (core, false);
		break;
	case 'Z':
		__handleTabKey (core, true);
		break;
	case ':':
		__handlePrompt (core, panels);
		break;
	case '?':
		__toggleHelp (core);
	case '"':
		__create_almighty (core, __getPanel (panels, 0), panels->almighty_db);
		__setMode (core, PANEL_MODE_DEFAULT);
		break;
	}
}

bool __handle_console(RCore *core, RPanel *panel, const int key) {
	if (!__check_panel_type (panel, PANEL_CMD_CONSOLE, strlen (PANEL_CMD_CONSOLE))) {
		return false;
	}
	r_cons_switchbuf (false);
	switch (key) {
	case 'i':
		{
			char cmd[128] = {0};
			char *prompt = r_str_newf ("[0x%08"PFMT64x"]) ", core->offset);
			__panelPrompt (prompt, cmd, sizeof (cmd));
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

void __handleTabKey(RCore *core, bool shift) {
	__setCursor (core, false);
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	r_cons_switchbuf (false);
	cur->view->refresh = true;
	if (!shift) {
		if (panels->mode == PANEL_MODE_MENU) {
			__set_curnode (core, 0);
			__setMode (core, PANEL_MODE_DEFAULT);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			__set_curnode (core, ++panels->curnode);
		} else {
			__set_curnode (core, ++panels->curnode);
		}
	} else {
		if (panels->mode == PANEL_MODE_MENU) {
			__set_curnode (core, panels->n_panels - 1);
			__setMode (core, PANEL_MODE_DEFAULT);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			__set_curnode (core, --panels->curnode);
		} else {
			__set_curnode (core, --panels->curnode);
		}
	}
	cur = __getCurPanel (panels);
	if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		__setRefreshAll (core, false, false);
		return;
	}
	cur->view->refresh = true;
	if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
		__resetSnow (panels);
	}
}

void __savePanelPos(RPanel* panel) {
	__set_geometry (&panel->view->prevPos, panel->view->pos.x, panel->view->pos.y,
			panel->view->pos.w, panel->view->pos.h);
}

void __restorePanelPos(RPanel* panel) {
	__set_geometry (&panel->view->pos, panel->view->prevPos.x, panel->view->prevPos.y,
			panel->view->prevPos.w, panel->view->prevPos.h);
}

char *__getPanelsConfigPath() {
	char *configPath = r_str_new (R_JOIN_2_PATHS (R2_HOME_DATADIR, ".r2panels"));
	if (!configPath) {
		return NULL;
	}
	char *newPath = r_str_home (configPath);
	R_FREE (configPath);
	return newPath;
}

void __savePanelsLayout(RCore *core) {
	int i, s;
	char *config_path = __getPanelsConfigPath ();
	char *tmp_config = r_file_slurp (config_path, &s);
	char *tmp_tmp_config = tmp_config;

	char *names = NULL;

	if (tmp_config) {
		int len = 0;
		while (*(tmp_config + 1) != '{') {
			len++;
			tmp_config++;
		}
		names = r_str_newlen (tmp_tmp_config, len + 1);
		tmp_config++;
	}

	char *panels_config = NULL;
	if (tmp_config) {
		panels_config = r_str_newlen (tmp_config + 1, strlen (tmp_config) - 2);
	}
	free (tmp_tmp_config);

	char *name = __show_status_input (core, "Name for the layout: ");
	if (names) {
		r_str_append (names, name);
	} else {
		names = r_str_new (name);
	}
	r_str_append (names, ",");

	RPanels *panels = core->panels;
	PJ *pj_tmp = NULL;
	pj_tmp = pj_new ();
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = __getPanel (panels, i);
		pj_o (pj_tmp);
		pj_ks (pj_tmp, "Title", panel->model->title);
		pj_ks (pj_tmp, "Cmd", panel->model->cmd);
		pj_kn (pj_tmp, "x", panel->view->pos.x);
		pj_kn (pj_tmp, "y", panel->view->pos.y);
		pj_kn (pj_tmp, "w", panel->view->pos.w);
		pj_kn (pj_tmp, "h", panel->view->pos.h);
		pj_kb (pj_tmp, "cache", panel->model->cache);
		pj_end (pj_tmp);
	}

	PJ *pj = NULL;
	pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, name, pj_drain (pj_tmp));
	if (panels_config) {
		pj_j (pj, panels_config);
	}
	pj_end (pj);

	FILE *file = r_sandbox_fopen (config_path, "w");
	if (!file) {
		free (config_path);
		return;
	}

	if (file) {
		fprintf (file, "%s", names);
		fprintf (file, "%s", pj_drain (pj));
		fclose (file);
	}
}

char *__parsePanelsConfig(const char *cfg, int len) {
	if (!cfg || !*cfg || len < 2) {
		eprintf ("Not valid config!\n");
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

void __load_config_menu(RCore *core) {
	RList *themes_list = r_core_list_themes (core);
	RListIter *th_iter;
	const char *th;
	int i = 0;
	r_list_foreach (themes_list, th_iter, th) {
		menus_Colors[i++] = th;
	}
}

int __loadSavedPanelsLayout(RCore *core, const char *name) {
	int i, s;

	char *config_path = __getPanelsConfigPath();
	char *panels_config = r_file_slurp (config_path, &s);
	free (config_path);
	if (!panels_config) {
		return 0;
	}

	int len = 0;
	while (*(panels_config + 1) != '{') {
		len++;
		panels_config++;
	}
	panels_config++;

	panels_config = sdb_json_get_str (panels_config, name);
	(void)r_str_arg_unescape (panels_config);
	char *parsedConfig = __parsePanelsConfig (panels_config, strlen (panels_config));
	free (panels_config);
	if (!parsedConfig) {
		return 0;
	}
	int count = r_str_split (parsedConfig, '\n');
	RPanels *panels = core->panels;
	__panelAllClear (panels);
	panels->n_panels = 0;
	__set_curnode (core, 0);
	char *title, *cmd, *x, *y, *w, *h, *p_cfg = parsedConfig;
	bool cache;
	for (i = 1; i < count; i++) {
		title = sdb_json_get_str (p_cfg, "Title");
		cmd = sdb_json_get_str (p_cfg, "Cmd");
		(void)r_str_arg_unescape (cmd);
		x = sdb_json_get_str (p_cfg, "x");
		y = sdb_json_get_str (p_cfg, "y");
		w = sdb_json_get_str (p_cfg, "w");
		h = sdb_json_get_str (p_cfg, "h");
		cache = sdb_json_get_bool (p_cfg, "cache");
		RPanel *p = __getPanel (panels, panels->n_panels);
		__set_geometry (&p->view->pos, atoi (x), atoi (y), atoi (w),atoi (h));
		__init_panel_param (core, p, title, cmd, cache);
		//TODO: Super hacky and refactoring is needed
		if (r_str_endswith (cmd, "Help")) {
			p->model->title = r_str_dup (p->model->title, "Help");
			p->model->cmd = r_str_dup (p->model->cmd, "Help");
			RStrBuf *rsb = r_strbuf_new (NULL);
			r_core_visual_append_help (rsb, "Visual Ascii Art Panels", help_msg_panels);
			if (!rsb) {
				return 0;
			}
			__setReadOnly (p, r_strbuf_drain (rsb));
		}
		p_cfg += strlen (p_cfg) + 1;
	}
	free (parsedConfig);
	if (!panels->n_panels) {
		return 0;
	}
	__setRefreshAll (core, true, false);
	return 1;
}

void __maximizePanelSize(RPanels *panels) {
	RPanel *cur = __getCurPanel (panels);
	__set_geometry (&cur->view->pos, 0, 1, panels->can->w, panels->can->h - 1);
	cur->view->refresh = true;
}

void __toggleZoomMode(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	if (panels->mode != PANEL_MODE_ZOOM) {
		panels->prevMode = panels->mode;
		__setMode (core, PANEL_MODE_ZOOM);
		__savePanelPos (cur);
		__maximizePanelSize (panels);
	} else {
		__setMode (core, panels->prevMode);
		panels->prevMode = PANEL_MODE_DEFAULT;
		__restorePanelPos (cur);
		__setRefreshAll (core, false, false);
		if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
			__resetSnow (panels);
		}
	}
}

void __toggleWindowMode(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->mode != PANEL_MODE_WINDOW) {
		panels->prevMode = panels->mode;
		__setMode (core, PANEL_MODE_WINDOW);
	} else {
		__setMode (core, panels->prevMode);
		panels->prevMode = PANEL_MODE_DEFAULT;
	}
}

void __toggleCache (RCore *core, RPanel *p) {
	p->model->cache = !p->model->cache;
	__setCmdStrCache (core, p, NULL);
	p->view->refresh = true;
}

void __toggleHelp(RCore *core) {
	RPanels *ps = core->panels;
	int i;
	for (i = 0; i < ps->n_panels; i++) {
		RPanel *p = __getPanel (ps, i);
		if (r_str_endswith (p->model->cmd, "Help")) {
			__dismantleDelPanel (core, p, i);
			if (ps->mode == PANEL_MODE_MENU) {
				__setMode (core, PANEL_MODE_DEFAULT);
			}
			__setRefreshAll (core, false, false);
			return;
		}
	}
	__addHelpPanel (core);
	if (ps->mode == PANEL_MODE_MENU) {
		__setMode (core, PANEL_MODE_DEFAULT);
	}
	__updateHelp (ps);
}

void __set_breakpoints_on_cursor(RCore *core, RPanel *panel) {
	if (!r_config_get_i (core->config, "cfg.debug")) {
		return;
	}
	if (__check_panel_type (panel, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		r_core_cmdf (core, "dbs 0x%08"PFMT64x, core->offset + core->print->cur);
		panel->view->refresh = true;
	}
}

void __insertValue(RCore *core) {
	if (!r_config_get_i (core->config, "io.cache")) {
		if (__show_status_yesno (core, 'y', "Insert is not available because io.cache is off. Turn on now?(Y/n)")) {
			r_config_set_i (core->config, "io.cache", 1);
			(void)__show_status (core, "io.cache is on and insert is available now.");
		} else {
			(void)__show_status (core, "You can always turn on io.cache in Menu->Edit->io.cache");
			return;
		}
	}
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	char buf[128];
	if (__check_panel_type (cur, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK))) {
		const char *prompt = "insert hex: ";
		__panelPrompt (prompt, buf, sizeof (buf));
		r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, cur->model->addr);
		cur->view->refresh = true;
	} else if (__check_panel_type (cur, PANEL_CMD_REGISTERS, strlen (PANEL_CMD_REGISTERS))) {
		const char *creg = core->dbg->creg;
		if (creg) {
			const char *prompt = "new-reg-value> ";
			__panelPrompt (prompt, buf, sizeof (buf));
			r_core_cmdf (core, "dr %s = %s", creg, buf);
			cur->view->refresh = true;
		}
	} else if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		const char *prompt = "insert hex: ";
		__panelPrompt (prompt, buf, sizeof (buf));
		r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, core->offset + core->print->cur);
		cur->view->refresh = true;
	} else if (__check_panel_type (cur, PANEL_CMD_HEXDUMP, strlen (PANEL_CMD_HEXDUMP))) {
		const char *prompt = "insert hex: ";
		__panelPrompt (prompt, buf, sizeof (buf));
		r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, cur->model->addr + core->print->cur);
		cur->view->refresh = true;
	}
}

RPanels *__panels_new(RCore *core) {
	RPanels *panels = R_NEW0 (RPanels);
	if (!panels) {
		return NULL;
	}
	int h, w = r_cons_get_size (&h);
	if (!__init (core, panels, w, h)) {
		free (panels);
		return NULL;
	}
	return panels;
}

void __renew_filter(RPanel *panel, int n) {
	panel->model->n_filter = 0;
	char **filter = calloc (sizeof (char *), n);
	if (!filter) {
		panel->model->filter = NULL;
		return;
	}
	panel->model->filter = filter;
}

void __panels_free(RPanelsRoot *panels_root, int i, RPanels *panels) {
	r_cons_switchbuf (true);
	if (panels) {
		__freeAllPanels (panels);
		r_cons_canvas_free (panels->can);
		sdb_free (panels->db);
		sdb_free (panels->rotate_db);
		sdb_free (panels->almighty_db);
		ht_pp_free (panels->mht);
		free (panels);
		panels_root->panels[i] = NULL;
	}
}

bool __moveToDirection(RCore *core, Direction direction) {
	RPanels *panels = core->panels;
	RPanel *cur = __getCurPanel (panels);
	int cur_x0 = cur->view->pos.x, cur_x1 = cur->view->pos.x + cur->view->pos.w - 1, cur_y0 = cur->view->pos.y, cur_y1 = cur->view->pos.y + cur->view->pos.h - 1;
	int temp_x0, temp_x1, temp_y0, temp_y1;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = __getPanel (panels, i);
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

void __update_modal(RCore *core, Sdb *menu_db, RModal *modal) {
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
	r_cons_canvas_write (can, r_strbuf_drain (modal->data));

	r_cons_canvas_box (can, modal->pos.x, modal->pos.y, modal->pos.w + 2, modal->pos.h + 2, core->cons->context->pal.graph_box2);

	r_cons_canvas_print (can);
	r_cons_flush ();
}

bool __draw_modal (RCore *core, RModal *modal, int range_end, int start, const char *name) {
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

void __create_almighty(RCore *core, RPanel *panel, Sdb *menu_db) {
	__setCursor (core, false);
	const int w = 40;
	const int h = 20;
	const int x = (core->panels->can->w - w) / 2;
	const int y = (core->panels->can->h - h) / 2;
	RModal *modal = __init_modal ();
	__set_geometry (&modal->pos, x, y, w, h);
	int okey, key;
	__update_modal (core, menu_db, modal);
	while (modal) {
		okey = r_cons_readchar ();
		key = r_cons_arrow_to_hjkl (okey);
		switch (key) {
		case 'j':
			modal->idx++;
			__update_modal (core, menu_db, modal);
			break;
		case 'k':
			modal->idx--;
			__update_modal (core, menu_db, modal);
			break;
		case 'v':
			__exec_almighty (core, panel, modal, menu_db, VERTICAL);
			__free_modal (&modal);
			break;
		case 'h':
			__exec_almighty (core, panel, modal, menu_db, HORIZONTAL);
			__free_modal (&modal);
			break;
		case 0x0d:
			__exec_almighty (core, panel, modal, menu_db, NONE);
			__free_modal (&modal);
			break;
		case '-':
			__delete_almighty (core, modal, menu_db);
			__update_modal (core, menu_db, modal);
			break;
		case 'q':
		case '"':
			__free_modal (&modal);
			break;
		}
	}
	__setRefreshAll (core, false, false);
}

void __exec_almighty(RCore *core, RPanel *panel, RModal *modal, Sdb *menu_db, RPanelLayout dir) {
	SdbList *l = sdb_foreach_list (menu_db, true);
	SdbKv *kv;
	SdbListIter *iter;
	int i = 0;
	ls_foreach (l, iter, kv) {
		if (i++ == modal->idx) {
			((RPanelAlmightyCallback)(sdb_ptr_get (menu_db, sdbkv_key (kv), 0))) (core, panel, dir, sdbkv_key (kv));
			return;
		}
	}
}

void __delete_almighty(RCore *core, RModal *modal, Sdb *menu_db) {
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

void __createDefaultPanels(RCore *core) {
	RPanels *panels = core->panels;
	panels->n_panels = 0;
	__set_curnode (core, 0);
	const char **panels_list = panels_static;
	if (panels->layout == PANEL_LAYOUT_DEFAULT_DYNAMIC) {
		panels_list = panels_dynamic;
	}

	int i = 0;
	while (panels_list[i]) {
		RPanel *p = __getPanel (panels, panels->n_panels);
		if (!p) {
			return;
		}
		const char *s = panels_list[i++];
		__init_panel_param (core, p, s, __search_db (core, s), 0);
	}
}

void __rotatePanels(RCore *core, bool rev) {
	RPanels *panels = core->panels;
	RPanel *first = __getPanel (panels, 0);
	RPanel *last = __getPanel (panels, panels->n_panels - 1);
	int i;
	RPanelModel *tmp_model;
	if (!rev) {
		tmp_model = first->model;
		for (i = 0; i < panels->n_panels - 1; i++) {
			RPanel *p0 = __getPanel (panels, i);
			RPanel *p1 = __getPanel (panels, i + 1);
			p0->model = p1->model;
		}
		last->model = tmp_model;
	} else {
		tmp_model = last->model;
		for (i = panels->n_panels - 1; i > 0; i--) {
			RPanel *p0 = __getPanel (panels, i);
			RPanel *p1 = __getPanel (panels, i - 1);
			p0->model = p1->model;
		}
		first->model = tmp_model;
	}
	__setRefreshAll (core, false, true);
}

void __rotateDisasCb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	RPanel *p = __getCurPanel (core->panels);

	//TODO: need to come up with a better solution but okay for now
	if (!strcmp (p->model->cmd, PANEL_CMD_DECOMPILER)) {
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
	__rotateAsmemu (core, p);
}

void __rotatePanelCmds(RCore *core, const char **cmds, const int cmdslen, const char *prefix, bool rev) {
	if (!cmdslen) {
		return;
	}
	RPanel *p = __getCurPanel (core->panels);
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
	__setCmdStrCache (core, p, NULL);
	p->view->refresh = true;
}

void __rotateEntropyVCb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	__rotatePanelCmds (core, entropy_rotate, COUNT (entropy_rotate), "p=", rev);
}

void __rotateEntropyHCb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	__rotatePanelCmds (core, entropy_rotate, COUNT (entropy_rotate), "p==", rev);
}

void __rotateHexdumpCb (void *user, bool rev) {
	RCore *core = (RCore *)user;
	__rotatePanelCmds (core, hexdump_rotate, COUNT (hexdump_rotate), "px", rev);
}

void __rotateRegisterCb (void *user, bool rev) {
	RCore *core = (RCore *)user;
	__rotatePanelCmds (core, register_rotate, COUNT (register_rotate), "dr", rev);
}

void __rotateFunctionCb (void *user, bool rev) {
	RCore *core = (RCore *)user;
	__rotatePanelCmds (core, function_rotate, COUNT (function_rotate), "af", rev);
}

void __undoSeek(RCore *core) {
	RPanel *cur = __getCurPanel (core->panels);
	if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		return;
	}
	RIOUndos *undo = r_io_sundo (core->io, core->offset);
	if (undo) {
		r_core_visual_seek_animation (core, undo->off);
		__set_panel_addr (core, cur, core->offset);
	}
}

void __set_filter(RCore *core, RPanel *panel) {
	if (!panel->model->filter) {
		return;
	}
	char *input = __show_status_input (core, "filter word: ");
	if (input) {
		panel->model->filter[panel->model->n_filter++] = input;
		__setCmdStrCache (core, panel, NULL);
		panel->view->refresh = true;
	}
	__resetScrollPos (panel);
}

void __reset_filter(RCore *core, RPanel *panel) {
	free (panel->model->filter);
	panel->model->filter = NULL;
	__renew_filter (panel, PANEL_NUM_LIMIT);
	__setCmdStrCache (core, panel, NULL);
	panel->view->refresh = true;
	__resetScrollPos (panel);
}

void __redoSeek(RCore *core) {
	RPanel *cur = __getCurPanel (core->panels);
	if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		return;
	}
	RIOUndos *undo = r_io_sundo_redo (core->io);
	if (undo) {
		r_core_visual_seek_animation (core, undo->off);
		__set_panel_addr (core, cur, core->offset);
	}
}

void __rotateAsmemu(RCore *core, RPanel *p) {
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

R_API int r_core_visual_panels_root(RCore *core, RPanelsRoot *panels_root) {
	if (!panels_root) {
		panels_root = R_NEW0 (RPanelsRoot);
		if (!panels_root) {
			return false;
		}
		core->panels_root = panels_root;
		panels_root->panels = calloc (sizeof (RPanels *), PANEL_NUM_LIMIT);
		panels_root->n_panels = 0;
		panels_root->cur_panels = 0;
		__set_root_state (core, DEFAULT);
		__init_new_panels_root (core);
	} else {
		if (!panels_root->n_panels) {
			panels_root->n_panels = 0;
			panels_root->cur_panels = 0;
			__init_new_panels_root (core);
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
	return true;
}

void __init_new_panels_root(RCore *core) {
	RPanelsRoot *panels_root = core->panels_root;
	RPanels *panels = __panels_new (core);
	if (!panels) {
		return;
	}
	RPanels *prev = core->panels;
	core->panels = panels;
	panels_root->panels[panels_root->n_panels++] = panels;
	if (!__initPanelsMenu (core)) {
		core->panels = prev;
		return;
	}
	if (!__initPanels (core, panels)) {
		core->panels = prev;
		return;
	}
	__init_all_dbs (core);
	__setMode (core, PANEL_MODE_DEFAULT);
	__createDefaultPanels (core);
	__panels_layout (panels);
	core->panels = prev;
}

void __set_root_state(RCore *core, RPanelsRootState state) {
	core->panels_root->root_state = state;
}

void __del_panels(RCore *core) {
	RPanelsRoot *panels_root = core->panels_root;
	if (panels_root->n_panels <= 1) {
		core->panels_root->root_state = QUIT;
		return;
	}
	__panels_free (panels_root, panels_root->cur_panels, __get_cur_panels (panels_root));
	int i;
	for (i = panels_root->cur_panels; i < panels_root->n_panels - 1; i++) {
		panels_root->panels[i] = panels_root->panels[i + 1];
	}
	panels_root->n_panels--;
	if (panels_root->cur_panels >= panels_root->n_panels) {
		panels_root->cur_panels = panels_root->n_panels - 1;
	}
}

RPanels *__get_panels(RPanelsRoot *panels_root, int i) {
	if (!panels_root || (i >= PANEL_NUM_LIMIT)) {
		return NULL;
	}
	return panels_root->panels[i];
}

RPanels *__get_cur_panels(RPanelsRoot *panels_root) {
	return __get_panels (panels_root, panels_root->cur_panels);
}

void __handle_tab(RCore *core) {
	r_cons_gotoxy (0, 0);
	if (core->panels_root->n_panels <= 1) {
		r_cons_printf (R_CONS_CLEAR_LINE"%s[Tab] t:new T:new with current panel -:del =:name"Color_RESET, core->cons->context->pal.graph_box2);
	} else {
		int min = 1;
		int max = core->panels_root->n_panels;
		r_cons_printf (R_CONS_CLEAR_LINE"%s[Tab] [%d..%d]:select; p:prev; n:next; t:new T:new with current panel -:del =:name"Color_RESET, core->cons->context->pal.graph_box2, min, max);
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

void __handle_tab_nth(RCore *core, int ch) {
	ch -= '0' + 1;
	if (ch < 0) {
		return;
	}
	if (ch != core->panels_root->cur_panels && ch < core->panels_root->n_panels) {
		core->panels_root->cur_panels = ch;
		__set_root_state (core, ROTATE);
	}
}

void __handle_tab_next(RCore *core) {
	if (core->panels_root->n_panels <= 1) {
		return;
	}
	core->panels_root->cur_panels++;
	core->panels_root->cur_panels %= core->panels_root->n_panels;
	__set_root_state (core, ROTATE);
	return;
}


void __handle_tab_prev(RCore *core) {
	if (core->panels_root->n_panels <= 1) {
		return;
	}
	core->panels_root->cur_panels--;
	if (core->panels_root->cur_panels < 0) {
		core->panels_root->cur_panels = core->panels_root->n_panels - 1;
	}
	__set_root_state (core, ROTATE);
}

void __handle_tab_name(RCore *core) {
	core->panels->name = __show_status_input (core, "tab name: ");
}

void __handle_tab_new(RCore *core) {
	if (core->panels_root->n_panels >= PANEL_NUM_LIMIT) {
		return;
	}
	__init_new_panels_root(core);
}

void __handle_tab_new_with_cur_panel (RCore *core) {
	RPanels *panels = core->panels;
	if (panels->n_panels <= 1) {
		return;
	}

	RPanelsRoot *root = core->panels_root;
	if (root->n_panels + 1 >= PANEL_NUM_LIMIT) {
		return;
	}

	RPanel *cur = __getCurPanel (panels);

	RPanels *new_panels = __panels_new (core);
	if (!new_panels) {
		return;
	}
	new_panels->addr = core->offset;
	root->panels[root->n_panels] = new_panels;

	RPanels *prev = core->panels;
	core->panels = new_panels;

	if (!__initPanelsMenu (core) || !__initPanels (core, new_panels)) {
		core->panels = prev;
		return;
	}
	__setMode (core, PANEL_MODE_DEFAULT);
	__init_all_dbs (core);

	RPanel *new_panel = __getPanel (new_panels, 0);
	__init_panel_param (core, new_panel, cur->model->title, cur->model->cmd, cur->model->cache);
	new_panel->model->funcName = r_str_new (cur->model->funcName);
	__setCmdStrCache (core, new_panel, r_str_new (cur->model->cmdStrCache));
	__maximizePanelSize (new_panels);

	core->panels = prev;
	__dismantleDelPanel (core, cur, panels->curnode);

	root->cur_panels = root->n_panels;
	root->n_panels++;

	__set_root_state (core, ROTATE);
}

void __panelPrompt(const char *prompt, char *buf, int len) {
	r_line_set_prompt (prompt);
	*buf = 0;
	r_cons_fgets (buf, len, 0, NULL);
}

static char *getWordFromCanvas(RCore *core, RPanels *panels, int x, int y) {
	char *s = r_cons_canvas_to_string (panels->can);
	char *R = r_str_ansi_crop (s, 0, y - 1, x + 1024, y);
	r_str_ansi_filter (R, NULL, NULL, -1);
	char *r = r_str_ansi_crop (s, x - 1, y - 1, x + 1024, y);
	r_str_ansi_filter (r, NULL, NULL, -1);
	char *pos = strstr (R, r);
	if (!pos) {
		pos = R;
	}
	const char *sp = r_str_rchr (R, pos, ' ');
	if (sp) {
		sp++;
	} else {
		sp = pos;
	}
	char *sp2 = strchr (sp, ' ');
	if (sp2) {
		*sp2 = 0;
	}
	char *res = strdup (sp);
	free (r);
	free (R);
	return res;
}

void __panels_process(RCore *core, RPanels *panels) {
	if (!panels) {
		return;
	}
	int i, okey, key;
	RPanelsRoot *panels_root = core->panels_root;
	RPanels *prev;
	prev = core->panels;
	core->panels = panels;
	core->offset = panels->addr;
	panels->autoUpdate = true;
	int h, w = r_cons_get_size (&h);
	panels->can = __createNewCanvas (core, w, h);
	__setRefreshAll (core, false, true);

	r_cons_switchbuf (false);

	int originCursor = core->print->cur;
	core->print->cur = 0;
	core->print->cur_enabled = false;
	core->print->col = 0;

	bool originVmode = core->vmode;
	core->vmode = true;

	r_cons_enable_mouse (false);
repeat:
	r_cons_enable_mouse (r_config_get_i (core->config, "scr.wheel"));
	core->panels = panels;
	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = core;
	core->cons->event_resize = (RConsEvent) __doPanelsRefreshOneShot;
	__panels_layout_refresh (core);
	RPanel *cur = __getCurPanel (panels);
	if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
		if (panels->mode == PANEL_MODE_MENU) {
			panels->fun = PANEL_FUN_NOFUN;
			__resetSnow (panels);
			__setRefreshAll (core, false, false);
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
	if (key == 0) {
		int x, y;
		if (r_cons_get_click (&x, &y)) {
			char *word = getWordFromCanvas (core, panels, x, y);
			if (panels->mode == PANEL_MODE_MENU) {
				key = '\n';
			} else if (y == 1) { // click on first line (The menu
				if (!strcmp (word, "Tab")) {
					__handle_tab_new (core);
					free (word);
					goto repeat;
				}
				if (word[0] == '[' && word[1] && word[2] == ']') {
					// do nothing
					goto repeat;
				}
				if (atoi (word)) {
					// XXX doesnt seems to update anything else than the selected tab
					__handle_tab_nth (core, word[0]);
					// __getCurPanel (panels)->view->refresh = true;
					__set_root_state (core, ROTATE);
					__panels_layout_refresh (core);
					goto repeat;
				}
				__setMode (core, PANEL_MODE_MENU);
				__clearPanelsMenu (core);
				__getCurPanel (panels)->view->refresh = true;
				key = 'j';
			} else {
				// TODO: select nth panel here
				if (r_str_endswith (word, "X]")) {
					key = 'X';
					free (word);
					goto skip;
				}
				if (word) {
					r_config_set (core->config, "scr.highlight", word);
					free (word);
				}
				int i;
				for (i = 0; i < panels->n_panels; i++) {
					RPanel *p = __getPanel (panels, i);
					if (x >= p->view->pos.x && x < p->view->pos.x + p->view->pos.w) {
						if (y >= p->view->pos.y && y < p->view->pos.y + p->view->pos.h) {
							if (x >= p->view->pos.x && x < p->view->pos.x + 4) {
								key = 'c';
								goto skip;
							}
							panels->curnode = i;
							__set_curnode(core, i);
							__setRefreshAll (core, true, true);
						}
						break;
					}
				}
				goto repeat;
				key = 'c'; // toggle cursor
			}
		} else {
			goto repeat;
		}
	}
skip:
	r_cons_switchbuf (true);

	if (panels->mode == PANEL_MODE_MENU) {
		__handleMenu (core, key);
		if (__check_root_state (core, QUIT)) {
			goto exit;
		}
		goto repeat;
	}

	if (core->print->cur_enabled) {
		if (__handleCursorMode (core, key)) {
			goto repeat;
		}
	}

	if (panels->mode == PANEL_MODE_ZOOM) {
		if (__handleZoomMode (core, key)) {
			goto repeat;
		}
	}

	if (panels->mode == PANEL_MODE_WINDOW) {
		if (__handleWindowMode (core, key)) {
			goto repeat;
		}
	}

	if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY)) && '0' < key && key <= '9') {
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
		__undoSeek (core);
		break;
	case 'U':
		__redoSeek (core);
		break;
	case 'p':
		__rotatePanels (core, false);
		break;
	case 'P':
		__rotatePanels (core, true);
		break;
	case '.':
		if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			ut64 addr = r_debug_reg_get (core->dbg, "PC");
			if (addr && addr != UT64_MAX) {
				r_core_seek (core, addr, 1);
			} else {
				addr = r_num_get (core->num, "entry0");
				if (addr && addr != UT64_MAX) {
					r_core_seek (core, addr, 1);
				}
			}
			__set_panel_addr (core, cur, core->offset);
		}
		break;
	case '?':
		__toggleHelp (core);
		break;
	case 'b':
		r_core_visual_browse (core, NULL);
		break;
	case ';':
		__handleComment (core);
		break;
	case 's':
		__panelSingleStepIn (core);
		if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			__set_panel_addr (core, cur, core->offset);
		}
		__setRefreshAll (core, false, false);
		break;
	case 'S':
		__panelSingleStepOver (core);
		if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			__set_panel_addr (core, cur, core->offset);
		}
		__setRefreshAll (core, false, false);
		break;
	case ' ':
		if (r_config_get_i (core->config, "graph.web")) {
			r_core_cmd0 (core, "agv $$");
		} else {
			__callVisualGraph (core);
		}
		break;
	case ':':
		r_core_visual_prompt_input (core);
		__set_panel_addr (core, cur, core->offset);
		__setRefreshAll (core, false, false);
		break;
	case 'c':
		__activateCursor (core);
		break;
	case 'C':
		{
			int color = r_config_get_i (core->config, "scr.color");
			if (++color > 2) {
				color = 0;
			}
			r_config_set_i (core->config, "scr.color", color);
			can->color = color;
			__setRefreshAll (core, true, false);
		}
		break;
	case 'r':
		if (r_config_get_i (core->config, "asm.hint.call")) {
			r_core_cmd0 (core, "e!asm.hint.call");
			r_core_cmd0 (core, "e!asm.hint.jmp");
		} else if (r_config_get_i (core->config, "asm.hint.jmp")) {
			r_core_cmd0 (core, "e!asm.hint.jmp");
			r_core_cmd0 (core, "e!asm.hint.lea");
		} else if (r_config_get_i (core->config, "asm.hint.lea")) {
			r_core_cmd0 (core, "e!asm.hint.lea");
			r_core_cmd0 (core, "e!asm.hint.call");
		}
		__setRefreshAll (core, false, false);
		break;
	case 'R':
		if (r_config_get_i (core->config, "scr.randpal")) {
			r_core_cmd0 (core, "ecr");
		} else {
			r_core_cmd0 (core, "ecn");
		}
		__doPanelsRefresh (core);
		break;
	case 'a':
		panels->autoUpdate = __show_status_yesno (core, 'y', "Auto update On? (Y/n)");
		break;
	case 'A':
		r_core_visual_asm (core, core->offset);
		break;
	case 'd':
		r_core_visual_define (core, "", 0);
		__setRefreshAll (core, false, false);
		break;
	case 'D':
		__replaceCmd (core, PANEL_TITLE_DISASSEMBLY, PANEL_CMD_DISASSEMBLY, 0);
		break;
	case 'j':
		r_cons_switchbuf (false);
		if (cur->model->directionCb) {
			cur->model->directionCb (core, (int)DOWN);
		}
		break;
	case 'k':
		r_cons_switchbuf (false);
		if (cur->model->directionCb) {
			cur->model->directionCb (core, (int)UP);
		}
		break;
	case 'K':
		r_cons_switchbuf (false);
		if (cur->model->directionCb) {
			for (i = 0; i < __getCurPanel (panels)->view->pos.h / 2 - 6; i++) {
				cur->model->directionCb (core, (int)UP);
			}
		}
		break;
	case 'J':
		r_cons_switchbuf (false);
		if (cur->model->directionCb) {
			for (i = 0; i < __getCurPanel (panels)->view->pos.h / 2 - 6; i++) {
				cur->model->directionCb (core, (int)DOWN);
			}
		}
		break;
	case 'H':
		r_cons_switchbuf (false);
		if (cur->model->directionCb) {
			for (i = 0; i < __getCurPanel (panels)->view->pos.w / 3; i++) {
				cur->model->directionCb (core, (int)LEFT);
			}
		}
		break;
	case 'L':
		r_cons_switchbuf (false);
		if (cur->model->directionCb) {
			for (i = 0; i < __getCurPanel (panels)->view->pos.w / 3; i++) {
				cur->model->directionCb (core, (int)RIGHT);
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
		{
			__create_almighty (core, cur, panels->almighty_db);
		}
		break;
	case 'n':
		if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			r_core_seek_next (core, r_config_get (core->config, "scr.nkey"));
			__set_panel_addr (core, cur, core->offset);
		}
		break;
	case 'N':
		if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
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
		setRefreshAll (panels, false);
#endif
		__dismantleDelPanel (core, cur, panels->curnode);
		__setRefreshAll (core, false, false);
		break;
	case 9: // TAB
		__handleTabKey (core, false);
		break;
	case 'Z': // SHIFT-TAB
		__handleTabKey (core, true);
		break;
	case 'M':
		__handle_visual_mark (core);
	break;
	case 'e':
	{
		char *new_name = __show_status_input (core, "New name: ");
		char *new_cmd = __show_status_input (core, "New command: ");
		bool cache = __show_status_yesno (core, 'y', "Cache the result? (Y/n) ");
		if (new_name && *new_name && new_cmd && *new_cmd) {
			__replaceCmd (core, new_name, new_cmd, cache);
		}
		free (new_name);
		free (new_cmd);
	}
		break;
	case 'm':
		__setMode (core, PANEL_MODE_MENU);
		__clearPanelsMenu (core);
		__getCurPanel (panels)->view->refresh = true;
		break;
	case 'g':
		{
			const char *hl = r_config_get (core->config, "scr.highlight");
			if (hl) {
				ut64 addr = r_num_math (core->num, hl);
				__set_panel_addr (core, cur, addr);
				// r_io_sundo_push (core->io, addr, false); // doesnt seems to work
			} else {
				r_core_visual_showcursor (core, true);
				r_core_visual_offset (core);
				r_core_visual_showcursor (core, false);
				__set_panel_addr (core, cur, core->offset);
			}
		}
		break;
	case 'G':
		if (__checkFunc (core)) {
			__replaceCmd (core, PANEL_TITLE_GRAPH, PANEL_CMD_GRAPH, 1);
		}
		break;
	case 'h':
		r_cons_switchbuf (false);
		if (cur->model->directionCb) {
			cur->model->directionCb (core, (int)LEFT);
		}
		break;
	case 'l':
		r_cons_switchbuf (false);
		if (cur->model->directionCb) {
			cur->model->directionCb (core, (int)RIGHT);
		}
		break;
	case 'V':
		if (r_config_get_i (core->config, "graph.web")) {
			r_core_cmd0 (core, "agv $$");
		} else {
			__callVisualGraph (core);
		}
		break;
	case ']':
		r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") + 1);
		cur->view->refresh = true;
		break;
	case '[':
		r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") - 1);
		cur->view->refresh = true;
		break;
	case '/':
		r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
		break;
	case 'z':
		if (panels->curnode > 0) {
			__swapPanels (panels, 0, panels->curnode);
			__set_curnode (core, 0);
			__setRefreshAll (core, false, false);
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
		__toggleWindowMode (core);
		__setRefreshAll (core, false, false);
		break;
	case 0x0d: // "\\n"
		__toggleZoomMode (core);
		break;
	case '|':
		{
			RPanel *p = __getCurPanel (panels);
			__splitPanelVertical (core, p, p->model->title, p->model->cmd, p->model->cache);
			break;
		}
	case '-':
		{
			RPanel *p = __getCurPanel (panels);
			__splitPanelHorizontal (core, p, p->model->title, p->model->cmd, p->model->cache);
			break;
		}
	case '*':
		if (__checkFunc (core)) {
			r_cons_canvas_free (can);
			panels->can = NULL;

			__replaceCmd (core, PANEL_TITLE_DECOMPILER, PANEL_CMD_DECOMPILER, 1);

			int h, w = r_cons_get_size (&h);
			panels->can = __createNewCanvas (core, w, h);
		}
		break;
	case '(':
		if (panels->fun != PANEL_FUN_SNOW && panels->fun != PANEL_FUN_SAKURA) {
			//TODO: Refactoring the FUN if bored af
			//panels->fun = PANEL_FUN_SNOW;
			panels->fun = PANEL_FUN_SAKURA;
		} else {
			panels->fun = PANEL_FUN_NOFUN;
			__resetSnow (panels);
		}
		break;
	case ')':
		__rotateAsmemu (core, __getCurPanel (panels));
		break;
	case '&':
		__toggleCache (core, __getCurPanel (panels));
		__resetScrollPos (__getCurPanel (panels));
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
			__panelBreakpoint (core);
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
			__panelSingleStepIn (core);
			__setRefreshAll (core, false, false);
		}
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			__panelSingleStepOver (core);
			__setRefreshAll (core, false, false);
		}
		break;
	case R_CONS_KEY_F9:
		cmd = r_config_get (core->config, "key.f9");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			if (__check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
				__panelContinue (core);
				__set_panel_addr (core, cur, core->offset);
				__setRefreshAll (core, false, false);
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
	case 'q':
	case -1: // EOF
		__set_root_state (core, DEL);
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
	core->panels->addr = core->offset;
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	core->print->cur = originCursor;
	core->print->cur_enabled = false;
	core->print->col = 0;
	core->vmode = originVmode;
	core->panels = prev;
}

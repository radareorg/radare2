/* Copyright radare2 2014-2019 - Author: pancake, vane11ope */

// pls move the typedefs into roons and rename it -> RConsPanel

#include <r_core.h>

#define PANEL_NUM_LIMIT 64

#define PANEL_TITLE_SYMBOLS      "Symbols"
#define PANEL_TITLE_STACK        "Stack"
#define PANEL_TITLE_REGISTERS    "Registers"
#define PANEL_TITLE_REGISTERREFS "RegisterRefs"
#define PANEL_TITLE_DISASSEMBLY  "Disassembly"
#define PANEL_TITLE_DECOMPILER   "Decompiler"
#define PANEL_TITLE_GRAPH        "Graph"
#define PANEL_TITLE_FUNCTIONS    "Functions"

#define PANEL_CMD_SYMBOLS        "isq"
#define PANEL_CMD_STACK          "px"
#define PANEL_CMD_REGISTERS      "dr"
#define PANEL_CMD_DISASSEMBLY    "pd"
#define PANEL_CMD_FUNCTION       "afl"
#define PANEL_CMD_GRAPH          "agf"
#define PANEL_CMD_HEXDUMP        "xc"

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
	"File", "Edit", "View", "Tools", "Search", "Debug", "Analyze", "Fun", "About", "Help",
	NULL
};

static const char *menus_File[] = {
	"New", "Open", "ReOpen", "Close", "Sections", "Strings", "Symbols", "Imports", "Info", "Database", "Save Layout", "Load Layout", "Quit",
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
	"Hexdump", "Disassembly", "Decompiler", "Graph", "Functions", "Breakpoints", "Comments", "Entropy", "Entropy Fire", "Colors",
	"Stack", "Var READ address", "Var WRITE address", "Summary",
	NULL
};

static const char *menus_Tools[] = {
	"Calculator", "R2 Shell", "System Shell",
	NULL
};

static const char *menus_Search[] = {
	"String", "ROP", "Code", "Hexpairs",
	NULL
};

static const char *menus_Debug[] = {
	"Registers", "DRX", "Breakpoints", "Watchpoints",
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

static int show_status(RCore *core, const char *msg);
static bool show_status_yesno(RCore *core, int def, const char *msg);
static char *show_status_input(RCore *core, const char *msg);
static bool check_panel_type(RPanel *panel, const char *type, int len);
static bool is_abnormal_cursor_type(RPanel *panel);
static bool is_normal_cursor_type(RPanel *panel);
static RPanels *panels_new(RCore *core);
static void renew_filter(RPanel *panel, int n);
static void panels_check_stackbase(RCore *core);
static void panels_layout(RPanels *panels);
static void layoutDefault(RPanels *panels);
static void adjustSidePanels(RCore *core);
static int addCmdPanel(void *user);
static void addHelpPanel(RCore *core);
static char *loadCmdf(RCore *core, RPanel *p, char *input, char *str);
static int addCmdfPanel(RCore *core, char *input, char *str);
static void insertPanel(RCore *core, int n, const char *name, const char*cmd, bool cache);
static void splitPanelVertical(RCore *core, RPanel *p, const char *name, const char*cmd, bool cache);
static void splitPanelHorizontal(RCore *core, RPanel *p, const char *name, const char*cmd, bool cache);
static void panelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int color);
static void menuPanelPrint(RConsCanvas *can, RPanel *panel, int x, int y, int w, int h);
static void defaultPanelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int x, int y, int w, int h, int color);
static void panelAllClear(RPanels *panels);
static bool checkPanelNum(RCore *core);
static bool checkFunc(RCore *core);
static bool checkFuncDiff(RCore *core, RPanel *p);
static bool findCmdStrCache(RCore *core, RPanel *panel, char **str);
static char *handleCmdStrCache(RCore *core, RPanel *panel);
static void activateCursor(RCore *core);
static void cursorLeft(RCore *core);
static void cursorRight(RCore *core);
static void cursorDown(RCore *core);
static void cursorUp(RCore *core);
static void fix_cursor_up(RCore *core);
static void fix_cursor_down(RCore *core);
static void delPanel(RPanels *ps, int pi);
static void dismantleDelPanel(RPanels *ps, RPanel *p, int pi);
static void delInvalidPanels(RPanels *panels);
static void fixBlockSize(RCore *core);
static void dismantlePanel(RPanels *ps, RPanel *p);
static void panels_refresh(RCore *core);
static void panels_layout_refresh(RCore *core);
static void doPanelsRefresh(RCore *core);
static void doPanelsRefreshOneShot(RCore *core);
static void refreshCoreOffset (RCore *core);
static bool handleZoomMode(RCore *core, const int key);
static bool handleWindowMode(RCore *core, const int key);
static bool handleCursorMode(RCore *core, const int key);
static void handle_visual_mark(RCore *core);
static void add_visual_mark(RCore *core);
static void resizePanelLeft(RPanels *panels);
static void resizePanelRight(RPanels *panels);
static void resizePanelUp(RPanels *panels);
static void resizePanelDown(RPanels *panels);
static void fitToCanvas(RPanels *panels);
static void handleTabKey(RCore *core, bool shift);
static void undoSeek(RCore *core);
static void redoSeek(RCore *core);
static void set_filter(RCore *core, RPanel *panel);
static void reset_filter(RPanel *panel);
static char *apply_filter_cmd(RCore *core, RPanel *panel);
static int openMenuCb(void *user);
static int openFileCb(void *user);
static int rwCb(void *user);
static int debuggerCb(void *user);
static int loadLayoutSavedCb(void *user);
static int loadLayoutDefaultCb(void *user);
static int closeFileCb(void *user);
static int saveLayoutCb(void *user);
static int copyCb(void *user);
static int pasteCb(void *user);
static int writeStrCb(void *user);
static int writeHexCb(void *user);
static int assembleCb(void *user);
static int fillCb(void *user);
static int colorsCb(void *user);
static int calculatorCb(void *user);
static int r2shellCb(void *user);
static int systemShellCb(void *user);
static int stringCb(void *user);
static int ropCb(void *user);
static int codeCb(void *user);
static int hexpairsCb(void *user);
static int continueCb(void *user);
static int stepCb(void *user);
static int stepoverCb(void *user);
static int reloadCb(void *user);
static int functionCb(void *user);
static int symbolsCb(void *user);
static int programCb(void *user);
static int basicblocksCb(void *user);
static int callsCb(void *user);
static int breakpointsCb(void *user);
static int watchpointsCb(void *user);
static int referencesCb(void *user);
static int helpCb(void *user);
static int fortuneCb(void *user);
static int gameCb(void *user);
static int licenseCb(void *user);
static int versionCb(void *user);
static int quitCb(void *user);
static int ioCacheOnCb(void *user);
static int ioCacheOffCb(void *user);
static void directionDefaultCb(void *user, int direction);
static void directionDisassemblyCb(void *user, int direction);
static void directionGraphCb(void *user, int direction);
static void directionRegisterCb(void *user, int direction);
static void directionStackCb(void *user, int direction);
static void directionHexdumpCb(void *user, int direction);
static void direction_panels_cursor_cb(void *user, int direction);
static void updateDisassemblyAddr (RCore *core);
static void updateAddr (RCore *core);
static void setMode(RPanels *ps, RPanelsMode mode);
static void updateHelp(RPanels *ps);
static void addMenu(RCore *core, const char *parent, const char *name, RPanelsMenuCallback cb);
static void removeMenu(RPanels *panels);
static int file_history_up(RLine *line);
static int file_history_down(RLine *line);
static void hudstuff(RCore *core);
static char *getPanelsConfigPath();
static int panels_process(RCore *core, RPanels **r_panels, bool *force_quit);
static bool init(RCore *core, RPanels *panels, int w, int h);
static void initSdb(RPanels *panels);
static void initRotatedb(RPanels *panels);
static bool initPanelsMenu(RCore *core);
static bool initPanels(RCore *core, RPanels *panels);
static void clearPanelsMenu(RCore *core);
static void clearPanelsMenuRec(RPanelsMenuItem *pmi);
static RStrBuf *drawMenu(RCore *core, RPanelsMenuItem *item);
static void moveMenuCursor(RCore *core, RPanelsMenu *menu, RPanelsMenuItem *parent);
static void panels_free(RPanelsRoot *panels_root, int i, RPanels *panels);
static void freePanelModel(RPanel *panel);
static void freePanelView(RPanel *panel);
static void freeSinglePanel(RPanel *panel);
static void freeAllPanels(RPanels *panels);
static void panelBreakpoint(RCore *core);
static void panelContinue(RCore *core);
static void panelPrompt(const char *prompt, char *buf, int len);
static void panelSingleStepIn(RCore *core);
static void panelSingleStepOver(RCore *core);
static void setRefreshAll(RPanels *panels, bool clearCache);
static void setRefreshByType(RPanels *panels, const char *cmd, bool clearCache);
static void setCursor(RCore *core, bool cur);
static void savePanelPos(RPanel* panel);
static void restorePanelPos(RPanel* panel);
static void savePanelsLayout(RPanels* panels);
static int loadSavedPanelsLayout(RCore *core);
static void load_config_menu(RCore *core);
static void replaceCmd(RCore *core, const char *title, const char *cmd, const bool cache);
static void swapPanels(RPanels *panels, int p0, int p1);
static bool handleMenu(RCore *core, const int key);
static void toggleZoomMode(RPanels *panels);
static void toggleWindowMode(RPanels *panels);
static void toggleCache (RPanel *p);
static void maximizePanelSize(RPanels *panels);
static void insertValue(RCore *core);
static bool moveToDirection(RPanels *panels, Direction direction);
static void toggleHelp(RCore *core);
static void createDefaultPanels(RCore *core);
static void createNewPanel(RCore *core, bool vertical);
static void printSnow(RPanels *panels);
static void resetSnow(RPanels *panels);
static void checkEdge(RPanels *panels);
static void callVisualGraph(RCore *core);
static char *parsePanelsConfig(const char *cfg, int len);
static void rotatePanels(RPanels *panels, bool rev);
static void rotateDisasCb(void *user, bool rev);
static void rotatePanelCmds(RCore *core, const char **cmds, const int cmdslen, const char *prefix, bool rev);
static void rotateEntropyVCb(void *user, bool rev);
static void rotateEntropyHCb(void *user, bool rev);
static void rotateHexdumpCb (void *user, bool rev);
static void rotateAsmemu(RCore *core, RPanel *p);
static void rotateRegisterCb (void *user, bool rev);
static void rotateFunctionCb (void *user, bool rev);
static void setdcb(RPanel *p);
static void setrcb(RPanels *ps, RPanel *p);
static void setCmdStrCache(RPanel *p, char *s);
static void setReadOnly(RPanel *p, char *s);
static void resetScrollPos(RPanel *p);
static RPanel *getPanel(RPanels *panels, int i);
static RPanel *getCurPanel(RPanels *panels);
static RPanels *get_panels(RPanelsRoot *panels_root, int i);
static RPanels *get_cur_panels(RPanelsRoot *panels_root);
static RConsCanvas *createNewCanvas(RCore *core, int w, int h);
static void buildPanelParam(RCore *core, RPanel *p, const char *title, const char *cmd, bool cache);
static bool handle_tab(RCore *core);
static bool handle_tab_nth(RCore *core, int ch);
static bool handle_tab_next(RCore *core);
static bool handle_tab_prev(RCore *core);
static void handle_tab_name(RCore *core);
static void handle_tab_new(RCore *core);
static bool handle_tab_del(RCore *core);
static void remove_panels(RCore *core);

static int show_status(RCore *core, const char *msg) {
	r_cons_gotoxy (0, 0);
	r_cons_printf (R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, core->cons->context->pal.graph_box2, msg);
	r_cons_flush ();
	return r_cons_readchar ();
}

static bool show_status_yesno(RCore *core, int def, const char *msg) {
	r_cons_gotoxy (0, 0);
	r_cons_flush ();
	return r_cons_yesno (def, R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, core->cons->context->pal.graph_box2, msg);
}

static char *show_status_input(RCore *core, const char *msg) {
	char *n_msg = r_str_newf (R_CONS_CLEAR_LINE"%s[Status] %s"Color_RESET, core->cons->context->pal.graph_box2, msg);
	r_cons_gotoxy (0, 0);
	r_cons_flush ();
	char *out = r_cons_input (n_msg);
	free (n_msg);
	return out;
}

static bool check_panel_type(RPanel *panel, const char *type, int len) {
	if (!strcmp (type, PANEL_CMD_DISASSEMBLY)) {
		if (!strncmp (panel->model->cmd, type, len) &&
				strcmp (panel->model->cmd, "pdc")) {
			return true;
		}
		return false;
	}
	return !strncmp (panel->model->cmd, type, len);
}

static bool is_abnormal_cursor_type(RPanel *panel) {
	if (check_panel_type (panel, PANEL_CMD_SYMBOLS, strlen (PANEL_CMD_SYMBOLS)) ||
			check_panel_type (panel, PANEL_CMD_FUNCTION, strlen (PANEL_CMD_FUNCTION))) {
		return true;
	}
	return false;
}

static bool is_normal_cursor_type(RPanel *panel) {
	if (check_panel_type (panel, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK)) ||
			check_panel_type (panel, PANEL_CMD_REGISTERS, strlen (PANEL_CMD_REGISTERS)) ||
			check_panel_type (panel, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY)) ||
			check_panel_type (panel, PANEL_CMD_HEXDUMP, strlen (PANEL_CMD_HEXDUMP))) {
		return true;
	}
	return false;
}

static void setCmdStrCache(RPanel *p, char *s) {
	free (p->model->cmdStrCache);
	p->model->cmdStrCache = s;
	setdcb (p);
}

static void setReadOnly(RPanel *p, char *s) {
	free (p->model->readOnly);
	p->model->readOnly = s;
}

static RPanel *getPanel(RPanels *panels, int i) {
	if (i >= PANEL_NUM_LIMIT) {
		return NULL;
	}
	return panels->panel[i];
}

static RPanel *getCurPanel(RPanels *panels) {
	return getPanel (panels, panels->curnode);
}

static void handlePrompt(RCore *core, RPanels *panels) {
	r_core_visual_prompt_input (core);
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = getPanel (panels, i);
		if (check_panel_type (p, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			p->model->addr = core->offset;
			break;
		}
	}
	setRefreshAll (panels, false);
}

static void panelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int color) {
	if (!can || !panel|| !panel->view->refresh) {
		return;
	}

	if (can->w <= panel->view->pos.x || can->h <= panel->view->pos.y) {
		return;
	}
	panel->view->refresh = false;
	r_cons_canvas_fill (can, panel->view->pos.x, panel->view->pos.y, panel->view->pos.w, panel->view->pos.h, ' ');
	if (panel->model->type == PANEL_TYPE_MENU) {
		menuPanelPrint (can, panel, panel->view->sx, panel->view->sy, panel->view->pos.w, panel->view->pos.h);
	} else {
		defaultPanelPrint (core, can, panel, panel->view->sx, panel->view->sy, panel->view->pos.w, panel->view->pos.h, color);
	}
	if (color) {
		r_cons_canvas_box (can, panel->view->pos.x, panel->view->pos.y, panel->view->pos.w, panel->view->pos.h, core->cons->context->pal.graph_box2);
	} else {
		r_cons_canvas_box (can, panel->view->pos.x, panel->view->pos.y, panel->view->pos.w, panel->view->pos.h, core->cons->context->pal.graph_box);
	}
}

static void menuPanelPrint(RConsCanvas *can, RPanel *panel, int x, int y, int w, int h) {
	(void) r_cons_canvas_gotoxy (can, panel->view->pos.x + 2, panel->view->pos.y + 2);
	char *text = r_str_ansi_crop (panel->model->title, x, y, w, h);
	if (text) {
		r_cons_canvas_write (can, text);
		free (text);
	} else {
		r_cons_canvas_write (can, panel->model->title);
	}
}

static void defaultPanelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int x, int y, int w, int h, int color) {
	char title[128], cache_title[128], *text, *cmdStr = NULL;
	char *readOnly = panel->model->readOnly;
	char *cmd_title  = apply_filter_cmd (core, panel);
	int graph_pad = 0;
	bool o_cur = core->print->cur_enabled;
	core->print->cur_enabled = o_cur & (getCurPanel (core->panels) == panel);
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
	(void) r_cons_canvas_gotoxy (can, panel->view->pos.x + 2, panel->view->pos.y + 2);
	if (readOnly) {
		cmdStr = readOnly;
	} else {
		if (panel->model->cmd) {
			if (check_panel_type (panel, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
				core->print->screen_bounds = 1LL;
				if (!findCmdStrCache (core, panel, &cmdStr)) {
					char *ocmd = panel->model->cmd;
					panel->model->cmd = r_str_newf ("%s %d", panel->model->cmd, panel->view->pos.h - 3);
					ut64 o_offset = core->offset;
					core->offset = panel->model->addr;
					r_core_seek (core, panel->model->addr, 1);
					if (r_config_get_i (core->config, "cfg.debug")) {
						r_core_cmd (core, ".dr*", 0);
					}
					cmdStr = handleCmdStrCache (core, panel);
					core->offset = o_offset;
					free (panel->model->cmd);
					panel->model->cmd = ocmd;
				}
			} else if (check_panel_type (panel, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK))) {
				const int delta = r_config_get_i (core->config, "stack.delta");
				const char sign = (delta < 0)? '+': '-';
				const int absdelta = R_ABS (delta);
				cmdStr = r_core_cmd_strf (core, "%s%c%d", panel->model->cmd, sign, absdelta);
			} else if (check_panel_type (panel, PANEL_CMD_HEXDUMP, strlen (PANEL_CMD_HEXDUMP))) {
				if (!findCmdStrCache (core, panel, &cmdStr)) {
					ut64 o_offset = core->offset;
					if (!panel->model->cache) {
						core->offset = panel->model->addr;
						r_core_seek (core, core->offset, 1);
						r_core_block_read (core);
					}
					cmdStr = handleCmdStrCache (core, panel);
					core->offset = o_offset;
				}
			} else {
				if ((core->panels->autoUpdate && checkFuncDiff (core, panel)) || !findCmdStrCache (core, panel, &cmdStr)) {
					cmdStr = handleCmdStrCache (core, panel);
					if (panel->model->cmdStrCache) {
						x = 0;
						y = 0;
						resetScrollPos (panel);
					}
				}
				if (check_panel_type (panel, PANEL_CMD_GRAPH, strlen (PANEL_CMD_GRAPH))) {
					graph_pad = 1;
					core->cons->event_resize = NULL; // avoid running old event with new data
					core->cons->event_data = core;
					core->cons->event_resize = (RConsEvent) doPanelsRefreshOneShot;
				}
			}
		}
	}
	if (y < 0) {
		y = 0;
	}
	bool b = is_abnormal_cursor_type (panel) && core->print->cur_enabled;
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
	core->print->cur_enabled = o_cur;
}

static void resetScrollPos(RPanel *p) {
	p->view->sx = 0;
	p->view->sy = 0;
}

bool findCmdStrCache(RCore *core, RPanel* panel, char **str) {
	if (panel->model->cmdStrCache) {
		*str = panel->model->cmdStrCache;
		return true;
	}
	return false;
}

char *apply_filter_cmd(RCore *core, RPanel *panel) {
	char *out = r_str_ndup (panel->model->cmd, strlen (panel->model->cmd) + 1024);
	if (!panel->model->filter) {
		return out;
	}
	int i;
	for (i = 0; i < panel->model->n_filter; i++) {
		char *filter = panel->model->filter[i];
		if (strlen (filter) > 1024) {
			(void)show_status (core, "filter is too big.");
			return out;
		}
		strcat (out, "~");
		strcat (out, filter);
	}
	return out;
}

char *handleCmdStrCache(RCore *core, RPanel *panel) {
	char *out;
	char *cmd = apply_filter_cmd (core, panel);
	bool b = core->print->cur_enabled && getCurPanel (core->panels) != panel;
	if (b) {
		core->print->cur_enabled = false;
	}
	out = r_core_cmd_str (core, cmd);
	if (panel->model->cache && R_STR_ISNOTEMPTY (out)) {
		setCmdStrCache (panel, out);
	}
	free (cmd);
	if (b) {
		core->print->cur_enabled = true;
	}
	return out;
}

static void panelAllClear(RPanels *panels) {
	if (!panels) {
		return;
	}
	int i;
	RPanel *panel = NULL;
	for (i = 0; i < panels->n_panels; i++) {
		panel = getPanel (panels, i);
		r_cons_canvas_fill (panels->can, panel->view->pos.x, panel->view->pos.y, panel->view->pos.w, panel->view->pos.h, ' ');
	}
	r_cons_canvas_print (panels->can);
	r_cons_flush ();
}

static void panels_layout (RPanels *panels) {
	panels->can->sx = 0;
	panels->can->sy = 0;
	layoutDefault (panels);
}

static void layoutDefault(RPanels *panels) {
	int h, w = r_cons_get_size (&h);
	int ph = (h - 1) / (panels->n_panels - 2);
	int i;
	int colpos = w - panels->columnWidth;
	RPanel *p0 = getPanel (panels, 0);
	RPanel *p1 = getPanel (panels, 1);
	p0->view->pos.x = 0;
	p0->view->pos.y = 1;
	if (panels->n_panels <= 1) {
		p0->view->pos.w = w;
		p0->view->pos.h = h - 1;
		return;
	}
	p0->view->pos.w = colpos / 2 + 1;
	p0->view->pos.h = h - 1;

	p1->view->pos.x = colpos / 2;
	p1->view->pos.y = 1;
	p1->view->pos.w = colpos / 2 + 1;
	p1->view->pos.h = h - 1;

	int pos_x = p1->view->pos.x + p1->view->pos.w - 1;
	for (i = 2; i < panels->n_panels; i++) {
		RPanel *p = getPanel (panels, i);
		p->view->pos.x = pos_x;
		p->view->pos.y = 2 + (ph * (i - 2));
		p->view->pos.w = w - colpos;
		if (p->view->pos.w < 0) {
			p->view->pos.w = 0;
		}
		if ((i + 1) == panels->n_panels) {
			p->view->pos.h = h - p->view->pos.y;
		} else {
			p->view->pos.h = ph;
		}
		p->view->pos.y--;
		p->view->pos.h++;
	}
}

static void adjustSidePanels(RCore *core) {
	int i, h;
	(void)r_cons_get_size (&h);
	RPanels *panels = core->panels;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = getPanel (panels, i);
		if (p->view->pos.x == 0) {
			if (p->view->pos.w >= PANEL_CONFIG_SIDEPANEL_W) {
				p->view->pos.x += PANEL_CONFIG_SIDEPANEL_W - 1;
				p->view->pos.w -= PANEL_CONFIG_SIDEPANEL_W - 1;
			}
		}
	}
}

static int addCmdPanel(void *user) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	if (!checkPanelNum (core)) {
		return 0;
	}
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	const char *cmd = sdb_get (panels->db, child->name, 0);
	if (!cmd) {
		return 0;
	}
	int h;
	(void)r_cons_get_size (&h);
	bool cache = show_status_yesno (core, 'y', "Cache the result? (Y/n)");
	adjustSidePanels (core);
	insertPanel (core, 0, child->name, cmd, cache);
	RPanel *p0 = getPanel (panels, 0);
	p0->view->pos.x = 0;
	p0->view->pos.y = 1;
	p0->view->pos.w = PANEL_CONFIG_SIDEPANEL_W;
	p0->view->pos.h = h - 1;
	panels->curnode = 0;
	setRefreshAll (panels, false);
	setMode (panels, PANEL_MODE_DEFAULT);
	return 0;
}

static void addHelpPanel(RCore *core) {
	//TODO: all these things done below are very hacky and refactoring needed
	RPanels *ps = core->panels;
	int h;
	const char *help = "Help";
	(void)r_cons_get_size (&h);
	adjustSidePanels (core);
	insertPanel (core, 0, help, help, true);
	RPanel *p0 = getPanel (ps, 0);
	p0->view->pos.x = 0;
	p0->view->pos.y = 1;
	p0->view->pos.w = PANEL_CONFIG_SIDEPANEL_W;
	p0->view->pos.h = h - 1;
	ps->curnode = 0;
	setRefreshAll (ps, false);
}

static char *loadCmdf(RCore *core, RPanel *p, char *input, char *str) {
	char *ret = NULL;
	char *res = show_status_input (core, input);
	if (res) {
		p->model->cmd = r_str_newf (str, res);
		ret = r_core_cmd_str (core, p->model->cmd);
		free (res);
	}
	return ret;
}

static int addCmdfPanel(RCore *core, char *input, char *str) {
	RPanels *panels = core->panels;
	if (!checkPanelNum (core)) {
		return 0;
	}
	int h;
	(void)r_cons_get_size (&h);
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	adjustSidePanels (core);
	insertPanel (core, 0, child->name, "", true);
	RPanel *p0 = getPanel (panels, 0);
	p0->view->pos.x = 0;
	p0->view->pos.y = 1;
	p0->view->pos.w = PANEL_CONFIG_SIDEPANEL_W;
	p0->view->pos.h = h - 1;
	setCmdStrCache (p0, loadCmdf (core, p0, input, str));
	panels->curnode = 0;
	setRefreshAll (panels, false);
	setMode (panels, PANEL_MODE_DEFAULT);
	return 0;
}

static void splitPanelVertical(RCore *core, RPanel *p, const char *name, const char*cmd, bool cache) {
	RPanels *panels = core->panels;
	if (!checkPanelNum (core)) {
		return;
	}
	insertPanel (core, panels->curnode + 1, name, cmd, cache);
	RPanel *next = getPanel (panels, panels->curnode + 1);
	int owidth = p->view->pos.w;
	p->view->pos.w = owidth / 2 + 1;
	next->view->pos.x = p->view->pos.x + p->view->pos.w - 1;
	next->view->pos.y = p->view->pos.y;
	next->view->pos.w = owidth - p->view->pos.w + 1;
	next->view->pos.h = p->view->pos.h;
	setRefreshAll (panels, false);
}

static void splitPanelHorizontal(RCore *core, RPanel *p, const char *name, const char*cmd, bool cache) {
	RPanels *panels = core->panels;
	if (!checkPanelNum (core)) {
		return;
	}
	insertPanel (core, panels->curnode + 1, name, cmd, cache);
	RPanel *next = getPanel (panels, panels->curnode + 1);
	int oheight = p->view->pos.h;
	p->view->curpos = 0;
	p->view->pos.h = oheight / 2 + 1;
	next->view->pos.x = p->view->pos.x;
	next->view->pos.y = p->view->pos.y + p->view->pos.h - 1;
	next->view->pos.w = p->view->pos.w;
	next->view->pos.h = oheight - p->view->pos.h + 1;
	setRefreshAll (panels, false);
}

static void panels_layout_refresh(RCore *core) {
	fixBlockSize (core);
	delInvalidPanels (core->panels);
	checkEdge (core->panels);
	panels_check_stackbase (core);
	panels_refresh (core);
}

static void insertPanel(RCore *core, int n, const char *name, const char *cmd, bool cache) {
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
	buildPanelParam (core, panel[n], name, cmd, cache);
}

static void setCursor(RCore *core, bool cur) {
	RPanel *p = getCurPanel (core->panels);
	RPrint *print = core->print;
	print->cur_enabled = cur;
	if (is_abnormal_cursor_type (p)) {
		return;
	}
	if (cur) {
		print->cur = p->view->curpos;
	} else {
		p->view->curpos = print->cur;
	}
	print->col = print->cur_enabled ? 1: 0;
}

static void activateCursor(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
	if (is_normal_cursor_type (cur) || is_abnormal_cursor_type (cur)) {
		if (cur->model->cache) {
			if (show_status_yesno (core, 'y', "You need to turn off cache to use cursor. Turn off now?(Y/n)")) {
				cur->model->cache = false;
				setCmdStrCache (cur, NULL);
				(void)show_status (core, "Cache is off and cursor is on");
				setCursor (core, !core->print->cur_enabled);
				cur->view->refresh = true;
				resetScrollPos (cur);
			} else {
				(void)show_status (core, "You can always toggle cache by \'&\' key");
			}
			return;
		}
		setCursor (core, !core->print->cur_enabled);
		cur->view->refresh = true;
	} else {
		(void)show_status (core, "Cursor is not available for the current panel.");
	}
}

static void cursorLeft(RCore *core) {
	RPanel *cur = getCurPanel (core->panels);
	RPrint *print = core->print;
	if (check_panel_type (cur, PANEL_CMD_REGISTERS, strlen (PANEL_CMD_REGISTERS))
			|| check_panel_type (cur, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK))) {
		if (print->cur > 0) {
			print->cur--;
			cur->model->addr--;
		}
	} else if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		print->cur--;
		fix_cursor_up (core);
	} else {
		print->cur--;
	}
}

static void cursorRight(RCore *core) {
	RPanel *cur = getCurPanel (core->panels);
	RPrint *print = core->print;
	if (check_panel_type (cur, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK)) && print->cur >= 15) {
		return;
	}
	if (check_panel_type (cur, PANEL_CMD_REGISTERS, strlen (PANEL_CMD_REGISTERS))
			|| check_panel_type (cur, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK))) {
		print->cur++;
		cur->model->addr++;
	} else if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		print->cur++;
		fix_cursor_down (core);
	} else {
		print->cur++;
	}
}


static void cursorUp(RCore *core) {
	RPrint *print = core->print;
	ut64 addr, oaddr = core->offset + print->cur;
	if (r_core_prevop_addr (core, oaddr, 1, &addr)) {
		const int delta = oaddr - addr;
		print->cur -= delta;
	} else {
		print->cur -= 4;
	}
	fix_cursor_up (core);
}

static void cursorDown(RCore *core) {
	RPrint *print = core->print;
	RAnalOp *aop = r_core_anal_op (core, core->offset + print->cur, R_ANAL_OP_MASK_BASIC);
	if (aop) {
		print->cur += aop->size;
		r_anal_op_free (aop);
	} else {
		print->cur += 4;
	}
	fix_cursor_down (core);
}

static void fix_cursor_up(RCore *core) {
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

static void fix_cursor_down(RCore *core) {
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

static bool handleZoomMode(RCore *core, const int key) {
	RPanels *panels = core->panels;
	r_cons_switchbuf (false);
	switch (key) {
	case 'Q':
	case 'q':
	case 0x0d:
		toggleZoomMode (panels);
		break;
	case 'c':
	case 'C':
	case ';':
	case ' ':
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
		return false;
	case 9:
		restorePanelPos (panels->panel[panels->curnode]);
		handleTabKey (core, false);
		savePanelPos (panels->panel[panels->curnode]);
		maximizePanelSize (panels);
		break;
	case 'Z':
		restorePanelPos (panels->panel[panels->curnode]);
		handleTabKey (core, true);
		savePanelPos (panels->panel[panels->curnode]);
		maximizePanelSize (panels);
		break;
	case '?':
		toggleZoomMode (panels);
		toggleHelp (core);
		toggleZoomMode (panels);
		break;
	}
	return true;
}

static void handleComment(RCore *core) {
	RPanel *p = getCurPanel (core->panels);
	if (!check_panel_type (p, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
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
	setRefreshByType (core->panels, p->model->cmd, true);
}

static bool handleWindowMode(RCore *core, const int key) {
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
	r_cons_switchbuf (false);
	switch (key) {
	case 'Q':
	case 'q':
	case 'w':
		toggleWindowMode (panels);
		break;
	case 0x0d:
		toggleZoomMode (panels);
		break;
	case 9: // tab
		handleTabKey (core, false);
		break;
	case 'Z': // shift-tab
		handleTabKey (core, true);
		break;
	case 'h':
		if (moveToDirection (panels, LEFT)) {
			setRefreshAll (panels, false);
		}
		if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
			resetSnow (panels);
		}
		break;
	case 'j':
		if (moveToDirection (panels, DOWN)) {
			setRefreshAll (panels, false);
		}
		if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
			resetSnow (panels);
		}
		break;
	case 'k':
		if (moveToDirection (panels, UP)) {
			setRefreshAll (panels, false);
		}
		if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
			resetSnow (panels);
		}
		break;
	case 'l':
		if (moveToDirection (panels, RIGHT)) {
			setRefreshAll (panels, false);
		}
		if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
			resetSnow (panels);
		}
		break;
	case 'H':
		r_cons_switchbuf (false);
		resizePanelLeft (panels);
		break;
	case 'L':
		r_cons_switchbuf (false);
		resizePanelRight (panels);
		break;
	case 'J':
		r_cons_switchbuf (false);
		resizePanelDown (panels);
		break;
	case 'K':
		r_cons_switchbuf (false);
		resizePanelUp (panels);
		break;
	case '"':
	case 'n':
		createNewPanel (core, true);
		break;
	case 'N':
		createNewPanel (core, false);
		break;
	case 'X':
		dismantleDelPanel (panels, cur, panels->curnode);
		setRefreshAll (panels, false);
		break;
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

static bool handleCursorMode(RCore *core, const int key) {
	RPanel *cur = getCurPanel (core->panels);
	RPrint *print = core->print;
	switch (key) {
	case ':':
	case ';':
	case 'd':
	case 'b':
	case 'h':
	case 'j':
	case 'k':
	case 'l':
		return false;
	case 'Q':
	case 'q':
	case 'c':
		setCursor (core, !print->cur_enabled);
		cur->view->refresh = true;
		break;
	case 'w':
		toggleWindowMode (core->panels);
		setCursor (core, !print->cur_enabled);
		cur->view->refresh = true;
		break;
	case 'i':
		insertValue (core);
		break;
	case '*':
		if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			r_core_cmdf (core, "dr PC=0x%08"PFMT64x, core->offset + print->cur);
			cur->model->addr = core->offset + print->cur;
			cur->view->refresh = true;
		}
		break;
	case 0x0d:
		if (check_panel_type (cur, PANEL_CMD_FUNCTION, strlen (PANEL_CMD_FUNCTION))) {
			RListIter *iter;
			RAnalFunction *fcn;
			int i = 0;
			r_list_foreach (core->anal->fcns, iter, fcn) {
				if (cur->view->curpos == i++) {
					core->offset = fcn->addr;
					updateDisassemblyAddr (core);
					break;
				}
			}
		}
		if (check_panel_type (cur, PANEL_CMD_SYMBOLS, strlen (PANEL_CMD_SYMBOLS))) {
			RListIter *iter;
			RBinSymbol *s;
			RList *syms = r_bin_get_symbols (core->bin);
			int i = 0;
			r_list_foreach (syms, iter, s) {
				if (cur->view->curpos == i++) {
					core->offset = s->vaddr;
					updateDisassemblyAddr (core);
				}
			}
		}
	}
	return true;
}

static void handle_visual_mark(RCore *core) {
	RPanel *cur = getCurPanel (core->panels);
	if (!check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		return;
	}
	int act = show_status (core, "Visual Mark  s:set -:remove \':use: ");
	switch (act) {
	case 's':
		add_visual_mark (core);
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
			cur->model->addr = core->offset;
			cur->view->refresh = true;
		}
	}
	return;
}

static void add_visual_mark(RCore *core) {
	char *msg = r_str_newf (R_CONS_CLEAR_LINE"Set shortcut key for 0x%"PFMT64x": ", core->offset);
	int ch = show_status (core, msg);
	free (msg);
	r_core_visual_mark (core, ch);
}

static void resizePanelLeft(RPanels *panels) {
	RPanel *cur = getCurPanel (panels);
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
		RPanel *p = getPanel (panels, i);
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

static void resizePanelRight(RPanels *panels) {
	RPanel *cur = getCurPanel (panels);
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
		RPanel *p = getPanel (panels, i);
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

static void resizePanelUp(RPanels *panels) {
	RPanel *cur = getCurPanel (panels);
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
		RPanel *p = getPanel (panels, i);
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

static void resizePanelDown(RPanels *panels) {
	RPanel *cur = getCurPanel (panels);
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
		RPanel *p = getPanel (panels, i);
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

static void checkEdge(RPanels *panels) {
	int i, tmpright, tmpbottom, maxright = 0, maxbottom = 0;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = getPanel (panels, i);
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
		RPanel *panel = getPanel (panels, i);
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

static void fitToCanvas(RPanels *panels) {
	RConsCanvas *can = panels->can;
	int i, w, h;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = getPanel (panels, i);
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

static void delPanel(RPanels *ps, int pi) {
	int i;
	RPanel *tmp = getPanel (ps, pi);
	if (!tmp) {
		return;
	}
	for (i = pi; i < (ps->n_panels - 1); i++) {
		ps->panel[i] = ps->panel[i + 1];
	}
	ps->panel[ps->n_panels - 1] = tmp;
	ps->n_panels--;
	if (ps->curnode >= ps->n_panels) {
		ps->curnode = ps->n_panels - 1;
	}
}

static void dismantleDelPanel(RPanels *ps, RPanel *p, int pi) {
	if (ps->n_panels <= 1) {
		return;
	}
	dismantlePanel (ps, p);
	delPanel (ps, pi);
}

static void fixBlockSize(RCore *core) {
	int cols = r_config_get_i (core->config, "hex.cols");
	r_core_block_size (core, (int)(core->cons->rows * cols * 3.5));
}

static void delInvalidPanels(RPanels *panels) {
	int i;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *panel = getPanel (panels, i);
		if (panel->view->pos.w < 2) {
			delPanel (panels, i);
			delInvalidPanels (panels);
			break;
		}
		if (panel->view->pos.h < 2) {
			delPanel (panels, i);
			delInvalidPanels (panels);
			break;
		}
	}
}

static void dismantlePanel(RPanels *ps, RPanel *p) {
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
		tmpPanel = getPanel (ps, i);
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
				tmpPanel = getPanel (ps, i);
				tmpPanel->view->pos.w += ox + ow - (tmpPanel->view->pos.x + tmpPanel->view->pos.w);
			}
		}
	} else if (rightUpValid && rightDownValid) {
		for (i = 0; i < ps->n_panels; i++) {
			if (right[i] != -1) {
				tmpPanel = getPanel (ps, i);
				tmpPanel->view->pos.w = tmpPanel->view->pos.x + tmpPanel->view->pos.w - ox;
				tmpPanel->view->pos.x = ox;
			}
		}
	} else if (upLeftValid && upRightValid) {
		for (i = 0; i < ps->n_panels; i++) {
			if (up[i] != -1) {
				tmpPanel = getPanel (ps, i);
				tmpPanel->view->pos.h += oy + oh - (tmpPanel->view->pos.y + tmpPanel->view->pos.h);
			}
		}
	} else if (downLeftValid && downRightValid) {
		for (i = 0; i < ps->n_panels; i++) {
			if (down[i] != -1) {
				tmpPanel = getPanel (ps, i);
				tmpPanel->view->pos.h = oh + tmpPanel->view->pos.y + tmpPanel->view->pos.h - (oy + oh);
				tmpPanel->view->pos.y = oy;
			}
		}
	}
}

static void replaceCmd(RCore *core, const char *title, const char *cmd, const bool cache) {
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
	freePanelModel (cur);
	cur->model = R_NEW0 (RPanelModel);
	cur->model->title = r_str_dup (cur->model->title, title);
	cur->model->cmd = r_str_dup (cur->model->cmd, cmd);
	cur->model->cache = cache;
	setCmdStrCache (cur, NULL);
	cur->model->addr = core->offset;
	cur->model->type = PANEL_TYPE_DEFAULT;
	setdcb (cur);
	setrcb (panels, cur);
	setRefreshAll (panels, false);
}

static void swapPanels(RPanels *panels, int p0, int p1) {
	RPanel *panel0 = getPanel (panels, p0);
	RPanel *panel1 = getPanel (panels, p1);
	RPanelModel *tmp = panel0->model;

	panel0->model = panel1->model;
	panel1->model = tmp;
}

static void callVisualGraph(RCore *core) {
	if (checkFunc (core)) {
		RPanels *panels = core->panels;

		r_cons_canvas_free (panels->can);
		panels->can = NULL;

		int ocolor = r_config_get_i (core->config, "scr.color");

		r_core_visual_graph (core, NULL, NULL, true);
		r_config_set_i (core->config, "scr.color", ocolor);

		int h, w = r_cons_get_size (&h);
		panels->can = createNewCanvas (core, w, h);
		setRefreshAll (panels, false);
	}
}

static bool checkFunc(RCore *core) {
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

static bool checkFuncDiff(RCore *core, RPanel *p) {
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

static void setRefreshAll(RPanels *panels, bool clearCache) {
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = getPanel (panels, i);
		panel->view->refresh = true;
		if (clearCache) {
			setCmdStrCache (panel, NULL);
		}
	}
}

static void setRefreshByType(RPanels *panels, const char *cmd, bool clearCache) {
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = getPanel (panels, i);
		if (!check_panel_type (p, cmd, strlen (cmd))) {
			continue;
		}
		p->view->refresh = true;
		if (clearCache) {
			free (p->model->cmdStrCache);
			p->model->cmdStrCache = NULL;
		}
	}
}

static RConsCanvas *createNewCanvas(RCore *core, int w, int h) {
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

static bool checkPanelNum(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->n_panels + 1 > PANEL_NUM_LIMIT) {
		const char *msg = "panel limit exceeded.";
		(void)show_status (core, msg);
		return false;
	}
	return true;
}

static void buildPanelParam(RCore *core, RPanel *p, const char *title, const char *cmd, bool cache) {
	RPanelModel *m = p->model;
	RPanelView *v = p->view;
	m->cache = cache;
	m->type = PANEL_TYPE_DEFAULT;
	m->rotate = 0;
	v->curpos = 0;
	m->addr = core->offset;
	m->rotateCb = NULL;
	setCmdStrCache (p, NULL);
	setReadOnly(p, NULL);
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
	if (R_STR_ISNOTEMPTY (m->cmd)) {
		setdcb (p);
		setrcb (core->panels, p);
		if (check_panel_type (p, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK))) {
			const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
			const ut64 stackbase = r_reg_getv (core->anal->reg, sp);
			m->baseAddr = stackbase;
			m->addr = stackbase - r_config_get_i (core->config, "stack.delta");
		}
	}
	core->panels->n_panels++;
	return;
}

static void setdcb(RPanel *p) {
	if (!p->model->cmd) {
		return;
	}
	if (p->model->cmdStrCache || p->model->readOnly) {
		p->model->directionCb = directionDefaultCb;
		return;
	}
	if (check_panel_type (p, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK))) {
		p->model->directionCb = directionStackCb;
	} else if (check_panel_type (p, PANEL_CMD_GRAPH, strlen (PANEL_CMD_GRAPH))) {
		p->model->directionCb = directionGraphCb;
	} else if (check_panel_type (p, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY)) &&
			strcmp (p->model->cmd, "pdc")) {
		p->model->directionCb = directionDisassemblyCb;
	} else if (check_panel_type (p, PANEL_CMD_REGISTERS, strlen (PANEL_CMD_REGISTERS))) {
		p->model->directionCb = directionRegisterCb;
	} else if (check_panel_type (p, PANEL_CMD_HEXDUMP, strlen (PANEL_CMD_HEXDUMP))) {
		p->model->directionCb = directionHexdumpCb;
	} else if (is_abnormal_cursor_type (p)) {
		p->model->directionCb = direction_panels_cursor_cb;
	} else {
		p->model->directionCb = directionDefaultCb;
	}
}

static void setrcb(RPanels *ps, RPanel *p) {
	SdbKv *kv;
	SdbListIter *sdb_iter;
	SdbList *sdb_list = sdb_foreach_list (ps->rotate_db, false);
	ls_foreach (sdb_list, sdb_iter, kv) {
		char *key =  sdbkv_key (kv);
		if (!check_panel_type (p, key, strlen (key))) {
			continue;
		}
		p->model->rotateCb = (RPanelRotateCallback)sdb_ptr_get (ps->rotate_db, key, 0);
		break;
	}
	ls_free (sdb_list);
}

static int openFileCb(void *user) {
	RCore *core = (RCore *)user;
	core->cons->line->prompt_type = R_LINE_PROMPT_FILE;
	r_line_set_hist_callback (core->cons->line, &file_history_up, &file_history_down);
	addCmdfPanel (core, "open file: ", "o %s");
	core->cons->line->prompt_type = R_LINE_PROMPT_DEFAULT;
	r_line_set_hist_callback (core->cons->line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	return 0;
}

static int rwCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "oo+", 0);
	return 0;
}

static int debuggerCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "oo", 0);
	return 0;
}

static int loadLayoutSavedCb(void *user) {
	RCore *core = (RCore *)user;
	if (!loadSavedPanelsLayout (core)) {
		createDefaultPanels (core);
		panels_layout (core->panels);
	}
	core->panels->curnode = 0;
	core->panels->panelsMenu->depth = 1;
	setMode (core->panels, PANEL_MODE_DEFAULT);
	return 0;
}

static int loadLayoutDefaultCb(void *user) {
	RCore *core = (RCore *)user;
	initPanels (core, core->panels);
	createDefaultPanels (core);
	panels_layout (core->panels);
	setRefreshAll (core->panels, false);
	core->panels->panelsMenu->depth = 1;
	setMode (core->panels, PANEL_MODE_DEFAULT);
	return 0;
}

static int closeFileCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "o-*");
	return 0;
}

static int saveLayoutCb(void *user) {
	RCore *core = (RCore *)user;
	savePanelsLayout (core->panels);
	(void)show_status (core, "Panels layout saved!");
	return 0;
}

static int copyCb(void *user) {
	RCore *core = (RCore *)user;
	addCmdfPanel (core, "How many bytes? ", "\"y %s\"");
	return 0;
}

static int pasteCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "yy");
	return 0;
}

static int writeStrCb(void *user) {
	RCore *core = (RCore *)user;
	addCmdfPanel (core, "insert string: ", "\"w %s\"");
	return 0;
}

static int writeHexCb(void *user) {
	RCore *core = (RCore *)user;
	addCmdfPanel (core, "insert hexpairs: ", "\"wx %s\"");
	return 0;
}

static int assembleCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_visual_asm (core, core->offset);
	return 0;
}

static int fillCb(void *user) {
	RCore *core = (RCore *)user;
	addCmdfPanel (core, "Fill with: ", "wow %s");
	return 0;
}

static int colorsCb(void *user) {
	RCore *core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	r_core_cmdf (core, "eco %s", child->name);
	setRefreshAll (core->panels, false);
	int i;
	for (i = 1; i < menu->depth; i++) {
		RPanel *p = menu->history[i]->p;
		p->view->refresh = true;
		menu->refreshPanels[menu->n_refresh++] = p;
	}
	return 0;
}

static int calculatorCb(void *user) {
	RCore *core = (RCore *)user;
	for (;;) {
		char *s = show_status_input (core, "> ");
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

static int r2shellCb(void *user) {
	RCore *core = (RCore *)user;
	core->vmode = false;
	r_core_visual_prompt_input (core);
	core->vmode = true;
	return 0;
}

static int systemShellCb(void *user) {
	r_cons_set_raw (0);
	r_cons_flush ();
	r_sys_cmd ("$SHELL");
	return 0;
}

static int stringCb(void *user) {
	RCore *core = (RCore *)user;
	addCmdfPanel (core, "search string: ", "\"/ %s\"");
	return 0;
}

static int ropCb(void *user) {
	RCore *core = (RCore *)user;
	addCmdfPanel (core, "rop grep: ", "\"/R %s\"");
	return 0;
}

static int codeCb(void *user) {
	RCore *core = (RCore *)user;
	addCmdfPanel (core, "search code: ", "\"/c %s\"");
	return 0;
}

static int hexpairsCb(void *user) {
	RCore *core = (RCore *)user;
	addCmdfPanel (core, "search hexpairs: ", "\"/x %s\"");
	return 0;
}

static int continueCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd (core, "dc", 0);
	r_cons_flush ();
	return 0;
}

static int stepCb(void *user) {
	RCore *core = (RCore *)user;
	panelSingleStepIn (core);
	updateDisassemblyAddr (core);
	return 0;
}

static int stepoverCb(void *user) {
	RCore *core = (RCore *)user;
	panelSingleStepOver (core);
	updateDisassemblyAddr (core);
	return 0;
}

static int ioCacheOnCb(void *user) {
	RCore *core = (RCore *)user;
	r_config_set_i (core->config, "io.cache", 1);
	(void)show_status (core, "io.cache is on");
	setMode (core->panels, PANEL_MODE_DEFAULT);
	return 0;
}

static int ioCacheOffCb(void *user) {
	RCore *core = (RCore *)user;
	r_config_set_i (core->config, "io.cache", 0);
	(void)show_status (core, "io.cache is off");
	setMode (core->panels, PANEL_MODE_DEFAULT);
	return 0;
}

static void updateDisassemblyAddr (RCore *core) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = getPanel (panels, i);
		if (check_panel_type (p, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			p->model->addr = core->offset;
		}
	}
	setRefreshAll (panels, false);
}

static void updateAddr (RCore *core) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = getPanel (panels, i);
		p->model->addr = core->offset;
	}
	setRefreshAll (panels, true);
}

static void setMode(RPanels *ps, RPanelsMode mode) {
	ps->mode = mode;
	updateHelp (ps);
}

static void updateHelp(RPanels *ps) {
	int i;
	for (i = 0; i < ps->n_panels; i++) {
		RPanel *p = getPanel (ps, i);
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
			setReadOnly (p, r_strbuf_drain (rsb));
			p->view->refresh = true;
		}
	}
}

static int reloadCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_file_reopen_debug (core, "");
	updateDisassemblyAddr (core);
	setRefreshAll (core->panels, false);
	return 0;
}

static int functionCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "af");
	setRefreshAll (core->panels, false);
	return 0;
}

static int symbolsCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aa");
	setRefreshAll (core->panels, false);
	return 0;
}

static int programCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aaa");
	setRefreshAll (core->panels, false);
	return 0;
}

static int basicblocksCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aab");
	setRefreshAll (core->panels, false);
	return 0;
}

static int callsCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aac");
	setRefreshAll (core->panels, false);
	return 0;
}

static int breakpointsCb(void *user) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	char buf[128];
	const char *prompt = "addr: ";
	panelPrompt (prompt, buf, sizeof (buf));
	ut64 addr = r_num_math (core->num, buf);
	r_core_cmdf (core, "dbs 0x%08"PFMT64x, addr);
	setRefreshAll (panels, false);
	return 0;
}

static int watchpointsCb(void *user) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	char addrBuf[128], rw[128];
	const char *addrPrompt = "addr: ", *rwPrompt = "<r/w/rw>: ";
	panelPrompt (addrPrompt, addrBuf, sizeof (addrBuf));
	panelPrompt (rwPrompt, rw, sizeof (rw));
	ut64 addr = r_num_math (core->num, addrBuf);
	r_core_cmdf (core, "dbw 0x%08"PFMT64x" %s", addr, rw);
	setRefreshAll (panels, false);
	return 0;
}

static int referencesCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aar");
	setRefreshAll (core->panels, false);
	return 0;
}

static int fortuneCb(void *user) {
	RCore *core = (RCore *)user;
	char *s = r_core_cmd_str (core, "fo");
	r_cons_message (s);
	free (s);
	return 0;
}

static int gameCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_2048 (core->panels->can->color);
	return 0;
}

static int helpCb(void *user) {
	RCore *core = (RCore *)user;
	toggleHelp (core);
	return 0;
}

static int licenseCb(void *user) {
	r_cons_message ("Copyright 2006-2018 - pancake - LGPL");
	return 0;
}

static int versionCb(void *user) {
	RCore *core = (RCore *)user;
	char *s = r_core_cmd_str (core, "?V");
	r_cons_message (s);
	free (s);
	return 0;
}

static int writeValueCb(void *user) {
	RCore *core = (RCore *)user;
	char *res = show_status_input (core, "insert number: ");
	if (res) {
		r_core_cmdf (core, "\"wv %s\"", res);
		free (res);
	}
	return 0;
}

static int quitCb(void *user) {
	return 1;
}

static void directionDefaultCb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanel *cur = getCurPanel (core->panels);
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

static void directionDisassemblyCb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
	int cols = core->print->cols;
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (core->print->cur_enabled) {
			cursorLeft (core);
			r_core_block_read (core);
			cur->model->addr = core->offset;
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
			cur->view->refresh = true;
		}
		return;
	case RIGHT:
		if (core->print->cur_enabled) {
			cursorRight (core);
			r_core_block_read (core);
			cur->model->addr = core->offset;
		} else {
			cur->view->sx++;
			cur->view->refresh = true;
		}
		return;
	case UP:
		core->offset = cur->model->addr;
		if (core->print->cur_enabled) {
			cursorUp (core);
			r_core_block_read (core);
			cur->model->addr = core->offset;
		} else {
			r_core_visual_disasm_up (core, &cols);
			r_core_seek_delta (core, -cols);
			cur->model->addr = core->offset;
		}
		return;
	case DOWN:
		core->offset = cur->model->addr;
		if (core->print->cur_enabled) {
			cursorDown (core);
			r_core_block_read (core);
			cur->model->addr = core->offset;
		} else {
			RAsmOp op;
			r_core_visual_disasm_down (core, &op, &cols);
			r_core_seek (core, core->offset + cols, 1);
			r_core_block_read (core);
			cur->model->addr = core->offset;
		}
		return;
	}
}

static void directionGraphCb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (cur->view->sx > 0) {
			cur->view->sx -= r_config_get_i (core->config, "graph.scroll");
		}
		return;
	case RIGHT:
		cur->view->sx += r_config_get_i (core->config, "graph.scroll");
		return;
	case UP:
		if (cur->view->sy > 0) {
			cur->view->sy -= r_config_get_i (core->config, "graph.scroll");
		}
		return;
	case DOWN:
		cur->view->sy += r_config_get_i (core->config, "graph.scroll");
		return;
	}
}

static void directionRegisterCb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
	int cols = core->dbg->regcols;
	cols = cols > 0 ? cols : 3;
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (core->print->cur_enabled) {
			cursorLeft (core);
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
			cur->view->refresh = true;
		}
		return;
	case RIGHT:
		if (core->print->cur_enabled) {
			cursorRight (core);
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

static void directionStackCb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
	int cols = r_config_get_i (core->config, "hex.cols");
	if (cols < 1) {
		cols = 16;
	}
	cur->view->refresh = true;
	switch ((Direction)direction) {
	case LEFT:
		if (core->print->cur_enabled) {
			cursorLeft (core);
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
			cur->view->refresh = true;
		}
		return;
	case RIGHT:
		if (core->print->cur_enabled) {
			cursorRight (core);
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

static void directionHexdumpCb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
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
			cursorLeft (core);
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
			cur->view->refresh = true;
		}
		return;
	case RIGHT:
		if (core->print->cur / cols + 1 > cur->view->pos.h - 5
				&& core->print->cur % cols == cols - 1) {
			cur->model->addr += cols;
			core->print->cur -= cols - 1;
		} else if (core->print->cur_enabled) {
			cursorRight (core);
		} else {
			cur->view->sx++;
			cur->view->refresh = true;
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
					cur->model->addr = 0;
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

static void direction_panels_cursor_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
	cur->view->refresh = true;
	const int THRESHOLD = cur->view->pos.h / 3;
	int n, sub;
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
				n = r_config_get_i (core->config, "graph.scroll");
				cur->view->curpos -= n;
				cur->view->sy -= n;
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
			n = r_config_get_i (core->config, "graph.scroll");
			cur->view->curpos += n;
			cur->view->sy += n;
		}
		return;
	}
}

static void hudstuff(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
	r_core_visual_hudstuff (core);

	if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		cur->model->addr = core->offset;
	} else {
		int i;
		for (i = 0; i < panels->n_panels; i++) {
			RPanel *panel = getPanel (panels, i);
			if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
				panel->model->addr = core->offset;
				break;
			}
		}
	}
	setRefreshAll (panels, true);
}

static void printSnow(RPanels *panels) {
	if (!panels->snows) {
		panels->snows = r_list_newf (free);
	}
	RPanel *cur = getCurPanel (panels);
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

static void resetSnow(RPanels *panels) {
	RPanel *cur = getCurPanel (panels);
	r_list_free (panels->snows);
	panels->snows = NULL;
	cur->view->refresh = true;
}

static int openMenuCb (void *user) {
	RCore* core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	if (menu->depth < 2) {
		child->p->view->pos.x = menu->root->selectedIndex * 6;
		child->p->view->pos.y = 1;
	} else {
		RPanelsMenuItem *p = menu->history[menu->depth - 2];
		RPanelsMenuItem *parent2 = p->sub[p->selectedIndex];
		child->p->view->pos.x = parent2->p->view->pos.x + parent2->p->view->pos.w - 1;
		child->p->view->pos.y = menu->depth == 2 ? parent2->p->view->pos.y + parent2->selectedIndex : parent2->p->view->pos.y;
	}
	RStrBuf *buf = drawMenu (core, child);
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

static void addMenu(RCore *core, const char *parent, const char *name, RPanelsMenuCallback cb) {
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
		p_item = panels->panelsMenu->root;
		ht_pp_insert (panels->mht, sdb_fmt ("%s", name), item);
	}
	item->n_sub = 0;
	item->selectedIndex = 0;
	item->name = name ? r_str_new (name) : NULL;
	item->sub = NULL;
	item->cb = cb;
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

static void removeMenu(RPanels *panels) {
	RPanelsMenu *menu = panels->panelsMenu;
	int i;
	menu->depth--;
	for (i = 1; i < menu->depth; i++) {
		menu->history[i]->p->view->refresh = true;
		menu->refreshPanels[i - 1] = menu->history[i]->p;
	}
	menu->n_refresh = menu->depth - 1;
	setRefreshAll (panels, false);
}

static RStrBuf *drawMenu(RCore *core, RPanelsMenuItem *item) {
	RStrBuf *buf = r_strbuf_new (NULL);
	if (!buf) {
		return NULL;
	}
	int i;
	for (i = 0; i < item->n_sub; i++) {
		if (i == item->selectedIndex) {
			r_strbuf_appendf (buf, "> %s %s"Color_RESET,
					core->cons->context->pal.graph_box2, item->sub[i]->name);
		} else {
			r_strbuf_appendf (buf, "   %s", item->sub[i]->name);
		}
		r_strbuf_append (buf, "          \n");
	}
	return buf;
}

static void moveMenuCursor(RCore *core, RPanelsMenu *menu, RPanelsMenuItem *parent) {
	RPanel *p = parent->p;
	RStrBuf *buf = drawMenu (core, parent);
	if (!buf) {
		return;
	}
	p->model->title = r_strbuf_drain (buf);
	p->view->pos.w = r_str_bounds (p->model->title, &p->view->pos.h);
	p->view->pos.h += 4;
	p->model->type = PANEL_TYPE_MENU;
	p->view->refresh = true;
	menu->refreshPanels[menu->n_refresh++] = p;
}

static bool initPanelsMenu(RCore *core) {
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
	root->name = NULL;
	root->sub = NULL;

	load_config_menu (core);

	int i = 0;
	while (menus[i]) {
		addMenu (core, NULL, menus[i], openMenuCb);
		i++;
	}
	char *parent = "File";
	i = 0;
	while (menus_File[i]) {
		if (!strcmp (menus_File[i], "Open")) {
			addMenu (core, parent, menus_File[i], openFileCb);
		} else if (!strcmp (menus_File[i], "ReOpen")) {
			addMenu (core, parent, menus_File[i], openMenuCb);
		} else if (!strcmp (menus_File[i], "Close")) {
			addMenu (core, parent, menus_File[i], closeFileCb);
		} else if (!strcmp (menus_File[i], "Save Layout")) {
			addMenu (core, parent, menus_File[i], saveLayoutCb);
		} else if (!strcmp (menus_File[i], "Load Layout")) {
			addMenu (core, parent, menus_File[i], openMenuCb);
		} else if (!strcmp (menus_File[i], "Quit")) {
			addMenu (core, parent, menus_File[i], quitCb);
		} else {
			addMenu (core, parent, menus_File[i], addCmdPanel);
		}
		i++;
	}

	parent = "Edit";
	i = 0;
	while (menus_Edit[i]) {
		if (!strcmp (menus_Edit[i], "Copy")) {
			addMenu (core, parent, menus_Edit[i], copyCb);
		} else if (!strcmp (menus_Edit[i], "Paste")) {
			addMenu (core, parent, menus_Edit[i], pasteCb);
		} else if (!strcmp (menus_Edit[i], "Write String")) {
			addMenu (core, parent, menus_Edit[i], writeStrCb);
		} else if (!strcmp (menus_Edit[i], "Write Hex")) {
			addMenu (core, parent, menus_Edit[i], writeHexCb);
		} else if (!strcmp (menus_Edit[i], "Write Value")) {
			addMenu (core, parent, menus_Edit[i], writeValueCb);
		} else if (!strcmp (menus_Edit[i], "Assemble")) {
			addMenu (core, parent, menus_Edit[i], assembleCb);
		} else if (!strcmp (menus_Edit[i], "Fill")) {
			addMenu (core, parent, menus_Edit[i], fillCb);
		} else if (!strcmp (menus_Edit[i], "io.cache")) {
			addMenu (core, parent, menus_Edit[i], openMenuCb);
		} else {
			addMenu (core, parent, menus_Edit[i], addCmdPanel);
		}
		i++;
	}

	parent = "View";
	i = 0;
	while (menus_View[i]) {
		if (!strcmp (menus_View[i], "Colors")) {
			addMenu (core, parent, menus_View[i], openMenuCb);
		} else {
			addMenu (core, parent, menus_View[i], addCmdPanel);
		}
		i++;
	}

	parent = "Tools";
	i = 0;
	while (menus_Tools[i]) {
		if (!strcmp (menus_Tools[i], "Calculator")) {
			addMenu (core, parent, menus_Tools[i], calculatorCb);
		} else if (!strcmp (menus_Tools[i], "R2 Shell")) {
			addMenu (core, parent, menus_Tools[i], r2shellCb);
		} else if (!strcmp (menus_Tools[i], "System Shell")) {
			addMenu (core, parent, menus_Tools[i], systemShellCb);
		}
		i++;
	}

	parent = "Search";
	i = 0;
	while (menus_Search[i]) {
		if (!strcmp (menus_Search[i], "String")) {
			addMenu (core, parent, menus_Search[i], stringCb);
		} else if (!strcmp (menus_Search[i], "ROP")) {
			addMenu (core, parent, menus_Search[i], ropCb);
		} else if (!strcmp (menus_Search[i], "Code")) {
			addMenu (core, parent, menus_Search[i], codeCb);
		} else if (!strcmp (menus_Search[i], "Hexpairs")) {
			addMenu (core, parent, menus_Search[i], hexpairsCb);
		}
		i++;
	}

	parent = "Debug";
	i = 0;
	while (menus_Debug[i]) {
		if (!strcmp (menus_Debug[i], "Breakpoints")) {
			addMenu (core, parent, menus_Debug[i], breakpointsCb);
		} else if (!strcmp (menus_Debug[i], "Watchpoints")) {
			addMenu (core, parent, menus_Debug[i], watchpointsCb);
		} else if (!strcmp (menus_Debug[i], "Continue")) {
			addMenu (core, parent, menus_Debug[i], continueCb);
		} else if (!strcmp (menus_Debug[i], "Step")) {
			addMenu (core, parent, menus_Debug[i], stepCb);
		} else if (!strcmp (menus_Debug[i], "Step Over")) {
			addMenu (core, parent, menus_Debug[i], stepoverCb);
		} else if (!strcmp (menus_Debug[i], "Reload")) {
			addMenu (core, parent, menus_Debug[i], reloadCb);
		} else {
			addMenu (core, parent, menus_Debug[i], addCmdPanel);
		}
		i++;
	}

	parent = "Analyze";
	i = 0;
	while (menus_Analyze[i]) {
		if (!strcmp (menus_Analyze[i], "Function")) {
			addMenu (core, parent, menus_Analyze[i], functionCb);
		} else if (!strcmp (menus_Analyze[i], "Symbols")) {
			addMenu (core, parent, menus_Analyze[i], symbolsCb);
		} else if (!strcmp (menus_Analyze[i], "Program")) {
			addMenu (core, parent, menus_Analyze[i], programCb);
		} else if (!strcmp (menus_Analyze[i], "BasicBlocks")) {
			addMenu (core, parent, menus_Analyze[i], basicblocksCb);
		} else if (!strcmp (menus_Analyze[i], "Calls")) {
			addMenu (core, parent, menus_Analyze[i], callsCb);
		} else if (!strcmp (menus_Analyze[i], "References")) {
			addMenu (core, parent, menus_Analyze[i], referencesCb);
		}
		i++;
	}

	parent = "Fun";
	i = 0;
	while (menus_Fun[i]) {
		if (!strcmp (menus_Fun[i], "Fortune")) {
			addMenu (core, parent, menus_Fun[i], fortuneCb);
		} else if (!strcmp (menus_Fun[i], "2048")) {
			addMenu (core, parent, menus_Fun[i], gameCb);
		}
		i++;
	}

	parent = "About";
	i = 0;
	while (menus_About[i]) {
		if (!strcmp (menus_About[i], "License")) {
			addMenu (core, parent, menus_About[i], licenseCb);
		} else if (!strcmp (menus_About[i], "Version")) {
			addMenu (core, parent, menus_About[i], versionCb);
		}
		i++;
	}

	parent = "Help";
	i = 0;
	while (menus_Help[i]) {
		if (!strcmp (menus_Help[i], "Toggle Help")) {
			addMenu (core, parent, menus_Help[i], helpCb);
		}
		i++;
	}

	parent = "File.ReOpen";
	i = 0;
	while (menus_ReOpen[i]) {
		if (!strcmp (menus_ReOpen[i], "In RW")) {
			addMenu (core, parent, menus_ReOpen[i], rwCb);
		} else if (!strcmp (menus_ReOpen[i], "In Debugger")) {
			addMenu (core, parent, menus_ReOpen[i], debuggerCb);
		}
		i++;
	}

	parent = "File.Load Layout";
	i = 0;
	while (menus_loadLayout[i]) {
		if (!strcmp (menus_loadLayout[i], "Saved")) {
			addMenu (core, parent, menus_loadLayout[i], loadLayoutSavedCb);
		} else if (!strcmp (menus_loadLayout[i], "Default")) {
			addMenu (core, parent, menus_loadLayout[i], loadLayoutDefaultCb);
		}
		i++;
	}

	parent = "Edit.io.cache";
	i = 0;
	while (menus_iocache[i]) {
		if (!strcmp (menus_iocache[i], "On")) {
			addMenu (core, parent, menus_iocache[i], ioCacheOnCb);
		} else if (!strcmp (menus_iocache[i], "Off")) {
			addMenu (core, parent, menus_iocache[i], ioCacheOffCb);
		}
		i++;
	}

	parent = "View.Colors";
	i = 0;
	while (menus_Colors[i]) {
		addMenu (core, parent, menus_Colors[i], colorsCb);
		i++;
	}

	panelsMenu->history = calloc (8, sizeof (RPanelsMenuItem *));
	clearPanelsMenu (core);
	panelsMenu->refreshPanels = calloc (8, sizeof (RPanel *));
	return true;
}

static void clearPanelsMenuRec(RPanelsMenuItem *pmi) {
	int i = 0;
	for(i = 0; i < pmi->n_sub; i++) {
		RPanelsMenuItem *sub = pmi->sub[i];
		if (sub) {
			sub->selectedIndex = 0;
			clearPanelsMenuRec (sub);
		}
	}
}

static void clearPanelsMenu(RCore *core) {
	RPanels *p = core->panels;
	RPanelsMenu *pm = p->panelsMenu;
	clearPanelsMenuRec (pm->root);
	pm->root->selectedIndex = 0;
	pm->history[0] = pm->root;
	pm->depth = 1;
	pm->n_refresh = 0;
}

static bool initPanels(RCore *core, RPanels *panels) {
	panels->panel = calloc (sizeof (RPanel *), PANEL_NUM_LIMIT);
	if (!panels->panel) {
		return false;
	}
	int i;
	for (i = 0; i < PANEL_NUM_LIMIT; i++) {
		panels->panel[i] = R_NEW0 (RPanel);
		panels->panel[i]->model = R_NEW0 (RPanelModel);
		renew_filter (panels->panel[i], PANEL_NUM_LIMIT);
		panels->panel[i]->view = R_NEW0 (RPanelView);
		if (!panels->panel[i]->model || !panels->panel[i]->view) {
			return false;
		}
	}
	return true;
}

static void freePanelModel(RPanel *panel) {
	free (panel->model->title);
	free (panel->model->cmd);
	free (panel->model->cmdStrCache);
	free (panel->model->readOnly);
	free (panel->model);
}

static void freePanelView(RPanel *panel) {
	free (panel->view);
}

static void freeSinglePanel(RPanel *panel) {
	freePanelModel (panel);
	freePanelView (panel);
	free (panel);
}

static void freeAllPanels(RPanels *panels) {
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = getPanel (panels, i);
		freeSinglePanel (p);
	}
	free (panels->panel);
}

static void refreshCoreOffset (RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
	if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		core->offset = cur->model->addr;
	}
}

static void panels_refresh(RCore *core) {
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
	refreshCoreOffset (core);
	r_cons_gotoxy (0, 0);
	if (panels->isResizing || (can->w != w || can->h != h)) {
		panels->isResizing = false;
		if (!r_cons_canvas_resize (can, w, h)) {
			return;
		}
		setRefreshAll (panels, false);
	}
	fitToCanvas (panels);
	//TODO use getPanel
	for (i = 0; i < panels->n_panels; i++) {
		if (i != panels->curnode) {
			panelPrint (core, can, getPanel (panels, i), 0);
		}
	}
	if (panels->mode == PANEL_MODE_MENU) {
		panelPrint (core, can, getCurPanel (panels), 0);
	} else {
		panelPrint (core, can, getCurPanel (panels), 1);
	}
	for (i = 0; i < panels->panelsMenu->n_refresh; i++) {
		panelPrint (core, can, panels->panelsMenu->refreshPanels[i], 1);
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
				snprintf (str, sizeof (title) - 1, "%s[%s] "Color_RESET, color, item->name);
			} else {
				snprintf (str, sizeof (title) - 1, "%s  ", item->name);
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
		printSnow (panels);
	}

	r_cons_canvas_print (can);
	if (core->scr_gadgets) {
		r_core_cmd0 (core, "pg");
	}
	r_cons_flush ();
}

static void doPanelsRefresh(RCore *core) {
	if (!core->panels) {
		return;
	}
	core->panels->isResizing = true;
	panelAllClear (core->panels);
	panels_refresh (core);
}

static void doPanelsRefreshOneShot(RCore *core) {
	r_core_task_enqueue_oneshot (core, (RCoreTaskOneShot) doPanelsRefresh, core);
}

static void panelSingleStepIn(RCore *core) {
	if (r_config_get_i (core->config, "cfg.debug")) {
		r_core_cmd (core, "ds", 0);
		r_core_cmd (core, ".dr*", 0);
	} else {
		r_core_cmd (core, "aes", 0);
		r_core_cmd (core, ".ar*", 0);
	}
}

static void panelSingleStepOver(RCore *core) {
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

static void panelBreakpoint(RCore *core) {
	RPanel *cur = getCurPanel (core->panels);
	if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		r_core_cmd (core, "dbs $$", 0);
		cur->view->refresh = true;
	}
}

static void panelContinue(RCore *core) {
	r_core_cmd (core, "dc", 0);
}

static void panels_check_stackbase(RCore *core) {
	if (!core || !core->panels) {
		return;
	}
	int i;
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	const ut64 stackbase = r_reg_getv (core->anal->reg, sp);
	RPanels *panels = core->panels;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *panel = getPanel (panels, i);
		if (panel->model->cmd && check_panel_type (panel, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK)) && panel->model->baseAddr != stackbase) {
			panel->model->baseAddr = stackbase;
			panel->model->addr = stackbase - r_config_get_i (core->config, "stack.delta") + core->print->cur;
			panel->view->refresh = true;
		}
	}
}

static void panelPrompt(const char *prompt, char *buf, int len) {
	r_line_set_prompt (prompt);
	*buf = 0;
	r_cons_fgets (buf, len, 0, NULL);
}

static void initRotatedb(RPanels *panels) {
	sdb_ptr_set (panels->rotate_db, "pd", &rotateDisasCb, 0);
	sdb_ptr_set (panels->rotate_db, "p==", &rotateEntropyHCb, 0);
	sdb_ptr_set (panels->rotate_db, "p=", &rotateEntropyVCb, 0);
	sdb_ptr_set (panels->rotate_db, "px", &rotateHexdumpCb, 0);
	sdb_ptr_set (panels->rotate_db, "dr", &rotateRegisterCb, 0);
	sdb_ptr_set (panels->rotate_db, "af", &rotateFunctionCb, 0);
}

static void initSdb(RPanels *panels) {
	sdb_set (panels->db, "Symbols", "isq", 0);
	sdb_set (panels->db, "Stack"  , "px 256@r:SP", 0);
	sdb_set (panels->db, "Locals", "afvd", 0);
	sdb_set (panels->db, "Registers", "dr", 0);
	sdb_set (panels->db, "Disassembly", "pd", 0);
	sdb_set (panels->db, "Decompiler", "pdc", 0);
	sdb_set (panels->db, "Graph", "agf", 0);
	sdb_set (panels->db, "Info", "i", 0);
	sdb_set (panels->db, "Database", "k ***", 0);
	sdb_set (panels->db, "Hexdump", "xc", 0);
	sdb_set (panels->db, "Functions", "afl", 0);
	sdb_set (panels->db, "Comments", "CC", 0);
	sdb_set (panels->db, "Entropy", "p=e", 0);
	sdb_set (panels->db, "Entropy Fire", "p==e", 0);
	sdb_set (panels->db, "DRX", "drx", 0);
	sdb_set (panels->db, "Sections", "iSq", 0);
	sdb_set (panels->db, "Strings", "izq", 0);
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

static void mht_free_kv(HtPPKv *kv) {
	free (kv->key);
	free (kv->value);
}

static bool init(RCore *core, RPanels *panels, int w, int h) {
	panels->panel = NULL;
	panels->n_panels = 0;
	panels->columnWidth = 80;
	if (r_config_get_i (core->config, "cfg.debug")) {
		panels->layout = PANEL_LAYOUT_DEFAULT_DYNAMIC;
	} else {
		panels->layout = PANEL_LAYOUT_DEFAULT_STATIC;
	}
	panels->isResizing = false;
	panels->autoUpdate = true;
	panels->can = createNewCanvas (core, w, h);
	panels->db = sdb_new0 ();
	panels->rotate_db = sdb_new0 ();
	panels->mht = ht_pp_new (NULL, (HtPPKvFreeFunc)mht_free_kv, (HtPPCalcSizeV)strlen);
	setMode (panels, PANEL_MODE_DEFAULT);
	panels->fun = PANEL_FUN_NOFUN;
	panels->prevMode = PANEL_MODE_DEFAULT;
	panels->name = NULL;
	initSdb (panels);
	initRotatedb (panels);

	if (w < 140) {
		panels->columnWidth = w / 3;
	}
	return true;
}

static int file_history_up(RLine *line) {
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

static int file_history_down(RLine *line) {
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

static bool handleMenu(RCore *core, const int key) {
	RPanels *panels = core->panels;
	RPanelsMenu *menu = panels->panelsMenu;
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
				setRefreshAll (panels, false);
				menu->root->sub[menu->root->selectedIndex]->cb (core);
			}
		} else {
			removeMenu (panels);
		}
		break;
	case 'j':
		{
			if (menu->depth == 1) {
				RPanelsMenuItem *parent = menu->history[menu->depth - 1];
				parent->sub[parent->selectedIndex]->cb(core);
			} else {
				RPanelsMenuItem *parent = menu->history[menu->depth - 1];
				parent->selectedIndex = R_MIN (parent->n_sub - 1, parent->selectedIndex + 1);
				moveMenuCursor (core, menu, parent);
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
				moveMenuCursor (core, menu, parent);
			} else if (menu->depth == 2) {
				menu->depth--;
				setRefreshAll (panels, false);
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
			RPanelsMenuItem *child = menu->history[menu->depth - 1];
			if (child->sub[child->selectedIndex]->sub) {
				child->sub[child->selectedIndex]->cb (core);
			} else {
				menu->root->selectedIndex++;
				menu->root->selectedIndex %= menu->root->n_sub;
				menu->depth = 1;
				setRefreshAll (panels, false);
				menu->root->sub[menu->root->selectedIndex]->cb (core);
			}
		}
		break;
	case 'm':
	case 'q':
	case 'Q':
	case -1:
		if (panels->panelsMenu->depth > 1) {
			removeMenu (panels);
		} else {
			setMode (panels, PANEL_MODE_DEFAULT);
			getCurPanel (panels)->view->refresh = true;
		}
		break;
	case '$':
		r_core_cmd0 (core, "dr PC=$$");
		break;
	case ' ':
	case '\r':
	case '\n':
		{
			RPanelsMenuItem *parent = menu->history[menu->depth - 1];
			RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
			if (child->cb (core)) {
				return false;
			}
		}
		break;
	case 9:
		handleTabKey (core, false);
		break;
	case 'Z':
		handleTabKey (core, true);
		break;
	case ':':
		handlePrompt (core, panels);
		break;
	case '?':
		toggleHelp (core);
		break;
	}
	return true;
}

static void handleTabKey(RCore *core, bool shift) {
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
	r_cons_switchbuf (false);
	cur->view->refresh = true;
	if (!shift) {
		if (panels->mode == PANEL_MODE_MENU) {
			panels->curnode = 0;
			setMode (panels, PANEL_MODE_DEFAULT);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			if (panels->curnode == panels->n_panels - 1) {
				panels->curnode = 0;
			} else {
				panels->curnode++;
			}
		} else {
			if (panels->curnode == panels->n_panels - 1) {
				panels->curnode = 0;
			} else {
				panels->curnode++;
			}
		}
	} else {
		if (panels->mode == PANEL_MODE_MENU) {
			panels->curnode = panels->n_panels - 1;
			setMode (panels, PANEL_MODE_DEFAULT);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			if (panels->curnode) {
				panels->curnode--;
			} else {
				panels->curnode = panels->n_panels - 1;
			}
		} else {
			if (panels->curnode) {
				panels->curnode--;
			} else {
				panels->curnode = panels->n_panels - 1;
			}
		}
	}
	cur = getCurPanel (panels);
	if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		setRefreshAll (panels, false);
		return;
	}
	cur->view->refresh = true;
	if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
		resetSnow (panels);
	}
}

static void savePanelPos(RPanel* panel) {
	panel->view->prevPos.x = panel->view->pos.x;
	panel->view->prevPos.y = panel->view->pos.y;
	panel->view->prevPos.w = panel->view->pos.w;
	panel->view->prevPos.h = panel->view->pos.h;
}

static void restorePanelPos(RPanel* panel) {
	panel->view->pos.x = panel->view->prevPos.x;
	panel->view->pos.y = panel->view->prevPos.y;
	panel->view->pos.w = panel->view->prevPos.w;
	panel->view->pos.h = panel->view->prevPos.h;
}

static char *getPanelsConfigPath() {
	char *configPath = r_str_new (R_JOIN_2_PATHS (R2_HOME_DATADIR, ".r2panels"));
	if (!configPath) {
		return NULL;
	}
	char *newPath = r_str_home (configPath);
	R_FREE (configPath);
	return newPath;
}

static void savePanelsLayout(RPanels* panels) {
	int i;
	PJ *pj = NULL;
	pj = pj_new ();
	pj_a (pj);
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = getPanel (panels, i);
		pj_o (pj);
		pj_ks (pj, "Title", panel->model->title);
		pj_ks (pj, "Cmd", panel->model->cmd);
		pj_kn (pj, "x", panel->view->pos.x);
		pj_kn (pj, "y", panel->view->pos.y);
		pj_kn (pj, "w", panel->view->pos.w);
		pj_kn (pj, "h", panel->view->pos.h);
		pj_kb (pj, "cache", panel->model->cache);
		pj_end (pj);
	}
	pj_end (pj);
	char *configPath = getPanelsConfigPath ();
	FILE *panelsConfig = r_sandbox_fopen (configPath, "w");
	free (configPath);
	if (panelsConfig) {
		fprintf (panelsConfig, "%s", pj_string (pj));
		fclose (panelsConfig);
	}
	pj_free (pj);
}

static char *parsePanelsConfig(const char *cfg, int len) {
	if (!cfg || !*cfg || len < 2 || *cfg != '[') {
		eprintf ("Not valid config!\n");
		return NULL;
	}
	char *tmp = r_str_new (cfg + 1);
	int i = 0;
	for (; i < len; i++) {
		if (tmp[i] == '}' && i + 1 < len) {
			if (tmp[i + 1] == ',') {
				tmp[i + 1] = '\n';
				continue;
			}
			if (tmp[i + 1] == ']') {
				tmp[i + 1] = '\n';
				break;
			}
			eprintf ("Not valid config!\n");
			free (tmp);
			return NULL;
		}
	}
	return tmp;
}

static void load_config_menu(RCore *core) {
	RList *themes_list = r_core_list_themes (core);
	RListIter *th_iter;
	const char *th;
	int i = 0;
	r_list_foreach (themes_list, th_iter, th) {
		menus_Colors[i++] = th;
	}
}

static int loadSavedPanelsLayout(RCore *core) {
	int i, s;
	char *panelsConfig;

	char *configPath = getPanelsConfigPath ();
	panelsConfig = r_file_slurp (configPath, &s);
	free (configPath);
	if (!panelsConfig) {
		free (panelsConfig);
		return 0;
	}
	char *parsedConfig = parsePanelsConfig (panelsConfig, strlen (panelsConfig));
	free (panelsConfig);
	if (!parsedConfig) {
		return 0;
	}
	int count = r_str_split (parsedConfig, '\n');
	RPanels *panels = core->panels;
	panelAllClear (panels);
	panels->n_panels = 0;
	panels->curnode = 0;
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
		RPanel *p = getPanel (panels, panels->n_panels);
		p->view->pos.x = atoi (x);
		p->view->pos.y = atoi (y);
		p->view->pos.w = atoi (w);
		p->view->pos.h = atoi (h);
		buildPanelParam (core, p, title, cmd, cache);
		//TODO: Super hacky and refactoring is needed
		if (r_str_endswith (cmd, "Help")) {
			p->model->title = r_str_dup (p->model->title, "Help");
			p->model->cmd = r_str_dup (p->model->cmd, "Help");
			RStrBuf *rsb = r_strbuf_new (NULL);
			r_core_visual_append_help (rsb, "Visual Ascii Art Panels", help_msg_panels);
			if (!rsb) {
				return 0;
			}
			setReadOnly (p, r_strbuf_drain (rsb));
		}
		p_cfg += strlen (p_cfg) + 1;
	}
	free (parsedConfig);
	if (!panels->n_panels) {
		return 0;
	}
	setRefreshAll (core->panels, true);
	return 1;
}

static void maximizePanelSize(RPanels *panels) {
	RPanel *cur = getCurPanel (panels);
	cur->view->pos.x = 0;
	cur->view->pos.y = 1;
	cur->view->pos.w = panels->can->w;
	cur->view->pos.h = panels->can->h - 1;
	cur->view->refresh = true;
}

static void toggleZoomMode(RPanels *panels) {
	RPanel *cur = getCurPanel (panels);
	if (panels->mode != PANEL_MODE_ZOOM) {
		panels->prevMode = panels->mode;
		setMode (panels, PANEL_MODE_ZOOM);
		savePanelPos (cur);
		maximizePanelSize (panels);
	} else {
		setMode (panels, panels->prevMode);
		panels->prevMode = PANEL_MODE_DEFAULT;
		restorePanelPos (cur);
		setRefreshAll (panels, false);
		if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
			resetSnow (panels);
		}
	}
}

static void toggleWindowMode(RPanels *panels) {
	if (panels->mode != PANEL_MODE_WINDOW) {
		panels->prevMode = panels->mode;
		setMode (panels, PANEL_MODE_WINDOW);
	} else {
		setMode (panels, panels->prevMode);
		panels->prevMode = PANEL_MODE_DEFAULT;
	}
}

static void toggleCache (RPanel *p) {
	p->model->cache = !p->model->cache;
	setCmdStrCache (p, NULL);
	p->view->refresh = true;
}

static void toggleHelp(RCore *core) {
	RPanels *ps = core->panels;
	int i;
	for (i = 0; i < ps->n_panels; i++) {
		RPanel *p = getPanel (ps, i);
		if (r_str_endswith (p->model->cmd, "Help")) {
			dismantleDelPanel (ps, p, i);
			if (ps->mode == PANEL_MODE_MENU) {
				setMode (ps, PANEL_MODE_DEFAULT);
			}
			setRefreshAll (ps, false);
			return;
		}
	}
	addHelpPanel (core);
	if (ps->mode == PANEL_MODE_MENU) {
		setMode (ps, PANEL_MODE_DEFAULT);
	}
	updateHelp (ps);
}

static void insertValue(RCore *core) {
	if (!r_config_get_i (core->config, "io.cache")) {
		if (show_status_yesno (core, 'y', "Insert is not available because io.cache is off. Turn on now?(Y/n)")) {
			r_config_set_i (core->config, "io.cache", 1);
			(void)show_status (core, "io.cache is on and insert is available now.");
		} else {
			(void)show_status (core, "You can always turn on io.cache in Menu->Edit->io.cache");
			return;
		}
	}
	RPanels *panels = core->panels;
	RPanel *cur = getCurPanel (panels);
	char buf[128];
	if (check_panel_type (cur, PANEL_CMD_STACK, strlen (PANEL_CMD_STACK))) {
		const char *prompt = "insert hex: ";
		panelPrompt (prompt, buf, sizeof (buf));
		r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, cur->model->addr);
		cur->view->refresh = true;
	} else if (check_panel_type (cur, PANEL_CMD_REGISTERS, strlen (PANEL_CMD_REGISTERS))) {
		const char *creg = core->dbg->creg;
		if (creg) {
			const char *prompt = "new-reg-value> ";
			panelPrompt (prompt, buf, sizeof (buf));
			r_core_cmdf (core, "dr %s = %s", creg, buf);
			cur->view->refresh = true;
		}
	} else if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY)) &&
					strcmp (cur->model->cmd, "pdc")) {
		const char *prompt = "insert hex: ";
		panelPrompt (prompt, buf, sizeof (buf));
		r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, core->offset + core->print->cur);
		cur->view->refresh = true;
	} else if (check_panel_type (cur, PANEL_CMD_HEXDUMP, strlen (PANEL_CMD_HEXDUMP))) {
		const char *prompt = "insert hex: ";
		panelPrompt (prompt, buf, sizeof (buf));
		r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, cur->model->addr + core->print->cur);
		cur->view->refresh = true;
	}
}

static RPanels *panels_new(RCore *core) {
	RPanels *panels = R_NEW0 (RPanels);
	if (!panels) {
		return NULL;
	}
	int h, w = r_cons_get_size (&h);
	if (!init (core, panels, w, h)) {
		free (panels);
		return NULL;
	}
	return panels;
}

static void renew_filter(RPanel *panel, int n) {
	panel->model->n_filter = 0;
	char **filter = calloc (sizeof (char *), n);
	if (!filter) {
		panel->model->filter = NULL;
		return;
	}
	panel->model->filter = filter;
}

static void panels_free(RPanelsRoot *panels_root, int i, RPanels *panels) {
	r_cons_switchbuf (true);
	if (panels) {
		freeAllPanels (panels);
		r_cons_canvas_free (panels->can);
		sdb_free (panels->db);
		sdb_free (panels->rotate_db);
		ht_pp_free (panels->mht);
		free (panels);
		panels_root->panels[i] = NULL;
	}
}

static bool moveToDirection(RPanels *panels, Direction direction) {
	RPanel *cur = getCurPanel (panels);
	int cur_x0 = cur->view->pos.x, cur_x1 = cur->view->pos.x + cur->view->pos.w - 1, cur_y0 = cur->view->pos.y, cur_y1 = cur->view->pos.y + cur->view->pos.h - 1;
	int temp_x0, temp_x1, temp_y0, temp_y1;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = getPanel (panels, i);
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
				panels->curnode = i;
				return true;
			}
			break;
		case RIGHT:
			if (temp_x0 == cur_x1) {
				if (temp_y1 <= cur_y0 || cur_y1 <= temp_y0) {
					continue;
				}
				panels->curnode = i;
				return true;
			}
			break;
		case UP:
			if (temp_y1 == cur_y0) {
				if (temp_x1 <= cur_x0 || cur_x1 <= temp_x0) {
					continue;
				}
				panels->curnode = i;
				return true;
			}
			break;
		case DOWN:
			if (temp_y0 == cur_y1) {
				if (temp_x1 <= cur_x0 || cur_x1 <= temp_x0) {
					continue;
				}
				panels->curnode = i;
				return true;
			}
			break;
		default:
			break;
		}
	}
	return false;
}

static void createNewPanel(RCore *core, bool vertical) {
	RPanels *panels = core->panels;
	if (!checkPanelNum (core)) {
		return;
	}
	char *name = show_status_input (core, "Name: ");
	char *res = show_status_input (core, "Command: ");
	if (R_STR_ISEMPTY (res)) {
		return;
	}
	bool cache = show_status_yesno (core, 'y', "Cache the result? (Y/n)");
	if (vertical) {
		splitPanelVertical (core, getCurPanel (panels), name, res, cache);
	} else {
		splitPanelHorizontal (core, getCurPanel (panels), name, res, cache);
	}
	free (res);
}

static void createDefaultPanels(RCore *core) {
	RPanels *panels = core->panels;
	panels->curnode = 0;
	panels->n_panels = 0;
	const char **panels_list = panels_static;
	if (panels->layout == PANEL_LAYOUT_DEFAULT_DYNAMIC) {
		panels_list = panels_dynamic;
	}

	int i = 0;
	while (panels_list[i]) {
		RPanel *p = getPanel (panels, panels->n_panels);
		if (!p) {
			return;
		}
		const char *s = panels_list[i++];
		buildPanelParam (core, p, s, sdb_get (panels->db, s, 0), 0);
	}
}

static void rotatePanels(RPanels *panels, bool rev) {
	RPanel *first = getPanel (panels, 0);
	RPanel *last = getPanel (panels, panels->n_panels - 1);
	int i;
	RPanelModel *tmp_model;
	if (!rev) {
		tmp_model = first->model;
		for (i = 0; i < panels->n_panels - 1; i++) {
			RPanel *p0 = getPanel (panels, i);
			RPanel *p1 = getPanel (panels, i + 1);
			p0->model = p1->model;
		}
		last->model = tmp_model;
	} else {
		tmp_model = last->model;
		for (i = panels->n_panels - 1; i > 0; i--) {
			RPanel *p0 = getPanel (panels, i);
			RPanel *p1 = getPanel (panels, i - 1);
			p0->model = p1->model;
		}
		first->model = tmp_model;
	}
	setRefreshAll (panels, false);
}

static void rotateDisasCb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	RPanel *p = getCurPanel (core->panels);

	//TODO: need to come up with a better solution but okay for now
	if (!strcmp (p->model->cmd, "pdc")) {
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
	rotateAsmemu (core, p);
}

static void rotatePanelCmds(RCore *core, const char **cmds, const int cmdslen, const char *prefix, bool rev) {
	if (!cmdslen) {
		return;
	}
	RPanel *p = getCurPanel (core->panels);
	reset_filter (p);
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
	setCmdStrCache (p, NULL);
	p->view->refresh = true;
}

static void rotateEntropyVCb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	rotatePanelCmds (core, entropy_rotate, COUNT (entropy_rotate), "p=", rev);
}

static void rotateEntropyHCb(void *user, bool rev) {
	RCore *core = (RCore *)user;
	rotatePanelCmds (core, entropy_rotate, COUNT (entropy_rotate), "p==", rev);
}

static void rotateHexdumpCb (void *user, bool rev) {
	RCore *core = (RCore *)user;
	rotatePanelCmds (core, hexdump_rotate, COUNT (hexdump_rotate), "px", rev);
}

static void rotateRegisterCb (void *user, bool rev) {
	RCore *core = (RCore *)user;
	rotatePanelCmds (core, register_rotate, COUNT (register_rotate), "dr", rev);
}

static void rotateFunctionCb (void *user, bool rev) {
	RCore *core = (RCore *)user;
	rotatePanelCmds (core, function_rotate, COUNT (function_rotate), "af", rev);
}

static void undoSeek(RCore *core) {
	RPanel *cur = getCurPanel (core->panels);
	if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		return;
	}
	RIOUndos *undo = r_io_sundo (core->io, core->offset);
	if (undo) {
		r_core_visual_seek_animation (core, undo->off);
		cur->model->addr = core->offset;
		cur->view->refresh = true;
	}
}

static void set_filter(RCore *core, RPanel *panel) {
	if (!panel->model->filter) {
		return;
	}
	char *input = show_status_input (core, "filter word: ");
	if (input) {
		panel->model->filter[panel->model->n_filter++] = input;
		setCmdStrCache (panel, NULL);
		panel->view->refresh = true;
	}
	resetScrollPos (panel);
}

static void reset_filter(RPanel *panel) {
	free (panel->model->filter);
	panel->model->filter = NULL;
	renew_filter (panel, PANEL_NUM_LIMIT);
	setCmdStrCache (panel, NULL);
	panel->view->refresh = true;
	resetScrollPos (panel);
}

static void redoSeek(RCore *core) {
	RPanel *cur = getCurPanel (core->panels);
	if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
		return;
	}
	RIOUndos *undo = r_io_sundo_redo (core->io);
	if (undo) {
		r_core_visual_seek_animation (core, undo->off);
		cur->model->addr = core->offset;
		cur->view->refresh = true;
	}
}

static void rotateAsmemu(RCore *core, RPanel *p) {
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
		panels_root->n_panels = 1;
		panels_root->cur_panels = 0;
	} else {
		if (!panels_root->n_panels) {
			panels_root->n_panels = 1;
			panels_root->cur_panels = 0;
		}
	}
	bool force_quit = false;
	while (panels_root->n_panels) {
		if (panels_process (core, &(panels_root->panels[panels_root->cur_panels]), &force_quit)) {
			if (force_quit) {
				return true;
			} else {
				if (panels_root->n_panels > 1) {
					remove_panels (core);
				} else {
					return true;
				}
			}
		}
	}
	return true;
}

static void remove_panels(RCore *core) {
	RPanelsRoot *panels_root = core->panels_root;
	panels_free (panels_root, panels_root->cur_panels, get_cur_panels (panels_root));
	int i;
	for (i = panels_root->cur_panels; i < panels_root->n_panels - 1; i++) {
		panels_root->panels[i] = panels_root->panels[i + 1];
	}
	panels_root->n_panels--;
	if (panels_root->cur_panels >= panels_root->n_panels) {
		panels_root->cur_panels = panels_root->n_panels - 1;
	}
}

static RPanels *get_panels(RPanelsRoot *panels_root, int i) {
	if (i >= PANEL_NUM_LIMIT) {
		return NULL;
	}
	return panels_root->panels[i];
}

static RPanels *get_cur_panels(RPanelsRoot *panels_root) {
	return get_panels (panels_root, panels_root->cur_panels);
}

static bool handle_tab(RCore *core) {
	r_cons_gotoxy (0, 0);
	if (core->panels_root->n_panels <= 1) {
		r_cons_printf (R_CONS_CLEAR_LINE"%s[Tab] t:new -:del =:name"Color_RESET, core->cons->context->pal.graph_box2);
	} else {
		int min = 1;
		int max = core->panels_root->n_panels;
		r_cons_printf (R_CONS_CLEAR_LINE"%s[Tab] [%d..%d]:select; p:prev; n:next; t:new -:del =:name"Color_RESET, core->cons->context->pal.graph_box2, min, max);
	}
	r_cons_flush ();
	int ch = r_cons_readchar ();
	if (handle_tab_nth (core, ch)) {
		return true;
	}
	switch (ch) {
	case 'n':
		return handle_tab_next (core);
	case 'p':
		return handle_tab_prev (core);
	case '-':
		return handle_tab_del (core);
	case '=':
		handle_tab_name (core);
		break;
	case 't':
		handle_tab_new (core);
	}
	return false;
}

static bool handle_tab_nth(RCore *core, int ch) {
	if (isdigit (ch)) {
		ch -= '0' + 1;
		if (ch < 0) {
			return  false;
		}
		if (ch != core->panels_root->cur_panels && ch < core->panels_root->n_panels) {
			core->panels_root->cur_panels = ch;
			return true;
		}
	}
	return false;
}

static bool handle_tab_next(RCore *core) {
	if (core->panels_root->n_panels <= 1) {
		return false;
	}
	core->panels_root->cur_panels++;
	core->panels_root->cur_panels %= core->panels_root->n_panels;
	return true;
}


static bool handle_tab_prev(RCore *core) {
	if (core->panels_root->n_panels <= 1) {
		return false;
	}
	core->panels_root->cur_panels--;
	if (core->panels_root->cur_panels < 0) {
		core->panels_root->cur_panels = core->panels_root->n_panels - 1;
	}
	return true;
}

static bool handle_tab_del(RCore *core) {
	core->panels_root->n_panels--;
	return true;
}

static void handle_tab_name(RCore *core) {
	core->panels->name = show_status_input (core, "tab name: ");
}

static void handle_tab_new(RCore *core) {
	if (core->panels_root->n_panels >= PANEL_NUM_LIMIT) {
		return;
	}
	core->panels_root->n_panels++;
}

static int panels_process(RCore *core, RPanels **r_panels, bool *force_quit) {
	int i, okey, key;
	bool first_load = !*r_panels;
	RPanelsRoot *panels_root = core->panels_root;
	RPanels *panels;
	RPanels *prev;
	if (!*r_panels) {
		panels = panels_new (core);
		if (!panels) {
			return true;
		}
		prev = core->panels;
		core->panels = panels;
		if (!initPanelsMenu (core)) {
			return true;
		}
		if (!initPanels (core, panels)) {
			return true;
		}
		*r_panels = panels;
	} else {
		prev = core->panels;
		panels = *r_panels;
		core->panels = panels;
		updateAddr (core);
	}

	r_cons_switchbuf (false);

	int originCursor = core->print->cur;
	core->print->cur = 0;
	core->print->cur_enabled = false;
	core->print->col = 0;

	bool originVmode = core->vmode;
	core->vmode = true;

	r_cons_enable_mouse (false);

	if (first_load) {
		createDefaultPanels (core);
		panels_layout (panels);
	}
repeat:
	r_cons_enable_mouse (r_config_get_i (core->config, "scr.wheel"));
	core->panels = panels;
	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = core;
	core->cons->event_resize = (RConsEvent) doPanelsRefreshOneShot;
	panels_layout_refresh (core);
	RPanel *cur = getCurPanel (panels);
	if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
		if (panels->mode != PANEL_MODE_MENU) {
			okey = r_cons_readchar_timeout (300);
			if (okey == -1) {
				cur->view->refresh = true;
				goto repeat;
			}
		} else {
			panels->fun = PANEL_FUN_NOFUN;
			resetSnow (panels);
			setRefreshAll (panels, false);
			goto repeat;
		}
	} else {
		okey = r_cons_readchar ();
	}
	key = r_cons_arrow_to_hjkl (okey);
	r_cons_switchbuf (true);

	if (panels->mode == PANEL_MODE_MENU) {
		if (!handleMenu (core, key)) {
			goto exit;
		}
		goto repeat;
	}

	if (core->print->cur_enabled) {
		if (handleCursorMode (core, key)) {
			goto repeat;
		}
	}

	if (panels->mode == PANEL_MODE_ZOOM) {
		if (handleZoomMode (core, key)) {
			goto repeat;
		}
	}

	if (panels->mode == PANEL_MODE_WINDOW) {
		if (handleWindowMode (core, key)) {
			goto repeat;
		}
	}

	if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY)) && '0' < key && key <= '9') {
		ut8 ch = key;
		r_core_visual_jump (core, ch);
		cur->model->addr = core->offset;
		cur->view->refresh = true;
		goto repeat;
	}

	const char *cmd;
	RConsCanvas *can = panels->can;
	switch (key) {
	case 'u':
		undoSeek (core);
		break;
	case 'U':
		redoSeek (core);
		break;
	case 'p':
		rotatePanels (panels, false);
		break;
	case 'P':
		rotatePanels (panels, true);
		break;
	case '.':
		if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			ut64 addr = r_debug_reg_get (core->dbg, "PC");
			if (addr && addr != UT64_MAX) {
				r_core_seek (core, addr, 1);
			} else {
				addr = r_num_get (core->num, "entry0");
				if (addr && addr != UT64_MAX) {
					r_core_seek (core, addr, 1);
				}
			}
			cur->model->addr = core->offset;
			cur->view->refresh = true;
		}
		break;
	case '?':
		toggleHelp (core);
		break;
	case 'b':
		r_core_visual_browse (core, NULL);
		break;
	case ';':
		handleComment (core);
		break;
	case 's':
		panelSingleStepIn (core);
		if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			cur->model->addr = core->offset;
		}
		setRefreshAll (panels, false);
		break;
	case 'S':
		panelSingleStepOver (core);
		if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			cur->model->addr = core->offset;
		}
		setRefreshAll (panels, false);
		break;
	case ' ':
		if (r_config_get_i (core->config, "graph.web")) {
			r_core_cmd0 (core, "agv $$");
		} else {
			callVisualGraph (core);
		}
		break;
	case ':':
		r_core_visual_prompt_input (core);
		cur->model->addr = core->offset;
		setRefreshAll (panels, false);
		break;
	case 'c':
		activateCursor (core);
		break;
	case 'C':
		{
			int color = r_config_get_i (core->config, "scr.color");
			if (++color > 2) {
				color = 0;
			}
			r_config_set_i (core->config, "scr.color", color);
			can->color = color;
			setRefreshAll (panels, true);
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
		setRefreshAll (panels, false);
		break;
	case 'R':
		if (r_config_get_i (core->config, "scr.randpal")) {
			r_core_cmd0 (core, "ecr");
		} else {
			r_core_cmd0 (core, "ecn");
		}
		doPanelsRefresh (core);
		break;
	case 'a':
		panels->autoUpdate = show_status_yesno (core, 'y', "Auto update On? (Y/n)");
		break;
	case 'A':
		r_core_visual_asm (core, core->offset);
		break;
	case 'd':
		r_core_visual_define (core, "", 0);
		setRefreshAll (panels, false);
		break;
	case 'D':
		replaceCmd (core, PANEL_TITLE_DISASSEMBLY, PANEL_CMD_DISASSEMBLY, 0);
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
			for (i = 0; i < getCurPanel (panels)->view->pos.h / 2 - 6; i++) {
				cur->model->directionCb (core, (int)UP);
			}
		}
		break;
	case 'J':
		r_cons_switchbuf (false);
		if (cur->model->directionCb) {
			for (i = 0; i < getCurPanel (panels)->view->pos.h / 2 - 6; i++) {
				cur->model->directionCb (core, (int)DOWN);
			}
		}
		break;
	case 'H':
		r_cons_switchbuf (false);
		if (cur->model->directionCb) {
			for (i = 0; i < getCurPanel (panels)->view->pos.w / 3; i++) {
				cur->model->directionCb (core, (int)LEFT);
			}
		}
		break;
	case 'L':
		r_cons_switchbuf (false);
		if (cur->model->directionCb) {
			for (i = 0; i < getCurPanel (panels)->view->pos.w / 3; i++) {
				cur->model->directionCb (core, (int)RIGHT);
			}
		}
		break;
	case 'f':
		set_filter (core, cur);
		break;
	case 'F':
		reset_filter (cur);
		break;
	case '_':
		hudstuff (core);
		break;
	case '\\':
		r_core_visual_hud (core);
		break;
	case '"':
		// createNewPanel (core, true);
		createNewPanel (core, false);
		break;
	case 'n':
		if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			r_core_seek_next (core, r_config_get (core->config, "scr.nkey"));
			cur->model->addr = core->offset;
			cur->view->refresh = true;
		}
		break;
	case 'N':
		if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
			r_core_seek_previous (core, r_config_get (core->config, "scr.nkey"));
			cur->model->addr = core->offset;
			cur->view->refresh = true;
		}
		break;
	case 'x':
		r_core_visual_refs (core, true, true);
		cur->model->addr = core->offset;
		setRefreshAll (panels, false);
		break;
	case 'X':
#if 0
// already accessible via xX
		r_core_visual_refs (core, false, true);
		cur->model->addr = core->offset;
		setRefreshAll (panels, false);
#endif
		dismantleDelPanel (panels, cur, panels->curnode);
		setRefreshAll (panels, false);
		break;
	case 9: // TAB
		handleTabKey (core, false);
		break;
	case 'Z': // SHIFT-TAB
		handleTabKey (core, true);
		break;
	case 'M':
		handle_visual_mark (core);
	break;
	case 'e':
	{
		char *new_name = show_status_input (core, "New name: ");
		char *new_cmd = show_status_input (core, "New command: ");
		bool cache = show_status_yesno (core, 'y', "Cache the result? (Y/n)");
		if (new_name && *new_name && new_cmd && *new_cmd) {
			replaceCmd (core, new_name, new_cmd, cache);
		}
		free (new_name);
		free (new_cmd);
	}
		break;
	case 'm':
		setMode (panels, PANEL_MODE_MENU);
		clearPanelsMenu (core);
		getCurPanel (panels)->view->refresh = true;
		break;
	case 'g':
		r_core_visual_showcursor (core, true);
		r_core_visual_offset (core);
		r_core_visual_showcursor (core, false);
		cur->model->addr = core->offset;
		cur->view->refresh = true;
		break;
	case 'G':
		if (checkFunc (core)) {
			replaceCmd (core, PANEL_TITLE_GRAPH, PANEL_CMD_GRAPH, 1);
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
			callVisualGraph (core);
		}
		break;
	case ']':
		r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") + 1);
		break;
	case '[':
		r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") - 1);
		break;
	case '/':
		r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
		break;
	case 'z':
		if (panels->curnode > 0) {
			swapPanels (panels, 0, panels->curnode);
			panels->curnode = 0;
			setRefreshAll (panels, false);
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
		if (handle_tab (core)) {
			return false;
		}
		break;
	case 'T':
		if (panels_root->n_panels > 1) {
			goto exit;
		}
		break;
	case 'w':
		toggleWindowMode (panels);
		setRefreshAll (panels, false);
		break;
	case 0x0d: // "\\n"
		toggleZoomMode (panels);
		break;
	case '|':
		{
			RPanel *p = getCurPanel (panels);
			splitPanelVertical (core, p, p->model->title, p->model->cmd, p->model->cache);
			break;
		}
	case '-':
		{
			RPanel *p = getCurPanel (panels);
			splitPanelHorizontal (core, p, p->model->title, p->model->cmd, p->model->cache);
			break;
		}
	case '*':
		if (checkFunc (core)) {
			r_cons_canvas_free (can);
			panels->can = NULL;

			replaceCmd (core, PANEL_TITLE_DECOMPILER, "pdc", 1);

			int h, w = r_cons_get_size (&h);
			panels->can = createNewCanvas (core, w, h);
		}
		break;
	case '(':
		if (panels->fun != PANEL_FUN_SNOW && panels->fun != PANEL_FUN_SAKURA) {
			//TODO: Refactoring the FUN if bored af
			//panels->fun = PANEL_FUN_SNOW;
			panels->fun = PANEL_FUN_SAKURA;
		} else {
			panels->fun = PANEL_FUN_NOFUN;
			resetSnow (panels);
		}
		break;
	case ')':
		rotateAsmemu (core, getCurPanel (panels));
		break;
	case '&':
		toggleCache (getCurPanel (panels));
		resetScrollPos (getCurPanel (panels));
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
			panelBreakpoint (core);
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
			panelSingleStepIn (core);
			setRefreshAll (panels, false);
		}
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			panelSingleStepOver (core);
			setRefreshAll (panels, false);
		}
		break;
	case R_CONS_KEY_F9:
		cmd = r_config_get (core->config, "key.f9");
		if (cmd && *cmd) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			if (check_panel_type (cur, PANEL_CMD_DISASSEMBLY, strlen (PANEL_CMD_DISASSEMBLY))) {
				panelContinue (core);
				cur->model->addr = core->offset;
				setRefreshAll (panels, false);
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
		*force_quit = true;
		goto exit;
	case '!':
	case 'q':
	case -1: // EOF
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
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	core->print->cur = originCursor;
	core->print->cur_enabled = false;
	core->print->col = 0;
	core->vmode = originVmode;
	core->panels = prev;
	return true;
}

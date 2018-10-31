/* Copyright radare2 2014-2018 - Author: pancake, vane11ope */

// pls move the typedefs into roons and rename it -> RConsPanel

#include <r_core.h>

#define PANEL_NUM_LIMIT 256
#define PANEL_MENU_LIMIT 10

#define PANEL_TITLE_SYMBOLS      "Symbols"
#define PANEL_TITLE_STACK        "Stack"
#define PANEL_TITLE_STACKREFS    "StackRefs"
#define PANEL_TITLE_REGISTERS    "Registers"
#define PANEL_TITLE_REGISTERREFS "RegisterRefs"
#define PANEL_TITLE_DISASSEMBLY  "Disassembly"
#define PANEL_TITLE_PSEUDO       "Pseudo"
#define PANEL_TITLE_GRAPH        "Graph"
#define PANEL_TITLE_FUNCTIONS    "Functions"
#define PANEL_TITLE_FCNINFO      "FcnInfo"

#define PANEL_CMD_SYMBOLS        "isq"
#define PANEL_CMD_STACK          "px 256@r:SP"
#define PANEL_CMD_STACKREFS      "pxr 256@r:SP"
#define PANEL_CMD_LOCALS         "afvd"
#define PANEL_CMD_REGISTERS      "dr="
#define PANEL_CMD_REGISTERREFS   "drr"
#define PANEL_CMD_DISASSEMBLY    "pd $r"
#define PANEL_CMD_PSEUDO         "pdc"
#define PANEL_CMD_GRAPH          "agf"
#define PANEL_CMD_FUNCTIONS      "afl"
#define PANEL_CMD_FCNINFO        "afi"

#define PANEL_CONFIG_MENU_MAX    64
#define PANEL_CONFIG_PAGE        10
#define PANEL_CONFIG_SIDEPANEL_W 60
#define PANEL_CONFIG_RESIZE_W    4
#define PANEL_CONFIG_RESIZE_H    4

#define MENU_NUM(x) ((int)sizeof (x) / (int)sizeof (const char *)) - 1

typedef enum {
	LEFT,
	RIGHT,
	UP,
	DOWN
} Direction;

static const char *menus[] = {
	"File", "Edit", "View", "Tools", "Search", "Debug", "Analyze", "Help",
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

static const char *menus_View[] = {
	"Hexdump", "Disassembly", "Graph", "FcnInfo", "Functions", "Breakpoints", "Comments", "Entropy", "Colors",
	"Stack", "StackRefs", "Pseudo",
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
	"Registers", "RegisterRefs", "DRX", "Breakpoints", "Watchpoints",
	"Maps", "Modules", "Backtrace", "Locals", "Continue",
	"Step", "Step Over", "Reload",
	NULL
};

static const char *menus_Analyze[] = {
	"Function", "Symbols", "Program", "BasicBlocks", "Calls", "References",
	NULL
};

static const char *menus_Help[] = {
	"Fortune", "Commands", "2048", "License", "Lock Screen", "About",
	NULL
};

static const char *help_msg_panels[] = {
	":",        "run r2 command in prompt",
	"_",        "start the hud input mode",
	"?",        "show this help",
	"??",       "show the user-friendly hud",
	"!",        "run r2048 game",
	".",        "seek to PC or entrypoint",
	"*",        "show pseudo code/r2dec in the current panel",
	"/",        "highlight the keyword",
	"[1-9]",    "follow jmp/call identified by shortcut (like ;[1])",
	"b",        "browse symbols, flags, configurations, classes, ...",
	"c",        "toggle cursor",
	"C",        "toggle color",
	"d",        "define in the current address. Same as Vd",
	"D",        "show disassembly in the current panel",
	"i",        "insert hex",
	"m",        "select the menu panel",
	"o",        "go/seek to given offset",
	"pP",       "seek to next or previous scr.nkey",
	"q",        "quit, back to visual mode",
	"r",        "toggle jmphints/leahints",
	"sS",       "step in / step over",
	"uU",       "undo / redo seek",
	NULL
};

static const char *help_msg_panels_window[] = {
	"|",        "split the current panel vertically",
	"-",        "split the current panel horizontally",
	"<>",       "scroll panels vertically by page",
	"' '",      "(space) toggle graph / panels",
	"e",        "change title and command of current panel",
	"g",        "show graph in the current panel",
	"hjkl",     "move around (left-down-up-right)",
	"JK",       "resize panels vertically",
	"HL",       "resize panels horizontally",
	"M",        "open new custom frame",
	"nN",       "create new panel with given command",
	"V",        "go to the graph mode",
	"w",        "start the window mode",
	"X",        "close current panel",
	"z",        "swap current panel with the first one",
	NULL
};

static void layoutDefault(RPanels *panels);
static int layoutSidePanel(void *user);
static void changePanelNum(RPanels *panels, int now, int after);
static void splitPanelVertical(RCore *core);
static void splitPanelHorizontal(RCore *core);
static void panelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int color);
static void menuPanelPrint(RConsCanvas *can, RPanel *panel, int x, int y, int w, int h);
static void defaultPanelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int x, int y, int w, int h, int color);
static void panelAllClear(RPanels *panels);
static void addPanelFrame(RCore* core, RPanels* panels, const char *title, const char *cmd);
static bool checkFunc(RCore *core);
static void activateCursor(RCore *core);
static void cursorLeft(RCore *core);
static void cursorRight(RCore *core);
static void cursorDown(RCore *core);
static void cursorUp(RCore *core);
static int cursorThreshold(RPanel* panel);
static void delPanel(RPanels *panels, int delPanelNum);
static void delCurPanel(RPanels *panels);
static void delInvalidPanels(RPanels *panels);
static void dismantlePanel(RPanels *panels);
static void doPanelsRefresh(RCore *core);
static void doPanelsRefreshOneShot(RCore *core);
static void handleZoomMode(RCore *core, const int key);
static void handleWindowMode(RCore *core, const int key);
static bool handleCursorMode(RCore *core, const int key);
static void handleUpKey(RCore *core);
static void handleDownKey(RCore *core);
static void handleLeftKey(RCore *core);
static void handleRightKey(RCore *core);
static void resizePanelLeft(RPanels *panels);
static void resizePanelRight(RPanels *panels);
static void resizePanelUp(RPanels *panels);
static void resizePanelDown(RPanels *panels);
static void handleTabKey(RCore *core, bool shift);
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
static int iocacheCb(void *user);
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
static int fortuneCb(void *user);
static int commandsCb(void *user);
static int gameCb(void *user);
static int licenseCb(void *user);
static int aboutCb(void *user);
static int quitCb(void *user);
static void updateDisassemblyAddr (RCore *core);
static void addMenu(RCore *core, const char *parent, const char *name, RPanelsMenuCallback cb);
static void removeMenu(RPanels *panels);
static int file_history_up(RLine *line);
static int file_history_down(RLine *line);
static char *getPanelsConfigPath();
static bool init(RCore *core, RPanels *panels, int w, int h);
static void initSdb(RPanels *panels);
static bool initPanelsMenu(RCore *core);
static bool initPanels(RCore *core, RPanels *panels);
static RStrBuf *drawMenu(RPanelsMenuItem *item);
static void moveMenuCursor(RPanelsMenu *menu, RPanelsMenuItem *parent);
static void freeSinglePanel(RPanel *panel);
static void freeAllPanels(RPanels *panels);
static void panelBreakpoint(RCore *core);
static void panelContinue(RCore *core);
static void panelPrompt(const char *prompt, char *buf, int len);
static void panelSingleStepIn(RCore *core);
static void panelSingleStepOver(RCore *core);
static void setRefreshAll(RPanels *panels);
static void setCursor(RCore *core, bool cur);
static void savePanelPos(RPanel* panel);
static void restorePanelPos(RPanel* panel);
static void savePanelsLayout(RCore* core, bool temp);
static int loadSavedPanelsLayout(RCore *core, bool temp);
static void replaceCmd(RPanels* panels, char *title, char *cmd);
static void handleMenu(RCore *core, const int key, int *exit);
static void toggleZoomMode(RPanels *panels);
static void toggleWindowMode(RPanels *panels);
static void maximizePanelSize(RPanels *panels);
static void insertValue(RCore *core);
static bool moveToDirection(RPanels *panels, Direction direction);
static void showHelp(RCore *core);
static RConsCanvas *createNewCanvas(RCore *core, int w, int h);

static void panelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int color) {
	if (!can || !panel|| !panel->refresh) {
		return;
	}

	if (can->w <= panel->pos.x || can->h <= panel->pos.y) {
		return;
	}
	panel->refresh = false;
	int w = R_MIN (can->w - panel->pos.x, panel->pos.w);
	int h = R_MIN (can->h - panel->pos.y, panel->pos.h);
	r_cons_canvas_fill (can, panel->pos.x, panel->pos.y, w, h, ' ');
	if (panel->type == PANEL_TYPE_MENU) {
		menuPanelPrint (can, panel, panel->sx, panel->sy, w, h);
	} else {
		defaultPanelPrint (core, can, panel, panel->sx, panel->sy, w, h, color);
	}
	if (color) {
		r_cons_canvas_box (can, panel->pos.x, panel->pos.y, w, h, core->cons->pal.graph_box2);
	} else {
		r_cons_canvas_box (can, panel->pos.x, panel->pos.y, w, h, core->cons->pal.graph_box);
	}
}

static void menuPanelPrint(RConsCanvas *can, RPanel *panel, int x, int y, int w, int h) {
	(void) r_cons_canvas_gotoxy (can, panel->pos.x + 2, panel->pos.y + 2);
	char *text = r_str_ansi_crop (panel->title, x, y, w, h);
	if (text) {
		r_cons_canvas_write (can, text);
		free (text);
	} else {
		r_cons_canvas_write (can, panel->title);
	}
}

static void defaultPanelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int x, int y, int w, int h, int color) {
	int graph_pad = 0;
	char title[128], *text, *cmdStr = NULL;
	if (color) {
		snprintf (title, sizeof (title) - 1,
				"%s[x] %s"Color_RESET, core->cons->pal.graph_box2, panel->title);
	} else {
		snprintf (title, sizeof (title) - 1,
				"   %s   ", panel->title);
	}
	if (r_cons_canvas_gotoxy (can, panel->pos.x + 1, panel->pos.y + 1)) {
		r_cons_canvas_write (can, title);
	}
	(void) r_cons_canvas_gotoxy (can, panel->pos.x + 2, panel->pos.y + 2);
	if (panel->cmd) {
		if (!strcmp (panel->cmd, PANEL_CMD_DISASSEMBLY)) {
			core->offset = panel->addr;
			r_core_seek (core, panel->addr, 1);
			r_core_block_read (core);
			cmdStr = r_core_cmd_str (core, panel->cmd);
		} else if (!strcmp (panel->cmd, PANEL_CMD_STACK)) {
			const int delta = r_config_get_i (core->config, "stack.delta");
			const char sign = (delta < 0)? '+': '-';
			const int absdelta = R_ABS (delta);
			cmdStr = r_core_cmd_strf (core, "%s%c%d", PANEL_CMD_STACK, sign, absdelta);
		} else if (!strcmp (panel->cmd, PANEL_CMD_GRAPH)) {
			if (panel->cmdStrCache) {
				cmdStr = panel->cmdStrCache;
			} else {
				cmdStr = r_core_cmd_str (core, panel->cmd);
				panel->cmdStrCache = cmdStr;
			}
			graph_pad = 1;
			core->cons->event_resize = NULL; // avoid running old event with new data
			core->cons->event_data = core;
			core->cons->event_resize = (RConsEvent) doPanelsRefreshOneShot;
		} else if (!strcmp (panel->cmd, PANEL_CMD_PSEUDO)) {
			if (panel->cmdStrCache) {
				cmdStr = panel->cmdStrCache;
			} else {
				cmdStr = r_core_cmd_str (core, panel->cmd);
				panel->cmdStrCache = cmdStr;
			}
		} else {
			cmdStr = r_core_cmd_str (core, panel->cmd);
		}
	}
	if (y < 0) {
		y = 0;
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
	if (!panel->cmdStrCache) {
		free (cmdStr);
	}
}

static void panelAllClear(RPanels *panels) {
	if (!panels) {
		return;
	}
	int i;
	RPanel *panel = NULL;
	for (i = 0; i < panels->n_panels; i++) {
		panel = &panels->panel[i];
		r_cons_canvas_fill (panels->can, panel->pos.x, panel->pos.y, panel->pos.w, panel->pos.h, ' ');
	}
	r_cons_canvas_print (panels->can);
	r_cons_flush ();
}

R_API void r_core_panels_layout (RPanels *panels) {
	panels->can->sx = 0;
	panels->can->sy = 0;
	layoutDefault (panels);
}

static void layoutDefault(RPanels *panels) {
	int h, w = r_cons_get_size (&h);
	int ph = (h - 1) / (panels->n_panels - 2);
	int i;
	int colpos = w - panels->columnWidth;
	RPanel *panel = panels->panel;
	panel[0].pos.x = 0;
	panel[0].pos.y = 1;
	if (panels->n_panels <= 1) {
		panel[0].pos.w = w;
		panel[0].pos.h = h - 1;
		return;
	}
	panel[0].pos.w = colpos / 2 + 1;
	panel[0].pos.h = h - 1;
	panel[1].pos.x = colpos / 2;
	panel[1].pos.y = 1;
	panel[1].pos.w = colpos / 2 + 1;
	panel[1].pos.h = h - 1;
	for (i = 2; i < panels->n_panels; i++) {
		panel[i].pos.x = colpos;
		panel[i].pos.y = 2 + (ph * (i - 2));
		panel[i].pos.w = w - colpos;
		if (panel[i].pos.w < 0) {
			panel[i].pos.w = 0;
		}
		if ((i + 1) == panels->n_panels) {
			panel[i].pos.h = h - panel[i].pos.y;
		} else {
			panel[i].pos.h = ph;
		}
		panel[i].pos.y--;
		panel[i].pos.h++;
	}
}

static int layoutSidePanel(void *user) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *panel = panels->panel;
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	const char *cmd = sdb_get (panels->db, child->name, 0);
	if (!cmd) {
		return 0;
	}
	int i, h;
	(void)r_cons_get_size (&h);
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = &panel[i];
		if (p->pos.x == 0) {
			if (p->pos.w >= PANEL_CONFIG_SIDEPANEL_W) {
				p->pos.x += PANEL_CONFIG_SIDEPANEL_W - 1;
				p->pos.w -= PANEL_CONFIG_SIDEPANEL_W - 1;
			}
		}
	}
	addPanelFrame (core, panels, child->name, cmd);
	changePanelNum (panels, panels->n_panels - 1, 0);
	panel[0].pos.x = 0;
	panel[0].pos.y = 1;
	panel[0].pos.w = PANEL_CONFIG_SIDEPANEL_W;
	panel[0].pos.h = h - 1;
	panels->curnode = 0;
	setRefreshAll (panels);
	return 0;
}

static void splitPanelVertical(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *panel = panels->panel;
	const int curnode = panels->curnode;
	const int owidth = panel[curnode].pos.w;

	addPanelFrame (core, panels, panel[curnode].title, panel[curnode].cmd);

	changePanelNum (panels, panels->n_panels - 1, panels->curnode + 1);

	panel[curnode].pos.w = owidth / 2 + 1;
	panel[curnode + 1].pos.x = panel[curnode].pos.x + panel[curnode].pos.w - 1;
	panel[curnode + 1].pos.y = panel[curnode].pos.y;
	panel[curnode + 1].pos.w = owidth - panel[curnode].pos.w + 1;
	panel[curnode + 1].pos.h = panel[curnode].pos.h;
	setRefreshAll (panels);
}

static void splitPanelHorizontal(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *panel = panels->panel;
	const int curnode = panels->curnode;
	const int oheight = panel[curnode].pos.h;

	panel[curnode].curpos = 0;
	addPanelFrame (core, panels, panel[curnode].title, panel[curnode].cmd);

	changePanelNum (panels, panels->n_panels - 1, panels->curnode + 1);

	panel[curnode].pos.h = oheight / 2 + 1;
	panel[curnode + 1].pos.x = panel[curnode].pos.x;
	panel[curnode + 1].pos.y = panel[curnode].pos.y + panel[curnode].pos.h - 1;
	panel[curnode + 1].pos.w = panel[curnode].pos.w;
	panel[curnode + 1].pos.h = oheight - panel[curnode].pos.h + 1;
	setRefreshAll (panels);
}

R_API void r_core_panels_layout_refresh(RCore *core) {
	delInvalidPanels (core->panels);
	r_core_panels_check_stackbase (core);
	r_core_panels_refresh (core);
}

static void changePanelNum(RPanels *panels, int now, int after) {
	RPanel *panel = panels->panel;
	const int n_panels = panels->n_panels;
	int i;
	RPanel tmpPanel = panel[now];
	for (i = n_panels - 1; i > after; i--) {
		panel[i] = panel[i - 1];
	}
	panel[after] = tmpPanel;
}

static void setCursor(RCore *core, bool cur) {
	core->print->cur_enabled = cur;
	if (cur) {
		core->print->cur = core->panels->panel[core->panels->curnode].curpos;
	} else {
		core->panels->panel[core->panels->curnode].curpos = core->print->cur;
	}
	core->print->col = core->print->cur_enabled ? 1: 0;
}

static void cursorRight(RCore *core) {
	if (!strcmp (core->panels->panel[core->panels->curnode].cmd, PANEL_CMD_STACK) && core->print->cur >= 15) {
		return;
	}
	if (!strcmp (core->panels->panel[core->panels->curnode].cmd, PANEL_CMD_REGISTERS)
			|| !strcmp (core->panels->panel[core->panels->curnode].cmd, PANEL_CMD_STACK)) {
		core->print->cur++;
		core->panels->panel[core->panels->curnode].addr++;
	} else {
		core->print->cur++;
		RPanel *curPanel = &core->panels->panel[core->panels->curnode];
		int threshold = cursorThreshold (curPanel);
		int row = r_print_row_at_off (core->print, core->print->cur);
		if (row >= threshold) {
			core->offset = core->panels->panel[core->panels->curnode].addr;
			RAsmOp op;
			ut32 next_roff = r_print_rowoff (core->print, row + 1);
			int sz = r_asm_disassemble (core->assembler, &op,
					core->block + next_roff, 32);
			if (sz < 1) {
				sz = 1;
			}
			r_core_seek_delta (core, sz);
			core->panels->panel[core->panels->curnode].addr = core->offset;
			r_core_block_read (core);
			core->print->cur = R_MAX (core->print->cur - sz, 0);
		}
	}
}

static void activateCursor(RCore *core) {
	RPanels *panels = core->panels;
	if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_STACK)
			|| !strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_REGISTERS)
			|| !strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)) {
		setCursor (core, !core->print->cur_enabled);
		panels->panel[panels->curnode].refresh = true;
	}
}

static void cursorLeft(RCore *core) {
	if (!strcmp (core->panels->panel[core->panels->curnode].cmd, PANEL_CMD_REGISTERS)
			|| !strcmp (core->panels->panel[core->panels->curnode].cmd, PANEL_CMD_STACK)) {
		if (core->print->cur > 0) {
			core->print->cur--;
			core->panels->panel[core->panels->curnode].addr--;
		}
	} else {
		core->print->cur--;
		int row = r_print_row_at_off (core->print, core->print->cur);
		if (row < 0) {
			int cols = core->print->cols;
			ut64 prevoff = core->offset;
			core->offset = core->panels->panel[core->panels->curnode].addr;
			r_core_visual_disasm_up (core, &cols);
			r_core_seek_delta (core, -cols);
			core->panels->panel[core->panels->curnode].addr = core->offset;
			core->print->cur = prevoff - core->offset - 1;
		}
	}
}

static void cursorUp(RCore *core) {
	RPrint *p = core->print;
	ut32 roff;
	int row;
	if (p->row_offsets) {
		row = r_print_row_at_off (p, p->cur);
		roff = r_print_rowoff (p, row);
		if (roff == UT32_MAX) {
			p->cur--;
			return;
		}
		if (row > 0) {
			ut32 prev_roff;
			int delta, prev_sz;
			prev_roff = r_print_rowoff (p, row - 1);
			delta = p->cur - roff;
			prev_sz = roff - prev_roff;
			int res = R_MIN (delta, prev_sz - 1);
			ut64 cur = prev_roff + res;
			if (cur == p->cur) {
				if (p->cur > 0) {
					p->cur--;
				}
			} else {
				p->cur = prev_roff + delta;
			}
		} else {
			int cols = core->print->cols;
			ut64 prevoff = core->offset;
			r_core_visual_disasm_up (core, &cols);
			r_core_seek_delta (core, -cols);
			core->panels->panel[core->panels->curnode].addr = core->offset;
			core->print->cur = R_MIN (prevoff - core->offset - 1, core->print->cur);
		}
	} else {
		p->cur -= p->cols;
	}
}

static void cursorDown(RCore *core) {
	RPanel *curPanel = &core->panels->panel[core->panels->curnode];
	int threshold = cursorThreshold (curPanel);
	RPrint *p = core->print;
	ut32 roff, next_roff;
	int row, sz, delta;
	RAsmOp op;
	if (p->row_offsets) {
		row = r_print_row_at_off (p, p->cur);
		roff = r_print_rowoff (p, row);
		if (roff == -1) {
			p->cur++;
			return;
		}
		next_roff = r_print_rowoff (p, row + 1);
		if (next_roff == -1) {
			p->cur++;
			return;
		}
		sz = r_asm_disassemble (core->assembler, &op,
				core->block + next_roff, 32);
		if (sz < 1) {
			sz = 1;
		}
		delta = p->cur - roff;
		p->cur = next_roff + R_MIN (delta, sz - 1);
		row = r_print_row_at_off (p, p->cur);
		if (row >= threshold) {
			r_core_seek_delta (core, sz);
			p->cur = R_MAX (p->cur - sz, 0);
		}
	} else {
		p->cur += R_MAX (1, p->cols);
	}
}

static int cursorThreshold(RPanel* panel) {
	int threshold = (panel->pos.h - 4) / 2;
	if (threshold < 10) {
		threshold = 1;
	}
	return threshold;
}

static void handleUpKey(RCore *core) {
	RPanels *panels = core->panels;

	r_cons_switchbuf (false);
	if (panels->curnode == panels->menu_pos) {
		RPanelsMenu *menu = panels->panelsMenu;
		if (menu->depth < 2) {
			return;
		}
		RPanelsMenuItem *parent = menu->history[menu->depth - 1];
		if (parent->selectedIndex > 0) {
			parent->selectedIndex--;
			moveMenuCursor (menu, parent);
		} else if (menu->depth == 2) {
			menu->depth--;
			setRefreshAll (panels);
		}
	} else {
		panels->panel[panels->curnode].refresh = true;
		if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)) {
			core->offset = panels->panel[panels->curnode].addr;
			if (core->print->cur_enabled) {
				cursorUp (core);
				panels->panel[panels->curnode].addr = core->offset;
			} else {
				int cols = core->print->cols;
				r_core_visual_disasm_up (core, &cols);
				r_core_seek_delta (core, -cols);
				panels->panel[panels->curnode].addr = core->offset;
			}
		} else if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_STACK)) {
			int width = r_config_get_i (core->config, "hex.cols");
			if (width < 1) {
				width = 16;
			}
			r_config_set_i (core->config, "stack.delta",
					r_config_get_i (core->config, "stack.delta") + width);
			panels->panel[panels->curnode].addr -= width;
		} else if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_REGISTERS)) {
			if (core->print->cur_enabled) {
				int cur = core->print->cur;
				int cols = core->dbg->regcols;
				cols = cols > 0 ? cols : 3;
				cur -= cols;
				if (cur >= 0) {
					core->print->cur = cur;
				}
			}
		} else if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_GRAPH)) {
			if (panels->panel[panels->curnode].sy > 0) {
				panels->panel[panels->curnode].sy -= r_config_get_i (core->config, "graph.scroll");
			}
		} else {
			if (panels->panel[panels->curnode].sy > 0) {
				panels->panel[panels->curnode].sy--;
			}
		}
	}
}

static void handleDownKey(RCore *core) {
	RPanels *panels = core->panels;
	r_cons_switchbuf (false);
	if (panels->curnode == panels->menu_pos) {
		RPanelsMenu *menu = panels->panelsMenu;
		if (menu->depth == 1) {
			RPanelsMenuItem *parent = menu->history[menu->depth - 1];
			parent->sub[parent->selectedIndex]->cb(core);
		} else {
			RPanelsMenuItem *parent = menu->history[menu->depth - 1];
			parent->selectedIndex = R_MIN (parent->n_sub - 1, parent->selectedIndex + 1);
			moveMenuCursor (menu, parent);
		}
	} else {
		panels->panel[panels->curnode].refresh = true;
		if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)) {
			core->offset = panels->panel[panels->curnode].addr;
			if (core->print->cur_enabled) {
				cursorDown (core);
				r_core_block_read (core);
				panels->panel[panels->curnode].addr = core->offset;
			} else {
				RAsmOp op;
				int cols = core->print->cols;
				r_core_visual_disasm_down (core, &op, &cols);
				r_core_seek (core, core->offset + cols, 1);
				r_core_block_read (core);
				panels->panel[panels->curnode].addr = core->offset;
			}
		} else if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_STACK)) {
			int width = r_config_get_i (core->config, "hex.cols");
			if (width < 1) {
				width = 16;
			}
			r_config_set_i (core->config, "stack.delta",
					r_config_get_i (core->config, "stack.delta") - width);
			panels->panel[panels->curnode].addr += width;
		} else if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_REGISTERS)) {
			if (core->print->cur_enabled) {
				const int cols = core->dbg->regcols;
				core->print->cur += cols > 0 ? cols : 3;
			}
		} else if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_GRAPH)) {
			panels->panel[panels->curnode].sy += r_config_get_i (core->config, "graph.scroll");
		} else {
			panels->panel[panels->curnode].sy++;
		}
	}
}

static void handleLeftKey(RCore *core) {
	RPanels *panels = core->panels;
	r_cons_switchbuf (false);
	if (panels->curnode == panels->menu_pos) {
		RPanelsMenu *menu = panels->panelsMenu;
		if (menu->depth <= 2) {
			if (menu->root->selectedIndex > 0) {
				menu->root->selectedIndex--;
			} else {
				menu->root->selectedIndex = menu->root->n_sub - 1;
			}
			if (menu->depth == 2) {
				menu->depth = 1;
				setRefreshAll (panels);
				menu->root->sub[menu->root->selectedIndex]->cb (core);
			}
		} else {
			removeMenu (panels);
		}
	} else if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_GRAPH)) {
		if (panels->panel[panels->curnode].sx > 0) {
			panels->panel[panels->curnode].sx -= r_config_get_i (core->config, "graph.scroll");
			panels->panel[panels->curnode].refresh = true;
		}
	} else if (core->print->cur_enabled
			&& (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_REGISTERS)
				|| !strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_STACK)
				|| !strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY))) {
		cursorLeft (core);
		panels->panel[panels->curnode].refresh = true;
	} else {
		if (panels->panel[panels->curnode].sx > 0) {
			panels->panel[panels->curnode].sx--;
			panels->panel[panels->curnode].refresh = true;
		}
	}
}

static void handleRightKey(RCore *core) {
	RPanels *panels = core->panels;
	r_cons_switchbuf (false);
	if (panels->curnode ==  panels->menu_pos) {
		RPanelsMenu *menu = panels->panelsMenu;
		if (menu->depth == 1) {
			menu->root->selectedIndex++;
			menu->root->selectedIndex %= menu->root->n_sub;
			return;
		}
		RPanelsMenuItem *child = menu->history[menu->depth - 1];
		if (child->sub[child->selectedIndex]->sub) {
			child->sub[child->selectedIndex]->cb (core);
		} else {
			menu->root->selectedIndex++;
			menu->root->selectedIndex %= menu->root->n_sub;
			menu->depth = 1;
			setRefreshAll (panels);
			menu->root->sub[menu->root->selectedIndex]->cb (core);
		}
	} else if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_GRAPH)) {
		panels->panel[panels->curnode].sx += r_config_get_i (core->config, "graph.scroll");
		panels->panel[panels->curnode].refresh = true;
	} else if (core->print->cur_enabled
			&& (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_REGISTERS)
				|| !strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_STACK)
				|| !strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY))) {
		cursorRight (core);
		panels->panel[panels->curnode].refresh = true;
	} else {
		panels->panel[panels->curnode].sx++;
		panels->panel[panels->curnode].refresh = true;
	}
}

static void handleZoomMode(RCore *core, const int key) {
	RPanels *panels = core->panels;
	RPanel *panel = panels->panel;
	switch (key) {
		case 'Q':
		case 'q':
		case 0x0d:
			toggleZoomMode (panels);
			break;
		case 'h':
			handleLeftKey (core);
			break;
		case 'j':
			handleDownKey (core);
			break;
		case 'k':
			handleUpKey (core);
			break;
		case 'l':
			handleRightKey (core);
			break;
		case 'c':
			activateCursor (core);
			break;
		case 'X':
			toggleZoomMode (panels);
			delCurPanel (panels);
			toggleZoomMode (panels);
			break;
		case 's':
			panelSingleStepIn (core);
			if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)) {
				panels->panel[panels->curnode].addr = core->offset;
			}
			setRefreshAll (panels);
			break;
		case 9:
			restorePanelPos (&panel[panels->curnode]);
			handleTabKey (core, false);
			panels->curnode = R_MAX (panels->curnode, 0);
			savePanelPos (&panel[panels->curnode]);
			maximizePanelSize (panels);
			break;
		case 'Z':
			restorePanelPos (&panel[panels->curnode]);
			handleTabKey (core, true);
			if (panels->curnode == panels->menu_pos) {
				panels->curnode = panels->n_panels - 1;
			}
			savePanelPos (&panel[panels->curnode]);
			maximizePanelSize (panels);
			break;
		case ':':
			r_core_visual_prompt_input (core);
			panels->panel[panels->curnode].addr = core->offset;
			setRefreshAll (panels);
			break;
		case '?':
			showHelp(core);
			break;
	}
}

static void handleWindowMode(RCore *core, const int key) {
	RPanels *panels = core->panels;
	switch (key) {
	case 'Q':
	case 'q':
		toggleWindowMode (panels);
		break;
	case 0x0d:
		toggleZoomMode (panels);
		break;
	case 'h':
		if (moveToDirection (panels, LEFT)) {
			setRefreshAll (panels);
		}
		break;
	case 'j':
		if (moveToDirection (panels, DOWN)) {
			setRefreshAll (panels);
		}
		break;
	case 'k':
		if (moveToDirection (panels, UP)) {
			setRefreshAll (panels);
		}
		break;
	case 'l':
		if (moveToDirection (panels, RIGHT)) {
			setRefreshAll (panels);
		}
		break;
	case 9:
		handleTabKey (core, false);
		break;
	case 'Z':
		handleTabKey (core, true);
		break;
	}
}

static bool handleCursorMode(RCore *core, const int key) {
	const RPanels *panels = core->panels;
	if (!core->print->cur_enabled) {
		return false;
	}
	if (core->print->cur_enabled) {
		switch (key) {
		case 'h':
			handleLeftKey (core);
			break;
		case 'j':
			handleDownKey (core);
			break;
		case 'k':
			handleUpKey (core);
			break;
		case 'l':
			handleRightKey (core);
			break;
		case 'Q':
		case 'q':
			setCursor (core, !core->print->cur_enabled);
			panels->panel[panels->curnode].refresh = true;
			break;
		case 'i':
			insertValue (core);
			break;
		case '*':
			if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)) {
				r_core_cmdf (core, "dr PC=0x%08"PFMT64x, core->offset + core->print->cur);
				panels->panel[panels->curnode].addr = core->offset + core->print->cur;
				panels->panel[panels->curnode].refresh = true;
			}
			break;
		}
	}
	return true;
}

static void resizePanelLeft(RPanels *panels) {
	RPanel *panel = panels->panel;
	RPanel *curPanel = &panel[panels->curnode];
	int i, cx0, cy0, cy1, tx0, tx1, ty0, ty1, cur1 = 0, cur2 = 0;
	cx0 = curPanel->pos.x;
	cy0 = curPanel->pos.y;
	cy1 = curPanel->pos.y + curPanel->pos.h - 1;
	RPanel **targets1 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets2 = malloc (sizeof (RPanel *) * panels->n_panels);
	if (!targets1 || !targets2) {
		goto beach;
	}
	for (i = 0; i < panels->n_panels; i++) {
		if (i == panels->curnode) {
			continue;
		}
		RPanel *p = &panel[i];
		tx0 = p->pos.x;
		tx1 = p->pos.x + p->pos.w - 1;
		ty0 = p->pos.y;
		ty1 = p->pos.y + p->pos.h - 1;
		if (ty0 == cy0 && ty1 == cy1 && tx1 == cx0) {
			if (tx1 - PANEL_CONFIG_RESIZE_W > tx0) {
				p->pos.w -= PANEL_CONFIG_RESIZE_W;
				curPanel->pos.x -= PANEL_CONFIG_RESIZE_W;
				curPanel->pos.w += PANEL_CONFIG_RESIZE_W;
				p->refresh = true;
				curPanel->refresh = true;
			}
			goto beach;
		}
		if (tx1 == cx0) {
			if (tx1 - PANEL_CONFIG_RESIZE_W <= tx0) {
				return;
			}
			targets1[cur1++] = p;
		}
		if (tx0 == cx0) {
			if (tx0 - PANEL_CONFIG_RESIZE_W <= 0) {
				return;
			}
			targets2[cur2++] = p;
		}
	}
	if (cur1 > 0) {
		for (i = 0; i < cur1; i++) {
			targets1[i]->pos.w -= PANEL_CONFIG_RESIZE_W;
			targets1[i]->refresh = true;
		}
		for (i = 0; i < cur2; i++) {
			targets2[i]->pos.x -= PANEL_CONFIG_RESIZE_W;
			targets2[i]->pos.w += PANEL_CONFIG_RESIZE_W;
			targets2[i]->refresh = true;
		}
		curPanel->pos.x -= PANEL_CONFIG_RESIZE_W;
		curPanel->pos.w += PANEL_CONFIG_RESIZE_W;
		curPanel->refresh = true;
	}
beach:
	free (targets1);
	free (targets2);
}

static void resizePanelRight(RPanels *panels) {
	RPanel *panel = panels->panel;
	RPanel *curPanel = &panel[panels->curnode];
	int i, tx0, tx1, ty0, ty1, cur1 = 0, cur2 = 0;
	int cx1 = curPanel->pos.x + curPanel->pos.w - 1;
	int cy0 = curPanel->pos.y;
	int cy1 = curPanel->pos.y + curPanel->pos.h - 1;
	RPanel **targets1 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets2 = malloc (sizeof (RPanel *) * panels->n_panels);
	if (!targets1 || !targets2) {
		goto beach;
	}
	for (i = 0; i < panels->n_panels; i++) {
		if (i == panels->curnode) {
			continue;
		}
		RPanel *p = &panel[i];
		tx0 = p->pos.x;
		tx1 = p->pos.x + p->pos.w - 1;
		ty0 = p->pos.y;
		ty1 = p->pos.y + p->pos.h - 1;
		if (ty0 == cy0 && ty1 == cy1 && tx0 == cx1) {
			if (cx1 + PANEL_CONFIG_RESIZE_W < tx1) {
				p->pos.x += PANEL_CONFIG_RESIZE_W;
				p->pos.w -= PANEL_CONFIG_RESIZE_W;
				curPanel->pos.w += PANEL_CONFIG_RESIZE_W;
				p->refresh = true;
				curPanel->refresh = true;
			}
			goto beach;
		}
		if (tx0 == cx1) {
			if (tx0 + PANEL_CONFIG_RESIZE_W >= tx1) {
				return;
			}
			targets1[cur1++] = p;
			continue;
		}
		if (tx1 == cx1) {
			if (tx1 + PANEL_CONFIG_RESIZE_W >= panels->can->w) {
				return;
			}
			targets2[cur2++] = p;
		}
	}
	if (cur1 > 0) {
		for (i = 0; i < cur1; i++) {
			targets1[i]->pos.x += PANEL_CONFIG_RESIZE_W;
			targets1[i]->pos.w -= PANEL_CONFIG_RESIZE_W;
			targets1[i]->refresh = true;
		}
		for (i = 0; i < cur2; i++) {
			targets2[i]->pos.w += PANEL_CONFIG_RESIZE_W;
			targets2[i]->refresh = true;
		}
		curPanel->pos.w += PANEL_CONFIG_RESIZE_W;
		curPanel->refresh = true;
	}
beach:
	free (targets1);
	free (targets2);
}

static void resizePanelUp(RPanels *panels) {
	RPanel *panel = panels->panel;
	RPanel *curPanel = &panel[panels->curnode];
	int i, tx0, tx1, ty0, ty1, cur1 = 0, cur2 = 0;
	int cx0 = curPanel->pos.x;
	int cx1 = curPanel->pos.x + curPanel->pos.w - 1;
	int cy0 = curPanel->pos.y;
	RPanel **targets1 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets2 = malloc (sizeof (RPanel *) * panels->n_panels);
	if (!targets1 || !targets2) {
		goto beach;
	}
	for (i = 0; i < panels->n_panels; i++) {
		if (i == panels->curnode) {
			continue;
		}
		RPanel *p = &panel[i];
		tx0 = p->pos.x;
		tx1 = p->pos.x + p->pos.w - 1;
		ty0 = p->pos.y;
		ty1 = p->pos.y + p->pos.h - 1;
		if (tx0 == cx0 && tx1 == cx1 && ty1 == cy0) {
			if (ty1 - PANEL_CONFIG_RESIZE_H > ty0) {
				p->pos.h -= PANEL_CONFIG_RESIZE_H;
				curPanel->pos.y -= PANEL_CONFIG_RESIZE_H;
				curPanel->pos.h += PANEL_CONFIG_RESIZE_H;
				p->refresh = true;
				curPanel->refresh = true;
			}
			goto beach;
		}
		if (ty1 == cy0) {
			if (ty1 - PANEL_CONFIG_RESIZE_H <= ty0) {
				return;
			}
			targets1[cur1++] = p;
		}
		if (ty0 == cy0) {
			if (ty0 - PANEL_CONFIG_RESIZE_H <= 0) {
				return;
			}
			targets2[cur2++] = p;
		}
	}
	if (cur1) {
		for (i = 0; i < cur1; i++) {
			targets1[i]->pos.h -= PANEL_CONFIG_RESIZE_H;
			targets1[i]->refresh = true;
		}
		for (i = 0; i < cur2; i++) {
			targets2[i]->pos.y -= PANEL_CONFIG_RESIZE_H;
			targets2[i]->pos.h += PANEL_CONFIG_RESIZE_H;
			targets2[i]->refresh = true;
		}
		curPanel->refresh = true;
		curPanel->pos.y -= PANEL_CONFIG_RESIZE_H;
		curPanel->pos.h += PANEL_CONFIG_RESIZE_H;
	}
beach:
	free (targets1);
	free (targets2);
}

static void resizePanelDown(RPanels *panels) {
	RPanel *panel = panels->panel;
	RPanel *curPanel = &panel[panels->curnode];
	int i, tx0, tx1, ty0, ty1, cur1 = 0, cur2 = 0;
	int cx0 = curPanel->pos.x;
	int cx1 = curPanel->pos.x + curPanel->pos.w - 1;
	int cy1 = curPanel->pos.y + curPanel->pos.h - 1;
	RPanel **targets1 = malloc (sizeof (RPanel *) * panels->n_panels);
	RPanel **targets2 = malloc (sizeof (RPanel *) * panels->n_panels);
	if (!targets1 || !targets2) {
		goto beach;
	}
	for (i = 0; i < panels->n_panels; i++) {
		if (i == panels->curnode) {
			continue;
		}
		RPanel *p = &panel[i];
		tx0 = p->pos.x;
		tx1 = p->pos.x + p->pos.w - 1;
		ty0 = p->pos.y;
		ty1 = p->pos.y + p->pos.h - 1;
		if (tx0 == cx0 && tx1 == cx1 && ty0 == cy1) {
			if (ty0 + PANEL_CONFIG_RESIZE_H < ty1) {
				p->pos.y += PANEL_CONFIG_RESIZE_H;
				p->pos.h -= PANEL_CONFIG_RESIZE_H;
				curPanel->pos.h += PANEL_CONFIG_RESIZE_H;
				p->refresh = true;
				curPanel->refresh = true;
			}
			goto beach;
		}
		if (ty0 == cy1) {
			if (ty0 + PANEL_CONFIG_RESIZE_H >= ty1) {
				return;
			}
			targets1[cur1++] = p;
		}
		if (ty1 == cy1) {
			if (ty1 + PANEL_CONFIG_RESIZE_H >= panels->can->h) {
				return;
			}
			targets2[cur2++] = p;
		}
	}
	if (cur1 > 0) {
		for (i = 0; i < cur1; i++) {
			targets1[i]->pos.y += PANEL_CONFIG_RESIZE_H;
			targets1[i]->pos.h -= PANEL_CONFIG_RESIZE_H;
			targets1[i]->refresh = true;
		}
		for (i = 0; i < cur2; i++) {
			targets2[i]->pos.h += PANEL_CONFIG_RESIZE_H;
			targets2[i]->refresh = true;
		}
		curPanel->pos.h += PANEL_CONFIG_RESIZE_H;
		curPanel->refresh = true;
	}
beach:
	free (targets1);
	free (targets2);
}

static void delPanel(RPanels *panels, int delPanelNum) {
	int i;
	for (i = delPanelNum; i < (panels->n_panels - 1); i++) {
		panels->panel[i] = panels->panel[i + 1];
	}
	panels->panel[i].title = 0;
	panels->n_panels--;
	if (panels->curnode >= panels->n_panels) {
		panels->curnode = panels->n_panels - 1;
	}
}

static void delCurPanel(RPanels *panels) {
	if (panels->n_panels <= 2) {
		return;
	}
	dismantlePanel (panels);
	delPanel (panels, panels->curnode);
}

static void delInvalidPanels(RPanels *panels) {
	int i;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *panel = &panels->panel[i];
		if (panel->pos.w < 2) {
			delPanel (panels, i);
			delInvalidPanels (panels);
			break;
		}
		if (panel->pos.h < 2) {
			delPanel (panels, i);
			delInvalidPanels (panels);
			break;
		}
	}
}

static void dismantlePanel(RPanels *panels) {
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
	ox = panels->panel[panels->curnode].pos.x;
	oy = panels->panel[panels->curnode].pos.y;
	ow = panels->panel[panels->curnode].pos.w;
	oh = panels->panel[panels->curnode].pos.h;
	for (i = 0; i < panels->n_panels; i++) {
		tmpPanel = &panels->panel[i];
		if (tmpPanel->pos.x + tmpPanel->pos.w - 1 == ox) {
			left[i] = 1;
			if (oy == tmpPanel->pos.y) {
				leftUpValid = true;
				if (oh == tmpPanel->pos.h) {
					justLeftPanel = tmpPanel;
					break;
				}
			}
			if (oy + oh == tmpPanel->pos.y + tmpPanel->pos.h) {
				leftDownValid = true;
			}
		}
		if (tmpPanel->pos.x == ox + ow - 1) {
			right[i] = 1;
			if (oy == tmpPanel->pos.y) {
				rightUpValid = true;
				if (oh == tmpPanel->pos.h) {
					rightDownValid = true;
					justRightPanel = tmpPanel;
				}
			}
			if (oy + oh == tmpPanel->pos.y + tmpPanel->pos.h) {
				rightDownValid = true;
			}
		}
		if (tmpPanel->pos.y + tmpPanel->pos.h - 1 == oy) {
			up[i] = 1;
			if (ox == tmpPanel->pos.x) {
				upLeftValid = true;
				if (ow == tmpPanel->pos.w) {
					upRightValid = true;
					justUpPanel = tmpPanel;
				}
			}
			if (ox + ow == tmpPanel->pos.x + tmpPanel->pos.w) {
				upRightValid = true;
			}
		}
		if (tmpPanel->pos.y == oy + oh - 1) {
			down[i] = 1;
			if (ox == tmpPanel->pos.x) {
				downLeftValid = true;
				if (ow == tmpPanel->pos.w) {
					downRightValid = true;
					justDownPanel = tmpPanel;
				}
			}
			if (ox + ow == tmpPanel->pos.x + tmpPanel->pos.w) {
				downRightValid = true;
			}
		}
	}
	if (justLeftPanel) {
		justLeftPanel->pos.w += ox + ow - (justLeftPanel->pos.x + justLeftPanel->pos.w);
	} else if (justRightPanel) {
		justRightPanel->pos.w = justRightPanel->pos.x + justRightPanel->pos.w - ox;
		justRightPanel->pos.x = ox;
	} else if (justUpPanel) {
		justUpPanel->pos.h += oy + oh - (justUpPanel->pos.y + justUpPanel->pos.h);
	} else if (justDownPanel) {
		justDownPanel->pos.h = oh + justDownPanel->pos.y + justDownPanel->pos.h - (oy + oh);
		justDownPanel->pos.y = oy;
	} else if (leftUpValid && leftDownValid) {
		for (i = 0; i < panels->n_panels; i++) {
			if (left[i] != -1) {
				tmpPanel = &panels->panel[i];
				tmpPanel->pos.w += ox + ow - (tmpPanel->pos.x + tmpPanel->pos.w);
			}
		}
	} else if (rightUpValid && rightDownValid) {
		for (i = 0; i < panels->n_panels; i++) {
			if (right[i] != -1) {
				tmpPanel = &panels->panel[i];
				tmpPanel->pos.w = tmpPanel->pos.x + tmpPanel->pos.w - ox;
				tmpPanel->pos.x = ox;
			}
		}
	} else if (upLeftValid && upRightValid) {
		for (i = 0; i < panels->n_panels; i++) {
			if (up[i] != -1) {
				tmpPanel = &panels->panel[i];
				tmpPanel->pos.h += oy + oh - (tmpPanel->pos.y + tmpPanel->pos.h);
			}
		}
	} else if (downLeftValid && downRightValid) {
		for (i = 0; i < panels->n_panels; i++) {
			if (down[i] != -1) {
				tmpPanel = &panels->panel[i];
				tmpPanel->pos.h = oh + tmpPanel->pos.y + tmpPanel->pos.h - (oy + oh);
				tmpPanel->pos.y = oy;
			}
		}
	}
}

static void replaceCmd(RPanels* panels, char *title, char *cmd) {
	freeSinglePanel (&panels->panel[panels->curnode]);
	panels->panel[panels->curnode].title = strdup (title);
	panels->panel[panels->curnode].cmd = r_str_newf (cmd);
	panels->panel[panels->curnode].cmdStrCache = NULL;
	setRefreshAll (panels);
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

static void setRefreshAll(RPanels *panels) {
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		panels->panel[i].refresh = true;
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

static void addPanelFrame(RCore *core, RPanels* panels, const char *title, const char *cmd) {
	RPanel* panel = panels->panel;
	const int n_panels = panels->n_panels;
	if (title) {
		panel[n_panels].title = strdup (title);
		panel[n_panels].cmd = r_str_newf (cmd);
	} else {
		panel[n_panels].title = r_core_cmd_str (core, cmd);
		panel[n_panels].cmd = NULL;
	}
	panel[n_panels].type = PANEL_TYPE_DEFAULT;
	panel[n_panels].refresh = true;
	panel[n_panels].curpos = 0;
	panel[n_panels].cmdStrCache = NULL;
	if (panel[n_panels].cmd) {
		if (!strcmp (panel[n_panels].cmd, PANEL_CMD_DISASSEMBLY)) {
			panel[n_panels].addr = core->offset;
		}
		if (!strcmp (panel[n_panels].cmd, PANEL_CMD_STACK)) {
			const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
			const ut64 stackbase = r_reg_getv (core->anal->reg, sp);
			panel[n_panels].baseAddr = stackbase;
			panel[n_panels].addr = stackbase - r_config_get_i (core->config, "stack.delta");
		}
	}
	panels->n_panels++;
}

static int openFileCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_enable_mouse (false);
	core->cons->line->file_prompt = true;
	r_line_set_hist_callback (core->cons->line, &file_history_up, &file_history_down);
	char *res = r_cons_input ("open file: ");
	if (res) {
		if (*res) {
			r_core_cmdf (core, "o %s", res);
		}
		free (res);
	}
	core->cons->line->file_prompt = false;
	r_line_set_hist_callback (core->cons->line, &cmd_history_up, &cmd_history_down);
	r_cons_enable_mouse (true);
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
	loadSavedPanelsLayout (core, false);
	core->panels->curnode = 0;
	core->panels->panelsMenu->depth = 1;
	return 0;
}

static int loadLayoutDefaultCb(void *user) {
	RCore *core = (RCore *)user;
	initPanels (core, core->panels);
	r_core_panels_layout (core->panels);
	setRefreshAll (core->panels);
	core->panels->panelsMenu->depth = 1;
	return 0;
}

static int closeFileCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "o-*");
	return 0;
}

static int saveLayoutCb(void *user) {
	RCore *core = (RCore *)user;
	savePanelsLayout (core, false);
	return 0;
}

static int copyCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_enable_mouse (false);
	char *res = r_cons_input ("How many bytes? ");
	if (res) {
		r_core_cmdf (core, "\"y %s\"", res);
		free (res);
	}
	r_cons_enable_mouse (true);
	return 0;
}

static int pasteCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "yy");
	return 0;
}

static int writeStrCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_enable_mouse (false);
	char *res = r_cons_input ("insert string: ");
	if (res) {
		r_core_cmdf (core, "\"w %s\"", res);
		free (res);
	}
	r_cons_enable_mouse (true);
	return 0;
}

static int writeHexCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_enable_mouse (false);
	char *res = r_cons_input ("insert hexpairs: ");
	if (res) {
		r_core_cmdf (core, "\"wx %s\"", res);
		free (res);
	}
	r_cons_enable_mouse (true);
	return 0;
}

static int assembleCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_visual_asm (core, core->offset);
	return 0;
}

static int fillCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_enable_mouse (false);
	char *s = r_cons_input ("Fill with: ");
	r_core_cmdf (core, "wow %s", s);
	free (s);
	r_cons_enable_mouse (true);
	return 0;
}

static int iocacheCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "e!io.cache");
	return 0;
}

static int colorsCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "e!scr.color");
	return 0;
}

static int calculatorCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_enable_mouse (false);
	for (;;) {
		char *s = r_cons_input ("> ");
		if (!s || !*s) {
			free (s);
			break;
		}
		r_core_cmdf (core, "? %s", s);
		r_cons_flush ();
		free (s);
	}
	r_cons_enable_mouse (true);
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
	r_cons_enable_mouse (false);
	char *res = r_cons_input ("search string: ");
	if (res) {
		r_core_cmdf (core, "\"/ %s\"", res);
		free (res);
	}
	r_cons_enable_mouse (true);
	return 0;
}

static int ropCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_enable_mouse (false);
	char *res = r_cons_input ("rop grep: ");
	if (res) {
		r_core_cmdf (core, "\"/R %s\"", res);
		free (res);
	}
	r_cons_enable_mouse (true);
	return 0;
}

static int codeCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_enable_mouse (false);
	char *res = r_cons_input ("search code: ");
	if (res) {
		r_core_cmdf (core, "\"/c %s\"", res);
		free (res);
	}
	r_cons_enable_mouse (true);
	return 0;
}

static int hexpairsCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_enable_mouse (false);
	char *res = r_cons_input ("search hexpairs: ");
	if (res) {
		r_core_cmdf (core, "\"/x %s\"", res);
		free (res);
	}
	r_cons_enable_mouse (true);
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

static void updateDisassemblyAddr (RCore *core) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		if (!strcmp (panels->panel[i].cmd, PANEL_CMD_DISASSEMBLY)) {
			panels->panel[i].addr = core->offset;
		}
	}
	setRefreshAll (panels);
}

static int reloadCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_file_reopen_debug (core, "");
	updateDisassemblyAddr (core);
	setRefreshAll (core->panels);
	return 0;
}

static int functionCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "af");
	setRefreshAll (core->panels);
	return 0;
}

static int symbolsCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aa");
	setRefreshAll (core->panels);
	return 0;
}

static int programCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aaa");
	setRefreshAll (core->panels);
	return 0;
}

static int basicblocksCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aab");
	setRefreshAll (core->panels);
	return 0;
}

static int callsCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aac");
	setRefreshAll (core->panels);
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
	setRefreshAll (panels);
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
	setRefreshAll (panels);
	return 0;
}

static int referencesCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmdf (core, "aar");
	setRefreshAll (core->panels);
	return 0;
}

static int fortuneCb(void *user) {
	RCore *core = (RCore *)user;
	char *s = r_core_cmd_str (core, "fo");
	r_cons_message (s);
	free (s);
	return 0;
}

static int commandsCb(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "?;?@?;?$?;???");
	r_cons_any_key (NULL);
	return 0;
}

static int gameCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_2048 (core->panels->can->color);
	return 0;
}

static int screenLock(void *user) {
	RCore *core = (RCore *)user;
	r_core_cmd0 (core, "LL");
	return 0;
}

static int licenseCb(void *user) {
	r_cons_message ("Copyright 2006-2018 - pancake - LGPL");
	return 0;
}

static int aboutCb(void *user) {
	RCore *core = (RCore *)user;
	char *s = r_core_cmd_str (core, "?V");
	r_cons_message (s);
	free (s);
	return 0;
}

static int writeValueCb(void *user) {
	RCore *core = (RCore *)user;
	r_cons_enable_mouse (false);
	char *res = r_cons_input ("insert number: ");
	if (res) {
		r_core_cmdf (core, "\"wv %s\"", res);
		free (res);
	}
	r_cons_enable_mouse (true);
	return 0;
}

static int quitCb(void *user) {
	return 1;
}

static int openMenuCb (void *user) {
	RCore* core = (RCore *)user;
	RPanelsMenu *menu = core->panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	if (menu->depth < 2) {
		child->p->pos.x = menu->root->selectedIndex * 6;
		child->p->pos.y = 1;
	} else {
		RPanelsMenuItem *p = menu->history[menu->depth - 2];
		RPanelsMenuItem *parent2 = p->sub[p->selectedIndex];
		child->p->pos.x = parent2->p->pos.x + parent2->p->pos.w - 1;
		child->p->pos.y = menu->depth == 2 ? parent2->p->pos.y + parent2->selectedIndex : parent2->p->pos.y;
	}
	RStrBuf *buf = drawMenu (child);
	if (!buf) {
		return 0;
	}
	child->p->title = r_strbuf_drain (buf);
	child->p->pos.w = r_str_bounds (child->p->title, &child->p->pos.h);
	child->p->pos.h += 4;
	child->p->type = PANEL_TYPE_MENU;
	child->p->refresh = true;
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
		void *addr = ht_find (panels->mht, parent, NULL);
		p_item = (RPanelsMenuItem *)addr;
		ht_insert (panels->mht, sdb_fmt ("%s.%s", parent, name), item);
	} else {
		p_item = panels->panelsMenu->root;
		ht_insert (panels->mht, sdb_fmt ("%s", name), item);
	}
	item->n_sub = 0;
	item->selectedIndex = 0;
	item->name = name ? strdup (name) : NULL;
	item->sub = NULL;
	item->cb = cb;
	item->p = R_NEW0 (RPanel);
	if (!item->p) {
		free (item);
		return;
	}
	p_item->n_sub++;
	struct r_panels_menu_item **sub = realloc (p_item->sub, sizeof (RPanelsMenuItem *) * p_item->n_sub);
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
		menu->history[i]->p->refresh = true;
		menu->refreshPanels[i - 1] = menu->history[i]->p;
	}
	menu->n_refresh = menu->depth - 1;
	setRefreshAll (panels);
}

static RStrBuf *drawMenu(RPanelsMenuItem *item) {
	RStrBuf *buf = r_strbuf_new (NULL);
	if (!buf) {
		return NULL;
	}
	int i;
	for (i = 0; i < item->n_sub; i++) {
		if (i == item->selectedIndex) {
			r_strbuf_append (buf, "> ");
		} else {
			r_strbuf_append (buf, "  ");
		}
		r_strbuf_append (buf, item->sub[i]->name);
		r_strbuf_append (buf, "          \n");
	}
	return buf;
}

static void moveMenuCursor(RPanelsMenu *menu, RPanelsMenuItem *parent) {
	RStrBuf *buf = drawMenu (parent);
	if (!buf) {
		return;
	}
	parent->p->title = r_strbuf_drain (buf);
	parent->p->pos.w = r_str_bounds (parent->p->title, &parent->p->pos.h);
	parent->p->pos.h += 4;
	parent->p->type = PANEL_TYPE_MENU;
	parent->p->refresh = true;
	menu->refreshPanels[menu->n_refresh++] = parent->p;
}

static bool initPanelsMenu(RCore *core) {
	RPanels *panels = core->panels;
	RPanelsMenu *panelsMenu = R_NEW0 (RPanelsMenu);
	RPanelsMenuItem *root = R_NEW0 (RPanelsMenuItem);
	panels->panelsMenu = panelsMenu;
	panelsMenu->root = root;
	root->n_sub = 0;
	root->selectedIndex = 0;
	root->name = NULL;
	root->sub = NULL;
	int i;
	for (i = 0; i < MENU_NUM (menus); i++) {
		addMenu (core, NULL, menus[i], openMenuCb);
	}
	char *parent;

	parent = "File";
	for (i = 0; i < MENU_NUM (menus_File); i++) {
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
			addMenu (core, parent, menus_File[i], layoutSidePanel);
		}
	}

	parent = "Edit";
	for (i = 0; i < MENU_NUM (menus_Edit); i++) {
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
			addMenu (core, parent, menus_Edit[i], iocacheCb);
		} else {
			addMenu (core, parent, menus_Edit[i], layoutSidePanel);
		}
	}

	parent = "View";
	for (i = 0; i < MENU_NUM (menus_View); i++) {
		if (!strcmp (menus_View[i], "Colors")) {
			addMenu (core, parent, menus_View[i], colorsCb);
		} else {
			addMenu (core, parent, menus_View[i], layoutSidePanel);
		}
	}

	parent = "Tools";
	for (i = 0; i < MENU_NUM (menus_Tools); i++) {
		if (!strcmp (menus_Tools[i], "Calculator")) {
			addMenu (core, parent, menus_Tools[i], calculatorCb);
		} else if (!strcmp (menus_Tools[i], "R2 Shell")) {
			addMenu (core, parent, menus_Tools[i], r2shellCb);
		} else if (!strcmp (menus_Tools[i], "System Shell")) {
			addMenu (core, parent, menus_Tools[i], systemShellCb);
		}
	}

	parent = "Search";
	for (i = 0; i < MENU_NUM (menus_Search); i++) {
		if (!strcmp (menus_Search[i], "String")) {
			addMenu (core, parent, menus_Search[i], stringCb);
		} else if (!strcmp (menus_Search[i], "ROP")) {
			addMenu (core, parent, menus_Search[i], ropCb);
		} else if (!strcmp (menus_Search[i], "Code")) {
			addMenu (core, parent, menus_Search[i], codeCb);
		} else if (!strcmp (menus_Search[i], "Hexpairs")) {
			addMenu (core, parent, menus_Search[i], hexpairsCb);
		}
	}

	parent = "Debug";
	for (i = 0; i < MENU_NUM (menus_Debug); i++) {
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
			addMenu (core, parent, menus_Debug[i], layoutSidePanel);
		}
	}

	parent = "Analyze";
	for (i = 0; i < MENU_NUM (menus_Analyze); i++) {
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
	}

	parent = "Help";
	for (i = 0; i < MENU_NUM (menus_Help); i++) {
		if (!strcmp (menus_Help[i], "Fortune")) {
			addMenu (core, parent, menus_Help[i], fortuneCb);
		} else if (!strcmp (menus_Help[i], "Commands")) {
			addMenu (core, parent, menus_Help[i], commandsCb);
		} else if (!strcmp (menus_Help[i], "2048")) {
			addMenu (core, parent, menus_Help[i], gameCb);
		} else if (!strcmp (menus_Help[i], "License")) {
			addMenu (core, parent, menus_Help[i], licenseCb);
		} else if (!strcmp (menus_Help[i], "Lock Screen")) {
			addMenu (core, parent, menus_Help[i], screenLock);
		} else if (!strcmp (menus_Help[i], "About")) {
			addMenu (core, parent, menus_Help[i], aboutCb);
		}
	}

	parent = "File.ReOpen";
	for (i = 0; i < MENU_NUM (menus_ReOpen); i++) {
		if (!strcmp (menus_ReOpen[i], "In RW")) {
			addMenu (core, parent, menus_ReOpen[i], rwCb);
		} else if (!strcmp (menus_ReOpen[i], "In Debugger")) {
			addMenu (core, parent, menus_ReOpen[i], debuggerCb);
		}
	}

	parent = "File.Load Layout";
	for (i = 0; i < MENU_NUM (menus_loadLayout); i++) {
		if (!strcmp (menus_loadLayout[i], "Saved")) {
			addMenu (core, parent, menus_loadLayout[i], loadLayoutSavedCb);
		} else if (!strcmp (menus_loadLayout[i], "Default")) {
			addMenu (core, parent, menus_loadLayout[i], loadLayoutDefaultCb);
		}
	}

	root->selectedIndex = 0;
	panelsMenu->history = calloc (8, sizeof (RPanelsMenuItem *));
	panelsMenu->history[0] = root;
	panelsMenu->depth = 1;
	panelsMenu->n_refresh = 0;
	panelsMenu->refreshPanels = calloc (8, sizeof (RPanel *));
	return true;
}

static bool initPanels(RCore *core, RPanels *panels) {
	panels->panel = calloc (sizeof (RPanel), PANEL_NUM_LIMIT);
	if (!panels->panel) {
		return false;
	}
	panels->n_panels = 0;
	addPanelFrame (core, panels, PANEL_TITLE_DISASSEMBLY, PANEL_CMD_DISASSEMBLY);

	RAnalFunction *fun = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	if (fun && !r_list_empty (fun->bbs)) {
		addPanelFrame (core, panels, PANEL_TITLE_PSEUDO, PANEL_CMD_PSEUDO);
	}

	if (panels->layout == PANEL_LAYOUT_DEFAULT_DYNAMIC) {
		addPanelFrame (core, panels, PANEL_TITLE_STACK, PANEL_CMD_STACK);
		addPanelFrame (core, panels, PANEL_TITLE_STACKREFS, PANEL_CMD_STACKREFS);
		addPanelFrame (core, panels, PANEL_TITLE_REGISTERS, PANEL_CMD_REGISTERS);
		addPanelFrame (core, panels, PANEL_TITLE_REGISTERREFS, PANEL_CMD_REGISTERREFS);
	} else {
		addPanelFrame (core, panels, PANEL_TITLE_FUNCTIONS, PANEL_CMD_FUNCTIONS);
		addPanelFrame (core, panels, PANEL_TITLE_FCNINFO, PANEL_CMD_FCNINFO);
		addPanelFrame (core, panels, PANEL_TITLE_SYMBOLS, PANEL_CMD_SYMBOLS);
	}
	panels->curnode = 0;
	return true;
}

static void freeSinglePanel(RPanel *panel) {
	free (panel->title);
	free (panel->cmd);
	free (panel->cmdStrCache);
}

static void freeAllPanels(RPanels *panels) {
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		freeSinglePanel (&panels->panel[i]);
	}
	free (panels->panel);
}

R_API void r_core_panels_refresh(RCore *core) {
	RPanels *panels = core->panels;
	if (!panels) {
		return;
	}
	RPanel *panel = panels->panel;
	if (!panel) {
		return;
	}
	RConsCanvas *can = panels->can;
	if (!can) {
		return;
	}
	char title[1024];
	char str[1024];
	int i, h, w = r_cons_get_size (&h);
	r_cons_gotoxy (0, 0);
	if (panels->isResizing) {
		panels->isResizing = false;
		if (!r_cons_canvas_resize (can, w, h)) {
			return;
		}
		setRefreshAll (panels);
	}
	for (i = 0; i < panels->n_panels; i++) {
		if (i != panels->curnode) {
			panelPrint (core, can, &panel[i], 0);
		}
	}
	if (panels->curnode > panels->menu_pos) {
		panelPrint (core, can, &panel[panels->curnode], 1);
	}
	for (i = 0; i < panels->panelsMenu->n_refresh; i++) {
		panelPrint (core, can, panels->panelsMenu->refreshPanels[i], 1);
	}
	panels->panelsMenu->n_refresh = 0;
	(void) r_cons_canvas_gotoxy (can, -can->sx, -can->sy);
	r_cons_canvas_fill (can, -can->sx, -can->sy, panel->pos.w, 1, ' ');
	title[0] = 0;
	if (panels->curnode == panels->menu_pos) {
		strcpy (title, "> ");
	}
	const char *color = panels->curnode == panels->menu_pos ? core->cons->pal.graph_box : core->cons->pal.graph_box2;
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
			if (panels->curnode == panels->menu_pos) {
				if (i == parent->selectedIndex) {
					snprintf (str, sizeof (title) - 1, "%s[%s]"Color_RESET, color, item->name);
				} else {
					snprintf (str, sizeof (title) - 1, "%s %s "Color_RESET, color, item->name);
				}
			} else {
				snprintf (str, sizeof (title) - 1, "%s %s "Color_RESET, color, item->name);
			}
			strcat (title, str);
		}
	}
	if (panels->curnode == panels->menu_pos) {
		r_cons_canvas_write (can, Color_BLUE);
		r_cons_canvas_write (can, title);
		r_cons_canvas_write (can, Color_RESET);
	} else {
		r_cons_canvas_write (can, Color_RESET);
		r_cons_canvas_write (can, title);
	}

	snprintf (title, sizeof (title) - 1,
		"[0x%08"PFMT64x "]", core->offset);
	(void) r_cons_canvas_gotoxy (can, -can->sx + w - strlen (title), -can->sy);
	r_cons_canvas_write (can, title);
	r_cons_canvas_print (can);
	r_cons_flush ();
}

static void doPanelsRefresh(RCore *core) {
	if (!core->panels) {
		return;
	}
	core->panels->isResizing = true;
	panelAllClear (core->panels);
	r_core_panels_refresh (core);
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
	RPanels *panels = core->panels;
	RPanel *curPanel = &panels->panel[panels->curnode];
	if (!strcmp (curPanel->cmd, PANEL_CMD_DISASSEMBLY)) {
		r_core_cmd (core, "dbs $$", 0);
		curPanel->refresh = true;
	}
}

static void panelContinue(RCore *core) {
	r_core_cmd (core, "dc", 0);
}

R_API void r_core_panels_check_stackbase(RCore *core) {
	if (!core || !core->panels) {
		return;
	}
	int i;
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	const ut64 stackbase = r_reg_getv (core->anal->reg, sp);
	RPanels *panels = core->panels;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *panel = &panels->panel[i];
		if (panel->cmd && !strcmp (panel->cmd, PANEL_CMD_STACK) && panel->baseAddr != stackbase) {
			panel->baseAddr = stackbase;
			panel->addr = stackbase - r_config_get_i (core->config, "stack.delta") + core->print->cur;
			panel->refresh = true;
		}
	}
}

static void panelPrompt(const char *prompt, char *buf, int len) {
	r_line_set_prompt (prompt);
	*buf = 0;
	r_cons_fgets (buf, len, 0, NULL);
}

static void initSdb(RPanels *panels) {
	sdb_set (panels->db, "Symbols", "isq", 0);
	sdb_set (panels->db, "Stack"  , "px 256@r:SP", 0);
	sdb_set (panels->db, "Locals", "afvd", 0);
	sdb_set (panels->db, "StackRefs", "pxr 256@r:SP", 0);
	sdb_set (panels->db, "Registers", "dr=", 0);
	sdb_set (panels->db, "RegisterRefs", "drr", 0);
	sdb_set (panels->db, "Disassembly", "pd $r", 0);
	sdb_set (panels->db, "Pseudo", "pdc", 0);
	sdb_set (panels->db, "Graph", "agf", 0);
	sdb_set (panels->db, "Info", "i", 0);
	sdb_set (panels->db, "Database", "k ***", 0);
	sdb_set (panels->db, "Hexdump", "px 512", 0);
	sdb_set (panels->db, "Functions", "afl", 0);
	sdb_set (panels->db, "Comments", "CC", 0);
	sdb_set (panels->db, "Entropy", "p=e", 0);
	sdb_set (panels->db, "DRX", "drx", 0);
	sdb_set (panels->db, "Sections", "iSq", 0);
	sdb_set (panels->db, "Strings", "izq", 0);
	sdb_set (panels->db, "Maps", "dm", 0);
	sdb_set (panels->db, "Modules", "dmm", 0);
	sdb_set (panels->db, "Backtrace", "dbt", 0);
	sdb_set (panels->db, "Breakpoints", "db", 0);
	sdb_set (panels->db, "Imports", "iiq", 0);
	sdb_set (panels->db, "Clipboard", "yx", 0);
	sdb_set (panels->db, "FcnInfo", "afi", 0);
	sdb_set (panels->db, "New", "o", 0);
}

static void mht_free_kv(HtKv *kv) {
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
	panels->menu_pos = -1;
	panels->isResizing = false;
	panels->can = createNewCanvas (core, w, h);
	panels->db = sdb_new0 ();
	panels->mht = ht_new (NULL, (HtKvFreeFunc)mht_free_kv, (CalcSize)strlen);
	panels->mode = PANEL_MODE_DEFAULT;
	panels->prevMode = PANEL_MODE_NONE;
	initSdb (panels);

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

static void handleMenu(RCore *core, const int key, int *exit) {
	RPanels *panels = core->panels;
	RPanel *panel = panels->panel;
	RPanelsMenu *menu = panels->panelsMenu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	switch (key) {
	case 'h':
		handleLeftKey (core);
		break;
	case 'j':
		handleDownKey (core);
		break;
	case 'k':
		handleUpKey (core);
		break;
	case 'l':
		handleRightKey (core);
		break;
	case 'q':
	case -1:
		if (panels->panelsMenu->depth > 1) {
			removeMenu (panels);
		} else {
			*exit = 1;
		}
		return;
	case ' ':
	case '\r':
	case '\n':
		if (child->cb (core)) {
			*exit = 1;
		}
		break;
	case 9:
		handleTabKey (core, false);
		break;
	case 'Z':
		handleTabKey (core, true);
		break;
	case ':':
		{
			r_core_visual_prompt_input (core);
			int i;
			for (i = 0; i < panels->n_panels; i++) {
				if (!strcmp (panel[i].cmd, PANEL_CMD_DISASSEMBLY)) {
					panel[i].addr = core->offset;
					break;
				}
			}
			setRefreshAll (panels);
		}
		break;
	case '?':
		showHelp(core);
		break;
	}
}

static void handleTabKey(RCore *core, bool shift) {
	RPanels *panels = core->panels;
	r_cons_switchbuf (false);
	if (panels->curnode != panels->menu_pos) {
		panels->panel[panels->curnode].refresh = true;
	}
	if (!shift) {
		panels->curnode++;
		if (panels->curnode == panels->n_panels) {
			panels->curnode = panels->menu_pos;
		}
	} else {
		if (panels->curnode > panels->menu_pos) {
			panels->curnode--;
		} else {
			panels->curnode = panels->n_panels - 1;
		}
	}
	if (panels->curnode != panels->menu_pos) {
		panels->panel[panels->curnode].refresh = true;
	}
}

static void savePanelPos(RPanel* panel) {
	panel->prevPos.x = panel->pos.x;
	panel->prevPos.y = panel->pos.y;
	panel->prevPos.w = panel->pos.w;
	panel->prevPos.h = panel->pos.h;
}

static void restorePanelPos(RPanel* panel) {
	panel->pos.x = panel->prevPos.x;
	panel->pos.y = panel->prevPos.y;
	panel->pos.w = panel->prevPos.w;
	panel->pos.h = panel->prevPos.h;
}

static char *getPanelsConfigPath() {
	char *configPath = r_str_newf (R_JOIN_2_PATHS (R2_HOME_DATADIR, ".r2panels"));
	if (!configPath) {
		return NULL;
	}
	char *newPath = r_str_home (configPath);
	R_FREE (configPath);
	return newPath;
}

static void savePanelsLayout(RCore* core, bool temp) {
	RPanels *panels = core->panels;
	char buf[1024];
	char *tmp = buf;
	int i, sz = sizeof (buf);
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = &panels->panel[i];
		RJSVar* obj = r_json_object_new ();
		RJSVar* title = r_json_string_new (panel->title);
		RJSVar* cmd = r_json_string_new (panel->cmd);
		RJSVar* x = r_json_number_new (panel->pos.x);
		RJSVar* y = r_json_number_new (panel->pos.y);
		RJSVar* w = r_json_number_new (panel->pos.w);
		RJSVar* h = r_json_number_new (panel->pos.h);
		R_JSON_FREE_ON_FAIL (r_json_object_add (obj, "Title", title), title);
		R_JSON_FREE_ON_FAIL (r_json_object_add (obj, "Cmd", cmd), cmd);
		R_JSON_FREE_ON_FAIL (r_json_object_add (obj, "x", x), x);
		R_JSON_FREE_ON_FAIL (r_json_object_add (obj, "y", y), y);
		R_JSON_FREE_ON_FAIL (r_json_object_add (obj, "w", w), w);
		R_JSON_FREE_ON_FAIL (r_json_object_add (obj, "h", h), h);
		char* c = r_json_stringify (obj, true);
		snprintf (tmp, sz, "%s\n", c);
		tmp += strlen (c) + 1;
		sz -= strlen (c) + 1;
		r_json_var_free (obj);
		r_json_var_free (title);
		r_json_var_free (cmd);
		r_json_var_free (x);
		r_json_var_free (y);
		r_json_var_free (w);
		r_json_var_free (h);
		free (c);
	}
	if (!temp) {
		char *configPath = getPanelsConfigPath ();
		FILE *panelsConfig = r_sandbox_fopen (configPath, "w");
		free (configPath);
		if (panelsConfig) {
			fprintf (panelsConfig, "%s", buf);
			fclose (panelsConfig);
		}
	} else {
		core->panels_tmpcfg = strdup (buf);
	}
}

static int loadSavedPanelsLayout(RCore* core, bool temp) {
	int i, s;
	char *panelsConfig;
	if (!temp) {
		char *configPath = getPanelsConfigPath ();
		panelsConfig = r_file_slurp (configPath, &s);
		free (configPath);
		if (!panelsConfig) {
			free (panelsConfig);
			return 0;
		}
	} else {
		panelsConfig = core->panels_tmpcfg;
	}
	int count = r_str_split (panelsConfig, '\n');
	RPanels *panels = core->panels;
	panelAllClear (panels);
	panels->n_panels = 0;
	panels->curnode = 0;
	char *title, *cmd, *x, *y, *w, *h, *p = panelsConfig;
	for (i = 1; i < count; i++) {
		title = sdb_json_get_str (p, "Title");
		cmd = sdb_json_get_str (p, "Cmd");
		x = sdb_json_get_str (p, "x");
		y = sdb_json_get_str (p, "y");
		w = sdb_json_get_str (p, "w");
		h = sdb_json_get_str (p, "h");
		panels->panel[panels->n_panels].title = title;
		panels->panel[panels->n_panels].cmd = cmd;
		panels->panel[panels->n_panels].pos.x = atoi (x);
		panels->panel[panels->n_panels].pos.y = atoi (y);
		panels->panel[panels->n_panels].pos.w = atoi (w);
		panels->panel[panels->n_panels].pos.h = atoi (h);
		panels->panel[panels->n_panels].addr  = core->offset;
		panels->n_panels++;
		p += strlen (p) + 1;
	}
	free (panelsConfig);
	setRefreshAll (core->panels);
	return 1;
}

static void maximizePanelSize(RPanels *panels) {
	RPanel *panel = &panels->panel[panels->curnode];
	panel->pos.x = 0;
	panel->pos.y = 1;
	panel->pos.w = panels->can->w;
	panel->pos.h = panels->can->h - 1;
	panel->refresh = true;
}

static void toggleZoomMode(RPanels *panels) {
	RPanel *curPanel = &panels->panel[panels->curnode];
	if (panels->mode != PANEL_MODE_ZOOM) {
		panels->prevMode = panels->mode;
		panels->mode = PANEL_MODE_ZOOM;
		savePanelPos (curPanel);
		maximizePanelSize (panels);
	} else {
		panels->mode = panels->prevMode;
		panels->prevMode = PANEL_MODE_NONE;
		restorePanelPos (curPanel);
		setRefreshAll (panels);
	}
}

static void toggleWindowMode(RPanels *panels) {
	if (panels->mode != PANEL_MODE_WINDOW) {
		panels->prevMode = panels->mode;
		panels->mode = PANEL_MODE_WINDOW;
	} else {
		panels->mode = panels->prevMode;
		panels->prevMode = PANEL_MODE_NONE;
	}
}

static void showHelp(RCore *core) {
	RStrBuf *p = r_strbuf_new (NULL);
	if (!p) {
		return;
	}
	r_cons_clear00 ();
	r_core_visual_append_help (p, "Visual Ascii Art Panels", help_msg_panels);
	r_core_visual_append_help (p, "Window management", help_msg_panels_window);
	int ret = r_cons_less_str (r_strbuf_get (p), "?");
	r_strbuf_free (p);
	if (ret == '?') {
		r_core_visual_hud (core);
	}
}

static void insertValue(RCore *core) {
	RPanels *panels = core->panels;
	char buf[128];
	if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_STACK)) {
		const char *prompt = "insert hex: ";
		panelPrompt (prompt, buf, sizeof (buf));
		r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, panels->panel[panels->curnode].addr);
		panels->panel[panels->curnode].refresh = true;
	} else if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_REGISTERS)) {
		const char *creg = core->dbg->creg;
		if (creg) {
			const char *prompt = "new-reg-value> ";
			panelPrompt (prompt, buf, sizeof (buf));
			r_core_cmdf (core, "dr %s = %s", creg, buf);
			panels->panel[panels->curnode].refresh = true;
		}
	} else if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)) {
		const char *prompt = "insert hex: ";
		panelPrompt (prompt, buf, sizeof (buf));
		r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, core->offset + core->print->cur);
		panels->panel[panels->curnode].refresh = true;
	}
}

R_API RPanels *r_core_panels_new(RCore *core) { int w, h;
	RPanels *panels = R_NEW0 (RPanels);

	if (!panels) {
		return NULL;
	}
	w = r_cons_get_size (&h);
	if (!init (core, panels, w, h)) {
		free (panels);
		return NULL;
	}
	return panels;
}

R_API void r_core_panels_free(RPanels *panels) {
	r_cons_switchbuf (true);
	if (panels) {
		freeAllPanels (panels);
		r_cons_canvas_free (panels->can);
		sdb_free (panels->db);
		ht_free (panels->mht);
		free (panels);
	}
}

static bool moveToDirection(RPanels *panels, Direction direction) {
	RPanel *panel = panels->panel;
	RPanel *cur = &panel[panels->curnode];
	int cur_x0 = cur->pos.x, cur_x1 = cur->pos.x + cur->pos.w - 1, cur_y0 = cur->pos.y, cur_y1 = cur->pos.y + cur->pos.h - 1;
	int temp_x0, temp_x1, temp_y0, temp_y1;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		temp_x0 = panel[i].pos.x;
		temp_x1 = panel[i].pos.x + panel[i].pos.w - 1;
		temp_y0 = panel[i].pos.y;
		temp_y1 = panel[i].pos.y + panel[i].pos.h - 1;
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

R_API int r_core_visual_panels(RCore *core, RPanels *panels) {
	int i, okey, key, wheel;

	if (!panels) {
		panels = r_core_panels_new (core);
		if (!panels) {
			r_core_panels_free (panels);
			return false;
		}
	}
	RPanels *prev = core->panels;
	core->panels = panels;

	if (!initPanelsMenu (core)) {
		return false;
	}

	if (!initPanels (core, panels)) {
		r_core_panels_free (panels);
		return false;
	}

	r_cons_switchbuf (false);
	int originCursor = core->print->cur;
	core->print->cur = 0;
	core->print->cur_enabled = false;
	core->print->col = 0;
	bool originVmode = core->vmode;
	core->vmode = true;

	if (core->panels_tmpcfg) {
		loadSavedPanelsLayout (core, true);
	} else {
		r_core_panels_layout (panels);
	}
repeat:
	core->panels = panels;
	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = core;
	core->cons->event_resize = (RConsEvent) doPanelsRefreshOneShot;
	r_core_panels_layout_refresh (core);
	wheel = r_config_get_i (core->config, "scr.wheel");
	if (wheel) {
		r_cons_enable_mouse (true);
	}
	okey = r_cons_readchar ();
	key = r_cons_arrow_to_hjkl (okey);
	r_cons_switchbuf (true);

	if (panels->curnode == panels->menu_pos) {
		int exit = 0;
		handleMenu (core, key, &exit);
		if (exit) {
			goto exit;
		}
		goto repeat;
	}

	if (handleCursorMode (core, key)) {
		goto repeat;
	}

	if (panels->mode == PANEL_MODE_ZOOM) {
		handleZoomMode (core, key);
		goto repeat;
	}

	if (panels->mode == PANEL_MODE_WINDOW) {
		handleWindowMode (core, key);
		goto repeat;
	}

	if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)
			&& '0' < key && key <= '9') {
		ut8 ch = key;
		r_core_visual_jump (core, ch);
		panels->panel[panels->curnode].addr = core->offset;
		panels->panel[panels->curnode].refresh = true;
		goto repeat;
	}

	const char *cmd;
	RConsCanvas *can = panels->can;
	switch (key) {
	case 'u':
		r_core_cmd0 (core, "s-");
		break;
	case 'U':
		r_core_cmd0 (core, "s+");
		break;
	case 'n':
		{
			r_cons_enable_mouse (false);
			char *res = r_cons_input ("New panel with command: ");
			if (res) {
				if (*res) {
					addPanelFrame (core, panels, res, res);
					// refresh stuff 
					changePanelNum (panels, panels->n_panels - 1, 0);
					r_core_panels_layout (core->panels);
					setRefreshAll (core->panels);
				}
				free (res);
			}
			r_cons_enable_mouse (true);
		}
		break;
	case 'N':
		{
			r_cons_enable_mouse (false);
			char *res = r_cons_input ("New panel with command: ");
			if (res) {
				if (*res) {
					addPanelFrame (core, panels, NULL, res);
					// refresh stuff 
					r_core_panels_layout (core->panels);
					setRefreshAll (core->panels);
					core->panels->panelsMenu->depth = 1;
				}
				free (res);
			}
			r_cons_enable_mouse (true);
		}
		break;
	case 'p':
		r_core_cmd0 (core, "sp");
		break;
	case 'P':
		r_core_cmd0 (core, "sn");
		break;
	case '.':
		if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)) {
			ut64 addr = r_debug_reg_get (core->dbg, "PC");
			if (addr && addr != UT64_MAX) {
				r_core_seek (core, addr, 1);
			} else {
				addr = r_num_get (core->num, "entry0");
				if (addr && addr != UT64_MAX) {
					r_core_seek (core, addr, 1);
				}
			}
			panels->panel[panels->curnode].addr = core->offset;
			panels->panel[panels->curnode].refresh = true;
		}
		break;
	case '?':
		showHelp(core);
		break;
	case 'b':
		r_core_visual_browse (core);
		break;
	case 'o':
		r_core_visual_showcursor (core, true);
		r_core_visual_offset (core);
		r_core_visual_showcursor (core, false);
		panels->panel[panels->curnode].addr = core->offset;
		panels->panel[panels->curnode].refresh = true;
		break;
	case 's':
		panelSingleStepIn (core);
		if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)) {
			panels->panel[panels->curnode].addr = core->offset;
		}
		setRefreshAll (panels);
		break;
	case 'S':
		panelSingleStepOver (core);
		if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)) {
			panels->panel[panels->curnode].addr = core->offset;
		}
		setRefreshAll (panels);
		break;
	case ' ':
			if (r_config_get_i (core->config, "graph.web")) {
				r_core_cmd0 (core, "agv $$");
			} else {
				RAnalFunction *fun = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
				int ocolor = r_config_get_i (core->config, "scr.color");
				if (!fun) {
					r_cons_message ("Not in a function. Type 'df' to define it here");
					break;
				} else if (r_list_empty (fun->bbs)) {
					r_cons_message ("No basic blocks in this function. You may want to use 'afb+'.");
					break;
				}
			//	reset_print_cur (core->print);
				eprintf ("\rRendering graph...");
				r_core_visual_graph (core, NULL, NULL, true);
				r_config_set_i (core->config, "scr.color", ocolor);
			}
		break;
	case ':':
		r_core_visual_prompt_input (core);
		panels->panel[panels->curnode].addr = core->offset;
		setRefreshAll (panels);
		break;
	case 'c':
		activateCursor (core);
		break;
	case 'C':
		can->color = !can->color;
		// r_config_toggle (core->config, "scr.color");
		// refresh graph
		setRefreshAll (panels);
		break;
	case 'r':
		r_core_cmd0 (core, "e!asm.jmphints");
		r_core_cmd0 (core, "e!asm.leahints");
		setRefreshAll (panels);
		break;
	case 'R':
		if (r_config_get_i (core->config, "scr.randpal")) {
			r_core_cmd0 (core, "ecr");
		} else {
			r_core_cmd0 (core, "ecn");
		}
		doPanelsRefresh (core);
		break;
	case 'A':
		r_core_visual_asm (core, core->offset);
		break;
	case 'd':
		r_core_visual_define (core, "");
		setRefreshAll (panels);
		break;
	case 'D':
		replaceCmd (panels, PANEL_TITLE_DISASSEMBLY, PANEL_CMD_DISASSEMBLY);
		break;
	case 'j':
		handleDownKey (core);
		break;
	case 'k':
		handleUpKey (core);
		break;
	case '<':
		for (i = 0; i < PANEL_CONFIG_PAGE; i++) {
			handleUpKey (core);
		}
		break;
	case '>':
		for (i = 0; i < PANEL_CONFIG_PAGE; i++) {
			handleDownKey (core);
		}
		break;
	case '_':
		if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)) {
			r_core_visual_hudstuff (core);
			panels->panel[panels->curnode].addr = core->offset;
			setRefreshAll (panels);
		}
		break;
	case 'x':
		r_core_visual_refs (core, true);
		core->panels->panel[core->panels->curnode].addr = core->offset;
		setRefreshAll (panels);
		break;
	case 'X':
		delCurPanel (panels);
		setRefreshAll (panels);
		break;
	case 9: // TAB
		handleTabKey (core, false);
		break;
	case 'Z': // SHIFT-TAB
		handleTabKey (core, true);
		break;
	case 'M':
	{
		r_cons_enable_mouse (false);
		char *name = r_cons_input ("Name: ");
		char *cmd = r_cons_input ("Command: ");
		if (name && *name && cmd && *cmd) {
			addPanelFrame (core, panels, name, cmd);
		}
		free (name);
		free (cmd);
		r_cons_enable_mouse (true);
	}
	break;
	case 'e':
	{
		r_cons_enable_mouse (false);
		char *new_name = r_cons_input ("New name: ");
		char *new_cmd = r_cons_input ("New command: ");
		if (new_name && *new_name && new_cmd && *new_cmd) {
			replaceCmd (panels, new_name, new_cmd);
		}
		free (new_name);
		free (new_cmd);
		r_cons_enable_mouse (true);
	}
	break;
	case 'm':
		panels->curnode = panels->menu_pos;
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
		resizePanelDown(panels);
		break;
	case 'K':
		r_cons_switchbuf (false);
		resizePanelUp (panels);
		break;
	case 'g':
		if (checkFunc (core)) {
			replaceCmd (panels, PANEL_TITLE_GRAPH, PANEL_CMD_GRAPH);
		}
		break;
	case 'h':
		handleLeftKey (core);
		break;
	case 'l':
		handleRightKey (core);
		break;
	case 'V':
		if (r_config_get_i (core->config, "graph.web")) {
			r_core_cmd0 (core, "agv $$");
		} else {
			if (checkFunc (core)) {
				r_cons_canvas_free (can);
				panels->can = NULL;

				int ocolor = r_config_get_i (core->config, "scr.color");
				r_core_visual_graph (core, NULL, NULL, true);
				r_config_set_i (core->config, "scr.color", ocolor);

				int h, w = r_cons_get_size (&h);
				panels->can = createNewCanvas (core, w, h);

				setRefreshAll (panels);
			}
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
			RPanel p0 = panels->panel[0];
			panels->panel[0] = panels->panel[panels->curnode];
			panels->panel[panels->curnode] = p0;
			r_core_panels_layout_refresh (core);
			setRefreshAll (panels);
		}
		break;
	case 'w':
		toggleWindowMode (panels);
		setRefreshAll (panels);
		break;
	case 0x0d: // "\\n"
		toggleZoomMode (panels);
		break;
	case '|':
		splitPanelVertical (core);
		break;
	case '-':
		splitPanelHorizontal (core);
		break;
	case '*':
		if (checkFunc (core)) {
			r_cons_canvas_free (can);
			panels->can = NULL;

			replaceCmd (panels, PANEL_TITLE_PSEUDO, PANEL_CMD_PSEUDO);

			int h, w = r_cons_get_size(&h);
			panels->can = createNewCanvas (core, w, h);
		}
		break;
	case R_CONS_KEY_F1:
		cmd = r_config_get (core->config, "key.f1");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F2:
		cmd = r_config_get (core->config, "key.f2");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		} else {
			panelBreakpoint (core);
		}
		break;
	case R_CONS_KEY_F3:
		cmd = r_config_get (core->config, "key.f3");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F4:
		cmd = r_config_get (core->config, "key.f4");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F5:
		cmd = r_config_get (core->config, "key.f5");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F6:
		cmd = r_config_get (core->config, "key.f6");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F7:
		cmd = r_config_get (core->config, "key.f7");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		} else {
			panelSingleStepIn (core);
			setRefreshAll (panels);
		}
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		} else {
			panelSingleStepOver (core);
			setRefreshAll (panels);
		}
		break;
	case R_CONS_KEY_F9:
		cmd = r_config_get (core->config, "key.f9");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		} else {
			panelContinue (core);
		}
		break;
	case R_CONS_KEY_F10:
		cmd = r_config_get (core->config, "key.f10");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F11:
		cmd = r_config_get (core->config, "key.f11");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F12:
		cmd = r_config_get (core->config, "key.f12");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		}
		break;
	case '!':
		r_cons_2048 (core->panels->can->color);
		break;
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
	savePanelsLayout (core, true);
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	core->print->cur = originCursor;
	core->print->cur_enabled = false;
	core->print->col = 0;
	core->vmode = originVmode;

	r_core_panels_free (panels);
	core->panels = prev;
	return true;
}

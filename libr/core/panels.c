/* Copyright radare2 2014-2018 - Author: pancake, vane11ope */

// pls move the typedefs into roons and rename it -> RConsPanel

#include <r_core.h>

#define PANEL_NUM_LIMIT 256
#define PANEL_MENU_LIMIT 10

#define PANEL_TITLE_SYMBOLS      "Symbols"
#define PANEL_TITLE_STACK        "Stack"
#define PANEL_TITLE_LOCALS       "Locals"
#define PANEL_TITLE_STACKREFS    "StackRefs"
#define PANEL_TITLE_REGISTERS    "Registers"
#define PANEL_TITLE_REGISTERREFS "RegisterRefs"
#define PANEL_TITLE_DISASSEMBLY  "Disassembly"
#define PANEL_TITLE_PSEUDO       "Pseudo"
#define PANEL_TITLE_NEWFILES     "New files"
#define PANEL_TITLE_INFO         "Info"
#define PANEL_TITLE_DATABASE     "Database"
#define PANEL_TITLE_HEXDUMP      "Hexdump"
#define PANEL_TITLE_FUNCTIONS    "Functions"
#define PANEL_TITLE_COMMENTS     "Comments"
#define PANEL_TITLE_ENTROPY      "Entropy"
#define PANEL_TITLE_DRX          "DRX"
#define PANEL_TITLE_SECTIONS     "Sections"
#define PANEL_TITLE_STRINGS      "Strings"
#define PANEL_TITLE_MAPS         "Maps"
#define PANEL_TITLE_MODULES      "Modules"
#define PANEL_TITLE_BACKTRACE    "Backtrace"
#define PANEL_TITLE_BREAKPOINTS  "Breakpoints"
#define PANEL_TITLE_IMPORTS      "Imports"
#define PANEL_TITLE_CLIPBOARD    "Clipboard"
#define PANEL_TITLE_FCNINFO      "FcnInfo"
#define PANEL_TITLE_GRAPH        "Graph"

#define PANEL_CMD_SYMBOLS        "isq"
#define PANEL_CMD_STACK          "px 256@r:SP"
#define PANEL_CMD_STACKREFS      "pxr 256@r:SP"
#define PANEL_CMD_LOCALS         "afvd"
#define PANEL_CMD_REGISTERS      "dr="
#define PANEL_CMD_REGISTERREFS   "drr"
#define PANEL_CMD_DISASSEMBLY    "pd $r"
#define PANEL_CMD_PSEUDO         "pdc"
#define PANEL_CMD_GRAPH          "agf"
#define PANEL_CMD_INFO           "i"
#define PANEL_CMD_DATABASE       "k ***"
#define PANEL_CMD_HEXDUMP        "px 512"
#define PANEL_CMD_FUNCTIONS      "afl"
#define PANEL_CMD_COMMENTS       "CC"
#define PANEL_CMD_ENTROPY        "p=e"
#define PANEL_CMD_DRX            "drx"
#define PANEL_CMD_SECTIONS       "iSq"
#define PANEL_CMD_STRINGS        "izq"
#define PANEL_CMD_MAPS           "dm"
#define PANEL_CMD_MODULES        "dmm"
#define PANEL_CMD_BACKTRACE      "dbt"
#define PANEL_CMD_BREAKPOINTS    "db"
#define PANEL_CMD_IMPORTS        "iiq"
#define PANEL_CMD_CLIPBOARD      "yx"
#define PANEL_CMD_FCNINFO        "afi"

#define PANEL_CONFIG_PAGE        10
#define PANEL_CONFIG_SIDEPANEL_W 60
#define PANEL_CONFIG_RESIZE_W    4
#define PANEL_CONFIG_RESIZE_H    4

static const int layoutMaxCount = 2;

enum {
	LAYOUT_DEFAULT = 0,
	LAYOUT_BALANCE = 1
};

static const char *menus[] = {
	"File", "Edit", "View", "Tools", "Search", "Debug", "Analyze", "Help",
	NULL
};
static const int menuNum = ((int)sizeof (menus) / (int)sizeof (const char*)) - 1;

static const char *menus_File[] = {
	"New", "Open", "ReOpen", "Close", "Sections", "Strings", "Symbols", "Imports", "Info", "Database",  "Quit",
	NULL
};

static const char *menus_ReOpen[] = {
	"In RW", "In Debugger",
	NULL
};

static const char *menus_Edit[] = {
	"Copy", "Paste", "Clipboard", "Write String", "Write Hex", "Write Value", "Assemble", "Fill", "io.cache",
	NULL
};

static const char *menus_View[] = {
	"Hexdump", "Disassembly", "Graph", "FcnInfo", "Functions", "Comments", "Entropy", "Colors",
	"Stack", "StackRefs", "Pseudo",
	NULL
};

static const char *menus_Tools[] = {
	"Assembler", "Calculator", "R2 Shell", "System Shell",
	NULL
};

static const char *menus_Search[] = {
	"String", "ROP", "Code", "Hexpairs",
	NULL
};

static const char *menus_Debug[] = {
	"Registers", "RegisterRefs", "DRX", "Breakpoints",
	"Watchpoints", "Maps", "Modules",
	"Backtrace", "Locals",
	"Continue", "Cont until.",
	"Step", "Step Over",
	"Reload",
	NULL
};

static const char *menus_Analyze[] = {
	"Function", "Symbols", "Program", "BasicBlocks", "Calls", "References",
	NULL
};

static const char *menus_Help[] = {
	"Fortune", "Commands", "2048", "License", ".", "About",
	NULL
};

static void layoutMenu(RPanel *panel);
static void layoutSubMenu(RPanels *panels, int w);
static void layoutDefault(RPanels *panels);
static void layoutBalance(RPanels *panels);
static void layoutSidePanel(RCore *core, const char *title, const char *cmd);
static void changePanelNum(RPanels *panels, int now, int after);
static void splitPanelVertical(RCore *core);
static void splitPanelHorizontal(RCore *core);
static void panelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int color);
static void panelAllClear(RPanels *panels);
static void addPanelFrame(RCore* core, RPanels* panels, const char *title, const char *cmd);
static RPanel createMenuPanel(int x, int y, char *title);
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
static bool init(RCore *core, RPanels *panels, int w, int h);
static bool initPanels(RCore *core, RPanels *panels);
static void freePanel(RPanel *panel);
static void panelBreakpoint(RCore *core);
static void panelContinue(RCore *core);
static void panelPrompt(const char *prompt, char *buf, int len);
static void panelSingleStepIn(RCore *core);
static void panelSingleStepOver(RCore *core);
static void setRefreshAll(RPanels *panels);
static void setCursor(RCore *core, bool cur);
static void savePanelPos(RPanel* panel);
static void restorePanelPos(RPanel* panel);
static void replaceCmd(RPanels* panels, char *title, char *cmd);
static void handleMenu(RCore *core, const int key, int *exit);
static void onMenu(RCore *core, const char *menu, int *exit);
static void changeMenu(RPanels *panels, const char **dstMenu);
static void switchMode(RPanels *panels);
static void maximizePanelSize(RPanels *panels);
static void insertValue(RCore *core);
static RConsCanvas *createNewCanvas(RCore *core, int w, int h);

static void panelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int color) {
	if (!can || !panel|| !panel->refresh) {
		return;
	}

	if (can->w <= panel->pos.x || can->h <= panel->pos.y) {
		return;
	}
	int w = R_MIN (can->w - panel->pos.x, panel->pos.w);
	int h = R_MIN (can->h - panel->pos.y, panel->pos.h);

	panel->refresh = false;
	char *text;
	char title[128];
	int delta_x, delta_y, graph_pad = 0;
	delta_x = panel->sx;
	delta_y = panel->sy;
	r_cons_canvas_fill (can, panel->pos.x, panel->pos.y, w, h, ' ');
	if (panel->type == PANEL_TYPE_MENU) {
		(void) r_cons_canvas_gotoxy (can, panel->pos.x + 2, panel->pos.y + 2);
		text = r_str_ansi_crop (panel->title,
				delta_x, delta_y, w + 5, h - delta_y);
		if (text) {
			r_cons_canvas_write (can, text);
			free (text);
		} else {
			r_cons_canvas_write (can, panel->title);
		}
	} else {
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
		char *cmdStr;
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
		if (delta_y < 0) {
			delta_y = 0;
		}
		if (delta_x < 0) {
			char *white = (char*)r_str_pad (' ', 128);
			int idx = -delta_x;
			if (idx >= sizeof (white)) {
				idx = sizeof (white) - 1;
			}
			white[idx] = 0;
			text = r_str_ansi_crop (cmdStr,
					0, delta_y + graph_pad, w + delta_x - 3, h - 2 + delta_y);
			char *newText = r_str_prefix_all (text, white);
			if (newText) {
				free (text);
				text = newText;
			}
		} else {
			text = r_str_ansi_crop (cmdStr,
					delta_x, delta_y + graph_pad, w + delta_x - 3, h - 2 + delta_y);
		}
		if (text) {
			r_cons_canvas_write (can, text);
			free (text);
		} else {
			r_cons_canvas_write (can, panel->title);
		}
		if (!panel->cmdStrCache) {
			free (cmdStr);
		}
	}
	if (color) {
		r_cons_canvas_box (can, panel->pos.x, panel->pos.y, w, h, core->cons->pal.graph_box2);
	} else {
		r_cons_canvas_box (can, panel->pos.x, panel->pos.y, w, h, core->cons->pal.graph_box);
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

static void layoutMenu(RPanel *panel) {
	panel->pos.w = r_str_bounds (panel->title, &panel->pos.h);
	panel->pos.h += 4;
}

static void layoutSubMenu(RPanels *panels, int w) {
	int i, j;
	RPanel panel;
	int x = panels->menuIndexStack[0] * 6;
	int y = 1;
	const char **currentMenu;
	int currentMenuIndex;
	for (i = 0; i < panels->menuStackDepth; i++) {
		if (i == 0) {
			continue;
		}
		currentMenu = panels->menuStack[i];
		currentMenuIndex = panels->menuIndexStack[i];
		RStrBuf *tit = r_strbuf_new (NULL);
		if (!tit) {
			return;
		}
		for (j = 0; currentMenu[j]; j++) {
			if (currentMenuIndex == j) {
				r_strbuf_append (tit, "> ");
			} else {
				r_strbuf_append (tit, "  ");
			}
			r_strbuf_append (tit, currentMenu[j]);
			r_strbuf_append (tit, "          \n");
		}
		panel = createMenuPanel (x, y, r_strbuf_drain (tit));
		layoutMenu (&panel);
		panels->menuPanel[i] = panel;
		x += panel.pos.w - 1;
		y = panels->menuIndexStack[i] + 2;
	}
	RStrBuf *tit = r_strbuf_new (NULL);
	if (!tit) {
		return;
	}
	for (i = 0; panels->currentMenu[i]; i++) {
		if (panels->currentMenuIndex == i) {
			r_strbuf_append (tit, "> ");
		} else {
			r_strbuf_append (tit, "  ");
		}
		r_strbuf_append (tit, panels->currentMenu[i]);
		r_strbuf_append (tit, "          \n");
	}
	panel = createMenuPanel (x, y, r_strbuf_drain (tit));
	layoutMenu (&panel);
	panels->menuPanel[panels->menuStackDepth] = panel;
}

R_API void r_core_panels_layout (RPanels *panels) {
	panels->can->sx = 0;
	panels->can->sy = 0;
	switch (panels->layout) {
		case LAYOUT_DEFAULT:
			layoutDefault (panels);
			break;
		case LAYOUT_BALANCE:
			layoutBalance (panels);
			break;
	}
}

static void layoutDefault(RPanels *panels) {
	int h, w = r_cons_get_size (&h);
	int ph = (h - 1) / (panels->n_panels - 1);
	int i;
	int colpos = w - panels->columnWidth;
	RPanel *panel = panels->panel;
	panel[0].pos.x = 0;
	panel[0].pos.y = 1;
	if (panels->n_panels > 1) {
		panel[0].pos.w = colpos + 1;
	} else {
		panel[0].pos.w = w;
	}
	panel[0].pos.h = h - 1;
	for (i = 1; i < panels->n_panels; i++) {
		panel[i].pos.x = colpos;
		panel[i].pos.y = 2 + (ph * (i - 1));
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

static void layoutBalance(RPanels *panels) {
	int h, w = r_cons_get_size (&h);
	int i, ii;
	int panelNum = panels->n_panels;
	int leftCol = panelNum / 2;
	int rightCol = panelNum - leftCol;
	int pw = w / 2;
	RPanel *panel = panels->panel;
	for (i = 0; i < leftCol; i++) {
		panel[i].pos.x = 0;
		panel[i].pos.y = 1 + i * (h / leftCol - 1);
		panel[i].pos.w = pw + 2;
		panel[i].pos.h = h / leftCol;
		if (i == leftCol - 1) {
			panel[i].pos.h = h - panel[i].pos.y;
		} else {
			panel[i].pos.h = h / leftCol;
		}
	}
	for (i = 0; i < rightCol; i++) {
		ii = i + leftCol;
		panel[ii].pos.x = pw + 1;
		panel[ii].pos.y = 1 + i * (h / rightCol - 1);
		panel[ii].pos.w = pw - 1;
		if (i == rightCol - 1) {
			panel[ii].pos.h = h - panel[ii].pos.y;
		} else {
			panel[ii].pos.h = h / rightCol;
		}
	}
}

static void layoutSidePanel(RCore *core, const char *title, const char *cmd) {
	RPanels *panels = core->panels;
	RPanel *panel = panels->panel;
	int h;
	r_cons_get_size (&h);
	int i;
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

	addPanelFrame (core, panels, title, cmd);
	changePanelNum (panels, panels->n_panels - 1, 0);
	panel[0].pos.x = 0;
	panel[0].pos.y = 1;
	panel[0].pos.w = PANEL_CONFIG_SIDEPANEL_W;
	panel[0].pos.h = h - 1;
	panels->curnode = 0;
	setRefreshAll (panels);
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
		if (panels->menuStackDepth == 0) {
			return;
		} else if (panels->menuStackDepth == 1) {
			if (!panels->currentMenuIndex) {
				panels->menuStackDepth = 0;
				panels->currentMenuIndex = panels->menuIndexStack[0];
				panels->currentMenu = panels->menuStack[0];
				setRefreshAll (panels);
			} else {
				panels->currentMenuIndex--;
			}
		} else {
			if (panels->currentMenuIndex) {
				panels->currentMenuIndex--;
			}
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
		if (!panels->menuStackDepth) {
			int exit = 0;
			onMenu (core, panels->currentMenu[panels->currentMenuIndex], &exit);
		} else {
			if (panels->currentMenu[panels->currentMenuIndex + 1]) {
				panels->currentMenuIndex++;
			}
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
		if (!panels->menuStackDepth) {
			if (panels->currentMenuIndex) {
				panels->currentMenuIndex--;
			} else  {
				panels->currentMenuIndex = menuNum - 1;
			}
		} else if (panels->menuStackDepth > 0) {
			panels->menuStackDepth = 0;
			panels->currentMenu = panels->menuStack[0];
			if (panels->menuIndexStack[0]) {
				panels->currentMenuIndex = panels->menuIndexStack[0] - 1;
			} else {
				panels->currentMenuIndex = menuNum - 1;
			}
			setRefreshAll (panels);
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
		if (!panels->menuStackDepth) {
			panels->currentMenuIndex++;
			panels->currentMenuIndex %= menuNum;
		} else if (panels->menuStackDepth > 0) {
			panels->menuStackDepth = 0;
			panels->currentMenu = panels->menuStack[0];
			panels->currentMenuIndex = panels->menuIndexStack[0] + 1;
			panels->currentMenuIndex %= menuNum;
			setRefreshAll (panels);
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
			switchMode (panels);
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
	int i, cx0, cx1, cy0, cy1, tx0, tx1, ty0, ty1, cur1 = 0, cur2 = 0, cur3 = 0, cur4 = 0;
	bool resize = true, left = true, right = true;
	cx0 = curPanel->pos.x;
	cx1 = curPanel->pos.x + curPanel->pos.w - 1;
	cy0 = curPanel->pos.y;
	cy1 = curPanel->pos.y + curPanel->pos.h - 1;
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
		RPanel *p = &panel[i];
		tx0 = p->pos.x;
		tx1 = p->pos.x + p->pos.w - 1;
		ty0 = p->pos.y;
		ty1 = p->pos.y + p->pos.h - 1;
		if (ty0 == cy0 && ty1 == cy1 && (tx0 == cx1 || tx1 == cx0)) {
			if (tx0 == cx1 && p->pos.x - PANEL_CONFIG_RESIZE_W > curPanel->pos.x) {
				p->pos.x -= PANEL_CONFIG_RESIZE_W;
				p->pos.w += PANEL_CONFIG_RESIZE_W;
				curPanel->pos.w -= PANEL_CONFIG_RESIZE_W;
				p->refresh = true;
				curPanel->refresh = true;
				goto beach;
			}
			if (tx1 == cx0 && curPanel->pos.x - PANEL_CONFIG_RESIZE_W > p->pos.x) {
				p->pos.w -= PANEL_CONFIG_RESIZE_W;
				curPanel->pos.x -= PANEL_CONFIG_RESIZE_W;
				curPanel->pos.w += PANEL_CONFIG_RESIZE_W;
				p->refresh = true;
				curPanel->refresh = true;
				goto beach;
			}
			resize = false;
			continue;
		}
		if (tx1 == cx0 && left) {
			if (tx1 - PANEL_CONFIG_RESIZE_W <= tx0) {
				left = false;
			} else {
				targets1[cur1++] = p;
			}
		}
		if (tx0 == cx0 && left) {
			targets2[cur2++] = p;
		}
		if (tx0 == cx1 && right) {
			targets3[cur3++] = p;
		}
		if (tx1 == cx1 && right) {
			if (tx1 - PANEL_CONFIG_RESIZE_W <= tx0) {
				right = false;
			} else {
				targets4[cur4++] = p;
			}
		}
	}
	if (!resize) {
		goto beach;
	}
	if (left && cur1 > 0 && curPanel->pos.x - PANEL_CONFIG_RESIZE_W > 0) {
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
	} else if (right && cur3 > 0 && cx1 - PANEL_CONFIG_RESIZE_W > 0) {
		for (i = 0; i < cur3; i++) {
			targets3[i]->pos.x -= PANEL_CONFIG_RESIZE_W;
			targets3[i]->pos.w += PANEL_CONFIG_RESIZE_W;
			targets3[i]->refresh = true;
		}
		for (i = 0; i < cur4; i++) {
			targets4[i]->pos.w -= PANEL_CONFIG_RESIZE_W;
			targets4[i]->refresh = true;
		}
		curPanel->pos.w -= PANEL_CONFIG_RESIZE_W;
		curPanel->refresh = true;
	}
beach:
	free (targets1);
	free (targets2);
	free (targets3);
	free (targets4);
}

static void resizePanelRight(RPanels *panels) {
	RPanel *panel = panels->panel;
	RPanel *curPanel = &panel[panels->curnode];
	int i, tx0, tx1, ty0, ty1, cur1 = 0, cur2 = 0, cur3 = 0, cur4 = 0;
	bool resize = true, left = true, right = true;
	int cx0 = curPanel->pos.x;
	int cx1 = curPanel->pos.x + curPanel->pos.w - 1;
	int cy0 = curPanel->pos.y;
	int cy1 = curPanel->pos.y + curPanel->pos.h - 1;
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
		RPanel *p = &panel[i];
		tx0 = p->pos.x;
		tx1 = p->pos.x + p->pos.w - 1;
		ty0 = p->pos.y;
		ty1 = p->pos.y + p->pos.h - 1;
		if (ty0 == cy0 && ty1 == cy1 && (tx1 == cx0 || tx0 == cx1)) {
			if (tx1 == cx0 && tx1 + PANEL_CONFIG_RESIZE_W < cx1) {
				p->pos.w += PANEL_CONFIG_RESIZE_W;
				curPanel->pos.x += PANEL_CONFIG_RESIZE_W;
				curPanel->pos.w -= PANEL_CONFIG_RESIZE_W;
				p->refresh = true;
				curPanel->refresh = true;
				goto beach;
			}
			if (tx0 == cx1 && cx1 + PANEL_CONFIG_RESIZE_W < tx1) {
				p->pos.x += PANEL_CONFIG_RESIZE_W;
				p->pos.w -= PANEL_CONFIG_RESIZE_W;
				curPanel->pos.w += PANEL_CONFIG_RESIZE_W;
				p->refresh = true;
				curPanel->refresh = true;
				goto beach;
			}
			resize = false;
			continue;
		}
		if (tx1 == cx0 && left) {
			targets1[cur1++] = p;
		}
		if (tx0 == cx0 && left) {
			if (tx0 + PANEL_CONFIG_RESIZE_W >= tx1) {
				left = false;
			} else {
				targets2[cur2++] = p;
			}
		}
		if (tx0 == cx1 && right) {
			if (tx0 + PANEL_CONFIG_RESIZE_W >= tx1) {
				right = false;
			} else {
				targets3[cur3++] = p;
			}
		}
		if (tx1 == cx1 && right) {
			targets4[cur4++] = p;
		}
	}
	if (!resize) {
		goto beach;
	}
	if (left && cur1 > 0 && curPanel->pos.x + PANEL_CONFIG_RESIZE_W < panels->can->w) {
		for (i = 0; i < cur1; i++) {
			targets1[i]->pos.w += PANEL_CONFIG_RESIZE_W;
			targets1[i]->refresh = true;
		}
		for (i = 0; i < cur2; i++) {
			targets2[i]->pos.x += PANEL_CONFIG_RESIZE_W;
			targets2[i]->pos.w -= PANEL_CONFIG_RESIZE_W;
			targets2[i]->refresh = true;
		}
		curPanel->refresh = true;
		curPanel->pos.x += PANEL_CONFIG_RESIZE_W;
		curPanel->pos.w -= PANEL_CONFIG_RESIZE_W;
	} else if (right && cur3 > 0 && cx1 + PANEL_CONFIG_RESIZE_W < panels->can->w) {
		for (i = 0; i < cur3; i++) {
			targets3[i]->pos.x += PANEL_CONFIG_RESIZE_W;
			targets3[i]->pos.w -= PANEL_CONFIG_RESIZE_W;
			targets3[i]->refresh = true;
		}
		for (i = 0; i < cur4; i++) {
			targets4[i]->pos.w += PANEL_CONFIG_RESIZE_W;
			targets4[i]->refresh = true;
		}
		curPanel->refresh = true;
		curPanel->pos.w += PANEL_CONFIG_RESIZE_W;
	}
beach:
	free (targets1);
	free (targets2);
	free (targets3);
	free (targets4);
}

static void resizePanelUp(RPanels *panels) {
	RPanel *panel = panels->panel;
	RPanel *curPanel = &panel[panels->curnode];
	int i, tx0, tx1, ty0, ty1, cur1 = 0, cur2 = 0, cur3 = 0, cur4 = 0;
	bool resize = true, up = true, down = true;
	int cx0 = curPanel->pos.x;
	int cx1 = curPanel->pos.x + curPanel->pos.w - 1;
	int cy0 = curPanel->pos.y;
	int cy1 = curPanel->pos.y + curPanel->pos.h - 1;
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
		RPanel *p = &panel[i];
		tx0 = p->pos.x;
		tx1 = p->pos.x + p->pos.w - 1;
		ty0 = p->pos.y;
		ty1 = p->pos.y + p->pos.h - 1;
		if (tx0 == cx0 && tx1 == cx1 && (ty1 == cy0 || ty0 == cy1)) {
			if (ty1 == cy0 && ty1 - PANEL_CONFIG_RESIZE_H > ty0) {
				p->pos.h -= PANEL_CONFIG_RESIZE_H;
				curPanel->pos.y -= PANEL_CONFIG_RESIZE_H;
				curPanel->pos.h += PANEL_CONFIG_RESIZE_H;
				p->refresh = true;
				curPanel->refresh = true;
				goto beach;
			}
			if (ty0 == cy1 && cy1 - PANEL_CONFIG_RESIZE_H > cy0) {
				p->pos.y -= PANEL_CONFIG_RESIZE_H;
				p->pos.h += PANEL_CONFIG_RESIZE_H;
				curPanel->pos.h -= PANEL_CONFIG_RESIZE_H;
				p->refresh = true;
				curPanel->refresh = true;
				goto beach;
			}
			resize = false;
			continue;
		}
		if (ty1 == cy0 && up) {
			if (ty1 - PANEL_CONFIG_RESIZE_H <= ty0) {
				up = false;
			} else {
				targets1[cur1++] = p;
			}
		}
		if (ty0 == cy0 && up) {
			targets2[cur2++] = p;
		}
		if (ty0 == cy1 && down) {
			targets3[cur3++] = p;
		}
		if (ty1 == cy1 && down) {
			if (ty1 - PANEL_CONFIG_RESIZE_H <= ty0) {
				down = false;
			} else {
				targets4[cur4++] = p;
			}
		}
	}
	if (!resize) {
		goto beach;
	}
	if (up && cur1 > 0 && cy0 - PANEL_CONFIG_RESIZE_H > 0) {
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
	} else if (down && cur3 > 0 && cy1 - PANEL_CONFIG_RESIZE_H > cy0) {
		for (i = 0; i < cur3; i++) {
			targets3[i]->pos.y -= PANEL_CONFIG_RESIZE_H;
			targets3[i]->pos.h += PANEL_CONFIG_RESIZE_H;
			targets3[i]->refresh = true;
		}
		for (i = 0; i < cur4; i++) {
			targets4[i]->pos.h -= PANEL_CONFIG_RESIZE_H;
			targets4[i]->refresh = true;
		}
		curPanel->refresh = true;
		curPanel->pos.h -= PANEL_CONFIG_RESIZE_H;
	}
beach:
	free (targets1);
	free (targets2);
	free (targets3);
	free (targets4);
}

static void resizePanelDown(RPanels *panels) {
	RPanel *panel = panels->panel;
	RPanel *curPanel = &panel[panels->curnode];
	int i, tx0, tx1, ty0, ty1, cur1 = 0, cur2 = 0, cur3 = 0, cur4 = 0;
	bool resize = true, up = true, down = true;
	int cx0 = curPanel->pos.x;
	int cx1 = curPanel->pos.x + curPanel->pos.w - 1;
	int cy0 = curPanel->pos.y;
	int cy1 = curPanel->pos.y + curPanel->pos.h - 1;
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
		RPanel *p = &panel[i];
		tx0 = p->pos.x;
		tx1 = p->pos.x + p->pos.w - 1;
		ty0 = p->pos.y;
		ty1 = p->pos.y + p->pos.h - 1;
		if (tx0 == cx0 && tx1 == cx1 && (ty1 == cy0 || ty0 == cy1)) {
			if (ty1 == cy0 && cy0 + PANEL_CONFIG_RESIZE_H < cy1) {
				p->pos.h += PANEL_CONFIG_RESIZE_H;
				curPanel->pos.y += PANEL_CONFIG_RESIZE_H;
				curPanel->pos.h -= PANEL_CONFIG_RESIZE_H;
				p->refresh = true;
				curPanel->refresh = true;
				goto beach;
			}
			if (ty0 == cy1 && ty0 + PANEL_CONFIG_RESIZE_H < ty1) {
				p->pos.y += PANEL_CONFIG_RESIZE_H;
				p->pos.h -= PANEL_CONFIG_RESIZE_H;
				curPanel->pos.h += PANEL_CONFIG_RESIZE_H;
				p->refresh = true;
				curPanel->refresh = true;
				goto beach;
			}
			resize = false;
			continue;
		}
		if (ty1 == cy0 && up) {
			targets1[cur1++] = p;
		}
		if (ty0 == cy0 && up) {
			if (ty0 + PANEL_CONFIG_RESIZE_H >= ty1) {
				up = false;
			} else {
				targets2[cur2++] = p;
			}
		}
		if (ty0 == cy1 && down) {
			if (ty0 + PANEL_CONFIG_RESIZE_H >= ty1) {
				down = false;
			} else {
				targets3[cur3++] = p;
			}
		}
		if (ty1 == cy1 && down) {
			targets4[cur4++] = p;
		}
	}
	if (!resize) {
		goto beach;
	}
	if (up && cur1 > 0 && cy0 + PANEL_CONFIG_RESIZE_H < cy1) {
		for (i = 0; i < cur1; i++) {
			targets1[i]->pos.h += PANEL_CONFIG_RESIZE_H;
			targets1[i]->refresh = true;
		}
		for (i = 0; i < cur2; i++) {
			targets2[i]->pos.y += PANEL_CONFIG_RESIZE_H;
			targets2[i]->pos.h -= PANEL_CONFIG_RESIZE_H;
			targets2[i]->refresh = true;
		}
		curPanel->refresh = true;
		curPanel->pos.y += PANEL_CONFIG_RESIZE_H;
		curPanel->pos.h -= PANEL_CONFIG_RESIZE_H;
	} else if (down && cur3 > 0 && cy1 + PANEL_CONFIG_RESIZE_H < panels->can->h) {
		for (i = 0; i < cur3; i++) {
			targets3[i]->pos.y += PANEL_CONFIG_RESIZE_H;
			targets3[i]->pos.h -= PANEL_CONFIG_RESIZE_H;
			targets3[i]->refresh = true;
		}
		for (i = 0; i < cur4; i++) {
			targets4[i]->pos.h += PANEL_CONFIG_RESIZE_H;
			targets4[i]->refresh = true;
		}
		curPanel->refresh = true;
		curPanel->pos.h += PANEL_CONFIG_RESIZE_H;
	}
beach:
	free (targets1);
	free (targets2);
	free (targets3);
	free (targets4);
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
	dismantlePanel (panels);
	if (panels->curnode >= 0 && panels->n_panels > 2) {
		delPanel (panels, panels->curnode);
	}
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
	freePanel (&panels->panel[panels->curnode]);
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
	panel[n_panels].type = PANEL_TYPE_FRAME;
	panel[n_panels].refresh = true;
	panel[n_panels].curpos = 0;
	panel[n_panels].cmdStrCache = NULL;
	if (!strcmp (panel[n_panels].cmd, PANEL_CMD_DISASSEMBLY)) {
		panel[n_panels].addr = core->offset;
	}
	if (!strcmp (panel[n_panels].cmd, PANEL_CMD_STACK)) {
		const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
		const ut64 stackbase = r_reg_getv (core->anal->reg, sp);
		panel[n_panels].baseAddr = stackbase;
		panel[n_panels].addr = stackbase - r_config_get_i (core->config, "stack.delta");
	}
	panels->n_panels++;
}

static RPanel createMenuPanel(int x, int y, char *title) {
	RPanel panel = {{0}};
	panel.pos.x = x;
	panel.pos.y = y;
	panel.title = title;
	panel.refresh = true;
	panel.type = PANEL_TYPE_MENU;
	return panel;
}

static bool initPanels(RCore *core, RPanels *panels) {
	panels->panel = calloc (sizeof (RPanel), PANEL_NUM_LIMIT);
	if (!panels->panel) {
		return false;
	}
	panels->n_panels = 0;
	addPanelFrame (core, panels, PANEL_TITLE_DISASSEMBLY, PANEL_CMD_DISASSEMBLY);
	addPanelFrame (core, panels, PANEL_TITLE_SYMBOLS, PANEL_CMD_SYMBOLS);
	//addPanelFrame (core, panels, PANEL_TITLE_STACK, PANEL_CMD_STACK);
	addPanelFrame (core, panels, PANEL_TITLE_STACKREFS, PANEL_CMD_STACKREFS);
	addPanelFrame (core, panels, PANEL_TITLE_REGISTERS, PANEL_CMD_REGISTERS);
	addPanelFrame (core, panels, PANEL_TITLE_REGISTERREFS, PANEL_CMD_REGISTERREFS);
	panels->curnode = 0;
	return true;
}

static void freePanel(RPanel *panel) {
	free (panel->title);
	free (panel->cmd);
	free (panel->cmdStrCache);
}

// damn singletons.. there should be only one screen and therefor
// only one visual instance of the graph view. refactoring this
// into a struct makes the code to reference pointers unnecesarily
// we can look for a non-global solution here in the future if
// necessary
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
	if (panels->curnode > panels->menu_pos) {
		panels->menuStackDepth = 0;
		panels->currentMenu = NULL;
		panels->currentMenuIndex = 0;
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
	if (panels->curnode == panels->menu_pos && panels->menuStackDepth > 0) {
		layoutSubMenu (panels, w);
		for (i = 0; i <= panels->menuStackDepth; i++) {
			panelPrint (core, can, &panels->menuPanel[i], 1);
		}
	}
	(void) r_cons_canvas_gotoxy (can, -can->sx, -can->sy);
	r_cons_canvas_fill (can, -can->sx, -can->sy, panel->pos.w, 1, ' ');
	title[0] = 0;
	if (panels->curnode == panels->menu_pos) {
		strcpy (title, "> ");
	}
	const char *color = panels->curnode == panels->menu_pos ? core->cons->pal.graph_box : core->cons->pal.graph_box2;
	if (panels->isZoom) {
		snprintf (str, sizeof (title) - 1, "%s Zoom Mode: Press Enter or q to quit"Color_RESET, color);
		strcat (title, str);
	} else {
		for (i = 0; menus[i]; i++) {
			if (panels->curnode == panels->menu_pos) {
				if (panels->menuStackDepth > 0) {
					if (i == panels->menuIndexStack[0]) {
						snprintf (str, sizeof (title) - 1, "%s[%s]"Color_RESET, color, menus[i]);
					} else {
						snprintf (str, sizeof (title) - 1, "%s %s "Color_RESET, color, menus[i]);
					}
				} else {
					if (i == panels->currentMenuIndex) {
						snprintf (str, sizeof (title) - 1, "%s[%s]"Color_RESET, color, menus[i]);
					} else {
						snprintf (str, sizeof (title) - 1, "%s %s "Color_RESET, color, menus[i]);
					}
				}
			} else {
				snprintf (str, sizeof (title) - 1, "%s %s "Color_RESET, color, menus[i]);
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
	if (!strcmp (core->panels->panel[core->panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)) {
		core->panels->panel[core->panels->curnode].addr = core->offset;
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
	if (!strcmp (core->panels->panel[core->panels->curnode].cmd, PANEL_CMD_DISASSEMBLY)) {
		core->panels->panel[core->panels->curnode].addr = core->offset;
	}
}

static void panelBreakpoint(RCore *core) {
	r_core_cmd (core, "dbs $$", 0);
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
		if (!strcmp (panel->cmd, PANEL_CMD_STACK) && panel->baseAddr != stackbase) {
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

static bool init (RCore *core, RPanels *panels, int w, int h) {
	panels->panel = NULL;
	panels->n_panels = 0;
	panels->columnWidth = 80;
	panels->layout = 0;
	panels->menu_pos = -1;
	panels->menuStack = calloc (sizeof (char **), PANEL_MENU_LIMIT);
	panels->menuIndexStack = calloc (sizeof (int), PANEL_MENU_LIMIT);
	panels->menuStackDepth = 0;
	panels->currentMenu = NULL;
	panels->currentMenuIndex = 0;
	panels->menuPanel = calloc (sizeof (RPanel), PANEL_MENU_LIMIT);
	panels->callgraph = 0;
	panels->isResizing = false;
	panels->isZoom = false;
	panels->can = createNewCanvas (core, w, h);
	if (w < 140) {
		panels->columnWidth = w / 3;
	}
	return true;
}

R_API int file_history_up(RLine *line) {
	RCore *core = line->user;
	RList *files = r_id_storage_list (core->io->files);
	int num_files = r_list_length (files);
	if (line->file_hist_index >= num_files || line->file_hist_index < 0) {
		return false;
	}
	line->file_hist_index++;
	RIODesc *desc = r_list_get_n (files, num_files - line->file_hist_index);
	strncpy (line->buffer.data, desc->name, R_LINE_BUFSIZE - 1);
	line->buffer.index = line->buffer.length = strlen (line->buffer.data);
	r_list_free (files);
	return true;
}

R_API int file_history_down(RLine *line) {
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
	strncpy (line->buffer.data, desc->name, R_LINE_BUFSIZE - 1);
	line->buffer.index = line->buffer.length = strlen (line->buffer.data);
	r_list_free (files);
	return true;
}

static void handleMenu(RCore *core, const int key, int *exit) {
	RPanels *panels = core->panels;
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
			if (panels->menuStackDepth == 0) {
				*exit = 1;
				return;
			}
			panels->menuStackDepth--;
			panels->currentMenu = panels->menuStack[panels->menuStackDepth];
			panels->currentMenuIndex = panels->menuIndexStack[panels->menuStackDepth];
			setRefreshAll (core->panels);
			break;
		case ' ':
		case '\r':
		case '\n':
			onMenu (core, panels->currentMenu[panels->currentMenuIndex], exit);
			break;
		case 9:
			handleTabKey (core, false);
			break;
		case 'Z':
			handleTabKey (core, true);
	}
}

static void onMenu(RCore *core, const char *menu, int *exit) {
	RPanels *panels = core->panels;
	if (!strcmp (menu, "File")) {
		changeMenu (panels, menus_File);
		return;
	}
	if (!strcmp (menu, "Edit")) {
		changeMenu (panels, menus_Edit);
		return;
	}
	if (!strcmp (menu, "View")) {
		changeMenu (panels, menus_View);
		return;
	}
	if (!strcmp (menu, "Tools")) {
		changeMenu (panels, menus_Tools);
		return;
	}
	if (!strcmp (menu, "Search")) {
		changeMenu (panels, menus_Search);
		return;
	}
	if (!strcmp (menu, "Debug")) {
		changeMenu (panels, menus_Debug);
		return;
	}
	if (!strcmp (menu, "Analyze")) {
		changeMenu (panels, menus_Analyze);
		return;
	}
	if (!strcmp (menu, "Help")) {
		changeMenu (panels, menus_Help);
		return;
	}
	if (!strcmp (menu, "ReOpen")) {
		panels->menuStack[panels->menuStackDepth] = panels->currentMenu;
		panels->menuIndexStack[panels->menuStackDepth] = panels->currentMenuIndex;
		panels->menuStackDepth++;
		panels->currentMenu = menus_ReOpen;
		panels->currentMenuIndex = 0;
		return;
	}
	if (!strcmp (menu, "New")) {
		addPanelFrame (core, panels, PANEL_TITLE_NEWFILES, "o");
	} else if (!strcmp (menu, "Open")) {
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
	} else if (!strcmp (menu, "RegisterRefs")) {
		layoutSidePanel (core, PANEL_TITLE_REGISTERREFS, PANEL_CMD_REGISTERREFS);
	} else if (!strcmp (menu, "Registers")) {
		layoutSidePanel (core, PANEL_TITLE_REGISTERS, PANEL_CMD_REGISTERS);
	} else if (!strcmp (menu, "Info")) {
		layoutSidePanel (core, PANEL_TITLE_INFO, PANEL_CMD_INFO);
	} else if (!strcmp (menu, "Database")) {
		layoutSidePanel (core, PANEL_TITLE_DATABASE, PANEL_CMD_DATABASE);
	} else if (!strcmp (menu, "About")) {
		char *s = r_core_cmd_str (core, "?V");
		r_cons_message (s);
		free (s);
	} else if (!strcmp (menu, "Hexdump")) {
		layoutSidePanel (core, PANEL_TITLE_HEXDUMP, PANEL_CMD_HEXDUMP);
	} else if (!strcmp (menu, "Disassembly")) {
		layoutSidePanel (core, PANEL_TITLE_DISASSEMBLY, PANEL_CMD_DISASSEMBLY);
	} else if (!strcmp (menu, "Functions")) {
		layoutSidePanel (core, PANEL_TITLE_FUNCTIONS, PANEL_CMD_FUNCTIONS);
	} else if (!strcmp (menu, "Comments")) {
		layoutSidePanel (core, PANEL_TITLE_COMMENTS, PANEL_CMD_COMMENTS);
	} else if (!strcmp (menu, "Entropy")) {
		layoutSidePanel (core, PANEL_TITLE_ENTROPY, PANEL_CMD_ENTROPY);
	} else if (!strcmp (menu, "Pseudo")) {
		layoutSidePanel (core, PANEL_TITLE_PSEUDO, PANEL_CMD_PSEUDO);
	} else if (!strcmp (menu, "Symbols")) {
		r_core_cmdf (core, "aa");
	} else if (!strcmp (menu, "BasicBlocks")) {
		r_core_cmdf (core, "aab");
	} else if (!strcmp (menu, "Function")) {
		r_core_cmdf (core, "af");
	} else if (!strcmp (menu, "DRX")) {
		layoutSidePanel (core, PANEL_TITLE_DRX, PANEL_CMD_DRX);
	} else if (!strcmp (menu, "Program")) {
		r_core_cmdf (core, "aaa");
	} else if (!strcmp (menu, "Calls")) {
		r_core_cmdf (core, "aac");
	} else if (!strcmp (menu, "ROP")) {
		r_cons_enable_mouse (false);
		char *res = r_cons_input ("rop grep: ");
		if (res) {
			r_core_cmdf (core, "\"/R %s\"", res);
			free (res);
		}
		r_cons_enable_mouse (true);
	} else if (!strcmp (menu, "String")) {
		r_cons_enable_mouse (false);
		char *res = r_cons_input ("search string: ");
		if (res) {
			r_core_cmdf (core, "\"/ %s\"", res);
			free (res);
		}
		r_cons_enable_mouse (true);
	} else if (!strcmp (menu, "Hexpairs")) {
		r_cons_enable_mouse (false);
		char *res = r_cons_input ("search hexpairs: ");
		if (res) {
			r_core_cmdf (core, "\"/x %s\"", res);
			free (res);
		}
		r_cons_enable_mouse (true);
	} else if (!strcmp (menu, "Code")) {
		r_cons_enable_mouse (false);
		char *res = r_cons_input ("search code: ");
		if (res) {
			r_core_cmdf (core, "\"/c %s\"", res);
			free (res);
		}
		r_cons_enable_mouse (true);
	} else if (!strcmp (menu, "Copy")) {
		r_cons_enable_mouse (false);
		char *res = r_cons_input ("How many bytes? ");
		if (res) {
			r_core_cmdf (core, "\"y %s\"", res);
			free (res);
		}
		r_cons_enable_mouse (true);
	} else if (!strcmp (menu, "Write String")) {
		r_cons_enable_mouse (false);
		char *res = r_cons_input ("insert string: ");
		if (res) {
			r_core_cmdf (core, "\"w %s\"", res);
			free (res);
		}
		r_cons_enable_mouse (true);
	} else if (!strcmp (menu, "Write Value")) {
		r_cons_enable_mouse (false);
		char *res = r_cons_input ("insert number: ");
		if (res) {
			r_core_cmdf (core, "\"wv %s\"", res);
			free (res);
		}
		r_cons_enable_mouse (true);
	} else if (!strcmp (menu, "Write Hex")) {
		r_cons_enable_mouse (false);
		char *res = r_cons_input ("insert hexpairs: ");
		if (res) {
			r_core_cmdf (core, "\"wx %s\"", res);
			free (res);
		}
		r_cons_enable_mouse (true);
	} else if (!strcmp (menu, "Calculator")) {
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
	} else if (!strcmp (menu, "Assemble")) {
		r_core_visual_asm (core, core->offset);
	} else if (!strcmp (menu, "Sections")) {
		layoutSidePanel (core, PANEL_TITLE_SECTIONS, PANEL_CMD_SECTIONS);
	} else if (!strcmp (menu, "Close")) {
		r_core_cmd0 (core, "o-*");
	} else if (!strcmp (menu, "Strings")) {
		layoutSidePanel (core, PANEL_TITLE_STRINGS, PANEL_CMD_STRINGS);
	} else if (!strcmp (menu, "Maps")) {
		layoutSidePanel (core, PANEL_TITLE_MAPS, PANEL_CMD_MAPS);
	} else if (!strcmp (menu, "Modules")) {
		layoutSidePanel (core, PANEL_TITLE_MODULES, PANEL_CMD_MODULES);
	} else if (!strcmp (menu, "Backtrace")) {
		layoutSidePanel (core, PANEL_TITLE_BACKTRACE, PANEL_CMD_BACKTRACE);
	} else if (!strcmp (menu, "Locals")) {
		layoutSidePanel (core, PANEL_TITLE_LOCALS, PANEL_CMD_LOCALS);
	} else if (!strcmp (menu, "Step")) {
		r_core_cmd (core, "ds", 0);
		r_cons_flush ();
	} else if (!strcmp (menu, "In RW")) {
		r_core_cmd (core, "oo+", 0);
		r_cons_flush ();
	} else if (!strcmp (menu, "In Debugger")) {
		r_core_cmd (core, "oo", 0);
		r_cons_flush ();
	} else if (!strcmp (menu, "Reload")) {
		r_core_cmd (core, "ood", 0);
		r_cons_flush ();
	} else if (!strcmp (menu, "Step Over")) {
		r_core_cmd (core, "dso", 0);
		r_cons_flush ();
	} else if (!strcmp (menu, "StackRefs")) {
		layoutSidePanel (core, PANEL_TITLE_STACKREFS, PANEL_CMD_STACKREFS);
	} else if (!strcmp (menu, "Stack")) {
		layoutSidePanel (core, PANEL_TITLE_STACK, PANEL_CMD_STACK);
	} else if (!strcmp (menu, "Continue")) {
		r_core_cmd (core, "dc", 0);
		r_cons_flush ();
	} else if (!strcmp (menu, "Breakpoints")) {
		layoutSidePanel (core, PANEL_TITLE_BREAKPOINTS, PANEL_CMD_BREAKPOINTS);
	} else if (!strcmp (menu, "Symbols")) {
		layoutSidePanel (core, PANEL_TITLE_SYMBOLS, PANEL_CMD_SYMBOLS);
	} else if (!strcmp (menu, "Imports")) {
		layoutSidePanel (core, PANEL_TITLE_IMPORTS, PANEL_CMD_IMPORTS);
	} else if (!strcmp (menu, "Paste")) {
		r_core_cmd0 (core, "yy");
	} else if (!strcmp (menu, "Clipboard")) {
		layoutSidePanel (core, PANEL_TITLE_CLIPBOARD, PANEL_CMD_CLIPBOARD);
	} else if (!strcmp (menu, "io.cache")) {
		r_core_cmd0 (core, "e!io.cache");
	} else if (!strcmp (menu, "Fill")) {
		r_cons_enable_mouse (false);
		char *s = r_cons_input ("Fill with: ");
		r_core_cmdf (core, "wow %s", s);
		free (s);
		r_cons_enable_mouse (true);
	} else if (!strcmp (menu, "References")) {
		r_core_cmdf (core, "aar");
	} else if (!strcmp (menu, "FcnInfo")) {
		layoutSidePanel (core, PANEL_TITLE_FCNINFO, PANEL_CMD_FCNINFO);
	} else if (!strcmp (menu, "Graph")) {
		r_core_visual_graph (core, NULL, NULL, true);
		// addPanelFrame ("Graph", "agf");
	} else if (!strcmp (menu, "System Shell")) {
		r_cons_set_raw (0);
		r_cons_flush ();
		r_sys_cmd ("$SHELL");
	} else if (!strcmp (menu, "R2 Shell")) {
		core->vmode = false;
		r_core_visual_prompt_input (core);
		core->vmode = true;
	} else if (!strcmp (menu, "2048")) {
		r_cons_2048 (panels->can->color);
	} else if (!strcmp (menu, "License")) {
		r_cons_message ("Copyright 2006-2016 - pancake - LGPL");
	} else if (!strcmp (menu, "Fortune")) {
		char *s = r_core_cmd_str (core, "fo");
		r_cons_message (s);
		free (s);
	} else if (!strcmp (menu, "Commands")) {
		r_core_cmd0 (core, "?;?@?;?$?;???");
		r_cons_any_key (NULL);
	} else if (!strcmp (menu, "Colors")) {
		r_core_cmd0 (core, "e!scr.color");
	} else if (!strcmp (menu, "Quit")) {
		*exit = 1;
		return;
	}
	doPanelsRefresh (core);
}

static void changeMenu(RPanels *panels, const char **dstMenu) {
	panels->menuStack[panels->menuStackDepth] = panels->currentMenu;
	panels->menuIndexStack[panels->menuStackDepth] = panels->currentMenuIndex;
	panels->menuStackDepth++;
	panels->currentMenu = dstMenu;
	panels->currentMenuIndex = 0;
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
	if (panels->curnode == panels->menu_pos) {
		panels->currentMenu = menus;
		panels->currentMenuIndex = 0;
	} else {
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

static void maximizePanelSize(RPanels *panels) {
	RPanel *panel = &panels->panel[panels->curnode];
	panel->pos.x = 0;
	panel->pos.y = 1;
	panel->pos.w = panels->can->w;
	panel->pos.h = panels->can->h - 1;
	panel->refresh = true;
}

static void switchMode(RPanels *panels) {
	panels->isZoom = !panels->isZoom;
	RPanel *curPanel = &panels->panel[panels->curnode];
	if (panels->isZoom) {
		savePanelPos (curPanel);
		maximizePanelSize (panels);
	} else {
		restorePanelPos (curPanel);
		setRefreshAll (panels);
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
	int i;
	r_cons_switchbuf (true);
	if (panels) {
		for (i = 0; i < panels->n_panels; i++) {
			freePanel (&panels->panel[i]);
		}
		free (panels->panel);
		if (panels->can) {
			r_cons_canvas_free (panels->can);
		}
		free (panels);
	}
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

	r_core_panels_layout (panels);
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

	if (panels->isZoom) {
		handleZoomMode (core, key);
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
					// do not refresh stuff 
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
			if (r_config_get_i (core->config, "cfg.debug")) {
				r_core_cmd0 (core, "sr PC");
			} else {
				r_core_cmd0 (core, "s entry0; px");
			}
			panels->panel[panels->curnode].addr = core->offset;
			panels->panel[panels->curnode].refresh = true;
		}
		break;
	case '?':
		r_cons_clear00 ();
		r_cons_printf ("Visual Ascii Art Panels:\n"
			" ?      - show this help\n"
			" !      - run r2048 game\n"
			" .      - seek to PC or entrypoint\n"
			" :      - run r2 command in prompt\n"
			" _      - start the hud input mode\n"
			" |      - split the current panel vertically\n"
			" -      - split the current panel horizontally\n"
			" *      - show pseudo code/r2dec in the current panel\n"
			" [1-9]  - follow jmp/call identified by shortcut (like ;[1])\n"
			" <>     - scroll panels vertically by page\n"
			" b      - browse symbols, flags, configurations, classes, ...\n"
			" c      - toggle cursor\n"
			" C      - toggle color\n"
			" d      - define in the current address. Same as Vd\n"
			" D      - show disassembly in the current panel\n"
			" e      - change title and command of current panel\n"
			" g      - show graph in the current panel\n"
			" hjkl   - move around (left-down-up-right)\n"
			" JK     - resize panels vertically\n"
			" HL     - resize panels horizontally\n"
			" i      - insert hex\n"
			" m      - move to the menu\n"
			" M      - open new custom frame\n"
			" nN     - create new panel with given command\n"
			" o      - go/seek to given offset\n"
			" pP     - seek to next or previous scr.nkey\n"
			" q      - quit, back to visual mode\n"
			" r      - toggle jmphints/leahints\n"
			" sS     - step in / step over\n"
			" uU     - undo / redo seek\n"
			" V      - go to the graph mode\n"
			" w      - change the current layout of the panels\n"
			" X      - close current panel\n"
			);
		r_cons_flush ();
		r_cons_any_key (NULL);
		break;
	case 'b':
		r_core_visual_browse (core);
		break;
	case 'o':
		//if (!strcmp (panels->panel[panels->curnode].cmd, PANEL_CMD_DISASSEMBLY))
		r_core_visual_showcursor (core, true);
		r_core_visual_offset (core);
		r_core_visual_showcursor (core, false);
		panels->panel[panels->curnode].addr = core->offset;
		panels->panel[panels->curnode].refresh = true;
		break;
	case 's':
		panelSingleStepIn (core);
		setRefreshAll (panels);
		break;
	case 'S':
		panelSingleStepOver (core);
		setRefreshAll (panels);
		break;
	case ':':
		core->vmode = false;
		r_core_visual_prompt_input (core);
		core->vmode = true;

		// FIX: Issue with visual mode instruction highlighter
		// not updating after 'ds' or 'dcu' commands.
		r_core_cmd0 (core, ".dr*");
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
		r_core_visual_hud (core);
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
		panels->currentMenu = menus;
		panels->currentMenuIndex = 0;
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
				int ocolor = r_config_get_i (core->config, "scr.color");
				r_core_visual_graph (core, NULL, NULL, true);
				r_config_set_i (core->config, "scr.color", ocolor);
				core->panels->can = createNewCanvas (core, core->panels->can->w, core->panels->can->h);
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
	case 'w':
		panels->layout++;
		if (panels->layout >= layoutMaxCount) {
			panels->layout = 0;
		}
		r_core_panels_layout (panels);
		setRefreshAll (panels);
		break;
	case 0x0d:
		switchMode (panels);
		break;
	case '|':
		splitPanelVertical (core);
		break;
	case '-':
		splitPanelHorizontal (core);
		break;
	case '*':
		if (checkFunc (core)) {
			replaceCmd (panels, PANEL_TITLE_PSEUDO, PANEL_CMD_PSEUDO);
			core->panels->can = createNewCanvas (core, core->panels->can->w, core->panels->can->h);
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
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	core->print->cur = originCursor;
	core->print->cur_enabled = false;
	core->print->col = 0;
	core->vmode = originVmode;

	r_core_panels_free (panels);
	core->panels = NULL;
	return true;
}

/* Copyright radare2 2014-2018 - Author: pancake, vane11ope */

// pls move the typedefs into roons and rename it -> RConsPanel

#include <r_core.h>

#define LIMIT 256

#define PANEL_TITLE_SYMBOLS      "Symbols"
#define PANEL_TITLE_STACK        "Stack"
#define PANEL_TITLE_REGISTERS    "Registers"
#define PANEL_TITLE_REGISTERREFS "RegisterRefs"
#define PANEL_TITLE_DISASSEMBLY  "Disassembly"
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

#define PANEL_CMD_SYMBOLS        "isq"
#define PANEL_CMD_STACK          "px 256@r:SP"
#define PANEL_CMD_REGISTERS      "dr="
#define PANEL_CMD_REGISTERREFS   "drr"
#define PANEL_CMD_DISASSEMBLY    "pd $r @e:scr.utf8=0"

static const int layoutMaxCount = 2;

enum {
	LAYOUT_DEFAULT = 0,
	LAYOUT_BALANCE = 1
};


static const char *menus[] = {
	"File", "Edit", "View", "Tools", "Search", "Debug", "Analyze", "Help",
	NULL
};

static const char *menus_File[] = {
	"New", "Open", "Close", ".", "Sections", "Strings", "Symbols", "Imports", "Info", "Database", ".", "Quit",
	NULL
};

static const char *menus_Edit[] = {
	"Copy", "Paste", "Clipboard", "Write String", "Write Hex", "Write Value", "Assemble", "Fill", "io.cache",
	NULL
};

static const char *menus_View[] = {
	"Hexdump", "Disassembly", "Graph", "FcnInfo", "Functions", "Comments", "Entropy", "Colors",
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
	"Backtrace",
	".",
	"Continue", "Cont until.",
	"Step", "Step Over",
	NULL
};

static const char *menus_Analyze[] = {
	"Function", "Program", "Calls", "References",
	NULL
};

static const char *menus_Help[] = {
	"Fortune", "Commands", "2048", "License", ".", "About",
	NULL
};

static const char **menus_sub[] = {
	menus_File,
	menus_Edit,
	menus_View,
	menus_Tools,
	menus_Search,
	menus_Debug,
	menus_Analyze,
	menus_Help,
	NULL
};

static void layoutRun(RPanels *panels);
static void panelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int color);
static void addPanelFrame(RCore* core, RPanels* panels, const char *title, const char *cmd);
static void checkStackbase(RCore *core);
static void cursorLeft(RCore *core);
static void cursorRight(RCore *core);
static void delCurPanel(RPanels *panels);
static void doPanelsRefresh(RCore *core);
static bool handleCursorMode(RCore *core, const int key);
static void handleUpKey(RCore *core);
static void handleDownKey(RCore *core);
static void handleLeftKey(RCore *core);
static void handleRightKey(RCore *core);
static bool handleEnterKey(RCore *core);
static int  havePanel(RPanels *panels, const char *s);
static bool init(RCore *core, RPanels *panels, int w, int h);
static bool initPanels(RCore *core, RPanels *panels);
static void panelBreakpoint(RCore *core);
static void panelContinue(RCore *core);
static void panelPrompt(const char *prompt, char *buf, int len);
static void panelSingleStepIn(RCore *core);
static void panelSingleStepOver(RCore *core);
static void panelsRefresh(RCore *core);
static void setRefreshAll(RPanels *panels);
static void setCursor(RCore *core, bool cur);
static void zoom(RPanels *panels);

static void panelPrint(RCore *core, RConsCanvas *can, RPanel *panel, int color) {
	if (!can || !panel|| !panel->refresh) {
		return;
	}
	panel->refresh = false;
	char *text;
	char title[128];
	int delta_x, delta_y;
	delta_x = panel->sx;
	delta_y = panel->sy;
	// clear the canvas first
	r_cons_canvas_fill (can, panel->x, panel->y, panel->w, panel->h, ' ', 0);
	// for menu
	RCons *cons = r_cons_singleton ();
	if (panel->type == PANEL_TYPE_MENU) {
		(void) r_cons_canvas_gotoxy (can, panel->x + 2, panel->y + 2);
		text = r_str_ansi_crop (panel->title,
				delta_x, delta_y, panel->w + 5, panel->h - delta_y);
		if (text) {
			r_cons_canvas_write (can, text);
			free (text);
		} else {
			r_cons_canvas_write (can, panel->title);
		}
	} else {
		if (color) {
			const char *k = cons->pal.graph_box;
			snprintf (title, sizeof (title) - 1,
				"%s[x] %s"Color_RESET, k, panel->title);
		} else {
			snprintf (title, sizeof (title) - 1,
				"   %s   ", panel->title);
		}
		if (r_cons_canvas_gotoxy (can, panel->x + 1, panel->y + 1)) {
			r_cons_canvas_write (can, title); // delta_x
		}
		(void) r_cons_canvas_gotoxy (can, panel->x + 2, panel->y + 2);

		char *cmdStr;
		bool ce = core->print->cur_enabled;
		if (!strcmp (panel->title, PANEL_TITLE_DISASSEMBLY)) {
			core->print->cur_enabled = false;
			cmdStr = r_core_cmd_str (core, panel->cmd);
		} else if (!strcmp (panel->title, PANEL_TITLE_STACK)) {
			const int delta = r_config_get_i (core->config, "stack.delta");
			const char sign = (delta < 0)? '+': '-';
			const int absdelta = R_ABS (delta);
			cmdStr = r_core_cmd_strf (core, "%s%c%d", PANEL_CMD_STACK, sign, absdelta);
		} else {
			cmdStr = r_core_cmd_str (core, panel->cmd);
		}
		if (delta_y < 0) {
			delta_y = 0;
		}
		if (delta_x < 0) {
			char *white = (char*)r_str_pad (' ', 128);;
			int idx = -delta_x;
			if (idx >= sizeof (white)) {
				idx = sizeof (white) - 1;
			}
			white[idx] = 0;
			text = r_str_ansi_crop (cmdStr,
					0, delta_y, panel->w + delta_x - 2, panel->h - 2 + delta_y);
			char *newText = r_str_prefix_all (text, white);
			if (newText) {
				free (text);
				text = newText;
			}
		} else {
			text = r_str_ansi_crop (cmdStr,
					delta_x, delta_y, panel->w + delta_x - 2, panel->h - 2 + delta_y);
		}
		if (text) {
			r_cons_canvas_write (can, text);
			free (text);
		} else {
			r_cons_canvas_write (can, panel->title);
		}
		free (cmdStr);
		core->print->cur_enabled = ce;
	}
	if (color) {
		r_cons_canvas_box (can, panel->x, panel->y, panel->w, panel->h, cons->pal.graph_box2);
	} else {
		r_cons_canvas_box (can, panel->x, panel->y, panel->w, panel->h, cons->pal.graph_box);
	}
}

static void layoutRun(RPanels *panels) {
	int h, w = r_cons_get_size (&h);
	int i, j;
	int colpos = w - panels->columnWidth;
	RPanel *panel = panels->panel;

	if (colpos < 0) {
		panels->columnWidth = w;
		colpos = 0;
	}
	panels->can->sx = 0;
	panels->can->sy = 0;
	for (i = j = 0; i < panels->n_panels; i++) {
		switch (panel[i].type) {
		case PANEL_TYPE_MENU:
			panel[i].w = r_str_bounds (
				panel[i].title,
				&panel[i].h);
			panel[i].h += 4;
			break;
		case PANEL_TYPE_FRAME:
			switch (panels->layout) {
			case LAYOUT_DEFAULT:
				if (j == 0) {
					panel[i].x = 0;
					panel[i].y = 1;
					if (panel[j + 1].title) {
						panel[i].w = colpos + 1;
					} else {
						panel[i].w = w;
					}
					panel[i].h = h - 1;
				} else {
					int ph = ((h - 1) / (panels->n_panels - 2));
					panel[i].x = colpos;
					panel[i].y = 1 + (ph * (j - 1));
					panel[i].w = w - colpos;
					if (panel[i].w < 0) {
						panel[i].w = 0;
					}
					panel[i].h = ph;
					if (!panel[i + 1].title) {
						panel[i].h = h - panel[i].y;
					}
					if (j != 1) {
						panel[i].y--;
						panel[i].h++;
					}
				}
				break;
			case LAYOUT_BALANCE:
				if (j == 0) {
					panel[i].x = 0;
					panel[i].y = 1;
					if (panel[j + 1].title) {
						panel[i].w = colpos + 1;
					} else {
						panel[i].w = w;
					}
					panel[i].h = (h / 2) + 1;
				} else if (j == 1) {
					panel[i].x = 0;
					panel[i].y = (h / 2) + 1;
					if (panel[j + 1].title) {
						panel[i].w = colpos + 1;
					} else {
						panel[i].w = w;
					}
					panel[i].h = (h - 1) / 2;
				} else {
					int ph = ((h - 1) / (panels->n_panels - 3));
					panel[i].x = colpos;
					panel[i].y = 1 + (ph * (j - 2));
					panel[i].w = w - colpos;
					if (panel[i].w < 0) {
						panel[i].w = 0;
					}
					panel[i].h = ph;
					if (!panel[i + 1].title) {
						panel[i].h = h - panel[i].y;
					}
					if (j != 2) {
						panel[i].y--;
						panel[i].h++;
					}
				}
				break;
			}
			j++;
		}
	}
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
	if (!strcmp (core->panels->panel[core->panels->curnode].title, PANEL_TITLE_STACK) && core->print->cur >= 15) {
		return;
	}
	core->print->cur++;
	core->panels->panel[core->panels->curnode].addr++;
	return;
}

static void cursorLeft(RCore *core) {
	if (core->print->cur > 0) {
		core->print->cur--;
		core->panels->panel[core->panels->curnode].addr--;
	}
	return;
}

static void handleUpKey(RCore *core) {
	RPanels *panels = core->panels;

	r_cons_switchbuf (false);
	panels->panel[panels->curnode].refresh = true;
	if (panels->panel[panels->curnode].type == PANEL_TYPE_MENU) {
		panels->menu_y--;
		if (panels->menu_y < 0) {
			panels->menu_y = 0;
		}
	} else {
		if (!strcmp (panels->panel[panels->curnode].title, PANEL_TITLE_DISASSEMBLY)) {
			r_core_cmd0 (core, "s-8");
		} else if (!strcmp (panels->panel[panels->curnode].title, PANEL_TITLE_STACK)) {
			int width = r_config_get_i (core->config, "hex.cols");
			if (width < 1) {
				width = 16;
			}
			r_config_set_i (core->config, "stack.delta",
					r_config_get_i (core->config, "stack.delta") + width);
			panels->panel[panels->curnode].addr -= width;
		} else if (!strcmp (panels->panel[panels->curnode].title, PANEL_TITLE_REGISTERS)) {
			if (core->print->cur_enabled) {
				int cur = core->print->cur;
				int cols = core->dbg->regcols;
				cols = cols > 0 ? cols : 3;
				cur -= cols;
				if (cur >= 0) {
					core->print->cur = cur;
				}
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
	panels->panel[panels->curnode].refresh = true;
	if (panels->panel[panels->curnode].type == PANEL_TYPE_MENU) {
		if (menus_sub[panels->menu_x][panels->menu_y]) {
			panels->menu_y++;
		}
	} else {
		if (!strcmp (panels->panel[panels->curnode].title, PANEL_TITLE_DISASSEMBLY)) {
			int cols = core->print->cols;
			RAnalFunction *f = NULL;
			RAsmOp op;
			f = r_anal_get_fcn_in (core->anal, core->offset, 0);
			op.size = 1;
			if (f && f->folded) {
				cols = core->offset - f->addr + r_anal_fcn_size (f);
			} else {
				r_asm_set_pc (core->assembler, core->offset);
				cols = r_asm_disassemble (core->assembler,
						&op, core->block, 32);
			}
			if (cols < 1) {
				cols = op.size > 1 ? op.size : 1;
			}
			r_core_seek (core, core->offset + cols, 1);
			r_core_block_read (core);
		} else if (!strcmp (panels->panel[panels->curnode].title, PANEL_TITLE_STACK)) {
			int width = r_config_get_i (core->config, "hex.cols");
			if (width < 1) {
				width = 16;
			}
			r_config_set_i (core->config, "stack.delta",
					r_config_get_i (core->config, "stack.delta") - width);
			panels->panel[panels->curnode].addr += width;
		} else if (!strcmp (panels->panel[panels->curnode].title, PANEL_TITLE_REGISTERS)) {
			if (core->print->cur_enabled) {
				const int cols = core->dbg->regcols;
				core->print->cur += cols > 0 ? cols : 3;
			}
		} else {
			panels->panel[panels->curnode].sy++;
		}
	}
}

static void handleLeftKey(RCore *core) {
	RPanels *panels = core->panels;

	r_cons_switchbuf (false);
	panels->panel[panels->curnode].refresh = true;
	if (core->print->cur_enabled) {
		cursorLeft (core);
	} else {
		if (panels->curnode == 0) {
			if (panels->menu_x) {
				panels->menu_x--;
				panels->menu_y = panels->menu_y? 1: 0;
			}
		} else {
			if (panels->panel[panels->curnode].sx > 0) {
				panels->panel[panels->curnode].sx--;
			}
		}
	}
}

static void handleRightKey(RCore *core) {
	RPanels *panels = core->panels;

	r_cons_switchbuf (false);
	panels->panel[panels->curnode].refresh = true;
	if (core->print->cur_enabled) {
		cursorRight (core);
	} else {
		if (panels->curnode == 0) {
			if (menus[panels->menu_x + 1]) {
				panels->menu_x++;
				panels->menu_y = panels->menu_y ? 1: 0;
			}
		} else {
			panels->panel[panels->curnode].sx++;
		}
	}
}

static bool handleCursorMode(RCore *core, const int key) {
	const char *creg;
	const RPanels *panels = core->panels;
	char buf[128];
	if (core->print->cur_enabled) {
		switch (key) {
			case 9: // TAB
			case 'J':
			case 'Z': // SHIFT-TAB
			case 'K':
				return true;
			case 'Q':
			case 'q':
				setCursor (core, !core->print->cur_enabled);
				panels->panel[panels->curnode].refresh = true;
				return true;
			case 'i':
				if (!strcmp (panels->panel[panels->curnode].title, PANEL_TITLE_STACK)) {
					// insert mode
					const char *prompt = "insert hex: ";
					panelPrompt (prompt, buf, sizeof (buf));
					r_core_cmdf (core, "wx %s @ 0x%08" PFMT64x, buf, panels->panel[panels->curnode].addr);
					panels->panel[panels->curnode].refresh = true;
				} else if (!strcmp (panels->panel[panels->curnode].title, PANEL_TITLE_REGISTERS)) {
					creg = core->dbg->creg;
					if (creg) {
						const char *prompt = "new-reg-value> ";
						panelPrompt (prompt, buf, sizeof (buf));
						r_core_cmdf (core, "dr %s = %s", creg, buf);
						panels->panel[panels->curnode].refresh = true;
					}
				}
				return true;
		}
	}
	return false;
}

static void delCurPanel(RPanels *panels) {
	int i;
	if (panels->curnode > 0 && panels->n_panels > 3) {
		for (i = panels->curnode; i < (panels->n_panels - 1); i++) {
			panels->panel[i] = panels->panel[i + 1];
		}
		panels->panel[i].title = 0;
		panels->n_panels--;
		if (panels->curnode >= panels->n_panels) {
			panels->curnode = panels->n_panels - 1;
		}
	}
}

static void zoom(RPanels *panels) {
	if (panels->n_panels > 2) {
		if (panels->curnode < 2) {
			panels->curnode = 2;
		}
		RPanel ocurnode = panels->panel[panels->curnode];
		panels->panel[panels->curnode] = panels->panel[1];
		panels->panel[1] = ocurnode;
		panels->curnode = 1;
	}
}

static void setRefreshAll(RPanels *panels) {
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		panels->panel[i].refresh = true;
	}
}

static void addPanelFrame(RCore *core, RPanels* panels, const char *title, const char *cmd) {
	RPanel* panel = panels->panel;
	int n_panels = panels->n_panels;
	if (title) {
		panel[n_panels].title = strdup (title);
		panel[n_panels].cmd = r_str_newf (cmd);
	} else {
		panel[n_panels].title = r_core_cmd_str (core, cmd);
		panel[n_panels].cmd = NULL;
	}
	panel[panels->n_panels].type = PANEL_TYPE_FRAME;
	panel[panels->n_panels].refresh = true;
	panel[panels->n_panels].curpos = 0;
	if (!strcmp (panel[panels->n_panels].title, PANEL_TITLE_STACK)) {
		const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
		const ut64 stackbase = r_reg_getv (core->anal->reg, sp);
		panel[panels->n_panels].baseAddr = stackbase;
		panel[panels->n_panels].addr = stackbase - r_config_get_i (core->config, "stack.delta");
	}
	panels->n_panels++;
	panels->curnode = panels->n_panels - 1;
	zoom (panels);
	panels->menu_y = 0;
}

static bool initPanels(RCore *core, RPanels *panels) {
	panels->panel = NULL;
	panels->panel = calloc (sizeof (RPanel), LIMIT);
	if (!panels->panel) return false;
	panels->n_panels = 0;
	panels->menu_pos = 0;
	panels->panel[panels->n_panels].title = strdup ("");
	panels->panel[panels->n_panels].type = PANEL_TYPE_MENU;
	panels->panel[panels->n_panels].refresh = true;
	panels->n_panels++;

	addPanelFrame (core, panels, PANEL_TITLE_SYMBOLS, PANEL_CMD_SYMBOLS);
	addPanelFrame (core, panels, PANEL_TITLE_STACK, PANEL_CMD_STACK);
	addPanelFrame (core, panels, PANEL_TITLE_REGISTERS, PANEL_CMD_REGISTERS);
	addPanelFrame (core, panels, PANEL_TITLE_REGISTERREFS, PANEL_CMD_REGISTERREFS);
	addPanelFrame (core, panels, PANEL_TITLE_DISASSEMBLY, PANEL_CMD_DISASSEMBLY);
	panels->curnode = 1;
	return true;
}

// damn singletons.. there should be only one screen and therefor
// only one visual instance of the graph view. refactoring this
// into a struct makes the code to reference pointers unnecesarily
// we can look for a non-global solution here in the future if
// necessary
static void panelsRefresh(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *panel = panels->panel;
	RConsCanvas *can = panels->can;
	int menu_pos = panels->menu_pos;
	int menu_x = panels->menu_x;
	int menu_y = panels->menu_y;
	char title[1024];
	char str[1024];
	int i, j, h, w = r_cons_get_size (&h);
	const char *color = panels->curnode ? core->cons->pal.graph_box : core->cons->pal.graph_box2;
	r_cons_gotoxy (0, 0);
	if (!can) {
		return;
	}
	if (panels->isResizing) {
		panels->isResizing = false;
		r_cons_canvas_resize (can, w, h);
		setRefreshAll (panels);
	}
#if 0
	/* avoid flickering */
	r_cons_canvas_clear (can);
	r_cons_flush ();
#endif
	if (panel) {
		panel[menu_pos].x = (menu_y > 0) ? menu_x * 6 : w;
		panel[menu_pos].y = 1;
		free (panel[menu_pos].title);
		panel[menu_pos].title = calloc (1, 1024); // r_str_newf ("%d", menu_y);
		int maxsub = 0;
		for (i = 0; menus_sub[i]; i++) {
			maxsub = i;
		}
		if (menu_x < 0) {
			panels->menu_x = 0;
		}
		if (menu_x > maxsub) {
			panels->menu_x = maxsub;
		}
		if (menu_x >= 0 && menu_x <= maxsub && menus_sub[menu_x]) {
			for (j = 0; menus_sub[menu_x][j]; j++) {
				if (menu_y - 1 == j) {
					strcat (panel[menu_pos].title, "> ");
				} else {
					strcat (panel[menu_pos].title, "  ");
				}
				strcat (panel[menu_pos].title, menus_sub[menu_x][j]);
				strcat (panel[menu_pos].title, "          \n");
			}
		}
		for (i = 0; i < panels->n_panels; i++) {
			if (i != panels->curnode) {
				panelPrint (core, can, &panel[i], 0);
			}
		}
	}
	if (panel && panels->n_panels > 1) {
		// always refresh first panel or can be trashed
		panel[1].refresh = true;
	}
	if (menu_y) {
		panels->curnode = menu_pos;
	}
	if (panels->panel) {
		if (panel[panels->curnode].type == PANEL_TYPE_MENU) {
			panel[panels->curnode].refresh = true;
			panelPrint (core, can, &panel[panels->curnode], menu_y);
		} else {
			panelPrint (core, can, &panel[panels->curnode], 1);
		}
	}

	(void) r_cons_canvas_gotoxy (can, -can->sx, -can->sy);
	title[0] = 0;
	if (panels->curnode == 0) {
		strcpy (title, "> ");
	}
	for (i = 0; menus[i]; i++) {
		if (menu_x == i) {
			snprintf (str, sizeof (title) - 1, "%s[%s]"Color_RESET, color, menus[i]);
		} else {
			snprintf (str, sizeof (title) - 1, "%s %s "Color_RESET, color, menus[i]);
		}
		strcat (title, str);
	}
	if (panels->curnode == 0) {
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
	core->panels->isResizing = true;
	layoutRun (core->panels);
	panelsRefresh (core);
}

static int havePanel(RPanels *panels, const char *s) {
	int i;
	if (!panels->panel || !panels->panel[0].title) {
		return 0;
	}
	// add new panel for testing
	for (i = 1; panels->panel[i].title; i++) {
		if (!strcmp (panels->panel[i].title, s)) {
			return 1;
		}
	}
	return 0;
}

static void panelSingleStepIn(RCore *core) {
	if (r_config_get_i (core->config, "cfg.debug")) {
		if (core->print->cur_enabled) {
			// dcu 0xaddr
			r_core_cmdf (core, "dcu 0x%08"PFMT64x, core->offset + core->print->cur);
			core->print->cur_enabled = 0;
		} else {
			r_core_cmd (core, "ds", 0);
			r_core_cmd (core, ".dr*", 0);
		}
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
	r_core_cmd (core, "dbs $$", 0);
}

static void panelContinue(RCore *core) {
	r_core_cmd (core, "dc", 0);
}

static void checkStackbase(RCore *core) {
	if (!core || !core->panels) {
		return;
	}
	int i;
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	const ut64 stackbase = r_reg_getv (core->anal->reg, sp);
	RPanels *panels = core->panels;
	for (i = 1; i < panels->n_panels; i++) {
		const RPanel panel = panels->panel[i];
		if (!strcmp (panel.title, PANEL_TITLE_STACK) && panel.baseAddr != stackbase) {
			panels->panel[panels->curnode].baseAddr = stackbase;
			panels->panel[panels->curnode].addr = stackbase - r_config_get_i (core->config, "stack.delta") + core->print->cur;
			panels->panel[panels->curnode].refresh = true;
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
	panels->menu_pos = 0;
	panels->menu_x = 0;
	panels->menu_y = 0;
	panels->callgraph = 0;
	panels->isResizing = false;
	panels->can = r_cons_canvas_new (w, h);
	r_cons_canvas_fill (panels->can, 0, 0, w, h, ' ', 0);
	if (!panels->can) {
		eprintf ("Cannot create RCons.canvas context\n");
		return false;
	}
	panels->can->linemode = r_config_get_i (core->config, "graph.linemode");
	panels->can->color = r_config_get_i (core->config, "scr.color");
	if (w < 140) {
		panels->columnWidth = w / 3;
	}
	return true;
}

static bool handleEnterKey(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->curnode == 0 && panels->menu_y) {
		const char *action = menus_sub[panels->menu_x][panels->menu_y - 1];
		if (strstr (action, "New")) {
			addPanelFrame (core, panels, PANEL_TITLE_NEWFILES, "o");
		} else if (strstr (action, "Open")) {
			/* XXX doesnt autocompletes filenames */
			r_cons_enable_mouse (false);
			char *res = r_cons_input ("open file: ");
			if (res) {
				if (*res) {
					r_core_cmdf (core, "o %s", res);
				}
				free (res);
			}
			r_cons_enable_mouse (true);
		} else if (strstr (action, "RegisterRefs")) {
			addPanelFrame (core, panels, "drr", "drr");
		} else if (strstr (action, "Registers")) {
			addPanelFrame (core, panels, "dr=", "dr=");
		} else if (strstr (action, "Info")) {
			addPanelFrame (core, panels, PANEL_TITLE_INFO, "i");
		} else if (strstr (action, "Database")) {
			addPanelFrame (core, panels, PANEL_TITLE_DATABASE, "k ***");
		} else if (strstr (action, "Registers")) {
			if (!havePanel (panels, "Registers")) {
				addPanelFrame (core, panels, PANEL_TITLE_REGISTERS, "dr=");
			}
		} else if (strstr (action, "About")) {
			char *s = r_core_cmd_str (core, "?V");
			r_cons_message (s);
			free (s);
		} else if (strstr (action, "Hexdump")) {
			addPanelFrame (core, panels, PANEL_TITLE_HEXDUMP, "px 512");
		} else if (strstr (action, "Disassembly")) {
			addPanelFrame (core, panels, PANEL_TITLE_DISASSEMBLY, "pd 128");
		} else if (strstr (action, "Functions")) {
			addPanelFrame (core, panels, PANEL_TITLE_FUNCTIONS, "afl");
		} else if (strstr (action, "Comments")) {
			addPanelFrame (core, panels, PANEL_TITLE_COMMENTS, "CC");
		} else if (strstr (action, "Entropy")) {
			addPanelFrame (core, panels, PANEL_TITLE_ENTROPY, "p=e");
		} else if (strstr (action, "Function")) {
			r_core_cmdf (core, "af");
		} else if (strstr (action, "DRX")) {
			addPanelFrame (core, panels, PANEL_TITLE_DRX, "drx");
		} else if (strstr (action, "Program")) {
			r_core_cmdf (core, "aaa");
		} else if (strstr (action, "Calls")) {
			r_core_cmdf (core, "aac");
		} else if (strstr (action, "ROP")) {
			r_cons_enable_mouse (false);
			char *res = r_cons_input ("rop grep: ");
			if (res) {
				r_core_cmdf (core, "\"/R %s\"", res);
				free (res);
			}
			r_cons_enable_mouse (true);
		} else if (strstr (action, "String")) {
			r_cons_enable_mouse (false);
			char *res = r_cons_input ("search string: ");
			if (res) {
				r_core_cmdf (core, "\"/ %s\"", res);
				free (res);
			}
			r_cons_enable_mouse (true);
		} else if (strstr (action, "Hexpairs")) {
			r_cons_enable_mouse (false);
			char *res = r_cons_input ("search hexpairs: ");
			if (res) {
				r_core_cmdf (core, "\"/x %s\"", res);
				free (res);
			}
			r_cons_enable_mouse (true);
		} else if (strstr (action, "Code")) {
			r_cons_enable_mouse (false);
			char *res = r_cons_input ("search code: ");
			if (res) {
				r_core_cmdf (core, "\"/c %s\"", res);
				free (res);
			}
			r_cons_enable_mouse (true);
		} else if (strstr (action, "Copy")) {
			r_cons_enable_mouse (false);
			char *res = r_cons_input ("How many bytes? ");
			if (res) {
				r_core_cmdf (core, "\"y %s\"", res);
				free (res);
			}
			r_cons_enable_mouse (true);
		} else if (strstr (action, "Write String")) {
			r_cons_enable_mouse (false);
			char *res = r_cons_input ("insert string: ");
			if (res) {
				r_core_cmdf (core, "\"w %s\"", res);
				free (res);
			}
			r_cons_enable_mouse (true);
		} else if (strstr (action, "Write Value")) {
			r_cons_enable_mouse (false);
			char *res = r_cons_input ("insert number: ");
			if (res) {
				r_core_cmdf (core, "\"wv %s\"", res);
				free (res);
			}
			r_cons_enable_mouse (true);
		} else if (strstr (action, "Write Hex")) {
			r_cons_enable_mouse (false);
			char *res = r_cons_input ("insert hexpairs: ");
			if (res) {
				r_core_cmdf (core, "\"wx %s\"", res);
				free (res);
			}
			r_cons_enable_mouse (true);
		} else if (strstr (action, "Calculator")) {
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
		} else if (strstr (action, "Assemble")) {
			r_core_visual_asm (core, core->offset);
		} else if (strstr (action, "Sections")) {
			addPanelFrame (core, panels, PANEL_TITLE_SECTIONS, "iSq");
		} else if (strstr (action, "Close")) {
			r_core_cmd0 (core, "o-*");
		} else if (strstr (action, "Strings")) {
			addPanelFrame (core, panels, PANEL_TITLE_STRINGS, "izq");
		} else if (strstr (action, "Maps")) {
			addPanelFrame (core, panels, PANEL_TITLE_MAPS, "dm");
		} else if (strstr (action, "Modules")) {
			addPanelFrame (core, panels, PANEL_TITLE_MODULES, "dmm");
		} else if (strstr (action, "Backtrace")) {
			addPanelFrame (core, panels, PANEL_TITLE_BACKTRACE, "dbt");
		} else if (strstr (action, "Step")) {
			r_core_cmd (core, "ds", 0);
			r_cons_flush ();
		} else if (strstr (action, "Step Over")) {
			r_core_cmd (core, "dso", 0);
			r_cons_flush ();
		} else if (strstr (action, "Continue")) {
			r_core_cmd (core, "dc", 0);
			r_cons_flush ();
		} else if (strstr (action, "Breakpoints")) {
			addPanelFrame (core, panels, PANEL_TITLE_BREAKPOINTS, "db");
		} else if (strstr (action, "Symbols")) {
			addPanelFrame (core, panels, PANEL_TITLE_SYMBOLS, "isq");
		} else if (strstr (action, "Imports")) {
			addPanelFrame (core, panels, PANEL_TITLE_IMPORTS, "iiq");
		} else if (strstr (action, "Paste")) {
			r_core_cmd0 (core, "yy");
		} else if (strstr (action, "Clipboard")) {
			addPanelFrame (core, panels, PANEL_TITLE_CLIPBOARD, "yx");
		} else if (strstr (action, "io.cache")) {
			r_core_cmd0 (core, "e!io.cache");
		} else if (strstr (action, "Fill")) {
			r_cons_enable_mouse (false);
			char *s = r_cons_input ("Fill with: ");
			r_core_cmdf (core, "wow %s", s);
			free (s);
			r_cons_enable_mouse (true);
		} else if (strstr (action, "References")) {
			r_core_cmdf (core, "aar");
		} else if (strstr (action, "FcnInfo")) {
			addPanelFrame (core, panels, PANEL_TITLE_FCNINFO, "afi");
		} else if (strstr (action, "Graph")) {
			r_core_visual_graph (core, NULL, NULL, true);
			// addPanelFrame ("Graph", "agf");
		} else if (strstr (action, "System Shell")) {
			r_cons_set_raw (0);
			r_cons_flush ();
			r_sys_cmd ("$SHELL");
		} else if (strstr (action, "R2 Shell")) {
			core->vmode = false;
			r_core_visual_prompt_input (core);
			core->vmode = true;
		} else if (!strcmp (action, "2048")) {
			r_cons_2048 (panels->can->color);
		} else if (strstr (action, "License")) {
			r_cons_message ("Copyright 2006-2016 - pancake - LGPL");
		} else if (strstr (action, "Fortune")) {
			char *s = r_core_cmd_str (core, "fo");
			r_cons_message (s);
			free (s);
		} else if (strstr (action, "Commands")) {
			r_core_cmd0 (core, "?;?@?;?$?;???");
			r_cons_any_key (NULL);
		} else if (strstr (action, "Colors")) {
			r_core_cmd0 (core, "e!scr.color");
		} else if (strstr (action, "Quit")) {
			return false;
		}
	} else {
		if (panels->curnode > 0) {
			zoom (panels);
		} else {
			panels->menu_y = 1;
		}
	}
	return true;
}

R_API RPanels *r_panels_new(RCore *core) {
	int w, h;
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

R_API void r_panels_free(RPanels *panels) {
	int i;
	r_cons_switchbuf (true);
	if (panels) {
		for (i = 0; i < panels->n_panels; i++) {
			free (panels->panel[i].title);
			free (panels->panel[i].cmd);
		}
		free (panels->panel);
		if (panels->can) {
			free (panels->can->b);
			free (panels->can->attrs);
			free (panels->can);
		}
		free (panels);
	}
}

R_API int r_core_visual_panels(RCore *core, RPanels *panels) {
	int okey, key, wheel;
	int asm_comments = 0;
	int asm_bytes = 0;
	int have_utf8 = 0;

	if (!panels) {
		panels = r_panels_new (core);
		if (!panels) {
			r_panels_free (panels);
			return false;
		}
	}

	if (!initPanels (core, panels)) {
		r_panels_free (panels);
		return false;
	}

	r_cons_switchbuf (false);
	panels->originCursor = core->print->cur;
	core->print->cur = 0;
	core->print->cur_enabled = false;
	core->print->col = 0;

	r_config_set_i (core->config, "asm.comments", 0);
	r_config_set_i (core->config, "asm.bytes", 1);
	r_config_set_i (core->config, "scr.utf8", 1);
	asm_comments = r_config_get_i (core->config, "asm.comments");
	asm_bytes = r_config_get_i (core->config, "asm.bytes");
	have_utf8 = r_config_get_i (core->config, "scr.utf8");

repeat:
	core->panels = panels;
	core->cons->event_data = core;
	core->cons->event_resize = (RConsEvent) doPanelsRefresh;
	checkStackbase (core);
	layoutRun (panels);
	panelsRefresh (core);
	wheel = r_config_get_i (core->config, "scr.wheel");
	if (wheel) {
		r_cons_enable_mouse (true);
	}
	okey = r_cons_readchar ();
	key = r_cons_arrow_to_hjkl (okey);
	r_cons_switchbuf (true);

	if (handleCursorMode (core, key)) {
		goto repeat;
	}

	const char *cmd;
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
		if (r_config_get_i (core->config, "cfg.debug")) {
			r_core_cmd0 (core, "sr PC");
			// r_core_seek (core, r_num_math (core->num, "entry0"), 1);
		} else {
			r_core_cmd0 (core, "s entry0; px");
		}
		doPanelsRefresh (core);
		break;
	case ' ':
	case '\r':
	case '\n':
		if (!handleEnterKey (core)) {
			goto exit;
		}
		doPanelsRefresh (core);
		break;
	case '?':
		r_cons_clear00 ();
		r_cons_printf ("Visual Ascii Art Panels:\n"
			" !    - run r2048 game\n"
			" .    - seek to PC or entrypoint\n"
			" :    - run r2 command in prompt\n"
			" _    - start the hud input mode\n"
			" ?    - show this help\n"
			" x    - close current panel\n"
			" m    - open menubar\n"
			" V    - view graph\n"
			" b    - browse symbols, flags, configurations, classes, ...\n"
			" c    - toggle cursor\n"
			" C    - toggle color\n"
			" i    - insert hex\n"
			" M    - open new custom frame\n"
			" hl   - toggle scr.color\n"
			" HL   - move vertical column split\n"
			" jk   - scroll/select menu\n"
			" JK   - select prev/next panels (same as TAB)\n"
			" sS   - step in / step over\n"
			" uU   - undo / redo seek\n"
			" pP   - seek to next or previous scr.nkey\n"
			" nN   - create new panel with given command\n"
			" q    - quit, back to visual mode\n"
			);
		r_cons_flush ();
		r_cons_any_key (NULL);
		break;
	case 'b':
		r_core_visual_browse (core);
		break;
	case 's':
		if (r_config_get_i (core->config, "cfg.debug")) {
			r_core_cmd0 (core, "ds;.dr*"); // ;sr PC");
		} else {
			panelSingleStepIn (core);
		}
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
		doPanelsRefresh (core);
		break;
	case 'c':
		if (!strcmp (panels->panel[panels->curnode].title, PANEL_TITLE_STACK) || !strcmp (panels->panel[panels->curnode].title, PANEL_TITLE_REGISTERS)) {
			setCursor (core, !core->print->cur_enabled);
			panels->panel[panels->curnode].refresh = true;
		}
		break;
	case 'C':
		panels->can->color = !panels->can->color;
		// r_config_toggle (core->config, "scr.color");
		// refresh graph
		doPanelsRefresh (core);
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
		break;
	case 'j':
		handleDownKey (core);
		break;
	case 'k':
		handleUpKey (core);
		break;
	case '_':
		r_core_visual_hud (core);
		break;
	case 'x':
		delCurPanel (panels);
		setRefreshAll (panels);
		break;
	case 9: // TAB
	case 'J':
		r_cons_switchbuf (false);
		panels->menu_y = 0;
		panels->menu_x = -1;
		panels->panel[panels->curnode].refresh = true;
		panels->curnode++;
		panels->panel[panels->curnode].refresh = true;
		if (!panels->panel[panels->curnode].title) {
			panels->curnode = 0;
			panels->menu_x = 0;
		}
		break;
	case 'Z': // SHIFT-TAB
	case 'K':
		r_cons_switchbuf (false);
		panels->menu_y = 0;
		panels->menu_x = -1;
		panels->panel[panels->curnode].refresh = true;
		panels->curnode--;
		panels->panel[panels->curnode].refresh = true;
		if (panels->curnode < 0) {
			panels->curnode = panels->n_panels - 1;
		}
		if (!panels->curnode) {
			panels->menu_x = 0;
		}
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
	case 'm':
		panels->curnode = 0;
		if (panels->menu_x < 0) {
			panels->menu_x = 0;
			panelsRefresh (core);
		}
		panels->menu_y = 1;
		break;
	case 'H':
		r_cons_switchbuf (false);
		panels->columnWidth += 4;
		panels->isResizing = true;
		break;
	case 'L':
		r_cons_switchbuf (false);
		panels->columnWidth -= 4;
		panels->isResizing = true;
		if (panels->columnWidth < 0) {
			panels->columnWidth = 0;
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
			RAnalFunction *fun = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
			int ocolor;

			if (!fun) {
				r_cons_message ("Not in a function. Type 'df' to define it here");
				break;
			} else if (r_list_empty (fun->bbs)) {
				r_cons_message ("No basic blocks in this function. You may want to use 'afb+'.");
				break;
			}
			ocolor = r_config_get_i (core->config, "scr.color");
			r_core_visual_graph (core, NULL, NULL, true);
			r_config_set_i (core->config, "scr.color", ocolor);
			setRefreshAll (panels);
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
		setRefreshAll (panels);
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
		}
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		} else {
			panelSingleStepOver (core);
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
	case 'q':
	case -1: // EOF
		if (panels->menu_y < 1) {
			goto exit;
		}
		panels->menu_y = 0;
		break;
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
	r_config_set_i (core->config, "scr.color", panels->can->color);
	r_config_set_i (core->config, "asm.comments", asm_comments);
	r_config_set_i (core->config, "asm.bytes", asm_bytes);
	r_config_set_i (core->config, "scr.utf8", have_utf8);

	core->print->cur = panels->originCursor;
	core->print->cur_enabled = false;
	core->print->col = 0;

	r_panels_free (panels);
	core->panels = NULL;
	return true;
}

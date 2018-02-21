/* Copyright radare2 2014-2017 - Author: pancake */

// pls move the typedefs into roons and rename it -> RConsPanel

#include <r_core.h>

#define PANEL_TYPE_FRAME 0
#define PANEL_TYPE_FLOAT 1
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

static RConsCanvas *can;

typedef struct {
	int x;
	int y;
	int w;
	int h;
	int depth;
	int type;
	int sx; // scroll-x
	int sy; // scroll-y
	ut64 addr;
	char *cmd;
	char *text;
} Panel;

static Panel *panels = NULL;
static int n_panels = 0;
static int COLW = 80;
static const int layoutCount = 2;
static int layout = 0;
static RCore *_core;
static int menu_pos = 0;
static int menu_x = 0;
static int menu_y = 0;
static int callgraph = 0;

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

// TODO: handle mouse wheel
static int curnode = 0;

static void Panel_print(RConsCanvas *can, Panel *n, int cur) {
	char title[128];
	int delta_x, delta_y;
	if (!n || !can) {
		return;
	}
	delta_x = n->sx;
	delta_y = n->sy;
	// clear
	r_cons_canvas_fill (can, n->x, n->y, n->w, n->h, ' ', 0);
	if (n->type == PANEL_TYPE_FRAME) {
		if (cur) {
			snprintf (title, sizeof (title) - 1,
				Color_BGREEN "[x] %s"Color_RESET, n->text);
		} else {
			snprintf (title, sizeof (title) - 1,
				"   %s   ", n->text);
		}
		if (r_cons_canvas_gotoxy (can, n->x + 1, n->y + 1)) {
			r_cons_canvas_write (can, title); // delta_x
		}
	}
	(void) r_cons_canvas_gotoxy (can, n->x + 2, n->y + 2);
	// if (
// TODO: only refresh if n->refresh is set
// TODO: temporary crop depending on out of screen offsets
	if (n->cmd && *n->cmd) {
		char *foo = r_core_cmd_str (_core, n->cmd);
		char *text;
		if (delta_y < 0) {
			delta_y = 0;
		}
		if (delta_x < 0) {
			char white[128];
			int idx = -delta_x;
			memset (white, ' ', sizeof(white));
			if (idx >= sizeof (white)) {
				idx = sizeof (white) - 1;
			}
			white[idx] = 0;
			text = r_str_ansi_crop (foo,
				0, delta_y, n->w + delta_x - 2, n->h - 2 + delta_y);
			char *newText = r_str_prefix_all (text, white);
			if (newText) {
				free (text);
				text = newText;
			}
		} else {
			text = r_str_ansi_crop (foo,
				delta_x, delta_y, n->w + delta_x - 2, n->h - 2 + delta_y);
		}
		if (text) {
			r_cons_canvas_write (can, text);
			free (text);
		} else {
			r_cons_canvas_write (can, n->text);
		}
		free (foo);
	} else {
		char *text = r_str_ansi_crop (n->text,
			delta_x, delta_y, n->w + 5, n->h - delta_y);
		if (text) {
			r_cons_canvas_write (can, text);
			free (text);
		} else {
			r_cons_canvas_write (can, n->text);
		}
	}
	if (cur) {
		r_cons_canvas_box (can, n->x, n->y, n->w, n->h, Color_BLUE);
	} else {
		r_cons_canvas_box (can, n->x, n->y, n->w, n->h, NULL);
	}
}

static void Layout_run(Panel *panels) {
	int h, w = r_cons_get_size (&h);
	int i, j;
	int colpos = w - COLW;
	if (colpos < 0) {
		COLW = w;
		colpos = 0;
	}
	if (layout >= layoutCount) {
		layout = 0;
	}
	can->sx = 0;
	can->sy = 0;
	for (i = j = 0; panels[i].text; i++) {
		switch (panels[i].type) {
		case PANEL_TYPE_FLOAT:
			panels[i].w = r_str_bounds (
				panels[i].text,
				&panels[i].h);
			panels[i].h += 4;
			break;
		case PANEL_TYPE_FRAME:
			switch (layout) {
			case 0:
				if (j == 0) {
					panels[i].x = 0;
					panels[i].y = 1;
					if (panels[j + 1].text) {
						panels[i].w = colpos + 1;
					} else {
						panels[i].w = w;
					}
					panels[i].h = h - 1;
				} else {
					int ph = ((h - 1) / (n_panels - 2));
					panels[i].x = colpos;
					panels[i].y = 1 + (ph * (j - 1));
					panels[i].w = w - colpos;
					if (panels[i].w < 0) {
						panels[i].w = 0;
					}
					panels[i].h = ph;
					if (!panels[i + 1].text) {
						panels[i].h = h - panels[i].y;
					}
					if (j != 1) {
						panels[i].y--;
						panels[i].h++;
					}
				}
				break;
			case 1:
				if (j == 0) {
					panels[i].x = 0;
					panels[i].y = 1;
					if (panels[j + 1].text) {
						panels[i].w = colpos + 1;
					} else {
						panels[i].w = w;
					}
					panels[i].h = (h / 2) + 1;
				} else if (j == 1) {
					panels[i].x = 0;
					panels[i].y = (h / 2) + 1;
					if (panels[j + 1].text) {
						panels[i].w = colpos + 1;
					} else {
						panels[i].w = w;
					}
					panels[i].h = (h - 1) / 2;
				} else {
					int ph = ((h - 1) / (n_panels - 3));
					panels[i].x = colpos;
					panels[i].y = 1 + (ph * (j - 2));
					panels[i].w = w - colpos;
					if (panels[i].w < 0) {
						panels[i].w = 0;
					}
					panels[i].h = ph;
					if (!panels[i + 1].text) {
						panels[i].h = h - panels[i].y;
					}
					if (j != 2) {
						panels[i].y--;
						panels[i].h++;
					}
				}
				break;
			}
			j++;
		}
	}
}

static void delcurpanel() {
	int i;
	if (curnode > 0 && n_panels > 3) {
		for (i = curnode; i < (n_panels - 1); i++) {
			panels[i] = panels[i + 1];
		}
		panels[i].text = 0;
		n_panels--;
		if (curnode >= n_panels) {
			curnode = n_panels - 1;
		}
	}
}

static void zoom() {
	if (n_panels > 2) {
		if (curnode < 2) {
			curnode = 2;
		}
		Panel ocurnode = panels[curnode];
		panels[curnode] = panels[1];
		panels[1] = ocurnode;
		curnode = 1;
	}
}

static void addPanelFrame(const char *title, const char *cmd, ut64 addr) {
	if (!panels) {
		panels = calloc (sizeof (Panel), LIMIT);
		if (!panels) {
			return;
		}
		panels[0].text = strdup ("");
		panels[0].addr = addr;
		panels[0].type = PANEL_TYPE_FLOAT;
		n_panels = 1;
		menu_pos = 0;
	}
	panels[n_panels].text = strdup (title);
	panels[n_panels].cmd = r_str_newf (cmd);
	panels[n_panels].addr = addr;
	panels[n_panels].type = PANEL_TYPE_FRAME;
	panels[n_panels + 1].text = NULL;
	n_panels++;
	curnode = n_panels - 1;
	zoom ();
	menu_y = 0;
}

static int bbPanels(RCore *core) {
	addPanelFrame (PANEL_TITLE_SYMBOLS, "isq", 0);
	addPanelFrame (PANEL_TITLE_STACK, "px 256@r:SP", 0);
	addPanelFrame (PANEL_TITLE_REGISTERS, "dr=", 0);
	addPanelFrame (PANEL_TITLE_REGISTERREFS, "drr", 0);
	addPanelFrame (PANEL_TITLE_DISASSEMBLY, "pd 128", 0);
	curnode = 1;
	Layout_run (panels);
	return n_panels;
}

// damn singletons.. there should be only one screen and therefor
// only one visual instance of the graph view. refactoring this
// into a struct makes the code to reference pointers unnecesarily
// we can look for a non-global solution here in the future if
// necessary
static void r_core_panels_refresh(RCore *core) {
	char title[1024];
	const char *color = curnode? Color_BLUE: Color_BGREEN;
	char str[1024];
	int i, j, h, w = r_cons_get_size (&h);
	r_cons_clear00 ();
	if (!can) {
		return;
	}
	r_cons_canvas_resize (can, w, h);
#if 0
	/* avoid flickering */
	r_cons_canvas_clear (can);
	r_cons_flush ();
#endif
	if (panels) {
		if (menu_y > 0) {
			panels[menu_pos].x = menu_x * 6;
		} else {
			panels[menu_pos].x = w;
		}
		panels[menu_pos].y = 1;
		free (panels[menu_pos].text);
		panels[menu_pos].text = calloc (1, 1024); // r_str_newf ("%d", menu_y);
		int maxsub = 0;
		for (i = 0; menus_sub[i]; i++) {
			maxsub = i;
		}
		if (menu_x >= 0 && menu_x <= maxsub && menus_sub[menu_x]) {
			for (j = 0; menus_sub[menu_x][j]; j++) {
				if (menu_y - 1 == j) {
					strcat (panels[menu_pos].text, "> ");
				} else {
					strcat (panels[menu_pos].text, "  ");
				}
				strcat (panels[menu_pos].text,
					menus_sub[menu_x][j]);
				strcat (panels[menu_pos].text, "          \n");
			}
		}
		for (i = 0; panels[i].text; i++) {
			if (i != curnode) {
				Panel_print (can, &panels[i], 0);
			}
		}
	}

	if (menu_y) {
		curnode = menu_pos;
	}
	// redraw current node to make it appear on top
	if (panels) {
		if (curnode > 0) {
			Panel_print (can, &panels[curnode], 1);
		} else {
			Panel_print (can, &panels[menu_pos], menu_y);
		}
	}

	(void) r_cons_canvas_gotoxy (can, -can->sx, -can->sy);
	title[0] = 0;
	if (curnode == 0) {
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
	if (curnode == 0) {
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

static void reloadPanels(RCore *core) {
	Layout_run (panels);
}

static int havePanel(const char *s) {
	int i;
	if (!panels || !panels[0].text) {
		return 0;
	}
	// add new panel for testing
	for (i = 1; panels[i].text; i++) {
		if (!strcmp (panels[i].text, s)) {
			return 1;
		}
	}
	return 0;
}

static void panel_single_step_in(RCore *core) {
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

static void panel_single_step_over(RCore *core) {
	if (r_config_get_i (core->config, "cfg.debug")) {
		if (core->print->cur_enabled) {
			r_core_cmd (core, "dcr", 0);
			core->print->cur_enabled = 0;
		} else {
			r_core_cmd (core, "dso", 0);
			r_core_cmd (core, ".dr*", 0);
		}
	} else {
		r_core_cmd (core, "aeso", 0);
		r_core_cmd (core, ".ar*", 0);
	}
}

static void panel_breakpoint(RCore *core) {
	r_core_cmd (core, "dbs $$", 0);
}

static void panel_continue(RCore *core) {
	r_core_cmd (core, "dc", 0);
}

static bool init (RCore *core, int w, int h) {
	panels = NULL;
	layout = 0;
	_core = core;
	menu_pos = 0;
	menu_x = 0;
	menu_y = 0;
	callgraph = 0;
	can = r_cons_canvas_new (w, h);
	if (!can) {
		eprintf ("Cannot create RCons.canvas context\n");
		return false;
	}
	can->linemode = r_config_get_i (core->config, "graph.linemode");
	can->color = r_config_get_i (core->config, "scr.color");
	n_panels = bbPanels (core);
	if (!panels) {
		r_config_set_i (core->config, "scr.color", can->color);
		free (can);
		return false;
	}
	if (w < 140) {
		COLW = w / 3;
	}
	reloadPanels (core);
	return true;
}

R_API int r_core_visual_panels(RCore *core) {
	int okey, key, wheel;
	int w, h;
	int asm_comments = 0;
	int asm_bytes = 0;
	int have_utf8 = 0;

	w = r_cons_get_size (&h);
	if (!init (core, w, h)) {
		return false;
	}

	asm_comments = r_config_get_i (core->config, "asm.comments");
	asm_bytes = r_config_get_i (core->config, "asm.bytes");
	have_utf8 = r_config_get_i (core->config, "scr.utf8");
	r_config_set_i (core->config, "asm.comments", 0);
	r_config_set_i (core->config, "asm.bytes", 0);
	r_config_set_i (core->config, "scr.utf8", 0);

repeat:
	core->cons->event_data = core;
	core->cons->event_resize =\
		(RConsEvent) r_core_panels_refresh;
	w = r_cons_get_size (&h);
	Layout_run (panels);
	r_core_panels_refresh (core);
	wheel = r_config_get_i (core->config, "scr.wheel");
	if (wheel) {
		r_cons_enable_mouse (true);
	}
	// r_core_graph_inputhandle()
	okey = r_cons_readchar ();
	key = r_cons_arrow_to_hjkl (okey);
	const char *cmd;
	switch (key) {
	case 'u':
		r_core_cmd0 (core, "s-");
		break;
	case 'U':
		r_core_cmd0 (core, "s+");
		break;
	case 'n':
		r_core_cmd0 (core, "sn");
		break;
	case 'p':
		r_core_cmd0 (core, "sp");
		break;
	case '.':
		if (r_config_get_i (core->config, "cfg.debug")) {
			r_core_cmd0 (core, "sr PC");
			// r_core_seek (core, r_num_math (core->num, "entry0"), 1);
		} else {
			r_core_cmd0 (core, "s entry0; px");
		}
		break;
	case ' ':
	case '\r':
	case '\n':
		if (curnode == 0 && menu_y) {
			const char *action = menus_sub[menu_x][menu_y - 1];
			if (strstr (action, "New")) {
				addPanelFrame (PANEL_TITLE_NEWFILES, "o", 0);
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
			} else if (strstr (action, "Info")) {
				addPanelFrame (PANEL_TITLE_INFO, "i", 0);
			} else if (strstr (action, "Database")) {
				addPanelFrame (PANEL_TITLE_DATABASE, "k ***", 0);
			} else if (strstr (action, "Registers")) {
				if (!havePanel ("Registers")) {
					addPanelFrame (PANEL_TITLE_REGISTERS, "dr=", core->offset);
				}
			} else if (strstr (action, "About")) {
				char *s = r_core_cmd_str (core, "?V");
				r_cons_message (s);
				free (s);
			} else if (strstr (action, "Hexdump")) {
				addPanelFrame (PANEL_TITLE_HEXDUMP, "px 512", core->offset);
			} else if (strstr (action, "Disassembly")) {
				addPanelFrame (PANEL_TITLE_DISASSEMBLY, "pd 128", core->offset);
			} else if (strstr (action, "Functions")) {
				addPanelFrame (PANEL_TITLE_FUNCTIONS, "afl", core->offset);
			} else if (strstr (action, "Comments")) {
				addPanelFrame (PANEL_TITLE_COMMENTS, "CC", core->offset);
			} else if (strstr (action, "Entropy")) {
				addPanelFrame (PANEL_TITLE_ENTROPY, "p=e", core->offset);
			} else if (strstr (action, "Function")) {
				r_core_cmdf (core, "af");
			} else if (strstr (action, "DRX")) {
				addPanelFrame (PANEL_TITLE_DRX, "drx", core->offset);
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
				addPanelFrame (PANEL_TITLE_SECTIONS, "iSq", 0);
			} else if (strstr (action, "Close")) {
				r_core_cmd0 (core, "o-*");
			} else if (strstr (action, "Strings")) {
				addPanelFrame (PANEL_TITLE_STRINGS, "izq", 0);
			} else if (strstr (action, "Maps")) {
				addPanelFrame (PANEL_TITLE_MAPS, "dm", 0);
			} else if (strstr (action, "Modules")) {
				addPanelFrame (PANEL_TITLE_MODULES, "dmm", 0);
			} else if (strstr (action, "Backtrace")) {
				addPanelFrame (PANEL_TITLE_BACKTRACE, "dbt", 0);
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
				addPanelFrame (PANEL_TITLE_BREAKPOINTS, "db", 0);
			} else if (strstr (action, "Symbols")) {
				addPanelFrame (PANEL_TITLE_SYMBOLS, "isq", 0);
			} else if (strstr (action, "Imports")) {
				addPanelFrame (PANEL_TITLE_IMPORTS, "iiq", 0);
			} else if (strstr (action, "Paste")) {
				r_core_cmd0 (core, "yy");
			} else if (strstr (action, "Clipboard")) {
				addPanelFrame (PANEL_TITLE_CLIPBOARD, "yx", 0);
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
				addPanelFrame (PANEL_TITLE_FCNINFO, "afi", 0);
			} else if (strstr (action, "Graph")) {
				r_core_visual_graph (core, NULL, NULL, true);
				// addPanelFrame ("Graph", "agf", 0);
			} else if (strstr (action, "System Shell")) {
				r_cons_set_raw (0);
				r_cons_flush ();
				r_sys_cmd ("$SHELL");
			} else if (strstr (action, "R2 Shell")) {
				core->vmode = false;
				r_core_visual_prompt_input (core);
				core->vmode = true;
			} else if (!strcmp (action, "2048")) {
				r_cons_2048 (can->color);
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
				goto beach;
			}
		} else {
			if (curnode > 0) {
				zoom ();
			} else {
				menu_y = 1;
			}
		}
		break;
	case '?':
		r_cons_clear00 ();
		r_cons_printf ("Visual Ascii Art Panels:\n"
			" !    - run r2048 game\n"
			" .    - seek to PC or entrypoint\n"
			":    - run r2 command in prompt\n"
			" _    - start the hud input mode\n"
			"?    - show this help\n"
			" x    - close current panel\n"
			" m    - open menubar\n"
			" V    - view graph\n"
			" C    - toggle color\n"
			" M    - open new custom frame\n"
			" hl   - toggle scr.color\n"
			" HL   - move vertical column split\n"
			" jk   - scroll/select menu\n"
			" JK   - select prev/next panels (same as TAB)\n"
			" sS   - step in / step over\n"
			" uU   - undo / redo seek\n"
			" np   - seek to next or previous scr.nkey\n"
			" q    - quit, back to visual mode\n"
			);
		r_cons_flush ();
		r_cons_any_key (NULL);
		break;
	case 's':
		if (r_config_get_i (core->config, "cfg.debug")) {
			r_core_cmd0 (core, "ds;.dr*"); // ;sr PC");
		} else {
			panel_single_step_in (core);
		}
		break;
	case 'S':
		if (r_config_get_i (core->config, "cfg.debug")) {
			r_core_cmd0 (core, "dso;.dr*"); // ;sr PC");
		} else {
			panel_single_step_over (core);
		}
		break;
	case ':':
		core->vmode = false;
		r_core_visual_prompt_input (core);
		core->vmode = true;

		// FIX: Issue with visual mode instruction highlighter
		// not updating after 'ds' or 'dcu' commands.
		r_core_cmd0 (core, ".dr*");
		break;
	case 'C':
		can->color = !can->color;
		// r_config_toggle (core->config, "scr.color");
		// refresh graph
		// reloadPanels (core);
		break;
	case 'R':
		if (r_config_get_i (core->config, "scr.randpal")) {
			r_core_cmd0 (core, "ecr");
		} else {
			r_core_cmd0 (core, "ecn");
		}
		break;
	case 'j':
		if (curnode == 0) {
			if (panels[curnode].type == PANEL_TYPE_FLOAT) {
				if (menus_sub[menu_x][menu_y]) {
					menu_y++;
				}
			}
		} else {
			if (curnode == 1) {
				r_core_cmd0 (core, "s+$l");
			} else {
				panels[curnode].sy++;
			}
		}
		break;
	case 'k':
		if (curnode == 0) {
			if (panels[curnode].type == PANEL_TYPE_FLOAT) {
				menu_y--;
				if (menu_y < 0) {
					menu_y = 0;
				}
			}
		} else {
			if (curnode == 1) {
				r_core_cmd0 (core, "s-8");
			} else {
				if (panels[curnode].sy > 0) {
					panels[curnode].sy--;
				}
			}
		}
		break;
	case '_':
		r_core_visual_hud (core);
		break;
	case 'x':
		delcurpanel ();
		break;
	case 9: // TAB
	case 'J':
		menu_y = 0;
		menu_x = -1;
		curnode++;
		if (!panels[curnode].text) {
			curnode = 0;
			menu_x = 0;
		}
		break;
	case 'Z': // SHIFT-TAB
	case 'K':
		menu_y = 0;
		menu_x = -1;
		curnode--;
		if (curnode < 0) {
			curnode = n_panels - 1;
		}
		if (!curnode) {
			menu_x = 0;
		}
		break;
	case 'M':
	{
		r_cons_enable_mouse (false);
		char *name = r_cons_input ("Name: ");
		char *cmd = r_cons_input ("Command: ");
		if (name && *name && cmd && *cmd) {
			addPanelFrame (name, cmd, 0);
		}
		free (name);
		free (cmd);
		r_cons_enable_mouse (true);
	}
	break;
	case 'm':
		curnode = 0;
		if (menu_x < 0) {
			menu_x = 0;
			r_core_panels_refresh (core);
		}
		menu_y = 1;
		break;
	case 'H':
		COLW += 4;
		break;
	case 'L':
		COLW -= 4;
		if (COLW < 0) {
			COLW = 0;
		}
		break;
	case 'h':
		if (curnode == 0) {
			if (menu_x) {
				menu_x--;
				menu_y = menu_y? 1: 0;
				r_core_panels_refresh (core);
			}
		} else {
			panels[curnode].sx--;
		}
		break;
	case 'l':
		if (curnode == 0) {
			if (menus[menu_x + 1]) {
				menu_x++;
				menu_y = menu_y? 1: 0;
				r_core_panels_refresh (core);
			}
		} else {
			panels[curnode].sx++;
		}
		break;
	case 'V':
		/* copypasta from visual.c */
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
		}
		break;
	case ']':
		r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") + 1);
		break;
	case '[':
		r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") - 1);
		break;
	case 'w':
		layout++;
		Layout_run (panels);
		r_core_panels_refresh (core);
		r_cons_canvas_print (can);
		r_cons_flush ();
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
			panel_breakpoint (core);
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
			panel_single_step_in (core);
		}
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		} else {
			panel_single_step_over (core);
		}
		break;
	case R_CONS_KEY_F9:
		cmd = r_config_get (core->config, "key.f9");
		if (cmd && *cmd) {
			key = r_core_cmd0 (core, cmd);
		} else {
			panel_continue (core);
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
		if (menu_y > 0) {
			menu_y = 0;
		} else {
			goto beach;
		}
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
beach:
	free (panels);
	r_config_set_i (core->config, "scr.color", can->color);
	free (can);
	r_config_set_i (core->config, "asm.comments", asm_comments);
	r_config_set_i (core->config, "asm.bytes", asm_bytes);
	r_config_set_i (core->config, "scr.utf8", have_utf8);
	return true;
}

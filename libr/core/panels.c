/* Copyright radare2 2014-2016 - Author: pancake */

// pls move the typedefs into roons and rename it -> RConsPanel

#include <r_core.h>

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

#define PANEL_TYPE_FRAME 0
#define PANEL_TYPE_DIALOG 1
#define PANEL_TYPE_FLOAT 2

static int COLW = 80;
static RCore *_core;
static int n_panels = 0;
static void reloadPanels(RCore *core) ;
static int menu_pos = 0;
#define LIMIT 256
struct {
	int panels[LIMIT];
	int size;
} ostack;

static RConsCanvas *can;
static Panel *panels = NULL;
static int callgraph = 0;
static int menu_x = 0;
static int menu_y = 0;

static const char *menus[] = {
	"File", "Edit", "View", "Tools", "Search", "Debug", "Analyze", "Help",
	NULL
};

static const char *menus_File[] = {
	"New", "Open", "Close", "--", "Sections", "Strings", "Symbols", "Imports", "Info", "Database", "Quit",
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
	"Watchpoints", "Maps",
	"Continue", "Cont until.",
	"Backtrace",
	NULL
};

static const char *menus_Analyze[] = {
	"Function", "Program", "Calls", "References",
	NULL
};

static const char *menus_Help[] = {
	"Fortune", "Commands", "2048", "License", "About",
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

#define G(x,y) r_cons_canvas_gotoxy (can, x, y)
#define W(x) r_cons_canvas_write (can, x)
#define B(x,y,w,h) r_cons_canvas_box(can, x,y,w,h,NULL)
#define B1(x,y,w,h) r_cons_canvas_box(can, x,y,w,h,Color_BLUE)
#define B2(x,y,w,h) r_cons_canvas_box(can, x,y,w,h,Color_MAGENTA)
#define L(x,y,x2,y2) r_cons_canvas_line(can, x,y,x2,y2,0)
#define L1(x,y,x2,y2) r_cons_canvas_line(can, x,y,x2,y2,1)
#define L2(x,y,x2,y2) r_cons_canvas_line(can, x,y,x2,y2,2)
#define F(x,y,x2,y2,c) r_cons_canvas_fill(can, x,y,x2,y2,c,0)

static void Panel_print(RConsCanvas *can, Panel *n, int cur) {
	char title[128];
	int delta_x, delta_y;
	if (!n || !can)
		return;
	delta_x = n->sx;
	delta_y = n->sy;
	// clear
	F(n->x, n->y, n->w, n->h, ' ');
	if (n->type == PANEL_TYPE_FRAME) {
		if (cur) {
			//F (n->x,n->y, n->w, n->h, '.');
			snprintf (title, sizeof (title)-1,
				Color_BGREEN"[x] %s"Color_RESET, n->text);
		} else {
			snprintf (title, sizeof (title)-1,
				"   %s   ", n->text);
		}
		if (G (n->x+1, n->y+1))
			W (title); // delta_x
	}
	(void)G (n->x+2, n->y+2);
	//if (
// TODO: only refresh if n->refresh is set
// TODO: temporary crop depending on out of screen offsets
	if (n->cmd && *n->cmd) {
		char *foo = r_core_cmd_str (_core, n->cmd);
		char *text;
		if (delta_y < 0) delta_y = 0;
		if (delta_x < 0) {
			char white [128];
			int idx = -delta_x;
			memset (white, ' ', sizeof(white));
			if (idx>=sizeof(white))
				idx = sizeof (white)-1;
			white[idx] = 0;
			text = r_str_ansi_crop (foo,
				0, delta_y, n->w + delta_x, n->h - 2 + delta_y);
			text = r_str_prefix_all (text, white);
		} else {
			text = r_str_ansi_crop (foo,
				delta_x, delta_y, n->w + delta_x, n->h - 2 + delta_y);
		}
		if (text) {
			W (text);
			free (text);
		} else {
			W (n->text);
		}
		free (foo);
	} else {
		char *text = r_str_ansi_crop (n->text,
			delta_x, delta_y, n->w+5, n->h - delta_y);
		if (text) {
			W (text);
			free (text);
		} else {
			W (n->text);
		}
	}
	if (cur) {
		B1 (n->x, n->y, n->w, n->h);
	} else {
		B (n->x, n->y, n->w, n->h);
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

	can->sx = 0;
	can->sy = 0;
	for (i=j=0; panels[i].text; i++) {
		switch (panels[i].type) {
		case PANEL_TYPE_FLOAT:
			panels[i].w = r_str_bounds (
				panels[i].text,
				&panels[i].h);
			panels[i].h += 4;
			break;
		case PANEL_TYPE_FRAME:
			if (j == 0) {
				panels[i].x = 0;
				panels[i].y = 1;
				if (panels[j+1].text) {
					panels[i].w = colpos+1;
				} else {
					panels[i].w = w;
				}
				panels[i].h = h-1;
			} else {
				int ph = ((h - 1) / (n_panels - 2));
				panels[i].x = colpos;
				panels[i].y = 1 + (ph * (j - 1));
				panels[i].w = w-colpos;
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
	}
}

static void addPanelFrame (const char *title, const char *cmd, ut64 addr) {
	int i = n_panels;
	if (!panels) {
		panels = calloc (sizeof (Panel), LIMIT);
		if (!panels) return;
		panels[0].text = strdup ("");
		panels[0].addr = addr;
		panels[0].type = PANEL_TYPE_FLOAT;
		i = n_panels = 1;
		menu_pos = 0;
	}
	panels[i].text = strdup (title);
	panels[i].cmd = r_str_newf (cmd);
	panels[i].addr = addr;
	panels[i].type = PANEL_TYPE_FRAME;
	panels[i+1].text = NULL;
	n_panels++;
}

static int bbPanels (RCore *core, Panel **n) {
	//panels = NULL;
	addPanelFrame ("Disassembly", "pd 128", 0);
	addPanelFrame ("Symbols", "isq", 0);
	addPanelFrame ("Stack", "px 256@r:SP", 0);
	addPanelFrame ("Registers", "dr=", 0);
	addPanelFrame ("RegisterRefs", "drr", 0);
	curnode = 0;
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
	r_cons_canvas_clear (can);
	r_cons_flush ();
	if (panels) {
		if (menu_y > 0) {
			panels[menu_pos].x = menu_x * 6;
		} else {
			panels[menu_pos].x = w;
		}
		panels[menu_pos].y = 1;
		free (panels[menu_pos].text);
		panels[menu_pos].text = calloc (1, 1024); //r_str_newf ("%d", menu_y);
		int maxsub = 0;
		for (i=0; menus_sub[i]; i++) { maxsub = i; }
		if (menu_x >= 0 && menu_x <= maxsub && menus_sub[menu_x]) {
			for (j = 0; menus_sub[menu_x][j]; j++) {
				if (menu_y-1 == j) {
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
				Panel_print (can, &panels[i], i==curnode);
			}
		}
	}

	if (menu_y) {
		curnode = menu_pos;
	}
	// redraw current node to make it appear on top
	if (curnode >= 0) {
		Panel_print (can, &panels[curnode], 1);
	}
	Panel_print (can, &panels[menu_pos], menu_y);

	(void)G (-can->sx, -can->sy);
	title[0] = 0;
	if (curnode == 0) {
		strcpy (title, "> ");
	}
	for (i = 0; menus[i]; i++) {
		if (menu_x == i) {
			snprintf (str, sizeof (title)-1, "%s[%s]"Color_RESET, color, menus[i]);
		} else {
			snprintf (str, sizeof (title)-1, "%s %s "Color_RESET, color, menus[i]);
		}
		strcat (title, str);
	}
	if (curnode == 0) {
		W (Color_BLUE);
		W (title);
		W (Color_RESET);
	} else {
		W (Color_RESET);
		W (title);
	}

	snprintf (title, sizeof (title)-1,
		"[0x%08"PFMT64x"]", core->offset);
	(void)G (-can->sx + w-strlen (title), -can->sy);
	W (title);

	r_cons_canvas_print (can);
	r_cons_flush ();
}

static void reloadPanels(RCore *core) {
	//W("HELLO WORLD");
	Layout_run (panels);
}

static int havePanel(const char *s) {
	int i;
	if (!panels || !panels[0].text) {
		return 0;
	}
	// add new panel for testing
	for (i = 1; panels[i].text; i++) {
		if (!strcmp (panels[i].text , s)) {
			return 1;
		}
	}
	return 0;
}

R_API int r_core_visual_panels(RCore *core) {
#define OS_INIT() ostack.size = 0; ostack.panels[0] = 0;
#define OS_PUSH(x) if (ostack.size<LIMIT) {ostack.panels[++ostack.size]=x;}
#define OS_POP() ((ostack.size>0)? ostack.panels[--ostack.size]:0)
	int okey, key, wheel;
	int w, h;
	int asm_comments = 0;
	int asm_bytes = 0;
	int have_utf8 = 0;
	n_panels = 0;
	panels = NULL;
	callgraph = 0;
	_core = core;

	OS_INIT();
	w = r_cons_get_size (&h);
	can = r_cons_canvas_new (w, h);
	if (!can) return false;
	can->linemode = 1;
	can->color = r_config_get_i (core->config, "scr.color");
	if (!can) {
		eprintf ("Cannot create RCons.canvas context\n");
		return false;
	}
	n_panels = bbPanels (core, NULL);
	if (!panels) {
		r_config_set_i (core->config, "scr.color", can->color);
		free (can);
		return false;
	}

	if (w < 140) {
		COLW = w / 3;
	}

	reloadPanels (core);

	asm_comments = r_config_get_i (core->config, "asm.comments");
	have_utf8 = r_config_get_i (core->config, "scr.utf8");
	r_config_set_i (core->config, "asm.comments", 0);
	asm_bytes = r_config_get_i (core->config, "asm.bytes");
	r_config_set_i (core->config, "asm.bytes", 0);
	r_config_set_i (core->config, "scr.utf8", 0);

repeat:
	core->cons->event_data = core;
	core->cons->event_resize = \
		(RConsEvent)r_core_panels_refresh;
	w = r_cons_get_size (&h);
	Layout_run (panels);
	r_core_panels_refresh (core);
	wheel = r_config_get_i (core->config, "scr.wheel");
	if (wheel)
		r_cons_enable_mouse (true);

	// r_core_graph_inputhandle()
	okey = r_cons_readchar ();
	key = r_cons_arrow_to_hjkl (okey);

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
			//r_core_seek (core, r_num_math (core->num, "entry0"), 1);
		} else {
			r_core_cmd0 (core, "s entry0; px");
		}
		break;
	case ' ':
	case '\r':
	case '\n':
		if (curnode == 0 && menu_y) {
			const char *action = menus_sub[menu_x][menu_y-1];
			if (strstr (action, "New")) {
				addPanelFrame ("New files", "o", 0);
			} else if (strstr (action, "Open")) {
				char *res = r_cons_input ("open file: ");
				if (res) {
					if (*res)
						r_core_cmdf (core, "o %s", res);
					free (res);
				}
			} else if (strstr (action, "Info")) {
				addPanelFrame ("Info", "i", 0);
			} else if (strstr (action, "Database")) {
				addPanelFrame ("Database", "k ***", 0);
			} else if (strstr (action, "Registers")) {
				if (!havePanel ("Registers")) {
					addPanelFrame ("Registers", "dr=", core->offset);
				}
			} else if (strstr (action, "About")) {
				char *s = r_core_cmd_str (core, "?V");
				r_cons_message (s);
				free (s);
			} else if (strstr (action, "Hexdump")) {
				addPanelFrame ("Hexdump", "px 512", core->offset);
			} else if (strstr (action, "Disassembly")) {
				addPanelFrame ("Disassembly", "pd 128", core->offset);
			} else if (strstr (action, "Functions")) {
				addPanelFrame ("Functions", "afl", core->offset);
			} else if (strstr (action, "Comments")) {
				addPanelFrame ("Comments", "CC", core->offset);
			} else if (strstr (action, "Entropy")) {
				addPanelFrame ("Entropy", "p=e", core->offset);
			} else if (strstr (action, "Function")) {
				r_core_cmdf (core, "af");
			} else if (strstr (action, "DRX")) {
				addPanelFrame ("DRX", "drx", core->offset);
			} else if (strstr (action, "Program")) {
				r_core_cmdf (core, "aaa");
			} else if (strstr (action, "Calls")) {
				r_core_cmdf (core, "aac");
			} else if (strstr (action, "ROP")) {
				char *res = r_cons_input ("rop grep: ");
				if (res) {
					r_core_cmdf (core, "\"/R %s\"", res);
					free (res);
				}
			} else if (strstr (action, "String")) {
				char *res = r_cons_input ("search string: ");
				if (res) {
					r_core_cmdf (core, "\"/ %s\"", res);
					free (res);
				}
			} else if (strstr (action, "Hexpairs")) {
				char *res = r_cons_input ("search hexpairs: ");
				if (res) {
					r_core_cmdf (core, "\"/x %s\"", res);
					free (res);
				}
			} else if (strstr (action, "Code")) {
				char *res = r_cons_input ("search code: ");
				if (res) {
					r_core_cmdf (core, "\"/c %s\"", res);
					free (res);
				}
			} else if (strstr (action, "Copy")) {
				char *res = r_cons_input ("How many bytes? ");
				if (res) {
					r_core_cmdf (core, "\"y %s\"", res);
					free (res);
				}
			} else if (strstr (action, "Write String")) {
				char *res = r_cons_input ("insert string: ");
				if (res) {
					r_core_cmdf (core, "\"w %s\"", res);
					free (res);
				}
			} else if (strstr (action, "Write Value")) {
				char *res = r_cons_input ("insert number: ");
				if (res) {
					r_core_cmdf (core, "\"wv %s\"", res);
					free (res);
				}
			} else if (strstr (action, "Write Hex")) {
				char *res = r_cons_input ("insert hexpairs: ");
				if (res) {
					r_core_cmdf (core, "\"wx %s\"", res);
					free (res);
				}
			} else if (strstr (action, "Calculator")) {
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
			} else if (strstr (action, "Assemble")) {
				r_core_visual_asm (core, core->offset);
			} else if (strstr (action, "Sections")) {
				addPanelFrame ("Sections", "iSq", 0);
			} else if (strstr (action, "Close")) {
				r_core_cmd0 (core, "o-*");
			} else if (strstr (action, "Strings")) {
				addPanelFrame ("Strings", "izq", 0);
			} else if (strstr (action, "Maps")) {
				addPanelFrame ("Maps", "dm", 0);
			} else if (strstr (action, "Backtrace")) {
				addPanelFrame ("Backtrace", "dbt", 0);
			} else if (strstr (action, "Breakpoints")) {
				addPanelFrame ("Breakpoints", "db", 0);
			} else if (strstr (action, "Symbols")) {
				addPanelFrame ("Symbols", "isq", 0);
			} else if (strstr (action, "Imports")) {
				addPanelFrame ("Imports", "iiq", 0);
			} else if (strstr (action, "Paste")) {
				r_core_cmd0 (core, "yy");
			} else if (strstr (action, "Clipboard")) {
				addPanelFrame ("Clipboard", "yx", 0);
			} else if (strstr (action, "io.cache")) {
				r_core_cmd0 (core, "e!io.cache");
			} else if (strstr (action, "Fill")) {
				char *s = r_cons_input ("Fill with: ");
				r_core_cmdf (core, "wow %s", s);
				free (s);
			} else if (strstr (action, "References")) {
				r_core_cmdf (core, "aar");
			} else if (strstr (action, "FcnInfo")) {
				addPanelFrame ("FcnInfo", "afi", 0);
			} else if (strstr (action, "Graph")) {
				r_core_visual_graph (core, NULL, NULL, true);
			//	addPanelFrame ("Graph", "agf", 0);
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
				r_cons_message ("Copyright 2006-2015 - pancake - LGPL");
			} else if (strstr (action, "Fortune")) {
				char *s = r_core_cmd_str (core, "fo");
				r_cons_message (s);
				free (s);
			} else if (strstr (action, "Commands")) {
				r_core_cmd0 (core, "?;?@?;?$?;???");
				r_cons_any_key(NULL);
			} else if (strstr (action, "Colors")) {
				r_core_cmd0 (core, "e!scr.color");
			} else if (strstr (action, "Quit")) {
				goto beach;
			}
		} else {
			if (curnode>0) {
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
		" :    - run r2 command in prompt\n"
		" _    - start the hud input mode\n"
		" ?    - show this help\n"
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
			r_core_cmd0 (core, "ds;.dr*"); //;sr PC");
		} else {
			r_core_cmd0 (core, "aes;.ar*");
		}
		break;
	case 'S':
		if (r_config_get_i (core->config, "cfg.debug")) {
			r_core_cmd0 (core, "dso;.dr*"); //;sr PC");
		} else {
			r_core_cmd0 (core, "aeso;.ar*");
		}
		break;
	case ':':
		core->vmode = false;
		r_core_visual_prompt_input (core);
		core->vmode = true;
		break;
	case 'C':
		can->color = !can->color;				//WTF
		//r_config_toggle (core->config, "scr.color");
		// refresh graph
	//	reloadPanels (core);
		break;
	case 'R':
		r_core_cmd0 (core, "ecr");
		break;
	case 'j':
		if (curnode==0) {
			if (panels[curnode].type == PANEL_TYPE_FLOAT) {
				if (menus_sub[menu_x][menu_y])
					menu_y ++;
			}
		} else {
			if (curnode == 1) {
				r_core_cmd0 (core, "s+$l");
			} else {
				panels[curnode].sy ++;
			}
		}
		break;
	case 'k':
		if (curnode==0) {
			if (panels[curnode].type == PANEL_TYPE_FLOAT) {
				menu_y --;
				if (menu_y < 0)
					menu_y = 0;
			}
		} else {
			if (curnode == 1) {
				r_core_cmd0 (core, "s-8");
			} else {
				panels[curnode].sy --;
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
			char *name = r_cons_input ("Name: ");
			char *cmd = r_cons_input ("Command: ");
			if (name && *name && cmd && *cmd) {
				addPanelFrame (name, cmd, 0);
			}
			free (name);
			free (cmd);
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
		if (COLW<0)
			COLW = 0;
		break;
	case 'h':
		if (curnode == 0) {
			if (menu_x) {
				menu_x --;
				menu_y = menu_y?1:0;
				r_core_panels_refresh (core);
			}
		} else {
			panels[curnode].sx ++;
		}
		break;
	case 'l':
		if (curnode == 0) {
			if (menus[menu_x + 1]) {
				menu_x ++;
				menu_y = menu_y?1:0;
				r_core_panels_refresh (core);
			}
		} else {
			panels[curnode].sx --;
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
				r_cons_message("Not in a function. Type 'df' to define it here");
				break;
			} else if (r_list_empty (fun->bbs)) {
				r_cons_message("No basic blocks in this function. You may want to use 'afb+'.");
				break;
			}
			ocolor = r_config_get_i (core->config, "scr.color");
			r_core_visual_graph (core, NULL, NULL, true);
			r_config_set_i (core->config, "scr.color", ocolor);
		}
		break;
	case '!':
	case 'q':
	case -1: // EOF
		if (menu_y>0) {
			menu_y = 0;
		} else {
			goto beach;
		}
		break;
#if 0
	case 27: // ESC
		if (r_cons_readchar () == 91) {
			if (r_cons_readchar () == 90) {
			}
		}
		break;
#endif
	default:
		//eprintf ("Key %d\n", key);
		//sleep (1);
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

/* Copyright radare2 2014-2015 - Author: pancake */

// pls move the typedefs into roons and rename it -> RConsPanel

#include <r_core.h>

typedef struct {
	int x;
	int y;
	int w;
	int h;
	int depth;
	int type;
	ut64 addr;
	char *cmd;
	char *text;
} Panel;

#define PANEL_TYPE_FRAME 0
#define PANEL_TYPE_DIALOG 1
#define PANEL_TYPE_FLOAT 2

static int COLW = 40;
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
static int instep = 0;

static int menu_x = 0;
static int menu_y = 0;

static const char *menus[] = {
	"File", "Edit", "View", "Tools", "Debug", "Analyze", "Help",
	NULL
};

static const char *menus_File[] = {
	"New", "Open", "Close", "Info", "Quit",
	NULL
};

static const char *menus_Edit[] = {
	"Copy", "Paste", "Insert", "Assemble", "Fill",
	NULL
};

static const char *menus_View[] = {
	"Hexdump", "Disassembly", "Entropy",
	NULL
};

static const char *menus_Tools[] = {
	"Assembler", "Calculator", "Shell",
	NULL
};

static const char *menus_Debug[] = {
	"Registers", "Breakpoints", "Watchpoints", "Maps",
	"Step", "Step Over", "Continue", "Cont until.",
	NULL
};

static const char *menus_Analyze[] = {
	"Function", "Program", "Calls", "Options",
	NULL
};

static const char *menus_Help[] = {
	"Commands", "License", "About",
	NULL
};

static const char **menus_sub[] = {
	menus_File,
	menus_Edit,
	menus_View,
	menus_Tools,
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
	int delta_x = 0;
	int delta_y = 0;

	if (!can)
		return;
	// clear
	F(n->x, n->y, n->w, n->h, ' ');
	if (n->type == PANEL_TYPE_FRAME) {
		if (cur) {
			//F (n->x,n->y, n->w, n->h, '.');
			snprintf (title, sizeof (title)-1,
				" [ %s ] ", n->text);
		} else {
			snprintf (title, sizeof (title)-1,
				"   %s   ", ""); //n->text);
		}
		if (G (n->x+1, n->y+1))
			W (title); // delta_x
	}
	(void)G (n->x+2+delta_x, n->y+2);
	//if (
// TODO: only refresh if n->refresh is set
// TODO: temporary crop depending on out of screen offsets
	if (n->cmd && *n->cmd) {
		char *foo = r_core_cmd_strf (_core, "%s", n->cmd);
		char *text = r_str_crop (foo, 
			delta_x, delta_y, n->w, n->h);
		if (text) {
			W (text);
			free (text);
		} else {
			W (n->text);
		}
		free (foo);
	} else {
		char *text = r_str_crop (n->text,
			delta_x, delta_y, n->w+5, n->h);
		if (text) {
			W (text);
			free (text);
		} else {
			W (n->text);
		}
	}
	if (G (n->x+1, n->y+1))
		W (title);
	// TODO: check if node is traced or not and hsow proper color
	// This info must be stored inside Panel* from RCore*
	if (cur) {
		B1 (n->x, n->y, n->w, n->h);
	} else {
		B (n->x, n->y, n->w, n->h);
	}
}

static void Layout_run(Panel *panels) {
	int h, w = r_cons_get_size (&h);
	int i, j;
	int colpos = w-COLW;

	can->sx = 0;
	can->sy = 0;

	n_panels = 0;
	for (i=0; panels[i].text; i++) {
		if (panels[i].type == PANEL_TYPE_FRAME)
			n_panels++;
	}
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
					panels[i].w = colpos;
				} else {
					panels[i].w = w;
				}
				panels[i].h = h-1;
			} else {
				int ph = ((h-1)/(n_panels-1));
				panels[i].x = colpos;
				panels[i].y = 1 + (ph*(j-1));
				panels[i].w = w-colpos;
				if (panels[i].w<0)
					panels[i].w = 0;
				panels[i].h = ph;
				if (!panels[i+1].text) {
					panels[i].h = h - panels[i].y;
				}
			}
			j++;
		}
	}
}

static int bbPanels (RCore *core, Panel **n) {
	int i;
	Panel *panels = calloc (sizeof (Panel), LIMIT); //(r_list_length (fcn->bbs)+1));
	if (!panels)
		return 0;
	i = 0;

	panels[i].text = strdup ("");
	panels[i].addr = core->offset;
	panels[i].type = PANEL_TYPE_FLOAT;
	menu_pos = i;
	i++;

	panels[i].text = strdup ("Disassembly");
	panels[i].cmd = r_str_newf ("pd $r-2");
	panels[i].addr = core->offset;
	panels[i].type = PANEL_TYPE_FRAME;
	i++;

	panels[i].text = strdup ("Symbols");
	panels[i].cmd = strdup ("isq");
	panels[i].addr = core->offset;
	panels[i].type = PANEL_TYPE_FRAME;
	i++;
	n_panels = 2;

	free (*n);
	*n = panels;
	panels[i].text = NULL;
	Layout_run (panels);
	return i;
}

// damn singletons.. there should be only one screen and therefor
// only one visual instance of the graph view. refactoring this
// into a struct makes the code to reference pointers unnecesarily
// we can look for a non-global solution here in the future if
// necessary
static void r_core_panels_refresh (RCore *core) {
	char title[128];
	int i, j, h, w = r_cons_get_size (&h);
	if (instep && core->io->debug) {
		r_core_cmd0 (core, "sr pc");
	}
	r_cons_clear00 ();
	if (!can) {
		return;
	}
	r_cons_canvas_resize (can, w, h);
	r_cons_canvas_clear (can);
	if (panels) {
		if (menu_y>0) {
			panels[menu_pos].x = menu_x * 6;
		} else {
			panels[menu_pos].x = w;
		}
		panels[menu_pos].y = 1;
		free (panels[menu_pos].text);
		panels[menu_pos].text = malloc(1024); //r_str_newf ("%d", menu_y);
		panels[menu_pos].text[0] = 0;
		int maxsub = 0;
		for (i=0; menus_sub[i]; i++) { maxsub = i; }
		if (menu_x >= 0 && menu_x <maxsub && menus_sub[menu_x]) {
			for (j = 0; menus_sub[menu_x][j]; j++) {
				if (menu_y-1 == j) {
					strcat (panels[menu_pos].text, "> ");
				} else {
					strcat (panels[menu_pos].text, "  ");
				}
				strcat (panels[menu_pos].text,
					menus_sub[menu_x][j]);
				strcat (panels[menu_pos].text, "        \n");
			}
		}
		for (i=0; panels[i].text; i++) {
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
	char str[128];
	title[0] = 0;
	for (i=0; menus[i]; i++) {
		if (menu_x == i) {
			snprintf (str, sizeof (title)-1, "[%s]", menus[i]);
		} else {
			snprintf (str, sizeof (title)-1, " %s ", menus[i]);
		}
		strcat (title, str);
	}
	W (title);

	snprintf (title, sizeof (title)-1,
		"[0x%08"PFMT64x"]", core->offset);
	(void)G (-can->sx + w-strlen (title), -can->sy);
	W (title);

	r_cons_canvas_print (can);
	r_cons_flush_nonewline ();
}

static void reloadPanels(RCore *core) {
	//W("HELLO WORLD");
	Layout_run (panels);
}

R_API int r_core_visual_panels(RCore *core) {
#define OS_INIT() ostack.size = 0; ostack.panels[0] = 0;
#define OS_PUSH(x) if (ostack.size<LIMIT) {ostack.panels[++ostack.size]=x;}
#define OS_POP() ((ostack.size>0)? ostack.panels[--ostack.size]:0)
	int okey, key, wheel;
	int w, h;
	int asm_comments = 0;
	int asm_bytes = 0;
	n_panels = 0;
	panels = NULL;
	callgraph = 0;
	_core = core;

	OS_INIT();
	w = r_cons_get_size (&h);
	can = r_cons_canvas_new (w, h);
	can->linemode = 1;
	can->color = r_config_get_i (core->config, "scr.color");
	// disable colors in disasm because canvas doesnt supports ansi text yet
	r_config_set_i (core->config, "scr.color", 0);
	//can->color = 0; 
	if (!can) {
		eprintf ("Cannot create RCons.canvas context\n");
		return R_FALSE;
	}
	n_panels = bbPanels (core, &panels);
	if (!panels) {
		r_config_set_i (core->config, "scr.color", can->color);
		free (can);
		return R_FALSE;
	}

	reloadPanels (core);

	asm_comments = r_config_get_i (core->config, "asm.comments");
	r_config_set_i (core->config, "asm.comments", 0);
	asm_bytes = r_config_get_i (core->config, "asm.bytes");
	r_config_set_i (core->config, "asm.bytes", 0);

repeat:
	core->cons->event_data = core;
	core->cons->event_resize = \
		(RConsEvent)r_core_panels_refresh;
	w = r_cons_get_size (&h);
	Layout_run (panels);
	r_core_panels_refresh (core);
	wheel = r_config_get_i (core->config, "scr.wheel");
	if (wheel)
		r_cons_enable_mouse (R_TRUE);

	// r_core_graph_inputhandle()
	okey = r_cons_readchar ();
	key = r_cons_arrow_to_hjkl (okey);

	switch (key) {
	case ' ':
	case '\n':
		if (menu_y) {
			const char *action = menus_sub[menu_x][menu_y-1];
			eprintf ("ACTION %s\n", action);
			if (strstr (action, "New")) {
				int i;
				// add new panel for testing
				for (i=0; panels[i].text; i++) {
					// find last panel
				}
				panels[i].text = strdup ("Test");
				panels[i].cmd = r_str_newf ("pxW $r-2");
				panels[i].addr = core->offset;
				panels[i].type = PANEL_TYPE_FRAME;
				i++;
				n_panels++;
				panels[i].text = NULL;
			}
			if (strstr (action, "Quit")) {
				goto beach;
			}
		}
		break;
	case '?':
		r_cons_clear00 ();
		r_cons_printf ("Visual Ascii Art Panels:\n"
		" !    run r2048 game\n"
		" .    - center graph to the current node\n"
		" :    - run r2 command in prompt\n"
		" hl   - toggle scr.color\n"
		" HL   - move vertical column split\n"
		" JK   - select prev/next panels\n"
		" jk   - scroll/select menu\n"
		" q    - quit, back to visual mode\n"
		);
		r_cons_flush ();
		r_cons_any_key (NULL);
		break;
	case ':':
		core->vmode = R_FALSE;
		r_core_visual_prompt_input (core);
		core->vmode = R_TRUE;
		break;
	case 'C':
		can->color = !!!can->color;				//WTF
		//r_config_swap (core->config, "scr.color");
		// refresh graph
	//	reloadPanels (core);
		break;
	case '!':
		r_cons_2048 ();
		break;
	case 'j':
		if (panels[curnode].type == PANEL_TYPE_FLOAT) {
			if (menus_sub[menu_x][menu_y])
				menu_y ++;
		}
		break;
	case 'k':
		if (panels[curnode].type == PANEL_TYPE_FLOAT) {
			menu_y --;
			if (menu_y<0)
				menu_y = 0;
		}
		break;
	case 'J':
		curnode++;
		if (!panels[curnode].text) {
			curnode--;
		}
		break;
	case 'K':
		curnode--;
		if (curnode<0)
			curnode = 0;
		break;
	case 'H':
		COLW += 4;
		break;
	case 'L':
		COLW -= 4;
		if (COLW<0)
			COLW=0;
		break;
	case 'h':
		if (menu_x) {
			menu_x --;
			menu_y = menu_y?1:0;
		}
		break;
	case 'l':
		if (menus[menu_x + 1]) {
			menu_x ++;
			menu_y = menu_y?1:0;
		}
		break;
	case 'q':
	case -1: // EOF
		goto beach;
	case 27: // ESC
		if (r_cons_readchar () == 91) {
			if (r_cons_readchar () == 90) {
			}
		}
		break;
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
	return R_TRUE;
}

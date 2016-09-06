/* radare - LGPL - Copyright 2013-2016 - pancake, sghctoma */

#include <r_cons.h>

R_API void r_cons_pal_free () {
	int i;
	RCons *cons = r_cons_singleton ();
	for (i = 0; i < R_CONS_PALETTE_LIST_SIZE; i++) {
		if (cons->pal.list[i]) R_FREE (cons->pal.list[i]);
	}
}

R_API void r_cons_pal_init (const char *foo) {
	RCons *cons = r_cons_singleton ();
	memset (&cons->pal, 0, sizeof (cons->pal));
	cons->pal.b0x00 = Color_GREEN;
	cons->pal.b0x7f = Color_CYAN;
	cons->pal.b0xff = Color_RED;
	cons->pal.args = Color_YELLOW;
	cons->pal.bin = Color_CYAN;
	cons->pal.btext = Color_YELLOW;
	cons->pal.call = Color_BGREEN;
	cons->pal.cjmp = Color_GREEN;
	cons->pal.cmp = Color_CYAN;
	cons->pal.comment = Color_RED;
	cons->pal.creg = Color_CYAN;
	cons->pal.flag = Color_CYAN;
	cons->pal.fline = Color_CYAN;
	cons->pal.floc = Color_CYAN;
	cons->pal.flow = Color_CYAN;
	cons->pal.fname = Color_RED;
	cons->pal.help = Color_GREEN;
	cons->pal.input = Color_WHITE;
	cons->pal.invalid = Color_BRED;
	cons->pal.jmp = Color_GREEN;
	cons->pal.label = Color_CYAN;
	cons->pal.math = Color_YELLOW;
	cons->pal.mov = Color_WHITE;
	cons->pal.nop = Color_BLUE;
	cons->pal.num = Color_YELLOW;
	cons->pal.offset = Color_GREEN;
	cons->pal.other = Color_WHITE;
	cons->pal.pop = Color_BMAGENTA;
	cons->pal.prompt = Color_YELLOW;
	cons->pal.push = Color_MAGENTA;
	cons->pal.crypto = Color_BGBLUE;
	cons->pal.reg = Color_CYAN;
	cons->pal.reset = Color_RESET;
	cons->pal.ret = Color_RED;
	cons->pal.swi = Color_MAGENTA;
	cons->pal.trap = Color_BRED;

	cons->pal.ai_read = Color_GREEN;
	cons->pal.ai_write = Color_BLUE;
	cons->pal.ai_exec = Color_RED;
	cons->pal.ai_seq = Color_MAGENTA;
	cons->pal.ai_ascii = Color_YELLOW;

	cons->pal.gui_cflow = Color_YELLOW;
	cons->pal.gui_dataoffset = Color_YELLOW;
	cons->pal.gui_background = Color_BLACK;
	cons->pal.gui_alt_background = Color_WHITE;
	cons->pal.gui_border = Color_BLACK;

	cons->pal.graph_box = Color_RESET;
	cons->pal.graph_box2 = Color_BLUE;
	cons->pal.graph_box3 = Color_MAGENTA;
	cons->pal.graph_box4 = Color_GRAY;
	cons->pal.graph_true = Color_GREEN;
	cons->pal.graph_false = Color_RED;
	cons->pal.graph_trufae = Color_BLUE; // single jump
	cons->pal.graph_traced = Color_YELLOW;
	cons->pal.graph_current = Color_BLUE;

	r_cons_pal_free ();
	cons->pal.list[0] = strdup (Color_RED);
	cons->pal.list[1] = strdup (Color_YELLOW);
	cons->pal.list[2] = strdup (Color_BGREEN);
	cons->pal.list[3] = strdup (Color_CYAN);
	cons->pal.list[4] = strdup (Color_MAGENTA);
	cons->pal.list[5] = strdup (Color_GRAY);
	cons->pal.list[6] = strdup (Color_BLUE);
	cons->pal.list[7] = strdup (Color_GREEN);
}

struct {
	const char *name;
	const char *code;
	const char *bgcode;
} colors[] = {
	{ "black",    Color_BLACK,    Color_BGBLACK },
	{ "red",      Color_RED,      Color_BGRED },
	{ "bred",     Color_BRED,     Color_BGRED },
	{ "white",    Color_WHITE,    Color_BGWHITE },
	{ "green",    Color_GREEN,    Color_BGGREEN },
	{ "bgreen",   Color_BGREEN,   Color_BGGREEN },
	{ "magenta",  Color_MAGENTA,  Color_BGMAGENTA },
	{ "bmagenta", Color_BMAGENTA, Color_BGMAGENTA },
	{ "yellow",   Color_YELLOW,   Color_BGYELLOW },
	{ "byellow",  Color_BYELLOW,  Color_BGYELLOW },
	{ "cyan",     Color_CYAN,     Color_BGCYAN },
	{ "bcyan",    Color_BCYAN,    Color_BGCYAN },
	{ "blue",     Color_BLUE,     Color_BGBLUE },
	{ "bblue",    Color_BBLUE,    Color_BGBLUE },
	{ "gray",     Color_GRAY,     Color_BGGRAY },
	{ "bgray",    Color_BGRAY,    Color_BGGRAY },
	{ "none",     Color_RESET,    Color_RESET },
	{ NULL, NULL, NULL }
};

static inline ut8 rgbnum (const char ch1, const char ch2) {
	ut8 r = 0, r2 = 0;
	r_hex_to_byte (&r, ch1);
	r_hex_to_byte (&r2, ch2);
	return r << 4 | r2;
}

R_API void r_cons_pal_random () {
	RCons *cons = r_cons_singleton ();
	ut8 r, g, b;
	char val[32];
	const char *k;
	int i;
	for (i = 0; ; i++) {
		k = r_cons_pal_get_i (i);
		if (!k) break;
		if (cons->truecolor > 0) {
			r = r_num_rand (0xff);
			g = r_num_rand (0xff);
			b = r_num_rand (0xff);
			sprintf (val, "rgb:%02x%02x%02x", r, g, b);
			r_cons_pal_set (k, val);
		} else {
			char *s = r_cons_color_random_string (0);
			if (s) {
				r_cons_pal_set (k, s);
				free (s);
			} else {
				r_cons_pal_set (k, "red");
			}
		}
	}
	for (i = 0; i < R_CONS_PALETTE_LIST_SIZE; i++) {
		if (cons->pal.list[i]) R_FREE (cons->pal.list[i]);
		cons->pal.list[i] = r_cons_color_random (0);
	}
}

R_API char *r_cons_pal_parse (const char *str) {
	int i;
	ut8 r, g, b;
	char out[128];
	char *s = strdup (str);
	if (!s) return NULL;
	char *p = strchr (s + 1, ' ');
	out[0] = 0;
	if (p) *p++ = 0;
	if (!strcmp (str, "random")) {
		free (s);
		return r_cons_color_random (0);
	}
	if (!strncmp (s, "#", 1)) {
		if (strlen (s) == 7) {
#define C(x) (x >> 4)
			int R, G, B;
			sscanf (s, "%02x%02x%02x", &R, &G, &B);
			r_cons_rgb_str (out, C(R), C(G), C(B), 0);
		} else {
			eprintf ("Invalid html color code\n");
		}
	} else if (!strncmp (s, "rgb:", 4)) {
		if (strlen (s) == 7) {
			r = rgbnum (s[4], '0');
			g = rgbnum (s[5], '0');
			b = rgbnum (s[6], '0');
			r_cons_rgb_str (out, r, g, b, 0);
		} else if (strlen (s) == 10) {
			r = rgbnum (s[4], s[5]);
			g = rgbnum (s[6], s[7]);
			b = rgbnum (s[8], s[9]);
			r_cons_rgb_str (out, r, g, b, 0);
		}
	}
	if (p && !strncmp (p, "rgb:", 4)) {
		if (strlen (s) == 7) {
			r = rgbnum (p[4], '0');
			g = rgbnum (p[5], '0');
			b = rgbnum (p[6], '0');
			r_cons_rgb_str (out + strlen (out), r, g, b, 1);
		} else if (strlen (s) == 10) {
			r = rgbnum (p[4], p[5]);
			g = rgbnum (p[6], p[7]);
			b = rgbnum (p[8], p[9]);
			r_cons_rgb_str (out + strlen (out), r, g, b, 1);
		}
	}
	for (i = 0; colors[i].name; i++) {
		if (!strcmp (s, colors[i].name)) {
			strncat (out, colors[i].code,
				sizeof (out) - strlen (out) - 1);
		}
		if (p && !strcmp (p, colors[i].name)) {
			strncat (out, colors[i].bgcode,
				sizeof (out) - strlen (out) - 1);
		}
	}
	free (s);
	return *out ? strdup (out) : NULL;
}

static struct {
	const char *name;
	int off;
} keys[] = {
	{ "comment", r_offsetof (RConsPalette, comment) },
	{ "args", r_offsetof (RConsPalette, args) },
	{ "fname", r_offsetof (RConsPalette, fname) },
	{ "floc", r_offsetof (RConsPalette, floc) },
	{ "fline", r_offsetof (RConsPalette, fline) },
	{ "flag", r_offsetof (RConsPalette, flag) },
	{ "label", r_offsetof (RConsPalette, label) },
	{ "help", r_offsetof (RConsPalette, help) },
	{ "flow", r_offsetof (RConsPalette, flow) },
	{ "prompt", r_offsetof (RConsPalette, prompt) },
	{ "offset", r_offsetof (RConsPalette, offset) },
	{ "input", r_offsetof (RConsPalette, input) },
	{ "invalid", r_offsetof (RConsPalette, invalid) },
	{ "other", r_offsetof (RConsPalette, other) },
	{ "b0x00", r_offsetof (RConsPalette, b0x00) },
	{ "b0x7f", r_offsetof (RConsPalette, b0x7f) },
	{ "b0xff", r_offsetof (RConsPalette, b0xff) },
	{ "math", r_offsetof (RConsPalette, math) },
	{ "bin", r_offsetof (RConsPalette, bin) },
	{ "btext", r_offsetof (RConsPalette, btext) },
	{ "push",  r_offsetof (RConsPalette, push) },
	{ "pop", r_offsetof (RConsPalette, pop) },
	{ "crypto", r_offsetof (RConsPalette, crypto) },
	{ "jmp", r_offsetof (RConsPalette, jmp) },
	{ "cjmp", r_offsetof (RConsPalette, cjmp) },
	{ "call", r_offsetof (RConsPalette, call) },
	{ "nop", r_offsetof (RConsPalette, nop) },
	{ "ret", r_offsetof (RConsPalette, ret) },
	{ "trap", r_offsetof (RConsPalette, trap) },
	{ "swi", r_offsetof (RConsPalette, swi) },
	{ "cmp", r_offsetof (RConsPalette, cmp) },
	{ "reg", r_offsetof (RConsPalette, reg) },
	{ "creg", r_offsetof (RConsPalette, creg) },
	{ "num", r_offsetof (RConsPalette, num) },
	{ "mov", r_offsetof (RConsPalette, mov) },

	{ "ai.read", r_offsetof (RConsPalette, ai_read) },
	{ "ai.write", r_offsetof (RConsPalette, ai_write) },
	{ "ai.exec", r_offsetof (RConsPalette, ai_exec) },
	{ "ai.seq", r_offsetof (RConsPalette, ai_seq) },
	{ "ai.ascii", r_offsetof (RConsPalette, ai_ascii) },

	{ "graph.box", r_offsetof (RConsPalette, graph_box) },
	{ "graph.box2", r_offsetof (RConsPalette, graph_box2) },
	{ "graph.box3", r_offsetof (RConsPalette, graph_box3) },
	{ "graph.box4", r_offsetof (RConsPalette, graph_box4) },
	{ "graph.true", r_offsetof (RConsPalette, graph_true) },
	{ "graph.false", r_offsetof (RConsPalette, graph_false) },
	{ "graph.trufae", r_offsetof (RConsPalette, graph_trufae) },
	{ "graph.current", r_offsetof (RConsPalette, graph_current) },
	{ "graph.traced", r_offsetof (RConsPalette, graph_traced) },

	{ "gui.cflow", r_offsetof (RConsPalette, gui_cflow) },
	{ "gui.dataoffset", r_offsetof (RConsPalette, gui_dataoffset) },
	{ "gui.background", r_offsetof (RConsPalette, gui_background) },
	{ "gui.alt_background", r_offsetof (RConsPalette, gui_alt_background) },
	{ "gui.border", r_offsetof (RConsPalette, gui_border) },
	{ NULL, 0 }
};

static void r_cons_pal_show_gs () {
	int i, n;
	r_cons_print ("\nGreyscale:\n");
	for (i = 0x08, n = 0;  i <= 0xee; i += 0xa) {
		char fg[32], bg[32];

		if (i < 0x76) strcpy (fg, Color_WHITE);
		else strcpy (fg, Color_BLACK);
		r_cons_rgb_str (bg, i, i, i, 1);
		r_cons_printf ("%s%s rgb:%02x%02x%02x "Color_RESET,
			fg, bg, i, i, i);
		if (n++ == 5) {
			n = 0;
			r_cons_newline ();
		}
	}
}

static void r_cons_pal_show_256 () {
	int r, g, b;
	r_cons_print ("\n\nXTerm colors:\n");
	for (r = 0x00; r <= 0xff; r += 0x28) {
		if (r == 0x28) {
			r = 0x5f;
		}
		for (b = 0x00; b <= 0xff; b += 0x28) {
			if (b == 0x28) {
				b = 0x5f;
			}
			for (g = 0x00; g <= 0xff; g += 0x28) {
				char fg[32], bg[32];
				if (g == 0x28) {
					g = 0x5f;
				}
				if ((r <= 0x5f) && (g <= 0x5f)) {
					strcpy (fg, Color_WHITE);
				} else {
					strcpy (fg, Color_BLACK);
				}
				r_cons_rgb_str (bg, r, g, b, 1);
				r_cons_printf ("%s%s rgb:%02x%02x%02x "
					Color_RESET, fg, bg, r, g, b);
				if (g == 0xff) {
					r_cons_newline ();
				}
			}
		}
	}
}

static void r_cons_pal_show_rgb () {
	const int inc = 3;
	int i, j, k, n = 0;
	r_cons_print ("\n\nRGB:\n");
	for (i = n = 0; i <= 0xf; i += inc) {
		for (k = 0; k <= 0xf; k += inc) {
			for (j = 0; j <= 0xf; j += inc) {
				char fg[32], bg[32];
				int r = i * 16;
				int g = j * 16;
				int b = k * 16;
				strcpy (fg, ((i < 6) && (j < 5))
					? Color_WHITE: Color_BLACK);
				r_cons_rgb_str (bg, r, g, b, 1);
				r_cons_printf ("%s%s rgb:%02x%02x%02x "
					Color_RESET, fg, bg, r, g, b);
				//if (n++==7) {
				if (n ++== 5) {
					n = 0;
					r_cons_newline ();
				}
			}
		}
	}
}

R_API void r_cons_pal_show () {
	int i;
	for (i = 0; colors[i].name; i++) {
		r_cons_printf ("%s%s__"Color_RESET" %s\n",
			colors[i].code,
			colors[i].bgcode,
			colors[i].name);
	}
	switch (r_cons_singleton ()->truecolor) {
	case 1: // 256 color palette
		r_cons_pal_show_gs ();
		r_cons_pal_show_256 ();
		break;
	case 2: // 16M
		r_cons_pal_show_gs ();
		r_cons_pal_show_rgb ();
		break;
	}
}

R_API const char *r_cons_pal_get_color (int n) {
	RConsPalette *pal = & (r_cons_singleton ()->pal);
	ut8 *p = (ut8*)pal;
	int i;
	for (i = 0; keys[i].name; i++) {
		if (i >= n) {
			const char **color = (const char**) (p + keys[i].off);
			color = (const char**)*color;
			return (const char *)color;
		}
	}
	return NULL;
}

R_API void r_cons_pal_list (int rad, const char *arg) {
	RConsPalette *pal = & (r_cons_singleton ()->pal);
	ut8 r, g, b, *p = (ut8*)pal;
	char *name, **color, rgbstr[32];
	const char *hasnext;
	int i;
	if (rad == 'j') r_cons_print ("{");
	for (i = 0; keys[i].name; i++) {
		color = (char**) (p + keys[i].off);
		switch (rad) {
		case 'j':
			r = g = b = 0;
			r_cons_rgb_parse (*color, &r, &g, &b, NULL);
			hasnext = (keys[i + 1].name) ? "," : "";
			r_cons_printf ("\"%s\":[%d,%d,%d]%s",
				keys[i].name, r, g, b, hasnext);
			break;
		case 'c': {
			const char *prefix = r_str_chop_ro (arg);
			if (!prefix) {
				prefix = "";
			}
			r = g = b = 0;
			r_cons_rgb_parse (*color, &r, &g, &b, NULL);
			hasnext = (keys[i + 1].name) ? "\n" : "";
			//Need to replace the '.' char because this is not
			//valid CSS
			char *name = strdup (keys[i].name);
			int j, len = strlen (name);
			for (j = 0; j < len; j++) {
				if (name[j] == '.') {
					name[j] = '_';
				}
			}
			r_cons_printf (".%s%s { color: rgb(%d, %d, %d); }%s",
				prefix, name, r, g, b, hasnext);
			free (name);
			}
			break;
		case 'h':
			r = g = b = 0;
			r_cons_rgb_parse (*color, &r, &g, &b, NULL);
			rgbstr[0] = 0;
			name = strdup (keys[i].name);
			r_str_replace_char (name, '.', '_');
			r_cons_printf (".%s { color:#%02x%02x%02x }\n",
				name, r, g, b);
			free (name);
			break;
		case '*':
		case 'r':
		case 1:
			r = g = b = 0;
			r_cons_rgb_parse (*color, &r, &g, &b, NULL);
			rgbstr[0] = 0;
			r_cons_rgb_str (rgbstr, r, g, b, 0);
			r_cons_printf ("ec %s rgb:%02x%02x%02x\n",
				keys[i].name, r, g, b);
			break;
		default:
			r_cons_printf (" %s##"Color_RESET"  %s\n", *color,
				keys[i].name);
		}
	}
	if (rad == 'j') r_cons_print ("}\n");
}

R_API int r_cons_pal_set(const char *key, const char *val) {
	int i;
	char **p;
	for (i = 0; keys[i].name; i++) {
		if (!strcmp (key, keys[i].name)) {
			p = (char **) ((char *)& (r_cons_singleton ()->pal) + keys[i].off);
			*p = r_cons_pal_parse (val);
			return true;
		}
	}
	return false;
}

R_API const char *r_cons_pal_get_i(int n) {
	int i;
	for (i = 0; i < n && keys[i].name; i++) {}
	if (i == n) return keys[n].name;
	return NULL;
}

R_API const char *r_cons_pal_get (const char *key) {
	int i;
	for (i = 0; keys[i].name; i++) {
		if (!strcmp (key, keys[i].name)) {
			char **p = (char **) ((char *)& (r_cons_singleton ()->pal) + keys[i].off);
			return p? *p: "";
		}
	}
	return "";
}

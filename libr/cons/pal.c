/* radare - LGPL - Copyright 2013-2014 - pancake */

#include <r_cons.h>

R_API void r_cons_pal_init(const char *foo) {
	RCons *cons = r_cons_singleton ();
	memset (&cons->pal, 0, sizeof (cons->pal));
	cons->pal.b0x00 = Color_GREEN;
	cons->pal.b0x7f = Color_CYAN;
	cons->pal.b0xff = Color_RED;
	cons->pal.args = Color_YELLOW;
	cons->pal.bin = Color_YELLOW;
	cons->pal.btext = Color_WHITE;
	cons->pal.call = Color_BGREEN;
	cons->pal.cjmp = Color_GREEN;
	cons->pal.cmp = Color_CYAN;
	cons->pal.comment = Color_CYAN; // blue
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
	cons->pal.gui_alt_background = Color_GRAY;
	cons->pal.gui_border = Color_BGGRAY;

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
	{ "white",    Color_WHITE,    Color_BGWHITE },
	{ "green",    Color_GREEN,    Color_BGGREEN },
	{ "magenta",  Color_MAGENTA,  Color_BGMAGENTA },
	{ "yellow",   Color_YELLOW,   Color_BGYELLOW },
	{ "cyan",     Color_CYAN,     Color_BGCYAN },
	{ "blue",     Color_BLUE,     Color_BGBLUE },
	{ "gray",     Color_GRAY,     Color_BGGRAY },
	{ "none",     Color_RESET,    Color_RESET },
	{ NULL, NULL, NULL }
};

static inline ut8 rgbnum (const char ch, const char cl) {
	ut8 h = 0;
	ut8 l = 0;
	r_hex_to_byte (&h, ch);
	r_hex_to_byte (&l, cl);
	return h*16+l;
}

R_API void r_cons_pal_random() {
	RCons *cons = r_cons_singleton ();
	ut8 r, g, b;
	char val[32];
	const char *k;
	int i;
	for (i=0;;i++) {
		k = r_cons_pal_get_i (i);
		if (!k) break;
		r = r_num_rand (0xf);
		g = r_num_rand (0xf);
		b = r_num_rand (0xf);
		sprintf (val, "rgb:%x%x%x", r, g, b);
		r_cons_pal_set (k, val);
	}
	for (i=0; i<R_CONS_PALETTE_LIST_SIZE; i++) {
		cons->pal.list[i] = r_cons_color_random (0);
	}
}

R_API char *r_cons_pal_parse(const char *str) {
	int i;
	ut8 r, g, b;
	char out[128];
	char *s = r_str_trim_head_tail (strdup (str));
	r_str_split (s, ' ');
	int length = strlen (s);
	out[0] = 0;
	if (!strcmp (str, "random")) {
		free (s);
		return r_cons_color_random (0);
	}
	if (!strncmp (s, "rgb:", 4)) {
		int correct = 0;
		if (length == 7) {
			r = rgbnum (s[4],s[4]);
			g = rgbnum (s[5],s[5]);
			b = rgbnum (s[6],s[6]);
			correct = 1;
		} else if (length == 10) {
			r = rgbnum(s[4],s[5]);
			g = rgbnum(s[6],s[7]);
			b = rgbnum(s[8],s[9]);
			correct = 1;
		}
		if (correct) {
			r_cons_rgb_str (out, r, g, b, 0);
		} else {
			eprintf ("Invalid rgb string (%s)\n", str);
		}
	}
	for (i=0; colors[i].name; i++) {
		if (!strcmp (s, colors[i].name))
			strcat (out, colors[i].code);
	}
	free (s);
	return *out? strdup (out): NULL;
}

static struct {
	const char *name;
	int off;
} keys[] = {
	{ "comment", r_offsetof (RConsPalette, comment) },
	{ "args", r_offsetof (RConsPalette, args) },
	{ "fname", r_offsetof (RConsPalette, fname) },
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

	{ "gui.cflow", r_offsetof (RConsPalette, gui_cflow) },
	{ "gui.dataoffset", r_offsetof (RConsPalette, gui_dataoffset) },
	{ "gui.background", r_offsetof (RConsPalette, gui_background) },
	{ "gui.alt_background", r_offsetof (RConsPalette, gui_alt_background) },
	{ "gui.border", r_offsetof (RConsPalette, gui_border) },
	{ NULL, 0 }
};

R_API void r_cons_pal_walk() {
	//RCons *c = r_cons_singleton ();
}

R_API void r_cons_pal_load(const char *sdbfile) {
}

R_API void r_cons_pal_save(const char *sdbfile) {
}

R_API void r_cons_pal_show () {
	const int inc = 3;
	int i, j, k, n = 0;
	for (i=0; colors[i].name; i++) {
		r_cons_printf ("%s%s__"Color_RESET" %s\n",
			colors[i].code,
			colors[i].bgcode,
			colors[i].name);
	}
	r_cons_printf ("\nGreyscale:\n");
	for (i=n=0; i<=0xf; i+=1) {
		char fg[32], bg[32];
		int r = i*16;
		if (i<5) strcpy (fg, Color_WHITE);
		else r_cons_rgb_str (fg, 0, 0, 0, 0);
		r_cons_rgb_str (bg, r, r, r, 1);
		r_cons_printf ("%s%s  rgb:%x%x%x  "
			Color_RESET, fg, bg, i, i, i);
		if (n++==5) {
			n = 0;
			r_cons_newline();
		}
	}
	r_cons_printf ("\n\nRGB:\n");
	for (i=n=0; i<=0xf; i+=inc) {
		for (k=0; k<=0xf; k+=inc) {
			for (j=0; j<=0xf; j+=inc) {
				char fg[32], bg[32];
				int r = i*16;
				int g = j*16;
				int b = k*16;
				if ((i<6) && (j<5) )
					strcpy (fg, Color_WHITE);
				//if (i<2 && j<6 && k<13)
				else r_cons_rgb_str (fg, 0, 0, 0, 0);
				r_cons_rgb_str (bg, r, g, b, 1);
				r_cons_printf ("%s%s  rgb:%x%x%x  "Color_RESET,
					fg, bg, i, j, k);
				//if (n++==7) {
				if (n++==5) {
					n = 0;
					r_cons_newline();
				}
			}
		}
	}
}

R_API const char *r_cons_pal_get_color(int n) {
	RConsPalette *pal = &(r_cons_singleton ()->pal);
	ut8 *p = (ut8*)pal;
	const char **color = NULL;
	int i;
	for (i=0; keys[i].name; i++) {
		if (i<n) continue;
		color = (const char**)(p + keys[i].off);
		color = (const char**)*color;
		return (const char *)color;
	}
	return NULL;
}

R_API void r_cons_pal_list (int rad) {
	RConsPalette *pal = &(r_cons_singleton ()->pal);
	ut8 *p = (ut8*)pal;
	ut8 r, g, b;
	char **color, rgbstr[32];
	const char *hasnext;
	int i;
	if (rad=='j')
		r_cons_printf ("{");
	for (i=0; keys[i].name; i++) {
		color = (char**)(p + keys[i].off);
		switch (rad) {
		case 'j':
			r = g = b = 0;
			r_cons_rgb_parse (*color, &r, &g, &b, NULL);
			hasnext = (keys[i+1].name)?",":"";
			r_cons_printf ("\"%s\":[%d,%d,%d]%s",
				keys[i].name, r, g, b, hasnext);
			break;
		case '*':
		case 'r':
		case 1:
			r = g = b = 0;
			r_cons_rgb_parse (*color, &r, &g, &b, NULL);
			rgbstr[0] = 0;
			r_cons_rgb_str (rgbstr, r, g, b, 0);
			// r >>= 4;
			// g >>= 4;
			// b >>= 4;
			r_cons_printf ("ec %s rgb:%02x%02x%02x\n",
				keys[i].name, r, g, b);
			break;
		default:
			r_cons_printf (" %s##"Color_RESET"  %s\n", *color, keys[i].name);
		}
	}
	if (rad=='j')
		r_cons_printf ("}\n");
}

R_API int r_cons_pal_set (const char *key, const char *val) {
	int i;
	char **p;
	for (i=0; keys[i].name; i++) {
		if (!strcmp (key, keys[i].name)) {
			p = (char **)((char *)&(r_cons_singleton()->pal) + keys[i].off);
//			free (*p);
			*p = r_cons_pal_parse (val);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API const char *r_cons_pal_get_i (int n) {
	int i;
	for (i=0; i<n && keys[i].name; i++) {}
	if (i==n) return keys[n].name;
	return NULL;
}

R_API const char *r_cons_pal_get (const char *key) {
	int i;
	char **p;
	for (i=0; keys[i].name; i++) {
		if (!strcmp (key, keys[i].name)) {
			p = (char **)((char *)&(r_cons_singleton()->pal) + keys[i].off);
			if (!p) return "";
			return *p;
		}
	}
	return "";
}

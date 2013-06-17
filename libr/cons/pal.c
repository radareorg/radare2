/* radare - LGPL - Copyright 2013 - pancake */

#include <r_cons.h>

R_API void r_cons_pal_init(const char *foo) {
	RCons *cons = r_cons_singleton ();
	memset (&cons->pal, 0, sizeof (cons->pal));
	cons->pal.prompt = Color_YELLOW;
	cons->pal.offset = Color_GREEN;
	cons->pal.input = Color_WHITE;
	cons->pal.comment = Color_CYAN;
	cons->pal.b0x00 = Color_GREEN;
	cons->pal.b0x7f = Color_YELLOW;
	cons->pal.b0xff = Color_RED;
	cons->pal.btext = Color_MAGENTA;
	cons->pal.push = Color_MAGENTA;
	cons->pal.pop = Color_BMAGENTA;
	cons->pal.nop = Color_BLUE;
	cons->pal.jmp = Color_GREEN;
	cons->pal.call = Color_BGREEN;
	cons->pal.cmp = Color_CYAN;
	cons->pal.swi = Color_MAGENTA;
	cons->pal.trap = Color_BRED;
	cons->pal.ret = Color_RED;
	cons->pal.reset = "\x1b[0m";
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
	{ NULL, NULL, NULL }
};

static inline ut8 rgbnum (const char ch) {
	ut8 r;
	r_hex_to_byte (&r, ch);
	return r*16;
}

R_API char *r_cons_pal_parse(const char *str) {
	int i;
	ut8 r, g, b;
	char out[128];
	char *s = strdup (str);
	char *p = strchr (s+1, ' ');
	out[0] = 0;
	if (p) *p++ = 0;
	if (!strncmp (s, "rgb:", 4)) {
		r = rgbnum (s[4]);
		g = rgbnum (s[5]);
		b = rgbnum (s[6]);
		r_cons_rgb_str (out, r, g, b, 0);
	}
	if (p && !strncmp (p, "rgb:", 4)) {
		r = rgbnum (p[4]);
		g = rgbnum (p[5]);
		b = rgbnum (p[6]);
		r_cons_rgb_str (out+strlen (out), r, g, b, 1);
	}
	for (i=0; colors[i].name; i++) {
		if (!strcmp (s, colors[i].name))
			strcat (out, colors[i].code);
		if (p && !strcmp (p, colors[i].name))
			strcat (out, colors[i].bgcode);
	}
	free (s);
	return *out? strdup (out): NULL;
}

struct {
	const char *name;
	int off;
} keys[] = {
	{ "comment", r_offsetof (RConsPalette, comment) },
	{ "prompt", r_offsetof (RConsPalette, prompt) },
	{ "offset", r_offsetof (RConsPalette, offset) },
	{ "input", r_offsetof (RConsPalette, input) },
	{ "other", r_offsetof (RConsPalette, other) },
	{ "b0x00", r_offsetof (RConsPalette, b0x00) },
	{ "b0x7f", r_offsetof (RConsPalette, b0x7f) },
	{ "b0xff", r_offsetof (RConsPalette, b0xff) },
	{ "btext", r_offsetof (RConsPalette, btext) },
	{ "math",  r_offsetof (RConsPalette, math) },
	{ "bin",  r_offsetof (RConsPalette, bin) },
	{ "push",  r_offsetof (RConsPalette, push) },
	{ "pop", r_offsetof (RConsPalette, pop) },
	{ "jmp", r_offsetof (RConsPalette, jmp) },
	{ "call", r_offsetof (RConsPalette, call) },
	{ "nop", r_offsetof (RConsPalette, nop) },
	{ "ret", r_offsetof (RConsPalette, ret) },
	{ "trap", r_offsetof (RConsPalette, trap) },
	{ "swi", r_offsetof (RConsPalette, swi) },
	{ "cmp", r_offsetof (RConsPalette, cmp) },
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
		if (i<2) strcpy (fg, Color_WHITE);
		else r_cons_rgb_str (fg, 0, 0, 0, 0);
		r_cons_rgb_str (bg, r, r, r, 1);
		r_cons_printf ("%s%s  rgb:%x%x%x  "Color_RESET, fg, bg, i, i, i);
		if (n++==5) {
			n = 0;
			r_cons_newline();
		}
	}
	r_cons_printf ("\n\nRGB:\n");
	for (i=n=0; i<=0xf; i+=inc) {
		for (j=0; j<=0xf; j+=inc) {
			for (k=0; k<=0xf; k+=inc) {
				char fg[32], bg[32];
				int r = i*16;
				int g = j*16;
				int b = k*16;
				if (i<2 && j<6 && k<13) strcpy (fg, Color_WHITE);
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

R_API void r_cons_pal_list () {
	RConsPalette *pal = &(r_cons_singleton ()->pal);
	ut8 *p = (ut8*)pal;
	char **color;
	int i;
	for (i=0; keys[i].name; i++) {
		color = (char**)(p + keys[i].off);
		color = (char**)*color;
		r_cons_printf (" %s##"Color_RESET"  %s\n",
			(color)? (char*)color: "", keys[i].name);
	}
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

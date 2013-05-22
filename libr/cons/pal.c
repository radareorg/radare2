/* radare - LGPL - Copyright 2013 - pancake */

#include <r_cons.h>

R_API void r_cons_pal_init(const char *foo) {
	RCons *cons = r_cons_singleton ();
	cons->pal.prompt = Color_YELLOW;
	cons->pal.offset = Color_GREEN;
	cons->pal.input = Color_WHITE;
	cons->pal.comment = Color_TURQOISE;
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
	{ "turqoise", Color_TURQOISE, Color_BGTURQOISE },
	{ "blue",     Color_BLUE,     Color_BGBLUE },
	{ "gray",     Color_GRAY      Color_BGGRAY },
	{ NULL, NULL }
};

static inline ut8 rgbnum (const char ch) {
	ut8 r;
	r_hex_to_byte (&r, ch);
	return r*16;
}

R_API char *r_cons_pal_parse(const char *str) {
	int i;
	ut8 r, g, b;
	char out[64];
	char *s = strdup (str);
	char *p = strchr (s+1, ' ');
	out[0] = 0;
	if (p) *p++ = 0;
	if (!strncmp (s, "rgb:", 4)) {
		r = rgbnum (s[4]);
		g = rgbnum (s[5]);
		b = rgbnum (s[6]);
		r_cons_rgb_str (out, r, g, b, 0);
		if (p && !strncmp (p, "rgb:", 4)) {
			r = rgbnum (p[4]);
			g = rgbnum (p[5]);
			b = rgbnum (p[6]);
			r_cons_rgb_str (out+strlen (out), r, g, b, 1);
		}
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
	{ NULL, 0 }
};

R_API void r_cons_pal_walk() {
	//RCons *c = r_cons_singleton ();
}

R_API void r_cons_pal_load(const char *sdbfile) {
}

R_API void r_cons_pal_save(const char *sdbfile) {
}

R_API void r_cons_pal_set (const char *key, const char *val) {
	int i;
	char **p;
	for (i=0; keys[i].name; i++) {
		if (!strcmp (key, keys[i].name)) {
			p = (char **)((char *)&(r_cons_singleton()->pal) + keys[i].off);
//			free (*p);
			*p = r_cons_pal_parse (val);
			break;
		}
	}
}

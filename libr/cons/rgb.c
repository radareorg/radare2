/* radare - LGPL - Copyright 2013-2018 - pancake, xarkes */
/* ansi 256 color extension for r_cons */
/* https://en.wikipedia.org/wiki/ANSI_color */

#include <r_cons.h>

int color_table[256] = { 0 };
int value_range[6] = { 0x00, 0x5f, 0x87, 0xaf, 0xd7, 0xff};

static void init_color_table () {
	int i, r, g, b;
	// ansi colors
	color_table[0] = 0x000000;
	color_table[1] = 0x800000;
	color_table[2] = 0x008000;
	color_table[3] = 0x808000;
	color_table[4] = 0x000080;
	color_table[5] = 0x800080;
	color_table[6] = 0x008080;
	color_table[7] = 0xc0c0c0;
	color_table[8] = 0x808080;
	color_table[9] = 0xff0000;
	color_table[10] = 0x00ff00;
	color_table[11] = 0xffff00;
	color_table[12] = 0x0000ff;
	color_table[13] = 0xff00ff;
	color_table[14] = 0x00ffff;
	color_table[15] = 0xffffff;
	// color palette
	for (i = 0; i < 216; i++) {
		r = value_range[(i / 36) % 6];
		g = value_range[(i / 6) % 6];
		b = value_range[i % 6];
		color_table[i + 16] = ((r << 16) & 0xffffff) +
			((g << 8) & 0xffff) + (b & 0xff);
	}
	// grayscale
	for (i = 0; i < 24; i++) {
		r = 8 + (i * 10);
		color_table[i + 232] = ((r << 16) & 0xffffff) +
			((r << 8) & 0xffff) + (r & 0xff);
	}
}

static int lookup_rgb (int r, int g, int b) {
	int i, color = (r << 16) + (g << 8) + b;
	// lookup extended colors only, coz non-extended can be changed by users.
	for (i = 16; i < 256; ++i) {
		if (color_table[i] == color) {
			return i;
		}
	}
	return -1;
}

static ut32 approximate_rgb (int r, int g, int b) {
	bool grey = (r > 0 && r < 255 && r == g && r == b);
	if (grey) {
		return 232 + (int)((double)r / (255 / 24.1));
	}
#if 0
	const double M = 16;
	double R = r;
	double G = g;
	double B = b;
	R = R /256 * 216;
	R /= 256 * 216;
	R /= 256 * 216;
	r = R = R_DIM (R / 16, 0, 16);
	g = G = R_DIM (G / 16, 0, 16);
	b = B = R_DIM (B / 16, 0, 16);
	r &= 0xff;
	g &= 0xff;
	b &= 0xff;
	return (ut32)((G * M * M)  + (g * M) + b) + 16;
#else
	const int k = (256.0 / 6);
	r = R_DIM (r / k, 0, 6);
	g = R_DIM (g / k, 0, 6);
	b = R_DIM (b / k, 0, 6);
	return 16 + (r * 36) + (g * 6) + b;
#endif
}

static int rgb (int r, int g, int b) {
	int c = lookup_rgb (r, g, b);
	if (c == -1) {
		return approximate_rgb (r, g, b);
	}
	return c;
}

static void unrgb (int color, int *r, int *g, int *b) {
	if (color < 0 || color > 256) {
		*r = *g = *b = 0;
		return;
	}
	int rgb = color_table[color];
	*r = (rgb >> 16) & 0xff;
	*g = (rgb >> 8) & 0xff;
	*b = rgb & 0xff;
}

R_API void r_cons_rgb_init (void) {
	if (color_table[255] == 0) {
		init_color_table ();
	}
}

/* Parse an ANSI code string into RGB values -- Used by HTML filter only */
R_API int r_cons_rgb_parse(const char *p, ut8 *r, ut8 *g, ut8 *b, ut8 *a) {
	const char *q = 0;
	ut8 isbg = 0, bold = 127;
	if (!p) return 0;
	if (*p == 0x1b) p++;
	if (*p != '[') p--;
	switch (p[1]) {
	case '1': bold = 255; p += 2; break;
	case '3': isbg = 0; break;
	case '4': isbg = 1; break;
	}
#define SETRGB(x,y,z) if (r) *r = (x); if (g) *g = (y); if (b) *b = (z)
	if (bold != 255 && strchr (p, ';')) {
		if (p[4] == '5')  { // \x1b[%d;5;%dm is 256 colors
			int x, y, z;
			int n = atoi (p + 6);
			unrgb (n, &x, &y, &z);
			SETRGB (x, y, z);
		} else { // 16M colors (truecolor)
			/* complex rgb */
			p += 6;
			if (r) *r = atoi (p);
			q = strchr (p, ';');
			if (!q) return 0;
			if (g) *g = atoi (q + 1);
			q = strchr (q + 1, ';');
			if (!q) return 0;
			if (b) *b = atoi (q + 1);
		}
		return 1;
	} else {
		/* plain ansi escape codes */
		if (a) *a = isbg;
		switch (p[2]) {
		case '0': SETRGB (0, 0, 0); break;
		case '1': SETRGB (bold, 0, 0); break;
		case '2': SETRGB (0, bold, 0); break;
		case '3': SETRGB (bold, bold, 0); break;
		case '4': SETRGB (0, 0, bold); break;
		case '5': SETRGB (bold, 0, bold); break;
		case '6': SETRGB (0, bold, bold); break;
		case '7': SETRGB (bold, bold, bold); break;
		}
	}
	return 1;
}

R_API char *r_cons_rgb_str_off(char *outstr, ut64 off) {
	RColor rc = RColor_BLACK;
	rc.r = (off >> 2) & 0xff;
	rc.g = (off >> 6) & 0xff;
	rc.b = (off >> 12) & 0xff;
	return r_cons_rgb_str (outstr, &rc);
}

/* Compute color string depending on cons->color */
static void r_cons_rgb_gen (char *outstr, ut8 a, ut8 r, ut8 g, ut8 b) {
	ut8 fgbg = (a == ALPHA_BG)? 48: 38; // ANSI codes for Background/Foreground
	const char *bold = (a & ALPHA_BOLD)? "1;": "";
	switch (r_cons_singleton ()->color) {
	case COLOR_MODE_256: // 256 color palette
		sprintf (outstr, "\x1b[%s%d;5;%dm", bold, fgbg, rgb (r, g, b));
		break;
	case COLOR_MODE_16M: // 16M (truecolor)
		sprintf (outstr, "\x1b[%s%d;2;%d;%d;%dm", bold, fgbg, r, g, b);
		break;
	case COLOR_MODE_16: // ansi 16 colors
		{
		fgbg -= 8;
		ut8 k = (r + g + b) / 3;
		r = (r >= k) ? 1 : 0;
		g = (g >= k) ? 1 : 0;
		b = (b >= k) ? 1 : 0;
		k = (r ? 1 : 0) + (g ? (b ? 6 : 2) : (b ? 4 : 0));
		sprintf (outstr, "\x1b[%s%dm", bold, fgbg + k);
		}
		break;
	}
}

/* Return the computed color string for the specified color */
R_API char *r_cons_rgb_str (char *outstr, RColor *rcolor) {
	if (!rcolor || (!outstr && !(outstr = malloc (128)))) {
		return NULL;
	}
	*outstr = 0;
	if (rcolor->a == ALPHA_RESET) {
		sprintf (outstr, "%s", Color_RESET);
		return outstr;
	}
	r_cons_rgb_gen (outstr, rcolor->a, rcolor->r, rcolor->g, rcolor->b);
	// If the color handles both foreground and background, also add background
	if (rcolor->a == ALPHA_FGBG) {
		ut8 length = strlen (outstr);
		r_cons_rgb_gen (outstr + length, ALPHA_BG, rcolor->r2, rcolor->g2, rcolor->b2);
	}

	return outstr;
}

R_API char *r_cons_rgb_tostring(ut8 r, ut8 g, ut8 b) {
	const char *str = NULL;
	if (r == 0x00 && g == b && g == 0) str = "black";
	if (r == 0xff && g == b && g == 0xff) str = "white";
	if (r == 0xff && g == b && g == 0) str = "red";
	if (g == 0xff && r == b && r == 0) str = "green";
	if (b == 0xff && r == g && r == 0) str = "blue";
	if (r == 0xff && g == 0xff && b == 0x00) str = "yellow";
	if (r == 0x00 && g == 0xff && b == 0xff) str = "cyan";
	if (r == 0xff && g == 0x00 && b == 0xff) str = "magenta";
	return str? strdup (str) : r_str_newf ("#%02x%02x%02x", r, g, b);
}

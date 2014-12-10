/* radare - LGPL - Copyright 2013 - pancake */
/* ansi 256 color extension for r_cons */
/* https://en.wikipedia.org/wiki/ANSI_color */

#include <r_cons.h>

int color_table[256] = { 0 };
int value_range[6] = { 0x00, 0x5f, 0x87, 0xaf, 0xd7, 0xff};

static void init_color_table() {
	int i, r, g, b;
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
	for (i=0; i < 216; i++) {
	    r = value_range[(i/36) % 6];
	    g = value_range[(i/6) % 6];
	    b = value_range[i % 6];
	    color_table[i + 16] = ((r << 16) & 0xffffff) + ((g << 8) & 0xffff) + (b & 0xff);
	}
	for (i=0; i < 24; i++) {
		r = 8 + (i * 10);
	    color_table[i + 232] = ((r << 16) & 0xffffff) + ((r << 8) & 0xffff) + (r & 0xff);
	}
}

static int gs (int rgb) {
	return 232 + (double)rgb/(255/24.1);
}

static int rgb(int r, int g, int b) {
	const double k = (256.0/6.0);
	int grey = 0;
	if (r > 0 && r < 255 && r == g && r == b) grey = 1;
	if (grey > 0) {
		return gs(r);
	} else {
		r = R_DIM (r/k, 0, 6);
		g = R_DIM (g/k, 0, 6);
		b = R_DIM (b/k, 0, 6);
		return 16 + (r*36) + (g*6) + b;
	}
}

static void unrgb(int color, int *r, int *g, int *b) {
	if (color_table[255] == 0) init_color_table();
	int rgb = color_table[color];
	*r = (rgb >> 16) & 0xff;
	*g = (rgb >> 8) & 0xff;
	*b = rgb & 0xff;
}

static inline void rgbinit(int r, int g, int b) {
#if __UNIX__
	r_cons_printf ("\x1b]4;%d;rgb:%2.2x/%2.2x/%2.2x\x1b\\",
			16 + (r * 36) + (g * 6) + b,
			(r ? (r * 40 + 55) : 0),
			(g ? (g * 40 + 55) : 0),
			(b ? (b * 40 + 55) : 0));
#endif
}

R_API void r_cons_rgb_init (void) {
	int r, g, b;
	for (r = 0; r < 6; r++)
		for (g = 0; g < 6; g++)
			for (b = 0; b < 6; b++)
				rgbinit (r, g, b);
}

R_API int r_cons_rgb_parse (const char *p, ut8 *r, ut8 *g, ut8 *b, int *is_bg) {
	const char *q = 0;
	int isbg = 0, bold=127;
	//const double k = (256/6);
	if (!p) return 0;
	if (*p==0x1b) p++;
	if (*p!='[') return 0;
	switch (p[1]) {
	case '1': bold=255; p+=2; break;
	case '3': isbg=0; break;
	case '4': isbg=1; break;
	}
#define SETRGB(x,y,z) if(r)*r=(x);if(g)*g=(y);if(b)*b=(z)
	if (bold != 255 && strchr (p, ';')) {
		if (p[4]=='5')  {
			int x, y, z;
			int n = atoi (p+6);
			unrgb (n, &x, &y, &z);
			SETRGB (x,y,z);
		} else {
			/* truecolor */
			p += 6;
			/* complex rgb */
			if (r) *r = atoi (p);
			q = strchr (p, ';');
			if (!q) return 0;
			if (g) *g = atoi (q+1);
			q = strchr (q+1, ';');
			if (!q) return 0;
			if (b) *b = atoi (q+1);
		}
		return 1;
	} else {
		/* plain ansi */
		if (is_bg) *is_bg = isbg;
		switch (p[2]) {
		case '0': SETRGB (0,0,0); break;
		case '1': SETRGB (bold,0,0); break;
		case '2': SETRGB (0,bold,0); break;
		case '3': SETRGB (bold,bold,0); break;
		case '4': SETRGB (0,0,bold); break;
		case '5': SETRGB (bold,0,bold); break;
		case '6': SETRGB (0,bold,bold); break;
		case '7': SETRGB (bold,bold,bold); break;
		}
	}
	return 1;
}

R_API char *r_cons_rgb_str (char *outstr, ut8 r, ut8 g, ut8 b, int is_bg) {
	int k, fgbg = is_bg? 48: 38;
	k = (r == g && g == b)?  gs (r): rgb (r, g, b);
	//k = rgb (r, g, b);
	if (!outstr) outstr = malloc (32);

	switch (r_cons_singleton()->truecolor) {
	case 1: // 256 color palette
		sprintf (outstr, "\x1b[%d;5;%dm", fgbg, k);
		break;
	case 2: // 16M - xterm only
		sprintf (outstr, "\x1b[%d;2;%d;%d;%dm", fgbg,
			r&0xff, g&0xff, b&0xff);
		break;
	case 0: // ansi 16 colors
	default:
		{
		int k = (r+g+b)/3;
		r = (r>k)?1:0;
		g = (g>k)?1:0;
		b = (b>k)?1:0;
		k = (r?1:0) + (g? (b?6:2): (b?4:0));
		sprintf (outstr, "\x1b[%dm", 30+k);
		}
		break;
	}
	return outstr;
}

R_API void r_cons_rgb (ut8 r, ut8 g, ut8 b, int is_bg) {
#if __WINDOWS__
	#warning r_cons_rgb not yet supported on windows
#else
	char outstr[64];
	r_cons_strcat (r_cons_rgb_str (outstr, r, g, b, is_bg));
#endif
}

R_API void r_cons_rgb_fgbg (ut8 r, ut8 g, ut8 b, ut8 R, ut8 G, ut8 B) {
	r_cons_rgb (r, g, b, 0);
	r_cons_rgb (R, G, B, 1);
}

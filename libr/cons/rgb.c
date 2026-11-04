/* radare - LGPL - Copyright 2013-2025 - pancake, xarkes */

#include <r_cons.h>
#include <r_th.h>

static int rgb_cube_index(int value) {
	if (!value) {
		return 0;
	}
	// Nonzero xterm cube levels start at 95 and advance by 40.
	if (value < 95 || value > 255 || (value - 95) % 40) {
		return -1;
	}
	return 1 + (value - 95) / 40;
}

static int rgb_lookup(RCons *cons, int r, int g, int b) {
	r = rgb_cube_index (r);
	g = rgb_cube_index (g);
	b = rgb_cube_index (b);
	if (r < 0 || g < 0 || b < 0) {
		return -1;
	}
	return 16 + r * 36 + g * 6 + b;
}

static ut32 rgb_aprox(int r, int g, int b) {
	const bool grey = (r > 0 && r < 255 && r == g && r == b);
	if (grey) {
		return 232 + (int)((double)r / (255 / 24.1));
	}
	const int k = 256 / 6;
	r = R_DIM (r / k, 0, 5);
	g = R_DIM (g / k, 0, 5);
	b = R_DIM (b / k, 0, 5);
	return 16 + (r * 36) + (g * 6) + b;
}

static int rgb(RCons *cons, int r, int g, int b) {
	const int c = rgb_lookup (cons, r, g, b);
	return (c != -1) ? c: rgb_aprox (r, g, b);
}

R_API char *r_cons_rgb_str_off(RCons *cons, char *outstr, size_t sz, ut64 off) {
	RColor rc = RColor_BLACK;
	rc.id16 = -1;
	rc.r = (off >> 2) & 0xff;
	rc.g = (off >> 6) & 0xff;
	rc.b = (off >> 12) & 0xff;
	return r_cons_rgb_str (cons, outstr, sz, &rc);
}

#if 0
R_API void r_cons_color(RCons *cons, int fg, int r, int g, int b) {
	int k;
	r = R_DIM (r, 0, 255);
	g = R_DIM (g, 0, 255);
	b = R_DIM (b, 0, 255);
	if (r == g && g == b) { // b&w
		k = 232 + (int)(((r+g+b)/3)/10.3);
	} else {
		r = (int)(r / 42.6);
		g = (int)(g / 42.6);
		b = (int)(b / 42.6);
		k = 16 + (r * 36) + (g * 6) + b;
	}
	r_cons_printf (cons, "\x1b[%d;5;%dm", fg? 48: 38, k);
}
#endif

/* Compute color string depending on cons->color */
static void rgb_gen(RCons *cons, RConsColorMode mode, char *outstr, size_t sz, ut8 attr, ut8 a, ut8 r, ut8 g, ut8 b, st8 id16) {
	ut8 fgbg = (a == ALPHA_BG)? 48: 38; // ANSI codes for Background/Foreground

	if (sz < 4) { // must have at least room for "<esc>[m\0"
		if (sz > 0) {
			outstr[0] = '\0';
		}
		return;
	}

	size_t i = 2;
	outstr[0] = '\x1b';
	outstr[1] = '[';
	for (; attr; attr &= attr - 1) {
		if (sz < i + 4) { // must have at least room for e.g. "1;m\0"
			outstr[0] = '\0';
			return;
		}
		switch (attr & -attr) {
		case R_CONS_ATTR_BOLD: outstr[i] = '1'; break;
		case R_CONS_ATTR_DIM: outstr[i] = '2'; break;
		case R_CONS_ATTR_ITALIC: outstr[i] = '3'; break;
		case R_CONS_ATTR_UNDERLINE: outstr[i] = '4'; break;
		case R_CONS_ATTR_BLINK: outstr[i] = '5'; break;
		}
		outstr[i + 1] = ';';
		i += 2;
	}

	int written = -1;
	switch (mode) {
	case COLOR_MODE_256: // 256 color palette
		written = snprintf (outstr + i, sz - i, "%d;5;%dm", fgbg, rgb (cons, r, g, b));
		break;
	case COLOR_MODE_16M: // 16M (truecolor)
		written = snprintf (outstr + i, sz - i, "%d;2;%d;%d;%dm", fgbg, r, g, b);
		break;
	case COLOR_MODE_16: { // ansi 16 colors
		ut8 bright, c;
		fgbg -= 8;
		if (id16 >= 0 && id16 <= 15) {
			c = id16 % 8;
			bright = id16 >= 8 ? 60 : 0;
		} else {
			bright = (r == 0x80 && g == 0x80 && b == 0x80)
				? 53
				: (r == 0xff || g == 0xff || b == 0xff)
					? 60
					: 0;  // eco bright-specific
			ut8 k = (r + g + b) / 3;
			r = (r >= k) ? 1 : 0;
			g = (g >= k) ? 1 : 0;
			b = (b >= k) ? 1 : 0;
			c = r + (g << 1) + (b << 2);
		}
		written = snprintf (outstr + i, sz - i, "%dm", fgbg + bright + c);
		break;
	}
	default:
		break;
	}

	if (written < 0 || written >= sz - i) {
		outstr[0] = '\0';
	}
}

static st8 rgb_ansi16(ut8 r, ut8 g, ut8 b) {
	static const RColor colors[] = {
		RColor_BLACK, RColor_RED, RColor_GREEN, RColor_YELLOW,
		RColor_BLUE, RColor_MAGENTA, RColor_CYAN, RColor_WHITE,
		RColor_BBLACK, RColor_BRED, RColor_BGREEN, RColor_BYELLOW,
		RColor_BBLUE, RColor_BMAGENTA, RColor_BCYAN, RColor_BWHITE
	};
	int best_distance = ST32_MAX;
	st8 best = 0;
	int i;
	for (i = 0; i < 16; i++) {
		int dr = r - colors[i].r;
		int dg = g - colors[i].g;
		int db = b - colors[i].b;
		int distance = dr * dr + dg * dg + db * db;
		if (distance < best_distance) {
			best_distance = distance;
			best = i;
		}
	}
	return best;
}

/* Return the computed color string for the specified color in the specified mode */
R_API char *r_cons_rgb_str_mode(RCons *cons, char *outstr, size_t sz, RColor *rcolor) {
	if (!rcolor) {
		return NULL;
	}
	RConsColorMode mode = cons->context->color_mode;
	if (!outstr) {
		sz = 64;
		outstr = calloc (sz, 1);
	}
	*outstr = 0;
	if (rcolor->a == ALPHA_RESET) {
		if (sz >= sizeof (Color_RESET)) {
			memcpy (outstr, Color_RESET, sizeof (Color_RESET));
		}
		return outstr;
	}
	// If the color handles both foreground and background, also add background
	st8 foreground_id = rcolor->id16;
	if (rcolor->a == ALPHA_FGBG) {
		st8 background_id = rcolor->id16;
		if (mode == COLOR_MODE_16) {
			foreground_id = rgb_ansi16 (rcolor->r, rcolor->g, rcolor->b);
			background_id = rgb_ansi16 (rcolor->r2, rcolor->g2, rcolor->b2);
		}
		rgb_gen (cons, mode, outstr, sz, 0, ALPHA_BG, rcolor->r2, rcolor->g2, rcolor->b2, background_id);
	}
	// APPEND
	size_t len = strlen (outstr);
	rgb_gen (cons, mode, outstr + len, sz - len,
		rcolor->attr, rcolor->a, rcolor->r, rcolor->g, rcolor->b, foreground_id);

	return outstr;
}

/* Return the computed color string for the specified color */
R_API char *r_cons_rgb_str(RCons *cons, char *outstr, size_t sz, RColor *rcolor) {
	return r_cons_rgb_str_mode (cons, outstr, sz, rcolor);
}

R_API char *r_cons_rgb_tostring(ut8 r, ut8 g, ut8 b) {
	const char *str = NULL;
	if (r == 0x00 && g == b && g == 0) {
		str = "black";
	} else if (r == 0xff && g == b && g == 0xff) {
		str = "white";
	} else if (r == 0xff && g == b && g == 0) {
		str = "red";
	} else if (g == 0xff && r == 0x80 && b == 0) {
		str = "orange";
	} else if (g == 0xff && r == b && r == 0) {
		str = "green";
	} else if (b == 0xff && r == g && r == 0) {
		str = "blue";
	} else if (r == 0xff && g == 0xff && b == 0x00) {
		str = "yellow";
	} else if (r == 0x00 && g == 0xff && b == 0xff) {
		str = "cyan";
	} else if (r == 0xff && g == 0x00 && b == 0xff) {
		str = "magenta";
	}
	return str? strdup (str) : r_str_newf ("#%02x%02x%02x", r, g, b);
}

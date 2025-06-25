/* radare - LGPL - Copyright 2013-2025 - pancake, xarkes */

#include <r_cons.h>
#include <r_th.h>

// generated with gen.256.c
// also in util/str_strip.c .. maybe dedup
static int colortable[256] = {
0, 8388608, 32768, 8421376, 128, 8388736, 32896, 12632256, 8421504, 16711680, 65280, 16776960, 255, 16711935, 65535, 16777215,
0, 95, 135, 175, 215, 255, 24320, 24415, 24455, 24495, 24535, 24575, 34560, 34655, 34695, 34735,
34775, 34815, 44800, 44895, 44935, 44975, 45015, 45055, 55040, 55135, 55175, 55215, 55255, 55295, 65280, 65375,
65415, 65455, 65495, 65535, 6225920, 6226015, 6226055, 6226095, 6226135, 6226175, 6250240, 6250335, 6250375, 6250415, 6250455, 6250495,
6260480, 6260575, 6260615, 6260655, 6260695, 6260735, 6270720, 6270815, 6270855, 6270895, 6270935, 6270975, 6280960, 6281055, 6281095, 6281135,
6281175, 6281215, 6291200, 6291295, 6291335, 6291375, 6291415, 6291455, 8847360, 8847455, 8847495, 8847535, 8847575, 8847615, 8871680, 8871775,
8871815, 8871855, 8871895, 8871935, 8881920, 8882015, 8882055, 8882095, 8882135, 8882175, 8892160, 8892255, 8892295, 8892335, 8892375, 8892415,
8902400, 8902495, 8902535, 8902575, 8902615, 8902655, 8912640, 8912735, 8912775, 8912815, 8912855, 8912895, 11468800, 11468895, 11468935, 11468975,
11469015, 11469055, 11493120, 11493215, 11493255, 11493295, 11493335, 11493375, 11503360, 11503455, 11503495, 11503535, 11503575, 11503615, 11513600, 11513695,
11513735, 11513775, 11513815, 11513855, 11523840, 11523935, 11523975, 11524015, 11524055, 11524095, 11534080, 11534175, 11534215, 11534255, 11534295, 11534335,
14090240, 14090335, 14090375, 14090415, 14090455, 14090495, 14114560, 14114655, 14114695, 14114735, 14114775, 14114815, 14124800, 14124895, 14124935, 14124975,
14125015, 14125055, 14135040, 14135135, 14135175, 14135215, 14135255, 14135295, 14145280, 14145375, 14145415, 14145455, 14145495, 14145535, 14155520, 14155615,
14155655, 14155695, 14155735, 14155775, 16711680, 16711775, 16711815, 16711855, 16711895, 16711935, 16736000, 16736095, 16736135, 16736175, 16736215, 16736255,
16746240, 16746335, 16746375, 16746415, 16746455, 16746495, 16756480, 16756575, 16756615, 16756655, 16756695, 16756735, 16766720, 16766815, 16766855, 16766895,
16766935, 16766975, 16776960, 16777055, 16777095, 16777135, 16777175, 16777215, 526344, 1184274, 1842204, 2500134, 3158064, 3815994, 4473924, 5131854,
5789784, 6447714, 7105644, 7763574, 8421504, 9079434, 9737364, 10395294, 11053224, 11711154, 12369084, 13027014, 13684944, 14342874, 15000804, 15658734 };

static int rgb_lookup(RCons *cons, int r, int g, int b) {
	int i, color = (r << 16) + (g << 8) + b;
	// lookup extended colors only, coz non-extended can be changed by users.
	for (i = 16; i < 232; i++) {
		if (colortable[i] == color) {
			return i;
		}
	}
	return -1;
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
		strcpy (outstr, Color_RESET);
		return outstr;
	}
	// If the color handles both foreground and background, also add background
	if (rcolor->a == ALPHA_FGBG) {
		rgb_gen (cons, mode, outstr, sz, 0, ALPHA_BG, rcolor->r2, rcolor->g2, rcolor->b2, rcolor->id16);
	}
	// APPEND
	size_t len = strlen (outstr);
	rgb_gen (cons, mode, outstr + len, sz - len,
			rcolor->attr, rcolor->a, rcolor->r, rcolor->g, rcolor->b, rcolor->id16);

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
	}
	if (r == 0xff && g == b && g == 0xff) {
		str = "white";
	}
	if (r == 0xff && g == b && g == 0) {
		str = "red";
	}
	if (g == 0xff && r == 0x80 && b == 0) {
		str = "orange";
	}
	if (g == 0xff && r == b && r == 0) {
		str = "green";
	}
	if (b == 0xff && r == g && r == 0) {
		str = "blue";
	}
	if (r == 0xff && g == 0xff && b == 0x00) {
		str = "yellow";
	}
	if (r == 0x00 && g == 0xff && b == 0xff) {
		str = "cyan";
	}
	if (r == 0xff && g == 0x00 && b == 0xff) {
		str = "magenta";
	}
	return str? strdup (str) : r_str_newf ("#%02x%02x%02x", r, g, b);
}

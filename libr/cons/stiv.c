/* tiv - terminal image viewer - MIT 2013-2026 - pancake */

#include <r_cons.h>
#include <r_util/r_utf8.h>

#define XY(b,x,y) ((b) + (y) * w * components + (x) * components)

typedef void (*Renderer)(RStrBuf *sb, const ut8*, const ut8 *, bool, bool);

static int reduce8(int r, int g, int b) {
	static const ut8 colors[][3] = {
		{ 0x00,0x00,0x00 }, // black
		{ 0xd0,0x10,0x10 }, // red
		{ 0x10,0xe0,0x10 }, // green
		{ 0xf7,0xf5,0x3a }, // yellow
		{ 0x10,0x10,0xf0 }, // blue
		{ 0xfb,0x3d,0xf8 }, // pink
		{ 0x10,0xf0,0xf0 }, // turqoise
		{ 0xf0,0xf0,0xf0 }, // white
	};

	// B&W
	if (r < 30 && g < 30 && b < 30) {
		return 0;
	}
	if (r > 200 && g > 200 && b > 200) {
		return 7;
	}
	int best_distance = ST32_MAX;
	int best = 0;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (colors); i++) {
		const int dr = r - colors[i][0];
		const int dg = g - colors[i][1];
		const int db = b - colors[i][2];
		const int distance = dr * dr + dg * dg + db * db;
		if (distance < best_distance) {
			best_distance = distance;
			best = i;
		}
	}
	return best;
}

static void render_ansi(RStrBuf *sb, const ut8 *c, const ut8 *d, bool foreground, bool background) {
	if (foreground) {
		r_strbuf_appendf (sb, "\x1b[%dm", 30 + reduce8 (c[0], c[1], c[2]));
	}
	if (background) {
		r_strbuf_appendf (sb, "\x1b[%dm", 40 + reduce8 (d[0], d[1], d[2]));
	}
}

static int rgb(int r, int g, int b) {
	r = R_DIM (r, 0, 255);
	g = R_DIM (g, 0, 255);
	b = R_DIM (b, 0, 255);
	r = (int)(r / 50.6);
	g = (int)(g / 50.6);
	b = (int)(b / 50.6);
	return 16 + (r * 36) + (g * 6) + b;
}

static void render_sixel(RStrBuf *sb, const ut8 *c, const ut8 *d, bool foreground, bool background) {
	int r = (c[0] * 100 / 255);
	int g = (c[1] * 100 / 255);
	int b = (c[2] * 100 / 255);
	r_strbuf_appendf (sb, "#0;2;%d;%d;%d", r, g, b); // bg is black
	r = (d[0] * 100 / 255);
	g = (d[1] * 100 / 255);
	b = (d[2] * 100 / 255);
	r_strbuf_appendf (sb, "#1;2;%d;%d;%d", r, g, b); // fg is color
	// r_strbuf_appendf (sb, "#%d!6%c", 1, 0x3f); // 6x6 pixel block
	r_strbuf_appendf (sb, "#%d~~~~~~", 1); // 6x6 pixel block
}

static void render_256(RStrBuf *sb, const ut8 *c, const ut8 *d, bool foreground, bool background) {
	if (foreground) {
		r_strbuf_appendf (sb, "\x1b[%d;5;%dm", 38, rgb (c[0], c[1], c[2]));
	}
	if (background) {
		r_strbuf_appendf (sb, "\x1b[%d;5;%dm", 48, rgb (d[0], d[1], d[2]));
	}
}

static void render_rgb(RStrBuf *sb, const ut8 *c, const ut8 *d, bool foreground, bool background) {
	if (foreground) {
		r_strbuf_appendf (sb, "\x1b[38;2;%d;%d;%dm", c[0], c[1], c[2]);
	}
	if (background) {
		r_strbuf_appendf (sb, "\x1b[48;2;%d;%d;%dm", d[0], d[1], d[2]);
	}
}

static void render_greyscale(RStrBuf *sb, const ut8 *c, const ut8 *d, bool foreground, bool background) {
	if (foreground) {
		int color = (c[0] + c[1] + c[2]) / 3;
		int palette = R_MAX (232, 231 + (int)((float)color / 10.3));
		r_strbuf_appendf (sb, "\x1b[38;5;%dm", palette);
	}
	if (background) {
		int color = (d[0] + d[1] + d[2]) / 3;
		int palette = R_MAX (232, 231 + (int)((float)color / 10.3));
		r_strbuf_appendf (sb, "\x1b[48;5;%dm", palette);
	}
}

static void render_ascii(RStrBuf *sb, const ut8 *c, const ut8 *d, bool foreground, bool background) {
	const char * const pal = " `.,-:+*%$#";
	int idx, pal_len = strlen (pal);
	float p = ((double)(c[0] + c[1] + c[2]) / 3);
	float q = ((double)(d[0] + d[1] + d[2]) / 3);
	idx = (int)(((p + q)/2) / (255 / pal_len));
	if (idx >= pal_len) {
		idx = pal_len - 1;
	}
	r_strbuf_append_n (sb, pal + idx, 1);
}

static void render_ascii_rgb(RStrBuf *sb, const ut8 *c, const ut8 *d, bool foreground, bool background) {
	const ut8 color[] = {
		(c[0] + d[0]) / 2,
		(c[1] + d[1]) / 2,
		(c[2] + d[2]) / 2
	};
	render_rgb (sb, color, color, foreground || background, false);
	render_ascii (sb, c, d, false, false);
}

static ut8 braille_mask(const ut8 *const pixels[8], ut8 colors[2][3], bool color) {
	static const ut8 dots[] = { 1, 8, 2, 16, 4, 32, 64, 128 };
	int channel = 0, midpoint = 0;
	int i, c;
	if (color) {
		ut8 low[] = { 255, 255, 255 }, high[3] = {0};
		for (i = 0; i < 8; i++) {
			for (c = 0; c < 3; c++) {
				low[c] = R_MIN (low[c], pixels[i][c]);
				high[c] = R_MAX (high[c], pixels[i][c]);
			}
		}
		// Split along the channel with the most contrast to preserve changes in hue.
		for (c = 1; c < 3; c++) {
			if (high[c] - low[c] > high[channel] - low[channel]) {
				channel = c;
			}
		}
		midpoint = (low[channel] + high[channel]) / 2;
	}
	int sums[2][3] = {{0}}, counts[2] = {0};
	ut8 mask = 0;
	for (i = 0; i < 8; i++) {
		const ut8 *pixel = pixels[i];
		const bool dot = color? pixel[channel] > midpoint: 3 * pixel[0] + 6 * pixel[1] + pixel[2] >= 128 * 10;
		if (dot) {
			mask |= dots[i];
		}
		if (color) {
			counts[dot]++;
			for (c = 0; c < 3; c++) {
				sums[dot][c] += pixel[c];
			}
		}
	}
	for (i = 0; i < 2; i++) {
		if (counts[i]) {
			for (c = 0; c < 3; c++) {
				colors[i][c] = sums[i][c] / counts[i];
			}
		}
	}
	return mask;
}

static void render_braille(RStrBuf *sb, const ut8 *buf, int w, int h, int components, bool color) {
	const ut8 black[3] = {0};
	if (color && h > 0) {
		r_strbuf_append (sb, Color_RESET);
	}
	int x, y;
	for (y = 0; y < h; y += 4) {
		ut8 previous[2][3];
		for (x = 0; x < w; x += 2) {
			const ut8 *pixels[8];
			int dx, dy;
			for (dy = 0; dy < 4; dy++) {
				for (dx = 0; dx < 2; dx++) {
					pixels[dy * 2 + dx] = x + dx < w && y + dy < h? XY (buf, x + dx, y + dy): black;
				}
			}
			ut8 colors[2][3] = {{0}};
			const ut8 mask = braille_mask (pixels, colors, color);
			if (color) {
				render_rgb (sb, colors[1], colors[0], !x || memcmp (previous[1], colors[1], 3),
					!x || memcmp (previous[0], colors[0], 3));
				memcpy (previous, colors, sizeof (previous));
			}
			ut8 glyph[4];
			const int len = r_utf8_encode (glyph, 0x2800 + mask);
			r_strbuf_append_n (sb, (const char *)glyph, len);
		}
		r_strbuf_append (sb, color? Color_RESET "\n": "\n");
	}
}

static void do_render(Renderer renderer, RStrBuf *sb, const ut8 *buf, int w, int h, int components) {
	const ut8 *c, *d;
	const bool ascii = renderer == render_ascii || renderer == render_ascii_rgb;
	int x, y;
	if (renderer == render_sixel) {
		r_strbuf_append (sb, "\x1bPq");
		for (y = 0; y < h; y += 6) {
			for (x = 0; x < w; x += 3) {
				c = XY (buf, x, y);
				d = y + 1 < h? XY (buf, x, y + 1): c;
				render_sixel (sb, c, d, true, true);
			}
			r_strbuf_append (sb, "$-");
		}
		r_strbuf_append (sb, "\x1b\\\n");
		return;
	}
	for (y = 0; y < h; y += 2) {
		const ut8 *previous_top = NULL, *previous_bottom = NULL;
		if (renderer == render_ascii_rgb) {
			r_strbuf_append (sb, Color_RESET);
		}
		for (x = 0; x < w; x++) {
			c = XY (buf, x, y);
			d = y + 1 < h? XY (buf, x, y + 1): c;
			bool foreground = !previous_top || memcmp (previous_top, c, 3);
			bool background = !previous_bottom || memcmp (previous_bottom, d, 3);
			if (foreground || background || ascii) {
				renderer (sb, c, d, foreground, background);
			}
			if (!ascii) {
				r_strbuf_append_n (sb, "▀", 3);
			}
			previous_top = c;
			previous_bottom = d;
		}
		r_strbuf_append (sb, (renderer == render_ascii)? "\n": "\x1b[0m\n");
	}
}

static Renderer select_renderer(int mode) {
	switch (mode) {
	case 'a':
		return render_ascii;
	case 'c':
		return render_ascii_rgb;
	case 'A':
		return render_ansi;
	case 'g':
		return render_greyscale;
	case 's':
		return render_sixel;
	case '2':
		return render_256;
	case 'r':
	default:
		return render_rgb;
	}
}

R_API char *r_cons_image(const ut8 *buf, int bufsz, int width, int mode, int components) {
	R_RETURN_VAL_IF_FAIL (buf && bufsz >= 0 && width > 0 && components > 0, NULL);
	if (components != 3 && components != 4) {
		return NULL;
	}
	const int height = (bufsz / width) / components;
	RStrBuf *sb = r_strbuf_new (NULL);
	if (mode == 'b' || mode == 'B') {
		render_braille (sb, buf, width, height, components, mode == 'b');
	} else {
		do_render (select_renderer (mode), sb, buf, width, height, components);
	}
	return r_strbuf_drain (sb);
}

#if 0
int
main(int argc, const char **argv) {
	ut8 *buf, *c, *d;
	int n, x, y, w, h, imgsz, readsz;
	if (argc<3) {
		printf ("stiv . suckless terminal image viewer\n");
		printf ("Usage: stiv [width] [height] [ascii|ansi|grey|256|rgb] < rgb24\n");
		return 1;
	}
	w = atoi (argv[1]);
	h = atoi (argv[2]);
	Renderer renderer;
	if (argc>3) {
		renderer = select_renderer (argv[3]);
	} else {
		renderer = render_rgb
	};
	if (w<1 || h<1) {
		printf ("Invalid arguments\n");
		return 1;
	}
	imgsz = w * h * 3;
	buf = malloc (imgsz);
	readsz = 0;
	do {
		n = read(0, buf+readsz, imgsz);
		if (n<1) break;
		readsz += n;
	} while (readsz < imgsz);

	do_render (render, buf, readsz, w, h);

	free (buf);
	return 0;
}
#endif

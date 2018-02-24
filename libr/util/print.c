/* radare - LGPL - Copyright 2007-2017 - pancake */

#include "r_anal.h"
#include "r_cons.h"
#include "r_print.h"
#include "r_util.h"

#define DFLT_ROWS 16

static void nullprinter(const char *a, ...) { }
static void libc_printf(const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	vprintf (format, ap);
	va_end (ap);
}
static bool isInterrupted = false;

R_API void r_print_portionbar(RPrint *p, const ut64 *portions, int n_portions) {
	const int use_color = p->flags & R_PRINT_FLAGS_COLOR;
	int i, j;
	ut64 total = 0LL;
	for (i = 0; i < n_portions; i++) {
		ut64 sum = total + portions[i];
		if (total > sum) {
			eprintf ("portionbar overflow aborted\n");
			return;
		}
		total = sum;
	}
	p->cb_printf ("[");
	if (total == 0) {
		total = 1;
	}
	for (i = 0; i < n_portions; i++) {
		int pc = portions[i] * 100 / total;
		// adjust pc to screen columns
		pc = pc * p->width / 100;
		if (use_color) {
			p->cb_printf ("\x1b[%dm", 31 + (i % 8));
		}
		if (pc == 0) {
			pc = 1;
		}
		for (j = 0; j < pc; j++) {
			p->cb_printf ("%c", 'A'+ i);
		}
		if (use_color) {
			p->cb_printf (Color_RESET);
		}
	}
	p->cb_printf ("]\n");
}

R_API void r_print_columns (RPrint *p, const ut8 *buf, int len, int height) {
	int i, j, cols = 78;
	int rows = height > 0 ? height : 10;
	// int realrows = rows * 2;
	bool colors = p->flags & R_PRINT_FLAGS_COLOR;
	if (colors) {
		for (i = 0; i < rows; i++) {
			int threshold = i * (0xff / rows);
			for (j = 0; j < cols; j++) {
				int realJ = j * len / cols;
				if (255 - buf[realJ] < threshold || (i + 1 == rows)) {
					p->cb_printf (Color_BGRED"_" Color_RESET);
				} else {
					p->cb_printf (" ");
				}
			}
			p->cb_printf ("\n");
		}
		return;
	}

	for (i = 0; i<rows; i++) {
		int threshold = i * (0xff / rows);
		for (j = 0; j < cols; j++) {
			int realJ = j * len / cols;
			if (255 - buf[realJ] < threshold) {
				p->cb_printf ("|");
			} else if (i + 1 == rows) {
				p->cb_printf ("_");
			} else {
				p->cb_printf (" ");
			}
		}
		p->cb_printf ("\n");
	}
}

R_API int r_util_lines_getline(ut64 *lines_cache, int lines_cache_sz, ut64 off) {
	int imax = lines_cache_sz;
	int imin = 0;
	int imid = 0;

	while (imin <= imax) {
		imid = imin + ((imax - imin) / 2);
		if (lines_cache[imid] == off) {
			return imid + 1;
		}
		if (lines_cache[imid] < off) {
			imin = imid + 1;
		} else {
			imax = imid - 1;
		}
	}
	return imin;
}

R_API int r_print_is_interrupted() {
	return isInterrupted;
}

R_API void r_print_set_interrupted(int i) {
	isInterrupted = i;
}

R_API bool r_print_mute(RPrint *p, int x) {
	if (x) {
		if (p->cb_printf == &nullprinter) {
			return false;
		}
		p->oprintf = p->cb_printf;
		p->cb_printf = nullprinter;
		return true;
	}
	if (p->cb_printf == nullprinter) {
		p->cb_printf = p->oprintf;
		return true;
	}
	return false;
}

static int r_print_stereogram_private(const char *bump, int w, int h, char *out, int size) {
	static char data[32768]; // ???
	const char *string = "Az+|.-=/^@_pT";
	const int string_len = strlen (string);

	int x, y, s, l = 0, l2 = 0, ch;
	int skip = 7;
	int bumpi = 0, outi = 0;
	if (!bump || !out) {
		return 0;
	}
	for (y = 0; bump[bumpi] && outi < size; y++) {
		l = l2 = 0;
		for (x = 0; bump[bumpi] && outi < size && x < w; x++) {
			ch = string[x % string_len];
			if (!l && x > skip) {
				s = bump[bumpi++];
				if (s >= '0' && s <= '9') {
					s = '0' - s;
				} else {
					switch (s) {
					case 0:
						bumpi--;
					/* passthru */
					case '\n':
						s = 0;
						l = 1;
						break;
					case ' ':
						s = 0;
						break;
					default:
						s = -2;
						break;
					}
				}
			} else {
				s = 0;
			}
			s += skip;
			s = x - s;
			if (s >= 0) {
				ch = data[s];
			}
			if (!ch) {
				ch = *string;
			}
			data[x] = ch;
			if (outi >= size) {
				break;
			}
			out[outi++] = ch;
		}
		out[outi++] = '\n';
		s = 'a';
		while (!l && s != '\n') {
			s = bump[bumpi++];
			if (!s) {
				bumpi--;
				break;
			}
		}
	}
	out[outi] = 0;
	return 1;
}

R_API char* r_print_stereogram(const char *bump, int w, int h) {
	ut64 size;
	char *out;
	if (w < 1 || h < 1) {
		return NULL;
	}
	size = w * (ut64) h * 2;
	if (size > UT32_MAX) {
		return NULL;
	}
	out = calloc (1, size * 2);
	if (!out) {
		return NULL;
	}
	//eprintf ("%s\n", bump);
	(void) r_print_stereogram_private (bump, w, h, out, size);
	return out;
}

#define STEREOGRAM_IN_COLOR 1
R_API char* r_print_stereogram_bytes(const ut8 *buf, int len) {
	int i, bumpi;
	char *ret;
	int scr_width = 80;
	if (!buf || len < 1) {
		return NULL;
	}
	//scr_width = r_cons_get_size (NULL) -10;
	int cols = scr_width;
	int rows = len / cols;

	int size = (2 + cols) * rows;
	char *bump = malloc (size + 1); //(cols+2) * rows);
	if (!bump) {
		return NULL;
	}
	for (i = bumpi = 0; bumpi < size && i < len; i++) {
		int v = buf[i] / 26;
		if (i && !(i % scr_width)) {
			bump[bumpi++] = '\n';
		}
		bump[bumpi++] = '0' + v;
	}
	bump[bumpi] = 0;
	ret = r_print_stereogram (bump, cols, rows);
	free (bump);
	return ret;
}

R_API void r_print_stereogram_print(RPrint *p, const char *ret) {
	int i;
	const int use_color = p->flags & R_PRINT_FLAGS_COLOR;
	if (!ret) {
		return;
	}
	if (use_color) {
		for (i = 0; ret[i]; i++) {
			p->cb_printf ("\x1b[%dm%c", 30 + (ret[i] % 8), ret[i]);
		}
		p->cb_printf ("\x1b[0m\n");
	} else {
		p->cb_printf ("%s\n", ret);
	}
}

R_API RPrint* r_print_new() {
	RPrint *p = R_NEW0 (RPrint);
	if (!p) {
		return NULL;
	}
	strcpy (p->datefmt, "%Y-%m-%d %H:%M:%S %z");
	r_io_bind_init (p->iob);
	p->pairs = true;
	p->cb_printf = libc_printf;
	p->oprintf = nullprinter;
	p->bits = 32;
	p->stride = 0;
	p->bytespace = 0;
	p->interrupt = 0;
	p->big_endian = false;
	p->datezone = 0;
	p->col = 0;
	p->width = 78;
	p->cols = 16;
	p->cur_enabled = false;
	p->cur = p->ocur = -1;
	p->formats = sdb_new0 ();
	p->addrmod = 4;
	p->flags =
		R_PRINT_FLAGS_COLOR |
		R_PRINT_FLAGS_OFFSET |
		R_PRINT_FLAGS_HEADER |
		R_PRINT_FLAGS_ADDRMOD;
	p->zoom = R_NEW0 (RPrintZoom);
	p->reg = NULL;
	p->get_register = NULL;
	p->get_register_value = NULL;
	p->lines_cache = NULL;
	p->calc_row_offsets = true;
	p->row_offsets_sz = 0;
	p->row_offsets = NULL;
	p->vflush = true;
	p->screen_bounds = 0;
	p->esc_bslash = false;
	p->strconv_mode = NULL;
	memset (&p->consbind, 0, sizeof (p->consbind));
	return p;
}

R_API RPrint* r_print_free(RPrint *p) {
	if (!p) {
		return NULL;
	}
	sdb_free (p->formats);
	p->formats = NULL;
	if (p->zoom) {
		free (p->zoom->buf);
		free (p->zoom);
		p->zoom = NULL;
	}
	R_FREE (p->lines_cache);
	R_FREE (p->row_offsets);
	free (p);
	return NULL;
}

// dummy setter can be removed
R_API void r_print_set_flags(RPrint *p, int _flags) {
	p->flags = _flags;
}

R_API void r_print_unset_flags(RPrint *p, int flags) {
	p->flags = p->flags & (p->flags ^ flags);
}

R_API void r_print_set_cursor(RPrint *p, int enable, int ocursor, int cursor) {
	if (!p) {
		return;
	}
	p->cur_enabled = enable;
	p->ocur = ocursor;
	if (cursor < 0) {
		cursor = 0;
	}
	p->cur = cursor;
}

R_API void r_print_cursor(RPrint *p, int cur, int set) {
	if (!p || !p->cur_enabled) {
		return;
	}
	if (p->ocur != -1) {
		int from = p->ocur;
		int to = p->cur;
		r_num_minmax_swap_i (&from, &to);
		if (cur >= from && cur <= to) {
			p->cb_printf ("%s", R_CONS_INVERT (set, 1));
		}
	} else if (cur == p->cur) {
		p->cb_printf ("%s", R_CONS_INVERT (set, 1));
	}
}

R_API void r_print_addr(RPrint *p, ut64 addr) {
	char space[32] = {
		0
	};
	const char *white;
#define PREOFF(x) (p && p->cons && p->cons->pal.x)? p->cons->pal.x
	PrintfCallback printfmt = (PrintfCallback) (p? p->cb_printf: libc_printf);
	bool use_segoff = p? (p->flags & R_PRINT_FLAGS_SEGOFF): false;
	bool use_color = p? (p->flags & R_PRINT_FLAGS_COLOR): false;
	bool dec = p? (p->flags & R_PRINT_FLAGS_ADDRDEC): false;
	bool mod = p? (p->flags & R_PRINT_FLAGS_ADDRMOD): false;
	char ch = p? ((p->addrmod && mod)? ((addr % p->addrmod)? ' ': ','): ' '): ' ';
	if (p && p->flags & R_PRINT_FLAGS_COMPACT && p->col == 1) {
		ch = '|';
	}
	if (use_segoff) {
		ut32 s, a;
		a = addr & 0xffff;
		s = (addr - a) >> 4;
		if (dec) {
			snprintf (space, sizeof (space), "%d:%d", s & 0xffff, a & 0xffff);
			white = r_str_pad (' ', 9 - strlen (space));
		}
		if (use_color) {
			const char *pre = PREOFF (offset): Color_GREEN;
			const char *fin = Color_RESET;
			if (dec) {
				printfmt ("%s%s%s%s%c", pre, white, space, fin, ch);
			} else {
				printfmt ("%s%04x:%04x%s%c", pre, s & 0xffff, a & 0xffff, fin, ch);
			}
		} else {
			if (dec) {
				printfmt ("%s%s%c", white, space, ch);
			} else {
				printfmt ("%04x:%04x%c", s & 0xffff, a & 0xffff, ch);
			}
		}
	} else {
		if (dec) {
			snprintf (space, sizeof (space), "%" PFMT64d, addr);
			int w = R_MAX (10 - strlen (space), 0);
			white = r_str_pad (' ', w);
		}
		if (use_color) {
			const char *pre = PREOFF (offset): Color_GREEN;
			const char *fin = Color_RESET;
			if (p->flags & R_PRINT_FLAGS_RAINBOW) {
				// pre = r_cons_rgb_str_off (rgbstr, addr);
				if (p && p->cons && p->cons->rgbstr) {
					char rgbstr[32];
					pre = p->cons->rgbstr (rgbstr, addr);
				}
			}
			if (dec) {
				printfmt ("%s%s%" PFMT64d "%s%c", pre, white, addr, fin, ch);
			} else {
				printfmt ("%s0x%08" PFMT64x "%s%c", pre, addr, fin, ch);
			}
		} else {
			if (dec) {
				printfmt ("%s%" PFMT64d "%c", white, addr, ch);
			} else {
				printfmt ("0x%08" PFMT64x "%c", addr, ch);
			}
		}
	}
}

R_API char* r_print_hexpair(RPrint *p, const char *str, int n) {
	const char *s, *lastcol = Color_WHITE;
	char *d, *dst = (char *) calloc ((strlen (str) + 2), 32);
	int colors = p->flags & R_PRINT_FLAGS_COLOR;
	const char *color_0x00 = "";
	const char *color_0x7f = "";
	const char *color_0xff = "";
	const char *color_text = "";
	const char *color_other = "";
	int bs = p->bytespace;
	/* XXX That's hacky as shit.. but partially works O:) */
	/* TODO: Use r_print_set_cursor for win support */
	int cur = R_MIN (p->cur, p->ocur);
	int ocur = R_MAX (p->cur, p->ocur);
	int ch, i;

	if (colors) {
#define P(x) (p->cons && p->cons->pal.x)? p->cons->pal.x
		color_0x00 = P (b0x00): Color_GREEN;
		color_0x7f = P (b0x7f): Color_YELLOW;
		color_0xff = P (b0xff): Color_RED;
		color_text = P (btext): Color_MAGENTA;
		color_other = P (other): "";
	}
	if (p->cur_enabled && cur == -1) {
		cur = ocur;
	}
	ocur++;
	d = dst;
// XXX: overflow here
// TODO: Use r_cons primitives here
#define memcat(x, y)\
	{ \
		memcpy (x, y, strlen (y));\
		x += strlen (y);\
	}
	for (s = str, i = 0; s[0]; i++) {
		int d_inc = 2;
		if (p->cur_enabled) {
			if (i == ocur - n) {
				memcat (d, Color_RESET);
			}
			memcat (d, lastcol);
			if (i >= cur - n && i < ocur - n) {
				memcat (d, Color_INVERT);
			}
		}
		if (colors) {
			if (s[0] == '0' && s[1] == '0') {
				lastcol = color_0x00;
			} else if (s[0] == '7' && s[1] == 'f') {
				lastcol = color_0x7f;
			} else if (s[0] == 'f' && s[1] == 'f') {
				lastcol = color_0xff;
			} else {
				ch = r_hex_pair2bin (s);
				if (ch == -1) {
					break;
				}
				if (IS_PRINTABLE (ch)) {
					lastcol = color_text;
				} else {
					lastcol = color_other;
				}
			}
			memcat (d, lastcol);
		}
		if (s[0] == '.') {
			d_inc = 1;
		}
		memcpy (d, s, d_inc);
		d += d_inc;
		s += d_inc;
		if (bs) {
			memcat (d, " ");
		}
	}
	if (colors || p->cur_enabled) {
		memcat (d, Color_RESET);
	}
	*d = '\0';
	return dst;
}

R_API void r_print_byte(RPrint *p, const char *fmt, int idx, ut8 ch) {
	PrintfCallback printfmt = (PrintfCallback) (p? p->cb_printf: libc_printf);
	ut8 rch = ch;
	if (!IS_PRINTABLE (ch) && fmt[0] == '%' && fmt[1] == 'c') {
		rch = '.';
	}
	r_print_cursor (p, idx, 1);
	if (p && p->flags & R_PRINT_FLAGS_COLOR) {
#define P(x) (p->cons && p->cons->pal.x)? p->cons->pal.x
		char *color_0x00 = P (b0x00): Color_GREEN;
		char *color_0x7f = P (b0x7f): Color_YELLOW;
		char *color_0xff = P (b0xff): Color_RED;
		char *color_text = P (btext): Color_MAGENTA;
		char *color_other = P (other): Color_WHITE;
		char *pre = NULL;
		switch (ch) {
		case 0x00:
			pre = color_0x00;
			break;
		case 0x7F:
			pre = color_0x7f;
			break;
		case 0xFF:
			pre = color_0xff;
			break;
		default:
			pre = IS_PRINTABLE (ch)? color_text: color_other;
			break;
		}
		if (pre) {
			printfmt (pre);
		}
		printfmt (fmt, rch);
		if (pre) {
			printfmt (Color_RESET);
		}
	} else {
		printfmt (fmt, rch);
	}
	r_print_cursor (p, idx, 0);
}

R_API int r_print_string(RPrint *p, ut64 seek, const ut8 *buf, int len, int options) {
	int i;
	bool wide = (options & R_PRINT_STRING_WIDE);
	bool wide32 = (options & R_PRINT_STRING_WIDE32);
	bool zeroend = (options & R_PRINT_STRING_ZEROEND);
	bool wrap = (options & R_PRINT_STRING_WRAP);
	bool urlencode = (options & R_PRINT_STRING_URLENCODE);
	p->interrupt = 0;
	int col = 0;
	i = 0;
	if (!urlencode && !wrap) {
		while (buf[i] == '\0' && i < 3 && i < len) {
			i++;
		}
	}
	for (; !p->interrupt && i < len; i++) {
		if (wide32) {
			int j = i;
			while (buf[j] == '\0' && j < (i + 3)) {
				j++;
			}
			i = j;
		}
		if (zeroend && buf[i] == '\0') {
			break;
		}
		r_print_cursor (p, i, 1);
		ut8 b = buf[i];
		if (b == '\n') {
			col = 0;
		}
		col++;
		if (urlencode) {
			// TODO: some ascii can be bypassed here
			p->cb_printf ("%%%02x", b);
		} else {
			if (b == '\n' || IS_PRINTABLE (b)) {
				p->cb_printf ("%c", b);
			} else {
				p->cb_printf ("\\x%02x", b);
			}
		}
		r_print_cursor (p, i, 0);
		if (wrap) {
			if (col + 1 >= p->width) {
				p->cb_printf ("\n");
				col = 0;
			}
		}
		if (wide) {
			i++;
		}
	}
	p->cb_printf ("\n");
	return i;
}

static const char hex[16] = "0123456789ABCDEF";
R_API void r_print_hexpairs(RPrint *p, ut64 addr, const ut8 *buf, int len) {
	int i;
	for (i = 0; i < len; i++) {
		p->cb_printf ("%02x ", buf[i]);
	}
}

static bool checkSparse(const ut8 *p, int len, int ch) {
	int i;
	ut8 q = *p;
	if (ch && ch != q) {
		return false;
	}
	for (i = 1; i < len; i++) {
		if (p[i] != q) {
			return false;
		}
	}
	return true;
}

static bool isAllZeros(const ut8 *buf, int len) {
	int i;
	for (i = 0; i < len; i++) {
		if (buf[i] != 0) {
			return false;
		}
	}
	return true;
}

R_API void r_print_hexii(RPrint *rp, ut64 addr, const ut8 *buf, int len, int step) {
#define Pal(x) (rp->cons && rp->cons->pal.x)? rp->cons->pal.x
	PrintfCallback p = (PrintfCallback) rp->cb_printf;
	bool c = rp->flags & R_PRINT_FLAGS_COLOR;
	const char *color_0xff = c? (Pal (b0xff): Color_RED): "";
	const char *color_text = c? (Pal (btext): Color_MAGENTA): "";
	const char *color_other = c? (Pal (other): Color_WHITE): "";
	const char *color_reset = c? Color_RESET: "";
	int i, j;

	if (rp->flags & R_PRINT_FLAGS_HEADER) {
		p ("         ");
		for (i = 0; i < step; i++) {
			p ("%3X", i);
		}
		p ("\n");
	}

	for (i = 0; i < len; i += step) {
		int inc = R_MIN (step, (len - i));
		if (isAllZeros (buf + i, inc)) {
			continue;
		}
		p ("%8X:", addr + i);
		for (j = 0; j < inc; j++) {
			ut8 ch = buf[i + j];
			if (ch == 0x00) {
				p ("   ");
			} else if (ch == 0xff) {
				p ("%s ##%s", color_0xff, color_reset);
			} else if (IS_PRINTABLE (ch)) {
				p ("%s .%c%s", color_text, ch, color_reset);
			} else {
				p ("%s %02x%s", color_other, ch, color_reset);
			}
		}
		p ("\n");
	}
	p ("%8X ]\n", addr + i);
}

/* set screen_bounds to addr if the cursor is not visible on the screen anymore.
 * Note: screen_bounds is set only the first time this happens. */
R_API void r_print_set_screenbounds(RPrint *p, ut64 addr) {
	int r, rc;

	if (!p || !p->screen_bounds) {
		return;
	}
	if (!p->consbind.get_size) {
		return;
	}
	if (!p->consbind.get_cursor) {
		return;
	}

	(void) p->consbind.get_size (&r);
	(void) p->consbind.get_cursor (&rc);

	if (rc > r - 1 && p->screen_bounds == 1) {
		p->screen_bounds = addr;
	}
}

R_API void r_print_hexdump(RPrint *p, ut64 addr, const ut8 *buf, int len, int base, int step, int zoomsz) {
	PrintfCallback printfmt = (PrintfCallback) printf;
	int i, j, k, inc = 16;
	int sparse_char = 0;
	int stride = 0;
	int col = 0; // selected column (0=none, 1=hex, 2=ascii)
	int use_sparse = 0;
	int use_header = 1;
	int use_offset = 1;
	bool compact = false;
	int use_segoff = 0;
	int pairs = 0;
	const char *fmt = "%02x";
	const char *pre = "";
	int last_sparse = 0;
	bool use_hexa = true;
	const char *a, *b;


	len = len - (len % step);
	if (p) {
		pairs = p->pairs;
		use_sparse = p->flags & R_PRINT_FLAGS_SPARSE;
		use_header = p->flags & R_PRINT_FLAGS_HEADER;
		use_segoff = p->flags & R_PRINT_FLAGS_SEGOFF;
		use_offset = p->flags & R_PRINT_FLAGS_OFFSET;
		use_hexa = !(p->flags & R_PRINT_FLAGS_NONHEX);
		compact = p->flags & R_PRINT_FLAGS_COMPACT;
		inc = p->cols;
		col = p->col;
		printfmt = (PrintfCallback) p->cb_printf;
		stride = p->stride;
	}
	if (!use_hexa) {
		inc *= 4;
	}
	if (step < 1) {
		step = 1;
	}
	if (inc < 1) {
		inc = 1;
	}
	if (zoomsz < 1) {
		zoomsz = 1;
	}
	switch (base) {
	case -10:
		fmt = "0x%08x ";
		pre = " ";
		if (inc < 4) {
			inc = 4;
		}
		break;
	case -1:
		fmt = "0x%08x ";
		pre = "  ";
		if (inc < 4) {
			inc = 4;
		}
		break;
	case 8:
		fmt = "%03o";
		pre = " ";
		break;
	case 10:
		fmt = "%3d";
		pre = " ";
		break;
	case 32:
		fmt = "0x%08x ";
		pre = " ";
		if (inc < 4) {
			inc = 4;
		}
		break;
	case 64:
		fmt = "0x%016x ";
		pre = " ";
		if (inc < 8) {
			inc = 8;
		}
		break;
	}

	// TODO: Use base to change %03o and so on
	if (step == 1 && base < 0) {
		use_header = false;
	}
	if (use_header) {
		if (base < 32) {
			ut32 opad = (ut32) (addr >> 32);
			{ // XXX: use r_print_addr_header
				int i, delta;
				char soff[32];
				if (use_segoff) {
					ut32 s, a;
					a = addr & 0xffff;
					s = ((addr - a) >> 4) & 0xffff;
					snprintf (soff, sizeof (soff), "%04x:%04x ", s, a);
					printfmt ("- offset -");
				} else {
					printfmt ("- offset - ");
					snprintf (soff, sizeof (soff), "0x%08" PFMT64x, addr);
				}
				delta = strlen (soff) - 10;
				if (compact) {
					delta--;
				}
				for (i = 0; i < delta; i++) {
					printfmt (" ");
				}
			}
			/* column after number, before hex data */
			printfmt ((col == 1)? "|": " ");
			opad >>= 4;
			k = 0; // TODO: ??? SURE??? config.seek & 0xF;
			if (use_hexa) {
				/* extra padding for offsets > 8 digits */
				for (i = 0; i < inc; i++) {
					printfmt (pre);
					if (base < 0) {
						if (i & 1) {
							printfmt (" ");
						}
					}
					printfmt (" %c", hex[(i + k) % 16]);
					if (i & 1 || !pairs) {
						if (!compact) {
							printfmt (col != 1? " ": ((i + 1) < inc)? " ": "|");
						}
					}
				}
			}
			/* ascii column */
			if (compact) {
				printfmt (col > 0? "|": " ");
			} else {
				printfmt (col == 2? "|": " ");
			}
			for (i = 0; i < inc; i++) {
				printfmt ("%c", hex[(i + k) % 16]);
			}
			if (col == 2) {
				printfmt ("|");
			}
			/* print comment header*/
			if (p && p->use_comments && !compact) {
				if (col != 2) {
					printfmt (" ");
				}
				printfmt (" comment ");
			}
			printfmt ("\n");
		}
	}

	if (p) {
		p->interrupt = 0;
	}
	for (i = j = 0; i < len; i += (stride? stride: inc), j += (stride? stride: 0)) {
		r_print_set_screenbounds (p, addr + i);
		if (p && p->cons && p->cons->breaked) {
			break;
		}
		if (use_sparse) {
			if (checkSparse (buf + i, inc, sparse_char)) {
				if (i + inc >= len || checkSparse (buf + i + inc, inc, sparse_char)) {
					if (i + inc + inc >= len ||
					checkSparse (buf + i + inc + inc, inc, sparse_char)) {
						sparse_char = buf[j];
						last_sparse++;
						if (last_sparse == 2) {
							printfmt (" ...\n");
							continue;
						}
						if (last_sparse > 2) {
							continue;
						}
					}
				}
			} else {
				last_sparse = 0;
			}
		}
		if (use_offset) {
			r_print_addr (p, addr + j * zoomsz);
		}
		if (use_hexa) {
			if (!compact) {
				printfmt ((col == 1)? "|": " ");
			}
			for (j = i; j < i + inc; j++) {
				if (!compact && j >= len) {
					if (col == 1) {
						if (j + 1 >= inc + i) {
							printfmt (j % 2? "  |": "| ");
						} else {
							printfmt (j % 2? "   ": "  ");
						}
					} else {
						if (base == 32) {
							printfmt ((j%4)? "   ": "  ");
						} else if (base == 10) {
							printfmt (j % 2? "     ": "  ");
						} else {
							printfmt (j % 2? "   ": "  ");
						}
					}
					continue;
				}
				if (p && (base == 32 || base == 64)) {
					int left = len - i;
					/* TODO: check step. it should be 2/4 for base(32) and 8 for
					 *       base(64) */
					ut64 n = 0;
					size_t sz_n;

					if (base == 64) {
						sz_n = sizeof (ut64);
					} else {
						sz_n = step == 2? sizeof (ut16): sizeof (ut32);
					}
					sz_n = R_MIN (left, sz_n);
					r_mem_swaporcopy ((ut8 *) &n, buf + j, sz_n, p && p->big_endian);
					r_print_cursor (p, j, 1);
					// stub for colors
					if (p && p->colorfor) {
						if (!p->iob.addr_is_mapped (p->iob.io, addr + j)) {
							a = p->cons->pal.ai_unmap;
						} else {
							a = p->colorfor (p->user, n, true);
						}
						if (a && *a) {
							b = Color_RESET;
						} else {
							a = b = "";
						}
					} else {
						a = b = "";
					}
					if (base == 64) {
						printfmt ("%s0x%016" PFMT64x "%s  ", a, (ut64) n, b);
					} else if (step == 2) {
						printfmt ("%s0x%04x%s ", a, (ut16) n, b);
					} else {
						printfmt ("%s0x%08x%s ", a, (ut32) n, b);
					}
					r_print_cursor (p, j, 0);
					j += step - 1;
				} else if (base == -8) {
					long long w = r_read_ble64 (buf + j, p && p->big_endian);
					printfmt ("%23" PFMT64d " ", w);
					j += 7;
				} else if (base == -1) {
					st8 w = r_read_ble8 (buf + j);
					printfmt ("%4d ", w);
				} else if (base == -10) {
					st16 w = r_read_ble16 (buf + j, p && p->big_endian);
					printfmt ("%7d ", w);
					j += 1;
				} else if (base == 10) {
					int w = r_read_ble32 (buf + j, p && p->big_endian);
					printfmt ("%13d ", w);
					j += 3;
				} else {
					if (j >= len) {
						break;
					}
					r_print_byte (p, fmt, j, buf[j]);
					if (j % 2 || !pairs) {
						if (col == 1) {
							if (j + 1 < inc + i) {
								if (!compact) {
									printfmt (" ");
								}
							} else {
								printfmt ("|");
							}
						} else {
							if (!compact) {
								printfmt (" ");
							}
						}
					}
				}
			}
		}
		if (compact) {
			if (col == 0) {
				printfmt (" ");
			} else if (col == 1) {
				//printfmt (" ");
			} else {
				printfmt ((col == 2)? "|": "");
			}
		} else {
			printfmt ((col == 2)? "|": " ");
		}
		for (j = i; j < i + inc; j++) {
			if (j >= len) {
				break;
			}
			r_print_byte (p, "%c", j, buf[j]);
		}
		/* ascii column */
		if (col == 2) {
			printfmt ("|");
		}
		if (p && p->flags & R_PRINT_FLAGS_REFS) {
			ut64 *foo = (ut64 *) (buf + i);
			ut64 off = *foo;
			if (base == 32) {
				off &= UT32_MAX;
			}
			if (p->hasrefs) {
				const char *rstr = p->hasrefs (p->user, addr + i, false);
				if (rstr && *rstr) {
					printfmt (" @%s", rstr);
				}
				rstr = p->hasrefs (p->user, off, true);
				if (rstr && *rstr) {
					printfmt ("%s", rstr);
				}
			}
		}
		if (p && p->use_comments) {
			for (; j < i + inc; j++) {
				printfmt (" ");
			}
			for (j = i; j < i + inc; j++) {
				char *comment = p->get_comments (p->user, addr + j);
				if (comment) {
					if (p && p->colorfor) {
						a = p->colorfor (p->user, addr + j, true);
						if (a && *a) {
							b = Color_RESET;
						} else {
							a = b = "";
						}
					} else {
						a = b = "";
					}
					printfmt ("%s  ; %s", a, comment);
					free (comment);
				}
			}
		}
		printfmt ("\n");
	}
}

static const char* getbytediff(char *fmt, ut8 a, ut8 b) {
	if (*fmt) {
		if (a == b) {
			sprintf (fmt, Color_GREEN "%02x" Color_RESET, a);
		} else {
			sprintf (fmt, Color_RED "%02x" Color_RESET, a);
		}
	} else {
		sprintf (fmt, "%02x", a);
	}
	// else sprintf (fmt, "%02x", a);
	return fmt;
}

static const char* getchardiff(char *fmt, ut8 a, ut8 b) {
	char ch = IS_PRINTABLE (a)? a: '.';
	if (*fmt) {
		if (a == b) {
			sprintf (fmt, Color_GREEN "%c" Color_RESET, ch);
		} else {
			sprintf (fmt, Color_RED "%c" Color_RESET, ch);
		}
	} else {
		sprintf (fmt, "%c", ch);
	}
	//else { fmt[0] = ch; fmt[1]=0; }
	return fmt;
}

#define BD(a, b) getbytediff (fmt, a[i + j], b[i + j])
#define CD(a, b) getchardiff (fmt, a[i + j], b[i + j])

static ut8* M(const ut8 *b, int len) {
	ut8 *r = malloc (len + 16);
	if (!r) {
		return NULL;
	}
	memset (r, 0xff, len + 16);
	memcpy (r, b, len);
	return r;
}

// TODO: add support for cursor
R_API void r_print_hexdiff(RPrint *p, ut64 aa, const ut8 *_a, ut64 ba, const ut8 *_b, int len, int scndcol) {
	ut8 *a, *b;
	char linediff, fmt[64];
	int color = p->flags & R_PRINT_FLAGS_COLOR;
	int diffskip = p->flags & R_PRINT_FLAGS_DIFFOUT;
	int i, j, min;
	if (!((a = M (_a, len)))) {
		return;
	}
	if (!((b = M (_b, len)))) {
		free (a);
		return;
	}
	for (i = 0; i < len; i += 16) {
		min = R_MIN (16, len - i);
		linediff = (memcmp (a + i, b + i, min))? '!': '|';
		if (diffskip && linediff == '|') {
			continue;
		}
		p->cb_printf ("0x%08" PFMT64x " ", aa + i);
		for (j = 0; j < min; j++) {
			*fmt = color;
			r_print_cursor (p, i + j, 1);
			p->cb_printf (BD (a, b));
			r_print_cursor (p, i + j, 0);
		}
		p->cb_printf (" ");
		for (j = 0; j < min; j++) {
			*fmt = color;
			r_print_cursor (p, i + j, 1);
			p->cb_printf ("%s", CD (a, b));
			r_print_cursor (p, i + j, 0);
		}
		if (scndcol) {
			p->cb_printf (" %c 0x%08" PFMT64x " ", linediff, ba + i);
			for (j = 0; j < min; j++) {
				*fmt = color;
				r_print_cursor (p, i + j, 1);
				p->cb_printf (BD (b, a));
				r_print_cursor (p, i + j, 0);
			}
			p->cb_printf (" ");
			for (j = 0; j < min; j++) {
				*fmt = color;
				r_print_cursor (p, i + j, 1);
				p->cb_printf ("%s", CD (b, a));
				r_print_cursor (p, i + j, 0);
			}
			p->cb_printf ("\n");
		} else {
			p->cb_printf (" %c\n", linediff);
		}
	}
	free (a);
	free (b);
}

R_API void r_print_bytes(RPrint *p, const ut8 *buf, int len, const char *fmt) {
	int i;
	if (p) {
		for (i = 0; i < len; i++) {
			p->cb_printf (fmt, buf[i]);
		}
		p->cb_printf ("\n");
	} else {
		for (i = 0; i < len; i++) {
			printf (fmt, buf[i]);
		}
		printf ("\n");
	}
}

R_API void r_print_raw(RPrint *p, ut64 addr, const ut8 *buf, int len, int offlines) {
	if (offlines == 2) {
		int i, j, cols = p->cols * 4;
		char ch;
		for (i = 0; i < len; i += cols) {
			p->cb_printf ("0x%08x  ", addr + i);
			for (j = 0; j < cols; j++) {
				if ((i + j) >= len) {
					break;
				}
				ch = buf[i + j];
				if (p->cur_enabled) {
					r_print_cursor (p, i + j, 1);
					p->cb_printf ("%c", IS_PRINTABLE (ch)? ch: ' ');
					r_print_cursor (p, i + j, 0);
				} else {
					p->cb_printf ("%c", IS_PRINTABLE (ch)? ch: ' ');
				}
			}
			p->cb_printf ("\n");
		}
	} else if (offlines) {
		const ut8 *o, *q;
		ut64 off;
		int i, linenum_abs, mustbreak = 0, linenum = 1;
		o = q = buf;
		i = 0;
		do {
			off = addr + (int) (size_t) (q - buf);
			linenum_abs = r_util_lines_getline (p->lines_cache, p->lines_cache_sz, off);
			if (p->lines_cache_sz > 0 && p->lines_abs) {
				p->cb_printf ("%d 0x%08" PFMT64x " ", linenum_abs, off);
			} else {
				p->cb_printf ("+%d 0x%08" PFMT64x " ", linenum, off);
			}
			for (; i < len && *q && *q != '\n'; q++, i++) {
				// just loop
			}
			if ((i + 1) >= len || !*q) {
				mustbreak = 1;
			}
			if ((q - o) > 0) {
				p->write (o, (int) (size_t) (q - o));
			}
			p->cb_printf ("\n");
			linenum++;
			o = ++q;
			i++;
		} while (!mustbreak);
	} else {
		p->write (buf, len);
	}
}

R_API void r_print_c(RPrint *p, const ut8 *str, int len) {
	int i, inc = p->width / 6;
	p->cb_printf ("#define _BUFFER_SIZE %d\n"
	"unsigned char buffer[_BUFFER_SIZE] = {\n",
	len);
	p->interrupt = 0;
	for (i = 0; !p->interrupt && i < len;) {
		r_print_byte (p, "0x%02x", i, str[i]);
		if (++i < len) {
			p->cb_printf (", ");
		}
		if (!(i % inc)) {
			p->cb_printf ("\n");
		}
	}
	p->cb_printf (" };\n");
}

// HACK :D
static RPrint staticp = {
	.cb_printf = libc_printf
};

/* TODO: handle screen width */
R_API void r_print_progressbar(RPrint *p, int pc, int _cols) {
	// TODO: add support for colors
	int i, cols = (_cols == -1)? 78: _cols;
	if (!p) {
		p = &staticp;
	}
	pc = R_MAX (0, R_MIN (100, pc));
	if (p->flags & R_PRINT_FLAGS_HEADER) {
		p->cb_printf ("%4d%% ", pc);
	}
	cols -= 15;
	p->cb_printf ("[");
	for (i = cols * pc / 100; i; i--) {
		p->cb_printf ("#");
	}
	for (i = cols - (cols * pc / 100); i; i--) {
		p->cb_printf ("-");
	}
	p->cb_printf ("]");
}

R_API void r_print_rangebar(RPrint *p, ut64 startA, ut64 endA, ut64 min, ut64 max, int cols) {
	const bool show_colors = p->flags & R_PRINT_FLAGS_COLOR;
	int j = 0;
	p->cb_printf ("|");
	if (cols < 1) {
		cols = 1;
	}
	int mul = (max - min) / cols;
	bool isFirst = true;
	for (j = 0; j < cols; j++) {
		ut64 startB = min + (j * mul);
		ut64 endB = min + ((j + 1) * mul);
		if (startA <= endB && endA >= startB) {
			if (show_colors & isFirst) {
				p->cb_printf (Color_GREEN "#");
				isFirst = false;
			} else {
				p->cb_printf ("#");
			}
		} else {
			if (isFirst) {
				p->cb_printf ("-");
			} else {
				p->cb_printf (Color_RESET "-");
				isFirst = true;
			}
		}
	}
	p->cb_printf ("|");
}

R_API void r_print_zoom(RPrint *p, void *user, RPrintZoomCallback cb, ut64 from, ut64 to, int len, int maxlen) {
	static int mode = -1;
	ut8 *bufz = NULL, *bufz2 = NULL;
	int i, j = 0;
	ut64 size = (to - from);
	size = len? size / len: 0;

	if (maxlen < 2) {
		maxlen = 1024 * 1024;
	}
	if (size > maxlen) {
		size = maxlen;
	}
	if (size < 1) {
		size = 1;
	}
	if (len < 1) {
		len = 1;
	}

	if (mode == p->zoom->mode && from == p->zoom->from && to == p->zoom->to && size == p->zoom->size) {
		// get from cache
		bufz = p->zoom->buf;
		size = p->zoom->size;
	} else {
		mode = p->zoom->mode;
		bufz = (ut8 *) calloc (1, len);
		if (!bufz) {
			return;
		}
		bufz2 = (ut8 *) calloc (1, size);
		if (!bufz2) {
			free (bufz);
			return;
		}

		// TODO: memoize blocks or gtfo
		for (i = 0; i < len; i++) {
			p->iob.read_at (p->iob.io, from + j, bufz2, size);
			bufz[i] = cb (user, p->zoom->mode, from + j, bufz2, size);
			j += size;
		}
		free (bufz2);
		// memoize
		free (p->zoom->buf);
		p->zoom->buf = bufz;
		p->zoom->from = from;
		p->zoom->to = to;
		p->zoom->size = len; // size;
	}
	p->flags &= ~R_PRINT_FLAGS_HEADER;
	r_print_hexdump (p, from, bufz, len, 16, 1, size);
	p->flags |= R_PRINT_FLAGS_HEADER;
}

R_API void r_print_fill(RPrint *p, const ut8 *arr, int size, ut64 addr, int step) {
	if (!p || !arr) {
		return;
	}
	const bool show_colors = (p && (p->flags & R_PRINT_FLAGS_COLOR));
	char *firebow[6];
	int i = 0, j;

	for (i = 0; i < 6; i++) {
		firebow[i] = p->cb_color (i, 6, true);
	}
#define INC 5
#if TOPLINE
	if (arr[0] > 1) {
		p->cb_printf ("         ");
		if (addr != UT64_MAX && step > 0) {
			p->cb_printf ("           ");
		}
		if (arr[0] > 1) {
			for (i = 0; i < arr[0]; i += INC) {
				p->cb_printf ("_");
			}
		}
		p->cb_printf ("\n");
	}
#endif
	for (i = 0; i < size; i++) {
		ut8 next = (i + 1 < size)? arr[i + 1]: 0;
		int base = 0;
		if (addr != UT64_MAX && step > 0) {
			ut64 at = addr + (i * step);
			if (p->cur_enabled) {
				if (i == p->cur) {
					p->cb_printf (Color_INVERT"> 0x%08" PFMT64x " "Color_RESET, at);
					if (p->num) {
						p->num->value = at;
					}
				} else {
					p->cb_printf ("  0x%08" PFMT64x " ", at);
				}
			} else {
				p->cb_printf ("0x%08" PFMT64x " ", at);
			}
			p->cb_printf ("%02x %04x |", i, arr[i]);
		} else {
			p->cb_printf ("|");
		}
		if (show_colors) {
			int idx = (int) (arr[i] * 5 / 255);
			const char *k = firebow[idx];
			p->cb_printf ("%s", k);
		}
		if (next < INC) {
			base = 1;
		}
		if (next < arr[i]) {
			//if (arr[i]>0 && i>0) p->cb_printf ("  ");
			if (arr[i] > INC) {
				for (j = 0; j < next + base; j += INC) p->cb_printf (i? " ": "'");
			}
			for (j = next + INC; j + base < arr[i]; j += INC) p->cb_printf ("_");
		} else {
			if (i == 0) {
				for (j = INC; j < arr[i] + base; j += INC) p->cb_printf ("'");
			} else {
				for (j = INC; j < arr[i] + base; j += INC) p->cb_printf (" ");
			}
		}
		//for (j=1;j<arr[i]; j+=INC) p->cb_printf (under);
		if (show_colors) {
			p->cb_printf ("|" Color_RESET);
		} else {
			p->cb_printf ("|");
		}
		if (i + 1 == size) {
			for (j = arr[i] + INC + base; j + base < next; j += INC) {
				p->cb_printf ("_");
			}
		} else if (arr[i + 1] > arr[i]) {
			for (j = arr[i] + INC + base; j + base < next; j += INC) {
				p->cb_printf ("_");
			}
		}
		p->cb_printf ("\n");
	}
	for (i = 0; i < 6; i++) {
		free (firebow[i]);
	}
}

R_API void r_print_2bpp_row(RPrint *p, ut8 *buf) {
	const bool useColor = p? (p->flags & R_PRINT_FLAGS_COLOR): false;
	int i, c = 0;
	for (i = 0; i < 8; i++) {
		if (buf[1] & ((1 << 7) >> i)) {
			c = 2;
		}
		if (buf[0] & ((1 << 7) >> i)) {
			c++;
		}
		if (useColor) {
			char *color = "";
			switch (c) {
			case 0:
				color = Color_BGWHITE;
				break;
			case 1:
				color = Color_BGRED;
				break;
			case 2:
				color = Color_BGBLUE;
				break;
			case 3:
				color = Color_BGBLACK;
				break;
			}
			if (p) {
				p->cb_printf ("%s  ", color);
			} else {
				printf ("%s  ", color);
			}
		} else {
			const char *chstr = "#=-.";
			const char ch = chstr[c % 4];
			if (p) {
				p->cb_printf ("%c%c", ch, ch);
			} else {
				printf ("%c%c", ch, ch);
			}
		}
		c = 0;
	}
}

R_API void r_print_2bpp_tiles(RPrint *p, ut8 *buf, ut32 tiles) {
	int i, r;
	const bool useColor = p? (p->flags & R_PRINT_FLAGS_COLOR): false;
	for (i = 0; i < 8; i++) {
		for (r = 0; r < tiles; r++) {
			r_print_2bpp_row (p, buf + 2 * i + r * 16);
		}
		if (p) {
			if (useColor) {
				p->cb_printf (Color_RESET "\n");
			} else {
				p->cb_printf ("\n");
			}
		} else {
			printf ("\n");
		}
	}
}

R_API const char* r_print_color_op_type(RPrint *p, ut64 anal_type) {
	switch (anal_type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_NOP:
		return p->cons->pal.nop;
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_MUL:
	case R_ANAL_OP_TYPE_DIV:
	case R_ANAL_OP_TYPE_MOD:
	case R_ANAL_OP_TYPE_LENGTH:
		return p->cons->pal.math;
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_OR:
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_NOT:
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SAL:
	case R_ANAL_OP_TYPE_SAR:
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_ROL:
	case R_ANAL_OP_TYPE_ROR:
	case R_ANAL_OP_TYPE_CPL:
		return p->cons->pal.bin;
	case R_ANAL_OP_TYPE_IO:
		return p->cons->pal.swi;
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_IJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_IRJMP:
	case R_ANAL_OP_TYPE_MJMP:
		return p->cons->pal.jmp;
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_UCJMP:
	case R_ANAL_OP_TYPE_SWITCH:
		return p->cons->pal.cjmp;
	case R_ANAL_OP_TYPE_CMP:
	case R_ANAL_OP_TYPE_ACMP:
		return p->cons->pal.cmp;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_IRCALL:
	case R_ANAL_OP_TYPE_UCCALL:
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_CCALL:
		return p->cons->pal.call;
	case R_ANAL_OP_TYPE_NEW:
	case R_ANAL_OP_TYPE_SWI:
		return p->cons->pal.swi;
	case R_ANAL_OP_TYPE_ILL:
	case R_ANAL_OP_TYPE_TRAP:
		return p->cons->pal.trap;
	case R_ANAL_OP_TYPE_CRET:
	case R_ANAL_OP_TYPE_RET:
		return p->cons->pal.ret;
	case R_ANAL_OP_TYPE_CAST:
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_CMOV: // TODO: add cmov cathegory?
		return p->cons->pal.mov;
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_UPUSH:
	case R_ANAL_OP_TYPE_LOAD:
		return p->cons->pal.push;
	case R_ANAL_OP_TYPE_POP:
	case R_ANAL_OP_TYPE_STORE:
		return p->cons->pal.pop;
	case R_ANAL_OP_TYPE_CRYPTO:
		return p->cons->pal.crypto;
	case R_ANAL_OP_TYPE_NULL:
		return p->cons->pal.other;
	case R_ANAL_OP_TYPE_UNK:
	default:
		return p->cons->pal.invalid;
	}
}

// Global buffer to speed up colorizing performance
#define COLORIZE_BUFSIZE 1024
static char o[COLORIZE_BUFSIZE];

static bool issymbol(char c) {
	switch (c) {
	case '+':
	case '-':
	/* case '/': not good for dalvik */
	case '>':
	case '<':
	case '(':
	case ')':
	case '*':
	case '%':
	case ']':
	case '[':
	case ',':
	case ' ':
	case '{':
	case '}':
		return true;
	default:
		return false;
	}
}

R_API char* r_print_colorize_opcode(RPrint *print, char *p, const char *reg, const char *num, bool partial_reset) {
	int i, j, k, is_mod, is_float = 0, is_arg = 0;
	char *reset = partial_reset ? Color_NOBGRESET:Color_RESET;
	ut32 c_reset = strlen (reset);
	int is_jmp = p && (*p == 'j' || ((*p == 'c') && (p[1] == 'a')))? 1: 0;
	ut32 opcode_sz = p && *p? strlen (p) * 10 + 1: 0;
	char previous = '\0';

	if (!p || !*p) {
		return NULL;
	}
	if (is_jmp) {
		return strdup (p);
	}
	if (opcode_sz > COLORIZE_BUFSIZE) {
		/* return same string in case of error */
		return strdup (p);
	}

	memset (o, 0, COLORIZE_BUFSIZE);
	for (i = j = 0; p[i]; i++, j++) {
		/* colorize numbers */
		if ((p[i] == '0' && p[i+1] == 'x') || (isdigit (p[i]) && issymbol (previous))) {
			int nlen = strlen (num);
			if (nlen + j >= sizeof (o)) {
				eprintf ("Colorize buffer is too small\n");
				break;
			}
			memcpy (o + j, num, nlen + 1);
			j += nlen;
		}
		previous = p[i];
		if (j + 100 >= COLORIZE_BUFSIZE) {
			eprintf ("r_print_colorize_opcode(): buffer overflow!\n");
			return strdup (p);
		}
		switch (p[i]) {
		// We dont need to skip ansi codes.
		// original colors must be preserved somehow
		case 0x1b:
#define STRIP_ANSI 1
#if STRIP_ANSI
			/* skip until 'm' */
			for (++i; p[i] && p[i] != 'm'; i++) {
				o[j] = p[i];
			}
			j--;
			continue;
#else
			/* copy until 'm' */
			for (; p[i] && p[i] != 'm'; i++) {
				o[j++] = p[i];
			}
			o[j++] = p[i++];
#endif
		case '+':
		case '-':
		case '/':
		case '>':
		case '<':
		case '(':
		case ')':
		case '*':
		case '%':
		case ']':
		case '[':
		case ',':
			/* ugly trick for dalvik */
			if (is_float) {
				/* do nothing, keep going until next */
				is_float = 0;
			} else if (is_arg) {
				if (c_reset + j + 10 >= COLORIZE_BUFSIZE) {
					eprintf ("r_print_colorize_opcode(): buffer overflow!\n");
					return strdup (p);
				}
				strcpy (o + j, reset);
				j += strlen (reset);
				o[j] = p[i];
				if (!(p[i+1] == '$' || ((p[i+1] > '0') && (p[i+1] < '9')))) {
					ut32 reg_len = strlen (reg);
					if (reg_len + j + 10 >= COLORIZE_BUFSIZE) {
						eprintf ("r_print_colorize_opcode(): buffer overflow!\n");
						return strdup (p);
					}
					strcpy (o + j + 1, reg);
					j += strlen (reg);
				}
				continue;
			}
			break;
		case ' ':
			is_arg = 1;
			// find if next ',' before ' ' is found
			is_mod = 0;
			is_float = 0;
			for (k = i + 1; p[k]; k++) {
				if (p[k] == 'e' && p[k + 1] == '+') {
					is_float = 1;
					break;
				}
				if (p[k] == ' ') {
					break;
				}
				if (p[k] == ',') {
					is_mod = 1;
					break;
				}
			}
			if (is_float) {
				strcpy (o + j, num);
				j += strlen (num);
			}
			if (!p[k]) {
				is_mod = 1;
			}
			if (is_mod) {
				// COLOR FOR REGISTER
				ut32 reg_len = strlen (reg);
				/* if (reg_len+j+10 >= opcode_sz) o = realloc_color_buffer (o, &opcode_sz, reg_len+100); */
				if (reg_len + j + 10 >= COLORIZE_BUFSIZE) {
					eprintf ("r_print_colorize_opcode(): buffer overflow!\n");
					return strdup (p);
				}
				strcpy (o + j, reg);
				j += strlen (reg);
			}
			break;
		case '0': /* address */
			if (p[i + 1] == 'x') {
				if (print->flags & R_PRINT_FLAGS_SECSUB) {
					RIOSection *s = NULL;
					SdbList *secs = print->iob.sections_vget (print->iob.io, r_num_get (NULL, p + i));
					if (secs) {
						s = (RIOSection *)ls_pop (secs);
						secs->free = NULL;
						ls_free (secs);
						secs = NULL;
					}
					if (s) {
						if (strlen (s->name) + j + 1 >= COLORIZE_BUFSIZE) {
							eprintf ("stop before overflow\n");
							break;
						}
						strcpy (o + j, s->name);
						j += strlen (o + j);
						strcpy (o + j, ".");
						j++;
					}
				}
			}
			break;
		}
		o[j] = p[i];
	}
	// decolorize at the end
	if (j + 20 >= opcode_sz) {
		char *t_o = o;
		/* o = malloc (opcode_sz+21); */
		memmove (o, t_o, opcode_sz);
		opcode_sz += 21;
		/* free (t_o); */
	}
	strcpy (o + j, reset);
	//strcpy (p, o); // may overflow .. but shouldnt because asm.buf_asm is big enought
	return strdup (o);
}

// reset the status of row_offsets
R_API void r_print_init_rowoffsets(RPrint *p) {
	if (p->calc_row_offsets) {
		R_FREE(p->row_offsets);
		p->row_offsets_sz = 0;
	}
}

// set the offset, from the start of the printing, of the i-th row
R_API void r_print_set_rowoff(RPrint *p, int i, ut32 offset, bool overwrite) {
	if (!overwrite) {
		return;
	}
	if (i < 0) {
		return;
	}
	if (!p->row_offsets || !p->row_offsets_sz) {
		p->row_offsets_sz = R_MAX (i + 1, DFLT_ROWS);
		p->row_offsets = R_NEWS (ut32, p->row_offsets_sz);
	}
	if (i >= p->row_offsets_sz) {
		size_t new_size;
		p->row_offsets_sz *= 2;
		//XXX dangerous
		while (i >= p->row_offsets_sz) {
			p->row_offsets_sz *= 2;
		}
		new_size = sizeof (ut32) * p->row_offsets_sz;
		p->row_offsets = realloc (p->row_offsets, new_size);
	}
	p->row_offsets[i] = offset;
}

// return the offset, from the start of the printing, of the i-th row.
// if the line index is not valid, UT32_MAX is returned.
R_API ut32 r_print_rowoff(RPrint *p, int i) {
	if (i < 0 || i >= p->row_offsets_sz) {
		return UT32_MAX;
	}
	return p->row_offsets[i];
}

// return the index of the row that contains the given offset or -1 if
// that row doesn't exist.
R_API int r_print_row_at_off(RPrint *p, ut32 offset) {
	int i = 0;
	ut32 tt;

	while ((tt = r_print_rowoff (p, i)) != UT32_MAX && tt <= offset) {
		i++;
	}
	return tt != UT32_MAX? i - 1: -1;
}

R_API int r_print_get_cursor(RPrint *p) {
	return p->cur_enabled? p->cur: 0;
}

R_API int r_print_jsondump(RPrint *p, const ut8 *buf, int len, int wordsize) {
	ut16 *buf16 = (ut16*) buf;
	ut32 *buf32 = (ut32*) buf;
	ut64 *buf64 = (ut64*) buf;
	// TODDO: support p==NULL too
	if (!p || !buf || len < 1 || wordsize < 1) {
		return 0;
	}
	int bytesize = wordsize / 8;
	if (bytesize < 1) {
		bytesize = 8;
	}
	int i, words = (len / bytesize);
	p->cb_printf ("[");
	for (i = 0; i < words; i++) {
		switch (wordsize) {
		case 8: {
			p->cb_printf ("%s%d", i ? "," : "", buf[i]);
			break;
		}
		case 16: {
			ut16 w16 = r_read_ble16 (&buf16[i], p->big_endian);
			p->cb_printf ("%s%hd", i ? "," : "", w16);
			break;
		}
		case 32: {
			ut32 w32 = r_read_ble32 (&buf32[i], p->big_endian);
			p->cb_printf ("%s%d", i ? "," : "", w32);
			break;
		}
		case 64: {
			ut64 w64 = r_read_ble64 (&buf64[i], p->big_endian);
			p->cb_printf ("%s%"PFMT64d, i ? "," : "", w64);
			break;
		}
		}
	}
	p->cb_printf ("]\n");
	return words;
}

R_API void r_print_hex_from_bin (RPrint *p, char *bin_str) {
	int i, j, index;
	RPrint myp = {.cb_printf = libc_printf};
	const int len = strlen (bin_str);
	ut64 n, *buf = malloc (sizeof (ut64) * ((len + 63) / 64));
	if (buf == NULL) {
		eprintf ("allocation failed\n");
		return;
	}
	if (!p) {
		p = &myp;
	}
	for (i = len - 1, index = 0; i >= 0; i -= 64, index++) {
		n = 0;
		for (j = 0; j < 64 && i - j >= 0; j++) {
			n += (ut64) (bin_str[i - j] - '0') << j;
		}
		buf[index] = n;
	}
	index--;
	p->cb_printf ("0x");
	while (buf[index] == 0 && index > 0) {
		index--;
	}
	p->cb_printf ("%" PFMT64x, buf[index]);
	index--;
	for (i = index; i >= 0; i--) {
		p->cb_printf ("%016" PFMT64x, buf[i]);
	}
	p->cb_printf ("\n");
	free (buf);
}

/* radare - LGPL - Copyright 2007-2020 - pancake */

#include <r_util/r_print.h>
#include <r_anal.h>

#define DFLT_ROWS 16

static const char hex[16] = "0123456789ABCDEF";

static int nullprinter(const char *a, ...) {
	return 0;
}

static int libc_printf(const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	vprintf (format, ap);
	va_end (ap);
	return 0;
}

static int libc_eprintf(const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	vfprintf (stderr, format, ap);
	va_end (ap);
	return 0;
}

static RPrintIsInterruptedCallback is_interrupted_cb = NULL;

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

R_API void r_print_columns(RPrint *p, const ut8 *buf, int len, int height) {
#define cb_print(x) p->cb_printf("%s", x)
	size_t i, j;
	int cols = 78; // TODO: do not hardcode this value, columns should be defined by the user
	int rows = height > 0 ? height : 10;
	// int realrows = rows * 2;
	bool colors = p->flags & R_PRINT_FLAGS_COLOR;
	RConsPrintablePalette *pal = &p->cons->context->pal;
	const char *vline = p->cons->use_utf8 ? RUNE_LINE_VERT : "|";
	const char *block = p->cons->use_utf8 ? UTF_BLOCK : "#";
	const char *kol[5];
	kol[0] = pal->call;
	kol[1] = pal->jmp;
	kol[2] = pal->cjmp;
	kol[3] = pal->mov;
	kol[4] = pal->nop;
	if (colors) {
		for (i = 0; i < rows; i++) {
			size_t threshold = i * (0xff / rows);
			size_t koli = i * 5 / rows;
			for (j = 0; j < cols; j++) {
				int realJ = j * len / cols;
	 			if (255 - buf[realJ] < threshold || (i + 1 == rows)) {
					if (p->histblock) {
						p->cb_printf ("%s%s%s", kol[koli], block, Color_RESET);
					} else {
						p->cb_printf ("%s%s%s", kol[koli], vline, Color_RESET);
					}
				} else {
					cb_print (" ");
				}
			}
			cb_print ("\n");
		}
		return;
	}

	for (i = 0; i < rows; i++) {
		size_t threshold = i * (0xff / rows);
		for (j = 0; j < cols; j++) {
			size_t realJ = j * len / cols;
			if (255 - buf[realJ] < threshold) {
				if (p->histblock) {
					p->cb_printf ("%s%s%s", Color_BGGRAY, block, Color_RESET);
				} else {
					cb_print (vline);
				}
			} else if (i + 1 == rows) {
				cb_print ("_");
			} else {
				cb_print (" ");
			}
		}
		cb_print ("\n");
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

R_API bool r_print_is_interrupted(void) {
	if (is_interrupted_cb) {
		return is_interrupted_cb ();
	}
	return false;
}

R_API void r_print_set_is_interrupted_cb(RPrintIsInterruptedCallback cb) {
	is_interrupted_cb = cb;
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
	if (w < 1 || h < 1) {
		return NULL;
	}
	ut64 size = w * (ut64) h * 2;
	if (size > UT32_MAX) {
		return NULL;
	}
	char *out = calloc (1, size * 2);
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

R_API RPrint* r_print_new(void) {
	RPrint *p = R_NEW0 (RPrint);
	if (!p) {
		return NULL;
	}
	strcpy (p->datefmt, "%Y-%m-%d %H:%M:%S %z");
	r_io_bind_init (p->iob);
	p->pairs = true;
	p->resetbg = true;
	p->cb_printf = libc_printf;
	p->cb_eprintf = libc_eprintf;
	p->oprintf = nullprinter;
	p->bits = 32;
	p->stride = 0;
	p->bytespace = 0;
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
	p->seggrn = 4;
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
	p->io_unalloc_ch = '.';
	p->enable_progressbar = true;
	p->charset = r_charset_new ();
	return p;
}

R_API RPrint* r_print_free(RPrint *p) {
	if (!p) {
		return NULL;
	}
	sdb_free (p->formats);
	p->formats = NULL;
	R_FREE (p->strconv_mode);
	if (p->zoom) {
		free (p->zoom->buf);
		free (p->zoom);
		p->zoom = NULL;
	}
	R_FREE (p->lines_cache);
	R_FREE (p->row_offsets);
	r_charset_free (p->charset);
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

R_API bool r_print_have_cursor(RPrint *p, int cur, int len) {
	if (!p || !p->cur_enabled) {
		return false;
	}
	if (p->ocur != -1) {
		int from = p->ocur;
		int to = p->cur;
		r_num_minmax_swap_i (&from, &to);
		do {
			if (cur + len - 1 >= from && cur + len - 1 <= to) {
				return true;
			}
		} while (--len);
	} else if (p->cur >= cur && p->cur <= cur + len - 1) {
		return true;
	}
	return false;
}

R_API bool r_print_cursor_pointer(RPrint *p, int cur, int len) {
	r_return_val_if_fail (p, false);
	if (!p->cur_enabled) {
		return false;
	}
	int to = p->cur;
	do {
		if (cur + len - 1 == to) {
			return true;
		}
	} while (--len);
	return false;
}

R_API void r_print_cursor(RPrint *p, int cur, int len, int set) {
	if (r_print_have_cursor (p, cur, len)) {
		p->cb_printf ("%s", R_CONS_INVERT (set, 1));
	}
}

R_API void r_print_addr(RPrint *p, ut64 addr) {
	char space[32] = {
		0
	};
	const char *white = "";
#define PREOFF(x) (p && p->cons && p->cons->context && p->cons->context->pal.x)? p->cons->context->pal.x
	PrintfCallback printfmt = (PrintfCallback) (p? p->cb_printf: libc_printf);
#define print(x) printfmt("%s", x)
	bool use_segoff = p? (p->flags & R_PRINT_FLAGS_SEGOFF): false;
	bool use_color = p? (p->flags & R_PRINT_FLAGS_COLOR): false;
	bool dec = p? (p->flags & R_PRINT_FLAGS_ADDRDEC): false;
	bool mod = p? (p->flags & R_PRINT_FLAGS_ADDRMOD): false;
	char ch = p? ((p->addrmod && mod)? ((addr % p->addrmod)? ' ': ','): ' '): ' ';
	if (p && p->flags & R_PRINT_FLAGS_COMPACT && p->col == 1) {
		ch = '|';
	}
	if (p && p->pava) {
		ut64 va = p->iob.p2v (p->iob.io, addr);
		if (va != UT64_MAX) {
			addr = va;
		}
	}
	if (use_segoff) {
		ut32 s, a;
		a = addr & 0xffff;
		s = (addr - a) >> (p? p->seggrn: 0);
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
			if (p && p->flags & R_PRINT_FLAGS_RAINBOW) {
				// pre = r_cons_rgb_str_off (rgbstr, addr);
				if (p->cons && p->cons->rgbstr) {
					static char rgbstr[32];
					pre = p->cons->rgbstr (rgbstr, sizeof (rgbstr), addr);
				}
			}
			if (dec) {
				printfmt ("%s%s%" PFMT64d "%s%c", pre, white, addr, fin, ch);
			} else {
				if (p && p->wide_offsets) {
					// TODO: make %016 depend on asm.bits
					printfmt ("%s0x%016" PFMT64x "%s%c", pre, addr, fin, ch);
				} else {
					printfmt ("%s0x%08" PFMT64x "%s%c", pre, addr, fin, ch);
				}
			}
		} else {
			if (dec) {
				printfmt ("%s%" PFMT64d "%c", white, addr, ch);
			} else {
				if (p && p->wide_offsets) {
					// TODO: make %016 depend on asm.bits
					printfmt ("0x%016" PFMT64x "%c", addr, ch);
				} else {
					printfmt ("0x%08" PFMT64x "%c", addr, ch);
				}
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
#define P(x) (p->cons && p->cons->context->pal.x)? p->cons->context->pal.x
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
		(x) += strlen (y);\
	}
	for (s = str, i = 0; s[0]; i++) {
		int d_inc = 2;
		if (p->cur_enabled) {
			if (i == ocur - n) {
				memcat (d, Color_RESET);
			}
			if (colors) {
				memcat (d, lastcol);
			}
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
		if (p->resetbg) {
			memcat (d, Color_RESET);
		} else {
			memcat (d, Color_RESET_NOBG);
		}
	}
	*d = '\0';
	return dst;
}

static char colorbuffer[64];
#define P(x) (p->cons && p->cons->context->pal.x)? p->cons->context->pal.x
R_API const char *r_print_byte_color(RPrint *p, int ch) {
	if (p->flags & R_PRINT_FLAGS_RAINBOW) {
		// EXPERIMENTAL
		int bg = (p->flags & R_PRINT_FLAGS_NONHEX)? 48: 38;
		snprintf (colorbuffer, sizeof (colorbuffer), "\033[%d;5;%dm", bg, ch);
		return colorbuffer;
	}
	const bool use_color = p->flags & R_PRINT_FLAGS_COLOR;
	if (!use_color) {
		return NULL;
	}
	switch (ch) {
	case 0x00: return P (b0x00): Color_GREEN;
	case 0x7F: return P (b0x7f): Color_YELLOW;
	case 0xFF: return P (b0xff): Color_RED;
	default: return IS_PRINTABLE (ch)? P (btext): Color_MAGENTA: P (other): Color_WHITE;
	}
	return NULL;
}

R_API void r_print_byte(RPrint *p, const char *fmt, int idx, ut8 ch) {
	PrintfCallback printfmt = (PrintfCallback) (p? p->cb_printf: libc_printf);
	#define print(x) printfmt("%s", x)
	ut8 rch = ch;
	if (!IS_PRINTABLE (ch) && fmt[0] == '%' && fmt[1] == 'c') {
		rch = '.';
	}
	r_print_cursor (p, idx, 1, 1);
	if (p && p->flags & R_PRINT_FLAGS_COLOR) {
		const char *bytecolor = r_print_byte_color (p, ch);
		if (bytecolor) {
			print ( bytecolor);
		}
		printfmt (fmt, rch);
		if (bytecolor) {
			print (Color_RESET);
		}
	} else {
		printfmt (fmt, rch);
	}
	r_print_cursor (p, idx, 1, 0);
}

R_API int r_print_string(RPrint *p, ut64 seek, const ut8 *buf, int len, int options) {
	int i;
	bool wide = (options & R_PRINT_STRING_WIDE);
	bool wide32 = (options & R_PRINT_STRING_WIDE32);
	bool zeroend = (options & R_PRINT_STRING_ZEROEND);
	bool wrap = (options & R_PRINT_STRING_WRAP);
	bool urlencode = (options & R_PRINT_STRING_URLENCODE);
	bool esc_nl = (options & R_PRINT_STRING_ESC_NL);
	int col = 0;
	i = 0;
	for (; !r_print_is_interrupted () && i < len; i++) {
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
		r_print_cursor (p, i, 1, 1);
		ut8 b = buf[i];
		if (b == '\n') {
			col = 0;
		}
		col++;
		if (urlencode) {
			// TODO: some ascii can be bypassed here
			p->cb_printf ("%%%02x", b);
		} else {
			if (b == '\\') {
				p->cb_printf ("\\\\");
			} else if ((b == '\n' && !esc_nl) || IS_PRINTABLE (b)) {
				p->cb_printf ("%c", b);
			} else {
				p->cb_printf ("\\x%02x", b);
			}
		}
		r_print_cursor (p, i, 1, 0);
		if (wrap && col + 1 >= p->width) {
			p->cb_printf ("\n");
			col = 0;
		}
		if (wide) {
			i++;
		}
	}
	p->cb_printf ("\n");
	return i;
}

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

#define Pal(x,y) (x->cons && x->cons->context->pal.y)? x->cons->context->pal.y
R_API void r_print_hexii(RPrint *rp, ut64 addr, const ut8 *buf, int len, int step) {
	PrintfCallback p = (PrintfCallback) rp->cb_printf;
	bool c = rp->flags & R_PRINT_FLAGS_COLOR;
	const char *color_0xff = c? (Pal (rp, b0xff): Color_RED): "";
	const char *color_text = c? (Pal (rp, btext): Color_MAGENTA): "";
	const char *color_other = c? (Pal (rp, other): Color_WHITE): "";
	const char *color_reset = c? Color_RESET: "";
	int i, j;
	bool show_offset = rp->show_offset;

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
		if (show_offset) {
			p ("%8"PFMT64x":", addr + i);
		}
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
	p ("%8"PFMT64x" ]\n", addr + i);
}

/* set screen_bounds to addr if the cursor is not visible on the screen anymore.
 * Note: screen_bounds is set only the first time this happens. */
R_API void r_print_set_screenbounds(RPrint *p, ut64 addr) {
	int r, rc;

	r_return_if_fail (p);

	if (!p->screen_bounds) {
		return;
	}
	if (!p->consbind.get_size) {
		return;
	}
	if (!p->consbind.get_cursor) {
		return;
	}

	if (p->screen_bounds == 1) {
		(void)p->consbind.get_size (&r);
		(void)p->consbind.get_cursor (&rc);

		if (rc > r - 1) {
			p->screen_bounds = addr;
		}
	}
}

R_API void r_print_section(RPrint *p, ut64 at) {
	bool use_section = p && p->flags & R_PRINT_FLAGS_SECTION;
	if (use_section) {
		const char *s = p->get_section_name (p->user, at);
		if (!s) {
			s = "";
		}
		char *tail = r_str_ndup (s, 19);
		p->cb_printf ("%20s ", tail);
		free (tail);
	}
}

R_API void r_print_hexdump(RPrint *p, ut64 addr, const ut8 *buf, int len, int base, int step, size_t zoomsz) {
	PrintfCallback printfmt = (PrintfCallback)printf;
#define print(x) printfmt("%s", x)
	bool c = p? (p->flags & R_PRINT_FLAGS_COLOR): false;
	const char *color_title = c? (Pal (p, offset): Color_MAGENTA): "";
	int inc = p? p->cols : 16;
	size_t i, j, k;
	int sparse_char = 0;
	int stride = 0;
	int col = 0; // selected column (0=none, 1=hex, 2=ascii)
	int use_sparse = 0;
	bool use_header = true;
	bool use_hdroff = true;
	bool use_pair = true;
	bool use_offset = true;
	bool compact = false;
	bool use_segoff = false;
	bool pairs = false;
	const char *bytefmt = "%02x";
	const char *pre = "";
	int last_sparse = 0;
	bool use_hexa = true;
	bool use_align = false;
	bool use_unalloc = false;
	const char *a, *b;
	int K = 0;
	bool hex_style = false;
	if (step < len) {
		len = len - (len % step);
	}
	if (p) {
		pairs = p->pairs;
		use_sparse = p->flags & R_PRINT_FLAGS_SPARSE;
		use_header = p->flags & R_PRINT_FLAGS_HEADER;
		use_hdroff = p->flags & R_PRINT_FLAGS_HDROFF;
		use_segoff = p->flags & R_PRINT_FLAGS_SEGOFF;
		use_align = p->flags & R_PRINT_FLAGS_ALIGN;
		use_offset = p->flags & R_PRINT_FLAGS_OFFSET;
		hex_style = p->flags & R_PRINT_FLAGS_STYLE;
		use_hexa = !(p->flags & R_PRINT_FLAGS_NONHEX);
		use_unalloc = p->flags & R_PRINT_FLAGS_UNALLOC;
		compact = p->flags & R_PRINT_FLAGS_COMPACT;
		inc = p->cols; // row width
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
		bytefmt = "0x%08x ";
		pre = " ";
		if (inc < 4) {
			inc = 4;
		}
		break;
	case -1:
		bytefmt = "0x%08x ";
		pre = "  ";
		if (inc < 4) {
			inc = 4;
		}
		break;
	case 8:
		bytefmt = "%03o";
		pre = " ";
		break;
	case 10:
		bytefmt = "%3d";
		pre = " ";
		break;
	case 16:
		if (inc < 2) {
			inc = 2;
			use_header = false;
		}
		break;
	case 32:
		bytefmt = "0x%08x ";
		pre = " ";
		if (inc < 4) {
			inc = 4;
		}
		break;
	case 64:
		bytefmt = "0x%016x ";
		pre = " ";
		if (inc < 8) {
			inc = 8;
		}
		break;
	}
	const char *space = hex_style? ".": " ";
	// TODO: Use base to change %03o and so on
	if (step == 1 && base < 0) {
		use_header = false;
	}
	if (use_header) {
		if (c) {
			print (color_title);
		}
		if (base < 32) {
			{ // XXX: use r_print_addr_header
				int i, delta;
				char soff[32];
				if (hex_style) {
					print ("..offset..");
				} else {
					print ("- offset -");
					if (p->wide_offsets) {
						print ("       ");
					}
				}
				if (use_segoff) {
					ut32 s, a;
					a = addr & 0xffff;
					s = ((addr - a) >> p->seggrn) & 0xffff;
					snprintf (soff, sizeof (soff), "%04x:%04x ", s, a);
					delta = strlen (soff) - 10;
				} else {
					snprintf (soff, sizeof (soff), "0x%08" PFMT64x, addr);
					delta = strlen (soff) - 9;
				}
				if (compact) {
					delta--;
				}
				for (i = 0; i < delta; i++) {
					print (space);
				}
			}
			/* column after number, before hex data */
			print ((col == 1)? "|": space);
			if (use_hdroff)  {
				k = addr & 0xf;
				K = (addr >> 4) & 0xf;
			} else {
				k = 0; // TODO: ??? SURE??? config.seek & 0xF;
			}
			if (use_hexa) {
				/* extra padding for offsets > 8 digits */
				for (i = 0; i < inc; i++) {
					print (pre);
					if (base < 0) {
						if (i & 1) {
							print (space);
						}
					}
					if  (use_hdroff) {
						if (use_pair) {
							printfmt ("%c%c",
									hex[(((i+k) >> 4) + K) % 16],
									hex[(i + k) % 16]);
						} else {
							printfmt (" %c", hex[(i + k) % 16]);
						}
					} else {
						printfmt (" %c", hex[(i + k) % 16]);
					}
					if (i & 1 || !pairs) {
						if (!compact) {
							print (col != 1? space: ((i + 1) < inc)? space: "|");
						}
					}
				}
			}
			/* ascii column */
			if (compact) {
				print (col > 0? "|": space);
			} else {
				print (col == 2? "|": space);
			}
			if (!p || !(p->flags & R_PRINT_FLAGS_NONASCII)) {
				for (i = 0; i < inc; i++) {
					printfmt ("%c", hex[(i + k) % 16]);
				}
			}
			if (col == 2) {
				printfmt ("|");
			}
			/* print comment header*/
			if (p && p->use_comments && !compact) {
				if (col != 2) {
					print (" ");
				}
				if (!hex_style) {
					print (" comment");
				}
			}
			print ("\n");
		}

		if (c) {
			print (Color_RESET);
		}
	}

	// is this necessary?
	r_print_set_screenbounds (p, addr);
	int rowbytes;
	int rows = 0;
	int bytes = 0;
	bool printValue = true;
	bool oPrintValue = true;
	bool isPxr = (p && p->flags & R_PRINT_FLAGS_REFS);

	for (i = j = 0; i < len; i += (stride? stride: inc)) {
		if (p && p->cons && p->cons->context && p->cons->context->breaked) {
			break;
		}
		rowbytes = inc;
		if (use_align) {
			int sz = (p && p->offsize)? p->offsize (p->user, addr + j): -1;
			if (sz > 0) { // flags with size 0 dont work
				rowbytes = sz;
			}
		}

		if (use_sparse) {
			if (checkSparse (buf + i, inc, sparse_char)) {
				if (i + inc >= len || checkSparse (buf + i + inc, inc, sparse_char)) {
					if (i + inc + inc >= len ||
					checkSparse (buf + i + inc + inc, inc, sparse_char)) {
						sparse_char = buf[j];
						last_sparse++;
						if (last_sparse == 2) {
							print (" ...\n");
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
		ut64 at = addr + (j * zoomsz);
		if (use_offset && (!isPxr || inc < 4)) {
			r_print_section (p, at);
			r_print_addr (p, at);
		}
		int row_have_cursor = -1;
		ut64 row_have_addr = UT64_MAX;
		if (use_hexa) {
			if (!compact && !isPxr) {
				print ((col == 1)? "|": " ");
			}
			for (j = i; j < i + inc; j++) {
				if (j!=i && use_align && rowbytes == inc) {
					int sz = (p && p->offsize)? p->offsize (p->user, addr + j): -1;
					if (sz >= 0) {
						rowbytes = bytes;
					}
				}
				if (row_have_cursor == -1) {
					if (r_print_cursor_pointer (p, j, 1)) {
						row_have_cursor = j - i;
						row_have_addr = addr + j;
					}
				}
				if (!compact && ((j >= len) || bytes >= rowbytes)) {
					if (col == 1) {
						if (j + 1 >= inc + i) {
							print (j % 2? "  |": "| ");
						} else {
							print (j % 2? "   ": "  ");
						}
					} else {
						if (base == 32) {
							print ((j % 4)? "   ": "  ");
						} else if (base == 10) {
							print (j % 2? "     ": "  ");
						} else {
							print (j % 2? "   ": "  ");
						}
					}
					continue;
				}
				const char *hl = (hex_style && p && p->offname (p->user, addr + j))? Color_INVERT: NULL;
				if (hl) {
					print (hl);
				}
				if (p && (base == 32 || base == 64)) {
					int left = len - i;
					/* TODO: check step. it should be 2/4 for base(32) and 8 for
					 *       base(64) */
					ut64 n = 0;
					size_t sz_n = (base == 64)
						? sizeof (ut64) : (step == 2)
						? sizeof (ut16) : sizeof (ut32);
					sz_n = R_MIN (left, sz_n);
					if (j + sz_n > len) {
						// oob
						j += sz_n;
						continue;
					}
					r_mem_swaporcopy ((ut8 *) &n, buf + j, sz_n, p && p->big_endian);
					r_print_cursor (p, j, sz_n, 1);
					// stub for colors
					if (p && p->colorfor) {
						if (!p->iob.addr_is_mapped (p->iob.io, addr + j)) {
							a = p->cons->context->pal.ai_unmap;
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
					printValue = true;
					bool hasNull = false;
					if (isPxr) {
						if (n == 0) {
							if (oPrintValue) {
								hasNull = true;
							}
							printValue = false;
						}
					}
					if (printValue) {
						if (use_offset && !hasNull && isPxr) {
							r_print_section (p, at);
							r_print_addr (p, addr + j * zoomsz);
						}
						if (base == 64) {
							printfmt ("%s0x%016" PFMT64x "%s  ", a, (ut64) n, b);
						} else if (step == 2) {
							printfmt ("%s0x%04x%s ", a, (ut16) n, b);
						} else {
							printfmt ("%s0x%08x%s ", a, (ut32) n, b);
						}
					} else {
						if (hasNull) {
							const char *n = p->offname (p->user, addr + j);
							r_print_section (p, at);
							r_print_addr (p, addr + j * zoomsz);
							printfmt ("..[ null bytes ]..   00000000 %s\n", r_str_get (n));
						}
					}
					r_print_cursor (p, j, sz_n, 0);
					oPrintValue = printValue;
					j += step - 1;
				} else if (base == -8) {
					long long w = r_read_ble64 (buf + j, p && p->big_endian);
					r_print_cursor (p, j, 8, 1);
					printfmt ("%23" PFMT64d " ", w);
					r_print_cursor (p, j, 8, 0);
					j += 7;
				} else if (base == -1) {
					st8 w = r_read_ble8 (buf + j);
					r_print_cursor (p, j, 1, 1);
					printfmt ("%4d ", w);
					r_print_cursor (p, j, 1, 0);
				} else if (base == -10) {
					if (j + 1 < len) {
						st16 w = r_read_ble16 (buf + j, p && p->big_endian);
						r_print_cursor (p, j, 2, 1);
						printfmt ("%7d ", w);
						r_print_cursor (p, j, 2, 0);
					}
					j += 1;
				} else if (base == 10) { // "pxd"
					if (j + 3 < len) {
						int w = r_read_ble32 (buf + j, p && p->big_endian);
						r_print_cursor (p, j, 4, 1);
						printfmt ("%13d ", w);
						r_print_cursor (p, j, 4, 0);
					}
					j += 3;
				} else {
					if (j >= len) {
						break;
					}
					if (use_unalloc && !p->iob.is_valid_offset (p->iob.io, addr + j, false)) {
						char ch = p->io_unalloc_ch;
						char dbl_ch_str[] = { ch, ch, 0 };
						p->cb_printf ("%s", dbl_ch_str);
					} else {
						r_print_byte (p, bytefmt, j, buf[j]);
					}
					if (pairs && !compact && (inc & 1)) {
						bool mustspace = (rows % 2) ? !(j&1) : (j&1);
						if (mustspace) {
							print (" ");
						}
					} else if (bytes % 2 || !pairs) {
						if (col == 1) {
							if (j + 1 < inc + i) {
								if (!compact) {
									print (" ");
								}
							} else {
								print ("|");
							}
						} else {
							if (!compact) {
								print (" ");
							}
						}
					}
				}
				if (hl) {
					print (Color_RESET);
				}
				bytes++;
			}
		}
		if (printValue) {
			if (compact) {
				if (col == 0) {
					print (" ");
				} else if (col == 1) {
					//print (" ");
				} else {
					print ((col == 2)? "|": "");
				}
			} else {
				print ((col == 2)? "|": " ");
			}
			if (!p || !(p->flags & R_PRINT_FLAGS_NONASCII)) {
				bytes = 0;
				size_t end = i + inc;
				for (j = i; j < end; j++) {
					if (j != i && use_align  && bytes >= rowbytes) {
						int sz = (p && p->offsize)? p->offsize (p->user, addr + j): -1;
						if (sz >= 0) {
							print (" ");
							break;
						}
					}
					if (j >= len || (use_align && bytes >= rowbytes)) {
						break;
					}
					ut8 ch = (use_unalloc && p && !p->iob.is_valid_offset (p->iob.io, addr + j, false))
						? ' ' : buf[j];
					r_print_byte (p, "%c", j, ch);
					bytes++;
				}
			}
			/* ascii column */
			if (col == 2) {
				print ("|");
			}
			bool eol = false;
			if (!eol && p && p->flags & R_PRINT_FLAGS_REFS) {
				ut64 off = UT64_MAX;
				if (inc == 8) {
					if (i + sizeof (ut64) - 1 < len) {
						off = r_read_le64 (buf + i);
					}
				} else if (inc == 4) {
					if (i + sizeof (ut32) - 1 < len) {
						off = r_read_le32 (buf + i);
					}
				} else if (inc == 2 && base == 16) {
					if (i + sizeof (ut16) - 1 < len) {
						off = r_read_le16 (buf + i);
						if (off == 0) {
							off = UT64_MAX;
						}
					}
				}
				if (p->hasrefs && off != UT64_MAX) {
					char *rstr = p->hasrefs (p->user, addr + i, false);
					if (rstr && *rstr) {
						printfmt (" @ %s", rstr);
					}
					free (rstr);
					rstr = p->hasrefs (p->user, off, true);
					if (rstr && *rstr) {
						printfmt (" %s", rstr);
					}
					free (rstr);
				}
			}
			if (!eol && p && p->use_comments) {
				for (; j < i + inc; j++) {
					print (" ");
				}
				for (j = i; j < i + inc; j++) {
					if (use_align && (j-i) >= rowbytes) {
						break;
					}
					if (p && p->offname) {
						a = p->offname (p->user, addr + j);
						if (p->colorfor && a && *a) {
							const char *color = p->colorfor (p->user, addr + j, true);
							printfmt ("%s  ; %s%s", r_str_get (color), a,
									color ? Color_RESET : "");
						}
					}
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
			if (use_align && rowbytes < inc && bytes >= rowbytes) {
				i -= (inc - bytes);
			}
			print ("\n");
		}
		rows++;
		bytes = 0;
		if (p && p->cfmt && *p->cfmt) {
			if (row_have_cursor != -1) {
				int i = 0;
				print (" _________");
				if (!compact) {
					print ("_");
				}
				for (i = 0; i < row_have_cursor; i++) {
					if (!pairs || (!compact && i % 2)) {
						print ("___");
					} else {
						print ("__");
					}
				}
				print ("__|\n");
				printfmt ("| cmd.hexcursor = %s\n", p->cfmt);
				p->coreb.cmdf (p->coreb.core,
						"%s @ 0x%08"PFMT64x, p->cfmt, row_have_addr);
			}
		}
	}
}

R_API void r_print_hexdump_simple(const ut8 *buf, int len) {
	r_print_hexdump (NULL, 0, buf, len, 16, 16, 0);
}

static const char* getbytediff(RPrint *p, char *fmt, ut8 a, ut8 b) {
	if (*fmt) {
		if (a == b) {
			sprintf (fmt, "%s%02x" Color_RESET, p->cons->context->pal.graph_true, a);
		} else {
			sprintf (fmt, "%s%02x" Color_RESET, p->cons->context->pal.graph_false, a);
		}
	} else {
		sprintf (fmt, "%02x", a);
	}
	return fmt;
}

static const char* getchardiff(RPrint *p, char *fmt, ut8 a, ut8 b) {
	char ch = IS_PRINTABLE (a)? a: '.';
	if (*fmt) {
		if (a == b) {
			sprintf (fmt, "%s%c" Color_RESET, p->cons->context->pal.graph_true, ch);
		} else {
			sprintf (fmt, "%s%c" Color_RESET, p->cons->context->pal.graph_false, ch);
		}
	} else {
		sprintf (fmt, "%c", ch);
	}
	//else { fmt[0] = ch; fmt[1]=0; }
	return fmt;
}

#define BD(a, b) getbytediff (p, fmt, (a)[i + j], (b)[i + j])
#define CD(a, b) getchardiff (p, fmt, (a)[i + j], (b)[i + j])

static ut8* M(const ut8 *b, int len) {
	ut8 *r = malloc (len + 16);
	if (r) {
		memset (r, 0xff, len + 16);
		memcpy (r, b, len);
	}
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
			r_print_cursor (p, i + j, 1, 1);
			p->cb_printf ("%s", BD (a, b));
			r_print_cursor (p, i + j, 1, 0);
		}
		p->cb_printf (" ");
		for (j = 0; j < min; j++) {
			*fmt = color;
			r_print_cursor (p, i + j, 1, 1);
			p->cb_printf ("%s", CD (a, b));
			r_print_cursor (p, i + j, 1, 0);
		}
		if (scndcol) {
			p->cb_printf (" %c 0x%08" PFMT64x " ", linediff, ba + i);
			for (j = 0; j < min; j++) {
				*fmt = color;
				r_print_cursor (p, i + j, 1, 1);
				p->cb_printf ("%s", BD (b, a));
				r_print_cursor (p, i + j, 1, 0);
			}
			p->cb_printf (" ");
			for (j = 0; j < min; j++) {
				*fmt = color;
				r_print_cursor (p, i + j, 1, 1);
				p->cb_printf ("%s", CD (b, a));
				r_print_cursor (p, i + j, 1, 0);
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
			p->cb_printf ("0x%08"PFMT64x"  ", addr + i);
			for (j = 0; j < cols; j++) {
				if ((i + j) >= len) {
					break;
				}
				ch = buf[i + j];
				if (p->cur_enabled) {
					r_print_cursor (p, i + j, 1, 1);
					p->cb_printf ("%c", IS_PRINTABLE (ch)? ch: ' ');
					r_print_cursor (p, i + j, 1, 0);
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
	for (i = 0; !r_print_is_interrupted () && i < len;) {
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
	const char *h_line = p->cons->use_utf8 ? RUNE_LONG_LINE_HORIZ : "-";
	const char *block = p->cons->use_utf8 ? UTF_BLOCK : "#";

	pc = R_MAX (0, R_MIN (100, pc));
	if (p->flags & R_PRINT_FLAGS_HEADER) {
		p->cb_printf ("%4d%% ", pc);
	}
	cols -= 15;
	p->cb_printf ("[");
	for (i = cols * pc / 100; i; i--) {
		p->cb_printf ("%s", block);
	}
	for (i = cols - (cols * pc / 100); i; i--) {
		p->cb_printf ("%s", h_line);
	}
	p->cb_printf ("]");
}

/* TODO: handle screen width */
R_API void r_print_progressbar_with_count(RPrint *p, unsigned int pc, unsigned int total, int _cols, bool reset_line) {
	int i, cols = (_cols == -1)? 78: _cols;
	if (!p) {
		p = &staticp;
	}
	const bool enable_colors = p && (p->flags & R_PRINT_FLAGS_COLOR);
	const char *h_line = p->cons->use_utf8? RUNE_LONG_LINE_HORIZ: "-";
	const char *block = p->cons->use_utf8? UTF_BLOCK: "#";

	total = R_MAX (1, total);
	pc = R_MAX (0, R_MIN (total, pc));
	if (reset_line) {
		p->cb_printf ("\r");
	}
	if (p->flags & R_PRINT_FLAGS_HEADER) {
		if (enable_colors) {
			p->cb_printf ("%s%4d%s%% %s%6d%s/%6d%s ", Color_GREEN, pc * 100 / total, Color_RESET, Color_GREEN, pc, Color_RESET, total, Color_YELLOW);
		} else {
			p->cb_printf ("%4d%% %6d/%6d ", pc * 100 / total, pc, total);
		}
		// TODO: determine string length of the numbers
		cols -= 20;
	}
	if (cols > 0) {
		if (enable_colors) {
			p->cb_printf ("[%s", Color_YELLOW);
		} else {
			p->cb_printf ("[");
		}
		for (i = cols * pc / total; i; i--) {
			p->cb_printf ("%s", block);
		}
		if (enable_colors) {
			p->cb_printf ("%s", Color_RESET);
		}
		for (i = cols - (cols * pc / total); i; i--) {
			p->cb_printf ("%s", h_line);
		}
		if (enable_colors) {
			p->cb_printf ("%s]", Color_RESET);
		}
		else {
			p->cb_printf ("]");
		}
	}
}

R_API void r_print_rangebar(RPrint *p, ut64 startA, ut64 endA, ut64 min, ut64 max, int cols) {
	const char *h_line = p->cons->use_utf8? RUNE_LONG_LINE_HORIZ: "-";
	const char *block = p->cons->use_utf8? UTF_BLOCK: "#";
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
				p->cb_printf (Color_GREEN);
				isFirst = false;
			}
			p->cb_printf ("%s", block);
		} else {
			if (!isFirst) {
				p->cb_printf (Color_RESET);
			}
			p->cb_printf ("%s", h_line);
		}
	}
	p->cb_printf ("|");
}

R_API void r_print_zoom_buf(RPrint *p, void *user, RPrintZoomCallback cb, ut64 from, ut64 to, int len, int maxlen) {
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
			if (p->cons->context->breaked) {
				break;
			}
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
}

R_API void r_print_zoom(RPrint *p, void *user, RPrintZoomCallback cb, ut64 from, ut64 to, int len, int maxlen) {
	ut64 size = (to - from);
	r_print_zoom_buf (p, user, cb, from, to, len, maxlen);
	size = len? size / len: 0;
	p->flags &= ~R_PRINT_FLAGS_HEADER;
	r_print_hexdump (p, from, p->zoom->buf, p->zoom->size, 16, 1, size);
	p->flags |= R_PRINT_FLAGS_HEADER;
}

static inline void printHistBlock (RPrint *p, int k, int cols) {
	RConsPrintablePalette *pal = &p->cons->context->pal;
	const char *h_line = p->cons->use_utf8 ? RUNE_LONG_LINE_HORIZ : "-";
	const char *block = p->cons->use_utf8 ? UTF_BLOCK : "#";
	const char *kol[5];
	kol[0] = pal->nop;
	kol[1] = pal->mov;
	kol[2] = pal->cjmp;
	kol[3] = pal->jmp;
	kol[4] = pal->call;
	if (cols < 1) {
		cols = 1;
	}
	const bool show_colors = (p && (p->flags & R_PRINT_FLAGS_COLOR));
	if (show_colors) {
		int idx = (int) ((k * 4) / cols);
		const char *str = kol[idx];
		if (p->histblock) {
			p->cb_printf ("%s%s%s", str, block, Color_RESET);
		} else {
			p->cb_printf ("%s%s%s", str, h_line, Color_RESET);
		}
	} else {
		if (p->histblock) {
			p->cb_printf ("%s", block);
		} else {
			p->cb_printf ("%s", h_line);
		}
	}
}

R_API void r_print_fill(RPrint *p, const ut8 *arr, int size, ut64 addr, int step) {
	r_return_if_fail (p && arr);
	const bool show_colors = (p && (p->flags & R_PRINT_FLAGS_COLOR));
	const bool show_offset = (p && (p->flags & R_PRINT_FLAGS_OFFSET));
	bool useUtf8 = p->cons->use_utf8;
	const char *v_line = useUtf8 ? RUNE_LINE_VERT : "|";
	int i = 0, j;

#define INC 5
#if TOPLINE
	if (arr[0] > 1) {
		p->cb_printf ("         ");
		if (addr != UT64_MAX && step > 0) {
			p->cb_printf ("           ");
		}
		if (arr[0] > 1) {
			for (i = 0; i < arr[0]; i += INC) {
				p->cb_printf (h_line);
			}
		}
		p->cb_printf ("\n");
	}
#endif
	// get the max of columns
	int cols = 0;
	for (i = 0; i < size; i++) {
		cols = arr[i] > cols ? arr[i] : cols;
	}
	cols /= 5;
	for (i = 0; i < size; i++) {
		ut8 next = (i + 1 < size)? arr[i + 1]: 0;
		int base = 0, k = 0;
		if (addr != UT64_MAX && step > 0) {
			ut64 at = addr + (i * step);
			if (show_offset) {
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
			}
			p->cb_printf ("%03x %04x %s", i, arr[i], v_line);
		} else {
			p->cb_printf ("%s", v_line);
		}
		if (next < INC) {
			base = 1;
		}
		if (next < arr[i]) {
			if (arr[i] > INC) {
				for (j = 0; j < next + base; j += INC) {
					printHistBlock (p, k, cols);
					k++;
				}
			}
			for (j = next + INC; j + base < arr[i]; j += INC) {
				printHistBlock (p, k, cols);
				k++;
			}
		} else {
			printHistBlock (p, k, cols);
			k++;
		}
		if (i + 1 == size) {
			for (j = arr[i] + INC + base; j + base < next; j += INC) {
				printHistBlock (p, k, cols);
				k++;
			}
		} else if (arr[i + 1] > arr[i]) {
			for (j = arr[i] + INC + base; j + base < next; j += INC) {
				printHistBlock (p, k, cols);
				k++;
			}
		}
		if (show_colors) {
			p->cb_printf ("%s", Color_RESET);
		}
		p->cb_printf ("\n");
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

// probably move somewhere else. RPrint doesnt needs to know about the R_ANAL_ enums
R_API const char* r_print_color_op_type(RPrint *p, ut32 anal_type) {
	RConsPrintablePalette *pal = &p->cons->context->pal;
	switch (anal_type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_NOP:
		return pal->nop;
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_MUL:
	case R_ANAL_OP_TYPE_DIV:
	case R_ANAL_OP_TYPE_MOD:
	case R_ANAL_OP_TYPE_LENGTH:
		return pal->math;
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
		return pal->bin;
	case R_ANAL_OP_TYPE_IO:
		return pal->swi;
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
		return pal->ujmp;
	case R_ANAL_OP_TYPE_IJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_IRJMP:
	case R_ANAL_OP_TYPE_MJMP:
		return pal->jmp;
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_UCJMP:
	case R_ANAL_OP_TYPE_SWITCH:
		return pal->cjmp;
	case R_ANAL_OP_TYPE_CMP:
	case R_ANAL_OP_TYPE_ACMP:
		return pal->cmp;
	case R_ANAL_OP_TYPE_UCALL:
		return pal->ucall;
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_IRCALL:
	case R_ANAL_OP_TYPE_UCCALL:
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_CCALL:
		return pal->call;
	case R_ANAL_OP_TYPE_NEW:
	case R_ANAL_OP_TYPE_SWI:
		return pal->swi;
	case R_ANAL_OP_TYPE_ILL:
	case R_ANAL_OP_TYPE_TRAP:
		return pal->trap;
	case R_ANAL_OP_TYPE_CRET:
	case R_ANAL_OP_TYPE_RET:
		return pal->ret;
	case R_ANAL_OP_TYPE_CAST:
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_CMOV: // TODO: add cmov cathegory?
		return pal->mov;
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_UPUSH:
	case R_ANAL_OP_TYPE_RPUSH:
	case R_ANAL_OP_TYPE_LOAD:
		return pal->push;
	case R_ANAL_OP_TYPE_POP:
	case R_ANAL_OP_TYPE_STORE:
		return pal->pop;
	case R_ANAL_OP_TYPE_CRYPTO:
		return pal->crypto;
	case R_ANAL_OP_TYPE_NULL:
		return pal->other;
	case R_ANAL_OP_TYPE_UNK:
	default:
		return pal->invalid;
	}
}

// Global buffer to speed up colorizing performance
#define COLORIZE_BUFSIZE 1024
static char o[COLORIZE_BUFSIZE];

static bool issymbol(char c) {
	switch (c) {
	case '$':
	case ':':
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

static bool check_arg_name(RPrint *print, char *p, ut64 func_addr) {
	if (func_addr && print->exists_var) {
		int z;
		for (z = 0; p[z] && (isalpha ((unsigned char)p[z]) || isdigit ((unsigned char)p[z]) || p[z] == '_'); z++) {
			;
		}
		char tmp = p[z];
		p[z] = '\0';
		bool ret = print->exists_var (print, func_addr, p);
		p[z] = tmp;
		return ret;
	}
	return false;
}

static bool ishexprefix(char *p) {
	return (p[0] == '0' && p[1] == 'x');
}

R_API char* r_print_colorize_opcode(RPrint *print, char *p, const char *reg, const char *num, bool partial_reset, ut64 func_addr) {
	int i, j, k, is_mod, is_float = 0, is_arg = 0;
	char *reset = partial_reset ? Color_RESET_NOBG : Color_RESET;
	ut32 c_reset = strlen (reset);
	int is_jmp = p && (*p == 'j' || ((*p == 'c') && (p[1] == 'a')))? 1: 0;
	ut32 opcode_sz = p && *p? strlen (p) * 10 + 1: 0;
	char previous = '\0';
	const char *color_flag = print->cons->context->pal.flag;

	if (!p || !*p) {
		return NULL;
	}
	if (is_jmp) {
		return strdup (p);
	}
	r_str_trim (p);
	if (opcode_sz > COLORIZE_BUFSIZE) {
		/* return same string in case of error */
		return strdup (p);
	}

	memset (o, 0, COLORIZE_BUFSIZE);
	for (i = j = 0; p[i]; i++, j++) {
		/* colorize numbers */
		if ((ishexprefix (&p[i]) && previous != ':') \
		     || (isdigit ((ut8)p[i]) && issymbol (previous))) {
			const char *num2 = num;
			ut64 n = r_num_get (NULL, p + i);
			const char *name = print->offname (print->user, n)? color_flag: NULL;
			if (name) {
				num2 = name;
			}
			int nlen = strlen (num2);
			if (nlen + j >= sizeof (o)) {
				eprintf ("Colorize buffer is too small\n");
				break;
			}
			memcpy (o + j, num2, nlen + 1);
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

				bool found_var = check_arg_name (print, p + i + 1, func_addr);
				strcpy (o + j, reset);
				j += strlen (reset);
				o[j] = p[i];
				if (!(p[i+1] == '$' || ((p[i+1] > '0') && (p[i+1] < '9')))) {
					const char *color = found_var ? print->cons->context->pal.func_var_type : reg;
					ut32 color_len = strlen (color);
					if (color_len + j + 10 >= COLORIZE_BUFSIZE) {
						eprintf ("r_print_colorize_opcode(): buffer overflow!\n");
						return strdup (p);
					}
					strcpy (o + j + 1, color);
					j += strlen (color);
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
					RIOMap *map = print->iob.map_get (print->iob.io, r_num_get (NULL, p + i));
					if (map && map->name) {
						if (strlen (map->name) + j + 1 >= COLORIZE_BUFSIZE) {
							eprintf ("stop before overflow\n");
							break;
						}
						strcpy (o + j, map->name);
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
		/* free (t_o); */
	}
	strcpy (o + j, reset);
	//strcpy (p, o); // may overflow .. but shouldnt because asm.buf_asm is big enought
	return strdup (o);
}

// reset the status of row_offsets
R_API void r_print_init_rowoffsets(RPrint *p) {
	if (p->calc_row_offsets) {
		R_FREE (p->row_offsets);
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

R_API void r_print_hex_from_bin(RPrint *p, char *bin_str) {
	int i, j, index;
	RPrint myp = {.cb_printf = libc_printf};
	const int len = strlen (bin_str);
	if (!len) {
		return;
	}
	ut64 n, *buf = malloc (sizeof (ut64) * ((len + 63) / 64));
	if (!buf) {
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

R_API const char* r_print_rowlog(RPrint *print, const char *str) {
	int use_color = print->flags & R_PRINT_FLAGS_COLOR;
	bool verbose = print->scr_prompt;
	r_return_val_if_fail (print->cb_eprintf, NULL);
	if (!verbose) {
		return NULL;
	}
	if (use_color) {
		print->cb_eprintf ("[ ] "Color_YELLOW"%s\r["Color_RESET, str);
	} else {
		print->cb_eprintf ("[ ] %s\r[", str);
	}
	return str;
}

R_API void r_print_rowlog_done(RPrint *print, const char *str) {
	int use_color = print->flags & R_PRINT_FLAGS_COLOR;
	bool verbose =  print->scr_prompt;
	r_return_if_fail (print->cb_eprintf);
	if (verbose) {
		if (use_color) {
			print->cb_eprintf ("\r"Color_GREEN"[x]"Color_RESET" %s\n", str);
		} else {
			print->cb_eprintf ("\r[x] %s\n", str);
		}
	}
}

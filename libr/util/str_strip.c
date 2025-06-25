/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_cons.h>

static void __unrgb(int color, int *r, int *g, int *b) {
	// TODO: remove rcons dependency
#if 0
	RConsContext *ctx = r_cons_singleton ()->context;
	if (color < 0 || color > 255) {
		*r = *g = *b = 0;
	} else {
		int rgb = ctx->colors[color];
		*r = (rgb >> 16) & 0xff;
		*g = (rgb >> 8) & 0xff;
		*b = rgb & 0xff;
	}
#endif
}

/* Parse an ANSI code string into RGB values -- Used by HTML filter only */
R_API bool r_str_html_rgbparse(const char *p, ut8 *r, ut8 *g, ut8 *b, ut8 *a) {
	const char *q = 0;
	ut8 isbg = 0, bold = 127;
	if (!p) {
		// XXX maybe assert?
		return false;
	}
	if (*p == 0x1b) {
		p++;
		if (!*p) {
			return false;
		}
	}
	if (*p == '[') {
		p++;
		if (!*p) {
			return false;
		}
	}
	// here, p should be just after the '['
	switch (*p) {
	case '1':
		bold = 255;
		if (!p[1] || !p[2]) {
			return false;
		}
		p += 2;
		break;
	case '3': isbg = 0; break;
	case '4': isbg = 1; break;
	}
#define SETRGB(x,y,z) if (r) *r = (x); if (g) *g = (y); if (b) *b = (z)
	if (bold != 255 && strchr (p, ';')) {
		if (!p[0] || !p[1] || !p[2]) {
			return 0;
		}
		if (p[3] == '5')  { // \x1b[%d;5;%dm is 256 colors
			int x, y, z;
			if (!p[3] || !p[4]) {
				return 0;
			}
			int n = atoi (p + 5);
			__unrgb (n, &x, &y, &z);
			SETRGB (x, y, z);
		} else { // 16M colors (truecolor)
			/* complex rgb */
			if (!p[3] || !p[4]) {
				return 0;
			}
			p += 5;
			if (r) {
				*r = atoi (p);
			}
			q = strchr (p, ';');
			if (!q) {
				return 0;
			}
			if (g) {
				*g = atoi (q + 1);
			}
			q = strchr (q + 1, ';');
			if (!q) {
				return false;
			}
			if (b) {
				*b = atoi (q + 1);
			}
		}
		return true;
	}
	/* plain ansi escape codes */
	if (a) {
		*a = isbg;
	}
	if (!*p) {
		return false;
	}
	switch (p[1]) {
	case '0': SETRGB (0, 0, 0); break;
	case '1': SETRGB (bold, 0, 0); break;
	case '2': SETRGB (0, bold, 0); break;
	case '3': SETRGB (bold, bold, 0); break;
	case '4': SETRGB (0, 0, bold); break;
	case '5': SETRGB (bold, 0, bold); break;
	case '6': SETRGB (0, bold, bold); break;
	case '7': SETRGB (bold, bold, bold); break;
	}
	return true;
}

// HTML
static bool gethtmlrgb(const char *str, char *buf, size_t buf_size) {
	ut8 r = 0, g = 0, b = 0;
	if (r_str_html_rgbparse (str, &r, &g, &b, 0)) {
		snprintf (buf, buf_size, "#%02x%02x%02x", r, g, b);
		return true;
	}
	buf[0] = '\0';
	return false;
}

static const char *gethtmlcolor(const char ptrch) {
	switch (ptrch) {
	case '0': return "#000"; // BLACK
	case '1': return "#f00"; // RED
	case '2': return "#0f0"; // GREEN
	case '3': return "#ff0"; // YELLOW
	case '4': return "#00f"; // BLUE
	case '5': return "#f0f"; // MAGENTA
	case '6': return "#aaf"; // TURQOISE
	case '7': return "#fff"; // WHITE
	case '8': return "#777"; // GREY
	case '9': break; // default
	}
	return "";
}

R_API char *r_str_html_strip(const char *ptr, int *newlen) {
	const char *str = ptr;
	int esc = 0;
	bool inv = false;
	char text_color[16] = {0};
	char background_color[16] = {0};
	bool has_bold = false;
	bool has_set = false;
	bool need_to_set = false;
	bool need_to_clear = false;
	bool first_style;
	int tmp;
	if (!ptr) {
		return NULL;
	}
	RStrBuf *res = r_strbuf_new ("");
	if (!res) {
		return NULL;
	}
	for (; ptr[0]; ptr++) {
		if (esc == 0 && ptr[0] != 0x1b && need_to_set) {
			if (has_set) {
				r_strbuf_append (res, "</span>");
				has_set = false;
			}
			if (!need_to_clear) {
				first_style = true;
				r_strbuf_append (res, "<span");
				if (text_color[0]) {
					r_strbuf_append (res, first_style? " style='": ";");
					r_strbuf_appendf (res, "color:%s", text_color);
					first_style = false;
				}
				if (background_color[0]) {
					r_strbuf_append (res, first_style? " style='": ";");
					r_strbuf_appendf (res, "background-color:%s", background_color);
					first_style = false;
				}
				if (inv) {
					r_strbuf_append (res, first_style? " style='": ";");
					r_strbuf_append (res, "text-decoration:underline overline");
					first_style = false;
				}
				if (has_bold) {
					r_strbuf_append (res, first_style? " style='": ";");
					r_strbuf_append (res, "font-weight:bold");
					first_style = false;
				}
				r_strbuf_append (res, first_style? ">": "'>");
				has_set = true;
			}
			need_to_clear = false;
			need_to_set = false;
		}
		if (ptr[0] == '\n') {
			if (ptr > str) {
				tmp = (int) (size_t) (ptr - str);
				r_strbuf_append_n (res, str, tmp);
				if (!ptr[1]) {
					// write new line if it's the end of the output
					r_strbuf_append (res, "\n");
				} else {
					r_strbuf_append (res, "<br />");
				}
				str = ptr + 1;
			} else {
				r_strbuf_append (res, "<br />\n");
			}
			continue;
		} else if (ptr[0] == '<') {
			tmp = (int)(size_t) (ptr - str);
			r_strbuf_append_n (res, str, tmp);
			r_strbuf_append (res, "&lt;");
			str = ptr + 1;
			continue;
		} else if (ptr[0] == '>') {
			tmp = (int)(size_t) (ptr - str);
			r_strbuf_append_n (res, str, tmp);
			r_strbuf_append (res, "&gt;");
			str = ptr + 1;
			continue;
		} else if (ptr[0] == ' ') {
			tmp = (int) (size_t) (ptr - str);
			if (tmp > 0) {
				r_strbuf_append_n (res, str, tmp);
				str = ptr + 1;
			} else {
				str++;
			}
			r_strbuf_append (res, "&nbsp;");
			continue;
		}
		if (ptr[0] == 0x1b) {
			esc = 1;
			tmp = (int)(size_t) (ptr - str);
			r_strbuf_append_n (res, str, tmp);
			str = ptr + 1;
			continue;
		}
		if (esc == 1) {
			// \x1b[2J
			if (ptr[0] != '[') {
				R_LOG_ERROR ("Oops invalid escape char");
				esc = 0;
				str = ptr + 1;
				continue;
			}
			esc = 2;
			continue;
		}
		if (esc == 2) {
			// TODO: use dword comparison here
			if (ptr[0] == '0' && ptr[1] == 'J') { // R_CONS_CLEAR_FROM_CURSOR_TO_END
				ptr += 2;
				esc = 0;
				str = ptr;
			} else if (ptr[0] == '1') {
				// ignore bold
				has_bold = true;
			} else if (!memcmp (ptr, "2K", 2)) {
				ptr += 2;
				esc = 0;
				str = ptr;
				continue;
			} else if (ptr[0] == '2' && ptr[1] == 'J') {
				r_strbuf_append (res, "<hr />");
				ptr++;
				esc = 0;
				str = ptr;
				continue;
			} else if (isdigit (ptr[0]) && ptr[1] == ';' && isdigit (ptr[2])) {
				char *m = strchr (ptr, 'm');
				if (m) {
					gethtmlrgb (ptr, background_color, sizeof (background_color));
					need_to_set = true;
					ptr = m;
					str = ptr + 1;
					esc = 0;
				}
			} else if (isdigit (ptr[0]) && isdigit (ptr[1]) && ptr[2] == ';') {
				char *m = strchr (ptr, 'm');
				if (m) {
					gethtmlrgb (ptr, text_color, sizeof (text_color));
					need_to_set = true;
					ptr = m;
					str = ptr + 1;
					esc = 0;
				}
			} else if (r_str_startswith (ptr, "48;5;") || r_str_startswith (ptr, "48;2;")) {
				char *end = strchr (ptr, 'm');
				gethtmlrgb (ptr, background_color, sizeof (background_color));
				need_to_set = true;
				ptr = end;
				str = ptr + 1;
				esc = 0;
			} else if (r_str_startswith (ptr, "38;5;") || r_str_startswith (ptr, "38;2;")) {
				char *end = strchr (ptr, 'm');
				gethtmlrgb (ptr, text_color, sizeof (text_color));
				need_to_set = true;
				if (end) {
					ptr = end;
					str = ptr + 1;
				}
				esc = 0;
			} else if ((ptr[0] == '0' || ptr[0] == '1') && ptr[1] == ';' && isdigit (ptr[2])) {
				// bg color is kind of ignored, but no glitch so far
				ptr += 4;
				esc = 0;
				str = ptr;
				continue;
			} else if (ptr[0] == '0' && ptr[1] == 'm') {
				ptr++;
				str = ptr + 1;
				esc = 0;
				inv = false;
				text_color[0] = '\0';
				background_color[0] = '\0';
				need_to_set = need_to_clear = true;
				continue;
				// reset color
			} else if (r_str_startswith (ptr, "27m")) {
				inv = false;
				need_to_set = true;
				ptr = ptr + 2;
				str = ptr + 1;
				esc = 0;
				continue;
				// reset invert color
			} else if (ptr[0] == '7' && ptr[1] == 'm') {
				ptr++;
				str = ptr + 1;
				inv = true;
				need_to_set = true;
				esc = 0;
				continue;
				// invert color
			} else if (ptr[0] == '3' && ptr[2] == 'm') {
				const char *htmlColor = gethtmlcolor (ptr[1]);
				if (htmlColor) {
					r_str_ncpy (text_color, htmlColor, sizeof (text_color));
				}
				need_to_set = true;
				ptr = ptr + 2;
				str = ptr + 1;
				esc = 0;
				continue;
			} else if ((ptr[0] == '4' || ptr[0] == '9') && ptr[2] == 'm') {
				const char *htmlColor = gethtmlcolor (ptr[1]);
				if (htmlColor) {
					r_str_ncpy (background_color, htmlColor, sizeof (background_color));
				}
				need_to_set = true;
				ptr = ptr + 2;
				str = ptr + 1;
				esc = 0;
				continue;
			}
		}
	}
	if (ptr > str) {
		r_strbuf_append_n (res, str, ptr - str);
	}
	if (has_set) {
		r_strbuf_append (res, "</span>");
	}
	if (newlen) {
		*newlen = res->len;
	}
	return r_strbuf_drain (res);
}

// ANSI
// ...

/* radare - LGPL - Copyright 2009-2023 - pancake, nibble */

#include <r_cons.h>

static bool gethtmlrgb(const char *str, char *buf, size_t buf_size) {
	ut8 r = 0, g = 0, b = 0;
	if (r_cons_rgb_parse (str, &r, &g, &b, 0)) {
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

// TODO: move into r_util/str
R_API char *r_cons_html_filter(const char *ptr, int *newlen) {
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
	for (; ptr[0]; ptr = ptr + 1) {
		if (esc == 0 && ptr[0] != 0x1b && need_to_set) {
			if (has_set) {
				r_strbuf_append (res, "</font>");
				has_set = false;
			}
			if (!need_to_clear) {
				first_style = true;
				r_strbuf_append (res, "<font");
				if (text_color[0]) {
					r_strbuf_appendf (res, " color='%s'", text_color);
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
			tmp = (int) (size_t) (ptr - str);
			r_strbuf_append_n (res, str, tmp);
			if (!ptr[1]) {
				// write new line if it's the end of the output
				r_strbuf_append (res, "\n");
			} else {
				r_strbuf_append (res, "<br />");
			}
			str = ptr + 1;
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
			r_strbuf_append_n (res, str, tmp);
			r_strbuf_append (res, "&nbsp;");
			str = ptr + 1;
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
			} else if (IS_DIGIT (ptr[0]) && ptr[1] == ';' && IS_DIGIT (ptr[2])) {
				char *m = strchr (ptr, 'm');
				if (m) {
					gethtmlrgb (ptr, background_color, sizeof (background_color));
					need_to_set = true;
					ptr = m;
					str = ptr + 1;
					esc = 0;
				}
			} else if (IS_DIGIT (ptr[0]) && IS_DIGIT (ptr[1]) && ptr[2] == ';') {
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
			} else if ((ptr[0] == '0' || ptr[0] == '1') && ptr[1] == ';' && IS_DIGIT (ptr[2])) {
				// bg color is kind of ignored, but no glitch so far
				r_cons_gotoxy (0, 0);
				ptr += 4;
				esc = 0;
				str = ptr;
				continue;
			} else if ((ptr[0] == '0' || ptr[0] == '1') && ptr[1] == ';' && ptr[2] == '0') {
				// bg color is kind of ignored, but no glitch so far
				r_cons_gotoxy (0, 0);
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
	r_strbuf_append_n (res, str, ptr - str);
	if (has_set) {
		r_strbuf_append (res, "</font>");
	}
	if (newlen) {
		*newlen = res->len;
	}
	return r_strbuf_drain (res);
}


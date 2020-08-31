/* radare - LGPL - Copyright 2009-2020 - pancake, nibble */

#include <r_cons.h>

static const char *gethtmlrgb(const char *str) {
	ut8 r = 0, g = 0, b = 0;
	if (r_cons_rgb_parse (str, &r, &g, &b, 0)) {
		static char buf[32];
		sprintf (buf, "#%02x%02x%02x", r, g, b);
		return buf;
	}
	return "";
}

static const char *gethtmlcolor(const char ptrch, const char *def) {
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
	case '9': break; // ???
	}
	return def;
}

// TODO: move into r_util/str
R_API char *r_cons_html_filter(const char *ptr, int *newlen) {
	const char *str = ptr;
	int esc = 0;
	int len = 0;
	int inv = 0;
	int tmp;
	bool tag_font = false;
	if (!ptr) {
		return NULL;
	}
	RStrBuf *res = r_strbuf_new ("");
	if (!res) {
		return NULL;
	}
	for (; ptr[0]; ptr = ptr + 1) {
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
			tmp = (int) (size_t) (ptr - str);
			r_strbuf_append_n (res, str, tmp);
			r_strbuf_append (res, "&lt;");
			str = ptr + 1;
			continue;
		} else if (ptr[0] == '>') {
			tmp = (int) (size_t) (ptr - str);
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
			tmp = (int) (size_t) (ptr - str);
			r_strbuf_append_n (res, str, tmp);
			if (tag_font) {
				r_strbuf_append (res, "</font>");
				tag_font = false;
			}
			str = ptr + 1;
			continue;
		}
		if (esc == 1) {
			// \x1b[2J
			if (ptr[0] != '[') {
				eprintf ("Oops invalid escape char\n");
				esc = 0;
				str = ptr + 1;
				continue;
			}
			esc = 2;
			continue;
		} else if (esc == 2) {
			// TODO: use dword comparison here
			if (ptr[0] == '0' && ptr[1] == 'J') { // R_CONS_CLEAR_FROM_CURSOR_TO_END
				ptr += 2;
				esc = 0;
				str = ptr;
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
			} else if (!strncmp (ptr, "48;5;", 5) || !strncmp (ptr, "48;2;", 5)) {
				char *end = strchr (ptr, 'm');
				r_strbuf_appendf (res, "<font style='background-color:%s'>", gethtmlrgb (ptr));
				tag_font = true;
				ptr = end;
				str = ptr + 1;
				esc = 0;
			} else if (!strncmp (ptr, "38;5;", 5) || !strncmp (ptr, "38;2;", 5)) {
				char *end = strchr (ptr, 'm');
				r_strbuf_appendf (res, "<font color='%s'>", gethtmlrgb (ptr));
				tag_font = true;
				ptr = end;
				str = ptr + 1;
				esc = 0;
			} else if (ptr[0] == '0' && ptr[1] == ';' && ptr[2] == '0') {
				// wtf ?
				r_cons_gotoxy (0, 0);
				ptr += 4;
				esc = 0;
				str = ptr;
				continue;
			} else if (ptr[0] == '0' && ptr[1] == 'm') {
				str = (++ptr) + 1;
				esc = inv = 0;
				continue;
				// reset color
			} else if (ptr[0] == '7' && ptr[1] == 'm') {
				str = (++ptr) + 1;
				inv = 128;
				esc = 0;
				continue;
				// reset color
			} else if (ptr[0] == '3' && ptr[2] == 'm') {
				const char *htmlColor = gethtmlcolor (ptr[1], inv? "#fff":NULL);
				if (htmlColor) {
					r_strbuf_appendf (res, "<font color='%s'>", htmlColor);
				}
				tag_font = true;
				ptr = ptr + 1;
				str = ptr + 2;
				esc = 0;
				continue;
			} else if (ptr[0] == '4' && ptr[2] == 'm') {
				const char *htmlColor = gethtmlcolor (ptr[1], inv? "#000":NULL);
				if (htmlColor) {
					r_strbuf_appendf (res, "<font style='background-color:%s'>", htmlColor);
				}
				tag_font = true;
				ptr = ptr + 1;
				str = ptr + 2;
				esc = 0;
				continue;
			}
		}
		len++;
	}
	if (tag_font) {
		r_strbuf_append (res, "</font>");
	}
	r_strbuf_append_n (res, str, ptr - str);
	if (newlen) {
		*newlen = res->len;
	}
	return r_strbuf_drain (res);
}


/* radare - LGPL - Copyright 2007-2026 - pancake */

#include <r_bin.h>

static void fill_line(RStrBuf *sb, int maxcol) {
	int i;
	if (maxcol < 1) {
		return;
	}
	for (i = 0; i < maxcol; i++) {
		r_strbuf_append (sb, " ");
	}
	r_strbuf_append (sb, Color_RESET_BG);
	r_strbuf_append (sb, Color_RESET);
	r_strbuf_append (sb, "\n");
}

R_API char *r_str_md2txt(const char *page, bool usecolor) {
	char *b = r_file_slurp (page, NULL);
	RStrBuf *sb = r_strbuf_new ("");
	int col = 0;
	const int maxcol = 75;
	bool codeblock = false;
	bool title = false;
	bool codeblockline = false;
	while (*b) {
		int ch = *b;
	repeat:
		switch (ch) {
		case 10: // '\n'
			if (codeblock || title) {
				const int j = title? maxcol + 2: maxcol - 4;
				if (usecolor) {
					fill_line (sb, j - col);
					if (title) {
						r_strbuf_append (sb, Color_BLACK);
						r_strbuf_append (sb, Color_BGBLUE);
						fill_line (sb, maxcol + 4);
					}
				}
				title = false;
			}
			col = 0;
			if (usecolor) {
				r_strbuf_append (sb, Color_RESET);
			}
			if (!codeblock) {
				r_strbuf_append (sb, "\n");
			}
			if (codeblockline) {
				codeblock = false;
				codeblockline = false;
			}
			break;
		case '\t':
			if (col == 0) {
				codeblock = true;
				codeblockline = true;
			} else {
				r_strbuf_append (sb, "  ");
			}
			break;
		case 13:
			// ignore
			break;
		default:
			if (col > maxcol) {
				ch = 10;
				if (*b == ' ') {
					b++;
				} else {
					if (codeblock) {
						col = 1;
						// nothing
					} else {
						r_strbuf_append (sb, "-");
					}
				}
				b--;
				goto repeat;
			}
			if (col == 0) {
				if (r_str_startswith (b, "```")) {
					while (*b && *b != '\n') {
						b++;
					}
					codeblock = !codeblock;
					if (!codeblock) {
						r_strbuf_append (sb, Color_RESET_BG);
					}
					continue;
				}
				if (!codeblock && r_str_startswith (b, "###")) {
					if (usecolor) {
						r_strbuf_append (sb, Color_BLACK);
						r_strbuf_append (sb, Color_BGBLUE);
						fill_line (sb, maxcol + 4);
						r_strbuf_append (sb, Color_BLUE);
						r_strbuf_append (sb, Color_BGCYAN);
					}
					r_strbuf_append (sb, "  ");
					b += 3;
					title = true;
				} else if (!codeblock && r_str_startswith (b, "##")) {
					if (usecolor) {
						r_strbuf_append (sb, Color_BLACK);
						r_strbuf_append (sb, Color_BGBLUE);
						fill_line (sb, maxcol + 4);
						r_strbuf_append (sb, Color_BLACK);
						r_strbuf_append (sb, Color_BGBLUE);
					}
					r_strbuf_append (sb, "  ");
					ch = ' ';
					b += 2;
					title = true;
				} else if (!codeblock && r_str_startswith (b, "#")) {
					RStrBuf *sb2 = r_strbuf_new ("");
					while (*b) {
						if (*b == '\n') {
							b++;
							break;
						}
						r_strbuf_appendf (sb2, "%c", *b);
						b++;
					}
					char *sb2s = r_strbuf_drain (sb2);
					char *sb2ss = r_str_ss (sb2s, 0, 0);
					char *p = sb2ss;
					char *nextlist = strstr (p, "\n");
					if (usecolor) {
						r_strbuf_append (sb, Color_BLACK);
						r_strbuf_append (sb, Color_BGGREEN);
					}
					while (nextlist) {
						char *line = r_str_ndup (p, nextlist - p);
						r_strbuf_appendf (sb, "%s", line);
						int col = strlen (line);
						int i;
						for (i = col; i < maxcol + 1; i++) {
							r_strbuf_append (sb, " ");
						}
						if (usecolor) {
							r_strbuf_append (sb, "  ");
							r_strbuf_append (sb, " " Color_RESET_BG "" Color_RESET "\n" Color_BGGREEN "" Color_BLACK);
						} else {
							r_strbuf_append (sb, "   \n");
						}
						p = nextlist + 1;
						nextlist = strstr (p, "\n");
					}
					// r_strbuf_append (sb, sb2ss);
					free (sb2ss);
					free (sb2s);
					if (usecolor) {
						r_strbuf_append (sb, Color_RESET_BG "" Color_RESET "\n");
					} else {
						r_strbuf_append (sb, "\n");
					}
					title = false;
					break;
				} else {
					if (codeblock) {
						if (usecolor) {
							r_strbuf_append (sb, "  " Color_BGYELLOW " " Color_BLACK);
						} else {
							r_strbuf_append (sb, "   ");
						}
					} else {
						r_strbuf_append (sb, "  ");
					}
				}
			}
			col++;
			r_strbuf_appendf (sb, "%c", ch);
			break;
		}
		b++;
	}
	return r_strbuf_drain (sb);
}

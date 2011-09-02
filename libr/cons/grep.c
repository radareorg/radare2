/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> nibble<develsec.org> */

#include <r_cons.h>
#include <r_util.h>

R_API void r_cons_grep(const char *str) {
	RCons *cons;
	char buf[1024];
	char *ptr, *optr, *ptr2, *ptr3;
	cons = r_cons_singleton ();
	cons->grep.str = NULL;
	cons->grep.nstrings = 0;
	cons->grep.tokenfrom = 0;
	cons->grep.tokento = ST32_MAX;
	cons->grep.line = -1;
	cons->grep.counter = cons->grep.neg = 0;

	if (str == NULL || !*str)
		return;

	if (*str == '!') { // neg
		cons->grep.neg = 1;
		str++;
	}
	if (*str == '?') { // counter
		cons->grep.counter = 1;
		str++;
	}

	strncpy (buf, str, sizeof (buf));
	ptr = buf;
	ptr3 = strchr (ptr, '['); // column number
	if (ptr3) {
		ptr3[0]='\0';
		cons->grep.tokenfrom = r_num_get (cons->num, ptr3+1);
		ptr3 = strchr (ptr3+1, '-');
		if (ptr3) {
			cons->grep.tokento = r_num_get (cons->num, ptr3+1);
			if (cons->grep.tokento == 0)
				cons->grep.tokento = ST32_MAX;
		} else cons->grep.tokento = cons->grep.tokenfrom;
		if (cons->grep.tokenfrom<0)
			cons->grep.tokenfrom = 0;
		if (cons->grep.tokento<0)
			cons->grep.tokento = ST32_MAX;
	}
	ptr2 = strchr (ptr, ':'); // line number
	if (ptr2) {
		*ptr2 = '\0';
		cons->grep.line = r_num_get (cons->num, ptr2+1);
		if (cons->grep.line<0)
			cons->grep.line = -1;
	}
	free (cons->grep.str);
	if (*ptr) {
		cons->grep.str = (char *)strdup (ptr);
		do {
			optr = ptr;
			ptr = strchr (ptr, ','); // grep keywords
			if (ptr) {
				ptr[0] = '\0';
				ptr = ptr+1;
			}
			// TODO: check if keyword > 64
			strncpy (cons->grep.strings[cons->grep.nstrings], optr, 63);
			cons->grep.nstrings++;
		} while (ptr);
	} else {
		cons->grep.str = strdup (ptr);
		cons->grep.nstrings++;
		cons->grep.strings[0][0] = 0;
	}
}

R_API int r_cons_grepbuf(char *buf, int len) {
	RCons *cons = r_cons_singleton ();
	char *tline, *tbuf, *p, *out, *in = buf;
	int ret, buffer_len = 0, l = 0, tl = 0;

	out = tbuf = calloc (1, len);
	tline = malloc (len);
	cons->lines = 0;
	while (in-buf<len) {
		p = strchr (in, '\n');
		if (!p) {
			free (tbuf);
			free (tline);
			return 0;
		}
		l = p-in;
		if (l > 0) {
			memcpy (tline, in, l);
			tl = r_str_ansi_filter (tline, l);
			if (tl < 0)
				ret = -1;
			else ret = r_cons_grep_line (tline, tl);
			if (ret > 0) {
				if (cons->grep.line == -1 ||
					(cons->grep.line != -1 && cons->grep.line == cons->lines)) {
					memcpy (out, tline, ret);
					memcpy (out+ret, "\n", 1);
					out += ret+1;
					buffer_len += ret+1;
				}
				cons->lines++;
			} else if (ret < 0) {
				free (tbuf);
				free (tline);
				return 0;
			} 
			in += l+1;
		} else in++;
	}
	memcpy (buf, tbuf, len);
	cons->buffer_len = buffer_len;
	free (tbuf);
	free (tline);
	if (cons->grep.counter) {
		snprintf (cons->buffer, cons->buffer_len, "%d\n", cons->lines);
		cons->buffer_len = strlen (cons->buffer);;
	}
	return cons->lines;
}

R_API int r_cons_grep_line(char *buf, int len) {
	RCons *cons = r_cons_singleton ();
	const char delims[6][2] = { "|", "/", "\\", ",", ";", "\t" };
	char *in, *out, *tok = NULL;
	int hit = cons->grep.neg;
	int i, j, outlen = 0;

	in = calloc (1, len+1);
	out = calloc (1, len+2);
	memcpy (in, buf, len);

	if (cons->grep.nstrings>0) {
		for (i=0; i<cons->grep.nstrings; i++)
			if (strstr (in, cons->grep.strings[i])) {
				hit = !cons->grep.neg;
				break;
			}
	} else hit = 1;

	if (hit) {
		if ((cons->grep.tokenfrom != 0 || cons->grep.tokento != ST32_MAX) &&
			(cons->grep.line == -1 || cons->grep.line == cons->lines)) {
			for (i=0; i<len; i++) for (j=0; j<6; j++)
				if (in[i] == delims[j][0])
					in[i] = ' ';
			for (i=0; i <= cons->grep.tokento; i++) {
				tok = (char *) strtok (i?NULL:in, " ");
				if (tok) {
					if (i >= cons->grep.tokenfrom) {
						int toklen = strlen (tok);
						memcpy (out+outlen, tok, toklen);
						memcpy (out+outlen+toklen, " ", 2);
						outlen += toklen+1;
					}
				} else {
					if (strlen (out) == 0) {
						free (in);
						free (out);
						return -1;
					} else break;
				}
			}
			outlen = outlen>0? outlen - 1: 0;
			if (outlen>len) { // should never happen
				eprintf ("r_cons_grep_line: wtf, how you reach this?\n");
				return -1;
			}
			memcpy (buf, out, len);
			len = outlen;
			
		}
	} else len = 0;

	free (in);
	free (out);

	return len;
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

// XXX: rename char *r_cons_filter_html(const char *ptr)
R_API int r_cons_html_print(const char *ptr) {
	const char *str = ptr;
	int esc = 0;
	int len = 0;
	int inv = 0;
	int tmp;

	if (!ptr)
		return 0;
	for (;ptr[0]; ptr = ptr + 1) {
		if (ptr[0] == '\n') {
			printf ("<br />");
			fflush (stdout);
		}
		if (ptr[0] == 0x1b) {
			esc = 1;
			tmp = (int) (size_t) (ptr-str);
			if (write (1, str, tmp) != tmp)
				eprintf ("r_cons_html_print: write: error\n");
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
		} else 
		if (esc == 2) {
			if (ptr[0]=='2'&&ptr[1]=='J') {
				printf ("<hr />\n"); fflush(stdout);
				ptr++;
				esc = 0;
				str = ptr;
				continue;
			} else
			if (ptr[0]=='0'&&ptr[1]==';'&&ptr[2]=='0') {
				r_cons_gotoxy (0,0);
				ptr += 4;
				esc = 0;
				str = ptr;
				continue;
			} else
			if (ptr[0]=='0'&&ptr[1]=='m') {
				str = (++ptr) +1;
				esc = inv = 0;
				continue;
				// reset color
			} else
			if (ptr[0]=='7'&&ptr[1]=='m') {
				str = (++ptr) +1;
				inv = 128;
				esc = 0;
				continue;
				// reset color
			} else
			if (ptr[0]=='3' && ptr[2]=='m') {
				// TODO: honor inv here
				printf ("<font color='%s'>", gethtmlcolor (ptr[1], "#000"));
				fflush(stdout);
				ptr = ptr + 1;
				str = ptr + 2;
				esc = 0;
				continue;
			} else
			if (ptr[0]=='4' && ptr[2]=='m') {
				// TODO: USE INV HERE
				printf ("<font style='background-color:%s'>", gethtmlcolor (ptr[1], "#fff"));
				fflush(stdout);
			}
		} 
		len++;
	}
	write (1, str, ptr-str);
	return len;
}

/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> nibble<develsec.org> */

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
		str = str + 1;
	}
	if (*str == '?') { // counter
		cons->grep.counter = 1;
		str = str + 1;
	}

	strncpy (buf, str, sizeof (buf));
	ptr = buf;
	ptr3 = strchr (ptr, '['); // column number
	if (ptr3) {
		ptr3[0]='\0';
		cons->grep.tokenfrom = atoi (ptr3+1);
		ptr3 = strchr (ptr3+1, '-');
		if (ptr3) {
			cons->grep.tokento = atoi (ptr3+1);
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
		ptr2[0]='\0';
		cons->grep.line = atoi (ptr2+1);
		if (cons->grep.line<0)
			cons->grep.line = -1;
	}
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
	return cons->lines;
}

R_API int r_cons_grep_line(char *buf, int len) {
	RCons *cons = r_cons_singleton ();
	const char delims[6][2] = { "|", "/", "\\", ",", ";", "\t" };
	char *in, *out, *tok = NULL;
	int hit = cons->grep.neg;
	int i, j;

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
				if (i==0) tok = (char *)strtok (in, " ");
				else tok = (char *)strtok (NULL, " ");
				if (tok == NULL) {
					if (strlen (out) == 0) {
						free (in);
						free (out);
						return -1;
					} else break;
				}
				if (i >= cons->grep.tokenfrom) {
					strcat (out, tok);
					strcat (out, " ");
				}
			}
			len = strlen (out) - 1;
			memcpy (buf, out, len);
		}
	} else len = 0;

	free (in);
	free (out);

	return len;
}

// XXX: rename char *r_cons_filter_html(const char *ptr)
R_API int r_cons_html_print(const char *ptr) {
	const char *str = ptr;
	int color = 0;
	int esc = 0;
	int len = 0;
	int inv = 0;
	int tmp;

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
				ptr = ptr +1;
				printf ("<hr />\n"); fflush(stdout);
				esc = 0;
				str = ptr;
				continue;
			} else
			if (ptr[0]=='0'&&ptr[1]==';'&&ptr[2]=='0') {
				ptr = ptr + 4;
				r_cons_gotoxy (0,0);
				esc = 0;
				str = ptr;
				continue;
			} else
			if (ptr[0]=='0'&&ptr[1]=='m') {
				ptr = ptr + 1;
				str = ptr + 1;
				inv = 0;
				esc = 0;
				continue;
				// reset color
			} else
			if (ptr[0]=='7'&&ptr[1]=='m') {
				inv = 128;
				ptr = ptr + 1;
				str = ptr + 1;
				esc = 0;
				continue;
				// reset color
			} else
			if (ptr[0]=='3' && ptr[2]=='m') {
				color = 1;
				switch(ptr[1]) {
				case '0': // BLACK
					printf ("<font color=black>"); fflush(stdout);
					break;
				case '1': // RED
					printf ("<font color=red>"); fflush(stdout);
					break;
				case '2': // GREEN
					printf ("<font color=green>"); fflush(stdout);
					break;
				case '3': // YELLOW
					printf ("<font color=yellow>"); fflush(stdout);
					break;
				case '4': // BLUE
					printf ("<font color=blue>"); fflush(stdout);
					break;
				case '5': // MAGENTA
					printf ("<font color=magenta>"); fflush(stdout);
					break;
				case '6': // TURQOISE
					printf ("<font color=#0ae>"); fflush(stdout);
					break;
				case '7': // WHITE
					printf ("<font color=white>"); fflush(stdout);
					break;
				case '8': // GRAY
					printf ("<font color=#777>"); fflush(stdout);
					break;
				case '9': // ???
					break;
				}
				ptr = ptr + 1;
				str = ptr + 2;
				esc = 0;
				continue;
			} else
			if (ptr[0]=='4' && ptr[2]=='m') {
				/* background color */
				switch (ptr[1]) {
				case '0': // BLACK
					printf ("<font style='background-color:#000'>"); fflush(stdout);
					break;
				case '1': // RED
					printf ("<font style='background-color:#f00'>"); fflush(stdout);
					break;
				case '2': // GREEN
					printf ("<font style='background-color:#0f0'>"); fflush(stdout);
					break;
				case '3': // YELLOW
					printf ("<font style='background-color:#ff0'>"); fflush(stdout);
					break;
				case '4': // BLUE
					printf ("<font style='background-color:#00f'>"); fflush(stdout);
					break;
				case '5': // MAGENTA
					printf ("<font style='background-color:#f0f'>"); fflush(stdout);
					break;
				case '6': // TURQOISE
					printf ("<font style='background-color:#aaf'>"); fflush(stdout);
					break;
				case '7': // WHITE
					printf ("<font style='background-color:#fff'>"); fflush(stdout);
					break;
				case '8': // GRAY
					printf ("<font style='background-color:#777'>"); fflush(stdout);
					break;
				case '9': // ???
					break;
				}
			}
		} 
		len++;
	}
	write (1, str, ptr-str);
	return len;
}

/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#include <r_cons.h>
#include <r_util.h>
#define sdb_json_indent r_cons_json_indent
#define sdb_json_unindent r_cons_json_unindent
#include "../../shlr/sdb/src/json/indent.c"

R_API void r_cons_grep_help() {
	eprintf (
"|Usage: [command]~[modifier][word,word][[column][:line]\n"
"| modifiers\n"
"|   &    all words must match to grep the line\n"
"|   ^    words must be placed at the beginning of line\n"
"|   !    negate grep\n"
"|   ?    count number of matching lines\n"
"|   ..   internal 'less'\n"
"|   {}   json indentation\n"
"|   {}.. less json indentation\n"
"| examples:\n"
"|   i~:0   # show fist line o 'i' output\n"
"|   pd~mov # disasm and grep for mov\n"
"|   pi~[0] # show only opcode\n"
	);
}

#define R_CONS_GREP_BUFSIZE 4096

R_API void r_cons_grep(const char *str) {
	int wlen, len;
	RCons *cons;
	char buf[R_CONS_GREP_BUFSIZE];
	char *ptr, *optr, *ptr2, *ptr3;

	if (!str || !*str)
		return;

	cons = r_cons_singleton ();
	cons->grep.str = NULL;
	cons->grep.neg = 0;
	cons->grep.amp = 0;
	cons->grep.end = 0;
	cons->grep.less = 0;
	cons->grep.json = 0;
	cons->grep.line = -1;
	cons->grep.begin = 0;
	cons->grep.counter = 0;
	cons->grep.nstrings = 0;
	cons->grep.tokenfrom = 0;
	cons->grep.tokento = ST32_MAX;

	while (*str) {
		switch (*str) {
		case '.':
			if (str[1]=='.') {
				cons->grep.less = 1;
				return;
			}
			str++;
			break;
		case '{':
			if (str[1]=='}') {
				cons->grep.json = 1;
				if (!strncmp (str, "{}..", 4))
					cons->grep.less = 1;
				str++;
				return;
			}
			str++;
			break;
		case '&': str++; cons->grep.amp = 1; break;
		case '^': str++; cons->grep.begin = 1;  break;
		case '!': str++; cons->grep.neg = 1; break;
		case '?': str++; cons->grep.counter = 1;
			if (*str=='?') {
				r_cons_grep_help ();
				return;
			}
			break;
		default: goto while_end;
		}
	} while_end:

	len = strlen (str)-1;
	if (len > R_CONS_GREP_BUFSIZE - 1) {
		eprintf("r_cons_grep: too long!\n");
		return;
	}
	if (len>0 && str[len] == '?') {
		cons->grep.counter = 1;
		strncpy (buf, str, R_MIN (len, sizeof (buf)-1));
		buf[len]=0;
		len--;
	} else strncpy (buf, str, sizeof (buf)-1);

	if (len>1 && buf[len]=='$' && buf[len-1]!='\\') {
		cons->grep.end = 1;
		buf[len] = 0;
	}
	ptr = buf;
	ptr3 = strchr (ptr, '['); // column number
	if (ptr3) {
		ptr3[0] = '\0';
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
			if (ptr) *ptr++ = '\0';
			wlen = strlen (optr);	
			if (wlen==0) continue;
			if (wlen>=R_CONS_GREP_WORD_SIZE-1) {
				eprintf ("grep string too long\n");
				continue;
			}
			strncpy (cons->grep.strings[cons->grep.nstrings],
				optr, R_CONS_GREP_WORD_SIZE-1);
			cons->grep.nstrings++;
			if (cons->grep.nstrings>R_CONS_GREP_WORDS-1) {
				eprintf ("too many grep strings\n");
				break;
			}
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

	if (cons->grep.json) {
		char *out = sdb_json_indent (buf);
		free (cons->buffer);
		cons->buffer = out;
		cons->buffer_len = strlen (out);
		cons->buffer_sz = cons->buffer_len +1;
		cons->grep.json = 0;
		if (cons->grep.less) {
			cons->grep.less = 0;
			r_cons_less (cons->buffer);
		}
		return 3;
	}
	if (cons->grep.less) {
		cons->grep.less = 0;
		r_cons_less (buf);
		buf[0] = 0;
		cons->buffer_len = 0;
		if (cons->buffer)
			cons->buffer[0] = 0;
		free (cons->buffer);
		cons->buffer = NULL;
		return 0;
	}
	if (!cons->buffer) {
		cons->buffer_len = len+20;
		cons->buffer = malloc (cons->buffer_len);
		cons->buffer[0] = 0;
	}
	out = tbuf = calloc (1, len);
	tline = malloc (len);
	cons->lines = 0;
	while ((int)(size_t)(in-buf)<len) {
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
		if (cons->buffer_len<10) cons->buffer_len = 10; // HACK
		snprintf (cons->buffer, cons->buffer_len, "%d\n", cons->lines);
		cons->buffer_len = strlen (cons->buffer);
	}
	return cons->lines;
}

R_API int r_cons_grep_line(char *buf, int len) {
	RCons *cons = r_cons_singleton ();
	const char delims[4][2] = { "|", ",", ";", "\t" };
	char *in, *out, *tok = NULL;
	int hit = cons->grep.neg;
	int i, j, outlen = 0;

	in = calloc (1, len+1);
	out = calloc (1, len+2);
	memcpy (in, buf, len);

	if (cons->grep.nstrings>0) {
		int ampfail = cons->grep.amp;
		for (i=0; i<cons->grep.nstrings; i++) {
			char *p = strstr (in, cons->grep.strings[i]);
			if (!p) {
				ampfail = 0;
				continue;
			}
			if (cons->grep.begin)
				hit = (p == in)? 1: 0;
			else hit = !cons->grep.neg;
			// TODO: optimize without strlen without breaking t/feat_grep (grep end)
			if (cons->grep.end && (strlen (cons->grep.strings[i]) != strlen (p)))
				hit = 0 ;
			if (!cons->grep.amp)
				break;
		}
		if (cons->grep.amp)
			hit = ampfail;
	} else hit = 1;

	if (hit) {
		if ((cons->grep.tokenfrom != 0 || cons->grep.tokento != ST32_MAX) &&
			(cons->grep.line == -1 || cons->grep.line == cons->lines)) {
			const int delims_count = sizeof (delims) / 2;
			for (i=0; i<len; i++) for (j=0; j<delims_count; j++)
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
					if (!(*out)) {
						free (in);
						free (out);
						return -1;
					} else break;
				}
			}
			outlen = outlen>0? outlen - 1: 0;
			if (outlen>len) { // should never happen
				eprintf ("r_cons_grep_line: wtf, how you reach this?\n");
				free (in);
				free (out);
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
		if (0 && ptr[0] == '\n') {
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
			// TODO: use dword comparison here
			if (ptr[0]=='2' && ptr[1]=='J') {
				printf ("<hr />\n"); fflush(stdout);
				ptr++;
				esc = 0;
				str = ptr;
				continue;
			} else
			if (ptr[0]=='0' && ptr[1]==';' && ptr[2]=='0') {
				r_cons_gotoxy (0, 0);
				ptr += 4;
				esc = 0;
				str = ptr;
				continue;
			} else
			if (ptr[0]=='0' && ptr[1]=='m') {
				str = (++ptr) + 1;
				esc = inv = 0;
				continue;
				// reset color
			} else
			if (ptr[0]=='7' && ptr[1]=='m') {
				str = (++ptr) +1;
				inv = 128;
				esc = 0;
				continue;
				// reset color
			} else
			if (ptr[0]=='3' && ptr[2]=='m') {
				printf ("<font color='%s'>", gethtmlcolor (ptr[1], inv?"#fff":"#000"));
				fflush(stdout);
				ptr = ptr + 1;
				str = ptr + 2;
				esc = 0;
				continue;
			} else
			if (ptr[0]=='4' && ptr[2]=='m') {
				printf ("<font style='background-color:%s'>",
						gethtmlcolor (ptr[1], inv?"#000":"#fff"));
				fflush(stdout);
			}
		} 
		len++;
	}
	write (1, str, ptr-str);
	return len;
}

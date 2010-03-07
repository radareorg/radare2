/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_cons.h>

R_API void r_cons_grep(const char *str) {
	RCons *cons;
	char *optr, *tptr;
	char buf[1024];
	char *ptr, *ptr2, *ptr3;
	cons = r_cons_singleton ();
	cons->grep.counter = 0;
	/* set grep string */
	if (str != NULL && *str) {
		if (*str == '!') {
			cons->grep.neg = 1;
			str = str + 1;
		} else cons->grep.neg = 0;
		if (*str == '?') {
			cons->grep.counter = 1;
			str = str + 1;
		}
		ptr = buf;
		strncpy (ptr, str, sizeof (buf));

		ptr3 = strchr (ptr, '[');
		ptr2 = strchr (ptr, '#'); // XXX: this is no longer valid!!! its a comment.

		if (ptr3) {
			ptr3[0]='\0';
			cons->grep.token = atoi (ptr3+1);
			if (cons->grep.token<0)
				cons->grep.token--;
		}
		if (ptr2) {
			ptr2[0]='\0';
			cons->grep.line = atoi (ptr2+1);
		}

		cons->grep.nstrings = 0;
		if (*ptr) {
			free (cons->grep.str);
			cons->grep.str = (char *)strdup (ptr);
			/* set the rest of words to grep */
			cons->grep.nstrings = 0;
			// TODO: refactor this ugly loop
			optr = cons->grep.str;
			tptr = strchr (optr, '!');
			while (tptr) {
				tptr[0] = '\0';
				// TODO: check if keyword > 64
				strncpy (cons->grep.strings[cons->grep.nstrings], optr, 63);
				cons->grep.nstrings++;
				optr = tptr+1;
				tptr = strchr (optr, '!');
			}
			strncpy (cons->grep.strings[cons->grep.nstrings], optr, 63);
			cons->grep.nstrings++;
			ptr = optr;
		}
	} else {
		cons->grep.token = -1;
		cons->grep.line = -1;
		cons->grep.str = NULL;
		cons->grep.nstrings = 0;
	}
}

/* TODO: use const char * instead ..strdup at the beggining? */
// TODO: this must be a filter like the html one
R_API int r_cons_grepbuf(char *buf, int len) {
	RCons *cons = r_cons_singleton ();
	const char delims[6][2] = {"|", "/", "\\", ",", ";", "\t"};
	int donotline = 0;
	int i, j, hit = 0;
	char *n = memchr (buf, '\n', len);

	if (cons->grep.nstrings==0) {
		if (n) cons->lines++;
		return len;
	}

	if (cons->lastline==NULL)
		cons->lastline = cons->buffer;

	if (!n) return len;

	for (i=0; i<cons->grep.nstrings; i++) {
		cons->grep.str = cons->grep.strings[i];
		if ( (!cons->grep.neg && strstr (buf, cons->grep.str))
		  || (cons->grep.neg && !strstr (buf, cons->grep.str))) {
			hit = 1;
			break;
		}
	}

	if (hit) {
		if (cons->grep.line != -1) {
			if (cons->grep.line==cons->lines) {
				cons->lastline = buf+len;
				//r_cons_lines++;
			} else {
				donotline = 1;
				cons->lines++;
			}
		}
	} else donotline = 1;

	if (donotline) {
//eprintf ("aaa GREPSTRING (%s)\n", cons->grep.str);
		cons->buffer_len -= strlen (cons->lastline)-len;
		cons->lastline[0] = '\0';
		len = 0;
	} else {
//eprintf ("zzz GREPSTRING (%s)\n", cons->grep.str);
		if (cons->grep.token != -1) {
			//ptr = alloca(strlen(cons->lastline));
			char *tok = NULL;
			char *ptr = alloca (1024); // XXX
			strcpy (ptr, cons->lastline);
			for (i=0; i<len; i++) for (j=0; j<6; j++)
				if (ptr[i] == delims[j][0])
					ptr[i] = ' ';
			tok = ptr;
			for (i=0; tok!=NULL && i<=cons->grep.token; i++) {
				if (i==0) tok = (char *)strtok (ptr, " ");
				else tok = (char *)strtok (NULL, " ");
			}
			if (tok) {
				// XXX remove strlen here!
				cons->buffer_len -= strlen (cons->lastline)-len;
				len = strlen (tok);
				memcpy (cons->lastline, tok, len);
				if (cons->lastline[len-1]!='\n')
					memcpy (cons->lastline+len, "\n", 2);
				len++;
				cons->lastline += len;
			}
		} else cons->lastline = buf+len;
		cons->lines++;
	}
	return len;
}


// XXX: rename char *r_cons_filter_html(const char *ptr)
R_API int r_cons_html_print(const char *ptr) {
	const char *str = ptr;
	int color = 0;
	int esc = 0;
	int len = 0;
	int inv = 0;

	for (;ptr[0]; ptr = ptr + 1) {
		if (ptr[0] == '\n') {
			printf("<br />");
			fflush(stdout);
		}
		if (ptr[0] == 0x1b) {
			esc = 1;
			write(1, str, ptr-str);
			str = ptr + 1;
			continue;
		}
		if (esc == 1) {
			// \x1b[2J
			if (ptr[0] != '[') {
				fprintf(stderr, "Oops invalid escape char\n");
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
				printf("<hr />\n"); fflush(stdout);
				esc = 0;
				str = ptr;
				continue;
			} else
			if (ptr[0]=='0'&&ptr[1]==';'&&ptr[2]=='0') {
				ptr = ptr + 4;
				r_cons_gotoxy(0,0);
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
					printf("<font color=black>"); fflush(stdout);
					break;
				case '1': // RED
					printf("<font color=red>"); fflush(stdout);
					break;
				case '2': // GREEN
					printf("<font color=green>"); fflush(stdout);
					break;
				case '3': // YELLOW
					printf("<font color=yellow>"); fflush(stdout);
					break;
				case '4': // BLUE
					printf("<font color=blue>"); fflush(stdout);
					break;
				case '5': // MAGENTA
					printf("<font color=magenta>"); fflush(stdout);
					break;
				case '6': // TURQOISE
					printf("<font color=#0ae>"); fflush(stdout);
					break;
				case '7': // WHITE
					printf("<font color=white>"); fflush(stdout);
					break;
				case '8': // GRAY
					printf("<font color=#777>"); fflush(stdout);
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
				switch(ptr[1]) {
				case '0': // BLACK
					printf("<font style='background-color:#000'>"); fflush(stdout);
					break;
				case '1': // RED
					printf("<font style='background-color:#f00'>"); fflush(stdout);
					break;
				case '2': // GREEN
					printf("<font style='background-color:#0f0'>"); fflush(stdout);
					break;
				case '3': // YELLOW
					printf("<font style='background-color:#ff0'>"); fflush(stdout);
					break;
				case '4': // BLUE
					printf("<font style='background-color:#00f'>"); fflush(stdout);
					break;
				case '5': // MAGENTA
					printf("<font style='background-color:#f0f'>"); fflush(stdout);
					break;
				case '6': // TURQOISE
					printf("<font style='background-color:#aaf'>"); fflush(stdout);
					break;
				case '7': // WHITE
					printf("<font style='background-color:#fff'>"); fflush(stdout);
					break;
				case '8': // GRAY
					printf("<font style='background-color:#777'>"); fflush(stdout);
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

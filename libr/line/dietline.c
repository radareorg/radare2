/* radare - LGPL - Copyright 2007-2011 pancake<nopcode.org> */
/* dietline is a lighweight and portable library similar to GNU readline */

#include <r_line.h>

#include <string.h>
#include <stdlib.h>

#if __WINDOWS__
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#endif

static char *r_line_nullstr = "";

static int inithist() {
	ZERO_FILL (&I.history);
	I.history.data = (char **)malloc ((I.history.size+1024)*sizeof(char *));
	if (I.history.data==NULL)
		return R_FALSE;
	I.history.size = R_LINE_HISTSIZE;
	memset (I.history.data, 0, I.history.size*sizeof(char *));
	return R_TRUE;
}

/* initialize history stuff */
R_API int r_line_dietline_init() {
	ZERO_FILL (&I.completion);
	if (!inithist ())
		return R_FALSE;
	I.echo = R_TRUE;
	return R_TRUE;
}

static int r_line_readchar() {
	ut8 buf[2];
	*buf = '\0';
#if __WINDOWS__
	BOOL ret;
	LPDWORD mode, out;
	HANDLE h = GetStdHandle (STD_INPUT_HANDLE);

	GetConsoleMode (h, &mode);
	SetConsoleMode (h, 0); // RAW
	ret = ReadConsole (h, buf, 1, &out, NULL);
	// wine hack-around
	if (!ret && read (0, buf, 1) != 1)
		return -1;
	SetConsoleMode (h, mode);
#else
	do {
		int ret = read (0, buf, 1);
		if (ret == -1)
			return 0; // read no char
		if (ret == 0) // EOF
			return -1;
//eprintf ("(((%x)))\n", *buf);
		// TODO: add support for other invalid chars
		if (*buf==0xc2 || *buf==0xc3) {
			read (0, buf+1, 1);
//eprintf ("(((%x)))\n", buf[1]);
			*buf = '\0';
		}	
	} while (*buf == '\0');
#endif
	return buf[0];
}

R_API int r_line_hist_add(const char *line) {
	if (!I.history.data)
		inithist ();
	if (I.history.top>=I.history.size)
		I.history.top = I.history.index = 0; // workaround
	if (line && *line) { // && I.history.index < I.history.size) {
		I.history.data[I.history.top++] = strdup (line);
		I.history.index = I.history.top;
		return R_TRUE;
	}
	return R_FALSE;
}

static int r_line_hist_up() {
	if (!I.history.data)
		inithist ();
	if (I.history.index>0) {
		strncpy (I.buffer.data, I.history.data[--I.history.index], R_LINE_BUFSIZE-1);
		I.buffer.index = I.buffer.length = strlen (I.buffer.data);
		return R_TRUE;
	}
	return R_FALSE;
}

static int r_line_hist_down() {
	I.buffer.index = 0;
	if (!I.history.data)
		inithist ();
	if (I.history.index<I.history.size) {
		if (I.history.data[I.history.index] == NULL) {
			I.buffer.data[0]='\0';
			I.buffer.index = I.buffer.length = 0;
			return 0;
		}
		strncpy (I.buffer.data, I.history.data[I.history.index++], R_LINE_BUFSIZE-1);
		I.buffer.index = I.buffer.length = strlen (I.buffer.data);
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_line_hist_list() {
	int i = 0;
	if (!I.history.data)
		inithist ();
	if (I.history.data != NULL)
		for (i=0; i<I.history.size && I.history.data[i]; i++)
			printf ("%.3d  %s\n", i, I.history.data[i]);
	return i;
}

R_API void r_line_hist_free() {
	int i;
	if (I.history.data != NULL)
	for (i=0; i<I.history.size; i++) {
		free (I.history.data[i]);
		I.history.data[i] = NULL;
	}
	free (I.history.data);
	I.history.data = NULL;
	I.history.index = 0;
}

/* load history from file. TODO: if file == NULL load from ~/.<prg>.history or so */
R_API int r_line_hist_load(const char *file) {
	char buf[R_LINE_BUFSIZE];
	FILE *fd;

	char *path = r_str_home (file);
	if (path == NULL)
		return R_FALSE;
	if (!(fd = fopen (path, "r"))) {
		free (path);
		return R_FALSE;
	}

	while (fgets(buf, sizeof(buf), fd) != NULL) {
		r_line_hist_add (buf);
	}
	fclose (fd);

	free (path);
	return R_TRUE;
}

R_API int r_line_hist_save(const char *file) {
	FILE *fd;
	int i, ret = R_FALSE;
	char *path = r_str_home (file);
	if (path != NULL) {
		fd = fopen (path, "w");
		if (fd != NULL && I.history.data) {
			for (i=0; i<I.history.index; i++) {
				fputs (I.history.data[i], fd);
				fputs ("\n", fd);
			}
			fclose (fd);
			ret = R_TRUE;
		}
	}
	free (path);
	return ret;
}

R_API int r_line_hist_chop(const char *file, int limit) {
	/* TODO */
	return 0;
}

R_API void r_line_autocomplete() {
	int argc = 0;
	char *p;
	const char **argv = NULL;
	int i, j, opt, plen, len = 0;
	int cols = r_cons_get_size (NULL)*0.82;

	/* prepare argc and argv */
	if (I.completion.run != NULL) {
		I.completion.run (&I);
		opt = argc = I.completion.argc;
		argv = I.completion.argv;
	} else opt = 0;

	p = r_str_lchr (I.buffer.data, ' ');
	if (p) {
		p++;
		plen = sizeof (I.buffer.data)-(int)(size_t)(p-I.buffer.data);
	} else {
		p = I.buffer.data;
		plen = sizeof (I.buffer.data);
	}
	/* autocomplete */
	if (argc==1) {
		int largv0 = strlen (argv[0]);
		if (largv0+3 < plen) {
			memcpy (p, argv[0], largv0);
			memcpy (p+largv0, " ", 2);
			I.buffer.length = I.buffer.index = strlen (I.buffer.data);
		}
	} else
	if (argc>0) {
		if (*p) {
			// TODO: do not use strdup here
			// TODO: avoid overflow
			char *root = strdup (argv[0]);
			// try to autocomplete argument
			for (i=0; i<argc; i++) {
				j = 0;
				while (argv[i][j]==root[j] && root[j] != '\0') j++;
				free (root);
				root = strdup (argv[i]);
				if (j<strlen (root))
					root[j] = 0;
			}
			strcpy (p, root);
			I.buffer.index = I.buffer.length = strlen (I.buffer.data);
			free (root);
		}
	}

	/* show options */
	if (opt>1 && I.echo) {
		const int sep = 3;
		int col = 10;
		int slen;
		printf ("%s%s\n", I.prompt, I.buffer.data);
		for (i=0; i<argc && argv[i]; i++) {
			int l = strlen (argv[i]);
			if ((sep+l)>col)
				col = sep+l;
			if (col>(cols>>1)) {
				col = (cols>>1);
				break;
			}
		}
		for (len=i=0; i<argc && argv[i]; i++) {
			slen = strlen (argv[i]);
			len += (slen>col)? (slen+sep): col+sep;
			if (len+col>cols) {
				printf ("\n");
				len = 0;
			}
			printf ("%-*s   ", col-sep, argv[i]);
		}
		printf ("\n");
	}
	fflush (stdout);
}

/* main readline function */
//R_API char *r_line_readline(const char *prompt, RLineCallba 
R_API char *r_line_readline() {
	int columns = r_cons_get_size (NULL)-2;
	const char *gcomp_line = "";
	static int gcomp_idx = 0;
	static int gcomp = 0;
	signed char buf[10];
	int ch, i; /* grep completion */

	I.buffer.index = I.buffer.length = 0;
	I.buffer.data[0] = '\0';
	if (I.disable) {
		I.buffer.data[0]='\0';
		if (!fgets (I.buffer.data, R_LINE_BUFSIZE-1, stdin))
			return NULL;
		I.buffer.data[strlen (I.buffer.data)] = '\0';
		return (*I.buffer.data)? I.buffer.data : r_line_nullstr;
	}

	memset (&buf, 0, sizeof buf);
	r_cons_set_raw (1);

//r_cons_gotoxy()
	if (I.echo) {
		r_cons_clear_line();
		eprintf ("\x1b[0K\r%s", I.prompt);
		fflush (stdout);
	}
	for (;;) {
#if 0
		if (I.echo) {
			printf("  (");
			for(i=1;i<argc;i++) {
				if (I.buffer.length==0||!strncmp(argv[i], I.buffer.data, I.buffer.length)) {
					len+=strlen(argv[i])+1;
					if (len+I.buffer.length+4 >= columns) break;
					printf("%s ", argv[i]);
				}
			}
			printf(")");
			fflush(stdout);
		}
#endif
		I.buffer.data[I.buffer.length]='\0';
		ch = r_line_readchar ();
		if (ch == -1)
			return NULL; //I.buffer.data;
		buf[0] = ch;
		
		if (I.echo)
			r_cons_clear_line();
		columns = r_cons_get_size (NULL)-2;
		if (columns<1)
			columns = 40;
#if __WINDOWS__
		if (I.echo)
			printf ("\r%*c\r", columns, ' ');
#else
		if (I.echo)
			printf ("\r\x1b[2K\r"); //%*c\r", columns, ' ');
#endif
		switch (*buf) {
		//case -1: // ^D
		//	return NULL;
		case 0: // control-space
			/* ignore atm */
			break;
		case 1: // ^A
			I.buffer.index = 0;
			break;
		case 5: // ^E
			I.buffer.index = I.buffer.length;
			break;
		case 3: // ^C 
			if (I.echo)
				eprintf ("^C\n");
			I.buffer.index = I.buffer.length = 0;
			*I.buffer.data = '\0';
			goto _end;
		case 4: // ^D
			if (I.echo)
				printf ("^D\n");
			if (!I.buffer.data[0]) { /* eof */
				r_cons_set_raw (R_FALSE);
				return NULL;
			}
			break;
		case 10: // ^J -- ignore
			return I.buffer.data;
		case 11: // ^K -- ignore
			break;
		case 12: // ^L -- right
			I.buffer.index = (I.buffer.index<I.buffer.length)?
				I.buffer.index+1 : I.buffer.length;
			if (I.echo)
				printf ("\x1b[2J\x1b[0;0H");
			fflush (stdout);
			break;
		case 18: // ^R -- autocompletion
			gcomp = 1;
			break;
		case 19: // ^S -- backspace
			if (gcomp) gcomp--;
			else I.buffer.index = I.buffer.index? I.buffer.index-1: 0;
			break;
		case 21: // ^U - cut
			free (I.clipboard);
			I.clipboard = strdup (I.buffer.data);
			I.buffer.data[0] = '\0';
			I.buffer.length = 0;
			I.buffer.index = 0;
			break;
		case 23: // ^W ^w
			if (I.buffer.index>0) {
				for (i=I.buffer.index-1; i>0&&I.buffer.data[i]==' '; i--);
				for (; i&&I.buffer.data[i]!=' '; i--);
				if (!i) for (; i>0&&I.buffer.data[i]==' '; i--);
				if (i>0) i++; else if (i<0) i=0;
				strcpy (I.buffer.data+i, I.buffer.data+I.buffer.index);
				I.buffer.length = strlen (I.buffer.data);
				I.buffer.index = i;
			}
			break;
		case 25: // ^Y - paste
			if (I.clipboard != NULL) {
				I.buffer.length += strlen(I.clipboard);
				// TODO: support endless strings
				if (I.buffer.length < R_LINE_BUFSIZE) {
					I.buffer.index = I.buffer.length;
					strcat (I.buffer.data, I.clipboard);
				} else I.buffer.length -= strlen (I.clipboard);
			}
			break;
		case 16:
			if (gcomp) {
				gcomp_idx++;
			} else r_line_hist_up ();
			break;
		case 14:
			if (gcomp) {
				if (gcomp_idx>0)
					gcomp_idx--;
			} else r_line_hist_down ();
			break;
		case 27: //esc-5b-41-00-00
			buf[0] = r_line_readchar();
			if (buf[0] == -1)
				return NULL;
			buf[1] = r_line_readchar();
			if (buf[1] == -1)
				return NULL;
			if (buf[0]==0x5b) {
				switch (buf[1]) {
				case 0x33: // supr
					if (I.buffer.index<I.buffer.length)
						memmove (I.buffer.data+I.buffer.index,
							I.buffer.data+I.buffer.index+1,
							strlen (I.buffer.data+I.buffer.index+1)+1);
					buf[1] = r_line_readchar ();
					if (buf[1] == -1)
						return NULL;
					break;
				/* arrows */
				case 0x41:
					if (gcomp) {
						gcomp_idx++;
					} else r_line_hist_up ();
					break;
				case 0x42:
					if (gcomp) {
						if (gcomp_idx>0)
							gcomp_idx--;
					} else r_line_hist_down ();
					break;
				case 0x43: // end
					I.buffer.index = I.buffer.index<I.buffer.length?
						I.buffer.index+1: I.buffer.length;
					break;
				case 0x44: // begin
					I.buffer.index = I.buffer.index? I.buffer.index-1: 0;
					break;
				case 0x31: // control + arrow
					r_cons_readchar ();
					r_cons_readchar ();
					ch = r_cons_readchar ();
					switch (ch) {
					case 0x41:
						//first
						I.buffer.index = 0;
						break;
					case 0x44:
						// previous word
						for (i=I.buffer.index; i>0; i--) {
							if (I.buffer.data[i] == ' ') {
								I.buffer.index = i-1;
								break;
							}
						}
						if (I.buffer.data[i] != ' ')
							I.buffer.index = 0;
						break;
					case 0x42:
						//end
						I.buffer.index = I.buffer.length;
						break;
					case 0x43:
						// next word
						for (i=I.buffer.index; i<I.buffer.length; i++) {
							if (I.buffer.data[i] == ' ') {
								I.buffer.index = i+1;
								break;
							}
						}
						if (I.buffer.data[i] != ' ')
							I.buffer.index = I.buffer.length;
						break;
					}
					r_cons_set_raw (1);
					break;
				case 0x48: // Start
					I.buffer.index = 0;
					break;
				case 0x34:
					r_cons_readchar ();
				case 0x46: // End
					I.buffer.index = I.buffer.length;
					break;
				}
			}
			break;
		case 8:
		case 127:
			if (I.buffer.index < I.buffer.length) {
				if (I.buffer.index>0) {
					I.buffer.index--;
					memmove (I.buffer.data+I.buffer.index,
						I.buffer.data+I.buffer.index+1,
						strlen (I.buffer.data+I.buffer.index));
				}
			} else {
				I.buffer.index = --I.buffer.length;
				if (I.buffer.length<0) I.buffer.length=0;
				I.buffer.data[I.buffer.length]='\0';
			}
			if (I.buffer.index<0)
				I.buffer.index = 0;
			break;
		case 9: // tab
			r_line_autocomplete ();
			break;
		case 13:
			if (gcomp && I.buffer.length>0) {
				// XXX overflow
				strcpy (I.buffer.data, gcomp_line);
				I.buffer.length = strlen (gcomp_line);
			}
			gcomp_idx = gcomp = 0;
			goto _end;
#if 0
			// force command fit
			for(i=1;i<argc;i++) {
				if (I.buffer.length==0 || !strncmp(argv[i], I.buffer.data, I.buffer.length)) {
					printf("%*c", columns, ' ');
					printf("\r");
					printf("\n\n(%s)\n\n", I.buffer.data);
					r_cons_set_raw(0);
					return I.buffer.data;
				}
			}
#endif
		default:
			if (gcomp)
				gcomp++;
			/* XXX use ^A & ^E */
			if (I.buffer.index<I.buffer.length) {
				for(i = ++I.buffer.length;i>I.buffer.index;i--)
					I.buffer.data[i] = I.buffer.data[i-1];
				I.buffer.data[I.buffer.index] = buf[0];
			} else {
				I.buffer.data[I.buffer.length]=buf[0];
				I.buffer.length++;
				if (I.buffer.length>(R_LINE_BUFSIZE-1))
					I.buffer.length--;
				I.buffer.data[I.buffer.length]='\0';
			}
			I.buffer.index++;
			break;
		}
		if (I.echo) {
			if (gcomp) {
				gcomp_line = "";
				//if (I.buffer.length == 0)
				//	gcomp = 0;
				if (I.history.data != NULL)
				for (i=0; i<I.history.size; i++) {
					if (I.history.data[i] == NULL)
						break;
					if (strstr (I.history.data[i], I.buffer.data)) {
						gcomp_line = I.history.data[i];
						if (!gcomp_idx--)
							break;
					}
				}
				printf ("\r (reverse-i-search (%s)): %s\r", I.buffer.data, gcomp_line);
			} else {
				printf ("\r%s%s", I.prompt, I.buffer.data);
				printf ("\r%s", I.prompt);
				for (i=0; i<I.buffer.index; i++)
					printf ("%c", I.buffer.data[i]);
			}
			fflush (stdout);
		}
	}
_end:
	r_cons_set_raw (0);
	if (I.echo) {
		printf ("\r%s%s\n", I.prompt, I.buffer.data);
		fflush (stdout);
	}

	if (!memcmp (I.buffer.data, "!history", 8)) {
	//if (I.buffer.data[0]=='!' && I.buffer.data[1]=='\0') {
		r_line_hist_list ();
		return r_line_nullstr;
	}
	return I.buffer.data? I.buffer.data : r_line_nullstr;
}

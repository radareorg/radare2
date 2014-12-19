/* radare - LGPL - Copyright 2007-2014 - pancake */
/* dietline is a lightweight and portable library similar to GNU readline */

#include <r_cons.h>
#include <r_core.h>
#include <string.h>
#include <stdlib.h>

#if __WINDOWS__
#include <windows.h>
#define USE_UTF8 0
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#define USE_UTF8 1
#endif

static char *r_line_nullstr = "";

#define ONLY_VALID_CHARS 1

#if ONLY_VALID_CHARS
static inline int is_valid_char (unsigned char ch) {
	if (ch>=32 && ch<=127) return R_TRUE;
	switch (ch) {
	//case 0: // wat
	case 1: // ^a
	case 2: // ^b -> emacs left
	case 4: // ^d
	case 5: // ^e
	case 6: // ^f -> emacs right
	case 8: // backspace
	case 9: // tab
	case 10: // newline
	case 13: // carriage return
	case 23: // ^w
	case 27: // arrow
		return R_TRUE;
	}
	return R_FALSE;
}
#endif

static int inithist() {
	ZERO_FILL (I.history);
	I.history.data = (char **)malloc ((I.history.size+1024)*sizeof(char *));
	if (I.history.data==NULL)
		return R_FALSE;
	I.history.size = R_LINE_HISTSIZE;
	memset (I.history.data, 0, I.history.size*sizeof(char *));
	return R_TRUE;
}

/* initialize history stuff */
R_API int r_line_dietline_init() {
	ZERO_FILL (I.completion);
	if (!inithist ())
		return R_FALSE;
	I.echo = R_TRUE;
	return R_TRUE;
}

#if USE_UTF8
/* read utf8 char into 's', return the length in bytes */
static int r_line_readchar_utf8(unsigned char *s, int slen) {
	// TODO: add support for w32
	int ret, len;
	for (len = 0; len+2<slen; len++) {
		s[len] = 0;
		ret = read (0, s+len, 1);
		if (ret!=1)
			return 0;
		s[len] = r_cons_controlz (s[len]);
		if (!s[len]) return 1; // ^z
		if (s[len] < 28)
			return s[0]?1:0;
		if (is_valid_char (s[len]))
			return s[0]?1:0;
		if ((s[len] & 0xc0) != 0x80) continue;
		if (len>0) break;
	}
	len++;
	s[len] = 0;
	return len;
}
#endif

static int r_line_readchar() {
	ut8 buf[2];
	*buf = '\0';
#if __WINDOWS__
	BOOL ret;
	DWORD mode, out;
	HANDLE h;
#else
	int ret;
#endif

do_it_again:
#if __WINDOWS__
	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &mode);
	SetConsoleMode (h, 0); // RAW
	ret = ReadConsole (h, buf, 1, &out, NULL);
	// wine hack-around
	if (!ret && read (0, buf, 1) != 1)
		return -1;
	SetConsoleMode (h, mode);
#else
	do {
		buf[0] = 0;
		ret = read (0, buf, 1);
		buf[0] = r_cons_controlz (buf[0]);
		// VTE HOME/END support
		if (buf[0]==79) {
			if (read (0, buf, 1) != 1)
				return -1;
			if (buf[0]==70) {
				return 5;
			} else if (buf[0]==72) {
				return 1;
			}
			return 0;
		}
		if (ret == -1) return 0; // read no char
		if (!buf[0] || ret == 0) return -1; // eof
		// TODO: add support for other invalid chars
		if (*buf==0xc2 || *buf==0xc3) {
			read (0, buf+1, 1);
			*buf = '\0';
		}
	} while (*buf == '\0');
#endif
#if ONLY_VALID_CHARS
	if (!is_valid_char (buf[0]))
		goto do_it_again;
#endif
	return buf[0];
}

R_API int r_line_hist_add(const char *line) {
	if (!I.history.data)
		inithist ();
	if (I.history.top>=I.history.size)
		I.history.top = I.history.index = 0; // workaround
	/* ignore dup */
	if (I.history.index>0 && !strcmp (line, I.history.data[I.history.index-1]))
		return R_FALSE;
	if (line && *line) { // && I.history.index < I.history.size) {
		I.history.data[I.history.top++] = strdup (line);
		I.history.index = I.history.top;
		return R_TRUE;
	}
	return R_FALSE;
}

static int r_line_hist_up() {
	if (I.hist_up)
		return I.hist_up (I.user);
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
	if (I.hist_down)
		return I.hist_down (I.user);
	I.buffer.index = 0;
	if (!I.history.data)
		inithist ();
	if (I.history.index<I.history.size
	    && I.history.data[I.history.index]) {
		I.history.index++;
		if (I.history.data[I.history.index] == NULL) {
			I.buffer.data[0]='\0';
			I.buffer.index = I.buffer.length = 0;
			return 0;
		}
		if (I.history.data[I.history.index]) {
			strncpy (I.buffer.data, I.history.data[I.history.index], R_LINE_BUFSIZE-1);
			I.buffer.index = I.buffer.length = strlen (I.buffer.data);
		}
		return R_TRUE;
	}
	return R_FALSE;
}

R_API const char *r_line_hist_get(int n) {
	int i = 0;
	if (!I.history.data)
		inithist ();
	if (I.history.data != NULL)
		for (i=0; i<I.history.size && I.history.data[i]; i++)
			if (n==i) return I.history.data[i];
	return NULL;
}

R_API int r_line_hist_list() {
	int i = 0;
	if (!I.history.data)
		inithist ();
	if (I.history.data != NULL)
		for (i=0; i<I.history.size && I.history.data[i]; i++)
			printf (" !%d  # %s\n", i, I.history.data[i]);
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
	FILE *fd;
	char buf[R_LINE_BUFSIZE],
		*path = r_str_home (file);
	if (path == NULL)
		return R_FALSE;
	if (!(fd = fopen (path, "r"))) {
		free (path);
		return R_FALSE;
	}
	while (fgets (buf, sizeof (buf), fd) != NULL) {
		buf[strlen (buf)-1] = 0;
		r_line_hist_add (buf);
	}
	fclose (fd);
	free (path);
	return R_TRUE;
}

R_API int r_line_hist_save(const char *file) {
	FILE *fd;
	int i, ret = R_FALSE;
	char *p, *path = r_str_home (file);
	if (path != NULL) {
		p = (char*)r_str_lastbut (path, R_SYS_DIR[0], NULL); // TODO: use fs
		if (p) {
			*p = 0;
			r_sys_rmkdir (path);
			*p = R_SYS_DIR[0];
		}
		fd = fopen (path, "w");
		if (fd != NULL) {
			if (I.history.data) {
				for (i=0; i<I.history.index; i++) {
					fputs (I.history.data[i], fd);
					fputs ("\n", fd);
				}
				fclose (fd);
				ret = R_TRUE;
			} else fclose (fd);
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

	p = (char *)r_str_lchr (I.buffer.data, ' ');
	if (!p)
		p = (char *)r_str_lchr (I.buffer.data, '@'); // HACK FOR r2
	if (p) {
		p++;
		plen = sizeof (I.buffer.data)-(int)(size_t)(p-I.buffer.data);
	} else {
		p = I.buffer.data; // XXX: removes current buffer 
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
			// TODO: avoid overflow
			const char *root = argv[0];
			int min_common_len = strlen(root);

			// try to autocomplete argument
			for (i=0; i<argc; i++) {
				j = 0;
				if (!argv[i]) break;
				while (argv[i][j]==root[j] && root[j] != '\0') j++;
				if (j < min_common_len)
					min_common_len = j;
				root = argv[i];
			}
			memmove (p, root, strlen (root)+1);
			if (min_common_len<strlen (root))
				p[min_common_len] = 0;
			I.buffer.index = I.buffer.length = strlen (I.buffer.data);
		}
	}

	/* show options */
	if (opt>1 && I.echo) {
		const int sep = 3;
		int slen, col = 10;
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

R_API char *r_line_readline() {
	return r_line_readline_cb (NULL, NULL);
}

R_API char *r_line_readline_cb(RLineReadCallback cb, void *user) {
	int columns = r_cons_get_size (NULL)-2;
	const char *gcomp_line = "";
	static int gcomp_idx = 0;
	static int gcomp = 0;
	signed char buf[10];
#if USE_UTF8
	int utflen;
#endif
	int ch, i=0; /* grep completion */
	char *tmp_ed_cmd, prev = 0;

	I.buffer.index = I.buffer.length = 0;
	I.buffer.data[0] = '\0';
	if (I.contents) {
		memmove (I.buffer.data, I.contents, 
			R_MIN (strlen (I.contents), R_LINE_BUFSIZE-1));
		I.buffer.data[R_LINE_BUFSIZE-1] = '\0'; 
		I.buffer.index = I.buffer.length = strlen (I.contents);
	}
	if (I.disable) {
		if (!fgets (I.buffer.data, R_LINE_BUFSIZE-1, stdin))
			return NULL;
		I.buffer.data[strlen (I.buffer.data)] = '\0';
		return (*I.buffer.data)? I.buffer.data : r_line_nullstr;
	}

	memset (&buf, 0, sizeof buf);
	r_cons_set_raw (1);

	if (I.echo) {
		r_cons_clear_line (0);
		printf ("\x1b[0K\r%s%s", I.prompt, I.buffer.data);
		fflush (stdout);
	}
	r_cons_singleton()->breaked = R_FALSE;
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
		if (cb && !cb (user, I.buffer.data)) {
			I.buffer.data[0] = 0;
			I.buffer.length = 0;
		}
#if USE_UTF8
		utflen = r_line_readchar_utf8 (
			(ut8*)buf, sizeof (buf));
		if (utflen <1) {
			return NULL;
		}
		buf[utflen] = 0;
#else
		ch = r_line_readchar ();
		if (ch == -1) return NULL;
		buf[0] = ch;
#endif
		if (I.echo)
			r_cons_clear_line (0);
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
		case 2: // ^b // emacs left
#if USE_UTF8
			 {
				char *s = I.buffer.data+I.buffer.index-1;
				utflen = 1;
				while (s>I.buffer.data && (*s & 0xc0) == 0x80) {
					utflen++;
					s--;
				}
			 }
			I.buffer.index = I.buffer.index? I.buffer.index-utflen: 0;
#else
			I.buffer.index = I.buffer.index? I.buffer.index-1: 0;
#endif
			break;
		case 5: // ^E
		        if (prev == 24) { // ^X = 0x18
				I.buffer.data[I.buffer.length] = 0; // probably unnecessary
				tmp_ed_cmd = I.editor_cb (I.user, I.buffer.data);
				if (tmp_ed_cmd) {
					/* copied from yank (case 25) */ 
					I.buffer.length = strlen (tmp_ed_cmd);
					if (I.buffer.length < R_LINE_BUFSIZE) {
						I.buffer.index = I.buffer.length;
						strncpy (I.buffer.data, tmp_ed_cmd, R_LINE_BUFSIZE-1);
						I.buffer.data[R_LINE_BUFSIZE-1] = '\0';
					} else I.buffer.length -= strlen (tmp_ed_cmd);
					free (tmp_ed_cmd);
				}
			} else I.buffer.index = I.buffer.length;  
			break;
		case 3: // ^C 
			if (I.echo)
				eprintf ("^C\n");
			I.buffer.index = I.buffer.length = 0;
			*I.buffer.data = '\0';
			r_cons_singleton()->breaked = R_TRUE;
			goto _end;
		case 4: // ^D
			if (!I.buffer.data[0]) { /* eof */
				if (I.echo)
					printf ("^D\n");
				r_cons_set_raw (R_FALSE);
				return NULL;
			}
			if (I.buffer.index<I.buffer.length)
				memmove (I.buffer.data+I.buffer.index,
					I.buffer.data+I.buffer.index+1,
					strlen (I.buffer.data+I.buffer.index+1)+1);
			break;
		case 10: // ^J -- ignore
			return I.buffer.data;
		case 11: // ^K -- ignore
			break;
		case 6: // ^f // emacs right
#if USE_UTF8
			 {
				char *s = I.buffer.data+I.buffer.index+1;
				utflen = 1;
				while ((*s & 0xc0) == 0x80) {
					utflen++;
					s++;
				}
				I.buffer.index = I.buffer.index<I.buffer.length?
				I.buffer.index+utflen: I.buffer.length;
			 }
#else
			I.buffer.index = I.buffer.index<I.buffer.length?
			I.buffer.index+1: I.buffer.length;
#endif
			break;
		case 12: // ^L -- right
			I.buffer.index = (I.buffer.index<I.buffer.length)?
				I.buffer.index+1 : I.buffer.length;
			if (I.echo)
				eprintf ("\x1b[2J\x1b[0;0H");
			fflush (stdout);
			break;
		case 18: // ^R -- autocompletion
			gcomp = 1;
			break;
		case 19: // ^S -- backspace
			if (gcomp) gcomp--;
			else {
#if USE_UTF8
				if (I.buffer.index>0) {
					char *s;
					do {
						I.buffer.index--;
						s = I.buffer.data+I.buffer.index;
					} while ((*s & 0xc0) == 0x80);
				}
#else
				I.buffer.index = I.buffer.index? I.buffer.index-1: 0;
#endif
			}
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
				if (I.buffer.index>I.buffer.length)
					I.buffer.length = I.buffer.index;
				memmove (I.buffer.data+i,
					I.buffer.data+I.buffer.index,
					I.buffer.length-I.buffer.index+1);
				I.buffer.data[i] = 0;
				I.buffer.length = strlen (I.buffer.data);
				I.buffer.index = i;
			}
			break;
		case 24: // ^X -- do nothing but store in prev = *buf
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
		case 14: // ^n
			if (gcomp) {
				if (gcomp_idx>0)
					gcomp_idx--;
			} else r_line_hist_down ();
			break;
		case 16: // ^p
			if (gcomp) {
				gcomp_idx++;
			} else r_line_hist_up ();
			break;
		case 27: //esc-5b-41-00-00
			buf[0] = r_line_readchar();
			switch (buf[0]) {
				case -1: return NULL;
				case 1: // begin
					 I.buffer.index = 0;
					 break;
				case 5: // end
					 I.buffer.index = I.buffer.length;
					 break;
				default:
					 buf[1] = r_line_readchar();
					 if (buf[1] == -1)
						 return NULL;
					 if (buf[0]==0x5b) { // [
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
								 if (gcomp) gcomp_idx++;
								 else if (r_line_hist_up ()==-1)
									 return NULL;
								 break;
							 case 0x42:
								 if (gcomp) {
									 if (gcomp_idx>0)
										 gcomp_idx--;
								 } else if (r_line_hist_down ()==-1)
									 return NULL;
								 break;
							 case 0x43: // C --> right arrow
#if USE_UTF8
								 {
									 char *s = I.buffer.data+I.buffer.index+1;
									 utflen = 1;
									 while ((*s & 0xc0) == 0x80) {
										 utflen++;
										 s++;
									 }
									 I.buffer.index = I.buffer.index<I.buffer.length?
										 I.buffer.index+utflen: I.buffer.length;
								 }
#else
								 I.buffer.index = I.buffer.index<I.buffer.length?
									 I.buffer.index+1: I.buffer.length;
#endif
								 break;
							 case 0x44: // D --> left arrow
#if USE_UTF8
								 {
									 char *s = I.buffer.data+I.buffer.index-1;
									 utflen = 1;
									 while (s>I.buffer.data && (*s & 0xc0) == 0x80) {
										 utflen++;
										 s--;
									 }
								 }
								 I.buffer.index = I.buffer.index? I.buffer.index-utflen: 0;
#else
								 I.buffer.index = I.buffer.index? I.buffer.index-1: 0;
#endif
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
							 case 0x37: // HOME xrvt-unicode
								 r_cons_readchar ();
							 case 0x48: // HOME
								 I.buffer.index = 0;
								 break;
							 case 0x34: // END
							 case 0x38: // END xrvt-unicode
								 r_cons_readchar ();
							 case 0x46: // END
								 I.buffer.index = I.buffer.length;
								 break;
						 }
					 }
			}
			break;
		case 8:
		case 127:
			if (I.buffer.index < I.buffer.length) {
				if (I.buffer.index>0) {
					int len = 0;
					// TODO: WIP
#if USE_UTF8
					char *s;
					do {
						I.buffer.index--;
						s = I.buffer.data+I.buffer.index;
						len++;
					} while ((*s &0xc0)==0x80);
#else
					len = 1;
					I.buffer.index--;
#endif
					memmove (I.buffer.data+I.buffer.index,
						I.buffer.data+I.buffer.index+len,
						strlen (I.buffer.data+I.buffer.index));
					I.buffer.length -= len;
					I.buffer.data[I.buffer.length] = 0;
				}
			} else {
// OK
#if USE_UTF8
				char *s;
				// utf8 backward size
				do {
					I.buffer.length--;
					s = I.buffer.data+I.buffer.length;
					i++;
				} while ((*s &0xc0)==0x80);
				I.buffer.index = I.buffer.length;
#else
				I.buffer.index = --I.buffer.length;
#endif
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
				strncpy (I.buffer.data, gcomp_line, R_LINE_BUFSIZE-1);
                I.buffer.data[R_LINE_BUFSIZE-1] = '\0';
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
			if (I.buffer.index<I.buffer.length) {
#if USE_UTF8
				if ((I.buffer.length + utflen) < sizeof (I.buffer.data)) {
					I.buffer.length += utflen;
					for (i = I.buffer.length; i>I.buffer.index; i--)
						I.buffer.data[i] = I.buffer.data[i-utflen];
					memcpy (I.buffer.data+I.buffer.index, buf, utflen);
				}
#else
				for (i = ++I.buffer.length; i>I.buffer.index; i--)
					I.buffer.data[i] = I.buffer.data[i-1];
				I.buffer.data[I.buffer.index] = buf[0];
#endif
			} else {
#if USE_UTF8
				if ((I.buffer.length + utflen) < sizeof (I.buffer.data)) {
					memcpy (I.buffer.data+I.buffer.length, buf, utflen);
					I.buffer.length+=utflen;
				}
				I.buffer.data[I.buffer.length]='\0';
#else
				I.buffer.data[I.buffer.length]=buf[0];
				I.buffer.length++;
				if (I.buffer.length>(R_LINE_BUFSIZE-1))
					I.buffer.length--;
				I.buffer.data[I.buffer.length]='\0';
#endif
			}
#if USE_UTF8
			I.buffer.index += utflen;
#else
			I.buffer.index++;
#endif
			break;
		}
		prev = buf[0];
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
				int chars = R_MAX (1, strlen (I.buffer.data)); // wtf?
				int len, cols = R_MAX (1, columns - r_str_ansi_len (I.prompt)-2);
				/* print line */
				printf ("\r%s", I.prompt);
				fwrite (I.buffer.data, 1, R_MIN (cols, chars), stdout);
				/* place cursor */
				printf ("\r%s", I.prompt);
				if (I.buffer.index>cols) {
					printf ("< ");
					i = I.buffer.index-cols;
					if (i>sizeof (I.buffer.data)) {
						i = sizeof(I.buffer.data)-1;
						len = 1;
					}
				} else i = 0;
				len = I.buffer.index;
				if ((len+i)>I.buffer.length)
					len = 1;
				fwrite (I.buffer.data+i, 1, len, stdout);
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

	// should be here or not?
	if (!memcmp (I.buffer.data, "!history", 8)) {
	//if (I.buffer.data[0]=='!' && I.buffer.data[1]=='\0') {
		r_line_hist_list ();
		return r_line_nullstr;
	}
	return I.buffer.data[0] != '\0'? I.buffer.data : r_line_nullstr;
}

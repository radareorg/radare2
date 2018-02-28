/* radare - LGPL - Copyright 2007-2018 - pancake */
/* dietline is a lightweight and portable library similar to GNU readline */

#include <r_cons.h>
#include <r_core.h>
#include <string.h>
#include <stdlib.h>

#if __WINDOWS__ && !__CYGWIN__
#include <windows.h>
#define USE_UTF8 0
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#define USE_UTF8 1
#endif

static char *r_line_nullstr = "";
static const char dl_basic_word_break_characters[] =  " \t\n\"\\'`@$><=;|&{(";

#define ONLY_VALID_CHARS 1

#if ONLY_VALID_CHARS
static inline int is_valid_char(unsigned char ch) {
	if (ch >= 32 && ch <= 127) {
		return true;
	}
	switch (ch) {
	// case 0: // wat
	case 1:	// ^a
	case 2:	// ^b -> emacs left
	case 4:	// ^d
	case 5:	// ^e
	case 6:	// ^f -> emacs right
	case 8:	// backspace
	case 9:	// tab
	case 10:// newline
	case 13:// carriage return
	case 23:// ^w
	case 27:// arrow
		return true;
	}
	return false;
}
#endif

static inline bool is_word_break_char(char ch) {
	int i;
	int len =
		sizeof (dl_basic_word_break_characters) /
		sizeof (dl_basic_word_break_characters[0]);
	for (i = 0; i < len; ++i) {
		if (ch == dl_basic_word_break_characters[i]) {
			return true;
		}
	}
	return false;
}

static void unix_word_rubout() {
	int i;
	if (I.buffer.index > 0) {
		for (i = I.buffer.index - 1; i > 0 && is_word_break_char (I.buffer.data[i]); i--) {
			/*nothing to see here*/
		}
		for (; i && !is_word_break_char (I.buffer.data[i]); i--) {
			/*nothing to see here*/
		}
		if (i > 0) {
			i++;
		} else if (i < 0) {
			i = 0;
		}
		if (I.buffer.index > I.buffer.length) {
			I.buffer.length = I.buffer.index;
		}
		memmove (I.buffer.data + i, I.buffer.data + I.buffer.index,
				I.buffer.length - I.buffer.index + 1);
		I.buffer.length = strlen (I.buffer.data);
		I.buffer.index = i;
	}
}

static int inithist() {
	ZERO_FILL (I.history);
	if ((I.history.size + 1024) * sizeof (char *) < I.history.size) {
		return false;
	}
	I.history.data = (char **) calloc ((I.history.size + 1024), sizeof(char *));
	if (!I.history.data) {
		return false;
	}
	I.history.size = R_LINE_HISTSIZE;
	return true;
}

/* initialize history stuff */
R_API int r_line_dietline_init() {
	ZERO_FILL (I.completion);
	if (!inithist ()) {
		return false;
	}
	I.echo = true;
	return true;
}

#if USE_UTF8
/* read utf8 char into 's', return the length in bytes */
static int r_line_readchar_utf8(ut8 *s, int slen) {
	// TODO: add support for w32
	ssize_t len, i;
	if (slen < 1) {
		return 0;
	}
	int ch = r_cons_readchar ();
	if (ch == -1) {
		return -1;
	}
	*s = ch;
#if 0
	if ((t = read (0, s, 1)) != 1) {
		return t;
	}
#endif
	*s = r_cons_controlz (*s);
	if (*s < 0x80) {
		len = 1;
	} else if ((s[0] & 0xe0) == 0xc0) {
		len = 2;
	} else if ((s[0] & 0xf0) == 0xe0) {
		len = 3;
	} else if ((s[0] & 0xf8) == 0xf0) {
		len = 4;
	} else {
		return -1;
	}
	if (slen < len) {
		return -1;
	}
	for (i = 1; i < len; i++) {
		int ch = r_cons_readchar ();
		if (ch != -1) {
			s[i] = ch;
			return 1;
		}
		if ((s[i] & 0xc0) != 0x80) {
			return -1;
		}
	}
	return len;
}
#endif

#if __WINDOWS__ && !__CYGWIN__
static int r_line_readchar_win(int *vch) { // this function handle the input in console mode
	INPUT_RECORD irInBuf[128];
	BOOL ret, bCtrl = FALSE;
	DWORD mode, out;
	ut8 buf[2];
	HANDLE h;
	int i;

	if (I.zerosep) {
		*vch = 0;
		buf[0] = 0;
		read (0, buf, 1);
		return buf[0];
	}

	*buf = '\0';
do_it_again:
	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &mode);
	SetConsoleMode (h, 0);	// RAW
	*vch = 0;
	ret = ReadConsoleInput (h, irInBuf, 128, &out);
	if (ret < 1) {
		return 0;
	}
	for (i = 0; i < out; i++) {
		if (irInBuf[i].EventType != KEY_EVENT) {
			continue;
		}
		if (!irInBuf[i].Event.KeyEvent.bKeyDown) {
			continue;
		}
		*buf = irInBuf[i].Event.KeyEvent.uChar.AsciiChar;
		bCtrl = irInBuf[i].Event.KeyEvent.dwControlKeyState & 8;
		if (irInBuf[i].Event.KeyEvent.uChar.AsciiChar) {
			continue;
		}
		switch (irInBuf[i].Event.KeyEvent.wVirtualKeyCode) {
		case VK_DOWN: *vch = bCtrl? 140: 40; break;
		case VK_UP: *vch = bCtrl? 138: 38; break;
		case VK_RIGHT: *vch = bCtrl? 139: 39; break;
		case VK_LEFT: *vch = bCtrl? 137: 37; break;
		case 46: *vch = bCtrl? 146: 46; break;	// SUPR KEY
		case VK_PRIOR: *vch = bCtrl? 136: 36; break;	// HOME KEY
		case VK_NEXT: *vch = bCtrl? 135: 35; break;	// END KEY
		default: *vch = *buf = 0; break;
		}
	}
	SetConsoleMode (h, mode);
	if (buf[0] == 0 && *vch == 0) {
		goto do_it_again;
	}
	return buf[0];
}
#endif

#if 0
// TODO use define here to hac
static int r_line_readchar() {
	ut8 buf[2];
	*buf = '\0';
#if __WINDOWS__ && !__CYGWIN__
#if 1		// new implementation for read input at windows by skuater. If something fail set this to 0
	int dummy = 0;
	return r_line_readchar_win (&dummy);
#endif
	BOOL ret;
	DWORD mode, out;
	HANDLE h;
#else
	int ret;
#endif

do_it_again:
#if __WINDOWS__ && !__CYGWIN__
	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &mode);
	SetConsoleMode (h, 0);	// RAW
	ret = ReadConsole (h, buf, 1, &out, NULL);
	// wine hack-around
	if (!ret && read (0, buf, 1) != 1) {
		return -1;
	}
	SetConsoleMode (h, mode);
#else
	do {
		buf[0] = 0;
		ret = read (0, buf, 1);
		buf[0] = r_cons_controlz (buf[0]);
		// VTE HOME/END support
		if (buf[0] == 79) {
			if (read (0, buf, 1) != 1) {
				return -1;
			}
			if (buf[0] == 70) {
				return 5;
			}
			if (buf[0] == 72) {
				return 1;
			}
			return 0;
		}
		if (ret == -1) {
			return 0;	// read no char
		}
		if (!buf[0] || !ret) {
			return -1;	// eof
		}
		// TODO: add support for other invalid chars
		if (*buf == 0xc2 || *buf == 0xc3) {
			read (0, buf + 1, 1);
			*buf = '\0';
		}
	} while (*buf == '\0');
#endif
#if ONLY_VALID_CHARS
	if (!is_valid_char (buf[0])) {
		goto do_it_again;
	}
#endif
	return buf[0];
}
#endif

R_API int r_line_hist_add(const char *line) {
	if (!line || !*line) {
		return false;
	}
	if (!I.history.data) {
		inithist ();
	}
	/* ignore dup */
	if (I.history.top > 0) {
		const char *data = I.history.data[I.history.top - 1];
		if (data && !strcmp (line, data)) {
			I.history.index = I.history.top;
			return false;
		}
	}
	if (I.history.top == I.history.size) {
		int i;
		free (I.history.data[0]);
		for (i = 0; i <= I.history.size - 2; i++) {
			I.history.data[i] = I.history.data[i + 1];
		}
		I.history.top--;
	}
	I.history.data[I.history.top++] = strdup (line);
	I.history.index = I.history.top;
	return true;
}

static int r_line_hist_up() {
	if (I.hist_up) {
		return I.hist_up (I.user);
	}
	if (!I.history.data) {
		inithist ();
	}
	if (I.history.index > 0) {
		strncpy (I.buffer.data, I.history.data[--I.history.index], R_LINE_BUFSIZE - 1);
		I.buffer.index = I.buffer.length = strlen (I.buffer.data);
		return true;
	}
	return false;
}

static int r_line_hist_down() {
	if (I.hist_down) {
		return I.hist_down (I.user);
	}
	I.buffer.index = 0;
	if (!I.history.data) {
		inithist ();
	}
	if (I.history.index == I.history.top) {
		return false;
	}
	I.history.index++;
	if (I.history.index == I.history.top) {
		I.buffer.data[0] = '\0';
		I.buffer.index = I.buffer.length = 0;
		return false;
	}
	if (I.history.data[I.history.index]) {
		strncpy (I.buffer.data, I.history.data[I.history.index], R_LINE_BUFSIZE - 1);
		I.buffer.index = I.buffer.length = strlen (I.buffer.data);
	}
	return true;
}

R_API const char *r_line_hist_get(int n) {
	int i = 0;
	if (!I.history.data) {
		inithist ();
	}
	if (I.history.data) {
		for (i = 0; i < I.history.size && I.history.data[i]; i++) {
			if (n == i) {
				return I.history.data[i];
			}
		}
	}
	return NULL;
}

R_API int r_line_hist_list() {
	int i = 0;
	if (!I.history.data) {
		inithist ();
	}
	if (I.history.data) {
		for (i = 0; i < I.history.size && I.history.data[i]; i++) {
			const char *pad = r_str_pad (' ', 32 - strlen (I.history.data[i]));
			r_cons_printf ("%s %s # !%d\n", I.history.data[i], pad, i);
		}
	}
	return i;
}

R_API void r_line_hist_free() {
	int i;
	if (I.history.data) {
		for (i = 0; i < I.history.size; i++) {
			free (I.history.data[i]);
			I.history.data[i] = NULL;
		}
	}
	R_FREE (I.history.data);
	I.history.index = 0;
}

/* load history from file. TODO: if file == NULL load from ~/.<prg>.history or so */
R_API int r_line_hist_load(const char *file) {
	FILE *fd;
	char buf[R_LINE_BUFSIZE], *path = r_str_home (file);
	if (!path) {
		return false;
	}
	if (!(fd = fopen (path, "r"))) {
		free (path);
		return false;
	}
	while (fgets (buf, sizeof (buf), fd) != NULL) {
		buf[strlen (buf) - 1] = 0;
		r_line_hist_add (buf);
	}
	fclose (fd);
	free (path);
	return true;
}

R_API int r_line_hist_save(const char *file) {
	FILE *fd;
	int i, ret = false;
	if (!file || !*file) {
		return false;
	}
	char *p, *path = r_str_home (file);
	if (path != NULL) {
		p = (char *) r_str_lastbut (path, R_SYS_DIR[0], NULL);	// TODO: use fs
		if (p) {
			*p = 0;
			r_sys_mkdirp (path);
			*p = R_SYS_DIR[0];
		}
		fd = fopen (path, "w");
		if (fd != NULL) {
			if (I.history.data) {
				for (i = 0; i < I.history.index; i++) {
					fputs (I.history.data[i], fd);
					fputs ("\n", fd);
				}
				fclose (fd);
				ret = true;
			} else {
				fclose (fd);
			}
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
	int i, j, opt = 0, plen, len = 0;
	int cols = (int)(r_cons_get_size (NULL) * 0.82);

	/* prepare argc and argv */
	if (I.completion.run) {
		I.completion.run (&I);
		opt = argc = I.completion.argc;
		argv = I.completion.argv;
	}

	p = (char *) r_sub_str_lchr (I.buffer.data, 0, I.buffer.index, ' ');
	if (!p) {
		p = (char *) r_sub_str_lchr (I.buffer.data, 0, I.buffer.index, '@');	// HACK FOR r2
	}
	if (p) {
		p++;
		plen = sizeof (I.buffer.data) - (int) (size_t) (p - I.buffer.data);
	} else {
		p = I.buffer.data;	// XXX: removes current buffer
		plen = sizeof (I.buffer.data);
	}
	/* autocomplete */
	if (argc == 1) {
		const char *end_word = r_sub_str_rchr (I.buffer.data,
			I.buffer.index, strlen (I.buffer.data), ' ');
		const char *t = end_word != NULL?
				end_word: I.buffer.data + I.buffer.index;
		int largv0 = strlen (argv[0]? argv[0]: "");
		size_t len_t = strlen (t);
		p[largv0]='\0';

		if ((p - I.buffer.data) + largv0 + 1 + len_t < plen) {
			if (len_t > 0) {
				int tt = largv0;
				if (*t != ' ') {
					p[tt++] = ' ';
				}
				memmove (p + tt, t, len_t);
			}
			memcpy (p, argv[0], largv0);

			if (p[largv0 - 1] != '/') {
				p[largv0] = ' ';
				if (!len_t) {
					p[largv0 + 1] = '\0';
				}
			}
			I.buffer.length = strlen (I.buffer.data);
			I.buffer.index = I.buffer.length;
		}
	} else if (argc > 0) {
		if (*p) {
			// TODO: avoid overflow
			const char *t = I.buffer.data + I.buffer.index;
			const char *root = argv[0];
			int min_common_len = strlen (root);
			size_t len_t = strlen (t);

			// try to autocomplete argument
			for (i = 0; i < argc; i++) {
				j = 0;
				if (!argv[i]) {
					break;
				}
				while (argv[i][j] == root[j] && root[j] != '\0') j++;
				if (j < min_common_len) {
					min_common_len = j;
				}
				root = argv[i];
			}
			if (len_t > 0) {
				int tt = min_common_len;
				memmove (p + tt, t, len_t);
				p[tt + len_t] = '\0';
			}
			memmove (p, root, min_common_len);
			if (!len_t) {
				p[min_common_len] = '\0';
			}
			I.buffer.length = strlen (I.buffer.data);
			I.buffer.index = (p - I.buffer.data) + min_common_len;
		}
	}

	/* show options */
	if (opt > 1 && I.echo) {
		const int sep = 3;
		int slen, col = 10;
		printf ("%s%s\n", I.prompt, I.buffer.data);
		for (i = 0; i < argc && argv[i]; i++) {
			int l = strlen (argv[i]);
			if (sep + l > col) {
				col = sep + l;
			}
			if (col > (cols >> 1)) {
				col = (cols >> 1);
				break;
			}
		}
		for (len = i = 0; i < argc && argv[i]; i++) {
			if (len + col > cols) {
				printf ("\n");
				len = 0;
			}
			printf ("%-*s   ", col - sep, argv[i]);
			slen = strlen (argv[i]);
			len += (slen > col)? (slen + sep): (col + sep);
		}
		printf ("\n");
	}
	fflush (stdout);
}

R_API const char *r_line_readline() {
	return r_line_readline_cb (NULL, NULL);
}

#if __WINDOWS__ && !__CYGWIN__
R_API const char *r_line_readline_cb_win(RLineReadCallback cb, void *user) {
	int columns = r_cons_get_size (NULL) - 2;
	const char *gcomp_line = "";
	static int gcomp_idx = 0;
	static int gcomp = 0;
	signed char buf[10];
	int ch, i = 0;	/* grep completion */
	int vch = 0;
	char *tmp_ed_cmd, prev = 0;
	HANDLE hClipBoard;
	char *clipText;

	I.buffer.index = I.buffer.length = 0;
	I.buffer.data[0] = '\0';
	if (I.contents) {
		memmove (I.buffer.data, I.contents,
			R_MIN (strlen (I.contents) + 1, R_LINE_BUFSIZE - 1));
		I.buffer.data[R_LINE_BUFSIZE - 1] = '\0';
		I.buffer.index = I.buffer.length = strlen (I.contents);
	}
	if (I.disable) {
		if (!fgets (I.buffer.data, R_LINE_BUFSIZE - 1, stdin)) {
			return NULL;
		}
		I.buffer.data[strlen (I.buffer.data)] = '\0';
		return (*I.buffer.data)? I.buffer.data: r_line_nullstr;
	}

	memset (&buf, 0, sizeof buf);
	r_cons_set_raw (1);

	if (I.echo) {
		r_cons_clear_line (0);
		printf ("\x1b[0K\r%s%s", I.prompt, I.buffer.data);
		fflush (stdout);
	}
	r_cons_break_push (NULL, NULL);
	for (;;) {
		I.buffer.data[I.buffer.length] = '\0';
		if (cb && !cb (user, I.buffer.data)) {
			I.buffer.data[0] = 0;
			I.buffer.length = 0;
		}
		ch = r_line_readchar_win (&vch);
		if (ch == -1) {
			r_cons_break_pop ();
			return NULL;
		}
		buf[0] = ch;
		if (I.echo) {
			r_cons_clear_line (0);
		}
		columns = r_cons_get_size (NULL) - 2;
		if (columns < 1) {
			columns = 40;
		}
		if (I.echo) {
			printf ("\r%*c\r", columns, ' ');
		}
		if (I.echo) {
			printf ("\r\x1b[2K\r");	// %*c\r", columns, ' ');
		}
		/* process special at vch codes first*/
		switch (vch) {
		case 37:	// left arrow
			I.buffer.index = I.buffer.index? I.buffer.index - 1: 0;
			break;
		case 38:	// up arrow
			if (gcomp) {
				gcomp_idx++;
			} else if (r_line_hist_up () == -1) {
				r_cons_break_pop ();
				return NULL;
			}
			break;
		case 39:// right arrow
			I.buffer.index = I.buffer.index < I.buffer.length?
					 I.buffer.index + 1: I.buffer.length;
			break;
		case 40:// down arrow
			if (gcomp) {
				if (gcomp_idx > 0) {
					gcomp_idx--;
				}
			} else if (r_line_hist_down () == -1) {
				r_cons_break_pop ();
				return NULL;
			}
			break;
		/* ctrl+arrows */
		case 137:// ctrl+left arrow
			// previous word
			for (i = I.buffer.index; i > 0; i--) {
				if (I.buffer.data[i] == ' ') {
					I.buffer.index = i - 1;
					break;
				}
			}
			if (I.buffer.data[i] != ' ') {
				I.buffer.index = 0;
			}
			break;
		case 138:// ctrl+up arrow
			// first
			I.buffer.index = 0;
			break;
		case 139:// ctrl+right arrow
			// next word
			for (i = I.buffer.index; i < I.buffer.length; i++) {
				if (I.buffer.data[i] == ' ') {
					I.buffer.index = i + 1;
					break;
				}
			}
			if (I.buffer.data[i] != ' ') {
				I.buffer.index = I.buffer.length;
			}
			break;
		case 140:// ctrl+down arrow
			// end
			I.buffer.index = I.buffer.length;
			break;
		case 36:// HOME
			I.buffer.index = 0;
			break;
		case 35:// END
			I.buffer.index = I.buffer.length;
			break;
		/*case 0x37: // HOME xrvt-unicode
		// r_cons_readchar ();
		case 0x38: // END xrvt-unicode
		// r_cons_readchar ();*/
		case 46:// supr
			if (I.buffer.index < I.buffer.length) {
				memmove (I.buffer.data + I.buffer.index,
					I.buffer.data + I.buffer.index + 1,
					strlen (I.buffer.data + I.buffer.index + 1) + 1);
			}
			if (buf[1] == -1) {
				r_cons_break_pop ();
				return NULL;
			}
			break;

		default:
			break;
		}
		vch = 0;
		switch (*buf) {
		// case -1: // ^D
		// return NULL;
		case 0:	// no key must by handle by the code up
			// ignore
			break;
		case 1:	// ^A
			I.buffer.index = 0;
			break;
		case 2:	// ^b // emacs left
			I.buffer.index = I.buffer.index? I.buffer.index - 1: 0;
			break;
		case 5:	// ^E
			if (prev == 24) {	// ^X = 0x18
				I.buffer.data[I.buffer.length] = 0;	// probably unnecessary
				tmp_ed_cmd = I.editor_cb (I.user, I.buffer.data);
				if (tmp_ed_cmd) {
					/* copied from yank (case 25) */
					I.buffer.length = strlen (tmp_ed_cmd);
					if (I.buffer.length < R_LINE_BUFSIZE) {
						I.buffer.index = I.buffer.length;
						strncpy (I.buffer.data, tmp_ed_cmd, R_LINE_BUFSIZE - 1);
						I.buffer.data[R_LINE_BUFSIZE - 1] = '\0';
					} else {
						I.buffer.length -= strlen (tmp_ed_cmd);
					}
					free (tmp_ed_cmd);
				}
			} else {
				I.buffer.index = I.buffer.length;
			}
			break;
		case 3:	// ^C
			if (I.echo) {
				eprintf ("^C\n");
			}
			I.buffer.index = I.buffer.length = 0;
			*I.buffer.data = '\0';
			gcomp = 0;
			goto _end;
		case 4:	// ^D
			if (!I.buffer.data[0]) {/* eof */
				if (I.echo) {
					printf ("^D\n");
				}
				r_cons_set_raw (false);
				r_cons_break_pop ();
				return NULL;
			}
			if (I.buffer.index < I.buffer.length) {
				memmove (I.buffer.data + I.buffer.index,
					I.buffer.data + I.buffer.index + 1,
					strlen (I.buffer.data + I.buffer.index + 1) + 1);
			}
			break;
		case 10:// ^J -- ignore
			return I.buffer.data;
		case 11:// ^K -- ignore
			break;
		case 6:	// ^f // emacs right
			I.buffer.index = I.buffer.index < I.buffer.length
					 ? I.buffer.index + 1
					 : I.buffer.length;
			break;
		case 12:// ^L -- right
			I.buffer.index = (I.buffer.index < I.buffer.length)
					 ? I.buffer.index + 1
					 : I.buffer.length;
			if (I.echo) {
				eprintf ("\x1b[2J\x1b[0;0H");
			}
			fflush (stdout);
			break;
		case 18:// ^R -- autocompletion
			gcomp = 1;
			break;
		case 19:// ^S -- backspace
			if (gcomp) {
				gcomp--;
			} else {
				I.buffer.index =
					I.buffer.index? I.buffer.index - 1: 0;
			}
			break;
		case 21:// ^U - cut
			free (I.clipboard);
			I.clipboard = strdup (I.buffer.data);
			I.buffer.data[0] = '\0';
			I.buffer.length = 0;
			I.buffer.index = 0;
			break;
		case 22:// ^V - Paste from windows clipboard
			if (OpenClipboard (NULL)) {
				hClipBoard = GetClipboardData (CF_TEXT);
				if (hClipBoard) {
					clipText = GlobalLock (hClipBoard);
					if (clipText) {
						I.buffer.length += strlen (clipText);
						if (I.buffer.length < R_LINE_BUFSIZE) {
							I.buffer.index = I.buffer.length;
							strcat (I.buffer.data, clipText);
						} else {
							I.buffer.length -= strlen (I.clipboard);
						}
					}
					GlobalUnlock (hClipBoard);
				}
				CloseClipboard ();
			}
			break;
		case 23:// ^W ^w
			unix_word_rubout ();
			break;
		case 24:// ^X -- do nothing but store in prev = *buf
			break;
		case 25:// ^Y - paste
			if (I.clipboard != NULL) {
				I.buffer.length += strlen (I.clipboard);
				// TODO: support endless strings
				if (I.buffer.length < R_LINE_BUFSIZE) {
					I.buffer.index = I.buffer.length;
					strcat (I.buffer.data, I.clipboard);
				} else {
					I.buffer.length -= strlen (I.clipboard);
				}
			}
			break;
		case 14:// ^n
			if (gcomp) {
				if (gcomp_idx > 0) {
					gcomp_idx--;
				}
			} else {
				r_line_hist_down ();
			}
			break;
		case 16:// ^p
			if (gcomp) {
				gcomp_idx++;
			} else {
				r_line_hist_up ();
			}
			break;
		case 8:
		case 127:
			if (I.buffer.index < I.buffer.length) {
				if (I.buffer.index > 0) {
					int len = 0;
					// TODO: WIP
					len = 1;
					I.buffer.index--;
					memmove (I.buffer.data + I.buffer.index,
						I.buffer.data + I.buffer.index + len,
						strlen (I.buffer.data + I.buffer.index));
					I.buffer.length -= len;
					I.buffer.data[I.buffer.length] = 0;
				}
			} else {
// OK
				I.buffer.index = --I.buffer.length;
				if (I.buffer.length < 0) {
					I.buffer.length = 0;
				}
				I.buffer.data[I.buffer.length] = '\0';
			}
			if (I.buffer.index < 0) {
				I.buffer.index = 0;
			}
			break;
		/* tab */
		case 9:	// tab
			r_line_autocomplete ();
			break;
		/* enter */
		case 13:
			if (gcomp && I.buffer.length > 0) {
				strncpy (I.buffer.data, gcomp_line, R_LINE_BUFSIZE - 1);
				I.buffer.data[R_LINE_BUFSIZE - 1] = '\0';
				I.buffer.length = strlen (gcomp_line);
			}
			gcomp_idx = gcomp = 0;
			goto _end;
		default:
			if (gcomp) {
				gcomp++;
			}
			if (I.buffer.index < I.buffer.length) {
				for (i = ++I.buffer.length; i > I.buffer.index; i--) {
					I.buffer.data[i] = I.buffer.data[i - 1];
				}
				I.buffer.data[I.buffer.index] = buf[0];
			} else {
				I.buffer.data[I.buffer.length] = buf[0];
				I.buffer.length++;
				if (I.buffer.length > (R_LINE_BUFSIZE - 1)) {
					I.buffer.length--;
				}
				I.buffer.data[I.buffer.length] = '\0';
			}
			I.buffer.index++;
			break;
		}
		prev = buf[0];
		if (I.echo) {
			if (gcomp) {
				gcomp_line = "";
				if (I.history.data) {
					for (i = 0; i < I.history.size; i++) {
						if (!I.history.data[i]) {
							break;
						}
						if (strstr (I.history.data[i], I.buffer.data)) {
							gcomp_line = I.history.data[i];
							if (!gcomp_idx--) {
								break;
							}
						}
					}
				}
				printf ("\r (reverse-i-search (%s)): %s\r", I.buffer.data, gcomp_line);
			} else {
				int chars = R_MAX (1, strlen (I.buffer.data));	// wtf?
				int len, cols = R_MAX (1, columns - r_str_ansi_len (I.prompt) - 2);
				/* print line */
				printf ("\r%s", I.prompt);
				fwrite (I.buffer.data, 1, R_MIN (cols, chars), stdout);
				/* place cursor */
				printf ("\r%s", I.prompt);
				if (I.buffer.index > cols) {
					printf ("< ");
					i = I.buffer.index - cols;
					if (i > sizeof (I.buffer.data)) {
						i = sizeof (I.buffer.data) - 1;
					}
				} else {
					i = 0;
				}
				len = I.buffer.index - i;
				if (len > 0 && (i + len) <= I.buffer.length) {
					fwrite (I.buffer.data + i, 1, len, stdout);
				}
			}
			fflush (stdout);
		}
	}
_end:
	r_cons_break_pop ();
	r_cons_set_raw (0);
	if (I.echo) {
		printf ("\r%s%s\n", I.prompt, I.buffer.data);
		fflush (stdout);
	}

	// should be here or not?
	if (!memcmp (I.buffer.data, "!history", 8)) {
		r_line_hist_list ();
		return r_line_nullstr;
	}
	return I.buffer.data[0] != '\0'? I.buffer.data: r_line_nullstr;
}
#endif

R_API const char *r_line_readline_cb(RLineReadCallback cb, void *user) {
#if __WINDOWS__ && !__CYGWIN__
	// new implementation for read input at windows by skuater. If something fail set this to 0
	return r_line_readline_cb_win (cb, user);
#endif
	int columns = r_cons_get_size (NULL) - 2;
	const char *gcomp_line = "";
	static int gcomp_idx = 0;
	static int gcomp = 0;
	signed char buf[10];
#if USE_UTF8
	int utflen;
#endif
	int ch, i = 0;	/* grep completion */
	char *tmp_ed_cmd, prev = 0;

	I.buffer.index = I.buffer.length = 0;
	I.buffer.data[0] = '\0';
	if (I.contents) {
		memmove (I.buffer.data, I.contents,
			R_MIN (strlen (I.contents) + 1, R_LINE_BUFSIZE - 1));
		I.buffer.data[R_LINE_BUFSIZE - 1] = '\0';
		I.buffer.index = I.buffer.length = strlen (I.contents);
	}
	if (I.disable) {
		if (!fgets (I.buffer.data, R_LINE_BUFSIZE - 1, stdin)) {
			return NULL;
		}
		I.buffer.data[strlen (I.buffer.data)] = '\0';
		return (*I.buffer.data)? I.buffer.data: r_line_nullstr;
	}

	memset (&buf, 0, sizeof buf);
	r_cons_set_raw (1);

	if (I.echo) {
		r_cons_clear_line (0);
		printf ("\x1b[0K\r%s%s", I.prompt, I.buffer.data);
		fflush (stdout);
	}
	r_cons_break_push (NULL, NULL);
	for (;;) {
		if (r_cons_is_breaked ()) {
			eprintf ("CATCH\n");
			break;
		}
		I.buffer.data[I.buffer.length] = '\0';
		if (cb && !cb (user, I.buffer.data)) {
			I.buffer.data[0] = 0;
			I.buffer.length = 0;
		}
#if USE_UTF8
		utflen = r_line_readchar_utf8 ((ut8 *) buf, sizeof (buf));
		if (utflen < 1) {
			r_cons_break_pop ();
			return NULL;
		}
		buf[utflen] = 0;
#else
		ch = r_cons_readchar ();
		if (ch == -1) {
			r_cons_break_pop ();
			return NULL;
		}
		buf[0] = ch;
#endif
		if (I.echo) {
			r_cons_clear_line (0);
		}
		if (columns < 1) {
			columns = 40;
		}
#if __WINDOWS__ && !__CYGWIN__
		if (I.echo) {
			printf ("\r%*c\r", columns, ' ');
		}
#else
		if (I.echo) {
			printf ("\r\x1b[2K\r");	// %*c\r", columns, ' ');
		}
#endif
		switch (*buf) {
		case 0:	// control-space
			/* ignore atm */
			break;
		case 1:	// ^A
			if (gcomp) {
				strcpy (I.buffer.data, gcomp_line);
				I.buffer.length = strlen (I.buffer.data);
				I.buffer.index = 0;
				gcomp = false;
			}
			I.buffer.index = 0;
			break;
		case 2:	// ^b // emacs left
#if USE_UTF8
			{
				char *s = I.buffer.data + I.buffer.index - 1;
				utflen = 1;
				while (s > I.buffer.data && (*s & 0xc0) == 0x80) {
					utflen++;
					s--;
				}
			}
			I.buffer.index = I.buffer.index
					 ? I.buffer.index - utflen
					 : 0;
#else
			I.buffer.index = I.buffer.index
					 ? I.buffer.index - 1
					 : 0;
#endif
			break;
		case 5:	// ^E
			if (gcomp) {
				strcpy (I.buffer.data, gcomp_line);
				I.buffer.index = strlen (I.buffer.data);
				I.buffer.length = I.buffer.index;
				gcomp = false;
			} else if (prev == 24) {// ^X = 0x18
				I.buffer.data[I.buffer.length] = 0;	// probably unnecessary
				tmp_ed_cmd = I.editor_cb (I.user, I.buffer.data);
				if (tmp_ed_cmd) {
					/* copied from yank (case 25) */
					I.buffer.length = strlen (tmp_ed_cmd);
					if (I.buffer.length < R_LINE_BUFSIZE) {
						I.buffer.index = I.buffer.length;
						strncpy (I.buffer.data, tmp_ed_cmd, R_LINE_BUFSIZE - 1);
						I.buffer.data[R_LINE_BUFSIZE - 1] = '\0';
					} else {
						I.buffer.length -= strlen (tmp_ed_cmd);
					}
					free (tmp_ed_cmd);
				}
			} else {
				I.buffer.index = I.buffer.length;
			}
			break;
		case 3:	// ^C
			if (I.echo) {
				eprintf ("^C\n");
			}
			I.buffer.index = I.buffer.length = 0;
			*I.buffer.data = '\0';
			gcomp = 0;
			goto _end;
		case 4:	// ^D
			if (!I.buffer.data[0]) {/* eof */
				if (I.echo) {
					printf ("^D\n");
				}
				r_cons_set_raw (false);
				r_cons_break_pop ();
				return NULL;
			}
			if (I.buffer.index < I.buffer.length) {
				memmove (I.buffer.data + I.buffer.index,
					I.buffer.data + I.buffer.index + 1,
					strlen (I.buffer.data + I.buffer.index + 1) + 1);
			}
			break;
		case 10:// ^J -- ignore
			r_cons_break_pop ();
			return I.buffer.data;
		case 11:// ^K
			I.buffer.data[I.buffer.index] = '\0';
			I.buffer.length = I.buffer.index;
			break;
		case 6:	// ^f // emacs right
#if USE_UTF8
			{
				char *s = I.buffer.data + I.buffer.index + 1;
				utflen = 1;
				while ((*s & 0xc0) == 0x80) {
					utflen++;
					s++;
				}
				I.buffer.index = I.buffer.index < I.buffer.length
						 ? I.buffer.index + utflen
						 : I.buffer.length;
			}
#else
			I.buffer.index = I.buffer.index < I.buffer.length
					 ? I.buffer.index + 1
					 : I.buffer.length;
#endif
			break;
		case 12:// ^L -- right
			I.buffer.index = I.buffer.index < I.buffer.length
					 ? I.buffer.index + 1
					 : I.buffer.length;
			if (I.echo) {
				eprintf ("\x1b[2J\x1b[0;0H");
			}
			fflush (stdout);
			break;
		case 18:// ^R -- autocompletion
			gcomp = 1;
			break;
		case 19:// ^S -- backspace
			if (gcomp) {
				gcomp--;
			} else {
#if USE_UTF8
				if (I.buffer.index > 0) {
					char *s;
					do {
						I.buffer.index--;
						s = I.buffer.data + I.buffer.index;
					} while ((*s & 0xc0) == 0x80);
				}
#else
				I.buffer.index = I.buffer.index? I.buffer.index - 1: 0;
#endif
			}
			break;
		case 21:// ^U - cut
			free (I.clipboard);
			I.clipboard = strdup (I.buffer.data);
			I.buffer.data[0] = '\0';
			I.buffer.length = 0;
			I.buffer.index = 0;
			break;
		case 23:// ^W ^w
			if (I.buffer.index > 0) {
				for (i = I.buffer.index - 1; i > 0 && I.buffer.data[i] == ' '; i--) {
					/*nothing to see here*/
				}
				for (; i && I.buffer.data[i] != ' '; i--) {
					/*nothing to see here*/
				}
				if (!i) {
					for (; i > 0 && I.buffer.data[i] == ' '; i--) {
						/*nothing to see here*/
					}
				}
				if (i > 0) {
					i++;
				} else if (i < 0) {
					i = 0;
				}
				if (I.buffer.index > I.buffer.length) {
					I.buffer.length = I.buffer.index;
				}
				memmove (I.buffer.data + i,
					I.buffer.data + I.buffer.index,
					I.buffer.length - I.buffer.index + 1);
				I.buffer.length = strlen (I.buffer.data);
				I.buffer.index = i;
			}
			break;
		case 24:// ^X -- do nothing but store in prev = *buf
			break;
		case 25:// ^Y - paste
			if (I.clipboard != NULL) {
				I.buffer.length += strlen (I.clipboard);
				// TODO: support endless strings
				if (I.buffer.length < R_LINE_BUFSIZE) {
					I.buffer.index = I.buffer.length;
					strcat (I.buffer.data, I.clipboard);
				} else {
					I.buffer.length -= strlen (I.clipboard);
				}
			}
			break;
		case 14:// ^n
			if (gcomp) {
				if (gcomp_idx > 0) {
					gcomp_idx--;
				}
			} else {
				r_line_hist_down ();
			}
			break;
		case 16:// ^p
			if (gcomp) {
				gcomp_idx++;
			} else {
				r_line_hist_up ();
			}
			break;
		case 27:// esc-5b-41-00-00
			buf[0] = r_cons_readchar ();
			switch (buf[0]) {
			case 127: // alt+bkspace
				unix_word_rubout ();
				break;
			case -1:
				r_cons_break_pop ();
				return NULL;
			case 1:	// begin
				I.buffer.index = 0;
				break;
			case 5:	// end
				I.buffer.index = I.buffer.length;
				break;
			case 'B':
			case 'b':
				// previous word
				for (i = I.buffer.index - 2; i >= 0; i--) {
					if (I.buffer.data[i] == ' ' && I.buffer.data[i + 1] != ' ') {
						I.buffer.index = i + 1;
						break;
					}
				}
				if (i < 0) {
					I.buffer.index = 0;
				}
				break;
			case 'F':
			case 'f':
				// next word
				for (i = I.buffer.index + 1; i < I.buffer.length; i++) {
					if (I.buffer.data[i] != ' ' && I.buffer.data[i - 1] == ' ') {
						I.buffer.index = i;
						break;
					}
				}
				if (i >= I.buffer.length) {
					I.buffer.index = I.buffer.length;
				}
				break;
			default:
				buf[1] = r_cons_readchar ();
				if (buf[1] == -1) {
					r_cons_break_pop ();
					return NULL;
				}
				if (buf[0] == 0x5b) {	// [
					switch (buf[1]) {
					case '3':	// supr
						if (I.buffer.index < I.buffer.length) {
							memmove (I.buffer.data + I.buffer.index,
								I.buffer.data + I.buffer.index + 1,
								strlen (I.buffer.data + I.buffer.index + 1) + 1);
						}
						buf[1] = r_cons_readchar ();
						if (buf[1] == -1) {
							r_cons_break_pop ();
							return NULL;
						}
						break;
					/* arrows */
					case 'A':	// up arrow
						if (gcomp) {
							gcomp_idx++;
						} else if (r_line_hist_up () == -1) {
							r_cons_break_pop ();
							return NULL;
						}
						break;
					case 'B':	// down arrow
						if (gcomp) {
							if (gcomp_idx > 0) {
								gcomp_idx--;
							}
						} else if (r_line_hist_down () == -1) {
							r_cons_break_pop ();
							return NULL;
						}
						break;
					case 'C':	// right arrow
#if USE_UTF8
						{
							char *s = I.buffer.data + I.buffer.index + 1;
							utflen = 1;
							while ((*s & 0xc0) == 0x80) {
								utflen++;
								s++;
							}
							I.buffer.index = I.buffer.index < I.buffer.length
									 ? I.buffer.index + utflen
									 : I.buffer.length;
						}
#else
						I.buffer.index = I.buffer.index < I.buffer.length
								 ? I.buffer.index + 1
								 : I.buffer.length;
#endif
						break;
					case 'D':	// left arrow
#if USE_UTF8
						{
							char *s = I.buffer.data + I.buffer.index - 1;
							utflen = 1;
							while (s > I.buffer.data && (*s & 0xc0) == 0x80) {
								utflen++;
								s--;
							}
						}
						I.buffer.index = I.buffer.index
								 ? I.buffer.index - utflen
								 : 0;
#else
						I.buffer.index = I.buffer.index
								 ? I.buffer.index - 1
								 : 0;
#endif
						break;
					case 0x31:	// control + arrow
						ch = r_cons_readchar ();
						if (ch == 0x7e) {	// HOME in screen/tmux
							// corresponding END is 0x34 below (the 0x7e is ignored there)
							I.buffer.index = 0;
							break;
						}
						r_cons_readchar ();
						ch = r_cons_readchar ();
						switch (ch) {
						case 0x41:
							// first
							I.buffer.index = 0;
							break;
						case 0x44:
							// previous word
							for (i = I.buffer.index; i > 0; i--) {
								if (I.buffer.data[i] == ' ') {
									I.buffer.index = i - 1;
									break;
								}
							}
							if (I.buffer.data[i] != ' ') {
								I.buffer.index = 0;
							}
							break;
						case 0x42:
							// end
							I.buffer.index = I.buffer.length;
							break;
						case 0x43:
							// next word
							for (i = I.buffer.index; i < I.buffer.length; i++) {
								if (I.buffer.data[i] == ' ') {
									I.buffer.index = i + 1;
									break;
								}
							}
							if (I.buffer.data[i] != ' ') {
								I.buffer.index = I.buffer.length;
							}
							break;
						}
						r_cons_set_raw (1);
						break;
					case 0x37:	// HOME xrvt-unicode
						r_cons_readchar ();
					case 0x48:	// HOME
						I.buffer.index = 0;
						break;
					case 0x34:	// END
					case 0x38:	// END xrvt-unicode
						r_cons_readchar ();
					case 0x46:	// END
						I.buffer.index = I.buffer.length;
						break;
					}
				}
			}
			break;
		case 8:
		case 127:
			if (I.buffer.index < I.buffer.length) {
				if (I.buffer.index > 0) {
					int len = 0;
					// TODO: WIP
#if USE_UTF8
					char *s;
					do {
						I.buffer.index--;
						s = I.buffer.data + I.buffer.index;
						len++;
					} while ((*s & 0xc0) == 0x80);
#else
					len = 1;
					I.buffer.index--;
#endif
					memmove (I.buffer.data + I.buffer.index,
						I.buffer.data + I.buffer.index + len,
						strlen (I.buffer.data + I.buffer.index));
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
					if (I.buffer.length < 0) {
						I.buffer.length = 0;
						break;
					}
					s = I.buffer.data + I.buffer.length;
					i++;
				} while ((*s & 0xc0) == 0x80);

				I.buffer.index = I.buffer.length;
#else
				I.buffer.index = --I.buffer.length;
#endif
				if (I.buffer.length < 0) {
					I.buffer.length = 0;
				}
				I.buffer.data[I.buffer.length] = '\0';
			}
			if (I.buffer.index < 0) {
				I.buffer.index = 0;
			}
			break;
		case 9:	// tab
			if (I.buffer.data[I.buffer.length - 1] == '@') {
				strcpy (I.buffer.data + I.buffer.length, " ");
				I.buffer.length++;
				I.buffer.index++;
			}
			r_line_autocomplete ();
			break;
		case 13:
			if (gcomp && I.buffer.length > 0) {
				strncpy (I.buffer.data, gcomp_line, R_LINE_BUFSIZE - 1);
				I.buffer.data[R_LINE_BUFSIZE - 1] = '\0';
				I.buffer.length = strlen (gcomp_line);
			}
			gcomp_idx = gcomp = 0;
			goto _end;
		default:
			if (gcomp) {
				gcomp++;
			}
			if (I.buffer.index < I.buffer.length) {
#if USE_UTF8
				if ((I.buffer.length + utflen) < sizeof (I.buffer.data)) {
					I.buffer.length += utflen;
					for (i = I.buffer.length; i > I.buffer.index; i--) {
						I.buffer.data[i] = I.buffer.data[i - utflen];
					}
					memcpy (I.buffer.data + I.buffer.index, buf, utflen);
				}
#else
				for (i = ++I.buffer.length; i > I.buffer.index; i--) {
					I.buffer.data[i] = I.buffer.data[i - 1];
				}
				I.buffer.data[I.buffer.index] = buf[0];
#endif
			} else {
#if USE_UTF8
				if ((I.buffer.length + utflen) < sizeof (I.buffer.data)) {
					memcpy (I.buffer.data + I.buffer.length, buf, utflen);
					I.buffer.length += utflen;
				}
				I.buffer.data[I.buffer.length] = '\0';
#else
				I.buffer.data[I.buffer.length] = buf[0];
				I.buffer.length++;
				if (I.buffer.length > (R_LINE_BUFSIZE - 1)) {
					I.buffer.length--;
				}
				I.buffer.data[I.buffer.length] = '\0';
#endif
			}
#if USE_UTF8
			if ((I.buffer.index + utflen) <= I.buffer.length) {
				I.buffer.index += utflen;
			}
#else
			if (I.buffer.index < I.buffer.length) {
				I.buffer.index++;
			}
#endif
			break;
		}
		prev = buf[0];
		if (I.echo) {
			if (gcomp) {
				gcomp_line = "";
				if (I.history.data != NULL) {
					for (i = 0; i < I.history.size; i++) {
						if (!I.history.data[i]) {
							break;
						}
						if (strstr (I.history.data[i], I.buffer.data)) {
							gcomp_line = I.history.data[i];
							if (!gcomp_idx--) {
								break;
							}
						}
					}
				}
				printf ("\r (reverse-i-search (%s)): %s\r", I.buffer.data, gcomp_line);
			} else {
				int chars = R_MAX (1, strlen (I.buffer.data));	// wtf?
				int len, cols = R_MAX (1, columns - r_str_ansi_len (I.prompt) - 2);
				/* print line */
				printf ("\r%s", I.prompt);
				fwrite (I.buffer.data, 1, R_MIN (cols, chars), stdout);
				/* place cursor */
				printf ("\r%s", I.prompt);
				if (I.buffer.index > cols) {
					printf ("< ");
					i = I.buffer.index - cols;
					if (i > sizeof (I.buffer.data)) {
						i = sizeof (I.buffer.data) - 1;
					}
				} else {
					i = 0;
				}
				len = I.buffer.index - i;
				if (len > 0 && (i + len) <= I.buffer.length) {
					fwrite (I.buffer.data + i, 1, len, stdout);
				}
			}
			fflush (stdout);
		}
	}
_end:
	r_cons_break_pop ();
	r_cons_set_raw (0);
	if (I.echo) {
		printf ("\r%s%s\n", I.prompt, I.buffer.data);
		fflush (stdout);
	}

	// should be here or not?
	if (!memcmp (I.buffer.data, "!history", 8)) {
		// if (I.buffer.data[0]=='!' && I.buffer.data[1]=='\0') {
		r_line_hist_list ();
		return r_line_nullstr;
	}
	return I.buffer.data[0] != '\0'? I.buffer.data: r_line_nullstr;
}

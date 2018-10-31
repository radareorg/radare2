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
static const char word_break_characters[] = "\t\n ~`!@#$%^&*()-_=+[]{}\\|;:\"'<>,./";

static inline bool is_word_break_char(char ch) {
	int i;
	int len =
		sizeof (word_break_characters) /
		sizeof (word_break_characters[0]);
	for (i = 0; i < len; ++i) {
		if (ch == word_break_characters[i]) {
			return true;
		}
	}
	return false;
}

/* https://www.gnu.org/software/bash/manual/html_node/Commands-For-Killing.html */
static void backward_kill_word() {
	int i, len;
	if (I.buffer.index > 0) {
		for (i = I.buffer.index - 1; i > 0 && is_word_break_char (I.buffer.data[i]); i--) {
			/* Move the cursor index back until we hit a non-word-break-character */
		}
		for (; i > 0 && !is_word_break_char (I.buffer.data[i]); i--) {
			/* Move the cursor index back until we hit a word-break-character */
		}
		if (i > 0) {
			i++;
		} else if (i < 0) {
			i = 0;
		}
		if (I.buffer.index > I.buffer.length) {
			I.buffer.length = I.buffer.index;
		}
		len = I.buffer.index - i + 1;
		free (I.clipboard);
		I.clipboard = r_str_ndup (I.buffer.data + i, len);
		memmove (I.buffer.data + i, I.buffer.data + I.buffer.index,
				I.buffer.length - I.buffer.index + 1);
		I.buffer.length = strlen (I.buffer.data);
		I.buffer.index = i;
	}
}

static void kill_word() {
	int i, len;
	for (i = I.buffer.index + 1; i < I.buffer.length && is_word_break_char (I.buffer.data[i]); i++) {
		/* Move the cursor index forward until we hit a non-word-break-character */
	}
	for (; i < I.buffer.length && !is_word_break_char (I.buffer.data[i]); i++) {
		/* Move the cursor index forward we hit a word-break-character */
	}
	if (I.buffer.index >= I.buffer.length) {
		I.buffer.length = I.buffer.index;
	}
	len = i - I.buffer.index + 1;
	free (I.clipboard);
	I.clipboard = r_str_ndup (I.buffer.data + I.buffer.index, len);
	memmove (I.buffer.data + I.buffer.index, I.buffer.data + i, len);
	I.buffer.length = strlen (I.buffer.data);
}

static void paste() {
	if (I.clipboard) {
		char *cursor = I.buffer.data + I.buffer.index;
		int dist = (I.buffer.data + I.buffer.length) - cursor;
		int len = strlen (I.clipboard);
		I.buffer.length += len;
		memmove (cursor + len, cursor, dist);
		memcpy (cursor, I.clipboard, len);
		I.buffer.index += len;
	}
}

static void unix_word_rubout() {
	int i;
	if (I.buffer.index > 0) {
		for (i = I.buffer.index - 1; i > 0 && I.buffer.data[i] == ' '; i--) {
			/* Move cursor backwards until we hit a non-space character or EOL */
			/* This removes any trailing spaces from the input */
		}
		for (; i > 0 && I.buffer.data[i] != ' '; i--) {
			/* Move cursor backwards until we hit a space character or EOL */
			/* This deletes everything back to the previous space character */
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
	if (len > slen) {
		return -1;
	}
	for (i = 1; i < len; i++) {
		int ch = r_cons_readchar ();
		if (ch != -1) {
			s[i] = ch;
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
	INPUT_RECORD irInBuf;
	BOOL ret, bCtrl = FALSE;
	DWORD mode, out;
	ut8 buf[2];
	HANDLE h;
	int i;
	void *bed;

	if (I.zerosep) {
		*vch = 0;
		buf[0] = 0;
		bed = r_cons_sleep_begin ();
		int rsz = read (0, buf, 1);
		r_cons_sleep_end (bed);
		if (rsz != 1)
			return -1;
		return buf[0];
	}

	*buf = '\0';

	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &mode);
	SetConsoleMode (h, 0);	// RAW
do_it_again:
	*vch = 0;
	bed = r_cons_sleep_begin ();
	ret = ReadConsoleInput (h, &irInBuf, 1, &out);
	r_cons_sleep_end (bed);
	if (ret < 1) {
		return 0;
	}
	if (irInBuf.EventType == KEY_EVENT) {
		if (irInBuf.Event.KeyEvent.bKeyDown) {
			if (irInBuf.Event.KeyEvent.uChar.AsciiChar) {
				*buf = irInBuf.Event.KeyEvent.uChar.AsciiChar;
				bCtrl = irInBuf.Event.KeyEvent.dwControlKeyState & 8;
			}
			else {
				switch (irInBuf.Event.KeyEvent.wVirtualKeyCode) {
				case VK_DOWN: *vch = bCtrl ? 140 : 40; break;
				case VK_UP: *vch = bCtrl ? 138 : 38; break;
				case VK_RIGHT: *vch = bCtrl ? 139 : 39; break;
				case VK_LEFT: *vch = bCtrl ? 137 : 37; break;
				case VK_DELETE: *vch = bCtrl ? 146 : 46; break;	// SUPR KEY
				case VK_HOME: *vch = bCtrl ? 136 : 36; break;	// HOME KEY
				case VK_END: *vch = bCtrl ? 135 : 35; break;	// END KEY
				default: *vch = *buf = 0; break;
				}
			}
		}
	}
	if (buf[0] == 0 && *vch == 0) {
		goto do_it_again;
	}
	SetConsoleMode (h, mode);
	return buf[0];
}
#endif

R_API int r_line_set_hist_callback(RLine *line, RLineHistoryUpCb up, RLineHistoryDownCb down) {
	line->cb_history_up = up;
	line->cb_history_down = down;
	line->offset_hist_index = 0;
	line->file_hist_index = 0;
	line->sdbshell_hist_iter = line->sdbshell_hist? r_list_head (line->sdbshell_hist): NULL;
	return 1;
}

R_API int cmd_history_up(RLine *line) {
	if (line->hist_up) {
		return line->hist_up (line->user);
	}
	if (!line->history.data) {
		inithist ();
	}
	if (line->history.index > 0 && line->history.data) {
		strncpy (line->buffer.data, line->history.data[--line->history.index], R_LINE_BUFSIZE - 1);
		line->buffer.index = line->buffer.length = strlen (line->buffer.data);
		return true;
	}
	return false;
}

R_API int cmd_history_down(RLine *line) {
	if (line->hist_down) {
		return line->hist_down (line->user);
	}
	line->buffer.index = 0;
	if (!line->history.data) {
		inithist ();
	}
	if (line->history.index == line->history.top) {
		return false;
	}
	line->history.index++;
	if (line->history.index == line->history.top) {
		line->buffer.data[0] = '\0';
		line->buffer.index = line->buffer.length = 0;
		return false;
	}
	if (line->history.data && line->history.data[line->history.index]) {
		strncpy (line->buffer.data, line->history.data[line->history.index], R_LINE_BUFSIZE - 1);
		line->buffer.index = line->buffer.length = strlen (line->buffer.data);
	}
	return true;
}

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
	if (!I.cb_history_up) {
		r_line_set_hist_callback (&I, &cmd_history_up, &cmd_history_down);
	}
	return I.cb_history_up (&I);
}

static int r_line_hist_down() {
	if (!I.cb_history_down) {
		r_line_set_hist_callback (&I, &cmd_history_up, &cmd_history_down);
	}
	return I.cb_history_down (&I);
}

R_API const char *r_line_hist_get(int n) {
	int i = 0;
	if (!I.history.data) {
		inithist ();
	}
	n--;
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
	R_FREE (I.sdbshell_hist);
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
			if (!r_sys_mkdirp (path)) {
				eprintf ("could not save history into %s\n", path);
				goto end;
			}
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
end:
	free (path);
	return ret;
}

R_API int r_line_hist_chop(const char *file, int limit) {
	/* TODO */
	return 0;
}

static void selection_widget_draw() {
	RCons *cons = r_cons_singleton ();
	RSelWidget *sel_widget = I.sel_widget;
	int y, pos_y = cons->rows, pos_x = r_str_ansi_len (I.prompt);

	for (y = 0; y < sel_widget->options_len; y++) {
		sel_widget->w = R_MAX (sel_widget->w, strlen (sel_widget->options[y]));
	}
	sel_widget->w = R_MIN (sel_widget->w, R_SELWIDGET_MAXW);

	char *background_color = cons->color ? cons->pal.widget_bg : Color_INVERT_RESET;
	char *selected_color = cons->color ? cons->pal.widget_sel : Color_INVERT;
	bool scrollbar = sel_widget->options_len > R_SELWIDGET_MAXH;
	int scrollbar_y = 0, scrollbar_l = 0;
	if (scrollbar) {
		scrollbar_y = (R_SELWIDGET_MAXH * (sel_widget->selection - sel_widget->scroll)) / sel_widget->options_len;
		scrollbar_l = (R_SELWIDGET_MAXH * R_SELWIDGET_MAXH) / sel_widget->options_len;
	}

	for (y = 0; y < R_MIN (sel_widget->h, R_SELWIDGET_MAXH); y++) {
		r_cons_gotoxy (pos_x + 1, pos_y - y - 1);
		int scroll = R_MAX (0, sel_widget->selection - sel_widget->scroll);
		const char *option = y < sel_widget->options_len ? sel_widget->options[y + scroll] : "";
		r_cons_printf ("%s", sel_widget->selection == y + scroll ? selected_color : background_color);
		r_cons_printf ("%-*.*s", sel_widget->w, sel_widget->w, option);
		if (scrollbar && R_BETWEEN (scrollbar_y, y, scrollbar_y + scrollbar_l)) {
			r_cons_memcat (Color_INVERT" "Color_INVERT_RESET, 10);
		} else {
			r_cons_memcat (" ", 1);
		}
	}

	r_cons_gotoxy (pos_x + I.buffer.length, pos_y);
	r_cons_memcat (Color_RESET_BG, 5);
	r_cons_flush ();
}

static void selection_widget_up(int steps) {
	RSelWidget *sel_widget = I.sel_widget;
	if (sel_widget) {
		int height = R_MIN (sel_widget->h, R_SELWIDGET_MAXH - 1);
		sel_widget->selection = R_MIN (sel_widget->selection + steps, sel_widget->options_len - 1);
		if (steps == 1) {
			sel_widget->scroll = R_MIN (sel_widget->scroll + 1, R_SELWIDGET_MAXH - 1);
		} else if (sel_widget->selection + (height - sel_widget->scroll) > sel_widget->options_len - 1) {
			sel_widget->scroll = height - (sel_widget->options_len - 1 - sel_widget->selection);
		}
	}
}

static void selection_widget_down(int steps) {
	RSelWidget *sel_widget = I.sel_widget;
	if (sel_widget) {
		sel_widget->selection = R_MAX (sel_widget->selection - steps, 0);
		if (steps == 1) {
			sel_widget->scroll = R_MAX (sel_widget->scroll - 1, 0);
		} else if (sel_widget->selection - sel_widget->scroll <= 0) {
			sel_widget->scroll = sel_widget->selection;
		}
	}
}

static void print_rline_task(void *core) {
	r_cons_clear_line (0);
	r_cons_printf ("%s%s%s", Color_RESET, I.prompt,  I.buffer.data); 
	r_cons_flush ();
}

static void selection_widget_erase() {
	RSelWidget *sel_widget = I.sel_widget;
	if (sel_widget) {
		sel_widget->options_len = 0;
		sel_widget->selection = -1;
		selection_widget_draw ();
		R_FREE (I.sel_widget);
		RCons *cons = r_cons_singleton ();
		if (cons->event_resize && cons->event_data) {
			cons->event_resize (cons->event_data);
			cons->cb_task_oneshot (cons->user, print_rline_task, NULL);
		}
	}
}

static void selection_widget_select() {
	RSelWidget *sel_widget = I.sel_widget;
	if (sel_widget && sel_widget->selection < sel_widget->options_len) {
		I.buffer.length = R_MIN (strlen (sel_widget->options[sel_widget->selection]), R_LINE_BUFSIZE - 1);
		memcpy (I.buffer.data, sel_widget->options[sel_widget->selection], I.buffer.length);
		I.buffer.data[I.buffer.length] = '\0';
		I.buffer.index = I.buffer.length;
		selection_widget_erase ();
	}
}

static void selection_widget_update() {
	if (I.completion.argc == 0 ||
		(I.completion.argc == 1 && I.buffer.length >= strlen (I.completion.argv[0]))) {
		selection_widget_erase ();
		return;
	}
	if (!I.sel_widget) {
		RSelWidget *sel_widget = R_NEW0 (RSelWidget);
		I.sel_widget = sel_widget;
	}
	I.sel_widget->scroll = 0;
	I.sel_widget->selection = 0;
	I.sel_widget->options_len = I.completion.argc;
	I.sel_widget->options = I.completion.argv;
	I.sel_widget->h = R_MAX (I.sel_widget->h, I.completion.argc);
	selection_widget_draw ();
	r_cons_flush ();
	return;
}

R_API void r_line_autocomplete() {
	char *p;
	const char **argv = NULL;
	int argc = 0, i, j, plen, len = 0;
	bool opt = false;
	int cols = (int)(r_cons_get_size (NULL) * 0.82);

	/* prepare argc and argv */
	if (I.completion.run) {
		I.completion.opt = false;
		I.completion.run (&I);
		argc = I.completion.argc;
		argv = I.completion.argv;
		opt = I.completion.opt;
	}
	if (I.sel_widget && !I.sel_widget->complete_common) {
		selection_widget_update ();
		return;
	}

	if (opt) {
		p = (char *) r_sub_str_lchr (I.buffer.data, 0, I.buffer.index, '=');
	} else {
		p = (char *) r_sub_str_lchr (I.buffer.data, 0, I.buffer.index, ' ');
	}
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

	if (I.offset_prompt || I.file_prompt) {
		selection_widget_update ();
		if (I.sel_widget) {
			I.sel_widget->complete_common = false;
		}
		return;
	}

	/* show options */
	if (argc > 1 && I.echo) {
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
	int prev_buflen = 0;

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
		if (I.ansicon) {
			printf ("\r%s", R_CONS_CLEAR_LINE);
			printf ("%s%s%s", Color_RESET, I.prompt, I.buffer.data);
		} else {
			r_cons_clear_line (0);
			printf ("%s%s", I.prompt, I.buffer.data);
		}
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
			if (I.ansicon) {
				printf ("\r%s", R_CONS_CLEAR_LINE);
			} else {
				r_cons_clear_line (0);
			}
		}
		/* process special at vch codes first*/
		switch (vch) {
		case 37:	// left arrow
			I.buffer.index = I.buffer.index? I.buffer.index - 1: 0;
			break;
		case 38:	// up arrow
			if (I.sel_widget) {
				selection_widget_up (1);
				selection_widget_draw ();
			} else if (gcomp) {
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
			if (I.sel_widget) {
				selection_widget_up (1);
				selection_widget_draw ();
			} else if (gcomp) {
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
				tmp_ed_cmd = I.cb_editor (I.user, I.buffer.data);
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
			paste ();
			break;
		case 14:// ^n
			if (I.sel_widget) {
				selection_widget_down (1);
				selection_widget_draw ();
			} else if (gcomp) {
				if (gcomp_idx > 0) {
					gcomp_idx--;
				}
			} else {
				r_line_hist_down ();
			}
			break;
		case 16:// ^p
			if (I.sel_widget) {
				selection_widget_down (1);
				selection_widget_draw ();
			} else if (gcomp) {
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
			if (I.sel_widget) {
				I.sel_widget->complete_common = true;
			}
			r_line_autocomplete ();
			break;
		/* enter */
		case 13:
			if (I.sel_widget) {
				selection_widget_select ();
				break;
			}
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
		if (I.sel_widget && I.buffer.length != prev_buflen) {
			prev_buflen = I.buffer.length;
			r_line_autocomplete ();
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
				if (I.ansicon) {
					printf ("\r%s%s", Color_RESET, I.prompt);
				} else {
					printf ("\r%s", I.prompt);
				}
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

	R_FREE (I.sel_widget);

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
	int prev_buflen = -1;

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
		printf ("%s%s%s", Color_RESET, I.prompt, I.buffer.data);
		fflush (stdout);
	}
	r_cons_break_push (NULL, NULL);
	for (;;) {
		if (r_cons_is_breaked ()) {
			break;
		}
		I.buffer.data[I.buffer.length] = '\0';
		if (cb) {
			int cbret = cb (user, I.buffer.data);
			if (cbret == 0) {
				I.buffer.data[0] = 0;
				I.buffer.length = 0;
			}
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
				tmp_ed_cmd = I.cb_editor (I.user, I.buffer.data);
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
		case 23:// ^W ^w unix-word-rubout
			unix_word_rubout ();
			break;
		case 24:// ^X -- do nothing but store in prev = *buf
			break;
		case 25:// ^Y - paste
			paste ();
			break;
		case 14:// ^n
			if (I.sel_widget) {
				selection_widget_down (1);
				selection_widget_draw ();
			} else if (gcomp) {
				if (gcomp_idx > 0) {
					gcomp_idx--;
				}
			} else {
				r_line_hist_down ();
			}
			break;
		case 16:// ^p
			if (I.sel_widget) {
				selection_widget_up (1);
				selection_widget_draw ();
			} else if (gcomp) {
				gcomp_idx++;
			} else {
				r_line_hist_up ();
			}
			break;
		case 27: // esc-5b-41-00-00 alt/meta key
			buf[0] = r_cons_readchar ();
			switch (buf[0]) {
			case 127: // alt+bkspace
				backward_kill_word ();
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
					if (is_word_break_char (I.buffer.data[i]) && !is_word_break_char (I.buffer.data[i + 1])) {
						I.buffer.index = i + 1;
						break;
					}
				}
				if (i < 0) {
					I.buffer.index = 0;
				}
				break;
			case 'D':
			case 'd':
				kill_word ();
				break;
			case 'F':
			case 'f':
				// next word
				for (i = I.buffer.index + 1; i < I.buffer.length; i++) {
					if (!is_word_break_char (I.buffer.data[i]) && is_word_break_char (I.buffer.data[i - 1])) {
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
					case '5': // pag up
						buf[1] = r_cons_readchar ();
						if (I.sel_widget) {
							selection_widget_up (R_MIN (I.sel_widget->h, R_SELWIDGET_MAXH));
							selection_widget_draw ();
						}
						break;
					case '6': // pag down
						buf[1] = r_cons_readchar ();
						if (I.sel_widget) {
							selection_widget_down (R_MIN (I.sel_widget->h, R_SELWIDGET_MAXH));
							selection_widget_draw ();
						}
						break;
					/* arrows */
					case 'A':	// up arrow
						if (I.sel_widget) {
							selection_widget_up (1);
							selection_widget_draw ();
						} else if (gcomp) {
							gcomp_idx++;
						} else if (r_line_hist_up () == -1) {
							r_cons_break_pop ();
							return NULL;
						}
						break;
					case 'B':	// down arrow
						if (I.sel_widget) {
							selection_widget_down (1);
							selection_widget_draw ();
						} else if (gcomp) {
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
						if (I.sel_widget) {
							selection_widget_up (I.sel_widget->options_len - 1);
							selection_widget_draw ();
							break;
						}
						I.buffer.index = 0;
						break;
					case 0x34:	// END
					case 0x38:	// END xrvt-unicode
						r_cons_readchar ();
					case 0x46:	// END
						if (I.sel_widget) {
							selection_widget_down (I.sel_widget->options_len - 1);
							selection_widget_draw ();
							break;
						}
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
			if (I.sel_widget) {
				I.sel_widget->complete_common = true;
			}
			r_line_autocomplete ();
			break;
		case 13: // enter
			if (I.sel_widget) {
				selection_widget_select ();
				break;
			}
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
		if (I.sel_widget && I.buffer.length != prev_buflen) {
			prev_buflen = I.buffer.length;
			r_line_autocomplete ();
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
				printf ("\r%s%s", Color_RESET, I.prompt);
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

	R_FREE (I.sel_widget);

	// should be here or not?
	if (!memcmp (I.buffer.data, "!history", 8)) {
		// if (I.buffer.data[0]=='!' && I.buffer.data[1]=='\0') {
		r_line_hist_list ();
		return r_line_nullstr;
	}
	return I.buffer.data[0] != '\0'? I.buffer.data: r_line_nullstr;
}

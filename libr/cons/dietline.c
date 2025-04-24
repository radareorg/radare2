/* radare - LGPL - Copyright 2007-2025 - pancake */
/* dietline is a lightweight and portable library similar to GNU readline */

#include "r_util/r_str_util.h"
#include <r_cons.h>
#include <r_core.h>

#if R2__WINDOWS__
#include <windows.h>
#define printf(...) r_cons_win_printf (false, __VA_ARGS__)
#define USE_UTF8 1
static int r_line_readchar_win(ut8 *s, int slen);
#else
#include <sys/ioctl.h>
#ifndef HAVE_PTY
#include <termios.h>
#endif
#include <signal.h>
#define USE_UTF8 1
#endif

static const char word_break_characters[] = "\t\r\n ~`!@#$%^&*()-=+[]{}\\|;:\"'<>,./";

typedef struct {
	bool enable_yank_pop;
	bool yank_flag;
	bool gcomp;
	int count;
	int gcomp_idx;
} Dietline;

static R_TH_LOCAL Dietline D = {0};

typedef enum {
	MINOR_BREAK,
	MAJOR_BREAK
} BreakMode;

static inline bool is_word_break_char(char ch, BreakMode mode) {
	int i;
	if (mode == MAJOR_BREAK) {
		return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
	}
	int len =
		sizeof (word_break_characters) /
		sizeof (word_break_characters[0]);
	for (i = 0; i < len; i++) {
		if (ch == word_break_characters[i]) {
			return true;
		}
	}
	return false;
}

static inline void swap_case(int index) {
	if (isupper (I.buffer.data[index])) {
		I.buffer.data[index] += 32;
	} else if (islower (I.buffer.data[index])) {
		I.buffer.data[index] -= 32;
	}
}

static void backward_skip_major_word_break_chars(int *cursor) {
	while (*cursor >= 0 && is_word_break_char (I.buffer.data[*cursor], MAJOR_BREAK)) {
		(*cursor)--;
	}
}

static void skip_major_word_break_chars(int *cursor) {
	while (*cursor < I.buffer.length && is_word_break_char (I.buffer.data[*cursor], MAJOR_BREAK)) {
		(*cursor)++;
	}
}

static void goto_word_start(int *cursor, BreakMode break_mode) {
	if (!is_word_break_char (I.buffer.data[*cursor], break_mode)) {
		/* move cursor backwards to the next word-break char */
		while (*cursor >= 0 && !is_word_break_char (I.buffer.data[*cursor], break_mode)) {
			(*cursor)--;
		}
	} else if (is_word_break_char (I.buffer.data[*cursor], MINOR_BREAK)) {
		/* move cursor backwards to the next non-word-break char OR MAJOR break char */
		while (*cursor >= 0 && is_word_break_char (I.buffer.data[*cursor], MINOR_BREAK)
		       && !is_word_break_char (I.buffer.data[*cursor], MAJOR_BREAK)) {
			(*cursor)--;
		}
	} else {
		/* move cursor backwards to the next MINOR word-break char OR non-word-break char */
		while (*cursor >= 0 && is_word_break_char (I.buffer.data[*cursor], MAJOR_BREAK)) {
			(*cursor)--;
		}
	}
	/* increment cursor to go to the start of current word */
	if (*cursor < I.buffer.length - 1) {
		(*cursor)++;
	}
}

static void goto_word_end(int *cursor, BreakMode break_mode) {
	if (!is_word_break_char (I.buffer.data[*cursor], break_mode)) {
		/* move cursor forward to the next word-break char */
		while (*cursor < I.buffer.length && !is_word_break_char (I.buffer.data[*cursor], break_mode)) {
			(*cursor)++;
		}
	} else if (is_word_break_char (I.buffer.data[*cursor], MINOR_BREAK)) {
		/* move cursor forward to the next non-word-break char or MAJOR break char */
		while (*cursor < I.buffer.length && is_word_break_char (I.buffer.data[*cursor], MINOR_BREAK)
		       && !is_word_break_char (I.buffer.data[*cursor], MAJOR_BREAK)) {
			(*cursor)++;
		}
	}
	/* decrement cursor to go to the end of current word */
	if (*cursor > 0) {
		(*cursor)--;
	}
}

static void goto_next_word(int *cursor, BreakMode break_mode) {
	goto_word_end (cursor, break_mode);
	(*cursor)++;
	if (is_word_break_char (I.buffer.data[*cursor], MAJOR_BREAK)) {
		skip_major_word_break_chars (cursor);
	}
}

static int vi_end_word_motion(BreakMode break_mode) {
	int cursor;
	if (I.buffer.index < I.buffer.length - 1) {
		cursor = I.buffer.index;
		if (is_word_break_char (I.buffer.data[cursor], MAJOR_BREAK)) {
			skip_major_word_break_chars (&cursor);
			goto_word_end (&cursor, break_mode);
		} else {
			cursor++;
			skip_major_word_break_chars (&cursor);
			goto_word_end (&cursor, break_mode);
		}
		return cursor;
	}
	return I.buffer.index;
}

static int vi_backward_word_motion(BreakMode break_mode) {
	int cursor;
	if (I.buffer.index > 0) {
		cursor = I.buffer.index - 1;
		backward_skip_major_word_break_chars (&cursor);
		goto_word_start (&cursor, break_mode);
		return cursor;
	}
	return I.buffer.index;
}

static int vi_next_word_motion(BreakMode break_mode) {
	int cursor;
	if (I.buffer.index < I.buffer.length) {
		cursor = I.buffer.index;
		if (is_word_break_char (I.buffer.data[cursor], MAJOR_BREAK)) {
			skip_major_word_break_chars (&cursor);
		} else {
			goto_next_word (&cursor, break_mode);
		}
		return cursor;
	}
	return I.buffer.index;
}

static inline void __delete_current_char(void) {
	if (I.buffer.index < I.buffer.length) {
		int len = r_str_utf8_charsize (I.buffer.data + I.buffer.index);
		memmove (I.buffer.data + I.buffer.index,
			I.buffer.data + I.buffer.index + len,
			strlen (I.buffer.data + I.buffer.index + 1) + 1);
		I.buffer.length -= len;
		if (I.buffer.index > 0 && I.buffer.index == I.buffer.length) {
			I.buffer.index--;
		}
	}
}

static inline int indexof(int c, int offset) {
	char *ptr;
	ptr = strchr (I.buffer.data + offset, c);
	if (ptr != NULL) {
		return ptr - I.buffer.data;
	}
	return -1;
}

static inline int vi_motion_seek_to_char(int c) {
	int i;
	if (I.buffer.index < I.buffer.length) {
		i = indexof (c, I.buffer.index + 1);
		if (i != -1) {
			return i;
		}
	}
	return I.buffer.index;
}

static inline int vi_motion_seek_to_char_backward(int c) {
	int i;
	if (I.buffer.index > 0) {
		i = I.buffer.index - 1;
		while (i >= 0) {
			if (I.buffer.data[i] == c) {
				return i;
			}
			i--;
		}
	}
	return I.buffer.index;
}

static inline void shift_buffer(int start, int end) {
	int len;
	len = end - start + 1;
	free (I.clipboard);
	I.clipboard = r_str_ndup (I.buffer.data + start, len);
	r_line_clipboard_push (I.clipboard);
	memmove (I.buffer.data + start, I.buffer.data + end, I.buffer.length - end);
	/* resize buffer to take into account the word we deleted */
	I.buffer.data[I.buffer.length - len + 1] = '\0';
	I.buffer.length = strlen (I.buffer.data);
}

/* https://www.gnu.org/software/bash/manual/html_node/Commands-For-Killing.html */
static void backward_kill_word(BreakMode break_mode) {
	int i;
	i = vi_backward_word_motion (break_mode);
	if (i == I.buffer.index) {
		return;
	}
	shift_buffer (i, I.buffer.index);
	I.buffer.index = i;
}

static void kill_word(BreakMode break_mode, char motion) {
	int i = 0;
	if (I.buffer.index == I.buffer.length - 1) {
		__delete_current_char ();
		return;
	}
	switch (motion) {
	case 'w':
		i = vi_next_word_motion (break_mode);
		break;
	case 'e':
		i = vi_end_word_motion (break_mode) + 1;
		break;
	}
	shift_buffer (I.buffer.index, i);
	if (I.buffer.index > 0 && I.buffer.index == I.buffer.length) {
		I.buffer.index--;
	}
}

/*
 * diw and diW commands
 * how it works:
 *   - go to the start of the current word (spaces are considered words here)
 *   - delete until the last character of the word
 *   - handle edge cases when the last character of the current word is the last character of the line
 */
static void delete_in_word(BreakMode break_mode) {
	int i;
	if (I.buffer.length > 0) {
		goto_word_start (&I.buffer.index, break_mode);
		i = I.buffer.index;
		if (!is_word_break_char (I.buffer.data[i], break_mode)) {
			while (i < I.buffer.length && !is_word_break_char (I.buffer.data[i], break_mode)) {
				i++;
			}
			if (i == I.buffer.length - 1 && !is_word_break_char (I.buffer.data[i], break_mode)) {
				i--;
			}
		} else if (is_word_break_char (I.buffer.data[i], MAJOR_BREAK)) {
			while (i < I.buffer.length && is_word_break_char (I.buffer.data[i], MAJOR_BREAK)) {
				i++;
			}
			if (i == I.buffer.length - 1 && is_word_break_char (I.buffer.data[i], MAJOR_BREAK)) {
				i--;
			}
		} else {
			while (i < I.buffer.length && is_word_break_char (I.buffer.data[i], MINOR_BREAK)
			       && !is_word_break_char (I.buffer.data[i], MAJOR_BREAK)) {
				i++;
			}
			if (i == I.buffer.length - 1 && is_word_break_char (I.buffer.data[i], MINOR_BREAK)
			    && !is_word_break_char (I.buffer.data[i], MAJOR_BREAK)) {
				i--;
			}
		}
		if (i == I.buffer.index) {
			__delete_current_char ();
			return;
		}
		shift_buffer (I.buffer.index, i);
		if (I.buffer.index > 0 && I.buffer.index == I.buffer.length) {
			I.buffer.index--;
		}
	}
}

/*
 * function used for di", di(, di{, ... commands
 * parameters:
 *   - start -> starting character like '('
 *   - end -> closing character like ')'
 * how it works:
 *   - start by looking for the start char backwards
 *   - if not found look forward
 *   - call indexof() to get the index of the closing char
 *   - shift (resize) the buffer
 * note: doesn't work well with nested chars like ((test))
 * would need a stack for that
 */
static inline int delete_between(int start, int end) {
	int i, stop;
	i = vi_motion_seek_to_char_backward (start);
	if (i == I.buffer.index) {
		i = vi_motion_seek_to_char (start);
	}
	if (i != I.buffer.index) {
		stop = indexof (end, i + 1);
		if (stop != -1) {
			shift_buffer (i + 1, stop);
			return i + 1;
		}
	}
	return -1;
}

static void paste(void) {
	if (I.clipboard) {
		char *cursor = I.buffer.data + I.buffer.index;
		int dist = (I.buffer.data + I.buffer.length) - cursor;
		int len = strlen (I.clipboard);
		I.buffer.length += len;
		memmove (cursor + len, cursor, dist);
		memcpy (cursor, I.clipboard, len);
		I.buffer.index += len;
		D.enable_yank_pop = true;
	}
}

static void unix_word_rubout(void) {
	int i, len;
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
		len = I.buffer.index - i + 1;
		free (I.clipboard);
		I.clipboard = r_str_ndup (I.buffer.data + i, len);
		r_line_clipboard_push (I.clipboard);
		memmove (I.buffer.data + i,
			I.buffer.data + I.buffer.index,
			I.buffer.length - I.buffer.index + 1);
		I.buffer.length = strlen (I.buffer.data);
		I.buffer.index = i;
	}
}

static int inithist(void) {
	if (I.history.data) {
		int new_size = I.hist_size;
		if (new_size > 0 && I.history.size != new_size) {
			char **new_data = (char **) calloc (new_size, sizeof (char *));
			if (new_data) {
				int nb_copy_lines = R_MIN (I.history.top + 1, new_size);
				memcpy (new_data, I.history.data + (I.history.top + 1 - nb_copy_lines), sizeof (char *) * nb_copy_lines);
				int i;
				for (i = 0; i < I.history.top + 1 - nb_copy_lines; i++) {
					free (I.history.data[i]);
				}
				free (I.history.data);
				I.history.data = new_data;
				I.history.size = new_size;
				I.history.top = R_MIN (I.history.top, nb_copy_lines - 1);
				I.history.index = R_MIN (I.history.index, nb_copy_lines - 1);
			}
		}
		return true;
	}
	ZERO_FILL (I.history);
	I.history.size = I.hist_size;
	if (I.history.size <= 0) {
		return false;
	}
	I.history.data = (char **) calloc (I.history.size, sizeof (char *));
	if (!I.history.data) {
		return false;
	}
	return true;
}

/* initialize history stuff */
R_API int r_line_dietline_init(void) {
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
#if R2__WINDOWS__
	return r_line_readchar_win (s, slen);
#else
	// TODO: add support for w32
	ssize_t len, i;
	if (slen < 1) {
		return 0;
	}
	int ch = -1;
	if (I.demo) {
		ch = r_cons_readchar_timeout (80);
	} else {
		ch = r_cons_readchar ();
	}
	if (ch == -1) {
		return I.demo? 0: -1;
	}
	*s = ch;
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
		ch = r_cons_readchar ();
		if (ch != -1) {
			s[i] = ch;
		}
		if ((s[i] & 0xc0) != 0x80) {
			return -1;
		}
	}
	return len;
#endif
}
#endif

#if R2__WINDOWS__
static int r_line_readchar_win(ut8 *s, int slen) {	// this function handle the input in console mode
	INPUT_RECORD irInBuf = { { 0 } };
	BOOL ret;
	DWORD mode, out;
	char buf[5] = {
		0
	};
	void *bed;

	HANDLE h = GetStdHandle (STD_INPUT_HANDLE);
	DWORD new_mode = I.vtmode == 2? ENABLE_VIRTUAL_TERMINAL_INPUT: 0;
	GetConsoleMode (h, &mode);
	SetConsoleMode (h, new_mode);
	if (I.zerosep) {
		bed = r_cons_sleep_begin ();
		DWORD rsz = 0;
		BOOL ret = ReadFile (h, s, 1, &rsz, NULL);
		r_cons_sleep_end (bed);
		SetConsoleMode (h, mode);
		if (!ret || rsz != 1) {
			return 0;
		}
		return 1;
	}
do_it_again:
	bed = r_cons_sleep_begin ();
	if (r_cons_singleton ()->term_xterm) {
		ret = ReadFile (h, buf, 1, &out, NULL);
	} else {
		ret = ReadConsoleInput (h, &irInBuf, 1, &out);
	}
	r_cons_sleep_end (bed);
	if (ret < 1) {
		return 0;
	}
	if (irInBuf.EventType == KEY_EVENT) {
		if (irInBuf.Event.KeyEvent.bKeyDown) {
			if (irInBuf.Event.KeyEvent.uChar.UnicodeChar) {
				ut8 chbuf[4] = {
					0
				};
				memcpy (chbuf, &(irInBuf.Event.KeyEvent.uChar), 2);
				char *tmp = r_sys_conv_win_to_utf8_l ((PTCHAR) &chbuf, 1);
				if (tmp) {
					r_str_ncpy (buf, tmp, sizeof (buf));
					free (tmp);
				}
			} else {
				int idx = 0;
				buf[idx++] = 27;
				buf[idx++] = '[';	// Simulate escaping
				if (irInBuf.Event.KeyEvent.dwControlKeyState & 8) {
					buf[idx++] = '1';	// control key
				}
				switch (irInBuf.Event.KeyEvent.wVirtualKeyCode) {
				case VK_UP: buf[idx++] = 'A'; break;
				case VK_DOWN: buf[idx++] = 'B'; break;
				case VK_RIGHT: buf[idx++] = 'C'; break;
				case VK_LEFT: buf[idx++] = 'D'; break;
				case VK_PRIOR: buf[idx++] = '5'; break;	// PAGE UP
				case VK_NEXT: buf[idx++] = '6'; break;	// PAGE DOWN
				case VK_DELETE: buf[idx++] = '3'; break;// SUPR KEY
				case VK_HOME: buf[idx++] = 'H'; break;	// HOME KEY
				case VK_END: buf[idx++] = 'F'; break;	// END KEY
				default: buf[0] = 0; break;
				}
			}
		}
	}
	if (!buf[0]) {
		goto do_it_again;
	}
	r_str_ncpy ((char *) s, buf, slen);
	SetConsoleMode (h, mode);
	return strlen ((char *) s);
}

#endif

R_API int r_line_set_hist_callback(RLine *line, RLineHistoryUpCb up, RLineHistoryDownCb down) {
	line->cb_history_up = up;
	line->cb_history_down = down;
	line->offset_hist_index = 0;
	line->file_hist_index = 0;
	line->sdbshell_hist_iter = r_list_head (line->sdbshell_hist);
	return 1;
}

static inline bool match_hist_line(RLine *line, int i) {
	const char *hist_line = line->history.data[i];
	char *cur_line = line->history.match;
	if (!line->histfilter) {
		return true;
	}
	// Starts with but not equal to
	return r_str_startswith (hist_line, cur_line) && strcmp (hist_line, cur_line);
}

static void setup_hist_match(RLine *line) {
	if (line->history.do_setup_match) {
		R_FREE (line->history.match);
		if (*line->buffer.data) {
			line->history.match = strdup (line->buffer.data);
		}
	}
	line->history.do_setup_match = false;
}

R_API int r_line_hist_cmd_up(RLine *line) {
	if (line->hist_up) {
		return line->hist_up (line->user);
	}
	if (!inithist ()) {
		return false;
	}
	if (line->history.index > 0 && line->history.data) {
		setup_hist_match (line);
		if (line->history.match) {
			int i;
			for (i = line->history.index - 1; i >= 0; i--) {
				if (match_hist_line (line, i)) {
					line->history.index = i;
					break;
				}
			}
			if (i < 0) {
				return false;
			}
		} else {
			line->history.index--;
		}
		strncpy (line->buffer.data, line->history.data[line->history.index], R_LINE_BUFSIZE - 1);
		line->buffer.index = line->buffer.length = strlen (line->buffer.data);
		return true;
	}
	return false;
}

R_API int r_line_hist_cmd_down(RLine *line) {
	if (line->hist_down) {
		return line->hist_down (line->user);
	}
	if (!line->history.data) {
		inithist ();
	}
	setup_hist_match (line);
	if (line->history.match) {
		int i;
		for (i = line->history.index + 1; i < line->history.top; i++) {
			if (match_hist_line (line, i)) {
				break;
			}
		}
		line->history.index = i;
	} else {
		line->history.index++;
	}
	if (line->history.index >= line->history.top) {
		line->history.index = line->history.top;
		if (line->history.match) {
			strncpy (line->buffer.data, line->history.match, R_LINE_BUFSIZE - 1);
		} else {
			line->buffer.data[0] = '\0';
		}
		line->buffer.index = line->buffer.length = strlen (line->buffer.data);
		return false;
	}
	if (line->history.data && line->history.data[line->history.index]) {
		strncpy (line->buffer.data, line->history.data[line->history.index], R_LINE_BUFSIZE - 1);
		line->buffer.index = line->buffer.length = strlen (line->buffer.data);
	}
	return true;
}

// TODO argument can be "owned" so we can save some unnecessary free/malloc's
R_API bool r_line_hist_add(const char *line) {
	if (R_STR_ISEMPTY (line)) {
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

static int r_line_hist_up(void) {
	if (!I.cb_history_up) {
		r_line_set_hist_callback (&I, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	}
	return I.cb_history_up (&I);
}

static int r_line_hist_down(void) {
	if (!I.cb_history_down) {
		r_line_set_hist_callback (&I, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	}
	return I.cb_history_down (&I);
}

R_API void r_line_hist_set_size(int size) {
	I.hist_size = R_MIN (size, 65536);
}

R_API int r_line_hist_get_size(void) {
	return I.history.size;
}

R_API const char *r_line_hist_get(int n) {
	int i = 0;
	inithist ();
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

R_API int r_line_hist_list(bool full) {
	int i = 0;
	inithist ();
	if (I.history.data) {
		i = full? 0: I.history.load_index;
		for (; i < I.history.size && I.history.data[i]; i++) {
			const char *pad = r_str_pad (' ', 32 - strlen (I.history.data[i]));
			r_cons_printf ("%s %s # !%d\n", I.history.data[i], pad, i);
		}
	}
	return i;
}

R_API void r_line_hist_free(void) {
	int i;
	if (I.history.data) {
		for (i = 0; i < I.history.size; i++) {
			R_FREE (I.history.data[i]);
		}
	}
	R_FREE (I.history.data);
	R_FREE (I.sdbshell_hist);
	I.history.index = 0;
}

/* load history from file. TODO: if file == NULL load from ~/.<prg>.history or so */
R_API bool r_line_hist_load(const char *file) {
	R_RETURN_VAL_IF_FAIL (file, false);
	// R_LOG_DEBUG ("LOAD %s", file);
	char *buf = calloc (1, R_LINE_BUFSIZE);
	if (!buf) {
		return false;
	}
	FILE *fd = r_sandbox_fopen (file, "rb");
	if (!fd) {
		free (buf);
		return false;
	}
	memset (buf, 0, R_LINE_BUFSIZE);
	while (fgets (buf, R_LINE_BUFSIZE - 1, fd)) {
		r_str_trim_tail (buf);
		if (*buf) {
			r_line_hist_add (buf);
		}
		memset (buf, 0, R_LINE_BUFSIZE);
	}
	I.history.load_index = I.history.index;
	fclose (fd);
	free (buf);
	return true;
}

R_API bool r_line_hist_save(const char *file) {
	R_RETURN_VAL_IF_FAIL (file && *file, false);
	// R_LOG_DEBUG ("SAVE %s", file);
	int i;
	bool ret = false;
	char *p = (char *) r_str_lastbut (file, R_SYS_DIR[0], NULL);
	if (p) {
		*p = 0;
		if (!r_sys_mkdirp (file)) {
			if (r_sandbox_check (R_SANDBOX_GRAIN_FILES)) {
				R_LOG_ERROR ("Could not save history into %s", file);
			}
			goto end;
		}
		*p = R_SYS_DIR[0];
	}
	FILE *fd = r_sandbox_fopen (file, "w");
	if (fd) {
		if (I.history.data) {
			for (i = 0; i < I.history.index; i++) {
				fputs (I.history.data[i], fd);
				fputs ("\n", fd);
			}
			ret = true;
		}
		fclose (fd);
	}
end:
	return ret;
}

R_API int r_line_hist_chop(const char *file, int limit) {
	/* TODO */
	return 0;
}

static void selection_widget_draw(void) {
	RCons *cons = r_cons_singleton ();
	RSelWidget *sel_widget = I.sel_widget;
	int y, pos_y, pos_x = r_str_ansi_len (I.prompt);
	sel_widget->h = R_MIN (sel_widget->h, R_SELWIDGET_MAXH);
	for (y = 0; y < sel_widget->options_len; y++) {
		sel_widget->w = R_MAX (sel_widget->w, strlen (sel_widget->options[y]));
	}
	if (sel_widget->direction == R_SELWIDGET_DIR_UP) {
		pos_y = cons->rows;
	} else {
		pos_y = r_cons_get_cur_line ();
		if (pos_y + sel_widget->h > cons->rows) {
			printf ("%s\n", r_str_pad ('\n', sel_widget->h));
			pos_y = cons->rows - sel_widget->h - 1;
		}
	}
	sel_widget->w = R_MIN (sel_widget->w, R_SELWIDGET_MAXW);

	char *background_color = cons->context->color_mode? cons->context->pal.widget_bg: Color_INVERT_RESET;
	char *selected_color = cons->context->color_mode? cons->context->pal.widget_sel: Color_INVERT;
	bool scrollbar = sel_widget->options_len > R_SELWIDGET_MAXH;
	int scrollbar_y = 0, scrollbar_l = 0;
	if (scrollbar) {
		scrollbar_y = (R_SELWIDGET_MAXH * (sel_widget->selection - sel_widget->scroll)) / sel_widget->options_len;
		scrollbar_l = (R_SELWIDGET_MAXH * R_SELWIDGET_MAXH) / sel_widget->options_len;
	}

	for (y = 0; y < sel_widget->h; y++) {
		if (sel_widget->direction == R_SELWIDGET_DIR_UP) {
			r_cons_gotoxy (pos_x + 1, pos_y - y - 1);
		} else {
			r_cons_gotoxy (pos_x + 1, pos_y + y + 1);
		}
		int scroll = R_MAX (0, sel_widget->selection - sel_widget->scroll);
		const char *option = y < sel_widget->options_len? sel_widget->options[y + scroll]: "";
		r_cons_printf ("%s", sel_widget->selection == y + scroll? selected_color: background_color);
		r_cons_printf ("%-*.*s", sel_widget->w, sel_widget->w, option);
		if (scrollbar && R_BETWEEN (scrollbar_y, y, scrollbar_y + scrollbar_l)) {
			r_cons_write (Color_INVERT " "Color_INVERT_RESET, 10);
		} else {
			r_cons_write (" ", 1);
		}
	}

	r_cons_gotoxy (pos_x + I.buffer.length, pos_y);
	r_cons_write (Color_RESET_BG, 5);
	r_cons_flush ();
}

static void selection_widget_up(int steps) {
	RSelWidget *sel_widget = I.sel_widget;
	if (sel_widget) {
		if (sel_widget->direction == R_SELWIDGET_DIR_UP) {
			int height = R_MIN (sel_widget->h, R_SELWIDGET_MAXH - 1);
			sel_widget->selection = R_MIN (sel_widget->selection + steps, sel_widget->options_len - 1);
			if (steps == 1) {
				sel_widget->scroll = R_MIN (sel_widget->scroll + 1, R_SELWIDGET_MAXH - 1);
			} else if (sel_widget->selection + (height - sel_widget->scroll) > sel_widget->options_len - 1) {
				sel_widget->scroll = height - (sel_widget->options_len - 1 - sel_widget->selection);
			}
		} else {
			sel_widget->selection = R_MAX (sel_widget->selection - steps, 0);
			if (steps == 1) {
				sel_widget->scroll = R_MAX (sel_widget->scroll - 1, 0);
			} else if (sel_widget->selection - sel_widget->scroll <= 0) {
				sel_widget->scroll = sel_widget->selection;
			}
		}
	}
}

static void selection_widget_down(int steps) {
	RSelWidget *sel_widget = I.sel_widget;
	if (sel_widget) {
		if (sel_widget->direction == R_SELWIDGET_DIR_UP) {
			sel_widget->selection = R_MAX (sel_widget->selection - steps, 0);
			if (steps == 1) {
				sel_widget->scroll = R_MAX (sel_widget->scroll - 1, 0);
			} else if (sel_widget->selection - sel_widget->scroll <= 0) {
				sel_widget->scroll = sel_widget->selection;
			}
		} else {
			int height = R_MIN (sel_widget->h, R_SELWIDGET_MAXH - 1);
			sel_widget->selection = R_MIN (sel_widget->selection + steps, sel_widget->options_len - 1);
			if (steps == 1) {
				sel_widget->scroll = R_MIN (sel_widget->scroll + 1, R_SELWIDGET_MAXH - 1);
			} else if (sel_widget->selection + (height - sel_widget->scroll) > sel_widget->options_len - 1) {
				sel_widget->scroll = height - (sel_widget->options_len - 1 - sel_widget->selection);
			}
		}
	}
}

static void print_rline_task(void *_core) {
	r_cons_clear_line (0);
	r_cons_printf ("%s%s%s", Color_RESET, I.prompt, I.buffer.data);
	r_cons_flush ();
}

static void selection_widget_erase(void) {
	RSelWidget *sel_widget = I.sel_widget;
	if (sel_widget) {
		sel_widget->options_len = 0;
		sel_widget->selection = -1;
		selection_widget_draw ();
		R_FREE (I.sel_widget);
		RCons *cons = r_cons_singleton ();
		if (cons->event_resize && cons->event_data) {
			cons->event_resize (cons->event_data);
			RCore *core = (RCore *) (cons->user);
			if (core) {
				cons->cb_task_oneshot (&core->tasks, print_rline_task, core);
			}
		}
		printf ("%s", R_CONS_CLEAR_FROM_CURSOR_TO_END);
	}
}

static void selection_widget_select(void) {
	RSelWidget *sel_widget = I.sel_widget;
	if (sel_widget && sel_widget->selection < sel_widget->options_len) {
		char *sp = strchr (I.buffer.data, ' ');
		if (sp) {
			int delta = sp - I.buffer.data + 1;
			I.buffer.length = R_MIN (delta + strlen (sel_widget->options[sel_widget->selection]), R_LINE_BUFSIZE - 1);
			memcpy (I.buffer.data + delta, sel_widget->options[sel_widget->selection], strlen (sel_widget->options[sel_widget->selection]));
			I.buffer.index = I.buffer.length;
			return;
		}
		I.buffer.length = R_MIN (strlen (sel_widget->options[sel_widget->selection]), R_LINE_BUFSIZE - 1);
		memcpy (I.buffer.data, sel_widget->options[sel_widget->selection], I.buffer.length);
		I.buffer.data[I.buffer.length] = '\0';
		I.buffer.index = I.buffer.length;
		selection_widget_erase ();
	}
}

static void selection_widget_update(void) {
	int argc = r_pvector_length (&I.completion.args);
	const char **argv = (const char **) r_pvector_data (&I.completion.args);
	if (argc == 0 || (argc == 1 && I.buffer.length >= strlen (argv[0]))) {
		selection_widget_erase ();
		return;
	}
	if (!I.sel_widget) {
		RSelWidget *sel_widget = R_NEW0 (RSelWidget);
		I.sel_widget = sel_widget;
	}
	I.sel_widget->scroll = 0;
	I.sel_widget->selection = 0;
	I.sel_widget->options_len = argc;
	I.sel_widget->options = argv;
	I.sel_widget->h = R_MAX (I.sel_widget->h, I.sel_widget->options_len);

	if (I.prompt_type == R_LINE_PROMPT_DEFAULT) {
		I.sel_widget->direction = R_SELWIDGET_DIR_DOWN;
	} else {
		I.sel_widget->direction = R_SELWIDGET_DIR_UP;
	}
	selection_widget_draw ();
	r_cons_flush ();
	return;
}

R_API void r_line_autocomplete(void) {
	char *p;
	const char **argv = NULL;
	int argc = 0, i, j, plen, len = 0;
	bool opt = false;
	int cols = (int) (r_cons_get_size (NULL) * 0.82);
	RCons *cons = r_cons_singleton ();

	/* prepare argc and argv */
	if (I.completion.run) {
		I.completion.opt = false;
		I.completion.run (&I.completion, &I.buffer, I.prompt_type, I.completion.run_user);
		argc = r_pvector_length (&I.completion.args);
		argv = (const char **) r_pvector_data (&I.completion.args);
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
		const char *t = end_word?
				end_word: I.buffer.data + I.buffer.index;
		int largv0 = strlen (r_str_get (argv[0]));
		size_t len_t = strlen (t);
		p[largv0] = '\0';

		if ((p - I.buffer.data) + largv0 + 1 + len_t < plen) {
			if (len_t > 0) {
				int tt = largv0;
				if (*t != ' ') {
					p[tt++] = ' ';
				}
				memmove (p + tt, t, len_t);
			}
			memcpy (p, argv[0], largv0);

			if (p[largv0 - 1] != R_SYS_DIR[0]) {
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

	if (I.prompt_type != R_LINE_PROMPT_DEFAULT || cons->show_autocomplete_widget) {
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
#ifdef R2__WINDOWS__
		r_cons_win_printf (false, "%s%s\n", I.prompt, I.buffer.data);
#else
		printf ("%s%s\n", I.prompt, I.buffer.data);
#endif
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

R_API const char *r_line_readline(void) {
	return r_line_readline_cb (NULL, NULL);
}

static inline void rotate_kill_ring(void) {
	if (D.enable_yank_pop) {
		I.buffer.index -= strlen (r_list_get_n (I.kill_ring, I.kill_ring_ptr));
		I.buffer.data[I.buffer.index] = 0;
		I.kill_ring_ptr -= 1;
		if (I.kill_ring_ptr < 0) {
			I.kill_ring_ptr = I.kill_ring->length - 1;
		}
		I.clipboard = r_list_get_n (I.kill_ring, I.kill_ring_ptr);
		paste ();
	}
}

static inline void __delete_prev_char(void) {
	if (I.buffer.index < I.buffer.length) {
		if (I.buffer.index > 0) {
			size_t len = r_str_utf8_charsize_prev (I.buffer.data + I.buffer.index, I.buffer.index);
			I.buffer.index -= len;
			memmove (I.buffer.data + I.buffer.index,
				I.buffer.data + I.buffer.index + len,
				strlen (I.buffer.data + I.buffer.index));
			I.buffer.length -= len;
		}
	} else {
		I.buffer.length -= r_str_utf8_charsize_last (I.buffer.data);
		I.buffer.index = I.buffer.length;
		if (I.buffer.length < 0) {
			I.buffer.length = 0;
		}
	}
	I.buffer.data[I.buffer.length] = '\0';
	if (I.buffer.index < 0) {
		I.buffer.index = 0;
	}
}

static inline void delete_till_end(void) {
	I.buffer.data[I.buffer.index] = '\0';
	I.buffer.length = I.buffer.index;
	I.buffer.index = I.buffer.index > 0? I.buffer.index - 1: 0;
}

static const char *promptcolor(void) {
	if (I.demo) {
		return r_cons_singleton ()->context->pal.prompt;
	}
	return Color_RESET;
}

static void __print_prompt(void) {
	RCons *cons = r_cons_singleton ();
	int columns = r_cons_get_size (NULL) - 2;
	int len, i, cols = R_MAX (1, columns - r_str_ansi_len (I.prompt) - 2);
	if (cons->line->prompt_type == R_LINE_PROMPT_OFFSET) {
		r_cons_gotoxy (0, cons->rows);
		r_cons_flush ();
	}
	// printf ("%s", promptcolor ());
	r_cons_clear_line (0);
	if (cons->context->color_mode > 0) {
		printf ("\r%s%s%s", Color_RESET, promptcolor (), I.prompt);
	} else {
		printf ("\r%s", I.prompt);
	}
#if 1
	if (I.buffer.length > 0) {
		int maxlen = R_MIN (I.buffer.length, cols);
		fwrite (I.buffer.data, maxlen, 1, stdout);
		if (I.buffer.length > cols) {
			fwrite (" >", 2, 1, stdout);
		}
	}
#endif
	if (I.demo) {
		// 15% cpu usage, but yeah its fancy demoscene. may be good to optimize
		int pos = (D.count > 0)? D.count % strlen (I.prompt): 0;
		char *a = strdup (I.prompt);
		char *kb = (char *) r_str_ansi_chrn (a, pos);
		char *kc = (char *) r_str_ansi_chrn (kb, 3);
		char *b = r_str_ndup (kb, kc - kb);
		char *c = strdup (kc);
		char *rb = r_str_newf (Color_WHITE "%s%s", b, promptcolor ());
		*kb = 0;
		printf ("\r%s%s%s%s%s", promptcolor (), a, rb, c, Color_RESET);
		free (a);
		free (b);
		free (rb);
		free (c);
		D.count++;
		if (D.count > strlen (I.prompt)) {
			D.count = 0;
		}
	} else {
		printf ("\r%s%s%s", promptcolor (), I.prompt, promptcolor ());
	}
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
		if (i < I.buffer.length) {
			size_t slen = R_MIN (len, (I.buffer.length - i));
			if (slen > 0 && i < sizeof (I.buffer.data)) {
				fwrite (I.buffer.data + i, 1, slen, stdout);
			}
		}
	}
	fflush (stdout);
}

static inline void vi_delete_commands(int rep) {
	char c, t, e;
	int i;
	c = r_cons_readchar ();
	while (rep--) {
		switch (c) {
		case 'i':
			t = r_cons_readchar ();
			switch (t) {
			case 'w':
				delete_in_word (MINOR_BREAK);
				break;
			case 'W':
				delete_in_word (MINOR_BREAK);
				break;
			case 'b':
				t = '(';
				e = ')';
				i = delete_between (t, e);
				if (i != -1) {
					I.buffer.index = i;
				}
				break;
			case '"':
				e = '"';
				i = delete_between (t, e);
				if (i != -1) {
					I.buffer.index = i;
				}
				break;
			case '\'':
				e = '\'';
				i = delete_between (t, e);
				if (i != -1) {
					I.buffer.index = i;
				}
				break;
			case '(':
				e = ')';
				i = delete_between (t, e);
				if (i != -1) {
					I.buffer.index = i;
				}
				break;
			case '[':
				e = ']';
				i = delete_between (t, e);
				if (i != -1) {
					I.buffer.index = i;
				}
				break;
			case '<':
				e = '>';
				i = delete_between (t, e);
				if (i != -1) {
					I.buffer.index = i;
				}
				break;
			case '{':
				e = '}';
				i = delete_between (t, e);
				if (i != -1) {
					I.buffer.index = i;
				}
				break;
			}
			if (I.hud) {
				I.hud->vi = false;
			}
			break;
		case 'f':
			t = r_cons_readchar ();
			i = vi_motion_seek_to_char (t);
			if (i != I.buffer.index) {
				shift_buffer (I.buffer.index, i + 1);
			}
			break;
		case 'F':
			t = r_cons_readchar ();
			i = vi_motion_seek_to_char_backward (t);
			if (i != I.buffer.index) {
				shift_buffer (i, I.buffer.index);
				I.buffer.index = i;
			}
			break;
		case 't':
			t = r_cons_readchar ();
			i = vi_motion_seek_to_char (t);
			if (i != I.buffer.index) {
				shift_buffer (I.buffer.index, i);
			}
			break;
		case 'T':
			t = r_cons_readchar ();
			i = vi_motion_seek_to_char_backward (t);
			if (i != I.buffer.index) {
				if (i < I.buffer.length) {
					i++;
				}
				shift_buffer (i, I.buffer.index);
				I.buffer.index = i;
			}
			break;
		case 'E':
			kill_word (MAJOR_BREAK, 'e');
			break;
		case 'e':
			kill_word (MINOR_BREAK, 'e');
			break;
		case 'W':
			kill_word (MAJOR_BREAK, 'w');
			break;
		case 'w':
			kill_word (MINOR_BREAK, 'w');
			break;
		case 'B':
			backward_kill_word (MAJOR_BREAK);
			break;
		case 'b':
			backward_kill_word (MINOR_BREAK);
			break;
		case 'h':
			__delete_prev_char ();
			break;
		case 'l':
			__delete_current_char ();
			break;
		case '$':
			delete_till_end ();
			break;
		case '^':
		case '0':
			strncpy (I.buffer.data, I.buffer.data + I.buffer.index, I.buffer.length);
			I.buffer.length -= I.buffer.index;
			I.buffer.index = 0;
			break;
		case 'c':
		case 'd':
			I.buffer.index = 0;
			delete_till_end ();
			break;
		}
		__print_prompt ();
	}	// end of while (rep--)
}

static inline void __move_cursor_right(void) {
	I.buffer.index = I.buffer.index < I.buffer.length
		? I.buffer.index + r_str_utf8_charsize (I.buffer.data + I.buffer.index)
		: I.buffer.length;
}

static inline void __move_cursor_left(void) {
	I.buffer.index = I.buffer.index
		? I.buffer.index - r_str_utf8_charsize_prev (I.buffer.data + I.buffer.index, I.buffer.index)
		: 0;
}

static void __update_prompt_color(void) {
	RCons *cons = r_cons_singleton ();
	const char *BEGIN = "", *END = Color_RESET;
	if (cons->context->color_mode) {
		if (I.prompt_mode) {
			switch (I.vi_mode) {
			case CONTROL_MODE:
				BEGIN = cons->context->pal.invalid;
				break;
			case INSERT_MODE:
			default:
				BEGIN = cons->context->pal.prompt;
				break;
			}
		} else {
			BEGIN = cons->context->pal.prompt;
		}
		// END = cons->context->pal.reset;
	}
	char *prompt = r_str_escape (I.prompt);		// remove the color
	free (I.prompt);
	I.prompt = r_str_newf ("%s%s%s", BEGIN, prompt, END);
}

static bool __vi_mode(void) {
	char ch;
	I.vi_mode = CONTROL_MODE;
	__update_prompt_color ();
	const char *gcomp_line = "";
	/* mimic vim's behaviour when entering normal mode */
	__move_cursor_left ();
	for (;;) {
		int rep = 0;
		if (I.echo) {
			__print_prompt ();
		}
		if (I.vi_mode != CONTROL_MODE) {// exit if insert mode is selected
			__update_prompt_color ();
			break;
		}
		bool o_do_setup_match = I.history.do_setup_match;
		I.history.do_setup_match = true;
		ch = r_cons_readchar ();
		while (isdigit (ch)) {			// handle commands like 3b
			if (ch == '0' && rep == 0) {	// to handle the command 0
				break;
			}
			int tmp = ch - '0';
			rep = (rep * 10) + tmp;
			ch = r_cons_readchar ();
		}
		rep = rep > 0? rep: 1;

		switch (ch) {
		case 3:
			if (I.hud) {
				I.hud->activate = false;
				I.hud->current_entry_n = -1;
			}
			if (I.echo) {
				eprintf ("^C\n");
			}
			I.buffer.index = I.buffer.length = 0;
			*I.buffer.data = '\0';
			D.gcomp = false;
			return false;
		case 'C':
			delete_till_end ();
			I.buffer.index++;
			if (I.hud) {
				I.hud->vi = false;
			}
			I.vi_mode = INSERT_MODE;
			break;
		case 'D':
			delete_till_end ();
			break;
		case 'r':
			ch = r_cons_readchar ();
			I.buffer.data[I.buffer.index] = ch;
			break;
		case 'x':
			while (rep--) {
				__delete_current_char ();
			}
			break;
		case 'c':
			if (I.hud) {
				I.hud->vi = false;
			}
			I.vi_mode = INSERT_MODE;
		/* fall through */
		case 'd':
			vi_delete_commands (rep);
			break;
		case 'I':
			if (I.hud) {
				I.hud->vi = false;
			}
			I.vi_mode = INSERT_MODE;
		/* fall through */
		case '^':
		case '0':
			if (D.gcomp) {
				strcpy (I.buffer.data, gcomp_line);
				I.buffer.length = strlen (I.buffer.data);
				I.buffer.index = 0;
				D.gcomp = false;
			}
			I.buffer.index = 0;
			break;
		case 'A':
			if (D.gcomp) {
				strcpy (I.buffer.data, gcomp_line);
				I.buffer.index = strlen (I.buffer.data);
				I.buffer.length = I.buffer.index;
				D.gcomp = false;
			} else {
				I.buffer.index = I.buffer.length;
			}
			if (I.hud) {
				I.hud->vi = false;
			}
			I.vi_mode = INSERT_MODE;
			break;
		case '$':
			if (D.gcomp) {
				strcpy (I.buffer.data, gcomp_line);
				I.buffer.index = strlen (I.buffer.data);
				I.buffer.length = I.buffer.index;
				D.gcomp = false;
			} else {
				I.buffer.index = I.buffer.length - 1;
			}
			break;
		case 'p':
			while (rep--) {
				paste ();
			}
			break;
		case 'a':
			I.buffer.index = I.buffer.index < I.buffer.length
				? I.buffer.index + r_str_utf8_charsize (I.buffer.data + I.buffer.index)
				: I.buffer.length;
		/* fall through */
		case 'i':
			if (I.hud) {
				I.hud->vi = false;
			}
			I.vi_mode = INSERT_MODE;
			break;
		case 'h':
			while (rep--) {
				__move_cursor_left ();
			}
			break;
		case 'l':
			while (rep--) {
				__move_cursor_right ();
			}
			break;
		case 'E':
			while (rep--) {
				I.buffer.index = vi_end_word_motion (MAJOR_BREAK);
			}
			break;
		case 'e':
			while (rep--) {
				I.buffer.index = vi_end_word_motion (MINOR_BREAK);
			}
			break;
		case 'B':
			while (rep--) {
				I.buffer.index = vi_backward_word_motion (MAJOR_BREAK);
			}
			break;
		case 'b':
			while (rep--) {
				I.buffer.index = vi_backward_word_motion (MINOR_BREAK);
			}
			break;
		case 'W':
			while (rep--) {
				I.buffer.index = vi_next_word_motion (MAJOR_BREAK);
				if (I.buffer.index == I.buffer.length) {
					I.buffer.index--;
				}
			}
			break;
		case 'w':
			while (rep--) {
				I.buffer.index = vi_next_word_motion (MINOR_BREAK);
				if (I.buffer.index == I.buffer.length) {
					I.buffer.index--;
				}
			}
			break;
		case '~':
			while (rep--) {
				swap_case (I.buffer.index);
				__move_cursor_right ();
			}
			break;
		case 'f':
			ch = r_cons_readchar ();
			while (rep--) {
				I.buffer.index = vi_motion_seek_to_char (ch);
			}
			break;
		case 'F':
			ch = r_cons_readchar ();
			while (rep--) {
				I.buffer.index = vi_motion_seek_to_char_backward (ch);
			}
			break;
		case 't':
			ch = r_cons_readchar ();
			while (rep--) {
				I.buffer.index = vi_motion_seek_to_char (ch);
				if (I.buffer.index > 0) {
					I.buffer.index--;
				}
			}
			break;
		case 'T':
			ch = r_cons_readchar ();
			while (rep--) {
				I.buffer.index = vi_motion_seek_to_char_backward (ch);
				if (I.buffer.index < I.buffer.length - 1) {
					I.buffer.index++;
				}
			}
			break;
		case 13:
		/* fall through */
		case '\n':
			return true;
		default:					// escape key
			ch = tolower (r_cons_arrow_to_hjkl (ch));
			switch (ch) {
			case 'k':			// up
				I.history.do_setup_match = o_do_setup_match;
				r_line_hist_up ();
				break;
			case 'j':			// down
				I.history.do_setup_match = o_do_setup_match;
				r_line_hist_down ();
				break;
			case 'l':			// right
				__move_cursor_right ();
				break;
			case 'h':			// left
				__move_cursor_left ();
				break;
			}
			break;
		}
		if (I.hud) {
			return false;
		}
	}
	return false;
}

static void dietline_print_risprompt(const char *gcomp_line) {
	RCons *cons = r_cons_singleton ();
	if (cons->context->color_mode && *gcomp_line && I.buffer.length > 0) {
		printf ("\r (ri-search): ");
		const char *line = gcomp_line;
		while (line) {
			char *m = strstr (line, I.buffer.data);
			if (m) {
				fwrite (line, m - line, 1, stdout);
				printf (Color_INVERT);
				fwrite (m, I.buffer.length, 1, stdout);
				printf (Color_RESET);
				line = m + I.buffer.length;
			} else {
				printf ("%s", line);
				line = NULL;
			}
		}
		printf ("\r");
	} else {
		printf ("\r(ri-search (%s)): %s\r", I.buffer.data, gcomp_line);
	}
}

R_API const char *r_line_readline_cb(RLineReadCallback cb, void *user) {
	int rows;
	const char *gcomp_line = "";
	signed char buf[10];
#if USE_UTF8
	int utflen;
#endif
	int ch = 0, key, i = 0;	/* grep completion */
	char *tmp_ed_cmd, prev = 0;
	int prev_buflen = -1;
	RCons *cons = r_cons_singleton ();

	if (!I.hud || (I.hud && !I.hud->activate)) {
		I.buffer.index = I.buffer.length = 0;
		I.buffer.data[0] = '\0';
		if (I.hud) {
			I.hud->activate = true;
		}
	}
	int mouse_status = cons->mouse;
	if (I.hud && I.hud->vi) {
		__vi_mode ();
		goto _end;
	}
	if (I.contents) {
		memmove (I.buffer.data, I.contents,
			R_MIN (strlen (I.contents) + 1, R_LINE_BUFSIZE - 1));
		I.buffer.data[R_LINE_BUFSIZE - 1] = '\0';
		I.buffer.index = I.buffer.length = strlen (I.contents);
	}
	if (I.disable) {
		if (!fgets (I.buffer.data, R_LINE_BUFSIZE, stdin)) {
			return NULL;
		}
		return (*I.buffer.data)? I.buffer.data: "";
	}

	memset (&buf, 0, sizeof buf);
	r_cons_set_raw (1);

	if (I.echo) {
		__print_prompt ();
	}
	r_cons_break_push (NULL, NULL);
	r_cons_enable_mouse (I.hud);
	for (;;) {
		D.yank_flag = false;
		if (r_cons_is_breaked ()) {
			break;
		}
#if 0
		// detect truncation
		if (I.buffer.length > I.length) {
			I.buffer.data[0] = 0;
			I.buffer.length = 0;
			return NULL;
		}
#endif
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
		if (utflen < (I.demo? 0: 1)) {
			r_cons_break_pop ();
			return NULL;
		}
		buf[utflen] = 0;
		if (I.demo && utflen == 0) {
			// refresh
			__print_prompt ();
			D.count++;
			continue;
		}
#else
#if R2__WINDOWS__
		{
			int len = r_line_readchar_win ((ut8 *) buf, sizeof (buf));
			if (len < 1) {
				r_cons_break_pop ();
				return NULL;
			}
			buf[len] = 0;
		}
#else
		ch = r_cons_readchar ();
		if (ch == -1) {
			r_cons_break_pop ();
			return NULL;
		}
		buf[0] = ch;
#endif
#endif
		bool o_do_setup_match = I.history.do_setup_match;
		I.history.do_setup_match = true;
		if (I.echo && cons->context->color_mode) {
			r_cons_clear_line (0);
		}
		(void) r_cons_get_size (&rows);
		switch (*buf) {
		case 0:	// control-space
			/* ignore atm */
			break;
		case 1:	// ^A
			if (D.gcomp) {
				strcpy (I.buffer.data, gcomp_line);
				I.buffer.length = strlen (I.buffer.data);
				I.buffer.index = 0;
				D.gcomp = false;
			}
			I.buffer.index = 0;
			break;
		case 2:	// ^b // emacs left
			__move_cursor_left ();
			break;
		case 5:	// ^E
			if (D.gcomp) {
				strcpy (I.buffer.data, gcomp_line);
				I.buffer.index = strlen (I.buffer.data);
				I.buffer.length = I.buffer.index;
				D.gcomp = false;
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
			if (I.hud) {
				I.hud->activate = false;
				I.hud->current_entry_n = -1;
			}
			if (I.echo) {
				eprintf ("^C\n");
			}
			I.buffer.index = I.buffer.length = 0;
			*I.buffer.data = '\0';
			D.gcomp = false;
			goto _end;
		case 4:	// ^D
			if (!I.buffer.data[0]) {/* eof */
				if (I.echo) {
					eprintf ("^D\n");
				}
				r_cons_set_raw (false);
				r_cons_break_pop ();
				return NULL;
			}
			if (I.buffer.index < I.buffer.length) {
				__delete_current_char ();
			}
			break;
		case 11:// ^K
			I.buffer.data[I.buffer.index] = '\0';
			I.buffer.length = I.buffer.index;
			break;
		case 6:	// ^f // emacs right
			__move_cursor_right ();
			break;
		case 12:// ^L -- clear screen
			if (I.echo) {
				eprintf ("\x1b[2J\x1b[0;0H");
			}
			fflush (stdout);
			break;
		case 18:// ^R -- autocompletion
			if (D.gcomp) {
				D.gcomp_idx++;
			}
			D.gcomp = true;
			break;
		case 19:// ^S -- backspace
			if (D.gcomp) {
				D.gcomp--;
			} else {
				__move_cursor_left ();
			}
			break;
		case 21:// ^U - cut
			free (I.clipboard);
			I.clipboard = strdup (I.buffer.data);
			r_line_clipboard_push (I.clipboard);
			I.buffer.data[0] = '\0';
			I.buffer.length = 0;
			I.buffer.index = 0;
			break;
#if R2__WINDOWS__
		case 22:// ^V - Paste from windows clipboard
		{
			HANDLE hClipBoard;
			PTCHAR clipText;
			if (OpenClipboard (NULL)) {
#if UNICODE
				hClipBoard = GetClipboardData (CF_UNICODETEXT);
#else
				hClipBoard = GetClipboardData (CF_TEXT);
#endif
				if (hClipBoard) {
					clipText = GlobalLock (hClipBoard);
					if (clipText) {
						char *txt = r_sys_conv_win_to_utf8 (clipText);
						if (!txt) {
							R_LOG_ERROR ("Failed to allocate memory");
							break;
						}
						int len = strlen (txt);
						I.buffer.length += len;
						if (I.buffer.length < R_LINE_BUFSIZE) {
							I.buffer.index = I.buffer.length;
							strcat (I.buffer.data, txt);
						} else {
							I.buffer.length -= len;
						}
						free (txt);
					}
					GlobalUnlock (hClipBoard);
				}
				CloseClipboard ();
			}
		}
		break;
#endif
		case 23:// ^W ^w unix-word-rubout
			unix_word_rubout ();
			break;
		case 24:// ^X
			if (I.buffer.index > 0) {
				strncpy (I.buffer.data, I.buffer.data + I.buffer.index, I.buffer.length);
				I.buffer.length -= I.buffer.index;
				I.buffer.index = 0;
			}
			break;
		case 25:// ^Y - paste
			paste ();
			D.yank_flag = true;
			break;
		case 29: // ^^ - rotate kill ring
			rotate_kill_ring ();
			D.yank_flag = D.enable_yank_pop;
			break;
		case 20: // ^t Kill from point to the end of the current word,
			kill_word (MINOR_BREAK, 'w');
			break;
		case 15:// ^o kill backward
			backward_kill_word (MINOR_BREAK);
			break;
		case 14:// ^n
			if (I.hud) {
				if (I.hud->top_entry_n + 1 < I.hud->current_entry_n) {
					I.hud->top_entry_n++;
				}
			} else if (I.sel_widget) {
				selection_widget_down (1);
				selection_widget_draw ();
			} else if (D.gcomp) {
				if (D.gcomp_idx > 0) {
					D.gcomp_idx--;
				}
			} else {
				I.history.do_setup_match = o_do_setup_match;
				r_line_hist_down ();
			}
			break;
		case 16:// ^p
			if (I.hud) {
				if (I.hud->top_entry_n >= 0) {
					I.hud->top_entry_n--;
				}
			} else if (I.sel_widget) {
				selection_widget_up (1);
				selection_widget_draw ();
			} else if (D.gcomp) {
				D.gcomp_idx++;
			} else {
				I.history.do_setup_match = o_do_setup_match;
				r_line_hist_up ();
			}
			break;
		case 27:// esc-5b-41-00-00 alt/meta key
#if R2__WINDOWS__
			// always skip escape
			memmove (buf, buf + 1, strlen ((char *) buf));
#if 0
			if (I.vtmode != 2) {
				if (buf[1] == '[') {
					memmove (buf, buf + 2, strlen (buf));
				} else {
					memmove (buf, buf + 1, strlen (buf));
				}
				if (!buf[0]) {
					buf[0] = -1;
				}
			} else {
				buf[0] = r_cons_readchar_timeout (50);
			}
#endif
#else
			buf[0] = r_cons_readchar_timeout (50);
#endif
			switch (buf[0]) {
			case 127:	// alt+bkspace
				backward_kill_word (MINOR_BREAK);
				break;
			case -1:	// escape key, goto vi mode
				if (I.enable_vi_mode) {
					if (I.hud) {
						I.hud->vi = true;
					}
					if (__vi_mode ()) {
						goto _end;
					}
				}
				;
				if (I.sel_widget) {
					selection_widget_erase ();
				}
				break;
			case 1:	// begin
				I.buffer.index = 0;
				break;
			case 5:	// end
				I.buffer.index = I.buffer.length;
				break;
			case 'B':
			case 'b':
				for (i = I.buffer.index - 2; i >= 0; i--) {
					if (is_word_break_char (I.buffer.data[i], MINOR_BREAK)
					    && !is_word_break_char (I.buffer.data[i + 1], MINOR_BREAK)) {
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
				kill_word (MINOR_BREAK, 'w');
				break;
			case 'F':
			case 'f':
				// next word
				for (i = I.buffer.index + 1; i < I.buffer.length; i++) {
					if (!is_word_break_char (I.buffer.data[i], MINOR_BREAK)
					    && is_word_break_char (I.buffer.data[i - 1], MINOR_BREAK)) {
						I.buffer.index = i;
						break;
					}
				}
				if (i >= I.buffer.length) {
					I.buffer.index = I.buffer.length;
				}
				break;
			default:
#if !R2__WINDOWS__
				if (I.vtmode == 2) {
					buf[1] = r_cons_readchar_timeout (50);
					if (buf[1] == -1) {	// alt+e
						r_cons_break_pop ();
						__print_prompt ();
						continue;
					}
				} else {
					buf[1] = r_cons_readchar_timeout (50);
				}
#endif
				if (buf[0] == 'O' && strchr("ABCDFH", buf[1]) != NULL) { // O
					buf[0] = '[';
				}
				if (buf[0] == '[') { // [
					switch (buf[1]) {
					case '3':	// supr or mouse click
						__delete_current_char ();
						if (I.vtmode == 2) {
							buf[1] = r_cons_readchar ();
							if (buf[1] == 126) {
								// handle SUPR key
								r_cons_break_pop ();
								__print_prompt ();
								continue;
							}
							if (buf[1] == -1) {
								r_cons_break_pop ();
								return NULL;
							}
						}
						for (;;) {
							ch = r_cons_readchar ();
							if (ch < 20) {
								r_cons_break_pop ();
								return NULL;
							}
							if (isupper (ch)) {	// read until 'M'
								break;
							}
						}
						break;
					case '5':	// pag up
						if (I.vtmode == 2) {
							buf[1] = r_cons_readchar ();
						}
						if (I.hud) {
							I.hud->top_entry_n -= (rows - 1);
							if (I.hud->top_entry_n < 0) {
								I.hud->top_entry_n = 0;
							}
						}
						if (I.sel_widget) {
							selection_widget_up (R_MIN (I.sel_widget->h, R_SELWIDGET_MAXH));
							selection_widget_draw ();
						}
						break;
					case '6':	// pag down
						if (I.vtmode == 2) {
							buf[1] = r_cons_readchar ();
						}
						if (I.hud) {
							I.hud->top_entry_n += (rows - 1);
							if (I.hud->top_entry_n >= I.hud->current_entry_n) {
								I.hud->top_entry_n = I.hud->current_entry_n - 1;
							}
						}
						if (I.sel_widget) {
							selection_widget_down (R_MIN (I.sel_widget->h, R_SELWIDGET_MAXH));
							selection_widget_draw ();
						}
						break;
					case '9':	// handle mouse wheel
						key = r_cons_readchar ();
						cons->mouse_event = 1;
						if (key == '6') {	// up
							if (I.hud && I.hud->top_entry_n + 1 < I.hud->current_entry_n) {
								I.hud->top_entry_n--;
							}
						} else if (key == '7') {	// down
							if (I.hud && I.hud->top_entry_n >= 0) {
								I.hud->top_entry_n++;
							}
						}
						while (r_cons_readchar () != 'M') {}
						break;
					/* arrows */
					case 'A':	// up arrow
						if (I.hud) {
							if (I.hud->top_entry_n > 0) {
								I.hud->top_entry_n--;
							}
						} else if (I.sel_widget) {
							selection_widget_up (1);
							selection_widget_draw ();
						} else if (D.gcomp) {
							D.gcomp_idx++;
						} else {
							I.history.do_setup_match = o_do_setup_match;
							if (r_line_hist_up () == -1) {
								r_cons_break_pop ();
								return NULL;
							}
						}
						break;
					case 'B':	// down arrow
						if (I.hud) {
							if (I.hud->top_entry_n + 1 < I.hud->current_entry_n) {
								I.hud->top_entry_n++;
							}
						} else if (I.sel_widget) {
							selection_widget_down (1);
							selection_widget_draw ();
						} else if (D.gcomp) {
							if (D.gcomp_idx > 0) {
								D.gcomp_idx--;
							}
						} else {
							I.history.do_setup_match = o_do_setup_match;
							if (r_line_hist_down () == -1) {
								r_cons_break_pop ();
								return NULL;
							}
						}
						break;
					case 'C':	// right arrow
						__move_cursor_right ();
						break;
					case 'D':	// left arrow
						__move_cursor_left ();
						break;
					case 0x31:	// control + arrow
						if (I.vtmode == 2) {
							ch = r_cons_readchar ();
							if (ch == 0x7e) {	// HOME in screen/tmux
								// corresponding END is 0x34 below (the 0x7e is ignored there)
								I.buffer.index = 0;
								break;
							}
							r_cons_readchar ();	// should be '5'
							ch = r_cons_readchar ();
						}
#if R2__WINDOWS__
						else {
							ch = buf[2];
						}
#endif
						int fkey = ch - '0';
						switch (ch) {
						case 0x41:
							// first
							I.buffer.index = 0;
							break;
						case 0x44:
							// previous word
							i = I.buffer.index;
							do {
								i--;
							} while (i > 0 && I.buffer.data[i - 1] != ' ');
							I.buffer.index = i;
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
						default:
							if (I.vtmode == 2) {
								if (I.cb_fkey) {
									I.cb_fkey (I.user, fkey);
								}
							}
							break;
						}
						r_cons_set_raw (true);
						break;
					case 0x37:	// HOME xrvt-unicode
						r_cons_readchar ();
						break;
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
			if (I.hud && (I.buffer.index == 0)) {
				I.hud->activate = false;
				I.hud->current_entry_n = -1;
			}
			__delete_prev_char ();
			break;
		case 9:	// TAB tab
			if (I.buffer.length > 0 && I.buffer.data[I.buffer.length - 1] == '@') {
				strcpy (I.buffer.data + I.buffer.length, " ");
				I.buffer.length++;
				I.buffer.index++;
			}
			if (I.sel_widget) {
				selection_widget_down (1);
				I.sel_widget->complete_common = true;
				selection_widget_draw ();
			}
			if (I.hud) {
				if (I.hud->top_entry_n + 1 < I.hud->current_entry_n) {
					I.hud->top_entry_n++;
				} else {
					I.hud->top_entry_n = 0;
				}
			} else {
				r_line_autocomplete ();
			}
			break;
		case 10:// ^J
		case 13:// enter
			if (I.hud) {
				I.hud->activate = false;
				break;
			}
			if (I.sel_widget) {
				selection_widget_select ();
				break;
			}
			if (D.gcomp && I.buffer.length > 0) {
				strncpy (I.buffer.data, gcomp_line, R_LINE_BUFSIZE - 1);
				I.buffer.data[R_LINE_BUFSIZE - 1] = '\0';
				I.buffer.length = strlen (gcomp_line);
			}
			D.gcomp_idx = 0;
			D.gcomp = false;
			goto _end;
		default:
			if (D.gcomp) {
				D.gcomp++;
			}
			{
#if USE_UTF8
				int size = utflen;
#else
				int size = 1;
#endif
				if (I.buffer.length + size >= R_LINE_BUFSIZE) {
					break;
				}
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
				if ((I.buffer.length + utflen + 1) < sizeof (I.buffer.data)) {
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
			if (D.gcomp) {
				gcomp_line = "";
				int counter = 0;
				if (I.history.data) {
					for (i = I.history.size - 1; i >= 0; i--) {
						if (!I.history.data[i]) {
							continue;
						}
						if (strstr (I.history.data[i], I.buffer.data)) {
							gcomp_line = I.history.data[i];
							if (++counter > D.gcomp_idx) {
								break;
							}
						}
						if (i == 0) {
							D.gcomp_idx--;
						}
					}
				}
				dietline_print_risprompt (gcomp_line);
			} else {
				__print_prompt ();
			}
			fflush (stdout);
		}
		D.enable_yank_pop = D.yank_flag;
		if (I.hud) {
			goto _end;
		}
	}
_end:
	r_cons_break_pop ();
	r_cons_set_raw (false);
	r_cons_enable_mouse (mouse_status);
#if 0
	if (I.buffer.length > 1024) {	// R2_590 - use I.maxlength
		I.buffer.data[0] = 0;
		I.buffer.length = 0;
		R_LOG_WARN ("Input is too large");
		return I.buffer.data;
	}
#endif
	if (I.echo) {
		printf ("\r%s%s%s%s\n", I.prompt, promptcolor (), I.buffer.data, Color_RESET);
		fflush (stdout);
	}

	R_FREE (I.sel_widget);

	// shouldnt be here
	if (r_str_startswith (I.buffer.data, "!history")) {
		r_line_hist_list (true);
		return "";
	}
	return I.buffer.data[0] != '\0'? I.buffer.data: "";
}

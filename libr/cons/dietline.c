/* radare - LGPL - Copyright 2007-2025 - pancake */
/* dietline is a lightweight and portable library similar to GNU readline */

#include "r_util/r_str_util.h"
#include <r_cons.h>
#include <r_core.h>

#if R2__WINDOWS__
#include <windows.h>
#define printf(...) r_cons_win_printf(r_cons_singleton(), false, __VA_ARGS__)
#define USE_UTF8 1
static int r_line_readchar_win(RCons *cons, ut8 *s, int slen);
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
	int gcomp;
	int count;
	int gcomp_idx;
} Dietline;

static R_TH_LOCAL Dietline D = { 0 };

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

static bool drain_csi_sequence(RCons *cons) {
	R_RETURN_VAL_IF_FAIL (cons, false);
	int ch;
	for (;;) {
		ch = r_cons_readchar (cons);
		if (ch < 20) {
			return false;
		}
		// check if it's a CSI terminator character
		if (ch >= '@' && ch <= '~') {
			break;
		}
	}
	return true;
}

static inline void swap_case(RLine *line, int index) {
	if (isupper (line->buffer.data[index])) {
		line->buffer.data[index] += 32;
	} else if (islower (line->buffer.data[index])) {
		line->buffer.data[index] -= 32;
	}
}

static void backward_skip_major_word_break_chars(RLine *line, int *cursor) {
	while (*cursor >= 0 && is_word_break_char (line->buffer.data[*cursor], MAJOR_BREAK)) {
		(*cursor)--;
	}
}

static void skip_major_word_break_chars(RLine *line, int *cursor) {
	while (*cursor < line->buffer.length && is_word_break_char (line->buffer.data[*cursor], MAJOR_BREAK)) {
		(*cursor)++;
	}
}

static void goto_word_start(RLine *line, int *cursor, BreakMode break_mode) {
	if (!is_word_break_char (line->buffer.data[*cursor], break_mode)) {
		/* move cursor backwards to the next word-break char */
		while (*cursor >= 0 && !is_word_break_char (line->buffer.data[*cursor], break_mode)) {
			(*cursor)--;
		}
	} else if (is_word_break_char (line->buffer.data[*cursor], MINOR_BREAK)) {
		/* move cursor backwards to the next non-word-break char OR MAJOR break char */
		while (*cursor >= 0 && is_word_break_char (line->buffer.data[*cursor], MINOR_BREAK) && !is_word_break_char (line->buffer.data[*cursor], MAJOR_BREAK)) {
			(*cursor)--;
		}
	} else {
		/* move cursor backwards to the next MINOR word-break char OR non-word-break char */
		while (*cursor >= 0 && is_word_break_char (line->buffer.data[*cursor], MAJOR_BREAK)) {
			(*cursor)--;
		}
	}
	/* increment cursor to go to the start of current word */
	if (*cursor < line->buffer.length - 1) {
		(*cursor)++;
	}
}

static void goto_word_end(RLine *line, int *cursor, BreakMode break_mode) {
	if (!is_word_break_char (line->buffer.data[*cursor], break_mode)) {
		/* move cursor forward to the next word-break char */
		while (*cursor < line->buffer.length && !is_word_break_char (line->buffer.data[*cursor], break_mode)) {
			(*cursor)++;
		}
	} else if (is_word_break_char (line->buffer.data[*cursor], MINOR_BREAK)) {
		/* move cursor forward to the next non-word-break char or MAJOR break char */
		while (*cursor < line->buffer.length && is_word_break_char (line->buffer.data[*cursor], MINOR_BREAK) && !is_word_break_char (line->buffer.data[*cursor], MAJOR_BREAK)) {
			(*cursor)++;
		}
	}
	/* decrement cursor to go to the end of current word */
	if (*cursor > 0) {
		(*cursor)--;
	}
}

static void goto_next_word(RLine *line, int *cursor, BreakMode break_mode) {
	goto_word_end (line, cursor, break_mode);
	(*cursor)++;
	if (is_word_break_char (line->buffer.data[*cursor], MAJOR_BREAK)) {
		skip_major_word_break_chars (line, cursor);
	}
}

static int vi_end_word_motion(RLine *line, BreakMode break_mode) {
	if (line->buffer.index < line->buffer.length - 1) {
		int cursor = line->buffer.index;
		if (is_word_break_char (line->buffer.data[cursor], MAJOR_BREAK)) {
			skip_major_word_break_chars (line, &cursor);
			goto_word_end (line, &cursor, break_mode);
		} else {
			cursor++;
			skip_major_word_break_chars (line, &cursor);
			goto_word_end (line, &cursor, break_mode);
		}
		return cursor;
	}
	return line->buffer.index;
}

static int vi_backward_word_motion(RLine *line, BreakMode break_mode) {
	if (line->buffer.index > 0) {
		int cursor = line->buffer.index - 1;
		backward_skip_major_word_break_chars (line, &cursor);
		goto_word_start (line, &cursor, break_mode);
		return cursor;
	}
	return line->buffer.index;
}

static int vi_next_word_motion(RLine *line, BreakMode break_mode) {
	int cursor;
	if (line->buffer.index < line->buffer.length) {
		cursor = line->buffer.index;
		if (is_word_break_char (line->buffer.data[cursor], MAJOR_BREAK)) {
			skip_major_word_break_chars (line, &cursor);
		} else {
			goto_next_word (line, &cursor, break_mode);
		}
		return cursor;
	}
	return line->buffer.index;
}

static inline void __delete_current_char(RLine *line) {
	if (line->buffer.index < line->buffer.length) {
		int len = r_str_utf8_charsize (line->buffer.data + line->buffer.index);
		memmove (line->buffer.data + line->buffer.index,
			line->buffer.data + line->buffer.index + len,
			strlen (line->buffer.data + line->buffer.index + 1) + 1);
		line->buffer.length -= len;
		if (line->buffer.index > 0 && line->buffer.index == line->buffer.length) {
			line->buffer.index--;
		}
	}
}

static inline int indexof(RLine *line, int c, int offset) {
	char *ptr = strchr (line->buffer.data + offset, c);
	if (ptr != NULL) {
		return ptr - line->buffer.data;
	}
	return -1;
}

static inline int vi_motion_seek_to_char(RLine *line, int c) {
	if (line->buffer.index < line->buffer.length) {
		const int i = indexof (line, c, line->buffer.index + 1);
		if (i != -1) {
			return i;
		}
	}
	return line->buffer.index;
}

static inline int vi_motion_seek_to_char_backward(RLine *line, int c) {
	if (line->buffer.index > 0) {
		int i = line->buffer.index - 1;
		while (i >= 0) {
			if (line->buffer.data[i] == c) {
				return i;
			}
			i--;
		}
	}
	return line->buffer.index;
}

static inline void shift_buffer(RLine *line, int start, int end) {
	int len = end - start + 1;
	free (line->clipboard);
	line->clipboard = r_str_ndup (line->buffer.data + start, len);
	r_line_clipboard_push (line, line->clipboard);
	memmove (line->buffer.data + start, line->buffer.data + end, line->buffer.length - end + 1);
	/* resize buffer to take into account the word we deleted */
	line->buffer.length = strlen (line->buffer.data);
}

/* https://www.gnu.org/software/bash/manual/html_node/Commands-For-Killing.html */
static void backward_kill_word(RLine *line, BreakMode break_mode) {
	int i = vi_backward_word_motion (line, break_mode);
	if (i == line->buffer.index) {
		return;
	}
	shift_buffer (line, i, line->buffer.index);
	line->buffer.index = i;
}

static void kill_word(RLine *line, BreakMode break_mode, char motion) {
	int i = 0;
	if (line->buffer.index == line->buffer.length - 1) {
		__delete_current_char (line);
		return;
	}
	switch (motion) {
	case 'w':
		i = vi_next_word_motion (line, break_mode);
		break;
	case 'e':
		i = vi_end_word_motion (line, break_mode) + 1;
		break;
	}
	shift_buffer (line, line->buffer.index, i);
	if (line->buffer.index > 0 && line->buffer.index == line->buffer.length) {
		line->buffer.index--;
	}
}

/*
 * diw and diW commands
 * how it works:
 *   - go to the start of the current word (spaces are considered words here)
 *   - delete until the last character of the word
 *   - handle edge cases when the last character of the current word is the last character of the line
 */
static void delete_in_word(RLine *line, BreakMode break_mode) {
	int i;
	if (line->buffer.length > 0) {
		goto_word_start (line, &line->buffer.index, break_mode);
		i = line->buffer.index;
		if (!is_word_break_char (line->buffer.data[i], break_mode)) {
			while (i < line->buffer.length && !is_word_break_char (line->buffer.data[i], break_mode)) {
				i++;
			}
			if (i == line->buffer.length - 1 && !is_word_break_char (line->buffer.data[i], break_mode)) {
				i--;
			}
		} else if (is_word_break_char (line->buffer.data[i], MAJOR_BREAK)) {
			while (i < line->buffer.length && is_word_break_char (line->buffer.data[i], MAJOR_BREAK)) {
				i++;
			}
			if (i == line->buffer.length - 1 && is_word_break_char (line->buffer.data[i], MAJOR_BREAK)) {
				i--;
			}
		} else {
			while (i < line->buffer.length && is_word_break_char (line->buffer.data[i], MINOR_BREAK) && !is_word_break_char (line->buffer.data[i], MAJOR_BREAK)) {
				i++;
			}
			if (i == line->buffer.length - 1 && is_word_break_char (line->buffer.data[i], MINOR_BREAK) && !is_word_break_char (line->buffer.data[i], MAJOR_BREAK)) {
				i--;
			}
		}
		if (i == line->buffer.index) {
			__delete_current_char (line);
			return;
		}
		shift_buffer (line, line->buffer.index, i);
		if (line->buffer.index > 0 && line->buffer.index == line->buffer.length) {
			line->buffer.index--;
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
 *   - call indexof () to get the index of the closing char
 *   - shift (resize) the buffer
 * note: doesn't work well with nested chars like ((test))
 * would need a stack for that
 */
static inline int delete_between(RLine *line, int start, int end) {
	int i = vi_motion_seek_to_char_backward (line, start);
	if (i == line->buffer.index) {
		i = vi_motion_seek_to_char (line, start);
	}
	if (i != line->buffer.index) {
		int stop = indexof (line, end, i + 1);
		if (stop != -1) {
			shift_buffer (line, i + 1, stop);
			return i + 1;
		}
	}
	return -1;
}

static void paste(RLine *line) {
	if (line->clipboard) {
		char *cursor = line->buffer.data + line->buffer.index;
		int dist = (line->buffer.data + line->buffer.length) - cursor;
		int len = strlen (line->clipboard);
		line->buffer.length += len;
		memmove (cursor + len, cursor, dist);
		memcpy (cursor, line->clipboard, len);
		line->buffer.index += len;
		D.enable_yank_pop = true;
	}
}

static void unix_word_rubout(RCons *cons) {
	int i, len;
	RLine *line = cons->line;
	if (line->buffer.index > 0) {
		for (i = line->buffer.index - 1; i > 0 && line->buffer.data[i] == ' '; i--) {
			/* Move cursor backwards until we hit a non-space character or EOL */
			/* This removes any trailing spaces from the input */
		}
		for (; i > 0 && line->buffer.data[i] != ' '; i--) {
			/* Move cursor backwards until we hit a space character or EOL */
			/* This deletes everything back to the previous space character */
		}
		if (i > 0) {
			i++;
		} else if (i < 0) {
			i = 0;
		}
		if (line->buffer.index > line->buffer.length) {
			line->buffer.length = line->buffer.index;
		}
		len = line->buffer.index - i + 1;
		free (line->clipboard);
		line->clipboard = r_str_ndup (line->buffer.data + i, len);
		r_line_clipboard_push (line, line->clipboard);
		memmove (line->buffer.data + i,
			line->buffer.data + line->buffer.index,
			line->buffer.length - line->buffer.index + 1);
		line->buffer.length = strlen (line->buffer.data);
		line->buffer.index = i;
	}
}

static int inithist(RLine *line) {
	if (line->history.data) {
		int new_size = line->hist_size;
		if (new_size > 0 && line->history.size != new_size) {
			char **new_data = (char **)calloc (new_size, sizeof (char *));
			if (new_data) {
				int nb_copy_lines = R_MIN (line->history.top + 1, new_size);
				memcpy (new_data, line->history.data + (line->history.top + 1 - nb_copy_lines), sizeof (char *) * nb_copy_lines);
				int i;
				for (i = 0; i < line->history.top + 1 - nb_copy_lines; i++) {
					free (line->history.data[i]);
				}
				free (line->history.data);
				line->history.data = new_data;
				line->history.size = new_size;
				line->history.top = R_MIN (line->history.top, nb_copy_lines - 1);
				line->history.index = R_MIN (line->history.index, nb_copy_lines - 1);
			}
		}
		return true;
	}
	ZERO_FILL (line->history);
	line->history.size = line->hist_size;
	if (line->history.size <= 0) {
		return false;
	}
	line->history.data = (char **)calloc (line->history.size, sizeof (char *));
	if (!line->history.data) {
		return false;
	}
	return true;
}

/* initialize history stuff */
R_API bool r_line_dietline_init(RLine *line) {
	ZERO_FILL (line->completion);
	if (!inithist (line)) {
		return false;
	}
	line->echo = true;
	return true;
}

#if USE_UTF8
/* read utf8 char into 's', return the length in bytes */
static int readchar_utf8(RCons *cons, ut8 *s, int slen) {
#if R2__WINDOWS__
	return r_line_readchar_win (cons, s, slen);
#else
	// TODO: add support for w32
	ssize_t len, i;
	if (slen < 1) {
		return 0;
	}
	int ch = -1;
	if (cons->line->demo) {
		ch = r_cons_readchar_timeout (cons, 80);
	} else {
		ch = r_cons_readchar (cons);
	}
	if (ch == -1) {
		return cons->line->demo? 0: -1;
	}
	*s = ch;
	*s = r_cons_controlz (cons, *s);
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
		ch = r_cons_readchar (cons);
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
static int r_line_readchar_win(RCons *cons, ut8 *s, int slen) {
	INPUT_RECORD irInBuf = { 0 };
	BOOL ret;
	DWORD mode, out;
	char buf[5] = { 0 };
	void *bed;

	HANDLE h = GetStdHandle (STD_INPUT_HANDLE);
	DWORD new_mode = cons->vtmode == 2? ENABLE_VIRTUAL_TERMINAL_INPUT: 0;
	GetConsoleMode (h, &mode);
	SetConsoleMode (h, new_mode);
	if (cons->line->zerosep) {
		bed = r_cons_sleep_begin (cons);
		DWORD rsz = 0;
		BOOL ret = ReadFile (h, s, 1, &rsz, NULL);
		r_cons_sleep_end (cons, bed);
		SetConsoleMode (h, mode);
		if (!ret || rsz != 1) {
			return 0;
		}
		return 1;
	}
do_it_again:
	bed = r_cons_sleep_begin (cons);
	if (cons->term_xterm) {
		ret = ReadFile (h, buf, 1, &out, NULL);
	} else {
		ret = ReadConsoleInput (h, &irInBuf, 1, &out);
	}
	r_cons_sleep_end (cons, bed);
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
				char *tmp = r_sys_conv_win_to_utf8_l ((PTCHAR)&chbuf, 1);
				if (tmp) {
					r_str_ncpy (buf, tmp, sizeof (buf));
					free (tmp);
				}
			} else {
				int idx = 0;
				buf[idx++] = 27;
				buf[idx++] = '['; // Simulate escaping
				if (irInBuf.Event.KeyEvent.dwControlKeyState & 8) {
					buf[idx++] = '1'; // control key
				}
				switch (irInBuf.Event.KeyEvent.wVirtualKeyCode) {
				case VK_UP: buf[idx++] = 'A'; break;
				case VK_DOWN: buf[idx++] = 'B'; break;
				case VK_RIGHT: buf[idx++] = 'C'; break;
				case VK_LEFT: buf[idx++] = 'D'; break;
				case VK_PRIOR: buf[idx++] = '5'; break; // PAGE UP
				case VK_NEXT: buf[idx++] = '6'; break; // PAGE DOWN
				case VK_DELETE: buf[idx++] = '3'; break; // SUPR KEY
				case VK_HOME: buf[idx++] = 'H'; break; // HOME KEY
				case VK_END: buf[idx++] = 'F'; break; // END KEY
				default: buf[0] = 0; break;
				}
			}
		}
	}
	if (!buf[0]) {
		goto do_it_again;
	}
	r_str_ncpy ((char *)s, buf, slen);
	SetConsoleMode (h, mode);
	return strlen ((char *)s);
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
		return line->hist_up (line->cons, line->user);
	}
	if (!inithist (line)) {
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
		return line->hist_down (line->cons, line->user);
	}
	if (!line->history.data) {
		inithist (line);
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
R_API bool r_line_hist_add(RLine *line, const char *text) {
	if (R_STR_ISEMPTY (text)) {
		return false;
	}
	if (!line->history.data) {
		if (!inithist (line)) {
			return false;
		}
	}
	if (!line->history.data || line->history.size <= 0) {
		return false;
	}
	/* ignore dup */
	if (line->history.top > 0) {
		const char *data = line->history.data[line->history.top - 1];
		if (data && !strcmp (text, data)) {
			line->history.index = line->history.top;
			return false;
		}
	}
	if (line->history.top == line->history.size) {
		int i;
		free (line->history.data[0]);
		for (i = 0; i <= line->history.size - 2; i++) {
			line->history.data[i] = line->history.data[i + 1];
		}
		line->history.top--;
	}
	line->history.data[line->history.top++] = strdup (text);
	line->history.index = line->history.top;
	return true;
}

static int r_line_hist_up(RLine *line) {
	if (!line->cb_history_up) {
		r_line_set_hist_callback (line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	}
	return line->cb_history_up (line);
}

static int r_line_hist_down(RLine *line) {
	if (!line->cb_history_down) {
		r_line_set_hist_callback (line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	}
	return line->cb_history_down (line);
}

R_API void r_line_hist_set_size(RLine *line, int size) {
	line->hist_size = R_MIN (size, 65536);
}

R_API int r_line_hist_get_size(RLine *line) {
	return line->history.size;
}

R_API const char *r_line_hist_get(RLine *line, int n) {
	int i = 0;
	inithist (line);
	n--;
	if (line->history.data) {
		for (i = 0; i < line->history.size && line->history.data[i]; i++) {
			if (n == i) {
				return line->history.data[i];
			}
		}
	}
	return NULL;
}

R_API int r_line_hist_list(RLine *line, bool full) {
	int i = 0;
	inithist (line);
	if (line->history.data) {
		i = full? 0: line->history.load_index;
		for (; i < line->history.size && line->history.data[i]; i++) {
			char *pad = r_str_pad (NULL, 0, ' ', 32 - strlen (line->history.data[i]));
			r_cons_printf (line->cons, "%s %s # !%d\n", line->history.data[i], pad, i);
			free (pad);
		}
	}
	return i;
}

R_API void r_line_hist_free(RLine *line) {
	if (line->history.data) {
		size_t i;
		for (i = 0; i < line->history.size; i++) {
			R_FREE (line->history.data[i]);
		}
	}
	R_FREE (line->history.data);
	R_FREE (line->sdbshell_hist);
	line->history.index = 0;
}

/* load history from file. TODO: if file == NULL load from ~/.<prg>.history or so */
R_API bool r_line_hist_load(RLine *line, const char *file) {
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
			r_line_hist_add (line, buf);
		}
		memset (buf, 0, R_LINE_BUFSIZE);
	}
	line->history.load_index = line->history.index;
	fclose (fd);
	free (buf);
	return true;
}

R_API bool r_line_hist_save(RLine *line, const char *file) {
	R_RETURN_VAL_IF_FAIL (file && *file, false);
	// R_LOG_DEBUG ("SAVE %s", file);
	int i;
	bool ret = false;
	char *p = (char *)r_str_lastbut (file, R_SYS_DIR[0], NULL);
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
		if (line->history.data) {
			for (i = 0; i < line->history.index; i++) {
				fputs (line->history.data[i], fd);
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

static void selection_widget_draw(RCons *cons) {
	RLine *line = cons->line;
	RSelWidget *sel_widget = line->sel_widget;
	int y, pos_y, pos_x = r_str_ansi_len (line->prompt);
	sel_widget->h = R_MIN (sel_widget->h, R_SELWIDGET_MAXH);
	for (y = 0; y < sel_widget->options_len; y++) {
		sel_widget->w = R_MAX (sel_widget->w, strlen (sel_widget->options[y]));
	}
	if (sel_widget->direction == R_SELWIDGET_DIR_UP) {
		pos_y = cons->rows;
	} else {
		pos_y = r_cons_get_cur_line ();
		if (pos_y + sel_widget->h > cons->rows) {
			char *padstr = r_str_pad (NULL, 0, '\n', sel_widget->h);
			printf ("%s\n", padstr);
			free (padstr);
			pos_y = cons->rows - sel_widget->h - 1;
		}
	}
	sel_widget->w = R_MIN (sel_widget->w, R_SELWIDGET_MAXW);

	char *background_color = cons->context->color_mode? cons->context->pal.widget_bg: Color_INVERT_RESET;
	char *selected_color = cons->context->color_mode? cons->context->pal.widget_sel: Color_INVERT;
	bool scrollbar = sel_widget->options_len > R_SELWIDGET_MAXH;
	int scrollbar_y = 0, scrollbar_l = 0;
	if (scrollbar) {
		scrollbar_y = (R_SELWIDGET_MAXH *(sel_widget->selection - sel_widget->scroll)) / sel_widget->options_len;
		scrollbar_l = (R_SELWIDGET_MAXH * R_SELWIDGET_MAXH) / sel_widget->options_len;
	}

	for (y = 0; y < sel_widget->h; y++) {
		if (sel_widget->direction == R_SELWIDGET_DIR_UP) {
			r_cons_gotoxy (cons, pos_x + 1, pos_y - y - 1);
		} else {
			r_cons_gotoxy (cons, pos_x + 1, pos_y + y + 1);
		}
		int scroll = R_MAX (0, sel_widget->selection - sel_widget->scroll);
		const char *option = y < sel_widget->options_len? sel_widget->options[y + scroll]: "";
		r_cons_printf (cons, "%s", sel_widget->selection == y + scroll? selected_color: background_color);
		r_cons_printf (cons, "%-*.*s", sel_widget->w, sel_widget->w, option);
		if (scrollbar && R_BETWEEN (scrollbar_y, y, scrollbar_y + scrollbar_l)) {
			r_cons_write (cons, (const ut8 *)Color_INVERT " " Color_INVERT_RESET, 10);
		} else {
			r_cons_write (cons, (const ut8 *)" ", 1);
		}
	}

	r_cons_gotoxy (cons, pos_x + line->buffer.length, pos_y);
	r_cons_write (cons, (const ut8 *)Color_RESET_BG, 5);
	r_cons_flush (cons);
}

static void selection_widget_up(RLine *line, int steps) {
	RSelWidget *sel_widget = line->sel_widget;
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

static void selection_widget_down(RLine *line, int steps) {
	RSelWidget *sel_widget = line->sel_widget;
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
	RCore *core = (RCore *)_core;
	RCons *cons = core->cons;
	RLine *line = cons->line;
	r_cons_clear_line (cons, false, false);
	r_cons_printf (cons, "%s%s%s", Color_RESET, line->prompt, line->buffer.data);
	r_cons_flush (cons);
}

static void selection_widget_erase(RLine *line) {
	RSelWidget *sel_widget = line->sel_widget;
	if (sel_widget) {
		sel_widget->options_len = 0;
		sel_widget->selection = -1;
		RCons *cons = line->cons;
		selection_widget_draw (line->cons);
		R_FREE (line->sel_widget);
		if (cons->event_resize && cons->event_data) {
			cons->event_resize (cons->event_data);
			RCore *core = (RCore *) (cons->user);
			if (core) {
				print_rline_task (core);
			}
		}
		printf ("%s", R_CONS_CLEAR_FROM_CURSOR_TO_END);
	}
}

static void selection_widget_select(RLine *line) {
	RSelWidget *sel_widget = line->sel_widget;
	if (sel_widget && sel_widget->selection < sel_widget->options_len) {
		char *sp = strchr (line->buffer.data, ' ');
		if (sp) {
			int delta = sp - line->buffer.data + 1;
			line->buffer.length = R_MIN (delta + strlen (sel_widget->options[sel_widget->selection]), R_LINE_BUFSIZE - 1);
			memcpy (line->buffer.data + delta, sel_widget->options[sel_widget->selection], strlen (sel_widget->options[sel_widget->selection]));
			line->buffer.index = line->buffer.length;
			return;
		}
		line->buffer.length = R_MIN (strlen (sel_widget->options[sel_widget->selection]), R_LINE_BUFSIZE - 1);
		memcpy (line->buffer.data, sel_widget->options[sel_widget->selection], line->buffer.length);
		line->buffer.data[line->buffer.length] = '\0';
		line->buffer.index = line->buffer.length;
		selection_widget_erase (line);
	}
}

static void selection_widget_update(RLine *line) {
	int argc = (int)RVecCString_length (&line->completion.args);
	const char **argv = (const char **)R_VEC_START_ITER (&line->completion.args);
	if (argc == 0 || (argc == 1 && line->buffer.length >= strlen (argv[0]))) {
		selection_widget_erase (line);
		return;
	}
	if (!line->sel_widget) {
		RSelWidget *sel_widget = R_NEW0 (RSelWidget);
		line->sel_widget = sel_widget;
	}
	line->sel_widget->scroll = 0;
	line->sel_widget->selection = 0;
	line->sel_widget->options_len = argc;
	line->sel_widget->options = argv;
	line->sel_widget->h = R_MAX (line->sel_widget->h, line->sel_widget->options_len);

	if (line->prompt_type == R_LINE_PROMPT_DEFAULT) {
		line->sel_widget->direction = R_SELWIDGET_DIR_DOWN;
	} else {
		line->sel_widget->direction = R_SELWIDGET_DIR_UP;
	}
	selection_widget_draw (line->cons);
	r_cons_flush (line->cons);
	return;
}

R_API void r_line_autocomplete(RCons *cons) {
	char *p;
	const char **argv = NULL;
	int argc = 0, i, j, plen, len = 0;
	bool opt = false;
	int cols = (int) (r_cons_get_size (cons, NULL) * 0.82);

	RLine *line = cons->line;
	/* prepare argc and argv */
	if (line->completion.run) {
		line->completion.opt = false;
		line->completion.run (&line->completion, &line->buffer, line->prompt_type, line->completion.run_user);
		argc = (int)RVecCString_length (&line->completion.args);
		argv = (const char **)R_VEC_START_ITER (&line->completion.args);
		opt = line->completion.opt;
	}
	if (line->sel_widget && !line->sel_widget->complete_common) {
		selection_widget_update (line);
		return;
	}
	if (opt) {
		p = (char *)r_sub_str_lchr (line->buffer.data, 0, line->buffer.index, '=');
	} else {
		p = (char *)r_sub_str_lchr (line->buffer.data, 0, line->buffer.index, ' ');
	}
	if (!p) {
		p = (char *)r_sub_str_lchr (line->buffer.data, 0, line->buffer.index, '@'); // HACK FOR r2
	}
	if (p) {
		p++;
		plen = sizeof (line->buffer.data) - (int) (size_t) (p - line->buffer.data);
	} else {
		p = line->buffer.data; // XXX: removes current buffer
		plen = sizeof (line->buffer.data);
	}
	/* autocomplete */
	if (argc == 1) {
		const char *end_word = r_sub_str_rchr (line->buffer.data,
			line->buffer.index, strlen (line->buffer.data), ' ');
		const char *t = end_word? end_word: line->buffer.data + line->buffer.index;
		int largv0 = strlen (r_str_get (argv[0]));
		size_t len_t = strlen (t);
		p[largv0] = '\0';

		if ((p - line->buffer.data) + largv0 + 1 + len_t < plen) {
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
			line->buffer.length = strlen (line->buffer.data);
			line->buffer.index = line->buffer.length;
		}
	} else if (argc > 0) {
		if (*p) {
			// TODO: avoid overflow
			const char *t = line->buffer.data + line->buffer.index;
			const char *root = argv[0];
			int min_common_len = strlen (root);
			size_t len_t = strlen (t);

			// try to autocomplete argument
			for (i = 0; i < argc; i++) {
				j = 0;
				if (!argv[i]) {
					break;
				}
				while (argv[i][j] == root[j] && root[j] != '\0') {
					j++;
				}
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
			line->buffer.length = strlen (line->buffer.data);
			line->buffer.index = (p - line->buffer.data) + min_common_len;
		}
	}

	if (line->prompt_type != R_LINE_PROMPT_DEFAULT || cons->show_autocomplete_widget) {
		selection_widget_update (line);
		if (line->sel_widget) {
			line->sel_widget->complete_common = false;
		}
		return;
	}

	/* show options */
	if (argc > 1 && line->echo) {
		const int sep = 3;
		int slen, col = 10;
#ifdef R2__WINDOWS__
		r_cons_win_printf (false, "%s%s\n", line->prompt, line->buffer.data);
#else
		printf ("\r%s%s\n", line->prompt, line->buffer.data);
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

R_API const char *r_line_readline(RCons *cons) {
	return r_line_readline_cb (cons, NULL, NULL);
}

static inline void rotate_kill_ring(RCons *cons) {
	RLine *line = cons->line;
	if (D.enable_yank_pop) {
		line->buffer.index -= strlen (r_list_get_n (line->kill_ring, line->kill_ring_ptr));
		line->buffer.data[line->buffer.index] = 0;
		line->kill_ring_ptr -= 1;
		if (line->kill_ring_ptr < 0) {
			line->kill_ring_ptr = line->kill_ring->length - 1;
		}
		line->clipboard = r_list_get_n (line->kill_ring, line->kill_ring_ptr);
		paste (line);
	}
}

static inline void __delete_prev_char(RLine *line) {
	if (line->buffer.index < line->buffer.length) {
		if (line->buffer.index > 0) {
			size_t len = r_str_utf8_charsize_prev (line->buffer.data + line->buffer.index, line->buffer.index);
			line->buffer.index -= len;
			memmove (line->buffer.data + line->buffer.index,
				line->buffer.data + line->buffer.index + len,
				strlen (line->buffer.data + line->buffer.index));
			line->buffer.length -= len;
		}
	} else {
		line->buffer.length -= r_str_utf8_charsize_last (line->buffer.data);
		line->buffer.index = line->buffer.length;
		if (line->buffer.length < 0) {
			line->buffer.length = 0;
		}
	}
	line->buffer.data[line->buffer.length] = '\0';
	if (line->buffer.index < 0) {
		line->buffer.index = 0;
	}
}

static inline void delete_till_end(RLine *line) {
	line->buffer.data[line->buffer.index] = '\0';
	line->buffer.length = line->buffer.index;
	line->buffer.index = line->buffer.index > 0? line->buffer.index - 1: 0;
}

static const char *promptcolor(RCons *cons) {
	if (cons->line->demo) {
		return cons->context->pal.prompt;
	}
	return Color_RESET;
}

static void __print_prompt(RCons *cons) {
	R_RETURN_IF_FAIL (cons);
	RLine *line = cons->line;
	int columns = r_cons_get_size (cons, NULL) - 2;
	int len, i, cols = R_MAX (1, columns - r_str_ansi_len (line->prompt) - 2);
	if (cons->line->prompt_type == R_LINE_PROMPT_OFFSET) {
		r_cons_gotoxy (cons, 0, cons->rows);
	}
	r_cons_clear_line (cons, false, false);
	if (cons->context->color_mode > 0) {
		printf ("%s%s%s", Color_RESET, promptcolor (cons), line->prompt);
	} else {
		printf ("%s", line->prompt);
	}
	if (line->buffer.length > 0) {
		int maxlen = R_MIN (line->buffer.length, cols);
		if (maxlen > 0) {
			fwrite (line->buffer.data, maxlen, 1, stdout);
			if (line->buffer.length > cols) {
				fwrite (" >", 2, 1, stdout);
			}
		}
	}
	if (line->demo) {
		// 15% cpu usage, but yeah its fancy demoscene. may be good to optimize
		int pos = (D.count > 0)? D.count % strlen (line->prompt): 0;
		char *a = strdup (line->prompt);
		char *kb = (char *)r_str_ansi_chrn (a, pos);
		char *kc = (char *)r_str_ansi_chrn (kb, 3);
		char *b = r_str_ndup (kb, kc - kb);
		char *c = strdup (kc);
		char *rb = r_str_newf (Color_WHITE "%s%s", b, promptcolor (cons));
		*kb = 0;
		printf ("\r%s%s%s%s%s", promptcolor (cons), a, rb, c, Color_RESET);
		free (a);
		free (b);
		free (rb);
		free (c);
		D.count++;
		if (D.count > strlen (line->prompt)) {
			D.count = 0;
		}
	} else {
		printf ("\r%s%s%s", promptcolor (cons), line->prompt, promptcolor (cons));
	}
	if (line->buffer.index > cols) {
		printf ("< ");
		i = line->buffer.index - cols;
		if (i > sizeof (line->buffer.data)) {
			i = sizeof (line->buffer.data) - 1;
		}
	} else {
		i = 0;
	}
	len = line->buffer.index - i;
	if (len > 0 && (i + len) <= line->buffer.length && i < line->buffer.length) {
		size_t slen = R_MIN (len, (line->buffer.length - i));
		if (slen > 0 && i < sizeof (line->buffer.data)) {
			fwrite (line->buffer.data + i, 1, slen, stdout);
		}
	}
	fflush (stdout);
}

static inline void vi_delete_commands(RCons *cons, int rep) {
	int i;
	char t, e;
	RLine *line = cons->line;
	char c = r_cons_readchar (cons);
	while (rep--) {
		switch (c) {
		case 'i':
			t = r_cons_readchar (cons);
			switch (t) {
			case 'w':
				delete_in_word (line, MINOR_BREAK);
				break;
			case 'W':
				delete_in_word (line, MINOR_BREAK);
				break;
			case 'b':
				t = '(';
				e = ')';
				i = delete_between (line, t, e);
				if (i != -1) {
					line->buffer.index = i;
				}
				break;
			case '"':
				e = '"';
				i = delete_between (line, t, e);
				if (i != -1) {
					line->buffer.index = i;
				}
				break;
			case '\'':
				e = '\'';
				i = delete_between (line, t, e);
				if (i != -1) {
					line->buffer.index = i;
				}
				break;
			case '(':
				e = ')';
				i = delete_between (line, t, e);
				if (i != -1) {
					line->buffer.index = i;
				}
				break;
			case '[':
				e = ']';
				i = delete_between (line, t, e);
				if (i != -1) {
					line->buffer.index = i;
				}
				break;
			case '<':
				e = '>';
				i = delete_between (line, t, e);
				if (i != -1) {
					line->buffer.index = i;
				}
				break;
			case '{':
				e = '}';
				i = delete_between (line, t, e);
				if (i != -1) {
					line->buffer.index = i;
				}
				break;
			}
			if (line->hud) {
				line->hud->vi = false;
			}
			break;
		case 'f':
			t = r_cons_readchar (cons);
			i = vi_motion_seek_to_char (line, t);
			if (i != line->buffer.index) {
				shift_buffer (line, line->buffer.index, i + 1);
			}
			break;
		case 'F':
			t = r_cons_readchar (cons);
			i = vi_motion_seek_to_char_backward (line, t);
			if (i != line->buffer.index) {
				shift_buffer (line, i, line->buffer.index);
				line->buffer.index = i;
			}
			break;
		case 't':
			t = r_cons_readchar (cons);
			i = vi_motion_seek_to_char (line, t);
			if (i != line->buffer.index) {
				shift_buffer (line, line->buffer.index, i);
			}
			break;
		case 'T':
			t = r_cons_readchar (cons);
			i = vi_motion_seek_to_char_backward (line, t);
			if (i != line->buffer.index) {
				if (i < line->buffer.length) {
					i++;
				}
				shift_buffer (line, i, line->buffer.index);
				line->buffer.index = i;
			}
			break;
		case 'E':
			kill_word (line, MAJOR_BREAK, 'e');
			break;
		case 'e':
			kill_word (line, MINOR_BREAK, 'e');
			break;
		case 'W':
			kill_word (line, MAJOR_BREAK, 'w');
			break;
		case 'w':
			kill_word (line, MINOR_BREAK, 'w');
			break;
		case 'B':
			backward_kill_word (line, MAJOR_BREAK);
			break;
		case 'b':
			backward_kill_word (line, MINOR_BREAK);
			break;
		case 'h':
			__delete_prev_char (line);
			break;
		case 'l':
			__delete_current_char (line);
			break;
		case '$':
			delete_till_end (line);
			break;
		case '^':
		case '0':
			strncpy (line->buffer.data, line->buffer.data + line->buffer.index, line->buffer.length);
			line->buffer.length -= line->buffer.index;
			line->buffer.index = 0;
			break;
		case 'c':
		case 'd':
			line->buffer.index = 0;
			delete_till_end (line);
			break;
		}
		__print_prompt (cons);
	} // end of while (rep--)
}

static inline void __move_cursor_right(RLine *line) {
	line->buffer.index = line->buffer.index < line->buffer.length
		? line->buffer.index + r_str_utf8_charsize (line->buffer.data + line->buffer.index)
		: line->buffer.length;
}

static inline void __move_cursor_left(RLine *line) {
	line->buffer.index = line->buffer.index
		? line->buffer.index - r_str_utf8_charsize_prev (line->buffer.data + line->buffer.index, line->buffer.index)
		: 0;
}

static void __update_prompt_color(RCons *cons) {
	const char *BEGIN = "", *END = Color_RESET;
	RLine *line = cons->line;
	if (cons->context->color_mode) {
		if (line->prompt_mode) {
			switch (line->vi_mode) {
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
	char *prompt = r_str_escape (line->prompt); // remove the color
	free (line->prompt);
	line->prompt = r_str_newf ("%s%s%s", BEGIN, prompt, END);
}

static bool __vi_mode(RCons *cons) {
	char ch;
	RLine *line = cons->line;
	line->vi_mode = CONTROL_MODE;
	__update_prompt_color (cons);
	const char *gcomp_line = "";
	/* mimic vim's behaviour when entering normal mode */
	__move_cursor_left (line);
	for (;;) {
		int rep = 0;
		if (line->echo) {
			__print_prompt (cons);
		}
		if (line->vi_mode != CONTROL_MODE) { // exit if insert mode is selected
			__update_prompt_color (cons);
			break;
		}
		bool o_do_setup_match = line->history.do_setup_match;
		line->history.do_setup_match = true;
		ch = r_cons_readchar (cons);
		while (isdigit (ch)) { // handle commands like 3b
			if (ch == '0' && rep == 0) { // to handle the command 0
				break;
			}
			int tmp = ch - '0';
			rep = (rep * 10) + tmp;
			ch = r_cons_readchar (cons);
		}
		rep = rep > 0? rep: 1;

		switch (ch) {
		case 3:
			if (line->hud) {
				line->hud->activate = false;
				line->hud->current_entry_n = -1;
			}
			if (line->echo) {
				eprintf ("^C\n");
			}
			line->buffer.index = line->buffer.length = 0;
			*line->buffer.data = '\0';
			D.gcomp = 0;
			return false;
		case 'C':
			delete_till_end (line);
			line->buffer.index++;
			if (line->hud) {
				line->hud->vi = false;
			}
			line->vi_mode = INSERT_MODE;
			break;
		case 'D':
			delete_till_end (line);
			break;
		case 'r':
			ch = r_cons_readchar (cons);
			line->buffer.data[line->buffer.index] = ch;
			break;
		case 'x':
			while (rep--) {
				__delete_current_char (line);
			}
			break;
		case 'c':
			if (line->hud) {
				line->hud->vi = false;
			}
			line->vi_mode = INSERT_MODE;
		/* fall through */
		case 'd':
			vi_delete_commands (cons, rep);
			break;
		case 'I':
			if (line->hud) {
				line->hud->vi = false;
			}
			line->vi_mode = INSERT_MODE;
		/* fall through */
		case '^':
		case '0':
			if (D.gcomp > 0) {
				strcpy (line->buffer.data, gcomp_line);
				line->buffer.length = strlen (line->buffer.data);
				line->buffer.index = 0;
				D.gcomp = 0;
			}
			line->buffer.index = 0;
			break;
		case 'A':
			if (D.gcomp > 0) {
				strcpy (line->buffer.data, gcomp_line);
				line->buffer.index = strlen (line->buffer.data);
				line->buffer.length = line->buffer.index;
				D.gcomp = 0;
			} else {
				line->buffer.index = line->buffer.length;
			}
			if (line->hud) {
				line->hud->vi = false;
			}
			line->vi_mode = INSERT_MODE;
			break;
		case '$':
			if (D.gcomp > 0) {
				strcpy (line->buffer.data, gcomp_line);
				line->buffer.index = strlen (line->buffer.data);
				line->buffer.length = line->buffer.index;
				D.gcomp = 0;
			} else {
				line->buffer.index = line->buffer.length - 1;
			}
			break;
		case 'p':
			while (rep--) {
				paste (line);
			}
			break;
		case 'a':
			line->buffer.index = line->buffer.index < line->buffer.length
				? line->buffer.index + r_str_utf8_charsize (line->buffer.data + line->buffer.index)
				: line->buffer.length;
		/* fall through */
		case 'i':
			if (line->hud) {
				line->hud->vi = false;
			}
			line->vi_mode = INSERT_MODE;
			break;
		case 'h':
			while (rep--) {
				__move_cursor_left (line);
			}
			break;
		case 'l':
			while (rep--) {
				__move_cursor_right (line);
			}
			break;
		case 'E':
			while (rep--) {
				line->buffer.index = vi_end_word_motion (line, MAJOR_BREAK);
			}
			break;
		case 'e':
			while (rep--) {
				line->buffer.index = vi_end_word_motion (line, MINOR_BREAK);
			}
			break;
		case 'B':
			while (rep--) {
				line->buffer.index = vi_backward_word_motion (line, MAJOR_BREAK);
			}
			break;
		case 'b':
			while (rep--) {
				line->buffer.index = vi_backward_word_motion (line, MINOR_BREAK);
			}
			break;
		case 'W':
			while (rep--) {
				line->buffer.index = vi_next_word_motion (line, MAJOR_BREAK);
				if (line->buffer.index == line->buffer.length) {
					line->buffer.index--;
				}
			}
			break;
		case 'w':
			while (rep--) {
				line->buffer.index = vi_next_word_motion (line, MINOR_BREAK);
				if (line->buffer.index == line->buffer.length) {
					line->buffer.index--;
				}
			}
			break;
		case '~':
			while (rep--) {
				swap_case (line, line->buffer.index);
				__move_cursor_right (line);
			}
			break;
		case 'f':
			ch = r_cons_readchar (cons);
			while (rep--) {
				line->buffer.index = vi_motion_seek_to_char (line, ch);
			}
			break;
		case 'F':
			ch = r_cons_readchar (cons);
			while (rep--) {
				line->buffer.index = vi_motion_seek_to_char_backward (line, ch);
			}
			break;
		case 't':
			ch = r_cons_readchar (cons);
			while (rep--) {
				line->buffer.index = vi_motion_seek_to_char (line, ch);
				if (line->buffer.index > 0) {
					line->buffer.index--;
				}
			}
			break;
		case 'T':
			ch = r_cons_readchar (cons);
			while (rep--) {
				line->buffer.index = vi_motion_seek_to_char_backward (line, ch);
				if (line->buffer.index < line->buffer.length - 1) {
					line->buffer.index++;
				}
			}
			break;
		case 13:
		/* fall through */
		case '\n':
			return true;
		default: // escape key
			ch = tolower (r_cons_arrow_to_hjkl (cons, ch));
			switch (ch) {
			case 'k': // up
				line->history.do_setup_match = o_do_setup_match;
				r_line_hist_up (line);
				break;
			case 'j': // down
				line->history.do_setup_match = o_do_setup_match;
				r_line_hist_down (line);
				break;
			case 'l': // right
				__move_cursor_right (line);
				break;
			case 'h': // left
				__move_cursor_left (line);
				break;
			}
			break;
		}
		if (line->hud) {
			return false;
		}
	}
	return false;
}

static void dietline_print_risprompt(const char *gcomp_line) {
	RCons *cons = r_cons_singleton ();
	RLine *line = cons->line;
	if (cons->context->color_mode && *gcomp_line && line->buffer.length > 0) {
		printf ("\r (ri-search): ");
		const char *text = gcomp_line;
		while (text) {
			char *m = strstr (text, line->buffer.data);
			if (m) {
				fwrite (text, m - text, 1, stdout);
				printf (Color_INVERT);
				fwrite (m, line->buffer.length, 1, stdout);
				printf (Color_RESET);
				text = m + line->buffer.length;
			} else {
				printf ("%s", text);
				text = NULL;
			}
		}
		printf ("\r");
	} else {
		printf ("\r(ri-search (%s)): %s\r", line->buffer.data, gcomp_line);
	}
}

R_API const char *r_line_readline_cb(RCons *cons, RLineReadCallback cb, void *user) {
	RLine *line = cons->line;
	int rows;
	const char *gcomp_line = "";
	signed char buf[10];
#if USE_UTF8
	int utflen;
#endif
	int ch = 0, key, i = 0; /* grep completion */
	char *tmp_ed_cmd, prev = 0;
	int prev_buflen = -1;
	// RCons *cons = r_cons_singleton ();

	if (!line->hud || (line->hud && !line->hud->activate)) {
		line->buffer.index = line->buffer.length = 0;
		line->buffer.data[0] = '\0';
		if (line->hud) {
			line->hud->activate = true;
			line->hud->current_entry_n = 0;
		}
	}
	int mouse_status = cons->mouse;
	if (line->hud && line->hud->vi) {
		__vi_mode (cons);
		goto _end;
	}
	if (line->contents) {
		memmove (line->buffer.data, line->contents,
			R_MIN (strlen (line->contents) + 1, R_LINE_BUFSIZE - 1));
		line->buffer.data[R_LINE_BUFSIZE - 1] = '\0';
		line->buffer.index = line->buffer.length = strlen (line->contents);
	}
	if (line->disable) {
		if (!fgets (line->buffer.data, R_LINE_BUFSIZE, stdin)) {
			return NULL;
		}
		return (*line->buffer.data)? line->buffer.data: "";
	}

	memset (&buf, 0, sizeof buf);
	r_cons_set_raw (cons, 1);

	if (cons->line->echo) {
		__print_prompt (cons);
	}
	r_cons_break_push (cons, NULL, NULL);
	r_cons_enable_mouse (cons, cons->line->hud);
	for (;;) {
		D.yank_flag = false;
		if (r_cons_is_breaked (cons)) {
			break;
		}
#if 0
		// detect truncation
		if (line->buffer.length > line->length) {
			line->buffer.data[0] = 0;
			line->buffer.length = 0;
			return NULL;
		}
#endif
		line->buffer.data[line->buffer.length] = '\0';
		if (cb) {
			int cbret = cb (cons, user, line->buffer.data);
			if (cbret == 0) {
				line->buffer.data[0] = 0;
				line->buffer.length = 0;
			}
		}
#if USE_UTF8
		utflen = readchar_utf8 (cons, (ut8 *)buf, sizeof (buf));
		if (utflen < (line->demo? 0: 1)) {
			r_cons_break_pop (cons);
			return NULL;
		}
		buf[utflen] = 0;
		if (line->demo && utflen == 0) {
			// refresh
			__print_prompt (cons);
			D.count++;
			continue;
		}
#else
#if R2__WINDOWS__
		{
			int len = r_line_readchar_win (cons, (ut8 *)buf, sizeof (buf));
			if (len < 1) {
				r_cons_break_pop (cons);
				return NULL;
			}
			buf[len] = 0;
		}
#else
		ch = r_cons_readchar (cons);
		if (ch == -1) {
			r_cons_break_pop (cons);
			return NULL;
		}
		buf[0] = ch;
#endif
#endif
		bool o_do_setup_match = line->history.do_setup_match;
		line->history.do_setup_match = true;
		// Avoid clearing the whole line before redraw to prevent flicker.
	repeat:
		(void)r_cons_get_size (cons, &rows);
		switch (*buf) {
		case 0: // control-space
			/* ignore atm */
			break;
		case 1: // ^A
			if (D.gcomp > 0) {
				strcpy (line->buffer.data, gcomp_line);
				line->buffer.length = strlen (line->buffer.data);
				line->buffer.index = 0;
				D.gcomp = 0;
			}
			line->buffer.index = 0;
			break;
		case 2: // ^b // emacs left
			__move_cursor_left (line);
			break;
		case 5: // ^E
			if (D.gcomp > 0) {
				strcpy (line->buffer.data, gcomp_line);
				line->buffer.index = strlen (line->buffer.data);
				line->buffer.length = line->buffer.index;
				D.gcomp = 0;
			} else if (prev == 24) { // ^X = 0x18
				line->buffer.data[line->buffer.length] = 0; // probably unnecessary
				tmp_ed_cmd = line->cons->cb_editor (line->user, NULL, line->buffer.data);
				if (tmp_ed_cmd) {
					/* copied from yank (case 25) */
					line->buffer.length = strlen (tmp_ed_cmd);
					if (line->buffer.length < R_LINE_BUFSIZE) {
						line->buffer.index = line->buffer.length;
						strncpy (line->buffer.data, tmp_ed_cmd, R_LINE_BUFSIZE - 1);
						line->buffer.data[R_LINE_BUFSIZE - 1] = '\0';
					} else {
						line->buffer.length -= strlen (tmp_ed_cmd);
					}
					free (tmp_ed_cmd);
				}
			} else {
				line->buffer.index = line->buffer.length;
			}
			break;
		case 3: // ^C
			if (line->hud) {
				line->hud->activate = false;
				line->hud->current_entry_n = -1;
			}
			if (line->echo) {
				eprintf ("^C\n");
			}
			line->buffer.index = line->buffer.length = 0;
			*line->buffer.data = '\0';
			D.gcomp = 0;
			goto _end;
		case 4: // ^D
			if (!line->buffer.data[0]) { /* eof */
				if (line->echo) {
					eprintf ("^D\n");
				}
				r_cons_set_raw (cons, false);
				r_cons_break_pop (cons);
				return NULL;
			}
			if (line->buffer.index < line->buffer.length) {
				__delete_current_char (line);
			}
			break;
		case 11: // ^K
			line->buffer.data[line->buffer.index] = '\0';
			line->buffer.length = line->buffer.index;
			break;
		case 6: // ^f // emacs right
			__move_cursor_right (line);
			break;
		case 12: // ^L -- clear screen
			if (line->echo) {
				eprintf ("\x1b[2J\x1b[0;0H");
			}
			fflush (stdout);
			break;
		case 18: // ^R -- autocompletion
			if (D.gcomp > 0) {
				D.gcomp_idx++;
			}
			D.gcomp = 1;
			break;
		case 19: // ^S -- backspace
			if (D.gcomp > 0) {
				D.gcomp--;
			} else {
				__move_cursor_left (line);
			}
			break;
		case 21: // ^U - cut
			free (line->clipboard);
			line->clipboard = strdup (line->buffer.data);
			r_line_clipboard_push (line, line->clipboard);
			line->buffer.data[0] = '\0';
			line->buffer.length = 0;
			line->buffer.index = 0;
			break;
#if R2__WINDOWS__
		case 22: // ^V - Paste from windows clipboard
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
						line->buffer.length += len;
						if (line->buffer.length < R_LINE_BUFSIZE) {
							line->buffer.index = line->buffer.length;
							strcat (line->buffer.data, txt);
						} else {
							line->buffer.length -= len;
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
		case 23: // ^W ^w unix-word-rubout
			unix_word_rubout (cons);
			break;
		case 24: // ^X
			if (line->buffer.index > 0) {
				strncpy (line->buffer.data, line->buffer.data + line->buffer.index, line->buffer.length);
				line->buffer.length -= line->buffer.index;
				line->buffer.index = 0;
			}
			break;
		case 25: // ^Y - paste
			paste (line);
			D.yank_flag = true;
			break;
		case 29: // ^^ - rotate kill ring
			rotate_kill_ring (cons);
			D.yank_flag = D.enable_yank_pop;
			break;
		case 20: // ^t Kill from point to the end of the current word,
			kill_word (line, MINOR_BREAK, 'w');
			break;
		case 15: // ^o kill backward
			backward_kill_word (line, MINOR_BREAK);
			break;
		case 14: // ^n
			if (line->hud) {
				if (line->hud->top_entry_n + 1 < line->hud->current_entry_n) {
					line->hud->top_entry_n++;
				}
			} else if (line->sel_widget) {
				selection_widget_down (line, 1);
				selection_widget_draw (cons);
			} else if (D.gcomp > 0) {
				if (D.gcomp_idx > 0) {
					D.gcomp_idx--;
				}
			} else {
				line->history.do_setup_match = o_do_setup_match;
				r_line_hist_down (line);
			}
			break;
		case 16: // ^p
			if (line->hud) {
				if (line->hud->top_entry_n >= 0) {
					line->hud->top_entry_n--;
				}
			} else if (line->sel_widget) {
				selection_widget_up (line, 1);
				selection_widget_draw (cons);
			} else if (D.gcomp > 0) {
				D.gcomp_idx++;
			} else {
				line->history.do_setup_match = o_do_setup_match;
				r_line_hist_up (line);
			}
			break;
		case 27: // esc-5b-41-00-00 alt/meta key
#if R2__WINDOWS__
			// always skip escape
			memmove (buf, buf + 1, strlen ((char *)buf));
#else
			buf[0] = r_cons_readchar_timeout (cons, 50);
#endif
			switch (buf[0]) {
			case 127: // alt+bkspace
				backward_kill_word (line, MINOR_BREAK);
				break;
			case -1: // escape key, goto vi mode
				if (line->enable_vi_mode) {
					if (line->hud) {
						line->hud->vi = true;
					}
					if (__vi_mode (cons)) {
						goto _end;
					}
				};
				if (line->sel_widget) {
					selection_widget_erase (line);
				}
				break;
			case 1: // begin
				line->buffer.index = 0;
				break;
			case 5: // end
				line->buffer.index = line->buffer.length;
				break;
			case 'B':
			case 'b':
				for (i = line->buffer.index - 2; i >= 0; i--) {
					if (is_word_break_char (line->buffer.data[i], MINOR_BREAK) && !is_word_break_char (line->buffer.data[i + 1], MINOR_BREAK)) {
						line->buffer.index = i + 1;
						break;
					}
				}
				if (i < 0) {
					line->buffer.index = 0;
				}
				break;
			case 'D':
			case 'd':
				kill_word (line, MINOR_BREAK, 'w');
				break;
			case 'F':
			case 'f':
				// next word
				for (i = line->buffer.index + 1; i < line->buffer.length; i++) {
					if (!is_word_break_char (line->buffer.data[i], MINOR_BREAK) && is_word_break_char (line->buffer.data[i - 1], MINOR_BREAK)) {
						line->buffer.index = i;
						break;
					}
				}
				if (i >= line->buffer.length) {
					line->buffer.index = line->buffer.length;
				}
				break;
			default:;
#if R2__UNIX__
				if (line->vtmode == 2) {
					buf[1] = r_cons_readchar_timeout (cons, 50);
					if (buf[1] == -1) { // alt+e
						r_cons_break_pop (cons);
						__print_prompt (cons);
						continue;
					}
				} else {
					buf[1] = r_cons_readchar_timeout (cons, 50);
				}
#endif
				if (buf[0] == 'O' && strchr ("ABCDFH", buf[1]) != NULL) { // O
					buf[0] = '[';
				}
				if (buf[0] == 79) {
					// Function Keys
					if (line->cb_fkey) {
						ut8 kbuf = buf[1] & 0xff;
						switch (kbuf) {
						case 80:
						case 81:
						case 82:
						case 83:
						case 84:
							{
								int fkey = kbuf - 80 + 1;
							if (fkey > 0 && fkey < 13) {
									line->cb_fkey (line->user, fkey);
								}
							}
							break;
						}
					}
				} else if (buf[0] == '[') { // [
					int fkey = 0;
					switch (buf[1]) {
					case '2': // termfix
						while (true) {
							ch = r_cons_readchar (cons);
							if (fkey == 0) {
								// F9, F10 ,..
								if (ch >= '0' && ch < '8') {
									fkey = ch - '0' + 9;
									if (fkey > 11) {
										fkey--;
									}
								}
							}
							if (!isdigit (ch) && ch != ';') {
								*buf = '\n';
								// if we get fkey15 here its actually control+return
								if (fkey > 0 && fkey < 13) {
									if (line->cb_fkey) {
										line->cb_fkey (line->user, fkey);
									}
								}
								goto repeat;
								break;
							}
						}
						break;
					case '3': // supr or mouse click
						// printf "\x1b\x5b\x33\x3b\x35\x7e\n" \x1b[3;5~
						// Insert=2~, Delete=3~, Home=1~, End=4~, PageUp=5~, PageDown=6~…).
						// Modifier: 2=Shift, 3=Alt, 5=Ctrl, 6=Shift+Ctrl
						// VTMode: 0=UNIX, 1=Windows, 2=Visual???
						__delete_current_char (line);
						if (line->vtmode == 0) {
							if (!drain_csi_sequence (cons)) {
								r_cons_break_pop (cons);
								return NULL;
							}
						} else if (line->vtmode == 2) {
							key = r_cons_readchar (cons);
							if (key == 126) {
								// handle SUPR key
								r_cons_break_pop (cons);
								__print_prompt (cons);
								continue;
							}
							if (key == -1) {
								r_cons_break_pop (cons);
								return NULL;
							}
							if (!drain_csi_sequence (cons)) {
								r_cons_break_pop (cons);
								return NULL;
							}
						}
						break;
					case '5': // pag up
						if (line->vtmode == 2) {
							buf[1] = r_cons_readchar (cons);
						}
						if (line->hud) {
							line->hud->top_entry_n -= (rows - 1);
							if (line->hud->top_entry_n < 0) {
								line->hud->top_entry_n = 0;
							}
						}
						if (line->sel_widget) {
							selection_widget_up (line, R_MIN (line->sel_widget->h, R_SELWIDGET_MAXH));
							selection_widget_draw (cons);
						}
						break;
					case '6': // pag down
						if (line->vtmode == 2) {
							buf[1] = r_cons_readchar (cons);
						}
						if (line->hud) {
							line->hud->top_entry_n += (rows - 1);
							if (line->hud->top_entry_n >= line->hud->current_entry_n) {
								line->hud->top_entry_n = line->hud->current_entry_n - 1;
							}
						}
						if (line->sel_widget) {
							selection_widget_down (line, R_MIN (line->sel_widget->h, R_SELWIDGET_MAXH));
							selection_widget_draw (cons);
						}
						break;
					case '9': // handle mouse wheel
						key = r_cons_readchar (cons);
						cons->mouse_event = 1;
						if (key == '6') { // up
							if (line->hud && line->hud->top_entry_n + 1 < line->hud->current_entry_n) {
								line->hud->top_entry_n--;
							}
						} else if (key == '7') { // down
							if (line->hud && line->hud->top_entry_n >= 0) {
								line->hud->top_entry_n++;
							}
						}
						drain_csi_sequence (cons);
						break;
					/* arrows */
					case 'A': // up arrow
						if (line->hud) {
							if (line->hud->current_entry_n > 0) {
								line->hud->current_entry_n--;
							}
						} else if (line->sel_widget) {
							selection_widget_up (line, 1);
							selection_widget_draw (cons);
						} else if (D.gcomp > 0) {
							D.gcomp_idx++;
						} else {
							line->history.do_setup_match = o_do_setup_match;
							if (r_line_hist_up (line) == -1) {
								r_cons_break_pop (line->cons);
								return NULL;
							}
						}
						break;
					case 'B': // down arrow
						if (line->hud) {
							line->hud->current_entry_n++;
						} else if (line->sel_widget) {
							selection_widget_down (line, 1);
							selection_widget_draw (cons);
						} else if (D.gcomp > 0) {
							if (D.gcomp_idx > 0) {
								D.gcomp_idx--;
							}
						} else {
							line->history.do_setup_match = o_do_setup_match;
							if (r_line_hist_down (line) == -1) {
								r_cons_break_pop (line->cons);
								return NULL;
							}
						}
						break;
					case 'C': // right arrow
						__move_cursor_right (line);
						break;
					case 'D': // left arrow
						__move_cursor_left (line);
						break;
						break;
					case '1': // 0x31 - control + arrow + home key
						if (line->vtmode == 2) {
							ch = r_cons_readchar (cons);
							if (ch == 0x7e) { // HOME in screen/tmux
								// corresponding END is 0x34 below (the 0x7e is ignored there)
								line->buffer.index = 0;
								break;
							}
							switch (ch) {
							case '5':
								fkey = ch - '0';
								break;
							case '6':
							case '7':
							case '8':
							case '9':

								fkey = ch - '0' - 1;
								break;
							default:
								R_LOG_ERROR ("Unknown fkey %d pressed", fkey);
								break;
							}
							ch = r_cons_readchar (cons); // should be '5'
							// ch = r_cons_readchar (cons);
						}
#if R2__WINDOWS__
						else {
							ch = buf[2];
							fkey = ch - '0';
						}
#endif
						switch (ch) {
						case 0x41:
							// first
							line->buffer.index = 0;
							break;
						case 0x44:
							// previous word
							i = line->buffer.index;
							do {
								i--;
							} while (i > 0 && line->buffer.data[i - 1] != ' ');
							line->buffer.index = i;
							break;
						case 0x42:
							// end
							line->buffer.index = line->buffer.length;
							break;
						case 0x43:
							// next word
							for (i = line->buffer.index; i < line->buffer.length; i++) {
								if (line->buffer.data[i] == ' ') {
									line->buffer.index = i + 1;
									break;
								}
							}
							if (line->buffer.data[i] != ' ') {
								line->buffer.index = line->buffer.length;
							}
							break;
						default:
							if (line->vtmode == 2) {
								if (line->cb_fkey) {
									line->cb_fkey (line->user, fkey);
								}
							}
							break;
						}
						r_cons_set_raw (cons, true);
						break;
					case 0x37: // HOME xrvt-unicode
						r_cons_readchar (cons);
						break;
					case 0x48: // HOME
						if (line->sel_widget) {
							selection_widget_up (line, line->sel_widget->options_len - 1);
							selection_widget_draw (cons);
							break;
						}
						line->buffer.index = 0;
						break;
					case '4': // END
					case '8': // END xrvt-unicode
						r_cons_readchar (cons);
					case 0x46: // END
						if (line->sel_widget) {
							selection_widget_down (line, line->sel_widget->options_len - 1);
							selection_widget_draw (cons);
							break;
						}
						line->buffer.index = line->buffer.length;
						break;
					}
				}
			}
			break;
		case 8:
		case 127:
			if (line->hud && (line->buffer.index == 0)) {
				line->hud->activate = false;
				line->hud->current_entry_n = -1;
			}
			__delete_prev_char (line);
			break;
		case 9: // TAB tab
			if (line->buffer.length > 0 && line->buffer.data[line->buffer.length - 1] == '@') {
				strcpy (line->buffer.data + line->buffer.length, " ");
				line->buffer.length++;
				line->buffer.index++;
			}
			if (line->sel_widget) {
				selection_widget_down (line, 1);
				line->sel_widget->complete_common = true;
				selection_widget_draw (cons);
			}
			if (line->hud) {
				if (line->hud->top_entry_n + 1 < line->hud->current_entry_n) {
					line->hud->top_entry_n++;
				} else {
					line->hud->top_entry_n = 0;
				}
			} else {
				r_line_autocomplete (cons);
			}
			break;
		case 10: // ^J
		case 13: // enter
			if (line->hud) {
				line->hud->activate = false;
				break;
			}
			if (line->sel_widget) {
				selection_widget_select (line);
				break;
			}
			if (D.gcomp > 0 && line->buffer.length > 0) {
				strncpy (line->buffer.data, gcomp_line, R_LINE_BUFSIZE - 1);
				line->buffer.data[R_LINE_BUFSIZE - 1] = '\0';
				line->buffer.length = strlen (gcomp_line);
			}
			D.gcomp_idx = 0;
			D.gcomp = 0;
			goto _end;
		default:
			if (D.gcomp > 0) {
				D.gcomp++;
			}
			{
#if USE_UTF8
				int size = utflen;
#else
				int size = 1;
#endif
				if (line->buffer.length + size >= R_LINE_BUFSIZE) {
					break;
				}
			}
			if (line->buffer.index < line->buffer.length) {
#if USE_UTF8
				if ((line->buffer.length + utflen) < sizeof (line->buffer.data)) {
					line->buffer.length += utflen;
					for (i = line->buffer.length; i > line->buffer.index; i--) {
						line->buffer.data[i] = line->buffer.data[i - utflen];
					}
					memcpy (line->buffer.data + line->buffer.index, buf, utflen);
				}
#else
				for (i = ++line->buffer.length; i > line->buffer.index; i--) {
					line->buffer.data[i] = line->buffer.data[i - 1];
				}
				line->buffer.data[line->buffer.index] = buf[0];
#endif
			} else {
#if USE_UTF8
				if ((line->buffer.length + utflen + 1) < sizeof (line->buffer.data)) {
					memcpy (line->buffer.data + line->buffer.length, buf, utflen);
					line->buffer.length += utflen;
				}
				line->buffer.data[line->buffer.length] = '\0';
#else
				line->buffer.data[line->buffer.length] = buf[0];
				line->buffer.length++;
				if (line->buffer.length > (R_LINE_BUFSIZE - 1)) {
					line->buffer.length--;
				}
				line->buffer.data[line->buffer.length] = '\0';
#endif
			}
#if USE_UTF8
			if ((line->buffer.index + utflen) <= line->buffer.length) {
				line->buffer.index += utflen;
			}
#else
			if (line->buffer.index < line->buffer.length) {
				line->buffer.index++;
			}
#endif
			break;
		}
		if (line->sel_widget && line->buffer.length != prev_buflen) {
			prev_buflen = line->buffer.length;
			r_line_autocomplete (cons);
		}
		prev = buf[0];
		if (line->echo) {
			if (D.gcomp > 0) {
				gcomp_line = "";
				int counter = 0;
				if (line->history.data) {
					for (i = line->history.size - 1; i >= 0; i--) {
						if (!line->history.data[i]) {
							continue;
						}
						if (strstr (line->history.data[i], line->buffer.data)) {
							gcomp_line = line->history.data[i];
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
				__print_prompt (cons);
			}
			fflush (stdout);
		}
		D.enable_yank_pop = D.yank_flag;
		if (line->hud) {
			goto _end;
		}
	}
_end:
	r_cons_break_pop (cons);
	r_cons_set_raw (cons, false);
	r_cons_enable_mouse (cons, mouse_status);
#if 0
	if (line->buffer.length > 1024) {	// R2_590 - use line->maxlength
		line->buffer.data[0] = 0;
		line->buffer.length = 0;
		R_LOG_WARN ("Input is too large");
		return line->buffer.data;
	}
#endif
	if (line->echo) {
		printf ("\r%s%s%s%s\n", line->prompt, promptcolor (cons), line->buffer.data, Color_RESET);
		fflush (stdout);
	}

	R_FREE (line->sel_widget);

	// shouldnt be here
	if (r_str_startswith (line->buffer.data, "!history")) {
		r_line_hist_list (line, true);
		return "";
	}
	return line->buffer.data[0] != '\0'? line->buffer.data: "";
}

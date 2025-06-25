/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_cons.h>
#include <r_th.h>
#include <r_util/r_assert.h>
#define I r_cons_singleton ()

// TODO: drop the `r_cons` prefix from all these functions

#if R2__WINDOWS__

static void __fill_tail(int cols, int lines) {
	lines++;
	if (lines > 0) {
		char white[1024];
		cols = R_MIN (cols, sizeof (white));
		memset (white, ' ', cols - 1);
		lines--;
		white[cols] = '\n';
		while (lines-- > 0) {
			write (1, white, cols);
		}
	}
}

R_IPI void r_cons_win_clear(RCons *cons) {
	COORD startCoords;
	DWORD dummy;
	if (cons->vtmode) {
		r_kons_print (cons, Color_RESET R_CONS_CLEAR_SCREEN);
		return;
	}
	if (cons->is_wine == 1) {
		write (1, "\033[0;0H\033[0m\033[2J", 6 + 4 + 4);
	}
	if (!cons->hStdout) {
		cons->hStdout = GetStdHandle (STD_OUTPUT_HANDLE);
	}
	GetConsoleScreenBufferInfo (cons->hStdout, &cons->csbi);
	startCoords = (COORD) {
		cons->csbi.srWindow.Left,
		cons->csbi.srWindow.Top
	};
	DWORD nLength = cons->csbi.dwSize.X * (cons->csbi.srWindow.Bottom - cons->csbi.srWindow.Top + 1);
	FillConsoleOutputCharacter (cons->hStdout, ' ', nLength, startCoords, &dummy);
	FillConsoleOutputAttribute (cons->hStdout,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
		nLength, startCoords, &dummy);
}

R_IPI void r_cons_win_gotoxy(RCons *cons, int fd, int x, int y) {
	HANDLE *hConsole = (fd == 1)? &cons->hStdout : &cons->hStderr;
	COORD coord = { .X = x, .Y = y };
	if (cons->vtmode) {
		r_kons_printf (cons, "\x1b[%d;%dH", y, x);
		return;
	}
	if (cons->is_wine == 1) {
		write (fd, "\x1b[0;0H", 6);
	}
	if (!*hConsole) {
		*hConsole = GetStdHandle ((fd == 1)?
			STD_OUTPUT_HANDLE: STD_ERROR_HANDLE);
	}
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo (*hConsole, &info);
	coord.X += info.srWindow.Left;
	coord.Y += info.srWindow.Top;
	SetConsoleCursorPosition (*hConsole, coord);
}

static int wrapline(const char *s, int len) {
	int l = 0, n = 0;
	for (; n < len; ) {
		l = r_str_len_utf8char (s+n, (len-n));
		n += l;
	}
	return n - ((n > len) ? l : 1);
}

// Dupe from canvas.c
static int utf8len_fixed(const char *s, int n) {
	int i = 0, j = 0, fullwidths = 0;
	while (s[i] && n > 0) {
		if ((s[i] & 0xc0) != 0x80) {
			j++;
			if (r_str_char_fullwidth (s + i, n)) {
				fullwidths++;
			}
		}
		n--;
		i++;
	}
	return j + fullwidths;
}

static int bytes_utf8len(const char *s, int n) {
	int ret = 0;
	while (n > 0) {
		int sz = r_str_utf8_charsize (s);
		ret += sz;
		s += sz;
		n--;
	}
	return ret;
}

static int win_hprint(RCons *cons, DWORD hdl, const char *ptr, int len, bool vmode) {
	HANDLE hConsole = GetStdHandle (hdl);
	int fd = (hdl == STD_OUTPUT_HANDLE) ? 1 : 2;
	int esc = 0;
	int bg = 0, fg = 1|2|4|8;
	const char *ptr_end, *str = ptr;
	int ret = 0;
	int inv = 0;
	int linelen = 0;
	int ll = 0;
	int raw_ll = 0;
	int lines, cols = r_cons_get_size (cons, &lines);
	if (I->is_wine == -1) {
		I->is_wine = r_file_is_directory ("/proc")? 1: 0;
	}
	if (len < 0) {
		len = strlen ((const char *)ptr);
	}
	ptr_end = ptr + len;
	if (ptr && hConsole)
	for (; *ptr && ptr < ptr_end; ptr++) {
		if (ptr[0] == 0xa) {
			raw_ll = (size_t)(ptr - str);
			ll = utf8len_fixed (str, raw_ll);
			lines--;
			if (vmode && lines < 1) {
				break;
			}
			if (raw_ll < 1) {
				continue;
			}
			if (vmode) {
				/* only chop columns if necessary */
				if (ll + linelen >= cols) {
					// chop line if too long
					ll = (cols - linelen) - 1;
					if (ll < 0) {
						continue;
					}
				}
			}
			if (ll > 0) {
				raw_ll = bytes_utf8len (str, ll);
				write (fd, str, raw_ll);
				linelen += ll;
			}
			esc = 0;
			str = ptr + 1;
			if (vmode) {
				int wlen = cols - linelen;
				char white[1024];
				if (wlen > 0 && wlen < sizeof (white)) {
					memset (white, ' ', sizeof (white));
					write (fd, white, wlen-1);
				}
			}
			write (fd, "\n\r", 2);
			// reset colors for next line
			SetConsoleTextAttribute (hConsole, 1 | 2 | 4 | 8);
			linelen = 0;
			continue;
		}
		if (ptr[0] == 0x1b) {
			raw_ll = (size_t)(ptr - str);
			ll = utf8len_fixed (str, raw_ll);
			if (str[0] == '\n') {
				str++;
				ll--;
				if (vmode) {
					int wlen = cols - linelen - 1;
					char white[1024];
					//wlen = 5;
					if (wlen > 0) {
						memset (white, ' ', sizeof (white));
						write (fd, white, wlen);
					}
				}
				write (fd, "\n\r", 2);
				//write (fd, "\r\n", 2);
				//lines--;
				linelen = 0;
			}
			if (vmode) {
				if (linelen + ll >= cols) {
					// chop line if too long
					ll = (cols - linelen) - 1;
					if (ll > 0) {
						// fix utf8 len here
						ll = wrapline ((const char*)str, cols - linelen - 1);
					}
				}
			}
			if (ll > 0) {
				raw_ll = bytes_utf8len (str, ll);
				write (fd, str, raw_ll);
				linelen += ll;
			}
			esc = 1;
			str = ptr + 1;
			continue;
		}
		if (esc == 1) {
			// \x1b[2J
			if (ptr[0] != '[') {
				R_LOG_ERROR ("Oops invalid escape char");
				esc = 0;
				str = ptr + 1;
				continue;
			}
			esc = 2;
			continue;
		} else if (esc == 2) {
			const char *ptr2 = NULL;
			int x, y, i, state = 0;
			for (i = 0; ptr[i] && state >= 0; i++) {
				switch (state) {
				case 0:
					if (ptr[i] == ';') {
						y = atoi ((const char *)ptr);
						state = 1;
						ptr2 = (const char *)ptr+i+1;
					} else if (ptr[i] >='0' && ptr[i]<='9') {
						// ok
					} else {
						state = -1; // END FAIL
					}
					break;
				case 1:
					if (ptr[i] == 'H') {
						x = atoi (ptr2);
						state = -2; // END OK
					} else if (ptr[i] >='0' && ptr[i]<='9') {
						// ok
					} else {
						state = -1; // END FAIL
					}
					break;
				}
			}
			if (state == -2) {
				r_cons_win_gotoxy (cons, fd, x, y);
				ptr += i;
				str = ptr; // + i-2;
				continue;
			}
			bool bright = false;
			if (ptr[0] == '0' && ptr[1] == ';' && ptr[2] == '0') {
				// \x1b[0;0H
				/** clear screen if gotoxy **/
				if (vmode) {
					// fill row here
					__fill_tail (cols, lines);
				}
				r_cons_win_gotoxy (cons, fd, 0, 0);
				lines = 0;
				esc = 0;
				ptr += 3;
				str = ptr + 1;
				continue;
			} else if (ptr[0] == '2' && ptr[1] == 'J') {
				r_cons_win_clear (cons);
				esc = 0;
				ptr = ptr + 1;
				str = ptr + 1;
				continue;
			} else if (ptr[0] == '0' && (ptr[1] == 'm' || ptr [1] == 'K')) {
				SetConsoleTextAttribute (hConsole, 1|2|4|8);
				fg = 1|2|4|8;
				bg = 0;
				inv = 0;
				esc = 0;
				ptr++;
				str = ptr + 1;
				continue;
				// reset color
			} else if (ptr[0] == '2' && ptr[1] == '7' && ptr[2] == 'm') {
				SetConsoleTextAttribute (hConsole, bg|fg);
				inv = 0;
				esc = 0;
				ptr = ptr + 2;
				str = ptr + 1;
				continue;
				// invert off
			} else if (ptr[0] == '7' && ptr[1] == 'm') {
				SetConsoleTextAttribute (hConsole, bg|fg|COMMON_LVB_REVERSE_VIDEO);
				inv = COMMON_LVB_REVERSE_VIDEO;
				esc = 0;
				ptr = ptr + 1;
				str = ptr + 1;
				continue;
				// invert
			} else if ((ptr[0] == '3' || (bright = ptr[0] == '9')) && (ptr[2] == 'm' || ptr[2] == ';')) {
				switch (ptr[1]) {
				case '0': // BLACK
					fg = 0;
					break;
				case '1': // RED
					fg = 4;
					break;
				case '2': // GREEN
					fg = 2;
					break;
				case '3': // YELLOW
					fg = 2|4;
					break;
				case '4': // BLUE
					fg = 1;
					break;
				case '5': // MAGENTA
					fg = 1|4;
					break;
				case '6': // CYAN
					fg = 1|2;
					break;
				case '7': // WHITE
					fg = 1|2|4;
					break;
				case '8': // ???
				case '9':
					break;
				}
				if (bright) {
					fg |= 8;
				}
				SetConsoleTextAttribute (hConsole, bg|fg|inv);
				esc = 0;
				ptr = ptr + 2;
				str = ptr + 1;
				continue;
			} else if ((ptr[0] == '4' && ptr[2] == 'm')
					|| (bright = ptr[0] == '1' && ptr[1] == '0' && ptr[3] == 'm')) {
				/* background color */
				ut8 col = bright ? ptr[2] : ptr[1];
				switch (col) {
				case '0': // BLACK
					bg = 0x0;
					break;
				case '1': // RED
					bg = 0x40;
					break;
				case '2': // GREEN
					bg = 0x20;
					break;
				case '3': // YELLOW
					bg = 0x20|0x40;
					break;
				case '4': // BLUE
					bg = 0x10;
					break;
				case '5': // MAGENTA
					bg = 0x10|0x40;
					break;
				case '6': // CYAN
					bg = 0x10|0x20;
					break;
				case '7': // WHITE
					bg = 0x10|0x20|0x40;
					break;
				case '8': // ???
				case '9':
					break;
				}
				if (bright) {
					bg |= 0x80;
				}
				SetConsoleTextAttribute (hConsole, bg|fg|inv);
				esc = 0;
				ptr = ptr + (bright ? 3 : 2);
				str = ptr + 1;
				continue;
			}
		}
		ret++;
	}
	if (vmode) {
		/* fill partial line */
		int wlen = cols - linelen - 1;
		if (wlen > 0) {
			char white[1024];
			memset (white, ' ', sizeof (white));
			write (fd, white, wlen);
		}
		/* fill tail */
		__fill_tail (cols, lines);
	} else {
		int ll = (size_t)(ptr - str);
		if (ll > 0) {
			write (fd, str, ll);
			linelen += ll;
		}
	}
	return ret;
}

R_IPI int r_cons_win_print(RCons *cons, const char *ptr, int len, bool vmode) {
	return win_hprint (cons, STD_OUTPUT_HANDLE, ptr, len, vmode);
}

R_IPI int r_cons_win_vhprintf(RCons *cons, DWORD hdl, bool vmode, const char *fmt, va_list ap) {
	va_list ap2;
	int ret = -1;
	FILE *con = hdl == STD_OUTPUT_HANDLE ? stdout : stderr;
	if (!strchr (fmt, '%')) {
		size_t len = strlen (fmt);
		if (I->vtmode) {
			return fwrite (fmt, 1, len, con);
		}
		return win_hprint (cons, hdl, fmt, len, vmode);
	}
	va_copy (ap2, ap);
	int num_chars = vsnprintf (NULL, 0, fmt, ap2);
	num_chars++;
	char *buf = calloc (1, num_chars);
	if (buf) {
		(void)vsnprintf (buf, num_chars, fmt, ap);
		if (I->vtmode) {
			ret = fwrite (buf, 1, num_chars - 1, con);
		} else {
			ret = win_hprint (cons, hdl, buf, num_chars - 1, vmode);
		}
		free (buf);
	}
	va_end (ap2);
	return ret;
}

R_IPI int r_cons_win_printf(RCons *cons, bool vmode, const char *fmt, ...) {
	va_list ap;
	int ret;
	R_RETURN_VAL_IF_FAIL (fmt, -1);

	va_start (ap, fmt);
	ret = r_cons_win_vhprintf (cons, STD_OUTPUT_HANDLE, vmode, fmt, ap);
	va_end (ap);
	return ret;
}

R_IPI int r_cons_win_eprintf(RCons *cons, bool vmode, const char *fmt, ...) {
	va_list ap;
	int ret;
	R_RETURN_VAL_IF_FAIL (fmt, -1);

	va_start (ap, fmt);
	ret = r_cons_win_vhprintf (cons, STD_ERROR_HANDLE, vmode, fmt, ap);
	va_end (ap);
	return ret;
}

R_IPI int win_is_vtcompat(void) {
	DWORD major;
	DWORD minor;
	DWORD release = 0;
	char *cmd_session = r_sys_getenv ("SESSIONNAME");
	if (cmd_session) {
		free (cmd_session);
		return 2;
	}
	// Windows Terminal
	char *wt_session = r_sys_getenv ("WT_SESSION");
	if (wt_session) {
		free (wt_session);
		return 2;
	}
	char *alacritty = r_sys_getenv ("ALACRITTY_LOG");
	if (alacritty) {
		free (alacritty);
		return 1;
	}
	char *term = r_sys_getenv ("TERM");
	if (term) {
		if (strstr (term, "xterm")) {
			I->term_xterm = true;
			free (term);
			return 2;
		}
		I->term_xterm = false;
		free (term);
	}
	char *ansicon = r_sys_getenv ("ANSICON");
	if (ansicon) {
		free (ansicon);
		return 1;
	}
	bool win_support = 0;
	RSysInfo *info = r_sys_info ();
	if (info && info->version) {
		char *save_ptr = NULL;
		char *dot = r_str_tok_r (info->version, ".", &save_ptr);
		major = atoi (dot);
		dot = r_str_tok_r (NULL, ".", &save_ptr);
		minor = atoi (dot);
		if (info->release) {
			release = atoi (info->release);
		}
		if (major > 10
			|| (major == 10 && minor > 0)
			|| (major == 10 && minor == 0 && release >= 1703)) {
			win_support = 1;
		}
	}
	r_sys_info_free (info);
	return win_support;
}
#endif

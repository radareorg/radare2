/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <r_cons.h>
#include <r_util/r_assert.h>
#define I r_cons_singleton ()

#if __WINDOWS__
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

R_API void r_cons_w32_clear(void) {
	static HANDLE hStdout = NULL;
	static CONSOLE_SCREEN_BUFFER_INFO csbi;
	COORD startCoords;
	DWORD dummy;
	if (I->is_wine == 1) {
		write (1, "\033[0;0H\033[0m\033[2J", 6 + 4 + 4);
	}
	if (!hStdout) {
		hStdout = GetStdHandle (STD_OUTPUT_HANDLE);
	}
	GetConsoleScreenBufferInfo (hStdout, &csbi);
	startCoords = (COORD) {
		csbi.srWindow.Left,
		csbi.srWindow.Top
	};
	DWORD nLength = csbi.dwSize.X * (csbi.srWindow.Bottom - csbi.srWindow.Top + 1);
	FillConsoleOutputCharacter (hStdout, ' ',
		nLength, startCoords, &dummy);
	FillConsoleOutputAttribute (hStdout,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
		nLength, startCoords, &dummy);
}

R_API void r_cons_w32_gotoxy(int fd, int x, int y) {
	static HANDLE hStdout = NULL;
	static HANDLE hStderr = NULL;
	HANDLE *hConsole = fd == 1 ? &hStdout : &hStderr;
	COORD coord;
	coord.X = x;
	coord.Y = y;
	if (I->is_wine == 1) {
		write (fd, "\x1b[0;0H", 6);
	}
	if (!*hConsole) {
		*hConsole = GetStdHandle (fd == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
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

static int r_cons_w32_hprint(DWORD hdl, const char *ptr, int len, bool vmode) {
	HANDLE hConsole = GetStdHandle (hdl);
	int fd = hdl == STD_OUTPUT_HANDLE ? 1 : 2;
	int esc = 0;
	int bg = 0, fg = 1|2|4|8;
	const char *ptr_end, *str = ptr;
	int ret = 0;
	int inv = 0;
	int linelen = 0;
	int ll = 0;
	int raw_ll = 0;
	int lines, cols = r_cons_get_size (&lines);
	if (I->is_wine==-1) {
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
				eprintf ("Oops invalid escape char\n");
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
					if (ptr[i]=='H') {
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
				r_cons_w32_gotoxy (fd, x, y);
				ptr += i;
				str = ptr; // + i-2;
				continue;
			}
			bool bright = false;
			if (ptr[0]=='0' && ptr[1] == ';' && ptr[2]=='0') {
				// \x1b[0;0H
				/** clear screen if gotoxy **/
				if (vmode) {
					// fill row here
					__fill_tail (cols, lines);
				}
				r_cons_w32_gotoxy (fd, 0, 0);
				lines = 0;
				esc = 0;
				ptr += 3;
				str = ptr + 1;
				continue;
			} else if (ptr[0]=='2'&&ptr[1]=='J') {
				r_cons_w32_clear ();
				esc = 0;
				ptr = ptr + 1;
				str = ptr + 1;
				continue;
			} else if (ptr[0]=='0'&&(ptr[1]=='m' || ptr [1]=='K')) {
				SetConsoleTextAttribute (hConsole, 1|2|4|8);
				fg = 1|2|4|8;
				bg = 0;
				inv = 0;
				esc = 0;
				ptr++;
				str = ptr + 1;
				continue;
				// reset color
			} else if (ptr[0]=='2'&&ptr[1]=='7'&&ptr[2]=='m') {
				SetConsoleTextAttribute (hConsole, bg|fg);
				inv = 0;
				esc = 0;
				ptr = ptr + 2;
				str = ptr + 1;
				continue;
				// invert off
			} else if (ptr[0]=='7'&&ptr[1]=='m') {
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

R_API int r_cons_w32_print(const char *ptr, int len, bool vmode) {
	return r_cons_w32_hprint (STD_OUTPUT_HANDLE, ptr, len, vmode);
}

R_API int r_cons_win_vhprintf(DWORD hdl, bool vmode, const char *fmt, va_list ap) {
	va_list ap2;
	int ret = -1;
	FILE *con = hdl == STD_OUTPUT_HANDLE ? stdout : stderr;
	if (!strchr (fmt, '%')) {
		size_t len = strlen (fmt);
		if (I->ansicon) {
			return fwrite (fmt, 1, len, con);
		}
		return r_cons_w32_hprint (hdl, fmt, len, vmode);
	}
	va_copy (ap2, ap);
	int num_chars = vsnprintf (NULL, 0, fmt, ap2);
	num_chars++;
	char *buf = calloc (1, num_chars);
	if (buf) {
		(void)vsnprintf (buf, num_chars, fmt, ap);
		if (I->ansicon) {
			ret = fwrite (buf, 1, num_chars - 1, con);
		} else {
			ret = r_cons_w32_hprint (hdl, buf, num_chars - 1, vmode);
		}
		free (buf);
	}
	va_end (ap2);
	return ret;
}

R_API int r_cons_win_printf(bool vmode, const char *fmt, ...) {
	va_list ap;
	int ret;
	r_return_val_if_fail (fmt, -1);

	va_start (ap, fmt);
	ret = r_cons_win_vhprintf (STD_OUTPUT_HANDLE, vmode, fmt, ap);
	va_end (ap);
	return ret;
}

R_API int r_cons_win_eprintf(bool vmode, const char *fmt, ...) {
	va_list ap;
	int ret;
	r_return_val_if_fail (fmt, -1);

	va_start (ap, fmt);
	ret = r_cons_win_vhprintf (STD_ERROR_HANDLE, vmode, fmt, ap);
	va_end (ap);
	return ret;
}
#endif

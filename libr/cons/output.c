/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <r_cons.h>
#define I r_cons_singleton ()

#if __WINDOWS__
static void fill_tail (int cols, int lines) {
	lines++;
	if (lines > 0) {
		char white[1024];
		memset (white, ' ', sizeof (white));
		cols = R_MIN (cols, sizeof (white));
		lines--;
		white[cols]='\n';
		while (lines-- > 0) {
			write (1, white, cols);
		}
	}
}

static void w32_clear() {
	static HANDLE hStdout = NULL;
	static CONSOLE_SCREEN_BUFFER_INFO csbi;
	const COORD startCoords = { 0, 0 };
	DWORD dummy;
	if (I->is_wine == 1) {
		write (1, "\033[0;0H\033[0m\033[2J", 6 + 4 + 4);
	}
	if (!hStdout) {
		hStdout = GetStdHandle (STD_OUTPUT_HANDLE);
		GetConsoleScreenBufferInfo (hStdout, &csbi);
		//GetConsoleWindowInfo (hStdout, &csbi);
	}
	FillConsoleOutputCharacter (hStdout, ' ',
		csbi.dwSize.X * csbi.dwSize.Y, startCoords, &dummy);
}

void w32_gotoxy(int x, int y) {
        static HANDLE hStdout = NULL;
        COORD coord;
        coord.X = x;
        coord.Y = y;
	if (I->is_wine == 1) {
		write (1, "\x1b[0;0H", 6);
	}
        if (!hStdout) {
                hStdout = GetStdHandle (STD_OUTPUT_HANDLE);
	}
        SetConsoleCursorPosition (hStdout, coord);
}

static int wrapline (const char *s, int len) {
	int l, n = 0;
	for (; n < len; ) {
		l = r_str_len_utf8char (s+n, (len-n));
		n += l;
	}
	return n - (n > len)? l: 1;
}

R_API int r_cons_w32_print(const ut8 *ptr, int len, int vmode) {
	HANDLE hConsole = GetStdHandle (STD_OUTPUT_HANDLE);
	int esc = 0;
	int bg = 0, fg = 1|2|4|8;
	const ut8 *ptr_end, *str = ptr;
	int ret = 0;
	int inv = 0;
	int linelen = 0;
	int ll = 0;
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
			ll = (size_t)(ptr - str);
			lines--;
			if (vmode && lines < 0) {
				break;
			}
			if (ll < 1) {
				continue;
			}
			if (vmode) {
				// TODO: Fix utf8 chop
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
				write (1, str, ll);
				linelen += ll;
			}
			esc = 0;
			str = ptr + 1;
			if (vmode) {
				int wlen = cols - linelen;
				char white[1024];
				if (wlen > 0 && wlen < sizeof (white)) {
					memset (white, ' ', sizeof (white));
					write (1, white, wlen-1);
				}
			}
			write (1, "\n\r", 2);
			// reset colors for next line
			SetConsoleTextAttribute (hConsole, 1 | 2 | 4 | 8);
			linelen = 0;
			continue;
		}
		if (ptr[0] == 0x1b) {
			ll = (size_t)(ptr-str);
			if (str[0] == '\n') {
				str++;
				ll--;
				if (vmode) {
					int wlen = cols - linelen - 1;
					char white[1024];
					//wlen = 5;
					if (wlen > 0) {
						memset (white, ' ', sizeof (white));
						write (1, white, wlen);
					}
				}
				write (1, "\n\r", 2);
				//write (1, "\r\n", 2);
				//lines--;
				linelen = 0;
			}
			if (vmode) {
				if (linelen + ll >= cols) {
					// chop line if too long
					ll = (cols-linelen) - 1;
					if (ll > 0) {
						// fix utf8 len here
						ll = wrapline ((const char*)str, cols - linelen - 1);
					}
				}
			}
			if (ll > 0) {
				write (1, str, ll);
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
				w32_gotoxy (x, y);
				ptr += i;
				str = ptr + 1;// + i-2;
				continue;
			}
			if (ptr[0]=='0' && ptr[1] == ';' && ptr[2]=='0') {
				// \x1b[0;0H
				/** clear screen if gotoxy **/
				if (vmode) {
					// fill row here
					fill_tail (cols, lines);
				}
				w32_gotoxy (0, 0);
				lines = 0;
				esc = 0;
				ptr += 3;
				str = ptr + 1;
				continue;
			} else if (ptr[0]=='2'&&ptr[1]=='J') {
				//fill_tail(cols, lines);
				w32_clear (); //r_cons_clear ();
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
				SetConsoleTextAttribute (hConsole, bg|fg|128);
				inv = 128;
				esc = 0;
				ptr = ptr + 1;
				str = ptr + 1;
				continue;
				// invert
			} else if (ptr[0]=='3' && (ptr[2]=='m' || ptr[2] == ';')) {
				// http://www.betarun.com/Pages/ConsoleColor/
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
				case '6': // TURQOISE
					fg = 1|2|8;
					break;
				case '7': // WHITE
					fg = 1|2|4;
					break;
				case '8': // GRAY
					fg = 8;
					break;
				case '9': // ???
					break;
				}
				SetConsoleTextAttribute (hConsole, bg|fg|inv);
				esc = 0;
				ptr = ptr + 2;
				str = ptr + 1;
				continue;
			} else if (ptr[0]=='4' && ptr[2]=='m') {
				/* background color */
				switch (ptr[1]) {
				case '0': // BLACK
					bg = 0;
					break;
				case '1': // RED
					bg = 40;
					break;
				case '2': // GREEN
					bg = 20;
					break;
				case '3': // YELLOW
					bg = 20|40;
					break;
				case '4': // BLUE
					bg = 10;
					break;
				case '5': // MAGENTA
					bg = 10|40;
					break;
				case '6': // TURQOISE
					bg = 10|20|80;
					break;
				case '7': // WHITE
					bg = 10|20|40;
					break;
				case '8': // GRAY
					bg = 80;
					break;
				case '9': // ???
					break;
				}
				esc = 0;
				ptr = ptr + 2;
				str = ptr + 1;
				continue;
			}
		}
		ret++;
	}
	if (vmode) {
		/* fill partial line */
		int wlen = cols-linelen - 1;
		if (wlen > 0) {
			char white[1024];
			memset (white, ' ', sizeof (white));
			write (1, white, wlen);
		}
		/* fill tail */
		fill_tail (cols, lines);
	} else {
		int ll = (size_t)(ptr - str);
		if (ll > 0) {
			write (1, str, ll);
			linelen += ll;
		}
	}
	return ret;
}
#endif

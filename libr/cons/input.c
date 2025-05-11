/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_cons.h>

#define I r_cons_singleton ()

R_API int r_cons_controlz(RCons *cons, int ch) {
#if R2__UNIX__
	if (ch == 0x1a) {
		r_kons_show_cursor (cons, true);
		r_kons_enable_mouse (cons, false);
		r_sys_stop ();
		return 0;
	}
#endif
	return ch;
}

// 96 - wheel up
// 97 - wheel down
// 95 - mouse up
// 92 - mouse down
static int parseMouseEvent(RCons *cons) {
	char xpos[32];
	char ypos[32];
	(void) r_cons_readchar (cons); // skip first char
	int ch2 = r_cons_readchar (cons);

	// [32M - mousedown
	// [35M - mouseup
	if (ch2 == ';') {
		size_t i;
		// read until next ;
		for (i = 0; i < sizeof (xpos) - 1; i++) {
			char ch = r_cons_readchar (cons);
			if (ch == ';' || ch == 'M') {
				break;
			}
			xpos[i] = ch;
		}
		xpos[i] = 0;
		for (i = 0; i < sizeof (ypos) - 1; i++) {
			char ch = r_cons_readchar (cons);
			if (ch == ';' || ch == 'M') {
				break;
			}
			ypos[i] = ch;
		}
		ypos[i] = 0;
		r_kons_set_click (cons, atoi (xpos), atoi (ypos));
		(void) r_cons_readchar (cons);
		// ignored
		int ch = r_cons_readchar (cons);
		if (ch == 27) {
			ch = r_cons_readchar (cons); // '['
		}
		if (ch == '[') {
			do {
				ch = r_cons_readchar (cons); // '3'
			} while (ch != 'M');
		}
	}
	return 0;
}

#if __APPLE__
static void skipchars(RCons *cons, char ech, int nch) {
	while (nch-- > 0) {
		if (r_cons_readchar (cons) == ech) {
			break;
		}
	}
}
#endif

R_API int r_cons_arrow_to_hjkl(RCons *cons, int ch) {
#if R2__WINDOWS__
	if (cons->vtmode != 2) {
		if (cons->is_arrow) {
			switch (ch) {
			case VK_DOWN: // key down
				ch = cons->bCtrl ? 'J' : 'j';
				break;
			case VK_RIGHT: // key right
				ch = cons->bCtrl ? 'L' : 'l';
				break;
			case VK_UP: // key up
				ch = cons->bCtrl ? 'K' : 'k';
				break;
			case VK_LEFT: // key left
				ch = cons->bCtrl ? 'H' : 'h';
				break;
			case VK_PRIOR: // key home
				ch = 'K';
				break;
			case VK_NEXT: // key end
				ch = 'J';
				break;
			}
		}
		return cons->mouse_event && (ut8)ch == UT8_MAX ? 0 : ch;
	}
#endif
	cons->mouse_event = 0;
	/* emacs */
	switch ((ut8)ch) {
	case 0xc3: r_cons_readchar (cons); ch = 'K'; break; // emacs repag (alt + v)
	case 0x16: ch = 'J'; break; // emacs avpag (ctrl + v)
	case 0x10: ch = 'k'; break; // emacs up (ctrl + p)
	case 0x0e: ch = 'j'; break; // emacs down (ctrl + n)
	case 0x06: ch = 'l'; break; // emacs right (ctrl + f)
	case 0x02: ch = 'h'; break; // emacs left (ctrl + b)
	}
	if (ch != 0x1b) {
		return ch;
	}
	ch = r_cons_readchar (cons);
	if (!ch) {
		return 0;
	}
	switch (ch) {
	case 0x1b:
		ch = 'q'; // XXX: must be 0x1b (R_CONS_KEY_ESC)
		break;
	case 0x4f: // function keys from f1 to f4
		ch = r_cons_readchar (cons);
#if defined(__HAIKU__)
		/* Haiku't don use the '[' char for function keys */
		if (ch > 'O') {/* only in f1..f12 function keys */
			ch = 0xf1 + (ch & 0xf);
			break;
		}
	case '[': // 0x5b function keys (2)
		/* Haiku need ESC + [ for PageUp and PageDown  */
		if (ch < 'A' || ch == '[') {
			ch = r_cons_readchar (cons);
		}
#else
		switch (ch) { // Arrow keys
		case 'A': ch = 'k'; break;
		case 'B': ch = 'j'; break;
		case 'C': ch = 'l'; break;
		case 'D': ch = 'h'; break;
		default: ch = 0xf1 + (ch & 0xf); break;
		}
		break;
	case '[': // function keys (2)
		ch = r_cons_readchar (cons);
#endif
		switch (ch) {
		case '<':
			{
				char pos[8] = {0};
				int p = 0;
				int x = 0;
				int y = 0;
				int sc = 0;

				char vel[8] = {0};
				int vn = 0;
				do {
					ch = r_cons_readchar (cons);
					// just for debugging
					if (sc > 0) {
						if (ch >= '0' && ch <= '9') {
							pos[p++] = ch;
						}
					}
					if (sc < 1) {
						vel[vn++] = ch;
					}
					if (ch == ';') {
						if (sc == 1) {
							pos[p++] = 0;
							x = atoi (pos);
						}
						sc++;
						p = 0;
					}
				} while (ch != 'M' && ch != 'm');
				int nvel = atoi (vel);
				switch (nvel) {
				case 2: // right click
					if (ch == 'M') {
						return INT8_MAX;
					}
					return -INT8_MAX;
				case 64: // wheel up
					return 'k';
				case 65: // wheel down
					return 'j';
				case 66: // wheel left
					return 'h';
				case 67: // wheel right
					return 'l';
				case 80: // control+wheel up // VTE only
					return 'h';
				case 81: // control+wheel down // VTE only
					return 'l';
				}
				pos[p++] = 0;
				y = atoi (pos);
				if (ch == 'm') { // mouse up only
					r_kons_set_click (cons, x, y);
				}
			}
			return 0;
		case '[':
			ch = r_cons_readchar (cons);
			switch (ch) {
			case '2': ch = R_CONS_KEY_F11; break;
			case 'A': ch = R_CONS_KEY_F1; break;
			case 'B': ch = R_CONS_KEY_F2; break;
			case 'C': ch = R_CONS_KEY_F3; break;
			case 'D': ch = R_CONS_KEY_F4; break;
			}
			break;
		case '9':
			// handle mouse wheel
	//		__parseWheelEvent();
			ch = r_cons_readchar (cons);
			// 6 is up
			// 7 is down
			I->mouse_event = 1;
			if (ch == '6') {
				ch = 'k';
			} else if (ch == '7') {
				ch = 'j';
			} else {
				// unhandled case
				ch = 0;
			}
			int ch2;
			do {
				ch2 = r_cons_readchar (cons);
			} while (ch2 != 'M');
			break;
		case '3':
			// handle mouse down /up events (35 vs 32)
			parseMouseEvent (cons);
			return 0;
		case '2':
			ch = r_cons_readchar (cons);
			switch (ch) {
			case 0x7e:
				ch = R_CONS_KEY_F12;
				break;
			default:
				r_cons_readchar (cons);
				switch (ch) {
				case '0': ch = R_CONS_KEY_F9; break;
				case '1': ch = R_CONS_KEY_F10; break;
				case '3': ch = R_CONS_KEY_F11; break;
				}
				break;
			}
			break;
		case '1':
			ch = r_cons_readchar (cons);
#if __APPLE__
			if (ch == '1') {
				// horizontal scroll on macOS (works on Therm and Terminal apps)
				ch = r_cons_readchar (cons);
				if (ch == '2') {
					skipchars (cons, 'M', 12);
					return 'l';
				}
				if (ch == '3') {
					skipchars (cons, 'M', 12);
					return 'h';
				}
			}
#endif
			switch (ch) {
			case '1': ch = R_CONS_KEY_F1; break;
			case '2': ch = R_CONS_KEY_F2; break;
			case '3': ch = R_CONS_KEY_F3; break;
			case '4': ch = R_CONS_KEY_F4; break;
			case '5': ch = R_CONS_KEY_F5; break;
			// case '6': ch = R_CONS_KEY_F5; break;
			case '7': ch = R_CONS_KEY_F6; break;
			case '8': ch = R_CONS_KEY_F7; break;
			case '9': ch = R_CONS_KEY_F8; break;
#if 0
			case '5':
				r_cons_readchar (cons);
				ch = 0xf5;
				break;
			case '6':
				r_cons_readchar (cons);
				ch = 0xf7;
				break;
			case '7':
				r_cons_readchar (cons);
				ch = 0xf6;
				break;
			case '8':
				r_cons_readchar (cons);
				ch = 0xf7;
				break;
			case '9':
				r_cons_readchar (cons);
				ch = 0xf8;
				break;
#endif
			// Support st/st-256color term and others
			// for shift+arrows
			case ';': // arrow+mod
				ch = r_cons_readchar (cons);
				switch (ch) {
				case '2': // arrow+shift
					ch = r_cons_readchar (cons);
					switch (ch) {
					case 'A': ch = 'K'; break;
					case 'B': ch = 'J'; break;
					case 'C': ch = 'L'; break;
					case 'D': ch = 'H'; break;
					}
					break;
				// add other modifiers
				}
				break;
			case ':': // arrow+shift
				ch = r_cons_readchar (cons);
				ch = r_cons_readchar (cons);
				switch (ch) {
				case 'A': ch = 'K'; break;
				case 'B': ch = 'J'; break;
				case 'C': ch = 'L'; break;
				case 'D': ch = 'H'; break;
				}
				break;
			} // F9-F12 not yet supported!!
			break;
		case '5': ch = 'K'; r_cons_readchar (cons); break; // repag
		case '6': ch = 'J'; r_cons_readchar (cons); break; // avpag
		/* arrow keys */
		case 'A': ch = 'k'; break; // up
		case 'B': ch = 'j'; break; // down
		case 'C': ch = 'l'; break; // right
		case 'D': ch = 'h'; break; // left
		// Support rxvt-unicode term for shift+arrows
		case 'a': ch = 'K'; break; // shift+up
		case 'b': ch = 'J'; break; // shift+down
		case 'c': ch = 'L'; break; // shift+right
		case 'd': ch = 'H'; break; // shift+left
		case 'M': ch = parseMouseEvent (cons); break; // mouse up
		}
		break;
	}
	return ch;
}

#if 0
#define P(x) fwrite ((x), strlen ((x)), 1, stdout);fflush(stdout);
#else
#define P(x) write (1, (x), strlen ((x)));
#endif
// XXX no control for max length here?!?!
R_API int r_cons_fgets(RCons *cons, char *buf, int len, int argc, const char **argv) {
#define RETURN(x) { ret=x; goto beach; }
	int ret = 0, color = cons->context->pal.input && *cons->context->pal.input;
	if (cons->echo) {
		r_cons_set_raw (false);
		r_cons_show_cursor (true);
	}
	errno = 0;
	if (cons->user_fgets) {
		RETURN (cons->user_fgets (buf, len));
	}
	const char *prompt = cons->line->prompt;
	P (prompt);
	*buf = '\0';
	if (color) {
		const char *p = cons->context->pal.input;
		if (R_STR_ISNOTEMPTY (p)) {
			P(p);
		}
	}
	if (!fgets (buf, len, cons->fdin)) {
		if (color) {
			P(Color_RESET);
		}
		RETURN (-1);
	}
	if (feof (cons->fdin)) {
		if (color) {
			P(Color_RESET);
		}
		RETURN (-2);
	}
	r_str_trim_tail (buf);
	if (color) {
		P (Color_RESET);
	}
	ret = strlen (buf);
beach:
	return ret;
}

R_API int r_cons_any_key(const char *msg) {
	if (R_STR_ISNOTEMPTY (msg)) {
		r_cons_printf ("\n-- %s --\n", msg);
	} else {
		r_cons_print ("\n--press any key--\n");
	}
	RCons *cons = r_cons_singleton ();
	r_kons_flush (cons);
	return r_cons_readchar (cons);
}

static inline void resizeWin(RCons *cons) {
	if (cons->event_resize) {
		cons->event_resize (cons->event_data);
	}
}

#if R2__WINDOWS__
static int readchar_w32(RCons *cons, ut32 usec) {
	int ch = 0;
	BOOL ret;
	cons->bCtrl = false;
	cons->is_arrow = false;
	DWORD mode, out;
	HANDLE h;
	INPUT_RECORD irInBuf = {0};
	CONSOLE_SCREEN_BUFFER_INFO info = {0};
	bool mouse_enabled = I->mouse;
	bool click_n_drag = false;
	void *bed;
	cons->mouse_event = 0;
	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &mode);
	DWORD newmode = ENABLE_WINDOW_INPUT;
	if (cons->vtmode == 2) {
		newmode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
	}
	newmode |= mode;
	SetConsoleMode (h, newmode);
	do {
		bed = r_cons_sleep_begin ();
		if (usec) {
			if (WaitForSingleObject (h, usec) == WAIT_TIMEOUT) {
				r_cons_sleep_end (bed);
				return -1;
			}
		}
		if (I->term_xterm) {
			ret = ReadFile (h, &ch, 1, &out, NULL);
			if (ret) {
				r_cons_sleep_end (bed);
				return ch;
			}
		} else {
			ret = ReadConsoleInput (h, &irInBuf, 1, &out);
		}
		r_cons_sleep_end (bed);
		if (ret) {
			if (irInBuf.EventType == MENU_EVENT || irInBuf.EventType == FOCUS_EVENT) {
				continue;
			}
			if (mouse_enabled) {
				r_kons_enable_mouse (cons, true);
			}
			if (irInBuf.EventType == MOUSE_EVENT) {
				if (irInBuf.Event.MouseEvent.dwEventFlags == MOUSE_MOVED) {
					if (irInBuf.Event.MouseEvent.dwButtonState == FROM_LEFT_1ST_BUTTON_PRESSED) {
						click_n_drag = true;
					}
					continue;
				}
				if (irInBuf.Event.MouseEvent.dwEventFlags == MOUSE_WHEELED) {
					if (irInBuf.Event.MouseEvent.dwButtonState & 0xFF000000) {
						ch = I->bCtrl ? 'J' : 'j';
					} else {
						ch = I->bCtrl ? 'K' : 'k';
					}
					I->mouse_event = 1;
				}
				switch (irInBuf.Event.MouseEvent.dwButtonState) {
				case FROM_LEFT_1ST_BUTTON_PRESSED:
					GetConsoleScreenBufferInfo (GetStdHandle (STD_OUTPUT_HANDLE), &info);
					int rel_y = irInBuf.Event.MouseEvent.dwMousePosition.Y - info.srWindow.Top;
					r_kons_set_click (cons, irInBuf.Event.MouseEvent.dwMousePosition.X + 1, rel_y + 1);
					ch = UT8_MAX;
					break;
				} // TODO: Handle more buttons?
			}

			if (click_n_drag) {
				r_kons_set_click (cons, irInBuf.Event.MouseEvent.dwMousePosition.X + 1, irInBuf.Event.MouseEvent.dwMousePosition.Y + 1);
				ch = UT8_MAX;
			}

			if (irInBuf.EventType == KEY_EVENT) {
				if (irInBuf.Event.KeyEvent.bKeyDown) {
					ch = irInBuf.Event.KeyEvent.uChar.AsciiChar;
					I->bCtrl = irInBuf.Event.KeyEvent.dwControlKeyState & 8;
					if (irInBuf.Event.KeyEvent.uChar.AsciiChar == 0) {
						switch (irInBuf.Event.KeyEvent.wVirtualKeyCode) {
						case VK_DOWN: // key down
						case VK_RIGHT: // key right
						case VK_UP: // key up
						case VK_LEFT: // key left
						case VK_PRIOR: // key home
						case VK_NEXT: // key end
							ch = irInBuf.Event.KeyEvent.wVirtualKeyCode;
							I->is_arrow = true;
							break;
						case VK_F1:
							ch = R_CONS_KEY_F1;
							break;
						case VK_F2:
							ch = R_CONS_KEY_F2;
							break;
						case VK_F3:
							ch = R_CONS_KEY_F3;
							break;
						case VK_F4:
							ch = R_CONS_KEY_F4;
							break;
						case VK_F5:
							ch = I->bCtrl ? 0xcf5 : R_CONS_KEY_F5;
							break;
						case VK_F6:
							ch = R_CONS_KEY_F6;
							break;
						case VK_F7:
							ch = R_CONS_KEY_F7;
							break;
						case VK_F8:
							ch = R_CONS_KEY_F8;
							break;
						case VK_F9:
							ch = R_CONS_KEY_F9;
							break;
						case VK_F10:
							ch = R_CONS_KEY_F10;
							break;
						case VK_F11:
							ch = R_CONS_KEY_F11;
							break;
						case VK_F12:
							ch = R_CONS_KEY_F12;
						case VK_SHIFT:
							if (mouse_enabled) {
								r_kons_enable_mouse (cons, false);
							}
							break;
						default:
							break;
						}
					}
				}
			}
			if (irInBuf.EventType == WINDOW_BUFFER_SIZE_EVENT) {
				resizeWin (cons);
			}
		}
		if (cons->vtmode != 2 && !cons->term_xterm) {
			FlushConsoleInputBuffer (h);
		}
	} while (ch == 0);
	SetConsoleMode (h, mode);
	return ch;
}
#endif

R_API int r_cons_readchar_timeout(RCons *cons, ut32 msec) {
#if R2__UNIX__
	struct timeval tv;
	fd_set fdset, errset;
	FD_ZERO (&fdset);
	FD_ZERO (&errset);
	FD_SET (0, &fdset);
	ut32 secs = msec / 1000;
	tv.tv_sec = secs;
	ut32 usec = (msec - secs) * 1000;
	tv.tv_usec = usec;
	r_kons_set_raw (cons, true);
	if (select (1, &fdset, NULL, &errset, &tv) == 1) {
		return r_cons_readchar (cons);
	}
	r_kons_set_raw (cons, false);
	// timeout
	return -1;
#else
	return  readchar_w32 (cons, msec);
#endif
}

R_API bool r_cons_readpush(const char *str, int len) {
	InputState *input_state = r_cons_input_state ();
	char *res = (len + input_state->readbuffer_length > 0)
		? realloc (input_state->readbuffer, len + input_state->readbuffer_length)
		: NULL;
	if (res) {
		input_state->readbuffer = res;
		memmove (input_state->readbuffer + input_state->readbuffer_length, str, len);
		input_state->readbuffer_length += len;
		return true;
	}
	return false;
}

R_API void r_cons_readflush(void) {
	InputState *input_state = r_cons_input_state ();
	R_FREE (input_state->readbuffer);
	input_state->readbuffer_length = 0;
}

R_API void r_cons_switchbuf(bool active) {
	InputState *input_state = r_cons_input_state ();
	input_state->bufactive = active;
}

#if !R2__WINDOWS__
extern volatile sig_atomic_t sigwinchFlag;
#endif

R_API int r_cons_readchar(RCons *cons) {
	char buf[2];
	buf[0] = -1;
	InputState *input_state = r_cons_input_state ();
	if (input_state->readbuffer_length > 0) {
		int ch = *input_state->readbuffer;
		input_state->readbuffer_length--;
		memmove (input_state->readbuffer, input_state->readbuffer + 1, input_state->readbuffer_length);
		return ch;
	}
	r_kons_set_raw (cons, true);
#if R2__WINDOWS__
	return readchar_w32 (cons, 0);
#elif __wasi__
	void *bed = r_cons_sleep_begin ();
	int ret = read (STDIN_FILENO, buf, 1);
	r_cons_sleep_end (bed);
	if (ret < 1) {
		return -1;
	}
	return r_cons_controlz (cons, buf[0]);
#else
	void *bed = r_cons_sleep_begin ();

	// Blocks until either stdin has something to read or a signal happens.
	// This serves to check if the terminal window was resized. It avoids the race
	// condition that could happen if we did not use pselect or select in case SIGWINCH
	// was handled immediately before the blocking call (select or read). The race is
	// prevented from happening by having SIGWINCH blocked process-wide except for in
	// pselect (that is what pselect is for).
	fd_set readfds;
	sigset_t sigmask;
	sigemptyset (&sigmask);
	FD_ZERO (&readfds);
	FD_SET (STDIN_FILENO, &readfds);
	r_signal_sigmask (0, NULL, &sigmask);
	sigdelset (&sigmask, SIGWINCH);
	while (pselect (STDIN_FILENO + 1, &readfds, NULL, NULL, NULL, &sigmask) == -1) {
		if (errno == EBADF) {
			R_LOG_ERROR ("r_cons_readchar (cons): EBADF");
			return -1;
		}
		if (sigwinchFlag) {
			sigwinchFlag = 0;
			resizeWin (cons);
		}
	}

	ssize_t ret = read (STDIN_FILENO, buf, 1);
	r_cons_sleep_end (bed);
	if (ret != 1) {
		return -1;
	}
	return r_cons_controlz (cons, buf[0]);
#endif
}

R_API bool r_cons_yesno(int def, const char *fmt, ...) {
	va_list ap;
	ut8 key = (ut8)def;
	va_start (ap, fmt);

	if (!r_cons_is_interactive ()) {
		va_end (ap);
		return def == 'y';
	}
	vfprintf (stderr, fmt, ap);
	va_end (ap);
	fflush (stderr);
	r_cons_set_raw (true);
	char buf[] = " ?\n";
	if (read (0, buf + 1, 1) == 1) {
		key = (ut8)buf[1];
		if (write (2, buf, 3) == 3) {
			if (key == 'Y') {
				key = 'y';
			}
			r_cons_set_raw (false);
			if (key == '\n' || key == '\r') {
				key = def;
			}
			return key == 'y';
		}
	}
	return false;
}

R_API char *r_cons_password(const char *msg) {
	int i = 0;
	printf ("\r%s", msg);
	fflush (stdout);
	r_cons_set_raw (true);
	RCons *cons = r_cons_singleton ();
#if R2__UNIX__ && !__wasi__
	cons->term_raw.c_lflag &= ~(ECHO | ECHONL);
	// //  required to make therm/iterm show the key
	// // cannot read when enabled in this way
	// a->term_raw.c_lflag |= ICANON;
	tcsetattr (0, TCSADRAIN, &cons->term_raw);
	r_sys_signal (SIGTSTP, SIG_IGN);
#endif
	const size_t buf_size = 256;
	char *buf = malloc (buf_size);
	if (!buf) {
		return NULL;
	}
	while (i < buf_size - 1) {
		int ch = r_cons_readchar (cons);
		if (ch == 127) { // backspace
			if (i < 1) {
				break;
			}
			i--;
			continue;
		}
		if (ch == '\r' || ch == '\n') {
			break;
		}
		buf[i++] = ch;
	}
	buf[i] = 0;
	r_cons_set_raw (false);
	printf ("\n");
#if R2__UNIX__
	r_sys_signal (SIGTSTP, SIG_DFL);
#endif
	return buf;
}

R_API char *r_cons_input(RCons *cons, const char *msg) {
	RLine *line = cons->line;
	char *oprompt = r_line_get_prompt (line);
	if (!oprompt) {
		return NULL;
	}
	r_line_set_prompt (cons->line, msg? msg: "");
	size_t buf_size = 1024;
	char *buf = malloc (buf_size);
	if (buf) {
		*buf = 0;
		r_cons_fgets (cons, buf, buf_size, 0, NULL);
		r_line_set_prompt (cons->line, oprompt);
	}
	free (oprompt);
	return buf;
}

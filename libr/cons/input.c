/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <r_cons.h>
#include <string.h>
#if __UNIX__
#include <errno.h>
#endif

/* experimental support for x/y click */
#define USE_CLICK 0

#define I r_cons_singleton()

#if 0
//__UNIX__
#include <poll.h>
static int is_fd_ready(int fd) {
	fd_set rfds;
	struct timeval tv;
	if (fd==-1)
		return 0;
	FD_ZERO (&rfds);
	FD_SET (fd, &rfds);
	tv.tv_sec = 0;
	tv.tv_usec = 1;
	if (select (1, &rfds, NULL, NULL, &tv) == -1)
		return 0;
	return 1;
	return !FD_ISSET (0, &rfds);
}
#endif

R_API int r_cons_controlz(int ch) {
#if __UNIX__
	if (ch == 0x1a) {
		r_cons_show_cursor (true);
		r_cons_enable_mouse (false);
		r_sys_stop ();
		return 0;
	}
#endif
	return ch;
}

static int parseMouseEvent() {
	int ch = r_cons_readchar ();
	/* Skip the x/y coordinates */
#if USE_CLICK
	int x = r_cons_readchar() - 33;
	int y = r_cons_readchar() - 33;
#else
	(void) r_cons_readchar ();
	(void) r_cons_readchar ();
#endif
#if USE_CLICK
	if (ch == 35) {
		/* handle click  */
#define CLICK_DEBUG 1
#if CLICK_DEBUG
		r_cons_gotoxy (0, 0);
		r_cons_printf ("Click at %d %d\n", x, y);
		r_cons_flush ();
#endif
		RCons *cons = r_cons_singleton ();
		if (cons->onclick) {
			cons->onclick (cons->data, x, y);
		}
		r_cons_enable_mouse (false);
		(void)r_cons_readchar ();
		return 0;
	}
#endif
	if (ch != 0x20 && ch >= 64 + 32) {
		/* Grab wheel events only */
		I->mouse_event = 1;
		return "kj"[(ch - (64 + 32))&1];
	}

	// temporary disable the mouse wheel to allow select
	r_cons_enable_mouse (false);
	(void)r_cons_readchar ();
	return 0;
}

R_API int r_cons_arrow_to_hjkl(int ch) {
#if __WINDOWS_ && !__CYGWIN__
	return ch;
#endif
	I->mouse_event = 0;
	/* emacs */
	switch ((ut8)ch) {
	case 0xc3: r_cons_readchar(); ch='K'; break; // emacs repag (alt + v)
	case 0x16: ch='J'; break; // emacs avpag (ctrl + v)
	case 0x10: ch='k'; break; // emacs up (ctrl + p)
	case 0x0e: ch='j'; break; // emacs down (ctrl + n)
	case 0x06: ch='l'; break; // emacs right (ctrl + f)
	case 0x02: ch='h'; break; // emacs left (ctrl + b)
	}
	if (ch != 0x1b) {
		return ch;
	}
	ch = r_cons_readchar ();
	if (!ch) {
		return 0;
	}
	switch (ch) {
	case 0x1b:
		ch = 'q'; // XXX: must be 0x1b (R_CONS_KEY_ESC)
		break;
	case 0x4f: // function keys from f1 to f4
		ch = r_cons_readchar ();
#if defined(__HAIKU__)	
		/* Haiku don use the '[' char for funcion keys */
		if (ch > 'O') {/* only in f1..f12 funcion keys */
			ch = 0xf1 + (ch&0xf);
			break;
		}
	case '[': // 0x5b function keys (2)
		/* Haiku need ESC + [ for PageUp and PageDown  */
		if (ch < 'A' || ch == '[') {
			ch = r_cons_readchar ();
		}
#else
		ch = 0xf1 + (ch & 0xf);
		break;
	case '[': // function keys (2)
		ch = r_cons_readchar ();
#endif
		switch (ch) {
		case '[':
			ch = r_cons_readchar ();
			switch (ch) {
			case '2': ch = R_CONS_KEY_F11; break;
			case 'A': ch = R_CONS_KEY_F1; break;
			case 'B': ch = R_CONS_KEY_F2; break;
			case 'C': ch = R_CONS_KEY_F3; break;
			case 'D': ch = R_CONS_KEY_F4; break;
			}
			break;
		case '2':
			ch = r_cons_readchar ();
			switch (ch) {
			case 0x7e:
				ch = R_CONS_KEY_F12;
				break;
			default:
				r_cons_readchar ();
				switch (ch) {
				case '0': ch = R_CONS_KEY_F9; break;
				case '1': ch = R_CONS_KEY_F10; break;
				case '3': ch = R_CONS_KEY_F11; break;
				}
				break;
			}
			break;
		case '1':
			ch = r_cons_readchar ();
			switch (ch) {
			case ':': // arrow+shift
				ch = r_cons_readchar ();
				ch = r_cons_readchar ();
				switch (ch) {
				case 'A': ch = 'K'; break;
				case 'B': ch = 'J'; break;
				case 'C': ch = 'L'; break;
				case 'D': ch = 'H'; break;
				}
				break;
/*
			case '1': ch = R_CONS_KEY_F1; break;
			case '2': ch = R_CONS_KEY_F2; break;
			case '3': ch = R_CONS_KEY_F3; break;
			case '4': ch = R_CONS_KEY_F4; break;
*/
			case '5': 
				r_cons_readchar ();
				ch = 0xf5;
				break;
			case '6': 
				r_cons_readchar ();
				ch = 0xf7;
				break;
			case '7': 
				r_cons_readchar ();
				ch = 0xf6;
				break;
			case '8': 
				r_cons_readchar ();
				ch = 0xf7;
				break;
			case '9': 
				r_cons_readchar ();
				ch = 0xf8;
				break;
			} // F9-F12 not yet supported!!
			break;
		case '5': ch = 'K'; r_cons_readchar(); break; // repag
		case '6': ch = 'J'; r_cons_readchar(); break; // avpag
		/* arrow keys */
		case 'A': ch = 'k'; break; // up
		case 'B': ch = 'j'; break; // down
		case 'C': ch = 'l'; break; // right
		case 'D': ch = 'h'; break; // left
		case 'M': ch = parseMouseEvent(); break;
		}
		break;
	}
	return ch;
}

// XXX no control for max length here?!?!
R_API int r_cons_fgets(char *buf, int len, int argc, const char **argv) {
#define RETURN(x) { ret=x; goto beach; }
	RCons *cons = r_cons_singleton ();
	int ret = 0, color = cons->pal.input && *cons->pal.input;
	if (cons->echo) {
		r_cons_set_raw (false);
		r_cons_show_cursor (true);
	}
#if 0
	int mouse = r_cons_enable_mouse (false);
	r_cons_enable_mouse (false);
	r_cons_flush ();
#endif
	if (cons->user_fgets) {
		RETURN (cons->user_fgets (buf, len));
	}
	printf ("%s", cons->line->prompt);
	fflush (stdout);
	*buf = '\0';
	fflush (cons->fdin);
	if (color) {
		const char *p = cons->pal.input;
		int len = p? strlen (p): 0;
		if (len>0)
			fwrite (p, len, 1, stdout);
		fflush (stdout);
	}
	if (!fgets (buf, len, cons->fdin)) {
		if (color) {
			printf (Color_RESET);
			fflush (stdout);
		}
		RETURN (-1);
	}
	if (feof (cons->fdin)) {
		if (color) {
			printf (Color_RESET);
		}
		RETURN (-2);
	}
	buf[strlen (buf)-1] = '\0';
	if (color) printf (Color_RESET);
	ret = strlen (buf);
beach:
#if __UNIX__
	if (errno == EINTR) {
		ret = 0;
	}
#endif
	//r_cons_enable_mouse (mouse);
	return ret;
}

R_API int r_cons_any_key(const char *msg) {
	if (msg && *msg) {
		r_cons_printf ("\n-- %s --\n", msg);
	} else {
		r_cons_print ("\n--press any key--\n");
	}
	r_cons_flush ();
	return r_cons_readchar ();
	//r_cons_strcat ("\x1b[2J\x1b[0;0H"); // wtf?
}

#if __WINDOWS__ && !__CYGWIN__
static int readchar_win(ut32 usec) {
	int ch = 0;
	BOOL ret;
	BOOL bCtrl = FALSE;
	DWORD mode, out;
	HANDLE h;
	INPUT_RECORD irInBuf[128];
	int i;
do_it_again:
	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &mode);
	SetConsoleMode (h, 0 | ENABLE_MOUSE_INPUT); // RAW
	if (usec) {
		if (WaitForSingleObject (h, usec) == WAIT_TIMEOUT) {
			return -1;
		}
	}
	ret = ReadConsoleInput (h, irInBuf, 128, &out);
	if (ret) {
		for (i = 0; i < out; i++) {
			if (irInBuf[i].EventType==MOUSE_EVENT) {
				switch (irInBuf[i].Event.MouseEvent.dwEventFlags) {
				case MOUSE_WHEELED:
					if (irInBuf[i].Event.MouseEvent.dwButtonState & 0xFF000000)
						ch='j';
					else
						ch='k';
				break;
				}
			}
			if (irInBuf[i].EventType==KEY_EVENT) {
				if (irInBuf[i].Event.KeyEvent.bKeyDown) {
					ch=irInBuf[i].Event.KeyEvent.uChar.AsciiChar;
					bCtrl=irInBuf[i].Event.KeyEvent.dwControlKeyState & 8;
					if (irInBuf[i].Event.KeyEvent.uChar.AsciiChar==0) {
						ch = 0;
						switch (irInBuf[i].Event.KeyEvent.wVirtualKeyCode) {
						case VK_DOWN: // key down
							ch = bCtrl ? 'J': 'j';
							break;
						case VK_RIGHT: // key right
							ch = bCtrl ? 'L': 'l';
							break;
						case VK_UP: // key up
							if (bCtrl)
								ch='K';
							else
								ch='k';
							break;
						case VK_LEFT: // key left
							if (bCtrl)
								ch='H';
							else
								ch='h';
							break;
						case VK_PRIOR: // key home
							if (bCtrl)
								ch='K';
							else
								ch='K';
							break;
						case VK_NEXT: // key end
							if (bCtrl)
								ch='J';
							else
								ch='J';
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
							if (bCtrl)
								ch=0xcf5;
							else
								ch=R_CONS_KEY_F5;
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
							break;
						default:
							ch = 0;
							break;
						}
					}
				}
			}
		}
	}
	FlushConsoleInputBuffer (h);
	SetConsoleMode (h, mode);
	if (ch == 0) {
		goto do_it_again;
	}
	/*r_cons_gotoxy (1, 2);
	r_cons_printf ("\n");
	r_cons_printf ("| buf = %x |\n", ch);
	r_cons_printf ("\n");
	r_cons_flush ();
	r_sys_sleep (1);*/
	return  ch;
}
#endif

R_API int r_cons_readchar_timeout(ut32 usec) {
#if __UNIX__
	struct timeval tv;
	fd_set fdset, errset;
	FD_ZERO (&fdset);
	FD_ZERO (&errset);
	FD_SET (0, &fdset);
	tv.tv_sec = 0; // usec / 1000;
	tv.tv_usec = 1000 * usec;
	r_cons_set_raw (1);
	if (select (1, &fdset, NULL, &errset, &tv) == 1) {
		return r_cons_readchar ();
	}
	r_cons_set_raw (0);
	// timeout
	return -1;
#else
	return  readchar_win (usec);
#endif
}

// TODO: support binary? buf+len
static char *readbuffer = NULL;
static int readbuffer_length = 0;

R_API bool r_cons_readpush(const char *str, int len) {
	char *res = realloc (readbuffer, len + readbuffer_length);
	if (res) {
		readbuffer = res;
		memmove (readbuffer + readbuffer_length, str, len);
		readbuffer_length += len;
		return true;
	}
	return false;
}

R_API void r_cons_readflush() {
	R_FREE (readbuffer);
	readbuffer_length = 0;
}

R_API int r_cons_readchar() {
	char buf[2];
	buf[0] = -1;
	if (readbuffer_length > 0) {
		int ch = *readbuffer;
		readbuffer_length--;
		memmove (readbuffer, readbuffer + 1, readbuffer_length);
		return ch;
	}
#if __WINDOWS__ && !__CYGWIN__ //&& !MINGW32
	#if 1   // if something goes wrong set this to 0. skuater.....
	return readchar_win(0);
	#endif
	BOOL ret;
	DWORD out;
	DWORD mode;
	HANDLE h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &mode);
	SetConsoleMode (h, 0); // RAW
	ret = ReadConsole (h, buf, 1, &out, NULL);
	FlushConsoleInputBuffer (h);
	if (!ret) {
		return -1;
	}
	SetConsoleMode (h, mode);
#else
	r_cons_set_raw (1);
	if (read (0, buf, 1) == -1) {
		return -1;
	}
	r_cons_set_raw (0);
#endif
	return r_cons_controlz (buf[0]);
}

R_API int r_cons_yesno(int def, const char *fmt, ...) {
	va_list ap;
	ut8 key = (ut8)def;
	va_start (ap, fmt);
	vfprintf (stderr, fmt, ap);
	va_end (ap);
	fflush (stderr);
	r_cons_set_raw (true);
	(void)read (0, &key, 1);
	write (2, "\n", 1);
	if (key == 'Y') {
		key = 'y';
	}
	r_cons_set_raw (false);
	if (key == '\n' || key == '\r') {
		key = def;
	}
	return key == 'y';
}

R_API char *r_cons_input(const char *msg) {
	char *oprompt = r_line_get_prompt (); //r_cons_singleton()->line->prompt);
	if (!oprompt) {
		return NULL;
	}
	char buf[1024];
	if (msg) {
		//r_cons_printf ("%s\n", msg);
		r_line_set_prompt (msg);
	} else {
		r_line_set_prompt ("");
	}
	buf[0] = 0;
	r_cons_fgets (buf, sizeof (buf), 0, NULL);
	r_line_set_prompt (oprompt);
	free (oprompt);
	return strdup (buf);
}

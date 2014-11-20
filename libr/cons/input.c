/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_cons.h>
#include <string.h>

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
		r_cons_set_raw (0);
		r_cons_show_cursor (1);
		r_sys_stop ();
		return 0;
	}
#endif
	return ch;
}

R_API int r_cons_arrow_to_hjkl(int ch) {
	/* emacs */
	switch ((ut8)ch) {
	case 0xc3: r_cons_readchar(); ch='K'; break; // emacs repag (alt + v)
	case 0x16: ch='J'; break; // emacs avpag (ctrl + v)
	case 0x10: ch='k'; break; // emacs up (ctrl + p)
	case 0x0e: ch='j'; break; // emacs down (ctrl + n)
	case 0x06: ch='l'; break; // emacs right (ctrl + f)
	case 0x02: ch='h'; break; // emacs left (ctrl + b)
	}
	if (ch != 0x1b)
		return ch;
	ch = r_cons_readchar ();
	if (!ch) return 0;
	switch (ch) {
	case 0x1b:
		ch = 'q'; // XXX: must be 0x1b (R_CONS_KEY_ESC)
		break;
	case 0x4f: // function keys from f1 to f4
		ch = r_cons_readchar ();
		ch = 0xf1 + (ch&0xf);
		break;
	case 0:
	case '[': // function keys (2)
		ch = r_cons_readchar ();
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
		case '5': ch='K'; break; // repag
		case '6': ch='J'; break; // avpag
		case 'A': ch='k'; break; // up
		case 'B': ch='j'; break; // down
		case 'C': ch='l'; break; // right
		case 'D': ch='h'; break; // left
		case 'M': // Mouse events
			ch = r_cons_readchar ();
			/* Skip the x/y coordinates */
			(void)r_cons_readchar();
			(void)r_cons_readchar();
			if (ch==0x20) {
				// click
				r_cons_enable_mouse (R_FALSE);
				ch = 0;
				//r_cons_enable_mouse (R_TRUE);
			} else
			if (ch >= 64 + 32) {
				/* Grab wheel events only */
				ch = "kj"[(ch - (64 + 32))&1];
			} else {
				// temporary disable the mouse wheel to allow select
				r_cons_enable_mouse (R_FALSE);
				(void)r_cons_readchar ();
				ch = 0;
			}
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
#if 0
	int mouse = r_cons_enable_mouse (R_FALSE);
	r_cons_enable_mouse (R_FALSE);
	r_cons_flush ();
#endif
	if (cons->user_fgets) {
		RETURN (cons->user_fgets (buf, len));
	}
	*buf = '\0';
	fflush (cons->fdin);
	if (color) {
		const char *p = cons->pal.input;
		int len = p? strlen (p): 0;
		if (len>0)
			fwrite (p, len, 1, stdout);
		fflush (stdout);
	}
	if (fgets (buf, len, cons->fdin) == NULL) {
		if (color) {
			printf (Color_RESET);
			fflush (stdout);
		}
		RETURN (-1);
	}
	if (feof (cons->fdin)) {
		if (color) printf (Color_RESET);
		RETURN (-2);
	}
	buf[strlen (buf)-1] = '\0';
	if (color) printf (Color_RESET);
	ret = strlen (buf);
beach:
	//r_cons_enable_mouse (mouse);
	return ret;
}

R_API void r_cons_any_key() {
	r_cons_strcat ("\n--press any key--\n");
	r_cons_flush ();
	r_cons_readchar ();
	//r_cons_strcat ("\x1b[2J\x1b[0;0H"); // wtf?
}

R_API int r_cons_readchar() {
	char buf[2];
	buf[0] = -1;
#if __WINDOWS__
	BOOL ret;
	DWORD out;
	DWORD mode;
	HANDLE h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &mode);
	SetConsoleMode (h, 0); // RAW
	ret = ReadConsole (h, buf, 1, &out, NULL);
	if (!ret)
		return -1;
	SetConsoleMode (h, mode);
#else
	r_cons_set_raw (1);
	if (read (0, buf, 1)==-1)
		return -1;
	r_cons_set_raw (0);
#endif
	return r_cons_controlz (buf[0]);
}

R_API int r_cons_yesno(int def, const char *fmt, ...) {
	va_list ap;
	int key = def;
	va_start (ap, fmt);
	vfprintf (stderr, fmt, ap);
	va_end (ap);
	fflush (stderr);
	r_cons_set_raw (1);
	(void)read (0, &key, 1);
	write (2, "\n", 1);
	if (key == 'Y')
		key = 'y';
	r_cons_set_raw (0);
	if (key=='\n' || key=='\r')
		key = def;
	return key=='y';
}

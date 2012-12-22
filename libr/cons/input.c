/* radare - LGPL - Copyright 2009-2012 - pancake */

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

R_API int r_cons_arrow_to_hjkl(int ch) {
	if (ch==0x1b) {
#if 0
//__UNIX__
		if (!is_fd_ready (0))
			return 0;
#endif
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
			}
			break;
		}
	}
	return ch;
}

// XXX no control for max length here?!?!
R_API int r_cons_fgets(char *buf, int len, int argc, const char **argv) {
	RCons *cons = r_cons_singleton ();
	if (cons->user_fgets)
		return cons->user_fgets (buf, len);
	*buf = '\0';
	fflush (cons->fdin);
	if (fgets (buf, len, cons->fdin) == NULL)
		return -1;
	if (feof (cons->fdin))
		return -2;
	buf[strlen (buf)-1] = '\0';
	return strlen (buf);
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
	return buf[0];
}

R_API int r_cons_yesno(int def, const char *fmt, ...) {
	va_list ap;
	int key = def;
	va_start (ap, fmt);
	vfprintf (stderr, fmt, ap);
	va_end (ap);
	fflush (stderr);
	r_cons_set_raw (1);
	read (0, &key, 1);
	write (2, "\n", 1);
	if (key == 'Y')
		key = 'y';
	r_cons_set_raw (1); // XXX with set_raw(0) causes problems wtf
	if (key=='\n' || key=='\r')
		key = def;
	return key=='y';
}

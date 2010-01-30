/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_cons.h>
#include <string.h>
#if HAVE_DIETLINE
#include <r_line.h>

extern char *dl_readline(int argc, const char **argv);
#endif

R_API int r_cons_arrow_to_hjkl(int ch)
{
	if (ch==0x1b) {
		ch = r_cons_readchar();
		if (ch==0x5b) {
			// TODO: must also work in interactive visual write ascii mode
			ch = r_cons_readchar();
			switch(ch) {
			case 0x35: ch='K'; break; // re.pag
			case 0x36: ch='J'; break; // av.pag
			case 0x41: ch='k'; break; // up
			case 0x42: ch='j'; break; // down
			case 0x43: ch='l'; break; // right
			case 0x44: ch='h'; break; // left
			case 0x3b: break;
			default: ch = 0;
			}
		}
	}
	return ch;
}

// XXX no control for max length here?!?!
R_API int r_cons_fgets(char *buf, int len, int argc, const char **argv)
{
	if (r_cons_instance.user_fgets)
		return r_cons_instance.user_fgets (buf, 512);
	else {
#if HAVE_DIETLINE
		char *ptr;
		buf[0]='\0';
		ptr = r_line_readline ((argv)?argc:CMDS, (argv)?argv:radare_argv);
		if (ptr == NULL)
			return -1;
		strncpy (buf, ptr, len);
#else
		buf[0]='\0';
		if (fgets (buf, len, r_cons_instance.fdin) == NULL)
			return -1;
		if (feof (r_cons_instance.fdin))
			return -1;
		buf[strlen(buf)-1]='\0';
#endif
	}
	return strlen (buf);
}

R_API void r_cons_any_key()
{
	r_cons_strcat ("\n--press any key--\n");
	r_cons_flush ();
	r_cons_readchar ();
	//r_cons_strcat ("\x1b[2J\x1b[0;0H"); // wtf?
}

R_API int r_cons_readchar()
{
	char buf[2];
#if __WINDOWS__
	BOOL ret;
	DWORD out;
	LPDWORD mode;
	HANDLE h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &mode);
	SetConsoleMode (h, 0); // RAW
	ret = ReadConsole (h, buf,1, &out, NULL);
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

/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_cons.h>
#include <r_line.h>
#include <string.h>

#define CMDS 54
static const char *radare_argv[CMDS] ={
	NULL, // padding
	"? ",
	"!step ",
	"!stepo ",
	"!cont ",
	"!signal ",
	"!fd ",
	"!maps ",
	".!maps*",
	"!bp ",
	"!!",
	"#md5",
	"#sha1",
	"#crc32",
	"#entropy",
	"Visual",
	"ad",
	"ac",
	"ag",
	"emenu ",
	"eval ",
	"seek ",
	"info ",
	"help ",
	"move ",
	"quit ",
	"flag ",
	"Po ",
	"Ps ",
	"Pi ",
	"H ",
	"H no ",
	"H nj ",
	"H fj ",
	"H lua ",
	"x ",
	"b ",
	"y ",
	"yy ",
	"y? ",
	"wx ",
	"ww ",
	"wf ",
	"w?",
	"pD ",
	"pG ",
	"pb ",
	"px ",
	"pX ",
	"po ",
	"pm ",
	"pz ",
	"pr > ",
	"p? "
};

char *dl_readline(int argc, const char **argv);
int r_cons_fgets(char *buf, int len, int argc, const char **argv)
{
#if HAVE_DIETLINE
	/* TODO: link against dietline if possible for autocompletion */
	char *ptr;
	buf[0]='\0';
	ptr = r_line_readline((argv)?argc:CMDS, (argv)?argv:radare_argv);
	if (ptr == NULL)
		return -1;
	strncpy(buf, ptr, len);
#else
	int ret ;
	buf[0]='\0';
	ret = fgets(buf, len, r_cons_stdin_fd);
	if (ret<0)
		return -1;
	buf[strlen(buf)-1]='\0';
#endif
	return strlen(buf);
}


void r_cons_any_key()
{
	r_cons_strcat("\n--press any key--\n");
	r_cons_flush();
	r_cons_readchar();
	r_cons_strcat("\x1b[2J\x1b[0;0H");
}

int r_cons_readchar()
{
	char buf[2];
#if __WINDOWS__
	DWORD out;
	BOOL ret;
	LPDWORD mode;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(h, &mode);
	SetConsoleMode(h, 0); // RAW
	ret = ReadConsole(h, buf,1, &out, NULL);
	if (!ret)
		return -1;
	SetConsoleMode(h, mode);
#else
	if (read(0, buf, 1)==-1)
		return -1;
#endif
	return buf[0];
}

/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */
/* dietline is a lighweight and portable library similar to GNU readline */

#include <r_line.h>

#include <string.h>
#include <stdlib.h>

#if __WINDOWS__
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#endif

#define I r_line_instance

static char *r_line_nullstr = "";

/* initialize history stuff */
R_API int r_line_dietline_init()
{
#if 0
	if (labels==NULL)
		labels = malloc(BLOCK);
#endif
	ZERO_FILL (&I.history);
	ZERO_FILL (&I.completion);
	I.history.data = (char **)malloc ((I.history.size+1024)*sizeof(char *));
	if (I.history.data==NULL)
		return R_FALSE;
	I.history.size = R_LINE_HISTSIZE;
	memset (I.history.data, 0, I.history.size*sizeof(char *));
	I.echo = R_TRUE;
	return R_TRUE;
}

static int r_line_readchar()
{
	char buf[2];
	*buf = '\0';
#if __WINDOWS__
	BOOL ret;
	LPDWORD mode, out;
	HANDLE h = GetStdHandle (STD_INPUT_HANDLE);

	GetConsoleMode (h, &mode);
	SetConsoleMode (h, 0); // RAW
	ret = ReadConsole (h, buf, 1, &out, NULL);
	// wine hack-around
	if (!ret && read (0, buf, 1) != 1)
		return -1;
	SetConsoleMode (h, mode);
#else
	if (read (0, buf, 1) != 1)
		return -1;
#endif
	return buf[0];
}

R_API int r_line_hist_add(const char *line)
{
	if (I.history.top>=I.history.size)
		I.history.top = I.history.index = 0; // workaround
	if (*line) { // && I.history.index < I.history.size) {
		I.history.data[I.history.top++] = strdup(line);
		I.history.index = I.history.top;
		return R_TRUE;
	}
	return R_FALSE;
}

static int r_line_hist_up()
{
	if (I.history.index>0) {
		strncpy (I.buffer.data, I.history.data[--I.history.index], R_LINE_BUFSIZE-1);
		I.buffer.index = I.buffer.length = strlen (I.buffer.data);
		return R_TRUE;
	}
	return R_FALSE;
}

static int r_line_hist_down()
{
	I.buffer.index = 0;
	if (I.history.index<I.history.size) {
		if (I.history.data[I.history.index] == NULL) {
			I.buffer.data[0]='\0';
			I.buffer.index = I.buffer.length = 0;
			return 0;
		}
		strncpy (I.buffer.data, I.history.data[I.history.index++], R_LINE_BUFSIZE-1);
		I.buffer.index = I.buffer.length = strlen (I.buffer.data);
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_line_hist_list()
{
	int i = 0;
	if (I.history.data != NULL)
	for (i=0; i<I.history.size; i++) {
		if (I.history.data[i] == NULL)
			break;
		printf ("%.3d  %s\n", i, I.history.data[i]);
	}
	return i;
}

R_API void r_line_hist_free()
{
	int i;
	if (I.history.data != NULL)
	for (i=0; i<I.history.size; i++) {
		free (I.history.data[i]);
		I.history.data[i] = NULL;
	}
	free (I.history.data);
	I.history.data = NULL;
	I.history.index = 0;
}

/* load history from file. if file == NULL load from ~/.<prg>.history or so */
R_API int r_line_hist_load(const char *file)
{
	char buf[1024];
	FILE *fd;

	// XXX dupped shitty code.. see hist_save ()
	snprintf (buf, 1023, "%s/%s", r_sys_getenv ("HOME"), file);
	fd = fopen (buf, "r");
	if (fd == NULL)
		return R_FALSE;

	fgets (buf, 1023, fd);
	while (!feof(fd)) {
		buf[strlen (buf)-1]='\0';
		r_line_hist_add (buf);
		fgets (buf, 1023, fd);
	}
	fclose (fd);
	return R_TRUE;
}

R_API int r_line_hist_save(const char *file)
{
	char buf[1024];
	FILE *fd;
	int i;

	snprintf (buf, 1023, "%s/%s", r_sys_getenv ("HOME"), file);
	fd = fopen (buf, "w");
	if (fd == NULL)
		return R_FALSE;
	for(i=0; i<I.history.index; i++) {
		fputs (I.history.data[i], fd);
		fputs ("\n", fd);
	}
	fclose (fd);
	return R_TRUE;
}

R_API int r_line_hist_chop(const char *file, int limit)
{
	/* TODO */
	return 0;
}

R_API void r_line_autocomplete()
{
	int argc;
	const char **argv;
	int i, opt, len = 0;

	/* prepare argc and argv */
	if (I.completion.run != NULL)
		I.completion.run (&I);

	argc = I.completion.argc;
	argv = I.completion.argv;

	if (I.buffer.index>0)
	for (i=0,opt=0; argv[i] && i<argc; i++)
		if (!strncmp (argv[i], I.buffer.data, I.buffer.index))
			opt++;

	if (I.buffer.length>0 && opt==1)
	for (i=0; i<argc; i++) {
		if (!strncmp (I.buffer.data, argv[i], I.buffer.length)) {
			strcpy (I.buffer.data, argv[i]);
			I.buffer.index = I.buffer.length = strlen (I.buffer.data) + 1;
			/* fucking inneficient */
			strcat (I.buffer.data, " ");
			I.buffer.length = ++I.buffer.index;
			break;
		}
	}

	/* show options */
	if (I.buffer.index==0 || opt>1) {
		if (I.echo)
			printf ("%s%s\n", I.prompt, I.buffer.data);
		for (i=0; i<argc; i++) {
			if (argv[i] != NULL)
			if (I.buffer.length==0 || !strncmp (argv[i], I.buffer.data, I.buffer.length)) {
				len += strlen (argv[i]);
	//			if (len+I.buffer.length+4 >= columns) break;
				if (I.echo)
					printf ("%s ", argv[i]);
			}
		}
		if (I.echo)
			printf ("\n");
	}
	fflush (stdout);
}

/* main readline function */
//R_API char *r_line_readline(const char *prompt, RLineCallba 
R_API char *r_line_readline()
{
	char buf[10];
	int ch, i, gcomp = 0; /* grep completion */
	int columns = r_cons_get_size (NULL)-2;

	I.buffer.index = I.buffer.length = 0;
	I.buffer.data[0] = '\0';
	if (I.disable) {
		I.buffer.data[0]='\0';
		if (!fgets (I.buffer.data, R_LINE_BUFSIZE-1, stdin))
			return NULL;
		I.buffer.data[strlen (I.buffer.data)] = '\0';
		return (*I.buffer.data)? I.buffer.data : r_line_nullstr;
	}

	memset (&buf, 0, sizeof buf);
	r_cons_set_raw (1);

	if (I.echo) {
		printf ("%s", I.prompt);
		fflush (stdout);
	}
#if __UNIX__
	/* TODO: move into r_line_readchar() */
	if (feof (stdin))
		return NULL;
#endif
	for (;;) {
#if 0
		if (I.echo) {
			printf("  (");
			for(i=1;i<argc;i++) {
				if (I.buffer.length==0||!strncmp(argv[i], I.buffer.data, I.buffer.length)) {
					len+=strlen(argv[i])+1;
					if (len+I.buffer.length+4 >= columns) break;
					printf("%s ", argv[i]);
				}
			}
			printf(")");
			fflush(stdout);
		}
#endif

		I.buffer.data[I.buffer.length]='\0';
		ch = r_line_readchar ();
		if (ch == -1)
			return NULL;
		buf[0] = ch;
		
//		printf("\x1b[K\r");
		columns = r_cons_get_size (NULL)-2;
		if (columns<1)
			columns = 40;
		if (I.echo)
			printf ("\r%*c\r", columns, ' ');

		switch (buf[0]) {
		//case -1: // ^D
		//	return NULL;
		case 0: // control-space
			/* ignore atm */
			break;
		case 1: // ^A
			I.buffer.index = 0;
			break;
		case 5: // ^E
			I.buffer.index = I.buffer.length;
			break;
		case 3: // ^C 
			if (I.echo)
				printf ("\n^C\n");
			I.buffer.index = I.buffer.length = 0;
			*I.buffer.data = '\0';
			goto _end;
		case 4: // ^D
			if (I.echo)
				printf ("^D\n");
			if (!I.buffer.data[0]) { /* eof */
				r_cons_set_raw (R_FALSE);
				return NULL;
			}
			break;
		case 10: // ^J -- ignore
			return I.buffer.data;
		case 11: // ^K -- ignore
			break;
		case 12: // ^L -- right
			I.buffer.index = (I.buffer.index<I.buffer.length)?
				I.buffer.index+1 : I.buffer.length;
			if (I.echo)
				printf ("\x1b[2J\x1b[0;0H");
			fflush (stdout);
			break;
		case 18: // ^R -- autocompletion
			gcomp = 1;
			break;
		case 19: // ^S -- backspace
			if (gcomp) gcomp--;
			else I.buffer.index = I.buffer.index? I.buffer.index-1: 0;
			break;
		case 21: // ^U - cut
			free (I.clipboard);
			I.clipboard = strdup (I.buffer.data);
			I.buffer.data[0] = '\0';
			I.buffer.length = 0;
			I.buffer.index = 0;
			break;
		case 23: // ^W
			if (I.buffer.index>0) {
				for (i=I.buffer.index-1; i&&I.buffer.data[i]==' '; i--);
				for (; i&&I.buffer.data[i]!=' '; i--);
				for (; i>0&&I.buffer.data[i]==' '; i--);
				if (i>1) {
					if (I.buffer.data[i+1]==' ')
					i+=2;
				} else if (i<0) i=0;
				strcpy (I.buffer.data+i, I.buffer.data+I.buffer.index);
				I.buffer.length = strlen (I.buffer.data);
				I.buffer.index = i;
			}
			break;
		case 25: // ^Y - paste
			if (I.clipboard != NULL) {
				I.buffer.length += strlen(I.clipboard);
				// TODO: support endless strings
				if (I.buffer.length < R_LINE_BUFSIZE) {
					I.buffer.index = I.buffer.length;
					strcat (I.buffer.data, I.clipboard);
				} else I.buffer.length -= strlen (I.clipboard);
			}
			break;
		case 16:
			r_line_hist_up ();
			break;
		case 14:
			r_line_hist_down ();
			break;
		case 27: //esc-5b-41-00-00
			buf[0] = r_line_readchar();
			if (buf[0] == -1)
				return NULL;
			buf[1] = r_line_readchar();
			if (buf[1] == -1)
				return NULL;
			if (buf[0]==0x5b) {
				switch(buf[1]) {
				case 0x33: // supr
					if (I.buffer.index<I.buffer.length)
						strcpy (I.buffer.data+I.buffer.index,
							I.buffer.data+I.buffer.index+1);
					buf[1] = r_line_readchar ();
					if (buf[1] == -1)
						return NULL;
					break;
				/* arrows */
				case 0x41:
					r_line_hist_up ();
					break;
				case 0x42:
					r_line_hist_down ();
					break;
				case 0x43:
					I.buffer.index = I.buffer.index<I.buffer.length?
						I.buffer.index+1: I.buffer.length;
					break;
				case 0x44:
					I.buffer.index = I.buffer.index?I.buffer.index-1:0;
					break;
				}
			}
			break;
		case 8:
		case 127:
			if (I.buffer.index < I.buffer.length) {
				if (I.buffer.index>0) {
					I.buffer.index--;
					memcpy (I.buffer.data+I.buffer.index,
						I.buffer.data+I.buffer.index+1,
						strlen (I.buffer.data+I.buffer.index));
				}
			} else {
				I.buffer.index = --I.buffer.length;
				if (I.buffer.length<0) I.buffer.length=0;
				I.buffer.data[I.buffer.length]='\0';
			}
			if (I.buffer.index<0)
				I.buffer.index = 0;
			break;
		case 9: // tab
			r_line_autocomplete ();
			break;
		case 13: 
			goto _end;
#if 0
			// force command fit
			for(i=1;i<argc;i++) {
				if (I.buffer.length==0 || !strncmp(argv[i], I.buffer.data, I.buffer.length)) {
					printf("%*c", columns, ' ');
					printf("\r");
					printf("\n\n(%s)\n\n", I.buffer.data);
					r_cons_set_raw(0);
					return I.buffer.data;
				}
			}
#endif
		default:
			if (gcomp)
				gcomp++;
			/* XXX use ^A & ^E */
			if (I.buffer.index<I.buffer.length) {
				for(i = ++I.buffer.length;i>I.buffer.index;i--)
					I.buffer.data[i] = I.buffer.data[i-1];
				I.buffer.data[I.buffer.index] = buf[0];
			} else {
				I.buffer.data[I.buffer.length]=buf[0];
				I.buffer.length++;
				if (I.buffer.length>1000)
					I.buffer.length--;
				I.buffer.data[I.buffer.length]='\0';
			}
			I.buffer.index++;
			break;
		}
		if (I.echo) {
			if (gcomp) {
				if (I.buffer.length == 0)
					gcomp = 0;
				printf ("\r (reverse-i-search): %s\r", I.buffer.data);
			} else {
				printf ("\r%s%s", I.prompt, I.buffer.data);
				printf ("\r%s", I.prompt);
			}
		
			for (i=0;i<I.buffer.index;i++)
				printf ("%c", I.buffer.data[i]);
			fflush (stdout);
		}
	}
_end:
	r_cons_set_raw (0);
	if (I.echo) {
		printf ("\r%s%s\n", I.prompt, I.buffer.data);
		fflush (stdout);
	}

	if (I.buffer.data[0]=='!' && I.buffer.data[1]=='\0') {
		r_line_hist_list ();
		return r_line_nullstr;
	}
	if (I.buffer.data == NULL)
		return r_line_nullstr;
	return I.buffer.data;
}

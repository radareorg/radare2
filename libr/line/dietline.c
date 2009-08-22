/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_line.h"

/* dietline is a lighweight and portable library similar to GNU readline */

#include <string.h>
#include <stdlib.h>

#if __WINDOWS__
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#endif

/* line input */
int r_line_echo = 1;
const char *r_line_prompt = "> ";
const char *r_line_clipboard = NULL;
static char *r_line_nullstr = "";
static char r_line_buffer[R_LINE_BUFSIZE];
static int r_line_buffer_len = 0;
static int r_line_buffer_idx = 0;

/* autocompletion callback */
char **(*r_line_callback)(const char *text, int start, int end) = NULL;

/* history */
char **r_line_history = NULL;
int r_line_histsize = R_LINE_HISTSIZE;
int r_line_histidx = 0;
int r_line_histtop = 0;
int r_line_autosave = 0; // TODO
int r_line_disable = 0; // TODO use fgets..no autocompletion

// TODO : FULL READLINE COMPATIBILITY
// rl_attempted_completion_function = rad_autocompletion;
// char **rad_autocompletion(const char *text, int start, int end)
// return  matches = rl_completion_matches (text, rad_offset_matches);

static int r_line_readchar()
{
	char buf[2];
#if __WINDOWS__
	LPDWORD out;
	BOOL ret;
	LPDWORD mode;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);

	GetConsoleMode(h, &mode);
	SetConsoleMode(h, 0); // RAW
	ret = ReadConsole(h, buf,1, &out, NULL);
	if (!ret) {
		// wine hack-around
		if (read(0,buf,1) != 1)
			return -1;
	}
	SetConsoleMode(h, mode);
#else
	int ret = read(0,buf,1);
	if (ret <1)
		return -1;
#endif
	//printf("CHAR(%d)\n", buf[0]);
	return buf[0];
}

/* scripting */

/* TODO: remove label related stuff */
#if 0
#define BLOCK 4096
static char *labels = NULL;
static ut32 size = 0;
static ut32 lsize = 0;

static int label_get(char *name)
{
	int i, n;
	for(i=0;i<size;i++) {
		if (!strcmp(name, labels+i+4)) {
			memcpy(&n, labels+i, 4);
			return n;
		}
		i+=strlen(labels+i+4)+4;
	}
	return -1;
}

static void label_add (const char *str) {
	ut32 size = r_line_histidx;
	ut32 len = strlen(str)-1;

	fprintf(stderr, "New label(%s)\n",str); // XXX debug
	memset(labels+lsize+4, '\0', BLOCK-((lsize+len+4)%BLOCK));
	memcpy(labels+lsize, &size, 4);
	memcpy(labels+lsize+4, str, len);
	lsize+=len+4+1;
}

void r_line_label_show()
{
	ut32 i, p, n = 0;
	for(i=0;i<lsize;i++,n++) {
		memcpy(&p, labels+i, 4);
		printf(" %03d %03d  %s\n", i, p, labels+i+4);
		i+=strlen(labels+i+4)+4;
	}
}

static void label_reset()
{
	lsize = 0;
	free(labels);
	labels = NULL;
}

static int is_label(const char *str)
{
	if (str[0]=='\0')
		return 0;
	if (str[strlen(str)-1]==':') {
		if (str[0]==':') {
			r_line_label_show();
			return 2;
		}
		return 1;
	}
	return 0;
}
#endif

/* history stuff */

int r_line_hist_label(const char *label, void (*cb)(const char*))
{
	int i;

#if 0
	if (label[0]=='.') {
		if (!is_label(label+1))
			return 0;
	} else {
		switch(is_label(label)) {
		case 0:
		case 2:
			return 0;
		}
	}
#endif

#if 0
	i = label_get(label);
	if (i == -1) {
		label_add(label);
		return 1;
	}
#endif

	if (r_line_history != NULL)
	for(i=0;i<r_line_histsize; i++) {
		if (r_line_history[i] == NULL)
			break;
		fprintf(stderr, "%s\n", r_line_history[i]);
		if (cb != NULL)
			cb(r_line_history[i]);
		else	fprintf(stderr, "%s\n", r_line_history[i]);
	}

	return 1;
}

R_API int r_line_hist_add(const char *line)
{
#if HAVE_LIB_READLINE
	add_history(line);
#endif
	if (r_line_histtop>=r_line_histsize)
		r_line_histtop = r_line_histidx = 0; // workaround
	if (*line) { // && r_line_histidx < r_line_histsize) {
		r_line_history[r_line_histtop++] = strdup(line);
		r_line_histidx = r_line_histtop;
		return 1;
	}
	return 0;
//#endif
}

static int r_line_hist_up()
{
	if (r_line_histidx>0) {
		strncpy(r_line_buffer, r_line_history[--r_line_histidx], R_LINE_BUFSIZE-1);
		r_line_buffer_idx = \
		r_line_buffer_len = strlen(r_line_buffer);
		return 1;
	}
	return 0;
}

static int r_line_hist_down()
{
	r_line_buffer_idx=0;
	if (r_line_histidx<r_line_histsize) {
		if (r_line_history[r_line_histidx] == NULL) {
			r_line_buffer[0]='\0';
			r_line_buffer_idx = r_line_buffer_len = 0;
			return 0;
		}
		strncpy(r_line_buffer, r_line_history[r_line_histidx++], R_LINE_BUFSIZE-1);
		r_line_buffer_idx=
		r_line_buffer_len = strlen(r_line_buffer);
		return 1;
	}
	return 0;
}

R_API int r_line_hist_list()
{
	int i = 0;

	if (r_line_history != NULL)
	for(i=0;i<r_line_histsize; i++) {
		if (r_line_history[i] == NULL)
			break;
		printf("%.3d  %s\n", i, r_line_history[i]);
	}

	return i;
}

R_API int r_line_hist_free()
{
	int i;
	if (r_line_history != NULL)
	for(i=0;i<r_line_histsize; i++) {
		free(r_line_history[i]);
		r_line_history[i] = NULL;
	}
	return r_line_histidx=0, r_line_histsize;
}

/* TODO: we need an state..? */
R_API void r_line_free()
{
	printf("Bye!\n");
	r_line_hist_free();
	//label_reset();
	free(r_line_history);
}

/* load history from file. if file == NULL load from ~/.<prg>.history or so */
R_API int r_line_hist_load(const char *file)
{
#if HAVE_LIB_READLINE
	rad_readline_init();
	return 0;
#else
	char buf[1024];
	FILE *fd;

	snprintf(buf, 1023, "%s/%s", getenv("HOME"), file);
	fd = fopen(buf, "r");
	if (fd == NULL)
		return 0;

	fgets(buf, 1023, fd);
	while (!feof(fd)) {
		buf[strlen(buf)-1]='\0';
		r_line_hist_add(buf);
		fgets(buf, 1023, fd);
	}
	fclose(fd);

	return 1;
#endif
}

R_API int r_line_hist_save(const char *file)
{
#if HAVE_LIB_READLINE
	rad_readline_finish();
#else
	char buf[1024];
	FILE *fd;
	int i;

	snprintf(buf, 1023, "%s/%s", getenv("HOME"), file);
	fd = fopen(buf, "w");
	if (fd == NULL)
		return 0;
	for(i=0;i<r_line_histidx;i++) {
		fputs(r_line_history[i], fd);
		fputs("\n", fd);
	}
	fclose(fd);
	
	return 1;
#endif
}

R_API int r_line_hist_chop(const char *file, int limit)
{
	/* TODO */
	return 0;
}

/* initialize history stuff */
R_API int r_line_init()
{
#if HAVE_LIB_READLINE
	rad_readline_init();
#endif
#if 0
	if (labels==NULL)
		labels = malloc(BLOCK);
#endif
	r_line_history = (char **)malloc(r_line_histsize*sizeof(char *));
	if (r_line_history==NULL)
		return 0;
	memset(r_line_history, '\0', r_line_histsize*sizeof(char *));
	r_line_histidx = 0;
	r_line_histsize = R_LINE_HISTSIZE;
	r_line_histidx = 0;
	r_line_autosave = 0;
	r_line_disable = 0;
	return 1;
}

/* TODO: Remove this test case .. this is not R_API */
static int r_line_printchar()
{
	unsigned char buf[10];

	r_cons_set_raw(1);
	buf[0]=r_line_readchar();

	switch(buf[0]) {
	case 226:
	case 197:
	case 195:
	case 194:
		buf[0] = r_line_readchar();
		printf("unicode-%02x-%02x\n", buf[0],buf[1]);
		break;
	case 8: // wtf is 127?
	case 127: printf("backspace\n"); break;
	case 32: printf("space\n"); break;
	case 27:
		read(0, buf, 5);
		printf("esc-%02x-%02x-%02x-%02x\n",
				buf[0],buf[1],buf[2],buf[3]);
		break;
	case 12: printf("^L\n"); break;
	case 13: printf("intro\n"); break;
	case 18: printf("^R\n"); break;
	case 9: printf("tab\n"); break;
	case 3: printf("control-c\n"); break;
	case 0: printf("control-space\n"); break;
	default:
		printf("(code:%d)\n", buf[0]);
		break;
	}

	r_cons_set_raw(0);

	return buf[0];
}

/* main readline function */
R_API char *r_line_readline(int argc, const char **argv)
{
	int buf[10];
	int i, len = 0;
	int opt = 0;
	int gcomp = 0; /* grep completion */
	int columns = r_cons_get_real_columns()-2;

	r_line_buffer_idx = r_line_buffer_len = 0;
	r_line_buffer[0]='\0';
	// r_line_echo = config.verbose;
	if (r_line_disable) {
		r_line_buffer[0]='\0';
		fgets(r_line_buffer, R_LINE_BUFSIZE-1, stdin);
		r_line_buffer[strlen(r_line_buffer)] = '\0';
		return (*r_line_buffer)? r_line_buffer : r_line_nullstr;
	}

	memset(&buf,0,sizeof buf);
	r_cons_set_raw(1);

	if (r_line_echo) {
		printf("%s", r_line_prompt);
		fflush(stdout);
	}

#if __UNIX__
	if (feof(stdin))
		return NULL;
#endif

	while(1) {
#if 0
		if (r_line_echo) {
			printf("  (");
			for(i=1;i<argc;i++) {
				if (r_line_buffer_len==0||!strncmp(argv[i], r_line_buffer, r_line_buffer_len)) {
					len+=strlen(argv[i])+1;
					if (len+r_line_buffer_len+4 >= columns) break;
					printf("%s ", argv[i]);
				}
			}
			printf(")");
			fflush(stdout);
		}
#endif

		r_line_buffer[r_line_buffer_len]='\0';
		buf[0] = r_line_readchar();
		
//		printf("\x1b[K\r");
		columns = r_cons_get_real_columns()-2;
		if (columns <1)
			columns = 40;
		if (r_line_echo)
		printf("\r%*c\r", columns, ' ');

		switch(buf[0]) {
//		case -1:
//			return NULL;
		case 0: // control-space
			/* ignore atm */
			break;
		case 1: // ^A
			r_line_buffer_idx = 0;
			break;
		case 5: // ^E
			r_line_buffer_idx = r_line_buffer_len;
			break;
		case 3: // ^C 
			if (r_line_echo)
				printf("\n^C\n");
			r_line_buffer[r_line_buffer_idx = r_line_buffer_len = 0] = '\0';
			goto _end;
		case 4: // ^D
			if (r_line_echo)
				printf("^D\n");
			if (!r_line_buffer[0]) { /* eof */
				r_cons_set_raw(0);
				return NULL;
			}
			break;
		case 10: // ^J -- ignore
			return r_line_buffer;
		case 11: // ^K -- ignore
			break;
		case 12: // ^L -- right
			r_line_buffer_idx = r_line_buffer_idx<r_line_buffer_len?r_line_buffer_idx+1:r_line_buffer_len;
			if (r_line_echo)
				printf("\x1b[2J\x1b[0;0H");
			fflush(stdout);
			break;
		case 18: // ^R -- autocompletion
			gcomp = 1;
			break;
		case 19: // ^S -- backspace
			if (gcomp) {
				gcomp--;
			} else r_line_buffer_idx = r_line_buffer_idx?r_line_buffer_idx-1:0;
			break;
		case 21: // ^U - cut
			r_line_clipboard = strdup(r_line_buffer);
			r_line_buffer[0]='\0';
			r_line_buffer_len = 0;
			r_line_buffer_idx = 0;
			break;
		case 23: // ^W
			if (r_line_buffer_idx>0) {
				for(i=r_line_buffer_idx-1;i&&r_line_buffer[i]==' ';i--);
				for(;i&&r_line_buffer[i]!=' ';i--);
				for(;i>0&&r_line_buffer[i]==' ';i--);
				if (i>1) {
					if (r_line_buffer[i+1]==' ')
					i+=2;
				} else if (i<0) i=0;
				strcpy(r_line_buffer+i, r_line_buffer+r_line_buffer_idx);
				r_line_buffer_len = strlen(r_line_buffer);
				r_line_buffer_idx = i;
			}
			break;
		case 25: // ^Y - paste
			if (r_line_clipboard != NULL) {
				r_line_buffer_len += strlen(r_line_clipboard);
				// TODO: support endless strings
				if (r_line_buffer_len < R_LINE_BUFSIZE) {
					r_line_buffer_idx = r_line_buffer_len;
					strcat(r_line_buffer, r_line_clipboard);
				} else r_line_buffer_len -= strlen(r_line_clipboard);
			}
			break;
		case 16:
			r_line_hist_up();
			break;
		case 14:
			r_line_hist_down();
			break;
		case 27: //esc-5b-41-00-00
			buf[0] = r_line_readchar();
			buf[1] = r_line_readchar();
			if (buf[0]==0x5b) {
				switch(buf[1]) {
				case 0x33: // supr
					if (r_line_buffer_idx<r_line_buffer_len)
						strcpy(r_line_buffer+r_line_buffer_idx,
							r_line_buffer+r_line_buffer_idx+1);
					buf[1] = r_line_readchar();
					break;
				/* arrows */
				case 0x41:
					r_line_hist_up();
					break;
				case 0x42:
					r_line_hist_down();
					break;
				case 0x43:
					r_line_buffer_idx = r_line_buffer_idx<r_line_buffer_len?r_line_buffer_idx+1:r_line_buffer_len;
					break;
				case 0x44:
					r_line_buffer_idx = r_line_buffer_idx?r_line_buffer_idx-1:0;
					break;
				}
			}
			break;
		case 8:
		case 127:
			if (r_line_buffer_idx < r_line_buffer_len) {
				if (r_line_buffer_idx>0) {
					r_line_buffer_idx--;
					memcpy(r_line_buffer+r_line_buffer_idx, r_line_buffer+r_line_buffer_idx+1,strlen(r_line_buffer+r_line_buffer_idx));
				}
			} else {
				r_line_buffer_idx = --r_line_buffer_len;
				if (r_line_buffer_len<0) r_line_buffer_len=0;
				r_line_buffer[r_line_buffer_len]='\0';
			}
			if (r_line_buffer_idx<0)
				r_line_buffer_idx = 0;
			break;
		case 9:// tab
			/* autocomplete */
			// XXX does not autocompletes correctly
			// XXX needs to check if valid results have the same prefix (from 1 to N)
			if (r_line_callback != NULL) {
				//const char *from = strrchr(r_line_buffer, ' ');
				//char **res = r_line_callback(r_line_buffer, (from==NULL)?r_line_buffer_idx:from-r_line_buffer, r_line_buffer_len);
				/* TODO: manage res */
			} else {
				if (r_line_buffer_idx>0)
				for(i=1,opt=0;i<argc;i++)
					if (!strncmp(argv[i], r_line_buffer, r_line_buffer_idx))
						opt++;

				if (r_line_buffer_len>0&&opt==1)
					for(i=1;i<argc;i++) {
						if (!strncmp(r_line_buffer, argv[i], r_line_buffer_len)) {
							strcpy(r_line_buffer, argv[i]);
							r_line_buffer_idx = r_line_buffer_len = strlen(r_line_buffer);
							// TODO: if only 1 keyword hits:
							//		if (argv[i][r_line_buffer_len]=='\0') {
							//			strcat(r_line_buffer, " ");
							//			r_line_buffer_len++;
							//		}
							break;
						}
					}

				/* show options */
				if (r_line_buffer_idx==0 || opt>1) {
					if (r_line_echo)
						printf("%s%s\n",r_line_prompt,r_line_buffer);
					for(i=1;i<argc;i++) {
						if (r_line_buffer_len==0||!strncmp(argv[i], r_line_buffer, r_line_buffer_len)) {
							len+=strlen(argv[i]);
				//			if (len+r_line_buffer_len+4 >= columns) break;
							if (r_line_echo)
								printf("%s ", argv[i]);
						}
					}
					if (r_line_echo)
						printf("\n");
				}
				fflush(stdout);
			}
			break;
		case 13: 
			goto _end;
#if 0
			// force command fit
			for(i=1;i<argc;i++) {
				if (r_line_buffer_len==0 || !strncmp(argv[i], r_line_buffer, r_line_buffer_len)) {
					printf("%*c", columns, ' ');
					printf("\r");
					printf("\n\n(%s)\n\n", r_line_buffer);
					r_cons_set_raw(0);
					return r_line_buffer;
				}
			}
#endif
		default:
			if (gcomp) {
				gcomp++;
			}
			/* XXX use ^A & ^E */
			if (r_line_buffer_idx<r_line_buffer_len) {
				for(i = ++r_line_buffer_len;i>r_line_buffer_idx;i--)
					r_line_buffer[i] = r_line_buffer[i-1];
				r_line_buffer[r_line_buffer_idx] = buf[0];
			} else {
				r_line_buffer[r_line_buffer_len]=buf[0];
				r_line_buffer_len++;
				if (r_line_buffer_len>1000)
					r_line_buffer_len--;
				r_line_buffer[r_line_buffer_len]='\0';
			}
			r_line_buffer_idx++;
			break;
		}
		if (r_line_echo) {
			if (gcomp) {
				if (r_line_buffer_len == 0)
					gcomp = 0;
				printf("\r (reverse-i-search): %s\r", r_line_buffer);
			} else {
				printf("\r%s%s", r_line_prompt, r_line_buffer);
				printf("\r%s", r_line_prompt);
			}
		
			for(i=0;i<r_line_buffer_idx;i++)
				printf("%c", r_line_buffer[i]);
			fflush(stdout);
		}
	}

_end:
	r_cons_set_raw(0);
	if (r_line_echo) {
		printf("\r%s%s\n", r_line_prompt, r_line_buffer);
		fflush(stdout);
	}

	if (r_line_buffer[0]=='!' && r_line_buffer[1]=='\0') {
		r_line_hist_list();
		return r_line_nullstr;
	}
	if (r_line_buffer == NULL)
		return r_line_nullstr;
	return r_line_buffer;
}

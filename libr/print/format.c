/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_cons.h"
#include "r_util.h"
#include "r_print.h"

static void print_mem_help()
{
	printf(
	"Usage: pm [times][format] [arg0 arg1]\n"
	"Example: pm 10xiz pointer length string\n"
	"Example: pm {array_size}b @ array_base\n"
	" e - temporally swap endian\n"
	//" D - double (8 bytes)\n"
	" f - float value\n"
	" b - one byte \n"
	" B - show 10 first bytes of buffer\n"
	" d - %%d integer value (4 bytes)\n"
	" w - word (16 bit hexa)\n"
	" q - quadword (8 bytes)\n"
	" p - pointer reference\n"
	" x - 0x%%08x hexadecimal value\n"
	" X - 0x%%08x hexadecimal value and flag (fd @ addr)\n"
	" z - \\0 terminated string\n"
	" Z - \\0 terminated wide string\n"
	" s - pointer to string\n"
	" t - unix timestamp string\n"
	" * - next char is pointer\n"
	" . - skip 1 byte\n");
}

void r_print_format(struct r_print_t *p, u64 seek, const u8* buf, int len, const char *fmt)
{
	/* TODO: needs refactoring */
	unsigned char buffer[256];
	int endian = 0;
	int i,j,idx;
	int times, otimes;
	char tmp, last;
	char *args, *bracket;
	int nargs;
	const char *arg = fmt;
	u64 addr = 0;
	i = j = 0;

	while(*arg && *arg==' ') arg = arg +1;
	/* get times */
	otimes = times = atoi(arg);
	if (times > 0)
		while((*arg>='0'&&*arg<='9')) arg = arg +1;
	bracket = strchr(arg,'{');
	if (bracket) {
		char *end = strchr(arg,'}');
		if (end == NULL) {
			fprintf(stderr, "No end bracket. Try pm {ecx}b @ esi\n");
			return;
		}
		*end='\0';
		times = r_num_math(NULL, bracket+1);
		arg = end + 1;
	}

	if (arg[0]=='\0') {
		print_mem_help();
		return;
	}
	/* get args */
	args = strchr(arg, ' ');
	if (args) {
		args = strdup(args+1);
		nargs = r_str_word_set0(args);
		if (nargs == 0)
			free((void **)&args);
	}

	/* go format */
	i = 0;
	if (times==0) otimes=times=1;
	for(;times;times--) { // repeat N times
		const char * orig = arg;
		if (otimes>1)
			r_cons_printf("0x%08llx [%d] {\n", seek+i, otimes-times);
		for(idx=0;idx<len;idx++, arg=arg+1) {
			addr = 0LL;
			if (endian)
				 addr = (*(buf+i))<<24   | (*(buf+i+1))<<16 | *(buf+i+2)<<8 | *(buf+i+3);
			else     addr = (*(buf+i+3))<<24 | (*(buf+i+2))<<16 | *(buf+i+1)<<8 | *(buf+i);

			tmp = *arg;
		feed_me_again:
			if (tmp == 0 && last != '*')
				break;
			/* skip chars */
			switch(tmp) {
			case ' ':
//config.interrupted =1;
				//i = len; // exit
				continue;
			case '*':
				if (i<=0) break;
				tmp = last;
				arg = arg - 1;
				idx--;
				goto feed_me_again;
			case 'e': // tmp swap endian
				idx--;
				endian ^=1;
				continue;
			case '.': // skip char
				i++;
				idx--;
				continue;
			case '?': // help
				print_mem_help();
				idx--;
				i=len; // exit
				continue;
			}
			if (idx<nargs)
				r_cons_printf("%10s : ", r_str_word_get0(args, idx));
			/* cmt chars */
			switch(tmp) {
	#if 0
			case 'n': // enable newline
				j ^= 1;
				continue;
	#endif
#if 0
			case 't':
				/* unix timestamp */
				D cons_printf("0x%08x = ", config.seek+i);
				{
				/* dirty hack */
				int oldfmt = last_print_format;
				u64 old = config.seek;
				radare_seek(config.seek+i, SEEK_SET);
				radare_read(0);
				print_data(config.seek+i, "8", buf+i, 4, FMT_TIME_UNIX);
				last_print_format=oldfmt;
				radare_seek(old, SEEK_SET);
				}
				break;
#endif
			case 'e': {
				double doub;
				memcpy(&doub, buf+i, sizeof(double));
				r_cons_printf("%e = ", doub);
				r_cons_printf("(double)");
				i+=8;
				}
				break;
			case 'q':
				r_cons_printf("0x%08x = ", seek+i);
				r_cons_printf("(qword)");
				i+=8;
				break;
			case 'b':
				r_cons_printf("0x%08x = ", seek+i);
				r_cons_printf("%d ; 0x%02x ; '%c' ", 
					buf[i], buf[i], IS_PRINTABLE(buf[i])?buf[i]:0);
				i++;
				break;
			case 'B':
				memset(buffer, '\0', 255);
				if (p->read_at)
					p->read_at((u64)addr, buffer, 248, p->user);
				else {
					printf("(cannot read memory)\n");
					break;
				}
				r_cons_printf("0x%08x = ", seek+i);
				for(j=0;j<10;j++) r_cons_printf("%02x ", buf[j]);
				r_cons_strcat(" ... (");
				for(j=0;j<10;j++)
					if (IS_PRINTABLE(buf[j]))
						r_cons_printf("%c", buf[j]);
				r_cons_strcat(")");
				i+=4;
				break;
			case 'd':
				r_cons_printf("0x%08x = ", seek+i);
				r_cons_printf("%d", addr);
				i+=4;
				break;
			case 'x':
				r_cons_printf("0x%08x = ", seek+i);
				r_cons_printf("0x%08x ", addr);
				i+=4;
				break;
			case 'X': {
				u32 addr32 = (u32)addr;
				//char buf[128];
				r_cons_printf("0x%08x = ", seek+i);
				r_cons_printf("0x%08llx ", addr32);
				//if (string_flag_offset(buf, (u64)addr32, -1))
				//	r_cons_printf("; %s", buf);
				i+=4;
				} break;
			case 'w':
			case '1': // word (16 bits)
				r_cons_printf("0x%08x = ", seek+i);
				if (endian)
					 addr = (*(buf+i))<<8  | (*(buf+i+1));
				else     addr = (*(buf+i+1))<<8 | (*(buf+i));
				r_cons_printf("0x%04x ", addr);
				break;
			case 'z': // zero terminated string
				r_cons_printf("0x%08x = ", seek+i);
				for(;buf[i]&&i<len;i++) {
					if (IS_PRINTABLE(buf[i]))
						r_cons_printf("%c", buf[i]);
					else r_cons_strcat(".");
				}
				break;
			case 'Z': // zero terminated wide string
				r_cons_printf("0x%08x = ", seek+i);
				for(;buf[i]&&i<len;i+=2) {
					if (IS_PRINTABLE(buf[i]))
						r_cons_printf("%c", buf[i]);
					else r_cons_strcat(".");
				}
				r_cons_strcat(" ");
				break;
			case 's':
				r_cons_printf("0x%08x = ", seek+i);
				memset(buffer, '\0', 255);
				if (p->read_at)
					p->read_at((u64)addr, buffer, 248, p->user);
				else {
					printf("(cannot read memory)\n");
					break;
				}
				r_cons_printf("0x%08x -> 0x%08x ", seek+i, addr);
				r_cons_printf("%s ", buffer);
				i+=4;
				break;
			default:
				/* ignore unknown chars */
				continue;
			}
		r_cons_newline();
		last = tmp;
		}
		if (otimes>1)
			r_cons_printf("}\n");
		arg = orig;
		idx = 0;
	}
//	free((void *)&args);
}

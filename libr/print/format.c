/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_cons.h"
#include "r_print.h"

void r_print_format(const u8* buf, int len, const char *fmt)
{
	/* TODO: needs refactoring */
#if 0
	unsigned char buffer[256];
	int i,j,idx;
	int times, otimes;
	char tmp, last;
	char *args, *bracket;
	int nargs;
	const char *arg = fmt;
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
			eprintf("No end bracket. Try pm {ecx}b @ esi\n");
			return;
		}
		*end='\0';
		times = get_math(bracket+1);
		arg = end+1;
	}

	if (arg[0]=='\0') {
		print_mem_help();
		return;
	}
	/* get args */
	args = strchr(arg, ' ');
	if (args) {
		args = strdup(args+1);
		nargs = set0word(args);
		if (nargs == 0)
			efree((void **)&args);
	}

	/* go format */
	i = 0;
	if (times==0) otimes=times=1;
	for(;times;times--) {// repeat N times
		const char * orig = arg;
		if (otimes>1)
			cons_printf("0x%08llx [%d] {\n", config.seek+i, otimes-times);
		config.interrupted = 0;
		for(idx=0;!config.interrupted && idx<len;idx++, arg=arg+1) {
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
				cons_printf("%10s : ", get0word(args, idx));
			/* cmt chars */
			switch(tmp) {
	#if 0
			case 'n': // enable newline
				j ^= 1;
				continue;
	#endif
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
			case 'e': {
				double doub;
				memcpy(&doub, buf+i, sizeof(double));
				D cons_printf("%e = ", doub);
				cons_printf("(double)");
				i+=8;
				}
				break;
			case 'q':
				D cons_printf("0x%08x = ", config.seek+i);
				cons_printf("(qword)");
				i+=8;
				break;
			case 'b':
				D cons_printf("0x%08x = ", config.seek+i);
				cons_printf("%d ; 0x%02x ; '%c' ", 
					buf[i], buf[i], is_printable(buf[i])?buf[i]:0);
				i++;
				break;
			case 'B':
				memset(buffer, '\0', 255);
				radare_read_at((u64)addr, buffer, 248);
				D cons_printf("0x%08x = ", config.seek+i);
				for(j=0;j<10;j++) cons_printf("%02x ", buf[j]);
				cons_strcat(" ... (");
				for(j=0;j<10;j++)
					if (is_printable(buf[j]))
						cons_printf("%c", buf[j]);
				cons_strcat(")");
				i+=4;
				break;
			case 'd':
				D cons_printf("0x%08x = ", config.seek+i);
				cons_printf("%d", addr);
				i+=4;
				break;
			case 'x':
				D cons_printf("0x%08x = ", config.seek+i);
				cons_printf("0x%08x ", addr);
				i+=4;
				break;
			case 'X': {
				u32 addr32 = (u32)addr;
				char buf[128];
				D cons_printf("0x%08x = ", config.seek+i);
				cons_printf("0x%08llx ", addr32);
				if (string_flag_offset(buf, (u64)addr32, -1))
					cons_printf("; %s", buf);
				i+=4;
				} break;
			case 'w':
			case '1': // word (16 bits)
				D cons_printf("0x%08x = ", config.seek+i);
				if (endian)
					 addr = (*(buf+i))<<8  | (*(buf+i+1));
				else     addr = (*(buf+i+1))<<8 | (*(buf+i));
				cons_printf("0x%04x ", addr);
				break;
			case 'z': // zero terminated string
				D cons_printf("0x%08x = ", config.seek+i);
				for(;buf[i]&&i<len;i++) {
					if (is_printable(buf[i]))
						cons_printf("%c", buf[i]);
					else cons_strcat(".");
				}
				break;
			case 'Z': // zero terminated wide string
				D cons_printf("0x%08x = ", config.seek+i);
				for(;buf[i]&&i<len;i+=2) {
					if (is_printable(buf[i]))
						cons_printf("%c", buf[i]);
					else cons_strcat(".");
				}
				cons_strcat(" ");
				break;
			case 's':
				D cons_printf("0x%08x = ", config.seek+i);
				memset(buffer, '\0', 255);
				radare_read_at((u64)addr, buffer, 248);
				D cons_printf("0x%08x -> 0x%08x ", config.seek+i, addr);
				cons_printf("%s ", buffer);
				i+=4;
				break;
			default:
				/* ignore unknown chars */
				continue;
			}
		D cons_newline();
		last = tmp;
		}
		if (otimes>1)
			cons_printf("}\n");
		arg = orig;
		idx=0;
	}
	efree((void *)&args);
#endif
}

/* radare - LGPL - Copyright 2007-2011 pancake<nopcode.org> */

#include "r_cons.h"
#include "r_util.h"
#include "r_print.h"

static void print_format_help(RPrint *p) {
	p->printf (
	"Usage: pf [times][format] [arg0 arg1]\n"
	"Example: pf 10xiz pointer length string\n"
	"Example: pf {array_size}b @ array_base\n"
	" e - temporally swap endian\n"
	//" D - double (8 bytes)\n"
	" f - float value\n"
	" b - one byte \n"
	" B - show 10 first bytes of buffer\n" // B must be for binary ??
	" i - %%i integer value (4 bytes)\n"
	" w - word (16 bit hexa)\n"
	" q - quadword (8 bytes)\n"
	" p - pointer reference\n"
	" d - 0x%%08x hexadecimal value\n"
	" x - 0x%%08x hexadecimal value and flag (fd @ addr)\n"
	" z - \\0 terminated string\n"
	" Z - \\0 terminated wide string\n"
	" s - pointer to string\n"
	" t - unix timestamp string\n"
	" * - next char is pointer\n"
	" + - toggle show flags for each offset\n"
	" . - skip 1 byte\n");
}

/* TODO: needs refactoring */
R_API void r_print_format(RPrint *p, ut64 seek, const ut8* buf, int len, const char *fmt) {
	ut8 buffer[256];
	int nargs, i, j, idx, times, otimes, endian;
	char *args, *bracket, tmp, last = 0;
	const char *arg = fmt;
	const char *argend = arg+strlen (fmt);
	char namefmt[8];
	ut64 addr = 0, addr64 = 0, seeki = 0;;
	int viewflags = 0;
	nargs = endian = i = j = 0;

	while (*arg && iswhitechar (*arg)) arg++;
	/* get times */
	otimes = times = atoi (arg);
	if (times > 0)
		while ((*arg>='0'&&*arg<='9')) arg++;
	bracket = strchr (arg,'{');
	if (bracket) {
		char *end = strchr (arg,'}');
		if (end == NULL) {
			eprintf ("No end bracket. Try pm {ecx}b @ esi\n");
			return;
		}
		*end='\0';
		times = r_num_math (NULL, bracket+1);
		arg = end + 1;
	}

	if (arg[0]=='\0') {
		print_format_help (p);
		return;
	}
	/* get args */
	args = strchr (arg, ' ');
	if (args) {
		int l=0, maxl = 0;
		argend = args;
		args = strdup (args+1);
		nargs = r_str_word_set0 (args+1);
		if (nargs == 0)
			R_FREE (args);
		for (i=0;i<nargs;i++) {
			int len = strlen (r_str_word_get0 (args+1, i));
			if (len>maxl) maxl = len;
		}
		l++;
		sprintf (namefmt, "%%%ds : ", maxl);
	}

	/* go format */
	i = 0;
	if (!times) otimes = times = 1;
	for (;times;times--) { // repeat N times
		const char * orig = arg;
		if (otimes>1)
			p->printf ("0x%08"PFMT64x" [%d] {\n", seek+i, otimes-times);
		for (idx=0; arg<argend && i<len && idx<len; idx++, arg++) {
			seeki = seek+i;
			addr = 0LL;
			if (endian)
				 addr = (*(buf+i))<<24   | (*(buf+i+1))<<16 | *(buf+i+2)<<8 | *(buf+i+3);
			else     addr = (*(buf+i+3))<<24 | (*(buf+i+2))<<16 | *(buf+i+1)<<8 | *(buf+i);
			if (endian)
				 addr64 = (ut64)(*(buf+i))<<56 | (ut64)(*(buf+i+1))<<48 | (ut64)*(buf+i+2)<<40 | (ut64)(*(buf+i+3))<<32
				 	| (*(buf+i+4))<<24 | (*(buf+i+5))<<16 | *(buf+i+6)<<8 | *(buf+i+7);
			 else addr64 = ((ut64)(*(buf+i+7)))<<56 | (ut64)(*(buf+i+6))<<48 | (ut64)(*(buf+i+5))<<40 | (ut64)(*(buf+i+4))<<32
				 	| (*(buf+i+3))<<24 | (*(buf+i+2))<<16 | *(buf+i+1)<<8 | *(buf+i);
			tmp = *arg;
		feed_me_again:
			if (tmp == 0 && last != '*')
				break;
			/* skip chars */
			switch (tmp) {
			case '*':
				if (i<=0) break;
				tmp = last;
				arg--;
				idx--;
				goto feed_me_again;
			case '+':
				idx--;
				viewflags = !viewflags;
				continue;
			case 'e': // tmp swap endian
				idx--;
				endian ^= 1;
				continue;
			case '.': // skip char
				i++;
				idx--;
				continue;
			case 'p':
				tmp = (sizeof (void*)==8)? 'q': 'x';
				break;
			case '?': // help
				print_format_help (p);
				idx--;
				i = len; // exit
				continue;
			}
			if (idx<nargs)
				p->printf (namefmt, r_str_word_get0 (args, idx));
			/* cmt chars */
			switch (tmp) {
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
				ut64 old = config.seek;
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
				memcpy (&doub, buf+i, sizeof (double));
				p->printf ("0x%08"PFMT64x" = (double) ", seeki);
				p->printf ("%e", doub);
				i += 8;
				}
				break;
			case 'q':
				p->printf ("0x%08"PFMT64x" = ", seeki);
				p->printf ("(qword) ");
				i += 8;
				p->printf ("0x%08"PFMT64x" ", addr64);
				break;
			case 'b':
				p->printf ("0x%08"PFMT64x" = ", seeki);
				p->printf ("%d ; 0x%02x ; '%c' ", 
					buf[i], buf[i], IS_PRINTABLE (buf[i])?buf[i]:0);
				i++;
				break;
			case 'B':
				memset (buffer, '\0', 255);
				if (!p->iob.read_at) {
					printf ("(cannot read memory)\n");
					break;
				} else p->iob.read_at (p->iob.io, (ut64)addr, buffer, 248);
				p->printf ("0x%08"PFMT64x" = ", seeki);
				for (j=0; j<10; j++) p->printf ("%02x ", buf[j]);
				p->printf(" ... (");
				for (j=0; j<10; j++)
					if (IS_PRINTABLE (buf[j]))
						p->printf ("%c", buf[j]);
				p->printf (")");
				i += 4;
				break;
			case 'i':
				p->printf ("0x%08"PFMT64x" = ", seeki);
				p->printf ("%d", addr);
				i += 4;
				break;
			case 'd':
				p->printf ("0x%08"PFMT64x" = ", seeki);
				p->printf ("%"PFMT64d" ", addr);
				i += 4;
				break;
			case 'x': {
				ut32 addr32 = (ut32)addr;
				//char buf[128];
				p->printf ("0x%08"PFMT64x" = ", seeki);
				p->printf ("0x%08"PFMT64x" ", addr32);
				//if (string_flag_offset(buf, (ut64)addr32, -1))
				//	p->printf("; %s", buf);
				i += 4;
				} break;
			case 'w':
			case '1': // word (16 bits)
				p->printf ("0x%08x = ", seeki);
				if (endian)
					 addr = (*(buf+i))<<8 | (*(buf+i+1));
				else     addr = (*(buf+i+1))<<8 | (*(buf+i));
				p->printf ("0x%04x ", addr);
				break;
			case 'z': // zero terminated string
				p->printf ("0x%08"PFMT64x" = ", seeki);
				for (; buf[i]&&i<len; i++) {
					if (IS_PRINTABLE (buf[i]))
						p->printf ("%c", buf[i]);
					else p->printf (".");
				}
				break;
			case 'Z': // zero terminated wide string
				p->printf ("0x%08"PFMT64x" = ", seeki);
				for (; buf[i]&&i<len; i+=2) {
					if (IS_PRINTABLE (buf[i]))
						p->printf ("%c", buf[i]);
					else p->printf (".");
				}
				p->printf (" ");
				break;
			case 's':
				p->printf ("0x%08"PFMT64x" = ", seeki);
				memset (buffer, '\0', 255);
				if (p->iob.read_at) {
					p->iob.read_at (p->iob.io, (ut64)addr, buffer, 248);
				} else {
					printf ("(cannot read memory)\n");
					break;
				}
				p->printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x" ", seeki, addr);
				p->printf ("%s ", buffer);
				i += 4;
				break;
			default:
				/* ignore unknown chars */
				break;
			}
			if (viewflags && p->offname) {
				const char *s = p->offname (p->user, seeki);
				if (s) p->printf ("@(%s)", s);
				s = p->offname (p->user, addr);
				if (s) p->printf ("*(%s)", s);
			}
			p->printf ("\n");
			last = tmp;
		}
		if (otimes>1)
			p->printf ("}\n");
		arg = orig;
		idx = 0;
	}
//	free((void *)&args);
}

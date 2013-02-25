/* radare - LGPL - Copyright 2007-2013 - pancake */

#include "r_cons.h"
#include "r_util.h"
#include "r_print.h"

static int nullprintf(const char *fmt, ...) { return 0; }

static void print_format_help(RPrint *p) {
	p->printf (
	"Usage: pf[.key[.field[=value]]|[ val]]|[times][format] [arg0 arg1 ...]\n"
	"Examples:\n"
	" pf 10xiz pointer length string\n"
	" pf {array_size}b @ array_base\n"
	" pf.             # list all formats\n"
	" pf.obj xxdz prev next size name\n"
	" pf.obj          # run stored format\n"
	" pf.obj.name     # show string inside object\n"
	" pf.obj.size=33  # set new size\n"
	"Format chars:\n"
	" e - temporally swap endian\n"
	//" D - double (8 bytes)\n"
	" f - float value (4 bytes)\n"
	" c - char (signed byte)\n"
	" b - byte (unsigned)\n"
	" B - show 10 first bytes of buffer\n" // B must be for binary ??
	" i - %%i integer value (4 bytes)\n"
	" w - word (2 bytes unsigned short in hex)\n"
	" q - quadword (8 bytes)\n"
	" p - pointer reference (2, 4 or 8 bytes)\n"
	" d - 0x%%08x hexadecimal value (4 bytes)\n"
	" D - disassemble one opcode\n"
	" x - 0x%%08x hexadecimal value and flag (fd @ addr)\n"
	" z - \\0 terminated string\n"
	" Z - \\0 terminated wide string\n"
	" s - 32bit pointer to string (4 bytes)\n"
	" S - 64bit pointer to string (8 bytes)\n"
	" t - unix timestamp string\n"
	" * - next char is pointer\n"
	" + - toggle show flags for each offset\n"
	" . - skip 1 byte\n");
}

/* TODO: needs refactoring */
R_API int r_print_format(RPrint *p, ut64 seek, const ut8* buf, int len, const char *fmt, int elem, const char *setval) {
	int nargs, i, j, idx, times, otimes, endian;
	int (*realprintf)(const char *str, ...);
	int (*oldprintf)(const char *str, ...);
	const char *argend = fmt+strlen (fmt);
	ut64 addr = 0, addr64 = 0, seeki = 0;;
	char *args, *bracket, tmp, last = 0;
	nargs = endian = i = j = 0;
	const char *arg = fmt;
	int viewflags = 0;
	char namefmt[8];
	ut8 buffer[256];

	endian = p->big_endian;

	oldprintf = NULL;
	realprintf = p->printf;

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
			return 0;
		}
		*end='\0';
		times = r_num_math (NULL, bracket+1);
		arg = end + 1;
	}

	if (*arg=='\0') {
		print_format_help (p);
		return 0;
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
		for (i=0; i<nargs; i++) {
			int len = strlen (r_str_word_get0 (args+1, i));
			if (len>maxl) maxl = len;
		}
		l++;
		snprintf (namefmt, sizeof (namefmt), "%%%ds : ", maxl);
	}

	/* go format */
	i = 0;
	if (!times) otimes = times = 1;
	for (; times; times--) { // repeat N times
		const char * orig = arg;
		if (otimes>1)
			p->printf ("0x%08"PFMT64x" [%d] {\n", seek+i, otimes-times);
		idx = 0;
		arg = orig;
		for (idx=0; arg<argend && *arg; idx++, arg++) {
			seeki = seek+i;
			addr = 0LL;
			if (endian)
				 addr = (*(buf+i))<<24   | (*(buf+i+1))<<16 | *(buf+i+2)<<8 | *(buf+i+3);
			else     addr = (*(buf+i+3))<<24 | (*(buf+i+2))<<16 | *(buf+i+1)<<8 | *(buf+i);
			if (endian)
				 addr64 = (ut64)(*(buf+i))<<56 | (ut64)(*(buf+i+1))<<48
					| (ut64)*(buf+i+2)<<40 | (ut64)(*(buf+i+3))<<32
				 	| (*(buf+i+4))<<24 | (*(buf+i+5))<<16 | *(buf+i+6)<<8 | *(buf+i+7);
			else addr64 = ((ut64)(*(buf+i+7)))<<56 | (ut64)(*(buf+i+6))<<48
					| (ut64)(*(buf+i+5))<<40 | (ut64)(*(buf+i+4))<<32
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
			if (otimes>1)
				p->printf ("   ");
#define MUSTSET (setval && elem == idx)
#define MUSTSEE (elem == -1 || elem == idx)
			if (MUSTSEE) {
				if (!(MUSTSET)) {
					if (oldprintf)
						p->printf = oldprintf;
					if (idx<nargs)
						p->printf (namefmt, r_str_word_get0 (args, idx));
				}
			} else {
				if (!oldprintf)
					oldprintf = p->printf;
				p->printf = nullprintf;
			}
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
			case 'e':
				if (MUSTSET) {
					realprintf ("?e pf e not yet supported\n");
				} else {
					double doub;
					memcpy (&doub, buf+i, sizeof (double));
					p->printf ("0x%08"PFMT64x" = (double) ", seeki);
					p->printf ("%e", doub);
					i += 8;
				}
				break;
			case 'q':
				if (MUSTSET) {
					realprintf ("wv8 %s @ 0x%08"PFMT64x"\n", setval, seeki);
				} else {
					p->printf ("0x%08"PFMT64x" = ", seeki);
					p->printf ("(qword) ");
					p->printf ("0x%08"PFMT64x" ", addr64);
				}
				i += 8;
				break;
			case 'b':
				if (MUSTSET) {
					realprintf ("w %s @ 0x%08"PFMT64x"\n", setval, seeki);
				} else {
					p->printf ("0x%08"PFMT64x" = ", seeki);
					p->printf ("%d ; 0x%02x ; '%c' ", 
						buf[i], buf[i], IS_PRINTABLE (buf[i])?buf[i]:0);
				}
				i++;
				break;
			case 'c':
				if (MUSTSET) {
					realprintf ("?e pf c not yet implemented\n");
				} else {
					p->printf ("0x%08"PFMT64x" = ", seeki);
					p->printf ("%d ; %d ; '%c' ", 
						buf[i], (char)buf[i],
						IS_PRINTABLE (buf[i])?buf[i]:0);
				}
				i++;
				break;
			case 'B':
				if (MUSTSET) {
					realprintf ("?e pf B not yet implemented\n");
				} else {
					memset (buffer, '\0', 255);
					if (!p->iob.read_at) {
						printf ("(cannot read memory)\n");
						break;
					} else p->iob.read_at (p->iob.io, (ut64)addr, buffer, 248);
					p->printf ("0x%08"PFMT64x" = ", seeki);
					for (j=0; j<10; j++) p->printf ("%02x ", buf[j]);
					p->printf (" ... (");
					for (j=0; j<10; j++)
						if (IS_PRINTABLE (buf[j]))
							p->printf ("%c", buf[j]);
					p->printf (")");
				}
				i += 4;
				break;
			case 'i':
				if (MUSTSET) {
					realprintf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki);
				} else {
					p->printf ("0x%08"PFMT64x" = ", seeki);
					p->printf ("%d", addr);
				}
				i += 4;
				break;
			case 'd':
				if (MUSTSET) {
					realprintf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki);
				} else {
					p->printf ("0x%08"PFMT64x" = ", seeki);
					p->printf ("%"PFMT64d" ", addr);
				}
				i += 4;
				break;
			case 'D':
				if (p->disasm && p->user)
					i += p->disasm (p->user, seeki);
				break;
			case 'x':
				if (MUSTSET) {
					realprintf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki);
				} else {
					ut32 addr32 = (ut32)addr;
					p->printf ("0x%08"PFMT64x" = ", seeki);
					p->printf ("0x%08"PFMT64x" ", addr32);
				}
				//if (string_flag_offset(buf, (ut64)addr32, -1))
				//	p->printf("; %s", buf);
				i += 4;
				break;
			case 'w':
			case '1': // word (16 bits)
				if (MUSTSET) {
					realprintf ("wv2 %s @ 0x%08"PFMT64x"\n", setval, seeki);
				} else {
					p->printf ("0x%08x = ", seeki);
					if (endian)
						 addr = (*(buf+i))<<8 | (*(buf+i+1));
					else     addr = (*(buf+i+1))<<8 | (*(buf+i));
					p->printf ("0x%04x ", addr);
				}
				i+=2;
				break;
			case 'z': // zero terminated string
				if (MUSTSET) {
					realprintf ("?e pf z not yet supported\n");
				} else {
					p->printf ("0x%08"PFMT64x" = ", seeki);
					for (; buf[i]&&i<len; i++) {
						if (IS_PRINTABLE (buf[i]))
							p->printf ("%c", buf[i]);
						else p->printf (".");
					}
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
					p->iob.read_at (p->iob.io, (ut64)addr,
						buffer, sizeof (buffer)-8);
				} else {
					printf ("(cannot read memory)\n");
					break;
				}
				p->printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x" ",
					seeki, addr);
				p->printf ("%s ", buffer);
				i += 4;
				break;
			case 'S':
				p->printf ("0x%08"PFMT64x" = ", seeki);
				memset (buffer, '\0', 255);
				if (p->iob.read_at) {
					p->iob.read_at (p->iob.io, addr64,
						buffer, sizeof (buffer)-8);
				} else {
					printf ("(cannot read memory)\n");
					break;
				}
				p->printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x" ",
					seeki, addr);
				p->printf ("%s ", buffer);
				i += 8;
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
			if (tmp != 'D')
				p->printf ("\n");
			last = tmp;
		}
		if (otimes>1)
			p->printf ("}\n");
		arg = orig;
		idx = 0;
	}
	if (oldprintf)
		p->printf = oldprintf;
//	free((void *)&args);
	return i;
}

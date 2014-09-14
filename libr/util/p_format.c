/* radare - LGPL - Copyright 2007-2014 - pancake */

#include "r_cons.h"
#include "r_util.h"
#include "r_print.h"

static int (*realprintf)(const char *str, ...);
static int nullprintf(const char *fmt, ...) { return 0; }

static void print_format_help(RPrint *p) {
	p->printf (
	"Usage: pf[.key[.field[=value]]|[ val]]|[times][ [size] format] [arg0 arg1 ...]\n"
	"Examples:\n"
	" pf 10xiz pointer length string\n"
	" pf {array_size}b @ array_base\n"
	" pf [4]w[7]i     # like pf w..i..."
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
	" X - show n hexpairs (default n=1)"
	" i - %%i integer value (4 bytes)\n"
	" w - word (2 bytes unsigned short in hex)\n"
	" q - quadword (8 bytes)\n"
	" p - pointer reference (2, 4 or 8 bytes)\n"
	" d - 0x%%08x hexadecimal value (4 bytes)\n"
	" D - disassemble one opcode\n"
	" o - 0x%%08o octal value (4 byte)\n"
	" x - 0x%%08x hexadecimal value and flag (fd @ addr)\n"
	" z - \\0 terminated string\n"
	" Z - \\0 terminated wide string\n"
	" s - 32bit pointer to string (4 bytes)\n"
	" S - 64bit pointer to string (8 bytes)\n"
	//" t - unix timestamp string\n"
	" * - next char is pointer (honors asm.bits)\n"
	" + - toggle show flags for each offset\n"
	" : - skip 4 bytes\n"
	" . - skip 1 byte\n");
}

static void updateAddr(const ut8 *buf, int i, int endian, ut64 *addr, ut64 *addr64) {
	if (endian)
		*addr = (*(buf+i))<<24
		| (*(buf+i+1))<<16
		| (*(buf+i+2))<<8
		| (*(buf+i+3));
	else
		*addr = (*(buf+i+3))<<24
		| (*(buf+i+2))<<16
		| (*(buf+i+1))<<8
		| (*(buf+i));
	if (endian)
		*addr64 = (((ut64)(*(buf+i))<<56))
		| ((ut64)(*(buf+i+1))<<48)
		| ((ut64)(*(buf+i+2))<<40)
		| ((ut64)(*(buf+i+3))<<32)
		| ((ut64)(*(buf+i+4))<<24)
		| ((ut64)(*(buf+i+5))<<16)
		| ((ut64)(*(buf+i+6))<<8)
		| ((ut64)(*(buf+i+7)));
	else
		*addr64 =(((ut64)(*(buf+i+7))<<56)) 
		| ((ut64)(*(buf+i+6))<<48)
		| ((ut64)(*(buf+i+5))<<40)
		| ((ut64)(*(buf+i+4))<<32)
		| ((ut64)(*(buf+i+3))<<24)
		| ((ut64)(*(buf+i+2))<<16)
		| ((ut64)(*(buf+i+1))<<8)
		| ((ut64)(*(buf+i)));
}

static void r_print_format_quadword(const RPrint* p, int mustset, const char* setval, ut64 seeki, ut64 addr64) {
	if (mustset) {
		realprintf ("wv8 %s @ 0x%08"PFMT64x"\n", setval, seeki);
	} else {
		p->printf ("0x%08"PFMT64x" = ", seeki);
		p->printf ("(qword) ");
		p->printf ("0x%016"PFMT64x, addr64);
	}
}

static void r_print_format_byte(const RPrint* p, int mustset, const char* setval, ut64 seeki, ut8* buf, int i) {
	if (mustset) {
		realprintf ("\"w %s\" @ 0x%08"PFMT64x"\n", setval, seeki);
	} else {
		p->printf ("0x%08"PFMT64x" = ", seeki);
		p->printf ("%d ; 0x%02x ; '%c'", buf[i], buf[i],
			IS_PRINTABLE (buf[i])?buf[i]:0);
	}
}

static void r_print_format_char(const RPrint* p, int mustset, const char* setval, ut64 seeki, ut8* buf, int i) {
	if (mustset) {
		realprintf ("\"w %s\" @ 0x%08"PFMT64x"\n", setval, seeki);
	} else {
		p->printf ("0x%08"PFMT64x" = ", seeki);
		p->printf ("%d ; %d ; '%c'", buf[i], (char)buf[i],
			IS_PRINTABLE (buf[i])?buf[i]:0);
	}
}

static int r_print_format_ptrstring(const RPrint* p, ut64 seeki, ut64 addr64, ut64 addr, int is64) {
	ut8 buffer[255];
	p->printf ("0x%08"PFMT64x" = ", seeki);
	if (p->iob.read_at) {
		if (is64 == 1)
			p->iob.read_at (p->iob.io, addr64, buffer, sizeof (buffer)-8);
		else
			p->iob.read_at (p->iob.io, (ut64)addr, buffer, sizeof (buffer)-8);
	} else {
		printf ("(cannot read memory)\n");
		return -1;
	}
	p->printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x" ", seeki, addr);
	p->printf ("%s", buffer);
	return 0;
}

// TODO: support unsigned int?
static void r_print_format_hex(const RPrint* p, int mustset, const char* setval, ut64 seeki, ut64 addr) {
	if (mustset) {
		realprintf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki);
	} else {
		p->printf ("0x%08"PFMT64x" = ", seeki);
		p->printf ("%"PFMT64d"", addr);
	}
}

static void r_print_format_octal (const RPrint* p, int mustset, const char* setval, ut64 seeki, ut64 addr) {
	if (mustset) {
		realprintf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki);
	} else {
		ut32 addr32 = (ut32)addr;
		p->printf ("0x%08"PFMT64x" = (octal) ", seeki);
		p->printf ("0%"PFMT64o"", addr32);
	}
	//if (string_flag_offset(buf, (ut64)addr32, -1))
	//	p->printf("; %s", buf);
}

static void r_print_format_hexflag(const RPrint* p, int mustset, const char* setval, ut64 seeki, ut64 addr) {
	if (mustset) {
		realprintf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki);
	} else {
		ut32 addr32 = (ut32)addr;
		p->printf ("0x%08"PFMT64x" = ", seeki);
		p->printf ("0x%08"PFMT64x"", addr32);
	}
	//if (string_flag_offset(buf, (ut64)addr32, -1))
	//	p->printf("; %s", buf);
}

static int r_print_format_10bytes(const RPrint* p, int mustset, const char* setval, ut64 seeki, ut64 addr, ut8* buf) {
	ut8 buffer[255];
	int j;

	if (mustset) {
		realprintf ("?e pf B not yet implemented\n");
	} else {
		if (!p->iob.read_at) {
			printf ("(cannot read memory)\n");
			return -1;
		} else
			p->iob.read_at (p->iob.io, (ut64)addr, buffer, 248);

		p->printf ("0x%08"PFMT64x" = ", seeki);

		for (j=0; j<10; j++)
			p->printf ("%02x ", buf[j]);

		p->printf (" ... (");
		for (j=0; j<10; j++)
			if (IS_PRINTABLE (buf[j]))
				p->printf ("%c", buf[j]);
			else
				p->printf (".");
		p->printf (")");
	}
	return 0;
}

static int r_print_format_hexpairs(const RPrint* p, int mustset, const char* setval, ut64 seeki, ut8* buf, int size) {
	int j;

	if (mustset) {
		realprintf ("?e pf X not yet implemented\n");
	} else {
		p->printf ("0x%08"PFMT64x" = ", seeki);
		size = (size < 1) ? 1 : size;

		for (j=0; j<size; j++)
			p->printf ("%02x ", (ut8)buf[j]);

		p->printf (" ... (");
		for (j=0; j<size; j++)
			if (IS_PRINTABLE (buf[j]))
				p->printf ("%c", buf[j]);
			else
				p->printf (".");
		p->printf (")");
	}
	return size;
}

static void r_print_format_float(const RPrint* p, int mustset, const char* setval, ut64 seeki, ut64 addr) {
	if (mustset)
		realprintf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki);
	else
		p->printf ("0x%08"PFMT64x" = %f", seeki, (float)(addr));
}

// XXX: this is very incomplete. must be updated to handle all format chars
static int computeStructSize(char *fmt) {
	char *end = strchr(fmt, ' ');
	int size = 0, i;
	if (!end)
		return -1;
	*end = 0;
	for (i=0; i<strlen(fmt); i++) {
		switch (fmt[i]) {
			case 'f':
				size += 4;
				break;
			case 'c':
				size++;
				break;
			case 'i':
				size += 4;
				break;
			case 'w':
				size += 2;
				break;
			case 'q':
				size += 8;
				break;
			case 'd':
				size += 4;
				break;
			case 's':
				size += 4;
				break;
			case 'S':
				size += 8;
				break;
			case ':':
				size += 4;
				break;
			case '.':
				size += 1;
				break;
			case '*':
				size += 4;
				i++;
				break;
				// TODO continue list
			default:
				break;
		}
	}
	free(fmt);
	return size;
}

static int r_print_format_struct(RPrint* p, ut64 seek, const ut8* b, int len, char *name, int slide) {
	const char *fmt;
	/*int flag = (slide>=10000) ? -2 : -1;*/
	if ((slide%100) > 14) {
		eprintf ("Too much nested struct, recursion too deep...\n");
		return 0;
	}
	fmt = r_strht_get (p->formats, name);
	r_print_format (p, seek, b, len, fmt, /*flag*/-1, NULL);
	return computeStructSize(strdup(fmt));
}

R_API int r_print_format(RPrint *p, ut64 seek, const ut8* b, const int len,
		const char *fmt, int elem, const char *setval) {
	int nargs, i, j, invalid, nexti, idx, times, otimes, endian, isptr = 0;
	int (*oldprintf)(const char *str, ...);
	const char *argend = fmt+strlen (fmt);
	ut64 addr = 0, addr64 = 0, seeki = 0;;
	char *args = NULL, *bracket, tmp, last = 0;
	const char *arg = fmt;
	int viewflags = 0;
	char namefmt[8];
	static int slide=0;
	ut8 *buf;

	nexti = nargs = i = j = 0;

	if (len < 1)
		return 0;
	buf = malloc (len);
	if (!buf)
		return 0;
	memcpy (buf, b, len);
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
		char *end = strchr (arg, '}');
		if (end == NULL) {
			eprintf ("No end bracket. Try pm {ecx}b @ esi\n");
			goto beach;
		}
		*end='\0';
		times = r_num_math (NULL, bracket+1);
		arg = end + 1;
	}

	if (*arg=='\0' || *arg=='?') {
		print_format_help (p);
		goto beach;
	}

	/* get args */
	args = strchr (arg, ' ');
	if (args) {
		int l=0, maxl = 0;
		argend = args;
		args = strdup (args+1);
		nargs = r_str_word_set0 (args);
		if (nargs == 0)
			R_FREE (args);
		for (i=0; i<nargs; i++) {
			const int len = strlen (r_str_word_get0 (args, i));
			if (len > maxl)
				maxl = len;
		}
		l++;
		snprintf (namefmt, sizeof (namefmt), "%%%ds : ", maxl+6*slide%100);
	}

	/* go format */
	i = 0;
	if (!times)
		otimes = times = 1;
	for (; times; times--) { // repeat N times
		const char * orig = arg;
		if (otimes>1)
			p->printf ("0x%08"PFMT64x" [%d] {\n", seek+i, otimes-times);
		arg = orig;
		for (idx=0; i<len && arg<argend && *arg; arg++) {
			int size;
			char *name = NULL;
			seeki = seek+i;
			addr = 0LL;
			invalid = 0;
			if (arg[0] == '[') {
				char *end = strchr (arg,']');
				if (end == NULL) {
					eprintf ("No end bracket.\n");
					goto beach;
				}
				*end = '\0';
				size = r_num_math (NULL, arg+1);
				arg = end + 1;
				*end = ']';
			} else {
				size = -1;
			}
			updateAddr (buf, i, endian, &addr, &addr64);

			tmp = *arg;

			if (otimes>1)
				p->printf ("   ");
#define MUSTSET (setval && elem == idx)
#define MUSTSEE (elem == -1 || elem == idx)
#define SEEFLAG (elem == -2)
			if (1 && MUSTSEE) {
				if (!(MUSTSET)) {
					if (oldprintf)
						p->printf = oldprintf;
					if (idx<nargs && tmp != 'e' && isptr == 0) {
						p->printf (namefmt, r_str_word_get0 (args, idx));
						idx++;
					}
				}
			} else {
				if (!oldprintf)
					oldprintf = p->printf;
				p->printf = nullprintf;
			}

		feed_me_again:
			switch (isptr) {
			case 1:
				{
				nexti = i + (p->bits/8);
				i = 0;
				if(tmp == '?' )seeki = addr;
				memset (buf, '\0', len);
				p->printf ("(*0x%"PFMT64x") ", addr);
				if (addr == 0) isptr = 3;
				else isptr = 2;
				if (/*addr<(b+len) && addr>=b && */p->iob.read_at) { /* The test was here to avoid segfault in the next line, 
																		but len make it doesnt work... */
					p->iob.read_at (p->iob.io, (ut64)addr, buf, len-4);
					updateAddr (buf, i, endian, &addr, &addr64);
				} else {
					eprintf ("(SEGFAULT: cannot read memory at 0x%08"PFMT64x", Block: %s, blocksize: 0x%x)\n",
							addr, b, len);
					p->printf("\n");
					goto beach;
				}
				}
				break;
			case 2:
				// restore state after pointer seek
				i = nexti;
				seeki = seek+i;
				memcpy (buf, b, len);
				isptr = 0;
				arg--;
				continue;
			}
			if (tmp == 0 && last != '*')
				break;

			/* skip chars */
			switch (tmp) {
			case '*': // next char is a pointer
				isptr = 1;
				arg++;
				tmp = *arg; //last;
				goto feed_me_again;
			case '+': // toggle view flags
				viewflags = !viewflags;
				continue;
			case 'e': // tmp swap endian
				endian ^= 1;
				continue;
			case ':': // skip 4 bytes
				i+=4;
				continue;
			case '.': // skip 1 byte
				i++;
				continue;
			case 'p': // pointer reference
				tmp = (p->bits == 64)? 'q': 'x';
				//tmp = (sizeof (void*)==8)? 'q': 'x';
				break;
			}
			if (1 && SEEFLAG) {
				p->printf ("f %s=0x%08"PFMT64x"\n",
					r_str_word_get0 (args, idx) , seeki);
			}

			if (isptr == 3) {
				p->printf ("NULL");
				isptr = 2;
			} else
			/* cmt chars */
			switch (tmp) {
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
			case 'e': //WTF is this? 'e' is supposed to swap endians?!
				if (size > 0)
					p->printf ("Size not yet implemented\n");
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
				r_print_format_quadword(p, MUSTSET, setval, seeki, addr64);
				i += (size==-1) ? 8 : size;
				break;
			case 'b':
				r_print_format_byte(p, MUSTSET, setval, seeki, buf, i);
				i+= (size==-1) ? 1 : size;
				break;
			case 'c':
				r_print_format_char (p, MUSTSET,
					setval, seeki, buf, i);
				i+= (size==-1) ? 1 : size;
				break;
			case 'X':
				size = r_print_format_hexpairs(p, MUSTSET,
					setval, seeki, buf, size);
				i += size;
				break;
			case 'B':
				if (r_print_format_10bytes (p, MUSTSET,
					setval, seeki, addr, buf) == 0)
					i += (size==-1) ? 4 : size;
				break;
			case 'f':
				r_print_format_float (p, MUSTSET, setval, seeki, addr);
				i+= (size==-1) ? 4 : size;
				break;
			case 'i':
			case 'd':
				r_print_format_hex(p, MUSTSET, setval, seeki, addr);
				i+= (size==-1) ? 4 : size;
				break;
			case 'D':
				if (size>0) p->printf ("Size not yet implemented\n");
				if (p->disasm && p->user)
					i += p->disasm (p->user, seeki);
				break;
			case 'o':
				r_print_format_octal (p, MUSTSET, setval, seeki, addr);
				i+= (size==-1) ? 4 : size;
				break;
			case 'x':
				r_print_format_hexflag(p, MUSTSET, setval, seeki, addr);
				i+= (size==-1) ? 4 : size;
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
					p->printf ("0x%04x", addr);
				}
				i+= (size==-1) ? 2 : size;
				break;
			case 'z': // zero terminated string
				if (MUSTSET) {
					int buflen = strlen ((const char *)buf);
					if (buflen>seeki) {
						buflen = strlen ((const char *)buf+seeki);
					}
					if (strlen (setval) > buflen) {
						eprintf ("Warning: new string is longer than previous one \n");
					}
					realprintf ("\"w %s\" @ 0x%08"PFMT64x"\n", setval, seeki);
				} else {
					p->printf ("0x%08"PFMT64x" = ", seeki);
					for (; ((size || size==-1) && buf[i]) && i<len; i++) {
						if (IS_PRINTABLE (buf[i]))
							p->printf ("%c", buf[i]);
						else p->printf (".");
						size -= (size==-1) ? 0 : 1;
					}
				}
				if (size == -1)
					i++;
				else
					while (size--) i++;
				break;
			case 'Z': // zero terminated wide string
				if (MUSTSET) {
					if ((size = strlen(setval)) > r_wstr_clen((char*)(buf+seeki)))
						eprintf ("Warning: new string is longer than previous one\n");
					realprintf ("\"ww %s\" @ 0x%08"PFMT64x"\n", setval, seeki);
					size*=2;
				} else {
					p->printf ("0x%08"PFMT64x" = ", seeki);
					for (; ((size || size==-1) && buf[i]) && i<len; i+=2) {
						if (IS_PRINTABLE (buf[i]))
							p->printf ("%c", buf[i]);
						else p->printf (".");
						size -= (size==-1) ? 0 : 2;
					}
				}
				if (size == -1)
					i+=2;
				else
					while (size--) i++;
				break;
			case 's':
				if (r_print_format_ptrstring (p, seeki, addr64, addr, 0) == 0)
					i += (size==-1) ? 4 : size;
				break;
			case 'S':
				if (r_print_format_ptrstring (p, seeki, addr64, addr, 1) == 0)
					i += (size==-1) ? 8 : size;
				break;
			case '?':
				{
				int s;
				char *structname = strdup (r_str_word_get0 (args, idx-1));
				if (*structname == '(') {
					name = strchr (structname, ')');
				} else {
					eprintf ("Struct name missing\n");
					free (structname);
					goto beach;
				}
				structname++;
				if (name == NULL) {
					eprintf ("No ')'\n");
				} else {
					*(name++) = '\0';
				}
				p->printf ("<struct>\n");
				/* if (SEEFLAG) slide+=10000;*/
				slide += (isptr) ? 100 : 1;
				s = r_print_format_struct (p, seeki,
					buf+i, len, structname--, slide);
				free (structname);
				i+= (isptr) ? 4 : s;
				slide -= (isptr) ? 100 : 1;
				/*if (SEEFLAG) slide-=10000;*/
				break;
				}
			default:
				/* ignore unknown chars */
				invalid = 1;
				break;
			}
			if (!MUSTSEE || MUSTSET)
				idx++;
			if (viewflags && p->offname) {
				const char *s = p->offname (p->user, seeki);
				if (s)
					p->printf ("@(%s)", s);
				s = p->offname (p->user, addr);
				if (s)
					p->printf ("*(%s)", s);
			}
			if (tmp != 'D' && !invalid && name==NULL)
				p->printf ("\n");
			last = tmp;
		}
		if (otimes>1)
			p->printf ("}\n");
		arg = orig;
	}
	if (oldprintf)
		p->printf = oldprintf;
beach:
	free (buf);
	if (args)
		free (args);
	return i;
}

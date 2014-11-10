/* radare - LGPL - Copyright 2007-2014 - pancake */

#include "r_anal.h"
#include "r_cons.h"
#include "r_print.h"
#include "r_util.h"

static int nullprinter(const char* a, ...) { return 0; }
static int IsInterrupted = 0;

R_API int r_print_is_interrupted() {
	return IsInterrupted;
}

R_API void r_print_set_interrupted(int i) {
	IsInterrupted = i;
}

R_API int r_print_mute(RPrint *p, int x) {
	if (x) {
		if (p->printf == &nullprinter)
			return 0;
		p->oprintf = p->printf;
		p->printf = nullprinter;
		return 1;
	}
	if (p->printf == nullprinter) {
		p->printf = p->oprintf;
		return 1;
	}
	return 0;
}

R_API RPrint *r_print_new() {
	RPrint *p = R_NEW0 (RPrint);
	if (!p) return NULL;
	strcpy (p->datefmt, "%d:%m:%Y %H:%M:%S %z");
	r_io_bind_init (p->iob);
	p->pairs = R_TRUE;
	p->printf = printf;
	p->oprintf = nullprinter;
	p->bits = 32;
	p->stride = 0;
	p->bytespace = 0;
	p->interrupt = 0;
	p->big_endian = CPU_ENDIAN;
	p->col = 0;
	p->width = 78;
	p->cols = 16;
	p->cur_enabled = R_FALSE;
	p->cur = p->ocur = -1;
	p->formats = r_strht_new ();
	p->addrmod = 4;
	p->flags = \
		   R_PRINT_FLAGS_COLOR |
		   R_PRINT_FLAGS_OFFSET |
		   R_PRINT_FLAGS_HEADER |
		   R_PRINT_FLAGS_ADDRMOD;
	p->zoom = R_NEW0 (RPrintZoom);
	return p;
}

R_API RPrint *r_print_free(RPrint *p) {
	if (!p) return NULL;
	r_strht_free (p->formats);
	p->formats = NULL;
	if (p->zoom) {
		free (p->zoom->buf);
		free (p->zoom);
		p->zoom = NULL;
	}
	free (p);
	return NULL;
}

// dummy setter can be removed
R_API void r_print_set_flags(RPrint *p, int _flags) {
	p->flags = _flags;
}

R_API void r_print_unset_flags(RPrint *p, int flags) {
	p->flags = p->flags & (p->flags^flags);
}

R_API void r_print_set_cursor(RPrint *p, int enable, int ocursor, int cursor) {
	if (!p) return;
	p->cur_enabled = enable;
	p->ocur = ocursor;
	if (cursor<0) cursor = 0;
	p->cur = cursor;
}

R_API void r_print_cursor(RPrint *p, int cur, int set) {
	if (!p || !p->cur_enabled)
		return;
	if (p->ocur != -1) {
		int from = p->ocur;
		int to = p->cur;
		r_num_minmax_swap_i (&from, &to);
		if (cur>=from && cur<=to)
			p->printf ("%s", R_CONS_INVERT (set, 1)); //r_cons_invert (set, 1); //p->flags&R_PRINT_FLAGS_COLOR);
	} else
	if (cur==p->cur)
		p->printf ("%s", R_CONS_INVERT (set, 1)); //r_cons_invert (set, 1); //p->flags&R_PRINT_FLAGS_COLOR);
}

R_API void r_print_addr(RPrint *p, ut64 addr) {
#define PREOFF(x) (p && p->cons &&p->cons->pal.x)?p->cons->pal.x
        PrintfCallback printfmt = (PrintfCallback) (p? p->printf: printf);
	int mod = p? (p->flags & R_PRINT_FLAGS_ADDRMOD): 0;
	char ch = p? ((p->addrmod&&mod)?((addr%p->addrmod)?' ':','):' '): ' ';
	int use_color = p? (p->flags & R_PRINT_FLAGS_COLOR): 0;
	int use_segoff = p? (p->flags & R_PRINT_FLAGS_SEGOFF): 0;
	if (use_segoff) {
		ut32 s, a;
		a = addr & 0xffff;
		s = (addr-a)>>4;
		if (use_color) {
			const char *pre = PREOFF(offset): Color_GREEN;
			const char *fin = Color_RESET;
			printfmt ("%s%04x:%04x%c%s", pre, s & 0xffff, a & 0xffff, ch, fin);
		} else printfmt ("%04x:%04x%c", s & 0xffff, a & 0xffff, ch);
	} else {
		if (use_color) {
			const char *pre = PREOFF(offset): Color_GREEN;
			const char *fin = Color_RESET;
			printfmt ("%s0x%08"PFMT64x"%c%s", pre, addr, ch, fin);
		} else printfmt ("0x%08"PFMT64x"%c", addr, ch);
	}
}

#define CURDBG 0
// XXX: redesign ? :)
R_API char *r_print_hexpair(RPrint *p, const char *str, int n) {
	const char *s, *lastcol = Color_WHITE;
	char *d, *dst = (char *)malloc ((strlen (str)+2)*32);
	int colors = p->flags & R_PRINT_FLAGS_COLOR;
	const char *color_0x00, *color_0x7f, *color_0xff, *color_text, *color_other;
	int bs = p->bytespace;
	/* XXX That's hacky as shit.. but partially works O:) */
	/* TODO: Use r_print_set_cursor for win support */
	int cur = R_MIN (p->cur, p->ocur);
	int ocur = R_MAX (p->cur, p->ocur);
	int ch, i;

	if (colors) {
#define P(x) (p->cons &&p->cons->pal.x)?p->cons->pal.x
		color_0x00 = P(b0x00): Color_GREEN;
		color_0x7f = P(b0x7f): Color_YELLOW;
		color_0xff = P(b0xff): Color_RED;
		color_text = P(btext): Color_MAGENTA;
		color_other = P(other): "";
	}
	if (p->cur_enabled && cur==-1)
		cur = ocur;
	ocur++;
#if CURDBG
	sprintf (dst, "(%d/%d/%d/%d)", p->cur_enabled, cur, ocur, n);
	d = dst + strlen (dst);
#else
	d = dst;
#endif
	// XXX: overflow here
// TODO: Use r_cons primitives here
#define memcat(x,y) { memcpy(x,y,strlen(y));x+=strlen(y); }
	//for (s=str, d=dst; *s; s+=2, d+=2, i++) {
	for (s=str, i=0 ; *s; s+=2, d+=2, i++) {
		if (p->cur_enabled) {
			if (i==ocur-n)
				//memcat (d, "\x1b[27;47;30m");
				//memcat (d, "\x1b[0m");//27;47;30m");
				memcat (d, "\x1b[0m");
				memcat (d, lastcol);
			if (i>=cur-n && i<ocur-n)
				memcat (d, "\x1b[7m");
		}
		if (colors) {
			if (s[0]=='0' && s[1]=='0') lastcol = color_0x00;
			else if (s[0]=='7' && s[1]=='f') lastcol = color_0x7f;
			else if (s[0]=='f' && s[1]=='f') lastcol = color_0xff;
			else {
				ch = r_hex_pair2bin (s);
				//sscanf (s, "%02x", &ch); // XXX can be optimized
				if (IS_PRINTABLE (ch))
					lastcol = color_text;
				else lastcol = color_other;
			}
			memcat (d, lastcol);
		}
		memcpy (d, s, 2);
		if (bs) {
			memcpy (d+2, " ",1);
			d++;
		}
	}
	if (colors || p->cur_enabled)
		memcpy (d, Color_RESET, strlen (Color_RESET)+1);
	else *d = 0;
	return dst;
}

R_API void r_print_byte(RPrint *p, const char *fmt, int idx, ut8 ch) {
        PrintfCallback printfmt = (PrintfCallback) (p? p->printf: printf);
	ut8 rch = ch;
	if (!IS_PRINTABLE (ch) && fmt[0]=='%'&&fmt[1]=='c')
		rch = '.';
	r_print_cursor (p, idx, 1);
	if (p && p->flags & R_PRINT_FLAGS_COLOR) {
#define P(x) (p->cons &&p->cons->pal.x)?p->cons->pal.x
		char *color_0x00 = P(b0x00): Color_GREEN;
		char *color_0x7f = P(b0x7f): Color_YELLOW;
		char *color_0xff = P(b0xff): Color_RED;
		char *color_text = P(btext): Color_MAGENTA;
		char *color_other = P(other): Color_WHITE;
		char *pre = NULL;
		switch (ch) {
		case 0x00: pre = color_0x00; break;
		case 0x7F: pre = color_0x7f; break;
		case 0xFF: pre = color_0xff; break;
		default:
			if (IS_PRINTABLE (ch))
				pre = color_text;
			else pre = color_other;
		}
		if (pre) printfmt (pre);
		printfmt (fmt, rch);
		if (pre) printfmt (Color_RESET);
	} else printfmt (fmt, rch);
	r_print_cursor (p, idx, 0);
}

R_API void r_print_code(RPrint *p, ut64 addr, ut8 *buf, int len, char lang) {
	int ws, i, w = p->cols*0.7;
	switch (lang) {
	case '?':
		eprintf ("Valid print code formats are: JSON, C, Python, Cstring (pcj, pc, pcp, pcs) \n"
		"  pc     C\n"
		"  pc*    print 'wx' r2 commands\n"
		"  pcw    C words (4 byte)\n"
		"  pcd    C dwords (8 byte)\n"
		"  pca    Assembly\n"
		"  pcs    string\n"
		"  pcS    shellscript that reconstructs the bin\n"
		"  pcj    json\n"
		"  pcJ    javascript\n"
		"  pcp    python\n");
		break;
	case '*':
		p->printf ("wx ");
		for (i=0; !p->interrupt && i<len; i++) {
			if (i && !(i%16)) p->printf (";s+16\nwx ");
			p->printf ("%02x", buf[i]);
		}
		if (i && !(i%16)) p->printf (";s+16\n");
		else p->printf (";s+%d\n", (i%16));
		p->printf ("s-%d\n", len);
		break;
	case 'a':
		p->printf ("shellcode:");
		for (i=0; !p->interrupt && i<len; i++) {
			if (!(i%8)) p->printf ("\n.byte ");
			else p->printf (", ");
			p->printf ("0x%02x", buf[i]);
		}
		p->printf ("\n.equ shellcode_len, %d\n", len);
		break;
	case 's':
		p->printf ("\"");
		for (i=0; !p->interrupt && i<len; i++) {
			p->printf ("\\x%02x", buf[i]);
		}
		p->printf ("\"\n");
		break;
	case 'S':
		{
			const int trunksize = 16;
			for (i=0; !p->interrupt && i<len; i++) {
				if ((i % trunksize ) == 0)
					p->printf ("printf \"");
				p->printf ("\\%03o", buf[i]);
				if ((i % trunksize ) == (trunksize-1))
					p->printf ("\" %s bin\n", (i <= trunksize) ? ">" : ">>" );
			}
			if ((i % trunksize))
				p->printf("\" %s bin\n", (i <= trunksize) ? ">" : ">>" );
		}
                break;
	case 'J':
		{
		       ut8 *out = malloc (len*3);
		       p->printf ("var buffer = new Buffer(\"");
		       out[0] = 0;
		       r_base64_encode (out, buf, len);
		       p->printf ("%s", out);
		       p->printf ("\", 'base64');\n");
		       free (out);
		}
		break;
	case 'j':
		p->printf ("[");
		for (i=0; !p->interrupt && i<len; i++) {
			r_print_cursor (p, i, 1);
			p->printf ("%d%s", buf[i], (i+1<len)?",":"");
			r_print_cursor (p, i, 0);
		}
		p->printf ("]\n");
		break;
	case 'P':
	case 'p':
		p->printf ("import struct\nbuf = struct.pack (\"%dB\", ", len);
		for (i=0; !p->interrupt && i<len; i++) {
			if (!(i%w)) p->printf ("\n");
			r_print_cursor (p, i, 1);
			p->printf ("0x%02x%c", buf[i], (i+1<len)?',':')');
			r_print_cursor (p, i, 0);
		}
		p->printf ("\n");
		break;
	case 'w':
		{
		ut32 *pbuf = (ut32*)buf;
		w = 5;
		ws = 4;
		len /= ws;
		p->printf ("#define _BUFFER_SIZE %d\n", len);
		p->printf ("unsigned int buffer[%d] = {", len);
		p->interrupt = 0;
		for (i=0; !p->interrupt && i<len; i++) {
			if (!(i%w)) p->printf ("\n  ");
			r_print_cursor (p, i, 1);
			p->printf ("0x%08x, ", pbuf[i]);
			r_print_cursor (p, i, 0);
		}
		p->printf ("};\n");
		}
		break;
	case 'd':
		{
		ut64 *pbuf = (ut64*)buf;
		w = 3;
		ws = 8;
		len /= ws;
		p->printf ("#define _BUFFER_SIZE %d\n", len);
		p->printf ("unsigned long long buffer[%d] = {", len);
		p->interrupt = 0;
		for (i=0; !p->interrupt && i<len; i++) {
			if (!(i%w)) p->printf ("\n  ");
			r_print_cursor (p, i, 1);
			p->printf ("0x%016"PFMT64x", ", pbuf[i]);
			r_print_cursor (p, i, 0);
		}
		p->printf ("};\n");
		}
		break;
	default:
		p->printf ("#define _BUFFER_SIZE %d\n", len);
		p->printf ("unsigned char buffer[%d] = {", len);
		p->interrupt = 0;
		for (i=0; !p->interrupt && i<len; i++) {
			if (!(i%w))
				p->printf ("\n  ");
			r_print_cursor (p, i, 1);
			p->printf ("0x%02x, ", buf[i]);
			r_print_cursor (p, i, 0);
		}
		p->printf ("};\n");
	}
}

R_API int r_print_string(RPrint *p, ut64 seek, const ut8 *buf, int len, int options) {
	int i, wide, zeroend, urlencode;
	wide = (options & R_PRINT_STRING_WIDE);
	zeroend = (options & R_PRINT_STRING_ZEROEND);
	urlencode = (options & R_PRINT_STRING_URLENCODE);
	//if (p->flags & R_PRINT_FLAGS_OFFSET)
		// r_print_addr(p, seek);
	p->interrupt = 0;
	for (i=0; !p->interrupt && i<len; i++) {
		if (zeroend && buf[i]=='\0')
			break;
		r_print_cursor (p, i, 1);
		if (urlencode) {
			// TODO: some ascii can be bypassed here
			p->printf ("%%%02x", buf[i]);
		} else {
			if (buf[i]=='\n' || IS_PRINTABLE (buf[i]))
				p->printf ("%c", buf[i]);
			else p->printf ("\\x%02x", buf[i]);
		}
		r_print_cursor (p, i, 0);
		if (wide) i++;
	}
	p->printf ("\n");
	return i;
}

static const char hex[16] = "0123456789ABCDEF";
R_API void r_print_hexpairs(RPrint *p, ut64 addr, const ut8 *buf, int len) {
	int i;
	for (i=0; i<len; i++)
		p->printf ("%02x ", buf[i]);
}

static int check_sparse (const ut8 *p, int len, int ch) {
	int i;
	ut8 q = *p;
	if (ch && ch != q)
		return 0;
	for (i=1; i<len; i++)
		if (p[i] != q)
			return 0;
	return 1;
}

// XXX: step is borken
R_API void r_print_hexdump(RPrint *p, ut64 addr, const ut8 *buf, int len, int base, int step) {
        PrintfCallback printfmt = (PrintfCallback) printf;
	int i, j, k, inc = 16;
	int sparse_char = 0;
	int stride = 0;
	int col = 0; // selected column (0=none, 1=hex, 2=ascii)
	int use_sparse = 0;
	int use_header = 1;
	int use_offset = 1;
	int use_segoff = 0;
	int pairs = 0;
	const char *fmt = "%02x";
	const char *pre = "";
	int last_sparse = 0;
	const char *a, *b;

	if (p) {
		pairs = p->pairs;
		use_sparse = p->flags & R_PRINT_FLAGS_SPARSE;
		use_header = p->flags & R_PRINT_FLAGS_HEADER;
		use_segoff = p->flags & R_PRINT_FLAGS_SEGOFF;
		use_offset = p->flags & R_PRINT_FLAGS_OFFSET;
		inc = p->cols;
		col = p->col;
		printfmt = (PrintfCallback) p->printf;
		stride = p->stride;
	}
	if (step<1) step = 1;
	if (inc<1)
		inc = 1;
	switch (base) {
	case 8: fmt = "%03o"; pre = " "; break;
	case 10: fmt = "%3d"; pre = " "; break;
	case 32: fmt = "0x%08x "; pre = " "; if (inc<4) inc = 4; break;
	case 64: fmt = "0x%016x "; pre = " "; if (inc<8) inc= 8; break;
	}

	// TODO: Use base to change %03o and so on
	if ((base<32) && use_header) {
		ut32 opad = (ut32)(addr >> 32);
		{ // XXX: use r_print_addr_header
			int i, delta;
			char soff[32];
			if (use_segoff) {
				ut32 s, a;
				a = addr & 0xffff;
				s = ((addr-a)>>4 ) &0xffff;
				snprintf (soff, sizeof (soff), "%04x:%04x ", s, a);
				printfmt ("- offset -");
			} else {
				printfmt ("- offset - ");
				snprintf (soff, sizeof (soff), "0x%08"PFMT64x, addr);
			}
			delta = strlen (soff) - 10;
			for (i=0; i<delta; i++)
				printfmt (" ");
				//printfmt (i+1==delta?" ":" "); // NOP WTF
		}
		printfmt (col==1?"|":" ");
		opad >>= 4;
		k = 0; // TODO: ??? SURE??? config.seek & 0xF;
		/* extra padding for offsets > 8 digits */
		for (i=0; i<inc; i++) {
			printfmt (pre);
			printfmt (" %c", hex[(i+k)%16]);
			if (i&1 || !pairs)
				printfmt (col!=1?" ":((i+1)<inc)?" ":"|");
		}
		printfmt ((col==2)? "|": " ");
		for (i=0; i<inc; i++)
			printfmt ("%c", hex[(i+k)%16]);
		printfmt (col==2?"|\n":"\n");
	}

	if (p) p->interrupt = 0;
	//for (i=j=0; (p&&!p->interrupt) && i<len; i+=(stride?stride:inc), j+=(stride?stride:0)) {
	for (i=j=0; i<len; i+=(stride?stride:inc), j+=(stride?stride:0)) {
		if (use_sparse) {
			if (check_sparse (buf+i, inc, sparse_char)) {
				if (i+inc>=len || check_sparse (buf+i+inc, inc, sparse_char)) {
					if (i+inc+inc>=len || check_sparse (buf+i+inc+inc, inc, sparse_char)) {
						sparse_char = buf[j];
						last_sparse++;
						if (last_sparse==2) {
							printfmt (" ...\n");
							continue;
						}
						if (last_sparse>2) continue;
					}
				}
			} else last_sparse = 0;
		}
		if (use_offset)
			r_print_addr (p, addr+j);
		printfmt ((col==1)? "|": " ");
		for (j=i; j<i+inc; j++) {
			if (j>=len) {
				if (col==1) {
					if (j+1>=inc+i)
						printfmt (j%2?"  |":"| ");
					else printfmt (j%2?"   ":"  ");
				} else printfmt (j%2?"   ":"  ");
				continue;
			}
			if (p && base==32) {
				ut32 n = 0;
				r_mem_copyendian ((ut8*)&n, buf+j, sizeof (n), !p->big_endian);
				r_print_cursor (p, j, 1);

				// stub for colors
				if (p && p->colorfor) {
					a = p->colorfor (p->user, n);
					if (a && *a) { b = Color_RESET; } else { a = b = ""; }
				} else { a = b = ""; }

				printfmt ("%s0x%08x%s ", a, n, b);
				r_print_cursor (p, j, 0);
				j += 3;
			} else
			if (p && base==64) {
				ut64 x = 0LL;
				/* Prevent reading outside of buf. Necessary as inc is not
				 * a multiple of 4 for base == 64. */
				r_mem_copyendian ((ut8*)&x, buf+j, sizeof (x), !p->big_endian);
				r_print_cursor (p, j, 1);
				// stub for colors
				if (p && p->colorfor) {
					a = p->colorfor (p->user, x);
					if (a && *a) { b = Color_RESET; } else { a = b = ""; }
				} else { a = b = ""; }
				printfmt ("%s0x%016"PFMT64x"%s  ", a, x, b);
				r_print_cursor (p, j, 0);
				j += 7;
			} else {
				r_print_byte (p, fmt, j, buf[j]);
				if (j%2 || !pairs) {
					if (col==1) {
						if (j+1<inc+i)
							printfmt (" ");
						else printfmt ("|");
					} else printfmt (" ");
				}
			}
		}
		printfmt ((col==2)? "|":" ");
		for (j=i; j<i+inc; j++) {
			if (j >= len) printfmt (" ");
			else r_print_byte (p, "%c", j, buf[j]);
		}
		if (col==2) printfmt("|");
		if (p->flags & R_PRINT_FLAGS_REFS) {
			ut64 *foo = (ut64*)(buf+i);
			ut64 addr = *foo;
			if (base==32) addr &= UT32_MAX;
			if (p->hasrefs) {
				const char *rstr = p->hasrefs (p->user, addr);
				if (rstr && *rstr)
					printfmt ("%s", rstr);
			}
		}
		printfmt ("\n");
	}
}

static const char *getbytediff (char *fmt, ut8 a, ut8 b) {
	if (*fmt) {
		if (a==b) sprintf (fmt, Color_GREEN"%02x"Color_RESET, a);
		else sprintf (fmt, Color_RED"%02x"Color_RESET, a);
	} else sprintf (fmt, "%02x", a);
	// else sprintf (fmt, "%02x", a);
	return fmt;
}

static const char *getchardiff (char *fmt, ut8 a, ut8 b) {
	char ch = IS_PRINTABLE (a)? a: '.';
	if (*fmt) {
		if (a==b) sprintf (fmt, Color_GREEN"%c"Color_RESET, ch);
		else sprintf (fmt, Color_RED"%c"Color_RESET, ch);
	} else sprintf (fmt, "%c", ch);
	//else { fmt[0] = ch; fmt[1]=0; }
	return fmt;
}

#define BD(a,b) getbytediff(fmt, a[i+j], b[i+j])
#define CD(a,b) getchardiff(fmt, a[i+j], b[i+j])

static ut8 *M(const ut8 *b, int len) {
	ut8 *r = malloc (len+16);
	if (!r) return NULL;
	memset (r, 0xff, len+16);
	memcpy (r, b, len);
	return r;
}

// TODO: add support for cursor
R_API void r_print_hexdiff(RPrint *p, ut64 aa, const ut8* _a, ut64 ba, const ut8 *_b, int len, int scndcol) {
	ut8 *a, *b;
	char linediff, fmt[64];
	int color = p->flags & R_PRINT_FLAGS_COLOR;
	int i, j, min;
	a = M (_a, len); if (!a) return;
	b = M (_b, len); if (!b) { free (a); return; }
	for (i =0 ; i<len; i+=16) {
		min = R_MIN (16, len-i);
		linediff = (memcmp (a+i, b+i, min))?'!':'|';
		p->printf ("0x%08"PFMT64x" ", aa+i);
		for (j=0; j<min; j++) {
			*fmt = color; 
			r_print_cursor (p, i+j, 1);
			p->printf (BD (a, b));
			r_print_cursor (p, i+j, 0);
		}
		p->printf (" ");
		for (j=0;j<min;j++) {
			*fmt = color; 
			r_print_cursor (p, i+j, 1);
			p->printf ("%s", CD (a, b));
			r_print_cursor (p, i+j, 0);
		}
		if (scndcol) {
			p->printf (" %c 0x%08"PFMT64x" ", linediff, ba+i);
			for (j=0;j<min;j++) {
				*fmt = color; 
				r_print_cursor (p, i+j, 1);
				p->printf (BD (b, a));
				r_print_cursor (p, i+j, 0);
			}
			p->printf (" ");
			for (j=0; j<min; j++) {
				*fmt = color; 
				r_print_cursor (p, i+j, 1);
				p->printf ("%s", CD (b, a));
				r_print_cursor (p, i+j, 0);
			}
			p->printf ("\n");
		} else p->printf (" %c\n", linediff);
	}
	free (a);
	free (b);
}

R_API void r_print_bytes(RPrint *p, const ut8* buf, int len, const char *fmt) {
	int i;
	if (p) {
		for (i=0; i<len; i++)
			p->printf (fmt, buf[i]);
		p->printf ("\n");
	} else {
		for (i=0; i<len; i++)
			printf (fmt, buf[i]);
		printf ("\n");
	}
}

R_API void r_print_raw(RPrint *p, const ut8* buf, int len, int offlines) {
	if (offlines) {
		const ut8 *o, *q;
		int mustbreak = 0, linenum = 1;
		o = q = buf;
		do {
			p->printf ("%d 0x%08x ", linenum,
				(int)(size_t)(q-buf));
			for (;*q && *q != '\n'; q++);
			if (!*q)
				mustbreak = 1;
			p->write (o, (int)(size_t)(q-o));

			p->printf ("\n");
			linenum++;
			o = ++q;
		} while (!mustbreak);
	} else {
		p->write (buf, len);
	}
}

R_API void r_print_c(RPrint *p, const ut8 *str, int len) {
	int i;
	int inc = p->width/6;
	p->printf ("#define _BUFFER_SIZE %d\n"
		"unsigned char buffer[_BUFFER_SIZE] = {\n", len);
	p->interrupt = 0;
	for (i = 0; !p->interrupt && i < len;) {
		r_print_byte (p, "0x%02x", i, str[i]);
		if (++i<len) p->printf (", ");
		if (!(i%inc)) p->printf ("\n");
	}
	p->printf (" };\n");
}

// HACK :D
static RPrint staticp = {
	.printf = printf
};

/* TODO: handle screen width */
// TODO: use stderr here?
R_API void r_print_progressbar(RPrint *p, int pc, int _cols) {
        int i, cols = (_cols==-1)? 78: _cols;
	if (!p) p = &staticp;
        (pc<0)?pc=0:(pc>100)?pc=100:0;
        p->printf ("%4d%% [", pc);
        cols -= 15;
        for (i=cols*pc/100;i;i--) p->printf ("#");
        for (i=cols-(cols*pc/100);i;i--) p->printf ("-");
        p->printf ("]");
}

R_API void r_print_zoom (RPrint *p, void *user, RPrintZoomCallback cb, ut64 from, ut64 to, int len, int maxlen) {
	static int mode = -1;
	ut8 *bufz, *bufz2;
	int i, j = 0;
	ut64 size = (to-from);
	size = len? size/len: 0;

	bufz = bufz2 = NULL;
	if (maxlen<2) maxlen = 1024*1024;
	if (size>maxlen) size = maxlen;
	if (size<1) size = 1;
	if (len<1) len = 1;

	if (mode == p->zoom->mode && from == p->zoom->from && to == p->zoom->to && size==p->zoom->size) {
		// get from cache
		bufz = p->zoom->buf;
		size = p->zoom->size;
	} else {
		mode = p->zoom->mode;
		bufz = (ut8 *) malloc (len);
		if (bufz == NULL) return;
		bufz2 = (ut8 *) malloc (size);
		if (bufz2 == NULL) {
			free (bufz);
			return;
		}
		memset (bufz, 0, len);

		// TODO: memoize blocks or gtfo
		for (i=0; i<len; i++) {
			p->iob.read_at (p->iob.io, from+j, bufz2, size);
			bufz[i] = cb (user, p->zoom->mode, from+j, bufz2, size);
			j += size;
		}
		free (bufz2);
		// memoize
		free (p->zoom->buf);
		p->zoom->buf = bufz;
		p->zoom->from = from;
		p->zoom->to = to;
		p->zoom->size = size;
	}
	p->flags &= ~R_PRINT_FLAGS_HEADER;
	r_print_hexdump (p, from, bufz, len, 16, size);
	p->flags |= R_PRINT_FLAGS_HEADER;
}

#if 0
/* Process source file with given parameters. Output to stdout */
// TODO: use buffer instead of FILE*

----------------
        /* File processing */
        if (all)
        {
                for (i = 0 ; i <= 1 ; i++)
                {
                        for (j = 0 ; j <= 1 ; j++)
                        {
                                for (offset = 0 ; offset <= 7 ; offset++)
                                {
                                        /* Brute-force run */
                                        process (fd, length, i, j, offset);
                                }
                        }
                }
        } else
                /* Customized one pass only run */
                process (fd, length, forward, downward, offset);
----------------


void lsb_stego_process (FILE *fd, int length, bool forward, bool downward, int offset)
{
        int byte;       /* Byte index */
        int bit;        /* Bit index */
        int lsb;        /* Least Significant Bit */
        char sbyte;     /* Source byte (i.e. from src file */
        char dbyte;     /* Destination byte (decrypted msg) */


        for ( byte = offset ; byte < length ; ) {
                dbyte = 0;

                for (bit = 0; bit <= 7; bit++, byte++) {
                        /* Set position at the beginning or eof */
                        if (forward)
                                fseek(fd, byte, SEEK_SET);
                        else fseek(fd, -(byte+1), SEEK_END);

                        /* Read one byte */
                        fread(&sbyte, sizeof(sbyte), 1, fd);

                        /* Obtain Least Significant Bit */
                        lsb = sbyte & 1;

                        /* Add lsb to decrypted message */
			dbyte = dbyte | lsb << ((downward)?(7-bit):bit);
                }
                printf ("%c", dbyte);
        }
}
#endif

/// XXX: fix ascii art with different INCs
R_API void r_print_fill(RPrint *p, const ut8 *arr, int size) {
	int i = 0, j;
#define INC 5
	p->printf ("         ");
	if (arr[0]>1) for (i=0;i<arr[0]; i+=INC) p->printf ("_");
	p->printf ("\n");
	for (i=0; i<size; i++) {
		ut8 next = (i+1<size)? arr[i+1]:0;
		p->printf ("%02x %04x |", i, arr[i]);
			int base = 0;
			if (next<INC) base = 1;
		if (next<arr[i]) {
			//if (arr[i]>0 && i>0) p->printf ("  ");
			if (arr[i]>INC)
			for (j=0;j<next+base; j+=INC) p->printf (" ");
			for (j=next+INC; j+base<arr[i]; j+=INC) p->printf ("_");
		} else {
			for (j=INC; j<arr[i]+base; j+=INC) p->printf (" ");
		}
		//for (j=1;j<arr[i]; j+=INC) p->printf (under);
		p->printf ("|");
		if (arr[i+1]>arr[i])
			for (j=arr[i]+INC+base; j+base<next; j+=INC) p->printf ("_");
		p->printf ("\n");
	}
}

R_API void r_print_2bpp_row(RPrint *p, ut8 *buf)
{
	int i, c = 0;
	char *color;
	for (i=0; i<8; i++) {
		if (buf[1] & ((1<<7)>>i) ) c = 2;
		if (buf[0] & ((1<<7)>>i) ) c++;
		switch (c) {
			case 0:
				color = Color_BGWHITE;
			break;
			case 1:
				color = Color_BGRED;
			break;
			case 2:
				color = Color_BGBLUE;
			break;
			case 3:
				color = Color_BGBLACK;
		}
		p->printf("%s  ", color);
		c = 0;
	}
}

R_API void r_print_2bpp_tiles(RPrint *p, ut8 *buf, ut32 tiles)
{
	int i, r;
	for(i=0; i<8; i++) {
		for(r=0; r<tiles; r++)
			r_print_2bpp_row(p, buf + 2*i + r*16);
		p->printf(Color_RESET"\n");
	}
}

R_API const char * r_print_color_op_type ( RPrint *p, ut64 anal_type) {

	switch (anal_type) {
		case R_ANAL_OP_TYPE_NOP:
			return p->cons->pal.nop;
		case R_ANAL_OP_TYPE_ADD:
		case R_ANAL_OP_TYPE_SUB:
		case R_ANAL_OP_TYPE_MUL:
		case R_ANAL_OP_TYPE_DIV:
			return p->cons->pal.math;
		case R_ANAL_OP_TYPE_AND:
		case R_ANAL_OP_TYPE_OR:
		case R_ANAL_OP_TYPE_XOR:
		case R_ANAL_OP_TYPE_NOT:
		case R_ANAL_OP_TYPE_SHL:
		case R_ANAL_OP_TYPE_SAR:
		case R_ANAL_OP_TYPE_SHR:
		case R_ANAL_OP_TYPE_ROL:
		case R_ANAL_OP_TYPE_ROR:
			return p->cons->pal.bin;
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_UJMP:
			return p->cons->pal.jmp;
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_UCJMP:
			return p->cons->pal.cjmp;
		case R_ANAL_OP_TYPE_CMP:
		case R_ANAL_OP_TYPE_ACMP:
			return p->cons->pal.cmp;
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_UCCALL:
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_CCALL:
			return p->cons->pal.call;
		case R_ANAL_OP_TYPE_SWI:
			return p->cons->pal.swi;
		case R_ANAL_OP_TYPE_ILL:
		case R_ANAL_OP_TYPE_TRAP:
			return p->cons->pal.trap;
		case R_ANAL_OP_TYPE_CRET:
		case R_ANAL_OP_TYPE_RET:
			return p->cons->pal.ret;
		case R_ANAL_OP_TYPE_MOV:
		case R_ANAL_OP_TYPE_LEA:
			return p->cons->pal.mov;
		case R_ANAL_OP_TYPE_PUSH:
		case R_ANAL_OP_TYPE_UPUSH:
		case R_ANAL_OP_TYPE_LOAD:
			return p->cons->pal.push;
		case R_ANAL_OP_TYPE_POP:
		case R_ANAL_OP_TYPE_STORE:
			return p->cons->pal.pop;
		case R_ANAL_OP_TYPE_NULL:
			return p->cons->pal.other;
		case R_ANAL_OP_TYPE_UNK:
		default:
			return p->cons->pal.invalid;
	}
}

// Global buffer to speed up colorizing performance
#define COLORIZE_BUFSIZE 1024
static char o[COLORIZE_BUFSIZE];

R_API char * r_print_colorize_opcode (char *p, const char *reg, const char *num) {
	int i, j, k, is_mod, is_arg = 0;
	ut32 c_reset = strlen (Color_RESET);
	int is_jmp = p && (*p == 'j' || ((*p == 'c') && (p[1] == 'a')))? 1: 0;
	ut32 opcode_sz = p && *p ? strlen (p)*10 + 1 : 0;

	if (!p || !*p) return NULL;
	if (is_jmp)
		return strdup (p);

	if (opcode_sz > COLORIZE_BUFSIZE) {
		/* return same string in case of error */
		return strdup (p);
	}

	memset (o, 0, COLORIZE_BUFSIZE);

	for (i=j=0; p[i]; i++,j++) {
		/* colorize numbers */
		/*
		if (j+100 >= opcode_sz) {
			o = realloc_color_buffer (o, &opcode_sz, 100);
		}
		*/
		if (j+100 >= COLORIZE_BUFSIZE) {
			eprintf ("r_print_colorize_opcode(): buffer overflow!\n");
			return strdup (p);
		}
		switch (p[i]) {
		// We dont need to skip ansi codes.
		// original colors must be preserved somehow
		case 0x1b:
#define STRIP_ANSI 1
#if STRIP_ANSI
			/* skip until 'm' */
			for (++i;p[i] && p[i]!='m'; i++)
				o[j] = p[i];
			continue;
#else
			/* copy until 'm' */
			for (;p[i] && p[i]!='m'; i++)
				o[j++] = p[i];
			o[j++] = p[i++];
#endif
		case '+':
		case '-':
		case '/':
		case '>':
		case '<':
		case '(':
		case ')':
		case '*':
		case '%':
		case ']':
		case '[':
		case ',':
			if (is_arg) {
				/* if (c_reset+j+10 >= opcode_sz) o = realloc_color_buffer (o, &opcode_sz, c_reset+100); */
				if (c_reset+j+10 >= COLORIZE_BUFSIZE) {
					eprintf ("r_print_colorize_opcode(): buffer overflow!\n");
					return strdup (p);
				}
				strcpy (o+j, Color_RESET);
				j += strlen (Color_RESET);
				o[j++] = p[i];
				if (p[i]=='$' || ((p[i] > '0') && (p[i] < '9'))) {
					ut32 num_len = strlen (num);
					/* if (num_len+j+10 >= opcode_sz) o = realloc_color_buffer (o, &opcode_sz, num_len+100); */
					if (num_len+j+10 >= COLORIZE_BUFSIZE) {
						eprintf ("r_print_colorize_opcode(): buffer overflow!\n");
						return strdup (p);
					}
					strcpy (o+j, num);
					j += strlen (num)-1;
				} else {
					ut32 reg_len = strlen (reg);
					/* if (reg_len+j+10 >= opcode_sz) o = realloc_color_buffer (o, &opcode_sz, reg_len+100); */
					if (reg_len+j+10 >= COLORIZE_BUFSIZE) {
						eprintf ("r_print_colorize_opcode(): buffer overflow!\n");
						return strdup (p);
					}
					strcpy (o+j, reg);
					j += strlen (reg)-1;
				}
				continue;
			}
			break;
		case ' ':
			is_arg = 1;
			// find if next ',' before ' ' is found
			is_mod = 0;
			for (k = i+1; p[k]; k++) {
				if (p[k]==' ')
					break;
				if (p[k]==',') {
					is_mod = 1;
					break;
				}
			}
			if (!p[k]) is_mod = 1;
			if (!is_jmp && is_mod) {
				// COLOR FOR REGISTER
				ut32 reg_len = strlen (reg);
				/* if (reg_len+j+10 >= opcode_sz) o = realloc_color_buffer (o, &opcode_sz, reg_len+100); */
				if (reg_len+j+10 >= COLORIZE_BUFSIZE) {
					eprintf ("r_print_colorize_opcode(): buffer overflow!\n");
					return strdup (p);
				}
				strcpy (o+j, reg);
				j += strlen (reg);
			}
			break;
		case '0':
			if (!is_jmp && p[i+1]== 'x') {
				ut32 num_len = strlen (num);
				/* if (num_len+j+10 >= opcode_sz) o = realloc_color_buffer (o, &opcode_sz, num_len+100); */
				if (num_len+j+10 >= COLORIZE_BUFSIZE) {
					eprintf ("r_print_colorize_opcode(): buffer overflow!\n");
					return strdup (p);
				}
				strcpy (o+j, num);
				j += strlen (num);
			}
			break;
		}
		o[j] = p[i];
	}
	// decolorize at the end
	if (j+20 >= opcode_sz) {
		char *t_o = o;
		/* o = malloc (opcode_sz+21); */
		memcpy (o, t_o, opcode_sz);
		opcode_sz += 21;
		/* free (t_o); */
	}
	strcpy (o+j, Color_RESET);
	//strcpy (p, o); // may overflow .. but shouldnt because asm.buf_asm is big enought
	return strdup (o);
}

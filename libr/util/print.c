/* radare - LGPL - Copyright 2007-2014 - pancake */

#include "r_cons.h"
#include "r_print.h"
#include "r_util.h"

static int nullprinter(const char* a, ...) { return 0; }

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
	RPrint *p = R_NEW (RPrint);
	if (!p) return NULL;
	strcpy (p->datefmt, "%d:%m:%Y %H:%M:%S %z");
	p->user = NULL;
	r_io_bind_init (p->iob);
	p->user = NULL;
	p->disasm = NULL;
	p->printf = printf;
	p->oprintf = nullprinter;
	p->bits = 32;
	p->stride = 0;
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
	p->cur_enabled = enable;
	p->ocur = ocursor;
	if (cursor<0) cursor = 0;
	p->cur = cursor;
}

R_API void r_print_cursor(RPrint *p, int cur, int set) {
	if (!p->cur_enabled)
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

#define P(x) (p->cons &&p->cons->pal.x)?p->cons->pal.x
R_API void r_print_addr(RPrint *p, ut64 addr) {
	int mod = p->flags & R_PRINT_FLAGS_ADDRMOD;
	char ch = (p->addrmod&&mod)?((addr%p->addrmod)?' ':','):' ';
	if (p->flags & R_PRINT_FLAGS_SEGOFF) {
		ut32 s, a;
		a = addr & 0xffff;
		s = (addr-a)>>4;
		if (p->flags & R_PRINT_FLAGS_COLOR) {
			const char *pre = P(offset): Color_GREEN;
			const char *fin = Color_RESET;
			p->printf ("%s%04x:%04x%c%s", pre, s & 0xffff, a & 0xffff, ch, fin);
		} else p->printf ("%04x:%04x%c", s & 0xffff, a & 0xffff, ch);
	} else {
		if (p->flags & R_PRINT_FLAGS_COLOR) {
			const char *pre = P(offset): Color_GREEN;
			const char *fin = Color_RESET;
			p->printf ("%s0x%08"PFMT64x"%c%s", pre, addr, ch, fin);
		} else p->printf ("0x%08"PFMT64x"%c", addr, ch);
	}
}

#define CURDBG 0
// XXX: redesign ? :)
R_API char *r_print_hexpair(RPrint *p, const char *str, int n) {
	const char *s, *lastcol = Color_WHITE;
	char *d, *dst = (char *)malloc ((strlen (str)+2)*32);
	int colors = p->flags & R_PRINT_FLAGS_COLOR;
	const char *color_0x00, *color_0x7f, *color_0xff, *color_text, *color_other;
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
	}
	if (colors || p->cur_enabled)
		memcpy (d, Color_RESET, strlen (Color_RESET)+1);
	else *d = 0;
	return dst;
}

R_API void r_print_byte(RPrint *p, const char *fmt, int idx, ut8 ch) {
	ut8 rch = ch;
	if (!IS_PRINTABLE (ch) && fmt[0]=='%'&&fmt[1]=='c')
		rch = '.';
	r_print_cursor (p, idx, 1);
	//if (p->flags & R_PRINT_FLAGS_CURSOR && idx == p->cur) {
	if (p->flags & R_PRINT_FLAGS_COLOR) {
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
		if (pre) p->printf (pre);
		p->printf (fmt, rch);
		if (pre) p->printf (Color_RESET);
	} else p->printf (fmt, rch);
	r_print_cursor (p, idx, 0);
}

R_API void r_print_code(RPrint *p, ut64 addr, ut8 *buf, int len, char lang) {
	int ws, i, w = p->cols*0.7;
	switch (lang) {
	case '?':
		eprintf ("Valid print code formats are: JSON, C, Python, Cstring (pcj, pc, pcp, pcs) \n"
		"  pc     C\n"
		"  pcs    string\n"
		"  pcj    json\n"
		"  pcJ    javascript\n"
		"  pcp    python\n"
		"  pcw    words (4 byte)\n"
		"  pcd    dwords (8 byte)\n");
		break;
	case 's':
		p->printf ("\"");
		for (i=0; !p->interrupt && i<len; i++) {
			p->printf ("\\x%02x", buf[i]);
		}
		p->printf ("\"\n");
		break;
	case 'J':
		{
		       ut8 *out = malloc (len*3);
		       p->printf ("var buffer = new Buffer(\"");
		       out[0] = 0;
		       r_base64_encode (out, buf, len);
		       p->printf ("%s", out);
		       p->printf ("\", 'base64').toString('binary');\n");
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
	int i, j, k, inc;
	int sparse_char = 0;
	int use_sparse = p->flags & R_PRINT_FLAGS_SPARSE;
	const char *fmt = "%02x";
	const char *pre = "";
	int last_sparse = 0;

	if (step<1) step = 1;

	switch (base) {
	case 8: fmt = "%03o"; pre = " "; break;
	case 10: fmt = "%03d"; pre = " "; break;
	case 32: fmt = "0x%08x "; pre = " "; break;
	case 64: fmt = "0x%016x "; pre = " "; break;
	}

	// TODO: Use base to change %03o and so on
	if (p == NULL) {
		// TODO: use defaults r_print_t (static one)
		eprintf ("TODO: r_print_hexdump does not supports NULL as arg0\n");
		return;
	}

	inc = p->cols;
		
	if ((base<32) && (p->flags & R_PRINT_FLAGS_HEADER)) {
		ut32 opad = (ut32)(addr >> 32);
		{ // XXX: use r_print_addr_header
			int i, delta;
			char soff[32];
			if (p->flags & R_PRINT_FLAGS_SEGOFF) {
				ut32 s, a;
				a = addr & 0xffff;
				s = ((addr-a)>>4 ) &0xffff;
				snprintf (soff, sizeof (soff), "%04x:%04x ", s, a);
				p->printf ("- offset -");
			} else {
				p->printf ("- offset - ");
				snprintf (soff, sizeof (soff), "0x%08"PFMT64x, addr);
			}
			delta = strlen (soff) - 10;
			for (i=0; i<delta; i++)
				p->printf (i+1==delta?" ":" ");
		}
		p->printf (p->col==1?"|":" ");
		opad >>= 4;
		k = 0; // TODO: ??? SURE??? config.seek & 0xF;
		/* extra padding for offsets > 8 digits */
		for (i=0; i<inc; i++) {
			p->printf (pre);
			p->printf (" %c", hex[(i+k)%16]);
			if (i&1)
				p->printf (p->col!=1?" ":((i+1)<inc)?" ":"|");
		}
		p->printf ((p->col==2)? "|": " ");
		for (i=0; i<inc; i++)
			p->printf ("%c", hex[(i+k)%16]);
		p->printf (p->col==2?"|\n":"\n");
	}

	p->interrupt = 0;
	for (i=j=0; !p->interrupt && i<len; i+=(p->stride?p->stride:inc), j+=(p->stride?p->stride:0)) {
		if (use_sparse) {
			if (check_sparse (buf+i, inc, sparse_char)) {
				if (i+inc>=len || check_sparse (buf+i+inc, inc, sparse_char)) {
					if (i+inc+inc>=len || check_sparse (buf+i+inc+inc, inc, sparse_char)) {
						sparse_char = buf[j];
						last_sparse++;
						if (last_sparse==2) {
							p->printf (" ...\n");
							continue;
						}
						if (last_sparse>2) continue;
					}
				}
			} else last_sparse = 0;
		}
		if (p->flags & R_PRINT_FLAGS_OFFSET)
			r_print_addr (p, addr+j);
		p->printf ((p->col==1)? "|": " ");
		for (j=i; j<i+inc; j++) {
			if (j>=len) {
				if (p->col==1) {
					if (j+1>=inc+i)
						p->printf (j%2?"  |":"| ");
					else p->printf (j%2?"   ":"  ");
				} else p->printf (j%2?"   ":"  ");
				continue;
			}
			if (base==32) {
				ut32 n;
				memcpy (&n, buf+j, sizeof (n));
				r_print_cursor (p, j, 1);
				p->printf ("0x%08x ", n);
				r_print_cursor (p, j, 0);
				j += 3;
			} else
			if (base==64) {
				ut32 a, b;
				/* Prevent reading outside of buf. Necessary as inc is not
				 * a multiple of 4 for base == 64. */
				// size_t l = sizeof (n); if (j + l > len) l = len - j;
				memcpy (&a, buf+j, 4);
				memcpy (&b, buf+j+4, 4);
				r_print_cursor (p, j, 1);
				p->printf ("0x%08x%08x  ", b, a); //n<<32, n&0xffffff);
				r_print_cursor (p, j, 0);
				j += 7;
			} else {
				r_print_byte (p, fmt, j, buf[j]);
				if (j%2) {
					if (p->col==1) {
						if (j+1<inc+i)
							p->printf (" ");
						else p->printf ("|");
					} else p->printf (" ");
				}
			}
		}
		p->printf ((p->col==2)? "|":" ");
		for (j=i; j<i+inc; j++) {
			if (j >= len) p->printf (" ");
			else r_print_byte (p, "%c", j, buf[j]);
		}
		p->printf (p->col==2?"|\n":"\n");
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

R_API void r_print_raw(RPrint *p, const ut8* buf, int len) {
	p->write (buf, len);
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

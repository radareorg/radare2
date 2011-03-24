/* radare - LGPL - Copyright 2007-2011 pancake<nopcode.org> */

#include "r_cons.h"
#include "r_print.h"
#include "r_util.h"

R_API RPrint *r_print_new() {
	RPrint *p = R_NEW (RPrint);
	if (p) {
		strcpy (p->datefmt, "%d:%m:%Y %H:%M:%S %z");
		p->user = NULL;
		r_io_bind_init (p->iob);
		p->printf = printf;
		p->interrupt = 0;
		p->bigendian = 0;
		p->width = 78;
		p->cur_enabled = R_FALSE;
		p->cur = p->ocur = -1;
		p->addrmod = 4;
		p->flags = \
			   R_PRINT_FLAGS_COLOR |
			   R_PRINT_FLAGS_HEADER |
			   R_PRINT_FLAGS_ADDRMOD;
		p->zoom = R_NEW0 (RPrintZoom);
	}
	return p;
}

R_API RPrint *r_print_free(RPrint *p) {
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
		if (cur>=from&&cur<=to)
			r_cons_invert (set, p->flags&R_PRINT_FLAGS_COLOR);
	} else
	if (cur==p->cur)
		r_cons_invert (set, p->flags & R_PRINT_FLAGS_COLOR);
}

R_API void r_print_addr(RPrint *p, ut64 addr) {
	int mod = p->flags & R_PRINT_FLAGS_ADDRMOD;
	char ch = (p->addrmod&&mod)?((addr%p->addrmod)?' ':','):' ';
	if (p->flags & R_PRINT_FLAGS_COLOR) {
#if 0
		p->printf("%s0x%08"PFMT64x""Color_RESET"%c ",
			r_cons_singleton ()->palette[PAL_ADDRESS], addr, ch);
#endif
		p->printf ("0x%08"PFMT64x"%c ", addr, ch);
	} else r_cons_printf ("0x%08"PFMT64x"%c ", addr, ch);
}

#define CURDBG 0
// XXX: redesign ? :)
R_API char *r_print_hexpair(RPrint *p, const char *str, int n) {
	const char *s;
	char *d, *dst = (char *)malloc ((strlen (str)+2)*32);
	int ch, i;
	/* XXX That's hacky as shit.. but partially works O:) */
	/* TODO: Use r_print_set_cursor for win support */
	int cur = R_MIN (p->cur, p->ocur);
	int ocur = R_MAX (p->cur, p->ocur);

	if (p->cur_enabled && cur==-1)
		cur = ocur;
	ocur++;
#if CURDBG
	sprintf(dst, "(%d/%d/%d/%d)", p->cur_enabled, cur, ocur, n);
	d = dst+ strlen(dst);
#else
	d = dst;
#endif
	// XXX: overflow here
#define memcat(x,y) { memcpy(x,y,strlen(y));x+=strlen(y); }
	//for (s=str, d=dst; *s; s+=2, d+=2, i++) {
	for (s=str, i=0 ; *s; s+=2, d+=2, i++) {
		if (p->cur_enabled) {
			if (i==ocur-n)
				memcat (d, "\x1b[27m");
			if (i>=cur-n && i<ocur-n)
				memcat (d, "\x1b[7m");
		}
		if (s[0]=='0' && s[1]=='0') { memcat (d, "\x1b[32m"); }
		else if (s[0]=='7' && s[1]=='f') { memcat (d, "\x1b[33m"); }
		else if (s[0]=='f' && s[1]=='f') { memcat (d, "\x1b[31m"); }
		else {
			sscanf (s, "%02x", &ch);
			if (IS_PRINTABLE (ch))
				memcat (d, "\x1b[35m");
		}
		memcpy (d, s, 2);
	}
	memcpy (d, "\x1b[0m", 5);
	return dst;
}

R_API void r_print_byte(RPrint *p, const char *fmt, int idx, ut8 ch) {
	ut8 rch = ch;
	if (!IS_PRINTABLE (ch) && fmt[0]=='%'&&fmt[1]=='c')
		rch = '.';
	r_print_cursor (p, idx, 1);
	//if (p->flags & R_PRINT_FLAGS_CURSOR && idx == p->cur) {
	if (p->flags & R_PRINT_FLAGS_COLOR) {
		char *pre = NULL;
		switch (ch) {
		case 0x00: pre = "\x1b[32m"; break;
		case 0x7F: pre = "\x1b[33m"; break;
		case 0xFF: pre = "\x1b[31m"; break;
		default:
			if (IS_PRINTABLE (ch))
				pre = "\x1b[35m";
		}
		if (pre) p->printf (pre);
		p->printf (fmt, rch);
		if (pre) p->printf ("\x1b[0m");
	} else p->printf (fmt, rch);
	r_print_cursor (p, idx, 0);
}

R_API void r_print_code(RPrint *p, ut64 addr, ut8 *buf, int len) {
	int i, w = 0;
	p->printf ("#define _BUFFER_SIZE %d\n", len);
	p->printf ("unsigned char buffer[%d] = {", len);
	p->interrupt = 0;
	for (i=0;!p->interrupt&&i<len;i++) {
		if (!(w%p->width))
			p->printf ("\n  ");
		r_print_cursor (p, i, 1);
		p->printf("0x%02x, ", buf[i]);
		r_print_cursor (p, i, 0);
		w+=6;
	}
	p->printf ("};\n");
}

R_API int r_print_string(RPrint *p, ut64 seek, const ut8 *buf, int len, int wide, int zeroend, int urlencode) {
	int i;
	//if (p->flags & R_PRINT_FLAGS_OFFSET)
		// r_print_addr(p, seek);
	p->interrupt = 0;
	for (i=0;!p->interrupt&&i<len;i++) {
		if (zeroend && buf[i]=='\0')
			break;
		r_print_cursor (p, i, 1);
		if (urlencode) {
			// TODO: some ascii can be bypassed here
			p->printf ("%%%02x", buf[i]);
		} else {
			if (IS_PRINTABLE (buf[i]))
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
	for (i=0;i<len;i++)
		p->printf ("%02x ", buf[i]);
}

// XXX: step is borken
R_API void r_print_hexdump(RPrint *p, ut64 addr, const ut8 *buf, int len, int base, int step) {
	int i, j, k, inc;
	const char *fmt = "%02x";
	const char *pre = "";
	if (step<1) step = 1;

	switch(base) {
	case 8: fmt = "%03x"; pre = " "; break;
	case 10: fmt = "%03d"; pre = " "; break;
	}

	// TODO: Use base to change %03o and so on
	if (p == NULL) {
		// TODO: use defaults r_print_t (static one)
		eprintf ("TODO: r_print_hexdump does not supports NULL as arg0\n");
		return;
	}

	inc = 2 + (int)((p->width-14)/4);
	if (inc%2) inc++;
	inc = 16;
	inc = p->cols;

	if (p->flags & R_PRINT_FLAGS_HEADER) {
		// only for color..too many options .. brbr
		//p->printf(r_cons_palette[PAL_HEADER]);
		p->printf ("   offset   ");
		k = 0; // TODO: ??? SURE??? config.seek & 0xF;
		for (i=0; i<inc; i++) {
			p->printf (pre);
			p->printf (" %c", hex[(i+k)%16]);
			if (i&1) p->printf (" ");
		}
		p->printf (" ");
		for (i=0; i<inc; i++)
			p->printf ("%c", hex[(i+k)%16]);
		p->printf ("\n");
	}

	p->interrupt = 0;
	for (i=0; !p->interrupt && i<len; i+=inc) {
		r_print_addr (p, addr+(i*step));

		for (j=i;j<i+inc;j++) {
			if (j>=len) {
				if (j%2) p->printf ("   ");
				else p->printf("  ");
				continue;
			}
			r_print_byte(p, fmt, j, buf[j]);
			if (j%2) p->printf(" ");
		}

		for (j=i; j<i+inc; j++) {
			if (j >= len) p->printf (" ");
			else r_print_byte (p, "%c", j, buf[j]);
		}
		p->printf ("\n");
		//addr+=inc;
	}
}

R_API void r_print_bytes(RPrint *p, const ut8* buf, int len, const char *fmt) {
	int i;
	for (i=0; i<len; i++)
		p->printf (fmt, buf[i]);
	p->printf ("\n");
}

R_API void r_print_raw(RPrint *p, const ut8* buf, int len) {
	// TODO independize from cons
	r_cons_memcat ((char *)buf, len);
}

R_API void r_print_c(RPrint *p, const ut8 *str, int len) {
	int i,j;
	int inc = p->width/6;
	p->printf ("#define _BUFFER_SIZE %d\n"
		"unsigned char buffer[_BUFFER_SIZE] = {\n", len);
	p->interrupt = 0;
	for (j = i = 0; !p->interrupt && i < len;) {
		r_print_byte (p, "0x%02x", i, str[i]);
		if (++i<len) p->printf (", ");
		if (!(i%inc)) p->printf ("\n");
	}
	p->printf (" };\n");
}

/* TODO: handle screen width */
// TODO: use stderr here?
R_API void r_print_progressbar(RPrint *p, int pc, int _cols) {
        int tmp, cols = (_cols==-1)?78:_cols;
        (pc<0)?pc=0:(pc>100)?pc=100:0;
        p->printf ("%4d%% [", pc);
        cols -= 15;
        for (tmp=cols*pc/100;tmp;tmp--) p->printf ("#");
        for (tmp=cols-(cols*pc/100);tmp;tmp--) p->printf ("-");
        p->printf ("]");
}


R_API void r_print_zoom (RPrint *p, void *user, RPrintZoomCallback cb, ut64 from, ut64 to, int len, int maxlen) {
	ut8 *bufz, *bufz2;
	int i, j = 0;
	ut64 size = (to-from)/len;

	bufz = bufz2 = NULL;
	if (maxlen<2) maxlen = 1024*1024;
	if (size>maxlen) size = maxlen;
	if (size<1) size = 1;
	if (from == p->zoom->from && to == p->zoom->to && size==p->zoom->size) {
		// get from cache
		bufz = p->zoom->buf;
		size = p->zoom->size;
	} else {
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

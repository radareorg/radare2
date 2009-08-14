/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_cons.h"
#include "r_print.h"
#include "r_util.h"

R_API int r_print_init(struct r_print_t *p)
{
	/* read callback */
	p->user = NULL;
	p->read_at = NULL;
	p->printf = printf;
	p->interrupt = 0;

	strcpy(p->datefmt, "%Y:%m:%d %H:%M:%S %z");

	/* setup prefs */
	p->bigendian = 0;
	p->width = 78;
	p->cur_enabled = R_FALSE;
	p->cur = p->ocur = -1;
	p->addrmod = 4;
	p->flags = \
		R_PRINT_FLAGS_COLOR |
		R_PRINT_FLAGS_HEADER |
		R_PRINT_FLAGS_ADDRMOD;
	return R_TRUE;
}

struct r_print_t *r_print_new()
{
	struct r_print_t *p = MALLOC_STRUCT(struct r_print_t);
	r_print_init(p);
	return p;
}

void r_print_set_flags(struct r_print_t *p, int _flags)
{
	p->flags = _flags;
}

void r_print_unset_flags(struct r_print_t *p, int flags)
{
	p->flags = p->flags & (p->flags^flags);
}

struct r_print_t *r_print_free(struct r_print_t *p)
{
	free(p);
	return NULL;
}

// XXX this is not thread safe...store into r_print_t ?

void r_print_set_cursor(struct r_print_t *p, int enable, int ocursor, int cursor)
{
	p->cur_enabled = enable;
	//if (ocursor<0) ocursor=0;
	p->ocur = ocursor;
	if (cursor<0) cursor=0;
	p->cur = cursor;
}

R_API void r_print_cursor(struct r_print_t *p, int cur, int set)
{
	if (!p->cur_enabled)
		return;
	if (p->ocur == -1) {
		if (cur==p->cur)
			r_cons_invert(set, p->flags & R_PRINT_FLAGS_COLOR);
	} else {
		int from = p->ocur;
		int to = p->cur;
		r_num_minmax_swap_i(&from, &to);
		if (cur>=from&&cur<=to)
			r_cons_invert(set, p->flags&R_PRINT_FLAGS_COLOR);
	}
}

void r_print_addr(struct r_print_t *p, ut64 addr)
{
	//config_get_i("cfg.addrmod");
	int mod = p->flags & R_PRINT_FLAGS_ADDRMOD;
	char ch = (0==(addr%(mod?mod:1)))?',':' ';

	if (p->flags & R_PRINT_FLAGS_COLOR) {
		p->printf("%s0x%08llx"C_RESET"%c ",
			r_cons_palette[PAL_ADDRESS], addr, ch);
	} else r_cons_printf("0x%08llx%c ", addr, ch);
}

R_API void r_print_byte(struct r_print_t *p, const char *fmt, int idx, ut8 ch)
{
	ut8 rch = ch;

	if (!IS_PRINTABLE(ch) && fmt[0]=='%'&&fmt[1]=='c')
		rch = '.';

	r_print_cursor(p, idx, 1);
	//if (p->flags & R_PRINT_FLAGS_CURSOR && idx == p->cur) {
	if (p->flags & R_PRINT_FLAGS_COLOR) {
		char *pre = NULL;
		switch(ch) {
		case 0x00: pre = "\e[31m"; break;
		case 0xFF: pre = "\e[32m"; break;
		case 0x7F: pre = "\e[33m"; break;
		default:
			if (IS_PRINTABLE(ch))
				pre = "\e[35m";
		}
		if (pre)
			p->printf(pre);
		p->printf(fmt, rch);
		if (pre)
			p->printf("\x1b[0m");
	} else p->printf(fmt, rch);
	r_print_cursor(p, idx, 0);
}

void r_print_code(struct r_print_t *p, ut64 addr, ut8 *buf, int len)
{
	int i, w = 0;
	p->printf("#define _BUFFER_SIZE %d\n", len);
	p->printf("unsigned char buffer[%d] = {", len);
	p->interrupt = 0;
	for(i=0;!p->interrupt&&i<len;i++) {
		if (!(w%p->width))
			p->printf("\n  ");
		r_print_cursor(p, i, 1);
		p->printf("0x%02x, ", buf[i]);
		r_print_cursor(p, i, 0);
		w+=6;
	}
	p->printf("};\n");
}

R_API int r_print_string(struct r_print_t *p, ut64 seek, const ut8 *buf, int len, int wide, int zeroend, int urlencode)
{
	int i;

	//if (p->flags & R_PRINT_FLAGS_OFFSET)
		// r_print_addr(p, seek);
	p->interrupt = 0;
	for(i=0;!p->interrupt&&i<len;i++) {
		if (zeroend && buf[i]=='\0')
			break;
		r_print_cursor(p, i, 1);
		if (urlencode) {
			// TODO: some ascii can be bypassed here
			p->printf("%%%02x", buf[i]);
		} else {
			if (IS_PRINTABLE(buf[i]))
				p->printf("%c", buf[i]);
			else p->printf("\\x%02x", buf[i]);
		}
		r_print_cursor(p, i, 0);
		if (wide) i++;
	}
	p->printf("\n");
	return i;
}

static const char hex[16] = "0123456789ABCDEF";
R_API void r_print_hexpairs(struct r_print_t *p, ut64 addr, ut8 *buf, int len)
{
	int i;
	for(i=0;i<len;i++) {
		p->printf("%02x ", buf[i]);
	}
}

// XXX: step is borken
R_API void r_print_hexdump(struct r_print_t *p, ut64 addr, ut8 *buf, int len, int base, int step)
{
	int i,j,k,inc;
	const char *fmt = "%02x";
	const char *pre = "";

	switch(base) {
	case 8: fmt = "%03x"; pre = " "; break;
	case 10: fmt = "%03d"; pre = " "; break;
	}

	// TODO: Use base to change %03o and so on
	if (p == NULL) {
		// TODO: use defaults r_print_t (static one)
		fprintf(stderr, "TODO: r_print_hexdump does not supports NULL as arg0\n");
		return;
	}

	inc = 2 + (int)((p->width-14)/4);
	if (inc%2) inc++;
	inc = 16;

	if (p->flags & R_PRINT_FLAGS_HEADER) {
		// only for color..too many options .. brbr
		p->printf(r_cons_palette[PAL_HEADER]);
		p->printf("   offset   ");
		k = 0; // TODO: ??? SURE??? config.seek & 0xF;
		for (i=0; i<inc; i++) {
			p->printf(pre);
			p->printf(" %c", hex[(i+k)%16]);
			if (i&1) p->printf(" ");
		}
		for (i=0; i<inc; i++)
			p->printf("%c", hex[(i+k)%16]);
		p->printf("\n");
	}

	p->interrupt = 0;
	for(i=0; !p->interrupt&& i<len; i+=inc) {
		r_print_addr(p, addr+(i*step));

		for(j=i;j<i+inc;j++) {
			if (j>=len) {
				p->printf("  ");
				if (j%2) p->printf(" ");
				continue;
			}
			r_print_byte(p, fmt, j, buf[j]);
			if (j%2) p->printf(" ");
		}

		for(j=i; j<i+inc; j++) {
			if (j >= len)
				p->printf(" ");
			else r_print_byte(p, "%c", j, buf[j]);
		}
		p->printf("\n");
		//addr+=inc;
	}
}

R_API void r_print_bytes(struct r_print_t *p, const ut8* buf, int len, const char *fmt)
{
	int i;
	for(i=0;i<len;i++)
		p->printf(fmt, buf[i]);
	p->printf("\n");
}

R_API void r_print_raw(struct r_print_t *p, const ut8* buf, int len)
{
	// TODO independize from cons
	r_cons_memcat((char *)buf, len);
}


R_API void r_print_c(struct r_print_t *p, const char *str, int len)
{
	int i,j;
	int inc= p->width/6;
	p->printf("#define _BUFFER_SIZE %d\n"
		"unsigned char buffer[_BUFFER_SIZE] = {\n", len);
	p->interrupt = 0;
	for(j = i = 0; !p->interrupt && i < len;) {
		r_print_byte(p, "0x%02x", i, str[i]);
		
		if (++i<len) p->printf(", ");
		if (!(i%inc))
			p->printf("\n");
	}
	p->printf(" };\n");
}

/* TODO: handle screen width */
R_API void r_print_progressbar(struct r_print_t *pr, int pc)
{
        int tmp, cols = 78;
        (pc<0)?pc=0:(pc>100)?pc=100:0;
        fprintf(stderr, "\x1b[K  %3d%% [", pc);
        cols-=15;
        for(tmp=cols*pc/100;tmp;tmp--) fprintf(stderr,"#");
        for(tmp=cols-(cols*pc/100);tmp;tmp--) fprintf(stderr,"-");
        fprintf(stderr, "]\r");
        fflush(stderr);
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


        for ( byte = offset ; byte < length ; ) 
        {
                dbyte = 0;

                for (bit = 0; bit <= 7; bit++, byte++)
                {
                        /* Set position at the beginning or eof */
                        if (forward)
                                fseek(fd, byte, SEEK_SET);
                        else
                                fseek(fd, -(byte+1), SEEK_END);

                        /* Read one byte */
                        fread(&sbyte, sizeof(sbyte), 1, fd);

                        /* Obtain Least Significant Bit */
                        lsb = sbyte & 1;

                        /* Add lsb to decrypted message */
                        if (downward)
                                dbyte = dbyte | lsb << (7-bit) ;
                        else
                                dbyte = dbyte | lsb << bit ;
                }

                printf ("%c", dbyte);
        }
}

#endif

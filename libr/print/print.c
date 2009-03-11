/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_cons.h"
#include "r_print.h"
#include "r_util.h"

int r_print_init(struct r_print_t *p)
{
	if (p == NULL)
		return R_FALSE;
	/* read callback */
	p->user = NULL;
	p->read_at = NULL;

	/* setup prefs */
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

void r_print_cursor(struct r_print_t *p, int cur, int set)
{
	if (!p->cur_enabled)
		return;
	if (p->ocur == -1) {
		if (cur==p->cur)
			r_cons_invert(set, p->flags&R_PRINT_FLAGS_COLOR);
	} else {
		int from = p->ocur;
		int to = p->cur;
		r_num_minmax_swap_i(&from, &to);
		if (cur>=from&&cur<=to)
			r_cons_invert(set, p->flags&R_PRINT_FLAGS_COLOR);
	}
}

void r_print_addr(struct r_print_t *p, u64 addr)
{
	//config_get_i("cfg.addrmod");
	int mod = p->flags & R_PRINT_FLAGS_ADDRMOD;
	char ch = (0==(addr%(mod?mod:1)))?',':' ';

	if (p->flags & R_PRINT_FLAGS_COLOR) {
		r_cons_printf("%s0x%08llx"C_RESET"%c ",
			r_cons_palette[PAL_ADDRESS], addr, ch);
	} else r_cons_printf("0x%08llx%c ", addr, ch);
}

void r_print_byte(int idx, u8 ch)
{
//	if (flags & R_PRINT_FLAGS_CURSOR && idx == p->cur)
	r_cons_printf("%c", ch);
//	else r_cons_printf("%c", ch);
}

void r_print_code(struct r_print_t *p, u64 addr, u8 *buf, int len)
{
	int i, w = 0;
	r_cons_printf("#define _BUFFER_SIZE %d\n", len);
	r_cons_printf("unsigned char buffer[%d] = {", len);
	for(i=0;i<len;i++) {
		if (!(w%p->width))
			r_cons_printf("\n  ");
		r_print_cursor(p, i, 1);
		r_cons_printf("0x%02x, ", buf[i]);
		r_print_cursor(p, i, 0);
		w+=6;
	}
	r_cons_printf("};\n");
}

void r_print_string(struct r_print_t *p, u64 addr, u8 *buf, int len)
{
	int i;
	for(i=0;i<len;i++) {
		r_print_cursor(p, i, 1);
		if (IS_PRINTABLE(buf[i]))
			r_cons_printf("%c", buf[i]);
		else r_cons_printf("\\x%02x", buf[i]);
		r_print_cursor(p, i, 0);
	}
	r_cons_newline();
}

static const char hex[16] = "0123456789ABCDEF";
// XXX: step is borken
void r_print_hexdump(struct r_print_t *p, u64 addr, u8 *buf, int len, int step)
{
	int i,j,k,inc;

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
		r_cons_printf(r_cons_palette[PAL_HEADER]);
		r_cons_strcat("   offset   ");
		k = 0; // TODO: ??? SURE??? config.seek & 0xF;
		for (i=0; i<inc; i++) {
			r_cons_printf(" %c", hex[(i+k)%16]);
			if (i&1) r_cons_strcat(" ");
		}
		for (i=0; i<inc; i++)
			r_cons_printf("%c", hex[(i+k)%16]);
		r_cons_newline();
	}

	for(i=0; i<len; i+=inc) {
		r_print_addr(p, addr+(i*step));

		for(j=i;j<i+inc;j++) {
			if (j>=len) {
				r_cons_printf("  ");
				if (j%2) r_cons_printf(" ");
				continue;
			}
			r_print_cursor(p, j, 1);
			r_cons_printf("%02x", (u8)buf[j]);
			r_print_cursor(p, j, 0);
			//print_color_byte_i(j, "%02x", (unsigned char)buf[j]);
			if (j%2) r_cons_strcat(" ");
		}

		for(j=i; j<i+inc; j++) {
			if (j >= len)
				r_cons_strcat(" ");
			else {
				r_print_cursor(p, j, 1);
				r_cons_printf("%c",
				(IS_PRINTABLE(buf[j]))?
					buf[j] : '.');
				r_print_cursor(p, j, 0);
			}
		}
		r_cons_newline();
		//addr+=inc;
	}
}

void r_print_bytes(struct r_print_t *p, const u8* buf, int len, const char *fmt)
{
	int i;
	for(i=0;i<len;i++)
		r_cons_printf(fmt, buf[i]);
	r_cons_newline();
}

void r_print_raw(struct r_print_t *p, const u8* buf, int len)
{
	r_cons_memcat((char *)buf, len);
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

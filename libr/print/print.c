/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_cons.h"
#include "r_print.h"
#include "r_util.h"

static int flags =
	R_PRINT_FLAGS_COLOR |
	R_PRINT_FLAGS_ADDRMOD;

void r_print_set_flags(int _flags)
{
	flags = _flags;
}

// XXX this is not thread safe...store into r_print_t ?
static int r_print_cur_enabled = 0;
static int r_print_cur = -1;
static int r_print_ocur = -1;

void r_print_set_cursor(int enable, int ocursor, int cursor)
{
	r_print_cur_enabled = enable;
	//if (ocursor<0) ocursor=0;
	r_print_ocur = ocursor;
	if (cursor<0) cursor=0;
	r_print_cur = cursor;
}

void r_print_cursor(int cur, int set)
{
	if (!r_print_cur_enabled)
		return;
	if (r_print_ocur == -1) {
		if (cur==r_print_cur)
			r_cons_invert(set, flags&R_PRINT_FLAGS_COLOR);
	} else {
		int from = r_print_ocur;
		int to = r_print_cur;
		r_num_minmax_swap_i(&from, &to);
		if (cur>=from&&cur<=to)
			r_cons_invert(set, flags&R_PRINT_FLAGS_COLOR);
	}
}

void r_print_addr(u64 addr)
{
	//config_get_i("cfg.addrmod");
	int mod = flags & R_PRINT_FLAGS_ADDRMOD;
	char ch = (0==(addr%(mod?mod:1)))?',':' ';

	if (flags & R_PRINT_FLAGS_COLOR) {
		r_cons_printf("%s0x%08llx"C_RESET"%c ",
			r_cons_palette[PAL_ADDRESS], addr, ch);
	} else r_cons_printf("0x%08llx%c ", addr, ch);
}

void r_print_byte(int idx, u8 ch)
{
//	if (flags & R_PRINT_FLAGS_CURSOR && idx == r_print_cur)
		r_cons_printf("%c", ch);
//	else r_cons_printf("%c", ch);
}

void r_print_code(u64 addr, u8 *buf, int len, int step, int columns, int header)
{
	int i, w = 0;
	r_cons_printf("#define _BUFFER_SIZE %d\n", len);
	r_cons_printf("unsigned char buffer[%d] = {", len);
	for(i=0;i<len;i++) {
		if (!(w%columns))
			r_cons_printf("\n  ");
		r_print_cursor(i, 1);
		r_cons_printf("0x%02x, ", buf[i]);
		r_print_cursor(i, 0);
		w+=6;
	}
	r_cons_printf("};\n");
}

void r_print_string(u64 addr, u8 *buf, int len, int step, int columns, int header)
{
	int i;
	for(i=0;i<len;i++) {
		r_print_cursor(i, 1);
		if (IS_PRINTABLE(buf[i]))
			r_cons_printf("%c", buf[i]);
		else r_cons_printf("\\x%02x", buf[i]);
		r_print_cursor(i, 0);
	}
	r_cons_newline();
}

static const char hex[16] = "0123456789ABCDEF";
void r_print_hexdump(u64 addr, u8 *buf, int len, int step, int columns, int header)
{
	int i,j,k,inc;

	inc = 2+(int)((columns-14)/4);
	if (inc%2) inc++;
	inc = 16;

	if (header) {
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
		r_print_addr(addr+(i*step));

		for(j=i;j<i+inc;j++) {
			if (j>=len) {
				r_cons_printf("  ");
				if (j%2) r_cons_printf(" ");
				continue;
			}
			r_print_cursor(j, 1);
			r_cons_printf("%02x", (u8)buf[j]);
			r_print_cursor(j, 0);
			//print_color_byte_i(j, "%02x", (unsigned char)buf[j]);
			if (j%2) r_cons_strcat(" ");
		}

		for(j=i; j<i+inc; j++) {
			if (j >= len)
				r_cons_strcat(" ");
			else {
				r_print_cursor(j, 1);
				r_cons_printf("%c",
				(IS_PRINTABLE(buf[j]))?
					buf[j] : '.');
				r_print_cursor(j, 0);
			}
		}
		r_cons_newline();
		//addr+=inc;
	}
}

void r_print_bytes(const u8* buf, int len, const char *fmt)
{
	int i;
	for(i=0;i<len;i++)
		r_cons_printf(fmt, buf[i]);
	r_cons_newline();
}

void r_print_raw(const u8* buf, int len)
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

/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>

/* int c; ret = hex_to_byet(&c, 'c'); */
int r_hex_to_byte(u8 *val, u8 c)
{
	if ('0' <= c && c <= '9')      *val = (unsigned char)(*val) * 16 + ( c - '0');
	else if (c >= 'A' && c <= 'F') *val = (unsigned char)(*val) * 16 + ( c - 'A' + 10);
	else if (c >= 'a' && c <= 'f') *val = (unsigned char)(*val) * 16 + ( c - 'a' + 10);
	else return 1;
	return 0;
}

/* int byte = hexpair2bin("A0"); */
int r_hex_pair2bin(const char *arg) // (0A) => 10 || -1 (on error)
{
	unsigned char *ptr;
	unsigned char c = '\0';
	unsigned char d = '\0';
	unsigned int  j = 0;

	for (ptr = (unsigned char *)arg; ;ptr = ptr + 1) {
		if (ptr[0]=='\0'||ptr[0]==' ' || j==2)
			break;
		d = c;
		if (r_hex_to_byte(&c, ptr[0])) {
			eprintf("Invalid hexa string at char '%c'.\n", ptr[0]);
			return -1;
		}
		c |= d;
		if (j++ == 0) c <<= 4;
	}

	return (int)c;
}

int r_hex_bin2str(const u8 *in, int len, char *out)
{
	int i;
	char tmp[5];
	out[0]='\0';
	for(i=0;i<len;i++)  {
		sprintf(tmp, "%02x", in[i]);
		strcat(out, tmp);
	}
	return len;
}
/* char buf[1024]; int len = hexstr2binstr("0a 33 45", buf); */
// XXX control out bytes
int r_hex_str2bin(const char *in, u8 *out) // 0A 3B 4E A0
{
	const char *ptr;
	unsigned char  c = '\0';
	unsigned char  d = '\0';
	unsigned int len = 0, j = 0;

	for (ptr = in; ;ptr = ptr + 1) {
		/* ignored chars */
		if (ptr[0]==':' || ptr[0]=='\n' || ptr[0]=='\t' || ptr[0]=='\r' || ptr[0]==' ')
			continue;

		if (j==2) {
			if (j>0) {
				out[len] = c;
				len++;
				c = j = 0;
			}
			if (ptr[0]==' ')
				continue;
		}

		/* break after len++ */
		if (ptr[0] == '\0') break;

		d = c;
		if (ptr[0]=='0' && ptr[1]=='x' ){ //&& c==0) {
			u64 addr   = r_num_get(NULL, ptr);
			unsigned int addr32 = (u32) addr;
			if (addr & ~0xFFFFFFFF) {
				// 64 bit fun
			} else {
				// 32 bit fun
				u8 *addrp = (u8*) &addr32;
				// XXX always copy in native endian?
				out[len++] = addrp[0];
				out[len++] = addrp[1];
				out[len++] = addrp[2];
				out[len++] = addrp[3];
				while(ptr[0]&&ptr[0]!=' '&&ptr[0]!='\t')
					ptr = ptr + 1;
				j = 0;
			}
			continue;
		}
		if (r_hex_to_byte(&c, ptr[0])) {
			//eprintf("binstr: Invalid hexa string at %d ('0x%02x') (%s).\n", (int)(ptr-in), ptr[0], in);
			return -1;
		}
		c |= d;
		if (j++ == 0) c <<= 4;
	}

	return (int)len;
}

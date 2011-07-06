/* radare - LGPL - Copyright 2007-2011 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>

/* int c; ret = hex_to_byet(&c, 'c'); */
R_API int r_hex_to_byte(ut8 *val, ut8 c) {
	if ('0' <= c && c <= '9')      *val = (ut8)(*val) * 16 + (c-'0');
	else if (c >= 'A' && c <= 'F') *val = (ut8)(*val) * 16 + (c-'A'+10);
	else if (c >= 'a' && c <= 'f') *val = (ut8)(*val) * 16 + (c-'a'+10);
	else return 1;
	return 0;
}

/* int byte = hexpair2bin("A0"); */
// (0A) => 10 || -1 (on error)
R_API int r_hex_pair2bin(const char *arg) {
	ut8 *ptr, c = 0, d = 0;
	ut32 j = 0;

	for (ptr = (ut8*)arg; ;ptr = ptr + 1) {
		if (!*ptr || *ptr==' ' || j==2)
			break;
		d = c;
		if (r_hex_to_byte (&c, *ptr)) {
			eprintf ("Invalid hexa string at char '%c'.\n", *ptr);
			return -1;
		}
		c |= d;
		if (j++ == 0) c <<= 4;
	}
	return (int)c;
}

R_API int r_hex_bin2str(const ut8 *in, int len, char *out) {
	int i, idx;
	char tmp[5];
	for (idx=i=0; i<len; i++,idx+=2)  {
		snprintf (tmp, sizeof (tmp), "%02x", in[i]);
		memcpy (out+idx, tmp, 2);
	}
	out[idx] = 0;
	return len;
}

R_API char *r_hex_bin2strdup(const ut8 *in, int len) {
	int i, idx;
	char tmp[5], *out = malloc ((len+1)*2);
	for (i=idx=0; i<len; i++, idx+=2)  {
		snprintf (tmp, sizeof (tmp), "%02x", in[i]);
		memcpy (out+idx, tmp, 2);
	}
	out[idx] = 0;
	return out;
}

R_API int r_hex_str2bin(const char *in, ut8 *out) {
	unsigned int len = 0, j = 0;
	const char *ptr;
	ut8 c = 0, d = 0;

	if (!memcmp (in, "0x", 2))
		in += 2;
	for (ptr = in; ; ptr++) {
		/* ignored chars */
		if (*ptr==':' || *ptr=='\n' || *ptr=='\t' || *ptr=='\r' || *ptr==' ')
			continue;

		if (j==2) {
			out[len] = c;
			len++;
			c = j = 0;
			if (ptr[0]==' ')
				continue;
		}

		/* break after len++ */
		if (ptr[0] == '\0') break;

		d = c;
		if (ptr[0]=='0' && ptr[1]=='x' ){ //&& c==0) {
			ut64 addr = r_num_get (NULL, ptr);
			unsigned int addr32 = (ut32) addr;
			if (addr & ~0xFFFFFFFF) {
				// 64 bit fun
			} else {
				// 32 bit fun
				ut8 *addrp = (ut8*) &addr32;
				// XXX always copy in native endian?
				out[len++] = addrp[0];
				out[len++] = addrp[1];
				out[len++] = addrp[2];
				out[len++] = addrp[3];
				while (*ptr && *ptr!=' ' && *ptr!='\t')
					ptr = ptr + 1;
				j = 0;
			}
			continue;
		}
		if (r_hex_to_byte (&c, ptr[0])) {
			//eprintf("binstr: Invalid hexa string at %d ('0x%02x') (%s).\n", (int)(ptr-in), ptr[0], in);
			return -1;
		}
		c |= d;
		if (j++ == 0) c <<= 4;
	}

	return (int)len;
}

R_API int r_hex_str2binmask(const char *in, ut8 *out, ut8 *mask) {
	ut8 *ptr;
	int len, ilen = strlen (in)+1;
	memcpy (out, in, ilen);
	for (ptr=out; *ptr; ptr++) if (*ptr=='.') *ptr = '0';
	len = r_hex_str2bin ((char*)out, out);
	if (len != -1) {
		memcpy (mask, in, ilen);
		for (ptr=mask; *ptr; ptr++) *ptr = (*ptr=='.')?'0':'f';
		len = r_hex_str2bin ((char*)mask, mask);
	}
	return len;
}

R_API st64 r_hex_bin_truncate (ut64 in, int n) {
	switch (n) {
	case 1:
		if ((in&UT8_GT0))
			return UT64_8U|in;
		return in&UT8_MAX;
	case 2: 
		if ((in&UT16_GT0))
			return UT64_16U|in;
		return in&UT16_MAX;
	case 4: 
		if ((in&UT32_GT0))
			return UT64_32U|in;
		return in&UT32_MAX;
	case 8:
		return in&UT64_MAX;
	}
	return in;
}

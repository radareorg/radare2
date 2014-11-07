/* radare - LGPL - Copyright 2007-2014 - pancake */

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

/* convert:
 *    char *foo = "\x41\x23\x42\x1b";
 * into:
 *    4123421b
 */
R_API char *r_hex_from_c(const char *code) {
	char *out, *ret = malloc (strlen (code)*3);
	int parse_on = 0, is_hexa = 0;
	*ret = 0;
	out = ret;
	if (code) {
		for (;*code; code++) {
			if (*code == '"') {
				parse_on = !!!parse_on;
			} else if (parse_on) {
					char abc[] = "0123456789abcdefABCDEF";
				if (*code == '\\') {
					code++;
					switch (code[0]) {
					case 'e': *out++='1';*out++='b';break;
					case 'r': *out++='0';*out++='d';break;
					case 'n': *out++='0';*out++='a';break;
					case 'x': break;
					default: 
						  goto error;
						  break;
					}
					is_hexa++;
				} else {
					if (is_hexa) {
						if (strchr (abc, *code)) {
							*out++ = *code;
							if (++is_hexa==3)
								is_hexa = 0;
						} else goto error;
					} else {
						*out++ = abc[*code >>4];
						*out++ = abc[*code & 0xf];
					}
				}
			}
		}
	}
	*out++ = 0;
	return ret;
error:
	free (ret);
	return NULL;
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
		if (*ptr!='.' && r_hex_to_byte (&c, *ptr)) {
			eprintf ("Invalid hexa string at char '%c' (%s).\n",
				*ptr, arg);
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
	if (len<0)
		return 0;
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
	int len = 0, j = 0;
	const char *ptr;
	ut8 c = 0, d = 0;
	int outbuf = 0;

	if (!in || !*in)
		return 0;
	if (!strncmp (in, "0x", 2))
		in += 2;
	if (!out) {
		outbuf = 1;
		out = malloc (strlen (in)+1);
	}
	for (ptr = in; ; ptr++) {
		/* comments */
		if (*ptr=='#') {
			while (*ptr && *ptr != '\n') ptr++;
			if (!ptr[0])
				break;
			ptr--;
			continue;
		}
		if (*ptr == '/' && ptr[1]=='*') {
			while (*ptr && ptr[1]) {
				if (*ptr == '*' && ptr[1]=='/')
					break;
				ptr++;
			}
			if (!ptr[0] || !ptr[1])
				break;
			ptr++;
			continue;
		}
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
					ptr++;
				j = 0;
			}
			/* Go back one character, the loop head does ptr++. */
			ptr--;
			continue;
		}
		if (r_hex_to_byte (&c, ptr[0])) {
			//eprintf("binstr: Invalid hexa string at %d ('0x%02x') (%s).\n", (int)(ptr-in), ptr[0], in);
			goto beach;
		}
		c |= d;
		if (j++ == 0) c <<= 4;
	}
	// has nibbles. requires a mask
beach:
	if (j) {
		out[len] = c;
		len = -len;
	}
	if (outbuf) {
		free (out);
	}
	return (int)len;
}

R_API int r_hex_str2binmask(const char *in, ut8 *out, ut8 *mask) {
	ut8 *ptr;
	int len, ilen = strlen (in)+1;
	int has_nibble = 0;
	memcpy (out, in, ilen);
	for (ptr=out; *ptr; ptr++) if (*ptr=='.') *ptr = '0';
	len = r_hex_str2bin ((char*)out, out);
	if (len<0) { has_nibble = 1; len = -len; }
	if (len != -1) {
		memcpy (mask, in, ilen);
		if (has_nibble)
			memcpy (mask+ilen, "f0", 3);
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

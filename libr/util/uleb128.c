/* radare - LGPL - Copyright 2014-2015 - pancake */

#include <r_util.h>

/* dex/dwarf uleb128 implementation */

R_API const ut8 *r_uleb128 (const ut8 *data, int datalen, ut64 *v) {
	ut8 c;
	ut64 s, sum = 0;
	const ut8 *data_end;
	if (v) *v = 0LL;
	if (datalen == ST32_MAX) {
		// WARNING; possible overflow
		datalen = 0xffff;
	} 
	if (datalen < 0) {
		return NULL;
	}
	data_end = data + datalen;
	if (data && datalen > 0) {
		if (*data) {
			for (s = 0; data < data_end; s += 7) {
				c = *(data++) & 0xff;
				sum |= ((ut32) (c & 0x7f) << s);
				if (!(c & 0x80)) break;
			}
		} else {
			data++;
		}
	}
	if (v) *v = sum;
	return data;
}

/* data is the char array containing the uleb number
 * datalen will point (if not NULL) to the length of the uleb number
 * v (if not NULL) will point to the data's value (if fitting the size of an ut64)
 */
R_API const ut8 *r_uleb128_decode (const ut8 *data, int *datalen, ut64 *v) {
	ut8 c = 0xff;
	ut64 s = 0, sum = 0, l = 0;
	if (data && *data) {
		do {
			c = *(data++) & 0xff;
			sum |= ((ut32) (c&0x7f) << s);
			s += 7;
			l++;
		} while (c & 0x80);
	}
	if (v) *v = sum;
	if (datalen) *datalen = l;
	return data;
}

R_API const ut8 *r_uleb128_encode (const ut64 s, int *len) {
	ut8 c = 0;
	int l = 0;
	ut8 *otarget = NULL, *target = NULL;
	ut64 source = s;
	do {
		l++;
		if (!(otarget = realloc (otarget, l))) {
			l = 0;
			break;
		}
		target = otarget+l-1;
		c = 0; //May not be necessary
		c = source & 0x7f;
		source >>= 7;
		if (source) c |= 0x80;
		*(target) = c;
	} while (source);
	if (len) *len = l;
	return otarget;
}

R_API const ut8 *r_leb128 (const ut8 *data, st64 *v) {
	ut8 c = 0;
	st64 s = 0, sum = 0;
	if (data) {
		for (s = 0; *data;) {
			c = *(data++) & 0x0ff;
			sum |= ((st64) (c & 0x7f) << s);
			s += 7;
			if (!(c & 0x80)) break;
		}
	}
	if ((s < (8 * sizeof (sum))) && (c & 0x40)) {
		sum |= -((st64)1 << s);
	}
	if (v) *v = sum;
	return data;
}

#if 0
main() {
	ut32 n;
	ut8 *buf = "\x10\x02\x90\x88";
	r_uleb128 (buf, &n);
	printf ("n = %d\n", n);
}
#endif

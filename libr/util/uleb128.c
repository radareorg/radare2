#include <r_util.h>

/* dex/dwarf uleb128 implementation */

R_API const ut8 *r_uleb128 (const ut8 *data, int datalen, ut64 *v) {
	ut8 c;
	ut64 s, sum = 0;
	const ut8 *data_end;
	if (datalen==ST32_MAX) {
		// WARNING; possible overflow
		datalen = 0xffff;
	} else
	if (datalen<0) {
		return NULL;
	}
	data_end = data + datalen;
	if (data && datalen>0) {
		if (*data) {
			for (s = 0; data<data_end; s += 7) {
				c = *(data++) & 0xff;
				sum |= ((ut32) (c&0x7f) << s);
				if (!(c&0x80)) break;
			}
		} else data++;
	}
	if (v) *v = sum;
	return data;
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

/* radare - LGPL - Copyright 2014-2015 - pancake */

#include "r_util/r_str.h"
#include <r_util.h>

/* dex/dwarf uleb128 implementation */

R_API const ut8 *r_uleb128(const ut8 *data, int datalen, ut64 *v, const char **error) {
	ut8 c;
	ut64 s, sum = 0;
	const ut8 *data_end;
	bool malformed_uleb = true;
	if (v) {
		*v = 0LL;
	}
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
				if (s > 63) {
					if (error) {
						*error = r_str_newf ("r_uleb128: undefined behaviour in %d shift on ut32\n", (int)s);
					}
					break;
				} else {
					sum |= ((ut64) (c & 0x7f) << s);
				}
				if (!(c & 0x80)) {
					malformed_uleb = false;
					break;
				}
			}
			if (malformed_uleb) {
				if (error) {
					*error = r_str_newf ("malformed uleb128\n");
				}
			}
		} else {
			data++;
		}
	}
	if (v) {
		*v = sum;
	}
	return data;
}

R_API int r_uleb128_len (const ut8 *data, int size) {
	int i = 1;
	ut8 c = *(data++);
	while (c > 0x7f && i < size) {
		c = *(data++);
		i++;
	}
	return i;
}

/* data is the char array containing the uleb number
 * datalen will point (if not NULL) to the length of the uleb number
 * v (if not NULL) will point to the data's value (if fitting the size of an ut64)
 */
R_API const ut8 *r_uleb128_decode(const ut8 *data, int *datalen, ut64 *v) {
	ut8 c = 0xff;
	ut64 s = 0, sum = 0, l = 0;
	do {
		c = *(data++) & 0xff;
		sum |= ((ut64) (c&0x7f) << s);
		s += 7;
		l++;
	} while (c & 0x80);
	if (v) {
		*v = sum;
	}
	if (datalen) {
		*datalen = l;
	}
	return data;
}

R_API ut8 *r_uleb128_encode(const ut64 s, int *len) {
	ut8 c = 0;
	int l = 0;
	ut8 *otarget = NULL, *target = NULL, *tmptarget = NULL;
	ut64 source = s;
	do {
		l++;
		if (!(tmptarget = realloc (otarget, l))) {
			l = 0;
			free (otarget);
			otarget = NULL;
			break;
		}
		otarget = tmptarget;
		target = otarget+l-1;
		c = source & 0x7f;
		source >>= 7;
		if (source) {
			c |= 0x80;
		}
		*(target) = c;
	} while (source);
	if (len) {
		*len = l;
	}
	return otarget;
}

R_API const ut8 *r_leb128(const ut8 *data, int datalen, st64 *v) {
	ut8 c = 0;
	st64 s = 0, sum = 0;
	const ut8 *data_end = data + datalen;
	if (data && datalen > 0) {
		if (!*data) {
			data++;
			goto beach;
		}
		while (data < data_end) {
			c = *(data++) & 0x0ff;
			sum |= ((st64) (c & 0x7f) << s);
			s += 7;
			if (!(c & 0x80)) {
				break;
			}
		}
	}
	if ((s < (8 * sizeof (sum))) && (c & 0x40)) {
		sum |= -((st64)1 << s);
	}
beach:
	if (v) {
		*v = sum;
	}
	return data;
}


R_API st64 r_sleb128(const ut8 **data, const ut8 *end) {
	const ut8 *p = *data;
	st64 result = 0;
	int offset = 0;
	ut8 value;
	bool cond;
	do {
		st64 chunk;
		value = *p;
		chunk = value & 0x7f;
		result |= (chunk << offset);
		offset += 7;
	} while (cond = *p & 0x80 && p + 1 < end, p++, cond);

	if ((value & 0x40) != 0) {
		result |= ~0ULL << offset;
	}
	*data = p;
	return result;
}

// API from https://github.com/WebAssembly/wabt/blob/master/src/binary-reader.cc

#define BYTE_AT(type, i, shift) (((type)(p[i]) & 0x7f) << (shift))

#define LEB128_1(type) (BYTE_AT (type, 0, 0))
#define LEB128_2(type) (BYTE_AT (type, 1, 7) | LEB128_1 (type))
#define LEB128_3(type) (BYTE_AT (type, 2, 14) | LEB128_2 (type))
#define LEB128_4(type) (BYTE_AT (type, 3, 21) | LEB128_3 (type))
#define LEB128_5(type) (BYTE_AT (type, 4, 28) | LEB128_4 (type))
#define LEB128_6(type) (BYTE_AT (type, 5, 35) | LEB128_5 (type))
#define LEB128_7(type) (BYTE_AT (type, 6, 42) | LEB128_6 (type))
#define LEB128_8(type) (BYTE_AT (type, 7, 49) | LEB128_7 (type))
#define LEB128_9(type) (BYTE_AT (type, 8, 56) | LEB128_8 (type))
#define LEB128_10(type) (BYTE_AT (type, 9, 63) | LEB128_9 (type))

#define SHIFT_AMOUNT(type, sign_bit) (sizeof(type) * 8 - 1 - (sign_bit))
#define SIGN_EXTEND(type, value, sign_bit) \
	((type)((value) << SHIFT_AMOUNT (type, sign_bit)) >> \
		SHIFT_AMOUNT (type, sign_bit))

R_API size_t read_u32_leb128 (const ut8* p, const ut8* max, ut32* out_value) {
	if (p < max && !(p[0] & 0x80)) {
		*out_value = LEB128_1 (ut32);
		return 1;
	} else if (p + 1 < max && !(p[1] & 0x80)) {
		*out_value = LEB128_2 (ut32);
		return 2;
	} else if (p + 2 < max && !(p[2] & 0x80)) {
		*out_value = LEB128_3 (ut32);
		return 3;
	} else if (p + 3 < max && !(p[3] & 0x80)) {
		*out_value = LEB128_4 (ut32);
		return 4;
	} else if (p + 4 < max && !(p[4] & 0x80)) {
		/* the top bits set represent values > 32 bits */
		// if (p[4] & 0xf0) {}
		*out_value = LEB128_5 (ut32);
		return 5;
	} else {
		/* past the end */
		*out_value = 0;
		return 0;
	}
}

R_API size_t read_i32_leb128 (const ut8* p, const ut8* max, st32* out_value) {
	if (p < max && !(p[0] & 0x80)) {
		ut32 result = LEB128_1 (ut32);
		*out_value = SIGN_EXTEND (ut32, result, 6);
		return 1;
	} else if (p + 1 < max && !(p[1] & 0x80)) {
		ut32 result = LEB128_2 (ut32);
		*out_value = SIGN_EXTEND (ut32, result, 13);
		return 2;
	} else if (p + 2 < max && !(p[2] & 0x80)) {
		ut32 result = LEB128_3 (ut32);
		*out_value = SIGN_EXTEND (ut32, result, 20);
		return 3;
	} else if (p + 3 < max && !(p[3] & 0x80)) {
		ut32 result = LEB128_4 (ut32);
		*out_value = SIGN_EXTEND (ut32, result, 27);
		return 4;
	} else if (p+4 < max && !(p[4] & 0x80)) {
		/* the top bits should be a sign-extension of the sign bit */
		bool sign_bit_set = (p[4] & 0x8);
		int top_bits = p[4] & 0xf0;
		if ((sign_bit_set && top_bits != 0x70) || (!sign_bit_set && top_bits != 0)) {
			return 0;
		}
		ut32 result = LEB128_5 (ut32);
		*out_value = result;
		return 5;
	} else {
		/* past the end */
		return 0;
	}
}

R_API size_t read_u64_leb128 (const ut8* p, const ut8* max, ut64* out_value) {
	if (p < max && !(p[0] & 0x80)) {
		*out_value = LEB128_1 (ut64);
		return 1;
	} else if (p + 1 < max && !(p[1] & 0x80)) {
		*out_value = LEB128_2 (ut64);
		return 2;
	} else if (p + 2 < max && !(p[2] & 0x80)) {
		*out_value = LEB128_3 (ut64);
		return 3;
	} else if (p + 3 < max && !(p[3] & 0x80)) {
		*out_value = LEB128_4 (ut64);
		return 4;
	} else if (p + 4 < max && !(p[4] & 0x80)) {
		*out_value = LEB128_5 (ut64);
		return 5;
	} else if (p + 5 < max && !(p[5] & 0x80)) {
		*out_value = LEB128_6 (ut64);
		return 6;
	} else if (p + 6 < max && !(p[6] & 0x80)) {
		*out_value = LEB128_7 (ut64);
		return 7;
	} else if (p + 7 < max && !(p[7] & 0x80)) {
		*out_value = LEB128_8 (ut64);
		return 8;
	} else if (p + 8 < max && !(p[8] & 0x80)) {
		*out_value = LEB128_9 (ut64);
		return 9;
	} else if (p + 9 < max && !(p[9] & 0x80)) {
		*out_value = LEB128_10 (ut64);
		return 10;
	} else {
		/* past the end */
		*out_value = 0;
		return 0;
	}
}

R_API size_t read_i64_leb128 (const ut8* p, const ut8* max, st64* out_value) {
	if (p < max && !(p[0] & 0x80)) {
		ut64 result = LEB128_1 (ut64);
		*out_value = SIGN_EXTEND (ut64, result, 6);
		return 1;
	} else if (p + 1 < max && !(p[1] & 0x80)) {
		ut64 result = LEB128_2(ut64);
		*out_value = SIGN_EXTEND (ut64, result, 13);
		return 2;
	} else if (p + 2 < max && !(p[2] & 0x80)) {
		ut64 result = LEB128_3 (ut64);
		*out_value = SIGN_EXTEND (ut64, result, 20);
		return 3;
	} else if (p + 3 < max && !(p[3] & 0x80)) {
		ut64 result = LEB128_4 (ut64);
		*out_value = SIGN_EXTEND (ut64, result, 27);
		return 4;
	} else if (p + 4 < max && !(p[4] & 0x80)) {
		ut64 result = LEB128_5 (ut64);
		*out_value = SIGN_EXTEND (ut64, result, 34);
		return 5;
	} else if (p + 5 < max && !(p[5] & 0x80)) {
		ut64 result = LEB128_6 (ut64);
		*out_value = SIGN_EXTEND (ut64, result, 41);
		return 6;
	} else if (p + 6 < max && !(p[6] & 0x80)) {
		ut64 result = LEB128_7 (ut64);
		*out_value = SIGN_EXTEND (ut64, result, 48);
		return 7;
	} else if (p + 7 < max && !(p[7] & 0x80)) {
		ut64 result = LEB128_8 (ut64);
		*out_value = SIGN_EXTEND (ut64, result, 55);
		return 8;
	} else if (p + 8 < max && !(p[8] & 0x80)) {
		ut64 result = LEB128_9 (ut64);
		*out_value = SIGN_EXTEND (ut64, result, 62);
		return 9;
	} else if (p + 9 < max && !(p[9] & 0x80)) {
		/* the top bits should be a sign-extension of the sign bit */
		bool sign_bit_set = (p[9] & 0x1);
		int top_bits = p[9] & 0xfe;
		if ((sign_bit_set && top_bits != 0x7e) || (!sign_bit_set && top_bits != 0)) {
			return 0;
		}
		ut64 result = LEB128_10 (ut64);
		*out_value = result;
		return 10;
	} else {
		/* past the end */
		return 0;
	}
}

#undef BYTE_AT
#undef LEB128_1
#undef LEB128_2
#undef LEB128_3
#undef LEB128_4
#undef LEB128_5
#undef LEB128_6
#undef LEB128_7
#undef LEB128_8
#undef LEB128_9
#undef LEB128_10
#undef SHIFT_AMOUNT
#undef SIGN_EXTEND

#if 0
main() {
	ut32 n;
	ut8 *buf = "\x10\x02\x90\x88";
	r_uleb128 (buf, &n);
	printf ("n = %d\n", n);
}
#endif

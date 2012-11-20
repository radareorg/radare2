/* radare - LGPL - Copyright 2012 - pancake */

#include <r_anal.h>

#define MINLEN 1
static int is_string (const ut8 *buf, int len) {
	int i;
	if (len>3 && buf[0] &&!buf[1]&&buf[2]&&!buf[3])
		return 2; // is wide
	for (i=0; i<len; i++) {
		if (!buf[i] && i>MINLEN) return 1;
		if (!IS_PRINTABLE (buf[i]))
			return 0;
	}
	return 1;
}

static int is_number (const ut8 *buf, int endian, int size) {
	ut64 n = r_mem_get_num (buf, size, endian);
	return (n<0xffffffff)? (int)n: 0;
}

static int is_null (const ut8 *buf, int size) {
	const char zero[8] = {0,0,0,0,0,0,0,0};
	return (!memcmp (buf, &zero, size))? 1: 0;
}

static int is_invalid (const ut8 *buf, int size) {
	return (!memcmp (buf, "\xff\xff\xff\xff\xff\xff\xff\xff", size))? 1: 0;
}

static ut64 is_pointer(RIOBind *iob, const ut8 *buf, int endian, int size) {
	ut8 buf2[32];
	int ret;
	ut64 n = r_mem_get_num (buf, size, endian);
	if (!n) return 1; // null pointer
	ret = iob->read_at (iob->io, n, buf2, size);
	if (ret != size) return 0;
	return is_invalid (buf2, size)? 0: n;
}

static int is_bin(const ut8 *buf) {
	// TODO: add more
	if((!memcmp (buf, "\xcf\xfa\xed\xfe", 4))
	|| (!memcmp (buf, "\x7FELF", 4))
	|| (!memcmp (buf, "MZ", 2)))
		return 1;
	return 0;
}

// TODO : is_flag, is comment?

typedef struct r_anal_data_t {
	int type;
	ut64 ptr;
	char *str;
} RAnalData;

R_API int r_anal_data (RAnal *anal, ut64 addr, const ut8 *buf, int size) {
	ut64 dst;
	int n, i;
	int bits = anal->bits;
	int endi = !anal->big_endian;
	int word = bits/8;

	eprintf ("0x%08"PFMT64x"  ", addr);
	for (i=0;i<word; i++)
		eprintf ("%02x ", buf[i]);
	eprintf (" ");
	if (is_null (buf, word)) {
		eprintf ("null\n");
		return R_ANAL_DATA_TYPE_NULL;
	}
	if (is_invalid (buf, word)) {
		eprintf ("invalid (-1)\n");
		return R_ANAL_DATA_TYPE_INVALID;
	}
	if (is_bin (buf)) {
		eprintf ("bin\n");
		return R_ANAL_DATA_TYPE_BIN;
	}
	n = is_number (buf, endi, word);
	if (n) {
		eprintf ("0x%x\n", n);
		return R_ANAL_DATA_TYPE_NUMBER;
	}
	dst = is_pointer (&anal->iob, buf, endi, word);
	if (dst) {
		eprintf ("ptr 0x%08"PFMT64x"\n", dst);
		return R_ANAL_DATA_TYPE_POINTER;
	}
	switch (is_string (buf, size)) {
	case 1:
		eprintf (" '%s'\n", buf);
		return R_ANAL_DATA_TYPE_STRING;
	case 2:
		eprintf ("\"%s\"\n", buf); // XXX
		return R_ANAL_DATA_TYPE_WIDE_STRING;
	}
	eprintf ("unknown\n");
	return R_ANAL_DATA_TYPE_UNKNOWN;
	// TODO detect TLV of 1 and 4 bytes
}

R_API int r_anal_data_type(RAnal *anal, const ut8 *buf, int len) {
	int i;
	for (i=0; i<len; i++) {
	}
// IS CODE, STACK OR DATA
	return 0;
}

R_API const char *r_anal_data_kind (RAnal *anal, ut64 addr, const ut8 *buf, int len) {
	int inv = 0;
	int unk = 0;
	int str = 0;
	int i, j;
	int word = anal->bits /8;
	for (i = j = 0; i<len ; j++ ) {
		int type = r_anal_data (anal, addr+i,
			buf+i, len-i);
		switch (type) {
		case R_ANAL_DATA_TYPE_INVALID:
			inv++;
			i += word;
			break;
		case R_ANAL_DATA_TYPE_UNKNOWN:
			unk++;
			i += word;
			break;
		case R_ANAL_DATA_TYPE_STRING:
			i += strlen ((const char*)buf+i)+1;
			str++;
			break;
		default:
			i += word;
		}
        }
	if ((inv*100/j)>60) return "invalid";
	if ((unk*100/j)>60) return "code";
	if ((str*100/j)>40) return "text";
	return "data";
}

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
	|| (!memcmp (buf, "\x7f""ELF", 4))
	|| (!memcmp (buf, "MZ", 2)))
		return 1;
	return 0;
}

// TODO : add is_flag, is comment?

// XXX: optimize by removing all strlens here
R_API char *r_anal_data_to_string (RAnalData *d) {
	int i;
	char *line = malloc (128);
	sprintf (line, "0x%08"PFMT64x"  ", d->addr);
	for (i=0;i<d->len; i++)
		sprintf (line+strlen (line), "%02x", d->buf[i]);
	strcat (line, "  ");
	switch (d->type) {
	case R_ANAL_DATA_TYPE_STRING:
		// XXX: overflow
		sprintf (line+strlen (line), "string \"%s\"", d->str);
		break;
	case R_ANAL_DATA_TYPE_WIDE_STRING:
		strcat (line, "wide string");
		break;
	case R_ANAL_DATA_TYPE_NUMBER:
		strcat (line, "number ");
		sprintf (line+strlen (line), " 0x%"PFMT64x, d->ptr);
		break;
	case R_ANAL_DATA_TYPE_POINTER:
		strcat (line, "pointer ");
		sprintf (line+strlen (line), " 0x%08"PFMT64x, d->ptr);
		break;
	case R_ANAL_DATA_TYPE_INVALID:
		strcat (line, "invalid");
		break;
	case R_ANAL_DATA_TYPE_HEADER:
		strcat (line, "header");
		break;
	case R_ANAL_DATA_TYPE_UNKNOWN:
		strcat (line, "unknown");
		break;
	}
	return line;
}

R_API RAnalData *r_anal_data_new_string (ut64 addr, const char *p, int wide) {
	RAnalData *ad = R_NEW0 (RAnalData);
	ad->addr = addr;
	ad->type = wide? R_ANAL_DATA_TYPE_WIDE_STRING: R_ANAL_DATA_TYPE_STRING;
	if (wide) {
		/* TODO: add support for wide strings */
		eprintf ("r_anal_data_new_string: wide string not supported yet\n");
	} else {
		ad->str = strdup (p);
		ad->len = strlen (p); 
	}
	ad->ptr = 0L; 
	return ad;
}

R_API RAnalData *r_anal_data_new (ut64 addr, int type, ut64 n, const ut8 *buf, int len) {
	RAnalData *ad = R_NEW0 (RAnalData);
	if (buf) memcpy (ad->buf, buf, 8);
	else memset (ad->buf, 0, 8);
	ad->addr = addr;
	ad->type = type;
	ad->str = NULL;
	ad->len = len;
	ad->ptr = n;
	return ad;
}

R_API void r_anal_data_free (RAnalData *d) {
	free (d->str);
	free (d);
}

R_API RAnalData *r_anal_data (RAnal *anal, ut64 addr, const ut8 *buf, int size) {
	ut64 dst;
	int n;
	int bits = anal->bits;
	int endi = !anal->big_endian;
	int word = bits/8;

	if (is_null (buf, word))
		return r_anal_data_new (addr, R_ANAL_DATA_TYPE_NULL, 0, buf, word);
	if (is_invalid (buf, word))
		return r_anal_data_new (addr, R_ANAL_DATA_TYPE_INVALID, -1, buf, word);
	if (is_bin (buf))
		return r_anal_data_new (addr, R_ANAL_DATA_TYPE_HEADER, -1, buf, word);
	dst = is_pointer (&anal->iob, buf, endi, word);
	if (dst) return r_anal_data_new (addr, R_ANAL_DATA_TYPE_POINTER, dst, buf, word);
	n = is_number (buf, endi, word);
	if (n) return r_anal_data_new (addr, R_ANAL_DATA_TYPE_NUMBER, n, buf, word);
	switch (is_string (buf, size)) {
	case 1: return r_anal_data_new_string (addr, (const char *)buf, R_ANAL_DATA_TYPE_STRING);
	case 2: return r_anal_data_new_string (addr, (const char *)buf, R_ANAL_DATA_TYPE_WIDE_STRING);
	}
	return r_anal_data_new (addr, R_ANAL_DATA_TYPE_UNKNOWN, dst, buf, word);
}

R_API const char *r_anal_data_kind (RAnal *anal, ut64 addr, const ut8 *buf, int len) {
	int inv = 0;
	int unk = 0;
	int str = 0;
	int num = 0;
	int i, j;
	RAnalData *data;
	int word = anal->bits /8;
	for (i = j = 0; i<len ; j++ ) {
		data = r_anal_data (anal, addr+i,
			buf+i, len-i);
		switch (data->type) {
		case R_ANAL_DATA_TYPE_INVALID:
			inv++;
			i += word;
			break;
		case R_ANAL_DATA_TYPE_NUMBER:
			if (data->ptr> 1000) num++;
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
		r_anal_data_free (data);
        }
	if ((inv*100/j)>60) return "invalid";
	if ((unk*100/j)>60) return "code";
	if ((num*100/j)>60) return "code";
	if ((str*100/j)>40) return "text";
	return "data";
}

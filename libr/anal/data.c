/* radare - LGPL - Copyright 2012-2014 - pancake */

#include <r_anal.h>

#define MINLEN 1
static int is_string (const ut8 *buf, int size, int *len) {
	int i;
	if (size<1)
		return 0;
	if (size>3 && buf[0] &&!buf[1]&&buf[2]&&!buf[3]) {
		*len = 1; // XXX: TODO: Measure wide string length
		return 2; // is wide
	}
	for (i=0; i<size; i++) {
		if (!buf[i] && i>MINLEN) {
			*len = i;
			return 1;
		}
		if (buf[i]<32 || buf[i]>127) {
			// not ascii text
			return 0;
		}
		if (buf[i]==10||buf[i]==13||buf[i]==9) {
			continue;
		}
		if (!IS_PRINTABLE (buf[i])) {
			*len = i;
			return 0;
		}
	}
	*len = i;
	return 1;
}

static int is_number (const ut8 *buf, int endian, int size) {
	ut64 n = r_mem_get_num (buf, size, endian);
	return (n<UT32_MAX)? (int)n: 0;
}

static int is_null (const ut8 *buf, int size) {
	const char zero[8] = {0,0,0,0,0,0,0,0};
	return (!memcmp (buf, &zero, size))? 1: 0;
}

static int is_invalid (const ut8 *buf, int size) {
	if (size<1) return 1;
	if (size>8) size = 8;
	return (!memcmp (buf, "\xff\xff\xff\xff\xff\xff\xff\xff", size))? 1: 0;
}

#define USE_IS_VALID_OFFSET 1
static ut64 is_pointer(RIOBind *iob, const ut8 *buf, int endian, int size) {
	ut64 n;
	ut8 buf2[32];
	if (size > sizeof (buf2))
		size = sizeof (buf2);
	n = r_mem_get_num (buf, size, endian);
	if (!n) return 1; // null pointer
#if USE_IS_VALID_OFFSET
	int r = iob->is_valid_offset (iob->io, n);
	return r? n: 0LL;
#else 
	// optimization to ignore very low and very high pointers
	// this makes disasm 5x faster, but can result in some false positives
	// we should compare with current offset, to avoid
	// short/long references. and discard invalid ones
	if (n<0x1000) return 0; // probably wrong
	if (n>0xffffffffffffLL) return 0; // probably wrong

	if (iob->read_at (iob->io, n, buf2, size) != size) return 0;
	return is_invalid (buf2, size)? 0: n;
#endif
}

static int is_bin(const ut8 *buf, int size) {
	// TODO: add more
	if((size >= 4 && !memcmp (buf, "\xcf\xfa\xed\xfe", 4))
	|| (size >= 4 && !memcmp (buf, "\x7e""ELF", 4))
	|| (size >= 2 && !memcmp (buf, "MZ", 2)))
		return 1;
	return 0;
}

// TODO : add is_flag, is comment?

// XXX: optimize by removing all strlens here
R_API char *r_anal_data_to_string (RAnalData *d) {
	int i, len, idx, mallocsz = 1024;
	ut32 n32;
	char *line;

	if (!d) return NULL;

	line = malloc (mallocsz);
	snprintf (line, mallocsz, "0x%08"PFMT64x"  ", d->addr);
	n32 = (ut32)d->ptr;
	len = R_MIN (d->len, 8);
	for (i=0, idx = strlen (line); i<len; i++) {
		int msz = mallocsz-idx;
		if (msz>1) {
			snprintf (line+idx, msz, "%02x", d->buf[i]);
			idx += 2;
		}
	}
	if (i>0 && d->len> len) {
		int msz = mallocsz-idx;
		snprintf (line+idx, msz, "..");
		idx += 2;
		msz -= 2;
	}
	strcat (line, "  ");
	idx += 2;
	if ((mallocsz-idx)>12)
	switch (d->type) {
	case R_ANAL_DATA_TYPE_STRING:
		snprintf (line+idx, mallocsz-idx, "string \"%s\"", d->str);
		idx = strlen (line);
		break;
	case R_ANAL_DATA_TYPE_WIDE_STRING:
		strcat (line, "wide string");
		break;
	case R_ANAL_DATA_TYPE_NUMBER:
		if (n32 == d->ptr)
			snprintf (line+idx, mallocsz-idx, "number %d 0x%x", n32, n32);
		else snprintf (line+idx, mallocsz-idx, "number %"PFMT64d" 0x%"PFMT64x,
				d->ptr, d->ptr);
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
	case R_ANAL_DATA_TYPE_SEQUENCE:
		strcat (line, "sequence");
		break;
	case R_ANAL_DATA_TYPE_PATTERN:
		strcat (line, "pattern");
		break;
	case R_ANAL_DATA_TYPE_UNKNOWN:
		strcat (line, "unknown");
		break;
	default:
		strcat (line, "(null)");
		break;
	}
	return line;
}

R_API RAnalData *r_anal_data_new_string (ut64 addr, const char *p, int len, int type) {
	RAnalData *ad = R_NEW0 (RAnalData);
	ad->str = NULL;
	ad->addr = addr;
	ad->type = type;
	if (len == 0)
		len = strlen (p);
	if (type == R_ANAL_DATA_TYPE_WIDE_STRING) {
		/* TODO: add support for wide strings */
		//eprintf ("r_anal_data_new_string: wide string not supported yet\n");
	} else {
		ad->str = malloc (len+1);
		memcpy (ad->str, p, len);
		ad->str[len] = 0;
		ad->buf = malloc (len+1);
		memcpy (ad->buf, ad->str, len+1);
		ad->len = len+1; // string length + \x00
	}
	ad->ptr = 0L;
	return ad;
}

R_API RAnalData *r_anal_data_new (ut64 addr, int type, ut64 n, const ut8 *buf, int len) {
	RAnalData *ad = R_NEW0 (RAnalData);
	int l = R_MIN (len, 8);
	ad->buf = (ut8*) &(ad->sbuf);
	memset (ad->buf, 0, 8);
	if (l<1) {
		r_anal_data_free (ad);
		return NULL;
	}
	if (buf) {
		memcpy (ad->buf, buf, l);
	}
	ad->addr = addr;
	ad->type = type;
	ad->str = NULL;
	switch (type) {
		case R_ANAL_DATA_TYPE_PATTERN:
		case R_ANAL_DATA_TYPE_SEQUENCE:
			ad->len = len;
			break;
		default:
			ad->len = l;
	}
	ad->ptr = n;
	return ad;
}

R_API void r_anal_data_free (RAnalData *d) {
	if (d) {
		if (d->buf != (ut8*)&(d->sbuf)) free (d->buf);
		if (d->str != NULL) free (d->str);
		free (d);
	}
}

R_API RAnalData *r_anal_data (RAnal *anal, ut64 addr, const ut8 *buf, int size) {
	ut64 dst = 0;
	int n, nsize = 0;
	int bits = anal->bits;
	int endi = !anal->big_endian;
	int word = R_MIN (8, bits/8);

	if (size<4)
		return NULL;
	if (size >= word && is_invalid (buf, word))
		return r_anal_data_new (addr, R_ANAL_DATA_TYPE_INVALID,
			-1, buf, word);
	{
		int i, len = R_MIN (size, 64);
		int is_pattern = 0;
		int is_sequence = 0;
		char ch = buf[0];
		char ch2 = ch+1;
		for (i=1; i<len; i++) {
			if (ch2 == buf[i]) {
				ch2++;
				is_sequence++;
			} else is_sequence = 0;
			if (ch==buf[i]) {
				is_pattern++;
			}
		}
		//eprintf ("%d %d %d %d\n", is_sequence, is_pattern , len, size);
		if (is_sequence>len-2) {
			return r_anal_data_new (addr, R_ANAL_DATA_TYPE_SEQUENCE, -1,
					buf, is_sequence);
		}
		if (is_pattern>len-2) {
			return r_anal_data_new (addr, R_ANAL_DATA_TYPE_PATTERN, -1,
					buf, is_pattern);
		}
	}
	if (size >= word && is_null (buf, word))
		return r_anal_data_new (addr, R_ANAL_DATA_TYPE_NULL,
			-1, buf, word);
	if (is_bin (buf, size))
		return r_anal_data_new (addr, R_ANAL_DATA_TYPE_HEADER, -1,
				buf, word);
	if (size>=word) {
		dst = is_pointer (&anal->iob, buf, endi, word);
		if (dst) return r_anal_data_new (addr,
			R_ANAL_DATA_TYPE_POINTER, dst, buf, word);
	}
	switch (is_string (buf, size, &nsize)) {
	case 1: return r_anal_data_new_string (addr, (const char *)buf,
		nsize, R_ANAL_DATA_TYPE_STRING);
	case 2: return r_anal_data_new_string (addr, (const char *)buf,
		nsize, R_ANAL_DATA_TYPE_WIDE_STRING);
	}
	if (size >= word) {
		n = is_number (buf, endi, word);
		if (n) return r_anal_data_new (addr, R_ANAL_DATA_TYPE_NUMBER,
				n, buf, word);
	}
	return r_anal_data_new (addr, R_ANAL_DATA_TYPE_UNKNOWN, dst,
		buf, R_MIN(word, size));
}

R_API const char *r_anal_data_kind (RAnal *a, ut64 addr, const ut8 *buf, int len) {
	int inv = 0;
	int unk = 0;
	int str = 0;
	int num = 0;
	int i, j;
	RAnalData *data;
	int word = a->bits /8;
	for (i = j = 0; i<len; j++) {
		if (str && !buf[i])
			str ++;
		data = r_anal_data (a, addr+i, buf+i, len-i);
		if (data == NULL) {
			i+= word;
			continue;
		}
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
			if (data->len>0) {
				i += data->len; //strlen ((const char*)buf+i)+1;
			} else i+=word;
			str++;
			break;
		default:
			i += word;
		}
		r_anal_data_free (data);
        }
//eprintf ("%d %d %d %d\n", inv, unk, num, str);
	if (j<1) return "unknown";
	if ((inv*100/j)>60) return "invalid";
	if ((unk*100/j)>60) return "code";
	if ((num*100/j)>60) return "code";
//return "text";
	if ((str*100/j)>40) return "text";
	return "data";
}

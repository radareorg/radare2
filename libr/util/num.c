/* radare - LGPL - Copyright 2007-2014 - pancake */

#include "r_util.h"
#define R_NUM_USE_CALC 1

R_API ut16 r_num_ntohs (ut16 foo) {
#if LIL_ENDIAN
	ut8 *p = (ut8*)&foo;
	foo = p[1] | p[0]<<8;
#endif
	return foo;
}

#define __htonq(x) (\
        (((x) & 0xff00000000000000LL) >> 56)  | \
        (((x) & 0x00ff000000000000LL) >> 40)  | \
        (((x) & 0x0000ff0000000000LL) >> 24)  | \
        (((x) & 0x000000ff00000000LL) >> 8)   | \
        (((x) & 0x00000000ff000000LL) << 8)   | \
        (((x) & 0x0000000000ff0000LL) << 24)  | \
        (((x) & 0x000000000000ff00LL) << 40)  | \
        (((x) & 0x00000000000000ffLL) << 56))

R_API ut64 r_num_htonq(ut64 value) {
        ut64 ret = value;
#if LIL_ENDIAN
        r_mem_copyendian ((ut8*)&ret, (ut8*)&value, 8, 0);
#endif
        return ret;
}

R_API void r_num_irand() {
	srand (r_sys_now ());
}

static int rand_initialized = 0;
R_API int r_num_rand(int max) {
	if (!rand_initialized) {
		r_num_irand ();
		rand_initialized = 1;
	}
	if (!max) max = 1;
	return rand()%max;
}

R_API void r_num_minmax_swap(ut64 *a, ut64 *b) {
	if (*a>*b) {
		ut64 tmp = *a;
		*a = *b;
		*b = tmp;
	}
}

R_API void r_num_minmax_swap_i(int *a, int *b) {
	if (*a>*b) {
		ut64 tmp = *a;
		*a = *b;
		*b = tmp;
	}
}

R_API RNum *r_num_new(RNumCallback cb, void *ptr) {
	RNum *num = R_NEW (RNum);
	if (!num) return NULL;
	num->value = 0LL;
	num->callback = cb;
	num->userptr = ptr;
	return num;
}

R_API void r_num_free(RNum *num) {
	free (num);
}

#define KB (1024)
#define MB (1024*KB)
#define GB (1024*MB)
#define TB (1024*GB)

R_API char *r_num_units(char *buf, ut64 num) {
	char unit;
	double fnum = num;
	if (!buf) buf = malloc (32);
	//if (num>TB) { unit = 'T'; fnum = num/TB; } else
	if (num>GB) { unit = 'G'; fnum = fnum/GB; } else
	if (num>MB) { unit = 'M'; fnum = fnum/MB; } else
	if (num>KB) { unit = 'K'; fnum = fnum/KB; } else
		{ unit = 0; fnum = num; }
	snprintf (buf, 31, "%.1f%c", fnum, unit);
	return buf;
}

// TODO: try to avoid the use of sscanf
/* old get_offset */
R_API ut64 r_num_get(RNum *num, const char *str) {
	int i, j, ok;
	char lch, len;
	ut64 ret = 0LL;
	ut32 s, a;

	if (!str) return 0;
	for (; *str==' '; ) str++;
	if (!*str) return 0;

	/* resolve string with an external callback */
	if (num && num->callback) {
		ok = 0;
		ret = num->callback (num->userptr, str, &ok);
		if (ok) return ret;
	}

	if (str[0]=='\'' && str[2]=='\'')
		return (ut64)str[1];

	len = strlen (str);
	if (len>3 && str[4] == ':') {
		if (sscanf (str, "%04x", &s)==1)
			if (sscanf (str+5, "%04x", &a)==1)
				return (ut64) ((s<<4) + a);
	} else if (len>6 && str[6] == ':') {
		if (sscanf (str, "0x%04x:0x%04x", &s, &a) == 2)
			return (ut64) ((s<<4) + a);
		if (sscanf (str, "0x%04x:%04x", &s, &a) == 2)
			return (ut64) ((s<<4) + a);
	}
	if (str[0]=='0' && str[1]=='b') {
		ret = 0;
		for (j=0, i=strlen (str)-1; i>0; i--, j++) {
			if (str[i]=='1') ret|=1<<j;
			else if (str[i]!='0') break;
		}
		sscanf (str, "0x%"PFMT64x, &ret);
	} else
	if (str[0]=='0' && str[1]=='x') {
		ret = strtoull (str+2, NULL, 16);
		//sscanf (str+2, "%"PFMT64x, &ret);
	} else {
		lch = str[len>0?len-1:0];
		if (*str=='0' && lch != 'b' && lch != 'h')
			lch = 'o';
		switch (lch) {
		case 'h': // hexa
			sscanf (str, "%"PFMT64x, &ret);
			break;
		case 'o': // octal
			sscanf (str, "%"PFMT64o, &ret);
			break;
		case 'b': // binary
			ret = 0;
			for (j=0, i=strlen (str)-2; i>=0; i--, j++) {
				if (str[i]=='1') ret|=1<<j;
				else if (str[i]!='0') break;
			}
			break;
		case 'K': case 'k':
			sscanf (str, "%"PFMT64d, &ret);
			ret *= 1024;
			break;
		case 'M': case 'm':
			sscanf (str, "%"PFMT64d, &ret);
			ret *= 1024*1024;
			break;
		case 'G': case 'g':
			sscanf (str, "%"PFMT64d, &ret);
			ret *= 1024*1024*1024;
			break;
		default:
			//sscanf (str, "%"PFMT64d, &ret);
			ret = strtoull (str, NULL, 10);
			break;
		}
	}
	if (num != NULL)
		num->value = ret;
	return ret;
}

#if !R_NUM_USE_CALC
static ut64 r_num_op(RNum *num, char op, ut64 a, ut64 b) {
	switch (op) {
	case '+': return a+b;
	case '-': return a-b;
	case '*': return a*b;
	case '/':
		if (!b && num) num->dbz = 1;
		return b?a/b:0;
	case '&': return a&b;
	case '|': return a|b;
	case '^': return a^b;
	}
	return b;
}

R_API static ut64 r_num_math_internal(RNum *num, char *s) {
	ut64 ret = 0LL;
	char *p = s;
	int i, nop, op = 0;
	for (i=0; s[i]; i++) {
		switch (s[i]) {
		case '/':
		case '+':
		case '-':
		case '*':
		case '&':
		case '^':
		case '|':
			nop = s[i]; s[i] = '\0';
			ret = r_num_op (num, op, ret, r_num_get (num, p));
			op = s[i] = nop; p = s + i + 1;
			break;
		}
	}
	return r_num_op (op, ret, r_num_get (num, p));
}
#endif

R_API ut64 r_num_math(RNum *num, const char *str) {
#if R_NUM_USE_CALC
	ut64 ret;
	const char *err = NULL;
	if (!str) return 0LL;
	//if (!str || !*str) return 0LL;
	if (num) {
		num->dbz = 0;
	}
	ret = r_num_calc (num, str, &err);
	if (err) eprintf ("r_num_calc error: (%s) in (%s)\n", err, str);
	else if (num) num->value = ret;
	if (num != NULL)
		num->value = ret;
	return ret;
#else
	ut64 ret = 0LL;
	char op = '+';
	int len;
	char *p, *s, *os;
	char *group;
	if (!str) return 0LL;

	len = strlen (str)+1;
	os = malloc (len+1);

	s = os;
	memcpy (s, str, len);
	for (; *s==' '; s++);
	p = s;

	do {
		group = strchr (p, '(');
		if (group) {
			group[0] = '\0';
			ret = r_num_op (op, ret, r_num_math_internal (num, p));
			for (; p<group; p+=1) {
				switch (*p) {
				case '+':
				case '-':
				case '*':
				case '/':
				case '&':
				case '|':
				case '^':
					op = *p;
					break;
				}
			}
			group[0] = '(';
			p = group+1;
			if (r_str_delta (p, '(', ')')<0) {
				char *p2 = strchr (p, '(');
				if (p2 != NULL) {
					*p2 = '\0';
					ret = r_num_op (op, ret, r_num_math_internal (num, p));
					ret = r_num_op (op, ret, r_num_math (num, p2+1));
					p = p2+1; 
					continue;
				} else eprintf ("WTF!\n");
			} else ret = r_num_op (op, ret, r_num_math_internal (num, p));
		} else ret = r_num_op (op, ret, r_num_math_internal (num, p));
	} while (0);

	if (num != NULL)
		num->value = ret;
	free (os);
	return ret;
#endif
}

R_API int r_num_is_float(struct r_num_t *num, const char *str) {
	// TODO: also support 'f' terminated strings
	return (strchr (str, '.') != NULL)? R_TRUE:R_FALSE;
}

R_API double r_num_get_float(struct r_num_t *num, const char *str) {
	double d = 0.0f;
	sscanf (str, "%lf", &d);
	return d;
}

R_API int r_num_to_bits (char *out, ut64 num) {
	int size = 64, i;

	if (num>>32) size = 64;
	else if (num&0xff000000) size = 32;
	else if (num&0xff0000) size = 24;
	else if (num&0xff00) size = 16;
	else if (num&0xff) size = 8;
	if (out) {
		int pos = 0;
		int realsize = 0;
		int hasbit = 0;
		for (i=0; i<size; i++) {
			char bit = ((num>>(size-i-1))&1)? '1': '0';
			if (hasbit || bit=='1') {
				out[pos++] = bit;//size-1-i] = bit;
			}
			if (!hasbit && bit=='1') {
				hasbit=1;
				realsize = size-i;
			}
		}
		if (realsize==0)
		out[realsize++] = '0';
		out[realsize] = '\0'; //Maybe not nesesary?

	}
	return size;
}

static const char *trit_c = "012";

R_API int r_num_to_trits (char *out, ut64 num) {
	int i = 63, j;
	while (i>=0 && num) {
		out[i] = trit_c[num % 3];
		num = num/3;
		i--;
	}
	j = 63 - i;
	i++;
	memmove (out, &out[i], j);
	out[j] = '\0';
	return R_TRUE;
}

R_API ut64 r_num_chs (int cylinder, int head, int sector, int sectorsize) {
	if (sectorsize<1) sectorsize = 512;
	return (ut64)cylinder * (ut64)head * (ut64)sector * (ut64)sectorsize;
}

R_API int r_num_conditional(RNum *num, const char *str) {
	char *lgt, *t, *p, *s = strdup (str);
	int res = 0;
	ut64 n, a, b;
	p = s;
	do {
		t = strchr (p, ',');
		if (t) *t = 0;
		lgt = strchr (p, '<');
		if (lgt) {
			*lgt = 0;
			a = r_num_math (num, p);
			if (lgt[1]=='=') {
				b = r_num_math (num, lgt+2);
				if (a>b) goto fail;
			} else {
				b = r_num_math (num, lgt+1);
				if (a>=b) goto fail;
			}
		} else {
			lgt = strchr (p, '>');
			if (lgt) {
				*lgt = 0;
				a = r_num_math (num, p);
				if (lgt[1]=='=') {
					b = r_num_math (num, lgt+2);
					if (a<b) goto fail;
				} else {
					b = r_num_math (num, lgt+1);
					if (a<=b) goto fail;
				}
			} else {
				lgt = strchr (p, '=');
				if (lgt && lgt > p) {
					lgt--;
					if (*lgt=='!') {
						r_str_replace_char (p, '!', ' ');
						r_str_replace_char (p, '=', '-');
						n = r_num_math (num, p);
						if (!n) goto fail;
					}
				}
				lgt = strstr (p, "==");
				if (lgt) *lgt = ' ';
				r_str_replace_char (p, '=', '-');
				n = r_num_math (num, p);
				if (n) goto fail;
			}
		}
		p = t+1;
	} while (t);
	res = 1;
fail:
	free (s);
	return res;
}

R_API int r_num_is_valid_input(RNum *num, const char *input_value) {
	ut64 value = input_value ? r_num_math (num, input_value) : 0;
	return !(value == 0 && input_value && *input_value != '0') || !(value == 0 && input_value && *input_value != '@');
}

R_API ut64 r_num_get_input_value(RNum *num, const char *input_value) {
	ut64 value = input_value ? r_num_math (num, input_value) : 0;
	return value;
}

R_API char* r_num_as_string(RNum *___, ut64 n) {
	char str[10];
	int stri, ret = 0;
	int len = sizeof (ut64);
	ut64 num = n;
	str[stri=0] = 0;
	while (len--) {
		char ch = (num & 0xff);
		if (ch>=33 && ch <127) {
			str[stri++] = ch;
			str[stri] = 0;
		} else {
			if (ch)
				return NULL;
		}
		ret |= (num&0xff);
		num >>= 8;
	}
	if (ret)
		return strdup (str);
	return NULL;
}

R_API int r_is_valid_input_num_value(RNum *num, const char *input_value){
	ut64 value = input_value ? r_num_math (num, input_value) : 0;
	return !(value == 0 && input_value && *input_value == '0');
}

R_API ut64 r_get_input_num_value(RNum *num, const char *input_value){
	ut64 value = input_value ? r_num_math (num, input_value) : 0;
	return value;
}

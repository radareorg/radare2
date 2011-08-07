/* radare - LGPL - Copyright 2007-2011 pancake<nopcode.org> */

#include "r_util.h"

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
        ut64 ret  = value;
#if LIL_ENDIAN
        r_mem_copyendian ((ut8*)&ret, (ut8*)&value, 8, 0);
#endif
        return ret;
}

R_API void r_num_irand() {
	srand (rand () % r_sys_now ());
}

R_API int r_num_rand(int max) {
	// TODO: add srand here for security and so on
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
	if (num) {
		num->value = 0LL;
		num->callback = cb;
		num->userptr = ptr;
	}
	return num;
}

/* old get_offset */
R_API ut64 r_num_get(RNum *num, const char *str) {
	int i, j;
	char lch, len;
	ut64 ret = 0LL;

	for (; *str==' '; ) str++;

	/* resolve string with an external callback */
	if (num && num->callback) {
		int ok = 0;
		ret = num->callback (num->userptr, str, &ok);
		if (ok) return ret;
	}

	if (str[0]=='\'' && str[2]=='\'')
		return (ut64)str[1];

	if (str[0]=='0' && str[1]=='x') {
		sscanf (str, "0x%"PFMT64x"", &ret);
	} else {
		len = strlen (str);
		lch = str[len>0?len-1:0];
		switch (lch) {
		case 'h': // hexa
			sscanf (str, "%"PFMT64x"", &ret);
			break;
		case 'o': // octal
			sscanf (str, "%"PFMT64o"", &ret);
			break;
		case 'b': // binary
			ret = 0;
			for (j=0, i=strlen (str)-2; i>=0; i--, j++) {
				if (str[i]=='1') ret|=1<<j;
				else if (str[i]!='0') break;
			}
			break;
		default:
			sscanf (str, "%"PFMT64d"", &ret);
			break;
		case 'K': case 'k':
			sscanf (str, "%"PFMT64d"", &ret);
			ret *= 1024;
			break;
		case 'M': case 'm':
			sscanf (str, "%"PFMT64d"", &ret);
			ret *= 1024*1024;
			break;
		case 'G': case 'g':
			sscanf (str, "%"PFMT64d"", &ret);
			ret *= 1024*1024*1024;
			break;
		}
	}

	if (num != NULL)
		num->value = ret;

	return ret;
}

R_API ut64 r_num_op(char op, ut64 a, ut64 b) {
	switch (op) {
	case '+': return a+b;
	case '-': return a-b;
	case '*': return a*b;
	case '/': return b?a/b:0;
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
		case '+':
		case '-':
		case '*':
		case '/':
		case '&':
		case '^':
		case '|':
			nop = s[i]; s[i] = '\0';
			ret = r_num_op (op, ret, r_num_get (num, p));
			op = s[i] = nop; p = s + i + 1;
			break;
		}
	}

	return r_num_op (op, ret, r_num_get (num, p));
}

R_API ut64 r_num_math(RNum *num, const char *str) {
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
					p2[0]='\0';
					ret = r_num_op (op, ret, r_num_math_internal (num, p));
					ret = r_num_op (op, ret, r_num_math (num, p2+1));
					p =p2+1; 
					continue;
				} else eprintf ("WTF!\n");
			} else ret = r_num_op (op, ret, r_num_math_internal (num, p));
		} else ret = r_num_op (op, ret, r_num_math_internal (num, p));
	} while (0);

	if (num != NULL)
		num->value = ret;
	free (os);
	return ret;
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

	if (num&0xff000000) size = 32;
	else if (num&0xff0000) size = 24;
	else if (num&0xff00) size = 16;
	else if (num&0xff) size = 8;
	if (out) {
		for (i=0; i<size; i++)
			out[size-1-i] = (num>>i&1)? '1': '0';
		out[size]='\0'; //Maybe not nesesary?
	}
	return size;
}


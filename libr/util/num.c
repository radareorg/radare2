/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"

#define D  if(0)

#define __htonq(x) (\
        (((x) & 0xff00000000000000LL) >> 56)  | \
        (((x) & 0x00ff000000000000LL) >> 40)  | \
        (((x) & 0x0000ff0000000000LL) >> 24)  | \
        (((x) & 0x000000ff00000000LL) >> 8)   | \
        (((x) & 0x00000000ff000000LL) << 8)   | \
        (((x) & 0x0000000000ff0000LL) << 24)  | \
        (((x) & 0x000000000000ff00LL) << 40)  | \
        (((x) & 0x00000000000000ffLL) << 56))

u64 r_num_htonq(u64 value) {
        u64 ret  = value;
#if LIL_ENDIAN
        endian_memcpy_e((u8*)&ret, (u8*)&value, 8, 0);
#endif
        return ret;
}

void r_num_minmax_swap(u64 *a, u64 *b)
{
	if (*a>*b) {
		u64 tmp = *a;
		*a = *b;
		*b = tmp;
	}
}

void r_num_minmax_swap_i(int *a, int *b)
{
	if (*a>*b) {
		u64 tmp = *a;
		*a = *b;
		*b = tmp;
	}
}

void r_num_init(struct r_num_t *num)
{
	num->callback = NULL;
	num->userptr = NULL;
	num->value = 0LL;
}

struct r_num_t *r_num_new(u64 (*cb)(void*,const char *,int*), void *ptr)
{
	struct r_num_t *num;
	num = (struct r_num_t*) malloc(sizeof(struct r_num_t));
	r_num_init(num);
	return num;
}

/* old get_offset */
u64 r_num_get(struct r_num_t *num, const char *str)
{
	int i, j;
	char lch;
	u64 ret = 0LL;

	for(;str[0]==' ';) str = str+1;

	/* resolve string with an external callback */
	if (num && num->callback) {
		int ok;
		ret = num->callback(num->userptr, str, &ok);
		if (ok) return ret;
	}

	if (str[0]=='\'' && str[2]=='\'')
		return (u64)str[1];

	if (str[0]=='0' && str[1]=='x') {
		sscanf(str, "0x%llx", &ret);
	} else {
		lch = str[strlen(str)-1];
		switch(lch) {
		case 'h': // hexa
			sscanf(str, "%llx", &ret);
			break;
		case 'o': // octal
			sscanf(str, "%llo", &ret);
			break;
		case 'b': // binary
			ret = 0;
			for(j=0,i=strlen(str)-2;i>=0;i--,j++) {
				if (str[i]=='1') ret|=1<<j;
				else if (str[i]!='0') break;
			}
			break;
		default:
			sscanf(str, "%lld", &ret);
			break;
		case 'K': case 'k':
			sscanf(str, "%lld", &ret);
			ret *= 1024;
			break;
		case 'M': case 'm':
			sscanf(str, "%lld", &ret);
			ret *= 1024*1024;
			break;
		case 'G': case 'g':
			sscanf(str, "%lld", &ret);
			ret *= 1024*1024*1024;
			break;
		}
	}

	if (num != NULL)
		num->value = ret;

	return ret;
}

u64 r_num_op(char op, u64 a, u64 b)
{
D printf("r_num_op: %lld %c %lld\n", a,op,b);
	switch(op) {
	case '+': return a+b;
	case '-': return a-b;
	case '*': return a*b;
	case '/': return a/b;
	case '&': return a&b;
	case '|': return a|b;
	case '^': return a^b;
	}
	return b;
}

static u64 r_num_math_internal(struct r_num_t *num, char *s)
{
	u64 ret = 0LL;
	char *p = s;
	int i, nop, op='\0';

	D printf("r_num_math_internal: %s\n", s);

	for(i=0;s[i];i++) {
		switch(s[i]) {
		case '+':
		case '-':
		case '*':
		case '/':
		case '&':
		case '^':
		case '|':
			nop = s[i]; s[i] = '\0';
			ret = r_num_op(op, ret, r_num_get(num, p));
			op = s[i] = nop; p = s + i + 1;
			break;
		}
	}

	return r_num_op(op, ret, r_num_get(num, p));
}

u64 r_num_math(struct r_num_t *num, const char *str)
{
	u64 ret = 0LL;
	char op='+';
	int len = strlen(str)+1;
	char *p, *s = alloca(len);
	char *group;

	D printf("r_num_math: %s\n", str);

	memcpy(s, str, len);
	for(;*s==' ';s+=1);
	p = s;
	
	do {
		group = strchr(p, '(');
		if (group) {
			group[0]='\0';
			ret = r_num_op(op, ret, r_num_math_internal(num, p));
			for(;p<group;p+=1) {
				switch(*p) {
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
			group[0]='(';
			p = group+1;
			if (r_str_delta(p, '(', ')')<0) {
				char *p2 = strchr(p, '(');
				if (p2 != NULL) {
					p2[0]='\0';
					ret = r_num_op(op, ret, r_num_math_internal(num, p));
					ret = r_num_op(op, ret, r_num_math(num, p2+1));
					p =p2+1; 
					continue;
				} else fprintf(stderr, "WTF!\n");
			} else ret = r_num_op(op, ret, r_num_math_internal(num, p));
		} else ret = r_num_op(op, ret, r_num_math_internal(num, p));
	} while(0);

	if (num != NULL)
		num->value = ret;

	return ret;
}

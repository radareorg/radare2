/* radare - LGPL - Copyright 2007-2011 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>

/* stable code */
static const char *nullstr = "";
static const char *nullstr_c = "(null)";

// TODO: simplify this horrible loop
R_API void r_str_chop_path (char *s) {
	char *src, *dst, *p;
	int i = 0;
	dst = src = s+1;
	while (*src) {
		if (*(src-1) == '/' && *src == '.' && *(src+1) == '.') {
			if (*(src+2) == '/' || *(src+2) == '\0') {
				p = dst-1;
				while (s != p) {
					if (*p == '/') {
						if (i) {
							dst = p+1;
							i = 0;
							break;
						}
						i = 1;
					}
					p--;
				}
				if (s == p && *p == '/')
					dst = p+1;
				src = src+2;
			} else {
				*dst = *src;
				dst++;
			}
		} else if (*src == '/' && *(src+1) == '.' && (*(src+2) == '/' || *(src+2) == '\0')) {
			src++;
		} else if (*src != '/' || *(src-1) != '/') {
			*dst = *src;
			dst++;
		}
		src++;
	}
	if (dst>s+1 && *(dst-1) == '/')
		*(dst-1) = 0;
	else *dst = 0;
}

#if 0
// TEST CASE FOR r_str_chop_path
main () {
	char buf[1024];
	strcpy (buf, "/foo/boo/");
	r_str_chop_path (buf);
	printf ("%d %s\n", strcmp ("/foo/boo", buf), buf);
	strcpy (buf, "/foo/boo");
	r_str_chop_path (buf);
	printf ("%d %s\n", strcmp ("/foo/boo", buf), buf);
	strcpy (buf, "/foo");
	r_str_chop_path (buf);
	printf ("%d %s\n", strcmp ("/foo", buf), buf);
	strcpy (buf, "/");
	r_str_chop_path (buf);
	printf ("%d %s\n", strcmp ("/", buf), buf);
}
#endif

R_API void r_str_subchr (char *s, int a, int b) {
	while (*s) {
		if (*s==a) {
			if (b) *s = b;
			else memmove (s, s+1, strlen (s+1)+1);
		}
		s++;
	}
}

// TODO: do not use toupper.. must support modes to also append lowercase chars like in r1
// TODO: this functions needs some stabilization
R_API int r_str_bits (char *strout, const ut8 *buf, int len, const char *bitz) {
	int i, j;
	if (bitz) {
		for (i=j=0; i<len && (!bitz||bitz[i]); i++) {
			if (i>0 && (i%8)==0)
				buf++;
	                if (*buf&(1<<(i%8)))
				strout[j++] = toupper (bitz[i]);
		}
	} else {
		for (i=j=0; i<len; i++) {
			if (i>0 && (i%8)==0)
				buf++;
			strout[j++] = (*buf&(1<<(7-(i%8))))?'1':'0';
		}
	}
	strout[j] = 0;
	return j;
}

/* int c; ret = hex2int(&c, 'c'); */
static int hex2int (ut8 *val, ut8 c) {
	if ('0' <= c && c <= '9') *val = (ut8)(*val) * 16 + ( c - '0');
	else if (c >= 'A' && c <= 'F') *val = (ut8)(*val) * 16 + ( c - 'A' + 10);
	else if (c >= 'a' && c <= 'f') *val = (ut8)(*val) * 16 + ( c - 'a' + 10);
	else return 1;
	return 0;
}

R_API int r_str_binstr2bin(const char *str, ut8 *out, int outlen) {
	int n, i, j, k, ret, len;
	len = strlen (str);
	for (n=i=0; i<len; i+=8) {
		ret = 0;
		while (str[i]==' ')
			str++;
		if (i+7<len)
		for (k=0, j=i+7; j>=i; j--, k++) {
		// INVERSE for (k=0,j=i; j<i+8; j++,k++) {
			if (str[j]==' ') {
				//k--;
				continue;
			}
	//		printf ("---> j=%d (%c) (%02x)\n", j, str[j], str[j]);
			if (str[j]=='1') ret|=1<<k;
			else if (str[j]!='0') return n;
		}
	//	printf ("-======> %02x\n", ret);
		out[n++] = ret;
		if (n==outlen)
			return n;
	}
	return n;
}

R_API int r_str_rwx(const char *str) {
	int ret = atoi (str);
	if (!ret) {
		ret |= strchr (str, 'r')?4:0;
		ret |= strchr (str, 'w')?2:0;
		ret |= strchr (str, 'x')?1:0;
	}
	return ret;
}

R_API const char *r_str_rwx_i(int rwx) {
	static const char *rwxstr[16] = {
		[0] = "---",
		[1] = "--x",
		[2] = "-w-",
		[3] = "-wx",
		[4] = "r--",
		[5] = "r-x",
		[6] = "rw-",
		[7] = "rwx",
		/* ... */
	};
	return rwxstr[rwx&7]; // 15 for srwx
}

R_API const char *r_str_bool(int b) {
	return b? "true": "false";
}

R_API void r_str_case(char *str, int up) {
	if (up) {
		while (*str)
			*str = tolower (*str);
	} else {
		while (*str)
			*str = toupper (*str);
	}
}

R_API char *r_str_home(const char *str) {
	int lhome, lstr;
	char *dst;
	const char *home = r_sys_getenv (R_SYS_HOME);
	if (home == NULL)
		return NULL;
	lhome = strlen (home);
	lstr = strlen (str);
	dst = (char *)malloc (lhome + lstr + 2);
	memcpy (dst, home, lhome+1);
	if (str && *str) {
		memcpy (dst+lhome, R_SYS_DIR, strlen (R_SYS_DIR));
		memcpy (dst+lhome+strlen (R_SYS_DIR), str, lstr+1);
	}
	free (home);
	return dst;
}

/* XXX Fix new hash algo*/
R_API ut64 r_str_hash64(const char *str) {
	ut64 ret = 0;
	for (; *str; str++)
		ret ^= (ret<<7 | *str);
	return ret;
}

R_API ut32 r_str_hash(const char *str) {
	ut32 ret = 0;
	for (; *str; str++)
		ret ^= (ret<<7 | *str);
	return ret;
}

R_API int r_str_delta(char *p, char a, char b) {
	char *_a = strchr (p, a);
	char *_b = strchr (p, b);
	return (!_a||!_b)?0:(_a-_b);
}

R_API int r_str_word_set0(char *str) {
	int i;
	char *p;
	if (!*str)
		return 0;
	/* TODO: sync with r1 code */
	for (i=1, p=str; *p; p++)
		if (*p==' ') {
			i++;
			*p='\0';
		} // s/ /\0/g
	return i;
}

R_API char *r_str_word_get0(char *str, int idx) {
	int i;
	char *ptr = str;
	if (ptr == NULL)
		return (char *)nullstr;
	for (i=0;*ptr && i != idx;i++)
		ptr = ptr + strlen(ptr) + 1;
	return ptr;
}

R_API int r_str_char_count(const char *string, char ch) {
	int i, count = 0;
	for (i=0; string[i]; i++)
		if (string[i]==ch)
			count++;
	return count;
}

R_API int r_str_word_count(const char *string) {
	const char *text, *tmp;
	int word;

	for (text = tmp = string; *text && isseparator (*text); text++);
	for (word = 0; *text; word++) {
		for (;*text && !isseparator (*text); text++);
		for (tmp = text; *text && isseparator (*text); text++);
	}
	return word;
}

R_API char *r_str_ichr(char *str, char chr) {
	while (*str==chr) str++;
	return str;
}

R_API char *r_str_lchr(char *str, char chr) {
	int len = strlen (str)+1;
	for (;len>=0;len--)
		if (str[len]==chr)
			return str+len;
	return NULL;
}

R_API int r_str_nchr(const char *str, char chr) {
	int n;
	for (n = 0; *str; str++)
		if (*str==chr)
			n++;
	return n;
}

R_API int r_str_nstr(char *from, char *to, int size) {
	int i;
	for (i=0; i<size; i++)
		if (from==NULL || to==NULL || from[i]!=to[i])
			break;
	return (size!=i);
}

R_API const char *r_str_chop_ro(const char *str) {
	if (str)
	while (*str && iswhitechar (*str))
		str++;
	return str;
}

R_API char *r_str_new(char *str) {
	return strdup (str);
}

R_API char *r_str_newf(const char *fmt, ...) {
	char string[1024];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (string, 1023, fmt, ap);
	fmt = r_str_new (string);
	va_end (ap);
	return (char*)fmt;
}

R_API char *r_str_chop(char *str) {
	int len;
	char *ptr;

	if (str == NULL)
		return NULL;
		
	while (*str && iswhitechar (*str))
		str = str + 1;
		
	len = strlen (str);
	
	if (len>0)
	for (ptr = str+len-1; ptr!=str; ptr--) {
		if (iswhitechar (*ptr)) 
			*ptr = '\0';
		else break;
	}	       
	return str;
}

R_API char *r_str_trim_head(char *str) {
	if (str)
		while (*str && iswhitechar (*str)) 
			str++;
	return str;
}

R_API char *r_str_trim_tail(char *str) {
	char *ptr = str;
	if (str == NULL) return NULL;
	if (!*str) return str;
	ptr += strlen (str);
	for (ptr--; (ptr > str) && iswhitechar (*ptr); ptr--)
		*ptr = '\0';
	return str;
}

R_API char *r_str_trim_head_tail(char *str) {
	return r_str_trim_tail (r_str_trim_head (str));
}

R_API char *r_str_trim(char *str) {
	int i;
	char *ptr;
	if (str == NULL)
		return NULL;
	for (ptr=str, i=0;str[i]; i++)
		if (!iswhitechar (str[i]))
			*ptr++ = str[i];
	*ptr='\0';
	return str;
}


R_API void r_str_cpy(char *dst, const char *src) {
	int i;
	for (i=0; src[i]; i++)
		dst[i] = src[i];
	dst[i] = 0;
}

/* memccmp("foo.bar", "foo.cow, '.') == 0 */
R_API int r_str_ccmp(const char *dst, const char *src, int ch) {
	int i;
	for (i=0;src[i] && src[i] != ch; i++)
		if (dst[i] != src[i])
			return 1;
	return 0;
}

R_API int r_str_cmp(const char *a, const char *b, int len) {
	if (a==b)
		return R_TRUE;
	for (;len--;) {
		if (*a=='\0'||*b=='\0'||*a!=*b)
			return R_TRUE;
		a++; b++;
	}
	return R_FALSE;
}

R_API int r_str_ccpy(char *dst, char *src, int ch) {
	int i;
	for (i=0;src[i] && src[i] != ch; i++)
		dst[i] = src[i];
	dst[i] = '\0';
	return i;
}

R_API char *r_str_word_get_first(const char *text) {
	char *ret;
	int len = 0;

	for (;*text && isseparator (*text); text++);

	/* strdup */
	len = strlen (text);
	ret = (char *)malloc (len+1);
	if (ret == NULL) {
		eprintf ("Cannot allocate %d bytes.\n", len+1);
		exit (1);
	}
	strncpy (ret, text, len);
	ret[len]='\0';

	return ret;
}

R_API const char *r_str_get(const char *str) {
	if (str == NULL)
		return nullstr_c;
	return str;
}

R_API char *r_str_dup(char *ptr, const char *string) {
	if (ptr) free (ptr);
	ptr = strdup (string);
	return ptr;
}

// TODO: rename to r_str_dupfmt
R_API char *r_str_dup_printf(const char *fmt, ...) {
	char *ret;
	va_list ap;
	va_start(ap, fmt);
	if ((ret = malloc (1024)) == NULL)
		return NULL;
	vsnprintf (ret, 1024, fmt, ap);
	va_end(ap);
	return ret;
}

R_API void r_str_writef(int fd, const char *fmt, ...) {
	char *buf;
	va_list ap;
	va_start (ap, fmt);
	if ((buf = malloc (4096)) != NULL) {
		vsnprintf (buf, 4096, fmt, ap);
		r_str_write (fd, buf);
		free (buf);
	}
	va_end (ap);
}

/*
 * return: the pointer ptr resized to string size.
 */
R_API char *r_str_concat(char *ptr, const char *string) {
	int slen, plen;
	if (ptr == NULL)
		return strdup (string);
	plen = strlen (ptr);
	slen = strlen (string);
	ptr = realloc (ptr, slen + plen + 1);
	if (ptr == NULL)
		return NULL;
	memcpy (ptr+plen, string, slen+1);
	return ptr;
}

R_API char *r_str_concatf(char *ptr, const char *fmt, ...) {
	char string[1024];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (string, 1023, fmt, ap);
	ptr = r_str_concat (ptr, string);
	va_end (ap);
	return ptr;
}

R_API char *r_str_concatch(char *x, char y) {
	char b[2] = {y, 0};
	return r_str_concat (x,b);
}

R_API void *r_str_free(void *ptr) {
	free (ptr);
	return NULL;
}

R_API char* r_str_replace(char *str, const char *key, const char *val, int g) {
	int off;
	int klen = strlen (key);
	int vlen = strlen (val);
	int slen = strlen (str);
	char *old, *p = str;
	for (;;) {
		p = (char *)r_mem_mem (
			(const ut8*)str, slen,
			(const ut8*)key, klen);
		if (p) {
			old = strdup (p+klen);
			slen += (vlen-klen)+1;
			off = (int)(size_t)(p-str);
			str = realloc (str, slen);
			p = str+off;
			memcpy (p, val, vlen);
			memcpy (p+vlen, old, strlen (old));
			p[vlen] = 0;
			free (old);
			if (g) continue;
			else break;
		} else break;
	}
	return str;
}

R_API char *r_str_clean(char *str) {
	int len;
	char *ptr;
	if (str != NULL) {
		while (*str && iswhitechar (*str))
			str++;
		if ((len = strlen(str))>0) 
		for (ptr = str+len-1; ptr!=str; ptr = ptr - 1) {
			if (iswhitechar (*ptr))
				*ptr = '\0';
			else break;
		}
	}
	return str;
}

R_API int r_str_escape(char *buf) {
	unsigned char ch = 0, ch2 = 0;
	int err = 0;
	int i;

	for (i=0; buf[i]; i++) {
		// only parse scaped characters //
		if (buf[i]!='\\')
			continue;
		if (buf[i+1]=='e') {
			buf[i] = 0x1b;
			memmove (buf+i+1, buf+i+2, strlen (buf+i+2)+1);
		} else if (buf[i+1]=='r') {
			buf[i] = 0x0d;
			memmove (buf+i+1, buf+i+2, strlen (buf+i+2)+1);
		} else if (buf[i+1]=='n') {
			buf[i] = 0x0a;
			memmove (buf+i+1, buf+i+2, strlen (buf+i+2)+1);
		} else if (buf[i+1]=='x') {
			err = ch2 = ch = 0;
			if (!buf[i+2] || !buf[i+3]) {
				eprintf ("Unexpected end of string.\n");
				return 0;
			}
			err |= hex2int (&ch,  buf[i+2]);
			err |= hex2int (&ch2, buf[i+3]);
			if (err) {
				eprintf ("Incorrect hexadecimal characters for conversion.\n");
				return 0;
			}
			buf[i] = (ch<<4)+ch2;
			memmove (buf+i+1, buf+i+4, strlen (buf+i+4)+1);
		} else {
			eprintf ("'\\x' expected.\n");
			return 0;
		}
	}

	//char *p = buf; while(*p) { eprintf("%d %c\n", *p, *p); p++; }
	//eprintf("OLEN=%d (%s)\n", strlen(buf), buf);
	return i; //strlen (buf);
}

R_API char *r_str_unscape(char *buf) {
	char *ptr, *ret;
	int len = strlen (buf);
	ptr = ret = malloc (1+len*2);
	if (ptr == NULL)
		return NULL;
	for (;*buf;buf++,ptr++) {
		if (*buf=='\n') {
			*ptr = '\\';
			ptr++;
			*ptr = 'n';
		} else
		if (*buf=='\t') {
			*ptr = '\\';
			ptr++;
			*ptr = 't';
		} else
		if (IS_PRINTABLE (*buf)) {
			*ptr = *buf;
		} else break;
	}
	*ptr = 0;
	return ret;
}

/* ansi helpers */
R_API int r_str_ansi_len(const char *str) {
	int i=0, len = 0;
	while (str[i]) {
		if (str[i]==0x1b && str[i+1]=='[')
			for (++i;str[i]&&str[i]!='J'&&str[i]!='m'&&str[i]!='H';i++);
		else len++;
		i++;
	}
	return len;
}

// TODO: support wide char strings
R_API int r_str_nlen(const char *str, int n) {
	int len = 0;
	while (*str++ && n--)
		len++;
	return len;
}

R_API const char *r_str_ansi_chrn(const char *str, int n) {
	int len, i, li;
	for (li=i=len=0; str[i] && (n!=len); i++) {
		if (str[i]==0x1b && str[i+1]=='[') {
			for (++i;str[i]&&str[i]!='J'&&str[i]!='m'&&str[i]!='H';i++);
		} else {
			len++;
			li = i;
		}
	}
	return str+li;
}

R_API int r_str_ansi_filter(char *str, int len) {
	char *tmp;
	int i, j;

	if (!(tmp = malloc (len)))
		return -1;
	memcpy (tmp, str, len);
	for (i=j=0; i<len; i++)
		if (i+1<len && tmp[i] == 0x1b && tmp[i+1] == '[')
			for (i+=2;i<len&&str[i]!='J'&&str[i]!='m'&&str[i]!='H';i++);
		else str[j++] = tmp[i];
	free (tmp);
	return j;
}

R_API void r_str_filter(char *str, int len) {
	int i;
	for (i=0; i<len; i++)
		if (!IS_PRINTABLE (str[i]))
			str[i] = '.';
}

R_API int r_str_glob (const char *str, const char *glob) {
	const char *p;
	int slen, glen;
	if (!*str) return R_TRUE;
	glen = strlen (glob);
	slen = strlen (str);
	if (*glob == '*') {
		if (glob[1] == '\0')
			return R_TRUE;
		if (glob[glen-1] == '*') {
			return r_mem_mem ((const ut8*)str, slen, (const ut8*)glob+1, glen-2) != 0;
		}
		if (slen<glen-2)
			return R_FALSE;
		p = str + slen - (glen-1);
		return memcmp (p, glob+1, glen-1) == 0;
	} else {
		if (glob[glen-1] == '*') {
			if (slen<glen-1)
				return R_FALSE;
			return memcmp (str, glob, glen-1) == 0;
		} else {
			char *p = strchr (glob, '*');
			if (p) {
				int a = (int)(size_t)(p-glob);
				return ((!memcmp (str, glob, a)) && ( !memcmp (str+slen-a, glob+a+1, glen-a-1)))? 1: 0;
			} else {
				return !strcmp (str, glob);
			}
		}
	}
	return R_FALSE; // statement never reached
}

// XXX: remove this limit .. use realloc
#define MAXARG 128
R_API char **r_str_argv(const char *_str, int *_argc) {
	int argc = 0;
	int escape = 0;
	int quote = 0;
	char *optr, *ptr, *str = strdup (_str);
	char **argv = (char **)malloc (MAXARG*sizeof(char*));

	optr = ptr = (char *)r_str_chop_ro (str);
	for (; *ptr && argc<MAXARG; ptr++) {
		switch (*ptr) {
		case '\'':
		case '"':
			if (escape) {
				escape = 0;
				memmove (ptr, ptr+1, strlen (ptr+1)+1);
			} else {
				if (quote) {
					*ptr = '\0';
					argv[argc++] = optr;
					optr = ptr+1;
					quote = 0;
				} else {
					quote = *ptr;
					optr = ptr+1;
				}
			}
			break;
		case '\\':
			escape = 1;
			break;
		case ' ':
			if (!escape && !quote) {
				*ptr = '\0';
				if (*optr) {
					argv[argc++] = optr; 
					optr = ptr+1;
				}
			}
			break;
		default:
			escape = 0;
			break;
		}
	}
	if (*optr) {
		argv[argc++] = optr; 
		optr = ptr+1;
	}
	argv[argc] = NULL;
	if (_argc)
		*_argc = argc;
	return argv;
}

R_API void r_str_argv_free(char **argv) {
	// TODO: free the internal food or just the first element
//	free (argv[0]); // MEMORY LEAK
	free (argv);
}

#if 0
/* XXX this is necessary ??? */
// TODO: make it dynamic
static int bprintf_init = 0;
static char bprintf_buf[4096];

// XXX overflow
R_API int r_bprintf(const char *fmt, ...) {
	va_list ap;
	if (bprintf_init==0)
		*bprintf_buf = 0;
	va_start(ap, fmt);
	r_str_concatf(bprintf_buf, fmt, ap);
	va_end(ap);
	return strlen(bprintf_buf);
}

R_API char *r_bprintf_get() {
	char *s;
	if (bprintf_init==0)
		*bprintf_buf = 0;
	s = strdup(bprintf_buf);
	bprintf_buf[0]='\0';
	return s;
}
#endif

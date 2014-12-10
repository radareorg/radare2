/* radare - LGPL - Copyright 2007-2014 - pancake */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>
#include <string.h>
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

R_API int r_str_replace_char_once (char *s, int a, int b) {
	int ret = 0;
	char *o = s;
	if (a==b)
		return 0;
	for (; *o; s++, o++) {
		if (*o==a) {
			if (b) {
				*s = b;
				ret++;
				continue;
			}
			o++;
		}
		*s = *o;
	}
	*s = 0;
	return ret;
}

// Spagetti.. must unify and support 'g', 'i' ...
R_API int r_str_replace_char (char *s, int a, int b) {
	int ret = 0;
	char *o = s;
	if (a==b)
		return 0;
	for (; *o; s++, o++) {
		if (*o==a) {
			ret++;
			if (b) {
				*s = b;
			} else {
				/* remove char */
				s--;
			}
		} else *s = *o;
	}
	*s = 0;
	return ret;
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
				strout[j++] = toupper ((const unsigned char)bitz[i]);
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

/**
 * function: r_str_bits_from_num
 * 
 */
R_API ut64 r_str_bits_from_string(const char *buf, const char *bitz) {
	ut64 out = 0LL;
	/* return the numberic value associated to a string (rflags) */
	for (; *buf; buf++) {
		char *ch = strchr (bitz, toupper ((const unsigned char)*buf));
		if (!ch) ch = strchr (bitz, tolower ((const unsigned char)*buf));
		if (ch) {
			int bit = (int)(size_t)(ch - bitz);
			out |= (ut64)(1LL << bit);
		} else {
			return UT64_MAX;
		}
	}
	return out;
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
		char oc = 0;
		for (; *str; oc = *str++)
			*str = (*str=='x' && oc=='0') ? 'x': toupper ((unsigned char)*str);
	} else
		for (; *str; str++)
			*str = tolower ((unsigned char)*str);
}

R_API char *r_str_home(const char *str) {
	char *dst, *home = r_sys_getenv (R_SYS_HOME);
	size_t length;
	if (home == NULL)
		return NULL;
	length = strlen (home) + 1;
	if (str)
		length += strlen (R_SYS_DIR) + strlen (str);
	dst = (char *)malloc (length);
	if (dst == NULL)
		goto fail;
	strcpy (dst, home);
	if (str) {
		strcat (dst, R_SYS_DIR);
		strcat (dst, str);
	}
fail:
	free (home);
	return dst;
}

R_API ut64 r_str_hash64(const char *s) {
        ut64 len, h = 5381;
	if (!s)
		return 0;
        for (len=strlen (s); len>0; len--)
                h = (h^(h<<5)) ^ *s++;
        return h;
}

R_API ut32 r_str_hash (const char *s) {
	return (ut32) r_str_hash64 (s);
}

R_API int r_str_delta(char *p, char a, char b) {
	char *_a = strchr (p, a);
	char *_b = strchr (p, b);
	return (!_a||!_b)?0:(_a-_b);
}

R_API int r_str_split(char *str, char ch) {
	int i;
	char *p;
	if (!str || !*str)
		return 0;
	/* TODO: sync with r1 code */
	for (i=1, p=str; *p; p++)
		if (*p==ch) {
			i++;
			*p='\0';
		} // s/ /\0/g
	return i;
}

R_API int r_str_word_set0(char *str) {
	int i, quote = 0;
	char *p;
	if (!str || !*str)
		return 0;
	for (i=0; str[i] && str[i+1]; i++) {
		if (str[i]==' ' && str[i+1]==' ') {
			int len = strlen (str+i+1)+1;
			memmove (str+i, str+i+1, len);
		}
	}
	if (str[i]==' ')
		str[i] = 0;
	for (i=1, p=str; *p; p++) {
		if (*p=='\"') {
			if (quote) {
				quote = 0;
				*p = '\0';
				// FIX: i++;
				continue;
			} else {
				quote = 1;
				memmove (p, p+1, strlen (p+1)+1);
			}
		}
		if (quote) continue;
		if (*p==' ') {
			char *q = p-1;
			if (p>str && *q=='\\') {
				memmove (q, p, strlen (p)+1);
				continue;
			}
			i++;
			*p='\0';
		} // s/ /\0/g
	}
	return i;
}

R_API char *r_str_word_get0set(char *stra, int stralen, int idx, const char *newstr, int *newlen) {
	char *p = NULL;
	char *out;
	int alen, blen, nlen;
	if (!stra && !newstr) return NULL;
	if (stra)
		p = (char *)r_str_word_get0 (stra, idx);
	if (!p) {
		int nslen = strlen (newstr);
		out = malloc (nslen+1);
		strcpy (out, newstr);
		out[nslen] = 0;
		if (newlen)
			*newlen = nslen;
		return out;
	}
	alen = (size_t)(p-stra);
	blen = stralen - ((alen + strlen (p))+1);
	if (blen<0) blen = 0;
	nlen = alen+blen+strlen (newstr);
	out = malloc (nlen + 2);
	if (alen>0)
		memcpy (out, stra, alen);
	memcpy (out+alen, newstr, strlen (newstr)+1);
	if (blen>0)
		memcpy (out+alen+strlen (newstr)+1, p+strlen (p)+1, blen+1);
	out[nlen+1] = 0;
	if (newlen)
		*newlen = nlen + ((blen==0)?1:0);
	return out;
}

R_API const char *r_str_word_get0(const char *str, int idx) {
	int i;
	const char *ptr = str;
	if (ptr == NULL)
		return (char *)nullstr;
	for (i=0; *ptr && i != idx; i++)
		ptr += strlen (ptr) + 1;
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

// find last char
R_API const char *r_str_lchr(const char *str, char chr) {
	if (str) {
		int len = strlen (str);
		for (;len>=0;len--)
			if (str[len]==chr)
				return str+len;
	}
	return NULL;
}

R_API const char *r_str_rchr(const char *base, const char *p, int ch) {
	if (!base) return NULL;
	if (!p) p = base + strlen (base);
	for (; p>base; p--)
		if (ch == *p)
			break;
	return p;
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

// TODO: rewrite in macro?
R_API const char *r_str_chop_ro(const char *str) {
	if (str) while (*str && iswhitechar (*str)) str++; return str;
}

R_API char *r_str_new(char *str) {
	if (!str) return NULL;
	return strdup (str);
}

R_API char *r_str_newf(const char *fmt, ...) {
	int ret, ret2;
	char *p, string[1024];
	va_list ap, ap2;
	va_start (ap, fmt);
	va_start (ap2, fmt);
	ret = vsnprintf (string, sizeof (string)-1, fmt, ap);
	if (ret < 1 || ret >= sizeof (string)) {
		p = malloc (ret+2);
		if (!p) {
			va_end (ap2);
			va_end (ap);
			return NULL;
		}
		ret2 = vsnprintf (p, ret+1, fmt, ap2);
		if (ret2 < 1 || ret2 > ret+1) {
			free (p);
			va_end (ap2);
			va_end (ap);
			return NULL;
		}
		fmt = r_str_new (p);
		free (p);
	} else {
		fmt = r_str_new (string);
	}
	va_end (ap2);
	va_end (ap);
	return (char*)fmt;
}

R_API char *r_str_chop(char *str) {
	int len;
	char *ptr;

	if (str == NULL)
		return NULL;

	while (*str && iswhitechar (*str))
		memmove (str, str+1, strlen (str+1)+1);

	len = strlen (str);

	if (len>0)
	for (ptr = str+len-1; ptr!=str; ptr--) {
		if (iswhitechar (*ptr))
			*ptr = '\0';
		else break;
	}
	return str;
}

R_API const char *r_str_trim_const(const char *str) {
	if (str)
		for (; *str && iswhitechar (*str); str++);
	return str;
}

R_API char *r_str_trim_head(char *str) {
	char *p;

	if (!str)
		return NULL;

	for (p = str; *p && iswhitechar (*p); p++)
		;

	/* Take the trailing null into account */
	memmove (str, p, strlen (p) + 1);

	return str;
}

R_API char *r_str_trim_tail(char *str) {
	int length;

	if (!str)
		return NULL;

	length = strlen (str);

	if (!length)
		return str;

	while (length--) {
		if (iswhitechar (str[length]))
			str[length] = '\0';
		else break;
	}

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

R_API void r_str_ncpy(char *dst, const char *src, int n) {
	int i;
	for (i=0; src[i] && n>0; i++, n--)
		dst[i] = IS_PRINTABLE (src[i])? src[i]: '.';
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
	for (i=0; src[i] && src[i] != ch; i++)
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

R_API char *r_str_ndup(const char *ptr, int len) {
	char *out = malloc (len+1);
	memcpy (out, ptr, len);
	out[len] = 0;
	return out;
}

// TODO: deprecate?
R_API char *r_str_dup(char *ptr, const char *string) {
	int len;
	free (ptr);
	if (!string) return NULL;
	len = strlen (string)+1;
	ptr = malloc (len+1);
	memcpy (ptr, string, len);
	return ptr;
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

R_API char *r_str_prefix(char *ptr, const char *string) {
	int slen, plen;
	if (ptr == NULL)
		return strdup (string);
	//plen = r_str_len_utf8 (ptr);
	//slen = r_str_len_utf8 (string);
	plen = strlen (ptr);
	slen = strlen (string);
	ptr = realloc (ptr, slen + plen + 1);
	if (ptr == NULL)
		return NULL;
	memmove (ptr+slen, ptr, plen+1);
	memmove (ptr, string, slen);
	return ptr;
}
/*
 * first argument must be allocated
 * return: the pointer ptr resized to string size.
 */
// TODO: use vararg here?
R_API char *r_str_concat(char *ptr, const char *string) {
	int slen, plen;
	if (!string && !ptr)
		return NULL;
	if (!string && ptr)
		return ptr;
	if (string && !ptr)
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
	int ret;
	char string[4096];
	va_list ap;
	va_start (ap, fmt);
	ret = vsnprintf (string, sizeof (string), fmt, ap);
	if (ret>=sizeof (string)) {
		char *p = malloc (ret+2);
		if (!p) {
			va_end (ap);
			return NULL;
		}
		vsnprintf (p, ret+1, fmt, ap);
		ptr = r_str_concat (ptr, p);
		free (p);
	} else ptr = r_str_concat (ptr, string);
	va_end (ap);
	return ptr;
}

R_API char *r_str_concatch(char *x, char y) {
	char b[2] = {y, 0};
	return r_str_concat (x,b);
}

// XXX: wtf must deprecate
R_API void *r_str_free(void *ptr) {
	free (ptr);
	return NULL;
}

R_API char* r_str_replace(char *str, const char *key, const char *val, int g) {
	int off, i, klen, vlen, slen;
	char *newstr, *scnd, *p = str;

	if (!str || !key || !val) return NULL;
	klen = strlen (key);
	vlen = strlen (val);
	if (klen == vlen && !strcmp (key, val))
		return str;
	slen = strlen (str);
	for (i = 0; i < slen; ) {
		p = (char *)r_mem_mem (
			(const ut8*)str + i, slen - i,
			(const ut8*)key, klen);
		if (!p) break;
		off = (int)(size_t)(p-str);
		scnd = strdup (p+klen);
		slen += vlen - klen;
		// HACK: this 32 avoids overwrites wtf
		newstr = realloc (str, slen+klen+1);
		if (!newstr) {
			eprintf ("realloc fail\n");
			free (str);
			free (scnd);
			str = NULL;
			break;
		}
		str = newstr;
		p = str+off;
		memcpy (p, val, vlen);
		memcpy (p+vlen, scnd, strlen (scnd)+1);
		i = off+vlen;
		free (scnd);
		if (!g) break;
	}
	return str;
}


R_API char *r_str_clean(char *str) {
	int len;
	char *ptr;
	if (str != NULL) {
		while (*str && iswhitechar (*str))
			str++;
		if ((len = strlen (str)) > 0 )
			for (ptr = str+len-1; ptr!=str; ptr = ptr - 1) {
				if (iswhitechar (*ptr))
					*ptr = '\0';
				else break;
			}
	}
	return str;
}

R_API int r_str_unescape(char *buf) {
	unsigned char ch = 0, ch2 = 0;
	int err = 0;
	int i;

	for (i=0; buf[i]; i++) {
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
				eprintf ("Error: Non-hexadecimal chars in input.\n");
				return 0; // -1?
			}
			buf[i] = (ch<<4)+ch2;
			memmove (buf+i+1, buf+i+4, strlen (buf+i+4)+1);
		} else {
			eprintf ("'\\x' expected.\n");
			return 0; // -1?
		}
	}
	return i;
}

R_API void r_str_sanitize(char *c) {
	char *d = c;
	if (d) for (; *d; c++, d++) {
		switch (*d) {
		case '`':
		case '$':
		case '{':
		case '}':
		case '~':
		case '|':
		case ';':
		case '#':
		case '@':
		case '&':
		case '<':
		case '>':
			*c = '_';
			continue;
		}
	}
}

/* Internal function. dot_nl specifies wheter to convert \n into the
 * graphiz-compatible newline \l */
static char *r_str_escape_ (const char *buf, const int dot_nl) {
	char *new_buf, *q;
	const char *p;

	if (!buf)
		return NULL;

	/* Worst case scenario, we convert every byte */
	new_buf = malloc (1 + (strlen(buf) * 4));

	if (!new_buf)
		return NULL;

	p = buf;
	q = new_buf;

	while (*p) {
		switch (*p) {
			case '\n':
				*q++ = '\\';
				*q++ = dot_nl? 'l': 'n';
				break;
			case '\r':
				*q++ = '\\';
				*q++ = 'r';
				break;
			case '\\':
				*q++ = '\\';
				*q++ = '\\';
				break;
			case '\t':
				*q++ = '\\';
				*q++ = 't';
				break;
			case '"' :
				*q++ = '\\';
				*q++ = '"';
				break;
			case '\f':
				*q++ = '\\';
				*q++ = 'f';
				break;
			case '\b':
				*q++ = '\\';
				*q++ = 'b';
				break;
			case 0x1b: // ESC
				p++;
				/* Parse the ANSI code (only the graphic mode
				 * set ones are supported) */
				if (*p == '[')
					for (p++; *p != 'm'; p++)
						;
				break;
			default:
				/* Outside the ASCII printable range */
				if (*p < ' ' && *p > 0x7E) {
					*q++ = '\\';
					*q++ = 'x';
					*q++ = '0'+((*p)>>4);
					*q++ = '0'+((*p)&0xf);
				} else {
					*q++ = *p;
				}
		}

		p++;
	}

	*q = '\0';

	return new_buf;
}

R_API char *r_str_escape (const char *buf) {
	return r_str_escape_ (buf, R_FALSE);
}

R_API char *r_str_escape_dot (const char *buf) {
	return r_str_escape_ (buf, R_TRUE);
}

/* ansi helpers */
R_API int r_str_ansi_len(const char *str) {
	int ch, ch2, i=0, len = 0, sub = 0;
	while (str[i]) {
		ch = str[i];
		ch2 = str[i+1];
		if (ch == 0x1b) {
			if (ch2 == '\\') {
				i++;
			} else if (ch2 == ']') {
				if (!strncmp (str+2+5, "rgb:", 4))
					i += 18;
			} else if (ch2 == '[') {
				for (++i; str[i]&&str[i]!='J'&& str[i]!='m'&&str[i]!='H';i++);
			}
		} else {
		len++;
#if 0
			int olen = strlen (str);
			int ulen = r_str_len_utf8 (str);
			if (olen != ulen) {
				len += (olen-ulen);
			} else len++;
			//sub -= (r_str_len_utf8char (str+i, 4))-2;
#endif
		}//len++;
		i++;
	}
	return len-sub;
}

// TODO: support wide char strings
R_API int r_str_nlen(const char *str, int n) {
	int len = 0;
	if (str) {
		//while (IS_PRINTABLE (*str) && n>0) {
		while (*str && n>0) {
			len++;
			str++;
			n--;
		}
	}
	return len;
}

// Length in chars of a wide string (find better name?)
R_API int r_wstr_clen (const char *s) {
	int len = 0;
	if (*s++ == 0) return 0;
	while (*s++ || *s++)
		len++;
	return len+1;
}

R_API const char *r_str_ansi_chrn(const char *str, int n) {
	int len, i, li;
	for (li=i=len=0; str[i] && (n!=len); i++) {
		if (str[i]==0x1b && str[i+1]=='[') {
			for (++i;str[i]&&str[i]!='J'&&str[i]!='m'&&str[i]!='H';i++);
		} else {
			if ((str[i] & 0xc0) != 0x80) len++;
			//len++;
			li = i;
		}
	}
	return str+li;
}

R_API int r_str_ansi_filter(char *str, int len) {
	int i, j;
	char *tmp;
	if (len<1) len = strlen (str)+1;
	tmp = malloc (len);
	if (!tmp) return -1;
	memcpy (tmp, str, len);
	for (i=j=0; i<len; i++)
		if (i+1<len && tmp[i] == 0x1b && tmp[i+1] == '[')
			for (i+=2;i<len&&str[i]!='J'&&str[i]!='m'&&str[i]!='H';i++);
		else str[j++] = tmp[i];
	free (tmp);
	return j;
}

R_API void r_str_filter_zeroline(char *str, int len) {
	int i;
	for (i=0; i<len && str[i]; i++) {
		if (str[i]=='\n' || str[i]=='\r')
			break;
		if (!IS_PRINTABLE (str[i]))
			break;
	}
	str[i] = 0;
}

R_API void r_str_filter(char *str, int len) {
	int i;
	if (len<1)
		len = strlen (str);
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
			return r_mem_mem ((const ut8*)str, slen,
				(const ut8*)glob+1, glen-2) != 0;
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
				return ((!memcmp (str, glob, a)) && \
					(!memcmp (str+slen-a, glob+a+1, glen-a-1)))? 1: 0;
			}
			return !strcmp (str, glob);
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
	char **argv = NULL, *optr = NULL, *ptr = NULL, *str = strdup (_str);

	if (!str) return NULL;
	argv = (char **)malloc (MAXARG*sizeof(char*));
	optr = ptr = (char *)r_str_chop_ro (str);
	for (; *ptr && argc < (MAXARG - 2); ptr++) {
		switch (*ptr) {
		case '\'':
		case '"':
			if (escape) {
				escape = 0;
				memmove (ptr, ptr+1, strlen (ptr+1)+1);
			} else {
				if (quote) {
					*ptr = '\0';
					argv[argc++] = strdup (optr);
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
					argv[argc++] = strdup (optr);
					optr = ptr+1;
				}
			}
			break;
		default:
			escape = 0;
			break;
		}
	}
	if (*optr)
		argv[argc++] = strdup (optr);
	argv[argc] = NULL;
	if (_argc)
		*_argc = argc;

	free (str);
	return argv;
}

R_API void r_str_argv_free(char **argv) {
	// TODO: free the internal food or just the first element
//	free (argv[0]); // MEMORY LEAK
	int argc = 0;
	while (argv[argc])
		free (argv[argc++]);
	free (argv);
}

R_API const char *r_str_lastbut (const char *s, char ch, const char *but) {
	int idx, _b = 0;
	ut8 *b = (ut8*)&_b;
	const char *isbut, *p, *lp = NULL;
	const int bsz = sizeof (_b);
	if (!but)
		return r_str_lchr (s, ch);
	if (strlen (but) >= bsz) {
		eprintf ("r_str_lastbut: but string too long\n");
		return NULL;
	}
	for (p=s; *p; p++) {
		isbut = strchr (but, *p);
		if (isbut) {
			idx = (int)(size_t)(isbut-but);
			_b = R_BIT_CHK (b, idx)?
				R_BIT_UNSET (b, idx):
				R_BIT_SET (b, idx);
			continue;
		}
		if (*p == ch && !_b) lp = p;
	}
	return lp;
}

// Must be merged inside strlen
R_API int r_str_len_utf8char (const char *s, int left) {
	int i = 1;
	while (s[i] && (!left || i<left)) {
		if ((s[i] & 0xc0) != 0x80) {
			i++;
		} else break;
	}
	return i;
}

R_API int r_str_len_utf8 (const char *s) {
	int i = 0, j = 0;
	while (s[i]) {
		if ((s[i] & 0xc0) != 0x80) j++;
		i++;
	}
	return j;
}

R_API const char *r_str_casestr(const char *a, const char *b) {
	// That's a GNUism that works in many places.. but we dont want it
	// return strcasestr (a, b);
	size_t hay_len = strlen (a);
	size_t needle_len = strlen (b);
	while (hay_len >= needle_len) {
		if (strncasecmp (a, b, needle_len) == 0)
			return (const char *) a;
		a++;
		hay_len--;
	}
	return NULL;
}

R_API int r_str_write (int fd, const char *b) {
	return write (fd, b, strlen (b));
}

R_API void r_str_range_foreach(const char *r, RStrRangeCallback cb, void *u) {
	const char *p = r;
	for (; *r; r++) {
		if (*r == ',') {
			cb (u, atoi (p));
			p = r+1;
		}
		if (*r == '-') {
			if (p != r) {
				int from = atoi (p);
				int to = atoi (r+1);
				for (; from<=to; from++)
					cb (u, from);
			} else fprintf (stderr, "Invalid range\n");
			for (r++; *r && *r!=','&& *r!='-'; r++);
			p = r;
		}
	}
	if (*p) cb (u, atoi (p));
}

// convert from html escaped sequence "foo%20bar" to "foo bar"
// TODO: find better name.. unencode? decode
R_API void r_str_uri_decode (char *s) {
	int n;
	char *d;
	for (d=s; *s; s++, d++) {
#if 0
		if (*s == '+') {
			*d = ' ';
		} else
#endif
		if (*s == '%') {
			sscanf (s+1, "%02x", &n);
			*d = n;
			s+=2;
		} else *d = *s;
	}
	*d = 0;
}

R_API char *r_str_uri_encode (const char *s) {
	char ch[4], *d, *od;
	if (!s) return NULL;
	od = d = malloc (1+(strlen (s)*4));
	if (!d) return NULL;
	for (; *s; s++) {
		if((*s>='0' && *s<='9')
		|| (*s>='a' && *s<='z')
		|| (*s>='A' && *s<='Z')) {
			*d++ = *s;
		} else {
			*d++ = '%';
			sprintf (ch, "%02x", (unsigned char)*s);
			*d++ = ch[0];
			*d++ = ch[1];
		}
	}
	*d = 0;
	return realloc (od, strlen (od)+1); // FIT
}

// TODO: merge print inside rutil
/* hack from print */
R_API int r_print_format_length (const char *fmt) {
	int nargs, i, j, idx, times, endian;
	char *args, *bracket, tmp, last = 0;
	const char *arg = fmt;
	const char *argend = arg+strlen (fmt);
	char namefmt[8];
	int viewflags = 0;
	nargs = endian = i = j = 0;

	while (*arg && iswhitechar (*arg)) arg++;
	/* get times */
	times = atoi (arg);
	if (times > 0)
		while ((*arg>='0'&&*arg<='9')) arg++;
	bracket = strchr (arg,'{');
	if (bracket) {
		char *end = strchr (arg,'}');
		if (end == NULL) {
			eprintf ("No end bracket. Try pm {ecx}b @ esi\n");
			return 0;
		}
		*end='\0';
		times = r_num_math (NULL, bracket+1);
		arg = end + 1;
	}

	if (*arg=='\0')
		return 0;

	/* get args */
	args = strchr (arg, ' ');
	if (args) {
		int l=0, maxl = 0;
		argend = args;
		args = strdup (args+1);
		nargs = r_str_word_set0 (args+1);
		if (nargs == 0)
			R_FREE (args);
		for (i=0; i<nargs; i++) {
			int len = strlen (r_str_word_get0 (args+1, i));
			if (len>maxl) maxl = len;
		}
		l++;
		snprintf (namefmt, sizeof (namefmt), "%%%ds : ", maxl);
	}

	/* go format */
	i = 0;
	if (!times) times = 1;
	for (; times; times--) { // repeat N times
		const char * orig = arg;
		idx = 0;
		arg = orig;
		for (idx=0; arg<argend && *arg; idx++, arg++) {
			tmp = *arg;
		feed_me_again:
			if (tmp == 0 && last != '*')
				break;
			/* skip chars */
			switch (tmp) {
			case '*':
				if (i<=0) break;
				tmp = last;
				arg--;
				idx--;
				goto feed_me_again;
			case '+':
				idx--;
				viewflags = !viewflags;
				continue;
			case 'e': // tmp swap endian
				idx--;
				endian ^= 1;
				continue;
			case '.': // skip char
				i++;
				idx--;
				continue;
			case 'p':
				tmp = (sizeof (void*)==8)? 'q': 'x';
				break;
			case '?': // help
				idx--;
				if (args) free (args);
				return 0;
			}
			switch (tmp) {
			case 'e': i += 8; break;
			case 'q': i += 8; break;
			case 'b': i++; break;
			case 'c': i++; break;
			case 'B': i += 4; break;
			case 'i': i += 4; break;
			case 'd': i += 4; break;
			case 'x': i += 4; break;
			case 'w':
			case '1': i += 2; break;
			case 'z': // XXX unsupported
			case 'Z': // zero terminated wide string
				break;
			case 's': i += 4; break; // S for 8?
			case 'S': i += 8; break; // S for 8?
			default:
				/* ignore unknown chars */
				break;
			}
			last = tmp;
		}
		arg = orig;
		idx = 0;
	}
	if (args) {
		free (args);
	}
	return i;
}

R_API char *r_str_prefix_all (char *s, const char *pfx) {
	int newlines = 1;
	int len = 0;
	int plen = 0;
	char *o, *p, *os = s;

	if (s) {
		len = strlen (s);
		if (pfx) {
			plen = strlen (pfx);
		}
		for (p=s;*p;p++) if (*p=='\n') newlines++;
		o = malloc (len + (plen*newlines)+1);
		memcpy (o, pfx, plen);
		for (p=o+plen;*s;s++) {
			*p++ = *s;
			if (*s=='\n' && s[1]) {
				memcpy (p, pfx, plen);
				p += plen;
			}
		}
		*p = 0;
		free (os);
		return o;
	} else {
		return NULL;
	}
}

#define HASCH(x) strchr (input_value,x)
#define CAST (void*)(size_t)
R_API ut8 r_str_contains_macro(const char *input_value) {
	char *has_tilde = input_value ? HASCH('~') : NULL,
		 *has_bang = input_value ? HASCH('!') : NULL,
		 *has_brace = input_value ? CAST(HASCH('[') || HASCH(']')) : NULL,
		 *has_paren = input_value ? CAST(HASCH('(') || HASCH(')')) : NULL,
		 *has_cbrace = input_value ? CAST(HASCH('{') || HASCH('}')) : NULL,
		 *has_qmark = input_value ? HASCH('?') : NULL,
		 *has_colon = input_value ? HASCH(':') : NULL,
		 *has_at = input_value ? strchr (input_value, '@') : NULL;

	return has_tilde || has_bang || has_brace || has_cbrace || has_qmark \
		|| has_paren || has_colon || has_at;
}

R_API void r_str_truncate_cmd(char *string) {
	ut32 pos = 0, done = 0;
	if (string) {
		ut32 sz = strlen (string);
		for (pos = 0; pos < sz; pos++) {
			switch (string[pos]) {
				case '!':
				case ':':
				case ';':
				case '@':
				case '~':
				case '(':
				case '[':
				case '{':
				case '?':
					string[pos] = '\0';
					done = 1;
			}
			if (done) break;
		}
	}
}

R_API const char *r_str_closer_chr (const char *b, const char *s) {
	const char *a;
	while (*b) {
		for (a=s;*a;a++)
			if (*b==*a)
				return b;
		b++;
	}
	return NULL;
}


#if 0
R_API int r_str_bounds(const char *str, int *h) {
        int W = 0, H = 0;
        int cw = 0;
       if (!str)
               return W;
       while (*str) {
               if (*str=='\n') {
                       H++;
                       if (cw>W)
                               W = cw;
                       cw = 0;
                }
               str++;
               cw++;
        }
       if (*str == '\n') // skip last newline
               H--;
       if (h) *h = H;
        return W;
}

#else
R_API int r_str_bounds(const char *_str, int *h) {
	char *ostr, *str, *ptr;
	int W = 0, H = 0;
	int cw = 0;
	
	if (_str) {
		ptr = str = ostr = strdup (_str);
		while (*str) {
			if (*str=='\n') {
				H++;
				*str = 0;
				cw = (size_t)(str-ptr);
				cw = r_str_ansi_len (ptr);
				if (cw>W)
					W = cw;
				*str = '\n';
				cw = 0;
				ptr = str+1;
			}
			str++;
			cw++;
		}
		if (*str == '\n') // skip last newline
			H--;
		if (h) *h = H;
		free (ostr);
	}
	return W;
}
#endif

R_API char *r_str_crop(const char *str, int x, int y, int w, int h) {
	char *ret = strdup (str);
	char *r = ret;
	int ch = 0, cw = 0;
	while (*str) {
		if (*str == '\n') {
			if (ch>=y && ch<h)
				if (cw>=x && cw<w)
					*r++ = *str;
			ch++;
			cw = 0;
		} else
		if (ch>=y && ch<h)
			if (cw>=x && cw<w)
				*r++ = *str;
		str++;
		cw++;
	}
	*r = 0;
	return ret;
}

R_API const char * r_str_tok (const char *str1, const char b, size_t len) {
	const char *p = str1;
	size_t i = 0;
	if (!p || !*p) return p;
	if (len == -1) len = strlen (str1);
	for ( ; i < len; i++,p++) if (*p == b) break;
	if (i == len) p = NULL;
	return p;
}

/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>

/* stable code */
static const char *nullstr = "";
static const char *nullstr_c = "(null)";

/* int c; ret = hex2int(&c, 'c'); */
static int hex2int (ut8 *val, ut8 c) {
	if ('0' <= c && c <= '9') *val = (ut8)(*val) * 16 + ( c - '0');
	else if (c >= 'A' && c <= 'F') *val = (ut8)(*val) * 16 + ( c - 'A' + 10);
	else if (c >= 'a' && c <= 'f') *val = (ut8)(*val) * 16 + ( c - 'a' + 10);
	else return 1;
	return 0;
}

R_API const char *r_str_bool(int b) {
	if (b) return "true";
	return "false";
}

R_API void r_str_case(char *str, int up) {
	if (up) {
		while(*str)
			*str = tolower (*str);
	} else {
		while(*str)
			*str = toupper (*str);
	}
}

#if __WINDOWS__
#define __ENV_HOME "USERPROFILE"
#define __ENV_DIR "\\"
#else
#define __ENV_HOME "HOME"
#define __ENV_DIR "/"
#endif

R_API char *r_str_home(const char *str) {
	char *dst;
	const char *home = r_sys_getenv (__ENV_HOME);
	if (home == NULL)
		return NULL;
	dst = (char *)malloc (strlen (home) + strlen (str)+2);
	strcpy (dst, home);
	if (str && *str) {
		strcat (dst, __ENV_DIR);
		strcat (dst, str);
	}
	return dst;
}

R_API int r_str_hash(const char *str) {
	int i = 1;
	int a = 0x31;
	int b = 0x337;
	int h = str[0];
	for (; str[i]; i++) {
		h += str[i]*i*a;
		a *= b;
	}
	return h&0x7fffffff;
}

R_API int r_str_delta(char *p, char a, char b) {
	char *_a = strchr (p, a);
	char *_b = strchr (p, b);
	return (!_a||!_b)?0:(_a-_b);
}

R_API int r_str_word_set0(char *str) { int i;
	char *p;
	if (str[0]=='\0')
		return 0;
	/* TODO: sync with r1 code */
	for (i=1,p=str; p[0]; p++)
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
		if (tmp == text) word--;
	}
	return word-1;
}

R_API char *r_str_ichr(char *str, char chr) {
	while (*str==chr)
		str = str+1;
	return str;
}

R_API char *r_str_lchr(char *str, char chr) {
	int len = strlen(str)+1;
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

R_API char *r_str_chop(char *str) {
	int len;
	char *ptr;

	if (str == NULL)
		return NULL;
		
	while (*str && iswhitechar (*str))
		str = str + 1;
		
	len = strlen(str);
	
	if (len>0)
	for (ptr = str+len-1;ptr!=str;ptr = ptr - 1) {
		if (iswhitechar (ptr[0])) 
			*ptr = '\0';
		else break;
	}	       
	return str;
}

R_API char *r_str_trim_head(char *str) {
	if (str == NULL)
		return NULL;
	while (*str && iswhitechar(*str)) 
		str++;
	return str;
}

R_API char *r_str_trim_tail(char *str) {
	char *ptr = str;
	if (str == NULL)
		return NULL;
	ptr += strlen(str)-1;
	while ((ptr > str) && iswhitechar(*ptr)) {
		*ptr = '\0';
		ptr--;
	}
	return str;
}

R_API char *r_str_trim_head_tail(char *str) {
	return r_str_trim_tail(r_str_trim_head(str));
}

R_API char *r_str_trim(char *str) {
	int i;
	char *ptr;
	if (str == NULL)
		return NULL;
	for (ptr=str, i=0;str[i];i++)
		if (!iswhitechar (str[i]))
			*ptr++ = str[i];
	*ptr='\0';
	return str;
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
	for (;len--;) {
		if (*a=='\0'||*b=='\0'||*a!=*b)
			return 1;
		a=a+1;
		b=b+1;
	}
	return 0;
}

R_API int r_str_ccpy(char *dst, char *src, int ch) {
	int i;
	for(i=0;src[i] && src[i] != ch; i++)
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
	if (ptr)
		free (ptr);
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

R_API int r_str_writef(int fd, const char *fmt, ...) {
	int ret = R_FALSE;
	char *buf;
	va_list ap;
	va_start (ap, fmt);
	if ((buf = malloc (4096)) != NULL)
		vsnprintf (buf, 4096, fmt, ap);
		r_str_write (fd, buf);
		free (buf);
	}
	va_end (ap);
	return ret;
}

/*
 * return: the pointer ptr resized to string size.
 */
R_API char *r_str_concat(char *ptr, const char *string) {
	if (!ptr)
		return strdup (string);
	ptr = realloc (ptr, strlen (string)+strlen (ptr)+1);
	if (ptr == NULL)
		return NULL;
	strcat (ptr, string);
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

R_API void r_str_concatch(char *x, char y) {
	char b[2]={y,0};
	strcat (x,b);
}

R_API void *r_str_free(void *ptr) {
	free (ptr);
	return NULL;
}

R_API int r_str_inject(char *begin, char *end, char *str, int maxlen) {
	int len = strlen (end)+1;
	char *tmp;
	if (maxlen > 0 && ((strlen (begin)-(end-begin)+strlen (str)) > maxlen))
		return 0;
	tmp = malloc (len);
	memcpy (tmp, end, len);
	strcpy (begin, str);
	strcat (begin, tmp);
	free (tmp);
	return 1;
}

/* unstable code (taken from GNU) */
/*------------------------------------------------*/

// FROM bash::stringlib
#define RESIZE_MALLOCED_BUFFER(str,cind,room,csize,sincr) \
	if ((cind) + (room) >= csize) { \
		while ((cind) + (room) >= csize) \
		csize += (sincr); \
		str = realloc (str, csize); \
	}

/* Replace occurrences of PAT with REP in STRING.  If GLOBAL is non-zero,
   replace all occurrences, otherwise replace only the first.
   This returns a new string; the caller should free it. */

static int strsub_memcmp (char *string, char *pat, int len) {
	int res;
	for (res = 0; len-->0; pat++) {
		if (*pat!='?')
			res += *string - *pat;
		string++;
	}
	return res;
}

// TODO: rename r_str_replace
R_API char *r_str_sub(char *string, char *pat, char *rep, int global) {
	int patlen, templen, tempsize, repl, i;
	char *temp, *r;

	patlen = strlen (pat);
	for (temp = (char *)NULL, i = templen = tempsize = 0, repl = 1; string[i]; ) {
		if (repl && !strsub_memcmp (string + i, pat, patlen)) {
			RESIZE_MALLOCED_BUFFER (temp, templen, patlen, tempsize, 4096); //UGLY HACK (patlen * 2));
			if (temp == NULL)
				break;
			for (r = rep; *r; )
				temp[templen++] = *r++;
			i += patlen;
			repl = (global != 0);
		} else {
			RESIZE_MALLOCED_BUFFER (temp, templen, 1, tempsize, 4096); // UGLY HACK 16);
			temp[templen++] = string[i++];
		}
	}
	if (temp)
		temp[templen] = '\0';
	return (temp);
}

R_API char *r_str_clean(char *str) {
	int len;
	char *ptr;
	if (str != NULL) {
		while (str[0] && iswhitechar (str[0]))
			str = str + 1;
		if ((len = strlen(str))>0) 
		for (ptr = str+len-1;ptr!=str;ptr = ptr - 1) {
			if (iswhitechar (ptr[0]))
				ptr[0]='\0';
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
			strcpy (buf+i+1, buf+i+2);
		} else if (buf[i+1]=='r') {
			buf[i] = 0x0d;
			strcpy (buf+i+1, buf+i+2);
		} else if (buf[i+1]=='n') {
			buf[i] = 0x0a;
			strcpy (buf+i+1, buf+i+2);
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
			strcpy (buf+i+1, buf+i+4);
		} else {
			eprintf ("'\\x' expected.\n");
			return 0;
		}
	}
	return i;
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

R_API const char *r_str_ansi_chrn(const char *str, int n) {
	int len, i;
	for (i=len=0; str[i] && (n!=len); i++) {
		if (str[i]==0x1b && str[i+1]=='[')
			for (++i;str[i]&&str[i]!='J'&&str[i]!='m'&&str[i]!='H';i++);
		else len++;
	}
	return str+i;
}

R_API void r_str_filter(char *str, int len) {
	int i;
	for (i=0; i<len; i++)
		if (!IS_PRINTABLE (str[i]))
			str[i] = '.';
}

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
				strcpy (ptr, ptr+1);
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
R_API int r_bprintf(const char *fmt, ...)
{
	va_list ap;
	if (bprintf_init==0)
		*bprintf_buf = 0;
	va_start(ap, fmt);
	r_str_concatf(bprintf_buf, fmt, ap);
	va_end(ap);
	return strlen(bprintf_buf);
}

R_API char *r_bprintf_get()
{
	char *s;
	if (bprintf_init==0)
		*bprintf_buf = 0;
	s = strdup(bprintf_buf);
	bprintf_buf[0]='\0';
	return s;
}
#endif

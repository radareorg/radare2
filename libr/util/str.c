/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>
#include <stdarg.h>

/* stable code */
static const char *nullstr = "";
static const char *nullstr_c = "(null)";

/* int c; ret = hex2int(&c, 'c'); */
static int hex2int (unsigned char *val, unsigned char c)
{
	if ('0' <= c && c <= '9')      *val = (unsigned char)(*val) * 16 + ( c - '0');
	else if (c >= 'A' && c <= 'F') *val = (unsigned char)(*val) * 16 + ( c - 'A' + 10);
	else if (c >= 'a' && c <= 'f') *val = (unsigned char)(*val) * 16 + ( c - 'a' + 10);
	else return 1;
	return 0;
}

/* TODO: port to w32 and move outside r_str namespace? */
R_API char *r_str_home(const char *str)
{
	const char *home = getenv("HOME");
	char *dst;
	if (home == NULL)
		return NULL;
	dst = (char *)malloc(strlen(home) + strlen(str)+2);
	strcpy(dst, home);
	strcat(dst, "/");
	strcat(dst, str);
	return dst;
}

R_API int r_str_hash(const char *str)
{
	int i = 1;
	int a = 0x31;
	int b = 0x337;
	int h = str[0];
	for(; str[i]; i++) {
		h+=str[i]*i*a;
		a*=b;
	}
	return h&0x7ffffff;
}

R_API int r_str_delta(char *p, char a, char b)
{
	char *_a = strchr(p, a);
	char *_b = strchr(p, b);
	if (!_a||!_b) return 0;
	return (_a-_b);
}

R_API int r_str_word_set0(char *str)
{
        int i;
        char *p;
        if (str[0]=='\0')
                return 0;
	/* TODO: sync with r1 code */
        for(i=1,p=str;p[0];p=p+1)if(*p==' '){i++;*p='\0';} // s/ /\0/g
        return i;
}

R_API const char *r_str_word_get0(const char *str, int idx)
{
        int i;
        const char *ptr = str;
        if (ptr == NULL)
                return nullstr;
        for (i=0;*ptr && i != idx;i++)
                ptr = ptr + strlen(ptr) + 1;
        return ptr;
}

R_API int r_str_word_count(const char *string)
{
        char *text = (char *)string;
        char *tmp  = (char *)string;
        int word   = 0;

        for(;(*text)&&(isseparator(*text));text=text+1);

        for(word = 0; *text; word++) {
                for(;*text && !isseparator(*text);text = text +1);
                tmp = text;
                for(;*text &&isseparator(*text);text = text +1);
                if (tmp == text)
                        word-=1;
        }

        return word-1;
}

R_API char *r_str_ichr(char *str, char chr)
{
	while(*str==chr) {
		str = str+1;
	}
	return str;
}

R_API char *r_str_lchr(char *str, char chr)
{
        int len = strlen(str)+1;
        for(;len>=0;len--)
                if (str[len]==chr)
                        return str+len;
        return NULL;
}

R_API int r_str_nchr(const char *str, char chr)
{
	int n = 0;
	while(str[0]) {
		if (str[0]==chr)
			n++;
		str = str+1;
	}
	return n;
}

R_API int r_str_nstr(char *from, char *to, int size)
{
        int i;
        for(i=0;i<size;i++)
                if (from==NULL||to==NULL||from[i]!=to[i])
                        break;
        return (size!=i);
}

R_API const char *r_str_chop_ro(const char *str)
{
	if (str)
        while(str[0]&&iswhitechar(str[0]))
                str = str + 1;
	return str;
}

R_API char *r_str_chop(char *str)
{
        int len;
        char *ptr;

        if (str == NULL)
                return NULL;
                
        while(str[0]&&iswhitechar(str[0]))
                str = str + 1;
                
        len = strlen(str);
        
        if (len>0)
        for(ptr = str+len-1;ptr!=str;ptr = ptr - 1) {
                if (iswhitechar(ptr[0])) 
                        ptr[0]='\0';
                else    break;
        }               
        return str;
}

R_API char *r_str_trim(char *str)
{
	int i;
	char *ptr;

	if (str == NULL)
		return NULL;

	for(ptr=str, i=0;str[i];i++)
		if (!iswhitechar(str[i]))
			*ptr++=str[i];
	*ptr='\0';
	return str;
}

/* memccmp("foo.bar", "foo.cow, '.') == 0 */
int r_str_ccmp(const char *dst, const char *orig, int ch)
{
        int i;
        for(i=0;orig[i] && orig[i] != ch; i++)
                if (dst[i] != orig[i])
                        return 1;
        return 0;
}

int r_str_cmp(const char *a, const char *b, int len)
{
	for(;len--;) {
		if (*a=='\0'||*b=='\0'||*a!=*b)
			return 1;
		a=a+1;
		b=b+1;
	}
	return 0;
}

int r_str_ccpy(char *dst, char *orig, int ch)
{
        int i;
        for(i=0;orig[i] && orig[i] != ch; i++)
                dst[i] = orig[i];
        dst[i] = '\0';
        return i;
}

char *r_str_word_get_first(const char *string)
{
        char *text  = (char *)string;
        char *start = NULL;
        char *ret   = NULL;
        int len     = 0;

        for(;*text &&isseparator(*text);text = text + 1);
        start = text;
        for(;*text &&!isseparator(*text);text = text + 1) len++;

        /* strdup */
        ret = (char *)malloc(len+1);
        if (ret == 0) {
                fprintf(stderr, "Cannot allocate %d bytes.\n", len+1);
                exit(1);
        }
        strncpy(ret, start, len);
        ret[len]='\0';

        return ret;
}

const char *r_str_get(const char *str)
{
        if (str == NULL)
                return nullstr_c;
        return str;
}

char *r_str_dup(char *ptr, const char *string)
{
        if (ptr)
                free(ptr);
        ptr = strdup(string);
        return ptr;
}

char *r_str_concat(char *ptr, const char *string)
{
        if (!ptr)
		return strdup(string);
	ptr = realloc(ptr, strlen(string)+strlen(ptr)+1);
	if (ptr == NULL)
		return NULL;
	strcat(ptr, string);
        return ptr;
}

char *r_str_concatf(char *ptr, const char *fmt, ...)
{
	char string[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(string, 1023, fmt, ap);
	ptr = r_str_concat(ptr, string);
	va_end(ap);
        return ptr;
}

inline void r_str_concatch(char *x, char y){char b[2]={y,0};strcat(x,b);}

void *r_str_free(void *ptr)
{
        free (ptr);
	return NULL;
}

int r_str_inject(char *begin, char *end, char *str, int maxlen)
{
        int len = strlen(end)+1;
        char *tmp = alloca(len);
	if (maxlen > 0 && ((strlen(begin)-(end-begin)+strlen(str)) > maxlen))
		return 0;
        memcpy(tmp, end, len);
        strcpy(begin, str);
        strcat(begin, tmp);
        return 1;
}

/* unstable code */
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

static int strsub_memcmp (char *string, char *pat, int len)
{
        int res = 0;
        while(len--) {
                if (*pat!='?')
                        res += *string - *pat;
                string = string+1;
                pat = pat+1;
        }
        return res;
}

char *r_str_sub(char *string, char *pat, char *rep, int global)
{
        int patlen, templen, tempsize, repl, i;
        char *temp, *r;

        patlen = strlen (pat);
        for (temp = (char *)NULL, i = templen = tempsize = 0, repl = 1; string[i]; )
        {
//              if (repl && !memcmp(string + i, pat, patlen)) {
                if (repl && !strsub_memcmp(string + i, pat, patlen)) {
                        RESIZE_MALLOCED_BUFFER (temp, templen, patlen, tempsize, 4096); //UGLY HACK (patlen * 2));
                        if (temp == NULL)
                                return NULL;
                        for (r = rep; *r; )
                                temp[templen++] = *r++;

                        i += patlen;
                        repl = global != 0;
                } else {
                        RESIZE_MALLOCED_BUFFER (temp, templen, 1, tempsize, 4096); // UGLY HACK 16);
                        temp[templen++] = string[i++];
                }
        }
        if (temp != NULL)
                temp[templen] = 0;
        return (temp);
}

int r_str_escape(char *buf)
{
	unsigned char ch = 0, ch2 = 0;
	int err = 0;
	int i;

	for(i=0;buf[i];i++) {
		if (buf[i]=='\\') {
			if (buf[i+1]=='e') {
				buf[i] = 0x1b;
				strcpy(buf+i+1, buf+i+2);
			} else if (buf[i+1]=='r') {
				buf[i] = 0x0d;
				strcpy(buf+i+1, buf+i+2);
			} else if (buf[i+1]=='n') {
				buf[i] = 0x0a;
				strcpy(buf+i+1, buf+i+2);
			} else if (buf[i+1]=='x') {
				err = ch2 = ch = 0;
				if (!buf[i+2] || !buf[i+3]) {
					printf("Unexpected end of string.\n");
					return 0;
				}
				err |= hex2int(&ch,  buf[i+2]);
				err |= hex2int(&ch2, buf[i+3]);
				if (err) {
					printf("Incorrect hexadecimal characters for conversion.\n");
					return 0;
				}
				buf[i] = (ch<<4)+ch2;
				strcpy(buf+i+1, buf+i+4);
			} else {
				printf("'\\x' expected.\n");
				return 0;
			}
		}
	}
	return i;
}

/* ansi helpers */
R_API int r_str_ansi_len(const char *str)
{
	int i=0, len = 0;
	while(str[i]) {
		if (str[i]==0x1b && str[i+1]=='[')
			for(++i;str[i]&&str[i]!='J'&&str[i]!='m'&&str[i]!='H';i++);
		else len++;
		i++;
	}
	return len;
}

R_API const char *r_str_ansi_chrn(const char *str, int n)
{
	int i=0, len = 0;
	while(str[i]) {
		if (n == len)
			break;
		if (str[i]==0x1b && str[i+1]=='[')
			for(++i;str[i]&&str[i]!='J'&&str[i]!='m'&&str[i]!='H';i++);
		else len++;
		i++;
	}
	return str+i;
}


#if 0
int r_str_argv_parse(const char *str, int argc, char **argv)
{
	int n = 0;

	int i = 0;
	char *tmp, *tmp2;
	free(ps.args);
	ps.args = strdup(ps.filename);
	tmp2 = ps.args;
	// parse argv
	//eprintf("commandline=\"%s\"\n", ps.args);
	for(tmp=ps.args;tmp[0];tmp=tmp+1) {
		if (tmp[0]==' '&&tmp!=ps.args) {                        if ((tmp[-1]=='\\') || (tmp[-1]=='/'))
			continue;
			tmp[0]='\0';
			ps.argv[i] = tmp2;
			tmp2 = tmp+1;
			if (++i>254) {
				printf("Too many arguments. truncated\n");
				break;
			}
		}
	}
	ps.argv[i] = tmp2;
	ps.argv[i+1] = 0;

	tmp = strchr(config.file, ' ');
	if (tmp) *tmp = '\0';
	//config.file = strdup("/bin/ls"); //ps.argv[0];
	//eprintf("ppa:A0(%s)\n", ps.argv[0]);

	return n;
}
#endif

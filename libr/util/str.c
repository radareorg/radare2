/* radare - LGPL - Copyright 2007-2016 - pancake */

#include "r_types.h"
#include "r_util.h"
#include "r_cons.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

/* stable code */
static const char *nullstr = "";
static const char *nullstr_c = "(null)";
static const char *rwxstr[] = {
	[0] = "----",
	[1] = "---x",
	[2] = "--w-",
	[3] = "--wx",
	[4] = "-r--",
	[5] = "-r-x",
	[6] = "-rw-",
	[7] = "-rwx",

	[8] = "----",
	[9] = "---x",
	[10] = "--w-",
	[11] = "--wx",
	[12] = "-r--",
	[13] = "-r-x",
	[14] = "-rw-",
	[15] = "-rwx",

	[16] = "m---",
	[17] = "m--x",
	[18] = "m-w-",
	[19] = "m-wx",
	[20] = "mr--",
	[21] = "mr-x",
	[22] = "mrw-",
	[23] = "mrwx",
};


// TODO: simplify this horrible loop
R_API void r_str_chop_path(char *s) {
	char *src, *dst, *p;
	int i = 0;
	if (!s || !*s) {
		return;
	}
	dst = src = s + 1;
	while (*src) {
		if (*(src - 1) == '/' && *src == '.' && *(src + 1) == '.') {
			if (*(src + 2) == '/' || *(src + 2) == '\0') {
				p = dst - 1;
				while (s != p) {
					if (*p == '/') {
						if (i) {
							dst = p + 1;
							i = 0;
							break;
						}
						i = 1;
					}
					p--;
				}
				if (s == p && *p == '/') {
					dst = p + 1;
				}
				src = src + 2;
			} else {
				*dst = *src;
				dst++;
			}
		} else if (*src == '/' && *(src + 1) == '.' && (*(src + 2) == '/' || *(src + 2) == '\0')) {
			src++;
		} else if (*src != '/' || *(src-1) != '/') {
			*dst = *src;
			dst++;
		}
		src++;
	}
	if (dst > s + 1 && *(dst - 1) == '/') {
		*(dst-1) = 0;
	} else {
		*dst = 0;
	}
}

// In-place replace the first instance of the character a, with the character b.
R_API int r_str_replace_char_once(char *s, int a, int b) {
	int ret = 0;
	char *o = s;
	if (a == b) {
		return 0;
	}
	for (; *o; s++, o++) {
		if (*o==a) {
			if (b) {
				*s = b;
				return ++ret;
			}
			o++;
		}
		*s = *o;
	}
	*s = 0;
	return ret;
}

// Spagetti.. must unify and support 'g', 'i' ...
// In-place replace all instances of character a with character b.
R_API int r_str_replace_char(char *s, int a, int b) {
	int ret = 0;
	char *o = s;
	if (a == b) {
		return 0;
	}
	for (; *o; s++, o++) {
		if (*o == a) {
			ret++;
			if (b) {
				*s = b;
			} else {
				/* remove char */
				s--;
			}
		} else {
			*s = *o;
		}
	}
	*s = 0;
	return ret;
}

// TODO: do not use toupper.. must support modes to also append lowercase chars like in r1
// TODO: this functions needs some stabilization
R_API int r_str_bits(char *strout, const ut8 *buf, int len, const char *bitz) {
	int i, j;
	if (bitz) {
		for (i = j = 0; i<len && (!bitz||bitz[i]); i++) {
			if (i > 0 && (i % 8) == 0) {
				buf++;
			}
			if (*buf & (1 << (i % 8))) {
				strout[j++] = toupper ((const ut8)bitz[i]);
			}
		}
	} else {
		for (i = j = 0; i < len; i++) {
			if (i > 0 && (i % 8) == 0) {
				buf++;
			}
			strout[j++] = (*buf & (1 << (7 - (i % 8))))? '1' : '0';
		}
	}
	strout[j] = 0;
	return j;
}

// In-place trims a bitstring to groups of 8 bits.
// For example, the bitstring 1000000000000000 will not be modified, but the
// bitstring 0000000001000000 will be changed to 01000000.
static void trimbits(char *b) {
	int len = strlen (b);
	char *one = strchr (b, '1');
	int pos = one ? (int)(size_t)(one - b) : len - 1;
	pos = (pos / 8) * 8;
	memmove (b, b + pos, len - pos + 1);
}

// Set 'strout' to the binary representation of the input value.
// strout must be a char array of 65 or greater.
// The string is then trimmed using the "trimbits" function above.
R_API int r_str_bits64(char* strout, ut64 in) {
	int i, bit, count = 0;
	count = 0;
	for (i = (sizeof (in) * 8) - 1; i >= 0; --i) {
		bit = in >> i;
		if (bit & 1) {
			strout[count] = '1';
		} else {
			strout[count] = '0';
		}
		++count;
	}
	strout[count] = '\0';
	/* trim by 8 bits */
	trimbits (strout);
	return count;
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

R_API int r_str_binstr2bin(const char *str, ut8 *out, int outlen) {
	int n, i, j, k, ret, len;
	len = strlen (str);
	for (n = i = 0; i < len; i += 8) {
		ret = 0;
		while (str[i]==' ') {
			str++;
		}
		if (i + 7 < len) {
			for (k = 0, j = i + 7; j >= i; j--, k++) {
				// INVERSE for (k=0,j=i; j<i+8; j++,k++) {
				if (str[j] == ' ') {
					//k--;
					continue;
				}
				//		printf ("---> j=%d (%c) (%02x)\n", j, str[j], str[j]);
				if (str[j] == '1') {
					ret|=1 << k;
				} else if (str[j] != '0') {
					return n;
				}
			}
		}
	//	printf ("-======> %02x\n", ret);
		out[n++] = ret;
		if (n == outlen) {
			return n;
		}
	}
	return n;
}

// Returns the permissions as in integer given an input in the form of rwx, rx,
// etc.
R_API int r_str_rwx(const char *str) {
	int ret = atoi (str);
	if (!ret) {
		ret |= strchr (str, 'm') ? 16 : 0;
		ret |= strchr (str, 'r') ? 4 : 0;
		ret |= strchr (str, 'w') ? 2 : 0;
		ret |= strchr (str, 'x') ? 1 : 0;
	} else if (ret < 0 || ret >= R_ARRAY_SIZE (rwxstr)) {
		ret = 0;
	}
	return ret;
}

// Returns the string representation of the permission of the inputted integer.
R_API const char *r_str_rwx_i(int rwx) {
	if (rwx < 0 || rwx >= R_ARRAY_SIZE (rwxstr)) {
		rwx = 0;
	}
	return rwxstr[rwx % 24]; // 15 for srwx
}

// Returns "true" or "false" as a string given an input integer. The returned
// value is consistant with C's definition of 0 is false, and all other values
// are true.
R_API const char *r_str_bool(int b) {
	return b? "true": "false";
}

// If up is true, upcase all characters in the string, otherwise downcase all
// characters in the string.
R_API void r_str_case(char *str, bool up) {
	if (up) {
		char oc = 0;
		for (; *str; oc = *str++)
			*str = (*str=='x' && oc=='0') ? 'x': toupper ((int)(ut8)*str);
	} else {
		for (; *str; str++)
			*str = tolower ((int)(ut8)*str);
	}
}

R_API char *r_str_home(const char *str) {
	char *dst, *home = r_sys_getenv (R_SYS_HOME);
	size_t length;
	if (!home) {
		return NULL;
	}
	length = strlen (home) + 1;
	if (str) {
		length += strlen (R_SYS_DIR) + strlen (str);
	}
	dst = (char *)malloc (length);
	if (!dst) {
		goto fail;
	}
	strcpy (dst, home);
	if (str) {
		strcat (dst, R_SYS_DIR);
		strcat (dst, str);
	}
fail:
	free (home);
	return dst;
}

// Compute a 64 bit DJB hash of a string.
R_API ut64 r_str_hash64(const char *s) {
	ut64 len, h = 5381;
	if (!s) {
		return 0;
	}
	for (len = strlen (s); len > 0; len--) {
		h = (h ^ (h << 5)) ^ *s++;
	}
	return h;
}

// Compute a 32bit DJB hash of a string.
R_API ut32 r_str_hash (const char *s) {
	return (ut32) r_str_hash64 (s);
}

R_API int r_str_delta(char *p, char a, char b) {
	char *_a = strchr (p, a);
	char *_b = strchr (p, b);
	return (!_a || !_b)? 0 : (_a - _b);
}

// In-place split string using ch as a delimeter. Replaces all instances of ch
// with a null byte. Returns the number of times that the string was split.
// For example r_str_split("hello world", ' ') will replace the space with '\0'
// and return 1.
R_API int r_str_split(char *str, char ch) {
	int i;
	char *p;
	if (!str || !*str) {
		return 0;
	}
	/* TODO: sync with r1 code */
	for (i = 1, p = str; *p; p++) {
		if (*p == ch) {
			i++;
			*p = '\0';
		} // s/ /\0/g
	}
	return i;
}

// Convert a string into an array of string separated by \0
// And the last by \0\0
// Separates by words and skip spaces.
// Returns the number of tokens that the string is tokenized into.
R_API int r_str_word_set0(char *str) {
	int i, quote = 0;
	char *p;
	if (!str || !*str) {
		return 0;
	}
	for (i = 0; str[i] && str[i + 1]; i++) {
		if (i > 0 && str[i-1] == ' ' && str[i] == ' ') {
			int len = strlen (str + i);
			memmove (str + i, str + i + 1, len);
			i--;
		}
	}
	if (str[i] == ' ') {
		str[i] = 0;
	}
	for (i = 1, p = str; *p; p++) {
		if (*p == '\"') {
			if (quote) {
				quote = 0;
				*p = '\0';
				// FIX: i++;
				continue;
			} else {
				quote = 1;
				memmove (p, p + 1, strlen (p + 1) + 1);
			}
		}
		if (quote) {
			continue;
		}
		if (*p == ' ') {
			char *q = p-1;
			if (p > str && (*q == '\\' || !*q)) {
				memmove (p, p + 1, strlen (p + 1) + 1);
				if (*q == '\\') {
					*q = ' ';
					continue;
				}
				p--;
			}
			i++;
			*p = '\0';
		} // s/ /\0/g
	}
	return i;
}

R_API int r_str_word_set0_stack(char *str) {
	int i;
	char *p, *q;
	RStack *s;
	void *pop;
	if (!str || !*str) {
		return 0;
	}
	for (i = 0; str[i] && str[i+1]; i++) {
		if (i > 0 && str[i - 1] == ' ' && str[i] == ' ') {
			int len = strlen (str + i) + 1;
			memmove (str + i, str + i + 1, len);
			i--;
		}
		if (i == 0 && str[i] == ' ') {
			memmove (str + i, str + i + 1, strlen (str + i) + 1);
		}
	}
	if (str[i] == ' ') {
		str[i] = 0;
	}
	s = r_stack_new (5); //Some random number
	for (i = 1, p = str; *p; p++) {
		q = p - 1;
		if (p > str && (*q == '\\')) {
			memmove (q, p, strlen (p) + 1);
			p--;
			continue;
		}
		switch (*p) {
		case '(':
		case '{':
		case '[':
			r_stack_push (s, (void *)p);
			continue;
		case '\'':
		case '"':
			pop = r_stack_pop (s);
			if (pop && *(char *)pop != *p) {
				r_stack_push (s, pop);
				r_stack_push (s, (void *)p);
			} else if (!pop) {
				r_stack_push (s, (void *)p);
			}
			continue;
		case ')':
		case '}':
	    case ']':
			pop = r_stack_pop (s);
			if (pop) {
				if ((*(char *)pop == '(' && *p == ')') ||
					(*(char *)pop == '{' && *p == '}') ||
					(*(char *)pop == '[' && *p == ']')) {
					continue;
				}
			}
			break;
		case ' ':
			if (p > str && !*q) {
				memmove (p, p+1, strlen (p + 1) + 1);
				if (*q == '\\') {
					*q = ' ';
					continue;
				}
				p--;
			}
			if (r_stack_is_empty (s)) {
				i++;
				*p = '\0';
			}
		default:
			break;
		}
	}
	r_stack_free (s);
	return i;
}

R_API char *r_str_word_get0set(char *stra, int stralen, int idx, const char *newstr, int *newlen) {
	char *p = NULL;
	char *out;
	int alen, blen, nlen;
	if (!stra && !newstr) return NULL;
	if (stra) {
		p = (char *)r_str_word_get0 (stra, idx);
	}
	if (!p) {
		int nslen = strlen (newstr);
		out = malloc (nslen + 1);
		if (!out) {
			return NULL;
		}
		strcpy (out, newstr);
		out[nslen] = 0;
		if (newlen) {
			*newlen = nslen;
		}
		return out;
	}
	alen = (size_t)(p-stra);
	blen = stralen - ((alen + strlen (p)) + 1);
	if (blen < 0) {
		blen = 0;
	}
	nlen = alen + blen + strlen (newstr);
	out = malloc (nlen + 2);
	if (!out) {
		return NULL;
	}
	if (alen > 0) {
		memcpy (out, stra, alen);
	}
	memcpy (out + alen, newstr, strlen (newstr) + 1);
	if (blen > 0) {
		memcpy (out + alen + strlen (newstr) + 1, p + strlen (p) + 1, blen + 1);
	}
	out[nlen + 1] = 0;
	if (newlen) {
		*newlen = nlen + ((blen == 0)? 1 : 0);
	}
	return out;
}

// Get the idx'th entry of a tokenized string.
// XXX: Warning! this function is UNSAFE, check that the string has, at least,
// idx+1 tokens.
R_API const char *r_str_word_get0(const char *str, int idx) {
	int i;
	const char *ptr = str;
	if (!ptr || idx < 0 /* prevent crashes with negative index */) {
		return (char *)nullstr;
	}
	for (i = 0; *ptr && i != idx; i++) {
		ptr += strlen (ptr) + 1;
	}
	return ptr;
}

// Return the number of times that the character ch appears in the string.
R_API int r_str_char_count(const char *string, char ch) {
	int i, count = 0;
	for (i = 0; string[i]; i++) {
		if (string[i] == ch) {
			count++;
		}
	}
	return count;
}

// Counts the number of words (separted by separator charactors: newlines, tabs,
// return, space). See r_util.h for more details of the isseparator macro.
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

// Returns a pointer to the first instance of a character that isn't chr in a
// string.
// TODO: make this const-correct.
// XXX if the string is only made up of chr, then the pointer will just point to
// a null byte!
R_API char *r_str_ichr(char *str, char chr) {
	while (*str == chr) {
		str++;
	}
	return str;
}

// Returns a pointer to the last instance of the character chr in the input
// string.
R_API const char *r_str_lchr(const char *str, char chr) {
	if (str) {
		int len = strlen (str);
		for (;len >= 0; len--) {
			if (str[len] == chr) {
				return str + len;
			}
		}
	}
	return NULL;
}

/* find the last char chr in the substring str[start:end] with end not included */
R_API const char *r_sub_str_lchr(const char *str, int start, int end, char chr) {
	do {
		end--;
	} while (str[end] != chr && end >= start);
	return str[end] == chr ? &str[end] : NULL;
}

/* find the first char chr in the substring str[start:end] with end not included */
R_API const char *r_sub_str_rchr(const char *str, int start, int end, char chr) {
	while (str[start] != chr && start < end) start++;
	return str[start] == chr ? &str[start] : NULL;
}

R_API const char *r_str_rchr(const char *base, const char *p, int ch) {
	if (!base) {
		return NULL;
	}
	if (!p) {
		p = base + strlen (base);
	}
	for (; p >= base; p--) {
		if (ch == *p) {
			break;
		}
	}
	return (p < base) ? NULL : p;
}

R_API int r_str_nstr(char *from, char *to, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (!from || !to || from[i] != to[i]) {
			break;
		}
	}
	return (size!=i);
}

// TODO: rewrite in macro?
R_API const char *r_str_chop_ro(const char *str) {
	if (str) {
		while (*str && iswhitechar (*str)) str++;
	}
	return str;
}

// Returns a new heap-allocated copy of str.
R_API char *r_str_new(const char *str) {
	if (!str) {
		return NULL;
	}
	return strdup (str);
}

// Returns a new heap-allocated copy of str, sets str[len] to '\0'.
// If the input str is longer than len, it will be truncated.
R_API char *r_str_newlen(const char *str, int len) {
	char *buf;
	if (len < 1) {
		return NULL;
	}
	buf = malloc (len + 1);
	if (!buf) {
		return NULL;
	}
	memcpy (buf, str, len);
	buf[len] = 0;
	return buf;
}

// Returns a new heap-allocated string that matches the format-string
// specification.
R_API char *r_str_newf(const char *fmt, ...) {
	int ret, ret2;
	char *p, string[1024];
	va_list ap, ap2;
	va_start (ap, fmt);
	va_start (ap2, fmt);
	if (!strchr (fmt, '%')) {
		va_end (ap2);
		va_end (ap);
		return strdup (fmt);
	}
	ret = vsnprintf (string, sizeof (string) - 1, fmt, ap);
	if (ret < 1 || ret >= sizeof (string)) {
		p = malloc (ret + 2);
		if (!p) {
			va_end (ap2);
			va_end (ap);
			return NULL;
		}
		ret2 = vsnprintf (p, ret + 1, fmt, ap2);
		if (ret2 < 1 || ret2 > ret + 1) {
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

// TODO: rename to r_str_trim_inplace() or something like that
R_API char *r_str_chop(char *str) {
	int len;
	char *ptr;

	if (!str) return NULL;
	while (*str && iswhitechar (*str)) {
		memmove (str, str + 1, strlen (str + 1) + 1);
	}
	len = strlen (str);
	if (len > 0) {
		for (ptr = str + len-1; ptr != str; ptr--) {
			if (!iswhitechar (*ptr)) {
				break;
			}
			*ptr = '\0';
		}
	}
	return str;
}

// Returns a pointer to the first non-whitespace character of str.
R_API const char *r_str_trim_const(const char *str) {
	if (str) {
		for (; *str && iswhitechar (*str); str++);
	}
	return str;
}

/* remove spaces from the head of the string.
 * the string is changed in place */
R_API char *r_str_trim_head(char *str) {
	char *p;

	if (!str) {
		return NULL;
	}

	for (p = str; *p && iswhitechar (*p); p++)
		;

	/* Take the trailing null into account */
	memmove (str, p, strlen (p) + 1);

	return str;
}

// Remove whitespace chars from the tail of the string, replacing them with
// null bytes. The string is changed in-place.
R_API char *r_str_trim_tail(char *str) {
	int length;

	if (!str) {
		return NULL;
	}
	length = strlen (str);
	if (!length) {
		return str;
	}

	while (length--) {
		if (iswhitechar (str[length])) {
			str[length] = '\0';
		} else {
			break;
		}
	}

	return str;
}

// Removes spaces from the head of the string, and zeros out whitespaces from
// the tail of the string. The string is changed in place.
R_API char *r_str_trim_head_tail(char *str) {
	return r_str_trim_tail (r_str_trim_head (str));
}

// Copy all printable characters from src to dst, copy all printable characters
// as '.'.
R_API void r_str_ncpy(char *dst, const char *src, int n) {
	int i;
	for (i = 0; src[i] && n > 0; i++, n--) {
		dst[i] = IS_PRINTABLE (src[i])? src[i]: '.';
	}
	dst[i] = 0;
}

/* memccmp("foo.bar", "foo.cow, '.') == 0 */
// Returns 1 if src and dst are equal up until the first instance of ch in src.
R_API int r_str_ccmp(const char *dst, const char *src, int ch) {
	int i;
	for (i = 0; src[i] && src[i] != ch; i++) {
		if (dst[i] != src[i]) {
			return 1;
		}
	}
	return 0;
}

// Compare two strings for the first len bytes. Returns true if they are equal.
// NOTE: this is not useful as a comparitor, as it returns true or false.
R_API int r_str_cmp(const char *a, const char *b, int len) {
	if (a == b) {
		return true;
	}
	for (;len--;) {
		if (*a == '\0' || *b == '\0' || *a != *b) {
			return true;
		}
		a++; b++;
	}
	return false;
}

// Copies all characters from src to dst up until the character 'ch'.
R_API int r_str_ccpy(char *dst, char *src, int ch) {
	int i;
	for (i = 0; src[i] && src[i] != ch; i++) {
		dst[i] = src[i];
	}
	dst[i] = '\0';
	return i;
}

R_API char *r_str_word_get_first(const char *text) {
	char *ret;
	int len = 0;
	for (;*text && isseparator (*text); text++);
	/* strdup */
	len = strlen (text);
	ret = (char *)malloc (len + 1);
	if (!ret) {
		eprintf ("Cannot allocate %d bytes.\n", len+1);
		exit (1);
	}
	strncpy (ret, text, len);
	ret[len] = '\0';

	return ret;
}

R_API const char *r_str_get(const char *str) {
	return str? str: nullstr_c;
}

R_API const char *r_str_get2(const char *str) {
	return str? str: nullstr;
}

R_API char *r_str_ndup(const char *ptr, int len) {
	char *out = malloc (len+1);
	if (!out) {
		return NULL;
	}
	strncpy (out, ptr, len);
	out[len] = 0;
	return out;
}

// TODO: deprecate?
R_API char *r_str_dup(char *ptr, const char *string) {
	int len;
	free (ptr);
	if (!string) {
		return NULL;
	}
	len = strlen (string)+1;
	ptr = malloc (len+1);
	if (!ptr) {
		return NULL;
	}
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
	if (!ptr)
		return strdup (string);
	//plen = r_str_len_utf8 (ptr);
	//slen = r_str_len_utf8 (string);
	plen = strlen (ptr);
	slen = strlen (string);
	ptr = realloc (ptr, slen + plen + 1);
	if (!ptr) {
		return NULL;
	}
	memmove (ptr + slen, ptr, plen + 1);
	memmove (ptr, string, slen);
	return ptr;
}

R_API char *r_str_concatlen(char *ptr, const char *string, int slen) {
	char *ret, *msg = r_str_newlen (string, slen);
	ret = r_str_concat (ptr, msg);
	free (msg);
	return ret;
}

/*
 * first argument must be allocated
 * return: the pointer ptr resized to string size.
 */
// TODO: use vararg here?
R_API char *r_str_concat(char *ptr, const char *string) {
	int slen, plen;
	if (!string && !ptr) {
		return NULL;
	}
	if (!string && ptr) {
		return ptr;
	}
	if (string && !ptr) {
		return strdup (string);
	}
	plen = strlen (ptr);
	slen = strlen (string);
	ptr = realloc (ptr, slen + plen + 1);
	if (!ptr) {
		return NULL;
	}
	memcpy (ptr + plen, string, slen + 1);
	return ptr;
}

R_API char *r_str_concatf(char *ptr, const char *fmt, ...) {
	int ret;
	char string[4096];
	va_list ap;
	va_start (ap, fmt);
	ret = vsnprintf (string, sizeof (string), fmt, ap);
	if (ret >= sizeof (string)) {
		char *p = malloc (ret + 2);
		if (!p) {
			va_end (ap);
			return NULL;
		}
		vsnprintf (p, ret + 1, fmt, ap);
		ptr = r_str_concat (ptr, p);
		free (p);
	} else {
		ptr = r_str_concat (ptr, string);
	}
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

	if (!str || !key || !val) {
		return NULL;
	}
	klen = strlen (key);
	vlen = strlen (val);
	if (klen == vlen && !strcmp (key, val)) {
		return str;
	}
	slen = strlen (str);
	for (i = 0; i < slen; ) {
		p = (char *)r_mem_mem (
			(const ut8*)str + i, slen - i,
			(const ut8*)key, klen);
		if (!p) {
			break;
		}
		off = (int)(size_t)(p-str);
		scnd = strdup (p+klen);
		slen += vlen - klen;
		// HACK: this 32 avoids overwrites wtf
		newstr = realloc (str, slen + klen + 1);
		if (!newstr) {
			eprintf ("realloc fail\n");
			free (str);
			free (scnd);
			str = NULL;
			break;
		}
		str = newstr;
		p = str + off;
		memcpy (p, val, vlen);
		memcpy (p + vlen, scnd, strlen (scnd) + 1);
		i = off + vlen;
		free (scnd);
		if (!g) {
			break;
		}
	}
	return str;
}

/* replace the key in str with val.
 *
 * str - input string
 * clean - input string cleaned of ANSI chars
 * thunk - array of integers that map each char of the clean string into the
 *         position in the str string
 * clen  - number of elements in thunk
 * key   - string to find in the clean string
 * val   - string that replaces key in the str string
 * g     - if true, replace all occurences of key
 *
 * It returns a pointer to the modified string */
R_API char* r_str_replace_thunked(char *str, char *clean, int *thunk, int clen,
				  const char *key, const char *val, int g) {
	int i, klen, vlen, slen, delta = 0, bias;
	char *newstr, *scnd, *p = clean, *str_p;

	if (!str || !key || !val || !clean || !thunk) {
		return NULL;
	}
	klen = strlen (key);
	vlen = strlen (val);
	if (klen == vlen && !strcmp (key, val)) {
		return str;
	}
	slen = strlen (str) + 1;

	for (i = 0; i < clen; ) {
		int newo;
		bias = 0;
		p = (char *)r_mem_mem (
			(const ut8*)clean + i, clen - i,
			(const ut8*)key, klen);
		if (!p) {
			break;
		}
		i = (int)(size_t)(p - clean);
		/* as the original string changes size during replacement
		 * we need delta to keep track of it*/
		str_p = str + thunk[i] + delta;

		newo = thunk[i + klen] - thunk[i];
		r_str_ansi_filter(str_p, NULL, NULL, newo);
		scnd = strdup (str_p + newo);
		bias = vlen - newo;

		slen += bias;
		// HACK: this 32 avoids overwrites wtf
		newstr = realloc (str, slen + klen);
		if (!newstr) {
			eprintf ("realloc fail\n");
			free (str);
			free (scnd);
			str = NULL;
			break;
		}
		str = newstr;
		str_p = str + thunk[i] + delta;
		memcpy (str_p, val, vlen);
		memcpy (str_p + vlen, scnd, strlen (scnd) + 1);
		i += klen;
		delta += bias;
		free (scnd);
		if (!g) {
			break;
		}
	}
	return str;
}

R_API char *r_str_replace_in(char *str, ut32 sz, const char *key, const char *val, int g) {
	char *heaped;
	if (!str || !key || !val) {
		return NULL;
	}
	heaped = r_str_replace (strdup (str), key, val, g);
	strncpy (str, heaped, sz);
	free (heaped);
	return str;
}

R_API char *r_str_clean(char *str) {
	int len;
	char *ptr;
	if (str) {
		while (*str && iswhitechar (*str)) {
			str++;
		}
		if ((len = strlen (str)) > 0 )
			for (ptr = str + len - 1; ptr != str; ptr = ptr - 1) {
				if (iswhitechar (*ptr)) {
					*ptr = '\0';
				} else {
					break;
				}
			}
	}
	return str;
}

R_API int r_str_unescape(char *buf) {
	unsigned char ch = 0, ch2 = 0;
	int err = 0;
	int i;

	for (i = 0; buf[i]; i++) {
		if (buf[i] != '\\') {
			continue;
		}
		if (buf[i+1] == 'e') {
			buf[i] = 0x1b;
			memmove (buf + i + 1, buf + i + 2, strlen (buf + i + 2) + 1);
		} else if (buf[i + 1] == '\\') {
			buf[i] = '\\';
			memmove (buf + i + 1, buf + i + 2, strlen (buf + i + 2) + 1);
		} else if (buf[i+1] == 'r') {
			buf[i] = 0x0d;
			memmove (buf + i + 1, buf + i + 2, strlen (buf + i + 2) + 1);
		} else if (buf[i+1] == 'n') {
			buf[i] = 0x0a;
			memmove (buf + i + 1, buf + i + 2, strlen (buf + i + 2) + 1);
		} else if (buf[i + 1] == 'x') {
			err = ch2 = ch = 0;
			if (!buf[i + 2] || !buf[i + 3]) {
				eprintf ("Unexpected end of string.\n");
				return 0;
			}
			err |= r_hex_to_byte (&ch,  buf[i + 2]);
			err |= r_hex_to_byte (&ch2, buf[i + 3]);
			if (err) {
				eprintf ("Error: Non-hexadecimal chars in input.\n");
				return 0; // -1?
			}
			buf[i] = (ch << 4) + ch2;
			memmove (buf + i + 1, buf + i + 4, strlen (buf + i + 4) + 1);
		} else {
			eprintf ("'\\x' expected.\n");
			return 0; // -1?
		}
	}
	return i;
}

R_API void r_str_sanitize(char *c) {
	char *d = c;
	if (d)  {
		for (; *d; c++, d++) {
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
}

/* Internal function. dot_nl specifies wheter to convert \n into the
 * graphiz-compatible newline \l */
static char *r_str_escape_(const char *buf, const int dot_nl) {
	char *new_buf, *q;
	const char *p;

	if (!buf) {
		return NULL;
	}
	/* Worst case scenario, we convert every byte */
	new_buf = malloc (1 + (strlen (buf) * 4));
	if (!new_buf) {
		return NULL;
	}
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
			if (*p == '\0') {
				goto out;
			}
			if (*p == '[') {
				for (p++; *p != 'm'; p++) {
					if (*p == '\0') {
						goto out;
					}
				}
			}
			break;
		default:
			/* Outside the ASCII printable range */
			if (!IS_PRINTABLE (*p)) {
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
out:
	*q = '\0';
	return new_buf;
}

R_API char *r_str_escape(const char *buf) {
	return r_str_escape_ (buf, false);
}

R_API char *r_str_escape_dot(const char *buf) {
	return r_str_escape_ (buf, true);
}

/* ansi helpers */
R_API int r_str_ansi_len(const char *str) {
	int ch, ch2, i = 0, len = 0, sub = 0;
	while (str[i]) {
		ch = str[i];
		ch2 = str[i + 1];
		if (ch == 0x1b) {
			if (ch2 == '\\') {
				i++;
			} else if (ch2 == ']') {
				if (!strncmp (str + 2 + 5, "rgb:", 4)) {
					i += 18;
				}
			} else if (ch2 == '[') {
				for (++i; str[i] && str[i] != 'J' && str[i] != 'm' && str[i] != 'H'; i++);
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
		}
		i++;
	}
	return len - sub;
}


/* suposed to chop a string with ansi controls to
 * max length of n. */
R_API int r_str_ansi_chop(char *str, int str_len, int n) {
	char ch, ch2;
	int back = 0, i = 0, len = 0;
	if (!str) {
		return 0;
	}
	/* simple case - no need to cut */
	if (str_len < 0) {
		str_len = strlen (str);
	}
	if (n >= str_len) {
		str[str_len] = 0;
		return str_len;
	}
	while ((i < str_len) && str[i] && len < n && n > 0) {
		ch = str[i];
		ch2 = str[i + 1];
		if (ch == 0x1b) {
			if (ch2 == '\\') {
				i++;
			} else if (ch2 == ']') {
				if (!strncmp (str + 2 + 5, "rgb:", 4)) {
					i += 18;
				}
			} else if (ch2 == '[') {
				for (++i; (i < str_len) && str[i]
					     && str[i]!='J' && str[i]!='m'
					     && str[i]!='H';
				     i++);
			}
		} else if ((str[i] & 0xc0) != 0x80) {
			len++;
		}
		i++;
		back = i; 	/* index in the original array */
	}
	str[back] = 0;
	return back;
}

R_API int r_str_nlen(const char *str, int n) {
	int len = 0;
	if (str) {
		while (*str && n > 0) {
			len++;
			str++;
			n--;
		}
	}
	return len;
}

//to handle wide string as well
//XXX can be error prone
R_API int r_str_nlen_w(const char *str, int n) {
	int len = 0;
	if (str) {
		while (*str && n > 0) {
			len++;
			str++;
			if (!*str) {
				//handle wide strings
			 	//xx00yy00bb00
				if (n - 2 > 0) {
					if (str[2]) {
						break;
					}
				}
				str++;
			}
			n--;
		}
	}
	return len;
}

R_API int r_str_is_printable(const char *str) {
	while (*str) {
		if (!IS_PRINTABLE (*str)) {
			return 0;
		}
		str++;
	}
	return 1;
}

// Length in chars of a wide string (find better name?)
R_API int r_wstr_clen (const char *s) {
	int len = 0;
	if (!*s++) {
		return 0;
	}
	while (*s++ || *s++) {
		len++;
	}
	return len + 1;
}

R_API const char *r_str_ansi_chrn(const char *str, int n) {
	int len, i, li;
	for (li = i = len = 0; str[i] && (n!=len); i++) {
		if (str[i] == 0x1b && str[i + 1] == '[') {
			for (++i; str[i] && str[i] != 'J' && str[i] != 'm' && str[i] != 'H'; i++);
		} else {
			if ((str[i] & 0xc0) != 0x80) {
				len++;
			}
			li = i;
		}
	}
	return str + li;
}

/*
 * filter out ansi CSI shit in-place!.
 * str - input string,
 * out - if not NULL write a pointer to the original string there,
 * cposs - if not NULL write a pointer to thunk array there
 * (*cposs)[i] is the offset of the out[i] in str
 * len - lenght of str
 *
 * it returns the number of normal characters found in str
 */
R_API int r_str_ansi_filter(char *str, char **out, int **cposs, int len) {
	int i, j, *cps;
	char *tmp;

	if (len < 1) {
		len = strlen (str);
	}
	tmp = malloc (len + 1);
	if (!tmp) {
		return -1;
	}
	memcpy (tmp, str, len + 1);
	cps = calloc (len, sizeof (int));
	if (!cps) {
		free (tmp);
		return -1;
	}

	for (i = j = 0; i < len; i++) {
		if ((i + 1) < len && tmp[i] == 0x1b && tmp[i + 1] == '[') {
			for (i += 2; i < len && str[i] != 'J'
				     && str[i] != 'm' && str[i] != 'H'; i++);
		} else {
			str[j] = tmp[i];
			cps[j] = i;
			j++;
		}
	}
	str[j] = tmp[i];

	if (out) {
		*out = tmp;
	} else {
		free (tmp);
	}

	if (cposs) {
		*cposs = cps;
	} else {
		free (cps);
	}

	return j;
}

R_API char *r_str_ansi_crop(const char *str, unsigned int x, unsigned int y,
		unsigned int x2, unsigned int y2) {
	char *r, *r_end, *ret;
	const char *s;
	size_t r_len, str_len = 0, nr_of_lines = 0;
	unsigned int ch = 0, cw = 0;
	if (x2 < 1 || y2 < 1 || !str) {
		return strdup ("");
	}
	s = str;
	while (*s) {
		str_len++;
		if (*s == '\n') {
			nr_of_lines++;
		}
		s++;
	}
	r_len = str_len + nr_of_lines * strlen (Color_RESET) + 1;
	r = ret = malloc (r_len);
	r_end = r + r_len;
	while (*str) {
		/* crop height */
		if (ch >= y2) {
			r--;
			break;
		}

		if (*str == '\n') {
			if (ch >= y && ch < y2) {
				const char *reset = Color_RESET "\n";
				if (strlen (reset) < (r_end - r)) {
					memcpy (r, reset, strlen (reset) + 1);
					r += strlen (reset);
				}
			}
			str++;
			ch++;
			cw = 0;
		} else if (*str == 0x1b && str + 1 && *(str + 1) == '[') {
			const char *ptr;

			/* copy 0x1b and [ */
			*r++ = *str++;
			*r++ = *str++;
			for (ptr = str; *ptr && *ptr != 'J' && *ptr != 'm' && *ptr != 'H'; ++ptr) {
				*r++ = *ptr;
			}
			*r++ = *ptr++;
			str = ptr;
		} else {
			if (ch >= y && ch < y2 && cw >= x && cw < x2) {
				*r++ = *str;
			}

			/* skip until newline */
			if (cw >= x2) {
				while (*str && *str != '\n') {
					str++;
				}
			} else {
				str++;
			}
			cw++;
		}
	}
	*r = 0;
	return ret;
}

R_API void r_str_filter_zeroline(char *str, int len) {
	int i;
	for (i = 0; i < len && str[i]; i++) {
		if (str[i] == '\n' || str[i] == '\r') {
			break;
		}
		if (!IS_PRINTABLE (str[i])) {
			break;
		}
	}
	str[i] = 0;
}

R_API void r_str_filter(char *str, int len) {
	int i;
	if (len < 1) {
		len = strlen (str);
	}
	for (i = 0; i < len; i++) {
		if (!IS_PRINTABLE (str[i])) {
			str[i] = '.';
		}
	}
}

R_API bool r_str_glob (const char* str, const char *glob) {
	const char* cp = NULL, *mp = NULL;
	if (!glob || !strcmp (glob, "*")) {
		return true;
	}
	while ((*str) && (*glob != '*')) {
		if ((*glob != *str)) {
			return false;
		}
		++glob;
		++str;
	}
	while (*str) {
		if (*glob == '*') {
			if (!*++glob) {
				return true;
			}
			mp = glob;
			cp = str+1;
		} else if (*glob == *str) {
			++glob;
			++str;
		} else {
			glob = mp;
			str = cp++;
		}
	}
	while (*glob == '*') {
		++glob;
	}
	return (*glob == '\x00');
}

// Escape the string arg so that it is parsed as a single argument by r_str_argv
R_API char *r_str_arg_escape (const char *arg) {
	char *str;
	int dest_i = 0, src_i = 0;
	if (!arg) {
		return NULL;
	}
	str = malloc ((2 * strlen (arg) + 1) * sizeof (char)); // Worse case when every character need to be escaped
	if (!str) {
		return NULL;
	}
	for (src_i = 0; arg[src_i] != '\0'; src_i++) {
		char c = arg[src_i];
		switch (c) {
		case '\'':
		case '"':
		case '\\':
		case ' ':
			str[dest_i++] = '\\';
			str[dest_i++] = c;
			break;
		default:
			str[dest_i++] = c;
			break;
		}
	}
	str[dest_i] = '\0';
	return realloc (str, (strlen(str)+1) * sizeof (char));
}

R_API char **r_str_argv(const char *cmdline, int *_argc) {
	int argc = 0;
	int argv_len = 128; // Begin with that, argv will reallocated if necessary
	char **argv;
	char *args; // Working buffer for writing unescaped args
	int cmdline_current = 0; // Current character index in _cmdline
	int args_current = 0; // Current character index in  args
	int arg_begin = 0; // Index of the first character of the current argument in args

	if (!cmdline) {
		return NULL;
	}

	argv = malloc (argv_len * sizeof (char *));
	args = malloc (128 + strlen (cmdline) * sizeof (char)); // Unescaped args will be shorter, so strlen (cmdline) will be enough
	do {
		// States for parsing args
		int escaped = 0;
		int singlequoted = 0;
		int doublequoted = 0;

		// Seek the beginning of next argument (skip whitespaces)
		while (cmdline[cmdline_current] != '\0' && iswhitechar (cmdline[cmdline_current])) {
			cmdline_current++;
		}

		if (cmdline[cmdline_current] == '\0') {
			break; // No more arguments
		}
		// Read the argument
		while (1) {
			char c = cmdline[cmdline_current];
			int end_of_current_arg = 0;
			if (escaped) {
				switch (c) {
				case '\'':
				case '"':
				case ' ':
				case '\\':
					args[args_current++] = c;
					break;
				case '\0':
					args[args_current++] = '\\';
					end_of_current_arg = 1;
					break;
				default:
					args[args_current++] = '\\';
					args[args_current++] = c;
				}
				escaped = 0;
			} else {
				switch (c) {
				case '\'':
					if (doublequoted) {
						args[args_current++] = c;
					} else {
						singlequoted = !singlequoted;
					}
					break;
				case '"':
					if (singlequoted) {
						args[args_current++] = c;
					} else {
						doublequoted = !doublequoted;
					}
					break;
				case '\\':
					escaped = 1;
					break;
				case ' ':
					if (singlequoted || doublequoted) {
						args[args_current++] = c;
					} else {
						end_of_current_arg = 1;
					}
					break;
				case '\0':
					end_of_current_arg = 1;
					break;
				default:
					args[args_current++] = c;
				}
			}
			if (end_of_current_arg) {
				break;
			}
			cmdline_current++;
		}
		args[args_current++] = '\0';
		argv[argc++] = strdup (&args[arg_begin]);
		if (argc >= argv_len) {
			argv_len *= 2;
			argv = realloc (argv, argv_len * sizeof (char *));
		}
		arg_begin = args_current;
	} while (cmdline[cmdline_current++] != '\0');
	argv[argc] = NULL;
	argv = realloc (argv, (argc+1) * sizeof (char *));
	if (_argc) {
		*_argc = argc;
	}
	free (args);
	return argv;
}

R_API void r_str_argv_free(char **argv) {
	// TODO: free the internal food or just the first element
//	free (argv[0]); // MEMORY LEAK
	int argc = 0;
	while (argv[argc]) {
		free (argv[argc++]);
	}
	free (argv);
}

R_API const char *r_str_lastbut (const char *s, char ch, const char *but) {
	int idx, _b = 0;
	ut8 *b = (ut8*)&_b;
	const char *isbut, *p, *lp = NULL;
	const int bsz = sizeof (_b);
	if (!but) {
		return r_str_lchr (s, ch);
	}
	if (strlen (but) >= bsz) {
		eprintf ("r_str_lastbut: but string too long\n");
		return NULL;
	}
	for (p = s; *p; p++) {
		isbut = strchr (but, *p);
		if (isbut) {
			idx = (int)(size_t)(isbut - but);
			_b = R_BIT_CHK (b, idx)?
				R_BIT_UNSET (b, idx):
				R_BIT_SET (b, idx);
			continue;
		}
		if (*p == ch && !_b) {
			lp = p;
		}
	}
	return lp;
}

// Must be merged inside strlen
R_API int r_str_len_utf8char (const char *s, int left) {
	int i = 1;
	while (s[i] && (!left || i<left)) {
		if ((s[i] & 0xc0) != 0x80) {
			i++;
		} else {
			break;
		}
	}
	return i;
}

R_API int r_str_len_utf8(const char *s) {
	int i = 0, j = 0;
	while (s[i]) {
		if ((s[i] & 0xc0) != 0x80) {
			j++;
		}
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
		if (!strncasecmp (a, b, needle_len)) {
			return (const char *) a;
		}
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
				for (; from <= to; from++) {
					cb (u, from);
				}
			} else {
				fprintf (stderr, "Invalid range\n");
			}
			for (r++; *r && *r!=','&& *r!='-'; r++);
			p = r;
		}
	}
	if (*p) {
		cb (u, atoi (p));
	}
}

// convert from html escaped sequence "foo%20bar" to "foo bar"
// TODO: find better name.. unencode? decode
R_API void r_str_uri_decode (char *s) {
	int n;
	char *d;
	for (d = s; *s; s++, d++) {
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
	if (!s) {
		return NULL;
	}
	od = d = malloc (1+(strlen (s)*4));
	if (!d) {
		return NULL;
	}
	for (; *s; s++) {
		if((*s>='0' && *s<='9')
		|| (*s>='a' && *s<='z')
		|| (*s>='A' && *s<='Z')) {
			*d++ = *s;
		} else {
			*d++ = '%';
			sprintf (ch, "%02x", 0xff & ((ut8)*s));
			*d++ = ch[0];
			*d++ = ch[1];
		}
	}
	*d = 0;
	return realloc (od, strlen (od)+1); // FIT
}

R_API int r_str_utf16_to_utf8 (ut8 *dst, int len_dst, const ut8 *src, int len_src, int little_endian) {
	ut8 *outstart = dst;
	const ut8 *processed = src;
	ut8 *outend = dst + len_dst;
	ut16 *in = (ut16*)src;
	ut16 *inend;
	ut32 c, d, inlen;
	ut8 *tmp;
	int bits;

	if ((len_src % 2) == 1) {
		len_src--;
	}
	inlen = len_src / 2;
	inend = in + inlen;
	while ((in < inend) && (dst - outstart + 5 < len_dst)) {
		if (little_endian) {
			c= *in++;
		} else {
			tmp = (ut8*) in;
			c = *tmp++;
			c = c | (((ut32)*tmp) << 8);
			in++;
		}
		if ((c & 0xFC00) == 0xD800) {    /* surrogates */
			if (in >= inend) {           /* (in > inend) shouldn't happens */
				break;
			}
			if (little_endian) {
				d = *in++;
			} else {
				tmp = (ut8*) in;
				d = *tmp++;
				d = d | (((ut32)*tmp) << 8);
				in++;
			}
			if ((d & 0xFC00) == 0xDC00) {
				c &= 0x03FF;
				c <<= 10;
				c |= d & 0x03FF;
				c += 0x10000;
			}
			else {
				len_dst = dst - outstart;
				len_src = processed - src;
				return -2;
			}
		}

		/* assertion: c is a single UTF-4 value */
		if (dst >= outend) {
			break;
		}
		if (c < 0x80) {
			*dst++ =  c; bits= -6;
		} else if (c < 0x800) {
			*dst++ = ((c >> 6) & 0x1F) | 0xC0;
			bits =  0;
		} else if (c < 0x10000) {
			*dst++ = ((c >> 12) & 0x0F) | 0xE0;
			bits =  6;
		} else {
			*dst++ = ((c >> 18) & 0x07) | 0xF0;
			bits = 12;
		}

		for (; bits >= 0; bits-= 6) {
			if (dst >= outend) {
				break;
			}
			*dst++ = ((c >> bits) & 0x3F) | 0x80;
		}
		processed = (const unsigned char*) in;
	}
	len_dst = dst - outstart;
	return len_dst;
}

R_API char *r_str_utf16_decode (const ut8 *s, int len) {
	int i = 0;
	int j = 0;
	char *result = NULL;
	int count_unicode = 0;
	int count_ascii = 0;
	int lenresult = 0;
	if (!s) {
		return NULL;
	}
	for (i = 0; i < len && (s[i] || s[i+1]); i += 2) {
		if (!s[i+1] && 0x20 <= s[i] && s[i] <= 0x7E) {
			++count_ascii;
		} else {
			++count_unicode;
		}
	}
	lenresult = 1 + count_ascii + count_unicode * 6; // len("\\uXXXX") = 6
	if (!(result = calloc (1 + count_ascii + count_unicode * 6, 1))) {
		return NULL;
	}
	for (i = 0; i < len && j < lenresult && (s[i] || s[i+1]); i += 2) {
		if (!s[i+1] && 0x20 <= s[i] && s[i] <= 0x7E) {
			result[j++] = s[i];
		} else {
			j += sprintf (&result[j], "\\u%.2hhx%.2hhx", s[i], s[i+1]);
		}
	}
	return result;
}

R_API char *r_str_utf16_encode (const char *s, int len) {
	int i;
	char ch[4], *d, *od, *tmp;
	if (!s) {
		return NULL;
	}
	if (len < 0) {
		len = strlen (s);
	}
	if ((len * 7) + 1 < len) {
		return NULL;
	}
	od = d = malloc (1 + (len * 7));
	if (!d) {
		return NULL;
	}
	for (i = 0; i < len; s++, i++) {
		if ((*s >= 0x20) && (*s <= 126)) {
			*d++ = *s;
		} else {
			*d++ = '\\';
			*d++ = '\\';
			*d++ = 'u';
			*d++ = '0';
			*d++ = '0';
			sprintf (ch, "%02x", 0xff & ((ut8)*s));
			*d++ = ch[0];
			*d++ = ch[1];
		}
	}
	*d = 0;
	tmp = realloc (od, strlen (od)+1); // FIT
	if (!tmp) {
		free (od);
		return NULL;
	}
	return tmp;
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

	while (*arg && iswhitechar (*arg)) {
		arg++;
	}
	/* get times */
	times = atoi (arg);
	if (times > 0) {
		while ((*arg>='0'&&*arg<='9')) arg++;
	}
	bracket = strchr (arg,'{');
	if (bracket) {
		char *end = strchr (arg,'}');
		if (!end) {
			eprintf ("No end bracket. Try pm {ecx}b @ esi\n");
			return 0;
		}
		*end='\0';
		times = r_num_math (NULL, bracket+1);
		arg = end + 1;
	}

	if (*arg == '\0') {
		return 0;
	}
	/* get args */
	args = strchr (arg, ' ');
	if (args) {
		int l = 0, maxl = 0;
		argend = args;
		args = strdup (args+1);
		nargs = r_str_word_set0 (args+1);
		if (!nargs) {
			R_FREE (args);
		}
		for (i = 0; i<nargs; i++) {
			int len = strlen (r_str_word_get0 (args + 1, i));
			if (len > maxl) {
				maxl = len;
			}
		}
		l++;
		snprintf (namefmt, sizeof (namefmt), "%%%ds : ", maxl);
	}

	/* go format */
	i = 0;
	if (!times) {
		times = 1;
	}
	for (; times; times--) { // repeat N times
		const char * orig = arg;
		arg = orig;
		for (idx = 0; arg < argend && *arg; idx++, arg++) {
			tmp = *arg;
		feed_me_again:
			if (!tmp && last != '*') {
				break;
			}
			/* skip chars */
			switch (tmp) {
			case '*':
				if (i <= 0) {
					break;
				}
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
				tmp = (sizeof (void*) == 8)? 'q': 'x';
				break;
			case '?': // help
				idx--;
				free (args);
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
		for (p = s; *p; p++)  {
			if (*p == '\n') {
				newlines++;
			}
		}
		o = malloc (len + (plen*newlines) + 1);
		memcpy (o, pfx, plen);
		for (p=o + plen; *s; s++) {
			*p++ = *s;
			if (*s == '\n' && s[1]) {
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
	ut32 pos = 0;
	if (string && *string) {
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
				return;
			}
		}
	}
}

R_API const char *r_str_closer_chr (const char *b, const char *s) {
	const char *a;
	while (*b) {
		for (a = s; *a; a++) {
			if (*b == *a) {
				return b;
			}
		}
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
				if (cw > W) {
					W = cw;
				}
				*str = '\n';
				cw = 0;
				ptr = str;
			}
			str++;
			cw++;
		}
		if (*str == '\n') {// skip last newline
			H--;
		}
		if (h) {
			*h = H;
		}
		free (ostr);
	}
	return W;
}
#endif

/* crop a string like it is in a rectangle with the upper-left corner at (x, y)
 * coordinates and the bottom-right corner at (x2, y2) coordinates. The result
 * is a newly allocated string, that should be deallocated by the user */
R_API char *r_str_crop(const char *str, unsigned int x, unsigned int y,
		unsigned int x2, unsigned int y2) {
	char *r, *ret;
	unsigned int ch = 0, cw = 0;
	if (x2 < 1 || y2 < 1 || !str) {
		return strdup ("");
	}
	r = ret = strdup (str);
	while (*str) {
		/* crop height */
		if (ch >= y2) {
			r--;
			break;
		}

		if (*str == '\n') {
			if (ch >= y && ch < y2) {
				*r++ = *str;
			}
			str++;
			ch++;
			cw = 0;
		} else {
			if (ch >= y && ch < y2 && cw >= x && cw < x2) {
				*r++ = *str;
			}
			/* crop width */
			/* skip until newline */
			if (cw >= x2) {
				while (*str && *str != '\n') {
					str++;
				}
			} else {
				str++;
			}
			cw++;
		}
	}
	*r = 0;
	return ret;
}

R_API const char * r_str_tok(const char *str1, const char b, size_t len) {
	const char *p = str1;
	size_t i = 0;
	if (!p || !*p) {
		return p;
	}
	if (len == -1) {
		len = strlen (str1);
	}
	for ( ; i < len; i++,p++) {
		if (*p == b) {
			break;
		}
	}
	if (i == len) {
		p = NULL;
	}
	return p;
}

R_API int r_str_do_until_token(str_operation op, char *str, const char tok) {
	int ret;
	if (!str) {
		return -1;
	}
	if (!op) {
		for (ret = 0; (str[ret] != tok) && str[ret]; ret++) {
			//empty body
		}
	} else {
		for (ret = 0; (str[ret] != tok) && str[ret]; ret++) {
			op (str + ret);
		}
	}
	return ret;
}

R_API const char *r_str_pad(const char ch, int sz) {
	static char pad[1024];
	if (sz < 0) {
		sz = 0;
	}
	memset (pad, ch, R_MIN (sz, sizeof (pad)));
	if (sz < sizeof (pad)) {
		pad[sz] = 0;
	}
	pad[sizeof(pad) - 1] = 0;
	return pad;
}

static char **consts = NULL;

R_API const char *r_str_const(const char *ptr) {
	int ctr = 0;
	if (consts) {
		const char *p;
		while ((p = consts[ctr])) {
			if (ptr == p || !strcmp (ptr, p)) {
				return p;
			}
			ctr ++;
		}
		consts = realloc (consts, (2+ctr) * sizeof(void*));
	} else {
		consts = malloc (sizeof (void*) * 2);
	}
	consts[ctr] = strdup (ptr);
	consts[ctr+1] = NULL;
	return consts[ctr];
}

R_API void r_str_const_free() {
	int i;
	if (consts) {
		for (i = 0; consts[i]; i++) {
			free (consts[i]);
		}
		R_FREE (consts);
	}
}

R_API char *r_str_between(const char *cmt, const char *prefix, const char *suffix) {
	char *c0, *c1;
	if (!cmt || !prefix || !suffix || !*cmt) {
		return NULL;
	}
	c0 = strstr (cmt, prefix);
	if (c0) {
		c1 = strstr (c0 + strlen (prefix), suffix);
		if (!c1) {
			return r_str_ndup (c0 + strlen (prefix), (c1 - c0 - strlen (prefix)));
		}
	}
	return NULL;
}

R_API bool r_str_startswith(const char *str, const char *needle) {
	return !strncmp (str, needle, strlen (needle));
}

R_API bool r_str_endswith(const char *str, const char *needle) {
	int slen = strlen (str);
	int nlen = strlen (needle);
	if (!slen || !nlen || slen < nlen) {
		return false;
	}
	return !strcmp (str + (slen - nlen), needle);
}

/* radare - LGPL - Copyright 2007-2020 - pancake */

#include "r_types.h"
#include "r_util.h"
#include "r_cons.h"
#include "r_bin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <r_util/r_base64.h>

/* stable code */
static const char *nullstr = "";
static const char *nullstr_c = "(null)";
static const char *rwxstr[] = {
	[0] = "---",
	[1] = "--x",
	[2] = "-w-",
	[3] = "-wx",
	[4] = "r--",
	[5] = "r-x",
	[6] = "rw-",
	[7] = "rwx",

	[8] = "---",
	[9] = "--x",
	[10] = "-w-",
	[11] = "-wx",
	[12] = "r--",
	[13] = "r-x",
	[14] = "rw-",
	[15] = "rwx",
};

R_API int r_str_casecmp(const char *s1, const char *s2) {
#ifdef _MSC_VER
	return stricmp (s1, s2);
#else
	return strcasecmp (s1, s2);
#endif
}

R_API int r_str_ncasecmp(const char *s1, const char *s2, size_t n) {
#ifdef _MSC_VER
	return _strnicmp (s1, s2, n);
#else
	return strncasecmp (s1, s2, n);
#endif
}

// GOOD
// In-place replace the first instance of the character a, with the character b.
R_API int r_str_replace_ch(char *s, char a, char b, bool global) {
	int ret = 0;
	char *o = s;
	if (!s || a == b) {
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
			if (!global) {
				return 1;
			}
		} else {
			*s = *o;
		}
	}
	*s = 0;
	return ret;
}

R_API int r_str_replace_char_once(char *s, int a, int b) {
	return r_str_replace_ch (s, a, b, false);
}

R_API int r_str_replace_char(char *s, int a, int b) {
	return r_str_replace_ch (s, a, b, true);
}

R_API void r_str_remove_char(char *str, char c) {
	while (*str) {
		if (*str == c) {
			memmove (str, str + 1, strlen (str + 1) + 1);
			continue;
		}
		str++;
	}
}

R_API void r_str_reverse(char *str) {
	int i, len = strlen (str);
	int half = len / 2;
	for (i = 0; i < half; i++) {
		char ch = str[i];
		str[i] = str[len - i - 1];
		str[len - i - 1] = ch;
	}
}

// TODO: do not use toupper.. must support modes to also append lowercase chars like in r1
// TODO: this functions needs some stabilization
R_API int r_str_bits(char *strout, const ut8 *buf, int len, const char *bitz) {
	int i, j, idx;
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
			idx = (i / 8);
			int bit = 7 - (i % 8);
			strout[j++] = (buf[idx] & (1 << bit))? '1' : '0';
		}
	}
	strout[j] = 0;
	return j;
}

R_API const char *r_str_sysbits(const int v) {
	switch (v) {
	case R_SYS_BITS_8: return "8";
	case R_SYS_BITS_16: return "16";
	case R_SYS_BITS_32: return "32";
	case R_SYS_BITS_64: return "64";
	case R_SYS_BITS_16 | R_SYS_BITS_32: return "16,32";
	case R_SYS_BITS_16 | R_SYS_BITS_32 | R_SYS_BITS_64: return "16,32,64";
	case R_SYS_BITS_32 | R_SYS_BITS_64: return "32,64";
	}
	return "?";
}

// In-place trims a bitstring to groups of 8 bits.
// For example, the bitstring 1000000000000000 will not be modified, but the
// bitstring 0000000001000000 will be changed to 01000000.
static void trimbits(char *b) {
	const int len = strlen (b);
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
	for (i = (sizeof (in) * 8) - 1; i >= 0; i--) {
		bit = in >> i;
		if (bit & 1) {
			strout[count] = '1';
		} else {
			strout[count] = '0';
		}
		count++;
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
	/* return the numeric value associated to a string (rflags) */
	for (; *buf; buf++) {
		char *ch = strchr (bitz, toupper ((const unsigned char)*buf));
		if (!ch) {
			ch = strchr (bitz, tolower ((const unsigned char)*buf));
		}
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

// If up is true, upcase all characters in the string, otherwise downcase all
// characters in the string.
R_API void r_str_case(char *str, bool up) {
	if (up) {
		char oc = 0;
		for (; *str; oc = *str++) {
			*str = (*str=='x' && oc=='0') ? 'x': toupper ((int)(ut8)*str);
		}
	} else {
		for (; *str; str++) {
			*str = tolower ((int)(ut8)*str);
		}
	}
}

R_API char *r_str_home(const char *str) {
	char *dst, *home = r_sys_getenv (R_SYS_HOME);
	size_t length;
	if (!home) {
		home = r_file_tmpdir ();
		if (!home) {
			return NULL;
		}
	}
	length = strlen (home) + 1;
	if (str) {
		length += strlen (R_SYS_DIR) + strlen (str);
	}
	dst = (char *)malloc (length);
	if (!dst) {
		goto fail;
	}
	int home_len = strlen (home);
	memcpy (dst, home, home_len + 1);
	if (str) {
		dst[home_len] = R_SYS_DIR[0];
		strcpy (dst + home_len + 1, str);
	}
fail:
	free (home);
	return dst;
}

R_API char *r_str_r2_prefix(const char *str) {
	return r_str_newf ("%s%s%s", r_sys_prefix (NULL), R_SYS_DIR, str);
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
R_API ut32 r_str_hash(const char *s) {
	return (ut32) r_str_hash64 (s);
}

R_API int r_str_delta(char *p, char a, char b) {
	char *_a = strchr (p, a);
	char *_b = strchr (p, b);
	return (!_a || !_b)? 0 : (_a - _b);
}

// In-place split string using ch as a delimiter. Replaces all instances of ch
// with a null byte. Returns the number of split strings. For example
// r_str_split("hello world", ' ') will replace the space with '\0' and
// return 2.
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
			char *q = p - 1;
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
			memmove (str + i, str + i + 1, strlen (str + i));
			i--;
		}
		if (i == 0 && str[i] == ' ') {
			memmove (str + i, str + i + 1, strlen (str + i));
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
	if (!stra && !newstr) {
		return NULL;
	}
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
	alen = (size_t)(p - stra);
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
	for (i = 0; i != idx; i++) {
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

// Counts the number of words (separated by separator characters: newlines, tabs,
// return, space). See r_util.h for more details of the IS_SEPARATOR macro.
R_API int r_str_word_count(const char *string) {
	const char *text, *tmp;
	int word;

	for (text = tmp = string; *text && IS_SEPARATOR (*text); text++) {
		;
	}
	for (word = 0; *text; word++) {
		for (; *text && !IS_SEPARATOR (*text); text++) {
			;
		}
		for (tmp = text; *text && IS_SEPARATOR (*text); text++) {
			;
		}
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
		for (; len >= 0; len--) {
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
	while (str[start] != chr && start < end) {
		start++;
	}
	return str[start] == chr ? str + start : NULL;
}

R_API const char *r_str_sep(const char *base, const char *sep) {
	int i;
	while (*base) {
		for (i = 0; sep[i]; i++) {
			if (*base == sep[i]) {
				return base;
			}
		}
		base++;
	}
	return NULL;
}

R_API const char *r_str_rsep(const char *base, const char *p, const char *sep) {
	int i;
	while (p >= base) {
		for (i = 0; sep[i]; i++) {
			if (*p == sep[i]) {
				return p;
			}
		}
		p--;
	}
	return NULL;
}

R_API const char *r_str_rstr(const char *base, const char *p) {
	char *s = strdup (base);
	char *k = strdup (p);
	r_str_reverse (s);
	r_str_reverse (k);
	char *q = strstr (s, k);
	const char *r = NULL;
	if (q) {
		r = base + strlen (base) - (q - s) - strlen (p);
	}
	free (s);
	free (k);
	return r;
}

R_API const char *r_str_rchr(const char *base, const char *p, int ch) {
	r_return_val_if_fail (base, NULL);
	if (!p) {
		return strrchr (base, ch);
	}
	for (; p >= base; p--) {
		if (ch == *p) {
			break;
		}
	}
	return (p >= base) ? p: NULL;
}

R_API const char *r_str_nstr(const char *s, const char *find, int slen) {
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen (find);
		do {
			do {
				if (slen-- < 1 || !(sc = *s++)) {
					return NULL;
				}
			} while (sc != c);
			if (len > slen) {
				return NULL;
			}
		} while (strncmp (s, find, len) != 0);
		s--;
	}
	return (char *)s;
}

// Returns a new heap-allocated copy of str.
// XXX what's the diff with r_str_dup ?
R_API char *r_str_new(const char *str) {
	return str? strdup (str): NULL;
}

// Returns a new heap-allocated copy of str, sets str[len] to '\0'.
// If the input str is longer than len, it will be truncated.
R_API char *r_str_newlen(const char *str, int len) {
	if (len < 1) {
		return NULL;
	}
	char *buf = malloc (len + 1);
	if (buf) {
		memcpy (buf, str, len);
		buf[len] = 0;
	}
	return buf;
}

R_API char *r_str_trunc_ellipsis(const char *str, int len) {
	if (!str) {
		return NULL;
	}
	if (strlen (str) < len) {
		return strdup (str);
	}
	char *buf = r_str_newlen (str, len);
	if (buf && len > 4) {
		strcpy (buf + len - 4, "...");
	}
	return buf;
}

R_API char *r_str_newf(const char *fmt, ...) {
	va_list ap, ap2;

	va_start (ap, fmt);
	if (!strchr (fmt, '%')) {
		va_end (ap);
		return strdup (fmt);
	}
	va_copy (ap2, ap);
	int ret = vsnprintf (NULL, 0, fmt, ap2);
	ret++;
	char *p = calloc (1, ret);
	if (p) {
		(void)vsnprintf (p, ret, fmt, ap);
	}
	va_end (ap2);
	va_end (ap);
	return p;
}

// Secure string copy with null terminator (like strlcpy or strscpy but ours
R_API size_t r_str_ncpy(char *dst, const char *src, size_t n) {
	size_t i;

	// do not do anything if n is 0
	if (n == 0) {
		return 0;
	}

	n--;
	for (i = 0; src[i] && n > 0; i++, n--) {
		dst[i] = src[i];
	}
	dst[i] = 0;
	return i;
}

/* memccmp("foo.bar", "foo.cow, '.') == 0 */
// Returns 1 if src and dst are equal up until the first instance of ch in src.
R_API bool r_str_ccmp(const char *dst, const char *src, int ch) {
	int i;
	for (i = 0; src[i] && src[i] != ch; i++) {
		if (dst[i] != src[i]) {
			return true;
		}
	}
	return false;
}

// Returns true if item is in sep-separated list
R_API bool r_str_cmp_list(const char *list, const char *item, char sep) {
	if (!list || !item) {
		return false;
	}
	int i = 0, j = 0;
	for (; list[i] && list[i] != sep; i++, j++) {
		if (item[j] != list[i]) {
			while (list[i] && list[i] != sep) {
				i++;
			}
			if (!list[i]) {
				return false;
			}
			j = -1;
			continue;
		}
	}
	return true;
}

// like strncmp, but checking for null pointers
R_API int r_str_cmp(const char *a, const char *b, int len) {
	if ((a == b) || (!a && !b)) {
		return 0;
	}
	if (!a && b) {
		return -1;
	}
	if (a && !b) {
		return 1;
	}
	if (len < 0) {
		return strcmp (a, b);
	}
	return strncmp (a, b, len);
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
	for (; *text && IS_SEPARATOR (*text); text++) {
		;
	}
	return strdup (text);
}

R_API const char *r_str_get(const char *str) {
	return str? str: nullstr_c;
}

R_API const char *r_str_get2(const char *str) {
	return str? str: nullstr;
}

R_API char *r_str_ndup(const char *ptr, int len) {
	if (len < 0) {
		return NULL;
	}
	char *out = malloc (len + 1);
	if (!out) {
		return NULL;
	}
	strncpy (out, ptr, len);
	out[len] = 0;
	return out;
}

// TODO: deprecate?
R_API char *r_str_dup(char *ptr, const char *string) {
	free (ptr);
	return r_str_new (string);
}

R_API char *r_str_prepend(char *ptr, const char *string) {
	int slen, plen;
	if (!ptr) {
		return strdup (string);
	}
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

R_API char *r_str_appendlen(char *ptr, const char *string, int slen) {
	char *msg = r_str_newlen (string, slen);
	char *ret = r_str_append (ptr, msg);
	free (msg);
	return ret;
}

R_API char *r_str_append_owned(char *ptr, char *string) {
	if (!ptr) {
		return string;
	}
	char *r = r_str_append(ptr, string);
	free (string);
	return r;
}
/*
 * first argument must be allocated
 * return: the pointer ptr resized to string size.
 */
R_API char *r_str_append(char *ptr, const char *string) {
	if (string && !ptr) {
		return strdup (string);
	}
	if (R_STR_ISEMPTY (string)) {
		return ptr;
	}
	int plen = strlen (ptr);
	int slen = strlen (string);
	char *newptr = realloc (ptr, slen + plen + 1);
	if (!newptr) {
		free (ptr);
		return NULL;
	}
	ptr = newptr;
	memcpy (ptr + plen, string, slen + 1);
	return ptr;
}

R_API char *r_str_appendf(char *ptr, const char *fmt, ...) {
	va_list ap, ap2;

	va_start (ap, fmt);
	if (!strchr (fmt, '%')) {
		va_end (ap);
		return r_str_append (ptr, fmt);
	}
	va_copy (ap2, ap);
	int ret = vsnprintf (NULL, 0, fmt, ap2);
	ret++;
	char *p = calloc (1, ret);
	if (p) {
		(void)vsnprintf (p, ret, fmt, ap);
		ptr = r_str_append (ptr, p);
		free (p);
	}
	va_end (ap2);
	va_end (ap);
	return ptr;
}

R_API char *r_str_appendch(char *x, char y) {
	char b[2] = { y, 0 };
	return r_str_append (x, b);
}

R_API char* r_str_replace(char *str, const char *key, const char *val, int g) {
	if (g == 'i') {
		return r_str_replace_icase (str, key, val, g, true);
	}
	r_return_val_if_fail (str && key && val, NULL);

	int off, i, slen;
	char *newstr, *p = str;
	int klen = strlen (key);
	int vlen = strlen (val);
	if (klen == 1 && vlen < 2) {
		r_str_replace_char (str, *key, *val);
		return str;
	}
	if (klen == vlen && !strcmp (key, val)) {
		return str;
	}
	slen = strlen (str);
	char *q = str;
	for (;;) {
		p = strstr (q, key);
		if (!p) {
			break;
		}
		off = (int)(size_t)(p - str);
		if (vlen != klen) {
			int tlen = slen - (off + klen);
			slen += vlen - klen;
			if (vlen > klen) {
				newstr = realloc (str, slen + 1);
				if (!newstr) {
					eprintf ("realloc fail\n");
					R_FREE (str);
					break;
				}
				str = newstr;
			}
			p = str + off;
			memmove (p + vlen, p + klen, tlen + 1);
		}
		memcpy (p, val, vlen);
		i = off + vlen;
		q = str + i;
		if (!g) {
			break;
		}
	}
	return str;
}

R_API char *r_str_replace_icase(char *str, const char *key, const char *val, int g, int keep_case) {
	r_return_val_if_fail (str && key && val, NULL);

	int off, i, klen, vlen, slen;
	char *newstr, *p = str;
	klen = strlen (key);
	vlen = strlen (val);

	slen = strlen (str);
	for (i = 0; i < slen;) {
		p = (char *)r_str_casestr (str + i, key);
		if (!p) {
			break;
		}
		off = (int)(size_t) (p - str);
		if (vlen != klen) {
			int tlen = slen - (off + klen);
			slen += vlen - klen;
			if (vlen > klen) {
				newstr = realloc (str, slen + 1);
				if (!newstr) {
					goto alloc_fail;
				}
				str = newstr;
			}
			p = str + off;
			memmove (p + vlen, p + klen, tlen + 1);
		}

		if (keep_case) {
			char *tmp_val = strdup (val);
			char *str_case = r_str_ndup (p, klen);
			if (!tmp_val || !str_case) {
				free (tmp_val);
				free (str_case);
				goto alloc_fail;
			}
			tmp_val = r_str_replace_icase (tmp_val, key, str_case, 0, 0);
			free (str_case);
			if (!tmp_val) {
				goto alloc_fail;
			}
			memcpy (p, tmp_val, vlen);
			free (tmp_val);
		} else {
			memcpy (p, val, vlen);
		}

		i = off + vlen;
		if (!g) {
			break;
		}
	}
	return str;

alloc_fail:
	eprintf ("alloc fail\n");
	free (str);
	return NULL;
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
 * g     - if true, replace all occurrences of key
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

		int newo = thunk[i + klen] - thunk[i];
		r_str_ansi_filter (str_p, NULL, NULL, newo);
		scnd = strdup (str_p + newo);
		bias = vlen - newo;

		slen += bias;
		// HACK: this 32 avoids overwrites wtf
		newstr = realloc (str, slen + klen);
		if (!newstr) {
			eprintf ("realloc fail\n");
			R_FREE (str);
			free (scnd);
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
	if (!str || !key || !val) {
		return NULL;
	}
	char *heaped = r_str_replace (strdup (str), key, val, g);
	if (heaped) {
		strncpy (str, heaped, sz);
		free (heaped);
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
		int esc_seq_len = 2;
		switch (buf[i + 1]) {
		case 'e':
			buf[i] = 0x1b;
			break;
		case '\\':
			buf[i] = '\\';
			break;
		case 'r':
			buf[i] = 0x0d;
			break;
		case 'n':
			buf[i] = 0x0a;
			break;
		case 'a':
			buf[i] = 0x07;
			break;
		case 'b':
			buf[i] = 0x08;
			break;
		case 't':
			buf[i] = 0x09;
			break;
		case 'v':
			buf[i] = 0x0b;
			break;
		case 'f':
			buf[i] = 0x0c;
			break;
		case 'x':
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
			esc_seq_len = 4;
			break;
		case '$':
			buf[i] = '$';
			break;
		default:
			if (IS_OCTAL (buf[i + 1])) {
				int num_digits = 1;
				buf[i] = buf[i + 1] - '0';
				if (IS_OCTAL (buf[i + 2])) {
					num_digits++;
					buf[i] = (ut8)buf[i] * 8 + (buf[i + 2] - '0');
					if (IS_OCTAL (buf[i + 3])) {
						num_digits++;
						buf[i] = (ut8)buf[i] * 8 + (buf[i + 3] - '0');
					}
				}
				esc_seq_len = 1 + num_digits;
			} else {
				eprintf ("Error: Unknown escape sequence.\n");
				return 0; // -1?
			}
		}
		memmove (buf + i + 1, buf + i + esc_seq_len, strlen (buf + i + esc_seq_len) + 1);
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

R_API char *r_str_sanitize_sdb_key(const char *s) {
	if (!s || !*s) {
		return NULL;
	}
	size_t len = strlen (s);
	char *ret = malloc (len + 1);
	if (!ret) {
		return NULL;
	}
	char *cur = ret;
	while (len > 0) {
		char c = *s;
		if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9')
			&& c != '_' && c != ':') {
			c = '_';
		}
		*cur = c;
		s++;
		cur++;
		len--;
	}
	*cur = '\0';
	return ret;
}

R_API void r_str_byte_escape(const char *p, char **dst, int dot_nl, bool default_dot, bool esc_bslash) {
	char *q = *dst;
	switch (*p) {
	case '\n':
		*q++ = '\\';
		*q++ = dot_nl ? 'l' : 'n';
		break;
	case '\r':
		*q++ = '\\';
		*q++ = 'r';
		break;
	case '\\':
		*q++ = '\\';
		if (esc_bslash) {
			*q++ = '\\';
		}
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
	case '\v':
		*q++ = '\\';
		*q++ = 'v';
		break;
	case '\a':
		*q++ = '\\';
		*q++ = 'a';
		break;
	default:
		/* Outside the ASCII printable range */
		if (!IS_PRINTABLE (*p)) {
			if (default_dot) {
				*q++ = '.';
			} else {
				*q++ = '\\';
				*q++ = 'x';
				*q++ = "0123456789abcdef"[*p >> 4 & 0xf];
				*q++ = "0123456789abcdef"[*p & 0xf];
			}
		} else {
			*q++ = *p;
		}
	}
	*dst = q;
}

/* Internal function. dot_nl specifies whether to convert \n into the
 * graphiz-compatible newline \l */
static char *r_str_escape_(const char *buf, int dot_nl, bool parse_esc_seq, bool ign_esc_seq, bool show_asciidot, bool esc_bslash) {
	r_return_val_if_fail (buf, NULL);

	/* Worst case scenario, we convert every byte to a single-char escape
	 * (e.g. \n) if show_asciidot, or \xhh if !show_asciidot */
	char *new_buf = malloc (1 + strlen (buf) * (show_asciidot ? 2 : 4));
	if (!new_buf) {
		return NULL;
	}
	const char *p = buf;
	char *q = new_buf;
	while (*p) {
		switch (*p) {
		case 0x1b: // ESC
			if (parse_esc_seq) {
				const char *start_seq = p;
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
					if (!ign_esc_seq) {
						memcpy (q, start_seq, p - start_seq + 1);
						q += (p - start_seq + 1);
					}
				}
				break;
			}
			/* fallthrough */
		default:
			r_str_byte_escape (p, &q, dot_nl, show_asciidot, esc_bslash);
		}
		p++;
	}
out:
	*q = '\0';
	return new_buf;
}

R_API char *r_str_escape(const char *buf) {
	return r_str_escape_ (buf, false, true, true, false, true);
}

// Return MUST BE surrounded by double-quotes
R_API char *r_str_escape_sh(const char *buf) {
	r_return_val_if_fail (buf, NULL);
	char *new_buf = malloc (1 + strlen (buf) * 2);
	if (!new_buf) {
		return NULL;
	}
	const char *p = buf;
	char *q = new_buf;
	while (*p) {
		switch (*p) {
#if __UNIX__
		case '$':
		case '`':
#endif
		case '\\':
		case '"':
			*q++ = '\\';
			/* FALLTHRU */
		default:
			*q++ = *p++;
			break;
		}
	}
	*q = '\0';
	return new_buf;
}

R_API char *r_str_escape_dot(const char *buf) {
	return r_str_escape_ (buf, true, true, true, false, true);
}

R_API char *r_str_escape_latin1(const char *buf, bool show_asciidot, bool esc_bslash, bool colors) {
	return r_str_escape_ (buf, false, colors, !colors, show_asciidot, esc_bslash);
}

static char *r_str_escape_utf(const char *buf, int buf_size, RStrEnc enc, bool show_asciidot, bool esc_bslash, bool keep_printable) {
	char *new_buf, *q;
	const char *p, *end;
	RRune ch;
	int i, len, ch_bytes;

	if (!buf) {
		return NULL;
	}
	switch (enc) {
	case R_STRING_ENC_UTF16LE:
	case R_STRING_ENC_UTF16BE:
	case R_STRING_ENC_UTF32LE:
	case R_STRING_ENC_UTF32BE:
		if (buf_size < 0) {
			return NULL;
		}
		if (enc == R_STRING_ENC_UTF16LE || enc == R_STRING_ENC_UTF16BE) {
			end = (char *)r_mem_mem_aligned ((ut8 *)buf, buf_size, (ut8 *)"\0\0", 2, 2);
		} else {
			end = (char *)r_mem_mem_aligned ((ut8 *)buf, buf_size, (ut8 *)"\0\0\0\0", 4, 4);
		}
		if (!end) {
			end = buf + buf_size - 1; /* TODO: handle overlong strings properly */
		}
		len = end - buf;
		break;
	default:
		len = strlen (buf);
		end = buf + len;
	}
	/* Worst case scenario, we convert every byte to \xhh */
	new_buf = malloc (1 + (len * 4));
	if (!new_buf) {
		return NULL;
	}
	p = buf;
	q = new_buf;
	while (p < end) {
		switch (enc) {
		case R_STRING_ENC_UTF16LE:
		case R_STRING_ENC_UTF16BE:
		case R_STRING_ENC_UTF32LE:
		case R_STRING_ENC_UTF32BE:
			if (enc == R_STRING_ENC_UTF16LE || enc == R_STRING_ENC_UTF16BE) {
				ch_bytes = r_utf16_decode ((ut8 *)p, end - p, &ch, enc == R_STRING_ENC_UTF16BE);
			} else {
				ch_bytes = r_utf32_decode ((ut8 *)p, end - p, &ch, enc == R_STRING_ENC_UTF32BE);
			}
			if (ch_bytes == 0) {
				p++;
				continue;
			}
			break;
		default:
			ch_bytes = r_utf8_decode ((ut8 *)p, end - p, &ch);
			if (ch_bytes == 0) {
				ch_bytes = 1;
			}
		}
		if (show_asciidot && !IS_PRINTABLE(ch)) {
			*q++ = '.';
		} else if (ch_bytes > 1) {
			if (keep_printable) {
				q += r_utf8_encode ((ut8 *)q, ch);
			} else {
				*q++ = '\\';
				*q++ = ch_bytes == 4 ? 'U' : 'u';
				for (i = ch_bytes == 4 ? 6 : 2; i >= 0; i -= 2) {
					*q++ = "0123456789abcdef"[ch >> 4 * (i + 1) & 0xf];
					*q++ = "0123456789abcdef"[ch >> 4 * i & 0xf];
				}
			}
		} else {
			int offset = enc == R_STRING_ENC_UTF16BE ? 1 : enc == R_STRING_ENC_UTF32BE ? 3 : 0;
			r_str_byte_escape (p + offset, &q, false, false, esc_bslash);
		}
		switch (enc) {
		case R_STRING_ENC_UTF16LE:
		case R_STRING_ENC_UTF16BE:
			p += ch_bytes < 2 ? 2 : ch_bytes;
			break;
		case R_STRING_ENC_UTF32LE:
		case R_STRING_ENC_UTF32BE:
			p += 4;
			break;
		default:
			p += ch_bytes;
		}
	}
	*q = '\0';
	return new_buf;
}

R_API char *r_str_escape_utf8(const char *buf, bool show_asciidot, bool esc_bslash) {
	return r_str_escape_utf (buf, -1, R_STRING_ENC_UTF8, show_asciidot, esc_bslash, false);
}

R_API char *r_str_escape_utf8_keep_printable(const char *buf, bool show_asciidot, bool esc_bslash) {
	return r_str_escape_utf (buf, -1, R_STRING_ENC_UTF8, show_asciidot, esc_bslash, true);
}

R_API char *r_str_escape_utf16le(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash) {
	return r_str_escape_utf (buf, buf_size, R_STRING_ENC_UTF16LE, show_asciidot, esc_bslash, false);
}

R_API char *r_str_escape_utf32le(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash) {
	return r_str_escape_utf (buf, buf_size, R_STRING_ENC_UTF32LE, show_asciidot, esc_bslash, false);
}

R_API char *r_str_escape_utf16be(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash) {
	return r_str_escape_utf (buf, buf_size, R_STRING_ENC_UTF16BE, show_asciidot, esc_bslash, false);
}

R_API char *r_str_escape_utf32be(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash) {
	return r_str_escape_utf (buf, buf_size, R_STRING_ENC_UTF32BE, show_asciidot, esc_bslash, false);
}

R_API char *r_str_encoded_json(const char *buf, int buf_size, int encoding) {
	r_return_val_if_fail (buf, NULL);
	size_t buf_sz = buf_size < 0 ? strlen (buf) : buf_size;
	char *encoded_str;

	if (encoding == PJ_ENCODING_STR_BASE64) {
		encoded_str = r_base64_encode_dyn (buf, buf_sz);
	} else if (encoding == PJ_ENCODING_STR_HEX || encoding == PJ_ENCODING_STR_ARRAY) {
		size_t loop = 0;
		size_t i = 0;
		size_t increment = encoding == PJ_ENCODING_STR_ARRAY ? 4 : 2;
		
		if (!SZT_MUL_OVFCHK (((buf_sz * increment) + 1), SZT_MAX)) {
			return NULL;
		}
		size_t new_sz = (buf_sz * increment) + 1;

		encoded_str = malloc (new_sz);
		if (!encoded_str) {
			return NULL;
		}

		const char *format = encoding == PJ_ENCODING_STR_ARRAY ? "%03u," : "%02X";
		while (buf[loop] != '\0' && i < (new_sz - 1)) {
			snprintf (encoded_str + i, sizeof (encoded_str), format, (ut8) buf[loop]);
			loop++;
			i += increment;
		}
		if (encoding == PJ_ENCODING_STR_ARRAY && i) {
			// get rid of the trailing comma
			encoded_str[i - 1] = '\0';
		} else {
			encoded_str[i] = '\0';
		}
	} else if (encoding == PJ_ENCODING_STR_STRIP) {
		encoded_str = r_str_escape_utf8_for_json_strip (buf, buf_sz);
	} else {
		encoded_str = r_str_escape_utf8_for_json (buf, buf_sz);
	}
	return encoded_str;
}

R_API char *r_str_escape_utf8_for_json_strip(const char *buf, int buf_size) {
	char *new_buf, *q;
	const char *p, *end;
	RRune ch;
	int i, len, ch_bytes;

	if (!buf) {
		return NULL;
	}
	len = buf_size < 0 ? strlen (buf) : buf_size;
	end = buf + len;
	/* Worst case scenario, we convert every byte to \u00hh */
	new_buf = malloc (1 + (len * 6));
	if (!new_buf) {
		return NULL;
	}
	p = buf;
	q = new_buf;
	while (p < end) {
		ch_bytes = r_utf8_decode ((ut8 *)p, end - p, &ch);
		if (ch_bytes == 1) {
			switch (*p) {
			case '\n':
				*q++ = '\\';
				*q++ = 'n';
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
			default:
				if (IS_PRINTABLE (*p)) {
					*q++ = *p;
				}
			}
		} else if (ch_bytes == 4) {
			if (r_isprint (ch)) {
				// Assumes buf is UTF8-encoded
				for (i = 0; i < ch_bytes; i++) {
					*q++ = *(p + i);
				}
			} else {
				RRune high, low;
				ch -= 0x10000;
				high = 0xd800 + (ch >> 10 & 0x3ff);
				low = 0xdc00 + (ch & 0x3ff);
				*q++ = '\\';
				*q++ = 'u';
				for (i = 2; i >= 0; i -= 2) {
					*q++ = "0123456789abcdef"[high >> 4 * (i + 1) & 0xf];
					*q++ = "0123456789abcdef"[high >> 4 * i & 0xf];
				}
				*q++ = '\\';
				*q++ = 'u';
				for (i = 2; i >= 0; i -= 2) {
					*q++ = "0123456789abcdef"[low >> 4 * (i + 1) & 0xf];
					*q++ = "0123456789abcdef"[low >> 4 * i & 0xf];
				}
			}
		} else if (ch_bytes > 1) {
			if (r_isprint (ch)) {
				// Assumes buf is UTF8-encoded
				for (i = 0; i < ch_bytes; i++) {
					*q++ = *(p + i);
				}
			} else {
				*q++ = '\\';
				*q++ = 'u';
				for (i = 2; i >= 0; i -= 2) {
					*q++ = "0123456789abcdef"[ch >> 4 * (i + 1) & 0xf];
					*q++ = "0123456789abcdef"[ch >> 4 * i & 0xf];
				}
			}
		} else { 
			ch_bytes = 1;
		}
		p += ch_bytes;
	}
	*q = '\0';
	return new_buf;
}


R_API char *r_str_escape_utf8_for_json(const char *buf, int buf_size) {
	char *new_buf, *q;
	const char *p, *end;
	RRune ch;
	int i, len, ch_bytes;

	if (!buf) {
		return NULL;
	}
	len = buf_size < 0 ? strlen (buf) : buf_size;
	end = buf + len;
	/* Worst case scenario, we convert every byte to \u00hh */
	new_buf = malloc (1 + (len * 6));
	if (!new_buf) {
		return NULL;
	}
	p = buf;
	q = new_buf;
	while (p < end) {
		ch_bytes = r_utf8_decode ((ut8 *)p, end - p, &ch);
		if (ch_bytes == 1) {
			switch (*p) {
			case '\n':
				*q++ = '\\';
				*q++ = 'n';
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
			default:
				if (!IS_PRINTABLE (*p)) {
					*q++ = '\\';
					*q++ = 'u';
					*q++ = '0';
					*q++ = '0';
					*q++ = "0123456789abcdef"[*p >> 4 & 0xf];
					*q++ = "0123456789abcdef"[*p & 0xf];
				} else {
					*q++ = *p;
				}
			}
		} else if (ch_bytes == 4) {
			if (r_isprint (ch)) {
				// Assumes buf is UTF8-encoded
				for (i = 0; i < ch_bytes; i++) {
					*q++ = *(p + i);
				}
			} else {
				RRune high, low;
				ch -= 0x10000;
				high = 0xd800 + (ch >> 10 & 0x3ff);
				low = 0xdc00 + (ch & 0x3ff);
				*q++ = '\\';
				*q++ = 'u';
				for (i = 2; i >= 0; i -= 2) {
					*q++ = "0123456789abcdef"[high >> 4 * (i + 1) & 0xf];
					*q++ = "0123456789abcdef"[high >> 4 * i & 0xf];
				}
				*q++ = '\\';
				*q++ = 'u';
				for (i = 2; i >= 0; i -= 2) {
					*q++ = "0123456789abcdef"[low >> 4 * (i + 1) & 0xf];
					*q++ = "0123456789abcdef"[low >> 4 * i & 0xf];
				}
			}
		} else if (ch_bytes > 1) {
			if (r_isprint (ch)) {
				// Assumes buf is UTF8-encoded
				for (i = 0; i < ch_bytes; i++) {
					*q++ = *(p + i);
				}
			} else {
				*q++ = '\\';
				*q++ = 'u';
				for (i = 2; i >= 0; i -= 2) {
					*q++ = "0123456789abcdef"[ch >> 4 * (i + 1) & 0xf];
					*q++ = "0123456789abcdef"[ch >> 4 * i & 0xf];
				}
			}
		} else { // ch_bytes == 0
			// Outside JSON spec, but apparently no better
			// alternative if need to reconstruct the original string
			*q++ = '\\';
			*q++ = 'x';
			*q++ = "0123456789abcdef"[*p >> 4 & 0xf];
			*q++ = "0123456789abcdef"[*p & 0xf];
			ch_bytes = 1;
		}
		p += ch_bytes;
	}
	*q = '\0';
	return new_buf;
}

// http://daviddeley.com/autohotkey/parameters/parameters.htm#WINCRULES
// https://docs.microsoft.com/en-us/cpp/cpp/main-function-command-line-args?redirectedfrom=MSDN&view=vs-2019#parsing-c-command-line-arguments
R_API char *r_str_format_msvc_argv(size_t argc, const char **argv) {
	RStrBuf sb;
	r_strbuf_init (&sb);

	size_t i;
	for (i = 0; i < argc; i++) {
		if (i > 0) {
			r_strbuf_append (&sb, " ");
		}
		const char *arg = argv[i];
		bool must_escape = strchr (arg, '\"') != NULL;
		bool must_quote = strpbrk (arg, " \t") != NULL || !*arg;
		if (!must_escape && must_quote && *arg && arg[strlen (arg) - 1] == '\\') {
			// if the last char is a bs and we would quote it, we must also escape
			must_escape = true;
		}
		if (must_quote) {
			r_strbuf_append (&sb, "\"");
		}
		if (must_escape) {
			size_t bs_count = 0; // bullshit counter
			for (; *arg; arg++) {
				switch (*arg) {
				case '\"':
					for (; bs_count; bs_count--) {
						// backslashes must be escaped iff they precede a "
						// so just duplicate the number of backslashes already printed
						r_strbuf_append (&sb, "\\");
					}
					r_strbuf_append (&sb, "\\\"");
					break;
				case '\\':
					bs_count++;
					r_strbuf_append (&sb, "\\");
					break;
				default:
					bs_count = 0;
					r_strbuf_append_n (&sb, arg, 1);
					break;
				}
			}
			if (must_quote) {
				// there will be a quote after this so we have to escape bs here as well
				for (; bs_count; bs_count--) {
					r_strbuf_append (&sb, "\\");
				}
			}
		} else {
			r_strbuf_append (&sb, arg);
		}
		if (must_quote) {
			r_strbuf_append (&sb, "\"");
		}
	}

	return r_strbuf_drain_nofree (&sb);
}

static size_t __str_ansi_length(char const *str) {
	size_t i = 1;
	if (str[0] == 0x1b) {
		if (str[1] == '[') {
			i++;
			while (str[i] && str[i] != 'J' && str[i] != 'm' && str[i] != 'H' && str[i] != 'K') {
				i++;
			}
		} else if (str[1] == '#') {
			while (str[i] && str[i] != 'q') {
				i++;
			}
		}
		if (str[i]) {
			i++;
		}
	}
	return i;
}

/* ansi helpers */
R_API size_t r_str_ansi_nlen(const char *str, size_t slen) {
	size_t i = 0, len = 0;
	if (slen > 0) {
		while (str[i] && i < slen) {
			size_t chlen = __str_ansi_length (str + i);
			if (chlen == 1) {
				len ++;
			}
			i += chlen;
		}
		return len > 0 ? len: 1;
	}
	while (str[i]) {
		size_t chlen = __str_ansi_length (str + i);
		if (chlen == 1) {
			len ++;
		}
		i += chlen;
	}
	return len > 0 ? len: 1;
}

R_API size_t r_str_ansi_len(const char *str) {
	return r_str_ansi_nlen (str, 0);
}

R_API size_t r_str_nlen(const char *str, int n) {
	size_t len = 0;
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
R_API size_t r_str_nlen_w(const char *str, int n) {
	size_t len = 0;
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

R_API bool r_str_is_ascii(const char *str) {
	const ut8 *ptr;
	for (ptr = (const ut8 *)str; *ptr; ptr++) {
		if (*ptr > 0x7f) {
			return false;
		}
	}
	return true;
}

R_API bool r_str_is_printable(const char *str) {
	while (*str) {
		int ulen = r_utf8_decode ((const ut8*)str, strlen (str), NULL);
		if (ulen > 1) {
			str += ulen;
			continue;
		}
		if (!IS_PRINTABLE (*str)) {
			return false;
		}
		str++;
	}
	return true;
}

R_API bool r_str_is_printable_limited(const char *str, int size) {
	while (size > 0 && *str) {
		int ulen = r_utf8_decode ((const ut8*)str, strlen (str), NULL);
		if (ulen > 1) {
			str += ulen;
			continue;
		}
		if (!IS_PRINTABLE (*str)) {
			return false;
		}
		str++;
		size--;
	}
	return true;
}

R_API bool r_str_is_printable_incl_newlines(const char *str) {
	while (*str) {
		int ulen = r_utf8_decode ((const ut8*)str, strlen (str), NULL);
		if (ulen > 1) {
			str += ulen;
			continue;
		}
		if (!IS_PRINTABLE (*str)) {
			if (*str != '\r' && *str != '\n' && *str != '\t') {
				return false;
			}
		}
		str++;
	}
	return true;
}

// Length in chars of a wide string (find better name?)
R_API size_t r_wstr_clen(const char *s) {
	size_t len = 0;
	if (!*s++) {
		return 0;
	}
	while (*s++ || *s++) {
		len++;
	}
	return len + 1;
}

R_API const char *r_str_ansi_chrn(const char *str, size_t n) {
	int len, i, li;
	for (li = i = len = 0; str[i] && (n != len); i++) {
		size_t chlen = __str_ansi_length (str + i);
		if (chlen > 1) {
			i += chlen - 1;
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
 * len - length of str
 *
 * it returns the number of normal characters found in str
 */
R_API int r_str_ansi_filter(char *str, char **out, int **cposs, int len) {
	int i, j, *cps;

	if (len == 0) {
		return 0;
	}
	if (len < 0) {
		len = strlen (str);
	}
	char *tmp = malloc (len + 1);
	if (!tmp) {
		return -1;
	}
	memcpy (tmp, str, len + 1);
	cps = calloc (len + 1, sizeof (int));
	if (!cps) {
		free (tmp);
		return -1;
	}

	for (i = j = 0; i < len; i++) {
		if (tmp[i] == 0x1b) {
			size_t chlen = __str_ansi_length (str + i);
			if (chlen > 1) {
				i += chlen;
				i--;
			}
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

R_API char *r_str_ansi_crop(const char *str, ut32 x, ut32 y, ut32 x2, ut32 y2) {
	char *r, *r_end, *ret;
	const char *s, *s_start;
	size_t r_len, str_len = 0, nr_of_lines = 0;
	ut32 ch = 0, cw = 0;
	if (x2 <= x || y2 <= y || !str) {
		return strdup ("");
	}
	s = s_start = str;
	while (*s) {
		str_len++;
		if (*s == '\n') {
			nr_of_lines++;
		}
		s++;
	}
	r_len = str_len + nr_of_lines * strlen (Color_RESET) + 1;
	r = ret = malloc (r_len);
	if (!r) {
		return NULL;
	}
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
					const int reset_length = strlen (reset);
					memcpy (r, reset, reset_length + 1);
					r += reset_length;
				}
			}
			str++;
			ch++;
			cw = 0;
		} else {
			if (ch >= y && ch < y2) {
				if ((*str & 0xc0) == 0x80) {
					if (cw > x) {
						*r++ = *str++;
					} else {
						str++;
					}
					continue;
				}
				if (r_str_char_fullwidth (str, str_len - (str - s_start))) {
					cw++;
					if (cw == x) {
						*r++ = ' ';
						str++;
						continue;
					}
				}
				if (*str == 0x1b && *(str + 1) == '[') {
					const char *ptr = str;
					if ((r_end - r) > 2) {
						/* copy 0x1b and [ */
						*r++ = *str++;
						*r++ = *str++;
						for (ptr = str; *ptr && *ptr != 'J' && *ptr != 'm' && *ptr != 'H'; ptr++) {
							*r++ = *ptr;
						}
						*r++ = *ptr++;
					}
					str = ptr;
					continue;
				} else if (cw >= x && cw < x2) {
					*r++ = *str;
				}
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

R_API size_t r_str_utf8_codepoint(const char* s, size_t left) {
	if ((*s & 0x80) != 0x80) {
		return 0;
	} else if ((*s & 0xe0) == 0xc0 && left >= 1) {
		return ((*s & 0x1f) << 6) + (*(s + 1) & 0x3f);
	} else if ((*s & 0xf0) == 0xe0 && left >= 2) {
		return ((*s & 0xf) << 12) + ((*(s + 1) & 0x3f) << 6) + (*(s + 2) & 0x3f);
	} else if ((*s & 0xf8) == 0xf0 && left >= 3) {
		return ((*s & 0x7) << 18) + ((*(s + 1) & 0x3f) << 12) + ((*(s + 2) & 0x3f) << 6) + (*(s + 3) & 0x3f);
	}
	return 0;
}

R_API bool r_str_char_fullwidth (const char* s, size_t left) {
	size_t codepoint = r_str_utf8_codepoint (s, left);
	return (codepoint >= 0x1100 &&
		 (codepoint <= 0x115f ||                  /* Hangul Jamo init. consonants */
			  codepoint == 0x2329 || codepoint == 0x232a ||
		 (R_BETWEEN (0x2e80, codepoint, 0xa4cf)
			&& codepoint != 0x303f) ||        /* CJK ... Yi */
		 R_BETWEEN (0xac00, codepoint, 0xd7a3) || /* Hangul Syllables */
		 R_BETWEEN (0xf900, codepoint, 0xfaff) || /* CJK Compatibility Ideographs */
		 R_BETWEEN (0xfe10, codepoint, 0xfe19) || /* Vertical forms */
		 R_BETWEEN (0xfe30, codepoint, 0xfe6f) || /* CJK Compatibility Forms */
		 R_BETWEEN (0xff00, codepoint, 0xff60) || /* Fullwidth Forms */
		 R_BETWEEN (0xffe0, codepoint, 0xffe6) ||
		 R_BETWEEN (0x20000, codepoint, 0x2fffd) ||
		 R_BETWEEN (0x30000, codepoint, 0x3fffd)));

}

/**
 * Returns size in bytes of the utf8 char
 * Returns 1 in case of ASCII
 * str - Pointer to buffer
 */
R_API size_t r_str_utf8_charsize(const char *str) {
	r_return_val_if_fail (str, 0);
	size_t size = 0;
	size_t length = strlen (str);
	while (size < length && size < 5) {
		size++;
		if ((str[size] & 0xc0) != 0x80) {
			break;
		}
	}
	return size < 5 ? size : 0;
}

/**
 * Returns size in bytes of the utf8 char previous to str
 * Returns 1 in case of ASCII
 * str - Pointer to leading utf8 char
 * prev_len - Length in bytes of the buffer until str
 */
R_API size_t r_str_utf8_charsize_prev(const char *str, int prev_len) {
	r_return_val_if_fail (str, 0);
	int pos = 0;
	size_t size = 0, minsize = R_MIN (5, prev_len);
	while (size < minsize) {
		size++;
		if ((str[--pos] & 0xc0) != 0x80) {
			break;
		}
	}
	return size < 5 ? size : 0;
}

/**
 * Returns size in bytes of the last utf8 char of the string
 * Returns 1 in case of ASCII
 * str - Pointer to buffer
 */
R_API size_t r_str_utf8_charsize_last(const char *str) {
	r_return_val_if_fail (str, 0);
	size_t len = strlen (str);
	return r_str_utf8_charsize_prev (str + len, len);
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
	size_t i;
	if (len < 1) {
		len = strlen (str);
	}
	for (i = 0; i < len; i++) {
		if (!IS_PRINTABLE (str[i])) {
			str[i] = '.';
		}
	}
}

R_API bool r_str_glob(const char* str, const char *glob) {
        const char* cp = NULL, *mp = NULL;
        if (!glob || !strcmp (glob, "*")) {
                return true;
        }
        if (!strchr (glob, '*')) {
                if (*glob == '^') {
                        glob++;
                        while (*str) {
                                if (*glob != *str) {
                                        return false;
                                }
                                if (!*++glob) {
                                        return true;
                                }
                                str++;
                        }
                } else {
                        return strstr (str, glob) != NULL;
                }
        }
        if (*glob == '^') {
                glob++;
        }
        while (*str && (*glob != '*')) {
                if (*glob != *str) {
                        return false;
                }
                glob++;
                str++;
        }
        while (*str) {
                if (*glob == '*') {
                        if (!*++glob) {
                                return true;
                        }
                        mp = glob;
                        cp = str + 1;
                } else if (*glob == *str) {
                        glob++;
                        str++;
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
R_API char *r_str_arg_escape(const char *arg) {
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

// Unescape the string arg to its original format
R_API int r_str_arg_unescape(char *arg) {
	int dest_i = 0, src_i = 0;
	if (!arg) {
		return 0;
	}
	for (src_i = 0; arg[src_i] != '\0'; src_i++) {
		char c = arg[src_i];
		if (c == '\\') {
			if (arg[++src_i] == '\0') {
				break;
			}
			arg[dest_i++] = arg[src_i];
		} else {
			arg[dest_i++] = c;
		}
	}
	arg[dest_i] = '\0';
	return dest_i;
}

R_API char *r_str_path_escape(const char *path) {
	char *str;
	int dest_i = 0, src_i = 0;

	if (!path) {
		return NULL;
	}
	// Worst case when every character need to be escaped
	str = malloc ((2 * strlen (path) + 1) * sizeof (char));
	if (!str) {
		return NULL;
	}

	for (src_i = 0; path[src_i] != '\0'; src_i++) {
		char c = path[src_i];
		switch (c) {
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
	return realloc (str, (strlen (str) + 1) * sizeof (char));
}

R_API int r_str_path_unescape(char *path) {
	int i;

	for (i = 0; path[i]; i++) {
		if (path[i] != '\\') {
			continue;
		}
		if (path[i + 1] == ' ') {
			path[i] = ' ';
			memmove (path + i + 1, path + i + 2, strlen (path + i + 2) + 1);
		}
	}

	return i;
}

R_API char **r_str_argv(const char *cmdline, int *_argc) {
	int argc = 0;
	int argv_len = 128; // Begin with that, argv will reallocated if necessary
	char *args; // Working buffer for writing unescaped args
	int cmdline_current = 0; // Current character index in _cmdline
	int args_current = 0; // Current character index in  args
	int arg_begin = 0; // Index of the first character of the current argument in args

	if (!cmdline) {
		return NULL;
	}

	char **argv = malloc (argv_len * sizeof (char *));
	if (!argv) {
		return NULL;
	}
	args = malloc (128 + strlen (cmdline) * sizeof (char)); // Unescaped args will be shorter, so strlen (cmdline) will be enough
	if (!args) {
		free (argv);
		return NULL;
	}
	do {
		// States for parsing args
		int escaped = 0;
		int singlequoted = 0;
		int doublequoted = 0;

		// Seek the beginning of next argument (skip whitespaces)
		while (cmdline[cmdline_current] != '\0' && IS_WHITECHAR (cmdline[cmdline_current])) {
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
					args[args_current++] = '\\';
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
			char **tmp = realloc (argv, argv_len * sizeof (char *));
			if (!tmp) {
				free (args);
				free (argv);
				return NULL;
			}
			argv = tmp;
		}
		arg_begin = args_current;
	} while (cmdline[cmdline_current++] != '\0');
	argv[argc] = NULL;
	char **tmp = realloc (argv, (argc + 1) * sizeof (char *));
	if (tmp) {
		argv = tmp;
	} else {
		free (argv);
		argv = NULL;
	}
	if (_argc) {
		*_argc = argc;
	}
	free (args);
	return argv;
}

R_API void r_str_argv_free(char **argv) {
	int argc = 0;
	if (!argv) {
		return;
	}
	while (argv[argc]) {
		free (argv[argc++]);
	}
	free (argv);
}

R_API const char *r_str_firstbut(const char *s, char ch, const char *but) {
	int idx, _b = 0;
	ut8 *b = (ut8*)&_b;
	const char *isbut, *p;
	const int bsz = sizeof (_b) * 8;
	if (!but) {
		return strchr (s, ch);
	}
	if (strlen (but) >= bsz) {
		eprintf ("r_str_firstbut: but string too long\n");
		return NULL;
	}
	for (p = s; *p; p++) {
		isbut = strchr (but, *p);
		if (isbut) {
			idx = (int)(size_t)(isbut - but);
			_b = R_BIT_TOGGLE (b, idx);
			continue;
		}
		if (*p == ch && !_b) {
			return p;
		}
	}
	return NULL;
}

R_API const char *r_str_lastbut(const char *s, char ch, const char *but) {
	int idx, _b = 0;
	ut8 *b = (ut8*)&_b;
	const char *isbut, *p, *lp = NULL;
	const int bsz = sizeof (_b) * 8;
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
			_b = R_BIT_TOGGLE (b, idx);
			continue;
		}
		if (*p == ch && !_b) {
			lp = p;
		}
	}
	return lp;
}

// Must be merged inside strlen
R_API size_t r_str_len_utf8char(const char *s, int left) {
	size_t i = 1;
	while (s[i] && (!left || i<left)) {
		if ((s[i] & 0xc0) != 0x80) {
			i++;
		} else {
			break;
		}
	}
	return i;
}

R_API size_t r_str_len_utf8(const char *s) {
	size_t i = 0, j = 0, fullwidths = 0;
	while (s[i]) {
		if ((s[i] & 0xc0) != 0x80) {
			j++;
			if (r_str_char_fullwidth (s + i, 4)) {
				fullwidths++;
			}
		}
		i++;
	}
	return j + fullwidths;
}

R_API size_t r_str_len_utf8_ansi(const char *str) {
	int i = 0, len = 0, fullwidths = 0;
	while (str[i]) {
		char ch = str[i];
		size_t chlen = __str_ansi_length (str + i);
		if (chlen > 1) {
			i += chlen - 1;
		} else if ((ch & 0xc0) != 0x80) { // utf8
			len++;
			if (r_str_char_fullwidth (str + i, 4)) {
				fullwidths++;
			}
		}
		i++;
	}
	return len + fullwidths;
}

// XXX must find across the ansi tags, as well as support utf8
R_API const char *r_strstr_ansi(const char *a, const char *b) {
	const char *ch, *p = a;
	do {
		ch = strchr (p, '\x1b');
		if (ch) {
			const char *v = r_str_nstr (p, b, ch - p);
			if (v) {
				return v;
			}
			p = ch + __str_ansi_length (ch);
		}
	} while (ch);
	return strstr (p, b);
}

R_API const char *r_str_casestr(const char *a, const char *b) {
	// That's a GNUism that works in many places.. but we don't want it
	// return strcasestr (a, b);
	size_t hay_len = strlen (a);
	size_t needle_len = strlen (b);
	if (!hay_len || !needle_len) {
		return NULL;
	}
	while (hay_len >= needle_len) {
		if (!r_str_ncasecmp (a, b, needle_len)) {
			return (const char *) a;
		}
		a++;
		hay_len--;
	}
	return NULL;
}

R_API int r_str_write(int fd, const char *b) {
	return write (fd, b, strlen (b));
}

R_API void r_str_range_foreach(const char *r, RStrRangeCallback cb, void *u) {
	const char *p = r;
	for (; *r; r++) {
		if (*r == ',') {
			cb (u, atoi (p));
			p = r + 1;
		}
		if (*r == '-') {
			if (p != r) {
				int from = atoi (p);
				int to = atoi (r + 1);
				for (; from <= to; from++) {
					cb (u, from);
				}
			} else {
				fprintf (stderr, "Invalid range\n");
			}
			for (r++; *r && *r != ',' && *r != '-'; r++) {
				;
			}
			p = r;
		}
	}
	if (*p) {
		cb (u, atoi (p));
	}
}

R_API bool r_str_range_in(const char *r, ut64 addr) {
	const char *p = r;
	ut64 min = UT64_MAX;
	ut64 max = 0;
	if (!r) {
		return false;
	}
	for (; *r; r++) {
		if (*r == ',') {
			if (max == 0) {
				if (addr == r_num_get (NULL, p)) {
					return true;
				}
			} else {
				if (addr >= min && addr <= r_num_get (NULL, p)) {
					return true;
				}
			}
			p = r + 1;
		}
		if (*r == '-') {
			if (p != r) {
				ut64 from = r_num_get (NULL, p);
				ut64 to = r_num_get (NULL, r + 1);
				if (addr >= from && addr <= to) {
					return true;
				}
			} else {
				fprintf (stderr, "Invalid range\n");
			}
			for (r++; *r && *r != ',' && *r != '-'; r++) {
				;
			}
			p = r;
		}
	}
	if (*p) {
		if (addr == r_num_get (NULL, p)) {
			return true;
		}
	}
	return false;
}

// convert from html escaped sequence "foo%20bar" to "foo bar"
// TODO: find better name.. unencode? decode
R_API void r_str_uri_decode(char *s) {
	int n;
	char *d;
	for (d = s; *s; s++, d++) {
		if (*s == '%') {
			sscanf (s + 1, "%02x", &n);
			*d = n;
			s += 2;
		} else {
			*d = *s;
		}
	}
	*d = 0;
}

R_API char *r_str_uri_encode(const char *s) {
	char ch[4], *d, *od;
	if (!s) {
		return NULL;
	}
	od = d = malloc (1 + (strlen (s) * 4));
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
			snprintf (ch, sizeof (ch), "%02x", 0xff & ((ut8)*s));
			*d++ = ch[0];
			*d++ = ch[1];
		}
	}
	*d = 0;
	char *trimDown = realloc (od, strlen (od) + 1); // FIT
	return trimDown? trimDown: od;
}

R_API int r_str_utf16_to_utf8(ut8 *dst, int len_dst, const ut8 *src, int len_src, int little_endian) {
	ut8 *outstart = dst;
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
			c = *in++;
		} else {
			tmp = (ut8*) in;
			c = *tmp++;
			if (!c && !*tmp) {
				break;
			}
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
			} else {
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

		for (; bits >= 0; bits -= 6) {
			if (dst >= outend) {
				break;
			}
			*dst++ = ((c >> bits) & 0x3F) | 0x80;
		}
	}
	len_dst = dst - outstart;
	return len_dst;
}

R_API char *r_str_utf16_decode(const ut8 *s, int len) {
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
		if (!s[i+1] && IS_PRINTABLE(s[i])) {
			result[j++] = s[i];
		} else {
			j += snprintf (&result[j], lenresult - j, "\\u%.2"HHXFMT"%.2"HHXFMT"", s[i], s[i+1]);
		}
	}
	return result;
}

// TODO: kill this completely, it makes no sense:
R_API char *r_str_utf16_encode(const char *s, int len) {
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
		if (*s == '\\') {
			*d++ = '\\';
			*d++ = '\\';
		} else if (*s == '"') {
			*d++ = '\\';
			*d++ = '"';
		} else if ((*s >= 0x20) && (*s <= 126)) {
			*d++ = *s;
		} else {
			*d++ = '\\';
			//	*d++ = '\\';
			*d++ = 'u';
			*d++ = '0';
			*d++ = '0';
			snprintf (ch, sizeof (ch), "%02x", 0xff & ((ut8)*s));
			*d++ = ch[0];
			*d++ = ch[1];
		}
	}
	*d = 0;
	tmp = realloc (od, strlen (od) + 1); // FIT
	if (!tmp) {
		free (od);
		return NULL;
	}
	return tmp;
}

R_API char *r_str_prefix_all(const char *s, const char *pfx) {
	const char *os = s;
	char *p;
	int newlines = 1;
	int len = 0;
	int pfx_len = 0;

	if (!s) {
		return strdup (pfx);
	}
	if (!pfx) {
		return strdup (s);
	}
	len = strlen (s);
	pfx_len = strlen (pfx);
	for (os = s; *os; os++)  {
		if (*os == '\n') {
			newlines++;
		}
	}
	char *o = malloc (len + (pfx_len * newlines) + 1);
	if (!o) {
		return NULL;
	}
	memcpy (o, pfx, pfx_len);
	for (p = o + pfx_len; *s; s++) {
		*p++ = *s;
		if (*s == '\n' && s[1]) {
			memcpy (p, pfx, pfx_len);
			p += pfx_len;
		}
	}
	*p = 0;
	return o;
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

R_API const char *r_str_closer_chr(const char *b, const char *s) {
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

R_API int r_str_bounds(const char *_str, int *h) {
	const char *str, *ptr;
	int W = 0, H = 0;
	int cw = 0;

	if (_str) {
		ptr = str = _str;
		while (*str) {
			if (*str == '\n') {
				H++;
				cw = r_str_ansi_nlen (ptr, (size_t)(str - ptr));
				if (cw > W) {
					W = cw;
				}
				cw = 0;
				ptr = str + 1;
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
	}
	return W;
}

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

R_API char *r_str_repeat(const char *ch, int sz) {
	int i;
	if (sz < 0) {
		sz = 0;
	}
	if (sz == 0) {
		return strdup ("");
	}
	RStrBuf *buf = r_strbuf_new (ch);
	for (i = 1; i < sz; i++) {
		r_strbuf_append (buf, ch);
	}
	return r_strbuf_drain (buf);
}

R_API char *r_str_between(const char *cmt, const char *prefix, const char *suffix) {
	char *c0, *c1;
	if (!cmt || !prefix || !suffix || !*cmt) {
		return NULL;
	}
	c0 = strstr (cmt, prefix);
	if (c0) {
		c1 = strstr (c0 + strlen (prefix), suffix);
		if (c1) {
			return r_str_ndup (c0 + strlen (prefix), (c1 - c0 - strlen (prefix)));
		}
	}
	return NULL;
}

R_API bool r_str_startswith(const char *str, const char *needle) {
	r_return_val_if_fail (str && needle, false);
	if (str == needle) {
		return true;
	}
	return !strncmp (str, needle, strlen (needle));
}

R_API bool r_str_endswith(const char *str, const char *needle) {
	r_return_val_if_fail (str && needle, false);
	if (!*needle) {
		return true;
	}
	int slen = strlen (str);
	int nlen = strlen (needle);
	if (!slen || !nlen || slen < nlen) {
		return false;
	}
	return !strcmp (str + (slen - nlen), needle);
}

// Splits the string <str> by string <c> and returns the result in a list.
R_API RList *r_str_split_list(char *str, const char *c, int n)  {
	r_return_val_if_fail (str && c, NULL);
	RList *lst = r_list_newf (NULL);
	char *aux = str;
	int i = 0;
	char  *e = aux;
	for (;e;) {
		e = strstr (aux, c);
		if (n > 0) {
			if (++i > n) {
				r_list_append (lst, aux);
				break;
			}
		}
		if (e) {
			*e++ =  0;
		}
		r_str_trim (aux);
		r_list_append (lst, aux);
		aux = e;
	}
	return lst;
}

R_API RList *r_str_split_duplist(const char *_str, const char *c, bool trim) {
	r_return_val_if_fail (_str && c, NULL);
	RList *lst = r_list_newf (free);
	char *str = strdup (_str);
	char *aux = str;
	size_t clen = strlen (c);
	while (aux) {
		char *next = strstr (aux, c);
		if (next) {
			*next = '\0';
			next += clen;
		}
		if (trim) {
			r_str_trim (aux);
		}
		r_list_append (lst, strdup (aux));
		aux = next;
	}
	free (str);
	return lst;
}

R_API size_t *r_str_split_lines(char *str, size_t *count) {
	int i;
	size_t lines = 0;
	if (!str) {
		return NULL;
	}
	size_t *indexes = NULL;
	// count lines
	for (i = 0; str[i]; i++) {
		if (str[i] == '\n') {
			lines++;
		}
	}
	// allocate and set indexes
	indexes = calloc (sizeof (count[0]), lines + 1);
	if (!indexes) {
		return NULL;
	}
	size_t line = 0;
	indexes[line++] = 0;
	for (i = 0; str[i]; i++) {
		if (str[i] == '\n') {
			str[i] = 0;
			indexes[line++] = i + 1;
		}
	}
	if (count) {
		*count = line;
	}
	return indexes;
}

R_API bool r_str_isnumber(const char *str) {
	if (!str || !*str) {
		return false;
	}
	bool isnum = IS_DIGIT (*str) || *str == '-';
	while (isnum && *++str) {
		if (!IS_DIGIT (*str)) {
			isnum = false;
		}
	}
	return isnum;
}

/* TODO: optimize to start searching by the end of the string */
R_API const char *r_str_last(const char *str, const char *ch) {
	char *ptr, *end = NULL;
	if (!str || !ch) {
		return NULL;
	}
	do {
		ptr = strstr (str, ch);
		if (!ptr) {
			break;
		}
		end = ptr;
		str = ptr + 1;
	} while (true);
	return end;
}

// copies the WHOLE string but check n against non color code chars only.
static int strncpy_with_color_codes(char *s1, char *s2, int n) {
	int i = 0, j = 0;
	int count = 0;
	while (s2[j] && count < n) {
		// detect (consecutive) color codes
		while (s2[j] == 0x1b) {
			// copy till 'm'
			while (s2[j] && s2[j] != 'm') {
				s1[i++] = s2[j++];
			}
			// copy 'm'
			if (s2[j]) {
				s1[i++] = s2[j++];
			}
		}
		if (s2[j]) {
			s1[i++] = s2[j++];
			count++;
		}
	}
	return i;
}

static int strncmp_skip_color_codes(const char *s1, const char *s2, int n) {
	int i = 0, j = 0;
	int count = 0;
	for (i = 0, j = 0; s1[i]  && s2[j] && count < n; i++, j++, count++) {
		while (s1[i] == 0x1b) {
			while (s1[i] && s1[i] != 'm') {
				i++;
			}
			if (s1[i]) {
				i++;
			}
		}
		while (s2[j] == 0x1b) {
			while (s2[j] && s2[j] != 'm') {
				j++;
			}
			if (s2[j]) {
				j++;
			}
		}
		if (s1[i] != s2[j]) {
			return -1;
		}
	}

	if (count < n && s1[i] != s2[j]) {
		return -1;
	}

	return 0;
}

static char *strchr_skip_color_codes(const char *s, int c) {
	int i = 0;
	for (i = 0; s[i]; i++) {
		while (s[i] && s[i] == 0x1b) {
			while (s[i] && s[i] != 'm') {
				i++;
			}
			if (s[i]) {
				i++;
			}
		}
		if (!s[i] || s[i] == (char)c) {
			return (char*)s + i;
		}
	}
	return NULL;
}

// Global buffer to speed up colorizing performance

R_API char* r_str_highlight(char *str, const char *word, const char *color, const char *color_reset) {
	if (!str || !*str) {
		return NULL;
	}
	ut32 i = 0, j = 0, to_copy;
	char *start = str;
	ut32 l_str = strlen (str);
	ut32 l_reset = strlen (color_reset);
	ut32 l_color = color? strlen (color): 0;
	if (!color) {
		return strdup (str);
	}
	if (!word || !*word) {
		return r_str_newf ("%s%s%s", color, str, color_reset);
	}
	ut32 l_word = strlen (word);
	// XXX don't use static buffers
	char o[1024] = {0};
	while (start && (start < str + l_str)) {
		int copied = 0;
		// find first letter
		start = strchr_skip_color_codes (str + i, *word);
		if (start) {
			to_copy = start - (str + i);
			if (to_copy + j + 1 > sizeof (o)) {
				// XXX. no limits
				break;
			}
			strncpy (o + j, str + i, to_copy);
			i += to_copy;
			j += to_copy;
			if (!strncmp_skip_color_codes (start, word, l_word)) {
				if (j + strlen (color) >= sizeof (o)) {
					// XXX. no limits
					break;
				}
				strcpy (o + j, color);
				j += l_color;
				if (j + l_word >= sizeof (o)) {
					// XXX. no limits
					break;
				}
				copied = strncpy_with_color_codes (o + j, str + i, l_word);
				i += copied;
				j += copied;
				if (j + strlen (color_reset) >= sizeof (o)) {
					// XXX. no limits
					break;
				}
				strcpy (o + j, color_reset);
				j += l_reset;
			} else {
				o[j++] = str[i++];
			}
		} else {
			if (j + strlen (str + i) >= sizeof (o)) {
				break;
			}
			strcpy (o + j, str + i);
			break;
		}
	}
	return strdup (o);
}

R_API wchar_t* r_str_mb_to_wc_l(const char *buf, int len) {
	wchar_t *res_buf = NULL;
	size_t sz;
	bool fail = true;

	if (!buf || len <= 0) {
		return NULL;
	}
	sz = mbstowcs (NULL, buf, len);
	if (sz == (size_t)-1) {
		goto err_r_str_mb_to_wc;
	}
	res_buf = (wchar_t *)calloc (1, (sz + 1) * sizeof (wchar_t));
	if (!res_buf) {
		goto err_r_str_mb_to_wc;
	}
	sz = mbstowcs (res_buf, buf, sz + 1);
	if (sz == (size_t)-1) {
		goto err_r_str_mb_to_wc;
	}
	fail = false;
err_r_str_mb_to_wc:
	if (fail) {
		R_FREE (res_buf);
	}
	return res_buf;
}

R_API char* r_str_wc_to_mb_l(const wchar_t *buf, int len) {
	char *res_buf = NULL;
	bool fail = true;
	size_t sz;

	if (!buf || len <= 0) {
		return NULL;
	}
	sz = wcstombs (NULL, buf, len);
	if (sz == (size_t)-1) {
		goto err_r_str_wc_to_mb;
	}
	res_buf = (char *)calloc (1, (sz + 1) * sizeof (char));
	if (!res_buf) {
		goto err_r_str_wc_to_mb;
	}
	sz = wcstombs (res_buf, buf, sz + 1);
	if (sz == (size_t)-1) {
		goto err_r_str_wc_to_mb;
	}
	fail = false;
err_r_str_wc_to_mb:
	if (fail) {
		R_FREE (res_buf);
	}
	return res_buf;
}

R_API char* r_str_wc_to_mb(const wchar_t *buf) {
	if (!buf) {
		return NULL;
	}
	return r_str_wc_to_mb_l (buf, wcslen (buf));
}

R_API wchar_t* r_str_mb_to_wc(const char *buf) {
	if (!buf) {
		return NULL;
	}
	return r_str_mb_to_wc_l (buf, strlen (buf));
}

R_API char *r_str_from_ut64(ut64 val) {
	int i = 0;
	char *v = (char *)&val;
	char *str = (char *)calloc(1, 9);
	if (!str) {
		return NULL;
	}
	while (i < 8 && *v) {
		str[i++] = *v++;
	}
	return str;
}

R_API int r_snprintf(char *string, int len, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	int ret = vsnprintf (string, len, fmt, ap);
	string[len - 1] = 0;
	va_end (ap);
	return ret;
}

// Strips all the lines in str that contain key
R_API void r_str_stripLine(char *str, const char *key) {
	size_t i, j, klen, slen, off;
	const char *ptr;

	if (!str || !key) {
		return;
	}
	klen = strlen (key);
	slen = strlen (str);

	for (i = 0; i < slen; ) {
		ptr = (char*) r_mem_mem ((ut8*) str + i, slen - i, (ut8*) "\n", 1);
		if (!ptr) {
			ptr = (char*) r_mem_mem ((ut8*) str + i, slen - i, (ut8*) key, klen);
			if (ptr) {
				str[i] = '\0';
				break;
			}
			break;
		}

		off = (size_t) (ptr - (str + i)) + 1;

		ptr = (char*) r_mem_mem ((ut8*) str + i, off, (ut8*) key, klen);
		if (ptr) {
			for (j = i; j < slen - off + 1; j++) {
				str[j] = str[j + off];
			}
			slen -= off;
		} else {
			i += off;
		}
	}
}

R_API char *r_str_list_join(RList *str, const char *sep) {
	RStrBuf *sb = r_strbuf_new ("");
	const char *p;
	while ((p = r_list_pop_head (str))) {
		if (r_strbuf_length (sb) != 0) {
			r_strbuf_append (sb, sep);
		}
		r_strbuf_append (sb, p);
	}
	return r_strbuf_drain (sb);
}

R_API char *r_str_array_join(const char **a, size_t n, const char *sep) {
	RStrBuf *sb = r_strbuf_new ("");
	size_t i;

	if (n > 0) {
		r_strbuf_append (sb, a[0]);
	}

	for (i = 1; i < n; i++) {
		r_strbuf_append (sb, sep);
		r_strbuf_append (sb, a[i]);
	}
	return r_strbuf_drain (sb);
}

/* return the number of arguments expected as extra arguments */
R_API int r_str_fmtargs(const char *fmt) {
	int n = 0;
	while (*fmt) {
		if (*fmt == '%') {
			if (fmt[1] == '*') {
				n++;
			}
			n++;
		}
		fmt++;
	}
	return n;
}

// str-bool

// Returns "true" or "false" as a string given an input integer. The returned
// value is consistent with C's definition of 0 is false, and all other values
// are true.
R_API const char *r_str_bool(int b) {
	return b? "true": "false";
}

R_API bool r_str_is_true(const char *s) {
	return !r_str_casecmp ("yes", s)
		|| !r_str_casecmp ("on", s)
		|| !r_str_casecmp ("true", s)
		|| !r_str_casecmp ("1", s);
}

R_API bool r_str_is_false(const char *s) {
	return !r_str_casecmp ("no", s)
		|| !r_str_casecmp ("off", s)
		|| !r_str_casecmp ("false", s)
		|| !r_str_casecmp ("0", s)
		|| !*s;
}

R_API bool r_str_is_bool(const char *val) {
	return r_str_is_true (val) || r_str_is_false (val);
}

R_API char *r_str_nextword(char *s, char ch) {
	char *p = strchr (s, ch);
	if (!p) {
		return NULL;
	}
	*p++ = 0;
	return p;
}

R_API char *r_str_scale(const char *s, int w, int h) {
	// count lines and rows in (s) string
	// compute how many lines we should remove or combine
	// return a string containing
	// for now this function is ascii only (no utf8 or ansi escapes)
	RListIter *iter;
	char *line;
	char *str = strdup (s);
	RList *lines = r_str_split_list (str, "\n", 0);
	int i, j;
	int rows = 0;
	int maxcol = 0;

	rows = r_list_length (lines);
	r_list_foreach (lines, iter, line) {
		maxcol = R_MAX (strlen (line), maxcol);
	}

	RList *out = r_list_newf (free);

	int curline = -1;
	char *linetext = (char*)r_str_pad (' ', w);
	for (i = 0; i < h; i++) {
		int zoomedline = i * ((float)rows / h);
		const char *srcline = r_list_get_n (lines, zoomedline);
		int cols = strlen (srcline);
		for (j = 0; j < w; j++) {
			int zoomedcol = j * ( (float)cols / w);
			linetext[j] = srcline[zoomedcol];
		}
		if (curline != zoomedline) {
			r_list_append (out, strdup (linetext));
			curline = zoomedline;
		}
		memset (linetext, ' ', w);
	}
	free (str);
	return r_str_list_join (out, "\n");
}

R_API const char *r_str_str_xy(const char *s, const char *word, const char *prev, int *x, int *y) {
	r_return_val_if_fail (s && word && x && y, NULL);
	r_return_val_if_fail (word[0] != '\0' && word[0] != '\n', NULL);
	const char *src = prev ? prev + 1 : s;
	const char *d = strstr (src, word);
	if (!d) {
		return NULL;
	}
	const char *q;
	for (q = prev ? prev : s; q < d; q++) {
		if (*q == '\n') {
			(*y)++;
			*x = 0;

		} else {
			(*x)++;
		}
	}
	return d;
}

// version.c
#include <r_userconf.h>
#include <r_util.h>

#ifndef R2_GITTAP
#define R2_GITTAP ""
#endif

#ifndef R2_GITTIP
#define R2_GITTIP ""
#endif

#ifndef R2_BIRTH
#define R2_BIRTH "unknown"
#endif

R_API char *r_str_version(const char *program) {
	char *s = r_str_newf ("%s "R2_VERSION" %d @ "
			R_SYS_OS"-"
			R_SYS_ARCH"-%d git.%s\n",
			program, R2_VERSION_COMMIT,
			(R_SYS_BITS & 8)? 64: 32,
			*R2_GITTAP ? R2_GITTAP: "");
	if (*R2_GITTIP) {
		s = r_str_appendf (s, "commit: "R2_GITTIP" build: "R2_BIRTH);
	}
	return s;
}

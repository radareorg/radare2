/* radare2 freestanding libc for UEFI targets - LGPL - Copyright 2026 - pancake */

/* This file implements the subset of libc that radare2 needs when running
 * as an EFI application. Console io is backed by the simple text protocols,
 * the heap by the boot services pool allocator and file io by the simple
 * file system protocol of the volume the application was loaded from.
 * The EFI application entrypoint must call r_uefi_init (image, systab)
 * before using any of these functions. */

#if defined(R2_UEFI) && R2_UEFI

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#define GNU_EFI_USE_MS_ABI 1
#include <efi.h>

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>
#include <termios.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <locale.h>
#include <ctype.h>
#include <wctype.h>
#include <poll.h>

int *__errno_location(void) {
	static int e = 0;
	return &e;
}

int *__h_errno_location(void) {
	static int e = 0;
	return &e;
}

char **environ = NULL;
char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = 0;
long timezone = 0;
int daylight = 0;
char *tzname[2] = { "UTC", "UTC" };

static EFI_HANDLE r2efi_image = NULL;
static EFI_SYSTEM_TABLE *r2efi_st = NULL;
static EFI_BOOT_SERVICES *r2efi_bs = NULL;
static EFI_RUNTIME_SERVICES *r2efi_rt = NULL;
static EFI_FILE_HANDLE r2efi_root = NULL;

void r_uefi_init(void *image_handle, void *system_table) {
	r2efi_image = (EFI_HANDLE)image_handle;
	r2efi_st = (EFI_SYSTEM_TABLE *)system_table;
	if (r2efi_st) {
		r2efi_bs = r2efi_st->BootServices;
		r2efi_rt = r2efi_st->RuntimeServices;
	}
}

bool r_uefi_initialized(void) {
	return r2efi_bs != NULL;
}

/* ---------- memory ---------- */

void *memcpy(void *dst, const void *src, size_t n) {
	unsigned char *d = dst;
	const unsigned char *s = src;
	while (n--) {
		*d++ = *s++;
	}
	return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
	unsigned char *d = dst;
	const unsigned char *s = src;
	if (d == s || !n) {
		return dst;
	}
	if (d < s) {
		while (n--) {
			*d++ = *s++;
		}
	} else {
		while (n--) {
			d[n] = s[n];
		}
	}
	return dst;
}

void *memset(void *s, int c, size_t n) {
	unsigned char *p = s;
	while (n--) {
		*p++ = (unsigned char)c;
	}
	return s;
}

int memcmp(const void *a, const void *b, size_t n) {
	const unsigned char *x = a, *y = b;
	for (; n; n--, x++, y++) {
		if (*x != *y) {
			return *x - *y;
		}
	}
	return 0;
}

void *memchr(const void *s, int c, size_t n) {
	const unsigned char *p = s;
	while (n--) {
		if (*p == (unsigned char)c) {
			return (void *)p;
		}
		p++;
	}
	return NULL;
}

void *memrchr(const void *s, int c, size_t n) {
	const unsigned char *p = (const unsigned char *)s + n;
	while (n--) {
		if (*--p == (unsigned char)c) {
			return (void *)p;
		}
	}
	return NULL;
}

void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen) {
	if (!nlen) {
		return (void *)haystack;
	}
	if (hlen < nlen) {
		return NULL;
	}
	const unsigned char *h = haystack;
	size_t last = hlen - nlen;
	size_t i;
	for (i = 0; i <= last; i++) {
		if (h[i] == *(const unsigned char *)needle && !memcmp (h + i, needle, nlen)) {
			return (void *)(h + i);
		}
	}
	return NULL;
}

void bzero(void *s, size_t n) {
	memset (s, 0, n);
}

void explicit_bzero(void *s, size_t n) {
	memset (s, 0, n);
	__asm__ volatile ("": : "r" (s): "memory");
}

void bcopy(const void *src, void *dest, size_t n) {
	memmove (dest, src, n);
}

int ffs(int i) {
	return i? __builtin_ffs (i): 0;
}

/* ---------- allocator ---------- */

/* boot services pool allocations are prefixed with their size so realloc
 * can copy the right amount; a static arena serves any allocation done
 * before r_uefi_init gets called */

#define R2EFI_ARENA_SIZE (512 * 1024)
static unsigned char r2efi_arena[R2EFI_ARENA_SIZE];
static size_t r2efi_arena_pos = 0;

typedef struct {
	size_t size;
	size_t magic;
} R2EfiChunk;

#define R2EFI_CHUNK_MAGIC ((size_t)0x52454649)

static bool r2efi_in_arena(void *p) {
	unsigned char *u = p;
	return u >= r2efi_arena && u < r2efi_arena + R2EFI_ARENA_SIZE;
}

void *malloc(size_t n) {
	if (!n) {
		n = 1;
	}
	if (!r2efi_bs) {
		size_t aligned = (n + 31) & ~(size_t)15;
		if (r2efi_arena_pos + aligned + 16 > R2EFI_ARENA_SIZE) {
			errno = ENOMEM;
			return NULL;
		}
		R2EfiChunk *c = (R2EfiChunk *)(r2efi_arena + r2efi_arena_pos);
		c->size = n;
		c->magic = R2EFI_CHUNK_MAGIC;
		r2efi_arena_pos += aligned + 16;
		return c + 1;
	}
	R2EfiChunk *c = NULL;
	if (r2efi_bs->AllocatePool (EfiLoaderData, n + sizeof (R2EfiChunk), (void **)&c) != EFI_SUCCESS) {
		errno = ENOMEM;
		return NULL;
	}
	c->size = n;
	c->magic = R2EFI_CHUNK_MAGIC;
	return c + 1;
}

void free(void *p) {
	if (!p) {
		return;
	}
	if (r2efi_in_arena (p)) {
		return;
	}
	R2EfiChunk *c = (R2EfiChunk *)p - 1;
	if (c->magic != R2EFI_CHUNK_MAGIC || !r2efi_bs) {
		return;
	}
	c->magic = 0;
	r2efi_bs->FreePool (c);
}

void *calloc(size_t nm, size_t sz) {
	if (sz && nm > (size_t)-1 / sz) {
		errno = ENOMEM;
		return NULL;
	}
	size_t n = nm * sz;
	void *p = malloc (n);
	if (p) {
		memset (p, 0, n);
	}
	return p;
}

void *realloc(void *p, size_t n) {
	if (!p) {
		return malloc (n);
	}
	if (!n) {
		free (p);
		return NULL;
	}
	R2EfiChunk *c = (R2EfiChunk *)p - 1;
	size_t old = (c->magic == R2EFI_CHUNK_MAGIC)? c->size: n;
	void *q = malloc (n);
	if (!q) {
		return NULL;
	}
	memcpy (q, p, (old < n)? old: n);
	free (p);
	return q;
}

void *aligned_alloc(size_t alignment, size_t size) {
	(void)alignment;
	return malloc (size);
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
	(void)alignment;
	void *p = malloc (size);
	if (!p) {
		return ENOMEM;
	}
	*memptr = p;
	return 0;
}

/* ---------- strings ---------- */

size_t strlen(const char *s) {
	const char *p = s;
	while (*p) {
		p++;
	}
	return (size_t)(p - s);
}

size_t strnlen(const char *s, size_t maxlen) {
	size_t i = 0;
	while (i < maxlen && s[i]) {
		i++;
	}
	return i;
}

char *strcpy(char *dst, const char *src) {
	char *d = dst;
	while ((*d++ = *src++)) {
	}
	return dst;
}

char *strncpy(char *dst, const char *src, size_t n) {
	size_t i;
	for (i = 0; i < n && src[i]; i++) {
		dst[i] = src[i];
	}
	for (; i < n; i++) {
		dst[i] = 0;
	}
	return dst;
}

size_t strlcpy(char *dst, const char *src, size_t size) {
	size_t slen = strlen (src);
	if (size) {
		size_t n = (slen >= size)? size - 1: slen;
		memcpy (dst, src, n);
		dst[n] = 0;
	}
	return slen;
}

size_t strlcat(char *dst, const char *src, size_t size) {
	size_t dlen = strnlen (dst, size);
	if (dlen == size) {
		return size + strlen (src);
	}
	return dlen + strlcpy (dst + dlen, src, size - dlen);
}

char *strcat(char *dst, const char *src) {
	strcpy (dst + strlen (dst), src);
	return dst;
}

char *strncat(char *dst, const char *src, size_t n) {
	char *d = dst + strlen (dst);
	size_t i;
	for (i = 0; i < n && src[i]; i++) {
		d[i] = src[i];
	}
	d[i] = 0;
	return dst;
}

int strcmp(const char *a, const char *b) {
	for (; *a && (*a == *b); a++, b++) {
	}
	return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n) {
	for (; n && *a && (*a == *b); a++, b++, n--) {
	}
	return n? (unsigned char)*a - (unsigned char)*b: 0;
}

int strcoll(const char *a, const char *b) {
	return strcmp (a, b);
}

size_t strxfrm(char *dst, const char *src, size_t n) {
	size_t l = strlen (src);
	if (n) {
		strlcpy (dst, src, n);
	}
	return l;
}

char *strchr(const char *s, int c) {
	char ch = (char)c;
	while (*s) {
		if (*s == ch) {
			return (char *)s;
		}
		s++;
	}
	return (ch == 0)? (char *)s: NULL;
}

char *strrchr(const char *s, int c) {
	const char *last = NULL;
	char ch = (char)c;
	do {
		if (*s == ch) {
			last = s;
		}
	} while (*s++);
	return (char *)last;
}

char *strstr(const char *haystack, const char *needle) {
	size_t nlen = strlen (needle);
	if (!nlen) {
		return (char *)haystack;
	}
	while (*haystack) {
		if (*haystack == *needle && !strncmp (haystack, needle, nlen)) {
			return (char *)haystack;
		}
		haystack++;
	}
	return NULL;
}

static int r2efi_lower(int c) {
	return (c >= 'A' && c <= 'Z')? c + 0x20: c;
}

int strcasecmp(const char *a, const char *b) {
	while (*a && r2efi_lower ((unsigned char)*a) == r2efi_lower ((unsigned char)*b)) {
		a++;
		b++;
	}
	return r2efi_lower ((unsigned char)*a) - r2efi_lower ((unsigned char)*b);
}

int strncasecmp(const char *a, const char *b, size_t n) {
	for (; n && *a && r2efi_lower ((unsigned char)*a) == r2efi_lower ((unsigned char)*b); a++, b++, n--) {
	}
	return n? r2efi_lower ((unsigned char)*a) - r2efi_lower ((unsigned char)*b): 0;
}

char *strcasestr(const char *haystack, const char *needle) {
	size_t nlen = strlen (needle);
	if (!nlen) {
		return (char *)haystack;
	}
	while (*haystack) {
		if (!strncasecmp (haystack, needle, nlen)) {
			return (char *)haystack;
		}
		haystack++;
	}
	return NULL;
}

size_t strspn(const char *s, const char *accept) {
	size_t n = 0;
	while (s[n] && strchr (accept, s[n])) {
		n++;
	}
	return n;
}

size_t strcspn(const char *s, const char *reject) {
	size_t n = 0;
	while (s[n] && !strchr (reject, s[n])) {
		n++;
	}
	return n;
}

char *strpbrk(const char *s, const char *accept) {
	while (*s) {
		if (strchr (accept, *s)) {
			return (char *)s;
		}
		s++;
	}
	return NULL;
}

char *strtok_r(char *str, const char *delim, char **saveptr) {
	if (!str) {
		str = *saveptr;
	}
	if (!str) {
		return NULL;
	}
	str += strspn (str, delim);
	if (!*str) {
		*saveptr = NULL;
		return NULL;
	}
	char *end = str + strcspn (str, delim);
	if (*end) {
		*end = 0;
		*saveptr = end + 1;
	} else {
		*saveptr = NULL;
	}
	return str;
}

char *strtok(char *str, const char *delim) {
	static char *save = NULL;
	return strtok_r (str, delim, &save);
}

char *strdup(const char *s) {
	size_t n = strlen (s) + 1;
	char *p = malloc (n);
	if (p) {
		memcpy (p, s, n);
	}
	return p;
}

char *strndup(const char *s, size_t n) {
	size_t l = strnlen (s, n);
	char *p = malloc (l + 1);
	if (p) {
		memcpy (p, s, l);
		p[l] = 0;
	}
	return p;
}

char *strsep(char **stringp, const char *delim) {
	char *s = *stringp;
	if (!s) {
		return NULL;
	}
	char *end = s + strcspn (s, delim);
	if (*end) {
		*end = 0;
		*stringp = end + 1;
	} else {
		*stringp = NULL;
	}
	return s;
}

char *strerror(int errnum) {
	switch (errnum) {
	case 0: return "Success";
	case EPERM: return "Operation not permitted";
	case ENOENT: return "No such file or directory";
	case EIO: return "Input/output error";
	case EBADF: return "Bad file descriptor";
	case ENOMEM: return "Cannot allocate memory";
	case EACCES: return "Permission denied";
	case EEXIST: return "File exists";
	case ENOTDIR: return "Not a directory";
	case EISDIR: return "Is a directory";
	case EINVAL: return "Invalid argument";
	case ENOSPC: return "No space left on device";
	case ERANGE: return "Numerical result out of range";
	case ENOSYS: return "Function not implemented";
	}
	return "Unknown error";
}

int strerror_r(int errnum, char *buf, size_t buflen) {
	strlcpy (buf, strerror (errnum), buflen);
	return 0;
}

/* ---------- wide chars (ascii-only) ---------- */

#include <wchar.h>

size_t wcslen(const wchar_t *s) {
	size_t n = 0;
	while (s[n]) {
		n++;
	}
	return n;
}

size_t mbstowcs(wchar_t *dest, const char *src, size_t n) {
	size_t i = 0;
	if (!dest) {
		return strlen (src);
	}
	while (i < n && src[i]) {
		dest[i] = (wchar_t)(unsigned char)src[i];
		i++;
	}
	if (i < n) {
		dest[i] = 0;
	}
	return i;
}

size_t wcstombs(char *dest, const wchar_t *src, size_t n) {
	size_t i = 0;
	if (!dest) {
		return wcslen (src);
	}
	while (i < n && src[i]) {
		dest[i] = (char)(src[i] & 0xff);
		i++;
	}
	if (i < n) {
		dest[i] = 0;
	}
	return i;
}

int mblen(const char *s, size_t n) {
	if (!s) {
		return 0;
	}
	return (n && *s)? 1: 0;
}

int mbtowc(wchar_t *pwc, const char *s, size_t n) {
	if (!s) {
		return 0;
	}
	if (!n || !*s) {
		return 0;
	}
	if (pwc) {
		*pwc = (wchar_t)(unsigned char)*s;
	}
	return 1;
}

int wctomb(char *s, wchar_t wc) {
	if (!s) {
		return 0;
	}
	*s = (char)(wc & 0xff);
	return 1;
}

/* ---------- number parsing ---------- */

static int r2efi_digit(int c, int base) {
	int v;
	if (c >= '0' && c <= '9') {
		v = c - '0';
	} else if (c >= 'a' && c <= 'z') {
		v = c - 'a' + 10;
	} else if (c >= 'A' && c <= 'Z') {
		v = c - 'A' + 10;
	} else {
		return -1;
	}
	return (v < base)? v: -1;
}

unsigned long long strtoull(const char *nptr, char **endptr, int base) {
	const char *s = nptr;
	while (*s == ' ' || (*s >= '\t' && *s <= '\r')) {
		s++;
	}
	bool neg = false;
	if (*s == '+' || *s == '-') {
		neg = (*s == '-');
		s++;
	}
	if ((base == 0 || base == 16) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') && r2efi_digit (s[2], 16) >= 0) {
		s += 2;
		base = 16;
	} else if (base == 0) {
		base = (s[0] == '0')? 8: 10;
	}
	unsigned long long v = 0;
	bool any = false;
	int d;
	while ((d = r2efi_digit (*s, base)) >= 0) {
		v = v * (unsigned)base + (unsigned)d;
		s++;
		any = true;
	}
	if (endptr) {
		*endptr = (char *)(any? s: nptr);
	}
	return neg? (unsigned long long)-(long long)v: v;
}

long long strtoll(const char *nptr, char **endptr, int base) {
	return (long long)strtoull (nptr, endptr, base);
}

unsigned long strtoul(const char *nptr, char **endptr, int base) {
	return (unsigned long)strtoull (nptr, endptr, base);
}

long strtol(const char *nptr, char **endptr, int base) {
	return (long)strtoull (nptr, endptr, base);
}

intmax_t strtoimax(const char *nptr, char **endptr, int base) {
	return (intmax_t)strtoull (nptr, endptr, base);
}

uintmax_t strtoumax(const char *nptr, char **endptr, int base) {
	return (uintmax_t)strtoull (nptr, endptr, base);
}

double strtod(const char *nptr, char **endptr) {
	const char *s = nptr;
	while (*s == ' ' || (*s >= '\t' && *s <= '\r')) {
		s++;
	}
	bool neg = false;
	if (*s == '+' || *s == '-') {
		neg = (*s == '-');
		s++;
	}
	double v = 0;
	bool any = false;
	while (*s >= '0' && *s <= '9') {
		v = v * 10 + (*s - '0');
		s++;
		any = true;
	}
	if (*s == '.') {
		s++;
		double f = 0.1;
		while (*s >= '0' && *s <= '9') {
			v += (*s - '0') * f;
			f *= 0.1;
			s++;
			any = true;
		}
	}
	if (any && (*s == 'e' || *s == 'E')) {
		const char *e = s + 1;
		bool eneg = false;
		if (*e == '+' || *e == '-') {
			eneg = (*e == '-');
			e++;
		}
		if (*e >= '0' && *e <= '9') {
			int ev = 0;
			while (*e >= '0' && *e <= '9') {
				ev = ev * 10 + (*e - '0');
				e++;
			}
			while (ev-- > 0) {
				v = eneg? v * 0.1: v * 10;
			}
			s = e;
		}
	}
	if (endptr) {
		*endptr = (char *)(any? s: nptr);
	}
	return neg? -v: v;
}

float strtof(const char *nptr, char **endptr) {
	return (float)strtod (nptr, endptr);
}

double atof(const char *nptr) {
	return strtod (nptr, NULL);
}

int atoi(const char *nptr) {
	return (int)strtol (nptr, NULL, 10);
}

long atol(const char *nptr) {
	return strtol (nptr, NULL, 10);
}

long long atoll(const char *nptr) {
	return strtoll (nptr, NULL, 10);
}

int abs(int j) {
	return j < 0? -j: j;
}

long labs(long j) {
	return j < 0? -j: j;
}

long long llabs(long long j) {
	return j < 0? -j: j;
}

intmax_t imaxabs(intmax_t j) {
	return j < 0? -j: j;
}

div_t div(int numer, int denom) {
	div_t r = { numer / denom, numer % denom };
	return r;
}

ldiv_t ldiv(long numer, long denom) {
	ldiv_t r = { numer / denom, numer % denom };
	return r;
}

lldiv_t lldiv(long long numer, long long denom) {
	lldiv_t r = { numer / denom, numer % denom };
	return r;
}

imaxdiv_t imaxdiv(intmax_t numer, intmax_t denom) {
	imaxdiv_t r = { numer / denom, numer % denom };
	return r;
}

static unsigned long long r2efi_seed = 0x2545f4914f6cdd1dULL;

int rand(void) {
	r2efi_seed ^= r2efi_seed << 13;
	r2efi_seed ^= r2efi_seed >> 7;
	r2efi_seed ^= r2efi_seed << 17;
	return (int)(r2efi_seed & RAND_MAX);
}

void srand(unsigned int seed) {
	r2efi_seed = seed? seed: 1;
}

long random(void) {
	return rand ();
}

void srandom(unsigned int seed) {
	srand (seed);
}

/* ---------- sorting ---------- */

void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)) {
	/* shell sort: no recursion and no allocations */
	unsigned char *b = base;
	size_t gap, i, j, k;
	if (nmemb < 2 || !size) {
		return;
	}
	for (gap = nmemb / 2; gap > 0; gap /= 2) {
		for (i = gap; i < nmemb; i++) {
			for (j = i; j >= gap && compar (b + (j - gap) * size, b + j * size) > 0; j -= gap) {
				unsigned char *x = b + (j - gap) * size;
				unsigned char *y = b + j * size;
				for (k = 0; k < size; k++) {
					unsigned char t = x[k];
					x[k] = y[k];
					y[k] = t;
				}
			}
		}
	}
}

void *bsearch(const void *key, const void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)) {
	size_t lo = 0, hi = nmemb;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		const void *p = (const unsigned char *)base + mid * size;
		int c = compar (key, p);
		if (!c) {
			return (void *)p;
		}
		if (c < 0) {
			hi = mid;
		} else {
			lo = mid + 1;
		}
	}
	return NULL;
}

/* ---------- console ---------- */

static void r2efi_putws(const CHAR16 *ws) {
	if (r2efi_st && r2efi_st->ConOut) {
		r2efi_st->ConOut->OutputString (r2efi_st->ConOut, (CHAR16 *)ws);
	}
}

static void r2efi_conwrite(const char *buf, size_t len) {
	CHAR16 tmp[128];
	size_t i, o = 0;
	for (i = 0; i < len; i++) {
		if (o >= 125) {
			tmp[o] = 0;
			r2efi_putws (tmp);
			o = 0;
		}
		if (buf[i] == '\n') {
			tmp[o++] = '\r';
		}
		tmp[o++] = (CHAR16)(unsigned char)buf[i];
	}
	tmp[o] = 0;
	if (o) {
		r2efi_putws (tmp);
	}
}

static int r2efi_congetc(void) {
	if (!r2efi_st || !r2efi_st->ConIn || !r2efi_bs) {
		return -1;
	}
	EFI_INPUT_KEY key;
	UINTN idx;
	for (;;) {
		if (r2efi_st->ConIn->ReadKeyStroke (r2efi_st->ConIn, &key) == EFI_SUCCESS) {
			if (key.UnicodeChar == '\r') {
				return '\n';
			}
			if (key.UnicodeChar) {
				return (int)(key.UnicodeChar & 0xff);
			}
			continue;
		}
		r2efi_bs->WaitForEvent (1, &r2efi_st->ConIn->WaitForKey, &idx);
	}
}

/* ---------- file descriptors ---------- */

#define R2EFI_NFD 128

typedef struct {
	EFI_FILE_HANDLE h;
	bool used;
	bool dir;
} R2EfiFd;

static R2EfiFd r2efi_fds[R2EFI_NFD];

static EFI_GUID r2efi_sfs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
static EFI_GUID r2efi_finfo_guid = EFI_FILE_INFO_ID;

static char r2efi_cwd[512] = "\\";

static EFI_FILE_HANDLE r2efi_get_root(void) {
	if (r2efi_root || !r2efi_bs) {
		return r2efi_root;
	}
	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfs = NULL;
	if (r2efi_bs->LocateProtocol (&r2efi_sfs_guid, NULL, (void **)&sfs) != EFI_SUCCESS || !sfs) {
		return NULL;
	}
	EFI_FILE_HANDLE root = NULL;
	if (sfs->OpenVolume (sfs, &root) != EFI_SUCCESS) {
		return NULL;
	}
	r2efi_root = root;
	return root;
}

static void r2efi_wpath(const char *path, CHAR16 *out, size_t outsz) {
	char full[512];
	if (path[0] == '/' || path[0] == '\\') {
		strlcpy (full, path, sizeof (full));
	} else {
		strlcpy (full, r2efi_cwd, sizeof (full));
		size_t l = strlen (full);
		if (l && full[l - 1] != '\\' && full[l - 1] != '/') {
			strlcat (full, "\\", sizeof (full));
		}
		strlcat (full, path, sizeof (full));
	}
	size_t i;
	for (i = 0; full[i] && i + 1 < outsz; i++) {
		out[i] = (full[i] == '/')? '\\': (CHAR16)(unsigned char)full[i];
	}
	out[i] = 0;
}

static int r2efi_newfd(void) {
	int i;
	for (i = 3; i < R2EFI_NFD; i++) {
		if (!r2efi_fds[i].used) {
			return i;
		}
	}
	errno = EMFILE;
	return -1;
}

int open(const char *pathname, int flags, ...) {
	EFI_FILE_HANDLE root = r2efi_get_root ();
	if (!root) {
		errno = ENOSYS;
		return -1;
	}
	int fd = r2efi_newfd ();
	if (fd < 0) {
		return -1;
	}
	CHAR16 wpath[512];
	r2efi_wpath (pathname, wpath, 512);
	UINT64 mode = EFI_FILE_MODE_READ;
	if ((flags & O_ACCMODE) != O_RDONLY) {
		mode |= EFI_FILE_MODE_WRITE;
	}
	if (flags & O_CREAT) {
		mode |= EFI_FILE_MODE_CREATE;
	}
	EFI_FILE_HANDLE fh = NULL;
	EFI_STATUS s = root->Open (root, &fh, wpath, mode, 0);
	if (s != EFI_SUCCESS || !fh) {
		errno = (s == EFI_NOT_FOUND)? ENOENT: EACCES;
		return -1;
	}
	if (flags & O_TRUNC) {
		/* recreate the file to drop its contents */
		fh->Delete (fh);
		fh = NULL;
		if (root->Open (root, &fh, wpath, mode | EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE, 0) != EFI_SUCCESS || !fh) {
			errno = EACCES;
			return -1;
		}
	}
	r2efi_fds[fd].h = fh;
	r2efi_fds[fd].used = true;
	r2efi_fds[fd].dir = false;
	if (flags & O_APPEND) {
		fh->SetPosition (fh, 0xffffffffffffffffULL);
	}
	return fd;
}

int creat(const char *pathname, mode_t mode_) {
	(void)mode_;
	return open (pathname, O_WRONLY | O_CREAT | O_TRUNC);
}

int close(int fd) {
	if (fd < 3) {
		return 0;
	}
	if (fd >= R2EFI_NFD || !r2efi_fds[fd].used) {
		errno = EBADF;
		return -1;
	}
	if (r2efi_fds[fd].h) {
		r2efi_fds[fd].h->Close (r2efi_fds[fd].h);
	}
	r2efi_fds[fd].used = false;
	r2efi_fds[fd].h = NULL;
	return 0;
}

ssize_t read(int fd, void *buf, size_t count) {
	if (fd == 0) {
		/* console line input */
		char *out = buf;
		size_t n = 0;
		while (n < count) {
			int c = r2efi_congetc ();
			if (c < 0) {
				break;
			}
			out[n++] = (char)c;
			r2efi_conwrite ((const char *)&out[n - 1], 1);
			if (c == '\n') {
				break;
			}
		}
		return (ssize_t)n;
	}
	if (fd < 3 || fd >= R2EFI_NFD || !r2efi_fds[fd].used) {
		errno = EBADF;
		return -1;
	}
	UINTN sz = count;
	if (r2efi_fds[fd].h->Read (r2efi_fds[fd].h, &sz, buf) != EFI_SUCCESS) {
		errno = EIO;
		return -1;
	}
	return (ssize_t)sz;
}

ssize_t write(int fd, const void *buf, size_t count) {
	if (fd == 1 || fd == 2) {
		r2efi_conwrite (buf, count);
		return (ssize_t)count;
	}
	if (fd < 3 || fd >= R2EFI_NFD || !r2efi_fds[fd].used) {
		errno = EBADF;
		return -1;
	}
	UINTN sz = count;
	if (r2efi_fds[fd].h->Write (r2efi_fds[fd].h, &sz, (void *)buf) != EFI_SUCCESS) {
		errno = EIO;
		return -1;
	}
	return (ssize_t)sz;
}

off_t lseek(int fd, off_t offset, int whence) {
	if (fd < 3 || fd >= R2EFI_NFD || !r2efi_fds[fd].used) {
		errno = EBADF;
		return -1;
	}
	EFI_FILE_HANDLE h = r2efi_fds[fd].h;
	UINT64 pos = 0;
	if (whence == SEEK_CUR) {
		h->GetPosition (h, &pos);
		pos += (UINT64)offset;
	} else if (whence == SEEK_END) {
		h->SetPosition (h, 0xffffffffffffffffULL);
		h->GetPosition (h, &pos);
		pos += (UINT64)offset;
	} else {
		pos = (UINT64)offset;
	}
	if (h->SetPosition (h, pos) != EFI_SUCCESS) {
		errno = EINVAL;
		return -1;
	}
	return (off_t)pos;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
	off_t cur = lseek (fd, 0, SEEK_CUR);
	if (cur < 0 || lseek (fd, offset, SEEK_SET) < 0) {
		return -1;
	}
	ssize_t r = read (fd, buf, count);
	lseek (fd, cur, SEEK_SET);
	return r;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
	off_t cur = lseek (fd, 0, SEEK_CUR);
	if (cur < 0 || lseek (fd, offset, SEEK_SET) < 0) {
		return -1;
	}
	ssize_t r = write (fd, buf, count);
	lseek (fd, cur, SEEK_SET);
	return r;
}

int unlink(const char *pathname) {
	EFI_FILE_HANDLE root = r2efi_get_root ();
	if (!root) {
		errno = ENOSYS;
		return -1;
	}
	CHAR16 wpath[512];
	r2efi_wpath (pathname, wpath, 512);
	EFI_FILE_HANDLE fh = NULL;
	if (root->Open (root, &fh, wpath, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0) != EFI_SUCCESS || !fh) {
		errno = ENOENT;
		return -1;
	}
	if (fh->Delete (fh) != EFI_SUCCESS) {
		errno = EACCES;
		return -1;
	}
	return 0;
}

int rmdir(const char *pathname) {
	return unlink (pathname);
}

int mkdir(const char *path, mode_t mode_) {
	(void)mode_;
	EFI_FILE_HANDLE root = r2efi_get_root ();
	if (!root) {
		errno = ENOSYS;
		return -1;
	}
	CHAR16 wpath[512];
	r2efi_wpath (path, wpath, 512);
	EFI_FILE_HANDLE fh = NULL;
	EFI_STATUS s = root->Open (root, &fh, wpath,
		EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, EFI_FILE_DIRECTORY);
	if (s != EFI_SUCCESS || !fh) {
		errno = EACCES;
		return -1;
	}
	fh->Close (fh);
	return 0;
}

static int r2efi_stat_handle(EFI_FILE_HANDLE fh, struct stat *st) {
	unsigned char info[sizeof (EFI_FILE_INFO) + 512];
	UINTN sz = sizeof (info);
	memset (st, 0, sizeof (*st));
	if (fh->GetInfo (fh, &r2efi_finfo_guid, &sz, info) != EFI_SUCCESS) {
		errno = EIO;
		return -1;
	}
	EFI_FILE_INFO *fi = (EFI_FILE_INFO *)info;
	st->st_size = (off_t)fi->FileSize;
	st->st_mode = (fi->Attribute & EFI_FILE_DIRECTORY)? (S_IFDIR | 0755): (S_IFREG | 0644);
	st->st_nlink = 1;
	st->st_blksize = 512;
	st->st_blocks = (blkcnt_t)((fi->PhysicalSize + 511) / 512);
	return 0;
}

int stat(const char *path, struct stat *buf) {
	int fd = open (path, O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	int r = r2efi_stat_handle (r2efi_fds[fd].h, buf);
	close (fd);
	return r;
}

int lstat(const char *path, struct stat *buf) {
	return stat (path, buf);
}

int fstat(int fd, struct stat *buf) {
	if (fd < 3) {
		memset (buf, 0, sizeof (*buf));
		buf->st_mode = S_IFCHR | 0666;
		return 0;
	}
	if (fd >= R2EFI_NFD || !r2efi_fds[fd].used) {
		errno = EBADF;
		return -1;
	}
	return r2efi_stat_handle (r2efi_fds[fd].h, buf);
}

int access(const char *pathname, int mode_) {
	(void)mode_;
	struct stat st;
	return stat (pathname, &st);
}

int chmod(const char *path, mode_t mode_) {
	(void)path;
	(void)mode_;
	return 0;
}

int fchmod(int fd, mode_t mode_) {
	(void)fd;
	(void)mode_;
	return 0;
}

mode_t umask(mode_t mask) {
	(void)mask;
	return 022;
}

int mkfifo(const char *path, mode_t mode_) {
	(void)path;
	(void)mode_;
	errno = ENOSYS;
	return -1;
}

int ftruncate(int fd, off_t length) {
	(void)fd;
	(void)length;
	errno = ENOSYS;
	return -1;
}

int truncate(const char *path, off_t length) {
	(void)path;
	(void)length;
	errno = ENOSYS;
	return -1;
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
	(void)pathname;
	(void)buf;
	(void)bufsiz;
	errno = EINVAL;
	return -1;
}

int symlink(const char *target, const char *linkpath) {
	(void)target;
	(void)linkpath;
	errno = ENOSYS;
	return -1;
}

int link(const char *oldpath, const char *newpath) {
	(void)oldpath;
	(void)newpath;
	errno = ENOSYS;
	return -1;
}

int chown(const char *pathname, uid_t owner, gid_t group) {
	(void)pathname;
	(void)owner;
	(void)group;
	return 0;
}

int fsync(int fd) {
	if (fd >= 3 && fd < R2EFI_NFD && r2efi_fds[fd].used) {
		r2efi_fds[fd].h->Flush (r2efi_fds[fd].h);
	}
	return 0;
}

int rename(const char *oldpath, const char *newpath) {
	(void)oldpath;
	(void)newpath;
	errno = ENOSYS;
	return -1;
}

int remove(const char *path) {
	return unlink (path);
}

char *getcwd(char *buf, size_t size) {
	if (!buf) {
		return strdup (r2efi_cwd);
	}
	strlcpy (buf, r2efi_cwd, size);
	return buf;
}

int chdir(const char *path) {
	strlcpy (r2efi_cwd, path, sizeof (r2efi_cwd));
	return 0;
}

int fchdir(int fd) {
	(void)fd;
	errno = ENOSYS;
	return -1;
}

int dup(int oldfd) {
	(void)oldfd;
	errno = ENOSYS;
	return -1;
}

int dup2(int oldfd, int newfd) {
	(void)oldfd;
	(void)newfd;
	errno = ENOSYS;
	return -1;
}

int pipe(int pipefd[2]) {
	(void)pipefd;
	errno = ENOSYS;
	return -1;
}

int isatty(int fd) {
	return fd >= 0 && fd <= 2;
}

char *ttyname(int fd) {
	return isatty (fd)? "efi-console": NULL;
}

int ttyname_r(int fd, char *buf, size_t buflen) {
	if (!isatty (fd)) {
		return ENOTTY;
	}
	strlcpy (buf, "efi-console", buflen);
	return 0;
}

int ioctl(int fd, int request, ...) {
	if (request == TIOCGWINSZ && isatty (fd) && r2efi_st && r2efi_st->ConOut) {
		va_list ap;
		va_start (ap, request);
		struct winsize *ws = va_arg (ap, struct winsize *);
		va_end (ap);
		UINTN cols = 80, rows = 25;
		r2efi_st->ConOut->QueryMode (r2efi_st->ConOut,
			r2efi_st->ConOut->Mode->Mode, &cols, &rows);
		ws->ws_col = (unsigned short)cols;
		ws->ws_row = (unsigned short)rows;
		ws->ws_xpixel = 0;
		ws->ws_ypixel = 0;
		return 0;
	}
	errno = ENOSYS;
	return -1;
}

int fcntl(int fd, int cmd, ...) {
	(void)fd;
	(void)cmd;
	return 0;
}

int flock(int fd, int operation) {
	(void)fd;
	(void)operation;
	return 0;
}

/* ---------- directories ---------- */

struct __dirstream {
	EFI_FILE_HANDLE h;
	struct dirent de;
};

DIR *opendir(const char *name) {
	int fd = open (name, O_RDONLY);
	if (fd < 0) {
		return NULL;
	}
	DIR *d = calloc (1, sizeof (DIR));
	if (!d) {
		close (fd);
		return NULL;
	}
	/* steal the handle from the fd table */
	d->h = r2efi_fds[fd].h;
	r2efi_fds[fd].used = false;
	r2efi_fds[fd].h = NULL;
	return d;
}

DIR *fdopendir(int fd) {
	(void)fd;
	errno = ENOSYS;
	return NULL;
}

struct dirent *readdir(DIR *dirp) {
	if (!dirp || !dirp->h) {
		return NULL;
	}
	unsigned char info[sizeof (EFI_FILE_INFO) + 512];
	UINTN sz = sizeof (info);
	if (dirp->h->Read (dirp->h, &sz, info) != EFI_SUCCESS || sz == 0) {
		return NULL;
	}
	EFI_FILE_INFO *fi = (EFI_FILE_INFO *)info;
	size_t i;
	for (i = 0; fi->FileName[i] && i < sizeof (dirp->de.d_name) - 1; i++) {
		dirp->de.d_name[i] = (char)(fi->FileName[i] & 0xff);
	}
	dirp->de.d_name[i] = 0;
	dirp->de.d_type = (fi->Attribute & EFI_FILE_DIRECTORY)? DT_DIR: DT_REG;
	return &dirp->de;
}

int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result) {
	struct dirent *de = readdir (dirp);
	if (de) {
		*entry = *de;
		*result = entry;
	} else {
		*result = NULL;
	}
	return 0;
}

void rewinddir(DIR *dirp) {
	if (dirp && dirp->h) {
		dirp->h->SetPosition (dirp->h, 0);
	}
}

long telldir(DIR *dirp) {
	(void)dirp;
	return 0;
}

void seekdir(DIR *dirp, long loc) {
	(void)dirp;
	(void)loc;
}

int closedir(DIR *dirp) {
	if (!dirp) {
		return -1;
	}
	if (dirp->h) {
		dirp->h->Close (dirp->h);
	}
	free (dirp);
	return 0;
}

int dirfd(DIR *dirp) {
	(void)dirp;
	return -1;
}

/* ---------- printf ---------- */

typedef struct {
	char *buf;
	size_t size;
	size_t len;
	int fd;
} R2EfiPr;

static void r2efi_prc(R2EfiPr *pr, char c) {
	if (pr->fd >= 0) {
		write (pr->fd, &c, 1);
	} else if (pr->len + 1 < pr->size) {
		pr->buf[pr->len] = c;
	}
	pr->len++;
}

static void r2efi_prs(R2EfiPr *pr, const char *s, size_t n) {
	size_t i;
	for (i = 0; i < n; i++) {
		r2efi_prc (pr, s[i]);
	}
}

static void r2efi_prnum(R2EfiPr *pr, unsigned long long v, int base, bool upper,
		bool neg, int width, int prec, bool zero, bool left, bool plus, bool space, bool alt) {
	char tmp[64];
	const char *digits = upper? "0123456789ABCDEF": "0123456789abcdef";
	int n = 0;
	if (!v) {
		tmp[n++] = '0';
	}
	while (v) {
		tmp[n++] = digits[v % (unsigned)base];
		v /= (unsigned)base;
	}
	while (n < prec && n < 63) {
		tmp[n++] = '0';
	}
	char sign = 0;
	if (neg) {
		sign = '-';
	} else if (plus) {
		sign = '+';
	} else if (space) {
		sign = ' ';
	}
	int extra = (sign? 1: 0) + ((alt && base == 16)? 2: 0);
	int pad = width - n - extra;
	if (!left && !zero) {
		while (pad-- > 0) {
			r2efi_prc (pr, ' ');
		}
	}
	if (sign) {
		r2efi_prc (pr, sign);
	}
	if (alt && base == 16) {
		r2efi_prc (pr, '0');
		r2efi_prc (pr, upper? 'X': 'x');
	}
	if (!left && zero) {
		while (pad-- > 0) {
			r2efi_prc (pr, '0');
		}
	}
	while (n > 0) {
		r2efi_prc (pr, tmp[--n]);
	}
	if (left) {
		while (pad-- > 0) {
			r2efi_prc (pr, ' ');
		}
	}
}

static void r2efi_prdouble(R2EfiPr *pr, double d, int prec) {
	if (d != d) {
		r2efi_prs (pr, "nan", 3);
		return;
	}
	if (d > 1e308 || d < -1e308) {
		r2efi_prs (pr, (d < 0)? "-inf": "inf", (d < 0)? 4: 3);
		return;
	}
	if (prec < 0) {
		prec = 6;
	}
	if (d < 0) {
		r2efi_prc (pr, '-');
		d = -d;
	}
	if (d > 9.2e18) {
		r2efi_prs (pr, "big", 3);
		return;
	}
	unsigned long long ip = (unsigned long long)d;
	double frac = d - (double)ip;
	r2efi_prnum (pr, ip, 10, false, false, 0, 0, false, false, false, false, false);
	if (prec > 0) {
		r2efi_prc (pr, '.');
		int i;
		for (i = 0; i < prec && i < 18; i++) {
			frac *= 10;
			int digit = (int)frac;
			if (digit > 9) {
				digit = 9;
			}
			r2efi_prc (pr, (char)('0' + digit));
			frac -= digit;
		}
	}
}

static int r2efi_vpr(R2EfiPr *pr, const char *fmt, va_list ap) {
	const char *p = fmt;
	while (*p) {
		if (*p != '%') {
			r2efi_prc (pr, *p++);
			continue;
		}
		p++;
		if (*p == '%') {
			r2efi_prc (pr, '%');
			p++;
			continue;
		}
		bool left = false, zero = false, plus = false, space = false, alt = false;
		for (;; p++) {
			if (*p == '-') {
				left = true;
			} else if (*p == '0') {
				zero = true;
			} else if (*p == '+') {
				plus = true;
			} else if (*p == ' ') {
				space = true;
			} else if (*p == '#') {
				alt = true;
			} else if (*p == '\'') {
				/* ignore */
			} else {
				break;
			}
		}
		int width = -1;
		if (*p == '*') {
			width = va_arg (ap, int);
			p++;
		} else {
			while (*p >= '0' && *p <= '9') {
				width = ((width < 0)? 0: width) * 10 + (*p - '0');
				p++;
			}
		}
		int prec = -1;
		if (*p == '.') {
			p++;
			prec = 0;
			if (*p == '*') {
				prec = va_arg (ap, int);
				p++;
			} else {
				while (*p >= '0' && *p <= '9') {
					prec = prec * 10 + (*p - '0');
					p++;
				}
			}
		}
		int lmod = 0; /* 0=int 1=long 2=llong 3=size_t 4=char 5=short 6=intmax 7=ptrdiff */
		for (;; p++) {
			if (*p == 'l') {
				lmod = (lmod == 1)? 2: 1;
			} else if (*p == 'h') {
				lmod = (lmod == 5)? 4: 5;
			} else if (*p == 'z') {
				lmod = 3;
			} else if (*p == 'j') {
				lmod = 6;
			} else if (*p == 't') {
				lmod = 7;
			} else if (*p == 'L' || *p == 'q') {
				lmod = 2;
			} else {
				break;
			}
		}
		char conv = *p;
		if (!conv) {
			break;
		}
		p++;
		switch (conv) {
		case 'c': {
			int c = va_arg (ap, int);
			int pad = width - 1;
			if (!left) {
				while (pad-- > 0) {
					r2efi_prc (pr, ' ');
				}
			}
			r2efi_prc (pr, (char)c);
			if (left) {
				while (pad-- > 0) {
					r2efi_prc (pr, ' ');
				}
			}
			break;
		}
		case 's': {
			const char *s = va_arg (ap, const char *);
			if (!s) {
				s = "(null)";
			}
			size_t sl = (prec >= 0)? strnlen (s, (size_t)prec): strlen (s);
			int pad = width - (int)sl;
			if (!left) {
				while (pad-- > 0) {
					r2efi_prc (pr, ' ');
				}
			}
			r2efi_prs (pr, s, sl);
			if (left) {
				while (pad-- > 0) {
					r2efi_prc (pr, ' ');
				}
			}
			break;
		}
		case 'd':
		case 'i': {
			long long v;
			if (lmod == 2 || lmod == 6) {
				v = va_arg (ap, long long);
			} else if (lmod == 1 || lmod == 3 || lmod == 7) {
				v = va_arg (ap, long);
			} else {
				v = va_arg (ap, int);
			}
			bool neg = v < 0;
			unsigned long long uv = neg? (unsigned long long)-v: (unsigned long long)v;
			r2efi_prnum (pr, uv, 10, false, neg, width, prec, zero, left, plus, space, false);
			break;
		}
		case 'u':
		case 'x':
		case 'X':
		case 'o': {
			unsigned long long v;
			if (lmod == 2 || lmod == 6) {
				v = va_arg (ap, unsigned long long);
			} else if (lmod == 1 || lmod == 3 || lmod == 7) {
				v = va_arg (ap, unsigned long);
			} else {
				v = va_arg (ap, unsigned int);
			}
			int base = (conv == 'u')? 10: (conv == 'o')? 8: 16;
			r2efi_prnum (pr, v, base, conv == 'X', false, width, prec, zero, left, false, false, alt);
			break;
		}
		case 'p': {
			void *v = va_arg (ap, void *);
			r2efi_prs (pr, "0x", 2);
			r2efi_prnum (pr, (unsigned long long)(uintptr_t)v, 16, false, false, 0, 0, false, false, false, false, false);
			break;
		}
		case 'f':
		case 'F':
		case 'g':
		case 'G':
		case 'e':
		case 'E': {
			double d = va_arg (ap, double);
			r2efi_prdouble (pr, d, prec);
			break;
		}
		case 'n': {
			int *out = va_arg (ap, int *);
			if (out) {
				*out = (int)pr->len;
			}
			break;
		}
		default:
			r2efi_prc (pr, '%');
			r2efi_prc (pr, conv);
			break;
		}
	}
	if (pr->fd < 0 && pr->size) {
		pr->buf[(pr->len < pr->size)? pr->len: pr->size - 1] = 0;
	}
	return (int)pr->len;
}

int vsnprintf(char *str, size_t size, const char *format, va_list ap) {
	R2EfiPr pr = { str, size, 0, -1 };
	return r2efi_vpr (&pr, format, ap);
}

int snprintf(char *str, size_t size, const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	int r = vsnprintf (str, size, format, ap);
	va_end (ap);
	return r;
}

int vsprintf(char *str, const char *format, va_list ap) {
	return vsnprintf (str, (size_t)-1, format, ap);
}

int sprintf(char *str, const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	int r = vsprintf (str, format, ap);
	va_end (ap);
	return r;
}

int vasprintf(char **strp, const char *format, va_list ap) {
	va_list ap2;
	va_copy (ap2, ap);
	int n = vsnprintf (NULL, 0, format, ap2);
	va_end (ap2);
	if (n < 0) {
		return -1;
	}
	char *buf = malloc ((size_t)n + 1);
	if (!buf) {
		return -1;
	}
	int r = vsnprintf (buf, (size_t)n + 1, format, ap);
	*strp = buf;
	return r;
}

int asprintf(char **strp, const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	int r = vasprintf (strp, format, ap);
	va_end (ap);
	return r;
}

/* ---------- stdio streams ---------- */

/* the musl FILE is a complete dummy type, so the real state hides behind it */
struct _r2efi_FILE {
	int fd;
	bool eof;
	bool err;
	int ungetc;
};

#define R2F(x) ((struct _r2efi_FILE *)(x))

static struct _r2efi_FILE r2efi_stdin = { 0, false, false, -1 };
static struct _r2efi_FILE r2efi_stdout = { 1, false, false, -1 };
static struct _r2efi_FILE r2efi_stderr = { 2, false, false, -1 };

FILE *const stdin = (FILE *)&r2efi_stdin;
FILE *const stdout = (FILE *)&r2efi_stdout;
FILE *const stderr = (FILE *)&r2efi_stderr;

FILE *fopen(const char *path, const char *mode) {
	int flags = O_RDONLY;
	if (strchr (mode, '+')) {
		flags = O_RDWR;
	} else if (*mode == 'w' || *mode == 'a') {
		flags = O_WRONLY;
	}
	if (*mode == 'w') {
		flags |= O_CREAT | O_TRUNC;
	} else if (*mode == 'a') {
		flags |= O_CREAT | O_APPEND;
	}
	int fd = open (path, flags);
	if (fd < 0) {
		return NULL;
	}
	FILE *f = calloc (1, sizeof (struct _r2efi_FILE));
	if (!f) {
		close (fd);
		return NULL;
	}
	R2F (f)->fd = fd;
	R2F (f)->ungetc = -1;
	return f;
}

FILE *fdopen(int fd, const char *mode) {
	(void)mode;
	FILE *f = calloc (1, sizeof (struct _r2efi_FILE));
	if (f) {
		R2F (f)->fd = fd;
		R2F (f)->ungetc = -1;
	}
	return f;
}

FILE *freopen(const char *path, const char *mode, FILE *stream) {
	(void)path;
	(void)mode;
	(void)stream;
	return NULL;
}

FILE *tmpfile(void) {
	return NULL;
}

char *tmpnam(char *s) {
	(void)s;
	return NULL;
}

int fclose(FILE *f) {
	if (!f) {
		return EOF;
	}
	if (R2F (f)->fd > 2) {
		close (R2F (f)->fd);
	}
	if (f != stdin && f != stdout && f != stderr) {
		free (f);
	}
	return 0;
}

int fflush(FILE *f) {
	if (f && R2F (f)->fd > 2) {
		fsync (R2F (f)->fd);
	}
	return 0;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *f) {
	if (!f || !size || !nmemb) {
		return 0;
	}
	ssize_t r = read (R2F (f)->fd, ptr, size * nmemb);
	if (r <= 0) {
		if (r == 0) {
			R2F (f)->eof = true;
		} else {
			R2F (f)->err = true;
		}
		return 0;
	}
	return (size_t)r / size;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f) {
	if (!f || !size || !nmemb) {
		return 0;
	}
	ssize_t r = write (R2F (f)->fd, ptr, size * nmemb);
	if (r <= 0) {
		R2F (f)->err = true;
		return 0;
	}
	return (size_t)r / size;
}

int fseeko(FILE *f, off_t offset, int whence) {
	if (!f) {
		return -1;
	}
	R2F (f)->eof = false;
	return (lseek (R2F (f)->fd, offset, whence) < 0)? -1: 0;
}

int fseek(FILE *f, long offset, int whence) {
	return fseeko (f, offset, whence);
}

off_t ftello(FILE *f) {
	return f? lseek (R2F (f)->fd, 0, SEEK_CUR): -1;
}

long ftell(FILE *f) {
	return (long)ftello (f);
}

void rewind(FILE *f) {
	fseeko (f, 0, SEEK_SET);
}

int fgetpos(FILE *f, fpos_t *pos) {
	off_t o = ftello (f);
	if (o < 0) {
		return -1;
	}
	memcpy (pos, &o, sizeof (o));
	return 0;
}

int fsetpos(FILE *f, const fpos_t *pos) {
	off_t o = 0;
	memcpy (&o, pos, sizeof (o));
	return fseeko (f, o, SEEK_SET);
}

int feof(FILE *f) {
	return f? R2F (f)->eof: 1;
}

int ferror(FILE *f) {
	return f? R2F (f)->err: 1;
}

void clearerr(FILE *f) {
	if (f) {
		R2F (f)->eof = false;
		R2F (f)->err = false;
	}
}

int fileno(FILE *f) {
	return f? R2F (f)->fd: -1;
}

void setbuf(FILE *f, char *buf) {
	(void)f;
	(void)buf;
}

int setvbuf(FILE *f, char *buf, int mode, size_t size) {
	(void)f;
	(void)buf;
	(void)mode;
	(void)size;
	return 0;
}

int fgetc(FILE *f) {
	if (!f) {
		return EOF;
	}
	if (R2F (f)->ungetc >= 0) {
		int c = R2F (f)->ungetc;
		R2F (f)->ungetc = -1;
		return c;
	}
	unsigned char c;
	if (read (R2F (f)->fd, &c, 1) != 1) {
		R2F (f)->eof = true;
		return EOF;
	}
	return c;
}

int getc(FILE *f) {
	return fgetc (f);
}

int getchar(void) {
	return fgetc (stdin);
}

char *fgets(char *s, int size, FILE *f) {
	int i = 0;
	while (i + 1 < size) {
		int c = fgetc (f);
		if (c == EOF) {
			break;
		}
		s[i++] = (char)c;
		if (c == '\n') {
			break;
		}
	}
	if (!i) {
		return NULL;
	}
	s[i] = 0;
	return s;
}

int fputc(int c, FILE *f) {
	unsigned char ch = (unsigned char)c;
	return (write (f? R2F (f)->fd: 1, &ch, 1) == 1)? c: EOF;
}

int putc(int c, FILE *f) {
	return fputc (c, f);
}

int putchar(int c) {
	return fputc (c, stdout);
}

int fputs(const char *s, FILE *f) {
	size_t n = strlen (s);
	return (write (f? R2F (f)->fd: 1, s, n) == (ssize_t)n)? 0: EOF;
}

int puts(const char *s) {
	fputs (s, stdout);
	return fputc ('\n', stdout);
}

int ungetc(int c, FILE *f) {
	if (!f || c == EOF) {
		return EOF;
	}
	R2F (f)->ungetc = c;
	R2F (f)->eof = false;
	return c;
}

ssize_t getline(char **lineptr, size_t *n, FILE *f) {
	if (!lineptr || !n || !f) {
		return -1;
	}
	if (!*lineptr) {
		*n = 256;
		*lineptr = malloc (*n);
		if (!*lineptr) {
			return -1;
		}
	}
	size_t i = 0;
	for (;;) {
		int c = fgetc (f);
		if (c == EOF) {
			break;
		}
		if (i + 2 > *n) {
			size_t nn = *n * 2;
			char *p = realloc (*lineptr, nn);
			if (!p) {
				return -1;
			}
			*lineptr = p;
			*n = nn;
		}
		(*lineptr)[i++] = (char)c;
		if (c == '\n') {
			break;
		}
	}
	if (!i) {
		return -1;
	}
	(*lineptr)[i] = 0;
	return (ssize_t)i;
}

int vfprintf(FILE *f, const char *format, va_list ap) {
	R2EfiPr pr = { NULL, 0, 0, f? R2F (f)->fd: 1 };
	return r2efi_vpr (&pr, format, ap);
}

int fprintf(FILE *f, const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	int r = vfprintf (f, format, ap);
	va_end (ap);
	return r;
}

int vprintf(const char *format, va_list ap) {
	return vfprintf (stdout, format, ap);
}

int printf(const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	int r = vfprintf (stdout, format, ap);
	va_end (ap);
	return r;
}

int dprintf(int fd, const char *format, ...) {
	R2EfiPr pr = { NULL, 0, 0, fd };
	va_list ap;
	va_start (ap, format);
	int r = r2efi_vpr (&pr, format, ap);
	va_end (ap);
	return r;
}

void perror(const char *s) {
	if (s && *s) {
		fputs (s, stderr);
		fputs (": ", stderr);
	}
	fputs (strerror (errno), stderr);
	fputs ("\n", stderr);
}

FILE *popen(const char *command, const char *type) {
	(void)command;
	(void)type;
	errno = ENOSYS;
	return NULL;
}

int pclose(FILE *stream) {
	(void)stream;
	errno = ENOSYS;
	return -1;
}

/* ---------- scanf ---------- */

int vsscanf(const char *str, const char *format, va_list ap) {
	const char *s = str;
	const char *p = format;
	int matched = 0;
	while (*p) {
		if (*p == ' ' || *p == '\t' || *p == '\n') {
			while (*s == ' ' || (*s >= '\t' && *s <= '\r')) {
				s++;
			}
			p++;
			continue;
		}
		if (*p != '%') {
			if (*s != *p) {
				return matched;
			}
			s++;
			p++;
			continue;
		}
		p++;
		bool skip = false;
		if (*p == '*') {
			skip = true;
			p++;
		}
		int width = -1;
		while (*p >= '0' && *p <= '9') {
			width = ((width < 0)? 0: width) * 10 + (*p - '0');
			p++;
		}
		int lmod = 0;
		for (;; p++) {
			if (*p == 'l') {
				lmod = (lmod == 1)? 2: 1;
			} else if (*p == 'h') {
				lmod = (lmod == 5)? 4: 5;
			} else if (*p == 'z' || *p == 'j' || *p == 't') {
				lmod = 2;
			} else {
				break;
			}
		}
		char conv = *p;
		if (!conv) {
			break;
		}
		p++;
		if (conv == '%') {
			if (*s != '%') {
				return matched;
			}
			s++;
			continue;
		}
		if (conv == 'n') {
			if (!skip) {
				*va_arg (ap, int *) = (int)(s - str);
			}
			continue;
		}
		if (conv == 'c') {
			if (!*s) {
				return matched;
			}
			if (skip) {
				s++;
			} else {
				*va_arg (ap, char *) = *s++;
				matched++;
			}
			continue;
		}
		/* skip leading spaces for everything else */
		while (*s == ' ' || (*s >= '\t' && *s <= '\r')) {
			s++;
		}
		if (!*s) {
			return matched;
		}
		if (conv == 's') {
			char *out = skip? NULL: va_arg (ap, char *);
			int n = 0;
			while (*s && !(*s == ' ' || (*s >= '\t' && *s <= '\r')) && (width < 0 || n < width)) {
				if (out) {
					out[n] = *s;
				}
				s++;
				n++;
			}
			if (out) {
				out[n] = 0;
				matched++;
			}
			continue;
		}
		if (conv == '[') {
			bool negate = (*p == '^');
			if (negate) {
				p++;
			}
			const char *set = p;
			while (*p && *p != ']') {
				p++;
			}
			size_t setlen = (size_t)(p - set);
			if (*p == ']') {
				p++;
			}
			char *out = skip? NULL: va_arg (ap, char *);
			int n = 0;
			while (*s && (width < 0 || n < width)) {
				bool in = memchr (set, *s, setlen) != NULL;
				if (in == negate) {
					break;
				}
				if (out) {
					out[n] = *s;
				}
				s++;
				n++;
			}
			if (out) {
				out[n] = 0;
				if (n) {
					matched++;
				}
			}
			continue;
		}
		if (conv == 'f' || conv == 'e' || conv == 'g') {
			char *end = NULL;
			double v = strtod (s, &end);
			if (end == s) {
				return matched;
			}
			s = end;
			if (!skip) {
				if (lmod >= 1) {
					*va_arg (ap, double *) = v;
				} else {
					*va_arg (ap, float *) = (float)v;
				}
				matched++;
			}
			continue;
		}
		int base = (conv == 'x' || conv == 'X' || conv == 'p')? 16: (conv == 'o')? 8: (conv == 'i')? 0: 10;
		char tmp[80];
		if (width > 0 && width < 79) {
			strlcpy (tmp, s, (size_t)width + 1);
		} else {
			strlcpy (tmp, s, sizeof (tmp));
		}
		char *end = NULL;
		unsigned long long v = strtoull (tmp, &end, base);
		if (end == tmp) {
			return matched;
		}
		s += end - tmp;
		if (!skip) {
			switch (lmod) {
			case 2: *va_arg (ap, long long *) = (long long)v; break;
			case 1: *va_arg (ap, long *) = (long)v; break;
			case 5: *va_arg (ap, short *) = (short)v; break;
			case 4: *va_arg (ap, char *) = (char)v; break;
			default: *va_arg (ap, int *) = (int)v; break;
			}
			matched++;
		}
	}
	return matched;
}

int sscanf(const char *str, const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	int r = vsscanf (str, format, ap);
	va_end (ap);
	return r;
}

int fscanf(FILE *stream, const char *format, ...) {
	(void)stream;
	(void)format;
	return 0;
}

int scanf(const char *format, ...) {
	(void)format;
	return 0;
}

/* ---------- process ---------- */

void abort(void) {
	fputs ("abort()\n", stderr);
	if (r2efi_bs && r2efi_image) {
		r2efi_bs->Exit (r2efi_image, EFI_ABORTED, 0, NULL);
	}
	for (;;) {
		__builtin_trap ();
	}
}

void exit(int code) {
	if (r2efi_bs && r2efi_image) {
		r2efi_bs->Exit (r2efi_image, code? EFI_ABORTED: EFI_SUCCESS, 0, NULL);
	}
	for (;;) {
		__builtin_trap ();
	}
}

void _Exit(int code) {
	exit (code);
}

void _exit(int code) {
	exit (code);
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
	(void)nfds;
	(void)readfds;
	(void)writefds;
	(void)exceptfds;
	(void)timeout;
	return 0;
}

int poll(struct pollfd *pfds, nfds_t nfds, int timeout) {
	(void)pfds;
	(void)nfds;
	(void)timeout;
	return 0;
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask) {
	(void)nfds;
	(void)readfds;
	(void)writefds;
	(void)exceptfds;
	(void)timeout;
	(void)sigmask;
	return 0;
}

int atexit(void (*function)(void)) {
	(void)function;
	return 0;
}

int system(const char *command) {
	(void)command;
	errno = ENOSYS;
	return -1;
}

pid_t getpid(void) {
	return 1;
}

pid_t getppid(void) {
	return 0;
}

uid_t getuid(void) {
	return 0;
}

uid_t geteuid(void) {
	return 0;
}

gid_t getgid(void) {
	return 0;
}

gid_t getegid(void) {
	return 0;
}

int setuid(uid_t uid) {
	(void)uid;
	return 0;
}

int seteuid(uid_t euid) {
	(void)euid;
	return 0;
}

int setgid(gid_t gid) {
	(void)gid;
	return 0;
}

pid_t fork(void) {
	errno = ENOSYS;
	return -1;
}

pid_t vfork(void) {
	errno = ENOSYS;
	return -1;
}

int execv(const char *pathname, char *const argv[]) {
	(void)pathname;
	(void)argv;
	errno = ENOSYS;
	return -1;
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
	(void)pathname;
	(void)argv;
	(void)envp;
	errno = ENOSYS;
	return -1;
}

int execvp(const char *file, char *const argv[]) {
	(void)file;
	(void)argv;
	errno = ENOSYS;
	return -1;
}

int execl(const char *pathname, const char *arg, ...) {
	(void)pathname;
	(void)arg;
	errno = ENOSYS;
	return -1;
}

int execlp(const char *file, const char *arg, ...) {
	(void)file;
	(void)arg;
	errno = ENOSYS;
	return -1;
}

pid_t setsid(void) {
	return 1;
}

int chroot(const char *path) {
	(void)path;
	errno = ENOSYS;
	return -1;
}

int setgroups(size_t size, const gid_t *list) {
	(void)size;
	(void)list;
	return 0;
}

int getgroups(int size, gid_t list[]) {
	(void)size;
	(void)list;
	return 0;
}

int pause(void) {
	errno = EINTR;
	return -1;
}

int daemon(int nochdir, int noclose) {
	(void)nochdir;
	(void)noclose;
	errno = ENOSYS;
	return -1;
}

int nice(int inc) {
	(void)inc;
	return 0;
}

pid_t wait(int *wstatus) {
	(void)wstatus;
	errno = ECHILD;
	return -1;
}

pid_t waitpid(pid_t pid, int *wstatus, int options) {
	(void)pid;
	(void)wstatus;
	(void)options;
	errno = ECHILD;
	return -1;
}

int kill(pid_t pid, int sig) {
	(void)pid;
	(void)sig;
	errno = ENOSYS;
	return -1;
}

int raise(int sig) {
	(void)sig;
	return 0;
}

sighandler_t signal(int signum, sighandler_t handler) {
	(void)signum;
	(void)handler;
	return SIG_DFL;
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
	(void)signum;
	(void)act;
	(void)oldact;
	return 0;
}

int sigemptyset(sigset_t *set) {
	memset (set, 0, sizeof (*set));
	return 0;
}

int sigfillset(sigset_t *set) {
	memset (set, 0xff, sizeof (*set));
	return 0;
}

int sigaddset(sigset_t *set, int signum) {
	(void)set;
	(void)signum;
	return 0;
}

int sigdelset(sigset_t *set, int signum) {
	(void)set;
	(void)signum;
	return 0;
}

int sigismember(const sigset_t *set, int signum) {
	(void)set;
	(void)signum;
	return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
	(void)how;
	(void)set;
	(void)oldset;
	return 0;
}

/* ---------- environment ---------- */

typedef struct r2efi_env_t {
	char *name;
	char *value;
	struct r2efi_env_t *next;
} R2EfiEnv;

static R2EfiEnv *r2efi_env = NULL;

char *getenv(const char *name) {
	R2EfiEnv *e = r2efi_env;
	while (e) {
		if (!strcmp (e->name, name)) {
			return e->value;
		}
		e = e->next;
	}
	return NULL;
}

int setenv(const char *name, const char *value, int overwrite) {
	R2EfiEnv *e = r2efi_env;
	while (e) {
		if (!strcmp (e->name, name)) {
			if (overwrite) {
				free (e->value);
				e->value = strdup (value);
			}
			return 0;
		}
		e = e->next;
	}
	e = calloc (1, sizeof (R2EfiEnv));
	if (!e) {
		return -1;
	}
	e->name = strdup (name);
	e->value = strdup (value);
	e->next = r2efi_env;
	r2efi_env = e;
	return 0;
}

int unsetenv(const char *name) {
	R2EfiEnv **pe = &r2efi_env;
	while (*pe) {
		if (!strcmp ((*pe)->name, name)) {
			R2EfiEnv *e = *pe;
			*pe = e->next;
			free (e->name);
			free (e->value);
			free (e);
			return 0;
		}
		pe = &(*pe)->next;
	}
	return 0;
}

int putenv(char *string) {
	char *eq = strchr (string, '=');
	if (!eq) {
		return unsetenv (string);
	}
	char *name = strndup (string, (size_t)(eq - string));
	int r = setenv (name, eq + 1, 1);
	free (name);
	return r;
}

/* ---------- time ---------- */

static time_t r2efi_mkgmtime(int year, int mon, int day, int hour, int min, int sec) {
	static const int mdays[] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
	long long days = (year - 1970) * 365LL + (year - 1969) / 4 - (year - 1901) / 100 + (year - 1601) / 400;
	days += mdays[(mon - 1) % 12];
	bool leap = !(year % 4) && ((year % 100) || !(year % 400));
	if (leap && mon > 2) {
		days++;
	}
	days += day - 1;
	return ((days * 24 + hour) * 60 + min) * 60 + sec;
}

time_t time(time_t *tloc) {
	time_t t = 0;
	if (r2efi_rt) {
		EFI_TIME et;
		if (r2efi_rt->GetTime (&et, NULL) == EFI_SUCCESS) {
			t = r2efi_mkgmtime (et.Year, et.Month, et.Day, et.Hour, et.Minute, et.Second);
		}
	}
	if (tloc) {
		*tloc = t;
	}
	return t;
}

double difftime(time_t time1, time_t time0) {
	return (double)(time1 - time0);
}

time_t mktime(struct tm *tm) {
	return r2efi_mkgmtime (tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
}

time_t timegm(struct tm *tm) {
	return mktime (tm);
}

static unsigned long long r2efi_rdtsc(void) {
	unsigned int lo, hi;
	__asm__ volatile ("rdtsc": "=a" (lo), "=d" (hi));
	return ((unsigned long long)hi << 32) | lo;
}

clock_t clock(void) {
	return (clock_t)(r2efi_rdtsc () / 1000);
}

struct tm *gmtime_r(const time_t *timep, struct tm *result) {
	static const int mdays[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	long long t = *timep;
	long long days = t / 86400;
	long long rem = t % 86400;
	if (rem < 0) {
		rem += 86400;
		days--;
	}
	memset (result, 0, sizeof (*result));
	result->tm_hour = (int)(rem / 3600);
	result->tm_min = (int)((rem % 3600) / 60);
	result->tm_sec = (int)(rem % 60);
	result->tm_wday = (int)((4 + days) % 7);
	if (result->tm_wday < 0) {
		result->tm_wday += 7;
	}
	int year = 1970;
	for (;;) {
		bool leap = !(year % 4) && ((year % 100) || !(year % 400));
		int ydays = leap? 366: 365;
		if (days < ydays) {
			break;
		}
		days -= ydays;
		year++;
	}
	result->tm_year = year - 1900;
	result->tm_yday = (int)days;
	bool leap = !(year % 4) && ((year % 100) || !(year % 400));
	int m;
	for (m = 0; m < 12; m++) {
		int md = mdays[m] + ((m == 1 && leap)? 1: 0);
		if (days < md) {
			break;
		}
		days -= md;
	}
	result->tm_mon = m;
	result->tm_mday = (int)days + 1;
	return result;
}

struct tm *gmtime(const time_t *timep) {
	static struct tm tm;
	return gmtime_r (timep, &tm);
}

struct tm *localtime_r(const time_t *timep, struct tm *result) {
	return gmtime_r (timep, result);
}

struct tm *localtime(const time_t *timep) {
	return gmtime (timep);
}

char *asctime_r(const struct tm *tm, char *buf) {
	static const char wday[7][4] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	static const char mon[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	snprintf (buf, 26, "%s %s %2d %02d:%02d:%02d %d\n",
		wday[tm->tm_wday % 7], mon[tm->tm_mon % 12], tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec, tm->tm_year + 1900);
	return buf;
}

char *asctime(const struct tm *tm) {
	static char buf[26];
	return asctime_r (tm, buf);
}

char *ctime_r(const time_t *timep, char *buf) {
	struct tm tm;
	return asctime_r (gmtime_r (timep, &tm), buf);
}

char *ctime(const time_t *timep) {
	static char buf[26];
	return ctime_r (timep, buf);
}

size_t strftime(char *s, size_t max, const char *format, const struct tm *tm) {
	/* minimal: only the common conversions used in radare2 */
	R2EfiPr pr = { s, max, 0, -1 };
	const char *p = format;
	while (*p) {
		if (*p != '%') {
			r2efi_prc (&pr, *p++);
			continue;
		}
		p++;
		char tmp[16];
		switch (*p) {
		case 'Y': snprintf (tmp, sizeof (tmp), "%d", tm->tm_year + 1900); break;
		case 'm': snprintf (tmp, sizeof (tmp), "%02d", tm->tm_mon + 1); break;
		case 'd': snprintf (tmp, sizeof (tmp), "%02d", tm->tm_mday); break;
		case 'H': snprintf (tmp, sizeof (tmp), "%02d", tm->tm_hour); break;
		case 'M': snprintf (tmp, sizeof (tmp), "%02d", tm->tm_min); break;
		case 'S': snprintf (tmp, sizeof (tmp), "%02d", tm->tm_sec); break;
		case 'j': snprintf (tmp, sizeof (tmp), "%03d", tm->tm_yday + 1); break;
		case 's': snprintf (tmp, sizeof (tmp), "%lld", (long long)mktime ((struct tm *)tm)); break;
		case '%': strcpy (tmp, "%"); break;
		default: tmp[0] = '%'; tmp[1] = *p; tmp[2] = 0; break;
		}
		if (*p) {
			p++;
		}
		r2efi_prs (&pr, tmp, strlen (tmp));
	}
	if (max) {
		s[(pr.len < max)? pr.len: max - 1] = 0;
	}
	return pr.len;
}

char *strptime(const char *s, const char *format, struct tm *tm) {
	(void)s;
	(void)format;
	(void)tm;
	return NULL;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
	if (clk_id == CLOCK_REALTIME) {
		tp->tv_sec = time (NULL);
		tp->tv_nsec = 0;
	} else {
		/* the tsc makes a poor but monotonic clock source */
		unsigned long long t = r2efi_rdtsc ();
		tp->tv_sec = (time_t)(t / 1000000000ULL);
		tp->tv_nsec = (long)(t % 1000000000ULL);
	}
	return 0;
}

int clock_settime(clockid_t clk_id, const struct timespec *tp) {
	(void)clk_id;
	(void)tp;
	errno = ENOSYS;
	return -1;
}

int clock_getres(clockid_t clk_id, struct timespec *res) {
	(void)clk_id;
	res->tv_sec = 0;
	res->tv_nsec = 1000;
	return 0;
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
	(void)rem;
	if (r2efi_bs) {
		r2efi_bs->Stall ((UINTN)(req->tv_sec * 1000000 + req->tv_nsec / 1000));
	}
	return 0;
}

void tzset(void) {
}

int gettimeofday(struct timeval *tv, void *tz) {
	(void)tz;
	if (tv) {
		tv->tv_sec = time (NULL);
		tv->tv_usec = 0;
	}
	return 0;
}

int settimeofday(const struct timeval *tv, const struct timezone *tz) {
	(void)tv;
	(void)tz;
	errno = ENOSYS;
	return -1;
}

unsigned int sleep(unsigned int seconds) {
	if (r2efi_bs) {
		r2efi_bs->Stall ((UINTN)seconds * 1000000);
	}
	return 0;
}

int usleep(useconds_t usec) {
	if (r2efi_bs) {
		r2efi_bs->Stall (usec);
	}
	return 0;
}

unsigned int alarm(unsigned int seconds) {
	(void)seconds;
	return 0;
}

/* ---------- misc ---------- */

long sysconf(int name) {
	if (name == _SC_PAGESIZE) {
		return 4096;
	}
	if (name == _SC_NPROCESSORS_ONLN) {
		return 1;
	}
	return -1;
}

int getpagesize(void) {
	return 4096;
}

int gethostname(char *name, size_t len) {
	strlcpy (name, "uefi", len);
	return 0;
}

char *getlogin(void) {
	return "root";
}

int getopt(int argc, char *const argv[], const char *optstring) {
	(void)argc;
	(void)argv;
	(void)optstring;
	return -1;
}

int uname(struct utsname *buf) {
	memset (buf, 0, sizeof (*buf));
	strcpy (buf->sysname, "UEFI");
	strcpy (buf->nodename, "uefi");
	strcpy (buf->release, "1.0");
	strcpy (buf->version, "1.0");
	strcpy (buf->machine, "x86_64");
	return 0;
}

int mkstemp(char *template_) {
	size_t l = strlen (template_);
	if (l < 6) {
		errno = EINVAL;
		return -1;
	}
	unsigned long long v = r2efi_rdtsc ();
	size_t i;
	for (i = l - 6; i < l; i++) {
		template_[i] = (char)('a' + (v % 26));
		v /= 26;
	}
	return open (template_, O_RDWR | O_CREAT | O_EXCL);
}

char *mktemp(char *template_) {
	int fd = mkstemp (template_);
	if (fd >= 0) {
		close (fd);
	}
	return template_;
}

char *realpath(const char *path, char *resolved_path) {
	if (!resolved_path) {
		return strdup (path);
	}
	strlcpy (resolved_path, path, PATH_MAX);
	return resolved_path;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	(void)addr;
	(void)length;
	(void)prot;
	(void)flags;
	(void)fd;
	(void)offset;
	errno = ENOSYS;
	return MAP_FAILED;
}

int munmap(void *addr, size_t length) {
	(void)addr;
	(void)length;
	errno = ENOSYS;
	return -1;
}

int mprotect(void *addr, size_t len, int prot) {
	(void)addr;
	(void)len;
	(void)prot;
	return 0;
}

int msync(void *addr, size_t length, int flags) {
	(void)addr;
	(void)length;
	(void)flags;
	return 0;
}

int mlock(const void *addr, size_t len) {
	(void)addr;
	(void)len;
	return 0;
}

int munlock(const void *addr, size_t len) {
	(void)addr;
	(void)len;
	return 0;
}

int tcgetattr(int fd, struct termios *termios_p) {
	(void)fd;
	memset (termios_p, 0, sizeof (*termios_p));
	return 0;
}

int tcsetattr(int fd, int optional_actions, const struct termios *termios_p) {
	(void)fd;
	(void)optional_actions;
	(void)termios_p;
	return 0;
}

int tcsendbreak(int fd, int duration) {
	(void)fd;
	(void)duration;
	return 0;
}

int tcdrain(int fd) {
	(void)fd;
	return 0;
}

int tcflush(int fd, int queue_selector) {
	(void)fd;
	(void)queue_selector;
	return 0;
}

int cfsetispeed(struct termios *termios_p, speed_t speed) {
	(void)termios_p;
	(void)speed;
	return 0;
}

int cfsetospeed(struct termios *termios_p, speed_t speed) {
	(void)termios_p;
	(void)speed;
	return 0;
}

speed_t cfgetispeed(const struct termios *termios_p) {
	(void)termios_p;
	return 0;
}

speed_t cfgetospeed(const struct termios *termios_p) {
	(void)termios_p;
	return 0;
}

void cfmakeraw(struct termios *termios_p) {
	(void)termios_p;
}

/* ---------- sockets (no network on uefi) ---------- */

int socket(int domain, int type, int protocol) {
	(void)domain;
	(void)type;
	(void)protocol;
	errno = EAFNOSUPPORT;
	return -1;
}

int socketpair(int domain, int type, int protocol, int sv[2]) {
	(void)domain;
	(void)type;
	(void)protocol;
	(void)sv;
	errno = EAFNOSUPPORT;
	return -1;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	(void)sockfd;
	(void)addr;
	(void)addrlen;
	errno = EBADF;
	return -1;
}

int listen(int sockfd, int backlog) {
	(void)sockfd;
	(void)backlog;
	errno = EBADF;
	return -1;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	(void)sockfd;
	(void)addr;
	(void)addrlen;
	errno = EBADF;
	return -1;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	(void)sockfd;
	(void)addr;
	(void)addrlen;
	errno = ENETUNREACH;
	return -1;
}

int shutdown(int sockfd, int how) {
	(void)sockfd;
	(void)how;
	errno = EBADF;
	return -1;
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
	(void)sockfd;
	(void)level;
	(void)optname;
	(void)optval;
	(void)optlen;
	errno = EBADF;
	return -1;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
	(void)sockfd;
	(void)level;
	(void)optname;
	(void)optval;
	(void)optlen;
	errno = EBADF;
	return -1;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	(void)sockfd;
	(void)addr;
	(void)addrlen;
	errno = EBADF;
	return -1;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	(void)sockfd;
	(void)addr;
	(void)addrlen;
	errno = EBADF;
	return -1;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
	(void)sockfd;
	(void)buf;
	(void)len;
	(void)flags;
	errno = EBADF;
	return -1;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
	(void)sockfd;
	(void)buf;
	(void)len;
	(void)flags;
	errno = EBADF;
	return -1;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	(void)dest_addr;
	(void)addrlen;
	return send (sockfd, buf, len, flags);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
	(void)src_addr;
	(void)addrlen;
	return recv (sockfd, buf, len, flags);
}

uint32_t htonl(uint32_t hostlong) {
	return __builtin_bswap32 (hostlong);
}

uint16_t htons(uint16_t hostshort) {
	return __builtin_bswap16 (hostshort);
}

uint32_t ntohl(uint32_t netlong) {
	return __builtin_bswap32 (netlong);
}

uint16_t ntohs(uint16_t netshort) {
	return __builtin_bswap16 (netshort);
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
	(void)node;
	(void)service;
	(void)hints;
	(void)res;
	return EAI_FAIL;
}

void freeaddrinfo(struct addrinfo *res) {
	(void)res;
}

const char *gai_strerror(int errcode) {
	(void)errcode;
	return "Name resolution not supported on UEFI";
}

int getnameinfo(const struct sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags) {
	(void)addr;
	(void)addrlen;
	(void)host;
	(void)hostlen;
	(void)serv;
	(void)servlen;
	(void)flags;
	return EAI_FAIL;
}

struct hostent *gethostbyname(const char *name) {
	(void)name;
	h_errno = HOST_NOT_FOUND;
	return NULL;
}

struct servent *getservbyname(const char *name, const char *proto) {
	(void)name;
	(void)proto;
	return NULL;
}

int getrlimit(int resource, struct rlimit *rlim) {
	(void)resource;
	rlim->rlim_cur = RLIM_INFINITY;
	rlim->rlim_max = RLIM_INFINITY;
	return 0;
}

int setrlimit(int resource, const struct rlimit *rlim) {
	(void)resource;
	(void)rlim;
	return 0;
}

struct passwd *getpwuid(uid_t uid) {
	(void)uid;
	return NULL;
}

struct passwd *getpwnam(const char *name) {
	(void)name;
	return NULL;
}

/* ---------- threads (single-threaded stubs) ---------- */

#include <pthread.h>
#include <semaphore.h>

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
	(void)thread;
	(void)attr;
	(void)start_routine;
	(void)arg;
	errno = ENOSYS;
	return ENOSYS;
}

int pthread_join(pthread_t thread, void **retval) {
	(void)thread;
	(void)retval;
	return 0;
}

int pthread_detach(pthread_t thread) {
	(void)thread;
	return 0;
}

void pthread_exit(void *retval) {
	(void)retval;
	exit (0);
}

pthread_t pthread_self(void) {
	return (pthread_t)1;
}

int (pthread_equal)(pthread_t t1, pthread_t t2) {
	return t1 == t2;
}

int pthread_cancel(pthread_t thread) {
	(void)thread;
	return 0;
}

int pthread_kill(pthread_t thread, int sig) {
	(void)thread;
	(void)sig;
	return 0;
}

int pthread_attr_init(pthread_attr_t *attr) {
	(void)attr;
	return 0;
}

int pthread_attr_destroy(pthread_attr_t *attr) {
	(void)attr;
	return 0;
}

int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize) {
	(void)attr;
	(void)stacksize;
	return 0;
}

int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stacksize) {
	(void)attr;
	*stacksize = 0x100000;
	return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate) {
	(void)attr;
	(void)detachstate;
	return 0;
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
	(void)attr;
	(void)mutex;
	return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) {
	(void)mutex;
	return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
	(void)mutex;
	return 0;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
	(void)mutex;
	return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
	(void)mutex;
	return 0;
}

int pthread_mutexattr_init(pthread_mutexattr_t *attr) {
	(void)attr;
	return 0;
}

int pthread_mutexattr_destroy(pthread_mutexattr_t *attr) {
	(void)attr;
	return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type) {
	(void)attr;
	(void)type;
	return 0;
}

int pthread_condattr_init(pthread_condattr_t *attr) {
	(void)attr;
	return 0;
}

int pthread_condattr_destroy(pthread_condattr_t *attr) {
	(void)attr;
	return 0;
}

int pthread_condattr_setclock(pthread_condattr_t *attr, clockid_t clock_id) {
	(void)attr;
	(void)clock_id;
	return 0;
}

int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
	(void)attr;
	(void)cond;
	return 0;
}

int pthread_cond_destroy(pthread_cond_t *cond) {
	(void)cond;
	return 0;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
	(void)cond;
	(void)mutex;
	return 0;
}

int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime) {
	(void)cond;
	(void)mutex;
	(void)abstime;
	return ETIMEDOUT;
}

int pthread_cond_signal(pthread_cond_t *cond) {
	(void)cond;
	return 0;
}

int pthread_cond_broadcast(pthread_cond_t *cond) {
	(void)cond;
	return 0;
}

int pthread_rwlock_init(pthread_rwlock_t *rwlock, const pthread_rwlockattr_t *attr) {
	(void)attr;
	(void)rwlock;
	return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock) {
	(void)rwlock;
	return 0;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock) {
	(void)rwlock;
	return 0;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock) {
	(void)rwlock;
	return 0;
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock) {
	(void)rwlock;
	return 0;
}

#define R2EFI_NKEYS 64
static const void *r2efi_tls[R2EFI_NKEYS];
static unsigned int r2efi_nkeys = 1;

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *)) {
	(void)destructor;
	if (r2efi_nkeys >= R2EFI_NKEYS) {
		return EAGAIN;
	}
	*key = r2efi_nkeys++;
	return 0;
}

int pthread_key_delete(pthread_key_t key) {
	(void)key;
	return 0;
}

void *pthread_getspecific(pthread_key_t key) {
	return (key < R2EFI_NKEYS)? (void *)r2efi_tls[key]: NULL;
}

int pthread_setspecific(pthread_key_t key, const void *value) {
	if (key >= R2EFI_NKEYS) {
		return EINVAL;
	}
	r2efi_tls[key] = value;
	return 0;
}

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) {
	if (!*once_control) {
		*once_control = 1;
		init_routine ();
	}
	return 0;
}

int pthread_setname_np(pthread_t thread, const char *name) {
	(void)thread;
	(void)name;
	return 0;
}

int pthread_getname_np(pthread_t thread, char *name, size_t len) {
	(void)thread;
	strlcpy (name, "main", len);
	return 0;
}

int sched_yield(void) {
	return 0;
}

int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask) {
	(void)pid;
	(void)cpusetsize;
	(void)mask;
	return 0;
}

int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
	(void)pid;
	(void)cpusetsize;
	if (mask) {
		CPU_ZERO (mask);
		CPU_SET (0, mask);
	}
	return 0;
}

int sem_init(sem_t *sem, int pshared, unsigned int value) {
	(void)pshared;
	(void)sem;
	(void)value;
	return 0;
}

int sem_destroy(sem_t *sem) {
	(void)sem;
	return 0;
}

int sem_wait(sem_t *sem) {
	(void)sem;
	return 0;
}

int sem_trywait(sem_t *sem) {
	(void)sem;
	return 0;
}

int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout) {
	(void)abs_timeout;
	return sem_wait (sem);
}

int sem_post(sem_t *sem) {
	(void)sem;
	return 0;
}

int sem_getvalue(sem_t *sem, int *sval) {
	(void)sem;
	*sval = 0;
	return 0;
}

sem_t *sem_open(const char *name, int oflag, ...) {
	(void)name;
	(void)oflag;
	return SEM_FAILED;
}

int sem_close(sem_t *sem) {
	(void)sem;
	return 0;
}

int sem_unlink(const char *name) {
	(void)name;
	return 0;
}

size_t malloc_usable_size(void *ptr) {
	if (!ptr) {
		return 0;
	}
	R2EfiChunk *c = (R2EfiChunk *)ptr - 1;
	return (c->magic == R2EFI_CHUNK_MAGIC)? c->size: 0;
}

/* ---------- fenv ---------- */

#include <fenv.h>

int feclearexcept(int excepts) {
	(void)excepts;
	return 0;
}

int fetestexcept(int excepts) {
	(void)excepts;
	return 0;
}

int fegetround(void) {
	return FE_TONEAREST;
}

int fesetround(int round_) {
	(void)round_;
	return 0;
}

int feraiseexcept(int excepts) {
	(void)excepts;
	return 0;
}

/* ---------- setjmp ---------- */

__attribute__((naked)) int setjmp(jmp_buf env) {
	__asm__ volatile (
		"movq %rbx, 0(%rdi)\n"
		"movq %rbp, 8(%rdi)\n"
		"movq %r12, 16(%rdi)\n"
		"movq %r13, 24(%rdi)\n"
		"movq %r14, 32(%rdi)\n"
		"movq %r15, 40(%rdi)\n"
		"leaq 8(%rsp), %rax\n"
		"movq %rax, 48(%rdi)\n"
		"movq (%rsp), %rax\n"
		"movq %rax, 56(%rdi)\n"
		"xorl %eax, %eax\n"
		"retq\n");
}

__attribute__((naked)) void longjmp(jmp_buf env, int val) {
	__asm__ volatile (
		"movq 0(%rdi), %rbx\n"
		"movq 8(%rdi), %rbp\n"
		"movq 16(%rdi), %r12\n"
		"movq 24(%rdi), %r13\n"
		"movq 32(%rdi), %r14\n"
		"movq 40(%rdi), %r15\n"
		"movq 48(%rdi), %rsp\n"
		"movl %esi, %eax\n"
		"testl %eax, %eax\n"
		"jnz 1f\n"
		"incl %eax\n"
		"1: jmpq *56(%rdi)\n");
}

__attribute__((naked)) int sigsetjmp(sigjmp_buf env, int savemask) {
	__asm__ volatile (
		"movq %rbx, 0(%rdi)\n"
		"movq %rbp, 8(%rdi)\n"
		"movq %r12, 16(%rdi)\n"
		"movq %r13, 24(%rdi)\n"
		"movq %r14, 32(%rdi)\n"
		"movq %r15, 40(%rdi)\n"
		"leaq 8(%rsp), %rax\n"
		"movq %rax, 48(%rdi)\n"
		"movq (%rsp), %rax\n"
		"movq %rax, 56(%rdi)\n"
		"xorl %eax, %eax\n"
		"retq\n");
}

__attribute__((naked)) void siglongjmp(sigjmp_buf env, int val) {
	__asm__ volatile (
		"movq 0(%rdi), %rbx\n"
		"movq 8(%rdi), %rbp\n"
		"movq 16(%rdi), %r12\n"
		"movq 24(%rdi), %r13\n"
		"movq 32(%rdi), %r14\n"
		"movq 40(%rdi), %r15\n"
		"movq 48(%rdi), %rsp\n"
		"movl %esi, %eax\n"
		"testl %eax, %eax\n"
		"jnz 1f\n"
		"incl %eax\n"
		"1: jmpq *56(%rdi)\n");
}

/* ---------- math ---------- */

double fabs(double x) {
	return __builtin_fabs (x);
}

float fabsf(float x) {
	return __builtin_fabsf (x);
}

double sqrt(double x) {
	double r;
	__asm__ ("sqrtsd %1, %0": "=x" (r): "x" (x));
	return r;
}

float sqrtf(float x) {
	float r;
	__asm__ ("sqrtss %1, %0": "=x" (r): "x" (x));
	return r;
}

double trunc(double x) {
	if (x != x || x > 9.2e18 || x < -9.2e18) {
		return x;
	}
	return (double)(long long)x;
}

double floor(double x) {
	double t = trunc (x);
	return (x < 0 && t != x)? t - 1: t;
}

double ceil(double x) {
	double t = trunc (x);
	return (x > 0 && t != x)? t + 1: t;
}

double round(double x) {
	return (x < 0)? trunc (x - 0.5): trunc (x + 0.5);
}

float truncf(float x) {
	return (float)trunc (x);
}

float floorf(float x) {
	return (float)floor (x);
}

float ceilf(float x) {
	return (float)ceil (x);
}

float roundf(float x) {
	return (float)round (x);
}

long lround(double x) {
	return (long)round (x);
}

long long llround(double x) {
	return (long long)round (x);
}

double nearbyint(double x) {
	return round (x);
}

double rint(double x) {
	return round (x);
}

double fmod(double x, double y) {
	if (y == 0) {
		return NAN;
	}
	return x - trunc (x / y) * y;
}

float fmodf(float x, float y) {
	return (float)fmod (x, y);
}

double fmin(double x, double y) {
	return (x < y)? x: y;
}

double fmax(double x, double y) {
	return (x > y)? x: y;
}

float fminf(float x, float y) {
	return (x < y)? x: y;
}

float fmaxf(float x, float y) {
	return (x > y)? x: y;
}

double copysign(double x, double y) {
	return __builtin_copysign (x, y);
}

float copysignf(float x, float y) {
	return __builtin_copysignf (x, y);
}

double ldexp(double x, int exp_) {
	while (exp_ > 0) {
		x *= 2;
		exp_--;
	}
	while (exp_ < 0) {
		x *= 0.5;
		exp_++;
	}
	return x;
}

float ldexpf(float x, int exp_) {
	return (float)ldexp (x, exp_);
}

double scalbn(double x, int n) {
	return ldexp (x, n);
}

float scalbnf(float x, int n) {
	return (float)ldexp (x, n);
}

double frexp(double x, int *exp_) {
	int e = 0;
	if (x == 0 || x != x) {
		*exp_ = 0;
		return x;
	}
	double ax = fabs (x);
	while (ax >= 1) {
		ax *= 0.5;
		e++;
	}
	while (ax < 0.5) {
		ax *= 2;
		e--;
	}
	*exp_ = e;
	return (x < 0)? -ax: ax;
}

float frexpf(float x, int *exp_) {
	return (float)frexp (x, exp_);
}

double modf(double x, double *iptr) {
	*iptr = trunc (x);
	return x - *iptr;
}

float modff(float x, float *iptr) {
	double ip;
	double r = modf (x, &ip);
	*iptr = (float)ip;
	return (float)r;
}

long double fminl(long double x, long double y) {
	return (x < y)? x: y;
}

long double fmaxl(long double x, long double y) {
	return (x > y)? x: y;
}

long double roundl(long double x) {
	return round ((double)x);
}

long double truncl(long double x) {
	return trunc ((double)x);
}

long double ldexpl(long double x, int exp_) {
	return ldexp ((double)x, exp_);
}

long double frexpl(long double x, int *exp_) {
	return frexp ((double)x, exp_);
}

long double modfl(long double x, long double *iptr) {
	double ip;
	double r = modf ((double)x, &ip);
	*iptr = ip;
	return r;
}

double log(double x) {
	if (x != x || x < 0) {
		return NAN;
	}
	if (x == 0) {
		return -HUGE_VAL;
	}
	/* reduce to [1,2) via exponent extraction, then atanh series */
	int e = 0;
	double m = frexp (x, &e);
	m *= 2;
	e--;
	double z = (m - 1) / (m + 1);
	double z2 = z * z;
	double sum = 0;
	double term = z;
	int k;
	for (k = 1; k < 40; k += 2) {
		sum += term / k;
		term *= z2;
	}
	return 2 * sum + e * M_LN2;
}

double exp(double x) {
	if (x != x) {
		return x;
	}
	if (x > 709) {
		return HUGE_VAL;
	}
	if (x < -709) {
		return 0;
	}
	/* x = k*ln2 + r; e^x = 2^k * e^r with |r| <= ln2/2 */
	int k = (int)round (x / M_LN2);
	double r = x - k * M_LN2;
	double sum = 1;
	double term = 1;
	int i;
	for (i = 1; i < 20; i++) {
		term *= r / i;
		sum += term;
	}
	return ldexp (sum, k);
}

double pow(double x, double y) {
	if (y == 0) {
		return 1;
	}
	if (x == 0) {
		return 0;
	}
	if (y == trunc (y) && fabs (y) < 1024) {
		double r = 1;
		double b = x;
		long long n = (long long)fabs (y);
		while (n) {
			if (n & 1) {
				r *= b;
			}
			b *= b;
			n >>= 1;
		}
		return (y < 0)? 1 / r: r;
	}
	if (x < 0) {
		return NAN;
	}
	return exp (y * log (x));
}

double exp2(double x) {
	return pow (2, x);
}

double log2(double x) {
	return log (x) / M_LN2;
}

double log10(double x) {
	return log (x) / M_LN10;
}

double cbrt(double x) {
	if (x == 0) {
		return 0;
	}
	bool neg = x < 0;
	double r = pow (fabs (x), 1.0 / 3.0);
	return neg? -r: r;
}

float powf(float x, float y) {
	return (float)pow (x, y);
}

float expf(float x) {
	return (float)exp (x);
}

float logf(float x) {
	return (float)log (x);
}

float log2f(float x) {
	return (float)log2 (x);
}

float log10f(float x) {
	return (float)log10 (x);
}

long double powl(long double x, long double y) {
	return pow ((double)x, (double)y);
}

long double expl(long double x) {
	return exp ((double)x);
}

long double logl(long double x) {
	return log ((double)x);
}

long double sqrtl(long double x) {
	return sqrt ((double)x);
}

long double fabsl(long double x) {
	return fabs ((double)x);
}

long double fmodl(long double x, long double y) {
	return fmod ((double)x, (double)y);
}

long double floorl(long double x) {
	return floor ((double)x);
}

long double ceill(long double x) {
	return ceil ((double)x);
}

static double r2efi_sin_kernel(double x) {
	/* taylor series after range reduction to [-pi, pi] */
	double x2 = x * x;
	double term = x;
	double sum = x;
	int i;
	for (i = 1; i < 12; i++) {
		term *= -x2 / ((2 * i) * (2 * i + 1));
		sum += term;
	}
	return sum;
}

double sin(double x) {
	if (x != x) {
		return x;
	}
	x = fmod (x, 2 * M_PI);
	if (x > M_PI) {
		x -= 2 * M_PI;
	} else if (x < -M_PI) {
		x += 2 * M_PI;
	}
	return r2efi_sin_kernel (x);
}

double cos(double x) {
	return sin (x + M_PI_2);
}

double tan(double x) {
	double c = cos (x);
	return (c == 0)? HUGE_VAL: sin (x) / c;
}

float sinf(float x) {
	return (float)sin (x);
}

float cosf(float x) {
	return (float)cos (x);
}

float tanf(float x) {
	return (float)tan (x);
}

double atan(double x) {
	if (x != x) {
		return x;
	}
	if (fabs (x) > 1) {
		double r = M_PI_2 - atan (1 / fabs (x));
		return (x < 0)? -r: r;
	}
	/* series converges for |x| <= 1 */
	double x2 = x * x;
	double term = x;
	double sum = 0;
	int k;
	for (k = 0; k < 60; k++) {
		sum += term / (2 * k + 1);
		term *= -x2;
	}
	return sum;
}

double atan2(double y, double x) {
	if (x > 0) {
		return atan (y / x);
	}
	if (x < 0) {
		return (y >= 0)? atan (y / x) + M_PI: atan (y / x) - M_PI;
	}
	if (y > 0) {
		return M_PI_2;
	}
	if (y < 0) {
		return -M_PI_2;
	}
	return 0;
}

float atan2f(float y, float x) {
	return (float)atan2 (y, x);
}

double asin(double x) {
	if (x < -1 || x > 1) {
		return NAN;
	}
	return atan2 (x, sqrt (1 - x * x));
}

double acos(double x) {
	return M_PI_2 - asin (x);
}

double sinh(double x) {
	double e = exp (x);
	return (e - 1 / e) / 2;
}

double cosh(double x) {
	double e = exp (x);
	return (e + 1 / e) / 2;
}

double tanh(double x) {
	double e = exp (2 * x);
	return (e - 1) / (e + 1);
}

double hypot(double x, double y) {
	return sqrt (x * x + y * y);
}

int __fpclassify(double x) {
	if (x != x) {
		return FP_NAN;
	}
	if (x == 0) {
		return FP_ZERO;
	}
	double ax = (x < 0)? -x: x;
	if (ax > 1.7976931348623157e308) {
		return FP_INFINITE;
	}
	return (ax < 2.2250738585072014e-308)? FP_SUBNORMAL: FP_NORMAL;
}

int __fpclassifyf(float x) {
	if (x != x) {
		return FP_NAN;
	}
	if (x == 0) {
		return FP_ZERO;
	}
	float ax = (x < 0)? -x: x;
	if (ax > 3.402823466e38f) {
		return FP_INFINITE;
	}
	return (ax < 1.1754943508222875e-38f)? FP_SUBNORMAL: FP_NORMAL;
}

int __fpclassifyl(long double x) {
	return __fpclassify ((double)x);
}

int __signbitl(long double x) {
	return __builtin_signbit ((double)x);
}

/* ---------- ctype ---------- */

/* the parenthesized names dodge the musl function-like macros */

int (isdigit)(int c) {
	return c >= '0' && c <= '9';
}

int (isupper)(int c) {
	return c >= 'A' && c <= 'Z';
}

int (islower)(int c) {
	return c >= 'a' && c <= 'z';
}

int (isalpha)(int c) {
	return (isupper) (c) || (islower) (c);
}

int (isalnum)(int c) {
	return (isalpha) (c) || (isdigit) (c);
}

int (isxdigit)(int c) {
	return (isdigit) (c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int (isspace)(int c) {
	return c == ' ' || (c >= '\t' && c <= '\r');
}

int (isblank)(int c) {
	return c == ' ' || c == '\t';
}

int (iscntrl)(int c) {
	return (c >= 0 && c < 0x20) || c == 0x7f;
}

int (isprint)(int c) {
	return c >= 0x20 && c < 0x7f;
}

int (isgraph)(int c) {
	return c > 0x20 && c < 0x7f;
}

int (ispunct)(int c) {
	return (isgraph) (c) && !(isalnum) (c);
}

int (isascii)(int c) {
	return c >= 0 && c < 0x80;
}

int (toupper)(int c) {
	return (islower) (c)? c - 0x20: c;
}

int (tolower)(int c) {
	return (isupper) (c)? c + 0x20: c;
}

int (toascii)(int c) {
	return c & 0x7f;
}

int (iswspace)(wint_t wc) {
	return wc < 0x80 && (isspace) ((int)wc);
}

int (iswdigit)(wint_t wc) {
	return wc < 0x80 && (isdigit) ((int)wc);
}

int (iswalpha)(wint_t wc) {
	return wc < 0x80 && (isalpha) ((int)wc);
}

int (iswalnum)(wint_t wc) {
	return wc < 0x80 && (isalnum) ((int)wc);
}

int (iswxdigit)(wint_t wc) {
	return wc < 0x80 && (isxdigit) ((int)wc);
}

int (iswprint)(wint_t wc) {
	return wc < 0x80 && (isprint) ((int)wc);
}

int (iswgraph)(wint_t wc) {
	return wc < 0x80 && (isgraph) ((int)wc);
}

int (iswpunct)(wint_t wc) {
	return wc < 0x80 && (ispunct) ((int)wc);
}

int (iswcntrl)(wint_t wc) {
	return wc < 0x80 && (iscntrl) ((int)wc);
}

int (iswblank)(wint_t wc) {
	return wc < 0x80 && (isblank) ((int)wc);
}

int (iswupper)(wint_t wc) {
	return wc < 0x80 && (isupper) ((int)wc);
}

int (iswlower)(wint_t wc) {
	return wc < 0x80 && (islower) ((int)wc);
}

wint_t (towupper)(wint_t wc) {
	return wc < 0x80? (wint_t)(toupper) ((int)wc): wc;
}

wint_t (towlower)(wint_t wc) {
	return wc < 0x80? (wint_t)(tolower) ((int)wc): wc;
}

int wcwidth(wchar_t c) {
	return (c >= 0x20)? 1: 0;
}

/* ---------- locale ---------- */

char *setlocale(int category, const char *locale) {
	(void)category;
	(void)locale;
	return "C";
}

struct lconv *localeconv(void) {
	static struct lconv lc = {
		.decimal_point = ".",
		.thousands_sep = "",
		.grouping = ""
	};
	return &lc;
}

/* ---------- assert ---------- */

_Noreturn void __assert_fail(const char *expr, const char *file, int line, const char *func) {
	fprintf (stderr, "assert failed: %s (%s:%d %s)\n", expr, file, line, func);
	abort ();
}

long lrint(double x) {
	return (long)round (x);
}

long long llrint(double x) {
	return (long long)round (x);
}

double asinh(double x) {
	return log (x + sqrt (x * x + 1));
}

double acosh(double x) {
	return log (x + sqrt (x * x - 1));
}

double atanh(double x) {
	return 0.5 * log ((1 + x) / (1 - x));
}

double expm1(double x) {
	return exp (x) - 1;
}

double log1p(double x) {
	return log (1 + x);
}

#else

/* not a uefi build */
typedef int r2efi_not_uefi;

#endif

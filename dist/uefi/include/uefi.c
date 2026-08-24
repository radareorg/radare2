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
#include <setjmp.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>

int *__errno_location(void) {
	static int e = 0;
	return &e;
}

static char *r2efi_empty_environ[] = { NULL };
char **environ = r2efi_empty_environ;

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

void explicit_bzero(void *s, size_t n) {
	memset (s, 0, n);
	__asm__ volatile ("": : "r" (s): "memory");
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

static size_t r2efi_strlcpy(char *dst, const char *src, size_t size) {
	size_t slen = strlen (src);
	if (size) {
		size_t n = (slen >= size)? size - 1: slen;
		memcpy (dst, src, n);
		dst[n] = 0;
	}
	return slen;
}

static size_t r2efi_strlcat(char *dst, const char *src, size_t size) {
	size_t dlen = strnlen (dst, size);
	if (dlen == size) {
		return size + strlen (src);
	}
	return dlen + r2efi_strlcpy (dst + dlen, src, size - dlen);
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

char *strdup(const char *s) {
	size_t n = strlen (s) + 1;
	char *p = malloc (n);
	if (p) {
		memcpy (p, s, n);
	}
	return p;
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

long long llabs(long long j) {
	return j < 0? -j: j;
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
		r2efi_strlcpy (full, path, sizeof (full));
	} else {
		r2efi_strlcpy (full, r2efi_cwd, sizeof (full));
		size_t l = strlen (full);
		if (l && full[l - 1] != '\\' && full[l - 1] != '/') {
			r2efi_strlcat (full, "\\", sizeof (full));
		}
		r2efi_strlcat (full, path, sizeof (full));
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

int fsync(int fd) {
	if (fd >= 3 && fd < R2EFI_NFD && r2efi_fds[fd].used) {
		r2efi_fds[fd].h->Flush (r2efi_fds[fd].h);
	}
	return 0;
}

int remove(const char *path) {
	return unlink (path);
}

char *getcwd(char *buf, size_t size) {
	if (!buf) {
		return strdup (r2efi_cwd);
	}
	r2efi_strlcpy (buf, r2efi_cwd, size);
	return buf;
}

int chdir(const char *path) {
	r2efi_strlcpy (r2efi_cwd, path, sizeof (r2efi_cwd));
	return 0;
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
	r2efi_strlcpy (buf, "efi-console", buflen);
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

/* ---------- stdio streams ---------- */

/* the musl FILE is a complete dummy type, so the real state hides behind it */
struct _r2efi_FILE {
	int fd;
	bool eof;
	bool err;
};

#define R2F(x) ((struct _r2efi_FILE *)(x))

static struct _r2efi_FILE r2efi_stdin = { 0, false, false };
static struct _r2efi_FILE r2efi_stdout = { 1, false, false };
static struct _r2efi_FILE r2efi_stderr = { 2, false, false };

FILE *r_uefi_stdio(int fd) {
	if (fd == 0) {
		return (FILE *)&r2efi_stdin;
	}
	return fd == 2? (FILE *)&r2efi_stderr: (FILE *)&r2efi_stdout;
}

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
	return f;
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

int fseek(FILE *f, long offset, int whence) {
	if (!f) {
		return -1;
	}
	R2F (f)->eof = false;
	return (lseek (R2F (f)->fd, offset, whence) < 0)? -1: 0;
}

long ftell(FILE *f) {
	return f? (long)lseek (R2F (f)->fd, 0, SEEK_CUR): -1;
}

void rewind(FILE *f) {
	fseek (f, 0, SEEK_SET);
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

int fgetc(FILE *f) {
	if (!f) {
		return EOF;
	}
	unsigned char c;
	if (read (R2F (f)->fd, &c, 1) != 1) {
		R2F (f)->eof = true;
		return EOF;
	}
	return c;
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

int fputs(const char *s, FILE *f) {
	size_t n = strlen (s);
	return (write (f? R2F (f)->fd: 1, s, n) == (ssize_t)n)? 0: EOF;
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

void perror(const char *s) {
	if (s && *s) {
		fputs (s, stderr);
		fputs (": ", stderr);
	}
	fputs (strerror (errno), stderr);
	fputs ("\n", stderr);
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
			r2efi_strlcpy (tmp, s, (size_t)width + 1);
		} else {
			r2efi_strlcpy (tmp, s, sizeof (tmp));
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

void _exit(int code) {
	exit (code);
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
	size_t name_len = (size_t)(eq - string);
	char *name = malloc (name_len + 1);
	if (!name) {
		return -1;
	}
	memcpy (name, string, name_len);
	name[name_len] = 0;
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

time_t mktime(struct tm *tm) {
	return r2efi_mkgmtime (tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static unsigned long long r2efi_rdtsc(void) {
	unsigned int lo, hi;
	__asm__ volatile ("rdtsc": "=a" (lo), "=d" (hi));
	return ((unsigned long long)hi << 32) | lo;
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

char *ctime_r(const time_t *timep, char *buf) {
	struct tm tm;
	return asctime_r (gmtime_r (timep, &tm), buf);
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

int gettimeofday(struct timeval *tv, void *tz) {
	(void)tz;
	if (tv) {
		tv->tv_sec = time (NULL);
		tv->tv_usec = 0;
	}
	return 0;
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

/* ---------- misc ---------- */

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
	r2efi_strlcpy (resolved_path, path, PATH_MAX);
	return resolved_path;
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

/* ---------- math ---------- */

double fabs(double x) {
	return __builtin_fabs (x);
}

double sqrt(double x) {
	double r;
	__asm__ ("sqrtsd %1, %0": "=x" (r): "x" (x));
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

double fmod(double x, double y) {
	if (y == 0) {
		return NAN;
	}
	return x - trunc (x / y) * y;
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

long double ldexpl(long double x, int exp_) {
	return ldexp ((double)x, exp_);
}

long double frexpl(long double x, int *exp_) {
	return frexp ((double)x, exp_);
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

double log2(double x) {
	return log (x) / M_LN2;
}

long double fabsl(long double x) {
	return fabs ((double)x);
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

int __fpclassifyl(long double x) {
	if (x != x) {
		return FP_NAN;
	}
	if (x == 0) {
		return FP_ZERO;
	}
	long double ax = x < 0? -x: x;
	if (ax > 1.189731495357231765e4932L) {
		return FP_INFINITE;
	}
	return ax < 3.3621031431120935063e-4932L? FP_SUBNORMAL: FP_NORMAL;
}

int __signbitl(long double x) {
	return __builtin_signbit ((double)x);
}

/* ---------- assert ---------- */

_Noreturn void __assert_fail(const char *expr, const char *file, int line, const char *func) {
	fprintf (stderr, "assert failed: %s (%s:%d %s)\n", expr, file, line, func);
	abort ();
}

#else

/* not a uefi build */
typedef int r2efi_not_uefi;

#endif

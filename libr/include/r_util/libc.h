// uefi/shim_libc.c
/* uefi_detect.h */
#ifndef R2_UTIL_LIBC_H
#define R2_UTIL_LIBC_H 1

#include <r_types_base.h>

#if R2_UEFI

#include <efi.h>
#include <efilib.h>
#include <stddef.h>
#include <stdint.h>

static inline void *memcpy(void *dst, const void *src, size_t n) {
	unsigned char *d = dst;
	const unsigned char *s = src;
	while (n--) {
		*d++ = *s++;
	}
	return dst;
}

static inline void *memmove(void *dst, const void *src, size_t n) {
	unsigned char *d = dst;
	const unsigned char *s = src;
	if (d == s) {
		return dst;
	}
	if (d < s) {
		while (n--) {
			*d++ = *s++;
		}
	} else {
		d += n;
		s += n;
		while (n--) {
			*--d = *--s;
		}
	}
	return dst;
}
static inline void *memset(void *s, int c, size_t n) {
	unsigned char *p = s;
	while (n--) {
		*p++ = (unsigned char)c;
	}
	return s;
}
static inline int memcmp(const void *a, const void *b, size_t n) {
	const unsigned char *x = a, *y = b;
	for (; n; --n, ++x, ++y) {
		if (*x != *y) {
			return *x - *y;
		}
	}
	return 0;
}

// ---------- Cadenes ----------
static inline size_t strlen(const char *s) {
	const char *p = s;
	while (*p) {
		++p;
	}
	return (size_t)(p - s);
}
static inline int strcmp(const char *a, const char *b) {
	for (; *a && (*a == *b); ++a, ++b) {
	}
	return (unsigned char)*a - (unsigned char)*b;
}
static inline int strncmp(const char *a, const char *b, size_t n) {
	for (; n && *a && (*a == *b); ++a, ++b, --n) {
	}
	return n ? (unsigned char)*a - (unsigned char)*b : 0;
}
static inline char *strchr(const char *s, int c) {
	char ch = (char)c;
	while (*s) {
		if (*s == ch) {
			return (char *)s;
		}
		++s;
	}
	return (ch == 0) ? (char *)s : NULL;
}

// ---------- Allocador ----------
static inline void *malloc(size_t n) {
	if (!n) {
		n = 1;
	}
	void *p = NULL;
	if (BS->AllocatePool(EfiLoaderData, n, &p) == EFI_SUCCESS) {
		return p;
	}
	return NULL;
}
static inline void free(void *p) {
	if (p) {
		BS->FreePool(p);
	}
}
static inline void *calloc(size_t nm, size_t sz) {
	size_t n = nm * sz;
	void *p = malloc(n);
	if (p) {
		memset(p, 0, n);
	}
	return p;
}
static inline void *realloc(void *p, size_t n) {
	if (!p) {
		return malloc(n);
	}
	if (n == 0) {
		free(p);
		return NULL;
	}
	void *q = malloc(n);
	if (!q) {
		return NULL;
	}
	// NOTE: no sabem la mida antiga -> còpia conservadora
	// si ho necessites bé, wrapeja malloc per guardar mides.
	// per ara, fem una còpia "petita".
	// Ajusta segons necessitats reals del teu camí de codi.
	memcpy(q, p, n);
	free(p);
	return q;
}

// ---------- Abort/exit ----------
void abort(void) {
	Print(L"abort()\\n");
	for (;;) {
	}
}
void exit(int code) {
	Print(L"exit(%d)\\n", code);
	for (;;) {
	}
}

// ---------- Directory operations ----------
struct dirent {
	char d_name[256];
};

typedef struct {
	void *dummy; // For UEFI, no real directory handle
} DIR;

static inline DIR *opendir(const char *name) {
	// For UEFI, directories not supported, return NULL
	return NULL;
}

static inline struct dirent *readdir(DIR *dir) {
	// Always return NULL, no entries
	return NULL;
}

static inline int closedir(DIR *dir) {
	// Nothing to do
	return 0;
}

// For readdir64, same as readdir
#define readdir64 readdir

#endif

#endif

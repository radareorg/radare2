/* radare - LGPL - Copyright 2007-2016 - pancake */

#include <r_util.h>
#include <stdlib.h>
#if __UNIX__
#include <sys/mman.h>
#endif

#define SET_BIT(p,n) ((p) |= (1 << (n)))
#define CLR_BIT(p,n) ((p) &= (~(1) << (n)))

// TODO: find better name (r_mem_length()); is this used somewhere?
R_API int r_mem_count(const ut8 **addr) {
	int i = 0;
	while (*addr++) {
		i++;
	}
	return i;
}

R_API int r_mem_eq(ut8 *a, ut8 *b, int len) {
	register int i;
	for (i = 0; i < len; i++) {
		if (a[i] != b[i]) {
			return false;
		}
	}
	return true;
}

R_API void r_mem_copyloop(ut8 *dest, const ut8 *orig, int dsize, int osize) {
	int i = 0, j;
	while (i < dsize) {
		for (j = 0; j < osize && i < dsize; j++) {
			dest[i++] = orig[j];
		}
	}
}

R_API int r_mem_cmp_mask(const ut8 *dest, const ut8 *orig, const ut8 *mask, int len) {
	int i, ret = -1;
	ut8 *mdest, *morig;
	mdest = malloc (len);
	if (!mdest) {
		return ret;
	}
	morig = malloc (len);
	if (!morig) {
		free (mdest);
		return ret;
	}
	for (i = 0; i < len; i++) {
		mdest[i] = dest[i] & mask[i];
		morig[i] = orig[i] & mask[i];
	}
	ret = memcmp (mdest, morig, len);
	free (mdest);
	free (morig);
	return ret;
}

R_API void r_mem_copybits(ut8 *dst, const ut8 *src, int bits) {
	ut8 srcmask, dstmask;
	int bytes = (int) (bits / 8);
	bits = bits % 8;
	memcpy (dst, src, bytes);
	if (bits) {
		srcmask = dstmask = 0;
		switch (bits) {
		case 1: srcmask = 0x80; dstmask = 0x7f; break;
		case 2: srcmask = 0xc0; dstmask = 0x3f; break;
		case 3: srcmask = 0xe0; dstmask = 0x1f; break;
		case 4: srcmask = 0xf0; dstmask = 0x0f; break;
		case 5: srcmask = 0xf8; dstmask = 0x07; break;
		case 6: srcmask = 0xfc; dstmask = 0x03; break;
		case 7: srcmask = 0xfe; dstmask = 0x01; break;
		}
		dst[bytes] = ((dst[bytes] & dstmask) | (src[bytes] & srcmask));
	}
}

static char readbit(const ut8 *src, int bitoffset) {
	const int wholeBytes = bitoffset / 8;
	const int remainingBits = bitoffset % 8;
	// return (src[wholeBytes] >> remainingBits) & 1;
	return (src[wholeBytes] & 1<< remainingBits);
}

static void writebit (ut8 *dst, int i, bool c) {
	int byte = i / 8;
	int bit = (i % 8);
// eprintf ("Write %d %d = %d\n", byte, bit, c);
dst += byte;
	if (c) {
		//dst[byte] |= (1 << bit);
		R_BIT_SET (dst , bit);
	} else {
		//dst[byte] &= (1 << bit);
		R_BIT_UNSET (dst , bit);
	}
}

// TODO: this method is ugly as shit.
R_API void r_mem_copybits_delta(ut8 *dst, int doff, const ut8 *src, int soff, int bits) {
	int i;
	if (doff < 0 || soff < 0 || !dst || !src) {
		return;
	}
	for (i = 0; i < bits; i++) {
		bool c = readbit (src, i + soff);
// eprintf ("%d %d\n", i, c);
		writebit (dst, i + doff, c);
	}
}

R_API ut64 r_mem_get_num(const ut8 *b, int size) {
	// LITTLE ENDIAN is the default for streams
	switch (size) {
	case 1:
		return r_read_le8 (b);
	case 2:
		return r_read_le16 (b);
	case 4:
		return r_read_le32 (b);
	case 8:
		return r_read_le64 (b);
	}
	return 0LL;
}

// TODO: SEE: R_API ut64 r_reg_get_value(RReg *reg, RRegItem *item) { .. dupped code?
R_API int r_mem_set_num(ut8 *dest, int dest_size, ut64 num) {
	// LITTLE ENDIAN is the default for streams
	switch (dest_size) {
	case 1:
		r_write_le8 (dest, (ut8) (num & UT8_MAX));
		break;
	case 2:
		r_write_le16 (dest, (ut16) (num & UT16_MAX));
		break;
	case 4:
		r_write_le32 (dest, (ut32) (num & UT32_MAX));
		break;
	case 8:
		r_write_le64 (dest, num);
		break;
	default:
		return false;
	}
	return true;
}

// The default endian is LE for streams.
// This function either swaps or copies len bytes depending on bool big_endian
// TODO: Remove completely
R_API void r_mem_swaporcopy(ut8 *dest, const ut8 *src, int len, bool big_endian) {
	if (big_endian) {
		r_mem_swapendian (dest, src, len);
	} else {
		memcpy (dest, src, len);
	}
}

// This function unconditionally swaps endian of size bytes of orig -> dest
// TODO: Remove completely
R_API void r_mem_swapendian(ut8 *dest, const ut8 *orig, int size) {
	ut8 buffer[8];
	switch (size) {
	case 1:
		*dest = *orig;
		break;
	case 2:
		*buffer = *orig;
		dest[0] = orig[1];
		dest[1] = buffer[0];
		break;
	case 3:
		*buffer = *orig;
		dest[0] = orig[2];
		dest[1] = orig[1];
		dest[2] = buffer[0];
		break;
	case 4:
		memcpy (buffer, orig, 4);
		dest[0] = buffer[3];
		dest[1] = buffer[2];
		dest[2] = buffer[1];
		dest[3] = buffer[0];
		break;
	case 8:
		memcpy (buffer, orig, 8);
		dest[0] = buffer[7];
		dest[1] = buffer[6];
		dest[2] = buffer[5];
		dest[3] = buffer[4];
		dest[4] = buffer[3];
		dest[5] = buffer[2];
		dest[6] = buffer[1];
		dest[7] = buffer[0];
		break;
	default:
		if (dest != orig) {
			memmove (dest, orig, size);
		}
	}
}

// R_DOC r_mem_mem: Finds the needle of nlen size into the haystack of hlen size
// R_UNIT printf("%s\n", r_mem_mem("food is pure lame", 20, "is", 2));
R_API const ut8 *r_mem_mem(const ut8 *haystack, int hlen, const ut8 *needle, int nlen) {
	int i, until = hlen - nlen + 1;
	if (hlen < 1 || nlen < 1) {
		return NULL;
	}
	for (i = 0; i < until; i++) {
		if (!memcmp (haystack + i, needle, nlen)) {
			return haystack + i;
		}
	}
	return NULL;
}

// TODO: rename to r_mem_mem and refactor all calls to this function
R_API const ut8 *r_mem_mem_aligned(const ut8 *haystack, int hlen, const ut8 *needle, int nlen, int align) {
	int i, until = hlen - nlen + 1;
	if (align < 1) {
		align = 1;
	}
	if (hlen < 1 || nlen < 1) {
		return NULL;
	}
	if (align > 1) {
		until -= (until % align);
	}
	for (i = 0; i < until; i += align) {
		if (!memcmp (haystack + i, needle, nlen)) {
			return haystack + i;
		}
	}
	return NULL;
}

R_API int r_mem_protect(void *ptr, int size, const char *prot) {
#if __UNIX__
	int p = 0;
	if (strchr (prot, 'x')) {
		p |= PROT_EXEC;
	}
	if (strchr (prot, 'r')) {
		p |= PROT_READ;
	}
	if (strchr (prot, 'w')) {
		p |= PROT_WRITE;
	}
	if (mprotect (ptr, size, p) == -1) {
		return false;
	}
#elif __WINDOWS__
	int r, w, x;
	DWORD p = PAGE_NOACCESS;
	r = strchr (prot, 'r')? 1: 0;
	w = strchr (prot, 'w')? 1: 0;
	x = strchr (prot, 'x')? 1: 0;
	if (w && x) {
		return false;
	}
	if (x) {
		p = PAGE_EXECUTE_READ;
	} else if (w) {
		p = PAGE_READWRITE;
	} else if (r) {
		p = PAGE_READONLY;
	}
	if (!VirtualProtect (ptr, size, p, NULL)) {
		return false;
	}
#else
#warning Unknown platform
#endif
	return true;
}

R_API void *r_mem_dup(const void *s, int l) {
	void *d = malloc (l);
	if (!d) {
		return NULL;
	}
	memcpy (d, s, l);
	return d;
}

R_API void r_mem_reverse(ut8 *b, int l) {
	ut8 tmp;
	int i, end = l / 2;
	for (i = 0; i < end; i++) {
		tmp = b[i];
		b[i] = b[l - i - 1];
		b[l - i - 1] = tmp;
	}
}

R_API bool r_mem_is_printable(const ut8 *a, int la) {
	int i;
	for (i = 0; i < la; i++) {
		if (a[i] != '\n' && a[i] != '\t' && !IS_PRINTABLE (a[i])) {
			return false;
		}
	}
	return true;
}

R_API bool r_mem_is_zero(const ut8 *b, int l) {
	int i;
	for (i = 0; i < l; i++) {
		if (b[i]) {
			return false;
		}
	}
	return true;
}

R_API void *r_mem_alloc(int sz) {
	return calloc (sz, 1);
}

R_API void r_mem_free(void *p) {
	free (p);
}

R_API void r_mem_memzero(void *dst, size_t l) {
#ifdef _MSC_VER
	RtlSecureZeroMemory (dst, l);
#else
#if HAVE_EXPLICIT_BZERO
	explicit_bzero (dst, l);
#elif HAVE_EXPLICIT_MEMSET
	(void)explicit_memset (dst, 0, l);
#else
	memset (dst, 0, l);
	__asm__ volatile ("" :: "r"(dst) : "memory");
#endif
#endif
}

R_API void *r_mem_mmap_resize(RMmap *m, ut64 newsize) {
#if __WINDOWS__
	if (m->fm != INVALID_HANDLE_VALUE) {
		CloseHandle (m->fm);
	}
	if (m->fh != INVALID_HANDLE_VALUE) {
		CloseHandle (m->fh);
	}
	if (m->buf) {
		UnmapViewOfFile (m->buf);
	}
#elif __UNIX__
	if (munmap (m->buf, m->len) != 0) {
		return NULL;
	}
#endif
	if (!r_sys_truncate (m->filename, newsize)) {
		return NULL;
	}

	m->len = newsize;
	r_file_mmap_arch (m, m->filename, m->fd);
	return m->buf;
}

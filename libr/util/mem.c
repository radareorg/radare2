/* radare - LGPL - Copyright 2007-2024 - pancake */

#include <r_util.h>
#if R2__UNIX__
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

// R2580 return bool
R_API bool r_mem_eq(ut8 *a, ut8 *b, int len) {
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
	ut8 *mdest = malloc (len);
	if (!mdest) {
		return -1;
	}
	ut8 *morig = malloc (len);
	if (!morig) {
		free (mdest);
		return -1;
	}
	int i;
	for (i = 0; i < len; i++) {
		mdest[i] = dest[i] & mask[i];
		morig[i] = orig[i] & mask[i];
	}
	int ret = memcmp (mdest, morig, len);
	free (mdest);
	free (morig);
	return ret;
}

R_API void r_mem_copybits(ut8 *dst, const ut8 *src, int bits) {
	const ut8 srcmask[8] = {0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE};
	const ut8 dstmask[8] = {0x00, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01};
	const int bytes = bits / 8;
	const int modbits = bits % 8;
	memcpy (dst, src, bytes);
	if (modbits) {
		dst[bytes] = (dst[bytes] & dstmask[modbits]) | (src[bytes] & srcmask[modbits]);
	}
}

static inline char readbit(const ut8 *src, int bitoffset) {
	const int wholeBytes = bitoffset / 8;
	const int remainingBits = bitoffset % 8;
	// return (src[wholeBytes] >> remainingBits) & 1;
	return (src[wholeBytes] & 1<< remainingBits);
}

static inline void writebit(ut8 *dst, int i, bool c) {
	const int byte = i / 8;
	const int bit = (i % 8);
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

R_API void r_mem_copybits_delta(ut8 *dst, int doff, const ut8 *src, int soff, int bits) {
	int i;
	if (doff < 0 || soff < 0 || !dst || !src) {
		return;
	}
	for (i = 0; i < bits; i++) {
		bool c = readbit (src, i + soff);
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
R_API bool r_mem_set_num(ut8 *dest, int dest_size, ut64 num) {
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
#if R_SYS_ENDIAN
	// on big endian machine
	if (big_endian) {
		memcpy (dest, src, len);
	} else {
		r_mem_swapendian (dest, src, len);
	}
#else
	// on little endian machine
	if (big_endian) {
		r_mem_swapendian (dest, src, len);
	} else {
		memcpy (dest, src, len);
	}
#endif
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

R_API void r_mem_swap(ut8 *buf, size_t buf_len) {
	size_t pos = 0;
	buf_len--;
	while (pos < buf_len) {
		int x = buf[pos];
		buf[pos] = buf[buf_len];
		buf[buf_len] = x;
		pos++;
		buf_len--;
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

R_API bool r_mem_protect(void *ptr, int size, const char *prot) {
#if __wasi__
	return false;
#elif R2__UNIX__
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
#elif R2__WINDOWS__
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
	R_RETURN_VAL_IF_FAIL (s, NULL);
	void *d = NULL;
	if (l > 0) {
		d = malloc (l);
		if (d != NULL) {
			memcpy (d, s, l);
		}
	}
	return d;
}

R_API void *r_mem_set(ut8 ch, int l) {
	void *d = malloc (l);
	if (d) {
		memset (d, ch, l);
	}
	return d;
}


R_API void r_mem_reverse(ut8 *b, int l) {
	R_RETURN_IF_FAIL (b);
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

R_API void r_mem_zero(void *dst, size_t l) {
#ifdef _MSC_VER
	RtlSecureZeroMemory (dst, l);
#elif __MINGW32__
	memset (dst, 0, l);
#elif HAVE_EXPLICIT_BZERO
	explicit_bzero (dst, l);
#elif HAVE_EXPLICIT_MEMSET
	(void)explicit_memset (dst, 0, l);
#else
	memset (dst, 0, l);
	__asm__ volatile ("" :: "r"(dst) : "memory");
#endif
}

R_API int r_mem_from_binstring(const char* str, ut8 *buf, size_t len) {
	int i, j, k, ret;
	str = r_str_trim_head_ro (str);

	int str_len = strlen (str);
	ut8 *b = buf;
	ut8 *e = buf + len;
	for (i = 0; i < str_len && b < e; i += 8) {
		ret = 0;
		str = r_str_trim_head_ro (str);
		if (i + 7 >= str_len) {
			b[0] = 0; // null terminate if possible
			// missing bytes
			return -1;
		}
		for (k = 0, j = i + 7; j >= i; j--, k++) {
			if (str[j] == ' ') {
				continue;
			}
			if (str[j] == '1') {
				ret |= (1 << k);
			} else if (str[j] != '0') {
				b[0] = 0; // null terminate if possible
				return -1;
			}
		}
		*b++ = ret;
	}
	b[0] = 0;
	return b - buf;
}

R_API char *r_mem_to_binstring(const ut8* str, int len) {
	if (len < 0) {
		len = strlen ((const char *)str);
	}
	RStrBuf *buf = r_strbuf_new (NULL);
	int i = 0;

	for (i = 0; i < len; i++) {
		ut8 ch = str[i];
		r_strbuf_appendf (buf, "%c", ch & 128? '1': '0');
		r_strbuf_appendf (buf, "%c", ch & 64? '1': '0');
		r_strbuf_appendf (buf, "%c", ch & 32? '1': '0');
		r_strbuf_appendf (buf, "%c", ch & 16? '1': '0');
		r_strbuf_appendf (buf, "%c", ch & 8? '1': '0');
		r_strbuf_appendf (buf, "%c", ch & 4? '1': '0');
		r_strbuf_appendf (buf, "%c", ch & 2? '1': '0');
		r_strbuf_appendf (buf, "%c", ch & 1? '1': '0');
	}

	return r_strbuf_drain (buf);
}

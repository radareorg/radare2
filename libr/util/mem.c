/* radare - LGPL - Copyright 2007-2014 - pancake */

#include <r_util.h>
#include <stdlib.h>
#if __UNIX__
#include <sys/mman.h>
#endif

// TODO: find better name (r_mem_length()); is this used somewhere?
R_API int r_mem_count(const ut8 **addr) {
	int i = 0;
	while (*addr++)
		i++;
	return i;
}

R_API int r_mem_eq(ut8 *a, ut8 *b, int len) {
	register int i;
	for (i=0; i<len; i++)
		if (a[i] != b[i])
			return R_FALSE;
	return R_TRUE;
}

R_API void r_mem_copyloop(ut8 *dest, const ut8 *orig, int dsize, int osize) {
	int i=0, j;
	while (i<dsize)
		for (j=0; j<osize && i<dsize;j++)
			dest[i++] = orig[j];
}

R_API int r_mem_cmp_mask(const ut8 *dest, const ut8 *orig, const ut8 *mask, int len) {
	int i, ret = -1;
	ut8 *mdest, *morig;
	mdest = malloc (len);
	morig = malloc (len);
	for (i=0; i<len; i++) {
		mdest[i] = dest[i]&mask[i];
		morig[i] = orig[i]&mask[i];
	}
	ret = memcmp (mdest, morig, len);
	free (mdest);
	free (morig);
	return ret;
}

R_API void r_mem_copybits(ut8 *dst, const ut8 *src, int bits) {
	ut8 srcmask, dstmask;
	int bytes = (int)(bits/8);
	bits = bits%8;

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
		dst[bytes] = ((dst[bytes]&dstmask) | (src[bytes]&srcmask));
	}
}

// TODO: this method is ugly as shit.
R_API void r_mem_copybits_delta(ut8 *dst, int doff, const ut8 *src, int soff, int bits) {
	int nbits = bits;
#if 0
	int dofb, sofb;
	int bdoff = (doff/8);
	int bsoff = (soff/8);
	int nbits = 0;
	ut8 mask;
	int sdelta = soff-doff;
	/* apply delta offsets */
	src = src+bsoff;
	dst = dst+bdoff;
	dofb=doff%8;
	sofb=soff%8;
	if (sofb||dofb) {
		// TODO : this algorithm is not implemented
		int mask = (1<<sofb);
		int nmask = 0xff^mask;
		int s = src[0]<<sofb;
		int d = dst[0]<<dofb;
		if (soff == doff && bits==1) {
			mask = 0xff^(1<<dofb);
			dst[0] = ((src[0]&mask) | (dst[0]&mask));
		} else printf("TODO: Oops. not supported method of bitcopy\n");
/*
	1) shift algin src i dst
	2) copy (8-dofb) bits from dst to src
	3) dst[0] = dst[0]&^(0x1<<nbits) | (src&(1<<nbits))
*/
		src++;
		dst++;
	}
/*
doff  v
dst |__________|___________|
soff     v
src |__________|_________|
*/
#endif
	r_mem_copybits (dst, src, nbits);
}

R_API ut64 r_mem_get_num(const ut8 *b, int size, int endian) {
        ut16 n16;
        ut32 n32;
        ut64 n64;
        switch (size) {
        case 1: return b[0];
        case 2:
                r_mem_copyendian ((ut8*)&n16, b, 2, endian);
		return (ut64)n16;
        case 4:
                r_mem_copyendian ((ut8*)&n32, b, 4, endian);
		return (ut64)n32;
        case 8:
                r_mem_copyendian ((ut8*)&n64, b, 8, endian);
		return (ut64)n64;
        }
	return 0LL;
}

// TODO: SEE: R_API ut64 r_reg_get_value(RReg *reg, RRegItem *item) { .. dupped code?
R_API int r_mem_set_num (ut8 *dest, int dest_size, ut64 num, int endian) {
	int num4;
	short num2;
	switch (dest_size) {
	case 1: dest[0] = (ut8) num;
		break;
	case 2: num2 = (short)num;
		r_mem_copyendian (dest, (const ut8*)&num2, 2, endian);
		break;
	case 4: num4 = (int)num;
		r_mem_copyendian (dest, (const ut8*)&num4, 4, endian);
		break;
	case 8: r_mem_copyendian (dest, (const ut8*)&num, 8, endian);
		break;
	default:
		return R_FALSE;
	}
	return R_TRUE;
}

/* XXX TODO check and use system endian */
// TODO: rename to r_mem_swap() */
R_API void r_mem_copyendian (ut8 *dest, const ut8 *orig, int size, int endian) {
	ut8 buffer[8];
        if (endian) {
		if (dest != orig)
			memmove (dest, orig, size);
        } else
	switch (size) {
	case 1:
		*dest = *orig;
		break;
	case 2:
		*buffer = *orig;
		dest[0] = orig[1];
		dest[1] = buffer[0];
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
		if (dest != orig)
			memmove (dest, orig, size);
		//eprintf ("Invalid endian copy of size: %d\n", size);
	}
}

//R_DOC r_mem_mem: Finds the needle of nlen size into the haystack of hlen size
//R_UNIT printf("%s\n", r_mem_mem("food is pure lame", 20, "is", 2));
R_API const ut8 *r_mem_mem(const ut8 *haystack, int hlen, const ut8 *needle, int nlen) {
	int i, until = hlen-nlen+1;
	if (hlen<1 || nlen<1)
		return NULL;
	for (i=0; i<until; i++) {
		if (!memcmp (haystack+i, needle, nlen))
			return haystack+i;
	}
	return NULL;
}

// TODO: implement pack/unpack helpers use vararg or wtf?
R_API int r_mem_pack() {
	// TODO: copy this from r_buf??
	return R_TRUE;
}

R_API int r_mem_unpack(const ut8 *buf) {
	// TODO: copy this from r_buf??
	return R_TRUE;
}

R_API int r_mem_protect(void *ptr, int size, const char *prot) {
#if __UNIX__
	int p = 0;
	if (strchr (prot, 'x')) p |= PROT_EXEC;
	if (strchr (prot, 'r')) p |= PROT_READ;
	if (strchr (prot, 'w')) p |= PROT_WRITE;
	if (mprotect (ptr, size, p)==-1)
		return R_FALSE;
#elif __WINDOWS__ || __CYGWIN__
	int r, w, x;
	DWORD p = PAGE_NOACCESS;
	r = strchr (prot, 'r')? 1: 0;
	w = strchr (prot, 'w')? 1: 0;
	x = strchr (prot, 'x')? 1: 0;;
	if (w && x) return R_FALSE;
	if (x) p = PAGE_EXECUTE_READ;
	else if (w) p = PAGE_READWRITE;
	else if (r) p = PAGE_READONLY;
	if (!VirtualProtect (ptr, size, p, NULL))
		return R_FALSE;
#else
	#warning Unknown platform
#endif
	return R_TRUE;
}

R_API void *r_mem_dup (void *s, int l) {
	void *d = malloc (l);
	if (!d) return NULL;
	memcpy (d, s, l);
	return d;
}

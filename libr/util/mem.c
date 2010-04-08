/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

#include <r_util.h>
#include <stdlib.h>

// TODO: find better name
R_API int r_mem_count(ut8 **addr) {
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
        int i=0,j;
        while (i<dsize)
                for (j=0; j<osize && i<dsize;j++)
                        dest[i++] = orig[j];
}

R_API int r_mem_cmp_mask(const ut8 *dest, const ut8 *orig, const ut8 *mask, int len) {
	int i, ret = 0;
	for (i=0; i<len; i++)
		ret += (orig[i]&mask[i])&dest[i];
	return ret;
}

R_API void r_mem_copybits(ut8 *dst, const ut8 *src, int bits) {
	int bytes = (int)(bits/8);
	bits = bits%8;
	
	memcpy (dst, src, bytes);
	if (bits) {
		ut8 srcmask, dstmask;
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

/* XXX TODO check and use system endian */
R_API void r_mem_copyendian (ut8 *dest, const ut8 *orig, int size, int endian) {
	ut8 buffer[8];
        if (endian) {
		if (dest != orig)
			memcpy (dest, orig, size);
        } else
	switch (size) {
	case 1:
		dest[0] = orig[0];
		break;
	case 2:
		buffer[0] = orig[0];
		dest[0] = orig[1];
		dest[1] = buffer[0];
		break;
	case 4:
		memcpy(buffer, orig, 4);
		dest[0] = buffer[3];
		dest[1] = buffer[2];
		dest[2] = buffer[1];
		dest[3] = buffer[0];
		break;
	case 8:
		memcpy(buffer, orig, 8);
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
		eprintf ("Invalid size: %d\n", size);
	}
}

//R_DOC r_mem_mem: Finds the needle of nlen size into the haystack of hlen size
//R_UNIT printf("%s\n", r_mem_mem("food is pure lame", 20, "is", 2));
R_API const ut8 *r_mem_mem(const ut8 *haystack, int hlen, const ut8 *needle, int nlen) {
	int i, until = hlen-nlen;
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

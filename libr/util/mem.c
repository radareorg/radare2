/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include <r_util.h>
#include <stdlib.h>

R_API void r_mem_copyloop (ut8 *dest, const ut8 *orig, int dsize, int osize)
{
        int i=0,j;
        while(i<dsize)
                for(j=0;j<osize && i<dsize;j++)
                        dest[i++] = orig[j];
}

R_API int r_mem_cmp_mask(const ut8 *dest, const ut8 *orig, const ut8 *mask, int len)
{
	int i, ret = 0;
	for(i=0;i<len;i++)
		ret += (orig[i]&mask[i])&dest[i];
	return ret;
}

R_API void r_mem_copybits(ut8 *dst, const ut8 *src, int bits)
{
	int bytes = (int)(bits/8);
	bits = bits%8;
	
	memcpy(dst, src, bytes);
	if (bits) {
		ut8 srcmask, dstmask;
		switch(bits) {
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

/* XXX TODO check and use system endian */
R_API void r_mem_copyendian (ut8 *dest, const ut8 *orig, int size, int endian)
{
        if (endian) {
		if (dest != orig)
			memcpy(dest, orig, size);
        } else {
                unsigned char buffer[8];
                switch(size) {
                case 2:
                        buffer[0] = orig[0];
                        dest[0]   = orig[1];
                        dest[1]   = buffer[0];
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
                        printf("Invalid size: %d\n", size);
                }
        }
}

//R_DOC r_mem_mem: Finds the needle of nlen size into the haystack of hlen size
//R_UNIT printf("%s\n", r_mem_mem("food is pure lame", 20, "is", 2));
R_API const ut8 *r_mem_mem(const ut8 *haystack, int hlen, const ut8 *needle, int nlen)
{
	int i, until = hlen-nlen;
	for(i=0;i<until;i++) {
		if (!memcmp(haystack+i, needle, nlen))
			return haystack+i;
	}
	return NULL;
}

// TODO: implement pack/unpack helpers use vararg or wtf?
R_API int r_mem_pack()
{
	// TODO
	return R_TRUE;
}

R_API int r_mem_unpack(const ut8 *buf)
{
	// TODO
	return R_TRUE;
}

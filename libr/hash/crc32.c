/* Copyright (C) radare2 - 2007-2012 - pancake */

#include <r_types.h>
#include <r_util.h>

static char crc_table_is_init = 0;
static ut32 crc_table[256];

R_API ut32 r_hash_crc32(const ut8 *buf, ut64 len) {
	ut32 crc = 0;
	ut8 tmp[sizeof (ut32)];
	if (!crc_table_is_init) {
		ut32 i, j, h = 1;
		crc_table_is_init = 1;
		crc_table[0] = 0;
		for (i = 128; i; i >>= 1) {
			h = (h >> 1) ^ ((h & 1) ? (int)0xedb88320 : 0);
			for (j = 0; j < 256; j += 2*i)
			crc_table[i+j] = crc_table[j] ^ h;
		}
	}
	crc ^= 0xffffffff;
	while (len--)
		crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];

	crc ^= 0xffffffff;

	// unswap endian
	r_write_le32 (tmp, crc);
	crc = r_read_be32 (tmp);
	return crc;
}

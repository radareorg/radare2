/* Copyright (C) radare2 - 2007-2016 - pancake */

#include <r_types.h>
#include <r_util.h>

static bool crc_table_is_init = false;
static ut32 crc_table[256];

R_API ut32 r_hash_crc32(const ut8 *buf, ut64 len) {
	ut32 crc = 0;
	ut8 tmp[sizeof (ut32)];
	if (!crc_table_is_init) {
		ut32 i, j, h = 1;
		crc_table_is_init = true;
		crc_table[0] = 0;
		for (i = 128; i; i >>= 1) {
			h = (h >> 1) ^ ((h & 1) ? (int)0xedb88320 : 0);
			for (j = 0; j < 256; j += 2*i)
			crc_table[i+j] = crc_table[j] ^ h;
		}
	}
	crc ^= UT32_MAX;
	while (len--) {
		crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
	}
	crc ^= UT32_MAX;

	// unswap endian
	r_write_le32 (tmp, crc);
	return r_read_le32 (tmp);
}

/*
 * Copyright (C) 2007, 2008
 *       pancake <youterm.com>
 *
 * radare is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * radare is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with radare; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "r_types.h"

static char crc_table_is_init = 0;
static ut32 crc_table[256];

ut32 r_hash_crc32(const ut8 *buf, ut64 len)
{
	unsigned int crc = 0;

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

	return crc ^ 0xffffffff;
}

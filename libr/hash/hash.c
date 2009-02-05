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

#define IS_PRINTABLE(x) (x>=' '&&x<='~')

/* returns 0-100 */
int r_hash_pcprint(u8 *buffer, u64 len)
{
	u8 *end = buffer + len;
	int n;

	for(n=0; buffer<end; buffer = buffer + 1)
		if (IS_PRINTABLE(buffer[0]))
			n++;

	return ((100*n)/len);
}

int r_hash_par(u8 *buf, u64 len)
{
	u8 *end = buf+len;
	u32 ones = 0;
	for(;buf<end; buf = buf + 1) {
		u8 x = buf[0];
		ones += ((x&128)?1:0) + ((x&64)?1:0) + ((x&32)?1:0) + ((x&16)?1:0) +
			((x&8)?1:0) + ((x&4)?1:0) + ((x&2)?1:0) + ((x&1)?1:0);
	}
	return ones%2;
}

/* These functions comes from 0xFFFF */
/* fmi: nopcode.org/0xFFFF */
u16 r_hash_xorpair(const u8 *a, u64 len)
{
	u16 *b = (u16 *)a;
	u16 result = 0;
	for(len>>=1;len--;b=b+1)
		result^=b[0];
	return result;
}

u8 r_hash_xor(const u8 *b, u64 len)
{
	u8 res = 0;
	for(;len--;b=b+1)
		res^=b[0];
	return res;
}

u8 r_hash_mod255(const u8 *b, u64 len)
{
	int i, c = 0;
	/* from gdb */
	for (i = 0; i < len; i++)
		c += b[i];
	return c%255;
}

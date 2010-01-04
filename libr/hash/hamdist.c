/*
 * Copyright (C) 2007-2010
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

#if 0

From Wikipedia, the free encyclopedia

In information theory, the Hamming distance between two strings of equal
length is the number of positions for which the corresponding symbols
are different. Put another way, it measures the minimum number of
substitutions required to change one into the other, or the number of
errors that transformed one string into the other.

#endif

#include "r_types.h"

static int hamdist(int x, ut64 y)
{
	int dist = 0, val = x^y;

	while(val) {
		++dist; 
		val &= val - 1;
	}

	return dist;
}

R_API ut8 r_hash_hamdist(const ut8 *buf, ut64 len)
{
	int i, x, y;
	x = y = i = 0;
	for(i=0;i<len;i++) {
		y = buf[i];
		x = hamdist(x, y);
	}
	return x;
}


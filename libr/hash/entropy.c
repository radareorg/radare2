/*
 * This code was done 
 *    by an anonymous gnome
 * ------------------------
 * That's pure mathematics, so no sense to adding license shit here.
 */

#include <stdlib.h>
#include <math.h>
#include "r_types.h"

static double get_px(ut8 x, const ut8 *data, ut64 size) {
	ut64 i, count = 0;
	for (i = 0; i < size; i++) {
		if (data[i] == x) {
			count++;
		}
	}
	return (size > 0) ? (double) count / size: 0;
}

R_API double r_hash_entropy(const ut8 *data, ut64 size) {
	ut32 x;
	double h = 0, px, log2 = log (2.0);
	for (x = 0; x < 256; x++) {
		px = get_px (x, data, size);
		if (px > 0) {
			h += -px * (log (px) / log2);
		}
	}
	return h;
}

R_API double r_hash_entropy_fraction(const ut8 *data, ut64 size) {
	double h = r_hash_entropy (data, size);
	if (size < 256) {
		double base = log (size);
		return base ? ((h * log (2.0)) / base) : 0;
	}
	return h / 8;
}

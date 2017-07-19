/*
 * This code was done 
 *    by an anonymous gnome
 * ------------------------
 * That's pure mathematics, so no sense to adding license shit here.
 */

#include <stdlib.h>
#include <math.h>
#include "r_types.h"

R_API double r_hash_entropy(const ut8 *data, ut64 size) {
	if (!data || !size) {
		return 0;
	}
	ut64 i, count[256] = {0};
	double h = 0;
	for (i = 0; i < size; i++) {
		count[data[i]]++;
	}
	for (i = 0; i < 256; i++) {
		if (count[i]) {
			double p = (double) count[i] / size;
			h -= p * log2 (p);
		}
	}
	return h;
}
R_API double r_hash_entropy_fraction(const ut8 *data, ut64 size) {
	return size ? r_hash_entropy (data, size) / \
		log2 ((double) R_MIN (size, 256)) : 0;
}

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
        for (i = 0; i < size; i++)
                if (data[i] == x)
                        count++;
        return (double) count / size;
}

R_API double r_hash_entropy(const ut8 *data, ut64 size) {
        ut32 x;
        double h = 0, px, log2 = log (2.0);
        for (x = 0; x < 256; x++) {
                px = get_px (x, data, size);
                if (px > 0)
                        h += -px * (log (px) / log2);
        }
        return h;
}

R_API double r_hash_entropy_fraction(const ut8 *data, ut64 size) {
	double h = r_hash_entropy (data, size);
	if (size < 256)
		return h * log (2.0) / log (size);
	return h/8; //(size/256);//8;
}

// 0-8
#if TEST
main() {
	int i;
	ut8 b[40960];
	for (i=0;i<sizeof(b);i++)
		b[i] = i;
	//memset (b, 'A', sizeof (b));
	memset (b, 'A', 512);
	printf ("%f\n", r_hash_entropy (b, 10));
	printf ("%f\n", r_hash_entropy (b, 100));
	printf ("%f\n", r_hash_entropy (b, 200));
	printf ("%f\n", r_hash_entropy (b, 256));
	printf ("%f\n", r_hash_entropy (b, 4095));
	printf ("%f\n", r_hash_entropy (b, 8095));
	printf ("%f\n", r_hash_entropy (b, sizeof (b)));
}
#endif

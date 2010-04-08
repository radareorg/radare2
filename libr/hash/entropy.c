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
        ut32 i, count = 0;
        for (i = 0; i < size; i++)
                if (data[i] == x)
                        count++;
        return (double)count/size;
}

R_API double r_hash_entropy(const ut8 *data, ut64 size) {
        double h = 0, px, log2;
        unsigned char x;

        log2 = logf ((double)2);
        for (x = 0; x < 255; x++) {
                px = get_px (x, data, size);
                if (px > 0)
                        h += -px * (log (px)/log2);
        }
        return h;
}

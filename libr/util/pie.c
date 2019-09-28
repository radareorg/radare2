/* radare2 - LGPL - Copyright 2018 - pancake */

#include <r_util.h>
#include <r_util/r_print.h>
#include <math.h>
#define PI 3.1415
#define O out[x + (y * size)]
#define USE_SINCOS 0

// TODO: add support for colors
// TODO: better rounding ascii art
// TODO: add support for xy_factor

static void drawSectorLine(char *out, int size, int percent) {
	int i, x, y;
	double A = (percent)*PI / 50;
	double foo = 0.1;
	for (i = (size - 1) / 2; i < (size - 3); i++) {
		x = y = (size - 1) / 2;
		x += cos (A) * foo + 1;
		y += sin (A) * foo + 1;
		foo += 1.1;
		O = '.';
	}
}

R_API int r_print_pie(RPrint *p, ut64 *values, int nvalues, int size) {
	ut8 *nv = calloc (nvalues, sizeof (ut8));
	char *out = calloc (size, size);
	int i, x, y;
	if (nv && out) {
		ut64 total = 0;
		for (i = 0; i < nvalues; i++) {
			total += values[i];
		}
		total /= 100;
		if (total < 1) {
			total = 1;
		}
		for (i = 0; i < nvalues; i++) {
			nv[i] = values[i] / total;
		}
		for (x = 0; x < size; x++) {
			for (y = 0; y < size; y++) {
				O = ' ';
			}
		}
#if USE_SINCOS
		float a = 0.0;
		int s = size / 2;
		while (a < 2 * PI) {
			x = s * cos (a) + (size / 2);
			y = s * sin (a) + (size / 2);
			O = '.';
			a += 0.1;
		}
#else
		int radius = (size - 1) / 2;

		// draw portions
		for (x = 0; x <= 2 * radius; x++) {
			for (y = 0; y <= 2 * radius; y++) {
				double distance = sqrt ((double)(x - radius) * (x - radius) + (y - radius) * (y - radius));
				O = (distance > radius - 0.5 && distance < radius + 0.5) ? 'x' : ' ';
			}
		}
#endif
		int amount = 0;
		for (i = 0; i < nvalues; i++) {
			drawSectorLine (out, size, nv[i] + amount);
			amount += nv[i];
		}

		/// render
		if (p && p->cb_printf) {
			for (x = 0; x < size; x++) {
				for (y = 0; y < size; y++) {
					p->cb_printf ("%c%c", O, O);
				}
				p->cb_printf ("\n");
			}
		}
	}
	free (out);
	free (nv);
	return 0;
}
#if 0
main() {
	ut64 v[] = { 10, 20, 30, 40 };
	r_print_pie (NULL, &v, 4, 20);
}
#endif

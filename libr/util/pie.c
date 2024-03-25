/* radare2 - LGPL - Copyright 2018-2024 - pancake */

#include <r_util.h>
#include <r_util/r_print.h>
#include <math.h>
#define PI 3.1415
#define O out[x + (y * size)]
#define USE_SINCOS 0

// TODO: [ ] add colors
// TODO: [ ] better rounding ascii art
// TODO: [ ] add support for xy_factor

static void drawSectorLine(char *out, int size, int percent, int ch) {
	int i, x, y;
	double foo = 0.02;
	double A = (percent * PI) / 50;
	for (i = (size - 1) / 2; i < (size*2); i++) {
		x = y = (size - 1) / 2;
		x += (int)(cos (A) * foo);
		y += (int)(sin (A) * foo);
		foo += 0.3; // 1.3;
		O = ch; //  '.';
	}
}

static void fillSectorLine(char *out, int size, int percent, int ch) {
	int i;
	for (i = 0; i < size; i++) {
		drawSectorLine (out, size, percent +i, ch);
	}
}

static void drawPieChart(char *out, int size, int numSlices, int sliceSizes[], const char **text) {
	int totalDegrees = 0;
	char sliceChars[] = "0123456789"; // {'*', '+', '=', '-', '#', '%', '&', '$'}; // Characters for different slices
	int sliceCharCount = sizeof(sliceChars) / sizeof(sliceChars[0]);
	int RADIUS = size / 2;
	int x, y, i;
	// Calculate the start and end angle for each slice
	int sliceAngles[11]; // max slices is 10
	sliceAngles[0] = 0; // Starting angle for the first slice
	for (i = 0; i < numSlices; i++) {
		totalDegrees += (int)(360.0 * sliceSizes[i] / 100.0);
		sliceAngles[i+1] = totalDegrees;
//		printf ("%d\n", totalDegrees);
	}
	// if (numSlices < 11 && totalDegrees < 360) {
	if (totalDegrees < 360) {
		numSlices++;
		sliceAngles[numSlices] = 360; //  - totalDegrees;
	}

	int half = RADIUS;
#define A out[(x+half) + ((y+half) * (half*2))]
	// Draw the pie chart
	for (y = -RADIUS; y <= RADIUS; y++) {
		for (x = -RADIUS; x <= RADIUS; x++) {
			double distance = sqrt (x * x + y * y);
			// Check if the current point is within the circle
			if (distance < RADIUS) {
				double angle = atan2(y, x) * 180 / PI;
				if (angle < 0) {
					angle += 360;
				}
				int sliceIndex = -1;
				for (i = 0; i < numSlices; i++) {
					if (angle >= sliceAngles[i] && angle < sliceAngles[i+1]) {
						sliceIndex = i;
						break;
					}
				}
				if (sliceIndex != -1) {
					const char ch = sliceChars[sliceIndex % sliceCharCount];
					A = ch;
				//	printf ("%c%c", ch, ch);
				} else {
					A = ' ';
				//	printf ("  "); // Should not happen, but just in case
				}
			} else {
				A = ' ';
				//printf ("  ");
			}
		}
		// printf ("\n");
	}
}

R_API int r_print_pie(R_NULLABLE RPrint *p, int nvalues, int *values, const char **text, int size) {
	if (nvalues > 9) {
		R_LOG_WARN ("Cant render more than 10 portions in a pie chart");
		nvalues = 9;
	}
	ut8 *nv = calloc (nvalues, sizeof (ut8));
	char *out = calloc (size, size);

	drawPieChart (out, size, nvalues, values, text);

	const bool use_colors = p? p->flags & R_PRINT_FLAGS_COLOR: false;
	const char *fg_colors[10] = {
		Color_GREEN,
		Color_RED,
		Color_YELLOW,
		Color_BLUE,
		Color_WHITE,
		Color_MAGENTA,
		Color_CYAN,
		Color_GREEN,
		Color_RED,
		Color_YELLOW,
	};
	const char *bg_colors[10] = {
		Color_BGGREEN,
		Color_BGRED,
		Color_BGYELLOW,
		Color_BGBLUE,
		Color_BGWHITE,
		Color_BGMAGENTA,
		Color_BGCYAN,
		Color_BGGREEN,
		Color_BGRED,
		Color_BGYELLOW,
	};
	const char *leg[20] = {0};
	int i, x, y;
	for (i = 0; i < 20; i++) {
		leg[i] = "??";
	}
	for (i = 0; i < nvalues;i++) {
		if (text[i]) {
			leg[i] = text[i];
		}
	}
	int legend_idx = 0;
	if (nv && out) {
#if 0
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
				O = (distance > radius - 0.5 && distance < radius + 0.5) ? '*' : ' ';
			}
		}
#endif
		int amount = 0;

		for (i = 0; i < nvalues; i++) {
			fillSectorLine (out, size, nv[i] + amount, '0' + i);
			amount += nv[i];
		}
#if 0
		for (i = 1; i < nvalues; i++) {
			drawSectorLine (out, size, nv[i] + amount, ',');
			amount += nv[i];
		}
#endif
#endif

		/// render
		if (p && p->cb_printf) {
			for (y = 0; y < size; y++) {
				for (x = 0; x < size; x++) {
					if (use_colors && isdigit (O)) {
						const int index = O - '0';
						p->cb_printf ("%s··"Color_RESET, fg_colors[index]);
					} else {
						p->cb_printf ("%c%c", O, O);
					}
				}
				if (y > 0 && legend_idx < nvalues) {
					if (y % 2) {
						if (leg[legend_idx]) {
							if (use_colors) {
								p->cb_printf ("  %s  "Color_RESET" - %s",
									bg_colors[legend_idx], leg[legend_idx]);
							} else {
								p->cb_printf ("  %c%c - %s",
									'0' + legend_idx,
									'0' + legend_idx,
									leg[legend_idx]);
							}
						}
						legend_idx++;
					}
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

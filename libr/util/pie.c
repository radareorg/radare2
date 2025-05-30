/* radare2 - LGPL - Copyright 2018-2024 - pancake */

#include <r_util.h>
#include <r_util/r_print.h>
#include <math.h>
#define PI 3.1415

#if 1
#define A(c) out[(x+half) + ((y+half) * (half*2))] = c
#else
printf ("%c%c", c, c);
#endif

static void drawPieChart(char *out, int diameter, int numSlices, int sliceSizes[], const char **text) {
	int totalDegrees = 0;
	char sliceChars[] = "0123456789";
	int sliceCharCount = sizeof (sliceChars) / sizeof (sliceChars[0]);
	int radius = diameter / 2;
	int x, y, i;

	// Calculate the start and end angle for each slice
	int sliceAngles[11]; // max slices is 10
	sliceAngles[0] = 0; // Starting angle for the first slice
	for (i = 0; i < numSlices; i++) {
		totalDegrees += (int)(360.0 * sliceSizes[i] / 100.0);
		sliceAngles[i+1] = totalDegrees;
//		printf ("%d\n", totalDegrees);
	}
	// Add the remaining slice if the sum of parts don't cover the whole pie
	if (totalDegrees < 360) {
		numSlices++;
		sliceAngles[numSlices] = 360;
	}

	int half = radius;
	// Draw the pie chart
	for (y = -radius; y <= radius; y++) {
		for (x = -radius; x <= radius; x++) {
			double distance = sqrt (x * x + y * y);
			// Check if the current point is within the circle
			if (distance < radius) {
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
					A (ch);
				//	printf ("%c%c", ch, ch);
				} else {
					A (' ');
				//	printf ("  "); // Should not happen, but just in case
				}
			} else {
				A (' ');
				// printf ("  ");
			}
		}
		// printf ("\n");
	}
}

R_API void r_print_pie(RPrint * R_NULLABLE p, int nvalues, int *values, const char **text, int size) {
	if (size < 1) {
		R_LOG_WARN ("No one cant eat such smol pie");
		return;
	}
	if (nvalues > 9) {
		R_LOG_WARN ("Cant render more than 10 portions in a pie chart");
		nvalues = 9;
	}
	ut8 *nv = calloc (nvalues, sizeof (ut8));
	char *out = calloc (size, size * size);

	drawPieChart (out, size, nvalues, values, text);

	const bool use_colors = p? p->flags & R_PRINT_FLAGS_COLOR: false;
	const char *fg_colors[10] = {
		Color_GREEN,
		Color_RED,
		Color_BLUE,
		Color_MAGENTA,
		Color_CYAN,
		Color_YELLOW,
		Color_WHITE,
		Color_GREEN,
		Color_RED,
		Color_YELLOW,
	};
	const char *bg_colors[10] = {
		Color_BGGREEN,
		Color_BGRED,
		Color_BGBLUE,
		Color_BGMAGENTA,
		Color_BGCYAN,
		Color_BGYELLOW,
		Color_BGWHITE,
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
	if (nv && out && p) {
		for (y = 0; y < size; y++) {
			for (x = 0; x < size; x++) {
				const char ch = out[x + (y * size)];
				if (use_colors && isdigit (ch)) {
					const int index = ch - '0';
					// r_print_printf (p, "%s··"Color_RESET, fg_colors[index]);
					r_print_printf (p, "%s##"Color_RESET, fg_colors[index]);
				} else {
					r_print_printf (p, "%c%c", ch, ch);
				}
			}
			if (y > 0 && legend_idx < nvalues) {
				if (y % 2) {
					if (leg[legend_idx]) {
						if (use_colors) {
							r_print_printf (p, "   %s  "Color_RESET" - %s",
									bg_colors[legend_idx], leg[legend_idx]);
						} else {
							r_print_printf (p, "   %c%c - %s",
									'0' + legend_idx,
									'0' + legend_idx,
									leg[legend_idx]);
						}
					}
					legend_idx++;
				}
			}
			r_print_printf (p, "\n");
		}
		r_print_printf (p, "\n");
	}
	free (out);
	free (nv);
}

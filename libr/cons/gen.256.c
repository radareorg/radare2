#include <stdio.h>
#include <string.h>

static const int value_range[6] = { 0x00, 0x5f, 0x87, 0xaf, 0xd7, 0xff};

int main() {
	int colors[256];
	int i, r, g, b;
	// ansi colors
	colors[0] = 0x000000;
	colors[1] = 0x800000;
	colors[2] = 0x008000;
	colors[3] = 0x808000;
	colors[4] = 0x000080;
	colors[5] = 0x800080;
	colors[6] = 0x008080;
	colors[7] = 0xc0c0c0;
	colors[8] = 0x808080;
	colors[9] = 0xff0000;
	colors[10] = 0x00ff00;
	colors[11] = 0xffff00;
	colors[12] = 0x0000ff;
	colors[13] = 0xff00ff;
	colors[14] = 0x00ffff;
	colors[15] = 0xffffff;
	// color palette
	for (i = 0; i < 216; i++) {
		r = value_range[(i / 36) % 6];
		g = value_range[(i / 6) % 6];
		b = value_range[i % 6];
		colors[i + 16] = ((r << 16) & 0xffffff) +
			((g << 8) & 0xffff) + (b & 0xff);
	}
	// grayscale
	for (i = 0; i < 24; i++) {
		r = 8 + (i * 10);
		colors[i + 232] = ((r << 16) & 0xffffff) +
			((r << 8) & 0xffff) + (r & 0xff);
	}

	printf ("static int colortable[] = {\n");
	for (i = 0; i< 256; i++) {
		if (i && !(i%16)) {
			printf ("\n");
		}
		printf ("%d, ", colors[i]);
	}
	printf ("};\n");
	return 0;
}

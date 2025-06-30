/* radare - LGPL - Copyright 2025 - pancake */

#include <r_util.h>
#include <r_util/r_print.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MIN_BOX_WIDTH 6
#define MIN_BOX_HEIGHT 3

static void drawBox(char **buffer, int width, int height, int x, int y, int w, int h, const char *text) {
	if (x < 0 || y < 0 || x + w > width || y + h > height) {
		return;
	}
	int i, j;
	for (i = 0; i < h; i++) {
		for (j = 0; j < w; j++) {
			int gx = x + j;
			int gy = y + i;
			char ch = ' ';
			if ((i == 0 || i == h - 1) || (j == 0 || j == w - 1)) {
				if ((i == 0 || i == h - 1) && (j == 0 || j == w - 1)) {
					ch = '+';
				} else if (i == 0 || i == h - 1) {
					ch = '-';
				} else if (j == 0 || j == w - 1) {
					ch = '|';
				}
			}
			(*buffer)[gy * (width + 1) + gx] = ch;
		}
	}
	if (text && w >= MIN_BOX_WIDTH && h >= MIN_BOX_HEIGHT) {
		int tx = x + 1;
		int ty = y + h / 2;
		int maxlen = w - 2;
		int len = strlen (text);
		if (len > maxlen) {
			len = maxlen;
		}
		memcpy (*buffer + ty * (width + 1) + tx, text, len);
	}
}

static inline int dodiv(float adjusted, float sum_adjusted, int d) {
	if (sum_adjusted < 1) {
		return 0;
	}
	float base = sum_adjusted * d;
	int boxw = (int)(adjusted / base);
	return R_MAX (boxw, 1);
}

static void treemapRecurse(char **buffer, int width, int height, int x, int y, int w, int h, int *values, const char **labels, int start, int n, int total, bool horizontal) {
	if (n <= 0 || w <= 0 || h <= 0 || total <= 0) {
		return;
	}
	if (n == 1) {
		char label[128];
		if (labels && labels[start]) {
			snprintf (label, sizeof (label), "%s (%d)", labels[start], values[start]);
		} else {
			snprintf (label, sizeof (label), "%d", values[start]);
		}
		drawBox (buffer, width, height, x, y, w, h, label);
		return;
	}

	int used = 0;
	int i, j;
	for (i = 0; i < n; i++) {
		int val = values[start + i];
		// soften extremes by taking square root
		float adjusted = sqrtf ((float)val);
		float sum_adjusted = 0;
		for (j = 0; j < n - i; j++) {
			sum_adjusted += sqrtf ((float)values[start + i + j]);
		}
		int boxw = w, boxh = h;
		if (horizontal) {
			boxw = dodiv (adjusted, sum_adjusted, w);
			if (i == n - 1) {
				boxw = w - used;
			}
		} else {
			boxh = dodiv (adjusted, sum_adjusted, h);
			if (i == n - 1) {
				boxh = h - used;
			}
		}

		char label[128];
		if (labels && labels[start + i]) {
			snprintf (label, sizeof (label), "%s (%d)", labels[start + i], val);
		} else {
			snprintf (label, sizeof (label), "%d", val);
		}
		drawBox (buffer, width, height, x, y, boxw, boxh, label);

		int newx = horizontal ? x + boxw - 1 : x;
		int newy = horizontal ? y : y + boxh - 1;
		int neww = horizontal ? w - boxw + 1 : w;
		int newh = horizontal ? h : h - boxh + 1;

		treemapRecurse (buffer, width, height, newx, newy, neww, newh, values, labels, start + i + 1, n - i - 1, total - val, !horizontal);
		break;
	}
}

static char *drawTreemapAscii(int *values, const char **labels, int n, int width, int height) {
	if (n <= 0 || width < 1 || height < 1) {
		return NULL;
	}
	char *buf = calloc (1, (width + 1) * height + 1);
	if (!buf) {
		return NULL;
	}
	int i;
	for (i = 0; i < height; i++) {
		memset(buf + i * (width + 1), ' ', width);
		buf[i * (width + 1) + width] = '\n';
	}
	int total = 0;
	for (i = 0; i < n; i++) {
		total += values[i];
	}
	treemapRecurse (&buf, width, height, 0, 0, width, height, values, labels, 0, n, total, true);
	return buf;
}

R_API char *r_print_treemap(int n, int *values, const char **labels, int width, int height) {
	return drawTreemapAscii(values, labels, n, width, height);
}

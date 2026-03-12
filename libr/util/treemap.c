/* radare - LGPL - Copyright 2025-2026 - pancake */

#include "../include/r_util.h"

#define MIN_BOX_WIDTH 6
#define MIN_BOX_HEIGHT 3

static char charfor(int i, int j, int w, int h) {
	// TODO: these nested conditionals look really confusing and complex, make it simple
	if ((i == 0 || i == h - 1) || (j == 0 || j == w - 1)) {
		if ((i == 0 || i == h - 1) && (j == 0 || j == w - 1)) {
			return '+';
		}
		if (i == 0 || i == h - 1) {
			return '-';
		}
		if (j == 0 || j == w - 1) {
			return '|';
		}
	}
	return ' ';
}

static void drawBox(char **buffer, int width, int height, int x, int y, int w, int h, const char *text) {
	if (x < 0 || y < 0 || x + w > width || y + h > height) {
		return;
	}
	int i, j;
	for (i = 0; i < h; i++) {
		for (j = 0; j < w; j++) {
			char ch = charfor (i, j, w, h);
			int gx = x + j;
			int gy = y + i;
			(*buffer)[gy *(width + 1) + gx] = ch;
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

static inline ut32 isqrt32(ut32 n) {
	ut32 res = 0;
	ut32 bit = 1U << 30;
	while (bit > n) {
		bit >>= 2;
	}
	while (bit) {
		if (n >= res + bit) {
			n -= res + bit;
			res = (res >> 1) + bit;
		} else {
			res >>= 1;
		}
		bit >>= 2;
	}
	return res;
}

static inline int dodiv(ut32 adjusted, ut64 sum_adjusted, int d) {
	if (sum_adjusted < 1 || d < 1) {
		return 0;
	}
	ut64 scaled = (ut64)adjusted * (ut64)d;
	int boxw = (int)(scaled / sum_adjusted);
	return R_MAX (boxw, 1);
}

static void formatLabel(char *label, size_t label_size, const char *text, ut32 value) {
	if (text) {
		snprintf (label, label_size, "%s (%" PFMT32u ")", text, value);
	} else {
		snprintf (label, label_size, "%" PFMT32u, value);
	}
}

static void treemapRecurse(char **buffer, int width, int height, int x, int y, int w, int h, const ut32 *values, const char **labels, int start, int n, ut64 total, bool horizontal) {
	if (n <= 0 || w <= 0 || h <= 0 || !total) {
		return;
	}
	if (n == 1) {
		char label[128];
		formatLabel (label, sizeof (label), labels ? labels[start] : NULL, values[start]);
		drawBox (buffer, width, height, x, y, w, h, label);
		return;
	}

	int used = 0;
	int i, j;
	for (i = 0; i < n; i++) {
		ut32 val = values[start + i];
		// soften extremes by taking square root
		ut32 adjusted = isqrt32 (val);
		ut64 sum_adjusted = 0;
		for (j = 0; j < n - i; j++) {
			sum_adjusted += isqrt32 (values[start + i + j]);
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
		formatLabel (label, sizeof (label), labels ? labels[start + i] : NULL, val);
		drawBox (buffer, width, height, x, y, boxw, boxh, label);

		int newx = horizontal ? x + boxw - 1 : x;
		int newy = horizontal ? y : y + boxh - 1;
		int neww = horizontal ? w - boxw + 1 : w;
		int newh = horizontal ? h : h - boxh + 1;

		treemapRecurse (buffer, width, height, newx, newy, neww, newh, values, labels, start + i + 1, n - i - 1, total - val, !horizontal);
		break;
	}
}

static char *drawTreemapAscii(const ut32 *values, const char **labels, int n, int width, int height) {
	if (n <= 0 || width < 1 || height < 1) {
		return NULL;
	}
	char *buf = calloc (1, (width + 1) * height + 1);
	if (!buf) {
		return NULL;
	}
	int i;
	for (i = 0; i < height; i++) {
		memset (buf + i *(width + 1), ' ', width);
		buf[i *(width + 1) + width] = '\n';
	}
	ut64 total = 0;
	for (i = 0; i < n; i++) {
		total += values[i];
	}
	treemapRecurse (&buf, width, height, 0, 0, width, height, values, labels, 0, n, total, true);
	return buf;
}

R_API char *r_print_treemap(int n, const ut32 *values, const char **labels, int width, int height) {
	R_RETURN_VAL_IF_FAIL (n >= 0, NULL);
	R_RETURN_VAL_IF_FAIL (values || !n, NULL);
	return drawTreemapAscii (values, labels, n, width, height);
}

#include <assert.h>
#include <r_types.h>
#include <r_util.h>

#define BASE 36
#define TMIN 1
#define TMAX 26
#define SKEW 38
#define DAMP 700
#define INITIAL_N 128
#define INITIAL_BIAS 72

ut32 adapt_bias(ut32 delta, unsigned n_points, int is_first) {
	ut32 k = 0;
	delta /= is_first ? DAMP : 2;
	delta += delta / n_points;

	while (delta > ((BASE - TMIN) * TMAX) / 2) {
		delta /= (BASE - TMIN);
		k += BASE;
	}

	return k + (((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

char encode_digit(int c) {
	assert (c >= 0 && c <= BASE - TMIN);
	if (c > 25) {
		return c + 22;
	}
	return c + 'a';
}

static ut32 encode_var_int(const ut32 bias, const ut32 delta, char *dst) {
	ut32 i, k, q, t;
	i = 0;
	k = BASE;
	q = delta;

	while (true) {
		if (k <= bias) {
			t = TMIN;
		} else if (k >= bias + TMAX) {
			t = TMAX;
		} else {
			t = k - bias;
		}

		if (q < t) {
			break;
		}

		dst[i++] = encode_digit (t + (q - t) % (BASE - t));

		q = (q - t) / (BASE - t);
		k += BASE;
	}

	dst[i++] = encode_digit (q);

	return i;
}

static char decode_digit(char v) {
	if (v >= '0' && v <= '9') {
		return v - 22;
	}
	if (v >= 'a' && v <= 'z') {
		return v - 'a';
	}
	if (v >= 'A' && v <= 'Z') {
		return v - 'A';
	}
	return -1;
}

R_API char *r_punycode_encode(const char *src, int srclen, int *dstlen) {
	ut8 m, n;
	ut32 b, h;
	ut32 si, di;
	ut32 delta, bias;
	char *dst;

	*dstlen = 0;

	if (!src || srclen < 1) {
		return NULL;
	}

	dst = calloc (2 * srclen + 10, 1);
	if (!dst) {
		return NULL;
	}

	for (si = 0, di = 0; si < srclen; si++) {
		if ((ut8)src[si] < 128) {
			dst[di++] = src[si];
		}
	}

	b = h = di;

	if (di > 0) {
		dst[di++] = '-';
	}

	n = INITIAL_N;
	bias = INITIAL_BIAS;

	for (delta = 0; h < srclen; n++, delta++) {
		for (m = 0xff, si = 0; si < srclen; si++) {
			if ((ut8)src[si] >= n && (ut8)src[si] <= m) {
				m = src[si];
			}
		}

		if ((unsigned int)(m - n) > (UT32_MAX - delta) / (h + 1)) {
			free (dst);
			return NULL;
		}

		delta += (m - n) * (h + 1);
		n = m;

		for (si = 0; si < srclen; si++) {
			if ((ut8)src[si] < n) {
				if (++delta == 0) {
					free (dst);
					return NULL;
				}
			} else if ((ut8)src[si] == n) {
				di += encode_var_int (bias, delta, &dst[di]);
				bias = adapt_bias (delta, h+1, h == b);
				delta = 0;
				h++;
			}
		}
	}
	*dstlen = di;
	return dst;
}

R_API char *r_punycode_decode(const char *src, int srclen, int *dstlen) {
	ut8 n;
	const char *p;
	ut32 si, di;
	ut32 b, t, i, k, w;
	ut32 digit, org_i, bias;
	char *dst;

	*dstlen = 0;
	if (!src || srclen < 1) {
		return NULL;
	}

	dst = calloc (2*srclen + 10, 1);
	if (!dst) {
		return NULL;
	}

	for (si = 0; si < srclen; si++) {
		if (src[si] & 0x80) {
			free (dst);
			return NULL;       /*just return it*/
		}
	}

	for (p = src + srclen - 1; p > src && *p != '-'; p--);
	b = p - src;

	di = b;
	for (i = 0; i < di; i++) {
		dst[i] = src[i];
	}

	i = 0;
	n = INITIAL_N;
	bias = INITIAL_BIAS;

	for (si = b + (b > 0); si < srclen; di++) {
		org_i = i;

		for (w = 1, k = BASE; ; k += BASE) {
			digit = decode_digit (src[si++]);

			if ((char)digit == -1) {
				free (dst);
				return NULL;
			}

			if (digit > (UT32_MAX - i) / w) {
				free (dst);
				return NULL;
			}

			i += digit * w;

			if (k <= bias) {
				t = TMIN;
			} else if (k >= bias + TMAX) {
				t = TMAX;
			} else {
				t = k - bias;
			}

			if (digit < t) {
				break;
			}

			if (w > UT32_MAX / (BASE - t)) {
				free (dst);
				return NULL;
			}

			w *= BASE- t;
		}

		bias = adapt_bias(i - org_i, di+1, org_i == 0);

		if (i / (di + 1) > UT32_MAX - n) {
			free (dst);
			return NULL;
		}

		n += i / (di + 1);
		i %= (di + 1);

		memmove (dst+i+1, dst+i, (di-i) * sizeof(char));
		dst[i++] = n;
	}
	*dstlen = di;
	return dst;
}

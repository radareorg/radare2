/*  Rakholiya Jenish - 2017 */

#include <r_types.h>
#include <r_util.h>

#define BASE 36
#define TMIN 1
#define TMAX 26
#define SKEW 38
#define DAMP 700
#define INITIAL_N 128
#define INITIAL_BIAS 72

int utf32len (ut32 *input) {
	int i = 0;
	while (*(input + i)) {
		i++;
	}
	return i;
}

ut8 *utf32toutf8 (ut32 *input) {
	if (!input) {
		eprintf ("ERROR input is null\n");
		return NULL;
	}

	int i = 0;
	int j = 0;
	int len = utf32len (input);
	ut8 *result = calloc (4, len + 1);
	if (!result) {
		eprintf ("ERROR: out of memory\n");
		return NULL;
	}

	for (i = 0; i < len; i++) {
		if (input[i] < 0x80) {
			result[j] = input[i];
			j++;
		} else if (input[i] < 0x800) {
			result[j + 1] = 0x80 | (input[i] & 0x3f);
			result[j] = 0xc0 | ((input[i] >> 6) & 0x1f);
			j += 2;
		} else if (input[i] < 0x10000) {
			result[j + 2] = 0x80 | (input[i] & 0x3f);
			result[j + 1] = 0x80 | ((input[i] >> 6) & 0x3f);
			result[j] = 0xe0 | ((input[i] >> 12) & 0xf);
			j += 3;
		} else if (input[i] < 0x200000) {
			result[j + 3] = 0x80 | (input[i] & 0x3f);
			result[j + 2] = 0x80 | ((input[i] >> 6) & 0x3f);
			result[j + 1] = 0x80 | ((input[i] >> 12) & 0x3f);
			result[j] = 0xf0 | ((input[i] >> 18) & 0x7);
			j += 4;
		} else {
			eprintf ("ERROR in toutf8. Seems like input is invalid\n");
			free (result);
			return NULL;
		}
	}

	result[j] = 0;
	return result;
}

ut32 *utf8toutf32 (const ut8 *input) {
	if (!input) {
		eprintf ("ERROR input is null\n");
		return NULL;
	}

	int i = 0;
	int j = 0;
	int val = 0;
	int len = strlen ((const char *) input);
	ut32 *result = calloc (strlen ((const char *) input) + 1, 4);

	if (!result) {
		eprintf ("ERROR: out of memory\n");
		return NULL;
	}

	while (i < len) {
		if (input[i] >> 7 == 0) {
			val = input[i];
			i += 1;
		} else if (input[i] >> 5 == 0x6) {
			val = (((input[i] & 0x1f) << 6) & 0xfc0) |
			(input[i + 1] & 0x3f);
			i += 2;
		} else if (input[i] >> 4 == 0xe) {
			val = (((input[i] & 0xf) << 12) & 0xf000) |
			(((input[i + 1] & 0x3f) << 6) & 0xffc0) |
			(input[i + 2] & 0x3f);
			i += 3;
		} else if (input[i] >> 3 == 0x1e) {
			val = (((input[i] & 0xf) << 18) & 0x1c0000) |
			(((input[i + 1] & 0x3f) << 12) & 0x1ff000) |
			(((input[i + 2] & 0x3f) << 6) & 0x1fffc0) |
			(input[i + 3] & 0x3f);
			i += 4;
		} else {
			eprintf ("ERROR in toutf32. Seems like input is invalid.\n");
			free (result);
			return NULL;
		}
		result[j] = val;
		j++;
	}

	return result;
}


ut32 adapt_bias(ut32 delta, unsigned n_points, int is_first) {
	ut32 k = 0;
	delta /= is_first? DAMP: 2;
	delta += delta / n_points;

	while (delta > ((BASE - TMIN) * TMAX) / 2) {
		delta /= (BASE - TMIN);
		k += BASE;
	}

	return k + (((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

char encode_digit(int c) {
//	assert (c >= 0 && c <= BASE - TMIN);
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

static ut32 decode_digit(ut32 v) {
	if (IS_DIGIT (v)) {
		return v - 22;
	}
	if (v >= 'a' && v <= 'z') {
		return v - 'a';
	}
	if (v >= 'A' && v <= 'Z') {
		return v - 'A';
	}
	return UT32_MAX;
}

R_API char *r_punycode_encode(const ut8 *src, int srclen, int *dstlen) {
	ut32 m, n;
	ut32 b, h;
	ut32 si, di;
	ut32 delta, bias;
	ut32 *actualsrc = NULL;
	ut32 len = 0;
	char *dst = NULL;

	*dstlen = 0;

	if (!src || srclen < 1) {
		return NULL;
	}

	actualsrc = utf8toutf32 (src);
	if (!actualsrc) {
		return NULL;
	}

	len = utf32len (actualsrc);

	dst = calloc (2 * len + 10, 1);
	if (!dst) {
		free (actualsrc);
		return NULL;
	}

	for (si = 0, di = 0; si < len; si++) {
		if (actualsrc[si] < 128) {
			dst[di++] = actualsrc[si];
		}
	}

	b = h = di;

	if (di > 0) {
		dst[di++] = '-';
	}

	n = INITIAL_N;
	bias = INITIAL_BIAS;

	for (delta = 0; h < len; n++, delta++) {
		for (m = UT32_MAX, si = 0; si < len; si++) {
			if (actualsrc[si] >= n && actualsrc[si] < m) {
				m = actualsrc[si];
			}
		}

		if ((m - n) > (UT32_MAX - delta) / (h + 1)) {
			free (actualsrc);
			free (dst);
			return NULL;
		}

		delta += (m - n) * (h + 1);
		n = m;

		for (si = 0; si < len; si++) {
			if (actualsrc[si] < n) {
				if (++delta == 0) {
					free (actualsrc);
					free (dst);
					return NULL;
				}
			} else if (actualsrc[si] == n) {
				di += encode_var_int (bias, delta, &dst[di]);
				bias = adapt_bias (delta, h + 1, h == b);
				delta = 0;
				h++;
			}
		}
	}
	*dstlen = di;
	free (actualsrc);
	return dst;
}

R_API char *r_punycode_decode(const char *src, int srclen, int *dstlen) {
	const char *p;
	ut32 si, di;
	ut32 b, n, t, i, k, w;
	ut32 digit, org_i, bias;
	ut32 *dst = NULL;
	ut8 *finaldst = NULL;

	*dstlen = 0;
	if (!src || srclen < 1) {
		return NULL;
	}

	dst = calloc (2 * srclen + 10, 4);
	if (!dst) {
		return NULL;
	}

	for (si = 0; si < srclen; si++) {
		if (src[si] & 0x80) {
			free (dst);
			return NULL;       /*just return it*/
		}
	}

	for (p = src + srclen - 1; p > src && *p != '-'; p--) {
		;
	}
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

		for (w = 1, k = BASE;; k += BASE) {
			digit = decode_digit (src[si++]);

			if (digit == UT32_MAX) {
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

			w *= BASE - t;
		}

		bias = adapt_bias (i - org_i, di + 1, org_i == 0);

		if (i / (di + 1) > UT32_MAX - n) {
			free (dst);
			return NULL;
		}

		n += i / (di + 1);
		i %= (di + 1);

		memmove (dst + i + 1, dst + i, (di - i) * sizeof(ut32));
		dst[i++] = n;
	}

	finaldst = utf32toutf8 (dst);
	free (dst);
	if (finaldst) {
		*dstlen = strlen ((const char *) finaldst);
	} else {
		eprintf ("ERROR: finaldst is null\n");
		return NULL;
	}
	return (char *) finaldst;
}

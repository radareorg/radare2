/* radare - LGPL - Copyright 2007-2025 - pancake */

#define R_LOG_ORIGIN "util.num"

#include <errno.h>
#include <math.h>  /* for ceill */
#include <r_util.h>

static ut64 r_num_tailff(RNum *num, const char *hex);

static void r_num_srand(int seed) {
#if HAVE_ARC4RANDOM_UNIFORM
	// no-op
	(void)seed;
#else
	srand (seed);
#endif
}

static int r_rand(int mod) {
#if HAVE_ARC4RANDOM_UNIFORM
	return (int)arc4random_uniform (mod);
#else
	return rand () % mod;
#endif
}

// This function count bits set on 32bit words
R_API size_t r_num_bit_clz32(ut32 val) { // CLZ
	val = val - ((val >> 1) & 0x55555555);
	val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
	return (((val + (val >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

R_API size_t r_num_bit_clz64(ut64 val) { // CLZ
	val = val - ((val >> 1) & 0x5555555555555555ULL);
	val = (val & 0x3333333333333333ULL) + ((val >> 2) & 0x3333333333333333ULL);
	return (((val + (val >> 4)) & 0x0F0F0F0F0F0F0F0FULL) * 0x0101010101010101ULL) >> 24;
}

R_API size_t r_num_bit_count(ut32 val) { // CLZ
	return r_num_bit_clz32 (val);
	/* visual studio doesnt supports __buitin_clz */
#if defined(_MSC_VER) || defined(__TINYC__)
	size_t count = 0;
	val = val - ((val >> 1) & 0x55555555);
	val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
	count = (((val + (val >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
	return count;
#else
	return val? __builtin_clz (val): 0;
#endif
}

R_API size_t r_num_bit_ctz64(ut64 val) { // CTZ
	const ut64 m = 0x0101010101010101ULL;
	val ^= val - 1;
	return (unsigned)(((ut64)((val & (m - 1)) * m)) >> 56);
}

R_API size_t r_num_bit_ctz32(ut32 val) { // CTZ
	// FROM shlr/lz4/lz4.c
	const ut32 m = 0x01010101;
	return (unsigned)((((val - 1) ^ val) & (m - 1)) * m) >> 24;
}

R_API void r_num_irand(void) {
	r_num_srand (r_time_now ());
}

R_API int r_num_rand(int max) {
	static R_TH_LOCAL bool rand_initialized = false; // OK
	if (!rand_initialized) {
		r_num_irand ();
		rand_initialized = true;
	}
	if (!max) {
		max = 1;
	}
	return r_rand (max);
}

R_API void r_num_minmax_swap(ut64 *a, ut64 *b) {
	if (*a > *b) {
		ut64 tmp = *a;
		*a = *b;
		*b = tmp;
	}
}

R_API void r_num_minmax_swap_i(int *a, int *b) {
	if (*a > *b) {
		ut64 tmp = *a;
		*a = *b;
		*b = tmp;
	}
}

R_API RNum *r_num_new(RNumCallback cb, RNumCallback2 cb2, void *ptr) {
	RNum *num = R_NEW0 (RNum);
	num->value = 0LL;
	num->callback = cb;
	num->cb_from_value = cb2;
	num->userptr = ptr;
	return num;
}

R_API void r_num_free(RNum *num) {
	free (num);
}

#define KB (1ULL << 10)
#define MB (1ULL << 20)
#define GB (1ULL << 30)
#define TB (1ULL << 40)
#define PB (1ULL << 50)
#define EB (1ULL << 60)

/**
 * Convert size in bytes to human-readable string
 *
 * Result is stored in buf (buf should be at least 8 bytes in size).
 * If buf is NULL, memory for the new string is obtained with malloc(3),
 * and can be freed with free(3).
 *
 * On success, returns a pointer to buf. It returns NULL if
 * insufficient memory was available.
 */
R_API char *r_num_units(char *buf, size_t len, ut64 num) {
#if R2_NO_LONG_DOUBLE_FMT
	double fnum;
#else
	long double fnum;
#endif
	char unit;
	const char *fmt_str;
	if (!buf) {
		len = 64;
		buf = malloc (len);
		if (!buf) {
			return NULL;
		}
	}
#if R2_NO_LONG_DOUBLE_FMT
	fnum = (long double)num;
#else
	fnum = (double)num;
#endif
	if (num >= EB) {
		unit = 'E'; fnum /= EB;
	} else if (num >= PB) {
		unit = 'P'; fnum /= PB;
	} else if (num >= TB) {
		unit = 'T'; fnum /= TB;
	} else if (num >= GB) {
		unit = 'G'; fnum /= GB;
	} else if (num >= MB) {
		unit = 'M'; fnum /= MB;
	} else if (num >= KB) {
		unit = 'K'; fnum /= KB;
	} else {
		unit = '\0';
	}
	fmt_str = ((double)ceill (fnum) == (double)fnum)
		? "%.0" LDBLFMT "%c"
		: "%.1" LDBLFMT "%c";
	snprintf (buf, len, fmt_str, fnum, unit);
	return buf;
}

R_API const char *r_num_get_name(RNum *num, ut64 n) {
	R_RETURN_VAL_IF_FAIL (num, NULL);
	if (num->cb_from_value) {
		bool ok = false;
		const char *msg = num->cb_from_value (num, n, &ok);
		if (R_STR_ISNOTEMPTY (msg)) {
			return msg;
		}
		if (ok) {
			return msg;
		}
	}
	return NULL;
}

static void error(RNum * R_NULLABLE num, const char *err_str) {
	if (num) {
		if (err_str) {
			num->nc.errors++;
			num->nc.calc_err = err_str;
		} else {
			num->nc.errors = 0;
			num->nc.calc_err = NULL;
		}
	}
}

static ut64 r_num_from_binary(RNum *num, const char *str) {
	int i, j;
	ut64 ret = 0;
	for (j = 0, i = strlen (str) - 1; i >= 0; i--, j++) {
		switch (str[i]) {
		case '_':
			j--;
			break;
		case '1':
			ret |= (ut64) (1ULL << j);
			break;
		case '0':
			break;
		default:
			error (num, "binary numbers must contain only 0 and 1");
			return 0;
		}
	}
//	sscanf (str, "0x%"PFMT64x, &ret);
	return ret;
}

R_API ut64 r_num_from_ternary(const char *inp) {
	if (R_STR_ISEMPTY (inp)) {
		return 0LL;
	}
	const char *p;
	int pos = strlen (inp);
	ut64 fr = 0;
	for (p = inp; *p ; p++, pos--) {
		ut64 n012 = 0;
		switch (*p) {
		case '0':
		case '1':
		case '2':
			n012 = *p - '0';
			fr += (ut64)(n012 * pow (3, pos - 1));
			break;
		}
	}
	return fr;
}

// TODO: try to avoid the use of sscanf
/* old get_offset */
R_API ut64 r_num_get(RNum * R_NULLABLE num, const char *str) {
	int i, j;
	char lch;
	ut64 ret = 0LL;
	ut32 s, a;

	if (num && !num->nc.under_calc) {
		error (num, NULL);
	}
	str = r_str_trim_head_ro (str);
	if (R_STR_ISEMPTY (str)) {
		return 0;
	}
	if (r_str_startswith (str, "1u")) { // '1' is captured by op :(
		if (num && num->value == UT64_MAX) {
			num->value = 0;
		}
		switch (atoi (str + 2)) {
		case 64: return (ut64)UT64_MAX;
		case 32: return (ut64)UT32_MAX;
		case 16: return (ut64)UT16_MAX;
		case 8: return (ut64)UT8_MAX;
		}
	}
	/* resolve string with an external callback */
	if (num && num->callback) {
		bool ok = false;
		ret = num->callback (num->userptr, str, &ok);
		if (ok) {
			return ret;
		}
	}

	if (str[0] && str[1] && str[2]) {
		if (str[0] == '\'' && str[2] == '\'') {
			return (ut64)str[1];
		}
	}

	size_t len = strlen (str);
	if (len > 3 && str[4] == ':') {
		if (sscanf (str, "%04x", &s) == 1) {
			if (sscanf (str + 5, "%04x", &a) == 1) {
				return (ut64) ((s<<4) + a);
			}
		}
	} else if (len > 6 && str[6] == ':') {
		if (sscanf (str, "0x%04x:0x%04x", &s, &a) == 2) {
			return (ut64) ((s << 4) + a);
		}
		if (sscanf (str, "0x%04x:%04x", &s, &a) == 2) {
			return (ut64) ((s << 4) + a);
		}
	}
	if (str[0] == '0' && str[1] == 'b') { // XXX this is wrong and causes bugs
		ret = r_num_from_binary (num, str + 2);
	} else if (str[0] == '\'') {
		ret = str[1] & 0xff;
	// ugly as hell
	} else if (!strncmp (str, "0xff..", 6) || !strncmp (str, "0xFF..", 6)) {
		ret = r_num_tailff (num, str + 6);
	// ugly as hell
	} else if (!strncmp (str, "0t", 2)) {
		// parse ternary number
		ret = r_num_from_ternary (str + 2);
	} else if (!strncmp (str, "0o", 2)) {
		if (sscanf (str + 2, "%"PFMT64o, &ret) != 1) {
			error (num, "invalid octal number");
		}
	} else if (!strncmp (str, "0xf..", 5) || !strncmp (str, "0xF..", 5)) {
		ret = r_num_tailff (num, str + 5);
	} else if (str[0] == '0' && tolower ((ut8)str[1]) == '_') {
		// base36 here
		ret = b36_tonum (str + 2);
	} else if (str[0] == '0' && tolower ((ut8)str[1]) == 'x') {
		const char *lodash = strchr (str + 2, '_');
		if (lodash) {
			// Support 0x1000_f000_4000
			// TODO: Only take underscores separated every 4 chars starting at the end
			char *s = strdup (str + 2);
			if (s) {
				r_str_replace_char (s, '_', 0);
				errno = 0;
				ret = strtoull (s, NULL, 16);
				free (s);
			}
		} else {
			errno = 0;
			ret = strtoull (str + 2, NULL, 16);
			// sscanf (str+2, "%"PFMT64x, &ret);
		}
		if (errno == ERANGE) {
			error (num, "number won't fit into 64 bits");
		}
	} else {
		char *endptr;
		int len_num = len > 0 ? len - 1 : 0;
		int chars_read = len_num;
		bool zero_read = false;
		lch = str[len > 0 ? len - 1 : 0];
		if (*str == '0' && isdigit (*(str + 1)) && lch != 'b' && lch != 'h') {
			lch = 'o';
			len_num++;
		}
		switch (lch) {
		case 'h': // hexa
			if (!sscanf (str, "%"PFMT64x"%n", &ret, &chars_read)
			    || chars_read != len_num) {
				error (num, "invalid hex number");
			}
			break;
		case 'o': // octal
			if (!sscanf (str, "%"PFMT64o"%n", &ret, &chars_read)
			    || chars_read != len_num) {
				error (num, "invalid octal number");
			}
			break;
		case 'b': // binary
			ret = 0;
			bool ok = true;
			if (strlen (str) <= 65) { // 64 bit + the 'b' suffix
				for (j = 0, i = strlen (str) - 2; i >= 0; i--, j++) {
					if (str[i] == '1') {
						ret |= (1ULL << j);
					} else if (str[i] != '0') {
						// eprintf ("Unexpected char in binary number string '%c'\n", str[i]);
						ok = false;
						break;
					}
				}
			} else {
				ok = false;
				// eprintf ("Binary number is too large to fit in ut64\n");
			}
			if (!ok || !len_num) {
				error (num, "invalid binary number");
			}
			break;
		case 't': // ternary
			ret = 0;
			ok = true;
			ut64 x = 1;
			for (i = strlen (str) - 2; i >= 0; i--) {
				if (str[i] < '0' || '2' < str[i]) {
					ok = false;
					break;
				}
				ret += x * (str[i] - '0');
				x *= 3;
			}
			if (!ok || !len_num) {
				error (num, "invalid ternary number");
			}
			break;
		case 'K': case 'k':
			if (strchr (str, '.')) {
				double d = 0;
				if (sscanf (str, "%lf%n", &d, &chars_read)) {
					ret = (ut64)(d * KB);
				} else {
					zero_read = true;
				}
			} else {
				if (sscanf (str, "%"PFMT64d"%n", &ret, &chars_read)) {
					ret *= KB;
				} else {
					zero_read = true;
				}
			}
			if (zero_read || chars_read != len_num) {
				error (num, "invalid kilobyte number");
			}
			break;
		case 'M': case 'm':
			if (strchr (str, '.')) {
				double d = 0;
				if (sscanf (str, "%lf%n", &d, &chars_read)) {
					ret = (ut64)(d * MB);
				} else {
					zero_read = true;
				}
			} else {
				if (sscanf (str, "%"PFMT64d"%n", &ret, &chars_read)) {
					ret *= MB;
				} else {
					zero_read = true;
				}
			}
			if (zero_read || chars_read != len_num) {
				error (num, "invalid megabyte number");
			}
			break;
		case 'G': case 'g':
			if (strchr (str, '.')) {
				double d = 0;
				if (sscanf (str, "%lf%n", &d, &chars_read)) {
					ret = (ut64)(d * GB);
				} else {
					zero_read = true;
				}
			} else {
				if (sscanf (str, "%"PFMT64d"%n", &ret, &chars_read)) {
					ret *= GB;
				} else {
					zero_read = true;
				}
			}
			if (zero_read || chars_read != len_num) {
				error (num, "invalid gigabyte number");
			}
			break;
#if 0
		case 's':
			// support 's' for miliseconds to seconds
			if (isdigit (*str)) {
				if (sscanf (str, "%"PFMT64d"%n", &ret, &chars_read)) {
					ret *= 1000;
				} else {
					error (num, "invalid seconds");
				}
			}
			break;
#endif
		default:
			errno = 0;
			if (*str != '-' && !isdigit (*str)) {
				error (num, "unknown symbol");
			} else {
				ret = strtoull (str, &endptr, 10);
				if (errno == EINVAL) {
					error (num, "invalid symbol");
				} else if (errno == ERANGE) {
					error (num, "number won't fit into 64 bits");
				}
			}
			break;
		}
	}
	if (num) {
		num->value = ret;
	}
	return ret;
}

R_API int r_num_is_float(RNum *num, const char *str) {
	return (isdigit (*str) && (strchr (str, '.') || str[strlen (str) - 1] == 'f'));
}

R_API double r_num_get_double(RNum *num, const char *str) {
	double d = 0.0f;
	(void) sscanf (str, "%lf", &d);
	return d;
}

R_API int r_num_to_bits(char *out, ut64 num) {
	int size = 64, i;

	if (num >> 32) {
		size = 64;
	} else if (num & 0xff000000) {
		size = 32;
	} else if (num & 0xff0000) {
		size = 24;
	} else if (num & 0xff00) {
		size = 16;
	} else if (num & 0xff) {
		size = 8;
	}
	if (out) {
		int pos = 0;
		int realsize = 0;
		int hasbit = 0;
		for (i = 0; i < size; i++) {
			char bit = ((num >> (size - i - 1)) & 1) ? '1': '0';
			if (hasbit || bit == '1') {
				out[pos++] = bit; // size - 1 - i] = bit;
			}
			if (!hasbit && bit == '1') {
				hasbit = 1;
				realsize = size - i;
			}
		}
		if (realsize == 0) {
			out[realsize++] = '0';
		}
		out[realsize] = '\0'; // Maybe not nesesary?
	}
	return size;
}

R_API int r_num_to_ternary(char *out, ut64 num) {
	if (out == NULL) {
		return false;
	}
	int i;
	for (i = 0; num; i++, num /= 3) {
		out[i] = (char) ('0' + num % 3);
	}
	if (i == 0) {
		out[0] = '0';
		i++;
	}
	out[i] = '\0';

	r_str_reverse (out);
	return true;
}

R_API ut64 r_num_chs(int cylinder, int head, int sector, int sectorsize) {
	if (sectorsize < 1) {
		sectorsize = 512;
	}
	return (ut64)cylinder * (ut64)head * (ut64)sector * (ut64)sectorsize;
}

R_API int r_num_conditional(RNum * R_NULLABLE num, const char *str) {
	char *lgt, *t, *p, *s = strdup (str);
	int res = 0;
	ut64 n, a, b;
	p = s;
	do {
		t = strchr (p, ',');
		if (t) {
			*t = 0;
		}
		lgt = strchr (p, '<');
		if (lgt) {
			*lgt = 0;
			a = r_num_math (num, p);
			if (lgt[1] == '=') {
				b = r_num_math (num, lgt + 2);
				if (a > b) {
					goto fail;
				}
			} else {
				b = r_num_math (num, lgt + 1);
				if (a >= b) {
					goto fail;
				}
			}
		} else {
			lgt = strchr (p, '>');
			if (lgt) {
				*lgt = 0;
				a = r_num_math (num, p);
				if (lgt[1] == '=') {
					b = r_num_math (num, lgt + 2);
					if (a < b) {
						goto fail;
					}
				} else {
					b = r_num_math (num, lgt + 1);
					if (a <= b) {
						goto fail;
					}
				}
			} else {
				lgt = strchr (p, '=');
				if (lgt && lgt > p) {
					lgt--;
					if (*lgt == '!') {
						r_str_replace_char (p, '!', ' ');
						r_str_replace_char (p, '=', '-');
						n = r_num_math (num, p);
						if (!n) {
							goto fail;
						}
					}
				}
				lgt = strstr (p, "==");
				if (lgt) {
					*lgt = ' ';
				}
				r_str_replace_char (p, '=', '-');
				n = r_num_math (num, p);
				if (n) {
					goto fail;
				}
			}
		}
		p = t + 1;
	} while (t);
	res = 1;
fail:
	free (s);
	return res;
}

R_API int r_num_is_valid_input(RNum *num, const char *input_value) {
	ut64 value = input_value ? r_num_math (num, input_value) : 0;
	return !(value == 0 && input_value && *input_value != '0') || !(value == 0 && input_value && *input_value != '@');
}

R_API ut64 r_num_get_input_value(RNum * R_NULLABLE num, const char *input_value) {
	ut64 value = input_value ? r_num_math (num, input_value) : 0;
	return value;
}

#define NIBBLE_TO_HEX(n) (((n) & 0xf) > 9 ? 'a' + ((n) & 0xf) - 10 : '0' + ((n) & 0xf))
static int escape_char(char* dst, char byte) {
	const char escape_map[] = "abtnvfr";
	if (byte >= 7 && byte <= 13) {
		*(dst++) = '\\';
		*(dst++) = escape_map [byte - 7];
		*dst = 0;
		return 2;
	}
	if (byte) {
		*(dst++) = '\\';
		*(dst++) = 'x';
		*(dst++) = NIBBLE_TO_HEX (byte >> 4);
		*(dst++) = NIBBLE_TO_HEX (byte);
		*dst = 0;
		return 4;
	}
	return 0;
}

R_API char* r_num_as_string(RNum *___, ut64 n, bool printable_only) {
	char str[34]; // 8 byte * 4 chars in \x?? format
	int stri, ret = 0, off = 0;
	int len = sizeof (ut64);
	ut64 num = n;
	str[stri = 0] = 0;
	while (len--) {
		char ch = (num & 0xff);
		if (ch >= 32 && ch < 127) {
			str[stri++] = ch;
			str[stri] = 0;
		} else if (!printable_only && (off = escape_char (str + stri, ch)) != 0) {
			stri += off;
		} else {
			if (ch) {
				return NULL;
			}
		}
		ret |= (num & 0xff);
		num >>= 8;
	}
	if (ret) {
		return strdup (str);
	}
	if (!printable_only) {
		return strdup ("\\0");
	}
	return NULL;
}

R_API bool r_is_valid_input_num_value(RNum * R_NULLABLE num, const char *input_value) {
	if (!input_value) {
		return false;
	}
	ut64 value = r_num_math (num, input_value);
	return !(value == 0 && *input_value != '0');
}

// SHITTY API
R_API ut64 r_get_input_num_value(RNum *num, const char *str) {
	return (str && *str)? r_num_math (num, str) : 0;
}

// SHITTY API
static inline ut64 __nth_nibble(ut64 n, ut32 i) {
	int sz = (sizeof (n) << 1) - 1;
	int s = (sz - i) * 4;
	return (n >> s) & 0xf;
}

R_API ut64 r_num_tail_base(RNum *num, ut64 addr, ut64 off) {
	int i;
	bool ready = false;
	ut64 res = 0;
	for (i = 0; i < 16; i++) {
		ut64 o = __nth_nibble (off, i);
		if (!ready) {
			bool iseq = __nth_nibble (addr, i) == o;
			if (i == 0 && !iseq) {
				return UT64_MAX;
			}
			if (iseq) {
				continue;
			}
		}
		ready = true;
		ut8 pos = (15 - i) * 4;
		res |= (o << pos);
	}
	return res;
}

R_API ut64 r_num_tail(RNum *num, ut64 addr, const char *hex) {
	ut64 mask = 0LL;
	ut64 n = 0;

	while (*hex && (*hex == ' ' || *hex == '.')) {
		hex++;
	}
	int i = strlen (hex) * 4;
	char *p = r_str_newf ("0x%s", hex);
	if (p) {
		if (isxdigit ((ut8)hex[0])) {
			n = r_num_math (num, p);
		} else {
			R_LOG_ERROR ("Invalid argument");
			free (p);
			return addr;
		}
		free (p);
	}
	mask = UT64_MAX << i;
	return (addr & mask) | n;
}

static ut64 r_num_tailff(RNum *num, const char *hex) {
	ut64 n = 0;

	while (*hex && (*hex == ' ' || *hex == '.')) {
		hex++;
	}
	int i = strlen (hex) * 4;
	char *p = r_str_newf ("0x%s", hex);
	if (p) {
		if (isxdigit ((ut8)hex[0])) {
			n = r_num_get (num, p);
		} else {
			R_LOG_ERROR ("Invalid argument");
			free (p);
			return UT64_MAX;
		}
		free (p);
	}
	ut64 left = ((UT64_MAX >> i) << i);
	return left | n;
}

R_API int r_num_between(RNum *num, const char *input_value) {
	int i;
	ut64 ns[3];
	char * const str = strdup (input_value);
	RList *nums = r_num_str_split_list (str);
	int len = r_list_length (nums);
	if (len < 3) {
		free (str);
		r_list_free (nums);
		return -1;
	}
	if (len > 3) {
		len = 3;
	}
	for (i = 0; i < len; i++) {
		ns[i] = r_num_math (num, r_list_pop_head (nums));
	}
	free (str);
	r_list_free (nums);
	return num->value = R_BETWEEN (ns[0], ns[1], ns[2]);
}

R_API bool r_num_is_op(const char c) {
	return c == '/' || c == '+' || c == '-' || c == '*' ||
		c == '%' || c == '&' || c == '^' || c == '|';
}

// Assumed *str is parsed as an expression correctly
R_API int r_num_str_len(const char *str) {
	int i = 0, len = 0, st;
	st = 0; // 0: number, 1: op
	if (str[0] == '(') {
		i++;
	}
	while (str[i] != '\0') {
		switch (st) {
		case 0: // number
			while (!r_num_is_op (str[i]) && str[i] != ' '
			  && str[i] != '\0') {
				i++;
				if (str[i] == '(') {
				  i += r_num_str_len (str+i);
				}
			}
			len = i;
			st = 1;
			break;
		case 1: // op
			while (str[i] != '\0' && str[i] == ' ') {
				i++;
			}
			if (!r_num_is_op (str[i])) {
				return len;
			}
			if (str[i] == ')') {
				return i + 1;
			}
			i++;
			while (str[i] != '\0' && str[i] == ' ') {
				i++;
			}
			st = 0;
			break;
		}
	}
	return len;
}

R_API int r_num_str_split(char *str) {
	int i = 0, count = 0;
	const int len = strlen (str);
	while (i < len) {
		i += r_num_str_len (str + i);
		str[i] = '\0';
		i++;
		count++;
	}
	return count;
}

R_API RList *r_num_str_split_list(char *str) {
	int i, count = r_num_str_split (str);
	RList *list = r_list_new ();
	for (i = 0; i < count; i++) {
		r_list_append (list, str);
		str += strlen (str) + 1;
	}
	return list;
}

R_API void *r_num_dup(ut64 n) {
	ut64 *hn = malloc (sizeof (ut64));
	if (!hn) {
		return NULL;
	}
	*hn = n;
	return (void*)hn;
}

R_API double r_num_cos(double a) {
	return cos (a);
}

R_API double r_num_sin(double a) {
	return sin (a);
}

// sega dance dance revolution numbers
// convert address into segmented address
// takes addr, segment base and segment granurality
R_API bool r_num_segaddr(ut64 addr, ut64 sb, int sg, ut32 *a, ut32 *b) {
#if 0
	s = n >> 16 << 12;
	a = n & 0x0fff;
#endif
	if (sb) {
		ut32 csbase = (sb << 4);
		if (addr > csbase) {
			*a = sb;
			*b = addr - csbase;
		} else {
			int delta = csbase - addr;
			*a = csbase + delta;
			*b = addr - csbase+ delta;
		}
	} else {
		*a = ((addr >> 16) << (16 - sg));
		*b = (addr & 0xffff);
	}
	return *a <= 0xffff && *b <= 0xffff;
}

// wont work for 64bit but thats by design
R_API char *r_num_list_join(RList *str, const char *sep) {
	R_RETURN_VAL_IF_FAIL (str && sep, NULL);
	RListIter *iter;
	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach_iter (str, iter) {
		if (r_strbuf_length (sb) != 0) {
			r_strbuf_append (sb, sep);
		}
		r_strbuf_appendf (sb, "%d", (int)(size_t)iter->data);
	}
	return r_strbuf_drain (sb);
}

/* Returns the number that has bits + 1 least significant bits set. */
R_API ut64 r_num_genmask(int bits) {
	ut64 m = UT64_MAX;
	if (bits > 0 && bits < 64) {
		m = (ut64)(((ut64)(2) << bits) - 1);
		if (!m) {
			m = UT64_MAX;
		}
	}
	return m;
}


/* radare - LGPL - Copyright 2025 - pancake */

#include <r_util.h>
#include <math.h>

R_API double r_cfloat_parse(const ut8 *buf, size_t buf_size, const RCFloatProfile *profile) {
	R_RETURN_VAL_IF_FAIL (buf && profile, NAN);
	RCFloatValue value;
	if (!r_cfloat_parse_ex (buf, buf_size, profile, &value)) {
		return NAN;
	}
	return r_cfloat_value_to_double (&value, profile);
}

// Convenience function with exp_bits and mant_bits, assuming sign=1, bias= (1<< (exp_bits-1))-1, little endian, implicit
R_API double r_cfloat_parse_simple(const ut8 *buf, size_t buf_size, int exp_bits, int mant_bits) {
	R_RETURN_VAL_IF_FAIL (buf && buf_size > 0, (double)0.0);
	RCFloatProfile profile = { 1, exp_bits, mant_bits, (1 << (exp_bits - 1)) - 1, false, false };
	return r_cfloat_parse (buf, buf_size, &profile);
}

R_API bool r_cfloat_write(double value, const RCFloatProfile *profile, ut8 *buf, size_t buf_size) {
	R_RETURN_VAL_IF_FAIL (profile && buf, false);
	RCFloatValue tmp;
	r_cfloat_value_from_double (&tmp, value, profile);
	return r_cfloat_write_ex (&tmp, profile, buf, buf_size);
}

R_API bool r_cfloat_write_simple(double value, int exp_bits, int mant_bits, ut8 *buf, size_t buf_size) {
	R_RETURN_VAL_IF_FAIL (buf && buf_size > 0, false);
	RCFloatProfile profile = { 1, exp_bits, mant_bits, (1 << (exp_bits - 1)) - 1, false, false };
	return r_cfloat_write (value, &profile, buf, buf_size);
}

static const RCFloatProfile binary16_profile = { 1, 5, 10, 15, false, false };
static const RCFloatProfile binary32_profile = { 1, 8, 23, 127, false, false };
static const RCFloatProfile binary64_profile = { 1, 11, 52, 1023, false, false };
static const RCFloatProfile binary128_profile = { 1, 15, 112, 16383, false, false };
static const RCFloatProfile bfloat16_profile = { 1, 8, 7, 127, false, false };
static const RCFloatProfile x87_80_profile = { 1, 15, 64, 16383, false, true };
static const RCFloatProfile vax_f_profile = { 1, 8, 23, 64, true, true };
static const RCFloatProfile vax_d_profile = { 1, 8, 55, 64, true, true };
static const RCFloatProfile vax_g_profile = { 1, 11, 52, 1024, true, true };
static const RCFloatProfile ibm370_short_profile = { 1, 7, 24, 64, true, true };
static const RCFloatProfile ibm370_long_profile = { 1, 7, 56, 64, true, true };
static const RCFloatProfile cray_48_profile = { 1, 11, 36, 1024, true, false };
static const RCFloatProfile cray_64_profile = { 1, 15, 48, 16384, true, false };
static const RCFloatProfile cray_128_profile = { 1, 15, 112, 16384, true, false };
static const RCFloatProfile bfloat8_profile = { 1, 4, 3, 8, false, false };
static const RCFloatProfile tf32_profile = { 1, 8, 10, 127, false, false };
static const RCFloatProfile binary96_profile = { 1, 15, 80, 16383, false, true };
static const RCFloatProfile binary128_ibm_profile = { 1, 15, 112, 16383, true, true };
static const RCFloatProfile binary256_profile = { 1, 19, 236, 262143, false, false };

static void set_bits(RCFloatValue *value, int bit_offset, int num_bits, ut64 data);

R_API const RCFloatProfile *r_cfloat_profile_from_name(const char *name) {
	R_RETURN_VAL_IF_FAIL (name, NULL);
	static const struct
	{
		const char *name;
		const RCFloatProfile *profile;
	} profiles[] = {
		{ "binary16", &binary16_profile },
		{ "binary32", &binary32_profile },
		{ "binary64", &binary64_profile },
		{ "binary128", &binary128_profile },
		{ "bfloat16", &bfloat16_profile },
		{ "x87_80", &x87_80_profile },
		{ "vax_f", &vax_f_profile },
		{ "vax_d", &vax_d_profile },
		{ "vax_g", &vax_g_profile },
		{ "ibm370_short", &ibm370_short_profile },
		{ "ibm370_long", &ibm370_long_profile },
		{ "cray48", &cray_48_profile },
		{ "cray64", &cray_64_profile },
		{ "cray128", &cray_128_profile },
		{ "bfloat8", &bfloat8_profile },
		{ "tf32", &tf32_profile },
		{ "binary96", &binary96_profile },
		{ "binary128_ibm", &binary128_ibm_profile },
		{ "binary256", &binary256_profile },
	};
	size_t i;
	for (i = 0; i < sizeof (profiles) / sizeof (profiles[0]); i++) {
		if (!strcmp (name, profiles[i].name)) {
			return profiles[i].profile;
		}
	}
	return NULL;
}

// Helper: read multi-word value from buffer
static void read_multiword(const ut8 *buf, size_t buf_size, bool big_endian, RCFloatValue *out) {
	memset (out->words, 0, sizeof (out->words));
	if (!buf || !out) {
		return;
	}
	size_t i;
	if (big_endian) {
		for (i = 0; i < buf_size; i++) {
			size_t bit_off = (buf_size - 1 - i) * 8;
			set_bits (out, bit_off, 8, buf[i]);
		}
	} else {
		for (i = 0; i < buf_size; i++) {
			set_bits (out, i * 8, 8, buf[i]);
		}
	}
}

// Helper: extract bit field from multi-word value
static ut64 extract_bits(const RCFloatValue *value, int bit_offset, int num_bits) {
	if (num_bits > 64) {
		return 0; // Can't extract more than 64 bits into a ut64
	}
	if (num_bits == 0) {
		return 0;
	}

	ut64 result = 0;
	int bits_extracted = 0;

	while (bits_extracted < num_bits) {
		int word_idx = bit_offset / 64;
		int bit_in_word = bit_offset % 64;
		int bits_available = 64 - bit_in_word;
		int bits_to_extract = num_bits - bits_extracted;
		if (bits_to_extract > bits_available) {
			bits_to_extract = bits_available;
		}

		if (word_idx < 4) {
			ut64 mask = (bits_to_extract == 64)? ~0ULL: ((1ULL << bits_to_extract) - 1);
			ut64 extracted = (value->words[word_idx] >> bit_in_word) & mask;
			result |= extracted << bits_extracted;
		}

		bits_extracted += bits_to_extract;
		bit_offset += bits_to_extract;
	}

	return result;
}

static inline int value_get_bit(const RCFloatValue *value, int bit_index) {
	if (!value || bit_index < 0 || bit_index >= (int) (sizeof (value->words) * 8)) {
		return 0;
	}
	return (int)extract_bits (value, bit_index, 1);
}

static long double fraction_from_bits(const RCFloatValue *value, int bit_offset, int num_bits) {
	if (num_bits <= 0) {
		return 0.0L;
	}
	long double frac = 0.0L;
	int i;
	for (i = num_bits - 1; i >= 0; i--) {
		if (value_get_bit (value, bit_offset + i)) {
			frac += ldexpl (1.0L, i - num_bits);
		}
	}
	return frac;
}

static void set_fraction_bits(RCFloatValue *value, int bit_offset, int num_bits, long double fractional) {
	if (num_bits <= 0 || !value) {
		return;
	}
	long double frac = fractional;
	int i;
	for (i = num_bits - 1; i >= 0; i--) {
		frac *= 2.0L;
		if (frac >= 1.0L) {
			set_bits (value, bit_offset + i, 1, 1);
			frac -= 1.0L;
		}
	}
}

R_API bool r_cfloat_parse_ex(const ut8 *buf, size_t buf_size, const RCFloatProfile *profile, RCFloatValue *out) {
	R_RETURN_VAL_IF_FAIL (buf && profile && out, false);

	const int total_bits = profile->sign_bits + profile->exp_bits + profile->mant_bits;
	if (buf_size * 8 < (size_t)total_bits) {
		return false;
	}

	// Read bytes into multi-word representation
	read_multiword (buf, (total_bits + 7) / 8, profile->big_endian, out);

	return true;
}

R_API double r_cfloat_value_to_double(const RCFloatValue *value, const RCFloatProfile *profile) {
	R_RETURN_VAL_IF_FAIL (value && profile, NAN);

	int mant_pos = 0;
	int exp_pos = profile->mant_bits;
	int sign_pos = profile->mant_bits + profile->exp_bits;

	ut64 sign = extract_bits (value, sign_pos, profile->sign_bits);
	sign = (profile->sign_bits == 1)? (sign? 1: 0): (sign != 0);
	ut64 exp = extract_bits (value, exp_pos, profile->exp_bits);
	ut64 exp_max = (1ULL << profile->exp_bits) - 1;
	if (exp == 0) {
		long double frac = fraction_from_bits (value, mant_pos, profile->mant_bits);
		if (frac == 0.0L) {
			return sign? -0.0: 0.0;
		}
		long double result = frac * ldexpl (1.0L, 1 - profile->bias);
		return sign? - (double)result: (double)result;
	} else if (exp == exp_max) {
		long double frac = fraction_from_bits (value, mant_pos, profile->mant_bits);
		if (frac == 0.0L) {
			return sign? -INFINITY: INFINITY;
		}
		return sign? -NAN: NAN;
	}

	long double mant_val = 0.0L;
	if (profile->explicit_leading_bit && profile->mant_bits > 0) {
		int leading_idx = profile->mant_bits - 1;
		long double leading = value_get_bit (value, mant_pos + leading_idx)? 1.0L: 0.0L;
		long double frac = fraction_from_bits (value, mant_pos, leading_idx);
		mant_val = leading + frac;
	} else {
		long double frac = fraction_from_bits (value, mant_pos, profile->mant_bits);
		mant_val = 1.0L + frac;
	}
	long double result = mant_val * ldexpl (1.0L, (int)exp - profile->bias);
	return sign? - (double)result: (double)result;
}

R_API long double r_cfloat_value_to_longdouble(const RCFloatValue *value, const RCFloatProfile *profile) {
	// For now, convert through double
	// A more sophisticated implementation would use native long double operations
	return (long double)r_cfloat_value_to_double (value, profile);
}

// Helper: set bits in multi-word value
static void set_bits(RCFloatValue *value, int bit_offset, int num_bits, ut64 data) {
	if (num_bits == 0 || num_bits > 64) {
		return;
	}

	int bits_set = 0;
	while (bits_set < num_bits) {
		int word_idx = bit_offset / 64;
		int bit_in_word = bit_offset % 64;
		int bits_available = 64 - bit_in_word;
		int bits_to_set = num_bits - bits_set;
		if (bits_to_set > bits_available) {
			bits_to_set = bits_available;
		}

		if (word_idx < 4) {
			ut64 mask = (bits_to_set == 64)? ~0ULL: ((1ULL << bits_to_set) - 1);
			ut64 data_part = (data >> bits_set) & mask;
			ut64 clear_mask = ~ (mask << bit_in_word);
			value->words[word_idx] = (value->words[word_idx] & clear_mask) | (data_part << bit_in_word);
		}

		bits_set += bits_to_set;
		bit_offset += bits_to_set;
	}
}

// Helper: write multi-word value to buffer
static void write_multiword(const RCFloatValue *value, ut8 *buf, size_t buf_size, bool big_endian) {
	memset (buf, 0, buf_size);
	if (!value || !buf) {
		return;
	}
	size_t i;
	if (big_endian) {
		for (i = 0; i < buf_size; i++) {
			ut64 byte = extract_bits (value, (buf_size - 1 - i) * 8, 8);
			buf[i] = byte & 0xFF;
		}
	} else {
		for (i = 0; i < buf_size; i++) {
			ut64 byte = extract_bits (value, i * 8, 8);
			buf[i] = byte & 0xFF;
		}
	}
}

R_API void r_cfloat_value_from_double(RCFloatValue *value, double d, const RCFloatProfile *profile) {
	R_RETURN_IF_FAIL (value && profile);

	memset (value->words, 0, sizeof (value->words));

	int mant_pos = 0;
	int exp_pos = profile->mant_bits;
	int sign_pos = profile->mant_bits + profile->exp_bits;

	int sign = signbit (d)? 1: 0;
	d = fabs (d);

	if (isnan (d)) {
		ut64 exp_max = (1ULL << profile->exp_bits) - 1;
		set_bits (value, sign_pos, profile->sign_bits, sign);
		set_bits (value, exp_pos, profile->exp_bits, exp_max);
		set_bits (value, mant_pos, R_MIN (profile->mant_bits, 64), 1); // NaN payload
	} else if (isinf (d)) {
		ut64 exp_max = (1ULL << profile->exp_bits) - 1;
		set_bits (value, sign_pos, profile->sign_bits, sign);
		set_bits (value, exp_pos, profile->exp_bits, exp_max);
		set_bits (value, mant_pos, profile->mant_bits, 0);
	} else if (d == 0.0) {
		set_bits (value, sign_pos, profile->sign_bits, sign);
	} else {
		long double val = fabs ((long double)d);
		int exp_max = (1 << profile->exp_bits) - 1;
		int frexp_exp;
		long double mant = frexpl (val, &frexp_exp);
		int stored_exp = frexp_exp + profile->bias - 1;
		int effective_exp;
		if (stored_exp <= 0) {
			stored_exp = 0;
			effective_exp = 1 - profile->bias;
		} else if (stored_exp >= exp_max) {
			stored_exp = exp_max;
			effective_exp = stored_exp - profile->bias;
			mant = 0.0L;
		} else {
			effective_exp = stored_exp - profile->bias;
		}
		set_bits (value, sign_pos, profile->sign_bits, sign);
		set_bits (value, exp_pos, profile->exp_bits, stored_exp);

		long double mantissa = mant != 0.0L? ldexpl (val, -effective_exp): 0.0L;
		if (stored_exp == 0) {
			mantissa = ldexpl (val, profile->bias - 1);
		}

		if (profile->explicit_leading_bit && profile->mant_bits > 0) {
			int msb = profile->mant_bits - 1;
			if (stored_exp != 0) {
				int leading = mantissa >= 1.0L? 1: 0;
				set_bits (value, mant_pos + msb, 1, leading);
				mantissa -= leading;
			} else {
				set_bits (value, mant_pos + msb, 1, 0);
			}
			set_fraction_bits (value, mant_pos, R_MAX (msb, 0), mantissa);
		} else {
			long double fractional = (stored_exp == 0)? mantissa: (mantissa - 1.0L);
			if (fractional < 0.0L) {
				fractional = 0.0L;
			}
			set_fraction_bits (value, mant_pos, profile->mant_bits, fractional);
		}
	}
}

R_API void r_cfloat_value_from_longdouble(RCFloatValue *value, long double ld, const RCFloatProfile *profile) {
	// For now, convert through double
	r_cfloat_value_from_double (value, (double)ld, profile);
}

R_API bool r_cfloat_write_ex(const RCFloatValue *value, const RCFloatProfile *profile, ut8 *buf, size_t buf_size) {
	R_RETURN_VAL_IF_FAIL (value && profile && buf, false);

	const int total_bits = profile->sign_bits + profile->exp_bits + profile->mant_bits;
	if (buf_size * 8 < (size_t)total_bits) {
		return false;
	}

	// Write multi-word value to buffer
	write_multiword (value, buf, (total_bits + 7) / 8, profile->big_endian);

	return true;
}

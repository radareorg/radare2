/* radare - LGPL - Copyright 2025 - pancake */

#include <r_util.h>
#include <math.h>

R_API double r_cfloat_parse(const ut8 *buf, size_t buf_size, const RCFloatProfile *profile) {
	R_RETURN_VAL_IF_FAIL (buf && profile, NAN);

	const int total_bits = profile->sign_bits + profile->exp_bits + profile->mant_bits;
	if (total_bits > 64 || buf_size * 8 < total_bits) {
		return NAN;
	}
	ut64 value_low = r_read_ble64 (buf, profile->big_endian);
	value_low &= (total_bits == 64)? ~0ULL: ((1ULL << total_bits) - 1);

	int sign_pos = total_bits - profile->sign_bits;
	int exp_pos = sign_pos - profile->exp_bits;
	int mant_pos = 0;

	ut64 sign = (value_low >> sign_pos) &((1ULL << profile->sign_bits) - 1);
	ut64 exp = (value_low >> exp_pos) &((1ULL << profile->exp_bits) - 1);
	ut64 mant = (value_low >> mant_pos) &((1ULL << profile->mant_bits) - 1);

	if (profile->sign_bits == 1) {
		sign = sign? 1: 0;
	} else {
		// for multiple sign bits, perhaps not standard, assume 0 or 1
		sign = sign != 0;
	}

	ut64 exp_max = (1ULL << profile->exp_bits) - 1;

	if (exp == 0) {
		if (mant == 0) {
			return sign? -0.0: 0.0;
		} else {
			// subnormal
			double mant_val = (double)mant;
			if (profile->explicit_leading_bit) {
				// for x87, mant includes leading bit
				int leading = (mant >> (profile->mant_bits - 1)) & 1;
				mant_val = (double)(mant &((1ULL << (profile->mant_bits - 1)) - 1));
				mant_val /= (double) (1ULL << (profile->mant_bits - 1));
				mant_val += leading;
			} else {
				mant_val /= (double) (1ULL << profile->mant_bits);
			}
			return (sign? -1.0: 1.0) * mant_val * pow (2.0, 1.0 - profile->bias);
		}
	} else if (exp == exp_max) {
		if (mant == 0) {
			return sign? -INFINITY: INFINITY;
		}
		return sign? -NAN: NAN;
	} else {
		// normal
		double mant_val = (double)mant;
		if (profile->explicit_leading_bit) {
			int leading = (mant >> (profile->mant_bits - 1)) & 1;
			mant_val = (double)(mant &((1ULL << (profile->mant_bits - 1)) - 1));
			mant_val /= (double) (1ULL << (profile->mant_bits - 1));
			mant_val += leading;
		} else {
			mant_val = 1.0 + mant_val / (double) (1ULL << profile->mant_bits);
		}
		return (sign? -1.0: 1.0) * mant_val * pow (2.0, (double)exp - profile->bias);
	}
}

// Convenience function with exp_bits and mant_bits, assuming sign=1, bias= (1<< (exp_bits-1))-1, little endian, implicit
R_API double r_cfloat_parse_simple(const ut8 *buf, size_t buf_size, int exp_bits, int mant_bits) {
	R_RETURN_VAL_IF_FAIL (buf && buf_size > 0, (double)0.0);
	RCFloatProfile profile = { 1, exp_bits, mant_bits, (1 << (exp_bits - 1)) - 1, false, false };
	return r_cfloat_parse (buf, buf_size, &profile);
}

R_API bool r_cfloat_write(double value, const RCFloatProfile *profile, ut8 *buf, size_t buf_size) {
	R_RETURN_VAL_IF_FAIL (profile && buf, false);
	int total_bits = profile->sign_bits + profile->exp_bits + profile->mant_bits;
	if (total_bits > 64 || buf_size * 8 < total_bits) {
		return false;
	}

	ut64 bits = 0;
	int sign = 0;
	if (value < 0) {
		sign = 1;
		value = -value;
	}

	if (isnan (value)) {
		ut64 exp_max = (1ULL << profile->exp_bits) - 1;
		ut64 mant = 1; // some payload
		bits |= (ut64)sign << (total_bits - profile->sign_bits);
		bits |= exp_max << profile->mant_bits;
		bits |= mant;
	} else if (isinf (value)) {
		ut64 exp_max = (1ULL << profile->exp_bits) - 1;
		bits |= (ut64)sign << (total_bits - profile->sign_bits);
		bits |= exp_max << profile->mant_bits;
	} else if (value == 0.0) {
		// zero
		bits |= (ut64)sign << (total_bits - profile->sign_bits);
	} else {
		// normal or subnormal
		int frexp_exp;
		double mant = frexp (value, &frexp_exp);
		int exp = frexp_exp + profile->bias;

		if (exp <= 0) {
			// subnormal
			exp = 0;
			mant *= pow (2.0, profile->bias);
		} else if (exp >= (1 << profile->exp_bits) - 1) {
			// overflow to inf
			exp = (1 << profile->exp_bits) - 1;
			mant = 0;
		}

		ut64 mant_bits;
		if (exp == 0) {
			// subnormal
			double mant_frexp = mant / pow (2.0, profile->bias);
			mant_bits = (ut64)round (mant_frexp * pow (2.0, frexp_exp + profile->mant_bits + profile->bias - 1));
		} else {
			mant_bits = (ut64)round ((mant * 2.0 - 1.0) *(double) (1ULL << profile->mant_bits));
		}
		if (!profile->explicit_leading_bit && exp > 0) {
			mant_bits &= (1ULL << profile->mant_bits) - 1;
		}

		bits |= (ut64)sign << (total_bits - profile->sign_bits);
		bits |= (ut64)exp << profile->mant_bits;
		bits |= mant_bits;
	}
	int byte_size = (total_bits + 7) / 8;
	if (byte_size == 1) {
		r_write_ble8 (buf, (ut8)bits);
	} else if (byte_size == 2) {
		r_write_ble16 (buf, (ut16)bits, profile->big_endian);
	} else if (byte_size == 4) {
		r_write_ble32 (buf, (ut32)bits, profile->big_endian);
	} else if (byte_size <= 8) {
		r_write_ble64 (buf, bits, profile->big_endian);
	} else {
		// for larger, but since total_bits <=64, byte_size <=8
		return false;
	}
	return true;
}

R_API bool r_cfloat_write_simple(double value, int exp_bits, int mant_bits, ut8 *buf, size_t buf_size) {
	R_RETURN_VAL_IF_FAIL (buf && buf_size > 0, false);
	RCFloatProfile profile = { 1, exp_bits, mant_bits, (1 << (exp_bits - 1)) - 1, false, false };
	return r_cfloat_write (value, &profile, buf, buf_size);
}

static const RCFloatProfile binary16_profile = {1, 5, 10, 15, false, false};
static const RCFloatProfile binary32_profile = {1, 8, 23, 127, false, false};
static const RCFloatProfile binary64_profile = {1, 11, 52, 1023, false, false};
static const RCFloatProfile binary128_profile = {1, 15, 112, 16383, false, false};
static const RCFloatProfile bfloat16_profile = {1, 8, 7, 127, false, false};
static const RCFloatProfile x87_80_profile = {1, 15, 64, 16383, false, true};
static const RCFloatProfile vax_f_profile = {1, 8, 23, 64, true, true};
static const RCFloatProfile vax_d_profile = {1, 8, 55, 64, true, true};
static const RCFloatProfile vax_g_profile = {1, 11, 52, 1024, true, true};
static const RCFloatProfile ibm370_short_profile = {1, 7, 24, 64, true, true};
static const RCFloatProfile ibm370_long_profile = {1, 7, 56, 64, true, true};
static const RCFloatProfile cray_48_profile = {1, 11, 36, 1024, true, false};
static const RCFloatProfile cray_64_profile = {1, 15, 48, 16384, true, false};
static const RCFloatProfile cray_128_profile = {1, 15, 112, 16384, true, false};
static const RCFloatProfile bfloat8_profile = {1, 4, 3, 8, false, false};
static const RCFloatProfile tf32_profile = {1, 8, 10, 127, false, false};
static const RCFloatProfile binary96_profile = {1, 15, 80, 16383, false, true};
static const RCFloatProfile binary128_ibm_profile = {1, 15, 112, 16383, true, true};
static const RCFloatProfile binary256_profile = {1, 19, 236, 262143, false, false};

R_API const RCFloatProfile *r_cfloat_profile_from_name(const char *name) {
	R_RETURN_VAL_IF_FAIL (name, NULL);
	static const struct {
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

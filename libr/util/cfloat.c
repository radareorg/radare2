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
	value_low &= (total_bits == 64) ? ~0ULL : ((1ULL << total_bits) - 1);

	int sign_pos = total_bits - profile->sign_bits;
	int exp_pos = sign_pos - profile->exp_bits;
	int mant_pos = 0;

	ut64 sign = (value_low >> sign_pos) & ((1ULL << profile->sign_bits) - 1);
	ut64 exp = (value_low >> exp_pos) & ((1ULL << profile->exp_bits) - 1);
	ut64 mant = (value_low >> mant_pos) & ((1ULL << profile->mant_bits) - 1);

	if (profile->sign_bits == 1) {
		sign = sign ? 1 : 0;
	} else {
		// for multiple sign bits, perhaps not standard, assume 0 or 1
		sign = sign != 0;
	}

	ut64 exp_max = (1ULL << profile->exp_bits) - 1;

	if (exp == 0) {
		if (mant == 0) {
			return sign ? -0.0 : 0.0;
		} else {
			// subnormal
			double mant_val = mant;
			if (profile->explicit_leading_bit) {
				// for x87, mant includes leading bit
				int leading = (mant >> (profile->mant_bits - 1)) & 1;
				mant_val = (mant & ((1ULL << (profile->mant_bits - 1)) - 1));
				mant_val /= (double)(1ULL << (profile->mant_bits - 1));
				mant_val += leading;
			} else {
				mant_val /= (double)(1ULL << profile->mant_bits);
			}
			return (sign ? -1.0 : 1.0) * mant_val * pow (2.0, 1.0 - profile->bias);
		}
	} else if (exp == exp_max) {
		if (mant == 0) {
			return sign ? -INFINITY : INFINITY;
		}
		return sign ? -NAN : NAN;
	} else {
		// normal
		double mant_val = mant;
		if (profile->explicit_leading_bit) {
			int leading = (mant >> (profile->mant_bits - 1)) & 1;
			mant_val = (mant & ((1ULL << (profile->mant_bits - 1)) - 1));
			mant_val /= (double)(1ULL << (profile->mant_bits - 1));
			mant_val += leading;
		} else {
			mant_val = 1.0 + mant_val / (double)(1ULL << profile->mant_bits);
		}
		return (sign ? -1.0 : 1.0) * mant_val * pow (2.0, (double)exp - profile->bias);
	}
}

// Convenience function with exp_bits and mant_bits, assuming sign=1, bias= (1<<(exp_bits-1))-1, little endian, implicit
R_API double r_cfloat_parse_simple(const ut8 *buf, size_t buf_size, int exp_bits, int mant_bits) {
	R_RETURN_VAL_IF_FAIL (buf && buf_size > 0, (double)0.0);
	RCFloatProfile profile = {1, exp_bits, mant_bits, (1 << (exp_bits - 1)) - 1, false, false};
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
		int exp;
		double mant = frexp (value, &exp);
		exp += profile->bias;

		if (exp <= 0) {
			// subnormal
			exp = 0;
			mant *= pow (2.0, profile->bias);
		} else if (exp >= (1 << profile->exp_bits) - 1) {
			// overflow to inf
			exp = (1 << profile->exp_bits) - 1;
			mant = 0;
		}

		ut64 mant_bits = (ut64)round (mant * (1ULL << profile->mant_bits));
		if (!profile->explicit_leading_bit && exp > 0) {
			mant_bits &= (1ULL << profile->mant_bits) - 1;
		}

		bits |= (ut64)sign << (total_bits - profile->sign_bits);
		bits |= (ut64)exp << profile->mant_bits;
		bits |= mant_bits;
	}
	r_write_ble64 (buf, bits, profile->big_endian);
	return true;
}

R_API bool r_cfloat_write_simple(double value, int exp_bits, int mant_bits, ut8 *buf, size_t buf_size) {
	R_RETURN_VAL_IF_FAIL (buf && buf_size > 0, false);
	RCFloatProfile profile = {1, exp_bits, mant_bits, (1 << (exp_bits - 1)) - 1, false, false};
	return r_cfloat_write (value, &profile, buf, buf_size);
}

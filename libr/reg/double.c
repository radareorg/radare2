/* radare - LGPL - Copyright 2015-2022 - pancake */

#include <r_reg.h>
#include <r_util.h>

// Helper to select appropriate float profile based on register size and endianness
static RCFloatProfile get_float_profile(RReg *reg, RRegItem *item, bool *success) {
	const bool be = (reg->endian & R_SYS_ENDIAN_BIG) == R_SYS_ENDIAN_BIG;
	RCFloatProfile profile;

	if (success) {
		*success = true;
	}

	switch (item->size) {
	case 16:
		profile = R_CFLOAT_PROFILE_BINARY16;
		profile.big_endian = be;
		break;
	case 32:
		profile = R_CFLOAT_PROFILE_BINARY32;
		profile.big_endian = be;
		break;
	case 64:
		profile = R_CFLOAT_PROFILE_BINARY64;
		profile.big_endian = be;
		break;
	case 80:
		profile = R_CFLOAT_PROFILE_X87_80;
		profile.big_endian = be;
		break;
	case 96:
		profile = R_CFLOAT_PROFILE_BINARY96;
		profile.big_endian = be;
		break;
	case 128:
		profile = R_CFLOAT_PROFILE_BINARY128;
		profile.big_endian = be;
		break;
	case 256:
		profile = R_CFLOAT_PROFILE_BINARY256;
		profile.big_endian = be;
		break;
	default:
		if (success) {
			*success = false;
		}
		// Return a default profile even on failure
		profile = R_CFLOAT_PROFILE_BINARY64;
		profile.big_endian = be;
		break;
	}

	return profile;
}

static double parse_profile_value(const ut8 *src, int size_bytes, const RCFloatProfile *profile) {
	if (size_bytes <= 0) {
		return 0.0;
	}

	// For >64-bit formats, use extended API
	if (size_bytes > 8) {
		RCFloatValue value;
		if (r_cfloat_parse_ex (src, size_bytes, profile, &value)) {
			return r_cfloat_value_to_double (&value, profile);
		}
		return 0.0;
	}

	// For <=64-bit formats, use regular API
	ut8 tmp[8] = { 0 };
	if (size_bytes > (int)sizeof (tmp)) {
		size_bytes = sizeof (tmp);
	}
	memcpy (tmp, src, size_bytes);
	return r_cfloat_parse (tmp, size_bytes, profile);
}

// long double = 128 bit
R_API double r_reg_get_double(RReg *reg, RRegItem *item) {
	R_RETURN_VAL_IF_FAIL (reg && item, 0.0);

	int off = BITS2BYTES (item->offset);
	int size_bytes = BITS2BYTES (item->size);
	RRegSet *regset = &reg->regset[item->arena];

	if (!regset->arena || off + size_bytes > regset->arena->size) {
		R_LOG_WARN ("Register %s out of bounds", item->name);
		return 0.0;
	}

	bool success;
	RCFloatProfile profile = get_float_profile (reg, item, &success);
	if (!success) {
		R_LOG_WARN ("Bit size %d not supported for float", item->size);
		return 0.0;
	}

	return parse_profile_value (regset->arena->bytes + off, size_bytes, &profile);
}

R_API bool r_reg_set_double(RReg *reg, RRegItem *item, double value) {
	R_RETURN_VAL_IF_FAIL (reg && item, false);

	int off = BITS2BYTES (item->offset);
	int size_bytes = BITS2BYTES (item->size);
	RRegArena *arena = reg->regset[item->arena].arena;

	if (!arena || off + size_bytes > arena->size) {
		R_LOG_WARN ("Register %s out of bounds", item->name);
		return false;
	}

	bool success;
	RCFloatProfile profile = get_float_profile (reg, item, &success);
	if (!success) {
		R_LOG_WARN ("Bit size %d not supported for float", item->size);
		return false;
	}

	ut8 tmp[32];
	if (size_bytes > sizeof (tmp)) {
		R_LOG_WARN ("Register size %d too large", item->size);
		return false;
	}

	// For >64-bit formats, use extended API
	if (size_bytes > 8) {
		RCFloatValue fval;
		r_cfloat_value_from_double (&fval, value, &profile);
		if (!r_cfloat_write_ex (&fval, &profile, tmp, size_bytes)) {
			R_LOG_WARN ("Cannot write float value to %s", item->name);
			return false;
		}
	} else {
		// For <=64-bit formats, use regular API
		if (!r_cfloat_write (value, &profile, tmp, size_bytes)) {
			R_LOG_WARN ("Cannot write float value to %s", item->name);
			return false;
		}
	}

	r_mem_copybits (arena->bytes + off, tmp, item->size);
	return true;
}

// long double = 80 bit
R_API long double r_reg_get_longdouble(RReg *reg, RRegItem *item) {
	R_RETURN_VAL_IF_FAIL (reg && item, 0.0);

	int off = BITS2BYTES (item->offset);
	int size_bytes = BITS2BYTES (item->size);
	RRegSet *regset = &reg->regset[item->arena];

	if (!regset->arena || off + size_bytes > regset->arena->size) {
		R_LOG_WARN ("Register %s out of bounds", item->name);
		return 0.0;
	}

	bool success;
	RCFloatProfile profile = get_float_profile (reg, item, &success);
	if (!success) {
		R_LOG_WARN ("Bit size %d not supported for float", item->size);
		return 0.0;
	}

	// Use extended API for all sizes
	if (size_bytes > 8) {
		RCFloatValue value;
		if (r_cfloat_parse_ex (regset->arena->bytes + off, size_bytes, &profile, &value)) {
			return r_cfloat_value_to_longdouble (&value, &profile);
		}
		return 0.0;
	} else {
		double parsed = parse_profile_value (regset->arena->bytes + off, size_bytes, &profile);
		return (long double)parsed;
	}
}

R_API bool r_reg_set_longdouble(RReg *reg, RRegItem *item, long double value) {
	R_RETURN_VAL_IF_FAIL (reg && item, false);

	int off = BITS2BYTES (item->offset);
	int size_bytes = BITS2BYTES (item->size);
	RRegArena *arena = reg->regset[item->arena].arena;

	if (!arena || off + size_bytes > arena->size) {
		R_LOG_WARN ("Register %s out of bounds", item->name);
		return false;
	}

	bool success;
	RCFloatProfile profile = get_float_profile (reg, item, &success);
	if (!success) {
		R_LOG_WARN ("Bit size %d not supported for float", item->size);
		return false;
	}

	ut8 tmp[32];
	if (size_bytes > sizeof (tmp)) {
		R_LOG_WARN ("Register size %d too large", item->size);
		return false;
	}

	// Use extended API for all sizes
	if (size_bytes > 8) {
		RCFloatValue fval;
		r_cfloat_value_from_longdouble (&fval, value, &profile);
		if (!r_cfloat_write_ex (&fval, &profile, tmp, size_bytes)) {
			R_LOG_WARN ("Cannot write long double value to %s", item->name);
			return false;
		}
	} else {
		if (!r_cfloat_write ((double)value, &profile, tmp, size_bytes)) {
			R_LOG_WARN ("Cannot write long double value to %s", item->name);
			return false;
		}
	}

	r_mem_copybits (arena->bytes + off, tmp, item->size);
	return true;
}

/* floating point . deprecate maybe? */
R_API float r_reg_get_float(RReg *reg, RRegItem *item) {
	R_RETURN_VAL_IF_FAIL (reg && item, 0.0f);

	int off = BITS2BYTES (item->offset);
	int size_bytes = BITS2BYTES (item->size);
	RRegSet *regset = &reg->regset[item->arena];

	if (!regset->arena || off + size_bytes > regset->arena->size) {
		R_LOG_WARN ("Register %s out of bounds", item->name);
		return 0.0f;
	}

	bool success;
	RCFloatProfile profile = get_float_profile (reg, item, &success);
	if (!success) {
		R_LOG_WARN ("Bit size %d not supported for float", item->size);
		return 0.0f;
	}

	double parsed = parse_profile_value (regset->arena->bytes + off, size_bytes, &profile);
	return (float)parsed;
}

R_API bool r_reg_set_float(RReg *reg, RRegItem *item, float value) {
	R_RETURN_VAL_IF_FAIL (reg && item, false);

	int off = BITS2BYTES (item->offset);
	int size_bytes = BITS2BYTES (item->size);
	RRegArena *arena = reg->regset[item->arena].arena;

	if (!arena || off + size_bytes > arena->size) {
		R_LOG_WARN ("Register %s out of bounds", item->name);
		return false;
	}

	bool success;
	RCFloatProfile profile = get_float_profile (reg, item, &success);
	if (!success) {
		R_LOG_WARN ("Bit size %d not supported for float", item->size);
		return false;
	}

	ut8 tmp[32];
	if (size_bytes > sizeof (tmp)) {
		R_LOG_WARN ("Register size %d too large", item->size);
		return false;
	}

	if (!r_cfloat_write ((double)value, &profile, tmp, size_bytes)) {
		R_LOG_WARN ("Cannot write float value to %s", item->name);
		return false;
	}

	r_mem_copybits (arena->bytes + off, tmp, item->size);
	return true;
}

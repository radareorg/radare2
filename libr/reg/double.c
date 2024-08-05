/* radare - LGPL - Copyright 2015-2022 - pancake */

#include <r_reg.h>

// TODO: add support for 80bit floating point value

// long double = 128 bit
R_API double r_reg_get_double(RReg *reg, RRegItem *item) {
	R_RETURN_VAL_IF_FAIL (reg && item, 0.0f);
	double vld = 0.0f;
	double ret = 0.0f;
	int off = BITS2BYTES (item->offset);
	RRegSet *regset = &reg->regset[item->arena];
	switch (item->size) {
	case 64:
		if (regset->arena->size - off - 1 >= 0) {
			memcpy (&vld, regset->arena->bytes + off, sizeof (double));
			ret = vld;
		}
		break;
	default:
		R_LOG_WARN ("Bit size %d not supported", item->size);
		return 0.0f;
	}
	return ret;
}

R_API bool r_reg_set_double(RReg *reg, RRegItem *item, double value) {
	R_RETURN_VAL_IF_FAIL (reg && item, false);
	ut8 *src;
	switch (item->size) {
	case 64:
		// FIXME: endian
		src = (ut8 *)&value;
		break;
	default:
		R_LOG_WARN ("r_reg_set_double: Bit size %d not supported", item->size);
		return false;
	}
	if (reg->regset[item->arena].arena->size - BITS2BYTES (item->offset) - BITS2BYTES (item->size) >= 0) {
		r_mem_copybits (reg->regset[item->arena].arena->bytes +
				BITS2BYTES (item->offset),
			src, item->size);
		return true;
	}
	R_LOG_WARN ("r_reg_set_value: Cannot set %s to %lf", item->name, value);
	return false;
}

// long double = 80 bit
R_API long double r_reg_get_longdouble(RReg *reg, RRegItem *item) {
	R_RETURN_VAL_IF_FAIL (reg && item, 0.0f);
	RRegSet *regset;
	long double vld = 0.0f;
	int off;
	long double ret = 0.0f;
	if (!reg || !item) {
		return 0LL;
	}
	off = BITS2BYTES (item->offset);
	regset = &reg->regset[item->arena];
	switch (item->size) {
	case 80:
	case 96:
	case 128:
	case 256:
		if (regset->arena->size - off - 1 >= 0) {
			memcpy (&vld, regset->arena->bytes + off, sizeof (long double));
			ret = vld;
		}
		break;
	default:
		R_LOG_WARN ("Bit size %d not supported", item->size);
		return 0.0f;
	}
	return ret;
}

R_API bool r_reg_set_longdouble(RReg *reg, RRegItem *item, long double value) {
	R_RETURN_VAL_IF_FAIL (reg && item, false);
	ut8 *src = NULL;

	switch (item->size) {
	case 80:
	case 96:
	case 128:
		// FIXME: endian
		src = (ut8 *)&value;
		break;
	default:
		R_LOG_WARN ("Bit size %d not supported", item->size);
		return false;
	}
	if (reg->regset[item->arena].arena->size - BITS2BYTES (item->offset) - BITS2BYTES (item->size) >= 0) {
		r_mem_copybits (reg->regset[item->arena].arena->bytes +
				BITS2BYTES (item->offset),
			src, item->size);
		return true;
	}
	R_LOG_WARN ("Cannot set %s to %lf", item->name, (double)value);
	return false;
}

/* floating point . deprecate maybe? */
R_API float r_reg_get_float(RReg *reg, RRegItem *item) {
	// TODO
	return 0.0f;
}

R_API bool r_reg_set_float(RReg *reg, RRegItem *item, float value) {
	return false;
}

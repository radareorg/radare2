/* radare - LGPL - Copyright 2015 - pancake */

#include <r_reg.h>
#include <r_util.h>

// long double = 80 bit
R_API long double r_reg_get_double(RReg *reg, RRegItem *item) {
	RRegSet *regset;
	long double vld = 0.0f;
	int off;
	long double ret = 0.0f;
	if (!reg || !item)
		return 0LL;
	off = BITS2BYTES (item->offset);
	regset = &reg->regset[item->type];
	switch (item->size) {
	case 80:
		if (regset->arena->size-off-1>=0) {
			memcpy (&vld, regset->arena->bytes+off, 10);
			ret = vld;
		}
		break;
	}
	return ret;
}

R_API int r_reg_set_double(RReg *reg, RRegItem *item, long double value) {
	long double vld = 0.0f;
	ut8 *src;

	if (!item) {
		eprintf ("r_reg_set_value: item is NULL\n");
		return false;
	}
	switch (item->size) {
	case 80:
		r_mem_copyendian ( (ut8*)&vld, (ut8*)&value, 10, !reg->big_endian);
		src = (ut8*)&vld;
		break;
	default:
		eprintf ("r_reg_set_double : Bit size %d not supported\n", item->size);
		return false;
	}
	if (reg->regset[item->type].arena->size - BITS2BYTES (item->offset) - BITS2BYTES(item->size)>=0) {
		r_mem_copybits (reg->regset[item->type].arena->bytes+
				BITS2BYTES (item->offset), src, item->size);
		return true;
	}
	eprintf ("r_reg_set_value: Cannot set %s to %Lf\n", item->name, value);
	return false;
}

/* floating point . deprecate maybe? */
R_API float r_reg_get_float(RReg *reg, RRegItem *item) {
	// TODO
	return 0.0;
}

R_API int r_reg_set_float(RReg *reg, RRegItem *item, float value) {
	int ret = false;
	// TODO
	return ret;
}


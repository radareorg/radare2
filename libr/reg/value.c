/* radare - LGPL - Copyright 2009-2012 pancake<nopcode.org> */

#include <r_reg.h>
#include <r_util.h>

/* XXX: reg get can be accessed using the print_format stuff */
// This is the same as r_buf_set_bits, arenas can be r_buf
R_API ut64 r_reg_get_value(RReg *reg, RRegItem *item) {
	struct r_reg_set_t *regset;
	ut32 v32;
	ut16 v16;
	ut8 v8;
	int off;
	ut64 ret = 0LL;
	if (reg == NULL || item == NULL)
		return 0LL;
	off = BITS2BYTES (item->offset);
	regset = &reg->regset[item->type];
	if (item)
	switch (item->size) {
	case 1:
		ret = (regset->arena->bytes[item->offset/8] & (1<<(item->offset%8)))?1:0;
		break;
	case 8:
		memcpy (&v8, regset->arena->bytes+off, 1);
		ret = v8;
		break;
	case 16:
		memcpy (&v16, regset->arena->bytes+off, 2);
		ret = v16;
		break;
	case 32:
		memcpy (&v32, regset->arena->bytes+off, 4);
		ret = v32;
		break;
	case 64:
		memcpy (&ret, regset->arena->bytes+off, 8);
		break;
	default:
		eprintf ("r_reg_get_value: Bit size %d not supported\n", item->size);
		break;
	}
	return ret;
}

// TODO: cleanup this ugly code
R_API int r_reg_set_value(RReg *reg, RRegItem *item, ut64 value) {
	ut64 v64;
	ut32 v32;
	ut16 v16;
	ut8 v8, *src;

	if (!item)
		return R_FALSE;
	switch (item->size) {
	case 64: v64 = (ut64)value; src = (ut8*)&v64; break;
	case 32: v32 = (ut32)value; src = (ut8*)&v32; break;
	case 16: v16 = (ut16)value; src = (ut8*)&v16; break;
	case 8:  v8  = (ut8)value;  src = (ut8*)&v8;  break;
	case 1: 
		if (value) {
			ut8 * buf = reg->regset[item->type].arena->bytes + (item->offset/8);
			int bit = (item->offset%8);
			ut8 mask = (1<<bit);
			buf[0] = (buf[0] &(0xff^mask)) | mask;
		} else {
			ut8 * buf = reg->regset[item->type].arena->bytes + (item->offset/8);
			int bit = (item->offset%8);
			ut8 mask = 0xff^(1<<bit);
			buf[0] = (buf[0] & mask) | 0;
		}
		return R_TRUE;
	default: 
		eprintf ("r_reg_set_value: Bit size %d not supported\n", item->size);
		return R_FALSE;
	}
	r_mem_copybits (reg->regset[item->type].arena->bytes+
		BITS2BYTES (item->offset), src, item->size);
	return R_TRUE;
}

R_API char *r_reg_get_bvalue(RReg *reg, RRegItem *item) {
	char *out;
	ut64 num;
	if (!item->flags)
		return NULL;
	out = malloc (strlen (item->flags)+1);
	num = r_reg_get_value (reg, item);
	r_str_bits (out, (ut8*)&num, strlen (item->flags)*8, item->flags);
	return out;
}

/* floating point */
// XXX: use double for better precission?
R_API float r_reg_get_fvalue(RReg *reg, RRegItem *item) {
	// TODO
	return 0.0;
}

R_API int r_reg_set_fvalue(RReg *reg, RRegItem *item, float value) {
	int ret = R_FALSE;
	// TODO
	return ret;
}

/* packed registers */
R_API ut64 r_reg_get_pvalue(RReg *reg, RRegItem *item, int packidx) {
	// TODO
	return 0LL;
}

R_API int r_reg_set_pvalue(RReg *reg, RRegItem *item, ut64 value, int packidx) {
	int ret = R_FALSE;
	// TODO
	return ret;
}

/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_reg.h>
#include <r_util.h>

/* XXX: reg get can be accessed using the print_format stuff */
// This is the same as r_buf_set_bits, arenas can be r_buf
R_API ut64 r_reg_get_value(RReg *reg, RRegItem *item) {
	RRegSet *regset;
	ut32 v32;
	ut16 v16;
	ut8 v8;
	int off;
	ut64 ret = 0LL;
	if (!reg || !item)
		return 0LL;
	off = BITS2BYTES (item->offset);
	regset = &reg->regset[item->type];
#if 0
	eprintf ("GET sz=%d off %d  off = %d %d\n",
		item->size, off, item->offset, (item->offset/8));
#endif
	switch (item->size) {
	case 1:
		ret = (regset->arena->bytes[item->offset/8] & \
			(1<<(item->offset%8)))?1:0;
#if 0
off=144;
eprintf ("..... %d  : %02x %02x %02x %02x\n",
off,
		(regset->arena->bytes[off]),
		(regset->arena->bytes[off+1]),
		(regset->arena->bytes[off+2]),
		(regset->arena->bytes[off+3]));
eprintf ("%d   :   %02x %02x %02x %02x\n",
	(int)(item->offset/8),
		(regset->arena->bytes[item->offset/8]),
		(regset->arena->bytes[1+(item->offset/8)]),
		(regset->arena->bytes[2+(item->offset/8)]),
		(regset->arena->bytes[3+(item->offset/8)]));
#endif

		break;
	case 8:
		if (regset->arena->size-off-1>=0) {
			memcpy (&v8, regset->arena->bytes+off, 1);
			ret = v8;
		}
		break;
	case 16:
		if (regset->arena->size-off-2>=0) {
			r_mem_copyendian ((ut8*)&v16, (ut8*)regset->arena->bytes+off, 2, !reg->big_endian);
			ret = v16;
		}
		break;
	case 32:
#if 0
eprintf ("%d  : %02x %02x %02x %02x\n",
off,
		(regset->arena->bytes[off]),
		(regset->arena->bytes[off+1]),
		(regset->arena->bytes[off+2]),
		(regset->arena->bytes[off+3]));
#endif
		if (off+4<=regset->arena->size) {
			r_mem_copyendian ((ut8*)&v32, (ut8*)regset->arena->bytes+off, 4, !reg->big_endian);
			ret = v32;
		} else eprintf ("r_reg_get_value: 32bit oob read %d\n", off);
		break;
	case 64:
		if (regset->arena->bytes && (off+8<=regset->arena->size))
			r_mem_copyendian ((ut8*)&ret, (ut8*)regset->arena->bytes+off, 8, !reg->big_endian);
		else eprintf ("r_reg_get_value: null or oob arena for current regset\n");
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

	if (!item) {
		eprintf ("r_reg_set_value: item is NULL\n");
		return R_FALSE;
	}
	switch (item->size) {
	case 64: r_mem_copyendian ( (ut8*)&v64, (ut8*)&value, 8, !reg->big_endian); src = (ut8*)&v64; break;
	case 32: r_mem_copyendian ( (ut8*)&v32, (ut8*)&value, 4, !reg->big_endian); src = (ut8*)&v32; break;
	case 16: r_mem_copyendian ( (ut8*)&v16, (ut8*)&value, 2, !reg->big_endian); src = (ut8*)&v16; break;
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
	if (reg->regset[item->type].arena->size
	    - BITS2BYTES (item->offset) - BITS2BYTES(item->size)>=0) {
		r_mem_copybits (reg->regset[item->type].arena->bytes+
				BITS2BYTES (item->offset), src, item->size);
		return R_TRUE;
	}
	eprintf ("r_reg_set_value: Cannot set %s to 0x%"PFMT64x"\n", item->name, value);
	return R_FALSE;
}

R_API ut64 r_reg_set_bvalue(RReg *reg, RRegItem *item, const char *str) {
	ut64 num;
	if (!item->flags)
		return UT64_MAX;
	num = r_str_bits_from_string (str, item->flags);
	if (num == UT64_MAX) 
		r_reg_set_value (reg, item, r_num_math (NULL, str));
	else r_reg_set_value (reg, item, num);
	return num;
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

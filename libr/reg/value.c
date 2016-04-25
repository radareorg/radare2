/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_reg.h>
#include <r_util.h>
#include <r_types.h>

#define SAME_ENDIAN ( \
	   ((strcmp(R_SYS_ENDIAN, "little") == 0) && reg->big_endian == 0) \
	|| ((strcmp(R_SYS_ENDIAN, "big") == 0) && reg->big_endian == 1)    \
	)

#define SWAP_ENDIAN (SAME_ENDIAN)

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
		ret = (regset->arena->bytes[item->offset / 8] &
		(1 << (item->offset % 8))) ?
			1 :
			0;
		break;
	case 4:
		if (regset->arena->size - off - 1 >= 0) {
			memcpy (&v8, regset->arena->bytes + off, 1);
			ret = v8 & 0xF;
		}
		break;
	case 8:
		if (regset->arena->size - off - 1 >= 0) {
			memcpy (&v8, regset->arena->bytes + off, 1);
			ret = v8;
		}
		break;
	case 16:
		if (regset->arena->size - off - 2 >= 0) {
			r_mem_copyendian ((ut8 *)&v16, (ut8 *)regset->arena->bytes + off, 2, SWAP_ENDIAN);
			ret = v16;
		}
		break;
	case 32:
		if (off + 4 <= regset->arena->size) {
			r_mem_copyendian ((ut8 *)&v32,
					(ut8 *)regset->arena->bytes + off,
					sizeof (ut32), SWAP_ENDIAN);
			ret = v32;
		} else eprintf ("r_reg_get_value: 32bit oob read %d\n", off);
		break;
	case 64:
		if (regset->arena->bytes && (off + 8 <= regset->arena->size))
			r_mem_copyendian ((ut8 *)&ret, (ut8 *)regset->arena->bytes + off, 8, SWAP_ENDIAN);
		else eprintf ("r_reg_get_value: null or oob arena for current regset\n");
		break;
	case 80: // long double
	case 96: // long floating value
		// FIXME: It is a precision loss, please implement me properly!
		ret = (ut64)r_reg_get_longdouble (reg, item);
		break;
	default:
		eprintf ("r_reg_get_value: Bit size %d not supported\n", item->size);
		break;
	}
	return ret;
}

R_API bool r_reg_set_value(RReg *reg, RRegItem *item, ut64 value) {
	ut64 v64;
	ut32 v32;
	ut16 v16;
	int fits_in_arena;
	ut8 v8, *src = NULL;

	if (!item) {
		eprintf ("r_reg_set_value: item is NULL\n");
		return false;
	}
	switch (item->size) {
	case 80:
	case 96: // long floating value
		r_reg_set_longdouble (reg, item, (long double)value);
		break;
	case 64:
		r_mem_copyendian ((ut8 *)&v64, (ut8 *)&value, 8, SWAP_ENDIAN);
		src = (ut8 *)&v64;
		break;
	case 32:
		r_mem_copyendian ((ut8 *)&v32, (ut8 *)&value, 4, SWAP_ENDIAN);
		src = (ut8 *)&v32;
		break;
	case 16:
		r_mem_copyendian ((ut8 *)&v16, (ut8 *)&value, 2, SWAP_ENDIAN);
		src = (ut8 *)&v16;
		break;
	case 8:
		v8 = (ut8)value;
		src = (ut8 *)&v8;
		break;
	case 1:
		if (value) {
			ut8 *buf = reg->regset[item->type].arena->bytes + (item->offset / 8);
			int bit = (item->offset % 8);
			ut8 mask = (1 << bit);
			buf[0] = (buf[0] & (0xff ^ mask)) | mask;
		} else {
			ut8 *buf = reg->regset[item->type].arena->bytes + (item->offset / 8);
			int bit = item->offset % 8;
			ut8 mask = 0xff ^ (1 << bit);
			buf[0] = (buf[0] & mask) | 0;
		}
		return true;
	default:
		eprintf ("r_reg_set_value: Bit size %d not supported\n", item->size);
		return false;
	}
	fits_in_arena = (reg->regset[item->type].arena->size - BITS2BYTES (item->offset) - BITS2BYTES (item->size)) >= 0;
	if (src && fits_in_arena) {
		r_mem_copybits (reg->regset[item->type].arena->bytes +
					BITS2BYTES (item->offset),
				src, item->size);
		return true;
	}
	eprintf ("r_reg_set_value: Cannot set %s to 0x%" PFMT64x "\n", item->name, value);
	return false;
}

R_API ut64 r_reg_set_bvalue(RReg *reg, RRegItem *item, const char *str) {
	ut64 num = UT64_MAX;
	if (item && item->flags && str) {
		num = r_str_bits_from_string (str, item->flags);
		if (num == UT64_MAX)
			num = r_num_math (NULL, str);
		r_reg_set_value (reg, item, num);
	}
	return num;
}

R_API R_HEAP char *r_reg_get_bvalue(RReg *reg, RRegItem *item) {
	char *out = NULL;
	if (reg && item && item->flags) {
		out = malloc (strlen (item->flags) + 1);
		if (out) {
			ut64 num = r_reg_get_value (reg, item);
			r_str_bits (out, (ut8 *)&num,
				strlen (item->flags) * 8, item->flags);
		}
	}
	return out;
}

/* packed registers */
// packbits can be 8, 16, 32 or 64
// result value is always casted into ut64
// TODO: use item->packed_size
R_API ut64 r_reg_get_pack(RReg *reg, RRegItem *item, int packidx, int packbits) {
	int packbytes, packmod;
	ut64 ret = 0LL;
	RRegSet *regset;
	int off;
	if (!reg || !item)
		return 0LL;
	if (packbits < 1) {
		packbits = item->packed_size;
	}
	packbytes = packbits / 8;
	packmod = packbits % 8;
	if (packmod) {
		eprintf ("Invalid bit size for packet register\n");
		return 0LL;
	}
	off = BITS2BYTES (item->offset);
	regset = &reg->regset[item->type];
	off += (packidx * packbytes);
	if (regset->arena->size - off - 1 >= 0) {
		memcpy (&ret, regset->arena->bytes + off, packbytes);
	}
	return ret;
}

R_API int r_reg_set_pack(RReg *reg, RRegItem *item, int packidx, int packbits, ut64 val) {
	int off, packbytes, packmod;

	if (!reg || !item) {
		eprintf ("r_reg_set_value: item is NULL\n");
		return false;
	}
	if (packbits < 1) {
		packbits = item->packed_size;
	}
	off = item->offset;
	packbytes = packbits / 8;
	packmod = packbits % 8;
	if (packidx * packbits > item->size) {
		eprintf ("Packed index is beyond the register size\n");
		return false;
	}
	if (packmod) {
		eprintf ("Invalid bit size for packet register\n");
		return false;
	}
	if (reg->regset[item->type].arena->size - BITS2BYTES (off) - BITS2BYTES (packbytes) >= 0) {
		ut8 *dst = reg->regset[item->type].arena->bytes + BITS2BYTES (off);
		r_mem_copybits (dst, (ut8 *)&val, packbytes);
		return true;
	}
	eprintf ("r_reg_set_value: Cannot set %s to 0x%" PFMT64x "\n", item->name, val);
	return false;
}

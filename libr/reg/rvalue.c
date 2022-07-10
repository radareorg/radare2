/* radare - LGPL - Copyright 2009-2022 - pancake */

#include <r_reg.h>

typedef ut32 ut27;
// 580 move to r_util
static ut27 r_read_me27(const ut8 *buf, int boff) {
	ut27 ret = 0;
	r_mem_copybits_delta ((ut8 *)&ret, 18, buf, boff, 9);
	r_mem_copybits_delta ((ut8 *)&ret, 9, buf, boff + 9, 9);
	r_mem_copybits_delta ((ut8 *)&ret, 0, buf, boff + 18, 9);
	return ret;
}

R_API ut64 r_reg_get_value_big(RReg *reg, RRegItem *item, utX *val) {
	r_return_val_if_fail (reg && item, 0);

	ut64 ret = 0LL;
	int off = BITS2BYTES (item->offset);
	RRegSet *regset = &reg->regset[item->arena];
	if (!regset->arena) {
		return 0LL;
	}
	switch (item->size) {
	case 80: // word + qword
		if (regset->arena->bytes && (off + 10 <= regset->arena->size)) {
			val->v80.Low = *((ut64 *)(regset->arena->bytes + off));
			val->v80.High = *((ut16 *)(regset->arena->bytes + off + 8));
		} else {
			R_LOG_WARN ("null or oob arena for current regset");
		}
		ret = val->v80.Low;
		break;
	case 96: // dword + qword
		if (regset->arena->bytes && (off + 12 <= regset->arena->size)) {
			val->v96.Low = *((ut64 *)(regset->arena->bytes + off));
			val->v96.High = *((ut32 *)(regset->arena->bytes + off + 8));
		} else {
			R_LOG_WARN ("null or oob arena for current regset");
		}
		ret = val->v96.Low;
		break;
	case 128: // qword + qword
		if (regset->arena->bytes && (off + 16 <= regset->arena->size)) {
			val->v128.Low = *((ut64 *)(regset->arena->bytes + off));
			val->v128.High = *((ut64 *)(regset->arena->bytes + off + 8));
		} else {
			R_LOG_WARN ("null or oob arena for current regset");
		}
		ret = val->v128.Low;
		break;
	case 256:// qword + qword + qword + qword
		if (regset->arena->bytes && (off + 32 <= regset->arena->size)) {
			val->v256.Low.Low = *((ut64 *)(regset->arena->bytes + off));
			val->v256.Low.High = *((ut64 *)(regset->arena->bytes + off + 8));
			val->v256.High.Low = *((ut64 *)(regset->arena->bytes + off + 16));
			val->v256.High.High = *((ut64 *)(regset->arena->bytes + off + 24));
		} else {
			R_LOG_WARN ("null or oob arena for current regset");
		}
		ret = val->v256.Low.Low;
		break;
	default:
		R_LOG_WARN ("Bit size %d not supported", item->size);
		break;
	}
	return ret;
}

R_API ut64 r_reg_get_value(RReg *reg, RRegItem *item) {
	r_return_val_if_fail (reg && item, 0);
	if (item->offset == -1) {
		return 0LL;
	}
	int off = BITS2BYTES (item->offset);
	RRegSet *regset = &reg->regset[item->arena];
	if (!regset->arena) {
		return 0LL;
	}
	bool be = (reg->config)? reg->config->big_endian: false;
	switch (item->size) {
	case 1: {
		int offset = item->offset / 8;
		if (offset >= regset->arena->size) {
			break;
		}
		return (regset->arena->bytes[offset] &
			       (1 << (item->offset % 8)))
			? 1
			: 0;
	} break;
	case 4:
		if (regset->arena->size - off - 1 >= 0) {
			return (r_read_at_ble8 (regset->arena->bytes, off)) & 0xF;
		}
		break;
	case 8:
		if (regset->arena->size - off - 1 >= 0) {
			return r_read_at_ble8 (regset->arena->bytes, off);
		}
		break;
	case 16:
		if (regset->arena->size - off - 2 >= 0) {
			return r_read_ble16 (regset->arena->bytes + off, be);
		}
		break;
	case 27:
		if (off + 3 < regset->arena->size) {
			return r_read_me27 (regset->arena->bytes + off, 0);
		}
		break;
	case 32:
		if (off + 4 <= regset->arena->size) {
			return r_read_ble32 (regset->arena->bytes + off, be);
		}
		R_LOG_WARN ("32bit oob read %d", off);
		break;
	case 64:
		if (regset->arena && regset->arena->bytes && (off + 8 <= regset->arena->size)) {
			return r_read_ble64 (regset->arena->bytes + off, be);
		}
		// R_LOG_WARN ("null or oob arena for current regset");
		break;
	case 80: // long double
	case 96: // long floating value
		// FIXME: It is a precision loss, please implement me properly!
		{
			long double ld = r_reg_get_longdouble (reg, item);
			return isnan (ld)? UT64_MAX: (ut64)ld;
		}
	case 128:
	case 256:
		// XXX 128 & 256 bit
		{
			long double ld = r_reg_get_longdouble (reg, item);
			return isnan (ld)? UT64_MAX: (ut64)ld;
		}
	default:
		R_LOG_WARN ("Bit size %d not supported", item->size);
		break;
	}
	return 0LL;
}

R_API ut64 r_reg_get_value_by_role(RReg *reg, RRegisterId role) {
	// TODO use mapping from RRegisterId to RRegItem (via RRegSet)
	return r_reg_get_value (reg, r_reg_get (reg, r_reg_get_name (reg, role), -1));
}

R_API bool r_reg_set_value(RReg *reg, RRegItem *item, ut64 value) {
	r_return_val_if_fail (reg && item, false);

	ut8 bytes[12] = {0};
	ut8 *src = bytes;

	if (r_reg_is_readonly (reg, item)) {
		return true;
	}
	if (item->offset < 0) {
		return true;
	}
	RRegArena *arena = reg->regset[item->arena].arena;
	if (!arena) {
		return false;
	}
	bool be = (reg->config)? reg->config->big_endian: false;
	switch (item->size) {
	case 80:
	case 96: // long floating value
		r_reg_set_longdouble (reg, item, (long double)value);
		break;
	case 64:
		r_write_ble64 (src, value, be);
		break;
	case 32:
		r_write_ble32 (src, value, be);
		break;
	case 16:
		r_write_ble16 (src, value, be);
		break;
	case 8:
		r_write_ble8 (src, (ut8) (value & UT8_MAX));
		break;
	case 1:
		if (value) {
			ut8 *buf = arena->bytes + (item->offset / 8);
			int bit = (item->offset % 8);
			ut8 mask = (1 << bit);
			buf[0] = (buf[0] & (0xff ^ mask)) | mask;
		} else {
			int idx = item->offset / 8;
			if (idx + item->size > arena->size) {
				R_LOG_WARN ("RRegSetOverflow %d vs %d", idx + item->size, arena->size);
				return false;
			}
			ut8 *buf = arena->bytes + idx;
			int bit = item->offset % 8;
			ut8 mask = 0xff ^ (1 << bit);
			buf[0] = (buf[0] & mask) | 0;
		}
		return true;
	case 128:
	case 256:
		// XXX 128 & 256 bit
		return false; // (ut64)r_reg_get_longdouble (reg, item);
	default:
		R_LOG_WARN ("Bit size %d not supported", item->size);
		return false;
	}
	const bool fits_in_arena = (arena->size - BITS2BYTES (item->offset) - BITS2BYTES (item->size)) >= 0;
	if (src && fits_in_arena) {
		r_mem_copybits (reg->regset[item->arena].arena->bytes +
				BITS2BYTES (item->offset),
				src, item->size);
		return true;
	}
	R_LOG_WARN ("Cannot set %s to 0x%" PFMT64x, item->name, value);
	return false;
}

R_API bool r_reg_set_value_by_role(RReg *reg, RRegisterId role, ut64 val) {
	r_return_val_if_fail (reg, false);
	// TODO use mapping from RRegisterId to RRegItem (via RRegSet)
	RRegItem *r = r_reg_get (reg, r_reg_get_name (reg, role), -1);
	return r? r_reg_set_value (reg, r, val): false;
}

R_API ut64 r_reg_set_bvalue(RReg *reg, RRegItem *item, const char *str) {
	r_return_val_if_fail (reg && item && str, UT64_MAX);
	ut64 num = UT64_MAX;
	if (item && item->flags && str) {
		num = r_str_bits_from_string (str, item->flags);
		if (num == UT64_MAX) {
			num = r_num_math (NULL, str);
		}
		r_reg_set_value (reg, item, num);
	}
	return num;
}

R_API R_HEAP char *r_reg_get_bvalue(RReg *reg, RRegItem *item) {
	r_return_val_if_fail (reg && item, NULL);
	char *out = NULL;
	if (item->flags) {
		size_t if_len = strlen (item->flags);
		out = malloc (if_len + 1);
		if (out) {
			ut64 num = r_reg_get_value (reg, item);
			r_str_bits (out, (ut8 *)&num, if_len * 8, item->flags);
		}
	}
	return out;
}

/* packed registers */
// packbits can be 8, 16, 32 or 64
// result value is always casted into ut64
// TODO: support packbits=128 for xmm registers
R_API ut64 r_reg_get_pack(RReg *reg, RRegItem *item, int packidx, int packbits) {
	r_return_val_if_fail (reg && item, 0LL);

	if (packbits < 1) {
		packbits = item->packed_size;
	}
	if (packbits > 64) {
		packbits = 64;
		R_LOG_WARN ("Does not support pack bits > 64");
	}

	ut64 ret = 0LL;
	const int packbytes = packbits / 8;
	const int packmod = packbits % 8;
	if (packmod) {
		R_LOG_WARN ("Invalid bit size for packet register");
		return 0LL;
	}
	if ((packidx + 1) * packbits > item->size) {
		R_LOG_WARN ("Packed index is beyond the register size");
		return 0LL;
	}
	RRegSet *regset = &reg->regset[item->arena];
	if (!regset->arena) {
		return 0LL;
	}
	int off = BITS2BYTES (item->offset);
	off += (packidx * packbytes);
	if (regset->arena->size - off - 1 >= 0) {
		int i;
		for (i = packbytes - 1; i >= 0; i--) {
			ret = (ret << 8) | regset->arena->bytes[off + i];
		}
	}
	return ret;
}

// TODO: support packbits=128 for xmm registers
// R2_580 : return bool instead of int
R_API int r_reg_set_pack(RReg *reg, RRegItem *item, int packidx, int packbits, ut64 val) {
	r_return_val_if_fail (reg && reg->regset->arena && item, false);

	if (packbits < 1) {
		packbits = item->packed_size;
	}
	if (packbits > 64) {
		packbits = 64;
		R_LOG_WARN ("Does not support pack bits > 64");
	}

	int packbytes = packbits / 8;
	if ((packidx + 1) * packbits > item->size) {
		R_LOG_WARN ("Packed index is beyond the register size");
		return false;
	}
	int off = BITS2BYTES (item->offset) + (packidx * packbytes);
	if (reg->regset[item->arena].arena->size - BITS2BYTES (off) - BITS2BYTES (packbytes) >= 0) {
		ut8 *dst = reg->regset[item->arena].arena->bytes + off;
		int i;
		for (i = 0; i < packbytes; i++, val >>= 8) {
			dst[i] = val & 0xff;
		}
		return true;
	}
	R_LOG_WARN ("Cannot set %s to 0x%" PFMT64x, item->name, val);
	return false;
}

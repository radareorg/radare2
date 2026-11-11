/* radare - LGPL - Copyright 2009-2023 - pancake */

#include <r_reg.h>
#include <r_util.h>

R_API R_OWNED char *r_reg_get_value_hex(RReg *reg, RRegItem *item) {
	R_RETURN_VAL_IF_FAIL (reg && item, NULL);
	RRegArena *arena = r_reg_value_arena (reg, item);
	size_t len;
	if (!arena || r_add_overflow_size_t (item->size / 4, 3, &len)) {
		return NULL;
	}
	const int size = item->size / 8;
	char *hex = malloc (len);
	if (hex) {
		const bool be = (reg->endian & R_SYS_ENDIAN_BIG) == R_SYS_ENDIAN_BIG;
		const ut8 *bytes = arena->bytes + item->offset / 8;
		hex[0] = '0';
		hex[1] = 'x';
		int i;
		for (i = 0; i < size; i++) {
			r_hex_from_byte (hex + 2 + (size - i - 1) * 2, bytes[r_reg_value_byte_offset (i, size, be)]);
		}
		hex[size * 2 + 2] = 0;
	}
	return hex;
}

// Accept an unsigned hexadecimal integer, zero-extended to the register width.
R_API bool r_reg_set_value_hex(RReg *reg, RRegItem *item, const char *hex) {
	R_RETURN_VAL_IF_FAIL (reg && item && hex, false);
	if (!r_reg_value_arena (reg, item)) {
		return false;
	}
	if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
		hex += 2;
	}
	const int size = item->size / 8;
	const size_t digits = strlen (hex);
	if (!digits || digits > size * 2) {
		return false;
	}
	ut8 *bytes = calloc (1, size);
	if (!bytes) {
		return false;
	}
	const bool be = (reg->endian & R_SYS_ENDIAN_BIG) == R_SYS_ENDIAN_BIG;
	bool ok = true;
	size_t i;
	for (i = 0; i < digits; i++) {
		ut8 nibble = 0;
		if (!r_hex_to_byte (&nibble, hex[digits - i - 1])) {
			ok = false;
			break;
		}
		bytes[r_reg_value_byte_offset (i / 2, size, be)] |= nibble << ((i & 1) * 4);
	}
	ok = ok && r_reg_set_value_bytes (reg, item, bytes, size);
	free (bytes);
	return ok;
}

static ut64 reg_read_bytes(const ut8 *bytes, int count, bool be) {
	ut64 value = 0;
	int i;
	for (i = 0; i < count; i++) {
		value = (value << 8) | bytes[be? i: count - 1 - i];
	}
	return value;
}

static void reg_write_bytes(ut8 *bytes, int count, bool be, ut64 value) {
	int i;
	for (i = 0; i < count; i++, value >>= 8) {
		bytes[be? count - 1 - i: i] = value & 0xff;
	}
}

R_API ut64 r_reg_get_value(RReg *reg, RRegItem *item) {
	R_RETURN_VAL_IF_FAIL (reg && item, 0);
	if (item->offset == -2) {
		return UT64_MAX;
	}
	if (item->offset == -1) {
		return 0LL;
	}
	if (item->size >= 128) {
		RRegArena *arena = r_reg_value_arena (reg, item);
		return arena? r_read_ble64 (arena->bytes + item->offset / 8,
			(reg->endian & R_SYS_ENDIAN_BIG) == R_SYS_ENDIAN_BIG): 0;
	}
	int off = BITS2BYTES (item->offset);
	RRegSet *regset = &reg->regset[item->arena];
	if (!regset->arena) {
		return 0LL;
	}
	bool be = (reg->endian & R_SYS_ENDIAN_BIG) == R_SYS_ENDIAN_BIG;
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
	case 4: {
		int byte = item->offset / 8;
		if (byte < regset->arena->size) {
			return (regset->arena->bytes[byte] >> (item->offset % 8)) & 0xf;
		}
		break;
	}
	case 8:
		if (regset->arena->size - off - 1 >= 0) {
			return r_read_at_ble8 (regset->arena->bytes, off);
		}
		break;
	case 12:
		if (regset->arena->size - off - 2 >= 0) {
			return r_read_ble16 (regset->arena->bytes + off, be) & 0x7ff;
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
	case 24:
		if (off + 3 <= regset->arena->size) {
			return r_read_ble24 (regset->arena->bytes + off, be);
		}
		R_LOG_WARN ("24bit oob read %d", off);
		break;
	case 32:
		if (off + 4 <= regset->arena->size) {
			return r_read_ble32 (regset->arena->bytes + off, be);
		}
		R_LOG_WARN ("32bit oob read %d", off);
		break;
	case 40:
	case 48:
	case 56: {
		const int count = BITS2BYTES (item->size);
		if (off + count <= regset->arena->size) {
			return reg_read_bytes (regset->arena->bytes + off, count, be);
		}
		break;
	}
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
#if R2_NO_LONG_DOUBLE
			double ld = r_reg_get_longdouble (reg, item);
#else
			long double ld = r_reg_get_longdouble (reg, item);
#endif
			return isnan (ld)? UT64_MAX: (ut64)ld;
		}
	default:
		R_LOG_WARN ("Bit size %d not supported", item->size);
		break;
	}
	return 0LL;
}

R_API ut64 r_reg_get_value_by_role(RReg *reg, RRegAlias alias) {
	// TODO use mapping from RRegisterId to RRegItem (via RRegSet)
	const char *rn = r_reg_alias_getname (reg, alias);
	ut64 res = UT64_MAX;
	if (R_LIKELY (rn)) {
		RRegItem *ri = r_reg_get (reg, rn, -1);
		if (ri) {
			res = r_reg_get_value (reg, ri);
			r_unref (ri);
		}
	}
	return res;
}

static bool item_is_zero(RReg *reg, RRegItem *item, RRegArena *arena) {
	if (item->size <= 64) {
		return !r_reg_get_value (reg, item);
	}
	const int off = item->offset / 8;
	return r_mem_is_zero (arena->bytes + off, BITS2BYTES (item->offset + item->size) - off);
}

R_API bool r_reg_set_value(RReg *reg, RRegItem *item, ut64 value) {
	R_RETURN_VAL_IF_FAIL (reg && item, false);
	if (item->ro) {
		return true;
	}
	if (item->offset < 0) {
		return true;
	}
	if (item->size >= 128) {
		RRegArena *arena = r_reg_value_arena (reg, item);
		if (!arena) {
			return false;
		}
		r_reg_arena_materialize (arena);
		if (!arena->bytes) {
			return false;
		}
		ut8 *bytes = arena->bytes + item->offset / 8;
		memset (bytes, 0, item->size / 8);
		r_write_ble64 (bytes, value, (reg->endian & R_SYS_ENDIAN_BIG) == R_SYS_ENDIAN_BIG);
		return true;
	}
	ut8 bytes[16] = {0};
	ut8 *src = bytes;
	RRegArena *arena = reg->regset[item->arena].arena;
	if (!arena) {
		return false;
	}
	// arps can shrink the arena below what the profile needs
	const int end = BITS2BYTES (item->offset + item->size);
	if (end > arena->size) {
		R_LOG_WARN ("RRegSetOverflow %d vs %d", end, arena->size);
		return false;
	}
	if (!value && item_is_zero (reg, item, arena)) {
		return true;
	}
	r_reg_arena_materialize (arena);
	const bool be = (reg->endian & R_SYS_ENDIAN_BIG) == R_SYS_ENDIAN_BIG;
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
	case 24:
		r_write_ble24 (src, value, be);
		break;
	case 40:
	case 48:
	case 56:
		reg_write_bytes (src, BITS2BYTES (item->size), be, value);
		break;
	case 4: {
		ut8 *buf = arena->bytes + item->offset / 8;
		int shift = item->offset % 8;
		*buf = (*buf & ~(0xf << shift)) | ((value & 0xf) << shift);
		return true;
	}
	case 8:
		r_write_ble8 (src, (ut8) (value & UT8_MAX));
		break;
	case 1:
		{
			ut8 *buf = arena->bytes + (item->offset / 8);
			const ut8 mask = 1 << (item->offset % 8);
			*buf = value? (*buf | mask): (*buf & ~mask);
		}
		return true;
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

R_API bool r_reg_set_value_by_role(RReg *reg, RRegAlias alias, ut64 val) {
	R_RETURN_VAL_IF_FAIL (reg, false);
	const char *rn = r_reg_alias_getname (reg, alias);
	bool res = false;
	if (R_LIKELY (rn)) {
		// TODO use mapping from RRegAlias to RRegItem (via RRegSet)
		RRegItem *r = r_reg_get (reg, rn, -1);
		if (r) {
			res = r_reg_set_value (reg, r, val);
			r_unref (r);
		}
	}
	return res;
}

R_API ut64 r_reg_set_bvalue(RReg *reg, RRegItem *item, const char *str) {
	R_RETURN_VAL_IF_FAIL (reg && item && str, UT64_MAX);
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
	R_RETURN_VAL_IF_FAIL (reg && item, NULL);
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

R_API ut64 r_reg_get_pack(RReg *reg, RRegItem *item, int packidx, int packbits) {
	ut64 value = 0;
	r_reg_get_pack_checked (reg, item, packidx, packbits, &value);
	return value;
}

R_API bool r_reg_set_pack(RReg *reg, RRegItem *item, int packidx, int packbits, ut64 val) {
	R_RETURN_VAL_IF_FAIL (reg && item, false);
	return r_reg_pack_access (reg, item, packidx, packbits, &val, true);
}

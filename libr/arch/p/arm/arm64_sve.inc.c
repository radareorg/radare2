/* radare2 - LGPL - Copyright 2026 - pancake */

static unsigned arm64_esil_sve_vl(REsil *esil) {
	REsilRegInterface *reg = &esil->reg_if;
	const unsigned vl = reg->reg_size? reg->reg_size (reg->reg, "z0"): 0;
	return vl >= 128 && vl <= 2048 && !(vl % 128)? vl: 0;
}

static bool arm64_sve_clear_upper(REsil *esil, unsigned reg) {
	const unsigned vl = arm64_esil_sve_vl (esil);
	unsigned chunk;
	for (chunk = 2; chunk < vl / 64; chunk++) {
		char name[16];
		snprintf (name, sizeof (name), "z%u[%u]", reg, chunk);
		if (!r_esil_reg_write (esil, name, 0)) {
			return false;
		}
	}
	return true;
}

static bool arm64_sve_clear(REsil *esil) {
	ut64 reg;
	RStrs arg = r_esil_pop (esil);
	return !r_strs_empty (arg) && r_esil_get_parm (esil, arg, &reg) && reg < 32
		&& arm64_sve_clear_upper (esil, reg);
}

static bool arm64_sve_unary(REsil *esil) {
	ut64 word;
	RStrs arg = r_esil_pop (esil);
	if (r_strs_empty (arg) || !r_esil_get_parm (esil, arg, &word) || word > UT32_MAX) {
		return false;
	}
	// Match the opcode independently of size, predication and registers.
	const ut32 opcode = word & 0xff2fe000;
	const bool integer = opcode == 0x0407a000;
	const bool absolute = opcode == 0x040ca000;
	if (!integer && !absolute && opcode != 0x040da000) {
		return false;
	}
	const unsigned bits = 8U << ((word >> 22) & 3);
	const unsigned vl = arm64_esil_sve_vl (esil);
	if ((!integer && bits == 8) || !vl) {
		return false;
	}
	const unsigned dst = word & 31;
	const unsigned src = (word >> 5) & 31;
	const unsigned pred = (word >> 10) & 7;
	const bool merging = word & (1U << 20);
	const ut64 mask = r_num_bitmask (bits);
	const ut64 sign = 1ULL << (bits - 1);
	const ut64 fraction = r_num_bitmask (bits == 16? 10: bits == 32? 23: 52);
	const ut64 exponent = mask & ~(sign | fraction);
	ut64 fpcr = 0;
	if (!integer && !r_esil_reg_read (esil, "fpcr", &fpcr, NULL)) {
		return false;
	}
	const bool alternative_fp = fpcr & 2;
	ut64 predicate = 0;
	unsigned chunk;
	for (chunk = 0; chunk < vl / 64; chunk++) {
		char name[16];
		if (!(chunk % 8)) {
			snprintf (name, sizeof (name), "p%u[%u]", pred, chunk / 8);
			if (!r_esil_reg_read (esil, name, &predicate, NULL)) {
				return false;
			}
		}
		const ut8 active = predicate >> (8 * (chunk % 8));
		if (merging && !active) {
			continue;
		}
		ut64 value = 0;
		if (active) {
			snprintf (name, sizeof (name), "z%u[%u]", src, chunk);
			if (!r_esil_reg_read (esil, name, &value, NULL)) {
				return false;
			}
		}
		snprintf (name, sizeof (name), "z%u[%u]", dst, chunk);
		ut64 old = value;
		if (merging && src != dst && !r_esil_reg_read (esil, name, &old, NULL)) {
			return false;
		}
		ut64 result = merging? old: 0;
		unsigned shift;
		for (shift = 0; shift < 64; shift += bits) {
			if (!(active & (1U << (shift / 8)))) {
				continue;
			}
			ut64 lane = (value >> shift) & mask;
			if (integer) {
				lane = (0 - lane) & mask;
			} else if (!(alternative_fp && (lane & exponent) == exponent && (lane & fraction))) {
				lane = absolute? lane & ~sign: lane ^ sign;
			}
			result = (result & ~(mask << shift)) | (lane << shift);
		}
		if ((!merging || result != old) && !r_esil_reg_write (esil, name, result)) {
			return false;
		}
	}
	return true;
}

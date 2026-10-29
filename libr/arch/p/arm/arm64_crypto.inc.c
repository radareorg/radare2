/* radare2 - LGPL - Copyright 2026 - pancake */

static ut32 arm64_ror32(ut32 value, unsigned shift) {
	return (value >> shift) | (value << (32 - shift));
}

static bool arm64_crypto_reg(REsil *esil, ut64 *reg) {
	RStrs arg = r_esil_pop (esil);
	return !r_strs_empty (arg) && r_esil_get_parm (esil, arg, reg) && *reg < 32;
}

static bool arm64_crypto_read(REsil *esil, ut64 reg, ut32 words[4]) {
	char name[16];
	ut64 low, high;
	snprintf (name, sizeof (name), "v%ul", (unsigned)reg);
	if (!r_esil_reg_read (esil, name, &low, NULL)) {
		return false;
	}
	snprintf (name, sizeof (name), "v%uh", (unsigned)reg);
	if (!r_esil_reg_read (esil, name, &high, NULL)) {
		return false;
	}
	words[0] = low;
	words[1] = low >> 32;
	words[2] = high;
	words[3] = high >> 32;
	return true;
}

static bool arm64_crypto_write(REsil *esil, ut64 reg, const ut32 words[4]) {
	char name[16];
	snprintf (name, sizeof (name), "v%ul", (unsigned)reg);
	if (!r_esil_reg_write (esil, name, words[0] | ((ut64)words[1] << 32))) {
		return false;
	}
	snprintf (name, sizeof (name), "v%uh", (unsigned)reg);
	return r_esil_reg_write (esil, name, words[2] | ((ut64)words[3] << 32));
}

static bool arm64_sha256su0(REsil *esil) {
	ut64 dst, src;
	ut32 d[4], n[4], result[4];
	if (!arm64_crypto_reg (esil, &dst) || !arm64_crypto_reg (esil, &src)
		|| !arm64_crypto_read (esil, dst, d) || !arm64_crypto_read (esil, src, n)) {
		return false;
	}
	unsigned i;
	for (i = 0; i < 4; i++) {
		ut32 word = i < 3? d[i + 1]: n[0];
		result[i] = d[i] + (arm64_ror32 (word, 7) ^ arm64_ror32 (word, 18) ^ (word >> 3));
	}
	return arm64_crypto_write (esil, dst, result);
}

static bool arm64_sha256su1(REsil *esil) {
	ut64 dst, src1, src2;
	ut32 d[4], n[4], m[4], result[4];
	if (!arm64_crypto_reg (esil, &dst) || !arm64_crypto_reg (esil, &src1) || !arm64_crypto_reg (esil, &src2)
		|| !arm64_crypto_read (esil, dst, d) || !arm64_crypto_read (esil, src1, n)
		|| !arm64_crypto_read (esil, src2, m)) {
		return false;
	}
	unsigned i;
	for (i = 0; i < 4; i++) {
		ut32 word = i < 2? m[i + 2]: result[i - 2];
		ut32 next = i < 3? n[i + 1]: m[0];
		result[i] = d[i] + next + (arm64_ror32 (word, 17) ^ arm64_ror32 (word, 19) ^ (word >> 10));
	}
	return arm64_crypto_write (esil, dst, result);
}

static bool arm64_sha256hash(REsil *esil, bool part2) {
	ut64 dst, src1, src2;
	ut32 abcd[4], efgh[4], wk[4];
	if (!arm64_crypto_reg (esil, &dst) || !arm64_crypto_reg (esil, &src1) || !arm64_crypto_reg (esil, &src2)
		|| !arm64_crypto_read (esil, part2? src1: dst, abcd)
		|| !arm64_crypto_read (esil, part2? dst: src1, efgh) || !arm64_crypto_read (esil, src2, wk)) {
		return false;
	}
	unsigned i;
	for (i = 0; i < 4; i++) {
		ut32 a = abcd[0], b = abcd[1], c = abcd[2], d = abcd[3];
		ut32 e = efgh[0], f = efgh[1], g = efgh[2], h = efgh[3];
		ut32 sigma0 = arm64_ror32 (a, 2) ^ arm64_ror32 (a, 13) ^ arm64_ror32 (a, 22);
		ut32 sigma1 = arm64_ror32 (e, 6) ^ arm64_ror32 (e, 11) ^ arm64_ror32 (e, 25);
		ut32 choice = (e & f) ^ (~e & g);
		ut32 majority = (a & b) ^ (a & c) ^ (b & c);
		ut32 t1 = h + sigma1 + choice + wk[i];
		abcd[0] = t1 + sigma0 + majority;
		abcd[1] = a;
		abcd[2] = b;
		abcd[3] = c;
		efgh[0] = d + t1;
		efgh[1] = e;
		efgh[2] = f;
		efgh[3] = g;
	}
	return arm64_crypto_write (esil, dst, part2? efgh: abcd);
}

static bool arm64_sha256h(REsil *esil) {
	return arm64_sha256hash (esil, false);
}

static bool arm64_sha256h2(REsil *esil) {
	return arm64_sha256hash (esil, true);
}

static bool esilcb(RArchSession *as, REsil *esil, RArchEsilAction action) {
	if (!esil) {
		return false;
	}
	switch (action) {
	case R_ARCH_ESIL_ACTION_INIT:
		if (as->config->bits != 64) {
			return true;
		}
		return r_esil_set_op (esil, "ARM64_SHA256SU0", arm64_sha256su0, 0, 2, R_ESIL_OP_TYPE_CUSTOM | R_ESIL_OP_TYPE_CRYPTO, NULL)
			&& r_esil_set_op (esil, "ARM64_SHA256SU1", arm64_sha256su1, 0, 3, R_ESIL_OP_TYPE_CUSTOM | R_ESIL_OP_TYPE_CRYPTO, NULL)
			&& r_esil_set_op (esil, "ARM64_SHA256H", arm64_sha256h, 0, 3, R_ESIL_OP_TYPE_CUSTOM | R_ESIL_OP_TYPE_CRYPTO, NULL)
			&& r_esil_set_op (esil, "ARM64_SHA256H2", arm64_sha256h2, 0, 3, R_ESIL_OP_TYPE_CUSTOM | R_ESIL_OP_TYPE_CRYPTO, NULL);
	case R_ARCH_ESIL_ACTION_FINI:
		r_esil_del_op (esil, "ARM64_SHA256SU0");
		r_esil_del_op (esil, "ARM64_SHA256SU1");
		r_esil_del_op (esil, "ARM64_SHA256H");
		r_esil_del_op (esil, "ARM64_SHA256H2");
		return true;
	default:
		return false;
	}
}

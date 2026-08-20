/* radare2 - LGPL - Copyright 2026 - pancake */

typedef enum {
	SM_50,
	SM_52,
	SM_53,
	SM_60,
	SM_61,
	SM_62,
	SM_70,
	SM_72,
	SM_75,
	SM_80,
	SM_86,
	SM_87,
	SM_89,
	SM_90,
	SM_100,
	SM_110,
} SmArch;

typedef struct {
	const char *name;
	int type;
	SmArch minarch;
} SassOpcode;

#define SASS_OP(name, type) { name, type, SM_50 }
#define SASS_OP_FROM(name, type, arch) { name, type, arch }

static const SassOpcode sass_opcodes[] = {
	[0x00] = SASS_OP ("nop", R_ANAL_OP_TYPE_NOP),
	[0x01] = SASS_OP ("iadd3", R_ANAL_OP_TYPE_ADD),
	[0x02] = SASS_OP ("isub", R_ANAL_OP_TYPE_SUB),
	[0x03] = SASS_OP ("lop3", R_ANAL_OP_TYPE_AND),
	[0x04] = SASS_OP ("lop2", R_ANAL_OP_TYPE_AND),
	[0x05] = SASS_OP ("and", R_ANAL_OP_TYPE_AND),
	[0x06] = SASS_OP ("or", R_ANAL_OP_TYPE_OR),
	[0x07] = SASS_OP ("xor", R_ANAL_OP_TYPE_XOR),
	[0x08] = SASS_OP ("imul32", R_ANAL_OP_TYPE_MUL),
	[0x09] = SASS_OP ("isad", R_ANAL_OP_TYPE_MUL),
	[0x0a] = SASS_OP ("shr", R_ANAL_OP_TYPE_SHR),
	[0x0b] = SASS_OP ("shl", R_ANAL_OP_TYPE_SHL),
	[0x0c] = SASS_OP ("bfe", R_ANAL_OP_TYPE_MOV),
	[0x0d] = SASS_OP ("bfi", R_ANAL_OP_TYPE_MOV),
	[0x0e] = SASS_OP ("brev", R_ANAL_OP_TYPE_MOV),
	[0x0f] = SASS_OP ("lopc", R_ANAL_OP_TYPE_MOV),
	[0x10] = SASS_OP ("fadd", R_ANAL_OP_TYPE_ADD),
	[0x11] = SASS_OP ("fmul", R_ANAL_OP_TYPE_MUL),
	[0x12] = SASS_OP ("ffma", R_ANAL_OP_TYPE_MUL),
	[0x13] = SASS_OP ("fsel", R_ANAL_OP_TYPE_CMOV),
	[0x14] = SASS_OP ("fmov", R_ANAL_OP_TYPE_MOV),
	[0x15] = SASS_OP ("mufu", R_ANAL_OP_TYPE_MOV),
	[0x16] = SASS_OP ("sel", R_ANAL_OP_TYPE_CMOV),
	[0x17] = SASS_OP ("setp", R_ANAL_OP_TYPE_CMP),
	[0x18] = SASS_OP ("set", R_ANAL_OP_TYPE_CMP),
	[0x19] = SASS_OP ("psetp", R_ANAL_OP_TYPE_CMP),
	[0x1a] = SASS_OP ("cset", R_ANAL_OP_TYPE_CMP),
	[0x1b] = SASS_OP ("csetp", R_ANAL_OP_TYPE_CMP),
	[0x1c] = SASS_OP ("popc", R_ANAL_OP_TYPE_MOV),
	[0x1d] = SASS_OP ("bfind", R_ANAL_OP_TYPE_MOV),
	[0x1f] = SASS_OP ("prmt", R_ANAL_OP_TYPE_MOV),
	[0x20] = SASS_OP ("ld", R_ANAL_OP_TYPE_LOAD),
	[0x21] = SASS_OP ("st", R_ANAL_OP_TYPE_STORE),
	[0x22] = SASS_OP ("ldg", R_ANAL_OP_TYPE_LOAD),
	[0x23] = SASS_OP ("stg", R_ANAL_OP_TYPE_STORE),
	[0x24] = SASS_OP ("lds", R_ANAL_OP_TYPE_LOAD),
	[0x25] = SASS_OP ("sts", R_ANAL_OP_TYPE_STORE),
	[0x26] = SASS_OP ("ldl", R_ANAL_OP_TYPE_LOAD),
	[0x27] = SASS_OP ("stl", R_ANAL_OP_TYPE_STORE),
	[0x28] = SASS_OP ("ldc", R_ANAL_OP_TYPE_LOAD),
	[0x29] = SASS_OP ("tex", R_ANAL_OP_TYPE_LOAD),
	[0x2a] = SASS_OP ("tld", R_ANAL_OP_TYPE_LOAD),
	[0x2b] = SASS_OP ("ldsm", R_ANAL_OP_TYPE_LOAD),
	[0x2c] = SASS_OP ("red", R_ANAL_OP_TYPE_STORE),
	[0x2d] = SASS_OP ("atom", R_ANAL_OP_TYPE_STORE),
	[0x2e] = SASS_OP ("atoms", R_ANAL_OP_TYPE_STORE),
	[0x2f] = SASS_OP ("cas", R_ANAL_OP_TYPE_STORE),
	[0x30] = SASS_OP ("bra", R_ANAL_OP_TYPE_JMP),
	[0x31] = SASS_OP ("jmp", R_ANAL_OP_TYPE_JMP),
	[0x32] = SASS_OP ("break", R_ANAL_OP_TYPE_TRAP),
	[0x33] = SASS_OP ("exit", R_ANAL_OP_TYPE_TRAP),
	[0x34] = SASS_OP ("call", R_ANAL_OP_TYPE_CALL),
	[0x35] = SASS_OP ("ret", R_ANAL_OP_TYPE_RET),
	[0x36] = SASS_OP ("ssy", R_ANAL_OP_TYPE_JMP),
	[0x37] = SASS_OP ("bssy", R_ANAL_OP_TYPE_JMP),
	[0x38] = SASS_OP ("sync", R_ANAL_OP_TYPE_SYNC),
	[0x39] = SASS_OP ("bsync", R_ANAL_OP_TYPE_SYNC),
	[0x3a] = SASS_OP ("bar", R_ANAL_OP_TYPE_SYNC),
	[0x40] = SASS_OP ("shfl", R_ANAL_OP_TYPE_MOV),
	[0x41] = SASS_OP ("vote", R_ANAL_OP_TYPE_CMP),
	[0x48] = SASS_OP ("s2r", R_ANAL_OP_TYPE_MOV),
	[0x49] = SASS_OP ("lea", R_ANAL_OP_TYPE_LEA),
	[0x4a] = SASS_OP ("isberd", R_ANAL_OP_TYPE_MOV),
	[0x4b] = SASS_OP ("delouter", R_ANAL_OP_TYPE_MOV),
	[0x50] = SASS_OP ("max", R_ANAL_OP_TYPE_MOV),
	[0x51] = SASS_OP ("min", R_ANAL_OP_TYPE_MOV),
	[0x58] = SASS_OP_FROM ("wgmma", R_ANAL_OP_TYPE_MUL, SM_90),
	[0x59] = SASS_OP_FROM ("bmma", R_ANAL_OP_TYPE_MUL, SM_90),
	[0x5a] = SASS_OP_FROM ("depbar", R_ANAL_OP_TYPE_SYNC, SM_90),
	[0x5b] = SASS_OP_FROM ("cp", R_ANAL_OP_TYPE_MOV, SM_90),
	[0x5c] = SASS_OP_FROM ("bulk", R_ANAL_OP_TYPE_MOV, SM_90),
	[0x5d] = SASS_OP_FROM ("isberd", R_ANAL_OP_TYPE_MOV, SM_90),
	[0x60] = SASS_OP_FROM ("ldtcls", R_ANAL_OP_TYPE_LOAD, SM_90),
	[0x61] = SASS_OP_FROM ("sttcsl", R_ANAL_OP_TYPE_STORE, SM_90),
	[0x68] = SASS_OP_FROM ("clause", R_ANAL_OP_TYPE_MOV, SM_110),
	[0x69] = SASS_OP_FROM ("griddepbar", R_ANAL_OP_TYPE_SYNC, SM_110),
	[0x6a] = SASS_OP_FROM ("dsm", R_ANAL_OP_TYPE_MOV, SM_110),
	[0x6b] = SASS_OP_FROM ("dsmr", R_ANAL_OP_TYPE_MOV, SM_110),
	[0x6c] = SASS_OP_FROM ("done", R_ANAL_OP_TYPE_TRAP, SM_110),
	[0x6d] = SASS_OP_FROM ("cpy", R_ANAL_OP_TYPE_MOV, SM_110),
	[0x6e] = SASS_OP_FROM ("tld4", R_ANAL_OP_TYPE_LOAD, SM_110),
	[0x70] = SASS_OP_FROM ("mma", R_ANAL_OP_TYPE_MUL, SM_110),
};

#undef SASS_OP
#undef SASS_OP_FROM

static SmArch parse_arch(const char *cpu) {
	static const char *const names[] = {
		"sm_50", "sm_52", "sm_53", "sm_60", "sm_61", "sm_62",
		"sm_70", "sm_72", "sm_75", "sm_80", "sm_86", "sm_87",
		"sm_89", "sm_90", "sm_100", "sm_110",
	};
	ut32 i;
	for (i = 0; i < R_ARRAY_SIZE (names); i++) {
		if (!strcmp (cpu, names[i])) {
			return (SmArch)i;
		}
	}
	return SM_86;
}

static const SassOpcode *opcode_for(SmArch arch, ut8 opcode) {
	const SassOpcode *entry = opcode < R_ARRAY_SIZE (sass_opcodes)? &sass_opcodes[opcode]: NULL;
	return entry && entry->name && arch >= entry->minarch? entry: NULL;
}

static int opcode_lookup(const char *name) {
	ut32 i;
	for (i = 0; i < R_ARRAY_SIZE (sass_opcodes); i++) {
		const SassOpcode *op = &sass_opcodes[i];
		if (op->name && !strcmp (op->name, name)) {
			return (int)i;
		}
	}
	return -1;
}

static int parse_reg(const char *s) {
	ut32 reg = 0;
	const char *p;
	if (!s || !*s) {
		return -1;
	}
	if (!strcmp (s, "rz")) {
		return UT8_MAX;
	}
	if (s[0] != 'r' || s[1] < '0' || s[1] > '9') {
		return -1;
	}
	for (p = s + 1; *p; p++) {
		if (*p < '0' || *p > '9') {
			return -1;
		}
		reg = reg * 10 + (*p - '0');
		if (reg >= UT8_MAX) {
			return -1;
		}
	}
	return reg;
}

static bool parse_uint(const char *s, ut64 max, ut64 *value) {
	const char *p = s;
	ut64 n = 0;
	int base = 10;
	if (!p || !*p) {
		return false;
	}
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
		base = 16;
		p += 2;
	}
	if (!*p) {
		return false;
	}
	for (; *p; p++) {
		int digit;
		if (*p >= '0' && *p <= '9') {
			digit = *p - '0';
		} else if (base == 16 && *p >= 'a' && *p <= 'f') {
			digit = *p - 'a' + 10;
		} else if (base == 16 && *p >= 'A' && *p <= 'F') {
			digit = *p - 'A' + 10;
		} else {
			return false;
		}
		if (digit >= base || (ut64)digit > max || n > (max - digit) / base) {
			return false;
		}
		n = n * base + digit;
	}
	*value = n;
	return true;
}

static int parse_special_reg(const char *s) {
	ut64 reg;
	if (!s || strncmp (s, "sr_", 3) || !parse_uint (s + 3, UT8_MAX, &reg)) {
		return -1;
	}
	return (int)reg;
}

static char *trim_token(char *s) {
	char *token = (char *)r_str_trim_head_ro (s);
	r_str_trim_tail (token);
	return token;
}

static void fmt_reg(char *buf, size_t size, ut8 reg) {
	if (reg == UT8_MAX) {
		r_str_ncpy (buf, "rz", size);
	} else {
		snprintf (buf, size, "r%u", reg);
	}
}

static void fmt_ureg(char *buf, size_t size, ut8 reg) {
	if (reg == UT8_MAX) {
		r_str_ncpy (buf, "urz", size);
	} else {
		snprintf (buf, size, "ur%u", reg);
	}
}

static char *regs(RArchSession *as) {
	RStrBuf *sb = r_strbuf_new ("");
	ut32 i;
	(void)as;
	r_strbuf_append (sb, "=PC\tpc\n=SP\tr1\n=BP\tr1\n=R0\tr0\n=A0\tr0\n=A1\tr1\n=A2\tr2\n=A3\tr3\n");
	r_strbuf_append (sb, "gpr\tpc\t.64\t0\t0\n");
	for (i = 0; i < UT8_MAX; i++) {
		r_strbuf_appendf (sb, "gpr\tr%u\t.32\t%u\t0\n", i, i * 4);
	}
	for (i = 0; i < 64; i++) {
		r_strbuf_appendf (sb, "gpr\tur%u\t.32\t%u\t0\n", i, 1024 + i * 4);
	}
	for (i = 0; i < 8; i++) {
		r_strbuf_appendf (sb, "gpr\tp%u\t.1\t%u\t0\n", i, 1280 + i);
	}
	r_strbuf_append (sb, "gpr\trz\t.32\t1288\t0\ngpr\turz\t.32\t1292\t0\ngpr\tpt\t.1\t1296\t0\n");
	return r_strbuf_drain (sb);
}

static bool decode_sm110(RAnalOp *op, RArchDecodeMask mask) {
	const ut8 *buf = op->bytes;
	const ut8 dst = buf[2];
	char rd[8];
	char ru[8];
	const char *mnemonic = NULL;
	if (!buf) {
		return false;
	}
	fmt_reg (rd, sizeof (rd), dst);
	op->type = R_ANAL_OP_TYPE_UNK;
	switch (buf[0]) {
	case 0x02:
		mnemonic = "mov";
		op->type = R_ANAL_OP_TYPE_MOV;
		op->mnemonic = r_str_newf ("mov %s, 0x%x", rd, r_read_le32 (buf + 4));
		break;
	case 0x0c:
		mnemonic = "isetp";
		op->type = R_ANAL_OP_TYPE_CMP;
		op->mnemonic = r_str_newf ("isetp.ne.u32.and p%u, pt, r%u, 0x%x, pt", dst, buf[3], buf[4]);
		break;
	case 0x10:
		mnemonic = "iadd3";
		op->type = R_ANAL_OP_TYPE_ADD;
		if (buf[1] == 0x7c) {
			op->mnemonic = r_str_newf ("iadd3 %s, p0, pt, r%u, ur%u, rz", rd, buf[3], buf[4]);
		} else {
			const st32 imm = (st32)r_read_le32 (buf + 4);
			const ut32 magnitude = imm < 0? 0U - (ut32)imm: (ut32)imm;
			op->mnemonic = r_str_newf ("iadd3 %s, pt, pt, r%u, %s0x%x, rz", rd, buf[3], imm < 0? "-": "", magnitude);
		}
		break;
	case 0x12:
		mnemonic = "lop3.lut";
		op->type = R_ANAL_OP_TYPE_AND;
		op->mnemonic = buf[1] == 0x72
			? r_str_newf ("lop3.lut %s, r%u, r%u, rz, 0x%x, !pt", rd, buf[3], buf[4], buf[9])
			: r_str_newf ("lop3.lut %s, r%u, 0x%x, rz, 0x%x, !pt", rd, buf[3], buf[4], buf[9]);
		break;
	case 0x18:
		mnemonic = "nop";
		op->type = R_ANAL_OP_TYPE_NOP;
		op->mnemonic = strdup (mnemonic);
		break;
	case 0x19:
		mnemonic = buf[1] == 0x79? "s2r": "shf";
		op->type = buf[1] == 0x79? R_ANAL_OP_TYPE_MOV: R_ANAL_OP_TYPE_SHL;
		op->mnemonic = buf[1] == 0x79
			? r_str_newf ("s2r %s, sr_tid.x", rd)
			: r_str_newf ("shf.l.u32 %s, r%u, 0x%x, rz", rd, buf[3], buf[4]);
		break;
	case 0x23:
		mnemonic = "ffma";
		op->type = R_ANAL_OP_TYPE_MUL;
		op->mnemonic = r_str_newf ("ffma %s, r%u, r%u, 0x%08x", rd, buf[3], buf[8], r_read_le32 (buf + 4));
		break;
	case 0x24:
		mnemonic = "imad";
		op->type = R_ANAL_OP_TYPE_MUL;
		if (buf[1] == 0x88) {
			op->mnemonic = r_str_newf ("imad %s, r%u, 0x%x, rz", rd, buf[3], buf[4]);
		} else {
			fmt_ureg (ru, sizeof (ru), buf[4]);
			op->mnemonic = r_str_newf ("imad%s %s, rz, rz, %s%s", (buf[15] & 2)? ".x": "", rd, ru, (buf[15] & 2)? ", p0": "");
		}
		break;
	case 0x25:
		mnemonic = "imad.wide.u32";
		op->type = R_ANAL_OP_TYPE_MUL;
		op->mnemonic = r_str_newf ("imad.wide.u32 %s, r%u, 0x%x, r%u", rd, buf[3], buf[4], buf[8]);
		break;
	case 0x31:
		mnemonic = "hfma2";
		op->type = R_ANAL_OP_TYPE_MUL;
		op->mnemonic = r_str_newf ("hfma2 %s, -rz, rz, 1.9375, 0", rd);
		break;
	case 0x43:
		mnemonic = "call";
		op->type = R_ANAL_OP_TYPE_CALL;
		op->mnemonic = r_str_newf ("call r%u", buf[3]);
		break;
	case 0x47:
		mnemonic = "bra";
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = op->addr;
		op->mnemonic = r_str_newf ("bra 0x%" PFMT64x, op->jump);
		break;
	case 0x4d:
		mnemonic = "exit";
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->mnemonic = strdup (mnemonic);
		break;
	case 0x4e:
		mnemonic = "lepc";
		op->type = R_ANAL_OP_TYPE_LEA;
		op->mnemonic = r_str_newf ("lepc %s", rd);
		break;
	case 0x81:
		mnemonic = "ldg";
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->mnemonic = r_str_newf ("ldg.e %s, desc[ur%u][r%u.64]", rd, buf[4], buf[3]);
		break;
	case 0x82:
		mnemonic = "ldc";
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->mnemonic = buf[7]
			? r_str_newf ("ldc.64 %s, c[0x4][r%u]", rd, buf[3])
			: r_str_newf ("ldc %s, c[0x0][0x%x]", rd, buf[5] << 2);
		break;
	case 0x86:
		mnemonic = "stg";
		op->type = R_ANAL_OP_TYPE_STORE;
		op->mnemonic = r_str_newf ("stg.e desc[ur%u][r%u.64], r%u", buf[8], buf[3], buf[4]);
		break;
	case 0x87:
		mnemonic = "stl";
		op->type = R_ANAL_OP_TYPE_STORE;
		op->mnemonic = r_str_newf ("stl [r%u], r%u", buf[3], buf[4]);
		break;
	case 0xac:
		mnemonic = "ldcu";
		op->type = R_ANAL_OP_TYPE_LOAD;
		fmt_ureg (ru, sizeof (ru), dst);
		op->mnemonic = r_str_newf ("ldcu%s %s, c[0x%x][0x%x]", buf[7]? ".64": "", ru, buf[7]? 4: 0, (buf[5] << 3) | ((buf[4] & 0x80)? 4: 0));
		break;
	default:
		return false;
	}
	if (!(mask & R_ARCH_OP_MASK_DISASM)) {
		free (op->mnemonic);
		op->mnemonic = NULL;
	}
	op->size = 16;
	return mnemonic != NULL;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut8 *buf;
	const SassOpcode *opcode;
	SmArch arch;
	char rd[8];
	char rs0[8];
	char rs1[8];
	char rs2[8];
	char predicate[8];
	if (!as || !as->config || !op) {
		return false;
	}
	buf = op->bytes;
	if (!buf || op->size < 16) {
		return false;
	}
	arch = parse_arch (r_str_get (as->config->cpu));
	if (arch >= SM_110 && decode_sm110 (op, mask)) {
		return true;
	}
	opcode = opcode_for (arch, buf[14]);
	op->size = 16;
	op->type = opcode? opcode->type: R_ANAL_OP_TYPE_UNK;
	if (!opcode || !(mask & R_ARCH_OP_MASK_DISASM)) {
		return true;
	}
	if (opcode->type == R_ANAL_OP_TYPE_CALL || opcode->type == R_ANAL_OP_TYPE_JMP) {
		op->jump = r_read_le16 (buf + 2);
		op->mnemonic = r_str_newf ("%s 0x%" PFMT64x, opcode->name, op->jump);
		return true;
	}
	if (opcode->type == R_ANAL_OP_TYPE_NOP || opcode->type == R_ANAL_OP_TYPE_RET || opcode->type == R_ANAL_OP_TYPE_TRAP) {
		op->mnemonic = strdup (opcode->name);
		return true;
	}
	fmt_reg (rd, sizeof (rd), buf[11]);
	fmt_reg (rs0, sizeof (rs0), buf[7]);
	fmt_reg (rs1, sizeof (rs1), buf[3]);
	fmt_reg (rs2, sizeof (rs2), buf[5]);
	if (opcode->type == R_ANAL_OP_TYPE_LOAD) {
		op->mnemonic = r_str_newf ("%s %s, [%s + %u]", opcode->name, rd, rs0, r_read_le32 (buf));
	} else if (opcode->type == R_ANAL_OP_TYPE_STORE) {
		op->mnemonic = r_str_newf ("%s [%s + %u], %s", opcode->name, rs0, r_read_le24 (buf), rs1);
	} else if (!strcmp (opcode->name, "s2r")) {
		op->mnemonic = r_str_newf ("s2r %s, sr_%u", rd, buf[7]);
	} else if ((buf[10] & 7) || (buf[10] & 8)) {
		snprintf (predicate, sizeof (predicate), "%sp%u", (buf[10] & 8)? "!": "", buf[10] & 7);
		op->mnemonic = r_str_newf ("@%s %s %s, %s, %s, %s", predicate, opcode->name, rd, rs0, rs1, rs2);
	} else {
		op->mnemonic = r_str_newf ("%s %s, %s, %s, %s", opcode->name, rd, rs0, rs1, rs2);
	}
	return true;
}

static bool encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	ut8 buf[16];
	const char *mnemonic;
	char *s, *p, *name;
	int opcode_byte;
	SmArch arch;
	if (!as || !as->config || !op || !op->mnemonic) {
		return false;
	}
	arch = parse_arch (r_str_get (as->config->cpu));
	mnemonic = op->mnemonic;
	memset (buf, 0, sizeof (buf));
	s = strdup (mnemonic);
	if (!s) {
		return false;
	}
	p = trim_token (s);
	// parse optional predicate prefix @pN or @!pN
	if (p[0] == '@') {
		p++;
		bool neg = false;
		if (p[0] == '!') {
			neg = true;
			p++;
		}
		if (p[0] != 'p' || p[1] < '0' || p[1] > '7' || p[2] != ' ') {
			free (s);
			return false;
		}
		buf[10] = p[1] - '0';
		if (neg) {
			buf[10] |= 8;
		}
		p = (char *)r_str_trim_head_ro (p + 2);
	}
	// extract opcode name
	name = p;
	char *space = strchr (p, ' ');
	if (space) {
		*space = '\0';
		p = space + 1;
	} else {
		p = "";
	}
	opcode_byte = opcode_lookup (name);
	if (opcode_byte < 0) {
		free (s);
		return false;
	}
	const SassOpcode *opcode = opcode_for (arch, opcode_byte);
	if (!opcode) {
		free (s);
		return false;
	}
	buf[14] = (ut8)opcode_byte;
	// handle simple mnemonics with no operands
	if (opcode->type == R_ANAL_OP_TYPE_NOP || opcode->type == R_ANAL_OP_TYPE_RET || opcode->type == R_ANAL_OP_TYPE_TRAP) {
		if (*p) {
			free (s);
			return false;
		}
		op->size = 16;
		r_anal_op_set_bytes (op, op->addr, buf, 16);
		free (s);
		return true;
	}
	// handle jmp/call: "bra 0x10" or "call 0x100"
	if (opcode->type == R_ANAL_OP_TYPE_JMP || opcode->type == R_ANAL_OP_TYPE_CALL) {
		ut64 addr;
		if (!parse_uint (trim_token (p), UT16_MAX, &addr)) {
			free (s);
			return false;
		}
		r_write_le16 (buf + 2, (ut16)addr);
		op->size = 16;
		r_anal_op_set_bytes (op, op->addr, buf, 16);
		free (s);
		return true;
	}
	// handle load: "ld r0, [r1 + 8]"
	if (opcode->type == R_ANAL_OP_TYPE_LOAD) {
		char *comma = strchr (p, ',');
		if (!comma) {
			free (s);
			return false;
		}
		*comma = '\0';
		int rd = parse_reg (trim_token (p));
		char *address = trim_token (comma + 1);
		size_t address_len = strlen (address);
		if (rd < 0 || address_len < 3 || address[0] != '[' || address[address_len - 1] != ']') {
			free (s);
			return false;
		}
		address[address_len - 1] = '\0';
		address = trim_token (address + 1);
		char *plus = strchr (address, '+');
		ut64 offset = 0;
		if (plus) {
			*plus = '\0';
			if (!parse_uint (trim_token (plus + 1), UT32_MAX, &offset)) {
				free (s);
				return false;
			}
		}
		int rs0 = parse_reg (trim_token (address));
		if (rs0 < 0) {
			free (s);
			return false;
		}
		buf[11] = (ut8)rd;
		buf[7] = (ut8)rs0;
		r_write_le32 (buf, (ut32)offset);
		op->size = 16;
		r_anal_op_set_bytes (op, op->addr, buf, 16);
		free (s);
		return true;
	}
	// handle store: "st [r0 + 8], r1"
	if (opcode->type == R_ANAL_OP_TYPE_STORE) {
		p = trim_token (p);
		char *end = strchr (p, ']');
		if (p[0] != '[' || !end) {
			free (s);
			return false;
		}
		char *rest = trim_token (end + 1);
		if (rest[0] != ',') {
			free (s);
			return false;
		}
		int rs1 = parse_reg (trim_token (rest + 1));
		if (rs1 < 0) {
			free (s);
			return false;
		}
		*end = '\0';
		char *address = trim_token (p + 1);
		char *plus = strchr (address, '+');
		ut64 offset = 0;
		if (plus) {
			*plus = '\0';
			if (!parse_uint (trim_token (plus + 1), UT24_MAX, &offset)) {
				free (s);
				return false;
			}
		}
		int rs0 = parse_reg (trim_token (address));
		if (rs0 < 0) {
			free (s);
			return false;
		}
		r_write_le24 (buf, (ut32)offset);
		buf[3] = (ut8)rs1;
		buf[7] = (ut8)rs0;
		op->size = 16;
		r_anal_op_set_bytes (op, op->addr, buf, 16);
		free (s);
		return true;
	}
	// handle s2r: "s2r r0, sr_1"
	if (!strcmp (name, "s2r")) {
		char *comma = strchr (p, ',');
		if (!comma) {
			free (s);
			return false;
		}
		*comma = '\0';
		int rd = parse_reg (trim_token (p));
		int sr = parse_special_reg (trim_token (comma + 1));
		if (rd < 0 || sr < 0) {
			free (s);
			return false;
		}
		buf[11] = (ut8)rd;
		buf[7] = (ut8)sr;
		op->size = 16;
		r_anal_op_set_bytes (op, op->addr, buf, 16);
		free (s);
		return true;
	}
	// generic ALU: "iadd3 rd, rs0, rs1, rs2"
	int regs[4];
	int i;
	for (i = 0; i < 2; i++) {
		char *comma = strchr (p, ',');
		if (!comma) {
			free (s);
			return false;
		}
		*comma = '\0';
		regs[i] = parse_reg (trim_token (p));
		p = comma + 1;
	}
	char *comma = strchr (p, ',');
	int nregs = 3;
	if (comma) {
		*comma = '\0';
		regs[2] = parse_reg (trim_token (p));
		p = comma + 1;
		regs[3] = parse_reg (trim_token (p));
		nregs = 4;
	} else {
		regs[2] = parse_reg (trim_token (p));
		regs[3] = 0;
	}
	if (strchr (p, ',')) {
		free (s);
		return false;
	}
	for (i = 0; i < nregs; i++) {
		if (regs[i] < 0) {
			free (s);
			return false;
		}
	}
	buf[11] = (ut8)regs[0];
	buf[7] = (ut8)regs[1];
	buf[3] = (ut8)regs[2];
	buf[5] = (ut8)regs[3];
	op->size = 16;
	r_anal_op_set_bytes (op, op->addr, buf, 16);
	free (s);
	return true;
}

#define PARSE_REG(_tok, _out) do { \
	int __v = -1; \
	if ((_tok) && (((_tok)[0]|32) == 'r')) { __v = atoi ((_tok) + 1); } \
	PARSE_NEED (__v >= 0 && __v <= 10); \
	_out = __v; \
} while (0)
#define EMIT(_opc,_dst,_src,_off,_imm) do { \
	out[0] = (_opc); \
	out[1] = (((_src)&0x0f) << 4) | ((_dst)&0x0f); \
	r_write_le16 (out + 2, (st16)(_off)); \
	r_write_le32 (out + 4, (ut32)(_imm)); \
	*outlen = 8; \
	return true; \
} while (0)
// ALU64 ops (imm/reg)
#define ALU64(_opk,_opx) do { \
	PARSE_NEED (opc == 3); \
	PARSE_REG (op[0], rd); \
	PARSE_STR (op[1], ","); \
	if (((op[2][0]|32) == 'r')) { PARSE_REG (op[2], rs); EMIT ((_opx), rd, rs, 0, 0); } \
	else { immv = strtoul (op[2], NULL, 0); EMIT ((_opk), rd, 0, 0, immv); } \
} while (0)
// 32-bit ALU common
#define ALU32(_opk,_opx) do { \
	PARSE_NEED (opc == 3); \
	PARSE_REG (op[0], rd); \
	PARSE_STR (op[1], ","); \
	if (((op[2][0]|32) == 'r')) { PARSE_REG (op[2], rs); EMIT ((_opx), rd, rs, 0, 0); } \
	else { immv = strtoul (op[2], NULL, 0); EMIT ((_opk), rd, 0, 0, immv); } \
} while (0)
#define JCC(_opk,_opx) do { \
	PARSE_NEED (opc == 5); \
	PARSE_REG (op[0], rd); \
	PARSE_STR (op[1], ","); \
	if (((op[2][0]|32) == 'r')) { PARSE_REG (op[2], rs); } else { rs = -1; } \
	PARSE_STR (op[3], ","); \
	offv = (st32)strtol (op[4], NULL, 0); \
	if (rs >= 0) { EMIT ((_opx), rd, rs, offv, 0); } \
	immv = strtoul (op[2], NULL, 0); \
	EMIT ((_opk), rd, 0, offv, immv); \
} while (0)

static inline bool parse_instruction(RBpfSockFilter *f, BPFAsmParser *p, ut64 pc, RBpfDialect dialect, ut8 *out, int *outlen) {
	const char *mnemonic_tok = token_next (p);
	PARSE_NEED_TOKEN (mnemonic_tok);
	int mlen = r_str_nlen (mnemonic_tok, 8);
	if (mlen < 2 || mlen > 7) {
		R_LOG_ERROR ("invalid mnemonic");
	}

	char mnemonic[8] = {0};
	strncpy (mnemonic, mnemonic_tok, 7);

	int opc;
	bpf_token op[11] = {0};
	if (dialect != R_BPF_DIALECT_EXTENDED) {
		for (opc = 0; opc < (int)(sizeof (op) / sizeof (op[0]));) {
			const char *t = token_next (p);
			if (t == NULL) {
				break;
			}
			strncpy (op[opc++], t, TOKEN_MAX_LEN);
		}
	} else {
		opc = 0;
	}

	if (dialect == R_BPF_DIALECT_EXTENDED) {
		// eBPF assembler fast-path for common instructions
		// Encoding: out[0]=opcode, out[1]=(src<<4)|dst, out[2..3]=off(le16), out[4..7]=imm(le32)
		int opc = 0;
		bpf_token op[12] = {0};
		for (opc = 0; opc < (int)(sizeof (op) / sizeof (op[0])); opc++) {
			const char *t = token_next (p);
			if (!t) break;
			strncpy (op[opc], t, TOKEN_MAX_LEN);
		}
		// helpers
		int rd, rs; st32 offv; ut32 immv;

		// exit
		if (TOKEN_EQ (mnemonic, "exit")) {
			PARSE_NEED (opc == 0);
			EMIT (0x95, 0, 0, 0, 0);
		}
		// call imm
		if (TOKEN_EQ (mnemonic, "call")) {
			PARSE_NEED (opc == 1);
			immv = strtoul (op[0], NULL, 0);
			EMIT (0x85, 0, 0, 0, immv);
		}
		// ja/jmp +off
		if (TOKEN_EQ (mnemonic, "ja") || TOKEN_EQ (mnemonic, "jmp")) {
			PARSE_NEED (opc == 1);
			offv = (st32)strtol (op[0], NULL, 0);
			EMIT (0x05, 0, 0, offv, 0);
		}
		// mov64 rd, rs|imm
		if (TOKEN_EQ (mnemonic, "mov64") || TOKEN_EQ (mnemonic, "mov")) {
			PARSE_NEED (opc == 3);
			PARSE_REG (op[0], rd);
			PARSE_STR (op[1], ",");
			if ((((op[2][0]|32) == 'r'))) {
				PARSE_REG (op[2], rs);
				EMIT (0xbf, rd, rs, 0, 0);
			} else {
				immv = strtoul (op[2], NULL, 0);
				EMIT (0xb7, rd, 0, 0, immv);
			}
		}
		if (TOKEN_EQ (mnemonic, "add64")) { ALU64 (0x07, 0x0f); }
		if (TOKEN_EQ (mnemonic, "sub64")) { ALU64 (0x17, 0x1f); }
		if (TOKEN_EQ (mnemonic, "mul64")) { ALU64 (0x27, 0x2f); }
		if (TOKEN_EQ (mnemonic, "div64")) { ALU64 (0x37, 0x3f); }
		if (TOKEN_EQ (mnemonic, "or64")) { ALU64 (0x47, 0x4f); }
		if (TOKEN_EQ (mnemonic, "and64")) { ALU64 (0x57, 0x5f); }
		if (TOKEN_EQ (mnemonic, "lsh64")) { ALU64 (0x67, 0x6f); }
		if (TOKEN_EQ (mnemonic, "rsh64")) { ALU64 (0x77, 0x7f); }
		if (TOKEN_EQ (mnemonic, "xor64")) { ALU64 (0xa7, 0xaf); }
		if (TOKEN_EQ (mnemonic, "mod64")) { ALU64 (0x97, 0x9f); }
		if (TOKEN_EQ (mnemonic, "add")) {
			if (opc == 1) { immv = strtoul (op[0], NULL, 0); EMIT (0x04, 0, 0, 0, immv); }
			ALU32 (0x04, 0x0c);
		}
		if (TOKEN_EQ (mnemonic, "sub")) { ALU32 (0x14, 0x1c); }
		if (TOKEN_EQ (mnemonic, "mul")) { ALU32 (0x24, 0x2c); }
		if (TOKEN_EQ (mnemonic, "div")) { ALU32 (0x34, 0x3c); }
		if (TOKEN_EQ (mnemonic, "or"))  { ALU32 (0x44, 0x4c); }
		if (TOKEN_EQ (mnemonic, "and")) { ALU32 (0x54, 0x5c); }
		if (TOKEN_EQ (mnemonic, "lsh")) { ALU32 (0x64, 0x6c); }
		if (TOKEN_EQ (mnemonic, "rsh")) { ALU32 (0x74, 0x7c); }
		if (TOKEN_EQ (mnemonic, "xor")) { ALU32 (0xa4, 0xac); }
		if (TOKEN_EQ (mnemonic, "mod")) { ALU32 (0x94, 0x9c); }
		// neg/neg64
		if (TOKEN_EQ (mnemonic, "neg64") || TOKEN_EQ (mnemonic, "neg")) {
			PARSE_NEED (opc == 1);
			PARSE_REG (op[0], rd);
			EMIT (TOKEN_EQ (mnemonic, "neg64") ? 0x87 : 0x84, rd, 0, 0, 0);
		}
		// loads: ldx[b|h|w] rd, [rs+off]
		if (TOKEN_EQ (mnemonic, "ldxb") || TOKEN_EQ (mnemonic, "ldxh") || TOKEN_EQ (mnemonic, "ldxw")) {
			ut8 base = TOKEN_EQ (mnemonic, "ldxb")? 0x71: TOKEN_EQ (mnemonic, "ldxh")? 0x69: 0x61;
			PARSE_NEED (opc >= 5);
			PARSE_REG (op[0], rd);
			PARSE_STR (op[1], ","); PARSE_STR (op[2], "[");
			PARSE_REG (op[3], rs);
			offv = 0;
			if (opc >= 6 && (op[4][0] == '+' || op[4][0] == '-')) {
				offv = (st32)strtol (op[4], NULL, 0);
				PARSE_STR (op[5], "]");
			} else {
				PARSE_STR (op[4], "]");
			}
			EMIT (base, rd, rs, offv, 0);
		}
		// stores: stx[b|h|w] [rs+off], rd
		if (TOKEN_EQ (mnemonic, "stxb") || TOKEN_EQ (mnemonic, "stxh") || TOKEN_EQ (mnemonic, "stxw")) {
			ut8 base = TOKEN_EQ (mnemonic, "stxb")? 0x73: TOKEN_EQ (mnemonic, "stxh")? 0x6b: 0x63;
			PARSE_NEED (opc >= 5);
			PARSE_STR (op[0], "[");
			PARSE_REG (op[1], rs);
			offv = 0; int idx = 2;
			if (opc >= 6 && (op[2][0] == '+' || op[2][0] == '-')) { offv = (st32)strtol (op[2], NULL, 0); idx = 3; }
			PARSE_STR (op[idx++], "]");
			PARSE_STR (op[idx++], ",");
			PARSE_REG (op[idx], rd);
			EMIT (base, rs, rd, offv, 0);
		}
		// atomics: xaddw [rs+off], rd
		if (TOKEN_EQ (mnemonic, "xaddw")) {
			PARSE_NEED (opc >= 5);
			PARSE_STR (op[0], "[");
			PARSE_REG (op[1], rs);
			offv = 0; int idx = 2;
			if (opc >= 6 && (op[2][0] == '+' || op[2][0] == '-')) { offv = (st32)strtol (op[2], NULL, 0); idx = 3; }
			PARSE_STR (op[idx++], "]");
			PARSE_STR (op[idx++], ",");
			PARSE_REG (op[idx], rd);
			EMIT (0xc3, rs, rd, offv, 0);
		}
		// conditionals: jeq/jne/jgt/jge ... with reg or imm
		if (TOKEN_EQ (mnemonic, "jeq")) { JCC (0x15, 0x1d); }
		if (TOKEN_EQ (mnemonic, "jne")) { JCC (0x55, 0x5d); }
		if (TOKEN_EQ (mnemonic, "jgt")) { JCC (0x25, 0x2d); }
		if (TOKEN_EQ (mnemonic, "jge")) { JCC (0x35, 0x3d); }
		if (TOKEN_EQ (mnemonic, "jset")) { JCC (0x45, 0x4d); }
		if (TOKEN_EQ (mnemonic, "jlt")) { JCC (0xa5, 0xad); }
		if (TOKEN_EQ (mnemonic, "jle")) { JCC (0xb5, 0xbd); }
		if (TOKEN_EQ (mnemonic, "jsgt")) { JCC (0x65, 0x6d); }
		if (TOKEN_EQ (mnemonic, "jsge")) { JCC (0x75, 0x7d); }
		if (TOKEN_EQ (mnemonic, "jslt")) { JCC (0xc5, 0xcd); }
		if (TOKEN_EQ (mnemonic, "jsle")) { JCC (0xd5, 0xdd); }

		return false;
	}

	if (TOKEN_EQ (mnemonic, "txa")) {
		f->code = BPF_MISC_TXA;
		return true;
	}
	if (TOKEN_EQ (mnemonic, "tax")) {
		f->code = BPF_MISC_TAX;
		return true;
	}

	if (TOKEN_EQ (mnemonic, "ret")) {
		f->code = BPF_RET;
		PARSE_NEED (opc == 1);
		if (is_k_tok (op[0])) {
			f->code |= BPF_K;
			return parse_k (f, op[0]);
		} else if (TOKEN_EQ (op[0], "x")) {
			f->code |= BPF_X;
			return true;
		} else if (TOKEN_EQ (op[0], "a")) {
			f->code |= BPF_A;
			return true;
		} else {
			return false;
		}
	}

	if (strncmp (mnemonic, "ld", 2) == 0) {
		return parse_ld (f, mnemonic, opc, op);
	}

	if (strncmp (mnemonic, "st", 2) == 0) {
		switch (mnemonic[2]) {
			case '\0': f->code = BPF_ST; break;
			case 'x': f->code = BPF_STX; break;
			default: return false;
		}
		// Expect: M[<k>]
		PARSE_NEED (opc == 4);
		PARSE_NEED (TOKEN_EQ (op[0], "M") || TOKEN_EQ (op[0], "m"));
		PARSE_STR (op[1], "[");
		PARSE_NEED (parse_k (f, op[2]));
		PARSE_STR (op[3], "]");
		return true;
	}

	if (mnemonic[0] == 'j') {
		return parse_j (f, mnemonic, opc, op, pc);
	}

	return parse_alu (f, mnemonic, opc, op);
}

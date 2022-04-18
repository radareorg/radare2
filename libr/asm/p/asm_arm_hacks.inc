static char *hack_handle_dp_imm(ut32 insn) {
	char *buf_asm = NULL;
	char *mnemonic = NULL;
	const ut8 op0 = (insn >> 23) & 0x7;

	// Add/subtract (immediate, with tags)
	if (op0 == 3) {
		const bool sf = (insn >> 31) & 0x1;
		const bool op = (insn >> 30) & 0x1;
		const bool S = (insn >> 29) & 0x1;
		const bool o2 = (insn >> 22) & 0x1;
		if (sf && !S && !o2) {
			if (op) {
				mnemonic = "subg";
			} else {
				mnemonic = "addg";
			}
		}
		if (mnemonic) {
			const ut8 uimm6 = ((insn >> 16) & 0x3f) << 4;
			const ut8 uimm4 = (insn >> 10) & 0xf;
			const ut8 Xn = (insn >> 5) & 0x1f;
			const ut8 Xd = (insn >> 0) & 0x1f;
			buf_asm = r_str_newf ("%s x%d, x%d, #0x%x, #0x%x",
				mnemonic, Xd, Xn, uimm6, uimm4);
			buf_asm = r_str_replace (buf_asm, "x31", "sp", 1);
			return buf_asm;
		}
	}
	return NULL;
}

static char *hack_handle_br_exc_sys(ut32 insn) {
	char *buf_asm = NULL;
	const char *mnemonic = "bti";
	const ut8 op0 = (insn >> 29) & 0x7;
	const ut16 op1 = (insn >> 12) & 0x3fff;
	ut8 op2 = insn & 0x1f;

	// Hints
	if (op0 == 6 && op1 == 4146 && op2 == 31) {
		const ut8 CRm = (insn >> 8) & 0xf;
		op2 = (insn >> 5) & 0x7;
		if (CRm == 4 && (op2 & 1) == 0) {
			switch (op2) {
			case 0:
				buf_asm = r_str_newf ("%s", mnemonic);
				break;
			case 2:
				buf_asm = r_str_newf ("%s c", mnemonic);
				break;
			case 4:
				buf_asm = r_str_newf ("%s j", mnemonic);
				break;
			case 6:
				buf_asm = r_str_newf ("%s jc", mnemonic);
				break;
			}
		}
	}
	return buf_asm;
}

static char *hack_handle_dp_reg(ut32 insn) {
	char *buf_asm = NULL;
	char *mnemonic = NULL;
	const bool op0 = (insn >> 30) & 0x1;
	const bool op1 = (insn >> 28) & 0x1;
	const ut8 op2 = (insn >> 21) & 0xf;

	// Data-processing (2 source)
	if (!op0 && op1 && op2 == 6) {
		const bool sf = (insn >> 31) & 0x1;
		const bool S = (insn >> 29) & 0x1;
		const ut8 opcode = (insn >> 10) & 0x1f;
		if (sf) {
			if (!S) {
				if (opcode == 4) {
					mnemonic = "irg";
				} else if (opcode == 0) {
					mnemonic = "subp";
				} else if (opcode == 5) {
					mnemonic = "gmi";
				}
			} else if (S && opcode == 0) {
				mnemonic = "subps";
			}
		}
		if (mnemonic) {
			const ut8 Xm = (insn >> 16) & 0x1f;
			const ut8 Xn = (insn >> 5) & 0x1f;
			const ut8 Xd = (insn >> 0) & 0x1f;
			if (Xm == 31 && !strcmp (mnemonic, "irg")) {
				// Xm is xzr, discard it
				buf_asm = r_str_newf ("%s x%d, x%d", mnemonic, Xd, Xn);
			} else if (!strcmp (mnemonic, "subps") && S == 1 && Xd == 0x1f) {
				// ccmp is an alias for subps when S == '1' && Xd == '11111'
				buf_asm = r_str_newf ("cmpp x%d, x%d", Xn, Xm);
			} else {
				buf_asm = r_str_newf ("%s x%d, x%d, x%d", mnemonic, Xd, Xn, Xm);
			}
			buf_asm = r_str_replace (buf_asm, "x31", "sp", 1);
			return buf_asm;
		}
	}
	return NULL;
}

static char *hack_handle_ldst(ut32 insn) {
	char *buf_asm = NULL;
	char *mnemonic = NULL;
	bool ignore_imm9 = false;
	const ut8 op0 = (insn >> 28) & 0xf;
	const bool op1 = (insn >> 26) & 0x1;
	ut8 op2 = (insn >> 23) & 0x3;
	const bool op3 = (insn >> 21) & 0x1;

	// Load/store memory tags
	if (op0 == 13 && !op1 && (op2 == 2 || op2 == 3) && op3) {
		const ut8 opc = (insn >> 22) & 0x3;
		const ut16 imm9 = ((insn >> 12) & 0x1ff) << 4;
		op2 = (insn >> 10) & 0x3;
		const ut8 Xn = (insn >> 5) & 0x1f;
		const ut8 Xt = (insn >> 0) & 0x1f;

		if (op2 > 0) {
			switch (opc) {
			case 0:
				mnemonic = "stg";
				break;
			case 1:
				mnemonic = "stzg";
				break;
			case 2:
				mnemonic = "st2g";
				break;
			case 3:
				mnemonic = "stz2g";
				break;
			}

			switch (op2) {
			case 1:
				buf_asm = r_str_newf ("%s x%d, [x%d], #0x%x",
					mnemonic, Xt, Xn, imm9);
				break;
			case 2:
				buf_asm = r_str_newf ("%s x%d, [x%d, #0x%x]",
					mnemonic, Xt, Xn, imm9);
				break;
			case 3:
				buf_asm = r_str_newf ("%s x%d, [x%d, #0x%x]!",
					mnemonic, Xt, Xn, imm9);
				break;
			}
			buf_asm = r_str_replace (buf_asm, "x31", "sp", 1);
			return buf_asm;
		} else if (op2 == 0) {
			switch (opc) {
			case 0:
				mnemonic = "stzgm";
				ignore_imm9 = true;
				break;
			case 1:
				mnemonic = "ldg";
				break;
			case 2:
				mnemonic = "stgm";
				ignore_imm9 = true;
				break;
			case 3:
				mnemonic = "ldgm";
				ignore_imm9 = true;
				break;
			}
			if (ignore_imm9) {
				buf_asm = r_str_newf ("%s x%d, [x%d]",
					mnemonic, Xt, Xn);
			} else {
				buf_asm = r_str_newf ("%s x%d, [x%d, #0x%x]",
					mnemonic, Xt, Xn, imm9);
			}
			buf_asm = r_str_replace (buf_asm, "x31", "sp", 1);
			return buf_asm;
		}
	// Load/store register pair
	} else if ((op0 & 0x3) == 2) {
		const ut8 opc = (insn >> 30) & 0x3;
		const bool V = (insn >> 26) & 0x1;
		const bool L = (insn >> 22) & 0x1;

		if (opc == 1 && !V && !L) {
			const ut8 imm7 = ((insn >> 15) & 0x7f) << 4;
			const ut8 Xt2 = (insn >> 10) & 0x1f;
			const ut8 Xn = (insn >> 5) & 0x1f;
			const ut8 Xt = (insn >> 0) & 0x1f;
			switch (op2) {
			case 1:
				buf_asm = r_str_newf ("stgp x%d, x%d, [x%d], #0x%x",
					Xt, Xt2, Xn, imm7);
				break;
			case 2:
				buf_asm = r_str_newf ("stgp x%d, x%d, [x%d, #0x%x]",
					Xt, Xt2, Xn, imm7);
				break;
			case 3:
				buf_asm = r_str_newf ("stgp x%d, x%d, [x%d, #0x%x]!",
					Xt, Xt2, Xn, imm7);
				break;
			default:
				return NULL;
			}
			buf_asm = r_str_replace (buf_asm, "x31", "sp", 1);
			return buf_asm;
		}
	}
	return NULL;
}

static int hackyArmAsm(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char *buf_asm = NULL;
    // Hacky support for ARMv8.5
	if (a->config->bits == 64 && len >= 4) {
		ut32 insn = r_read_ble32 (buf, a->config->big_endian);
		int insn_class = (insn >> 25) & 0xf;
		switch (insn_class) {
		// Data Processing -- Register
		case 5:
		case 13:
			// irg, subp, gmi, subps
			buf_asm = hack_handle_dp_reg (insn);
			break;
		// Data Processing -- Immediate
		case 8:
		case 9:
			// addg, subg
			buf_asm = hack_handle_dp_imm (insn);
			break;
		// Branches, Exception generating, and System instructions
		case 10:
		case 11:
			// bti
			buf_asm = hack_handle_br_exc_sys (insn);
			break;
		// Loads and Stores
		case 4:
		case 6:
		case 12:
		case 14:
			// stg, stzgm, ldg, stzg, st2g, stgm, stz2g, ldgm, stgp
			buf_asm = hack_handle_ldst (insn);
			break;
		default:
			break;
		}

		if (buf_asm) {
			if (!a->immdisp) {
				r_str_replace_char (buf_asm, '#', 0);
			}
			r_strbuf_set (&op->buf_asm, buf_asm);
			free (buf_asm);
			return op->size = 4;
		}
	}
	return -1;
}

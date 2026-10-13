#include "r_anal.h"

static const char *reg_list[] = {
	"x0", "x1", "x2", "x3", "x4",
	"x5", "x6", "x7", "x8", "x9",
	"x10", "x11", "x12", "x13", "x14",
	"x15", "x16", "x17", "x18", "x19",
	"x20", "x21", "x22", "x23", "x24",
	"x25", "x26", "x27", "x28", "x29",
	"x30"
};

#if CS_API_MAJOR < 6
static void hack_cpa_values(RAnalOp *op, const char *const *regs, int count, int shift, bool accumulate, RAnalOpMask mask) {
	if (mask & R_ARCH_OP_MASK_VAL) {
		RArchValue value = { .type = R_ANAL_VAL_REG, .reg = regs[0], .access = R_PERM_W };
		RVecRArchValue_push_back (&op->dsts, &value);
		value.access = R_PERM_R;
		int i;
		for (i = accumulate? 0: 1; i < count; i++) {
			value.reg = regs[i];
			value.mul = i == 2? 1 << shift: 1;
			RVecRArchValue_push_back (&op->srcs, &value);
		}
	}
	if (mask & R_ARCH_OP_MASK_OPEX) {
		PJ *pj = pj_new ();
		if (pj) {
			pj_o (pj);
			pj_ka (pj, "operands");
			int i;
			for (i = 0; i < count; i++) {
				pj_o (pj);
				pj_ks (pj, "type", "reg");
				pj_ks (pj, "value", regs[i]);
				if (i == 2 && shift) {
					pj_ko (pj, "shift");
					pj_ks (pj, "type", "lsl");
					pj_ki (pj, "value", shift);
					pj_end (pj);
				}
				pj_end (pj);
			}
			pj_end (pj);
			pj_end (pj);
			r_strbuf_set (&op->opex, pj_string (pj));
			pj_free (pj);
		}
	}
}

static bool hack_decode_sve_cpa(RAnalOp *op, ut32 insn, RAnalOpMask mask) {
	static const char *const vector_regs[] = {
		"z0", "z1", "z2", "z3", "z4", "z5", "z6", "z7",
		"z8", "z9", "z10", "z11", "z12", "z13", "z14", "z15",
		"z16", "z17", "z18", "z19", "z20", "z21", "z22", "z23",
		"z24", "z25", "z26", "z27", "z28", "z29", "z30", "z31"
	};
	static const char *const predicate_regs[] = { "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7" };
	bool predicated = false;
	bool accumulate = false;
	const char *mnemonic;
	if ((insn & 0xffe0f800) == 0x04e00800) {
		mnemonic = (insn & 0x400)? "subpt": "addpt";
	} else if ((insn & 0xfffee000) == 0x04c40000) {
		predicated = true;
		mnemonic = (insn & 0x10000)? "subpt": "addpt";
	} else if ((insn & 0xffe0f400) == 0x44c0d000) {
		accumulate = true;
		mnemonic = (insn & 0x800)? "madpt": "mlapt";
	} else {
		return false;
	}
	const char *regs[] = {
		vector_regs[insn & 31],
		vector_regs[(insn >> 5) & 31],
		vector_regs[(insn >> 16) & 31],
		NULL
	};
	int count = 3;
	if (predicated) {
		regs[3] = regs[1];
		regs[2] = regs[0];
		regs[1] = predicate_regs[(insn >> 10) & 7];
		count = 4;
	} else if (accumulate && (insn & 0x800)) {
		const char *addend = regs[1];
		regs[1] = regs[2];
		regs[2] = addend;
	}
	op->size = 4;
	op->cycles = 1;
	op->family = R_ANAL_OP_FAMILY_VEC;
	op->type = !strcmp (mnemonic, "subpt")? R_ANAL_OP_TYPE_SUB: R_ANAL_OP_TYPE_ADD;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		free (op->mnemonic);
		if (predicated) {
			op->mnemonic = r_str_newf ("%s %s.d, %s/m, %s.d, %s.d", mnemonic, regs[0], regs[1], regs[2], regs[3]);
		} else {
			op->mnemonic = r_str_newf ("%s %s.d, %s.d, %s.d", mnemonic, regs[0], regs[1], regs[2]);
		}
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		// Scalable lanes and predicates are not represented by the register profile.
		r_strbuf_set (&op->esil, "");
	}
	hack_cpa_values (op, regs, count, 0, accumulate, mask);
	return true;
}

static bool hack_decode_cpa(RAnalOp *op, ut32 insn, RAnalOpMask mask) {
	const bool multiply = (insn & 0xffe00000) == 0x9b600000;
	if (!multiply && (insn & 0xbfe0e000) != 0x9a002000) {
		return hack_decode_sve_cpa (op, insn, mask);
	}
	const bool subtract = multiply? (insn >> 15) & 1: (insn >> 30) & 1;
	const ut8 shift = multiply? 0: (insn >> 10) & 7;
	const ut8 rd = insn & 31;
	const ut8 rn = (insn >> 5) & 31;
	const ut8 rm = (insn >> 16) & 31;
	const ut8 ra = (insn >> 10) & 31;
	const char *base_zero_reg = multiply? "xzr": "sp";
	const char *regs[] = {
		rd == 31? base_zero_reg: reg_list[rd],
		rn == 31? base_zero_reg: reg_list[rn],
		rm == 31? "xzr": reg_list[rm],
		ra == 31? "xzr": reg_list[ra]
	};
	op->size = 4;
	op->cycles = multiply? 2: 1;
	op->type = subtract? R_ANAL_OP_TYPE_SUB: R_ANAL_OP_TYPE_ADD;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		free (op->mnemonic);
		if (multiply) {
			op->mnemonic = r_str_newf ("%s %s, %s, %s, %s", subtract? "msubpt": "maddpt", regs[0], regs[1], regs[2], regs[3]);
		} else {
			op->mnemonic = r_str_newf ("%s %s, %s, %s", subtract? "subpt": "addpt", regs[0], regs[1], regs[2]);
			if (shift) {
				op->mnemonic = r_str_appendf (op->mnemonic, ", lsl %u", shift);
			}
		}
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		// Model address arithmetic without the system-controlled pointer checks.
		if (multiply) {
			r_strbuf_setf (&op->esil, "%s,%s,*,%s,%c", regs[2], regs[1], regs[3], subtract? '-': '+');
			if (rd == 31) {
				r_strbuf_append (&op->esil, ",POP");
			} else {
				r_strbuf_appendf (&op->esil, ",%s,=", regs[0]);
			}
		} else {
			r_strbuf_setf (&op->esil, "%u,%s,<<,%s,%c,%s,=", shift, rm == 31? "0": regs[2], regs[1], subtract? '-': '+', regs[0]);
		}
	}
	hack_cpa_values (op, regs, multiply? 4: 3, shift, false, mask);
	return true;
}
#endif

static int hack_handle_dp_reg(ut32 insn, RAnalOp *op) {
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
					// irg
					op->type = R_ANAL_OP_TYPE_MOV;
					return op->size = 4;
				} else if (opcode == 0) {
					// subp
					op->type = R_ANAL_OP_TYPE_SUB;
					return op->size = 4;
				} else if (opcode == 5) {
					// gmi
					op->type = R_ANAL_OP_TYPE_MOV;
					return op->size = 4;
				}
			} else if (S && opcode == 0) {
				// subps
				op->type = R_ANAL_OP_TYPE_SUB;
				return op->size = 4;
			}
		}
	}
	return -1;
}

static int hack_handle_ldst(ut32 insn, RAnalOp *op) {
	const ut8 op0 = (insn >> 28) & 0xf;
	const bool op1 = (insn >> 26) & 0x1;
	ut8 op2 = (insn >> 23) & 0x3;
	const bool op3 = (insn >> 21) & 0x1;

	// Load/store memory tags
	if (op0 == 13 && !op1 && (op2 == 2 || op2 == 3) && op3) {
		const ut8 opc = (insn >> 22) & 0x3;
		op2 = (insn >> 10) & 0x3;
		if (op2 > 0) {
			switch (opc) {
			case 0:
				// stg
				op->type = R_ANAL_OP_TYPE_STORE;
				return op->size = 4;
			case 1:
				// stzg
				op->type = R_ANAL_OP_TYPE_STORE;
				return op->size = 4;
			case 2:
				// st2g
				op->type = R_ANAL_OP_TYPE_STORE;
				return op->size = 4;
			case 3:
				// stz2g
				op->type = R_ANAL_OP_TYPE_STORE;
				return op->size = 4;
			}
		} else if (op2 == 0) {
			switch (opc) {
			case 0:
				// stzgm
				op->type = R_ANAL_OP_TYPE_STORE;
				return op->size = 4;
			case 1:
				// ldg
				op->type = R_ANAL_OP_TYPE_LOAD;
				return op->size = 4;
			case 2:
				// stgm
				op->type = R_ANAL_OP_TYPE_STORE;
				return op->size = 4;
			case 3:
				// ldgm
				op->type = R_ANAL_OP_TYPE_LOAD;
				return op->size = 4;
			}
		}
	// Load/store register pair
	} else if ((op0 & 0x3) == 2) {
		const ut8 opc = (insn >> 30) & 0x3;
		const bool V = (insn >> 26) & 0x1;
		const bool L = (insn >> 22) & 0x1;
		if (opc == 1 && !V && !L) {
			// stgp
			op->type = R_ANAL_OP_TYPE_STORE;
			return op->size = 4;
		}
	}
	return -1;
}

static int hack_handle_dp_imm(ut32 insn, RAnalOp *op) {
	const ut8 op0 = (insn >> 23) & 0x7;

	// Add/subtract (immediate, with tags)
	if (op0 == 3) {
		const bool sf = (insn >> 31) & 0x1;
		const bool op_ = (insn >> 30) & 0x1;
		const bool S = (insn >> 29) & 0x1;
		const bool o2 = (insn >> 22) & 0x1;
		if (sf && !S && !o2) {
			if (op_ ) {
				// subg
				op->type = R_ANAL_OP_TYPE_SUB;
				return op->size = 4;
			}
			// addg
			op->type = R_ANAL_OP_TYPE_ADD;
			return op->size = 4;
		}
	}
	return -1;
}

static int hack_handle_br_exc_sys(ut32 insn, RAnalOp *op) {
	if (insn == 0xd503251f) { // chkfeat x16
		op->type = R_ANAL_OP_TYPE_MOV;
		return op->size = 4;
	}
	if (insn == 0xd50322df || insn == 0xd503227f) { // clrbhb, gcsb dsync
		op->type = R_ANAL_OP_TYPE_SYNC;
		return op->size = 4;
	}
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
			case 2:
			case 4:
			case 6:
				op->type = R_ANAL_OP_TYPE_CMP;
				return op->size = 4;
			}
		}
	}
	return -1;
}

// Map FEAT_PAuth_LR encodings to the closest instructions supported by Capstone 5.
static const char *hack_pauth_lr_mnemonic(ut32 insn, bool *is_ret) {
	*is_ret = false;
	if ((insn & 0xffc0001f) == 0x5500001f) {
		*is_ret = true;
		return (insn & 0x00200000)? "retab": "retaa";
	}
	if ((insn & 0xffffffe0) == 0xd65f0be0 && (insn & 0x1f) != 0x1f) {
		*is_ret = true;
		return "retaa";
	}
	if ((insn & 0xffffffe0) == 0xd65f0fe0 && (insn & 0x1f) != 0x1f) {
		*is_ret = true;
		return "retab";
	}
	if ((insn & 0xffc0001f) == 0xf380001f) {
		return (insn & 0x00200000)? "autibsp": "autiasp";
	}
	if ((insn & 0xfffffc1f) == 0xdac1901e) {
		return "autiasp";
	}
	if ((insn & 0xfffffc1f) == 0xdac1941e) {
		return "autibsp";
	}
	switch (insn) {
	case 0xd50324ff: // pacm
		return "pacm";
	case 0xdac1bbfe: // autia171615
		return "autia1716";
	case 0xdac1bffe: // autib171615
		return "autib1716";
	case 0xdac183fe: // pacnbiasppc
	case 0xdac1a3fe: // paciasppc
		return "paciasp";
	case 0xdac187fe: // pacnbibsppc
	case 0xdac1a7fe: // pacibsppc
		return "pacibsp";
	case 0xdac18bfe: // pacia171615
		return "pacia1716";
	case 0xdac18ffe: // pacib171615
		return "pacib1716";
	}
	return NULL;
}

static inline int hacky_arm_anal(RArchSession *a, RAnalOp *op, const ut8 *buf, int len, RAnalOpMask mask) {
	int ret = -1;
	// Hacky support for ARMv8.3 and ARMv8.5
	if (a->config->bits == 64 && len >= 4) {
		ut32 insn = r_read_le32 (buf);
		int insn_class = (insn >> 25) & 0xf;
		bool is_ret;
		if (hack_pauth_lr_mnemonic (insn, &is_ret)) {
			op->type = is_ret? R_ANAL_OP_TYPE_RET: R_ANAL_OP_TYPE_CMP;
			op->family = R_ANAL_OP_FAMILY_SECURITY;
			if (is_ret && (mask & R_ARCH_OP_MASK_ESIL)) {
				r_strbuf_set (&op->esil, "lr,pc,:=");
			}
			return op->size = 4;
		}
		// xpaci // e#43c1da
		if (!memcmp (buf + 1, "\x43\xc1\xda", 3)) {
			op->type = R_ANAL_OP_TYPE_MOV;
			return op->size = 4;
		}
		// retaa
		if (!memcmp (buf, "\xff\x0b\x5f\xd6", 4)) {
			op->type = R_ANAL_OP_TYPE_RET;
			return op->size = 4;
		}
		// retab
		if (!memcmp (buf, "\xff\x0f\x5f\xd6", 4)) {
			op->type = R_ANAL_OP_TYPE_RET;
			return op->size = 4;
		}

		switch (insn_class) {
		// Data Processing -- Register
		case 5:
		case 13:
			// irg, subp, gmi, subps
			ret = hack_handle_dp_reg (insn, op);
			break;
		// Data Processing -- Immediate
		case 8:
		case 9:
			// addg, subg
			ret = hack_handle_dp_imm (insn, op);
			break;
		case 10:
		case 11:
			// bti
			ret = hack_handle_br_exc_sys (insn, op);
			break;
		// Loads and Stores
		case 4:
		case 6:
		case 12:
		case 14:
			// stg, stzgm, ldg, stzg, st2g, stgm, stz2g, ldgm, stgp
			ret = hack_handle_ldst (insn, op);
			break;
		default:
			break;
		}

		if (ret > 0) {
			op->family = R_ANAL_OP_FAMILY_SECURITY;
		}

	}
	return ret;
}

#include "r_anal.h"
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

static inline int hackyArmAnal(RAnal *a, RAnalOp *op, const ut8 *buf, int len) {
	int ret = -1;
	// Hacky support for ARMv8.3 and ARMv8.5
	if (a->bits == 64 && len >= 4) {
		ut32 insn = r_read_ble32 (buf, a->big_endian);
		int insn_class = (insn >> 25) & 0xf;
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

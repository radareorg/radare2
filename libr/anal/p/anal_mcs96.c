/* radare - LGPL - Copyright - 2015-2022 - condret */

#include <r_asm.h>
#include <r_lib.h>
#include "../arch/mcs96/mcs96.h"

static int mcs96_len(const ut8 *buf, int len, RAnalOp *op) {
	int ret = 1;
	if (buf[0] == 0xfe) {
		if (len < 2) {
			return 0;
		}
		if (mcs96_op[buf[1]].type & MCS96_FE) {
			if (mcs96_op[buf[1]].type & MCS96_5B_OR_6B) {
				if (len < 3) {
					return 0;
				}
				ret = 6 + (buf[2] & 0x1);
			}
			if (mcs96_op[buf[1]].type & MCS96_4B_OR_5B) {
				if (len < 3) {
					return 0;
				}
				ret = 5 + (buf[2] & 0x1);
			}
			if (mcs96_op[buf[1]].type & MCS96_3B_OR_4B) {
				if (len < 3) {
					return 0;
				}
				ret = 4 + (buf[1] & 0x1);
			}
			if (mcs96_op[buf[1]].type & MCS96_5B) {
				ret = 6;
			}
			if (mcs96_op[buf[1]].type & MCS96_4B) {
				ret = 5;
			}
			if (mcs96_op[buf[1]].type & MCS96_3B) {
				ret = 4;
			}
			if (mcs96_op[buf[1]].type & MCS96_2B) {
				ret = 3;
			}
			if (ret <= len) {
				const ut32 fe_idx = ((buf[1] & 0x70) >> 4) ^ 0x4;
				if ((mcs96_op[buf[1]].type & (MCS96_2OP | MCS96_REG_8)) == (MCS96_2OP | MCS96_REG_8) && buf[2] > 0x19 && buf[3] > 0x19) {
					op->mnemonic = r_str_newf ("%s rb%02x, rb%02x",
						mcs96_fe_op[fe_idx], buf[2] - 0x1a, buf[3] - 0x1a);
				} else {
					op->mnemonic = strdup (mcs96_fe_op[fe_idx]);
				}
			} else {
				ret = 0;
			}
			return ret;
		}
	}
	if (mcs96_op[buf[0]].type & MCS96_5B_OR_6B) {
		if (len < 2) {
			return 0;
		}
		ret = 5 + (buf[1] & 0x1);
	}
	if (mcs96_op[buf[0]].type & MCS96_4B_OR_5B) {
		if (len < 2) {
			return 0;
		}
		ret = 4 + (buf[1] & 0x1);
	}
	if (mcs96_op[buf[0]].type & MCS96_3B_OR_4B) {
		if (len < 2) {
			return 0;
		}
		ret = 3 + (buf[1] & 0x1);
	}
	if (mcs96_op[buf[0]].type & MCS96_5B) {
		ret = 5;
	}
	if (mcs96_op[buf[0]].type & MCS96_4B) {
		ret = 4;
	}
	if (mcs96_op[buf[0]].type & MCS96_3B) {
		ret = 3;
	}
	if (mcs96_op[buf[0]].type & MCS96_2B) {
		ret = 2;
	}
	if (ret <= len) {
		const char *opstr = mcs96_op[buf[0]].ins;
		if ((mcs96_op[buf[0]].type & (MCS96_2OP | MCS96_REG_8)) == (MCS96_2OP | MCS96_REG_8) && buf[1] > 0x19 && buf[2] > 0x19) {
			op->mnemonic = r_str_newf ("%s rb%02x, rb%02x", opstr, buf[1] - 0x1a, buf[2] - 0x1a);
		} else {
			op->mnemonic = strdup (opstr);
		}
	} else {
		ret = 0;
	}
	return ret;
}

static int disassemble(RAnal *a, RAnalOp *op, const ut8 *buf, int len) {
	if (len > 1 && !memcmp (buf, "\xff\xff", 2)) {
		return -1;
	}
	op->size = mcs96_len (buf, len, op);
	return op->size;
}

static int _6502_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	int len = disassemble (anal, op, data, len);
	if (mask & R_ANAL_OP_MASK_DISASM) {
		// do nothing
	}
	return len;
}

RAnalPlugin r_anal_plugin_mcs96 = {
	.name = "mcs96",
	.desc = "Intel MCS96 microcontroller, also known as 8xC196 or 80196",
	.arch = "mcs96",
	.license = "LGPL3",
	.op = &_op,
	.author = "condret",
	.bits = 16,
	.endian = R_SYS_ENDIAN_NONE,
	// .disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_mcs96,
	.version = R2_VERSION
};
#endif

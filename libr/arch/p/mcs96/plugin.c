/* radare - LGPL - Copyright - 2015-2024 - condret */

#include <r_asm.h>
#include "mcs96.h"

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
		if (buf[0] == 0xf0) {
			op->type = R_ANAL_OP_TYPE_RET;
			op->mnemonic = strdup (opstr);
		} else if ((mcs96_op[buf[0]].type & (MCS96_2OP | MCS96_REG_8)) == (MCS96_2OP | MCS96_REG_8) &&
				buf[1] > 0x19 && buf[2] > 0x19) {
			op->mnemonic = r_str_newf ("%s rb%02x, rb%02x", opstr, buf[1] - 0x1a, buf[2] - 0x1a);
		} else if (mcs96_op[buf[0]].type & MCS96_2B) {
			if (mcs96_op[buf[0]].type & MCS96_11B_RELA) {
				ut16 rela = ((buf[0] & 0x7) << 8) | buf[1];
				ut64 dst = op->addr + 2 - (rela & 0x400) + (rela & 0x3ff);
				op->mnemonic = r_str_newf ("%s 0x%04"PFMT64x, opstr, dst);
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = dst;
			} else if (mcs96_op[buf[0]].type & MCS96_1B_RELJMP) {
				ut64 dst = op->addr + 2 - (buf[1] & 0x80) + (buf[1] & 0x7f);
				op->mnemonic = r_str_newf ("%s 0x%04"PFMT64x, opstr, dst);
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = dst;
				op->fail = op->addr + 2;
			} else {
				op->mnemonic = strdup (opstr);
			}
		} else if (mcs96_op[buf[0]].type & MCS96_3B) {
			if (mcs96_op[buf[0]].type & MCS96_2B_RELJMP) {
				ut16 rela = (buf[2]<< 8) | buf[1];
				ut64 dst = op->addr + 3 - (rela & 0x8000) + (rela & 0x7fff);
				op->mnemonic = r_str_newf ("%s 0x%04"PFMT64x, opstr, dst);
				op->type = (buf[0] == 0xef)? R_ANAL_OP_TYPE_CALL: R_ANAL_OP_TYPE_JMP;
				op->jump = dst;
			} else {
				op->mnemonic = strdup (opstr);
			}
		} else {
			op->mnemonic = strdup (opstr);
		}
	} else {
		ret = 0;
	}
	return ret;
}

static int disassemble(RArchSession *a, RAnalOp *op, const ut8 *buf, int len) {
	op->size = mcs96_len (buf, len, op);
	return op->size;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	int ilen = disassemble (as, op, op->bytes, op->size);
	op->size = ilen;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		// do nothing
	}
	if (r_str_startswith (op->mnemonic, "invalid")) {
		return false;
	}
	return ilen > 0;
}

// WORDs must be aligned at even byte boundaries in the address space
static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_CODE_ALIGN:
		return 1;
	case R_ARCH_INFO_DATA_ALIGN:
		return 2; // data alignment depends on word size used
#if 0
	case R_ARCH_INFO_DATA4_ALIGN:
		return 4;
	case R_ARCH_INFO_DATA8_ALIGN:
		return 8;
#endif
	case R_ARCH_INFO_MAXOP_SIZE:
		return 5;
	case R_ARCH_INFO_MINOP_SIZE:
		return 1;
	}
	return 0;
}
// 512 bytes register RAM
// window selection registers
//  PSW, INT_MASK, INT_MASK1
// http://datasheets.chipdb.org/Intel/MCS96/MANUALS/27231703.PDF
static char *regs(RArchSession *s) {
	const char *p =
		"=PC	pc\n"
		"=SP	r3\n"
		"=A0	r0\n"
		"=ZF	z\n"
		"=SF	s\n"
		"=OF	ov\n"
		"=CF	cy\n"
		"gpr	pc	.32	0   0\n"
		"gpr	psw	.32	4   0\n"
		"gpr	int_mask	.32	8   0\n"
		"gpr	int_mask1	.32	12   0\n"
		;
	return strdup (p);
}

const RArchPlugin r_arch_plugin_mcs96 = {
	.meta = {
		.name = "mcs96",
		.desc = "Intel MCS96 microcontroller (aka 8xC196 / 80196)",
		.license = "LGPL-3.0-only",
		.author = "condret",
	},
	.arch = "mcs96",
	.decode = &decode,
	.regs = regs,
	.info = archinfo,
	.bits = R_SYS_BITS_PACK3 (16, 32, 64), // can work with 64bit registers too
	.endian = R_SYS_ENDIAN_NONE,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_mcs96,
	.version = R2_VERSION
};
#endif

/* radare - LGPL - Copyright - 2015-2019 - condret */

#include <r_types.h>
#include <string.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/mcs96/mcs96.h"

static int mcs96_len (const ut8 *buf, int len, RStrBuf *asm_buf) {
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
				r_strbuf_set (asm_buf, mcs96_fe_op[fe_idx]);
				if ((mcs96_op[buf[1]].type & (MCS96_2OP | MCS96_REG_8)) == (MCS96_2OP | MCS96_REG_8) &&
					buf[2] > 0x19 && buf[3] > 0x19) {
					r_strbuf_appendf(asm_buf, " rb%02x, rb%02x", buf[2] - 0x1a, buf[3] - 0x1a);
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
		r_strbuf_set (asm_buf, mcs96_op[buf[0]].ins);
		if ((mcs96_op[buf[0]].type & (MCS96_2OP | MCS96_REG_8)) == (MCS96_2OP | MCS96_REG_8) &&
			buf[1] > 0x19 && buf[2] > 0x19) {
			r_strbuf_appendf(asm_buf, " rb%02x, rb%02x", buf[1] - 0x1a, buf[2] - 0x1a);
		}
	} else {
		ret = 0;
	}
	return ret;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	if (len > 1 && !memcmp (buf, "\xff\xff", 2)) {
		return -1;
	}
	op->size = mcs96_len (buf, len, &op->buf_asm);
	return op->size;
}

RAsmPlugin r_asm_plugin_mcs96 = {
	.name = "mcs96",
	.desc = "condrets car",
	.arch = "mcs96",
	.license = "LGPL3",
	.bits = 16,
	.endian = R_SYS_ENDIAN_NONE,
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mcs96,
	.version = R2_VERSION
};
#endif

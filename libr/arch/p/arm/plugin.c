/* radare2 - LGPL - Copyright 2008-2024 - pancake */

#include <r_arch.h>
#include <sdb/ht_uu.h>
#include "./cs_version.h"
#include "./asm-arm.h"

static bool encode(RArchSession *s, RAnalOp *op, ut32 mask) {
	int bits = s->config->bits;
	if (bits & R_SYS_BITS_32) {
		bits = 32;
	} else if (bits & R_SYS_BITS_16) {
		bits = 16;
	}
#if 0
	if (s->config->bits & R_SYS_BITS_64) {
		bits = 64;
	} else if (s->config->bits & R_SYS_BITS_32) {
		bits = 32;
	} else if (s->config->bits & R_SYS_BITS_16) {
		bits = 16;
	}
#endif
	const bool is_thumb = (bits == 16);
	int opsize;
	ut32 opcode = UT32_MAX;
	if (bits == 64) {
		if (!arm64ass (op->mnemonic, op->addr, &opcode)) {
			return false;
		}
	} else {
		opcode = armass_assemble (op->mnemonic, op->addr, is_thumb);
		if (bits != 32 && bits != 16) {
			R_LOG_ERROR ("ARM assembler only supports 16 or 32 bits");
			return false;
		}
	}
	if (opcode == UT32_MAX) {
		return false;
	}
	ut8 opbuf[4];
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (s->config);
	if (is_thumb) {
		const int o = opcode >> 16;
		opsize = o > 0? 4: 2;
		if (opsize == 4) {
			if (be) {
				r_write_le16 (opbuf, opcode >> 16);
				r_write_le16 (opbuf + 2, opcode & UT16_MAX);
			} else {
				r_write_be32 (opbuf, opcode);
			}
		} else if (opsize == 2) {
			if (be) {
				r_write_le16 (opbuf, opcode & UT16_MAX);
			} else {
				r_write_be16 (opbuf, opcode & UT16_MAX);
			}
		}
	} else {
		opsize = 4;
		if (be) {
			r_write_le32 (opbuf, opcode);
		} else {
			r_write_be32 (opbuf, opcode);
		}
	}
	r_anal_op_set_bytes (op, op->addr, opbuf, opsize);
	// r_strbuf_setbin (&op->buf, opbuf, opsize);
	return true;
}

#if 0
// old api
static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	const int bits = a->config->bits;
	const bool is_thumb = (bits == 16);
	int opsize;
	ut32 opcode = UT32_MAX;
	if (bits == 64) {
		if (!arm64ass (buf, a->pc, &opcode)) {
			return -1;
		}
	} else {
		opcode = armass_assemble (buf, a->pc, is_thumb);
		if (bits != 32 && bits != 16) {
			R_LOG_ERROR ("ARM assembler only supports 16 or 32 bits");
			return -1;
		}
	}
	if (opcode == UT32_MAX) {
		return -1;
	}
	ut8 opbuf[4];
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
	if (is_thumb) {
		const int o = opcode >> 16;
		opsize = o > 0? 4: 2;
		if (opsize == 4) {
			if (be) {
				r_write_le16 (opbuf, opcode >> 16);
				r_write_le16 (opbuf + 2, opcode & UT16_MAX);
			} else {
				r_write_be32 (opbuf, opcode);
			}
		} else if (opsize == 2) {
			if (be) {
				r_write_le16 (opbuf, opcode & UT16_MAX);
			} else {
				r_write_be16 (opbuf, opcode & UT16_MAX);
			}
		}
	} else {
		opsize = 4;
		if (be) {
			r_write_le32 (opbuf, opcode);
		} else {
			r_write_be32 (opbuf, opcode);
		}
	}
	r_strbuf_setbin (&op->buf, opbuf, opsize);
// XXX. thumb endian assembler needs no swap
	return opsize;
}
#endif

static int archinfo(RArchSession *a, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_DATA_ALIGN:
	case R_ARCH_INFO_INVOP_SIZE:
	case R_ARCH_INFO_MAXOP_SIZE:
		break;
	case R_ARCH_INFO_MINOP_SIZE:
	case R_ARCH_INFO_CODE_ALIGN:
		if (a->config && a->config->bits == 16) {
			return 2;
		}
		break;
	}
	return 4; // XXX
}

const RArchPlugin r_arch_plugin_arm = {
	.meta = {
		.name = "arm.nz",
		.desc = "custom thumb, arm32 and arm64 assembler",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.arch = "arm",
	.info = archinfo,
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.encode = &encode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_arm,
	.version = R2_VERSION
};
#endif

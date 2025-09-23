/* radare2 - LGPL - Copyright 2008-2024 - pancake */

#include <r_arch.h>
#include <sdb/ht_uu.h>
#include "./cs_version.h"
#include "./asm-arm.h"

static bool encode(RArchSession *s, RAnalOp *op, ut32 mask) {
	int bits = s->config->bits;
	if (R_SYS_BITS_CHECK (bits, 64)) {
		bits = 64;
	} else if (R_SYS_BITS_CHECK (bits, 32)) {
		bits = 32;
	} else if (R_SYS_BITS_CHECK (bits, 16)) {
		bits = 16;
	}
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
			r_write_ble16 (opbuf, opcode & UT16_MAX, !be);
		}
	} else {
		opsize = 4;
		r_write_ble32 (opbuf, opcode, !be);
	}
	r_anal_op_set_bytes (op, op->addr, opbuf, opsize);
	// r_strbuf_setbin (&op->buf, opbuf, opsize);
	return true;
}

static int archinfo(RArchSession *a, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_ISVM:
		return 0;
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

#include "preludes.inc.c"
const RArchPlugin r_arch_plugin_arm = {
	.meta = {
		.name = "arm.nz",
		.desc = "Custom thumb, arm32 and arm64 assembler",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.arch = "arm",
	.preludes = anal_preludes,
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

/* radare2 - BSD - Copyright 2013-2022 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <ht_uu.h>
#include "cs_version.h"
#include "../arch/arm/asm-arm.h"

bool arm64ass(const char *str, ut64 addr, ut32 *op);

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
	const bool be = a->config->big_endian;
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

RAsmPlugin r_asm_plugin_arm = {
	.name = "arm",
	.desc = "Custom THUMB, ARM32, AARCH64 assembler for radare2",
	.cpus = ",v8,cortex",
	.features = "v8",
	.license = "BSD",
	.arch = "arm",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.assemble = &assemble,
#if 0
	// arm32 and arm64
	"crypto,databarrier,divide,fparmv8,multpro,neon,t2extractpack,"
	"thumb2dsp,trustzone,v4t,v5t,v5te,v6,v6t2,v7,v8,vfp2,vfp3,vfp4,"
	"arm,mclass,notmclass,thumb,thumb1only,thumb2,prev8,fpvmlx,"
	"mulops,crc,dpvfp,v6m"
#endif
};


#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm,
	.version = R2_VERSION
};
#endif

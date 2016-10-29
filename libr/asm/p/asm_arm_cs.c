/* radare2 - LGPL - Copyright 2013-2016 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include "../arch/arm/asm-arm.h"

bool arm64ass(const char *str, ut64 addr, ut32 *op);
static int check_features(RAsm *a, cs_insn *insn);
static csh cd = 0;

#include "cs_mnemonics.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static int omode = -1;
	static int obits = 32;
	cs_insn* insn = NULL;
	cs_mode mode = 0;
	int ret, n = 0;
	mode |= (a->bits == 16)? CS_MODE_THUMB: CS_MODE_ARM;
	mode |= (a->big_endian)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	if (mode != omode || a->bits != obits) {
		cs_close (&cd);
		cd = 0; // unnecessary
		omode = mode;
		obits = a->bits;
	}

	if (a->features && strstr (a->features, "mclass"))
		mode |= CS_MODE_MCLASS;
	if (a->features && strstr (a->features, "v8"))
		mode |= CS_MODE_V8;
	if (op) {
		op->size = 4;
		op->buf_asm[0] = 0;
	}
	if (cd == 0) {
		ret = (a->bits == 64)?
			cs_open (CS_ARCH_ARM64, mode, &cd):
			cs_open (CS_ARCH_ARM, mode, &cd);
		if (ret) {
			ret = -1;
			goto beach;
		}
	}
	if (a->syntax == R_ASM_SYNTAX_REGNUM) {
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	} else cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	if (a->features && *a->features) {
		cs_option (cd, CS_OPT_DETAIL, CS_OPT_ON);
	} else {
		cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	if (!buf) {
		goto beach;
	}
	n = cs_disasm (cd, buf, R_MIN (4, len), a->pc, 1, &insn);
	if (n < 1) {
		ret = -1;
		goto beach;
	}
	if (op) {
		op->size = 0;
	}
	if (insn->size < 1) {
		ret = -1;
		goto beach;
	}
	if (a->features && *a->features) {
		if (!check_features (a, insn) && op) {
			op->size = insn->size;
			strcpy (op->buf_asm, "illegal");
		}
	}
	if (op && !op->size) {
		op->size = insn->size;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
			insn->mnemonic,
			insn->op_str[0]?" ":"",
			insn->op_str);
		r_str_rmch (op->buf_asm, '#');
	}
	cs_free (insn, n);
	beach:
	//cs_close (&cd);
	if (op) {
		if (!op->buf_asm[0]) {
			strcpy (op->buf_asm, "invalid");
		}
		return op->size;
	}
	return 0;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	const bool is_thumb = (a->bits == 16);
	int opsize;
	ut32 opcode;
	if (a->bits == 64) {
		if (!arm64ass (buf, a->pc, &opcode)) {
			return -1;
		}
	} else {
		opcode = armass_assemble (buf, a->pc, is_thumb);
		if (a->bits != 32 && a->bits != 16) {
			eprintf ("Error: ARM assembler only supports 16 or 32 bits\n");
			return -1;
		}
	}
	if (opcode == UT32_MAX) {
		return -1;
	}
	if (is_thumb) {
		const int o = opcode >> 16;
		opsize = o > 0? 4: 2; //(o&0x80 && ((o&0xe0)==0xe0))? 4: 2;
		if (opsize == 4) {
			if (a->big_endian) {
				r_write_le32 (op->buf, opcode);
			} else {
				r_write_be32 (op->buf, opcode);
			}
		} else if (opsize == 2) {
			r_write_be16 (op->buf, opcode & UT16_MAX);
		}
	} else {
		opsize = 4;
		if (a->big_endian) {
			r_write_le32 (op->buf, opcode);
		} else {
			r_write_be32 (op->buf, opcode);
		}
	}
// XXX. thumb endian assembler needs no swap
	return opsize;
}

RAsmPlugin r_asm_plugin_arm_cs = {
	.name = "arm",
	.desc = "Capstone ARM disassembler",
	.cpus = "v8,cortex-m",
	.license = "BSD",
	.arch = "arm",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	.mnemonics = mnemonics,
	.assemble = &assemble,
	.features = "no-mclass,v8"
#if 0
		// arm32 and arm64
		"crypto,databarrier,divide,fparmv8,multpro,neon,t2extractpack,"
		"thumb2dsp,trustzone,v4t,v5t,v5te,v6,v6t2,v7,v8,vfp2,vfp3,vfp4,"
		"arm,mclass,notmclass,thumb,thumb1only,thumb2,prev8,fpvmlx,"
		"mulops,crc,dpvfp,v6m"
#endif
};

static int check_features(RAsm *a, cs_insn *insn) {
	const char *name;
	int i;
	if (!insn || !insn->detail) {
		return 1;
	}
	for (i = 0; i < insn->detail->groups_count; i++) {
		int id = insn->detail->groups[i];
		if (id == ARM_GRP_ARM)
			continue;
		if (id == ARM_GRP_THUMB)
			continue;
		if (id == ARM_GRP_THUMB1ONLY)
			continue;
		if (id == ARM_GRP_THUMB2)
			continue;
		if (id < 128) {
			continue;
		}
		name = cs_group_name (cd, id);
		if (!name) {
			return 1;
		}
		if (!strstr (a->features, name)) {
			//eprintf ("CANNOT FIND %s\n", name);
			return 0;
		}
	}
	return 1;
}

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_cs,
	.version = R2_VERSION
};
#endif

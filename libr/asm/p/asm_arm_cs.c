/* radare2 - LGPL - Copyright 2013-2018 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include "../arch/arm/asm-arm.h"

bool arm64ass(const char *str, ut64 addr, ut32 *op);
static csh cd = 0;

#include "cs_mnemonics.c"

static bool check_features(RAsm *a, cs_insn *insn) {
	int i;
	if (!insn || !insn->detail) {
		return true;
	}
	for (i = 0; i < insn->detail->groups_count; i++) {
		int id = insn->detail->groups[i];
		switch (id) {
		case ARM_GRP_ARM:
		case ARM_GRP_THUMB:
		case ARM_GRP_THUMB1ONLY:
		case ARM_GRP_THUMB2:
			continue;
		default:
			if (id < 128) {
				continue;
			}
		}
		const char *name = cs_group_name (cd, id);
		if (!name) {
			return true;
		}
		if (!strstr (a->features, name)) {
			return false;
		}
	}
	return true;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static int omode = -1;
	static int obits = 32;
	bool disp_hash = a->immdisp;
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

	if (a->cpu) {
		if (strstr (a->cpu, "cortex")) {
			mode |= CS_MODE_MCLASS;
		}
		if (a->bits != 64) {
			if (strstr (a->cpu, "v8")) {
				mode |= CS_MODE_V8;
			}
		}
	}
	if (a->features && a->bits != 64) {
		if (strstr (a->features, "v8")) {
			mode |= CS_MODE_V8;
		}
	}
	if (op) {
		op->size = 4;
		r_strbuf_set (&op->buf_asm, "");
	}
	if (!cd || mode != omode) {
		ret = (a->bits == 64)?
			cs_open (CS_ARCH_ARM64, mode, &cd):
			cs_open (CS_ARCH_ARM, mode, &cd);
		if (ret) {
			ret = -1;
			goto beach;
		}
	}
	cs_option (cd, CS_OPT_SYNTAX, (a->syntax == R_ASM_SYNTAX_REGNUM)
			? CS_OPT_SYNTAX_NOREGNAME
			: CS_OPT_SYNTAX_DEFAULT);
	cs_option (cd, CS_OPT_DETAIL, (a->features && *a->features)
		? CS_OPT_ON: CS_OPT_OFF);
	if (!buf) {
		goto beach;
	}
	n = cs_disasm (cd, buf, R_MIN (4, len), a->pc, 1, &insn);
	if (n < 1 || insn->size < 1) {
		ret = -1;
		goto beach;
	}
	if (op) {
		op->size = 0;
	}
	if (a->features && *a->features) {
		if (!check_features (a, insn) && op) {
			op->size = insn->size;
			r_strbuf_set (&op->buf_asm, "illegal");
		}
	}
	if (op && !op->size) {
		op->size = insn->size;
		char *buf_asm = sdb_fmt ("%s%s%s",
			insn->mnemonic,
			insn->op_str[0]?" ":"",
			insn->op_str);
		if (!disp_hash) {
			r_str_rmch (buf_asm, '#');
		}
		r_strbuf_set (&op->buf_asm, buf_asm);
	}
	cs_free (insn, n);
	beach:
	cs_close (&cd);
	if (op) {
		if (!*r_strbuf_get (&op->buf_asm)) {
			r_strbuf_set (&op->buf_asm, "invalid");
		}
		return op->size;
	}
	return ret;
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
	ut8 opbuf[4];
	if (is_thumb) {
		const int o = opcode >> 16;
		opsize = o > 0? 4: 2;
		if (opsize == 4) {
			if (a->big_endian) {
				r_write_le16 (opbuf, opcode >> 16);
				r_write_le16 (opbuf + 2, opcode & UT16_MAX);
			} else {
				r_write_be32 (opbuf, opcode);
			}
		} else if (opsize == 2) {
			if (a->big_endian) {
				r_write_le16 (opbuf, opcode & UT16_MAX);
			} else {
				r_write_be16 (opbuf, opcode & UT16_MAX);
			}
		}
	} else {
		opsize = 4;
		if (a->big_endian) {
			r_write_le32 (opbuf, opcode);
		} else {
			r_write_be32 (opbuf, opcode);
		}
	}
	r_strbuf_setbin (&op->buf, opbuf, opsize);
// XXX. thumb endian assembler needs no swap
	return opsize;
}

RAsmPlugin r_asm_plugin_arm_cs = {
	.name = "arm",
	.desc = "Capstone ARM disassembler",
	.cpus = ",v8,cortex",
	.features = "v8",
	.license = "BSD",
	.arch = "arm",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	.mnemonics = mnemonics,
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
	.data = &r_asm_plugin_arm_cs,
	.version = R2_VERSION
};
#endif

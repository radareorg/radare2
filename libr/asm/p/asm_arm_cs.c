/* radare2 - LGPL - Copyright 2013-2022 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <ht_uu.h>
#include "cs_version.h"
#include "../arch/arm/asm-arm.h"
#include "./asm_arm_hacks.inc"

bool arm64ass(const char *str, ut64 addr, ut32 *op);
// XXX kill globals
static R_TH_LOCAL csh cd = 0;
static R_TH_LOCAL HtUU *ht_itblock = NULL;
static R_TH_LOCAL HtUU *ht_it = NULL;

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
		if (a->config->features && !strstr (a->config->features, name)) {
			return false;
		}
	}
	return true;
}

static const char *cc_name(arm_cc cc) {
	switch (cc) {
	case ARM_CC_EQ: // Equal                      Equal
		return "eq";
	case ARM_CC_NE: // Not equal                  Not equal, or unordered
		return "ne";
	case ARM_CC_HS: // Carry set                  >, ==, or unordered
		return "hs";
	case ARM_CC_LO: // Carry clear                Less than
		return "lo";
	case ARM_CC_MI: // Minus, negative            Less than
		return "mi";
	case ARM_CC_PL: // Plus, positive or zero     >, ==, or unordered
		return "pl";
	case ARM_CC_VS: // Overflow                   Unordered
		return "vs";
	case ARM_CC_VC: // No overflow                Not unordered
		return "vc";
	case ARM_CC_HI: // Unsigned higher            Greater than, or unordered
		return "hi";
	case ARM_CC_LS: // Unsigned lower or same     Less than or equal
		return "ls";
	case ARM_CC_GE: // Greater than or equal      Greater than or equal
		return "ge";
	case ARM_CC_LT: // Less than                  Less than, or unordered
		return "lt";
	case ARM_CC_GT: // Greater than               Greater than
		return "gt";
	case ARM_CC_LE: // Less than or equal         <, ==, or unordered
		return "le";
	default:
		return "";
	}
}

static void disass_itblock(RAsm *a, cs_insn *insn) {
	size_t i, size;
	size = r_str_nlen (insn->mnemonic, 5);
	ht_uu_update (ht_itblock, a->pc, size);
	for (i = 1; i < size; i++) {
		switch (insn->mnemonic[i]) {
		case 0x74: //'t'
			ht_uu_update (ht_it, a->pc + (i * insn->size), insn->detail->arm.cc);
			break;
		case 0x65: //'e'
			ht_uu_update (ht_it, a->pc + (i * insn->size), (insn->detail->arm.cc % 2)?
				insn->detail->arm.cc + 1:insn->detail->arm.cc - 1);
			break;
		default:
			break;
		}
	}
}

static void check_itblock(RAsm *a, cs_insn *insn) {
	size_t x;
	bool found;
	ut64 itlen = ht_uu_find (ht_itblock, a->pc, &found);
	if (found) {
		for (x = 1; x < itlen; x++) {
			ht_uu_delete (ht_it, a->pc + (x*insn->size));
		}
		ht_uu_delete (ht_itblock, a->pc);
	}
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static int omode = -1;
	static int obits = 32;
	bool disp_hash = a->immdisp;
	cs_insn* insn = NULL;
	int ret, n = 0;
	bool found = false;
	ut64 itcond;
	const int bits = a->config->bits;

	cs_mode mode = 0;
	mode |= (bits == 16)? CS_MODE_THUMB: CS_MODE_ARM;
	mode |= (a->config->big_endian)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	if (mode != omode || bits != obits) {
		cs_close (&cd);
		cd = 0; // unnecessary
		omode = mode;
		obits = bits;
	}

	const char *cpu = a->config->cpu;
	if (R_STR_ISNOTEMPTY (cpu)) {
		if (strstr (cpu, "cortex")) {
			mode |= CS_MODE_MCLASS;
		}
		if (bits != 64 && strstr (cpu, "v8")) {
			mode |= CS_MODE_V8;
		}
	}
	const char *features = a->config->features;
	if (features && bits != 64) {
		if (strstr (features, "v8")) {
			mode |= CS_MODE_V8;
		}
	}
	if (op) {
		op->size = 4;
		r_strbuf_set (&op->buf_asm, "");
	}
	if (!cd || mode != omode) {
		ret = (bits == 64)?
			cs_open (CS_ARCH_ARM64, mode, &cd):
			cs_open (CS_ARCH_ARM, mode, &cd);
		if (ret) {
			ret = -1;
			goto beach;
		}
	}
	cs_option (cd, CS_OPT_SYNTAX, (a->config->syntax == R_ASM_SYNTAX_REGNUM)
			? CS_OPT_SYNTAX_NOREGNAME
			: CS_OPT_SYNTAX_DEFAULT);
	cs_option (cd, CS_OPT_DETAIL, R_STR_ISNOTEMPTY (features) ? CS_OPT_ON: CS_OPT_OFF);
	cs_option (cd, CS_OPT_DETAIL, CS_OPT_ON);
	if (!buf) {
		goto beach;
	}
	int haa = hackyArmAsm (a, op, buf, len);
	if (haa > 0) {
		return haa;
	}

	n = cs_disasm (cd, buf, R_MIN (4, len), a->pc, 1, &insn);
	if (n < 1 || insn->size < 1) {
		ret = -1;
		goto beach;
	}
	if (op) {
		op->size = 0;
	}
	if (R_STR_ISNOTEMPTY (features)) {
		if (!check_features (a, insn) && op) {
			op->size = insn->size;
			r_strbuf_set (&op->buf_asm, "illegal");
		}
	}
	if (op && !op->size) {
		op->size = insn->size;
		if (insn->id == ARM_INS_IT) {
			disass_itblock (a, insn);
		} else {
			check_itblock (a, insn);
		}
		itcond = ht_uu_find (ht_it,  a->pc, &found);
		if (found) {
			insn->detail->arm.cc = itcond;
			insn->detail->arm.update_flags = 0;
			char *tmpstr = r_str_newf ("%s%s",
				cs_insn_name (cd, insn->id),
				cc_name (itcond));
			r_str_cpy (insn->mnemonic, tmpstr);
			free (tmpstr);
		}
		char opstr[256];
		snprintf (opstr, sizeof (opstr) - 1, "%s%s%s",
			insn->mnemonic,
			insn->op_str[0]? " ": "",
			insn->op_str);
		if (!disp_hash) {
			r_str_replace_char (opstr, '#', 0);
		}
		r_strbuf_set (&op->buf_asm, opstr);
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
			eprintf ("Error: ARM assembler only supports 16 or 32 bits\n");
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

static bool init(void* user) {
	if (!ht_it) {
		ht_it = ht_uu_new0 ();
	}
	if (!ht_itblock) {
		ht_itblock = ht_uu_new0 ();
	}
	return 0;
}

static bool fini(void* user) {
	ht_uu_free (ht_it);
	ht_uu_free (ht_itblock);
	ht_it = NULL;
	ht_itblock = NULL;
	return 0;
}

RAsmPlugin r_asm_plugin_arm_cs = {
	.name = "arm",
	.desc = "Capstone "CAPSTONE_VERSION_STRING" ARM disassembler",
	.cpus = ",v8,cortex",
	.features = "v8",
	.license = "BSD",
	.arch = "arm",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	.mnemonics = mnemonics,
	.assemble = &assemble,
	.init = &init,
	.fini = &fini,
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

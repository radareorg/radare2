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

static int hack_handle_dp_imm(ut32 insn, char **buf_asm) {
	char *mnemonic = NULL;
	const ut8 op0 = (insn >> 23) & 0x7;

	// Add/subtract (immediate, with tags)
	if (op0 == 3) {
		const ut8 sf = (insn >> 31) & 0x1;
		const ut8 op = (insn >> 30) & 0x1;
		const ut8 S = (insn >> 29) & 0x1;
		const ut8 o2 = (insn >> 2) & 0x1;
		if (sf == 1 && op == 0 && S == 0 && o2 == 0) {
			mnemonic = sdb_fmt ("addg");
		} else if (sf == 1 && op == 1 && S == 0 && o2 == 0) {
			mnemonic = sdb_fmt ("subg");
		} else {
			return -1;
		}
		const ut8 uimm6 = ((insn >> 16) & 0x3f) << 4;
		const ut8 uimm4 = (insn >> 10) & 0xf;
		const ut8 Xn = (insn >> 5) & 0x1f;
		const ut8 Xd = (insn >> 0) & 0x1f;
		*buf_asm = sdb_fmt ("%s x%d, x%d, #0x%x, #0x%x",
			mnemonic, Xn, Xd, uimm6, uimm4);
		*buf_asm = r_str_replace (*buf_asm, "x31", "sp", 1);
		return 0;
	}
	return -1;
}

static int hack_handle_dp_reg(ut32 insn, char **buf_asm) {
	char *mnemonic = NULL;
	const ut8 op0 = (insn >> 30) & 0x1;
	const ut8 op1 = (insn >> 28) & 0x1;
	const ut8 op2 = (insn >> 21) & 0xf;

	// Data-processing (2 source)
	if (op0 == 0 && op1 == 1 && op2 == 0x6) {
		const ut8 sf = (insn >> 31) & 0x1;
		const ut8 S = (insn >> 29) & 0x1;
		const ut8 opcode = (insn >> 10) & 0x1f;
		if (sf == 1 && S == 0 && opcode == 4) {
			mnemonic = sdb_fmt ("irg");
		} else if (sf == 1 && S == 0 && opcode == 0) {
			mnemonic = sdb_fmt ("subp");
		} else if (sf == 1 && S == 0 && opcode == 5) {
			mnemonic = sdb_fmt ("gmi");
		} else if (sf == 1 && S == 1 && opcode == 0) {
			mnemonic = sdb_fmt ("subps");
		} else {
			return -1;
		}
		const ut8 Xm = (insn >> 16) & 0x1f;
		const ut8 Xn = (insn >> 5) & 0x1f;
		const ut8 Xd = (insn >> 0) & 0x1f;
		if (Xm == 31 && !strcmp (mnemonic, "irg")) {
			*buf_asm = sdb_fmt ("%s x%d, x%d, xzr", mnemonic, Xd, Xn);
		} else {
			*buf_asm = sdb_fmt ("%s x%d, x%d, x%d", mnemonic, Xd, Xn, Xm);
		}
		*buf_asm = r_str_replace (*buf_asm, "x31", "sp", 1);
		return 0;
	}
	return -1;
}

static int hack_handle_ldst(ut32 insn, char **buf_asm) {
	char *mnemonic = NULL;
	const ut8 op0 = (insn >> 28) & 0xf;
	const ut8 op1 = (insn >> 26) & 0x1;
	ut8 op2 = (insn >> 24) & 0x2;
	const ut8 op3 = (insn >> 21) & 0x1;

	// Load/store memory tags
	if (op0 == 13 && op1 == 0 && op2 == 1 && op3 == 1) {
		const ut8 opc = (insn >> 22) & 0x2;
		const ut16 imm9 = ((insn >> 12) & 0x1ff) << 4;
		op2 = (insn >> 10) & 0x2;
		const ut8 Xn = (insn >> 5) & 0x1f;
		const ut8 Xt = (insn >> 0) & 0x1f;

		if (op2 > 0) {
			switch (opc) {
			case 0:
				mnemonic = "stg";
				break;
			case 1:
				mnemonic = "stzg";
				break;
			case 2:
				mnemonic = "st2g";
				break;
			case 3:
				mnemonic = "stz2g";
				break;
			}

			if (!imm9) {
				*buf_asm = sdb_fmt ("%s x%d, [x%d]", mnemonic, Xt, Xn);
			} else {
				switch (op2) {
				case 1:
					*buf_asm = sdb_fmt ("%s x%d, [x%d], #0x%x",
						mnemonic, Xt, Xn, imm9);
					break;
				case 2:
					*buf_asm = sdb_fmt ("%s x%d, [x%d, #0x%x]!",
						mnemonic, Xt, Xn, imm9);
					break;
				case 3:
					*buf_asm = sdb_fmt ("%s x%d, [x%d, #0x%x]",
						mnemonic, Xt, Xn, imm9);
					break;
				}			
			}
			*buf_asm = r_str_replace (*buf_asm, "x31", "sp", 1);
			return 0;	
		} else if (op2 == 0) {
			switch (opc) {
			case 0:
				mnemonic = "stzgm";
				break;
			case 1:
				mnemonic = "ldg";
				break;
			case 2:
				mnemonic = "stgm";
				break;
			case 3:
				mnemonic = "ldgm";
				break;
			}

			if (!imm9) {
				*buf_asm = sdb_fmt ("%s x%d, [x%d]", mnemonic, Xt, Xn);
			} else {
				*buf_asm = sdb_fmt ("%s x%d, [x%d, #0x%x]",
					mnemonic, Xt, Xn, imm9);
			}
			*buf_asm = r_str_replace (*buf_asm, "x31", "sp", 1);
			return 0;	
		} 
	// Load/store register pair
	} else if ((op0 & 0x2) == 2) {
		const ut8 opc = (insn >> 30) & 0x2;
		const ut8 V = (insn >> 26) & 0x1;
		const ut8 L = (insn >> 22) & 0x1;

		if (opc == 1 && V == 0 && L == 0) {
			const ut8 imm7 = (insn >> 15) & 0x7f;
			const ut8 Xt2 = (insn >> 10) & 0x1f;
			const ut8 Xt = (insn >> 5) & 0x1f;
			const ut8 Xn = (insn >> 0) & 0x1f;
			if (!imm7) {
				*buf_asm = sdb_fmt ("stgp x%d, [x%d, #0x%x]",
					Xt, Xt2, Xn, imm7);
			} else {
				switch (op2) {
				case 1:
					*buf_asm = sdb_fmt ("stgp x%d, x%d, [x%d], #0x%x",
						Xt, Xt2, Xn, imm7);
					break;
				case 2:
					*buf_asm = sdb_fmt ("stgp x%d, [x%d, #0x%x]!",
						Xt, Xt2, Xn, imm7);
					break;
				case 3:
					*buf_asm = sdb_fmt ("stgp x%d, [x%d, #0x%x]",
						Xt, Xt2, Xn, imm7);
					break;
				default:
					return -1;
				}
			}
			*buf_asm = r_str_replace (*buf_asm, "x31", "sp", 1);
			return 0;			
		}
	}
	return -1;
}

static int hack_arm_asm(RAsm *a, RAsmOp *op, const ut8 *buf, bool disp_hash) {
	int r = -1;
	char *buf_asm;
	ut32 *insn = (ut32 *)buf;
	int insn_class = (*insn >> 25) & 0xf;

	switch (insn_class) {
	// Data Processing -- Register
	case 5:
	case 13:
		// irg, subp, gmi, subps
		r = hack_handle_dp_reg (*insn, &buf_asm);
		break;
	// Data Processing -- Immediate
	case 8:
	case 9:
		// addg, subg
		r = hack_handle_dp_imm (*insn, &buf_asm);
		break;
	// Loads and Stores
	case 4:
	case 6:
	case 12:
	case 14:
		// stg, stzgm, ldg, stzg, st2g, stgm, stz2g, ldgm, stgp
		r = hack_handle_ldst (*insn, &buf_asm);
		break;
	default:
		break;
	}

	if (r < 0) {
		return r;
	}

	if (!disp_hash) {
		r_str_replace_char (buf_asm, '#', 0);
	}
	r_strbuf_set (&op->buf_asm, buf_asm);
	return op->size = 4;
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
	int haa = hack_arm_asm (a, op, buf, disp_hash);
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
			r_str_replace_char (buf_asm, '#', 0);
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

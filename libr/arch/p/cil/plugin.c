/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_anal.h>
#include <r_arch.h>
#include <r_lib.h>
#include <r_util.h>

#include "cil.inc.c"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut8 *buf = op->bytes;
	int len = op->size;
	ut64 addr = op->addr;

	if (len < 1) {
		return false;
	}

	op->size = 1;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->family = R_ANAL_OP_FAMILY_CPU;

	ut8 opcode = buf[0];
	const CilInstruction *ci = NULL;
	if (opcode == 0xfe) {
		if (len < 2) {
			return false;
		}
		ut8 opcode2 = buf[1];
		ci = &cil_fe_instructions[opcode2];
		if (!ci->mnemonic) {
			op->type = R_ANAL_OP_TYPE_ILL;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("ill 0xfe%02x", opcode2);
			}
			op->size = 2;
			return true;
		}
		op->size = ci->size;
		if (len < op->size) {
			return false;
		}
	} else {
		ci = &cil_instructions[opcode];
		if (!ci->mnemonic) {
			op->type = R_ANAL_OP_TYPE_ILL;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("ill 0x%02x", opcode);
			}
			return true;
		}
		op->size = ci->size;
		if (opcode == 0x45) { // switch
			if (len < 5) {
				return false;
			}
			ut32 count = r_read_le32 (buf + 1);
			op->size = 5 + 4 * count;
		}
		if (len < op->size) {
			return false;
		}
	}

	op->type = ci->type;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		char *mnemonic = r_str_new (ci->mnemonic);
		// Decode operand
		switch (ci->operand) {
		case CIL_OP_I1:
			mnemonic = r_str_appendf (mnemonic, " 0x%02x", buf[op->size - 1]);
			break;
		case CIL_OP_I4:
			mnemonic = r_str_appendf (mnemonic, " 0x%08x", r_read_le32 (buf + 1));
			break;
		case CIL_OP_I8:
			mnemonic = r_str_appendf (mnemonic, " 0x%016" PFMT64x, r_read_le64 (buf + 1));
			break;
		case CIL_OP_R4:
			{
				float f = r_read_le32 (buf + 1);
				mnemonic = r_str_appendf (mnemonic, " %f", f);
			}
			break;
		case CIL_OP_R8:
			{
				double d = r_read_le64 (buf + 1);
				mnemonic = r_str_appendf (mnemonic, " %f", d);
			}
			break;
		case CIL_OP_BR_S:
			{
				st8 offset = buf[op->size - 1];
				ut64 target = addr + op->size + offset;
				mnemonic = r_str_appendf (mnemonic, " 0x%08" PFMT64x, target);
			}
			break;
		case CIL_OP_BR_L:
			{
				st32 offset = r_read_le32 (buf + 1);
				ut64 target = addr + op->size + offset;
				mnemonic = r_str_appendf (mnemonic, " 0x%08" PFMT64x, target);
			}
			break;
		case CIL_OP_TOKEN:
			mnemonic = r_str_appendf (mnemonic, " 0x%08x", r_read_le32 (buf + 1));
			break;
		case CIL_OP_VAR_S:
			mnemonic = r_str_appendf (mnemonic, " %u", buf[op->size - 1]);
			break;
		case CIL_OP_VAR_L:
			mnemonic = r_str_appendf (mnemonic, " %u", r_read_le16 (buf + 2));
			break;
		case CIL_OP_NONE:
		default:
			break;
		}
		if (opcode == 0x45) { // switch
			ut32 count = r_read_le32 (buf + 1);
			for (ut32 i = 0; i < count; i++) {
				st32 offset = r_read_le32 (buf + 5 + i * 4);
				ut64 target = addr + op->size + offset;
				mnemonic = r_str_appendf (mnemonic, i ? ", 0x%08" PFMT64x : " 0x%08" PFMT64x, target);
			}
		}
		op->mnemonic = mnemonic;
	}

	// Set jump addresses for branches
	if (opcode >= 0x2b && opcode <= 0x44) {
		if (opcode >= 0x38) {
			// 32-bit offset
			st32 offset = r_read_le32 (buf + 1);
			op->jump = addr + 5 + offset;
			op->fail = addr + 5;
			if (opcode == 0x38) {
				op->eob = true;
			}
		} else {
			// 8-bit offset
			st8 offset = buf[1];
			op->jump = addr + 2 + offset;
			op->fail = addr + 2;
			if (opcode == 0x2b) {
				op->eob = true;
			}
		}
	} else if (opcode == 0xdd) {
		st32 offset = r_read_le32 (buf + 1);
		op->jump = addr + 5 + offset;
	} else if (opcode == 0xde) {
		st8 offset = buf[1];
		op->jump = addr + 2 + offset;
	}

	if (op->type == R_ANAL_OP_TYPE_RET) {
		op->eob = true;
	}

	return true;
}

static bool encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	if (!op->mnemonic) {
		return false;
	}
	// Simple assembler for basic instructions
	for (int i = 0; i < 256; i++) {
		if (cil_instructions[i].mnemonic && !strcmp (cil_instructions[i].mnemonic, op->mnemonic)) {
			op->size = cil_instructions[i].size;
			free (op->bytes);
			op->bytes = malloc (op->size);
			if (!op->bytes) {
				return false;
			}
			op->bytes[0] = i;
			return true;
		}
	}
	for (int i = 0; i < 256; i++) {
		if (cil_fe_instructions[i].mnemonic && !strcmp (cil_fe_instructions[i].mnemonic, op->mnemonic)) {
			op->size = cil_fe_instructions[i].size;
			free (op->bytes);
			op->bytes = malloc (op->size);
			if (!op->bytes) {
				return false;
			}
			op->bytes[0] = 0xfe;
			op->bytes[1] = i;
			return true;
		}
	}
	return false;
}

// static int info (RArchSession *as, ut32 q) {
// 	return -1;
// }

static char *regs(RArchSession *as) {
	const char p[] =
		"=PC	pc\n"
		"=SP	sp\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"

		"gpr	pc	.32	0	0\n"
		"gpr	sp	.32	4	0\n"
		"gpr	r0	.32	8	0\n"
		"gpr	r1	.32	12	0\n"
		"gpr	r2	.32	16	0\n"
		"gpr	r3	.32	20	0\n";
	return strdup (p);
}

const RArchPlugin r_arch_plugin_cil = {
	.meta = {
		.name = "cil",
		.author = "pancake",
		.desc = "Common Intermediate Language disassembler",
		.license = "LGPL-3.0-only",
	},
	.arch = "cil",
	.bits = R_SYS_BITS_PACK (32),
	.decode = &decode,
	.encode = &encode,
	.regs = regs,
	.info = NULL,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_cil,
	.version = R2_VERSION
};
#endif

/* radare - LGPL - Copyright 2008-2016,2022 - pancake */

#include <r_lib.h>
#include <r_arch.h>
#include "./dis.c"

static int label_off(struct directive *d) {
	int off = d->d_operand;
	int lame = off & 0x80;

	if (!d->d_prefix) { // WTF
		off = (char) (off & 0xff);
	} else if (d->d_prefix == 1) {
		off = (short) (off & 0xffff);
		if (lame) {
			off -= 0x100;
		}
	} else {
		off = (int) (off & 0xffffff);
		if (off & 0x800000) {
			off |= 0xff000000;
		}
		if (off & 0x8000) {
			off -= 0x10000;
		}
		if (lame) {
			off -= 0x100;
		}
	}
	return d->d_off + off;
}

static inline int fix_jump_address(int jump) {
	return (jump & 1)? jump + 3: jump;
}

static inline ut16 i2ut16(struct instruction *in) {
	return *((uint16_t *)in);
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const ut8 *bytes = op->bytes;
	struct instruction *in = (struct instruction *)bytes;
	ut16 lol, ins;
	struct directive d = { { 0 } };
	struct state s = { 0 };

	if (!op) {
		return 2;
	}

	memcpy (&ins, bytes, sizeof (ins));
	lol = ins;
	s.s_buf = (void *)bytes;
	s.s_off = addr;
	s.s_out = NULL;
	s.s_prefix = 0;
	memset (&d, 0, sizeof (struct directive));
	d.d_inst = *((struct instruction *)s.s_buf);
	s.s_off += 2;
	d.d_off = s.s_off;
	xap_decode (&s, &d);
	d.d_operand = get_operand (&s, &d);

	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = 2;

	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = r_str_ndup (d.d_asm, sizeof (d.d_asm));
	}

	switch (i2ut16 (in)) {
	case INST_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case INST_BRK:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case INST_BC:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case INST_BRXL:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	default:
		switch (in->in_opcode) {
		case 0:
			switch (lol & 0xf) {
			case 1:
			case 2:
			case 3:
			case 0xa:
				op->type = R_ANAL_OP_TYPE_PUSH;
				break;
			case 4:
			case 5:
			case 6:
			case 7:
			case 0xe:
				op->type = R_ANAL_OP_TYPE_POP;
				break;
			}
			break;
		case 1:
			op->type = R_ANAL_OP_TYPE_POP;
			break;
		case 2:
			op->type = R_ANAL_OP_TYPE_PUSH;
			break;
		case 3:
		case 4:
		case 7:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 5:
		case 6:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 8:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case 9:
			switch (in->in_reg) {
			case 0:
				op->type = R_ANAL_OP_TYPE_MUL;
				break;
			case 1:
				op->type = R_ANAL_OP_TYPE_DIV;
				break;
			case 2:
				op->type = R_ANAL_OP_TYPE_CMP;
				break;
			case 3:
				// BSR
				op->type = R_ANAL_OP_TYPE_CALL;
				op->jump = fix_jump_address (label_off (&d));
				op->fail = addr + 2;
				op->eob = true;
				break;
			}
			break;
		case 0xb:
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case 0xc:
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case 0xd:
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case 0xe:
			switch (in->in_reg) {
			case 0: // BRA
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = fix_jump_address (label_off (&d) + 4);
				op->eob = true;
				break;
			case 1:
				// BLT
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = fix_jump_address (label_off (&d));
				op->fail = addr + 2;
				op->eob = true;
				break;
			case 2:
				// BPL
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = fix_jump_address (label_off (&d));
				op->fail = addr + 2;
				op->eob = true;
				break;
			case 3:
				// BMI
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = fix_jump_address (label_off (&d));
				op->fail = addr + 2;
				op->eob = true;
				break;
			}
			break;
		case 0xf:
			switch (in->in_reg) {
			case 0: // BNE
			case 1: // BEQ
			case 2: // BCC
			case 3: // BCS
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = fix_jump_address (label_off (&d));
				op->fail = addr + 2;
				break;
			}
			break;
		}
		break;
	}
	return op->size;
}

const RArchPlugin r_arch_plugin_xap = {
	.meta = {
		.name = "xap",
		.desc = "Cambridge Consultants RISC XAP 32-bit Signal Processing",
		.license = "LGPL-3.0-only",
		.author = "pancake",
	},
	.arch = "xap",
	.bits = R_SYS_BITS_PACK2 (16, 32),
	.endian = R_SYS_ENDIAN_LITTLE,
	.decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_xap,
	.version = R2_VERSION
};
#endif

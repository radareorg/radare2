/* radare - LGPL - Copyright 2012-2016 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#define ARC_REG_ILINK1 0x1d
#define ARC_REG_ILINK2 0x1e
#define ARC_REG_BLINK 0x1f
#define ARC_REG_LIMM 0x3e
#define ARC_REG_PCL 0x3f

/* the CPU fields that we decode get stored in this struct */
typedef struct arc_fields_t {
	ut8 opcode;    /* major opcode */
	ut8 subopcode; /* sub opcode */
	ut8 format;    /* operand format */
	ut8 format2;
	ut8 cond;
	ut16 a; /* destination register */
	ut16 b; /* source/destination register */
	ut16 c; /* source/destintaion register */
	ut8 mode_aa;
	ut8 mode_zz;
	ut8 mode_m;
	ut8 mode_n; /* Delay slot flag */
	st64 imm;   /* data stored in the opcode */
	st64 limm;  /* data stored immediately following the opcode */
} arc_fields;

static void arccompact_dump_fields(ut64 addr, ut32 words[2], arc_fields *f) {
#if DEBUG
	/* Quick and dirty debug print */
	eprintf ("DEBUG: 0x%04llx: %08x op=0x%x subop=0x%x format=0x%x fields.a=0x%x fields.b=0x%x fields.c=0x%x imm=%i limm=%lli\n",
		addr, words[0], f->opcode, f->subopcode, f->format, f->a, f->b, f->c, f->imm, f->limm);
#endif
}

/* For (arguably valid) reasons, the ARCompact CPU uses "middle endian"
	encoding on Little-Endian systems
 */
static inline ut32 r_read_me32_arc(const void *src) {
	const ut8 *s = src;
	return (((ut32)s[1]) << 24) | (((ut32)s[0]) << 16) | (((ut32)s[3]) << 8) | (((ut32)s[2]) << 0);
}

static int sex(int bits, int imm) {
	int maxsint = (1 << (bits - 1)) - 1;
	int maxuint = (1 << (bits)) - 1;

	if (imm > maxsint) {
		/* sign extend */
		imm = -maxuint + imm - 1;
	}
	return imm;
}

#define SEX_S7(imm) sex (7, imm);
#define SEX_S8(imm) sex (8, imm);
#define SEX_S9(imm) sex (9, imm);
#define SEX_S10(imm) sex (10, imm);
#define SEX_S12(imm) sex (12, imm);
#define SEX_S13(imm) sex (13, imm);
#define SEX_S21(imm) sex (21, imm);
#define SEX_S25(imm) sex (25, imm);

static int map_cond2radare(ut8 cond) {
	switch (cond) {
	case 0: return R_ANAL_COND_AL;
	case 1: return R_ANAL_COND_EQ;
	case 2: return R_ANAL_COND_NE;
	case 3: return R_ANAL_COND_PL;
	case 4: return R_ANAL_COND_MI;
	case 7: return R_ANAL_COND_VS;
	case 8: return R_ANAL_COND_VC;
	case 9: return R_ANAL_COND_GT;
	case 0xa: return R_ANAL_COND_GE;
	case 0xb: return R_ANAL_COND_LT;
	case 0xc: return R_ANAL_COND_LE;
	case 0xd: return R_ANAL_COND_HI;
	case 0xe: return R_ANAL_COND_LS;
#if 0
	/* TODO: */
	/* - radare defines R_ANAL_COND_LO as carry clear and _HS as carry set */
	/*   which appears different to the ARC definitions. */
	/*   Need to do some math and double check the details */
	case 5: return R_ANAL_COND_?? - CS,C,LO - Carry set & LO
	case 6: return R_ANAL_COND_?? - CC,NC,HS - Carry clear & HS
	/* - Positive non-zero doesnt map to any Radare cond code.  Perhaps just add it? */
	case 0xf: return R_ANAL_COND_?? - PNZ - Positive non-zero
#endif
	}
	return -1;
}

static void arcompact_jump(RAnalOp *op, ut64 addr, ut64 jump, ut8 delay) {
	op->jump = jump;
	op->fail = addr + op->size;
	op->delay = delay;
}

static void arcompact_jump_cond(RAnalOp *op, ut64 addr, ut64 jump, ut8 delay, ut8 cond) {
	arcompact_jump (op, addr, jump, delay);
	op->cond = map_cond2radare (cond);
}

static void arcompact_branch(RAnalOp *op, ut64 addr, st64 offset, ut8 delay) {
	arcompact_jump (op, addr, (addr & ~3) + offset, delay);
}

static void map_zz2refptr(RAnalOp *op, ut8 mode_zz) {
	switch (mode_zz) {
	case 0: op->refptr = 4; break;
	case 1: op->refptr = 1; break;
	case 2: op->refptr = 2; break;
	default:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	}
}

static int arcompact_genops_jmp(RAnalOp *op, ut64 addr, arc_fields *f, ut64 basic_type) {
	ut64 type_ujmp;
	ut64 type_cjmp;
	ut64 type_ucjmp;

	switch (basic_type) {
	case R_ANAL_OP_TYPE_JMP:
		type_ujmp = R_ANAL_OP_TYPE_UJMP;
		type_cjmp = R_ANAL_OP_TYPE_CJMP;
		type_ucjmp = R_ANAL_OP_TYPE_UCJMP;
		break;
	case R_ANAL_OP_TYPE_CALL:
		type_ujmp = R_ANAL_OP_TYPE_UCALL;
		type_cjmp = R_ANAL_OP_TYPE_CCALL;
		type_ucjmp = R_ANAL_OP_TYPE_UCCALL;
		break;
	default:
		return -1; /* Should not happen */
	}

	f->cond = f->a & 0x1f;

	switch (f->format) {
	case 0: /* unconditional jumps via reg or long imm */
		if (f->c == ARC_REG_LIMM) {
			/* limm */
			op->type = basic_type;
			arcompact_jump (op, addr, f->limm, f->mode_n);
			return op->size;
		}
		if (f->c == ARC_REG_ILINK1 || f->c == ARC_REG_ILINK2 || f->c == ARC_REG_BLINK) {
			/* ilink1, ilink2, blink */
			/* Note: not valid for basic_type == CALL */
			op->type = R_ANAL_OP_TYPE_RET;
			op->delay = f->mode_n;
			return op->size;
		}
		op->type = type_ujmp;
		return op->size;
	case 1: /* unconditional jumps via u6 imm */
		op->type = basic_type;
		arcompact_jump (op, addr, f->c, f->mode_n);
		return op->size;
	case 2: /* unconditional jumps via s12 imm */
		op->type = basic_type;
		f->imm = (f->a << 6 | f->c);
		f->imm = SEX_S12 (f->imm);
		arcompact_jump (op, addr, f->imm, f->mode_n);
		return op->size;
	case 3: /* conditional jumps */
		if (f->mode_m == 0) {
			if (f->c == ARC_REG_LIMM) {
				op->type = type_cjmp;
				arcompact_jump_cond (op, addr, f->limm, f->mode_n, f->cond);
				return op->size;
			}
			if (f->c == ARC_REG_ILINK1 || f->c == ARC_REG_ILINK2 || f->c == ARC_REG_BLINK) {
				/* ilink1, ilink2, blink */
				/* Note: not valid for basic_type == CALL */
				op->type = R_ANAL_OP_TYPE_CRET;
				op->cond = map_cond2radare (f->cond);
				op->delay = f->mode_n;
				return op->size;
			}

			op->cond = map_cond2radare (f->cond);
			op->type = type_ucjmp;
			return op->size;
		}

		op->type = type_cjmp;
		arcompact_jump_cond (op, addr, f->c, f->mode_n, f->cond);
		return op->size;
	}

	/* should not be reached */
	return 0;
}

static int arcompact_genops(RAnalOp *op, ut64 addr, ut32 words[2]) {
	arc_fields fields = {0};

	fields.format = (words[0] & 0x00c00000) >> 22;
	fields.subopcode = (words[0] & 0x003f0000) >> 16;
	fields.c = (words[0] & 0x00000fc0) >> 6;
	fields.a = (words[0] & 0x0000003f);
	fields.b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;
	fields.mode_n = 0;

	/* increase the size to cover any limm reg fields */
	if (fields.b == ARC_REG_LIMM) {
		op->size = 8;
		fields.limm = words[1];
		/* FIXME: MOV<.f> 0,x is encoded as fields.b == ARC_REG_LIMM, but no limm */
	} else if ((fields.format == 0 || fields.format == 1) && (fields.a == ARC_REG_LIMM)) {
		op->size = 8;
		fields.limm = words[1];
	} else if ((fields.format == 0) && (fields.c == ARC_REG_LIMM)) {
		op->size = 8;
		fields.limm = words[1];
	} else if ((fields.format == 3) && ((fields.a & 0x20) == 0x20) && (fields.c == ARC_REG_LIMM)) {
		op->size = 8;
		fields.limm = words[1];
	}

	if (fields.format == 1) {
		/* REG_U6IMM */
		fields.imm = fields.c;
	} else if (fields.format == 2) {
		/* REG_S12IMM */
		fields.imm = SEX_S12 (fields.c | fields.a << 6);
	}

	switch (fields.subopcode) {
	case 0x00: /* add */
		if ((fields.format == 1 || fields.format == 2) && fields.b == ARC_REG_PCL) {
			/* dst = PCL + src */
			op->ptr = (addr & ~3) + fields.imm;
			op->refptr = 1; /* HACK! we don't actually know what size it is */
		}
	case 0x01: /* add with carry */
	case 0x14: /* add with left shift by 1 */
	case 0x15: /* add with left shift by 2 */
	case 0x16: /* add with left shift by 3 */
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x02: /* subtract */
	case 0x03: /* subtract with carry */
	case 0x0e: /* reverse subtract */
	case 0x17: /* subtract with left shift by 1 */
	case 0x18: /* subtract with left shift by 2 */
	case 0x19: /* subtract with left shift by 3 */
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x04: /* logical bitwise AND */
	case 0x06: /* logical bitwise AND with invert */
	case 0x10: /* bit clear */
	case 0x13: /* bit mask */
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case 0x05: /* logical bitwise OR */
	case 0x0f: /* bit set */
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case 0x07: /* logical bitwise exclusive-OR */
	case 0x12: /* bit xor */
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case 0x08: /* larger of 2 signed integers */
	case 0x09: /* smaller of 2 signed integers */
		op->type = R_ANAL_OP_TYPE_CMOV;
		break;
	case 0x0a: /* move */
		if (fields.format == 2) {
			op->type = R_ANAL_OP_TYPE_MOV;
			op->val = SEX_S12 (fields.a << 6 | fields.c);
		} else if (fields.format == 3) {
			fields.cond = fields.a & 0x1f;
			op->cond = map_cond2radare (fields.cond);
			op->type = R_ANAL_OP_TYPE_CMOV;
			if ((fields.a & 0x20)) {
				/* its a move from imm u6 */
				op->val = fields.c;
			} else if (fields.c == ARC_REG_LIMM) {
				/* its a move from limm */
				op->val = fields.limm;
			}
		}
		break;
	case 0x0b: /* test */
	case 0x0c: /* compare */
	case 0x0d: /* reverse compare */
	case 0x11: /* bit test */
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 0x1a: /* 32 X 32 signed multiply */
	case 0x1b: /* 32 X 32 signed multiply */
	case 0x1c: /* 32 X 32 unsigned multiply */
	case 0x1d: /* 32 X 32 unsigned multiply */
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case 0x21: /* Jump with delay slot */
		fields.mode_n = 1;
	/* fall through */
	case 0x20: /* Jump */
		fields.mode_m = (words[0] & 0x20) >> 5;
		arcompact_genops_jmp (op, addr, &fields, R_ANAL_OP_TYPE_JMP);
		break;
	case 0x23: /* jump and link with delay slot */
		fields.mode_n = 1;
	/* fall through */
	case 0x22: /* jump and link */
		fields.mode_m = (words[0] & 0x20) >> 5;
		arcompact_genops_jmp (op, addr, &fields, R_ANAL_OP_TYPE_CALL);
		break;
	case 0x1e: /* Reserved */
	case 0x1f: /* Reserved */
	case 0x24: /* Reserved */
	case 0x25: /* Reserved */
	case 0x26: /* Reserved */
	case 0x27: /* Reserved */
	case 0x2c: /* Reserved */
	case 0x2d: /* Reserved */
	case 0x2e: /* Reserved */
	case 0x38: /* Reserved */
	case 0x39: /* Reserved */
	case 0x3a: /* Reserved */
	case 0x3b: /* Reserved */
	case 0x3c: /* Reserved */
	case 0x3d: /* Reserved */
	case 0x3e: /* Reserved */
	case 0x3f: /* Reserved */
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case 0x28: /* loop (16-bit aligned target address) */
		/* this is essentially a COME FROM instruction!! */
		/* TODO: describe it to radare better? */
		switch (fields.format) {
		case 2: /* Loop Set Up (Unconditional) */
			fields.imm = SEX_S13 ((fields.c | (fields.a << 6)) << 1);
			op->jump = (addr & ~3) + fields.imm;
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			break;
		case 3: /* Loop Set Up (Conditional) */
			fields.imm = fields.c << 1;
			fields.cond = fields.a & 0x1f;
			op->cond = map_cond2radare (fields.a & 0x1f);
			op->jump = (addr & ~3) + fields.imm;
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			break;
		default:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		}
		break;
	case 0x29: /* set status flags */
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0x2a: /* load from auxiliary register. */
	case 0x2b: /* store to auxiliary register. */
		op->type = R_ANAL_OP_TYPE_IO;
		break;
	case 0x2f: /* Single Operand Instructions, 0x04, [0x2F, 0x00 - 0x3F] */
		switch (fields.a) {
		case 0: /* Arithmetic shift left by one */
			op->type = R_ANAL_OP_TYPE_SAL;
			break;
		case 1: /* Arithmetic shift right by one */
			op->type = R_ANAL_OP_TYPE_SAR;
			break;
		case 2: /* Logical shift right by one */
			op->type = R_ANAL_OP_TYPE_SHR;
			break;
		case 3: /* Rotate right */
		case 4: /* Rotate right through carry */
			op->type = R_ANAL_OP_TYPE_ROR;
			break;
		case 5: /* Sign extend byte */
		case 6: /* Sign extend word */
		case 7: /* Zero extend byte */
		case 8: /* Zero extend word */
			// op->type = R_ANAL_OP_TYPE_UNK;
			op->type = R_ANAL_OP_TYPE_MOV;
			/* TODO: a better encoding for SEX and EXT instructions */
			break;
		case 9: /* Absolute */
			op->type = R_ANAL_OP_TYPE_ABS;
			break;
		case 0xa: /* Logical NOT */
			op->type = R_ANAL_OP_TYPE_NOT;
			break;
		case 0xb: /* Rotate left through carry */
			op->type = R_ANAL_OP_TYPE_ROL;
			break;
		case 0xc: /* Atomic Exchange */
			op->type = R_ANAL_OP_TYPE_XCHG;
			break;
		case 0x3f: /* See Zero operand (ZOP) table */
			switch (fields.b) {
			case 1: /* Sleep */
				/* TODO: a better encoding for this */
				op->type = R_ANAL_OP_TYPE_NULL;
				break;
			case 2: /* Software interrupt */
				op->type = R_ANAL_OP_TYPE_SWI;
				break;
			case 3: /* Wait for all data-based memory transactions to complete */
				/* TODO: a better encoding for this */
				op->type = R_ANAL_OP_TYPE_NULL;
				break;
			case 4: /* Return from interrupt/exception */
				op->type = R_ANAL_OP_TYPE_RET;
				break;
			case 5: /* Breakpoint instruction */
				op->type = R_ANAL_OP_TYPE_TRAP;
				break;
			default:
				op->type = R_ANAL_OP_TYPE_ILL;
				break;
			}
			break;
		default:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		}
		break;
	case 0x30:
	case 0x31:
	case 0x32:
	case 0x33:
	case 0x34:
	case 0x35:
	case 0x36:
	case 0x37: /* Load Register-Register, 0x04, [0x30 - 0x37] */
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	}

	arccompact_dump_fields (addr, words, &fields);
	return op->size;
}

static int arcompact_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	ut32 words[2]; /* storage for the de-swizled opcode data */
	arc_fields fields;

	/* ARCompact ISA, including */
	/* ARCtangent-A5, ARC 600, ARC 700 */

	/* no unaligned code */
	if (addr % 2 != 0) {
		/* this fixes some of the reverse disassembly issues */
		op->type = R_ANAL_OP_TYPE_ILL;
		return 0;
	}
	if (len < 8) {
		//when r_read_me32_arc/be32 oob read
		return 0;
	}

	op->type = R_ANAL_OP_TYPE_UNK;
	op->ptr = UT64_MAX;
	op->val = UT64_MAX;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->refptr = 0;
	op->delay = 0;

	if (anal->big_endian) {
		words[0] = r_read_be32 (&data[0]);
		words[1] = r_read_be32 (&data[4]);
	} else {
		words[0] = r_read_me32_arc (&data[0]);
		words[1] = r_read_me32_arc (&data[4]);
	}

	fields.opcode = (words[0] & 0xf8000000) >> 27;

	op->size = (fields.opcode >= 0x0c)? 2: 4;
	op->nopcode = op->size;
// eprintf ("%x\n", fields.opcode);

	switch (fields.opcode) {
	case 0:
		fields.format = (words[0] & 0x00010000) >> 16;
		fields.a = (words[0] & 0x07fe0000) >> 17;
		fields.b = (words[0] & 0x0000ffc0) >> 6;
		fields.c = (words[0] & 0x0000000f);
		fields.mode_n = (words[0] & 0x20) >> 5;
		fields.limm = fields.a << 1 | fields.b << 11;

		if (fields.format == 0) {
			/* Branch Conditionally 0x00 [0x0] */
			fields.limm = SEX_S21 (fields.limm);
			fields.cond = (words[0] & 0x1f);
			op->cond = map_cond2radare (fields.cond);
			op->type = R_ANAL_OP_TYPE_CJMP;
		} else {
			/* Branch Unconditional Far 0x00 [0x1] */
			fields.limm |= (fields.c & 0x0f) << 21;
			/* the  & 0xf clearly shows we don't overflow */
			/* TODO: don't generate code to show this */
			fields.limm = SEX_S25 (fields.limm);
			op->type = R_ANAL_OP_TYPE_JMP;
		}
		arcompact_branch (op, addr, fields.limm, fields.mode_n);
		break;
	case 1:
		fields.format = (words[0] & 0x00010000) >> 16;
		fields.mode_n = (words[0] & 0x20) >> 5;

		if (fields.format == 1) {
			fields.format2 = (words[0] & 0x10) >> 4;
			fields.subopcode = (words[0] & 0x0f);
			fields.b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;
			fields.c = (words[0] & 0x00000fc0) >> 6;
			fields.imm = SEX_S9 ((words[0] & 0x00fe0000) >> 16 | (words[0] & 0x8000) >> 7);
			op->type = R_ANAL_OP_TYPE_CJMP;

			if (fields.format2 == 0) {
				/* Branch on Compare Register-Register, 0x01, [0x1, 0x0] */
				if (fields.b == ARC_REG_LIMM || fields.c == ARC_REG_LIMM) {
					op->size = 8;
					fields.limm = words[1];
				}
				/* TODO: cond codes (using the "br" mapping) */
			} else {
				/* Branch on Compare/Bit Test Register-Immediate, 0x01, [0x1, 0x1] */
				/* TODO: cond codes and imm u6 (using the "br" mapping) */
			}
			arcompact_branch (op, addr, fields.imm, fields.mode_n);
		} else {
			fields.format2 = (words[0] & 0x00020000) >> 17;
			fields.a = (words[0] & 0x07fc0000) >> 18;
			fields.b = (words[0] & 0x0000ffc0) >> 6;
			fields.c = (words[0] & 0x0000000f);
			fields.imm = fields.a << 2 | fields.b << 11;

			if (fields.format2 == 0) {
				/* Branch and Link Conditionally, 0x01, [0x0, 0x0] */
				fields.imm = SEX_S21 (fields.imm);
				fields.cond = (words[0] & 0x1f);
				op->cond = map_cond2radare (fields.cond);
				op->type = R_ANAL_OP_TYPE_CCALL;
			} else {
				/* Branch and Link Unconditional Far, 0x01, [0x0, 0x1] */
				fields.imm |= (fields.c & 0x0f) << 21;
				/* the  & 0xf clearly shows we don't overflow */
				/* TODO: don't generate code to show this */
				fields.imm = SEX_S25 (fields.imm);
				op->type = R_ANAL_OP_TYPE_CALL;
			}
			arcompact_branch (op, addr, fields.imm, fields.mode_n);
		}
		break;
	case 2: /* Load Register with Offset, 0x02 */
		fields.a = (words[0] & 0x0000003f);
		fields.b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;
		fields.imm = SEX_S9 ((words[0] & 0x00ff0000) >> 16 | (words[0] & 0x8000) >> 7);
		/* fields.mode_aa = (words[0] & 0x600) >> 9; */
		fields.mode_zz = (words[0] & 0x180) >> 7;

		op->type = R_ANAL_OP_TYPE_LOAD;

		/* dst (fields.a) cannot be an extension core register */
		if (fields.a == ARC_REG_PCL || fields.a == 61 || (fields.a >= 0x20 && fields.a <= 0x2b)) {
			op->type = R_ANAL_OP_TYPE_ILL;
		}

		map_zz2refptr (op, fields.mode_zz);

		if (fields.b == ARC_REG_LIMM) {
			op->size = 8;
			fields.limm = words[1];
			op->ptr = fields.limm + fields.imm;
			/* fields.aa is reserved - and ignored with limm */
		} else if (fields.b == ARC_REG_PCL) { /* PCL */
			op->ptr = (addr & ~3) + fields.imm;
		}
		/* TODO: set op with GP,FP,SP src/dst details */
		break;
	case 3: /* Store Register with Offset, 0x03 */
		fields.c = (words[0] & 0xfc0) >> 6;
		fields.b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;
		fields.imm = SEX_S9 ((words[0] & 0x00ff0000) >> 16 | (words[0] & 0x8000) >> 7);
		/* ut8 mode_aa = (words[0] & 0x18) >> 3; */
		fields.mode_zz = (words[0] & 0x6) >> 1;

		op->type = R_ANAL_OP_TYPE_STORE;

		map_zz2refptr (op, fields.mode_zz);

		if (fields.b == ARC_REG_LIMM) {
			op->size = 8;
			fields.limm = words[1];
			op->ptr = fields.limm;
		} else if (fields.c == ARC_REG_LIMM) {
			op->size = 8;
			fields.limm = words[1];
			op->val = fields.limm;
		}

		if (fields.b == ARC_REG_PCL) { /* PCL */
			op->ptr = (addr & ~3) + fields.imm;
		}
		/* TODO: set op with GP,FP,SP src/dst details */
		break;
	case 4: /* General Operations */
		op->type = R_ANAL_OP_TYPE_MOV;
		return arcompact_genops (op, addr, words);
	case 5:
	case 6:
	case 7:
	case 8: /* 32-bit Extension Instructions, 0x05 - 0x08 */
		fields.subopcode = (words[0] & 0x003f0000) >> 16;
		fields.format = (words[0] & 0x00c00000) >> 22;
		fields.c = (words[0] & 0x00000fc0) >> 6;
		fields.a = (words[0] & 0x0000003f);
		fields.b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;

		if (fields.b == ARC_REG_LIMM) {
			op->size = 8;
			fields.limm = words[1];
		} else if ((fields.format == 0 || fields.format == 1) && (fields.a == ARC_REG_LIMM)) {
			op->size = 8;
			fields.limm = words[1];
		} else if ((fields.format == 0) && (fields.c == ARC_REG_LIMM)) {
			op->size = 8;
			fields.limm = words[1];
		} else if ((fields.format == 3) && ((fields.a & 0x20) == 0x20) && (fields.c == ARC_REG_LIMM)) {
			op->size = 8;
			fields.limm = words[1];
		}
		/* TODO: fill in the extansion functions */
		// op->type = R_ANAL_OP_TYPE_UNK;
		// op->type = R_ANAL_OP_TYPE_SHL;
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case 0x09:
	case 0x0a:
	case 0x0b: /* Market Specific Extension Instructions, 0x09 - 0x0B */
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case 0x0c: /* Load /Add Register-Register, 0x0C, [0x00 - 0x03] */
		op->type = R_ANAL_OP_TYPE_LOAD;
		fields.subopcode = (words[0] & 0x00180000) >> 19;
		/* fields.a	= (words[0] & 0x00070000) >> 16; */
		/* fields.c	= (words[0] & 0x00e00000) >> 21; */
		/* fields.b	= (words[0] & 0x07000000) >> 24; */

		switch (fields.subopcode) {
		case 0: /* Load long word (reg.+reg.) */
		case 1: /* Load unsigned byte (reg.+reg.) */
		case 2: /* Load unsigned word (reg.+reg.) */
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 3: /* Add */
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		}
		break;
	case 0x0d: /* Add/Sub/Shift Register-Immediate, 0x0D, [0x00 - 0x03] */
		fields.subopcode = (words[0] & 0x00180000) >> 19;
		/* fields.imm = (words[0] & 0x00070000) >> 16; src2 u3 */
		/* fields.c = (words[0] & 0x00e00000) >> 21; dst */
		/* fields.b = (words[0] & 0x07000000) >> 24; src1 */

		switch (fields.subopcode) {
		case 0: /* Add */
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 1: /* Subtract */
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 2: /* Multiple arithmetic shift left */
			op->type = R_ANAL_OP_TYPE_SHL;
			break;
		case 3: /* Multiple arithmetic shift right */
			op->type = R_ANAL_OP_TYPE_SHR;
			break;
		}
		break;
	case 0x0e: /* Mov/Cmp/Add with High Register, 0x0E, [0x00 - 0x03] */
		fields.subopcode = (words[0] & 0x00180000) >> 19;
		/* fields.b	= (words[0] & 0x07000000) >> 24; dst, src1 */
		fields.c = (words[0] & 0x00e00000) >> 21 | (words[0] & 0x00070000) >> 13; /* src2 */

		if (fields.c == ARC_REG_LIMM) {
			op->size = 6;
			op->val = (words[0] & 0x0000ffff) << 16 | (words[1] & 0xffff0000) >> 16;
		}

		switch (fields.subopcode) {
		case 0: /* Add */
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 1: /* Move */
		case 3: /* Move */
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case 2: /* Compare */
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		}
		break;
	case 0xf: /* General Register Format Instructions, 0x0F, [0x00 - 0x1F] */
		fields.subopcode = (words[0] & 0x001f0000) >> 16;
		fields.c = (words[0] & 0x00e00000) >> (16 + 5);
		fields.b = (words[0] & 0x07000000) >> (16 + 8);

		switch (fields.subopcode) {
		case 0: /* Single Operand, Jumps and Special Format Instructions, 0x0F, [0x00, 0x00 - 0x07] */
			switch (fields.c) {
			case 0: /* J_S [r]*/
				op->type = R_ANAL_OP_TYPE_UJMP;
				arcompact_jump (op, 0, 0, 0);
				break;
			case 1: /* J_S.D [r] */
				op->type = R_ANAL_OP_TYPE_UJMP;
				arcompact_jump (op, 0, 0, 1);
				break;
			case 2: /* JL_S [r] */
				op->type = R_ANAL_OP_TYPE_UCALL;
				arcompact_jump (op, 0, 0, 0);
				break;
			case 3: /* JL_S.D [r] */
				op->type = R_ANAL_OP_TYPE_UCALL;
				arcompact_jump (op, 0, 0, 1);
				break;
			case 4:
			case 5: /* Reserved - instruction error */
				op->type = R_ANAL_OP_TYPE_ILL;
				break;
			case 6: /* SUB_S.NE [b] */
				op->cond = R_ANAL_COND_NE;
				op->type = R_ANAL_OP_TYPE_SUB;
				break;
			case 7: /* Zero Operand Instructions, 0x0F, [0x00, 0x07, 0x00 - 0x07] */
				switch (fields.b) {
				case 0: /* nop_s */
					op->type = R_ANAL_OP_TYPE_NOP;
					op->size = 4;
					break;
				case 1:
				case 2:
				case 3: /* unimplemented and Reserved - instruction error */
					op->type = R_ANAL_OP_TYPE_ILL;
					break;
				case 4: /* JEQ_S [blink] */
					op->cond = R_ANAL_COND_EQ;
					op->type = R_ANAL_OP_TYPE_CRET;
					break;
				case 5: /* JNE_S [blink] */
					op->cond = R_ANAL_COND_NE;
					op->type = R_ANAL_OP_TYPE_CRET;
					break;
				case 7: /* J_S.D [blink] */
					op->delay = 1;
				/* fall through */
				case 6: /* J_S [blink] */
					op->type = R_ANAL_OP_TYPE_RET;
					break;
				}
				break;
			}
			break;
		case 1:
		case 3:
		case 8:
		case 9:
		case 0xa:
		case 0x17: /* Reserved - instruction error */
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		case 2:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 4:
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case 5:
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case 6: /* Logical bitwise AND with invert */
			/* dest = src1 AND NOT src2 */
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case 7:
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case 0xb: /* Test */
			/* no dst, b AND c */
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case 0xc:
			op->type = R_ANAL_OP_TYPE_MUL;
			break;
		case 0xd:  /* Sign extend byte */
		case 0xe:  /* Sign extend word */
		case 0xf:  /* Zero extend byte */
		case 0x10: /* Zero extend word */
		case 0x13: /* Negate */
			op->type = R_ANAL_OP_TYPE_CPL;
			break;
		case 0x11:
			op->type = R_ANAL_OP_TYPE_ABS;
			break;
		case 0x12:
			op->type = R_ANAL_OP_TYPE_NOT;
			break;
		case 0x14: /* Add with left shift by 1 */
		case 0x15: /* Add with left shift by 2 */
		case 0x16: /* Add with left shift by 3 */
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 0x18: /* Multiple arithmetic shift left */
			op->type = R_ANAL_OP_TYPE_SAL;
			break;
		case 0x19: /* Multiple logical shift right */
			op->type = R_ANAL_OP_TYPE_SHR;
			break;
		case 0x1a: /* Multiple arithmetic shift right */
			op->type = R_ANAL_OP_TYPE_SAR;
			break;
		case 0x1b: /* Arithmetic shift left by one */
			op->type = R_ANAL_OP_TYPE_SAL;
			break;
		case 0x1c: /* Arithmetic shift right by one */
			op->type = R_ANAL_OP_TYPE_SAR;
			break;
		case 0x1d: /* Logical shift right by one */
			op->type = R_ANAL_OP_TYPE_SHL;
			break;
		case 0x1e:
			op->type = R_ANAL_OP_TYPE_TRAP;
			/* TODO: the description sounds more like a */
			/* R_ANAL_OP_TYPE_SWI, but I don't know what */
			/* difference that would make to radare */
			break;
		case 0x1f:
			op->type = R_ANAL_OP_TYPE_TRAP;
			/* TODO: this should be R_ANAL_OP_TYPE_DEBUG, */
			/* but that type is commented out */
			break;
		}
		break;
	case 0x10: /* LD_S	c,[b,u7] */
	case 0x11: /* LDB_S	c,[b,u5] */
	case 0x12: /* LDW_S	c,[b,u6] */
	case 0x13: /* LDW_S.X	c,[b,u6] */
		/* Load/Store with Offset, 0x10 - 0x16 */
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case 0x14: /* ST_S	c, [b, u7] */
	case 0x15: /* STB_S c, [b, u5] */
	case 0x16: /* STW_S c, [b, u6] */
		/* Load/Store with Offset, 0x10 - 0x16 */
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case 0x17: /* Shift/Subtract/Bit Immediate, 0x17, [0x00 - 0x07] */
		fields.subopcode = (words[0] & 0x00e00000) >> (16 + 5);
		switch (fields.subopcode) {
		case 0: /* Multiple arithmetic shift left */
			op->type = R_ANAL_OP_TYPE_SAL;
			break;
		case 1: /* Multiple logical shift left */
			op->type = R_ANAL_OP_TYPE_SHL;
			break;
		case 2: /* Multiple arithmetic shift right */
			op->type = R_ANAL_OP_TYPE_SAR;
			break;
		case 3: /* Subtract */
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 4: /* Bit set */
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case 5: /* Bit clear */
		case 6: /* Bit mask */
		case 7: /* Bit test */
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		}
		break;
	case 0x18: /* Stack Pointer Based Instructions, 0x18, [0x00 - 0x07]	*/
		fields.subopcode = (words[0] & 0x00e00000) >> (16 + 5);
		switch (fields.subopcode) {
		case 0: /* Load long word sp-rel. */
		case 1: /* Load unsigned byte sp-rel. */
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 2: /* Store long word sp-rel. */
		case 3: /* Store unsigned byte sp-rel. */
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 4: /* Add */
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 5: /* Add/Subtract SP Relative, 0x18, [0x05, 0x00-0x07] */
			fields.b = (words[0] & 0x07000000) >> (16 + 8);
			switch (fields.b) {
			case 0: /* Add immediate to SP */
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			case 1: /* Subtract immediate from SP */
				op->type = R_ANAL_OP_TYPE_SUB;
				break;
			default:
				op->type = R_ANAL_OP_TYPE_ILL;
				break;
			}
			break;
		case 6: /* POP Register from Stack, 0x18, [0x06, 0x00-0x1F] */
			fields.c = (words[0] & 0x001f0000) >> 16;
			switch (fields.c) {
			case 1:    /* Pop register from stack */
			case 0x11: /* Pop blink from stack */
				op->type = R_ANAL_OP_TYPE_POP;
				break;
			default:
				op->type = R_ANAL_OP_TYPE_ILL;
				break;
			}
			break;
		case 7: /* PUSH Register to Stack, 0x18, [0x07, 0x00-0x1F] */
			fields.c = (words[0] & 0x001f0000) >> 16;
			switch (fields.c) {
			case 1:    /* Push register to stack */
			case 0x11: /* Push blink to stack */
				op->type = R_ANAL_OP_TYPE_PUSH;
				break;
			default:
				op->type = R_ANAL_OP_TYPE_ILL;
				break;
			}
			break;
		}
		break;
	case 0x19: /* Load/Add GP-Relative, 0x19, [0x00 - 0x03] */
		fields.subopcode = (words[0] & 0x06000000) >> (16 + 9);
		switch (fields.subopcode) {
		case 0: /* Load gp-relative (32-bit aligned) to r0 */
		case 1: /* Load unsigned byte gp-relative (8-bit aligned) to r0 */
		case 2: /* Load unsigned word gp-relative (16-bit aligned) to r0 */
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 3: /* Add gp-relative (32-bit aligned) to r0 */
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		}
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case 0x1a: /* Load PCL-Relative, 0x1A */
		fields.c = (words[0] & 0x00ff0000) >> 14;
		op->ptr = (addr & ~3) + fields.c;
		op->refptr = 4;
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case 0x1b: /* Move Immediate, 0x1B */
		op->val = (words[0] & 0x00ff0000) >> 16;
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0x1c: /* ADD/CMP Immediate, 0x1C, [0x00 - 0x01] */
		fields.subopcode = (words[0] & 0x00800000) >> (16 + 7);
		if (fields.subopcode == 0) {
			op->type = R_ANAL_OP_TYPE_ADD;
		} else {
			op->type = R_ANAL_OP_TYPE_CMP;
		}
		break;
	case 0x1d: /* Branch on Compare Register with Zero, 0x1D, [0x00 - 0x01] */
		/* fields.subopcode = (words[0] & 0x00800000) >> (16+7); */
		fields.imm = SEX_S8 ((words[0] & 0x007f0000) >> (16 - 1));
		/* fields.subopcode? reg NE: reg EQ; */
		op->type = R_ANAL_OP_TYPE_CJMP;
		arcompact_branch (op, addr, fields.imm, 0);
		break;
	case 0x1e: /* Branch Conditionally, 0x1E, [0x00 - 0x03] */
		fields.subopcode = (words[0] & 0x06000000) >> (16 + 9);
		fields.imm = SEX_S10 ((words[0] & 0x01ff0000) >> (16 - 1));
		switch (fields.subopcode) {
		case 0: /* B_S */
			op->type = R_ANAL_OP_TYPE_JMP;
			break;
		case 1: /* BEQ_S */
			op->cond = R_ANAL_COND_EQ;
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case 2: /* BNE_S */
			op->cond = R_ANAL_COND_NE;
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case 3: /* Bcc_S */
			op->type = R_ANAL_OP_TYPE_CJMP;
			fields.imm = SEX_S7 ((words[0] & 0x003f0000) >> (16 - 1));
			/* TODO: cond codes (looks like it is the BR table again?) */
			break;
		}
		arcompact_branch (op, addr, fields.imm, 0);
		break;
	case 0x1f: /* Branch and Link Unconditionally, 0x1F */
		fields.imm = SEX_S13 ((words[0] & 0x07ff0000) >> (16 - 2));
		op->type = R_ANAL_OP_TYPE_CALL;
		arcompact_branch (op, addr, fields.imm, 0);
		break;
	}
	arccompact_dump_fields (addr, words, &fields);
	return op->size;
}

static int arc_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	const ut8 *b = (ut8 *)data;

	if (anal->bits == 16) {
		return arcompact_op (anal, op, addr, data, len);
	}

	/* ARCtangent A4 */
	op->size = 4;
	op->fail = addr + 4;
	ut8 basecode = (len > 3)? ((b[3] & 0xf8) >> 3): 0;
	switch (basecode) {
	case 0x04: /* Branch */
	case 0x05: /* Branch with Link */
	case 0x06: /* Loop */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + 4 + ((r_read_le32 (&data[0]) & 0x07ffff80) >> (7 - 2));
		break;
	case 0x07: /* Conditional Jump and Jump with Link */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = 0;
		break;
	case 0x08:
	case 0x09:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x0a:
	case 0x0b:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x0c:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case 0x0d:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case 0x0f:
		if ((b[0] == 0xff) && (b[1] == 0xff)) {
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		}
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case 0x13:
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	default:
		break;
	}
	return op->size;
}

static int archinfo(RAnal *anal, int query) {
	if (anal->bits != 16) {
		return -1;
	}
	switch (query) {
	case R_ANAL_ARCHINFO_ALIGN:
		return 2;
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		/* all ops are at least 1 word long */
		return 2;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return 8;
	default:
		return -1;
	}
}

static int set_reg_profile(RAnal *anal) {
	if (anal->bits != 16) {
		return -1;
	}
	const char *p16 =
		"=PC	pcl\n"
		"=SP	sp\n"
		"=LR	blink\n"
		// "=BP	r27\n" // ??
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"

		"gpr	r0	.32	0	0\n"
		"gpr	r1	.32	4	0\n"
		"gpr	r2	.32	8	0\n"
		"gpr	r3	.32	12	0\n"
		"gpr	r4	.32	16	0\n"
		"gpr	r5	.32	20	0\n"
		"gpr	r6	.32	24	0\n"
		"gpr	r7	.32	28	0\n"
		"gpr	r8	.32	32	0\n"
		"gpr	r9	.32	36	0\n"
		"gpr	r10	.32	40	0\n"
		"gpr	r11	.32	44	0\n"
		"gpr	r12	.32	48	0\n"
		"gpr	r13	.32	52	0\n"
		"gpr	r14	.32	56	0\n"
		"gpr	r15	.32	60	0\n"
		"gpr	r16	.32	64	0\n"
		"gpr	r17	.32	68	0\n"
		"gpr	r18	.32	72	0\n"
		"gpr	r19	.32	76	0\n"
		"gpr	r20	.32	80	0\n"
		"gpr	r21	.32	84	0\n"
		"gpr	r22	.32	88	0\n"
		"gpr	r23	.32	92	0\n"
		"gpr	r24	.32	96	0\n"
		"gpr	r25	.32	100	0\n"
		"gpr	gp	.32	104	0\n"
		"gpr	fp	.32	108	0\n"
		"gpr	sp	.32	112	0\n"
		"gpr	ilink1	.32	116	0\n"
		"gpr	ilink2	.32	120	0\n"
		"gpr	blink	.32	124	0\n"
		"gpr	lp_count	.32	128	0\n"
		"gpr	pcl	.32	132	0\n";

	/* TODO: */
	/* Should I add the Auxiliary Register Set? */
	/* it contains the flag bits, amongst other things */
	return r_reg_set_profile_string (anal->reg, p16);
}

RAnalPlugin r_anal_plugin_arc = {
	.name = "arc",
	.arch = "arc",
	.license = "LGPL3",
	.bits = 16 | 32,
	.desc = "ARC code analysis plugin",
	.op = &arc_op,
	.archinfo = archinfo,
	.set_reg_profile = set_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_arc,
	.version = R2_VERSION,
};
#endif

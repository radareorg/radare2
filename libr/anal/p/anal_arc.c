/* radare - LGPL - Copyright 2012-2013 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#define ARC_REG_LIMM	0x3e
#define ARC_REG_ILINK1	0x1d
#define ARC_REG_ILINK2	0x1e
#define ARC_REG_BLINK	0x1f

/* the CPU fields that we decode get stored in this struct */
typedef struct arc_fields_t {
	ut8 opcode;	/* major opcode */
	ut8 subopcode;	/* sub opcode */
	ut8 format;	/* operand format */
	ut8 format2;
	ut16 a;		/* destination register */
	ut16 b;		/* source/destination register */
	ut16 c;		/* source/destintaion register */
	ut8 mode_aa;
	ut8 mode_zz;
	ut8 mode_m;
	st16 imm;
	st64 limm;
} arc_fields;

static void arccompact_dump_fields(ut64 addr, ut32 words[2], arc_fields *f) {
#if DEBUG
	/* Quick and dirty debug print */
	eprintf ("DEBUG: 0x%04llx: %08x op=0x%x subop=0x%x format=0x%x fields.a=0x%x fields.b=0x%x fields.c=0x%x imm=%i limm=%lli\n",
		addr,words[0], f->opcode,f->subopcode,f->format, f->a,f->b,f->c, f->imm,f->limm);
#endif
}


/* For (arguably valid) reasons, the ARCompact CPU uses "middle endian"
	encoding on Little-Endian systems
 */
static inline ut32 r_read_me32(const void *src) {
	const ut8 *s = src;
	return (((ut32)s[1]) << 24) | (((ut32)s[0]) << 16) |
		(((ut32)s[3]) << 8) | (((ut32)s[2]) << 0);
}

static int sex(int bits, int imm) {
	int maxsint = (1 << (bits-1))-1;
	int maxuint = (1 << (bits))-1;

	if (imm > maxsint) {
		/* sign extend */
		imm = -maxuint + imm -1;
	}
	return imm;
}

static int sex_s7(int imm) { return sex(7, imm); }
static int sex_s8(int imm) { return sex(8, imm); }
static int sex_s9(int imm) { return sex(9, imm); }
static int sex_s10(int imm) { return sex(10, imm); }
static int sex_s12(int imm) { return sex(12, imm); }
static int sex_s13(int imm) { return sex(13, imm); }
static int sex_s21(int imm) { return sex(21, imm); }
static int sex_s25(int imm) { return sex(25, imm); }

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

	switch (f->format) {
	case 0: /* unconditional jumps via reg or long imm */
		if (f->c == ARC_REG_LIMM) {
			/* limm */
			op->type = basic_type;
			op->jump = f->limm;
			op->fail = addr + op->size;
		} else if (f->c == ARC_REG_ILINK1 || f->c == ARC_REG_ILINK2 || f->c == ARC_REG_BLINK) {
			/* ilink1, ilink2, blink */
			/* Note: not valid for basic_type == CALL */
			op->type = R_ANAL_OP_TYPE_RET;
		} else {
			op->type = type_ujmp;
		}
		break;
	case 1: /* unconditional jumps via u6 imm */
		op->type = basic_type;
		op->jump = addr + f->c; /* TODO: is addr aligned? */
		op->fail = addr + op->size;
		break;
	case 2: /* unconditional jumps via s12 imm */
		op->type = basic_type;
		f->imm = (f->a << 6 | f->c);
		f->imm = sex_s12 (f->imm);
		op->jump = addr + f->imm;
		op->fail = addr + op->size;
		break;
	case 3: /* conditional jumps */
		if (f->mode_m == 0) {
			if (f->c == ARC_REG_LIMM) {
				op->type = type_cjmp;
				op->jump = f->limm;
			} else if (f->c == ARC_REG_ILINK1 || f->c == ARC_REG_ILINK2 || f->c == ARC_REG_BLINK) {
				/* ilink1, ilink2, blink */
				/* Note: not valid for basic_type == CALL */
				op->type = R_ANAL_OP_TYPE_CRET;
			} else {
				op->type = type_ucjmp;
			}
		} else {
			f->imm = f->c;
			op->type = type_cjmp;
			op->jump = addr + f->c; /* TODO: is addr aligned? */
		}

		/* TODO: cond codes */
		op->fail = addr + op->size;
		break;
	}

	return op->size;
}

static int arcompact_genops(RAnalOp *op, ut64 addr, ut32 words[2]) {
	arc_fields fields;

	fields.format = (words[0] & 0x00c00000) >> 22;
	fields.subopcode = (words[0] & 0x003f0000) >> 16;
	fields.c = (words[0] & 0x00000fc0) >> 6;
	fields.a = (words[0] & 0x0000003f);
	fields.b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;

	/* if any one of the reg fields indicates a limm value,
	   increase the size to cover it */
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
		fields.imm = sex_s12 (fields.c | fields.a << 6);
	}

	switch (fields.subopcode) {
	case 0x00: /* add */
		if ((fields.format == 1 || fields.format == 2) && fields.b == 0x3f) {
			/* dst = PCL + src */
			op->ptr = (addr & ~3) + fields.imm;
			op->refptr = 1; /* HACK! we dont actually know what size it is */
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
			op->val = sex_s12 (fields.a << 6 | fields.c);
		} else if (fields.format == 3) {
			op->type = R_ANAL_OP_TYPE_CMOV;
			/* TODO: cond codes */
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
	case 0x20: /* Jump */
	case 0x21: /* Jump with delay slot */
		fields.mode_m = (words[0] & 0x20) >> 5;
		arcompact_genops_jmp(op, addr, &fields, R_ANAL_OP_TYPE_JMP);
		break;
	case 0x22: /* jump and link */
	case 0x23: /* jump and link with delay slot */
		fields.mode_m = (words[0] & 0x20) >> 5;
		arcompact_genops_jmp(op, addr, &fields, R_ANAL_OP_TYPE_JMP);
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
		/* TODO: describe it to radare better ? */
		switch (fields.format) {
		case 2: /* Loop Set Up (Unconditional) */
			fields.imm = sex_s13 ((fields.c | (fields.a << 6)) << 1);
			op->jump = (addr & ~3) + fields.imm;
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			break;
		case 3: /* Loop Set Up (Conditional) */
			fields.imm = fields.c << 1;
			op->jump = (addr & ~3) + fields.imm;
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			/* TODO: cond codes */
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
			op->type = R_ANAL_OP_TYPE_UNK;
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
	ut32 words[2];	 /* storage for the de-swizled opcode data */
	const ut8 *b = (ut8 *)data;
	arc_fields fields;

	/* ARCompact ISA, including */
	/* ARCtangent-A5, ARC 600, ARC 700 */

	/* no unaligned code */
	if (addr % 2 != 0) {
		/* this fixes some of the reverse dissassembly issues */
		op->type = R_ANAL_OP_TYPE_ILL;
		return 0;
	}

	op->delay = 0;

	if (anal->big_endian) {
		int i;
		for (i=0; i < 8; i += 4) {
			words[i/4] = r_read_be32 (&b[i]);
		}
	} else {
		int i;
		for (i=0; i<8; i+=4) {
			words[i/4] = r_read_me32 (&b[i]);
		}
	}

	ut8 opcode = (words[0] & 0xf8000000) >> 27;

	op->size = (opcode >= 0x0c)? 2: 4;
	op->nopcode = op->size;

	switch (opcode) {
	case 0:
		fields.format = (words[0] & 0x00010000) >> 16;
		fields.a = (words[0] & 0x07fe0000) >> 17;
		fields.b = (words[0] & 0x0000ffc0) >> 6;
		fields.c = (words[0] & 0x0000000f);
		fields.limm = fields.a << 1 | fields.b << 11;

		if (fields.format == 0) {
			/* Branch Conditionally 0x00 [0x0] */
			fields.limm = sex_s21 (fields.limm);
			op->type = R_ANAL_OP_TYPE_CJMP;
			/* TODO: cond codes */
		} else {
			/* Branch Unconditional Far 0x00 [0x1] */
			fields.limm |= fields.c << 21;
			fields.limm = sex_s25 (fields.limm);
			op->type = R_ANAL_OP_TYPE_JMP;
		}
		op->jump = (addr & ~3) + fields.limm;
		op->fail = addr + op->size;
		break;
	case 1:
		fields.format = (words[0] & 0x00010000) >> 16;

		if (fields.format == 1) {
			fields.format2 = (words[0] & 0x10) >> 4;
			fields.subopcode = (words[0] & 0x0f);
			fields.b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;
			fields.c = (words[0] & 0x00000fc0) >> 6;
			fields.imm = sex_s9 ((words[0] & 0x00fe0000) >> 16 | (words[0] & 0x8000) >> 7);
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = (addr & ~3) + fields.imm;

			if (fields.format2 == 0) {
				/* Branch on Compare Register-Register, 0x01, [0x1, 0x0] */
				if (fields.b == ARC_REG_LIMM || fields.c == ARC_REG_LIMM) {
					op->size = 8;
					fields.limm = words[1];
				}
				/* TODO: cond codes */
			} else {
				/* Branch on Compare/Bit Test Register-Immediate, 0x01, [0x1, 0x1] */
				/* TODO: cond codes and imm u6 */
			}
			op->fail = addr + op->size;
		} else {
			fields.format2 = (words[0] & 0x00020000) >> 17;
			fields.a = (words[0] & 0x07fc0000) >> 18;
			fields.b = (words[0] & 0x0000ffc0) >> 6;
			fields.c = (words[0] & 0x0000000f);
			fields.limm = fields.a << 2 | fields.b << 11;

			if (fields.format2 == 0) {
				/* Branch and Link Conditionally, 0x01, [0x0, 0x0] */
				fields.limm = sex_s21 (fields.limm);
				op->type = R_ANAL_OP_TYPE_CCALL;
				/* TODO: cond codes */
			} else {
				/* Branch and Link Unconditional Far, 0x01, [0x0, 0x1] */
				fields.limm |= fields.c << 21;
				fields.limm = sex_s25 (fields.limm);
				op->type = R_ANAL_OP_TYPE_CALL;
			}
			op->jump = (addr & ~3) + fields.limm;
			op->fail = addr + op->size;
		}
		break;
	case 2: /* Load Register with Offset, 0x02 */
		fields.a = (words[0] & 0x0000003f);
		fields.b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;
		fields.imm = sex_s9 ((words[0] & 0x00ff0000) >> 16 | (words[0] & 0x8000) >> 7);
		fields.mode_aa = (words[0] & 0x600) >> 9;
		fields.mode_zz = (words[0] & 0x180) >> 7;

		op->type = R_ANAL_OP_TYPE_LOAD;

		switch (fields.mode_zz) {
		case 0: op->refptr = 4; break;
		case 1: op->refptr = 1; break;
		case 2: op->refptr = 2; break;
		default:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		}

		if (fields.b == ARC_REG_LIMM) {
			op->size = 8;
			fields.limm = words[1];

			switch (fields.mode_aa) {
			case 0: /* No Field Syntax */
				op->ptr = fields.limm+fields.imm;
				break;
			case 1: /* .A or .AW - invalid with limm */
			case 2: /* .AB - invalid with limm */
				op->type = R_ANAL_OP_TYPE_ILL;
				break;
			case 3: /* .AS */
				if (fields.mode_zz == 2) {
					op->ptr = fields.limm + (fields.imm << 1);
				} else if (fields.mode_zz == 0) {
					op->ptr = fields.limm + (fields.imm << 2);
				}
				break;
			}
		} else if (fields.b == 0x3f) { /* PCL */
			op->ptr = (addr & ~3) + fields.imm;
		}
		break;
	case 3: /* Store Register with Offset, 0x03 */
		fields.c = (words[0] & 0xfc0) >> 6;
		fields.b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;
		fields.imm = sex_s9 ((words[0] & 0x00ff0000) >> 16 | (words[0] & 0x8000) >> 7);
		/* ut8 mode_aa = (words[0] & 0x18) >> 3; */
		fields.mode_zz = (words[0] & 0x6) >> 1;

		op->type = R_ANAL_OP_TYPE_STORE;

		switch (fields.mode_zz) {
		case 0: op->refptr = 4; break;
		case 1: op->refptr = 1; break;
		case 2: op->refptr = 2; break;
		default:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		}

		if (fields.b == ARC_REG_LIMM) {
			op->size = 8;
			fields.limm = words[1];
			op->ptr = fields.limm;
		} else if (fields.c == ARC_REG_LIMM) {
			op->size = 8;
			fields.limm = words[1];
			op->val = fields.limm;
		}

		if (fields.b == 0x3f) { /* PCL */
			op->ptr = (addr & ~3) + fields.imm;
		}
		break;
	case 4: /* General Operations */
		return arcompact_genops (op,addr,words);
	case 0x05:
	case 0x06:
	case 0x07:
	case 0x08: /* 32-bit Extension Instructions, 0x05 - 0x08 */
		fields.subopcode = (words[0] & 0x003f0000) >> 16;
		fields.format = (words[0] & 0x00c00000) >> 22;
		fields.c = (words[0] & 0x00000fc0) >>	6;
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
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case 0x09:
	case 0x0a:
	case 0x0b: /* Market Specific Extension Instructions, 0x09 - 0x0B */
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case 0x0c: /* Load /Add Register-Register, 0x0C, [0x00 - 0x03] */
		fields.subopcode = (words[0] & 0x00180000) >> 19;
		/* fields.a	 = (words[0] & 0x00070000) >> 16; */
		/* fields.c	 = (words[0] & 0x00e00000) >> 21; */
		/* fields.b	 = (words[0] & 0x07000000) >> 24; */

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
		/* fields.b	 = (words[0] & 0x07000000) >> 24; dst, src1 */
		fields.c = (words[0] & 0x00e00000) >> 21 | (words[0] &0x00070000) >> 13; /* src2 */

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
		fields.c = (words[0] & 0x00e00000) >> (16+5);
		fields.b = (words[0] & 0x07000000) >> (16+8);

		switch (fields.subopcode) {
		case 0: /* Single Operand, Jumps and Special Format Instructions, 0x0F, [0x00, 0x00 - 0x07] */
			switch (fields.c) {
			case 0: /* J_S [r]*/
			case 1: /* J_S.D [r] */
				op->type = R_ANAL_OP_TYPE_UJMP;
				break;
			case 2: /* JL_S [r] */
			case 3: /* JL_S.D [r] */
				op->type = R_ANAL_OP_TYPE_UCALL;
				break;
			case 4:
			case 5: /* Reserved - instruction error */
				op->type = R_ANAL_OP_TYPE_ILL;
				break;
			case 6: /* SUB_S.NE [b] */
				op->type = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_SUB;
				break;
			case 7: /* Zero Operand Instructions, 0x0F, [0x00, 0x07, 0x00 - 0x07] */
				switch (fields.b) {
				case 0: /* nop_s */
					op->type = R_ANAL_OP_TYPE_NOP;
					break;
				case 1:
				case 2:
				case 3:	/* unimplemented and Reserved - instruction error */
					op->type = R_ANAL_OP_TYPE_ILL;
					break;
				case 4: /* JEQ_S [blink] */
				case 5: /* JNE_S [blink] */
					op->type = R_ANAL_OP_TYPE_CRET;
					break;
				case 6: /* J_S [blink] */
				case 7: /* J_S.D [blink] */
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
		case 0xd: /* Sign extend byte */
		case 0xe: /* Sign extend word */
		case 0xf: /* Zero extend byte */
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
			/* TODO: the description sounds more like a
			   R_ANAL_OP_TYPE_SWI, but I dont know what difference
			   that would make to radare */
			break;
		case 0x1f:
			op->type = R_ANAL_OP_TYPE_TRAP;
			/* TODO: this should be R_ANAL_OP_TYPE_DEBUG, but that
			   type is commented out */
			break;
		}
		break;
	case 0x10: /* LD_S		c,[b,u7] */
	case 0x11: /* LDB_S	 c,[b,u5] */
	case 0x12: /* LDW_S	 c,[b,u6] */
	case 0x13: /* LDW_S.X c,[b,u6] */
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
			fields.b = (words[0] & 0x07000000) >> (16+8);
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
			case 1: /* Pop register from stack */
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
			case 1: /* Push register to stack */
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
		fields.imm = sex_s8 ((words[0] & 0x007f0000) >> (16 - 1));
		op->jump = (addr & ~3) + fields.imm;
		op->fail = addr + op->size;
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case 0x1e: /* Branch Conditionally, 0x1E, [0x00 - 0x03] */
		fields.subopcode = (words[0] & 0x06000000) >> (16 + 9);
		fields.imm = sex_s10 ((words[0] & 0x01ff0000) >> (16 - 1));
		switch (fields.subopcode) {
		case 0: /* B_S */
			op->type = R_ANAL_OP_TYPE_JMP;
			break;
		case 1: /* BEQ_S */
		case 2: /* BNE_S */
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case 3: /* Bcc_S */
			op->type = R_ANAL_OP_TYPE_CJMP;
			fields.imm = sex_s7 ((words[0] & 0x003f0000) >> (16 - 1));
			break;
		}
		op->jump = (addr & ~3) + fields.imm;
		op->fail = addr + op->size;
		break;
	case 0x1f: /* Branch and Link Unconditionally, 0x1F */
		fields.imm = sex_s13 ((words[0] & 0x07ff0000) >> (16 - 2));
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = (addr & ~3) + fields.imm;
		op->fail = addr + op->size;
		break;
	}
	arccompact_dump_fields(addr, words, &fields);
	return op->size;
}

static int arc_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	const ut8 *b = (ut8 *)data;
	memset (op, '\0', sizeof (RAnalOp));

	if (anal->bits == 16)
		return arcompact_op (anal, op, addr, data, len);

	/* ARCtangent A4 */
	op->size = 4;
	op->fail = addr + 4;
	ut8 basecode = (b[3] & 0xf8) >> 3;
	switch (basecode) {
	case 0x04: /* Branch */
	case 0x05: /* Branch with Link */
	case 0x06: /* Loop */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + 4 + (((b[1] << 1) | (b[2] << 9) |
			((b[3] & 7) << 17) | ((b[0] & 0x80) >> 7)) << 2);
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

struct r_anal_plugin_t r_anal_plugin_arc = {
	.name = "arc",
	.arch = "arc",
	.license = "LGPL3",
	.bits = 16 | 32,
	.desc = "ARC code analysis plugin",
	.op = &arc_op
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_arc,
	.version = R2_VERSION
};
#endif

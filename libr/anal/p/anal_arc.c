/* radare - LGPL - Copyright 2012-2013 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

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

static int arcompact_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	const ut8 *b = (ut8 *)data;

        /* ARCompact ISA, including */
        /*      ARCtangent-A5, ARC 600, ARC 700 */

        /* no unaligned code */
        if (addr % 2 != 0) {
            /* this fixes some of the reverse dissassembly issues */
            op->type = R_ANAL_OP_TYPE_ILL;
            return 0;
        }

	op->delay = 0;

        ut32 words[2];   /* storage for the de-swizled opcode data */
        if (anal->big_endian) {
            int i;
            for (i=0; i<8; i+=4) {
                words[i/4] = r_read_be32(&b[i]);
            }
        } else {
            int i;
            for (i=0; i<8; i+=4) {
                words[i/4] = r_read_me32(&b[i]);
            }
        }

        ut8 opcode = (words[0] &0xf8000000) >> 27;

        if (opcode >= 0x0c) {
            op->size = 2;
        } else {
            op->size = 4;
        }

        ut8 subopcode = 0;
        ut8 format = 0;
        ut8 format2 = 0;
        ut16 field_a = 0;
        ut16 field_b = 0;
        ut16 field_c = 0;
        ut8 field_aa;
        ut8 field_zz;
        ut8 field_m;
        st16 imm;
        st64 limm;

        switch (opcode) {
        case 0:
            format = (words[0] & 0x00010000) >> 16;
            field_a = (words[0] & 0x07fe0000) >> 17;
            field_b = (words[0] & 0x0000ffc0) >> 6;
            field_c = (words[0] & 0x0000000f);
            limm = field_a << 1 | field_b << 11;

            if (format == 0) {
                /* Branch Conditionally 0x00 [0x0] */
                limm = sex_s21 (limm);
                op->type = R_ANAL_OP_TYPE_CJMP;
                /* TODO: cond codes */
            } else {
                /* Branch Unconditional Far 0x00 [0x1] */
                limm |= field_c << 21;
                limm = sex_s25 (limm);
                op->type = R_ANAL_OP_TYPE_JMP;
            }
            op->jump = (addr & ~3) + limm;
            op->fail = addr + op->size;
            break;
        case 1:
            format = (words[0] & 0x00010000) >> 16;

            if (format == 1) {
                format2 = (words[0] & 0x10) >> 4;
                subopcode = (words[0] & 0x0f);
                field_b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;
                field_c = (words[0] & 0x00000fc0) >> 6;
                imm = sex_s9 ((words[0] & 0x00fe0000) >> 16 | (words[0] & 0x8000) >> 7);
                op->type = R_ANAL_OP_TYPE_CJMP;
                op->jump = (addr & ~3) + imm;

                if (format2 == 0) {
                    /* Branch on Compare Register-Register, 0x01, [0x1, 0x0] */
                    if (field_b == 0x3e || field_c == 0x3e) {
                        op->size = 8;
                        limm = words[1];
                    }
                    /* TODO: cond codes */
                } else {
                    /* Branch on Compare/Bit Test Register-Immediate, 0x01, [0x1, 0x1] */
                    /* TODO: cond codes and imm u6 */
                }
                op->fail = addr + op->size;
            } else {
                format2 = (words[0] & 0x00020000) >> 17;
                field_a = (words[0] & 0x07fc0000) >> 18;
                field_b = (words[0] & 0x0000ffc0) >> 6;
                field_c = (words[0] & 0x0000000f);
                limm = field_a << 2 | field_b << 11;

                if (format2 == 0) {
                    /* Branch and Link Conditionally, 0x01, [0x0, 0x0] */
                    limm = sex_s21 (limm);
                    op->type = R_ANAL_OP_TYPE_CCALL;
                    /* TODO: cond codes */
                } else {
                    /* Branch and Link Unconditional Far, 0x01, [0x0, 0x1] */
                    limm |= field_c << 21;
                    limm = sex_s25 (limm);
                    op->type = R_ANAL_OP_TYPE_CALL;
                }
                op->jump = (addr & ~3) + limm;
                op->fail = addr + op->size;
            }
            break;
        case 2: /* Load Register with Offset, 0x02 */
            field_a = (words[0] & 0x0000003f);
            field_b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;
            imm = sex_s9 ((words[0] & 0x00ff0000) >> 16 | (words[0] & 0x8000) >> 7);
            field_aa = (words[0] & 0x600) >> 9;
            field_zz = (words[0] & 0x180) >> 7;

            op->type = R_ANAL_OP_TYPE_LOAD;

            switch (field_zz) {
            case 0: op->refptr = 4; break;
            case 1: op->refptr = 1; break;
            case 2: op->refptr = 2; break;
            default:
                op->type = R_ANAL_OP_TYPE_ILL;
                break;
            }

            if (field_b == 0x3e) {
                op->size = 8;
                limm = words[1];

                switch (field_aa) {
                case 0: /* No Field Syntax */
                    op->ptr = limm+imm;
                    break;
                case 1: /* .A or .AW - invalid with limm */
                case 2: /* .AB - invalid with limm */
                    op->type = R_ANAL_OP_TYPE_ILL;
                    break;
                case 3: /* .AS */
                    if (field_zz == 2) {
                        op->ptr = limm + (imm << 1);
                    } else if (field_zz == 0) {
                        op->ptr = limm + (imm << 2);
                    }
                    break;
                }
            } else if (field_b == 0x3f) { /* PCL */
                op->ptr = (addr & ~3) + imm;
            }
            break;
        case 3: /* Store Register with Offset, 0x03 */
            field_c = (words[0] & 0xfc0) >> 6;
            field_b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;
            imm = sex_s9 ((words[0] & 0x00ff0000) >> 16 | (words[0] & 0x8000) >> 7);
            /* ut8 field_aa = (words[0] & 0x18) >> 3; */
            field_zz = (words[0] & 0x6) >> 1;

            op->type = R_ANAL_OP_TYPE_STORE;

            switch (field_zz) {
            case 0: op->refptr = 4; break;
            case 1: op->refptr = 1; break;
            case 2: op->refptr = 2; break;
            default:
                op->type = R_ANAL_OP_TYPE_ILL;
                break;
            }

            if (field_b == 0x3e) {
                op->size = 8;
                limm = words[1];
                op->ptr = limm;
            } else if (field_c == 0x3e) {
                op->size = 8;
                limm = words[1];
                op->val = limm;
            }

            if (field_b == 0x3f) { /* PCL */
                op->ptr = (addr & ~3) + imm;
            }
            break;
        case 4: /* General Operations */
            format = (words[0] & 0x00c00000) >> 22;
            subopcode = (words[0] & 0x003f0000) >> 16;
            field_c = (words[0] & 0x00000fc0) >> 6;
            field_a = (words[0] & 0x0000003f);
            field_b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;

            /* if any one of the reg fields indicates a limm value,
               increase the size to cover it */
            if (field_b == 0x3e) {
                op->size = 8;
                limm = words[1];
                /* FIXME: MOV<.f> 0,x is encoded as field_b == 0x3e, but no limm */
            } else if ((format == 0 || format == 1) && (field_a == 0x3e)) {
                op->size = 8;
                limm = words[1];
            } else if ((format == 0) && (field_c == 0x3e)) {
                op->size = 8;
                limm = words[1];
            } else if ((format == 3) && ((field_a & 0x20) == 0x20) && (field_c == 0x3e)) {
                op->size = 8;
                limm = words[1];
            }

            if (format == 1) {
                /* REG_U6IMM */
                imm = field_c;
            } else if (format == 2) {
                /* REG_S12IMM */
                imm = sex_s12 (field_c | field_a << 6);
            }

            switch (subopcode) {
            case 0x00: /* add */
                if ((format == 1 || format == 2) && field_b == 0x3f) {
                    /* dst = PCL + src */
                    op->ptr = (addr & ~3) + imm;
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
                if (format == 2) {
                    op->type = R_ANAL_OP_TYPE_MOV;
                    op->val = sex_s12 (field_a << 6 | field_c);
                } else if (format == 3) {
                    op->type = R_ANAL_OP_TYPE_CMOV;
                    /* TODO: cond codes */
                    if ((field_a & 0x20) == 1) {
                        /* its a move from imm u6 */
                        op->val = field_c;
                    } else if (field_c == 0x3e) {
                        /* its a move from limm */
                        op->val = limm;
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
                switch (format) {
                case 0: /* unconditional jumps via reg or long imm */
                    if (field_c == 0x3e) {
                        /* limm */
                        op->type = R_ANAL_OP_TYPE_JMP;
                        op->jump = limm;
                        op->fail = addr + op->size;
                    } else if (field_c == 0x1d || field_c == 0x1e || field_c == 0x1f) {
                        /* ilink1, ilink2, blink */
                        op->type = R_ANAL_OP_TYPE_RET;
                    } else {
                        op->type = R_ANAL_OP_TYPE_UJMP;
                    }
                    break;
                case 1: /* unconditional jumps via u6 imm */
                    op->type = R_ANAL_OP_TYPE_JMP;
                    op->jump = addr + field_c; /* TODO: is addr aligned? */
                    op->fail = addr + op->size;
                    break;
                case 2: /* unconditional jumps via s12 imm */
                    op->type = R_ANAL_OP_TYPE_JMP;
                    imm = (field_a << 6 | field_c);
                    imm = sex_s12 (imm);
                    op->jump = addr + imm;
                    op->fail = addr + op->size;
                    break;
                case 3: /* conditional jumps */
                    field_m = (words[0] & 0x20) >> 5;
                    if (field_m == 0) {
                        if (field_c == 0x3e) {
                            op->type = R_ANAL_OP_TYPE_CJMP;
                            op->jump = limm;
                        } else if (field_c == 0x1d || field_c == 0x1e || field_c == 0x1f) {
                            /* ilink1, ilink2, blink */
                            op->type = R_ANAL_OP_TYPE_CRET;
                        } else {
                            op->type = R_ANAL_OP_TYPE_UCJMP;
                        }
                    } else {
                        imm = field_c;
                        op->type = R_ANAL_OP_TYPE_CJMP;
                        op->jump = addr + field_c; /* TODO: is addr aligned? */
                    }

                    /* TODO: cond codes */
                    op->fail = addr + op->size;
                    break;
                }
            case 0x22: /* jump and link */
            case 0x23: /* jump and link with delay slot */
                /* FIXME: DRY this code and the previous jumps .. */
                switch (format) {
                case 0: /* unconditional jumps via reg or long imm */
                    if (field_c == 0x3e) {
                        /* limm */
                        op->type = R_ANAL_OP_TYPE_CALL;
                        op->jump = limm;
                        op->fail = addr + op->size;
                    } else {
                        op->type = R_ANAL_OP_TYPE_UCALL;
                    }
                    break;
                case 1: /* unconditional jumps via u6 imm */
                    op->type = R_ANAL_OP_TYPE_CALL;
                    op->jump = addr + field_c; /* TODO: is addr aligned? */
                    op->fail = addr + op->size;
                    break;
                case 2: /* unconditional jumps via s12 imm */
                    op->type = R_ANAL_OP_TYPE_CALL;
                    imm = (field_a << 6 | field_c);
                    imm = sex_s12 (imm);
                    op->jump = addr + imm;
                    break;
                case 3: /* conditional jumps */
                    field_m = (words[0] & 0x20) >> 5;
                    if (field_m == 0) {
                        if (field_c == 0x3e) {
                            op->type = R_ANAL_OP_TYPE_CCALL;
                            op->jump = limm;
                        } else {
                            op->type = R_ANAL_OP_TYPE_UCCALL;
                        }
                    } else {
                        imm = field_c;
                        op->type = R_ANAL_OP_TYPE_CCALL;
                        op->jump = addr + field_c; /* TODO: is addr aligned? */
                    }

                    /* TODO: cond codes */
                    op->fail = addr + op->size;
                    break;
                }
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
                switch (format) {
                case 2: /* Loop Set Up (Unconditional) */
                    imm = sex_s13 ((field_c | (field_a << 6)) << 1);
                    op->jump = (addr & ~3) + imm;
                    op->type = R_ANAL_OP_TYPE_CJMP;
                    op->fail = addr + op->size;
                    break;
                case 3: /* Loop Set Up (Conditional) */
                    imm = field_c << 1;
                    op->jump = (addr & ~3) + imm;
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
                switch (field_a) {
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
                    switch (field_b) {
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
            /* 0x2f Special ops */
            }
            break;
        case 0x05:
        case 0x06:
        case 0x07:
        case 0x08: /* 32-bit Extension Instructions, 0x05 - 0x08 */
            subopcode = (words[0] & 0x003f0000) >> 16;
            format = (words[0] & 0x00c00000) >> 22;
            field_c = (words[0] & 0x00000fc0) >>  6;
            field_a = (words[0] & 0x0000003f);
            field_b = (words[0] & 0x07000000) >> 24 | (words[0] & 0x7000) >> 9;

            if (field_b == 0x3e) {
                op->size = 8;
                limm = words[1];
            } else if ((format == 0 || format == 1) && (field_a == 0x3e)) {
                op->size = 8;
                limm = words[1];
            } else if ((format == 0) && (field_c == 0x3e)) {
                op->size = 8;
                limm = words[1];
            } else if ((format == 3) && ((field_a & 0x20) == 0x20) && (field_c == 0x3e)) {
                op->size = 8;
                limm = words[1];
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
            subopcode = (words[0] & 0x00180000) >> 19;
            /* field_a   = (words[0] & 0x00070000) >> 16; */
            /* field_c   = (words[0] & 0x00e00000) >> 21; */
            /* field_b   = (words[0] & 0x07000000) >> 24; */

            switch (subopcode) {
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
            subopcode = (words[0] & 0x00180000) >> 19;
            /* imm = (words[0] & 0x00070000) >> 16; src2 u3 */
            /* field_c = (words[0] & 0x00e00000) >> 21; dst */
            /* field_b = (words[0] & 0x07000000) >> 24; src1 */

            switch (subopcode) {
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
            subopcode = (words[0] & 0x00180000) >> 19;
            /* field_b   = (words[0] & 0x07000000) >> 24; dst, src1 */
            field_c = (words[0] & 0x00e00000) >> 21 | (words[0] &0x00070000) >> 13; /* src2 */

            if (field_c == 0x3e) {
                op->size = 6;
                op->val = (words[0] & 0x0000ffff) << 16 | (words[1] & 0xffff0000) >> 16;
            }

            switch (subopcode) {
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
            subopcode = (words[0] & 0x001f0000) >> 16;
            field_c = (words[0] & 0x00e00000) >> (16+5);
            field_b = (words[0] & 0x07000000) >> (16+8);

            switch (subopcode) {
            case 0: /* Single Operand, Jumps and Special Format Instructions, 0x0F, [0x00, 0x00 - 0x07] */
                switch (field_c) {
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
                    switch (field_b) {
                    case 0: /* nop_s */
                        op->type = R_ANAL_OP_TYPE_NOP;
                        break;
                    case 1:
                    case 2:
                    case 3:  /* unimplemented and Reserved - instruction error */
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
        case 0x10: /* LD_S    c,[b,u7] */
        case 0x11: /* LDB_S   c,[b,u5] */
        case 0x12: /* LDW_S   c,[b,u6] */
        case 0x13: /* LDW_S.X c,[b,u6] */
            { /* Load/Store with Offset, 0x10 - 0x16 */
            op->type = R_ANAL_OP_TYPE_LOAD;
            }
            break;
        case 0x14: /* ST_S  c, [b, u7] */
        case 0x15: /* STB_S c, [b, u5] */
        case 0x16: /* STW_S c, [b, u6] */
            { /* Load/Store with Offset, 0x10 - 0x16 */
            op->type = R_ANAL_OP_TYPE_STORE;
            }
            break;
        case 0x17: /* Shift/Subtract/Bit Immediate, 0x17, [0x00 - 0x07] */
            subopcode = (words[0] & 0x00e00000) >> (16+5);
            switch (subopcode) {
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
        case 0x18: /* Stack Pointer Based Instructions, 0x18, [0x00 - 0x07]  */
            subopcode = (words[0] & 0x00e00000) >> (16+5);
            switch (subopcode) {
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
                field_b = (words[0] & 0x07000000) >> (16+8);
                switch (field_b) {
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
                field_c = (words[0] & 0x001f0000) >> 16;
                switch (field_c) {
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
                field_c = (words[0] & 0x001f0000) >> 16;
                switch (field_c) {
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
            subopcode = (words[0] & 0x06000000) >> (16+9);
            switch (subopcode) {
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
            field_c = (words[0] & 0x00ff0000) >> 14;
            op->ptr = (addr & ~3) + field_c;
            op->refptr = 4;
            op->type = R_ANAL_OP_TYPE_LOAD;
            break;
        case 0x1b: /* Move Immediate, 0x1B */
            op->val = (words[0] & 0x00ff0000) >> 16;
            op->type = R_ANAL_OP_TYPE_MOV;
            break;
        case 0x1c: /* ADD/CMP Immediate, 0x1C, [0x00 - 0x01] */
            subopcode = (words[0] & 0x00800000) >> (16+7);
            if (subopcode == 0) {
                op->type = R_ANAL_OP_TYPE_ADD;
            } else {
                op->type = R_ANAL_OP_TYPE_CMP;
            }
            break;
        case 0x1d: /* Branch on Compare Register with Zero, 0x1D, [0x00 - 0x01] */
            /* subopcode = (words[0] & 0x00800000) >> (16+7); */
            imm = sex_s8 ((words[0] & 0x007f0000) >> (16-1));
            op->jump = (addr & ~3) + imm;
            op->fail = addr + op->size;
            op->type = R_ANAL_OP_TYPE_CJMP;
            break;
        case 0x1e: /* Branch Conditionally, 0x1E, [0x00 - 0x03] */
            subopcode = (words[0] & 0x06000000) >> (16+9);
            imm = sex_s10 ((words[0] & 0x01ff0000) >> (16-1));

            switch (subopcode) {
            case 0: /* B_S */
                op->type = R_ANAL_OP_TYPE_JMP;
                break;
            case 1: /* BEQ_S */
            case 2: /* BNE_S */
                op->type = R_ANAL_OP_TYPE_CJMP;
                break;
            case 3: /* Bcc_S */
                op->type = R_ANAL_OP_TYPE_CJMP;
                imm = sex_s7 ((words[0] & 0x003f0000) >> (16-1));
                break;
            }
            op->jump = (addr & ~3) + imm;
            op->fail = addr + op->size;
            break;
        case 0x1f: /* Branch and Link Unconditionally, 0x1F */
            imm = sex_s13 ((words[0] & 0x07ff0000) >> (16-2));
            op->type = R_ANAL_OP_TYPE_CALL;
            op->jump = (addr & ~3) + imm;
            op->fail = addr + op->size;
            break;
        }

        /* Quick and dirty debug print */
        if (getenv ("HCDEBUG")) {
            eprintf ("DEBUG: 0x%04llx: %08x op=0x%x subop=0x%x format=0x%x field_a=0x%x field_b=0x%x field_c=0x%x imm=%i limm=%lli\n",
                addr,words[0],
                opcode,subopcode,format,
                field_a,field_b,field_c,
                imm,limm
            );
        }

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
	.bits = 16|32,
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

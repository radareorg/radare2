/* Assemble V850 instructions. -- 2021-2022 - pancake
   Based on the GNU disassembler from binutils
*/

#include "v850dis.h"
#include "mybfd.h"

// TODO: delete this global
static unsigned long G_pos;

#define V850NP_EXTRACT(n) ut64 extract_##n(ut64 insn, bool *invalid)
#define V850NP_INSERT(n) ut64 insert_##n(ut64 insn, long value, const char ** errmsg)

/* Regular opcodes.  */
#define OP(x)		((x & 0x3f) << 5)
#define OP_MASK		OP (0x3f)

/* Conditional branch opcodes (Format III).  */
#define BOP(x)		((0x58 << 4) | (x & 0x0f))
#define BOP_MASK	((0x78 << 4) | 0x0f)

/* Conditional branch opcodes (Format VII).  */
#define BOP7(x)		(0x107e0 | (x & 0xf))
#define BOP7_MASK	(0x1ffe0 | 0xf)

#define one(x)		((unsigned int) (x))
#define two(x,y)	((unsigned int) (x) | ((unsigned int) (y) << 16))

static const char *not_valid    = "displacement value is not in range and is not aligned";
static const char *out_of_range = "displacement value is out of range";
static const char *not_aligned  = "displacement value is not aligned";
static const char *immediate_out_of_range = "immediate value is out of range";
static const char *branch_out_of_range = "branch value out of range";
static const char *branch_out_of_range_and_odd_offset = "branch value not in range and to odd offset";
static const char *branch_to_odd_offset = "branch to odd offset";
static const char *pos_out_of_range = "position value is out of range";
static const char *width_out_of_range = "width value is out of range";
static const char *selid_out_of_range = "SelID is out of range";
static const char *vector8_out_of_range = "vector8 is out of range";
static const char *vector5_out_of_range = "vector5 is out of range";
static const char *imm10_out_of_range = "imm10 is out of range";
static const char *sr_selid_out_of_range = "SR/SelID is out of range";

bool v850_msg_is_out_of_range(const char* msg) {
	return msg == out_of_range || msg == immediate_out_of_range || msg == branch_out_of_range;
}

static V850NP_INSERT(i5div1) {
	if (value > 30 || value < 2) {
		*errmsg = (value & 1)? not_valid: out_of_range;
	} else if (value & 1) {
		*errmsg = not_aligned;
	}
	value = (32 - value) / 2;
	return (insn | ((value << 18) & 0x3c0000));
}

static V850NP_EXTRACT(i5div1) {
	unsigned long ret = (insn & 0x003c0000) >> 18;
	ret = 32 - (ret * 2);
	*invalid = (ret > 30 || ret < 2) ? 1 : 0;
	return ret;
}

static V850NP_INSERT(i5div2) {
	if (value > 30 || value < 4) {
		*errmsg = (value & 1)? not_valid: out_of_range;
	} else if (value & 1) {
		*errmsg = not_aligned;
	}
	value = (32 - value) / 2;
	return insn | ((value << (2 + 16)) & 0x3c0000);
}

static V850NP_EXTRACT(i5div2) {
	unsigned long ret = (insn & 0x003c0000) >> (16+2);
	ret = 32 - (ret * 2);
	*invalid = (ret > 30 || ret < 4) ? 1 : 0;
	return ret;
}

static V850NP_INSERT(i5div3) {
	if (value > 32 || value < 2) {
		* errmsg = (value&1)? not_valid: out_of_range;
	} else if (value & 1) {
		* errmsg = not_aligned;
	}
	value = (32 - value)/2;
	return insn | ((value << (2+16)) & 0x3c0000);
}

static V850NP_EXTRACT(i5div3) {
	unsigned long ret = (insn & 0x003c0000) >> (16+2);
	ret = 32 - (ret * 2);
	*invalid = (ret > 32 || ret < 2) ? 1 : 0;
	return ret;
}

static V850NP_INSERT(d5_4) {
	if (value > 0x1f || value < 0) {
		*errmsg = (value&1)? not_valid: out_of_range;
	} else if (value & 1) {
		*errmsg = not_aligned;
	}
	value >>= 1;

	return insn | (value & 0x0f);
}

static V850NP_EXTRACT(d5_4) {
	return (insn & 0x0f) << 1;
}

static V850NP_INSERT(d8_6) {
	if (value > 0xff || value < 0) {
		*errmsg = (value % 4)? not_valid: out_of_range;
	} else if ((value % 4) != 0) {
		*errmsg = not_aligned;
	}
	value >>= 1;
	return insn | (value & 0x7e);
}

static V850NP_EXTRACT(d8_6) {
	unsigned long ret = (insn & 0x7e);
	ret <<= 1;
	return ret;
}

static V850NP_INSERT(d8_7) {
	if (value > 0xff || value < 0) {
		*errmsg = (value%2)? not_valid: out_of_range;
	} else if ((value % 2) != 0) {
		*errmsg = not_aligned;
	}
	value >>= 1;
	return insn | (value & 0x7f);
}

static V850NP_EXTRACT(d8_7) {
	return (insn & 0x7f) << 1;
}

static V850NP_INSERT(v8) {
	if (value > 0xff || value < 0) {
		* errmsg = immediate_out_of_range;
	}
	return insn | (value & 0x1f) | ((value & 0xe0) << (27-5));
}

static V850NP_EXTRACT(v8) {
	return (insn & 0x1f) | ((insn >> (27-5)) & 0xe0);
}

static V850NP_INSERT(d9) {
	if (value > 0xff || value < -0x100) {
		* errmsg = (value%2)? branch_out_of_range_and_odd_offset: branch_out_of_range;
	} else if ((value % 2) != 0) {
		* errmsg = branch_to_odd_offset;
	}
	return insn | ((value & 0x1f0) << 7) | ((value & 0x0e) << 3);
}

static V850NP_EXTRACT(d9) {
	signed long ret = ((insn >> 7) & 0x1f0) | ((insn >> 3) & 0x0e);
	return (ret ^ 0x100) - 0x100;
}

static V850NP_INSERT(u16_loop) {
	/* Loop displacement is encoded as a positive value,
	   even though the instruction branches backwards.  */
	if (value < 0 || value > 0xffff) {
		*errmsg = (value % 2)? branch_out_of_range_and_odd_offset: branch_out_of_range;
	} else if ((value % 2) != 0) {
		*errmsg = branch_to_odd_offset;
	}
	return insn | ((value & 0xfffe) << 16);
}

static V850NP_EXTRACT(u16_loop) {
	return (insn >> 16) & 0xfffe;
}

static V850NP_INSERT(d16_15) {
	if (value > 0x7fff || value < -0x8000) {
		*errmsg = (value % 2)? not_valid: out_of_range;
	} else if ((value % 2) != 0) {
		* errmsg = not_aligned;
	}
	return insn | ((value & 0xfffe) << 16);
}

static V850NP_EXTRACT(d16_15) {
	signed long ret = (insn >> 16) & 0xfffe;
	return (ret ^ 0x8000) - 0x8000;
}

static V850NP_INSERT(d16_16) {
	if (value > 0x7fff || value < -0x8000) {
		* errmsg = out_of_range;
	}
	return insn | ((value & 0xfffe) << 16) | ((value & 1) << 5);
}

static V850NP_EXTRACT(d16_16) {
	signed long ret = ((insn >> 16) & 0xfffe) | ((insn >> 5) & 1);
	return (ret ^ 0x8000) - 0x8000;
}

static V850NP_INSERT(d17_16) {
	if (value > 0xffff || value < -0x10000) {
		* errmsg = out_of_range;
	}
	return insn | ((value & 0xfffe) << 16) | ((value & 0x10000) >> (16 - 4));
}

static V850NP_EXTRACT(d17_16) {
	signed long ret = ((insn >> 16) & 0xfffe) | ((insn << (16 - 4)) & 0x10000);
	return (ret ^ 0x10000) - 0x10000;
}

static V850NP_INSERT(d22) {
	if (value > 0x1fffff || value < -0x200000) {
		* errmsg = (value%2)? branch_out_of_range_and_odd_offset: branch_out_of_range;
	} else if ((value % 2) != 0) {
		* errmsg = branch_to_odd_offset;
	}
	return insn | ((value & 0xfffe) << 16) | ((value & 0x3f0000) >> 16);
}

static V850NP_EXTRACT(d22) {
	signed long ret = ((insn >> 16) & 0xfffe) | ((insn << 16) & 0x3f0000);
	return (ret ^ 0x200000) - 0x200000;
}

static V850NP_INSERT(d23) {
	if (value > 0x3fffff || value < -0x400000) {
		* errmsg = out_of_range;
	}
	return insn | ((value & 0x7f) << 4) | ((value & 0x7fff80) << (16-7));
}

static V850NP_INSERT(d23_align1) {
	if (value > 0x3fffff || value < -0x400000) {
		*errmsg = (value&1)? not_valid: out_of_range;
	} else if (value & 0x1) {
		*errmsg = not_aligned;
	}
	return insn | ((value & 0x7e) << 4) | ((value & 0x7fff80) << (16 - 7));
}

static V850NP_EXTRACT(d23) {
	signed long ret = ((insn >> 4) & 0x7f) | ((insn >> (16-7)) & 0x7fff80);
	return (ret ^ 0x400000) - 0x400000;
}

static V850NP_INSERT(i9) {
	if (value > 0xff || value < -0x100) {
		* errmsg = immediate_out_of_range;
	}
	return insn | ((value & 0x1e0) << 13) | (value & 0x1f);
}

static V850NP_EXTRACT(i9) {
	signed long ret = ((insn >> 13) & 0x1e0) | (insn & 0x1f);
	return (ret ^ 0x100) - 0x100;
}

static V850NP_INSERT(u9) {
	if (value > 0x1ff) {
		* errmsg = immediate_out_of_range;
	}
	return insn | ((value & 0x1e0) << 13) | (value & 0x1f);
}

static V850NP_EXTRACT(u9) {
	return ((insn >> 13) & 0x1e0) | (insn & 0x1f);
}

static V850NP_INSERT(spe) {
	if (value != 3) {
		* errmsg = "invalid register for stack adjustment";
	}
	return insn & ~0x180000;
}

static V850NP_EXTRACT(spe) {
	return 3;
}

static V850NP_INSERT(r4) {
	if (value >= 32) {
		* errmsg = "invalid register name";
	}
	return insn | ((value & 0x01) << 23) | ((value & 0x1e) << 16);
}

static V850NP_EXTRACT(r4) {
	ut64 insn2 = insn >> 16;
	return ((insn2 & 0x0080) >> 7) | (insn2 & 0x001e);
}

static V850NP_INSERT(POS) {
	if (value > 0x1f || value < 0) {
		* errmsg = pos_out_of_range;
	}
	G_pos = (unsigned long) value;
	return insn; /* Not an oparaton until WIDTH.  */
}

static V850NP_EXTRACT(POS_U) {
	unsigned long insn2 = insn >> 16;
	return 16 + (((insn2 & 0x0800) >>  8) | ((insn2 & 0x000e) >>  1));
}

static V850NP_EXTRACT(POS_L) {
	unsigned long insn2 = insn >> 16;
	return ((insn2 & 0x0800) >>  8) | ((insn2 & 0x000e) >>  1);
}

static V850NP_INSERT(WIDTH) {
	unsigned long msb, lsb, opc;
	unsigned long msb_expand, lsb_expand;

	ut64 width = value;
	msb = (unsigned long)width + G_pos - 1;
	lsb = G_pos;
	opc = 0;
	G_pos = 0;

	if (width > 0x20 || width < 0)
		* errmsg = width_out_of_range;

	if ((msb >= 16) && (lsb >= 16)) {
		opc = 0x0090;
	} else if ((msb >= 16) && (lsb < 16)) {
		opc = 0x00b0;
	} else if ((msb < 16) && (lsb < 16)) {
		opc = 0x00d0;
	} else {
		* errmsg = width_out_of_range;
	}

	msb &= 0x0f;
	msb_expand = msb << 12;
	lsb &= 0x0f;
	lsb_expand = ((lsb & 0x8) << 8)|((lsb & 0x7) << 1);

	return (insn & 0x0000ffff) | ((opc | msb_expand | lsb_expand) << 16);
}

static V850NP_EXTRACT(WIDTH_U) {
	ut32 insn2 = insn >> 16;
	ut32 msb = ((insn2 & 0xf000) >> 12) + 16;
	ut32 lsb = (((insn2 & 0x0800) >>  8) | ((insn2 & 0x000e) >>  1)) + 16;
	return msb - lsb + 1;
}

static V850NP_EXTRACT(WIDTH_M) {
	ut32 insn2 = insn >> 16;
	ut32 msb = ((insn2 & 0xf000) >> 12) + 16;
	ut32 lsb = ((insn2 & 0x0800) >>  8) | ((insn2 & 0x000e) >> 1);
	return msb - lsb + 1;
}

static V850NP_EXTRACT(WIDTH_L) {
	ut32 insn2 = insn >> 16;
	ut32 msb = ((insn2 & 0xf000) >> 12) ;
	ut32 lsb = ((insn2 & 0x0800) >>  8) | ((insn2 & 0x000e) >>  1);
	return msb - lsb + 1;
}

static V850NP_INSERT(SELID) {
	if ((unsigned long) value > 0x1f) {
		* errmsg = selid_out_of_range;
	}
	return insn | ((value & 0x1fUL) << 27);
}

static V850NP_EXTRACT(SELID) {
	unsigned long insn2 = insn >> 16;
	return ((insn2 & 0xf800) >> 11);
}

static V850NP_INSERT(VECTOR8) {
	unsigned long vector8 = value;
	unsigned long VVV, vvvvv;

	if (vector8 > 0xff || vector8 < 0) {
		* errmsg = vector8_out_of_range;
	}
	VVV   = (vector8 & 0xe0) >> 5;
	vvvvv = (vector8 & 0x1f);

	return (insn | (VVV << 27) | vvvvv);
}

static V850NP_EXTRACT(VECTOR8) {
	unsigned long VVV,vvvvv;
	unsigned long insn2;

	insn2   = insn >> 16;
	VVV     = ((insn2 & 0x3800) >> 11);
	vvvvv   = (insn & 0x001f);
	return VVV << 5 | vvvvv;
}

static V850NP_INSERT(VECTOR5) {
	unsigned long vector5 = value;
	if (vector5 > 0x1f || vector5 < 0) {
		* errmsg = vector5_out_of_range;
	}
	ut64 vvvvv = (vector5 & 0x1f);
	return (insn | vvvvv);
}

static V850NP_EXTRACT(VECTOR5) {
	return (insn & 0x001f);
}

static V850NP_INSERT(CACHEOP) {
	unsigned long cacheop = value;
	unsigned long pp,PPPPP;

	pp    = (cacheop & 0x60) >> 5;
	PPPPP = (cacheop & 0x1f);

	return insn | (pp << 11) | (PPPPP << 27);
}

static V850NP_EXTRACT(CACHEOP) {
	unsigned long insn2 = insn >> 16;
	unsigned long PPPPP = ((insn2 & 0xf800) >> 11);
	unsigned long pp    = ((insn  & 0x1800) >> 11);
	return (pp << 5) | PPPPP;
}

static V850NP_INSERT(PREFOP) {
	ut64 PPPPP = (value & 0x1f);
	return insn | (PPPPP << 27);
}

static V850NP_EXTRACT(PREFOP) {
	ut64 insn2 = insn >> 16;
	return (insn2 & 0xf800) >> 11;
}

static V850NP_INSERT(IMM10U) {
	unsigned long imm10;
	unsigned long iiiii,IIIII;

	if (value > 0x3ff || value < 0)
		* errmsg = imm10_out_of_range;

	imm10 = ((unsigned long) value) & 0x3ff;
	IIIII = (imm10 >> 5) & 0x1f;
	iiiii =  imm10       & 0x1f;

	return insn | IIIII << 27 | iiiii;
}

static V850NP_EXTRACT(IMM10U) {
	ut64 insn2 = insn >> 16;
	ut64 IIIII = ((insn2 & 0xf800) >> 11);
	ut64 iiiii = (insn   & 0x001f);
	return (IIIII << 5) | iiiii;
}

static V850NP_INSERT(SRSEL1) {
	if (value > 0x3ff || value < 0) {
		* errmsg = sr_selid_out_of_range;
	}
	unsigned long imm10 = (unsigned long) value;
	unsigned long selid = (imm10 & 0x3e0) >> 5;
	unsigned long sr    =  imm10 & 0x1f;

	return insn | selid << 27 | sr;
}

static V850NP_EXTRACT(SRSEL1) {
	ut32 insn2 = insn >> 16;
	ut32 selid = ((insn2 & 0xf800) >> 11);
	ut32 sr    = (insn  & 0x001f);
	return (selid << 5) | sr;
}

static V850NP_INSERT(SRSEL2) {
	if (value > 0x3ff || value < 0) {
		* errmsg = sr_selid_out_of_range;
	}
	ut32 imm10 = (unsigned long) value;
	ut32 selid = (imm10 & 0x3e0) >> 5;
	ut32 sr    =  imm10 & 0x1f;
	return insn | selid << 27 | sr << 11;
}

static V850NP_EXTRACT(SRSEL2) {
	ut32 insn2 = insn >> 16;
	ut32 selid = ((insn2 & 0xf800) >> 11);
	ut32 sr    = ((insn  & 0xf800) >> 11);
	ut32 ret   = (selid << 5) | sr;
	return ret;
}

enum {
	UNUSED_R,
	R1, /* The R1 field in a format 1, 6, 7, 9, C insn.  */
	R1_NOTR0, /* As above, but register 0 is not allowed.  */
	R1_EVEN, /* Even register is allowed.  */
	R1_BANG, /* Bang (bit reverse).  */
	R1_PERCENT, /* Percent (modulo).  */
	R2, /* The R2 field in a format 1, 2, 4, 5, 6, 7, 9, C insn.  */
	R2_NOTR0, /* As above, but register 0 is not allowed.  */
	R2_EVEN, /* Even register is allowed.  */
	R2_DISPOSE, /* Reg2 in dispose instruction.  */
	R3, /* The R3 field in a format 11, 12, C insn.  */
	R3_NOTR0, /* As above, but register 0 is not allowed.  */
	R3_EVEN, /* As above, but odd number registers are not allowed.  */
	R3_EVEN_NOTR0, /* As above, but register 0 is not allowed.  */
	R4, /* Forth register in FPU Instruction.  */
	R4_EVEN, /* As above, but odd number registers are not allowed.  */
	SP, /* Stack pointer in prepare instruction.  */
	EP, /* EP Register.  */
	LIST12, /* A list of registers in a prepare/dispose instruction.  */
	OLDSR1, /* System register operands.  */
	SR1,
	OLDSR2, /* The R2 field as a system register.  */
	SR2,
	FFF, /* FPU CC bit position */
	CCCC, /* The 4 bit condition code in a setf instruction.  */
	CCCC_NOTSA,/* Condition code in adf,sdf.  */
	MOVCC, /* Condition code in conditional moves.  */
	FLOAT_CCCC, /* Condition code in FPU.  */
	VI1, /* The 1 bit immediate field in format C insn.  */
	VC1, /* The 1 bit immediate field in format C insn.  */
	DI2, /* The 2 bit immediate field in format C insn.  */
	VI2, /* The 2 bit immediate field in format C insn.  */
	VI2DUP, /* The 2 bit immediate field in format C - DUP insn.  */
	B3, /* The 3 bit immediate field in format 8 insn.  */
	DI3, /* The 3 bit immediate field in format C insn.  */
	I3U, /* The 3 bit immediate field in format C insn.  */
	I4U, /* The 4 bit immediate field in format C insn.  */
	I4U_NOTIMM0, /* The 4 bit immediate field in fetrap.  */
	D4U, /* The unsigned disp4 field in a sld.bu.  */
	I5, /* The imm5 field in a format 2 insn.  */
	I5DIV1, /* The imm5 field in a format 11 insn.  */
	I5DIV2,
	I5DIV3,
	I5U, /* The unsigned imm5 field in a format 2 insn.  */
	IMM5, /* The imm5 field in a prepare/dispose instruction.  */
	D5_4U, /* The unsigned disp5 field in a sld.hu.  */
	IMM6, /* The IMM6 field in a callt instruction.  */
	D7U, /* The signed disp7 field in a format 4 insn.  */
	D8_7U, /* The unsigned DISP8 field in a format 4 insn.  */
	D8_6U,	/* The unsigned DISP8 field in a format 4 insn.  */
	V8, /* The unsigned DISP8 field in a format 4 insn.  */
	I9, /* The imm9 field in a multiply word.  */
	U9, /* The unsigned imm9 field in a multiply word.  */
	D9, /* The DISP9 field in a format 3 insn.  */
	D9_RELAX, /* The DISP9 field in a format 3 insn, relaxable.  */
	I16, /* The imm16 field in a format 6 insn.  */
	IMM16LO, /* The signed 16 bit immediate following a prepare instruction.  */
	IMM16HI, /* The hi 16 bit immediate following a 32 bit instruction.  */
	I16U, /* The unsigned imm16 in a format 6 insn.  */
	D16, /* The disp16 field in a format 8 insn.  */
	D16_16, /* The disp16 field in an format 7 unsigned byte load insn.  */
	D16_15, /* The disp16 field in a format 6 insn.  */
	D16_LOOP, /* The unsigned DISP16 field in a format 7 insn.  */
	D17_16, /* The DISP17 field in a format 7 insn.  */
	D22, /* The DISP22 field in a format 4 insn, relaxable. (follows D9_RELAX for the assembler */
	D23,
	D23_ALIGN1,
	IMM32, /* The 32 bit immediate following a 32 bit instruction.  */
	D32_31,
	D32_31_PCREL,
	POS_U,
	POS_M,
	POS_L,
	WIDTH_U,
	WIDTH_M,
	WIDTH_L,
	SELID,
	RIE_IMM5,
	RIE_IMM4,
	VECTOR8,
	VECTOR5,
	VR1,
	VR2,
	CACHEOP,
	PREFOP,
	IMM10U
};

// order must be in sync with the enum, but msvc doesnt support indexed initializations
const struct v850_operand v850_operands[] = {
	/*UNUSED_R*/  { 0, 0, NULL, NULL, 0, BFD_RELOC_NONE },
	/*R1*/        { 5, 0, NULL, NULL, V850_OPERAND_REG, BFD_RELOC_NONE },
	/*R1_NOTR0*/  { 5, 0, NULL, NULL, V850_OPERAND_REG | V850_NOT_R0, BFD_RELOC_NONE },
	/*R1_EVEN*/   { 4, 1, NULL, NULL, V850_OPERAND_REG | V850_REG_EVEN, BFD_RELOC_NONE },
	/*R1_BANG*/   { 5, 0, NULL, NULL, V850_OPERAND_REG | V850_OPERAND_BANG, BFD_RELOC_NONE },
	/*R1_PERCENT*/{ 5, 0, NULL, NULL, V850_OPERAND_REG | V850_OPERAND_PERCENT, BFD_RELOC_NONE },
	/*R2*/        { 5, 11, NULL, NULL, V850_OPERAND_REG, BFD_RELOC_NONE },
	/*R2_NOTR0*/  { 5, 11, NULL, NULL, V850_OPERAND_REG | V850_NOT_R0, BFD_RELOC_NONE },
	/*R2_EVEN*/   { 4, 12, NULL, NULL, V850_OPERAND_REG | V850_REG_EVEN, BFD_RELOC_NONE },
        /*R2_DISPOSE*/{ 5, 16, NULL, NULL, V850_OPERAND_REG | V850_NOT_R0, BFD_RELOC_NONE },
	/*R3*/        { 5, 27, NULL, NULL, V850_OPERAND_REG, BFD_RELOC_NONE },
	/*R3_NOTR0*/  { 5, 27, NULL, NULL, V850_OPERAND_REG | V850_NOT_R0, BFD_RELOC_NONE },
	/*R3_EVEN*/   { 4, 28, NULL, NULL, V850_OPERAND_REG | V850_REG_EVEN, BFD_RELOC_NONE },
	/*R3_EVEN_NOTR0*/{ 4, 28, NULL, NULL, V850_OPERAND_REG | V850_REG_EVEN | V850_NOT_R0, BFD_RELOC_NONE },
	/*R4*/        { 5, 0, insert_r4, extract_r4, V850_OPERAND_REG, BFD_RELOC_NONE },
	/*R4_EVEN*/   { 4, 17, NULL, NULL, V850_OPERAND_REG | V850_REG_EVEN, BFD_RELOC_NONE },
	/*SP*/        { 2, 0, insert_spe, extract_spe, V850_OPERAND_REG, BFD_RELOC_NONE },
	/*EP*/        { 0, 0, NULL, NULL, V850_OPERAND_EP, BFD_RELOC_NONE },
	/*LIST12 */   { -1, 0xffe00001, NULL, NULL, V850E_OPERAND_REG_LIST, BFD_RELOC_NONE },
	/* OLDSR1 */ { 5, 0, NULL, NULL, V850_OPERAND_SRG, BFD_RELOC_NONE },
	/* SR1 */ { 0, 0, insert_SRSEL1, extract_SRSEL1, V850_OPERAND_SRG, BFD_RELOC_NONE },
	/* OLDSR2 */ { 5, 11, NULL, NULL, V850_OPERAND_SRG, BFD_RELOC_NONE },
	/* SR2 */ { 0, 0, insert_SRSEL2, extract_SRSEL2, V850_OPERAND_SRG, BFD_RELOC_NONE },
	/* FFF (SR2 + 1) */ { 3, 17, NULL, NULL, 0, BFD_RELOC_NONE },
	/* CCCC */ { 4, 0, NULL, NULL, V850_OPERAND_CC, BFD_RELOC_NONE },
	/* CCCC_NOTSA */ { 4, 17, NULL, NULL, V850_OPERAND_CC|V850_NOT_SA, BFD_RELOC_NONE },
	/* MOVCC */ { 4, 17, NULL, NULL, V850_OPERAND_CC, BFD_RELOC_NONE },
	/* FLOAT_CCCC */ { 4, 27, NULL, NULL, V850_OPERAND_FLOAT_CC, BFD_RELOC_NONE },
	/* VI1 */ { 1, 3, NULL, NULL, 0, BFD_RELOC_NONE },
	/* VC1 */ { 1, 0, NULL, NULL, 0, BFD_RELOC_NONE },
	/* DI2 */ { 2, 17, NULL, NULL, 0, BFD_RELOC_NONE },
	/* VI2 */ { 2, 0, NULL, NULL, 0, BFD_RELOC_NONE },
	/* VI2DUP */ { 2, 2, NULL, NULL, 0, BFD_RELOC_NONE },
	/* B3 */ { 3, 11, NULL, NULL, 0, BFD_RELOC_NONE },
	/* DI3 */ { 3, 17, NULL, NULL, 0, BFD_RELOC_NONE },
	/* I3U */ { 3, 0, NULL, NULL, 0, BFD_RELOC_NONE },
	/* I4U */ { 4, 0, NULL, NULL, 0, BFD_RELOC_NONE },
	/* I4U_NOTIMM0 */ { 4, 11, NULL, NULL, V850_NOT_IMM0, BFD_RELOC_NONE },
	/* D4U */ { 4, 0, NULL, NULL, V850_OPERAND_DISP, BFD_RELOC_V850_TDA_4_4_OFFSET },
	/* I5 */ { 5, 0, NULL, NULL, V850_OPERAND_SIGNED, BFD_RELOC_NONE },
	/* I5DIV1 */ { 5, 0, insert_i5div1, extract_i5div1, 0, BFD_RELOC_NONE },
	/* I5DIV2 */ { 5, 0, insert_i5div2, extract_i5div2, 0, BFD_RELOC_NONE },
	/* I5DIV3 */ { 5, 0, insert_i5div3, extract_i5div3, 0, BFD_RELOC_NONE },
	/* I5U */ { 5, 0, NULL, NULL, 0, BFD_RELOC_NONE },
	/* IMM5 */ { 5, 1, NULL, NULL, 0, BFD_RELOC_NONE },
	/* D5_4U */ { 5, 0, insert_d5_4, extract_d5_4, V850_OPERAND_DISP, BFD_RELOC_V850_TDA_4_5_OFFSET },
	/* IMM6 */ { 6, 0, NULL, NULL, 0, BFD_RELOC_V850_CALLT_6_7_OFFSET },
	/* D7U */ { 7, 0, NULL, NULL, V850_OPERAND_DISP, BFD_RELOC_V850_TDA_7_7_OFFSET },
	/* D8_7U */ { 8, 0, insert_d8_7, extract_d8_7, V850_OPERAND_DISP, BFD_RELOC_V850_TDA_7_8_OFFSET },
	/* D8_6U */ { 8, 0, insert_d8_6, extract_d8_6, V850_OPERAND_DISP, BFD_RELOC_V850_TDA_6_8_OFFSET },
	/* V8 */ { 8, 0, insert_v8, extract_v8, 0, BFD_RELOC_NONE },
	/* I9 */ { 9, 0, insert_i9, extract_i9, V850_OPERAND_SIGNED, BFD_RELOC_NONE },
	/* U9 */ { 9, 0, insert_u9, extract_u9, 0, BFD_RELOC_NONE },
	/* D9 */ { 9, 0, insert_d9, extract_d9, V850_OPERAND_SIGNED | V850_OPERAND_DISP | V850_PCREL, BFD_RELOC_V850_9_PCREL },
	/* D9_RELAX */ { 9, 0, insert_d9, extract_d9, V850_OPERAND_RELAX | V850_OPERAND_SIGNED | V850_OPERAND_DISP | V850_PCREL, BFD_RELOC_V850_9_PCREL },
	/* I16 */ { 16, 16, NULL, NULL, V850_OPERAND_SIGNED, BFD_RELOC_16 },
	/* IMM16LO */ { 16, 32, NULL, NULL, V850E_IMMEDIATE16 | V850_OPERAND_SIGNED, BFD_RELOC_LO16 },
	/* IMM16HI */ { 16, 16, NULL, NULL, V850E_IMMEDIATE16HI, BFD_RELOC_HI16 },
	/* I16U */ { 16, 16, NULL, NULL, 0, BFD_RELOC_16 },

	/* D16 */ { 16, 16, NULL, NULL, V850_OPERAND_SIGNED | V850_OPERAND_DISP, BFD_RELOC_16 },
	/* D16_16 */ { 16, 0, insert_d16_16, extract_d16_16, V850_OPERAND_SIGNED | V850_OPERAND_DISP, BFD_RELOC_V850_16_SPLIT_OFFSET },
	/* D16_15 */ { 16, 0, insert_d16_15, extract_d16_15, V850_OPERAND_SIGNED | V850_OPERAND_DISP , BFD_RELOC_V850_16_S1 },
	/* D16_LOOP */ { 16, 0, insert_u16_loop, extract_u16_loop, V850_OPERAND_RELAX | V850_OPERAND_DISP | V850_PCREL | V850_INVERSE_PCREL, BFD_RELOC_V850_16_PCREL },
	/* D17_16 */ { 17, 0, insert_d17_16, extract_d17_16, V850_OPERAND_SIGNED | V850_OPERAND_DISP | V850_PCREL, BFD_RELOC_V850_17_PCREL },
	/* D22 */ { 22, 0, insert_d22, extract_d22, V850_OPERAND_SIGNED | V850_OPERAND_DISP | V850_PCREL, BFD_RELOC_V850_22_PCREL },
	/* D23 */ { 23, 0, insert_d23, extract_d23, V850E_IMMEDIATE23 | V850_OPERAND_SIGNED | V850_OPERAND_DISP, BFD_RELOC_V850_23 },
	/* D23_ALIGN1 */ { 23, 0, insert_d23_align1, extract_d23, V850E_IMMEDIATE23 | V850_OPERAND_SIGNED | V850_OPERAND_DISP, BFD_RELOC_V850_23 },
	/* IMM32 */ { 32, 32, NULL, NULL, V850E_IMMEDIATE32, BFD_RELOC_32 },
	/* D32_31 */ { 32, 32, NULL, NULL, V850E_IMMEDIATE32 | V850_OPERAND_SIGNED | V850_OPERAND_DISP, BFD_RELOC_V850_32_ABS },
	/* D32_31_PCREL */ { 32, 32, NULL, NULL, V850E_IMMEDIATE32 | V850_OPERAND_SIGNED | V850_OPERAND_DISP | V850_PCREL, BFD_RELOC_V850_32_PCREL },
	/* POS_U */ { 0, 0, insert_POS, extract_POS_U, 0, BFD_RELOC_NONE },
	/* POS_M */ { 0, 0, insert_POS, extract_POS_L, 0, BFD_RELOC_NONE },
	/* POS_L */ { 0, 0, insert_POS, extract_POS_L, 0, BFD_RELOC_NONE },
	/* WIDTH_U */ { 0, 0, insert_WIDTH, extract_WIDTH_U, 0, BFD_RELOC_NONE },
	/* WIDTH_M */ { 0, 0, insert_WIDTH, extract_WIDTH_M, 0, BFD_RELOC_NONE },
	/* WIDTH_L */ { 0, 0, insert_WIDTH, extract_WIDTH_L, 0, BFD_RELOC_NONE },
	/* SELID */ { 5, 27, insert_SELID, extract_SELID, 0, BFD_RELOC_NONE },
	/* RIE_IMM5 */ { 5, 11, NULL, NULL, 0, BFD_RELOC_NONE },
	/* RIE_IMM4 */ { 4, 0, NULL, NULL, 0, BFD_RELOC_NONE },
	/* VECTOR8 */ { 0, 0, insert_VECTOR8, extract_VECTOR8, 0, BFD_RELOC_NONE },
	/* VECTOR5 */ { 0, 0, insert_VECTOR5, extract_VECTOR5, 0, BFD_RELOC_NONE },
	/* VR1 */ { 5, 0, NULL, NULL, V850_OPERAND_VREG, BFD_RELOC_NONE },
	/* VR2 */ { 5, 11, NULL, NULL, V850_OPERAND_VREG, BFD_RELOC_NONE },
	/* CACHEOP */ { 0, 0, insert_CACHEOP, extract_CACHEOP, V850_OPERAND_CACHEOP, BFD_RELOC_NONE },
	/* PREFOP */ { 0, 0, insert_PREFOP, extract_PREFOP, V850_OPERAND_PREFOP, BFD_RELOC_NONE },
	/* IMM10U */ { 0, 0, insert_IMM10U, extract_IMM10U, 0, BFD_RELOC_NONE },
};


/* Reg - Reg instruction format (Format I).  */
#define IF1	{R1, R2}

/* Imm - Reg instruction format (Format II).  */
#define IF2	{I5, R2}

/* Conditional branch instruction format (Format III).  */
#define IF3	{D9_RELAX}

/* 3 operand instruction (Format VI).  */
#define IF6	{I16, R1, R2}

/* 3 operand instruction (Format VI).  */
#define IF6U	{I16U, R1, R2}

/* Conditional branch instruction format (Format VII).  */
#define IF7	{D17_16}


// this array can be used for the assembler, not just the disassembler
// flag registers are: s, z, ov and cy (for sign, zero, overflow and carry

const struct v850_opcode v850_opcodes[] = {
	/* Standard instructions. */
	{ "add", OP (0x0e), OP_MASK, IF1, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_ADD, "#0,#1,+="},
	{ "add", OP (0x12), OP_MASK, IF2, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_ADD, "#0,#1,+=" },
	{ "addi", OP (0x30), OP_MASK, IF6, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_ADD, "#0,#1,+,#2,=" },
	{ "adf", two (0x07e0, 0x03a0), two (0x07e0, 0x07e1), {CCCC_NOTSA, R1, R2, R3}, 0, V850_CPU_E2_UP },
	{ "and", OP (0x0a), OP_MASK, IF1, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_AND, "#0,#1,&,#1,=,0,o,:=,$s,s,:=,$z,z,:=" },
	{ "andi", OP (0x36), OP_MASK, IF6U, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_AND, "#0,#1,&,#1,=,0,o,:=,$s,s,:=,$z,z,:=" },
	/* Signed integer. */
	{ "bge", BOP (0xe), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "s,o,^,!,?{,#0,PC,:=,}"},
	{ "bgt", BOP (0xf), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "ble", BOP (0x7), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "blt", BOP (0x6), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "s,o,^,?{,#0,PC,:=,}" },
	/* Unsigned integer. */
	{ "bh", BOP (0xb), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "bl", BOP (0x1), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "c,?{,#0,PC,:=,}" },
	{ "bnh", BOP (0x3), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "bnl", BOP (0x9), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	/* Common. */
	{ "be", BOP (0x2), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "z,?{,#0,PC,=,}" },
	{ "bne", BOP (0xa), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "z,!,?{,#0,PC,=,}" },
	/* Others. */
	{ "bc", BOP (0x1), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "c,?{,#0,PC,=,}" },
	{ "bf", BOP (0xa), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "bn", BOP (0x4), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "bnc", BOP (0x9), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "c,!,?{,#0,PC,=,}" },
	{ "bnv", BOP (0x8), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "bnz", BOP (0xa), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "bp", BOP (0xc), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "s,!,?{,#0,PC,=,}" },
	{ "br", BOP (0x5), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_JMP, "#0,PC,=" },
	{ "bsa", BOP (0xd), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "bt", BOP (0x2), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "bv", BOP (0x0), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "$o,!,?{,#0,PC,=,}" },
	{ "bz", BOP (0x2), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	/* Signed integer. */
	{ "bge", two (0x07ee, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bgt", two (0x07ef, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "ble", two (0x07e7, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "blt", two (0x07e6, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	/* Unsigned integer. */
	{ "bh", two (0x07eb, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bl", two (0x07e1, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bnh", two (0x07e3, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bnl", two (0x07e9, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	/* Common. */
	{ "be", two (0x07e2, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bne", two (0x07ea, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	/* Others. */
	{ "bc", two (0x07e1, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bf", two (0x07ea, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bn", two (0x07e4, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bnc", two (0x07e9, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bnv", two (0x07e8, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bnz", two (0x07ea, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bp", two (0x07ec, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "br", two (0x07e5, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_JMP, "#0,PC,=" },
	{ "bsa", two (0x07ed, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bt", two (0x07e2, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bv", two (0x07e0, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	{ "bz", two (0x07e2, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CJMP },
	/* Bcond disp17 Gas local alias(not defined in spec). */

	/* Signed integer. */
	{ "bge17", two (0x07ee, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bgt17", two (0x07ef, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "ble17", two (0x07e7, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "blt17", two (0x07e6, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	/* Unsigned integer. */
	{ "bh17", two (0x07eb, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bl17", two (0x07e1, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bnh17", two (0x07e3, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bnl17", two (0x07e9, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	/* Common. */
	{ "be17", two (0x07e2, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bne17", two (0x07ea, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	/* Others. */
	{ "bc17", two (0x07e1, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bf17", two (0x07ea, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bn17", two (0x07e4, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bnc17", two (0x07e9, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bnv17", two (0x07e8, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bnz17", two (0x07ea, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bp17", two (0x07ec, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "br17", two (0x07e5, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bsa17", two (0x07ed, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bt17", two (0x07e2, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bv17", two (0x07e0, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bz17", two (0x07e2, 0x0001), two (0xffef, 0x0001), IF7, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "bsh", two (0x07e0, 0x0342), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_NON0 },
	{ "bsw", two (0x07e0, 0x0340), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_NON0 },

	/* v850e3v5 bitfield instructions. */
	{ "bins", two (0x07e0, 0x0090), two (0x07e0, 0x07f1), {R1, POS_U, WIDTH_U, R2}, 0, V850_CPU_E3V5_UP },
	{ "bins", two (0x07e0, 0x00b0), two (0x07e0, 0x07f1), {R1, POS_M, WIDTH_M, R2}, 0, V850_CPU_E3V5_UP },
	{ "bins", two (0x07e0, 0x00d0), two (0x07e0, 0x07f1), {R1, POS_L, WIDTH_L, R2}, 0, V850_CPU_E3V5_UP },
	/* Gas local alias(not defined in spec). */
	{ "binsu",two (0x07e0, 0x0090), two (0x07e0, 0x07f1), {R1, POS_U, WIDTH_U, R2}, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "binsm",two (0x07e0, 0x00b0), two (0x07e0, 0x07f1), {R1, POS_M, WIDTH_M, R2}, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "binsl",two (0x07e0, 0x00d0), two (0x07e0, 0x07f1), {R1, POS_L, WIDTH_L, R2}, 0, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS },
	{ "cache", two (0xe7e0, 0x0160), two (0xe7e0, 0x07ff), {CACHEOP, R1}, 2, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_NOP },
	{ "callt", one (0x0200), one (0xffc0), {IMM6}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_UCALL },
	{ "caxi", two (0x07e0, 0x00ee), two (0x07e0, 0x07ff), {R1, R2, R3}, 1, V850_CPU_E2_UP, R_ANAL_OP_TYPE_MOV },
	{ "clr1", two (0x87c0, 0x0000), two (0xc7e0, 0x0000), {B3, D16, R1}, 3, V850_CPU_ALL },
	{ "clr1", two (0x07e0, 0x00e4), two (0x07e0, 0xffff), {R2, R1}, 3, V850_CPU_NON0 },
	{ "cmov", two (0x07e0, 0x0320), two (0x07e0, 0x07e1), {MOVCC, R1, R2, R3}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_MOV },
	{ "cmov", two (0x07e0, 0x0300), two (0x07e0, 0x07e1), {MOVCC, I5, R2, R3}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_MOV },
	{ "cmp", OP (0x0f), OP_MASK, IF1, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CMP, "#0,#1,==,$z,z,:=,$s,s,:=,$c,cy,:=" },
	{ "cmp", OP (0x13), OP_MASK, IF2, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CMP, "#0,#1,==,$z,z,:=,$s,s,:=,$c,cy,:=" },
	{ "ctret", two (0x07e0, 0x0144), two (0xffff, 0xffff), {0}, 0, V850_CPU_NON0 },
	{ "dbcp", one (0xe840), one (0xffff), {0}, 0, V850_CPU_E3V5_UP },
	{ "dbhvtrap", one (0xe040), one (0xffff), {0}, 0, V850_CPU_E3V5_UP },
	{ "dbpush", two (0x5fe0, 0x0160), two (0xffe0, 0x07ff), {R1, R3}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_PUSH },
	{ "dbret", two (0x07e0, 0x0146), two (0xffff, 0xffff), {0}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_RET },
	{ "dbtag", two (0xcfe0, 0x0160), two (0xffe0, 0x07ff), {IMM10U}, 0, V850_CPU_E3V5_UP },
	{ "dbtrap", one (0xf840), one (0xffff), {0}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_TRAP },
	{ "di", two (0x07e0, 0x0160), two (0xffff, 0xffff), {0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_SWI },
	{ "dispose", two (0x0640, 0x0000), two (0xffc0, 0x0000), {IMM5, LIST12, R2_DISPOSE},3, V850_CPU_NON0, R_ANAL_OP_TYPE_POP, "" },
	{ "dispose", two (0x0640, 0x0000), two (0xffc0, 0x001f), {IMM5, LIST12}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_POP, "" },

	{ "div", two (0x07e0, 0x02c0), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_DIV, "#2,#1,/,#2,=,#2,#1,%,#3,=" },
	{ "divh", two (0x07e0, 0x0280), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_NON0 , R_ANAL_OP_TYPE_DIV, ""},
	{ "divh", OP (0x02), OP_MASK, {R1_NOTR0, R2_NOTR0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_DIV, "" },
	{ "divhn", two (0x07e0, 0x0280), two (0x07e0, 0x07c3), {I5DIV1, R1, R2, R3}, 0, V850_CPU_NON0 | V850_CPU_OPTION_EXTENSION, R_ANAL_OP_TYPE_DIV, "" },
	{ "divhu", two (0x07e0, 0x0282), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_DIV, "" },
	{ "divhun", two (0x07e0, 0x0282), two (0x07e0, 0x07c3), {I5DIV1, R1, R2, R3}, 0, V850_CPU_NON0 | V850_CPU_OPTION_EXTENSION, R_ANAL_OP_TYPE_DIV, "" },
	{ "divn", two (0x07e0, 0x02c0), two (0x07e0, 0x07c3), {I5DIV2, R1, R2, R3}, 0, V850_CPU_NON0 | V850_CPU_OPTION_EXTENSION, R_ANAL_OP_TYPE_DIV, "" },
	{ "divq", two (0x07e0, 0x02fc), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E2_UP, R_ANAL_OP_TYPE_DIV, "" },
	{ "divqu", two (0x07e0, 0x02fe), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E2_UP, R_ANAL_OP_TYPE_DIV, "" },
	{ "divu", two (0x07e0, 0x02c2), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_DIV, "" },
	{ "divun", two (0x07e0, 0x02c2), two (0x07e0, 0x07c3), {I5DIV2, R1, R2, R3}, 0, V850_CPU_NON0 | V850_CPU_OPTION_EXTENSION, R_ANAL_OP_TYPE_DIV, "" },

	{ "dst", two (0x07e0, 0x0134), two (0xfffff, 0xffff), {0}, 0, V850_CPU_E3V5_UP },

	{ "ei", two (0x87e0, 0x0160), two (0xffff, 0xffff), {0}, 0, V850_CPU_ALL },
	{ "eiret", two (0x07e0, 0x0148), two (0xffff, 0xffff), {0}, 0, V850_CPU_E2_UP },

	{ "est", two (0x07e0, 0x0132), two (0xfffff, 0xffff), {0}, 0, V850_CPU_E3V5_UP },
	{ "feret", two (0x07e0, 0x014a), two (0xffff, 0xffff), {0}, 0, V850_CPU_E2_UP },
	{ "fetrap", one (0x0040), one (0x87ff), {I4U_NOTIMM0}, 0, V850_CPU_E2_UP },
	{ "halt", two (0x07e0, 0x0120), two (0xffff, 0xffff), {0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_TRAP },
	{ "hsh", two (0x07e0, 0x0346), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2_UP },
	{ "hsw", two (0x07e0, 0x0344), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_NON0 },
	{ "hvcall", two (0xd7e0, 0x4160), two (0xffe0, 0x41ff), {VECTOR8}, 0, V850_CPU_E3V5_UP },
	{ "hvtrap", two (0x07e0, 0x0110), two (0xffe0, 0xffff), {VECTOR5}, 0, V850_CPU_E3V5_UP },

	{ "jarl", two (0xc7e0, 0x0160), two (0xffe0, 0x07ff), {R1, R3_NOTR0}, 1, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_CALL, "PC,#1,=,#0,PC,="}, // TODO: Incorrect? PC+4, PC+6 not impl here?
	{ "jarl", two (0x0780, 0x0000), two (0x07c0, 0x0001), {D22, R2_NOTR0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CALL, "PC,#1,=,#0,PC,="},
	{ "jarl", one (0x02e0), one (0xffe0), {D32_31_PCREL, R1_NOTR0}, 0, V850_CPU_E2_UP, R_ANAL_OP_TYPE_CALL, "PC,lp,=,#0,PC,="},
	/* Gas local alias (not defined in spec). */
	{ "jarlr", two (0xc7e0, 0x0160), two (0xffe0, 0x07ff), {R1, R3_NOTR0}, 1, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_RCALL},
	/* Gas local alias of jarl imm22 (not defined in spec). */
	{ "jarl22", two (0x0780, 0x0000), two (0x07c0, 0x0001), {D22, R2_NOTR0}, 0, V850_CPU_ALL | V850_CPU_OPTION_ALIAS},
	/* Gas local alias of jarl imm32 (not defined in spec). */
	{ "jarl32", one (0x02e0), one (0xffe0), {D32_31_PCREL, R1_NOTR0}, 0, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS },
	{ "jarlw", one (0x02e0), one (0xffe0), {D32_31_PCREL, R1_NOTR0}, 0, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS },

	{ "jmp", two (0x06e0, 0x0000), two (0xffe0, 0x0001), {D32_31, R1}, 2, V850_CPU_E3V5_UP , R_ANAL_OP_TYPE_MJMP, "#1,[4],PC,:=" },
	{ "jmp", one (0x06e0), one (0xffe0), {D32_31, R1}, 2, V850_CPU_E2 | V850_CPU_E2V3, R_ANAL_OP_TYPE_MJMP, "#1,[4],PC,:=" },
	{ "jmp", one (0x0060), one (0xffe0), {R1}, 1, V850_CPU_ALL, R_ANAL_OP_TYPE_RJMP, "#1,[4],PC,:=" },
	/* Gas local alias of jmp disp22(not defined in spec). */
	{ "jmp22", one (0x0060), one (0xffe0), {R1}, 1, V850_CPU_ALL | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_JMP },
	/* Gas local alias of jmp disp32(not defined in spec). */
	{ "jmp32", one (0x06e0), one (0xffe0), {D32_31, R1}, 2, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS },
	{ "jmpw", one (0x06e0), one (0xffe0), {D32_31, R1}, 2, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS },

	{ "jr", two (0x0780, 0x0000), two (0xffc0, 0x0001), {D22}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_JMP, "#0,PC,:=" },
	{ "jr", one (0x02e0), one (0xffff), {D32_31_PCREL}, 0, V850_CPU_E2_UP, R_ANAL_OP_TYPE_JMP, "#0,PC,:=" },
	/* Gas local alias of mov imm22(not defined in spec). */
	{ "jr22", two (0x0780, 0x0000), two (0xffc0, 0x0001), {D22}, 0, V850_CPU_ALL | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_JMP, "#0,PC,:=" },
	/* Gas local alias of mov imm32(not defined in spec). */
	{ "jr32", one (0x02e0), one (0xffff), {D32_31_PCREL}, 0, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_JMP, "#0,PC,:=" },

	/* Alias of bcond (same as CA850). */
	{ "jgt", BOP (0xf), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "jge", BOP (0xe), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "jlt", BOP (0x6), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "jle", BOP (0x7), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	/* Unsigned integer. */
	{ "jh", BOP (0xb), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "jnh", BOP (0x3), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "jl", BOP (0x1), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "jnl", BOP (0x9), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	/* Common. */
	{ "je", BOP (0x2), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "z,?{,#0,PC,:=,}" },
	{ "jne", BOP (0xa), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "z,!,?{,#0,PC,:=,}" },
	/* Others. */
	{ "jv", BOP (0x0), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "jnv", BOP (0x8), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "jn", BOP (0x4), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "jp", BOP (0xc), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "jc", BOP (0x1), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "cy,?{,#0,PC,:=,}" },
	{ "jnc", BOP (0x9), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "cy,!,?{,#0,PC,:=,}" },
	{ "jz", BOP (0x2), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP , "z,?{,#0,PC,:=,}" },
	{ "jnz", BOP (0xa), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP, "z,!,?{,#0,PC,:=,}" },
	{ "jbr", BOP (0x5), BOP_MASK, IF3, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CJMP },
	{ "ldacc", two (0x07e0, 0x0bc4), two (0x07e0, 0xffff), {R1, R2}, 0, V850_CPU_E2_UP | V850_CPU_OPTION_EXTENSION, R_ANAL_OP_TYPE_LOAD },
	{ "ld.b", two (0x0700, 0x0000), two (0x07e0, 0x0000), {D16, R1, R2}, 2, V850_CPU_ALL, R_ANAL_OP_TYPE_LOAD, "#0,[1],#1,=" },
	{ "ld.b", two (0x0780, 0x0005), two (0xffe0, 0x000f), {D23, R1, R3}, 2, V850_CPU_E2_UP, R_ANAL_OP_TYPE_LOAD, "#0,[1],#1,=" },
	{ "ld.b23", two (0x0780, 0x0005), two (0x07e0, 0x000f), {D23, R1, R3}, 2, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_LOAD },
	{ "ld.bu", two (0x0780, 0x0001), two (0x07c0, 0x0001), {D16_16, R1, R2_NOTR0}, 2, V850_CPU_NON0, R_ANAL_OP_TYPE_LOAD, "#0,[1],#1,=" }, // TODO: not sure how to do unsigned in ESIL
	{ "ld.bu", two (0x07a0, 0x0005), two (0xffe0, 0x000f), {D23, R1, R3}, 2, V850_CPU_E2_UP, R_ANAL_OP_TYPE_LOAD, "#0,[1],#1,=" },
	{ "ld.bu23", two (0x07a0, 0x0005), two (0x07e0, 0x000f), {D23, R1, R3}, 2, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_LOAD },
	{ "ld.dw", two (0x07a0, 0x0009), two (0xffe0, 0x001f), {D23_ALIGN1, R1, R3_EVEN}, 2, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_LOAD },
	{ "ld.dw23", two (0x07a0, 0x0009), two (0xffe0, 0x001f), {D23_ALIGN1, R1, R3_EVEN}, 2, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_LOAD },
	{ "ld.h", two (0x0720, 0x0000), two (0x07e0, 0x0001), {D16_15, R1, R2}, 2, V850_CPU_ALL, R_ANAL_OP_TYPE_LOAD },
	{ "ld.h", two (0x0780, 0x0007), two (0x07e0, 0x000f), {D23_ALIGN1, R1, R3}, 2, V850_CPU_E2_UP, R_ANAL_OP_TYPE_LOAD },
	{ "ld.h23", two (0x0780, 0x0007), two (0x07e0, 0x000f), {D23_ALIGN1, R1, R3}, 2, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_LOAD },
	{ "ld.hu", two (0x07e0, 0x0001), two (0x07e0, 0x0001), {D16_15, R1, R2_NOTR0}, 2, V850_CPU_NON0, R_ANAL_OP_TYPE_LOAD, "#0,[2],#1,="   },
	{ "ld.hu", two (0x07a0, 0x0007), two (0x07e0, 0x000f), {D23_ALIGN1, R1, R3}, 2, V850_CPU_E2_UP, R_ANAL_OP_TYPE_LOAD, "#0,[2],#1,=" },
	{ "ld.hu23", two (0x07a0, 0x0007), two (0x07e0, 0x000f), {D23_ALIGN1, R1, R3}, 2, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_LOAD },
	{ "ld.w", two (0x0720, 0x0001), two (0x07e0, 0x0001), {D16_15, R1, R2}, 2, V850_CPU_ALL, R_ANAL_OP_TYPE_LOAD, "#0,[4],#1," },
	{ "ld.w", two (0x0780, 0x0009), two (0xffe0, 0x001f), {D23_ALIGN1, R1, R3}, 2, V850_CPU_E2_UP, R_ANAL_OP_TYPE_LOAD, "#0,[4],#1,=" },
	{ "ld.w23", two (0x0780, 0x0009), two (0x07e0, 0x001f), {D23_ALIGN1, R1, R3}, 2, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_LOAD },
	{ "ldl.w", two (0x07e0, 0x0378), two (0xffe0, 0x07ff), {R1, R3}, 1, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_LOAD },
	{ "ldsr", two (0x07e0, 0x0020), two (0x07e0, 0x07ff), {R1, SR2, SELID}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_LOAD },
	{ "ldsr", two (0x07e0, 0x0020), two (0x07e0, 0x07ff), {R1, SR2}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_LOAD },
	{ "ldsr", two (0x07e0, 0x0020), two (0x07e0, 0x07ff), {R1, OLDSR2}, 0, (V850_CPU_ALL & (~ V850_CPU_E3V5_UP)), R_ANAL_OP_TYPE_LOAD },
	{ "ldtc.gr", two (0x07e0, 0x0032), two (0x07e0, 0xffff), {R1, R2}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_LOAD },
	{ "ldtc.sr", two (0x07e0, 0x0030), two (0x07e0, 0x07ff), {R1, SR2, SELID}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_LOAD },
	{ "ldtc.sr", two (0x07e0, 0x0030), two (0x07e0, 0x07ff), {R1, SR2}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_LOAD },
	{ "ldtc.vr", two (0x07e0, 0x0832), two (0x07e0, 0xffff), {R1, VR2}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_LOAD },
	{ "ldtc.pc", two (0x07e0, 0xf832), two (0x07e0, 0xffff), {R1}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_LOAD },
	{ "ldvc.sr", two (0x07e0, 0x0034), two (0x07e0, 0x07ff), {R1, SR2, SELID}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_LOAD },
	{ "ldvc.sr", two (0x07e0, 0x0034), two (0x07e0, 0x07ff), {R1, SR2}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_LOAD },
	{ "loop", two (0x06e0, 0x0001), two (0xffe0, 0x0001), {R1, D16_LOOP}, 0, V850_CPU_E3V5_UP },
	{ "macacc", two (0x07e0, 0x0bc0), two (0x07e0, 0xffff), {R1, R2}, 0, V850_CPU_E2_UP | V850_CPU_OPTION_EXTENSION },
	{ "mac", two (0x07e0, 0x03c0), two (0x07e0, 0x0fe1), {R1, R2, R3_EVEN, R4_EVEN}, 0, V850_CPU_E2_UP, R_ANAL_OP_TYPE_MUL },
	{ "macu", two (0x07e0, 0x03e0), two (0x07e0, 0x0fe1), {R1, R2, R3_EVEN, R4_EVEN}, 0, V850_CPU_E2_UP, R_ANAL_OP_TYPE_MUL },
	{ "macuacc", two (0x07e0, 0x0bc2), two (0x07e0, 0xffff), {R1, R2}, 0, V850_CPU_E2_UP | V850_CPU_OPTION_EXTENSION, R_ANAL_OP_TYPE_MUL },
	{ "mov", OP (0x00), OP_MASK, {R1, R2_NOTR0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_MOV, "#0,#1,=" }, // TODO: mov 0xff, r2, r1
	{ "mov", OP (0x10), OP_MASK, {I5, R2_NOTR0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_MOV, "#0,#1,=" },
	{ "mov", one (0x0620), one (0xffe0), {IMM32, R1}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_MOV, "#0,#1,=" }, // mov 0xfff, r1
	/* Gas local alias of mov imm32(not defined in spec). */
	{ "movl", one (0x0620), one (0xffe0), {IMM32, R1}, 0, V850_CPU_NON0 | V850_CPU_OPTION_ALIAS },
	{ "movea", OP (0x31), OP_MASK, {I16, R1, R2_NOTR0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_MOV, "#0,#1,+,#2,=" },
	{ "movhi", OP (0x32), OP_MASK, {I16, R1, R2_NOTR0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_MOV, "16,#0,<<,#1,+,#2,=" },
	{ "mul", two (0x07e0, 0x0220), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_MUL, "#0,#1,*,#2,=" },
	{ "mul", two (0x07e0, 0x0240), two (0x07e0, 0x07c3), {I9, R2, R3}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_MUL },
	{ "mulh", OP (0x17), OP_MASK, {I5, R2_NOTR0}, 0, V850_CPU_ALL , R_ANAL_OP_TYPE_MUL },
	{ "mulh", OP (0x07), OP_MASK, {R1, R2_NOTR0}, 0, V850_CPU_ALL , R_ANAL_OP_TYPE_MUL },
	{ "mulhi", OP (0x37), OP_MASK, {I16, R1, R2_NOTR0}, 0, V850_CPU_ALL , R_ANAL_OP_TYPE_MUL },
	{ "mulu", two (0x07e0, 0x0222), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_MUL },
	{ "mulu", two (0x07e0, 0x0242), two (0x07e0, 0x07c3), {U9, R2, R3}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_MUL },
	{ "nop", one (0x00), one (0xffff), {0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_NOP, "," },
	{ "not", OP (0x01), OP_MASK, IF1, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_NOT, "#0,~,=" },
	{ "not1", two (0x47c0, 0x0000), two (0xc7e0, 0x0000), {B3, D16, R1}, 3, V850_CPU_ALL },
	{ "not1", two (0x07e0, 0x00e2), two (0x07e0, 0xffff), {R2, R1}, 3, V850_CPU_NON0 },
	{ "or", OP (0x08), OP_MASK, IF1, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_OR, "#0,#1,|,#1,=" },
	{ "ori", OP (0x34), OP_MASK, IF6U, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_OR, "#0,#1,|,#2,=" },
	{ "popsp", two (0x67e0, 0x0160), two (0xffe0, 0x07ff), {R1, R3}, 0, V850_CPU_E3V5_UP , R_ANAL_OP_TYPE_POP },
	{ "pref", two (0xdfe0, 0x0160), two (0xffe0, 0x07ff), {PREFOP, R1}, 2, V850_CPU_E3V5_UP },
	{ "prepare", two (0x0780, 0x0003), two (0xffc0, 0x001f), {LIST12, IMM5, SP}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_PUSH, "#0" }, // #0 contains the comma separated list of registers, #1 the im5 and #2 the sp
	{ "prepare", two (0x0780, 0x000b), two (0xffc0, 0x001f), {LIST12, IMM5, IMM16LO},0, V850_CPU_NON0, R_ANAL_OP_TYPE_PUSH, "#0" },
	{ "prepare", two (0x0780, 0x0013), two (0xffc0, 0x001f), {LIST12, IMM5, IMM16HI},0, V850_CPU_NON0, R_ANAL_OP_TYPE_PUSH, "#0" },
	{ "prepare", two (0x0780, 0x001b), two (0xffc0, 0x001f), {LIST12, IMM5, IMM32}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_PUSH, "#0" },
	{ "prepare", two (0x0780, 0x0001), two (0xffc0, 0x001f), {LIST12, IMM5}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_PUSH, "#0" },
	{ "pushsp", two (0x47e0, 0x0160), two (0xffe0, 0x07ff), {R1, R3}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_PUSH },
	{ "rotl", two (0x07e0, 0x00c6), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_ROL },
	{ "rotl", two (0x07e0, 0x00c4), two (0x07e0, 0x07ff), {I5U, R2, R3}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_ROL },
	{ "reti", two (0x07e0, 0x0140), two (0xffff, 0xffff), {0}, 0, V850_CPU_ALL , R_ANAL_OP_TYPE_RET},
	{ "sar", two (0x07e0, 0x00a2), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E2_UP, R_ANAL_OP_TYPE_SAR, "#0,#1,>>,#1,=" },
	{ "sar", OP (0x15), OP_MASK, {I5U, R2}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_SAR, "#0,#1,>>,#1,=" },
	{ "sar", two (0x07e0, 0x00a0), two (0x07e0, 0xffff), {R1, R2}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_SAR, "#0,#1,>>,#1,=" },

	{ "sasf", two (0x07e0, 0x0200), two (0x07f0, 0xffff), {CCCC, R2}, 0, V850_CPU_NON0 },

	{ "satadd", two (0x07e0, 0x03ba), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E2_UP, R_ANAL_OP_TYPE_ADD },
	{ "satadd", OP (0x11), OP_MASK, {I5, R2_NOTR0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_ADD },
	{ "satadd", OP (0x06), OP_MASK, {R1, R2_NOTR0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_ADD },

	{ "satsub", two (0x07e0, 0x039a), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E2_UP, R_ANAL_OP_TYPE_SUB },
	{ "satsub", OP (0x05), OP_MASK, {R1, R2_NOTR0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_SUB },

	{ "satsubi", OP (0x33), OP_MASK, {I16, R1, R2_NOTR0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_SUB },

	{ "satsubr", OP (0x04), OP_MASK, {R1, R2_NOTR0}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_SUB },

	{ "sbf", two (0x07e0, 0x0380), two (0x07e0, 0x07e1), {CCCC_NOTSA, R1, R2, R3}, 0, V850_CPU_E2_UP },

	{ "sch0l", two (0x07e0, 0x0364), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2_UP },

	{ "sch0r", two (0x07e0, 0x0360), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2_UP },

	{ "sch1l", two (0x07e0, 0x0366), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2_UP },

	{ "sch1r", two (0x07e0, 0x0362), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2_UP },

	{ "sdivhn", two (0x07e0, 0x0180), two (0x07e0, 0x07c3), {I5DIV3, R1, R2, R3}, 0, V850_CPU_NON0 | V850_CPU_OPTION_EXTENSION },
	{ "sdivhun", two (0x07e0, 0x0182), two (0x07e0, 0x07c3), {I5DIV3, R1, R2, R3}, 0, V850_CPU_NON0 | V850_CPU_OPTION_EXTENSION },
	{ "sdivn", two (0x07e0, 0x01c0), two (0x07e0, 0x07c3), {I5DIV3, R1, R2, R3}, 0, V850_CPU_NON0 | V850_CPU_OPTION_EXTENSION },
	{ "sdivun", two (0x07e0, 0x01c2), two (0x07e0, 0x07c3), {I5DIV3, R1, R2, R3}, 0, V850_CPU_NON0 | V850_CPU_OPTION_EXTENSION },
	{ "set1", two (0x07c0, 0x0000), two (0xc7e0, 0x0000), {B3, D16, R1}, 3, V850_CPU_ALL },
	{ "set1", two (0x07e0, 0x00e0), two (0x07e0, 0xffff), {R2, R1}, 3, V850_CPU_NON0 },
	{ "setf", two (0x07e0, 0x0000), two (0x07f0, 0xffff), {CCCC, R2}, 0, V850_CPU_ALL },
	{ "shl", two (0x07e0, 0x00c2), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E2_UP, R_ANAL_OP_TYPE_SHL, "#0,#1,<<,#1,=" },
	{ "shl", OP (0x16), OP_MASK, {I5U, R2}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_SHL, "#0,#1,<<,#1,=" },
	{ "shl", two (0x07e0, 0x00c0), two (0x07e0, 0xffff), {R1, R2}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_SHL, "#0,#1,<<,#1,=" },
	{ "shr", two (0x07e0, 0x0082), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E2_UP, R_ANAL_OP_TYPE_SHR, "#0,#1,>>,#1,=" },
	{ "shr", OP (0x14), OP_MASK, {I5U, R2}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_SHR, "#0,#1,>>,#1,=" },
	{ "shr", two (0x07e0, 0x0080), two (0x07e0, 0xffff), {R1, R2}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_SHR, "#0,#1,>>,#1,=" },

	{ "sld.b", one (0x0300), one (0x0780), {D7U, EP, R2}, 2, V850_CPU_ALL, R_ANAL_OP_TYPE_LOAD, "1,#0,>>,#1,ep,+,[1],4,#1,=" },
	{ "sld.bu", one (0x0060), one (0x07f0), {D4U, EP, R2_NOTR0}, 2, V850_CPU_NON0, R_ANAL_OP_TYPE_LOAD },
	{ "sld.h", one (0x0400), one (0x0780), {D8_7U,EP, R2}, 2, V850_CPU_ALL, R_ANAL_OP_TYPE_LOAD },
	{ "sld.hu", one (0x0070), one (0x07f0), {D5_4U,EP, R2_NOTR0}, 2, V850_CPU_NON0, R_ANAL_OP_TYPE_LOAD },
	{ "sld.w", one (0x0500), one (0x0781), {D8_6U,EP, R2}, 2, V850_CPU_ALL, R_ANAL_OP_TYPE_LOAD },

	{ "snooze", two (0x0fe0, 0x0120), two (0xffff, 0xffff), {0}, 0, V850_CPU_E3V5_UP },
	{ "sst.b", one (0x0380), one (0x0780), {R2, D7U, EP}, 3, V850_CPU_ALL, R_ANAL_OP_TYPE_STORE, "#0,[1],ep,~,=[1]"},
	{ "sst.h", one (0x0480), one (0x0780), {R2, D8_7U,EP}, 3, V850_CPU_ALL, R_ANAL_OP_TYPE_STORE },
	{ "sst.w", one (0x0501), one (0x0781), {R2, D8_6U,EP}, 3, V850_CPU_ALL, R_ANAL_OP_TYPE_STORE },
	{ "stacch", two (0x07e0, 0x0bca), two (0x07ff, 0xffff), {R2}, 0, V850_CPU_E2_UP | V850_CPU_OPTION_EXTENSION },
	{ "staccl", two (0x07e0, 0x0bc8), two (0x07ff, 0xffff), {R2}, 0, V850_CPU_E2_UP | V850_CPU_OPTION_EXTENSION },
	{ "st.b", two (0x0740, 0x0000), two (0x07e0, 0x0000), {R2, D16, R1}, 3, V850_CPU_ALL, R_ANAL_OP_TYPE_STORE, "#0,#1,#2,+,~,=[4]" },
	{ "st.b", two (0x0780, 0x000d), two (0x07e0, 0x000f), {R3, D23, R1}, 3, V850_CPU_E2_UP, R_ANAL_OP_TYPE_STORE, "#0,#1,#2,+,~,=[4]" },
	{ "st.b23", two (0x0780, 0x000d), two (0x07e0, 0x000f), {R3, D23, R1}, 3, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_STORE },
	{ "st.dw", two (0x07a0, 0x000f), two (0xffe0, 0x001f), {R3_EVEN, D23_ALIGN1, R1}, 3, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_STORE },
	{ "st.dw23", two (0x07a0, 0x000f), two (0xffe0, 0x001f), {R3_EVEN, D23_ALIGN1, R1}, 3, V850_CPU_E3V5_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_STORE },
	{ "st.h", two (0x0760, 0x0000), two (0x07e0, 0x0001), {R2, D16_15, R1}, 3, V850_CPU_ALL, R_ANAL_OP_TYPE_STORE, "#0,#1,~,=[4]" },
	{ "st.h", two (0x07a0, 0x000d), two (0x07e0, 0x000f), {R3, D23_ALIGN1, R1}, 3, V850_CPU_E2_UP, R_ANAL_OP_TYPE_STORE, "#0,#1,~,=[4]" },
	{ "st.h23", two (0x07a0, 0x000d), two (0x07e0, 0x000f), {R3, D23_ALIGN1, R1}, 3, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_STORE },
	{ "st.w", two (0x0760, 0x0001), two (0x07e0, 0x0001), {R2, D16_15, R1}, 3, V850_CPU_ALL, R_ANAL_OP_TYPE_STORE, "#0,#1,~,=[4]" },
	{ "st.w", two (0x0780, 0x000f), two (0x07e0, 0x000f), {R3, D23_ALIGN1, R1}, 3, V850_CPU_E2_UP, R_ANAL_OP_TYPE_STORE, "#0,#1,~,=[4]" },
	{ "st.w23", two (0x0780, 0x000f), two (0x07e0, 0x000f), {R3, D23_ALIGN1, R1}, 3, V850_CPU_E2_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_STORE },
	{ "stc.w", two (0x07e0, 0x037a), two (0xffe0, 0x07ff), {R3, R1}, 2, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_STORE },
	{ "stsr", two (0x07e0, 0x0040), two (0x07e0, 0x07ff), {SR1, R2, SELID}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_STORE },
	{ "stsr", two (0x07e0, 0x0040), two (0x07e0, 0x07ff), {SR1, R2}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_STORE },
	{ "stsr", two (0x07e0, 0x0040), two (0x07e0, 0x07ff), {OLDSR1, R2}, 0, (V850_CPU_ALL & (~ V850_CPU_E3V5_UP)), R_ANAL_OP_TYPE_STORE },
	{ "sttc.gr", two (0x07e0, 0x0052), two (0x07e0, 0xffff), {R1, R2}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_STORE },
	{ "sttc.sr", two (0x07e0, 0x0050), two (0x07e0, 0x07ff), {SR1, R2, SELID}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_STORE },
	{ "sttc.sr", two (0x07e0, 0x0050), two (0x07e0, 0x07ff), {SR1, R2}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_STORE },
	{ "sttc.vr", two (0x07e0, 0x0852), two (0x07e0, 0xffff), {VR1, R2}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_STORE },
	{ "sttc.pc", two (0x07e0, 0xf852), two (0x07e0, 0xffff), {R2}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_STORE },
	{ "stvc.sr", two (0x07e0, 0x0054), two (0x07e0, 0x07ff), {SR1, R2, SELID}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_STORE },
	{ "stvc.sr", two (0x07e0, 0x0054), two (0x07e0, 0x07ff), {SR1, R2}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_STORE },
	{ "sub", OP (0x0d), OP_MASK, IF1, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_SUB, "#0,#1,-,="},
	{ "subr", OP (0x0c), OP_MASK, IF1, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_SUB, "#1,#0,-,="  },
	{ "switch", one (0x0040), one (0xffe0), {R1_NOTR0}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_RJMP },
	{ "sxb", one (0x00a0), one (0xffe0), {R1}, 0, V850_CPU_NON0 },
	{ "sxh", one (0x00e0), one (0xffe0), {R1}, 0, V850_CPU_NON0 },
	{ "tlbai", two (0x87e0, 0x8960), two (0xffff, 0xffff), {0}, 0, V850_CPU_E3V5_UP },
	{ "tlbr", two (0x87e0, 0xe960), two (0xffff, 0xffff), {0}, 0, V850_CPU_E3V5_UP },
	{ "tlbs", two (0x87e0, 0xc160), two (0xffff, 0xffff), {0}, 0, V850_CPU_E3V5_UP },
	{ "tlbvi", two (0x87e0, 0x8160), two (0xffff, 0xffff), {0}, 0, V850_CPU_E3V5_UP },
	{ "tlbw", two (0x87e0, 0xe160), two (0xffff, 0xffff), {0}, 0, V850_CPU_E3V5_UP },
	{ "trap", two (0x07e0, 0x0100), two (0xffe0, 0xffff), {I5U}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_TRAP },
	{ "tst", OP (0x0b), OP_MASK, IF1, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_CMP, "#1,#0,&,POP,0,ov,:=,$s,s,:=,$z,z,:=" },
	{ "tst1", two (0xc7c0, 0x0000), two (0xc7e0, 0x0000), {B3, D16, R1}, 3, V850_CPU_ALL, R_ANAL_OP_TYPE_CMP },
	{ "tst1", two (0x07e0, 0x00e6), two (0x07e0, 0xffff), {R2, R1}, 3, V850_CPU_NON0, R_ANAL_OP_TYPE_CMP },
	{ "xor", OP (0x09), OP_MASK, IF1, 0, V850_CPU_ALL , R_ANAL_OP_TYPE_XOR, "#0,#1,^,#1,=" },
	{ "xori", OP (0x35), OP_MASK, IF6U, 0, V850_CPU_ALL , R_ANAL_OP_TYPE_XOR, "#0,#1,^,#2,="},
	{ "zxb", one (0x0080), one (0xffe0), {R1}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_MOV },
	{ "zxh", one (0x00c0), one (0xffe0), {R1}, 0, V850_CPU_NON0, R_ANAL_OP_TYPE_MOV },

	/* Floating point operation. */
	{ "absf.d", two (0x07e0, 0x0458), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "absf.s", two (0x07e0, 0x0448), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "addf.d", two (0x07e0, 0x0470), two (0x0fe1, 0x0fff), {R1_EVEN, R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_ADD },
	{ "addf.s", two (0x07e0, 0x0460), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_ADD },
	{ "ceilf.dl", two (0x07e2, 0x0454), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "ceilf.dul", two (0x07f2, 0x0454), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "ceilf.duw", two (0x07f2, 0x0450), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP },
	{ "ceilf.dw", two (0x07e2, 0x0450), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP },
	{ "ceilf.sl", two (0x07e2, 0x0444), two (0x07ff, 0x0fff), {R2, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "ceilf.sul", two (0x07f2, 0x0444), two (0x07ff, 0x0fff), {R2, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "ceilf.suw", two (0x07f2, 0x0440), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "ceilf.sw", two (0x07e2, 0x0440), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "cmovf.d", two (0x07e0, 0x0410), two (0x0fe1, 0x0ff1), {FFF, R1_EVEN, R2_EVEN, R3_EVEN_NOTR0}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_MOV },
	/* Default value for FFF is 0(not defined in spec). */
	{ "cmovf.d", two (0x07e0, 0x0410), two (0x0fe1, 0x0fff), {R1_EVEN, R2_EVEN, R3_EVEN_NOTR0}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_MOV },
	{ "cmovf.s", two (0x07e0, 0x0400), two (0x07e0, 0x07f1), {FFF, R1, R2, R3_NOTR0}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_MOV },
	/* Default value for FFF is 0(not defined in spec). */
	{ "cmovf.s", two (0x07e0, 0x0400), two (0x07e0, 0x07ff), {R1, R2, R3_NOTR0}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_MOV },
	{ "cmpf.d", two (0x07e0, 0x0430), two (0x0fe1, 0x87f1), {FLOAT_CCCC, R2_EVEN, R1_EVEN, FFF}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_CMP },
	{ "cmpf.d", two (0x07e0, 0x0430), two (0x0fe1, 0x87ff), {FLOAT_CCCC, R2_EVEN, R1_EVEN}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_CMP },
	{ "cmpf.s", two (0x07e0, 0x0420), two (0x07e0, 0x87f1), {FLOAT_CCCC, R2, R1, FFF}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_CMP },
	{ "cmpf.s", two (0x07e0, 0x0420), two (0x07e0, 0x87ff), {FLOAT_CCCC, R2, R1}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_CMP },
	{ "cvtf.dl", two (0x07e4, 0x0454), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.ds", two (0x07e3, 0x0452), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.dul", two (0x07f4, 0x0454), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.duw", two (0x07f4, 0x0450), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.dw", two (0x07e4, 0x0450), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.hs", two (0x07e2, 0x0442), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E3V5_UP },
	{ "cvtf.ld", two (0x07e1, 0x0452), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.ls", two (0x07e1, 0x0442), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.sd", two (0x07e2, 0x0452), two (0x07ff, 0x0fff), {R2, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.sl", two (0x07e4, 0x0444), two (0x07ff, 0x0fff), {R2, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.sh", two (0x07e3, 0x0442), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E3V5_UP },
	{ "cvtf.sul", two (0x07f4, 0x0444), two (0x07ff, 0x0fff), {R2, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.suw", two (0x07f4, 0x0440), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.sw", two (0x07e4, 0x0440), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.uld", two (0x07f1, 0x0452), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.uls", two (0x07f1, 0x0442), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.uwd", two (0x07f0, 0x0452), two (0x07ff, 0x0fff), {R2, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.uws", two (0x07f0, 0x0442), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.wd", two (0x07e0, 0x0452), two (0x07ff, 0x0fff), {R2, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "cvtf.ws", two (0x07e0, 0x0442), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "divf.d", two (0x07e0, 0x047e), two (0x0fe1, 0x0fff), {R1_EVEN, R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "divf.s", two (0x07e0, 0x046e), two (0x07e0, 0x07ff), {R1_NOTR0, R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "floorf.dl", two (0x07e3, 0x0454), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "floorf.dul", two (0x07f3, 0x0454), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "floorf.duw", two (0x07f3, 0x0450), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP },
	{ "floorf.dw", two (0x07e3, 0x0450), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP },
	{ "floorf.sl", two (0x07e3, 0x0444), two (0x07ff, 0x0fff), {R2, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "floorf.sul", two (0x07f3, 0x0444), two (0x07ff, 0x0fff), {R2, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "floorf.suw", two (0x07f3, 0x0440), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "floorf.sw", two (0x07e3, 0x0440), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "maddf.s", two (0x07e0, 0x0500), two (0x07e0, 0x0761), {R1, R2, R3, R4}, 0, V850_CPU_E2V3 },
	{ "fmaf.s", two (0x07e0, 0x04e0), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E3V5_UP },
	{ "maxf.d", two (0x07e0, 0x0478), two (0x0fe1, 0x0fff), {R1_EVEN, R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "maxf.s", two (0x07e0, 0x0468), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "minf.d", two (0x07e0, 0x047a), two (0x0fe1, 0x0fff), {R1_EVEN, R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "minf.s", two (0x07e0, 0x046a), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "msubf.s", two (0x07e0, 0x0520), two (0x07e0, 0x0761), {R1, R2, R3, R4}, 0, V850_CPU_E2V3 },
	{ "fmsf.s", two (0x07e0, 0x04e2), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E3V5_UP },
	{ "mulf.d", two (0x07e0, 0x0474), two (0x0fe1, 0x0fff), {R1_EVEN, R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_MUL },
	{ "mulf.s", two (0x07e0, 0x0464), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_MUL },
	{ "negf.d", two (0x07e1, 0x0458), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_NOT },
	{ "negf.s", two (0x07e1, 0x0448), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_NOT },
	{ "nmaddf.s", two (0x07e0, 0x0540), two (0x07e0, 0x0761), {R1, R2, R3, R4}, 0, V850_CPU_E2V3 },
	{ "fnmaf.s", two (0x07e0, 0x04e4), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E3V5_UP },
	{ "nmsubf.s", two (0x07e0, 0x0560), two (0x07e0, 0x0761), {R1, R2, R3, R4}, 0, V850_CPU_E2V3 },
	{ "fnmsf.s", two (0x07e0, 0x04e6), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E3V5_UP },
	{ "recipf.d", two (0x07e1, 0x045e), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "recipf.s", two (0x07e1, 0x044e), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },

	{ "roundf.dl", two (0x07e0, 0x0454), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP | V850_CPU_OPTION_EXTENSION },
	{ "roundf.dul", two (0x07f0, 0x0454), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP | V850_CPU_OPTION_EXTENSION },
	{ "roundf.duw", two (0x07f0, 0x0450), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP | V850_CPU_OPTION_EXTENSION },
	{ "roundf.dw", two (0x07e0, 0x0450), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP | V850_CPU_OPTION_EXTENSION },
	{ "roundf.sl", two (0x07e0, 0x0444), two (0x07ff, 0x0fff), {R2, R3_EVEN}, 0, V850_CPU_E2V3_UP | V850_CPU_OPTION_EXTENSION },
	{ "roundf.sul", two (0x07f0, 0x0444), two (0x07ff, 0x0fff), {R2, R3_EVEN}, 0, V850_CPU_E2V3_UP | V850_CPU_OPTION_EXTENSION },
	{ "roundf.suw", two (0x07f0, 0x0440), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP | V850_CPU_OPTION_EXTENSION },
	{ "roundf.sw", two (0x07e0, 0x0440), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP | V850_CPU_OPTION_EXTENSION },

	{ "rsqrtf.d", two (0x07e2, 0x045e), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "rsqrtf.s", two (0x07e2, 0x044e), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "sqrtf.d", two (0x07e0, 0x045e), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "sqrtf.s", two (0x07e0, 0x044e), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "subf.d", two (0x07e0, 0x0472), two (0x0fe1, 0x0fff), {R1_EVEN, R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_SUB },
	{ "subf.s", two (0x07e0, 0x0462), two (0x07e0, 0x07ff), {R1, R2, R3}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_SUB },
	{ "trfsr", two (0x07e0, 0x0400), two (0xffff, 0xfff1), {FFF}, 0, V850_CPU_E2V3_UP },
	{ "trfsr", two (0x07e0, 0x0400), two (0xffff, 0xffff), {0}, 0, V850_CPU_E2V3_UP },
	{ "trncf.dl", two (0x07e1, 0x0454), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "trncf.dul", two (0x07f1, 0x0454), two (0x0fff, 0x0fff), {R2_EVEN, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "trncf.duw", two (0x07f1, 0x0450), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP },
	{ "trncf.dw", two (0x07e1, 0x0450), two (0x0fff, 0x07ff), {R2_EVEN, R3}, 0, V850_CPU_E2V3_UP },
	{ "trncf.sl", two (0x07e1, 0x0444), two (0x07ff, 0x0fff), {R2, R3_EVEN}, 0, V850_CPU_E2V3_UP },
	{ "trncf.sul", two (0x07f1, 0x0444), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "trncf.suw", two (0x07f1, 0x0440), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },
	{ "trncf.sw", two (0x07e1, 0x0440), two (0x07ff, 0x07ff), {R2, R3}, 0, V850_CPU_E2V3_UP },

	/* Special instruction (from gdb) mov 1, r0. */
	{ "breakpoint", one (0x0001), one (0xffff), {UNUSED_R}, 0, V850_CPU_ALL, R_ANAL_OP_TYPE_TRAP },

	{ "synci", one (0x001c), one (0xffff), {0}, 0, V850_CPU_E3V5_UP, R_ANAL_OP_TYPE_SYNC },

	{ "synce", one (0x001d), one (0xffff), {0}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_SYNC },
	{ "syncm", one (0x001e), one (0xffff), {0}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_SYNC },
	{ "syncp", one (0x001f), one (0xffff), {0}, 0, V850_CPU_E2V3_UP, R_ANAL_OP_TYPE_SYNC },
	{ "syscall", two (0xd7e0, 0x0160), two (0xffe0, 0xc7ff), {V8}, 0, V850_CPU_E2V3_UP , R_ANAL_OP_TYPE_SWI },
	/* Alias of syncp. */
	{ "sync", one (0x001f), one (0xffff), {0}, 0, V850_CPU_E2V3_UP | V850_CPU_OPTION_ALIAS, R_ANAL_OP_TYPE_SYNC },
	{ "rmtrap", one (0xf040), one (0xffff), {0}, 0, V850_CPU_E2V3_UP },
	{ "rie", one (0x0040), one (0xffff), {0}, 0, V850_CPU_E2V3_UP },
	{ "rie", two (0x07f0, 0x0000), two (0x07f0, 0xffff), {RIE_IMM5,RIE_IMM4}, 0, V850_CPU_E2V3_UP },
	{ 0, 0, 0, {0}, 0, 0 },
};

const size_t v850_num_opcodes = R_ARRAY_SIZE (v850_opcodes);

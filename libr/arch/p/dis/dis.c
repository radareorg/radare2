/* radare2 - MIT - Copyright 2023 - keegan */

#include "dis.h"

// From "Dis Virtual Machine Specification":
// > OP encoded integer operand, encoding selected by the two most significant
// > bits as follows:
// >     00: signed 7 bits, 1 byte
// >     10: signed 14 bits, 2 bytes
// >     11: signed 30 bits, 4 bytes
// Based off of `operand' in Inferno's load.c
static bool dis_read_operand(RBuffer *buf, st32 *n) {
	ut8 c;
	if (r_buf_read (buf, &c, sizeof (c)) != sizeof (c)) {
		return false;
	}

	switch (c & 0xc0) {
	case 0x00:
		*n = c;
		return true;
	case 0x40:
		*n = c | ~0x7f;
		return true;
	case 0x80: {
		ut8 b;
		if (r_buf_read (buf, &b, sizeof (b)) != sizeof (b)) {
			return false;
		}

		if (c & 0x20) {
			c |= ~0x3f;
		} else {
			c &= 0x3f;
		}

		*n = (c << 8) | (st32)b;
		return true;
	}
	case 0xc0: {
		ut8 k[3] = {0};
		if (r_buf_read (buf, k, sizeof (k)) != sizeof (k)) {
			return false;
		}

		if (c & 0x20) {
			c |= ~0x3f;
		} else {
			c &= 0x3f;
		}
		*n = (ut32)((ut32)c << 24) | (k[0] << 16) | (k[1] << 8) | k[2];
		return true;
	}
	}

	return false;
}

static bool dis_read_instr(RBuffer *buf, struct dis_instr *instr) {
	ut8 opcode;
	if (r_buf_read (buf, &opcode, sizeof (opcode)) != sizeof (opcode)) {
		return false;
	}
	if (opcode >= DIS_OP_INVALID) {
		return false;
	}
	instr->opcode = opcode;
	ut8 address_mode;
	if (r_buf_read (buf, &address_mode, sizeof (address_mode)) != sizeof (address_mode)) {
		return false;
	}

	// address mode is packed as follows:
	//      7  6  5  4  3  2  1  0
	//     m1 m0 s2 s1 s0 d2 d1 d0
	ut8 mmode = (address_mode >> 6) & 3;
	ut8 smode = (address_mode >> 3) & 7;
	ut8 dmode = address_mode & 7;

	switch (mmode) {
	// small immediate
	case 1:
		instr->mop = DIS_OPERAND_IMM;
		break;
	// small offset indirect from fp
	case 2:
		instr->mop = DIS_OPERAND_IND_FP;
		break;
	// small offset indirect from mp
	case 3:
		instr->mop = DIS_OPERAND_IND_MP;
		break;
	// no operand
	default:
		instr->mop = DIS_OPERAND_NONE;
		break;
	}
	if (instr->mop) {
		if (!dis_read_operand (buf, &instr->mop_imm)) {
			return false;
		}
	}

	switch (smode) {
	// offset indirect from mp
	case 0:
		instr->sop = DIS_OPERAND_IND_MP;
		break;
	// offset indirect from fp
	case 1:
		instr->sop = DIS_OPERAND_IND_FP;
		break;
	case 2:
		instr->sop = DIS_OPERAND_IMM;
		break;
	// double-indirect from mp
	case 4:
		instr->sop = DIS_OPERAND_DIND_MP;
		break;
	// double-indirect from fp
	case 5:
		instr->sop = DIS_OPERAND_DIND_FP;
		break;
	// no operand
	default:
		instr->sop = DIS_OPERAND_NONE;
		break;
	}
	if (instr->sop) {
		if (!dis_read_operand (buf, &instr->sop_imm1)) {
			return false;
		}
	}
	if (instr->sop == DIS_OPERAND_DIND_MP || instr->sop == DIS_OPERAND_DIND_FP) {
		if (!dis_read_operand (buf, &instr->sop_imm2)) {
			return false;
		}
	}

	switch (dmode) {
	case 0:
		instr->dop = DIS_OPERAND_IND_MP;
		break;
	case 1:
		instr->dop = DIS_OPERAND_IND_FP;
		break;
	case 2:
		instr->dop = DIS_OPERAND_IMM;
		break;
	case 4:
		instr->dop = DIS_OPERAND_DIND_MP;
		break;
	case 5:
		instr->dop = DIS_OPERAND_DIND_FP;
		break;
	default:
		instr->dop = DIS_OPERAND_NONE;
		break;
	}
	if (instr->dop) {
		if (!dis_read_operand (buf, &instr->dop_imm1)) {
			return false;
		}
	}
	if (instr->dop == DIS_OPERAND_DIND_MP || instr->dop == DIS_OPERAND_DIND_FP) {
		if (!dis_read_operand (buf, &instr->dop_imm2)) {
			return false;
		}
	}
	return true;
}

FUNC_ATTR_USED static bool dis_read_type(RBuffer *buf, struct dis_type *typ) {
	if (!dis_read_operand (buf, &typ->desc_number)) {
		return false;
	}

	if (!dis_read_operand (buf, &typ->size)) {
		return false;
	}

	if (!dis_read_operand (buf, &typ->number_ptrs)) {
		return false;
	}

	// TODO: ignored for now (unused)
	typ->array = NULL;
	// skip
	r_buf_seek (buf, typ->number_ptrs, R_BUF_CUR);

	return true;
}

FUNC_ATTR_USED static bool dis_read_link(RBuffer *buf, struct dis_link *link) {
	ut8 k[4];

	if (!dis_read_operand (buf, &link->pc)) {
		return false;
	}

	if (!dis_read_operand (buf, &link->desc_number)) {
		return false;
	}

	if (r_buf_read (buf, k, sizeof (k)) != sizeof (k)) {
		return false;
	}
	link->sig = r_read_be32 (k);

	// TODO: ignored for now (unused)
	link->name = NULL;
	// skip
	for (;;) {
		ut8 b;
		if (r_buf_read (buf, &b, sizeof (b)) != sizeof (b)) {
			return false;
		}
		if (b == 0) {
			break;
		}
	}

	return true;
}

static const char *const dis_opcodes[256] = {
	[DIS_OP_NOP]     = "nop",
	[DIS_OP_ALT]     = "alt",
	[DIS_OP_NBALT]   = "nbalt",
	[DIS_OP_GOTO]    = "goto",
	[DIS_OP_CALL]    = "call",
	[DIS_OP_FRAME]   = "frame",
	[DIS_OP_SPAWN]   = "spawn",
	[DIS_OP_RUNT]    = "runt",
	[DIS_OP_LOAD]    = "load",
	[DIS_OP_MCALL]   = "mcall",
	[DIS_OP_MSPAWN]  = "mspawn",
	[DIS_OP_MFRAME]  = "mframe",
	[DIS_OP_RET]     = "ret",
	[DIS_OP_JMP]     = "jmp",
	[DIS_OP_CASE]    = "case",
	[DIS_OP_EXIT]    = "exit",
	[DIS_OP_NEW]     = "new",
	[DIS_OP_NEWA]    = "newa",
	[DIS_OP_NEWCB]   = "newcb",
	[DIS_OP_NEWCW]   = "newcw",
	[DIS_OP_NEWCF]   = "newcf",
	[DIS_OP_NEWCP]   = "newcp",
	[DIS_OP_NEWCM]   = "newcm",
	[DIS_OP_NEWCMP]  = "newcmp",
	[DIS_OP_SEND]    = "send",
	[DIS_OP_RECV]    = "recv",
	[DIS_OP_CONSB]   = "consb",
	[DIS_OP_CONSW]   = "consw",
	[DIS_OP_CONSP]   = "consp",
	[DIS_OP_CONSF]   = "consf",
	[DIS_OP_CONSM]   = "consm",
	[DIS_OP_CONSMP]  = "consmp",
	[DIS_OP_HEADB]   = "headb",
	[DIS_OP_HEADW]   = "headw",
	[DIS_OP_HEADP]   = "headp",
	[DIS_OP_HEADF]   = "headf",
	[DIS_OP_HEADM]   = "headm",
	[DIS_OP_HEADMP]  = "headmp",
	[DIS_OP_TAIL]    = "tail",
	[DIS_OP_LEA]     = "lea",
	[DIS_OP_INDX]    = "indx",
	[DIS_OP_MOVP]    = "movp",
	[DIS_OP_MOVM]    = "movm",
	[DIS_OP_MOVMP]   = "movmp",
	[DIS_OP_MOVB]    = "movb",
	[DIS_OP_MOVW]    = "movw",
	[DIS_OP_MOVF]    = "movf",
	[DIS_OP_CVTBW]   = "cvtbw",
	[DIS_OP_CVTWB]   = "cvtwb",
	[DIS_OP_CVTFW]   = "cvtfw",
	[DIS_OP_CVTWF]   = "cvtwf",
	[DIS_OP_CVTCA]   = "cvtca",
	[DIS_OP_CVTAC]   = "cvtac",
	[DIS_OP_CVTWC]   = "cvtwc",
	[DIS_OP_CVTCW]   = "cvtcw",
	[DIS_OP_CVTFC]   = "cvtfc",
	[DIS_OP_CVTCF]   = "cvtcf",
	[DIS_OP_ADDB]    = "addb",
	[DIS_OP_ADDW]    = "addw",
	[DIS_OP_ADDF]    = "addf",
	[DIS_OP_SUBB]    = "subb",
	[DIS_OP_SUBW]    = "subw",
	[DIS_OP_SUBF]    = "subf",
	[DIS_OP_MULB]    = "mulb",
	[DIS_OP_MULW]    = "mulw",
	[DIS_OP_MULF]    = "mulf",
	[DIS_OP_DIVB]    = "divb",
	[DIS_OP_DIVW]    = "divw",
	[DIS_OP_DIVF]    = "divf",
	[DIS_OP_MODW]    = "modw",
	[DIS_OP_MODB]    = "modb",
	[DIS_OP_ANDB]    = "andb",
	[DIS_OP_ANDW]    = "andw",
	[DIS_OP_ORB]     = "orb",
	[DIS_OP_ORW]     = "orw",
	[DIS_OP_XORB]    = "xorb",
	[DIS_OP_XORW]    = "xorw",
	[DIS_OP_SHLB]    = "shlb",
	[DIS_OP_SHLW]    = "shlw",
	[DIS_OP_SHRB]    = "shrb",
	[DIS_OP_SHRW]    = "shrw",
	[DIS_OP_INSC]    = "insc",
	[DIS_OP_INDC]    = "indc",
	[DIS_OP_ADDC]    = "addc",
	[DIS_OP_LENC]    = "lenc",
	[DIS_OP_LENA]    = "lena",
	[DIS_OP_LENL]    = "lenl",
	[DIS_OP_BEQB]    = "beqb",
	[DIS_OP_BNEB]    = "bneb",
	[DIS_OP_BLTB]    = "bltb",
	[DIS_OP_BLEB]    = "bleb",
	[DIS_OP_BGTB]    = "bgtb",
	[DIS_OP_BGEB]    = "bgeb",
	[DIS_OP_BEQW]    = "beqw",
	[DIS_OP_BNEW]    = "bnew",
	[DIS_OP_BLTW]    = "bltw",
	[DIS_OP_BLEW]    = "blew",
	[DIS_OP_BGTW]    = "bgtw",
	[DIS_OP_BGEW]    = "bgew",
	[DIS_OP_BEQF]    = "beqf",
	[DIS_OP_BNEF]    = "bnef",
	[DIS_OP_BLTF]    = "bltf",
	[DIS_OP_BLEF]    = "blef",
	[DIS_OP_BGTF]    = "bgtf",
	[DIS_OP_BGEF]    = "bgef",
	[DIS_OP_BEQC]    = "beqc",
	[DIS_OP_BNEC]    = "bnec",
	[DIS_OP_BLTC]    = "bltc",
	[DIS_OP_BLEC]    = "blec",
	[DIS_OP_BGTC]    = "bgtc",
	[DIS_OP_BGEC]    = "bgec",
	[DIS_OP_SLICEA]  = "slicea",
	[DIS_OP_SLICELA] = "slicela",
	[DIS_OP_SLICEC]  = "slicec",
	[DIS_OP_INDW]    = "indw",
	[DIS_OP_INDF]    = "indf",
	[DIS_OP_INDB]    = "indb",
	[DIS_OP_NEGF]    = "negf",
	[DIS_OP_MOVL]    = "movl",
	[DIS_OP_ADDL]    = "addl",
	[DIS_OP_SUBL]    = "subl",
	[DIS_OP_DIVL]    = "divl",
	[DIS_OP_MODL]    = "modl",
	[DIS_OP_MULL]    = "mull",
	[DIS_OP_ANDL]    = "andl",
	[DIS_OP_ORL]     = "orl",
	[DIS_OP_XORL]    = "xorl",
	[DIS_OP_SHLL]    = "shll",
	[DIS_OP_SHRL]    = "shrl",
	[DIS_OP_BNEL]    = "bnel",
	[DIS_OP_BLTL]    = "bltl",
	[DIS_OP_BLEL]    = "blel",
	[DIS_OP_BGTL]    = "bgtl",
	[DIS_OP_BGEL]    = "bgel",
	[DIS_OP_BEQL]    = "beql",
	[DIS_OP_CVTLF]   = "cvtlf",
	[DIS_OP_CVTFL]   = "cvtfl",
	[DIS_OP_CVTLW]   = "cvtlw",
	[DIS_OP_CVTWL]   = "cvtwl",
	[DIS_OP_CVTLC]   = "cvtlc",
	[DIS_OP_CVTCL]   = "cvtcl",
	[DIS_OP_HEADL]   = "headl",
	[DIS_OP_CONSL]   = "consl",
	[DIS_OP_NEWCL]   = "newcl",
	[DIS_OP_CASEC]   = "casec",
	[DIS_OP_INDL]    = "indl",
	[DIS_OP_MOVPC]   = "movpc",
	[DIS_OP_TCMP]    = "tcmp",
	[DIS_OP_MNEWZ]   = "mnewz",
	[DIS_OP_CVTRF]   = "cvtrf",
	[DIS_OP_CVTFR]   = "cvtfr",
	[DIS_OP_CVTWS]   = "cvtws",
	[DIS_OP_CVTSW]   = "cvtsw",
	[DIS_OP_LSRW]    = "lsrw",
	[DIS_OP_LSRL]    = "lsrl",
	[DIS_OP_ECLR]    = "eclr",
	[DIS_OP_NEWZ]    = "newz",
	[DIS_OP_NEWAZ]   = "newaz",
	[DIS_OP_RAISE]   = "raise",
	[DIS_OP_CASEL]   = "casel",
	[DIS_OP_MULX]    = "mulx",
	[DIS_OP_DIVX]    = "divx",
	[DIS_OP_CVTXX]   = "cvtxx",
	[DIS_OP_MULX0]   = "mulx0",
	[DIS_OP_DIVX0]   = "divx0",
	[DIS_OP_CVTXX0]  = "cvtxx0",
	[DIS_OP_MULX1]   = "mulx1",
	[DIS_OP_DIVX1]   = "divx1",
	[DIS_OP_CVTXX1]  = "cvtxx1",
	[DIS_OP_CVTFX]   = "cvtfx",
	[DIS_OP_CVTXF]   = "cvtxf",
	[DIS_OP_EXPW]    = "expw",
	[DIS_OP_EXPL]    = "expl",
	[DIS_OP_EXPF]    = "expf",
	[DIS_OP_SELF]    = "self",
};

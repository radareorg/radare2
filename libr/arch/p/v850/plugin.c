/* radare - MIT - Copyright 2021-2023 - pancake, brainstorm, condret */

#include <r_lib.h>
#include <r_anal.h>
#include "v850dis.h"
#include "v850e0.h"

// Format I
#define F1_REG1(instr) ((instr) & 0x1F)
#define F1_REG2(instr) (((instr) & 0xF800) >> 11)

#define F1_RN1(instr) (V850_REG_NAMES[F1_REG1(instr)])
#define F1_RN2(instr) (V850_REG_NAMES[F1_REG2(instr)])

// Format II
#define F2_IMM(instr) F1_REG1(instr)
#define F2_REG2(instr) F1_REG2(instr)

#define F2_RN2(instr) (V850_REG_NAMES[F2_REG2(instr)])

// Format III
#define F3_COND(instr) ((instr) & 0xF)
#define F3_DISP(instr) (((instr) & 0x70) >> 4) | (((instr) & 0xF800) >> 7)

// Format IV
#define F4_DISP(instr) ((instr) & 0x3F)
#define F4_REG2(instr) F1_REG2(instr)

#define F4_RN2(instr) (V850_REG_NAMES[F4_REG2(instr)])

// Format V
#define F5_REG2(instr) F1_REG2(instr)
#define F5_DISP(instr) ((((ut32)(instr) & 0xffff) << 31) | (((ut32)(instr) & 0xffff0000) << 1))
#define F5_RN2(instr) (V850_REG_NAMES[F5_REG2(instr)])

// Format VI
#define F6_REG1(instr) F1_REG1(instr)
#define F6_REG2(instr) F1_REG2(instr)
#define F6_IMM(instr) (((instr) & 0xFFFF0000) >> 16)

#define F6_RN1(instr) (V850_REG_NAMES[F6_REG1(instr)])
#define F6_RN2(instr) (V850_REG_NAMES[F6_REG2(instr)])

// Format VII
#define F7_REG1(instr) F1_REG1(instr)
#define F7_REG2(instr) F1_REG2(instr)
#define F7_DISP(instr) F6_IMM(instr)

#define F7_RN1(instr) (V850_REG_NAMES[F7_REG1(instr)])
#define F7_RN2(instr) (V850_REG_NAMES[F7_REG2(instr)])

// Format VIII
#define F8_REG1(instr) F1_REG1(instr)
#define F8_DISP(instr) F6_IMM(instr)
#define F8_BIT(instr) (((instr) & 0x3800) >> 11)
#define F8_SUB(instr) (((instr) & 0xC000) >> 14)

#define F8_RN1(instr) (V850_REG_NAMES[F8_REG1(instr)])
#define F8_RN2(instr) (V850_REG_NAMES[F8_REG2(instr)])

// Format IX
// Also regID/cond
#define F9_REG1(instr) F1_REG1(instr)
#define F9_REG2(instr) F1_REG2(instr)
#define F9_SUB(instr) (((instr) & 0x7E00000) >> 21)

#define F9_RN1(instr) (V850_REG_NAMES[F9_REG1(instr)])
#define F9_RN2(instr) (V850_REG_NAMES[F9_REG2(instr)])
// TODO: Format X

// Format XI
#define F11_REG1(instr) F1_REG1(instr)
#define F11_REG2(instr) F1_REG2(instr)
#define F11_REG3(instr) (((instr) & 0xF8000000) >> 27)
#define F11_SUB(instr) ((((instr) & 0x7E00000) >> 20) | (((instr) & 2) >> 1))

#define F11_RN1(instr) (V850_REG_NAMES[F11_REG1(instr)])
#define F11_RN2(instr) (V850_REG_NAMES[F11_REG2(instr)])
// Format XII
#define F12_IMM(instr) (F1_REG1(instr) | (((instr) & 0x7C0000) >> 13))
#define F12_REG2(instr) F1_REG2(instr)
#define F12_REG3(instr) (((instr) & 0xF8000000) >> 27)
#define F12_SUB(instr) ((((instr) & 0x7800001) >> 22) | (((instr) & 2) >> 1))

#define F12_RN2(instr) (V850_REG_NAMES[F12_REG2(instr)])
#define F12_RN3(instr) (V850_REG_NAMES[F12_REG3(instr)])

// Format XIII
#define F13_IMM(instr) (((instr) & 0x3E) >> 1)
// Also a subopcode
#define F13_REG2(instr) (((instr) & 0x1F0000) >> 16)
#define F13_LIST(instr) (((instr) && 0xFFE00000) >> 21)

#define F13_RN2(instr) (V850_REG_NAMES[F13_REG2(instr)])

#define	SEXT_IMM16_32(imm16)	(((imm16) & 0x8000)? ((imm16) | 0xffff0000): (imm16))

static const char* V850_REG_NAMES[] = {
	"zero",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
	"r16",
	"r17",
	"r18",
	"r19",
	"r20",
	"r21",
	"r22",
	"r23",
	"r24",
	"r25",
	"r26",
	"r27",
	"r28",
	"r29",
	"ep",
	"lp",
};

static const char * const esil_conds[] = {
	[V850_COND_V]	= "v",
	[V850_COND_CL]	= "cy",
	[V850_COND_ZE]	= "z",
	[V850_COND_NH]	= "cy,z,|",
	[V850_COND_N]	= "s",
	[V850_COND_AL]	= "1",
	[V850_COND_LT]	= "s,ov,^",
	[V850_COND_LE]	= "s,ov,^,z,|",
	[V850_COND_NV]	= "ov,!",
	[V850_COND_NC]	= "cy,!",
	[V850_COND_NZ]	= "z,!",
	[V850_COND_H]	= "cy,z,|,!",
	[V850_COND_NS]	= "s,!",
	[V850_COND_SA]	= "sat",
	[V850_COND_GE]	= "s,ov,^,!",
	[V850_COND_GT]	= "s,ov,^,z,|,!",
};

static char *get_sysreg(ut32 regid) {
	//TODO: check cpu-model
	switch (regid) {
	case 0:
		return "eipc";
	case 1:
		return "eipsw";
	case 2:
		return "fepc";
	case 3:
		return "fepsw";
	case 4:
		return "ecr";
	case 5:
		return "psw";
	case 16:
		return "ctpc";
	case 17:
		return "ctpsw";
	case 18:
		return "dbpc";
	case 19:
		return "dbpsw";
	case 20:
		return "ctbp";
	}
	return NULL;
}

static void update_flags(RAnalOp *op, int flags) {
	if (flags & V850_FLAG_CY) {
		r_strbuf_append (&op->esil, "31,$c,cy,:=");
	}
	if (flags & V850_FLAG_OV) {
		r_strbuf_append (&op->esil, ",31,$o,ov,:=");
	}
	if (flags & V850_FLAG_S) {
		r_strbuf_append (&op->esil, ",31,$s,s,:=");
	}
	if (flags & V850_FLAG_Z) {
		r_strbuf_append (&op->esil, ",$z,z,:=");
	}
}

static void clear_flags(RAnalOp *op, int flags) {
	if (flags & V850_FLAG_CY) {
		r_strbuf_append (&op->esil, ",0,cy,:=");
	}
	if (flags & V850_FLAG_OV) {
		r_strbuf_append (&op->esil, ",0,ov,:=");
	}
	if (flags & V850_FLAG_S) {
		r_strbuf_append (&op->esil, ",0,s,:=");
	}
	if (flags & V850_FLAG_Z) {
		r_strbuf_append (&op->esil, ",0,z,:=");
	}
}

static int v850e0_op(RArchSession *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	ut8 opcode = 0;
	const char *reg1 = NULL;
	const char *reg2 = NULL;
	ut32 bitmask = 0;
	ut16 destaddr = 0;
	st16 destaddrs = 0;
	struct v850_cmd cmd = {0};

	if (len < 1 || !memcmp (buf, "\xff\xff\xff\xff\xff\xff", R_MIN (len, 6))) {
		return -1;
	}

	int ret = op->size = v850_decode_command (buf, len, &cmd);
	if (ret < 1) {
		return ret;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		if (R_STR_ISNOTEMPTY (cmd.operands)) {
			op->mnemonic = r_str_newf ("%s %s", cmd.instr, cmd.operands);
 		} else {
			op->mnemonic = r_str_newf ("%s", cmd.instr);
		}
	}

	op->addr = addr;

	ut16 word1 = r_read_le16 (buf);
	ut16 word2 = (ret == 4)? r_read_le16 (buf + 2): 0;
	opcode = get_opcode (word1);

	switch (opcode) {
	case V850_MOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		r_strbuf_appendf (&op->esil, "%s,%s,:=", F1_RN1 (word1), F1_RN2 (word1));
		break;
	case V850_MOV_IMM5:
		op->type = R_ANAL_OP_TYPE_MOV;
		r_strbuf_appendf (&op->esil, "0x%x,%s,:=", SEXT5 (F2_IMM(word1)), F2_RN2 (word1));
		break;
	case V850_MOVEA:
		op->type = R_ANAL_OP_TYPE_MOV;
#if 0
		// FIXME: to decide about reading 16/32 bit and use only macros to access
		r_strbuf_appendf (&op->esil, "%s,0xffff,&,%u,+,%s,=", F6_RN1(word1), word2, F6_RN2(word1));
#else
		r_strbuf_appendf (&op->esil, "0x%x,%s,+,%s,:=", SEXT_IMM16_32 (word2), F6_RN1 (word1), F6_RN2 (word1));
#endif
		break;
	case V850_SLDB:
		// sign extension here is probably a good candidate for a custom op
		// avoid using DUP here to not fuck up esil-dfg
		r_strbuf_appendf (&op->esil, "ep,0x%x,+,[1],ep,0x%x,+,[1],0x80,&,!,!,0xffffff00,*,|,%s,:=",
			word1 & 0x7f, word1 & 0x7f, F4_RN2 (word1));
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (F4_REG2 (word1) == V850_SP) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = 0;
		}
		break;
	case V850_SLDH:
		r_strbuf_appendf (&op->esil, "ep,0x%x,+,[2],ep,0x%x,+,[2],0x8000,&,!,!,0xffff0000,*,|,%s,:=",
			(word1 & 0x7f) << 1, (word1 & 0x7f) << 1, F4_RN2 (word1));
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (F4_REG2 (word1) == V850_SP) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = 0;
		}
		break;
	case V850_SLDW:
		r_strbuf_appendf (&op->esil, "ep,0x%x,+,[4],%s,:=", (word1 & 0x7e) << 1, F4_RN2 (word1));
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (F4_REG2 (word1) == V850_SP) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = 0;
		}
		break;
	case V850_SSTB:
		r_strbuf_appendf (&op->esil, "%s,ep,0x%x,+,=[1]", F4_RN2 (word1), word1 & 0x7f);
		op->type = R_ANAL_OP_TYPE_STORE;
		if (F4_REG2 (word1) == V850_SP) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = 0;
		}
		break;
	case V850_SSTH:
		r_strbuf_appendf (&op->esil, "%s,ep,0x%x,+,=[2]", F4_RN2 (word1), (word1 & 0x7f) << 1);
		op->type = R_ANAL_OP_TYPE_STORE;
		if (F4_REG2 (word1) == V850_SP) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = 0;
		}
		break;
	case V850_SSTW:
		r_strbuf_appendf (&op->esil, "%s,ep,0x%x,+,=[4]", F4_RN2 (word1), (word1 & 0x7e) << 1);
		op->type = R_ANAL_OP_TYPE_STORE;
		if (F4_REG2 (word1) == V850_SP) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = 0;
		}
		break;
	case V850_LDB:
		op->type = R_ANAL_OP_TYPE_LOAD;
		r_strbuf_appendf (&op->esil, "0x%x,%s,+,[1],0x%x,%s,+,[1],0x80,&,!,!,0xffffff00,*,|,%s,:=",
			SEXT_IMM16_32 (word2), F6_RN1 (word1), SEXT_IMM16_32 (word2),
			F6_RN1 (word1), F6_RN2 (word1));
		break;
	case V850_LDHW:
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (word2 & 0x1) {
			// LDW
			const ut32 imm = SEXT_IMM16_32 (word2) & 0xfffffffe;
			r_strbuf_appendf (&op->esil, "0x%x,%s,+,[4],%s,:=", imm, F6_RN1 (word1), F6_RN2 (word1));
		} else {
			// LDH
			const ut32 imm = SEXT_IMM16_32 (word2);
			r_strbuf_appendf (&op->esil, "0x%x,%s,+,[2],0x%x,%s,+,[2],0x8000,&,!,!,0xffff0000,*,|,%s,:=",
				imm, F6_RN1 (word1), imm, F6_RN1 (word1), F6_RN2 (word1));
		}
		break;
	case V850_STB:
		op->type = R_ANAL_OP_TYPE_STORE;
		r_strbuf_appendf (&op->esil, "%s,0x%x,%s,+,=[1]", F6_RN1 (word1), SEXT_IMM16_32 (word2), F6_RN2 (word1));
		break;
	case V850_STHW:
		op->type = R_ANAL_OP_TYPE_STORE;
		if (word2 & 0x1) {
			// STW
			r_strbuf_appendf (&op->esil, "%s,0x%x,%s,+,=[4]", F6_RN1 (word1),
				SEXT_IMM16_32 (word2) & 0xfffffffe, F6_RN2 (word1));
		} else {
			// STH
			r_strbuf_appendf (&op->esil, "%s,0x%x,%s,+,=[2]", F6_RN1 (word1),
				SEXT_IMM16_32 (word2), F6_RN2 (word1));
		}
		break;
	case V850_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		r_strbuf_appendf (&op->esil, "%s,0xffffffff,^,%s,=",F1_RN1(word1), F1_RN2(word1));
		update_flags (op, V850_FLAG_S | V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV);
		break;
	case V850_DIVH:
		op->type = R_ANAL_OP_TYPE_DIV;
		// TODO add customop for signed division
		r_strbuf_appendf (&op->esil, "%s,%s,0xffff,&,/,%s,=",
						 F1_RN1(word1), F1_RN2(word1), F1_RN2(word1));
		update_flags (op, V850_FLAG_OV | V850_FLAG_S | V850_FLAG_Z);
		break;
	case V850_JMP:
		if (F1_REG1 (word1) == 31) {
			op->type = R_ANAL_OP_TYPE_RET;
		} else {
			op->type = R_ANAL_OP_TYPE_UJMP;
		}
		op->jump = word1; // UT64_MAX; // this is n RJMP instruction .. F1_RN1 (word1);
		op->fail = addr + 2;
		r_strbuf_appendf (&op->esil, "%s,pc,:=", F1_RN1(word1));
		break;
	case V850_JARL2:
		// TODO: fix displacement reading
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + F5_DISP (((ut32)word2 << 16) | word1);
		r_strbuf_appendf (&op->esil, "pc,%s,:=,0x%"PFMT64x",pc,:=", F5_RN2 (word1), op->jump);
		break;
	case V850_JARL1:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + F5_DISP (((ut32)word2 << 16) | word1);
		r_strbuf_appendf (&op->esil, "0x%"PFMT64x",pc,:=", op->jump);
		break;
	case V850_OR:
		op->type = R_ANAL_OP_TYPE_OR;
		r_strbuf_appendf (&op->esil, "%s,%s,|=", F1_RN1(word1), F1_RN2(word1));
		update_flags (op, V850_FLAG_S | V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV);
		break;
	case V850_ORI:
		op->type = R_ANAL_OP_TYPE_OR;
		r_strbuf_appendf (&op->esil, "0x%x,%s,|,%s,=", word2, F6_RN1(word1), F6_RN2(word1));
		update_flags (op, V850_FLAG_S | V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV);
		break;
	case V850_MULH:
		op->type = R_ANAL_OP_TYPE_MUL;
		r_strbuf_appendf (&op->esil,
			"0xffff,%s,&=,%s,0x8000,&,%s,0x8000,&,^,?{,%s,0xffff,&,%s,*,0xffffffff,^,1,+,%s,=,}{,%s,0xffff,&,%s,*,%s,=,}",
			F6_RN2 (word1), F6_RN1 (word1), F6_RN2 (word1), F6_RN1 (word1),
			F6_RN2 (word1), F6_RN2 (word1), F6_RN1 (word1), F6_RN2 (word1), F6_RN2 (word1));
		update_flags (op, -1);
		break;
	case V850_MULH_IMM5:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case V850_XOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		r_strbuf_appendf (&op->esil, "%s,%s,^=", F1_RN1(word1), F1_RN2(word1));
		update_flags (op, V850_FLAG_S | V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV);
		break;
	case V850_XORI:
		op->type = R_ANAL_OP_TYPE_XOR;
		r_strbuf_appendf (&op->esil, "0x%x,%s,^,%s,=", word2, F6_RN1(word1), F6_RN2(word1));
		update_flags (op, V850_FLAG_S | V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV);
		break;
	case V850_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		r_strbuf_appendf (&op->esil, "%s,%s,&=", F1_RN1(word1), F1_RN2(word1));
		update_flags (op, V850_FLAG_S | V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV);
		break;
	case V850_ANDI:
		op->type = R_ANAL_OP_TYPE_AND;
		r_strbuf_appendf (&op->esil, "%hu,%s,&,%s,=", word2, F6_RN1(word1), F6_RN2(word1));
		update_flags (op, V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV | V850_FLAG_S);
		break;
	case V850_CMP:
		op->type = R_ANAL_OP_TYPE_CMP;
		r_strbuf_appendf (&op->esil, "%s,%s,==", F1_RN1(word1), F1_RN2(word1));
		update_flags (op, -1);
		break;
	case V850_CMP_IMM5:
		op->type = R_ANAL_OP_TYPE_CMP;
		r_strbuf_appendf (&op->esil, "0x%x,%s,==", SEXT5 (F2_IMM (word1)), F2_RN2 (word1));
		update_flags (op, -1);
		break;
	case V850_TST:
		op->type = R_ANAL_OP_TYPE_CMP;
		r_strbuf_appendf (&op->esil, "%s,%s,&", F1_RN1(word1), F1_RN2(word1));
		update_flags (op, V850_FLAG_S | V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV);
		break;
	case V850_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		r_strbuf_appendf (&op->esil, "%s,%s,-=", F1_RN1(word1), F1_RN2(word1));
		update_flags (op, -1);
		break;
	case V850_SUBR:
		op->type = R_ANAL_OP_TYPE_SUB;
		r_strbuf_appendf (&op->esil, "%s,%s,-,%s=", F1_RN2 (word1), F1_RN1 (word1), F1_RN2 (word1));
		update_flags (op, -1);
		break;
	case V850_ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		r_strbuf_appendf (&op->esil, "%s,%s,+=", F1_RN1 (word1), F1_RN2 (word1));
		update_flags (op, -1);
		break;
	case V850_ADD_IMM5:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (F2_REG2(word1) == V850_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = F2_IMM (word1);
			op->val = op->stackptr;
		}
		r_strbuf_appendf (&op->esil, "0x%x,%s,+=", SEXT5 (F2_IMM (word1)), F2_RN2 (word1));
		update_flags (op, -1);
		break;
	case V850_ADDI:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (F6_REG2(word1) == V850_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = (st64) word2;
			op->val = op->stackptr;
		}
		r_strbuf_appendf (&op->esil, "0x%x,%s,+,%s,=",  SEXT_IMM16_32 (word2), F6_RN1 (word1), F6_RN2 (word1));
		update_flags (op, -1);
		break;
	case V850_SHR_IMM5:
		op->type = R_ANAL_OP_TYPE_SHR;
		r_strbuf_appendf (&op->esil, "%u,%s,>>=", (ut8)F2_IMM (word1), F2_RN2 (word1));
		update_flags (op, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV);
		break;
	case V850_SAR_IMM5:
		op->type = R_ANAL_OP_TYPE_SAR;
		ut16 imm5 = F2_IMM(word1);
		reg2 = F2_RN2(word1);
		r_strbuf_appendf (&op->esil, "31,%s,>>,?{,%u,32,-,%u,1,<<,--,<<,}{,0,},%u,%s,>>,|,%s,=", reg2, (ut8)imm5, (ut8)imm5, (ut8)imm5, reg2, reg2);
		update_flags (op, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV);
		break;
	case V850_SHL_IMM5:
		op->type = R_ANAL_OP_TYPE_SHL;
		r_strbuf_appendf (&op->esil, "%u,%s,<<=", (ut8)F2_IMM(word1), F2_RN2(word1));
		update_flags (op, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV);
		break;
	case V850_SATADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		// check overflow for msb sign and saturate accordingly
		r_strbuf_appendf (&op->esil, "%s,%s,+=,31,$o,?{,31,$s,?{,0x7fffffff,%s,:=,}{,0x80000000,%s,:=,},}",
			F1_RN1 (word1), F1_RN2 (word1), F1_RN2 (word1), F1_RN2 (word1));
		break;
	case V850_SATADD_IMM5:
		op->type = R_ANAL_OP_TYPE_ADD;
		// check overflow for msb sign and saturate accordingly
		r_strbuf_appendf (&op->esil,
			"0x%x,%s,+=,31,$o,sat,:=,sat,?{,31,$s,?{,0x7fffffff,%s,:=,}{,0x80000000,%s,:=,},}",
			SEXT5 (F2_IMM (word1)), F2_RN2 (word1), F2_RN2 (word1), F2_RN2 (word1));
		update_flags (op, -1);
		break;
	case V850_SATSUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		// check overflow for msb sign and saturate accordingly
		r_strbuf_appendf (&op->esil,
			"%s,%s,-=,31,$o,sat,:=,sat,?{,31,$s,?{,0x7fffffff,%s,:=,}{,0x80000000,%s,:=,},}",
			F1_RN1 (word1), F1_RN2 (word1), F1_RN2 (word1), F1_RN2 (word1));
		update_flags (op, -1);
		break;
	case V850_SATSUBR:
		op->type = R_ANAL_OP_TYPE_SUB;
		r_strbuf_appendf (&op->esil,
			"%s,NUM,%s,%s,:=,%s,-=,31,$o,sat,:=,sat,?{,31,$s,?{,0x7fffffff,%s,:=,}{,0x80000000,%s,:=,},}",
			F1_RN2 (word1), F1_RN1 (word1), F1_RN2 (word1), F1_RN2 (word1), F1_RN2 (word1), F1_RN2 (word1));
		update_flags (op, -1);
		break;
	case V850_SATSUBI:
		op->type = R_ANAL_OP_TYPE_SUB;
		{
			const char *dst = F6_RN2 (word1);
			const char *src = F6_RN1 (word1);
			r_strbuf_appendf (&op->esil,
				"%s,%s,:=,0x%x,%s,-=,31,$o,sat,:=,sat,?{,31,$s,?{,0x7fffffff,%s,:=,}{,0x80000000,%s,:=,},}",
				src, dst, SEXT_IMM16_32 (word2), dst, dst, dst);
			update_flags (op, -1);
		}
		break;
	case V850_BCOND:
	case V850_BCOND2:
	case V850_BCOND3:
	case V850_BCOND4:
		destaddr = ((((word1 >> 4) & 0x7) |
			((word1 >> 11) << 3)) << 1);
		if (destaddr & 0x100) {
			destaddrs = destaddr | 0xfe00;
		} else {
			destaddrs = destaddr;
		}
		op->jump = addr + destaddrs;
		op->fail = addr + 2;
		if (F3_COND (word1) == V850_COND_AL) {
			op->type = R_ANAL_OP_TYPE_JMP;
			r_strbuf_appendf (&op->esil, "0x%"PFMT64x",pc,:=", op->jump);
		} else {
			op->type = R_ANAL_OP_TYPE_CJMP;
			r_strbuf_appendf (&op->esil, "%s,?{,0x%"PFMT64x",pc,:=,}",
				esil_conds[F3_COND (word1)], op->jump);
		}
		break;
	case V850_BIT_MANIP:
		{
			ut8 bitop = word1 >> 14;
			switch (bitop) {
			case V850_BIT_CLR1:
				bitmask = (1 << F8_BIT(word1));
				r_strbuf_appendf (&op->esil,
					"0%x,%s,+,0xffffffff,&,[1],DUP,0x%x,&,!,z,:=,0x%x,&,0x%x,%s,+,0xffffffff,&,=[1]",
					SEXT_IMM16_32 (word2), F8_RN1 (word1), bitmask,
					bitmask ^ 0xff, SEXT_IMM16_32 (word2), F8_RN1 (word1));
				break;
			case V850_BIT_NOT1:
				bitmask = (1 << F8_BIT(word1));
				r_strbuf_appendf (&op->esil,
					"0x%x,%s,+,0xffffffff,&,[1],DUP,0x%x,&,!,z,:=,0x%x,^,0x%x,%s,+,0xffffffff,&,=[1]",
					SEXT_IMM16_32 (word2), F8_RN1 (word1), bitmask,
					bitmask, SEXT_IMM16_32 (word2), F8_RN1 (word1));
				break;
			case V850_BIT_TST1:
				bitmask = (1 << F8_BIT(word1));
				r_strbuf_appendf (&op->esil, "0x%x,%s,+,0xffffffff,&,[1],0x%x,&,!,z,:=",
					SEXT_IMM16_32 (word2), F8_RN1 (word1), bitmask);
				break;
			}
		}
		break;
	case V850_EXT1:
		switch (get_subopcode(word1 | (ut32)word2 << 16)) {
		case V850_EXT_SETF:
			op->type = R_ANAL_OP_TYPE_MOV;
			// probably not matching format, but it should work anyways
			r_strbuf_appendf (&op->esil, "%s,%s,:=", esil_conds[F3_COND (word1)], F9_RN2 (word1));
			// update flags here?
			break;
		case V850_EXT_LDSR:
			{
				const ut32 regid = (word1 & 0xf800) >> 11;
				if (regid == 4) {
					break;
				}
				const char *sr = get_sysreg (regid);
				if (!sr) {
					break;
				}
				op->type = R_ANAL_OP_TYPE_LOAD;
				r_strbuf_appendf (&op->esil, "%s,%s,:=", F9_RN1 (word1), sr);
				if (regid == 5) {
					r_strbuf_append (&op->esil, "0,sat,:=");
					clear_flags (op, -1);
				}
			}
			break;
		case V850_EXT_STSR:
			{
				const char *sr = get_sysreg ((word1 & 0xf800) >> 11);
				if (!sr) {
					break;
				}
				op->type = R_ANAL_OP_TYPE_STORE;
				r_strbuf_appendf (&op->esil, "%s,%s,:=", sr, F9_RN1 (word1));
			}
			break;
		case V850_EXT_SHL:
			op->type = R_ANAL_OP_TYPE_SHL;
			r_strbuf_appendf (&op->esil, "%s,%s,<<=", F9_RN1(word1), F9_RN2(word1));
			update_flags (op, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
			clear_flags (op, V850_FLAG_OV);
			break;
		case V850_EXT_SHR:
			op->type = R_ANAL_OP_TYPE_SHR;
			r_strbuf_appendf (&op->esil, "%s,%s,>>=", F9_RN1(word1), F9_RN2(word1));
			update_flags (op, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
			clear_flags (op, V850_FLAG_OV);
			break;
		case V850_EXT_SAR:
			op->type = R_ANAL_OP_TYPE_SAR;
			reg1 = F9_RN1 (word1);
			reg2 = F9_RN2 (word1);
			r_strbuf_appendf (&op->esil, "31,%s,>>,?{,%s,32,-,%s,1,<<,--,<<,}{,0,},%s,%s,>>,|,%s,=", reg2, reg1, reg1, reg1, reg2, reg2);
			update_flags (op, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
			clear_flags (op, V850_FLAG_OV);
			break;
		case V850_EXT_RETI:
			op->type = R_ANAL_OP_TYPE_RCJMP;
			r_strbuf_append (&op->esil, "epi,!,npi,&,?{,fepc,pc,:=,fepsw,psw,:=,BREAK,},eipc,pc,:=,eipsw,psw,:=");
			break;
		case V850_EXT_EXT2:
			//ei and di
			op->type = R_ANAL_OP_TYPE_MOV;
			r_strbuf_appendf (&op->esil, "%d,id,:=", (word2 >> 13) & 1);
			break;
		}
		break;
	}

	return ret;
}

// V850NP

#define DEFAULT_CPU_MODEL V850_CPU_E2
static int cpumodel_from_string(const char *s) {
	if (R_STR_ISEMPTY (s) || !strcmp (s, "v850")) {
		return DEFAULT_CPU_MODEL;
	}
	if (!strcmp (s, "all")) {
		return V850_CPU_ALL;
	}
	if (!strcmp (s, "e2v3")) {
		return V850_CPU_E2V3;
	}
	if (!strcmp (s, "e3v5")) {
		return V850_CPU_E3V5;
	}
	if (!strcmp (s, "e2")) {
		return V850_CPU_E2;
	}
	if (!strcmp (s, "e1")) {
		return V850_CPU_E1;
	}
	if (!strcmp (s, "e0")) {
		return V850_CPU_E0;
	}
	if (!strcmp (s, "e")) {
		return V850_CPU_E;
	}
	if (!strcmp (s, "0")) {
		return V850_CPU_0;
	}
	int num = r_num_get (NULL, s);
	return num? num: DEFAULT_CPU_MODEL;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;
// static int v850_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	int cpumodel = cpumodel_from_string (as->config->cpu);
	if (cpumodel == V850_CPU_E0) {
		//  RAnal *anal = ((RCore*)(as->user))->anal;
		return v850e0_op (as, op, op->addr, buf, len, mask);
	}
#if 0
	cpumodel |= V850_CPU_OPTION_ALIAS;
	cpumodel |= V850_CPU_OPTION_EXTENSION;
#endif
	v850np_inst inst = {0};
	op->size = v850np_disasm (&inst, cpumodel, addr, buf, len);
	if (op->size < 2) {
		op->size = 2;
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		r_strbuf_set (&op->esil, inst.esil);
	}
	if (inst.op) {
		op->type = inst.op->type;
		op->family = inst.op->family;
		if (len >= 2 && !memcmp (buf, "\x7f\x00", 2)) {
			op->type = R_ANAL_OP_TYPE_RET;
		}
	}
	switch (op->type) {
	case R_ANAL_OP_TYPE_MOV:
		op->val = inst.value;
		break;
	case R_ANAL_OP_TYPE_STORE:
	case R_ANAL_OP_TYPE_LOAD:
		op->ptr = inst.value;
		break;
	case R_ANAL_OP_TYPE_JMP:
		op->jump = addr + inst.value;
		break;
	case R_ANAL_OP_TYPE_CJMP:
		op->jump = addr + inst.value;
		op->fail = addr + inst.size;
		break;
	case R_ANAL_OP_TYPE_POP:
		if (inst.op && strstr (inst.op->esil, "#2")) {
			op->type = R_ANAL_OP_TYPE_RET;
		}
		break;
	case R_ANAL_OP_TYPE_CALL:
		op->jump = addr + inst.value;
		op->fail = addr + inst.size;
		break;
	}
	op->size = inst.size;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		if (as->config->syntax == R_ARCH_SYNTAX_ATT) {
			op->mnemonic = r_str_replace (inst.text, "[r", "[%r", -1);
			op->mnemonic = r_str_replace (op->mnemonic, " r", " %r", -1);
			op->mnemonic = r_str_replace (op->mnemonic, "(r", "(%r", -1);
		} else {
			op->mnemonic = inst.text;
		}
	} else {
		free (inst.text);
	}
	return inst.size;
}

static char *regs(RArchSession *s) {
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	ep\n"
		"=SN	r1\n"
		"=ZF	z\n"
		"=A0	r1\n"
		"=A1	r5\n"
		"=A2	r6\n"
		"=A3	r7\n"
		"=A4	r8\n"
		"=SF	s\n"
		"=OF	ov\n"
		"=CF	cy\n"

		"gpr	r0	.32	?   0\n"
		"gpr	r1	.32	4   0\n"
		"gpr	r2	.32	8   0\n"
		"gpr	sp	.32	12  0\n"
		"gpr	r3	.32	12  0\n"
		"gpr	gp	.32	16  0\n"
		"gpr	r4	.32	16  0\n"
		"gpr	r5	.32	20  0\n"
		"gpr	tp	.32	20  0\n"
		"gpr	r6	.32	24  0\n"
		"gpr	r7	.32	28  0\n"
		"gpr	r8	.32	32  0\n"
		"gpr	r9	.32	36  0\n"
		"gpr	r10	.32	40  0\n"
		"gpr	r11	.32	44  0\n"
		"gpr	r12	.32	48  0\n"
		"gpr	r13	.32	52  0\n"
		"gpr	r14	.32	56  0\n"
		"gpr	r15	.32	60  0\n"
		"gpr	r16	.32	64  0\n"
		"gpr	r17	.32	68  0\n"
		"gpr	r18	.32	72  0\n"
		"gpr	r19	.32	76  0\n"
		"gpr	r20	.32	80  0\n"
		"gpr	r21	.32	84  0\n"
		"gpr	r22	.32	88  0\n"
		"gpr	r23	.32	92  0\n"
		"gpr	r24	.32	96  0\n"
		"gpr	r25	.32	100 0\n"
		"gpr	r26	.32	104 0\n"
		"gpr	r27	.32	108 0\n"
		"gpr	r28	.32	112 0\n"
		"gpr	r29	.32	116 0\n"
		"gpr	r30	.32	120 0\n"
		"gpr	ep	.32	120 0\n"
		"gpr	r31	.32	124 0\n"
		"gpr	lp	.32	124 0\n"
		"gpr	pc	.32	128 0\n"

		// 32bit [   RFU   ][NP EP ID SAT CY OV S Z]
		"gpr	psw .32 132 0\n" // program status word
		"gpr	npi  .1 132.16 0\n" // non maskerable interrupt (NMI)
		"gpr	epi  .1 132.17 0\n" // exception processing interrupt
		"gpr	id   .1 132.18 0\n" // :? should be id
		"gpr	sat  .1 132.19 0\n" // saturation detection
		"flg	cy  .1 132.28 0 carry\n" // carry or borrow
		"flg	ov  .1 132.29 0 overflow\n" // overflow
		"flg	s   .1 132.30 0 sign\n" // signed result
		"flg	z   .1 132.31 0 zero\n" // zero result

		"gpr	eipc	.32	$	0\n"
		"gpr	eipsw	.32	$	0\n"
		"gpr	fepc	.32	$	0\n"
		"gpr	fepsw	.32	$	0\n"
		"gpr	ecr	.32	$	0\n"
		"gpr	sr6	.32	$	0\n"
		"gpr	sr7	.32	$	0\n"
		"gpr	sr8	.32	$	0\n"
		"gpr	sr9	.32	$	0\n"
		"gpr	sr10	.32	$	0\n"
		"gpr	sr11	.32	$	0\n"
		"gpr	sr12	.32	$	0\n"
		"gpr	eiic	.32	$	0\n"
		"gpr	feic	.32	$	0\n"
		"gpr	dbic	.32	$	0\n"
		"gpr	ctpc	.32	$	0\n"
		"gpr	ctpcw	.32	$	0\n"
		"gpr	dbpc	.32	$	0\n"
		"gpr	dbpsw	.32	$	0\n"
		"gpr	ctbp	.32	$	0\n"
		"gpr	dir	.32	$	0\n"
		"gpr	bpc	.32	$	0\n"
		"gpr	asid	.32	$	0\n"
		"gpr	bpav	.32	$	0\n"
		"gpr	bpam	.32	$	0\n"
		"gpr	bpdv	.32	$	0\n"
		"gpr	bpdm	.32	$	0\n"
		"gpr	eiwr	.32	$	0\n"
		"gpr	fewr	.32	$	0\n"
		"gpr	dbwr	.32	$	0\n"
		"gpr	bsel	.32	$	0\n";
	return strdup (p);
}

static RList *preludes(RArchSession *as) {
	RList *l = r_list_newf (free);
	r_list_append (l, r_str_newf ("8007 f0ff"));
	r_list_append (l, r_str_newf ("501a630f f0ffff0f"));
	return l;
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_CODE_ALIGN:
	case R_ARCH_INFO_DATA_ALIGN:
		return 2;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 8;
	case R_ARCH_INFO_MINOP_SIZE:
		return 2;
	}
	return 0;
}

static bool encode(RArchSession *s, RAnalOp *op, ut32 mask) {
	R_RETURN_VAL_IF_FAIL (s && op, false);
	const char *str = op->mnemonic;
	if (!strcmp (str, "nop")) {
		r_anal_op_set_bytes (op, op->addr, (const ut8* const)"\x00\x00", 2);
		// memset (op->bytes, 0, R_MIN (op->size, 2));
		return 2;
	}
	return 0;
}

const RArchPlugin r_arch_plugin_v850 = {
	.meta = {
		.name = "v850",
		.author = "pancake,brainstorm,condret",
		.desc = "V850 Renesas Electronics RISC",
		.license = "MIT",
	},
	.preludes = preludes,
	.cpus = "e0,0,e,e1,e2,e2v3,e3v5,all",
	.arch = "v850",
	.bits = 32,
	.encode = encode,
	.decode = decode,
	.info = archinfo,
	.regs = regs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_v850,
	.version = R2_VERSION
};
#endif

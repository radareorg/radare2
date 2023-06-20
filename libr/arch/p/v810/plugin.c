/* radare - LGPL - Copyright 2015-2023 - danielps, pancake */

#include <r_arch.h>
#include "./v810_disas.h"

enum {
	V810_FLAG_CY = 1,
	V810_FLAG_OV = 2,
	V810_FLAG_S = 4,
	V810_FLAG_Z = 8,
};

static void update_flags(RAnalOp *op, int flags) {
	if (flags & V810_FLAG_CY) {
		r_strbuf_append (&op->esil, ",31,$c,cy,:=");
	}
	if (flags & V810_FLAG_OV) {
		r_strbuf_append (&op->esil, ",31,$o,ov,:=");
	}
	if (flags & V810_FLAG_S) {
		r_strbuf_append (&op->esil, ",31,$s,s,:=");
	}
	if (flags & V810_FLAG_Z) {
		r_strbuf_append (&op->esil, ",$z,z,:=");
	}
}

static void clear_flags(RAnalOp *op, int flags) {
	if (flags & V810_FLAG_CY) {
		r_strbuf_append (&op->esil, ",0,cy,:=");
	}
	if (flags & V810_FLAG_OV) {
		r_strbuf_append (&op->esil, ",0,ov,:=");
	}
	if (flags & V810_FLAG_S) {
		r_strbuf_append (&op->esil, ",0,s,:=");
	}
	if (flags & V810_FLAG_Z) {
		r_strbuf_append (&op->esil, ",0,z,:=");
	}
}

static bool v810_decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	ut64 addr = op->addr;
	int len = op->size;
	const ut8 *buf = op->bytes;
	ut8 opcode, reg1, reg2, imm5, cond;
	ut16 word2 = 0;
	st32 jumpdisp;
	struct v810_cmd cmd;

	memset (&cmd, 0, sizeof (cmd));

	int ret = v810_decode_command (buf, len, &cmd);
	if (ret <= 0) {
		op->size = 1;
		return ret;
	}
	op->size = ret;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = r_str_newf ("%s %s", cmd.instr, cmd.operands);
	}
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (s->config);
	ut16 word1 = r_read_ble16 (buf, be);
	if (ret == 4) {
		word2 = r_read_ble16 (buf + 2, be);
	}
	op->addr = addr;
	opcode = OPCODE (word1);
	if (opcode >> 3 == 0x4) {
		opcode &= 0x20;
	}

	switch (opcode) {
	case V810_MOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (mask & R_ARCH_OP_MASK_ESIL) {
			r_strbuf_appendf (&op->esil, "r%u,r%u,=", REG1(word1), REG2(word1));
		}
		break;
	case V810_MOV_IMM5:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (mask & R_ARCH_OP_MASK_ESIL) {
			r_strbuf_appendf (&op->esil, "%d,r%u,=", (st8)SEXT5(IMM5(word1)), REG2(word1));
		}
		break;
	case V810_MOVHI:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (mask & R_ARCH_OP_MASK_ESIL) {
			r_strbuf_appendf (&op->esil, "16,%hu,<<,r%u,+,r%u,=", word2, REG1(word1), REG2(word1));
		}
		break;
	case V810_MOVEA:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (mask & R_ARCH_OP_MASK_ESIL) {
			r_strbuf_appendf (&op->esil, "%hd,r%u,+,r%u,=", word2, REG1(word1), REG2(word1));
		}
		break;
	case V810_LDSR:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case V810_STSR:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case V810_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		if (mask & R_ARCH_OP_MASK_ESIL) {
			r_strbuf_appendf (&op->esil, "r%u,0xffffffff,^,r%u,=", REG1(word1), REG2(word1));
		}
		update_flags (op, V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_DIV:
	case V810_DIVU:
		op->type = R_ANAL_OP_TYPE_DIV;
		if (mask & R_ARCH_OP_MASK_ESIL) {
			r_strbuf_appendf (&op->esil, "r%u,r%u,/=,r%u,r%u,%%,r30,=",
						 REG1(word1), REG2(word1),
						 REG1(word1), REG2(word1));
		}
		update_flags (op, V810_FLAG_OV | V810_FLAG_S | V810_FLAG_Z);
		break;
	case V810_JMP:
		if (REG1 (word1) == 31) {
			op->type = R_ANAL_OP_TYPE_RET;
		} else {
			op->type = R_ANAL_OP_TYPE_UJMP;
		}
		r_strbuf_appendf (&op->esil, "r%u,pc,:=", REG1(word1));
		break;
	case V810_OR:
		op->type = R_ANAL_OP_TYPE_OR;
		if (mask & R_ARCH_OP_MASK_ESIL) {
			r_strbuf_appendf (&op->esil, "r%u,r%u,|=",
				REG1(word1), REG2(word1));
		}
		update_flags (op, V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_ORI:
		op->type = R_ANAL_OP_TYPE_OR;
		r_strbuf_appendf (&op->esil, "%hu,r%u,|,r%u,=",
						 word2, REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_MUL:
	case V810_MULU:
		op->type = R_ANAL_OP_TYPE_MUL;
		r_strbuf_appendf (&op->esil, "r%u,r%u,*=,32,r%u,r%u,*,>>,r30,=",
						 REG1(word1), REG2(word1),
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_OV | V810_FLAG_S | V810_FLAG_Z);
		break;
	case V810_XOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		r_strbuf_appendf (&op->esil, "r%u,r%u,^=",
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_XORI:
		op->type = R_ANAL_OP_TYPE_XOR;
		r_strbuf_appendf (&op->esil, "%hu,r%u,^,r%u,=",
						 word2, REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		r_strbuf_appendf (&op->esil, "r%u,r%u,&=",
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_ANDI:
		op->type = R_ANAL_OP_TYPE_AND;
		r_strbuf_appendf (&op->esil, "%hu,r%u,&,r%u,=",
						 word2, REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV | V810_FLAG_S);
		break;
	case V810_CMP:
		op->type = R_ANAL_OP_TYPE_CMP;
		r_strbuf_appendf (&op->esil, "r%u,r%u,==",
						 REG1(word1), REG2(word1));
		update_flags (op, -1);
		break;
	case V810_CMP_IMM5:
		op->type = R_ANAL_OP_TYPE_CMP;
		r_strbuf_appendf (&op->esil, "%d,r%u,==",
						  (st8)SEXT5(IMM5(word1)), REG2(word1));
		update_flags (op, -1);
		break;
	case V810_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		r_strbuf_appendf (&op->esil, "r%u,r%u,-=",
						 REG1(word1), REG2(word1));
		update_flags (op, -1);
		break;
	case V810_ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		r_strbuf_appendf (&op->esil, "r%u,r%u,+=",
						 REG1(word1), REG2(word1));
		update_flags (op, -1);
		break;
	case V810_ADDI:
		op->type = R_ANAL_OP_TYPE_ADD;
		r_strbuf_appendf (&op->esil, "%hd,r%u,+,r%u,=",
						 word2, REG1(word1), REG2(word1));
		update_flags (op, -1);
		break;
	case V810_ADD_IMM5:
		op->type = R_ANAL_OP_TYPE_ADD;
		r_strbuf_appendf (&op->esil, "%d,r%u,+=",
						  (st8)SEXT5(IMM5(word1)), REG2(word1));
		update_flags(op, -1);
		break;
	case V810_SHR:
		op->type = R_ANAL_OP_TYPE_SHR;
		r_strbuf_appendf (&op->esil, "r%u,r%u,>>=",
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_CY | V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_SHR_IMM5:
		op->type = R_ANAL_OP_TYPE_SHR;
		r_strbuf_appendf (&op->esil, "%u,r%u,>>=",
						  (ut8)IMM5(word1), REG2(word1));
		update_flags (op, V810_FLAG_CY | V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_SAR:
		op->type = R_ANAL_OP_TYPE_SAR;
		reg1 = REG1(word1);
		reg2 = REG2(word1);
		r_strbuf_appendf (&op->esil, "31,r%u,>>,?{,r%u,32,-,r%u,1,<<,--,<<,}{,0,},r%u,r%u,>>,|,r%u,=",
						 reg2, reg1, reg1, reg1, reg2, reg2);
		update_flags (op, V810_FLAG_CY | V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_SAR_IMM5:
		op->type = R_ANAL_OP_TYPE_SAR;
		imm5 = IMM5(word1);
		reg2 = REG2(word1);
		r_strbuf_appendf (&op->esil, "31,r%u,>>,?{,%u,32,-,%u,1,<<,--,<<,}{,0,},%u,r%u,>>,|,r%u,=",
						  reg2, (ut8)imm5, (ut8)imm5, (ut8)imm5, reg2, reg2);
		update_flags (op, V810_FLAG_CY | V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_SHL:
		op->type = R_ANAL_OP_TYPE_SHL;
		r_strbuf_appendf (&op->esil, "r%u,r%u,<<=",
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_CY | V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_SHL_IMM5:
		op->type = R_ANAL_OP_TYPE_SHL;
		r_strbuf_appendf (&op->esil, "%u,r%u,<<=",
						  (ut8)IMM5(word1), REG2(word1));
		update_flags (op, V810_FLAG_CY | V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_LDB:
		op->type = R_ANAL_OP_TYPE_LOAD;
		r_strbuf_appendf (&op->esil, "r%u,%hd,+,[1],r%u,=",
						 REG1(word1), word2, REG2(word1));
		r_strbuf_append (&op->esil, ",DUP,0x80,&,?{,0xffffff00,|,}");
		break;
	case V810_LDH:
		op->type = R_ANAL_OP_TYPE_LOAD;
		r_strbuf_appendf (&op->esil, "r%u,%hd,+,0xfffffffe,&,[2],r%u,=",
						 REG1(word1), word2, REG2(word1));
		r_strbuf_append (&op->esil, ",DUP,0x8000,&,?{,0xffffff00,|,}");
		break;
	case V810_LDW:
		op->type = R_ANAL_OP_TYPE_LOAD;
		r_strbuf_appendf (&op->esil, "r%u,%hd,+,0xfffffffc,&,[4],r%u,=",
						 REG1(word1), word2, REG2(word1));
		r_strbuf_append (&op->esil, ",DUP,0x80000000,&,?{,0xffffff00,|,}");
		break;
	case V810_STB:
		op->type = R_ANAL_OP_TYPE_STORE;
		r_strbuf_appendf (&op->esil, "r%u,r%u,%hd,+,=[1]",
						 REG2(word1), REG1(word1), word2);
		break;
	case V810_STH:
		op->type = R_ANAL_OP_TYPE_STORE;
		r_strbuf_appendf (&op->esil, "r%u,r%u,%hd,+,0xfffffffe,&,=[2]",
						 REG2(word1), REG1(word1), word2);
		break;
	case V810_STW:
		op->type = R_ANAL_OP_TYPE_STORE;
		r_strbuf_appendf (&op->esil, "r%u,r%u,%hd,+,=[4]",
						 REG2(word1), REG1(word1), word2);
		break;
	case V810_INB:
	case V810_INH:
	case V810_INW:
	case V810_OUTB:
	case V810_OUTH:
	case V810_OUTW:
		op->type = R_ANAL_OP_TYPE_IO;
		break;
	case V810_TRAP:
		op->type = R_ANAL_OP_TYPE_TRAP;
		r_strbuf_appendf (&op->esil, "%u,TRAP", IMM5(word1));
		break;
	case V810_RETI:
		op->type = R_ANAL_OP_TYPE_RET;
		// r_strbuf_append (&op->esil, "np,?{,fepc,fepsw,}{,eipc,eipsw,},psw,=,pc,=");
		break;
	case V810_JAL:
	case V810_JR:
		jumpdisp = DISP26 (word1, word2);
		op->jump = addr + jumpdisp;
		op->fail = addr + 4;

		if (opcode == V810_JAL) {
			op->type = R_ANAL_OP_TYPE_CALL;
			r_strbuf_appendf (&op->esil, "0x%"PFMT64x",+,r31,=,", op->fail);
		} else {
			op->type = R_ANAL_OP_TYPE_JMP;
		}

		r_strbuf_appendf (&op->esil, "0x%"PFMT64x",+,pc,:=", op->jump);
		break;
	case V810_BCOND:
		cond = COND(word1);
		if (cond == V810_COND_NOP) {
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		}
		jumpdisp = DISP9 (word1);
		op->jump = addr + jumpdisp;
		op->fail = addr + 2;
		op->type = R_ANAL_OP_TYPE_CJMP;

		switch (cond) {
		case V810_COND_V:
			r_strbuf_append (&op->esil, "ov");
			break;
		case V810_COND_L:
			r_strbuf_append (&op->esil, "cy");
			break;
		case V810_COND_E:
			r_strbuf_append (&op->esil, "z");
			break;
		case V810_COND_NH:
			r_strbuf_append (&op->esil, "cy,z,|");
			break;
		case V810_COND_N:
			r_strbuf_append (&op->esil, "s");
			break;
		case V810_COND_NONE:
			r_strbuf_append (&op->esil, "1");
			break;
		case V810_COND_LT:
			r_strbuf_append (&op->esil, "s,ov,^");
			break;
		case V810_COND_LE:
			r_strbuf_append (&op->esil, "s,ov,^,z,|");
			break;
		case V810_COND_NV:
			r_strbuf_append (&op->esil, "ov,!");
			break;
		case V810_COND_NL:
			r_strbuf_append (&op->esil, "cy,!");
			break;
		case V810_COND_NE:
			r_strbuf_append (&op->esil, "z,!");
			break;
		case V810_COND_H:
			r_strbuf_append (&op->esil, "cy,z,|,!");
			break;
		case V810_COND_P:
			r_strbuf_append (&op->esil, "s,!");
			break;
		case V810_COND_GE:
			r_strbuf_append (&op->esil, "s,ov,^,!");
			break;
		case V810_COND_GT:
			r_strbuf_append (&op->esil, "s,ov,^,z,|,!");
			break;
		}
		r_strbuf_appendf (&op->esil, ",?{,0x%"PFMT64x",pc,:=,}", op->jump);
		break;
	}
	op->size = ret;
	return true;
}

static char *v810_regs(RArchSession *s) {
	const char *p =
		"=PC	pc\n"
		"=SP	r3\n"
		"=A0	r0\n"
		"=ZF	z\n"
		"=SF	s\n"
		"=OF	ov\n"
		"=CF	cy\n"

		"gpr	r0	.32	?   0\n"
		"gpr	r1	.32	4   0\n"
		"gpr	r2	.32	8   0\n"
		"gpr	r3	.32	12  0\n"
		"gpr	r4	.32	16  0\n"
		"gpr	r5	.32	20  0\n"
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
		"gpr	r31	.32	124 0\n"
		"gpr	pc	.32	128 0\n"

		"gpr	psw .32 132 0\n"
		"gpr	np  .1 132.16 0\n"
		"gpr	ep  .1 132.17 0\n"
		"gpr	ae  .1 132.18 0\n"
		"gpr	id  .1 132.19 0\n"
		"flg	cy  .1 132.28 0\n"
		"flg	ov  .1 132.29 0\n"
		"flg	s   .1 132.30 0\n"
		"flg	z   .1 132.31 0\n";
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ANAL_ARCHINFO_ALIGN:
		return 1;
	case R_ANAL_ARCHINFO_DATA_ALIGN:
		return 2;
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return 1;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return 4;
	}
	return 0;
}

const RArchPlugin r_arch_plugin_v810 = {
	.meta = {
		.name = "v810",
		.desc = "V810 code analysis plugin",
		.license = "LGPL3",
	},
	.arch = "v810",
	.bits = R_SYS_BITS_PACK1 (32),
	.decode = v810_decode,
	.regs = v810_regs,
	.info = archinfo,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_v810,
	.version = R2_VERSION
};
#endif

/* radare - LGPL - Copyright 2012-2013 - pancake
	2014 - Fedor Sakharov <fedor.sakharov@gmail.com> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_util.h>
#include <r_endian.h>

#include <v850_disas.h>

static void update_flags(RAnalOp *op, int flags) {
	if (flags & V850_FLAG_CY) r_strbuf_append (&op->esil, ",$c31,cy,=");
	if (flags & V850_FLAG_OV) r_strbuf_append (&op->esil, ",$o,ov,=");
	if (flags & V850_FLAG_S) r_strbuf_append (&op->esil, ",$s,s,=");
	if (flags & V850_FLAG_Z) r_strbuf_append (&op->esil, ",$z,z,=");
}

static void clear_flags(RAnalOp *op, int flags) {
	if (flags & V850_FLAG_CY) r_strbuf_append (&op->esil, ",0,cy,=");
	if (flags & V850_FLAG_OV) r_strbuf_append (&op->esil, ",0,ov,=");
	if (flags & V850_FLAG_S) r_strbuf_append (&op->esil, ",0,s,=");
	if (flags & V850_FLAG_Z) r_strbuf_append (&op->esil, ",0,z,=");
}

static int v850_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	int ret = 0;
	ut8 opcode = 0;
	const char *reg1 = NULL;
	const char *reg2 = NULL;
	ut32 bitmask = 0;
	ut16 destaddr = 0;
	st16 destaddrs = 0;
	ut16 word1 = 0, word2 = 0;
	struct v850_cmd cmd;

	memset (&cmd, 0, sizeof (cmd));
	memset (op, 0, sizeof (RAnalOp));
	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");

	ret = op->size = v850_decode_command (buf, &cmd);

	if (ret <= 0) {
		return ret;
	}

	op->addr = addr;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;

	word1 = r_read_le16 (buf);
	if (ret == 4) {
		word2 = r_read_le16 (buf + 2);
	}
	opcode = get_opcode (word1);

	switch (opcode) {
	case V850_MOV_IMM5:
	case V850_MOV:
		// 2 formats
		op->type = R_ANAL_OP_TYPE_MOV;
		if (opcode != V850_MOV_IMM5) { // Format I
			r_strbuf_appendf (&op->esil, "%s,%s,=", F1_RN1(word1), F1_RN2(word1));
		} else { // Format II
			r_strbuf_appendf (&op->esil, "%"PFMT64d",%s,=", F2_IMM(word1), F2_RN2(word1));
		}
		break;
	case V850_MOVEA:
		op->type = R_ANAL_OP_TYPE_MOV;
		// FIXME: to decide about reading 16/32 bit and use only macroses to access
		r_strbuf_appendf (&op->esil, "%s,0xffff,&,%u,+,%s,=", F6_RN1(word1), word2, F6_RN2(word1));
		break;
	case V850_SLDB:
	case V850_SLDH:
	case V850_SLDW:
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (F4_REG2(word1) == V850_SP) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = 0;
		}
		break;
	case V850_SSTB:
	case V850_SSTH:
	case V850_SSTW:
		op->type = R_ANAL_OP_TYPE_STORE;
		if (F4_REG2(word1) == V850_SP) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = 0;
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
		r_strbuf_appendf (&op->esil, "%s,%s,0xffff,&,/,%s,=",
						 F1_RN1(word1), F1_RN2(word1), F1_RN2(word1));
		update_flags (op, V850_FLAG_OV | V850_FLAG_S | V850_FLAG_Z);
		break;
	case V850_JMP:
		if (F1_REG1(word1) == 31) {
			op->type = R_ANAL_OP_TYPE_RET;
		} else {
			op->type = R_ANAL_OP_TYPE_UJMP;
		}
		op->jump = word1; // UT64_MAX; // this is n RJMP instruction .. F1_RN1 (word1);
		op->fail = addr + 2;
		r_strbuf_appendf (&op->esil, "%s,pc,=", F1_RN1(word1));
		break;
	case V850_JARL2:
		// TODO: fix displacement reading
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + F5_DISP(((ut32)word2 << 16) | word1);
		op->fail = addr + 4;
		r_strbuf_appendf (&op->esil, "pc,%s,=,pc,%hu,+=", F5_RN2(word1), F5_DISP(((ut32)word2 << 16) | word1));
		break;
#if 0 // WTF - same opcode as JARL?
	case V850_JR:
		jumpdisp = DISP26(word1, word2);
		op->type = R_ANAL_OP_TYPE_JMP;
		r_strbuf_appendf (&op->esil, "$$,%d,+,pc,=", jumpdisp);
		break;
#endif
	case V850_OR:
		op->type = R_ANAL_OP_TYPE_OR;
		r_strbuf_appendf (&op->esil, "%s,%s,|=", F1_RN1(word1), F1_RN2(word1));
		update_flags (op, V850_FLAG_S | V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV);
		break;
	case V850_ORI:
		op->type = R_ANAL_OP_TYPE_OR;
		r_strbuf_appendf (&op->esil, "%hu,%s,|,%s,=",
						 word2, F6_RN1(word1), F6_RN2(word1));
		update_flags (op, V850_FLAG_S | V850_FLAG_Z);
		clear_flags (op, V850_FLAG_OV);
		break;
	case V850_MULH:
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
		r_strbuf_appendf (&op->esil, "%hu,%s,^,%s,=", word2, F6_RN1(word1), F6_RN2(word1));
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
		r_strbuf_appendf (&op->esil, "%d,%s,==", (st8)SEXT5(F2_IMM(word1)), F2_RN2(word1));
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
		r_strbuf_appendf (&op->esil, "%d,%s,+=", (st8)SEXT5(F2_IMM (word1)), F2_RN2 (word1));
		update_flags (op, -1);
		break;
	case V850_ADDI:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (F6_REG2(word1) == V850_SP) {
			op->stackop = R_ANAL_STACK_INC;
			// Not so sure about the fix but
			// F6_IMM works only for 32 bit words.
			// word1 is 16 bits long.
			op->stackptr = F2_IMM (word1);
			op->val = op->stackptr;
		}
		r_strbuf_appendf (&op->esil, "%hd,%s,+,%s,=", word2, F6_RN1 (word1), F6_RN2 (word1));
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

	case V850_BCOND:
	case V850_BCOND2:
	case V850_BCOND3:
	case V850_BCOND4:
		destaddr = ((((word1 >> 4) & 0x7) |
			((word1 >> 11) << 3)) << 1);
		if (destaddr & 0x100) {
			destaddrs = destaddr | 0xFE00;
		} else {
			destaddrs = destaddr;
		}
		op->jump = addr + destaddrs;
		op->fail = addr + 2;
		op->type = R_ANAL_OP_TYPE_CJMP;
		switch (F3_COND(word1)) {
		case V850_COND_V:
			r_strbuf_appendf (&op->esil, "ov");
			break;
		case V850_COND_CL:
			r_strbuf_appendf (&op->esil, "cy");
			break;
		case V850_COND_ZE:
			r_strbuf_appendf (&op->esil, "z");
			break;
		case V850_COND_NH:
			r_strbuf_appendf (&op->esil, "cy,z,|");
			break;
		case V850_COND_N:
			r_strbuf_appendf (&op->esil, "s");
			break;
		case V850_COND_AL: // Always
			r_strbuf_appendf (&op->esil, "1");
			break;
		case V850_COND_LT:
			r_strbuf_appendf (&op->esil, "s,ov,^");
			break;
		case V850_COND_LE:
			r_strbuf_appendf (&op->esil, "s,ov,^,z,|");
			break;
		case V850_COND_NV:
			r_strbuf_appendf (&op->esil, "ov,!");
			break;
		case V850_COND_NL:
			r_strbuf_appendf (&op->esil, "cy,!");
			break;
		case V850_COND_NE:
			r_strbuf_appendf (&op->esil, "z,!");
			break;
		case V850_COND_H:
			r_strbuf_appendf (&op->esil, "cy,z,|,!");
			break;
		case V850_COND_P:
			r_strbuf_appendf (&op->esil, "s,!");
			break;
		case V850_COND_GE:
			r_strbuf_appendf (&op->esil, "s,ov,^,!");
			break;
		case V850_COND_GT:
			r_strbuf_appendf (&op->esil, "s,ov,^,z,|,!");
			break;
		}
		r_strbuf_appendf (&op->esil, ",?{,$$,%d,+,pc,=,}", destaddrs);
		break;
	case V850_BIT_MANIP:
		{
		ut8 bitop = word1 >> 14;
		switch (bitop) {
		case V850_BIT_CLR1:
			bitmask = (1 << F8_BIT(word1));
			r_strbuf_appendf (&op->esil, "%hu,%s,+,[1],%u,&,%hu,%s,+,=[1]", word2, F8_RN1(word1), bitmask, word2, F8_RN1(word1));
			// TODO: Read the value of the memory byte and set zero flag accordingly!
			break;
		case V850_BIT_NOT1:
			bitmask = (1 << F8_BIT(word1));
			r_strbuf_appendf (&op->esil, "%hu,%s,+,[1],%u,^,%hu,%s,+,=[1]", word2, F8_RN1(word1), bitmask, word2, F8_RN1(word1));
			// TODO: Read the value of the memory byte and set zero flag accordingly!
			break;
		}
		}
		break;
	case V850_EXT1:
		switch (get_subopcode(word1 | (ut32)word2 << 16)) {
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
			reg1 = F9_RN1(word1);
			reg2 = F9_RN2(word1);
			r_strbuf_appendf (&op->esil, "31,%s,>>,?{,%s,32,-,%s,1,<<,--,<<,}{,0,},%s,%s,>>,|,%s,=", reg2, reg1, reg1, reg1, reg2, reg2);
			update_flags (op, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
			clear_flags (op, V850_FLAG_OV);
			break;
		}
		break;
	}

	return ret;
}

static char *get_reg_profile(RAnal *anal) {
	const char *p =
		"=PC	pc\n"
		"=SP	r3\n"
		"=ZF	z\n"
		"=SF	s\n"
		"=OF	ov\n"
		"=CF	cy\n"

		"gpr	r0	.32	0   0\n"
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

RAnalPlugin r_anal_plugin_v850 = {
	.name = "v850",
	.desc = "V850 code analysis plugin",
	.license = "LGPL3",
	.arch = "v850",
	.bits = 32,
	.op = v850_op,
	.esil = true,
	.get_reg_profile = get_reg_profile,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_v850,
	.version = R2_VERSION
};
#endif

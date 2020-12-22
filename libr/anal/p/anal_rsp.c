/* radare - LGPL - Copyright 2016-2017 - bobby.smiles32@gmail.com */
/*
 * TODO: finish esil support of the non vector instructions
 * TODO: implement vector instruction using custom esil commands
 * (will be easier than pure esil approach)
 * TODO: refactor code to simplify per opcode analysis
 */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/rsp/rsp_idec.h"

static int rsp_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b, int len, RAnalOpMask mask) {
	int i;
	typedef struct {
		RAnalValue* value;
		char esil[32];
	} ParsedOperands;

	ParsedOperands parsed_operands[RSP_MAX_OPNDS];
	memset (parsed_operands, 0, sizeof (ParsedOperands) * RSP_MAX_OPNDS);
	ut32 iw;
	rsp_instruction r_instr;

	if (!op) {
		return 4;
	}

	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = 4;
	op->addr = addr;
	r_strbuf_set (&op->esil, "TODO");

	iw = r_read_ble32 (b, anal->big_endian);
	r_instr = rsp_instruction_decode (addr, iw);

	/* parse operands */
	for (i = 0; i < r_instr.noperands; i++) {
		parsed_operands[i].value = r_anal_value_new ();
		parsed_operands[i].esil[0] = '\0';

		switch (r_instr.operands[i].type) {
		case RSP_OPND_GP_REG:
			snprintf (parsed_operands[i].esil, sizeof (parsed_operands[i].esil), "%s", rsp_gp_reg_soft_names[r_instr.operands[i].u]);
			parsed_operands[i].value->reg = r_reg_get (anal->reg, rsp_gp_reg_soft_names[r_instr.operands[i].u], R_REG_TYPE_GPR);
			break;
		case RSP_OPND_ZIMM:
		case RSP_OPND_SHIFT_AMOUNT:
			snprintf (parsed_operands[i].esil, sizeof (parsed_operands[i].esil), "%"PFMT64d, r_instr.operands[i].u);
			parsed_operands[i].value->imm = op->val = r_instr.operands[i].u;
			break;
		case RSP_OPND_SIMM:
			snprintf (parsed_operands[i].esil, sizeof (parsed_operands[i].esil), "%"PFMT64d, r_instr.operands[i].s);
			parsed_operands[i].value->imm = op->val = r_instr.operands[i].s;
			break;
		case RSP_OPND_BASE_OFFSET:
			snprintf (parsed_operands[i].esil, sizeof (parsed_operands[i].esil),
			"%"PFMT64d",%s,+", r_instr.operands[i].s, rsp_gp_reg_soft_names[r_instr.operands[i].u]);
			parsed_operands[i].value->reg = r_reg_get (anal->reg, rsp_gp_reg_soft_names[r_instr.operands[i].u], R_REG_TYPE_GPR);
			parsed_operands[i].value->imm = r_instr.operands[i].s;
			break;
		case RSP_OPND_OFFSET:
		case RSP_OPND_TARGET:
			op->delay = 1;
			op->jump = r_instr.operands[i].u;
			op->fail = rsp_mem_addr (addr + 8, RSP_IMEM_OFFSET);
			op->eob = 1;
			snprintf (parsed_operands[i].esil, sizeof (parsed_operands[i].esil), "%"PFMT64d, r_instr.operands[i].u);
			parsed_operands[i].value->imm = r_instr.operands[i].u;
			parsed_operands[i].value->memref = 4;
			break;
		case RSP_OPND_C0_REG:
			snprintf (parsed_operands[i].esil, sizeof (parsed_operands[i].esil), "%s", rsp_c0_reg_names[r_instr.operands[i].u]);
			parsed_operands[i].value->reg = r_reg_get (anal->reg, rsp_c0_reg_names[r_instr.operands[i].u], R_REG_TYPE_GPR);
			break;
		case RSP_OPND_C2_CREG:
		case RSP_OPND_C2_ACCU:
		case RSP_OPND_C2_VREG:
		case RSP_OPND_C2_VREG_BYTE:
		case RSP_OPND_C2_VREG_SCALAR:
		case RSP_OPND_C2_VREG_ELEMENT:
			/* TODO */
			break;
		}
	}

	switch (r_instr.opcode) {
	case RSP_OP_INVALID:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case RSP_OP_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		r_strbuf_set (&op->esil, ",");
		break;
	case RSP_OP_BREAK:
		op->type = R_ANAL_OP_TYPE_TRAP;
		// TODO
		break;
	case RSP_OP_LUI:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		r_strbuf_setf (&op->esil, "%s,%s,=", parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_ADD:
	case RSP_OP_ADDU:
	case RSP_OP_ADDI:
	case RSP_OP_ADDIU:
		op->type = R_ANAL_OP_TYPE_ADD;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[1] = parsed_operands[2].value;
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,=", parsed_operands[2].esil, parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_SUB:
	case RSP_OP_SUBU:
		op->type = R_ANAL_OP_TYPE_SUB;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[1] = parsed_operands[2].value;
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,=", parsed_operands[2].esil, parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_AND:
	case RSP_OP_ANDI:
		op->type = R_ANAL_OP_TYPE_AND;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[1] = parsed_operands[2].value;
		r_strbuf_setf (&op->esil, "%s,%s,&,%s,=", parsed_operands[2].esil, parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_OR:
	case RSP_OP_ORI:
		op->type = R_ANAL_OP_TYPE_OR;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[1] = parsed_operands[2].value;
		r_strbuf_setf (&op->esil, "%s,%s,|,%s,=", parsed_operands[2].esil, parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_XOR:
	case RSP_OP_XORI:
		op->type = R_ANAL_OP_TYPE_XOR;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[1] = parsed_operands[2].value;
		r_strbuf_setf (&op->esil, "%s,%s,^,%s,=", parsed_operands[2].esil, parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_NOR:
		op->type = R_ANAL_OP_TYPE_NOR;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[1] = parsed_operands[2].value;
		// TODO
		break;
	case RSP_OP_SLL:
	case RSP_OP_SLLV:
		op->type = R_ANAL_OP_TYPE_SHL;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[1] = parsed_operands[2].value;
		r_strbuf_setf (&op->esil, "%s,%s,<<,%s,=", parsed_operands[2].esil, parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_SRL:
	case RSP_OP_SRLV:
		op->type = R_ANAL_OP_TYPE_SHR;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[1] = parsed_operands[2].value;
		r_strbuf_setf (&op->esil, "%s,%s,>>,%s,=", parsed_operands[2].esil, parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_SRA:
	case RSP_OP_SRAV:
		op->type = R_ANAL_OP_TYPE_SAR;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[1] = parsed_operands[2].value;
		// TODO
		break;
	case RSP_OP_SLT:
	case RSP_OP_SLTU:
	case RSP_OP_SLTI:
	case RSP_OP_SLTIU:
		op->type = R_ANAL_OP_TYPE_CMOV;
		op->cond = R_ANAL_COND_LT;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[1] = parsed_operands[2].value;
		r_strbuf_setf (&op->esil, "%s,%s,<,$z,?{,1,%s,=,}{,0,%s,=,}", parsed_operands[2].esil, parsed_operands[1].esil, parsed_operands[0].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_J:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->dst = r_anal_value_new ();
		op->dst->reg = r_reg_get (anal->reg, "PC", R_REG_TYPE_GPR);
		op->src[0] = parsed_operands[0].value;
		r_strbuf_setf (&op->esil, "%s,PC,=", parsed_operands[0].esil);
		break;
	case RSP_OP_JAL:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->dst = r_anal_value_new ();
		op->dst->reg = r_reg_get (anal->reg, "PC", R_REG_TYPE_GPR);
		op->src[0] = parsed_operands[0].value;
		r_strbuf_setf (&op->esil, "%s,PC,=,0x%08" PFMT64x ",RA,=", parsed_operands[0].esil, op->fail);
		break;
	case RSP_OP_JR:
		/* if register is RA, this is a return */
		op->type = (r_instr.operands[0].u == 29)
			? R_ANAL_OP_TYPE_RET
			: R_ANAL_OP_TYPE_UJMP;
		op->delay = 1;
		op->eob = 1;
		op->fail = rsp_mem_addr (addr + 8, RSP_IMEM_OFFSET);
		op->dst = r_anal_value_new ();
		op->dst->reg = r_reg_get (anal->reg, "PC", R_REG_TYPE_GPR);
		op->src[0] = parsed_operands[0].value;
		r_strbuf_setf (&op->esil, "%s,PC,=", parsed_operands[0].esil);
		break;
	case RSP_OP_BEQ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->cond = R_ANAL_COND_EQ;
		op->dst = r_anal_value_new ();
		op->dst->reg = r_reg_get (anal->reg, "PC", R_REG_TYPE_GPR);
		op->src[0] = parsed_operands[0].value;
		op->src[1] = parsed_operands[1].value;
		r_strbuf_setf (&op->esil, "%s,%s,==,$z,?{,%s,PC,=,}", parsed_operands[0].esil, parsed_operands[1].esil, parsed_operands[2].esil);
		break;
	case RSP_OP_BNE:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->cond = R_ANAL_COND_NE;
		op->dst = r_anal_value_new ();
		op->dst->reg = r_reg_get (anal->reg, "PC", R_REG_TYPE_GPR);
		op->src[0] = parsed_operands[0].value;
		op->src[1] = parsed_operands[1].value;
		r_strbuf_setf (&op->esil, "%s,%s,==,$z,!,?{,%s,PC,=,}", parsed_operands[0].esil, parsed_operands[1].esil, parsed_operands[2].esil);
		break;
	case RSP_OP_BLEZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->cond = R_ANAL_COND_LE;
		op->dst = r_anal_value_new ();
		op->dst->reg = r_reg_get (anal->reg, "PC", R_REG_TYPE_GPR);
		op->src[0] = parsed_operands[0].value;
		op->src[1] = parsed_operands[1].value;
		r_strbuf_setf (&op->esil, "%s,!,%s,0x80000000,&,!,!,|,?{,%s,PC,=,}", parsed_operands[0].esil, parsed_operands[0].esil, parsed_operands[1].esil);
//		r_strbuf_setf (&op->esil, "0,%s,<=,$z,?{,%s,PC,=,}", parsed_operands[0].esil, parsed_operands[1].esil);
		break;
	case RSP_OP_BGTZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->cond = R_ANAL_COND_GT;
		op->dst = r_anal_value_new ();
		op->dst->reg = r_reg_get (anal->reg, "PC", R_REG_TYPE_GPR);
		op->src[0] = parsed_operands[0].value;
		op->src[1] = parsed_operands[1].value;
		r_strbuf_setf (&op->esil, "%s,0x80000000,&,!,%s,!,!,&,?{,%s,PC,=,}", parsed_operands[0].esil, parsed_operands[0].esil, parsed_operands[1].esil);
//		r_strbuf_setf (&op->esil, "0,%s,>,$z,?{,%s,PC,=,}", parsed_operands[0].esil, parsed_operands[1].esil);
		break;
	case RSP_OP_BLTZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->cond = R_ANAL_COND_LT;
		op->dst = r_anal_value_new ();
		op->dst->reg = r_reg_get (anal->reg, "PC", R_REG_TYPE_GPR);
		op->src[0] = parsed_operands[0].value;
		op->src[1] = parsed_operands[1].value;
		r_strbuf_setf (&op->esil, "%s,0x80000000,&,!,!,?{,%s,PC,=,}", parsed_operands[0].esil, parsed_operands[1].esil);
//		r_strbuf_setf (&op->esil, "0,%s,<,?{,%s,PC,=,}", parsed_operands[0].esil, parsed_operands[1].esil);
		break;
	case RSP_OP_BGEZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->cond = R_ANAL_COND_GE;
		op->dst = r_anal_value_new ();
		op->dst->reg = r_reg_get (anal->reg, "PC", R_REG_TYPE_GPR);
		op->src[0] = parsed_operands[0].value;
		op->src[1] = parsed_operands[1].value;
		r_strbuf_setf (&op->esil, "%s,0x80000000,&,!,?{,%s,PC,=,}", parsed_operands[0].esil, parsed_operands[1].esil);
//		r_strbuf_setf (&op->esil, "0,%s,>=,?{,%s,PC,=,}", parsed_operands[0].esil, parsed_operands[1].esil);
		break;
	case RSP_OP_BLTZAL:
		op->type = R_ANAL_OP_TYPE_CCALL;
		op->cond = R_ANAL_COND_LT;
		op->dst = r_anal_value_new ();
		op->dst->reg = r_reg_get (anal->reg, "PC", R_REG_TYPE_GPR);
		op->src[0] = parsed_operands[0].value;
		op->src[1] = parsed_operands[1].value;
		// TODO
		break;
	case RSP_OP_BGEZAL:
		op->type = R_ANAL_OP_TYPE_CCALL;
		op->cond = R_ANAL_COND_GE;
		op->dst = r_anal_value_new ();
		op->dst->reg = r_reg_get (anal->reg, "PC", R_REG_TYPE_GPR);
		op->src[0] = parsed_operands[0].value;
		op->src[1] = parsed_operands[1].value;
		// TODO
		break;
	case RSP_OP_LB:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[0]->memref = op->refptr = 1;
		// FIXME: sign extend
		r_strbuf_setf (&op->esil, "%s,[1],%s,=", parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_LH:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[0]->memref = op->refptr = 2;
		// FIXME: sign extend
		r_strbuf_setf (&op->esil, "%s,[2],%s,=", parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_LW:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[0]->memref = op->refptr = 4;
		r_strbuf_setf (&op->esil, "%s,[4],%s,=", parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_LBU:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[0]->memref = op->refptr = 1;
		r_strbuf_setf (&op->esil, "%s,[1],%s,=", parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_LHU:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		op->src[0]->memref = op->refptr = 2;
		r_strbuf_setf (&op->esil, "%s,[2],%s,=", parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_SB:
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = parsed_operands[0].value;
		op->dst = parsed_operands[1].value;
		op->dst->memref = op->refptr = 1;
		r_strbuf_setf (&op->esil, "%s,%s,=[1]", parsed_operands[0].esil, parsed_operands[1].esil);
		break;
	case RSP_OP_SH:
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = parsed_operands[0].value;
		op->dst = parsed_operands[1].value;
		op->dst->memref = op->refptr = 2;
		r_strbuf_setf (&op->esil, "%s,%s,=[2]", parsed_operands[0].esil, parsed_operands[1].esil);
		break;
	case RSP_OP_SW:
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = parsed_operands[0].value;
		op->dst = parsed_operands[1].value;
		op->dst->memref = op->refptr = 4;
		r_strbuf_setf (&op->esil, "%s,%s,=[4]", parsed_operands[0].esil, parsed_operands[1].esil);
		break;
	case RSP_OP_MFC0:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->dst = parsed_operands[0].value;
		op->src[0] = parsed_operands[1].value;
		r_strbuf_setf (&op->esil, "%s,%s,=", parsed_operands[1].esil, parsed_operands[0].esil);
		break;
	case RSP_OP_MTC0:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = parsed_operands[0].value;
		op->dst = parsed_operands[1].value;
		r_strbuf_setf (&op->esil, "%s,%s,=", parsed_operands[0].esil, parsed_operands[1].esil);
		break;
	case RSP_OP_MFC2:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->dst = parsed_operands[0].value;
		//op->src[0] = parsed_operands[1].value;
		break;
	case RSP_OP_MTC2:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = parsed_operands[0].value;
		//op->dst = parsed_operands[1].value;
		break;
	case RSP_OP_CFC2:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case RSP_OP_CTC2:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case RSP_OP_VMULF:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case RSP_OP_VMULU:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case RSP_OP_VMUDL:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case RSP_OP_VMUDM:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case RSP_OP_VMUDN:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case RSP_OP_VMUDH:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case RSP_OP_VMACF:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case RSP_OP_VMACU:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case RSP_OP_VMADL:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case RSP_OP_VMADM:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case RSP_OP_VMADN:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case RSP_OP_VMADH:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case RSP_OP_VADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case RSP_OP_VSUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case RSP_OP_VABS:
		op->type = R_ANAL_OP_TYPE_ABS;
		break;
	case RSP_OP_VADDC:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case RSP_OP_VSUBC:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case RSP_OP_VSAR:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case RSP_OP_VLT:
		op->type = R_ANAL_OP_TYPE_CMP;
		op->cond = R_ANAL_COND_LT;
		break;
	case RSP_OP_VEQ:
		op->type = R_ANAL_OP_TYPE_CMP;
		op->cond = R_ANAL_COND_EQ;
		break;
	case RSP_OP_VNE:
		op->type = R_ANAL_OP_TYPE_CMP;
		op->cond = R_ANAL_COND_NE;
		break;
	case RSP_OP_VGE:
		op->type = R_ANAL_OP_TYPE_CMP;
		op->cond = R_ANAL_COND_GE;
		break;
	case RSP_OP_VCL:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case RSP_OP_VCH:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case RSP_OP_VCR:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case RSP_OP_VMRG:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case RSP_OP_VAND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case RSP_OP_VNAND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case RSP_OP_VOR:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case RSP_OP_VNOR:
		op->type = R_ANAL_OP_TYPE_NOR;
		break;
	case RSP_OP_VXOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case RSP_OP_VNXOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case RSP_OP_VRCP:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case RSP_OP_VRCPL:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case RSP_OP_VRCPH:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case RSP_OP_VMOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case RSP_OP_VRSQ:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case RSP_OP_VRSQL:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case RSP_OP_VRSQH:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case RSP_OP_VNOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case RSP_OP_LBV:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case RSP_OP_LSV:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case RSP_OP_LLV:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case RSP_OP_LDV:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case RSP_OP_LQV:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case RSP_OP_LRV:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case RSP_OP_LPV:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case RSP_OP_LUV:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case RSP_OP_LHV:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case RSP_OP_LFV:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case RSP_OP_LTV:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case RSP_OP_SBV:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case RSP_OP_SSV:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case RSP_OP_SLV:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case RSP_OP_SDV:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case RSP_OP_SQV:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case RSP_OP_SRV:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case RSP_OP_SPV:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case RSP_OP_SUV:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case RSP_OP_SHV:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case RSP_OP_SFV:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case RSP_OP_SWV:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case RSP_OP_STV:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	default: break;
	}

	return op->size;
}


static char *get_reg_profile(RAnal *anal) {
	static const char *p =
		"=PC    pc\n"
		"=SP    sp\n"
		"=A0    a0\n"
		"=A1    a1\n"
		"=A2    a2\n"
		"=A3    a3\n"
		"=R0    v0\n"
		"=R1    v1\n"
/* GP registers */
		"gpr	zero	.32	0	0\n"
		"gpr	at	.32	4	0\n"
		"gpr	v0	.32	8	0\n"
		"gpr	v1	.32	12	0\n"
		"gpr	a0	.32	16	0\n"
		"gpr	a1	.32	20	0\n"
		"gpr	a2	.32	24	0\n"
		"gpr	a3	.32	28	0\n"
		"gpr	t0	.32	32	0\n"
		"gpr	t1	.32	36	0\n"
		"gpr	t2	.32	40	0\n"
		"gpr	t3	.32	44	0\n"
		"gpr	t4	.32	48	0\n"
		"gpr	t5	.32	52	0\n"
		"gpr	t6	.32	56	0\n"
		"gpr	t7	.32	60	0\n"
		"gpr	s0	.32	64	0\n"
		"gpr	s1	.32	68	0\n"
		"gpr	s2	.32	72	0\n"
		"gpr	s3	.32	76	0\n"
		"gpr	s4	.32	80	0\n"
		"gpr	s5	.32	84	0\n"
		"gpr	s6	.32	88	0\n"
		"gpr	s7	.32	92	0\n"
		"gpr	t8	.32	96	0\n"
		"gpr	t9	.32	100	0\n"
		"gpr	k0	.32	104	0\n"
		"gpr	k1	.32	108	0\n"
		"gpr	gp	.32	112	0\n"
		"gpr	sp	.32	116	0\n"
		"gpr	s8	.32	120	0\n"
		"gpr	ra	.32	124	0\n"
/* PC register */
		"gpr	pc	.32	128	0\n"
/* C0 registers */
		"gpr	$c0	.32	132	0\n"
		"gpr	$c1	.32	136	0\n"
		"gpr	$c2	.32	140	0\n"
		"gpr	$c3	.32	144	0\n"
		"gpr	$c4	.32	148	0\n"
		"gpr	$c5	.32	152	0\n"
		"gpr	$c6	.32	156	0\n"
		"gpr	$c7	.32	160	0\n"
		"gpr	$c8	.32	164	0\n"
		"gpr	$c9	.32	168	0\n"
		"gpr	$c10	.32	172	0\n"
		"gpr	$c11	.32	176	0\n"
		"gpr	$c12	.32	180	0\n"
		"gpr	$c13	.32	184	0\n"
		"gpr	$c14	.32	188	0\n"
		"gpr	$c15	.32	192	0\n"
/* C2 vector registers - (32 x 128 bit) */
		"gpr	$v0	.128	196	0\n"
		"gpr	$v1	.128	212	0\n"
		"gpr	$v2	.128	228	0\n"
		"gpr	$v3	.128	244	0\n"
		"gpr	$v4	.128	260	0\n"
		"gpr	$v5	.128	276	0\n"
		"gpr	$v6	.128	292	0\n"
		"gpr	$v7	.128	308	0\n"
		"gpr	$v8	.128	324	0\n"
		"gpr	$v9	.128	340	0\n"
		"gpr	$v10	.128	356	0\n"
		"gpr	$v11	.128	372	0\n"
		"gpr	$v12	.128	388	0\n"
		"gpr	$v13	.128	404	0\n"
		"gpr	$v14	.128	420	0\n"
		"gpr	$v15	.128	436	0\n"
		"gpr	$v16	.128	452	0\n"
		"gpr	$v17	.128	468	0\n"
		"gpr	$v18	.128	484	0\n"
		"gpr	$v19	.128	500	0\n"
		"gpr	$v20	.128	516	0\n"
		"gpr	$v21	.128	532	0\n"
		"gpr	$v22	.128	548	0\n"
		"gpr	$v23	.128	564	0\n"
		"gpr	$v24	.128	580	0\n"
		"gpr	$v25	.128	596	0\n"
		"gpr	$v26	.128	612	0\n"
		"gpr	$v27	.128	628	0\n"
		"gpr	$v28	.128	644	0\n"
		"gpr	$v29	.128	660	0\n"
		"gpr	$v30	.128	676	0\n"
		"gpr	$v31	.128	692	0\n"
/* C2 control registers - (vco, vcc, vce) */
		"gpr    $vco	.128	708	0\n"
		"gpr    $vcc	.128	724	0\n"
		"gpr    $vce	.128	740	0\n"
	;

	return strdup (p);
}

static int archinfo(RAnal *anal, int q) {
	return 4;
}

RAnalPlugin r_anal_plugin_rsp = {
	.name = "rsp",
	.desc = "RSP code analysis plugin",
	.license = "LGPL3",
	.arch = "rsp",
	.esil = true,
	.bits = 32,
	.op = &rsp_op,
	.archinfo = &archinfo,
	.get_reg_profile = &get_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_rsp,
	.version = R2_VERSION
};
#endif

/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>
#include <mips.h>

// http://www.mrc.uidaho.edu/mrc/people/jff/digital/MIPSir.html

#define OPERAND(x) insn->detail->mips.operands[x]
#define REG(x) cs_reg_name (*handle, insn->detail->mips.operands[x].reg)
#define IMM(x) insn->detail->mips.operands[x].imm
#define MEMBASE(x) cs_reg_name(*handle, insn->detail->mips.operands[x].mem.base)
#define MEMINDEX(x) insn->detail->mips.operands[x].mem.index
#define MEMDISP(x) insn->detail->mips.operands[x].mem.disp
// TODO scale and disp

static const char *arg(csh *handle, cs_insn *insn, char *buf, int n) {
	*buf = 0;
	switch (insn->detail->mips.operands[n].type) {
	case MIPS_OP_INVALID:
		break;
	case MIPS_OP_REG:
		sprintf (buf, "%s",
			cs_reg_name (*handle,
				insn->detail->mips.operands[n].reg));
		break;
	case MIPS_OP_IMM:
		sprintf (buf, "%"PFMT64d, (ut64)insn->detail->mips.operands[n].imm);
		break;
	case MIPS_OP_MEM:
		{
			int disp = insn->detail->mips.operands[n].mem.disp;
		if (disp<0) {
		sprintf (buf, "%s,%"PFMT64d",-",
			cs_reg_name (*handle,
				insn->detail->mips.operands[n].mem.base),
			(ut64)-insn->detail->mips.operands[n].mem.disp);
		} else {
		sprintf (buf, "%s,%"PFMT64d",+",
			cs_reg_name (*handle,
				insn->detail->mips.operands[n].mem.base),
			(ut64)insn->detail->mips.operands[n].mem.disp);
		}
		}
		break;
	}
	return buf;
}

#define ARG(x) arg(handle, insn, str[x], x)

static int analop_esil(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn) {
	char str[32][32];
	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");
	if (insn)
	switch (insn->id) {
	case MIPS_INS_NOP:
		r_strbuf_setf (&op->esil, ",");
		break;
	case MIPS_INS_SW:
		r_strbuf_appendf (&op->esil, "%s,%s,=[4]",
			ARG(0), ARG(1));
		break;
	case MIPS_INS_SWC1:
	case MIPS_INS_SWC2:
		r_strbuf_setf (&op->esil, "%s,$", ARG(1));
		break;
	case MIPS_INS_SB:
		r_strbuf_appendf (&op->esil, "%s,%s,=[1]",
			ARG(0), ARG(1));
		break;
	case MIPS_INS_CMP:
	case MIPS_INS_CMPU:
	case MIPS_INS_CMPGU:
	case MIPS_INS_CMPGDU:
	case MIPS_INS_CMPI:
		r_strbuf_appendf (&op->esil, "%s,%s,==", ARG(1), ARG(0));
		break;
	case MIPS_INS_SHRAV:
	case MIPS_INS_SHRAV_R:
	case MIPS_INS_SHRA:
	case MIPS_INS_SHRA_R:
	case MIPS_INS_SRA:
		r_strbuf_appendf (&op->esil, "%s,%s,>>,31,%s,>>,?{,32,%s,-,%s,1,<<,1,-,<<,}{,0,},|,%s,=,",
				ARG(2), ARG(1), ARG(1), ARG(2), ARG(2), ARG(0));
		break;
	case MIPS_INS_SHRL:
		// suffix 'S' forces conditional flag to be updated
	case MIPS_INS_SRLV:
	case MIPS_INS_SRL:
		r_strbuf_appendf (&op->esil, "%s,%s,>>,%s,=", ARG(2), ARG(1), ARG(0));
		break;
	case MIPS_INS_SLLV:
	case MIPS_INS_SLL:
		r_strbuf_appendf (&op->esil, "%s,%s,<<,%s,=", ARG(2), ARG(1), ARG(0));
		break;
	case MIPS_INS_BAL:
	case MIPS_INS_JAL:
	case MIPS_INS_JALR:
	case MIPS_INS_JALRS:
	case MIPS_INS_JALRC:
	case MIPS_INS_BLTZAL: // Branch on less than zero and link
		r_strbuf_appendf (&op->esil, "pc,8,+,ra,=,%s,pc,=", ARG(0));
		break;
	case MIPS_INS_JR:
	case MIPS_INS_JRC:
	case MIPS_INS_J:
		// jump to address with conditional
		r_strbuf_appendf (&op->esil, "%s,pc,=", ARG(0));
		break;
	case MIPS_INS_B: // ???
	case MIPS_INS_BZ:
	case MIPS_INS_BGTZ:
	case MIPS_INS_BGTZC:
	case MIPS_INS_BGTZALC:
	case MIPS_INS_BGEZ:
	case MIPS_INS_BGEZC:
	case MIPS_INS_BGEZAL: // Branch on less than zero and link
	case MIPS_INS_BGEZALC:
		r_strbuf_appendf (&op->esil, "%s,pc,=", ARG(0));
		break;
	case MIPS_INS_BNE:  // bne $s, $t, offset 
	case MIPS_INS_BNEZ:
		r_strbuf_appendf (&op->esil, "%s,%s,==,!,?{,%s,pc,=,}",
			ARG(0), ARG(1), ARG(2));
		break;
	case MIPS_INS_BEQ:
	case MIPS_INS_BEQZ:
	case MIPS_INS_BEQZC:
	case MIPS_INS_BEQZALC:
		r_strbuf_appendf (&op->esil, "%s,%s,==,?{,%s,pc,=,}",
			ARG(0), ARG(1), ARG(2));
		break;
	case MIPS_INS_BTEQZ:
	case MIPS_INS_BTNEZ:
		r_strbuf_appendf (&op->esil, "%s,pc,=", ARG(0));
		break;
	case MIPS_INS_MOV:
	case MIPS_INS_MOVE:
	case MIPS_INS_MOVF:
	case MIPS_INS_MOVT:
	case MIPS_INS_MOVZ:
		if (REG(0)[0]!='z'){
			r_strbuf_appendf (&op->esil, "%s,%s,=", ARG(1), REG(0));
		} else {
			r_strbuf_appendf (&op->esil, ",");
		}
		break;
	case MIPS_INS_FSUB:
	case MIPS_INS_SUB:
		if (REG(0)[0]!='z'){
			r_strbuf_appendf(&op->esil, "%s,%s,>,?{,$$,}{,%s,%s,-,%s,=",ARG(2), ARG(1), ARG(1), ARG(2), ARG(0));
		} else {
			r_strbuf_appendf (&op->esil, ",");
		}
		break;
	case MIPS_INS_SUBU:
	case MIPS_INS_NEGU:
	case MIPS_INS_DSUB:
	case MIPS_INS_DSUBU:
		{
		const char *arg0 = ARG(0);
		const char *arg1 = ARG(1);
		const char *arg2 = ARG(2);
		r_strbuf_appendf (&op->esil, "%s,%s,-,%s,=",
			arg1, arg2, arg0);
		}
		break;
	/** signed -- sets overflow flag */
	case MIPS_INS_ADD:
		{
		if (REG(0)[0]!='z'){
			r_strbuf_appendf (&op->esil, "32,%s,%s,+,>>,0,>,?{,$$,}{,%s,%s,+,%s,=,}",
					ARG(2), ARG(1), ARG(2), ARG(1), ARG(0));
		} else {
			r_strbuf_appendf (&op->esil, ",");
		}
		}
		break;
	case MIPS_INS_ADDI:
		if (REG(0)[0]!='z'){
			r_strbuf_appendf (&op->esil, "32,%s,0xffffffff,&,%s,+,>>,0,>,?{,$$,}{,%s,%s,+,%s,=,}",
					ARG(2), ARG(1), ARG(2), ARG(1), ARG(0));
		} else {
			r_strbuf_appendf (&op->esil, ",");
		}
		break;
	case MIPS_INS_DADD:
	case MIPS_INS_DADDI:
	/** unsigned */
	case MIPS_INS_ADDU:
	case MIPS_INS_ADDIU:
	case MIPS_INS_DADDIU:
		{
		const char *arg0 = ARG(0);
		const char *arg1 = ARG(1);
		const char *arg2 = ARG(2);
		if (REG(0)[0]!='z'){
			r_strbuf_appendf (&op->esil, "%s,%s,+,%s,=",
					arg2, arg1, arg0);
		} else {
			r_strbuf_appendf (&op->esil, ",");
		}
		}
		break;
	case MIPS_INS_LI:
		r_strbuf_appendf (&op->esil, "0x%"PFMT64x",%s,=", IMM(1), ARG(0));
		break;
	case MIPS_INS_LUI:
		r_strbuf_appendf (&op->esil, "0x%"PFMT64x"0000,%s,=", IMM(1), ARG(0));
		break;
	case MIPS_INS_LB:
	case MIPS_INS_LBU:
		//one of these is wrong
		r_strbuf_appendf (&op->esil, "%s,[1],%s,=",
			ARG(1), REG(0));
		break;
	case MIPS_INS_LW:
	case MIPS_INS_LWC1:
	case MIPS_INS_LWC2:
	case MIPS_INS_LWL:
	case MIPS_INS_LWR:
	case MIPS_INS_LWU:
	case MIPS_INS_LWX:
	case MIPS_INS_LH:
	case MIPS_INS_LHX:
	case MIPS_INS_LL:
	case MIPS_INS_LLD:
	case MIPS_INS_LD:
	case MIPS_INS_LDI:
	case MIPS_INS_LDL:
	case MIPS_INS_LDC1:
	case MIPS_INS_LDC2:
		r_strbuf_appendf (&op->esil, "%s,[4],%s,=",
			ARG(1), REG(0));
		break;
	case MIPS_INS_AND:
	case MIPS_INS_ANDI:
		{
		const char *arg0 = ARG(0);
		const char *arg1 = ARG(1);
		const char *arg2 = ARG(2);
		r_strbuf_appendf (&op->esil, "%s,%s,&,%s,=",
			arg2, arg1, arg0);
		}
		break;
	case MIPS_INS_OR:
	case MIPS_INS_ORI:
		{
		const char *arg0 = ARG(0);
		const char *arg1 = ARG(1);
		const char *arg2 = ARG(2);
		if (REG(0)[0]!='z'){
			r_strbuf_appendf (&op->esil, "%s,%s,|,%s,=",
				arg2, arg1, arg0);
		} else {
			r_strbuf_appendf (&op->esil, ",");
		}
		}
		break;
	case MIPS_INS_XOR:
	case MIPS_INS_XORI:
		{
		const char *arg0 = ARG(0);
		const char *arg1 = ARG(1);
		const char *arg2 = ARG(2);
		if (REG(0)[0]!='z'){
			r_strbuf_appendf (&op->esil, "%s,%s,^,%s,=",
				arg2, arg1, arg0);
		} else {
			r_strbuf_appendf (&op->esil, ",");
		}
		}
		break;
	case MIPS_INS_NOR:
		{
		const char *arg0 = ARG(0);
		const char *arg1 = ARG(1);
		const char *arg2 = ARG(2);
		if (REG(0)[0]!='z'){
			r_strbuf_appendf (&op->esil, "%s,%s,|,0xffffffff,^,%s,=",
				arg2, arg1, arg0);
		} else {
			r_strbuf_appendf (&op->esil, ",");
		}
		}
		break;
	case MIPS_INS_SLTU:
		r_strbuf_appendf (&op->esil, "%s,%s,<,%s,=", ARG(1), ARG(2), ARG(0));
		break;
	case MIPS_INS_SLTIU:
		{
		r_strbuf_appendf (&op->esil, "%s,0xffffffff,&,%s,0xffffffff,<,?{%s,1,=,}{,%s,0,=,}",
					ARG(1), ARG(2), ARG(0), ARG(0));
		}
		break;
	}
	return 0;
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	int n, ret, opsize = -1;
	csh handle;
	cs_insn* insn;
	int mode = a->big_endian? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;

	mode |= (a->bits==64)? CS_MODE_64: CS_MODE_32;
// XXX no arch->cpu ?!?! CS_MODE_MICRO, N64
	ret = cs_open (CS_ARCH_MIPS, mode, &handle);
	op->delay = 0;
	op->type = R_ANAL_OP_TYPE_ILL;
	op->size = 4;
	if (ret != CS_ERR_OK) goto fin;
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	n = cs_disasm (handle, (ut8*)buf, len, addr, 1, &insn);
	if (n<1 || insn->size<1)
		goto beach;
	op->type = R_ANAL_OP_TYPE_NULL;
	op->delay = 0;
	opsize = op->size = insn->size;
	switch (insn->id) {
	case MIPS_INS_INVALID:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case MIPS_INS_LB:
	case MIPS_INS_LBU:
	case MIPS_INS_LBUX:
	case MIPS_INS_LW:
	case MIPS_INS_LWC1:
	case MIPS_INS_LWC2:
	case MIPS_INS_LWL:
	case MIPS_INS_LWR:
	case MIPS_INS_LWXC1:
	case MIPS_INS_LD:
	case MIPS_INS_LDC1:
	case MIPS_INS_LDC2:
	case MIPS_INS_LDL:
	case MIPS_INS_LDR:
	case MIPS_INS_LDXC1:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->refptr = 4;
		switch (OPERAND(1).type) {
		case MIPS_OP_MEM:
			if (OPERAND(1).mem.base == MIPS_REG_GP) {
				op->ptr = a->gp + OPERAND(1).mem.disp;
				op->refptr = 4;
			}
			break;
		case MIPS_OP_IMM:
			op->ptr = OPERAND(1).imm;
			break;
		case MIPS_OP_REG:
			// wtf?
			break;
		default:
			break;
		}
		// TODO: fill
		break;
	case MIPS_INS_SW:
	case MIPS_INS_SWC1:
	case MIPS_INS_SWC2:
	case MIPS_INS_SWL:
	case MIPS_INS_SWR:
	case MIPS_INS_SWXC1:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case MIPS_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case MIPS_INS_SYSCALL:
	case MIPS_INS_BREAK:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case MIPS_INS_JALR:
		op->type = R_ANAL_OP_TYPE_UCALL;
		op->delay = 1;
		break;
	case MIPS_INS_JAL:
	case MIPS_INS_JALS:
	case MIPS_INS_JALX:
	case MIPS_INS_JIALC:
	case MIPS_INS_JIC:
	case MIPS_INS_JRADDIUSP:
	case MIPS_INS_BAL:
	case MIPS_INS_BGEZAL: // Branch on less than zero and link
		op->type = R_ANAL_OP_TYPE_CALL;
		op->delay = 1;
		op->jump = IMM(0);
		op->fail = addr+4;
		break;
	case MIPS_INS_MOVE:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case MIPS_INS_ADD:
	case MIPS_INS_ADDI:
	case MIPS_INS_ADDIU:
	case MIPS_INS_DADD:
	case MIPS_INS_DADDI:
	case MIPS_INS_DADDIU:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case MIPS_INS_SUB:
	case MIPS_INS_SUBV:
	case MIPS_INS_SUBVI:
	case MIPS_INS_DSUBU:
	case MIPS_INS_FSUB:
	case MIPS_INS_FMSUB:
	case MIPS_INS_SUBU:
	case MIPS_INS_DSUB:
	case MIPS_INS_SUBS_S:
	case MIPS_INS_SUBS_U:
	case MIPS_INS_SUBUH:
	case MIPS_INS_SUBUH_R:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case MIPS_INS_MULV:
	case MIPS_INS_MULT:
	case MIPS_INS_MULSA:
	case MIPS_INS_FMUL:
	case MIPS_INS_MUL:
	case MIPS_INS_DMULT:
	case MIPS_INS_DMULTU:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case MIPS_INS_XOR:
	case MIPS_INS_XORI:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case MIPS_INS_AND:
	case MIPS_INS_ANDI:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case MIPS_INS_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case MIPS_INS_OR:
	case MIPS_INS_ORI:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case MIPS_INS_DIV:
	case MIPS_INS_DIVU:
	case MIPS_INS_DDIV:
	case MIPS_INS_DDIVU:
	case MIPS_INS_FDIV:
	case MIPS_INS_DIV_S:
	case MIPS_INS_DIV_U:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case MIPS_INS_CMPGDU:
	case MIPS_INS_CMPGU:
	case MIPS_INS_CMPU:
	case MIPS_INS_CMPI:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case MIPS_INS_J:
	case MIPS_INS_B:
	case MIPS_INS_BZ:
	case MIPS_INS_BEQ:
	case MIPS_INS_BNZ:
	case MIPS_INS_BNE:
	case MIPS_INS_BEQZ:
	case MIPS_INS_BNEG:
	case MIPS_INS_BNEGI:
	case MIPS_INS_BNEZ:
	case MIPS_INS_BTEQZ:
	case MIPS_INS_BTNEZ:
	case MIPS_INS_BLTZ:
	case MIPS_INS_BGEZ:
	case MIPS_INS_BGEZC:
	case MIPS_INS_BGEZALC:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->delay = 1;
		if (OPERAND(0).type == MIPS_OP_IMM) {
			op->jump = IMM(0);
		} else if (OPERAND(1).type == MIPS_OP_IMM) {
			op->jump = IMM(1);
		} else if (OPERAND(2).type == MIPS_OP_IMM) {
			op->jump = IMM(2);
		}
		break;
	case MIPS_INS_JR:
	case MIPS_INS_JRC:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->delay = 1;
        // register 32 is $ra, so jmp is a return
        if (insn->detail->mips.operands[0].reg == 32) {
            op->type = R_ANAL_OP_TYPE_RET;
        }
		break;
	}
	beach:
	if (a->decode) {
		if (!analop_esil (a, op, addr, buf, len, &handle, insn))
			r_strbuf_fini (&op->esil);
	}
	cs_free (insn, n);
	cs_close (&handle);
	fin:
	return opsize;
}

static int set_reg_profile(RAnal *anal) {
	// XXX : 64bit profile
	char *p = "=pc    pc\n"
		"=sp    sp\n"
		"=a0    a0\n"
		"=a1    a1\n"
		"=a2    a2\n"
		"=a3    a3\n"
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
		"gpr	t2 	.32	40	0\n"
		"gpr	t3 	.32	44	0\n"
		"gpr	t4 	.32	48	0\n"
		"gpr	t5 	.32	52	0\n"
		"gpr	t6 	.32	56	0\n"
		"gpr	t7 	.32	60	0\n"
		"gpr	s0	.32	64	0\n"
		"gpr	s1	.32	68	0\n"
		"gpr	s2	.32	72	0\n"
		"gpr	s3	.32	76	0\n"
		"gpr	s4 	.32	80	0\n"
		"gpr	s5 	.32	84	0\n"
		"gpr	s6 	.32	88	0\n"
		"gpr	s7 	.32	92	0\n"
		"gpr	t8 	.32	96	0\n"
		"gpr	t9 	.32	100	0\n"
		"gpr	k0 	.32	104	0\n"
		"gpr	k1 	.32	108	0\n"
		"gpr	gp 	.32	112	0\n"
		"gpr	sp	.32	116	0\n"
		"gpr	fp	.32	120	0\n"
		"gpr	ra	.32	124	0\n"
		"gpr	pc	.32	128	0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_mips_cs = {
	.name = "mips",
	.desc = "Capstone MIPS analyzer",
	.license = "BSD",
	.esil = R_TRUE,
	.arch = R_SYS_ARCH_MIPS,
	.set_reg_profile = set_reg_profile,
	.bits = 16|32|64,
	.op = &analop,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_mips_cs
};
#endif

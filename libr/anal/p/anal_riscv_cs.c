/* radare2 - LGPL - Copyright 2013-2020 - pancake */

#include <r_asm.h>
#include <r_lib.h>

#include <capstone.h>
#if CS_API_MAJOR >= 5
#include <riscv.h>

// http://www.mrc.uidaho.edu/mrc/people/jff/digital/RISCVir.html

#define OPERAND(x) insn->detail->riscv.operands[x]
#define REGID(x) insn->detail->riscv.operands[x].reg
#define REG(x) cs_reg_name (*handle, insn->detail->riscv.operands[x].reg)
#define IMM(x) insn->detail->riscv.operands[x].imm
#define MEMBASE(x) cs_reg_name(*handle, insn->detail->riscv.operands[x].mem.base)
#define MEMINDEX(x) insn->detail->riscv.operands[x].mem.index
#define MEMDISP(x) insn->detail->riscv.operands[x].mem.disp
#define OPCOUNT() insn->detail->riscv.op_count
// TODO scale and disp

#define SET_VAL(op,i) \
	if ((i)<OPCOUNT() && OPERAND(i).type == RISCV_OP_IMM) {\
		(op)->val = OPERAND(i).imm;\
	}

#define CREATE_SRC_DST_3(op) \
	(op)->src[0] = r_anal_value_new ();\
	(op)->src[1] = r_anal_value_new ();\
	(op)->dst = r_anal_value_new ();

#define CREATE_SRC_DST_2(op) \
	(op)->src[0] = r_anal_value_new ();\
	(op)->dst = r_anal_value_new ();

#define SET_SRC_DST_3_REGS(op) \
	CREATE_SRC_DST_3 (op);\
	(op)->dst->reg = r_reg_get (anal->reg, REG (0), R_REG_TYPE_GPR);\
	(op)->src[0]->reg = r_reg_get (anal->reg, REG (1), R_REG_TYPE_GPR);\
	(op)->src[1]->reg = r_reg_get (anal->reg, REG (2), R_REG_TYPE_GPR);

#define SET_SRC_DST_3_IMM(op) \
	CREATE_SRC_DST_3 (op);\
	(op)->dst->reg = r_reg_get (anal->reg, REG (0), R_REG_TYPE_GPR);\
	(op)->src[0]->reg = r_reg_get (anal->reg, REG (1), R_REG_TYPE_GPR);\
	(op)->src[1]->imm = IMM (2);

#define SET_SRC_DST_2_REGS(op) \
	CREATE_SRC_DST_2 (op);\
	(op)->dst->reg = r_reg_get (anal->reg, REG (0), R_REG_TYPE_GPR);\
	(op)->src[0]->reg = r_reg_get (anal->reg, REG (1), R_REG_TYPE_GPR);

#define SET_SRC_DST_3_REG_OR_IMM(op) \
	if (OPERAND(2).type == RISCV_OP_IMM) {\
		SET_SRC_DST_3_IMM (op);\
	} else if (OPERAND(2).type == RISCV_OP_REG) {\
		SET_SRC_DST_3_REGS (op);\
	}


// ESIL macros:

// put the sign bit on the stack
#define ES_IS_NEGATIVE(arg) "1,"arg",<<<,1,&"


// call with delay slot
#define ES_CALL_DR(ra, addr) "pc,4,+,"ra",=,"ES_J(addr)
#define ES_CALL_D(addr) ES_CALL_DR("ra", addr)

// call without delay slot
#define ES_CALL_NDR(ra, addr) "pc,"ra",=,"ES_J(addr)
#define ES_CALL_ND(addr) ES_CALL_NDR("ra", addr)

#define USE_DS 0
#if USE_DS
// emit ERR trap if executed in a delay slot
#define ES_TRAP_DS() "$ds,!,!,?{,$$,1,TRAP,BREAK,},"
// jump to address
#define ES_J(addr) addr",SETJT,1,SETD"
#else
#define ES_TRAP_DS() ""
#define ES_J(addr) addr",pc,="
#endif

// sign extend 32 -> 64
#define ES_SIGN_EXT64(arg) \
	arg",0x80000000,&,0,<,?{,"\
		"0xffffffff00000000,"arg",|=,"\
	"}"

#define PROTECT_ZERO() \
	if (REG(0)[0]=='z'){\
		r_strbuf_appendf (&op->esil, ",");\
	} else

#define ESIL_LOAD(size) \
	PROTECT_ZERO () {\
		r_strbuf_appendf (&op->esil, "%s,["size"],%s,=",\
			ARG(1), REG(0));\
	}

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	cs_riscv *x = &insn->detail->riscv;
	for (i = 0; i < x->op_count; i++) {
		cs_riscv_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case RISCV_OP_REG:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", cs_reg_name (handle, op->reg));
			break;
		case RISCV_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_kN (pj, "value", op->imm);
			break;
		case RISCV_OP_MEM:
			pj_ks (pj, "type", "mem");
			if (op->mem.base != RISCV_REG_INVALID) {
				pj_ks (pj, "base", cs_reg_name (handle, op->mem.base));
			}
			pj_kN (pj, "disp", op->mem.disp);
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		pj_end (pj); /* o operand */
	}
	pj_end (pj); /* a operands */
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}

static const char *arg(csh *handle, cs_insn *insn, char *buf, int n) {
	*buf = 0;
	switch (insn->detail->riscv.operands[n].type) {
	case RISCV_OP_INVALID:
		break;
	case RISCV_OP_REG:
		sprintf (buf, "%s",
			cs_reg_name (*handle,
				insn->detail->riscv.operands[n].reg));
		break;
	case RISCV_OP_IMM:
	{
		st64 x = (st64)insn->detail->riscv.operands[n].imm;
		sprintf (buf, "%"PFMT64d, x);
		break;
	}
	case RISCV_OP_MEM:
	{
		st64 disp = insn->detail->riscv.operands[n].mem.disp;
		if (disp < 0) {
			sprintf (buf, "%"PFMT64d",%s,-",
				(ut64)-insn->detail->riscv.operands[n].mem.disp,
				cs_reg_name (*handle,
					insn->detail->riscv.operands[n].mem.base));
		} else {
			sprintf (buf, "0x%"PFMT64x",%s,+",
				insn->detail->riscv.operands[n].mem.disp,
				cs_reg_name (*handle,
					insn->detail->riscv.operands[n].mem.base));
		}
		break;
	}
	}
	return buf;
}

#define ARG(x) (*str[x]!=0)?str[x]:arg(handle, insn, str[x], x)

static int analop_esil(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn) {
	char str[8][32] = {{0}};
	int i;

	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");

	if (insn) {
		// caching operands
		for (i = 0; i < insn->detail->riscv.op_count && i < 8; i++) {
			*str[i] = 0;
			ARG (i);
		}
	}

	switch (insn->id) {
	//case RISCV_INS_NOP:
	//	r_strbuf_setf (&op->esil, ",");
	//	break;
	}
	return 0;
}

static int parse_reg_name(RRegItem *reg, csh handle, cs_insn *insn, int reg_num) {
	if (!reg) {
		return -1;
	}
	switch (OPERAND (reg_num).type) {
	case RISCV_OP_REG:
		reg->name = (char *)cs_reg_name (handle, OPERAND (reg_num).reg);
		break;
	case RISCV_OP_MEM:
		if (OPERAND (reg_num).mem.base != RISCV_REG_INVALID) {
			reg->name = (char *)cs_reg_name (handle, OPERAND (reg_num).mem.base);
		}
	default:
		break;
	}
	return 0;
}

static void op_fillval(RAnal *anal, RAnalOp *op, csh *handle, cs_insn *insn) {
	static RRegItem reg;
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_LOAD:
		if (OPERAND(1).type == RISCV_OP_MEM) {
			ZERO_FILL (reg);
			op->src[0] = r_anal_value_new ();
			op->src[0]->reg = &reg;
			parse_reg_name (op->src[0]->reg, *handle, insn, 1);
			op->src[0]->delta = OPERAND(1).mem.disp;
		}
		break;
	case R_ANAL_OP_TYPE_STORE:
		if (OPERAND(1).type == RISCV_OP_MEM) {
			ZERO_FILL (reg);
			op->dst = r_anal_value_new ();
			op->dst->reg = &reg;
			parse_reg_name (op->dst->reg, *handle, insn, 1);
			op->dst->delta = OPERAND(1).mem.disp;
		}
		break;
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_SAR:
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_OR:
		SET_SRC_DST_3_REG_OR_IMM (op);
		break;
	case R_ANAL_OP_TYPE_MOV:
		SET_SRC_DST_3_REG_OR_IMM (op);
		break;
	case R_ANAL_OP_TYPE_DIV: // UDIV
#if 0
capstone bug
------------
	$ r2 -a riscv -e cfg.bigendian=1 -c "wx 0083001b" -
	// should be 3 regs, right?
	[0x00000000]> aoj~{}
	[
	  {
	    "opcode": "divu zero, a0, v1",
	    "disasm": "divu zero, a0, v1",
	    "mnemonic": "divu",
	    "sign": false,
	    "prefix": 0,
	    "id": 192,
	    "opex": {
	      "operands": [
		{
		  "type": "reg",
		  "value": "a0"
		},
		{
		  "type": "reg",
		  "value": "v1"
		}
	      ]
	    },
#endif
		if (OPERAND(0).type == RISCV_OP_REG && OPERAND(1).type == RISCV_OP_REG && OPERAND(2).type == RISCV_OP_REG) {
			SET_SRC_DST_3_REGS (op);
		} else if (OPERAND(0).type == RISCV_OP_REG && OPERAND(1).type == RISCV_OP_REG) {
			SET_SRC_DST_2_REGS (op);
		} else {
			eprintf ("Unknown div at 0x%08"PFMT64x"\n", op->addr);
		}
		break;
	}
	if (insn && (insn->id == RISCV_INS_SLTI || insn->id == RISCV_INS_SLTIU)) {
		SET_SRC_DST_3_IMM (op);
	}
}

static void set_opdir(RAnalOp *op) {
        switch (op->type & R_ANAL_OP_TYPE_MASK) {
        case R_ANAL_OP_TYPE_LOAD:
                op->direction = R_ANAL_OP_DIR_READ;
                break;
        case R_ANAL_OP_TYPE_STORE:
                op->direction = R_ANAL_OP_DIR_WRITE;
                break;
        case R_ANAL_OP_TYPE_LEA:
                op->direction = R_ANAL_OP_DIR_REF;
                break;
        case R_ANAL_OP_TYPE_CALL:
        case R_ANAL_OP_TYPE_JMP:
        case R_ANAL_OP_TYPE_UJMP:
        case R_ANAL_OP_TYPE_UCALL:
                op->direction = R_ANAL_OP_DIR_EXEC;
                break;
        default:
                break;
        }
}

static int analop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	int n, ret, opsize = -1;
	static csh hndl = 0;
	static int omode = -1;
	static int obits = 32;
	cs_insn* insn;
	int mode = (anal->bits==64)? CS_MODE_RISCV64: CS_MODE_RISCV32;
	if (mode != omode || anal->bits != obits) {
		cs_close (&hndl);
		hndl = 0;
		omode = mode;
		obits = anal->bits;
	}
// XXX no arch->cpu ?!?! CS_MODE_MICRO, N64
	op->addr = addr;
	if (len < 4) {
		return -1;
	}
	op->size = 4;
	if (hndl == 0) {
		ret = cs_open (CS_ARCH_RISCV, mode, &hndl);
		if (ret != CS_ERR_OK) {
			goto fin;
		}
		cs_option (hndl, CS_OPT_DETAIL, CS_OPT_ON);
	}
	n = cs_disasm (hndl, (ut8*)buf, len, addr, 1, &insn);
	if (n < 1 || insn->size < 1) {
		goto beach;
	}
	op->id = insn->id;
	opsize = op->size = insn->size;
	switch (insn->id) {
	case RISCV_INS_C_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case RISCV_INS_INVALID:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case RISCV_INS_C_JALR:
		op->type = R_ANAL_OP_TYPE_UCALL;
		break;
	case RISCV_INS_C_JR:
		op->type = R_ANAL_OP_TYPE_UJMP;
		break;
	case RISCV_INS_C_MV:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case RISCV_INS_JAL:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = IMM(0);
		op->fail = op->addr + op->size;
		break;
	case RISCV_INS_MRET:
	case RISCV_INS_SRET:
	case RISCV_INS_URET:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
beach:
	set_opdir (op);
	if (insn && mask & R_ANAL_OP_MASK_OPEX) {
		opex (&op->opex, hndl, insn);
	}
	if (mask & R_ANAL_OP_MASK_ESIL) {
		if (analop_esil (anal, op, addr, buf, len, &hndl, insn) != 0) {
			r_strbuf_fini (&op->esil);
		}
	}
	if (mask & R_ANAL_OP_MASK_VAL) {
		op_fillval (anal, op, &hndl, insn);
	}
	cs_free (insn, n);
	//cs_close (&handle);
fin:
	return opsize;
}

static char *get_reg_profile(RAnal *anal) {
	const char *p = NULL;
	switch (anal->bits) {
	case 32: p =
		"=PC	pc\n"
		"=SP	sp\n" // ABI: stack pointer
		"=LR	ra\n" // ABI: return address
		"=BP	s0\n" // ABI: frame pointer
		"=A0	a0\n"
		"=A1	a1\n"

		"gpr	pc	.32	0	0\n"
		// RV32I regs (ABI names)
		// From user-Level ISA Specification, section 2.1
		// "zero" has been left out as it ignores writes and always reads as zero
		"gpr	ra	.32	4	0\n" // =x1
		"gpr	sp	.32	8	0\n" // =x2
		"gpr	gp	.32	12	0\n" // =x3
		"gpr	tp	.32	16	0\n" // =x4
		"gpr	t0	.32	20	0\n" // =x5
		"gpr	t1	.32	24	0\n" // =x6
		"gpr	t2	.32	28	0\n" // =x7
		"gpr	s0	.32	32	0\n" // =x8
		"gpr	s1	.32	36	0\n" // =x9
		"gpr	a0	.32	40	0\n" // =x10
		"gpr	a1	.32	44	0\n" // =x11
		"gpr	a2	.32	48	0\n" // =x12
		"gpr	a3	.32	52	0\n" // =x13
		"gpr	a4	.32	56	0\n" // =x14
		"gpr	a5	.32	60	0\n" // =x15
		"gpr	a6	.32	64	0\n" // =x16
		"gpr	a7	.32	68	0\n" // =x17
		"gpr	s2	.32	72	0\n" // =x18
		"gpr	s3	.32	76	0\n" // =x19
		"gpr	s4	.32	80	0\n" // =x20
		"gpr	s5	.32	84	0\n" // =x21
		"gpr	s6	.32	88	0\n" // =x22
		"gpr	s7	.32	92	0\n" // =x23
		"gpr	s8	.32	96	0\n" // =x24
		"gpr	s9	.32	100	0\n" // =x25
		"gpr	s10	.32	104	0\n" // =x26
		"gpr	s11	.32	108	0\n" // =x27
		"gpr	t3	.32	112	0\n" // =x28
		"gpr	t4	.32	116	0\n" // =x29
		"gpr	t5	.32	120	0\n" // =x30
		"gpr	t6	.32	124	0\n" // =x31
		// RV32F/D regs (ABI names)
		// From user-Level ISA Specification, section 8.1 and 9.1
		"gpr	ft0	.64	128	0\n" // =f0
		"gpr	ft1	.64	136	0\n" // =f1
		"gpr	ft2	.64	144	0\n" // =f2
		"gpr	ft3	.64	152	0\n" // =f3
		"gpr	ft4	.64	160	0\n" // =f4
		"gpr	ft5	.64	168	0\n" // =f5
		"gpr	ft6	.64	176	0\n" // =f6
		"gpr	ft7	.64	184	0\n" // =f7
		"gpr	fs0	.64	192	0\n" // =f8
		"gpr	fs1	.64	200	0\n" // =f9
		"gpr	fa0	.64	208	0\n" // =f10
		"gpr	fa1	.64	216	0\n" // =f11
		"gpr	fa2	.64	224	0\n" // =f12
		"gpr	fa3	.64	232	0\n" // =f13
		"gpr	fa4	.64	240	0\n" // =f14
		"gpr	fa5	.64	248	0\n" // =f15
		"gpr	fa6	.64	256	0\n" // =f16
		"gpr	fa7	.64	264	0\n" // =f17
		"gpr	fs2	.64	272	0\n" // =f18
		"gpr	fs3	.64	280	0\n" // =f19
		"gpr	fs4	.64	288	0\n" // =f20
		"gpr	fs5	.64	296	0\n" // =f21
		"gpr	fs6	.64	304	0\n" // =f22
		"gpr	fs7	.64	312	0\n" // =f23
		"gpr	fs8	.64	320	0\n" // =f24
		"gpr	fs9	.64	328	0\n" // =f25
		"gpr	fs10	.64	336	0\n" // =f26
		"gpr	fs11	.64	344	0\n" // =f27
		"gpr	ft8	.64	352	0\n" // =f28
		"gpr	ft9	.64	360	0\n" // =f29
		"gpr	ft10	.64	368	0\n" // =f30
		"gpr	ft11	.64	376	0\n" // =f31
		"gpr	fcsr	.32	384	0\n"
		"flg	nx	.1	3072	0\n"
		"flg	uf	.1	3073	0\n"
		"flg	of	.1	3074	0\n"
		"flg	dz	.1	3075	0\n"
		"flg	nv	.1	3076	0\n"
		"flg	frm	.3	3077	0\n"
		;

		break;
	case 64: p =
		"=PC	pc\n"
		"=SP	sp\n" // ABI: stack pointer
		"=LR	ra\n" // ABI: return address
		"=BP	s0\n" // ABI: frame pointer
		"=A0	a0\n"
		"=A1	a1\n"

		"gpr	pc	.64	0	0\n"
		// RV64I regs (ABI names)
		// From user-Level ISA Specification, section 2.1 and 4.1
		// "zero" has been left out as it ignores writes and always reads as zero
		"gpr	ra	.64	8	0\n" // =x1
		"gpr	sp	.64	16	0\n" // =x2
		"gpr	gp	.64	24	0\n" // =x3
		"gpr	tp	.64	32	0\n" // =x4
		"gpr	t0	.64	40	0\n" // =x5
		"gpr	t1	.64	48	0\n" // =x6
		"gpr	t2	.64	56	0\n" // =x7
		"gpr	s0	.64	64	0\n" // =x8
		"gpr	s1	.64	72	0\n" // =x9
		"gpr	a0	.64	80	0\n" // =x10
		"gpr	a1	.64	88	0\n" // =x11
		"gpr	a2	.64	96	0\n" // =x12
		"gpr	a3	.64	104	0\n" // =x13
		"gpr	a4	.64	112	0\n" // =x14
		"gpr	a5	.64	120	0\n" // =x15
		"gpr	a6	.64	128	0\n" // =x16
		"gpr	a7	.64	136	0\n" // =x17
		"gpr	s2	.64	144	0\n" // =x18
		"gpr	s3	.64	152	0\n" // =x19
		"gpr	s4	.64	160	0\n" // =x20
		"gpr	s5	.64	168	0\n" // =x21
		"gpr	s6	.64	176	0\n" // =x22
		"gpr	s7	.64	184	0\n" // =x23
		"gpr	s8	.64	192	0\n" // =x24
		"gpr	s9	.64	200	0\n" // =x25
		"gpr	s10	.64	208	0\n" // =x26
		"gpr	s11	.64	216	0\n" // =x27
		"gpr	t3	.64	224	0\n" // =x28
		"gpr	t4	.64	232	0\n" // =x29
		"gpr	t5	.64	240	0\n" // =x30
		"gpr	t6	.64	248	0\n" // =x31
		// RV64F/D regs (ABI names)
		"gpr	ft0	.64	256	0\n" // =f0
		"gpr	ft1	.64	264	0\n" // =f1
		"gpr	ft2	.64	272	0\n" // =f2
		"gpr	ft3	.64	280	0\n" // =f3
		"gpr	ft4	.64	288	0\n" // =f4
		"gpr	ft5	.64	296	0\n" // =f5
		"gpr	ft6	.64	304	0\n" // =f6
		"gpr	ft7	.64	312	0\n" // =f7
		"gpr	fs0	.64	320	0\n" // =f8
		"gpr	fs1	.64	328	0\n" // =f9
		"gpr	fa0	.64	336	0\n" // =f10
		"gpr	fa1	.64	344	0\n" // =f11
		"gpr	fa2	.64	352	0\n" // =f12
		"gpr	fa3	.64	360	0\n" // =f13
		"gpr	fa4	.64	368	0\n" // =f14
		"gpr	fa5	.64	376	0\n" // =f15
		"gpr	fa6	.64	384	0\n" // =f16
		"gpr	fa7	.64	392	0\n" // =f17
		"gpr	fs2	.64	400	0\n" // =f18
		"gpr	fs3	.64	408	0\n" // =f19
		"gpr	fs4	.64	416	0\n" // =f20
		"gpr	fs5	.64	424	0\n" // =f21
		"gpr	fs6	.64	432	0\n" // =f22
		"gpr	fs7	.64	440	0\n" // =f23
		"gpr	fs8	.64	448	0\n" // =f24
		"gpr	fs9	.64	456	0\n" // =f25
		"gpr	fs10	.64	464	0\n" // =f26
		"gpr	fs11	.64	472	0\n" // =f27
		"gpr	ft8	.64	480	0\n" // =f28
		"gpr	ft9	.64	488	0\n" // =f29
		"gpr	ft10	.64	496	0\n" // =f30
		"gpr	ft11	.64	504	0\n" // =f31
		"gpr	fcsr	.32	512	0\n"
		"flg	nx	.1	4096	0\n"
		"flg	uf	.1	4097	0\n"
		"flg	of	.1	4098	0\n"
		"flg	dz	.1	4099	0\n"
		"flg	nv	.1	4100	0\n"
		"flg	frm	.3	4101	0\n"
		;

		break;
	}
	return (p && *p)? strdup (p): NULL;
}

static int archinfo(RAnal *anal, int q) {
	switch (q) {
	case R_ANAL_ARCHINFO_ALIGN:
		return 4;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		if (anal->bits == 64) {
			return 4;
		}
		return 2;
	}
	return 0;
}

RAnalPlugin r_anal_plugin_riscv_cs = {
	.name = "riscv.cs",
	.desc = "Capstone RISCV analyzer",
	.license = "BSD",
	.esil = true,
	.arch = "riscv",
	.get_reg_profile = get_reg_profile,
	.archinfo = archinfo,
	.bits = 32|64,
	.op = &analop,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_riscv_cs,
	.version = R2_VERSION
};
#endif

#else
RAnalPlugin r_anal_plugin_riscv_cs = {0};
#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.version = R2_VERSION
};
#endif
#endif

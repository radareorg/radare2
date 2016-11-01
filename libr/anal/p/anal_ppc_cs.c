/* radare2 - LGPL - Copyright 2013-2016 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include <capstone/ppc.h>

struct Getarg {
	csh handle;
	cs_insn *insn;
	int bits;
};

#define esilprintf(op, fmt, arg...) r_strbuf_setf (&op->esil, fmt, ##arg)
#define INSOPS insn->detail->ppc.op_count
#define INSOP(n) insn->detail->ppc.operands[n]

static char *getarg2(struct Getarg *gop, int n, const char *setstr) {
	cs_insn *insn = gop->insn;
	csh handle = gop->handle;
	static char words[3][64];
	cs_ppc_op op;

	if (n < 0 || n >= 3) {
		return NULL;
	}
	op = INSOP (n);
	switch (op.type) {
	case PPC_OP_INVALID:
		strcpy (words[n], "invalid");
		break;
	case PPC_OP_REG:
		snprintf (words[n], sizeof (words[n]), 
			"%s%s", cs_reg_name (handle, op.reg), setstr);
		break;
	case PPC_OP_IMM:
		snprintf (words[n], sizeof (words[n]), 
			"0x%"PFMT64x"%s", (ut64)op.imm, setstr);
		break;
	case PPC_OP_MEM:
		snprintf (words[n], sizeof (words[n]), 
			"%"PFMT64d",%s,+,%s",
			(ut64)op.mem.disp,
			cs_reg_name (handle, op.mem.base), setstr);
		break;
	case PPC_OP_CRX: // Condition Register field
		words[n][0] = 0;
		break;
	}
	return words[n];
}

#define ARG(n) getarg2(&gop, n, "")
#define ARG2(n,m) getarg2(&gop, n, m)

static int set_reg_profile(RAnal *anal) {
	const char *p = NULL;
	p =
	"=PC	pc\n"
	"=SP	r1\n"
	"=SR	srr1\n" // status register ??
	"=A0	r3\n" // also for ret
	"=A1	r4\n"
	"=A2	r5\n"
	"=A3	r6\n"
	"=A4	r7\n"
	"=A5	r8\n"
	"=A6	r6\n"
	"gpr	srr0	.32	0	0\n"
	"gpr	srr1	.32	4	0\n"
	"gpr	r0	.32	8	0\n"
	"gpr	r1	.32	12	0\n"
	"gpr	r2	.32	16	0\n"
	"gpr	r3	.32	20	0\n"
	"gpr	r4	.32	24	0\n"
	"gpr	r5	.32	28	0\n"
	"gpr	r6	.32	32	0\n"
	"gpr	r7	.32	36	0\n"
	"gpr	r8	.32	40	0\n"
	"gpr	r9	.32	44	0\n"
	"gpr	r10	.32	48	0\n"
	"gpr	r11	.32	52	0\n"
	"gpr	r12	.32	56	0\n"
	"gpr	r13	.32	60	0\n"
	"gpr	r14	.32	64	0\n"
	"gpr	r15	.32	68	0\n"
	"gpr	r16	.32	72	0\n"
	"gpr	r17	.32	76	0\n"
	"gpr	r18	.32	80	0\n"
	"gpr	r19	.32	84	0\n"
	"gpr	r20	.32	88	0\n"
	"gpr	r21	.32	92	0\n"
	"gpr	r22	.32	96	0\n"

	"gpr	r23	.32	100	0\n"
	"gpr	r24	.32	104	0\n"
	"gpr	r25	.32	108	0\n"
	"gpr	r26	.32	112	0\n"
	"gpr	r27	.32	116	0\n"
	"gpr	r28	.32	120	0\n"
	"gpr	r29	.32	124	0\n"
	"gpr	r30	.32	128	0\n"
	"gpr	r31	.32	132	0\n"
	"gpr	cr	.32	136	0\n"
	"gpr	xer	.32	140	0\n"
	"gpr	lr	.32	144	0\n"
	"gpr	ctr	.32	148	0\n"
	"gpr	mq	.32	152	0\n"
	"gpr	vrsave	.32	156	0\n" 
	// extra
	"gpr	pc	.32	160	0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	static csh handle = 0;
	static int omode = -1;
	int n, ret;
	cs_insn *insn;
	int mode = (a->bits==64)? CS_MODE_64: (a->bits==32)? CS_MODE_32: 0;
	mode |= CS_MODE_BIG_ENDIAN;
	if (mode != omode) {
		cs_close (&handle);
		handle = 0;
		omode = mode;
	}
	if (handle == 0) {
		ret = cs_open (CS_ARCH_PPC, mode, &handle);
		if (ret != CS_ERR_OK) {
			return -1;
		}
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	}
	op->delay = 0;
	op->type = R_ANAL_OP_TYPE_NULL;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->size = 4;
	
	// capstone-next
	n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else {
		struct Getarg gop = {
			.handle = handle,
			.insn = insn,
			.bits = a->bits
		};
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
		case PPC_INS_MFLR:
			op->type = R_ANAL_OP_TYPE_PUSH;
			break;
		case PPC_INS_MTLR:
			op->type = R_ANAL_OP_TYPE_POP;
			break;
		case PPC_INS_MR:
		case PPC_INS_LI:
		case PPC_INS_LIS:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", ARG(1), ARG(0)); break;
			break;
		case PPC_INS_RLWINM:
			op->type = R_ANAL_OP_TYPE_ROL;
			break;
		case PPC_INS_SC:
			op->type = R_ANAL_OP_TYPE_SWI;
			esilprintf (op, "0,$");
			break;
		case PPC_INS_NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			esilprintf (op, ",");
			break;
		case PPC_INS_STW:
		case PPC_INS_STWU:
		case PPC_INS_STWUX:
		case PPC_INS_STWX:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG(0), ARG2(1, "=[4]"));
			break;
		case PPC_INS_STB:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s", ARG(0), ARG2(1, "=[1]"));
			break;
		case PPC_INS_STH:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s", ARG(0), ARG2(1, "=[2]"));
			break;
		case PPC_INS_STWBRX:
		case PPC_INS_STWCX:
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case PPC_INS_LA:
		case PPC_INS_LBZ:
		case PPC_INS_LBZU:
		case PPC_INS_LBZUX:
		case PPC_INS_LBZX:
		case PPC_INS_LD:
		case PPC_INS_LDARX:
		case PPC_INS_LDBRX:
		case PPC_INS_LDU:
		case PPC_INS_LDUX:
		case PPC_INS_LDX:
		case PPC_INS_LFD:
		case PPC_INS_LFDU:
		case PPC_INS_LFDUX:
		case PPC_INS_LFDX:
		case PPC_INS_LFIWAX:
		case PPC_INS_LFIWZX:
		case PPC_INS_LFS:
		case PPC_INS_LFSU:
		case PPC_INS_LFSUX:
		case PPC_INS_LFSX:
		case PPC_INS_LHA:
		case PPC_INS_LHAU:
		case PPC_INS_LHAUX:
		case PPC_INS_LHAX:
		case PPC_INS_LHBRX:
		case PPC_INS_LHZ:
		case PPC_INS_LHZU:
		case PPC_INS_LWA:
		case PPC_INS_LWARX:
		case PPC_INS_LWAUX:
		case PPC_INS_LWAX:
		case PPC_INS_LWBRX:
		case PPC_INS_LWZ:
		case PPC_INS_LWZU:
		case PPC_INS_LWZUX:
		case PPC_INS_LWZX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,[4],%s,=", ARG(1), ARG(0));
			break;
		case PPC_INS_SLW:
		case PPC_INS_SLWI:
			op->type = R_ANAL_OP_TYPE_SHL;
			esilprintf (op, "%s,%s,<<,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_SRW:
		case PPC_INS_SRWI:
			op->type = R_ANAL_OP_TYPE_SHR;
			esilprintf (op, "%s,%s,>>,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_CMPW:
		case PPC_INS_CMPWI:
		case PPC_INS_CMPLWI:
			op->type = R_ANAL_OP_TYPE_CMP;
			esilprintf (op, "%s,%s,==", ARG(1), ARG(0));
			break;
		case PPC_INS_MULLI:
		case PPC_INS_MULLW:
			op->type = R_ANAL_OP_TYPE_MUL;
			esilprintf (op, "%s,%s,*,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_SUB:
		case PPC_INS_SUBC:
		case PPC_INS_SUBFIC:
		case PPC_INS_SUBFZE:
			op->type = R_ANAL_OP_TYPE_SUB;
			esilprintf (op, "%s,%s,-,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_ADD:
		case PPC_INS_ADDI:
		case PPC_INS_ADDC:
		case PPC_INS_ADDE:
		case PPC_INS_ADDIC:
		case PPC_INS_ADDIS:
		case PPC_INS_ADDME:
		case PPC_INS_ADDZE:
			op->type = R_ANAL_OP_TYPE_ADD;
			esilprintf (op, "%s,%s,+,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_MTSPR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", ARG(1), ARG(0));
			break;
		case PPC_INS_BCTR: // switch table here
			op->type = R_ANAL_OP_TYPE_UJMP;
			esilprintf (op, "ctr,pc,=");
			break;
		case PPC_INS_BC:
			op->type = R_ANAL_OP_TYPE_UJMP;
			esilprintf (op, "%s,pc,=", ARG(0));
			break;
		case PPC_INS_B:
		case PPC_INS_BA:
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = (ut64)insn->detail->ppc.operands[0].imm;
			switch (insn->detail->ppc.bc) {
#if 0
			case PPC_BC_INVALID:
				// non-conditional
				op->type = R_ANAL_OP_TYPE_ILL;
				break;
#endif
			case PPC_BC_LT:
			case PPC_BC_LE:
			case PPC_BC_EQ:
			case PPC_BC_GE:
			case PPC_BC_GT:
			case PPC_BC_NE:
			case PPC_BC_UN:
			case PPC_BC_NU:
			case PPC_BC_SO:
			case PPC_BC_NS:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->fail = addr + 4;
				break;
			default:
				break;
			}
			switch (insn->detail->ppc.operands[0].type) {
			case PPC_OP_CRX:
				op->type = R_ANAL_OP_TYPE_CJMP;
				break;
			case PPC_OP_REG:
				if (op->type == R_ANAL_OP_TYPE_CJMP) {
					op->type = R_ANAL_OP_TYPE_UCJMP;
				} else {
					op->type = R_ANAL_OP_TYPE_CJMP;
				}
				op->jump = (ut64)insn->detail->ppc.operands[1].imm;
				op->fail = addr+4;
				//op->type = R_ANAL_OP_TYPE_UJMP;
			default:
				break;
			}
			break;
		case PPC_INS_NOR:
			op->type = R_ANAL_OP_TYPE_NOR;
			//esilprintf (op, "%s,%s,^,%s,=", ARG(1), ARG(2), ARG(0));
			break;
		case PPC_INS_XOR:
		case PPC_INS_XORI:
		case PPC_INS_XORIS:
			op->type = R_ANAL_OP_TYPE_XOR;
			esilprintf (op, "%s,%s,^,%s,=", ARG(1), ARG(2), ARG(0));
			break;
		case PPC_INS_DIVD:
		case PPC_INS_DIVDU:
		case PPC_INS_DIVW:
		case PPC_INS_DIVWU:
			op->type = R_ANAL_OP_TYPE_DIV;
			break;
		case PPC_INS_BL:
		case PPC_INS_BLA:
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = (ut64)insn->detail->ppc.operands[0].imm;
			op->fail = addr + 4;
			esilprintf (op, "pc,lr,=,%s,pc,=", ARG(0));
			break;
		case PPC_INS_TRAP:
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case PPC_INS_BLR:
		case PPC_INS_BLRL:
			op->type = R_ANAL_OP_TYPE_RET;
			esilprintf (op, "lr,pc,=");
			break;
		case PPC_INS_AND:
		case PPC_INS_NAND:
		case PPC_INS_ANDI:
		case PPC_INS_ANDIS:
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case PPC_INS_OR:
		case PPC_INS_ORC:
		case PPC_INS_ORI:
		case PPC_INS_ORIS:
			op->type = R_ANAL_OP_TYPE_OR;
			esilprintf (op, "%s,%s,|,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		}
		cs_free (insn, n);
		//cs_close (&handle);
	}
	return op->size;
}

static int archinfo(RAnal *anal, int q) {
	return 4; /* :D */
}

RAnalPlugin r_anal_plugin_ppc_cs = {
	.name = "ppc",
	.desc = "Capstone PowerPC analysis",
	.license = "BSD",
	.arch = "ppc",
	.bits = 32|64,
	.archinfo = archinfo,
	.op = &analop,
	.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_ppc_cs,
	.version = R2_VERSION
};
#endif

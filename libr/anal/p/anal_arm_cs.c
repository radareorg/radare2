/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone.h>
#include <arm.h>
#include "esil.h"
/* arm64 */
#define IMM64(x) insn->detail->arm64.operands[x].imm

/* arm32 */
#define REG(x) cs_reg_name (*handle, insn->detail->arm.operands[x].reg)
#define REGID(x) insn->detail->arm.operands[x].reg
#define IMM(x) insn->detail->arm.operands[x].imm
#define MEMBASE(x) cs_reg_name(*handle, insn->detail->arm.operands[x].mem.base)
#define REGBASE(x) insn->detail->arm.operands[x].mem.base
#define MEMINDEX(x) insn->detail->arm.operands[x].mem.index
#define MEMDISP(x) insn->detail->arm.operands[x].mem.disp
// TODO scale and disp

static const char *arg(RAnal *a, csh *handle, cs_insn *insn, char *buf, int n) {
	switch (insn->detail->arm.operands[n].type) {
	case ARM_OP_REG:
		sprintf (buf, "%s",
			cs_reg_name (*handle,
				insn->detail->arm.operands[n].reg));
		break;
	case ARM_OP_IMM:
		if (a->bits == 64) {
			// 64bit only
			sprintf (buf, "%"PFMT64d, (ut64)
					insn->detail->arm.operands[n].imm);
		} else {
			// 32bit only
			sprintf (buf, "%"PFMT64d, (ut64)(ut32)
					insn->detail->arm.operands[n].imm);
		}
		break;
	case ARM_OP_MEM:
		// TODO
		break;
	default:
		break;
	}
	return buf;
}
#define ARG(x) arg(a, handle, insn, str[x], x)

static int analop_esil(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn) {
	int i;
	char str[32][32];
	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");
	switch (insn->detail->arm.cc) {
	case ARM_CC_AL:
		// no condition
		break;
	case ARM_CC_EQ:
		r_strbuf_setf (&op->esil, "zf,0,?,");
		break;
	case ARM_CC_NE:
		r_strbuf_setf (&op->esil, "zf,!,0,?,");
		break;
	case ARM_CC_GT:
	case ARM_CC_LE:
		break;
	default:
		break;
	}
	// TODO: PREFIX CONDITIONAL
	switch (insn->id) {
	case ARM_INS_PUSH:
		// TODO: increment stack
	case ARM_INS_STM:
		for (i=1; i<insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,%s,%d,+,=[4],",
				REG (i), ARG (0), i*4);
		}
		break;
	case ARM_INS_POP:
		// TODO: decrement stack
	case ARM_INS_LDM:
		for (i=1; i<insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,%d,+,[4],%s,=",
				ARG (0), i*4, REG (i));
		}
		break;
	case ARM_INS_CMP:
		r_strbuf_appendf (&op->esil, "%s,%s,==", ARG(1), ARG(0));
		break;
	case ARM_INS_LSL:
		// suffix 'S' forces conditional flag to be updated
		r_strbuf_appendf (&op->esil, "%s,%s,<<=", ARG(1), ARG(0));
		break;
	case ARM_INS_LSR:
		// suffix 'S' forces conditional flag to be updated
		r_strbuf_appendf (&op->esil, "%s,%s,>>=", ARG(1), ARG(0));
		break;
	case ARM_INS_B:
		r_strbuf_appendf (&op->esil, "%s,pc,=", ARG(0));
		break;
	case ARM_INS_BL:
	case ARM_INS_BLX:
		r_strbuf_appendf (&op->esil, "4,pc,+,lr,=,%s,pc,=", ARG(0));
		break;
	case ARM_INS_MOV:
	case ARM_INS_MOVS:
		r_strbuf_appendf (&op->esil, "%s,%s,=", ARG(1), REG(0));
		break;
	case ARM_INS_SSUB16:
	case ARM_INS_SSUB8:
	case ARM_INS_SUB:
		r_strbuf_appendf (&op->esil, "%s,%s,-=", ARG(1), ARG(0));
		break;
	case ARM_INS_SADD16:
	case ARM_INS_SADD8:
	case ARM_INS_ADD:
		if (!strcmp (ARG(0),ARG(1))) {
			r_strbuf_appendf (&op->esil, "%s,%s,+=", ARG(2), ARG(0));
		} else if (!strcmp (ARG(2),"0")) {
			r_strbuf_appendf (&op->esil, "%s,%s,=", ARG(1), ARG(0));
		} else {
			r_strbuf_appendf (&op->esil, "%s,%s,+,%s,=", ARG(2), ARG(1), ARG(0));
		}
		break;
	case ARM_INS_STR:
		r_strbuf_appendf (&op->esil, "%s,%s,%d,+,=[4]",
			REG(0), MEMBASE(1), MEMDISP(1));
		break;
	case ARM_INS_STRB:
		r_strbuf_appendf (&op->esil, "%s,%s,%d,+,=[1]",
			REG(0), MEMBASE(1), MEMDISP(1));
		break;
	case ARM_INS_LDR:
		if (MEMDISP(1)<0) {
			if (REGBASE(1) == ARM_REG_PC) {
				r_strbuf_appendf (&op->esil, "8,%s,+,%d,-,[4],%s,=",
						MEMBASE(1), -MEMDISP(1), REG(0));
				switch (a->bits) {
				case 32:
					op->ptr = addr + 8 - MEMDISP(1);
					op->refptr = 4;
					break;
				case 16:
					if ( (addr % 4) == 0 ) {
						op->ptr = addr + 4 - MEMDISP(1);
						op->refptr = 4;
					} else {
						op->ptr = addr + 2 - MEMDISP(1);
						op->refptr = 4;
					}
					break;
				}
			} else {
				r_strbuf_appendf (&op->esil, "%s,%d,-,[4],%s,=",
					MEMBASE(1), -MEMDISP(1), REG(0));
			}
		} else {
			if (REGBASE(1) == ARM_REG_PC) {
				r_strbuf_appendf (&op->esil, "8,%s,+,%d,+,[4],%s,=",
					MEMBASE(1), MEMDISP(1), REG(0));
				if (a->bits==32) {
					op->ptr = addr + 8 + MEMDISP(1);
					op->refptr = 4;
				} else if (a->bits==16) {
					if ( (addr % 4) == 0 ) {
						op->ptr = addr + 4 + MEMDISP(1);
						op->refptr = 4;
					} else {
						op->ptr = addr + 2 + MEMDISP(1);
						op->refptr = 4;
					}
				}
			} else {
				r_strbuf_appendf (&op->esil, "%s,%d,+,[4],%s,=",
					MEMBASE(1), MEMDISP(1), REG(0));
			}
			op->refptr = 4;
		}
		break;
	case ARM_INS_LDRB:
		r_strbuf_appendf (&op->esil, "%s,%d,+,[1],%s,=",
			MEMBASE(1), MEMDISP(1), REG(0));
		break;
	default:
		break;
	}
	return 0;
}

static void anop64 (RAnalOp *op, cs_insn *insn) {
	ut64 addr = op->addr;
	switch (insn->id) {
	case ARM64_INS_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case ARM64_INS_ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case ARM64_INS_MOV:
	case ARM64_INS_MOVI:
	case ARM64_INS_MOVK:
	case ARM64_INS_MOVN:
	case ARM64_INS_MOVZ:
	case ARM64_INS_SMOV:
	case ARM64_INS_UMOV:
	case ARM64_INS_FMOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM64_INS_CMP:
	case ARM64_INS_TST:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case ARM64_INS_ROR:
	case ARM64_INS_ORN:
	case ARM64_INS_LSL:
	case ARM64_INS_LSR:
		break;
	case ARM64_INS_STR:
		//case ARM64_INS_POP:
	case ARM64_INS_LDR:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case ARM64_INS_BL:
	case ARM64_INS_BLR:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = IMM64(0);
		break;
	case ARM64_INS_B:
		// BX LR == RET
		if (insn->detail->arm64.operands[0].reg == ARM64_REG_LR) {
			op->type = R_ANAL_OP_TYPE_RET;
		} else if (insn->detail->arm64.cc) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM64(0);
			op->fail = addr+op->size;
		} else {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = IMM64(0);
		}
		break;
	default:
		break;
	}
}

static void anop32 (RAnalOp *op, cs_insn *insn) {
	ut64 addr = op->addr;
	int i;
	switch (insn->id) {
	case ARM_INS_POP:
	case ARM_INS_LDM:
		op->type = R_ANAL_OP_TYPE_POP;
		for (i = 0; i < insn->detail->arm.op_count; i++) {
			if (insn->detail->arm.operands[i].type == ARM_OP_REG &&
					insn->detail->arm.operands[i].reg == ARM_REG_PC) {
				if (insn->detail->arm.cc == ARM_CC_AL)
					op->type = R_ANAL_OP_TYPE_RET;
				else
					op->type = R_ANAL_OP_TYPE_CRET;
				break;
			}
		}
		break;
	case ARM_INS_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case ARM_INS_ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (REGID(1)==ARM_REG_PC) {
			op->ptr = addr + 8 + IMM(2);
			op->refptr = 0;
		}
		break;
	case ARM_INS_MOV:
	case ARM_INS_MOVS:
	case ARM_INS_MOVT:
	case ARM_INS_MOVW:
	case ARM_INS_VMOVL:
	case ARM_INS_VMOVN:
	case ARM_INS_VQMOVUN:
	case ARM_INS_VQMOVN:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM_INS_CMP:
	case ARM_INS_TST:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case ARM_INS_ROR:
	case ARM_INS_ORN:
	case ARM_INS_LSL:
	case ARM_INS_LSR:
		break;
	case ARM_INS_PUSH:
	case ARM_INS_STR:
		//case ARM_INS_POP:
	case ARM_INS_LDR:
		if (insn->detail->arm.operands[0].reg == ARM_REG_PC) {
			op->type = R_ANAL_OP_TYPE_UJMP;
		} else {
			op->type = R_ANAL_OP_TYPE_LOAD;
		}
		break;
	case ARM_INS_BL:
	case ARM_INS_BLX:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = IMM(0);
		break;
	case ARM_INS_B:
	case ARM_INS_BX:
	case ARM_INS_BXJ:
		// BX LR == RET
		if (insn->detail->arm.operands[0].reg == ARM_REG_LR) {
			op->type = R_ANAL_OP_TYPE_RET;
		} else if (insn->detail->arm.cc) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = (ut64) (ut32)IMM(0);
			op->fail = addr+op->size;
		} else {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = IMM(0);
		}
		break;
	default:
		break;
	}
}
static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	csh handle = 0;
	cs_insn *insn = NULL;
	int mode = (a->bits==16)? CS_MODE_THUMB: CS_MODE_ARM;
	int n, ret;
	mode |= (a->big_endian)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;

	ret = (a->bits==64)?
		cs_open (CS_ARCH_ARM64, mode, &handle):
		cs_open (CS_ARCH_ARM, mode, &handle);
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	op->type = R_ANAL_OP_TYPE_NULL;
	op->size = (a->bits==16)? 2: 4;
	op->delay = 0;
	op->jump = op->fail = -1;
	op->addr = addr;
	op->ptr = op->val = -1;
	op->refptr = 0;
	r_strbuf_init (&op->esil);
	if (ret == CS_ERR_OK) {
		n = cs_disasm (handle, (ut8*)buf, len, addr, 1, &insn);
		if (n<1) {
			op->type = R_ANAL_OP_TYPE_ILL;
		} else {
			op->size = insn->size;
			if (a->bits == 64) {
				anop64 (op, insn);
			} else {
				anop32 (op, insn);
			}
			if (a->decode) {
				analop_esil (a, op, addr, buf, len, &handle, insn);
			}
			cs_free (insn, n);
		}
		cs_close (&handle);
	}
	return op->size;
}

static int set_reg_profile(RAnal *anal) {
	char *p = (anal->bits != 64) ?
			"=pc	r15\n"
			"=sp	r14\n" // XXX
			"=bp	r14\n" // XXX
			"=a0	r0\n"
			"=a1	r1\n"
			"=a2	r2\n"
			"=a3	r3\n"
			"gpr	lr	.32	56	0\n" // r14
			"gpr	pc	.32	60	0\n" // r15

			"gpr	r0	.32	0	0\n"
			"gpr	r1	.32	4	0\n"
			"gpr	r2	.32	8	0\n"
			"gpr	r3	.32	12	0\n"
			"gpr	r4	.32	16	0\n"
			"gpr	r5	.32	20	0\n"
			"gpr	r6	.32	24	0\n"
			"gpr	r7	.32	28	0\n"
			"gpr	r8	.32	32	0\n"
			"gpr	r9	.32	36	0\n"
			"gpr	r10	.32	40	0\n"
			"gpr	r11	.32	44	0\n"
			"gpr	r12	.32	48	0\n"
			"gpr	r13	.32	52	0\n"
			"gpr	r14	.32	56	0\n"
			"gpr	r15	.32	60	0\n"
			"gpr	r16	.32	64	0\n"
			"gpr	r17	.32	68	0\n"
		:
			"=pc	pc\n"
			"=sp	sp\n" // XXX
			"=a0	x0\n"
			"=a1	x1\n"
			"=a2	x2\n"
			"=a3	x3\n"
			"=zf	zf\n"
			"=sf	nf\n"
			"=of	vf\n"
			"=cf	cf\n"
			"=sn	ox0\n"
			"gpr	x0	.64	0	0\n" // x0
			"gpr	x1	.64	8	0\n" // x0
			"gpr	x2	.64	16	0\n" // x0
			"gpr	x3	.64	24	0\n" // x0
			"gpr	x4	.64	32	0\n" // x0
			"gpr	x5	.64	40	0\n" // x0
			"gpr	x6	.64	48	0\n" // x0
			"gpr	x7	.64	56	0\n" // x0
			"gpr	x8	.64	64	0\n" // x0
			"gpr	x9	.64	72	0\n" // x0
			"gpr	x10	.64	80	0\n" // x0
			"gpr	x11	.64	88	0\n" // x0
			"gpr	x12	.64	96	0\n" // x0
			"gpr	x13	.64	104	0\n" // x0
			"gpr	x14	.64	112	0\n" // x0
			"gpr	x15	.64	120	0\n" // x0
			"gpr	x16	.64	128	0\n" // x0
			"gpr	x17	.64	136	0\n" // x0
			"gpr	x18	.64	144	0\n" // x0
			"gpr	x19	.64	152	0\n" // x0
			"gpr	x20	.64	160	0\n" // x0
			"gpr	x21	.64	168	0\n" // x0
			"gpr	x22	.64	176	0\n" // x0
			"gpr	x23	.64	184	0\n" // x0
			"gpr	x24	.64	192	0\n" // x0
			"gpr	x25	.64	200	0\n" // x0
			"gpr	x26	.64	208	0\n" // x0
			"gpr	x27	.64	216	0\n" // x0
			"gpr	x28	.64	224	0\n" // x0
			"gpr	x29	.64	232	0\n" // x0
			"gpr	x30	.64	240	0\n" // x0
			"gpr	pc	.64	248	0\n" // x0
			"gpr	pstate	.64	256	0\n" // x0
			"gpr	ox0	.64	264	0\n" // x0
			"gpr	snr	.64	272	0\n" // x0

			// probably wrong
			"gpr	nf	.1	.256	0	sign\n" // msb bit of last op
			"gpr	zf	.1	.257	0	zero\n" // set if last op is 0
			"gpr	cf	.1	.258	0	carry\n" // set if last op carries
			"gpr	vf	.1	.515	0	overflow\n"; // set if overflows

	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_arm_cs = {
	.name = "arm",
	.desc = "Capstone ARM analyzer",
	.license = "BSD",
	.esil = R_TRUE,
	.arch = R_SYS_ARCH_ARM,
	.set_reg_profile = set_reg_profile,
	.bits = 16|32|64,
	.op = &analop,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_arm_cs
};
#endif

/* radare2 - LGPL - Copyright 2013-2015 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include <capstone/arm.h>
#include "esil.h"
/* arm64 */
#define IMM64(x) insn->detail->arm64.operands[x].imm

/* arm32 */
#define REG(x) cs_reg_name (*handle, insn->detail->arm.operands[x].reg)
#define REG64(x) cs_reg_name (*handle, insn->detail->arm64.operands[x].reg)
#define REGID(x) insn->detail->arm.operands[x].reg
#define IMM(x) insn->detail->arm.operands[x].imm
#define IMM64(x) insn->detail->arm64.operands[x].imm
#define MEMBASE(x) cs_reg_name(*handle, insn->detail->arm.operands[x].mem.base)
#define MEMBASE64(x) cs_reg_name(*handle, insn->detail->arm64.operands[x].mem.base)
#define REGBASE(x) insn->detail->arm.operands[x].mem.base
#define REGBASE64(x) insn->detail->arm64.operands[x].mem.base
#define MEMINDEX(x) insn->detail->arm.operands[x].mem.index
#define MEMINDEX64(x) insn->detail->arm64.operands[x].mem.index
#define MEMDISP(x) insn->detail->arm.operands[x].mem.disp
#define MEMDISP64(x) insn->detail->arm64.operands[x].mem.disp
#define ISREG(x) insn->detail->arm.operands[x].type == ARM_OP_REG
#define ISREG64(x) insn->detail->arm64.operands[x].type == ARM_OP_REG
// TODO scale and disp

/* arm64 */

static const char *arg(RAnal *a, csh *handle, cs_insn *insn, char *buf, int n) {
	buf[0] = 0;
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
		break;
	case ARM_OP_FP:
		sprintf (buf, "%lf", insn->detail->arm.operands[n].fp);
		break;
	default:
		break;
	}
	return buf;
}
#define ARG(x) arg(a, handle, insn, str[x], x)

static int analop64_esil(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn) {
	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");

	switch (insn->id) {
	case ARM64_INS_ADD:
		/* TODO: support WZR XZR to specify 32, 64bit op */
		r_strbuf_setf (&op->esil, "%s,%s,-=", REG64 (1), REG64 (0));
		break;
	case ARM64_INS_SUB:
		/* TODO: support WZR XZR to specify 32, 64bit op */
		r_strbuf_setf (&op->esil, "%s,%s,+=", REG64 (1), REG64 (0));
		break;
	case ARM64_INS_MUL:
		/* TODO: support WZR XZR to specify 32, 64bit op */
		r_strbuf_setf (&op->esil, "%s,%s,*=", REG64 (1), REG64 (0));
		break;
	case ARM64_INS_ORR:
		// TODO: if (IMM64(1) == 6) { // WZR }
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,|=",
			IMM64(2), REG64 (0));
		break;
	case ARM64_INS_STURB: // sturb wzr, [x9, 0xffffffffffffffff]
		// TODO
		break;
	case ARM64_INS_EOR:
		r_strbuf_setf (&op->esil, "%s,%s,%s,^,=",
			REG64(2), REG64(1), REG64(0));
		break;
	case ARM64_INS_FDIV:
	case ARM64_INS_SDIV:
	case ARM64_INS_UDIV:
		/* TODO: support WZR XZR to specify 32, 64bit op */
		r_strbuf_setf (&op->esil, "%s,%s,/=", REG64 (1), REG64 (0));
		break;
	case ARM64_INS_B:
		r_strbuf_setf (&op->esil, "%d,pc,=", IMM64 (0));
		break;
	case ARM64_INS_BL:
		r_strbuf_setf (&op->esil, "pc,lr,=,%d,pc,=", IMM64 (0));
		break;
	case ARM64_INS_BLR:
		// XXX
		r_strbuf_setf (&op->esil, "pc,lr,=,%d,pc,=", IMM64 (0));
		break;
	case ARM64_INS_LDR: // ldr x6, [x6,0xf90]
		r_strbuf_setf (&op->esil, "%s,%d,+,[],%s,=",
			MEMBASE64(1), MEMDISP64(1),  REG64(0));
		break;
	case ARM64_INS_LDRSB:
	case ARM64_INS_LDRB: // ldr x6, [x6,0xf90]
		r_strbuf_setf (&op->esil, "%s,%d,+,[1],%s,=",
			MEMBASE64(1), MEMDISP64(1), REG64(0));
		break;
	case ARM64_INS_TST: // cmp w8, 0xd
	case ARM64_INS_CMP: // cmp w8, 0xd
		// update esil, cpu flags
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,==,%%z,=",
			IMM64(1), REG64(0));
		break;
	case ARM64_INS_FCSEL:
	case ARM64_INS_CSEL: // CSEL w8, w13, w14, eq
		// TODO: w8 = eq? w13: w14
		// COND64(4) { ARM64_CC_EQ, NE, HS, ...
		r_strbuf_setf (&op->esil, "%%z,?{,%s,}{,%s,},%s,=",
			REG64(1), REG64(2), REG64(0));
		break;
	case ARM64_INS_STRB:
		r_strbuf_setf (&op->esil, "%s,%s,%"PFMT64d",+,=[1]",
			REG64(0), MEMBASE64(1), MEMDISP64(1));
	case ARM64_INS_STR: // str x6, [x6,0xf90]
	case ARM64_INS_STRH:
		r_strbuf_setf (&op->esil, "%s,%s,%"PFMT64d",+,=[]",
			REG64(0), MEMBASE64(1), MEMDISP64(1));
		break;
	case ARM64_INS_CBZ:
		r_strbuf_setf (&op->esil, "%s,?{,%"PFMT64d",pc,=,}",
			REG64(0), IMM64(1));
		break;
	case ARM64_INS_CBNZ:
		r_strbuf_setf (&op->esil, "%s,!,?{,%"PFMT64d",pc,=,}",
			REG64(0), IMM64(1));
		break;
	case ARM64_INS_TBZ:
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		r_strbuf_setf (&op->esil, "%d,1,<<=,%s,&,!,?{,%"PFMT64d",pc,=,}",
			IMM64(1), REG64(0), IMM64(2));
		break;
	case ARM64_INS_TBNZ:
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		r_strbuf_setf (&op->esil, "%d,1,<<=,%s,&,?{,%"PFMT64d",pc,=,}",
			IMM64(1), REG64(0), IMM64(2));
		break;
	case ARM64_INS_STP: // str x6, x7, [x6,0xf90]
		{
		int disp = (int)MEMDISP64(2);
		char sign = disp>=0?'+':'-';
		ut64 abs = disp>=0? MEMDISP64(2): -MEMDISP64(2);
		r_strbuf_setf (&op->esil, 
			"%s,%s,%"PFMT64d",%c,=[],"
			"%s,%s,%"PFMT64d",%c,%d,+,=[]",
			REG64(0), MEMBASE64(2), abs, sign, 
			REG64(1), MEMBASE64(2), abs, sign, 8);
		}
		break;
	case ARM64_INS_LDP: // ldp x29, x30, [sp], 0x10
		{
		int disp = (int)MEMDISP64(2);
		char sign = disp>=0?'+':'-';
		ut64 abs = disp>=0? MEMDISP64(2): -MEMDISP64(2);
		r_strbuf_setf (&op->esil, 
			"%s,%s,%"PFMT64d",%c,=[],"
			"%s,%s,%"PFMT64d",%c,%d,+,=[]",
			REG64(0), MEMBASE64(2), abs, sign, 
			REG64(1), MEMBASE64(2), abs, sign, 8);
		}
		break;
	case ARM64_INS_ADRP:
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,=", IMM64 (1), REG64 (0));
		break;
	case ARM64_INS_MOV:
		r_strbuf_setf (&op->esil, "%s,%s,=", REG64 (1), REG64 (0));
		break;
	case ARM64_INS_MOVK: // movk w8, 0x1290
		// XXX: wrongly implemented
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,=", IMM64 (1), REG64 (0));
		break;
	case ARM64_INS_MOVZ:
		// XXX: wrongly implemented
		r_strbuf_setf (&op->esil, "%d,%s,=", IMM64 (1), REG64 (0));
		break;
	case ARM64_INS_RET:
		r_strbuf_setf (&op->esil, "lr,pc,=");
		break;
	}
	return 0;
}

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
#if 0
PUSH { r4, r5, r6, r7, lr }
4,sp,-=,lr,sp,=[4],
4,sp,-=,r7,sp,=[4],
4,sp,-=,r6,sp,=[4],
4,sp,-=,r5,sp,=[4],
4,sp,-=,r4,sp,=[4]

20,sp,-=,r4,r5,r6,r7,lr,5,sp,=[*]
#endif
		r_strbuf_setf (&op->esil, "%d,sp,-=,",
			4 * insn->detail->arm.op_count);
		for (i=0; i<insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,", REG (i));
		}
		r_strbuf_appendf (&op->esil, "%d,sp,=[*]",
			insn->detail->arm.op_count);
		break;
	case ARM_INS_STM:
		r_strbuf_setf (&op->esil, "");
		for (i=1; i<insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,%s,%d,+,=[4],",
				REG (i), ARG (0), i*4);
		}
		break;
	case ARM_INS_POP:
#if 0
POP { r4,r5, r6}
r4,r5,r6,3,sp,[*],12,sp,+=
#endif
		r_strbuf_setf (&op->esil, "");
		for (i=0; i<insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,", REG (i));
		}
		r_strbuf_appendf (&op->esil, "%d,sp,[*],",
			insn->detail->arm.op_count);
		r_strbuf_appendf (&op->esil, "%d,sp,+=",
			4 * insn->detail->arm.op_count);
		break;
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
	case ARM_INS_MOVT:
		r_strbuf_appendf (&op->esil, "16,%s,<<,%s,|=", ARG(1), REG(0));
		break;
	case ARM_INS_MOV:
	case ARM_INS_VMOV:
	case ARM_INS_MOVW:
		r_strbuf_appendf (&op->esil, "%s,%s,=", ARG(1), REG(0));
		break;
	case ARM_INS_SSUB16:
	case ARM_INS_SSUB8:
	case ARM_INS_SUB:
		if (!strcmp (ARG(2), "")) {
			if (!strcmp (ARG(0), ARG(1))) {
				r_strbuf_appendf (&op->esil, "0,%s,=", ARG(0));
			} else {
				r_strbuf_appendf (&op->esil, "%s,%s,-=",
					ARG(1), ARG(0));
			}
		} else {
			if (!strcmp (ARG(0), ARG(1))) {
				r_strbuf_appendf (&op->esil, "%s,%s,-=", ARG(2), ARG(0));
			} else {
				r_strbuf_appendf (&op->esil, "%s,%s,-,%s,=",
					ARG(2), ARG(1), ARG(0));
			}
		}
		break;
	case ARM_INS_SADD16:
	case ARM_INS_SADD8:
	case ARM_INS_ADD:
		if (!strcmp (ARG(2), "")) {
			if (!strcmp (ARG(0), ARG(1))) {
				r_strbuf_appendf (&op->esil, "2,%s,*=", ARG(0));
			} else {
				r_strbuf_appendf (&op->esil, "%s,%s,+=", ARG(1), ARG(0));
			}
		} else {
			if (!strcmp (ARG(0),ARG(1))) {
				r_strbuf_appendf (&op->esil, "%s,%s,+=", ARG(2), ARG(0));
			} else if (!strcmp (ARG(2),"0")) {
				r_strbuf_appendf (&op->esil, "%s,%s,=", ARG(1), ARG(0));
			} else {
				r_strbuf_appendf (&op->esil, "%s,%s,+,%s,=", ARG(2), ARG(1), ARG(0));
			}
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
	case ARM_INS_LDRD:
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
	case ARM64_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case ARM64_INS_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case ARM64_INS_ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case ARM64_INS_CSEL:
	case ARM64_INS_FCSEL:
		op->type = R_ANAL_OP_TYPE_CMOV;
		break;
	case ARM64_INS_MOV:
	case ARM64_INS_MOVI:
	case ARM64_INS_MOVK:
	case ARM64_INS_MOVN:
	case ARM64_INS_SMOV:
	case ARM64_INS_UMOV:
	case ARM64_INS_FMOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM64_INS_MOVZ:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 8;
		break;
	case ARM64_INS_UXTB:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 4;
		break;
	case ARM64_INS_UXTH:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 2;
		break;
	case ARM64_INS_CMP:
	case ARM64_INS_TST:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case ARM64_INS_ROR:
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case ARM64_INS_ORR:
	case ARM64_INS_ORN:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case ARM64_INS_EOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case ARM64_INS_LSL:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case ARM64_INS_ASR:
	case ARM64_INS_LSR:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case ARM64_INS_STRB:
	case ARM64_INS_STR:
		op->type = R_ANAL_OP_TYPE_STORE;
		if (REGBASE64(1) == ARM64_REG_X29) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = -MEMDISP64(1);
		}
		break;
	case ARM64_INS_LDR:
	case ARM64_INS_LDRB:
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (REGBASE64(1) == ARM64_REG_X29) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = MEMDISP64(1);
		}
		break;
	case ARM64_INS_RET:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case ARM64_INS_BL: // bl 0x89480
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = IMM64(0);
		break;
	case ARM64_INS_BLR: // blr x0
		op->type = R_ANAL_OP_TYPE_UCALL;
		//op->jump = IMM64(0);
		break;
	case ARM64_INS_CBZ:
	case ARM64_INS_CBNZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = IMM64(1);
		op->fail = addr+op->size;
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
	case ARM_INS_IT:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + insn->size;
		op->fail = addr + insn->size + 2;
			// XXX what if instruction is 4
		break;
	case ARM_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case ARM_INS_POP:
	case ARM_INS_FLDMDBX:
	case ARM_INS_FLDMIAX:
	case ARM_INS_LDMDA:
	case ARM_INS_LDMDB:
	case ARM_INS_LDMIB:
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
		if (ISREG(0)) {
			if (REGID(0) == ARM_REG_SP) {
// 0x00008254    10d04de2     sub sp, sp, 0x10
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = IMM (2);
			}
		}
		break;
	case ARM_INS_ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (REGID(1)==ARM_REG_PC) {
			op->ptr = addr + 8 + IMM(2);
			op->refptr = 0;
		}
		break;
	case ARM_INS_VMOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_FPU;
		break;
	case ARM_INS_MOV:
	case ARM_INS_MOVT:
	case ARM_INS_MOVW:
	case ARM_INS_VMOVL:
	case ARM_INS_VMOVN:
	case ARM_INS_VQMOVUN:
	case ARM_INS_VQMOVN:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM_INS_SVC:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case ARM_INS_AND:
		op->type = R_ANAL_OP_TYPE_AND;
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
		//case ARM_INS_POP:
	case ARM_INS_PUSH:
	case ARM_INS_STR:
		op->type = R_ANAL_OP_TYPE_STORE;
// 0x00008160    04202de5     str r2, [sp, -4]!
// 0x000082a0    28000be5     str r0, [fp, -0x28]
		if (REGBASE(1) == ARM_REG_FP) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = MEMDISP(1);
		}
		break;
	case ARM_INS_LDR:
	case ARM_INS_LDRD:
	case ARM_INS_LDRB:
	case ARM_INS_LDRBT:
	case ARM_INS_LDREX:
	case ARM_INS_LDREXB:
	case ARM_INS_LDREXD:
	case ARM_INS_LDREXH:
	case ARM_INS_LDRH:
	case ARM_INS_LDRHT:
	case ARM_INS_LDRSB:
	case ARM_INS_LDRSBT:
	case ARM_INS_LDRSH:
	case ARM_INS_LDRSHT:
	case ARM_INS_LDRT:
// 0x000082a8    28301be5     ldr r3, [fp, -0x28]
		if (insn->detail->arm.operands[0].reg == ARM_REG_PC) {
			op->type = R_ANAL_OP_TYPE_UJMP;
		} else {
			op->type = R_ANAL_OP_TYPE_LOAD;
		}
		if (REGBASE(1) == ARM_REG_FP) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = MEMDISP(1);
		}
		break;
	case ARM_INS_BL:
	case ARM_INS_BLX:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = IMM(0);
		break;
	case ARM_INS_CBZ:
	case ARM_INS_CBNZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = IMM(1);
		op->fail = addr+op->size;
		break;
	case ARM_INS_B:
	case ARM_INS_BX:
	case ARM_INS_BXJ:
		// BX LR == RET
		if (insn->detail->arm.operands[0].reg == ARM_REG_LR) {
			op->type = R_ANAL_OP_TYPE_RET;
		} else if (insn->detail->arm.cc) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			if (REGID(1)==ARM_REG_PC) {
				op->jump = addr+op->size;
			} else {
				op->jump = (ut64) (ut32)IMM(0);
			//	op->jump = addr+op->size;
			}
			op->fail = addr+op->size;
			if (op->jump == op->fail) {
				op->type = R_ANAL_OP_TYPE_JMP;
				op->fail = UT64_MAX;
			}
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
	op->stackop = R_ANAL_STACK_NULL;
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
				if (a->decode) {
					analop64_esil (a, op, addr, buf, len, &handle, insn);
				}
			} else {
				anop32 (op, insn);
				if (a->decode) {
					analop_esil (a, op, addr, buf, len, &handle, insn);
				}
			}
			cs_free (insn, n);
		}
		cs_close (&handle);
	}
	return op->size;
}

static int set_reg_profile(RAnal *anal) {
	const char *p;
	if (anal->bits == 64) {
		p = \
		"=pc	pc\n"
		"=sp	sp\n"
		"=bp	x29\n"
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
		"gpr	x27	.64	216	0\n"
		"gpr	x28	.64	224	0\n"
		"gpr	x29	.64	232	0\n"
		"gpr	x30	.64	240	0\n"
		"gpr	pc	.64	248	0\n"
		"gpr	pstate	.64	256	0\n"
		"gpr	ox0	.64	264	0\n"
		"gpr	snr	.64	272	0\n"
		// probably wrong
		"gpr	nf	.1	.256	0	sign\n" // msb bit of last op
		"gpr	zf	.1	.257	0	zero\n" // set if last op is 0
		"gpr	cf	.1	.258	0	carry\n" // set if last op carries
		"gpr	vf	.1	.515	0	overflow\n"; // set if overflows
	} else {
		p = \
		"=pc	r15\n"
		"=sp	r14\n" // XXX
		"=bp	fp\n" // XXX
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
		"gpr	r17	.32	68	0\n";
	}

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

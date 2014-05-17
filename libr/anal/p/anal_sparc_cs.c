/* radare2 - LGPL - Copyright 2014 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone.h>
#include <sparc.h>

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif
#if CS_API_MINOR < 1
#error Old Capstone not supported
#endif

#define esilprintf(op, fmt, arg...) r_strbuf_setf (&op->esil, fmt, ##arg)
#define INSOP(n) insn->detail->sparc.operands[n]

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	csh handle;
	cs_insn *insn;
	int mode, n, ret;
	mode = CS_MODE_BIG_ENDIAN;
	if (!strcmp (a->cpu, "v9"))
		mode |= CS_MODE_V9;
	ret = cs_open (CS_ARCH_SPARC, mode, &handle);
	op->type = R_ANAL_OP_TYPE_NULL;
	op->size = 0;
	op->delay = 0;
	r_strbuf_init (&op->esil);
	if (ret == CS_ERR_OK) {
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
		// capstone-next
		n = cs_disasm_ex (handle, (const ut8*)buf, len, addr, 1, &insn);
		if (n<1) {
			op->type = R_ANAL_OP_TYPE_ILL;
		} else {
			op->size = insn->size;
			switch (insn->id) {
			case SPARC_INS_RETT:
				op->type = R_ANAL_OP_TYPE_RET;
			case SPARC_INS_CALL:
				op->type = R_ANAL_OP_TYPE_CALL;
				op->jump = INSOP(0).imm;
				break;
			case SPARC_INS_CMP:
				op->type = R_ANAL_OP_TYPE_CMP;
				break;
			case SPARC_INS_JMP:
			case SPARC_INS_JMPL:
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = INSOP(0).imm;
				break;
			case SPARC_INS_BRGEZ:
			case SPARC_INS_BRGZ:
			case SPARC_INS_BRLEZ:
			case SPARC_INS_BRLZ:
			case SPARC_INS_BRNZ:
			case SPARC_INS_BRZ:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = INSOP(0).imm;
				op->fail = UT64_MAX;
				break;
			case SPARC_INS_FHSUBD:
			case SPARC_INS_FHSUBS:
			case SPARC_INS_FPSUB16:
			case SPARC_INS_FPSUB16S:
			case SPARC_INS_FPSUB32:
			case SPARC_INS_FPSUB32S:
			case SPARC_INS_FSUBD:
			case SPARC_INS_FSUBQ:
			case SPARC_INS_FSUBS:
			case SPARC_INS_SUBCC:
			case SPARC_INS_SUBX:
			case SPARC_INS_SUBXCC:
			case SPARC_INS_SUB:
			case SPARC_INS_TSUBCCTV:
			case SPARC_INS_TSUBCC:
				op->type = R_ANAL_OP_TYPE_SUB;
				break;
			case SPARC_INS_ADDCC:
			case SPARC_INS_ADDX:
			case SPARC_INS_ADDXCC:
			case SPARC_INS_ADDXC:
			case SPARC_INS_ADDXCCC:
			case SPARC_INS_ADD:
			case SPARC_INS_FADDD:
			case SPARC_INS_FADDQ:
			case SPARC_INS_FADDS:
			case SPARC_INS_FHADDD:
			case SPARC_INS_FHADDS:
			case SPARC_INS_FNADDD:
			case SPARC_INS_FNADDS:
			case SPARC_INS_FNHADDD:
			case SPARC_INS_FNHADDS:
			case SPARC_INS_FPADD16:
			case SPARC_INS_FPADD16S:
			case SPARC_INS_FPADD32:
			case SPARC_INS_FPADD32S:
			case SPARC_INS_FPADD64:
			case SPARC_INS_TADDCCTV:
			case SPARC_INS_TADDCC:
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			case SPARC_INS_FDMULQ:
			case SPARC_INS_FMUL8SUX16:
			case SPARC_INS_FMUL8ULX16:
			case SPARC_INS_FMUL8X16:
			case SPARC_INS_FMUL8X16AL:
			case SPARC_INS_FMUL8X16AU:
			case SPARC_INS_FMULD:
			case SPARC_INS_FMULD8SUX16:
			case SPARC_INS_FMULD8ULX16:
			case SPARC_INS_FMULQ:
			case SPARC_INS_FMULS:
			case SPARC_INS_FSMULD:
			case SPARC_INS_MULX:
			case SPARC_INS_SMULCC:
			case SPARC_INS_SMUL:
			case SPARC_INS_UMULCC:
			case SPARC_INS_UMULXHI:
			case SPARC_INS_UMUL:
			case SPARC_INS_XMULX:
			case SPARC_INS_XMULXHI:
				op->type = R_ANAL_OP_TYPE_MUL;
				break;
			case SPARC_INS_FDIVD:
			case SPARC_INS_FDIVQ:
			case SPARC_INS_FDIVS:
			case SPARC_INS_SDIVCC:
			case SPARC_INS_SDIVX:
			case SPARC_INS_SDIV:
			case SPARC_INS_UDIVCC:
			case SPARC_INS_UDIVX:
			case SPARC_INS_UDIV:
				op->type = R_ANAL_OP_TYPE_DIV;
				break;
			}

		}
		cs_free (insn, n);
		cs_close (&handle);
	}
	return op->size;
}

RAnalPlugin r_anal_plugin_sparc_cs = {
	.name = "sparc.cs",
	.desc = "Capstone SPARC analysis",
	.license = "BSD",
	.arch = R_SYS_ARCH_SPARC,
	.bits = 32|64,
	.op = &analop,
	//.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_sparc_cs
};
#endif

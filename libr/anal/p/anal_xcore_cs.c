/* radare2 - LGPL - Copyright 2014 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone.h>
#include <xcore.h>

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif

#define esilprintf(op, fmt, arg...) r_strbuf_setf (&op->esil, fmt, ##arg)
#define INSOP(n) insn->detail->xcore.operands[n]

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	csh handle;
	cs_insn *insn;
	int mode, n, ret;
	mode = CS_MODE_BIG_ENDIAN;
	if (!strcmp (a->cpu, "v9"))
		mode |= CS_MODE_V9;
	ret = cs_open (CS_ARCH_XCORE, mode, &handle);
	op->type = R_ANAL_OP_TYPE_NULL;
	op->size = 0;
	op->delay = 0;
	r_strbuf_init (&op->esil);
	if (ret == CS_ERR_OK) {
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
		// capstone-next
		n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
		if (n<1) {
			op->type = R_ANAL_OP_TYPE_ILL;
		} else {
			op->size = insn->size;
			switch (insn->id) {
			case XCORE_INS_DRET:
			case XCORE_INS_KRET:
			case XCORE_INS_RETSP:
				op->type = R_ANAL_OP_TYPE_RET;
				break;
			case XCORE_INS_DCALL:
			case XCORE_INS_KCALL:
			case XCORE_INS_ECALLF:
			case XCORE_INS_ECALLT:
				op->type = R_ANAL_OP_TYPE_CALL;
				op->jump = INSOP(0).imm;
				break;
			/* ??? */
			case XCORE_INS_BL:
			case XCORE_INS_BLA:
			case XCORE_INS_BLAT:
			case XCORE_INS_BT:
			case XCORE_INS_BF:
			case XCORE_INS_BU:
			case XCORE_INS_BRU:
				op->type = R_ANAL_OP_TYPE_CALL;
				op->jump = INSOP(0).imm;
				break;
			case XCORE_INS_SUB:
			case XCORE_INS_LSUB:
				op->type = R_ANAL_OP_TYPE_SUB;
				break;
			case XCORE_INS_ADD:
			case XCORE_INS_LADD:
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			}

		}
		cs_free (insn, n);
		cs_close (&handle);
	}
	return op->size;
}

RAnalPlugin r_anal_plugin_xcore_cs = {
	.name = "xcore",
	.desc = "Capstone XCORE analysis",
	.license = "BSD",
	.esil = R_TRUE,
	.arch = R_SYS_ARCH_XCORE,
	.bits = 32,
	.op = &analop,
	//.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_xcore_cs
};
#endif

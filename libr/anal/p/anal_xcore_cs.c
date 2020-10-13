/* radare2 - LGPL - Copyright 2014-2017 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone.h>
#include <xcore.h>

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif

#define esilprintf(op, fmt, ...) r_strbuf_setf (&op->esil, fmt, ##__VA_ARGS__)
#define INSOP(n) insn->detail->xcore.operands[n]

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	r_strbuf_init (buf);
	r_strbuf_append (buf, "{");
	cs_xcore *x = &insn->detail->xcore;
	r_strbuf_append (buf, "\"operands\":[");
	for (i = 0; i < x->op_count; i++) {
		cs_xcore_op *op = &x->operands[i];
		if (i > 0) {
			r_strbuf_append (buf, ",");
		}
		r_strbuf_append (buf, "{");
		switch (op->type) {
		case XCORE_OP_REG:
			r_strbuf_append (buf, "\"type\":\"reg\"");
			r_strbuf_appendf (buf, ",\"value\":\"%s\"", cs_reg_name (handle, op->reg));
			break;
		case XCORE_OP_IMM:
			r_strbuf_append (buf, "\"type\":\"imm\"");
			r_strbuf_appendf (buf, ",\"value\":%"PFMT64d, (st64)op->imm);
			break;
		case XCORE_OP_MEM:
			r_strbuf_append (buf, "\"type\":\"mem\"");
			if (op->mem.base != XCORE_REG_INVALID) {
				r_strbuf_appendf (buf, ",\"base\":\"%s\"", cs_reg_name (handle, op->mem.base));
			}
			r_strbuf_appendf (buf, ",\"disp\":%"PFMT64d"", (st64)op->mem.disp);
			break;
		default:
			r_strbuf_append (buf, "\"type\":\"invalid\"");
			break;
		}
		r_strbuf_append (buf, "}");
	}
	r_strbuf_append (buf, "]");
	r_strbuf_append (buf, "}");
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	static csh handle = 0;
	static int omode = 0;
	cs_insn *insn;
	int mode, n, ret;
	mode = CS_MODE_BIG_ENDIAN;
	if (!strcmp (a->cpu, "v9")) {
		mode |= CS_MODE_V9;
	}
	if (mode != omode) {
		if (handle) {
			cs_close (&handle);
			handle = 0;
		}
		omode = mode;
	}
	if (handle == 0) {
		ret = cs_open (CS_ARCH_XCORE, mode, &handle);
		if (ret != CS_ERR_OK) {
			return -1;
		}
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	}
	// capstone-next
	n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else {
		if (mask & R_ANAL_OP_MASK_OPEX) {
			opex (&op->opex, handle, insn);
		}
		op->size = insn->size;
		op->id = insn->id;
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
		cs_free (insn, n);
	}
	//	cs_close (&handle);
	return op->size;
}

RAnalPlugin r_anal_plugin_xcore_cs = {
	.name = "xcore",
	.desc = "Capstone XCORE analysis",
	.license = "BSD",
	.esil = false,
	.arch = "xcore",
	.bits = 32,
	.op = &analop,
	//.set_reg_profile = &set_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_xcore_cs,
	.version = R2_VERSION
};
#endif

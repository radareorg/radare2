/* radare2 - LGPL - Copyright 2014-2017 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include <capstone/systemz.h>
// instruction set: http://www.tachyonsoft.com/inst390m.htm

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif

#define esilprintf(op, fmt, ...) r_strbuf_setf (&op->esil, fmt, ##__VA_ARGS__)
#define INSOP(n) insn->detail->sysz.operands[n]

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	r_strbuf_init (buf);
	r_strbuf_append (buf, "{");
	cs_ppc *x = &insn->detail->ppc;
	r_strbuf_append (buf, "\"operands\":[");
	for (i = 0; i < x->op_count; i++) {
		cs_ppc_op *op = &x->operands[i];
		if (i > 0) {
			r_strbuf_append (buf, ",");
		}
		r_strbuf_append (buf, "{");
		switch (op->type) {
		case PPC_OP_REG:
			r_strbuf_append (buf, "\"type\":\"reg\"");
			r_strbuf_appendf (buf, ",\"value\":\"%s\"", cs_reg_name (handle, op->reg));
			break;
		case PPC_OP_IMM:
			r_strbuf_append (buf, "\"type\":\"imm\"");
			r_strbuf_appendf (buf, ",\"value\":%"PFMT64d, op->imm);
			break;
		case PPC_OP_MEM:
			r_strbuf_append (buf, "\"type\":\"mem\"");
			if (op->mem.base != PPC_REG_INVALID) {
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
	r_strbuf_append (buf, "]}");
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	csh handle;
	cs_insn *insn;
	int mode, n, ret;
	mode = CS_MODE_BIG_ENDIAN;
	ret = cs_open (CS_ARCH_SYSZ, mode, &handle);
	op->type = R_ANAL_OP_TYPE_NULL;
	op->size = 0;
	op->delay = 0;
	r_strbuf_init (&op->esil);
	if (ret == CS_ERR_OK) {
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
		// capstone-next
		n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
		if (n < 1) {
			op->type = R_ANAL_OP_TYPE_ILL;
		} else {
			opex (&op->opex, handle, insn);
			op->size = insn->size;
			switch (insn->id) {
			case SYSZ_INS_BRCL:
			case SYSZ_INS_BRASL:
				op->type = R_ANAL_OP_TYPE_CALL;
				break;
			case SYSZ_INS_BR:
				op->type = R_ANAL_OP_TYPE_JMP;
				break;
			case SYSZ_INS_BRC:
			case SYSZ_INS_BER:
			case SYSZ_INS_BHR:
			case SYSZ_INS_BHER:
			case SYSZ_INS_BLR:
			case SYSZ_INS_BLER:
			case SYSZ_INS_BLHR:
			case SYSZ_INS_BNER:
			case SYSZ_INS_BNHR:
			case SYSZ_INS_BNHER:
			case SYSZ_INS_BNLR:
			case SYSZ_INS_BNLER:
			case SYSZ_INS_BNLHR:
			case SYSZ_INS_BNOR:
			case SYSZ_INS_BOR:
			case SYSZ_INS_BASR:
			case SYSZ_INS_BRAS:
			case SYSZ_INS_BRCT:
			case SYSZ_INS_BRCTG:
				op->type = R_ANAL_OP_TYPE_CJMP;
				break;
			case SYSZ_INS_JE:
			case SYSZ_INS_JGE:
			case SYSZ_INS_JHE:
			case SYSZ_INS_JGHE:
			case SYSZ_INS_JH:
			case SYSZ_INS_JGH:
			case SYSZ_INS_JLE:
			case SYSZ_INS_JGLE:
			case SYSZ_INS_JLH:
			case SYSZ_INS_JGLH:
			case SYSZ_INS_JL:
			case SYSZ_INS_JGL:
			case SYSZ_INS_JNE:
			case SYSZ_INS_JGNE:
			case SYSZ_INS_JNHE:
			case SYSZ_INS_JGNHE:
			case SYSZ_INS_JNH:
			case SYSZ_INS_JGNH:
			case SYSZ_INS_JNLE:
			case SYSZ_INS_JGNLE:
			case SYSZ_INS_JNLH:
			case SYSZ_INS_JGNLH:
			case SYSZ_INS_JNL:
			case SYSZ_INS_JGNL:
			case SYSZ_INS_JNO:
			case SYSZ_INS_JGNO:
			case SYSZ_INS_JO:
			case SYSZ_INS_JGO:
			case SYSZ_INS_JG:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = INSOP(0).imm;
				op->fail = addr+op->size;
				break;
			case SYSZ_INS_J:
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = INSOP(0).imm;
				op->fail = UT64_MAX;
				break;
			}
		}
		cs_free (insn, n);
		cs_close (&handle);
	}
	return op->size;
}

RAnalPlugin r_anal_plugin_sysz = {
	.name = "systemz.cs",
	.desc = "Capstone SystemZ microanalysis",
	.esil = false,
	.license = "BSD",
	.arch = "sysz",
	.bits = 32|64,
	.op = &analop,
	//.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_sysz,
	.version = R2_VERSION
};
#endif

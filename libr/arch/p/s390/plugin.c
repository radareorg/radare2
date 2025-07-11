/* radare2 - LGPL - Copyright 2014-2023 - pancake */

#include <r_arch.h>
#include <r_lib.h>
#define CAPSTONE_SYSTEMZ_COMPAT_HEADER
#include <capstone/capstone.h>
#include <capstone/systemz.h>
// instruction set: https://www.tachyonsoft.com/inst390m.htm

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif

#define INSOP(n) insn->detail->sysz.operands[n]

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	cs_sysz *x = &insn->detail->sysz;
	for (i = 0; i < x->op_count; i++) {
		cs_sysz_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case SYSZ_OP_REG:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", cs_reg_name (handle, op->reg));
			break;
		case SYSZ_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_kN (pj, "value", op->imm);
			break;
		case SYSZ_OP_MEM:
			pj_ks (pj, "type", "mem");
			if (op->mem.base != SYSZ_REG_INVALID) {
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

#define CSINC SYSZ
#define CSINC_MODE CS_MODE_BIG_ENDIAN
#include "../capstone.inc.c"

static char *mnemonics(RArchSession *s, int id, bool json) {
	CapstonePluginData *cpd = (CapstonePluginData*)s->data;
	return r_arch_cs_mnemonics (s, cpd->cs_handle, id, json);
}

static bool init(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	if (s->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	s->data = R_NEW0 (CapstonePluginData);
	CapstonePluginData *cpd = (CapstonePluginData*)s->data;
	if (!r_arch_cs_init (s, &cpd->cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (s->data);
		return false;
	}
	return true;
}

static bool decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	CapstonePluginData *cpd = (CapstonePluginData*)a->data;
// static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	const ut8 *buf = op->bytes;
	size_t len = op->size;
	ut64 addr = op->addr;

	cs_insn *insn = NULL;
	op->addr = addr;

	int n = cs_disasm (cpd->cs_handle, (const ut8*)buf, len, addr, 1, &insn);
	if (n < 1) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		op->size = 1;
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}
	if (mask & R_ARCH_OP_MASK_OPEX) {
		opex (&op->opex, cpd->cs_handle, insn);
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = r_str_newf ("%s%s%s",
				insn->mnemonic, insn->op_str[0]? " ": "",
				insn->op_str);
		// if syntax is not AT&T
		if (a->config->syntax != R_ARCH_SYNTAX_ATT) {
			op->mnemonic = r_str_replace (op->mnemonic, "%", "", -1);
		}
	}
	op->size = insn->size;
	if (op->size > 1 && !memcmp (buf, "\x07\x07", 2)) {
		// bcr 0, r7 -> used for padding
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 2;
		return false;
	}
	switch (insn->id) {
#if CS_API_MAJOR >= 5
	case SYSZ_INS_SVC:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case SYSZ_INS_STM:
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case SYSZ_INS_BASR:
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case SYSZ_INS_BALR:
		op->type = R_ANAL_OP_TYPE_RCALL;
		//op->jump = INSOP (0).imm;
		op->fail = addr + op->size;
		break;
	case SYSZ_INS_B: // "b 1(r15)"
		op->type = R_ANAL_OP_TYPE_UJMP;
		op->jump = addr + r_num_get (NULL, insn->op_str);
		break;
#endif
	case SYSZ_INS_BRCL:
	case SYSZ_INS_BRASL:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = INSOP (1).imm;
		break;
	case SYSZ_INS_LDR:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case SYSZ_INS_L:
	case SYSZ_INS_LR:
	case SYSZ_INS_LA:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case SYSZ_INS_ST:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case SYSZ_INS_BR:
		op->type = R_ANAL_OP_TYPE_RJMP;
		break;
	case SYSZ_INS_NGR:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case SYSZ_INS_AGR:
	case SYSZ_INS_AGHI:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case SYSZ_INS_SGR:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case SYSZ_INS_SRAG:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case SYSZ_INS_SRLG:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case SYSZ_INS_XC:
	case SYSZ_INS_XG:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case SYSZ_INS_STMG:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case SYSZ_INS_BCR:
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case SYSZ_INS_LARL: // absolute
	case SYSZ_INS_LGRL: // relative
		// Load Address Relative Long
		op->type = R_ANAL_OP_TYPE_LEA;
		op->ptr = INSOP (1).imm;
		break;
#if CS_VERSION_MAJOR >= 5
	case SYSZ_INS_LAT: // lai
		op->type = R_ANAL_OP_TYPE_LEA;
		break;
#endif
	case SYSZ_INS_CLI:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case SYSZ_INS_LHI:
	case SYSZ_INS_LMG:
	case SYSZ_INS_MVI:
	case SYSZ_INS_LPGR:
	case SYSZ_INS_LLCR:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
#if CS_VERSION_MAJOR >= 5
	case SYSZ_INS_RISBGN:
#endif
	case SYSZ_INS_RISBG:
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case SYSZ_INS_ICY:
	case SYSZ_INS_STC:
		op->type = R_ANAL_OP_TYPE_STORE;
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
	case SYSZ_INS_BRAS:
	case SYSZ_INS_BRCT:
	case SYSZ_INS_BRCTG:
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case SYSZ_INS_CLRJLE:
	// case SYSZ_INS_CLRJGE:
	case SYSZ_INS_CLRJE:
	case SYSZ_INS_CLRJNE:
	case SYSZ_INS_CLRJNLE:
	case SYSZ_INS_CLRJNLH:
	case SYSZ_INS_CLRJHE:
	case SYSZ_INS_CLRJL:
	case SYSZ_INS_CLRJLH:
	case SYSZ_INS_CLGIJLE:
	case SYSZ_INS_CLGIJH:
	case SYSZ_INS_CGIJE:
	case SYSZ_INS_CGRJE:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = INSOP (2).imm;
		op->fail = addr + op->size;
		break;
	case SYSZ_INS_JE:
#if CS_NEXT_VERSION < 6
	case SYSZ_INS_JGE:
	case SYSZ_INS_JGHE:
	case SYSZ_INS_JGH:
	case SYSZ_INS_JGLE:
	case SYSZ_INS_JGLH:
	case SYSZ_INS_JGL:
	case SYSZ_INS_JGNE:
	case SYSZ_INS_JGNHE:
	case SYSZ_INS_JGNH:
	case SYSZ_INS_JGNLE:
	case SYSZ_INS_JGNLH:
	case SYSZ_INS_JGNL:
	case SYSZ_INS_JGNO:
	case SYSZ_INS_JGO:
	case SYSZ_INS_JG:
#endif
	case SYSZ_INS_JHE:
	case SYSZ_INS_JH:
	case SYSZ_INS_JLE:
	case SYSZ_INS_JLH:
	case SYSZ_INS_JL:
	case SYSZ_INS_JNE:
	case SYSZ_INS_JNHE:
	case SYSZ_INS_JNH:
	case SYSZ_INS_JNLE:
	case SYSZ_INS_JNLH:
	case SYSZ_INS_JNL:
	case SYSZ_INS_JNO:
	case SYSZ_INS_JO:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = INSOP (0).imm;
		op->fail = addr + op->size;
		break;
	case SYSZ_INS_XI:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case SYSZ_INS_OI:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case SYSZ_INS_J:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = INSOP (0).imm;
		op->fail = UT64_MAX;
		break;
	}
	cs_free (insn, n);
	return op->size > 1;
}

static char *regs(RArchSession *as) {
	const char p[] =
		"=PC	r15\n"
		"=LR	r14\n"
		"=SP	r13\n"
		"=BP	r12\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=SN	r0\n"
		"gpr	sb	.32	36	0\n" // r9
		"gpr	sl	.32	40	0\n" // rl0
		"gpr	fp	.32	44	0\n" // r11
		"gpr	ip	.32	48	0\n" // r12
		"gpr	sp	.32	52	0\n" // r13
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
	;
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_DATA_ALIGN:
	case R_ARCH_INFO_CODE_ALIGN:
		return 1;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 6;
	case R_ARCH_INFO_MINOP_SIZE:
		return 2;
	}
	return 2;
}

static bool fini(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	CapstonePluginData *cpd = (CapstonePluginData*)s->data;
	cs_close (&cpd->cs_handle);
	R_FREE (s->data);
	return true;
}

static RList *preludes(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->config, NULL);
	RList *l = r_list_newf (free);
	r_list_append (l, strdup ("c010000104")); // imports -- some false positives
	r_list_append (l, strdup ("eb6ff03000")); // stgm
	return l;
}

const RArchPlugin r_arch_plugin_s390_cs = {
	.meta = {
		.name = "s390",
		.desc = "IBM s390 - SystemZ (capstone)",
		.author = "pancake",
		.license = "Apache-2.0",
	},
	.arch = "s390",
	.bits = R_SYS_BITS_PACK2 (32, 64), // it's actually 31
	.decode = decode,
	.info = archinfo,
	.regs = regs,
	.preludes = preludes,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_s390_cs,
	.version = R2_VERSION
};
#endif

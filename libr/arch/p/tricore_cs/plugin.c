/* radare2 - LGPL - Copyright 2023 - pancake */

#include <r_arch.h>
#include <r_lib.h>
#include <capstone/capstone.h>

#if CS_API_MAJOR < 5
const RArchPlugin r_arch_plugin_tricore_cs = {
	0
};
#else

#define INSOP(n) insn->detail->sh.operands[n]

#define CSINC TRICORE
#define CSINC_MODE 0
	// CS_MODE_BIG_ENDIAN
#include "../capstone.inc.c"

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
#if 0
	int i;
	cs_sh *x = &insn->detail->sh;
	for (i = 0; i < x->op_count; i++) {
		cs_tricore_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case TRICORE_OP_REG:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", cs_reg_name (handle, op->reg));
			break;
		case TRICORE_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_ki (pj, "value", op->imm);
			break;
		case TRICORE_OP_MEM:
			pj_ks (pj, "type", "mem");
			pj_ki (pj, "disp", op->mem.disp);
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		pj_end (pj); /* o operand */
	}
#endif
	pj_end (pj); /* a operands */
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}

static csh cs_handle_for_session(RArchSession *as) {
	r_return_val_if_fail (as && as->data, 0);
	CapstonePluginData *pd = as->data;
	return pd->cs_handle;
}

static ut64 imm(cs_insn *insn, int n) {
	if (n < insn->detail->tricore.op_count) {
		struct cs_tricore_op *o = &insn->detail->tricore.operands[n];
		if (o->type == TRICORE_OP_IMM) {
			return (ut64)(o->imm & UT32_MAX); // its int32
		}
	}
	return UT64_MAX;
}

static bool decode(RArchSession *as, RAnalOp *op, RAnalOpMask mask) {
	const ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;

	csh handle = cs_handle_for_session (as);
	if (handle == 0) {
		return false;
	}
	op->size = 2;
	cs_insn *insn;
	int n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
	} else {
		if (mask & R_ARCH_OP_MASK_OPEX) {
			opex (&op->opex, handle, insn);
		}
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = r_str_newf ("%s%s%s",
				insn->mnemonic, insn->op_str[0]? " ": "",
				insn->op_str);
		}
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
		case TRICORE_INS_LOOP:
		case TRICORE_INS_LOOPU:
			op->jump = op->addr + (int)imm (insn, 1);
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case TRICORE_INS_J:
		case TRICORE_INS_JA:
			op->jump = imm (insn, 0);
			op->type = R_ANAL_OP_TYPE_JMP;
			break;
		case TRICORE_INS_JEQ_A:
		case TRICORE_INS_JEQ:
		case TRICORE_INS_JGEZ:
		case TRICORE_INS_JGE_U:
		case TRICORE_INS_JGE:
		case TRICORE_INS_JGTZ:
		case TRICORE_INS_JI:
		case TRICORE_INS_JLA:
		case TRICORE_INS_JLEZ:
		case TRICORE_INS_JLI:
		case TRICORE_INS_JLTZ:
		case TRICORE_INS_JLT_U:
		case TRICORE_INS_JLT:
		case TRICORE_INS_JL:
		case TRICORE_INS_JNED:
		case TRICORE_INS_JNEI:
		case TRICORE_INS_JNE_A:
		case TRICORE_INS_JNE:
		case TRICORE_INS_JNZ_A:
		case TRICORE_INS_JNZ_T:
		case TRICORE_INS_JNZ:
		case TRICORE_INS_JZ_A:
		case TRICORE_INS_JZ_T:
		case TRICORE_INS_JZ:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = imm (insn, 2);
			op->fail = op->addr + op->size;
			break;
		case TRICORE_INS_RET:
		case TRICORE_INS_RFE:
		case TRICORE_INS_RFM:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case TRICORE_INS_NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case TRICORE_INS_DIV_F:
		case TRICORE_INS_DIV_U:
		case TRICORE_INS_DIV:
			op->type = R_ANAL_OP_TYPE_DIV;
			break;
		case TRICORE_INS_MAX:
		case TRICORE_INS_MIN_B:
		case TRICORE_INS_MIN_BU:
		case TRICORE_INS_MIN_H:
		case TRICORE_INS_MIN_HU:
		case TRICORE_INS_MIN_U:
		case TRICORE_INS_MIN:
		case TRICORE_INS_CMPSWAP_W:
		case TRICORE_INS_CMP_F:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case TRICORE_INS_NOT:
			op->type = R_ANAL_OP_TYPE_NOT;
			break;
		case TRICORE_INS_MADD:
		case TRICORE_INS_CADD:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case TRICORE_INS_SUBS:
		case TRICORE_INS_SUBX:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case TRICORE_INS_SYSCALL:
			op->type = R_ANAL_OP_TYPE_SWI;
			break;
		case TRICORE_INS_LD_A:
		case TRICORE_INS_LD_BU:
		case TRICORE_INS_LD_B:
		case TRICORE_INS_LD_DA:
		case TRICORE_INS_LD_D:
		case TRICORE_INS_LD_HU:
		case TRICORE_INS_LD_H:
		case TRICORE_INS_LD_Q:
		case TRICORE_INS_LD_W:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case TRICORE_INS_ST_A:
		case TRICORE_INS_ST_B:
		case TRICORE_INS_ST_W:
		case TRICORE_INS_ST_Q:
		case TRICORE_INS_ST_DA:
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case TRICORE_INS_ADD:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case TRICORE_INS_XOR:
		case TRICORE_INS_XOR_NE: // TODO: CXOR
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case TRICORE_INS_CMOVN:
		case TRICORE_INS_CMOV:
			op->type = R_ANAL_OP_TYPE_CMOV;
			break;
		case TRICORE_INS_MOV:
		case TRICORE_INS_SWAP_A:
		case TRICORE_INS_SWAP_W:
		case TRICORE_INS_MOV_AA:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TRICORE_INS_INVALID:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		}
		cs_free (insn, n);
	}
	return op->size > 0;
}

static int archinfo(RArchSession *as, ut32 q) {
	if (q == R_ANAL_ARCHINFO_DATA_ALIGN) {
		return 2;
	}
	if (q == R_ANAL_ARCHINFO_ALIGN) {
		return 2;
	}
	if (q == R_ANAL_ARCHINFO_INV_OP_SIZE) {
		return 2;
	}
	if (q == R_ANAL_ARCHINFO_MAX_OP_SIZE) {
		return 4;
	}
	if (q == R_ANAL_ARCHINFO_MIN_OP_SIZE) {
		return 2;
	}
	return 4; // XXX
}

static char *mnemonics(RArchSession *as, int id, bool json) {
	CapstonePluginData *cpd = as->data;
	return r_arch_cs_mnemonics (as, cpd->cs_handle, id, json);
}

static bool init(RArchSession *as) {
	r_return_val_if_fail (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	as->data = R_NEW0 (CapstonePluginData);
	CapstonePluginData *cpd = (CapstonePluginData*)as->data;
	if (!r_arch_cs_init (as, &cpd->cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (as->data);
		return false;
	}
	return true;
}

static bool fini(RArchSession *as) {
	r_return_val_if_fail (as, false);
	CapstonePluginData *cpd = as->data;
	cs_close (&cpd->cs_handle);
	R_FREE (as->data);
	return true;
}

static char *regs(RArchSession *as) {
	const char *p =
		"=PC	pc\n"
		"=SP	a10\n"
		"=A0	a0\n"
		"gpr	p0	.64	0	0\n"
		"gpr	a0	.32	0	0\n"
		"gpr	a1	.32	4	0\n"
		"gpr	p2	.64	8	0\n"
		"gpr	a2	.32	8	0\n"
		"gpr	a3	.32	12	0\n"
		"gpr	p4	.64	16	0\n"
		"gpr	a4	.32	16	0\n"
		"gpr	a5	.32	20	0\n"
		"gpr	p6	.64	24	0\n"
		"gpr	a6	.32	24	0\n"
		"gpr	a7	.32	28	0\n"
		"gpr	p8	.64	32	0\n"
		"gpr	a8	.32	32	0\n"
		"gpr	a9	.32	36	0\n"
		"gpr	p10	.64	40	0\n"
		"gpr	a10	.32	40	0\n"
		"gpr	a11	.32	44	0\n"
		"gpr	p12	.64	48	0\n"
		"gpr	a12	.32	48	0\n"
		"gpr	a13	.32	52	0\n"
		"gpr	p14	.64	56	0\n"
		"gpr	a14	.32	56	0\n"
		"gpr	a15	.32	60	0\n"
		"gpr	e0	.64	64	0\n"
		"gpr	d0	.32	64	0\n"
		"gpr	d1	.32	68	0\n"
		"gpr	e2	.64	72	0\n"
		"gpr	d2	.32	72	0\n"
		"gpr	d3	.32	76	0\n"
		"gpr	e4	.64	80	0\n"
		"gpr	d4	.32	80	0\n"
		"gpr	d5	.32	84	0\n"
		"gpr	e6	.64	88	0\n"
		"gpr	d6	.32	88	0\n"
		"gpr	d7	.32	92	0\n"
		"gpr	e8	.64	96	0\n"
		"gpr	d8	.32	96	0\n"
		"gpr	d9	.32	100	0\n"
		"gpr	e10	.64	104	0\n"
		"gpr	d10	.32	104	0\n"
		"gpr	d11	.32	108	0\n"
		"gpr	e12	.64	112	0\n"
		"gpr	d12	.32	112	0\n"
		"gpr	d13	.32	114	0\n"
		"gpr	e14	.64	118	0\n"
		"gpr	d14	.32	118	0\n"
		"gpr	d15	.32	120	0\n"
		"gpr	PSW	.32	124	0\n"
		"gpr	PCXI	.32	128	0\n"
		"gpr	FCX	.32	132	0\n"
		"gpr	LCX	.32	136	0\n"
		"gpr	ISP	.32	140	0\n"
		"gpr	ICR	.32	144	0\n"
		"gpr	PIPN	.32	148	0\n"
		"gpr	BIV	.32	152	0\n"
		"gpr	BTV	.32	156	0\n"
		"gpr	pc	.32	160	0\n";
	return strdup (p);
}

const RArchPlugin r_arch_plugin_tricore_cs = {
	.meta = {
		.name = "tricore.cs",
		.desc = "Capstone TriCore analysis",
		.license = "BSD",
	},
	.endian = R_SYS_ENDIAN_LITTLE,
	.arch = "tricore",
	.bits = R_SYS_BITS_PACK1 (32),
	.decode = decode,
	.info = archinfo,
	.regs = regs,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini,
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_tricore_cs,
	.version = R2_VERSION
};
#endif

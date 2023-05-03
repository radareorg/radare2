/* radare2 - LGPL - Copyright 2023 - pancake */

#include <r_arch.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include <capstone/tricore.h>

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif

#define INSOP(n) insn->detail->sh.operands[n]

#define CSINC TRICORE
#define CSINC_MODE 0
	// CS_MODE_BIG_ENDIAN
#include "../capstone.inc"

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

RArchPlugin r_arch_plugin_tricore_cs = {
	.name = "tricore.cs",
	.desc = "Capstone TriCore analysis",
	.endian = R_SYS_ENDIAN_LITTLE,
	.license = "BSD",
	.arch = "tricore",
	.bits = R_SYS_BITS_PACK1 (32),
	.decode = decode,
	.info = archinfo,
	.regs = regs,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_tricore_cs,
	.version = R2_VERSION
};
#endif

/* radare2 - LGPL - Copyright 2014-2024 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include <capstone/sparc.h>

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif

#define INSOP(n) insn->detail->sparc.operands[n]
#define INSCC insn->detail->sparc.cc

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	cs_sparc *x = &insn->detail->sparc;
	for (i = 0; i < x->op_count; i++) {
		cs_sparc_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case SPARC_OP_REG:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", cs_reg_name (handle, op->reg));
			break;
		case SPARC_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_kN (pj, "value", op->imm);
			break;
		case SPARC_OP_MEM:
			pj_ks (pj, "type", "mem");
			if (op->mem.base != SPARC_REG_INVALID) {
				pj_ks (pj, "base", cs_reg_name (handle, op->mem.base));
			}
			pj_ki (pj, "disp", op->mem.disp);
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

static const char *parse_reg_name(csh handle, cs_insn *insn, int reg_num) {
	switch (INSOP (reg_num).type) {
	case SPARC_OP_REG:
		return cs_reg_name (handle, INSOP (reg_num).reg);
	case SPARC_OP_MEM:
		if (INSOP (reg_num).mem.base != SPARC_REG_INVALID) {
			return cs_reg_name (handle, INSOP (reg_num).mem.base);
		}
		return NULL;
	default:
		return NULL;
	}
}

static int get_capstone_mode(RArchSession *as) {
	int mode = CS_MODE_LITTLE_ENDIAN;
#if 0
	// XXX capstone doesnt support big endian sparc, this code does nothing, so we need to swap around
	if (as->config->big_endian) {
		mode = CS_MODE_BIG_ENDIAN;
	}
#endif
	const char *cpu = as->config->cpu;
	if (cpu && !strcmp (cpu, "v9")) {
		mode |= CS_MODE_V9;
	}
	return mode;
}

#define CSINC SPARC
#define CSINC_MODE get_capstone_mode(as)
#include "../capstone.inc.c"

typedef struct plugin_data_t {
	CapstonePluginData cpd;
	RRegItem reg;
} PluginData;

static void op_fillval(PluginData *pd, RAnalOp *op, csh handle, cs_insn *insn) {
	RRegItem *reg = &pd->reg;
	RAnalValue *val;
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_LOAD:
		if (INSOP (0).type == SPARC_OP_MEM) {
			memset (reg, 0, sizeof (RRegItem));
			val = r_vector_push (&op->srcs, NULL);
			val->reg = parse_reg_name (handle, insn, 0);
			val->delta = INSOP(0).mem.disp;
		}
		break;
	case R_ANAL_OP_TYPE_STORE:
		if (INSOP (1).type == SPARC_OP_MEM) {
			memset (reg, 0, sizeof (RRegItem));
			val = r_vector_push (&op->dsts, NULL);
			val->reg = parse_reg_name (handle, insn, 1);
			val->delta = INSOP(1).mem.disp;
		}
		break;
	}
}

static csh cs_handle_for_session(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, 0);
	CapstonePluginData *pd = as->data;
	return pd->cs_handle;
}

static bool decode(RArchSession *as, RAnalOp *op, RAnalOpMask mask) {
	const ut64 addr = op->addr;
	csh handle = cs_handle_for_session (as);
	if (handle == 0) {
		return false;
	}
	cs_insn *insn = NULL;
#if 0
SPARC-V9 supports both little- and big-endian byte orders for data accesses only; instruction accesses
are always performed using big-endian byte order. In SPARC-V8, all data and instruction accesses are
performed in big-endian byte order.
#endif
	if (op->size < 4) {
		return false;
	}
#if R_SYS_ENDIAN
	ut32 lbuf = r_read_ble32 (op->bytes, R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config));
#else
	ut32 lbuf = r_read_ble32 (op->bytes, !R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config));
#endif

	// capstone-next
	int n = cs_disasm (handle, (const ut8*)&lbuf, sizeof (lbuf), addr, 1, &insn);
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 4;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			free (op->mnemonic);
			op->mnemonic = strdup ("invalid");
		}
	} else {
		if (mask & R_ARCH_OP_MASK_OPEX) {
			opex (&op->opex, handle, insn);
		}
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = r_str_newf ("%s%s%s",
					insn->mnemonic,
					insn->op_str[0]? " ": "",
					insn->op_str);
			op->mnemonic = r_str_replace (op->mnemonic, "+-", "-", true);
			r_str_replace_char (op->mnemonic, '%', 0);
		}
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
		case SPARC_INS_INVALID:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		case SPARC_INS_MOV:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case SPARC_INS_RETT:
		case SPARC_INS_RET:
		case SPARC_INS_RETL:
			op->type = R_ANAL_OP_TYPE_RET;
			op->delay = 1;
			break;
		case SPARC_INS_UNIMP:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		case SPARC_INS_CALL:
			switch (INSOP(0).type) {
			case SPARC_OP_MEM:
				// TODO
				break;
			case SPARC_OP_REG:
				op->type = R_ANAL_OP_TYPE_UCALL;
				op->delay = 1;
				op->fail = addr + 8;
				break;
			default:
				op->type = R_ANAL_OP_TYPE_CALL;
				op->delay = 1;
				op->jump = INSOP(0).imm;
				op->fail = addr + 8;
				break;
			}
			break;
		case SPARC_INS_NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case SPARC_INS_CMP:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case SPARC_INS_JMP:
		case SPARC_INS_JMPL:
			op->type = R_ANAL_OP_TYPE_JMP;
			op->delay = 1;
			op->jump = INSOP(0).imm;
			break;
		case SPARC_INS_LDD:
		case SPARC_INS_LD:
		case SPARC_INS_LDQ:
		case SPARC_INS_LDSB:
		case SPARC_INS_LDSH:
		case SPARC_INS_LDSW:
		case SPARC_INS_LDUB:
		case SPARC_INS_LDUH:
		case SPARC_INS_LDX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case SPARC_INS_STBAR:
		case SPARC_INS_STB:
		case SPARC_INS_STD:
		case SPARC_INS_ST:
		case SPARC_INS_STH:
		case SPARC_INS_STQ:
		case SPARC_INS_STX:
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case SPARC_INS_ORCC:
		case SPARC_INS_ORNCC:
		case SPARC_INS_ORN:
		case SPARC_INS_OR:
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case SPARC_INS_B:
		case SPARC_INS_BMASK:
		case SPARC_INS_BRGEZ:
		case SPARC_INS_BRGZ:
		case SPARC_INS_BRLEZ:
		case SPARC_INS_BRLZ:
		case SPARC_INS_BRNZ:
		case SPARC_INS_BRZ:
		case SPARC_INS_FB:
			switch (INSOP(0).type) {
			case SPARC_OP_REG:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->delay = 1;
				if (INSCC != SPARC_CC_ICC_N) { // never
					op->jump = INSOP (1).imm;
				}
				if (INSCC == SPARC_CC_ICC_A) { // always
					op->type = R_ANAL_OP_TYPE_JMP;
					op->delay = 0;
				} else {
					op->fail = addr + 8;
				}
				break;
			case SPARC_OP_IMM:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->delay = 1;
				op->jump = INSOP (0).imm;
				// this never thing is incorrectly handled in capstone < v5.0.2
				// if (INSCC != SPARC_CC_ICC_N) { /* never */ }
				if (INSCC == SPARC_CC_ICC_A) { // always
					op->type = R_ANAL_OP_TYPE_JMP;
					op->delay = 0;
				} else {
					op->fail = addr + 8;
				}
				break;
			default:
				// MEM?
				break;
			}
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
		if (mask & R_ARCH_OP_MASK_VAL) {
			op_fillval (as->data, op, handle, insn);
		}
		cs_free (insn, n);
	}
	return op->size > 0;
}

static char *regs(RArchSession *as) {
	const char *p = \
		"=PC	pc\n"
		"=SN	g1\n"
		"=SP	sp\n"
		"=BP	fp\n"
		"=A0	i0\n"
		"=A1	i1\n"
		"=A2	i2\n"
		"=A3	i3\n"
		"=A4	i4\n"
		"=A5	i5\n"
		"=R0	i7\n"
		"gpr	psr	.32	0	0\n"
		"gpr	pc	.32	4	0\n"
		"gpr	npc	.32	8	0\n"
		"gpr	y	.32	12	0\n"
		/* r0-r7 are global aka g0-g7 */
		"gpr	g0	.32	16	0\n"
		"gpr	g1	.32	20	0\n"
		"gpr	g2	.32	24	0\n"
		"gpr	g3	.32	28	0\n"
		"gpr	g4	.32	32	0\n"
		"gpr	g5	.32	36	0\n"
		"gpr	g6	.32	40	0\n"
		"gpr	g7	.32	44	0\n"
		/* r8-15 are out (o0-o7) */
		"gpr	o0	.32	48	0\n"
		"gpr	o1	.32	52	0\n"
		"gpr	o2	.32	56	0\n"
		"gpr	o3	.32	60	0\n"
		"gpr	o4	.32	64	0\n"
		"gpr	o5	.32	68	0\n"
		"gpr	o6	.32	72	0\n"
		"gpr	sp	.32	72	0\n"
		"gpr	o7	.32	76	0\n"
		/* r16-23 are local (l0-l7) */
		"gpr	l0	.32	80	0\n"
		"gpr	l1	.32	84	0\n"
		"gpr	l2	.32	88	0\n"
		"gpr	l3	.32	92	0\n"
		"gpr	l4	.32	96	0\n"
		"gpr	l5	.32	100	0\n"
		"gpr	l6	.32	104	0\n"
		"gpr	l7	.32	108	0\n"
		/* r24-31 are in (i0-i7) */
		"gpr	i0	.32	112	0\n"
		"gpr	i1	.32	116	0\n"
		"gpr	i2	.32	120	0\n"
		"gpr	i3	.32	124	0\n"
		"gpr	i4	.32	128	0\n"
		"gpr	i5	.32	132	0\n"
		"gpr	i6	.32	136	0\n"
		"gpr	fp	.32	136	0\n"
		"gpr	i7	.32	140	0\n"
	;
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	return 4; /* :D */
}

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	as->data = R_NEW0 (PluginData);
	CapstonePluginData *cpd = as->data;
	if (!r_arch_cs_init (as, &cpd->cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (as->data);
		return false;
	}
	return true;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	PluginData *pd = as->data;
	cs_close (&pd->cpd.cs_handle);
	R_FREE (as->data);
	return true;
}

static char *mnemonics(RArchSession *as, int id, bool json) {
	R_RETURN_VAL_IF_FAIL (as && as->data, NULL);
	CapstonePluginData *cpd = as->data;
	return r_arch_cs_mnemonics (as, cpd->cs_handle, id, json);
}

const RArchPlugin r_arch_plugin_sparc_cs = {
	.meta = {
		.name = "sparc",
		.author = "pancake",
		.desc = "Scalable Processor Architecture (capstone)",
		.license = "Apache-2.0",
	},
	.arch = "sparc",
	.cpus = "v9",
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.info = archinfo,
	.decode = decode,
	.regs = regs,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_anal_plugin_sparc_cs,
	.version = R2_VERSION
};
#endif

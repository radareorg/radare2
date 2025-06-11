/* radare2 - LGPL - Copyright 2023-2024 - pancake */

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
#define CSINC_MODE get_capstone_mode(as)

static int get_capstone_mode(RArchSession *as) {
	int mode = 0;
	const char *cpu = as->config->cpu;
	if (R_STR_ISNOTEMPTY (cpu)) {
		if (!strcmp (cpu, "tc110")) {
			mode |= CS_MODE_TRICORE_110;
		} else if (!strcmp (cpu, "tc120")) {
			mode |= CS_MODE_TRICORE_120;
		} else if (!strcmp (cpu, "tc130")) {
			mode |= CS_MODE_TRICORE_130;
		} else if (!strcmp (cpu, "tc131")) {
			mode |= CS_MODE_TRICORE_131;
		} else if (!strcmp (cpu, "tc160")) {
			mode |= CS_MODE_TRICORE_160;
		} else if (!strcmp (cpu, "tc161")) {
			mode |= CS_MODE_TRICORE_161;
		} else if (!strcmp (cpu, "tc162")) {
			mode |= CS_MODE_TRICORE_162;
		}
	}
	if (mode == 0) {
		mode |= CS_MODE_TRICORE_162;
	}
	return mode;
}
#include "../capstone.inc.c"

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	int i;
	cs_tricore *x = &insn->detail->tricore;
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
			pj_ki (pj, "base", op->mem.base);
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

static csh cs_handle_for_session(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, 0);
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
	const bool esil = mask & R_ARCH_OP_MASK_ESIL;
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
			// op->jump = imm (insn, 1);
			op->fail = op->addr + op->size;
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case TRICORE_INS_J:
		case TRICORE_INS_JA:
			op->jump = imm (insn, 0);
			op->type = R_ANAL_OP_TYPE_JMP;
			break;
		case TRICORE_INS_JI:
			op->type = R_ANAL_OP_TYPE_RJMP;
			break;
		case TRICORE_INS_JEQ_A:
		case TRICORE_INS_JEQ:
		case TRICORE_INS_JGEZ:
		case TRICORE_INS_JGE_U:
		case TRICORE_INS_JGE:
		case TRICORE_INS_JGTZ:
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
		case TRICORE_INS_CALL:
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = imm (insn, 0);
			op->fail = op->addr + op->size;
			break;
		case TRICORE_INS_CALLI:
			op->type = R_ANAL_OP_TYPE_RCALL;
			break;
		case TRICORE_INS_SUBS:
		case TRICORE_INS_SUBX:
			op->type = R_ANAL_OP_TYPE_SUB;
			if (esil) {
				cs_tricore *x = &insn->detail->tricore;
				cs_tricore_op *arg0 = x->operands + 0;
				cs_tricore_op *arg1 = x->operands + 1;
				const char *dr = cs_reg_name (handle, arg0->reg);
				const char *sr = cs_reg_name (handle, arg1->reg);
				r_strbuf_initf (&op->esil, "%s,%s,:=", sr, dr);
			}
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
			if (esil) {
				cs_tricore *x = &insn->detail->tricore;
				cs_tricore_op *arg0 = x->operands + 0;
				cs_tricore_op *arg1 = x->operands + 1;
				cs_tricore_op *arg2 = x->operands + 2;
				const char *dr = cs_reg_name (handle, arg0->reg);
				if (arg1->type == TRICORE_OP_REG) {
					if (arg2->type == TRICORE_OP_REG) {
						const char *sr = cs_reg_name (handle, arg1->reg);
						const char *sR = cs_reg_name (handle, arg2->reg);
						r_strbuf_initf (&op->esil, "%s,%s,+,%s,:=", sr, sR, dr);
					} else {
						const char *sr = cs_reg_name (handle, arg1->reg);
						r_strbuf_initf (&op->esil, "%d,%s,+,%s,:=", arg2->imm, sr, dr);
					}
				} else {
					// CAPSTONE BUG https://github.com/capstone-engine/capstone/issues/2474
				}
			}
			break;
		case TRICORE_INS_ADDI:
			op->type = R_ANAL_OP_TYPE_ADD;
			if (esil) {
				cs_tricore *x = &insn->detail->tricore;
				cs_tricore_op *arg0 = x->operands + 0;
				cs_tricore_op *arg1 = x->operands + 1;
				cs_tricore_op *arg2 = x->operands + 2;
				const char *dr = cs_reg_name (handle, arg0->reg);
				const char *sr = cs_reg_name (handle, arg1->reg);
				ut64 v = (ut64)arg2->imm;
				r_strbuf_initf (&op->esil, "%"PFMT64d",%s,+,%s,:=", v, sr, dr);
			}
			break;
		case TRICORE_INS_XOR:
		case TRICORE_INS_XOR_NE: // TODO: CXOR
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case TRICORE_INS_CMOVN:
		case TRICORE_INS_CMOV:
			op->type = R_ANAL_OP_TYPE_CMOV;
			break;
		case TRICORE_INS_MOVH:
		case TRICORE_INS_MOVH_A:
			op->type = R_ANAL_OP_TYPE_MOV;
			if (esil) {
				cs_tricore *x = &insn->detail->tricore;
				cs_tricore_op *arg0 = x->operands + 0;
				cs_tricore_op *arg1 = x->operands + 1;
				const char *dr = cs_reg_name (handle, arg0->reg);
				ut64 v = (ut64)arg1->imm;
				r_strbuf_initf (&op->esil, "16,%"PFMT64d",<<,%s,:=", v, dr);
			}
			break;
		case TRICORE_INS_LEA:
			op->type = R_ANAL_OP_TYPE_LEA;
			if (esil) {
				cs_tricore *x = &insn->detail->tricore;
				cs_tricore_op *arg0 = x->operands + 0;
				cs_tricore_op *arg1 = x->operands + 1;
				const char *dr = cs_reg_name (handle, arg0->reg);
				const char *sr = cs_reg_name (handle, arg0->mem.base);
				ut64 sd = (ut64)arg1->mem.disp;
				r_strbuf_initf (&op->esil, "%"PFMT64d",%s,+,%s,:=", sd, sr, dr);
			}
			break;
		case TRICORE_INS_MOV:
			op->type = R_ANAL_OP_TYPE_MOV;
			if (esil) {
				cs_tricore *x = &insn->detail->tricore;
				cs_tricore_op *arg0 = x->operands + 0;
				cs_tricore_op *arg1 = x->operands + 1;
				if (arg0->type == TRICORE_OP_REG && arg1->type == TRICORE_OP_IMM) {
					const char *dr = cs_reg_name (handle, arg0->reg);
					ut64 sn = arg1->imm;
					r_strbuf_initf (&op->esil, "%"PFMT64d",%s,:=", sn, dr);
				} else {
					R_LOG_DEBUG ("Invalid capstone details for a MOV");
				}
			}
			break;
		case TRICORE_INS_SWAP_A:
		case TRICORE_INS_SWAP_W:
		case TRICORE_INS_MOV_AA:
		case TRICORE_INS_MOV_U:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TRICORE_INS_INVALID:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		}
		cs_free (insn, n);
		r_str_replace_char (op->mnemonic, '#', 0);
	}
	return op->size > 0;
}

static int archinfo(RArchSession *as, ut32 q) {
	if (q == R_ARCH_INFO_DATA_ALIGN) {
		return 2;
	}
	if (q == R_ARCH_INFO_CODE_ALIGN) {
		return 2;
	}
	if (q == R_ARCH_INFO_INVOP_SIZE) {
		return 2;
	}
	if (q == R_ARCH_INFO_MAXOP_SIZE) {
		return 4;
	}
	if (q == R_ARCH_INFO_MINOP_SIZE) {
		return 2;
	}
	return 4; // XXX
}

static char *mnemonics(RArchSession *as, int id, bool json) {
	CapstonePluginData *cpd = as->data;
	return r_arch_cs_mnemonics (as, cpd->cs_handle, id, json);
}

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
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
	R_RETURN_VAL_IF_FAIL (as, false);
	CapstonePluginData *cpd = as->data;
	cs_close (&cpd->cs_handle);
	R_FREE (as->data);
	return true;
}

// Registers profile perfectly suitable for TC1767 CPU. Others CPU can require minor adjustments.
static char *regs(RArchSession *as) {
	const char *p =
		"=PC     pc\n"
		"=SP     a10\n"
		"=BP     a11\n"
		"=A0     a4\n"
		"=A1     a5\n"
		"=A2     a6\n"
		"=A3     a7\n"
		"=SN     a0\n"
		"# General-Purpose Address Registers (A0 - A15)\n"
		"gpr     a0      .32     0       0\n"
		"gpr     a1      .32     4       0\n"
		"gpr     a2      .32     8       0\n"
		"gpr     a3      .32     12      0\n"
		"gpr     a4      .32     16      0\n"
		"gpr     a5      .32     20      0\n"
		"gpr     a6      .32     24      0\n"
		"gpr     a7      .32     28      0\n"
		"gpr     a8      .32     32      0\n"
		"gpr     a9      .32     36      0\n"
		"gpr     sp      .32     40      0\n"
		"gpr     a10     .32     40      0\n"
		"gpr     a11     .32     44      0\n"
		"gpr     a12     .32     48      0\n"
		"gpr     a13     .32     52      0\n"
		"gpr     a14     .32     56      0\n"
		"gpr     a15     .32     60      0\n"
		"# General-Purpose Data Registers (D0 - D15)\n"
		"gpr     e0      .64     64      0\n"
		"gpr     d0      .32     64      0\n"
		"gpr     d1      .32     68      0\n"
		"gpr     e2      .64     72      0\n"
		"gpr     d2      .32     72      0\n"
		"gpr     d3      .32     76      0\n"
		"gpr     e4      .64     80      0\n"
		"gpr     d4      .32     80      0\n"
		"gpr     d5      .32     84      0\n"
		"gpr     e6      .64     88      0\n"
		"gpr     d6      .32     88      0\n"
		"gpr     d7      .32     92      0\n"
		"gpr     e8      .64     96      0\n"
		"gpr     d8      .32     96      0\n"
		"gpr     d9      .32     100     0\n"
		"gpr     e10     .64     104     0\n"
		"gpr     d10     .32     104     0\n"
		"gpr     d11     .32     108     0\n"
		"gpr     e12     .64     112     0\n"
		"gpr     d12     .32     112     0\n"
		"gpr     d13     .32     116     0\n"
		"gpr     e14     .64     120     0\n"
		"gpr     d14     .32     120     0\n"
		"gpr     d15     .32     124     0\n"
		"# Special-Purpose Registers\n"
		"gpr     PSW     .32     128     0   # Program Status Word\n"
		"gpr     PCXI    .32     132     0   # Previous Context Information\n"
		"gpr     FCX     .32     136     0   # Free Context List Pointer\n"
		"gpr     LCX     .32     140     0   # Last Context Save Pointer\n"
		"gpr     ISP     .32     144     0   # Interrupt Stack Pointer\n"
		"gpr     ICR     .32     148     0   # Interrupt Control Register\n"
		"gpr     PIPN    .32     152     0   # Pending Interrupt Priority Number\n"
		"gpr     BIV     .32     156     0   # Base Interrupt Vector\n"
		"gpr     BTV     .32     160     0   # Base Trap Vector\n"
		"gpr     pc      .32     164     0   # Program Counter\n"
		"# System Control and Configuration Registers\n"
		"gpr     SYSCON  .32     168     0   # System Configuration Register\n"
		"gpr     DCON2   .32     172     0   # Debug Control Register 2\n"
		"gpr     CSP     .32     176     0   # Context Save Pointer\n"
		"gpr     MMUCON  .32     180     0   # Memory Management Unit Control\n"
		"gpr     CPU_ID  .32     184     0   # CPU Identification Register\n"
		"gpr     PSWEN   .32     188     0   # Program Status Word Enable Register\n"
		"gpr     CCUDR   .32     192     0   # Cache Control Unit Debug Register\n"
		"gpr     IECON   .32     196     0   # Interrupt Enable Configuration Register\n"
		"gpr     TRAPV   .32     200     0   # Trap Vector Register\n"
		"gpr     BBR     .32     204     0   # Base Boundary Register (Optional, depending on use)\n"
		"gpr     DBGSR   .32     208     0   # Debug Status Register (Optional, depending on use)\n"
		"gpr     PCON    .32     212     0   # Peripheral Control Register (Optional, depending on use)\n";
	return strdup (p);
}

const RArchPlugin r_arch_plugin_tricore_cs = {
	.meta = {
		.name = "tricore.cs",
		.desc = "Infineon TriCore microcontroller (capstone)",
		.license = "Apache-2.0",
	},
	.endian = R_SYS_ENDIAN_LITTLE,
	.arch = "tricore",
	.cpus = "tc110,tc120,tc130,tc131,tc160,tc161,tc162",
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

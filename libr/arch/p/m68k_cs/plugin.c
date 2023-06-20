/* radare2 - LGPL - Copyright 2015-2022 - pancake */

#include <r_arch.h>
#include <capstone/capstone.h>

#ifdef CAPSTONE_M68K_H
#define CAPSTONE_HAS_M68K 1
#else
#define CAPSTONE_HAS_M68K 0
#ifdef _MSC_VER
#pragma message ("Cannot find capstone-m68k support")
#else
#warning Cannot find capstone-m68k support
#endif
#endif

#if CAPSTONE_HAS_M68K
#include <capstone/m68k.h>
// http://www.mrc.uidaho.edu/mrc/people/jff/digital/M68Kir.html

// clang-format off
// Source: https://wiki.neogeodev.org/index.php?title=68k_instructions_timings

#define CYCLES_MOVE_LUT_SRCS 12
#define CYCLES_MOVE_LUT_DSTS 9
typedef ut8 cycles_move_lut[CYCLES_MOVE_LUT_SRCS][CYCLES_MOVE_LUT_DSTS];

// move.b, move.w
static cycles_move_lut cycles_move_w = {
	/*  Dn, An, (An), (An)+, -(An), d(An), d(An,ix), xxx.W, xxx.L */
	{   4,  4,    8,     8,     8,    12,       14,    12,    16 }, /* Dn       */
	{   4,  4,    8,     8,     8,    12,       14,    12,    16 }, /* An       */
	{   8,  8,   12,    12,    12,    16,       18,    16,    20 }, /* (An)     */
	{   8,  8,   12,    12,    12,    16,       18,    16,    20 }, /* (An)+    */
	{  10, 10,   14,    14,    14,    18,       20,    18,    22 }, /* -(An)    */
	{  12, 12,   16,    16,    16,    20,       22,    20,    24 }, /* d(An)    */
	{  14, 14,   18,    18,    18,    22,       24,    22,    26 }, /* d(An,ix) */
	{  12, 12,   16,    16,    16,    20,       22,    20,    24 }, /* xxx.W    */
	{  16, 16,   20,    20,    20,    24,       26,    24,    28 }, /* xxx.L    */
	{  12, 12,   16,    16,    16,    20,       22,    20,    24 }, /* d(PC)    */
	{  14, 14,   18,    18,    18,    22,       24,    22,    26 }, /* d(PC,ix) */
	{  8,   8,   12,    12,    12,    16,       18,    16,    20 }, /* #xxx     */
};

// move.l
static cycles_move_lut cycles_move_l = {
	/*  Dn, An, (An), (An)+, -(An), d(An), d(An,ix), xxx.W, xxx.L */
	{   4,  4,   12,    12,    12,    16,       18,    16,    20 }, /* Dn       */
	{   4,  4,   12,    12,    12,    16,       18,    16,    20 }, /* An       */
	{  12, 12,   20,    20,    20,    24,       26,    24,    28 }, /* (An)     */
	{  12, 12,   20,    20,    20,    24,       26,    24,    28 }, /* (An)+    */
	{  14, 14,   22,    22,    22,    26,       28,    26,    30 }, /* -(An)    */
	{  16, 16,   24,    24,    24,    28,       30,    28,    32 }, /* d(An)    */
	{  18, 18,   26,    26,    26,    30,       32,    30,    34 }, /* d(An,ix) */
	{  16, 16,   24,    24,    24,    28,       30,    28,    32 }, /* xxx.W    */
	{  20, 20,   28,    28,    28,    32,       34,    32,    36 }, /* xxx.L    */
	{  16, 16,   24,    24,    24,    28,       30,    28,    32 }, /* d(PC)    */
	{  18, 18,   26,    26,    26,    30,       32,    30,    34 }, /* d(PC,ix) */
	{  12, 12,   20,    20,    20,    24,       26,    24,    28 }  /* #xxx     */
};

static int get_move_cycles (m68k_address_mode dst, m68k_address_mode src, bool is_long) {
	ut8 dst_idx = ((ut8) dst) - 1;
	ut8 src_idx = ((ut8) src) - 1;
	if (dst_idx >= CYCLES_MOVE_LUT_DSTS || src_idx >= CYCLES_MOVE_LUT_SRCS) {
		return 0;
	}
	cycles_move_lut *lut = is_long? & cycles_move_l: & cycles_move_w;
	return (*lut)[src_idx][dst_idx];
}

// End of instruction timings
// clang-format on

static int get_capstone_mode (RArchSession *as) {
	int mode = R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	// XXX no arch->cpu ?!?! CS_MODE_MICRO, N64
	// replace this with the asm.features?
	const char *cpu = as->config->cpu;
	if (R_STR_ISNOTEMPTY (cpu)) {
		if (strstr (cpu, "68000")) {
			mode |= CS_MODE_M68K_000;
		}
		if (strstr (cpu, "68010")) {
			mode |= CS_MODE_M68K_010;
		}
		if (strstr (cpu, "68020")) {
			mode |= CS_MODE_M68K_020;
		}
		if (strstr (cpu, "68030")) {
			mode |= CS_MODE_M68K_030;
		}
		if (strstr (cpu, "68040")) {
			mode |= CS_MODE_M68K_040;
		}
		if (strstr (cpu, "68060")) {
			mode |= CS_MODE_M68K_060;
		}
	}
	return mode;
}

#define CSINC M68K
#define CSINC_MODE get_capstone_mode(as)
#include "../capstone.inc.c"

typedef struct plugin_data_t {
	CapstonePluginData cpd;
	RRegItem reg;
} PluginData;

#define OPERAND(x) insn->detail->m68k.operands[x]
#define REG(x) cs_reg_name (*handle, insn->detail->m68k.operands[x].reg)
#define IMM(x) insn->detail->m68k.operands[x].imm
#define MEMBASE(x) cs_reg_name(*handle, insn->detail->m68k.operands[x].mem.base)
#define MEMINDEX(x) insn->detail->m68k.operands[x].mem.index
#define MEMDISP(x) insn->detail->m68k.operands[x].mem.disp

static inline ut64 make_64bits_address(ut64 address) {
	return UT32_MAX & address;
}

static inline void handle_branch_instruction(RAnalOp *op, ut64 addr, cs_m68k *m68k, ut32 type, int index) {
#if CS_API_MAJOR >= 4
	if (m68k->operands[index].type == M68K_OP_BR_DISP) {
		op->type = type;
		// TODO: disp_size is ignored
		op->jump = make_64bits_address (addr + m68k->operands[index].br_disp.disp + 2);
		op->fail = make_64bits_address (addr + op->size);
	}
#else
	op->type = type;
	// TODO: disp_size is ignored
	op->jump = make_64bits_address (addr + m68k->operands[index].br_disp.disp + 2);
	op->fail = make_64bits_address (addr + op->size);
#endif
}

static inline void handle_jump_instruction(RAnalOp *op, ut64 addr, cs_m68k *m68k, ut32 type) {
	op->type = type;

	// Handle PC relative mode jump
	if (m68k->operands[0].address_mode == M68K_AM_PCI_DISP) {
		op->jump = make_64bits_address (addr + m68k->operands[0].mem.disp + 2);
	} else {
		op->jump = make_64bits_address (m68k->operands[0].imm);
	}

	op->fail = make_64bits_address (addr + op->size);
}

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	cs_m68k *x = &insn->detail->m68k;
	pj_ka (pj, "operands");
	for (i = 0; i < x->op_count; i++) {
		cs_m68k_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case M68K_OP_REG:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", cs_reg_name (handle, op->reg));
			break;
		case M68K_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_kN (pj, "value", (st64)op->imm);
			break;
		case M68K_OP_MEM:
			pj_ks (pj, "type", "mem");
			if (op->mem.base_reg != M68K_REG_INVALID) {
				pj_ks (pj, "base_reg", cs_reg_name (handle, op->mem.base_reg));
			}
			if (op->mem.index_reg != M68K_REG_INVALID) {
				pj_ks (pj, "index_reg", cs_reg_name (handle, op->mem.index_reg));
			}
			if (op->mem.in_base_reg != M68K_REG_INVALID) {
				pj_ks (pj, "in_base_reg", cs_reg_name (handle, op->mem.in_base_reg));
			}
			pj_kN (pj, "in_disp", op->mem.in_disp);
			pj_kN (pj, "out_disp", op->mem.out_disp);
			pj_ki (pj, "disp", op->mem.disp);
			pj_ki (pj, "scale", op->mem.scale);
			pj_ki (pj, "bitfield", op->mem.bitfield);
			pj_ki (pj, "width", op->mem.width);
			pj_ki (pj, "offset", op->mem.offset);
			pj_ki (pj, "index_size", op->mem.index_size);
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
	switch (OPERAND (reg_num).type) {
	case M68K_OP_REG:
		return (char *)cs_reg_name (handle, OPERAND (reg_num).reg);
	case M68K_OP_MEM:
		if (OPERAND (reg_num).mem.base_reg != M68K_REG_INVALID) {
			return (char *)cs_reg_name (handle, OPERAND (reg_num).mem.base_reg);
		}
		return NULL;
	default:
		return NULL;
	}
}

static void op_fillval(PluginData *pd, RAnalOp *op, csh handle, cs_insn *insn) {
	RAnalValue *src, *dst;
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_MOV:
		ZERO_FILL (pd->reg);
		if (OPERAND(1).type == M68K_OP_MEM) {
			src = r_vector_push (&op->srcs, NULL);
			src->reg = parse_reg_name (handle, insn, 1);
			src->delta = OPERAND(0).mem.disp;
		} else if (OPERAND(0).type == M68K_OP_MEM) {
			dst = r_vector_push (&op->dsts, NULL);
			dst->reg = parse_reg_name (handle, insn, 0);
			dst->delta = OPERAND(1).mem.disp;
		}
		break;
	case R_ANAL_OP_TYPE_LEA:
		ZERO_FILL (pd->reg);
		if (OPERAND(1).type == M68K_OP_MEM) {
			dst = r_vector_push (&op->dsts, NULL);
			dst->reg = parse_reg_name (handle, insn, 1);
			dst->delta = OPERAND(1).mem.disp;
		}
		break;
	}
}

static inline csh cs_handle_for_session(RArchSession *as) {
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

	int n, opsize = -1;
	cs_insn* insn = NULL;
	cs_m68k *m68k;
	cs_detail *detail;

	op->size = 4;
	n = cs_disasm (handle, (ut8*)buf, len, addr, 1, &insn);
	int on = n;
	if (!insn || !strncmp (insn->mnemonic, "dc.w", 4)) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
			n = 2;
		} else {
			n = -1;
		}
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 2;
		opsize = 2;
		goto beach;
	} else if (mask & R_ARCH_OP_MASK_DISASM) {
		char *str = r_str_newf ("%s%s%s", insn->mnemonic, insn->op_str[0]? " ": "", insn->op_str);
		if (str) {
			char *p = r_str_replace (str, "$", "0x", true);
			if (p) {
				r_str_replace_char (p, '#', 0);
				op->mnemonic = p;
			} else {
				free (p);
			}
		}
	}
	if (n < 1 || insn->size < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 2;
		opsize = -1;
		goto beach;
	}
	if (!memcmp (buf, "\xff\xff", R_MIN (len, 2))) {
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 2;
		opsize = -1;
		goto beach;
	}
	detail = insn->detail;
	m68k = &detail->m68k;
	op->id = insn->id;
	opsize = op->size = insn->size;
	if (mask & R_ARCH_OP_MASK_OPEX) {
		opex (&op->opex, handle, insn);
	}
	switch (insn->id) {
	case M68K_INS_INVALID:
		op->type  = R_ANAL_OP_TYPE_ILL;
		break;
	case M68K_INS_ADD:
	case M68K_INS_ADDA:
	case M68K_INS_ADDI:
	case M68K_INS_ADDQ:
	case M68K_INS_ADDX:
		op->type  = R_ANAL_OP_TYPE_ADD;
		break;
	case M68K_INS_AND:
	case M68K_INS_ANDI:
		op->type  = R_ANAL_OP_TYPE_AND;
		break;
	case M68K_INS_ASL:
		op->type  = R_ANAL_OP_TYPE_SHL;
		break;
	case M68K_INS_ASR:
		op->type  = R_ANAL_OP_TYPE_SHR;
		break;
	case M68K_INS_ABCD:
		break;
	case M68K_INS_BHS:
	case M68K_INS_BLO:
	case M68K_INS_BHI:
	case M68K_INS_BLS:
	case M68K_INS_BCC:
	case M68K_INS_BCS:
	case M68K_INS_BNE:
	case M68K_INS_BEQ:
	case M68K_INS_BVC:
	case M68K_INS_BVS:
	case M68K_INS_BPL:
	case M68K_INS_BMI:
	case M68K_INS_BGE:
	case M68K_INS_BLT:
	case M68K_INS_BGT:
	case M68K_INS_BLE:
		handle_branch_instruction (op, addr, m68k, R_ANAL_OP_TYPE_CJMP, 0);
		break;
	case M68K_INS_BRA:
		handle_branch_instruction (op, addr, m68k, R_ANAL_OP_TYPE_JMP, 0);
		break;
	case M68K_INS_BSR:
		handle_branch_instruction (op, addr, m68k, R_ANAL_OP_TYPE_CALL, 0);
		break;
	case M68K_INS_BCHG:
	case M68K_INS_BCLR:
	case M68K_INS_BSET:
	case M68K_INS_BTST:
	case M68K_INS_BFCHG:
	case M68K_INS_BFCLR:
	case M68K_INS_BFEXTS:
	case M68K_INS_BFEXTU:
	case M68K_INS_BFFFO:
	case M68K_INS_BFINS:
	case M68K_INS_BFSET:
	case M68K_INS_BFTST:
	case M68K_INS_BKPT:
	case M68K_INS_CALLM:
	case M68K_INS_CAS:
	case M68K_INS_CAS2:
	case M68K_INS_CHK:
	case M68K_INS_CHK2:
	case M68K_INS_CLR:
		// TODO:
		break;
	case M68K_INS_CMP:
	case M68K_INS_CMPA:
	case M68K_INS_CMPI:
	case M68K_INS_CMPM:
	case M68K_INS_CMP2:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case M68K_INS_CINVL:
	case M68K_INS_CINVP:
	case M68K_INS_CINVA:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case M68K_INS_CPUSHL:
	case M68K_INS_CPUSHP:
	case M68K_INS_CPUSHA:
		break;
	case M68K_INS_DBT:
	case M68K_INS_DBF:
	case M68K_INS_DBHI:
	case M68K_INS_DBLS:
	case M68K_INS_DBCC:
	case M68K_INS_DBCS:
	case M68K_INS_DBNE:
	case M68K_INS_DBEQ:
	case M68K_INS_DBVC:
	case M68K_INS_DBVS:
	case M68K_INS_DBPL:
	case M68K_INS_DBMI:
	case M68K_INS_DBGE:
	case M68K_INS_DBLT:
	case M68K_INS_DBGT:
	case M68K_INS_DBLE:
	case M68K_INS_DBRA:
		handle_branch_instruction (op, addr, m68k, R_ANAL_OP_TYPE_CJMP, 1);
		break;
	case M68K_INS_DIVS:
	case M68K_INS_DIVSL:
	case M68K_INS_DIVU:
	case M68K_INS_DIVUL:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case M68K_INS_EOR:
	case M68K_INS_EORI:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case M68K_INS_EXG:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case M68K_INS_EXT:
	case M68K_INS_EXTB:
		break;
	case M68K_INS_FABS:
	case M68K_INS_FSABS:
	case M68K_INS_FDABS:
	case M68K_INS_FACOS:
	case M68K_INS_FADD:
	case M68K_INS_FSADD:
	case M68K_INS_FDADD:
	case M68K_INS_FASIN:
	case M68K_INS_FATAN:
	case M68K_INS_FATANH:
	case M68K_INS_FBF:
	case M68K_INS_FBEQ:
	case M68K_INS_FBOGT:
	case M68K_INS_FBOGE:
	case M68K_INS_FBOLT:
	case M68K_INS_FBOLE:
	case M68K_INS_FBOGL:
	case M68K_INS_FBOR:
	case M68K_INS_FBUN:
	case M68K_INS_FBUEQ:
	case M68K_INS_FBUGT:
	case M68K_INS_FBUGE:
	case M68K_INS_FBULT:
	case M68K_INS_FBULE:
	case M68K_INS_FBNE:
	case M68K_INS_FBT:
	case M68K_INS_FBSF:
	case M68K_INS_FBSEQ:
	case M68K_INS_FBGT:
	case M68K_INS_FBGE:
	case M68K_INS_FBLT:
	case M68K_INS_FBLE:
	case M68K_INS_FBGL:
	case M68K_INS_FBGLE:
	case M68K_INS_FBNGLE:
	case M68K_INS_FBNGL:
	case M68K_INS_FBNLE:
	case M68K_INS_FBNLT:
	case M68K_INS_FBNGE:
	case M68K_INS_FBNGT:
	case M68K_INS_FBSNE:
	case M68K_INS_FBST:
	case M68K_INS_FCMP:
	case M68K_INS_FCOS:
	case M68K_INS_FCOSH:
	case M68K_INS_FDBF:
	case M68K_INS_FDBEQ:
	case M68K_INS_FDBOGT:
	case M68K_INS_FDBOGE:
	case M68K_INS_FDBOLT:
	case M68K_INS_FDBOLE:
	case M68K_INS_FDBOGL:
	case M68K_INS_FDBOR:
	case M68K_INS_FDBUN:
	case M68K_INS_FDBUEQ:
	case M68K_INS_FDBUGT:
	case M68K_INS_FDBUGE:
	case M68K_INS_FDBULT:
	case M68K_INS_FDBULE:
	case M68K_INS_FDBNE:
	case M68K_INS_FDBT:
	case M68K_INS_FDBSF:
	case M68K_INS_FDBSEQ:
	case M68K_INS_FDBGT:
	case M68K_INS_FDBGE:
	case M68K_INS_FDBLT:
	case M68K_INS_FDBLE:
	case M68K_INS_FDBGL:
	case M68K_INS_FDBGLE:
	case M68K_INS_FDBNGLE:
	case M68K_INS_FDBNGL:
	case M68K_INS_FDBNLE:
	case M68K_INS_FDBNLT:
	case M68K_INS_FDBNGE:
	case M68K_INS_FDBNGT:
	case M68K_INS_FDBSNE:
	case M68K_INS_FDBST:
	case M68K_INS_FDIV:
	case M68K_INS_FSDIV:
	case M68K_INS_FDDIV:
	case M68K_INS_FETOX:
	case M68K_INS_FETOXM1:
	case M68K_INS_FGETEXP:
	case M68K_INS_FGETMAN:
	case M68K_INS_FINT:
	case M68K_INS_FINTRZ:
	case M68K_INS_FLOG10:
	case M68K_INS_FLOG2:
	case M68K_INS_FLOGN:
	case M68K_INS_FLOGNP1:
	case M68K_INS_FMOD:
	case M68K_INS_FMOVE:
	case M68K_INS_FSMOVE:
	case M68K_INS_FDMOVE:
	case M68K_INS_FMOVECR:
	case M68K_INS_FMOVEM:
	case M68K_INS_FMUL:
	case M68K_INS_FSMUL:
	case M68K_INS_FDMUL:
	case M68K_INS_FNEG:
	case M68K_INS_FSNEG:
	case M68K_INS_FDNEG:
	case M68K_INS_FNOP:
	case M68K_INS_FREM:
	case M68K_INS_FRESTORE:
	case M68K_INS_FSAVE:
	case M68K_INS_FSCALE:
	case M68K_INS_FSGLDIV:
	case M68K_INS_FSGLMUL:
	case M68K_INS_FSIN:
	case M68K_INS_FSINCOS:
	case M68K_INS_FSINH:
	case M68K_INS_FSQRT:
	case M68K_INS_FSSQRT:
	case M68K_INS_FDSQRT:
	case M68K_INS_FSF:
	case M68K_INS_FSBEQ:
	case M68K_INS_FSOGT:
	case M68K_INS_FSOGE:
	case M68K_INS_FSOLT:
	case M68K_INS_FSOLE:
	case M68K_INS_FSOGL:
	case M68K_INS_FSOR:
	case M68K_INS_FSUN:
	case M68K_INS_FSUEQ:
	case M68K_INS_FSUGT:
	case M68K_INS_FSUGE:
	case M68K_INS_FSULT:
	case M68K_INS_FSULE:
	case M68K_INS_FSNE:
	case M68K_INS_FST:
	case M68K_INS_FSSF:
	case M68K_INS_FSSEQ:
	case M68K_INS_FSGT:
	case M68K_INS_FSGE:
	case M68K_INS_FSLT:
	case M68K_INS_FSLE:
	case M68K_INS_FSGL:
	case M68K_INS_FSGLE:
	case M68K_INS_FSNGLE:
	case M68K_INS_FSNGL:
	case M68K_INS_FSNLE:
	case M68K_INS_FSNLT:
	case M68K_INS_FSNGE:
	case M68K_INS_FSNGT:
	case M68K_INS_FSSNE:
	case M68K_INS_FSST:
	case M68K_INS_FSUB:
	case M68K_INS_FSSUB:
	case M68K_INS_FDSUB:
	case M68K_INS_FTAN:
	case M68K_INS_FTANH:
	case M68K_INS_FTENTOX:
	case M68K_INS_FTRAPF:
	case M68K_INS_FTRAPEQ:
	case M68K_INS_FTRAPOGT:
	case M68K_INS_FTRAPOGE:
	case M68K_INS_FTRAPOLT:
	case M68K_INS_FTRAPOLE:
	case M68K_INS_FTRAPOGL:
	case M68K_INS_FTRAPOR:
	case M68K_INS_FTRAPUN:
	case M68K_INS_FTRAPUEQ:
	case M68K_INS_FTRAPUGT:
	case M68K_INS_FTRAPUGE:
	case M68K_INS_FTRAPULT:
	case M68K_INS_FTRAPULE:
	case M68K_INS_FTRAPNE:
	case M68K_INS_FTRAPT:
	case M68K_INS_FTRAPSF:
	case M68K_INS_FTRAPSEQ:
	case M68K_INS_FTRAPGT:
	case M68K_INS_FTRAPGE:
	case M68K_INS_FTRAPLT:
	case M68K_INS_FTRAPLE:
	case M68K_INS_FTRAPGL:
	case M68K_INS_FTRAPGLE:
	case M68K_INS_FTRAPNGLE:
	case M68K_INS_FTRAPNGL:
	case M68K_INS_FTRAPNLE:
	case M68K_INS_FTRAPNLT:
	case M68K_INS_FTRAPNGE:
	case M68K_INS_FTRAPNGT:
	case M68K_INS_FTRAPSNE:
	case M68K_INS_FTRAPST:
	case M68K_INS_FTST:
	case M68K_INS_FTWOTOX:
		op->type = R_ANAL_OP_TYPE_UNK;
		op->family = R_ANAL_OP_FAMILY_FPU;
		break;
	case M68K_INS_HALT:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case M68K_INS_ILLEGAL:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case M68K_INS_JMP:
		handle_jump_instruction (op, addr, m68k, R_ANAL_OP_TYPE_JMP);
		break;
	case M68K_INS_JSR:
		handle_jump_instruction (op, addr, m68k, R_ANAL_OP_TYPE_CALL);
		break;
	case M68K_INS_LPSTOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case M68K_INS_LSL:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case M68K_INS_LINK:
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -(st16)IMM(1);
		break;
	case M68K_INS_LSR:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case M68K_INS_PEA:
	case M68K_INS_LEA:
		op->type = R_ANAL_OP_TYPE_LEA;
		break;
	case M68K_INS_MOVE:
		op->type = R_ANAL_OP_TYPE_MOV;
		assert (m68k->op_count >= 2);
		assert (m68k->op_size.type == M68K_SIZE_TYPE_CPU);
		bool is_long = m68k->op_size.cpu_size == M68K_CPU_SIZE_LONG;
		op->cycles = get_move_cycles (m68k->operands[0].address_mode, m68k->operands[1].address_mode, is_long);
		break;
	case M68K_INS_MOVEA:
	case M68K_INS_MOVEC:
	case M68K_INS_MOVEM:
	case M68K_INS_MOVEP:
	case M68K_INS_MOVEQ:
	case M68K_INS_MOVES:
	case M68K_INS_MOVE16:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case M68K_INS_MULS:
	case M68K_INS_MULU:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case M68K_INS_NBCD:
	case M68K_INS_NEG:
	case M68K_INS_NEGX:
		break;
	case M68K_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case M68K_INS_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case M68K_INS_OR:
	case M68K_INS_ORI:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case M68K_INS_PACK:
	case M68K_INS_PFLUSH:
	case M68K_INS_PFLUSHA:
	case M68K_INS_PFLUSHAN:
	case M68K_INS_PFLUSHN:
	case M68K_INS_PLOADR:
	case M68K_INS_PLOADW:
	case M68K_INS_PLPAR:
	case M68K_INS_PLPAW:
	case M68K_INS_PMOVE:
	case M68K_INS_PMOVEFD:
	case M68K_INS_PTESTR:
	case M68K_INS_PTESTW:
	case M68K_INS_PULSE:
	case M68K_INS_REMS:
	case M68K_INS_REMU:
	case M68K_INS_RESET:
		break;
	case M68K_INS_ROL:
		op->type = R_ANAL_OP_TYPE_ROL;
		break;
	case M68K_INS_ROR:
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case M68K_INS_ROXL:
	case M68K_INS_ROXR:
		break;
	case M68K_INS_RTD:
	case M68K_INS_RTE:
	case M68K_INS_RTM:
	case M68K_INS_RTR:
	case M68K_INS_RTS:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case M68K_INS_SBCD:
	case M68K_INS_ST:
	case M68K_INS_SF:
	case M68K_INS_SHI:
	case M68K_INS_SLS:
	case M68K_INS_SCC:
	case M68K_INS_SHS:
	case M68K_INS_SCS:
	case M68K_INS_SLO:
	case M68K_INS_SNE:
	case M68K_INS_SEQ:
	case M68K_INS_SVC:
	case M68K_INS_SVS:
	case M68K_INS_SPL:
	case M68K_INS_SMI:
	case M68K_INS_SGE:
	case M68K_INS_SLT:
	case M68K_INS_SGT:
	case M68K_INS_SLE:
	case M68K_INS_STOP:
		break;
	case M68K_INS_SUB:
	case M68K_INS_SUBA:
	case M68K_INS_SUBI:
	case M68K_INS_SUBQ:
	case M68K_INS_SUBX:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case M68K_INS_SWAP:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case M68K_INS_TAS:
		break;
	case M68K_INS_TRAP:
	case M68K_INS_TRAPV:
	case M68K_INS_TRAPT:
	case M68K_INS_TRAPF:
	case M68K_INS_TRAPHI:
	case M68K_INS_TRAPLS:
	case M68K_INS_TRAPCC:
	case M68K_INS_TRAPHS:
	case M68K_INS_TRAPCS:
	case M68K_INS_TRAPLO:
	case M68K_INS_TRAPNE:
	case M68K_INS_TRAPEQ:
	case M68K_INS_TRAPVC:
	case M68K_INS_TRAPVS:
	case M68K_INS_TRAPPL:
	case M68K_INS_TRAPMI:
	case M68K_INS_TRAPGE:
	case M68K_INS_TRAPLT:
	case M68K_INS_TRAPGT:
	case M68K_INS_TRAPLE:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case M68K_INS_TST:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case M68K_INS_UNPK: // unpack BCD
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case M68K_INS_UNLK:
		op->type = R_ANAL_OP_TYPE_POP;
		// reset stackframe
		op->stackop = R_ANAL_STACK_SET;
		op->stackptr = 0;
		break;
	}
	if (mask & R_ARCH_OP_MASK_VAL) {
		PluginData *pd = as->data;
		op_fillval (pd, op, handle, insn);
	}
beach:
	cs_free (insn, on);
	return opsize > 0;
}

static char *regs(RArchSession *as) {
	const char *p = \
		"=PC    pc\n"
		"=SP    a7\n"
		"=BP    a6\n"
		"=R0    a0\n"
		"=A0    a0\n"
		"=A1    a1\n"
		"=A2    a2\n"
		"=A3    a3\n"
		"gpr	d0	.32	0	0\n"
		"gpr	d1	.32	4	0\n"
		"gpr	d2	.32	8	0\n"
		"gpr	d3	.32	12	0\n"
		"gpr	d4	.32	16	0\n"
		"gpr	d5	.32	20	0\n"
		"gpr	d6	.32	24	0\n"
		"gpr	d7	.32	28	0\n"
		"gpr	a0	.32	32	0\n"
		"gpr	a1	.32	36	0\n"
		"gpr	a2 	.32	40	0\n"
		"gpr	a3 	.32	44	0\n"
		"gpr	a4 	.32	48	0\n"
		"gpr	a5	.32	52	0\n"
		"gpr	a6 	.32	56	0\n"
		"gpr	a7 	.32	60	0\n"
		"gpr	fp0	.32	64	0\n" //FPU register 0, 96bits to write and read max
		"gpr	fp1	.32	68	0\n" //FPU register 1, 96bits to write and read max
		"gpr	fp2	.32	72	0\n" //FPU register 2, 96bits to write and read max
		"gpr	fp3 	.32	76	0\n" //FPU register 3, 96bits to write and read max
		"gpr	fp4 	.32	80	0\n" //FPU register 4, 96bits to write and read max
		"gpr	fp5 	.32	84	0\n" //FPU register 5, 96bits to write and read max
		"gpr	fp6 	.32	88	0\n" //FPU register 6, 96bits to write and read max
		"gpr	fp7 	.32	92	0\n" //FPU register 7, 96bits to write and read max
		"gpr	pc 	.32	96	0\n"
		"gpr	sr 	.32	100	0\n" //only available for read and write access during supervisor mode 16bit
		"gpr	ccr 	.32	104	0\n" //subset of the SR, available from any mode
		"gpr	sfc 	.32	108	0\n" //source function code register
		"gpr	dfc	.32	112	0\n" //destination function code register
		"gpr	usp	.32	116	0\n" //user stack point this is an shadow register of A7 user mode, SR bit 0xD is 0
		"gpr	vbr	.32	120	0\n" //vector base register, this is a Address pointer
		"gpr	cacr	.32	124	0\n" //cache control register, implementation specific
		"gpr	caar	.32	128	0\n" //cache address register, 68020, 68EC020, 68030 and 68EC030 only.
		"gpr	msp	.32	132	0\n" //master stack pointer, this is an shadow register of A7 supervisor mode, SR bits 0xD && 0xC are set
		"gpr	isp	.32	136	0\n" //interrupt stack pointer, this is an shadow register of A7  supervisor mode, SR bit 0xD is set, 0xC is not.
		"gpr	tc	.32	140	0\n"
		"gpr	itt0	.32	144	0\n" //in 68EC040 this is IACR0
		"gpr	itt1	.32	148	0\n" //in 68EC040 this is IACR1
		"gpr	dtt0	.32	156	0\n" //in 68EC040 this is DACR0
		"gpr	dtt1	.32	160	0\n" //in 68EC040 this is DACR1
		"gpr	mmusr	.32	164	0\n"
		"gpr	urp	.32	168	0\n"
		"gpr	srp	.32	172	0\n"
		"gpr	fpcr	.32	176	0\n"
		"gpr	fpsr	.32	180	0\n"
		"gpr	fpiar	.32	184	0\n";
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ANAL_ARCHINFO_ALIGN:
		return 2;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return 6;
	case R_ANAL_ARCHINFO_INV_OP_SIZE:
		return 2;
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return 2;
	case R_ANAL_ARCHINFO_DATA_ALIGN:
		{
		const char *cpu = as->config->cpu;
		if (strstr (cpu, "68030") || strstr (cpu, "68040") || strstr (cpu, "68060")) {
			return 1;
		}
		return 2;
		}
	}
	return 2;
}

static char *mnemonics(RArchSession *s, int id, bool json) {
	CapstonePluginData *cpd = s->data;
	return r_arch_cs_mnemonics (s, cpd->cs_handle, id, json);
}

static bool init(RArchSession *s) {
	r_return_val_if_fail (s, false);
	if (s->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}

	s->data = R_NEW0 (PluginData);
	if (!s->data) {
		R_LOG_ERROR ("Could not allocate memory for m68k_cs plugin");
		return false;
	}

	PluginData *pd = s->data;
	if (!r_arch_cs_init (s, &pd->cpd.cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (s->data);
		return false;
	}
	return true;
}

static bool fini(RArchSession *s) {
	r_return_val_if_fail (s, false);
	CapstonePluginData *cpd = s->data;
	cs_close (&cpd->cs_handle);
	R_FREE (s->data);
	return true;
}

const RArchPlugin r_arch_plugin_m68k_cs = {
	.meta = {
		.name = "m68k",
		.desc = "Capstone M68K analyzer",
		.license = "BSD",
	},
	.cpus = "68000,68010,68020,68030,68040,68060",
	.arch = "m68k",
	.info = archinfo,
	.regs = regs,
	.bits = R_SYS_BITS_PACK1 (32),
	.decode = decode,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini,
};
#else
const RArchPlugin r_arch_plugin_m68k_cs = {
	.name = "m68k (unsupported)",
	.desc = "Capstone M68K analyzer (unsupported)",
	.license = "BSD",
	.arch = "m68k",
	.bits = R_SYS_BITS_PACK1 (32),
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_anal_plugin_m68k_cs,
	.version = R2_VERSION
};
#endif

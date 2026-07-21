/* radare2 - LGPL - Copyright 2026 - pancake, avi */

#include <r_arch.h>
#include <r_anal.h>
#include <r_core.h>
#include <r_lib.h>

#if USE_SYS_ZYDIS
#include <Zydis/Zydis.h>
#else
#include <Zydis.h>
#endif

/* zydis 5 replaced mem.disp.has_displacement with mem.disp.size, and zydis
 * <= 4.1.0 defines ZYDIS_VERSION with a cast that breaks preprocessor checks,
 * so building against a system zydis requires at least version 4.1.1 */
#if ZYDIS_VERSION >= 0x0005000000000000ULL
#define HAS_MEM_DISP(op) ((op)->mem.disp.size != 0)
#else
#define HAS_MEM_DISP(op) ((op)->mem.disp.has_displacement)
#endif

#define ZYDIS_MAX_INSN_SIZE 16

typedef struct plugin_data_t {
	ZydisDecoder decoder;
	ZydisFormatter formatter;
	int bits;
	int syntax;
	ZydisMachineMode mode;
	ZydisStackWidth width;
} PluginData;

static ZydisMachineMode zydis_mode(int bits) {
	switch (bits) {
	case 16:
		return ZYDIS_MACHINE_MODE_LEGACY_16;
	case 32:
		return ZYDIS_MACHINE_MODE_LEGACY_32;
	case 64:
		return ZYDIS_MACHINE_MODE_LONG_64;
	default:
		return ZYDIS_MACHINE_MODE_LEGACY_32;
	}
}

static ZydisStackWidth zydis_width(int bits) {
	switch (bits) {
	case 16:
		return ZYDIS_STACK_WIDTH_16;
	case 64:
		return ZYDIS_STACK_WIDTH_64;
	default:
		return ZYDIS_STACK_WIDTH_32;
	}
}

static ZydisFormatterStyle zydis_style(int syntax) {
	switch (syntax) {
	case R_ARCH_SYNTAX_ATT:
		return ZYDIS_FORMATTER_STYLE_ATT;
	case R_ARCH_SYNTAX_MASM:
		return ZYDIS_FORMATTER_STYLE_INTEL_MASM;
	default:
		return ZYDIS_FORMATTER_STYLE_INTEL;
	}
}

static bool zydis_configure(PluginData *pd, RArchConfig *cfg) {
	R_RETURN_VAL_IF_FAIL (pd && cfg, false);
	pd->bits = cfg->bits;
	pd->syntax = cfg->syntax;
	pd->mode = zydis_mode (cfg->bits);
	pd->width = zydis_width (cfg->bits);
	if (!ZYAN_SUCCESS (ZydisDecoderInit (&pd->decoder, pd->mode, pd->width))) {
		return false;
	}
	if (!ZYAN_SUCCESS (ZydisFormatterInit (&pd->formatter, zydis_style (cfg->syntax)))) {
		return false;
	}
	ZydisFormatterSetProperty (&pd->formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
	ZydisFormatterSetProperty (&pd->formatter, ZYDIS_FORMATTER_PROP_HEX_UPPERCASE, ZYAN_FALSE);
	ZydisFormatterSetProperty (&pd->formatter, ZYDIS_FORMATTER_PROP_ADDR_PADDING_ABSOLUTE, ZYDIS_PADDING_DISABLED);
	ZydisFormatterSetProperty (&pd->formatter, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL, ZYAN_TRUE);
	return true;
}

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->config, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	PluginData *pd = R_NEW0 (PluginData);
	if (!pd) {
		return false;
	}
	if (!zydis_configure (pd, as->config)) {
		free (pd);
		return false;
	}
	as->data = pd;
	return true;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	R_FREE (as->data);
	return true;
}

static bool plugin_changed(RArchSession *as) {
	PluginData *pd = as->data;
	return !pd || as->config->bits != pd->bits || as->config->syntax != pd->syntax;
}

static bool refresh_plugin(RArchSession *as) {
	if (!plugin_changed (as)) {
		return true;
	}
	PluginData *pd = as->data;
	if (!pd) {
		return false;
	}
	return zydis_configure (pd, as->config);
}

static const char *zyreg(ZydisRegister reg) {
	const char *name = ZydisRegisterGetString (reg);
	return name? name: "";
}

static ut64 zydis_imm_value(const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *op, ut64 addr) {
	if (!insn || !op) {
		return UT64_MAX;
	}
	if (op->imm.is_relative) {
		return addr + insn->length + op->imm.value.s;
	}
	return op->imm.value.u;
}

static const ZydisDecodedOperand *visible_op(const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops, size_t n) {
	if (!insn || !ops || n >= insn->operand_count_visible) {
		return NULL;
	}
	return &ops[n];
}

static int operand_bytes(const ZydisDecodedOperand *op) {
	return op && op->size? R_MAX (1, op->size / 8): 0;
}

static bool is_mem_abs(const ZydisDecodedOperand *op) {
	return op && op->type == ZYDIS_OPERAND_TYPE_MEMORY
		&& op->mem.base == ZYDIS_REGISTER_NONE
		&& op->mem.index == ZYDIS_REGISTER_NONE
		&& HAS_MEM_DISP (op);
}

static bool is_mem_riprel(const ZydisDecodedOperand *op) {
	return op && op->type == ZYDIS_OPERAND_TYPE_MEMORY
		&& (op->mem.base == ZYDIS_REGISTER_RIP || op->mem.base == ZYDIS_REGISTER_EIP)
		&& HAS_MEM_DISP (op);
}

static int cond_x86_zydis(ZydisMnemonic mnemonic) {
	switch (mnemonic) {
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_CMOVZ:
	case ZYDIS_MNEMONIC_SETZ:
		return R_ANAL_CONDTYPE_EQ;
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_CMOVNZ:
	case ZYDIS_MNEMONIC_SETNZ:
		return R_ANAL_CONDTYPE_NE;
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_CMOVNL:
	case ZYDIS_MNEMONIC_SETNL:
		return R_ANAL_CONDTYPE_GE;
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_CMOVNLE:
	case ZYDIS_MNEMONIC_SETNLE:
		return R_ANAL_CONDTYPE_GT;
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_CMOVLE:
	case ZYDIS_MNEMONIC_SETLE:
		return R_ANAL_CONDTYPE_LE;
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_CMOVL:
	case ZYDIS_MNEMONIC_SETL:
		return R_ANAL_CONDTYPE_LT;
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_CMOVNB:
	case ZYDIS_MNEMONIC_SETNB:
		return R_ANAL_CONDTYPE_HS;
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_CMOVB:
	case ZYDIS_MNEMONIC_SETB:
		return R_ANAL_CONDTYPE_LO;
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_CMOVS:
	case ZYDIS_MNEMONIC_SETS:
		return R_ANAL_CONDTYPE_MI;
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_CMOVNS:
	case ZYDIS_MNEMONIC_SETNS:
		return R_ANAL_CONDTYPE_PL;
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_CMOVO:
	case ZYDIS_MNEMONIC_SETO:
		return R_ANAL_CONDTYPE_VS;
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_CMOVNO:
	case ZYDIS_MNEMONIC_SETNO:
		return R_ANAL_CONDTYPE_VC;
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_CMOVNBE:
	case ZYDIS_MNEMONIC_SETNBE:
		return R_ANAL_CONDTYPE_HI;
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_CMOVBE:
	case ZYDIS_MNEMONIC_SETBE:
		return R_ANAL_CONDTYPE_LS;
	default:
		return R_ANAL_CONDTYPE_AL;
	}
}

static void normalize_mnemonic(RArchSession *as, RAnalOp *op) {
	if (!op->mnemonic) {
		return;
	}
	if (as->config->syntax != R_ARCH_SYNTAX_MASM) {
		op->mnemonic = r_str_replace (op->mnemonic, "ptr ", "", true);
	}
}

static void format_mnemonic(RArchSession *as, RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops) {
	PluginData *pd = as->data;
	char text[256];
	text[0] = 0;
	ZyanStatus status = ZydisFormatterFormatInstruction (
		&pd->formatter, insn, ops, insn->operand_count_visible,
		text, sizeof (text), op->addr, ZYAN_NULL);
	if (ZYAN_SUCCESS (status)) {
		op->mnemonic = strdup (text);
		normalize_mnemonic (as, op);
	}
}

static void set_prefix(RAnalOp *op, const ZydisDecodedInstruction *insn) {
	size_t i;
	for (i = 0; i < insn->raw.prefix_count; i++) {
		switch (insn->raw.prefixes[i].value) {
		case 0xf0:
			op->prefix |= R_ANAL_OP_PREFIX_LOCK;
			op->family = R_ANAL_OP_FAMILY_THREAD;
			break;
		case 0xf2:
			op->prefix |= R_ANAL_OP_PREFIX_REPNE;
			break;
		case 0xf3:
			op->prefix |= R_ANAL_OP_PREFIX_REP;
			break;
		default:
			break;
		}
	}
}

static void set_family(RAnalOp *op, const ZydisDecodedInstruction *insn) {
	switch (insn->meta.category) {
	case ZYDIS_CATEGORY_X87_ALU:
		op->family = R_ANAL_OP_FAMILY_FPU;
		break;
	case ZYDIS_CATEGORY_AES:
	case ZYDIS_CATEGORY_SHA:
	case ZYDIS_CATEGORY_SHA512:
	case ZYDIS_CATEGORY_VAES:
	case ZYDIS_CATEGORY_VPCLMULQDQ:
	case ZYDIS_CATEGORY_PCLMULQDQ:
		op->family = R_ANAL_OP_FAMILY_CRYPTO;
		break;
	case ZYDIS_CATEGORY_MMX:
	case ZYDIS_CATEGORY_SSE:
	case ZYDIS_CATEGORY_AVX:
	case ZYDIS_CATEGORY_AVX2:
	case ZYDIS_CATEGORY_AVX512:
	case ZYDIS_CATEGORY_AVX_IFMA:
	case ZYDIS_CATEGORY_AVX2GATHER:
	case ZYDIS_CATEGORY_AVX512_4FMAPS:
	case ZYDIS_CATEGORY_AVX512_4VNNIW:
	case ZYDIS_CATEGORY_AVX512_BITALG:
	case ZYDIS_CATEGORY_AVX512_VBMI:
	case ZYDIS_CATEGORY_AVX512_VP2INTERSECT:
		op->family = R_ANAL_OP_FAMILY_VEC;
		break;
	case ZYDIS_CATEGORY_IO:
	case ZYDIS_CATEGORY_IOSTRINGOP:
		op->family = R_ANAL_OP_FAMILY_IO;
		break;
	case ZYDIS_CATEGORY_SGX:
	case ZYDIS_CATEGORY_CET:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		break;
	case ZYDIS_CATEGORY_VTX:
		op->family = R_ANAL_OP_FAMILY_VIRT;
		break;
	case ZYDIS_CATEGORY_SYSTEM:
		op->family = R_ANAL_OP_FAMILY_PRIV;
		break;
	default:
		break;
	}
}

static void set_mem_ref(RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *mop) {
	if (!mop || mop->type != ZYDIS_OPERAND_TYPE_MEMORY) {
		return;
	}
	op->refptr = operand_bytes (mop);
	op->ptrsize = op->refptr;
	if (is_mem_riprel (mop)) {
		op->ptr = op->addr + insn->length + mop->mem.disp.value;
	} else if (is_mem_abs (mop)) {
		op->ptr = mop->mem.disp.value;
	} else if (HAS_MEM_DISP (mop)) {
		op->disp = mop->mem.disp.value;
	}
	if (mop->mem.base != ZYDIS_REGISTER_NONE) {
		op->reg = zyreg (mop->mem.base);
	}
	if (mop->mem.index != ZYDIS_REGISTER_NONE) {
		op->ireg = zyreg (mop->mem.index);
	}
	op->scale = mop->mem.scale;
}

static bool op_writes_memory(const ZydisDecodedOperand *op) {
	return op && op->type == ZYDIS_OPERAND_TYPE_MEMORY
		&& (op->actions & (ZYDIS_OPERAND_ACTION_WRITE | ZYDIS_OPERAND_ACTION_CONDWRITE));
}

static bool op_reads_memory(const ZydisDecodedOperand *op) {
	return op && op->type == ZYDIS_OPERAND_TYPE_MEMORY
		&& (op->actions & (ZYDIS_OPERAND_ACTION_READ | ZYDIS_OPERAND_ACTION_CONDREAD));
}

static int operand_access(const ZydisDecodedOperand *op) {
	int access = 0;
	if (!op) {
		return access;
	}
	if (op->actions & (ZYDIS_OPERAND_ACTION_READ | ZYDIS_OPERAND_ACTION_CONDREAD)) {
		access |= R_PERM_R;
	}
	if (op->actions & (ZYDIS_OPERAND_ACTION_WRITE | ZYDIS_OPERAND_ACTION_CONDWRITE)) {
		access |= R_PERM_W;
	}
	return access;
}

static bool is_sp_reg(ZydisRegister reg) {
	switch (reg) {
	case ZYDIS_REGISTER_SP:
	case ZYDIS_REGISTER_ESP:
	case ZYDIS_REGISTER_RSP:
		return true;
	default:
		return false;
	}
}

static bool is_xmm_reg(ZydisRegister reg) {
	return reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM31;
}

static char *gpr64_from_32(const char *reg) {
	if (!reg || !*reg) {
		return NULL;
	}
	if (reg[0] == 'e') {
		if (!strcmp (reg, "eax")) {
			return strdup ("rax");
		}
		if (!strcmp (reg, "ebx")) {
			return strdup ("rbx");
		}
		if (!strcmp (reg, "ecx")) {
			return strdup ("rcx");
		}
		if (!strcmp (reg, "edx")) {
			return strdup ("rdx");
		}
		if (!strcmp (reg, "esp")) {
			return strdup ("rsp");
		}
		if (!strcmp (reg, "ebp")) {
			return strdup ("rbp");
		}
		if (!strcmp (reg, "esi")) {
			return strdup ("rsi");
		}
		if (!strcmp (reg, "edi")) {
			return strdup ("rdi");
		}
	} else if (reg[0] == 'r') {
		if (reg[1] >= '8' && reg[1] <= '9' && reg[2] == 'd' && !reg[3]) {
			return r_str_newf ("r%c", reg[1]);
		}
		if (reg[1] >= '1' && reg[1] <= '3' && reg[2] >= '0' && reg[2] <= '5' && reg[3] == 'd' && !reg[4]) {
			return r_str_newf ("r%c%c", reg[1], reg[2]);
		}
	}
	return NULL;
}

static const char *pc_reg(int bits) {
	switch (bits) {
	case 16:
		return "ip";
	case 32:
		return "eip";
	default:
		return "rip";
	}
}

static const char *sp_reg(int bits) {
	switch (bits) {
	case 16:
		return "sp";
	case 32:
		return "esp";
	default:
		return "rsp";
	}
}

static const char *bp_reg(int bits) {
	switch (bits) {
	case 16:
		return "bp";
	case 32:
		return "ebp";
	default:
		return "rbp";
	}
}

static ut64 pointer_value(RArchSession *as, const ZydisDecodedOperand *op) {
	if (!op || op->type != ZYDIS_OPERAND_TYPE_POINTER) {
		return UT64_MAX;
	}
	return ((ut64)op->ptr.segment << as->config->seggrn) + op->ptr.offset;
}

static void append_esil_mem_component(RStrBuf *sb, int *count, const char *component, bool subtract) {
	if (!component || !*component) {
		return;
	}
	if (*count == 0) {
		if (subtract) {
			r_strbuf_appendf (sb, "%s,0,-", component);
		} else {
			r_strbuf_append (sb, component);
		}
		(*count)++;
		return;
	}
	if (subtract) {
		r_strbuf_prependf (sb, "%s,", component);
		r_strbuf_append (sb, ",-");
	} else {
		r_strbuf_appendf (sb, ",%s,+", component);
	}
	(*count)++;
}

static char *memaddr_esil(const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *op, ut64 addr) {
	if (!op || op->type != ZYDIS_OPERAND_TYPE_MEMORY) {
		return NULL;
	}
	if (is_mem_riprel (op)) {
		return r_str_newf ("0x%"PFMT64x, addr + insn->length + op->mem.disp.value);
	}
	if (is_mem_abs (op)) {
		return r_str_newf ("0x%"PFMT64x, (ut64)op->mem.disp.value);
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	int count = 0;
	if (op->mem.base != ZYDIS_REGISTER_NONE) {
		append_esil_mem_component (sb, &count, zyreg (op->mem.base), false);
	}
	if (op->mem.index != ZYDIS_REGISTER_NONE) {
		char *index = NULL;
		if (op->mem.scale > 1) {
			index = r_str_newf ("%s,%u,*", zyreg (op->mem.index), op->mem.scale);
		} else {
			index = strdup (zyreg (op->mem.index));
		}
		append_esil_mem_component (sb, &count, index, false);
		free (index);
	}
	if (HAS_MEM_DISP (op) && op->mem.disp.value) {
		const st64 disp = op->mem.disp.value;
		char *d = r_str_newf ("0x%"PFMT64x, (ut64)R_ABS (disp));
		append_esil_mem_component (sb, &count, d, disp < 0);
		free (d);
	}
	if (!count) {
		r_strbuf_set (sb, "0");
	}
	return r_strbuf_drain (sb);
}

static char *operand_esil(const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *op, ut64 addr, int set, const char *setop, ut32 *bitsize) {
	if (bitsize) {
		*bitsize = op && op->size? op->size: 8;
	}
	if (!op) {
		return NULL;
	}
	const char *setarg = r_str_get (setop);
	switch (op->type) {
	case ZYDIS_OPERAND_TYPE_REGISTER:
		if (set == 1) {
			return r_str_newf ("%s,%s=", zyreg (op->reg.value), setarg);
		}
		return strdup (zyreg (op->reg.value));
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		if (set == 1) {
			return NULL;
		}
		return r_str_newf ("0x%"PFMT64x, zydis_imm_value (insn, op, addr));
	case ZYDIS_OPERAND_TYPE_MEMORY:
		{
			char *expr = memaddr_esil (insn, op, addr);
			if (!expr) {
				return NULL;
			}
			const int size = R_MAX (1, operand_bytes (op));
			char *ret = NULL;
			if (set == 1) {
				ret = r_str_newf ("%s,%s=[%d]", expr, setarg, size);
			} else if (set == 2) {
				ret = strdup (expr);
			} else {
				ret = r_str_newf ("%s,[%d]", expr, size);
			}
			free (expr);
			return ret;
		}
	case ZYDIS_OPERAND_TYPE_POINTER:
		if (set == 1) {
			return NULL;
		}
		return r_str_newf ("0x%"PFMT64x, ((ut64)op->ptr.segment << 4) + op->ptr.offset);
	default:
		break;
	}
	return NULL;
}

static int string_width_from_mnemonic(ZydisMnemonic mnemonic) {
	switch (mnemonic) {
	case ZYDIS_MNEMONIC_CMPSB:
	case ZYDIS_MNEMONIC_LODSB:
	case ZYDIS_MNEMONIC_MOVSB:
	case ZYDIS_MNEMONIC_SCASB:
	case ZYDIS_MNEMONIC_STOSB:
		return 1;
	case ZYDIS_MNEMONIC_CMPSW:
	case ZYDIS_MNEMONIC_LODSW:
	case ZYDIS_MNEMONIC_MOVSW:
	case ZYDIS_MNEMONIC_SCASW:
	case ZYDIS_MNEMONIC_STOSW:
		return 2;
	case ZYDIS_MNEMONIC_CMPSD:
	case ZYDIS_MNEMONIC_LODSD:
	case ZYDIS_MNEMONIC_MOVSD:
	case ZYDIS_MNEMONIC_SCASD:
	case ZYDIS_MNEMONIC_STOSD:
		return 4;
	case ZYDIS_MNEMONIC_CMPSQ:
	case ZYDIS_MNEMONIC_LODSQ:
	case ZYDIS_MNEMONIC_MOVSQ:
	case ZYDIS_MNEMONIC_SCASQ:
	case ZYDIS_MNEMONIC_STOSQ:
		return 8;
	default:
		return 0;
	}
}

static const char *counter_reg(int bits) {
	switch (bits) {
	case 16:
		return "cx";
	case 32:
		return "ecx";
	default:
		return "rcx";
	}
}

static const char *acc_reg(int width) {
	switch (width) {
	case 1:
		return "al";
	case 2:
		return "ax";
	case 4:
		return "eax";
	case 8:
		return "rax";
	default:
		return NULL;
	}
}

static const char *reg32_to_name(ut8 reg) {
	static const char *names[] = {
		"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"
	};
	return reg < R_ARRAY_SIZE (names)? names[reg]: "eax";
}

static const ZydisDecodedOperand *find_mem_operand(const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops, int access, int nth) {
	if (!insn || !ops) {
		return NULL;
	}
	size_t i;
	for (i = 0; i < insn->operand_count; i++) {
		const ZydisDecodedOperand *zop = &ops[i];
		if (zop->type != ZYDIS_OPERAND_TYPE_MEMORY) {
			continue;
		}
		if (access == R_PERM_R && !(zop->actions & (ZYDIS_OPERAND_ACTION_READ | ZYDIS_OPERAND_ACTION_CONDREAD))) {
			continue;
		}
		if (access == R_PERM_W && !(zop->actions & (ZYDIS_OPERAND_ACTION_WRITE | ZYDIS_OPERAND_ACTION_CONDWRITE))) {
			continue;
		}
		if (!nth--) {
			return zop;
		}
	}
	return NULL;
}

static void append_df_update(RStrBuf *sb, int width, const char *reg0, const char *reg1) {
	if (width < 1 || !reg0 || !*reg0) {
		return;
	}
	r_strbuf_appendf (sb, ",df,?{,%d,%s,-=", width, reg0);
	if (reg1 && *reg1) {
		r_strbuf_appendf (sb, ",%d,%s,-=", width, reg1);
	}
	r_strbuf_append (sb, ",},df,!,?{,");
	r_strbuf_appendf (sb, "%d,%s,+=", width, reg0);
	if (reg1 && *reg1) {
		r_strbuf_appendf (sb, ",%d,%s,+=", width, reg1);
	}
	r_strbuf_append (sb, ",}");
}

static void append_rep_tail(RStrBuf *sb, const ZydisDecodedInstruction *insn, const char *counter) {
	if (!counter || !(insn->attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE))) {
		return;
	}
	r_strbuf_appendf (sb, ",%s,--=", counter);
	if (insn->attributes & ZYDIS_ATTRIB_HAS_REPNE) {
		r_strbuf_appendf (sb, ",%s,?{,zf,!,?{,0,GOTO,},}", counter);
	} else if (insn->attributes & ZYDIS_ATTRIB_HAS_REPE) {
		r_strbuf_appendf (sb, ",%s,?{,zf,?{,0,GOTO,},}", counter);
	} else {
		r_strbuf_append (sb, ",0,GOTO");
	}
}

static void set_cmp_expr_esil(RAnalOp *op, const char *src, const char *dst, ut32 bitsize) {
	if (!src || !dst || !bitsize || bitsize > 64) {
		return;
	}
	esilprintf (op, "%s,%s,==,$z,zf,:=,%u,$b,cf,:=,$p,pf,:=,%u,$s,sf,:=,%s,0x%"PFMT64x",-,!,%u,$o,^,of,:=,3,$b,af,:=",
		src, dst, bitsize, bitsize - 1, src, (ut64)(1ULL << (bitsize - 1)), bitsize - 1);
}

static const char *cond_esil(ZydisMnemonic mnemonic) {
	switch (mnemonic) {
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_CMOVZ:
	case ZYDIS_MNEMONIC_SETZ:
		return "zf";
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_CMOVNZ:
	case ZYDIS_MNEMONIC_SETNZ:
		return "zf,!";
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_CMOVO:
	case ZYDIS_MNEMONIC_SETO:
		return "of";
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_CMOVNO:
	case ZYDIS_MNEMONIC_SETNO:
		return "of,!";
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_CMOVP:
	case ZYDIS_MNEMONIC_SETP:
		return "pf";
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_CMOVNP:
	case ZYDIS_MNEMONIC_SETNP:
		return "pf,!";
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_CMOVS:
	case ZYDIS_MNEMONIC_SETS:
		return "sf";
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_CMOVNS:
	case ZYDIS_MNEMONIC_SETNS:
		return "sf,!";
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_CMOVB:
	case ZYDIS_MNEMONIC_SETB:
		return "cf";
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_CMOVNB:
	case ZYDIS_MNEMONIC_SETNB:
		return "cf,!";
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_CMOVL:
	case ZYDIS_MNEMONIC_SETL:
		return "sf,of,^";
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_CMOVLE:
	case ZYDIS_MNEMONIC_SETLE:
		return "zf,sf,of,^,|";
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_CMOVNLE:
	case ZYDIS_MNEMONIC_SETNLE:
		return "zf,!,sf,of,^,!,&";
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_CMOVNL:
	case ZYDIS_MNEMONIC_SETNL:
		return "sf,of,^,!";
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_CMOVNBE:
	case ZYDIS_MNEMONIC_SETNBE:
		return "cf,zf,|,!";
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_CMOVBE:
	case ZYDIS_MNEMONIC_SETBE:
		return "cf,zf,|";
	default:
		break;
	}
	return NULL;
}

static bool is_jcc(ZydisMnemonic mnemonic) {
	switch (mnemonic) {
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JRCXZ:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_LOOP:
	case ZYDIS_MNEMONIC_LOOPE:
	case ZYDIS_MNEMONIC_LOOPNE:
		return true;
	default:
		return false;
	}
}

static bool is_setcc(ZydisMnemonic mnemonic) {
	switch (mnemonic) {
	case ZYDIS_MNEMONIC_SETB:
	case ZYDIS_MNEMONIC_SETBE:
	case ZYDIS_MNEMONIC_SETL:
	case ZYDIS_MNEMONIC_SETLE:
	case ZYDIS_MNEMONIC_SETNB:
	case ZYDIS_MNEMONIC_SETNBE:
	case ZYDIS_MNEMONIC_SETNL:
	case ZYDIS_MNEMONIC_SETNLE:
	case ZYDIS_MNEMONIC_SETNO:
	case ZYDIS_MNEMONIC_SETNP:
	case ZYDIS_MNEMONIC_SETNS:
	case ZYDIS_MNEMONIC_SETNZ:
	case ZYDIS_MNEMONIC_SETO:
	case ZYDIS_MNEMONIC_SETP:
	case ZYDIS_MNEMONIC_SETS:
	case ZYDIS_MNEMONIC_SETZ:
		return true;
	default:
		return false;
	}
}

static RAnalValue *new_access_value(int type, int access, const char *reg, st64 delta, int memref) {
	RAnalValue *val = R_NEW0 (RAnalValue);
	if (val) {
		val->type = type;
		val->access = access;
		val->reg = reg;
		val->delta = delta;
		val->memref = memref;
	}
	return val;
}

static void set_value_from_operand(RAnalValue *val, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *op, ut64 addr) {
	if (!val || !op) {
		return;
	}
	switch (op->type) {
	case ZYDIS_OPERAND_TYPE_REGISTER:
		val->type = R_ANAL_VAL_REG;
		val->reg = zyreg (op->reg.value);
		break;
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		val->type = R_ANAL_VAL_IMM;
		val->imm = zydis_imm_value (insn, op, addr);
		break;
	case ZYDIS_OPERAND_TYPE_MEMORY:
		val->type = R_ANAL_VAL_MEM;
		val->memref = operand_bytes (op);
		val->delta = op->mem.disp.value;
		val->mul = op->mem.scale;
		val->seg = op->mem.segment != ZYDIS_REGISTER_NONE? zyreg (op->mem.segment): NULL;
		val->reg = op->mem.base != ZYDIS_REGISTER_NONE? zyreg (op->mem.base): NULL;
		val->regdelta = op->mem.index != ZYDIS_REGISTER_NONE? zyreg (op->mem.index): NULL;
		if (is_mem_riprel (op)) {
			val->base = addr + insn->length;
		} else if (is_mem_abs (op)) {
			val->base = op->mem.disp.value;
			val->delta = 0;
			val->absolute = true;
		}
		break;
	default:
		break;
	}
}

static void add_src_dst(RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *zop, ut64 addr, bool dst) {
	RAnalValue *val = RVecRArchValue_emplace_back (dst? &op->dsts: &op->srcs);
	set_value_from_operand (val, insn, zop, addr);
}

static void add_reg_src_dst(RAnalOp *op, const char *reg, bool dst) {
	if (!op || !reg) {
		return;
	}
	RAnalValue *val = RVecRArchValue_emplace_back (dst? &op->dsts: &op->srcs);
	val->type = R_ANAL_VAL_REG;
	val->reg = reg;
}

static void set_access_info(RArchSession *as, RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops) {
	RList *ret = r_list_newf ((RListFree)r_anal_value_free);
	if (!ret) {
		return;
	}
	const int regsz = R_SYS_BITS_CHECK (as->config->bits, 64)? 8: R_SYS_BITS_CHECK (as->config->bits, 16)? 2: 4;
	size_t i;
	for (i = 0; i < insn->operand_count; i++) {
		const ZydisDecodedOperand *zop = &ops[i];
		const int access = operand_access (zop);
		if (!access) {
			continue;
		}
		RAnalValue *val = NULL;
		switch (zop->type) {
		case ZYDIS_OPERAND_TYPE_REGISTER:
			val = new_access_value (R_ANAL_VAL_REG, access, zyreg (zop->reg.value), 0, 0);
			break;
		case ZYDIS_OPERAND_TYPE_MEMORY:
			val = new_access_value (R_ANAL_VAL_MEM, access,
				zop->mem.base != ZYDIS_REGISTER_NONE? zyreg (zop->mem.base): NULL,
				zop->mem.disp.value, operand_bytes (zop));
			if (val) {
				val->mul = zop->mem.scale;
				val->seg = zop->mem.segment != ZYDIS_REGISTER_NONE? zyreg (zop->mem.segment): NULL;
				val->regdelta = zop->mem.index != ZYDIS_REGISTER_NONE? zyreg (zop->mem.index): NULL;
				if (is_mem_riprel (zop)) {
					val->base = op->addr + insn->length;
				} else if (is_mem_abs (zop)) {
					val->base = zop->mem.disp.value;
					val->delta = 0;
					val->absolute = true;
				}
			}
			break;
		default:
			break;
		}
		if (val) {
			r_list_append (ret, val);
		}
	}
	switch (insn->mnemonic) {
	case ZYDIS_MNEMONIC_PUSH:
	case ZYDIS_MNEMONIC_PUSHF:
	case ZYDIS_MNEMONIC_PUSHFD:
	case ZYDIS_MNEMONIC_PUSHFQ:
	case ZYDIS_MNEMONIC_CALL:
		r_list_append (ret, new_access_value (R_ANAL_VAL_MEM, R_PERM_W, sp_reg (as->config->bits), -regsz, regsz));
		break;
	case ZYDIS_MNEMONIC_POP:
	case ZYDIS_MNEMONIC_POPF:
	case ZYDIS_MNEMONIC_POPFD:
	case ZYDIS_MNEMONIC_POPFQ:
	case ZYDIS_MNEMONIC_RET:
		r_list_append (ret, new_access_value (R_ANAL_VAL_MEM, R_PERM_R, sp_reg (as->config->bits), 0, regsz));
		break;
	default:
		break;
	}
	op->access = ret;
}

static void op_fillval(RArchSession *as, RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops) {
	set_access_info (as, op, insn, ops);
	size_t i;
	for (i = 0; i < insn->operand_count_visible; i++) {
		const ZydisDecodedOperand *zop = &ops[i];
		if (zop->actions & (ZYDIS_OPERAND_ACTION_READ | ZYDIS_OPERAND_ACTION_CONDREAD)) {
			add_src_dst (op, insn, zop, op->addr, false);
		}
		if (zop->actions & (ZYDIS_OPERAND_ACTION_WRITE | ZYDIS_OPERAND_ACTION_CONDWRITE)) {
			add_src_dst (op, insn, zop, op->addr, true);
		}
	}
	if ((insn->mnemonic == ZYDIS_MNEMONIC_IMUL || insn->mnemonic == ZYDIS_MNEMONIC_MUL)
			&& insn->operand_count_visible == 1) {
		const ZydisDecodedOperand *op0 = visible_op (insn, ops, 0);
		const char *acc = op0? acc_reg (operand_bytes (op0)): NULL;
		if (acc) {
			if (RVecRArchValue_empty (&op->dsts)) {
				add_reg_src_dst (op, acc, true);
			}
			while (RVecRArchValue_length (&op->srcs) < 2) {
				add_reg_src_dst (op, acc, false);
			}
		}
	}
}

static void set_op_type(RArchSession *as, RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops) {
	const ZydisDecodedOperand *op0 = visible_op (insn, ops, 0);
	const ZydisDecodedOperand *op1 = visible_op (insn, ops, 1);
	const int regsz = R_SYS_BITS_CHECK (as->config->bits, 64)? 8: R_SYS_BITS_CHECK (as->config->bits, 16)? 2: 4;

	op->type = R_ANAL_OP_TYPE_UNK;
	op->cycles = 1;
	op->cond = cond_x86_zydis (insn->mnemonic);
	if (op0 && op0->type == ZYDIS_OPERAND_TYPE_MEMORY) {
		set_mem_ref (op, insn, op0);
	} else if (op1 && op1->type == ZYDIS_OPERAND_TYPE_MEMORY) {
		set_mem_ref (op, insn, op1);
	}

	switch (insn->mnemonic) {
	case ZYDIS_MNEMONIC_INVALID:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case ZYDIS_MNEMONIC_NOP:
	case ZYDIS_MNEMONIC_ENDBR32:
	case ZYDIS_MNEMONIC_ENDBR64:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case ZYDIS_MNEMONIC_CALL:
		op->fail = op->addr + op->size;
		if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = zydis_imm_value (insn, op0, op->addr);
		} else if (op0 && op0->type == ZYDIS_OPERAND_TYPE_POINTER) {
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = pointer_value (as, op0);
			op->ptr = op0->ptr.offset;
			op->val = op0->ptr.segment;
		} else if (op0 && op0->type == ZYDIS_OPERAND_TYPE_MEMORY) {
			op->type = (op0->mem.base != ZYDIS_REGISTER_NONE
				|| op0->mem.index != ZYDIS_REGISTER_NONE)? R_ANAL_OP_TYPE_IRCALL: R_ANAL_OP_TYPE_ICALL;
		} else if (op0 && op0->type == ZYDIS_OPERAND_TYPE_REGISTER) {
			op->type = R_ANAL_OP_TYPE_RCALL;
			op->reg = zyreg (op0->reg.value);
		} else {
			op->type = R_ANAL_OP_TYPE_UCALL;
		}
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = regsz;
		break;
	case ZYDIS_MNEMONIC_JMP:
		if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = zydis_imm_value (insn, op0, op->addr);
		} else if (op0 && op0->type == ZYDIS_OPERAND_TYPE_POINTER) {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = pointer_value (as, op0);
			op->ptr = op0->ptr.offset;
			op->val = op0->ptr.segment;
		} else if (op0 && op0->type == ZYDIS_OPERAND_TYPE_MEMORY) {
			op->type = (op0->mem.base != ZYDIS_REGISTER_NONE
				|| op0->mem.index != ZYDIS_REGISTER_NONE)? R_ANAL_OP_TYPE_IRJMP: R_ANAL_OP_TYPE_MJMP;
		} else if (op0 && op0->type == ZYDIS_OPERAND_TYPE_REGISTER) {
			op->type = R_ANAL_OP_TYPE_RJMP;
			op->reg = zyreg (op0->reg.value);
		} else {
			op->type = R_ANAL_OP_TYPE_UJMP;
		}
		op->eob = true;
		break;
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JRCXZ:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_LOOP:
	case ZYDIS_MNEMONIC_LOOPE:
	case ZYDIS_MNEMONIC_LOOPNE:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->fail = op->addr + op->size;
		if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			op->jump = zydis_imm_value (insn, op0, op->addr);
		}
		break;
	case ZYDIS_MNEMONIC_RET:
	case ZYDIS_MNEMONIC_IRET:
	case ZYDIS_MNEMONIC_IRETD:
	case ZYDIS_MNEMONIC_IRETQ:
	case ZYDIS_MNEMONIC_SYSRET:
		op->type = R_ANAL_OP_TYPE_RET;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -regsz;
		if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			op->stackptr -= (st64)zydis_imm_value (insn, op0, op->addr);
		}
		op->eob = true;
		break;
	case ZYDIS_MNEMONIC_INT:
		op->type = R_ANAL_OP_TYPE_SWI;
		if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			op->val = zydis_imm_value (insn, op0, op->addr);
		}
		op->eob = true;
		break;
	case ZYDIS_MNEMONIC_INT1:
	case ZYDIS_MNEMONIC_INT3:
	case ZYDIS_MNEMONIC_INTO:
		op->type = R_ANAL_OP_TYPE_TRAP;
		if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			op->val = zydis_imm_value (insn, op0, op->addr);
		}
		op->eob = true;
		break;
	case ZYDIS_MNEMONIC_SYSCALL:
	case ZYDIS_MNEMONIC_SYSENTER:
		op->type = R_ANAL_OP_TYPE_SWI;
		op->family = R_ANAL_OP_FAMILY_PRIV;
		break;
	case ZYDIS_MNEMONIC_PUSH:
	case ZYDIS_MNEMONIC_PUSHF:
	case ZYDIS_MNEMONIC_PUSHFD:
	case ZYDIS_MNEMONIC_PUSHFQ:
	case ZYDIS_MNEMONIC_PUSHA:
	case ZYDIS_MNEMONIC_PUSHAD:
		op->type = (op0 && op0->type == ZYDIS_OPERAND_TYPE_REGISTER)? R_ANAL_OP_TYPE_RPUSH: R_ANAL_OP_TYPE_PUSH;
		if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			op->val = op->ptr = zydis_imm_value (insn, op0, op->addr);
		}
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = (insn->mnemonic == ZYDIS_MNEMONIC_PUSHAD || insn->mnemonic == ZYDIS_MNEMONIC_PUSHA)? regsz * 8: regsz;
		break;
	case ZYDIS_MNEMONIC_POP:
	case ZYDIS_MNEMONIC_POPF:
	case ZYDIS_MNEMONIC_POPFD:
	case ZYDIS_MNEMONIC_POPFQ:
	case ZYDIS_MNEMONIC_POPA:
	case ZYDIS_MNEMONIC_POPAD:
		op->type = R_ANAL_OP_TYPE_POP;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = (insn->mnemonic == ZYDIS_MNEMONIC_POPAD || insn->mnemonic == ZYDIS_MNEMONIC_POPA)? -regsz * 8: -regsz;
		break;
	case ZYDIS_MNEMONIC_ENTER:
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = regsz;
		if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			op->stackptr += zydis_imm_value (insn, op0, op->addr);
		}
		break;
	case ZYDIS_MNEMONIC_LEAVE:
		op->type = R_ANAL_OP_TYPE_LEAVE;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -regsz;
		break;
	case ZYDIS_MNEMONIC_LEA:
		op->type = R_ANAL_OP_TYPE_LEA;
		if (op0 && op1 && op0->type == ZYDIS_OPERAND_TYPE_REGISTER
				&& op1->type == ZYDIS_OPERAND_TYPE_MEMORY
				&& is_sp_reg (op0->reg.value)
				&& is_sp_reg (op1->mem.base)
				&& op1->mem.index == ZYDIS_REGISTER_NONE
				&& HAS_MEM_DISP (op1)) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = op1->mem.disp.value;
		}
		break;
	case ZYDIS_MNEMONIC_MOV:
	case ZYDIS_MNEMONIC_MOVAPS:
	case ZYDIS_MNEMONIC_MOVSD:
	case ZYDIS_MNEMONIC_MOVSX:
	case ZYDIS_MNEMONIC_MOVSXD:
	case ZYDIS_MNEMONIC_MOVUPS:
	case ZYDIS_MNEMONIC_MOVZX:
	case ZYDIS_MNEMONIC_MOVSB:
	case ZYDIS_MNEMONIC_MOVSQ:
	case ZYDIS_MNEMONIC_MOVSW:
		if (op_writes_memory (op0)) {
			op->type = R_ANAL_OP_TYPE_STORE;
		} else if (op_reads_memory (op1)) {
			op->type = R_ANAL_OP_TYPE_LOAD;
		} else {
			op->type = R_ANAL_OP_TYPE_MOV;
		}
		if (op1 && op1->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			op->val = zydis_imm_value (insn, op1, op->addr);
		}
		break;
	case ZYDIS_MNEMONIC_STOSB:
	case ZYDIS_MNEMONIC_STOSD:
	case ZYDIS_MNEMONIC_STOSQ:
	case ZYDIS_MNEMONIC_STOSW:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case ZYDIS_MNEMONIC_LODSB:
	case ZYDIS_MNEMONIC_LODSD:
	case ZYDIS_MNEMONIC_LODSQ:
	case ZYDIS_MNEMONIC_LODSW:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case ZYDIS_MNEMONIC_CMOVB:
	case ZYDIS_MNEMONIC_CMOVBE:
	case ZYDIS_MNEMONIC_CMOVL:
	case ZYDIS_MNEMONIC_CMOVLE:
	case ZYDIS_MNEMONIC_CMOVNB:
	case ZYDIS_MNEMONIC_CMOVNBE:
	case ZYDIS_MNEMONIC_CMOVNL:
	case ZYDIS_MNEMONIC_CMOVNLE:
	case ZYDIS_MNEMONIC_CMOVNO:
	case ZYDIS_MNEMONIC_CMOVNP:
	case ZYDIS_MNEMONIC_CMOVNS:
	case ZYDIS_MNEMONIC_CMOVNZ:
	case ZYDIS_MNEMONIC_CMOVO:
	case ZYDIS_MNEMONIC_CMOVP:
	case ZYDIS_MNEMONIC_CMOVS:
	case ZYDIS_MNEMONIC_CMOVZ:
		op->type = R_ANAL_OP_TYPE_CMOV;
		break;
	case ZYDIS_MNEMONIC_SETB:
	case ZYDIS_MNEMONIC_SETBE:
	case ZYDIS_MNEMONIC_SETL:
	case ZYDIS_MNEMONIC_SETLE:
	case ZYDIS_MNEMONIC_SETNB:
	case ZYDIS_MNEMONIC_SETNBE:
	case ZYDIS_MNEMONIC_SETNL:
	case ZYDIS_MNEMONIC_SETNLE:
	case ZYDIS_MNEMONIC_SETNO:
	case ZYDIS_MNEMONIC_SETNP:
	case ZYDIS_MNEMONIC_SETNS:
	case ZYDIS_MNEMONIC_SETNZ:
	case ZYDIS_MNEMONIC_SETO:
	case ZYDIS_MNEMONIC_SETP:
	case ZYDIS_MNEMONIC_SETS:
	case ZYDIS_MNEMONIC_SETZ:
		op->type = R_ANAL_OP_TYPE_CMOV;
		break;
	case ZYDIS_MNEMONIC_CMP:
	case ZYDIS_MNEMONIC_BT:
	case ZYDIS_MNEMONIC_BTC:
	case ZYDIS_MNEMONIC_BTR:
	case ZYDIS_MNEMONIC_BTS:
	case ZYDIS_MNEMONIC_CMPSB:
	case ZYDIS_MNEMONIC_CMPSD:
	case ZYDIS_MNEMONIC_CMPSQ:
	case ZYDIS_MNEMONIC_CMPSW:
	case ZYDIS_MNEMONIC_SCASB:
	case ZYDIS_MNEMONIC_SCASD:
	case ZYDIS_MNEMONIC_SCASQ:
	case ZYDIS_MNEMONIC_SCASW:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case ZYDIS_MNEMONIC_TEST:
		op->type = R_ANAL_OP_TYPE_ACMP;
		break;
	case ZYDIS_MNEMONIC_ADD:
	case ZYDIS_MNEMONIC_ADC:
	case ZYDIS_MNEMONIC_INC:
	case ZYDIS_MNEMONIC_XADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (op1 && op1->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			op->val = zydis_imm_value (insn, op1, op->addr);
		}
		if (op0 && op1 && op0->type == ZYDIS_OPERAND_TYPE_REGISTER
				&& op1->type == ZYDIS_OPERAND_TYPE_IMMEDIATE
				&& is_sp_reg (op0->reg.value)) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = (st64)zydis_imm_value (insn, op1, op->addr);
		}
		break;
	case ZYDIS_MNEMONIC_SUB:
	case ZYDIS_MNEMONIC_SBB:
	case ZYDIS_MNEMONIC_DEC:
		op->type = R_ANAL_OP_TYPE_SUB;
		if (op1 && op1->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			op->val = zydis_imm_value (insn, op1, op->addr);
		}
		if (op0 && op1 && op0->type == ZYDIS_OPERAND_TYPE_REGISTER
				&& op1->type == ZYDIS_OPERAND_TYPE_IMMEDIATE
				&& is_sp_reg (op0->reg.value)) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)zydis_imm_value (insn, op1, op->addr);
		}
		break;
	case ZYDIS_MNEMONIC_MUL:
	case ZYDIS_MNEMONIC_IMUL:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case ZYDIS_MNEMONIC_DIV:
	case ZYDIS_MNEMONIC_IDIV:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case ZYDIS_MNEMONIC_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case ZYDIS_MNEMONIC_OR:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case ZYDIS_MNEMONIC_XOR:
	case ZYDIS_MNEMONIC_PXOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case ZYDIS_MNEMONIC_CPUID:
	case ZYDIS_MNEMONIC_BSF:
	case ZYDIS_MNEMONIC_BSR:
	case ZYDIS_MNEMONIC_BSWAP:
	case ZYDIS_MNEMONIC_CLC:
	case ZYDIS_MNEMONIC_CLD:
	case ZYDIS_MNEMONIC_CLI:
	case ZYDIS_MNEMONIC_CMC:
	case ZYDIS_MNEMONIC_STC:
	case ZYDIS_MNEMONIC_STD:
	case ZYDIS_MNEMONIC_STI:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ZYDIS_MNEMONIC_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case ZYDIS_MNEMONIC_NEG:
		op->type = R_ANAL_OP_TYPE_CPL;
		break;
	case ZYDIS_MNEMONIC_SHL:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case ZYDIS_MNEMONIC_SHR:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case ZYDIS_MNEMONIC_SAR:
		op->type = R_ANAL_OP_TYPE_SAR;
		break;
	case ZYDIS_MNEMONIC_ROL:
	case ZYDIS_MNEMONIC_RCL:
		op->type = R_ANAL_OP_TYPE_ROL;
		break;
	case ZYDIS_MNEMONIC_ROR:
	case ZYDIS_MNEMONIC_RCR:
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case ZYDIS_MNEMONIC_XCHG:
		op->type = R_ANAL_OP_TYPE_XCHG;
		break;
	case ZYDIS_MNEMONIC_IN:
	case ZYDIS_MNEMONIC_OUT:
		op->type = R_ANAL_OP_TYPE_IO;
		break;
	case ZYDIS_MNEMONIC_HLT:
	case ZYDIS_MNEMONIC_UD0:
	case ZYDIS_MNEMONIC_UD1:
	case ZYDIS_MNEMONIC_UD2:
		op->type = R_ANAL_OP_TYPE_ILL;
		op->eob = true;
		break;
	default:
		switch (insn->meta.category) {
		case ZYDIS_CATEGORY_CALL:
			op->type = R_ANAL_OP_TYPE_UCALL;
			op->fail = op->addr + op->size;
			break;
		case ZYDIS_CATEGORY_COND_BR:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = op->addr + op->size;
			if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				op->jump = zydis_imm_value (insn, op0, op->addr);
			}
			break;
		case ZYDIS_CATEGORY_UNCOND_BR:
			op->type = R_ANAL_OP_TYPE_UJMP;
			break;
		case ZYDIS_CATEGORY_RET:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case ZYDIS_CATEGORY_PUSH:
			op->type = R_ANAL_OP_TYPE_PUSH;
			break;
		case ZYDIS_CATEGORY_POP:
			op->type = R_ANAL_OP_TYPE_POP;
			break;
		case ZYDIS_CATEGORY_NOP:
		case ZYDIS_CATEGORY_WIDENOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		default:
			break;
		}
		break;
	}
}

static void set_opdir(RAnalOp *op) {
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_LOAD:
		op->direction = R_ANAL_OP_DIR_READ;
		break;
	case R_ANAL_OP_TYPE_STORE:
		op->direction = R_ANAL_OP_DIR_WRITE;
		break;
	case R_ANAL_OP_TYPE_LEA:
		op->direction = R_ANAL_OP_DIR_REF;
		break;
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
		op->direction = R_ANAL_OP_DIR_EXEC;
		break;
	default:
		break;
	}
}

static void set_logic_esil(RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops, const char *setop) {
	const ZydisDecodedOperand *op0 = visible_op (insn, ops, 0);
	const ZydisDecodedOperand *op1 = visible_op (insn, ops, 1);
	ut32 bitsize = 0;
	char *src = operand_esil (insn, op1, op->addr, 0, NULL, NULL);
	char *dst = operand_esil (insn, op0, op->addr, 1, setop, &bitsize);
	if (src && dst && bitsize) {
		esilprintf (op, "%s,%s,$z,zf,:=,$p,pf,:=,%u,$s,sf,:=,0,cf,:=,0,of,:=", src, dst, bitsize - 1);
	}
	free (src);
	free (dst);
}

static void set_add_esil(RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops, bool carry) {
	const ZydisDecodedOperand *op0 = visible_op (insn, ops, 0);
	const ZydisDecodedOperand *op1 = visible_op (insn, ops, 1);
	ut32 bitsize = 0;
	char *src = operand_esil (insn, op1, op->addr, 0, NULL, NULL);
	char *dst = operand_esil (insn, op0, op->addr, 1, "+", &bitsize);
	if (src && dst && bitsize) {
		if (carry) {
			esilprintf (op, "cf,%s,+,%s,%u,$o,of,:=,%u,$s,sf,:=,$z,zf,:=,%u,$c,cf,:=,$p,pf,:=,3,$c,af,:=",
				src, dst, bitsize - 1, bitsize - 1, bitsize - 1);
		} else {
			esilprintf (op, "%s,%s,%u,$o,of,:=,%u,$s,sf,:=,$z,zf,:=,%u,$c,cf,:=,$p,pf,:=,3,$c,af,:=",
				src, dst, bitsize - 1, bitsize - 1, bitsize - 1);
		}
	}
	free (src);
	free (dst);
}

static void set_sub_esil(RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops, bool borrow) {
	const ZydisDecodedOperand *op0 = visible_op (insn, ops, 0);
	const ZydisDecodedOperand *op1 = visible_op (insn, ops, 1);
	ut32 bitsize = 0;
	char *src = operand_esil (insn, op1, op->addr, 0, NULL, NULL);
	char *dst = operand_esil (insn, op0, op->addr, 1, "-", &bitsize);
	if (src && dst && bitsize && bitsize <= 64) {
		if (borrow) {
			esilprintf (op, "cf,%s,+,%s,%u,$o,of,:=,%u,$s,sf,:=,$z,zf,:=,$p,pf,:=,%u,$b,cf,:=,3,$b,af,:=",
				src, dst, bitsize - 1, bitsize - 1, bitsize);
		} else {
			esilprintf (op, "%s,%s,%s,0x%"PFMT64x",-,!,%u,$o,^,of,:=,%u,$s,sf,:=,$z,zf,:=,$p,pf,:=,%u,$b,cf,:=,3,$b,af,:=",
				src, dst, src, (ut64)(1ULL << (bitsize - 1)), bitsize - 1, bitsize - 1, bitsize);
		}
	}
	free (src);
	free (dst);
}

static void set_cmp_esil(RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops, bool test) {
	const ZydisDecodedOperand *op0 = visible_op (insn, ops, 0);
	const ZydisDecodedOperand *op1 = visible_op (insn, ops, 1);
	ut32 bitsize = 0;
	char *src = operand_esil (insn, op1, op->addr, 0, NULL, NULL);
	char *dst = operand_esil (insn, op0, op->addr, 0, NULL, &bitsize);
	if (src && dst && bitsize && bitsize <= 64) {
		if (test) {
			esilprintf (op, "0,%s,%s,&,==,$z,zf,:=,$p,pf,:=,%u,$s,sf,:=,0,cf,:=,0,of,:=", src, dst, bitsize - 1);
		} else {
			esilprintf (op, "%s,%s,==,$z,zf,:=,%u,$b,cf,:=,$p,pf,:=,%u,$s,sf,:=,%s,0x%"PFMT64x",-,!,%u,$o,^,of,:=,3,$b,af,:=",
				src, dst, bitsize, bitsize - 1, src, (ut64)(1ULL << (bitsize - 1)), bitsize - 1);
		}
	}
	free (src);
	free (dst);
}

static void set_shift_esil(RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops, const char *shiftop) {
	const ZydisDecodedOperand *op0 = visible_op (insn, ops, 0);
	const ZydisDecodedOperand *op1 = visible_op (insn, ops, 1);
	ut32 bitsize = 0;
	char *src = operand_esil (insn, op1, op->addr, 0, NULL, NULL);
	char *dst = operand_esil (insn, op0, op->addr, 1, NULL, &bitsize);
	char *dst_r = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
	if (src && dst && dst_r && bitsize) {
		if (!strcmp (shiftop, ">>") || !strcmp (shiftop, "ASR")) {
			esilprintf (op, "0,cf,:=,1,%s,-,1,<<,%s,&,?{,1,cf,:=,},%s,%s,%s,%s,$z,zf,:=,$p,pf,:=,%u,$s,sf,:=",
				src, dst_r, src, dst_r, shiftop, dst, bitsize - 1);
		} else if (!strcmp (shiftop, "<<")) {
			char *dst_s = operand_esil (insn, op0, op->addr, 1, "<<", NULL);
			ut64 sign = bitsize == 64? UT64_MAX ^ (UT64_MAX >> 1): 1ULL << (bitsize - 1);
			if (dst_s) {
				esilprintf (op, "%s,0x%"PFMT64x",&,POP,$z,cf,:=,%s,%s,$z,zf,:=,$p,pf,:=,%u,$s,sf,:=",
					dst_r, sign, src, dst_s, bitsize - 1);
			}
			free (dst_s);
		} else {
			esilprintf (op, "%s,%s,%s,%s,$z,zf,:=,$p,pf,:=,%u,$s,sf,:=", src, dst_r, shiftop, dst, bitsize - 1);
		}
	}
	free (src);
	free (dst);
	free (dst_r);
}

static void set_mov_esil(RArchSession *as, RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *op0, const ZydisDecodedOperand *op1) {
	ut32 srcbits = 0;
	char *src = operand_esil (insn, op1, op->addr, 0, NULL, &srcbits);
	if (!src) {
		return;
	}
	char *dst = NULL;
	char *dst_r = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
	char *dst64 = (as->config->bits == 64 && op0 && op0->type == ZYDIS_OPERAND_TYPE_REGISTER && op0->size == 32)? gpr64_from_32 (dst_r): NULL;
	if (dst64) {
		if (insn->mnemonic == ZYDIS_MNEMONIC_MOVSX || insn->mnemonic == ZYDIS_MNEMONIC_MOVSXD) {
			esilprintf (op, "%u,%s,~,0xffffffff,&,%s,=", srcbits, src, dst64);
		} else {
			esilprintf (op, "%s,%s,=", src, dst64);
		}
	} else {
		dst = operand_esil (insn, op0, op->addr, 1, NULL, NULL);
		if (dst) {
			if (insn->mnemonic == ZYDIS_MNEMONIC_MOVSX || insn->mnemonic == ZYDIS_MNEMONIC_MOVSXD) {
				esilprintf (op, "%u,%s,~,%s", srcbits, src, dst);
			} else {
				esilprintf (op, "%s,%s", src, dst);
			}
		}
	}
	free (src);
	free (dst);
	free (dst_r);
	free (dst64);
}

static void set_xchg_esil(RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *op0, const ZydisDecodedOperand *op1, bool add_after) {
	char *op0r = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
	char *op1r = operand_esil (insn, op1, op->addr, 0, NULL, NULL);
	char *op0w = operand_esil (insn, op0, op->addr, 1, NULL, NULL);
	char *op1w = operand_esil (insn, op1, op->addr, 1, NULL, NULL);
	char *op0add = add_after? operand_esil (insn, op0, op->addr, 1, "+", NULL): NULL;
	if (op0r && op1r && op0w && op1w) {
		if (!strcmp (op0r, op1r)) {
			esilprintf (op, ",");
		} else if (add_after && op0add) {
			esilprintf (op, "%s,%s,^,%s,%s,%s,^,%s,%s,%s,^,%s,%s,%s",
				op0r, op1r, op1w,
				op1r, op0r, op0w,
				op0r, op1r, op1w,
				op1r, op0add);
		} else {
			esilprintf (op, "%s,%s,^,%s,%s,%s,^,%s,%s,%s,^,%s",
				op0r, op1r, op1w,
				op1r, op0r, op0w,
				op0r, op1r, op1w);
		}
	}
	free (op0r);
	free (op1r);
	free (op0w);
	free (op1w);
	free (op0add);
}

static void set_bsf_bsr_esil(RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops, bool reverse) {
	const ZydisDecodedOperand *op0 = visible_op (insn, ops, 0);
	const ZydisDecodedOperand *op1 = visible_op (insn, ops, 1);
	char *src = operand_esil (insn, op1, op->addr, 0, NULL, NULL);
	char *dst = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
	const ut32 bits = op0 && op0->size? op0->size: 0;
	if (src && dst && bits && bits <= 64) {
		if (strcmp (src, dst)) {
			const ut32 commas = r_str_char_count (src, ',');
			if (reverse) {
				esilprintf (op, "%s,!,zf,:=,zf,?{,BREAK,},%u,%s,:=,%s,--,%s,:=,%s,1,<<,%s,&,!,?{,%u,GOTO,}",
					src, bits, dst, dst, dst, dst, src, 11 + commas * 2);
			} else {
				esilprintf (op, "%s,!,zf,:=,zf,?{,BREAK,},0x%"PFMT64x",%s,:=,%s,++,%s,:=,%s,1,<<,%s,&,!,?{,%u,GOTO,}",
					src, UT64_MAX, dst, dst, dst, dst, src, 11 + commas * 2);
			}
		} else if (reverse) {
			ut32 i = bits - 1;
			esilprintf (op, "%s,!,zf,:=,zf,?{,BREAK,}", src);
			for (; i; i--) {
				r_strbuf_appendf (&op->esil, ",0x%"PFMT64x",%s,&,?{,%u,%s,:=,BREAK,}",
					((ut64)1) << i, src, i, dst);
			}
			r_strbuf_appendf (&op->esil, ",0,%s,:=", dst);
		} else {
			ut32 i = 0;
			esilprintf (op, "%s,!,zf,:=,zf,?{,BREAK,}", src);
			for (; i < bits - 1; i++) {
				r_strbuf_appendf (&op->esil, ",0x%"PFMT64x",%s,&,?{,%u,%s,:=,BREAK,}",
					((ut64)1) << i, src, i, dst);
			}
			r_strbuf_appendf (&op->esil, ",%u,%s,:=", i, dst);
		}
	}
	free (src);
	free (dst);
}

static void set_bswap_esil(RArchSession *as, RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *op0) {
	char *src = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
	char *dst64 = (as->config->bits == 64 && op0 && op0->type == ZYDIS_OPERAND_TYPE_REGISTER && op0->size == 32)? gpr64_from_32 (src): NULL;
	const char *dst = dst64? dst64: src;
	if (src && dst) {
		if (op0->size == 32) {
			esilprintf (op, "0xff000000,24,%s,NUM,<<,&,24,%s,NUM,>>,|,8,0x00ff0000,%s,NUM,&,>>,|,8,0x0000ff00,%s,NUM,&,<<,|,%s,=",
				src, src, src, src, dst);
		} else if (op0->size == 64) {
			esilprintf (op, "0xff00000000000000,56,%s,NUM,<<,&,56,%s,NUM,>>,|,40,0xff000000000000,%s,NUM,&,>>,|,40,0xff00,%s,NUM,&,<<,|,24,0xff0000000000,%s,NUM,&,>>,|,24,0xff0000,%s,NUM,&,<<,|,8,0xff00000000,%s,NUM,&,>>,|,8,0xff000000,%s,NUM,&,<<,|,%s,=",
				src, src, src, src, src, src, src, src, dst);
		}
	}
	free (src);
	free (dst64);
}

static void set_div_esil(RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *op0, bool sign) {
	char *src = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
	const int width = operand_bytes (op0);
	const char *r_quot = width == 1? "al": width == 2? "ax": width == 4? "eax": "rax";
	const char *r_rema = width == 1? "ah": width == 2? "dx": width == 4? "edx": "rdx";
	const char *r_nume = width == 1? "ax": r_quot;
	if (src && width) {
		if (sign) {
			op->sign = true;
			esilprintf (op, "%d,%s,~,%d,%s,<<,%s,+,~%%,%d,%s,~,%d,%s,<<,%s,+,~/,%s,=,%s,=",
				width * 8, src, width * 8, r_rema, r_nume,
				width * 8, src, width * 8, r_rema, r_nume, r_quot, r_rema);
		} else {
			esilprintf (op, "%s,%d,%s,<<,%s,+,%%,%s,%d,%s,<<,%s,+,/,%s,=,%s,=",
				src, width * 8, r_rema, r_nume, src, width * 8, r_rema, r_nume, r_quot, r_rema);
		}
	}
	free (src);
}

static void set_bit_esil(RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *op0, const ZydisDecodedOperand *op1) {
	char *src = operand_esil (insn, op1, op->addr, 0, NULL, NULL);
	ut32 bitsize = op0 && op0->size? op0->size: 0;
	if (!src || !bitsize || bitsize > 64) {
		free (src);
		return;
	}
	char *dst_r = NULL;
	char *dst_w = NULL;
	char *addr = NULL;
	if (op0->type == ZYDIS_OPERAND_TYPE_MEMORY) {
		addr = memaddr_esil (insn, op0, op->addr);
		if (addr) {
			const int width = operand_bytes (op0);
			esilprintf (op, "0,cf,:=,%u,%s,%%,1,<<,%u,%s,/,%s,+,[%d],&,?{,1,cf,:=,}",
				bitsize, src, bitsize, src, addr, width);
			switch (insn->mnemonic) {
			case ZYDIS_MNEMONIC_BTC:
				r_strbuf_appendf (&op->esil, ",%u,%s,%%,1,<<,%u,%s,/,%s,+,^=[%d]", bitsize, src, bitsize, src, addr, width);
				break;
			case ZYDIS_MNEMONIC_BTR:
				r_strbuf_appendf (&op->esil, ",-1,%u,%s,%%,1,<<,^,%u,%s,/,%s,+,&=[%d]", bitsize, src, bitsize, src, addr, width);
				break;
			case ZYDIS_MNEMONIC_BTS:
				r_strbuf_appendf (&op->esil, ",%u,%s,%%,1,<<,%u,%s,/,%s,+,|=[%d]", bitsize, src, bitsize, src, addr, width);
				break;
			default:
				break;
			}
		}
	} else {
		dst_r = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
		dst_w = operand_esil (insn, op0, op->addr, 1, NULL, NULL);
		if (dst_r) {
			esilprintf (op, "0,cf,:=,%u,%s,%%,1,<<,%s,&,?{,1,cf,:=,}", bitsize, src, dst_r);
			if (dst_w) {
				switch (insn->mnemonic) {
				case ZYDIS_MNEMONIC_BTC:
					r_strbuf_appendf (&op->esil, ",%u,%s,%%,1,<<,%s,^,%s", bitsize, src, dst_r, dst_w);
					break;
				case ZYDIS_MNEMONIC_BTR:
					r_strbuf_appendf (&op->esil, ",-1,%u,%s,%%,1,<<,^,%s,&,%s", bitsize, src, dst_r, dst_w);
					break;
				case ZYDIS_MNEMONIC_BTS:
					r_strbuf_appendf (&op->esil, ",%u,%s,%%,1,<<,%s,|,%s", bitsize, src, dst_r, dst_w);
					break;
				default:
					break;
				}
			}
		}
	}
	free (src);
	free (dst_r);
	free (dst_w);
	free (addr);
}

static void set_string_esil(RArchSession *as, RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops) {
	const int bits = as->config->bits;
	const int width = string_width_from_mnemonic (insn->mnemonic);
	const char *counter = counter_reg (bits);
	const bool rep = insn->attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE);
	const ZydisDecodedOperand *memw = find_mem_operand (insn, ops, R_PERM_W, 0);
	const ZydisDecodedOperand *memr0 = find_mem_operand (insn, ops, R_PERM_R, 0);
	const ZydisDecodedOperand *memr1 = find_mem_operand (insn, ops, R_PERM_R, 1);
	char *src = NULL;
	char *dst = NULL;
	const char *sreg = NULL;
	const char *dreg = NULL;

	switch (insn->mnemonic) {
	case ZYDIS_MNEMONIC_MOVSB:
	case ZYDIS_MNEMONIC_MOVSD:
	case ZYDIS_MNEMONIC_MOVSQ:
	case ZYDIS_MNEMONIC_MOVSW:
		if (!memw || !memr0) {
			break;
		}
		src = operand_esil (insn, memr0, op->addr, 0, NULL, NULL);
		dst = operand_esil (insn, memw, op->addr, 1, NULL, NULL);
		sreg = memr0->mem.base != ZYDIS_REGISTER_NONE? zyreg (memr0->mem.base): NULL;
		dreg = memw->mem.base != ZYDIS_REGISTER_NONE? zyreg (memw->mem.base): NULL;
		if (src && dst) {
			if (rep) {
				esilprintf (op, "%s,!,?{,BREAK,},%s,%s", counter, src, dst);
			} else {
				esilprintf (op, "%s,%s", src, dst);
			}
			append_df_update (&op->esil, width, sreg, dreg);
			append_rep_tail (&op->esil, insn, counter);
		}
		break;
	case ZYDIS_MNEMONIC_STOSB:
	case ZYDIS_MNEMONIC_STOSD:
	case ZYDIS_MNEMONIC_STOSQ:
	case ZYDIS_MNEMONIC_STOSW:
		if (!memw) {
			break;
		}
		src = strdup (r_str_get_fail (acc_reg (width), "al"));
		dst = operand_esil (insn, memw, op->addr, 1, NULL, NULL);
		dreg = memw->mem.base != ZYDIS_REGISTER_NONE? zyreg (memw->mem.base): NULL;
		if (src && dst) {
			if (rep) {
				esilprintf (op, "%s,!,?{,BREAK,},%s,%s", counter, src, dst);
			} else {
				esilprintf (op, "%s,%s", src, dst);
			}
			append_df_update (&op->esil, width, dreg, NULL);
			append_rep_tail (&op->esil, insn, counter);
		}
		break;
	case ZYDIS_MNEMONIC_LODSB:
	case ZYDIS_MNEMONIC_LODSD:
	case ZYDIS_MNEMONIC_LODSQ:
	case ZYDIS_MNEMONIC_LODSW:
		if (!memr0) {
			break;
		}
		src = operand_esil (insn, memr0, op->addr, 0, NULL, NULL);
		dst = r_str_newf ("%s,=", r_str_get_fail (acc_reg (width), "al"));
		sreg = memr0->mem.base != ZYDIS_REGISTER_NONE? zyreg (memr0->mem.base): NULL;
		if (src && dst) {
			if (rep) {
				esilprintf (op, "%s,!,?{,BREAK,},%s,%s", counter, src, dst);
			} else {
				esilprintf (op, "%s,%s", src, dst);
			}
			append_df_update (&op->esil, width, sreg, NULL);
			append_rep_tail (&op->esil, insn, counter);
		}
		break;
	case ZYDIS_MNEMONIC_CMPSB:
	case ZYDIS_MNEMONIC_CMPSD:
	case ZYDIS_MNEMONIC_CMPSQ:
	case ZYDIS_MNEMONIC_CMPSW:
		if (!memr0 || !memr1) {
			break;
		}
		src = operand_esil (insn, memr1, op->addr, 0, NULL, NULL);
		dst = operand_esil (insn, memr0, op->addr, 0, NULL, NULL);
		sreg = memr0->mem.base != ZYDIS_REGISTER_NONE? zyreg (memr0->mem.base): NULL;
		dreg = memr1->mem.base != ZYDIS_REGISTER_NONE? zyreg (memr1->mem.base): NULL;
		if (src && dst) {
			set_cmp_expr_esil (op, src, dst, width * 8);
			if (rep) {
				r_strbuf_prependf (&op->esil, "%s,!,?{,BREAK,},", counter);
			}
			append_df_update (&op->esil, width, sreg, dreg);
			append_rep_tail (&op->esil, insn, counter);
		}
		break;
	case ZYDIS_MNEMONIC_SCASB:
	case ZYDIS_MNEMONIC_SCASD:
	case ZYDIS_MNEMONIC_SCASQ:
	case ZYDIS_MNEMONIC_SCASW:
		if (!memr0) {
			break;
		}
		src = operand_esil (insn, memr0, op->addr, 0, NULL, NULL);
		dst = strdup (r_str_get_fail (acc_reg (width), "al"));
		dreg = memr0->mem.base != ZYDIS_REGISTER_NONE? zyreg (memr0->mem.base): NULL;
		if (src && dst) {
			set_cmp_expr_esil (op, src, dst, width * 8);
			if (rep) {
				r_strbuf_prependf (&op->esil, "%s,!,?{,BREAK,},", counter);
			}
			append_df_update (&op->esil, width, dreg, NULL);
			append_rep_tail (&op->esil, insn, counter);
		}
		break;
	default:
		break;
	}
	free (src);
	free (dst);
}

static void anop_esil(RArchSession *as, RAnalOp *op, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops) {
	const ZydisDecodedOperand *op0 = visible_op (insn, ops, 0);
	const ZydisDecodedOperand *op1 = visible_op (insn, ops, 1);
	const ZydisDecodedOperand *op2 = visible_op (insn, ops, 2);
	const int bits = as->config->bits;
	const int regsz = R_SYS_BITS_CHECK (bits, 64)? 8: R_SYS_BITS_CHECK (bits, 16)? 2: 4;
	const char *pc = pc_reg (bits);
	const char *sp = sp_reg (bits);
	const char *bp = bp_reg (bits);
	char *src = NULL;
	char *dst = NULL;
	ut32 bitsize = 0;

	switch (insn->mnemonic) {
	case ZYDIS_MNEMONIC_NOP:
	case ZYDIS_MNEMONIC_ENDBR32:
	case ZYDIS_MNEMONIC_ENDBR64:
		esilprintf (op, ",");
		break;
	case ZYDIS_MNEMONIC_MOV:
	case ZYDIS_MNEMONIC_MOVAPS:
	case ZYDIS_MNEMONIC_MOVUPS:
	case ZYDIS_MNEMONIC_MOVSX:
	case ZYDIS_MNEMONIC_MOVSXD:
	case ZYDIS_MNEMONIC_MOVZX:
		set_mov_esil (as, op, insn, op0, op1);
		break;
	case ZYDIS_MNEMONIC_MOVSD:
		if (find_mem_operand (insn, ops, R_PERM_W, 0) && find_mem_operand (insn, ops, R_PERM_R, 0)) {
			set_string_esil (as, op, insn, ops);
		} else {
			set_mov_esil (as, op, insn, op0, op1);
		}
		break;
	case ZYDIS_MNEMONIC_MOVSB:
	case ZYDIS_MNEMONIC_MOVSQ:
	case ZYDIS_MNEMONIC_MOVSW:
	case ZYDIS_MNEMONIC_STOSB:
	case ZYDIS_MNEMONIC_STOSD:
	case ZYDIS_MNEMONIC_STOSQ:
	case ZYDIS_MNEMONIC_STOSW:
	case ZYDIS_MNEMONIC_LODSB:
	case ZYDIS_MNEMONIC_LODSD:
	case ZYDIS_MNEMONIC_LODSQ:
	case ZYDIS_MNEMONIC_LODSW:
	case ZYDIS_MNEMONIC_CMPSB:
	case ZYDIS_MNEMONIC_CMPSD:
	case ZYDIS_MNEMONIC_CMPSQ:
	case ZYDIS_MNEMONIC_CMPSW:
	case ZYDIS_MNEMONIC_SCASB:
	case ZYDIS_MNEMONIC_SCASD:
	case ZYDIS_MNEMONIC_SCASQ:
	case ZYDIS_MNEMONIC_SCASW:
		set_string_esil (as, op, insn, ops);
		break;
	case ZYDIS_MNEMONIC_LEA:
		src = operand_esil (insn, op1, op->addr, 2, NULL, NULL);
		dst = operand_esil (insn, op0, op->addr, 1, NULL, NULL);
		if (src && dst) {
			esilprintf (op, "%s,%s", src, dst);
		}
		break;
	case ZYDIS_MNEMONIC_ADD:
		set_add_esil (op, insn, ops, false);
		break;
	case ZYDIS_MNEMONIC_ADC:
		set_add_esil (op, insn, ops, true);
		break;
	case ZYDIS_MNEMONIC_INC:
		dst = operand_esil (insn, op0, op->addr, 1, "++", &bitsize);
		if (dst && bitsize) {
			esilprintf (op, "%s,%u,$o,of,:=,%u,$s,sf,:=,$z,zf,:=,$p,pf,:=,3,$c,af,:=", dst, bitsize - 1, bitsize - 1);
		}
		break;
	case ZYDIS_MNEMONIC_XADD:
		set_xchg_esil (op, insn, op0, op1, true);
		break;
	case ZYDIS_MNEMONIC_SUB:
		set_sub_esil (op, insn, ops, false);
		break;
	case ZYDIS_MNEMONIC_SBB:
		set_sub_esil (op, insn, ops, true);
		break;
	case ZYDIS_MNEMONIC_DEC:
		dst = operand_esil (insn, op0, op->addr, 1, "--", &bitsize);
		if (dst && bitsize) {
			esilprintf (op, "%s,%u,$o,of,:=,%u,$s,sf,:=,$z,zf,:=,$p,pf,:=,3,$b,af,:=", dst, bitsize - 1, bitsize - 1);
		}
		break;
	case ZYDIS_MNEMONIC_CMP:
		set_cmp_esil (op, insn, ops, false);
		break;
	case ZYDIS_MNEMONIC_TEST:
		set_cmp_esil (op, insn, ops, true);
		break;
	case ZYDIS_MNEMONIC_AND:
		set_logic_esil (op, insn, ops, "&");
		break;
	case ZYDIS_MNEMONIC_OR:
		set_logic_esil (op, insn, ops, "|");
		break;
	case ZYDIS_MNEMONIC_XOR:
		set_logic_esil (op, insn, ops, "^");
		break;
	case ZYDIS_MNEMONIC_PXOR:
		if (op0 && op1 && op0->type == ZYDIS_OPERAND_TYPE_REGISTER
				&& op1->type == ZYDIS_OPERAND_TYPE_REGISTER
				&& is_xmm_reg (op0->reg.value) && is_xmm_reg (op1->reg.value)) {
			src = operand_esil (insn, op1, op->addr, 0, NULL, NULL);
			dst = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
			if (src && dst) {
				esilprintf (op, "%sl,%sl,^=,%sh,%sh,^=", src, dst, src, dst);
			}
		}
		break;
	case ZYDIS_MNEMONIC_CPUID:
		esilprintf (op, "0xa,eax,=,0x756E6547,ebx,=,0x6C65746E,ecx,=,0x49656E69,edx,=");
		break;
	case ZYDIS_MNEMONIC_INT:
		if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			esilprintf (op, "%"PFMT64u",$", zydis_imm_value (insn, op0, op->addr));
		}
		break;
	case ZYDIS_MNEMONIC_BSF:
		set_bsf_bsr_esil (op, insn, ops, false);
		break;
	case ZYDIS_MNEMONIC_BSR:
		set_bsf_bsr_esil (op, insn, ops, true);
		break;
	case ZYDIS_MNEMONIC_BSWAP:
		set_bswap_esil (as, op, insn, op0);
		break;
	case ZYDIS_MNEMONIC_BT:
	case ZYDIS_MNEMONIC_BTC:
	case ZYDIS_MNEMONIC_BTR:
	case ZYDIS_MNEMONIC_BTS:
		set_bit_esil (op, insn, op0, op1);
		break;
	case ZYDIS_MNEMONIC_DIV:
		set_div_esil (op, insn, op0, false);
		break;
	case ZYDIS_MNEMONIC_IDIV:
		set_div_esil (op, insn, op0, true);
		break;
	case ZYDIS_MNEMONIC_IMUL:
		{
			char *arg0 = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
			char *arg1 = operand_esil (insn, op1, op->addr, 0, NULL, NULL);
			char *arg2 = operand_esil (insn, op2, op->addr, 0, NULL, NULL);
			const int width = operand_bytes (op0);
			op->sign = true;
			if (arg1) {
				char *multiplier = arg2? arg2: arg0;
				if (arg0 && multiplier && width) {
					esilprintf (op, "%d,%s,~,%d,%s,~,*,DUP,%s,=,%d,%s,~,-,!,!,DUP,cf,:=,of,:=",
						width * 8, multiplier, width * 8, arg1, arg0, width * 8, arg0);
				}
			} else if (arg0 && width) {
				const char *r_quot = width == 1? "al": width == 2? "ax": width == 4? "eax": "rax";
				const char *r_rema = width == 1? "ah": width == 2? "dx": width == 4? "edx": "rdx";
				const char *r_nume = width == 1? "ax": r_quot;
				if (width == 8) {
					esilprintf (op, "%s,%s,L*,%s,=,DUP,%s,=,!,!,DUP,cf,:=,of,:=",
						arg0, r_nume, r_nume, r_rema);
				} else {
					esilprintf (op, "%d,%s,~,%d,%s,~,*,DUP,DUP,%s,=,%d,SWAP,>>,%s,=,%d,%s,~,-,!,!,DUP,cf,:=,of,:=",
						width * 8, arg0, width * 8, r_nume, r_nume, width * 8, r_rema, width * 8, r_nume);
				}
			}
			free (arg0);
			free (arg1);
			free (arg2);
		}
		break;
	case ZYDIS_MNEMONIC_MUL:
		src = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
		if (src) {
			const int width = operand_bytes (op0);
			const char *r_quot = width == 1? "al": width == 2? "ax": width == 4? "eax": "rax";
			const char *r_rema = width == 1? "ah": width == 2? "dx": width == 4? "edx": "rdx";
			const char *r_nume = width == 1? "ax": r_quot;
			if (width == 8) {
				esilprintf (op, "%s,%s,L*,%s,=,DUP,%s,=,!,!,DUP,cf,:=,of,:=",
					src, r_nume, r_nume, r_rema);
			} else if (width) {
				esilprintf (op, "%s,%s,*,DUP,%s,=,%d,SWAP,>>,DUP,%s,=,!,!,DUP,cf,:=,of,:=",
					src, r_nume, r_nume, width * 8, r_rema);
			}
		}
		break;
	case ZYDIS_MNEMONIC_CLC:
		esilprintf (op, "0,cf,:=");
		break;
	case ZYDIS_MNEMONIC_CLD:
		esilprintf (op, "0,df,:=");
		break;
	case ZYDIS_MNEMONIC_CLI:
		esilprintf (op, "0,if,:=");
		break;
	case ZYDIS_MNEMONIC_CMC:
		esilprintf (op, "cf,!,cf,=");
		break;
	case ZYDIS_MNEMONIC_STC:
		esilprintf (op, "1,cf,:=");
		break;
	case ZYDIS_MNEMONIC_STD:
		esilprintf (op, "1,df,:=");
		break;
	case ZYDIS_MNEMONIC_STI:
		esilprintf (op, "1,if,:=");
		break;
	case ZYDIS_MNEMONIC_NOT:
		dst = operand_esil (insn, op0, op->addr, 1, "^", NULL);
		if (dst) {
			esilprintf (op, "-1,%s", dst);
		}
		break;
	case ZYDIS_MNEMONIC_NEG:
		src = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
		dst = operand_esil (insn, op0, op->addr, 1, NULL, &bitsize);
		if (src && dst && bitsize) {
			ut64 mask = bitsize == 64? UT64_MAX: ((1ULL << bitsize) - 1);
			esilprintf (op, "%s,!,!,cf,:=,%s,0x%"PFMT64x",^,1,+,%s,$z,zf,:=,0,of,:=,%u,$s,sf,:=,%u,$o,pf,:=",
				src, src, mask, dst, bitsize - 1, bitsize - 1);
		}
		break;
	case ZYDIS_MNEMONIC_SHL:
		set_shift_esil (op, insn, ops, "<<");
		break;
	case ZYDIS_MNEMONIC_SHR:
		set_shift_esil (op, insn, ops, ">>");
		break;
	case ZYDIS_MNEMONIC_SAR:
		set_shift_esil (op, insn, ops, "ASR");
		break;
	case ZYDIS_MNEMONIC_ROL:
	case ZYDIS_MNEMONIC_RCL:
		set_shift_esil (op, insn, ops, "ROL");
		break;
	case ZYDIS_MNEMONIC_ROR:
	case ZYDIS_MNEMONIC_RCR:
		set_shift_esil (op, insn, ops, "ROR");
		break;
	case ZYDIS_MNEMONIC_PUSH:
		src = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
		if (src) {
			esilprintf (op, "%s,%d,%s,-,=[%d],%d,%s,-=", src, regsz, sp, regsz, regsz, sp);
		}
		break;
	case ZYDIS_MNEMONIC_PUSHA:
	case ZYDIS_MNEMONIC_PUSHAD:
		if (regsz == 4) {
			esilprintf (op,
				"0,%s,+,"
				"%d,%s,-=,eax,%s,=[%d],"
				"%d,%s,-=,ecx,%s,=[%d],"
				"%d,%s,-=,edx,%s,=[%d],"
				"%d,%s,-=,ebx,%s,=[%d],"
				"%d,%s,-=,%s,=[%d],"
				"%d,%s,-=,ebp,%s,=[%d],"
				"%d,%s,-=,esi,%s,=[%d],"
				"%d,%s,-=,edi,%s,=[%d]",
				sp,
				regsz, sp, sp, regsz,
				regsz, sp, sp, regsz,
				regsz, sp, sp, regsz,
				regsz, sp, sp, regsz,
				regsz, sp, sp, regsz,
				regsz, sp, sp, regsz,
				regsz, sp, sp, regsz,
				regsz, sp, sp, regsz);
		}
		break;
	case ZYDIS_MNEMONIC_PUSHF:
	case ZYDIS_MNEMONIC_PUSHFD:
	case ZYDIS_MNEMONIC_PUSHFQ:
		esilprintf (op, "%d,%s,-=,eflags,%s,=[%d]", regsz, sp, sp, regsz);
		break;
	case ZYDIS_MNEMONIC_POP:
		dst = operand_esil (insn, op0, op->addr, 1, NULL, NULL);
		if (dst) {
			esilprintf (op, "%s,[%d],%d,%s,+=,%s", sp, regsz, regsz, sp, dst);
		}
		break;
	case ZYDIS_MNEMONIC_POPA:
	case ZYDIS_MNEMONIC_POPAD:
		if (regsz == 4) {
			esilprintf (op,
				"%s,[%d],%d,%s,+=,edi,=,"
				"%s,[%d],%d,%s,+=,esi,=,"
				"%s,[%d],%d,%s,+=,ebp,=,"
				"%s,[%d],%d,%s,+=,"
				"%s,[%d],%d,%s,+=,ebx,=,"
				"%s,[%d],%d,%s,+=,edx,=,"
				"%s,[%d],%d,%s,+=,ecx,=,"
				"%s,[%d],%d,%s,+=,eax,=,"
				"%s,=",
				sp, regsz, regsz, sp,
				sp, regsz, regsz, sp,
				sp, regsz, regsz, sp,
				sp, regsz, regsz, sp,
				sp, regsz, regsz, sp,
				sp, regsz, regsz, sp,
				sp, regsz, regsz, sp,
				sp, regsz, regsz, sp,
				sp);
		}
		break;
	case ZYDIS_MNEMONIC_POPF:
	case ZYDIS_MNEMONIC_POPFD:
	case ZYDIS_MNEMONIC_POPFQ:
		esilprintf (op, "%s,[%d],eflags,=,%d,%s,+=", sp, regsz, regsz, sp);
		break;
	case ZYDIS_MNEMONIC_ENTER:
		{
			ut64 alloc = 0;
			if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				alloc = zydis_imm_value (insn, op0, op->addr);
			}
			esilprintf (op, "%s,%d,%s,-,=[%d],%d,%s,-=,%s,%s,=,%"PFMT64u",%s,-=",
				bp, regsz, sp, regsz, regsz, sp, sp, bp, alloc, sp);
		}
		break;
	case ZYDIS_MNEMONIC_LEAVE:
		esilprintf (op, "%s,%s,=,%s,[%d],%s,=,%d,%s,+=", bp, sp, sp, regsz, bp, regsz, sp);
		break;
	case ZYDIS_MNEMONIC_CALL:
		if (bits == 32 && op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			const ut64 target = zydis_imm_value (insn, op0, op->addr);
			const ut64 retaddr = op->addr + op->size;
			ut8 thunk[4] = {0};
			RBin *bin = as->arch->binb.bin;
			if (bin && bin->iob.read_at && bin->iob.read_at (bin->iob.io, target, thunk, sizeof (thunk))) {
				if (thunk[0] == 0x8b && thunk[3] == 0xc3
						&& (thunk[1] & 0xc7) == 4
						&& (thunk[2] & 0x3f) == 0x24) {
					ut8 reg = (thunk[1] & 0x38) >> 3;
					esilprintf (op, "0x%"PFMT64x",%s,=", retaddr, reg32_to_name (reg));
					break;
				}
			}
			if (target == retaddr && bin && bin->iob.read_at && bin->iob.read_at (bin->iob.io, retaddr, thunk, 1)) {
				if (thunk[0] >= 0x58 && thunk[0] <= 0x5f) {
					esilprintf (op, "0x%"PFMT64x",%s,=", retaddr, reg32_to_name (thunk[0] - 0x58));
					break;
				}
			}
		}
		src = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
		if (src) {
			esilprintf (op, "%s,%s,%d,%s,-=,%s,=[%d],%s,=", src, pc, regsz, sp, sp, regsz, pc);
		}
		break;
	case ZYDIS_MNEMONIC_RET:
	case ZYDIS_MNEMONIC_IRET:
	case ZYDIS_MNEMONIC_IRETD:
	case ZYDIS_MNEMONIC_IRETQ:
	case ZYDIS_MNEMONIC_SYSRET:
		{
			ut64 cleanup = 0;
			if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				cleanup = zydis_imm_value (insn, op0, op->addr);
			}
			esilprintf (op, "%s,[%d],%s,=,%"PFMT64u",%s,+=", sp, regsz, pc, (ut64)regsz + cleanup, sp);
		}
		break;
	case ZYDIS_MNEMONIC_JMP:
		src = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
		if (src) {
			esilprintf (op, "%s,%s,=", src, pc);
		}
		break;
	case ZYDIS_MNEMONIC_XCHG:
		set_xchg_esil (op, insn, op0, op1, false);
		break;
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JRCXZ:
		src = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
		if (src) {
			const char *cnt = insn->mnemonic == ZYDIS_MNEMONIC_JCXZ? "cx": insn->mnemonic == ZYDIS_MNEMONIC_JECXZ? "ecx": "rcx";
			esilprintf (op, "%s,!,?{,%s,%s,=,}", cnt, src, pc);
		}
		break;
	case ZYDIS_MNEMONIC_LOOP:
	case ZYDIS_MNEMONIC_LOOPE:
	case ZYDIS_MNEMONIC_LOOPNE:
		src = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
		if (src) {
			const char *cnt = bits == 16? "cx": bits == 32? "ecx": "rcx";
			if (insn->mnemonic == ZYDIS_MNEMONIC_LOOP) {
				esilprintf (op, "1,%s,-=,%s,?{,%s,%s,=,}", cnt, cnt, src, pc);
			} else if (insn->mnemonic == ZYDIS_MNEMONIC_LOOPE) {
				esilprintf (op, "1,%s,-=,%s,?{,zf,?{,%s,%s,=,},}", cnt, cnt, src, pc);
			} else {
				esilprintf (op, "1,%s,-=,%s,?{,zf,!,?{,%s,%s,=,},}", cnt, cnt, src, pc);
			}
		}
		break;
	default:
		if (is_jcc (insn->mnemonic)) {
			src = operand_esil (insn, op0, op->addr, 0, NULL, NULL);
			const char *cond = cond_esil (insn->mnemonic);
			if (src && cond) {
				esilprintf (op, "%s,?{,%s,%s,=,}", cond, src, pc);
			}
		} else if (is_setcc (insn->mnemonic)) {
			dst = operand_esil (insn, op0, op->addr, 1, NULL, NULL);
			const char *cond = cond_esil (insn->mnemonic);
			if (dst && cond) {
				esilprintf (op, "%s,%s", cond, dst);
			}
		} else if ((op->type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_CMOV) {
			src = operand_esil (insn, op1, op->addr, 0, NULL, NULL);
			dst = operand_esil (insn, op0, op->addr, 1, NULL, NULL);
			const char *cond = cond_esil (insn->mnemonic);
			if (src && dst && cond) {
				esilprintf (op, "%s,?{,%s,%s,}", cond, src, dst);
			}
		}
		break;
	}
	free (src);
	free (dst);
}

static void opex(RStrBuf *buf, const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops, ut64 addr) {
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	size_t i;
	for (i = 0; i < insn->operand_count_visible; i++) {
		const ZydisDecodedOperand *op = &ops[i];
		pj_o (pj);
		pj_ki (pj, "size", operand_bytes (op));
		int rw = 0;
		if (op->actions & (ZYDIS_OPERAND_ACTION_READ | ZYDIS_OPERAND_ACTION_CONDREAD)) {
			rw |= R_ANAL_OP_DIR_READ;
		}
		if (op->actions & (ZYDIS_OPERAND_ACTION_WRITE | ZYDIS_OPERAND_ACTION_CONDWRITE)) {
			rw |= R_ANAL_OP_DIR_WRITE;
		}
		if (rw) {
			pj_ki (pj, "rw", rw);
		}
		switch (op->type) {
		case ZYDIS_OPERAND_TYPE_REGISTER:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", zyreg (op->reg.value));
			break;
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			pj_ks (pj, "type", "imm");
			if (!op->imm.is_relative && op->imm.is_signed) {
				pj_kN (pj, "value", op->imm.value.s);
			} else {
				pj_kn (pj, "value", zydis_imm_value (insn, op, addr));
			}
			break;
		case ZYDIS_OPERAND_TYPE_MEMORY:
			pj_ks (pj, "type", "mem");
			if (op->mem.segment != ZYDIS_REGISTER_NONE) {
				pj_ks (pj, "segment", zyreg (op->mem.segment));
			}
			if (op->mem.base != ZYDIS_REGISTER_NONE) {
				pj_ks (pj, "base", zyreg (op->mem.base));
			}
			if (op->mem.index != ZYDIS_REGISTER_NONE) {
				pj_ks (pj, "index", zyreg (op->mem.index));
			}
			pj_ki (pj, "scale", op->mem.scale);
			pj_kn (pj, "disp", op->mem.disp.value);
			break;
		case ZYDIS_OPERAND_TYPE_POINTER:
			pj_ks (pj, "type", "ptr");
			pj_ki (pj, "segment", op->ptr.segment);
			pj_kN (pj, "offset", op->ptr.offset);
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		pj_end (pj);
	}
	pj_end (pj);
	if (insn->attributes & ZYDIS_ATTRIB_HAS_REX) {
		pj_kb (pj, "rex", true);
	}
	if (insn->attributes & ZYDIS_ATTRIB_HAS_MODRM) {
		pj_kb (pj, "modrm", true);
	}
	if (insn->attributes & ZYDIS_ATTRIB_HAS_SIB) {
		pj_kb (pj, "sib", true);
	}
	if (insn->raw.disp.size) {
		pj_kn (pj, "disp", insn->raw.disp.value);
	}
	pj_end (pj);
	char *json = pj_drain (pj);
	if (json) {
		r_strbuf_set (buf, json);
		free (json);
	}
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	R_RETURN_VAL_IF_FAIL (as && as->data && op && op->bytes, false);
	if (!refresh_plugin (as)) {
		return false;
	}
	PluginData *pd = as->data;
	const int len = R_MIN (op->size, ZYDIS_MAX_INSN_SIZE);
	ZydisDecodedInstruction insn;
	ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
	if (!ZYAN_SUCCESS (ZydisDecoderDecodeFull (&pd->decoder, op->bytes, len, &insn, ops))) {
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 1;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		return true;
	}
	op->size = insn.length;
	op->id = insn.mnemonic;
	op->family = R_ANAL_OP_FAMILY_CPU;
	op->nopcode = insn.raw.prefix_count + 1;
	set_prefix (op, &insn);
	set_family (op, &insn);
	set_op_type (as, op, &insn, ops);
	set_opdir (op);
	if (mask & R_ARCH_OP_MASK_DISASM) {
		format_mnemonic (as, op, &insn, ops);
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		anop_esil (as, op, &insn, ops);
	}
	if (mask & R_ARCH_OP_MASK_OPEX) {
		opex (&op->opex, &insn, ops, op->addr);
	}
	if (mask & R_ARCH_OP_MASK_VAL) {
		op_fillval (as, op, &insn, ops);
	}
	return op->size > 0;
}

#include "reg_profile.inc.c"

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_CODE_ALIGN:
	case R_ARCH_INFO_DATA_ALIGN:
		return 0;
	case R_ARCH_INFO_FUNC_ALIGN:
		if (R_SYS_BITS_CHECK (as->config->bits, 64)) {
			return 4;
		}
		return 0;
	case R_ARCH_INFO_MAXOP_SIZE:
		return ZYDIS_MAX_INSN_SIZE;
	case R_ARCH_INFO_INVOP_SIZE:
	case R_ARCH_INFO_MINOP_SIZE:
		return 1;
	}
	return 0;
}

static RList *anal_preludes(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->config, NULL);
	RList *l = NULL;
	switch (as->config->bits) {
	case 32:
		l = r_list_newf (free);
		r_list_append (l, strdup ("8bff558bec"));
		r_list_append (l, strdup ("5589e5"));
		r_list_append (l, strdup ("558bec"));
		r_list_append (l, strdup ("f30f1efb")); // endbr32
		r_list_append (l, strdup ("55575653")); // push ebp, edi, esi, ebx
		break;
	case 64:
		l = r_list_newf (free);
		r_list_append (l, strdup ("554889e5"));
		r_list_append (l, strdup ("55488bec"));
		r_list_append (l, strdup ("f30f1efa")); // endbr64
		r_list_append (l, strdup ("5541574156")); // push rbp,r15,r14
		r_list_append (l, strdup ("415741564154")); // push r15,r14,r13,r12
		r_list_append (l, strdup ("56534883"));
		break;
	default:
		break;
	}
	return l;
}

static char *mnemonics(RArchSession *as, int id, bool json) {
	R_RETURN_VAL_IF_FAIL (as, NULL);
	if (id != -1) {
		const char *name = ZydisMnemonicGetString (id);
		if (!name) {
			return NULL;
		}
		if (json) {
			PJ *pj = pj_new ();
			if (!pj) {
				return NULL;
			}
			pj_a (pj);
			pj_s (pj, name);
			pj_end (pj);
			return pj_drain (pj);
		}
		return strdup (name);
	}
	PJ *pj = NULL;
	RStrBuf *buf = NULL;
	if (json) {
		pj = pj_new ();
		if (!pj) {
			return NULL;
		}
		pj_a (pj);
	} else {
		buf = r_strbuf_new ("");
		if (!buf) {
			return NULL;
		}
	}
	int i;
	for (i = 1; i <= ZYDIS_MNEMONIC_MAX_VALUE; i++) {
		const char *op = ZydisMnemonicGetString (i);
		if (!op) {
			continue;
		}
		if (pj) {
			pj_s (pj, op);
		} else {
			r_strbuf_append (buf, op);
			r_strbuf_append (buf, "\n");
		}
	}
	if (pj) {
		pj_end (pj);
	}
	return pj? pj_drain (pj): r_strbuf_drain (buf);
}

static bool tls_begin(REsil *esil) {
	RCoreBind *coreb = &esil->anal->coreb;
	coreb->cmdf (coreb->core, "omb fs");
	return true;
}

static bool tls_end(REsil *esil) {
	RCoreBind *coreb = &esil->anal->coreb;
	coreb->cmdf (coreb->core, "omb default");
	return true;
}

static bool esilcb(RArchSession *as R_UNUSED, REsil *esil, RArchEsilAction action) {
	if (!esil) {
		R_LOG_ERROR ("Failed to find an esil instance");
		return false;
	}
	switch (action) {
	case R_ARCH_ESIL_ACTION_INIT:
		r_esil_set_op (esil, "TLS_BEGIN", tls_begin, 0, 0, R_ESIL_OP_TYPE_CUSTOM, NULL);
		r_esil_set_op (esil, "TLS_END", tls_end, 0, 0, R_ESIL_OP_TYPE_CUSTOM, NULL);
		break;
	case R_ARCH_ESIL_ACTION_FINI:
		break;
	default:
		return false;
	}
	return true;
}

const RArchPlugin r_arch_plugin_x86_zydis = {
	.meta = {
		.name = "x86.zydis",
		.desc = "Zydis X86 analysis",
		.license = "MIT",
	},
	.arch = "x86",
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.endian = R_SYS_ENDIAN_LITTLE,
	.decode = &decode,
	.preludes = anal_preludes,
	.init = init,
	.fini = fini,
	.info = archinfo,
	.regs = &get_reg_profile,
	.esilcb = esilcb,
	.mnemonics = mnemonics,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_x86_zydis,
	.version = R2_VERSION
};
#endif

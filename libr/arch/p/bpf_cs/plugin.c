/* radare2 - LGPL - Copyright 2022-2024 - terorie */

#include <r_anal.h>
#include <r_esil.h>
#include <r_lib.h>

#include <capstone/capstone.h>
#include "../bpf/bpf.h"

#if CS_API_MAJOR >= 5

#define CSINC BPF
#define CSINC_MODE get_capstone_mode(as)

static int get_capstone_mode(RArchSession *as) {
	int mode = R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config)
		? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	const char *cpu = as->config->cpu;
	if (cpu && !strcmp (cpu, "extended")) {
		mode |= CS_MODE_BPF_EXTENDED;
	} else if (cpu && !strcmp (cpu, "classic")) {
		mode |= CS_MODE_BPF_CLASSIC;
	} else {
		mode |= (as->config->bits == 32)? CS_MODE_BPF_CLASSIC: CS_MODE_BPF_EXTENDED;
	}
	return mode;
}
#include "../capstone.inc.c"

#define OP(n) insn->detail->bpf.operands[n]
// the "& 0xffffffff" is for some weird CS bug in JMP
#define IMM(n) (insn->detail->bpf.operands[n].imm & UT32_MAX)
#define OPCOUNT insn->detail->bpf.op_count

// calculate jump address from immediate
#define JUMP(n) (op->addr + insn->size * (st16)(1 + IMM (n)))

static void analop_esil(RArchSession *a, RAnalOp *op, cs_insn *insn, ut64 addr);

static char *mnemonics(RArchSession *s, int id, bool json) {
	CapstonePluginData *cpd = (CapstonePluginData*)s->data;
	return r_arch_cs_mnemonics (s, cpd->cs_handle, id, json);
}

/* Assembler integration (classic + extended via shared parser) */

#define TOKEN_MAX_LEN 15
typedef char bpf_token[TOKEN_MAX_LEN + 1];

#define TOKEN_EQ(x, s) (strcmp ((x), (s)) == 0)

#define PARSE_NEED_TOKEN(x) \
	if (x == NULL) { \
		return false; \
	}
#define PARSE_NEED(x) \
	if (!(x)) { \
		return false; \
	}
#define PARSE_STR(x, s) PARSE_NEED (TOKEN_EQ (x, s))

typedef struct bpf_asm_parser {
	const char *str;
	RStrBuf *token;
} BPFAsmParser;

static void token_fini(BPFAsmParser *t) {
	if (t->token) {
		r_strbuf_free (t->token);
		t->token = NULL;
	}
}

static const char *trim_input(const char *p) {
	while (*p) {
		switch (*p) {
			case ' ': case '\t': p++; continue;
			case ';': return NULL;
			default: return p;
		}
	}
	return NULL;
}

static inline bool is_single_char_token(char c) {
	return c == '(' || c == ')' || c == '[' || c == ']' || c == ',';
}

static inline bool is_arithmetic(char c) {
	return c == '+' || c == '-';
}

static const char *token_next(BPFAsmParser *t) {
	token_fini (t);
	t->str = trim_input (t->str);
	if (!t->str) {
		return NULL;
	}
	RStrBuf *token = r_strbuf_new (NULL);
	if (!r_strbuf_reserve (token, TOKEN_MAX_LEN + 1)) {
		r_strbuf_free (token);
		return NULL;
	}
	t->token = token;
	if (is_single_char_token (t->str[0])) {
		r_strbuf_append_n (token, t->str++, 1);
		return r_strbuf_get (token);
	}
	int i;
	for (i = 0; i < TOKEN_MAX_LEN; i++) {
		if (!isgraph (t->str[0]) || is_single_char_token (t->str[0]) || (is_arithmetic (t->str[0]) && i != 0)) {
			break;
		}
		r_strbuf_append_n (token, t->str++, 1);
	}
	return r_strbuf_get (token);
}

static bool is_k_tok(const char *tok) {
	return is_arithmetic (tok[0]) || R_BETWEEN ('0', tok[0], '9');
}

static bool parse_k(RBpfSockFilter *f, const char *t) {
	char *t2; f->k = strtol (t, &t2, 0); return t != t2;
}

static bool parse_k_or_x(RBpfSockFilter *f, const char *t) {
	if (TOKEN_EQ (t, "x")) { f->code |= BPF_X; return true; }
	f->code |= BPF_K; return parse_k (f, t);
}

static bool parse_label_value(ut64 *out, const char *t) {
	char *t2; *out = strtoul (t, &t2, 0); return t != t2;
}

static bool parse_jump_targets(RBpfSockFilter *f, int opc, const bpf_token *op, ut64 pc) {
	PARSE_NEED (opc >= 1);
	PARSE_NEED (parse_k_or_x (f, op[0]));
	ut64 label;
	if (opc >= 2) {
		parse_label_value (&label, op[1]);
		f->jt = (label - pc - 8) / 8;
		f->jf = (pc >> 3) + 1;
	}
	if (opc == 3) {
		parse_label_value (&label, op[2]);
		f->jf = (label - pc - 8) / 8;
	}
	return true;
}

static bool parse_ind_or_abs(RBpfSockFilter *f, int opc, const bpf_token *op) {
	PARSE_NEED (opc >= 2);
	PARSE_STR (op[0], "[");
	if (TOKEN_EQ (op[1], "x")) {
		PARSE_NEED (opc == 4);
		f->code |= BPF_IND;
		PARSE_NEED (parse_k (f, op[2]));
		PARSE_STR (op[3], "]");
	} else {
		PARSE_NEED (opc == 3);
		f->code |= BPF_ABS;
		PARSE_NEED (parse_k (f, op[1]));
		PARSE_STR (op[2], "]");
	}
	return true;
}

static bool parse_ld(RBpfSockFilter *f, const char *mnemonic, int opc, const bpf_token *op) {
	switch (mnemonic[2]) {
	case '\0':
		PARSE_NEED (opc >= 1);
		if (opc == 4 && (TOKEN_EQ (op[0], "M") || TOKEN_EQ (op[0], "m"))) {
			f->code = BPF_LD | BPF_MEM;
			PARSE_NEED (opc == 4);
			PARSE_STR (op[1], "[");
			PARSE_NEED (parse_k (f, op[2]));
			PARSE_STR (op[3], "]");
			return true;
		} else if (opc >= 1 && is_k_tok (op[0])) {
			f->code = BPF_LD | BPF_IMM;
			return parse_k (f, op[0]);
		} else if (opc >= 1 && TOKEN_EQ (op[0], "len")) {
			f->code = BPF_LD | BPF_LEN;
			return true;
		} else {
			f->code = BPF_LD_W;
			return parse_ind_or_abs (f, opc, op);
		}
		break;
	case 'i':
		f->code = BPF_LD | BPF_IMM;
		PARSE_NEED (opc == 1);
		return parse_k (f, op[0]);
	case 'b':
		f->code = BPF_LD_B;
		return parse_ind_or_abs (f, opc, op);
	case 'h':
		f->code = BPF_LD_H;
		return parse_ind_or_abs (f, opc, op);
	case 'x':
		switch (mnemonic[3]) {
		case '\0':
			PARSE_NEED (opc >= 1);
			if (opc == 4 && (TOKEN_EQ (op[0], "M") || TOKEN_EQ (op[0], "m"))) {
				f->code = BPF_LDX | BPF_MEM;
				PARSE_NEED (opc == 4);
				PARSE_STR (op[1], "[")
					PARSE_NEED (parse_k (f, op[2]));
				PARSE_STR (op[3], "]");
				return true;
			} else if (opc >= 1 && is_k_tok (op[0])) {
				f->code = BPF_LDX | BPF_IMM;
				return parse_k (f, op[0]);
			} else if (opc >= 1 && TOKEN_EQ (op[0], "len")) {
				f->code = BPF_LDX | BPF_LEN;
				return true;
			} else {
				f->code = BPF_LDX_W;
				return parse_ind_or_abs (f, opc, op);
			}
			break;
		case 'i':
			f->code = BPF_LDX | BPF_IMM;
			PARSE_NEED (opc == 1);
			return parse_k (f, op[0]);
		case 'b':
			f->code = BPF_LDX_B | BPF_MSH;
			PARSE_NEED (opc == 9 || opc == 8);
			int i = 0;
			if (opc == 9) { PARSE_STR (op[0], "4"); PARSE_STR (op[1], "*"); i = 2; }
			else { PARSE_STR (op[0], "4*"); i = 1; }
			PARSE_STR (op[i + 0], "(");
			PARSE_STR (op[i + 1], "[");
			PARSE_NEED (parse_k (f, op[i + 2]));
			PARSE_STR (op[i + 3], "]");
			int rem = opc - (i + 4);
			if (rem == 3) {
				PARSE_STR (op[i + 4], "&"); PARSE_STR (op[i + 5], "0xf"); PARSE_STR (op[i + 6], ")");
			} else if (rem == 2) {
				PARSE_STR (op[i + 4], "&0xf"); PARSE_STR (op[i + 5], ")");
			} else { return false; }
			return true;
		}
		return false;
	}
	return false;
}

static bool parse_j (RBpfSockFilter *f, const char *m, int opc, const bpf_token *op, ut64 pc) {
	st8 temp;
	if (TOKEN_EQ (m, "jmp") || TOKEN_EQ (m, "ja")) {
		f->code = BPF_JMP_JA;
		PARSE_NEED (opc == 1);
		ut64 label = 0; PARSE_NEED (parse_label_value (&label, op[0]));
		f->k = (label - pc - 8) / 8;
		return true;
	}
	if (TOKEN_EQ (m, "jne") || TOKEN_EQ (m, "jneq")) {
		f->code = BPF_JMP_JEQ; PARSE_NEED (parse_jump_targets (f, opc, op, pc));
		temp = f->jt; f->jt = f->jf; f->jf = temp; return true;
	}
	if (TOKEN_EQ (m, "jeq")) {
		f->code = BPF_JMP_JEQ; PARSE_NEED (parse_jump_targets (f, opc, op, pc)); return true; }
	if (TOKEN_EQ (m, "jlt")) {
		f->code = BPF_JMP_JGE; PARSE_NEED (parse_jump_targets (f, opc, op, pc)); temp = f->jt; f->jt = f->jf; f->jf = temp; return true; }
	if (TOKEN_EQ (m, "jge")) {
		f->code = BPF_JMP_JGE; PARSE_NEED (parse_jump_targets (f, opc, op, pc)); return true; }
	if (TOKEN_EQ (m, "jle")) {
		f->code = BPF_JMP_JGT; PARSE_NEED (parse_jump_targets (f, opc, op, pc)); temp = f->jt; f->jt = f->jf; f->jf = temp; return true; }
	if (TOKEN_EQ (m, "jgt")) {
		f->code = BPF_JMP_JGT; PARSE_NEED (parse_jump_targets (f, opc, op, pc)); return true; }
	if (TOKEN_EQ (m, "jset")) {
		f->code = BPF_JMP_JSET; PARSE_NEED (parse_jump_targets (f, opc, op, pc)); return true; }
	return false;
}

static bool parse_alu(RBpfSockFilter *f, const char *m, int opc, const bpf_token *op) {
	if (TOKEN_EQ (m, "add")) { f->code = BPF_ALU_ADD; PARSE_NEED (opc == 1); PARSE_NEED (parse_k_or_x (f, op[0])); return true; }
	if (TOKEN_EQ (m, "sub")) { f->code = BPF_ALU_SUB; PARSE_NEED (opc == 1); PARSE_NEED (parse_k_or_x (f, op[0])); return true; }
	if (TOKEN_EQ (m, "mul")) { f->code = BPF_ALU_MUL; PARSE_NEED (opc == 1); PARSE_NEED (parse_k_or_x (f, op[0])); return true; }
	if (TOKEN_EQ (m, "div")) { f->code = BPF_ALU_DIV; PARSE_NEED (opc == 1); PARSE_NEED (parse_k_or_x (f, op[0])); return true; }
	if (TOKEN_EQ (m, "mod")) { f->code = BPF_ALU_MOD; PARSE_NEED (opc == 1); PARSE_NEED (parse_k_or_x (f, op[0])); return true; }
	if (TOKEN_EQ (m, "neg")) { f->code = BPF_ALU_NEG; PARSE_NEED (opc == 0); return true; }
	if (TOKEN_EQ (m, "and")) { f->code = BPF_ALU_AND; PARSE_NEED (opc == 1); PARSE_NEED (parse_k_or_x (f, op[0])); return true; }
	if (TOKEN_EQ (m, "or"))  { f->code = BPF_ALU_OR;  PARSE_NEED (opc == 1); PARSE_NEED (parse_k_or_x (f, op[0])); return true; }
	if (TOKEN_EQ (m, "xor")) { f->code = BPF_ALU_XOR; PARSE_NEED (opc == 1); PARSE_NEED (parse_k_or_x (f, op[0])); return true; }
	if (TOKEN_EQ (m, "lsh")) { f->code = BPF_ALU_LSH; PARSE_NEED (opc == 1); PARSE_NEED (parse_k_or_x (f, op[0])); return true; }
	if (TOKEN_EQ (m, "rsh")) { f->code = BPF_ALU_RSH; PARSE_NEED (opc == 1); PARSE_NEED (parse_k_or_x (f, op[0])); return true; }
	return false;
}

#ifndef RBPF_DIALECT_T_DEFINED
typedef enum {
	R_BPF_DIALECT_CLASSIC = 32,
	R_BPF_DIALECT_EXTENDED = 64,
} RBpfDialect;
#define RBPF_DIALECT_T_DEFINED
#endif

#include "../bpf/bpfasm.inc.c"

static RBpfDialect get_bpf_dialect2(RArchSession *s) {
	const char *cpu = s && s->config ? s->config->cpu : NULL;
	if (cpu) {
		if (!strcmp (cpu, "classic") || !strcmp (cpu, "cbpf") || !strcmp (cpu, "cBPF")) {
			return R_BPF_DIALECT_CLASSIC;
		}
		if (!strcmp (cpu, "extended") || !strcmp (cpu, "ebpf") || !strcmp (cpu, "eBPF") || !strcmp (cpu, "64")) {
			return R_BPF_DIALECT_EXTENDED;
		}
	}
	return (s && s->config && s->config->bits == 64) ? R_BPF_DIALECT_EXTENDED : R_BPF_DIALECT_CLASSIC;
}

static bool encode(RArchSession *s, RAnalOp *op, ut32 mask) {
	RBpfDialect dialect = get_bpf_dialect2 (s);
	RBpfSockFilter f = {0};
	BPFAsmParser p = { .str = op->mnemonic };
	ut8 ebuf[16] = {0};
	int elen = 0;
	bool ret = parse_instruction (&f, &p, op->addr, dialect, ebuf, &elen);
	token_fini (&p);
	if (!ret) return false;
	if (dialect == R_BPF_DIALECT_EXTENDED) {
		if (elen == 8 || elen == 16) {
			r_anal_op_set_bytes (op, op->addr, ebuf, elen);
			op->size = elen;
			return true;
		}
		return false;
	} else {
		ut8 encoded[8];
		r_write_le16 (encoded, f.code);
		encoded[2] = f.jt;
		encoded[3] = f.jf;
		r_write_le32 (encoded + 4, f.k);
		r_anal_op_set_bytes (op, op->addr, encoded, 8);
		op->size = 8;
		return true;
	}
}

static bool decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	CapstonePluginData *cpd = (CapstonePluginData*)a->data;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	op->size = 8;
	cs_insn *insn = NULL;
	int n = cs_disasm (cpd->cs_handle, (ut8*)buf, len, op->addr, 1, &insn);
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
	} else {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = r_str_newf ("%s%s%s",
				insn->mnemonic,
				insn->op_str[0]? " ": "",
				insn->op_str);
		}
		if (insn->detail) {
			switch (insn->id) {
#if CS_API_MAJOR > 5
			case BPF_INS_JAL:
#else
			case BPF_INS_JMP:
#endif
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = JUMP (0);
				break;
			case BPF_INS_JEQ:
			case BPF_INS_JGT:
			case BPF_INS_JGE:
			case BPF_INS_JSET:
			case BPF_INS_JNE:	///< eBPF only
			case BPF_INS_JSGT:	///< eBPF only
			case BPF_INS_JSGE:	///< eBPF only
			case BPF_INS_JLT:	///< eBPF only
			case BPF_INS_JLE:	///< eBPF only
			case BPF_INS_JSLT:	///< eBPF only
			case BPF_INS_JSLE:	///< eBPF only
				op->type = R_ANAL_OP_TYPE_CJMP;
				if (a->config->bits == 32) {
					op->jump = JUMP (1);
					op->fail = (insn->detail->bpf.op_count == 3) ? JUMP (2) : op->addr + insn->size;
				} else {
					op->jump = JUMP (2);
					op->fail = op->addr + insn->size;
				}
				break;
			case BPF_INS_CALL: ///< eBPF only
				op->type = R_ANAL_OP_TYPE_CALL;
				break;
			case BPF_INS_EXIT: ///< eBPF only
				//op->type = R_ANAL_OP_TYPE_TRAP;
				op->type = R_ANAL_OP_TYPE_RET;
				break;
			case BPF_INS_RET:
				op->type = R_ANAL_OP_TYPE_RET;
				break;
			case BPF_INS_TAX:
			case BPF_INS_TXA:
				op->type = R_ANAL_OP_TYPE_MOV;
				break;
			case BPF_INS_ADD:
			case BPF_INS_ADD64:
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			case BPF_INS_SUB:
			case BPF_INS_SUB64:
				op->type = R_ANAL_OP_TYPE_SUB;
				break;
			case BPF_INS_MUL:
			case BPF_INS_MUL64:
				op->type = R_ANAL_OP_TYPE_MUL;
				break;
			case BPF_INS_DIV:
			case BPF_INS_DIV64:
			case BPF_INS_MOD:
			case BPF_INS_MOD64:
				op->type = R_ANAL_OP_TYPE_DIV;
				break;
			case BPF_INS_OR:
			case BPF_INS_OR64:
				op->type = R_ANAL_OP_TYPE_OR;
				break;
			case BPF_INS_AND:
			case BPF_INS_AND64:
				op->type = R_ANAL_OP_TYPE_AND;
				break;
			case BPF_INS_LSH:
			case BPF_INS_LSH64:
				op->type = R_ANAL_OP_TYPE_SHL;
				break;
			case BPF_INS_RSH:
			case BPF_INS_RSH64:
				op->type = R_ANAL_OP_TYPE_SHR;
				break;
			case BPF_INS_XOR:
			case BPF_INS_XOR64:
				op->type = R_ANAL_OP_TYPE_XOR;
				break;
			case BPF_INS_NEG:
			case BPF_INS_NEG64:
				op->type = R_ANAL_OP_TYPE_NOT;
				break;
			case BPF_INS_ARSH:	///< eBPF only
						///< ALU64: eBPF only
			case BPF_INS_ARSH64:
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			case BPF_INS_MOV:	///< eBPF only
			case BPF_INS_MOV64:
			case BPF_INS_LDDW:	///< eBPF only: load 64-bit imm
				op->type = R_ANAL_OP_TYPE_MOV;
				if (OPCOUNT > 1 && OP (1).type == BPF_OP_IMM) {
					op->val = OP (1).imm;
				} else if (insn->size == 16) { // lddw wtf
					op->val = r_read_ble64 (insn->bytes + 8, 0) + IMM (0);
				}
				break;
				///< Byteswap: eBPF only
			case BPF_INS_LE16:
			case BPF_INS_LE32:
			case BPF_INS_LE64:
			case BPF_INS_BE16:
			case BPF_INS_BE32:
			case BPF_INS_BE64:
				op->type = R_ANAL_OP_TYPE_MOV;
				break;
				///< Load
			case BPF_INS_LDW:	///< eBPF only
			case BPF_INS_LDH:
			case BPF_INS_LDB:
			case BPF_INS_LDXW:	///< eBPF only
			case BPF_INS_LDXH:	///< eBPF only
			case BPF_INS_LDXB:	///< eBPF only
			case BPF_INS_LDXDW:	///< eBPF only
				op->type = R_ANAL_OP_TYPE_LOAD;
				break;
				///< Store
			case BPF_INS_STW:	///< eBPF only
			case BPF_INS_STH:	///< eBPF only
			case BPF_INS_STB:	///< eBPF only
			case BPF_INS_STDW:	///< eBPF only
			case BPF_INS_STXW:	///< eBPF only
			case BPF_INS_STXH:	///< eBPF only
			case BPF_INS_STXB:	///< eBPF only
			case BPF_INS_STXDW:	///< eBPF only
			case BPF_INS_XADDW:	///< eBPF only
			case BPF_INS_XADDDW:	///< eBPF only
				op->type = R_ANAL_OP_TYPE_STORE;
				break;
			}
			if (mask & R_ARCH_OP_MASK_ESIL) {
				analop_esil (a, op, insn, op->addr);
			}
		}
		op->size = insn->size;
		op->id = insn->id;
		cs_free (insn, n);
	}
	return op->size;
}

static char* regname(uint8_t reg) {
	switch (reg) {
	///< cBPF
	case BPF_REG_A:
		return "a";
	case BPF_REG_X:
		return "x";

	///< eBPF
	case BPF_REG_R0:
		return "r0";
	case BPF_REG_R1:
		return "r1";
	case BPF_REG_R2:
		return "r2";
	case BPF_REG_R3:
		return "r3";
	case BPF_REG_R4:
		return "r4";
	case BPF_REG_R5:
		return "r5";
	case BPF_REG_R6:
		return "r6";
	case BPF_REG_R7:
		return "r7";
	case BPF_REG_R8:
		return "r8";
	case BPF_REG_R9:
		return "r9";
	case BPF_REG_R10:
		return "r10";

	default:
		return "0"; // hax
	}
}

#define REG(n) (regname(OP(n).reg))
void bpf_alu(RArchSession *a, RAnalOp *op, cs_insn *insn, const char* operation, int bits) {
	if (OPCOUNT == 2 && a->config->bits == 64) { // eBPF
		if (bits == 64) {
			if (OP (1).type == BPF_OP_IMM) {
				op->val = IMM (1);
				esilprintf (op, "%" PFMT64d ",%s,%s=", IMM (1), REG (0), operation);
			} else {
				esilprintf (op, "%s,%s,%s=", REG (1), REG (0), operation);
			}
		} else {
			if (OP (1).type == BPF_OP_IMM) {
				op->val = IMM (1);
				esilprintf (op, "%" PFMT64d ",%s,0xffffffff,&,%s,0xffffffff,&,%s,=",
					IMM (1), REG (0), operation, REG (0));
			} else {
				esilprintf (op, "%s,%s,0xffffffff,&,%s,0xffffffff,&,%s,=",
					REG (1), REG (0), operation, REG (0));
			}
		}
	} else { // cBPF
		if (OPCOUNT > 0) {
			switch (OP (0).type) {
			case BPF_OP_IMM:
				op->val = IMM (0);
				esilprintf (op, "%" PFMT64d ",%s=", IMM (0), operation);
				break;
			case BPF_OP_REG:
				op->val = IMM (1);
				esilprintf (op, "%" PFMT64d ",%s,%s=", IMM (1), REG (0), operation);
				break;
			default:
				R_LOG_ERROR ("oops");
				break;
			}
		} else {
			esilprintf (op, "x,a,%s=", operation);
		}
	}
}

void bpf_load(RArchSession *a, RAnalOp *op, cs_insn *insn, char* reg, int size) {
	if (OPCOUNT > 1 && OP (0).type == BPF_OP_REG) {
		esilprintf (op, "%d,%s,+,[%d],%s,=",
			OP (1).mem.disp, regname(OP (1).mem.base), size, REG (0));
	} else if (OPCOUNT > 0 && OP (0).type == BPF_OP_MMEM) { // cBPF
		esilprintf (op, "m[%d],%s,=", OP (0).mmem, reg);
	} else if (OPCOUNT > 0) {
		esilprintf (op, "%d,%s,+,[%d],%s,=",
			OP (0).mem.disp, regname(OP (0).mem.base), size, reg);
	}
}

void bpf_store(RArchSession *a, RAnalOp *op, cs_insn *insn, char *reg, int size) {
	if (OPCOUNT > 0 && a->config->bits == 32) { // cBPF
		esilprintf (op, "%s,m[%d],=", reg, OP (0).mmem);
	} else if (OPCOUNT > 1) { // eBPF
		if (OP (1).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",%d,%s,+,=[%d]",
				IMM (1), OP (0).mem.disp, regname(OP (0).mem.base), size);
		} else {
			esilprintf (op, "%s,%d,%s,+,=[%d]",
				REG (1), OP (0).mem.disp, regname(OP (0).mem.base), size);
		}
	}
}

void bpf_jump(RArchSession *a, RAnalOp *op, cs_insn *insn, char *condition) {
	if (OPCOUNT > 0 && a->config->bits == 32) { // cBPF
		if (OP (0).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",a,NUM,%s,?{,0x%" PFMT64x ",}{,0x%" PFMT64x ",},pc,=",
				IMM (0), condition, op->jump, op->fail);
		} else {
			esilprintf (op, "x,NUM,a,NUM,%s,?{,0x%" PFMT64x ",}{,0x%" PFMT64x ",},pc,=",
				condition, op->jump, op->fail);
		}
	} else if (OPCOUNT > 1) { // eBPF
		if (OP (1).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",%s,%s,?{,0x%" PFMT64x ",pc,=,}",
				IMM (1), REG (0), condition, op->jump);
		} else {
			esilprintf (op, "%s,%s,%s,?{,0x%" PFMT64x ",pc,=,}",
				REG (1), REG (0), condition, op->jump);
		}
	}
}

#define ALU(c, b) bpf_alu (a, op, insn, c, b)
#define LOAD(c, s) bpf_load (a, op, insn, c, s)
#define STORE(c, s) bpf_store (a, op, insn, c, s)
#define CJMP(c) bpf_jump (a, op, insn, c)

static void analop_esil(RArchSession *a, RAnalOp *op, cs_insn *insn, ut64 addr) {
	switch (insn->id) {
#if CS_API_MAJOR > 5
	case BPF_INS_JAL:
#else
	case BPF_INS_JMP:
#endif
		esilprintf (op, "0x%" PFMT64x ",pc,=", op->jump);
		break;
	case BPF_INS_JEQ:
		CJMP ("==,$z");
		break;
	case BPF_INS_JGT:
		CJMP ("==,63,$c,$z,|,!");
		break;
	case BPF_INS_JGE:
		CJMP ("==,63,$c,!");
		break;
	case BPF_INS_JSET:
		CJMP ("&");
		break;
	case BPF_INS_JNE:	///< eBPF only
		CJMP ("-");
		break;
	case BPF_INS_JSGT:	///< eBPF only
		CJMP (">");
		break;
	case BPF_INS_JSGE:	///< eBPF only
		CJMP (">=");
		break;
	case BPF_INS_JLT:	///< eBPF only
		CJMP ("==,63,$c");
		break;
	case BPF_INS_JSLT:	///< eBPF only
		CJMP ("<");
		break;
	case BPF_INS_JLE:	///< eBPF only
		CJMP ("==,63,$c,$z,|");
		break;
	case BPF_INS_JSLE:	///< eBPF only
		CJMP ("<=");
		break;
	case BPF_INS_CALL:	///< eBPF only
		// the call immediate is almost never used as an addr so its an INT
		// maybe this will change in the future once the relocs are added?
		esilprintf (op, "pc,sp,=[8],8,sp,-=,0x%" PFMT64x ",$", IMM (0));
		break;
	case BPF_INS_EXIT:	///< eBPF only
		esilprintf (op, "8,sp,+=,sp,[8],pc,=");
		break;
	case BPF_INS_RET:
		// cBPF shouldnt really need the stack, but gonna leave it
		esilprintf (op, "%" PFMT64d ",r0,=,8,sp,+=,sp,[8],pc,=", IMM (0));
		break;
	case BPF_INS_TAX:
		esilprintf (op, "a,x,=");
		break;
	case BPF_INS_TXA:
		esilprintf (op, "x,a,=");
		break;
	case BPF_INS_ADD:
		ALU ("+", 32);
		break;
	case BPF_INS_ADD64:
		ALU ("+", 64);
		break;
	case BPF_INS_SUB:
		ALU ("-", 32);
		break;
	case BPF_INS_SUB64:
		ALU ("-", 64);
		break;
	case BPF_INS_MUL:
		ALU ("*", 32);
		break;
	case BPF_INS_MUL64:
		ALU ("*", 64);
		break;
	case BPF_INS_DIV:
		ALU ("/", 32);
		break;
	case BPF_INS_DIV64:
		ALU ("/", 64);
		break;
	case BPF_INS_MOD:
		ALU ("%", 32);
		break;
	case BPF_INS_MOD64:
		ALU ("%", 64);
		break;
	case BPF_INS_OR:
		ALU ("|", 32);
		break;
	case BPF_INS_OR64:
		ALU ("|", 64);
		break;
	case BPF_INS_AND:
		ALU ("&", 32);
		break;
	case BPF_INS_AND64:
		ALU ("&", 64);
		break;
	case BPF_INS_LSH:
		ALU ("<<", 32);
		break;
	case BPF_INS_LSH64:
		ALU ("<<", 64);
		break;
	case BPF_INS_RSH:
		ALU (">>", 32);
		break;
	case BPF_INS_RSH64:
		ALU (">>", 64);
		break;
	case BPF_INS_XOR:
		ALU ("^", 32);
		break;
	case BPF_INS_XOR64:
		ALU ("^", 64);
		break;
	case BPF_INS_NEG:
		if (OPCOUNT == 1) {
			esilprintf (op, "-1,%s,*,0xffffffff,&,%s,=", REG (0), REG (0));
			break;
		} else {
			esilprintf (op, "-1,a,*=");
			break;
		}
	case BPF_INS_NEG64:
		esilprintf (op, "-1,%s,*=", REG (0));
		break;
	case BPF_INS_ARSH:	///< eBPF only
		ALU (">>>>", 32);
		break;
	case BPF_INS_ARSH64:
		ALU (">>>>", 64);
		break;
	case BPF_INS_MOV:	///< eBPF only
		if (OP (1).type == BPF_OP_IMM) {
			// i already truncate IMM to 32 bits
			esilprintf (op, "%" PFMT64d ",%s,=", IMM (1), REG (0));
		} else {
			esilprintf (op, "%s,0xffffffff,&,%s,=", REG (1), REG (0));
		}
		break;
	case BPF_INS_LDDW:	///< eBPF only: load 64-bit imm
	{
		char *reg = regname(insn->bytes[1]+3);
		ut64 val = r_read_ble64((insn->bytes)+8, 0) + IMM (0); // wtf
		esilprintf (op, "%" PFMT64d ",%s,=", val, reg);
		break;
	}
	case BPF_INS_MOV64:
		if (OP (1).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",%s,=", IMM (1), REG (0));
		} else {
			esilprintf (op, "%s,%s,=", REG (1), REG (0));
		}
		break;
		///< Byteswap: eBPF only
	case BPF_INS_LE16:
	case BPF_INS_LE32:
	case BPF_INS_LE64:
		break; // TODO we are assuming host is LE right now and maybe forever
	case BPF_INS_BE16:
	{
		const char *r0 = REG (0);
		esilprintf (op, "8,%s,>>,0xff,&,8,%s,<<,0xffff,&,|,%s,=", r0, r0, r0);
		break;
	}
	case BPF_INS_BE32:
	{
		const char *r0 = REG (0);
		esilprintf (op,
				"0xffffffff,%s,&=,"
				"24,0xff,%s,&,<<,tmp,=,"
				"16,0xff,8,%s,>>,&,<<,tmp,|=,"
				"8,0xff,16,%s,>>,&,<<,tmp,|=,"
				"0xff,24,%s,>>,&,tmp,|=,tmp,%s,=",
				r0, r0, r0, r0, r0, r0);

		break;
	}
	case BPF_INS_BE64:
	{
		const char *r0 = REG (0);
		esilprintf (op,
			"56,0xff,%s,&,<<,tmp,=,"
			"48,0xff,8,%s,>>,&,<<,tmp,|=,"
			"40,0xff,16,%s,>>,&,<<,tmp,|=,"
			"32,0xff,24,%s,>>,&,<<,tmp,|=,"
			"24,0xff,32,%s,>>,&,<<,tmp,|=,"
			"16,0xff,40,%s,>>,&,<<,tmp,|=,"
			"8,0xff,48,%s,>>,&,<<,tmp,|=,"
			"0xff,56,%s,>>,&,tmp,|=,tmp,%s,=",
			r0, r0, r0, r0, r0, r0, r0, r0, r0);

		break;
	}
		///< Load
	case BPF_INS_LDW:	///< eBPF only
		LOAD ("a", 4);
		break;
	case BPF_INS_LDXW:	///< eBPF only
		LOAD ("x", 4);
		break;
	case BPF_INS_LDH:
		LOAD ("a", 2);
		break;
	case BPF_INS_LDXH:	///< eBPF only
		LOAD ("x", 2);
		break;
	case BPF_INS_LDB:
		LOAD ("a", 1);
		break;
	case BPF_INS_LDXB:	///< eBPF only
		LOAD ("x", 1);
		break;
	case BPF_INS_LDXDW:	///< eBPF only
		LOAD ("a", 8); // reg never used here
		break;
		///< Store
	case BPF_INS_STW:	///< eBPF only
		STORE ("a", 4);
		break;
	case BPF_INS_STXW:	///< eBPF only
		STORE ("x", 4);
		break;
	case BPF_INS_STH:	///< eBPF only
	case BPF_INS_STXH:	///< eBPF only
		STORE ("a", 2);
		break;
	case BPF_INS_STB:	///< eBPF only
	case BPF_INS_STXB:	///< eBPF only
		STORE ("a", 1);
		break;
	case BPF_INS_STDW:	///< eBPF only
	case BPF_INS_STXDW:	///< eBPF only
		STORE ("a", 8);
		break;

	case BPF_INS_XADDW:	///< eBPF only
		esilprintf (op, "%s,0xffffffff,&,%d,%s,+,[4],DUP,%s,=,+,%d,%s,+,=[4]",
			REG (1), OP (0).mem.disp, regname(OP (0).mem.base),
			REG (1), OP (0).mem.disp, regname(OP (0).mem.base));

		break;
	case BPF_INS_XADDDW: ///< eBPF only
		esilprintf (op, "%s,NUM,%d,%s,+,[8],DUP,%s,=,+,%d,%s,+,=[8]",
			REG (1), OP (0).mem.disp, regname(OP (0).mem.base),
			REG (1), OP (0).mem.disp, regname(OP (0).mem.base));

		break;
	}
}

static char *regs(RArchSession *as) {
	const char *p =
		"=PC    pc\n"
		"=A0    r1\n"
		"=A1    r2\n"
		"=A2    r3\n"
		"=A3    r4\n"
		"=R0    r0\n"
		"=SP    r10\n"
		"=BP    r10\n"
		"gpr    z        .32 ?    0\n"
		"gpr    a        .32 0    0\n"
		"gpr    x        .32 4    0\n"
		"gpr    m[0]     .32 8    0\n"
		"gpr    m[1]     .32 12   0\n"
		"gpr    m[2]     .32 16   0\n"
		"gpr    m[3]     .32 20   0\n"
		"gpr    m[4]     .32 24   0\n"
		"gpr    m[5]     .32 28   0\n"
		"gpr    m[6]     .32 32   0\n"
		"gpr    m[7]     .32 36   0\n"
		"gpr    m[8]     .32 40   0\n"
		"gpr    m[9]     .32 44   0\n"
		"gpr    m[10]    .32 48   0\n"
		"gpr    m[11]    .32 52   0\n"
		"gpr    m[12]    .32 56   0\n"
		"gpr    m[13]    .32 60   0\n"
		"gpr    m[14]    .32 64   0\n"
		"gpr    m[15]    .32 68   0\n"
		"gpr    pc       .64 72   0\n"
		"gpr    r0       .64 80   0\n"
		"gpr    r1       .64 88   0\n"
		"gpr    r2       .64 96   0\n"
		"gpr    r3       .64 104  0\n"
		"gpr    r4       .64 112  0\n"
		"gpr    r5       .64 120  0\n"
		"gpr    r6       .64 128  0\n"
		"gpr    r7       .64 136  0\n"
		"gpr    r8       .64 144  0\n"
		"gpr    r9       .64 152  0\n"
		"gpr    r10      .64 160  0\n"
		"gpr    sp       .64 160  0\n"
		"gpr    tmp      .64 168  0\n";
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	const int bits = as->config->bits;
	switch (q) {
		// R_ARCH_INFO_MINOPSZ
	case R_ARCH_INFO_MINOP_SIZE:
		return 8;
	case R_ARCH_INFO_MAXOP_SIZE:
		return (bits == 64)? 16: 8;
	case R_ARCH_INFO_INVOP_SIZE:
		return 8;
	case R_ARCH_INFO_CODE_ALIGN:
		return 8;
	case R_ARCH_INFO_DATA_ALIGN:
		return 1;
	}
	return 0;
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

static bool fini(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	CapstonePluginData *cpd = (CapstonePluginData*)s->data;
	cs_close (&cpd->cs_handle);
	R_FREE (s->data);
	return true;
}

const RArchPlugin r_arch_plugin_bpf_cs = {
	.meta = {
		.name = "bpf",
		.desc = "Capstone Berkeley Packet Filtering bytecode",
		.license = "BSD-3-Clause",
		.author = "terorie,aemmitt",
	},
	.arch = "bpf",
	.cpus = "classic,extended",
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.info = archinfo,
	.regs = &regs,
	.decode = &decode,
	.mnemonics = &mnemonics,
	.encode = &encode,
	.init = init,
	.fini = fini
};

#else
const RArchPlugin r_arch_plugin_bpf_cs = {0};
#endif // CS_API_MAJOR

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
#if CS_API_MAJOR >= 5
	.data = &r_anal_plugin_bpf_cs,
#endif
	.version = R2_VERSION
};
#endif

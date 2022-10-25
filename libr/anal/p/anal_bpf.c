/* radare2 - LGPL - Copyright 2015-2022 - mrmacete, pancake */

#include <r_lib.h>
#include <r_anal.h>
#include "../arch/bpf/bpf.h"

// disassembly
static int disassemble(RAnalOp *r_op, ut64 pc, const ut8 *buf, int len) {
	const char *op, *fmt;
	RBpfSockFilter *f = (RBpfSockFilter *)buf;
	int val = f->k;
	char vbuf[256];

	switch (f->code) {
	case BPF_RET | BPF_K:
		op = r_bpf_op_table[BPF_RET];
		fmt = "%#x";
		break;
	case BPF_RET | BPF_A:
		op = r_bpf_op_table[BPF_RET];
		fmt = "a";
		break;
	case BPF_RET | BPF_X:
		op = r_bpf_op_table[BPF_RET];
		fmt = "x";
		break;
	case BPF_MISC_TAX:
		op = r_bpf_op_table[BPF_MISC_TAX];
		fmt = "";
		break;
	case BPF_MISC_TXA:
		op = r_bpf_op_table[BPF_MISC_TXA];
		fmt = "";
		break;
	case BPF_ST:
		op = r_bpf_op_table[BPF_ST];
		fmt = "M[%d]";
		break;
	case BPF_STX:
		op = r_bpf_op_table[BPF_STX];
		fmt = "M[%d]";
		break;
	case BPF_LD_W | BPF_ABS:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "[%d]";
		break;
	case BPF_LD_H | BPF_ABS:
		op = r_bpf_op_table[BPF_LD_H];
		fmt = "[%d]";
		break;
	case BPF_LD_B | BPF_ABS:
		op = r_bpf_op_table[BPF_LD_B];
		fmt = "[%d]";
		break;
	case BPF_LD_W | BPF_LEN:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "len";
		break;
	case BPF_LD_W | BPF_IND:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "[x%+d]";
		break;
	case BPF_LD_H | BPF_IND:
		op = r_bpf_op_table[BPF_LD_H];
		fmt = "[x%+d]";
		break;
	case BPF_LD_B | BPF_IND:
		op = r_bpf_op_table[BPF_LD_B];
		fmt = "[x%+d]";
		break;
	case BPF_LD | BPF_IMM:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "%#x";
		break;
	case BPF_LDX | BPF_IMM:
		op = r_bpf_op_table[BPF_LDX];
		fmt = "%#x";
		break;
	case BPF_LDX | BPF_LEN:
		op = r_bpf_op_table[BPF_LDX];
		fmt = "len";
		break;
	case BPF_LDX | BPF_ABS:
		op = r_bpf_op_table[BPF_LDX];
		fmt = "[%d]";
		break;
	case BPF_LDX_B | BPF_MSH:
		op = r_bpf_op_table[BPF_LDX_B];
		fmt = "4*([%d]&0xf)";
		break;
	case BPF_LD | BPF_MEM:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "M[%d]";
		break;
	case BPF_LDX | BPF_MEM:
		op = r_bpf_op_table[BPF_LDX];
		fmt = "M[%d]";
		break;
	case BPF_JMP_JA:
		op = r_bpf_op_table[BPF_JMP_JA];
		fmt = "%d";
		val = pc + 8 + f->k * 8;
		break;
	case BPF_JMP_JGT | BPF_X:
		op = r_bpf_op_table[BPF_JMP_JGT];
		fmt = "x";
		break;
	case BPF_JMP_JGT | BPF_K:
		op = r_bpf_op_table[BPF_JMP_JGT];
		fmt = "%#x";
		break;
	case BPF_JMP_JGE | BPF_X:
		op = r_bpf_op_table[BPF_JMP_JGE];
		fmt = "x";
		break;
	case BPF_JMP_JGE | BPF_K:
		op = r_bpf_op_table[BPF_JMP_JGE];
		fmt = "%#x";
		break;
	case BPF_JMP_JEQ | BPF_X:
		op = r_bpf_op_table[BPF_JMP_JEQ];
		fmt = "x";
		break;
	case BPF_JMP_JEQ | BPF_K:
		op = r_bpf_op_table[BPF_JMP_JEQ];
		fmt = "%#x";
		break;
	case BPF_JMP_JSET | BPF_X:
		op = r_bpf_op_table[BPF_JMP_JSET];
		fmt = "x";
		break;
	case BPF_JMP_JSET | BPF_K:
		op = r_bpf_op_table[BPF_JMP_JSET];
		fmt = "%#x";
		break;
	case BPF_ALU_NEG:
		op = r_bpf_op_table[BPF_ALU_NEG];
		fmt = "";
		break;
	case BPF_ALU_LSH | BPF_X:
		op = r_bpf_op_table[BPF_ALU_LSH];
		fmt = "x";
		break;
	case BPF_ALU_LSH | BPF_K:
		op = r_bpf_op_table[BPF_ALU_LSH];
		fmt = "%d";
		break;
	case BPF_ALU_RSH | BPF_X:
		op = r_bpf_op_table[BPF_ALU_RSH];
		fmt = "x";
		break;
	case BPF_ALU_RSH | BPF_K:
		op = r_bpf_op_table[BPF_ALU_RSH];
		fmt = "%d";
		break;
	case BPF_ALU_ADD | BPF_X:
		op = r_bpf_op_table[BPF_ALU_ADD];
		fmt = "x";
		break;
	case BPF_ALU_ADD | BPF_K:
		op = r_bpf_op_table[BPF_ALU_ADD];
		fmt = "%d";
		break;
	case BPF_ALU_SUB | BPF_X:
		op = r_bpf_op_table[BPF_ALU_SUB];
		fmt = "x";
		break;
	case BPF_ALU_SUB | BPF_K:
		op = r_bpf_op_table[BPF_ALU_SUB];
		fmt = "%d";
		break;
	case BPF_ALU_MUL | BPF_X:
		op = r_bpf_op_table[BPF_ALU_MUL];
		fmt = "x";
		break;
	case BPF_ALU_MUL | BPF_K:
		op = r_bpf_op_table[BPF_ALU_MUL];
		fmt = "%d";
		break;
	case BPF_ALU_DIV | BPF_X:
		op = r_bpf_op_table[BPF_ALU_DIV];
		fmt = "x";
		break;
	case BPF_ALU_DIV | BPF_K:
		op = r_bpf_op_table[BPF_ALU_DIV];
		fmt = "%d";
		break;
	case BPF_ALU_MOD | BPF_X:
		op = r_bpf_op_table[BPF_ALU_MOD];
		fmt = "x";
		break;
	case BPF_ALU_MOD | BPF_K:
		op = r_bpf_op_table[BPF_ALU_MOD];
		fmt = "%d";
		break;
	case BPF_ALU_AND | BPF_X:
		op = r_bpf_op_table[BPF_ALU_AND];
		fmt = "x";
		break;
	case BPF_ALU_AND | BPF_K:
		op = r_bpf_op_table[BPF_ALU_AND];
		fmt = "%#x";
		break;
	case BPF_ALU_OR | BPF_X:
		op = r_bpf_op_table[BPF_ALU_OR];
		fmt = "x";
		break;
	case BPF_ALU_OR | BPF_K:
		op = r_bpf_op_table[BPF_ALU_OR];
		fmt = "%#x";
		break;
	case BPF_ALU_XOR | BPF_X:
		op = r_bpf_op_table[BPF_ALU_XOR];
		fmt = "x";
		break;
	case BPF_ALU_XOR | BPF_K:
		op = r_bpf_op_table[BPF_ALU_XOR];
		fmt = "%#x";
		break;
	default:
		op = "invalid";
		fmt = "%#x";
		val = f->code;
		break;
	}

	snprintf (vbuf, sizeof (vbuf), fmt, val);

	if ((BPF_CLASS (f->code) == BPF_JMP && BPF_OP (f->code) != BPF_JA)) {
		r_op->mnemonic = r_str_newf ("%s %s, 0x%08" PFMT64x ", 0x%08" PFMT64x, op, vbuf,
			pc + 8 + f->jt * 8, pc + 8 + f->jf * 8);
	} else {
		r_op->mnemonic = r_str_newf ("%s %s", op, vbuf);
	}

	return r_op->size = 8;
}

/* start of ASSEMBLER code */

#define TOKEN_MAX_LEN 15
typedef char bpf_token[TOKEN_MAX_LEN + 1];

#define SWAP_JUMP_TARGETS(f) \
	temp = f->jt; \
	f->jt = f->jf; \
	f->jf = temp;

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
		// Skip the whitespace
		case ' ':
		case '\t':
			p++;
			continue;
		// Skip the rest of the line is a comment is encountered
		case ';':
			return NULL;
		default:
			return p;
		}
	}
	// Nothing left
	return NULL;
}

static inline bool is_single_char_token(char c) {
	return c == '(' || c == ')' || c == '[' || c == ']';
}

static inline bool is_arithmetic(char c) {
	return c == '+' || c == '-';
}

static const char *token_next(BPFAsmParser *t) {
	token_fini (t);

	// Seek to token
	t->str = trim_input (t->str);
	if (!t->str) {
		return NULL;
	}

	// Allocate scratch space for token
	RStrBuf *token = r_strbuf_new (NULL);
	if (token == NULL) {
		return NULL;
	}
	if (!r_strbuf_reserve (token, TOKEN_MAX_LEN + 1)) {
		r_strbuf_free (token);
		return NULL;
	}
	t->token = token;

	if (is_single_char_token (t->str[0])) {
		r_strbuf_append_n (token, t->str++, 1);
		return r_strbuf_get (token);
	}

	// Gather a handful of chars
	// Use isgraph instead of isprint because the latter considers ' ' printable
	int i;
	for (i = 0; i < TOKEN_MAX_LEN; i++) {
		if (!isgraph (t->str[0]) || is_single_char_token (t->str[0]) || (is_arithmetic (t->str[0]) && i != 0)) {
			break;
		}
		r_strbuf_append_n (token, t->str++, 1);
	}
	if (i == TOKEN_MAX_LEN) {
		return NULL; // token too long
	}
	return r_strbuf_get (token);
}

static bool is_k_tok(const char *tok) {
	return is_arithmetic (tok[0]) || R_BETWEEN ('0', tok[0], '9');
}

static bool parse_k(RBpfSockFilter *f, const char *t) {
	char *t2;
	f->k = strtol (t, &t2, 0);
	return t != t2;
}

static bool parse_k_or_x(RBpfSockFilter *f, const char *t) {
	if (TOKEN_EQ (t, "x")) {
		f->code |= BPF_X;
		return true;
	} else {
		f->code |= BPF_K;
		return parse_k (f, t);
	}
}

static bool parse_label_value(ut64 *out, const char *t) {
	char *t2;
	*out = strtoul (t, &t2, 0);
	return t != t2;
}

static bool parse_label(RBpfSockFilter *f, const char *t) {
	ut64 k = 0;
	bool r = parse_label_value (&k, t);
	f->k = k;
	return r;
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

static bool parse_ind_or_abs (RBpfSockFilter *f, int opc, const bpf_token *op) {
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

static bool parse_ld (RBpfSockFilter *f, const char *mnemonic, int opc, const bpf_token *op) {
	switch (mnemonic[2]) {
	case '\0':
		PARSE_NEED (opc >= 2);
		if (TOKEN_EQ (op[1], "m")) {
			f->code = BPF_LD | BPF_MEM;
			PARSE_NEED (opc == 4);
			PARSE_STR (op[1], "[");
			PARSE_NEED (parse_k (f, op[2]));
			PARSE_STR (op[3], "]");
			return true;
		} else if (is_k_tok (op[1])) {
			f->code = BPF_LD | BPF_IMM;
			return parse_k (f, op[1]);
		} else if (TOKEN_EQ (op[1], "len")) {
			f->code = BPF_LD | BPF_LEN;
			return true;
		} else {
			f->code = BPF_LD_W;
			return parse_ind_or_abs (f, opc, op);
		}
		break;
	case 'i':
		f->code = BPF_LD | BPF_IMM;
		PARSE_NEED (opc == 2);
		return parse_k (f, op[1]);
	case 'b':
		f->code = BPF_LD_B;
		return parse_ind_or_abs (f, opc, op);
	case 'h':
		f->code = BPF_LD_H;
		return parse_ind_or_abs (f, opc, op);
	case 'x':
		switch (mnemonic[3]) {
		case '\0':
			PARSE_NEED (opc >= 2);
			if (TOKEN_EQ (op[1], "m")) {
				f->code = BPF_LDX | BPF_MEM;
				PARSE_NEED (opc == 4);
				PARSE_STR (op[1], "[")
				PARSE_NEED (parse_k (f, op[2]));
				PARSE_STR (op[3], "]");
				return true;
			} else if (is_k_tok (op[1])) {
				f->code = BPF_LDX | BPF_IMM;
				return parse_k (f, op[1]);
			} else if (TOKEN_EQ (op[1], "len")) {
				f->code = BPF_LDX | BPF_LEN;
				return true;
			} else {
				f->code = BPF_LDX_W;
				return parse_ind_or_abs (f, opc, op);
			}
			break;
		case 'i':
			f->code = BPF_LDX | BPF_IMM;
			PARSE_NEED (opc == 2);
			return parse_k (f, op[1]);
		case 'b':
			f->code = BPF_LDX_B | BPF_MSH;
			PARSE_NEED (opc == 10);
			PARSE_STR (op[1], "4");
			PARSE_STR (op[2], "*");
			PARSE_STR (op[3], "(");
			PARSE_STR (op[4], "[");
			PARSE_NEED (parse_k (f, op[5]));
			PARSE_STR (op[6], "]");
			PARSE_STR (op[7], "&");
			PARSE_STR (op[8], "0xf");
			PARSE_STR (op[9], ")");
			break;
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
		PARSE_NEED (parse_label (f, op[0]))
		return true;
	}

	if (TOKEN_EQ (m, "jne") || TOKEN_EQ (m, "jneq")) {
		f->code = BPF_JMP_JEQ;
		PARSE_NEED (parse_jump_targets (f, opc, op, pc));
		SWAP_JUMP_TARGETS (f);
		return true;
	}
	if (TOKEN_EQ (m, "jeq")) {
		f->code = BPF_JMP_JEQ;
		PARSE_NEED (parse_jump_targets (f, opc, op, pc));
		return true;
	}

	if (TOKEN_EQ (m, "jlt")) {
		f->code = BPF_JMP_JGE;
		PARSE_NEED (parse_jump_targets (f, opc, op, pc));
		SWAP_JUMP_TARGETS (f);
		return true;
	}
	if (TOKEN_EQ (m, "jge")) {
		f->code = BPF_JMP_JGE;
		PARSE_NEED (parse_jump_targets (f, opc, op, pc));
		return true;
	}

	if (TOKEN_EQ (m, "jle")) {
		f->code = BPF_JMP_JGT;
		PARSE_NEED (parse_jump_targets (f, opc, op, pc));
		SWAP_JUMP_TARGETS (f);
		return true;
	}
	if (TOKEN_EQ (m, "jgt")) {
		f->code = BPF_JMP_JGT;
		PARSE_NEED (parse_jump_targets (f, opc, op, pc));
		return true;
	}

	if (TOKEN_EQ (m, "jge")) {
		f->code = BPF_JMP_JGE;
		PARSE_NEED (parse_jump_targets (f, opc, op, pc));
		return true;
	}

	if (TOKEN_EQ (m, "jset")) {
		f->code = BPF_JMP_JSET;
		PARSE_NEED (parse_jump_targets (f, opc, op, pc));
		return true;
	}

	return false;
}

static bool parse_alu (RBpfSockFilter *f, const char *m, int opc, const bpf_token *op) {
	if (TOKEN_EQ (m, "add")) {
		f->code = BPF_ALU_ADD;
		PARSE_NEED (opc == 1);
		PARSE_NEED (parse_k_or_x (f, op[0]));
		return true;
	}
	if (TOKEN_EQ (m, "sub")) {
		f->code = BPF_ALU_SUB;
		PARSE_NEED (opc == 1);
		PARSE_NEED (parse_k_or_x (f, op[0]));
		return true;
	}
	if (TOKEN_EQ (m, "mul")) {
		f->code = BPF_ALU_MUL;
		PARSE_NEED (opc == 1);
		PARSE_NEED (parse_k_or_x (f, op[0]));
		return true;
	}
	if (TOKEN_EQ (m, "div")) {
		f->code = BPF_ALU_DIV;
		PARSE_NEED (opc == 1);
		PARSE_NEED (parse_k_or_x (f, op[0]));
		return true;
	}
	if (TOKEN_EQ (m, "mod")) {
		f->code = BPF_ALU_MOD;
		PARSE_NEED (opc == 1);
		PARSE_NEED (parse_k_or_x (f, op[0]));
		return true;
	}
	if (TOKEN_EQ (m, "neg")) {
		f->code = BPF_ALU_NEG;
		PARSE_NEED (opc == 0);
		return true;
	}
	if (TOKEN_EQ (m, "and")) {
		f->code = BPF_ALU_AND;
		PARSE_NEED (opc == 1);
		PARSE_NEED (parse_k_or_x (f, op[0]));
		return true;
	}
	if (TOKEN_EQ (m, "or")) {
		f->code = BPF_ALU_OR;
		PARSE_NEED (opc == 1);
		PARSE_NEED (parse_k_or_x (f, op[0]));
		return true;
	}
	if (TOKEN_EQ (m, "xor")) {
		f->code = BPF_ALU_XOR;
		PARSE_NEED (opc == 1);
		PARSE_NEED (parse_k_or_x (f, op[0]));
		return true;
	}
	if (TOKEN_EQ (m, "lsh")) {
		f->code = BPF_ALU_LSH;
		PARSE_NEED (opc == 1);
		PARSE_NEED (parse_k_or_x (f, op[0]));
		return true;
	}
	if (TOKEN_EQ (m, "rsh")) {
		f->code = BPF_ALU_RSH;
		PARSE_NEED (opc == 1);
		PARSE_NEED (parse_k_or_x (f, op[0]));
		return true;
	}
	return false;
}

static bool parse_instruction (RBpfSockFilter *f, BPFAsmParser *p, ut64 pc) {
	const char *mnemonic_tok = token_next (p);
	PARSE_NEED_TOKEN (mnemonic_tok);
	int mlen = strnlen (mnemonic_tok, 5);
	if (mlen < 2 || mlen > 4) {
		R_LOG_ERROR ("invalid mnemonic");
	}

	char mnemonic[5] = {0};
	strncpy (mnemonic, mnemonic_tok, 4);

	int opc;
	bpf_token op[11] = {0};
	for (opc = 0; opc < (sizeof (op) / sizeof (op[0]));) {
		const char *t = token_next (p);
		if (t == NULL) {
			break;
		}
		strncpy (op[opc++], t, TOKEN_MAX_LEN);
	}

	if (TOKEN_EQ (mnemonic, "txa")) {
		f->code = BPF_MISC_TXA;
		return true;
	}
	if (TOKEN_EQ (mnemonic, "tax")) {
		f->code = BPF_MISC_TAX;
		return true;
	}

	if (TOKEN_EQ (mnemonic, "ret")) {
		f->code = BPF_RET;
		PARSE_NEED (opc == 1);
		if (is_k_tok (op[0])) {
			f->code |= BPF_K;
			return parse_k (f, op[0]);
		} else if (TOKEN_EQ (op[0], "x")) {
			f->code |= BPF_X;
			return true;
		} else if (TOKEN_EQ (op[0], "a")) {
			f->code |= BPF_A;
			return true;
		} else {
			return false;
		}
	}

	if (strncmp (mnemonic, "ld", 2) == 0) {
		return parse_ld (f, mnemonic, opc, op);
	}

	if (strncmp (mnemonic, "st", 2) == 0) {
		switch (mnemonic[2]) {
		case '\0': f->code = BPF_ST; break;
		case 'x': f->code = BPF_STX; break;
		default: return false;
		}
		PARSE_NEED (opc == 4);
		PARSE_STR (op[1], "[")
		PARSE_NEED (parse_k (f, op[2]));
		PARSE_STR (op[3], "]");
		return true;
	}

	if (mnemonic[0] == 'j') {
		return parse_j (f, mnemonic, opc, op, pc);
	}

	return parse_alu (f, mnemonic, opc, op);
}

static int bpf_opasm (RAnal *a, ut64 pc, const char *str, ut8 *outbuf, int outsize) {
	if (outsize < 8) {
		return -1;
	}

	RBpfSockFilter f = {0};
	BPFAsmParser p = { .str = str };

	bool ret = parse_instruction (&f, &p, pc);
	token_fini (&p);
	if (!ret) {
		return -1;
	}

	memcpy (outbuf, &f, 8);
	return 8;
}

/// analysis

#define EMIT_CJMP(op, addr, f) \
	(op)->type = R_ANAL_OP_TYPE_CJMP; \
	(op)->jump = (addr) + 8 + (f)->jt * 8; \
	(op)->fail = (addr) + 8 + (f)->jf * 8;

#define EMIT_LOAD(op, addr, size) \
	(op)->type = R_ANAL_OP_TYPE_LOAD; \
	(op)->ptr = (addr); \
	(op)->ptrsize = (size);

#define NEW_SRC_DST(op) \
	src = r_vector_push (&(op)->srcs, NULL); \
	dst = r_vector_push (&(op)->dsts, NULL);

#define SET_REG_SRC_DST(op, _src, _dst) \
	NEW_SRC_DST ((op)); \
	src->reg = r_reg_get (anal->reg, (_src), R_REG_TYPE_GPR); \
	dst->reg = r_reg_get (anal->reg, (_dst), R_REG_TYPE_GPR);

#define SET_REG_DST_IMM(op, _dst, _imm) \
	NEW_SRC_DST ((op)); \
	dst->reg = r_reg_get (anal->reg, (_dst), R_REG_TYPE_GPR); \
	src->imm = (_imm);

#define SET_A_SRC(op) \
	src = r_vector_push (&(op)->srcs, NULL); \
	src->reg = r_reg_get (anal->reg, "A", R_REG_TYPE_GPR);

#define SET_A_DST(op) \
	dst = r_vector_push (&(op)->dsts, NULL); \
	dst->reg = r_reg_get (anal->reg, "A", R_REG_TYPE_GPR);

// (k) >= 0 must also be true, but the value is already unsigned
#define INSIDE_M(k) ((k) < 16)

/*
static bool bpf_int_exit(RAnalEsil *esil, ut32 interrupt, void *user);
RAnalEsilInterruptHandler ih = { 0, NULL, NULL, &bpf_int_exit, NULL };
*/

static const char *M[] = {
	"m[0]",
	"m[1]",
	"m[2]",
	"m[3]",
	"m[4]",
	"m[5]",
	"m[6]",
	"m[7]",
	"m[8]",
	"m[9]",
	"m[10]",
	"m[11]",
	"m[12]",
	"m[13]",
	"m[14]",
	"m[15]"
};

static int bpf_anal (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	RAnalValue *dst, *src;
	RBpfSockFilter *f = (RBpfSockFilter *)data;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = UT64_MAX;
	op->val = -1;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = 8;
	op->addr = addr;

	r_strbuf_init (&op->esil);
	if (mask & R_ARCH_OP_MASK_DISASM) {
		(void)disassemble (op, addr, data, len);
	}

	switch (f->code) {
	case BPF_RET | BPF_A:
		op->type = R_ANAL_OP_TYPE_RET;
		esilprintf (op, "a,r0,=,0,$");
		break;
	case BPF_RET | BPF_K:
	case BPF_RET | BPF_X:
		op->type = R_ANAL_OP_TYPE_RET;
		if (BPF_SRC (f->code) == BPF_K) {
			esilprintf (op, "%" PFMT64d ",r0,=,0,$", (ut64)f->k);
		} else if (BPF_SRC (f->code) == BPF_X) {
			esilprintf (op, "x,r0,=,0,$");
		}
		break;
	case BPF_MISC_TAX:
		op->type = R_ANAL_OP_TYPE_MOV;
		SET_REG_SRC_DST (op, "a", "x");
		esilprintf (op, "a,x,=");
		break;
	case BPF_MISC_TXA:
		op->type = R_ANAL_OP_TYPE_MOV;
		SET_REG_SRC_DST (op, "x", "a");
		esilprintf (op, "x,a,=");
		break;
	case BPF_ST:
		if (INSIDE_M (f->k)) {
			op->type = R_ANAL_OP_TYPE_MOV;
			SET_REG_SRC_DST (op, "a", M[f->k]);
			esilprintf (op, "a,m[%" PFMT64d "],=", (ut64)f->k);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_STX:
		if (INSIDE_M (f->k)) {
			op->type = R_ANAL_OP_TYPE_MOV;
			SET_REG_SRC_DST (op, "x", M[f->k]);
			esilprintf (op, "x,m[%" PFMT64d "],=", (ut64)f->k);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_LD_W | BPF_LEN:
		op->type = R_ANAL_OP_TYPE_MOV;
		SET_REG_SRC_DST (op, "len", "a");
		esilprintf (op, "%" PFMT64d ",a,=", (ut64)f->k);
		break;
	case BPF_LDX | BPF_LEN:
		op->type = R_ANAL_OP_TYPE_MOV;
		SET_REG_SRC_DST (op, "len", "x");
		esilprintf (op, "%" PFMT64d ",x,=", (ut64)f->k);
		break;
	case BPF_LD_W | BPF_ABS:
		EMIT_LOAD (op, anal->gp + f->k, 4);
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",>,?{,0,r0,=,0,$,BREAK,},%" PFMT64d ",[4],a,=",
			(ut64)f->k + 4, op->ptr);
		break;
	case BPF_LD_H | BPF_ABS:
		EMIT_LOAD (op, anal->gp + f->k, 2);
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",[2],a,=",
			(ut64)f->k + 2, op->ptr);
		break;
	case BPF_LD_B | BPF_ABS:
		EMIT_LOAD (op, anal->gp + f->k, 1);
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",[1],a,=",
			(ut64)f->k + 1, op->ptr);
		break;
	case BPF_LD_W | BPF_IND:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 4;
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",x,+,0xffffffff,&,>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",x,+,0xffffffff,&,[4],A,=",
			(st64)f->k + 4, anal->gp + (st32)f->k);
		break;
	case BPF_LD_H | BPF_IND:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 2;
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",x,+,0xffffffff,&,>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",x,+,0xffffffff,&,[2],a,=",
			(st64)f->k + 2, anal->gp + (st32)f->k);
		break;
	case BPF_LD_B | BPF_IND:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 1;
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",x,+,0xffffffff,&,>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",x,+,0xffffffff,&,[1],a,=",
			(st64)f->k + 1, anal->gp + (st32)f->k);
		break;
	case BPF_LD | BPF_IMM:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->val = f->k;
		SET_REG_DST_IMM (op, "a", (ut64)f->k);
		esilprintf (op, "0x%08" PFMT64x ",a,=", (ut64)f->k);
		break;
	case BPF_LDX | BPF_IMM:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->val = f->k;
		SET_REG_DST_IMM (op, "x", (ut64)f->k);
		esilprintf (op, "0x%08" PFMT64x ",x,=", (ut64)f->k);
		break;
	case BPF_LDX_B | BPF_MSH:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 1;
		op->ptr = anal->gp + f->k;
		SET_A_DST (op);
		esilprintf (op, "%" PFMT64d ",[1],0xf,&,4,*,x,=", op->ptr);
		break;
	case BPF_LD | BPF_MEM:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (INSIDE_M (f->k)) {
			SET_REG_SRC_DST (op, M[f->k], "a");
			esilprintf (op, "m[%" PFMT64d "],a,=", (ut64)f->k);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_LDX | BPF_MEM:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (INSIDE_M (f->k)) {
			SET_REG_SRC_DST (op, M[f->k], "x");
			esilprintf (op, "m[%" PFMT64d "],x,=", (ut64)f->k);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_JMP_JA:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + 8 + f->k * 8;
		esilprintf (op, "%" PFMT64d ",pc,=", op->jump);

		break;
	case BPF_JMP_JGT | BPF_X:
	case BPF_JMP_JGT | BPF_K:
		EMIT_CJMP (op, addr, f);
		op->cond = R_ANAL_COND_GT;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			esilprintf (op,
				"%" PFMT64d ",a,>,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->val, op->jump, op->fail);
		} else if (BPF_SRC (f->code) == BPF_X) {
			esilprintf (op,
				"x,a,>,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->jump, op->fail);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_JMP_JGE | BPF_X:
	case BPF_JMP_JGE | BPF_K:
		EMIT_CJMP (op, addr, f);
		op->cond = R_ANAL_COND_GE;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			esilprintf (op,
				"%" PFMT64d ",a,>=,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->val, op->jump, op->fail);
		} else {
			esilprintf (op,
				"x,a,>=,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->jump, op->fail);
		}
		break;
	case BPF_JMP_JEQ | BPF_X:
	case BPF_JMP_JEQ | BPF_K:
		EMIT_CJMP (op, addr, f);
		op->cond = R_ANAL_COND_EQ;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			esilprintf (op,
				"%" PFMT64d ",a,==,$z,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->val, op->jump, op->fail);
		} else {
			esilprintf (op,
				"x,a,==,$z,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->jump, op->fail);
		}
		break;
	case BPF_JMP_JSET | BPF_X:
	case BPF_JMP_JSET | BPF_K:
		EMIT_CJMP (op, addr, f);
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			esilprintf (op,
				"%" PFMT64d ",a,&,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				(st64)op->val, op->jump, op->fail);
		} else {
			esilprintf (op,
				"%" PFMT64d ",a,&,!,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				(st64)op->val, op->jump, op->fail);
		}
		break;
	case BPF_ALU_NEG:
		op->type = R_ANAL_OP_TYPE_NOT;
		esilprintf (op, "a,0,-,a,=");
		SET_REG_SRC_DST (op, "a", "a");
		break;
	case BPF_ALU_LSH | BPF_X:
	case BPF_ALU_LSH | BPF_K:
		op->type = R_ANAL_OP_TYPE_SHL;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "a", (ut64)f->k);
			esilprintf (op, "%" PFMT64d ",a,<<=", (ut64)f->k);
		} else {
			SET_REG_SRC_DST (op, "x", "a");
			esilprintf (op, "x,a,<<=");
		}
		break;
	case BPF_ALU_RSH | BPF_X:
	case BPF_ALU_RSH | BPF_K:
		op->type = R_ANAL_OP_TYPE_SHR;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "a", (ut64)f->k);
			esilprintf (op, "%" PFMT64d ",a,>>=", (ut64)f->k);
		} else {
			SET_REG_SRC_DST (op, "x", "a");
			esilprintf (op, "x,a,>>=");
		}
		break;
	case BPF_ALU_ADD | BPF_X:
	case BPF_ALU_ADD | BPF_K:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "a", op->val);
			esilprintf (op, "%" PFMT64d ",a,+=", op->val);
		} else {
			SET_REG_SRC_DST (op, "x", "a");
			esilprintf (op, "x,a,+=");
		}
		break;
	case BPF_ALU_SUB | BPF_X:
	case BPF_ALU_SUB | BPF_K:
		op->type = R_ANAL_OP_TYPE_SUB;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "a", op->val);
			esilprintf (op, "%" PFMT64d ",a,-=", op->val);

		} else {
			SET_REG_SRC_DST (op, "x", "a");
			esilprintf (op, "x,a,-=");
		}
		break;
	case BPF_ALU_MUL | BPF_X:
	case BPF_ALU_MUL | BPF_K:
		op->type = R_ANAL_OP_TYPE_MUL;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "a", (ut64)f->k);
			esilprintf (op, "%" PFMT64d ",a,*=", (ut64)f->k);
		} else {
			SET_REG_SRC_DST (op, "x", "a");
			esilprintf (op, "x,a,*=");
		}
		break;
	case BPF_ALU_DIV | BPF_X:
	case BPF_ALU_DIV | BPF_K:
		op->type = R_ANAL_OP_TYPE_DIV;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "a", (ut64)f->k);
			if (f->k == 0) {
				esilprintf (op, "0,r0,=,0,$");
			} else {
				esilprintf (op, "%" PFMT64d ",a,/=", (ut64)f->k);
			}
		} else {
			SET_REG_SRC_DST (op, "x", "a");
			esilprintf (op, "0,x,==,$z,?{,0,r0,=,0,$,BREAK,},x,a,/=");
		}
		break;
	case BPF_ALU_MOD | BPF_X:
	case BPF_ALU_MOD | BPF_K:
		op->type = R_ANAL_OP_TYPE_MOD;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "a", (ut64)f->k);
			if (f->k == 0) {
				esilprintf (op, "0,r0,=,0,$");
			} else {
				esilprintf (op, "%" PFMT64d ",a,%%=", (ut64)f->k);
			}
		} else {
			SET_REG_SRC_DST (op, "x", "a");
			esilprintf (op, "0,x,==,$z,?{,0,r0,=,0,$,BREAK,},x,a,%%=");
		}
		break;
	case BPF_ALU_AND | BPF_X:
	case BPF_ALU_AND | BPF_K:
		op->type = R_ANAL_OP_TYPE_AND;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "a", (ut64)f->k);
			esilprintf (op, "%" PFMT64d ",a,&=", (ut64)f->k);
		} else {
			SET_REG_SRC_DST (op, "x", "a");
			esilprintf (op, "x,a,&=");
		}
		break;
	case BPF_ALU_OR | BPF_X:
	case BPF_ALU_OR | BPF_K:
		op->type = R_ANAL_OP_TYPE_OR;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "a", (ut64)f->k);
			esilprintf (op, "%" PFMT64d ",a,|=", (ut64)f->k);
		} else {
			SET_REG_SRC_DST (op, "x", "a");
			esilprintf (op, "x,a,|,a,=");
		}
		break;
	case BPF_ALU_XOR | BPF_X:
	case BPF_ALU_XOR | BPF_K:
		op->type = R_ANAL_OP_TYPE_XOR;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "a", (ut64)f->k);
			esilprintf (op, "%" PFMT64d ",a,^=", (ut64)f->k);
		} else {
			SET_REG_SRC_DST (op, "x", "a");
			esilprintf (op, "x,a,^=");
		}
		break;
	default:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	}
	return op->size;
}

static bool set_reg_profile (RAnal *anal) {
	const char *p =
		"=PC    pc\n"
		"=A0    z\n"
		"=R0    z\n"
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
		"gpr    pc       .32 72   0\n"
		"gpr    len      .32 76   0\n"
		"gpr    r0       .32 80   0\n"
		"gpr    r1       .32 84   0\n"
		"gpr    r2       .32 88   0\n"
		"gpr    r3       .32 92   0\n"
		"gpr    r4       .32 96   0\n"
		"gpr    r5       .32 100  0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

/*
static bool bpf_int_exit(RAnalEsil *esil, ut32 interrupt, void *user) {
	int syscall;
	ut64 r0;
	if (!esil || (interrupt != 0x0))
		return false;
	r_anal_esil_reg_read (esil, "R0", &r0, NULL);
	if (r0 == 0) {
		esil->anal->cb_printf ("; BPF result: DROP value: %d\n", (int)r0);
		eprintf ("BPF result: DROP value: %d\n", (int)r0);
	} else {
		esil->anal->cb_printf ("; BPF result: ACCEPT value: %d\n", (int)r0);
		eprintf ("BPF result: ACCEPT value: %d\n", (int)r0);
	}
	return true;
}

static int esil_bpf_init(RAnalEsil *esil) {
	if (!esil) {
		return false;
	}
	RAnalEsilInterrupt *intr = r_anal_esil_interrupt_new (esil, 0, &ih);
	r_anal_esil_set_interrupt (esil, intr);
	return true;
}

static int esil_bpf_fini(RAnalEsil *esil) {
	return true;
}
*/

static int archinfo (RAnal *anal, int q) {
	switch (q) {
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return 8;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return 8;
	case R_ANAL_ARCHINFO_INV_OP_SIZE:
		return 8;
	case R_ANAL_ARCHINFO_ALIGN:
		return 8;
	case R_ANAL_ARCHINFO_DATA_ALIGN:
		return 1;
	}
	return 0;
}

RAnalPlugin r_anal_plugin_bpf = {
	.name = "bpf.mr",
	.desc = "Classic BPF analysis plugin",
	.license = "LGPLv3",
	.arch = "bpf",
	.bits = 32,
	.esil = true,
	.op = &bpf_anal,
	.archinfo = archinfo,
	.opasm = &bpf_opasm,
	.set_reg_profile = &set_reg_profile,
	/*
		.esil_init = &esil_bpf_init,
		.esil_fini = &esil_bpf_fini
	*/
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_bpf,
	.version = R2_VERSION
};
#endif

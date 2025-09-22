/* radare2 - LGPL - Copyright 2015-2025 - mrmacete, pancake */

#include <r_arch.h>
#include <r_anal/op.h>
#include "bpf.h"

typedef enum {
	R_BPF_DIALECT_CLASSIC = 32,
	R_BPF_DIALECT_EXTENDED = 64,
} RBpfDialect;

// disassembly
static int disassemble(RAnalOp *r_op, const ut8 *buf, int len) {
	const ut64 pc = r_op->addr;
	const char *op, *fmt;
	RBpfSockFilter f[1] = {{
		r_read_le16 (buf),
			    buf[2],
			    buf[3],
			    r_read_le32 (buf + 4)
	}};
	int val = f->k;
	char vbuf[256];

	// Minimal eBPF disassembly for common opcodes (disabled here to avoid impacting classic tests)
#if 0
	if (len >= 8) {
		ut8 opc = buf[0];
		bool ebpf_match = false;
		switch (opc) {
			case 0x71: case 0x69: case 0x61: case 0x73: case 0x6b: case 0x63:
			case 0xc3: case 0x85: case 0x95:
			case 0x1d: case 0x5d: case 0x2d: case 0x3d: case 0x4d:
			case 0xad: case 0xbd: case 0x6d: case 0x7d: case 0xcd: case 0xdd:
			case 0xb7: case 0xbf:
			case 0x07: case 0x17: case 0x27: case 0x37: case 0x47: case 0x57:
			case 0x67: case 0x77: case 0x97: case 0xa7:
			case 0x0f: case 0x1f: case 0x2f: case 0x3f: case 0x4f: case 0x5f:
			case 0x6f: case 0x7f: case 0x9f: case 0xaf:
			case 0x84: case 0x87:
				ebpf_match = true; break;
			default: break;
		}
		if (ebpf_match) {
			ut8 dst = buf[1] & 0x0f;
			ut8 src = (buf[1] >> 4) & 0x0f;
			st16 off = r_read_le16 (buf + 2);
			ut32 imm32 = r_read_le32 (buf + 4);
			char tmp[128];
			switch (opc) {
				case 0x95:
					r_op->mnemonic = strdup ("exit");
					return r_op->size = 8;
				case 0x85:
					r_op->mnemonic = r_str_newf ("call %#x", imm32);
					return r_op->size = 8;
				case 0x05: {
						   char sign = (off >= 0)? '+': '-';
						   int a = off >= 0? off: -off;
						   r_op->mnemonic = r_str_newf ("ja %c0x%x", sign, a);
						   return r_op->size = 8;
					   }
				case 0xb7:
					   r_op->mnemonic = r_str_newf ("mov64 r%u, %#x", dst, imm32);
					   return r_op->size = 8;
				case 0xbf:
					   r_op->mnemonic = r_str_newf ("mov64 r%u, r%u", dst, src);
					   return r_op->size = 8;
				case 0x07: case 0x17: case 0x27: case 0x37: case 0x47: case 0x57:
				case 0x67: case 0x77: case 0x97: case 0xa7:
					   // imm variants of ALU64
					   switch (opc) {
						   case 0x07: op = "add64"; break; case 0x17: op = "sub64"; break;
						   case 0x27: op = "mul64"; break; case 0x37: op = "div64"; break;
						   case 0x47: op = "or64"; break;  case 0x57: op = "and64"; break;
						   case 0x67: op = "lsh64"; break; case 0x77: op = "rsh64"; break;
						   case 0x97: op = "mod64"; break; case 0xa7: op = "xor64"; break;
						   default: op = "unk"; break;
					   }
					   r_op->mnemonic = r_str_newf ("%s r%u, %#x", op, dst, imm32);
					   return r_op->size = 8;
				case 0x0f: case 0x1f: case 0x2f: case 0x3f: case 0x4f: case 0x5f:
				case 0x6f: case 0x7f: case 0x9f: case 0xaf:
					   // reg variants of ALU64
					   switch (opc) {
						   case 0x0f: op = "add64"; break; case 0x1f: op = "sub64"; break;
						   case 0x2f: op = "mul64"; break; case 0x3f: op = "div64"; break;
						   case 0x4f: op = "or64"; break;  case 0x5f: op = "and64"; break;
						   case 0x6f: op = "lsh64"; break; case 0x7f: op = "rsh64"; break;
						   case 0x9f: op = "mod64"; break; case 0xaf: op = "xor64"; break;
						   default: op = "unk"; break;
					   }
					   r_op->mnemonic = r_str_newf ("%s r%u, r%u", op, dst, src);
					   return r_op->size = 8;
				case 0x84:
					   r_op->mnemonic = r_str_newf ("neg r%u", dst);
					   return r_op->size = 8;
				case 0x87:
					   r_op->mnemonic = r_str_newf ("neg64 r%u", dst);
					   return r_op->size = 8;
				case 0x71: // ldxb rD, [rS+off]
				case 0x69: // ldxh
				case 0x61: // ldxw
					   op = (opc == 0x71) ? "ldxb" : (opc == 0x69) ? "ldxh" : "ldxw";
					   if (off) {
						   char sign = (off >= 0)? '+': '-';
						   int a = off >= 0? off: -off;
						   snprintf (tmp, sizeof (tmp), "%s r%u, [r%u%c0x%x]", op, dst, src, sign, a);
					   } else {
						   snprintf (tmp, sizeof (tmp), "%s r%u, [r%u]", op, dst, src);
					   }
					   r_op->mnemonic = strdup (tmp);
					   return r_op->size = 8;
				case 0x73: // stxb [rS+off], rD
				case 0x6b:
				case 0x63:
					   op = (opc == 0x73) ? "stxb" : (opc == 0x6b) ? "stxh" : "stxw";
					   if (off) {
						   char sign = (off >= 0)? '+': '-';
						   int a = off >= 0? off: -off;
						   snprintf (tmp, sizeof (tmp), "%s [r%u%c0x%x], r%u", op, dst, sign, a, src);
					   } else {
						   snprintf (tmp, sizeof (tmp), "%s [r%u], r%u", op, dst, src);
					   }
					   r_op->mnemonic = strdup (tmp);
					   return r_op->size = 8;
				case 0xc3: // xaddw [rS+off], rD
					   if (off) {
						   char sign = (off >= 0)? '+': '-';
						   int a = off >= 0? off: -off;
						   snprintf (tmp, sizeof (tmp), "xaddw [r%u%c0x%x], r%u", dst, sign, a, src);
					   } else {
						   snprintf (tmp, sizeof (tmp), "xaddw [r%u], r%u", dst, src);
					   }
					   r_op->mnemonic = strdup (tmp);
					   return r_op->size = 8;
				case 0x15: case 0x55: case 0x25: case 0x35: case 0x45:
				case 0xa5: case 0xb5: case 0x65: case 0x75: case 0xc5: case 0xd5:
					   {
						   const char *cc = (opc==0x15)?"jeq":(opc==0x55)?"jne":(opc==0x25)?"jgt":(opc==0x35)?"jge":
							   (opc==0x45)?"jset":(opc==0xa5)?"jlt":(opc==0xb5)?"jle":(opc==0x65)?"jsgt":
							   (opc==0x75)?"jsge":(opc==0xc5)?"jslt":"jsle";
						   char sign = (off >= 0)? '+': '-';
						   int a = off >= 0? off: -off;
						   snprintf (tmp, sizeof (tmp), "%s r%u, %#x, %c0x%x", cc, dst, imm32, sign, a);
						   r_op->mnemonic = strdup (tmp);
						   return r_op->size = 8;
					   }
				case 0x1d: case 0x5d: case 0x2d: case 0x3d: case 0x4d:
				case 0xad: case 0xbd: case 0x6d: case 0x7d: case 0xcd: case 0xdd:
					   {
						   const char *cc = (opc==0x1d)?"jeq":(opc==0x5d)?"jne":(opc==0x2d)?"jgt":(opc==0x3d)?"jge":
							   (opc==0x4d)?"jset":(opc==0xad)?"jlt":(opc==0xbd)?"jle":(opc==0x6d)?"jsgt":
							   (opc==0x7d)?"jsge":(opc==0xcd)?"jslt":"jsle";
						   char sign = (off >= 0)? '+': '-';
						   int a = off >= 0? off: -off;
						   snprintf (tmp, sizeof (tmp), "%s r%u, r%u, %c0x%x", cc, dst, src, sign, a);
						   r_op->mnemonic = strdup (tmp);
						   return r_op->size = 8;
					   }
				default:
					   break;
			}
		}
	}
#endif

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

static RBpfDialect get_bpf_dialect(RArchSession *s) {
	const char *cpu = s && s->config ? s->config->cpu : NULL;
	if (cpu) {
		if (!strcmp (cpu, "classic") || !strcmp (cpu, "cbpf") || !strcmp (cpu, "cBPF")) {
			return R_BPF_DIALECT_CLASSIC;
		}
		if (!strcmp (cpu, "extended") || !strcmp (cpu, "ebpf") || !strcmp (cpu, "eBPF") || !strcmp (cpu, "64")) {
			return R_BPF_DIALECT_EXTENDED;
		}
	}
	if (s && s->config && s->config->bits == 64) {
		return R_BPF_DIALECT_EXTENDED;
	}
	return R_BPF_DIALECT_CLASSIC;
}

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
	return c == '(' || c == ')' || c == '[' || c == ']' || c == ',';
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

#if 0
static bool parse_label(RBpfSockFilter *f, const char *t) {
	ut64 k = 0;
	bool r = parse_label_value (&k, t);
	f->k = k;
	return r;
}
#endif

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
			// Accept multiple tokenizations: "4","*",..., and "4*",..., and "&0xf" vs "&","0xf"
			PARSE_NEED (opc >= 7 && opc <= 9);
			int i = 0;
			if (opc >= 9 && TOKEN_EQ (op[0], "4") && TOKEN_EQ (op[1], "*")) {
				i = 2;
			} else if (TOKEN_EQ (op[0], "4*")) {
				i = 1;
			} else {
				return false;
			}
			PARSE_STR (op[i + 0], "(");
			PARSE_STR (op[i + 1], "[");
			PARSE_NEED (parse_k (f, op[i + 2]));
			PARSE_STR (op[i + 3], "]");
			int rem = opc - (i + 4);
			if (rem == 3) {
				PARSE_STR (op[i + 4], "&");
				PARSE_STR (op[i + 5], "0xf");
				PARSE_STR (op[i + 6], ")");
			} else if (rem == 2) {
				PARSE_STR (op[i + 4], "&0xf");
				PARSE_STR (op[i + 5], ")");
			} else {
				return false;
			}
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
		// Accept absolute address and convert to relative K
		{
			ut64 label = 0;
			PARSE_NEED (parse_label_value (&label, op[0]));
			f->k = (label - pc - 8) / 8;
		}
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

static bool parse_alu(RBpfSockFilter *f, const char *m, int opc, const bpf_token *op) {
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

#include "bpfasm.inc.c"

static bool encode(RArchSession *s, RAnalOp *op, ut32 mask) {
	RBpfDialect dialect = get_bpf_dialect (s);
	RBpfSockFilter f = {0};
	BPFAsmParser p = { .str = op->mnemonic };
	ut8 ebuf[16] = {0};
	int elen = 0;

	bool ret = parse_instruction (&f, &p, op->addr, dialect, ebuf, &elen);
	token_fini (&p);
	if (ret) {
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
	return false;
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

#if 0
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
#else
// R2_590 - port to the new RArchValue thing
#define SET_REG_SRC_DST(op, _src, _dst)
#define SET_REG_DST_IMM(op, _dst, _imm)
#define SET_A_SRC(op)
#define SET_A_DST(op)
#endif

// (k) >= 0 must also be true, but the value is already unsigned
#define INSIDE_M(k) ((k) < 16)

#if 0
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
#endif

static bool decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	const ut8 *data = op->bytes;
	const int len = op->size;
	// RAnalValue *dst, *src;
	RBpfSockFilter *f = (RBpfSockFilter *)data;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = UT64_MAX;
	op->val = -1;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = 8;

	r_strbuf_init (&op->esil);
	if (mask & R_ARCH_OP_MASK_DISASM) {
		(void)disassemble (op, data, len);
	}
	ut64 gp = a->config->gp; // r_reg_getv (r, "gp");

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
		EMIT_LOAD (op, gp + f->k, 4);
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",>,?{,0,r0,=,0,$,BREAK,},%" PFMT64d ",[4],a,=",
			(ut64)f->k + 4, op->ptr);
		break;
	case BPF_LD_H | BPF_ABS:
		EMIT_LOAD (op, gp + f->k, 2);
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",[2],a,=",
			(ut64)f->k + 2, op->ptr);
		break;
	case BPF_LD_B | BPF_ABS:
		EMIT_LOAD (op, gp + f->k, 1);
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
			(st64)f->k + 4, gp + (st32)f->k);
		break;
	case BPF_LD_H | BPF_IND:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 2;
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",x,+,0xffffffff,&,>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",x,+,0xffffffff,&,[2],a,=",
			(st64)f->k + 2, gp + (st32)f->k);
		break;
	case BPF_LD_B | BPF_IND:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 1;
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",x,+,0xffffffff,&,>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",x,+,0xffffffff,&,[1],a,=",
			(st64)f->k + 1, gp + (st32)f->k);
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
		op->ptr = gp + f->k;
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
		op->jump = op->addr + 8 + f->k * 8;
		esilprintf (op, "%" PFMT64d ",pc,=", op->jump);
		break;
	case BPF_JMP_JGT | BPF_X:
	case BPF_JMP_JGT | BPF_K:
		EMIT_CJMP (op, op->addr, f);
		op->cond = R_ANAL_CONDTYPE_GT;
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
		EMIT_CJMP (op, op->addr, f);
		op->cond = R_ANAL_CONDTYPE_GE;
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
		EMIT_CJMP (op, op->addr, f);
		op->cond = R_ANAL_CONDTYPE_EQ;
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
		EMIT_CJMP (op, op->addr, f);
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

static char *regs(RArchSession *as) {
	const char * const p =
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
		"gpr    r5       .32 100  0\n"
		"gpr    gp       .32 104  0\n";
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_MINOP_SIZE:
		return 8;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 8;
	case R_ARCH_INFO_INVOP_SIZE:
		return 8;
	case R_ARCH_INFO_CODE_ALIGN:
		return 8;
	case R_ARCH_INFO_DATA_ALIGN:
		return 1;
	case R_ARCH_INFO_ISVM:
		// dont run aav in aaa
		return R_ARCH_INFO_ISVM;
	}
	return 0;
}

static bool bpf_int_exit(REsil *esil, ut32 interrupt, void *user) {
	ut64 r0;
	if (!esil || (interrupt != 0x0)) {
		return false;
	}
	r_esil_reg_read (esil, "R0", &r0, NULL);
	if (r0 == 0) {
		R_LOG_INFO ("BPF result: DROP value: %d", (int)r0);
	} else {
		R_LOG_INFO ("BPF result: ACCEPT value: %d", (int)r0);
	}
	return true;
}

static bool esilcb(RArchSession *as, RArchEsilAction action) {
	REsil *esil = as->arch->esil;
	if (!esil) {
		return false;
	}
	const int syscall_number = 0;
	switch (action) {
	case R_ARCH_ESIL_ACTION_INIT:
		r_esil_set_interrupt (esil, syscall_number, &bpf_int_exit, as);
		break;
	case R_ARCH_ESIL_ACTION_FINI:
		r_esil_del_interrupt (esil, 0);
		break;
	default:
		return false;
	}
	return true;
}

const RArchPlugin r_arch_plugin_bpf = {
	.meta = {
		.name = "bpf.mr",
		.desc = "BPF the Berkeley Packet Filter bytecode",
		.license = "LGPL-3.0-only",
		.author = "mrmacete"
	},
	.arch = "bpf",
	// Keep decode limited to classic 32-bit to avoid clobbering cs-based eBPF
	.bits = 32,
	.info = archinfo,
	.encode = encode,
	.decode = decode,
	.regs = &regs,
	.esilcb = &esilcb,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_bpf,
	.version = R2_VERSION
};
#endif

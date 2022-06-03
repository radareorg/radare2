/* radare2 - LGPL - Copyright 2015-2022 - mrmacete, pancake*/

#include <r_lib.h>
#include <r_anal.h>
#include "../arch/bpf/bpf.h"

// disassembly
// static int disassemble(RAsm *a, RAsmOp *r_op, const ut8 *buf, int len) {
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
		fmt = "[x+%d]";
		break;
	case BPF_LD_H | BPF_IND:
		op = r_bpf_op_table[BPF_LD_H];
		fmt = "[x+%d]";
		break;
	case BPF_LD_B | BPF_IND:
		op = r_bpf_op_table[BPF_LD_B];
		fmt = "[x+%d]";
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

	memset (vbuf, 0, sizeof (vbuf));
	snprintf (vbuf, sizeof (vbuf), fmt, val);
	vbuf[sizeof (vbuf) - 1] = 0;

	if ((BPF_CLASS (f->code) == BPF_JMP && BPF_OP (f->code) != BPF_JA)) {
		r_op->mnemonic = r_str_newf ("%s %s, 0x%08" PFMT64x ", 0x%08" PFMT64x "", op, vbuf,
			pc + 8 + f->jt * 8, pc + 8 + f->jf * 8);
	} else {
		r_op->mnemonic = r_str_newf ("%s %s", op, vbuf);
	}

	return r_op->size = 8;
}

#if 0
/* start of ASSEMBLER code */

#define PARSER_MAX_TOKENS 4

#define COPY_AND_RET(pc, b)\
	r_strbuf_setbin (&a, (const ut8 *)b, sizeof (*b) + 1);\
	return 0;

#define PARSE_FAILURE(message, arg...)\
	{\
		eprintf ("PARSE FAILURE: " message "\n", ##arg);\
		return -1;\
	}

#define CMP4(tok, n, x, y, z, w)\
	(tok[n][0] == x && tok[n][1] == y && tok[n][2] == z && tok[n][3] == w)

#define CMP3(tok, n, x, y, z)\
	(tok[n][0] == x && tok[n][1] == y && tok[n][2] == z)

#define CMP2(tok, n, x, y)\
	(tok[n][0] == x && tok[n][1] == y)

#define IS_K_TOK(tok, n)\
	(tok[n][0] == '-' || R_BETWEEN ('0', tok[n][0], '9'))

#define IS_LEN(tok, n)\
	CMP4 (tok, n, 'l', 'e', 'n', '\0')

#define PARSE_K_OR_FAIL(dst, tok, n)\
	dst = strtol (&tok[n][0], &end, 0);\
	if (*end != '\0' && *end != ',')\
		PARSE_FAILURE ("could not parse k");

#define PARSE_LABEL_OR_FAIL(dst, tok, n)\
	dst = strtoul (&tok[n][0], &end, 0);\
	if (*end != '\0' && *end != ',') {\
		return -1;\
	}

#define PARSE_OFFSET_OR_FAIL(dst, tok, n, off)\
	dst = strtoul (&tok[n][off], &end, 10);\
	if (*end != ']')\
		PARSE_FAILURE ("could not parse offset value");

#define PARSE_IND_ABS_OR_FAIL(f, tok, n)\
	if (CMP3 (tok, 1, '[', 'x', '+')) {\
		f->code = f->code | BPF_IND;\
		PARSE_OFFSET_OR_FAIL (f->k, tok, 1, 3);\
		return 0;\
	} else if (tok[1][0] == '[') {\
		f->code = f->code | BPF_ABS;\
		PARSE_OFFSET_OR_FAIL (f->k, tok, 1, 1);\
		return 0;\
	}\
	PARSE_FAILURE ("could not parse addressing mode");

#define PARSE_K_OR_X_OR_FAIL(f, tok)\
	if (IS_K_TOK (tok, 1)) {\
		PARSE_K_OR_FAIL (f->k, tok, 1);\
		f->code = f->code | BPF_K;\
	} else if (tok[1][0] == 'x' && (tok[1][1] == '\0' || tok[1][1] == ',')) {\
		f->code = f->code | BPF_X;\
	} else {\
		PARSE_FAILURE ("could not parse k or x: %s", tok[1]);\
	}

#define PARSE_A_OR_X_OR_FAIL(f, tok)\
	if (tok[1][0] == 'x' && (tok[1][1] == '\0' || tok[1][1] == ',')) {\
		f->code = f->code | BPF_X;\
	} else if (tok[1][0] == 'a' && (tok[1][1] == '\0' || tok[1][1] == ',')) {\
		f->code = f->code | BPF_A;\
	} else {\
		PARSE_FAILURE ("could not parse a or x");\
	}

#define PARSE_JUMP_TARGETS(pc, f, tok, count)\
	PARSE_K_OR_X_OR_FAIL (f, tok);\
	if (count >= 3) {\
		PARSE_LABEL_OR_FAIL (label, tok, 2);\
		f->jt = (st64) (label - pc - 8) / 8;\
		f->jf = (pc >> 3) + 1;\
	}\
	if (count == 4) {\
		PARSE_LABEL_OR_FAIL (label, tok, 3);\
		f->jf = (st64) (label - pc - 8) / 8;\
	}

#define SWAP_JUMP_TARGETS(f)\
	temp = f->jt;\
	f->jt = f->jf;\
	f->jf = temp;

#define ENFORCE_COUNT(count, n)\
	if (count != n)\
		PARSE_FAILURE ("invalid argument count, try to omit '#'");

#define ENFORCE_COUNT_GE(count, n)\
	if (count < n)\
		PARSE_FAILURE ("invalid argument count, try to omit '#'");

static int assemble_ld(RAsm *a, RAsmOp *op, char *tok[PARSER_MAX_TOKENS], int count, RBpfSockFilter *f) {
	char *end;

	switch (tok[0][2]) {
	case '\0':
		if (CMP2 (tok, 1, 'm', '[')) {
			f->code = BPF_LD | BPF_MEM;
			PARSE_OFFSET_OR_FAIL (f->k, tok, 1, 2);
		} else if (IS_K_TOK (tok, 1)) {
			f->code = BPF_LD | BPF_IMM;
			PARSE_K_OR_FAIL (f->k, tok, 1);
		} else if (IS_LEN (tok, 1)) {
			f->code = BPF_LD | BPF_LEN;
		} else {
			f->code = BPF_LD_W;
			PARSE_IND_ABS_OR_FAIL (f, tok, 1);
		}
		break;
	case 'i':
		if (IS_K_TOK (tok, 1)) {
			f->code = BPF_LD | BPF_IMM;
			PARSE_K_OR_FAIL (f->k, tok, 1);
		} else {
			PARSE_FAILURE ("ldi without k");
		}
		break;
	case 'b':
		f->code = BPF_LD_B;
		PARSE_IND_ABS_OR_FAIL (f, tok, 1);
		break;
	case 'h':
		f->code = BPF_LD_H;
		PARSE_IND_ABS_OR_FAIL (f, tok, 1);
		break;
	case 'x':
		switch (tok[0][3]) {
		case '\0':
			if (CMP2 (tok, 1, 'm', '[')) {
				f->code = BPF_LDX | BPF_MEM;
				PARSE_OFFSET_OR_FAIL (f->k, tok, 1, 2);
			} else if (IS_K_TOK (tok, 1)) {
				f->code = BPF_LDX | BPF_IMM;
				PARSE_K_OR_FAIL (f->k, tok, 1);
			} else if (IS_LEN (tok, 1)) {
				f->code = BPF_LDX | BPF_LEN;
			} else {
				f->code = BPF_LDX_W;
				PARSE_IND_ABS_OR_FAIL (f, tok, 1);
			}
			break;
		case 'i':
			if (IS_K_TOK (tok, 1)) {
				f->code = BPF_LDX | BPF_IMM;
				PARSE_K_OR_FAIL (f->k, tok, 1);
			} else {
				PARSE_FAILURE ("ldxi without k");
			}
			break;
		case 'b':
			f->code = BPF_LDX_B | BPF_MSH;
			if (sscanf (tok[1], "4*([%d]&0xf)", &f->k) != 1) {
				PARSE_FAILURE ("invalid nibble addressing");
			}
			break;
		}
		break;
	default:
		PARSE_FAILURE ("unsupported load instruction");
	}

	return 0;
}

static int assemble_j(ut64 pc, RAsmOp *op, char *tok[PARSER_MAX_TOKENS], int count, RBpfSockFilter *f) {
	int label;
	ut8 temp;
	char *end;

	if (CMP4 (tok, 0, 'j', 'm', 'p', '\0') ||
		CMP3 (tok, 0, 'j', 'a', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_JMP_JA;
		PARSE_LABEL_OR_FAIL (f->k, tok, 1);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 'n', 'e', '\0') ||
		CMP4 (tok, 0, 'j', 'n', 'e', 'q')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JEQ;
		PARSE_JUMP_TARGETS (pc, f, tok, count);
		SWAP_JUMP_TARGETS (f);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 'e', 'q', '\0')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JEQ;
		PARSE_JUMP_TARGETS (pc, f, tok, count);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 'l', 't', '\0')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JGE;
		PARSE_JUMP_TARGETS (pc, f, tok, count);
		SWAP_JUMP_TARGETS (f);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 'l', 'e', '\0')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JGT;
		PARSE_JUMP_TARGETS (pc, f, tok, count);
		SWAP_JUMP_TARGETS (f);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 'g', 't', '\0')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JGT;
		PARSE_JUMP_TARGETS (pc, f, tok, count);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 'g', 'e', '\0')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JGE;
		PARSE_JUMP_TARGETS (pc, f, tok, count);
		return 0;
	}

	if (CMP4 (tok, 0, 'j', 's', 'e', 't')) {
		ENFORCE_COUNT_GE (count, 3);
		f->code = BPF_JMP_JSET;
		PARSE_JUMP_TARGETS (pc, f, tok, count);
		return 0;
	}

	return -1;
}

static int assemble_alu(RAsm *a, RAsmOp *op, char *tok[PARSER_MAX_TOKENS], int count, RBpfSockFilter *f) {
	char *end;

	if (CMP4 (tok, 0, 'a', 'd', 'd', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_ADD;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 's', 'u', 'b', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_SUB;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'm', 'u', 'l', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_MUL;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'd', 'i', 'v', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_DIV;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'm', 'o', 'd', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_MOD;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'n', 'e', 'g', '\0')) {
		ENFORCE_COUNT (count, 1);
		f->code = BPF_ALU_NEG;
		return 0;
	}

	if (CMP4 (tok, 0, 'a', 'n', 'd', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_AND;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP3 (tok, 0, 'o', 'r', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_OR;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'x', 'o', 'r', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_XOR;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'l', 's', 'h', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_LSH;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	if (CMP4 (tok, 0, 'r', 's', 'h', '\0')) {
		ENFORCE_COUNT (count, 2);
		f->code = BPF_ALU_RSH;
		PARSE_K_OR_X_OR_FAIL (f, tok);
		return 0;
	}

	return -1;
}

static int assemble_tok(ut64 pc, char *buf, char *tok[PARSER_MAX_TOKENS], int count) {
	char *end;
	int oplen = 0;
	RBpfSockFilter f = { 0, 0, 0, 0 };
	oplen = strnlen (tok[0], 5);

	if (oplen < 2 || oplen > 4) {
		PARSE_FAILURE ("mnemonic length not valid");
	}

	if (CMP4 (tok, 0, 't', 'x', 'a', '\0')) {
		ENFORCE_COUNT (count, 1);
		f.code = BPF_MISC_TXA;
		COPY_AND_RET (buf, &f);
	}

	if (CMP4 (tok, 0, 't', 'a', 'x', '\0')) {
		ENFORCE_COUNT (count, 1);
		f.code = BPF_MISC_TAX;
		COPY_AND_RET (buf, &f);
	}

	if (CMP4 (tok, 0, 'r', 'e', 't', '\0')) {
		ENFORCE_COUNT (count, 2);
		if (IS_K_TOK (tok, 1)) {
			f.code = BPF_RET | BPF_K;
			PARSE_K_OR_FAIL (f.k, tok, 1);
		} else if (tok[1][0] == 'x') {
			f.code = BPF_RET | BPF_X;
		} else if (tok[1][0] == 'a') {
			f.code = BPF_RET | BPF_A;
		} else {
			PARSE_FAILURE ("unsupported ret instruction");
		}
		COPY_AND_RET (buf, &f);
	}

	if (CMP2 (tok, 0, 'l', 'd')) {
		ENFORCE_COUNT (count, 2);
		if (assemble_ld (pc, op, tok, count, &f) == 0) {
			COPY_AND_RET (buf, &f);
		} else {
			return -1;
		}
	}

	if (CMP2 (tok, 0, 's', 't')) {
		ENFORCE_COUNT (count, 2);
		if (tok[0][2] == '\0') {
			f.code = BPF_ST;
		} else if (tok[0][2] == 'x') {
			f.code = BPF_STX;
		}

		if (CMP2 (tok, 1, 'm', '[')) {
			PARSE_OFFSET_OR_FAIL (f.k, tok, 1, 2);
			if (f.k > 15) {
				PARSE_FAILURE ("mem addressing out of bounds");
			}
			COPY_AND_RET (buf, &f);
		} else {
			PARSE_FAILURE ("invalid store addressing");
		}
	}

	if (tok[0][0] == 'j') {
		if (assemble_j (pc, op, tok, count, &f) == 0) {
			COPY_AND_RET (buf, &f);
		} else {
			return -1;
		}
	}

	if (assemble_alu (pc, op, tok, count, &f) == 0) {
		COPY_AND_RET (buf, &f);
	} else {
		return -1;
	}
}

static void lower_op(char *c) {
	if ((c[0] <= 'Z') && (c[0] >= 'A')) {
		c[0] += 0x20;
	}
}

#define R_TRUE 1
static void normalize(RStrBuf *buf) {
	int i;
	char *buf_asm;
	if (!buf)
		return;
	buf_asm = r_strbuf_get (buf);

	/* this normalization step is largely sub-optimal */

	i = strlen (buf_asm);
	while (strstr (buf_asm, "  ")) {
		r_str_replace_in (buf_asm, (ut32)i, "  ", " ", R_TRUE);
	}
	r_str_replace_in (buf_asm, (ut32)i, " ,", ",", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "[ ", "[", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, " ]", "]", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "( ", "(", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, " )", ")", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "+ ", "+", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, " +", "+", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "* ", "*", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, " *", "*", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "& ", "&", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, " &", "&", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "%", "", R_TRUE);
	r_str_replace_in (buf_asm, (ut32)i, "#", "", R_TRUE);
	r_str_do_until_token (lower_op, buf_asm, '\0');
	r_strbuf_set (buf, buf_asm);
}

static int bf_opasm(RAnal *a, ut64 pc, const char *str, ut8 *outbuf, int outsize) {
	char *tok[PARSER_MAX_TOKENS];
	char tmp[128];
	int i, j, l;
	const char *p = NULL;

	RStrBuf *sb = r_strbuf_new (str);
	normalize (sb);

	// tokenization, copied from profile.c
	j = 0;
	p = r_strbuf_get (sb);

	// For every word
	while (*p) {
		// Skip the whitespace
		while (*p == ' ' || *p == '\t') {
			p++;
		}
		// Skip the rest of the line is a comment is encountered
		if (*p == ';') {
			while (*p != '\0') {
				p++;
			}
		}
		// EOL ?
		if (*p == '\0') {
			break;
		}
		// Gather a handful of chars
		// Use isgraph instead of isprint because the latter considers ' ' printable
		for (i = 0; isgraph ((const unsigned char)*p) && i < sizeof (tmp) - 1;) {
			tmp[i++] = *p++;
		}
		tmp[i] = '\0';
		// Limit the number of tokens
		if (j > PARSER_MAX_TOKENS - 1) {
			break;
		}
		// Save the token
		tok[j++] = strdup (tmp);
	}

	if (j) {
		if (assemble_tok (pc, p, tok, j) < 0) {
			return -1;
		}

		// Clean up
		for (i = 0; i < j; i++) {
			free (tok[i]);
		}
	}
	r_str_ncpy (outbuf, r_strbuf_get (sb), outsize);
	r_strbuf_free (sb);

	return 8;
}
#endif

/// analysis

#define EMIT_CJMP(op, addr, f)\
	(op)->type = R_ANAL_OP_TYPE_CJMP;\
	(op)->jump = (addr) + 8 + (st8) (f)->jt * 8;\
	(op)->fail = (addr) + 8 + (st8) (f)->jf * 8;

#define EMIT_LOAD(op, addr, size)\
	(op)->type = R_ANAL_OP_TYPE_LOAD;\
	(op)->ptr = (addr);\
	(op)->ptrsize = (size);

#define NEW_SRC_DST(op)\
	(op)->src[0] = r_anal_value_new ();\
	(op)->dst = r_anal_value_new ();

#define SET_REG_SRC_DST(op, _src, _dst)\
	NEW_SRC_DST ((op));\
	(op)->src[0]->reg = r_reg_get (anal->reg, (_src), R_REG_TYPE_GPR);\
	(op)->dst->reg = r_reg_get (anal->reg, (_dst), R_REG_TYPE_GPR);

#define SET_REG_DST_IMM(op, _dst, _imm)\
	NEW_SRC_DST ((op));\
	(op)->dst->reg = r_reg_get (anal->reg, (_dst), R_REG_TYPE_GPR);\
	(op)->src[0]->imm = (_imm);

#define SET_A_SRC(op)\
	(op)->src[0] = r_anal_value_new ();\
	(op)->src[0]->reg = r_reg_get (anal->reg, "A", R_REG_TYPE_GPR);

#define SET_A_DST(op)\
	(op)->dst = r_anal_value_new ();\
	(op)->dst->reg = r_reg_get (anal->reg, "A", R_REG_TYPE_GPR);

#define INSIDE_M(k) ((k) >= 0 && (k) <= 16)

/*
static bool bpf_int_exit(RAnalEsil *esil, ut32 interrupt, void *user);
RAnalEsilInterruptHandler ih = { 0, NULL, NULL, &bpf_int_exit, NULL };
*/

static const char *M[] = {
	"M[0]",
	"M[1]",
	"M[2]",
	"M[3]",
	"M[4]",
	"M[5]",
	"M[6]",
	"M[7]",
	"M[8]",
	"M[9]",
	"M[10]",
	"M[11]",
	"M[12]",
	"M[13]",
	"M[14]",
	"M[15]"
};

static int bpf_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	RBpfSockFilter *f = (RBpfSockFilter *)data;
	memset (op, '\0', sizeof (RAnalOp));
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = 8;
	op->addr = addr;

	r_strbuf_init (&op->esil);
	if (mask & R_ANAL_OP_MASK_DISASM) {
		(void) disassemble (op, addr, data, len);
	}

	switch (f->code) {
	case BPF_RET | BPF_A:
		op->type = R_ANAL_OP_TYPE_RET;
		esilprintf (op, "A,r0,=,0,$");
		break;
	case BPF_RET | BPF_K:
	case BPF_RET | BPF_X:
		op->type = R_ANAL_OP_TYPE_RET;
		if (BPF_SRC (f->code) == BPF_K) {
			esilprintf (op, "%" PFMT64d ",r0,=,0,$", (ut64)f->k);
		} else if (BPF_SRC (f->code) == BPF_X) {
			esilprintf (op, "X,r0,=,0,$");
		}
		break;
	case BPF_MISC_TAX:
		op->type = R_ANAL_OP_TYPE_MOV;
		SET_REG_SRC_DST (op, "A", "X");
		esilprintf (op, "A,X,=");
		break;
	case BPF_MISC_TXA:
		op->type = R_ANAL_OP_TYPE_MOV;
		SET_REG_SRC_DST (op, "X", "A");
		esilprintf (op, "X,A,=");
		break;
	case BPF_ST:
		if (INSIDE_M (f->k)) {
			op->type = R_ANAL_OP_TYPE_MOV;
			SET_REG_SRC_DST (op, "A", M[f->k]);
			esilprintf (op, "A,M[%" PFMT64d "],=", (ut64)f->k);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_STX:
		if (INSIDE_M (f->k)) {
			op->type = R_ANAL_OP_TYPE_MOV;
			SET_REG_SRC_DST (op, "X", M[f->k]);
			esilprintf (op, "X,M[%" PFMT64d "],=", (ut64)f->k);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_LD_W | BPF_LEN:
		op->type = R_ANAL_OP_TYPE_MOV;
		SET_REG_SRC_DST (op, "len", "A");
		esilprintf (op, "%"PFMT64d",A,=", (ut64)f->k);
		break;
	case BPF_LDX | BPF_LEN:
		op->type = R_ANAL_OP_TYPE_MOV;
		SET_REG_SRC_DST (op, "len", "X");
		esilprintf (op, "%"PFMT64d",X,=", (ut64)f->k);
		break;
	case BPF_LD_W | BPF_ABS:
		EMIT_LOAD (op, anal->gp + f->k, 4);
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",>,?{,0,r0,=,0,$,BREAK,},%" PFMT64d ",[4],A,=",
			(ut64)f->k + 4, op->ptr);
		break;
	case BPF_LD_H | BPF_ABS:
		EMIT_LOAD (op, anal->gp + f->k, 2);
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",[2],A,=",
			(ut64)f->k + 2, op->ptr);
		break;
	case BPF_LD_B | BPF_ABS:
		EMIT_LOAD (op, anal->gp + f->k, 1);
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",[1],A,=",
			(ut64)f->k + 1, op->ptr);
		break;
	case BPF_LD_W | BPF_IND:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 4;
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",X,+,0xffffffff,&,>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",X,+,0xffffffff,&,[4],A,=",
			(st64)f->k + 4, anal->gp + (st32)f->k);
		break;
	case BPF_LD_H | BPF_IND:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 2;
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",X,+,0xffffffff,&,>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",X,+,0xffffffff,&,[2],A,=",
			(st64)f->k + 2, anal->gp + (st32)f->k);
		break;
	case BPF_LD_B | BPF_IND:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 1;
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",X,+,0xffffffff,&,>,?{,0,r0,=,0,$,BREAK,},"
			"%" PFMT64d ",X,+,0xffffffff,&,[1],A,=",
			(st64)f->k + 1, anal->gp + (st32)f->k);
		break;
	case BPF_LD | BPF_IMM:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->val = f->k;
		SET_REG_DST_IMM (op, "A", (ut64)f->k);
		esilprintf (op, "0x%08" PFMT64x ",A,=", (ut64)f->k);
		break;
	case BPF_LDX | BPF_IMM:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->val = f->k;
		SET_REG_DST_IMM (op, "X", (ut64)f->k);
		esilprintf (op, "0x%08" PFMT64x ",X,=", (ut64)f->k);
		break;
	case BPF_LDX_B | BPF_MSH:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 1;
		op->ptr = anal->gp + f->k;
		SET_A_DST (op);
		esilprintf (op, "%" PFMT64d ",[1],0xf,&,4,*,X,=", op->ptr);
		break;
	case BPF_LD | BPF_MEM:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (INSIDE_M (f->k)) {
			SET_REG_SRC_DST (op, M[f->k], "A");
			esilprintf (op, "M[%" PFMT64d "],A,=", (ut64)f->k);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_LDX | BPF_MEM:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (INSIDE_M (f->k)) {
			SET_REG_SRC_DST (op, M[f->k], "X");
			esilprintf (op, "M[%" PFMT64d "],X,=", (ut64)f->k);
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
				"%" PFMT64d ",A,>,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->val, op->jump, op->fail);
		} else if (BPF_SRC (f->code) == BPF_X) {
			esilprintf (op,
				"X,A,>,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
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
				"%" PFMT64d ",A,>=,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->val, op->jump, op->fail);
		} else {
			esilprintf (op,
				"X,A,>=,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
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
				"%" PFMT64d ",A,==,$z,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->val, op->jump, op->fail);
		} else {
			esilprintf (op,
				"X,A,==,$z,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->jump, op->fail);
		}
		break;
	case BPF_JMP_JSET | BPF_X:
	case BPF_JMP_JSET | BPF_K:
		EMIT_CJMP (op, addr, f);
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			esilprintf (op,
				"%" PFMT64d ",A,&,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				(st64)op->val, op->jump, op->fail);
		} else {
			esilprintf (op,
				"%"PFMT64d",A,&,!,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				(st64)op->val, op->jump, op->fail);
		}
		break;
	case BPF_ALU_NEG:
		op->type = R_ANAL_OP_TYPE_NOT;
		esilprintf (op, "A,0,-,A,=");
		SET_REG_SRC_DST (op, "A", "A");
		break;
	case BPF_ALU_LSH | BPF_X:
	case BPF_ALU_LSH | BPF_K:
		op->type = R_ANAL_OP_TYPE_SHL;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", (ut64)f->k);
			esilprintf (op, "%" PFMT64d ",A,<<=", (ut64)f->k);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,<<=");
		}
		break;
	case BPF_ALU_RSH | BPF_X:
	case BPF_ALU_RSH | BPF_K:
		op->type = R_ANAL_OP_TYPE_SHR;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", (ut64)f->k);
			esilprintf (op, "%" PFMT64d ",A,>>=", (ut64)f->k);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,>>=");
		}
		break;
	case BPF_ALU_ADD | BPF_X:
	case BPF_ALU_ADD | BPF_K:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", op->val);
			esilprintf (op, "%" PFMT64d ",A,+=", op->val);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,+=");
		}
		break;
	case BPF_ALU_SUB | BPF_X:
	case BPF_ALU_SUB | BPF_K:
		op->type = R_ANAL_OP_TYPE_SUB;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", op->val);
			esilprintf (op, "%" PFMT64d ",A,-=", op->val);

		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,-=");
		}
		break;
	case BPF_ALU_MUL | BPF_X:
	case BPF_ALU_MUL | BPF_K:
		op->type = R_ANAL_OP_TYPE_MUL;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", (ut64)f->k);
			esilprintf (op, "%" PFMT64d ",A,*=", (ut64)f->k);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,*=");
		}
		break;
	case BPF_ALU_DIV | BPF_X:
	case BPF_ALU_DIV | BPF_K:
		op->type = R_ANAL_OP_TYPE_DIV;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", (ut64)f->k);
			if (f->k == 0) {
				esilprintf (op, "0,r0,=,0,$");
			} else {
				esilprintf (op, "%" PFMT64d ",A,/=", (ut64)f->k);
			}
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "0,X,==,$z,?{,0,r0,=,0,$,BREAK,},X,A,/=");
		}
		break;
	case BPF_ALU_MOD | BPF_X:
	case BPF_ALU_MOD | BPF_K:
		op->type = R_ANAL_OP_TYPE_MOD;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", (ut64)f->k);
			if (f->k == 0) {
				esilprintf (op, "0,r0,=,0,$");
			} else {
				esilprintf (op, "%" PFMT64d ",A,%%=", (ut64)f->k);
			}
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "0,X,==,$z,?{,0,R0,=,0,$,BREAK,},X,A,%%=");
		}
		break;
	case BPF_ALU_AND | BPF_X:
	case BPF_ALU_AND | BPF_K:
		op->type = R_ANAL_OP_TYPE_AND;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", (ut64)f->k);
			esilprintf (op, "%" PFMT64d ",A,&=", (ut64)f->k);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,&=");
		}
		break;
	case BPF_ALU_OR | BPF_X:
	case BPF_ALU_OR | BPF_K:
		op->type = R_ANAL_OP_TYPE_OR;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", (ut64)f->k);
			esilprintf (op, "%" PFMT64d ",A,|=", (ut64)f->k);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,|,A,=");
		}
		break;
	case BPF_ALU_XOR | BPF_X:
	case BPF_ALU_XOR | BPF_K:
		op->type = R_ANAL_OP_TYPE_XOR;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", (ut64)f->k);
			esilprintf (op, "%" PFMT64d ",A,^=", (ut64)f->k);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,^=");
		}
		break;
	default:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	}
	return op->size;
}

static bool set_reg_profile(RAnal *anal) {
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

static int archinfo(RAnal *anal, int q) {
	const int bits = anal->config->bits;
	switch (q) {
	case R_ANAL_ARCHINFO_ALIGN:
	case R_ANAL_ARCHINFO_DATA_ALIGN:
		return 1;
	}
	//case R_ANAL_ARCHINFO_MAX_OP_SIZE:
	//case R_ANAL_ARCHINFO_MIN_OP_SIZE:
	return (bits == 64)? 8: 4;
}
RAnalPlugin r_anal_plugin_bpf = {
	.name = "bpf.mr",
	.desc = "Berkely packet filter analysis plugin",
	.license = "LGPLv3",
	.arch = "bpf",
	.bits = 32,
	.esil = true,
	.op = &bpf_anal,
	.archinfo = archinfo,
//	.opasm = &bf_opasm,
	.set_reg_profile = &set_reg_profile,
/*
	.esil_init = &esil_bpf_init,
	.esil_fini = &esil_bpf_fini
*/
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_bpf,
	.version = R2_VERSION
};
#endif

/* radare2 - LGPL - Copyright 2015-2026 - mrmacete, pancake */

#ifndef R2_BPF_H
#define R2_BPF_H

#include <r_types.h>

// classic BPF instruction encoding (BSD Packet Filter, McCanne & Jacobson 1992)

// instruction class: bits 0-2
#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_LD 0x00
#define BPF_LDX 0x01
#define BPF_ST 0x02
#define BPF_STX 0x03
#define BPF_ALU 0x04
#define BPF_JMP 0x05
#define BPF_RET 0x06
#define BPF_MISC 0x07

// load size: bits 3-4
#define BPF_W 0x00
#define BPF_H 0x08
#define BPF_B 0x10

// load addressing mode: bits 5-7
#define BPF_IMM 0x00
#define BPF_ABS 0x20
#define BPF_IND 0x40
#define BPF_MEM 0x60
#define BPF_LEN 0x80
#define BPF_MSH 0xa0

// alu and jump operation: bits 4-7
#define BPF_OP(code) ((code) & 0xf0)
#define BPF_ADD 0x00
#define BPF_SUB 0x10
#define BPF_MUL 0x20
#define BPF_DIV 0x30
#define BPF_OR 0x40
#define BPF_AND 0x50
#define BPF_LSH 0x60
#define BPF_RSH 0x70
#define BPF_NEG 0x80
#define BPF_MOD 0x90
#define BPF_XOR 0xa0
#define BPF_JA 0x00
#define BPF_JEQ 0x10
#define BPF_JGT 0x20
#define BPF_JGE 0x30
#define BPF_JSET 0x40

// operand source: bit 3 (constant k or index register x)
#define BPF_SRC(code) ((code) & 0x08)
#define BPF_K 0x00
#define BPF_X 0x08

// ret operand from the accumulator, and misc register transfers
#define BPF_A 0x10
#define BPF_TAX 0x00
#define BPF_TXA 0x80

#define BPF_LD_W (BPF_LD | BPF_W)
#define BPF_LD_H (BPF_LD | BPF_H)
#define BPF_LD_B (BPF_LD | BPF_B)
#define BPF_LDX_W (BPF_LDX | BPF_W)
#define BPF_LDX_B (BPF_LDX | BPF_B)
#define BPF_ALU_ADD (BPF_ALU | BPF_ADD)
#define BPF_ALU_SUB (BPF_ALU | BPF_SUB)
#define BPF_ALU_MUL (BPF_ALU | BPF_MUL)
#define BPF_ALU_DIV (BPF_ALU | BPF_DIV)
#define BPF_ALU_OR (BPF_ALU | BPF_OR)
#define BPF_ALU_AND (BPF_ALU | BPF_AND)
#define BPF_ALU_LSH (BPF_ALU | BPF_LSH)
#define BPF_ALU_RSH (BPF_ALU | BPF_RSH)
#define BPF_ALU_NEG (BPF_ALU | BPF_NEG)
#define BPF_ALU_MOD (BPF_ALU | BPF_MOD)
#define BPF_ALU_XOR (BPF_ALU | BPF_XOR)
#define BPF_JMP_JA (BPF_JMP | BPF_JA)
#define BPF_JMP_JEQ (BPF_JMP | BPF_JEQ)
#define BPF_JMP_JGT (BPF_JMP | BPF_JGT)
#define BPF_JMP_JGE (BPF_JMP | BPF_JGE)
#define BPF_JMP_JSET (BPF_JMP | BPF_JSET)
#define BPF_MISC_TAX (BPF_MISC | BPF_TAX)
#define BPF_MISC_TXA (BPF_MISC | BPF_TXA)

// mnemonics indexed by class|size or class|op, without the source bit
static const char * const r_bpf_op_table[] = {
	[BPF_LD_W] = "ld",
	[BPF_LD_H] = "ldh",
	[BPF_LD_B] = "ldb",
	[BPF_LDX] = "ldx",
	[BPF_LDX_B] = "ldxb",
	[BPF_ST] = "st",
	[BPF_STX] = "stx",
	[BPF_ALU_ADD] = "add",
	[BPF_ALU_SUB] = "sub",
	[BPF_ALU_MUL] = "mul",
	[BPF_ALU_DIV] = "div",
	[BPF_ALU_OR] = "or",
	[BPF_ALU_AND] = "and",
	[BPF_ALU_LSH] = "lsh",
	[BPF_ALU_RSH] = "rsh",
	[BPF_ALU_NEG] = "neg",
	[BPF_ALU_MOD] = "mod",
	[BPF_ALU_XOR] = "xor",
	[BPF_JMP_JA] = "ja",
	[BPF_JMP_JEQ] = "jeq",
	[BPF_JMP_JGT] = "jgt",
	[BPF_JMP_JGE] = "jge",
	[BPF_JMP_JSET] = "jset",
	[BPF_RET] = "ret",
	[BPF_MISC_TAX] = "tax",
	[BPF_MISC_TXA] = "txa",
};

typedef struct r_bpf_sock_filter {
	ut16 code;
	ut8 jt; // jump offset when the condition is true
	ut8 jf; // jump offset when the condition is false
	ut32 k; // constant operand
} RBpfSockFilter;

#endif

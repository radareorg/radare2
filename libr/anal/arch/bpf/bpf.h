/*
 * Most of this is copied and pasted from linux kernel source
 *
 * Copyright 2015 - mrmacete <mrmacete@protonmail.ch>
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 */

#ifndef _BPF_H_
#define _BPF_H_

#include "bpf_common.h"

/* defines ripped from linux/filter.h : */

#define         BPF_A           0x10
#define         BPF_TAX         0x00
#define         BPF_TXA         0x80

/*  defines ripped from bpf_dbg.c : */

#define BPF_LDX_B	(BPF_LDX | BPF_B)
#define BPF_LDX_W	(BPF_LDX | BPF_W)
#define BPF_JMP_JA	(BPF_JMP | BPF_JA)
#define BPF_JMP_JEQ	(BPF_JMP | BPF_JEQ)
#define BPF_JMP_JGT	(BPF_JMP | BPF_JGT)
#define BPF_JMP_JGE	(BPF_JMP | BPF_JGE)
#define BPF_JMP_JSET	(BPF_JMP | BPF_JSET)
#define BPF_ALU_ADD	(BPF_ALU | BPF_ADD)
#define BPF_ALU_SUB	(BPF_ALU | BPF_SUB)
#define BPF_ALU_MUL	(BPF_ALU | BPF_MUL)
#define BPF_ALU_DIV	(BPF_ALU | BPF_DIV)
#define BPF_ALU_MOD	(BPF_ALU | BPF_MOD)
#define BPF_ALU_NEG	(BPF_ALU | BPF_NEG)
#define BPF_ALU_AND	(BPF_ALU | BPF_AND)
#define BPF_ALU_OR	(BPF_ALU | BPF_OR)
#define BPF_ALU_XOR	(BPF_ALU | BPF_XOR)
#define BPF_ALU_LSH	(BPF_ALU | BPF_LSH)
#define BPF_ALU_RSH	(BPF_ALU | BPF_RSH)
#define BPF_MISC_TAX	(BPF_MISC | BPF_TAX)
#define BPF_MISC_TXA	(BPF_MISC | BPF_TXA)
#define BPF_LD_B	(BPF_LD | BPF_B)
#define BPF_LD_H	(BPF_LD | BPF_H)
#define BPF_LD_W	(BPF_LD | BPF_W)

static const char * const r_bpf_op_table[] = {
	[BPF_ST]	= "st",
	[BPF_STX]	= "stx",
	[BPF_LD_B]	= "ldb",
	[BPF_LD_H]	= "ldh",
	[BPF_LD_W]	= "ld",
	[BPF_LDX]	= "ldx",
	[BPF_LDX_B]	= "ldxb",
	[BPF_JMP_JA]	= "ja",
	[BPF_JMP_JEQ]	= "jeq",
	[BPF_JMP_JGT]	= "jgt",
	[BPF_JMP_JGE]	= "jge",
	[BPF_JMP_JSET]	= "jset",
	[BPF_ALU_ADD]	= "add",
	[BPF_ALU_SUB]	= "sub",
	[BPF_ALU_MUL]	= "mul",
	[BPF_ALU_DIV]	= "div",
	[BPF_ALU_MOD]	= "mod",
	[BPF_ALU_NEG]	= "neg",
	[BPF_ALU_AND]	= "and",
	[BPF_ALU_OR]	= "or",
	[BPF_ALU_XOR]	= "xor",
	[BPF_ALU_LSH]	= "lsh",
	[BPF_ALU_RSH]	= "rsh",
	[BPF_MISC_TAX]	= "tax",
	[BPF_MISC_TXA]	= "txa",
	[BPF_RET]	= "ret",
};


typedef struct r_bpf_sock_filter {	/* Filter block */
	ut16 	code;   /* Actual filter code */
	st8		jt;	/* Jump true */
	st8		jf;	/* Jump false */
	ut32	k;      /* Generic multiuse field */
} RBpfSockFilter;

#endif
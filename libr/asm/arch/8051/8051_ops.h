/* radare - LGPL - Copyright 2015-2016 - pancake, condret, riq, qnix */

#ifndef _8051_OPS_H
#define _8051_OPS_H

#include <r_types.h>

enum {
	A_NONE = 0,
	A_RI,		// @Ri
	A_RN,		// Rn
	A_ADDR11,
	A_ADDR16,
	A_DIRECT,
	A_BIT,
	A_IMMEDIATE,
	A_IMM16,
	A_OFFSET
};

enum {
	M_NONE = 0,
	M_RI = 0x01,
	M_RN = 0x07,
	M_ADDR11 = 0xe0
};

typedef struct {
	ut8 op;
	char* name;
	size_t len;
	ut8 mask;	// bits masked to determine opcode
	ut8 arg1;
	ut8 arg2;
	ut8 arg3;
} _8051_op_t;

static _8051_op_t _8051_ops[] = {
	{0x00, "nop", 1, M_NONE, 0, 0, 0},
	{0x01, "ajmp 0x%04x", 2, M_ADDR11, A_ADDR11, 0, 0},
	{0x02, "ljmp 0x%04x", 3, M_NONE, A_ADDR16, 0, 0},
	{0x03, "rr a", 1, M_NONE, 0, 0, 0},
	{0x04, "inc a", 1, M_NONE, 0, 0, 0},
	{0x05, "inc 0x%02x", 2, M_NONE, A_DIRECT, 0, 0},
	{0x06, "inc @r%d", 1, M_RI, A_RI, 0, 0},
	{0x08, "inc r%d", 1, M_RN, A_RN, 0, 0},
	{0x10, "jbc 0x%02x, 0x%04x", 3, M_NONE, A_BIT, A_OFFSET, 0},
	{0x11, "acall 0x%04x", 2, M_ADDR11, A_ADDR11, 0, 0},
	{0x12, "lcall 0x%04x", 3, M_NONE, A_ADDR16, 0, 0},
	{0x13, "rrc a", 1, M_NONE, 0, 0, 0},
	{0x14, "dec a", 1, M_NONE, 0, 0, 0},
	{0x15, "dec 0x%02x", 2, M_NONE, A_DIRECT, 0, 0},
	{0x16, "dec @r%d", 1, M_RI, A_RI, 0, 0},
	{0x18, "dec r%d", 1, M_RN, A_RN, 0, 0},
	{0x20, "jb 0x%02x, 0x%04x", 3, M_NONE, A_BIT, A_OFFSET, 0},
	{0x22, "ret", 1, M_NONE, A_NONE, 0, 0},
	{0x23, "rl a", 1, M_NONE, A_NONE, 0, 0},
	{0x24, "add a, #0x%02x", 2, M_NONE, A_IMMEDIATE, 0, 0},
	{0x25, "add a, 0x%02x", 2, M_NONE, A_DIRECT, 0, 0},
	{0x26, "add a, @r%d", 1, M_RI, A_RI, 0, 0},
	{0x28, "add a, r%d", 1, M_RN, A_RN, 0, 0},
	{0x30, "jnb 0x%02x, 0x%04x", 3, M_NONE, A_BIT, A_OFFSET, 0},
	{0x32, "reti", 1, M_NONE, 0, 0, 0},
	{0x33, "rlc a", 1, M_NONE, 0, 0, 0},
	{0x34, "addc a, #0x%02x", 2, M_NONE, A_IMMEDIATE, 0, 0},
	{0x35, "addc a, 0x%02x", 2, M_NONE, A_DIRECT, 0, 0},
	{0x36, "addc a, @r%d", 1, M_RI, A_RI, 0, 0},
	{0x38, "addc a, r%d", 1, M_RN, A_RN, 0, 0},
	{0x40, "jc 0x%04x", 2, M_NONE, A_OFFSET, 0, 0},
	{0x42, "orl 0x%02x, a", 2, M_NONE, A_DIRECT, 0, 0},
	{0x43, "orl 0x%02x, #0x%02x", 3, M_NONE, A_DIRECT, A_IMMEDIATE, 0},
	{0x44, "orl a, #0x%02x", 2, M_NONE, A_IMMEDIATE, 0, 0},
	{0x45, "orl a, 0x%02x", 2, M_NONE, A_DIRECT, 0, 0},
	{0x46, "orl a, @r%d", 1, M_RI, A_RI, 0, 0},
	{0x48, "orl a, r%d", 1, M_RN, A_RN, 0, 0},
	{0x50, "jnc 0x%04x", 2, M_NONE, A_OFFSET, 0, 0},
	{0x52, "anl 0x%02x, a", 2, M_NONE, A_DIRECT, 0, 0},
	{0x53, "anl 0x%02x, #0x%02x", 3, M_NONE, A_DIRECT, A_IMMEDIATE, 0},
	{0x54, "anl a, #0x%02x", 2, M_NONE, A_IMMEDIATE, 0, 0},
	{0x55, "anl a, 0x%02x", 2, M_NONE, A_DIRECT, 0, 0},
	{0x56, "anl a, @r%d", 2, M_RI, A_RI, 0, 0},
	{0x58, "anl a, r%d", 2, M_RN, A_RN, 0, 0},
	{0x60, "jz 0x%04x", 2, M_NONE, A_OFFSET, 0, 0},
	{0x62, "xrl 0x%02x, a", 2, M_NONE, A_DIRECT, 0, 0},
	{0x63, "xrl 0x%02x, #0x%02x", 3, M_NONE, A_DIRECT, A_IMMEDIATE, 0},
	{0x64, "xrl a, #0x%02x", 2, M_NONE, A_IMMEDIATE, 0, 0},
	{0x65, "xrl a, 0x%02x", 2, M_NONE, A_DIRECT, 0, 0},
	{0x66, "xrl a, @r%d", 2, M_RI, A_RI, 0, 0},
	{0x68, "xrl a, r%d", 2, M_RN, A_RN, 0, 0},
	{0x70, "jnz 0x%04x", 2, M_NONE, A_OFFSET, 0, 0},
	{0x72, "orl c, 0x%02x", 2, M_NONE, A_BIT, 0, 0},
	{0x73, "jmp @a+dptr", 1, M_NONE, 0, 0, 0},
	{0x74, "mov a, #0x%02x", 2, M_NONE, A_IMMEDIATE, 0, 0},
	{0x75, "mov 0x%02x, #0x%02x", 3, M_NONE, A_DIRECT, A_IMMEDIATE, 0},
	{0x76, "mov @r%d, #0x%02x", 2, M_RI, A_RI, A_IMMEDIATE, 0},
	{0x78, "mov r%d, #0x%02x", 2, M_RN, A_RN, A_IMMEDIATE, 0},
	{0x80, "sjmp 0x%04x", 2, M_NONE, A_OFFSET, 0, 0},
	{0x82, "anl c, 0x%02x", 2, M_NONE, A_BIT, 0, 0},
	{0x83, "movc a, @a+pc", 1, M_NONE, 0, 0, 0},
	{0x84, "div ab", 1, M_NONE, 0, 0, 0},
	{0x85, "mov 0x%02x, 0x%02x", 3, M_NONE, A_DIRECT, A_DIRECT, 0},
	{0x86, "mov 0x%02x, @r%d", 2, M_RI, A_DIRECT, A_RI, 0},
	{0x88, "mov 0x%02x, r%d", 2, M_RN, A_DIRECT, A_RN, 0},
	{0x90, "mov dptr, #0x%04x", 3, M_NONE, A_IMM16, 0, 0},
	{0x92, "mov 0x%02x, c", 2, M_NONE, A_BIT, 0, 0},
	{0x93, "movc a, @a+dptr", 1, M_NONE, 0, 0, 0},
	{0x94, "subb a, #0x%02x", 2, M_NONE, A_IMMEDIATE, 0, 0},
	{0x95, "subb a, 0x%02x", 2, M_NONE, A_DIRECT, 0, 0},
	{0x96, "subb a, @r%d", 1, M_RI, A_RI, 0, 0},
	{0x98, "subb a, r%d", 1, M_RN, A_RN, 0, 0},
	{0xa0, "orl c, /0x%02x", 2, M_NONE, A_BIT, 0, 0},
	{0xa2, "mov c, 0x%02x", 2, M_NONE, A_BIT, 0, 0},
	{0xa3, "inc dptr", 1, M_NONE, 0, 0, 0},
	{0xa4, "mul ab", 1, M_NONE, 0, 0, 0},
	{0xa6, "mov @r%d, 0x%02x", 2, M_RI, A_RI, A_DIRECT, 0},
	{0xa8, "mov r%d, 0x%02x", 2, M_RN, A_RN, A_DIRECT, 0},
	{0xb0, "anl c, /0x%02x", 2, M_NONE, A_BIT, 0, 0},
	{0xb2, "cpl 0x%02x", 2, M_NONE, A_BIT, 0, 0},
	{0xb3, "cpl c", 1, M_NONE, 0, 0},
	{0xb4, "cjne a, #0x%02x, 0x%04x", 3, M_NONE, A_IMMEDIATE, A_OFFSET, 0},
	{0xb5, "cjne a, 0x%02x, 0x%04x", 3, M_NONE, A_DIRECT, A_OFFSET, 0},
	{0xb6, "cjne @r%d, #0x%02x, 0x%04x", 3, M_RI, A_RI, A_IMMEDIATE, A_OFFSET},
	{0xb8, "cjne r%d, #0x%02x, 0x%04x", 3, M_RN, A_RN, A_IMMEDIATE, A_OFFSET},
	{0xc0, "push 0x%02x", 2, M_NONE, A_DIRECT, 0, 0},
	{0xc2, "clr 0x%02x", 2, M_NONE, A_BIT, 0, 0},
	{0xc3, "clr c", 1, M_NONE, 0, 0, 0},
	{0xc4, "swap a", 1, M_NONE, 0, 0, 0},
	{0xc5, "xch a, 0x%02x", 2, M_NONE, A_DIRECT, 0, 0},
	{0xc6, "xch a, @r%d", 1, M_RI, A_RI, 0, 0},
	{0xc8, "xch a, r%d", 1, M_RN, A_RN, 0, 0},
	{0xd0, "pop 0x%02x", 2, M_NONE, A_DIRECT, 0, 0},
	{0xd2, "setb 0x%02x", 2, M_NONE, A_BIT, 0, 0},
	{0xd3, "setb c", 1, M_NONE, 0, 0, 0},
	{0xd4, "da a", 1, M_NONE, 0, 0, 0},
	{0xd5, "djnz 0x%02x, 0x%04x", 3, M_NONE, A_DIRECT, A_OFFSET, 0},
	{0xd6, "xchd a, @r%d", 1, M_RI, A_RI, 0, 0},
	{0xd8, "djnz r%d, 0x%04x", 2, M_RN, A_RN, A_OFFSET, 0},
	{0xe0, "movx a, @dptr", 1, M_NONE, 0, 0, 0},
	{0xe2, "movx a, @r%d", 1, M_RI, A_RI, 0, 0},
	{0xe4, "clr a", 1, M_NONE, 0, 0, 0},
	{0xe5, "mov a, 0x%02x", 2, M_NONE, A_DIRECT, 0, 0},
	{0xe6, "mov a, @r%d", 1, M_RI, A_RI, 0, 0},
	{0xe8, "mov a, r%d", 1, M_RN, A_RN, 0, 0},
	{0xf0, "movx @dptr, a", 1, M_NONE, 0, 0, 0},
	{0xf2, "movx @r%d, a", 1, M_RI, A_RI, 0, 0},
	{0xf4, "cpl a", 1, M_NONE, 0, 0, 0},
	{0xf5, "mov 0x%02x, a", 2, M_NONE, A_DIRECT, 0, 0},
	{0xf6, "mov @r%d, a", 1, M_RI, A_RI, 0, 0},
	{0xf8, "mov r%d, a", 1, M_RN, A_RN, 0, 0},
	{0xff, NULL, 0, 0, 0}
};

#endif


/* radare - Copyright 2025 - xXAbieGamingXx */

#ifndef S1C88_TAB_H
#define S1C88_TAB_H

#include <r_anal.h>

enum {
	S1C88_ARG_NONE = 0,
	S1C88_ARG_I8 = 1,
	S1C88_ARG_S8 = 2,
	S1C88_ARG_I16 = 3,
	S1C88_ARG_S16 = 4,
	S1C88_ARG_I8I8 = 5,
	S1C88_ARG_MASK = 7,

	S1C88_REL = 1 << 3,
	S1C88_JUMP = 1 << 4,
	S1C88_CALL = 1 << 5,
	S1C88_COND = 1 << 6,
	S1C88_RET = 1 << 7
};

typedef struct {
	const char *name;
	ut16 type;
	ut32 optype;
} s1c88_opcode;

/* bytes per S1C88_ARG_* */
static const ut8 s1c88_arglen[] = { 0, 1, 1, 2, 2, 2 };

static const s1c88_opcode s1c88_op[256] = {
	{ "add a, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x00
	{ "add a, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x01
	{ "add a, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_ADD }, // 0x02
	{ "add a, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x03
	{ "add a, [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_ADD }, // 0x04
	{ "add a, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_ADD }, // 0x05
	{ "add a, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x06
	{ "add a, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x07
	{ "adc a, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x08
	{ "adc a, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x09
	{ "adc a, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_ADD }, // 0x0a
	{ "adc a, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x0b
	{ "adc a, [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_ADD }, // 0x0c
	{ "adc a, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_ADD }, // 0x0d
	{ "adc a, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x0e
	{ "adc a, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x0f
	{ "sub a, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x10
	{ "sub a, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x11
	{ "sub a, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_SUB }, // 0x12
	{ "sub a, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x13
	{ "sub a, [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_SUB }, // 0x14
	{ "sub a, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_SUB }, // 0x15
	{ "sub a, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x16
	{ "sub a, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x17
	{ "sbc a, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x18
	{ "sbc a, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x19
	{ "sbc a, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_SUB }, // 0x1a
	{ "sbc a, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x1b
	{ "sbc a, [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_SUB }, // 0x1c
	{ "sbc a, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_SUB }, // 0x1d
	{ "sbc a, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x1e
	{ "sbc a, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x1f
	{ "and a, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_AND }, // 0x20
	{ "and a, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_AND }, // 0x21
	{ "and a, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_AND }, // 0x22
	{ "and a, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_AND }, // 0x23
	{ "and a, [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_AND }, // 0x24
	{ "and a, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_AND }, // 0x25
	{ "and a, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_AND }, // 0x26
	{ "and a, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_AND }, // 0x27
	{ "or a, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_OR }, // 0x28
	{ "or a, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_OR }, // 0x29
	{ "or a, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_OR }, // 0x2a
	{ "or a, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_OR }, // 0x2b
	{ "or a, [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_OR }, // 0x2c
	{ "or a, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_OR }, // 0x2d
	{ "or a, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_OR }, // 0x2e
	{ "or a, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_OR }, // 0x2f
	{ "cp a, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x30
	{ "cp a, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x31
	{ "cp a, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_CMP }, // 0x32
	{ "cp a, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x33
	{ "cp a, [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_CMP }, // 0x34
	{ "cp a, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_CMP }, // 0x35
	{ "cp a, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x36
	{ "cp a, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x37
	{ "xor a, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XOR }, // 0x38
	{ "xor a, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XOR }, // 0x39
	{ "xor a, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_XOR }, // 0x3a
	{ "xor a, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XOR }, // 0x3b
	{ "xor a, [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_XOR }, // 0x3c
	{ "xor a, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_XOR }, // 0x3d
	{ "xor a, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XOR }, // 0x3e
	{ "xor a, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XOR }, // 0x3f
	{ "ld a, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x40
	{ "ld a, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x41
	{ "ld a, l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x42
	{ "ld a, h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x43
	{ "ld a, [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_LOAD }, // 0x44
	{ "ld a, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x45
	{ "ld a, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x46
	{ "ld a, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x47
	{ "ld b, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x48
	{ "ld b, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x49
	{ "ld b, l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x4a
	{ "ld b, h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x4b
	{ "ld b, [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_LOAD }, // 0x4c
	{ "ld b, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x4d
	{ "ld b, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x4e
	{ "ld b, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x4f
	{ "ld l, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x50
	{ "ld l, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x51
	{ "ld l, l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x52
	{ "ld l, h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x53
	{ "ld l, [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_LOAD }, // 0x54
	{ "ld l, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x55
	{ "ld l, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x56
	{ "ld l, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x57
	{ "ld h, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x58
	{ "ld h, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x59
	{ "ld h, l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x5a
	{ "ld h, h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0x5b
	{ "ld h, [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_LOAD }, // 0x5c
	{ "ld h, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x5d
	{ "ld h, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x5e
	{ "ld h, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x5f
	{ "ld [ix], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x60
	{ "ld [ix], b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x61
	{ "ld [ix], l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x62
	{ "ld [ix], h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x63
	{ "ld [ix], [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0x64
	{ "ld [ix], [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x65
	{ "ld [ix], [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x66
	{ "ld [ix], [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x67
	{ "ld [hl], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x68
	{ "ld [hl], b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x69
	{ "ld [hl], l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x6a
	{ "ld [hl], h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x6b
	{ "ld [hl], [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0x6c
	{ "ld [hl], [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x6d
	{ "ld [hl], [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x6e
	{ "ld [hl], [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x6f
	{ "ld [iy], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x70
	{ "ld [iy], b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x71
	{ "ld [iy], l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x72
	{ "ld [iy], h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x73
	{ "ld [iy], [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0x74
	{ "ld [iy], [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x75
	{ "ld [iy], [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x76
	{ "ld [iy], [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x77
	{ "ld [br+0x%02x], a", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0x78
	{ "ld [br+0x%02x], b", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0x79
	{ "ld [br+0x%02x], l", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0x7a
	{ "ld [br+0x%02x], h", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0x7b
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x7c
	{ "ld [br+0x%02x], [hl]", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0x7d
	{ "ld [br+0x%02x], [ix]", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0x7e
	{ "ld [br+0x%02x], [iy]", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0x7f
	{ "inc a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x80
	{ "inc b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x81
	{ "inc l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x82
	{ "inc h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x83
	{ "inc br", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x84
	{ "inc [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_ADD }, // 0x85
	{ "inc [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x86
	{ "inc sp", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x87
	{ "dec a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x88
	{ "dec b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x89
	{ "dec l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x8a
	{ "dec h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x8b
	{ "dec br", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x8c
	{ "dec [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_SUB }, // 0x8d
	{ "dec [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x8e
	{ "dec sp", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x8f
	{ "inc ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x90
	{ "inc hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x91
	{ "inc ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x92
	{ "inc iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x93
	{ "bit a, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ACMP }, // 0x94
	{ "bit [hl], 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_ACMP }, // 0x95
	{ "bit a, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_ACMP }, // 0x96
	{ "bit b, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_ACMP }, // 0x97
	{ "dec ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x98
	{ "dec hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x99
	{ "dec ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x9a
	{ "dec iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x9b
	{ "and sc, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_AND }, // 0x9c
	{ "or sc, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_OR }, // 0x9d
	{ "xor sc, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_XOR }, // 0x9e
	{ "ld sc, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_MOV }, // 0x9f
	{ "push ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xa0
	{ "push hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xa1
	{ "push ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xa2
	{ "push iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xa3
	{ "push br", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xa4
	{ "push ep", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xa5
	{ "push xp, yp", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xa6
	{ "push sc", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xa7
	{ "pop ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xa8
	{ "pop hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xa9
	{ "pop ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xaa
	{ "pop iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xab
	{ "pop br", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xac
	{ "pop ep", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xad
	{ "pop xp, yp", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xae
	{ "pop sc", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xaf
	{ "ld a, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_MOV }, // 0xb0
	{ "ld b, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_MOV }, // 0xb1
	{ "ld l, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_MOV }, // 0xb2
	{ "ld h, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_MOV }, // 0xb3
	{ "ld br, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_MOV }, // 0xb4
	{ "ld [hl], 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0xb5
	{ "ld [ix], 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0xb6
	{ "ld [iy], 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_STORE }, // 0xb7
	{ "ld ba, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_LOAD }, // 0xb8
	{ "ld hl, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_LOAD }, // 0xb9
	{ "ld ix, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_LOAD }, // 0xba
	{ "ld iy, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_LOAD }, // 0xbb
	{ "ld [0x%04x], ba", S1C88_ARG_I16, R_ANAL_OP_TYPE_STORE }, // 0xbc
	{ "ld [0x%04x], hl", S1C88_ARG_I16, R_ANAL_OP_TYPE_STORE }, // 0xbd
	{ "ld [0x%04x], ix", S1C88_ARG_I16, R_ANAL_OP_TYPE_STORE }, // 0xbe
	{ "ld [0x%04x], iy", S1C88_ARG_I16, R_ANAL_OP_TYPE_STORE }, // 0xbf
	{ "add ba, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_ADD }, // 0xc0
	{ "add hl, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_ADD }, // 0xc1
	{ "add ix, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_ADD }, // 0xc2
	{ "add iy, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_ADD }, // 0xc3
	{ "ld ba, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_MOV }, // 0xc4
	{ "ld hl, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_MOV }, // 0xc5
	{ "ld ix, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_MOV }, // 0xc6
	{ "ld iy, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_MOV }, // 0xc7
	{ "ex ba, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XCHG }, // 0xc8
	{ "ex ba, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XCHG }, // 0xc9
	{ "ex ba, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XCHG }, // 0xca
	{ "ex ba, sp", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XCHG }, // 0xcb
	{ "ex a, b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XCHG }, // 0xcc
	{ "ex a, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XCHG }, // 0xcd
	{ "", S1C88_ARG_NONE, R_ANAL_OP_TYPE_NULL }, // 0xce
	{ "", S1C88_ARG_NONE, R_ANAL_OP_TYPE_NULL }, // 0xcf
	{ "sub ba, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_SUB }, // 0xd0
	{ "sub hl, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_SUB }, // 0xd1
	{ "sub ix, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_SUB }, // 0xd2
	{ "sub iy, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_SUB }, // 0xd3
	{ "cp ba, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_CMP }, // 0xd4
	{ "cp hl, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_CMP }, // 0xd5
	{ "cp ix, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_CMP }, // 0xd6
	{ "cp iy, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_CMP }, // 0xd7
	{ "and [br+0x%02x], 0x%02x", S1C88_ARG_I8I8, R_ANAL_OP_TYPE_AND }, // 0xd8
	{ "or [br+0x%02x], 0x%02x", S1C88_ARG_I8I8, R_ANAL_OP_TYPE_OR }, // 0xd9
	{ "xor [br+0x%02x], 0x%02x", S1C88_ARG_I8I8, R_ANAL_OP_TYPE_XOR }, // 0xda
	{ "cp [br+0x%02x], 0x%02x", S1C88_ARG_I8I8, R_ANAL_OP_TYPE_CMP }, // 0xdb
	{ "bit [br+0x%02x], 0x%02x", S1C88_ARG_I8I8, R_ANAL_OP_TYPE_ACMP }, // 0xdc
	{ "ld [br+0x%02x], 0x%02x", S1C88_ARG_I8I8, R_ANAL_OP_TYPE_STORE }, // 0xdd
	{ "pack", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xde
	{ "upck", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xdf
	{ "cars c, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xe0
	{ "cars nc, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xe1
	{ "cars z, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xe2
	{ "cars nz, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xe3
	{ "jrs c, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe4
	{ "jrs nc, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe5
	{ "jrs z, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe6
	{ "jrs nz, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe7
	{ "carl c, 0x%06x", S1C88_ARG_S16 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xe8
	{ "carl nc, 0x%06x", S1C88_ARG_S16 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xe9
	{ "carl z, 0x%06x", S1C88_ARG_S16 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xea
	{ "carl nz, 0x%06x", S1C88_ARG_S16 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xeb
	{ "jrl c, 0x%06x", S1C88_ARG_S16 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xec
	{ "jrl nc, 0x%06x", S1C88_ARG_S16 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xed
	{ "jrl z, 0x%06x", S1C88_ARG_S16 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xee
	{ "jrl nz, 0x%06x", S1C88_ARG_S16 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xef
	{ "cars 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL, R_ANAL_OP_TYPE_CALL }, // 0xf0
	{ "jrs 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP, R_ANAL_OP_TYPE_JMP }, // 0xf1
	{ "carl 0x%06x", S1C88_ARG_S16 | S1C88_REL | S1C88_JUMP | S1C88_CALL, R_ANAL_OP_TYPE_CALL }, // 0xf2
	{ "jrl 0x%06x", S1C88_ARG_S16 | S1C88_REL | S1C88_JUMP, R_ANAL_OP_TYPE_JMP }, // 0xf3
	{ "jp hl", S1C88_ARG_NONE | S1C88_JUMP, R_ANAL_OP_TYPE_RJMP }, // 0xf4
	{ "djr nz, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xf5
	{ "swap a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROL }, // 0xf6
	{ "swap [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROL }, // 0xf7
	{ "ret", S1C88_ARG_NONE | S1C88_RET, R_ANAL_OP_TYPE_RET }, // 0xf8
	{ "rete", S1C88_ARG_NONE | S1C88_RET, R_ANAL_OP_TYPE_RET }, // 0xf9
	{ "rets", S1C88_ARG_NONE | S1C88_RET, R_ANAL_OP_TYPE_RET }, // 0xfa
	{ "call [0x%04x]", S1C88_ARG_I16 | S1C88_JUMP | S1C88_CALL, R_ANAL_OP_TYPE_ICALL }, // 0xfb
	{ "int [0x%02x]", S1C88_ARG_I8 | S1C88_JUMP | S1C88_CALL, R_ANAL_OP_TYPE_SWI }, // 0xfc
	{ "jp [0x%02x]", S1C88_ARG_I8 | S1C88_JUMP, R_ANAL_OP_TYPE_IJMP }, // 0xfd
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xfe
	{ "nop", S1C88_ARG_NONE, R_ANAL_OP_TYPE_NOP }, // 0xff
};

static const s1c88_opcode s1c88_op_ce[256] = {
	{ "add a, [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_ADD }, // 0x00
	{ "add a, [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_ADD }, // 0x01
	{ "add a, [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x02
	{ "add a, [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x03
	{ "add [hl], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x04
	{ "add [hl], 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_ADD }, // 0x05
	{ "add [hl], [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x06
	{ "add [hl], [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x07
	{ "adc a, [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_ADD }, // 0x08
	{ "adc a, [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_ADD }, // 0x09
	{ "adc a, [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x0a
	{ "adc a, [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x0b
	{ "adc [hl], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x0c
	{ "adc [hl], 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_ADD }, // 0x0d
	{ "adc [hl], [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x0e
	{ "adc [hl], [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x0f
	{ "sub a, [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_SUB }, // 0x10
	{ "sub a, [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_SUB }, // 0x11
	{ "sub a, [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x12
	{ "sub a, [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x13
	{ "sub [hl], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x14
	{ "sub [hl], 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_SUB }, // 0x15
	{ "sub [hl], [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x16
	{ "sub [hl], [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x17
	{ "sbc a, [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_SUB }, // 0x18
	{ "sbc a, [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_SUB }, // 0x19
	{ "sbc a, [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x1a
	{ "sbc a, [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x1b
	{ "sbc [hl], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x1c
	{ "sbc [hl], 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_SUB }, // 0x1d
	{ "sbc [hl], [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x1e
	{ "sbc [hl], [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x1f
	{ "and a, [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_AND }, // 0x20
	{ "and a, [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_AND }, // 0x21
	{ "and a, [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_AND }, // 0x22
	{ "and a, [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_AND }, // 0x23
	{ "and [hl], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_AND }, // 0x24
	{ "and [hl], 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_AND }, // 0x25
	{ "and [hl], [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_AND }, // 0x26
	{ "and [hl], [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_AND }, // 0x27
	{ "or a, [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_OR }, // 0x28
	{ "or a, [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_OR }, // 0x29
	{ "or a, [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_OR }, // 0x2a
	{ "or a, [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_OR }, // 0x2b
	{ "or [hl], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_OR }, // 0x2c
	{ "or [hl], 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_OR }, // 0x2d
	{ "or [hl], [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_OR }, // 0x2e
	{ "or [hl], [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_OR }, // 0x2f
	{ "cp a, [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_CMP }, // 0x30
	{ "cp a, [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_CMP }, // 0x31
	{ "cp a, [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x32
	{ "cp a, [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x33
	{ "cp [hl], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x34
	{ "cp [hl], 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_CMP }, // 0x35
	{ "cp [hl], [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x36
	{ "cp [hl], [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x37
	{ "xor a, [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_XOR }, // 0x38
	{ "xor a, [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_XOR }, // 0x39
	{ "xor a, [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XOR }, // 0x3a
	{ "xor a, [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XOR }, // 0x3b
	{ "xor [hl], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XOR }, // 0x3c
	{ "xor [hl], 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_XOR }, // 0x3d
	{ "xor [hl], [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XOR }, // 0x3e
	{ "xor [hl], [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_XOR }, // 0x3f
	{ "ld a, [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_LOAD }, // 0x40
	{ "ld a, [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_LOAD }, // 0x41
	{ "ld a, [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x42
	{ "ld a, [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x43
	{ "ld [ix%s0x%02x], a", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x44
	{ "ld [iy%s0x%02x], a", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x45
	{ "ld [ix+l], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x46
	{ "ld [iy+l], a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x47
	{ "ld b, [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_LOAD }, // 0x48
	{ "ld b, [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_LOAD }, // 0x49
	{ "ld b, [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x4a
	{ "ld b, [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x4b
	{ "ld [ix%s0x%02x], b", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x4c
	{ "ld [iy%s0x%02x], b", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x4d
	{ "ld [ix+l], b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x4e
	{ "ld [iy+l], b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x4f
	{ "ld l, [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_LOAD }, // 0x50
	{ "ld l, [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_LOAD }, // 0x51
	{ "ld l, [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x52
	{ "ld l, [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x53
	{ "ld [ix%s0x%02x], l", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x54
	{ "ld [iy%s0x%02x], l", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x55
	{ "ld [ix+l], l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x56
	{ "ld [iy+l], l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x57
	{ "ld h, [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_LOAD }, // 0x58
	{ "ld h, [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_LOAD }, // 0x59
	{ "ld h, [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x5a
	{ "ld h, [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0x5b
	{ "ld [ix%s0x%02x], h", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x5c
	{ "ld [iy%s0x%02x], h", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x5d
	{ "ld [ix+l], h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x5e
	{ "ld [iy+l], h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x5f
	{ "ld [hl], [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x60
	{ "ld [hl], [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x61
	{ "ld [hl], [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x62
	{ "ld [hl], [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x63
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x64
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x65
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x66
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x67
	{ "ld [ix], [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x68
	{ "ld [ix], [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x69
	{ "ld [ix], [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x6a
	{ "ld [ix], [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x6b
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x6c
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x6d
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x6e
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x6f
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x70
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x71
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x72
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x73
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x74
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x75
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x76
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x77
	{ "ld [iy], [ix%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x78
	{ "ld [iy], [iy%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x79
	{ "ld [iy], [ix+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x7a
	{ "ld [iy], [iy+l]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0x7b
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x7c
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x7d
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x7e
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x7f
	{ "sla a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SAL }, // 0x80
	{ "sla b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SAL }, // 0x81
	{ "sla [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_SAL }, // 0x82
	{ "sla [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SAL }, // 0x83
	{ "sll a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SHL }, // 0x84
	{ "sll b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SHL }, // 0x85
	{ "sll [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_SHL }, // 0x86
	{ "sll [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SHL }, // 0x87
	{ "sra a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SAR }, // 0x88
	{ "sra b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SAR }, // 0x89
	{ "sra [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_SAR }, // 0x8a
	{ "sra [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SAR }, // 0x8b
	{ "srl a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SHR }, // 0x8c
	{ "srl b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SHR }, // 0x8d
	{ "srl [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_SHR }, // 0x8e
	{ "srl [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SHR }, // 0x8f
	{ "rl a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROL }, // 0x90
	{ "rl b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROL }, // 0x91
	{ "rl [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_ROL }, // 0x92
	{ "rl [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROL }, // 0x93
	{ "rlc a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROL }, // 0x94
	{ "rlc b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROL }, // 0x95
	{ "rlc [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_ROL }, // 0x96
	{ "rlc [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROL }, // 0x97
	{ "rr a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROR }, // 0x98
	{ "rr b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROR }, // 0x99
	{ "rr [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_ROR }, // 0x9a
	{ "rr [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROR }, // 0x9b
	{ "rrc a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROR }, // 0x9c
	{ "rrc b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROR }, // 0x9d
	{ "rrc [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_ROR }, // 0x9e
	{ "rrc [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ROR }, // 0x9f
	{ "cpl a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CPL }, // 0xa0
	{ "cpl b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CPL }, // 0xa1
	{ "cpl [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_CPL }, // 0xa2
	{ "cpl [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CPL }, // 0xa3
	{ "neg a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0xa4
	{ "neg b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0xa5
	{ "neg [br+0x%02x]", S1C88_ARG_I8, R_ANAL_OP_TYPE_SUB }, // 0xa6
	{ "neg [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0xa7
	{ "sep", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CAST }, // 0xa8
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xa9
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xaa
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xab
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xac
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xad
	{ "halt", S1C88_ARG_NONE, R_ANAL_OP_TYPE_NOP }, // 0xae
	{ "slp", S1C88_ARG_NONE, R_ANAL_OP_TYPE_NOP }, // 0xaf
	{ "and b, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_AND }, // 0xb0
	{ "and l, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_AND }, // 0xb1
	{ "and h, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_AND }, // 0xb2
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xb3
	{ "or b, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_OR }, // 0xb4
	{ "or l, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_OR }, // 0xb5
	{ "or h, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_OR }, // 0xb6
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xb7
	{ "xor b, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_XOR }, // 0xb8
	{ "xor l, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_XOR }, // 0xb9
	{ "xor h, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_XOR }, // 0xba
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xbb
	{ "cp b, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_CMP }, // 0xbc
	{ "cp l, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_CMP }, // 0xbd
	{ "cp h, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_CMP }, // 0xbe
	{ "cp br, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_CMP }, // 0xbf
	{ "ld a, br", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xc0
	{ "ld a, sc", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xc1
	{ "ld br, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xc2
	{ "ld sc, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xc3
	{ "ld nb, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_MOV }, // 0xc4
	{ "ld ep, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_MOV }, // 0xc5
	{ "ld xp, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_MOV }, // 0xc6
	{ "ld yp, 0x%02x", S1C88_ARG_I8, R_ANAL_OP_TYPE_MOV }, // 0xc7
	{ "ld a, nb", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xc8
	{ "ld a, ep", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xc9
	{ "ld a, xp", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xca
	{ "ld a, yp", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xcb
	{ "ld nb, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xcc
	{ "ld ep, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xcd
	{ "ld xp, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xce
	{ "ld yp, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xcf
	{ "ld a, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_LOAD }, // 0xd0
	{ "ld b, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_LOAD }, // 0xd1
	{ "ld l, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_LOAD }, // 0xd2
	{ "ld h, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_LOAD }, // 0xd3
	{ "ld [0x%04x], a", S1C88_ARG_I16, R_ANAL_OP_TYPE_STORE }, // 0xd4
	{ "ld [0x%04x], b", S1C88_ARG_I16, R_ANAL_OP_TYPE_STORE }, // 0xd5
	{ "ld [0x%04x], l", S1C88_ARG_I16, R_ANAL_OP_TYPE_STORE }, // 0xd6
	{ "ld [0x%04x], h", S1C88_ARG_I16, R_ANAL_OP_TYPE_STORE }, // 0xd7
	{ "mlt l, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MUL }, // 0xd8
	{ "div hl, a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_DIV }, // 0xd9
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xda
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xdb
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xdc
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xdd
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xde
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xdf
	{ "jrs lt, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe0
	{ "jrs le, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe1
	{ "jrs gt, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe2
	{ "jrs ge, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe3
	{ "jrs v, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe4
	{ "jrs nv, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe5
	{ "jrs p, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe6
	{ "jrs m, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe7
	{ "jrs f0, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe8
	{ "jrs f1, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xe9
	{ "jrs f2, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xea
	{ "jrs f3, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xeb
	{ "jrs nf0, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xec
	{ "jrs nf1, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xed
	{ "jrs nf2, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xee
	{ "jrs nf3, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_COND, R_ANAL_OP_TYPE_CJMP }, // 0xef
	{ "cars lt, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xf0
	{ "cars le, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xf1
	{ "cars gt, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xf2
	{ "cars ge, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xf3
	{ "cars v, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xf4
	{ "cars nv, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xf5
	{ "cars p, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xf6
	{ "cars m, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xf7
	{ "cars f0, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xf8
	{ "cars f1, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xf9
	{ "cars f2, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xfa
	{ "cars f3, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xfb
	{ "cars nf0, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xfc
	{ "cars nf1, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xfd
	{ "cars nf2, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xfe
	{ "cars nf3, 0x%06x", S1C88_ARG_S8 | S1C88_REL | S1C88_JUMP | S1C88_CALL | S1C88_COND, R_ANAL_OP_TYPE_CCALL }, // 0xff
};

static const s1c88_opcode s1c88_op_cf[256] = {
	{ "add ba, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x00
	{ "add ba, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x01
	{ "add ba, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x02
	{ "add ba, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x03
	{ "adc ba, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x04
	{ "adc ba, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x05
	{ "adc ba, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x06
	{ "adc ba, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x07
	{ "sub ba, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x08
	{ "sub ba, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x09
	{ "sub ba, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x0a
	{ "sub ba, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x0b
	{ "sbc ba, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x0c
	{ "sbc ba, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x0d
	{ "sbc ba, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x0e
	{ "sbc ba, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x0f
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x10
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x11
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x12
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x13
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x14
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x15
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x16
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x17
	{ "cp ba, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x18
	{ "cp ba, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x19
	{ "cp ba, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x1a
	{ "cp ba, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x1b
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x1c
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x1d
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x1e
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x1f
	{ "add hl, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x20
	{ "add hl, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x21
	{ "add hl, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x22
	{ "add hl, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x23
	{ "adc hl, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x24
	{ "adc hl, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x25
	{ "adc hl, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x26
	{ "adc hl, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x27
	{ "sub hl, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x28
	{ "sub hl, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x29
	{ "sub hl, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x2a
	{ "sub hl, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x2b
	{ "sbc hl, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x2c
	{ "sbc hl, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x2d
	{ "sbc hl, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x2e
	{ "sbc hl, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x2f
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x30
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x31
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x32
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x33
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x34
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x35
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x36
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x37
	{ "cp hl, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x38
	{ "cp hl, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x39
	{ "cp hl, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x3a
	{ "cp hl, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x3b
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x3c
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x3d
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x3e
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x3f
	{ "add ix, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x40
	{ "add ix, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x41
	{ "add iy, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x42
	{ "add iy, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x43
	{ "add sp, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x44
	{ "add sp, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ADD }, // 0x45
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x46
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x47
	{ "sub ix, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x48
	{ "sub ix, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x49
	{ "sub iy, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x4a
	{ "sub iy, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x4b
	{ "sub sp, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x4c
	{ "sub sp, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_SUB }, // 0x4d
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x4e
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x4f
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x50
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x51
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x52
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x53
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x54
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x55
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x56
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x57
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x58
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x59
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x5a
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x5b
	{ "cp sp, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x5c
	{ "cp sp, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_CMP }, // 0x5d
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x5e
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x5f
	{ "adc ba, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_ADD }, // 0x60
	{ "adc hl, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_ADD }, // 0x61
	{ "sbc ba, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_SUB }, // 0x62
	{ "sbc hl, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_SUB }, // 0x63
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x64
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x65
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x66
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x67
	{ "add sp, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_ADD }, // 0x68
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x69
	{ "sub sp, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_SUB }, // 0x6a
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x6b
	{ "cp sp, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_CMP }, // 0x6c
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x6d
	{ "ld sp, 0x%04x", S1C88_ARG_I16, R_ANAL_OP_TYPE_MOV }, // 0x6e
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x6f
	{ "ld ba, [sp%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_LOAD }, // 0x70
	{ "ld hl, [sp%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_LOAD }, // 0x71
	{ "ld ix, [sp%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_LOAD }, // 0x72
	{ "ld iy, [sp%s0x%02x]", S1C88_ARG_S8, R_ANAL_OP_TYPE_LOAD }, // 0x73
	{ "ld [sp%s0x%02x], ba", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x74
	{ "ld [sp%s0x%02x], hl", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x75
	{ "ld [sp%s0x%02x], ix", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x76
	{ "ld [sp%s0x%02x], iy", S1C88_ARG_S8, R_ANAL_OP_TYPE_STORE }, // 0x77
	{ "ld sp, [0x%04x]", S1C88_ARG_I16, R_ANAL_OP_TYPE_LOAD }, // 0x78
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x79
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x7a
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x7b
	{ "ld [0x%04x], sp", S1C88_ARG_I16, R_ANAL_OP_TYPE_STORE }, // 0x7c
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x7d
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x7e
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x7f
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x80
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x81
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x82
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x83
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x84
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x85
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x86
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x87
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x88
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x89
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x8a
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x8b
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x8c
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x8d
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x8e
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x8f
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x90
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x91
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x92
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x93
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x94
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x95
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x96
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x97
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x98
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x99
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x9a
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x9b
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x9c
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x9d
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x9e
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0x9f
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xa0
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xa1
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xa2
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xa3
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xa4
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xa5
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xa6
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xa7
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xa8
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xa9
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xaa
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xab
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xac
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xad
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xae
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xaf
	{ "push a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xb0
	{ "push b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xb1
	{ "push l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xb2
	{ "push h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xb3
	{ "pop a", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xb4
	{ "pop b", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xb5
	{ "pop l", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xb6
	{ "pop h", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xb7
	{ "push all", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xb8
	{ "push ale", S1C88_ARG_NONE, R_ANAL_OP_TYPE_PUSH }, // 0xb9
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xba
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xbb
	{ "pop all", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xbc
	{ "pop ale", S1C88_ARG_NONE, R_ANAL_OP_TYPE_POP }, // 0xbd
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xbe
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xbf
	{ "ld ba, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0xc0
	{ "ld hl, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0xc1
	{ "ld ix, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0xc2
	{ "ld iy, [hl]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0xc3
	{ "ld [hl], ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0xc4
	{ "ld [hl], hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0xc5
	{ "ld [hl], ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0xc6
	{ "ld [hl], iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0xc7
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xc8
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xc9
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xca
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xcb
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xcc
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xcd
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xce
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xcf
	{ "ld ba, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0xd0
	{ "ld hl, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0xd1
	{ "ld ix, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0xd2
	{ "ld iy, [ix]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0xd3
	{ "ld [ix], ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0xd4
	{ "ld [ix], hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0xd5
	{ "ld [ix], ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0xd6
	{ "ld [ix], iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0xd7
	{ "ld ba, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0xd8
	{ "ld hl, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0xd9
	{ "ld ix, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0xda
	{ "ld iy, [iy]", S1C88_ARG_NONE, R_ANAL_OP_TYPE_LOAD }, // 0xdb
	{ "ld [iy], ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0xdc
	{ "ld [iy], hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0xdd
	{ "ld [iy], ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0xde
	{ "ld [iy], iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_STORE }, // 0xdf
	{ "ld ba, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xe0
	{ "ld ba, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xe1
	{ "ld ba, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xe2
	{ "ld ba, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xe3
	{ "ld hl, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xe4
	{ "ld hl, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xe5
	{ "ld hl, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xe6
	{ "ld hl, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xe7
	{ "ld ix, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xe8
	{ "ld ix, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xe9
	{ "ld ix, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xea
	{ "ld ix, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xeb
	{ "ld iy, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xec
	{ "ld iy, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xed
	{ "ld iy, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xee
	{ "ld iy, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xef
	{ "ld sp, ba", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xf0
	{ "ld sp, hl", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xf1
	{ "ld sp, ix", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xf2
	{ "ld sp, iy", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xf3
	{ "ld hl, sp", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xf4
	{ "ld hl, pc", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xf5
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xf6
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xf7
	{ "ld ba, sp", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xf8
	{ "ld ba, pc", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xf9
	{ "ld ix, sp", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xfa
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xfb
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xfc
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xfd
	{ "ld iy, sp", S1C88_ARG_NONE, R_ANAL_OP_TYPE_MOV }, // 0xfe
	{ "invalid", S1C88_ARG_NONE, R_ANAL_OP_TYPE_ILL }, // 0xff
};

#endif

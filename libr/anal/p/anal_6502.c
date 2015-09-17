/* radare - LGPL - Copyright 2015 - condret, riq */

/* 6502 info taken from http://unusedino.de/ec64/technical/aay/c64/bchrt651.htm */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/snes/snes_op_table.h"

static void _6502_anal_esil_call(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "2,sp,-=,pc,sp,=[2],0x%04x,pc,=", (op->jump & 0xffff));
}

static void _6502_anal_esil_ccall(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "0x%04x,pc,=", (op->jump & 0xffff));
}

static void _6502_anal_esil_ret(RAnalOp *op)
{
	r_strbuf_append (&op->esil, "sp,[2],pc,=,2,sp,+=");
}

static void _6502_anal_esil_jmp(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "0x%04x,pc,=", (op->jump & 0xffff));
}

static void _6502_anal_esil_store(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_load(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_mov(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_push(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_pop(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_or(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_and(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_xor(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_shift(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_rol(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_cmp(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_flags(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_add(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}

static void _6502_anal_esil_sub(RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "TODO");
}


static int _6502_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	memset (op, '\0', sizeof (RAnalOp));
	op->size = snes_op[data[0]].len;	//snes-arch is similiar to nes/6502
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	r_strbuf_init (&op->esil);
	switch (data[0]) {
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x07:
		case 0x0b:
		case 0x0c:
		case 0x0f:
		case 0x12:
		case 0x13:
		case 0x14:
		case 0x17:
		case 0x1a:
		case 0x1b:
		case 0x1c:
		case 0x1f:
		case 0x22:
		case 0x23:
		case 0x27:
		case 0x2b:
		case 0x2f:
		case 0x32:
		case 0x33:
		case 0x34:
		case 0x37:
		case 0x3a:
		case 0x3b:
		case 0x3c:
		case 0x3f:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x47:
		case 0x4b:
		case 0x4f:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x57:
		case 0x5a:
		case 0x5b:
		case 0x5c:
		case 0x5f:
		case 0x62:
		case 0x63:
		case 0x64:
		case 0x67:
		case 0x6b:
		case 0x6f:
		case 0x72:
		case 0x73:
		case 0x74:
		case 0x77:
		case 0x7a:
		case 0x7b:
		case 0x7c:
		case 0x7f:
		case 0x80:
		case 0x82:
		case 0x83:
		case 0x87:
		case 0x89:
		case 0x8b:
		case 0x8f:
		case 0x92:
		case 0x93:
		case 0x97:
		case 0x9b:
		case 0x9c:
		case 0x9e:
		case 0x9f:
		case 0xa3:
		case 0xa7:
		case 0xab:
		case 0xaf:
		case 0xb2:
		case 0xb3:
		case 0xb7:
		case 0xbb:
		case 0xbf:
		case 0xc2:
		case 0xc3:
		case 0xc7:
		case 0xcb:
		case 0xcf:
		case 0xd2:
		case 0xd3:
		case 0xd4:
		case 0xd7:
		case 0xda:
		case 0xdb:
		case 0xdc:
		case 0xdf:
		case 0xe2:
		case 0xe3:
		case 0xe7:
		case 0xeb:
		case 0xef:
		case 0xf2:
		case 0xf3:
		case 0xf4:
		case 0xf7:
		case 0xfa:
		case 0xfb:
		case 0xfc:
		case 0xff:
			// undocumented or not-implemented opcodes for 6502.
			// some of them might be implemented in 65816
			op->size = 1;
			op->type = R_ANAL_OP_TYPE_ILL;		
			break;

		// BRK
		case 0x00: // brk
			// takes one byte, but pc+2 instead of pc+1
			// overrides SNES size
			op->size = 1;
			op->cycles = 7;
			// FIXME: Not sure if there is an opcode for this one
			op->type = R_ANAL_OP_TYPE_UNK;		
			break;

		// FLAGS
		case 0x78: // sei
		case 0x58: // cli
		case 0x38: // sec
		case 0x18: // clc
		case 0xf8: // sed
		case 0xd8: // cld
		case 0xb8: // clv
			op->cycles = 2;
			// FIXME: what opcode for this?
			op->type = R_ANAL_OP_TYPE_NOP;
			_6502_anal_esil_flags (op);
			break;

		// ORA
		case 0x09: // ora #$ff
		case 0x05: // ora $ff
		case 0x15: // ora $ff,x
		case 0x0d: // ora $ffff
		case 0x1d: // ora $ffff,x
		case 0x19: // ora $ffff,y
		case 0x01: // ora ($ff,x)
		case 0x11: // ora ($ff),y
			// FIXME: set correct cycles for each opcode
			op->cycles = 5;
			op->type = R_ANAL_OP_TYPE_OR;
			_6502_anal_esil_or (op);
			break;

		// AND
		case 0x29: // and #$ff
		case 0x25: // and $ff
		case 0x35: // and $ff,x
		case 0x2d: // and $ffff
		case 0x3d: // and $ffff,x
		case 0x39: // and $ffff,y
		case 0x21: // and ($ff,x)
		case 0x31: // and ($ff),y
			// FIXME: set correct cycles for each opcode
			op->cycles = 5;
			op->type = R_ANAL_OP_TYPE_AND;
			_6502_anal_esil_and (op);
			break;

		// EOR
		case 0x49: // eor #$ff
		case 0x45: // eor $ff
		case 0x55: // eor $ff,x
		case 0x4d: // eor $ffff
		case 0x5d: // eor $ffff,x
		case 0x59: // eor $ffff,y
		case 0x41: // eor ($ff,x)
		case 0x51: // eor ($ff),y
			// FIXME: set correct cycles for each opcode
			op->cycles = 5;
			op->type = R_ANAL_OP_TYPE_XOR;
			_6502_anal_esil_xor (op);
			break;

		// ASL 
		case 0x0a: // asl a
		case 0x06: // asl $ff
		case 0x16: // asl $ff,x
		case 0x0e: // asl $ffff
		case 0x1e: // asl $ffff,x
			// FIXME: set correct cycles for each opcode
			op->cycles = 7;
			op->type = R_ANAL_OP_TYPE_SHL;
			_6502_anal_esil_shift (op);
			break;

		// LSR
		case 0x4a: // lsr a
		case 0x46: // lsr $ff
		case 0x56: // lsr $ff,x
		case 0x4e: // lsr $ffff
		case 0x5e: // lsr $ffff,x
			// FIXME: set correct cycles for each opcode
			op->cycles = 7;
			op->type = R_ANAL_OP_TYPE_SHR;
			_6502_anal_esil_shift (op);
			break;

		// ROL
		case 0x2a: // rol a
		case 0x26: // rol $ff
		case 0x36: // rol $ff,x
		case 0x2e: // rol $ffff
		case 0x3e: // rol $ffff,x
			// FIXME: set correct cycles for each opcode
			op->cycles = 7;
			op->type = R_ANAL_OP_TYPE_ROL;
			_6502_anal_esil_rol (op);
			break;

		// ROR
		case 0x6a: // ror a
		case 0x66: // ror $ff
		case 0x76: // ror $ff,x
		case 0x6e: // ror $ffff
		case 0x7e: // ror $ffff,x
			// FIXME: set correct cycles for each opcode
			op->cycles = 7;
			op->type = R_ANAL_OP_TYPE_ROR;
			_6502_anal_esil_rol (op);
			break;

		// INC
		case 0xe6: // inc $ff
		case 0xf6: // inc $ff,x
		case 0xee: // inc $ffff
		case 0xfe: // inc $ffff,x
			// FIXME: set correct cycles for each opcode
			op->cycles = 7;
			op->type = R_ANAL_OP_TYPE_STORE;
			_6502_anal_esil_store (op);
			break;

		// DEC
		case 0xc6: // dec $ff
		case 0xd6: // dec $ff,x
		case 0xce: // dec $ffff
		case 0xde: // dec $ffff,x
			// FIXME: set correct cycles for each opcode
			op->cycles = 7;
			op->type = R_ANAL_OP_TYPE_STORE;
			_6502_anal_esil_store (op);
			break;

		// INY,INX,DEY,DEX
		case 0xe8: // inx
		case 0xca: // dex
		case 0xc8: // iny
		case 0x88: // dey
			op->cycles = 2;
			op->type = R_ANAL_OP_TYPE_STORE;
			_6502_anal_esil_load (op);
			break;

		// CMP
		case 0xc9: // cmp #$ff
		case 0xc5: // cmp $ff
		case 0xd5: // cmp $ff,x
		case 0xcd: // cmp $ffff
		case 0xdd: // cmp $ffff,x
		case 0xd9: // cmp $ffff,y
		case 0xc1: // cmp ($ff,x)
		case 0xd1: // cmp ($ff),y
			// FIXME: set correct cycles for each opcode
			op->cycles = 7;
			op->type = R_ANAL_OP_TYPE_CMP;
			_6502_anal_esil_cmp (op);
			break;

		// CPX
		case 0xe0: // cpx #$ff
		case 0xe4: // cpx $ff
		case 0xec: // cpx $ffff
			// FIXME: set correct cycles for each opcode
			op->cycles = 7;
			op->type = R_ANAL_OP_TYPE_CMP;
			_6502_anal_esil_cmp (op);
			break;

		// CPY
		case 0xc0: // cpy #$ff
		case 0xc4: // cpy $ff
		case 0xcc: // cpy $ffff
			// FIXME: set correct cycles for each opcode
			op->cycles = 7;
			op->type = R_ANAL_OP_TYPE_CMP;
			_6502_anal_esil_cmp (op);
			break;

		// ADC
		case 0x69: // adc #$ff
		case 0x65: // adc $ff
		case 0x75: // adc $ff,x
		case 0x6d: // adc $ffff
		case 0x7d: // adc $ffff,x
		case 0x79: // adc $ffff,y
		case 0x61: // adc ($ff,x)
		case 0x71: // adc ($ff,y)
			// FIXME: set correct cycles for each opcode
			op->cycles = 7;
			op->type = R_ANAL_OP_TYPE_ADD;
			_6502_anal_esil_add (op);
			break;

		// SBC
		case 0xe9: // sbc #$ff
		case 0xe5: // sbc $ff
		case 0xf5: // sbc $ff,x
		case 0xed: // sbc $ffff
		case 0xfd: // sbc $ffff,x
		case 0xf9: // sbc $ffff,y
		case 0xe1: // sbc ($ff,x)
		case 0xf1: // sbc ($ff,y)
			// FIXME: set correct cycles for each opcode
			op->cycles = 7;
			op->type = R_ANAL_OP_TYPE_SUB;
			_6502_anal_esil_sub (op);
			break;

		// BRANCHES 
		case 0x10: // bpl $ffff
		case 0x30: // bmi $ffff
		case 0x50: // bvc $ffff
		case 0x70: // bvs $ffff
		case 0x90: // bcc $ffff
		case 0xb0: // bcs $ffff
		case 0xd0: // bne $ffff
		case 0xf0: // beq $ffff
			// FIXME: it could be one more if page crossing. How can I find this out?
			op->cycles = 2;
			op->failcycles = 3;
			op->type = R_ANAL_OP_TYPE_CJMP;
			if (data[1] <= 127)
				op->jump = addr + data[1] + op->size;
			else
				op->jump = addr - (256-data[1]) + op->size;
			op->fail = addr + op->size;
			// FIXME: add a type of conditional
			// op->cond = R_ANAL_COND_LE;
			_6502_anal_esil_ccall (op);
			break;

		// JSR
		case 0x20: // jsr $ffff
			op->cycles = 6;
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = data[1] | data[2] << 8;
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = 2;
			_6502_anal_esil_call (op);
			break;

		// JMP
		case 0x4c: // jmp $ffff
			op->cycles = 3;
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = data[1] | data[2] << 8;
			_6502_anal_esil_jmp (op);
			break;
		case 0x6c: // jmp ($ffff)
			op->cycles = 5;
			op->type = R_ANAL_OP_TYPE_UJMP;
			// op->jump = data[1] | data[2] << 8;
			_6502_anal_esil_jmp (op);
			break;

		// RTS
		case 0x60: // rts
			op->eob = 1;
			op->type = R_ANAL_OP_TYPE_RET;
			op->cycles = 6;
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -2;
			_6502_anal_esil_ret (op);
			break;

		// RTI
		case 0x40: // rti
			op->eob = 1;
			op->type = R_ANAL_OP_TYPE_RET;
			op->cycles = 6;
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -3;		// pops PC and P
			_6502_anal_esil_ret (op);
			break;

		// NOP
		case 0xea: // nop
			op->type = R_ANAL_OP_TYPE_NOP;
			op->cycles = 2;
			break;


		// LDA
		case 0xa9: // lda #$ff
		case 0xa5: // lda $ff
		case 0xb5: // lda $ff,x
		case 0xad: // lda $ffff
		case 0xbd: // lda $ffff,x
		case 0xb9: // lda $ffff,y
		case 0xa1: // lda ($ff,x)
		case 0xb1: // lda ($ff),y
			op->type = R_ANAL_OP_TYPE_LOAD;
			op->cycles = 6; // FIXME
			_6502_anal_esil_load (op);
			break;

		// LDX
		case 0xa2: // ldx #$ff
		case 0xa6: // ldx $ff
		case 0xb6: // ldx $ff,y
		case 0xae: // ldx $ffff
		case 0xbe: // ldx $ffff,y
			op->type = R_ANAL_OP_TYPE_LOAD;
			op->cycles = 6; // FIXME
			_6502_anal_esil_load (op);
			break;

		// LDY
		case 0xa0: // ldy #$ff
		case 0xa4: // ldy $ff
		case 0xb4: // ldy $ff,x
		case 0xac: // ldy $ffff
		case 0xbc: // ldy $ffff,x
			op->type = R_ANAL_OP_TYPE_LOAD;
			op->cycles = 6; // FIXME
			_6502_anal_esil_load (op);
			break;

		// STA
		case 0x85: // sta $ff
		case 0x95: // sta $ff,x
		case 0x8d: // sta $ffff
		case 0x9d: // sta $ffff,x
		case 0x99: // sta $ffff,y
		case 0x81: // sta ($ff,x)
		case 0x91: // sta ($ff),y
			op->type = R_ANAL_OP_TYPE_STORE;
			op->cycles = 6; // FIXME
			_6502_anal_esil_store (op);
			break;

		// STX
		case 0x86: // stx $ff
		case 0x96: // stx $ff,y
		case 0x8e: // stx $ffff
			op->type = R_ANAL_OP_TYPE_STORE;
			op->cycles = 6; // FIXME
			_6502_anal_esil_store (op);
			break;

		// STY
		case 0x84: // sty $ff
		case 0x94: // sty $ff,x
		case 0x8c: // sty $ffff
			op->type = R_ANAL_OP_TYPE_STORE;
			op->cycles = 6; // FIXME
			_6502_anal_esil_store (op);
			break;

		// PHP/PHA
		case 0x08: // php
		case 0x48: // pha
			op->type = R_ANAL_OP_TYPE_PUSH;
			op->cycles = 3;
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = 1;
			_6502_anal_esil_push (op);
			break;

		// PLP,PLA
		case 0x28: // plp
		case 0x68: // plp
			op->type = R_ANAL_OP_TYPE_POP;
			op->cycles = 4;
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -1;
			_6502_anal_esil_pop (op);
			break;

		// TAX,TYA,...
		case 0xaa: // tax 
		case 0x8a: // txa
		case 0xa8: // tay 
		case 0x98: // tya
			op->type = R_ANAL_OP_TYPE_MOV;
			op->cycles = 2;
			_6502_anal_esil_mov (op);
			break;
		case 0x9a: // txs
			op->type = R_ANAL_OP_TYPE_MOV;
			op->cycles = 2;
			op->stackop = R_ANAL_STACK_SET;
			// FIXME: get register X a place it here
			// op->stackptr = get_register_x();
			_6502_anal_esil_mov (op);
			break;
		case 0xba: // tsx
			op->type = R_ANAL_OP_TYPE_MOV;
			op->cycles = 2;
			op->stackop = R_ANAL_STACK_GET;
			_6502_anal_esil_mov (op);
			break;

	}
	return op->size;
}

static int set_reg_profile(RAnal *anal) {
	char *p =
		"=pc	pc\n"
		"=sp	sp\n"

		"gpr	a	.8	0	0\n"
		"gpr	x	.8	1	0\n"
		"gpr	y	.8	2	0\n"

		"gpr	flags	.8	3	0\n"
		"flg	C	.1	.24	0\n"
		"flg	Z	.1	.25	0\n"
		"flg	I	.1	.26	0\n"
		"flg	D	.1	.27	0\n"
		"flg	B	.1	.28	0\n"
		// bit 5 (.29) is not used
		"flg	V	.1	.30	0\n"
		"flg	N	.1	.31	0\n"

		"gpr	sp	.8	4	0\n"

		"gpr	pc	.16	5	0\n";

	return r_reg_set_profile_string (anal->reg, p);
}

static int esil_gb_init (RAnalEsil *esil) {
	if (esil->anal && esil->anal->reg) {		//initial values
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "pc", -1), 0xc000);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "sp", -1), 0x00);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "a", -1), 0x00);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "x", -1), 0x00);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "y", -1), 0x00);
	}
	return true;
}

static int esil_gb_fini (RAnalEsil *esil) {
	return true;
}

struct r_anal_plugin_t r_anal_plugin_6502 = {
	.name = "6502",
	.desc = "6502/NES analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_NONE,
	.bits = 8,
	.init = NULL,
	.fini = NULL,
	.op = &_6502_op,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL,
	.set_reg_profile = &set_reg_profile,
	.esil_init = esil_gb_init,
	.esil_fini = esil_gb_fini,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_6502,
	.version = R2_VERSION
};
#endif

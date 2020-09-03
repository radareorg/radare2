/* radare - LGPL - Copyright 2019-2020 - condret, riq */

/* 6502 info taken from http://unusedino.de/ec64/technical/aay/c64/bchrt651.htm
 *
 * Mnemonics logic based on:
 *	http://homepage.ntlworld.com/cyborgsystems/CS_Main/6502/6502.htm
 * and:
 *	http://vice-emu.sourceforge.net/
 */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/snes/snes_op_table.h"

enum {
	_6502_FLAGS_C = (1 << 0),
	_6502_FLAGS_B = (1 << 1),
	_6502_FLAGS_Z = (1 << 2),
	_6502_FLAGS_N = (1 << 3),

	_6502_FLAGS_NZ = (_6502_FLAGS_Z | _6502_FLAGS_N),
	_6502_FLAGS_CNZ = (_6502_FLAGS_C | _6502_FLAGS_Z | _6502_FLAGS_N),
	_6502_FLAGS_BNZ = (_6502_FLAGS_B | _6502_FLAGS_Z | _6502_FLAGS_N),
};

static void _6502_anal_update_flags(RAnalOp *op, int flags) {
	/* FIXME: 9,$b instead of 8,$b to prevent the bug triggered by: A = 0 - 0xff - 1 */
	if (flags & _6502_FLAGS_B) {
		r_strbuf_append (&op->esil, ",9,$b,C,:=");
	}
	if (flags & _6502_FLAGS_C) {
		r_strbuf_append (&op->esil, ",7,$c,C,:=");
	}
	if (flags & _6502_FLAGS_Z) {
		r_strbuf_append (&op->esil, ",$z,Z,:=");
	}
	if (flags & _6502_FLAGS_N) {
		r_strbuf_append (&op->esil, ",7,$s,N,:=");
	}
}

/* ORA, AND, EOR, ADC, STA, LDA, CMP and SBC share this pattern */
static void _6502_anal_esil_get_addr_pattern1(RAnalOp *op, const ut8* data, int len, char* addrbuf, int addrsize) {
	if (len < 1) {
		return;
	}
	// turn off bits 5, 6 and 7
	switch (data[0] & 0x1f) { // 0x1f = b00111111
	case 0x09: // op #$ff
		op->cycles = 2;
		snprintf (addrbuf, addrsize,"0x%02x", (len > 1)? data[1]: 0);
		break;
	case 0x05: // op $ff
		op->cycles = 3;
		snprintf (addrbuf, addrsize,"0x%02x", (len > 1)? data[1]: 0);
		break;
	case 0x15: // op $ff,x
		op->cycles = 4;
		snprintf (addrbuf, addrsize,"x,0x%02x,+", (len > 1)? data[1]: 0);
		break;
	case 0x0d: // op $ffff
		op->cycles = 4;
		snprintf (addrbuf, addrsize,"0x%04x", (len > 2) ? (data[1] | data[2] << 8): 0);
		break;
	case 0x1d: // op $ffff,x
		// FIXME: Add 1 if page boundary is crossed.
		op->cycles = 4;
		snprintf (addrbuf, addrsize,"x,0x%04x,+", (len > 2) ? data[1] | data[2] << 8: 0);
		break;
	case 0x19: // op $ffff,y
		// FIXME: Add 1 if page boundary is crossed.
		op->cycles = 4;
		snprintf (addrbuf, addrsize,"y,0x%04x,+", (len > 2)? data[1] | data[2] << 8: 0);
		break;
	case 0x01: // op ($ff,x)
		op->cycles = 6;
		snprintf (addrbuf, addrsize,"x,0x%02x,+,[2]", (len > 1)? data[1]: 0);
		break;
	case 0x11: // op ($ff),y
		// FIXME: Add 1 if page boundary is crossed.
		op->cycles = 5;
		snprintf (addrbuf, addrsize,"y,0x%02x,[2],+", (len > 1) ? data[1]: 0);
		break;
	}
}

/* ASL, ROL, LSR, ROR, STX, LDX, DEC and INC share this pattern */
static void _6502_anal_esil_get_addr_pattern2(RAnalOp *op, const ut8* data, int len, char* addrbuf, int addrsize, char reg) {
	// turn off bits 5, 6 and 7
	if (len < 1) {
		return;
	}
	switch (data[0] & 0x1f) { // 0x1f = b00111111
	case 0x02: // op #$ff
		op->cycles = 2;
		snprintf (addrbuf, addrsize, "0x%02x", (len>1)? data[1]: 0);
		break;
	case 0x0a: //op a
		op->cycles = 2;
		snprintf (addrbuf, addrsize, "a");
		break;
	case 0x06: // op $ff
		op->cycles = 5;
		snprintf (addrbuf, addrsize, "0x%02x", (len>1)?data[1]:0);
		break;
	case 0x16: // op $ff,x
		op->cycles = 6;
		snprintf (addrbuf, addrsize, "%c,0x%02x,+", reg, (len >1)? data[1]:0);
		break;
	case 0x0e: // op $ffff
		op->cycles = 6;
		snprintf (addrbuf, addrsize, "0x%04x", (len>2)? data[1] | data[2] << 8: 0);
		break;
	case 0x1e: // op $ffff,x
		op->cycles = 7;
		snprintf (addrbuf, addrsize, "%c,0x%04x,+", reg, (len>2)? data[1] | data[2] << 8: 0);
		break;
	}
}

/* BIT, JMP, JMP(), STY, LDY, CPY, and CPX share this pattern */
static void _6502_anal_esil_get_addr_pattern3(RAnalOp *op, const ut8* data, int len, char* addrbuf, int addrsize, char reg) {
	// turn off bits 5, 6 and 7
	if (len < 1) {
		return;
	}
	switch (data[0] & 0x1f) { // 0x1f = b00111111
	case 0x00: // op #$ff
		op->cycles = 2;
		snprintf (addrbuf, addrsize, "0x%02x", (len > 1) ? data[1]: 0);
		break;
	case 0x08: //op a
		op->cycles = 2;
		snprintf (addrbuf, addrsize, "a");
		break;
	case 0x04: // op $ff
		op->cycles = 5;
		snprintf (addrbuf, addrsize, "0x%02x", (len > 1)? data[1]: 0);
		break;
	case 0x14: // op $ff,x
		op->cycles = 6;
		snprintf (addrbuf, addrsize, "%c,0x%02x,+", reg, (len>1)? data[1]:0);
		break;
	case 0x0c: // op $ffff
		op->cycles = 6;
		snprintf (addrbuf, addrsize, "0x%04x", (len>2)? data[1] | data[2] << 8: 0);
		break;
	case 0x1c: // op $ffff,x
		op->cycles = 7;
		snprintf (addrbuf, addrsize, "%c,0x%04x,+", reg, (len>2)? data[1] | data[2] << 8: 0);
		break;
	}
}

static void _6502_anal_esil_ccall(RAnalOp *op, ut8 data0) {
	char *flag;
	switch (data0) {
	case 0x10: // bpl $ffff
		flag = "N,!";
		break;
	case 0x30: // bmi $ffff
		flag = "N";
		break;
	case 0x50: // bvc $ffff
		flag = "V,!";
		break;
	case 0x70: // bvs $ffff
		flag = "V";
		break;
	case 0x90: // bcc $ffff
		flag = "C,!";
		break;
	case 0xb0: // bcs $ffff
		flag = "C";
		break;
	case 0xd0: // bne $ffff
		flag = "Z,!";
		break;
	case 0xf0: // beq $ffff
		flag = "Z";
		break;
	default:
		// FIXME: should not happen
		flag = "unk";
		break;
	}
	r_strbuf_setf (&op->esil, "%s,?{,0x%04x,pc,=,}", flag, (ut32)(op->jump & 0xffff));
}

// inc register
static void _6502_anal_esil_inc_reg(RAnalOp *op, ut8 data0, char* sign) {
	char* reg = NULL;

	switch(data0) {
	case 0xe8: // inx
	case 0xca: // dex
		reg = "x";
		break;
	case 0xc8: // iny
	case 0x88: // dey
		reg = "y";
		break;
	}
	r_strbuf_setf (&op->esil, "%s,%s%s=", reg, sign, sign);
	_6502_anal_update_flags (op, _6502_FLAGS_NZ);
}

static void _6502_anal_esil_mov(RAnalOp *op, ut8 data0) {
	const char* src="unk";
	const char* dst="unk";
	switch(data0) {
	case 0xaa: // tax
		src="a";
		dst="x";
		break;
	case 0x8a: // txa
		src="x";
		dst="a";
		break;
	case 0xa8: // tay
		src="a";
		dst="y";
		break;
	case 0x98: // tya
		src="y";
		dst="a";
		break;
	case 0x9a: // txs
		src="x";
		dst="sp";
		break;
	case 0xba: // tsx
		src="sp";
		dst="x";
		break;
	default:
		// FIXME: should not happen
		break;
	}
	r_strbuf_setf (&op->esil, "%s,%s,=",src,dst);

	// don't update NZ on txs
	if (data0 != 0x9a) {
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
	}
}

static void _6502_anal_esil_push(RAnalOp *op, ut8 data0) {
	// case 0x08: // php
	// case 0x48: // pha
	char *reg = (data0==0x08) ? "flags" : "a";
	// stack is on page one: sp + 0x100
	r_strbuf_setf (&op->esil, "%s,sp,0x100,+,=[1],sp,--=", reg);
}

static void _6502_anal_esil_pop(RAnalOp *op, ut8 data0) {
	// case 0x28: // plp
	// case 0x68: // pla
	char *reg = (data0==0x28) ? "flags" : "a";
	// stack is on page one: sp + 0x100
	r_strbuf_setf (&op->esil, "sp,++=,sp,0x100,+,[1],%s,=", reg);

	if (data0 == 0x68) {
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
	}
}

static void _6502_anal_esil_flags(RAnalOp *op, ut8 data0) {
	int enabled=0;
	char flag ='u';
	switch(data0) {
	case 0x78: // sei
		enabled = 1;
		flag = 'I';
		break;
	case 0x58: // cli
		enabled = 0;
		flag = 'I';
		break;
	case 0x38: // sec
		enabled = 1;
		flag = 'C';
		break;
	case 0x18: // clc
		enabled = 0;
		flag = 'C';
		break;
	case 0xf8: // sed
		enabled = 1;
		flag = 'D';
		break;
	case 0xd8: // cld
		enabled = 0;
		flag = 'D';
		break;
	case 0xb8: // clv
		enabled = 0;
		flag = 'V';
		break;
		break;
	}
	r_strbuf_setf (&op->esil, "%d,%c,=", enabled, flag);
}

static int _6502_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	char addrbuf[64];
	const int buffsize = sizeof (addrbuf) - 1;
	if (len < 1) {
		return -1;
	}

	op->size = snes_op_get_size (1, 1, &snes_op[data[0]]);	//snes-arch is similar to nes/6502
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->id = data[0];
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
		op->cycles = 7;
		op->type = R_ANAL_OP_TYPE_SWI;
		// override 65816 code which seems to be wrong: size is 1, but pc = pc + 2
		op->size = 1;
		// PC + 2 to Stack, P to Stack  B=1 D=0 I=1. "B" is not a flag. Only its bit is pushed on the stack
		// PC was already incremented by one at this point. Needs to incremented once more
		// New PC is Interrupt Vector: $fffe. (FIXME: Confirm this is valid for all 6502)
		r_strbuf_set (&op->esil, ",1,I,=,0,D,=,flags,0x10,|,0x100,sp,+,=[1],pc,1,+,0xfe,sp,+,=[2],3,sp,-=,0xfffe,[2],pc,=");
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
		_6502_anal_esil_flags (op, data[0]);
		break;
	// BIT
	case 0x24: // bit $ff
	case 0x2c: // bit $ffff
		op->type = R_ANAL_OP_TYPE_MOV;
		_6502_anal_esil_get_addr_pattern3 (op, data, len, addrbuf, buffsize, 0);
		r_strbuf_setf (&op->esil, "%s,[1],0x80,&,!,!,N,=,%s,[1],0x40,&,!,!,V,=,a,%s,[1],&,0xff,&,!,Z,=", addrbuf, addrbuf, addrbuf);
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
		// FIXME: update V
		// FIXME: support BCD mode
		op->type = R_ANAL_OP_TYPE_ADD;
		_6502_anal_esil_get_addr_pattern1 (op, data, len, addrbuf, buffsize);
		if (data[0] == 0x69) { // immediate mode
			r_strbuf_setf (&op->esil, "%s,a,+=,7,$c,C,a,+=,7,$c,|,C,:=", addrbuf);
		} else {
			r_strbuf_setf (&op->esil, "%s,[1],a,+=,7,$c,C,a,+=,7,$c,|,C,:=", addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
		// fix Z
		r_strbuf_append (&op->esil, ",a,a,=,$z,Z,:=");
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
		// FIXME: update V
		// FIXME: support BCD mode
		op->type = R_ANAL_OP_TYPE_SUB;
		_6502_anal_esil_get_addr_pattern1 (op, data, len, addrbuf, buffsize);
		if (data[0] == 0xe9) { // immediate mode
			r_strbuf_setf (&op->esil, "C,!,%s,+,a,-=", addrbuf);
		} else {
			r_strbuf_setf (&op->esil, "C,!,%s,[1],+,a,-=", addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_BNZ);
		// fix Z and revert C
		r_strbuf_append (&op->esil, ",a,a,=,$z,Z,:=,C,!=");
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
		op->type = R_ANAL_OP_TYPE_OR;
		_6502_anal_esil_get_addr_pattern1 (op, data, len, addrbuf, buffsize);
		if (data[0] == 0x09) { // immediate mode
			r_strbuf_setf (&op->esil, "%s,a,|=", addrbuf);
		} else {
			r_strbuf_setf (&op->esil, "%s,[1],a,|=", addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
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
		op->type = R_ANAL_OP_TYPE_AND;
		_6502_anal_esil_get_addr_pattern1 (op, data, len, addrbuf, buffsize);
		if (data[0] == 0x29) { // immediate mode
			r_strbuf_setf (&op->esil, "%s,a,&=", addrbuf);
		} else {
			r_strbuf_setf (&op->esil, "%s,[1],a,&=", addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
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
		op->type = R_ANAL_OP_TYPE_XOR;
		_6502_anal_esil_get_addr_pattern1 (op, data, len, addrbuf, buffsize);
		if (data[0] == 0x49) { // immediate mode
			r_strbuf_setf (&op->esil, "%s,a,^=", addrbuf);
		} else {
			r_strbuf_setf (&op->esil, "%s,[1],a,^=", addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
		break;
	// ASL
	case 0x0a: // asl a
	case 0x06: // asl $ff
	case 0x16: // asl $ff,x
	case 0x0e: // asl $ffff
	case 0x1e: // asl $ffff,x
		op->type = R_ANAL_OP_TYPE_SHL;
		if (data[0] == 0x0a) {
			r_strbuf_set (&op->esil, "1,a,<<=,7,$c,C,:=,a,a,=");
		} else  {
			_6502_anal_esil_get_addr_pattern2 (op, data, len, addrbuf, buffsize, 'x');
			r_strbuf_setf (&op->esil, "1,%s,[1],<<,%s,=[1],7,$c,C,:=", addrbuf, addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
		break;
	// LSR
	case 0x4a: // lsr a
	case 0x46: // lsr $ff
	case 0x56: // lsr $ff,x
	case 0x4e: // lsr $ffff
	case 0x5e: // lsr $ffff,x
		op->type = R_ANAL_OP_TYPE_SHR;
		if (data[0] == 0x4a) {
			r_strbuf_set (&op->esil, "1,a,&,C,=,1,a,>>=");
		} else {
			_6502_anal_esil_get_addr_pattern2 (op, data, len, addrbuf, buffsize, 'x');
			r_strbuf_setf (&op->esil, "1,%s,[1],&,C,=,1,%s,[1],>>,%s,=[1]", addrbuf, addrbuf, addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
		break;
	// ROL
	case 0x2a: // rol a
	case 0x26: // rol $ff
	case 0x36: // rol $ff,x
	case 0x2e: // rol $ffff
	case 0x3e: // rol $ffff,x
		op->type = R_ANAL_OP_TYPE_ROL;
		if (data[0] == 0x2a) {
			r_strbuf_set (&op->esil, "1,a,<<,C,|,a,=,7,$c,C,:=,a,a,=");
		} else {
			_6502_anal_esil_get_addr_pattern2 (op, data, len, addrbuf, buffsize, 'x');
			r_strbuf_setf (&op->esil, "1,%s,[1],<<,C,|,%s,=[1],7,$c,C,:=", addrbuf, addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
		break;
	// ROR
	case 0x6a: // ror a
	case 0x66: // ror $ff
	case 0x76: // ror $ff,x
	case 0x6e: // ror $ffff
	case 0x7e: // ror $ffff,x
		// uses N as temporary to hold C value. but in fact,
		// it is not temporary since in all ROR ops, N will have the value of C
		op->type = R_ANAL_OP_TYPE_ROR;
		if (data[0] == 0x6a) {
			r_strbuf_set (&op->esil, "C,N,=,1,a,&,C,=,1,a,>>,7,N,<<,|,a,=");
		} else {
			_6502_anal_esil_get_addr_pattern2 (op, data, len, addrbuf, buffsize, 'x');
			r_strbuf_setf (&op->esil, "C,N,=,1,%s,[1],&,C,=,1,%s,[1],>>,7,N,<<,|,%s,=[1]", addrbuf, addrbuf, addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
		break;
	// INC
	case 0xe6: // inc $ff
	case 0xf6: // inc $ff,x
	case 0xee: // inc $ffff
	case 0xfe: // inc $ffff,x
		op->type = R_ANAL_OP_TYPE_STORE;
		_6502_anal_esil_get_addr_pattern2 (op, data, len, addrbuf, buffsize, 'x');
		r_strbuf_setf (&op->esil, "%s,++=[1]", addrbuf);
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
		break;
	// DEC
	case 0xc6: // dec $ff
	case 0xd6: // dec $ff,x
	case 0xce: // dec $ffff
	case 0xde: // dec $ffff,x
		op->type = R_ANAL_OP_TYPE_STORE;
		_6502_anal_esil_get_addr_pattern2 (op, data, len, addrbuf, buffsize, 'x');
		r_strbuf_setf (&op->esil, "%s,--=[1]", addrbuf);
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
		break;
	// INX, INY
	case 0xe8: // inx
	case 0xc8: // iny
		op->cycles = 2;
		op->type = R_ANAL_OP_TYPE_STORE;
		_6502_anal_esil_inc_reg (op, data[0], "+");
		break;
	// DEX, DEY
	case 0xca: // dex
	case 0x88: // dey
		op->cycles = 2;
		op->type = R_ANAL_OP_TYPE_STORE;
		_6502_anal_esil_inc_reg (op, data[0], "-");
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
		op->type = R_ANAL_OP_TYPE_CMP;
		_6502_anal_esil_get_addr_pattern1 (op, data, len, addrbuf, buffsize);
		if (data[0] == 0xc9) { // immediate mode
			r_strbuf_setf (&op->esil, "%s,a,==", addrbuf);
		} else {
			r_strbuf_setf (&op->esil, "%s,[1],a,==", addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_BNZ);
		// invert C, since C=1 when A-M >= 0
		r_strbuf_append (&op->esil, ",C,!,C,=");
		break;
	// CPX
	case 0xe0: // cpx #$ff
	case 0xe4: // cpx $ff
	case 0xec: // cpx $ffff
		op->type = R_ANAL_OP_TYPE_CMP;
		_6502_anal_esil_get_addr_pattern3 (op, data, len, addrbuf, buffsize, 0);
		if (data[0] == 0xe0) { // immediate mode
			r_strbuf_setf (&op->esil, "%s,x,==", addrbuf);
		} else {
			r_strbuf_setf (&op->esil, "%s,[1],x,==", addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_BNZ);
		// invert C, since C=1 when A-M >= 0
		r_strbuf_append (&op->esil, ",C,!,C,=");
		break;
	// CPY
	case 0xc0: // cpy #$ff
	case 0xc4: // cpy $ff
	case 0xcc: // cpy $ffff
		op->type = R_ANAL_OP_TYPE_CMP;
		_6502_anal_esil_get_addr_pattern3 (op, data, len, addrbuf, buffsize, 0);
		if (data[0] == 0xc0) { // immediate mode
			r_strbuf_setf (&op->esil, "%s,y,==", addrbuf);
		} else {
			r_strbuf_setf (&op->esil, "%s,[1],y,==", addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_BNZ);
		// invert C, since C=1 when A-M >= 0
		r_strbuf_append (&op->esil, ",C,!,C,=");
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
		// FIXME: Add 1 if branch occurs to same page.
		// FIXME: Add 2 if branch occurs to different page
		op->cycles = 2;
		op->failcycles = 3;
		op->type = R_ANAL_OP_TYPE_CJMP;
		if (len > 1) {
			if (data[1] <= 127) {
				op->jump = addr + data[1] + op->size;
			} else {
				op->jump = addr - (256 - data[1]) + op->size;
			}
		} else {
			op->jump = addr;
		}
		op->fail = addr + op->size;
		// FIXME: add a type of conditional
		// op->cond = R_ANAL_COND_LE;
		_6502_anal_esil_ccall (op, data[0]);
		break;
	// JSR
	case 0x20: // jsr $ffff
		op->cycles = 6;
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = (len > 2)? data[1] | data[2] << 8: 0;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
		// JSR pushes the address-1 of the next operation on to the stack before transferring program
		// control to the following address
		// stack is on page one and sp is an 8-bit reg: operations must be done like: sp + 0x100
		r_strbuf_setf (&op->esil, "1,pc,-,0xff,sp,+,=[2],0x%04" PFMT64x ",pc,=,2,sp,-=", op->jump);
		break;
	// JMP
	case 0x4c: // jmp $ffff
		op->cycles = 3;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = (len > 2)? data[1] | data[2] << 8: 0;
		r_strbuf_setf (&op->esil, "0x%04" PFMT64x ",pc,=", op->jump);
		break;
	case 0x6c: // jmp ($ffff)
		op->cycles = 5;
		op->type = R_ANAL_OP_TYPE_UJMP;
		// FIXME: how to read memory?
		// op->jump = data[1] | data[2] << 8;
		r_strbuf_setf (&op->esil, "0x%04x,[2],pc,=", len > 2? data[1] | data[2] << 8: 0);
		break;
	// RTS
	case 0x60: // rts
		op->eob = true;
		op->type = R_ANAL_OP_TYPE_RET;
		op->cycles = 6;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -2;
		// Operation:  PC from Stack, PC + 1 -> PC
		// stack is on page one and sp is an 8-bit reg: operations must be done like: sp + 0x100
		r_strbuf_set (&op->esil, "0x101,sp,+,[2],pc,=,pc,++=,2,sp,+=");
		break;
	// RTI
	case 0x40: // rti
		op->eob = true;
		op->type = R_ANAL_OP_TYPE_RET;
		op->cycles = 6;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -3;
		// Operation: P from Stack, PC from Stack
		// stack is on page one and sp is an 8-bit reg: operations must be done like: sp + 0x100
		r_strbuf_set (&op->esil, "0x101,sp,+,[1],flags,=,0x102,sp,+,[2],pc,=,3,sp,+=");
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
		_6502_anal_esil_get_addr_pattern1 (op, data, len, addrbuf, buffsize);
		if (data[0] == 0xa9) { // immediate mode
			r_strbuf_setf (&op->esil, "%s,a,=", addrbuf);
		} else {
			r_strbuf_setf (&op->esil, "%s,[1],a,=", addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
		break;
	// LDX
	case 0xa2: // ldx #$ff
	case 0xa6: // ldx $ff
	case 0xb6: // ldx $ff,y
	case 0xae: // ldx $ffff
	case 0xbe: // ldx $ffff,y
		op->type = R_ANAL_OP_TYPE_LOAD;
		_6502_anal_esil_get_addr_pattern2 (op, data, len, addrbuf, buffsize, 'y');
		if (data[0] == 0xa2) { // immediate mode
			r_strbuf_setf (&op->esil, "%s,x,=", addrbuf);
		} else {
			r_strbuf_setf (&op->esil, "%s,[1],x,=", addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
		break;
	// LDY
	case 0xa0: // ldy #$ff
	case 0xa4: // ldy $ff
	case 0xb4: // ldy $ff,x
	case 0xac: // ldy $ffff
	case 0xbc: // ldy $ffff,x
		op->type = R_ANAL_OP_TYPE_LOAD;
		_6502_anal_esil_get_addr_pattern3 (op, data, len, addrbuf, buffsize, 'x');
		if (data[0] == 0xa0) { // immediate mode
			r_strbuf_setf (&op->esil, "%s,y,=", addrbuf);
		} else {
			r_strbuf_setf (&op->esil, "%s,[1],y,=", addrbuf);
		}
		_6502_anal_update_flags (op, _6502_FLAGS_NZ);
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
		_6502_anal_esil_get_addr_pattern1 (op, data, len, addrbuf, buffsize);
		r_strbuf_setf (&op->esil, "a,%s,=[1]", addrbuf);
		break;
	// STX
	case 0x86: // stx $ff
	case 0x96: // stx $ff,y
	case 0x8e: // stx $ffff
		op->type = R_ANAL_OP_TYPE_STORE;
		_6502_anal_esil_get_addr_pattern2 (op, data, len, addrbuf, buffsize, 'y');
		r_strbuf_setf (&op->esil, "x,%s,=[1]", addrbuf);
		break;
	// STY
	case 0x84: // sty $ff
	case 0x94: // sty $ff,x
	case 0x8c: // sty $ffff
		op->type = R_ANAL_OP_TYPE_STORE;
		_6502_anal_esil_get_addr_pattern3 (op, data, len, addrbuf, buffsize, 'x');
		r_strbuf_setf (&op->esil, "y,%s,=[1]", addrbuf);
		break;
	// PHP/PHA
	case 0x08: // php
	case 0x48: // pha
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->cycles = 3;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 1;
		_6502_anal_esil_push (op, data[0]);
		break;
	// PLP,PLA
	case 0x28: // plp
	case 0x68: // plp
		op->type = R_ANAL_OP_TYPE_POP;
		op->cycles = 4;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -1;
		_6502_anal_esil_pop (op, data[0]);
		break;
	// TAX,TYA,...
	case 0xaa: // tax
	case 0x8a: // txa
	case 0xa8: // tay
	case 0x98: // tya
		op->type = R_ANAL_OP_TYPE_MOV;
		op->cycles = 2;
		_6502_anal_esil_mov (op, data[0]);
		break;
	case 0x9a: // txs
		op->type = R_ANAL_OP_TYPE_MOV;
		op->cycles = 2;
		op->stackop = R_ANAL_STACK_SET;
		// FIXME: should I get register X a place it here?
		// op->stackptr = get_register_x();
		_6502_anal_esil_mov (op, data[0]);
		break;
	case 0xba: // tsx
		op->type = R_ANAL_OP_TYPE_MOV;
		op->cycles = 2;
		op->stackop = R_ANAL_STACK_GET;
		_6502_anal_esil_mov (op, data[0]);
		break;
	}
	return op->size;
}

static bool set_reg_profile(RAnal *anal) {
	char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=A0	y\n"
		"=A1	y\n"
		"gpr	a	.8	0	0\n"
		"gpr	x	.8	1	0\n"
		"gpr	y	.8	2	0\n"

		"gpr	flags	.8	3	0\n"
		"gpr	C	.1	.24	0\n"
		"gpr	Z	.1	.25	0\n"
		"gpr	I	.1	.26	0\n"
		"gpr	D	.1	.27	0\n"
		// bit 4 (.28) is NOT a real flag.
		// "gpr	B	.1	.28	0\n"
		// bit 5 (.29) is not used
		"gpr	V	.1	.30	0\n"
		"gpr	N	.1	.31	0\n"
		"gpr	sp	.8	4	0\n"
		"gpr	pc	.16	5	0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

static int esil_6502_init (RAnalEsil *esil) {
	if (esil->anal && esil->anal->reg) {		//initial values
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "pc", -1), 0x0000);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "sp", -1), 0xff);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "a", -1), 0x00);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "x", -1), 0x00);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "y", -1), 0x00);
		r_reg_set_value (esil->anal->reg, r_reg_get (esil->anal->reg, "flags", -1), 0x00);
	}
	return true;
}

static int esil_6502_fini (RAnalEsil *esil) {
	return true;
}

RAnalPlugin r_anal_plugin_6502 = {
	.name = "6502",
	.desc = "6502/NES analysis plugin",
	.license = "LGPL3",
	.arch = "6502",
	.bits = 8,
	.op = &_6502_op,
	.set_reg_profile = &set_reg_profile,
	.esil = true,
	.esil_init = esil_6502_init,
	.esil_fini = esil_6502_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_6502,
	.version = R2_VERSION
};
#endif

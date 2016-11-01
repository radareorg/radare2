/* radare - LGPL - Copyright 2010-2016 - pancake */

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "../../asm/arch/dalvik/opcode.h"
#include "../../bin/format/dex/dex.h" 

static int dalvik_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	int sz = dalvik_opcodes[data[0]].len;
	if (!op) {
		return sz;
	}
	memset (op, '\0', sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_UNK;
	op->ptr = UT64_MAX;
	op->val = UT64_MAX;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->refptr = 0;
	op->size = sz;
	op->nopcode = 1; // Necessary??
	op->id = data[0];

	switch (data[0]) {
	case 0xca: // rem-float:
		op->family = R_ANAL_OP_FAMILY_FPU;
		/* pass thru */
	case 0x1b: // const-string/jumbo
	case 0x01: // move
	case 0x02: // move
	case 0x03: // move/16
	case 0x04: // mov-wide
	case 0x05: // mov-wide
	case 0x06: // mov-wide
	case 0x07: //
	case 0x08: //
	case 0x09: //
	case 0x0a: //
	case 0x0d: // move-exception
	case 0x12: // const/4
	case 0x13: // const/16
	case 0x14: // const
	case 0x15: // const
	case 0x16: // const
	case 0x17: // const
	case 0x42: // const
	case 0x18: // const-wide
	case 0x19: // const-wide
	case 0x0c: // move-result-object // TODO: add MOVRET OP TYPE ??
	case 0x0b: // move-result-wide
		op->type = R_ANAL_OP_TYPE_MOV;
		int vA = (int) -data[1];
		op->stackop = R_ANAL_STACK_SET;
		op->ptr = vA;
		break;
	case 0x1a: // const-string
		op->type = R_ANAL_OP_TYPE_MOV;
		{
			ut32 vB = (data[3]<<8) | data[2];
			ut64 offset = R_ANAL_GET_OFFSET (anal, 's', vB);
			op->ptr = offset;
		}
		break;
	case 0x1c: // const-class
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0x85: // long-to-float
	case 0x8e: // double-to-int
	case 0x89: // float-to-double
	case 0x8a: // double-to-int
	case 0x87: // double-to-int
	case 0x8c: // double-to-float
	case 0x8b: // double-to-long
	case 0x88: // float-to-long
	case 0x86: // long-to-double
		op->family = R_ANAL_OP_FAMILY_FPU;
		/* pass thru */
	case 0x81: // int-to-long
	case 0x82: // 
	case 0x83: // 
	case 0x84: // 
	case 0x8d: // int-to-byte
	case 0x8f: // int-to-short
	case 0x20: // instance-of
		op->type = R_ANAL_OP_TYPE_CAST;
		break;
	case 0x21: // array-length
		op->type = R_ANAL_OP_TYPE_LENGTH;
		break;
	case 0x44: // aget
	case 0x45: //aget-bool
	case 0x46:
	case 0x47: //aget-bool
	case 0x48: //aget-byte
	case 0x49: //aget-char
	case 0x4a: //aget-short
	case 0x52: //iget
	case 0x58: //iget-short
	case 0x53: //iget-wide
	case 0x56: //iget-byte
	case 0x57: //iget-char
	case 0xea: //sget-wide-volatile
	case 0x63: //sget-boolean
	case 0xf4: //iget-byte
	case 0x66: //sget-short
	case 0xfd: //sget-object
	case 0x55: //iget-bool
	case 0x60: // sget
	case 0x61: // 
	case 0x62: //
	case 0x64: // sget-byte
	case 0x65: // sget-char
	case 0xe3: //iget-volatile
	case 0xe4: //
	case 0xe5: // sget
	case 0xe6: // sget
	case 0x54: // iget-object
	case 0xe7: // iget-object-volatile
	case 0xe8: //iget-bool
	case 0xf3: //iget-bool
	case 0xf8: //iget-bool
	case 0xf2: //iget-quick
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case 0x6b: //sput-byte
	case 0x6d: //sput-short
	case 0xeb: //sput-wide-volatile
	case 0x4b: //aput
	case 0x4c: //aput-wide
	case 0x4d: // aput-object
	case 0x4e: // aput-bool
	case 0x4f: // 
	case 0x5e: //iput-char
	case 0xfc: //iput-object-volatile
	case 0xf5: //iput-quick
	case 0x5c: //iput-bool
	case 0x69: //sput-object
	case 0x5f: //iput-wide
	case 0xe9: //iput-wide-volatile
	case 0xf6: //iput-wide
	case 0xf7: //iput-wide
	case 0x67: //iput-wide
	case 0x59: //iput-wide
	case 0x5a: //iput-wide
	case 0x5b: //iput-wide
	case 0x5d: //iput-wide
	case 0x50: //
	case 0x51: // aput-short
	case 0x68: // sput-wide
	case 0x6a: // sput-boolean
	case 0x6c: // sput-wide
	case 0xfe: // sput
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case 0x9d:
	case 0xad: // mul-double
	case 0xc8: // mul-float
		op->family = R_ANAL_OP_FAMILY_FPU;
		/* fall through */
	case 0xcd:
	case 0xd2:
	case 0x92:
	case 0xb2:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case 0x7c: // not-int
	case 0x7e: // not-long
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case 0xa4: // shr-long
	case 0xba: // ushr-int/2addr
	case 0xe2: // ushr-int
	case 0xa5: // ushr-long
	case 0x9a: // ushr-long
	case 0xc5: // ushr-long/2addr
	case 0xc4: // shr-long/2addr
	case 0xe1: // shr-int/lit8
	case 0x99: // shr-int
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case 0xaa: // rem-float
	case 0xcf: // rem-double
	case 0xaf: // rem-double
		op->family = R_ANAL_OP_FAMILY_FPU;
		/* pass thru */
	case 0xb4: // rem-int/2addr
	case 0xdc: // rem-int/lit8
	case 0xd4: // rem-int
	case 0xbf: // rem-long/2addr
	case 0x9f: // rem-long
	case 0x94: // rem-int
		op->type = R_ANAL_OP_TYPE_MOD; // mod = rem
		break;
	case 0xd7:
	case 0xd9:
	case 0xda:
	case 0xde:
	case 0xdf:
	case 0x96:
	case 0xc2: // xor-long
	case 0x97: // xor-int
	case 0xa2: // xor-long
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case 0xc9: // div-float
		op->family = R_ANAL_OP_FAMILY_FPU;
		/* pass thru */
	case 0x93: // div-int
	case 0xd3: // div-int/lit16
	case 0xdb: // div-int/lit8
	case 0xce: // div-double
	case 0x9e: // div-double
	case 0xbe: // div-double
	case 0xae: // div-double
	case 0xa9: // div-float
	case 0xb3: // div-int/2addr
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case 0x0e: // return-void
	case 0x0f: // return
	case 0x10: // return-wide
	case 0x11: // return-object
	case 0xf1: // return-void-barrier
		op->type = R_ANAL_OP_TYPE_RET;
		op->eob = true;
		break;
	case 0x28: // goto
		op->jump = addr + ((char)data[1])*2;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->eob = true;
		break;
	case 0x29: // goto/16
		op->jump = addr + (short)(data[2]|data[3]<<8)*2;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->eob = true;
		break;
	case 0x2a: // goto/32
		op->jump = addr + (int)(data[2]|(data[3]<<8)|(data[4]<<16)|(data[5]<<24))*2;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->eob = true;
		break;
	case 0x2c:
	case 0x2b:
		op->type = R_ANAL_OP_TYPE_SWITCH;
		break;
	case 0x2d: // cmpl-float
	case 0x2e: // cmpg-float
	case 0x3f: // cmpg-float // ???? wrong disasm imho 2e0f12003f0f
	case 0x2f: // cmpl-double
	case 0x30: // cmlg-double
	case 0x31: // cmp-long
	case 0x1f: // check-cast
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 0x32: // if-eq
	case 0x33: // if-ne
	case 0x34: // if-lt
	case 0x35: // if-ge
	case 0x36: // if-gt
	case 0x37: // if-le
	case 0x38: // if-eqz
	case 0x39: // if-nez
	case 0x3a: // if-ltz
	case 0x3b: // if-gez
	case 0x3c: // if-gtz
	case 0x3d: // if-lez
		op->type = R_ANAL_OP_TYPE_CJMP;
		//XXX fix this better the check is to avoid an oob
		op->jump = addr + (len>3?(short)(data[2]|data[3]<<8)*2 : 0);
		op->fail = addr + sz;
		op->eob = true;
		break;
	case 0xec: // breakpoint
	case 0x1d: // monitor-enter
		op->type = R_ANAL_OP_TYPE_UPUSH;
		break;
	case 0x1e: // monitor-exit /// wrong type?
		op->type = R_ANAL_OP_TYPE_POP;
		break;
	case 0x6f: // invoke-super
	case 0xfa: // invoke-super-quick
	case 0x70: // invoke-direct
	case 0x71: // invoke-static
	case 0x72: // invoke-interface
	case 0x73: //
	case 0x74: //
	case 0x75: //
	case 0x76: // invoke-direct
	case 0x77: //
	case 0x78: // invokeinterface/range
	case 0xb9: // invokeinterface
	case 0xb7: // invokespecial
	case 0xb8: // invokestatic
	case 0xb6: // invokevirtual
	case 0x6e: // invoke-virtual
	case 0xf0: // invoke-object-init-range
	case 0xf9: // invoke-virtual-quick/range
	case 0xfb: // invoke-super-quick/range
		{
		//XXX fix this better since the check avoid an oob
		//but the jump will be incorrect
		ut32 vB = len > 3?(data[3] << 8) | data[2] : 0;
		op->jump = anal->binb.get_offset (
			anal->binb.bin, 'm', vB);
		op->fail = addr + sz;
		op->type = R_ANAL_OP_TYPE_CALL;
		}
		break;
	case 0x27: // throw
	case 0xee: // execute-inline
	case 0xef: // execute-inline/range
	case 0xed: // throw-verification-error
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
#if 0
	case 0xbb: // new
	case 0xbc: // newarray
	case 0xc5: // multi new array
#endif
	case 0x22: // new-instance
	case 0x23: // new-array
	case 0x24: // filled-new-array
	case 0x25: // filled-new-array-range
	case 0x26: // filled-new-array-data
		op->type = R_ANAL_OP_TYPE_NEW;
		break;
	case 0x00: // nop
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case 0x90: // add-int
	case 0x9b: // add-long
	case 0xa6: // add-float
	case 0xac: // add-double
	case 0xb0: // add-int/2addr
	case 0xbb: // add-long/2addr
	case 0xc6: // add-float/2addr
	case 0xcb: // add-double/2addr
	case 0xd0: // add-int/lit16
	case 0xd8: // add-int/lit8
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0xa7: // sub-float
	case 0xcc: //sub-double
		op->family = R_ANAL_OP_FAMILY_FPU;
		/* fall thru */
	case 0xc7:
	case 0xbc:
	case 0x91:
	case 0xb1: //sub-int/2addr
	case 0xd1: //sub-int/2addr
	case 0x9c: //sub-long
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x7b: // neg-int
	case 0x7d: // neg-long
	case 0x7f: // neg-float
	case 0x80: // neg-double
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case 0xa0: // and-long
	case 0xc0: // and-long
	case 0xdd: // and-long
	case 0xd5: // and-long
	case 0x95:
	case 0xb5: // and-int
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case 0xd6: // orint/lit16
	case 0xc1: // or-long/2addr
	case 0xa1: // or-long
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case 0xe0: //lshl
	case 0xc3: //lshl
	case 0xa3: // shl-long
	case 0x98: // shl-long
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	}

	return sz;
}

static int set_reg_profile(RAnal *anal) {
	const char *p = 
	"=PC	ip\n"
	"=SP	sp\n"
	"=BP	bp\n"
	"=A0	v0\n"
	"=A1	v1\n"
	"=A2	v2\n"
	"=A3	v3\n"
	"gpr	v0	.32	0	0\n"
	"gpr	v1	.32	4	0\n"
	"gpr	v2	.32	8	0\n"
	"gpr	v3	.32	12	0\n"
	"gpr	ip	.32	40	0\n"
	"gpr	sp	.32	44	0\n"
	;
	return r_reg_set_profile_string (anal->reg, p);
}

static bool is_valid_offset(RAnal *anal, ut64 addr, int hasperm) {
	RBinDexObj *bin_dex = (RBinDexObj*) anal->binb.bin->cur->o->bin_obj;
	return addr >= bin_dex->code_from && addr <= bin_dex->code_to;
}

struct r_anal_plugin_t r_anal_plugin_dalvik = {
	.name = "dalvik",
	.arch = "dalvik",
	.set_reg_profile = &set_reg_profile,
	.license = "LGPL3",
	.bits = 32,
	.desc = "Dalvik (Android VM) bytecode analysis plugin",
	.op = &dalvik_op,
	.is_valid_offset = &is_valid_offset
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_dalvik,
	.version = R2_VERSION
};
#endif

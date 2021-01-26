/* radare - LGPL - Copyright 2010-2019 - pancake */

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "../../asm/arch/dalvik/opcode.h"
#include "../../bin/format/dex/dex.h"

static const char *getCond(ut8 cond) {
	switch (cond) {
	case 0x32: // if-eq
		return "$z";
	case 0x33: // if-ne
		return "$z,!";
	case 0x34: // if-lt
		return "63,$c,!";
	case 0x35: // if-ge
		return "63,$c,$z,|";
	case 0x36: // if-gt
		return "63,$c";
	case 0x37: // if-le
		return "63,$c,!,$z,|";
	}
	return "";
}

static const char *getCondz(ut8 cond) {
	switch (cond) {
	case 0x38: // if-eqz
		return "NOP";
	case 0x39: // if-nez
		return "!";
	case 0x3a: // if-ltz
		return "0,==,63,$c,!";
	case 0x3b: // if-gez
		return "0,==,63,$c,$z,|";
	case 0x3c: // if-gtz
		return "0,==,63,$c";
	case 0x3d: // if-lez
		return "0,==,63,$c,!";
	}
	return "";
}

static int dalvik_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	int sz = dalvik_opcodes[data[0]].len;
	if (!op || sz >= len) {
		if (op && (mask & R_ANAL_OP_MASK_DISASM)) {
			op->mnemonic = strdup ("invalid");
		}
		return -1;
	}
	op->size = sz;
	op->nopcode = 1; // Necessary??
	op->id = data[0];

	ut32 vA = 0;
	ut32 vB = 0;
	ut32 vC = 0;
	if (len > 3) {
		vA = data[1];
		vB = data[2];
		vC = data[3];
	}
	switch (data[0]) {
	case 0xca: // rem-float:
		op->family = R_ANAL_OP_FAMILY_FPU;
		/* pass through */
	case 0x1b: // const-string/jumbo
	case 0x14: // const
	case 0x15: // const
	case 0x16: // const
	case 0x17: // const
	case 0x42: // const
	case 0x12: // const/4
		{
			op->type = R_ANAL_OP_TYPE_MOV;
			ut32 vB = (data[1] & 0x0f);
			ut32 vA = (data[1] & 0xf0) >> 4;
			ut32 vC = (len > 4)? r_read_le32 (data + 2): 0x22;
			// op->stackop = R_ANAL_STACK_SET;
			// op->ptr = vC; // why
			ut64 val = vC?vC:vA;
			op->val = val;
	//		op->reg = vB;
			op->nopcode = 2;
			if (mask & R_ANAL_OP_MASK_ESIL) {
				esilprintf (op, "0x%" PFMT64x ",v%d,=", val, vB);
			}
		}
		break;
	case 0x01: // move
	case 0x07: // move-object
	case 0x04: // mov-wide
		{
			ut32 vB = (data[1] & 0x0f);
			ut32 vA = (data[1] & 0xf0) >> 4;
			if (vA == vB) {
				op->type = R_ANAL_OP_TYPE_NOP;
				if (mask & R_ANAL_OP_MASK_ESIL) {
					esilprintf (op, ",");
				}
			} else {
				op->type = R_ANAL_OP_TYPE_MOV;
				//op->stackop = R_ANAL_STACK_SET;
				//op->ptr = -vA;
				if (mask & R_ANAL_OP_MASK_ESIL) {
					esilprintf (op, "v%d,v%d,=", vA, vB);
				}
			}
		}
		break;
	case 0x02: // move/from16
	case 0x03: // move/16
	case 0x05: // move-wide/from16
	case 0x06: // mov-wide&17
	case 0x08: // move-object/from16
	case 0x09: // move-object/16
	case 0x13: // const/16
		op->type = R_ANAL_OP_TYPE_MOV;
		if (len > 2) {
			int vA = (int) data[1];
			ut32 vB = (data[3] << 8) | data[2];
			if (mask & R_ANAL_OP_MASK_ESIL) {
				esilprintf (op, "v%d,v%d,=", vA, vB);
			}
			op->val = vB;
		}
		break;
	case 0x18: // const-wide
	case 0x19: // const-wide
		// 180001000101.  const-wide v0:v1, 0x18201cd01010001
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0x0a: // move-result
	case 0x0d: // move-exception
	case 0x0c: // move-result-object
	case 0x0b: // move-result-wide
	 	// TODO: add MOVRET OP TYPE ??
		op->type = R_ANAL_OP_TYPE_MOV;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			ut32 vA = data[1];
			esilprintf (op, "sp,v%d,=[8],8,sp,+=,8", vA);
		}
		break;
	case 0x1a: // const-string
		op->type = R_ANAL_OP_TYPE_MOV;
		op->datatype = R_ANAL_DATATYPE_STRING;
		if (len > 2) {
			ut32 vA = data[1];
			ut32 vB = (data[3]<<8) | data[2];
			ut64 offset = R_ANAL_GET_OFFSET (anal, 's', vB);
			op->ptr = offset;
			if (mask & R_ANAL_OP_MASK_ESIL) {
				// op->refptr = 0;
				esilprintf (op, "0x%"PFMT64x",v%d,=", offset, vA);
			}
		}
		break;
	case 0x1c: // const-class
		op->type = R_ANAL_OP_TYPE_MOV;
		op->datatype = R_ANAL_DATATYPE_CLASS;
		break;
	case 0x89: // float-to-double
	case 0x8a: // double-to-int
	case 0x87: // double-to-int
	case 0x8c: // double-to-float
	case 0x8b: // double-to-long
	case 0x88: // float-to-long
	case 0x86: // long-to-double
		op->family = R_ANAL_OP_FAMILY_FPU;
		/* pass through */
	case 0x81: // int-to-long
	case 0x82: // int-to-float
	case 0x85: // long-to-float
	case 0x83: // int-to-double
	case 0x8d: // int-to-byte
	case 0x8e: // int-to-char
		op->type = R_ANAL_OP_TYPE_CAST;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			ut32 vA = (data[1] & 0x0f);
			ut32 vB = (data[1] & 0xf0) >> 4;
			esilprintf (op, "v%d,0xff,&,v%d,=", vB, vA);
		}
		break;
	case 0x8f: // int-to-short
		op->type = R_ANAL_OP_TYPE_CAST;
		// op->datatype = R_ANAL_DATATYPE_INT32 | R_ANAL_DATATYPE_INT16;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			ut32 vA = (data[1] & 0x0f);
			ut32 vB = (data[1] & 0xf0) >> 4;
			esilprintf (op, "v%d,0xffff,&,v%d,=", vB, vA);
		}
		break;
	case 0x84: // long-to-int
		op->type = R_ANAL_OP_TYPE_CAST;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			ut32 vA = (data[1] & 0x0f);
			ut32 vB = (data[1] & 0xf0) >> 4;
			esilprintf (op, "v%d,0xffffffff,&,v%d,=", vB, vA);
		}
		break;
	case 0x20: // instance-of
		op->type = R_ANAL_OP_TYPE_CMP;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			esilprintf (op, "%d,instanceof,%d,-,!,v%d,=", vC, vB, vA);
		}
		break;
	case 0x21: // array-length
		op->type = R_ANAL_OP_TYPE_LENGTH;
		op->datatype = R_ANAL_DATATYPE_ARRAY;
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
	case 0xf4: //iget-byte
	case 0x66: //sget-short
	case 0xfd: //sget-object
	case 0x55: //iget-bool
	case 0x60: // sget
	case 0x61: //
	case 0x64: // sget-byte
	case 0x65: // sget-char
	case 0xe3: //iget-volatile
	case 0xe4: //
	case 0xe5: // sget
	case 0xe6: // sget
	case 0xe7: // iget-object-volatile
	case 0xe8: //iget-bool
	case 0xf3: //iget-bool
	case 0xf8: //iget-bool
	case 0xf2: //iget-quick
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case 0x54: // iget-object
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			ut32 vA = (data[1] & 0x0f);
			ut32 vB = (data[1] & 0xf0) >> 4;
			ut32 vC = (data[2] & 0x0f);
			esilprintf (op, "%d,v%d,iget,v%d,=", vC, vB, vA);
		}
		break;
	case 0x63: // sget-boolean
		op->datatype = R_ANAL_DATATYPE_BOOLEAN;
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			ut32 vA = (data[1] & 0x0f);
			ut32 vB = (data[1] & 0xf0) >> 4;
			ut32 vC = (data[2] & 0x0f);
			const char *vT = "-boolean";
			esilprintf (op, "%d,%d,sget%s,v%d,=", vC, vB, vT, vA);
		}
		break;
	case 0x62: // sget-object
		{
			op->datatype = R_ANAL_DATATYPE_OBJECT;
			op->type = R_ANAL_OP_TYPE_LOAD;
			ut32 vC = len > 3?(data[3] << 8) | data[2] : 0;
			op->ptr = anal->binb.get_offset (anal->binb.bin, 'f', vC);
			if (mask & R_ANAL_OP_MASK_ESIL) {
				ut32 vA = (data[1] & 0x0f);
				esilprintf (op, "%" PFMT64d ",v%d,=", op->ptr, vA);
			}
		}
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
{
	op->type = R_ANAL_OP_TYPE_STORE;
	ut32 vC = len > 3?(data[3] << 8) | data[2] : 0;
	op->ptr = anal->binb.get_offset (anal->binb.bin, 'f', vC);
}
		if (mask & R_ANAL_OP_MASK_ESIL) {
			ut32 vA = (data[1] & 0x0f);
			esilprintf (op, "%" PFMT64d ",v%d,=", op->ptr, vA);
		}
		break;
	case 0xad: // mul-double
		op->family = R_ANAL_OP_FAMILY_FPU;
		op->type = R_ANAL_OP_TYPE_MUL;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			esilprintf (op, "v%d,v%d,*,v%d,=", vC, vB, vA);
		}
		break;
	case 0x9d:
	case 0xc8: // mul-float
		op->family = R_ANAL_OP_FAMILY_FPU;
		/* fall through */
	case 0xcd:
	case 0xd2: // mul-int/lit16
	case 0x92:
	case 0xb2:
		op->type = R_ANAL_OP_TYPE_MUL;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			ut32 vA = (data[1] & 0x0f);
			ut32 vB = (data[1] & 0xf0) >> 4;
			ut32 vC = (data[2] << 8) | data[3];
			esilprintf (op, "%d,v%d,*,v%d,=", vC, vB, vA);
			op->val = vC;
		}
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
		/* pass through */
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

	case 0x95: // and-int
	case 0x96: // or-int
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case 0xc2: // xor-long
	case 0x97: // xor-int
	case 0xdf: // xor-int/lit16
	case 0xa2: // xor-long
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case 0xc9: // div-float
		op->family = R_ANAL_OP_FAMILY_FPU;
		/* pass through */
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
		//TODO: handle return if(0x0e) {} else {}
		if (mask & R_ANAL_OP_MASK_ESIL) {
			if (data[0] == 0x0e) {// return-void
				esilprintf (op, "sp,[8],ip,=,8,sp,+=");
			} else {
				ut32 vA = data[1];
				esilprintf (op, "sp,[8],ip,=,8,sp,+=,8,sp,-=,v%d,sp,=[8]", vA);
			}
		}
		break;
	case 0x28: // goto
		op->jump = addr + ((char)data[1])*2;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->eob = true;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			esilprintf (op, "0x%"PFMT64x",ip,=", op->jump);
		}
		break;
	case 0x29: // goto/16
		if (len > 3) {
			op->jump = addr + (short)(data[2]|data[3]<<8)*2;
			op->type = R_ANAL_OP_TYPE_JMP;
			op->eob = true;
			if (mask & R_ANAL_OP_MASK_ESIL) {
				esilprintf (op, "0x%"PFMT64x",ip,=", op->jump);
			}
		}
		break;
	case 0x2a: // goto/32
		if (len > 5) {
			st64 dst = (st64)(data[2]|(data[3]<<8)|(data[4]<<16)|((ut32)data[5]<<24));
			op->jump = addr + (dst * 2);
			op->type = R_ANAL_OP_TYPE_JMP;
			op->eob = true;
			if (mask & R_ANAL_OP_MASK_ESIL) {
				esilprintf (op, "0x%"PFMT64x",ip,=", op->jump);
			}
		}
		break;
	case 0x2c:
	case 0x2b:
		op->type = R_ANAL_OP_TYPE_SWITCH;
		break;
	case 0x3e: // glitch 0 width instruction .. invalid instruction
	case 0x43:
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 1;
		op->eob = true;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			esilprintf (op, ",");
		}
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
		op->type = R_ANAL_OP_TYPE_CJMP;
		//XXX fix this better the check is to avoid an oob
		if (len > 2) {
			op->jump = addr + (len>3?(short)(data[2]|data[3]<<8)*2 : 0);
			op->fail = addr + sz;
			op->eob = true;
			if (mask & R_ANAL_OP_MASK_ESIL) {
				ut32 vA = data[1];
				ut32 vB = data[2];
				const char *cond = getCond (data[0]);
				esilprintf (op, "v%d,v%d,==,%s,?{,%"PFMT64d",ip,=}", vB, vA, cond, op->jump);
			}
		}
		break;
	case 0x38: // if-eqz
	case 0x39: // if-nez
	case 0x3a: // if-ltz
	case 0x3b: // if-gez
	case 0x3c: // if-gtz
	case 0x3d: // if-lez
		op->type = R_ANAL_OP_TYPE_CJMP;
		//XXX fix this better the check is to avoid an oob
		if (len > 2) {
			op->jump = addr + (len>3?(short)(data[2]|data[3]<<8)*2 : 0);
			op->fail = addr + sz;
			op->eob = true;
			if (mask & R_ANAL_OP_MASK_ESIL) {
				ut32 vA = data[1];
				const char *cond = getCondz (data[0]);
				esilprintf (op, "v%d,%s,?{,%"PFMT64d",ip,=}", vA, cond, op->jump);
			}
		}
		break;
	case 0xec: // breakpoint
		op->type = R_ANAL_OP_TYPE_TRAP;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			esilprintf (op, "TRAP");
		}
		break;
	case 0x1d: // monitor-enter
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 1;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			esilprintf (op, ",");
		}
		break;
	case 0x1e: // monitor-exit /// wrong type?
		op->type = R_ANAL_OP_TYPE_POP;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -1;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			esilprintf (op, ",");
		}
		break;
	case 0x73: // invalid
		break;
	case 0x6f: // invoke-super
	case 0x70: // invoke-direct
	case 0x71: // invoke-static
	case 0x72: // invoke-interface
	case 0x77: //
	case 0xb9: // invokeinterface
	case 0xb7: // invokespecial
	case 0xb6: // invokevirtual
	case 0x6e: // invoke-virtual
		if (len > 2) {
			//XXX fix this better since the check avoid an oob
			//but the jump will be incorrect
			ut32 vB = len > 3?(data[3] << 8) | data[2] : 0;
			ut64 dst = anal->binb.get_offset (anal->binb.bin, 'm', vB);
			if (dst == 0) {
				op->type = R_ANAL_OP_TYPE_UCALL;
			} else {
				op->type = R_ANAL_OP_TYPE_CALL;
				op->jump = dst;
			}
			op->fail = addr + sz;
			if (mask & R_ANAL_OP_MASK_ESIL) {
				// TODO: handle /range instructions
				esilprintf (op, "8,sp,-=,0x%"PFMT64x",sp,=[8],0x%"PFMT64x",ip,=", op->fail, op->jump);
			}
		}
		break;
	case 0x78: // invokeinterface/range
	case 0xf0: // invoke-object-init-range
	case 0xf9: // invoke-virtual-quick/range
	case 0xfb: // invoke-super-quick/range
	case 0x74: // invoke-virtual/range
	case 0x75: // invoke-super/range
	case 0x76: // invoke-direct/range
	case 0xfa: // invoke-super-quick // invoke-polymorphic
		if (len > 2) {
			//XXX fix this better since the check avoid an oob
			//but the jump will be incorrect
			// ut32 vB = len > 3?(data[3] << 8) | data[2] : 3;
			//op->jump = anal->binb.get_offset (anal->binb.bin, 'm', vB);
			op->fail = addr + sz;
			// op->type = R_ANAL_OP_TYPE_CALL;
			op->type = R_ANAL_OP_TYPE_UCALL;
			// TODO: handle /range instructions
			// NOP esilprintf (op, "8,sp,-=,0x%"PFMT64x",sp,=[8],0x%"PFMT64x",ip,=", addr);
		}
		if (mask & R_ANAL_OP_MASK_ESIL) {
			// TODO: handle /range instructions
			esilprintf (op, "8,sp,-=,0x%"PFMT64x",sp,=[8],0x%"PFMT64x",ip,=", op->fail, op->jump);
		}
		break;
	case 0x27: // throw
		{
			op->type = R_ANAL_OP_TYPE_TRAP;
			if (mask & R_ANAL_OP_MASK_ESIL) {
				ut32 vA = data[1];
				esilprintf (op, "v%d,TRAP", vA);
			}
		}
		break;
	case 0xee: // execute-inline
	case 0xef: // execute-inline/range
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xed: // throw-verification-error
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case 0x22: // new-instance
		op->type = R_ANAL_OP_TYPE_NEW;
		if (len > 2) {
			// resolve class name for vB
			int vB = (data[3] << 8) | data[2];
			ut64 off = R_ANAL_GET_OFFSET (anal, 't', vB);
			op->ptr = off;
			if (mask & R_ANAL_OP_MASK_ESIL) {
				int vA = (int) data[1];
				esilprintf (op, "%" PFMT64d ",new,v%d,=", off, vA);
			}
		}
		break;
	case 0x23: // new-array
		op->type = R_ANAL_OP_TYPE_NEW;
		// 0x1c, 0x1f, 0x22
		if (len > 2 && mask & R_ANAL_OP_MASK_ESIL) {
			ut32 vA = (data[1] & 0x0f);
			ut32 vB = (data[1] & 0xf0) >> 4;
			ut32 vC = (int) data[2] | (data[3]<<8);
			esilprintf (op, "%d,%d,new-array,v%d,=",vC, vB, vA);
		}
		break;
	case 0x24: // filled-new-array
	case 0x25: // filled-new-array-range
	case 0x26: // filled-new-array-data
		op->type = R_ANAL_OP_TYPE_NEW;
		// 0x1c, 0x1f, 0x22
		if (len > 2) {
			//int vA = (int) data[1];
			int vB = (data[3] << 8) | data[2];
			// resolve class name for vB
			ut64 off = R_ANAL_GET_OFFSET (anal, 't', vB);
			op->ptr = off;
		}
		break;
	case 0x00: // nop
		op->type = R_ANAL_OP_TYPE_NOP;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			esilprintf (op, ",");
		}
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
		if (mask & R_ANAL_OP_MASK_ESIL) {
			ut32 vB = (data[1] & 0x0f);
			ut32 vA = (data[1] & 0xf0) >> 4;
			esilprintf (op, "v%d,v%d,+=", vB, vA);
		}
		break;
	case 0xa7: // sub-float
	case 0xcc: // sub-double
		op->family = R_ANAL_OP_FAMILY_FPU;
		/* fall through */
	case 0xc7:
	case 0xbc:
	case 0x91:
	case 0xb1: //sub-int/2addr
	case 0xd1: //sub-int/2addr
	case 0x9c: //sub-long
		op->type = R_ANAL_OP_TYPE_SUB;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			esilprintf (op, "v%d,v%d,-,v%d,=", vC, vB, vA);
		}
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
	case 0xb5: // and-int
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case 0xd6: // orint/lit16
	case 0xc1: // or-long/2addr
	case 0xa1: // or-long
		op->type = R_ANAL_OP_TYPE_OR;
		if (mask & R_ANAL_OP_MASK_ESIL) {
			ut32 vA = (data[1] & 0x0f);
			ut32 vB = (data[1] & 0xf0) >> 4;
			ut32 vC = (data[2] << 8) | data[3];
			esilprintf (op, "%d,v%d,|,v%d,=", vC, vB, vA);
			op->val = vC;
		}
		break;
	case 0xe0: //lshl
	case 0xc3: //lshl
	case 0xa3: // shl-long
	case 0x98: // shl-long
	case 0xb8: // shl-int/2addr
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	}
	return sz;
}

static bool set_reg_profile(RAnal *anal) {
	const char *p =
	"=PC	ip\n"
	"=SP	sp\n"
	"=BP	bp\n"
	"=A0	v0\n"
	"=A1	v1\n"
	"=A2	v2\n"
	"=A3	v3\n"
	"=SN	v0\n"
	"gpr	v0	.32	0	0\n"
	"gpr	v1	.32	4	0\n"
	"gpr	v2	.32	8	0\n"
	"gpr	v3	.32	12	0\n"
	"gpr	v4	.32	16	0\n"
	"gpr	v5	.32	20	0\n"
	"gpr	v6	.32	24	0\n"
	"gpr	v7	.32	28	0\n"
	"gpr	v8	.32	32	0\n"
	"gpr	v9	.32	36	0\n"
	"gpr	v10	.32	40	0\n"
	"gpr	v11	.32	44	0\n"
	"gpr	v12	.32	48	0\n"
	"gpr	v13	.32	52	0\n"
	"gpr	v14	.32	56	0\n"
	"gpr	v15	.32	60	0\n"
	"gpr	v16	.32	40	0\n"
	"gpr	v17	.32	44	0\n"
	"gpr	v18	.32	48	0\n"
	"gpr	v19	.32	52	0\n"
	"gpr	v20	.32	56	0\n"
	"gpr	v21	.32	60	0\n"
	"gpr	v22	.32	64	0\n"
	"gpr	v23	.32	68	0\n"
	"gpr	v24	.32	72	0\n"
	"gpr	v25	.32	76	0\n"
	"gpr	v26	.32	80	0\n"
	"gpr	v27	.32	84	0\n"
	"gpr	v28	.32	88	0\n"
	"gpr	v29	.32	92	0\n"
	"gpr	v30	.32	96	0\n"
	"gpr	v31	.32	100	0\n"
	"gpr	v32	.32	104	0\n"
	"gpr	v33	.32	108	0\n"
	"gpr	v34	.32	112	0\n"
	"gpr	ip	.32	116	0\n"
	"gpr	sp	.32	120	0\n"
	"gpr	bp	.32	124	0\n"
	;
	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_dalvik = {
	.name = "dalvik",
	.arch = "dalvik",
	.set_reg_profile = &set_reg_profile,
	.license = "LGPL3",
	.bits = 32,
	.desc = "Dalvik (Android VM) bytecode analysis plugin",
	.op = &dalvik_op,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_dalvik,
	.version = R2_VERSION
};
#endif
